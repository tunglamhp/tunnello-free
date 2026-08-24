//! TLS acceptor with ALPN dispatch. One :443 listener, two worlds:
//! `ddns-tcp` → raw TCP bridge; `h2`/`http/1.1` → hyper auto serving the axum app.
//!
//! Two paths: static PEM certs (tests, manual deploys) or ACME (auto-renewed
//! via rustls-acme, TLS-ALPN-01 validation on port 443).

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_acme::caches::DirCache;
use tokio_rustls::TlsAcceptor;

use crate::config::{AcmeProvider, BrokerConfig};
use crate::providers::ChallengeStore;

/// Raw-TCP tunnel ALPN token.
pub const ALPN_TCP: &[u8] = b"ddns-tcp";

/// TLS-ALPN-01 validation ALPN (RFC 8737), used by Let's Encrypt's
/// validation client. MUST be in the acceptor's ALPN list for ACME issuance.
pub const ACME_ALPN: &[u8] = rustls_acme::acme::ACME_TLS_ALPN_NAME;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("PEM parse error: {0}")]
    Pem(#[from] std::io::Error),
    #[error("no private key found in PEM")]
    MissingPrivateKey,
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}
/// Result of building the TLS configuration. In the ACME path, the
/// `ChallengeStore` is returned alongside the acceptor so it can be shared
/// with the :80 HTTP-01 listener and the dashboard cert-status endpoint.
pub struct TlsConfig {
    pub acceptor: TlsAcceptor,
    /// ACME challenge store, if the ACME path was used.
    pub challenge_store: Option<Arc<ChallengeStore>>,
    /// ACME state machine, if the ACME path was used. The caller drives it
    /// (spawns the issuance/renewal task) AFTER all listeners are bound, so
    /// a bind failure cannot leak a detached ACME task.
    pub acme_state: Option<rustls_acme::AcmeState<std::io::Error, std::io::Error>>,
}

/// Build a TLS acceptor from PEM cert chain + private key.
/// Advertises `ddns-tcp`, `h2`, `http/1.1` in that order.
pub fn static_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor, TlsError> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut &key_pem[..])?.ok_or(TlsError::MissingPrivateKey)?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![ALPN_TCP.to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Build the TLS configuration from [`BrokerConfig`]. ACME path is used when
/// `config.acme` is `Some`; otherwise the static PEM path.
///
/// # ACME path
/// Uses `rustls_acme::AcmeConfig` with TLS-ALPN-01 validation (built-in) —
/// the acceptor advertises `acme-tls/1` so Let's Encrypt validation
/// handshakes are accepted. The `ChallengeStore` is returned for the :80
/// listener and the dashboard. Certificates are cached to `./acme_cache`.
///
/// # Deviation from brief
/// rustls-acme 0.12.1 does not expose `.dns01_solver()` or
/// `.into_rustls_acceptor()` (verified against vendored sources: it has no
/// DNS-01/HTTP-01 solver hooks and validates solely via TLS-ALPN-01). We use
/// `.state()` → `.resolver()` to feed the rustls `ServerConfig`. The state
/// machine is returned via [`TlsConfig::acme_state`] for the caller to drive
/// (spawn) after listeners are bound, so a bind failure cannot leak a
/// detached task. DNS-01 providers are plumbed and tested but not yet driven
/// by issuance (v1 limitation, warned at start).
pub fn server_config(config: &BrokerConfig) -> Result<TlsConfig, TlsError> {
    if let Some(acme) = &config.acme {
        let challenge_store = Arc::new(ChallengeStore::default());
        // rustls-acme 0.12.1 validates exclusively via TLS-ALPN-01 on :443 —
        // it exposes no Dns01Solver/Http01Solver hooks (verified against the
        // vendored sources). A DNS-01 provider selection therefore does not
        // change issuance today; warn loudly so an operator expecting
        // TXT-based validation (e.g. :443 unreachable, or a wildcard) is not
        // silently misled.
        match &acme.provider {
            AcmeProvider::Manual => {
                tracing::warn!(
                    "ACME: DNS-01 is not yet active in v1 — issuance uses TLS-ALPN-01 on :443 \
                     (manual-TXT provider recorded for the dashboard only)"
                );
            }
            AcmeProvider::Cloudflare { .. } => {
                tracing::warn!(
                    "ACME: DNS-01 is not yet active in v1 — issuance uses TLS-ALPN-01 on :443 \
                     (Cloudflare provider is wired for the API but not yet driven by issuance)"
                );
            }
        }

        let mut builder = rustls_acme::AcmeConfig::new(acme.domains.clone());
        if let Some(email) = &acme.contact_email {
            builder = builder.contact_push(format!("mailto:{email}"));
        }
        if let Some(url) = &acme.directory_url {
            builder = builder.directory(url);
        } else {
            // Spec §5: broker certificates come from production Let's Encrypt.
            builder = builder.directory(rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY);
        }
        let effective_dir = acme
            .directory_url
            .clone()
            .unwrap_or_else(|| rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY.to_string());
        if effective_dir.contains("staging") {
            tracing::warn!(
                directory = %effective_dir,
                "ACME staging directory in use — issued certificates will NOT be trusted by browsers"
            );
        } else {
            tracing::info!(directory = %effective_dir, "ACME directory");
        }
        // Keep the ACME account/certificate cache on the persistent broker
        // volume. A container restart must not force a new ACME registration.
        let cache = DirCache::new("/data/acme_cache");
        let builder = builder.cache(cache);
        let state = rustls_acme::AcmeState::new(builder);

        // Build a custom ServerConfig that uses the ACME cert resolver and
        // advertises our ALPN protocols. `acme-tls/1` MUST be listed:
        // rustls 0.23 aborts with no_application_protocol when the client's
        // ALPN (here: exactly ["acme-tls/1"], per RFC 8737) does not
        // intersect the server's list, which would reject every Let's Encrypt
        // TLS-ALPN-01 validation connection before the ACME resolver
        // (holding the per-domain auth key) is consulted.
        let resolver = state.resolver();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![ALPN_TCP.to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.alpn_protocols
            .push(rustls_acme::acme::ACME_TLS_ALPN_NAME.to_vec());

        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        Ok(TlsConfig {
            acceptor,
            challenge_store: Some(challenge_store),
            acme_state: Some(state),
        })
    } else {
        let acceptor = static_server_config(&config.tls_cert_pem, &config.tls_key_pem)?;
        Ok(TlsConfig {
            acceptor,
            challenge_store: None,
            acme_state: None,
        })
    }
}
