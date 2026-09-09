//! TLS acceptor with ALPN dispatch. One :443 listener, two worlds:
//! `ddns-tcp` → raw TCP bridge; `h2`/`http/1.1` → hyper auto serving the axum app.
//!
//! Three certificate paths:
//! - **Static PEM** — operator-supplied cert chain + key.
//! - **ACME TLS-ALPN-01** (default ACME path, provider `manual`) — driven by
//!   rustls-acme's state machine; apex-only (Let's Encrypt requires DNS-01
//!   for wildcards). Certificates hot-reload through rustls-acme's resolver.
//! - **ACME DNS-01** (provider `cloudflare`/`porkbun`) — driven by
//!   [`crate::dns_acme`], a self-contained RFC 8555 client that writes
//!   `_acme-challenge` TXT records through the provider, requests the apex +
//!   wildcard in one order, and swaps the served certificate through an
//!   [`AcceptorSlot`]. Requires no inbound validation ports.
//!
//! Every path serves through an [`AcceptorSlot`] so the DNS-01 engine can
//! atomically replace the certificate at renewal without touching the accept
//! loop.

use std::sync::Arc;

use parking_lot::RwLock;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_acme::caches::DirCache;
use tokio_rustls::TlsAcceptor;

use crate::config::{AcmeProvider, BrokerConfig};
use crate::providers::{ChallengeStore, Cloudflare, Dns01Provider, Porkbun};

/// Raw-TCP tunnel ALPN token.
pub const ALPN_TCP: &[u8] = b"ddns-tcp";

/// TLS-ALPN-01 validation ALPN (RFC 8737), used by Let's Encrypt's
/// validation client. MUST be in the acceptor's ALPN list for ACME issuance.
pub const ACME_ALPN: &[u8] = rustls_acme::acme::ACME_TLS_ALPN_NAME;

/// Shared slot holding the live acceptor. The accept loop clones the current
/// acceptor per connection; the DNS-01 engine swaps in a freshly issued
/// certificate at renewal.
#[derive(Clone)]
pub struct AcceptorSlot {
    inner: Arc<RwLock<TlsAcceptor>>,
}

impl AcceptorSlot {
    pub fn new(acceptor: TlsAcceptor) -> Self {
        Self {
            inner: Arc::new(RwLock::new(acceptor)),
        }
    }
    pub fn get(&self) -> TlsAcceptor {
        self.inner.read().clone()
    }
    pub fn set(&self, acceptor: TlsAcceptor) {
        *self.inner.write() = acceptor;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("PEM parse error: {0}")]
    Pem(#[from] std::io::Error),
    #[error("no private key found in PEM")]
    MissingPrivateKey,
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Result of building the TLS configuration.
pub struct TlsConfig {
    /// Live acceptor slot. In the ACME DNS-01 path the engine swaps the
    /// certificate inside this slot at issuance/renewal.
    pub slot: AcceptorSlot,
    /// ACME challenge store (present only in the legacy ACME path). Exposed
    /// so operators/tests can seed HTTP-01 challenges and read cert status.
    pub challenge_store: Option<Arc<ChallengeStore>>,
    /// rustls-acme state machine (legacy TLS-ALPN-01 path only). The caller
    /// drives it (spawns the issuance/renewal task) AFTER all listeners are
    /// bound, so a bind failure cannot leak a detached ACME task.
    pub acme_state: Option<rustls_acme::AcmeState<std::io::Error, std::io::Error>>,
    /// DNS-01 issuance engine (provider `cloudflare`/`porkbun`). The caller
    /// spawns its renewal loop after listeners are bound.
    pub dns_acme: Option<crate::dns_acme::DnsAcmeController>,
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

/// Self-signed bootstrap certificate for the DNS-01 path, served only until
/// the first ACME certificate is issued (normally minutes). Covers the apex
/// and its wildcard so the dashboard and tunnels negotiate TLS while the
/// order is in flight.
fn bootstrap_acceptor(domain: &str) -> Result<TlsAcceptor, String> {
    use rcgen::{CertificateParams, KeyPair};
    let sans = vec![domain.to_string(), format!("*.{domain}")];
    let params = CertificateParams::new(sans).map_err(|e| format!("rcgen params: {e}"))?;
    let key = KeyPair::generate().map_err(|e| format!("rcgen keygen: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("rcgen sign: {e}"))?;
    static_server_config(&cert.pem().into_bytes(), &key.serialize_pem().into_bytes())
        .map_err(|e| format!("bootstrap acceptor: {e}"))
}

/// Build the TLS configuration from [`BrokerConfig`].
///
/// # ACME paths
/// - `provider = Manual` (or unset): rustls-acme `AcmeState` validates via
///   TLS-ALPN-01 on :443 (apex-only). The acceptor advertises `acme-tls/1` so
///   Let's Encrypt validation handshakes are accepted. Certificates are
///   cached in `config.acme_cache_dir` and hot-reloaded by the resolver.
/// - `provider = Cloudflare`/`Porkbun`: the DNS-01 engine
///   ([`crate::dns_acme`]) writes TXT records and swaps the issued
///   `[apex, *.apex]` certificate into the acceptor slot.
pub fn server_config(config: &BrokerConfig) -> Result<TlsConfig, TlsError> {
    let Some(acme) = &config.acme else {
        let acceptor = static_server_config(&config.tls_cert_pem, &config.tls_key_pem)?;
        return Ok(TlsConfig {
            slot: AcceptorSlot::new(acceptor),
            challenge_store: None,
            acme_state: None,
            dns_acme: None,
        });
    };

    if acme.provider.uses_dns01() {
        return dns01_config(config, acme);
    }

    // ------------------------------------------------------------------
    // Legacy TLS-ALPN-01 path (rustls-acme)
    // ------------------------------------------------------------------
    let challenge_store = Arc::new(ChallengeStore::default());

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
        tracing::info!(directory = %effective_dir, "ACME directory (TLS-ALPN-01, apex-only)");
    }
    // Keep the ACME account/certificate cache on the persistent broker
    // volume. A container restart must not force a new ACME registration.
    let cache = DirCache::new(config.acme_cache_dir.to_string_lossy().to_string());
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
        slot: AcceptorSlot::new(acceptor),
        challenge_store: Some(challenge_store),
        acme_state: Some(state),
        dns_acme: None,
    })
}

/// Build the DNS-01 configuration: a provider wired to the live API, an
/// initial acceptor (cached certificate when valid, else a self-signed
/// bootstrap), and the issuance controller.
fn dns01_config(
    config: &BrokerConfig,
    acme: &crate::config::AcmeOptions,
) -> Result<TlsConfig, TlsError> {
    let provider: Arc<dyn Dns01Provider> = match &acme.provider {
        AcmeProvider::Cloudflare { api_token, zone_id } => Arc::new(Cloudflare::new(
            api_token.clone(),
            zone_id.clone(),
            Cloudflare::API_BASE.to_string(),
        )),
        AcmeProvider::Porkbun { api_key, secret } => Arc::new(Porkbun::new(
            api_key.clone(),
            secret.clone(),
            config.domain.clone(),
            Porkbun::API_BASE.to_string(),
        )),
        AcmeProvider::Manual => {
            // Wildcards + Manual are rejected in BrokerConfig::validate(); a
            // bare apex-only Manual request never reaches the DNS-01 path.
            return Err(TlsError::Rustls(rustls::Error::General(
                "manual ACME provider cannot drive DNS-01 issuance".into(),
            )));
        }
    };

    let cache_dir = config.acme_cache_dir.clone();
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| TlsError::Rustls(rustls::Error::General(format!("cache dir: {e}"))))?;

    // Start from a cached certificate when present and still valid; the
    // renewal loop swaps in a fresh one before it expires.
    let cached = crate::dns_acme::read_cached_bundle(&cache_dir);
    let initial = match &cached {
        Some((chain_pem, key_pem))
            if crate::dns_acme::bundle_not_after(chain_pem)
                .map(|na| na > crate::dns_acme::now_secs() + 30 * 24 * 3600)
                .unwrap_or(false) =>
        {
            static_server_config(chain_pem.as_bytes(), key_pem.as_bytes())
                .unwrap_or_else(|_| bootstrap_acceptor(&config.domain).expect("bootstrap cert"))
        }
        _ => bootstrap_acceptor(&config.domain).expect("bootstrap cert"),
    };
    let slot = AcceptorSlot::new(initial);

    let directory = acme
        .directory_url
        .clone()
        .unwrap_or_else(|| rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY.to_string());
    tracing::info!(directory = %directory, domains = ?acme.domains, "ACME DNS-01 engine");

    let issuer_cfg = crate::dns_acme::DnsIssuerConfig::new(
        directory,
        acme.contact_email.clone(),
        acme.domains.clone(),
        cache_dir,
        provider,
    );
    let controller = crate::dns_acme::DnsAcmeController::new(issuer_cfg, slot.clone());
    Ok(TlsConfig {
        slot,
        challenge_store: Some(Arc::new(ChallengeStore::default())),
        acme_state: None,
        dns_acme: Some(controller),
    })
}
