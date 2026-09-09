//! DNS-01 ACME issuance engine (RFC 8555).
//!
//! rustls-acme 0.12 drives certificate issuance exclusively through
//! TLS-ALPN-01 (and its JWS internals are crate-private), so wildcard
//! certificates — which Let's Encrypt validates only via DNS-01 — need a
//! separate client. This module implements the ACME v2 protocol directly
//! (account, order, DNS-01 challenge, finalize, download) over `reqwest`,
//! signs requests with an ES256 account key (`p256`), writes/clears the
//! `_acme-challenge` TXT records through a [`Dns01Provider`], caches the
//! account key and issued certificate under the broker's cache directory,
//! and hot-swaps the served certificate through an [`AcceptorSlot`].
//!
//! A single order requests `[apex, *.apex]` (one certificate covering the
//! dashboard at the apex and every tunnel subdomain). Both authorizations
//! place their TXT digest on the *same* `_acme-challenge.<apex>` name with
//! different values, which is valid DNS-01 (the CA looks for its own digest
//! among the TXT set).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey;
use rcgen::{CertificateParams, KeyPair};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::providers::Dns01Provider;
use crate::tls::AcceptorSlot;

/// Renew when the cached certificate has fewer than this many seconds left.
const RENEW_LEAD_SECS: i64 = 30 * 24 * 3600;
/// How long to wait for DNS propagation before asking the CA to validate.
const DEFAULT_PROPAGATION: Duration = Duration::from_secs(20);
/// Default poll interval while waiting for authorizations/order to flip.
const DEFAULT_POLL: Duration = Duration::from_secs(5);
const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(300);

const CACHE_ACCOUNT_KEY: &str = "dns01-account-key.der";
const CACHE_CERT: &str = "dns01-cert.pem";
const CACHE_KEY: &str = "dns01-key.pem";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything the DNS-01 engine needs. Constructed by `tls::server_config`
/// when the ACME provider is Cloudflare/Porkbun; tests construct it directly
/// against a mock ACME directory.
#[derive(Clone)]
pub struct DnsIssuerConfig {
    pub directory_url: String,
    pub contact_email: Option<String>,
    /// Identifiers to request (e.g. `[apex, *.apex]`).
    pub domains: Vec<String>,
    pub cache_dir: std::path::PathBuf,
    pub provider: Arc<dyn Dns01Provider>,
    pub http: Client,
    pub propagation_delay: Duration,
    pub poll_interval: Duration,
    pub max_wait: Duration,
}

impl DnsIssuerConfig {
    pub fn new(
        directory_url: String,
        contact_email: Option<String>,
        domains: Vec<String>,
        cache_dir: std::path::PathBuf,
        provider: Arc<dyn Dns01Provider>,
    ) -> Self {
        Self {
            directory_url,
            contact_email,
            domains,
            cache_dir,
            provider,
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client build"),
            propagation_delay: DEFAULT_PROPAGATION,
            poll_interval: DEFAULT_POLL,
            max_wait: DEFAULT_MAX_WAIT,
        }
    }
}

/// What an issuance produced (observable by tests).
pub struct IssuedBundle {
    pub chain_pem: String,
    pub leaf_key_pem: String,
    pub not_after_secs: i64,
}

/// Controller handed to the broker: owns the loop that keeps the served
/// certificate valid and swaps it into the acceptor slot.
pub struct DnsAcmeController {
    issuer: DnsIssuer,
}

impl DnsAcmeController {
    pub fn new(config: DnsIssuerConfig, slot: AcceptorSlot) -> Self {
        Self {
            issuer: DnsIssuer { cfg: config, slot },
        }
    }

    /// Run one issuance/cache-check pass (serve cached cert when fresh,
    /// otherwise issue + hot-swap). Tests use this instead of the loop.
    pub async fn run_once(&self) -> Result<(), String> {
        self.issuer.ensure_issued().await.map(|_| ())
    }

    /// Drive issuance + renewal forever. The caller aborts the task to stop.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.issuer.run().await;
        })
    }
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

struct DnsIssuer {
    cfg: DnsIssuerConfig,
    slot: AcceptorSlot,
}

/// One DNS-01 challenge ready to be served: TXT record base host and digest.
struct PendingChallenge {
    /// Host the TXT record is written on, without the `_acme-challenge.`
    /// prefix (the identifier with any leading `*.` stripped).
    base: String,
    /// Full digest value for the TXT record.
    value: String,
    /// Authorization URL (polling).
    authz_url: String,
    /// Challenge URL (validation trigger).
    challenge_url: String,
}

impl DnsIssuer {
    async fn run(&self) {
        loop {
            match self.ensure_issued().await {
                Ok(Some(secs_left)) => {
                    let nap = Duration::from_secs((secs_left - RENEW_LEAD_SECS).max(60) as u64)
                        .min(Duration::from_secs(12 * 3600));
                    info!(
                        nap_secs = nap.as_secs(),
                        "ACME DNS-01 certificate valid; sleeping until renewal check"
                    );
                    tokio::time::sleep(nap).await;
                }
                Ok(None) => {
                    // Nothing cached and nothing issued yet this boot — the
                    // issuing task already retried with backoff inside
                    // ensure_issued; nap briefly and re-check.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                Err(e) => {
                    warn!(error = %e, "ACME DNS-01 issuance failed; retrying");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        }
    }

    /// Serve the cached certificate when still valid; otherwise issue a fresh
    /// one and hot-swap it. Returns seconds until expiry when a certificate is
    /// installed. A certificate that cannot be installed (e.g. provider key
    /// mismatch after a restart) is logged and the previous acceptor keeps
    /// serving — a bad renewal must never take the broker's TLS down.
    async fn ensure_issued(&self) -> Result<Option<i64>, String> {
        std::fs::create_dir_all(&self.cfg.cache_dir)
            .map_err(|e| format!("create cache dir: {e}"))?;

        if let Some((chain_pem, key_pem)) = read_cached_bundle(&self.cfg.cache_dir) {
            match bundle_not_after(&chain_pem) {
                Ok(not_after) if not_after > now_secs() + RENEW_LEAD_SECS => {
                    info!(not_after, "ACME DNS-01: serving cached certificate");
                    match self.install(&chain_pem, &key_pem) {
                        Ok(()) => return Ok(Some(not_after - now_secs())),
                        Err(e) => {
                            warn!(error = %e, "ACME DNS-01: cached certificate could not be installed; keeping current acceptor");
                            return Ok(None);
                        }
                    }
                }
                Ok(not_after) => {
                    warn!(
                        not_after,
                        "ACME DNS-01: cached certificate expires soon; re-issuing"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "ACME DNS-01: cached certificate unparsable; re-issuing")
                }
            }
        }

        let bundle = self.issue().await?;
        write_cached_bundle(&self.cfg.cache_dir, &bundle)?;
        match self.install(&bundle.chain_pem, &bundle.leaf_key_pem) {
            Ok(()) => Ok(Some(bundle.not_after_secs - now_secs())),
            Err(e) => {
                warn!(error = %e, "ACME DNS-01: issued certificate could not be installed; keeping previous acceptor");
                Ok(None)
            }
        }
    }

    fn install(&self, chain_pem: &str, key_pem: &str) -> Result<(), String> {
        let acceptor = crate::tls::static_server_config(chain_pem.as_bytes(), key_pem.as_bytes())
            .map_err(|e| format!("install certificate: {e}"))?;
        self.slot.set(acceptor);
        info!("ACME DNS-01: new certificate installed");
        Ok(())
    }

    /// Run one full ACME DNS-01 order. TXT records are always cleared before
    /// returning, success or failure.
    async fn issue(&self) -> Result<IssuedBundle, String> {
        let mut written: Vec<(Arc<dyn Dns01Provider>, String)> = Vec::new();
        let result = self.issue_inner(&mut written).await;
        for (provider, base) in &written {
            if let Err(e) = provider.clear_challenge(base).await {
                warn!(error = %e, base, "ACME DNS-01: failed to clear TXT record");
            }
        }
        result
    }

    async fn issue_inner(
        &self,
        written: &mut Vec<(Arc<dyn Dns01Provider>, String)>,
    ) -> Result<IssuedBundle, String> {
        let account_der = load_or_create_account_key(&self.cfg.cache_dir)?;
        let mut session = AcmeSession::new(
            self.cfg.http.clone(),
            self.cfg.directory_url.clone(),
            account_der,
            self.cfg.contact_email.clone(),
        )
        .await?;
        session.ensure_account().await?;

        let (order_url, order) = session.new_order(&self.cfg.domains).await?;
        if order.authorizations.is_empty() {
            return Err("ACME order returned no authorizations".into());
        }

        // Collect the DNS-01 challenges and write the TXT records.
        let mut pending: Vec<PendingChallenge> = Vec::new();
        for authz_url in &order.authorizations {
            let auth = session.auth(authz_url).await?;
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.typ == "dns-01")
                .ok_or_else(|| {
                    format!(
                        "no dns-01 challenge offered for {} (got: {})",
                        auth.identifier.value,
                        auth.challenges
                            .iter()
                            .map(|c| c.typ.clone())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            let base = auth.identifier.value.trim_start_matches("*.").to_string();
            let value = session.dns01_txt_value(&challenge.token)?;
            pending.push(PendingChallenge {
                base: base.clone(),
                value,
                authz_url: authz_url.clone(),
                challenge_url: challenge.url.clone(),
            });
        }

        for p in &pending {
            self.cfg
                .provider
                .write_challenge(&p.base, &p.value)
                .await
                .map_err(|e| format!("TXT write failed for {}: {e}", p.base))?;
            written.push((self.cfg.provider.clone(), p.base.clone()));
        }

        info!(
            challenges = pending.len(),
            "ACME DNS-01: TXT records written; waiting for DNS propagation"
        );
        if !self.cfg.propagation_delay.is_zero() {
            tokio::time::sleep(self.cfg.propagation_delay).await;
        }

        // Ask the CA to validate each authorization.
        for p in &pending {
            session.trigger(&p.challenge_url).await?;
        }

        // Poll the authorizations until they are all valid.
        let deadline = Instant::now() + self.cfg.max_wait;
        loop {
            let mut all_valid = true;
            for p in &pending {
                let auth = session.auth(&p.authz_url).await?;
                match auth.status.as_str() {
                    "valid" => {}
                    "pending" => all_valid = false,
                    other => {
                        return Err(format!(
                            "authorization for {} became {other}",
                            auth.identifier.value
                        ));
                    }
                }
            }
            if all_valid {
                break;
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for DNS-01 authorizations".into());
            }
            tokio::time::sleep(self.cfg.poll_interval).await;
        }

        // Order should be ready now; finalize with a fresh leaf key + CSR.
        let order = session.order(&order_url).await?;
        if order.status != "ready" && order.status != "pending" {
            return Err(format!(
                "order not ready after validation (status: {})",
                order.status
            ));
        }
        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf keygen: {e}"))?;
        let csr = build_csr(&self.cfg.domains, &leaf_key)?;
        session.finalize(&order.finalize, &csr).await?;

        // Poll until the order is valid and the certificate URL appears.
        let deadline = Instant::now() + self.cfg.max_wait;
        let cert_url = loop {
            let o = session.order(&order_url).await?;
            match o.status.as_str() {
                "valid" => break o.certificate.ok_or("order valid but no certificate URL")?,
                "invalid" => return Err("order became invalid after finalize".into()),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for order to become valid".into());
            }
            tokio::time::sleep(self.cfg.poll_interval).await;
        };

        let chain_pem = session.certificate(&cert_url).await?;
        let not_after = bundle_not_after(&chain_pem)?;
        info!(
            not_after,
            domains = ?self.cfg.domains,
            "ACME DNS-01: certificate issued"
        );
        Ok(IssuedBundle {
            chain_pem,
            leaf_key_pem: leaf_key.serialize_pem(),
            not_after_secs: not_after,
        })
    }
}

// ---------------------------------------------------------------------------
// ACME wire protocol
// ---------------------------------------------------------------------------

/// JWK parts needed for account registration and thumbprints.
struct JwkParts {
    x: String,
    y: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryDto {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrderDto {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct IdentifierDto {
    #[serde(rename = "type")]
    _typ: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthDto {
    status: String,
    identifier: IdentifierDto,
    challenges: Vec<ChallengeDto>,
}

#[derive(Deserialize)]
struct ChallengeDto {
    #[serde(rename = "type")]
    typ: String,
    url: String,
    token: String,
}

/// ACME session: directory + account key + account URL, nonce handled per
/// request (HEAD `newNonce` before each signed POST).
struct AcmeSession {
    http: Client,
    directory: DirectoryDto,
    signing_key: p256::ecdsa::SigningKey,
    jwk: JwkParts,
    kid: Option<String>,
    contact: Option<String>,
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<JwkBody<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

#[derive(Serialize)]
struct JwkBody<'a> {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: &'a str,
    y: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThumbBody<'a> {
    crv: &'static str,
    kty: &'static str,
    x: &'a str,
    y: &'a str,
}

fn b64url(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse the not-after of the first certificate in a PEM chain.
pub fn bundle_not_after(chain_pem: &str) -> Result<i64, String> {
    use x509_parser::prelude::FromDer;
    let der = rustls_pemfile::certs(&mut chain_pem.as_bytes())
        .next()
        .ok_or("no certificates in PEM chain")?
        .map_err(|e| format!("PEM parse: {e}"))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
        .map_err(|e| format!("cert parse: {e}"))?;
    Ok(cert.validity().not_after.timestamp())
}

fn jwk_parts(sk: &p256::ecdsa::SigningKey) -> JwkParts {
    let point = sk.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes(); // 0x04 || X || Y (33..=65)
    JwkParts {
        x: b64url(&bytes[1..33]),
        y: b64url(&bytes[33..]),
    }
}

/// RFC 7638 JWK thumbprint of the account key.
fn account_thumbprint(jwk: &JwkParts) -> String {
    // Field order matters for the SHA-256 over the canonical JSON.
    let body = serde_json::to_vec(&ThumbBody {
        crv: "P-256",
        kty: "EC",
        x: &jwk.x,
        y: &jwk.y,
    })
    .expect("thumb json");
    b64url(&Sha256::digest(&body))
}

/// DNS-01 TXT digest for a challenge token (RFC 8555 §8.4):
/// keyAuthorization = token "." thumbprint; digest = base64url(SHA-256(keyAuthorization)).
fn dns01_txt_digest(jwk: &JwkParts, token: &str) -> String {
    let key_auth = format!("{token}.{}", account_thumbprint(jwk));
    b64url(&Sha256::digest(key_auth.as_bytes()))
}

/// Compute the DNS-01 TXT digest for an account key (PKCS#8 DER) and token.
/// Public so integration tests can derive expected record values.
pub fn dns01_txt_for_key(account_der: &[u8], token: &str) -> Result<String, String> {
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(account_der)
        .map_err(|e| format!("account key parse: {e}"))?;
    Ok(dns01_txt_digest(&jwk_parts(&signing_key), token))
}

impl AcmeSession {
    async fn new(
        http: Client,
        directory_url: String,
        account_der: Vec<u8>,
        contact: Option<String>,
    ) -> Result<Self, String> {
        let resp = http
            .get(&directory_url)
            .send()
            .await
            .map_err(|e| format!("ACME directory fetch failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("ACME directory returned {}", resp.status()));
        }
        let directory: DirectoryDto = resp
            .json()
            .await
            .map_err(|e| format!("ACME directory parse: {e}"))?;
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&account_der)
            .map_err(|e| format!("account key parse: {e}"))?;
        let jwk = jwk_parts(&signing_key);
        Ok(Self {
            http,
            directory,
            signing_key,
            jwk,
            kid: None,
            contact,
        })
    }

    async fn nonce(&self) -> Result<String, String> {
        let resp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await
            .map_err(|e| format!("nonce fetch failed: {e}"))?;
        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| "ACME newNonce response missing Replay-Nonce".into())
    }

    fn jws_body(
        &self,
        kid: Option<&str>,
        nonce: &str,
        url: &str,
        payload: &str,
    ) -> Result<String, String> {
        let jwk_body = kid.is_none().then(|| JwkBody {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: &self.jwk.x,
            y: &self.jwk.y,
        });
        let protected = serde_json::to_string(&ProtectedHeader {
            alg: "ES256",
            jwk: jwk_body,
            kid,
            nonce,
            url,
        })
        .map_err(|e| format!("protected header json: {e}"))?;
        let protected_b64 = b64url(protected.as_bytes());
        let payload_b64 = b64url(payload.as_bytes());
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let digest = Sha256::digest(signing_input.as_bytes());
        let signature =
            <p256::ecdsa::SigningKey as PrehashSigner<p256::ecdsa::Signature>>::sign_prehash(
                &self.signing_key,
                &digest,
            )
            .map_err(|e| format!("ES256 sign: {e}"))?;
        let body = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(signature.to_bytes().as_slice()),
        });
        Ok(body.to_string())
    }

    /// One signed POST with a badNonce retry. Returns the 2xx response.
    async fn signed_post(&self, url: &str, payload: &str) -> Result<Response, String> {
        let mut attempt = 0;
        loop {
            let nonce = self.nonce().await?;
            let body = self.jws_body(self.kid.as_deref(), &nonce, url, payload)?;
            let resp = self
                .http
                .post(url)
                .header("Content-Type", "application/jose+json")
                .body(body)
                .send()
                .await
                .map_err(|e| format!("ACME POST {url} failed: {e}"))?;
            if resp.status().is_success() {
                return Ok(resp);
            }
            attempt += 1;
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if attempt < 2 && text.contains("badNonce") {
                warn!("ACME badNonce; retrying once");
                continue;
            }
            return Err(problem_message(status, &text, url));
        }
    }

    async fn ensure_account(&mut self) -> Result<String, String> {
        let payload = match &self.contact {
            Some(email) => serde_json::json!({
                "termsOfServiceAgreed": true,
                "contact": [format!("mailto:{email}")],
            }),
            None => serde_json::json!({ "termsOfServiceAgreed": true }),
        };
        let resp = self
            .signed_post(&self.directory.new_account, &payload.to_string())
            .await?;
        let kid = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or("ACME newAccount response missing Location header")?;
        self.kid = Some(kid.clone());
        Ok(kid)
    }

    /// Create a new order for the identifiers; returns (order URL, order).
    async fn new_order(&self, domains: &[String]) -> Result<(String, OrderDto), String> {
        let identifiers: Vec<serde_json::Value> = domains
            .iter()
            .map(|d| serde_json::json!({ "type": "dns", "value": d }))
            .collect();
        let payload = serde_json::json!({ "identifiers": identifiers }).to_string();
        let resp = self
            .signed_post(&self.directory.new_order, &payload)
            .await?;
        let url = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or("ACME newOrder response missing Location header")?;
        let order: OrderDto = resp.json().await.map_err(|e| format!("order parse: {e}"))?;
        Ok((url, order))
    }

    /// POST-as-GET an authorization.
    async fn auth(&self, url: &str) -> Result<AuthDto, String> {
        let resp = self.signed_post(url, "").await?;
        resp.json().await.map_err(|e| format!("authz parse: {e}"))
    }

    /// POST-as-GET the order resource.
    async fn order(&self, url: &str) -> Result<OrderDto, String> {
        let resp = self.signed_post(url, "").await?;
        resp.json().await.map_err(|e| format!("order parse: {e}"))
    }

    /// Ask the CA to validate a challenge.
    async fn trigger(&self, url: &str) -> Result<(), String> {
        self.signed_post(url, "{}").await?;
        Ok(())
    }

    /// Submit the CSR; returns the order body (processing/pending/valid).
    async fn finalize(&self, url: &str, csr_der: &[u8]) -> Result<OrderDto, String> {
        let payload = serde_json::json!({ "csr": b64url(csr_der) }).to_string();
        let resp = self.signed_post(url, &payload).await?;
        resp.json()
            .await
            .map_err(|e| format!("finalize parse: {e}"))
    }

    /// Download the PEM certificate chain (POST-as-GET on the certificate URL).
    async fn certificate(&self, url: &str) -> Result<String, String> {
        let resp = self.signed_post(url, "").await?;
        resp.text()
            .await
            .map_err(|e| format!("certificate read: {e}"))
    }

    pub fn dns01_txt_value(&self, token: &str) -> Result<String, String> {
        Ok(dns01_txt_digest(&self.jwk, token))
    }
}

fn problem_message(status: StatusCode, text: &str, url: &str) -> String {
    let detail = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v["detail"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| text.chars().take(300).collect());
    format!("ACME {url} failed with {status}: {detail}")
}

// ---------------------------------------------------------------------------
// Cache + key helpers
// ---------------------------------------------------------------------------

fn cache_path(dir: &Path, name: &str) -> std::path::PathBuf {
    dir.join(name)
}

fn load_or_create_account_key(cache_dir: &Path) -> Result<Vec<u8>, String> {
    let path = cache_path(cache_dir, CACHE_ACCOUNT_KEY);
    if let Ok(der) = std::fs::read(&path) {
        // Validate it parses as a P-256 key before trusting it.
        p256::ecdsa::SigningKey::from_pkcs8_der(&der)
            .map_err(|e| format!("cached account key unparsable: {e}"))?;
        return Ok(der);
    }
    let key = KeyPair::generate().map_err(|e| format!("account keygen: {e}"))?;
    let der = key.serialize_der();
    write_private_file(&path, &der)?;
    Ok(der)
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn read_cached_bundle(cache_dir: &Path) -> Option<(String, String)> {
    let cert = std::fs::read_to_string(cache_path(cache_dir, CACHE_CERT)).ok()?;
    let key = std::fs::read_to_string(cache_path(cache_dir, CACHE_KEY)).ok()?;
    Some((cert, key))
}

fn write_cached_bundle(cache_dir: &Path, bundle: &IssuedBundle) -> Result<(), String> {
    let cert_path = cache_path(cache_dir, CACHE_CERT);
    let key_path = cache_path(cache_dir, CACHE_KEY);
    std::fs::write(&cert_path, &bundle.chain_pem)
        .map_err(|e| format!("write {}: {e}", cert_path.display()))?;
    write_private_file(&key_path, bundle.leaf_key_pem.as_bytes())?;
    Ok(())
}

/// Build a PKCS#10 CSR for the domains with the given leaf key.
pub fn build_csr(domains: &[String], key: &KeyPair) -> Result<Vec<u8>, String> {
    let mut params =
        CertificateParams::new(domains.to_vec()).map_err(|e| format!("csr params: {e}"))?;
    if let Some(first) = domains.first() {
        let cn = first.trim_start_matches("*.");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
    }
    let csr = params
        .serialize_request(key)
        .map_err(|e| format!("csr serialize: {e}"))?;
    Ok(csr.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8555 §8.4 known-answer: fixed P-256 account key (scalar
    /// 0x01..0x20) derived independently with python-cryptography.
    /// Account PKCS#8 DER and expected TXT digest below.
    const ACCOUNT_DER_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a14403420004515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";
    const TOKEN: &str = "mytesttoken123";
    const EXPECTED_DIGEST: &str = "2UvLveSfRqGJcR47GCio8_7BJSlTm2lunYbO0iiPfk0";
    const EXPECTED_THUMB: &str = "6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM";

    #[test]
    fn dns01_txt_known_answer() {
        let der = hex::decode(ACCOUNT_DER_HEX).expect("der hex");
        let digest = dns01_txt_for_key(&der, TOKEN).expect("digest");
        assert_eq!(digest, EXPECTED_DIGEST);
        assert_eq!(digest.len(), 43, "base64url sha256 digest length");
    }

    #[test]
    fn thumbprint_known_answer() {
        let der = hex::decode(ACCOUNT_DER_HEX).expect("der hex");
        let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&der).expect("parse");
        assert_eq!(account_thumbprint(&jwk_parts(&sk)), EXPECTED_THUMB);
    }

    #[test]
    fn distinct_tokens_produce_distinct_digests() {
        let der = hex::decode(ACCOUNT_DER_HEX).expect("der hex");
        let a = dns01_txt_for_key(&der, "token-a").unwrap();
        let b = dns01_txt_for_key(&der, "token-b").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn csr_carries_apex_and_wildcard_sans() {
        use x509_parser::prelude::FromDer;
        let key = KeyPair::generate().unwrap();
        let csr = build_csr(
            &["tunnel.example.com".into(), "*.tunnel.example.com".into()],
            &key,
        )
        .unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
        let mut sans: Vec<String> = Vec::new();
        if let Some(exts) = csr.requested_extensions() {
            for ext in exts {
                if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext {
                    for g in &san.general_names {
                        sans.push(g.to_string());
                    }
                }
            }
        }
        assert!(
            sans.iter()
                .any(|s| s.contains("tunnel.example.com") && !s.contains('*')),
            "SANs: {sans:?}"
        );
        assert!(
            sans.iter().any(|s| s.contains("*.tunnel.example.com")),
            "SANs: {sans:?}"
        );
    }

    #[test]
    fn cache_roundtrip_preserves_cert_and_key() {
        use rcgen::CertificateParams;
        let dir = std::env::temp_dir().join(format!("ddns-acme-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["a.test".into(), "*.a.test".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let bundle = IssuedBundle {
            chain_pem: cert.pem(),
            leaf_key_pem: key.serialize_pem(),
            not_after_secs: bundle_not_after(&cert.pem()).unwrap(),
        };
        write_cached_bundle(&dir, &bundle).unwrap();
        let (chain, key_pem) = read_cached_bundle(&dir).expect("cache read");
        assert_eq!(chain, bundle.chain_pem);
        assert_eq!(key_pem, bundle.leaf_key_pem);
        let not_after = bundle_not_after(&chain).unwrap();
        assert!(not_after > now_secs());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_key_reused_across_loads() {
        let dir = std::env::temp_dir().join(format!("ddns-acme-acct-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = load_or_create_account_key(&dir).unwrap();
        let second = load_or_create_account_key(&dir).unwrap();
        assert_eq!(first, second, "account key must persist across restarts");
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Minimal hex decoder (avoids a dev-dependency for the test vector).
#[cfg(test)]
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = nibble(bytes[i])?;
            let lo = nibble(bytes[i + 1])?;
            out.push(hi << 4 | lo);
            i += 2;
        }
        Ok(out)
    }
    fn nibble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(format!("bad hex: {}", b as char)),
        }
    }
}
