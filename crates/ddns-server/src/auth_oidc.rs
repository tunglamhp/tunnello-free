//! Generic OIDC provider client: discovery (1 h cache), PKCE S256,
//! authorization-code exchange, id_token email claim. Broker-wide config
//! via DDNS_OIDC_ISSUER / DDNS_OIDC_CLIENT_ID / DDNS_OIDC_CLIENT_SECRET.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
}

impl OidcConfig {
    pub fn from_env() -> Option<Self> {
        let (issuer, client_id, client_secret) = (
            std::env::var("DDNS_OIDC_ISSUER").ok()?,
            std::env::var("DDNS_OIDC_CLIENT_ID").ok()?,
            std::env::var("DDNS_OIDC_CLIENT_SECRET").ok()?,
        );
        Some(Self {
            issuer,
            client_id,
            client_secret,
        })
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Discovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

pub struct OidcClient {
    http: reqwest::Client,
    cache: RwLock<Option<(Instant, Discovery)>>,
}

const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

impl Default for OidcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcClient {
    pub fn new() -> Self {
        // reqwest is built with `rustls-tls-no-provider`; install the process
        // default if nothing else did (idempotent; first installer wins).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        Self {
            http: reqwest::Client::new(),
            cache: RwLock::new(None),
        }
    }

    /// Fetch (or serve from the 1 h cache) `{issuer}/.well-known/openid-configuration`.
    pub async fn discover(&self, cfg: &OidcConfig) -> Result<Discovery, String> {
        if let Some((at, d)) = self.cache.read().await.as_ref()
            && at.elapsed() < DISCOVERY_TTL
        {
            return Ok(d.clone());
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            cfg.issuer.trim_end_matches('/')
        );
        let d: Discovery = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("discovery fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discovery parse failed: {e}"))?;
        *self.cache.write().await = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    /// Authorization-code exchange (confidential client: client_secret in form).
    pub async fn exchange(
        &self,
        cfg: &OidcConfig,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<String, String> {
        let d = self.discover(cfg).await?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &cfg.client_id),
            ("client_secret", &cfg.client_secret),
            ("code_verifier", verifier),
        ];
        let resp: serde_json::Value = self
            .http
            .post(&d.token_endpoint)
            .form(&form)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("token exchange failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("token response parse failed: {e}"))?;
        resp.get("id_token")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("no id_token in response: {resp}"))
    }
}

/// (verifier, challenge) — challenge = BASE64URL-UNPADDED(SHA256(verifier)).
pub fn pkce_pair() -> (String, String) {
    let mut bytes = [0u8; 48]; // → 64 b64url chars
    rand::rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Pull the `email` claim from a JWT payload. No signature check here — the
/// token arrived straight from the provider's token_endpoint over TLS.
pub fn email_from_id_token(jwt: &str) -> Option<String> {
    let mut parts = jwt.split('.');
    let _hdr = parts.next()?;
    let payload = parts.next()?;
    let _sig = parts.next()?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("email")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_pair_is_url_safe_and_challenge_matches() {
        let (v, c) = pkce_pair();
        assert!((43..=128).contains(&v.len()));
        assert!(v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()));
        assert_eq!(c, expect);
    }

    #[test]
    fn email_extracted_from_id_token_payload() {
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"x","email":"u@d.e"}"#);
        let jwt = format!("hdr.{payload}.sig");
        assert_eq!(email_from_id_token(&jwt).as_deref(), Some("u@d.e"));
        assert_eq!(email_from_id_token("not-a-jwt"), None);
    }

    #[tokio::test]
    async fn discovery_parses_mock_issuer() {
        let app = axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({
                    "authorization_endpoint": "http://auth/authorize",
                    "token_endpoint": "http://auth/token",
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = OidcConfig {
            issuer: url.clone(),
            client_id: "cid".into(),
            client_secret: "sec".into(),
        };
        let d = OidcClient::new().discover(&cfg).await.unwrap();
        assert_eq!(d.authorization_endpoint, "http://auth/authorize");
        assert_eq!(d.token_endpoint, "http://auth/token");
    }
}
