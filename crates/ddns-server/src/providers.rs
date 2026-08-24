//! DNS-01 challenge providers (spec §5). `ManualTxt` records pending
//! challenges for the operator to paste (dashboard); `Cloudflare` writes TXT
//! records via the Cloudflare API v4. Route53/DuckDNS are deferred (v2).
//!
//! Deviation from brief: rustls-acme 0.12.1 does not expose a `Dns01Solver`
//! trait or `.dns01_solver()`/`.http01_solver()` builder methods on
//! `AcmeConfig`. We implement our own provider trait and use the library's
//! built-in TLS-ALPN-01 validation for certificate issuance. The DNS-01
//! providers are wired for testing and the manual flow; full DNS-01 ACME
//! integration will use the lower-level `rustls_acme::acme` module in a
//! follow-up when DNS-01 is required (most deployments will use TLS-ALPN-01
//! on port 443, which rustls-acme handles automatically).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;

/// Pending `_acme-challenge` TXT values, keyed by challenge domain. Shared by
/// the DNS solver (manual provider), the HTTP-01 solver, and the dashboard.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    pending: Mutex<HashMap<String, String>>,
}

impl ChallengeStore {
    pub fn write(&self, domain: &str, value: &str) {
        self.pending
            .lock()
            .unwrap()
            .insert(domain.to_string(), value.to_string());
    }
    pub fn clear(&self, domain: &str) {
        self.pending.lock().unwrap().remove(domain);
    }
    pub fn get(&self, domain: &str) -> Option<String> {
        self.pending.lock().unwrap().get(domain).cloned()
    }
    #[allow(dead_code)]
    pub fn all(&self) -> Vec<(String, String)> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
    /// HTTP-01 challenge tokens use `http01:<token>` as key.
    pub fn write_http01(&self, token: &str, key_auth: &str) {
        self.write(&format!("http01:{token}"), key_auth);
    }
    pub fn get_http01(&self, token: &str) -> Option<String> {
        self.get(&format!("http01:{token}"))
    }
    #[allow(dead_code)]
    pub fn clear_http01(&self, token: &str) {
        self.clear(&format!("http01:{token}"));
    }
}

/// DNS-01 challenge provider trait. Implementors write and clear TXT records
/// for `_acme-challenge.<domain>`.
pub trait Dns01Provider: Send + Sync + std::fmt::Debug {
    /// Write a TXT record. Called before the ACME server validates.
    fn write_challenge(
        &self,
        domain: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
    /// Remove the TXT record after validation.
    fn clear_challenge(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Manual-TXT provider: record the challenge; the operator copies it from the
/// dashboard and pastes it into their DNS provider.
#[derive(Debug)]
pub struct ManualTxt {
    pub store: Arc<ChallengeStore>,
}

impl Dns01Provider for ManualTxt {
    async fn write_challenge(&self, domain: &str, value: &str) -> Result<(), String> {
        self.store.write(domain, value);
        tracing::info!(
            domain,
            value,
            "DNS-01 challenge — add this TXT record to _acme-challenge.{domain}"
        );
        Ok(())
    }
    async fn clear_challenge(&self, domain: &str) -> Result<(), String> {
        self.store.clear(domain);
        tracing::info!(
            domain,
            "DNS-01 challenge cleared for _acme-challenge.{domain}"
        );
        Ok(())
    }
}

/// Cloudflare provider: PUT/DELETE a TXT record on the zone via the Cloudflare
/// API v4.
///
/// `base_url` defaults to `https://api.cloudflare.com/client/v4`; tests
/// override it with a mock server.
pub struct Cloudflare {
    pub store: Arc<ChallengeStore>,
    pub api_token: String,
    pub zone_id: String,
    pub base_url: String,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
    record_ids: Mutex<HashMap<String, String>>,
}

impl std::fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cloudflare")
            .field("store", &self.store)
            .field("api_token", &"[redacted]")
            .field("zone_id", &self.zone_id)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Cloudflare {
    pub fn new(api_token: String, zone_id: String, base_url: String) -> Self {
        Self {
            store: Arc::default(),
            api_token,
            zone_id,
            base_url,
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http(),
            record_ids: Mutex::new(HashMap::new()),
        }
    }

    async fn create_txt(&self, name: &str, content: &str) -> Result<String, String> {
        let url = format!("{}/zones/{}/dns_records", self.base_url, self.zone_id);
        let body = serde_json::json!({
            "type": "TXT",
            "name": name,
            "content": content,
            "ttl": 60
        });
        let req = hyper::Request::post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| format!("Cloudflare request build error: {e}"))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Cloudflare API error: {e}"))?;
        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Cloudflare read error: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "Cloudflare API returned {status}: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Cloudflare JSON parse error: {e}"))?;
        if v["success"] != true {
            return Err(format!(
                "Cloudflare API error: {}",
                serde_json::to_string(&v["errors"]).unwrap_or_default()
            ));
        }
        let id = v["result"]["id"]
            .as_str()
            .ok_or("Cloudflare response missing result.id")?
            .to_string();
        Ok(id)
    }

    async fn delete_txt(&self, record_id: &str) -> Result<(), String> {
        let url = format!(
            "{}/zones/{}/dns_records/{record_id}",
            self.base_url, self.zone_id
        );
        let req = hyper::Request::delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .body(Full::new(Bytes::new()))
            .map_err(|e| format!("Cloudflare request build error: {e}"))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Cloudflare API error: {e}"))?;
        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Cloudflare read error: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "Cloudflare DELETE returned {status}: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Cloudflare JSON parse error: {e}"))?;
        if v["success"] != true {
            return Err(format!(
                "Cloudflare DELETE error: {}",
                serde_json::to_string(&v["errors"]).unwrap_or_default()
            ));
        }
        Ok(())
    }
}

impl Dns01Provider for Cloudflare {
    async fn write_challenge(&self, domain: &str, value: &str) -> Result<(), String> {
        let name = format!("_acme-challenge.{domain}");
        let id = self.create_txt(&name, value).await?;
        self.record_ids
            .lock()
            .unwrap()
            .insert(domain.to_string(), id);
        self.store.write(domain, value);
        Ok(())
    }
    async fn clear_challenge(&self, domain: &str) -> Result<(), String> {
        let id = {
            let mut ids = self.record_ids.lock().unwrap();
            ids.remove(domain)
        };
        if let Some(id) = id {
            self.delete_txt(&id).await?;
        }
        self.store.clear(domain);
        Ok(())
    }
}
