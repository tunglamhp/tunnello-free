//! DNS-01 challenge providers (spec §5). `ManualTxt` records pending
//! challenges for the operator to paste (dashboard); `Cloudflare` writes TXT
//! records via the Cloudflare API v4; `Porkbun` via the Porkbun DNS API v3.
//!
//! Both DNS providers are driven by the DNS-01 issuance engine (`dns_acme`),
//! which requests the apex plus its wildcard in a single order — the two
//! authorizations share the `_acme-challenge.<apex>` TXT name with different
//! values, so providers track created records per domain (not one id each).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use parking_lot::Mutex;

/// Boxed async result of a DNS-01 provider call (keeps `Dns01Provider` dyn-compatible).
pub type ProviderFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

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
            .insert(domain.to_string(), value.to_string());
    }
    pub fn clear(&self, domain: &str) {
        self.pending.lock().remove(domain);
    }
    pub fn get(&self, domain: &str) -> Option<String> {
        self.pending.lock().get(domain).cloned()
    }
    #[allow(dead_code)]
    pub fn all(&self) -> Vec<(String, String)> {
        self.pending
            .lock()
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
/// for `_acme-challenge.<domain>`. Boxed futures (not RPITIT) keep the trait
/// dyn-compatible so the issuance engine can hold `Arc<dyn Dns01Provider>`.
pub trait Dns01Provider: Send + Sync + std::fmt::Debug {
    /// Write a TXT record. Called before the ACME server validates.
    fn write_challenge(&self, domain: &str, value: &str) -> ProviderFuture<'_>;
    /// Remove the TXT record after validation.
    fn clear_challenge(&self, domain: &str) -> ProviderFuture<'_>;
}

/// Manual-TXT provider: record the challenge; the operator copies it from the
/// dashboard and pastes it into their DNS provider.
#[derive(Debug)]
pub struct ManualTxt {
    pub store: Arc<ChallengeStore>,
}

impl Dns01Provider for ManualTxt {
    fn write_challenge(&self, domain: &str, value: &str) -> ProviderFuture<'_> {
        let domain = domain.to_string();
        let value = value.to_string();
        Box::pin(async move {
            self.store.write(&domain, &value);
            tracing::info!(
                domain,
                value,
                "DNS-01 challenge — add this TXT record to _acme-challenge.{domain}"
            );
            Ok(())
        })
    }
    fn clear_challenge(&self, domain: &str) -> ProviderFuture<'_> {
        let domain = domain.to_string();
        Box::pin(async move {
            self.store.clear(&domain);
            tracing::info!(
                domain,
                "DNS-01 challenge cleared for _acme-challenge.{domain}"
            );
            Ok(())
        })
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
    /// Created record ids per challenge domain. A wildcard order writes two
    /// TXT records on the same `_acme-challenge.<apex>` name (apex + wildcard
    /// authorizations), so each domain maps to a list.
    record_ids: Mutex<HashMap<String, Vec<String>>>,
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
    /// Production API base URL (tests construct with a mock base URL).
    pub const API_BASE: &'static str = "https://api.cloudflare.com/client/v4";

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
    fn write_challenge(&self, domain: &str, value: &str) -> ProviderFuture<'_> {
        let name = format!("_acme-challenge.{domain}");
        let domain = domain.to_string();
        let value = value.to_string();
        let this = self;
        Box::pin(async move {
            let id = this.create_txt(&name, &value).await?;
            this.record_ids
                .lock()
                .entry(domain.clone())
                .or_default()
                .push(id);
            this.store.write(&domain, &value);
            Ok(())
        })
    }
    fn clear_challenge(&self, domain: &str) -> ProviderFuture<'_> {
        let domain = domain.to_string();
        let this = self;
        Box::pin(async move {
            let ids = {
                let mut ids = this.record_ids.lock();
                ids.remove(&domain).unwrap_or_default()
            };
            for id in ids {
                this.delete_txt(&id).await?;
            }
            this.store.clear(&domain);
            Ok(())
        })
    }
}

/// Porkbun provider: POST TXT create/delete via the Porkbun DNS API v3.
///
/// `zone` is the registered apex domain (e.g. `example.com`) — the broker's
/// `--domain`. `base_url` defaults to the production API; tests override it
/// with a mock server. Challenge names are always `_acme-challenge.<base>`,
/// and the API host field is that name with the `.<zone>` suffix removed.
pub struct Porkbun {
    pub store: Arc<ChallengeStore>,
    pub api_key: String,
    pub secret: String,
    pub zone: String,
    pub base_url: String,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
    record_ids: Mutex<HashMap<String, Vec<String>>>,
}

impl std::fmt::Debug for Porkbun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Porkbun")
            .field("store", &self.store)
            .field("api_key", &"[redacted]")
            .field("secret", &"[redacted]")
            .field("zone", &self.zone)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Porkbun {
    /// Production API base URL (tests construct with a mock base URL).
    pub const API_BASE: &'static str = "https://api.porkbun.com/api/json/v3";

    pub fn new(api_key: String, secret: String, zone: String, base_url: String) -> Self {
        Self {
            store: Arc::default(),
            api_key,
            secret,
            zone,
            base_url,
            client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http(),
            record_ids: Mutex::new(HashMap::new()),
        }
    }

    fn zone_suffix(&self) -> String {
        format!(".{}", self.zone.trim_end_matches('.'))
    }

    /// Map a full record name (`_acme-challenge.example.com`) to the Porkbun
    /// `host` field (the label(s) left of the registered zone).
    fn host_for(&self, name: &str) -> Result<String, String> {
        let suffix = self.zone_suffix();
        let name = name.trim_end_matches('.');
        if let Some(host) = name.strip_suffix(&suffix) {
            Ok(host.to_string())
        } else {
            Err(format!(
                "record name {name} is not under zone {}",
                self.zone
            ))
        }
    }

    async fn create_txt(&self, name: &str, content: &str) -> Result<String, String> {
        let url = format!("{}/dns/create/{}", self.base_url, self.zone);
        let body = serde_json::json!({
            "secretapikey": self.secret,
            "apikey": self.api_key,
            "name": self.host_for(name)?,
            "type": "TXT",
            "content": content,
            "ttl": "60",
        });
        let req = hyper::Request::post(&url)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| format!("Porkbun request build error: {e}"))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Porkbun API error: {e}"))?;
        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Porkbun read error: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "Porkbun API returned {status}: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Porkbun JSON parse error: {e}"))?;
        if v["status"] != "SUCCESS" {
            return Err(format!(
                "Porkbun API error: {}",
                serde_json::to_string(&v["message"]).unwrap_or_default()
            ));
        }
        let id = v["id"]
            .as_str()
            .ok_or("Porkbun response missing id")?
            .to_string();
        Ok(id)
    }

    async fn delete_txt(&self, record_id: &str) -> Result<(), String> {
        let url = format!("{}/dns/delete/{}/{}", self.base_url, self.zone, record_id);
        let body = serde_json::json!({
            "secretapikey": self.secret,
            "apikey": self.api_key,
        });
        let req = hyper::Request::post(&url)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| format!("Porkbun request build error: {e}"))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| format!("Porkbun API error: {e}"))?;
        let status = resp.status();
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Porkbun read error: {e}"))?
            .to_bytes();
        if !status.is_success() {
            return Err(format!(
                "Porkbun DELETE returned {status}: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
        }
        let v: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Porkbun JSON parse error: {e}"))?;
        if v["status"] != "SUCCESS" {
            return Err(format!(
                "Porkbun DELETE error: {}",
                serde_json::to_string(&v["message"]).unwrap_or_default()
            ));
        }
        Ok(())
    }
}

impl Dns01Provider for Porkbun {
    fn write_challenge(&self, domain: &str, value: &str) -> ProviderFuture<'_> {
        let name = format!("_acme-challenge.{domain}");
        let domain = domain.to_string();
        let value = value.to_string();
        let this = self;
        Box::pin(async move {
            let id = this.create_txt(&name, &value).await?;
            this.record_ids
                .lock()
                .entry(domain.clone())
                .or_default()
                .push(id);
            this.store.write(&domain, &value);
            Ok(())
        })
    }
    fn clear_challenge(&self, domain: &str) -> ProviderFuture<'_> {
        let domain = domain.to_string();
        let this = self;
        Box::pin(async move {
            let ids = {
                let mut ids = this.record_ids.lock();
                ids.remove(&domain).unwrap_or_default()
            };
            for id in ids {
                this.delete_txt(&id).await?;
            }
            this.store.clear(&domain);
            Ok(())
        })
    }
}
