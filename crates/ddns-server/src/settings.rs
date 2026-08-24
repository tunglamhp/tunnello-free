//! Operator-editable settings: a flat key/value table persisted in the shared
//! SQLite connection, loaded into a cached [`Settings`] struct at startup and
//! refreshed on save. Also the dashboard IP allowlist matcher (hand-rolled
//! CIDR, no `ipnet` dependency — reuses `http_options::cidr_matches`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;

use ddns_proto::TokenLimits;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;

use crate::session::TunnelSession;
use crate::token::{StoreError, TokenStore};

/// Settings keys (the flat `settings` table). Consumed by later tasks' save
/// handlers and by [`Settings::to_kv`]/[`Settings::from_kv`].
pub const KEY_INSTANCE_NAME: &str = "instance_name";
pub const KEY_SUPPORT_URL: &str = "support_url";
pub const KEY_SESSION_TTL_HOURS: &str = "session_ttl_hours";
pub const KEY_DASHBOARD_IP_ALLOWLIST: &str = "dashboard_ip_allowlist";
pub const KEY_WEBHOOK_URL: &str = "webhook_url";
pub const KEY_WEBHOOK_SECRET: &str = "webhook_secret";
pub const KEY_EMAIL_ALERTS_ENABLED: &str = "email_alerts_enabled";
pub const KEY_DEFAULT_TOKEN_LIMITS: &str = "default_token_limits";
pub const KEY_OTP_PENDING_SECRET: &str = "otp_pending_secret";
pub const KEY_CLIENT_HEARTBEAT_MS: &str = "client_heartbeat_ms";
pub const KEY_TOKEN_PACK_PRICE_ID: &str = "token_pack_price_id";
pub const KEY_TOKEN_PACK_TOKENS: &str = "token_pack_tokens";
pub const KEY_TOKEN_PACK_PRICE_CENTS: &str = "token_pack_price_cents";

/// Runtime settings, cached in `BrokerState` and refreshed on save.
#[derive(Debug, Clone)]
pub struct Settings {
    pub instance_name: String,
    pub support_url: String,
    pub session_ttl_hours: u64,
    pub dashboard_ip_allowlist: Vec<String>,
    pub webhook_url: String,
    pub webhook_secret: String,
    pub email_alerts_enabled: bool,
    pub default_token_limits: TokenLimits,
    pub client_heartbeat_ms: Option<u64>,
    pub token_pack_price_id: String,
    pub token_pack_tokens: i64,
    pub token_pack_price_cents: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            instance_name: "Tunello".into(),
            support_url: String::new(),
            session_ttl_hours: 24,
            dashboard_ip_allowlist: Vec::new(),
            webhook_url: String::new(),
            webhook_secret: String::new(),
            email_alerts_enabled: false,
            default_token_limits: TokenLimits::default(),
            client_heartbeat_ms: None,
            token_pack_price_id: String::new(),
            token_pack_tokens: 100_000,
            token_pack_price_cents: 5,
        }
    }
}

impl Settings {
    /// True when `ip` is permitted by the dashboard allowlist. An empty list
    /// allows everyone; each entry is an exact IP or CIDR (IPv4/IPv6).
    /// A malformed entry only denies that entry (never the whole list).
    pub fn peer_allowed(&self, ip: &IpAddr) -> bool {
        if self.dashboard_ip_allowlist.is_empty() {
            return true;
        }
        // `http_options::cidr_matches` clamps an out-of-range prefix to a
        // full-width mask (a malformed allowlist entry would silently grant a
        // single address in a security allowlist), so reject those first.
        let rules: Vec<String> = self
            .dashboard_ip_allowlist
            .iter()
            .filter(|entry| prefix_in_range(entry))
            .cloned()
            .collect();
        crate::http_options::cidr_matches(*ip, &rules)
    }

    /// Flat key/value rows for the `settings` table.
    fn to_kv(&self) -> Vec<(String, String)> {
        let allowlist = serde_json::to_string(&self.dashboard_ip_allowlist)
            .unwrap_or_else(|_| "[]".to_string());
        let limits =
            serde_json::to_string(&self.default_token_limits).unwrap_or_else(|_| "{}".to_string());
        vec![
            (KEY_INSTANCE_NAME.to_string(), self.instance_name.clone()),
            (KEY_SUPPORT_URL.to_string(), self.support_url.clone()),
            (
                KEY_SESSION_TTL_HOURS.to_string(),
                self.session_ttl_hours.to_string(),
            ),
            (KEY_DASHBOARD_IP_ALLOWLIST.to_string(), allowlist),
            (KEY_WEBHOOK_URL.to_string(), self.webhook_url.clone()),
            (KEY_WEBHOOK_SECRET.to_string(), self.webhook_secret.clone()),
            (
                KEY_EMAIL_ALERTS_ENABLED.to_string(),
                (self.email_alerts_enabled as i64).to_string(),
            ),
            (KEY_DEFAULT_TOKEN_LIMITS.to_string(), limits),
            (
                KEY_CLIENT_HEARTBEAT_MS.to_string(),
                self.client_heartbeat_ms
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
            ),
            (
                KEY_TOKEN_PACK_PRICE_ID.to_string(),
                self.token_pack_price_id.clone(),
            ),
            (
                KEY_TOKEN_PACK_TOKENS.to_string(),
                self.token_pack_tokens.to_string(),
            ),
            (
                KEY_TOKEN_PACK_PRICE_CENTS.to_string(),
                self.token_pack_price_cents.to_string(),
            ),
        ]
    }

    fn from_kv(kv: &HashMap<String, String>) -> Self {
        let mut s = Settings::default();
        if let Some(v) = kv.get(KEY_INSTANCE_NAME) {
            s.instance_name = v.clone();
        }
        if let Some(v) = kv.get(KEY_SUPPORT_URL) {
            s.support_url = v.clone();
        }
        if let Some(v) = kv.get(KEY_SESSION_TTL_HOURS)
            && let Ok(n) = v.parse()
        {
            s.session_ttl_hours = n;
        }
        if let Some(v) = kv.get(KEY_DASHBOARD_IP_ALLOWLIST)
            && let Ok(list) = serde_json::from_str(v)
        {
            s.dashboard_ip_allowlist = list;
        }
        if let Some(v) = kv.get(KEY_WEBHOOK_URL) {
            s.webhook_url = v.clone();
        }
        if let Some(v) = kv.get(KEY_WEBHOOK_SECRET) {
            s.webhook_secret = v.clone();
        }
        if let Some(v) = kv.get(KEY_EMAIL_ALERTS_ENABLED) {
            s.email_alerts_enabled = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Some(v) = kv.get(KEY_DEFAULT_TOKEN_LIMITS)
            && let Ok(l) = serde_json::from_str(v)
        {
            s.default_token_limits = l;
        }
        if let Some(v) = kv.get(KEY_CLIENT_HEARTBEAT_MS)
            && let Ok(n) = v.parse()
        {
            s.client_heartbeat_ms = Some(n);
        }
        if let Some(v) = kv.get(KEY_TOKEN_PACK_PRICE_ID) {
            s.token_pack_price_id = v.clone();
        }
        if let Some(v) = kv.get(KEY_TOKEN_PACK_TOKENS) {
            s.token_pack_tokens = v.parse().unwrap_or(100_000);
        }
        if let Some(v) = kv.get(KEY_TOKEN_PACK_PRICE_CENTS) {
            s.token_pack_price_cents = v.parse().unwrap_or(500);
        }
        s
    }
}
/// How long a webhook POST may take before it is aborted. Fire-and-forget:
/// the session lifecycle never waits on it.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the webhook body: `{event: <event>, <payload fields>}`. The payload
/// is a JSON object whose keys are merged at the top level (a non-object
/// payload is nested under `payload`).
fn webhook_body(event: &str, payload: serde_json::Value) -> String {
    let mut map = match payload {
        serde_json::Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("payload".to_string(), other);
            m
        }
    };
    map.insert(
        "event".to_string(),
        serde_json::Value::String(event.to_string()),
    );
    serde_json::Value::Object(map).to_string()
}

/// `sha256=<lowercase hex HMAC-SHA256 of body>`; `None` when `secret` is
/// empty (unsigned webhooks).
fn webhook_signature(secret: &str, body: &str) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(body.as_bytes());
    Some(format!(
        "sha256={}",
        hex_encode(&mac.finalize().into_bytes())
    ))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// POST an already-serialized + signed webhook body to `url`.
async fn post_webhook(url: &str, body: String, signature: Option<String>) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(body);
    if let Some(sig) = signature {
        req = req.header("X-DDNS-Signature", sig);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("webhook returned {}", resp.status()));
    }
    Ok(())
}

/// Fire-and-forget webhook emission. No-op when `webhook_url` is empty; the
/// POST runs on a spawned task and never blocks the session lifecycle.
pub fn send_webhook(settings: &Settings, event: &str, payload: serde_json::Value) {
    let url = settings.webhook_url.trim().to_string();
    if url.is_empty() {
        return;
    }
    let secret = settings.webhook_secret.clone();
    let body = webhook_body(event, payload);
    let signature = webhook_signature(&secret, &body);
    let event_name = event.to_string();
    tokio::spawn(async move {
        if let Err(e) = post_webhook(&url, body, signature).await {
            tracing::warn!(webhook_event = %event_name, error = %e, "webhook delivery failed");
        }
    });
}

/// Session payload: `{session: {slug, token_id, uptime_secs, streams,
/// bytes_tx, bytes_rx}, server: {domain, max_sessions}}`.
pub fn session_payload(
    session: &TunnelSession,
    domain: &str,
    max_sessions: usize,
) -> serde_json::Value {
    let usage = session.usage();
    serde_json::json!({
        "session": {
            "slug": &session.slug,
            "token_id": &session.token_id,
            "uptime_secs": session.created_at.elapsed().as_secs(),
            "streams": usage.streams,
            "bytes_tx": usage.bytes_tx,
            "bytes_rx": usage.bytes_rx,
        },
        "server": {
            "domain": domain,
            "max_sessions": max_sessions,
        }
    })
}

/// Server-full payload: `{server: {domain, max_sessions}}`.
pub fn server_full_payload(domain: &str, max_sessions: usize) -> serde_json::Value {
    serde_json::json!({
        "server": {
            "domain": domain,
            "max_sessions": max_sessions,
        }
    })
}

/// Token-warning payload: `{level, balance, allowance, account_id}` (80 or 95
/// percent of the monthly allowance consumed).
pub fn token_warning_payload(
    level: &str,
    balance: i64,
    allowance: i64,
    account_id: i64,
) -> serde_json::Value {
    serde_json::json!({
        "level": level,
        "balance": balance,
        "allowance": allowance,
        "account_id": account_id,
    })
}

/// Token-exhausted payload: `{account_id, balance: 0}`.
pub fn token_exhausted_payload(account_id: i64) -> serde_json::Value {
    serde_json::json!({
        "account_id": account_id,
        "balance": 0,
    })
}

/// True when `entry` is a bare IP (no prefix to validate) or its CIDR prefix
/// is within range for its address family. Malformed net/prefix → false.
fn prefix_in_range(entry: &str) -> bool {
    let Some((net, prefix)) = entry.trim().split_once('/') else {
        return true;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match net.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix <= 32,
        Ok(IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

/// Flat key/value settings persistence, sharing the TokenStore's connection.
#[derive(Clone)]
pub struct SettingsStore {
    inner: Arc<SettingsInner>,
}

struct SettingsInner {
    store: TokenStore,
}

impl SettingsStore {
    pub fn open(ts: &TokenStore) -> Self {
        let db = ts.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        crate::schema::ensure_columns(&db).expect("schema migration");
        Self {
            inner: Arc::new(SettingsInner { store: ts.clone() }),
        }
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.inner
            .store
            .db_conn()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Read every stored key; missing keys fall back to [`Settings::default`].
    pub fn load(&self) -> Result<Settings, StoreError> {
        let db = self.db();
        let mut stmt = db.prepare("SELECT key, value FROM settings")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<HashMap<String, String>, rusqlite::Error>>()?;
        Ok(Settings::from_kv(&rows))
    }

    /// Upsert a single key.
    pub fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let db = self.db();
        db.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Read a single key's value (`None` when absent).
    pub fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        Ok(row)
    }

    /// Delete a key (no-op when absent).
    pub fn remove(&self, key: &str) -> Result<(), StoreError> {
        let db = self.db();
        db.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Persist every field of `settings` (the single-pointed write path so the
    /// cache and store never diverge).
    pub fn save(&self, settings: &Settings) -> Result<(), StoreError> {
        let db = self.db();
        for (key, value) in settings.to_kv() {
            db.execute(
                "INSERT INTO settings(key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SettingsStore {
        SettingsStore::open(&TokenStore::new())
    }

    #[test]
    fn defaults_when_absent() {
        let settings = store().load().unwrap();
        assert_eq!(settings.instance_name, "Tunello");
        assert_eq!(settings.support_url, "");
        assert_eq!(settings.session_ttl_hours, 24);
        assert!(settings.dashboard_ip_allowlist.is_empty());
        assert_eq!(settings.webhook_url, "");
        assert_eq!(settings.webhook_secret, "");
        assert!(!settings.email_alerts_enabled);
        assert_eq!(settings.default_token_limits, TokenLimits::default());
        assert_eq!(settings.client_heartbeat_ms, None);
    }

    #[test]
    fn set_then_load_round_trips() {
        let s = store();
        s.set(KEY_INSTANCE_NAME, "Acme Tunnels").unwrap();
        s.set(KEY_SUPPORT_URL, "https://support.example.com")
            .unwrap();
        s.set(KEY_SESSION_TTL_HOURS, "8").unwrap();
        s.set(KEY_EMAIL_ALERTS_ENABLED, "1").unwrap();
        s.set(KEY_CLIENT_HEARTBEAT_MS, "15000").unwrap();

        let settings = s.load().unwrap();
        assert_eq!(settings.instance_name, "Acme Tunnels");
        assert_eq!(settings.support_url, "https://support.example.com");
        assert_eq!(settings.session_ttl_hours, 8);
        assert!(settings.email_alerts_enabled);
        assert_eq!(settings.client_heartbeat_ms, Some(15000));
        // Untouched keys keep their defaults.
        assert!(settings.dashboard_ip_allowlist.is_empty());
        assert_eq!(settings.default_token_limits, TokenLimits::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let s = store();
        let settings = Settings {
            instance_name: "My Tunnels".into(),
            support_url: "https://help.example.com".into(),
            session_ttl_hours: 12,
            dashboard_ip_allowlist: vec!["10.0.0.0/8".to_string()],
            client_heartbeat_ms: Some(30000),
            ..Settings::default()
        };
        s.save(&settings).unwrap();

        let loaded = s.load().unwrap();
        assert_eq!(loaded.instance_name, "My Tunnels");
        assert_eq!(loaded.support_url, "https://help.example.com");
        assert_eq!(loaded.session_ttl_hours, 12);
        assert_eq!(
            loaded.dashboard_ip_allowlist,
            vec!["10.0.0.0/8".to_string()]
        );
        assert_eq!(loaded.client_heartbeat_ms, Some(30000));
    }

    #[test]
    fn peer_allowed_empty_means_all() {
        let s = Settings::default();
        assert!(s.peer_allowed(&"198.51.100.7".parse().unwrap()));
        assert!(s.peer_allowed(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn peer_allowed_exact_ip() {
        let s = Settings {
            dashboard_ip_allowlist: vec!["192.0.2.10".to_string()],
            ..Settings::default()
        };
        assert!(s.peer_allowed(&"192.0.2.10".parse().unwrap()));
        assert!(!s.peer_allowed(&"192.0.2.11".parse().unwrap()));
    }

    #[test]
    fn peer_allowed_ipv4_cidr() {
        let s = Settings {
            dashboard_ip_allowlist: vec!["10.20.0.0/16".to_string()],
            ..Settings::default()
        };
        assert!(s.peer_allowed(&"10.20.3.4".parse().unwrap()));
        assert!(!s.peer_allowed(&"10.21.3.4".parse().unwrap()));
    }

    #[test]
    fn peer_allowed_ipv6_cidr() {
        let s = Settings {
            dashboard_ip_allowlist: vec!["2001:db8::/32".to_string()],
            ..Settings::default()
        };
        assert!(s.peer_allowed(&"2001:db8::1".parse().unwrap()));
        assert!(!s.peer_allowed(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn peer_allowed_malformed_entry_denies_that_entry() {
        let s = Settings {
            dashboard_ip_allowlist: vec!["not-an-ip".to_string()],
            ..Settings::default()
        };
        assert!(!s.peer_allowed(&"192.0.2.10".parse().unwrap()));
        // A valid entry alongside a malformed one still matches.
        let s2 = Settings {
            dashboard_ip_allowlist: vec!["not-an-ip".to_string(), "192.0.2.0/24".to_string()],
            ..Settings::default()
        };
        assert!(s2.peer_allowed(&"192.0.2.99".parse().unwrap()));
    }

    #[test]
    fn peer_allowed_out_of_range_prefix_denies_that_entry() {
        let v4 = Settings {
            dashboard_ip_allowlist: vec!["192.0.2.10/33".to_string()],
            ..Settings::default()
        };
        assert!(!v4.peer_allowed(&"192.0.2.10".parse().unwrap()));

        let v6 = Settings {
            dashboard_ip_allowlist: vec!["2001:db8::/129".to_string()],
            ..Settings::default()
        };
        assert!(!v6.peer_allowed(&"2001:db8::1".parse().unwrap()));
    }

    /// Minimal one-shot HTTP receiver. Returns the bound address and a
    /// receiver that yields `(raw head, raw body)` for the single request.
    async fn mock_receiver() -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let header_end = loop {
                let n = sock.read(&mut tmp).await.unwrap();
                assert!(n > 0, "webhook client closed before headers");
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
            let content_len = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            while buf.len() < header_end + content_len {
                let n = sock.read(&mut tmp).await.unwrap();
                assert!(n > 0, "webhook client closed before body");
                buf.extend_from_slice(&tmp[..n]);
            }
            let body =
                String::from_utf8_lossy(&buf[header_end..header_end + content_len]).to_string();
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
            let _ = tx.send((head, body));
        });
        (addr, rx)
    }

    fn settings_with_webhook(url: &str, secret: &str) -> Settings {
        Settings {
            webhook_url: url.to_string(),
            webhook_secret: secret.to_string(),
            ..Settings::default()
        }
    }

    /// reqwest's `rustls-tls-no-provider` feature installs no default crypto
    /// provider; production installs one in `Broker::start`. Do the same here
    /// so the spawned webhook client can build a TLS-capable config.
    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn hmac_hex(secret: &str, body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        hex_encode(&mac.finalize().into_bytes())
    }

    #[test]
    fn webhook_body_merges_event_and_fields() {
        let payload = serde_json::json!({
            "session": {"slug": "abc123", "streams": 2},
            "server": {"domain": "tunnel.example.com", "max_sessions": 256},
        });
        let body: serde_json::Value =
            serde_json::from_str(&webhook_body("session_started", payload)).unwrap();
        assert_eq!(body["event"], "session_started");
        assert_eq!(body["session"]["slug"], "abc123");
        assert_eq!(body["session"]["streams"], 2);
        assert_eq!(body["server"]["domain"], "tunnel.example.com");
        assert_eq!(body["server"]["max_sessions"], 256);
    }

    #[test]
    fn token_warning_payload_shape() {
        let body: serde_json::Value = serde_json::from_str(&webhook_body(
            "token_warning",
            token_warning_payload("80", 100, 500, 7),
        ))
        .unwrap();
        assert_eq!(body["event"], "token_warning");
        assert_eq!(body["level"], "80");
        assert_eq!(body["balance"], 100);
        assert_eq!(body["allowance"], 500);
        assert_eq!(body["account_id"], 7);
    }

    #[test]
    fn token_exhausted_payload_shape() {
        let body: serde_json::Value =
            serde_json::from_str(&webhook_body("token_exhausted", token_exhausted_payload(7)))
                .unwrap();
        assert_eq!(body["event"], "token_exhausted");
        assert_eq!(body["account_id"], 7);
        assert_eq!(body["balance"], 0);
    }

    #[test]
    fn webhook_signature_is_hmac_sha256_hex_and_unsigned_when_empty() {
        let sig = webhook_signature("s3cret", "{\"event\":\"x\"}").unwrap();
        assert_eq!(
            sig,
            format!("sha256={}", hmac_hex("s3cret", "{\"event\":\"x\"}"))
        );
        assert!(webhook_signature("", "{}").is_none());
    }

    #[tokio::test]
    async fn send_webhook_posts_signed_body() {
        install_crypto_provider();
        let (addr, mut rx) = mock_receiver().await;
        let settings = settings_with_webhook(&format!("http://{addr}/hook"), "test-secret");
        let payload = serde_json::json!({
            "session": {"slug": "abc123", "token_id": "tok", "uptime_secs": 0, "streams": 0, "bytes_tx": 0, "bytes_rx": 0},
            "server": {"domain": "tunnel.example.com", "max_sessions": 256},
        });
        send_webhook(&settings, "session_started", payload);
        let (head, body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("webhook not received")
            .expect("receiver dropped");
        let sig = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("x-ddns-signature")
                    .then(|| v.trim().to_string())
            })
            .expect("X-DDNS-Signature missing");
        assert_eq!(sig, format!("sha256={}", hmac_hex("test-secret", &body)));
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event"], "session_started");
        assert_eq!(json["session"]["slug"], "abc123");
    }

    #[tokio::test]
    async fn send_webhook_unsigned_when_secret_empty() {
        install_crypto_provider();
        let (addr, mut rx) = mock_receiver().await;
        let settings = settings_with_webhook(&format!("http://{addr}/hook"), "");
        send_webhook(
            &settings,
            "server_full",
            serde_json::json!({"server": {"domain": "d", "max_sessions": 1}}),
        );
        let (head, body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("webhook not received")
            .expect("receiver dropped");
        assert!(
            !head.to_ascii_lowercase().contains("x-ddns-signature"),
            "unexpected signature header: {head}"
        );
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["event"], "server_full");
    }
}
