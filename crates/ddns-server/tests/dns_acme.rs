//! End-to-end DNS-01 issuance test against a mock ACME directory.
//!
//! The mock implements the RFC 8555 surface the driver touches (directory,
//! nonce, account, order, authorization, challenge, finalize, certificate)
//! and *verifies every JWS signature* with the account key offered in the
//! first request — a forged/incorrect signature makes the flow fail, so a
//! green test proves the request signing is valid. TXT writes/clears go to a
//! recording provider, and the driver must write two distinct digests on the
//! same `_acme-challenge.<apex>` name (apex + wildcard authorizations), then
//! clear both, persist the cache, and hot-swap the acceptor slot.

use std::sync::Arc;

use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::{get, head, post};
use axum::{Json, Router};
use base64::prelude::*;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

mod common;

// ---------------------------------------------------------------------------
// Mock ACME directory
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MockState {
    nonce: u64,
    account: bool,
    triggered: Vec<bool>, // per challenge id
    order_status: String,
    new_order_calls: u64,
    finalized: bool,
    captured_csr: Option<Vec<u8>>,
    last_jwk: Option<(String, String)>, // x, y (base64url)
}

#[derive(Clone)]
struct Ctx {
    base: String,
    state: Arc<Mutex<MockState>>,
    chain_pem: Arc<String>,
}

/// Verify an RFC 8555 JWS body against the recorded account key.
/// Returns the decoded payload string on success.
fn verify_jws(
    state: &MockState,
    body: &serde_json::Value,
    expected_url: &str,
    base: &str,
) -> Result<String, String> {
    let expected_url = format!("{base}{expected_url}");
    let protected_b64 = body["protected"].as_str().ok_or("no protected")?;
    let payload_b64 = body["payload"].as_str().ok_or("no payload")?;
    let signature_b64 = body["signature"].as_str().ok_or("no signature")?;
    let protected: serde_json::Value = serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(protected_b64)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if protected["url"].as_str() != Some(expected_url.as_str()) {
        return Err(format!("url mismatch: {:?}", protected["url"]));
    }
    if protected["alg"].as_str() != Some("ES256") {
        return Err("alg mismatch".into());
    }
    let (x, y) = state.last_jwk.as_ref().ok_or("no account key recorded")?;
    let x = BASE64_URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| e.to_string())?;
    let y = BASE64_URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| e.to_string())?;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| e.to_string())?;
    let signed_input = format!("{protected_b64}.{payload_b64}");
    let digest = Sha256::digest(signed_input.as_bytes());
    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| e.to_string())?;
    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|e| e.to_string())?;
    <p256::ecdsa::VerifyingKey as PrehashVerifier<p256::ecdsa::Signature>>::verify_prehash(
        &vk, &digest, &sig,
    )
    .map_err(|e| e.to_string())?;
    let payload = BASE64_URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&payload).into_owned())
}

fn next_nonce(state: &MockState) -> String {
    format!("nonce-{}", state.nonce)
}

fn nonce_headers(st: &MockState) -> HeaderMap {
    let mut m = HeaderMap::new();
    m.insert(
        "replay-nonce",
        HeaderValue::from_str(&next_nonce(st)).unwrap(),
    );
    m
}

async fn directory_h(State(ctx): State<Ctx>) -> (HeaderMap, Json<serde_json::Value>) {
    let st = ctx.state.lock();
    (
        nonce_headers(&st),
        Json(serde_json::json!({
            "newNonce": format!("{}/new-nonce", ctx.base),
            "newAccount": format!("{}/new-account", ctx.base),
            "newOrder": format!("{}/new-order", ctx.base),
        })),
    )
}

async fn new_nonce_h(State(ctx): State<Ctx>) -> (HeaderMap, &'static str) {
    let st = ctx.state.lock();
    (nonce_headers(&st), "")
}

async fn new_account_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    // First request carries the account key inline (jwk).
    let protected: serde_json::Value = serde_json::from_slice(
        &BASE64_URL_SAFE_NO_PAD
            .decode(body["protected"].as_str().unwrap_or(""))
            .unwrap(),
    )
    .unwrap();
    let jwk = &protected["jwk"];
    st.last_jwk = Some((
        jwk["x"].as_str().unwrap().to_string(),
        jwk["y"].as_str().unwrap().to_string(),
    ));
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["termsOfServiceAgreed"], true);
    st.account = true;
    let mut m = nonce_headers(&st);
    m.insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&format!("{}/acct/1", ctx.base)).unwrap(),
    );
    (
        StatusCode::CREATED,
        m,
        Json(serde_json::json!({"status": "valid"})),
    )
}

async fn new_order_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let ids: Vec<String> = payload["identifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["value"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2, "expected apex + wildcard: {ids:?}");
    assert!(ids.contains(&"tunnel.example.test".to_string()));
    assert!(ids.contains(&"*.tunnel.example.test".to_string()));
    st.new_order_calls += 1;
    st.order_status = "pending".into();
    st.triggered = vec![false, false];
    st.finalized = false;
    let mut m = nonce_headers(&st);
    m.insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&format!("{}/order/1", ctx.base)).unwrap(),
    );
    (
        StatusCode::CREATED,
        m,
        Json(serde_json::json!({
            "status": "pending",
            "authorizations": [
                format!("{}/authz/1", ctx.base),
                format!("{}/authz/2", ctx.base),
            ],
            "finalize": format!("{}/finalize/1", ctx.base),
        })),
    )
}

async fn authz_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    assert!(payload.is_empty(), "authz must be POST-as-GET");
    let idx: usize = id.parse().unwrap();
    let (value, token) = if idx == 1 {
        ("tunnel.example.test", "token-apex")
    } else {
        ("*.tunnel.example.test", "token-wild")
    };
    let status = if idx <= st.triggered.len() && st.triggered[idx - 1] {
        "valid"
    } else {
        "pending"
    };
    Json(serde_json::json!({
        "status": status,
        "identifier": {"type": "dns", "value": value},
        "challenges": [{
            "type": "dns-01",
            "url": format!("{}/challenge/{idx}", ctx.base),
            "token": token,
        }],
    }))
}

async fn challenge_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload, serde_json::json!({}));
    let idx: usize = id.parse().unwrap();
    st.triggered[idx - 1] = true;
    Json(serde_json::json!({}))
}

async fn order_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    if st.finalized {
        st.order_status = "valid".into();
    } else if st.triggered.iter().all(|t| *t) {
        st.order_status = "ready".into();
    }
    let mut order = serde_json::json!({
        "status": st.order_status,
        "authorizations": [
            format!("{}/authz/1", ctx.base),
            format!("{}/authz/2", ctx.base),
        ],
        "finalize": format!("{}/finalize/1", ctx.base),
    });
    if st.order_status == "valid" {
        order["certificate"] = serde_json::json!(format!("{}/cert/1", ctx.base));
    }
    Json(order)
}

async fn finalize_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let csr_b64 = payload["csr"].as_str().unwrap();
    st.captured_csr = Some(BASE64_URL_SAFE_NO_PAD.decode(csr_b64).unwrap());
    st.finalized = true;
    st.order_status = "processing".into();
    Json(serde_json::json!({
        "status": "processing",
        "authorizations": [],
        "finalize": format!("{}/finalize/1", ctx.base),
    }))
}

async fn cert_h(
    State(ctx): State<Ctx>,
    original: OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> String {
    let mut st = ctx.state.lock();
    st.nonce += 1;
    let payload = verify_jws(&st, &body, original.path(), &ctx.base).unwrap();
    assert!(payload.is_empty());
    ctx.chain_pem.as_str().to_string()
}

async fn build_app() -> (Ctx, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let ctx = Ctx {
        base: base.clone(),
        state: Arc::new(Mutex::new(MockState {
            nonce: 1,
            order_status: "pending".into(),
            ..Default::default()
        })),
        chain_pem: {
            use rcgen::{CertificateParams, KeyPair};
            let params = CertificateParams::new(vec![
                "tunnel.example.test".into(),
                "*.tunnel.example.test".into(),
            ])
            .unwrap();
            let key = KeyPair::generate().unwrap();
            Arc::new(params.self_signed(&key).unwrap().pem())
        },
    };

    let router = Router::new()
        .route("/directory", get(directory_h))
        .route("/new-nonce", head(new_nonce_h))
        .route("/new-account", post(new_account_h))
        .route("/new-order", post(new_order_h))
        .route("/authz/{id}", post(authz_h))
        .route("/challenge/{id}", post(challenge_h))
        .route("/order/1", post(order_h))
        .route("/finalize/1", post(finalize_h))
        .route("/cert/1", post(cert_h))
        .with_state(ctx.clone());

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (ctx, addr)
}

// ---------------------------------------------------------------------------
// Recording provider
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Rec {
    writes: Mutex<Vec<(String, String)>>,
    clears: Mutex<Vec<String>>,
}

#[derive(Debug)]
struct RecordingProvider {
    rec: Arc<Rec>,
}

impl ddns_server::providers::Dns01Provider for RecordingProvider {
    fn write_challenge(
        &self,
        domain: &str,
        value: &str,
    ) -> ddns_server::providers::ProviderFuture<'_> {
        let rec = self.rec.clone();
        let domain = domain.to_string();
        let value = value.to_string();
        Box::pin(async move {
            rec.writes.lock().push((domain.clone(), value.clone()));
            Ok(())
        })
    }
    fn clear_challenge(&self, domain: &str) -> ddns_server::providers::ProviderFuture<'_> {
        let rec = self.rec.clone();
        let domain = domain.to_string();
        Box::pin(async move {
            rec.clears.lock().push(domain.clone());
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ddns-dnsacme-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Full protocol pass against the mock directory: JWS signatures verified by
/// the mock at every step, two distinct TXT digests on the shared
/// `_acme-challenge.<apex>` name written and then cleared, cache persisted,
/// and a second pass served from cache without a new order.
#[tokio::test]
async fn dns01_engine_issues_wildcard_cert_through_mock_directory() {
    use ddns_server::dns_acme::{DnsAcmeController, DnsIssuerConfig};
    use ddns_server::tls::{AcceptorSlot, static_server_config};

    // Accept-loop/server-config paths need a process-level rustls provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (ctx, addr) = build_app().await;
    let rec = Arc::new(Rec::default());
    let provider = RecordingProvider { rec: rec.clone() };

    let (cert, key) = common::test_cert();
    let slot = AcceptorSlot::new(static_server_config(&cert, &key).unwrap());

    let cache = temp_dir("issue");
    let cfg = DnsIssuerConfig {
        directory_url: format!("http://{addr}/directory"),
        contact_email: Some("ops@example.test".into()),
        domains: vec!["tunnel.example.test".into(), "*.tunnel.example.test".into()],
        cache_dir: cache.clone(),
        provider: Arc::new(provider),
        http: reqwest::Client::new(),
        propagation_delay: std::time::Duration::ZERO,
        poll_interval: std::time::Duration::from_millis(20),
        max_wait: std::time::Duration::from_secs(10),
    };
    let controller = DnsAcmeController::new(cfg, slot.clone());
    controller.run_once().await.expect("issuance succeeded");

    // Two TXT digests written on the same base, distinct values.
    let (write_pairs, cleared, calls_before, csr_seen) = {
        let writes = rec.writes.lock();
        assert_eq!(writes.len(), 2, "apex + wildcard authorizations");
        assert_eq!(writes[0].0, "tunnel.example.test");
        assert_eq!(writes[1].0, "tunnel.example.test");
        assert_ne!(writes[0].1, writes[1].1, "distinct digest per authz");
        for (_, v) in writes.iter() {
            assert_eq!(v.len(), 43, "base64url sha256 digest");
        }
        let pairs = writes.clone();
        let cleared = rec.clears.lock().clone();
        let calls_before = ctx.state.lock().new_order_calls;
        let csr_seen = ctx.state.lock().captured_csr.is_some();
        (pairs, cleared, calls_before, csr_seen)
    };
    assert_eq!(write_pairs.len(), 2);
    assert_eq!(cleared.len(), 2);
    assert!(cleared.iter().all(|c| c == "tunnel.example.test"));
    assert_eq!(calls_before, 1);
    assert!(csr_seen, "finalize carried a CSR");

    // Cache persisted for restart reuse.
    assert!(cache.join("dns01-cert.pem").exists());
    assert!(cache.join("dns01-key.pem").exists());
    assert!(cache.join("dns01-account-key.der").exists());

    // Second pass serves the cache: no new order, no TXT traffic.
    controller.run_once().await.expect("cached pass");
    let (calls_after, writes_after) = {
        let calls_after = ctx.state.lock().new_order_calls;
        let writes_after = rec.writes.lock().len();
        (calls_after, writes_after)
    };
    assert_eq!(calls_after, 1, "cache must skip re-issuance");
    assert_eq!(writes_after, 2, "no new TXT writes on cached pass");

    std::fs::remove_dir_all(&cache).ok();
}

/// A broker restart with a valid cached certificate must serve it without
/// contacting the ACME directory at all (unreachable directory below).
#[tokio::test]
async fn cached_certificate_served_without_acme_contact() {
    use ddns_server::dns_acme::{DnsAcmeController, DnsIssuerConfig};
    use ddns_server::tls::{AcceptorSlot, static_server_config};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (cert_pem, key_pem) = common::test_cert();
    let cache = temp_dir("cache");
    std::fs::write(cache.join("dns01-cert.pem"), &cert_pem).unwrap();
    std::fs::write(cache.join("dns01-key.pem"), &key_pem).unwrap();

    let rec = Arc::new(Rec::default());
    let provider = RecordingProvider { rec: rec.clone() };
    let slot = AcceptorSlot::new(static_server_config(&cert_pem, &key_pem).unwrap());

    let cfg = DnsIssuerConfig {
        directory_url: "http://127.0.0.1:1/directory".into(),
        contact_email: None,
        domains: vec!["tunnel.example.test".into(), "*.tunnel.example.test".into()],
        cache_dir: cache.clone(),
        provider: Arc::new(provider),
        http: reqwest::Client::new(),
        propagation_delay: std::time::Duration::ZERO,
        poll_interval: std::time::Duration::from_millis(20),
        max_wait: std::time::Duration::from_secs(2),
    };
    DnsAcmeController::new(cfg, slot.clone())
        .run_once()
        .await
        .expect("cache-served pass (no ACME contact)");
    assert_eq!(rec.writes.lock().len(), 0, "no TXT writes when cached");

    std::fs::remove_dir_all(&cache).ok();
}
