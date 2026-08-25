//! Tests for cert manager, :80 listener, and DNS-01 provider plumbing.
//! All tests are offline (no real ACME endpoint, no real Cloudflare API).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{Router, routing};
use ddns_server::config::{AcmeOptions, AcmeProvider, BrokerConfig};
use ddns_server::providers::{ChallengeStore, Cloudflare, Dns01Provider, ManualTxt};
use ddns_server::{Broker, TokenStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

// ---------------------------------------------------------------------------
// :80 plain listener tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_listener_redirects_301_location() {
    let (cert, key) = common::test_cert();
    // Bind a random port first to find one.
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    drop(http_listener);

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: cert,
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 16,
        watchdog_interval: Duration::from_secs(30),
        http_listen: Some(http_addr),
        stun_listen: None,
        acme: None,
        download_dir: None,
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();

    // Send a plain HTTP GET to the http_listen addr.
    let stream = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    write
        .write_all(b"GET /some/path?q=1 HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    write.shutdown().await.unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf);

    assert!(
        response.contains("301"),
        "expected 301 redirect, got: {response}"
    );
    assert!(
        response.contains("Location: https://example.com/some/path?q=1"),
        "expected Location header, got: {response}"
    );

    drop(broker);
}

#[tokio::test]
async fn challenge_endpoint_serves_value() {
    // End-to-end through the :80 listener: seed the broker's ChallengeStore,
    // then GET the token over plain HTTP.
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    drop(http_listener);

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: vec![],
        tls_key_pem: vec![],
        token_store: TokenStore::new(),
        max_sessions: 16,
        watchdog_interval: Duration::from_secs(30),
        http_listen: Some(http_addr),
        stun_listen: None,
        acme: Some(AcmeOptions {
            domains: vec!["tunnel.example.com".to_string()],
            contact_email: None,
            provider: AcmeProvider::Manual,
            // Unreachable directory: issuance never starts; only :80 is
            // exercised here.
            directory_url: Some("http://127.0.0.1:1/directory".to_string()),
        }),
        download_dir: None,
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    let store = broker
        .challenge_store
        .as_ref()
        .expect("acme path exposes the challenge store");
    store.write_http01("abc123", "challenge-value-xyz");

    // Seeded token → 200 with the challenge value as body.
    let resp = plain_get(http_addr, "/.well-known/acme-challenge/abc123").await;
    assert!(resp.contains("200 OK"), "expected 200, got: {resp}");
    assert!(
        resp.contains("challenge-value-xyz"),
        "expected challenge body, got: {resp}"
    );

    // Unknown token → 404.
    let resp = plain_get(http_addr, "/.well-known/acme-challenge/nope").await;
    assert!(
        resp.contains("404"),
        "expected 404 for unknown token, got: {resp}"
    );

    // Cleared token → 404.
    store.clear_http01("abc123");
    let resp = plain_get(http_addr, "/.well-known/acme-challenge/abc123").await;
    assert!(
        resp.contains("404"),
        "expected 404 after clear, got: {resp}"
    );

    broker.stop().await;
}

// ---------------------------------------------------------------------------
// Provider plumbing tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manual_provider_records_challenges() {
    let provider = ManualTxt {
        store: Arc::new(ChallengeStore::default()),
    };

    provider
        .write_challenge("example.com", "txt-value-1")
        .await
        .unwrap();
    assert_eq!(
        provider.store.get("example.com"),
        Some("txt-value-1".into())
    );

    provider.clear_challenge("example.com").await.unwrap();
    assert_eq!(provider.store.get("example.com"), None);
}

#[tokio::test]
async fn cloudflare_provider_writes_and_clears() {
    // Spin up a mock Cloudflare API server.
    let requests: Arc<Mutex<Vec<MockCfRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let reqs = requests.clone();

    let app = Router::new()
        .route(
            "/zones/{zone}/dns_records",
            routing::post({
                let reqs = reqs.clone();
                move |axum::extract::Path(zone): axum::extract::Path<String>,
                      axum::Json(body): axum::Json<serde_json::Value>| {
                    let mut reqs = reqs.lock().unwrap();
                    let n = reqs.len() + 1;
                    reqs.push(MockCfRequest {
                        method: "POST".into(),
                        zone: zone.clone(),
                        body: body.clone(),
                    });
                    async move {
                        axum::Json(serde_json::json!({
                            "success": true,
                            "result": {"id": format!("rec-{}-{}", zone, n)}
                        }))
                    }
                }
            }),
        )
        .route(
            "/zones/{zone}/dns_records/{id}",
            routing::delete({
                let reqs = reqs.clone();
                move |axum::extract::Path((zone, id)): axum::extract::Path<(String, String)>| {
                    let mut reqs = reqs.lock().unwrap();
                    reqs.push(MockCfRequest {
                        method: "DELETE".into(),
                        zone: zone.clone(),
                        body: serde_json::json!({"id": id.clone()}),
                    });
                    async move { axum::Json(serde_json::json!({"success": true})) }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let cf = Cloudflare::new(
        "test-token".into(),
        "test-zone-id".into(),
        format!("http://{addr}"),
    );

    cf.write_challenge("example.com", "dns-txt-value")
        .await
        .unwrap();

    assert_eq!(cf.store.get("example.com"), Some("dns-txt-value".into()));

    // Verify the mock saw a POST.
    {
        let reqs = requests.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].zone, "test-zone-id");
        assert_eq!(reqs[0].body["name"], "_acme-challenge.example.com");
        assert_eq!(reqs[0].body["content"], "dns-txt-value");
        assert_eq!(reqs[0].body["type"], "TXT");
    }

    cf.clear_challenge("example.com").await.unwrap();
    assert_eq!(cf.store.get("example.com"), None);

    // Verify the mock saw a DELETE.
    {
        let reqs = requests.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].method, "DELETE");
        assert_eq!(reqs[1].zone, "test-zone-id");
    }
}

// ---------------------------------------------------------------------------
// ACME acceptor construction test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acme_acceptor_constructs_and_does_not_panic() {
    // Broker with acme pointing at an unreachable directory — start should
    // succeed (no panic, no hang). TLS handshake may fail fast but that's ok.
    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: Vec::new(),
        tls_key_pem: Vec::new(),
        token_store: TokenStore::new(),
        max_sessions: 4,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: Some(AcmeOptions {
            domains: vec!["example.com".into()],
            contact_email: Some("admin@example.com".into()),
            provider: AcmeProvider::Manual,
            directory_url: Some("http://127.0.0.1:1/directory".into()),
        }),
        download_dir: None,
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };

    let broker = Broker::start(config).await.unwrap();
    let client_tls = common::client_tls(&common::test_cert().0);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let tcp = tokio::net::TcpStream::connect(broker.addr).await.unwrap();
    let result = connector
        .connect("example.com".try_into().unwrap(), tcp)
        .await;
    assert!(
        result.is_err(),
        "expected TLS handshake to fail (no cert yet)"
    );
    broker.stop().await;
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn acme_and_explicit_certs_are_mutually_exclusive() {
    let (cert, key) = common::test_cert();
    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: cert,
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: Some(AcmeOptions {
            domains: vec!["example.com".into()],
            contact_email: None,
            provider: AcmeProvider::Manual,
            directory_url: None,
        }),
        download_dir: None,
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };

    let result = Broker::start(config).await;
    assert!(
        result.is_err(),
        "expected error for mutually exclusive config"
    );
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.contains("mutually exclusive"),
        "expected mutual exclusion error, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Static cert status reports expiry

// ---------------------------------------------------------------------------
// Static cert status via /api/cert (requires auth)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn static_cert_status_reports_expiry() {
    let (cert, key) = common::test_cert();
    let cert_pem = cert.clone();

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: cert,
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 16,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: None,
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    let addr = broker.addr;

    // Set up admin + login using the same helpers as api.rs tests.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert_pem, "tunnel.example.com", &req).await;

    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert_pem, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // Query /api/cert.
    let req = format!(
        "GET /api/cert HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert_pem, "tunnel.example.com", &req).await;
    assert_eq!(status_code(&resp), 200, "GET /api/cert → 200, got:\n{resp}");

    let v = json_body(&resp);
    assert_eq!(v["source"], "static");
    assert_eq!(v["status"], "serving");
    let expiry = v["cert_expiry_secs"].as_i64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        expiry > now,
        "cert expiry {expiry} should be in the future (now={now})"
    );

    drop(broker);
}

// ---------------------------------------------------------------------------
// HTTP/1.1 helpers (same pattern as tests/api.rs)
// ---------------------------------------------------------------------------

/// Send a plain-HTTP GET (no TLS) to `addr` and read the full response.
async fn plain_get(addr: std::net::SocketAddr, target: &str) -> String {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    write
        .write_all(
            format!(
                "GET {target} HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    write.shutdown().await.unwrap();
    let mut buf = Vec::new();
    read.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

async fn http1(addr: std::net::SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
    let mut cfg = common::client_tls(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(host.to_string().try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut resp_buf = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => resp_buf.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&resp_buf).into_owned()
}

fn parse_set_cookie(response: &str) -> Option<String> {
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie: ") {
            let offset = line.len() - rest.len();
            let val = &line[offset..];
            return Some(val.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn json_body(response: &str) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

fn status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MockCfRequest {
    method: String,
    zone: String,
    body: serde_json::Value,
}
