//! Rate-limit tests: /login and /connect are per-IP token-bucketed because
//! both run CPU-bound argon2 work while unauthenticated.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{FakeClient, start_broker, test_cert};
use ddns_proto::Control;
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// helpers (same pattern as tests/auth.rs)
// ---------------------------------------------------------------------------

async fn http1(addr: std::net::SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
    let mut cfg = common::client_tls(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(host.to_string().try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&resp).into_owned()
}

fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Set up the admin password (POST /setup) on a fresh broker.
async fn setup_admin(addr: std::net::SocketAddr, cert: &[u8]) {
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("302"), "setup should redirect, got: {resp}");
}

/// Attempt a WS upgrade to /connect (no register). Ok = upgrade succeeded.
async fn try_upgrade(addr: std::net::SocketAddr, cert: &[u8]) -> Result<(), String> {
    let cfg = Arc::new(common::client_tls(cert));
    let connector = tokio_tungstenite::Connector::Rustls(cfg);
    let url = format!("wss://127.0.0.1:{}/connect", addr.port());
    match tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector)).await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// /login: 5 wrong passwords (burst) → 401s; the 6th from the same IP is
/// rejected with 429 before any argon2 work.
#[tokio::test]
async fn login_rate_limited_per_ip() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;
    setup_admin(addr, &cert).await;

    for _ in 0..5 {
        let body = form_body(&[("password", "wrong-password")]);
        let req = format!(
            "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
        assert!(
            resp.contains("401"),
            "wrong password should 401 (attempt within burst), got:\n{resp}"
        );
    }

    // 6th attempt → rate limited. The 0.5/s refill is a compile-time constant,
    // so on a slow run a token may have refilled between the burst requests and
    // the 6th one lands a 401. Loop a bounded number of attempts: every
    // response must be 401 (limiter not engaged yet) or 429 (engaged) — never
    // a successful login — and a 429 must eventually appear.
    let mut limited = false;
    for _ in 0..10 {
        let body = form_body(&[("password", "wrong-password")]);
        let req = format!(
            "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
        assert!(
            resp.contains("401") || resp.contains("429"),
            "login from an exhausted IP must be 401 or 429, got:\n{resp}"
        );
        if resp.contains("429") {
            limited = true;
            break;
        }
    }
    assert!(limited, "rate limiter never engaged for an exhausted IP");

    broker.stop().await;
}

/// /connect: the first 30 WS upgrades (the register limiter burst) succeed
/// (register then fails with token_invalid — no token registered); once the
/// burst is drained past its 5/s refill, an upgrade from the same IP is
/// rejected with 429. The drain loop overshoots (30 + 15) so the test cannot
/// pass by racing the time-based refill.
#[tokio::test]
async fn register_rate_limited_per_ip() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    for _ in 0..30 {
        let (mut fc, reply) = FakeClient::connect_raw(addr, &cert, "bad-token", true, true).await;
        assert!(
            matches!(reply, Err(Control::Error { .. })),
            "register with a bad token should get error{{token_invalid}}, got {reply:?}"
        );
        fc.ws.close(None).await.ok();
    }
    // Keep draining past the burst so the refill can never recover the bucket
    // (upgrades past the limit fail with 429 — that is expected, ignore it).
    for _ in 0..15 {
        let _ = try_upgrade(addr, &cert).await;
    }

    // Next upgrade from the same IP → rejected (429) before upgrade completes.
    let err = try_upgrade(addr, &cert).await;
    assert!(
        err.is_err(),
        "drained /connect from the same IP should be rate limited (429)"
    );

    broker.stop().await;
}
