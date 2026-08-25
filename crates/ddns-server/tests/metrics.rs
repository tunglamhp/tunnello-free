//! Task C2 acceptance: operator-gated Prometheus `/metrics` endpoint.
//!
//! Two checks: (1) an unauthenticated request is redirected, and (2) an
//! operator session gets the text exposition (`text/plain`), which lists the
//! `ddns_*` metrics and reports a non-zero `ddns_bytes_total` after one real
//! proxied visitor request through a live tunnel.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{FakeClient, client_tls, spawn_local_app, start_broker, test_cert};
use ddns_proto::frame::CLOSE_OK;
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// low-level helpers (same pattern as tests/pages.rs)
// ---------------------------------------------------------------------------

/// Send an HTTP/1.1 request over TLS and read the full response.
async fn http1(addr: std::net::SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
    let mut cfg = client_tls(cert);
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

/// Parse the `Set-Cookie` value from an HTTP response.
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

/// Build a form body: `name=value` URL-encoded pairs.
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Get the status code from an HTTP response.
fn status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Find a header value by name (case-insensitive).
fn header_value(response: &str, name: &str) -> Option<String> {
    let lower_name = name.to_ascii_lowercase();
    for line in response.lines() {
        if let Some((k, v)) = line.split_once(": ")
            && k.to_ascii_lowercase() == lower_name
        {
            return Some(v.to_string());
        }
    }
    None
}

/// Extract a metric's value from a text exposition (e.g. `ddns_bytes_total 42`
/// or `ddns_requests_total{tunnel="x"} 7`).
fn metric_value(exposition: &str, name: &str) -> Option<u64> {
    exposition
        .lines()
        .find(|l| l.starts_with(&format!("{name} ")) || l.starts_with(&format!("{name}{{")))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

/// Start a broker with one registered token, create the operator password, and
/// log in. Returns (addr, broker, session cookie, cert).
async fn setup_admin() -> (std::net::SocketAddr, ddns_server::Broker, String, Vec<u8>) {
    let (cert, key) = test_cert();
    let store = TokenStore::new();
    store
        .insert("tok_metrics".into(), common::test_record("t-metrics", true))
        .await
        .unwrap();
    let (addr, broker) = start_broker(&cert, &key, store, 256, Duration::from_secs(5)).await;

    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");
    (addr, broker, cookie, cert)
}

/// Build an authed page request with the session cookie.
fn page_req(cookie: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    )
}

// ---------------------------------------------------------------------------
// test 1: unauthenticated /metrics → redirect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metrics_requires_operator_session() {
    let (addr, broker, _cookie, cert) = setup_admin().await;

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /metrics HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status_code(&resp),
        302,
        "unauthenticated /metrics should redirect, got:\n{resp}"
    );
    assert_eq!(
        header_value(&resp, "location").as_deref(),
        Some("/login"),
        "unauthenticated /metrics should redirect to /login, got:\n{resp}"
    );

    broker.stop().await;
}

// ---------------------------------------------------------------------------
// test 2: operator session → text exposition with live byte counts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metrics_operator_session_serves_live_exposition() {
    let (addr, broker, cookie, cert) = setup_admin().await;

    // One real proxied visitor request through a live tunnel must move the
    // request/byte counters (the local app's response body flows through the
    // broker's record_rx path).
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_metrics").await;
    let slug = FakeClient::slug(&reply);
    let app = spawn_local_app().await;

    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let visitor = tokio::spawn(async move {
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {slug1}.tunnel.example.com\r\nConnection: close\r\n\r\n"
        );
        http1(addr, &cert1, "127.0.0.1", &req).await
    });

    let open = tokio::time::timeout(Duration::from_secs(5), fc.recv_open()).await;
    let (stream_id, meta) = match open {
        Ok(open) => open,
        Err(_) => {
            let visitor_resp = visitor.await.unwrap();
            panic!("visitor was not routed to the tunnel; got: {visitor_resp}");
        }
    };
    let head = meta.head.as_ref().unwrap().clone();
    let mut app_sock = tokio::net::TcpStream::connect(app.addr).await.unwrap();
    app_sock.write_all(&head).await.unwrap();
    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = app_sock.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
    }
    let idx = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let (rhead, rbody) = resp.split_at(idx);
    fc.send_open_ack(stream_id, Bytes::copy_from_slice(rhead))
        .await;
    fc.send_data(stream_id, Bytes::copy_from_slice(rbody)).await;
    fc.send_close(stream_id, CLOSE_OK).await;

    let visitor_resp = visitor.await.unwrap();
    assert_eq!(
        status_code(&visitor_resp),
        200,
        "visitor must reach the tunnel, got:\n{visitor_resp}"
    );
    drop(fc);

    // Operator GET /metrics → 200 + text/plain + all ddns_* families, with
    // live values reflecting the visitor request above.
    let metrics = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/metrics"),
    )
    .await;
    assert_eq!(
        status_code(&metrics),
        200,
        "operator GET /metrics should return 200, got:\n{metrics}"
    );
    assert!(
        header_value(&metrics, "content-type").is_some_and(|v| v.starts_with("text/plain")),
        "content-type must be text/plain, got:\n{metrics}"
    );
    for name in [
        "ddns_requests_total",
        "ddns_bytes_total",
        "ddns_active_sessions",
        "ddns_ratelimit_429_total",
    ] {
        assert!(
            metrics.contains(name),
            "exposition must list {name}, got:\n{metrics}"
        );
    }
    assert!(
        metric_value(&metrics, "ddns_requests_total").unwrap_or(0) >= 1,
        "ddns_requests_total must count the visitor request, got:\n{metrics}"
    );
    let bytes = metric_value(&metrics, "ddns_bytes_total").expect("ddns_bytes_total sample line");
    assert!(
        bytes > 0,
        "ddns_bytes_total must be non-zero after a proxied visitor request, got:\n{metrics}"
    );

    broker.stop().await;
}
