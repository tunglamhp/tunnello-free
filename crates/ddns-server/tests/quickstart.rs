//! Quickstart one-liner: install.sh?code=&port= (+ fallback + validation).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ddns_server::TokenStore;
use ddns_server::setup::SetupStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use common::{client_tls, start_broker, test_cert, test_record};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Send an HTTP/1.1 request over TLS and return the full raw response.
async fn http1(addr: SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
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

async fn get_install(addr: SocketAddr, cert: &[u8], query: &str, host: &str) -> (u16, String) {
    let resp = http1(
        addr,
        cert,
        host,
        &format!("GET /install.sh{query} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let status = resp
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

/// Boot a broker on the given store (so a code can be created before `start`).
async fn boot_with(ts: TokenStore) -> (SocketAddr, ddns_server::Broker, Vec<u8>) {
    let (cert, key) = test_cert();
    let (addr, broker) = start_broker(&cert, &key, ts, 256, Duration::from_secs(5)).await;
    (addr, broker, cert)
}

/// Bind a `t-test` token and issue a code with the given profile `ports`.
async fn make_code(ts: &TokenStore, ports: &str) -> String {
    ts.insert("tok_test".into(), test_record("t-test", true))
        .await
        .unwrap();
    SetupStore::open(ts).create(0, "t-test", ports)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quickstart_script_embeds_code_and_port() {
    let ts = TokenStore::new();
    let code = make_code(&ts, "8080").await;
    let (addr, broker, cert) = boot_with(ts).await;

    let (status, body) = get_install(
        addr,
        &cert,
        &format!("?code={code}&port=8080"),
        "tunnel.example.com",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains(&format!("--token '{code}'")),
        "code must be embedded single-quoted: {body}"
    );
    assert!(
        body.contains("--port 8080"),
        "port flag must be embedded: {body}"
    );

    broker.stop().await;
}

#[tokio::test]
async fn quickstart_script_validates_bad_port() {
    let (addr, broker, cert) = boot_with(TokenStore::new()).await;

    let (status, _) =
        get_install(addr, &cert, "?code=sc_abc&port=99999", "tunnel.example.com").await;
    assert_eq!(status, 400);

    broker.stop().await;
}

#[tokio::test]
async fn quickstart_script_rejects_bad_code_charset() {
    let (addr, broker, cert) = boot_with(TokenStore::new()).await;

    let (status, _) = get_install(
        addr,
        &cert,
        "?code=$(rm+-rf+/)&port=80",
        "tunnel.example.com",
    )
    .await;
    assert_eq!(status, 400);

    broker.stop().await;
}

#[tokio::test]
async fn quickstart_script_falls_back_to_profile_ports() {
    let ts = TokenStore::new();
    let code = make_code(&ts, "8080,22").await;
    let (addr, broker, cert) = boot_with(ts).await;

    let (status, body) =
        get_install(addr, &cert, &format!("?code={code}"), "tunnel.example.com").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("--port 8080"),
        "profile HTTP port must be embedded: {body}"
    );
    assert!(
        body.contains("--tcp 22"),
        "profile TCP port must be embedded: {body}"
    );

    broker.stop().await;
}

#[tokio::test]
async fn quickstart_script_prints_hint_when_no_ports() {
    let ts = TokenStore::new();
    let code = make_code(&ts, "").await;
    let (addr, broker, cert) = boot_with(ts).await;

    let (status, body) =
        get_install(addr, &cert, &format!("?code={code}"), "tunnel.example.com").await;
    assert_eq!(status, 200);
    assert!(
        body.contains("--port YOUR_PORT"),
        "usage hint must guide the user: {body}"
    );
    assert!(body.contains("exit 1"), "hint script must exit 1: {body}");

    broker.stop().await;
}

// ---------------------------------------------------------------------------
// portal quickstart (part 2)
// ---------------------------------------------------------------------------
