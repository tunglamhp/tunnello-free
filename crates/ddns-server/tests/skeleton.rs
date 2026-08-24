//! ALPN dispatch smoke tests (updated for the Plan 3 auth gate: an
//! unauthenticated non-tunnel request is redirected to /setup, since the
//! operator dashboard now requires a session).

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{client_tls, start_broker, test_cert};
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn http1_request_is_auth_gated() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    let mut cfg = client_tls(&cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect("tunnel.example.com".try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        b"GET /nonexistent HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("302") && text.contains("/setup"),
        "expected 302 redirect, got:\n{text}"
    );
    broker.stop().await;
}

#[tokio::test]
async fn h2_request_is_auth_gated() {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    let cfg = client_tls(&cert);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http2()
        .build();
    let client: Client<_, String> = Client::builder(TokioExecutor::new()).build(https);
    let res = client
        .request(
            http::Request::builder()
                .uri(
                    format!("https://127.0.0.1:{}/nonexistent", addr.port())
                        .parse::<http::Uri>()
                        .unwrap(),
                )
                .body(String::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), 302);
    broker.stop().await;
}

#[tokio::test]
async fn tunnel_subdomain_root_serves_tunnel_not_dashboard() {
    // Regression: GET / on a tunnel subdomain must NOT expose the operator
    // dashboard. Unknown slug -> 404 from the tunnel dispatch.
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    let mut cfg = client_tls(&cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect("tunnel.example.com".try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        b"GET / HTTP/1.1\r\nHost: unknown-slug.tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("404") && !text.contains("Tunnel Dashboard"),
        "tunnel subdomain root must not serve the dashboard, got:\n{text}"
    );
    broker.stop().await;
}

#[tokio::test]
async fn apex_root_serves_operator_dashboard() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    let mut cfg = client_tls(&cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect("tunnel.example.com".try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("302") && text.contains("/setup"),
        "apex root must redirect to /setup when no admin, got:\n{text}"
    );
    broker.stop().await;
}

#[tokio::test]
async fn ddns_tcp_alpn_connection_is_accepted_then_dropped() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    let mut cfg = client_tls(&cert);
    cfg.alpn_protocols = vec![b"ddns-tcp".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect("nope.tunnel.example.com".try_into().unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"ddns-tcp".as_slice())
    );

    let mut tls = tls;
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    assert!(
        r.is_ok(),
        "broker must close ddns-tcp connections (bridge not wired until Task 5)"
    );
    broker.stop().await;
}
