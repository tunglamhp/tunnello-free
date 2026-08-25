//! Tests for /install.sh and /download/{file} static-binary serving (Task 5).

use std::sync::Arc;
use std::time::Duration;

use ddns_server::{Broker, BrokerConfig, TokenStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

mod common;

use common::client_tls;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Send an HTTP/1.1 request over TLS and return the full raw response.
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

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_script_served() {
    let (cert, key) = common::test_cert();
    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
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

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /install.sh HTTP/1.1\r\nHost: tunnel.example.com:8443\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "expected 200, got: {:.200}",
        resp
    );
    assert!(
        resp.contains("#!/bin/sh"),
        "expected script body, got: {:.200}",
        resp
    );
    assert!(
        resp.contains("BASE=\"${DDNS_SERVER:-https://tunnel.example.com:8443}\""),
        "install script should preserve the public port, got: {resp}"
    );
    assert!(
        resp.to_lowercase()
            .contains("content-type: text/x-shellscript"),
        "expected text/x-shellscript, got: {:.200}",
        resp
    );

    broker.stop().await;
}

#[tokio::test]
async fn download_serves_binary() {
    use std::io::Write;

    let (cert, key) = common::test_cert();

    // Create a temp dir with a fake binary file.
    let tmpdir = std::env::temp_dir().join(format!(
        "ddns-download-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let binary_name = "ddns-x86_64-unknown-linux-musl";
    let binary_path = tmpdir.join(binary_name);
    let binary_bytes = b"fake-binary-content-abc123";
    {
        let mut f = std::fs::File::create(&binary_path).unwrap();
        f.write_all(binary_bytes).unwrap();
    }

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: Some(tmpdir.clone()),
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    let addr = broker.addr;

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &format!(
            "GET /download/{binary_name} HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;

    assert!(
        resp.starts_with("HTTP/1.1 200 OK"),
        "expected 200, got: {:.200}",
        resp
    );
    assert!(
        resp.to_lowercase()
            .contains("content-type: application/octet-stream"),
        "expected octet-stream, got: {:.200}",
        resp
    );

    // Verify the body contains the exact bytes.
    let body_start = resp.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = &resp[body_start..];
    assert!(
        body.as_bytes()
            .windows(binary_bytes.len())
            .any(|w| w == binary_bytes),
        "body does not contain expected bytes '{}'",
        String::from_utf8_lossy(binary_bytes)
    );

    // Best-effort cleanup.
    broker.stop().await;
    let _ = std::fs::remove_file(&binary_path);
    let _ = std::fs::remove_dir(&tmpdir);
}

#[tokio::test]
async fn download_missing_404() {
    let (cert, key) = common::test_cert();

    let tmpdir = std::env::temp_dir().join(format!(
        "ddns-download-test-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmpdir).unwrap();

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: Some(tmpdir.clone()),
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    let addr = broker.addr;

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /download/nope HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        resp.starts_with("HTTP/1.1 404"),
        "expected 404, got: {:.200}",
        resp
    );

    broker.stop().await;
    let _ = std::fs::remove_dir(&tmpdir);
}

#[tokio::test]
async fn download_traversal_blocked() {
    let (cert, key) = common::test_cert();

    let tmpdir = std::env::temp_dir().join(format!(
        "ddns-download-test-traversal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmpdir).unwrap();

    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
        watchdog_interval: Duration::from_secs(30),
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: Some(tmpdir.clone()),
        dev: false,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    let addr = broker.addr;

    // URL-encoded traversal attempt: ..%2F..%2Fetc%2Fpasswd
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /download/..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        resp.starts_with("HTTP/1.1 404"),
        "expected 404 for traversal attempt, got: {:.200}",
        resp
    );

    broker.stop().await;
    let _ = std::fs::remove_dir(&tmpdir);
}

#[tokio::test]
async fn download_requires_download_dir() {
    let (cert, key) = common::test_cert();
    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: TokenStore::new(),
        max_sessions: 4,
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

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /download/x HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        resp.starts_with("HTTP/1.1 404"),
        "expected 404 when download_dir is None, got: {:.200}",
        resp
    );

    broker.stop().await;
}
