//! Shared test helpers for ddns-client integration tests.
//!
//! Mirrors ddns-server's test helpers: self-signed TLS certs via rcgen 0.13,
//! in-process broker launch, TLS HTTP/1.1 client, and root cert construction.

use std::net::SocketAddr;
use std::time::Duration;

use rustls::pki_types::CertificateDer;

/// Self-signed cert with SANs for the tunnel domain, its wildcard, and loopback
/// IPs (so wss:// tests can connect to 127.0.0.1 with a verifiable server_name).
pub fn test_cert() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair};
    let params = CertificateParams::new(vec![
        "tunnel.example.com".to_string(),
        "*.tunnel.example.com".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

/// Launch an in-process broker with the given cert/key and a single token.
/// Returns the bound address, the broker handle, and the token secret.
pub async fn start_broker(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    token: &str,
) -> (SocketAddr, ddns_server::Broker, String /* token */) {
    let store = ddns_server::TokenStore::new();
    let (_, secret) = store
        .create(token, ddns_proto::TokenLimits::default())
        .await
        .unwrap();
    let (addr, broker) = start_broker_with_store(cert_pem, key_pem, store).await;
    (addr, broker, secret)
}

/// Start a broker with a pre-seeded store (e.g. a client account already at
/// zero balance, to exercise the token-exhaustion registration path).
pub async fn start_broker_with_store(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    store: ddns_server::TokenStore,
) -> (SocketAddr, ddns_server::Broker) {
    use ddns_server::{Broker, BrokerConfig};
    let config = BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert_pem,
        tls_key_pem: key_pem,
        token_store: store,
        max_sessions: 16,
        watchdog_interval: Duration::from_millis(200),
        http_listen: None,
        stun_listen: None,
        download_dir: None,
        dev: true,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        acme: None,
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = Broker::start(config).await.unwrap();
    (broker.addr, broker)
}

/// Build a `Vec<CertificateDer<'static>>` from the PEM cert bytes so the
/// client TLS config can trust a test broker's self-signed certificate.
pub fn root_certs(cert_pem: &[u8]) -> Vec<CertificateDer<'static>> {
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .unwrap();
    certs
}

/// Minimal TLS HTTP/1.1 client. Connects to `addr`, performs a TLS handshake
/// with `cert_pem` as the trusted root, and sends `request` (e.g.
/// `"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"`).
/// Returns the FULL raw response (status line + headers + body) so tests can
/// assert on the status line (e.g. the broker's 502 for a dead target).
#[allow(dead_code)]
pub async fn http1(addr: SocketAddr, cert_pem: &[u8], host: &str, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host)
        .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("tunnel.example.com").unwrap())
        .to_owned();
    let mut tls = connector.connect(server_name, stream).await.unwrap();

    tls.write_all(request.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    // Read with a generous timeout. The broker may need to forward the
    // request to the client and wait for an OpenAck (up to 30 s).
    match tokio::time::timeout(Duration::from_secs(30), tls.read_to_end(&mut buf)).await {
        Ok(Ok(_n)) => {}
        Ok(Err(e)) => panic!("TLS read error: {e}"),
        Err(_) => panic!("timeout waiting for HTTP response"),
    }
    // Keep the full raw response (head + body) — tests assert on the head.
    String::from_utf8_lossy(&buf).into_owned()
}
