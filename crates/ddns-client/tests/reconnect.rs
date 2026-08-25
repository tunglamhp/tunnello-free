//! Integration tests for ddns-client reconnect, kill semantics, and
//! session events (Task 3).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use ddns_client::cli::Cli;
use ddns_client::targets::LocalTarget;
use ddns_client::{Event, ExitStatus};
use ddns_proto::{KillReason, TokenLimits};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Tolerant TLS HTTP/1.1 visitor for the kill test: the broker may reset
/// (RST) the visitor connection when the session is killed, so a read error
/// is treated as the response ending rather than a test failure.
async fn tolerant_http_visitor(
    addr: SocketAddr,
    cert_pem: &[u8],
    host: &str,
    request: &str,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut root_store = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        root_store.add(c).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = host.to_string().try_into().unwrap();
    let mut tls = connector.connect(server_name, stream).await.unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf).await; // tolerate a mid-response reset
    String::from_utf8_lossy(&buf).into_owned()
}

/// Start a broker on a *specific* address.
async fn start_broker_on_addr(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    token_name: &str,
    limits: TokenLimits,
    addr: SocketAddr,
) -> (SocketAddr, ddns_server::Broker, String /* secret */) {
    let store = ddns_server::TokenStore::new();
    let (_, secret) = store.create(token_name, limits).await.unwrap();
    let config = ddns_server::BrokerConfig {
        listen: addr,
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
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
    let broker = ddns_server::Broker::start(config).await.unwrap();
    (broker.addr, broker, secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Token with max_bytes: 50. Client registers with a working local HTTP
/// target. Visitor does a GET request; the local server responds with a
/// 1000-byte body. The broker forwarding this response exceeds the quota.
/// Watchdog sends Quota + Kill. Client emits Killed with usage, returns
/// ExitStatus::Killed(QuotaExceeded).
#[tokio::test]
async fn kill_quota_exits_killed() {
    let (cert, key) = common::test_cert();
    let roots = common::root_certs(&cert);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let limits = TokenLimits {
        max_bytes: 50,
        ..TokenLimits::default()
    };
    let (bound_addr, broker, token) =
        start_broker_on_addr(cert.clone(), key, "killtest", limits, addr).await;

    // Local server that reads request head and returns a large body (1000 B).
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = local_listener.local_addr().unwrap().port();
    let _local_handle = tokio::spawn(async move {
        let (mut sock, _) = local_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
        let body = "x".repeat(1000);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, resp.as_bytes()).await;
    });

    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", bound_addr.port()),
        http_target: Some(LocalTarget::http(local_port)),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let roots2 = roots.clone();
    let h = tokio::spawn(async move {
        ddns_client::run(cli, &roots2, |event| {
            let _ = tx.send(event);
        })
        .await
    });

    // Wait for Registered
    let slug = loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(Event::Registered(ref info))) => break info.slug.clone(),
            Ok(Some(Event::Fatal(msg))) => panic!("unexpected Fatal: {msg}"),
            Ok(Some(_)) => continue,
            Ok(None) => panic!("channel closed before Registered"),
            Err(_) => panic!("timed out waiting for Registered"),
        }
    };

    // Visitor GET request — response body will be 1000 bytes, exceeding quota.
    let request =
        format!("GET / HTTP/1.1\r\nHost: {slug}.tunnel.example.com\r\nConnection: close\r\n\r\n");
    // The broker may reset the visitor connection when the session is killed
    // (mid-response), so use the tolerant visitor.
    let _resp = tolerant_http_visitor(
        bound_addr,
        &cert,
        &format!("{slug}.tunnel.example.com"),
        &request,
    )
    .await;

    // Wait for Killed event
    let mut saw_killed = false;
    let mut kill_reason = None;
    let mut kill_usage = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(Event::Killed { reason, usage })) => {
                saw_killed = true;
                kill_reason = Some(reason);
                kill_usage = Some(usage);
                break;
            }
            Ok(Some(Event::Retrying { .. })) => {
                // The 0-attempt connection was killed, backoff will retry.
                // Continue waiting — we may get another Killed for the
                // retry (but quota kill should be final for that session).
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => {
                if tokio::time::Instant::now() > deadline {
                    panic!("timed out waiting for Killed event");
                }
            }
        }
    }

    let status = h.await.unwrap();
    assert!(saw_killed, "never saw Killed event");
    assert_eq!(status, ExitStatus::Killed(KillReason::QuotaExceeded));
    assert_eq!(kill_reason, Some(KillReason::QuotaExceeded));
    assert!(
        kill_usage.flatten().is_some(),
        "Killed event should include usage: {kill_usage:?}"
    );

    broker.stop().await;
}

/// Blackhole port → Retrying events → broker starts on that port →
/// re-registration with a new slug.
#[tokio::test]
async fn reconnect_after_blackhole_re_registers() {
    // 1. Find an unused port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blackhole_port = listener.local_addr().unwrap().port();
    drop(listener);

    let (cert, key) = common::test_cert();
    let roots = common::root_certs(&cert);

    // Pre-create token so client and broker share secret.
    let store = ddns_server::TokenStore::new();
    let limits = TokenLimits::default();
    let (_id, token_secret) = store.create("blackhole-tok", limits).await.unwrap();

    let cli = Cli {
        token: token_secret.clone(),
        server: format!("https://127.0.0.1:{blackhole_port}"),
        http_target: Some(LocalTarget::http(8080)),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };

    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let (status_tx, _status_rx) = mpsc::channel(1);
    let cli2 = cli.clone();
    let roots2 = roots.clone();
    let h = tokio::spawn(async move {
        let s = ddns_client::run(cli2, &roots2, |event| {
            let _ = ev_tx.send(event);
        })
        .await;
        let _ = status_tx.send(s).await;
    });

    // 2. Wait for Retrying (attempt >= 1) within ~6 s.
    let mut saw_retrying = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(300), ev_rx.recv()).await {
            Ok(Some(Event::Retrying { attempt, .. })) if attempt >= 1 => {
                saw_retrying = true;
                break;
            }
            Ok(Some(Event::Fatal(msg))) => panic!("unexpected Fatal before broker: {msg}"),
            _ => continue,
        }
    }
    assert!(saw_retrying, "expected Retrying event within 6 s");

    // 3. Start broker on the blackhole port.
    let addr: SocketAddr = format!("127.0.0.1:{blackhole_port}").parse().unwrap();
    let broker_config = ddns_server::BrokerConfig {
        listen: addr,
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        udp_routes: Vec::new(),
        oidc: None,
        tls_cert_pem: cert.clone(),
        tls_key_pem: key,
        token_store: store,
        max_sessions: 16,
        watchdog_interval: Duration::from_millis(200),
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: None,
        dev: true,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        redis_url: None,
        max_streams_per_session: 512,
    };
    let broker = ddns_server::Broker::start(broker_config).await.unwrap();

    // 4. Wait for Registered within ~15 s.
    let mut saw_registered = false;
    let mut slug = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), ev_rx.recv()).await {
            Ok(Some(Event::Registered(ref info))) => {
                saw_registered = true;
                slug = info.slug.clone();
                break;
            }
            Ok(Some(Event::Fatal(msg))) => panic!("unexpected Fatal: {msg}"),
            _ => continue,
        }
    }
    assert!(
        saw_registered,
        "expected Registered event after broker started"
    );
    assert!(!slug.is_empty(), "slug should not be empty");
    assert!(
        slug.split('-').count() >= 2,
        "slug should have hyphens: {slug}"
    );

    h.abort();
    broker.stop().await;
}

/// Unit test: Backoff::next_delay() produces correct exponential sequence.
#[test]
fn backoff_sequence() {
    use ddns_client::reconnect::Backoff;
    let mut b = Backoff::new();
    assert_eq!(b.next_delay(), Duration::from_secs(1));
    assert_eq!(b.next_delay(), Duration::from_secs(2));
    assert_eq!(b.next_delay(), Duration::from_secs(4));
    assert_eq!(b.next_delay(), Duration::from_secs(8));
    assert_eq!(b.next_delay(), Duration::from_secs(16));
    assert_eq!(b.next_delay(), Duration::from_secs(30));
    assert_eq!(b.next_delay(), Duration::from_secs(30));
    assert_eq!(b.next_delay(), Duration::from_secs(30));

    // A successful registration resets: the next delay is 1 s again.
    b.reset();
    assert_eq!(b.next_delay(), Duration::from_secs(1));
}

/// Invalid token → Fatal immediately, no retry.
#[tokio::test]
async fn invalid_token_fatal_no_retry() {
    let (cert, key) = common::test_cert();
    let roots = common::root_certs(&cert);
    let (addr, broker, _token) = common::start_broker(cert, key, "valid-tok").await;

    let cli = Cli {
        token: "bogus-invalid-token".to_string(),
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: Some(LocalTarget::http(8080)),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };

    let mut events: Vec<Event> = Vec::new();
    let status = ddns_client::run(cli, &roots, |event| {
        events.push(event);
    })
    .await;

    assert_eq!(
        status,
        ExitStatus::Fatal,
        "expected Fatal for invalid token"
    );
    assert!(
        events.iter().any(|e| matches!(e, Event::Fatal(_))),
        "expected Fatal event: {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, Event::Retrying { .. })),
        "should not retry on invalid token: {events:?}"
    );

    broker.stop().await;
}
