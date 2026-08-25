//! End-to-end tunnel tests: HTTP + TCP mux streams through a real broker.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use ddns_client::cli::Cli;
use ddns_client::targets::LocalTarget;
use ddns_client::{Event, TunnelInfo};
use ddns_proto::StreamKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Launch a local raw-HTTP server that reads one request head and replies
/// with a fixed 200 response. Returns its address and the task handle.
async fn http_local_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .unwrap();
    });
    (addr, h)
}

/// Launch a local TCP echo server. Returns its address and the task handle.
async fn tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    (addr, h)
}

/// Launch a local echo server that echoes the request body length as the
/// response body (for the large_payload test).
/// Launch a local server that reads the full request, counts total bytes,
/// and returns the count as a JSON body.
async fn http_echo_body_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 8192];
        // Shut down the write side so the client knows we're done reading
        // (the client sees EOF on lr after we close our write side).
        // But we need to send a response, so just read until we have
        // the Content-Length worth of data.
        //
        // Simple approach: read until \r\n\r\n, extract Content-Length,
        // then read exactly that many bytes.
        let mut head = Vec::new();
        loop {
            match sock.read(&mut tmp).await {
                Ok(0) => return,
                Ok(n) => {
                    head.extend_from_slice(&tmp[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let head_end = head.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head_str = String::from_utf8_lossy(&head[..head_end]);
        let mut cl: usize = 0;
        for line in head_str.split("\r\n") {
            let lower = line.to_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                cl = v.trim().parse().unwrap_or(0);
                break;
            }
        }
        // The head buffer may already contain some body bytes.
        let body_so_far = head.len() - (head_end + 4);
        let mut remaining = cl.saturating_sub(body_so_far);
        while remaining > 0 {
            match sock.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => remaining = remaining.saturating_sub(n),
                Err(_) => break,
            }
        }
        let response_body = cl.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let _ = sock.write_all(response.as_bytes()).await;
    });
    (addr, h)
}

/// Connect, register, and spawn the tunnel mux in a background task.
/// Returns the TunnelInfo (slug etc.) and an abort handle.
async fn spawn_tunnel(cli: Cli, cert_pem: &[u8]) -> (TunnelInfo, tokio::task::JoinHandle<()>) {
    let roots = common::root_certs(cert_pem);
    let (info_tx, mut info_rx) = mpsc::channel(1);
    let h = tokio::spawn(async move {
        ddns_client::run(cli, &roots, |event| {
            if let Event::Registered(info) = event {
                let _ = info_tx.try_send(info);
            }
        })
        .await;
    });
    let info = info_rx.recv().await.expect("tunnel should register");
    (info, h)
}

/// TLS TCP client for ddns-tcp ALPN. Connects, performs TLS with SNI + ALPN,
/// and returns the TLS stream.
async fn tls_tcp_connect(
    addr: SocketAddr,
    cert_pem: &[u8],
    sni: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"ddns-tcp".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name = sni.to_string().try_into().unwrap();
    connector.connect(server_name, stream).await.unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// HTTP end-to-end: broker + client + a local raw-HTTP server.
/// Visitor does TLS HTTP/1.1 GET to the tunnel subdomain and gets the local
/// server's response.
#[tokio::test]
async fn http_tunnel_end_to_end() {
    let (cert, key) = common::test_cert();
    let (addr, broker, token) = common::start_broker(cert.clone(), key, "t1").await;
    let (local_addr, _lh) = http_local_server().await;
    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: Some(LocalTarget {
            kind: StreamKind::Http,
            host: "127.0.0.1".into(),
            port: local_addr.port(),
        }),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };
    let (info, _tunnel_h) = spawn_tunnel(cli, &cert).await;
    let slug = info.slug;
    let host = format!("{slug}.tunnel.example.com");

    // Visitor request
    let request = format!("GET /hi HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let resp = common::http1(addr, &cert, &host, &request).await;
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 from tunnel, got: {resp}"
    );
    assert!(resp.contains("hello"), "expected body 'hello', got: {resp}");

    broker.stop().await;
    _tunnel_h.abort();
}

/// TCP end-to-end: local echo server; visitor connects with SNI=<slug> and
/// ALPN=ddns-tcp, sends "ping", reads "ping" back, sends "pong", reads "pong".
#[tokio::test]
async fn tcp_tunnel_end_to_end() {
    let (cert, key) = common::test_cert();
    let (addr, broker, token) = common::start_broker(cert.clone(), key, "t2").await;
    let (local_addr, _eh) = tcp_echo_server().await;
    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: None,
        tcp_target: Some(LocalTarget {
            kind: StreamKind::Tcp,
            host: "127.0.0.1".into(),
            port: local_addr.port(),
        }),
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };
    let (info, _tunnel_h) = spawn_tunnel(cli, &cert).await;
    let slug = info.slug;
    let sni = format!("{slug}.tunnel.example.com");

    let mut tls = tls_tcp_connect(addr, &cert, &sni).await;

    tls.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"ping", "expected ping echo");

    tls.write_all(b"pong").await.unwrap();
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong", "expected pong echo");

    broker.stop().await;
    _tunnel_h.abort();
}

/// A stalled local TCP peer must not wedge the session. The local target
/// accepts a connection and never reads it; once the client's bounded local
/// write times out it sends Close{CLOSE_APP_ERROR} (broker closes the visitor
/// side) and keeps draining, so the shared mux recv loop survives and a NEW
/// stream still dials + echoes. Regression for the unbounded ws→local write
/// that wedged the whole session (recv loop blocked on a full channel, Kill/
/// Close never processed, client hung forever).
#[tokio::test]
async fn stalled_tcp_peer_does_not_wedge_session() {
    let (cert, key) = common::test_cert();
    let (addr, broker, token) = common::start_broker(cert.clone(), key, "t5").await;

    // Local target: accept two connections. The first is never read (stalled
    // peer); the second is an echo server proving new streams still work.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let stalled_h = tokio::spawn(async move {
        // _s1 is the stalled peer: accepted, never read, kept open for the
        // task's lifetime (it is only dropped when the task ends).
        let (_s1, _) = listener.accept().await.unwrap();
        let (mut s2, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        loop {
            match s2.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if s2.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: None,
        tcp_target: Some(LocalTarget {
            kind: StreamKind::Tcp,
            host: "127.0.0.1".into(),
            port: local_addr.port(),
        }),
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };
    let (info, _tunnel_h) = spawn_tunnel(cli, &cert).await;
    let sni = format!("{}.tunnel.example.com", info.slug);

    // Visitor 1: push 2 MiB at the stalled peer (well past the client's
    // per-stream channel + socket buffering, so the client's local write
    // blocks), then expect the stream to be closed by the client within a
    // bounded window. Without the fix the client hangs forever.
    let v1 = tokio::spawn({
        let cert = cert.clone();
        let sni = sni.clone();
        async move {
            let mut tls = tls_tcp_connect(addr, &cert, &sni).await;
            let chunk = vec![0u8; 8192];
            for _ in 0..256 {
                if tls.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let mut buf = [0u8; 16];
            tls.read(&mut buf).await
        }
    });
    let v1_res = tokio::time::timeout(Duration::from_secs(15), v1)
        .await
        .expect("stalled stream must be closed by the client, not hang the session");
    assert!(
        matches!(v1_res, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "stalled visitor stream should be closed (EOF/err), got {v1_res:?}"
    );

    // Visitor 2: a brand-new stream still dials and echoes — the recv loop
    // survived the stall.
    let mut tls2 = tls_tcp_connect(addr, &cert, &sni).await;
    tls2.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    let n = tokio::time::timeout(Duration::from_secs(10), tls2.read(&mut buf))
        .await
        .expect("second stream must be served after the stall")
        .unwrap();
    assert_eq!(&buf[..n], b"ping", "expected ping echo after stall");

    broker.stop().await;
    _tunnel_h.abort();
    stalled_h.abort();
}

/// OpenReject: http target port has nothing listening → visitor gets 502.
#[tokio::test]
async fn dead_local_target_gives_502() {
    let (cert, key) = common::test_cert();
    let (addr, _broker, token) = common::start_broker(cert.clone(), key, "t3").await;
    // Pick a port nothing is listening on (bind then drop — never flaky).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = l.local_addr().unwrap().port();
    drop(l);
    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: Some(LocalTarget {
            kind: StreamKind::Http,
            host: "127.0.0.1".into(),
            port: dead_port,
        }),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };
    let (info, _tunnel_h) = spawn_tunnel(cli, &cert).await;
    let slug = info.slug;
    let host = format!("{slug}.tunnel.example.com");

    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let resp = common::http1(addr, &cert, &host, &request).await;
    // The broker turns the client's OpenReject into a real 502 (BAD_GATEWAY).
    assert!(
        resp.starts_with("HTTP/1.1 502"),
        "expected 502 for dead target, got: {resp}"
    );

    _broker.stop().await;
    _tunnel_h.abort();
}

/// Data chunking: send 100 KiB through the HTTP tunnel; local server echoes
/// the body length; assert visitor receives the full 100 KiB (exercises
/// MAX_FRAME_PAYLOAD boundaries + multiple DATA frames).
#[tokio::test]
async fn large_payload_roundtrip() {
    let (cert, key) = common::test_cert();
    let (addr, broker, token) = common::start_broker(cert.clone(), key, "t4").await;
    let (local_addr, _eh) = http_echo_body_server().await;
    let cli = Cli {
        token,
        server: format!("https://127.0.0.1:{}", addr.port()),
        http_target: Some(LocalTarget {
            kind: StreamKind::Http,
            host: "127.0.0.1".into(),
            port: local_addr.port(),
        }),
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: None,
        heartbeat_interval: Duration::from_secs(30),
    };
    let (info, _tunnel_h) = spawn_tunnel(cli, &cert).await;
    let slug = info.slug;
    let host = format!("{slug}.tunnel.example.com");

    let body = "A".repeat(100 * 1024); // 100 KiB
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let resp = common::http1(addr, &cert, &host, &request).await;
    // The local server echoes the body length as the response body.
    let expected_len = body.len().to_string();
    assert!(
        resp.contains(&expected_len),
        "expected response to contain body length {expected_len}, got: {resp}"
    );

    broker.stop().await;
    _tunnel_h.abort();
}
