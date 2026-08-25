//! Integration tests for ddns-client connect + register + heartbeat.

mod common;

use std::time::Duration;

use ddns_client::cli::{self, Cli};
use ddns_client::connect::{self, ConnError};
use ddns_client::targets::LocalTarget;
use ddns_proto::{Control, ErrorCode};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

fn make_cli(
    token: &str,
    server: &str,
    http_target: Option<LocalTarget>,
    tcp_target: Option<LocalTarget>,
    udp_target: Option<u16>,
) -> Cli {
    Cli {
        token: token.to_string(),
        server: server.to_string(),
        http_target,
        udp_target,
        tcp_target,
        name: None,
        ca_pem: None,
        heartbeat_interval: ddns_proto::HEARTBEAT_INTERVAL,
    }
}

#[tokio::test]
async fn register_success_http_tcp() {
    let (cert, key) = common::test_cert();
    let (addr, _broker, token) = common::start_broker(cert.clone(), key, "tok1").await;
    let roots = common::root_certs(&cert);

    let cli = make_cli(
        &token,
        &format!("https://127.0.0.1:{}", addr.port()),
        Some(LocalTarget::http(8080)),
        Some(LocalTarget::tcp(22)),
        None,
    );

    let (_write, _read, reply, _session_secret) =
        connect::connect_and_register(&cli, &roots).await.unwrap();
    match reply {
        Control::Registered {
            http_url, tcp_addr, ..
        } => {
            assert!(http_url.is_some(), "http_url should be Some");
            assert!(tcp_addr.is_some(), "tcp_addr should be Some");
            let url = http_url.unwrap();
            assert!(
                url.contains("tunnel.example.com"),
                "url should contain domain"
            );
            // 4-part slug: <slug>.tunnel.example.com
            let slug = url
                .strip_prefix("https://")
                .unwrap_or(&url)
                .strip_suffix(".tunnel.example.com")
                .unwrap_or("");
            assert_eq!(slug.split('-').count(), 4, "expected 4-part slug in: {url}");
        }
        other => panic!("expected Registered, got {other:?}"),
    }
}

#[tokio::test]
async fn register_http_only_sends_tcp_none() {
    let (cert, key) = common::test_cert();
    let (addr, _broker, token) = common::start_broker(cert.clone(), key, "tok2").await;
    let roots = common::root_certs(&cert);

    let cli = make_cli(
        &token,
        &format!("https://127.0.0.1:{}", addr.port()),
        Some(LocalTarget::http(8080)),
        None,
        None,
    );

    let (_write, _read, reply, _session_secret) =
        connect::connect_and_register(&cli, &roots).await.unwrap();
    match reply {
        Control::Registered {
            http_url, tcp_addr, ..
        } => {
            assert!(http_url.is_some(), "http_url should be Some");
            assert!(
                tcp_addr.is_none(),
                "tcp_addr should be None when only http requested"
            );
        }
        other => panic!("expected Registered, got {other:?}"),
    }
}

#[tokio::test]
async fn register_rejected_token() {
    let (cert, key) = common::test_cert();
    let (addr, _broker, _token) = common::start_broker(cert.clone(), key, "tok3").await;
    let roots = common::root_certs(&cert);

    let cli = make_cli(
        "bogus",
        &format!("https://127.0.0.1:{}", addr.port()),
        Some(LocalTarget::http(8080)),
        None,
        None,
    );

    let err = connect::connect_and_register(&cli, &roots)
        .await
        .unwrap_err();
    match err {
        ConnError::Rejected(code) => assert_eq!(code, ErrorCode::TokenInvalid),
        other => panic!("expected Rejected(TokenInvalid), got {other:?}"),
    }
}

#[tokio::test]
async fn heartbeat_gets_pong() {
    let (cert, key) = common::test_cert();
    let (addr, _broker, token) = common::start_broker(cert.clone(), key, "tok4").await;
    let roots = common::root_certs(&cert);

    let mut cli = make_cli(
        &token,
        &format!("https://127.0.0.1:{}", addr.port()),
        Some(LocalTarget::http(8080)),
        None,
        None,
    );
    cli.heartbeat_interval = Duration::from_millis(150);

    let (write, mut read, reply, _session_secret) =
        connect::connect_and_register(&cli, &roots).await.unwrap();
    assert!(matches!(reply, Control::Registered { .. }));

    // Create a channel and spawn a writer task that drains into the WS write half.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(64);
    tokio::spawn(async move {
        use futures_util::SinkExt;
        let mut write = write;
        while let Some(msg) = rx.recv().await {
            if write.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn heartbeat on the shared queue.
    connect::spawn_heartbeat(tx, cli.heartbeat_interval);

    // Read Pongs from the returned read half.
    use futures_util::StreamExt;
    let result = timeout(Duration::from_secs(2), async {
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(text) = msg
                && let Ok(Control::Pong { seq }) = serde_json::from_str(&text)
            {
                assert!(seq >= 1, "pong seq should be >= 1, got {seq}");
                return;
            }
        }
    })
    .await;

    assert!(result.is_ok(), "timed out waiting for Pong");
}

#[test]
fn cli_parse_defaults_and_errors() {
    // Valid: --token + --port → http_target Some, tcp None
    let cli = cli::parse(&[
        "--token".to_string(),
        "t".to_string(),
        "--port".to_string(),
        "8080".to_string(),
    ])
    .unwrap();
    assert!(cli.http_target.is_some());
    assert!(cli.tcp_target.is_none());
    assert_eq!(cli.server, "https://tunnel.example.com");

    // Missing token
    let err = cli::parse(&["--port".to_string(), "8080".to_string()]).unwrap_err();
    assert!(err.contains("token"), "expected token error, got: {err}");

    // No target
    let err = cli::parse(&["--token".to_string(), "t".to_string()]).unwrap_err();
    assert!(
        err.contains("target") || err.contains("--port") || err.contains("--tcp"),
        "expected target error, got: {err}"
    );

    // --server not https/wss
    let err = cli::parse(&[
        "--token".to_string(),
        "t".to_string(),
        "--server".to_string(),
        "http://x".to_string(),
        "--port".to_string(),
        "8080".to_string(),
    ])
    .unwrap_err();
    assert!(
        err.contains("https://") || err.contains("wss://"),
        "expected server scheme error, got: {err}"
    );

    // --tcp flag
    let cli = cli::parse(&[
        "--token".to_string(),
        "t".to_string(),
        "--tcp".to_string(),
        "22".to_string(),
    ])
    .unwrap();
    assert!(cli.http_target.is_none());
    assert!(cli.tcp_target.is_some());

    // --local flag
    let cli = cli::parse(&[
        "--token".to_string(),
        "t".to_string(),
        "--local".to_string(),
        "tcp://192.168.1.50:5432".to_string(),
    ])
    .unwrap();
    assert!(cli.tcp_target.is_some());
    let tgt = cli.tcp_target.unwrap();
    assert_eq!(tgt.host, "192.168.1.50");
    assert_eq!(tgt.port, 5432);

    // --server with wss://
    let cli = cli::parse(&[
        "--token".to_string(),
        "t".to_string(),
        "--server".to_string(),
        "wss://custom.example.com:9443".to_string(),
        "--port".to_string(),
        "8080".to_string(),
    ])
    .unwrap();
    assert_eq!(cli.server, "wss://custom.example.com:9443");
}

#[tokio::test]
async fn client_registers_with_no_tunnel_hint() {
    // Construct the same Control the client sends (mirror connect.rs) and
    // assert the wire shape stays hint-less by default.
    let msg = ddns_proto::Control::Register {
        token: "tok_x".into(),
        want_tcp: true,
        want_http: true,
        want_udp: false,
        udp_port: 0,
        subdomain_hint: None,
    };
    let json = serde_json::to_string(&msg).unwrap();
    let back: ddns_proto::Control = serde_json::from_str(&json).unwrap();
    match back {
        ddns_proto::Control::Register { subdomain_hint, .. } => assert!(subdomain_hint.is_none()),
        _ => panic!("expected Register"),
    }
}
