//! Graceful shutdown tests: drain, kill, new-connection refusal, instant stop.

mod common;

use std::time::Duration;

use common::{FakeClient, start_broker, test_cert};
use ddns_proto::{Control, KillReason, TokenLimits};
use ddns_server::TokenStore;
use tokio_tungstenite::tungstenite;

/// Read controls until `Kill{want}`, asserting `Quota{usage}` preceded it.
/// Skips in-flight binary frames.
async fn recv_until_kill(fc: &mut FakeClient, want: KillReason) {
    use futures_util::StreamExt as _;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut saw_quota = false;
    loop {
        assert!(tokio::time::Instant::now() < deadline, "kill never arrived");
        let msg = tokio::time::timeout(Duration::from_secs(3), fc.ws.next())
            .await
            .expect("timed out waiting for control")
            .expect("ws closed before kill")
            .expect("ws error before kill");
        match msg {
            tungstenite::Message::Text(t) => match serde_json::from_str::<Control>(&t).unwrap() {
                Control::Quota { .. } => saw_quota = true,
                Control::Kill { reason } => {
                    assert_eq!(reason, want);
                    assert!(saw_quota, "quota{{usage}} must precede kill");
                    return;
                }
                other => panic!("unexpected control {other:?}"),
            },
            tungstenite::Message::Binary(_) => continue,
            _ => continue,
        }
    }
}

#[tokio::test]
async fn stop_kills_sessions_gracefully() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert(
            "tok_stop".into(),
            common::test_record_with_limits(
                "t-stop",
                TokenLimits {
                    max_bytes: u64::MAX,
                    ttl_secs: 3600,
                    ..TokenLimits::default()
                },
            ),
        )
        .await
        .unwrap();

    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(3600)).await;
    let (mut fc, _reply) = FakeClient::connect(addr, &cert, "tok_stop").await;

    // Stop the broker gracefully.
    broker.stop().await;

    // Client must receive quota{usage} then kill{admin} then WS close.
    recv_until_kill(&mut fc, KillReason::Admin).await;
    fc.expect_ws_close().await;
}

#[tokio::test]
async fn stop_returns_promptly() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert(
            "tok_prompt".into(),
            common::test_record_with_limits(
                "t-prompt",
                TokenLimits {
                    max_bytes: u64::MAX,
                    ttl_secs: 3600,
                    ..TokenLimits::default()
                },
            ),
        )
        .await
        .unwrap();

    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(3600)).await;
    let (_fc, _reply) = FakeClient::connect(addr, &cert, "tok_prompt").await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    broker.stop().await;
    assert!(
        tokio::time::Instant::now() < deadline,
        "stop() took longer than 5 s"
    );
}

#[tokio::test]
async fn new_connections_refused_after_stop() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert(
            "tok_refuse".into(),
            common::test_record_with_limits(
                "t-refuse",
                TokenLimits {
                    max_bytes: u64::MAX,
                    ttl_secs: 3600,
                    ..TokenLimits::default()
                },
            ),
        )
        .await
        .unwrap();

    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(3600)).await;

    // Stop the broker first.
    broker.stop().await;

    // A fresh TLS connect should fail within 2 s.
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        FakeClient::connect_raw(addr, &cert, "tok_refuse", true, true),
    )
    .await;

    // Either the connect times out (listener gone) or the broker rejects it.
    // In either case we did not hang.
    if let Ok((_fc, Ok(_))) = result {
        panic!("connection succeeded after stop() — should be refused");
    }
}

#[tokio::test]
async fn stop_without_sessions_is_instant() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();

    let (_addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(3600)).await;
    // Give the accept loop a moment to enter its select.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let start = tokio::time::Instant::now();
    broker.stop().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "stop() without sessions took {:?}, expected < 1 s",
        elapsed
    );
}
