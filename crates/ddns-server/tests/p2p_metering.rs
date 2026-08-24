//! P2P data plane metering: bytes reported by the client over `UsageReport`
//! must accrue to the session counters and drive the existing quota watchdog.
//! Two reports of 600_000 tx + 400_000 rx = 2 MB, over the 1 MB cap.

mod common;

use std::time::Duration;

use common::{FakeClient, start_broker, test_cert};
use ddns_proto::{Control, KillReason, TokenLimits};
use ddns_server::TokenStore;

async fn store(limits: TokenLimits) -> TokenStore {
    let s = TokenStore::new();
    s.insert(
        "tok_quota".into(),
        common::test_record_with_limits("t-quota", limits),
    )
    .await
    .unwrap();
    s
}

/// Read controls until `Kill{want}`, asserting `Quota{usage}` preceded it and
/// that the reported usage is at least the cap (proves the UsageReport bytes
/// accrued, not some unrelated trigger). No stream frames are in flight here,
/// so every WS message is a control; binary frames are skipped for safety.
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
            tokio_tungstenite::tungstenite::Message::Text(t) => {
                match serde_json::from_str::<Control>(&t).unwrap() {
                    Control::Quota { usage } => {
                        assert!(
                            usage.bytes_tx.saturating_add(usage.bytes_rx) >= 1_000_000,
                            "quota usage must reflect the reported bytes: {usage:?}"
                        );
                        saw_quota = true;
                    }
                    Control::Kill { reason } => {
                        assert_eq!(reason, want);
                        assert!(saw_quota, "quota{{usage}} must precede kill");
                        return;
                    }
                    other => panic!("unexpected control {other:?}"),
                }
            }
            tokio_tungstenite::tungstenite::Message::Binary(_) => continue,
            _ => continue,
        }
    }
}

#[tokio::test]
async fn p2p_usage_report_accrues_and_kills_at_quota() {
    let (cert, key) = test_cert();
    let limits = TokenLimits {
        max_bytes: 1_000_000,
        ..TokenLimits::default()
    };
    let (addr, broker) = start_broker(
        &cert,
        &key,
        store(limits).await,
        256,
        Duration::from_millis(200),
    )
    .await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_quota").await;
    let slug = FakeClient::slug(&reply);

    // Two UsageReport controls, 600_000 tx + 400_000 rx = 1_000_000 bytes
    // each; 2 MB total over the 1 MB cap.
    for _ in 0..2 {
        fc.send_control(&Control::UsageReport {
            bytes_tx: 600_000,
            bytes_rx: 400_000,
            streams: 0,
            since_ts: 1_700_000_000,
        })
        .await;
    }

    recv_until_kill(&mut fc, KillReason::QuotaExceeded).await;
    fc.expect_ws_close().await;

    // Slug freed after kill:
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while broker.registry().lookup(&slug).is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "slug not freed after kill"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    broker.stop().await;
}
