//! Task 2 acceptance: allocation, caps, counters.

use std::time::Duration;

use ddns_proto::{KillReason, TokenLimits, Usage};
use ddns_server::{AllocError, Registry, TunnelSession};
use tokio::sync::mpsc;
use tokio::sync::watch;

fn ws_tx() -> mpsc::Sender<axum::extract::ws::Message> {
    let (tx, _rx) = mpsc::channel(8);
    tx
}

fn kill_tx() -> watch::Sender<Option<KillReason>> {
    let (tx, _rx) = watch::channel(None);
    tx
}

fn limits() -> TokenLimits {
    TokenLimits {
        max_sessions: 2,
        max_streams: 2,
        max_bytes: 1000,
        ttl_secs: 60,
        ..TokenLimits::default()
    }
}

#[test]
fn allocated_slugs_match_pattern_and_are_unique() {
    let reg = Registry::new(256);
    let mut slugs = std::collections::HashSet::new();
    for i in 0..32 {
        // Distinct token ids keep the per-token session cap (2) out of the way.
        let s = reg
            .allocate(
                format!("t-{i}"),
                true,
                true,
                false,
                0,
                limits(),
                ws_tx(),
                kill_tx(),
                None,
                None,
                Default::default(),
            )
            .unwrap();
        let parts: Vec<&str> = s.slug.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[2].len(), 2);
        assert!(u8::from_str_radix(parts[2], 16).is_ok());
        assert_eq!(parts[3].len(), 4);
        assert!(u16::from_str_radix(parts[3], 16).is_ok());
        assert!(slugs.insert(s.slug.clone()), "duplicate slug {}", s.slug);
    }
    assert_eq!(reg.len(), 32);
}

#[test]
fn global_cap_rejects_allocation() {
    let reg = Registry::new(2);
    reg.allocate(
        "t1".into(),
        false,
        true,
        false,
        0,
        limits(),
        ws_tx(),
        kill_tx(),
        None,
        None,
        Default::default(),
    )
    .unwrap();
    reg.allocate(
        "t1".into(),
        false,
        true,
        false,
        0,
        limits(),
        ws_tx(),
        kill_tx(),
        None,
        None,
        Default::default(),
    )
    .unwrap();
    match reg.allocate(
        "t1".into(),
        false,
        true,
        false,
        0,
        limits(),
        ws_tx(),
        kill_tx(),
        None,
        None,
        Default::default(),
    ) {
        Err(AllocError::ServerFull { active, max }) => {
            assert_eq!(active, 2);
            assert_eq!(max, 2);
        }
        Err(e) => panic!("expected ServerFull, got {e:?}"),
        Ok(_) => panic!("expected ServerFull, got Ok"),
    }
}

#[test]
fn lookup_and_remove() {
    let reg = Registry::new(4);
    let s = reg
        .allocate(
            "t1".into(),
            false,
            true,
            false,
            0,
            limits(),
            ws_tx(),
            kill_tx(),
            None,
            None,
            Default::default(),
        )
        .unwrap();
    assert!(reg.lookup(&s.slug).is_some());
    let removed = reg.remove(&s.slug);
    assert!(removed.is_some());
    assert!(reg.lookup(&s.slug).is_none());
    assert!(reg.is_empty());
}

#[tokio::test]
async fn session_counters_streams_and_ttl() {
    let (kill_tx, mut kill_rx) = watch::channel(None);
    let s = TunnelSession::new(
        "t1".into(),
        "vivid-otter-72".into(),
        true,
        true,
        false,
        0,
        limits(),
        ws_tx(),
        kill_tx.clone(),
        Default::default(),
        512,
    );
    // stream slots
    assert!(s.register_stream());
    assert!(s.register_stream());
    assert!(
        !s.register_stream(),
        "third stream must be rejected at max_streams=2"
    );
    s.release_stream();
    assert!(s.register_stream(), "slot freed after release");
    s.release_stream();
    s.release_stream();
    assert_eq!(s.usage().streams, 0);
    // byte counters
    s.record_tx(500);
    s.record_rx(400);
    let u: Usage = s.usage();
    assert_eq!((u.bytes_tx, u.bytes_rx), (500, 400));
    assert!(!s.over_quota(), "900 < 1000");
    s.record_rx(100);
    assert!(s.over_quota(), "1000 >= 1000");
    // stream ids monotonic from 1
    assert_eq!(s.next_stream_id(), 1);
    assert_eq!(s.next_stream_id(), 2);
    // ttl
    let mut limits = limits();
    limits.ttl_secs = 1;
    let short = TunnelSession::new(
        "t1".into(),
        "x".into(),
        false,
        true,
        false,
        0,
        limits,
        ws_tx(),
        kill_tx.clone(),
        Default::default(),
        512,
    );
    assert!(!short.expired());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(short.expired());
    // kill channel: kill() signals the receiver the mux would hold
    short.kill(KillReason::TtlExpired);
    kill_rx.changed().await.unwrap();
    assert_eq!(*kill_rx.borrow(), Some(KillReason::TtlExpired));
}

#[tokio::test]
async fn send_frame_queues_encoded_binary_message() {
    let (tx, mut rx) = mpsc::channel(8);
    let s = TunnelSession::new(
        "t1".into(),
        "slug".into(),
        false,
        true,
        false,
        0,
        limits(),
        tx,
        kill_tx(),
        Default::default(),
        512,
    );
    let f = ddns_proto::Frame {
        opcode: ddns_proto::Opcode::Ping,
        stream_id: 3,
        payload: bytes::Bytes::from_static(b"hi"),
    };
    assert!(s.send_frame(&f).await);
    let msg = rx.try_recv().unwrap();
    match msg {
        axum::extract::ws::Message::Binary(b) => {
            let decoded = ddns_proto::Frame::decode(&b).unwrap();
            assert_eq!(decoded, f);
        }
        other => panic!("expected Binary, got {other:?}"),
    }
}

#[tokio::test]
async fn allocate_preferred_slug_and_custom_host() {
    let reg = Registry::new(8);
    let opts = ddns_server::tunnel::HttpOptions::default();
    let _s = reg
        .allocate(
            "tok".into(),
            true,
            true,
            false,
            0,
            limits(),
            ws_tx(),
            kill_tx(),
            Some("my-fixed".into()),
            Some("app.example.com".into()),
            opts,
        )
        .unwrap();
    assert!(reg.lookup("my-fixed").is_some());
    assert!(reg.custom_host("app.example.com").is_some());
    assert!(
        reg.custom_host("APP.example.com").is_some(),
        "case-insensitive"
    );
    let err = reg.allocate(
        "tok2".into(),
        true,
        true,
        false,
        0,
        limits(),
        ws_tx(),
        kill_tx(),
        Some("my-fixed".into()),
        None,
        Default::default(),
    );
    match err {
        Err(AllocError::Taken) => {}
        Err(e) => panic!("expected Taken, got {e:?}"),
        Ok(_) => panic!("expected Taken, got Ok"),
    }
    reg.remove("my-fixed");
    assert!(
        reg.custom_host("app.example.com").is_none(),
        "remove clears custom index"
    );
    assert!(reg.lookup("my-fixed").is_none());
}

#[test]
fn unlimited_token_sessions_bypass_per_token_cap() {
    let reg = Registry::new(256);
    let mut l = limits();
    l.max_sessions = 0;
    for _ in 0..8 {
        reg.allocate(
            "t-0".into(),
            true,
            true,
            false,
            0,
            l,
            ws_tx(),
            kill_tx(),
            None,
            None,
            Default::default(),
        )
        .unwrap();
    }
    assert_eq!(reg.len(), 8, "0 = unlimited per-token sessions");
}

#[test]
fn global_cap_still_applies_with_unlimited_token() {
    let reg = Registry::new(3);
    let mut l = limits();
    l.max_sessions = 0;
    for _ in 0..3 {
        reg.allocate(
            "t-0".into(),
            true,
            true,
            false,
            0,
            l,
            ws_tx(),
            kill_tx(),
            None,
            None,
            Default::default(),
        )
        .unwrap();
    }
    match reg.allocate(
        "t-0".into(),
        true,
        true,
        false,
        0,
        l,
        ws_tx(),
        kill_tx(),
        None,
        None,
        Default::default(),
    ) {
        Err(AllocError::ServerFull { .. }) => {}
        Err(e) => panic!("expected ServerFull, got {e:?}"),
        Ok(_) => panic!("expected ServerFull, got Ok"),
    }
}
