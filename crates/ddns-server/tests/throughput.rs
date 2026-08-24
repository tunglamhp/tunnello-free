//! Throughput regression test: a large visitor→client→visitor round trip must
//! not regress below a conservative floor, and the full payload must echo back
//! byte-count exact. Guards the per-frame chunk sizing (8 KiB chunks once made
//! a 100 MB transfer ~12,800 frames; 256 KiB keeps frame overhead negligible).
//! In-process (no network bridge), so the floor is intentionally far below the
//! expected rate to stay CI-stable.

mod common;

use std::time::{Duration, Instant};

use common::{FakeClient, connect_tcp, start_broker, test_cert};
use ddns_proto::{Opcode, StreamKind};
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD_MB: usize = 32;
const MIN_MB_PER_SEC: f64 = 25.0; // conservative floor; in-process runs far faster

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_throughput_stays_above_floor() {
    let (cert, key) = test_cert();
    let store = TokenStore::new();
    store
        .insert("tok_perf".into(), common::test_record("t-perf", true))
        .await
        .unwrap();
    let (addr, broker) = start_broker(&cert, &key, store, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_perf").await;
    let slug = FakeClient::slug(&reply);

    let tls = connect_tcp(addr, &cert, &slug).await;
    let (_stream_id, meta) = fc.recv_open().await;
    assert_eq!(meta.kind, StreamKind::Tcp);

    // Client echo task: relay every DATA frame back to the visitor.
    let echo = tokio::spawn(async move {
        let mut frames = 0usize;
        loop {
            let f = fc.recv_frame().await;
            match f.opcode {
                Opcode::Data => {
                    frames += 1;
                    fc.send_data(f.stream_id, f.payload.to_vec()).await;
                }
                Opcode::Close => break,
                _ => {}
            }
        }
        frames
    });

    // Full duplex: write PAYLOAD_MB MiB while concurrently reading the echo
    // back (writing without reading would deadlock the backpressured pipe).
    let payload = vec![0xABu8; 64 * 1024];
    let target = PAYLOAD_MB * 1024 * 1024;
    let (mut tls_r, mut tls_w) = tokio::io::split(tls);
    let start = Instant::now();
    let writer = tokio::spawn(async move {
        let mut sent = 0usize;
        while sent < target {
            let n = (target - sent).min(payload.len());
            tls_w.write_all(&payload[..n]).await.unwrap();
            sent += n;
        }
        sent
    });
    let reader = tokio::spawn(async move {
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while got < target {
            let n = tls_r.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF after {got} bytes of {target}");
            got += n;
        }
        got
    });
    let sent = writer.await.unwrap();
    let got = reader.await.unwrap();
    let elapsed = start.elapsed();
    let frames = echo.await.unwrap();

    assert_eq!(sent, target, "visitor must send the full payload");
    assert_eq!(got, target, "visitor must receive the full echo");
    assert!(
        frames >= PAYLOAD_MB * 4,
        "expected many small frames, got {frames}"
    );
    // Round trip: PAYLOAD_MB out + PAYLOAD_MB in.
    let mbps = (2 * PAYLOAD_MB) as f64 / elapsed.as_secs_f64();
    assert!(
        mbps >= MIN_MB_PER_SEC,
        "round-trip {mbps:.1} MiB/s below floor {MIN_MB_PER_SEC} MiB/s ({elapsed:?})"
    );
    broker.stop().await;
}
