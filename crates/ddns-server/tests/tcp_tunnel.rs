//! Task 5 acceptance: raw TCP echo through the broker, SNI routing.

mod common;

use std::time::Duration;

use common::{FakeClient, connect_tcp, start_broker, test_cert};
use ddns_proto::frame::CLOSE_OK;
use ddns_proto::{Control, Opcode, StreamKind};
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn tokens() -> TokenStore {
    let store = TokenStore::new();
    store
        .insert("tok_tcp".into(), common::test_record("t-tcp", true))
        .await
        .unwrap();
    store
}

#[tokio::test]
async fn tcp_echo_through_the_tunnel() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_tcp").await;
    let slug = FakeClient::slug(&reply);

    let mut tls = connect_tcp(addr, &cert, &slug).await;

    // Broker opens the stream (kind Tcp, port 0):
    let (stream_id, meta) = fc.recv_open().await;
    assert_eq!(meta.kind, StreamKind::Tcp);
    assert_eq!(meta.port, 0);
    assert!(meta.head.is_none());

    // Visitor -> client:
    tls.write_all(b"hello over tcp").await.unwrap();
    let f = fc.recv_frame().await;
    assert_eq!(f.opcode, Opcode::Data);
    assert_eq!(f.payload.as_ref(), b"hello over tcp");
    assert_eq!(f.stream_id, stream_id);

    // Client -> visitor:
    fc.send_data(stream_id, b"world back".to_vec()).await;
    let mut buf = [0u8; 16];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"world back");

    // Visitor closes -> client sees CLOSE(OK):
    drop(tls);
    let (sid, reason) = fc.recv_close().await;
    assert_eq!(sid, stream_id);
    assert_eq!(reason, CLOSE_OK);

    // Client closes -> visitor socket gets EOF:
    let mut tls2 = connect_tcp(addr, &cert, &slug).await;
    let (sid2, _) = fc.recv_open().await;
    assert_eq!(sid2, stream_id + 1, "stream ids monotonic");
    fc.send_close(sid2, CLOSE_OK).await;
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(2), tls2.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "visitor socket must hit EOF after client CLOSE"
    );
    broker.stop().await;
}

#[tokio::test]
async fn unknown_slug_connection_is_dropped() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let mut tls = connect_tcp(addr, &cert, "nope").await;
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    assert!(r.is_ok(), "unknown slug must be dropped promptly");
    broker.stop().await;
}

#[tokio::test]
async fn tcp_disabled_session_is_dropped() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (_fc, reply) = FakeClient::connect_with_flags(addr, &cert, "tok_tcp", false, true).await;
    let slug = FakeClient::slug(&reply);
    assert!(matches!(reply, Control::Registered { tcp_addr: None, .. }));
    let mut tls = connect_tcp(addr, &cert, &slug).await;
    let mut buf = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf)).await;
    assert!(r.is_ok(), "http-only session must drop tcp conns");
    broker.stop().await;
}
