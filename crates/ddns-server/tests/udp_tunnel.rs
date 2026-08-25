//! UDP tunnel integration test: a fake client registers with `want_udp`,
//! the broker's UDP bridge opens a flow (UOpen) for a visitor datagram, the
//! fake client relays UData into a local UDP echo server and back, and the
//! visitor receives its echoed datagram.

mod common;

use bytes::Bytes;
use common::FakeClient;
use ddns_proto::{Frame, Opcode};
use ddns_server::TokenStore;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Pick a free localhost UDP port by binding :0 and reading the address.
async fn free_udp_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.local_addr().unwrap().port()
}

#[tokio::test]
async fn udp_datagram_round_trips_through_tunnel() {
    let (cert, key) = common::test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    let udp_port = free_udp_port().await;

    let mut config = common::broker_config(&cert, &key, tokens.clone(), 16, Duration::from_secs(5));
    config.udp_port = udp_port;
    let (addr, _broker) = common::start_broker_with_config(config).await;

    // Local UDP echo server the "client" relays into.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        }
    });

    // Register a UDP-capable fake client (want_udp + its local echo port).
    let (mut fc, _reply) =
        FakeClient::connect_udp_flags(addr, &cert, "tok_test", false, true, true, echo_port).await;

    // Visitor datagram → broker UDP port.
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor
        .send_to(b"ping-udp", format!("127.0.0.1:{udp_port}"))
        .await
        .unwrap();

    // Client receives UOpen then UData.
    let open = timeout(Duration::from_secs(5), fc.recv_frame())
        .await
        .unwrap();
    assert_eq!(open.opcode, Opcode::UOpen, "first frame must be UOpen");
    let data = timeout(Duration::from_secs(5), fc.recv_frame())
        .await
        .unwrap();
    assert_eq!(data.opcode, Opcode::UData);
    assert_eq!(data.payload.as_ref(), b"ping-udp");
    assert_eq!(data.stream_id, open.stream_id);

    // Relay into the echo server; get the echo back.
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay
        .send_to(data.payload.as_ref(), format!("127.0.0.1:{echo_port}"))
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ping-udp");

    // Send the echo upstream as UData on the same flow.
    fc.send_frame(&Frame {
        opcode: Opcode::UData,
        stream_id: data.stream_id,
        payload: Bytes::copy_from_slice(&buf[..n]),
    })
    .await;

    // Visitor receives the echoed datagram.
    let (n, _) = timeout(Duration::from_secs(5), visitor.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"ping-udp");
}
