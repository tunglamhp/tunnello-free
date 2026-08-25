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
    let (mut fc, reply) =
        FakeClient::connect_udp_flags(addr, &cert, "tok_test", false, true, true, echo_port, None)
            .await;
    let slug = FakeClient::slug(&reply);

    // Visitor datagram → broker shared UDP port. The FIRST datagram of a
    // flow must carry the `<slug>\n` prefix (multi-tenant routing).
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut first = slug.clone().into_bytes();
    first.push(b'\n');
    first.extend_from_slice(b"ping-udp");
    visitor
        .send_to(&first, format!("127.0.0.1:{udp_port}"))
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

#[tokio::test]
async fn udp_dedicated_route_needs_no_prefix() {
    let (cert, key) = common::test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    let route_port = free_udp_port().await;

    // Pin the session slug: seed a tunnel profile with a fixed subdomain so
    // the dedicated route can reference it before the client connects.
    let domains = ddns_server::domain::DomainStore::open(&tokens);
    let apex = domains
        .create("tunnel.example.com", ddns_server::domain::DomainKind::Apex)
        .await
        .unwrap();
    let tunnels = ddns_server::tunnel::TunnelStore::open(&tokens, &domains);
    tunnels
        .create(&ddns_server::tunnel::NewTunnel {
            name: "udp-b".into(),
            token_id: "t-test".into(),
            domain_id: apex.id.clone(),
            subdomain: Some("udp-b".into()),
            custom_hostname: None,
            options: Default::default(),
            ports: String::new(),
        })
        .await
        .unwrap();

    let mut config = common::broker_config(&cert, &key, tokens.clone(), 16, Duration::from_secs(5));
    config.udp_routes = vec![("udp-b".into(), route_port)];
    let (addr, _broker) = common::start_broker_with_config(config).await;

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

    let (mut fc, _reply) = FakeClient::connect_udp_flags(
        addr,
        &cert,
        "tok_test",
        false,
        true,
        true,
        echo_port,
        Some("udp-b"),
    )
    .await;

    // No prefix on a dedicated route port.
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor
        .send_to(b"bare-datagram", format!("127.0.0.1:{route_port}"))
        .await
        .unwrap();

    let open = timeout(Duration::from_secs(5), fc.recv_frame())
        .await
        .unwrap();
    assert_eq!(open.opcode, Opcode::UOpen);
    let data = timeout(Duration::from_secs(5), fc.recv_frame())
        .await
        .unwrap();
    assert_eq!(data.payload.as_ref(), b"bare-datagram");

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

    fc.send_frame(&Frame {
        opcode: Opcode::UData,
        stream_id: data.stream_id,
        payload: Bytes::copy_from_slice(&buf[..n]),
    })
    .await;

    let (n, _) = timeout(Duration::from_secs(5), visitor.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"bare-datagram");
}

#[tokio::test]
async fn udp_shared_port_without_prefix_is_dropped() {
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

    let (mut fc, _reply) =
        FakeClient::connect_udp_flags(addr, &cert, "tok_test", false, true, true, 9999, None).await;

    // No slug prefix on the shared port → dropped, no UOpen reaches the client.
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor
        .send_to(b"prefixless", format!("127.0.0.1:{udp_port}"))
        .await
        .unwrap();

    // Give the broker a moment, then assert nothing arrived: recv_frame would
    // block on the WS; a short timeout proves the drop path.
    let result = timeout(Duration::from_millis(700), fc.recv_control()).await;
    assert!(result.is_err(), "prefixless datagram must not open a flow");
}
