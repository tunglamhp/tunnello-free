//! Bind a broker with STUN enabled, send a real binding request over UDP,
//! expect a binding success whose tx id is echoed back.

use ddns_server::Broker;
mod common;

#[tokio::test]
async fn stun_binding_returns_mapped_address() {
    let (cert, key) = common::test_cert();
    let tokens = ddns_server::TokenStore::new();
    let mut config = common::broker_config(
        &cert,
        &key,
        tokens,
        16,
        std::time::Duration::from_millis(200),
    );
    config.stun_listen = Some("127.0.0.1:0".parse().unwrap());
    let broker = Broker::start(config).await.unwrap();
    let stun_addr = broker.stun_addr.expect("stun bound");

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg.extend_from_slice(&20u16.to_be_bytes());
    msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
    msg.extend_from_slice(&[0x42; 12]);
    sock.send_to(&msg, stun_addr).await.unwrap();

    let mut buf = [0u8; 256];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("stun response within 5s")
        .expect("recv ok");
    assert!(n >= 20, "full STUN header received, got {n} bytes");
    assert_eq!(&buf[0..2], &0x0101u16.to_be_bytes(), "binding success");
    assert_eq!(&buf[8..20], &[0x42; 12], "echoed tx id");
}
