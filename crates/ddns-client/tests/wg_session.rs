//! WG loopback e2e (plan Task 3): two in-process `WgPeer` instances over
//! real UDP loopback (no admin). Proves handshake + cryptokey routing +
//! payload round-trip — the core of the WireGuard data plane.

use std::sync::Arc;
use std::time::Duration;

use ddns_client::wg::keys::generate_keypair;
use ddns_client::wg::session::WgPeer;
use x25519_dalek::{PublicKey as DalekPk, StaticSecret};

/// A minimal inner IPv4 packet (protocol 253 = experimental; the WG layer
/// treats it as opaque payload).
fn inner_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + payload.len()];
    pkt[0] = 0x45; // v4, IHL 5
    pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes()); // total_len
    pkt[8] = 64; // TTL
    pkt[9] = 253; // protocol (experimental)
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..].copy_from_slice(payload);
    pkt
}

#[tokio::test]
async fn wg_loopback_handshake_and_forward() {
    // --- Key material (visitor ↔ exit) --------------------------------------
    let (sk_v, pk_v) = generate_keypair().expect("getrandom failure in test");
    let (sk_e, pk_e) = generate_keypair().expect("getrandom failure in test");
    let psk = [42u8; 32];

    let sk_v = StaticSecret::from(sk_v.to_bytes());
    let pk_v = DalekPk::from(pk_v.to_bytes());
    let sk_e = StaticSecret::from(sk_e.to_bytes());
    let pk_e = DalekPk::from(pk_e.to_bytes());

    // --- Real UDP loopback sockets ------------------------------------------
    let v_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let e_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    v_sock.connect(e_sock.local_addr().unwrap()).await.unwrap();

    let mut visitor = WgPeer::new(v_sock.clone(), sk_v, pk_e, Some(psk), 1);
    let mut exit = WgPeer::new(e_sock.clone(), sk_e, pk_v, Some(psk), 2);

    // --- Handshake: visitor forces initiation, exit responds ----------------
    // Initiate ONCE: repeated initiations trip the exit's rate limiter into
    // cookie mode, which drops the first data packet (WG spec behavior).
    visitor.initiate().await.unwrap();
    let mut established = false;
    for _ in 0..20 {
        // Exit processes the initiation → emits response (None return).
        let _ = exit.recv_ip(Duration::from_millis(100)).await;
        // Visitor processes the response → handshake done at visitor.
        let _ = visitor.recv_ip(Duration::from_millis(100)).await;
        if visitor.is_up() {
            established = true;
            break;
        }
    }
    assert!(established, "handshake must complete over UDP loopback");

    // --- Data: visitor inner packet → exit → reply → visitor -----------------
    let payload = b"exit-node-ping";
    let pkt = inner_packet([10, 200, 200, 2], [10, 200, 200, 1], payload);
    visitor.send_ip(&pkt).await.unwrap();

    // Exit decapsulates the inner packet, swaps src/dst for the reply.
    // WG retransmit: the first encapsulate after a fresh handshake may
    // carry a re-initiation (exit cookie-replies it) — re-send until the
    // inner packet lands.
    let mut got = None;
    for _ in 0..3 {
        visitor.send_ip(&pkt).await.unwrap();
        if let Some(inner) = exit.recv_ip(Duration::from_millis(300)).await {
            got = Some(inner);
            break;
        }
    }
    let got = got.expect("exit got inner packet");
    assert_eq!(&got[12..16], &[10, 200, 200, 2], "inner src = visitor");
    assert_eq!(&got[16..20], &[10, 200, 200, 1], "inner dst = exit");
    assert_eq!(&got[20..], payload);

    let mut reply = got.clone();
    reply[12..16].copy_from_slice(&got[16..20]); // src = exit
    reply[16..20].copy_from_slice(&got[12..16]); // dst = visitor
    exit.send_ip(&reply).await.unwrap();

    let echoed = visitor
        .recv_ip(Duration::from_secs(5))
        .await
        .expect("visitor got reply");
    assert_eq!(&echoed[20..], payload, "payload round-trips");
}
