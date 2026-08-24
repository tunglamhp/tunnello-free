//! Phase 2 (0.3.0) regression net: the `ddns connect` native helper rides the
//! *same* `/__p2p/signal` hello flow the browser connector uses (Phase 1).
//!
//! There is no server change here: the helper is a visitor, not a tunnel
//! client, so this test replays the exact wire exchange the helper performs
//! (`hello` → `P2pVisitorOffer` → `P2pAnswer` → `answer`) against the live
//! broker and asserts the full round trip. It proves the TCP helper needs no
//! new broker matchmaking message — the `"tcp"` data-channel label is the only
//! mode discriminator (see `P2pGateway::bridge_for_label`).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{FakeClient, client_tls, start_broker, test_cert};
use ddns_proto::Control;
use ddns_proto::ticket::verify_ticket;
use ddns_server::TokenStore;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

async fn tokens() -> TokenStore {
    let store = TokenStore::new();
    store
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    store
}

/// Open a plain (helper-style) signaling WebSocket to `/__p2p/signal`.
async fn connect_signal_ws(
    addr: SocketAddr,
    cert: &[u8],
) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
    let cfg = Arc::new(client_tls(cert));
    let connector = tokio_tungstenite::Connector::Rustls(cfg);
    let url = format!("wss://127.0.0.1:{}/__p2p/signal", addr.port());
    let (ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
            .await
            .unwrap();
    ws
}

async fn send_json(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>, v: serde_json::Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

async fn recv_json(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> serde_json::Value {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).unwrap(),
            Some(Ok(_)) => continue,
            _ => panic!("ws closed while waiting for JSON"),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn connect_helper_hello_flow_reaches_client_and_returns_answer() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;

    // The fake client stands in for the tunnel's ddns client (registered with
    // a token, advertising `want_tcp`). It holds the session secret from its
    // own `registered` reply — exactly what the real client uses to validate
    // a visitor's ticket (the helper never sees this secret).
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let secret = match &reply {
        Control::Registered { session_secret, .. } => URL_SAFE_NO_PAD
            .decode(session_secret.as_bytes())
            .expect("session_secret is base64url"),
        other => panic!("expected registered with session_secret, got {other:?}"),
    };

    // The visitor: the `ddns connect` helper opens a plain WS to the signal
    // endpoint and sends `hello` with an explicit slug (no token, no tunnel
    // registration — mirror of `connect_p2p_channel`).
    let mut ws = connect_signal_ws(addr, &cert).await;
    send_json(
        &mut ws,
        serde_json::json!({ "type": "hello", "slug": slug, "sdp": "v=0\r\n", "ice": [] }),
    )
    .await;

    // Client control socket receives the visitor offer with a valid ticket.
    let offer = fc.recv_control().await;
    let Control::P2pVisitorOffer { ticket, sdp, ice } = offer else {
        panic!("expected p2p_visitor_offer, got {offer:?}");
    };
    assert_eq!(sdp, "v=0\r\n");
    assert!(ice.is_empty());
    verify_ticket(&secret, &slug, &ticket, now_secs()).expect("ticket must verify");

    // Client answers → the helper's WS receives the answer JSON.
    fc.send_control(&Control::P2pAnswer {
        ticket: ticket.clone(),
        sdp: "v=0 answer".into(),
        ice: vec![],
    })
    .await;

    let answer = recv_json(&mut ws).await;
    assert_eq!(answer["type"], "answer");
    assert_eq!(answer["sdp"], "v=0 answer");

    broker.stop().await;
}
