//! Loopback WebRTC: two in-process PeerConnections exchange SDP directly
//! (host candidates only, no STUN), open a data channel, and push bytes
//! through the client's gateway bridge into a local echo TCP server.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use ddns_client::p2p::{
    OP_CLOSE, OP_DATA, OP_REQ, OP_RESP, P2pGateway, decode_frame, encode_frame,
};
use ddns_client::targets::LocalTarget;
use webrtc::data_channel::DataChannelEvent;
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState, RTCSessionDescription,
};

/// Offer-side handler: signals ICE gathering completion so the offer SDP is
/// serialized only once host candidates are baked in (non-trickle).
#[derive(Clone)]
struct OfferHandler {
    gather_tx: tokio::sync::mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for OfferHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }
}

#[tokio::test]
async fn gateway_bridges_data_channel_to_local_tcp() {
    // --- Local echo server ---------------------------------------------------
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        }
    });

    // --- Peer A (visitor): create a data channel and offer -------------------
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::channel::<()>(1);
    let a: Arc<dyn PeerConnection> = Arc::new(
        PeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_handler(Arc::new(OfferHandler { gather_tx }))
            .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
            .build()
            .await
            .unwrap(),
    );

    let dc = a.create_data_channel("http", None).await.unwrap();
    let offer = a.create_offer(None).await.unwrap();
    a.set_local_description(offer).await.unwrap();
    // Wait for ICE gathering (non-trickle) so host candidates are in the SDP.
    let _ = tokio::time::timeout(Duration::from_secs(10), gather_rx.recv()).await;
    let offer_sdp = a.local_description().await.unwrap();

    // --- Peer B (gateway): accept the offer, answer --------------------------
    let target = LocalTarget::from_url(&format!("tcp://127.0.0.1:{}", echo_addr.port())).unwrap();
    let ticket = ddns_proto::ticket::issue_ticket(&[0u8; 32], "vivid-otter-72");
    let mut seen = std::collections::HashSet::new();
    let answer = P2pGateway::handle_visitor_offer(
        P2pGateway::new(),
        [0u8; 32],
        "vivid-otter-72",
        &target,
        &ticket,
        &offer_sdp.sdp,
        &[],
        &mut seen,
    )
    .await
    .expect("gateway accepts offer");

    a.set_remote_description(RTCSessionDescription::answer(answer.sdp).unwrap())
        .await
        .unwrap();

    // --- Wait for the channel to open on A -----------------------------------
    let mut opened = false;
    let open_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !opened && tokio::time::Instant::now() < open_deadline {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => opened = true,
            Some(DataChannelEvent::OnClose) | None => break,
            _ => {}
        }
    }
    assert!(opened, "data channel did not open");

    // --- Send a REQ frame and expect the echo back ---------------------------
    let head =
        ddns_proto::http::build_http_head("GET", "/", &[("Host".to_string(), "x".to_string())]);
    let req = encode_frame(OP_REQ, 1, &head);
    dc.send(BytesMut::from(&req[..])).await.unwrap();

    // Reassemble RESP + DATA payloads until CLOSE; assert they equal the head.
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        loop {
            match dc.poll().await {
                Some(DataChannelEvent::OnMessage(msg)) => {
                    if msg.is_string {
                        continue;
                    }
                    let frame = decode_frame(&msg.data).expect("valid frame");
                    match frame.opcode {
                        OP_RESP | OP_DATA => received.extend_from_slice(&frame.payload),
                        OP_CLOSE => break,
                        _ => {}
                    }
                }
                Some(DataChannelEvent::OnClose) | None => break,
                _ => {}
            }
        }
        received
    })
    .await
    .expect("timed out waiting for echoed bytes");

    assert_eq!(
        received, head,
        "echoed bytes must round-trip through the bridge"
    );

    let _ = a.close().await;
}

#[tokio::test]
async fn gateway_bridges_tcp_channel_multiple_streams() {
    // --- Local echo server (per-connection echo, like the Phase 1 test) -----
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        }
    });

    // --- Peer A (helper): channel labeled "tcp" -----------------------------
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::channel::<()>(1);
    let a: Arc<dyn PeerConnection> = Arc::new(
        PeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_handler(Arc::new(OfferHandler { gather_tx }))
            .with_udp_addrs(vec!["127.0.0.1:0".to_string()])
            .build()
            .await
            .unwrap(),
    );

    let dc = a.create_data_channel("tcp", None).await.unwrap();
    let offer = a.create_offer(None).await.unwrap();
    a.set_local_description(offer).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), gather_rx.recv()).await;
    let offer_sdp = a.local_description().await.unwrap();

    // --- Peer B (gateway): accept the offer, answer -------------------------
    let target = LocalTarget::from_url(&format!("tcp://127.0.0.1:{}", echo_addr.port())).unwrap();
    let ticket = ddns_proto::ticket::issue_ticket(&[0u8; 32], "vivid-otter-72");
    let mut seen = std::collections::HashSet::new();
    let answer = P2pGateway::handle_visitor_offer(
        P2pGateway::new(),
        [0u8; 32],
        "vivid-otter-72",
        &target,
        &ticket,
        &offer_sdp.sdp,
        &[],
        &mut seen,
    )
    .await
    .expect("gateway accepts offer");

    a.set_remote_description(RTCSessionDescription::answer(answer.sdp).unwrap())
        .await
        .unwrap();

    // --- Wait for the channel to open on A ----------------------------------
    let mut opened = false;
    let open_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !opened && tokio::time::Instant::now() < open_deadline {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => opened = true,
            Some(DataChannelEvent::OnClose) | None => break,
            _ => {}
        }
    }
    assert!(opened, "data channel did not open");

    // --- Two concurrent streams, interleaved ---------------------------------
    // Open both streams, then send their bytes interleaved BEFORE either echo
    // arrives; the bridge must route each stream by request_id.
    dc.send(BytesMut::from(&encode_frame(OP_REQ, 1, &[])[..]))
        .await
        .unwrap();
    dc.send(BytesMut::from(&encode_frame(OP_REQ, 2, &[])[..]))
        .await
        .unwrap();
    dc.send(BytesMut::from(&encode_frame(OP_DATA, 1, b"hello-1")[..]))
        .await
        .unwrap();
    dc.send(BytesMut::from(&encode_frame(OP_DATA, 2, b"hello-2")[..]))
        .await
        .unwrap();

    // Reassemble each stream's echo until its CLOSE; assert per-stream bytes.
    let (got1, got2) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got1 = Vec::new();
        let mut got2 = Vec::new();
        let mut closed1 = false;
        let mut closed2 = false;
        while !(closed1 && closed2) {
            match dc.poll().await {
                Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                    let frame = decode_frame(&msg.data).expect("valid frame");
                    match frame.opcode {
                        OP_DATA if frame.request_id == 1 => got1.extend_from_slice(&frame.payload),
                        OP_DATA if frame.request_id == 2 => got2.extend_from_slice(&frame.payload),
                        OP_CLOSE if frame.request_id == 1 => closed1 = true,
                        OP_CLOSE if frame.request_id == 2 => closed2 = true,
                        _ => {}
                    }
                }
                Some(DataChannelEvent::OnClose) | None => break,
                _ => {}
            }
        }
        (got1, got2)
    })
    .await
    .expect("timed out waiting for stream echoes");

    assert_eq!(got1, b"hello-1".to_vec());
    assert_eq!(got2, b"hello-2".to_vec());

    let _ = a.close().await;
}
