//! In-process end-to-end for the `ddns connect` helper: the helper's
//! `"tcp"`-labeled channel is paired loopback with the gateway's TCP bridge
//! (no broker), then a native visitor connects to the helper's bound port and
//! round-trips bytes through the pumps → channel → gateway bridge → echo.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use ddns_client::connect_p2p::{bind_listener, connect_p2p_channel, run_pumps};
use ddns_client::p2p::P2pGateway;
use ddns_client::targets::LocalTarget;

#[tokio::test]
async fn connect_p2p_round_trips_tcp() {
    // --- Local echo server (per-connection echo) ---------------------------
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

    // --- Helper side: channel labeled "tcp", loopback-paired with the gateway
    let target = LocalTarget::from_url(&format!("tcp://127.0.0.1:{}", echo_addr.port())).unwrap();
    let ticket = ddns_proto::ticket::issue_ticket(&[0u8; 32], "vivid-otter-72");

    let (pc, dc) = connect_p2p_channel(move |offer_sdp| {
        let target = target.clone();
        let ticket = ticket.clone();
        async move {
            let mut seen = std::collections::HashSet::new();
            let answer = P2pGateway::handle_visitor_offer(
                P2pGateway::new(),
                [0u8; 32],
                "vivid-otter-72",
                &target,
                &ticket,
                &offer_sdp,
                &[],
                &mut seen,
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok::<String, String>(answer.sdp)
        }
    })
    .await
    .expect("channel negotiation");

    // --- Bind the helper's local listener + run the pumps -------------------
    let (tcp_listener, port) = bind_listener("vivid-otter-72").await.unwrap();
    let pumps = tokio::spawn(run_pumps(
        pc.clone(),
        dc.clone(),
        tcp_listener,
        "vivid-otter-72".to_string(),
    ));

    // --- A native visitor connects to the printed port ----------------------
    let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    sock.write_all(b"hi").await.unwrap();

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
        .await
        .expect("timed out waiting for echoed bytes")
        .unwrap();
    assert_eq!(&buf[..n], b"hi");

    let _ = pc.close().await;
    pumps.abort();
}
