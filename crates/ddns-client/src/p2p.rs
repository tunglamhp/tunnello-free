//! WebRTC gateway: accept a visitor's PeerConnection (ticket-verified),
//! bridge the data channel to the local HTTP/TCP target, and count usage
//! for the control-plane `UsageReport`.
//!
//! Data-channel framing (spec §4):
//! ```text
//! REQ  0x01 ‖ u32 request_id ‖ u32 len ‖ HTTP/1.1 head text
//! RESP 0x02 ‖ u32 request_id ‖ u32 len ‖ HTTP/1.1 status+headers text
//! DATA 0x03 ‖ u32 request_id ‖ u32 len ‖ body
//! CLOSE 0x04 ‖ u32 request_id
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use ddns_proto::ticket::{TicketError, verify_ticket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::{AbortHandle, JoinSet};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceGatheringState, RTCSessionDescription,
};

use crate::targets::LocalTarget;

/// Data-channel frame opcodes (spec §4).
pub const OP_REQ: u8 = 0x01;
pub const OP_RESP: u8 = 0x02;
pub const OP_DATA: u8 = 0x03;
pub const OP_CLOSE: u8 = 0x04;
/// Maximum declared frame payload length accepted by `decode_frame` (1 MiB).
/// Guards the decoder against absurd length fields before it slices/copies.
pub const MAX_P2P_FRAME: usize = 1 << 20;

/// Channel label → bridge mode. The browser connector opens `"http"`; the
/// `ddns connect` helper opens `"tcp"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeMode {
    Http,
    Tcp,
}

/// Map a data-channel label to its bridge mode. Anything other than `"tcp"`
/// is the HTTP bridge (browser connector).
pub fn bridge_for_label(label: &str) -> BridgeMode {
    if label == "tcp" {
        BridgeMode::Tcp
    } else {
        BridgeMode::Http
    }
}

/// A decoded data-channel frame (`opcode ‖ u32 request_id ‖ payload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2pFrame {
    pub opcode: u8,
    pub request_id: u32,
    pub payload: Vec<u8>,
}

/// Encode one frame per spec §4.
pub fn encode_frame(opcode: u8, request_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(opcode);
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode one frame. Returns `None` on truncation.
pub fn decode_frame(buf: &[u8]) -> Option<P2pFrame> {
    if buf.len() < 9 {
        return None;
    }
    let opcode = buf[0];
    let request_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let len = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
    if len > MAX_P2P_FRAME {
        return None;
    }
    if buf.len() < 9 + len {
        return None;
    }
    Some(P2pFrame {
        opcode,
        request_id,
        payload: buf[9..9 + len].to_vec(),
    })
}

/// The gateway's answer to a visitor offer (non-trickle: candidates ride the
/// SDP, so `ice` is empty in v1).
#[derive(Debug, Clone)]
pub struct P2pAnswer {
    pub sdp: String,
    pub ice: Vec<String>,
}

/// Shared usage counters for the session's `UsageReport` interval task.
pub struct P2pGateway {
    pub bytes_tx: Arc<AtomicU64>,
    pub bytes_rx: Arc<AtomicU64>,
}

impl P2pGateway {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            bytes_tx: Arc::new(AtomicU64::new(0)),
            bytes_rx: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Accept a visitor offer. Verifies the ticket (replay-guarded by the
    /// caller's `seen_tickets`), builds the answer, and spawns the channel
    /// bridge. Returns the answer SDP for the broker to relay back.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_visitor_offer(
        gateway: Arc<Self>,
        secret: [u8; 32],
        subdomain: &str,
        target: &LocalTarget,
        ticket: &str,
        sdp: &str,
        ice: &[String],
        seen_tickets: &mut HashSet<String>,
    ) -> Result<P2pAnswer, String> {
        if !seen_tickets.insert(ticket.to_string()) {
            return Err("ticket replay".to_string());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        verify_ticket(&secret, subdomain, ticket, now).map_err(|e| match e {
            TicketError::Malformed => "ticket malformed".to_string(),
            TicketError::Expired { .. } => "ticket expired".to_string(),
            TicketError::BadMac => "ticket invalid".to_string(),
        })?;

        // Bind the wildcard (every non-loopback interface, so a remote visitor
        // can reach the client) AND loopback (so the in-process loopback test
        // connects over 127.0.0.1). A loopback candidate is unusable by a
        // remote visitor but harmless in production.
        let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<Arc<dyn DataChannel>>(4);
        let (gather_tx, mut gather_rx) = tokio::sync::mpsc::channel::<()>(1);

        let pc = PeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_handler(Arc::new(GatewayHandler { dc_tx, gather_tx }))
            .with_udp_addrs(vec!["0.0.0.0:0".to_string(), "127.0.0.1:0".to_string()])
            .build()
            .await
            .map_err(|e| e.to_string())?;

        let offer = RTCSessionDescription::offer(sdp.to_string()).map_err(|e| e.to_string())?;
        pc.set_remote_description(offer)
            .await
            .map_err(|e| e.to_string())?;
        for c in ice {
            pc.add_ice_candidate(RTCIceCandidateInit {
                candidate: c.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| e.to_string())?;
        }
        let answer = pc.create_answer(None).await.map_err(|e| e.to_string())?;
        pc.set_local_description(answer)
            .await
            .map_err(|e| e.to_string())?;

        // Non-trickle ICE: wait for host-candidate gathering so the answer SDP
        // carries the candidates (v1 does not relay trickle candidates).
        let _ = tokio::time::timeout(Duration::from_secs(10), gather_rx.recv()).await;
        let answer_sdp = pc
            .local_description()
            .await
            .map(|d| d.sdp)
            .ok_or_else(|| "no local description after answer".to_string())?;

        let target = target.clone();
        let (tx_count, rx_count) = (gateway.bytes_tx.clone(), gateway.bytes_rx.clone());
        let sub = subdomain.to_string();
        tokio::spawn(async move {
            // webrtc-rs 0.20.x can silently skip `on_data_channel` when the
            // inbound DCEP channel registration races the driver's announce
            // check — the visitor's channel opens but the bridge is never
            // handed the DataChannel. Bound the wait and fail the bridge
            // instead of hanging the visitor's stream forever.
            let dc = match tokio::time::timeout(Duration::from_secs(20), dc_rx.recv()).await {
                Ok(Some(dc)) => dc,
                _ => {
                    tracing::warn!(
                        %sub,
                        "p2p visitor data channel never arrived within 20s; closing bridge"
                    );
                    let _ = pc.close().await;
                    return;
                }
            };
            // Read the channel label once and route: the browser connector
            // opens `"http"`; the `ddns connect` helper opens `"tcp"`.
            let label = dc.label().await.unwrap_or_default();
            let mode = bridge_for_label(&label);
            // The bridges send their CLOSE frames and return; dropping `pc`
            // (default non-reactor mode) does not abort the driver, so the
            // queued RESP/DATA/CLOSE frames flush before the teardown.
            let _ = match mode {
                BridgeMode::Http => bridge_channel(dc, target, tx_count, rx_count, sub).await,
                BridgeMode::Tcp => bridge_tcp_channel(dc, target, tx_count, rx_count, sub).await,
            };
        });

        Ok(P2pAnswer {
            sdp: answer_sdp,
            ice: vec![],
        })
    }
}

/// Receives inbound data channels and signals ICE-gathering completion.
#[derive(Clone)]
struct GatewayHandler {
    dc_tx: tokio::sync::mpsc::Sender<Arc<dyn DataChannel>>,
    gather_tx: tokio::sync::mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for GatewayHandler {
    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let _ = self.dc_tx.try_send(dc);
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }
}

/// Bridge one data channel to the local target using the REQ/RESP/DATA/CLOSE
/// framing. v1 handles a single request per channel: first REQ → dial → pump →
/// CLOSE.
async fn bridge_channel(
    dc: Arc<dyn DataChannel>,
    target: LocalTarget,
    tx_count: Arc<AtomicU64>,
    rx_count: Arc<AtomicU64>,
    subdomain: String,
) -> Result<(), String> {
    // Wait for the channel to open.
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(DataChannelEvent::OnClose) | None => return Ok(()),
            _ => {}
        }
    }
    tracing::info!(%subdomain, "p2p visitor joined");

    // Wait for the first REQ.
    let req = loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                match decode_frame(&msg.data) {
                    Some(f) if f.opcode == OP_REQ => break f,
                    Some(f) if f.opcode == OP_CLOSE => return Ok(()),
                    _ => {}
                }
            }
            Some(DataChannelEvent::OnClose) | None => return Ok(()),
            _ => {}
        }
    };
    let request_id = req.request_id;

    let result = serve_one_request(&dc, &target, &tx_count, &rx_count, req).await;

    // End the request with a CLOSE frame (spec §4), success or failure. The
    // channel is left open for the visitor to close (or reuse in a later
    // phase); an explicit `dc.close()`/`pc.close()` here would abort the
    // driver before the queued RESP/CLOSE frames flush.
    let _ = send_frame(&dc, OP_CLOSE, request_id, &[]).await;
    tracing::info!(%subdomain, "p2p visitor left");
    result
}

/// Maximum number of concurrent TCP streams multiplexed over one channel.
const MAX_TCP_STREAMS: usize = 512;

/// An open TCP stream: the socket write half (owned by the event loop) and the
struct OpenStream {
    write: OwnedWriteHalf,
    task: AbortHandle,
}

/// Bridge one data channel to the local TCP target, multiplexing many
/// concurrent TCP streams over the single channel. A stream is opened by a
/// `REQ` (empty payload, request_id = stream id), carries bytes in `DATA`
/// frames (both directions), and ends with `CLOSE`.
async fn bridge_tcp_channel(
    dc: Arc<dyn DataChannel>,
    target: LocalTarget,
    tx_count: Arc<AtomicU64>,
    rx_count: Arc<AtomicU64>,
    subdomain: String,
) -> Result<(), String> {
    // Wait for the channel to open.
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(DataChannelEvent::OnClose) | None => return Ok(()),
            _ => {}
        }
    }
    tracing::info!(%subdomain, "p2p tcp visitor joined");

    let mut streams: HashMap<u32, OpenStream> = HashMap::new();
    let mut read_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            // Reap finished read tasks so a long-lived channel cannot leak
            // completed task handles. The guard keeps this branch disabled
            // while the set is empty (`join_next` on an empty set resolves
            // immediately, which would otherwise busy-loop).
            _ = read_tasks.join_next(), if !read_tasks.is_empty() => {}

            ev = dc.poll() => {
                match ev {
                    Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                        let Some(frame) = decode_frame(&msg.data) else { continue; };
                        match frame.opcode {
                            OP_REQ if frame.payload.is_empty() => {
                                let id = frame.request_id;
                                // A duplicate id would overwrite the existing
                                // stream and let its read task's CLOSE corrupt
                                // the new one; drop it defensively.
                                if streams.contains_key(&id) {
                                    continue;
                                }
                                if streams.len() >= MAX_TCP_STREAMS {
                                    let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                                    continue;
                                }
                                let sock = match tokio::time::timeout(
                                    Duration::from_secs(10),
                                    target.dial(),
                                )
                                .await
                                {
                                    Ok(Ok(s)) => s,
                                    Ok(Err(e)) => {
                                        tracing::warn!(%subdomain, %id, "tcp dial failed: {e}");
                                        let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                                        continue;
                                    }
                                    Err(_) => {
                                        tracing::warn!(%subdomain, %id, "tcp dial timed out");
                                        let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                                        continue;
                                    }
                                };
                                let (rd, write) = sock.into_split();
                                let task = read_tasks.spawn(read_stream(
                                    dc.clone(),
                                    rd,
                                    id,
                                    rx_count.clone(),
                                ));
                                streams.insert(id, OpenStream { write, task });
                            }
                            OP_DATA => {
                                let Some(stream) = streams.get_mut(&frame.request_id) else {
                                    continue;
                                };
                                tx_count.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                                let wrote = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    stream.write.write_all(&frame.payload),
                                )
                                .await;
                                if !matches!(wrote, Ok(Ok(())))
                                    && let Some(stream) = streams.remove(&frame.request_id)
                                {
                                    drop(stream.write);
                                    stream.task.abort();
                                }
                            }
                            OP_CLOSE => {
                                if let Some(stream) = streams.remove(&frame.request_id) {
                                    drop(stream.write);
                                    stream.task.abort();
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(DataChannelEvent::OnClose) | None => {
                        read_tasks.abort_all();
                        tracing::info!(%subdomain, "p2p tcp visitor left");
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Pump one target socket's read half into DATA frames until EOF/error, then
/// signal CLOSE and return.
async fn read_stream(
    dc: Arc<dyn DataChannel>,
    mut rd: OwnedReadHalf,
    id: u32,
    rx_count: Arc<AtomicU64>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => {
                let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                return;
            }
            Ok(n) => {
                rx_count.fetch_add(n as u64, Ordering::Relaxed);
                if send_frame(&dc, OP_DATA, id, &buf[..n]).await.is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                return;
            }
        }
    }
}

/// Serve one request: dial the target, write the head, pump request body
/// (DATA → socket) while reading the response (RESP head + DATA body).
async fn serve_one_request(
    dc: &Arc<dyn DataChannel>,
    target: &LocalTarget,
    tx_count: &AtomicU64,
    rx_count: &AtomicU64,
    req: P2pFrame,
) -> Result<(), String> {
    let request_id = req.request_id;

    let sock = target
        .dial()
        .await
        .map_err(|e| format!("dial {}: {e}", target.host))?;
    let (mut lr, mut lw) = sock.into_split();

    // Forward the request head to the local target.
    if !req.payload.is_empty() {
        lw.write_all(&req.payload)
            .await
            .map_err(|e| format!("write head: {e}"))?;
        tx_count.fetch_add(req.payload.len() as u64, Ordering::Relaxed);
    }

    let mut head_buf: Vec<u8> = Vec::new();
    let mut head_sent = false;
    let mut buf = [0u8; 4096];
    let mut forward_body = true;

    loop {
        tokio::select! {
            // Response direction: local target → visitor.
            r = lr.read(&mut buf) => {
                match r {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        rx_count.fetch_add(n as u64, Ordering::Relaxed);
                        if head_sent {
                            send_frame(dc, OP_DATA, request_id, &buf[..n]).await?;
                        } else {
                            head_buf.extend_from_slice(&buf[..n]);
                            if head_buf.len() > 64 * 1024 {
                                return Err("response head too large".to_string());
                            }
                            if let Some(end) = find_head_end(&head_buf) {
                                send_frame(dc, OP_RESP, request_id, &head_buf[..end]).await?;
                                head_sent = true;
                                if end < head_buf.len() {
                                    send_frame(dc, OP_DATA, request_id, &head_buf[end..]).await?;
                                }
                            }
                        }
                    }
                    Err(e) => return Err(format!("local read: {e}")),
                }
            }
            // Request-body direction: visitor DATA → local target.
            ev = dc.poll() => {
                match ev {
                    Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                        match decode_frame(&msg.data) {
                            Some(f) if f.opcode == OP_DATA && f.request_id == request_id => {
                                if forward_body {
                                    tx_count.fetch_add(f.payload.len() as u64, Ordering::Relaxed);
                                    if tokio::time::timeout(
                                        Duration::from_secs(5),
                                        lw.write_all(&f.payload),
                                    )
                                    .await
                                    .is_err()
                                    {
                                        forward_body = false;
                                    }
                                }
                            }
                            Some(f) if f.opcode == OP_CLOSE && f.request_id == request_id => {
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                    Some(DataChannelEvent::OnClose) | None => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

/// Index just past the terminating `\r\n\r\n` of an HTTP/1.1 head.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn send_frame(
    dc: &Arc<dyn DataChannel>,
    opcode: u8,
    request_id: u32,
    payload: &[u8],
) -> Result<(), String> {
    let buf = encode_frame(opcode, request_id, payload);
    dc.send(BytesMut::from(&buf[..]))
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips() {
        for (opcode, payload) in [
            (OP_REQ, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
            (OP_RESP, b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
            (OP_DATA, b"hello".to_vec()),
            (OP_CLOSE, vec![]),
        ] {
            let buf = encode_frame(opcode, 7, &payload);
            let frame = decode_frame(&buf).expect("decode");
            assert_eq!(frame.opcode, opcode);
            assert_eq!(frame.request_id, 7);
            assert_eq!(frame.payload, payload);
        }
    }

    #[test]
    fn decode_rejects_truncated_frame() {
        let buf = encode_frame(OP_REQ, 1, b"abc");
        assert!(decode_frame(&buf[..8]).is_none());
        assert!(decode_frame(&buf[..buf.len() - 1]).is_none());
    }

    #[test]
    fn decode_rejects_oversized_frame() {
        // A complete frame whose declared payload exceeds MAX_P2P_FRAME must
        // be rejected by the cap, not copied.
        let payload = vec![0u8; MAX_P2P_FRAME + 1];
        let buf = encode_frame(OP_DATA, 7, &payload);
        assert!(decode_frame(&buf).is_none());
    }

    #[test]
    fn bridge_for_label_discriminates_tcp() {
        assert_eq!(bridge_for_label("tcp"), BridgeMode::Tcp);
        assert_eq!(bridge_for_label("http"), BridgeMode::Http);
        assert_eq!(bridge_for_label("other"), BridgeMode::Http);
    }

    #[test]
    fn usage_counter_swap_reports_since_last_report() {
        let gw = P2pGateway::new();

        gw.bytes_tx.fetch_add(100, Ordering::Relaxed);
        gw.bytes_rx.fetch_add(200, Ordering::Relaxed);
        assert_eq!(gw.bytes_tx.swap(0, Ordering::Relaxed), 100);
        assert_eq!(gw.bytes_rx.swap(0, Ordering::Relaxed), 200);

        gw.bytes_tx.fetch_add(50, Ordering::Relaxed);
        gw.bytes_rx.fetch_add(60, Ordering::Relaxed);
        assert_eq!(gw.bytes_tx.swap(0, Ordering::Relaxed), 50);
        assert_eq!(gw.bytes_rx.swap(0, Ordering::Relaxed), 60);

        assert_eq!(gw.bytes_tx.load(Ordering::Relaxed), 0);
        assert_eq!(gw.bytes_rx.load(Ordering::Relaxed), 0);
    }
}
