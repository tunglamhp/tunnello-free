//! Stream multiplexer. One recv task owns the WS read half and routes:
//!   Text(Control::Kill/Quota/Error/Pong) → session signals (Task 3 policy)
//!   Binary(Frame::Open)    → spawn per-stream task (dial + pump)
//!   Binary(Frame::Data)    → forward to that stream's mpsc
//!   Binary(Frame::Close)   → forward to that stream (EOF for its pumps)
//!
//! All writes go through a single mpsc → writer task → WS write half, so the
//! socket is written by exactly one task (mirrors ddns-server's mux).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use ddns_proto::MAX_FRAME_PAYLOAD;
use ddns_proto::frame::{CLOSE_APP_ERROR, CLOSE_OK};
use ddns_proto::{Control, Frame, Opcode, OpenMeta, StreamKind, Usage};

use crate::cli::Cli;
use crate::connect::{self, ClientWsStream};
use crate::p2p::P2pGateway;
use crate::reconnect::SessionEnd;
use crate::targets::LocalTarget;

/// Per-stream message: Data payload or Close with code.
#[derive(Debug)]
pub enum StreamMsg {
    Data(Bytes),
    Close(u8),
}

// --------------------------------------------------------------------------
// Send helper
// --------------------------------------------------------------------------

/// Encode a frame and queue it for the writer task. BLOCKING on a full queue
/// (never silently drops) — OpenAck/OpenReject must not be lost, or the
/// broker waits out HEAD_TIMEOUT and 502s a healthy tunnel. Returns false
/// when the writer is gone (session tearing down).
async fn send_frame(
    tx: &mpsc::Sender<Message>,
    stream_id: u32,
    opcode: Opcode,
    payload: Bytes,
) -> bool {
    let f = Frame {
        opcode,
        stream_id,
        payload,
    };
    let mut buf = Vec::with_capacity(9 + f.payload.len());
    if f.encode(&mut buf).is_err() {
        tracing::warn!(stream = stream_id, "frame encode failed");
        return false;
    }
    tx.send(Message::Binary(Bytes::from(buf))).await.is_ok()
}

/// Removes the stream's map entry when the task exits (any path, including
/// abort), so client-initiated Closes don't leak entries for the session.
struct StreamCleanup {
    streams: Arc<DashMap<u32, mpsc::Sender<StreamMsg>>>,
    id: u32,
}

impl Drop for StreamCleanup {
    fn drop(&mut self) {
        self.streams.remove(&self.id);
    }
}

// --------------------------------------------------------------------------
// run_mux — the recv loop + writer + heartbeat
// --------------------------------------------------------------------------

/// Run the mux: spawns the writer task (drains `ws_rx` → WS write half),
/// the heartbeat, and the recv loop that routes frames to per-stream tasks.
/// Returns a [`SessionEnd`] describing why the loop exited.
#[allow(clippy::too_many_arguments)]
pub async fn run_mux(
    tunnel_tx: mpsc::Sender<Message>,
    ws_rx: mpsc::Receiver<Message>,
    read: futures_util::stream::SplitStream<ClientWsStream>,
    write: futures_util::stream::SplitSink<ClientWsStream, Message>,
    cli: &Cli,
    session_secret: String,
    gateway: Arc<P2pGateway>,
    subdomain: String,
) -> SessionEnd {
    let streams: Arc<DashMap<u32, mpsc::Sender<StreamMsg>>> = Arc::new(DashMap::new());
    // Track per-stream tasks so teardown can abort them (they may be blocked
    // on a keep-alive local socket) before the writer is awaited.
    let mut stream_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    // --- writer task --------------------------------------------------------
    let mut writer = tokio::spawn(async move {
        let mut rx = ws_rx;
        let mut sink = write;
        while let Some(msg) = rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // --- heartbeat ----------------------------------------------------------
    let hb_tx = tunnel_tx.clone();
    let hb_interval = cli.heartbeat_interval;
    let heartbeat = connect::spawn_heartbeat(hb_tx, hb_interval);

    // --- usage report -------------------------------------------------------
    // Every 15 s, swap the P2P gateway counters out and report them over the
    // control WSS so the broker can meter the P2P data plane.
    let usage_tx = tunnel_tx.clone();
    let usage_gw = gateway.clone();
    let usage_report = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let report = Control::UsageReport {
                bytes_tx: usage_gw.bytes_tx.swap(0, Ordering::Relaxed),
                bytes_rx: usage_gw.bytes_rx.swap(0, Ordering::Relaxed),
                streams: 0,
                since_ts: unix_now(),
            };
            let Ok(json) = serde_json::to_string(&report) else {
                continue;
            };
            if usage_tx.send(Message::Text(json.into())).await.is_err() {
                return;
            }
        }
    });

    // --- recv loop ----------------------------------------------------------
    let mut read = read;
    let mut last_usage: Option<Usage> = None;
    // Replay guard for P2P visitor tickets. Entries are only added; a ticket
    // is valid for TICKET_TTL_SECS (60 s), so anything stale can never
    // re-verify regardless.
    let mut seen_tickets: HashSet<String> = HashSet::new();
    loop {
        match read.next().await {
            Some(Ok(Message::Text(t))) => {
                let ctrl: Control = match serde_json::from_str(&t) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad control from broker");
                        continue;
                    }
                };
                match ctrl {
                    Control::Quota { usage } => {
                        last_usage = Some(usage);
                    }
                    Control::Kill { reason } => {
                        tracing::info!(?reason, "broker sent Kill");
                        let session_end = SessionEnd::Killed(reason, last_usage);
                        teardown(
                            &mut writer,
                            &heartbeat,
                            &usage_report,
                            &mut stream_tasks,
                            &streams,
                            tunnel_tx,
                        )
                        .await;
                        return session_end;
                    }
                    Control::Error { code } => {
                        tracing::info!(?code, "broker sent Error");
                        teardown(
                            &mut writer,
                            &heartbeat,
                            &usage_report,
                            &mut stream_tasks,
                            &streams,
                            tunnel_tx,
                        )
                        .await;
                        return SessionEnd::ServerError(code);
                    }
                    Control::P2pVisitorOffer { ticket, sdp, ice } => {
                        let Some(secret) = decode_secret(&session_secret) else {
                            tracing::warn!("session_secret is not valid base64url");
                            continue;
                        };
                        let Some(target) = cli.http_target.as_ref() else {
                            tracing::warn!("p2p offer but no http target configured");
                            continue;
                        };
                        match P2pGateway::handle_visitor_offer(
                            gateway.clone(),
                            secret,
                            &subdomain,
                            target,
                            &ticket,
                            &sdp,
                            &ice,
                            &mut seen_tickets,
                        )
                        .await
                        {
                            Ok(answer) => {
                                let json = match serde_json::to_string(&Control::P2pAnswer {
                                    ticket,
                                    sdp: answer.sdp,
                                    ice: answer.ice,
                                }) {
                                    Ok(j) => j,
                                    Err(_) => continue,
                                };
                                let _ = tunnel_tx.send(Message::Text(json.into())).await;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "p2p offer rejected");
                            }
                        }
                    }
                    Control::P2pIce { .. } => {
                        // v1: candidates ride the offer/answer SDP (non-trickle).
                        tracing::debug!("p2p trickle candidate ignored (non-trickle)");
                    }
                    Control::P2pReady { .. } => {
                        tracing::info!("p2p ready");
                    }
                    Control::P2pFailed { reason, .. } => {
                        tracing::debug!(%reason, "p2p failed (broker)");
                    }
                    _ => { /* ignore other control frames post-register */ }
                }
            }
            Some(Ok(Message::Binary(b))) => match Frame::decode(&b) {
                Ok(Frame {
                    opcode: Opcode::Open,
                    stream_id,
                    payload,
                }) => {
                    if streams.contains_key(&stream_id) {
                        continue;
                    }
                    let meta = match OpenMeta::decode(&payload) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(stream = stream_id, error = %e, "bad OpenMeta");
                            continue;
                        }
                    };
                    let target = match meta.kind {
                        StreamKind::Http => cli.http_target.clone(),
                        StreamKind::Tcp => cli.tcp_target.clone(),
                    };
                    let Some(target) = target else {
                        // No target configured for this kind → OpenReject
                        let f = Frame {
                            opcode: Opcode::OpenReject,
                            stream_id,
                            payload: Bytes::new(),
                        };
                        let mut buf = Vec::with_capacity(9);
                        let _ = f.encode(&mut buf);
                        let _ = tunnel_tx.send(Message::Binary(Bytes::from(buf))).await;
                        continue;
                    };
                    let (stx, srx) = mpsc::channel(64);
                    streams.insert(stream_id, stx);
                    let stream_tx = tunnel_tx.clone();
                    let streams_map = streams.clone();
                    stream_tasks.spawn(stream_task(
                        streams_map,
                        stream_tx,
                        stream_id,
                        meta,
                        target,
                        srx,
                    ));
                }
                Ok(Frame {
                    opcode: Opcode::Data,
                    stream_id,
                    payload,
                }) => {
                    if let Some(s) = streams.get(&stream_id) {
                        let _ = s.send(StreamMsg::Data(payload)).await;
                    } else {
                        tracing::warn!(stream = stream_id, "Data for unknown stream");
                    }
                }
                Ok(Frame {
                    opcode: Opcode::Close,
                    stream_id,
                    payload,
                }) => {
                    let code = payload.first().copied().unwrap_or(CLOSE_OK);
                    if let Some((_, s)) = streams.remove(&stream_id) {
                        let _ = s.send(StreamMsg::Close(code)).await;
                    }
                }
                Ok(_) => {
                    tracing::warn!("unexpected opcode from broker");
                }
                Err(e) => tracing::warn!(error = %e, "bad frame from broker"),
            },
            Some(Ok(Message::Close(_))) | None => {
                break;
            }
            Some(Ok(Message::Ping(_)))
            | Some(Ok(Message::Pong(_)))
            | Some(Ok(Message::Frame(_))) => {
                // Transport-level; tungstenite handles these automatically
            }
            Some(Err(e)) => {
                tracing::debug!(error = %e, "ws read error");
                break;
            }
        }
    }

    // --- teardown -----------------------------------------------------------
    teardown(
        &mut writer,
        &heartbeat,
        &usage_report,
        &mut stream_tasks,
        &streams,
        tunnel_tx,
    )
    .await;
    SessionEnd::WsClosed
}

/// Shared teardown for every exit path (Kill, Error, WS close): abort the
/// heartbeat and all stream tasks FIRST so their tunnel_tx clones drop, then
/// drop our own sender: the writer's rx.recv() then returns None and it
/// exits. Guard the writer await with a grace period (pending frames flush;
/// mirrors ddns-server's CLOSE_GRACE pattern) so a stalled socket cannot
/// hang run_mux — and with it the reconnect loop.
async fn teardown(
    writer: &mut tokio::task::JoinHandle<()>,
    heartbeat: &tokio::task::JoinHandle<()>,
    usage_report: &tokio::task::JoinHandle<()>,
    stream_tasks: &mut tokio::task::JoinSet<()>,
    streams: &Arc<DashMap<u32, mpsc::Sender<StreamMsg>>>,
    tunnel_tx: mpsc::Sender<Message>,
) {
    heartbeat.abort();
    usage_report.abort();
    stream_tasks.abort_all();
    streams.clear();
    drop(tunnel_tx);
    tokio::select! {
        _ = &mut *writer => {}
        _ = tokio::time::sleep(Duration::from_millis(500)) => writer.abort(),
    }
    // stream_tasks: abort_all() already signalled termination; the JoinSet
    // aborts any stragglers when the caller drops it (end of run_mux scope).
}

// --------------------------------------------------------------------------
// stream_task — one per Open frame
// --------------------------------------------------------------------------

/// Per-stream task: dial local target, handshake, bidirectional pump.
/// Per-stream task: dial local target, handshake, bidirectional pump.
///
/// For HTTP streams, the handshake forwards the request head to the local
/// server, then concurrently reads the response head from the local socket
/// while forwarding request-body Data frames from the broker. This avoids
/// deadlock when the request has a body (the local server needs the full
/// request before responding, and the broker sends the body as Data frames).
async fn stream_task(
    streams: Arc<DashMap<u32, mpsc::Sender<StreamMsg>>>,
    tunnel_tx: mpsc::Sender<Message>,
    stream_id: u32,
    meta: OpenMeta,
    target: LocalTarget,
    mut rx: mpsc::Receiver<StreamMsg>,
) {
    // Remove our map entry on every exit path (including abort).
    let _cleanup = StreamCleanup {
        streams,
        id: stream_id,
    };

    // 1. Dial the local target
    let local = match target.dial().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(stream = stream_id, error = %e, "dial failed");
            send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
            return;
        }
    };
    let (mut lr, mut lw) = local.into_split();

    // 2. HTTP handshake or TCP empty ack
    // For HTTP: forward the request head, then concurrently pump request-body
    // Data frames to the local socket while reading the response head.
    if meta.kind == StreamKind::Http {
        // Forward the request head verbatim
        let head = meta.head.unwrap_or_default();
        if !head.is_empty() && lw.write_all(&head).await.is_err() {
            send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
            return;
        }

        // Concurrently pump request body from broker → local while reading
        // the response head from local. Timeout: 30 s total.
        let mut head_buf = Vec::new();
        let mut acked = false;
        let handshake = tokio::time::timeout(Duration::from_secs(30), async {
            let mut tmp = [0u8; 1024];
            loop {
                tokio::select! {
                    // Read a chunk from the local server
                    result = lr.read(&mut tmp) => {
                        match result {
                            Ok(0) => {
                                send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
                                return;
                            }
                            Ok(n) => {
                                head_buf.extend_from_slice(&tmp[..n]);
                                if head_buf.len() > 64 * 1024 {
                                    send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
                                    return;
                                }
                                // Check if we have the full response head
                                if head_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    // Got the head!
                                    if !head_buf.starts_with(b"HTTP/") {
                                        send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
                                        return;
                                    }
                                    let head_end = head_buf
                                        .windows(4)
                                        .position(|w| w == b"\r\n\r\n")
                                        .map(|p| p + 4)
                                        .unwrap_or(head_buf.len());
                                    let head_bytes = Bytes::copy_from_slice(
                                        &head_buf[..head_end]
                                    );
                                    send_frame(&tunnel_tx, stream_id, Opcode::OpenAck, head_bytes).await;
                                    // Buffer any body bytes that were read past
                                    // the \r\n\r\n for the pump below.
                                    if head_end < head_buf.len() {
                                        // Feed the extra bytes back through the
                                        // pump by sending them as Data frames.
                                        let rest = Bytes::copy_from_slice(
                                            &head_buf[head_end..]
                                        );
                                        if !rest.is_empty() {
                                            for chunk in rest.chunks(MAX_FRAME_PAYLOAD)
                                            {
                                                send_frame(
                                                    &tunnel_tx,
                                                    stream_id,
                                                    Opcode::Data,
                                                    Bytes::copy_from_slice(chunk),
                                                ).await;
                                            }
                                        }
                                    }
                                    acked = true;
                                    return;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    stream = stream_id,
                                    error = %e,
                                    "local read error during handshake"
                                );
                                send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
                                return;
                            }
                        }
                    }
                    // Receive Data/Close frames from broker → forward to local
                    msg = rx.recv() => {
                        match msg {
                            Some(StreamMsg::Data(data)) => {
                                if lw.write_all(&data).await.is_err() {
                                    return;
                                }
                            }
                            Some(StreamMsg::Close(_)) | None => {
                                // Broker closed the stream before we acked.
                                return;
                            }
                        }
                    }
                }
            }
        })
        .await;

        if !acked {
            // Timeout or error during handshake
            if handshake.is_err() {
                tracing::warn!(stream = stream_id, "HTTP handshake timed out");
            }
            send_frame(&tunnel_tx, stream_id, Opcode::OpenReject, Bytes::new()).await;
            return;
        }
    } else {
        // TCP: empty ack
        send_frame(&tunnel_tx, stream_id, Opcode::OpenAck, Bytes::new()).await;
    }

    // 3. Bidirectional pump: local → ws and ws → local.
    //
    // For HTTP: after the handshake the LOCAL server has responded, but the
    // broker forwards visitor request-body Data unconditionally (no ack gate,
    // see ddns-server http_tunnel.rs) — a fast responder (401/404/413, or a
    // slow upload) can produce OpenAck before the visitor finishes sending.
    // rx MUST stay drained or the shared recv loop blocks forever when the
    // per-stream channel (cap 64) fills, wedging the whole session. We keep
    // forwarding body Data to the local server until it stops consuming.
    //
    // For TCP: full-duplex pump for the lifetime of the stream.
    if meta.kind == StreamKind::Http {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
        let mut forward_body = true;
        loop {
            tokio::select! {
                // Response direction: local → broker.
                result = lr.read(&mut buf) => {
                    match result {
                        Ok(0) => {
                            send_frame(&tunnel_tx, stream_id, Opcode::Close, Bytes::from_static(&[CLOSE_OK])).await;
                            return;
                        }
                        Ok(n) => {
                            for chunk in buf[..n].chunks(MAX_FRAME_PAYLOAD) {
                                let f = Frame {
                                    opcode: Opcode::Data,
                                    stream_id,
                                    payload: Bytes::copy_from_slice(chunk),
                                };
                                let mut enc = Vec::with_capacity(9 + chunk.len());
                                if f.encode(&mut enc).is_err() {
                                    return;
                                }
                                if tunnel_tx.send(Message::Binary(Bytes::from(enc))).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(stream = stream_id, error = %e, "local read error");
                            send_frame(&tunnel_tx, stream_id, Opcode::Close, Bytes::from_static(&[CLOSE_APP_ERROR])).await;
                            return;
                        }
                    }
                }
                // Request-body direction: broker → local (late Data).
                msg = rx.recv() => {
                    match msg {
                        Some(StreamMsg::Data(data)) => {
                            if forward_body {
                                // Bounded local write: a keep-alive responder
                                // that never reads its body must not stall us
                                // forever — stop forwarding but keep draining.
                                match tokio::time::timeout(Duration::from_secs(5), lw.write_all(&data)).await {
                                    Ok(Ok(())) => {}
                                    _ => forward_body = false,
                                }
                            }
                        }
                        Some(StreamMsg::Close(_)) | None => return,
                    }
                }
            }
        }
    }

    // TCP: full-duplex pump.
    let local_to_ws = {
        let tunnel_tx = tunnel_tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
            loop {
                match lr.read(&mut buf).await {
                    Ok(0) => {
                        let f = Frame {
                            opcode: Opcode::Close,
                            stream_id,
                            payload: Bytes::from_static(&[CLOSE_OK]),
                        };
                        let mut enc = Vec::with_capacity(10);
                        let _ = f.encode(&mut enc);
                        let _ = tunnel_tx.send(Message::Binary(Bytes::from(enc))).await;
                        return;
                    }
                    Ok(n) => {
                        for chunk in buf[..n].chunks(MAX_FRAME_PAYLOAD) {
                            let f = Frame {
                                opcode: Opcode::Data,
                                stream_id,
                                payload: Bytes::copy_from_slice(chunk),
                            };
                            let mut enc = Vec::with_capacity(9 + chunk.len());
                            let _ = f.encode(&mut enc);
                            if tunnel_tx
                                .send(Message::Binary(Bytes::from(enc)))
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(stream = stream_id, error = %e, "local read error");
                        let f = Frame {
                            opcode: Opcode::Close,
                            stream_id,
                            payload: Bytes::from_static(&[CLOSE_APP_ERROR]),
                        };
                        let mut enc = Vec::with_capacity(10);
                        let _ = f.encode(&mut enc);
                        let _ = tunnel_tx.send(Message::Binary(Bytes::from(enc))).await;
                        return;
                    }
                }
            }
        })
    };

    // ws → local: forward StreamMsg::Data to the local peer. Bound the local
    // write: a stalled local peer (full window, alive socket) must not block
    // this loop, because then the per-stream channel fills and the shared
    // recv loop blocks in `s.send(...)` — wedging the whole session (Quota/
    // Kill/Close and the WS close frame would never be read, so the reconnect
    // loop never fires). On timeout, Close{CLOSE_APP_ERROR} the stream so the
    // broker tears down the visitor side, but KEEP draining rx until the
    // broker's Close arrives (same pattern as the HTTP pump above).
    let mut forward = true;
    while let Some(msg) = rx.recv().await {
        match msg {
            StreamMsg::Data(data) => {
                if forward {
                    match tokio::time::timeout(Duration::from_secs(5), lw.write_all(&data)).await {
                        Ok(Ok(())) => {}
                        _ => {
                            forward = false;
                            tracing::warn!(
                                stream = stream_id,
                                "local write stalled; closing stream"
                            );
                            send_frame(
                                &tunnel_tx,
                                stream_id,
                                Opcode::Close,
                                Bytes::from_static(&[CLOSE_APP_ERROR]),
                            )
                            .await;
                        }
                    }
                }
            }
            StreamMsg::Close(_) => break,
        }
    }

    local_to_ws.abort();
}

/// Decode the base64url session secret (32 bytes) delivered in `Registered`.
fn decode_secret(s: &str) -> Option<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    bytes.try_into().ok()
}

/// Wall-clock epoch seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
