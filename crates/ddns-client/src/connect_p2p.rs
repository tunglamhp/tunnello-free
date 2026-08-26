//! `ddns connect <sub>` helper — the native visitor side of the P2P TCP data
//! plane (spec §5.2).
//!
//! Opens a `"tcp"`-labeled WebRTC data channel through the existing
//! `/__p2p/signal` endpoint (the `hello` flow — no token, no tunnel
//! registration), binds `127.0.0.1:0`, and pumps each accepted TCP connection
//! over the channel with the same `REQ`/`DATA`/`CLOSE` framing as the
//! gateway's TCP bridge (Task 1). On punch failure it returns a relay hint.
//!
//! The signaling + channel setup is factored into
//! [`connect_p2p_channel`], whose `negotiate` closure exchanges the offer SDP
//! for an answer — the broker in production, a loopback `P2pGateway` in the
//! in-process e2e test.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::{AbortHandle, JoinSet};
use tokio_tungstenite::tungstenite::Message;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState, RTCSessionDescription,
};

use crate::cli::{Cli, split_host_port};
use crate::connect::client_config;
use crate::p2p::{OP_CLOSE, OP_DATA, OP_REQ, decode_frame, encode_frame};

/// Maximum concurrent TCP streams multiplexed over one helper channel
/// (mirrors the gateway's stream cap).
const MAX_CONNECT_STREAMS: usize = 512;

/// Hard cap on the whole punch attempt (offer gather → answer → channel open).
/// On timeout the helper exits with the relay hint (spec §5.2 step 4).
const SIGNAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The whole connect flow: negotiate the `"tcp"` channel, bind a local TCP
/// listener, and pump accepted connections over the channel until it closes.
pub async fn run_connect(
    server: &str,
    subdomain: &str,
    ca_pem: Option<&str>,
    roots: &[CertificateDer<'static>],
) -> Result<(), String> {
    let relay = relay_address(server, subdomain);

    // Owned copies so the `negotiate` closure returns a `'static` future.
    let server_owned = server.to_string();
    let subdomain_owned = subdomain.to_string();
    let ca_pem_owned = ca_pem.map(str::to_string);
    let roots_owned = roots.to_vec();

    let negotiate = move |offer_sdp| {
        signal_via_broker(
            server_owned,
            subdomain_owned,
            ca_pem_owned,
            roots_owned,
            offer_sdp,
        )
    };

    let (pc, dc) = match tokio::time::timeout(SIGNAL_TIMEOUT, connect_p2p_channel(negotiate)).await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(relay_error(&relay)),
    };

    let (listener, _port) = bind_listener(subdomain).await?;
    run_pumps(pc, dc, listener, subdomain.to_string()).await
}

/// Build a `"tcp"`-labeled `PeerConnection`, gather host candidates
/// (non-trickle), then hand the offer SDP to `negotiate` and apply the answer.
/// Returns the open `(pc, dc)` pair. The `negotiate` closure is the seam that
/// lets the in-process e2e test drive the same code without a real broker.
pub async fn connect_p2p_channel<F, Fut>(
    negotiate: F,
) -> Result<(Arc<dyn PeerConnection>, Arc<dyn DataChannel>), String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    connect_p2p_channel_labeled("tcp", negotiate).await
}

/// [`connect_p2p_channel`] with an explicit channel label (`"tcp"` | `"udp"`).
pub async fn connect_p2p_channel_labeled<F, Fut>(
    label: &str,
    negotiate: F,
) -> Result<(Arc<dyn PeerConnection>, Arc<dyn DataChannel>), String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let (gather_tx, mut gather_rx) = tokio::sync::mpsc::channel::<()>(1);
    let pc: Arc<dyn PeerConnection> = Arc::new(
        PeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_handler(Arc::new(ConnectHandler { gather_tx }))
            .with_udp_addrs(vec!["0.0.0.0:0".to_string(), "127.0.0.1:0".to_string()])
            .build()
            .await
            .map_err(|e| e.to_string())?,
    );

    let dc = pc
        .create_data_channel(label, None)
        .await
        .map_err(|e| e.to_string())?;

    let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
    pc.set_local_description(offer)
        .await
        .map_err(|e| e.to_string())?;

    // Non-trickle: wait for host-candidate gathering so the offer SDP carries
    // the candidates (the gateway answers non-trickle in v1 too).
    let _ = tokio::time::timeout(Duration::from_secs(10), gather_rx.recv()).await;
    let offer_sdp = pc
        .local_description()
        .await
        .map(|d| d.sdp)
        .ok_or_else(|| "no local description after offer".to_string())?;

    let answer_sdp = negotiate(offer_sdp).await?;
    let answer = RTCSessionDescription::answer(answer_sdp).map_err(|e| e.to_string())?;
    pc.set_remote_description(answer)
        .await
        .map_err(|e| e.to_string())?;

    // Wait for the channel to open.
    let mut opened = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !opened && tokio::time::Instant::now() < deadline {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => opened = true,
            Some(DataChannelEvent::OnClose) | None => break,
            _ => {}
        }
    }
    if !opened {
        return Err("p2p data channel did not open".to_string());
    }

    Ok((pc, dc))
}

/// Offer-side handler: signals ICE-gathering completion so the offer SDP is
/// serialized only once host candidates are baked in (non-trickle).
#[derive(Clone)]
struct ConnectHandler {
    gather_tx: tokio::sync::mpsc::Sender<()>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ConnectHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }
}

/// Open `wss://<server>/__p2p/signal`, send the `hello` offer, and wait for the
/// `answer`. Returns the answer SDP.
async fn signal_via_broker(
    server: String,
    subdomain: String,
    ca_pem: Option<String>,
    roots: Vec<CertificateDer<'static>>,
    offer_sdp: String,
) -> Result<String, String> {
    // Build the TLS config from the server + optional ca_pem via a throwaway
    // `Cli` so we reuse `connect::client_config` without touching its public
    // API (only `ca_pem` is read by it).
    let cli = Cli {
        token: String::new(),
        server: server.clone(),
        http_target: None,
        tcp_target: None,
        udp_target: None,
        name: None,
        ca_pem: ca_pem.map(std::path::PathBuf::from),
        heartbeat_interval: Duration::from_secs(0),
    };
    let tls_cfg = Arc::new(client_config(&cli, &roots)?);
    let connector = tokio_tungstenite::Connector::Rustls(tls_cfg);

    let url = signal_url(&server)?;
    let (mut ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
            .await
            .map_err(|e| format!("WS connect: {e}"))?;

    let hello = serde_json::json!({
        "type": "hello",
        "slug": subdomain,
        "sdp": offer_sdp,
        "ice": [],
    });
    ws.send(Message::Text(hello.to_string().into()))
        .await
        .map_err(|e| format!("send hello: {e}"))?;

    // v1 is non-trickle: the answer SDP carries the gateway's candidates, so
    // there is no `ice` relay to apply. Wait for `answer` or `failed`.
    loop {
        let msg = ws
            .next()
            .await
            .ok_or_else(|| "signaling ws closed before answer".to_string())?
            .map_err(|e| format!("ws read: {e}"))?;
        let text = msg
            .to_text()
            .map_err(|e| format!("expected text, got binary: {e}"))?;
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| format!("bad signaling JSON: {e}"))?;
        match value.get("type").and_then(|t| t.as_str()) {
            Some("answer") => {
                let sdp = value
                    .get("sdp")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| "answer missing sdp".to_string())?;
                return Ok(sdp.to_string());
            }
            Some("failed") => {
                let reason = value
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                return Err(format!("p2p signaling failed: {reason}"));
            }
            _ => {}
        }
    }
}

/// Map a broker URL (`https://host[:port]`) to the signaling WebSocket URL.
fn signal_url(server: &str) -> Result<String, String> {
    let (scheme, rest) = server
        .split_once("://")
        .ok_or_else(|| format!("invalid server URL: {server}"))?;
    let ws_scheme = match scheme {
        "https" => "wss",
        "http" => "ws",
        "wss" => "wss",
        "ws" => "ws",
        _ => return Err(format!("unsupported server scheme: {scheme}")),
    };
    Ok(format!(
        "{ws_scheme}://{}/__p2p/signal",
        rest.trim_end_matches('/')
    ))
}

/// The broker relay address to suggest on punch failure:
/// `<subdomain>.<domain>:<port>` (port defaults to 443).
fn relay_address(server: &str, subdomain: &str) -> String {
    let rest = server
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(server)
        .trim_end_matches('/');
    let (host, port) = split_host_port(rest).unwrap_or_else(|_| (rest.to_string(), None));
    format!("{subdomain}.{host}:{}", port.unwrap_or(443))
}

fn relay_error(relay: &str) -> String {
    format!("p2p connect failed — use the relay address {relay} instead")
}

/// Bind the local TCP listener and print the forward line. Returns the
/// listener and its bound port.
pub async fn bind_listener(subdomain: &str) -> Result<(TcpListener, u16), String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    println!("Forwarding TCP 127.0.0.1:{port} → {subdomain} (P2P)");
    tracing::info!(subdomain, port, "p2p connect forwarding");
    Ok((listener, port))
}

/// Accept loop + channel pumps, mirroring the gateway's TCP bridge with the
/// socket/channel roles swapped: each accepted connection opens a stream
/// (`REQ`), socket bytes → `DATA`, channel `DATA` → socket, EOF/`CLOSE` ends
/// the stream. Runs until the channel closes.
pub async fn run_pumps(
    _pc: Arc<dyn PeerConnection>,
    dc: Arc<dyn DataChannel>,
    listener: TcpListener,
    subdomain: String,
) -> Result<(), String> {
    let next_id = AtomicU32::new(1);
    let mut streams: HashMap<u32, OpenStream> = HashMap::new();
    let mut read_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            // Reap finished read pumps so a long-lived channel cannot leak
            // completed task handles (disabled while the set is empty).
            _ = read_tasks.join_next(), if !read_tasks.is_empty() => {}

            ev = dc.poll() => {
                match ev {
                    Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                        let Some(frame) = decode_frame(&msg.data) else { continue; };
                        match frame.opcode {
                            OP_DATA => {
                                let Some(stream) = streams.get_mut(&frame.request_id) else {
                                    continue;
                                };
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
                        tracing::info!(subdomain, "p2p connect channel closed");
                        return Ok(());
                    }
                    _ => {}
                }
            }

            accepted = listener.accept() => {
                let (sock, _peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(subdomain, "accept failed: {e}");
                        continue;
                    }
                };
                if streams.len() >= MAX_CONNECT_STREAMS {
                    tracing::warn!(subdomain, "p2p connect stream cap reached; dropping connection");
                    drop(sock);
                    continue;
                }
                let id = next_id.fetch_add(1, Ordering::Relaxed);
                if send_frame(&dc, OP_REQ, id, &[]).await.is_err() {
                    drop(sock);
                    continue;
                }
                let (rd, write) = sock.into_split();
                let task = read_tasks.spawn(read_socket_pump(dc.clone(), rd, id));
                streams.insert(id, OpenStream { write, task });
                tracing::info!(subdomain, stream = id, "p2p connect stream opened");
            }
        }
    }
}

/// An open TCP stream: the socket write half (owned by the event loop) and the
/// read-pump task (socket → `DATA` frames).
struct OpenStream {
    write: OwnedWriteHalf,
    task: AbortHandle,
}

/// The whole UDP connect flow: negotiate the `"udp"` channel, bind a local
/// UDP socket, and pump datagrams over the channel until it closes.
pub async fn run_connect_udp(
    server: &str,
    subdomain: &str,
    ca_pem: Option<&str>,
    roots: &[CertificateDer<'static>],
) -> Result<(), String> {
    let relay = relay_address(server, subdomain);

    let server_owned = server.to_string();
    let subdomain_owned = subdomain.to_string();
    let ca_pem_owned = ca_pem.map(str::to_string);
    let roots_owned = roots.to_vec();

    let negotiate = move |offer_sdp| {
        signal_via_broker(
            server_owned,
            subdomain_owned,
            ca_pem_owned,
            roots_owned,
            offer_sdp,
        )
    };

    let (pc, dc) = match tokio::time::timeout(
        SIGNAL_TIMEOUT,
        connect_p2p_channel_labeled("udp", negotiate),
    )
    .await
    {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(relay_error(&relay)),
    };

    let (sock, _port) = bind_udp_socket(subdomain).await?;
    run_udp_pumps(pc, dc, sock, subdomain.to_string()).await
}

/// Bind the visitor's local UDP socket (ephemeral port) and print the
/// forward line. Returns the socket and its bound port.
pub async fn bind_udp_socket(subdomain: &str) -> Result<(tokio::net::UdpSocket, u16), String> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind udp: {e}"))?;
    let port = sock.local_addr().map_err(|e| e.to_string())?.port();
    println!("Forwarding UDP 127.0.0.1:{port} -> p2p:{subdomain}");
    Ok((sock, port))
}

/// Visitor-side UDP pumps (mirror of [`run_pumps`] with datagram semantics):
/// one flow per remote address; an empty `REQ` announces the flow; the flow's
/// first datagram carries the `<subdomain>\n` shared-port routing prefix;
/// 30 s idle sends `CLOSE`. Channel `DATA` frames go back to the flow's
/// remote address. Runs until the channel closes.
pub async fn run_udp_pumps(
    _pc: Arc<dyn PeerConnection>,
    dc: Arc<dyn DataChannel>,
    sock: tokio::net::UdpSocket,
    subdomain: String,
) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::time::Instant;

    const FLOW_IDLE: Duration = Duration::from_secs(30);
    type FlowMap = Arc<Mutex<HashMap<u32, std::net::SocketAddr>>>;

    let sock = Arc::new(sock);
    let mut flows: HashMap<std::net::SocketAddr, u32> = HashMap::new();
    let remotes: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let mut first: HashSet<u32> = HashSet::new();
    let mut last_seen: HashMap<u32, Instant> = HashMap::new();
    let mut next_flow: u32 = 1;

    // Downstream reader (own task): channel DATA → visitor app. It resolves
    // the flow's remote address through the shared map.
    let remotes_reader: FlowMap = remotes.clone();
    let sock_down = sock.clone();
    let dc_down = dc.clone();
    let down = tokio::spawn(async move {
        let mut buf = vec![0u8; 0]; // placeholder to keep types simple
        let _ = &mut buf;
        loop {
            match dc_down.poll().await {
                Some(webrtc::data_channel::DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                    let Some(frame) = crate::p2p::decode_frame(&msg.data) else {
                        continue;
                    };
                    match frame.opcode {
                        crate::p2p::OP_DATA => {
                            let remote = remotes_reader
                                .lock()
                                .unwrap()
                                .get(&frame.request_id)
                                .copied();
                            if let Some(remote) = remote {
                                let _ = sock_down.send_to(&frame.payload, remote).await;
                            }
                        }
                        crate::p2p::OP_CLOSE => {
                            remotes_reader.lock().unwrap().remove(&frame.request_id);
                        }
                        _ => {}
                    }
                }
                Some(webrtc::data_channel::DataChannelEvent::OnClose) | None => break,
                _ => {}
            }
        }
    });

    // Upstream loop: visitor datagrams → channel (single owner of `flows`).
    let mut buf = vec![0u8; 65_535];
    let result = loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((len, remote)) = r else { break Ok(()) };
                let datagram = &buf[..len];
                let flow_id = match flows.get(&remote) {
                    Some(id) => *id,
                    None => {
                        let id = next_flow;
                        next_flow += 1;
                        flows.insert(remote, id);
                        remotes.lock().unwrap().insert(id, remote);
                        first.insert(id);
                        // Announce the flow (empty REQ).
                        send_frame(&dc, OP_REQ, id, &[]).await?;
                        id
                    }
                };
                last_seen.insert(flow_id, Instant::now());
                let payload: Vec<u8> = if first.remove(&flow_id) {
                    let mut prefixed = subdomain.as_bytes().to_vec();
                    prefixed.push(b'\n');
                    prefixed.extend_from_slice(datagram);
                    prefixed
                } else {
                    datagram.to_vec()
                };
                send_frame(&dc, OP_DATA, flow_id, &payload).await?;
            }

            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                // Reap flows idle past FLOW_IDLE (CLOSE + drop both maps).
                let now = Instant::now();
                let expired: Vec<u32> = last_seen
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) > FLOW_IDLE)
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    last_seen.remove(&id);
                    first.remove(&id);
                    remotes.lock().unwrap().remove(&id);
                    flows.retain(|_, v| *v != id);
                    send_frame(&dc, OP_CLOSE, id, &[]).await?;
                }
            }
        }
    };

    down.abort();
    result
}

/// Pump one accepted socket's read half into `DATA` frames until EOF/error,/// Pump one accepted socket's read half into `DATA` frames until EOF/error,
/// then signal `CLOSE` and return.
async fn read_socket_pump(dc: Arc<dyn DataChannel>, mut rd: OwnedReadHalf, id: u32) {
    let mut buf = [0u8; 4096];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => {
                let _ = send_frame(&dc, OP_CLOSE, id, &[]).await;
                return;
            }
            Ok(n) => {
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
