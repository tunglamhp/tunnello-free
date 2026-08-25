//! UDP tunnel: public UDP sockets forward datagrams to clients' local UDP
//! services over each session's mux. One flow per visitor address; the
//! client dials its local target and relays `UData` frames both ways. Flows
//! expire after `UDP_FLOW_IDLE` without traffic — UDP has no close, so both
//! sides reap independently.
//!
//! Routing (v2, multi-tenant):
//!   * Shared port (`--udp-port N`): the FIRST datagram of a flow must carry
//!     a `<slug>\n` prefix; the broker strips it and binds the flow to that
//!     slug's session. Later datagrams on the same visitor address ride the
//!     established flow without a prefix.
//!   * Dedicated ports (`--udp-route slug=port`, repeatable): every datagram
//!     on that port goes to the named slug's session, no prefix needed.

use bytes::Bytes;
use ddns_proto::{Frame, Opcode, OpenMeta, StreamKind};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::http_app::BrokerState;
use crate::session::{TunnelSession, UDP_DATAGRAM_MAX};

/// Flow idle timeout: no datagrams either way → reap the flow.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(30);
/// Per-flow downstream queue depth (client → visitor datagrams).
const FLOW_QUEUE: usize = 64;

pub async fn run(
    state: BrokerState,
    shared_port: u16,
    routes: Vec<(String, u16)>,
) -> std::io::Result<()> {
    if shared_port > 0 {
        let bind = SocketAddr::from(([0, 0, 0, 0], shared_port));
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        tracing::info!(%bind, "UDP tunnel listener ready (shared; slug-prefix routing)");
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_shared(st, sock).await {
                tracing::warn!(error = %e, "shared UDP listener exited");
            }
        });
    }
    for (slug, port) in routes {
        let bind = SocketAddr::from(([0, 0, 0, 0], port));
        let sock = Arc::new(UdpSocket::bind(bind).await?);
        tracing::info!(%bind, %slug, "UDP tunnel route ready (dedicated port)");
        let st = state.clone();
        let slug2 = slug.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_dedicated(st, sock, slug2).await {
                tracing::warn!(error = %e, "dedicated UDP listener exited");
            }
        });
    }
    Ok(())
}

struct Flow {
    session: Arc<TunnelSession>,
    stream_id: u32,
    last_seen: Instant,
}

/// Shared listener: first datagram carries `<slug>\n`; later ones ride the flow.
async fn serve_shared(state: BrokerState, sock: Arc<UdpSocket>) -> std::io::Result<()> {
    let (down_tx, mut down_rx) = mpsc::channel::<(SocketAddr, Bytes)>(1024);
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut buf = vec![0u8; UDP_DATAGRAM_MAX + 64]; // headroom for the slug prefix
    let mut reap = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((len, peer)) = r else { continue };
                let mut datagram = &buf[..len];
                let session = if let Some(flow) = flows.get_mut(&peer) {
                    flow.last_seen = Instant::now();
                    flow.session.clone()
                } else {
                    // New flow: parse the `<slug>\n` prefix and bind the flow.
                    let Some(nl) = datagram.iter().position(|&b| b == b'\n') else {
                        tracing::debug!(%peer, "first UDP datagram missing slug prefix; dropped");
                        continue;
                    };
                    let slug = std::str::from_utf8(&datagram[..nl]).unwrap_or("");
                    datagram = &datagram[nl + 1..];
                    let Some(session) = state.registry.lookup(slug).filter(|s| s.want_udp) else {
                        tracing::debug!(%peer, %slug, "no live UDP session for slug; dropped");
                        continue;
                    };
                    open_flow(&session, &sock, peer, datagram, &down_tx, &mut flows).await;
                    continue;
                };
                let f = Frame {
                    opcode: Opcode::UData,
                    stream_id: flows.get(&peer).expect("flow just checked").stream_id,
                    payload: Bytes::copy_from_slice(datagram),
                };
                let _ = session.send_frame(&f).await;
            }
            Some((peer, data)) = down_rx.recv() => {
                let _ = sock.send_to(&data, peer).await;
            }
            _ = reap.tick() => {
                reap_flows(&mut flows);
            }
        }
    }
}

/// Dedicated listener: all datagrams go to one slug's session, no prefix.
async fn serve_dedicated(
    state: BrokerState,
    sock: Arc<UdpSocket>,
    slug: String,
) -> std::io::Result<()> {
    let (down_tx, mut down_rx) = mpsc::channel::<(SocketAddr, Bytes)>(1024);
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut buf = vec![0u8; UDP_DATAGRAM_MAX];
    let mut reap = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((len, peer)) = r else { continue };
                let datagram = &buf[..len];
                if let Some(flow) = flows.get_mut(&peer) {
                    flow.last_seen = Instant::now();
                    let f = Frame {
                        opcode: Opcode::UData,
                        stream_id: flow.stream_id,
                        payload: Bytes::copy_from_slice(datagram),
                    };
                    let _ = flow.session.send_frame(&f).await;
                } else {
                    let Some(session) = state.registry.lookup(&slug).filter(|s| s.want_udp) else {
                        tracing::debug!(%peer, %slug, "no live UDP session for slug; dropped");
                        continue;
                    };
                    open_flow(&session, &sock, peer, datagram, &down_tx, &mut flows).await;
                }
            }
            Some((peer, data)) = down_rx.recv() => {
                let _ = sock.send_to(&data, peer).await;
            }
            _ = reap.tick() => {
                reap_flows(&mut flows);
            }
        }
    }
}

/// Bind a new flow: UOpen + first UData to the client, register the
/// downstream pump, and record the flow entry.
async fn open_flow(
    session: &Arc<TunnelSession>,
    sock: &Arc<UdpSocket>,
    peer: SocketAddr,
    first_datagram: &[u8],
    down_tx: &mpsc::Sender<(SocketAddr, Bytes)>,
    flows: &mut HashMap<SocketAddr, Flow>,
) {
    if !session.register_stream() {
        return;
    }
    let stream_id = session.next_stream_id();
    let mut meta = Vec::new();
    let open = OpenMeta {
        kind: StreamKind::Udp,
        port: session.udp_target_port,
        head: None,
    };
    if open.encode(&mut meta).is_err() {
        session.release_stream();
        return;
    }
    let _ = session
        .send_frame(&Frame {
            opcode: Opcode::UOpen,
            stream_id,
            payload: Bytes::from(meta),
        })
        .await;
    let _ = session
        .send_frame(&Frame {
            opcode: Opcode::UData,
            stream_id,
            payload: Bytes::copy_from_slice(first_datagram),
        })
        .await;
    flows.insert(
        peer,
        Flow {
            session: session.clone(),
            stream_id,
            last_seen: Instant::now(),
        },
    );
    // Downstream pump: UData/UClose from the client for this stream.
    let pump_tx = down_tx.clone();
    let (flow_tx, mut flow_rx) = mpsc::channel::<Frame>(FLOW_QUEUE);
    session.streams.insert(stream_id, flow_tx);
    let sock2 = sock.clone();
    tokio::spawn(async move {
        while let Some(f) = flow_rx.recv().await {
            match f.opcode {
                Opcode::UData => {
                    let _ = pump_tx.send((peer, f.payload)).await;
                }
                Opcode::UClose | Opcode::Close => break,
                _ => {}
            }
        }
        // Channel closed (session died) → pump exits; the reaper drops the
        // flow entry on idle timeout.
        drop(sock2);
    });
}

/// Drop flows idle past `UDP_FLOW_IDLE`, sending a best-effort UClose.
fn reap_flows(flows: &mut HashMap<SocketAddr, Flow>) {
    let now = Instant::now();
    flows.retain(|_, flow| {
        let alive = now.duration_since(flow.last_seen) < UDP_FLOW_IDLE;
        if !alive {
            let close = Frame {
                opcode: Opcode::UClose,
                stream_id: flow.stream_id,
                payload: Bytes::new(),
            };
            let session = flow.session.clone();
            tokio::spawn(async move {
                let _ = session.send_frame(&close).await;
            });
        }
        alive
    });
}
