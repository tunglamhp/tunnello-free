//! UDP tunnel: a public UDP socket (`--udp-port`, default disabled) forwards
//! datagrams to the client's local UDP service over the session's mux. One
//! flow per visitor address; the client dials its local target and relays
//! `UData` frames both ways. Flows expire after `UDP_FLOW_IDLE` without
//! traffic — UDP has no close, so both sides reap independently.
//!
//! Routing (v1): the port serves the FIRST live session that registered
//! `want_udp`. Multi-tenant UDP routing (per-slug ports) is future work.

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

struct Flow {
    session: Arc<TunnelSession>,
    stream_id: u32,
    last_seen: Instant,
}

pub async fn run(state: BrokerState, port: u16) -> std::io::Result<()> {
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!(%bind, "UDP tunnel listener ready");

    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    // Downstream channel: (visitor addr, datagram) from flow tasks → main loop.
    let (down_tx, mut down_rx) = mpsc::channel::<(SocketAddr, Bytes)>(1024);
    let mut buf = vec![0u8; UDP_DATAGRAM_MAX];
    let mut reap = tokio::time::interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((len, peer)) = r else { continue };
                let datagram = Bytes::copy_from_slice(&buf[..len]);
                if let Some(flow) = flows.get_mut(&peer) {
                    flow.last_seen = Instant::now();
                    let f = Frame {
                        opcode: Opcode::UData,
                        stream_id: flow.stream_id,
                        payload: datagram,
                    };
                    let _ = flow.session.send_frame(&f).await;
                } else {
                    // New flow: pick the first live session that wants UDP.
                    let Some(session) = state
                        .registry
                        .all_sessions()
                        .into_iter()
                        .find(|s| s.want_udp)
                    else {
                        continue; // no UDP-capable client online; datagram dropped
                    };
                    if !session.register_stream() {
                        continue;
                    }
                    let stream_id = session.next_stream_id();
                    // Tell the client to dial its local UDP target.
                    let mut meta = Vec::new();
                    let open = OpenMeta {
                        kind: StreamKind::Udp,
                        port: session.udp_target_port,
                        head: None,
                    };
                    if open.encode(&mut meta).is_err() {
                        session.release_stream();
                        continue;
                    }
                    let _ = session.send_frame(&Frame {
                        opcode: Opcode::UOpen,
                        stream_id,
                        payload: Bytes::from(meta),
                    }).await;
                    let _ = session.send_frame(&Frame {
                        opcode: Opcode::UData,
                        stream_id,
                        payload: datagram,
                    }).await;
                    flows.insert(peer, Flow {
                        session: session.clone(),
                        stream_id,
                        last_seen: Instant::now(),
                    });
                    // Spawn the downstream pump: UData/UClose frames from the
                    // client for this stream → visitor via the shared socket.
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
                        // Channel closed (session died) → pump exits; the main
                        // loop's reaper drops the flow entry on idle timeout.
                        drop(sock2);
                    });
                }
            }
            Some((peer, data)) = down_rx.recv() => {
                let _ = sock.send_to(&data, peer).await;
            }
            _ = reap.tick() => {
                let now = Instant::now();
                flows.retain(|_, flow| {
                    let alive = now.duration_since(flow.last_seen) < UDP_FLOW_IDLE;
                    if !alive {
                        // Best-effort close; the client also idles out its side.
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
        }
    }
}
