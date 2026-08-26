//! WireGuard tunnel session over `boringtun::noise::Tunn` — the protocol
//! core is boringtun (standard WG, spec ADR-W1); this module owns the
//! transport pump (UDP socket ↔ Tunn ↔ IP packets) so both the real `ddns up`
//! (TUN device) and the loopback e2e (in-memory) drive the same code.

use boringtun::noise::{Tunn, TunnResult};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// One WG peer session bound to a UDP socket.
pub struct WgPeer {
    tunn: Tunn,
    sock: Arc<UdpSocket>,
    /// Peer endpoint: set at construction (visitor) or learned from the
    /// first packet (exit, roaming).
    peer_addr: std::sync::Mutex<Option<std::net::SocketAddr>>,
    /// Scratch for encapsulated (WG transport) packets.
    send_buf: Vec<u8>,
    /// Scratch for decapsulated (inner IP) packets.
    recv_buf: Vec<u8>,
    /// Set when the peer's handshake response was processed.
    handshake_done: bool,
}

impl WgPeer {
    /// Create a peer session bound to `sock` (already "connected" to the
    /// peer endpoint on the visitor side; exit side uses recv_from).
    pub fn new(
        sock: Arc<UdpSocket>,
        private_key: x25519_dalek::StaticSecret,
        peer_public_key: x25519_dalek::PublicKey,
        psk: Option<[u8; 32]>,
        index: u32,
    ) -> Self {
        Self {
            tunn: Tunn::new(private_key, peer_public_key, psk, Some(25), index, None),
            peer_addr: std::sync::Mutex::new(None),
            sock,
            send_buf: vec![0u8; 65_535],
            recv_buf: vec![0u8; 65_535],
            handshake_done: false,
        }
    }

    /// Learn the peer endpoint from an inbound datagram (roaming support).
    fn note_peer(&self, addr: std::net::SocketAddr) {
        *self.peer_addr.lock().unwrap() = Some(addr);
    }

    /// Send a WG transport packet to the peer endpoint.
    async fn send_to_peer(&self, pkt: &[u8]) -> Result<(), String> {
        let addr = *self.peer_addr.lock().unwrap();
        match addr {
            Some(a) => self
                .sock
                .send_to(pkt, a)
                .await
                .map(|_| ())
                .map_err(|e| format!("wg udp send_to: {e}")),
            None => self
                .sock
                .send(pkt)
                .await
                .map(|_| ())
                .map_err(|e| format!("wg udp send: {e}")),
        }
    }

    /// True once a handshake completed (stats report a handshake time).
    pub fn is_up(&self) -> bool {
        self.tunn.stats().0.is_some()
    }

    /// Force-send a handshake initiation (first contact).
    pub async fn initiate(&mut self) -> Result<(), String> {
        let mut buf = vec![0u8; 148];
        match self.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(out) => {
                let out = out.to_vec();
                self.send_to_peer(&out).await
            }
            _ => Ok(()),
        }
    }

    /// Drive protocol timers; may emit handshake packets (visitor side
    /// initiates). Call periodically.
    pub async fn tick(&mut self) -> Result<(), String> {
        let mut timer_buf = vec![0u8; 148];
        let result = self.tunn.update_timers(&mut timer_buf);
        match result {
            TunnResult::WriteToNetwork(out) => {
                let out = out.to_vec();
                self.send_to_peer(&out).await
            }
            TunnResult::Err(e) => {
                tracing::debug!(error = ?e, "wg tunn error");
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Encapsulate an inner IP packet and send it over UDP.
    pub async fn send_ip(&mut self, pkt: &[u8]) -> Result<(), String> {
        let outbound = {
            let Self { tunn, send_buf, .. } = self;
            match tunn.encapsulate(pkt, send_buf) {
                TunnResult::WriteToNetwork(out) => Some(out.to_vec()),
                _ => None,
            }
        };
        match outbound {
            Some(out) => self.send_to_peer(&out).await,
            None => Ok(()),
        }
    }

    /// Receive the next inner IP packet from the peer (drives handshake
    /// responses internally). Returns None on timeout.
    pub async fn recv_ip(&mut self, timeout: std::time::Duration) -> Option<Vec<u8>> {
        let mut udp_buf = vec![0u8; 65_535];
        let (len, src_addr) = timeout_at(self.sock.recv_from(&mut udp_buf), timeout).await?;
        self.note_peer(src_addr);
        let outcome = {
            let Self {
                tunn,
                recv_buf,
                handshake_done,
                ..
            } = self;
            // boringtun: after WriteToNetwork (cookie/handshake reply),
            // REPEAT decapsulate with an empty datagram until Done or
            // WriteToTunnel — otherwise the data packet is dropped.
            let mut inner = None;
            let mut outbound = None;
            let mut datagram: Option<&[u8]> = Some(&udp_buf[..len]);
            for round in 0..4 {
                let dec = match datagram.take() {
                    Some(d) => tunn.decapsulate(Some(src_addr.ip()), d, recv_buf),
                    None => tunn.decapsulate(Some(src_addr.ip()), &[], recv_buf),
                };
                eprintln!("[exit-decap] round {round} -> {dec:?}");
                match dec {
                    // Keepalive decapsulates to an empty inner packet — skip
                    // it so callers polling for data keep waiting.
                    TunnResult::WriteToTunnelV4(ref pkt, _src) if pkt.is_empty() => {}
                    TunnResult::WriteToTunnelV6(ref pkt, _src) if pkt.is_empty() => {}
                    TunnResult::WriteToTunnelV4(pkt, _src) => {
                        inner = Some(pkt.to_vec());
                        break;
                    }
                    TunnResult::WriteToTunnelV6(pkt, _src) => {
                        inner = Some(pkt.to_vec());
                        break;
                    }
                    TunnResult::WriteToNetwork(out) => {
                        outbound = Some(out.to_vec());
                    }
                    TunnResult::Done => break,
                    TunnResult::Err(e) => {
                        tracing::debug!(error = ?e, "wg decap error");
                        break;
                    }
                }
            }
            if outbound.is_some() {
                *handshake_done = true;
            }
            (inner, outbound)
        };
        let (inner, outbound) = outcome;
        if let Some(out) = outbound {
            let _ = self.send_to_peer(&out).await;
            return inner;
        }
        inner
    }
}

async fn timeout_at<T, E>(
    fut: impl Future<Output = Result<T, E>>,
    timeout: std::time::Duration,
) -> Option<T> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(value)) => Some(value),
        _ => None,
    }
}
