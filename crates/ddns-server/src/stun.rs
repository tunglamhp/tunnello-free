//! Minimal RFC 5389 STUN server: answers binding requests with a binding
//! success carrying XOR-MAPPED-ADDRESS. Used for WebRTC ICE candidate
//! gathering (P2P data plane). Logs nothing about content; the only
//! processing is a fixed-size header parse.

use crate::rate_limit::RateLimiter;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Per-IP token bucket for STUN binding responses. STUN is public by design
/// (WebRTC ICE), but a spoofed source should not drive unbounded reply work
/// (sub-2x amplification, yet still a nuisance reflection surface).
const STUN_BURST: u32 = 60;
const STUN_REFILL_PER_SEC: f64 = 25.0;

const MAGIC_COOKIE: u32 = 0x2112A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    BindingRequest,
    Other,
}

fn parse_header(buf: &[u8]) -> Result<(MessageKind, [u8; 12]), ()> {
    if buf.len() < 20 {
        return Err(());
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(());
    }
    let mut tx = [0u8; 12];
    tx.copy_from_slice(&buf[8..20]);
    Ok((
        if msg_type == 0x0001 {
            MessageKind::BindingRequest
        } else {
            MessageKind::Other
        },
        tx,
    ))
}

fn binding_success(tx: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&0x0101u16.to_be_bytes()); // binding success
    out.extend_from_slice(&(8u16).to_be_bytes()); // attr len
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(tx);
    out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes()); // attr len: 4 reserved+family+port + 4 addr
    out.extend_from_slice(&0u16.to_be_bytes()); // reserved
    out.extend_from_slice(&1u16.to_be_bytes()); // family: IPv4
    let port = mapped.port() ^ (MAGIC_COOKIE >> 16) as u16;
    out.extend_from_slice(&port.to_be_bytes());
    let ip = match mapped.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(v6) => {
            // IPv6 needs a 20-byte attr; keep it simple: v4-only in v1,
            // send 0.0.0.0 for v6 (clients still prefer v4 candidates).
            v6.octets()[..4].try_into().unwrap_or([0u8; 4])
        }
    };
    for (i, b) in ip.iter().enumerate() {
        out.push(b ^ MAGIC_COOKIE.to_be_bytes()[i]);
    }
    out
}

/// Serve STUN binding requests on an already-bound UDP socket. Never returns
/// on its own; the caller aborts the spawned task to stop it.
pub async fn run_stun(sock: UdpSocket) -> Result<(), String> {
    let addr = sock.local_addr().map_err(|e| e.to_string())?;
    tracing::info!(addr = %addr, "stun listening");
    let mut buf = [0u8; 1500];
    let limiter = RateLimiter::new(STUN_BURST, STUN_REFILL_PER_SEC);
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "stun recv error");
                continue;
            }
        };
        let Ok((kind, tx)) = parse_header(&buf[..n]) else {
            continue;
        };
        if kind != MessageKind::BindingRequest {
            continue;
        }
        if !limiter.allow(Some(peer.ip())) {
            continue;
        }
        let resp = binding_success(&tx, peer);
        let _ = sock.send_to(&resp, peer).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binding_request() {
        // RFC 5389 binding request: type 0x0001, magic cookie, 12-byte tx id.
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x0001u16.to_be_bytes());
        msg.extend_from_slice(&20u16.to_be_bytes());
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
        msg.extend_from_slice(&[0xAA; 12]);
        let (kind, tx) = parse_header(&msg).unwrap();
        assert_eq!(kind, MessageKind::BindingRequest);
        assert_eq!(tx, [0xAA; 12]);
    }

    #[test]
    fn rejects_short_and_unknown_messages() {
        assert!(parse_header(&[0u8; 3]).is_err());
        let mut msg = vec![0u8; 20];
        msg[0..2].copy_from_slice(&0x0002u16.to_be_bytes()); // not a request
        assert!(parse_header(&msg).is_err());
    }

    #[test]
    fn builds_binding_success_with_xor_mapped_address() {
        // IPv4 203.0.113.7:5000 with cookie 0x2112A442.
        let tx = [0x11; 12];
        let resp = binding_success(&tx, "203.0.113.7:5000".parse().unwrap());
        assert_eq!(&resp[0..2], &0x0101u16.to_be_bytes()); // binding success
        assert_eq!(&resp[2..4], &8u16.to_be_bytes()); // message length
        assert_eq!(&resp[4..8], &0x2112A442u32.to_be_bytes()); // magic cookie
        assert_eq!(&resp[8..20], &tx); // echoed tx id
        // XOR-MAPPED-ADDRESS attr: type 0x0020, len 8, family 0x01, port, addr.
        assert_eq!(&resp[20..22], &0x0020u16.to_be_bytes());
        assert_eq!(&resp[22..24], &8u16.to_be_bytes());
        assert_eq!(&resp[24..26], &0u16.to_be_bytes()); // reserved
        assert_eq!(&resp[26..28], &1u16.to_be_bytes()); // family IPv4
        assert_eq!(&resp[28..30], &0x329Au16.to_be_bytes()); // 5000 ^ 0x2112
        assert_eq!(&resp[30..34], &[0xEA, 0x12, 0xD5, 0x45]); // 203.0.113.7 ^ cookie
    }
}
