//! Exit-node wire helpers: destination encoding inside REQ payloads and the
//! MTU/MSS constants (spec 2026-08-26-exit-node-design §2-ADR-3, §5).

/// TUN interface MTU: 1500 − 116 headroom for outer IPv6 + DTLS/SCTP +
/// framing overhead. Avoids visitor-side fragmentation entirely.
pub const EXIT_MTU: u16 = 1384;

/// TCP MSS advertised on the TUN: MTU − 40 (IPv6 header headroom).
pub const EXIT_MSS: u16 = EXIT_MTU - 40;

/// Encode a `host:port` destination as the REQ payload (NUL-terminated).
pub fn encode_dest(dest: &str) -> Vec<u8> {
    let mut out = dest.as_bytes().to_vec();
    out.push(0);
    out
}

/// Parse the destination from a REQ payload. Returns `None` when the payload
/// is empty or not NUL-terminated.
pub fn parse_dest(payload: &[u8]) -> Option<&str> {
    let end = payload.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&payload[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_roundtrip() {
        let enc = encode_dest("1.2.3.4:443");
        assert_eq!(enc, b"1.2.3.4:443\0");
        assert_eq!(parse_dest(&enc), Some("1.2.3.4:443"));
        assert_eq!(parse_dest(b"no-nul"), None);
        assert_eq!(parse_dest(b""), None);
        assert_eq!(parse_dest(b"\0"), None);
    }

    #[test]
    fn mtu_math() {
        assert_eq!(EXIT_MTU, 1384);
        assert_eq!(EXIT_MSS, 1344);
    }
}
