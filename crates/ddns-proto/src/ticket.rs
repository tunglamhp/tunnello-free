//! One-time, short-TTL capability for a P2P visitor to join a client's
//! WebRTC peer. Issued by the broker (per-session secret), verified by the
//! client. Format: base64url(ts_be8 ‖ nonce12) "." hex(HMAC-SHA256(secret, ts ‖ nonce ‖ subdomain)).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

pub const TICKET_TTL_SECS: i64 = 60;
/// Upper bound on accepted clock skew: a ticket stamped more than this far
/// in the future is rejected (defense-in-depth — only the broker mints
/// tickets, but a rotated secret or skewed client clock must not keep old
/// tickets verifiable indefinitely).
pub const TICKET_FUTURE_SKEW_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    Malformed,
    Expired { age_secs: i64 },
    BadMac,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TicketError::Malformed => write!(f, "malformed ticket"),
            TicketError::Expired { age_secs } => write!(f, "ticket expired {age_secs}s ago"),
            // The subdomain is inside the HMAC payload, so a ticket for
            // another subdomain fails as BadMac — there is no separate
            // WrongSubdomain variant.
            TicketError::BadMac => write!(f, "ticket signature mismatch"),
        }
    }
}

const NONCE_LEN: usize = 12;
const TS_LEN: usize = 8;

fn hmac(secret: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac accepts any key len");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

pub fn issue_ticket(secret: &[u8], subdomain: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    issue_ticket_at(secret, subdomain, now)
}

/// Deterministic variant for tests: the timestamp is explicit instead of
/// wall-clock.
pub fn issue_ticket_at(secret: &[u8], subdomain: &str, now: i64) -> String {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce);
    let mut body = Vec::with_capacity(TS_LEN + NONCE_LEN);
    body.extend_from_slice(&now.to_be_bytes());
    body.extend_from_slice(&nonce);
    let tag = hmac(secret, &[&body[..], subdomain.as_bytes()].concat());
    let mut tag_hex = String::with_capacity(tag.len() * 2);
    for b in tag {
        use std::fmt::Write;
        write!(&mut tag_hex, "{b:02x}").unwrap();
    }
    format!("{}.{tag_hex}", URL_SAFE_NO_PAD.encode(&body))
}

pub fn verify_ticket(
    secret: &[u8],
    subdomain: &str,
    ticket: &str,
    now: i64,
) -> Result<(), TicketError> {
    let (body_b64, tag_hex) = ticket.split_once('.').ok_or(TicketError::Malformed)?;
    let body = URL_SAFE_NO_PAD
        .decode(body_b64)
        .map_err(|_| TicketError::Malformed)?;
    if body.len() != TS_LEN + NONCE_LEN {
        return Err(TicketError::Malformed);
    }
    let expected = hmac(secret, &[&body[..], subdomain.as_bytes()].concat());
    let mut expected_hex = String::with_capacity(expected.len() * 2);
    for b in expected {
        use std::fmt::Write;
        write!(&mut expected_hex, "{b:02x}").unwrap();
    }
    // Constant-time comparison of the hex tags.
    if !crate::ct_eq(tag_hex.as_bytes(), expected_hex.as_bytes()) {
        return Err(TicketError::BadMac);
    }
    let mut ts_bytes = [0u8; TS_LEN];
    ts_bytes.copy_from_slice(&body[..TS_LEN]);
    let ts = i64::from_be_bytes(ts_bytes);
    let age = now - ts;
    if !(-TICKET_FUTURE_SKEW_SECS..=TICKET_TTL_SECS).contains(&age) {
        return Err(TicketError::Expired { age_secs: age });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_round_trip() {
        let secret = [7u8; 32];
        let t = issue_ticket_at(&secret, "vivid-otter-72", 1_700_000_000);
        assert!(verify_ticket(&secret, "vivid-otter-72", &t, 1_700_000_000).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_subdomain() {
        // The subdomain is bound into the HMAC, so a different subdomain is a
        // signature failure (BadMac), not a distinct error.
        let t = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(matches!(
            verify_ticket(&[7u8; 32], "other-slug", &t, 1_700_000_000),
            Err(TicketError::BadMac)
        ));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let t = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(matches!(
            verify_ticket(&[8u8; 32], "vivid-otter-72", &t, 1_700_000_000),
            Err(TicketError::BadMac)
        ));
    }

    #[test]
    fn verify_rejects_expired() {
        let t = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(matches!(
            verify_ticket(
                &[7u8; 32],
                "vivid-otter-72",
                &t,
                1_700_000_000 + TICKET_TTL_SECS + 1
            ),
            Err(TicketError::Expired { .. })
        ));
    }

    #[test]
    fn verify_accepts_at_ttl_boundary() {
        let t = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(
            verify_ticket(
                &[7u8; 32],
                "vivid-otter-72",
                &t,
                1_700_000_000 + TICKET_TTL_SECS
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_rejects_garbage() {
        assert!(matches!(
            verify_ticket(&[7u8; 32], "s", "not-a-ticket", 1_700_000_000),
            Err(TicketError::Malformed)
        ));
        assert!(matches!(
            verify_ticket(&[7u8; 32], "s", "AAAA.AAAA", 1_700_000_000),
            Err(TicketError::Malformed)
        ));
    }

    #[test]
    fn ticket_is_deterministic_only_with_nonce() {
        // Two issues differ (random nonce); both verify.
        let a = issue_ticket_at(&[1u8; 32], "s", 1_700_000_000);
        let b = issue_ticket_at(&[1u8; 32], "s", 1_700_000_000);
        assert_ne!(a, b);
        assert!(verify_ticket(&[1u8; 32], "s", &a, 1_700_000_000).is_ok());
        assert!(verify_ticket(&[1u8; 32], "s", &b, 1_700_000_000).is_ok());
    }

    #[test]
    fn wall_clock_issue_verifies_immediately() {
        // Smoke test for the wall-clock wrapper: a ticket issued now verifies
        // a moment later.
        let t = issue_ticket(&[1u8; 32], "s");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        assert!(verify_ticket(&[1u8; 32], "s", &t, now + 5).is_ok());
    }

    #[test]
    fn verify_rejects_future_dated_beyond_skew() {
        // 2 minutes in the future exceeds the 60 s skew bound.
        let t = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(matches!(
            verify_ticket(
                &[7u8; 32],
                "vivid-otter-72",
                &t,
                1_700_000_000 - TICKET_FUTURE_SKEW_SECS - 1
            ),
            Err(TicketError::Expired { .. })
        ));
        // Small future skew (30 s) still verifies.
        let t2 = issue_ticket_at(&[7u8; 32], "vivid-otter-72", 1_700_000_000);
        assert!(verify_ticket(&[7u8; 32], "vivid-otter-72", &t2, 1_700_000_000 - 30).is_ok());
    }
}
