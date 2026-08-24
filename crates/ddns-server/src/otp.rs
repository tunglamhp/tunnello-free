//! Time-based one-time passwords (RFC 6238) for operator two-factor auth,
//! plus the hand-rolled RFC 4648 base32 codec (no padding) used to store the
//! shared secret as text.
//!
//! The default RFC 6238 parameters are used: HMAC-SHA1, a 30-second time
//! step, and 6-digit codes (dynamic truncation, mod 1_000_000).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

/// RFC 4648 base32 alphabet (`A-Z`, `2-7`).
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Seconds per TOTP time step (RFC 6238 default).
const TIME_STEP: u64 = 30;

/// Number of digits in a code (6-digit convention).
const CODE_MOD: u32 = 1_000_000;

/// Encode `data` as RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(buffer >> bits) as usize & 0x1F] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(buffer << (5 - bits)) as usize & 0x1F] as char);
    }
    out
}

/// Decode RFC 4648 base32 (`A-Z`, `2-7`), case-insensitive, with or without
/// trailing `=` padding. Returns `None` on any character outside the
/// alphabet (other than `=`), so a corrupt secret can never yield a code.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        if c == '=' {
            break; // padding marks the end; trailing bits are ignored
        }
        let idx = ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_uppercase() as u8)?;
        buffer = (buffer << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Generate a fresh 20-byte shared secret, base32-encoded for storage/QR.
pub fn totp_generate_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::rng().fill_bytes(&mut bytes);
    base32_encode(&bytes)
}

/// The 6-digit TOTP code for `secret` at `now_unix` (seconds since epoch).
///
/// A secret that does not decode to base32 yields an empty string, which can
/// never match a valid code — login/verify treat that as a failed check.
pub fn totp_code(secret: &str, now_unix: u64) -> String {
    totp_code_opt(secret, now_unix).unwrap_or_default()
}

/// Same as [`totp_code`], but `None` on an undecodable secret (so callers can
/// distinguish "no code" from "code is 000000", though in practice both fail).
fn totp_code_opt(secret: &str, now_unix: u64) -> Option<String> {
    let key = base32_decode(secret)?;
    let counter = now_unix / TIME_STEP;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 §5.3): offset = low 4 bits of the last
    // byte; take 4 bytes, mask the MSB, interpret as a 31-bit integer.
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    let binary = ((digest[offset] & 0x7F) as u32) << 24
        | (digest[offset + 1] as u32) << 16
        | (digest[offset + 2] as u32) << 8
        | digest[offset + 3] as u32;
    Some(format!("{:06}", binary % CODE_MOD))
}

/// Verify `code` against `secret` at `now_unix`, accepting the current time
/// step and one step either side (±1 window) to absorb clock skew.
pub fn totp_verify(secret: &str, code: &str, now_unix: u64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = now_unix / TIME_STEP;
    // No early return: every step in the ±1 window is computed and compared,
    // and each compare is constant-time, so the result does not leak how many
    // leading digits matched.
    let mut matched = false;
    for s in step.saturating_sub(1)..=step + 1 {
        matched |= code_eq(
            totp_code_opt(secret, s * TIME_STEP)
                .as_deref()
                .unwrap_or(""),
            code,
        );
    }
    matched
}

/// Constant-time equality over the full 6 code digits (XOR-fold, no
/// short-circuit). Both sides are always 6 ASCII digits in practice; a
/// length mismatch (undecodable secret) simply cannot match.
fn code_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != 6 || b.len() != 6 {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..6 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// Build the `otpauth://` provisioning URI an authenticator app scans.
///
/// RFC 3986 percent-encoding is applied to the label and issuer components;
/// the secret is already base32 (unreserved).
pub fn totp_uri(issuer: &str, account: &str, secret: &str) -> String {
    fn pct(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        pct(issuer),
        pct(account),
        secret,
        pct(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trips() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"12345678901234567890",
        ] {
            assert_eq!(base32_decode(&base32_encode(data)).unwrap(), data);
        }
    }

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 §10 test vectors (no padding).
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        // Padded forms decode identically.
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(base32_decode("mzxw6===").unwrap(), b"foo");
    }

    #[test]
    fn base32_rejects_invalid_chars() {
        assert!(base32_decode("MZXW6!").is_none());
        assert!(base32_decode("MZXW61").is_none()); // '1' is not in the alphabet
        assert!(base32_decode("MZXW68").is_none()); // '8' is not in the alphabet
    }

    #[test]
    fn totp_rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B: secret "12345678901234567890" (ASCII), SHA1.
        // 8-digit reference values are 94287082 / 07081804 / 14050471 /
        // 89005924 / 69279037 / 65353130; the 6-digit convention is the
        // dynamic-truncation value `mod 1_000_000` (the last six digits of
        // the 8-digit value). Values below were computed from the algorithm,
        // not copied from the brief: t=1234567890 → 005924 (the brief's
        // "050471" is actually t=1111111111's code).
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 of the ASCII secret
        let cases = [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];
        for (t, expected) in cases {
            assert_eq!(totp_code(secret, t), expected, "t={t}");
        }
    }

    #[test]
    fn totp_verify_accepts_window() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let t = 59;
        let code = totp_code(secret, t);
        assert!(totp_verify(secret, &code, t));
        assert!(totp_verify(secret, &code, t + 29)); // same step
        assert!(totp_verify(secret, &code, t + 1)); // same step (step 1)
        // A code from step-1 verifies at t-30 (its own step) but not t+60.
        let prev = totp_code(secret, t.saturating_sub(30));
        assert!(totp_verify(secret, &prev, t - 30));
        assert!(!totp_verify(secret, &prev, t + 60));
        // Malformed / wrong-length codes always fail.
        assert!(!totp_verify(secret, "12345", t));
        assert!(!totp_verify(secret, "abcdef", t));
        assert!(!totp_verify(secret, "", t));
    }

    #[test]
    fn totp_invalid_secret_yields_no_code() {
        assert_eq!(totp_code("not-base32!", 59), "");
        assert!(!totp_verify("not-base32!", "287082", 59));
    }

    #[test]
    fn totp_uri_percent_encodes_components() {
        let uri = totp_uri("Acme Tunnels", "operator@example.com", "GEZDGNBV");
        assert_eq!(
            uri,
            "otpauth://totp/Acme%20Tunnels:operator%40example.com?secret=GEZDGNBV&issuer=Acme%20Tunnels"
        );
    }
}
