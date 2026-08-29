//! Signed visitor-auth cookie (`email|exp`, HMAC-SHA256) + redirect-target
//! validation shared by the OIDC and OTP gates. Stateless: no server-side
//! session store; expiry rides inside the signed payload.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::{hmac_eq, now_unix};

pub struct VisitorAuthCookie;

impl VisitorAuthCookie {
    /// Cookie value: `base64url(email|exp).base64url(hmac(payload))`.
    // `()` error mirrors the broker's HMAC helpers; callers map it to a 500.
    #[allow(clippy::result_unit_err)]
    pub fn issue(server_secret: &[u8], email: &str, ttl_secs: u64) -> Result<String, ()> {
        let exp = now_unix().saturating_add(ttl_secs).to_string();
        let payload = format!("{email}|{exp}");
        let enc = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let tag = Self::tag(server_secret, enc.as_bytes())?;
        Ok(format!("{enc}.{tag}"))
    }

    /// Returns the authenticated email, or `None` (bad tag / expired).
    pub fn verify(cookie: &str, server_secret: &[u8]) -> Option<String> {
        let (enc, tag) = cookie.split_once('.')?;
        let Ok(expected) = Self::tag(server_secret, enc.as_bytes()) else {
            return None;
        };
        if !hmac_eq(expected.as_bytes(), tag.as_bytes()) {
            return None;
        }
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(enc).ok()?).ok()?;
        let (email, exp) = payload.rsplit_once('|')?;
        if exp.parse::<u64>().ok()? <= now_unix() || email.is_empty() {
            return None;
        }
        Some(email.to_string())
    }

    fn tag(server_secret: &[u8], payload: &[u8]) -> Result<String, ()> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_secret).map_err(|_| ())?;
        mac.update(payload);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

/// Only same-origin relative paths survive; everything else falls back to `/`.
pub fn safe_back(back: Option<&str>) -> String {
    match back {
        Some(b) if b.starts_with('/') && !b.starts_with("//") => b.to_string(),
        _ => "/".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_roundtrip_and_expiry() {
        let secret = vec![b'k'; 32];
        let c = VisitorAuthCookie::issue(&secret, "a@b.c", 3600).unwrap();
        assert_eq!(
            VisitorAuthCookie::verify(&c, &secret).as_deref(),
            Some("a@b.c")
        );
        let expired = VisitorAuthCookie::issue(&secret, "a@b.c", 0).unwrap();
        assert_eq!(VisitorAuthCookie::verify(&expired, &secret), None);
        assert_eq!(VisitorAuthCookie::verify(&c, b"other"), None);
        let tampered = format!("garbage.{}", c.split_once('.').unwrap().1);
        assert_eq!(VisitorAuthCookie::verify(&tampered, &secret), None);
    }

    #[test]
    fn safe_back_blocks_open_redirects() {
        assert_eq!(safe_back(Some("/x")), "/x");
        assert_eq!(safe_back(Some("/a?b=c")), "/a?b=c");
        assert_eq!(safe_back(Some("//evil.com")), "/");
        assert_eq!(safe_back(Some("https://evil.com")), "/");
        assert_eq!(safe_back(Some("javascript:alert(1)")), "/");
        assert_eq!(safe_back(None), "/");
    }
}
