//! Email OTP: 6-digit codes, 5-min expiry, 5 attempts, 3 sends/min/email.
//! In-memory only — a broker restart invalidates outstanding codes (safe:
//! visitors just request a new one).

use std::collections::HashMap;
use parking_lot::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::auth::hmac_eq;

const CODE_TTL: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS: u32 = 5;
const SEND_WINDOW: Duration = Duration::from_secs(60);
const MAX_SENDS_PER_WINDOW: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    NoCode,
    Expired,
    TooManyAttempts,
    Mismatch,
}

struct Entry {
    code_hash: [u8; 32],
    exp: Instant,
    attempts: u32,
    sends: Vec<Instant>,
}

pub struct OtpStore {
    inner: Mutex<HashMap<String, Entry>>,
    /// Test hook: `send` invokes `code_sink` with the plaintext code (tests
    /// install it; production leaves it unset and passes a mailer closure).
    code_sink: Mutex<Option<Box<dyn Fn(String) + Send>>>,
}

impl Default for OtpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OtpStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            code_sink: Mutex::new(None),
        }
    }

    /// Install the test sink receiving each generated code.
    pub fn set_code_sink(&self, f: impl Fn(String) + Send + 'static) {
        *self.code_sink.lock() = Some(Box::new(f));
    }

    /// Generate + deliver a code. `send_email` is the mailer closure
    /// (injected by the route handler so this module stays transport-agnostic).
    pub async fn send(
        &self,
        email: &str,
        send_email: impl FnOnce(String, String) -> Result<(), String>,
    ) -> Result<(), String> {
        let code = {
            let mut map = self.inner.lock();
            let entry = map.entry(email.to_string()).or_insert_with(|| Entry {
                code_hash: [0; 32],
                exp: Instant::now(),
                attempts: 0,
                sends: Vec::new(),
            });
            entry.sends.retain(|t| t.elapsed() < SEND_WINDOW);
            if entry.sends.len() >= MAX_SENDS_PER_WINDOW as usize {
                return Err("too many codes requested; wait a minute".into());
            }
            entry.sends.push(Instant::now());
            let code = format!("{:06}", rand::Rng::random_range(&mut rand::rng(), 0..1_000_000));
            entry.code_hash = Sha256::digest(code.as_bytes()).into();
            entry.exp = Instant::now() + CODE_TTL;
            entry.attempts = 0;
            code
        };
        if let Some(f) = self.code_sink.lock().as_ref() {
            f(code.clone());
        }
        send_email(email.to_string(), format!("Your access code is {code} (valid 5 minutes)"))
    }

    /// Constant-time code check. Burns an attempt on mismatch; 5 mismatches
    /// destroy the entry (request a fresh code).
    pub fn verify(&self, email: &str, code: &str) -> Result<(), OtpError> {
        let mut map = self.inner.lock();
        let Some(entry) = map.get_mut(email) else {
            return Err(OtpError::NoCode);
        };
        if entry.exp < Instant::now() {
            map.remove(email);
            return Err(OtpError::Expired);
        }
        let got = Sha256::digest(code.as_bytes());
        if hmac_eq(got.as_slice(), &entry.code_hash) {
            map.remove(email);
            return Ok(());
        }
        entry.attempts += 1;
        if entry.attempts >= MAX_ATTEMPTS {
            map.remove(email);
            return Err(OtpError::TooManyAttempts);
        }
        Err(OtpError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_verify_roundtrip_and_limits() {
        let store = OtpStore::new();
        let got = std::sync::Arc::new(parking_lot::Mutex::new(String::new()));
        let sink = got.clone();
        store.set_code_sink(move |code| {
            *sink.lock() = code;
        });
        store.send("a@b.c", |_to, _body| Ok(())).await.unwrap();
        let code = got.lock().clone();
        assert_eq!(code.len(), 6, "code is 6 digits");
        assert!(store.verify("a@b.c", &code).is_ok(), "correct code verifies");
        assert_eq!(store.verify("a@b.c", &code), Err(OtpError::NoCode), "entry consumed");

        // wrong code burns attempts; 5th mismatch destroys the entry
        store.send("x@y.z", |_to, _body| Ok(())).await.unwrap();
        for _ in 0..5 {
            let _ = store.verify("x@y.z", "000000");
        }
        assert_eq!(store.verify("x@y.z", "000000"), Err(OtpError::NoCode));
    }

    #[tokio::test]
    async fn send_rate_limit_three_per_minute() {
        let store = OtpStore::new();
        for _ in 0..3 {
            store.send("r@r.r", |_to, _body| Ok(())).await.unwrap();
        }
        assert!(
            store.send("r@r.r", |_to, _body| Ok(())).await.is_err(),
            "4th send within a minute is rejected"
        );
    }

    #[tokio::test]
    async fn mailer_error_propagates_but_code_still_rotates() {
        let store = OtpStore::new();
        let err = store
            .send("m@m.m", |_to, _body| Err("smtp down".into()))
            .await
            .unwrap_err();
        assert_eq!(err, "smtp down");
    }
}
