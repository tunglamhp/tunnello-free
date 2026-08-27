//! Visitor WireGuard key-age tracking (spec 2026-08-26-exit-node-wireguard
//! §3.Broker): every registered visitor WG pubkey is recorded at first sight;
//! after `max_age_days` the key is treated as expired and signaling fails
//! with `key_expired` until the visitor re-registers a fresh keypair.
//!
//! In-memory only — a broker restart resets the clock (safe: keys re-register
//! on the next `ddns up`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const DAY_SECS: i64 = 86_400;

static STORE: OnceLock<KeyAgeStore> = OnceLock::new();

/// Process-wide store (180-day default policy). Initialized once at broker
/// start; `key_age()` is safe to call from any handler afterwards.
pub fn init_key_age(max_age_days: u64) {
    let _ = STORE.set(KeyAgeStore::new(max_age_days));
}

/// Panics if called before [`init_key_age`] — a programming error, not a
/// runtime path.
pub fn key_age() -> &'static KeyAgeStore {
    STORE.get().expect("key-age store not initialized")
}

pub struct KeyAgeStore {
    issued_at: Mutex<HashMap<String, i64>>,
    max_age_days: u64,
}

impl KeyAgeStore {
    pub fn new(max_age_days: u64) -> Self {
        Self {
            issued_at: Mutex::new(HashMap::new()),
            max_age_days,
        }
    }

    /// Record the first sighting of a pubkey. Later hellos with the same key
    /// do NOT refresh the clock (spec §3.Broker: "recorded at first sight"),
    /// so a stale key can never extend its own lifetime by re-registering.
    pub fn record(&self, pubkey_b64: &str, now_unix: i64) {
        self.issued_at
            .lock()
            .unwrap()
            .entry(pubkey_b64.to_string())
            .or_insert(now_unix);
    }

    /// True when the key is unknown OR older than the max age.
    /// Lazy sweep: stale entries are dropped from the store as they are
    /// observed, bounding growth to keys seen within the policy window.
    pub fn expired(&self, pubkey_b64: &str, now_unix: i64) -> bool {
        let mut map = self.issued_at.lock().unwrap();
        let cutoff = now_unix - self.max_age_days as i64 * DAY_SECS;
        map.retain(|_, t| *t >= cutoff);
        match map.get(pubkey_b64) {
            None => true,
            Some(t) => now_unix - *t >= self.max_age_days as i64 * DAY_SECS,
        }
    }

    /// Drop a key record (peer removed / key rotated).
    pub fn remove(&self, pubkey_b64: &str) {
        self.issued_at.lock().unwrap().remove(pubkey_b64);
    }

    /// Number of tracked keys (metrics).
    pub fn len(&self) -> usize {
        self.issued_at.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.issued_at.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_boundary() {
        let store = KeyAgeStore::new(180);
        store.record("k", 1_000_000);
        assert!(!store.expired("k", 1_000_000 + 180 * 86_400 - 1));
        assert!(store.expired("k", 1_000_000 + 180 * 86_400));
        store.remove("k");
        assert!(store.expired("k", 1_000_000), "unknown key = treat expired");
    }

    #[test]
    fn record_keeps_first_sighting() {
        let store = KeyAgeStore::new(1);
        store.record("k", 0);
        store.record("k", 86_400); // re-hello must NOT refresh the clock
        assert!(
            store.expired("k", 86_400 + 3_600),
            "first sighting wins: key is 1 day+ old → expired"
        );
    }

    #[test]
    fn expired_sweeps_stale_keys() {
        let store = KeyAgeStore::new(1);
        store.record("fresh", 86_400);
        store.record("stale", 0);
        assert!(store.expired("stale", 86_400 + 3_600));
        assert_eq!(store.len(), 1, "stale key swept on expiry check");
        assert!(!store.expired("fresh", 86_400 + 3_600));
    }

    #[test]
    fn len_and_empty() {
        let store = KeyAgeStore::new(180);
        assert!(store.is_empty());
        store.record("a", 1);
        store.record("b", 1);
        assert_eq!(store.len(), 2);
    }
}
