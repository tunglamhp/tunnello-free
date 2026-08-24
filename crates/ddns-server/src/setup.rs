//! One-time setup codes for the "download my client" auto-connect flow.
//!
//! A code (`sc_...`) is a bearer credential bound to (account, token, ports):
//! the client sends it in place of the token secret during the register
//! handshake, the broker resolves it to the real token, and the session binds
//! normally — the raw token secret is never exposed to the download script.
//! Codes are single-use and expire after 7 days. The raw code is generated
//! here and shown only inside the generated download script.

use std::sync::{Arc, MutexGuard};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use crate::token::TokenStore;

/// Setup codes are valid for 7 days — long enough to download and run the
/// generated script, short enough to bound a leaked-code window.
const CODE_TTL_SECS: i64 = 7 * 24 * 3600;

#[derive(Clone)]
pub struct SetupStore {
    inner: Arc<SetupStoreInner>,
}

struct SetupStoreInner {
    store: TokenStore,
}

/// A resolved (consumed) setup code binding.
#[derive(Debug, Clone)]
pub struct SetupCode {
    pub token_id: String,
    pub account_id: i64,
    /// The tunnel profile's ports string (e.g. "8080,22") captured at
    /// generation time, so the script can pass the right --port/--tcp.
    pub ports: String,
}

impl SetupStore {
    pub fn open(ts: &TokenStore) -> Self {
        let db = ts.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        crate::schema::ensure_columns(&db).expect("schema migration");
        Self {
            inner: Arc::new(SetupStoreInner { store: ts.clone() }),
        }
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.inner
            .store
            .db_conn()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Issue a single-use setup code bound to the token + ports string.
    /// Returns the raw `sc_...` code (shown only in the download script).
    pub fn create(&self, account_id: i64, token_id: &str, ports: &str) -> String {
        let raw = format!("sc_{}", random_secret());
        let now = crate::account::unix_now();
        let _ = self.db().execute(
            "INSERT INTO setup_codes(code_hash, account_id, token_id, ports, expires_at, \
             created_at, used_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
            params![
                digest(&raw),
                account_id,
                token_id,
                ports,
                now + CODE_TTL_SECS,
                now
            ],
        );
        raw
    }

    /// Look up a code without consuming it. The register handshake peeks,
    /// runs its gates (token enabled, balance), and only then marks the code
    /// used — a rejected connect must not burn the one-shot code.
    pub fn peek(&self, code: &str) -> Option<SetupCode> {
        let hash = digest(code);
        let db = self.db();
        db.query_row(
            "SELECT token_id, account_id, ports FROM setup_codes \
             WHERE code_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![hash, crate::account::unix_now()],
            |r| {
                Ok(SetupCode {
                    token_id: r.get(0)?,
                    account_id: r.get(1)?,
                    ports: r.get(2)?,
                })
            },
        )
        .ok()
    }

    /// Atomically claim a code (single-use): `true` when this caller won the
    /// claim, `false` when a concurrent connect already consumed it. Call this
    /// only after the token/balance gates pass.
    pub fn consume_claimed(&self, code: &str) -> bool {
        let hash = digest(code);
        let now = crate::account::unix_now();
        // Opportunistic prune of spent/expired codes (bounded by the row count
        // that actually matches).
        let _ = self.db().execute(
            "DELETE FROM setup_codes WHERE used_at IS NOT NULL AND used_at < ?1",
            params![now - 7 * 24 * 3600],
        );
        self.db()
            .execute(
                "UPDATE setup_codes SET used_at = ?1 WHERE code_hash = ?2 AND used_at IS NULL",
                params![now, hash],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }
}

/// base64url sha256 — the at-rest digest for setup codes.
fn digest(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

/// 32 random bytes as base64url (setup-code entropy).
fn random_secret() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenStore;

    #[test]
    fn create_and_consume_once() {
        let ts = TokenStore::new();
        let setup = SetupStore::open(&ts);
        let code = setup.create(7, "t-abc", "8080,22");
        assert!(code.starts_with("sc_"), "code prefix: {code}");
        let c = setup.peek(&code).expect("first peek");
        assert_eq!(c.token_id, "t-abc");
        assert_eq!(c.account_id, 7);
        assert_eq!(c.ports, "8080,22");
        // Peek does not consume: a second peek still works.
        assert!(setup.peek(&code).is_some(), "peek must not consume");
        // consume_claimed is single-use: first call wins, second loses.
        assert!(setup.consume_claimed(&code), "first claim wins");
        assert!(!setup.consume_claimed(&code), "second claim loses");
        assert!(setup.peek(&code).is_none(), "code must be single-use");
        // Unknown code is a miss.
        assert!(setup.peek("sc_nope").is_none());
    }
}
