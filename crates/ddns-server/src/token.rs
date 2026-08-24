//! SQLite + argon2 token store (spec §6). Plan 3 replaces the Plan 2
//! in-memory DashMap store. Tokens are validated by re-verifying their
//! argon2id hash (hashes are not lookup keys); the cache below makes the
//! common paths (list, validate) DB-free between mutations.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ddns_proto::TokenLimits;
use ddns_proto::random_slug;
use rand::RngCore as _;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    /// Owning account id (NULL = legacy/operatorless token, exempt from
    /// plan entitlement).
    pub owner_id: Option<i64>,
    pub limits: TokenLimits,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
struct CachedToken {
    record: TokenRecord,
    hash: String,
    /// `sha256(raw secret)` (base64url). `None` for pre-migration rows whose
    /// secret was never recoverable (they must be re-created).
    digest: Option<String>,
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("password hashing: {0}")]
    Argon2(String),
    #[error("store poisoned")]
    Poisoned,
    #[error("blocking task failed: {0}")]
    Join(String),
    #[error("{0}")]
    Validation(String),
    #[error("in use: {0}")]
    InUse(String),
    #[error("{0}")]
    Quota(String),
}

impl From<argon2::password_hash::Error> for StoreError {
    fn from(e: argon2::password_hash::Error) -> Self {
        StoreError::Argon2(e.to_string())
    }
}

#[derive(Clone)]
pub struct TokenStore {
    inner: Arc<TokenStoreInner>,
}

impl fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self
            .inner
            .cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len();
        f.debug_struct("TokenStore").field("tokens", &n).finish()
    }
}

struct TokenStoreInner {
    db: Mutex<Connection>,
    cache: RwLock<HashMap<String, CachedToken>>,
    /// `sha256(raw secret)` → token id. Lets `validate` reject an unknown
    /// secret in O(1) without touching argon2 (secrets are 160-bit entropy,
    /// so the digest leaks nothing useful at rest).
    secret_index: RwLock<HashMap<String, String>>,
    secret_cache: RwLock<Option<Vec<u8>>>,
    /// Argon2 verifies performed by `validate` (test observability: proves the
    /// fast-index miss path performs zero argon2 work).
    argon2_verifies: AtomicU64,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        Self::init(conn)
    }
    /// Shared SQLite connection used by all stores (tokens, domains, tunnels).
    /// Hidden: stores are the intended accessors; integration tests use it
    /// directly to assert schema.
    #[doc(hidden)]
    pub fn db_conn(&self) -> &Mutex<Connection> {
        &self.inner.db
    }

    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;",
        )?;
        Ok(Self::init(conn))
    }

    fn init(conn: Connection) -> Self {
        conn.execute_batch(crate::schema::SCHEMA).expect("schema");
        // Add any columns introduced after the DB was first created (e.g.
        // `secret_digest`) before the cache reload reads them.
        crate::schema::ensure_columns(&conn).expect("schema migration");
        let store = Self {
            inner: Arc::new(TokenStoreInner {
                db: Mutex::new(conn),
                cache: RwLock::new(HashMap::new()),
                secret_index: RwLock::new(HashMap::new()),
                secret_cache: RwLock::new(None),
                argon2_verifies: AtomicU64::new(0),
            }),
        };
        store.reload_cache_sync();
        store
    }

    fn reload_cache_sync(&self) {
        let rows: Vec<CachedToken> = {
            let inner = &*self.inner;
            let guard = inner.db.lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard
                .prepare(
                    "SELECT id, name, secret_hash, owner_id, max_sessions, max_streams, \
                     max_bytes, ttl_secs, enabled, created_at, secret_digest FROM tokens",
                )
                .expect("prepare");
            stmt.query_map([], |r| {
                Ok(CachedToken {
                    record: TokenRecord {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        owner_id: r.get(3)?,
                        limits: TokenLimits {
                            max_sessions: r.get::<_, i64>(4)? as u32,
                            max_streams: r.get::<_, i64>(5)? as u32,
                            max_bytes: r.get::<_, i64>(6)? as u64,
                            ttl_secs: r.get::<_, i64>(7)? as u64,
                            ..TokenLimits::default()
                        },
                        enabled: r.get::<_, i64>(8)? != 0,
                        created_at: r.get(9)?,
                    },
                    hash: r.get(2)?,
                    digest: r.get(10)?,
                })
            })
            .expect("query")
            .filter_map(|r| r.ok())
            .collect()
        };
        let mut cache = self.inner.cache.write().unwrap_or_else(|p| p.into_inner());
        let mut index = self
            .inner
            .secret_index
            .write()
            .unwrap_or_else(|p| p.into_inner());
        cache.clear();
        index.clear();
        for t in rows {
            if let Some(digest) = &t.digest {
                index.insert(digest.clone(), t.record.id.clone());
            }
            cache.insert(t.record.id.clone(), t);
        }
    }

    fn hash_secret(secret: &str) -> Result<String, StoreError> {
        let mut salt_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut salt_bytes);
        let salt =
            SaltString::encode_b64(&salt_bytes).map_err(|e| StoreError::Argon2(e.to_string()))?;
        Ok(Argon2::default()
            .hash_password(secret.as_bytes(), &salt)?
            .to_string())
    }

    fn verify_secret(secret: &str, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok()
    }

    /// `sha256(raw secret)` as base64url. The fast-index key; secrets are
    /// high-entropy (24 random bytes → 192 bits), so the digest is safe to
    /// persist and cannot be used to recover the secret.
    fn secret_digest(secret: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
    }

    fn write_token_sync(
        &self,
        record: &TokenRecord,
        hash: &str,
        digest: &str,
    ) -> Result<(), StoreError> {
        let guard = self.inner.db.lock().unwrap_or_else(|p| p.into_inner());
        guard.execute(
            "INSERT OR REPLACE INTO tokens(\
                 id, name, secret_hash, owner_id, max_sessions, max_streams, \
                 max_bytes, ttl_secs, enabled, created_at, secret_digest\
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                record.id,
                record.name,
                hash,
                record.owner_id,
                record.limits.max_sessions as i64,
                record.limits.max_streams as i64,
                record.limits.max_bytes as i64,
                record.limits.ttl_secs as i64,
                record.enabled as i64,
                record.created_at,
                digest,
            ],
        )?;
        Ok(())
    }

    /// Run a DB-touching closure off the async runtime; a JoinError (the
    /// blocking task panicked) surfaces as `StoreError::Join` instead of
    /// panicking the calling task.
    async fn spawn_result<T>(
        f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Insert with a caller-chosen secret, hashing it. Test convenience and
    /// the Plan 2 test surface; production creation goes through `create`.
    pub async fn insert(&self, secret: String, record: TokenRecord) -> Result<(), StoreError> {
        let store = self.clone();
        Self::spawn_result(move || {
            let hash = Self::hash_secret(&secret)?;
            let digest = Self::secret_digest(&secret);
            store.write_token_sync(&record, &hash, &digest)?;
            store.reload_cache_sync();
            Ok(())
        })
        .await
    }

    /// Create a token: random id + tok_ secret, argon2id-hashed. The secret
    /// is returned once and never stored in recoverable form. Ownerless
    /// (legacy/operator) tokens are exempt from plan entitlement.
    pub async fn create(
        &self,
        name: &str,
        limits: TokenLimits,
    ) -> Result<(String, String), StoreError> {
        self.create_owned(name, limits, None).await
    }

    pub async fn create_owned(
        &self,
        name: &str,
        limits: TokenLimits,
        owner_id: Option<i64>,
    ) -> Result<(String, String), StoreError> {
        let id = format!("t-{}", random_slug(&mut rand::rng()));
        let secret = new_secret();
        let record = TokenRecord {
            id: id.clone(),
            name: name.to_string(),
            owner_id,
            limits,
            enabled: true,
            created_at: now_unix(),
        };
        let store = self.clone();
        let secret2 = secret.clone();
        Self::spawn_result(move || {
            let hash = Self::hash_secret(&secret2)?;
            let digest = Self::secret_digest(&secret2);
            store.write_token_sync(&record, &hash, &digest)?;
            store.reload_cache_sync();
            Ok(())
        })
        .await?;
        Ok((id, secret))
    }

    /// Validate a presented secret. An unknown secret is rejected in O(1)
    /// from the `sha256(secret)` index with **no argon2 work**; a known secret
    /// still runs one argon2 verify against that token's hash (defense in
    /// depth) and re-reads `enabled` after the match so a revocation that
    /// commits mid-verify still wins.
    ///
    /// Legacy rows (created before the digest column existed) have a `NULL`
    /// digest and cannot be indexed (the raw secret is unrecoverable). An
    /// index miss falls back to the old argon2 scan over **only** those legacy
    /// rows, so existing tokens keep validating across an upgrade; the slow
    /// path shrinks as legacy tokens are re-created.
    pub async fn validate(&self, secret: &str) -> Option<TokenRecord> {
        let inner = self.inner.clone();
        let token_id = {
            let index = inner.secret_index.read().unwrap_or_else(|p| p.into_inner());
            index.get(&Self::secret_digest(secret)).cloned()
        };
        if let Some(token_id) = token_id {
            // Fast path: snapshot the one candidate hash, dropping the lock
            // before argon2.
            let hash = inner
                .cache
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get(&token_id)
                .map(|t| t.hash.clone())?;
            let secret = secret.to_string();
            return tokio::task::spawn_blocking(move || {
                inner.argon2_verifies.fetch_add(1, Ordering::Relaxed);
                if !Self::verify_secret(&secret, &hash) {
                    return None;
                }
                let cache = inner.cache.read().unwrap_or_else(|p| p.into_inner());
                let enabled = cache
                    .get(&token_id)
                    .map(|c| c.record.enabled)
                    .unwrap_or(false);
                enabled.then(|| cache.get(&token_id).unwrap().record.clone())
            })
            .await
            .ok()
            .flatten();
        }

        // Index miss: scan only legacy (NULL-digest) rows. When there are none
        // (the common case), reject in O(1) with zero argon2 work.
        let legacy: Vec<CachedToken> = inner
            .cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|t| t.digest.is_none())
            .cloned()
            .collect();
        if legacy.is_empty() {
            return None;
        }
        let secret = secret.to_string();
        tokio::task::spawn_blocking(move || {
            for t in &legacy {
                inner.argon2_verifies.fetch_add(1, Ordering::Relaxed);
                if Self::verify_secret(&secret, &t.hash) {
                    let cache = inner.cache.read().unwrap_or_else(|p| p.into_inner());
                    let enabled = cache
                        .get(&t.record.id)
                        .map(|c| c.record.enabled)
                        .unwrap_or(false);
                    return enabled.then(|| t.record.clone());
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    pub async fn list(&self) -> Vec<TokenRecord> {
        self.inner
            .cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|t| t.record.clone())
            .collect()
    }

    /// Cached read: returns a clone of the cached record, or `None`.
    pub async fn get(&self, id: &str) -> Option<TokenRecord> {
        self.inner
            .cache
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .map(|c| c.record.clone())
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), StoreError> {
        let store = self.clone();
        let id = id.to_string();
        Self::spawn_result(move || {
            {
                let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
                guard.execute(
                    "UPDATE tokens SET enabled=?1 WHERE id=?2",
                    params![enabled as i64, id],
                )?;
            }
            store.reload_cache_sync();
            Ok(())
        })
        .await
    }

    pub async fn delete(&self, id: &str) -> Result<(), StoreError> {
        let store = self.clone();
        let id = id.to_string();
        Self::spawn_result(move || {
            {
                let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
                guard.execute("DELETE FROM tokens WHERE id=?1", params![id])?;
            }
            store.reload_cache_sync();
            Ok(())
        })
        .await
    }

    pub async fn admin_password(&self) -> Option<String> {
        self.get_setting("admin_password").await
    }

    pub async fn set_admin_password(&self, hash: String) -> Result<(), StoreError> {
        self.set_setting("admin_password", hash).await
    }

    /// Set the admin password only if none is set yet (first run). Atomic:
    /// the existence check and the write run under the store's connection
    /// lock, so concurrent first-run POSTs cannot both win. Returns true when
    /// this call performed the write.
    pub async fn set_admin_password_if_absent(&self, hash: String) -> Result<bool, StoreError> {
        let store = self.clone();
        Self::spawn_result(move || {
            let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
            let n = guard.execute(
                "INSERT INTO settings(key, value)
                 SELECT 'admin_password', ?1
                 WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key = 'admin_password')",
                params![hash],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// 32-byte random HMAC secret, generated and persisted on first use so
    /// session cookies survive restarts. A corrupt or wrong-length stored
    /// value is regenerated (self-healing) rather than yielding a weak key.
    /// Cached after the first successful read: `require_session` calls this
    /// on every authenticated request and must not hit the DB each time.
    pub async fn server_secret(&self) -> Result<Vec<u8>, StoreError> {
        {
            let guard = self
                .inner
                .secret_cache
                .read()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(s) = guard.as_ref() {
                return Ok(s.clone());
            }
        }
        let mut fresh: Option<Vec<u8>> = None;
        if let Some(s) = self.get_setting("server_secret").await {
            match URL_SAFE_NO_PAD.decode(&s) {
                Ok(bytes) if bytes.len() == 32 => fresh = Some(bytes),
                _ => {}
            }
            if fresh.is_none() {
                tracing::warn!("server_secret setting is corrupt; regenerating");
            }
        }
        let bytes = match fresh {
            Some(b) => b,
            None => {
                let mut bytes = [0u8; 32];
                rand::rng().fill_bytes(&mut bytes);
                let encoded = URL_SAFE_NO_PAD.encode(bytes);
                self.set_setting("server_secret", encoded).await?;
                bytes.to_vec()
            }
        };
        *self
            .inner
            .secret_cache
            .write()
            .unwrap_or_else(|p| p.into_inner()) = Some(bytes.clone());
        Ok(bytes)
    }

    async fn get_setting(&self, key: &str) -> Option<String> {
        let store = self.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .query_row(
                    "SELECT value FROM settings WHERE key=?1",
                    params![key],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten()
        })
        .await
        .ok()
        .flatten()
    }

    async fn set_setting(&self, key: &str, value: String) -> Result<(), StoreError> {
        let store = self.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
            guard.execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )?;
            Ok(())
        })
        .await
        .expect("set_setting task")
    }
}

fn new_secret() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut bytes);
    format!("tok_{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bogus_secret_misses_without_argon2_and_valid_secret_verifies() {
        let store = TokenStore::new();
        let (_id, secret) = store
            .create("fastidx", ddns_proto::TokenLimits::default())
            .await
            .unwrap();

        // Bogus secret: O(1) index miss → zero argon2 verifies.
        let before = store
            .inner
            .argon2_verifies
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            store.validate("tok_does_not_exist").await.is_none(),
            "bogus secret must not validate"
        );
        assert_eq!(
            store
                .inner
                .argon2_verifies
                .load(std::sync::atomic::Ordering::Relaxed),
            before,
            "bogus secret must not run argon2"
        );

        // Valid secret: one argon2 verify against its single hash.
        assert!(store.validate(&secret).await.is_some());
        assert_eq!(
            store
                .inner
                .argon2_verifies
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "valid secret runs exactly one argon2 verify"
        );
    }

    #[tokio::test]
    async fn legacy_null_digest_token_still_validates_via_fallback() {
        let store = TokenStore::new();
        let (_id, secret) = store
            .create("legacy", ddns_proto::TokenLimits::default())
            .await
            .unwrap();

        // Simulate a pre-migration row: NULL the digest in the DB (the raw
        // secret is unrecoverable) and rebuild the cache/index.
        {
            let guard = store.inner.db.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .execute("UPDATE tokens SET secret_digest = NULL", [])
                .unwrap();
        }
        store.reload_cache_sync();

        // The legacy row is not in the fast index, so validation falls back to
        // the argon2 scan over NULL-digest rows and still succeeds.
        assert!(
            store.validate(&secret).await.is_some(),
            "legacy (NULL-digest) token must still validate"
        );
        // An unknown secret still fails (one argon2 verify over the legacy row).
        assert!(store.validate("tok_nope").await.is_none());
    }
}
