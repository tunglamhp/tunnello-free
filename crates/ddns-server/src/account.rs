//! Client & operator accounts and verification tokens (spec §4–§5).
//!
//! Shares the TokenStore's SQLite connection (same pattern as DomainStore).

use crate::token::{StoreError, TokenStore};
use ddns_proto::TokenLimits;
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::{Arc, MutexGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: i64,
    pub email: String,
    pub password_hash: String,
    pub role: String,
    pub email_verified_at: Option<i64>,
    pub created_at: i64,
    pub currency: String,
    pub price_monthly_override_cents: Option<i64>,
    pub price_yearly_override_cents: Option<i64>,
    pub otp_secret: Option<String>,
    pub otp_enabled: bool,
    pub limits_override: Option<String>,
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Max unexpired verification/reset tokens kept per account. A signup/reset
/// flood must not grow the table unboundedly (verify keys on token_hash, not
/// row count).
const MAX_VERIFICATION_TOKENS: i64 = 5;

#[derive(Clone)]
pub struct AccountStore {
    inner: Arc<AccountStoreInner>,
}

struct AccountStoreInner {
    store: TokenStore,
}

impl AccountStore {
    pub fn open(ts: &TokenStore) -> Self {
        let db = ts.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        crate::schema::ensure_columns(&db).expect("schema migration");
        Self {
            inner: Arc::new(AccountStoreInner { store: ts.clone() }),
        }
    }

    pub(crate) fn db(&self) -> MutexGuard<'_, Connection> {
        self.inner
            .store
            .db_conn()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<Account>, StoreError> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT id, email, password_hash, role, email_verified_at, created_at, \
                 currency, price_monthly_override_cents, price_yearly_override_cents, \
                 otp_secret, otp_enabled, limits_override
                 FROM accounts WHERE email = ?1",
                params![email],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        password_hash: r.get(2)?,
                        role: r.get(3)?,
                        email_verified_at: r.get(4)?,
                        created_at: r.get(5)?,
                        currency: r.get(6)?,
                        price_monthly_override_cents: r.get(7)?,
                        price_yearly_override_cents: r.get(8)?,
                        otp_secret: r.get(9)?,
                        otp_enabled: r.get::<_, i64>(10)? != 0,
                        limits_override: r.get(11)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<Account>, StoreError> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT id, email, password_hash, role, email_verified_at, created_at, \
                 currency, price_monthly_override_cents, price_yearly_override_cents, \
                 otp_secret, otp_enabled, limits_override
                 FROM accounts WHERE id = ?1",
                params![id],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        password_hash: r.get(2)?,
                        role: r.get(3)?,
                        email_verified_at: r.get(4)?,
                        created_at: r.get(5)?,
                        currency: r.get(6)?,
                        price_monthly_override_cents: r.get(7)?,
                        price_yearly_override_cents: r.get(8)?,
                        otp_secret: r.get(9)?,
                        otp_enabled: r.get::<_, i64>(10)? != 0,
                        limits_override: r.get(11)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// All client accounts, newest first (operator admin).
    pub async fn list_clients(&self) -> Result<Vec<Account>, StoreError> {
        let db = self.db();
        let mut stmt = db
            .prepare(
                "SELECT id, email, password_hash, role, email_verified_at, created_at, \
                 currency, price_monthly_override_cents, price_yearly_override_cents, \
                 otp_secret, otp_enabled, limits_override \
                 FROM accounts WHERE role = 'client' ORDER BY id DESC",
            )
            .map_err(StoreError::from)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Account {
                    id: r.get(0)?,
                    email: r.get(1)?,
                    password_hash: r.get(2)?,
                    role: r.get(3)?,
                    email_verified_at: r.get(4)?,
                    created_at: r.get(5)?,
                    currency: r.get(6)?,
                    price_monthly_override_cents: r.get(7)?,
                    price_yearly_override_cents: r.get(8)?,
                    otp_secret: r.get(9)?,
                    otp_enabled: r.get::<_, i64>(10)? != 0,
                    limits_override: r.get(11)?,
                })
            })
            .map_err(StoreError::from)?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        Ok(rows)
    }

    pub async fn find_operator(&self) -> Result<Option<Account>, StoreError> {
        let db = self.db();
        let row = db
            .query_row(
                "SELECT id, email, password_hash, role, email_verified_at, created_at, \
                 currency, price_monthly_override_cents, price_yearly_override_cents, \
                 otp_secret, otp_enabled, limits_override
                 FROM accounts WHERE role = 'operator' ORDER BY id LIMIT 1",
                [],
                |r| {
                    Ok(Account {
                        id: r.get(0)?,
                        email: r.get(1)?,
                        password_hash: r.get(2)?,
                        role: r.get(3)?,
                        email_verified_at: r.get(4)?,
                        created_at: r.get(5)?,
                        currency: r.get(6)?,
                        price_monthly_override_cents: r.get(7)?,
                        price_yearly_override_cents: r.get(8)?,
                        otp_secret: r.get(9)?,
                        otp_enabled: r.get::<_, i64>(10)? != 0,
                        limits_override: r.get(11)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    pub async fn has_operator(&self) -> Result<bool, StoreError> {
        Ok(self.find_operator().await?.is_some())
    }

    pub async fn create(
        &self,
        email: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<Account, StoreError> {
        {
            let db = self.db();
            db.execute(
                "INSERT INTO accounts(email, password_hash, role, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![email, password_hash, role, unix_now()],
            )?;
        } // drop guard before awaiting find_by_email (std Mutex is not re-entrant)
        self.find_by_email(email)
            .await?
            .ok_or(StoreError::Validation(
                "insert succeeded but row missing".into(),
            ))
    }

    pub async fn mark_verified(&self, id: i64) -> Result<(), StoreError> {
        let db = self.db();
        db.execute(
            "UPDATE accounts SET email_verified_at = ?1 WHERE id = ?2",
            params![unix_now(), id],
        )?;
        Ok(())
    }

    pub async fn update_password(&self, id: i64, new_hash: &str) -> Result<(), StoreError> {
        let db = self.db();
        db.execute(
            "UPDATE accounts SET password_hash = ?1 WHERE id = ?2",
            params![new_hash, id],
        )?;
        Ok(())
    }

    /// Set (or clear) an account's TOTP 2FA. `secret: None` disables 2FA and
    /// clears the stored secret; a `Some(secret)` enables it.
    pub async fn set_otp(
        &self,
        account_id: i64,
        secret: Option<&str>,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let db = self.db();
        db.execute(
            "UPDATE accounts SET otp_secret = ?1, otp_enabled = ?2 WHERE id = ?3",
            params![secret, enabled as i64, account_id],
        )?;
        Ok(())
    }

    /// `monthly`/`yearly` of `None` clear the override (fall back to plan price).
    /// Read the account's `limits_override` JSON parsed to a `TokenLimits`.
    /// `None` when unset or malformed (degrade to plan limits, never brick
    /// enforcement on a bad override).
    pub async fn limits_override(
        &self,
        account_id: i64,
    ) -> Result<Option<TokenLimits>, StoreError> {
        let db = self.db();
        let raw: Option<String> = db
            .query_row(
                "SELECT limits_override FROM accounts WHERE id = ?1",
                params![account_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        match raw {
            Some(s) => match serde_json::from_str::<TokenLimits>(&s) {
                Ok(l) => Ok(Some(l)),
                Err(e) => {
                    tracing::warn!(
                        account = account_id,
                        error = %e,
                        "limits override JSON unparseable; falling back to plan limits"
                    );
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Set (or clear) the account's wholesale `limits_override`. `None`
    /// clears the override so the account falls back to its plan limits.
    pub async fn set_limits_override(
        &self,
        account_id: i64,
        limits: Option<TokenLimits>,
    ) -> Result<(), StoreError> {
        let json = limits
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| StoreError::Validation(format!("serialize limits override: {e}")))?;
        let db = self.db();
        db.execute(
            "UPDATE accounts SET limits_override = ?1 WHERE id = ?2",
            params![json, account_id],
        )?;
        Ok(())
    }

    /// Effective limits for an account: the wholesale `limits_override` when
    /// Free edition: the account's stored per-account limits column.
    async fn stored_limits(&self, account_id: i64) -> Result<TokenLimits, StoreError> {
        let guard = self.db();
        let row: Option<String> = guard
            .query_row(
                "SELECT limits FROM accounts WHERE id = ?1",
                [account_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::from)?;
        match row {
            Some(json) => {
                serde_json::from_str(&json).map_err(|e| StoreError::Validation(e.to_string()))
            }
            None => Ok(TokenLimits::default()),
        }
    }

    /// set, else the account's plan limits (operator accounts stay unlimited).
    pub async fn effective_limits(&self, account_id: i64) -> Result<TokenLimits, StoreError> {
        if let Some(ov) = self.limits_override(account_id).await? {
            return Ok(ov);
        }
        // Free edition: operator-set overrides or the account's own limits.
        self.stored_limits(account_id).await
    }

    /// Hard-delete a client account and everything it owns. Children are
    /// removed in FK order inside one transaction; activation-code
    /// redemptions are unlinked. Callers must
    /// kill the account's live sessions first (the registry has no FK).
    pub async fn delete_account(&self, id: i64) -> Result<(), StoreError> {
        let mut guard = self.db();
        let tx = guard.transaction()?;
        tx.execute(
            "DELETE FROM verification_tokens WHERE account_id = ?1",
            params![id],
        )?;
        tx.execute(
            "DELETE FROM token_movements WHERE account_id = ?1",
            params![id],
        )?;
        tx.execute("DELETE FROM audit_log WHERE account_id = ?1", params![id])?;
        tx.execute("DELETE FROM tunnels WHERE account_id = ?1", params![id])?;
        tx.execute("DELETE FROM domains WHERE owner_id = ?1", params![id])?;
        tx.execute("DELETE FROM tokens WHERE owner_id = ?1", params![id])?;
        tx.execute(
            "UPDATE activation_codes SET redeemed_by = NULL WHERE redeemed_by = ?1",
            params![id],
        )?;
        let n = tx.execute(
            "DELETE FROM accounts WHERE id = ?1 AND role = 'client'",
            params![id],
        )?;
        tx.commit()?;
        if n == 0 {
            return Err(StoreError::Validation("no client account to delete".into()));
        }
        Ok(())
    }

    pub async fn insert_verification_token(
        &self,
        token_hash: &str,
        account_id: i64,
        purpose: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        let db = self.db();
        db.execute(
            "INSERT INTO verification_tokens(token_hash, account_id, purpose, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![token_hash, account_id, purpose, expires_at, unix_now()],
        )?;
        // Bound rows per account: keep only the latest N verification/reset
        // tokens and prune the rest.
        db.execute(
            "DELETE FROM verification_tokens
             WHERE account_id = ?1
               AND token_hash NOT IN (
                   SELECT token_hash FROM verification_tokens
                   WHERE account_id = ?1
                   ORDER BY created_at DESC, token_hash DESC
                   LIMIT ?2
               )",
            params![account_id, MAX_VERIFICATION_TOKENS],
        )?;
        Ok(())
    }

    /// Consume a single-use verification token. Returns `(account_id, purpose)`
    /// and deletes the row atomically, but only if it is unexpired.
    pub async fn consume_verification_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(i64, String)>, StoreError> {
        let db = self.db();
        let found = db
            .query_row(
                "SELECT account_id, purpose FROM verification_tokens
                 WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, unix_now()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        if found.is_some() {
            db.execute(
                "DELETE FROM verification_tokens WHERE token_hash = ?1",
                params![token_hash],
            )?;
        }
        Ok(found)
    }
}

/// First-run migration (spec §6): create the operator account from the
/// legacy `admin_password` settings row (hash preserved), then backfill
/// `owner_id` on tokens/domains to the operator.
pub async fn migrate_operator(accounts: &AccountStore, ts: &TokenStore) -> Result<(), StoreError> {
    let email =
        std::env::var("DDNS_OPERATOR_EMAIL").unwrap_or_else(|_| "operator@localhost".to_string());
    let existing = accounts.find_operator().await?;
    if existing.is_none()
        && let Some(hash) = ts.admin_password().await
    {
        accounts.create(&email, &hash, "operator").await?;
    }
    let op_id = match accounts.find_operator().await? {
        Some(op) => op.id,
        None => return Ok(()), // no operator yet; /setup will create one
    };
    let db = accounts.db();
    db.execute(
        "UPDATE tokens SET owner_id = ?1 WHERE owner_id IS NULL",
        params![op_id],
    )?;
    db.execute(
        "UPDATE domains SET owner_id = ?1 WHERE owner_id IS NULL",
        params![op_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> AccountStore {
        AccountStore::open(&TokenStore::new())
    }

    #[tokio::test]
    async fn create_and_find_by_email() {
        let s = store();
        let a = s.create("a@example.com", "hash1", "client").await.unwrap();
        let found = s.find_by_email("a@example.com").await.unwrap().unwrap();
        assert_eq!(found, a);
        assert_eq!(found.role, "client");
        assert!(found.email_verified_at.is_none());
        assert!(s.find_by_email("nope@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn email_is_unique() {
        let s = store();
        s.create("dup@example.com", "h1", "client").await.unwrap();
        assert!(s.create("dup@example.com", "h2", "client").await.is_err());
    }

    #[tokio::test]
    async fn find_operator_and_has_operator() {
        let s = store();
        assert!(!s.has_operator().await.unwrap());
        let op = s.create("op@localhost", "h", "operator").await.unwrap();
        assert!(s.has_operator().await.unwrap());
        assert_eq!(s.find_operator().await.unwrap().unwrap().id, op.id);
    }

    #[tokio::test]
    async fn verify_and_password_lifecycle() {
        let s = store();
        let a = s.create("v@example.com", "h", "client").await.unwrap();
        assert!(a.email_verified_at.is_none());
        s.mark_verified(a.id).await.unwrap();
        assert!(
            s.find_by_id(a.id)
                .await
                .unwrap()
                .unwrap()
                .email_verified_at
                .is_some()
        );
        s.update_password(a.id, "h2").await.unwrap();
        assert_eq!(
            s.find_by_id(a.id).await.unwrap().unwrap().password_hash,
            "h2"
        );
    }

    #[tokio::test]
    async fn verification_token_consume() {
        let s = store();
        let a = s.create("t@example.com", "h", "client").await.unwrap();
        let now = unix_now();
        s.insert_verification_token("abc-hash", a.id, "verify", now + 3600)
            .await
            .unwrap();
        let got = s.consume_verification_token("abc-hash").await.unwrap();
        assert_eq!(got, Some((a.id, "verify".to_string())));
        // single-use: second consume returns None
        assert!(
            s.consume_verification_token("abc-hash")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_verification_token_rejected() {
        let s = store();
        let a = s.create("e@example.com", "h", "client").await.unwrap();
        s.insert_verification_token("old-hash", a.id, "verify", unix_now() - 1)
            .await
            .unwrap();
        assert!(
            s.consume_verification_token("old-hash")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn migrate_operator_preserves_hash_and_backfills_owners() {
        use crate::auth::hash_password;
        use ddns_proto::TokenLimits;
        let ts = TokenStore::new();
        ts.set_admin_password(hash_password("old-pw").unwrap())
            .await
            .unwrap();
        // an existing token without an owner (create returns (id, secret))
        let (id, _secret) = ts.create("legacy", TokenLimits::default()).await.unwrap();
        let accounts = AccountStore::open(&ts);
        migrate_operator(&accounts, &ts).await.unwrap();
        let op = accounts
            .find_operator()
            .await
            .unwrap()
            .expect("operator exists");
        assert_eq!(op.email, "operator@localhost");
        assert!(crate::auth::verify_password("old-pw", &op.password_hash));
        // backfill: token now owned by the operator
        let db = ts.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        let owner: Option<i64> = db
            .query_row(
                "SELECT owner_id FROM tokens WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owner, Some(op.id));
    }

    #[tokio::test]
    async fn new_account_has_default_currency_and_null_overrides() {
        let s = store();
        let a = s
            .create("client@example.com", "h", "client")
            .await
            .unwrap();
        assert_eq!(a.currency, "USD");
        assert_eq!(a.price_monthly_override_cents, None);
        assert_eq!(a.price_yearly_override_cents, None);
    }

    #[tokio::test]
    async fn set_otp_round_trip_and_clear() {
        let s = store();
        let a = s.create("otp@example.com", "h", "client").await.unwrap();
        assert!(!a.otp_enabled);
        assert_eq!(a.otp_secret, None);

        s.set_otp(a.id, Some("GEZDGNBVGY3TQOJQ"), true)
            .await
            .unwrap();
        let got = s.find_by_id(a.id).await.unwrap().unwrap();
        assert!(got.otp_enabled);
        assert_eq!(got.otp_secret.as_deref(), Some("GEZDGNBVGY3TQOJQ"));

        // Disable: secret cleared, enabled false.
        s.set_otp(a.id, None, false).await.unwrap();
        let got = s.find_by_id(a.id).await.unwrap().unwrap();
        assert!(!got.otp_enabled);
        assert_eq!(got.otp_secret, None);
    }
}
