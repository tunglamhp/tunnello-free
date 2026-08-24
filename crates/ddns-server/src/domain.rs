//! Domain store: CRUD + active-apex tracking + idempotent config seeding.
//!
//! Follows `token.rs`'s async/spawn_blocking/error-handling conventions.

use std::fmt;

use ddns_proto::random_slug;
use rusqlite::{OptionalExtension, params};

use crate::token::{StoreError, TokenStore, now_unix};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    Apex,
    Custom,
}

impl DomainKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainKind::Apex => "apex",
            DomainKind::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "apex" => Ok(DomainKind::Apex),
            "custom" => Ok(DomainKind::Custom),
            other => Err(format!("invalid DomainKind: {other}")),
        }
    }
}

impl fmt::Display for DomainKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    Pending,
    Validating,
    Active,
    Failed,
}

impl ValidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValidationStatus::Pending => "pending",
            ValidationStatus::Validating => "validating",
            ValidationStatus::Active => "active",
            ValidationStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(ValidationStatus::Pending),
            "validating" => Ok(ValidationStatus::Validating),
            "active" => Ok(ValidationStatus::Active),
            "failed" => Ok(ValidationStatus::Failed),
            other => Err(format!("invalid ValidationStatus: {other}")),
        }
    }
}

impl fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Absent,
    Pending,
    Active,
    Failed,
}

impl CertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CertStatus::Absent => "absent",
            CertStatus::Pending => "pending",
            CertStatus::Active => "active",
            CertStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "absent" => Ok(CertStatus::Absent),
            "pending" => Ok(CertStatus::Pending),
            "active" => Ok(CertStatus::Active),
            "failed" => Ok(CertStatus::Failed),
            other => Err(format!("invalid CertStatus: {other}")),
        }
    }
}

impl fmt::Display for CertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DomainRecord
// ---------------------------------------------------------------------------

/// Validate a domain name for storage. Allows an optional `*.` wildcard
/// prefix; rejects control characters, empty/overlong labels, and malformed
/// charset. Whatever passes is safe to render in HTML and to embed in URLs.
pub fn valid_domain_name(name: &str, _kind: DomainKind) -> bool {
    let raw = name.trim();
    let raw = raw.strip_prefix("*.").unwrap_or(raw);
    if raw.is_empty() || raw.len() > 253 || raw.starts_with('.') || raw.ends_with('.') {
        return false;
    }
    raw.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

#[derive(Debug, Clone)]
pub struct DomainRecord {
    pub id: String,
    pub name: String,
    pub kind: DomainKind,
    /// Owning account id (NULL = operator/legacy domain, exempt from quota).
    pub owner_id: Option<i64>,
    pub active: bool,
    pub validation_status: ValidationStatus,
    pub validation_token: Option<String>,
    pub cert_status: CertStatus,
    pub cert_expiry_secs: Option<i64>,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// DomainStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DomainStore {
    store: TokenStore,
}

impl DomainStore {
    pub fn open(ts: &TokenStore) -> Self {
        Self { store: ts.clone() }
    }

    // -- helpers ----------------------------------------------------------

    fn row(row: &rusqlite::Row) -> rusqlite::Result<DomainRecord> {
        let kind_str: String = row.get(2)?;
        let validation_str: String = row.get(5)?;
        let cert_str: String = row.get(7)?;
        Ok(DomainRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            kind: DomainKind::parse(&kind_str).map_err(rusqlite::Error::InvalidColumnName)?,
            owner_id: row.get(3)?,
            active: row.get::<_, i64>(4)? != 0,
            validation_status: ValidationStatus::parse(&validation_str)
                .map_err(rusqlite::Error::InvalidColumnName)?,
            validation_token: row.get(6)?,
            cert_status: CertStatus::parse(&cert_str)
                .map_err(rusqlite::Error::InvalidColumnName)?,
            cert_expiry_secs: row.get(8)?,
            created_at: row.get(9)?,
        })
    }

    // -- public API -------------------------------------------------------

    pub async fn list(&self) -> Result<Vec<DomainRecord>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, kind, owner_id, active, validation_status, validation_token, \
                 cert_status, cert_expiry_secs, created_at FROM domains ORDER BY created_at",
            )?;
            let rows = stmt
                .query_map([], Self::row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn get(&self, id: &str) -> Result<Option<DomainRecord>, StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, kind, owner_id, active, validation_status, validation_token, \
                 cert_status, cert_expiry_secs, created_at FROM domains WHERE id=?1",
            )?;
            stmt.query_row(params![id], Self::row)
                .optional()
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn create(&self, name: &str, kind: DomainKind) -> Result<DomainRecord, StoreError> {
        self.create_owned(name, kind, None).await
    }

    pub async fn create_owned(
        &self,
        name: &str,
        kind: DomainKind,
        owner_id: Option<i64>,
    ) -> Result<DomainRecord, StoreError> {
        if !valid_domain_name(name, kind) {
            return Err(StoreError::Validation(format!(
                "invalid domain name: {name:?}"
            )));
        }
        let id = format!("d-{}", random_slug(&mut rand::rng()));
        let name = name.to_string();
        let store = self.store.clone();
        let kind2 = kind;
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let now = now_unix();
            guard.execute(
                "INSERT INTO domains (id, name, kind, owner_id, active, validation_status, \
                 validation_token, cert_status, cert_expiry_secs, created_at) \
                 VALUES (?1, ?2, ?3, ?4, 0, 'pending', NULL, 'absent', NULL, ?5)",
                params![id, name, kind2.as_str(), owner_id, now],
            )?;
            // Read back the inserted row
            let mut stmt = guard.prepare(
                "SELECT id, name, kind, owner_id, active, validation_status, validation_token, \
                 cert_status, cert_expiry_secs, created_at FROM domains WHERE id=?1",
            )?;
            stmt.query_row(params![id], Self::row)
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Active domains owned by an account, oldest first (quota suspension
    /// order: beyond the cap, the oldest survive).
    pub async fn active_for_owner(&self, owner_id: i64) -> Result<Vec<DomainRecord>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard
                .prepare(
                    "SELECT id, name, kind, owner_id, active, validation_status, \
                     validation_token, cert_status, cert_expiry_secs, created_at \
                     FROM domains WHERE owner_id = ?1 AND active = 1 \
                     ORDER BY created_at ASC",
                )
                .map_err(StoreError::from)?;
            let rows = stmt
                .query_map(params![owner_id], Self::row)
                .map_err(StoreError::from)?
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>();
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn set_active(&self, id: &str, active: bool) -> Result<(), StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            guard
                .execute(
                    "UPDATE domains SET active = ?1 WHERE id = ?2",
                    params![active as i64, id],
                )
                .map_err(StoreError::from)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn update(&self, id: &str, name: &str, kind: DomainKind) -> Result<(), StoreError> {
        if !valid_domain_name(name, kind) {
            return Err(StoreError::Validation(format!(
                "invalid domain name: {name:?}"
            )));
        }
        let store = self.store.clone();
        let id = id.to_string();
        let name = name.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            guard.execute(
                "UPDATE domains SET name=?2, kind=?3 WHERE id=?1",
                params![id, name, kind.as_str()],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn delete(&self, id: &str) -> Result<(), StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            // Check for tunnel references
            let count: i64 = guard.query_row(
                "SELECT COUNT(*) FROM tunnels WHERE domain_id=?1",
                params![id],
                |r| r.get(0),
            )?;
            if count > 0 {
                return Err(StoreError::InUse("domain is referenced by tunnels".into()));
            }
            guard.execute("DELETE FROM domains WHERE id=?1", params![id])?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn activate(&self, id: &str) -> Result<(), StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let tx = guard.transaction()?;
            tx.execute("UPDATE domains SET active=0 WHERE kind='apex'", [])?;
            tx.execute(
                "UPDATE domains SET active=1 WHERE id=?1 AND kind='apex'",
                params![id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn active_apex(&self) -> Result<Option<DomainRecord>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, kind, owner_id, active, validation_status, validation_token, \
                 cert_status, cert_expiry_secs, created_at FROM domains \
                 WHERE active=1 AND kind='apex' LIMIT 1",
            )?;
            stmt.query_row([], Self::row)
                .optional()
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn apex_names(&self) -> Result<Vec<String>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt =
                guard.prepare("SELECT name FROM domains WHERE kind='apex' ORDER BY created_at")?;
            let names = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(names)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Idempotent: inserts the configured apex domain if no apex exists,
    /// then activates it. Safe to call at every broker start.
    pub fn seed_from_config(&self, domain: &str) {
        let guard = self
            .store
            .db_conn()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Check if any apex exists
        let exists: bool = guard
            .query_row("SELECT COUNT(*) FROM domains WHERE kind='apex'", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|c| c > 0)
            .unwrap_or(false);
        if exists {
            return;
        }
        // Insert the configured apex
        let id = format!("d-{}", random_slug(&mut rand::rng()));
        let now = now_unix();
        let _ = guard.execute(
            "INSERT INTO domains (id, name, kind, owner_id, active, validation_status, \
             validation_token, cert_status, cert_expiry_secs, created_at) \
             VALUES (?1, ?2, 'apex', NULL, 1, 'pending', NULL, 'absent', NULL, ?3)",
            params![id, domain, now],
        );
    }
}
