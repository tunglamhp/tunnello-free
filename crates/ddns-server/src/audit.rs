//! Operator + client activity audit log.
//!
//! Records who did what when: token/client/plan/settings/tunnel/domain/code
//! operations, logins, and purchases. `record` is fire-and-forget — errors
//! are logged and never break the calling handler. Rows are immutable; there
//! is no edit/delete surface. Financial transactions already live in
//! the paid-edition ledgers; this log captures the operations
//! around them.

use std::sync::{Arc, MutexGuard};

use rusqlite::{Connection, params};

use crate::token::TokenStore;

#[derive(Clone)]
pub struct AuditStore {
    inner: Arc<AuditStoreInner>,
}

struct AuditStoreInner {
    store: TokenStore,
}

impl AuditStore {
    pub fn open(ts: &TokenStore) -> Self {
        let db = ts.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        crate::schema::ensure_columns(&db).expect("schema migration");
        Self {
            inner: Arc::new(AuditStoreInner { store: ts.clone() }),
        }
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.inner
            .store
            .db_conn()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Append an audit entry (fire-and-forget: log + ignore on error).
    pub fn record(&self, actor_type: &str, actor_id: &str, action: &str, detail: &str) {
        let res = self.db().execute(
            "INSERT INTO audit_log(actor_type, actor_id, action, detail, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                actor_type,
                actor_id,
                action,
                detail,
                crate::account::unix_now()
            ],
        );
        if let Err(e) = res {
            tracing::warn!(?e, "audit record failed");
        } else {
            // Retention: rows are immutable and only grow. Keep 90 days; the
            // index on created_at keeps this cheap at admin-op volume.
            let cutoff = crate::account::unix_now() - 90 * 24 * 3600;
            let _ = self.db().execute(
                "DELETE FROM audit_log WHERE created_at < ?1",
                params![cutoff],
            );
        }
    }

    /// Recent entries, newest first (bounded).
    pub fn recent(&self, limit: usize) -> Vec<AuditRow> {
        let limit = limit.min(500) as i64;
        let db = self.db();
        let mut stmt = match db.prepare(
            "SELECT actor_type, actor_id, action, detail, created_at FROM audit_log \
             ORDER BY id DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(?e, "audit query failed");
                return Vec::new();
            }
        };
        stmt.query_map(params![limit], |r| {
            Ok(AuditRow {
                actor_type: r.get(0)?,
                actor_id: r.get(1)?,
                action: r.get(2)?,
                detail: r.get(3)?,
                created_at: r.get(4)?,
            })
        })
        .map(|it| it.filter_map(|x| x.ok()).collect())
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub detail: String,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenStore;

    #[test]
    fn record_and_recent_round_trip() {
        let ts = TokenStore::new();
        let audit = AuditStore::open(&ts);
        audit.record("operator", "1", "token.create", "smoke");
        audit.record("client", "7", "login", "client@example.com");
        let rows = audit.recent(10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].actor_type, "client");
        assert_eq!(rows[0].action, "login");
        assert_eq!(rows[1].action, "token.create");
        assert!(rows[1].created_at > 0);
    }
}
