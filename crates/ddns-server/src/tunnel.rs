//! Tunnel store: CRUD for tunnel profiles with HttpOptions, duplicate checks,
//! and resolution helpers. Follows `domain.rs`'s async/spawn_blocking/error
//! conventions.

use base64::Engine as _;
use rand::RngCore as _;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::domain::DomainStore;
use crate::token::{StoreError, TokenStore, now_unix};

// ---------------------------------------------------------------------------
// HttpOptions
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HttpOptions {
    #[serde(default = "default_true")]
    pub reverse_proxy_headers: bool,
    #[serde(default)]
    pub basic_auth: Option<(String, String)>,
    #[serde(default)]
    pub key_auth: Option<String>,
    #[serde(default)]
    pub pin_auth: Option<String>,
    #[serde(default)]
    pub oidc_auth: bool,
    #[serde(default)]
    pub email_otp: bool,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub https_only: bool,
    #[serde(default)]
    pub host_rewrite: Option<String>,
    #[serde(default)]
    pub add_headers: Vec<(String, String)>,
    #[serde(default)]
    pub remove_headers: Vec<String>,
    #[serde(default)]
    pub pass_preflight: bool,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            reverse_proxy_headers: true,
            basic_auth: None,
            key_auth: None,
            pin_auth: None,
            oidc_auth: false,
            email_otp: false,
            ip_whitelist: Vec::new(),
            https_only: false,
            host_rewrite: None,
            add_headers: Vec::new(),
            remove_headers: Vec::new(),
            pass_preflight: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TunnelRecord / NewTunnel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TunnelRecord {
    pub id: String,
    pub name: String,
    pub token_id: String,
    pub domain_id: String,
    pub subdomain: Option<String>,
    pub custom_hostname: Option<String>,
    pub options: HttpOptions,
    pub enabled: bool,
    pub created_at: i64,
    /// Owning account id, resolved from the token's owner at create time
    /// (NULL for operator/legacy tokens). Tenant-scope key for quotas.
    pub account_id: Option<i64>,
    /// Cumulative tunnel request counter (metering; not used for quota).
    pub request_count: i64,
    /// Expected local ports this tunnel forwards, comma-separated (informational
    /// config shown on the operator + customer tunnel pages; the client passes
    /// the actual --port/--tcp at runtime).
    pub ports: String,
}

#[derive(Debug, Clone)]
pub struct NewTunnel {
    pub name: String,
    pub token_id: String,
    pub domain_id: String,
    pub subdomain: Option<String>,
    pub custom_hostname: Option<String>,
    pub options: HttpOptions,
    pub ports: String,
}

// ---------------------------------------------------------------------------
// TunnelStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct TunnelStore {
    store: TokenStore,
    #[allow(dead_code)]
    domains: DomainStore,
}

impl TunnelStore {
    pub fn open(ts: &TokenStore, domains: &DomainStore) -> Self {
        Self {
            store: ts.clone(),
            domains: domains.clone(),
        }
    }

    // -- helpers ----------------------------------------------------------

    fn row(row: &rusqlite::Row) -> rusqlite::Result<TunnelRecord> {
        let options_str: String = row.get(6)?;
        let options: HttpOptions = serde_json::from_str(&options_str).unwrap_or_default();
        Ok(TunnelRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            token_id: row.get(2)?,
            domain_id: row.get(3)?,
            subdomain: row.get(4)?,
            custom_hostname: row.get(5)?,
            options,
            enabled: row.get::<_, i64>(7)? != 0,
            created_at: row.get(8)?,
            account_id: row.get(9)?,
            request_count: row.get(10)?,
            ports: row.get(11)?,
        })
    }

    // -- public API -------------------------------------------------------

    pub async fn list(&self) -> Result<Vec<TunnelRecord>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                 options, enabled, created_at, account_id, request_count, ports \
                 FROM tunnels ORDER BY created_at",
            )?;
            let rows = stmt
                .query_map([], Self::row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn get(&self, id: &str) -> Result<Option<TunnelRecord>, StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                 options, enabled, created_at, account_id, request_count, ports \
                 FROM tunnels WHERE id=?1",
            )?;
            stmt.query_row(params![id], Self::row)
                .optional()
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn create(&self, n: &NewTunnel) -> Result<TunnelRecord, StoreError> {
        self.create_checked(n, 0).await
    }

    /// Create a tunnel, enforcing the tenant's enabled-tunnel cap in the SAME
    /// mutex acquisition as the INSERT — two concurrent creates for one
    /// account can no longer both pass the check and exceed the cap.
    /// `max_enabled` is the account's plan cap (0 = unlimited); ownerless
    /// (operator/legacy) tokens are exempt because their `account_id` is NULL.
    pub async fn create_checked(
        &self,
        n: &NewTunnel,
        max_enabled: i64,
    ) -> Result<TunnelRecord, StoreError> {
        let id = format!("u-{}", random_slug());
        let n = n.clone();
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());

            // Validate
            let token_ok = guard
                .query_row(
                    "SELECT COUNT(*) FROM tokens WHERE id=?1",
                    params![&n.token_id],
                    |r| r.get::<_, i64>(0),
                )
                .is_ok_and(|c| c > 0);
            let domain_ok = guard
                .query_row(
                    "SELECT COUNT(*) FROM domains WHERE id=?1",
                    params![&n.domain_id],
                    |r| r.get::<_, i64>(0),
                )
                .is_ok_and(|c| c > 0);
            let dup_name: bool = guard
                .query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE name=?1",
                    params![&n.name],
                    |r| r.get::<_, i64>(0),
                )
                .is_ok_and(|c| c > 0);
            let dup_sub = n.subdomain.as_ref().is_some_and(|s| {
                guard
                    .query_row(
                        "SELECT COUNT(*) FROM tunnels WHERE subdomain=?1",
                        params![s],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok_and(|c| c > 0)
            });
            let dup_host = n.custom_hostname.as_ref().is_some_and(|h| {
                guard
                    .query_row(
                        "SELECT COUNT(*) FROM tunnels WHERE lower(custom_hostname) = lower(?1)",
                        params![h],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok_and(|c| c > 0)
            });

            validate(&n, token_ok, domain_ok, dup_name, dup_sub, dup_host)?;

            // Resolve the tenant from the token's owner (the token's
            // existence is validated above, so this row exists).
            let account_id: Option<i64> = guard.query_row(
                "SELECT owner_id FROM tokens WHERE id=?1",
                params![&n.token_id],
                |r| r.get(0),
            )?;

            // Atomic quota check — count enabled tunnels for this tenant under
            // the same guard as the INSERT below.
            if max_enabled > 0
                && let Some(owner) = account_id
            {
                let enabled: i64 = guard.query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE account_id=?1 AND enabled=1",
                    params![owner],
                    |r| r.get(0),
                )?;
                if enabled >= max_enabled {
                    return Err(StoreError::Quota(format!(
                        "Plan tunnel limit reached ({})",
                        max_enabled
                    )));
                }
            }

            let now = now_unix();
            let options_json = serde_json::to_string(&n.options).unwrap_or_default();
            guard.execute(
                "INSERT INTO tunnels (id, name, token_id, domain_id, subdomain, \
                 custom_hostname, options, enabled, created_at, account_id, request_count, ports) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, 0, ?10)",
                params![
                    id,
                    n.name,
                    n.token_id,
                    n.domain_id,
                    n.subdomain,
                    n.custom_hostname,
                    options_json,
                    now,
                    account_id,
                    n.ports
                ],
            )?;
            // Read back
            let mut stmt = guard.prepare(
                "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                 options, enabled, created_at, account_id, request_count, ports \
                 FROM tunnels WHERE id=?1",
            )?;
            stmt.query_row(params![id], Self::row)
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn update(&self, id: &str, n: &NewTunnel) -> Result<(), StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        let n = n.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());

            let token_ok = guard
                .query_row("SELECT COUNT(*) FROM tokens WHERE id=?1", params![&n.token_id], |r| r.get::<_, i64>(0))
                .is_ok_and(|c| c > 0);
            let domain_ok = guard
                .query_row("SELECT COUNT(*) FROM domains WHERE id=?1", params![&n.domain_id], |r| r.get::<_, i64>(0))
                .is_ok_and(|c| c > 0);
            let dup_name: bool = guard
                .query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE name=?1 AND id!=?2",
                    params![&n.name, &id],
                    |r| r.get::<_, i64>(0),
                )
                .is_ok_and(|c| c > 0);
            let dup_sub = n.subdomain.as_ref().is_some_and(|s| {
                guard
                    .query_row(
                        "SELECT COUNT(*) FROM tunnels WHERE subdomain=?1 AND id!=?2",
                        params![s, &id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok_and(|c| c > 0)
            });
            let dup_host = n.custom_hostname.as_ref().is_some_and(|h| {
                guard
                    .query_row(
                        "SELECT COUNT(*) FROM tunnels WHERE lower(custom_hostname) = lower(?1) AND id!=?2",
                        params![h, &id],
                        |r| r.get::<_, i64>(0),
                    )
                    .is_ok_and(|c| c > 0)
            });

            validate(&n, token_ok, domain_ok, dup_name, dup_sub, dup_host)?;

            let options_json = serde_json::to_string(&n.options).unwrap_or_default();
            guard.execute(
                "UPDATE tunnels SET name=?2, token_id=?3, domain_id=?4, \
                 subdomain=?5, custom_hostname=?6, options=?7, ports=?8 WHERE id=?1",
                params![id, n.name, n.token_id, n.domain_id, n.subdomain, n.custom_hostname, options_json, n.ports],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Delete every tunnel profile bound to a token (cascade on token
    /// delete — otherwise orphaned profiles keep counting toward the plan cap).
    pub async fn delete_for_token(&self, token_id: &str) -> Result<(), StoreError> {
        let store = self.store.clone();
        let token_id = token_id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            guard.execute("DELETE FROM tunnels WHERE token_id=?1", params![token_id])?;
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
            guard.execute("DELETE FROM tunnels WHERE id=?1", params![id])?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn toggle(&self, id: &str) -> Result<bool, StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            guard.execute(
                "UPDATE tunnels SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?1",
                params![id],
            )?;
            let new_enabled: i64 = guard.query_row(
                "SELECT enabled FROM tunnels WHERE id=?1",
                params![id],
                |r| r.get(0),
            )?;
            Ok(new_enabled != 0)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    pub async fn resolve_for_token(
        &self,
        token_id: &str,
        hint: Option<&str>,
    ) -> Result<Option<TunnelRecord>, StoreError> {
        let enabled = self.list_inner(Some(token_id), true).await?;
        if enabled.is_empty() {
            return Ok(None);
        }
        if let Some(h) = hint
            && let Some(rec) = enabled.iter().find(|r| r.name == h)
        {
            return Ok(Some(rec.clone()));
        }
        Ok(enabled.into_iter().next())
    }

    pub async fn custom_host(&self, host: &str) -> Result<Option<TunnelRecord>, StoreError> {
        let store = self.store.clone();
        let host = host.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                 options, enabled, created_at, account_id, request_count, ports FROM tunnels \
                 WHERE lower(custom_hostname) = lower(?1)",
            )?;
            stmt.query_row(params![host], Self::row)
                .optional()
                .map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Tunnels owned by a tenant account (JOIN tokens ON owner). Returns all
    /// tunnels for the account; quota checks filter for `enabled`.
    pub async fn list_for_account(&self, account_id: i64) -> Result<Vec<TunnelRecord>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard.prepare(
                "SELECT t.id, t.name, t.token_id, t.domain_id, t.subdomain, t.custom_hostname, \
                 t.options, t.enabled, t.created_at, t.account_id, t.request_count, t.ports \
                 FROM tunnels t JOIN tokens tk ON tk.id = t.token_id \
                 WHERE tk.owner_id = ?1 ORDER BY t.created_at",
            )?;
            let rows = stmt
                .query_map(params![account_id], Self::row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    // -- private helpers ---------------------------------------------------

    async fn list_inner(
        &self,
        token_id: Option<&str>,
        enabled_only: bool,
    ) -> Result<Vec<TunnelRecord>, StoreError> {
        let store = self.store.clone();
        let tid = token_id.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || -> Result<Vec<TunnelRecord>, StoreError> {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let rows: Result<Vec<TunnelRecord>, rusqlite::Error> = if let Some(t) = &tid {
                let mut stmt = guard.prepare(
                    "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                     options, enabled, created_at, account_id, request_count, ports FROM tunnels \
                     WHERE token_id=?1 AND enabled=1 ORDER BY created_at",
                )?;
                stmt.query_map(params![t], Self::row)?
                    .collect::<Result<Vec<_>, _>>()
            } else if enabled_only {
                let mut stmt = guard.prepare(
                    "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                     options, enabled, created_at, account_id, request_count, ports FROM tunnels \
                     WHERE enabled=1 ORDER BY created_at",
                )?;
                stmt.query_map([], Self::row)?
                    .collect::<Result<Vec<_>, _>>()
            } else {
                let mut stmt = guard.prepare(
                    "SELECT id, name, token_id, domain_id, subdomain, custom_hostname, \
                     options, enabled, created_at, account_id, request_count, ports \
                     FROM tunnels ORDER BY created_at",
                )?;
                stmt.query_map([], Self::row)?
                    .collect::<Result<Vec<_>, _>>()
            };
            rows.map_err(StoreError::from)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate(
    n: &NewTunnel,
    token_ok: bool,
    domain_ok: bool,
    dup_name: bool,
    dup_sub: bool,
    dup_host: bool,
) -> Result<(), StoreError> {
    if !token_ok {
        return Err(StoreError::Validation("token not found".into()));
    }
    if !domain_ok {
        return Err(StoreError::Validation("domain not found".into()));
    }
    if dup_name {
        return Err(StoreError::Validation("tunnel name already exists".into()));
    }
    match (&n.subdomain, &n.custom_hostname) {
        (Some(_), Some(_)) => {
            return Err(StoreError::Validation(
                "subdomain and custom hostname are mutually exclusive".into(),
            ));
        }
        (Some(s), None) => {
            if !valid_slug(s) {
                return Err(StoreError::Validation("invalid subdomain".into()));
            }
            if dup_sub {
                return Err(StoreError::Validation("subdomain already in use".into()));
            }
        }
        (None, Some(h)) => {
            if !valid_hostname(h) {
                return Err(StoreError::Validation("invalid custom hostname".into()));
            }
            if dup_host {
                return Err(StoreError::Validation(
                    "custom hostname already in use".into(),
                ));
            }
        }
        (None, None) => {}
    }
    Ok(())
}

fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_hostname(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    for label in h.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return false;
        }
    }
    true
}

fn random_slug() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(buf)
        .to_lowercase()
}

impl TunnelStore {
    /// Save a named policy (upsert by name). Returns the policy id.
    pub async fn save_policy(&self, name: &str, options_json: &str) -> Result<String, StoreError> {
        let store = self.store.clone();
        let name = name.to_string();
        let options_json = options_json.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let now = now_unix();
            guard.execute(
                "INSERT INTO policies (id, name, options, created_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(name) DO UPDATE SET options=excluded.options",
                params![format!("p-{}", random_slug()), name, options_json, now],
            )?;
            let id: String = guard
                .query_row(
                    "SELECT id FROM policies WHERE name=?1",
                    params![name],
                    |r| r.get(0),
                )
                .map_err(StoreError::Sqlite)?;
            Ok(id)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// List all policies as (id, name, options_json).
    pub async fn list_policies(&self) -> Result<Vec<(String, String, String)>, StoreError> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            let mut stmt = guard
                .prepare("SELECT id, name, options FROM policies ORDER BY name")
                .map_err(StoreError::Sqlite)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })
                .map_err(StoreError::Sqlite)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(StoreError::Sqlite)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }

    /// Delete a policy by id.
    pub async fn delete_policy(&self, id: &str) -> Result<(), StoreError> {
        let store = self.store.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let guard = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
            guard
                .execute("DELETE FROM policies WHERE id=?1", params![id])
                .map_err(StoreError::Sqlite)?;
            Ok(())
        })
        .await
        .map_err(|e| StoreError::Join(e.to_string()))?
    }
}
