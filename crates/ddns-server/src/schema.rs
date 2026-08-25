//! Single source of truth for the SQLite schema. Every store's init runs
//! this batch; all statements are idempotent (`IF NOT EXISTS`).

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS verification_tokens(
    token_hash TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    purpose TEXT NOT NULL,
    expires_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE TABLE IF NOT EXISTS accounts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    email_verified_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    currency TEXT NOT NULL DEFAULT 'USD',
    price_monthly_override_cents INTEGER,
    price_yearly_override_cents INTEGER,
    otp_secret TEXT,
    otp_enabled INTEGER NOT NULL DEFAULT 0,
    limits_override TEXT
);

CREATE TABLE IF NOT EXISTS tokens(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    owner_id INTEGER,
    max_sessions INT NOT NULL,
    max_streams INT NOT NULL,
    max_bytes INT NOT NULL,
    ttl_secs INT NOT NULL,
    enabled INT NOT NULL,
    created_at INT NOT NULL,
    secret_digest TEXT
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domains(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    owner_id INTEGER,
    active INTEGER NOT NULL DEFAULT 0,
    validation_status TEXT NOT NULL DEFAULT 'pending',
    validation_token TEXT,
    cert_status TEXT NOT NULL DEFAULT 'absent',
    cert_expiry_secs INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tunnels(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    subdomain TEXT,
    custom_hostname TEXT,
    options TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    account_id INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,
    ports TEXT NOT NULL DEFAULT ''
);









CREATE TABLE IF NOT EXISTS policies(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  options TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,          -- operator | client | system
  actor_id TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
CREATE TABLE IF NOT EXISTS setup_codes(
  code_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL,
  token_id TEXT NOT NULL,
  ports TEXT NOT NULL DEFAULT '',
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);

"#;

/// SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`; existing
/// databases need a PRAGMA-guarded column add for the new `owner_id` columns.
pub fn ensure_columns(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    if !has_column(conn, "accounts", "currency")? {
        conn.execute_batch(
            "ALTER TABLE accounts ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD';",
        )?;
    }
    if !has_column(conn, "accounts", "price_monthly_override_cents")? {
        conn.execute_batch(
            "ALTER TABLE accounts ADD COLUMN price_monthly_override_cents INTEGER;",
        )?;
    }
    if !has_column(conn, "accounts", "price_yearly_override_cents")? {
        conn.execute_batch("ALTER TABLE accounts ADD COLUMN price_yearly_override_cents INTEGER;")?;
    }
    if !has_column(conn, "accounts", "otp_secret")? {
        conn.execute_batch("ALTER TABLE accounts ADD COLUMN otp_secret TEXT;")?;
    }
    if !has_column(conn, "accounts", "otp_enabled")? {
        conn.execute_batch(
            "ALTER TABLE accounts ADD COLUMN otp_enabled INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !has_column(conn, "accounts", "limits_override")? {
        conn.execute_batch("ALTER TABLE accounts ADD COLUMN limits_override TEXT;")?;
    }

    fn has_column(
        conn: &rusqlite::Connection,
        table: &str,
        column: &str,
    ) -> Result<bool, rusqlite::Error> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = stmt
            .query_map([], |r| r.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        Ok(names.iter().any(|n| n == column))
    }
    if !has_column(conn, "tokens", "owner_id")? {
        conn.execute_batch("ALTER TABLE tokens ADD COLUMN owner_id INTEGER;")?;
    }
    if !has_column(conn, "tokens", "secret_digest")? {
        conn.execute_batch("ALTER TABLE tokens ADD COLUMN secret_digest TEXT;")?;
    }
    if !has_column(conn, "domains", "owner_id")? {
        conn.execute_batch("ALTER TABLE domains ADD COLUMN owner_id INTEGER;")?;
    }
    if !has_column(conn, "tunnels", "account_id")? {
        conn.execute_batch("ALTER TABLE tunnels ADD COLUMN account_id INTEGER;")?;
        conn.execute_batch(
            "UPDATE tunnels SET account_id = \
             (SELECT owner_id FROM tokens WHERE tokens.id = tunnels.token_id);",
        )?;
    }
    if !has_column(conn, "tunnels", "request_count")? {
        conn.execute_batch(
            "ALTER TABLE tunnels ADD COLUMN request_count INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !has_column(conn, "tunnels", "ports")? {
        conn.execute_batch("ALTER TABLE tunnels ADD COLUMN ports TEXT NOT NULL DEFAULT '';")?;
    }
    Ok(())
}
