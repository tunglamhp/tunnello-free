# DDNS Tunnel Broker — Operator Manual

Self-hosted tunnel broker with fixed hostnames, per-tunnel HTTP hardening,
and a liquid-glass operator dashboard. A lightweight client (the `ddns`
binary) opens a WSS connection to the broker and forwards visitor HTTP/TCP
traffic to a local service; visitors reach it through a stable hostname such
as `my-app.tunnel.example.com`.

```
visitor ──HTTPS──▶ broker (ddns-server) ──WSS/Frame──▶ client (ddns) ──HTTP/TCP──▶ your service
                        │
                        └─ dashboard / API / SQLite state
```

This manual covers: quickstart, dashboard, domains, tunnel profiles with the
HTTP-options pipeline, tokens, the REST API, both binaries' CLIs, security,
and troubleshooting. Production container deployment lives in
[`deploy/README.md`](deploy/README.md).

---

## 1. Quickstart (local development)

Prerequisites: a Rust 1.94+ toolchain, a checkout of this repo.

```bash
# 1. Broker with a self-signed dev cert for tunnel.example.com
target/debug/ddns-server --dev --domain tunnel.example.com \
  --listen 127.0.0.1:8443 --public-port 8443 \
  --db .demo/ddns.db --download-dir .demo/downloads --max-sessions 8

# 2. First run: open https://127.0.0.1:8443/setup and set the admin password.
#    The dev CA is written next to the DB (<db>.dev-ca.pem); pass it to the
#    client with --ca-pem.

# 3. Serve something locally, then run the client
python3 -m http.server 9090
target/debug/ddns --token tok_xxx --server https://127.0.0.1:8443 \
  --ca-pem .demo/ddns.db.dev-ca.pem --port 9090

# 4. The client prints its live hostname; visit it (with --resolve or a hosts
#    entry while testing locally).
```

---

## 2. Broker CLI (`ddns-server`)

```
Usage: ddns-server --domain DOMAIN [OPTIONS]

Required:
  --domain DOMAIN         Tunnel apex domain (e.g. tunnel.example.com)

Certificate (exactly one source):
  --cert FILE --key FILE  Static PEM cert chain + private key
  --acme-email EMAIL      ACME (automatic certificates) via TLS-ALPN-01 (apex
                          domains only; wildcards need DNS-01, which v1 does
                          not drive)
  --dev                   Self-signed cert for DOMAIN, *.DOMAIN and loopback
                          addresses; writes <db>.dev-ca.pem for the client's
                          --ca-pem flag

Options:
  --listen ADDR           Bind address (default 0.0.0.0:443 inside container)
  --public-port N         Port advertised in registered URLs (default 443 in VPS bundle)
  --http-listen ADDR      Optional plain-HTTP listener (301 -> HTTPS + HTTP-01)
  --db PATH               SQLite database path (default ddns.db)
  --max-sessions N        Server-wide session cap (default 256)
  --watchdog-ms N         Quota watchdog tick in ms (default 5000)
  --download-dir PATH     Directory served by /download/{file}
  --web-dist PATH         Directory served by /_assets/{path} (default dist/public)
  --acme-directory URL    ACME directory override (default: ACME staging)
```

- The DB is migrated idempotently at startup (tokens, settings, domains,
  tunnels tables).
- The TLS listener also serves `/connect` (client WSS), the dashboard, the
  REST API, `/install.sh` and `/download/{file}`.

The dashboard's client-side islands (`crates/ddns-web`, Dioxus) are built to
WASM and served from the `--web-dist` directory. Build them before running the
broker (the broker serves its server-rendered HTML without them, but islands
won't hydrate):

```bash
rustup target add wasm32-unknown-unknown
cargo install dioxus-cli          # or the official installer
dx bundle --platform web --package ddns-web
```

The bundle lands in `dist/public` and is served at `/_assets/wasm/ddns-web.js`.

## 3. Client CLI (`ddns`)

```
Usage: ddns --token TOKEN [OPTIONS]

  --token TOKEN    Authentication token (required)
  --server URL     Broker URL (default: https://tunnel.example.com)
  --port N         Local HTTP port to forward (e.g. 8080)
  --tcp N          Local TCP port to forward (e.g. 22)
  --local URL      Local target as http://host:port or tcp://host:port
                   (repeatable; one per scheme)
  --name NAME      Friendly name (v1: not transmitted, reserved for future use)
  --ca-pem PATH    Extra CA certificate PEM file for custom TLS roots
  --help           Show this help message
```

- At least one of `--port` / `--tcp` / `--local` is required.
- Heartbeat interval: env `DDNS_HEARTBEAT_MS` overrides the default.
- On reconnect the broker re-resolves the token's tunnel profile, so a fixed
  subdomain is reused; a session whose slug is taken gets
  `NoSubdomainAvailable` (visible in the client log).
- `GET /install.sh` on the broker returns a script that downloads the right
  static client binary (`/download/ddns-<arch>-<abi>`) for Linux/macOS.

---

## 4. Operator dashboard

Session-cookie protected; first run goes through `/setup` (admin password,
8–128 chars, argon2-hashed), then `/login` (per-IP rate limited).

| Page        | Route                    | Contents |
| ----------- | ------------------------ | -------- |
| Dashboard   | `/`                      | Live sessions: slug, token, uptime, stream counts, bytes, traffic sparklines, kill button |
| Tunnels     | `/tunnels`, `/tunnels/new`, `/tunnels/{id}/edit` | Fixed-hostname profiles bound to a token + domain, with the HTTP-options form |
| Domains     | `/domains`               | Apex/custom domains, activate an apex, DNS-guidance column |
| Tokens      | `/tokens`                | Create tokens with a MAX BYTES slider; disable/enable/delete |
| Settings    | `/settings`              | Instance branding, security (session TTL, IP allowlist, 2FA), alert webhooks/email, token defaults, admin password |

A public status page exists per session at `/t/{slug}`.

### 4.1 Domains

- **Apex** (`kind: apex`): the wildcard base — the active apex defines
  `slug.<apex>` visitor routing. Activate exactly one apex; activation is
  transactional (previous apex deactivates automatically).
- **Custom** (`kind: custom`): an alternative hostname; when a tunnel binds a
  custom hostname and the client is live, that host routes to the tunnel
  (checked before `slug.<active-apex>`).
- `validation_status` / `cert_status` are stored and displayed; Phase B
  (DNS-01 ACME, CNAME/TXT/A validation) drives them out of
  `pending`/`absent`. Until then, point `*.apex` at the broker yourself.

### 4.2 Tunnel profiles

A profile binds a **token** + **domain** and optionally a fixed subdomain or
custom hostname. On registration, the broker resolves the token's enabled
profile and allocates its slug (or a random one if none).

Hostname preview rules:

- `subdomain` set → `https://<sub>.<domain>`
- `custom_hostname` set → `https://<custom_hostname>`
- neither → random per session

### 4.3 HTTP options pipeline

Options are applied to visitor requests in this exact order (pure function
`HttpOptions::apply` in `crates/ddns-server/src/http_options.rs`):

1. **Preflight** — if `pass_preflight` is set, OPTIONS requests pass through
   untouched; otherwise normal processing.
2. **IP whitelist** (`ip_whitelist`) — exact IPs or CIDRs (IPv4 and IPv6);
   non-matching sources get `403`.
3. **Basic auth** (`basic_auth: user,pass`) — missing/wrong credentials get
   `401` with `WWW-Authenticate: Basic realm="ddns"`.
4. **Key auth** (`key_auth`) — `Authorization: Bearer <key>` required, else
   `401`.
5. **Header mutations** — `remove_headers`, then `add_headers`
   (`host_rewrite` maps to `Host`), then `reverse_proxy_headers`
   (default true: injects `X-Forwarded-For`, `X-Forwarded-Proto`,
   `X-Forwarded-Host`).

`https_only` is stored/displayed; v1 enforces HTTPS at the listener level
(`--http-listen` 301), the pipeline does not re-emit redirects.

### 4.4 Tokens and limits

Tokens are the client credential (argon2-hashed at rest) and carry limits:
| Limit          | Meaning                                   |
| -------------- | ----------------------------------------- |
| `max_sessions` | Concurrent sessions per token (`0` = unlimited) |
| `max_streams`  | Concurrent visitor streams per session (`0` = unlimited) |
| `max_bytes`    | Total traffic cap per session, watchdog-enforced (`0` = no byte quota) |
| `ttl_secs`     | Session lifetime (`0` = no expiry)         |

The dashboard's MAX BYTES control posts the resolved byte count:
a unit select (B/KB/MB/GB/TB), a logarithmic range slider (top reach 16 TiB),
preset chips (64 MB … 1 TB), an exact number input in the selected unit
(fractional allowed, e.g. `2.5` GB → 2684354560 bytes), and an Unlimited
checkbox that posts `0`. Per-field Unlimited checkboxes on sessions, streams,
and TTL also post `0` to disable their respective caps. In the token table,
`0` limits render as "Unlimited" / "no expiry".

New tokens created without explicit limits inherit the operator's **default
token limits** (Settings → Defaults); the same defaults are advertised in
`/api/config` and the client heartbeat override can be set there too.

### 4.5 Settings

`/settings` is the operator's runtime control surface (SQLite-backed; CLI
flags remain startup defaults — settings override at runtime and persist
across restarts).

- **Instance** — instance name (rendered in the sidebar brand, page titles
  and footer) and an optional support URL (footer link).
- **Security**
  - Session TTL (hours, default 24): lifetime of the HMAC session cookie
    issued at login.
  - Dashboard IP allowlist: exact IPs or CIDRs (IPv4/IPv6), one per line.
    When non-empty, operator and portal requests from other peers get 403.
    The broker sees the **direct peer** — behind a reverse proxy, list the
    proxy's IP. Saving a list that excludes your own IP is refused with an
    inline warning (self-lockout guard).
  - **Two-factor authentication (TOTP)**: enable from the settings page —
    a QR code + base32 secret are shown, and the secret is only stored after
    you verify a 6-digit code. Once enabled, `/login` requires the code.
    Disabling requires a valid code. Operator-only (clients stay
    password-only).
- **Alerts**
  - Webhook URL + optional HMAC secret: the broker POSTs JSON events
    (`session_started`, `session_ended` with usage totals, `quota_hit`,
    `server_full`) fire-and-forget; when a secret is set, requests carry
    `X-DDNS-Signature: sha256=<hex hmac>` over the raw body.
  - Email alerts: session started/ended notifications to the operator
    (requires SMTP configuration; a warning is shown at save time if SMTP
    is not configured).
- **Defaults** — default limits for newly created tokens
  (`0` = unlimited) and the advertised client heartbeat (ms; empty = client
  default). The client's own `DDNS_HEARTBEAT_MS` env remains authoritative.

### 4.6 Client portal — API keys

The tenant portal (`/portal`) includes an **API** page at `/portal/api-keys`
(Account → API). It lists the client's scoped API keys (name, scopes,
created, last used, revoked) and creates new ones with the default scopes
`tunnels:read`. A newly created key's raw secret (`ddns_` + 40
hex chars) is shown **once** — copy it before leaving the page; afterwards
only its sha256 digest exists. Keys can be revoked (with confirmation), after
which the key stops authenticating against `/api/v1/*`.

### 4.8 Token system (commercial metering)

Every client account carries a **token balance** used to meter tunnel traffic.
The accounting model:

- **1 token = 1 MiB transferred** or **100 HTTP requests** (a delta debits the
  floor `bytes/1MiB + requests/100`).
- Each plan has a **monthly allowance** (`bandwidth_monthly / 1 MiB`): Free
  5 GiB → 5120 tokens, Pro 200 GiB → 204800 tokens, Business unlimited
  (`bandwidth_monthly = 0` → no metering). The allowance is credited
  idempotently per `(account, month)` on first use, never on signup.
- **Soft warnings** fire at **80%** and **95%** of the monthly allowance
  consumed (deduped per cycle via `soft80_at` / `soft95_at`).
- **Hard cutoff** at **zero** balance: the registration gate blocks new
  sessions and the quota watchdog tears down live ones once the balance is
  exhausted.
- **Top-up packs**: a one-time checkout credits 100,000 tokens
  unset). Webhook `checkout.session.completed` credits idempotently per
  session id.
- **Admin credit**: `/clients/{id}/credit` credits an arbitrary amount
  (ledger kind `admin_credit`).

`token_movements`), with a best-effort cache hot counter for the enforcement
fast path. The tenant can inspect the balance in the portal overview's
"Token balance" card or via `GET /api/v1/tokens`.
---

## 5. REST API

All `/api/*` endpoints require the operator session cookie; without it they
return `401 session required`. Errors: `400` validation, `404` missing,
`409` name/subdomain/hostname in use, `500` internal.

| Method   | Path                            | Body / notes |
| -------- | ------------------------------- | ------------ |
| GET/POST | `/api/tokens`                   | create: `{name, max_sessions?, max_streams?, max_bytes?, ttl_secs?}` → `201 {id, secret}` (secret shown once; `0` = unlimited) |
| POST     | `/api/tokens/{id}/disable`      | |
| POST     | `/api/tokens/{id}/enable`       | |
| DELETE   | `/api/tokens/{id}`              | |
| GET/POST | `/api/domains`                  | create: `{name, kind: "apex"\|"custom"}` |
| PUT/DELETE | `/api/domains/{id}`           | PUT: `{name, kind}` |
| POST     | `/api/domains/{id}/activate`    | activates an apex (transactional) |
| GET/POST | `/api/tunnels`                  | create: `{name, token_id, domain_id, subdomain?, custom_hostname?, options?}` |
| PUT/DELETE | `/api/tunnels/{id}`           | PUT: same shape as create |
| POST     | `/api/tunnels/{id}/toggle`      | enable/disable |
| GET      | `/api/sessions`                 | live sessions |
| POST     | `/api/sessions/{slug}/kill`     | |
| GET      | `/api/cert`                     | cert source/domains/status/expiry |
| GET      | `/api/config`                   | domain, public_port, max_sessions, watchdog, default limits, cert |
| POST     | `/api/settings/password`        | `{current, new}` |

`TunnelView` includes resolved `token_name` / `domain_name` plus the full
`options` object (`HttpOptions`, serde-defaults on read).

### 5.1 Tenant API keys & `/api/v1` endpoints

Separate from the operator-session `/api/*` surface above, the tenant
`/api/v1/*` surface authenticates with a scoped **API key** (Bearer
`ddns_<key>`), never the operator session cookie. Clients create keys in the
portal (`/portal/api-keys`); the raw key is shown exactly once and only its
sha256 digest is stored.

| Method | Path         | Body / notes |
| ------ | ------------ | ------------ |
## 6. Operations

### 6.1 Request rate limiting

Visitor HTTP requests through a tunnel are rate-limited with a **fixed-minute
cache sliding window**, enforced only when the cache is configured
(`DDNS_REDIS_URL`). The per-tenant limit is the account's plan
`rate_limit_rpm` (`0` = unlimited → no limiting).

- **Window**: one UTC minute; two counters per request — per-tunnel
  (`rl:{account}:{tunnel}:{minute}`) and per-source-IP
  (`rl:{account}:ip:{ip}:{minute}`) — so one abusive source can't drain a
  tenant's whole tunnel budget, and one tenant can't hide behind many IPs.
- **Per-tunnel window key is the session slug**: tunnels without a fixed-slug
  profile (the default) draw a fresh random slug on every registration, so
  each reconnect is a new per-tunnel window; a fixed slug that is occupied
  yields `NoSubdomainAvailable` and a retry, not a random fallback. The per-IP
  window (`rl:{account}:ip:{ip}:{minute}`) still binds the client, so the
  degradation is bounded per-IP, never unlimited.
- **On limit**: `429 Too Many Requests` + `Retry-After: <seconds>` (time to
  the next minute boundary), plain-text body "rate limit exceeded".
- **Cache required**: without `DDNS_REDIS_URL` the broker runs in SQLite-only
  mode and does **no rate limiting** (traffic passes through). A downed cache
  fails **open** — requests are never throttled by a cache outage (warned
  once, mirroring the token hot-counter degradation).

### 6.2 Metrics `/metrics`

`GET /metrics` serves metrics text exposition
(`text/plain; version=0.0.4; charset=utf-8`) and is **operator-gated** — no
operator session → `401`. The exported metrics are `ddns_*`:

| Metric | Type | Meaning |
| ------ | ---- | ------- |
| `ddns_requests_total{tunnel="<slug>"}` | counter | visitor HTTP requests, per tunnel |
| `ddns_bytes_total` | counter | total bytes transferred (both directions) |
| `ddns_active_sessions` | gauge | live tunnel sessions |
| `ddns_ratelimit_429_total` | counter | requests rejected with `429` by the limiter |
| `ddns_tokens_debited_total` | counter | tokens debited from account balances |

### 6.3 Cache in production

- The Compose file (section 9) ships a `redis:7-alpine` service backing both
rate limiting and the token-balance hot counter. It is in-memory only (no
AOF/RDB) — a restart resets the current minute's counters, which is the
intended fail-open behavior. The broker service sets
`DDNS_REDIS_URL=redis://redis:6379` by default; unset/empty means SQLite-only
mode (no rate limiting). See `deploy/.env.example` and `deploy/README.md`.

---

## 7. Admin

The operator dashboard's **Revenue** and **Aggregates** cards surface the
commercial state; the per-client page (`/clients/{id}`) is where tenant

### 7.2 Tenant limits overrides

`/clients/{id}` → **Limits override** sets a per-account `TokenLimits` that
**replaces the plan's limits wholesale** when present (empty = inherit the
plan). The four fields (`max_tunnels`, `bandwidth_monthly`, `max_clients`,
`rate_limit_rpm`) are optional: a blank field inherits the **plan's** value at
save time, and an all-blank save or the **Clear override** button removes the
override, returning the tenant to live plan inheritance. `0` means unlimited.

- **Snapshot note**: a tenant with an override always uses it
  (`effective_limits` returns the override, never the plan), so later plan
  edits do **not** reach tenants carrying an override. Separately, a connecting
  token's limits are snapshotted at registration from `effective_limits`; a
  plan or override change affects only **new** sessions — live sessions keep
  the limits they registered with until they reconnect.

## 8. Security model

- **TLS** — rustls; exactly one source: static PEM, ACME TLS-ALPN-01 (apex
  only), or `--dev` self-signed (writes `<db>.dev-ca.pem`).
- **Operator auth** — argon2-hashed admin password (setup runs once,
  conditional write), optional TOTP 2FA (RFC 6238; required at login once
  enabled), stateless HMAC session cookie (24 h default, configurable),
  login rate limited per IP; optional dashboard/API IP allowlist (CIDR,
  403 when non-matching).
- **Client auth** — tokens argon2-verified per registration, registration
  rate limited per IP; server-wide session cap.
- **Event webhooks** — JSON POSTs signed with `X-DDNS-Signature`
  (HMAC-SHA256 over the raw body) when a secret is configured; verify the
  signature before acting on the payload.
- **Visitor routing** — DB-free: exact custom-host match (registry map), then
  `slug.<active-apex>` from a cached string. Dashboard/operator routes are
  never reachable through a faked tunnel `Host` header; `/api/*` always 401s
  without a session even under a tunnel host.
- **Per-tunnel hardening** — basic auth / bearer key / IP whitelist /
  header control (section 4.3). Credentials are stored in the tunnel's
  `options` JSON in the DB — restrict DB access accordingly.
- **Quotas** — per-session byte cap, stream cap, TTL enforced by a watchdog;
  excessive use can be killed from the dashboard.

---

## 9. Container production deployment

See [`deploy/README.md`](deploy/README.md): `docker compose up -d --build`
with `deploy/.env` (`DDNS_DOMAIN` + exactly one cert source), named-volume
SQLite persistence, non-root runtime, seeded client download binary, and a
healthcheck on `/install.sh`.

Quick reference:

```bash
cd deploy
cp .env.example .env        # set DDNS_DOMAIN; choose cert source
mkdir certs                 # place fullchain.pem + privkey.pem (static option)
docker compose up -d --build
```

---

## 10. Troubleshooting

| Symptom | Cause / fix |
| ------- | ----------- |
| Client log: repeated reconnects, random slugs | Token has no enabled tunnel profile; or the fixed slug is occupied by another session (`NoSubdomainAvailable`); or token limits exhausted. |
| Visitor: `no such tunnel` | Apex not activated (activate it in `/domains`) or the client isn't connected. |
| Visitor: 401 + `WWW-Authenticate: Basic realm="ddns"` | The tunnel's basic auth is set; supply credentials. |
| Visitor: 403 | Source IP outside the tunnel's `ip_whitelist`. |
| `curl: (60) SSL certificate problem` | Dev setup: pass `--ca-pem <db>.dev-ca.pem` to the client, or `curl -k` / browser dev-CA install for testing only. |
| `--resolve` not resolving | On some curl builds use `-H "Host: my-app.example.com"` against `https://127.0.0.1:8443/` instead. |
| Windows rebuild: `Access is denied` removing `ddns-server.exe` | A broker process is still running — stop it first. |
| Client registered, no traffic | Check `want_http`/`want_tcp` flags match the local target; check the tunnel options pipeline isn't rejecting (403/401). |

---

## 11. Status and limits (v1 / Phase A)

- DNS-01 ACME issuance (wildcard certs), SNI per-domain cert resolution
  (`cert_store.rs`), and CNAME/TXT/A validation flows are **deferred to
  Phase B**; `validation_status`/`cert_status` stay `pending`/`absent`.
- Client multi-target forwarding (`--local` repeat) accepts one target per
  scheme in v1; more targets are deferred.
- The client `--name` flag is accepted but not transmitted (wire contract
  frozen).

## 12. Related docs

- Phase A implementation plan:
  `docs/superpowers/plans/2026-08-12-operator-domains-tunnels-glass-ui.md`
- Design spec + Phase B deferrals:
  `docs/superpowers/specs/2026-08-12-operator-domains-tunnels-glass-ui-design.md`
