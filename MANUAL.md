# DDNS Tunnel Broker — Operator Manual (Free Edition)

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

> Free edition note: billing, plans UI, Stripe, token packs, and portal
> payments remain private-edition only. This manual documents the public
> broker and client surface only.

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
  --acme-email EMAIL      ACME automatic certificates. Default provider manual
                          validates via TLS-ALPN-01 on :443 (apex only). With
                          --acme-provider cloudflare|porkbun the broker
                          validates via DNS-01 TXT records and obtains one
                          certificate covering DOMAIN + *.DOMAIN (tunnels
                          included) — no inbound validation port needed
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
  --acme-provider NAME    DNS-01 provider: manual (default) | cloudflare | porkbun
  --acme-cf-token TOKEN   Cloudflare API token (zone-level; DNS edit)
  --acme-cf-zone ZONE     Cloudflare zone id for --domain
  --acme-porkbun-key KEY  Porkbun API key
  --acme-porkbun-secret SECRET
                          Porkbun API secret
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
- `validation_status` / `cert_status` are stored and displayed. With a
  DNS-01 ACME provider (Cloudflare/Porkbun) the broker issues a wildcard
  certificate covering `*.apex` itself; otherwise point `*.apex` at the
  broker and supply a static wildcard cert (see `deploy/README.md`).

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
