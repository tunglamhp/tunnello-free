# Tunello — production container deployment

Self-hosted tunnel broker. Clients (the static `ddns` binary) open a WSS
connection with a token; visitors reach their local services through fixed
hostnames `<slug>.<domain>`. This folder packages the broker as a
single-container, non-root deployment with a persistent SQLite DB.

## Guides (Tiếng Việt)

- **`GUIDE-CAI-DAT-VPS.md`** — cài đặt + quản lý cho chủ VPS (Ubuntu 24.04/26.04):
  DNS, one-click `deploy.sh`, bảo mật lần đầu, backup/restore, giám sát,
  xử lý sự cố.
- **`GUIDE-KHACH-HANG.md`** — hướng dẫn khách hàng: đăng ký portal, cài client,
  tạo token, chạy tunnel, tự quản lý tài khoản, FAQ.

## Prerequisites

- Docker Engine 24+ (Docker Desktop on Windows/macOS works). On a fresh Ubuntu
  VPS run `./deploy.sh` as root and it installs the container runtime automatically.
- A domain you control, e.g. `tunnel.example.com`.
- DNS wildcard: `*.tunnel.example.com` → your host's public IP (A/AAAA).
  Apex `tunnel.example.com` → same IP (needed for the dashboard, ACME
  TLS-ALPN-01, and apex access).

## Quick start

```bash
cd deploy
cp .env.example .env
# edit .env: set DDNS_DOMAIN, choose a cert source

# Option A — static certificates (recommended):
mkdir certs
# place fullchain.pem + privkey.pem in certs/

# Option B — ACME (automatic certificates) TLS-ALPN-01 (apex only):
#   set DDNS_ACME_EMAIL in .env

docker compose up -d --build
```

The default public port is `443` (`443:443`), so public URLs carry no port
(`https://<slug>.<domain>`). Set `DDNS_PUBLIC_PORT=8443` only when another
web server already owns 443 (URLs then show `:8443`). WireGuard, when
enabled, uses `51821/udp`. Set `DDNS_BASE_URL=https://your-domain` for
emailed links.

First run: open `https://<domain>/setup` and set the operator dashboard
password (8–128 chars; argon2-hashed in the DB). Subsequent visits go to
`/login`.

## What you get

| Path          | Purpose                                        |
| ------------- | ---------------------------------------------- |
| `Dockerfile`  | Multi-stage build (builder, web bundle, runtime; non-root) |
| `entrypoint.sh` | Env-var → CLI flag translation, privilege drop |
| `docker-compose.yml` | Broker + redis services, volumes, healthchecks |
| `.env.example` | Configuration template                        |

Container layout:

- `/data/ddns.db` — SQLite state (tokens, domains, tunnels, admin password).
  Persisted in the named volume `broker-data`. **Back this volume up.**
- `/data/acme_cache` — persistent ACME account and certificate cache when
  `DDNS_ACME_EMAIL` is used. Keep this volume backed up to avoid unnecessary
  re-registration with the certificate authority after a restart.
- `/data/downloads` — client binaries served at `/download/{file}`.
  A static-musl Linux x86_64 client is seeded on first boot
  (`ddns-x86_64-unknown-linux-musl`, matching `/install.sh`). Drop other
  triples (macOS, aarch64, Windows) into the volume to serve them too.
- `/certs` — mounted read-only from `deploy/certs` for `--cert/--key`.
- `/opt/ddns/web/public` — the Dioxus web bundle (`crates/ddns-web`), built in
  the Dockerfile `web` stage and served at `/_assets/*` via `--web-dist`.
  Override with `DDNS_WEB_DIST` in `.env` (default `/opt/ddns/web/public`).
  The flag is only added when that directory exists, so the image also runs
  without the bundle (server-rendered HTML only).

## Certificates

Exactly one source is required (enforced by `entrypoint.sh`):

1. **Static PEM** — `DDNS_CERT`/`DDNS_KEY`. Renew externally (certbot, your
   CA) and `docker compose restart broker`. No auto-reload yet.
2. **ACME (automatic certificates) TLS-ALPN-01** — `DDNS_ACME_EMAIL`. Auto-issued/renewed by
   the broker for the **apex only**. Wildcard `*.domain` certs need DNS-01,
   which is Phase B (deferred); until then, either use a wildcard cert via
   option 1 or point every fixed tunnel subdomain at the broker and let the
   broker present the apex cert (visitor TLS validates against the wildcard
   you must provision yourself).

## Operator dashboard & API

- Dashboard `/`, tunnels `/tunnels`, domains `/domains` (activate an apex +
  DNS guidance), tokens `/tokens` (MAX BYTES slider), settings `/settings`
  (instance branding, session TTL + dashboard IP allowlist, TOTP 2FA,
  alert webhooks/email, default token limits).
- REST API under `/api/*` (session cookie required): tokens, domains
  (CRUD + activate), tunnels (CRUD + toggle), sessions (list/kill), cert
  status, config, password change. See the repo `MANUAL.md`.
  Aggregates, per-client overrides (`/clients/{id}` → Limits override, token

## Rate limiting & metrics

- **Request rate limiting** (cache): visitor HTTP requests through a tunnel
  are rate-limited with a fixed-minute cache sliding window at the tenant's
  plan `rate_limit_rpm`. Requests over the limit get `429 Too Many Requests`
  + `Retry-After` (seconds to the next minute boundary). Enforcement runs only
  when the cache is configured — see `DDNS_REDIS_URL` below.
- **Cache service**: `docker-compose.yml` ships a `redis:7-alpine` service
  (healthcheck `redis-cli ping`) backing rate limiting and the token-balance
  hot counter; the broker `depends_on` it. It is in-memory only (no AOF/RDB) —
  a restart resets the current minute's counters, which is the intended
  fail-open behavior.
- **`DDNS_REDIS_URL`**: the broker service defaults to `redis://redis:6379`.
  To run SQLite-only (no rate limiting, no fast-path token counter), set the
  URL **empty** (`DDNS_REDIS_URL=`) and **keep** the `redis` service in the
  Compose file — the broker `depends_on` it, so removing the service prevents
  startup. A downed cache fails open — traffic is never throttled by a cache
  outage.
- **Metrics `/metrics`**: operator-gated (session cookie) text exposition
  of the `ddns_*` metrics — `ddns_requests_total`, `ddns_bytes_total`,
  `ddns_active_sessions`, `ddns_ratelimit_429_total`,
  `ddns_tokens_debited_total`. See the repo `MANUAL.md` §6.

## Operations

- **Health**: `docker compose ps` — the broker's internal HTTPS health endpoint is polled.
- **Logs**: `docker compose logs -f broker`.
- **Backup**: stop, `docker run --rm -v ddns_broker-data:/data -v $PWD:/backup alpine tar czf /backup/ddns-data.tar.gz -C /data .`, restart.
- **Upgrade**: `git pull && docker compose up -d --build`.
- **TLS checks**: `docker compose exec broker wget -qO- --no-check-certificate https://127.0.0.1:443/`.

## Security notes

- The broker drops to an unprivileged `ddns` user (`setpriv`) after
  preparing `/data`; bind mounts of certs are read-only.
- Tokens are argon2-hashed; registration and login are per-IP rate-limited.
- Optional operator TOTP 2FA, configurable session TTL, and a dashboard/API
  IP allowlist (Settings → Security). Webhook alerts are HMAC-signed
  (`X-DDNS-Signature`) when a secret is configured.
- Per-tunnel visitor hardening: HTTP basic auth, bearer key auth, IP
  whitelist (exact IP or CIDR), header add/remove/rewrite, optional
  preflight passthrough — configure in the tunnel editor.
- Keep port 80 disabled (`DDNS_HTTP_LISTEN` unset) unless you need HTTP-01
  or HTTP→HTTPS redirects.

## Dev smoke test (no real domain)

```bash
docker run --rm -p 8443:443 \
  -e DDNS_DOMAIN=test.local -e DDNS_DEV=1 \
  -e DDNS_LISTEN=0.0.0.0:443 -e DDNS_PUBLIC_PORT=443 \
  -e DDNS_DB=/data/ddns.db -e DDNS_DOWNLOAD_DIR=/data/downloads \
  -v ddns-smoke:/data ddns-broker:latest
# open https://localhost:8443/setup (accept the self-signed dev CA)
```

## One-click deploy (recommended)

This folder is self-contained. The release bundle is named `tunnello-vps/`;
upload that one folder to the VPS and run:


```bash
cd deploy
./deploy.sh          # as root: auto-installs the container runtime if missing, asks for the
                     # domain + cert source, clones the source, builds,
                     # starts, prints the first-run steps
```

- The script detects a repo checkout when run from `deploy/` inside a clone;
  otherwise it clones the source from `DDNS_REPO_URL` (or prompts).
- Non-interactive: `DDNS_DOMAIN=… DDNS_ACME_EMAIL=… ./deploy.sh`.
- Updates: `./deploy.sh --update` (git pull + rebuild + restart).
- Settings are stored in `deploy/.env` (chmod 600) — never commit it.

## Deploy to a VPS (step by step)

**Home + VPS failover**: run the broker at home (bridge mode, dynamic IP —
see `GUIDE-CAI-DAT-VPS.md` §2.3) and keep this VPS as the automatic backup
(§2.4): `deploy/failover/vps-monitor.sh` watches the home broker and flips
the Porkbun DNS to this VPS when home dies; the home broker pushes DB
snapshots + certs every 5 minutes (`deploy/failover/home-push-backup.sh`).
**1. DNS** (before anything else):
- `*.tunnel.example.com` → your VPS public IP (A/AAAA). This is what visitor
  traffic and fixed subdomains resolve to.
- `tunnel.example.com` (apex) → the same IP. Needed for the dashboard and
  for ACME TLS-ALPN-01.

**2. Firewall** — allow inbound:
- `443/tcp` — HTTPS and WSS (default; also needed for ACME TLS-ALPN-01).
- `3478/udp` — WebRTC ICE STUN (P2P data plane).
- `51821/udp` — only when the WireGuard profile is enabled.
- `8443/tcp` — only when you set `DDNS_PUBLIC_PORT=8443`.
- `80/tcp` — only if you enable `DDNS_HTTP_LISTEN` (HTTP-01 challenges or
  HTTP→HTTPS 301). Keep it closed otherwise.

**3. Get the code on the VPS**:
```bash
git clone <your-repo-url> ddns && cd ddns/deploy
cp .env.example .env      # edit: DDNS_DOMAIN + one cert source
```

**4. Certificates** — pick exactly one:
- **Static PEM (recommended)**: `mkdir certs` and place `fullchain.pem` +
  `privkey.pem` there (mount is read-only). Renew externally and
  `docker compose restart broker`.
- **ACME (automatic certificates) (apex only)**: set `DDNS_ACME_EMAIL=you@example.com`
  (TLS-ALPN-01; port 443 must be reachable).

**5. Start**:
```bash
docker compose up -d --build     # first build compiles the web bundle (slow once)
docker compose ps                 # healthcheck on /install.sh; wait for healthy
```

**6. First run — secure it**:
- Open `https://tunnel.example.com/setup` → set the admin password.
- `/settings` → **Security**: enable TOTP 2FA, set a session TTL, and add
  your IP(s) to the dashboard allowlist (remember: the broker sees the
  direct peer — list your proxy's IP if you front it with one).
- `/settings` → **Instance**: set the instance name; **Alerts**: add a
  webhook URL + secret (events are HMAC-signed) if you want notifications.
- Create a token, then point a `ddns` client at it.

**7. Day-to-day**:
```bash
docker compose logs -f broker        # logs
docker compose up -d --build         # upgrade (git pull first)
# Backup (stop → tar the volume → start):
docker compose stop
docker run --rm -v ddns_broker-data:/data -v $PWD:/backup \
  alpine tar czf /backup/ddns-data-$(date +%F).tar.gz -C /data .
docker compose start
```

**8. Troubleshooting**:
- `no such tunnel` on visitors → apex not activated (`/domains`) or the
  client isn't connected; DNS wildcard must point at the VPS.
- Healthcheck failing → `docker compose logs broker`; port 443 not open on
  the firewall is the usual cause.
- Client registration rejected → `--max-sessions` cap or token limits;
  check `/api/config`.
