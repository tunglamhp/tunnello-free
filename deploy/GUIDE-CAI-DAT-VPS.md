# Tunello Broker — VPS install & management guide (Ubuntu 24.04 / 26.04)

> For the **system owner / operator**. Customers use `GUIDE-KHACH-HANG.md`.
> The broker is the self-hosted tunnel platform: customers run the `ddns`
> client on their machine and reach their local services at a fixed
> hostname `https://<slug>.<your-domain>`.

---

## 1. Prerequisites (required)

| Item | Requirement |
|---|---|
| VPS | Ubuntu 24.04 or 26.04, at least 1 vCPU / 1 GB RAM (2 GB recommended), public IP |
| Domain | You control the DNS, e.g. `tunnel.example.com` |
| DNS | `A` (or AAAA) records pointing **both** of these at the VPS IP: |
| | `tunnel.example.com` → VPS IP (dashboard, ACME certificates) |
| | `*.tunnel.example.com` → VPS IP (every customer tunnel) |
| Firewall | Open **443/tcp** by default (HTTPS + WSS — clean URLs without a port) and **3478/udp** (STUN P2P). Only open **8443/tcp** when you set `DDNS_PUBLIC_PORT=8443` (443 is taken); **51821/udp** when WireGuard is enabled; **80** when HTTP-01/redirect is enabled |
| Swap | On a 1 GB RAM VPS add 1–2 GB swap before building (Rust builds need RAM) |

Set up DNS **first** and let the records propagate (minutes → hours depending on the DNS).

---

## 2. One-click install

The whole `deploy/` folder is a self-contained package. Move it to the VPS
(`scp`, `rsync`, or a repo clone), then run **a single command**:

```bash
# option A — copy the deploy/ folder to the VPS from your machine:
scp -r deploy/ root@VPS-IP:/opt/ddns-deploy/

# option B — clone the repo and enter deploy/:
git clone <your-repo-url> /opt/ddns && cd /opt/ddns/deploy
```

On the VPS:

```bash
cd /opt/ddns-deploy
./deploy.sh
```

When run as `root`, the script automatically:

1. **Installs the container engine + Compose plugin** when missing (via `get.docker.com`; disable with `DDNS_INSTALL_DOCKER=0`).
2. Asks for the **domain** and the **certificate source** (1 = static PEM, 2 = ACME (automatic), 3 = dev — never in production).
3. Writes `deploy/.env` (chmod 600, holds secrets — **never commit it**).
4. Clones the source (when there is no checkout), builds the image, and starts the `broker` + `redis` stack.
5. Prints the first-run steps.

> **Non-interactive** (for CI/scripts): provide the env vars up front, e.g.
> `DDNS_DOMAIN=tunnel.example.com DDNS_ACME_EMAIL=admin@example.com ./deploy.sh`
> (or set `DDNS_CERT=/certs/fullchain.pem DDNS_KEY=/certs/privkey.pem` and place the PEM files in `deploy/certs/`).

### 2.1. Certificate source — pick exactly one

1. **Static PEM (recommended)** — place `fullchain.pem` + `privkey.pem` in `deploy/certs/` (read-only mount). Renew externally (certbot, your CA) then `docker compose restart broker`.
2. **ACME (automatic certificates)** — set `DDNS_ACME_EMAIL`. Two validation methods:
   - **TLS-ALPN-01** (default, provider `manual`): the broker issues and renews for the **apex**; port 443 must be open.
   - **DNS-01** (`DDNS_ACME_PROVIDER=cloudflare|porkbun` with credentials in `.env`): the broker writes the `_acme-challenge` TXT records itself and obtains **ONE** certificate for the apex + `*.domain` — the dashboard and every tunnel hostname get valid HTTPS, auto-renewed and hot-swapped without a restart, and no inbound validation port is needed.

> The ACME account/certificate cache lives in `/data/acme_cache` on the
> `broker-data` volume, so it survives container restarts/rebuilds. Back this
> volume up together with the SQLite DB.
3. `DDNS_DEV=1` — self-signed cert, **test only**.

### 2.2. First run — secure it immediately

```bash
# open the dashboard:
#   https://tunnel.example.com/setup   → set the admin password (8–128 chars, argon2)
#   afterwards: https://tunnel.example.com/ → log in
```

In **Settings** (`/settings`):

- **Security** → enable **TOTP 2FA**; set a **session TTL**; add your IPs to the **dashboard IP allowlist** (CIDR; empty = allow everyone — fill it in).
- **Alerts** → webhook URL + secret (events signed with `X-DDNS-Signature`) and/or email alerts.
- **Defaults** → default token limits applied to new tokens.

---

## 2.3. Run at home with a dynamic IP (bridge mode, no VPS)

Works when your modem is in **bridge mode** so the home router receives a real
**dynamic public IPv4** (no CGNAT — check with `curl -4 -s https://api.ipify.org`,
the IP must not be in `100.64.0.0/10` or `10.0.0.0/8`). The whole design stays
the same (P2P, STUN 3478).

1. **Modem bridge mode** → the home router dials PPPoE itself (use the ISP user/pass) → the WAN is a dynamic public IP.
2. **Port forwarding on the router**: `443/tcp` + `3478/udp` → the broker machine.
   Check whether the ISP blocks inbound 80/443 (if blocked: change `DDNS_PUBLIC_PORT` — URLs will then show the port).
3. **DDNS via the Porkbun API** — `deploy/ddns-porkbun.sh` (ships with the repo):
   ```bash
   cp deploy/ddns-porkbun.sh /opt/ddns-deploy/
   cp deploy/systemd/ddns-porkbun.{service,timer} /etc/systemd/system/
   # add to deploy/.env (or the unit environment):
   #   DDNS_PORKBUN_API_KEY=...   DDNS_PORKBUN_SECRET=...   (porkbun.com/account/api)
   #   DDNS_PORKBUN_HOSTS="tunnel.example.com *.tunnel.example.com"
   systemctl daemon-reload && systemctl enable --now ddns-porkbun.timer
   ```
   The timer runs every 5 minutes: when the IP changes it updates the apex +
   wildcard A records (TTL 300). Manual check: `/opt/ddns-deploy/ddns-porkbun.sh --dry-run`.
4. **Wildcard TLS** — when the broker uses ACME DNS-01 (Cloudflare/Porkbun) the `*.domain` certificate is already covered. If you need a wildcard with a different DNS provider, issue it externally with **certbot + the dns-porkbun plugin** (shares the API key):
   ```bash
   sudo apt install certbot python3-certbot-dns-porkbun
   sudo certbot certonly --dns-porkbun --dns-porkbun-credentials /etc/porkbun.ini \
     -d tunnel.example.com -d '*.tunnel.example.com'
   # copy fullchain.pem + privkey.pem into deploy/certs/ (set DDNS_CERT/DDNS_KEY)
   # renew: certbot renew + docker compose restart broker (see README §Certificates)
   ```
5. **When the IP changes**: DNS updates within ≤ ~5 minutes → clients reconnect on
   their own (1–30 s backoff); live WebRTC P2P sessions drop → a visitor reload
   reconnects (falls back to relay, then P2P again).

> Note: a power/network outage at home stops the service temporarily — no SLA
> like a VPS. If the ISP does not allow bridge mode / a public IP, use Oracle
> Cloud Always Free (4 OCPU/24 GB, $0) or Cloudflare Tunnel (relay-only, loses P2P).

## 2.4. Failover: home primary + VPS backup (run in parallel)

When the home server goes down or loses network, the **backup VPS takes over
within ~5–10 minutes** (3 failed checks × 60 s + DNS TTL 300 s). Both brokers
run side by side; Porkbun DNS is the switch.

**Roles:**
- **Home (primary):** the broker runs normally; every 5 minutes it pushes a SQLite snapshot
  (`.backup` via sqlite3 in the alpine container) + certs to the VPS.
- **VPS (backup):** a monitor health-checks `https://<home-ip>/install.sh` directly
  (via `--resolve`, not DNS). When home fails ≥ 3 times in a row → restore the latest
  snapshot → `docker compose up -d` → point DNS (apex + wildcard) at the VPS IP.
  When home recovers → point DNS back home → stop the VPS stack.

**Install home (`deploy/failover/home-push-backup.sh`):**
```bash
cp deploy/failover/home-push-backup.sh /opt/ddns-deploy/
cp deploy/failover/systemd/home-push-backup.{service,timer} /etc/systemd/system/
# deploy/.env: DDNS_VPS_SSH=root@<vps-ip>  DDNS_VOLUME=<real volume name>
ssh-copy-id root@<vps-ip>          # once: home key -> VPS
systemctl daemon-reload && systemctl enable --now home-push-backup.timer
```

**Install VPS (`deploy/failover/vps-monitor.sh`):**
```bash
# deploy/.env on the VPS: DDNS_HOME_IP, DDNS_VPS_IP, DDNS_DOMAIN,
# DDNS_PORKBUN_API_KEY/SECRET + the failover variables
cp deploy/failover/vps-monitor.sh /opt/ddns-deploy/
cp deploy/failover/systemd/vps-monitor.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vps-monitor
```

**Testing:** `vps-monitor.sh --once` (one pass), `--force-to-vps` / `--force-to-home`
(manual flip); `ddns-porkbun.sh get` (see where DNS points).

**Limits (be upfront):** up to ~5 minutes of the newest data can be lost (between
two pushes); live sessions drop on a flip → clients reconnect (backoff) to the
broker DNS now points at; tokens come from the last snapshot; P2P
sessions need a visitor reload. The VPS normally does **not** run the stack
(monitor only) — it starts on failover and stops when home recovers.

## 3. Optional configuration (deploy/.env)

| Variable | Meaning |
|---|---|
| `DDNS_DOMAIN` | Apex domain (required) |
| `DDNS_CERT` / `DDNS_KEY` | PEM paths inside the container (`/certs/...`) |
| `DDNS_ACME_EMAIL` | ACME email (cert source #2) |
| `DDNS_ACME_PROVIDER` | `manual` (TLS-ALPN-01, apex) / `cloudflare` / `porkbun` (DNS-01, apex + wildcard) |
| `DDNS_ACME_CF_TOKEN` / `DDNS_ACME_CF_ZONE` | Cloudflare API token (zone-scoped, DNS edit) + zone id |
| `DDNS_ACME_PORKBUN_KEY` / `DDNS_ACME_PORKBUN_SECRET` | Porkbun API key + secret |
| `DDNS_SKIP_DNS_CHECK` / `DDNS_SKIP_FIREWALL` | Disable the `deploy.sh` DNS/firewall preflight (=1) |
| `DDNS_HTTP_LISTEN=0.0.0.0:80` | Enable the HTTP listener (301→HTTPS + HTTP-01) |
| `DDNS_MAX_SESSIONS` | Concurrent session limit (default 256) |
| `DDNS_BASE_URL` | External URL used in emails (verification/reset) |
| `DDNS_REDIS_URL` | Default `redis://redis:6379` (rate limit + hot counter). Set it **empty** (`DDNS_REDIS_URL=`) for SQLite-only — **keep the redis service** (the broker `depends_on` it), only drop the URL. A dead cache fails open — traffic is never blocked |
| `DDNS_SMTP_*` | SMTP for verification/reset/alert emails (missing → only dev-mode link logging) |

After editing, re-run: `./deploy.sh --update`.

---

## 4. Day-to-day management

```bash
cd /opt/ddns-deploy            # the deploy/ folder

./deploy.sh --update           # update: git pull + rebuild + restart

docker compose ps              # status (broker must be "healthy", redis "healthy")
docker compose logs -f broker  # real-time logs
docker compose logs --tail 200 broker   # last 200 lines

# restart the broker (e.g. after swapping a static PEM cert):
docker compose restart broker
```

### Backup & restore (IMPORTANT — data lives in the `broker-data` volume)

```bash
# backup (brief stop for a consistent snapshot):
docker compose stop
docker run --rm -v ddns_broker-data:/data -v $PWD:/backup \
  alpine tar czf /backup/ddns-data-$(date +%F).tar.gz -C /data .
docker compose start

# restore:
docker compose stop
docker run --rm -v ddns_broker-data:/data -v $PWD:/backup \
  alpine sh -c 'rm -rf /data/* && tar xzf /backup/ddns-data-YYYY-MM-DD.tar.gz -C /data'
docker compose start
```

> The volume is named `<project>_broker-data` (default `ddns_broker-data` when run
> from `deploy/`). Verify the exact name with `docker volume ls`.

### Monitoring

- **Healthcheck**: `/install.sh` is polled every 30 s (compose healthcheck).
- **Metrics**: `https://tunnel.example.com/metrics` (operator session required; `ddns_*` text exposition). Example scrape:

```yaml
scrape_configs:
  - job_name: ddns-broker
    metrics_path: /metrics
    scheme: https
    bearer_token: <operator-session-cookie-string>   # or front with a basic-auth proxy
    static_configs: [{ targets: ["tunnel.example.com"] }]
```


---

## 5. Sales operations (what customers see)

| Page | Purpose |
|---|---|
| `https://domain/portal/signup` | Customer account registration |
| `https://domain/portal/login` | Customer login + self-service |
| Portal → API keys | Create API keys (`ddns_...`, shown once), access `/api/v1/*` |
| `/tokens`, `/tunnels`, `/domains` (operator) | Tokens, tunnel profiles, activate the apex + DNS guidance |


---

## 6. Abuse response

When you receive an **abuse report** (phishing, malware, spam…), follow this order:

1. **Log the report** — record the reported tunnel slug/URL/domain (e.g. `https://<slug>.tunnel.example.com`).
2. **Identify the account** — the dashboard shows the `Peer IP` of the direct client connection in the session list. Use the slug/token to find the account in SQLite (`/data/ddns.db`, `broker-data` volume):

   ```sql
   SELECT account_id FROM tunnels WHERE subdomain = '<slug>';   -- from the reported slug
   SELECT owner_id   FROM tokens  WHERE id        = 't-xxxx';   -- from the token id (t-xxxx)
   ```

   To run it in the container (the broker image has no `sqlite3`): `docker run --rm -v ddns_broker-data:/data alpine sh -c 'apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /data/ddns.db'` — replace `ddns_broker-data` with the real volume name (`docker volume ls`).
3. **Stop it immediately** (in this order — kill first, because Suspend does not close running sessions):
   - **Kill session** — the kill button on the dashboard (disconnects the live session right away).
   - **Suspend** — `/clients/{id}` → **Suspend** (downgrades to Free/expired trial, blocks new registrations; does **not** close running sessions — handled by the kill step).
   - **Disable the token** — `/tokens`, disable the offending token.
   - **Delete the tunnel profile** — if needed (prevents the slug from being re-registered).
4. **Investigate** — evidence available: `Peer IP` on live sessions, per-account `usage_daily` (daily bandwidth/requests), and token movement history (`token_movements`). The peer IP is the direct socket address the broker sees; behind a reverse proxy it may be the proxy's IP — cross-check the proxy logs.
5. **Proactive controls already in place**:
   - Per-token rate limiting (`rate_limit_rpm`) — **needs Redis**: SQLite-only mode (empty `DDNS_REDIS_URL`) has no rpm enforcement, deliberately fail-open (never blocks traffic).
   - Monthly bandwidth caps (`bandwidth_monthly`).
   - Soft warnings at **80% / 95%** of the allowance.
   - **Hard cut** when tokens run out (new tunnel registration refused, running sessions closed).
   - Per-tunnel auth: basic auth, bearer keys, IP whitelists (CIDR) — configured in the tunnel editor.
6. **Legal notes** — collect the minimum (per-account usage + token movements); the broker does **not** log client IPs or traffic content. Verify before locking an account to avoid false positives (e.g. an impersonated customer / stolen token).

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Healthcheck failing | `docker compose logs broker`; usually port 443 closed on the firewall, or a bad certificate |
| Visitor gets "no such tunnel" | Apex not activated (`/domains`), client not connected, or the DNS wildcard does not point at the VPS |
| Customer gets 429 | Per-token rate limit (`rate_limit_rpm`); retry after `Retry-After`; raise the limit or override it |
| Customer gets 402 / token rejected | Token exhausted → top up (payment gateway) or operator `Credit tokens` |
| Client "slug occupied" (`NoSubdomainAvailable`) | The fixed slug is held by another session; wait or change the slug |
| Port 443 is taken | Set `DDNS_PUBLIC_PORT=8443` in `deploy/.env` (URLs then show `:8443`); the container port stays 443 |
| Cache does not come up | `docker compose ps` — redis must be healthy first (depends_on service_healthy) |
| Certificate expired (static PEM) | Replace the files in `deploy/certs/` → `docker compose restart broker` |

---

## 8. Upgrading from an older release

```bash
cd /opt/ddns-deploy
./deploy.sh --update     # pull new code + rebuild + restart (keeps .env and the volume)
```

No manual migrations — the schema upgrades itself via `ensure_columns` at
startup. Old records are not back-billed for tokens (the monthly allowance
starts at the first metering after the upgrade).

---

## 9. References

- `README.md` — architecture overview + container layout.
- `GUIDE-KHACH-HANG.md` — customer guide (send this file to them).
- `MANUAL.md` (in the repo) — full technical manual: §4 dashboard/portal, §5 REST API, §6 Operations, §7 Admin.
