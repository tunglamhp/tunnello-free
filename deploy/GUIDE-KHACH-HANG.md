# Using the DDNS Tunnel — customer guide

> DDNS is a **tunnel** service that exposes a service running on your machine
> (web server, API, SSH…) to the internet at a fixed address:
> **`https://<slug>.<your-domain>`** — no static IP, no router port forwarding,
> no separate VPS needed. You only run a small program (`ddns`) on the machine
> that hosts the service.

---

## 1. Create an account

1. Open **`https://<your-domain>/portal/signup`**
   (replace `<your-domain>` with the service domain, e.g. `https://tunnel.example.com/portal/signup`).
2. Enter email + password (8+ characters), then verify your email via the link that was sent.
3. Log in at **`https://<your-domain>/portal/login`**.

After logging in you manage everything yourself in the **portal**: create
tokens and view your allowance — no need to contact the operator.

---

## 2. Install the `ddns` client

### Linux (x86_64 / aarch64)

One command (replace `https://<your-domain>` with the real domain):

```bash
DDNS_SERVER=https://<your-domain> curl -fsSL https://<your-domain>/install.sh | sh
# creates the ./ddns file in the current directory
```

Or download it manually: `https://<your-domain>/download/ddns-x86_64-unknown-linux-musl`
(rename to `ddns`, `chmod +x ddns`). Check: `./ddns --help`.

### macOS / Windows

- **macOS**: download `https://<your-domain>/download/ddns-x86_64-apple-darwin` (or `...-aarch64-apple-darwin` on Apple Silicon).
- **Windows**: download `https://<your-domain>/download/ddns-x86_64-pc-windows-msvc.exe` and rename it to `ddns.exe`.
- If the matching build is not on the download page, ask the operator to add a build for your platform.

---

## 3. Create a tunnel token

1. Log in to the portal → **Tokens** (or from Overview).
2. Click **Create token**, give it a name (e.g. `web-server`), and pick limits (sessions / streams / bandwidth / duration).
3. **Copy the secret string** (`tok_...`) right away — it is shown **once**.
   This token is your connection key; anyone who has it can open your tunnel — keep it secret.

> Tokens created from the **portal** belong to your account and count against
> your token's limits (number of tunnels, bandwidth, request rate). Tokens
> created by the operator (dashboard) are standalone and do not count against
> your account.

---

## 4. Run a tunnel

### HTTP web service (e.g. a local web server on port 8080)

```bash
./ddns --token tok_XXXXXXXX --server https://<your-domain> --port 8080
```

Done — reach your service at:

```
https://<slug>.<your-domain>
```

(the program prints the full address when connected, e.g. `https://drowsy-fox-4d.tunnel.example.com`).

### Multiple services / flexible targets

```bash
# forward several schemes at once:
./ddns --token tok_XXX --server https://<your-domain> \
       --local http://127.0.0.1:8080 \
       --local tcp://127.0.0.1:5432

# direct TCP (e.g. SSH on port 22):
./ddns --token tok_XXX --server https://<your-domain> --tcp 22
```

Main options:

| Option | Meaning |
|---|---|
| `--token` | Connection token (required) |
| `--server` | Broker URL (default `https://tunnel.example.com`) |
| `--port N` | Local HTTP port to forward |
| `--tcp N` | Local TCP port to forward |
| `--local URL` | Target as `http://host:port` or `tcp://host:port` (repeatable) |
| `--ca-pem FILE` | Custom CA when the broker uses its own CA |

> Long-running on Linux: `nohup ./ddns ... > ddns.log 2>&1 &` or configure
> systemd (a `ddns.service` unit with `Restart=always`).

---

## 4b. Connect in one minute — Quickstart (one line)

After you registered and created a token + tunnel, the fastest way to open a
tunnel is the **Quickstart** button on the portal's **Tunnels** page:

1. **Register** an account (§1) and log in to the portal.
2. **Create a token** (§3), then create a tunnel under **Tunnels** (enter the local port, e.g. `8080`).
3. Click the **Quickstart** button on the tunnel row you just created.
4. **Copy** the command that appears and paste it into the terminal on the machine running the service:

```bash
curl -sSL "https://<your-domain>/install.sh?code=sc_XXX&port=8080" | sh
```

The command installs the client and opens the tunnel with your own token +
port — the secret `tok_...` never appears. The `sc_...` code is single-use and
expires after **7 days**; refresh the Quickstart page to get a new one.

---

## 5. Self-service portal

| Section | Purpose |
|---|---|
| **Overview** | Token meter (balance, monthly allowance, % used, 80%/95% warning marks), live per-tunnel gauges (5 s) |
| **Tokens** | Create / disable / delete tokens |
| **API keys** | Create API keys (`ddns_...`, shown once) to call `/api/v1/*` |

**API** (API key, header `Authorization: Bearer ddns_...`):

```
GET  /api/v1/me              → account info + token balance
GET  /api/v1/tokens          → balance + token history
GET  /api/v1/tunnels         → tunnel list + live numbers
GET  /api/v1/usage?since=    → daily usage series
```

---

## 6. Allowances & how tokens are counted

- **1 token = 1 MiB of tunnel traffic OR 100 requests** (per your plan).
- Each month your account is topped up according to your plan.
- At **80% / 95%** of the monthly allowance the system sends email/warnings.
- When **tokens run out**: tunnels are cut off and new tunnel registration is refused until the operator tops up your allowance or the next cycle renews it.
- Rate limit: requests/minute per token; exceeding it returns `429` with `Retry-After` (retry after N seconds).

---

## 7. Common problems

| Problem | Fix |
|---|---|
| `error: token rejected` / cannot connect | Wrong token (recheck `tok_...`), token deleted/disabled, or your account ran out of tokens (see §6) |
| `429 Too Many Requests` | Over your token's request rate; wait `Retry-After` seconds and retry |
| Page shows "no such tunnel" | Client not connected (check client logs) or wrong slug |
| `slug is occupied` (NoSubdomainAvailable) | The slug is used by another session; end the old session or wait a few minutes |
| Tunnel keeps dropping | Check network/local firewall, or the token allowance is nearly out; run the client with `Restart=always` |
| Verification email never arrives | Check spam; contact the operator (SMTP may not be configured) |

Need more help? Contact the service operator (system owner) with: your account
name, token ID, and the client log output.
