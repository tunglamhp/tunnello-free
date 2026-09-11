<p align="center">
  <img src="docs/logo.svg" alt="Tunello" width="96"/>
</p>

<h1 align="center">Tunello Free</h1>

<p align="center"><em>Self-hosted tunnel service. One command on your VPS, one line on your laptop.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
  <a href="https://github.com/tunglamhp/tunnello-free/releases"><img src="https://img.shields.io/github/v/release/tunglamhp/tunnello-free" alt="Release"/></a>
  <img src="https://img.shields.io/badge/version-0.11.0-6f42c1" alt="version 0.11.0"/>
</p>

```
visitor ──https──▶ Tunello broker ◀──wss── ddns-client ──http/tcp──▶ your local app
```

## 1. Install the broker on a VPS (Ubuntu, 1 command)

SSH into the VPS and run:

```bash
curl -sSL https://raw.githubusercontent.com/tunglamhp/tunnello-free/main/install-server.sh | bash
```

The script installs Docker when missing, clones the repo, runs `deploy.sh`, and prints the URL plus the first `/setup` steps. Open that URL in your browser → create the operator account.

Later upgrades: `cd /opt/tunnello/deploy && bash deploy.sh --update`.

### What's new in this release (see CHANGELOG)
- **ACME DNS-01** — set `DDNS_ACME_PROVIDER=cloudflare|porkbun` (with credentials in `deploy/.env`): the broker writes the `_acme-challenge` TXT itself and issues one Let's Encrypt certificate for the apex + `*.domain` — every tunnel hostname gets HTTPS, auto-renewed, no open ports needed.
- **`deploy.sh` preflight** — DNS checks (apex + wildcard) and automatic firewall rules (ufw/firewalld); disable with `DDNS_SKIP_DNS_CHECK=1` / `DDNS_SKIP_FIREWALL=1`.

## 2. Install the client on the machine you want to expose

Dashboard → **Tokens** → create a token → **Quickstart** → copy the command for your machine:

- **Linux / macOS**:
  ```bash
  curl -sSL "https://<broker>/install.sh?code=sc_xxx&port=8080" | sh
  ```
- **Windows (PowerShell)**:
  ```powershell
  irm "https://<broker>/install.ps1?code=sc_xxx&port=8080" | iex
  ```

The command downloads the static `ddns` binary, installs it to PATH, and opens a tunnel to your local service (`localhost:8080`). The tunnel URL is printed at the end of the output.

---

## What's included

- `ddns-proto`, `ddns-client`, `ddns-server` — protocol, tunnel client and broker
- Self-hosted dashboard, custom domains, visitor auth (OIDC / email OTP)
- `/connect`, `/install.sh`, `/install.ps1`, `/download/{file}` one-line client setup

---

## Updating

```bash
# Server
cd /opt/tunnello/deploy && bash deploy.sh --update

# Client
ddns update           # pulls the latest binary from GitHub Releases
```

## Advanced configuration & troubleshooting

See **[MANUAL.md](MANUAL.md)** — STUN port, environment variables, dashboard pages, dev mode, building from source, architecture, debugging.

## Release notes

See **[CHANGELOG.md](CHANGELOG.md)** and the [GitHub Releases](https://github.com/tunglamhp/tunnello-free/releases) page.

## License

[MIT](LICENSE)
