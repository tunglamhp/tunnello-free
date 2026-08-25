# Service Templates

Pre-configured tunnel profiles for common services. Pick a template, replace
the placeholder values with your own, and run the command.

Each template shows: the local service port, the tunnel command to run, and
how to connect from outside.

---

## SSH (port 22)

Expose a Linux/Mac SSH server.

```sh
# On the server running SSH:
ddns --token <SECRET> --server https://<broker> --tcp 22

# From outside, connect via P2P helper:
ddns connect https://<sub>.<domain>
ssh user@127.0.0.1 -p <forwarded-port>

# Or via relay (public URL):
ssh -o ProxyCommand="openssl s_client -connect <sub>.<domain>:443" user@<sub>.<domain>
```

---

## RDP — Windows Remote Desktop (port 3389)

Expose a Windows Remote Desktop server.

```sh
# On the Windows machine running RDP:
ddns.exe --token <SECRET> --server https://<broker> --tcp 3389

# From outside, connect via P2P helper on another machine:
ddns connect https://<sub>.<domain>
# Then open mstsc.exe → connect to 127.0.0.1:<forwarded-port>
```

---

## VNC (port 5900)

Expose a VNC remote desktop server (TightVNC, TigerVNC, RealVNC).

```sh
ddns --token <SECRET> --server https://<broker> --tcp 5900
```

---

## MySQL / MariaDB (port 3306)

Expose a database for secure remote administration.

```sh
ddns --token <SECRET> --server https://<broker> --tcp 3306

# Connect remotely via P2P helper:
mysql -h 127.0.0.1 -P <forwarded-port> -u admin -p
```

---

## PostgreSQL (port 5432)

```sh
ddns --token <SECRET> --server https://<broker> --tcp 5432

psql -h 127.0.0.1 -p <forwarded-port> -U postgres
```

---

## Home Assistant (port 8123)

Expose your Home Assistant web UI.

```sh
ddns --token <SECRET> --server https://<broker> --port 8123

# Access from anywhere:
open https://<sub>.<domain>
```

---

## Plex Media Server (port 32400)

Expose Plex web UI for remote access behind CGNAT.

```sh
ddns --token <SECRET> --server https://<broker> --port 32400

open https://<sub>.<domain>/web
```

---

## MQTT Broker (port 1883)

Expose an MQTT broker (Mosquitto, EMQX) for IoT devices.

```sh
ddns --token <SECRET> --server https://<broker> --tcp 1883

mosquitto_pub -h 127.0.0.1 -p <forwarded-port> -t "sensors/temp" -m "22.5"
```

---

## Web Server (port 80 or 3000/8000/5000)

Expose any HTTP(S) web application.

```sh
ddns --token <SECRET> --server https://<broker> --port 3000

open https://<sub>.<domain>
```

---

## Docker container port

Expose a specific Docker container's published port.

```sh
# Find the published port:
docker port <container-name>

# Tunnel it:
ddns --token <SECRET> --server https://<broker> --port <published-port>
```

---

## Protecting tunnels with a PIN code

Any HTTP tunnel can require visitors to enter a PIN before access
(inspired by Pangolin's resource authentication):

1. Open the operator dashboard → your tunnel → **Options**.
2. Set **PIN code** (e.g. `2468`) and save.
3. Visitors now see an "Access Code Required" page; entering the correct PIN
   (via `https://<sub>.<domain>?pin=2468`) sets a 24-hour session cookie.

Other per-tunnel protections available in Options:

| Option | Effect |
|---|---|
| Basic auth | `WWW-Authenticate: Basic` username/password prompt |
| Key auth (Bearer) | Requires `Authorization: Bearer <secret>` header |
| PIN code | Browser PIN entry page + 24h cookie session |
| OIDC login | Requires broker OIDC env; visitor logs in via your identity provider |
| Email OTP | Visitor receives a 6-digit code by email before access |
| IP whitelist | Only listed IPs/CIDRs may connect |
| Add/remove headers | Rewrite request headers before forwarding |

All options compose: e.g. IP whitelist **and** PIN gives two independent gates.

---

## Live request debugger

Every tunnel has a live request log (last 100 requests, metadata only — never
bodies). Open it from the dashboard session table → **Debug**, or directly at
`/debug/<slug>` while logged in as operator.

Shows: time, method, path, status, duration, peer IP.

**Body capture + replay** (off by default): enable **Debug body capture** in
the tunnel's Options to record request/response bodies (first 4 KiB,
`Authorization`/`Cookie` headers redacted). The debug page then offers
per-request **Replay** to re-send a captured request through the tunnel.

---

## Resource Policies (option presets)

Save a tunnel's HTTP options as a named preset and reuse it:

1. Dashboard → **Policies** → enter a name + options JSON
   (e.g. `{"pin_auth":"1234","ip_whitelist":["10.0.0.0/8"]}`).
2. Apply the same JSON to any tunnel's Options form.

Policies are stored in the broker database and audited (`policy.save`,
`policy.delete` in the Activity log).

---

## UDP services (DNS, game servers, WireGuard)

Expose a UDP service (broker needs `--udp-port`, client uses `--udp`):

```sh
# Broker side (one-time) — shared port; the FIRST datagram of each flow
# must start with the tunnel slug + a newline:
ddns-server --domain <domain> --udp-port 5353

# ...or dedicated per-tunnel ports (no prefix needed):
ddns-server --domain <domain> --udp-route mydns=5353 --udp-route backup=5354

# Client side:
ddns --token <SECRET> --server https://<broker> --udp 53

# Test with dig (via the P2P helper or direct UDP to the broker):
dig @<broker-host> -p 5353 example.com
```

Notes:
- One UDP "flow" per visitor address; flows idle out after 30 s.
- Datagrams up to 64 KiB; larger ones are dropped (like real UDP).
- Multi-tenant: the shared port routes by the `<slug>` prefix on the first
  datagram; `--udp-route` gives a tunnel its own port with no prefix.
