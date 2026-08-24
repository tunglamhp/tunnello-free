# Tunello system design

Tunello keeps the existing TLS/WSS tunnel protocol for public customer traffic
and adds an optional WireGuard network for operator control-plane access. This
avoids breaking existing `ddns` clients while giving the administrator a
private path for SSH, dashboard access, and emergency operations.

```mermaid
flowchart LR
    U[Public visitor] -->|HTTPS / WSS (relay fallback)| B[Tunello broker]
    U <-->|WebRTC DTLS data channel (P2P)| C[Customer ddns client]
    C -->|TLS + WebSocket control| B
    B -.->|SDP / ICE signaling| C
    B --> R[(SQLite state)]
    B --> K[(Redis hot path)]
    C --> L[Local customer HTTP/TCP service]
    O[Operator laptop] -->|WireGuard UDP 51821| W[Private admin network]
    W --> S[SSH / private admin access]
    W --> B
```

## Runtime boundaries

| Boundary | Public surface | Protection |
|---|---|---|
| Customer data plane | `8443/tcp` by default, tunnel hostnames | TLS, WSS, tunnel token, per-plan quotas |
| Customer free portal | `/portal/*` free workflows | Client session cookie and role middleware |
| Operator control plane | SSH and optional private admin path | WireGuard network, operator cookie, optional 2FA/IP allowlist |
| Durable state | SQLite in `broker-data` | Docker volume, backups, container non-root runtime |
| Hot enforcement state | Redis | Private Compose network; fail-open only for cache-backed limits |

## Request flow

1. A customer client opens an outbound TLS/WSS connection to the broker and
   authenticates with a tunnel token.
2. The broker allocates a session, snapshots effective limits, and multiplexes
   HTTP/TCP streams without dialing into the customer network.
3. Visitors reach the broker through the public hostname; the broker forwards
   streams over the already-open client connection.
4. The broker records usage in SQLite and uses Redis for rate-limit and token
   hot counters when configured.
5. The optional WireGuard profile is separate from the data path. It creates a
   private operator network and does not expose Redis or replace TLS for public
   tunnels.

## P2P data plane

When NAT allows, browser visitors bypass the broker's data path entirely: the
broker serves a small connector page whose Service Worker negotiates a WebRTC
data channel (`DTLS`-encrypted) straight to the customer client, which bridges
it to the local HTTP service. The broker stays in the control plane only —
serving the connector page, relaying SDP/ICE signaling, issuing short-TTL
tickets, and metering the session from the client's periodic `UsageReport`
over the control WebSocket. Byte quotas still apply: the broker accrues
reported P2P bytes into the same per-session counters the watchdog enforces,
so an over-quota P2P session is killed exactly like a relay session.

The relay path remains as automatic fallback for failed hole-punches (no
WebRTC/Service Worker support, ICE timeout, ticket error, or quota kill).

Native visitors take the same path with `ddns connect <sub>`: the helper
opens a WebRTC data channel labeled `"tcp"` and negotiates it through the
existing `/__p2p/signal` `hello` flow (no token, no tunnel registration). The
`"tcp"` label is the only mode discriminator — the browser connector uses
`"http"` — and the short-TTL ticket still gates the client. There is no
separate `p2p_connect_req` matchmaking message: the design spec's §4 table
lists it as a Phase 2 option, but the implementation reuses the `hello` flow
instead. On punch failure the helper prints the broker relay address and
exits; only the broker's self-hosted STUN (UDP 3478) must be reachable from
the helper.

**Known limitation — tunneled-app WebSockets.** A Service Worker cannot
intercept WebSockets opened by the tunneled application itself, so those ride
the existing broker relay path (only HTTP(S) fetches use the P2P channel).
This is acceptable because app WebSockets are typically low-bandwidth control
traffic. To force the relay path for any request — e.g. a client that needs
broker-measured bytes or has trouble with the SW — send the
`X-Tunnello-Relay: 1` header; the broker then skips the connector page and
relays the request as before.

## VPS deployment shape

The single deploy bundle contains the source checkout, Compose files, scripts,
certificate mount, and this design document. The default stack is broker plus
Redis. The optional WireGuard service is enabled explicitly:

```bash
docker compose up -d --build
docker compose --profile wireguard up -d
```

The host port is `8443` by default and the WireGuard port is `51821/udp`.
Both are configurable in `deploy/.env`; the broker still listens on container
port `443` internally.

The generated WireGuard peer files are stored in the `wireguard-config` volume.
Copy the operator peer configuration to the administrator device, then restrict
SSH and any private admin proxy to the WireGuard subnet at the VPS firewall.

## Visibility and entitlement policy

Free customer workflows remain public through the client portal. Paid controls

operator middleware. Client-side paid navigation and checkout routes are not
registered. A paid entitlement can still be granted manually by the operator,
and its limits are enforced at tunnel registration.