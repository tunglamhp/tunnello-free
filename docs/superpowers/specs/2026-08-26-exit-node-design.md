# Exit Node (`ddns up --exit-node`) — Design (2026-08-26)

Status: DRAFT — awaiting operator review before implementation.
Scope: Phase 4 of the Visitor Auth Expansion umbrella
(`2026-08-26-visitor-auth-expansion-design.md`). Largest phase; this spec is
implementation-ready but intentionally NOT started until approved.

## 1. Goal

`ddns up --exit-node` turns the visitor's machine into a full-tunnel client:
a TUN interface captures the device's default traffic and routes it through
the P2P data channel to the client machine (the "exit"), which dials the
internet on the visitor's behalf. The broker stays out of the data plane
(same as Phases 2–3).

Non-goals first (§9), because this phase's blast radius is the visitor's
entire network stack.

## 2. Architecture decision records

### ADR-1: TUN driver — `tun` crate (wintun on Windows) over tap-windows6

| Option | Pros | Cons |
|---|---|---|
| **`tun` crate (chosen)** | L3 TUN; wintun backend on Windows (WireGuard's driver — signed, modern, kernel-bypass ring buffer); `/dev/net/tun` on Linux; one API both platforms; async support | wintun needs the `wintun.dll` shipped beside the exe (bundled at build; load at runtime) |
| tap-windows6 | NDIS legacy, widely deployed | L2 (Ethernet frames — we'd carry ARP/MTU overhead we don't need); old driver model; extra signing burden; no benefit for an IP-only tunnel |

Decision: `tun` crate. L3-only matches our payload (IP packets), avoids ARP
handling, and wintun is the same driver Tailscale/WireGuard ship on Windows.

### ADR-2: IP stack — user-space `smoltcp` over kernel NAT

| Option | Pros | Cons |
|---|---|---|
| **`smoltcp` user-space stack (chosen)** | Cross-platform (zero per-OS firewall/NAT scripting); terminates TCP/UDP flows in-process — maps cleanly onto our per-flow data-channel framing (Tailscale's "userspace netstack" model); testable in-process (loopback e2e like Phases 2–3) | CPU cost of user-space TCP (acceptable: single-digit Gbps ceiling is far above our data-channel throughput); smoltcp is no_std-flavored — integration care needed |
| Kernel NAT (iptables/PF/wintun NAT) | Kernel TCP performance | Per-platform scripting + admin divergence; the CLIENT would receive raw NATed packets and need its own reverse-NAT — a second kernel dependency on the exit machine; untestable in-process |

Decision: smoltcp on the VISITOR side only. The visitor's TUN feeds IP
packets into smoltcp, which terminates flows and hands us **streams**
(TCP) / **datagrams** (UDP) — the exact shapes our existing framing
already carries. The EXIT side dials real internet sockets; no IP stack
there.

### ADR-3: Framing — reuse REQ/RESP/DATA/CLOSE + Phase-3 UDP semantics

- TCP flow: visitor smoltcp accepts a flow → helper sends `REQ(id, "host:port\0")`
  (destination in the REQ payload — one byte extension of the current
  empty-REQ convention) → client dials `host:port` directly (exit behavior)
  → bidirectional `DATA` → `CLOSE`.
- UDP flow: same as Phase 3 (`REQ(id)` announce, `DATA` = one datagram with
  a `host:port\0` destination header on the first datagram of the flow,
  `CLOSE` on idle).
- New opcode NOT required; the only wire change is "REQ may carry a
  destination string", which old bridges ignore safely (they dial their
  fixed local target instead — documented compatibility rule).

## 3. Components

### Visitor side (`ddns up --exit-node`, new subcommand `up`)

1. **TUN device** — `tun` crate; address `10.111.0.1/30`, MTU **1384**
   (§5). Routes: default via TUN with a **host exception** for the broker
   and the client's observed endpoint (existing connection must survive —
   §7). Windows: `route ADD`; Linux: `ip route` via `netlink` (no shell-out).
2. **smoltcp stack** — `Interface` + `SocketSet` on the TUN fd; DHCP-free
   static config; DNS proxy address `10.111.0.1:53` handed to the OS
   (§6).
3. **Flow pump** — per accepted TCP flow / UDP flow: the data-channel
   framing of §2-ADR-3 over a `"exit"`-labeled channel (one channel for all
   flows, `request_id` = flow id, same 512-stream cap).
4. **DNS leak protection** — the helper sets the TUN interface's DNS to
   `10.111.0.1` and runs a tiny UDP DNS proxy: port 53 on the TUN address →
   one UDP flow to the exit → exit resolves via the system resolver and
   returns the answer. All other port-53 traffic leaving other interfaces is
   dropped by the route exception rules (§7), not silently leaked.
5. **Kill switch** — while `ddns up` runs, a firewall rule (Windows WFP via
   `netsh`; Linux: `iptables -I OUTPUT` mark-based) blocks non-tunnel
   egress. Removed on clean exit AND on crash (best-effort signal handler +
   stale-rule sweep on next start: rules are tagged with a marker comment).

### Exit side (client machine — the tunnel owner's `ddns` gains `--allow-exit`)

1. The tunnel operator opts in per token/tunnel: `--allow-exit` on the
   client CLI sets `want_exit: true` in `Control::Register` (serde default
   false — wire compatible). The broker stores it on the session and
   rejects exit-mode `REQ`s from visitors whose session lacks it (403-style
   `CLOSE` with reason byte).
2. Exit bridge (`p2p.rs`): on `REQ` with a destination → `tokio::net::TcpStream::connect(dest)`
   (TCP) or a UDP socket (UDP) → pump. Egress is the operator's machine —
   the operator has opted in and their existing `http_options`/
   rate-limiting still applies to nothing here (exit traffic bypasses the
   broker), which is exactly why the opt-in is explicit and off by default.

### Broker side

- Carry `want_exit` on `Control::Register`/session (serde default false).
- Metrics: `ddns_exit_flows_active` gauge. Nothing else — the broker never
  sees exit traffic.

## 4. Data flow (happy path, TCP)

```
browser → TUN(10.111.0.1) → smoltcp accepts flow → REQ(id, "1.2.3.4:443\0")
  → data channel ("exit" label) → exit bridge dials 1.2.3.4:443
  → RESP(id) → DATA both ways → CLOSE either side → smoltcp RST/FIN → TUN
```

UDP: same minus RESP; datagrams both directions; idle 30 s reaps the flow.

## 5. MTU

- Data-channel message practical ceiling ≈ 16 KiB (SCTP/DTLS headroom);
  smoltcp TCP MSS on the TUN is what the visitor's apps see.
- **TUN MTU 1384** = 1500 − 116 headroom for outer overhead (IPv6 worst
  case 40 + SCTP/DTLS + framing). Rationale: avoids visitor-side
  fragmentation entirely; matches WireGuard's 1420 conservative posture
  with extra margin for the DTLS-in-SCTP layer. smoltcp advertises MSS =
  MTU − 40 (IPv6) = 1344.
- Exit-side sockets use the system default MTU; no clamp needed (we
  terminate TCP, so each side has its own MSS).

## 6. DNS

- Visitor TUN DNS = `10.111.0.1` (the TUN address). The helper's DNS proxy
  forwards port-53 UDP flows through the tunnel (§3.Visitor-4).
- Leak protection: (a) route exception only for broker/client endpoints —
  all other default traffic, including port 53, goes through TUN;
  (b) kill-switch blocks non-TUN egress; (c) the proxy answers only from
  the tunnel's resolver. IPv6: the helper **disables** IPv6 routes on the
  physical adapter for the session (documented limitation: v1 is IPv4-only
  inside the tunnel; IPv6 traffic is blocked, not leaked — same posture as
  Tailscale's "block rather than leak" v1).
- WebRTC/DTLS itself uses UDP to the broker/client endpoint — that traffic
  is the route exception, never the leak.

## 7. Routing table & admin requirements

| Platform | TUN + route | Kill switch | Admin needed |
|---|---|---|---|
| Windows | wintun adapter; `route ADD 0.0.0.0 MASK 0.0.0.0 10.111.0.1 METRIC 1` + host exceptions for broker/client IPs (`route ADD <ip> <orig-gw> METRIC 1`) | `netsh advfirewall firewall add rule name="tunello-ks" dir=out action=block` (allow-list tunnel process) | **Administrator** (wintun + route + firewall) |
| Linux | `/dev/net/tun`; `ip addr add` + `ip route replace default dev tun0` + host exceptions via `ip route <ip> via <orig-gw>`; netlink via `rtnetlink` crate (no shell-out) | `iptables -I OUTPUT -m mark ! --mark 0x539 -j DROP` + mark tunnel sockets (`SO_MARK`) | **CAP_NET_ADMIN** (root or cap) |

- Original gateway is captured before route changes and restored on exit.
- Crash safety: rules are idempotent + tagged; next `ddns up` start sweeps
  stale rules before installing fresh ones. A `--cleanup` subcommand
  removes leftovers manually.
- The CLIENT (exit) machine needs no admin: it only dials outbound sockets.

## 8. Security analysis

| Risk | Mitigation |
|---|---|
| Visitor routes ALL traffic through an operator machine → traffic visibility | Exit is opt-in by the operator (`--allow-exit`); the visitor chose the tunnel; docs must state "exit sees your traffic metadata (SNI/DNS) and payload unless the app encrypts" |
| Malicious exit tampering | Same trust model as any VPN; out of scope (no E2E crypto added in v1) — documented |
| Open relay (anyone can use a client as exit) | `want_exit` default false; broker enforces per-session; visitor must already hold a valid P2P ticket for that tunnel |
| DNS leak | §6 (a)(b)(c) |
| IPv6 leak | v1 blocks IPv6 egress during exit mode (§6) |
| Kill-switch leaves device offline after crash | Tagged rules + startup sweep + `--cleanup`; documented recovery |
| Route hijack persists after unclean exit | Original gateway recorded + restored; `--cleanup` fallback |
| smoltcp resource exhaustion (flow flood) | 512-flow cap (same as TCP bridge); per-flow buffers bounded (64 KiB); excess flows RST |
| Exit dials internal services of the operator machine (SSRF-style) | Exit bridge refuses destinations that resolve to loopback/link-local/RFC1918 of the EXIT machine (configurable allowlist `--exit-allow-lan`) — default deny |

## 9. Non-goals (v1)

- No IPv6 inside the tunnel (IPv4-only TUN; IPv6 blocked, not leaked).
- No multi-exit / exit selection UI; one exit = the connected tunnel.
- No kill-switch on mobile/platforms beyond Windows/Linux.
- No performance tuning beyond MSS/MTU (no GSO/GRO, no batching).
- No broker visibility into exit traffic (by design).
- macOS/BSD TUN support (the `tun` crate has it; defer testing/docs).
- Split tunneling by app or by CIDR allowlist (default-route only v1; the
  route-exception list is fixed to broker/client endpoints).

## 10. Testing strategy (feeds the plan)

- Pure unit: destination encode/parse in REQ; MTU/MSS math; route-exception
  list builder; kill-switch command generation per platform (command
  objects, not executed).
- In-process integration (no admin): smoltcp loopback — a userspace
  "TUN substitute" (Unix socket pair acting as the device) proves
  TCP flow → REQ(dest) → exit dial → RESP/DATA round-trip, mirroring the
  Phase-2/3 e2e seam pattern.
- Admin-required platform tests (route/firewall) are manual checklists in
  docs, NOT CI (documented limitation).

## 11. Rollout

1. Spec review (this document).
2. Plan: T1 framing (REQ dest + exit bridge), T2 smoltcp visitor stack +
   flow pump, T3 TUN/route/kill-switch platform layer, T4 DNS proxy +
   leak tests, T5 docs/version 0.10.0.
3. Each task TDD; full serial suite + clippy + fmt before every commit.
