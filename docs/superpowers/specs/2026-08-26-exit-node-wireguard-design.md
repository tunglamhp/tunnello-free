# Exit Node via WireGuard — Design (2026-08-26, rev 2)

Status: DRAFT — GATED on operator review (replaces the smoltcp design of
`2026-08-26-exit-node-design.md`, which is superseded and its code reverted
in `refactor: remove userspace TCP exit bridge`).
Scope: Phase 4 of the Visitor Auth Expansion umbrella. Data plane pivots
from a hand-rolled userspace TCP/IP stack to **standard WireGuard** per
operator decision — no custom crypto, no custom IP stack.

Research basis: `docs/research/wireguard-exit-node-best-practices.md`
(nftables anti-spoof, PSK rotation, fwmark kill-switch, DNS leak
prevention, MTU table, verifier checklist).

## 1. Goal

`ddns up --exit-node` routes the visitor device's default traffic through a
standard WireGuard tunnel terminated on the client machine (the exit). The
client NATs egress via nftables. ddns keeps the CONTROL plane: tunnel name
registration, OIDC+OTP auth, and WireGuard peer-key signaling through the
broker. The broker never touches exit traffic.

## 2. Architecture decision records

### ADR-W1: WireGuard data plane implementation — userspace `boringtun` vs kernel WG

| Option | Pros | Cons |
|---|---|---|
| **`boringtun` (userspace, chosen for free edition)** | Pure Rust (Cloudflare's implementation of the WG protocol); zero kernel-driver install — pairs with the `tun` crate for the TUN device; identical behavior Windows/Linux; testable in-process | Userspace throughput below kernel WG (fine: home uplinks) |
| Kernel WG (Linux `wireguard` module + `wireguard-nt` Windows) | Line-rate; `wg-quick` tooling | Driver/dkms install per platform; divergent admin flows; harder CI |

Decision: free edition embeds `boringtun` + `tun` (zero-install, one
binary). The PRIVATE edition may add a kernel-WG backend as deep
customization (out of free scope per the repo-split rule).

### ADR-W2: NAT on the exit — nftables (operator-decided)

The exit machine forwards + masquerades the WG subnet out its WAN:
`nftables` `inet` table with forward-chain `policy drop`, tunnel-source-only
accept, `masquerade` scoped to the WG subnet (research §1.1). Windows exit:
`netsh routing` NAT equivalent (documented, not CI-tested).

### ADR-W3: Key exchange — through the existing ddns control plane

The visitor generates an ephemeral WireGuard keypair **on-device** (the
private key never leaves). The PUBLIC key is registered through the
existing signaling path (`/__p2p/signal` hello gains an optional
`wg_pubkey` field — serde default, wire-compatible). The client adds the
visitor pubkey as a WG peer scoped to the visitor's tunnel IP `/32`
(cryptokey routing — research §1.2), then answers signaling as today.
`want_exit` (already on `Control::Register`, default false) remains the
exit opt-in; the broker rejects exit signaling from sessions without it.

## 3. Components

### Visitor (`ddns up --exit-node` — free edition, minimal surface)

1. **TUN device** via `tun` crate; **MTU 1420** default (research §2.4;
   1412 PPPoE / 1280 fallback are PRIVATE tuning knobs, not free flags).
2. **boringtun session** to the exit's WG endpoint (the client's public
   host:port — already known from tunnel registration).
3. **AllowedIPs `0.0.0.0/0`** + fwmark policy routing (research §2.1) with
   a host exception for the broker/exit endpoints.
4. **Kill-switch (safe default, free)**: fwmark-based egress REJECT
   (research §2.3) so a dead tunnel cannot leak; installed on up, removed
   on down, swept on next start, `--cleanup` for manual recovery.
5. **DNS**: TUN DNS = the exit's tunnel resolver address (research §2.2);
   IPv6 blocked rather than leaked (research §2.2 note).

### Exit (client machine — `ddns --allow-exit`)

1. WG interface `wg0` (boringtun) with the tunnel's WG subnet
   (`10.200.200.0/24` default).
2. Per-visitor peer: `AllowedIPs = <visitor-tunnel-ip>/32` + per-peer PSK
   (research §1.3).
3. nftables NAT + forward policy-drop (ADR-W2) — installed on first exit
   peer, removed when the last one leaves (tagged table, crash-safe sweep).
4. Peer removal: `wg set ... peer remove` / `syncconf` — no tunnel bounce
   (research §1.4).

### Broker

- Relay the `wg_pubkey` in signaling (one field).
- **KEY-AGE TRACKING (gap from research §1.3, closed here)**: the broker
  records the issue time of every visitor WG key registration and enforces
  re-authentication after **180 days** (operator-configurable 1–180 in the
  PRIVATE edition; free ships the 180-day default, no UI). Expired keys
  fail signaling with `error{key_expired}` until the visitor re-registers
  a fresh keypair.
- Metrics: `ddns_exit_peers_active` gauge. No exit traffic visibility.

## 4. Data flow (happy path)

```
ddns up --exit-node
  → visitor keypair (on-device) → hello{wg_pubkey} → broker → client
  → client adds peer (pubkey, /32, PSK) + nftables ready → answer
  → boringtun handshake → default route via WG → traffic NATs out the exit
```

## 5. Security design (from research; each maps to a plan task)

| Control | Source | Where |
|---|---|---|
| Cryptokey routing `/32` per peer | research §1.2 | T2 exit peer add |
| nftables forward `policy drop` + source-scoped NAT | §1.1 | T2 |
| Reverse-path filter (`rp_filter=1`) guidance | §1.2 | T5 docs |
| Per-peer PSK, never reused | §1.3 | T2 |
| **Key-age tracking + forced re-auth (180 d)** | §1.3 GAP | T1 broker |
| `syncconf` peer add/remove without bounce | §1.4 | T2 |
| fwmark policy routing + endpoint roaming | §2.1 | T3 visitor |
| DNS via tunnel resolver + block :53 outside | §2.2 | T3/T4 |
| Kill-switch `OUTPUT ! -o wg0 ! fwmark REJECT` | §2.3 | T3 |
| IPv6 block-not-leak | §2.2 | T3 |
| MTU 1420 explicit (1412/1280 private tuning) | §2.4 | T3 |
| Private keys never leave the generating device | WG model | T1/T2 |

## 6. Threat model deltas vs the smoltcp design

- No custom TCP/IP stack to harden (the reason for the pivot).
- WG protocol provides replay protection + forward secrecy (Noise
  transport, ~2-min session key rotation) — not our code.
- New risks: WG private-key storage on disk (0600, document; TPM-bound
  storage = PRIVATE future), peer-list growth on the exit (bounded by
  tunnel count), broker key-age DB row per visitor (small).

## 7. Repo split (deep-customization rule)

| | FREE (tunnello-free) | PRIVATE (tunnello) |
|---|---|---|
| Exit on/off | `ddns up --exit-node` | same |
| Defaults | MTU 1420, DNS via tunnel, kill-switch on, 180-day key age, deny-LAN | same baseline |
| Tuning | — (not exposed) | split DNS, MTU override, allowed subnets, multi-exit, kernel-WG backend, key-age window |

## 8. Non-goals (v1)

- No IPv6 inside the tunnel (blocked, not leaked).
- No macOS/BSD support (undocumented, untested).
- No multi-exit selection UI; one exit per visitor session.
- No broker visibility into exit traffic.
- No TPM-bound key storage (documented future/private).

## 9. Testing strategy (feeds the plan)

- Unit: key generation + pubkey derivation; peer-config rendering
  (`AllowedIPs /32`, PSK wiring); key-age expiry math; route/kill-switch
  command planners (pure, per-platform); MTU constant.
- Integration (in-process, no admin): boringtun handshake between two
  in-process WG instances over UDP loopback → ping-like payload round-trip
  through the exit's userspace forwarding path (boringtun test pattern).
- Platform (manual checklists, not CI): nftables ruleset, route table
  state, DNS-leak test (`dig whoami.akamai.net`), kill-switch
  (`curl ifconfig.me` must fail when tunnel down), PMTU
  (`ping -M do`), sleep/resume caveat (research §2.3).
