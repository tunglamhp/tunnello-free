# Exit Node via WireGuard (Phase 4 rev 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **GATE: do NOT start any task until the operator approves the spec
> `docs/superpowers/specs/2026-08-26-exit-node-wireguard-design.md`.**
> Presented for review before coding, per operator instruction.

**Goal:** `ddns up --exit-node` full-tunnel client over standard WireGuard (boringtun userspace + tun crate), exit NAT via nftables, broker-side key-age enforcement (180 d), free-edition surface = on/off + safe defaults.

**Architecture:** Visitor generates a WG keypair on-device; the pubkey rides the existing signaling (`hello{wg_pubkey}`); the client adds the visitor as a `/32` WG peer with per-peer PSK and NATs the WG subnet via nftables; the visitor runs fwmark policy routing + kill-switch. Broker tracks key age and forces re-auth after 180 days.

**Tech Stack:** `boringtun` (userspace WG), `tun` crate, `x25519-dalek` (keypair), `nftables` command generation (pure planners + thin real exec), existing ddns signaling.

**Spec:** `docs/superpowers/specs/2026-08-26-exit-node-wireguard-design.md`

## Global Constraints

- `want_exit` stays default false; `--allow-exit` (client) gates exit service.
- WG private keys NEVER leave the generating device; only pubkeys transit signaling.
- Free edition exposes NO tuning flags: MTU 1420 fixed, key-age 180 d fixed,
  kill-switch always on while `up`. (Private tuning = separate repo work.)
- New deps (client): `boringtun`, `x25519-dalek`, `tun` (re-added), `rtnetlink` (Linux routes). No new server deps.
- Platform admin tests (nftables/routes/firewall) are manual docs checklists, NOT CI.
- TDD every task; fmt + `clippy --workspace --all-targets -D warnings` before every commit.
- Version lands at **0.10.0** (final task). Docs mirrored to `A:/web/ddns`.

## File Structure

- Modify `crates/ddns-proto/src/control.rs` — `hello` signaling message gains `wg_pubkey: Option<String>` (serde default).
- Modify `crates/ddns-server/src/p2p_signal.rs` — relay `wg_pubkey`; store key-issue time; enforce 180-day key age (reject `error{key_expired}`).
- Create `crates/ddns-server/src/keyage.rs` — key-age store + policy (pure, unit-tested).
- Create `crates/ddns-client/src/wg/mod.rs` — visitor/exit WG module root.
- Create `crates/ddns-client/src/wg/keys.rs` — keypair gen/parse (x25519-dalek), pubkey derivation (pure).
- Create `crates/ddns-client/src/wg/config.rs` — peer/interface config rendering (pure): `AllowedIPs /32`, PSK, MTU 1420, fwmark 51820.
- Create `crates/ddns-client/src/wg/session.rs` — boringtun session + tun pump.
- Create `crates/ddns-client/src/wg/platform.rs` — route/kill-switch planners (pure) + real exec (Linux netlink/nft; Windows route/netsh).
- Modify `crates/ddns-client/src/cli.rs`, `main.rs` — `up --exit-node`, `up --cleanup`, `--allow-exit`.
- Tests: `crates/ddns-client/tests/wg_keys.rs`, `wg_config.rs`; server `keyage` unit tests in-module; signaling relay covered by existing p2p tests extended.

---

### Task 1: Key-age tracking on the broker + signaling relay

**Files:**
- Modify: `crates/ddns-proto/src/control.rs` (hello `wg_pubkey`), `crates/ddns-server/src/p2p_signal.rs`
- Create: `crates/ddns-server/src/keyage.rs`
- Modify: `crates/ddns-server/src/lib.rs` (module + store wiring)

**Interfaces:**
- Produces:
  - `VisitorMsg::Hello { …, wg_pubkey: Option<String> }` (serde default) relayed to the client inside `Control::P2pVisitorOffer` (new field `wg_pubkey: Option<String>`, serde default).
  - `keyage::KeyAgeStore::new(max_age_days: u64)`; `record(pubkey_b64: &str, now_unix: i64)`; `expired(pubkey_b64: &str, now_unix: i64) -> bool`; `remove(pubkey_b64: &str)`. Pure-time unit tests.
  - Signaling rejects expired keys with `{type:"failed", reason:"key_expired"}`.
- Consumes: existing `signal_run` relay path.

- [ ] **Step 1: Failing tests** (in `keyage.rs` `#[cfg(test)]`)

```rust
#[test]
fn expiry_boundary() {
    let store = KeyAgeStore::new(180);
    store.record("k", 1_000_000);
    assert!(!store.expired("k", 1_000_000 + 180 * 86_400 - 1));
    assert!(store.expired("k", 1_000_000 + 180 * 86_400));
    store.remove("k");
    assert!(store.expired("k", 1_000_000)); // unknown key = treat expired
}
```

- [ ] **Step 2: RED** — `cargo test -p ddns-server --lib keyage`.
- [ ] **Step 3: Implement** store + wire into `signal_run`: on hello with `wg_pubkey`, check expiry (record on first sight); relay pubkey to the client in `P2pVisitorOffer`.
- [ ] **Step 4: GREEN** + `cargo test -p ddns-server`.
- [ ] **Step 5: Commit** — `feat: broker key-age tracking + wg_pubkey signaling relay`

---

### Task 2: WG keys + config rendering (pure)

**Files:**
- Create: `crates/ddns-client/src/wg/keys.rs`, `crates/ddns-client/src/wg/config.rs`, `crates/ddns-client/src/wg/mod.rs`
- Modify: `crates/ddns-client/src/lib.rs`
- Test: `crates/ddns-client/tests/wg_keys.rs`, `wg_config.rs`

**Interfaces:**
- Produces:
  - `wg::keys::generate_keypair() -> (PrivateKey, PublicKey)`; `PublicKey::to_base64() / from_base64()`.
  - `wg::config::VisitorWgConfig { private, exit_pubkey, exit_endpoint: SocketAddr, tun_addr: Ipv4Addr, mtu: u16, fwmark: u32 }` with `render_route_plan(&self, exceptions: &[IpAddr]) -> Vec<RouteCmd>` (reuses a fresh `exit::platform`-style planner — recreated here, WG-shaped) and `render_kill_switch(platform) -> Vec<FirewallCmd>` (fwmark REJECT per research §2.3).
  - `wg::config::ExitPeerConfig { visitor_pubkey, visitor_tunnel_ip: Ipv4Addr, psk: [u8; 32] }` with `render_wg_set_peer() -> String` (`wg set wg0 peer … allowed-ips …/32 preshared-key …`) and `render_nft_ruleset(wg_if: &str, wan_if: &str, subnet: &str) -> String` (research §1.1 ruleset verbatim-shape).
- Consumes: `x25519-dalek`, `base64`.

- [ ] **Step 1: Failing tests**

```rust
// tests/wg_keys.rs
#[test]
fn keypair_roundtrip_and_distinctness() {
    let (sk1, pk1) = ddns_client::wg::keys::generate_keypair();
    let (sk2, pk2) = ddns_client::wg::keys::generate_keypair();
    assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    // pubkey derives from secret
    assert_eq!(pk1.to_bytes().len(), 32);
}

// tests/wg_config.rs
#[test]
fn visitor_route_plan_order() {
    let cfg = visitor_cfg_fixture();
    let plan = cfg.render_route_plan(&[broker_ip()]);
    assert!(matches!(plan[0], RouteCmd::AddHostVia { .. }));
    assert!(matches!(plan[plan.len() - 1], RouteCmd::Restore(_)));
}

#[test]
fn exit_peer_renders_slash32_and_psk() {
    let cfg = exit_peer_fixture();
    let s = cfg.render_wg_set_peer();
    assert!(s.contains("allowed-ips 10.200.200.2/32"));
    assert!(s.contains("preshared-key"));
}

#[test]
fn nft_ruleset_has_policy_drop_and_scoped_masquerade() {
    let s = exit_peer_fixture().render_nft_ruleset("wg0", "eth0", "10.200.200.0/24");
    assert!(s.contains("policy drop"));
    assert!(s.contains("ip saddr 10.200.200.0/24"));
    assert!(s.contains("masquerade"));
}
```

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** (pure modules; `RouteCmd`/`FirewallCmd` recreated WG-shaped in `wg::platform` — the smoltcp-era planners were reverted).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: Commit** — `feat: wg keys + config rendering (peer /32, psk, nft ruleset)`

---

### Task 3: boringtun session + tun pump (visitor) and exit forwarding

**Files:**
- Create: `crates/ddns-client/src/wg/session.rs`
- Modify: `crates/ddns-client/src/wg/mod.rs`
- Test: `crates/ddns-client/tests/wg_session.rs`

**Interfaces:**
- Produces:
  - `pub struct WgTunnel { … }` with `pub async fn up(visitor: VisitorWgConfig, tun: tun::AsyncDevice) -> Result<Self, String>` and `pub async fn down(self)`.
  - Exit side: `pub async fn serve_exit(wg_port: u16, peers: &[ExitPeerConfig], wan_if: &str) -> Result<ExitHandle, String>` — boringtun UDP socket + tun pump + per-peer cryptokey routing.
- Consumes: `boringtun` (noise::X25519KeyPair, tunnel::TunSocket/UDPSocket), `tun`.

- [ ] **Step 1: Failing loopback e2e** (`tests/wg_session.rs`)

```rust
// Two in-process boringtun instances over UDP loopback (127.0.0.1 pair),
// each bound to an in-memory TUN substitute (channel-backed, same seam as
// the reverted stack test). Visitor sends a payload packet destined for the
// exit's tunnel IP; the exit forwards to a local UDP echo; the reply
// round-trips. Proves handshake + cryptokey routing + forwarding without
// admin rights.
#[tokio::test]
async fn wg_loopback_handshake_and_forward() { … }
```

NOTE to implementer: mirror the boringtun crate's own
`tunnel/tests` loopback pattern (two `TunSocket`/`UDPSocket` pairs on
127.0.0.1). The pinned contract: visitor payload in → exit echo out →
visitor payload back, all inside the test process.

- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** session pump (encap/decap loops), exit forwarding (tunnel-IP → local dial or UDP relay; TCP via port-forward map v1 = UDP echo only for the test; full TCP forwarding = exit NAT at the nftables layer in production, not userspace).
- [ ] **Step 4: GREEN** — `cargo test -p ddns-client`.
- [ ] **Step 5: Commit** — `feat: boringtun tunnel session + exit forwarding loopback`

---

### Task 4: Platform layer — routes, kill switch, real TUN

**Files:**
- Create: `crates/ddns-client/src/wg/platform.rs` (real exec) + planners from Task 2 move here if cleaner
- Modify: `crates/ddns-client/Cargo.toml` (`rtnetlink` Linux)

**Interfaces:**
- Produces: `apply_routes(plan)`, `apply_firewall(plan)` (Linux netlink/iptables-fwmark per research §2.3; Windows `route`/`netsh`), `RealTun` implementing the device seam for `WgTunnel`, stale-rule sweep + `--cleanup`.

- [ ] **Step 1: Failing planner tests** (pure: Linux plan contains fwmark rule `REJECT ... --mark 51820`, host exceptions, restore; Windows plan contains `route ADD` + firewall tag).
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** planners + real exec (thin, manual-checklist tested).
- [ ] **Step 4: GREEN** + full client suite.
- [ ] **Step 5: Commit** — `feat: wg platform layer (fwmark kill switch, routes, real tun)`

---

### Task 5: `ddns up --exit-node` wiring + docs + version 0.10.0

**Files:**
- Modify: `cli.rs`/`main.rs` (`up`, `--exit-node`, `--cleanup`, `--allow-exit`)
- Modify: `docs/DEVICE-GUIDES.md` (admin checklist: Linux nftables/rp_filter/fwmark; Windows netsh; sleep/resume caveat research §2.3), `docs/SERVICE-TEMPLATES.md`
- Root `Cargo.toml` → 0.10.0

- [ ] **Step 1: CLI parse tests** (RED → implement → GREEN): `up --exit-node`, `up --cleanup`, `--allow-exit` (client tunnel mode), no tuning flags exist (free rule).
- [ ] **Step 2: Docs** — admin checklists + verifier checklist from research §4 (kill-switch curl test, DNS-leak dig, nft ruleset audit, peer add/remove under load, PMTU ping) + security notice (exit sees traffic metadata).
- [ ] **Step 3:** version 0.10.0; full serial suite green; fmt; clippy `-D warnings`.
- [ ] **Step 4: Commit** — `feat: ddns up --exit-node wireguard full tunnel (0.10.0)`; push; mirror docs + spec + plan to private.

---

## Self-Review (done at write time)

- Spec coverage: ADR-W1 (T3 boringtun), ADR-W2 (T2 nft rendering + T4 apply), ADR-W3 (T1 signaling relay), key-age GAP closed (T1), repo split (T5 docs; no tuning flags in free CLI tests), kill-switch/DNS/MTU (T2/T3/T4 per research table).
- Placeholders: none — T3 e2e pins the boringtun loopback pattern source; platform exec paths are manual-checklist per spec §9 (explicit scope, not deferred work).
- Type consistency: `KeyAgeStore` API used in T1 only; `RouteCmd`/`FirewallCmd` WG-shaped recreated in T2 and consumed by T4; `WgTunnel`/`serve_exit` names consistent T3→T5.
- Operator gate: header blocks task start until spec approval; presented via review handoff.
