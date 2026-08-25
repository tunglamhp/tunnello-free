# Visitor UDP Helper (Phase 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ddns connect <sub> --udp PORT` — a native visitor UDP forwarder over the P2P WebRTC data channel, mirroring the TCP helper: binds `127.0.0.1:0`, prints the forwarded port, prepends the `<slug>\n` prefix on each flow's first datagram (shared-port routing wire format), relays datagrams to the client's local UDP service.

**Architecture:** The helper opens a `"udp"`-labeled data channel through the existing `/__p2p/signal` hello flow (same `connect_p2p_channel` seam as TCP). The client gateway routes `"udp"` channels to a new `bridge_udp_channel` that dials the tunnel's local UDP target and pumps datagrams with the existing `REQ`/`DATA`/`CLOSE` framing (`request_id` = flow id; one flow per visitor address). The helper binds a local UDP socket, allocates a flow per remote address, announces it with an empty `REQ`, prepends `<slug>\n` to the flow's first datagram, and prints `Forwarding UDP 127.0.0.1:<port>`.

**Tech Stack:** Rust 2024, existing webrtc-rs data-channel plumbing (`p2p.rs`), existing frame codec (`OP_REQ`/`OP_DATA`/`OP_CLOSE`), tokio UdpSocket. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-26-visitor-auth-expansion-design.md` §Phase 3

## Gap Analysis (server-side components check — per request)

**Server side: nothing missing.**
- `/__p2p/signal` is label-agnostic: the `hello` flow relays any offer; the client's gateway picks the bridge by channel label. A `"udp"` label needs zero broker changes.
- The broker's `udp_bridge` (shared public port, slug-prefix routing) belongs to the RELAY path; the P2P path keeps the broker out of the data plane entirely. The two paths coexist.

**Client side: three missing pieces, all built here.**
1. `p2p.rs`: `BridgeMode` is `{Http, Tcp}` and `bridge_for_label("udp")` currently falls into the HTTP bridge (wrong). → `BridgeMode::Udp` + `bridge_udp_channel`.
2. `cli.rs`: `Command::Connect` has no UDP field; `--udp PORT` is unparseable for `connect`.
3. `connect_p2p.rs`: TCP-only (`bind_listener` + `run_pumps`). → `bind_udp_socket` + `run_udp_pumps`.

## Design decisions (pinned)

- **Framing:** reuse `REQ`/`DATA`/`CLOSE`; `request_id` = flow id. Empty `REQ` announces a flow; `DATA` carries one datagram verbatim; `CLOSE` ends a flow (idle or socket error). No new opcodes — the wire format stays compatible.
- **Slug prefix:** the helper prepends `<slug>\n` to the FIRST datagram of EVERY flow (spec: shared-port routing wire format). The client bridge strips exactly `<slug>\n` when the first datagram starts with it (it knows the slug) and forwards the remainder. This is lossless for generic UDP services (DNS never sees the prefix) while keeping the prefix on the wire for a future relay path that routes by slug.
- **Flow lifecycle:** helper allocates a flow id per remote `SocketAddr` (counter from 1). Client bridge maps flow id → connected `UdpSocket`. Idle reaping: helper sends `CLOSE` after 30 s without traffic on a flow; the bridge drops the socket on `CLOSE`/error.
- **Local target:** the client bridge dials `target` (the tunnel's UDP target from `--udp` on the CLIENT side, same `LocalTarget` the TCP bridge uses).

## Global Constraints

- No new opcodes, no wire-format changes to `REQ`/`DATA`/`CLOSE`.
- `ddns connect <sub> --udp PORT` must not change TCP-helper behavior (`ddns connect <sub>` without `--udp` stays TCP).
- TDD every task; `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -q -- -D warnings` clean before each commit.
- Work from repo root (`A:/web/ddns-free`, branch `main`); version bump to **0.9.0** in the final task; mirror docs to `A:/web/ddns`.

## File Structure

- Modify `crates/ddns-client/src/p2p.rs` — `BridgeMode::Udp`, label mapping, `bridge_udp_channel`, `strip_slug_prefix` helper + unit tests.
- Modify `crates/ddns-client/src/cli.rs` — `Command::Connect { udp: Option<u16> }`, parse `--udp PORT`.
- Modify `crates/ddns-client/src/main.rs` — dispatch `Connect` with `udp`.
- Modify `crates/ddns-client/src/connect_p2p.rs` — `bind_udp_socket`, `run_udp_pumps` (flow table, prefix, idle reaper).
- Test files: `crates/ddns-client/tests/p2p.rs` (bridge unit tests), `crates/ddns-client/tests/connect_p2p.rs` (loopback e2e UDP round-trip).

---

### Task 1: `BridgeMode::Udp` + `bridge_udp_channel` + prefix helper

**Files:**
- Modify: `crates/ddns-client/src/p2p.rs`
- Modify: `crates/ddns-client/tests/p2p.rs` (unit tests)

**Interfaces:**
- Produces:
  - `pub enum BridgeMode { Http, Tcp, Udp }`; `bridge_for_label("udp") == BridgeMode::Udp` (unchanged for `"tcp"`/other).
  - `pub fn strip_slug_prefix<'a>(datagram: &'a [u8], slug: &str) -> &'a [u8]` — strips leading `<slug>\n` when present, else returns the input.
  - `async fn bridge_udp_channel(dc: Arc<dyn DataChannel>, target: LocalTarget, tx_count: Arc<AtomicU64>, rx_count: Arc<AtomicU64>, subdomain: String) -> Result<(), String>` — same visibility pattern as `bridge_tcp_channel` (private, called from `handle_visitor_offer`'s dispatch).
  - Dispatch in `handle_visitor_offer`: `BridgeMode::Udp => bridge_udp_channel(...)`.

- [ ] **Step 1: Write the failing tests** (in `tests/p2p.rs`)

```rust
#[test]
fn udp_label_maps_to_udp_bridge() {
    assert!(matches!(bridge_for_label("udp"), BridgeMode::Udp));
    assert!(matches!(bridge_for_label("tcp"), BridgeMode::Tcp));
    assert!(!matches!(bridge_for_label("http"), BridgeMode::Udp));
}

#[test]
fn strip_slug_prefix_strips_only_matching() {
    assert_eq!(strip_slug_prefix(b"myslug\nping", "myslug"), b"ping");
    assert_eq!(strip_slug_prefix(b"other\nping", "myslug"), b"other\nping");
    assert_eq!(strip_slug_prefix(b"ping", "myslug"), b"ping");
    // partial prefix (slug without newline) must NOT strip
    assert_eq!(strip_slug_prefix(b"myslug", "myslug"), b"myslug");
}
```

(Imports: extend the existing `use ddns_client::p2p::{...}` list with `BridgeMode`, `strip_slug_prefix`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ddns-client --test p2p`
Expected: FAIL — `BridgeMode::Udp` / `strip_slug_prefix` missing.

- [ ] **Step 3: Implement**

`p2p.rs`:
```rust
pub enum BridgeMode { Http, Tcp, Udp }

pub fn bridge_for_label(label: &str) -> BridgeMode {
    match label {
        "tcp" => BridgeMode::Tcp,
        "udp" => BridgeMode::Udp,
        _ => BridgeMode::Http,
    }
}

/// Strip a leading `<slug>\n` (the visitor helper's shared-port routing
/// prefix). Returns the input unchanged when the prefix does not match.
pub fn strip_slug_prefix<'a>(datagram: &'a [u8], slug: &str) -> &'a [u8] {
    let mut expected = slug.as_bytes().to_vec();
    expected.push(b'\n');
    datagram.strip_prefix(&expected).unwrap_or(datagram)
}
```

`bridge_udp_channel` (same shape as `bridge_tcp_channel`, datagram semantics):
```rust
async fn bridge_udp_channel(
    dc: Arc<dyn DataChannel>,
    target: LocalTarget,
    tx_count: Arc<AtomicU64>,
    rx_count: Arc<AtomicU64>,
    subdomain: String,
) -> Result<(), String> {
    // Wait for the channel to open (same loop as bridge_tcp_channel).
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(DataChannelEvent::OnClose) | None => return Ok(()),
            _ => {}
        }
    }
    tracing::info!(%subdomain, "p2p udp visitor joined");

    let udp_addr = match &target {
        LocalTarget::Udp(port) => format!("127.0.0.1:{port}"),
        other => return Err(format!("udp bridge requires a udp target, got {other:?}")),
    };

    let mut flows: HashMap<u32, Arc<tokio::net::UdpSocket>> = HashMap::new();
    let mut upstream: JoinSet<(u32, Vec<u8>)> = JoinSet::new();

    loop {
        tokio::select! {
            // Reap finished upstream readers: forward each datagram as DATA.
            Some(Ok((flow_id, datagram))) = upstream.join_next() => {
                tx_count.fetch_add(datagram.len() as u64, Ordering::Relaxed);
                send_frame(&dc, OP_DATA, flow_id, &datagram).await?;
            }
            ev = dc.poll() => match ev {
                Some(DataChannelEvent::OnMessage(msg)) if !msg.is_string => {
                    let Some(frame) = decode_frame(&msg.data) else { continue; };
                    match frame.opcode {
                        OP_REQ if frame.payload.is_empty() => {
                            let id = frame.request_id;
                            if flows.contains_key(&id) { continue; }
                            let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
                            if sock.connect(&udp_addr).await.is_err() {
                                send_frame(&dc, OP_CLOSE, id, &[]).await?;
                                continue;
                            }
                            flows.insert(id, sock.clone());
                            let rx = rx_count.clone();
                            upstream.spawn(async move {
                                let mut buf = [0u8; 65_535];
                                loop {
                                    match sock.recv(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            rx.fetch_add(n as u64, Ordering::Relaxed);
                                            upstream_yield(id, buf[..n].to_vec()).await;
                                        }
                                    }
                                }
                                (id, Vec::new())
                            });
                            // NOTE: the upstream task must RETURN datagrams via
                            // JoinSet; see `upstream_yield` below — a task cannot
                            // both read the socket and push into its own JoinSet,
                            // so the reader returns datagrams through a channel
                            // instead. (Concrete wiring in the implementation.)
                        }
                        OP_DATA => {
                            let Some(sock) = flows.get(&frame.request_id) else { continue; };
                            let payload = strip_slug_prefix(&frame.payload, &subdomain);
                            rx_count.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            if sock.send(payload).await.is_err() {
                                flows.remove(&frame.request_id);
                                send_frame(&dc, OP_CLOSE, frame.request_id, &[]).await?;
                            }
                        }
                        OP_CLOSE => { flows.remove(&frame.request_id); }
                        _ => {}
                    }
                }
                Some(DataChannelEvent::OnClose) | None => return Ok(()),
                _ => {}
            },
        }
    }
}
```

NOTE to implementer: the sketch above has one deliberate wrinkle — an upstream reader task cannot push into its own `JoinSet`. Wire it with an `mpsc::unbounded_channel` instead: the reader task sends `(flow_id, datagram)` into the channel; the main loop's `select!` drains the channel and emits `DATA` frames. Keep the `JoinSet` only if you keep per-flow reader tasks; a single reader per flow via `tokio::spawn` + channel is the pinned shape.

`LocalTarget` — check `targets.rs`: if it lacks a UDP variant, add `Udp(u16)` with `LocalTarget::udp(port)` (the `--udp` client flag from Phase "UDP tunneling" already models this on the tunnel side — reuse that variant if present).

Dispatch in `handle_visitor_offer`:
```rust
BridgeMode::Udp => bridge_udp_channel(dc, target, tx_count, rx_count, sub).await,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-client --test p2p --lib`
Expected: PASS (new unit tests + existing gateway tests).

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-client/src/p2p.rs crates/ddns-client/src/targets.rs crates/ddns-client/tests/p2p.rs
git commit -m "feat: udp bridge mode for p2p data channels (label routing + slug prefix strip)"
```

---

### Task 2: `ddns connect --udp PORT` — CLI + UDP pumps

**Files:**
- Modify: `crates/ddns-client/src/cli.rs` (`Command::Connect` gains `udp: Option<u16>`; parse `--udp PORT`)
- Modify: `crates/ddns-client/src/main.rs` (dispatch)
- Modify: `crates/ddns-client/src/connect_p2p.rs` (`bind_udp_socket`, `run_udp_pumps`)
- Modify: `crates/ddns-client/tests/cli.rs` (parse tests)

**Interfaces:**
- Consumes: `connect_p2p_channel` (existing seam).
- Produces:
  - `Command::Connect { server, subdomain, ca_pem, udp: Option<u16> }`.
  - `pub async fn bind_udp_socket(subdomain: &str) -> Result<(tokio::net::UdpSocket, u16), String>` — binds `127.0.0.1:0`.
  - `pub async fn run_udp_pumps(pc: Arc<dyn PeerConnection>, dc: Arc<dyn DataChannel>, sock: tokio::net::UdpSocket, subdomain: String) -> Result<(), String>` — visitor-side: flow table (remote addr → flow id), empty `REQ` per new flow, `<slug>\n` prefix on each flow's first datagram, channel `DATA` → sendto the flow's remote addr, 30 s idle `CLOSE`.

- [ ] **Step 1: Write the failing tests** (`tests/cli.rs`)

```rust
#[test]
fn connect_parses_udp_flag() {
    let args = svec!["connect", "myslug", "--udp", "53"];
    match parse_command(&args).unwrap() {
        Command::Connect { subdomain, udp, .. } => {
            assert_eq!(subdomain, "myslug");
            assert_eq!(udp, Some(53));
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[test]
fn connect_without_udp_is_tcp_mode() {
    let args = svec!["connect", "myslug"];
    match parse_command(&args).unwrap() {
        Command::Connect { udp, .. } => assert_eq!(udp, None),
        other => panic!("expected Connect, got {other:?}"),
    }
}
```

(`svec!` = the file's existing string-vec helper; mirror its pattern.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ddns-client --test cli`
Expected: FAIL — no `udp` field / flag.

- [ ] **Step 3: Implement**

`cli.rs` — extend `Command::Connect` with `udp: Option<u16>`; parse `--udp PORT` in the connect branch (port 1..=65535, reject 0). Thread through `main.rs`'s Connect dispatch into `connect_p2p::run_connect_udp` (new) vs the existing TCP `run_connect`.

`connect_p2p.rs`:
```rust
/// Bind the visitor's local UDP socket (ephemeral port) and print the
/// forward line. Returns the socket and its bound port.
pub async fn bind_udp_socket(subdomain: &str) -> Result<(tokio::net::UdpSocket, u16), String> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind udp: {e}"))?;
    let port = sock.local_addr().map_err(|e| e.to_string())?.port();
    println!("Forwarding UDP 127.0.0.1:{port} → p2p:{subdomain}");
    Ok((sock, port))
}

/// Visitor-side UDP pumps (mirror of run_pumps, datagram semantics):
/// flow = remote addr; empty REQ announces; first datagram per flow carries
/// the "<subdomain>\n" shared-port routing prefix; 30 s idle → CLOSE.
pub async fn run_udp_pumps(
    _pc: Arc<dyn PeerConnection>,
    dc: Arc<dyn DataChannel>,
    sock: tokio::net::UdpSocket,
    subdomain: String,
) -> Result<(), String> { … }
```

Pump shape (pinned):
- `flows: HashMap<SocketAddr, u32>`, `next_flow: u32` (from 1), `last_seen: HashMap<u32, Instant>`, `first_datagram: HashSet<u32>`.
- Downstream (visitor app → channel): `sock.recv_from` → resolve/allocate flow → if first datagram for the flow, prepend `format!("{subdomain}\n")` → if the flow is new, send empty `REQ(flow)` first → `DATA(flow, datagram)`.
- Upstream (channel → visitor app): `DATA(frame)` → `sock.send_to(&frame.payload, remote_of(flow))`; unknown flow → ignore. `CLOSE(flow)` → drop flow state.
- Idle reaper: 5 s tick; flows idle > 30 s → `CLOSE(flow)` + drop.
- Channel close → return.

`main.rs` Connect dispatch: when `udp` is `Some(_)` the client's local target for the gateway side is the tunnel's UDP service — the gateway's `target` comes from the ANSWER side (the client machine), unchanged. The helper only needs its own listener kind. Wire:
```rust
Command::Connect { server, subdomain, ca_pem, udp } => match udp {
    None => run_connect_tcp(...),   // existing path
    Some(_port) => run_connect_udp(...),  // new: connect_p2p_channel("udp" label) + bind_udp_socket + run_udp_pumps
},
```
Add a `"udp"`-labeled variant of the channel setup: `connect_p2p_channel` currently hardcodes `create_data_channel("tcp", None)` — parameterize it: `connect_p2p_channel_labeled(label: &str, negotiate: F)` and keep `connect_p2p_channel` as the `"tcp"` wrapper (existing callers/tests untouched).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-client --test cli --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-client/src/cli.rs crates/ddns-client/src/main.rs crates/ddns-client/src/connect_p2p.rs crates/ddns-client/tests/cli.rs
git commit -m "feat: ddns connect --udp PORT (visitor UDP forwarder over p2p channel)"
```

---

### Task 3: Loopback e2e + docs + version 0.9.0

**Files:**
- Modify: `crates/ddns-client/tests/connect_p2p.rs` (UDP e2e, mirrors the TCP e2e)
- Modify: `docs/SERVICE-TEMPLATES.md`, `docs/DEVICE-GUIDES.md` (UDP helper usage)
- Modify: root `Cargo.toml` (0.8.0 → 0.9.0) + `Cargo.lock`

**Interfaces:**
- Consumes: `connect_p2p_channel_labeled("udp", …)`, `run_udp_pumps`, gateway `bridge_udp_channel` (Tasks 1–2).
- Produces: in-process proof that a visitor datagram round-trips helper → channel → gateway UDP bridge → local UDP echo → back.

- [ ] **Step 1: Write the failing e2e test** (`tests/connect_p2p.rs`)

```rust
#[tokio::test]
async fn connect_p2p_round_trips_udp() {
    // --- Local UDP echo -----------------------------------------------------
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65_535];
        loop {
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        }
    });

    // --- Helper side: channel labeled "udp", loopback-paired ----------------
    let target = LocalTarget::from_url(&format!("udp://127.0.0.1:{}", echo_addr.port())).unwrap();
    let ticket = ddns_proto::ticket::issue_ticket(&[0u8; 32], "vivid-otter-72");
    let (pc, dc) = connect_p2p_channel_labeled("udp", move |offer_sdp| {
        // (same negotiate closure as the TCP e2e — P2pGateway::handle_visitor_offer)
        …
    })
    .await
    .expect("channel negotiation");

    // --- Helper's local UDP socket + pumps ----------------------------------
    let (sock, port) = bind_udp_socket("vivid-otter-72").await.unwrap();
    let pumps = tokio::spawn(run_udp_pumps(pc.clone(), dc.clone(), sock, "vivid-otter-72".to_string()));

    // --- Native visitor: one datagram in, the echo back out -----------------
    let visitor = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor.send_to(b"dns-query", ("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 65_535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), visitor.recv_from(&mut buf))
        .await
        .expect("timed out waiting for echoed datagram")
        .unwrap();
    assert_eq!(&buf[..n], b"dns-query");

    let _ = pc.close().await;
    pumps.abort();
}
```

NOTE: the gateway's UDP bridge STRIPS the `<slug>\n` prefix (Task 1), so the echo sees the clean datagram and the visitor gets `dns-query` back verbatim.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p ddns-client --test connect_p2p connect_p2p_round_trips_udp`
Expected: FAIL — `connect_p2p_channel_labeled` / `bind_udp_socket` / `run_udp_pumps` missing (or datagram never echoes if only partially wired).

- [ ] **Step 3: Implement whatever the RED run exposes**

(The pieces exist from Tasks 1–2; this step fixes integration gaps the loopback exposes — channel-open ordering, prefix handling on the first datagram, flow teardown on `pc.close()`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-client`
Expected: PASS (all client suites incl. the new e2e).

- [ ] **Step 5: Docs + version + full verification**

`docs/SERVICE-TEMPLATES.md` — UDP services section gains:
```markdown
Or P2P (no broker UDP port needed): `ddns connect <sub> --udp 53` forwards
datagrams to the tunnel's UDP service from your machine.
```
`docs/DEVICE-GUIDES.md` — one line in the multi-service section.

Root `Cargo.toml`: `version = "0.9.0"`; `cargo check --workspace -q` refreshes `Cargo.lock`.

```bash
cargo test --workspace -q -- --test-threads=1   # all green (throughput retry handles the known flake)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -q -- -D warnings
git add -A
git commit -m "feat: visitor UDP helper e2e + docs (0.9.0)"
git push origin-free main
```
Copy the two docs to `A:/web/ddns/docs/` and push `origin master`.

---

## Self-Review (done at write time)

- Spec coverage: `--udp PORT` flag (T2), data-channel path mirroring TCP (T1 label routing + T2 labeled channel), `<slug>\n` prefix per flow (T2 pumps + T1 strip), prints forwarded local port (T2 `bind_udp_socket`), TCP helper shape reused (`connect_p2p_channel` seam, pump structure) — all pinned.
- Gap analysis: server-side none (signaling label-agnostic; broker udp_bridge is relay-path only); client-side three pieces built in T1/T2 — stated up front as requested.
- Placeholders: T1's JoinSet wrinkle carries an explicit NOTE with the pinned channel-based wiring; T3's negotiate closure says "same as the TCP e2e" with the file named — concrete, not TBD.
- Type consistency: `BridgeMode::Udp` / `strip_slug_prefix` / `connect_p2p_channel_labeled` / `bind_udp_socket` / `run_udp_pumps` names identical across tasks; `Command::Connect.udp: Option<u16>` consistent T2/T3.
