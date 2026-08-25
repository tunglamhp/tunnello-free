# Deep Web Debugger (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in per-tunnel request/response body capture (4 KiB truncate, sensitive headers redacted) in the existing debug ring, plus request replay from the operator debug page.

**Architecture:** `HttpOptions.debug_capture: bool` (default OFF — privacy) gates capture inside `http_tunnel::serve_inner`: request headers (redacted) are cloned before forwarding, the first 4 KiB of request and response bodies are buffered alongside the existing pumps without changing flow. `DebugEntry` gains three `#[serde(default)]`-style optional fields; the debug page renders a body preview per entry and a POST `/debug/{slug}/replay` (operator router — session-gated) re-sends a captured request through the tunnel and shows the response.

**Tech Stack:** Rust 2024, axum, existing `session::DebugEntry` ring, existing `http_tunnel` pumps. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-26-visitor-auth-expansion-design.md` §Phase 2

## Global Constraints

- `debug_capture` defaults **OFF**; absent field parses as `false` (privacy).
- Body capture caps at **4 KiB** per side (request, response); longer bodies get a `"…(truncated)"` suffix.
- Redacted headers (case-insensitive): `authorization`, `cookie`, `set-cookie` → value `[REDACTED]`.
- Storage stays in-memory per session (existing 100-entry ring); no DB writes.
- Replay route lives in the operator router (session middleware applies); it re-drives the request through the normal tunnel path.
- Capture must never block or alter forwarding: buffering is a copy alongside existing pumps.
- TDD: failing test first for every task; `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -q -- -D warnings` clean before each commit.
- Work from repo root (`A:/web/ddns-free`, branch `main`); mirror docs to `A:/web/ddns` at the end. Version stays 0.7.0 unless a feature commit warrants 0.8.0 — bump to **0.8.0** in the final task.

## File Structure

- Modify `crates/ddns-server/src/tunnel.rs` — `HttpOptions.debug_capture` field + Default + form parser hook (parser lives in `http_app.rs`).
- Create `crates/ddns-server/src/debug_capture.rs` — pure helpers: `redact_headers`, `truncate_body`, `capture_request_headers`; unit tests inline.
- Modify `crates/ddns-server/src/session.rs` — `DebugEntry` gains `req_headers`, `req_body`, `resp_body` (with `#[serde(default)]`-compatible construction; the struct is not serialized today, but keep `Clone + Debug` and add `Default`-ish construction helpers).
- Modify `crates/ddns-server/src/http_tunnel.rs` — capture wiring in `serve_inner` (headers + body pumps) gated on `opts.debug_capture`.
- Modify `crates/ddns-server/src/http_app.rs` — Options form checkbox + parser field; debug page body column + replay form; `POST /debug/{slug}/replay` handler in the operator router.
- Test files: `crates/ddns-server/tests/debug_capture.rs` (integration: capture on/off through a live tunnel + replay endpoint).

---

### Task 1: `debug_capture.rs` — redact + truncate helpers

**Files:**
- Create: `crates/ddns-server/src/debug_capture.rs`
- Modify: `crates/ddns-server/src/lib.rs` (`pub mod debug_capture;`)

**Interfaces:**
- Produces:
  - `pub const CAPTURE_LIMIT: usize = 4096;`
  - `pub fn is_sensitive_header(name: &str) -> bool` (case-insensitive `authorization` | `cookie` | `set-cookie`)
  - `pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)>`
  - `pub fn truncate_body(body: &[u8]) -> String` (UTF-8 lossy; > `CAPTURE_LIMIT` bytes → first `CAPTURE_LIMIT` bytes + `"…(truncated)"`)
- Consumes: nothing new.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_headers_redacted_case_insensitive() {
        let raw = vec![
            ("Authorization".to_string(), "Bearer sekret".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("COOKIE".to_string(), "session=abc".to_string()),
            ("Set-Cookie".to_string(), "a=1".to_string()),
        ];
        let out = redact_headers(&raw);
        assert_eq!(out[0].1, "[REDACTED]");
        assert_eq!(out[1].1, "application/json");
        assert_eq!(out[2].1, "[REDACTED]");
        assert_eq!(out[3].1, "[REDACTED]");
    }

    #[test]
    fn body_truncates_at_4kib_with_marker() {
        let small = b"hello".to_vec();
        assert_eq!(truncate_body(&small), "hello");
        let big = vec![b'x'; CAPTURE_LIMIT + 100];
        let out = truncate_body(&big);
        assert!(out.starts_with('x'));
        assert_eq!(out.len(), CAPTURE_LIMIT + "…(truncated)".len());
        assert!(out.ends_with("…(truncated)"));
    }

    #[test]
    fn invalid_utf8_is_lossy() {
        let bytes = vec![0x68, 0x69, 0xFF]; // "hi" + invalid
        assert!(truncate_body(&bytes).starts_with("hi"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p ddns-server --lib debug_capture`
Expected: FAIL — module missing (compile error).

- [ ] **Step 3: Write minimal implementation**

```rust
//! Body/header capture helpers for the deep web debugger (spec Phase 2).
//! Pure functions — no session or I/O dependencies — so the capture path in
//! `http_tunnel` stays a thin call.

/// Max captured bytes per side (request, response).
pub const CAPTURE_LIMIT: usize = 4096;

/// Headers whose values must never be stored or replayed.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "authorization" || lower == "cookie" || lower == "set-cookie"
}

/// Copy `headers`, replacing sensitive values with `[REDACTED]`.
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            let v = if is_sensitive_header(k) { "[REDACTED]".to_string() } else { v.clone() };
            (k.clone(), v)
        })
        .collect()
}

/// UTF-8-lossy body preview capped at [`CAPTURE_LIMIT`] bytes.
pub fn truncate_body(body: &[u8]) -> String {
    if body.len() <= CAPTURE_LIMIT {
        return String::from_utf8_lossy(body).into_owned();
    }
    let mut out = String::from_utf8_lossy(&body[..CAPTURE_LIMIT]).into_owned();
    out.push_str("…(truncated)");
    out
}

#[cfg(test)]
mod tests {
    // (tests from Step 1)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p ddns-server --lib debug_capture`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-server/src/debug_capture.rs crates/ddns-server/src/lib.rs
git commit -m "feat: debug capture helpers (header redact, 4KiB body truncate)"
```

---

### Task 2: `HttpOptions.debug_capture` + `DebugEntry` capture fields

**Files:**
- Modify: `crates/ddns-server/src/tunnel.rs` (`HttpOptions` + `Default`)
- Modify: `crates/ddns-server/src/http_app.rs` (`parse_options_from_form` — new field)
- Modify: `crates/ddns-server/src/session.rs` (`DebugEntry` fields)
- Modify: `crates/ddns-server/tests/tunnel_store.rs` (round-trip)
- Modify: `crates/ddns-server/tests/http_options.rs` (default-off assertion)

**Interfaces:**
- Produces:
  - `HttpOptions.debug_capture: bool` (serde default false).
  - `DebugEntry { req_headers: Vec<(String, String)>, req_body: Option<String>, resp_body: Option<String>, ..existing }` — empty/None when capture off.

- [ ] **Step 1: Write the failing tests**

In `tests/tunnel_store.rs` `options_json_round_trip`: add `debug_capture: true,` to the literal and `assert!(!empty.debug_capture, "capture defaults off");` at the end.

In `tests/http_options.rs` append:

```rust
#[test]
fn debug_capture_defaults_off() {
    let opts: HttpOptions = serde_json::from_str("{}").unwrap();
    assert!(!opts.debug_capture, "absent debug_capture must parse as false");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p ddns-server --test tunnel_store --test http_options`
Expected: FAIL — `debug_capture` missing.

- [ ] **Step 3: Implement**

`tunnel.rs` — after `email_otp`:
```rust
/// Deep debugger: capture request/response bodies (4 KiB, redacted headers)
/// for the operator debug page. Privacy-sensitive — default off.
#[serde(default)]
pub debug_capture: bool,
```
plus `debug_capture: false,` in `Default`.

`http_app.rs` `parse_options_from_form` — after `email_otp`:
```rust
debug_capture: !form_field(body, "options_debug_capture").is_empty(),
```

`session.rs` `DebugEntry` — after `peer_ip`:
```rust
/// Redacted request headers (capture mode only; empty otherwise).
pub req_headers: Vec<(String, String)>,
/// Request body preview (4 KiB max; None when capture off / no body).
pub req_body: Option<String>,
/// Response body preview (4 KiB max; None when capture off).
pub resp_body: Option<String>,
```
Update `http_tunnel.rs` `record_debug` callsite with `req_headers: Vec::new(), req_body: None, resp_body: None,` (wiring lands in Task 3 — keep compiling).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-server --test tunnel_store --test http_options`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-server/src/tunnel.rs crates/ddns-server/src/http_app.rs crates/ddns-server/src/session.rs crates/ddns-server/src/http_tunnel.rs crates/ddns-server/tests/tunnel_store.rs crates/ddns-server/tests/http_options.rs
git commit -m "feat: debug_capture option + capture fields on DebugEntry"
```

---

### Task 3: Capture wiring in `http_tunnel::serve_inner`

**Files:**
- Modify: `crates/ddns-server/src/http_tunnel.rs`

**Interfaces:**
- Consumes: `debug_capture::redact_headers/truncate_body/CAPTURE_LIMIT` (Task 1), `HttpOptions.debug_capture` (Task 2).
- Produces: populated `DebugEntry.req_headers/req_body/resp_body` when capture is on. The existing `record_debug` call gains real values.

- [ ] **Step 1: Write the failing integration test** (`crates/ddns-server/tests/debug_capture.rs`)

```rust
mod common;

use std::time::Duration;

use ddns_proto::{Frame, Opcode};
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod tcp {
    // Reuse the raw-TCP bridge helper shape from tests/throughput.rs:
    // connect with ALPN ddns-tcp + SNI <slug>.domain, return the TLS stream.
    include!("throughput_tcp_helper.rs");
}

#[tokio::test]
async fn capture_off_by_default_no_bodies_recorded() {
    let (cert, key) = common::test_cert();
    let tokens = TokenStore::new();
    tokens.insert("tok_cap".into(), common::test_record("t-cap", true)).await.unwrap();
    let (addr, broker) = common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;

    // Create a tunnel profile with debug_capture OFF (default options).
    // (Seed via TunnelStore like tests/udp_tunnel.rs — name "cap-off".)
    // Register a fake client, dial the TCP bridge, send one request, read echo.
    // Then: broker.registry().lookup(<slug>) → debug_snapshot() last entry
    // has req_body == None && resp_body == None && req_headers.is_empty().
}

#[tokio::test]
async fn capture_on_records_redacted_headers_and_bodies() {
    // Same shape but the tunnel profile sets options.debug_capture = true.
    // Send request with `Authorization: Bearer x` header + body "hello-body".
    // Assert last DebugEntry:
    //   req_headers contains ("Authorization", "[REDACTED]")
    //   req_headers contains ("content-type", "text/plain") if sent
    //   req_body == Some("hello-body")
    //   resp_body == Some(<echoed body>)
}
```

NOTE to implementer: copy the exact TCP-bridge dial helper from
`tests/throughput.rs` (the `connect_tcp(addr, &cert, &slug)` fn + echo task
pattern) into a shared `tests/common` helper OR duplicate it inline — the
plan pins the behavior, not the file layout. The fake client relays DATA
frames like `throughput.rs`'s echo task.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p ddns-server --test debug_capture`
Expected: FAIL — assertions on `req_body`/`req_headers` see `None`/empty even with capture on.

- [ ] **Step 3: Implement capture in `serve_inner`**

In `http_tunnel.rs`:

1. Before the OPEN frame (where `debug_method`/`debug_path` are captured), add:
```rust
let capture = session.http_options().debug_capture;
let captured_headers = if capture {
    crate::debug_capture::redact_headers(
        &req.headers().iter()
            .map(|(k, v)| (k.as_str().to_string(),
                           String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect::<Vec<_>>())
} else {
    Vec::new()
};
let captured_req: std::sync::Arc<parking_lot::Mutex<Vec<u8>>> = Default::default();
```
(Add `parking_lot` to `ddns-server` deps if not present — it was added in Phase 1.)

2. In the request body pump, after `let Ok(data) = frame.into_data()`, add:
```rust
if capture {
    let mut buf = captured_req.lock();
    let room = crate::debug_capture::CAPTURE_LIMIT - buf.len();
    if room > 0 {
        buf.extend_from_slice(&data[..data.len().min(room)]);
    }
}
```

3. In the response `forward` task, accumulate the first `CAPTURE_LIMIT` bytes of DATA into a shared `captured_resp` buffer the same way.

4. In the `record_debug` call:
```rust
let (req_body, resp_body) = if capture {
    (
        Some(crate::debug_capture::truncate_body(&captured_req.lock())),
        Some(crate::debug_capture::truncate_body(&captured_resp.lock())),
    )
} else {
    (None, None)
};
session.record_debug(crate::session::DebugEntry {
    // …existing fields…
    req_headers: captured_headers,
    req_body,
    resp_body,
});
```
Note: the response `forward` task must hand its buffer back before `record_debug` runs — either await a clone of the task's completion or move the buffer into a `Mutex` shared with `record_debug`'s scope (the plan pins: shared `Arc<Mutex<Vec<u8>>>`, read after `forward` task's first DATA frames; simplest correct approach is reading the shared buffer at `record_debug` time — the forward task keeps filling it until the response ends, and `record_debug` runs right after `resp` is returned, so the first-chunk preview is already present).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-server --test debug_capture --test http_tunnel --test http_options`
Expected: PASS (capture on/off + regression).

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-server/src/http_tunnel.rs crates/ddns-server/tests/debug_capture.rs
git commit -m "feat: capture request/response bodies in debug ring when enabled"
```

---

### Task 4: Debug page body column + replay endpoint

**Files:**
- Modify: `crates/ddns-server/src/http_app.rs` (debug page render + replay handler + route)

**Interfaces:**
- Consumes: `DebugEntry` capture fields (Task 2/3), `serve_inner`-equivalent path for replay — replay re-enters via an internal HTTP self-request is FORBIDDEN (deadlock risk); instead replay constructs a fresh `axum::http::Request` and calls the same tunnel dispatch the router uses: `crate::http_tunnel::serve_tunnel(req, session, peer, quota, account_id)`.
- Produces: `POST /debug/{slug}/replay` (form: `index` = 0-based index into `debug_snapshot()` oldest-first) → re-renders the debug page with a replay result banner (status + body preview).

- [ ] **Step 1: Write the failing test** (extend `tests/debug_capture.rs`)

```rust
#[tokio::test]
async fn replay_resends_captured_request() {
    // Setup identical to capture_on test (capture on, one request recorded).
    // Operator session: log in via the dashboard form (auth::login_submit
    // path) OR — simpler — call the handler through the router with a valid
    // session cookie minted via SessionCookie::issue (tests do this today in
    // cert_http.rs — copy that login helper).
    // POST /debug/<slug>/replay form "index=0"
    // Assert: 200, page contains "Replay" and the replayed status line,
    // and the debug ring now has 2 entries (original + replayed).
}
```

NOTE to implementer: `tests/cert_http.rs` already drives operator login
against the dashboard — copy its helper (form POST `/login` with the dev
admin password, capture the session cookie). The dev password for a fresh
broker is set via `/setup` — `cert_http.rs` shows the exact flow.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p ddns-server --test debug_capture replay`
Expected: FAIL — route missing (404).

- [ ] **Step 3: Implement**

`http_app.rs` — operator router:
```rust
.route("/debug/{slug}/replay", post(debug_replay))
```

Handler:
```rust
#[derive(serde::Deserialize)]
struct ReplayForm { index: usize }

async fn debug_replay(
    State(state): State<BrokerState>,
    Path(slug): Path<String>,
    Form(f): Form<ReplayForm>,
) -> Response {
    let Some(session) = state.registry.lookup(&slug) else {
        return crate::ui::flash_redirect("/", crate::ui::FlashKind::Error, "Session not found");
    };
    let entries = session.debug_snapshot();
    let Some(entry) = entries.get(f.index) else {
        return crate::ui::flash_redirect(&format!("/debug/{slug}"), crate::ui::FlashKind::Error, "Entry gone");
    };
    // Rebuild the request from captured data (headers already redacted —
    // replaying them is safe: Authorization/Cookie arrive as [REDACTED]).
    let mut builder = Request::builder()
        .method(entry.method.as_str())
        .uri(entry.path.as_str())
        .header("host", entry.path.split('/').next().unwrap_or("localhost"));
    // Host header: use the tunnel's public host form instead —
    // format!("{slug}.{}", state.config.domain).
    for (k, v) in &entry.req_headers {
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let body = entry.req_body.clone().unwrap_or_default();
    let req = match builder.body(Body::from(body)) {
        Ok(r) => r,
        Err(e) => return crate::ui::flash_redirect(&format!("/debug/{slug}"), crate::ui::FlashKind::Error, &format!("replay build failed: {e}")),
    };
    let quota = state.quota.as_ref();
    let peer = session.peer_ip().unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    let resp = crate::http_tunnel::serve_tunnel(req, session.clone(), peer, quota, None).await;
    let status = resp.status();
    // Body preview for the banner (bounded read).
    let preview = match axum::body::to_bytes(resp.into_body(), crate::debug_capture::CAPTURE_LIMIT).await {
        Ok(b) => crate::debug_capture::truncate_body(&b),
        Err(e) => format!("<body read failed: {e}>"),
    };
    // Render the debug page again with a replay banner (reuse debug_page's
    // renderer — factor the page body into a fn debug_page_html(slug, entries,
    // replay: Option<(u16, String)>).
    debug_page_html(&slug, &session.debug_snapshot(), Some((status.as_u16(), preview)))
}
```

Refactor `debug_page` to call `debug_page_html(slug, entries, None)`; the renderer adds:
- a "Body" column: `📄 view` link → `/debug/{slug}/body/{index}` when `req_body`/`resp_body` present (new tiny GET handler rendering the redacted headers + bodies in `<pre>`), else `—`
- a replay form per row: `<form method="post" action="/debug/{slug}/replay"><input type="hidden" name="index" value="{i}"><button>↻ Replay</button></form>`
- when `replay` is `Some((status, body))`: a banner `<div class="replay">Replay → {status}<pre>{body}</pre></div>`

Also add `GET /debug/{slug}/body/{index}` (operator router) rendering captured headers/bodies.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p ddns-server --test debug_capture`
Expected: PASS (3 tests: capture off, capture on, replay).

- [ ] **Step 5: Commit**

```bash
git add crates/ddns-server/src/http_app.rs crates/ddns-server/tests/debug_capture.rs
git commit -m "feat: debug page body preview + request replay (operator-gated)"
```

---

### Task 5: Options checkbox + docs + version 0.8.0

**Files:**
- Modify: `crates/ddns-server/src/http_app.rs` (Options form checkbox + format args — parser field landed in Task 2)
- Modify: `docs/SERVICE-TEMPLATES.md` (debugger section gains capture/replay rows)
- Modify: root `Cargo.toml` (0.7.0 → 0.8.0) + `Cargo.lock` via `cargo check`

**Interfaces:**
- Consumes: `options_debug_capture` form field (Task 2 parser already reads it).

- [ ] **Step 1: Options form checkbox**

After the email-OTP row in the tunnel Options form:
```html
<div class="form-group"><label>Debug body capture (privacy-sensitive)</label><input type="checkbox" name="options_debug_capture" {dc}></div>
```
format args: `dc = if o.debug_capture { "checked" } else { "" },`.

- [ ] **Step 2: Docs**

In `docs/SERVICE-TEMPLATES.md`, extend the debugger section:

```markdown
**Body capture + replay** (off by default): enable **Debug body capture** in
the tunnel's Options to record request/response bodies (first 4 KiB,
`Authorization`/`Cookie` headers redacted). The debug page then offers
per-request **Replay** to re-send a captured request through the tunnel.
```

- [ ] **Step 3: Version bump**

Root `Cargo.toml`: `version = "0.8.0"`; `cargo check --workspace -q` refreshes `Cargo.lock`.

- [ ] **Step 4: Full verification**

```bash
cargo test --workspace -q -- --test-threads=1   # expect all suites green
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -q -- -D warnings
```

- [ ] **Step 5: Commit + push + mirror docs**

```bash
git add -A
git commit -m "feat: deep web debugger — body capture opt-in + replay (0.8.0)"
git push origin-free main
```
Copy `docs/SERVICE-TEMPLATES.md` to `A:/web/ddns/docs/` and push `origin master`.

---

## Self-Review (done at write time)

- Spec coverage: opt-in capture (T2 option + T3 wiring), 4 KiB truncate (T1/T3), header redaction (T1/T3), in-memory per session (existing ring, unchanged), replay from debug page (T4), operator-only toggle + operator-gated replay route (T4/T5), default OFF (T2 test).
- Placeholders: T3/T4 NOTE-to-implementer blocks pin exact sources to copy (`throughput.rs` dial helper, `cert_http.rs` login flow) — concrete actions, not TBDs.
- Type consistency: `debug_capture::CAPTURE_LIMIT` used in T1/T3/T4; `DebugEntry.req_headers/req_body/resp_body` names identical across T2/T3/T4; `debug_page_html(slug, entries, replay)` signature introduced and consumed in T4.
