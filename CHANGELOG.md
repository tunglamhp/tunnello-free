# Changelog

## Versioning

- Releases use plain `X.Y.Z` tags.
- `release/<major>.<minor>` branches preserve maintenance versions.

## [Unreleased]

### Security
- **`rustls` upgraded 0.23.43 → 0.23.45** (RUSTSEC-2026-0285, "TLS 1.3 handshake
  messages incorrectly accepted across encryption level boundaries"). `rustls`
  terminates the broker's TLS, so the advisory was reachable from the network.
  `rustls-webpki` moved 0.103.13 → 0.103.15 in the same update. `cargo audit`
  reports zero vulnerabilities; the two accepted advisory *warnings* are
  unchanged (`rustls-pemfile` unmaintained, `chacha20` yanked).
- **`h2` upgraded 0.4.15 → 0.4.19** (RUSTSEC-2026-0258, "h2 unbounded empty DATA
  frames"). `h2` backs hyper, which serves the broker's HTTP/2 traffic, so the
  advisory was reachable from the network. `cargo audit` now reports zero
  vulnerabilities. Two advisory *warnings* remain and are accepted:
  `rustls-pemfile 2.2.0` is flagged unmaintained (still used by `axum-server`
  via `rustls-acme`; no drop-in replacement yet), and `chacha20 0.10.1` is
  flagged yanked (an older entry in the lockfile, not a vulnerability).

### Fixed
- **A bad Host-rewrite value aborted the whole broker.** `http_options::apply`
  did `HeaderValue::from_str(h).unwrap()` on the operator-supplied
  `host_rewrite`. `HeaderValue` rejects control bytes, and the value is stored
  un-validated — the options form percent-decodes `%0A` to a real newline and the
  JSON API accepts `\n` — so a pasted newline was enough to make `from_str` fail.
  The release profile is `panic = "abort"`, so that panic killed the process for
  *every* tenant on the next visitor request to that tunnel. An un-encodable
  value is now dropped with a warning, matching the `add_headers` loop below it.
- **Exit-node / multi-exit P2P never worked.** `KeyAgeStore::expired` reports an
  *unknown* key as expired, but `p2p_signal` checked `expired()` **before**
  `record()` — and that was the only `record` call site — so every first-seen
  `wg_pubkey` was rejected `key_expired` and never stored. No exit-mode offer
  could ever succeed. `record` now runs first; it is an `or_insert`, so a
  re-hello still does not refresh the clock and key rotation stays enforced.
- **One stalled visitor could wedge a whole session.** `mux::route_frame` awaited
  an unbounded send on the bounded per-stream channel (`STREAM_QUEUE_CAP`).
  Consumers write to the visitor socket with no timeout, so a visitor that stops
  reading parks its consumer; once the queue filled, that await parked the
  session's entire `select!` loop — no quota kill, no drain, no read-idle
  timeout — leaving a session the operator could not reclaim until the visitor
  released the socket. The wait is now bounded by `STREAM_SEND_TIMEOUT` (30 s),
  after which the stream is closed with `CLOSE_APP_ERROR` and the loop resumes.
  It is deliberately a *bounded wait* rather than a `try_send`: a visitor reading
  a large response is routinely slower than the client sending it (a 256 KiB body
  is 16 back-to-back frames against an 8-slot queue), and failing fast there
  truncates healthy transfers.
- **Stacked cards had no vertical gutter.** `.section` carried a bottom margin
  but `.card` did not, so pages that stack bare `.card`s — Settings and a
  client's detail page — rendered each card flush against the next. `.card` now
  has a 20px bottom margin, matching the `.cards` grid gap; the grid still resets
  its own children so the dashboard stat row is unaffected.
- **Mismatched field baselines in two-column form rows.** `.form-row` used
  `align-items: flex-end`, so a column carrying a `.hint` under its input grew
  taller and pushed its own input above its sibling's. It is now `flex-start`, so
  labels and inputs stay in line.
- **TCP tunnel could drop the tail of a transfer** — `tcp_bridge` cancelled the
  visitor→client task with `abort()` as soon as the client closed. `abort()`
  cancels at the current await point, so a DATA frame mid-`send_frame` was
  discarded instead of relayed. The task now gets a bounded 5 s grace period,
  which returns immediately in the normal case where the visitor read hits EOF.
- **Throughput test never half-closed** — the writer sent all 32 MiB but never
  shut down its TLS write half, so the last bytes were discarded on drop and
  exactly 64 KiB (4 of 2048 chunks) was lost, stalling the test ~91 s until the
  idle watchdog reaped the stream. It now passes in ~2 s.
- **TCP-tunnel tests used an uncovered SNI** — `connect_tcp` connected as
  `<slug>.localhost` while the test certificate only covers
  `tunnel.example.com` and loopback, so rustls failed the handshake with
  `NotValidForName` and the throughput suite could not run. It now uses
  `<slug>.tunnel.example.com`.
- **Test HTTP helper could block forever** — the per-file `http1` readers waited
  only for EOF, so a keep-alive or chunked response hung the suite instead of
  failing. All eight readers now stop on HTTP framing (content-length / chunked
  terminator / bodyless status) with a per-read timeout and a response size cap.
- **`install-server.sh` cloned a fixed branch name** — it defaulted to
  `DDNS_BRANCH=main`, which breaks any override of `DDNS_REPO_URL` for a mirror
  whose default branch differs. It now resolves the remote's default branch via
  `git ls-remote --symref`, validates an explicit `DDNS_BRANCH` override, and
  falls back to `main`/`master`.

### Planned
- Keep the dashboard and client surface aligned with the broker core.

## [0.11.0] — 2026-09-09

### Added
- **ACME DNS-01 (Let's Encrypt wildcard)**: Cloudflare/Porkbun providers write the `_acme-challenge` TXT records themselves; one certificate covers the apex AND `*.domain` — the dashboard and every tunnel hostname get valid HTTPS, auto-renewed and hot-swapped.
- **`deploy.sh` preflight**: DNS checks (apex + wildcard) and automatic firewall rules for HTTPS/WSS, STUN (3478/udp) and WireGuard when enabled; disable with `DDNS_SKIP_FIREWALL=1` / `DDNS_SKIP_DNS_CHECK=1`.

### Changed
- Wildcard ACME domains are now allowed when a DNS provider is configured (`DDNS_ACME_PROVIDER=cloudflare|porkbun` + credentials).

## [0.10.3] — 2026-08-29

### Fixed
- Completed **no-panic** hardening (M7): `SessionCookie::issue`/`tag` return `Result` instead of `.expect` panics; callers map to 500.
- Backported **key-age**: `key_age_or_panic` → `Option`, lazy sweep, pubkey validation.
- Restored test compatibility (secrets as `Vec`, `generate_keypair` returns `Result`, gated cookie unwraps).
- Clippy clean (collapsed `if-let`, `result_unit_err` allows).

---

## [0.10.2] — earlier

Exit-node WireGuard full tunnel (`ddns up --exit-node`), wg platform layer (fwmark kill switch, route planners), key-age first-sighting semantics.
