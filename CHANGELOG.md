# Changelog

## Versioning

- Releases use plain `X.Y.Z` tags.
- `release/<major>.<minor>` branches preserve maintenance versions.

## [Unreleased]

### Security
- **`h2` upgraded 0.4.15 → 0.4.19** (RUSTSEC-2026-0258, "h2 unbounded empty DATA
  frames"). `h2` backs hyper, which serves the broker's HTTP/2 traffic, so the
  advisory was reachable from the network. `cargo audit` now reports zero
  vulnerabilities. Two advisory *warnings* remain and are accepted:
  `rustls-pemfile 2.2.0` is flagged unmaintained (still used by `axum-server`
  via `rustls-acme`; no drop-in replacement yet), and `chacha20 0.10.1` is
  flagged yanked (an older entry in the lockfile, not a vulnerability).

### Fixed
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
