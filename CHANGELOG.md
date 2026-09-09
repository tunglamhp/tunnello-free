# Changelog

## Versioning

- `free` releases use plain `X.Y.Z` tags.
- `private` releases use `X.Y.Z-private` tags in the private repo.
- `release/<major>.<minor>` branches preserve maintenance versions.

## [0.11.0] — 2026-09-09

### Added
- **ACME DNS-01 (Let's Encrypt wildcard)**: Cloudflare/Porkbun providers write the `_acme-challenge` TXT records themselves; one certificate covers the apex AND `*.domain` — dashboard and every tunnel hostname get valid HTTPS, auto-renewed and hot-swapped.
- **`deploy.sh` preflight**: DNS checks (apex + wildcard) and automatic firewall rules for HTTPS/WSS, STUN (3478/udp) and WireGuard when enabled; disable with `DDNS_SKIP_FIREWALL=1` / `DDNS_SKIP_DNS_CHECK=1`.

### Changed
- Wildcard ACME domains are now allowed when a DNS provider is configured (`DDNS_ACME_PROVIDER=cloudflare|porkbun` + credentials).

## [Unreleased]

### Planned
- Keep free/public surface aligned with private broker core minus billing/plans UI.

## [0.10.3] — 2026-08-29

### Sửa
- Hoàn tất hardening **no-panic** (M7): `SessionCookie::issue`/`tag` trả `Result` thay vì `.expect` panic, caller map sang 500.
- Backport **key-age**: `key_age_or_panic` → `Option`, lazy sweep, pubkey validation.
- Khôi phục test compat (secret dạng `Vec`, `generate_keypair` trả `Result`, cookie unwrap gated).
- Clippy sạch (collapsed `if-let`, `result_unit_err` allows).

---

## [0.10.2] — trước đó

Exit-node WireGuard full tunnel (`ddns up --exit-node`), wg platform layer (fwmark kill switch, route planners), key-age first-sighting semantics.
