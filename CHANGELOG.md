# Changelog

## Versioning

- `free` releases use plain `X.Y.Z` tags.
- `private` releases use `X.Y.Z-private` tags in the private repo.
- `release/<major>.<minor>` branches preserve maintenance versions.

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
