# Visitor Auth Expansion — Design (2026-08-26)

Status: approved (sections 1–2 reviewed interactively).
Scope: umbrella spec for 4 phases; Phase 1 gets a full implementation plan
this session. Phases 2–4 get their own plans later.

## Background

Tunello learned features from ZeroTier, Tailscale, Pangolin, Pinggy, and
OpenZiti. Already shipped: PIN code auth, live request debugger (metadata),
resource policies, WebSocket tunneling, multi-tenant UDP routing. Remaining
gaps, ordered by value:

| Phase | Feature | Learned from | Status |
|---|---|---|---|
| 1 | OIDC + email-OTP per-tunnel visitor auth | Pangolin | planned here |
| 2 | Deep web debugger (body capture + replay) | Pinggy | backlog |
| 3 | `ddns connect --udp` visitor-side UDP helper | Pinggy | backlog |
| 4 | Exit-node / full-traffic routing (TUN) | Tailscale | backlog |

## Phase 1 — Per-tunnel OIDC + Email OTP (this plan)

### Approach (chosen)

Per-tunnel gate inside the existing `http_options` pipeline (Approach A).
Rejected Approach B (global middleware layer): loses per-tunnel granularity
and tangles the router middleware stack. Pangolin also gates per-resource.
Resource Policies (already shipped) covers reuse across tunnels.

### HttpOptions changes (wire-compatible, serde defaults)

```rust
pub oidc_auth: bool,  // require OIDC login before forwarding
pub email_otp: bool,  // require email OTP before forwarding
```

Pipeline order (locked, after `pin_auth`):
`ip_whitelist → basic → bearer → pin → oidc → otp → header mutations`.

### OIDC flow

Config (env): `DDNS_OIDC_ISSUER`, `DDNS_OIDC_CLIENT_ID`,
`DDNS_OIDC_CLIENT_SECRET`. Discovery from `{issuer}/.well-known/
openid-configuration`, cached 1 h. Authorization Code + PKCE (S256).

1. Visitor hits gated tunnel without cookie `tnl_auth` → `302
   /__auth/oidc/start?back=<orig-path>`.
2. `/__auth/oidc/start`: generate `state` + PKCE verifier; stash them in a
   short-lived signed cookie `tnl_oauth` (10 min) → `302` to the provider's
   authorization endpoint.
3. Provider redirects to `/__auth/oidc/cb?code&state`: verify state,
   exchange code at token_endpoint, parse `email` from id_token → set
   signed cookie `tnl_auth` (`email|exp`, 12 h) → `302 back`.
4. Request re-enters `apply()`; valid cookie → forward.

### Email OTP flow

1. Gated visitor without cookie `tnl_otp` → `302 /__auth/otp?back=<path>`.
2. Form posts email → `/__auth/otp/send`: rate-limit 3/min/email; generate
   a 6-digit code; store in-memory `Mutex<HashMap<email, Entry>>` where
   `Entry { code_hash: [u8;32], exp: 5 min, attempts: 5 }`; send via the
   existing `mailer::Mailer` (dev mode logs the link instead of SMTP).
3. `/__auth/otp/verify`: constant-time compare (hmac_eq) → set signed
   cookie `tnl_otp` (`email|exp`, 12 h) → `302 back`.
4. 5 wrong attempts destroys the entry; the visitor requests a new code.

Cookies: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` in production.
Signing reuses the broker's HMAC secret + constant-time compare (same
mechanism as `pin_auth`).

### New components (ddns-server)

- `auth_oidc.rs` — discovery client (1 h cache), PKCE, code exchange,
  id_token email parsing. HTTP client: reuse the workspace's existing HTTP
  stack; if none fits, add a minimal dependency (decision in plan).
- `auth_otp.rs` — in-memory OTP store, rate limiting, mailer send.
- `http_app.rs` — 5 public routes (no operator session required):
  `/__auth/oidc/start`, `/__auth/oidc/cb`, `/__auth/otp`,
  `/__auth/otp/send`, `/__auth/otp/verify`.
- `http_options.rs` — two new gate checks + signed-cookie verification.
- Dashboard: two checkboxes in the tunnel Options form (mirrors `pin_auth`).

### Error handling

- `oidc_auth=on` but OIDC env missing → `503` "OIDC not configured on this
  broker" (never a redirect loop).
- `email_otp=on` but mailer unconfigured → `503` with a clear message.
- State mismatch or token exchange failure → error page with back link +
  `tracing::warn`.
- Expired auth cookie → treated as unauthenticated; flow restarts.
- Open redirect: `back` must start with `/` and must not start with `//`
  (scheme-relative); otherwise fall back to `/`.

### Testing (TDD)

- Unit: PKCE verifier/challenge round-trip; auth-cookie sign/verify +
  expiry; OTP hash compare + attempt burn + rate window; back-path
  validation.
- Integration: full OTP flow end-to-end using mailer dev mode (link logged);
  OIDC flow against a mock issuer (in-test axum server serving discovery +
  token endpoints).
- Regression: existing pipeline (pin/basic/bearer/whitelist) unchanged.

### Explicit non-goals (Phase 1)

- No per-tunnel OIDC provider override (broker-wide env config only).
- No JWT access tokens for API visitors (cookie sessions only).
- No group/role claims mapping (email presence is the gate).
- Free edition only; no billing hooks.

## Phase 2 — Deep Web Debugger (backlog summary)

Extend the existing debug ring: opt-in body capture (truncate at 4 KiB,
redact `Authorization`/`Cookie` headers) + request replay from the debug
page. Storage stays in-memory per session. Gate behind an operator-only
toggle per tunnel (privacy default off).

## Phase 3 — Visitor UDP helper (backlog summary)

`ddns connect <sub> --udp PORT`: WebRTC data-channel path mirrors TCP mode;
prepends the `<slug>\n` prefix for shared-port routing; prints the forwarded
local port. Reuses the Phase 2 (of the original P2P plan) TCP helper shape.

## Phase 4 — Exit node (backlog summary)

`ddns up --exit-node`: TUN interface on the visitor device, route default
traffic through the tunnel's TCP bridge. Largest phase; needs its own spec
(platform TUN deps, MTU, DNS handling). Explicitly out of scope until
Phases 1–3 land.
