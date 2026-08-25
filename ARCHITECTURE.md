# Architecture

## Workspace layout

| Crate | Role | Free | Paid |
|---|---|---|---|
| `ddns-proto` | Wire protocol: control frames, stream framing, limits, tickets | ✅ | ✅ |
| `ddns-server` | Broker: TLS listener, tunnel relay, dashboard, health, metrics | ✅ | ✅ |
| `ddns-client` | Tunnel client: WSS connect + P2P WebRTC data plane + `ddns connect` helper | ✅ | ✅ |
| `ddns-echo` | Tiny echo app for demo/testing | ✅ | ✅ |
| `ddns-web` | Dashboard frontend islands (Dioxus/WASM) | ✅ | ✅ |
| `ddns-billing` | Stripe checkout, plans, subscriptions, client accounts, portal | ❌ | ✅ |

## Broker module map (ddns-server)

```
ddns-server/src/
├── main.rs          Entry point: parse CLI, build config, start broker
├── lib.rs           Crate root: mod declarations, re-exports
│
├── ── Core relay engine ──
│   ├── mux.rs            WebSocket multiplexer: register → route frames → teardown
│   ├── http_tunnel.rs    HTTP/HTTPS visitor → broker → client relay
│   ├── tcp_bridge.rs     Raw TCP tunnel bridge (ddns-tcp ALPN)
│   ├── session.rs        Per-session state: limits, counters, kill
│   ├── registry.rs       Session registry with capacity limits
│   ├── p2p_signal.rs     WebRTC signaling relay (/__p2p/signal)
│   ├── http_options.rs   Per-tunnel HTTP header options
│   ├── connector.rs      Browser connector page + service worker
│   │
├── ── Auth & security ──
│   ├── auth.rs           Operator login/session cookie/CSRF/rate-limit middleware
│   ├── token.rs          Tunnel tokens: argon2id hashing, SQLite store, fast-index
│   ├── rate_limit.rs     Per-IP token buckets (register/login/signal)
│   ├── otp.rs            TOTP 2FA for operator login (RFC 6238)
│   ├── audit.rs          Activity audit log
│   ├── tls.rs            ACME (TLS-ALPN-01) + static PEM certificates
│   ├── stun.rs           Embedded STUN server for NAT traversal
│   ├── setup.rs          Quickstart setup codes
│   │
├── ── Dashboard & config ──
│   ├── http_app.rs       Router: all routes, security headers, CSRF
│   ├── ui.rs             HTML templates + nav + branding
│   ├── settings.rs       Runtime settings (instance name, TTL defaults…)
│   ├── domain.rs         Custom domain management
│   ├── tunnel.rs         Tunnel profile management
│   ├── metrics.rs        Prometheus exposition
│   ├── providers.rs      DNS-01 challenge provider abstraction
│   ├── mailer.rs         SMTP email delivery
│   ├── schema.rs         SQLite DDL + column migrations
│   │
├── ── Infrastructure ──
│   ├── config.rs         BrokerConfig: listen/domain/cert/env vars
│   ├── hot.rs            Redis hot counter (rate limit fast path)
│   ├── quota.rs          Session watchdog + per-tunnel rate limiter
```

## Key design decisions

- **Unlimited by default**: every token limit defaults to `0` (= unlimited).
  Operators set guard rails via the dashboard when needed.
- **Deny-by-default auth**: all routes require a valid session unless explicitly
  allow-listed. First-run setup requires a bootstrap token on non-loopback binds.
- **Argon2id** for password/token hashing; **HMAC-SHA256** constant-time compare
  for session cookies and P2P tickets.
- **Rate limiting**: per-IP token buckets on public endpoints (register,
  login, portal signup); per-tunnel sliding window via Redis when configured.
- **Graceful degradation**: Redis down → rate limiting passes through.
  Metrics endpoint always serves. Health endpoint never blocks.

## Extension points

| Trait | Purpose | Implementations |
|---|---|---|
| `Dns01Provider` | ACME DNS-01 challenge fulfillment | ManualTxt, Cloudflare |
| `BillingBackend` *(paid)* | Payment processing | Stripe |
| *Future:* `TransportCodec` | Alternative wire formats | — |

## Adding a new feature

1. Create a new module in `crates/ddns-server/src/<module>.rs`
2. Add `pub mod <module>;` to `lib.rs`
3. Register routes in `http_app.rs::router()`
4. Add tests in `crates/ddns-server/tests/<module>_tests.rs`
5. Run `cargo test --workspace -q -- --test-threads=1`

## Removing a feature

1. Delete the module file(s) from `crates/ddns-server/src/`
2. Remove `pub mod <module>;` from `lib.rs`
3. Remove routes referencing it from `http_app.rs::router()`
4. Remove tests referencing it
5. Run `cargo check --workspace` to catch dangling references
