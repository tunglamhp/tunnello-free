use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::header;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use dashmap::DashMap;
use std::collections::HashMap;
use tokio::sync::watch;

use crate::account;

use crate::auth;

use crate::domain;
use crate::providers::ChallengeStore;
use crate::rate_limit::RateLimiter;
use crate::token;
use crate::tunnel;

use crate::config::BrokerConfig;
use crate::http_tunnel;
use crate::mux;
use crate::registry::Registry;
use crate::session::TunnelSession;
use crate::settings;
use crate::tunnel::{HttpOptions, NewTunnel};
use ddns_proto::{KillReason, TokenLimits};

// ---------------------------------------------------------------------------
// traffic ring buffer for sparklines
// ---------------------------------------------------------------------------

const RING_SIZE: usize = 20;

/// Per-session traffic history: ring of recent byte-rate deltas (tx+rx).
pub(crate) struct TrafficRing {
    deltas: Vec<u64>,
    pos: usize,
    filled: bool,
    prev_total: u64,
}

impl TrafficRing {
    fn new() -> Self {
        Self {
            deltas: vec![0; RING_SIZE],
            pos: 0,
            filled: false,
            prev_total: 0,
        }
    }

    /// Snapshot the current total (tx+rx), push the delta into the ring.
    fn sample(&mut self, current_total: u64) {
        let delta = current_total.saturating_sub(self.prev_total);
        self.deltas[self.pos] = delta;
        self.pos = (self.pos + 1) % RING_SIZE;
        if self.pos == 0 {
            self.filled = true;
        }
        self.prev_total = current_total;
    }
}

// ---------------------------------------------------------------------------
// shared broker state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BrokerState {
    pub config: Arc<BrokerConfig>,
    pub registry: Arc<Registry>,
    /// Per-ticket visitor signaling senders (key: ticket). The P2P signal
    /// handler inserts its sender after issuing a ticket and removes it on
    /// drop; the client mux relays `P2pAnswer`/`P2pIce` here.
    pub(crate) p2p_visitors: Arc<DashMap<String, tokio::sync::mpsc::Sender<String>>>,
    /// Per-session traffic history for sparkline rendering (dashboard only).
    pub(crate) traffic: Arc<DashMap<String, std::sync::Mutex<TrafficRing>>>,
    /// Drain signal: set to `true` during graceful shutdown.
    pub drain: watch::Sender<bool>,
    /// ACME challenge store for the :80 HTTP-01 listener and dashboard.
    pub acme: Option<Arc<ChallengeStore>>,
    /// Per-IP token bucket for `/connect` register (O(n) argon2 verify).
    pub register_limiter: Arc<RateLimiter>,
    /// Per-IP token bucket for operator `/login` (admin-password argon2 verify).
    pub operator_login_limiter: Arc<RateLimiter>,
    /// Domains registry (CRUD + active apex) shared with the API and mux.
    pub domains: domain::DomainStore,
    /// Tunnel profiles (fixed slugs, custom hosts, http options) shared with
    /// the API and mux.
    pub tunnels: tunnel::TunnelStore,
    /// Operator account (login, password change, 2FA). Client accounts are a
    /// paid-edition feature and do not exist in this build.
    pub accounts: account::AccountStore,
    /// SMTP mailer (None when DDNS_SMTP_HOST is unset; `--dev` logs links).
    pub mailer: Option<crate::mailer::Mailer>,
    /// Cached active apex name (`slug.<apex>` visitor routing, DB-free).
    pub active_apex: Arc<RwLock<Option<String>>>,
    /// Runtime settings cache (loaded at startup, refreshed on save).
    pub settings: Arc<RwLock<settings::Settings>>,
    /// Settings persistence handle (single-pointed write path).
    pub settings_store: settings::SettingsStore,
    /// Redis hot counter for the tunnel-traffic rate limiter (None → no
    /// limiting; SQLite-only mode passes through).
    pub hot: Option<crate::hot::HotCounter>,
    /// Fixed-minute rate limiter over the tunnel traffic path (None → no
    /// limiting). Built from `hot`; Redis is the only rate-limit hot path.
    pub quota: Option<crate::quota::RateLimiter>,
    /// Visitor email-OTP store (in-memory; codes die with the process).
    pub otp: std::sync::Arc<crate::auth_otp::OtpStore>,
    /// Generic OIDC client (None → `/__auth/oidc/*` answers 503).
    pub oidc: Option<std::sync::Arc<crate::auth_oidc::OidcClient>>,
    /// Operator activity audit log (operations + logins).
    pub audit: crate::audit::AuditStore,
    /// One-time client setup codes (download-my-client auto-connect).
    pub setup: crate::setup::SetupStore,
}

impl BrokerState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<BrokerConfig>,
        registry: Arc<Registry>,
        drain_tx: watch::Sender<bool>,
        acme: Option<Arc<ChallengeStore>>,
        register_limiter: Arc<RateLimiter>,
        operator_login_limiter: Arc<RateLimiter>,
        domains: domain::DomainStore,
        tunnels: tunnel::TunnelStore,
        accounts: account::AccountStore,
        mailer: Option<crate::mailer::Mailer>,
        active_apex: Option<String>,
        settings: Arc<RwLock<settings::Settings>>,
        settings_store: settings::SettingsStore,
        hot: Option<crate::hot::HotCounter>,
        quota: Option<crate::quota::RateLimiter>,
        audit: crate::audit::AuditStore,
        setup: crate::setup::SetupStore,
        otp: std::sync::Arc<crate::auth_otp::OtpStore>,
        oidc: Option<std::sync::Arc<crate::auth_oidc::OidcClient>>,
    ) -> Self {
        Self {
            config,
            registry,
            traffic: Arc::new(DashMap::new()),
            p2p_visitors: Arc::new(DashMap::new()),
            drain: drain_tx,
            acme,
            register_limiter,
            operator_login_limiter,
            domains,
            tunnels,
            accounts,
            mailer,
            active_apex: Arc::new(RwLock::new(active_apex)),
            settings,
            settings_store,
            hot,
            quota,
            audit,
            setup,
            otp,
            oidc,
        }
    }

    /// Refresh the cached active apex (called by the domains API after
    /// activate/create/delete/update — Task 9).
    pub async fn refresh_active_apex(&self) {
        let name = self
            .domains
            .active_apex()
            .await
            .ok()
            .flatten()
            .map(|d| d.name);
        *self.active_apex.write().unwrap_or_else(|p| p.into_inner()) = name;
    }

    /// Kill every live session whose token id matches `token_id` (admin
    /// action: token disable/delete).
    pub fn kill_sessions_for_token(&self, token_id: &str) {
        for session in self.registry.list() {
            if session.token_id == token_id {
                session.kill(KillReason::Admin);
            }
        }
    }

    /// Apply a mutation to the cached settings, persist it, and refresh the
    /// shell branding. Single write path for settings changes.
    pub fn update_settings(
        &self,
        f: impl FnOnce(&mut settings::Settings),
    ) -> Result<(), token::StoreError> {
        let mut next = self
            .settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        f(&mut next);
        self.settings_store.save(&next)?;
        crate::ui::set_branding(&next.instance_name, &next.support_url);
        *self.settings.write().unwrap_or_else(|p| p.into_inner()) = next;
        Ok(())
    }

    /// Entitlement snapshot for a connecting token:
    /// plan limits; operator/ownerless tokens keep their own limits. Store
    /// errors degrade to the token's own limits (never block registration).
    pub async fn entitle(&self, record: &token::TokenRecord) -> TokenLimits {
        // Free edition: tokens carry their own operator-set limits.
        record.limits
    }

    /// Resolve the account's plan `max_tunnels` cap for a tunnel create
    /// (0 = unlimited/exempt). Ownerless (operator/legacy) tokens and unknown
    /// tokens are exempt (0). The cap comes from the account's PLAN via
    /// `effective_limits` (never `TokenRecord.limits`). The handler passes it
    /// to `TunnelStore::create_checked`, which enforces it atomically with the
    /// INSERT (count + insert share one mutex acquisition).
    pub async fn tunnel_quota_cap(&self, token_id: &str) -> u32 {
        let Some(record) = self.config.token_store.get(token_id).await else {
            // Unknown token: let create_checked surface the validation error.
            return 0;
        };
        if record.owner_id.is_none() {
            return 0; // operator/legacy token — exempt from plan quota
        }
        self.entitle(&record).await.max_tunnels
    }
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------

pub fn router(state: BrokerState) -> Router {
    // Operator-only routes (dashboard + pages + REST API). The global
    // require_session layer runs first (outermost) and inserts claims; this
    // inner require_operator enforces the operator role. Tunnel visitors
    // (no claims) pass through the middleware's None branch.
    let operator_private = Router::new()
        .route("/", get(dashboard))
        .route("/metrics", get(metrics_page))
        .route("/tokens", get(tokens_page).post(tokens_submit))
        .route("/tokens/{id}/disable", post(tokens_disable))
        .route("/tokens/{id}/enable", post(tokens_enable))
        .route("/tokens/{id}/delete", post(tokens_delete))
        .route("/domains", get(domains_page).post(domains_submit))
        .route("/domains/{id}/activate", post(domains_activate))
        .route("/domains/{id}/delete", post(domains_delete))
        .route("/tunnels", get(tunnels_page).post(tunnels_submit))
        .route("/tunnels/new", get(tunnels_new_page))
        .route("/tunnels/{id}/edit", get(tunnel_edit_page))
        .route("/tunnels/{id}", post(tunnels_update))
        .route("/tunnels/{id}/toggle", post(tunnels_toggle))
        .route("/tunnels/{id}/delete", post(tunnels_delete))
        .route(
            "/settings",
            get(settings_page).post(settings_password_submit),
        )
        .route("/ui-kit", get(ui_kit_page))
        .route("/settings/2fa/setup", post(settings_2fa_setup))
        .route("/settings/2fa/verify", post(settings_2fa_verify))
        .route("/settings/2fa/disable", post(settings_2fa_disable))
        .route("/settings/security", post(settings_security_submit))
        .route("/settings/alerts", post(settings_alerts_submit))
        .route("/settings/defaults", post(settings_defaults_submit))
        .route("/settings/instance", post(settings_instance_submit))
        .route("/audit", get(audit_page))
        .route("/api/cert", get(api_cert))
        .route("/sessions/{slug}/kill", post(session_kill))
        .route("/debug/{slug}", get(debug_page))
        .route("/debug/{slug}/replay", post(debug_replay))
        .route("/debug/{slug}/body/{index}", get(debug_body))
        .route("/policies", get(policies_page).post(policies_submit))
        .route("/policies/{id}/delete", post(policies_delete));

    Router::new()
        .route("/health", get(health_check))
        .route("/__auth/oidc/start", get(oidc_start))
        .route("/__auth/oidc/cb", get(oidc_cb))
        .route("/__auth/otp", get(otp_form))
        .route("/__auth/otp/send", post(otp_send))
        .route("/__auth/otp/verify", post(otp_verify))
        .route("/api/version", get(api_version))
        .route("/connect", get(mux::ws_handler))
        .route("/__p2p/signal", get(crate::p2p_signal::signal_handler))
        .route("/__tunnello/sw.js", get(service_worker))
        .route("/t/{slug}", get(tunnel_status))
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route("/logout", get(auth::logout))
        .route("/setup", get(auth::setup_page).post(auth::setup_submit))
        .route("/install.sh", get(install_script))
        .route("/downloads", get(downloads_page))
        .route("/download/{file}", get(download_file))
        .route("/_assets/{*path}", get(web_asset))
        .merge(operator_private)
        .fallback(fallback)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// security headers + CSRF origin check (outermost middleware)
// ---------------------------------------------------------------------------

/// Content-Security-Policy applied to every response. The `'unsafe-inline'`
/// for script/style is required by the existing inline theme-boot/toast
/// scripts — tightening would break the islands' theme toggle.
const CSP_VALUE: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src \
     'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; \
     base-uri 'none'; form-action 'self'";

/// Outermost middleware: adds security headers to every response and enforces
/// a same-origin check (CSRF defense-in-depth) on state-changing methods that
/// carry an `Origin` header. Requests without an `Origin` header (curl, API
/// clients and the raw-HTTP test harness) pass through.
async fn security_headers(
    State(state): State<BrokerState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Tunnel visitor requests serve the customer's own site, not broker UI:
    // the broker's CSP would break their external resources and the Origin
    // check would 403 cross-site browser POSTs to their site. The Origin check
    // runs before the handler, so detect tunnel visitors from the request
    // host; the header skip is driven by the `TunneledResponse` extension set
    // by `serve_tunnel`.
    let tunneled = matches!(
        req.method(),
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    ) && resolve_tunnel(&state, &req).is_some();
    if !tunneled && let Some(forbidden) = csrf_forbidden(&state, &req) {
        return forbidden;
    }

    let mut response = next.run(req).await;
    if response
        .extensions()
        .get::<http_tunnel::TunneledResponse>()
        .is_none()
    {
        apply_security_headers(response.headers_mut(), &state);
    }
    response
}

/// Return a 403 when a state-changing request carries a mismatched `Origin`.
fn csrf_forbidden(state: &BrokerState, req: &Request<Body>) -> Option<Response> {
    if !matches!(
        req.method(),
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    ) {
        return None;
    }
    let origin = req.headers().get(header::ORIGIN)?;
    let matched = origin
        .to_str()
        .map(|o| origin_matches(o, req))
        .unwrap_or(false);
    if matched {
        return None;
    }
    let mut response = (StatusCode::FORBIDDEN, "forbidden").into_response();
    apply_security_headers(response.headers_mut(), state);
    Some(response)
}

/// Insert the security headers into a response, honouring dev-mode HSTS.
fn apply_security_headers(headers: &mut axum::http::HeaderMap, state: &BrokerState) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CSP_VALUE),
    );
    // Dev brokers use self-signed certs — HSTS would break local testing.
    if !state.config.dev {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000"),
        );
    }
}

/// Compare an `Origin` header against the request's own effective origin:
/// `https://host[:port]`, where host/port come from the request's `Host`
/// header. The broker is TLS-only even in dev (self-signed cert; the :80
/// listener only 301-redirects/serves ACME), so a browser's same-origin form
/// post always carries an `https://` origin. Default ports (`:443`/`:80`) are
/// normalized away on both sides.
fn origin_matches(origin: &str, req: &Request<Body>) -> bool {
    let Some(authority) = req_authority(req) else {
        return false;
    };
    let Some((host, port)) = split_host_port(authority) else {
        return false;
    };

    let Some((origin_scheme, origin_host, origin_port)) = parse_origin(origin) else {
        return false;
    };

    origin_scheme == "https"
        && origin_host.eq_ignore_ascii_case(host)
        && effective_port(origin_scheme, origin_port) == effective_port(origin_scheme, port)
}

/// The request's `Host` header, falling back to the h2 `:authority`.
fn req_authority(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
}

/// Parse a `scheme://host[:port]` origin value. A trailing path/query or the
/// opaque `null` origin yields `None` (never a match).
fn parse_origin(origin: &str) -> Option<(&str, &str, Option<u16>)> {
    let (scheme, rest) = origin
        .strip_prefix("https://")
        .map(|r| ("https", r))
        .or_else(|| origin.strip_prefix("http://").map(|r| ("http", r)))?;
    if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return None;
    }
    let (host, port) = split_host_port(rest)?;
    Some((scheme, host, port))
}

/// Split `host[:port]` (or `[ipv6]:port`) into host + optional numeric port.
fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if after.is_empty() {
            return Some((host, None));
        }
        let port = after.strip_prefix(':')?;
        return Some((host, parse_port(port)));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some((host, parse_port(port)))
        }
        _ => Some((authority, None)),
    }
}

/// Parse an optional numeric port (`None` when absent).
fn parse_port(port: &str) -> Option<u16> {
    port.parse::<u16>().ok()
}

/// Normalize a port: the scheme's default port is collapsed to `None` so
/// `https://x` and `https://x:443` compare equal.
fn effective_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    match port {
        Some(80) if scheme == "http" => None,
        Some(443) if scheme == "https" => None,
        other => other,
    }
}

// ---------------------------------------------------------------------------
// metrics — GET /metrics (operator-gated Prometheus text exposition)
// ---------------------------------------------------------------------------

/// Serve the Prometheus text exposition of the `ddns_*` metrics. Reached only
/// through the `operator_private` router (behind `require_session` +
/// `require_operator`).
/// GET /health — public liveness/readiness probe (no auth).
/// Returns broker uptime, active session count, and version.
/// GET /api/version — public version info for client update checks.
async fn api_version() -> Response {
    let body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "min_client_version": "0.4.0",
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn health_check(State(state): State<BrokerState>) -> Response {
    let sessions = state.registry.list().len();
    let body = serde_json::json!({
        "status": "ok",
        "sessions": sessions,
        "version": env!("CARGO_PKG_VERSION"),
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn metrics_page() -> Response {
    let body = crate::metrics::render();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// fallback — tunnel dispatch (unchanged from Tasks 1-6)
// ---------------------------------------------------------------------------

/// Request host (port stripped, lowercased) from the `Host` header or the h2
/// `:authority` (exposed on the URI) — both are checked so h2 visitor traffic
/// routes too.
pub(crate) fn req_host(req: &Request<Body>) -> Option<String> {
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))?;
    Some(strip_port(&host).to_ascii_lowercase())
}

/// Strip an optional `:port` suffix from a Host/authority value. A bracketed
/// IPv6 literal is left intact (`[::1]:8080` → `[::1]`); a bare `split(':')`
/// would mangle it into `[`, breaking Host matching for IPv6 literals.
pub(crate) fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host.find(']').map(|i| &host[..=i]).unwrap_or(host);
    }
    host.split_once(':').map(|(h, _)| h).unwrap_or(host)
}

/// If the request Host is `<slug>.<domain>` (a tunnel subdomain), return the
/// slug. Apex (`<domain>`) and unrelated hosts yield None.
pub(crate) fn tunnel_slug(req: &Request<Body>, domain: &str) -> Option<String> {
    let host = req_host(req)?;
    let suffix = format!(".{domain}");
    host.strip_suffix(&suffix)
        .filter(|s| !s.is_empty() && !s.contains('.'))
        .map(str::to_string)
}

/// Resolve a visitor request to a live session. DB-free: an exact custom-host
/// match first, then `slug.<active-apex>`. Unknown hosts → None → 404 / dashboard.
pub(crate) fn resolve_tunnel(
    state: &BrokerState,
    req: &Request<Body>,
) -> Option<Arc<TunnelSession>> {
    let host = req_host(req)?;
    if let Some(s) = state.registry.custom_host(&host) {
        return Some(s);
    }
    let apex = state
        .active_apex
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()?;
    let slug = tunnel_slug(req, &apex)?;
    state.registry.lookup(&slug)
}

/// Unmatched path: if `Host: <slug>.<domain>` resolves to a live session,
/// serve the request through the tunnel; otherwise 404.
async fn fallback(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    let Some(session) = resolve_tunnel(&state, &req) else {
        return (StatusCode::NOT_FOUND, "no such tunnel").into_response();
    };
    // P2P connector page: the root HTML document of a tunnel is served by the
    // broker (the connector registers the SW and drives the signaling), unless
    // the client explicitly asked to relay — the SW's fallback fetch carries
    // `X-Tunnello-Relay: 1` so it never re-serves the connector page.
    if req.method() == Method::GET
        && req.uri().path() == "/"
        && !req.headers().contains_key("x-tunnello-relay")
        && req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("text/html"))
    {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            crate::connector::connector_page(&session.slug),
        )
            .into_response();
    }
    // Tenant scope for the rate limiter: the token's owner account. Operator /
    // ownerless (legacy) tokens are exempt (None). This is the in-memory token
    // cache — no SQLite hit on the visitor hot path.
    let account_id = state
        .config
        .token_store
        .get(&session.token_id)
        .await
        .and_then(|t| t.owner_id);
    http_tunnel::serve_tunnel(req, session, peer, state.quota.as_ref(), account_id).await
}

/// GET /__tunnello/sw.js — the P2P Service Worker, served at the tunnel origin
/// with a scope-wide allowance (so it can control any path under the tunnel)
/// and no caching (the broker always serves the current version).
async fn service_worker() -> Response {
    (
        StatusCode::OK,
        [
            ("content-type", "application/javascript"),
            ("service-worker-allowed", "/"),
            ("cache-control", "no-store"),
        ],
        crate::connector::service_worker_js(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// operator dashboard — GET /
// ---------------------------------------------------------------------------

async fn dashboard(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    // Tunnel traffic is tunnel traffic even at `/` — never the dashboard.
    // Slug-shaped hosts divert unconditionally (dead slugs 404 via fallback,
    // never render operator pages); custom hosts divert only when a live
    // session holds them (a faked custom host must stay auth-gated).
    let is_tunnel = tunnel_slug(&req, &state.config.domain).is_some()
        || req_host(&req).is_some_and(|h| state.registry.custom_host(&h).is_some());
    if is_tunnel {
        return fallback(State(state), ConnectInfo(peer), req).await;
    }
    let sessions = state.registry.list();
    let total_sessions = sessions.len();
    let max_sessions = state.registry.max_sessions();

    // Aggregate totals and sample traffic rings.
    let mut total_bytes: u64 = 0;
    let mut total_streams: u32 = 0;
    let mut rows = String::new();

    for s in &sessions {
        let usage = s.usage();
        let current_total = usage.bytes_tx.saturating_add(usage.bytes_rx);
        total_bytes = total_bytes.saturating_add(current_total);
        total_streams = total_streams.saturating_add(usage.streams);

        // Update traffic ring.
        let ring = {
            let entry = state
                .traffic
                .entry(s.slug.clone())
                .or_insert_with(|| std::sync::Mutex::new(TrafficRing::new()));
            let mut ring = entry.lock().unwrap();
            ring.sample(current_total);
            ring.deltas.clone()
        };
        let sparkline = sparkline_svg(&ring);

        let uptime = uptime_str(s.created_at);
        let bytes_in = bytes_human(usage.bytes_tx);
        let bytes_out = bytes_human(usage.bytes_rx);
        let streams_peak = s.streams_peak.load(std::sync::atomic::Ordering::Relaxed);
        let peer_ip = s
            .peer_ip()
            .map(|ip| html_escape(&ip.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        rows.push_str(&format!(
            "<tr>\
               <td><a class=\"slug\" href=\"/t/{slug}\">{slug}</a></td>\
               <td class=\"token\">{token}</td>\
               <td class=\"mono\">{peer_ip}</td>\
               <td>{uptime}</td>\
               <td>{streams} / {peak}</td>\
               <td class=\"bytes\">{bytes_in}</td>\
               <td class=\"bytes\">{bytes_out}</td>\
               <td>{sparkline}</td>\
               <td><form method=\"post\" action=\"/sessions/{slug}/kill\"><button class=\"kill-btn\" type=\"submit\">Kill</button></form></td>\
             </tr>",
            slug = html_escape(&s.slug),
            token = &truncate_escape(&s.token_id, 32),
            peer_ip = peer_ip,
            uptime = uptime,
            streams = usage.streams,
            peak = streams_peak,
            bytes_in = bytes_in,
            bytes_out = bytes_out,
            sparkline = sparkline,
        ));
    }

    let body = format!(
        r###"<h1>Tunnel Dashboard</h1>
  <div id="island-root" data-island="dashboard">
  <p class="subtitle">{total_sessions} of {max_sessions} sessions active</p>
  <div class="stats">
    <div class="stat-card glass"><div class="label">Active Tunnels</div><div class="value">{total_sessions}</div></div>
    <div class="stat-card glass"><div class="label">Total Bytes</div><div class="value">{total_bytes_human}</div></div>
    <div class="stat-card glass"><div class="label">Total Streams</div><div class="value">{total_streams}</div></div>
  </div>
  {table_or_empty}</div>
  <script type="module" src="{bundle}"></script>
  <footer>Tunello</footer>"###,
        total_sessions = total_sessions,
        max_sessions = max_sessions,
        total_bytes_human = bytes_human(total_bytes),
        total_streams = total_streams,
        bundle = crate::ui::bundle_script(),
        table_or_empty = if total_sessions == 0 {
            r#"<div class="empty-state"><div class="empty-icon">&#128225;</div>
<div class="empty-title">No live tunnels</div>
<div class="empty-text">Start a client with one of your tokens to open a tunnel.</div>
<div class="empty-cta"><a class="btn" href="/tokens">View tokens</a></div></div>"#
                .to_string()
        } else {
            format!(
                "<div class=\"glass\" style=\"padding:6px 6px\"><table><thead><tr><th>Subdomain</th><th>Token</th><th>Peer IP</th><th>Uptime</th><th>Streams (peak)</th><th>Bytes In</th><th>Bytes Out</th><th>Activity</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        }
    );

    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        crate::ui::page_shell("Dashboard", crate::ui::NavItem::Dashboard, &body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// public per-tunnel status page — GET /t/:slug
// ---------------------------------------------------------------------------

async fn tunnel_status(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(slug): Path<String>,
    req: Request<Body>,
) -> Response {
    // `/t/...` on a tunnel subdomain is tunnel traffic too.
    if tunnel_slug(&req, &state.config.domain).is_some() {
        return fallback(State(state), ConnectInfo(peer), req).await;
    }
    if slug.is_empty() || slug.len() > 64 || slug.chars().any(char::is_control) {
        return not_found_page(&slug);
    }
    let Some(session) = state.registry.lookup(&slug) else {
        return not_found_page(&slug);
    };

    let usage = session.usage();
    let total_bytes = usage.bytes_tx.saturating_add(usage.bytes_rx);
    let active_streams = usage.streams;
    let peak = session
        .streams_peak
        .load(std::sync::atomic::Ordering::Relaxed);
    let uptime = uptime_str(session.created_at);
    let expired = session.expired();
    let status_class = if expired { "status-down" } else { "status-up" };
    let status_text = if expired { "DOWN" } else { "UP" };

    let body = format!(
        r###"<h1><span class="slug" style="color:#4f46e5;font-family:ui-monospace,monospace">{slug}</span></h1>
  <p class="subtitle">Public tunnel status page</p>
  <div class="cards">
    <div class="card glass"><div class="label">Status</div><div class="value"><span class="status {status_class}">{status_text}</span></div></div>
    <div class="card glass"><div class="label">Uptime</div><div class="value">{uptime}</div></div>
    <div class="card glass"><div class="label">Active Streams</div><div class="value">{active_streams}</div></div>
    <div class="card glass"><div class="label">Peak Streams</div><div class="value">{peak}</div></div>
  </div>
  <div class="section card glass">
    <h2>Traffic</h2>
    <div class="kv"><span class="k">Bytes In</span><span class="v">{bytes_in}</span></div>
    <div class="kv"><span class="k">Bytes Out</span><span class="v">{bytes_out}</span></div>
    <div class="kv"><span class="k">Total</span><span class="v">{total_bytes_human}</span></div>
  </div>
  <div class="section card glass">
    <h2>Connection</h2>
    <div class="kv"><span class="k">Handles HTTP</span><span class="v">{want_http}</span></div>
    <div class="kv"><span class="k">Handles TCP</span><span class="v">{want_tcp}</span></div>
    <div class="kv"><span class="k">Max Streams</span><span class="v">{max_streams}</span></div>
    <div class="kv"><span class="k">Max Bytes</span><span class="v">{max_bytes_human}</span></div>
    <div class="kv"><span class="k">TTL</span><span class="v">{ttl}</span></div>
  </div>
  <a class="back" href="/">&larr; Back to dashboard</a>
  <footer>Tunello</footer>"###,
        slug = html_escape(&slug),
        status_class = status_class,
        status_text = status_text,
        uptime = uptime,
        active_streams = active_streams,
        peak = peak,
        bytes_in = bytes_human(usage.bytes_tx),
        bytes_out = bytes_human(usage.bytes_rx),
        total_bytes_human = bytes_human(total_bytes),
        want_http = if session.want_http { "yes" } else { "no" },
        want_tcp = if session.want_tcp { "yes" } else { "no" },
        max_streams = limit_count_human(session.limits.max_streams),
        max_bytes_human = limit_bytes_human(session.limits.max_bytes),
        ttl = limit_duration_human(session.limits.ttl_secs),
    );

    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        crate::ui::page_shell(
            &format!("{slug} — Tunnel Status"),
            crate::ui::NavItem::None,
            &body,
        ),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// session kill (form-based, for dashboard kill button)
// ---------------------------------------------------------------------------

async fn session_kill(State(state): State<BrokerState>, Path(slug): Path<String>) -> Response {
    if let Some(session) = state.registry.lookup(&slug) {
        session.kill(KillReason::Admin);
    }
    crate::ui::flash_redirect("/", crate::ui::FlashKind::Success, "Session killed")
}

/// Named option presets ("resource policies") — list + create form.
async fn policies_page(State(state): State<BrokerState>) -> Response {
    let policies = state.tunnels.list_policies().await.unwrap_or_default();
    let mut rows = String::new();
    for (id, name, options_json) in &policies {
        rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{}</code></td>\
             <td><form method=\"post\" action=\"/policies/{}/delete\">\
             <button class=\"btn danger\">Delete</button></form></td></tr>",
            html_escape(name),
            html_escape(options_json),
            id,
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"3\">No policies yet.</td></tr>".into();
    }
    let body = format!(
        "<div class=\"box\"><h2>Create / update policy</h2>\
         <form method=\"post\" action=\"/policies\" class=\"inline-form\">\
         <input name=\"name\" placeholder=\"policy name\" required>\
         <input name=\"options_json\" placeholder='{{\"pin_auth\":\"1234\"}}' required>\
         <button class=\"btn\" type=\"submit\">Save</button></form></div>\
         <div class=\"box\"><h2>Existing policies</h2>\
         <table><thead><tr><th>Name</th><th>Options JSON</th><th></th></tr></thead>\
         <tbody>{}</tbody></table></div>",
        rows,
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        crate::ui::page_shell("Policies", crate::ui::NavItem::Policies, &body),
    )
        .into_response()
}

async fn policies_submit(State(state): State<BrokerState>, body: String) -> Response {
    let name = form_field(&body, "name");
    let options_json = form_field(&body, "options_json");
    if name.is_empty() || options_json.is_empty() {
        return crate::ui::flash_redirect(
            "/policies",
            crate::ui::FlashKind::Error,
            "Name and options JSON are required",
        );
    }
    // Validate the JSON is a parseable HttpOptions
    if serde_json::from_str::<serde_json::Value>(&options_json).is_err() {
        return crate::ui::flash_redirect("/policies", crate::ui::FlashKind::Error, "Invalid JSON");
    }
    match state.tunnels.save_policy(&name, &options_json).await {
        Ok(_) => {
            state.audit.record("operator", "-", "policy.save", &name);
            crate::ui::flash_redirect("/policies", crate::ui::FlashKind::Success, "Policy saved")
        }
        Err(e) => crate::ui::flash_redirect(
            "/policies",
            crate::ui::FlashKind::Error,
            &format!("Save failed: {e}"),
        ),
    }
}

async fn policies_delete(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    match state.tunnels.delete_policy(&id).await {
        Ok(_) => {
            state.audit.record("operator", "-", "policy.delete", &id);
            crate::ui::flash_redirect("/policies", crate::ui::FlashKind::Success, "Policy deleted")
        }
        Err(e) => crate::ui::flash_redirect(
            "/policies",
            crate::ui::FlashKind::Error,
            &format!("Delete failed: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// visitor auth: OIDC + email OTP (public routes; spec 2026-08-26 Phase 1)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct AuthQuery {
    back: Option<String>,
}

#[derive(serde::Deserialize)]
struct OtpForm {
    email: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    back: String,
}

fn server_secret(
    state: &BrokerState,
) -> impl std::future::Future<Output = Result<Vec<u8>, crate::token::StoreError>> + '_ {
    state.config.token_store.server_secret()
}

fn append_cookie(resp: &mut axum::response::Response, cookie: &str, dev: bool) {
    let mut v = cookie.to_string();
    if !dev {
        v.push_str("; Secure");
    }
    if let Ok(hv) = axum::http::HeaderValue::from_str(&v) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, hv);
    }
}

fn err_page(msg: &str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<!DOCTYPE html><html><body style=\"font-family:system-ui\">\
             <h2>Sign-in failed</h2><p>{msg}</p>\
             <p><a href=\"/\">Back</a></p></body></html>"
        ),
    )
        .into_response()
}

/// OIDC step 1: stash state+verifier in a short signed cookie, bounce to the
/// provider's authorization endpoint.
async fn oidc_start(State(state): State<BrokerState>, Query(q): Query<AuthQuery>) -> Response {
    let Some(oidc) = &state.oidc else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC not configured on this broker",
        )
            .into_response();
    };
    let Some(cfg) = &state.config.oidc else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC not configured on this broker",
        )
            .into_response();
    };
    let back = crate::visitor_auth::safe_back(q.back.as_deref());
    let (verifier, challenge) = crate::auth_oidc::pkce_pair();
    let oauth_state = format!("{:016x}", rand::Rng::random::<u64>(&mut rand::rng()));
    let d = match oidc.discover(cfg).await {
        Ok(d) => d,
        Err(e) => return err_page(&e),
    };
    let redirect_uri = format!(
        "{}/__auth/oidc/cb",
        state.config.base_url.trim_end_matches('/')
    );
    let loc = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email&state={oauth_state}&code_challenge={challenge}&code_challenge_method=S256",
        d.authorization_endpoint,
        urlencode(&cfg.client_id),
        urlencode(&redirect_uri),
    );
    let secret = match server_secret(&state).await {
        Ok(s) => s,
        Err(e) => return err_page(&e.to_string()),
    };
    // Signed stash cookie: payload "oauth|{state}|{verifier}" rides the email
    // field of VisitorAuthCookie (opaque to the visitor, HMAC-checked on cb).
    let tmp = crate::visitor_auth::VisitorAuthCookie::issue(
        &secret,
        &format!("oauth|{oauth_state}|{verifier}"),
        600,
    )
    .unwrap_or_default();
    let dev = state.config.dev;
    let mut resp = axum::response::Redirect::to(&loc).into_response();
    append_cookie(
        &mut resp,
        &format!("tnl_oauth={tmp}; Path=/; HttpOnly; SameSite=Lax"),
        dev,
    );
    append_cookie(
        &mut resp,
        &format!("tnl_back={back}; Path=/; HttpOnly; SameSite=Lax"),
        dev,
    );
    resp
}

/// OIDC step 2: verify state, exchange the code, mint the 12 h auth cookie.
async fn oidc_cb(
    State(state): State<BrokerState>,
    Query(q): Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return (StatusCode::SERVICE_UNAVAILABLE, "OIDC not configured").into_response();
    };
    let Some(cfg) = &state.config.oidc else {
        return (StatusCode::SERVICE_UNAVAILABLE, "OIDC not configured").into_response();
    };
    let secret = match server_secret(&state).await {
        Ok(s) => s,
        Err(e) => return err_page(&e.to_string()),
    };
    let cookie_of = |prefix: &str| {
        headers
            .get_all(axum::http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|c| c.split(';'))
            .find_map(|p| p.trim().strip_prefix(prefix))
            .map(str::to_string)
    };
    let Some(stash) = cookie_of("tnl_oauth=")
        .as_deref()
        .and_then(|v| crate::visitor_auth::VisitorAuthCookie::verify(v, &secret))
    else {
        return err_page("expired sign-in attempt; try again");
    };
    let Some(rest) = stash.strip_prefix("oauth|") else {
        return err_page("bad sign-in state");
    };
    let Some((oauth_state, verifier)) = rest.split_once('|') else {
        return err_page("bad sign-in state");
    };
    if q.get("state").map(String::as_str) != Some(oauth_state) {
        tracing::warn!("oidc state mismatch");
        return err_page("state mismatch; try again");
    }
    let Some(code) = q.get("code") else {
        return err_page("missing code");
    };
    let redirect_uri = format!(
        "{}/__auth/oidc/cb",
        state.config.base_url.trim_end_matches('/')
    );
    let id_token = match oidc.exchange(cfg, code, verifier, &redirect_uri).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "oidc token exchange failed");
            return err_page("token exchange failed; try again");
        }
    };
    let Some(email) = crate::auth_oidc::email_from_id_token(&id_token) else {
        return err_page("provider did not return an email claim");
    };
    let back = cookie_of("tnl_back=").unwrap_or_else(|| "/".into());
    let auth = crate::visitor_auth::VisitorAuthCookie::issue(&secret, &email, 12 * 3600)
        .unwrap_or_default();
    let dev = state.config.dev;
    let mut resp =
        axum::response::Redirect::to(&crate::visitor_auth::safe_back(Some(&back))).into_response();
    append_cookie(
        &mut resp,
        &format!("tnl_auth={auth}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200"),
        dev,
    );
    append_cookie(
        &mut resp,
        "tnl_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        dev,
    );
    append_cookie(
        &mut resp,
        "tnl_back=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        dev,
    );
    resp
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// OTP entry form (email + hidden back target).
async fn otp_form(Query(q): Query<AuthQuery>) -> Response {
    let back = crate::visitor_auth::safe_back(q.back.as_deref());
    let html = format!(
        "<!DOCTYPE html><html><head><title>Sign in</title>\
         <style>body{{font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0;background:#f5f5f5}}\
         form{{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}}\
         input{{padding:.5rem;font-size:1rem;border:1px solid #ccc;border-radius:4px;margin:.25rem 0;width:16rem}}\
         button{{padding:.5rem 1rem;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer}}</style>\
         </head><body><form method=\"post\" action=\"/__auth/otp/send\">\
         <h2>Lock Email sign-in</h2>\
         <p>Enter your email to receive an access code.</p>\
         <input type=\"hidden\" name=\"back\" value=\"{back}\">\
         <input type=\"email\" name=\"email\" placeholder=\"you@example.com\" required autofocus>\
         <button type=\"submit\">Send code</button></form></body></html>"
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

async fn otp_send(State(state): State<BrokerState>, Form(f): Form<OtpForm>) -> Response {
    let email = f.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return err_page("enter a valid email address");
    }
    let code = match state.otp.generate(&email) {
        Ok(c) => c,
        Err(e) => return err_page(&e),
    };
    let mailer = state.mailer.clone();
    let dev = state.config.dev;
    let body = format!("Your access code is {code} (valid 5 minutes)");
    // Never leak whether the email exists; only surface config errors.
    if let Err(e) =
        crate::mailer::deliver(&mailer, dev, &email, "Your access code", &body, &body).await
        && e.contains("SMTP not configured")
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "email OTP not configured on this broker",
        )
            .into_response();
    }
    let back = crate::visitor_auth::safe_back(Some(&f.back));
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        format!(
            "<!DOCTYPE html><html><body style=\"font-family:system-ui\">\
             <h2>Code sent</h2><p>Check {email} for your 6-digit code.</p>\
             <form method=\"post\" action=\"/__auth/otp/verify\">\
             <input type=\"hidden\" name=\"email\" value=\"{email}\">\
             <input type=\"hidden\" name=\"back\" value=\"{back}\">\
             <input name=\"code\" placeholder=\"123456\" required autofocus>\
             <button type=\"submit\">Verify</button></form></body></html>"
        ),
    )
        .into_response()
}

async fn otp_verify(State(state): State<BrokerState>, Form(f): Form<OtpForm>) -> Response {
    let email = f.email.trim().to_lowercase();
    if let Err(e) = state.otp.verify(&email, f.code.trim()) {
        tracing::debug!(%email, ?e, "otp verify failed");
        return (StatusCode::UNAUTHORIZED, "invalid or expired code").into_response();
    }
    let secret = match server_secret(&state).await {
        Ok(s) => s,
        Err(e) => return err_page(&e.to_string()),
    };
    let auth = crate::visitor_auth::VisitorAuthCookie::issue(&secret, &email, 12 * 3600)
        .unwrap_or_default();
    let back = crate::visitor_auth::safe_back(Some(&f.back));
    let dev = state.config.dev;
    let mut resp = axum::response::Redirect::to(&back).into_response();
    append_cookie(
        &mut resp,
        &format!("tnl_otp={auth}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200"),
        dev,
    );
    resp
}

/// Live request debugger for one tunnel (last 100 requests; bodies only
/// when the tunnel's `debug_capture` option is on).
async fn debug_page(State(state): State<BrokerState>, Path(slug): Path<String>) -> Response {
    let Some(session) = state.registry.lookup(&slug) else {
        return crate::ui::flash_redirect("/", crate::ui::FlashKind::Error, "Session not found");
    };
    let entries = session.debug_snapshot();
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        debug_page_html(&slug, &entries, None),
    )
        .into_response()
}

/// Shared renderer: request table (+ body links + replay buttons) and an
/// optional replay-result banner.
fn debug_page_html(
    slug: &str,
    entries: &[crate::session::DebugEntry],
    replay: Option<(u16, String)>,
) -> String {
    let mut rows = String::new();
    for (i, e) in entries.iter().enumerate() {
        let status_class = match e.status {
            200..=299 => "ok",
            400..=499 => "warn",
            _ => "err",
        };
        let has_body = e.req_body.is_some() || e.resp_body.is_some();
        let body_cell = if has_body {
            format!("<a href=\"/debug/{slug}/body/{i}\">view</a>")
        } else {
            "&mdash;".to_string()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"st {}\">{}</td>\
             <td>{}ms</td><td>{} B / {} B</td><td>{}</td><td>{}</td>\
             <td><form method=\"post\" action=\"/debug/{slug}/replay\" class=\"replay-form\">\
             <input type=\"hidden\" name=\"index\" value=\"{i}\">\
             <button title=\"Replay this request\">Replay</button></form></td></tr>",
            e.at_unix,
            e.method,
            html_escape(&e.path),
            status_class,
            e.status,
            e.duration_ms,
            e.bytes_tx,
            e.bytes_rx,
            html_escape(&e.peer_ip),
            body_cell,
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"9\">No requests recorded yet.</td></tr>".into();
    }
    let banner = match replay {
        Some((status, body)) => format!(
            "<div class=\"replay-banner\"><strong>Replay: {status}</strong>\
             <pre>{}</pre></div>",
            html_escape(&body)
        ),
        None => String::new(),
    };
    format!(
        "<!DOCTYPE html><html><head><title>Debug {slug}</title><style>\
         body{{font-family:system-ui;margin:2rem;background:#0f172a;color:#e2e8f0}}\
         table{{border-collapse:collapse;width:100%}}\
         th,td{{padding:.5rem .75rem;border-bottom:1px solid #1e293b;text-align:left}}\
         th{{color:#94a3b8;font-weight:600}}\
         .st.ok{{color:#4ade80}}.st.warn{{color:#fbbf24}}.st.err{{color:#f87171}}\
         a{{color:#60a5fa}}\
         .replay-form{{display:inline}}\
         button{{background:#2563eb;color:#fff;border:0;border-radius:4px;padding:.25rem .6rem;cursor:pointer}}\
         .replay-banner{{background:#1e293b;border:1px solid #2563eb;border-radius:6px;padding:1rem;margin-bottom:1rem}}\
         pre{{white-space:pre-wrap;word-break:break-all;color:#94a3b8}}\
         </style></head><body>\
         <h1>Debug: {slug}</h1>\
         {banner}\
         <p><a href=\"/\">Back to Dashboard</a> | last {} requests, oldest first \
         | bodies appear when the tunnel's debug-capture option is on</p>\
         <table><tr><th>Time (unix)</th><th>Method</th><th>Path</th><th>Status</th>\
         <th>Duration</th><th>Bytes</th><th>Peer IP</th><th>Body</th><th>Replay</th></tr>{}</table>\
         </body></html>",
        entries.len(),
        rows,
    )
}

#[derive(serde::Deserialize)]
struct ReplayForm {
    index: usize,
}

/// Re-send a captured request through its tunnel (operator-only route).
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
        return crate::ui::flash_redirect(
            &format!("/debug/{slug}"),
            crate::ui::FlashKind::Error,
            "Entry no longer in the ring",
        );
    };
    // Rebuild the request from captured data. Sensitive headers arrive as
    // [REDACTED] — replaying them is safe (the backend sees the marker).
    let host = format!("{slug}.{}", state.config.domain);
    let mut builder = axum::http::Request::builder()
        .method(entry.method.as_str())
        .uri(entry.path.as_str())
        .header(axum::http::header::HOST, &host);
    for (k, v) in &entry.req_headers {
        if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_str());
    }
    let body = entry.req_body.clone().unwrap_or_default();
    let req = match builder.body(Body::from(body)) {
        Ok(r) => r,
        Err(e) => {
            return crate::ui::flash_redirect(
                &format!("/debug/{slug}"),
                crate::ui::FlashKind::Error,
                &format!("replay build failed: {e}"),
            );
        }
    };
    let peer: std::net::SocketAddr = session
        .peer_ip()
        .map(|ip| std::net::SocketAddr::new(ip, 0))
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    let resp =
        crate::http_tunnel::serve_tunnel(req, session.clone(), peer, state.quota.as_ref(), None)
            .await;
    let status = resp.status();
    let preview =
        match axum::body::to_bytes(resp.into_body(), crate::debug_capture::CAPTURE_LIMIT).await {
            Ok(b) => crate::debug_capture::truncate_body(&b),
            Err(e) => format!("<body read failed: {e}>"),
        };
    let entries = session.debug_snapshot();
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        debug_page_html(&slug, &entries, Some((status.as_u16(), preview))),
    )
        .into_response()
}

/// Captured headers + bodies for one entry (operator-only).
async fn debug_body(
    State(state): State<BrokerState>,
    Path((slug, index)): Path<(String, usize)>,
) -> Response {
    let Some(session) = state.registry.lookup(&slug) else {
        return crate::ui::flash_redirect("/", crate::ui::FlashKind::Error, "Session not found");
    };
    let entries = session.debug_snapshot();
    let Some(e) = entries.get(index) else {
        return crate::ui::flash_redirect(
            &format!("/debug/{slug}"),
            crate::ui::FlashKind::Error,
            "Entry no longer in the ring",
        );
    };
    let mut headers_html = String::new();
    for (k, v) in &e.req_headers {
        headers_html.push_str(&format!("{}: {}\n", html_escape(k), html_escape(v)));
    }
    let html = format!(
        "<!DOCTYPE html><html><head><title>Body {slug} #{index}</title><style>\
         body{{font-family:system-ui;margin:2rem;background:#0f172a;color:#e2e8f0}}\
         h2{{color:#94a3b8}}pre{{white-space:pre-wrap;word-break:break-all;background:#1e293b;\
         padding:1rem;border-radius:6px}}a{{color:#60a5fa}}</style></head><body>\
         <h1>{} {}</h1>\
         <p><a href=\"/debug/{slug}\">Back to Debug</a></p>\
         <h2>Request headers (redacted)</h2><pre>{headers_html}</pre>\
         <h2>Request body</h2><pre>{}</pre>\
         <h2>Response body</h2><pre>{}</pre>\
         </body></html>",
        html_escape(&e.method),
        html_escape(&e.path),
        html_escape(e.req_body.as_deref().unwrap_or("(not captured)")),
        html_escape(e.resp_body.as_deref().unwrap_or("(not captured)")),
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// form helpers (duplicated from auth.rs)
// ---------------------------------------------------------------------------

/// Extract a URL-encoded form field value. Returns `""` when absent.
fn form_field(body: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    for part in body.split('&') {
        if let Some(val) = part.strip_prefix(&prefix) {
            return percent_decode(val);
        }
    }
    String::new()
}

/// Decode `%XX` and `+` → space, byte-wise.
fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '+' => out.push(b' '),
            '%' => {
                let hi = chars.next().and_then(|c| c.to_digit(16));
                let lo = chars.next().and_then(|c| c.to_digit(16));
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
                    _ => out.push(b'%'),
                }
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// tokens page — GET /tokens
// ---------------------------------------------------------------------------

async fn tokens_page(State(state): State<BrokerState>) -> Response {
    let tokens = state.config.token_store.list().await;
    let mut owners = std::collections::HashMap::new();
    if let Ok(clients) = state.accounts.list_clients().await {
        for c in clients {
            owners.insert(c.id, c.email);
        }
    }
    let mut tunnel_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    if let Ok(tunnels) = state.tunnels.list().await {
        for t in &tunnels {
            *tunnel_counts.entry(t.token_id.clone()).or_insert(0) += 1;
        }
    }
    let (_table, body) = render_tokens_page(&tokens, None, &owners, &tunnel_counts);
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// tokens create submit — POST /tokens (form-encoded, returns page with secret)
// ---------------------------------------------------------------------------

async fn tokens_submit(State(state): State<BrokerState>, body: String) -> Response {
    let name = form_field(&body, "name");
    state.audit.record("operator", "-", "token.create", &name);
    let mut owners = std::collections::HashMap::new();
    if let Ok(clients) = state.accounts.list_clients().await {
        for c in clients {
            owners.insert(c.id, c.email);
        }
    }
    let mut tunnel_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    if let Ok(tunnels) = state.tunnels.list().await {
        for t in &tunnels {
            *tunnel_counts.entry(t.token_id.clone()).or_insert(0) += 1;
        }
    }
    if name.trim().is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        let tokens = state.config.token_store.list().await;
        let (_table, body) = render_tokens_page(&tokens, None, &owners, &tunnel_counts);
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    let defaults = state
        .settings
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .default_token_limits;
    let max_sessions: u32 = if form_field(&body, "max_sessions_unlimited") == "on" {
        0
    } else {
        match form_field(&body, "max_sessions").parse::<u32>() {
            Ok(n) => n.clamp(1, 65535),
            Err(_) => defaults.max_sessions,
        }
    };
    let max_streams: u32 = if form_field(&body, "max_streams_unlimited") == "on" {
        0
    } else {
        match form_field(&body, "max_streams").parse::<u32>() {
            Ok(n) => n.clamp(1, 65535),
            Err(_) => defaults.max_streams,
        }
    };
    let max_bytes: u64 = if form_field(&body, "max_bytes_unlimited") == "on" {
        0
    } else {
        match form_field(&body, "max_bytes").parse::<u64>() {
            Ok(n) => n.max(1),
            Err(_) => defaults.max_bytes,
        }
    };
    let ttl_secs: u64 = if form_field(&body, "ttl_secs_unlimited") == "on" {
        0
    } else {
        match form_field(&body, "ttl_secs").parse::<u64>() {
            Ok(n) => n.max(1),
            Err(_) => defaults.ttl_secs,
        }
    };

    let limits = TokenLimits {
        max_sessions,
        max_streams,
        max_bytes,
        ttl_secs,
        ..defaults
    };

    match state.config.token_store.create(&name, limits).await {
        Ok((_id, secret)) => {
            let tokens = state.config.token_store.list().await;
            let (_table, page) =
                render_tokens_page(&tokens, Some(&secret), &owners, &tunnel_counts);
            (
                StatusCode::CREATED,
                [
                    (
                        axum::http::header::CONTENT_TYPE,
                        "text/html; charset=utf-8".to_string(),
                    ),
                    (
                        axum::http::header::SET_COOKIE,
                        crate::ui::flash_cookie(crate::ui::FlashKind::Success, "Token created"),
                    ),
                ],
                page,
            )
                .into_response()
        }
        Err(_) => {
            let tokens = state.config.token_store.list().await;
            let (_table, body) = render_tokens_page(&tokens, None, &owners, &tunnel_counts);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// tokens actions — POST /tokens/{id}/disable|enable|delete
// ---------------------------------------------------------------------------

async fn tokens_disable(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "token.disable", &id);
    let _ = state.config.token_store.set_enabled(&id, false).await;
    state.kill_sessions_for_token(&id);
    crate::ui::flash_redirect("/tokens", crate::ui::FlashKind::Success, "Token disabled")
}

async fn tokens_enable(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "token.enable", &id);
    let _ = state.config.token_store.set_enabled(&id, true).await;
    crate::ui::flash_redirect("/tokens", crate::ui::FlashKind::Success, "Token enabled")
}

async fn tokens_delete(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "token.delete", &id);
    if let Err(e) = state.tunnels.delete_for_token(&id).await {
        tracing::warn!(?e, "token tunnel cascade failed");
    }
    if let Err(e) = state.config.token_store.delete(&id).await {
        tracing::warn!(?e, "token delete failed");
        return crate::ui::flash_redirect(
            "/tokens",
            crate::ui::FlashKind::Error,
            "Token delete failed",
        );
    }
    state.kill_sessions_for_token(&id);
    crate::ui::flash_redirect("/tokens", crate::ui::FlashKind::Success, "Token deleted")
}

// ---------------------------------------------------------------------------
// clients — GET /clients, GET /clients/{id}, POST activate-plan, POST suspend
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// plans — GET /plans, POST /plans/{id}
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// codes — GET /codes, POST /codes, POST /codes/{code}
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// analytics — GET /analytics (usage totals, top accounts, per-account table)
// ---------------------------------------------------------------------------

/// GET /audit — operator activity log (newest first). Transactions live in
/// this is the operation + login trail.
async fn audit_page(State(state): State<BrokerState>) -> Response {
    let rows = state.audit.recent(200);
    let mut out = String::new();
    for r in &rows {
        let when = chrono_str(r.created_at);
        let actor = match r.actor_type.as_str() {
            "client" => format!("client #{}", html_escape(&r.actor_id)),
            "operator" => "operator".to_string(),
            _ => html_escape(&r.actor_type),
        };
        out.push_str(&format!(
            "<tr><td class=\"mono\">{when}</td><td>{actor}</td>             <td>{action}</td><td>{detail}</td></tr>",
            when = when,
            actor = actor,
            action = html_escape(&r.action),
            detail = html_escape(&r.detail),
        ));
    }
    let table_or_empty = if rows.is_empty() {
        r#"<div class="empty-state"><div class="empty-icon">&#128221;</div>
<div class="empty-title">No activity yet</div>
<div class="empty-text">Operator and customer actions will appear here.</div></div>"#
            .to_string()
    } else {
        format!(
            "<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>{out}</tbody></table>"
        )
    };
    let body = format!(
        "<h1>Activity log</h1>\
         <p class=\"subtitle\">{n} entries — latest first · operations are listed latest-first</p>\
         {table_or_empty}",
        n = rows.len()
    );
    crate::auth::Html::ok(crate::ui::page_shell(
        "Activity",
        crate::ui::NavItem::Audit,
        &body,
    ))
}

// ---------------------------------------------------------------------------
// domains page — GET /domains
// ---------------------------------------------------------------------------

fn html_page(status: StatusCode, html: String) -> Response {
    (status, [("content-type", "text/html; charset=utf-8")], html).into_response()
}

/// Hostname-shaped: letters, digits, dots, hyphens — enough to keep the DNS
/// guidance legible. The store validates canonical names more strictly.
fn valid_domain_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

async fn render_domains_page(state: &BrokerState, err: Option<&str>) -> String {
    let domains = state.domains.list().await.unwrap_or_default();
    let mut rows = String::new();
    for d in &domains {
        let active_badge = if d.active {
            r#"<span class="status status-up">active</span>"#
        } else {
            r#"<span class="status status-down">inactive</span>"#
        };
        let val_class = if d.validation_status.as_str() == "active" {
            "status-up"
        } else {
            "status-down"
        };
        let guidance = match d.kind {
            crate::domain::DomainKind::Apex => format!(
                "Point *.{name} (and {name}) at this broker — CNAME or A/AAAA per provider; Phase B drives DNS-01 validation.",
                name = html_escape(&d.name)
            ),
            crate::domain::DomainKind::Custom => {
                "Phase B: DNS-01 validation + certificate issuance.".to_string()
            }
        };
        let actions = format!(
            "<span class=\"row-actions\">\
             <form method=\"post\" action=\"/domains/{id}/activate\"><button class=\"btn-sm\" type=\"submit\">Activate</button></form>\
             <form method=\"post\" action=\"/domains/{id}/delete\" onsubmit=\"return confirm('Delete this domain?')\"><button class=\"btn-sm btn-danger\" type=\"submit\">Delete</button></form>\
             </span>",
            id = html_escape(&d.id)
        );
        rows.push_str(&format!(
            "<tr>\
             <td>{name}</td><td>{kind}</td><td>{active}</td>\
             <td><span class=\"status {val_class}\">{val}</span></td>\
             <td><span class=\"status status-down\">{cert}</span></td>\
             <td class=\"guidance\">{guidance}</td>\
             <td>{actions}</td>\
             </tr>",
            name = html_escape(&d.name),
            kind = d.kind.as_str(),
            active = active_badge,
            val = d.validation_status.as_str(),
            cert = d.cert_status.as_str(),
            guidance = guidance,
            actions = actions,
        ));
    }
    let table = if domains.is_empty() {
        r#"<div class="empty-state"><div class="empty-icon">&#128230;</div>
<div class="empty-title">No domains yet</div>
<div class="empty-text">Add an apex domain to route slug.&lt;domain&gt; traffic.</div>
<div class="empty-cta"><a class="btn" href="/domains">Add a domain</a></div></div>"#
            .to_string()
    } else {
        format!(
            "<div class=\"glass\" style=\"padding:6px 6px\"><table><thead><tr><th>Name</th><th>Kind</th><th>Active</th><th>Validation</th><th>Cert</th><th>DNS guidance</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    };
    let err_html = err
        .map(|e| format!("<div class=\"msg-error\">{}</div>", html_escape(e)))
        .unwrap_or_default();
    let body = format!(
        r###"<h1>Domains</h1>
  <p class="subtitle">Apex and custom domains behind tunnel hostnames</p>
  {err_html}
  <div class="create-form glass">
    <h2>Add domain</h2>
    <form method="post" action="/domains">
      <div class="form-row">
        <div class="form-group">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required maxlength="253" autofocus placeholder="example.com">
        </div>
        <div class="form-group">
          <label for="kind">Kind</label>
          <select id="kind" name="kind">
            <option value="apex">apex</option>
            <option value="custom">custom</option>
          </select>
        </div>
      </div>
      <button class="create-btn" type="submit">Add domain</button>
    </form>
  </div>
  {table}
  <footer>Tunello</footer>"###,
        err_html = err_html,
        table = table,
    );
    crate::ui::page_shell("Domains", crate::ui::NavItem::Domains, &body)
}

async fn domains_page(
    State(state): State<BrokerState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let err = params.get("err").map(String::as_str);
    html_page(StatusCode::OK, render_domains_page(&state, err).await)
}

/// POST /domains — create a domain.
async fn domains_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record(
        "operator",
        "-",
        "domain.create",
        &auth::form_field(&body, "name"),
    );
    let name = form_field(&body, "name");
    let kind_raw = form_field(&body, "kind");
    if !valid_domain_name(&name) {
        return html_page(
            StatusCode::BAD_REQUEST,
            render_domains_page(&state, Some("Name must be a valid hostname.")).await,
        );
    }
    let kind = match crate::domain::DomainKind::parse(&kind_raw) {
        Ok(k) => k,
        Err(_) => {
            return html_page(
                StatusCode::BAD_REQUEST,
                render_domains_page(&state, Some("Kind must be 'apex' or 'custom'.")).await,
            );
        }
    };
    match state.domains.create(name.trim(), kind).await {
        Ok(_) => {
            crate::ui::flash_redirect("/domains", crate::ui::FlashKind::Success, "Domain added")
        }
        Err(e) => html_page(
            StatusCode::BAD_REQUEST,
            render_domains_page(&state, Some(&format!("{e}"))).await,
        ),
    }
}

/// POST /domains/{id}/activate
async fn domains_activate(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "domain.activate", &id);
    match state.domains.activate(&id).await {
        Ok(_) => {
            state.refresh_active_apex().await;
            crate::ui::flash_redirect("/domains", crate::ui::FlashKind::Success, "Apex activated")
        }
        Err(e) => (
            StatusCode::SEE_OTHER,
            [(
                "location",
                format!("/domains?err={}", urlencode(&e.to_string())).as_str(),
            )],
        )
            .into_response(),
    }
}

/// POST /domains/{id}/delete
async fn domains_delete(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "domain.delete", &id);
    match state.domains.delete(&id).await {
        Ok(_) => {
            crate::ui::flash_redirect("/domains", crate::ui::FlashKind::Success, "Domain deleted")
        }
        Err(e) => (
            StatusCode::SEE_OTHER,
            [(
                "location",
                format!("/domains?err={}", urlencode(&e.to_string())).as_str(),
            )],
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// tunnels pages
// ---------------------------------------------------------------------------

/// Parse the tunnel-options form group into `HttpOptions`. Checkboxes encode
/// presence; every field defaults off unless the form states it (API-created
/// tunnels keep `HttpOptions::default` semantics instead).
fn parse_options_from_form(body: &str) -> HttpOptions {
    HttpOptions {
        reverse_proxy_headers: !form_field(body, "options_reverse_proxy_headers").is_empty(),
        basic_auth: {
            let user = form_field(body, "options_basic_user");
            if user.is_empty() {
                None
            } else {
                Some((user, form_field(body, "options_basic_pass")))
            }
        },
        key_auth: {
            let k = form_field(body, "options_key_auth");
            if k.is_empty() { None } else { Some(k) }
        },
        pin_auth: {
            let p = form_field(body, "options_pin_auth");
            if p.is_empty() { None } else { Some(p) }
        },
        ip_whitelist: form_field(body, "options_ip_whitelist")
            .split([',', ' ', '\n', '\t'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        https_only: !form_field(body, "options_https_only").is_empty(),
        host_rewrite: {
            let h = form_field(body, "options_host_rewrite");
            let t = h.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        },
        add_headers: parse_header_lines(&form_field(body, "options_add_headers")),
        remove_headers: form_field(body, "options_remove_headers")
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        pass_preflight: !form_field(body, "options_pass_preflight").is_empty(),
        oidc_auth: !form_field(body, "options_oidc_auth").is_empty(),
        email_otp: !form_field(body, "options_email_otp").is_empty(),
        debug_capture: !form_field(body, "options_debug_capture").is_empty(),
    }
}

fn parse_header_lines(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

fn parse_new_tunnel_from_form(body: &str) -> NewTunnel {
    NewTunnel {
        name: form_field(body, "name"),
        token_id: form_field(body, "token_id"),
        domain_id: form_field(body, "domain_id"),
        subdomain: {
            let s = form_field(body, "subdomain");
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        },
        custom_hostname: {
            let s = form_field(body, "custom_hostname");
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        },
        options: parse_options_from_form(body),
        ports: form_field(body, "ports").trim().to_string(),
    }
}

async fn render_tunnels_page(state: &BrokerState) -> String {
    let tunnels = state.tunnels.list().await.unwrap_or_default();
    let tokens = state.config.token_store.list().await;
    let token_names: std::collections::HashMap<String, String> = tokens
        .iter()
        .map(|t| (t.id.clone(), t.name.clone()))
        .collect();
    let domains = state.domains.list().await.unwrap_or_default();
    let domain_names: std::collections::HashMap<String, String> = domains
        .iter()
        .map(|d| (d.id.clone(), d.name.clone()))
        .collect();
    let active_apex = state
        .active_apex
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone();

    let mut rows = String::new();
    for t in &tunnels {
        let hostname = match (&t.subdomain, &t.custom_hostname) {
            (Some(sub), _) => {
                let base = domain_names
                    .get(&t.domain_id)
                    .map(|s| s.as_str())
                    .or(active_apex.as_deref())
                    .unwrap_or("");
                format!("{sub}.{base}")
            }
            (None, Some(h)) => h.clone(),
            (None, None) => "random per session".to_string(),
        };
        let enabled_badge = if t.enabled {
            r#"<span class="status status-up">enabled</span>"#
        } else {
            r#"<span class="status status-down">disabled</span>"#
        };
        let toggle = if t.enabled {
            format!(
                "<form method=\"post\" action=\"/tunnels/{id}/toggle\"><button class=\"btn-sm btn-warn\" type=\"submit\">Disable</button></form>",
                id = html_escape(&t.id)
            )
        } else {
            format!(
                "<form method=\"post\" action=\"/tunnels/{id}/toggle\"><button class=\"btn-sm\" type=\"submit\">Enable</button></form>",
                id = html_escape(&t.id)
            )
        };
        rows.push_str(&format!(
            "<tr>\
             <td>{name}</td><td class=\"token\">{token}</td>\
             <td><a class=\"slug\" href=\"https://{host}\">{host}</a></td>\
             <td class=\"mono\">{ports}</td>\
             <td>{enabled}</td>\
             <td><span class=\"row-actions\">\
               {toggle}\
               <a class=\"btn btn-ghost btn-sm\" href=\"/tunnels/{id}/edit\">Edit</a>\
               <form method=\"post\" action=\"/tunnels/{id}/delete\" onsubmit=\"return confirm('Delete this tunnel?')\"><button class=\"btn-sm btn-danger\" type=\"submit\">Delete</button></form>\
             </span></td>\
             </tr>",
            name = html_escape(&t.name),
            token = &truncate_escape(
                token_names.get(&t.token_id).map(|s| s.as_str()).unwrap_or("?"),
                24,
            ),
            host = html_escape(&hostname),
            ports = html_escape(&t.ports),
            enabled = enabled_badge,
            id = html_escape(&t.id),
        ));
    }
    let table = if tunnels.is_empty() {
        r#"<div class="empty-state"><div class="empty-icon">&#128230;</div>
<div class="empty-title">No tunnels configured</div>
<div class="empty-text">Pin a token to a fixed hostname so clients reconnect to the same URL.</div>
<div class="empty-cta"><a class="btn" href="/tunnels/new">New tunnel</a></div></div>"#
            .to_string()
    } else {
        format!(
            "<div class=\"glass\" style=\"padding:6px 6px\"><table><thead><tr><th>Name</th><th>Token</th><th>Hostname</th><th>Ports</th><th>Status</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    };
    let body = format!(
        r###"<h1>Tunnels</h1>
  <p class="subtitle">Fixed hostname profiles bound to tokens</p>
  <p><a class="btn" href="/tunnels/new">+ New Tunnel</a></p>
  <p>&nbsp;</p>
  {table}
  <footer>Tunello</footer>"###,
        table = table,
    );
    crate::ui::page_shell("Tunnels", crate::ui::NavItem::Tunnels, &body)
}

/// GET /tunnels
async fn tunnels_page(State(state): State<BrokerState>) -> Response {
    html_page(StatusCode::OK, render_tunnels_page(&state).await)
}

fn options_checkbox(name: &str, checked: bool) -> String {
    let chk = if checked { " checked" } else { "" };
    format!(
        r#"<label><input type="checkbox" name="{name}"{chk}>{}</label>"#,
        match name {
            "options_reverse_proxy_headers" => "Reverse-proxy headers",
            "options_pass_preflight" => "Pass CORS preflight through auth",
            "options_https_only" => "HTTPS-only redirect",
            _ => name,
        }
    )
}

fn tune_options_html(o: &HttpOptions) -> String {
    format!(
        r#"<h2>Tunnel options</h2>
  <div class="form-group">{rph}</div>
  <div class="form-group">{pp}</div>
  <div class="form-group">{ho}</div>
  <div class="form-group"><label>Basic auth user</label><input name="options_basic_user" value="{bu}" placeholder="admin"></div>
  <div class="form-group"><label>Basic auth password</label><input name="options_basic_pass" type="password" value="{bp}" placeholder="password"></div>
  <div class="form-group"><label>Key auth (Bearer)</label><input name="options_key_auth" value="{ka}" placeholder="secret-token"></div>
  <div class="form-group"><label>PIN code</label><input name="options_pin_auth" value="{pa}" placeholder="4-8 digit PIN"></div>
  <div class="form-group"><label>Require OIDC login</label><input type="checkbox" name="options_oidc_auth" {oc}></div>
  <div class="form-group"><label>Require email OTP</label><input type="checkbox" name="options_email_otp" {eo}></div>
  <div class="form-group"><label>Debug body capture (privacy-sensitive)</label><input type="checkbox" name="options_debug_capture" {dc}></div>
  <div class="form-group"><label>Host rewrite (backend Host)</label><input name="options_host_rewrite" value="{hr}" placeholder="backend.example.com"></div>
  <div class="form-group"><label>Add headers (Name: Value per line)</label><textarea name="options_add_headers">{ah}</textarea></div>
  <div class="form-group"><label>Remove headers (one per line)</label><textarea name="options_remove_headers">{rh}</textarea></div>
  <div class="form-group"><label>IP whitelist (IP or CIDR, comma-separated)</label><input name="options_ip_whitelist" value="{wl}"></div>"#,
        rph = options_checkbox("options_reverse_proxy_headers", o.reverse_proxy_headers),
        pp = options_checkbox("options_pass_preflight", o.pass_preflight),
        ho = options_checkbox("options_https_only", o.https_only),
        bu = html_escape(o.basic_auth.as_ref().map(|(u, _)| u.as_str()).unwrap_or("")),
        bp = html_escape(o.basic_auth.as_ref().map(|(_, p)| p.as_str()).unwrap_or("")),
        ka = html_escape(o.key_auth.as_deref().unwrap_or("")),
        pa = html_escape(o.pin_auth.as_deref().unwrap_or("")),
        oc = if o.oidc_auth { "checked" } else { "" },
        eo = if o.email_otp { "checked" } else { "" },
        dc = if o.debug_capture { "checked" } else { "" },
        hr = html_escape(o.host_rewrite.as_deref().unwrap_or("")),
        ah = html_escape(
            &o.add_headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        rh = html_escape(&o.remove_headers.join("\n")),
        wl = html_escape(&o.ip_whitelist.join(", ")),
    )
}

/// GET /tunnels/new — empty editor form.
async fn tunnels_new_page(State(state): State<BrokerState>) -> Response {
    html_page(StatusCode::OK, render_tunnel_edit(&state, None, None).await)
}

/// GET /tunnels/{id}/edit.
async fn tunnel_edit_page(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    let Some(rec) = state.tunnels.get(&id).await.ok().flatten() else {
        return (StatusCode::SEE_OTHER, [("location", "/tunnels")]).into_response();
    };
    html_page(
        StatusCode::OK,
        render_tunnel_edit(&state, Some(&rec), None).await,
    )
}

async fn render_tunnel_edit(
    state: &BrokerState,
    rec: Option<&crate::tunnel::TunnelRecord>,
    err: Option<&str>,
) -> String {
    let tokens = state.config.token_store.list().await;
    let domains = state.domains.list().await.unwrap_or_default();
    let name = rec.map(|r| html_escape(&r.name)).unwrap_or_default();
    let token_id = rec.map(|r| r.token_id.clone()).unwrap_or_default();
    let domain_id = rec.map(|r| r.domain_id.clone()).unwrap_or_default();
    let sub = rec.and_then(|r| r.subdomain.clone()).unwrap_or_default();
    let custom = rec
        .and_then(|r| r.custom_hostname.clone())
        .unwrap_or_default();
    let ports = rec.map(|r| r.ports.clone()).unwrap_or_default();
    let enabled = rec.map(|r| r.enabled).unwrap_or(true);
    let options = rec.map(|r| &r.options).cloned().unwrap_or_default();

    let token_opts = tokens
        .iter()
        .map(|t| {
            let sel = if t.id == token_id { " selected" } else { "" };
            format!(
                "<option value=\"{id}\"{sel}>{name}</option>",
                id = html_escape(&t.id),
                name = html_escape(&t.name)
            )
        })
        .collect::<String>();
    let domain_opts = domains
        .iter()
        .map(|d| {
            let sel = if d.id == domain_id { " selected" } else { "" };
            format!(
                "<option value=\"{id}\"{sel}>{name}</option>",
                id = html_escape(&d.id),
                name = html_escape(&d.name)
            )
        })
        .collect::<String>();
    let err_html = err
        .map(|e| format!("<div class=\"msg-error\">{}</div>", html_escape(e)))
        .unwrap_or_default();
    let action = if rec.is_some() {
        "Update Tunnel"
    } else {
        "Create Tunnel"
    };
    let post_url = rec
        .map(|r| format!("/tunnels/{}", html_escape(&r.id)))
        .unwrap_or_else(|| "/tunnels".to_string());
    let enabled_chk = if enabled { " checked" } else { "" };
    // Tunnel ids are `u-<slug>` (URL-safe chars only); JSON-string-escape the
    // value for the single-quoted data-props attribute. Empty in create mode.
    let data_props = rec
        .map(|r| format!(r#" data-props='{{"edit_id":"{}"}}'"#, html_escape(&r.id)))
        .unwrap_or_default();

    let body = format!(
        r###"<h1>{action}</h1>
  <p class="subtitle">{subtitle}</p>
  {err_html}
  <div id="island-root" data-island="tunnel-form"{data_props}>
  <div class="create-form glass" style="max-width:640px">
    <form method="post" action="{post_url}">
      <div class="form-group">
        <label for="name">Name</label>
        <input type="text" id="name" name="name" required maxlength="64" value="{name}">
      </div>
      <div class="form-row">
        <div class="form-group">
          <label for="token_id">Token</label>
          <select id="token_id" name="token_id" required>{token_opts}</select>
        </div>
        <div class="form-group">
          <label for="domain_id">Domain</label>
          <select id="domain_id" name="domain_id" required>{domain_opts}</select>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label for="subdomain">Fixed subdomain</label>
          <input type="text" id="subdomain" name="subdomain" value="{sub}" placeholder="my-app">
        </div>
        <div class="form-group">
          <label for="custom_hostname">Custom hostname</label>
          <input type="text" id="custom_hostname" name="custom_hostname" value="{custom}" placeholder="app.example.com">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label for="ports">Ports</label>
          <input type="text" id="ports" name="ports" value="{ports}" placeholder="8080,22,5432">
          <div class="hint">Local ports this tunnel forwards, comma-separated. The client passes the actual --port / --tcp at runtime.</div>
        </div>
      </div>
      <div class="form-group">
        <label><input type="checkbox" name="enabled"{enabled_chk}> Tunnel enabled</label>
      </div>
      <div class="section">{options_html}</div>
      <button class="create-btn" type="submit">{action}</button>
    </form>
  </div>
  </div>
  <script type="module" src="{bundle}"></script>
  <a class="back" href="/tunnels">&larr; Back to tunnels</a>"###,
        action = action,
        subtitle = if rec.is_some() {
            "Edit tunnel profile"
        } else {
            "Create a fixed hostname profile"
        },
        err_html = err_html,
        post_url = post_url,
        name = name,
        token_opts = token_opts,
        domain_opts = domain_opts,
        sub = sub,
        custom = custom,
        ports = ports,
        enabled_chk = enabled_chk,
        data_props = data_props,
        bundle = crate::ui::bundle_script(),
        options_html = tune_options_html(&options),
    );
    crate::ui::page_shell(
        if rec.is_some() {
            "Edit tunnel"
        } else {
            "New tunnel"
        },
        crate::ui::NavItem::Tunnels,
        &body,
    )
}

/// POST /tunnels — create a tunnel profile.
async fn tunnels_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record(
        "operator",
        "-",
        "tunnel.create",
        &auth::form_field(&body, "name"),
    );
    let n = parse_new_tunnel_from_form(&body);
    if n.name.trim().is_empty() {
        return html_page(
            StatusCode::BAD_REQUEST,
            render_tunnel_edit(&state, None, Some("Name is required.")).await,
        );
    }
    let cap = state.tunnel_quota_cap(&n.token_id).await;
    match state.tunnels.create_checked(&n, cap as i64).await {
        Ok(_) => {
            crate::ui::flash_redirect("/tunnels", crate::ui::FlashKind::Success, "Tunnel created")
        }
        Err(e @ token::StoreError::Quota(_)) => html_page(
            StatusCode::CONFLICT,
            render_tunnel_edit(&state, None, Some(&format!("{e}"))).await,
        ),
        Err(e) => html_page(
            StatusCode::BAD_REQUEST,
            render_tunnel_edit(&state, None, Some(&format!("{e}"))).await,
        ),
    }
}

/// POST /tunnels/{id} — update a tunnel profile.
async fn tunnels_update(
    State(state): State<BrokerState>,
    Path(id): Path<String>,
    body: String,
) -> Response {
    state.audit.record("operator", "-", "tunnel.update", &id);
    let n = parse_new_tunnel_from_form(&body);
    if n.name.trim().is_empty() {
        let rec = state.tunnels.get(&id).await.ok().flatten();
        return html_page(
            StatusCode::BAD_REQUEST,
            render_tunnel_edit(&state, rec.as_ref(), Some("Name is required.")).await,
        );
    }
    match state.tunnels.update(&id, &n).await {
        Ok(_) => {
            crate::ui::flash_redirect("/tunnels", crate::ui::FlashKind::Success, "Tunnel updated")
        }
        Err(e) => {
            let rec = state.tunnels.get(&id).await.ok().flatten();
            html_page(
                StatusCode::BAD_REQUEST,
                render_tunnel_edit(&state, rec.as_ref(), Some(&format!("{e}"))).await,
            )
        }
    }
}

/// POST /tunnels/{id}/toggle
async fn tunnels_toggle(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "tunnel.toggle", &id);
    let _ = state.tunnels.toggle(&id).await;
    crate::ui::flash_redirect("/tunnels", crate::ui::FlashKind::Success, "Tunnel toggled")
}

/// POST /tunnels/{id}/delete
async fn tunnels_delete(State(state): State<BrokerState>, Path(id): Path<String>) -> Response {
    state.audit.record("operator", "-", "tunnel.delete", &id);
    let _ = state.tunnels.delete(&id).await;
    crate::ui::flash_redirect("/tunnels", crate::ui::FlashKind::Success, "Tunnel deleted")
}

// ---------------------------------------------------------------------------
// shared tokens page renderer
// ---------------------------------------------------------------------------

const MAX_BYTES_SLIDER_JS: &str = r#"(function () {
  var slider = document.getElementById('max_bytes');
  var hidden = document.getElementById('max_bytes_field');
  var unit = document.getElementById('max_bytes_unit');
  var exact = document.getElementById('max_bytes_exact');
  var out = document.getElementById('max-bytes-readout');
  var unlimited = document.getElementById('max_bytes_unlimited');
  var chips = document.querySelectorAll('[data-bytes-chip]');
  var UNITS = { B: 1, KB: 1024, MB: 1048576, GB: 1073741824, TB: 1099511627776 };
  var HI = { B: 16384, KB: 16384, MB: 16384, GB: 16384, TB: 16 };
  var BITS = { B: 14, KB: 14, MB: 14, GB: 14, TB: 4 };
  var POS = 16383;
  var state = { unit: 'GB', value: 2, unlimited: false };
  function logValue(k, bits) { return Math.round(Math.pow(2, (k / POS) * bits)); }
  function snap(k) {
    var v = logValue(k, BITS[state.unit]);
    if (v < 1) v = 1;
    if (v > HI[state.unit]) v = HI[state.unit];
    return v;
  }
  function nearestPos(v) {
    var k = Math.round((Math.log(v) / Math.LN2) * POS / BITS[state.unit]);
    if (k < 0) k = 0;
    if (k > POS) k = POS;
    return k;
  }
  function fmt(bytes) {
    if (bytes >= 1099511627776) return (bytes / 1099511627776).toFixed(2) + ' TiB';
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GiB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MiB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KiB';
    return bytes + ' B';
  }
  function refresh() {
    if (state.unlimited) {
      hidden.value = 0;
      out.textContent = 'Unlimited';
      slider.disabled = true; unit.disabled = true; exact.disabled = true;
      chips.forEach(function (c) { c.disabled = true; });
      return;
    }
    slider.disabled = false; unit.disabled = false; exact.disabled = false;
    chips.forEach(function (c) { c.disabled = false; });
    if (state.value < 1) state.value = 1;
    if (state.value > HI[state.unit]) state.value = HI[state.unit];
    var bytes = Math.round(state.value * UNITS[state.unit]);
    hidden.value = bytes;
    exact.value = state.value;
    slider.min = 0; slider.max = POS;
    slider.value = nearestPos(state.value);
    out.textContent = fmt(bytes) + ' (' + bytes + ' bytes)';
  }
  slider.addEventListener('input', function () { state.value = snap(Number(slider.value)); refresh(); });
  unit.addEventListener('change', function () {
    var old = UNITS[state.unit] * state.value;
    state.unit = unit.value;
    state.value = Math.max(1, Math.min(HI[state.unit], Math.round(old / UNITS[state.unit])));
    refresh();
  });
  exact.addEventListener('input', function () {
    var v = Number(exact.value);
    if (!isFinite(v)) v = state.value;
    state.value = v;
    refresh();
  });
  unlimited.addEventListener('change', function () { state.unlimited = unlimited.checked; refresh(); });
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      if (chip.dataset.bytesChip === 'unlimited') {
        state.unlimited = true;
      } else {
        state.unlimited = false;
        var b = Number(chip.dataset.bytesChip);
        var order = ['B', 'KB', 'MB', 'GB', 'TB'];
        state.unit = 'B'; state.value = b;
        for (var i = 0; i < order.length; i++) {
          var u = order[i];
          var v = b / UNITS[u];
          if (v >= 1 && v <= HI[u]) { state.unit = u; state.value = Math.round(v); }
        }
      }
      unit.value = state.unit;
      unlimited.checked = state.unlimited;
      refresh();
    });
  });
  refresh();
})();"#;

fn render_tokens_page(
    tokens: &[crate::token::TokenRecord],
    secret: Option<&str>,
    owners: &std::collections::HashMap<i64, String>,
    tunnel_counts: &std::collections::HashMap<String, usize>,
) -> (String, String) {
    let mut rows = String::new();
    for t in tokens {
        let enabled_str = if t.enabled { "yes" } else { "no" };
        let created = chrono_str(t.created_at);
        let action = if t.enabled {
            format!(
                "<form method=\"post\" action=\"/tokens/{id}/disable\"><button class=\"btn-sm btn-warn\" type=\"submit\">Disable</button></form>",
                id = html_escape(&t.id)
            )
        } else {
            format!(
                "<form method=\"post\" action=\"/tokens/{id}/enable\"><button class=\"btn-sm\" type=\"submit\">Enable</button></form>",
                id = html_escape(&t.id)
            )
        };
        // Static confirm text: interpolating the token name into inline JS
        // would be a stored-XSS vector (html_escape can't protect JS string
        // context — the browser decodes &#39; back to ' before JS runs).
        let delete = format!(
            "<form method=\"post\" action=\"/tokens/{id}/delete\" onsubmit=\"return confirm('Delete this token?')\"><button class=\"btn-sm btn-danger\" type=\"submit\">Delete</button></form>",
            id = html_escape(&t.id)
        );

        let owner = match t.owner_id {
            Some(id) => owners
                .get(&id)
                .cloned()
                .unwrap_or_else(|| format!("client #{id}")),
            None => "operator".to_string(),
        };
        let tunnels = tunnel_counts
            .get(&t.id)
            .copied()
            .unwrap_or_default()
            .to_string();
        rows.push_str(&format!(
            "<tr>\
               <td>{name}</td>\
               <td class=\"token\">{id}</td>\
               <td>{owner}</td>\
               <td>{tunnels}</td>\
               <td>{max_sessions} / {max_streams} / {max_bytes} / {ttl}</td>\
               <td>{enabled}</td>\
               <td>{created}</td>\
               <td><span class=\"row-actions\">{action}{delete}</span></td>\
             </tr>",
            name = html_escape(&t.name),
            id = &truncate_escape(&t.id, 16),
            owner = html_escape(&owner),
            tunnels = tunnels,
            max_sessions = limit_count_human(t.limits.max_sessions),
            max_streams = limit_count_human(t.limits.max_streams),
            max_bytes = limit_bytes_human(t.limits.max_bytes),
            ttl = limit_duration_human(t.limits.ttl_secs),
            enabled = enabled_str,
            created = created,
            action = action,
            delete = delete,
        ));
    }

    let table_or_empty = if tokens.is_empty() {
        r#"<div class="empty-state"><div class="empty-icon">&#128230;</div>
<div class="empty-title">No tokens yet</div>
<div class="empty-text">Clients authenticate with tokens. Create one to open tunnels.</div>
<div class="empty-cta"><a class="btn" href="/tokens">Create a token</a></div></div>"#
            .to_string()
    } else {
        format!(
            "<table><thead><tr><th>Name</th><th>ID</th><th>Owner</th><th>Tunnels</th><th>Limits (sessions / streams / bytes / TTL)</th><th>Enabled</th><th>Created</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    };

    let secret_html = if let Some(s) = secret {
        format!(
            r#"<div class="secret-box">
  <p class="secret-warn">&#9888; Copy this secret now — it will <strong>never</strong> be shown again.</p>
  <code class="secret-code">{secret}</code>
  <button class="copy-btn" onclick="navigator.clipboard.writeText('{secret_js}');this.textContent='Copied!'">Copy</button>
</div>"#,
            secret = html_escape(s),
            secret_js = s.replace('\\', "\\\\").replace('\'', "\\'")
        )
    } else {
        String::new()
    };

    let body = format!(
        r###"<h1>Tokens</h1>
  <p class="subtitle">{count} token(s)</p>
  <div class="box"><h2>What are tokens?</h2>\
  <p class="hint">Tokens are the credentials a client uses to open a tunnel:\
  <span class="mono">ddns --token &lt;secret&gt; --server https://&lt;your-domain&gt;</span>.\
  <b>Ownerless</b> tokens are created here by the operator (legacy).\
  <b>Client-owned</b> tokens are created by customers in their portal — their\
  owner shows in the Owner column, and Tunnels shows how many tunnel profiles\
  use each token.</p></div>
  {secret_html}
  <div class="create-form glass">
    <h2>Create Token</h2>
    <form method="post" action="/tokens">
      <div class="form-row">
        <div class="form-group">
          <label for="name">Name</label>
          <input type="text" id="name" name="name" required maxlength="64" autofocus placeholder="web-server" style="width:200px">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label for="max_sessions">Max sessions</label>
          <input type="number" id="max_sessions" name="max_sessions" value="2" min="1" max="65535">
          <label class="checkbox-inline"><input type="checkbox" id="max_sessions_unlimited" name="max_sessions_unlimited" value="on" onchange="document.getElementById('max_sessions').disabled=this.checked"> Unlimited</label>
        </div>
        <div class="form-group">
          <label for="max_streams">Max streams</label>
          <input type="number" id="max_streams" name="max_streams" value="32" min="1" max="65535">
          <label class="checkbox-inline"><input type="checkbox" id="max_streams_unlimited" name="max_streams_unlimited" value="on" onchange="document.getElementById('max_streams').disabled=this.checked"> Unlimited</label>
        </div>
        <div class="form-group">
          <label for="max_bytes">Max bytes — <span id="max-bytes-readout">2.00 GiB (2147483648 bytes)</span></label>
          <div class="slider-row">
            <input type="hidden" id="max_bytes_field" name="max_bytes">
            <input type="range" id="max_bytes" min="0" max="16383" value="0" step="1">
            <select id="max_bytes_unit" name="max_bytes_unit">
              <option value="B">B</option><option value="KB">KB</option><option value="MB">MB</option><option value="GB" selected>GB</option><option value="TB">TB</option>
            </select>
            <input type="number" id="max_bytes_exact" min="1" max="16384" value="2" step="any">
          </div>
          <div class="chips">
            <button type="button" class="chip" data-bytes-chip="67108864">64 MB</button>
            <button type="button" class="chip" data-bytes-chip="268435456">256 MB</button>
            <button type="button" class="chip" data-bytes-chip="1073741824">1 GB</button>
            <button type="button" class="chip" data-bytes-chip="2147483648">2 GB</button>
            <button type="button" class="chip" data-bytes-chip="10737418240">10 GB</button>
            <button type="button" class="chip" data-bytes-chip="107374182400">100 GB</button>
            <button type="button" class="chip" data-bytes-chip="1099511627776">1 TB</button>
            <button type="button" class="chip" data-bytes-chip="unlimited">Unlimited</button>
          </div>
          <label class="checkbox-inline"><input type="checkbox" id="max_bytes_unlimited" name="max_bytes_unlimited" value="on" checked> Unlimited</label>
        </div>
        <script>{slider_js}</script>
        <div class="form-group">
          <label for="ttl_secs">TTL (seconds)</label>
          <input type="number" id="ttl_secs" name="ttl_secs" placeholder="∞" min="1">
          <label class="checkbox-inline"><input type="checkbox" id="ttl_secs_unlimited" name="ttl_secs_unlimited" value="on" checked onchange="document.getElementById('ttl_secs').disabled=this.checked"> Unlimited</label>
        </div>
      </div>
      <button class="create-btn" type="submit">Create Token</button>
    </form>
  </div>
  <div class="glass" style="padding:6px 6px">{table_or_empty}</div>
  <footer>Tunello</footer>"###,
        count = tokens.len(),
        secret_html = secret_html,
        table_or_empty = table_or_empty,
        slider_js = MAX_BYTES_SLIDER_JS,
    );

    (
        table_or_empty,
        crate::ui::page_shell("Tokens", crate::ui::NavItem::Tokens, &body),
    )
}

// ---------------------------------------------------------------------------
// settings page — GET /settings
// ---------------------------------------------------------------------------

async fn settings_page(State(state): State<BrokerState>) -> Response {
    let body = render_settings_page(&state, None, None).await;
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// settings password submit — POST /settings (form-encoded)
// ---------------------------------------------------------------------------

async fn settings_password_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record("operator", "-", "settings.password", "");
    let current = form_field(&body, "current");
    let new_password = form_field(&body, "new");

    if new_password.len() < 8 || new_password.len() > 128 {
        let body =
            render_settings_page(&state, None, Some("New password must be 8-128 characters."))
                .await;
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    let Some(op) = state.accounts.find_operator().await.ok().flatten() else {
        let body = render_settings_page(&state, None, Some("No operator account set.")).await;
        return (
            StatusCode::CONFLICT,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    };

    let current_clone = current.clone();
    let hash_clone = op.password_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        crate::auth::verify_password(&current_clone, &hash_clone)
    })
    .await
    .unwrap_or(false);
    if !verified {
        let body = render_settings_page(&state, None, Some("Current password is incorrect.")).await;
        return (
            StatusCode::UNAUTHORIZED,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    let new_clone = new_password.clone();
    let h = match tokio::task::spawn_blocking(move || crate::auth::hash_password(&new_clone)).await
    {
        Ok(Ok(h)) => h,
        _ => {
            let body = render_settings_page(&state, None, Some("Password hashing failed.")).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response();
        }
    };

    match state.accounts.update_password(op.id, &h).await {
        Ok(_) => crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Success,
            "Password changed",
        ),
        Err(_) => {
            let body = render_settings_page(&state, None, Some("Failed to save password.")).await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// settings instance submit — POST /settings/instance (form-encoded)
// ---------------------------------------------------------------------------

async fn settings_instance_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record(
        "operator",
        "-",
        "settings.instance",
        &auth::form_field(&body, "instance_name"),
    );
    let instance_name = form_field(&body, "instance_name").trim().to_string();
    let support_url = form_field(&body, "support_url").trim().to_string();

    if !support_url.is_empty()
        && !support_url.starts_with("http://")
        && !support_url.starts_with("https://")
    {
        let body = render_settings_page(
            &state,
            None,
            Some("Support URL must start with http:// or https://."),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    if let Err(e) = state.update_settings(|s| {
        s.instance_name = instance_name;
        s.support_url = support_url;
    }) {
        tracing::error!(?e, "instance settings save failed");
        let body =
            render_settings_page(&state, None, Some("Failed to save instance settings.")).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    crate::ui::flash_redirect(
        "/settings",
        crate::ui::FlashKind::Success,
        "Instance settings saved",
    )
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// settings security submit — POST /settings/security (form-encoded)
// ---------------------------------------------------------------------------

/// True when `line` is a bare IP or an in-range CIDR (the same shape
/// `Settings::peer_allowed` accepts). Empty lines are skipped by the caller.
fn allowlist_line_valid(line: &str) -> bool {
    let line = line.trim();
    if line.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let Some((net, prefix)) = line.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match net.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => prefix <= 32,
        Ok(std::net::IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

async fn settings_security_submit(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: String,
) -> Response {
    state.audit.record("operator", "-", "settings.security", "");
    let ttl_raw = form_field(&body, "session_ttl_hours");
    let allowlist_raw = form_field(&body, "ip_allowlist");

    let ttl: u64 = match ttl_raw.trim().parse() {
        Ok(n) if n >= 1 => n,
        _ => {
            let body = render_settings_page(
                &state,
                None,
                Some("Session TTL must be a whole number of hours (at least 1)."),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response();
        }
    };

    // Validate each non-empty allowlist line; a bad line re-renders with an
    // inline error naming the line and saves nothing.
    let mut allowlist: Vec<String> = Vec::new();
    for (idx, raw_line) in allowlist_raw.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if !allowlist_line_valid(line) {
            let msg = format!(
                "Invalid allowlist entry on line {}: \"{line}\". Use an IP (10.0.0.1) or CIDR (10.0.0.0/24).",
                idx + 1
            );
            let body = render_settings_page(&state, None, Some(&msg)).await;
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response();
        }
        allowlist.push(line.to_string());
    }

    // Guardrail: refuse to save an allowlist that would lock the operator out.
    // The dashboard has no UI recovery path once the peer IP is excluded, so
    // evaluate the *new* list against the request's peer before persisting.
    // An empty list allows all, so it is always safe to save.
    if !allowlist.is_empty() {
        let mut candidate = state
            .settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        candidate.dashboard_ip_allowlist = allowlist.clone();
        if !candidate.peer_allowed(&peer.ip()) {
            let msg = format!(
                "The new allowlist excludes your IP ({}) — you would be locked out.",
                peer.ip()
            );
            let body = render_settings_page(&state, None, Some(&msg)).await;
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "text/html; charset=utf-8")],
                body,
            )
                .into_response();
        }
    }

    if let Err(e) = state.update_settings(|s| {
        s.session_ttl_hours = ttl;
        s.dashboard_ip_allowlist = allowlist;
    }) {
        tracing::error!(?e, "security settings save failed");
        let body =
            render_settings_page(&state, None, Some("Failed to save security settings.")).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    crate::ui::flash_redirect(
        "/settings",
        crate::ui::FlashKind::Success,
        "Security settings saved",
    )
}

// ---------------------------------------------------------------------------
// settings alerts submit — POST /settings/alerts (form-encoded)
// ---------------------------------------------------------------------------

async fn settings_alerts_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record("operator", "-", "settings.alerts", "");
    let webhook_url = form_field(&body, "webhook_url").trim().to_string();
    let webhook_secret = form_field(&body, "webhook_secret");
    let email_alerts_enabled = form_field(&body, "email_alerts_enabled") == "on";

    if !webhook_url.is_empty()
        && !webhook_url.starts_with("http://")
        && !webhook_url.starts_with("https://")
    {
        let body = render_settings_page(
            &state,
            None,
            Some("Webhook URL must start with http:// or https://."),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    // Warn once at save time when email alerts are enabled without a mailer
    // (and not in --dev, which logs alerts instead of SMTP). The per-event
    // path skips silently, so this is the only signal the operator gets.
    if email_alerts_enabled && state.mailer.is_none() && !state.config.dev {
        tracing::warn!(
            "email alerts enabled but no SMTP configured — session alerts will be skipped \
             (set DDNS_SMTP_* or run with --dev)"
        );
    }

    if let Err(e) = state.update_settings(|s| {
        s.webhook_url = webhook_url;
        s.webhook_secret = webhook_secret;
        s.email_alerts_enabled = email_alerts_enabled;
    }) {
        tracing::error!(?e, "alert settings save failed");
        let body = render_settings_page(&state, None, Some("Failed to save alert settings.")).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    crate::ui::flash_redirect(
        "/settings",
        crate::ui::FlashKind::Success,
        "Alert settings saved",
    )
}

// ---------------------------------------------------------------------------
// settings defaults submit — POST /settings/defaults (form-encoded)
// ---------------------------------------------------------------------------

/// Parse a non-negative whole-number form field (0 = unlimited). Empty or
/// out-of-range input yields a human-readable error.
fn parse_nonneg_field(body: &str, field: &str, max: u64) -> Result<u64, String> {
    let raw = form_field(body, field);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} is required (use 0 for unlimited)."));
    }
    let n: u64 = trimmed
        .parse()
        .map_err(|_| format!("{field} must be a non-negative whole number."))?;
    if n > max {
        return Err(format!("{field} must be at most {max}."));
    }
    Ok(n)
}

async fn defaults_error(state: &BrokerState, msg: &str) -> Response {
    let body = render_settings_page(state, None, Some(msg)).await;
    (
        StatusCode::BAD_REQUEST,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn settings_defaults_submit(State(state): State<BrokerState>, body: String) -> Response {
    state.audit.record("operator", "-", "settings.defaults", "");
    let max_sessions = match parse_nonneg_field(&body, "max_sessions", u32::MAX as u64) {
        Ok(n) => n as u32,
        Err(e) => return defaults_error(&state, &e).await,
    };
    let max_streams = match parse_nonneg_field(&body, "max_streams", u32::MAX as u64) {
        Ok(n) => n as u32,
        Err(e) => return defaults_error(&state, &e).await,
    };
    let max_bytes = match parse_nonneg_field(&body, "max_bytes", u64::MAX) {
        Ok(n) => n,
        Err(e) => return defaults_error(&state, &e).await,
    };
    let ttl_secs = match parse_nonneg_field(&body, "ttl_secs", u64::MAX) {
        Ok(n) => n,
        Err(e) => return defaults_error(&state, &e).await,
    };

    // Heartbeat is optional: empty → None (client default), else non-negative.
    let heartbeat_raw = form_field(&body, "heartbeat_ms").trim().to_string();
    let heartbeat = if heartbeat_raw.is_empty() {
        None
    } else {
        match heartbeat_raw.parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                return defaults_error(&state, "heartbeat_ms must be a non-negative whole number.")
                    .await;
            }
        }
    };

    let limits = TokenLimits {
        max_sessions,
        max_streams,
        max_bytes,
        ttl_secs,
        ..TokenLimits::default()
    };
    if let Err(e) = state.update_settings(|s| {
        s.default_token_limits = limits;
        s.client_heartbeat_ms = heartbeat;
    }) {
        tracing::error!(?e, "defaults save failed");
        let body = render_settings_page(&state, None, Some("Failed to save defaults.")).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response();
    }

    crate::ui::flash_redirect("/settings", crate::ui::FlashKind::Success, "Defaults saved")
}

/// Fire-and-forget email alert to the operator (session start/end). No-ops
/// when alerts are disabled; the send runs on a spawned task and never blocks
/// the session lifecycle. SMTP failures warn; `--dev` logs instead of SMTP.
pub(crate) fn email_alert(
    settings: &settings::Settings,
    state: &BrokerState,
    subject: &str,
    body: &str,
) {
    send_operator_email(
        settings,
        &state.mailer,
        &state.accounts,
        state.config.dev,
        subject,
        body,
    );
}

/// Core of [`email_alert`], split out so the token guard can alert without
/// holding a full `BrokerState`. Same fire-and-forget contract.
pub(crate) fn send_operator_email(
    settings: &settings::Settings,
    mailer: &Option<crate::mailer::Mailer>,
    accounts: &account::AccountStore,
    dev: bool,
    subject: &str,
    body: &str,
) {
    if !settings.email_alerts_enabled {
        return;
    }
    // No mailer and not in --dev (where alerts are logged instead): skip
    // silently. settings_alerts_submit already warned once at save time;
    // a per-event failure here would just be noise.
    if mailer.is_none() && !dev {
        return;
    }
    let mailer = mailer.clone();
    let accounts = accounts.clone();
    let subject = subject.to_string();
    let body = body.to_string();
    tokio::spawn(async move {
        let operator = match accounts.find_operator().await {
            Ok(Some(op)) => op,
            Ok(None) => {
                tracing::warn!("email alert skipped: no operator account");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "email alert skipped: operator lookup failed");
                return;
            }
        };
        let result = match &mailer {
            Some(m) => m.send(&operator.email, &subject, &body).await,
            None if dev => {
                tracing::info!(to = %operator.email, subject = %subject, "[dev-mail] alert");
                Ok(())
            }
            None => Err("SMTP not configured (set DDNS_SMTP_* or run with --dev)".into()),
        };
        if let Err(e) = result {
            tracing::warn!(to = %operator.email, subject = %subject, error = %e, "email alert failed");
        }
    });
}

// ---------------------------------------------------------------------------
// 2FA setup / verify / disable
// ---------------------------------------------------------------------------

/// The issuer label for otpauth URIs: the configured instance name, or "Tunello".
fn otp_issuer(state: &BrokerState) -> String {
    let s = state.settings.read().unwrap_or_else(|p| p.into_inner());
    if s.instance_name.is_empty() {
        "Tunello".to_string()
    } else {
        s.instance_name.clone()
    }
}

/// Inline `<img>` data URI for an SVG QR code encoding the otpauth URI.
/// SVG (not PNG/PBM) is emitted — the `qrcode` crate's `svg` feature needs no
/// extra image dependency and browsers render `data:image/svg+xml;base64,…`.
fn qr_svg_data_uri(uri: &str) -> String {
    use base64::Engine as _;
    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => {
            let svg = code
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(180, 180)
                .build();
            let b64 = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
            format!("data:image/svg+xml;base64,{b64}")
        }
        Err(_) => String::new(),
    }
}

/// Render the 2FA section for the settings page: enabled / pending / off.
async fn render_2fa_section(state: &BrokerState) -> String {
    let Some(op) = state.accounts.find_operator().await.ok().flatten() else {
        return String::new();
    };

    if op.otp_enabled {
        return r###"<div class="card glass">
    <h2>Two-Factor Authentication</h2>
    <p>2FA is <strong>enabled</strong>.</p>
    <form method="post" action="/settings/2fa/disable">
      <label for="otp-disable">Current 2FA code (6 digits)</label>
      <input type="text" id="otp-disable" name="otp" required maxlength="6" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}">
      <button class="save-btn" type="submit">Disable 2FA</button>
    </form>
  </div>"###.to_string();
    }

    if let Some(secret) = state
        .settings_store
        .get(crate::settings::KEY_OTP_PENDING_SECRET)
        .ok()
        .flatten()
    {
        let issuer = otp_issuer(state);
        let uri = crate::otp::totp_uri(&issuer, &op.email, &secret);
        let qr = qr_svg_data_uri(&uri);
        return format!(
            r###"<div class="card glass">
    <h2>Two-Factor Authentication</h2>
    <p>Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.</p>
    <img src="{qr}" alt="TOTP QR code" width="180" height="180">
    <p>Manual entry secret: <code>{secret}</code></p>
    <form method="post" action="/settings/2fa/verify">
      <label for="otp-verify">6-digit code</label>
      <input type="text" id="otp-verify" name="otp" required maxlength="6" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}">
      <button class="save-btn" type="submit">Verify &amp; Enable</button>
    </form>
  </div>"###,
            qr = qr,
            secret = html_escape(&secret),
        );
    }

    r###"<div class="card glass">
    <h2>Two-Factor Authentication</h2>
    <p>Add a second factor to protect the operator dashboard.</p>
    <form method="post" action="/settings/2fa/setup">
      <button class="save-btn" type="submit">Enable 2FA</button>
    </form>
  </div>"###
        .to_string()
}

/// POST /settings/2fa/setup — generate a fresh secret, store it as a pending
/// secret (not yet attached to the account), and redirect to /settings where
/// the QR + verify form render.
async fn settings_2fa_setup(State(state): State<BrokerState>) -> Response {
    state
        .audit
        .record("operator", "-", "settings.2fa.setup", "");
    if let Some(op) = state.accounts.find_operator().await.ok().flatten()
        && op.otp_enabled
    {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Info,
            "2FA is already enabled",
        );
    }
    let secret = crate::otp::totp_generate_secret();
    if let Err(e) = state
        .settings_store
        .set(crate::settings::KEY_OTP_PENDING_SECRET, &secret)
    {
        tracing::error!(?e, "otp pending secret save failed");
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "Failed to start 2FA setup",
        );
    }
    crate::ui::flash_redirect(
        "/settings",
        crate::ui::FlashKind::Success,
        "2FA setup started — scan the QR code below",
    )
}

/// POST /settings/2fa/verify — verify a code against the pending secret, then
/// enable 2FA on the operator account and clear the pending secret.
async fn settings_2fa_verify(State(state): State<BrokerState>, body: String) -> Response {
    state
        .audit
        .record("operator", "-", "settings.2fa.verify", "");
    let code = form_field(&body, "otp");
    let Some(op) = state.accounts.find_operator().await.ok().flatten() else {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "No operator account",
        );
    };
    let Some(secret) = state
        .settings_store
        .get(crate::settings::KEY_OTP_PENDING_SECRET)
        .ok()
        .flatten()
    else {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "No pending 2FA setup — enable it first",
        );
    };
    if !crate::otp::totp_verify(&secret, &code, crate::account::unix_now() as u64) {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "Incorrect code — try again",
        );
    }
    if let Err(e) = state.accounts.set_otp(op.id, Some(&secret), true).await {
        tracing::error!(?e, "set_otp failed");
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "Failed to enable 2FA",
        );
    }
    if let Err(e) = state
        .settings_store
        .remove(crate::settings::KEY_OTP_PENDING_SECRET)
    {
        tracing::error!(?e, "otp pending secret clear failed");
    }
    crate::ui::flash_redirect("/settings", crate::ui::FlashKind::Success, "2FA enabled")
}

/// POST /settings/2fa/disable — require a valid current code, then clear the
/// secret and disable 2FA.
async fn settings_2fa_disable(State(state): State<BrokerState>, body: String) -> Response {
    state
        .audit
        .record("operator", "-", "settings.2fa.disable", "");
    let code = form_field(&body, "otp");
    let Some(op) = state.accounts.find_operator().await.ok().flatten() else {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "No operator account",
        );
    };
    let Some(secret) = op.otp_secret.as_deref() else {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Info,
            "2FA is not enabled",
        );
    };
    if !crate::otp::totp_verify(secret, &code, crate::account::unix_now() as u64) {
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "Incorrect code",
        );
    }
    if let Err(e) = state.accounts.set_otp(op.id, None, false).await {
        tracing::error!(?e, "set_otp disable failed");
        return crate::ui::flash_redirect(
            "/settings",
            crate::ui::FlashKind::Error,
            "Failed to disable 2FA",
        );
    }
    if let Err(e) = state
        .settings_store
        .remove(crate::settings::KEY_OTP_PENDING_SECRET)
    {
        tracing::error!(?e, "otp pending secret clear failed");
    }
    crate::ui::flash_redirect("/settings", crate::ui::FlashKind::Success, "2FA disabled")
}

// ---------------------------------------------------------------------------
// shared settings page renderer
// ---------------------------------------------------------------------------

/// Demo script for the /ui-kit page: toggles the embedded loading spinner on
/// two buttons (pointer-events disabled while loading; dimensions preserved).
const UI_KIT_SCRIPT: &str = r#"<script>
(function () {
  function wire(id, label) {
    var b = document.getElementById(id);
    if (!b) return;
    b.onclick = function () {
      if (b.classList.contains('is-loading')) return;
      b.classList.add('is-loading');
      b.innerHTML = '<span class="spinner"></span>' + label + '…';
      setTimeout(function () {
        b.classList.remove('is-loading');
        b.textContent = b.dataset.label;
      }, 2000);
    };
    b.dataset.label = label;
  }
  wire('demo-run', 'Run action');
  wire('demo-run2', 'Sync data');
})();
</script>"#;

async fn ui_kit_page(State(_state): State<BrokerState>) -> Response {
    // Inline SVG icons for the showcase (plus / gear / trash).
    let icon_plus = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 3v10M3 8h10"/></svg>"#;
    let icon_gear = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4"/></svg>"#;
    let icon_trash = r#"<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2.5 4.5h11M6.5 4.5V3h3v1.5M4 4.5l.8 9h6.4l.8-9M6.5 7.5v3.5M9.5 7.5v3.5"/></svg>"#;

    let size_card = |label: &str, sm: &str| {
        format!(
            r###"<div class="box"><h2>{label}</h2>
  <div class="actions" style="flex-wrap:wrap;align-items:center">
    <button class="btn {sm}">{icon_plus}<span>Create Tunnel</span></button>
    <button class="btn {sm} btn-secondary">{icon_gear}<span>Configure</span></button>
    <button class="btn {sm} btn-danger">{icon_trash}<span>Terminate</span></button>
    <button class="btn {sm} btn-icon" title="icon-only">{icon_plus}</button>
    <button class="btn {sm} is-loading"><span class="spinner"></span>Connecting</button>
    <button class="btn {sm} btn-secondary" disabled>Disabled</button>
    <span class="badge badge-connected">Connected</span>
    <span class="badge badge-idle">Idle</span>
    <span class="badge badge-warning">Degraded</span>
  </div>
</div>"###,
            label = label,
            sm = sm,
            icon_plus = icon_plus,
            icon_gear = icon_gear,
            icon_trash = icon_trash,
        )
    };

    let body = format!(
        r###"<h1>UI Kit</h1>
  <p class="subtitle">Button system — primary / secondary / danger × small / medium / large · WCAG AA · 150&thinsp;ms ease-in-out</p>
  {sm}
  {md}
  {lg}
  <div class="box"><h2>Interactive states</h2>
    <p class="subtitle">Click to toggle the embedded loading spinner (dimensions are preserved — no layout shift).</p>
    <div class="actions">
      <button class="btn btn-primary" type="button" id="demo-run">Run action</button>
      <button class="btn btn-secondary" type="button" id="demo-run2">Sync data</button>
    </div>
  </div>
  <div class="box"><h2>Focus states</h2>
    <p class="subtitle">Tab through the buttons — the 2px focus ring (offset 2px) uses the theme&rsquo;s focus token.</p>
  </div>
  {script}"###,
        sm = size_card("Small · 32px · 12px font · 6px radius", "btn-sm"),
        md = size_card("Medium · 40px · 14px font · 8px radius", "btn-md"),
        lg = size_card("Large · 48px · 16px font · 8px radius", "btn-lg"),
        script = UI_KIT_SCRIPT,
    );
    crate::auth::Html::ok(crate::ui::page_shell(
        "UI Kit",
        crate::ui::NavItem::None,
        &body,
    ))
}

async fn api_cert(State(state): State<BrokerState>) -> Response {
    let view = cert_status_inner(&state);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&view).unwrap_or_default(),
    )
        .into_response()
}

fn cert_status_inner(state: &BrokerState) -> CertStatusView {
    if state.config.acme.is_some() {
        CertStatusView {
            source: "acme".into(),
            domains: state
                .config
                .acme
                .as_ref()
                .map(|a| a.domains.clone())
                .unwrap_or_default(),
            status: "auto".into(),
            cert_expiry_secs: None,
            last_renewed_secs: None,
        }
    } else {
        let expiry = parse_cert_expiry(&state.config.tls_cert_pem);
        CertStatusView {
            source: "static".into(),
            domains: vec![state.config.domain.clone()],
            status: "serving".into(),
            cert_expiry_secs: expiry,
            last_renewed_secs: None,
        }
    }
}

async fn render_settings_page(
    state: &BrokerState,
    success: Option<&str>,
    error: Option<&str>,
) -> String {
    let cert_status = cert_status_inner(state);
    let twofa = render_2fa_section(state).await;
    let sec = state.settings.read().unwrap_or_else(|p| p.into_inner());
    let current_instance_name = sec.instance_name.clone();
    let current_support_url = sec.support_url.clone();
    let current_ttl = sec.session_ttl_hours;
    let current_allowlist = sec.dashboard_ip_allowlist.join("\n");
    let current_webhook_url = sec.webhook_url.clone();
    let current_webhook_secret = sec.webhook_secret.clone();
    let email_alerts_enabled = sec.email_alerts_enabled;
    let defaults = sec.default_token_limits;
    let heartbeat_ms = sec.client_heartbeat_ms;
    drop(sec);

    let instance = format!(
        r###"  <div class="card glass">
    <h2>Instance</h2>
    <form method="post" action="/settings/instance">
      <label for="instance_name">Instance Name</label>
      <input type="text" id="instance_name" name="instance_name" value="{instance_name}" placeholder="Tunello">
      <label for="support_url">Support URL</label>
      <input type="text" id="support_url" name="support_url" value="{support_url}" placeholder="https://support.example.com">
      {support_hint}
      <button class="save-btn" type="submit">Save Instance Settings</button>
    </form>
  </div>"###,
        instance_name = html_escape(&current_instance_name),
        support_url = html_escape(&current_support_url),
        support_hint = if current_support_url.is_empty() {
            r#"<p class="hint">Support link hidden until set</p>"#
        } else {
            ""
        },
    );
    let security = format!(
        r###"  <div class="card glass">
    <h2>Security</h2>
    <form method="post" action="/settings/security">
      <label for="session_ttl_hours">Session TTL (hours)</label>
      <input type="number" id="session_ttl_hours" name="session_ttl_hours" min="1" value="{ttl}" required>
      <label for="ip_allowlist">Dashboard IP Allowlist (one IP or CIDR per line; empty allows all)</label>
      <textarea id="ip_allowlist" name="ip_allowlist" rows="6">{allowlist}</textarea>
      {allowlist_hint}
      <button class="save-btn" type="submit">Save Security Settings</button>
    </form>
  </div>"###,
        ttl = current_ttl,
        allowlist = html_escape(&current_allowlist),
        allowlist_hint = if current_allowlist.is_empty() {
            r#"<p class="hint">IP allowlist disabled — all IPs allowed</p>"#
        } else {
            ""
        },
    );
    let alerts = format!(
        r###"  <div class="card glass">
    <h2>Alerts</h2>
    <form method="post" action="/settings/alerts">
      <label for="webhook_url">Webhook URL (empty disables)</label>
      <input type="text" id="webhook_url" name="webhook_url" value="{webhook_url}" placeholder="https://example.com/hook">
      <label for="webhook_secret">Webhook Secret</label>
      <input type="password" id="webhook_secret" name="webhook_secret" value="{webhook_secret}" autocomplete="new-password">
      <label class="checkbox-inline"><input type="checkbox" id="email_alerts_enabled" name="email_alerts_enabled" value="on"{email_checked}> Email alerts on session start/end</label>
      {webhook_hint}
      <button class="save-btn" type="submit">Save Alert Settings</button>
    </form>
  </div>"###,
        webhook_url = html_escape(&current_webhook_url),
        webhook_secret = html_escape(&current_webhook_secret),
        email_checked = if email_alerts_enabled { " checked" } else { "" },
        webhook_hint = if current_webhook_url.is_empty() {
            r#"<p class="hint">Webhooks disabled until a URL is set</p>"#
        } else {
            ""
        },
    );

    let defaults_card = format!(
        r###"  <div class="card glass">
    <h2>Token Defaults</h2>
    <form method="post" action="/settings/defaults">
      <label for="def_max_sessions">Default Max Sessions (0 = unlimited)</label>
      <input type="number" id="def_max_sessions" name="max_sessions" min="0" value="{def_max_sessions}">
      <label for="def_max_streams">Default Max Streams (0 = unlimited)</label>
      <input type="number" id="def_max_streams" name="max_streams" min="0" value="{def_max_streams}">
      <label for="def_max_bytes">Default Max Bytes (0 = unlimited)</label>
      <input type="number" id="def_max_bytes" name="max_bytes" min="0" value="{def_max_bytes}">
      <label for="def_ttl_secs">Default TTL (seconds, 0 = unlimited)</label>
      <input type="number" id="def_ttl_secs" name="ttl_secs" min="0" value="{def_ttl_secs}">
      <label for="heartbeat_ms">Client heartbeat interval (ms, empty = default)</label>
      <input type="number" id="heartbeat_ms" name="heartbeat_ms" min="0" value="{heartbeat_ms}">
      <button class="save-btn" type="submit">Save Defaults</button>
    </form>
  </div>"###,
        def_max_sessions = defaults.max_sessions,
        def_max_streams = defaults.max_streams,
        def_max_bytes = defaults.max_bytes,
        def_ttl_secs = defaults.ttl_secs,
        heartbeat_ms = heartbeat_ms.map(|v| v.to_string()).unwrap_or_default(),
    );

    let msg_html = if let Some(msg) = success {
        format!(
            "<div class=\"msg-success\">{msg}</div>",
            msg = html_escape(msg)
        )
    } else if let Some(msg) = error {
        format!(
            "<div class=\"msg-error\">{msg}</div>",
            msg = html_escape(msg)
        )
    } else {
        String::new()
    };

    let inner = format!(
        r###"<h1>Settings</h1>
  <p class="subtitle">Broker configuration and credentials</p>
  {msg_html}
  {instance}
  {security}
  {twofa}
  {alerts}
  {defaults_card}
  
  <div class="card glass">
    <h2>Configuration</h2>
    <div class="kv"><span class="k">Domain</span><span class="v">{domain}</span></div>
    <div class="kv"><span class="k">Public Port</span><span class="v">{public_port}</span></div>
    <div class="kv"><span class="k">Max Sessions</span><span class="v">{max_sessions}</span></div>
    <div class="kv"><span class="k">Watchdog Interval</span><span class="v">{watchdog_secs}s</span></div>
    <div class="kv"><span class="k">Default Max Sessions</span><span class="v">{def_max_sessions}</span></div>
    <div class="kv"><span class="k">Default Max Streams</span><span class="v">{def_max_streams}</span></div>
    <div class="kv"><span class="k">Default Max Bytes</span><span class="v">{def_max_bytes}</span></div>
    <div class="kv"><span class="k">Default TTL</span><span class="v">{def_ttl}</span></div>
  </div>
  <div class="card glass">
    <h2>TLS Certificate</h2>
    <div class="kv"><span class="k">Provisioned</span><span class="v">{cert_provisioned}</span></div>
    <div class="kv"><span class="k">Status</span><span class="v">{cert_message}</span></div>
  </div>
  <div class="card glass">
    <h2>Change Admin Password</h2>
    <form method="post" action="/settings">
      <label for="current">Current Password</label>
      <input type="password" id="current" name="current" required>
      <label for="new">New Password</label>
      <input type="password" id="new" name="new" required minlength="8">
      <button class="save-btn" type="submit">Change Password</button>
    </form>
  </div>
  <footer>Tunello v{version}</footer>"###,
        instance = instance,
        version = env!("CARGO_PKG_VERSION"),
        twofa = twofa,
        security = security,
        alerts = alerts,
        defaults_card = defaults_card,
        domain = html_escape(&state.config.domain),
        public_port = state.config.public_port,
        max_sessions = state.config.max_sessions,
        watchdog_secs = state.config.watchdog_interval.as_secs(),
        def_max_sessions = defaults.max_sessions,
        def_max_streams = defaults.max_streams,
        def_max_bytes = bytes_human(defaults.max_bytes),
        def_ttl = duration_human(defaults.ttl_secs),
        cert_provisioned = cert_status.source,
        cert_message = html_escape(&format!(
            "status={} domains={:?}",
            cert_status.status, cert_status.domains
        )),
    );
    crate::ui::page_shell("Settings", crate::ui::NavItem::Settings, &inner)
}

// ---------------------------------------------------------------------------
// chrono_str helper
// ---------------------------------------------------------------------------

fn chrono_str(unix: i64) -> String {
    if unix <= 0 {
        return "-".to_string();
    }
    let secs = unix as u64;
    let days = secs / 86400;
    let rem = secs % 86400;
    let hours = rem / 3600;
    let mins = (rem % 3600) / 60;
    let total_days = days;
    // Simple date from epoch (UTC) — coarse but works for operator display
    let y = 1970 + (total_days / 365) as i64;
    let d = total_days % 365;
    let mo = d / 30 + 1;
    let day = d % 30 + 1;
    format!("{y:04}-{mo:02}-{day:02} {hours:02}:{mins:02}")
}
// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Escape HTML special characters: & < > " '
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape, then truncate to `max` chars (never splitting a UTF-8 char).
fn truncate_escape(s: &str, max: usize) -> String {
    let escaped = html_escape(s);
    let end = escaped.floor_char_boundary(max);
    escaped[..end].to_string()
}

/// Human-readable byte count.
fn bytes_human(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit_idx])
    }
}

/// Human-readable duration from an Instant.
fn uptime_str(created_at: std::time::Instant) -> String {
    let elapsed = created_at.elapsed();
    duration_human(elapsed.as_secs())
}

fn duration_human(total_secs: u64) -> String {
    if total_secs < 60 {
        return format!("{}s", total_secs);
    }
    let mins = total_secs / 60;
    if mins < 60 {
        let secs = total_secs % 60;
        return format!("{mins}m {secs}s");
    }
    let hours = mins / 60;
    let mins = mins % 60;
    if hours < 24 {
        return format!("{hours}h {mins}m");
    }
    let days = hours / 24;
    let hours = hours % 24;
    format!("{days}d {hours}h")
}

/// 0 = unlimited sentinel — limit values only, never usage/uptime.
fn limit_count_human(n: u32) -> String {
    if n == 0 {
        "Unlimited".to_string()
    } else {
        n.to_string()
    }
}

fn limit_bytes_human(n: u64) -> String {
    if n == 0 {
        "Unlimited".to_string()
    } else {
        bytes_human(n)
    }
}

fn limit_duration_human(secs: u64) -> String {
    if secs == 0 {
        "no expiry".to_string()
    } else {
        duration_human(secs)
    }
}

/// Render an inline SVG sparkline from a ring buffer of byte-rate deltas.
fn sparkline_svg(deltas: &[u64]) -> String {
    let max = deltas.iter().copied().max().unwrap_or(1).max(1) as f64;
    let w = 100.0;
    let h = 24.0;
    let n = deltas.len() as f64;

    let pts: Vec<(f64, f64)> = deltas
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = (i as f64) * w / (n - 1.0).max(1.0);
            let y = h - ((v as f64) / max * (h - 4.0)) - 2.0;
            (x, y)
        })
        .collect();
    if deltas.iter().all(|&v| v == 0) {
        return r##"<svg width="100" height="24" class="sparkline is-flat"><polyline fill="none" stroke-width="1.5" points="0,23 100,23"/></svg>"##.to_string();
    }
    let points = pts
        .iter()
        .map(|(x, y)| format!("{x:.1},{y:.1}"))
        .collect::<Vec<_>>()
        .join(" ");
    let area = format!(
        "M{:.1},24 L{points} L{:.1},24 Z",
        pts[0].0,
        pts[pts.len() - 1].0
    );
    let (cx, cy) = pts[pts.len() - 1];
    format!(
        r##"<svg width="100" height="24" class="sparkline"><path d="{area}" fill-opacity="0.12"/><polyline fill="none" stroke-width="1.8" points="{points}"/><circle cx="{cx:.1}" cy="{cy:.1}" r="2.2"/></svg>"##,
        area = area,
        points = points,
        cx = cx,
        cy = cy,
    )
}

/// Simple 404 page for unknown tunnel slugs.
fn not_found_page(slug: &str) -> Response {
    let body = format!(
        r###"<div class="box glass" style="text-align:center">
<h1>404</h1>
<p>Tunnel <code>{slug}</code> not found. It may have expired or been disconnected.</p>
<p><a href="/">Back to dashboard</a></p>
</div>"###,
        slug = html_escape(slug),
    );

    (
        StatusCode::NOT_FOUND,
        [("content-type", "text/html; charset=utf-8")],
        crate::ui::page_shell("Not found", crate::ui::NavItem::None, &body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// public download / install-script handlers
// ---------------------------------------------------------------------------

const INSTALL_SH: &str = r#"#!/bin/sh
# ddns install script — detects OS/arch and fetches the right static binary.
set -eu
BASE="${DDNS_SERVER:-https://tunnel.example.com}"
case "$(uname -s)" in
  Linux) abi=unknown-linux-musl ;;
  Darwin) abi=apple-darwin ;;
  *) echo "unsupported OS (Windows: use the PowerShell one-liner from the docs)" >&2; exit 1 ;;
esac
case "$(uname -m)" in x86_64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
triple="${arch}-${abi}"
curl -fsSL "${BASE}/download/ddns-${triple}" -o ddns && chmod +x ddns
echo "installed ./ddns"
"#;

/// Characters safe to reflect a Host header value into a URL / shell-script
/// context. Anything else (control chars, quotes, backticks, `$`, spaces,
/// `;`) → false. Used by the :80 redirect and the install-script builder.
pub(crate) fn host_is_safe(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'[' | b']' | b'-'))
}

/// Only [A-Za-z0-9._-] may cross into a generated shell script literal.
pub(crate) fn shell_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validated query params for the one-line quickstart `install.sh`.
#[derive(serde::Deserialize)]
struct QuickstartQuery {
    code: Option<String>,
    port: Option<u32>,
    tcp: Option<u32>,
}

async fn install_script(
    State(state): State<BrokerState>,
    Query(q): Query<QuickstartQuery>,
    headers: HeaderMap,
) -> Response {
    let base = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .filter(|value| host_is_safe(value))
        .map(|host| format!("https://{host}"))
        .unwrap_or_else(|| "https://tunnel.example.com".to_string());
    let mut script = INSTALL_SH.replace("https://tunnel.example.com", &base);

    if let Some(code) = q.code {
        // The code is embedded inside single quotes, so it must be a plain
        // sc_ code with a shell-safe charset before it crosses into the
        // generated script literal.
        if !code.starts_with("sc_") || !shell_safe(&code) {
            return (StatusCode::BAD_REQUEST, "invalid code").into_response();
        }
        for p in [q.port, q.tcp].into_iter().flatten() {
            if !(1..=65535).contains(&p) {
                return (StatusCode::BAD_REQUEST, "invalid port").into_response();
            }
        }
        let port_flags = if q.port.is_some() || q.tcp.is_some() {
            let mut flags = String::new();
            if let Some(p) = q.port {
                flags.push_str(&format!("--port {p} "));
            }
            if let Some(t) = q.tcp {
                flags.push_str(&format!("--tcp {t} "));
            }
            flags.trim_end().to_string()
        } else if let Some(sc) = state.setup.peek(&code) {
            let (http_port, tcp_port) = crate::portal::split_ports(&sc.ports);
            let mut flags = String::new();
            if let Some(p) = http_port {
                flags.push_str(&format!("--port {p} "));
            }
            if let Some(t) = tcp_port {
                flags.push_str(&format!("--tcp {t} "));
            }
            flags.trim_end().to_string()
        } else {
            String::new()
        };
        if port_flags.is_empty() {
            script.push_str(&format!(
                "\necho \"tunnel ready to run: ./ddns --token '{code}' --port YOUR_PORT\"\nexit 1\n"
            ));
        } else {
            script.push_str(&format!("\nexec ./ddns --token '{code}' {port_flags}\n"));
        }
    }

    (
        StatusCode::OK,
        [("content-type", "text/x-shellscript")],
        script,
    )
        .into_response()
}

async fn download_file(State(state): State<BrokerState>, Path(file): Path<String>) -> Response {
    let Some(dir) = &state.config.download_dir else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Reject separators and dot-segments.
    if file.contains('/') || file.contains('\\') || file == ".." {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = dir.join(&file);
    // Canonicalize and enforce prefix check to prevent traversal.
    if let Ok(canon) = path.canonicalize()
        && let Ok(dir_canon) = dir.canonicalize()
        && !canon.starts_with(&dir_canon)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /downloads — public cross-platform client download page. Lists every
/// platform binary present in the download dir (Linux/macOS/Windows ×
/// x86_64/arm64) with the matching install command for each OS.
async fn downloads_page(State(state): State<BrokerState>) -> Response {
    let Some(dir) = &state.config.download_dir else {
        return crate::auth::Html::status(
            StatusCode::NOT_FOUND,
            "<h1>downloads not configured</h1>".into(),
        );
    };
    // platform -> (display, install command, file names to check)
    let platforms: [(&str, &str, &str, &[&str]); 6] = [
        (
            "Linux x86_64",
            "curl -fsSL https://<domain>/install.sh | sh",
            "ddns-x86_64-unknown-linux-musl",
            &["ddns-x86_64-unknown-linux-musl"],
        ),
        (
            "Linux arm64",
            "curl -fsSL https://<domain>/install.sh | sh",
            "ddns-aarch64-unknown-linux-musl",
            &["ddns-aarch64-unknown-linux-musl"],
        ),
        (
            "macOS x86_64",
            "curl -fsSL https://<domain>/install.sh | sh",
            "ddns-x86_64-apple-darwin",
            &["ddns-x86_64-apple-darwin"],
        ),
        (
            "macOS arm64 (Apple Silicon)",
            "curl -fsSL https://<domain>/install.sh | sh",
            "ddns-aarch64-apple-darwin",
            &["ddns-aarch64-apple-darwin"],
        ),
        (
            "Windows x86_64",
            "powershell -Command \"Invoke-WebRequest https://<domain>/download/ddns-x86_64-pc-windows-msvc.exe -OutFile ddns.exe\"",
            "ddns-x86_64-pc-windows-msvc.exe",
            &["ddns-x86_64-pc-windows-msvc.exe"],
        ),
        (
            "Windows arm64",
            "powershell -Command \"Invoke-WebRequest https://<domain>/download/ddns-aarch64-pc-windows-msvc.exe -OutFile ddns.exe\"",
            "ddns-aarch64-pc-windows-msvc.exe",
            &["ddns-aarch64-pc-windows-msvc.exe"],
        ),
    ];
    let mut rows = String::new();
    for (name, cmd, file, files) in &platforms {
        let present = files.iter().any(|f| dir.join(f).exists());
        let (status, action) = if present {
            (
                "<span class=\"chip ok\">ready</span>",
                format!(
                    "<a class=\"btn-sm\" href=\"/download/{file}\">Download</a>",
                    file = html_escape(file)
                ),
            )
        } else {
            (
                "<span class=\"chip warn\">not built</span>",
                "—".to_string(),
            )
        };
        rows.push_str(&format!(
            "<tr><td>{name}</td><td>{status}</td><td class=\"mono\">{cmd}</td><td>{action}</td></tr>",
            name = name,
            status = status,
            cmd = crate::http_app::html_escape(cmd),
            action = action,
        ));
    }
    let body = format!(
        "<h1>Download the client</h1>\
         <p class=\"subtitle\">The ddns client runs on Linux, macOS and Windows — x86_64 and arm64.\
         After downloading, run it with your token: <span class=\"mono\">ddns --token &lt;secret&gt; --server https://&lt;domain&gt; --port 8080</span></p>\
         <div class=\"box\"><table><thead><tr><th>Platform</th><th>Status</th><th>Install</th><th></th></tr></thead><tbody>{rows}</tbody></table>\
         <p class=\"hint\">Binaries are built by deploy/build-clients.sh and placed in the broker's download\
         directory (the container seeds a Linux x86_64 build on first boot).</p></div>"
    );
    crate::auth::Html::ok(crate::ui::page_shell(
        "Downloads",
        crate::ui::NavItem::None,
        &body,
    ))
}

/// GET /_assets/{path} — serve the ddns-web bundle from --web-dist.
async fn web_asset(State(state): State<BrokerState>, Path(path): Path<String>) -> Response {
    if path.contains("..") || path.contains('\\') || path.split('/').any(|s| s.is_empty()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let base = state.config.web_dist.clone();
    let full = base.join(&path);
    // Canonicalize and enforce a prefix check to prevent traversal. This also
    // neutralises Windows drive-letter absolute paths (e.g. "C:/..."), which
    // `PathBuf::join` would treat as replacing the base, and symlink escapes.
    if let Ok(canon) = full.canonicalize()
        && let Ok(base_canon) = base.canonicalize()
        && !canon.starts_with(&base_canon)
    {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    match tokio::fs::read(&full).await {
        Ok(bytes) => {
            let mime = match full.extension().and_then(|e| e.to_str()) {
                Some("wasm") => "application/wasm",
                Some("js") => "text/javascript",
                Some("css") => "text/css",
                Some("html") => "text/html; charset=utf-8",
                Some("json") => "application/json",
                Some("svg") => "image/svg+xml",
                _ => "application/octet-stream",
            };
            (StatusCode::OK, [("content-type", mime)], bytes).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[derive(serde::Serialize)]
pub struct CertStatusView {
    pub source: String,
    pub domains: Vec<String>,
    pub status: String,
    pub cert_expiry_secs: Option<i64>,
    pub last_renewed_secs: Option<i64>,
}

fn parse_cert_expiry(pem: &[u8]) -> Option<i64> {
    use x509_parser::prelude::FromDer;

    // Parse PEM to DER via rustls-pemfile (already a dep).
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<_, _>>()
        .ok()?;
    let der = certs.first()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref()).ok()?;
    let not_after: i64 = cert.validity().not_after.timestamp();
    Some(not_after)
}

mod tests {
    #[test]
    fn strip_port_handles_hosts_and_ipv6() {
        assert_eq!(crate::http_app::strip_port("example.com"), "example.com");
        assert_eq!(
            crate::http_app::strip_port("example.com:443"),
            "example.com"
        );
        assert_eq!(crate::http_app::strip_port("127.0.0.1:8443"), "127.0.0.1");
        assert_eq!(crate::http_app::strip_port("[::1]"), "[::1]");
        assert_eq!(crate::http_app::strip_port("[::1]:8080"), "[::1]");
        // malformed (unclosed bracket) is returned as-is, never truncated
        assert_eq!(crate::http_app::strip_port("[::1"), "[::1");
    }
}
