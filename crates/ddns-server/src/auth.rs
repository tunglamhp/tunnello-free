//! Operator authentication: one admin password (argon2id, SQLite settings row)
//! and an HMAC-signed HttpOnly session cookie (TTL-configurable, default 24 h). Spec §5.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Extension;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Redirect as AxumRedirect;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::http_app::BrokerState;
use crate::http_app::tunnel_slug;

const COOKIE_NAME: &str = "ddns_session";

/// Full `Set-Cookie` value that clears the session cookie. It mirrors the
/// attributes the cookie was issued with (HttpOnly, SameSite=Lax, Secure) —
/// a Secure cookie can only be deleted by a Secure Set-Cookie — and is shared
/// by the operator (`logout`) and portal (`Redirect::clear_cookie`) paths so
/// the two can never drift.
const CLEAR_COOKIE_VALUE: &str = "ddns_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure";

// ---------------------------------------------------------------------------
// password hashing
// ---------------------------------------------------------------------------
pub fn hash_password(pw: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)?;
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(pw.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// session cookie
// ---------------------------------------------------------------------------

pub struct SessionCookie;

/// Role-scoped session claims carried by the cookie (spec §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    pub account_id: i64,
    pub role: String,
}

impl SessionCookie {
    /// Cookie value: `base64url(exp.account_id.role).base64url(hmac)`.
    pub fn issue(server_secret: &[u8], account_id: i64, role: &str, ttl_secs: u64) -> String {
        let exp = now_unix().saturating_add(ttl_secs).to_string();
        let payload = format!("{exp}.{account_id}.{role}");
        let enc = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let tag = Self::tag(server_secret, enc.as_bytes());
        format!("{enc}.{tag}")
    }

    pub fn verify(cookie: &str, server_secret: &[u8]) -> Option<SessionClaims> {
        let (enc, tag) = cookie.split_once('.')?;
        let expected = Self::tag(server_secret, enc.as_bytes());
        if !hmac_eq(expected.as_bytes(), tag.as_bytes()) {
            return None;
        }
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(enc).ok()?).ok()?;
        let mut parts = payload.splitn(3, '.');
        let exp: u64 = parts.next()?.parse().ok()?;
        if exp <= now_unix() {
            return None;
        }
        let account_id: i64 = parts.next()?.parse().ok()?;
        let role = parts.next()?.to_string();
        Some(SessionClaims { account_id, role })
    }

    fn tag(server_secret: &[u8], payload: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(server_secret).expect("hmac key");
        mac.update(payload);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

/// Session TTL in seconds from the runtime settings cache (minimum 1 hour,
/// so a mis-set value can never mint a cookie that is already expired).
pub fn ttl_from_settings(state: &BrokerState) -> u64 {
    let s = state.settings.read().unwrap_or_else(|p| p.into_inner());
    s.session_ttl_hours.max(1) * 3600
}

/// Constant-time byte comparison without an extra dep.
pub(crate) fn hmac_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn cookie_name() -> &'static str {
    COOKIE_NAME
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse `ddns_session=<value>` from a `Cookie` header value.
fn parse_session_cookie(header: &str) -> Option<String> {
    for part in header.split("; ") {
        if let Some(value) = part.strip_prefix("ddns_session=") {
            return Some(value.to_string());
        }
    }
    None
}

/// Check whether the request Host is a tunnel subdomain that should bypass
/// authentication (tunnel visitor traffic, not operator pages). Covers both
/// `slug.<domain>` shapes and custom hostnames bound to a live session.
fn is_tunnel_host(req: &Request<Body>, state: &BrokerState) -> bool {
    if tunnel_slug(req, &state.config.domain).is_some() {
        return true;
    }
    crate::http_app::req_host(req).is_some_and(|h| state.registry.custom_host(&h).is_some())
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

/// Paths that never require a session or role check. Keep in sync with the
/// public routes registered in `http_app::router`.
pub fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/connect"
            | "/health"
            | "/api/version"
            | "/login"
            | "/setup"
            | "/logout"
            | "/install.sh"
            | "/downloads"
            | "/portal/signup"
            | "/portal/login"
            | "/portal/forgot"
            | "/portal/reset"
            | "/portal/verify"
            | "/__p2p/signal"
            | "/__tunnello/sw.js"
    ) || path.starts_with("/t/")
        || path.starts_with("/download/")
        || path.starts_with("/_assets/")
        || path.starts_with("/webhooks/")
        || path.starts_with("/api/v1/")
}

/// axum middleware that requires a valid session cookie for protected routes.
///
/// * Public paths (`is_public_path`) and tunnel-subdomain Hosts pass through
///   unauthenticated.
/// * API routes (`/api/…`, `/portal/api/…`) without a session → 401.
/// * Page routes without a session → 302 `/portal/login` (portal), `/setup`
///   (first run) or `/login`.
pub async fn require_session(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let is_api = path.starts_with("/api/") || path.starts_with("/portal/api/");

    // Public paths — always allow.
    if is_public_path(path) {
        return next.run(req).await;
    }

    // Check session cookie.
    let cookie_val = req
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_session_cookie);

    let claims = match &cookie_val {
        Some(cookie) => match state.config.token_store.server_secret().await {
            Ok(secret) => SessionCookie::verify(cookie, &secret),
            Err(_) => None,
        },
        None => None,
    };

    if let Some(claims) = claims {
        req.extensions_mut().insert(claims);
        // Dashboard IP allowlist (Task 3): after the session check passes,
        // deny peers outside a non-empty allowlist. Empty allowlist = allow
        // all. Runs before the role checks in require_operator/require_client.
        let allowed = {
            let s = state.settings.read().unwrap_or_else(|p| p.into_inner());
            s.peer_allowed(&peer.ip())
        };
        if !allowed {
            if is_api {
                return (StatusCode::FORBIDDEN, "forbidden").into_response();
            }
            return Html::status(
                StatusCode::FORBIDDEN,
                "Your IP is not allowed to access the dashboard.".to_string(),
            );
        }
        return next.run(req).await;
    }

    // API routes: never bypassed by tunnel-host Host headers — always 401
    // without a session. (A client can trivially fake Host: <slug>.<domain>;
    // the tunnel-host pass-through below is for *page* visitor traffic only.)
    if is_api {
        return (StatusCode::UNAUTHORIZED, "session required").into_response();
    }

    // Tunnel-host traffic (a live `slug.<domain>` or a bound custom host)
    // must reach the fallback handler unauthenticated — it serves the
    // customer's site at ANY path (/echo, /foo/bar, …), not just "/".
    // A faked Host: x.<domain> passes through here too, but every operator
    // and portal route is gated by require_operator below,
    // which reject when no session claims were inserted (defense-in-depth:
    // the incomplete path allowlist that used to live here let spoofed Hosts
    // reach /clients, /plans, /codes, /audit, /tunnels, …).
    if is_tunnel_host(&req, &state) {
        return next.run(req).await;
    }

    // Page — bounce portal paths to the portal login, operator pages to
    // /setup on first run, otherwise /login.
    if path.starts_with("/portal") {
        return Redirect::temporary("/portal/login");
    }
    let target = if state.accounts.has_operator().await.unwrap_or(false) {
        "/login"
    } else {
        "/setup"
    };
    Redirect::temporary(target)
}

/// Require an operator session (applied after `require_session`).
///
/// Claims are `Option` because axum extracts middleware arguments before the
/// body runs: public paths and tunnel-host visitor traffic to "/" (which
/// `require_session` passes through without inserting claims) must reach
/// `is_public_path`/the dashboard handler instead of 500ing. Every other
/// non-public path rejects when claims is absent — defense-in-depth so a
/// spoofed tunnel Host header can never bypass operator auth.
pub async fn require_operator(
    claims: Option<Extension<SessionClaims>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if is_public_path(req.uri().path()) {
        return next.run(req).await;
    }
    let path = req.uri().path();
    let Some(Extension(claims)) = claims else {
        // Defense-in-depth: require_session should have redirected
        // unauthenticated requests already. If we reach here without claims
        // (a tunnel-host bypass path), only allow "/" — the dashboard
        // disambiguates tunnel hosts and delegates to fallback. Every other
        // operator route rejects; never pass through without auth.
        if path == "/" {
            return next.run(req).await;
        }
        return AxumRedirect::to("/login").into_response();
    };
    if claims.role != "operator" {
        return AxumRedirect::to("/portal").into_response();
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// GET /setup — render the first-run operator-setup form.
///
/// If an operator account already exists, redirect to `/`.
pub async fn setup_page(State(state): State<BrokerState>) -> Response {
    if state.accounts.has_operator().await.unwrap_or(false) {
        return Redirect::temporary("/");
    }
    // A non-loopback bind is network-reachable before setup completes, so the
    // bootstrap token is required — render the token field so the operator
    // knows what to supply (and why).
    let loopback_only = state.config.listen.ip().is_loopback();
    let token_required = !loopback_only || std::env::var("DDNS_SETUP_TOKEN").is_ok();
    let hint = if token_required && loopback_only {
        Some((true, "DDNS_SETUP_TOKEN is set — provide the token below."))
    } else if token_required {
        Some((
            true,
            "This broker is reachable from the network — provide the \
             DDNS_SETUP_TOKEN set at startup.",
        ))
    } else {
        None
    };
    Html::ok(setup_html_with_token(hint))
}

/// POST /setup — create the operator account.
///
/// Setup is disabled once an operator exists; a second POST gets a 403.
///
/// First-run takeover guard: a broker bound to a non-loopback address is
/// reachable from the network before the operator completes setup, so any
/// peer could claim the operator account (and be issued an operator session).
/// When the listener is not loopback-only, `DDNS_SETUP_TOKEN` MUST be set and
/// the posted `token` field MUST match it (constant-time). Loopback binds
/// (local dev, tests) skip the requirement unless the env var is configured.
pub async fn setup_submit(State(state): State<BrokerState>, body: String) -> Response {
    // Setup disabled once an operator account exists (fast path; the
    // accounts.email UNIQUE constraint is the real enforcement).
    if state.accounts.has_operator().await.unwrap_or(false) {
        return (StatusCode::FORBIDDEN, "setup already complete").into_response();
    }

    // First-run takeover guard (see fn doc).
    let expected = std::env::var("DDNS_SETUP_TOKEN").ok();
    let posted_token = form_field(&body, "token");
    let loopback_only = state.config.listen.ip().is_loopback();
    if !loopback_only && expected.is_none() {
        return Html::status(
            StatusCode::FORBIDDEN,
            setup_html(Some(
                "Setup blocked: this broker is reachable from the network and \
                 DDNS_SETUP_TOKEN is not set. Restart with DDNS_SETUP_TOKEN \
                 set, then POST /setup with token=<value> to claim the \
                 operator account.",
            )),
        );
    }
    if let Some(expected) = &expected
        && !hmac_eq(posted_token.as_bytes(), expected.as_bytes())
    {
        return Html::status(
            StatusCode::FORBIDDEN,
            setup_html(Some("Invalid setup token.")),
        );
    }

    // Parse form: password=<val>&confirm=<val>
    let pw = form_field(&body, "password");
    let confirm = form_field(&body, "confirm");

    // Same 8-128 bound as the change-password API.
    if !(8..=128).contains(&pw.len()) {
        return Html::status(
            StatusCode::BAD_REQUEST,
            setup_html(Some("Password must be 8-128 characters.")),
        );
    }
    if pw != confirm {
        return Html::status(
            StatusCode::BAD_REQUEST,
            setup_html(Some("Passwords do not match.")),
        );
    }

    // argon2 is CPU-bound — hash off the async runtime.
    let pw_for_hash = pw.clone();
    let hash = match tokio::task::spawn_blocking(move || hash_password(&pw_for_hash)).await {
        Ok(Ok(h)) => h,
        _ => {
            return Html::status(
                StatusCode::INTERNAL_SERVER_ERROR,
                setup_html(Some("Password hashing failed.")),
            );
        }
    };

    let email =
        std::env::var("DDNS_OPERATOR_EMAIL").unwrap_or_else(|_| "operator@localhost".to_string());
    let op = match state.accounts.create(&email, &hash, "operator").await {
        Ok(op) => op,
        Err(e) => {
            tracing::error!(?e, "operator account create failed");
            return Html::status(
                StatusCode::INTERNAL_SERVER_ERROR,
                setup_html(Some("Failed to save operator account.")),
            );
        }
    };

    let secret = match state.config.token_store.server_secret().await {
        Ok(s) => s,
        Err(_) => {
            return Html::status(
                StatusCode::INTERNAL_SERVER_ERROR,
                setup_html(Some("Session error.")),
            );
        }
    };
    let ttl = ttl_from_settings(&state);
    let cookie = SessionCookie::issue(&secret, op.id, "operator", ttl);
    let set_cookie = format!(
        "{COOKIE_NAME}={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}; Secure",
        ttl
    );
    Redirect::with_cookie("/", &set_cookie)
}

/// GET /login — render the operator login form.
///
/// If no operator account exists, redirect to `/setup`.
pub async fn login_page(State(state): State<BrokerState>) -> Response {
    if !state.accounts.has_operator().await.unwrap_or(false) {
        return Redirect::temporary("/setup");
    }
    Html::ok(login_html(None))
}

/// POST /login — verify the operator account password and issue a session
/// cookie with the account id + role claims.
pub async fn login_submit(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: String,
) -> Response {
    state.audit.record("operator", "-", "login", "");
    // Argon2 verify is CPU-bound — per-IP rate-limited against brute force
    // (see rate_limit.rs).
    if !state.operator_login_limiter.allow(Some(peer.ip())) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let password = form_field(&body, "password");

    let Some(op) = state.accounts.find_operator().await.ok().flatten() else {
        return Redirect::temporary("/setup");
    };

    // argon2 is CPU-bound — verify off the async runtime.
    let verified = if password.is_empty() {
        false
    } else {
        let pw = password.clone();
        let hash = op.password_hash.clone();
        tokio::task::spawn_blocking(move || verify_password(&pw, &hash))
            .await
            .unwrap_or(false)
    };
    if !verified {
        return Html::status(
            StatusCode::UNAUTHORIZED,
            login_html(Some("Incorrect password or code.")),
        );
    }

    // 2FA: when enabled, require a valid TOTP code. The failure message is
    // identical to a wrong password so the form does not reveal whether 2FA
    // is enabled for the operator account (no enumeration).
    if op.otp_enabled {
        let code = form_field(&body, "otp");
        let secret = op.otp_secret.as_deref().unwrap_or("");
        if !crate::otp::totp_verify(secret, &code, now_unix()) {
            return Html::status(
                StatusCode::UNAUTHORIZED,
                login_html(Some("Incorrect password or code.")),
            );
        }
    }

    let secret = match state.config.token_store.server_secret().await {
        Ok(s) => s,
        Err(_) => {
            return Html::status(
                StatusCode::INTERNAL_SERVER_ERROR,
                login_html(Some("Session error.")),
            );
        }
    };

    let ttl = ttl_from_settings(&state);
    let cookie = SessionCookie::issue(&secret, op.id, "operator", ttl);
    let set_cookie = format!(
        "{COOKIE_NAME}={cookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}; Secure",
        ttl
    );

    (
        StatusCode::SEE_OTHER,
        [("location", "/"), ("set-cookie", set_cookie.as_str())],
    )
        .into_response()
}

/// GET /logout — clear the session cookie and redirect to /login.
///
/// The cookie is stateless (HMAC): clearing the client-side value is the only
/// invalidation; a captured cookie stays valid until its configured expiry.
pub async fn logout() -> Response {
    (
        StatusCode::SEE_OTHER,
        [("location", "/login"), ("set-cookie", CLEAR_COOKIE_VALUE)],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// tiny helpers
// ---------------------------------------------------------------------------

/// Extract a URL-encoded form field value. Returns `""` when absent.
pub fn form_field(body: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    for part in body.split('&') {
        if let Some(val) = part.strip_prefix(&prefix) {
            return percent_decode(val);
        }
    }
    String::new()
}

/// Decode `%XX` and `+` → space, byte-wise (multi-byte UTF-8 percent
/// sequences decode as whole bytes, then validate as UTF-8). A malformed
/// sequence degrades lossy — identically for setup and login, so the browser
/// round-trip stays self-consistent and raw-UTF-8 clients agree with
/// percent-encoded ones.
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
// tiny HTML/Redirect builders
// ---------------------------------------------------------------------------

pub struct Html;

impl Html {
    pub fn ok(html: String) -> Response {
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            html,
        )
            .into_response()
    }

    pub fn status(status: StatusCode, html: String) -> Response {
        (status, [("content-type", "text/html; charset=utf-8")], html).into_response()
    }
}

pub struct Redirect;

impl Redirect {
    pub fn temporary(location: &str) -> Response {
        (StatusCode::FOUND, [("location", location)]).into_response()
    }

    /// 302 with the session cookie set (attributes mirror `login_submit`'s
    /// Set-Cookie string).
    pub fn with_cookie(location: &str, cookie: &str) -> Response {
        (
            StatusCode::FOUND,
            [
                ("location", location.to_string()),
                ("set-cookie", cookie.to_string()),
            ],
        )
            .into_response()
    }

    /// 302 with an expired session cookie (logout).
    pub fn clear_cookie(location: &str) -> Response {
        (
            StatusCode::FOUND,
            [
                ("location", location.to_string()),
                ("set-cookie", CLEAR_COOKIE_VALUE.to_string()),
            ],
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// page templates
// ---------------------------------------------------------------------------

/// Setup page body (no `<html>` frame — `setup_html` wraps it in the shell).
/// `{token_field}` is replaced with a bootstrap-token input when required.
const SETUP_BODY: &str = r###"<div class="box glass">
<h1>Setup Admin Password</h1>
<p class="subtitle">First run — choose a password for the operator dashboard.</p>
<form method="post" action="/setup">
{token_field}
<label for="password">Password</label>
<input type="password" id="password" name="password" required minlength="8" autofocus>
<label for="confirm">Confirm</label>
<input type="password" id="confirm" name="confirm" required minlength="8">
<button type="submit">Set Password</button>
</form>
</div>"###;

fn setup_html(error: Option<&str>) -> String {
    setup_html_with_token(error.map(|e| (false, e)))
}

/// Render the setup page. `hint` is `(required, message)` for the bootstrap
/// token; `None` renders no token field.
fn setup_html_with_token(hint: Option<(bool, &str)>) -> String {
    let err = hint
        .filter(|(required, _)| !required)
        .map(|(_, e)| format!("<p class=\"error\">{e}</p>"))
        .unwrap_or_default();
    let token_field = match hint {
        Some((required, msg)) => format!(
            "<label for=\"token\">Setup token</label>\n<input type=\"password\" id=\"token\" name=\"token\" {}\n<p class=\"subtitle\">{msg}</p>",
            if required { "required autofocus" } else { "" }
        ),
        None => String::new(),
    };
    let body = SETUP_BODY.replace("{token_field}", &token_field);
    crate::ui::page_shell("Setup", crate::ui::NavItem::None, &format!("{body}{err}"))
}

/// Login page body (no `<html>` frame — `login_html` wraps it in the shell).
const LOGIN_BODY: &str = r###"<div class="box glass">
<h1>Operator Login</h1>
<p class="subtitle">Sign in to manage your Tunello tunnel broker.</p>
<form method="post" action="/login">
<label for="password">Password</label>
<input type="password" id="password" name="password" required autofocus>
<label for="otp">2FA code (6 digits)</label>
<input type="text" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6" pattern="[0-9]{6}">
<button type="submit">Sign In</button>
</form>
</div>"###;

fn login_html(error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p class=\"error\">{e}</p>"))
        .unwrap_or_default();
    crate::ui::page_shell(
        "Sign in",
        crate::ui::NavItem::None,
        &format!("{LOGIN_BODY}{err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_round_trips_with_claims() {
        let secret = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let cookie = SessionCookie::issue(secret, 7, "client", 3600);
        let claims = SessionCookie::verify(&cookie, secret).unwrap();
        assert_eq!(claims.account_id, 7);
        assert_eq!(claims.role, "client");
        // tampering fails
        let tampered = format!("{}x", &cookie[..cookie.len() - 2]);
        assert!(SessionCookie::verify(&tampered, secret).is_none());
        // wrong secret fails
        assert!(SessionCookie::verify(&cookie, b"other-secret-0123456789abcdef").is_none());
        // old two-part cookies (exp.hmac) are rejected (re-login required)
        let legacy = format!("{}.{}", "MTc4OTkwMDAwMA", "AAAA");
        assert!(SessionCookie::verify(&legacy, secret).is_none());
    }

    #[test]
    fn issue_ttl_controls_expiry() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let before = now_unix();
        // ttl=1 → exp = now + 1 (payload embeds the expiry).
        let cookie = SessionCookie::issue(secret, 7, "client", 1);
        let enc = cookie.split_once('.').unwrap().0;
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(enc).unwrap()).unwrap();
        let exp: u64 = payload.split('.').next().unwrap().parse().unwrap();
        assert!(
            exp > before && exp <= before + 2,
            "exp={exp} before={before}"
        );
        // Not yet expired: verifies now.
        assert!(SessionCookie::verify(&cookie, secret).is_some());

        // A crafted cookie whose exp is already in the past is rejected.
        let payload = format!("{}.7.client", before.saturating_sub(1));
        let enc = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let tag = SessionCookie::tag(secret, enc.as_bytes());
        let expired = format!("{enc}.{tag}");
        assert!(SessionCookie::verify(&expired, secret).is_none());
    }

    #[test]
    fn session_cookie_tampered_rejected() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let cookie = SessionCookie::issue(secret, 7, "operator", 3600);
        // Flip a character in the tag
        let dot = cookie.rfind('.').unwrap();
        let mut tampered = cookie.clone();
        let bytes = unsafe { tampered.as_bytes_mut() };
        bytes[dot + 1] = if bytes[dot + 1] == b'A' { b'B' } else { b'A' };
        assert!(
            SessionCookie::verify(&tampered, secret).is_none(),
            "tampered cookie must reject"
        );
    }

    #[tokio::test]
    async fn require_operator_and_client_enforce_role() {
        use axum::Router;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn handler() -> &'static str {
            "ok"
        }

        fn req() -> Request<Body> {
            Request::builder().uri("/x").body(Body::empty()).unwrap()
        }

        let op = SessionClaims {
            account_id: 1,
            role: "operator".into(),
        };
        let cl = SessionClaims {
            account_id: 2,
            role: "client".into(),
        };

        // client claims hitting an operator-only route → 303 to /portal
        let router = Router::new()
            .route("/x", get(handler))
            .route_layer(axum::middleware::from_fn(require_operator))
            .layer(Extension(cl.clone()));
        let resp = router.oneshot(req()).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SEE_OTHER);
        // operator claims pass through → 200
        let router = Router::new()
            .route("/x", get(handler))
            .route_layer(axum::middleware::from_fn(require_operator))
            .layer(Extension(op.clone()));
        let resp = router.oneshot(req()).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
