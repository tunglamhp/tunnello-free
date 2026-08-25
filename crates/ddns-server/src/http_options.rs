//! Pure request-options pipeline applied to every HTTP request before it is
//! forwarded to a tunnel backend.
//!
//! Processing order (locked):
//! 1. CORS preflight passthrough (only when `pass_preflight` is set)
//! 2. IP whitelist (403 when the peer is not allowed)
//! 3. Basic auth (`WWW-Authenticate: Basic realm="ddns"`, 401)
//! 4. Key auth (`Bearer`, 401)
//! 5. Header mutations (`X-Forwarded-*`, host rewrite, add/remove)
//!
//! `https_only` is deliberately NOT acted upon: v1 always 301s plain HTTP at
//! `http_listen`, so the pipeline never sees plain HTTP and does not re-emit
//! redirects. The flag is stored and displayed in Phase A only.

use crate::tunnel::HttpOptions;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, FORWARDED, HOST, WWW_AUTHENTICATE};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::net::IpAddr;

pub fn cidr_matches(ip: IpAddr, rules: &[String]) -> bool {
    rules.iter().any(|rule| {
        if let Some((net, len)) = rule.split_once('/') {
            let Ok(prefix) = len.parse::<u8>() else {
                return false;
            };
            let Ok(net_ip) = net.parse::<IpAddr>() else {
                return false;
            };
            return match (ip, net_ip) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    let shift = 32u32.saturating_sub(prefix as u32);
                    let mask = if shift >= 32 { 0 } else { u32::MAX << shift };
                    (u32::from(a) & mask) == (u32::from(b) & mask)
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    let shift = 128u32.saturating_sub(prefix as u32);
                    let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
                    let (a1, b1) = (
                        u128::from_be_bytes(a.octets()),
                        u128::from_be_bytes(b.octets()),
                    );
                    (a1 & mask) == (b1 & mask)
                }
                _ => false,
            };
        }
        rule.parse::<IpAddr>()
            .map(|exact| exact == ip)
            .unwrap_or(false)
    })
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Basic realm=\"ddns\"")],
    )
        .into_response()
}

fn is_preflight(req: &Request<Body>) -> bool {
    req.method() == axum::http::Method::OPTIONS
        && req.headers().contains_key("Access-Control-Request-Method")
}

fn basic_ok(req: &Request<Body>, user: &str, pass: &str) -> bool {
    let Some(h) = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(encoded) = h.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return false;
    };
    text.split_once(':').is_some_and(|(u, p)| {
        crate::auth::hmac_eq(u.as_bytes(), user.as_bytes())
            && crate::auth::hmac_eq(p.as_bytes(), pass.as_bytes())
    })
}

fn key_ok(req: &Request<Body>, key: &str) -> bool {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|k| crate::auth::hmac_eq(k.as_bytes(), key.as_bytes()))
}

/// Verify a PIN code from a form POST or from the `tunnello_pin` cookie.
/// Returns `Some(redirect_or_forbidden)` when the visitor still needs to
/// authenticate, `None` when the PIN is valid (or not configured).
fn pin_check(req: &mut Request<Body>, pin: &str) -> Option<Response> {
    use axum::http::header::{COOKIE, SET_COOKIE};

    // 1. Cookie already carries a verified PIN (HMAC-signed by the broker).
    if let Some(cookie) = req.headers().get(COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix("tunnello_pin=")
                && crate::auth::hmac_eq(val.as_bytes(), pin.as_bytes())
            {
                return None; // already authenticated
            }
        }
    }

    // 2. Form POST: verify the submitted PIN and set a session cookie.
    //    We only support application/x-www-form-urlencoded with `pin=<code>`.
    //    (Body is buffered by the caller for POSTs; here we check the query
    //    string as a lightweight alternative.)
    if let Some(q) = req.uri().query() {
        for pair in q.split('&') {
            if let Some(val) = pair.strip_prefix("pin=")
                && crate::auth::hmac_eq(val.as_bytes(), pin.as_bytes())
            {
                let mut resp = axum::response::Redirect::to("/").into_response();
                resp.headers_mut().insert(
                    SET_COOKIE,
                    HeaderValue::from_str(&format!(
                        "tunnello_pin={pin}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
                    ))
                    .unwrap(),
                );
                return Some(resp);
            }
        }
    }

    // 3. Not authenticated: render a minimal PIN entry page.
    let html = r#"<!DOCTYPE html><html><head><title>Access Code</title>
<style>body{font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0;background:#f5f5f5}
form{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
input{padding:.5rem;font-size:1rem;border:1px solid #ccc;border-radius:4px;margin-right:.5rem}
button{padding:.5rem 1rem;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer}</style>
</head><body><form method="GET"><h2>🔒 Access Code Required</h2>
<p>Enter the PIN code to access this tunnel.</p>
<input type="password" name="pin" placeholder="PIN code" autofocus required>
<button type="submit">Unlock</button></form></body></html>"#;
    Some(
        (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
    )
}

/// Full pipeline incl. visitor-auth gates. [`apply`] delegates here with
/// auth disabled so existing callers are unaffected.
pub fn apply_with_auth(
    req: &mut Request<Body>,
    peer_ip: IpAddr,
    opts: &HttpOptions,
    secret: Option<&[u8]>,
    oidc_ready: bool,
    otp_ready: bool,
) -> Option<Response> {
    if is_preflight(req) && opts.pass_preflight {
        return None;
    }
    if !opts.ip_whitelist.is_empty() && !cidr_matches(peer_ip, &opts.ip_whitelist) {
        return Some(StatusCode::FORBIDDEN.into_response());
    }
    if let Some((u, p)) = &opts.basic_auth
        && !basic_ok(req, u, p)
    {
        return Some(unauthorized());
    }
    if let Some(key) = &opts.key_auth
        && !key_ok(req, key)
    {
        return Some(unauthorized());
    }
    if let Some(pin) = &opts.pin_auth
        && let Some(resp) = pin_check(req, pin)
    {
        return Some(resp);
    }
    if opts.oidc_auth {
        let ok = secret.is_some_and(|s| auth_cookie_ok(req, "tnl_auth", s));
        if !ok {
            return Some(match (secret, oidc_ready) {
                (Some(_), true) => redirect_to_auth("oidc", &current_path(req)),
                _ => (StatusCode::SERVICE_UNAVAILABLE, "OIDC not configured on this broker")
                    .into_response(),
            });
        }
    }
    if opts.email_otp {
        let ok = secret.is_some_and(|s| auth_cookie_ok(req, "tnl_otp", s));
        if !ok {
            return Some(match (secret, otp_ready) {
                (Some(_), true) => redirect_to_auth("otp", &current_path(req)),
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "email OTP not configured on this broker",
                )
                    .into_response(),
            });
        }
    }
    // header mutations ------------------------------------------------------
    if opts.reverse_proxy_headers {
        let host = req
            .headers()
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        req.headers_mut().insert(
            "X-Forwarded-For",
            HeaderValue::from_str(&peer_ip.to_string()).unwrap(),
        );
        req.headers_mut()
            .insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
        req.headers_mut().insert(
            "X-Forwarded-Host",
            HeaderValue::from_str(&host).unwrap_or(HeaderValue::from_static("")),
        );
        req.headers_mut().insert(
            FORWARDED,
            HeaderValue::from_str(&format!("for={peer_ip};proto=https;host={host}"))
                .unwrap_or(HeaderValue::from_static("")),
        );
    }
    if let Some(h) = &opts.host_rewrite {
        let _ = req
            .headers_mut()
            .insert(HOST, HeaderValue::from_str(h).unwrap());
    }
    for (name, value) in &opts.add_headers {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes())
            && let Ok(v) = HeaderValue::from_str(value)
        {
            req.headers_mut().insert(n, v);
        }
    }
    for name in &opts.remove_headers {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
            req.headers_mut().remove(n);
        }
    }
    None
}

/// Delegate: no visitor-auth secret → OIDC/OTP gates never configured.
pub fn apply(req: &mut Request<Body>, peer_ip: IpAddr, opts: &HttpOptions) -> Option<Response> {
    apply_with_auth(req, peer_ip, opts, None, false, false)
}

/// True when the request carries a valid signed visitor-auth cookie.
fn auth_cookie_ok(req: &Request<Body>, name: &str, secret: &[u8]) -> bool {
    req.headers()
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| {
            let prefix = format!("{name}=");
            c.split(';').find_map(|p| p.trim().strip_prefix(prefix.as_str()))
        })
        .and_then(|v| crate::visitor_auth::VisitorAuthCookie::verify(v, secret))
        .is_some()
}

fn redirect_to_auth(kind: &str, back: &str) -> Response {
    use axum::response::Redirect;
    Redirect::to(&format!("/__auth/{kind}?back={back}")).into_response()
}

fn current_path(req: &Request<Body>) -> String {
    crate::visitor_auth::safe_back(req.uri().path_and_query().map(|p| p.as_str()))
}
