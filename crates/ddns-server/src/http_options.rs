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

pub fn apply(req: &mut Request<Body>, peer_ip: IpAddr, opts: &HttpOptions) -> Option<Response> {
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
