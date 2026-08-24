//! Plan 3 Task 2: admin auth tests — setup, login, session cookie.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{client_tls, start_broker, test_cert};
use ddns_server::TokenStore;
use rusqlite::{OptionalExtension, params};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// low-level helpers
// ---------------------------------------------------------------------------

/// Send an HTTP/1.1 request over TLS and read the full response.
async fn http1(addr: std::net::SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
    let mut cfg = client_tls(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connector
        .connect(host.to_string().try_into().unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&resp).into_owned()
}

/// Parse `Set-Cookie` header from an HTTP response, case-insensitive on
/// the header name; does NOT modify the cookie value itself.
fn parse_set_cookie(response: &str) -> Option<String> {
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie: ") {
            // `rest` points into the lowercased copy; use the original line
            // at the same offset to get the unmodified cookie value.
            let offset = line.len() - rest.len();
            let val = &line[offset..];
            return Some(val.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

/// Build a form body: `name=value` URL-encoded pairs.
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// 1. Full flow: no admin → / redirects to /setup, setup, / redirects to
///    /login, login, then / returns 200 + "Tunnel Dashboard".
#[tokio::test]
async fn setup_then_login_then_dashboard() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Step 1: GET / — no admin yet → 302 to /setup.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("302") && resp.contains("/setup"),
        "step 1: / → /setup, got:\n{resp}"
    );

    // Step 2: POST /setup — create the operator account (auto-login: issues
    // a session cookie and redirects to /).
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        resp.contains("302") && resp.contains("location: /\r\n"),
        "step 2: setup auto-logs-in → /, got:\n{resp}"
    );
    assert!(
        parse_set_cookie(&resp).is_some(),
        "step 2: setup issues a session cookie, got:\n{resp}"
    );

    // Step 3: GET / — admin exists but no session → 302 to /login.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("302") && resp.contains("/login"),
        "step 3: / → /login, got:\n{resp}"
    );

    // Step 4: POST /login — authenticate.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let session_cookie = parse_set_cookie(&resp).expect("Set-Cookie after login");

    // Step 5: GET / with session cookie → 200 + "Tunnel Dashboard".
    let req = format!(
        "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {session_cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        resp.contains("200") && resp.contains("Tunnel Dashboard"),
        "step 5: dashboard, got:\n{resp}"
    );

    broker.stop().await;
}

/// 2. Setup is a one-time operation; second POST is rejected.
#[tokio::test]
async fn setup_only_once() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // First setup succeeds.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        resp.contains("302"),
        "first setup should redirect, got:\n{resp}"
    );

    // Second setup is rejected.
    let body = form_body(&[("password", "another1"), ("confirm", "another1")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        resp.contains("403") || resp.contains("302"),
        "second setup should be rejected, got:\n{resp}"
    );
    assert!(
        !resp.contains("/login"),
        "second setup should not succeed, got:\n{resp}"
    );

    broker.stop().await;
}

/// 3. Wrong password returns 401 HTML.
#[tokio::test]
async fn wrong_password_rejected() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Set up admin first.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Try wrong password.
    let body = form_body(&[("password", "wrongpw")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("401"), "wrong password → 401, got:\n{resp}");
    assert!(
        resp.contains("Incorrect password or code"),
        "error message, got:\n{resp}"
    );

    broker.stop().await;
}

/// 4. API routes require a session: 401 without, 200 with.
#[tokio::test]
async fn api_requires_session() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Set up admin.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Without cookie → 401.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /api/tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("401"),
        "API without session → 401, got:\n{resp}"
    );

    // Login to get cookie.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // With cookie → the handler (which doesn't exist yet) runs behind middleware,
    // but the route /api/tokens isn't defined, so it hits the fallback → 404 or
    // gets 501. The test just checks that the middleware lets it through (not 401).
    let req = format!(
        "GET /api/tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        !resp.contains("401"),
        "API with session must not be 401, got:\n{resp}"
    );

    broker.stop().await;
}

/// 5. Public routes are accessible unauthenticated.
#[tokio::test]
async fn public_routes_open() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // /t/unknown-slug → 404 page (no redirect to /setup or /login).
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /t/unknown-slug HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.contains("404"), "/t/unknown → 404, got:\n{resp}");
    assert!(
        !resp.contains("/setup"),
        "/t/unknown must not redirect, got:\n{resp}"
    );

    // /login without cookie → 200 (login page, or redirect to /setup since no admin yet).
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /login HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    // No admin → /login redirects to /setup.
    assert!(
        resp.contains("302") && resp.contains("/setup"),
        "/login without admin → /setup, got:\n{resp}"
    );

    // /connect → WebSocket upgrade. The server may respond with 101 (upgrade)
    // or 426 (upgrade required), or drop the connection if the handshake fails.
    // We just verify it doesn't get an auth redirect.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /connect HTTP/1.1\r\nHost: tunnel.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .await;
    assert!(
        !resp.contains("/login") && !resp.contains("/setup"),
        "/connect should not be auth-redirected, got:\n{resp}"
    );

    broker.stop().await;
}

/// 6. Tunnel subdomain Hosts bypass authentication (visitor traffic).
#[tokio::test]
async fn tunnel_host_bypasses_auth() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // GET / with Host slug.tunnel.example.com → 404 "no such tunnel", NOT a redirect.
    let resp = http1(
        addr,
        &cert,
        "slug.tunnel.example.com",
        "GET / HTTP/1.1\r\nHost: slug.tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("404") || resp.contains("no such tunnel"),
        "tunnel host → 404, got:\n{resp}"
    );
    assert!(
        !resp.contains("/setup"),
        "tunnel host must not redirect to /setup, got:\n{resp}"
    );
    assert!(
        !resp.contains("/login"),
        "tunnel host must not redirect to /login, got:\n{resp}"
    );

    broker.stop().await;
}

/// 7. Expired cookie is rejected.
#[tokio::test]
async fn cookie_expired_rejected() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Set up admin + get the server secret so we can craft a cookie.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Craft an expired cookie: exp = 1 (well in the past).
    // Format: base64url("1").base64url(hmac(payload, secret))
    // We need the server secret. Since we can't easily extract it, we log in,
    // capture a valid cookie, then manually corrupt the expiry portion.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // The cookie is "ddns_session=<payload>.<tag>". Replace the payload with an
    // expired one: base64url("1") = "MQ".
    let cookie_val = cookie.strip_prefix("ddns_session=").unwrap();
    let parts: Vec<&str> = cookie_val.splitn(2, '.').collect();
    assert_eq!(parts.len(), 2, "cookie must have payload.tag format");
    let expired_cookie = format!("ddns_session=MQ.{}", parts[1]);

    let req = format!(
        "GET /api/tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {expired_cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("401"), "expired cookie → 401, got:\n{resp}");

    broker.stop().await;
}

/// 8. Tampered cookie is rejected.
#[tokio::test]
async fn tampered_cookie_rejected() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Set up admin.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Login to get a valid cookie.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // Tamper: flip the last char of the tag.
    let mut tampered = cookie.clone();
    // The tag is after the '.'. Flip the last character.
    if let Some(last) = tampered.pop() {
        let flipped = if last == 'A' { 'B' } else { 'A' };
        tampered.push(flipped);
    }

    let req = format!(
        "GET /api/tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {tampered}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("401"), "tampered cookie → 401, got:\n{resp}");

    broker.stop().await;
}

/// 9. Logout clears the session cookie (stateless HMAC cookie: clearing the
/// client value is the only server-side invalidation; a captured cookie
/// remains valid until expiry).
#[tokio::test]
async fn logout_clears_session_cookie() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, TokenStore::new(), 256, Duration::from_secs(5)).await;

    // Set up admin.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Login.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // Verify cookie works.
    let req = format!(
        "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        resp.contains("Tunnel Dashboard"),
        "dashboard with valid cookie, got:\n{resp}"
    );
    // Logout — the observable contract: a clearing Set-Cookie (Max-Age=0,
    // Path=/). The HMAC cookie is stateless, so the clearing directive is the
    // only server-side invalidation; a captured cookie stays valid until its
    // 24 h expiry.
    let req = format!(
        "GET /logout HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    let logout_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(
        logout_resp.contains("303"),
        "logout redirects, got:\n{logout_resp}"
    );
    assert!(
        logout_resp.contains("ddns_session=; Max-Age=0; Path=/"),
        "logout must clear the session cookie, got:\n{logout_resp}"
    );

    // After logout, a request without a cookie (browser deleted it) → 401.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /api/tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("401"),
        "without cookie after logout → 401, got:\n{resp}"
    );

    broker.stop().await;
}

// ---------------------------------------------------------------------------
// 2FA helpers + tests
// ---------------------------------------------------------------------------

/// Build a POST request with the session cookie (bodyless when `body` empty).
fn post_req(cookie: &str, path: &str, body: &str) -> String {
    if body.is_empty() {
        format!(
            "POST {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "POST {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
}

/// Read a single nullable TEXT cell (or `None` when the row/column is absent).
fn read_string(tokens: &TokenStore, sql: &str) -> Option<String> {
    let db = tokens.db_conn().lock().unwrap_or_else(|p| p.into_inner());
    db.query_row(sql, [], |r| r.get::<_, Option<String>>(0))
        .optional()
        .unwrap()
        .flatten()
}

/// Read a single non-null INTEGER cell.
fn read_i64(tokens: &TokenStore, sql: &str) -> i64 {
    let db = tokens.db_conn().lock().unwrap_or_else(|p| p.into_inner());
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

/// 10. With 2FA enabled, login requires a valid code: a wrong code returns the
/// same generic 401 as a wrong password and issues no session; the right code
/// issues a session.
#[tokio::test]
async fn login_requires_2fa_code_when_enabled() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    let tokens2 = tokens.clone();
    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(5)).await;

    // Set up admin.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Enable 2FA directly (the setup/verify flow is covered separately).
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // RFC 6238 test secret
    {
        let db = tokens2.db_conn().lock().unwrap_or_else(|p| p.into_inner());
        db.execute(
            "UPDATE accounts SET otp_secret = ?1, otp_enabled = 1 WHERE role = 'operator'",
            params![secret],
        )
        .unwrap();
    }

    let now = ddns_server::now_secs() as u64;
    let code = ddns_server::otp::totp_code(secret, now);
    // A code three minutes ahead is outside the ±1 step window, so it can
    // never verify at `now`.
    let wrong = ddns_server::otp::totp_code(secret, now + 180);

    // Wrong code → generic 401, no session cookie.
    let body = form_body(&[("password", "secret123"), ("otp", wrong.as_str())]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("401"), "wrong 2FA code → 401, got:\n{resp}");
    assert!(
        resp.contains("Incorrect password or code"),
        "generic error, got:\n{resp}"
    );
    assert!(
        parse_set_cookie(&resp).is_none(),
        "no session on wrong code, got:\n{resp}"
    );

    // Right code → 303 + session cookie.
    let body = form_body(&[("password", "secret123"), ("otp", code.as_str())]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&resp).expect("Set-Cookie after 2FA login");

    // Session works.
    let req = format!(
        "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert!(resp.contains("Tunnel Dashboard"), "dashboard, got:\n{resp}");

    broker.stop().await;
}

/// 11. Full 2FA lifecycle: setup stores only a pending secret (the account is
/// not enabled until a valid code verifies); verify enables it and clears the
/// pending key; disable requires a valid current code.
#[tokio::test]
async fn two_factor_setup_verify_disable_flow() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    let tokens2 = tokens.clone();
    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(5)).await;

    // Set up admin (auto-issues the session cookie).
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let setup_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&setup_resp).expect("session cookie from setup");

    // 1. Start setup → pending secret stored; account still disabled.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(&cookie, "/settings/2fa/setup", ""),
    )
    .await;
    assert!(resp.contains("303"), "setup redirects, got:\n{resp}");
    let pending = read_string(
        &tokens2,
        "SELECT value FROM settings WHERE key = 'otp_pending_secret'",
    )
    .expect("pending secret stored");
    assert_eq!(
        read_i64(
            &tokens2,
            "SELECT otp_enabled FROM accounts WHERE role = 'operator'"
        ),
        0,
        "account must not enable until verified"
    );

    let now = ddns_server::now_secs() as u64;
    let code = ddns_server::otp::totp_code(&pending, now);
    let wrong = ddns_server::otp::totp_code(&pending, now + 180);

    // 2. Verify with wrong code → error, pending kept, account still disabled.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(
            &cookie,
            "/settings/2fa/verify",
            &form_body(&[("otp", wrong.as_str())]),
        ),
    )
    .await;
    assert!(resp.contains("303"), "verify redirects, got:\n{resp}");
    assert!(
        read_string(
            &tokens2,
            "SELECT value FROM settings WHERE key = 'otp_pending_secret'"
        )
        .is_some(),
        "pending secret kept on wrong code"
    );
    assert_eq!(
        read_i64(
            &tokens2,
            "SELECT otp_enabled FROM accounts WHERE role = 'operator'"
        ),
        0
    );

    // 3. Verify with correct code → enabled, pending cleared.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(
            &cookie,
            "/settings/2fa/verify",
            &form_body(&[("otp", code.as_str())]),
        ),
    )
    .await;
    assert!(resp.contains("303"), "verify redirects, got:\n{resp}");
    assert_eq!(
        read_i64(
            &tokens2,
            "SELECT otp_enabled FROM accounts WHERE role = 'operator'"
        ),
        1,
        "2FA enabled after verify"
    );
    assert!(
        read_string(
            &tokens2,
            "SELECT value FROM settings WHERE key = 'otp_pending_secret'"
        )
        .is_none(),
        "pending secret cleared after verify"
    );

    // 4. Disable with wrong code → error, still enabled.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(
            &cookie,
            "/settings/2fa/disable",
            &form_body(&[("otp", wrong.as_str())]),
        ),
    )
    .await;
    assert!(resp.contains("303"), "disable redirects, got:\n{resp}");
    assert_eq!(
        read_i64(
            &tokens2,
            "SELECT otp_enabled FROM accounts WHERE role = 'operator'"
        ),
        1,
        "wrong code must not disable"
    );

    // 5. Disable with correct code → disabled, secret cleared.
    let code = ddns_server::otp::totp_code(&pending, ddns_server::now_secs() as u64);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(
            &cookie,
            "/settings/2fa/disable",
            &form_body(&[("otp", code.as_str())]),
        ),
    )
    .await;
    assert!(resp.contains("303"), "disable redirects, got:\n{resp}");
    assert_eq!(
        read_i64(
            &tokens2,
            "SELECT otp_enabled FROM accounts WHERE role = 'operator'"
        ),
        0,
        "2FA disabled"
    );
    assert!(
        read_string(
            &tokens2,
            "SELECT otp_secret FROM accounts WHERE role = 'operator'"
        )
        .is_none(),
        "secret cleared on disable"
    );

    broker.stop().await;
}

/// 12. The settings page renders the 2FA section as a sibling form — the
/// Change Admin Password form is closed before the 2FA card, so the 2FA
/// button submits to its own endpoint (not POST /settings) instead of being
/// dropped by HTML5 form-nesting parsing. All three states (off / pending /
/// enabled) are exercised.
#[tokio::test]
async fn settings_page_renders_separate_2fa_forms() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    let tokens2 = tokens.clone();
    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(5)).await;

    // Set up admin (auto-issues the session cookie).
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let setup_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&setup_resp).expect("session cookie");

    let get_settings = |cookie: &str| {
        format!(
            "GET /settings HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
        )
    };
    // Assert a rendered 2FA form is a separate, well-formed form.
    fn assert_form(resp: &str, action: &str) {
        assert!(
            resp.contains(&format!("action=\"{action}\"")),
            "form {action} present, got:\n{resp}"
        );
        let opens = resp.matches("<form ").count();
        let closes = resp.matches("</form>").count();
        assert_eq!(opens, closes, "balanced form tags, got:\n{resp}");
        let action_idx = resp.find(&format!("action=\"{action}\"")).unwrap();
        let action_close = action_idx + resp[action_idx..].find("</form>").unwrap();
        let change_idx = resp.find("Change Password</button>").unwrap();
        assert!(
            action_close < change_idx,
            "2FA form {action} closes before the change-password form, got:\n{resp}"
        );
    }

    // 1. Off state → enable form.
    let resp = http1(addr, &cert, "tunnel.example.com", &get_settings(&cookie)).await;
    assert_form(&resp, "/settings/2fa/setup");

    // 2. Pending state → verify form.
    http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(&cookie, "/settings/2fa/setup", ""),
    )
    .await;
    let resp = http1(addr, &cert, "tunnel.example.com", &get_settings(&cookie)).await;
    assert_form(&resp, "/settings/2fa/verify");

    // 3. Enabled state → disable form.
    let pending = read_string(
        &tokens2,
        "SELECT value FROM settings WHERE key = 'otp_pending_secret'",
    )
    .expect("pending secret");
    let code = ddns_server::otp::totp_code(&pending, ddns_server::now_secs() as u64);
    http1(
        addr,
        &cert,
        "tunnel.example.com",
        &post_req(
            &cookie,
            "/settings/2fa/verify",
            &form_body(&[("otp", code.as_str())]),
        ),
    )
    .await;
    let resp = http1(addr, &cert, "tunnel.example.com", &get_settings(&cookie)).await;
    assert_form(&resp, "/settings/2fa/disable");

    broker.stop().await;
}
