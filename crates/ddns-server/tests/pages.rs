//! Plan 3 Task 4: Dashboard page tests — tokens, settings, XSS, auth.

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use common::{FakeClient, broker_config, client_tls, spawn_local_app, start_broker, test_cert};
use ddns_proto::frame::CLOSE_OK;
use ddns_server::TokenStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// low-level helpers (copied from tests/api.rs — small helpers, not worth
// a shared module for the task scope)
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

/// Parse `Set-Cookie` header from an HTTP response.
fn parse_set_cookie(response: &str) -> Option<String> {
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie: ") {
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

/// Get the status code from an HTTP response.
fn status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Find a header value by name (case-insensitive).
fn header_value(response: &str, name: &str) -> Option<String> {
    let lower_name = name.to_ascii_lowercase();
    for line in response.lines() {
        if let Some((k, v)) = line.split_once(": ")
            && k.to_ascii_lowercase() == lower_name
        {
            return Some(v.to_string());
        }
    }
    None
}

/// Set up admin + login, return (addr, broker, cookie, cert).
async fn setup_admin() -> (std::net::SocketAddr, ddns_server::Broker, String, Vec<u8>) {
    let (cert, key) = test_cert();
    let (addr, broker) = start_broker(
        &cert,
        &key,
        TokenStore::new(),
        256,
        std::time::Duration::from_secs(5),
    )
    .await;

    // Set up admin password.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    // Login to get cookie.
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");
    (addr, broker, cookie, cert)
}

/// Build an authed page request with the session cookie.
fn page_req(cookie: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
    )
}

/// Build an authed API request with the session cookie.
fn api_req(
    cookie: &str,
    method: &str,
    path: &str,
    body_json: Option<&serde_json::Value>,
) -> String {
    let body = body_json.map(|j| j.to_string()).unwrap_or_default();
    format!(
        "{method} {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Build a form-encoded POST request with the session cookie.
fn form_req(cookie: &str, path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

// ---------------------------------------------------------------------------
// test 1: tokens_page_renders_and_creates
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// test 1b: token_create_sets_flash_cookie
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_create_sets_flash_cookie() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    let create_body = form_body(&[("name", "flash-test")]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/tokens", &create_body),
    )
    .await;

    // Token creation still renders the show-once secret inline (201) and
    // additionally sets the "Token created" flash cookie so the toast shows
    // on the next page load.
    assert_eq!(status_code(&resp), 201, "POST /tokens should return 201");
    assert!(
        resp.contains("Copy this secret"),
        "secret box should still appear"
    );
    assert!(
        resp.contains("id=\"toast-stack\""),
        "201 page should embed the toast container"
    );
    let cookie = parse_set_cookie(&resp).unwrap_or_default();
    assert!(
        cookie.starts_with("ddns_flash="),
        "Set-Cookie should contain ddns_flash=, got: {cookie}"
    );
    let encoded = cookie.strip_prefix("ddns_flash=").unwrap_or_default();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .unwrap_or_default();
    assert_eq!(
        String::from_utf8_lossy(&decoded),
        "success|Token created",
        "flash cookie should decode to success|Token created"
    );
}

// ---------------------------------------------------------------------------
// test 2: settings_page_renders
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settings_page_renders() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/settings"),
    )
    .await;
    assert_eq!(status_code(&resp), 200, "GET /settings should return 200");
    assert!(
        resp.contains("tunnel.example.com"),
        "settings page should contain domain"
    );
    assert!(
        resp.contains("Change Admin Password"),
        "settings page should contain password form"
    );
}

// ---------------------------------------------------------------------------
// test 2b: dashboard IP allowlist — allow + deny branches
// ---------------------------------------------------------------------------

/// The test broker binds 127.0.0.1, so the peer is always 127.0.0.1.
/// An empty allowlist allows all (all other tests rely on it); a non-empty
/// list must 403 non-matching peers (HTML for pages, plain for API routes).
/// The save handler refuses an allowlist that excludes the operator's own
/// peer IP (self-lockout guardrail); non-matching enforcement is exercised
/// in `dashboard_ip_allowlist_seeded_blocks_peer`.
#[tokio::test]
async fn dashboard_ip_allowlist_enforced() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    // Default (empty allowlist) → dashboard accessible.
    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(status_code(&resp), 200, "empty allowlist allows all");

    // Allow branch: allowlist the test peer → dashboard accessible.
    let body = form_body(&[("session_ttl_hours", "24"), ("ip_allowlist", "127.0.0.1")]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/security", &body),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        303,
        "allow save redirects, got:\n{resp}"
    );

    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(status_code(&resp), 200, "matching peer allowed");

    // Guardrail: saving an allowlist that excludes the operator's own peer IP
    // is refused inline (there is no UI path back once locked out), and
    // nothing is persisted.
    let body = form_body(&[("session_ttl_hours", "24"), ("ip_allowlist", "10.0.0.1")]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/security", &body),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        400,
        "excluding peer refused, got:\n{resp}"
    );
    assert!(
        resp.contains("would be locked out"),
        "inline lockout warning, got:\n{resp}"
    );

    // The refused save did not persist: the dashboard stays reachable.
    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(
        status_code(&resp),
        200,
        "refused save leaves dashboard accessible"
    );
}

/// Enforcement from a pre-seeded allowlist (e.g. configured out-of-band): the
/// UI guardrail prevents an operator from locking themselves out, so the 403
/// path can only be reached by seeding the settings store before startup.
#[tokio::test]
async fn dashboard_ip_allowlist_seeded_blocks_peer() {
    let (cert, key) = test_cert();
    let tokens = TokenStore::new();
    let store = ddns_server::settings::SettingsStore::open(&tokens);
    store
        .set(
            ddns_server::settings::KEY_DASHBOARD_IP_ALLOWLIST,
            r#"["10.0.0.1"]"#,
        )
        .unwrap();
    let (addr, broker) = start_broker(&cert, &key, tokens, 256, Duration::from_secs(5)).await;

    // Setup + login are public paths, so they succeed despite the allowlist.
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;
    let body = form_body(&[("password", "secret123")]);
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let login_resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let cookie = parse_set_cookie(&login_resp).expect("Set-Cookie after login");

    // Protected page → 403 with the message; API → plain 403.
    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(status_code(&resp), 403, "non-matching peer blocked");
    assert!(
        resp.contains("Your IP is not allowed to access the dashboard."),
        "page 403 carries the message, got:\n{resp}"
    );
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &api_req(&cookie, "GET", "/api/tokens", None),
    )
    .await;
    assert_eq!(status_code(&resp), 403, "API 403 plain");
    assert!(
        !resp.to_lowercase().contains("<html"),
        "API 403 is plain text, got:\n{resp}"
    );
    broker.stop().await;
}

// ---------------------------------------------------------------------------
// test 2c: security card saves + validates (bad line → inline error, nothing
// saved; good values → flash + persisted)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn security_settings_validate_and_save() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    // Bad allowlist line → 400 with an inline error naming the line.
    let body = form_body(&[
        ("session_ttl_hours", "2"),
        ("ip_allowlist", "127.0.0.1\nnot-an-ip"),
    ]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/security", &body),
    )
    .await;
    assert_eq!(status_code(&resp), 400, "bad line rejected, got:\n{resp}");
    assert!(
        resp.contains("Invalid allowlist entry on line 2"),
        "inline error names the line, got:\n{resp}"
    );
    // Nothing was saved: the 400 body still shows the default TTL (24) and an
    // empty allowlist textarea.
    assert!(
        resp.contains(r#"name="session_ttl_hours" min="1" value="24""#),
        "TTL unchanged on bad line, got:\n{resp}"
    );
    assert!(
        resp.contains(r#"<textarea id="ip_allowlist" name="ip_allowlist" rows="6"></textarea>"#),
        "allowlist empty on bad line, got:\n{resp}"
    );

    // Good values → 303 + flash + persisted.
    let body = form_body(&[("session_ttl_hours", "2"), ("ip_allowlist", "127.0.0.1")]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/security", &body),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        303,
        "valid save redirects, got:\n{resp}"
    );
    assert!(
        header_value(&resp, "set-cookie").is_some_and(|v| v.contains("ddns_flash")),
        "save sets a flash cookie, got:\n{resp}"
    );

    // The settings page now renders the persisted TTL + allowlist.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/settings"),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    assert!(resp.contains("value=\"2\""), "TTL persisted, got:\n{resp}");
    assert!(
        resp.contains("127.0.0.1"),
        "allowlist persisted, got:\n{resp}"
    );
}

// ---------------------------------------------------------------------------
// test 3: dashboard_kill_button_posts
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test 4: xss_escaped_in_pages
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test 5: unauthenticated_page_redirects
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_page_redirects() {
    let (addr, _broker, _cookie, cert) = setup_admin().await;

    // GET /tokens without cookie → 302 /login.
    let req = "GET /tokens HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n";
    let resp = http1(addr, &cert, "tunnel.example.com", req).await;
    assert_eq!(
        status_code(&resp),
        302,
        "unauthenticated /tokens should redirect"
    );
    let location = header_value(&resp, "location").unwrap_or_default();
    assert!(
        location.contains("/login"),
        "redirect should point to /login, got '{location}'"
    );

    // GET /settings without cookie → 302 /login.
    let req2 = "GET /settings HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n";
    let resp2 = http1(addr, &cert, "tunnel.example.com", req2).await;
    assert_eq!(
        status_code(&resp2),
        302,
        "unauthenticated /settings should redirect"
    );
    let location2 = header_value(&resp2, "location").unwrap_or_default();
    assert!(
        location2.contains("/login"),
        "redirect should point to /login, got '{location2}'"
    );
}

// ---------------------------------------------------------------------------
// test 6: faked tunnel Host must never reach operator routes (P0 regression:
// an unauthenticated client can trivially set Host: <slug>.<domain>; the
// tunnel-host passthrough must stay scoped to tunnel visitor traffic)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test 7: dashboard_html_is_well_formed (P1 regression — the dashboard
// template was missing `</style>`, so browsers swallowed the entire body
// as raw CSS text and rendered a blank dark page after login)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dashboard_html_is_well_formed() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(status_code(&resp), 200, "GET / should return 200");

    // Every <style> opened in <head> must be closed before </head>.
    let head = resp.split("</head>").next().expect("</head> present");
    assert_eq!(
        head.matches("<style>").count(),
        head.matches("</style>").count(),
        "each <style> in <head> must be closed before </head>; head:\n{head}"
    );

    // </head> must appear strictly before <body> so nothing leaks into CSS.
    let head_end = resp.find("</head>").expect("</head> present");
    let body_start = resp.find("<body>").expect("<body> present");
    assert!(head_end < body_start, "</head> must close before <body>");

    // Content must be present (sidebar + heading) so the page is not blank.
    assert!(
        resp.contains("Tunnel Dashboard"),
        "dashboard heading should render"
    );
    assert!(resp.contains("class=\"sidebar\""), "sidebar should render");
}

#[tokio::test]
async fn custom_host_visitor_gets_tunnel_not_dashboard() {
    let (cert, key) = test_cert();

    // Store-backed profile: token + apex + tunnel with a custom hostname.
    let ts = TokenStore::new();
    ts.insert("tok_custom".into(), common::test_record("t-custom", true))
        .await
        .unwrap();
    let dom = ddns_server::domain::DomainStore::open(&ts);
    dom.seed_from_config("tunnel.example.com");
    let apex = dom.active_apex().await.unwrap().unwrap();
    let tunnels = ddns_server::tunnel::TunnelStore::open(&ts, &dom);
    tunnels
        .create(&ddns_server::tunnel::NewTunnel {
            name: "custom".into(),
            token_id: "t-custom".into(),
            domain_id: apex.id.clone(),
            subdomain: None,
            custom_hostname: Some("app.example.com".into()),
            options: Default::default(),
            ports: String::new(),
        })
        .await
        .unwrap();

    let (addr, broker) = start_broker(&cert, &key, ts, 256, Duration::from_secs(5)).await;
    let (mut fc, _reply) = FakeClient::connect(addr, &cert, "tok_custom").await;
    let app = spawn_local_app().await;

    // Visitor GET / with Host: app.example.com → tunnel traffic, NOT the
    // operator dashboard (whose HTML contains "Tunnel Dashboard").
    let cert1 = cert.clone();
    let visitor = tokio::spawn(async move {
        http1(
            addr,
            &cert1,
            "127.0.0.1",
            "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n",
        )
        .await
    });

    // The tunnel must pick up the request (OPEN arrives within the timeout);
    // relay it to the local app and return its response to the visitor.
    let open = tokio::time::timeout(Duration::from_secs(5), fc.recv_open()).await;
    let (stream_id, meta) = match open {
        Ok(open) => open,
        Err(_) => {
            let visitor_resp = visitor.await.unwrap();
            panic!("custom-host visitor was not routed to the tunnel; got: {visitor_resp}");
        }
    };
    let head = meta.head.as_ref().unwrap().clone();
    let mut app_sock = tokio::net::TcpStream::connect(app.addr).await.unwrap();
    app_sock.write_all(&head).await.unwrap();
    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = app_sock.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
    }
    let idx = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let (rhead, rbody) = resp.split_at(idx);
    fc.send_open_ack(stream_id, Bytes::copy_from_slice(rhead))
        .await;
    fc.send_data(stream_id, Bytes::copy_from_slice(rbody)).await;
    fc.send_close(stream_id, CLOSE_OK).await;

    let visitor_resp = visitor.await.unwrap();
    assert_eq!(
        status_code(&visitor_resp),
        200,
        "custom-host visitor must reach the tunnel, got: {visitor_resp}"
    );
    assert!(
        !visitor_resp.contains("Tunnel Dashboard"),
        "custom-host visitor must never render the operator dashboard"
    );

    drop(fc);
    broker.stop().await;
}

#[tokio::test]
async fn pages_use_flat_dark_shell() {
    let (addr, _broker, cookie, cert) = setup_admin().await;
    for path in ["/", "/tokens", "/settings"] {
        let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, path)).await;
        assert_eq!(status_code(&resp), 200, "GET {path}");
        assert!(
            resp.contains("--sidebar-w"),
            "{path} must use the flat dark design system"
        );
        assert!(
            !resp.contains("linear-gradient") && !resp.contains("radial-gradient"),
            "{path} must not contain any CSS gradient declarations (flat design constraint)"
        );
        assert!(
            resp.contains("class=\"sidebar\""),
            "{path} must render the sidebar"
        );
        if path == "/" {
            assert!(
                resp.contains("data-island=\"dashboard\""),
                "dashboard mounts the island"
            );
            assert!(
                resp.contains("/_assets/wasm/ddns-web.js"),
                "dashboard includes the bundle script"
            );
            assert!(
                resp.contains("class=\"stats\""),
                "dashboard keeps the SSR fallback"
            );
        }
        assert_eq!(
            resp.matches("<style>").count(),
            1,
            "{path} exactly one style"
        );
        assert!(resp.contains("</style>"), "{path} style must close");
    }
    let login = http1(
        addr,
        &cert,
        "tunnel.example.com",
        "GET /login HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        login.contains("--sidebar-w"),
        "login page uses the flat dark shell too"
    );
}

// ---------------------------------------------------------------------------
// test: domains page CRUD flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn domains_page_crud_flows() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    // list shows the seeded apex (broker seeded from config.domain)
    let page = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/domains"),
    )
    .await;
    assert_eq!(status_code(&page), 200, "GET /domains → 200, got:\n{page}");
    assert!(page.contains("tunnel.example.com"), "seeded apex shown");
    assert!(page.contains("Add domain"), "add-domain form present");

    // create via form
    let body = form_body(&[("name", "ops.example.com"), ("kind", "apex")]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/domains", &body),
    )
    .await;
    assert_eq!(status_code(&resp), 303, "create redirects, got:\n{resp}");
    let page2 = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/domains"),
    )
    .await;
    assert!(
        page2.contains("ops.example.com"),
        "created domain listed, got:\n{page2}"
    );

    // delete a domain that is not referenced → 303 and gone
    let del_body = form_body(&[]);
    let del = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/domains/does-not-exist/delete", &del_body),
    )
    .await;
    assert_eq!(status_code(&del), 303, "delete redirects, got:\n{del}");
}

// ---------------------------------------------------------------------------
// test: tunnels page create / preview / edit
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test: tokens page MAX BYTES slider
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test: plans page renders name + full limits with hints (standard labels)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test: plans page escapes an operator-editable plan name
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// removed: client detail page tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settings_instance_card_renders_and_persists() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    // Fresh instance: card renders with empty-state hints.
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/settings"),
    )
    .await;
    assert_eq!(status_code(&resp), 200, "GET /settings → 200, got:\n{resp}");
    for needle in [
        "<h2>Instance</h2>",
        "name=\"instance_name\"",
        "name=\"support_url\"",
        "Support link hidden until set",
        "IP allowlist disabled — all IPs allowed",
        "Webhooks disabled until a URL is set",
    ] {
        assert!(resp.contains(needle), "missing {needle} in settings page");
    }

    // Reject a non-http(s) support URL.
    let body = form_body(&[
        ("instance_name", "My+Tunnels"),
        ("support_url", "ftp://example.com"),
    ]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/instance", &body),
    )
    .await;
    assert_eq!(
        status_code(&resp),
        400,
        "bad support URL rejected, got:\n{resp}"
    );

    // Save name + URL.
    let body = form_body(&[
        ("instance_name", "My+Tunnels"),
        ("support_url", "https://support.example.com/help"),
    ]);
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &form_req(&cookie, "/settings/instance", &body),
    )
    .await;
    assert_eq!(status_code(&resp), 303, "save redirects, got:\n{resp}");
    assert!(
        header_value(&resp, "set-cookie").is_some_and(|v| v.contains("ddns_flash")),
        "save sets a flash cookie, got:\n{resp}"
    );

    // Persisted values re-render (escaped).
    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/settings"),
    )
    .await;
    assert_eq!(status_code(&resp), 200);
    assert!(
        resp.contains("value=\"My Tunnels\""),
        "instance name persisted:\n{resp}"
    );
    assert!(
        resp.contains("value=\"https://support.example.com/help\""),
        "support URL persisted:\n{resp}"
    );
    assert!(
        !resp.contains("Support link hidden until set"),
        "support hint cleared once URL set:\n{resp}"
    );
}

#[tokio::test]
async fn settings_page_card_order_and_balanced_forms() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    let resp = http1(
        addr,
        &cert,
        "tunnel.example.com",
        &page_req(&cookie, "/settings"),
    )
    .await;
    assert_eq!(status_code(&resp), 200, "GET /settings → 200, got:\n{resp}");

    // Balanced form tags (no nested-form regression).
    let opens = resp.matches("<form ").count();
    let closes = resp.matches("</form>").count();
    assert_eq!(opens, closes, "balanced form tags, got:\n{resp}");
    assert!(opens >= 5, "expected several forms, got {opens}:\n{resp}");

    // Cards render in the brief's order.
    let order = [
        "<h2>Instance</h2>",
        "<h2>Security</h2>",
        "<h2>Two-Factor Authentication</h2>",
        "<h2>Alerts</h2>",
        "<h2>Token Defaults</h2>",
        "<h2>Configuration</h2>",
        "<h2>TLS Certificate</h2>",
        "<h2>Change Admin Password</h2>",
    ];
    let mut last = 0;
    for heading in order {
        let idx = resp
            .find(heading)
            .unwrap_or_else(|| panic!("missing {heading}:\n{resp}"));
        assert!(idx >= last, "card order broken at {heading}:\n{resp}");
        last = idx;
    }
}

// ---------------------------------------------------------------------------
// test: defaults card renders current values; POST saves + persists
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// test: admin credit route — token balance card + valid/invalid POST
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// test: client delete — danger zone on the detail page, Delete on the list,
// POST removes the account + its owned rows, re-delete 404s
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// T2: security headers + CSRF Origin check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn security_headers_on_pages_dev_has_no_hsts() {
    let (addr, _broker, cookie, cert) = setup_admin().await;

    let resp = http1(addr, &cert, "tunnel.example.com", &page_req(&cookie, "/")).await;
    assert_eq!(status_code(&resp), 200);

    assert_eq!(
        header_value(&resp, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "nosniff header:\n{resp}"
    );
    assert_eq!(
        header_value(&resp, "referrer-policy").as_deref(),
        Some("same-origin"),
        "referrer-policy header:\n{resp}"
    );
    let csp = header_value(&resp, "content-security-policy").expect("CSP header present");
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP frame-ancestors:\n{csp}"
    );
    assert!(csp.contains("base-uri 'none'"), "CSP base-uri:\n{csp}");

    // Dev broker uses a self-signed cert → HSTS must be absent.
    assert_eq!(
        header_value(&resp, "strict-transport-security"),
        None,
        "dev broker must not set HSTS:\n{resp}"
    );
}

#[tokio::test]
async fn security_headers_non_dev_sets_hsts() {
    let (cert, key) = test_cert();
    let mut config = broker_config(
        &cert,
        &key,
        TokenStore::new(),
        256,
        std::time::Duration::from_secs(5),
    );
    config.dev = false;
    let broker = ddns_server::Broker::start(config).await.unwrap();
    let addr = broker.addr;

    let req = "GET /login HTTP/1.1\r\nHost: tunnel.example.com\r\nConnection: close\r\n\r\n";
    let resp = http1(addr, &cert, "tunnel.example.com", req).await;
    assert_eq!(
        header_value(&resp, "strict-transport-security").as_deref(),
        Some("max-age=31536000"),
        "non-dev broker must set HSTS:\n{resp}"
    );
}

#[tokio::test]
async fn csrf_origin_check_on_state_changing_methods() {
    let (cert, key) = test_cert();
    let (addr, _broker) = start_broker(
        &cert,
        &key,
        TokenStore::new(),
        256,
        std::time::Duration::from_secs(5),
    )
    .await;

    // Create the operator so POST /login is reachable (not redirected to /setup).
    let body = form_body(&[("password", "secret123"), ("confirm", "secret123")]);
    let req = format!(
        "POST /setup HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    http1(addr, &cert, "tunnel.example.com", &req).await;

    let login_body = form_body(&[("password", "secret123")]);

    // Mismatched Origin → 403.
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nOrigin: https://evil.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_body}",
        login_body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert_eq!(status_code(&resp), 403, "foreign Origin must 403:\n{resp}");

    // Matching Origin (https — the broker is TLS-only even in dev, so a
    // same-origin form post carries an https:// origin) → normal 303.
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nOrigin: https://tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_body}",
        login_body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert_eq!(
        status_code(&resp),
        303,
        "matching Origin must pass:\n{resp}"
    );

    // No Origin → normal (curl/API/raw-HTTP-harness/webhook clients).
    let req = format!(
        "POST /login HTTP/1.1\r\nHost: tunnel.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_body}",
        login_body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    assert_eq!(status_code(&resp), 303, "no Origin must pass:\n{resp}");
}

#[tokio::test]
async fn csrf_origin_check_guards_put_patch_delete() {
    let (cert, key) = test_cert();
    let (addr, _broker) = start_broker(
        &cert,
        &key,
        TokenStore::new(),
        256,
        std::time::Duration::from_secs(5),
    )
    .await;

    // PUT /api/tunnels/{id} is a real operator route; PATCH has no matching
    // route but still must be gated by the Origin check (which runs before
    // routing). Without a session these all reach `require_session`'s 401,
    // so "passes the origin check" = NOT 403.
    for method in ["PUT", "PATCH", "DELETE"] {
        let cross = format!(
            "{method} /api/tunnels/t1 HTTP/1.1\r\nHost: tunnel.example.com\r\nOrigin: https://evil.example\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let resp = http1(addr, &cert, "tunnel.example.com", &cross).await;
        assert_eq!(
            status_code(&resp),
            403,
            "cross-origin {method} must 403:\n{resp}"
        );

        let same = format!(
            "{method} /api/tunnels/t1 HTTP/1.1\r\nHost: tunnel.example.com\r\nOrigin: https://tunnel.example.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let resp = http1(addr, &cert, "tunnel.example.com", &same).await;
        assert_ne!(
            status_code(&resp),
            403,
            "same-origin {method} must pass the origin check:\n{resp}"
        );
    }
}
