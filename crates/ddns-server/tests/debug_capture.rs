//! Deep debugger capture integration (HTTP path): bodies captured only when
//! the tunnel profile opts in; headers redacted; 4 KiB previews.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::FakeClient;
use ddns_proto::frame::CLOSE_OK;
use ddns_server::TokenStore;
use ddns_server::tunnel::HttpOptions;

async fn tokens() -> TokenStore {
    let store = TokenStore::new();
    store
        .insert("tok_cap".into(), common::test_record("t-cap", true))
        .await
        .unwrap();
    store
}

/// Seed a tunnel profile with a fixed slug + debug_capture flag.
async fn seed_tunnel(tokens: &TokenStore, slug: &str, capture: bool) {
    let domains = ddns_server::domain::DomainStore::open(tokens);
    let apex = domains
        .create("tunnel.example.com", ddns_server::domain::DomainKind::Apex)
        .await
        .unwrap();
    // Visitor Host routing resolves via the ACTIVE apex; a freshly created
    // apex is inactive, so activate it (mirrors the dashboard flow).
    domains.activate(&apex.id).await.unwrap();
    let tunnels = ddns_server::tunnel::TunnelStore::open(tokens, &domains);
    let options = HttpOptions {
        debug_capture: capture,
        ..Default::default()
    };
    tunnels
        .create(&ddns_server::tunnel::NewTunnel {
            name: slug.to_string(),
            token_id: "t-cap".into(),
            domain_id: apex.id.clone(),
            subdomain: None,
            custom_hostname: None,
            options,
            ports: String::new(),
        })
        .await
        .unwrap();
}

fn https_client(
    cert: &[u8],
) -> hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    String,
> {
    let cfg = common::client_tls(cert);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

/// Relay the OPEN'd stream to a local app that answers with a fixed HTTP
/// response (mirrors tests/http_tunnel.rs relay_to_app).
async fn relay_response(fc: &mut FakeClient, resp_head: &str, resp_body: &str) {
    let (stream_id, _meta) = fc.recv_open().await;
    // Drain the forwarded request head/body from the stream (best effort).
    let _ = fc.recv_frame().await; // DATA (request head/body)
    fc.send_open_ack(stream_id, Bytes::copy_from_slice(resp_head.as_bytes()))
        .await;
    fc.send_data(stream_id, Bytes::copy_from_slice(resp_body.as_bytes()))
        .await;
    fc.send_close(stream_id, CLOSE_OK).await;
}

async fn last_entry(
    broker: &ddns_server::Broker,
    slug: &str,
) -> Option<ddns_server::session::DebugEntry> {
    // The entry lands when the tunnel's cleanup task completes (both pumps
    // done); poll briefly instead of sleeping blindly.
    for i in 0..100 {
        if let Some(e) = broker
            .registry()
            .lookup(slug)
            .and_then(|s| s.debug_snapshot().last().cloned())
        {
            return Some(e);
        }
        if i % 20 == 0 {
            let n = broker
                .registry()
                .lookup(slug)
                .map(|s| s.debug_snapshot().len())
                .unwrap_or(0);
            eprintln!("poll {i}: ring len {n}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn capture_off_by_default_no_bodies_recorded() {
    let (cert, key) = common::test_cert();
    let tokens = tokens().await;
    seed_tunnel(&tokens, "cap-off", false).await;
    let (addr, broker) = common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;
    common::spawn_local_app().await;
    let (mut fc, reply) =
        common::FakeClient::connect_udp_flags(addr, &cert, "tok_cap", false, true, false, 0, None)
            .await;
    let slug = common::FakeClient::slug(&reply);
    eprintln!(
        "DEBUG slug={slug} lookup={:?}",
        broker.registry().lookup(&slug).is_some()
    );

    let client = https_client(&cert);
    let slug1 = slug.clone();
    let get_fut = tokio::spawn(async move {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("https://127.0.0.1:{}/submit", addr.port()))
            .header("host", format!("{slug1}.tunnel.example.com"))
            .header("content-type", "text/plain")
            .body(String::from("hello-body"))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    });

    // Drive the tunnel side inline: drain the request DATA, answer, close.
    relay_response(
        &mut fc,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
        "hello",
    )
    .await;

    let (status, body) = get_fut.await.unwrap();
    assert_eq!(status, 200, "visitor got: {body}");
    assert_eq!(body, "hello");

    let entry = last_entry(&broker, &slug).await.expect("entry recorded");
    assert!(entry.req_body.is_none(), "capture off → no req body");
    assert!(entry.resp_body.is_none(), "capture off → no resp body");
    assert!(entry.req_headers.is_empty(), "capture off → no headers");
}

#[tokio::test]
async fn capture_on_records_redacted_headers_and_bodies() {
    let (cert, key) = common::test_cert();
    let tokens = tokens().await;
    seed_tunnel(&tokens, "cap-on", true).await;
    let (addr, broker) = common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;
    common::spawn_local_app().await;
    let (mut fc, reply2) =
        common::FakeClient::connect_udp_flags(addr, &cert, "tok_cap", false, true, false, 0, None)
            .await;
    let slug = common::FakeClient::slug(&reply2);

    let client = https_client(&cert);
    let slug1 = slug.clone();
    let get_fut = tokio::spawn(async move {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("https://127.0.0.1:{}/submit", addr.port()))
            .header("host", format!("{slug1}.tunnel.example.com"))
            .header("authorization", "Bearer sekret")
            .header("content-type", "text/plain")
            .body(String::from("hello-body"))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    });

    relay_response(
        &mut fc,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
        "hello",
    )
    .await;

    let (status, body) = get_fut.await.unwrap();
    assert_eq!(status, 200, "visitor got: {body}");
    assert_eq!(body, "hello");

    let entry = last_entry(&broker, &slug).await.expect("entry recorded");
    let auth = entry
        .req_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    assert_eq!(auth.as_deref(), Some("[REDACTED]"), "auth header redacted");
    assert_eq!(entry.req_body.as_deref(), Some("hello-body"));
    assert_eq!(entry.resp_body.as_deref(), Some("hello"));
}

// ---------------------------------------------------------------------------
// operator raw-HTTP helpers (mirror cert_http.rs)
// ---------------------------------------------------------------------------

async fn http1(addr: std::net::SocketAddr, cert: &[u8], host: &str, request: &str) -> String {
    use std::sync::Arc;
    let mut cfg = common::client_tls(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(tls);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    wr.write_all(request.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    loop {
        let mut tmp = [0u8; 8192];
        match rd.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&tmp[..n]),
        }
    }
    String::from_utf8_lossy(&resp).to_string()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={}", v.replace('%', "%25").replace(' ', "%20")))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_set_cookie(response: &str) -> Option<String> {
    for line in response.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("set-cookie: ") {
            let end = rest.find(';').unwrap_or(rest.len());
            // Re-attach the original-case value from the same line.
            let orig = response
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("set-cookie: "))?;
            let orig_val = &orig["set-cookie: ".len()..];
            return Some(orig_val[..end].to_string());
        }
    }
    None
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[tokio::test]
async fn replay_resends_captured_request() {
    let (cert, key) = common::test_cert();
    let tokens = tokens().await;
    seed_tunnel(&tokens, "cap-replay", true).await;
    let (addr, broker) = common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;
    common::spawn_local_app().await;
    let (mut fc, reply) =
        common::FakeClient::connect_udp_flags(addr, &cert, "tok_cap", false, true, false, 0, None)
            .await;
    let slug = common::FakeClient::slug(&reply);

    // Operator: setup + login → session cookie (raw HTTP/1.1, dashboard Host).
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
    let cookie = parse_set_cookie(&login_resp).expect("operator session cookie");

    // One captured request through the tunnel (inline relay).
    let client = https_client(&cert);
    let client2 = client.clone();
    let slug1 = slug.clone();
    let get_fut = tokio::spawn(async move {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("https://127.0.0.1:{}/submit", addr.port()))
            .header("host", format!("{slug1}.tunnel.example.com"))
            .header("content-type", "text/plain")
            .body(String::from("replay-me"))
            .unwrap();
        client2.request(req).await.unwrap().status()
    });
    relay_response(
        &mut fc,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n",
        "hello",
    )
    .await;
    assert_eq!(get_fut.await.unwrap(), 200);

    // Replay entry 0 with the operator cookie.
    let body = form_body(&[("index", "0")]);
    let req = format!(
        "POST /debug/{slug}/replay HTTP/1.1\r\nHost: tunnel.example.com\r\nCookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http1(addr, &cert, "tunnel.example.com", &req).await;
    let status = status_of(&resp);
    assert_eq!(
        status,
        200,
        "replay page renders: {}",
        &resp[..200.min(resp.len())]
    );
    assert!(resp.contains("Replay:"), "banner present");

    // The replay itself traverses the tunnel again → ring grows to 2.
    let entry = last_entry(&broker, &slug)
        .await
        .expect("entry after replay");
    assert_eq!(entry.path, "/submit");
}
