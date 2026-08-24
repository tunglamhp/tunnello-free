//! Task 4 acceptance: HTTP round-trip through the broker.

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{FakeClient, client_tls, spawn_local_app, start_broker, test_cert};
use ddns_proto::frame::CLOSE_OK;
use ddns_proto::{Opcode, TokenLimits};
use ddns_server::TokenStore;
use http::header::HOST;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn tokens() -> TokenStore {
    let store = TokenStore::new();
    store
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    store
}

/// HTTPS client (HTTP/1.1) that trusts the broker cert; connects to the
/// ephemeral listener, so the slug lives only in the Host header.
fn https_client(
    cert: &[u8],
) -> Client<hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, String>
{
    let cfg = client_tls(cert);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

async fn get(
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        String,
    >,
    addr: std::net::SocketAddr,
    slug: &str,
    path: &str,
) -> hyper::Response<hyper::body::Incoming> {
    client
        .request(
            http::Request::builder()
                .uri(format!("https://127.0.0.1:{}{path}", addr.port()))
                .header(HOST, format!("{slug}.tunnel.example.com"))
                .body(String::new())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Relay an OPEN stream to the local app and send its response back to the
/// broker. Returns the response body bytes for assertion.
async fn relay_to_app(
    fc: &mut FakeClient,
    stream_id: u32,
    head: &[u8],
    body: &[u8],
    app: &common::LocalApp,
) -> Vec<u8> {
    let mut app_sock = TcpStream::connect(app.addr).await.unwrap();
    app_sock.write_all(head).await.unwrap();
    app_sock.write_all(body).await.unwrap();
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
    rbody.to_vec()
}

#[tokio::test]
async fn http_get_roundtrips_through_the_tunnel() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let app = spawn_local_app().await;
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let get_fut = tokio::spawn(async move {
        let c = https_client(&cert1);
        get(&c, addr, &slug1, "/alpha?q=1").await
    });

    // Broker forwards the request head to the client:
    let (stream_id, meta) = fc.recv_open().await;
    assert_eq!(meta.kind, ddns_proto::StreamKind::Http);
    let head = String::from_utf8_lossy(meta.head.as_ref().unwrap()).to_string();
    assert!(head.starts_with("GET /alpha?q=1 HTTP/1.1"), "head: {head}");
    let lower = head.to_lowercase();
    assert!(lower.contains("host: "), "head: {head}");
    assert!(lower.contains("x-forwarded-for: 127.0.0.1"), "head: {head}");

    // GET has no body — relay head only:
    let rbody = relay_to_app(&mut fc, stream_id, meta.head.as_ref().unwrap(), b"", &app).await;

    let res = get_fut.await.unwrap();
    assert_eq!(res.status(), 200);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let echoed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    assert_eq!(echoed, parsed);
    assert_eq!(echoed["path"], "/alpha?q=1");
    assert_eq!(echoed["host"], format!("{slug}.tunnel.example.com"));
    broker.stop().await;
}

#[tokio::test]
async fn http_post_forwards_the_body() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let app = spawn_local_app().await;
    let body = "hello tunnel body";
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let body1 = body.to_string();
    let post_fut = tokio::spawn(async move {
        let c = https_client(&cert1);
        c.request(
            http::Request::builder()
                .uri(format!("https://127.0.0.1:{}/submit", addr.port()))
                .header(HOST, format!("{slug1}.tunnel.example.com"))
                .header(http::header::CONTENT_TYPE, "text/plain")
                .method(http::Method::POST)
                .body(body1)
                .unwrap(),
        )
        .await
    });

    let (stream_id, meta) = fc.recv_open().await;
    let head = String::from_utf8_lossy(meta.head.as_ref().unwrap()).to_string();
    assert!(head.starts_with("POST /submit HTTP/1.1"), "head: {head}");

    // Gather the request body frames (content-length knows when we're done):
    let mut req_body = Vec::new();
    while req_body.len() < body.len() {
        let f = fc.recv_frame().await;
        assert_eq!(f.opcode, Opcode::Data, "got {f:?}");
        req_body.extend_from_slice(&f.payload);
    }
    assert_eq!(req_body, body.as_bytes());

    let rbody = relay_to_app(
        &mut fc,
        stream_id,
        meta.head.as_ref().unwrap(),
        &req_body,
        &app,
    )
    .await;

    let res = post_fut.await.unwrap().unwrap();
    assert_eq!(res.status(), 200);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let echoed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    assert_eq!(echoed, parsed);
    assert_eq!(echoed["path"], "/submit");
    assert_eq!(echoed["body_len"], body.len());
    broker.stop().await;
}

#[tokio::test]
async fn large_response_streams_without_deadlock() {
    // Regression: a response body larger than the broker's per-stream frame
    // queue must stream to the visitor. The old code awaited the client->visitor
    // forward pump before returning the response, so the pump's bounded channel
    // filled up and the exchange deadlocked once the client sent > 8 DATA frames.
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let get_fut = tokio::spawn(async move {
        let c = https_client(&cert1);
        get(&c, addr, &slug1, "/big").await
    });

    let (stream_id, meta) = fc.recv_open().await;
    assert_eq!(meta.kind, ddns_proto::StreamKind::Http);

    // 16 chunks of 16 KiB = 256 KiB response, well beyond any 8-frame queue.
    let chunk = vec![0x7Au8; 16 * 1024];
    let total = chunk.len() * 16;
    let rhead = format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n");
    fc.send_open_ack(stream_id, Bytes::from(rhead)).await;
    for _ in 0..16 {
        fc.send_data(stream_id, Bytes::copy_from_slice(&chunk))
            .await;
    }
    fc.send_close(stream_id, CLOSE_OK).await;

    let res = tokio::time::timeout(Duration::from_secs(10), get_fut)
        .await
        .expect("large response must not deadlock")
        .unwrap();
    assert_eq!(res.status(), 200);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body_bytes.len(), total, "response body must be complete");
    assert!(body_bytes.iter().all(|&b| b == 0x7A));
    broker.stop().await;
}

#[tokio::test]
async fn unknown_slug_gets_404() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let client = https_client(&cert);
    let res = client
        .request(
            http::Request::builder()
                .uri(format!("https://127.0.0.1:{}/x", addr.port()))
                .header(HOST, "nope.tunnel.example.com")
                .body(String::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    broker.stop().await;
}

#[tokio::test]
async fn max_streams_rejects_extra_requests_with_503() {
    let (cert, key) = test_cert();
    let store = TokenStore::new();
    store
        .insert(
            "tok_test".into(),
            common::test_record_with_limits(
                "t-test",
                TokenLimits {
                    max_streams: 1,
                    ..TokenLimits::default()
                },
            ),
        )
        .await
        .unwrap();
    let (addr, broker) = start_broker(&cert, &key, store, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);

    // First request: stream stays open (client never answers).
    // Spawn with owned slug so it outlives the test scope.
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let first = tokio::spawn(async move {
        let c = https_client(&cert1);
        get(&c, addr, &slug1, "/one").await
    });
    let (stream_id, _meta) = fc.recv_open().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second request: max_streams=1 → 503 without touching the client.
    let client = https_client(&cert);
    let res = get(&client, addr, &slug, "/two").await;
    assert_eq!(res.status(), 503);

    // Close the first stream → slot frees → third request works.
    fc.send_close(stream_id, CLOSE_OK).await;
    let slug3 = slug.clone();
    let cert3 = cert.clone();
    let third = tokio::spawn(async move {
        let c = https_client(&cert3);
        get(&c, addr, &slug3, "/three").await
    });
    let (sid2, meta2) = fc.recv_open().await;
    let app = spawn_local_app().await;
    let rbody = relay_to_app(&mut fc, sid2, meta2.head.as_ref().unwrap(), b"", &app).await;
    let res = third.await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(!rbody.is_empty());

    first.abort();
    broker.stop().await;
}

#[tokio::test]
async fn tunnel_applies_basic_auth_from_session_options() {
    let (cert, key) = test_cert();

    // Store-backed profile: token + apex + tunnel with basic_auth options,
    // so the registered session carries the options into the bridge.
    let ts = TokenStore::new();
    ts.insert("tok_auth".into(), common::test_record("t-auth", true))
        .await
        .unwrap();
    let dom = ddns_server::domain::DomainStore::open(&ts);
    dom.seed_from_config("tunnel.example.com");
    let apex = dom.active_apex().await.unwrap().unwrap();
    let tunnels = ddns_server::tunnel::TunnelStore::open(&ts, &dom);
    tunnels
        .create(&ddns_server::tunnel::NewTunnel {
            name: "auth".into(),
            token_id: "t-auth".into(),
            domain_id: apex.id.clone(),
            subdomain: Some("my-fixed".into()),
            custom_hostname: None,
            options: ddns_server::tunnel::HttpOptions {
                basic_auth: Some(("u".into(), "p".into())),
                ..Default::default()
            },
            ports: String::new(),
        })
        .await
        .unwrap();

    let (addr, broker) = start_broker(&cert, &key, ts, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_auth").await;
    let slug = FakeClient::slug(&reply);
    assert_eq!(slug, "my-fixed", "profile slug must be used");
    let app = spawn_local_app().await;

    // Visitor WITHOUT credentials → 401 + WWW-Authenticate.
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let unauth = tokio::spawn(async move {
        let c = https_client(&cert1);
        get(&c, addr, &slug1, "/secret").await
    });
    let res = unauth.await.unwrap();
    assert_eq!(
        res.status(),
        hyper::StatusCode::UNAUTHORIZED,
        "missing basic-auth credentials must be rejected before forwarding"
    );
    let www = res
        .headers()
        .get(http::header::WWW_AUTHENTICATE)
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        www.contains("Basic"),
        "WWW-Authenticate must advertise Basic: {www}"
    );

    // Visitor WITH valid credentials → forwarded to the local service → 200.
    let slug2 = slug.clone();
    let cert2 = cert.clone();
    let authed = tokio::spawn(async move {
        let c = https_client(&cert2);
        c.request(
            http::Request::builder()
                .uri(format!("https://127.0.0.1:{}/secret", addr.port()))
                .header(HOST, format!("{slug2}.tunnel.example.com"))
                .header(http::header::AUTHORIZATION, "Basic dTpw") // base64("u:p")
                .body(String::new())
                .unwrap(),
        )
        .await
        .unwrap()
    });
    let (stream_id, meta) = fc.recv_open().await;
    let head = String::from_utf8_lossy(meta.head.as_ref().unwrap()).to_string();
    assert!(head.starts_with("GET /secret HTTP/1.1"), "head: {head}");
    let rbody = relay_to_app(&mut fc, stream_id, meta.head.as_ref().unwrap(), b"", &app).await;
    let res = authed.await.unwrap();
    assert_eq!(res.status(), 200);
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let echoed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    assert_eq!(echoed, parsed);
    assert_eq!(echoed["path"], "/secret");

    drop(fc);
    broker.stop().await;
}

#[tokio::test]
async fn tunnel_traffic_skips_broker_csp_and_origin_check() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let app = spawn_local_app().await;
    let body = "cross-origin post";
    let slug1 = slug.clone();
    let cert1 = cert.clone();
    let body1 = body.to_string();
    // Cross-site browser POST to the customer's own site: the Origin differs
    // from the tunnel Host, which the broker's CSRF check would otherwise 403.
    let post_fut = tokio::spawn(async move {
        let c = https_client(&cert1);
        c.request(
            http::Request::builder()
                .uri(format!("https://127.0.0.1:{}/submit", addr.port()))
                .header(HOST, format!("{slug1}.tunnel.example.com"))
                .header(http::header::ORIGIN, "https://customer.example.com")
                .header(http::header::CONTENT_TYPE, "text/plain")
                .method(http::Method::POST)
                .body(body1)
                .unwrap(),
        )
        .await
    });

    let (stream_id, meta) = fc.recv_open().await;
    assert_eq!(meta.kind, ddns_proto::StreamKind::Http);
    let mut req_body = Vec::new();
    while req_body.len() < body.len() {
        let f = fc.recv_frame().await;
        assert_eq!(f.opcode, Opcode::Data, "got {f:?}");
        req_body.extend_from_slice(&f.payload);
    }
    let rbody = relay_to_app(
        &mut fc,
        stream_id,
        meta.head.as_ref().unwrap(),
        &req_body,
        &app,
    )
    .await;

    let res = post_fut.await.unwrap().unwrap();
    assert_eq!(
        res.status(),
        hyper::StatusCode::OK,
        "cross-origin POST through the tunnel must not be 403'd"
    );
    assert!(
        !res.headers().contains_key("content-security-policy"),
        "tunneled response must not carry the broker CSP: {:?}",
        res.headers()
    );
    let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
    let echoed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&rbody).unwrap();
    assert_eq!(echoed, parsed);
    assert_eq!(echoed["path"], "/submit");
    broker.stop().await;
}
