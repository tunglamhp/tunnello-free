//! Task 7 acceptance: the browser-visible surface the demo checks.
//!
//! Mirrors the two P2P assertions in `demo/demo.ps1`:
//!   1. `GET /` with `Accept: text/html` serves the connector page (it
//!      registers `__tunnello/sw.js`).
//!   2. `GET /` with `Accept: text/html` + `X-Tunnello-Relay: 1` bypasses the
//!      connector page and reaches the local app (the "echo" marker).
//!
//! plus the Service Worker route the connector page registers.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use common::{FakeClient, client_tls, start_broker, test_cert};
use ddns_proto::frame::CLOSE_OK;
use ddns_server::TokenStore;
use http::header::HOST;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    String,
>;

async fn tokens() -> TokenStore {
    let store = TokenStore::new();
    store
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    store
}

fn https_client(cert: &[u8]) -> HttpsClient {
    let cfg = client_tls(cert);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cfg)
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// GET a path with `Host: <slug>.tunnel.example.com`, an `Accept` header, and
/// an optional extra header (the relay escape hatch).
async fn get(
    client: &HttpsClient,
    addr: SocketAddr,
    slug: &str,
    path: &str,
    accept: &str,
    extra: Option<(&str, &str)>,
) -> hyper::Response<hyper::body::Incoming> {
    let mut builder = http::Request::builder()
        .uri(format!("https://127.0.0.1:{}{path}", addr.port()))
        .header(HOST, format!("{slug}.tunnel.example.com"))
        .header("accept", accept);
    if let Some((k, v)) = extra {
        builder = builder.header(k, v);
    }
    client
        .request(builder.body(String::new()).unwrap())
        .await
        .unwrap()
}

/// Answer the broker's OPEN with a canned HTTP response (the demo's echo app
/// answers `/` with a body containing "echo"). Proves the relay path forwards
/// the client's response verbatim.
async fn relay_canned(fc: &mut FakeClient, stream_id: u32) {
    fc.send_open_ack(
        stream_id,
        Bytes::from_static(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 4\r\n\r\n",
        ),
    )
    .await;
    fc.send_data(stream_id, Bytes::from_static(b"echo")).await;
    fc.send_close(stream_id, CLOSE_OK).await;
}

#[tokio::test]
async fn connector_page_served_for_browser_navigation() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);

    let c = https_client(&cert);
    let res = get(&c, addr, &slug, "/", "text/html", None).await;
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(
        text.contains("__tunnello/sw.js"),
        "connector page must register the Service Worker"
    );

    drop(fc);
    broker.stop().await;
}

#[tokio::test]
async fn relay_header_reaches_the_app_and_skips_the_connector_page() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);

    // Issue the relay request concurrently with answering the broker's OPEN.
    let c = https_client(&cert);
    let slug1 = slug.clone();
    let get_fut = tokio::spawn(async move {
        get(
            &c,
            addr,
            &slug1,
            "/",
            "text/html",
            Some(("X-Tunnello-Relay", "1")),
        )
        .await
    });

    let (stream_id, meta) = fc.recv_open().await;
    let head = meta
        .head
        .expect("relay OPEN must carry an HTTP request head");
    let head_lower = String::from_utf8_lossy(&head).to_lowercase();
    assert!(
        !head_lower.contains("x-tunnello-relay"),
        "relay control header must be stripped before the local app: {head_lower}"
    );

    relay_canned(&mut fc, stream_id).await;

    let res = get_fut.await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(
        text.contains("echo"),
        "relay must reach the app (echo marker)"
    );
    assert!(
        !text.contains("__tunnello/sw.js"),
        "relay header must bypass the connector page"
    );

    broker.stop().await;
}

#[tokio::test]
async fn service_worker_served_with_js_headers() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;

    let c = https_client(&cert);
    let res = c
        .request(
            http::Request::builder()
                .uri(format!(
                    "https://127.0.0.1:{}/__tunnello/sw.js",
                    addr.port()
                ))
                .header(HOST, "anything.tunnel.example.com")
                .body(String::new())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/javascript");
    assert_eq!(res.headers()["service-worker-allowed"], "/");

    broker.stop().await;
}
