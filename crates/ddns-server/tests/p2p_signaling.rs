//! Task 5 acceptance: P2P signaling relay + connector page + SW fallback.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::{FakeClient, client_tls, spawn_local_app, start_broker, test_cert};
use ddns_proto::Control;
use ddns_proto::frame::CLOSE_OK;
use ddns_proto::ticket::verify_ticket;
use ddns_server::TokenStore;
use futures_util::{SinkExt, StreamExt};
use http::header::HOST;
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

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

/// Relay an OPEN stream to the local app and send its response back to the
/// broker (mirrors `http_tunnel.rs`).
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

async fn connect_signal_ws(
    addr: SocketAddr,
    cert: &[u8],
) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
    let cfg = Arc::new(client_tls(cert));
    let connector = tokio_tungstenite::Connector::Rustls(cfg);
    let url = format!("wss://127.0.0.1:{}/__p2p/signal", addr.port());
    let (ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
            .await
            .unwrap();
    ws
}

async fn send_json(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>, v: serde_json::Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

async fn recv_json(ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> serde_json::Value {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).unwrap(),
            Some(Ok(_)) => continue,
            _ => panic!("ws closed while waiting for JSON"),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn connector_page_served_at_tunnel_root_and_relay_header_bypasses() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);
    let app = spawn_local_app().await;

    // No relay header + Accept: text/html → the connector page (served by the
    // broker directly; no OPEN reaches the client).
    let c = https_client(&cert);
    let res = get(&c, addr, &slug, "/", "text/html", None).await;
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(
        text.contains("__tunnello/sw.js"),
        "connector page must register the SW"
    );

    // Relay header → bypass the connector page and reach the local app.
    let c2 = https_client(&cert);
    let slug1 = slug.clone();
    let get_fut = tokio::spawn(async move {
        get(
            &c2,
            addr,
            &slug1,
            "/",
            "text/html",
            Some(("X-Tunnello-Relay", "1")),
        )
        .await
    });
    let (stream_id, meta) = fc.recv_open().await;
    let _rbody = relay_to_app(&mut fc, stream_id, meta.head.as_ref().unwrap(), b"", &app).await;

    let res = get_fut.await.unwrap();
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(
        !text.contains("__tunnello/sw.js"),
        "relay header must bypass the connector page"
    );
    assert!(
        text.contains("\"path\":\"/\""),
        "relay must reach the local app"
    );
    broker.stop().await;
}

#[tokio::test]
async fn signaling_ws_issues_ticket_and_relays_offer_to_client() {
    let (cert, key) = test_cert();
    let (addr, broker) =
        start_broker(&cert, &key, tokens().await, 256, Duration::from_secs(5)).await;
    let (mut fc, reply) = FakeClient::connect(addr, &cert, "tok_test").await;
    let slug = FakeClient::slug(&reply);

    // The broker keeps the raw per-session secret in memory; read it through
    // the registry so verify_ticket() can check the issued ticket.
    let secret = broker
        .registry()
        .lookup(&slug)
        .expect("session live")
        .session_secret();

    let mut ws = connect_signal_ws(addr, &cert).await;
    send_json(
        &mut ws,
        serde_json::json!({ "type": "hello", "slug": slug, "sdp": "v=0\r\n", "ice": [] }),
    )
    .await;

    // Client control socket receives the visitor offer with a valid ticket.
    let offer = fc.recv_control().await;
    let Control::P2pVisitorOffer { ticket, sdp, ice } = offer else {
        panic!("expected p2p_visitor_offer, got {offer:?}");
    };
    assert_eq!(sdp, "v=0\r\n");
    assert!(ice.is_empty());
    verify_ticket(&secret, &slug, &ticket, now_secs()).expect("ticket must verify");

    // Client answers → the visitor WS receives the answer JSON.
    fc.send_control(&Control::P2pAnswer {
        ticket: ticket.clone(),
        sdp: "v=0 answer".into(),
        ice: vec![],
    })
    .await;

    let answer = recv_json(&mut ws).await;
    assert_eq!(answer["type"], "answer");
    assert_eq!(answer["sdp"], "v=0 answer");

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
    assert_eq!(res.headers()["cache-control"], "no-store");

    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("X-Tunnello-Relay"),
        "SW must carry the relay escape hatch"
    );
    broker.stop().await;
}
