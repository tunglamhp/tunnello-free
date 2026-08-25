//! Visitor-auth integration tests: OTP end-to-end through the real HTTP
//! routes (dev mailer), and the OIDC-unconfigured 503 path.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use tokio::time::timeout;

use ddns_server::TokenStore;

/// Minimal HTTPS GET/POST helpers (mirror tests/p2p_signaling.rs client).
mod https {
    use std::collections::HashMap;
    use std::sync::Arc;

    pub fn client_tls(cert_pem: &[u8]) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        let certs: Vec<rustls::pki_types::CertificateDer> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<Result<_, _>>()
                .unwrap();
        for c in certs {
            root_store.add(c).unwrap();
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }

    pub type Client = hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        axum::body::Body,
    >;

    pub fn https_client(cert: &[u8]) -> Client {
        let cfg = client_tls(cert);
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(cfg)
            .https_or_http()
            .enable_http1()
            .build();
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(https)
    }

    pub async fn get(
        client: &Client,
        addr: std::net::SocketAddr,
        path: &str,
    ) -> (u16, HashMap<String, String>, String) {
        let uri = format!("https://127.0.0.1:{addr}{path}");
        let _ = uri;
        let uri = format!("https://127.0.0.1:{}{}", addr.port(), path);
        let req = axum::http::Request::builder()
            .uri(uri)
            .header("host", "anything.tunnel.example.com")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            if let Ok(val) = v.to_str() {
                headers.insert(k.as_str().to_string(), val.to_string());
            }
        }
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body = String::from_utf8_lossy(&body).to_string();
        (status, headers, body)
    }

    pub async fn post_form(
        client: &Client,
        addr: std::net::SocketAddr,
        path: &str,
        form: &str,
    ) -> (u16, HashMap<String, String>, String) {
        let uri = format!("https://127.0.0.1:{}{}", addr.port(), path);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("host", "anything.tunnel.example.com")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(form.to_string()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            if let Ok(val) = v.to_str() {
                headers.insert(k.as_str().to_string(), val.to_string());
            }
        }
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body = String::from_utf8_lossy(&body).to_string();
        (status, headers, body)
    }
}

#[tokio::test]
async fn otp_flow_end_to_end_sets_cookie() {
    let (cert, key) = common::test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    let (addr, broker) = common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;

    // Capture dev-mode codes through the test sink.
    let got = std::sync::Arc::new(parking_lot::Mutex::new(String::new()));
    let sink = got.clone();
    broker.otp_store().set_code_sink(move |code| {
        *sink.lock() = code;
    });

    let client = https::https_client(&cert);

    // 1. Form renders.
    let (status, _, body) = https::get(&client, addr, "/__auth/otp").await;
    assert_eq!(status, 200);
    assert!(body.contains("name=\"email\""), "form has an email input");

    // 2. Send → code captured via sink (dev mode also logs).
    let (status, _, _) = https::post_form(
        &client,
        addr,
        "/__auth/otp/send",
        "email=v%40t.ld&back=%2Ft%2Fx",
    )
    .await;
    assert_eq!(status, 200);
    let code = got.lock().clone();
    assert_eq!(code.len(), 6, "sink captured the 6-digit code");

    // 3. Wrong code → 401.
    let (status, _, _) = https::post_form(
        &client,
        addr,
        "/__auth/otp/verify",
        "email=v%40t.ld&code=000000&back=%2Ft%2Fx",
    )
    .await;
    assert_eq!(status, 401);

    // 4. Correct code → 303 + tnl_otp cookie.
    let (status, headers, _) = https::post_form(
        &client,
        addr,
        "/__auth/otp/verify",
        &format!("email=v%40t.ld&code={code}&back=%2Ft%2Fx"),
    )
    .await;
    assert_eq!(status, 303, "verify redirects to back target");
    let cookie = headers.get("set-cookie").expect("tnl_otp cookie set");
    assert!(cookie.contains("tnl_otp="), "cookie is tnl_otp: {cookie}");

    let _ = timeout(Duration::from_secs(1), std::future::ready(())).await;
}

#[tokio::test]
async fn oidc_start_without_config_returns_503() {
    let (cert, key) = common::test_cert();
    let tokens = TokenStore::new();
    tokens
        .insert("tok_test".into(), common::test_record("t-test", true))
        .await
        .unwrap();
    let (addr, _broker) =
        common::start_broker(&cert, &key, tokens, 8, Duration::from_secs(5)).await;
    let client = https::https_client(&cert);
    let (status, _, body) = https::get(&client, addr, "/__auth/oidc/start?back=%2F").await;
    assert_eq!(status, 503);
    assert!(body.contains("OIDC not configured"));
}
