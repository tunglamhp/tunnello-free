//! Tiny HTTP echo app for the local demo — the "local app" behind the tunnel.
//!
//! Usage: `ddns-echo [--port N]` (default 8088). Responds on `/` and `/echo`
//! (JSON echo of path, query, headers and client address) so a tunnel
//! round-trip is easy to verify end to end.

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Uri};
use axum::response::Json;
use axum::routing::get;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let mut port = 8088u16;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().and_then(|p| p.parse().ok()).unwrap_or(port),
            other => {
                eprintln!("ddns-echo: unknown argument {other:?}");
                std::process::exit(2);
            }
        }
    }
    let app = Router::new()
        .route("/", get(root))
        .route("/echo", get(echo))
        .into_make_service_with_connect_info::<SocketAddr>();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("ddns-echo: bind {addr} failed: {e}");
            std::process::exit(1);
        });
    println!("ddns-echo listening on http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "ddns-echo is up — the local app behind your tunnel."
}

async fn echo(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Json<serde_json::Value> {
    let mut hs = serde_json::Map::new();
    for (k, v) in headers.iter() {
        hs.insert(
            k.as_str().to_string(),
            serde_json::Value::String(v.to_str().unwrap_or("").to_string()),
        );
    }
    Json(serde_json::json!({
        "app": "ddns-echo",
        "path": uri.path(),
        "query": uri.query(),
        "remote": peer.to_string(),
        "headers": hs,
    }))
}
