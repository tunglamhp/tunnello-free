//! One outbound `wss://` connection: TLS (webpki-roots + optional --ca-pem),
//! WS upgrade, `register`, then a heartbeat task until the socket closes.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use ddns_proto::{Control, ErrorCode};

use crate::cli::Cli;

/// The concrete WS stream type returned by `connect_and_register`.
pub type ClientWsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    #[error("dns/tcp: {0}")]
    Io(#[from] io::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("websocket: {0}")]
    Ws(String),
    #[error("server rejected token: {0:?}")]
    Rejected(ErrorCode),
    #[error("bad reply: {0}")]
    Protocol(String),
}

/// Build a rustls `ClientConfig` that trusts:
///   - webpki-roots (Mozilla CA bundle)
///   - `--ca-pem` file contents (if set)
///   - the `roots` argument (test CAs from integration tests)
pub fn client_config(
    cli: &Cli,
    roots: &[CertificateDer<'static>],
) -> Result<rustls::ClientConfig, String> {
    // webrtc's DTLS defaults to the `ring` rustls provider while the rest of
    // the workspace uses `aws-lc-rs`; once both are linked into one binary
    // rustls cannot auto-detect a default (it panics). Pin the process default
    // to `aws-lc-rs` explicitly. Idempotent: a later call is a no-op.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut root_store = rustls::RootCertStore::empty();

    // WebPKI roots — extend with TrustAnchors directly
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.to_vec());

    // --ca-pem file
    if let Some(ref path) = cli.ca_pem {
        let pem_bytes = std::fs::read(path).map_err(|e| format!("reading --ca-pem: {e}"))?;
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut &pem_bytes[..])
            .collect::<Result<_, _>>()
            .map_err(|e| format!("parsing --ca-pem: {e}"))?;
        for c in certs {
            root_store
                .add(c)
                .map_err(|e| format!("--ca-pem cert: {e}"))?;
        }
    }

    // Extra test roots
    for c in roots {
        root_store
            .add(c.clone())
            .map_err(|e| format!("extra root: {e}"))?;
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

/// Extract host and port from the --server URL. Strips the scheme prefix
/// (`https://` or `wss://`). Default port is 443.
fn parse_server(server: &str) -> Result<(String, u16), ConnError> {
    let url = server.trim_end_matches('/');
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("wss://"))
        .unwrap_or(server);

    let (host, port) = if rest.starts_with('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| ConnError::Protocol("invalid IPv6 in --server".into()))?;
        let host = &rest[..=close];
        let after = &rest[close + 1..];
        if let Some(port_str) = after.strip_prefix(':') {
            let p: u16 = port_str.parse().map_err(|_| {
                ConnError::Protocol(format!("invalid port in --server: {port_str}"))
            })?;
            (host.to_string(), p)
        } else {
            (host.to_string(), 443)
        }
    } else if let Some((h, p)) = rest.rsplit_once(':') {
        let p: u16 = p
            .parse()
            .map_err(|_| ConnError::Protocol(format!("invalid port in --server: {p}")))?;
        (h.to_string(), p)
    } else {
        (rest.to_string(), 443)
    };

    Ok((host, port))
}

/// Spawn the keepalive task: sends `Control::Heartbeat { seq }` every
/// `interval` until the shared send queue is dropped.
/// Uses the mpsc channel so the mux writer task owns the actual WS write half.
pub fn spawn_heartbeat(
    tx: tokio::sync::mpsc::Sender<Message>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut seq: u64 = 0;
        loop {
            tokio::time::sleep(interval).await;
            seq += 1;
            let json = match serde_json::to_string(&Control::Heartbeat { seq }) {
                Ok(j) => j,
                Err(_) => continue,
            };
            if tx.send(Message::Text(json.into())).await.is_err() {
                return;
            }
        }
    })
}

/// Connect, upgrade, and send `register`. Returns both WS halves, the
/// reply, and the base64url `session_secret` (from `Registered`). The caller
/// owns the halves and is responsible for spawning the writer task and
/// heartbeat (via the mux).
///
/// Steps:
/// 1. Build the `wss://` URL from `--server`.
/// 2. TCP connect.
/// 3. TLS handshake with SNI.
/// 4. WebSocket upgrade via `client_async_tls`.
/// 5. Send `Control::Register`.
/// 6. Read one text frame (10 s timeout) → `Registered`, `Error`, or protocol error.
pub async fn connect_and_register(
    cli: &Cli,
    roots: &[CertificateDer<'static>],
) -> Result<
    (
        futures_util::stream::SplitSink<ClientWsStream, Message>,
        futures_util::stream::SplitStream<ClientWsStream>,
        Control,
        String,
    ),
    ConnError,
> {
    // 1. Build the wss URL
    let (host, port) = parse_server(&cli.server)?;
    let url = format!("wss://{host}:{port}/connect");

    // 2-4. TCP + TLS + WS upgrade via the connector pattern
    let tls_cfg = Arc::new(client_config(cli, roots).map_err(ConnError::Tls)?);
    let connector = tokio_tungstenite::Connector::Rustls(tls_cfg);
    let (mut ws, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
            .await
            .map_err(|e| ConnError::Ws(format!("WS connect: {e}")))?;

    // 5. Send Register
    let register = Control::Register {
        token: cli.token.clone(),
        want_tcp: cli.tcp_target.is_some(),
        want_http: cli.http_target.is_some(),
        want_udp: cli.udp_target.is_some(),
        udp_port: cli.udp_target.unwrap_or(0),
        subdomain_hint: None,
    };
    let json = serde_json::to_string(&register).map_err(|e| ConnError::Protocol(e.to_string()))?;

    ws.send(Message::Text(json.into()))
        .await
        .map_err(|e| ConnError::Ws(format!("send register: {e}")))?;

    // 6. Read one text frame (10 s timeout)
    let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .map_err(|_| ConnError::Protocol("timeout waiting for register reply".into()))?
        .ok_or_else(|| ConnError::Protocol("ws closed before register reply".into()))?
        .map_err(|e| ConnError::Ws(format!("ws read error: {e}")))?;

    let text = msg
        .to_text()
        .map_err(|e| ConnError::Protocol(format!("expected text, got binary: {e}")))?;

    let control: Control = serde_json::from_str(text)
        .map_err(|e| ConnError::Protocol(format!("bad JSON in register reply: {e}")))?;

    match &control {
        Control::Registered { session_secret, .. } => {
            let secret = session_secret.clone();
            let (write, read) = ws.split();
            Ok((write, read, control, secret))
        }
        Control::Error { code } => Err(ConnError::Rejected(*code)),
        other => Err(ConnError::Protocol(format!(
            "expected Registered, got {other:?}"
        ))),
    }
}
