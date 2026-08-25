use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ddns_proto::{Control, Frame, Opcode, OpenMeta};
use ddns_server::{Broker, BrokerConfig, TokenStore};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Convenience: creates a `TokenRecord` for tests.
#[allow(dead_code)]
pub fn test_record(id: &str, enabled: bool) -> ddns_server::TokenRecord {
    ddns_server::TokenRecord {
        id: id.into(),
        name: "test".into(),
        owner_id: None,
        limits: ddns_proto::TokenLimits::default(),
        enabled,
        created_at: 0,
    }
}

/// Convenience: creates a `TokenRecord` with custom limits for tests.
#[allow(dead_code)]
pub fn test_record_with_limits(
    id: &str,
    limits: ddns_proto::TokenLimits,
) -> ddns_server::TokenRecord {
    ddns_server::TokenRecord {
        id: id.into(),
        name: "test".into(),
        owner_id: None,
        limits,
        enabled: true,
        created_at: 0,
    }
}

/// Self-signed cert with SANs for the tunnel domain, its wildcard, and loopback
/// IPs (so HTTPS tests can connect to 127.0.0.1 with a verifiable server_name).
#[allow(dead_code)]
pub fn test_cert() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair};
    let params = CertificateParams::new(vec![
        "tunnel.example.com".to_string(),
        "*.tunnel.example.com".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

/// Client TLS config trusting the given PEM cert chain as root.
pub fn client_tls(cert_pem: &[u8]) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .unwrap();
    for c in certs {
        root_store.add(c).unwrap();
    }
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

#[allow(dead_code)]
pub fn broker_config(
    cert: &[u8],
    key: &[u8],
    tokens: TokenStore,
    max_sessions: usize,
    watchdog: Duration,
) -> BrokerConfig {
    BrokerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        domain: "tunnel.example.com".to_string(),
        public_port: 443,
        udp_port: 0,
        udp_target_port: 0,
        tls_cert_pem: cert.to_vec(),
        tls_key_pem: key.to_vec(),
        token_store: tokens,
        max_sessions,
        watchdog_interval: watchdog,
        http_listen: None,
        stun_listen: None,
        acme: None,
        download_dir: None,
        dev: true,
        base_url: "https://tunnel.example.com".to_string(),
        web_dist: std::path::PathBuf::from("dist/public"),
        max_streams_per_session: 512,
        redis_url: None,
    }
}

#[allow(dead_code)]
pub async fn start_broker_with_config(config: BrokerConfig) -> (SocketAddr, Broker) {
    let broker = Broker::start(config).await.unwrap();
    let addr = broker.addr;
    (addr, broker)
}

#[allow(dead_code)]
pub async fn start_broker(
    cert: &[u8],
    key: &[u8],
    tokens: TokenStore,
    max_sessions: usize,
    watchdog: Duration,
) -> (SocketAddr, Broker) {
    let config = broker_config(cert, key, tokens, max_sessions, watchdog);
    let broker = Broker::start(config).await.unwrap();
    (broker.addr, broker)
}

/// Like `start_broker`, with a Redis URL (rate limiting + hot counter).
#[allow(dead_code)]
pub async fn start_broker_with_redis(
    cert: &[u8],
    key: &[u8],
    tokens: TokenStore,
    max_sessions: usize,
    watchdog: Duration,
    redis_url: &str,
) -> (SocketAddr, Broker) {
    let mut config = broker_config(cert, key, tokens, max_sessions, watchdog);
    config.redis_url = Some(redis_url.to_string());
    let broker = Broker::start(config).await.unwrap();
    (broker.addr, broker)
}

/// Like `start_broker`, with extra config applied by the caller.
#[allow(dead_code)]
pub async fn start_broker_with_webhook(
    cert: &[u8],
    key: &[u8],
    tokens: TokenStore,
    max_sessions: usize,
    watchdog: Duration,
) -> (SocketAddr, Broker) {
    let config = broker_config(cert, key, tokens, max_sessions, watchdog);
    let broker = Broker::start(config).await.unwrap();
    (broker.addr, broker)
}

#[allow(dead_code)]
pub struct FakeClient {
    pub ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

#[allow(dead_code)]
impl FakeClient {
    /// Connect to the broker's /connect and register with want_tcp/want_http
    /// both true. Panics on error replies — error tests use `connect_raw`.
    pub async fn connect(addr: SocketAddr, cert_pem: &[u8], token: &str) -> (FakeClient, Control) {
        Self::connect_with_flags(addr, cert_pem, token, true, true).await
    }

    pub async fn connect_with_flags(
        addr: SocketAddr,
        cert_pem: &[u8],
        token: &str,
        want_tcp: bool,
        want_http: bool,
    ) -> (FakeClient, Control) {
        Self::connect_udp_flags(addr, cert_pem, token, want_tcp, want_http, false, 0).await
    }

    /// Full-flag register: TCP/HTTP/UDP capability + local UDP target port.
    pub async fn connect_udp_flags(
        addr: SocketAddr,
        cert_pem: &[u8],
        token: &str,
        want_tcp: bool,
        want_http: bool,
        want_udp: bool,
        udp_port: u16,
    ) -> (FakeClient, Control) {
        let (fc, reply) = Self::connect_raw_udp(
            addr, cert_pem, token, want_tcp, want_http, want_udp, udp_port,
        )
        .await;
        match reply {
            Ok(c) => (fc, c),
            Err(e) => panic!("register failed: {e:?}"),
        }
    }

    /// Returns `Err(control)` when the broker answers `error{...}`.
    pub async fn connect_raw(
        addr: SocketAddr,
        cert_pem: &[u8],
        token: &str,
        want_tcp: bool,
        want_http: bool,
    ) -> (FakeClient, Result<Control, Control>) {
        Self::connect_raw_udp(addr, cert_pem, token, want_tcp, want_http, false, 0).await
    }

    /// Full-flag variant of [`connect_raw`] with UDP capability fields.
    pub async fn connect_raw_udp(
        addr: SocketAddr,
        cert_pem: &[u8],
        token: &str,
        want_tcp: bool,
        want_http: bool,
        want_udp: bool,
        udp_port: u16,
    ) -> (FakeClient, Result<Control, Control>) {
        let cfg = Arc::new(client_tls(cert_pem));
        let connector = tokio_tungstenite::Connector::Rustls(cfg);
        let url = format!("wss://127.0.0.1:{}/connect", addr.port());
        let (ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector))
                .await
                .unwrap();
        let mut fc = FakeClient { ws };
        fc.send_control(&Control::Register {
            token: token.to_string(),
            want_tcp,
            want_http,
            want_udp,
            udp_port,
            subdomain_hint: None,
        })
        .await;
        let reply = fc.recv_control().await;
        let result = match &reply {
            Control::Error { .. } => Err(reply),
            _ => Ok(reply),
        };
        (fc, result)
    }

    /// Extract the slug from a `registered` reply.
    pub fn slug(reply: &Control) -> String {
        match reply {
            Control::Registered {
                http_url: Some(u), ..
            } => u
                .trim_start_matches("https://")
                .trim_end_matches(".tunnel.example.com")
                .to_string(),
            other => panic!("expected registered with http_url, got {other:?}"),
        }
    }

    pub async fn send_control(&mut self, c: &Control) {
        let json = serde_json::to_string(c).unwrap();
        self.ws
            .send(tokio_tungstenite::tungstenite::Message::Text(json.into()))
            .await
            .unwrap();
    }

    /// Next WS message must be a text control message.
    pub async fn recv_control(&mut self) -> Control {
        loop {
            match self.ws.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
                    return serde_json::from_str(&t).unwrap();
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(b))) => {
                    panic!("expected control, got binary frame {b:?}");
                }
                Some(Ok(_)) => continue,
                _ => panic!("ws closed while waiting for control"),
            }
        }
    }

    pub async fn send_frame(&mut self, f: &Frame) {
        let mut buf = Vec::new();
        f.encode(&mut buf).unwrap();
        self.ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(buf.into()))
            .await
            .unwrap();
    }

    /// Next WS message must be a binary stream frame.
    pub async fn recv_frame(&mut self) -> Frame {
        loop {
            match self.ws.next().await {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(b))) => {
                    return Frame::decode(&b).unwrap();
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(t))) => {
                    panic!("expected frame, got control {t}");
                }
                Some(Ok(_)) => continue,
                _ => panic!("ws closed while waiting for frame"),
            }
        }
    }

    pub async fn recv_open(&mut self) -> (u32, OpenMeta) {
        let f = self.recv_frame().await;
        assert_eq!(f.opcode, Opcode::Open, "expected OPEN, got {f:?}");
        let meta = OpenMeta::decode(&f.payload).unwrap();
        (f.stream_id, meta)
    }

    pub async fn send_open_ack(&mut self, id: u32, head: impl Into<Bytes>) {
        self.send_frame(&Frame {
            opcode: Opcode::OpenAck,
            stream_id: id,
            payload: head.into(),
        })
        .await;
    }

    pub async fn send_data(&mut self, id: u32, payload: impl Into<Bytes>) {
        self.send_frame(&Frame {
            opcode: Opcode::Data,
            stream_id: id,
            payload: payload.into(),
        })
        .await;
    }

    pub async fn send_close(&mut self, id: u32, reason: u8) {
        self.send_frame(&Frame {
            opcode: Opcode::Close,
            stream_id: id,
            payload: Bytes::from(vec![reason]),
        })
        .await;
    }

    pub async fn recv_close(&mut self) -> (u32, u8) {
        let f = self.recv_frame().await;
        assert_eq!(f.opcode, Opcode::Close, "expected CLOSE, got {f:?}");
        (f.stream_id, f.payload.first().copied().unwrap_or(0))
    }

    /// Assert the broker closes the WS within 5 s (either a Close frame or EOF).
    pub async fn expect_ws_close(&mut self) {
        let r = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match self.ws.next().await {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => return,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => return,
                }
            }
        })
        .await;
        assert!(r.is_ok(), "broker did not close the WS within 5 s");
    }
}

/// A tiny local service that echoes `{"path":…,"body_len":…,"host":…}` back.
/// Used to verify the broker forwarded the request head/body intact.
#[allow(dead_code)]
pub struct LocalApp {
    pub addr: SocketAddr,
}

#[allow(dead_code)]
pub async fn spawn_local_app() -> LocalApp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 1 << 16 {
                        return;
                    }
                }
                let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let cl = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + cl {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = &buf[head_end..head_end + cl];
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let host = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("host:")
                            .map(|v| v.trim().to_string())
                    })
                    .unwrap_or_default();
                let json = format!(
                    r#"{{"path":"{path}","body_len":{},"host":"{host}"}}"#,
                    body.len()
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    LocalApp { addr }
}

/// Raw TLS client with ALPN ddns-tcp and SNI `<slug>.tunnel.example.com`.
#[allow(dead_code)]
pub async fn connect_tcp(
    addr: SocketAddr,
    cert: &[u8],
    slug: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut cfg = client_tls(cert);
    cfg.alpn_protocols = vec![b"ddns-tcp".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect(
            format!("{slug}.tunnel.example.com").try_into().unwrap(),
            tcp,
        )
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"ddns-tcp".as_slice())
    );
    tls
}

/// Echo server: bytes in → bytes out.
#[allow(dead_code)]
pub async fn spawn_echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(sock);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}
