//! ddns-server: the tunnel broker engine.
//!
//! One TLS :443 listener ALPN-dispatches between the HTTP(S) tunnel
//! (hyper/axum app + `Host`-header routing) and the raw-TCP tunnel
//! (`ddns-tcp` ALPN, SNI routing). Plan 3 adds SQLite, REST API, operator
//! auth and Let's Encrypt; Plan 4 adds the dashboard UI and the client CLI.

pub mod account;
pub mod audit;
pub mod auth;
pub mod auth_oidc;
pub mod auth_otp;
pub mod config;
pub mod connector;
pub mod debug_capture;
pub mod domain;
pub mod hot;
pub mod http_app;
pub mod http_options;
pub mod http_tunnel;
pub mod mailer;
pub mod metrics;
pub mod mux;
pub mod otp;
pub mod p2p_signal;
pub mod portal;
pub mod providers;
pub mod quota;
pub mod rate_limit;
pub mod registry;
pub mod schema;
pub mod session;
pub mod settings;
pub mod setup;
pub mod stun;
pub mod tcp_bridge;
pub mod tls;
pub mod token;
pub mod tunnel;
pub mod udp_bridge;
pub mod ui;
pub mod visitor_auth;

/// Current unix epoch (seconds) — shared clock for tests and rate limiting.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use http_app::BrokerState;
use providers::ChallengeStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::info;

pub use config::{AcmeOptions, AcmeProvider, BrokerConfig};

/// Format a Unix timestamp (seconds) as `YYYY-MM-DD` (UTC).
pub fn fmt_ts(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
pub use domain::{CertStatus, DomainKind, DomainRecord, DomainStore, ValidationStatus};
pub use http_options::{apply, cidr_matches};
pub use registry::{AllocError, Registry};
pub use session::TunnelSession;
pub use tls::TlsError;
pub use token::{TokenRecord, TokenStore};
pub use tunnel::{HttpOptions, NewTunnel, TunnelRecord, TunnelStore};

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("bind failed: {0}")]
    Bind(#[from] std::io::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] tls::TlsError),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("store error: {0}")]
    Store(#[from] token::StoreError),
}

/// A running broker. `addr` is the bound listener address (ephemeral in tests).
pub struct Broker {
    pub addr: SocketAddr,
    /// Bound address of the embedded STUN server (`None` when disabled).
    pub stun_addr: Option<SocketAddr>,
    /// ACME challenge store (present only in the ACME path). Exposed so
    /// operators/tests can seed HTTP-01 challenges and read cert status.
    pub challenge_store: Option<Arc<ChallengeStore>>,
    registry: Arc<Registry>,
    /// Visitor OTP store (test accessor target).
    otp: std::sync::Arc<crate::auth_otp::OtpStore>,
    handle: JoinHandle<()>,
    drain_tx: watch::Sender<bool>,
    _http_handle: Option<JoinHandle<()>>,
    _downgrade_task: Option<JoinHandle<()>>,
    _usage_task: Option<JoinHandle<()>>,
    _acme_task: Option<JoinHandle<()>>,
}

/// Grace window for connections to finish after drain is signaled.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// How often the accept loop re-checks the drain signal between connections.
const ACCEPT_POLL: Duration = Duration::from_millis(100);

#[cfg(unix)]
async fn shutdown_signal() {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    if let Ok(mut sig) = terminate {
        let _ = sig.recv().await;
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    std::future::pending::<()>().await;
}

impl Broker {
    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// Gracefully stop: signal sessions to drain (each client receives
    /// `kill{admin}` + WS close), stop accepting, wait up to DRAIN_GRACE for
    /// sessions to tear down AND the accept loop to exit, then abort anything
    /// still running.
    pub async fn stop(self) {
        let _ = self.drain_tx.send(true);
        let deadline = tokio::time::Instant::now() + DRAIN_GRACE;
        // The registry shrinks as each session's drain path completes (frames
        // sent, then kill → remove). Poll it alongside the accept loop so the
        // kill{admin} frames have time to flush before the runtime drops.
        while !self.handle.is_finished() || !self.registry.is_empty() {
            if tokio::time::Instant::now() >= deadline {
                if !self.handle.is_finished() {
                    self.handle.abort();
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = self.handle.await;
        if let Some(h) = self._http_handle {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self._downgrade_task {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self._usage_task {
            h.abort();
            let _ = h.await;
        }
        if let Some(h) = self._acme_task {
            h.abort();
            let _ = h.await;
        }
    }

    /// Production entry: serve until SIGINT/SIGTERM, then drain and exit.
    pub async fn serve(config: BrokerConfig) -> Result<(), ServerError> {
        let broker = Broker::start(config).await?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = shutdown_signal() => {}
        }
        broker.stop().await;
        Ok(())
    }

    /// Start the broker: bind, build the TLS acceptor + axum app, spawn the accept loop.
    ///
    /// When `config.http_listen` is Some, a plain-HTTP :80 listener is also
    /// bound. It serves 301 redirects to HTTPS and ACME HTTP-01 challenge
    /// responses. Both listeners are bound BEFORE the ACME state machine is
    /// spawned, so a bind failure cannot leak a detached ACME task.
    /// Test-only access to the visitor OTP store (integration tests install
    /// a code sink to capture dev-mode codes).
    #[doc(hidden)]
    pub fn otp_store(&self) -> &crate::auth_otp::OtpStore {
        &self.otp
    }

    pub async fn start(config: BrokerConfig) -> Result<Broker, ServerError> {
        config.validate().map_err(ServerError::Config)?;

        // Process default crypto provider for reqwest's rustls (workspace
        // uses aws-lc-rs; rustls-acme may have installed it already).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let tls_cfg = tls::server_config(&config)?;
        let acceptor = tls_cfg.acceptor;
        let challenge_store = tls_cfg.challenge_store;
        let acme_state = tls_cfg.acme_state;

        let listener = TcpListener::bind(config.listen).await?;
        let addr = listener.local_addr()?;

        // Bind :80 too, before the TLS accept loop starts and before the ACME
        // task is spawned.
        let mut http_handle: Option<JoinHandle<()>> = None;
        if let Some(http_addr) = config.http_listen {
            let http_listener = TcpListener::bind(http_addr).await?;
            let http_state = HttpLoopState {
                acme: challenge_store.clone(),
                https_port: config.public_port,
                domain: config.domain.clone(),
            };
            http_handle = Some(tokio::spawn(http_loop(http_listener, http_state)));
        }

        // Bind the embedded STUN UDP listener (P2P ICE candidate gathering).
        let stun_addr: Option<SocketAddr> = match config.stun_listen {
            Some(bind) => {
                let sock = tokio::net::UdpSocket::bind(bind).await?;
                let bound = sock.local_addr()?;
                tokio::spawn(async move {
                    let _ = crate::stun::run_stun(sock).await;
                });
                Some(bound)
            }
            None => None,
        };

        // Drive the ACME state machine (issuance + renewal) only now that both
        // binds succeeded.
        let acme_task = acme_state.map(|state| tokio::spawn(drive_acme(state)));

        let registry = Arc::new(Registry::with_limits(
            config.max_sessions,
            config.max_streams_per_session,
        ));
        let domains = domain::DomainStore::open(&config.token_store);
        let tunnels = tunnel::TunnelStore::open(&config.token_store, &domains);
        let mailer = mailer::Mailer::from_env();
        let accounts = account::AccountStore::open(&config.token_store);
        account::migrate_operator(&accounts, &config.token_store).await?;
        domains.seed_from_config(&config.domain);
        let active_apex = domains.active_apex().await.ok().flatten().map(|d| d.name);
        let (drain_tx, _) = watch::channel(false);
        let audit = crate::audit::AuditStore::open(&config.token_store);
        crate::ui::set_audit(audit.clone());
        let setup = crate::setup::SetupStore::open(&config.token_store);
        let hot = match &config.redis_url {
            Some(url) => hot::HotCounter::connect_retry(url).await,
            None => None,
        };
        // The tunnel-traffic rate limiter shares the hot counter's connection.
        // None (no Redis / SQLite mode) → no rate limiting.
        let quota = hot
            .as_ref()
            .map(|h| crate::quota::RateLimiter::new(h.clone()));
        let settings_store = settings::SettingsStore::open(&config.token_store);
        let settings = Arc::new(RwLock::new(
            settings_store.load().map_err(ServerError::Store)?,
        ));
        {
            let s = settings.read().unwrap_or_else(|p| p.into_inner());
            crate::ui::set_branding(&s.instance_name, &s.support_url);
        }
        crate::ui::set_bundle_script(&crate::ui::discover_bundle_script(&config.web_dist));
        let otp_store = std::sync::Arc::new(crate::auth_otp::OtpStore::new());
        let oidc_client = config
            .oidc
            .as_ref()
            .map(|_| std::sync::Arc::new(crate::auth_oidc::OidcClient::new()));
        let state = BrokerState::new(
            Arc::new(config.clone()),
            registry.clone(),
            drain_tx.clone(),
            challenge_store.clone(),
            Arc::new(rate_limit::RateLimiter::new(
                REGISTER_BURST,
                REGISTER_REFILL_PER_SEC,
            )),
            Arc::new(rate_limit::RateLimiter::new(
                OPERATOR_LOGIN_BURST,
                OPERATOR_LOGIN_REFILL_PER_SEC,
            )),
            domains,
            tunnels,
            accounts,
            mailer,
            active_apex,
            settings,
            settings_store,
            hot.clone(),
            quota,
            audit,
            setup,
            otp_store.clone(),
            oidc_client,
        );
        let app = http_app::router(state.clone());
        // Public UDP tunnel listener (disabled when --udp-port is 0/absent).
        if config.udp_port > 0 || !config.udp_routes.is_empty() {
            let udp_state = state.clone();
            let udp_port = config.udp_port;
            let udp_routes = config.udp_routes.clone();
            tokio::spawn(async move {
                if let Err(e) = udp_bridge::run(udp_state, udp_port, udp_routes).await {
                    tracing::warn!(error = %e, "UDP listener exited; UDP tunnels disabled");
                }
            });
        }
        info!(%addr, domain = %config.domain, "ddns broker listening");
        // Global connection cap: bounds memory/fd usage and the amount of
        // concurrent pre-registration argon2 work (register/login are public
        // and CPU-bound). Permits are held by per-connection tasks.
        let conn_cap = config.max_sessions.saturating_mul(16).max(256);
        let permits = Arc::new(tokio::sync::Semaphore::new(conn_cap));

        let handle = tokio::spawn(accept_loop(listener, acceptor, app, state, permits));

        Ok(Broker {
            addr,
            stun_addr,
            challenge_store,
            registry,
            otp: otp_store,
            handle,
            drain_tx,
            _http_handle: http_handle,
            _downgrade_task: None,
            _usage_task: None,
            _acme_task: acme_task,
        })
    }
}

/// Per-IP token bucket params for the public argon2-verify endpoints.
/// Generous burst so reconnect storms and shared-NAT clients are not starved
/// (the digest fast-index makes unknown-token registers cheap; argon2 runs
/// only on digest hits, ~50 ms each — 30@5/s keeps worst-case CPU bounded).
const REGISTER_BURST: u32 = 30;
const REGISTER_REFILL_PER_SEC: f64 = 5.0;
/// Operator `/login` (admin-password argon2 verify).
const OPERATOR_LOGIN_BURST: u32 = 5;
const OPERATOR_LOGIN_REFILL_PER_SEC: f64 = 0.5;

/// Drive the ACME state machine: poll the directory, issue the initial
/// certificate, then renew before expiry. The stream never terminates on its
/// own (errors are retried with backoff), so the task runs until aborted by
/// [`Broker::stop`].
async fn drive_acme(mut state: rustls_acme::AcmeState<std::io::Error, std::io::Error>) {
    use futures_util::StreamExt;
    while let Some(event) = state.next().await {
        match event {
            Ok(ok) => tracing::info!(?ok, "ACME event"),
            Err(e) => tracing::warn!(?e, "ACME error"),
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: axum::Router,
    state: BrokerState,
    permits: Arc<tokio::sync::Semaphore>,
) {
    let drain_rx = state.drain.subscribe();
    loop {
        // Accept with a short timeout so we can re-check the drain signal.
        match tokio::time::timeout(ACCEPT_POLL, listener.accept()).await {
            Ok(Ok((tcp, peer))) => {
                // Connection cap: drop the connection outright when saturated
                // (the client can retry; bounded resources beat queueing).
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(%peer, "connection cap reached; dropping connection");
                    continue;
                };
                let acceptor = acceptor.clone();
                let state = state.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for the connection's lifetime
                    let tls = match acceptor.accept(tcp).await {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::debug!(%peer, error = %e, "TLS handshake failed");
                            return;
                        }
                    };
                    let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                    if alpn.as_deref() == Some(tls::ALPN_TCP) {
                        tcp_bridge::handle(tls, state).await;
                        return;
                    }
                    if alpn.as_deref() == Some(tls::ACME_ALPN) {
                        // TLS-ALPN-01 validation connection: the challenge was
                        // answered inside the handshake by the ACME resolver;
                        // the CA sends nothing further, so drop it.
                        return;
                    }
                    let svc = hyper::service::service_fn(
                        move |mut req: hyper::Request<hyper::body::Incoming>| {
                            let app = app.clone();
                            async move {
                                req.extensions_mut()
                                    .insert(axum::extract::ConnectInfo(peer));
                                app.oneshot(req).await
                            }
                        },
                    );
                    let io = hyper_util::rt::TokioIo::new(tls);
                    let builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
                        tracing::debug!(%peer, error = %e, "HTTP connection error");
                    }
                });
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "accept failed");
            }
            Err(_elapsed) => {
                // Timeout: re-check the drain signal.
            }
        }
        // Check drain after each accept attempt.
        if *drain_rx.borrow() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Plain-HTTP :80 listener
// ---------------------------------------------------------------------------

struct HttpLoopState {
    acme: Option<Arc<ChallengeStore>>,
    https_port: u16,
    domain: String,
}

/// Serve 301 redirects to HTTPS for everything except ACME HTTP-01 challenges.
/// Stopped by aborting the task handle (see [`Broker::stop`]).
async fn http_loop(listener: TcpListener, state: HttpLoopState) {
    loop {
        let (stream, _peer) = match tokio::time::timeout(ACCEPT_POLL, listener.accept()).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "HTTP accept failed");
                continue;
            }
            Err(_) => continue,
        };

        let acme = state.acme.clone();
        let https_port = state.https_port;
        let domain = state.domain.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_request(stream, acme.as_deref(), https_port, &domain).await
            {
                tracing::debug!(error = %e, "HTTP request error");
            }
        });
    }
}

async fn handle_http_request(
    stream: tokio::net::TcpStream,
    acme_store: Option<&ChallengeStore>,
    https_port: u16,
    domain: &str,
) -> Result<(), std::io::Error> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Bounded request-line read with a timeout (slowloris defense on an
    // internet-facing :80 port): at most READ_MAX_LINE bytes in one line,
    // and no line may take longer than READ_TIMEOUT.
    let mut line = String::new();
    let read_line = tokio::time::timeout(READ_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request line timeout"))??;
    if read_line == 0 {
        return Ok(()); // client closed before sending anything
    }
    if line.len() > READ_MAX_LINE {
        return write_error(&mut write_half, 431, "Request Header Fields Too Large").await;
    }
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let target = parts[1];

    // Read headers until empty line — each header line timed, total bounded.
    let mut headers = String::new();
    let mut header_buf = String::new();
    loop {
        header_buf.clear();
        let n = tokio::time::timeout(READ_TIMEOUT, reader.read_line(&mut header_buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "header timeout"))??;
        if n == 0 || header_buf == "\r\n" || header_buf == "\n" || header_buf.is_empty() {
            break;
        }
        if headers.len() + header_buf.len() > READ_MAX_LINE {
            return write_error(&mut write_half, 431, "Request Header Fields Too Large").await;
        }
        headers.push_str(&header_buf);
    }

    // Read Host header for redirect.
    let host = extract_host(&headers).unwrap_or_else(|| domain.to_string());

    // The Host header is attacker-controlled on this listener; only reflect
    // a safe subset into the redirect Location (control chars would corrupt
    // the header value; anything exotic gets a plain 400).
    if !crate::http_app::host_is_safe(&host) || !target.starts_with('/') {
        return write_error(&mut write_half, 400, "Bad Request").await;
    }

    // ACME HTTP-01 challenge endpoint.
    if method == "GET" && target.starts_with("/.well-known/acme-challenge/") {
        let token = target.trim_start_matches("/.well-known/acme-challenge/");
        // Strip any query string or trailing slash.
        let token = token.split('?').next().unwrap_or(token).trim_matches('/');
        if let Some(store) = acme_store
            && let Some(value) = store.get_http01(token)
        {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                value.len(),
                value
            );
            write_half.write_all(response.as_bytes()).await?;
            write_half.shutdown().await?;
            return Ok(());
        }
        // 404 for unknown challenge tokens.
        return write_error(&mut write_half, 404, "Not Found").await;
    }

    // 301 redirect to HTTPS, preserving path+query.
    let location = if https_port == 443 {
        format!("https://{host}{target}")
    } else {
        // Extract path only from target, reconstruct with https.
        let path_query = if target.starts_with('/') {
            target.to_string()
        } else {
            format!("/{target}")
        };
        format!("https://{host}:{https_port}{path_query}")
    };
    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    write_half.write_all(response.as_bytes()).await?;
    write_half.shutdown().await?;
    Ok(())
}

/// Write a minimal error response and close the connection.
async fn write_error<W: tokio::io::AsyncWrite + Unpin>(
    write_half: &mut W,
    code: u16,
    reason: &str,
) -> Result<(), std::io::Error> {
    let response =
        format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    write_half.write_all(response.as_bytes()).await?;
    write_half.shutdown().await?;
    Ok(())
}

/// Timeout for reading the request line and each header line.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum length of the request line, and of the accumulated headers.
const READ_MAX_LINE: usize = 8 * 1024;

/// Extract the `Host` header value (case-insensitive per RFC 7230), stripping
/// the port only when it is a numeric suffix; IPv6 literals (`[::1]:8080`)
/// keep their bracketed form.
fn extract_host(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            let host = value.trim();
            if host.starts_with('[') {
                // IPv6 literal: keep everything through the closing bracket.
                if let Some(end) = host.rfind(']') {
                    return Some(host[..=end].to_string());
                }
                return Some(host.to_string());
            }
            // host:port → host; bare host unchanged.
            if let Some((h, port)) = host.rsplit_once(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit())
            {
                return Some(h.to_string());
            }
            return Some(host.to_string());
        }
    }
    None
}
