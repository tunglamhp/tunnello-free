//! ddns-client: the tunnel client library.
//!
//! Opens one outbound `wss://` connection to the broker, registers with a
//! token, and multiplexes visitor HTTP/raw-TCP traffic to a local target.
//!
//! The public API is event-driven: `run()` takes a `Cli` config and an event
//! sink, drives the connection lifecycle, and returns an `ExitStatus`.

pub mod cli;
pub mod connect;
pub mod connect_p2p;
pub mod mux;
pub mod p2p;
pub mod reconnect;
pub mod targets;
mod udp;
use std::time::Duration;

use rustls::pki_types::CertificateDer;

use ddns_proto::{Control, ErrorCode};

use crate::cli::Cli;
use crate::p2p::P2pGateway;
use crate::reconnect::{Backoff, SessionEnd};
use tokio::sync::mpsc;

pub use connect::ConnError;
pub use ddns_proto::{KillReason, Usage};

/// Hint for an exhausted token balance, shared by the mid-session Error path
/// and the registration-rejection path so the user gets the same guidance as
/// the `KillReason::TokenExhausted` hint.
const TOKEN_EXHAUSTED_HINT: &str = "token balance exhausted — top up or upgrade your plan";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Information about an established tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelInfo {
    pub slug: String,
    pub http_url: Option<String>,
    pub tcp_addr: Option<String>,
}

/// Lifecycle events emitted by the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Registered(TunnelInfo),
    Killed {
        reason: KillReason,
        usage: Option<Usage>,
    },
    Retrying {
        attempt: u32,
        delay: Duration,
    },
    Fatal(String),
}

/// Terminal outcome of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    Clean,
    Killed(KillReason),
    Fatal,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Connect, register, and drive the tunnel lifecycle with exponential
/// backoff on transient failures. Emits lifecycle events through `sink`.
/// Returns the terminal exit status.
pub async fn run(
    cli: Cli,
    roots: &[CertificateDer<'static>],
    mut sink: impl FnMut(Event),
) -> ExitStatus {
    let mut backoff = Backoff::new();
    loop {
        match connect::connect_and_register(&cli, roots).await {
            Ok((
                write,
                read,
                Control::Registered {
                    http_url, tcp_addr, ..
                },
                session_secret,
            )) => {
                let slug = extract_slug(http_url.as_deref(), tcp_addr.as_deref());
                let info = TunnelInfo {
                    slug: slug.clone(),
                    http_url,
                    tcp_addr,
                };
                // Broker version compatibility check (informational only).
                backoff.reset();

                // Shared write queue — moved into the mux task.
                let (tx, rx) = mpsc::channel(64);
                let gateway = P2pGateway::new();
                let cli_clone = cli.clone();
                let subdomain = slug;
                let mux_handle = tokio::spawn(async move {
                    mux::run_mux(
                        tx,
                        rx,
                        read,
                        write,
                        &cli_clone,
                        session_secret,
                        gateway,
                        subdomain,
                    )
                    .await
                });

                sink(Event::Registered(info));

                match mux_handle.await {
                    Ok(SessionEnd::WsClosed) => {
                        // fall through to retry
                    }
                    Ok(SessionEnd::Killed(reason, usage)) => {
                        sink(Event::Killed { reason, usage });
                        return ExitStatus::Killed(reason);
                    }
                    Ok(SessionEnd::ServerError(ErrorCode::TokenInvalid)) => {
                        sink(Event::Fatal("token rejected by broker".into()));
                        return ExitStatus::Fatal;
                    }
                    Ok(SessionEnd::ServerError(ErrorCode::TokenExhausted)) => {
                        sink(Event::Fatal(TOKEN_EXHAUSTED_HINT.into()));
                        return ExitStatus::Fatal;
                    }
                    Ok(SessionEnd::ServerError(_)) => {
                        // server_full / no_subdomain: retry
                    }
                    Err(_) => {
                        // mux task panicked or was cancelled
                    }
                }
            }
            Ok(_) => {
                sink(Event::Fatal("unexpected register reply".into()));
                return ExitStatus::Fatal;
            }
            Err(ConnError::Rejected(ErrorCode::TokenExhausted)) => {
                sink(Event::Fatal(TOKEN_EXHAUSTED_HINT.into()));
                return ExitStatus::Fatal;
            }
            Err(ConnError::Rejected(code)) => {
                sink(Event::Fatal(format!("token rejected: {code:?}")));
                return ExitStatus::Fatal;
            }
            Err(e) => {
                // transient (io/tls/ws): retry — surface the reason instead of
                // a silent "reconnecting…" loop (e.g. HTTP 429 rate-limited
                // register, TLS failure, broker unreachable).
                tracing::error!(error = %e, "tunnel connect failed; retrying");
                eprintln!("ddns: connect failed: {e}");
            }
        }

        // Backoff + Ctrl-C check
        let delay = backoff.next_delay();
        let attempt = backoff.attempt;
        sink(Event::Retrying { attempt, delay });
        if tokio::select! {
            _ = tokio::signal::ctrl_c() => true,
            _ = tokio::time::sleep(delay) => false,
        } {
            return ExitStatus::Clean;
        }
    }
}

fn extract_slug(http_url: Option<&str>, tcp_addr: Option<&str>) -> String {
    let candidate = http_url.or(tcp_addr).unwrap_or("");
    // URL looks like "https://<slug>.tunnel.example.com"
    // or tcp address "<slug>.tunnel.example.com:443"
    // Extract the slug (first subdomain)
    if let Some(rest) = candidate
        .strip_prefix("https://")
        .or_else(|| candidate.strip_prefix("wss://"))
        .or(Some(candidate))
    {
        if let Some(dot) = rest.find('.') {
            rest[..dot].to_string()
        } else {
            rest.to_string()
        }
    } else {
        candidate.to_string()
    }
}
