//! The `/connect` WebSocket endpoint: one WS connection per client session.
//!
//! Text frames carry JSON `Control` messages; binary frames carry exactly one
//! encoded `Frame` (the multiplexed stream protocol from ddns-proto).
//!
//! Lifecycle: read `register` (10 s timeout) → validate token → allocate slug
//! → reply `registered`/`error` → spawn WS writer + quota watchdog → route
//! frames and controls until the client leaves or a kill fires → free the slug.

use std::time::Duration;

use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ddns_proto::{Control, ErrorCode, Frame, KillReason, MAX_FRAME_PAYLOAD, Opcode};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};

use crate::http_app::BrokerState;
use crate::quota;
use crate::registry::AllocError;
use crate::session::{TunnelSession, WS_QUEUE_CAP};
use crate::settings;
use crate::tunnel;

/// How long the client has to send `register` after the WS upgrade.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-WS-message cap at the transport layer: binary frames carry exactly one
/// `Frame` (≤ MAX_FRAME_PAYLOAD) and text frames are small JSON controls, so
/// the axum default (64 MiB) would let a peer allocate 64 MiB before our
/// decode rejects it. +64 covers the frame header.
const WS_MAX_MESSAGE: usize = MAX_FRAME_PAYLOAD + 64;
/// Read-idle timeout: the client heartbeats every 30 s, so a healthy session
/// always produces traffic well inside 90 s. A silent socket (dead peer, NAT
/// blackhole) is reaped instead of occupying a session slot until TTL.
const READ_IDLE: Duration = Duration::from_secs(90);
/// After teardown begins, how long to let the writer flush pending frames
/// before force-closing the socket (a client that ignores `kill` must not
/// leak the writer task).
const CLOSE_GRACE: Duration = Duration::from_millis(500);

pub async fn ws_handler(
    State(state): State<BrokerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    // Register runs an O(#tokens) argon2 verify per connection — per-IP
    // rate-limited so an unauthenticated attacker cannot drive unbounded
    // CPU work (see rate_limit.rs).
    if !state.register_limiter.allow(Some(peer.ip())) {
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    ws.max_message_size(WS_MAX_MESSAGE)
        .on_upgrade(move |socket| run(socket, state, peer))
}

async fn run(ws: WebSocket, state: BrokerState, peer: std::net::SocketAddr) {
    // All outbound traffic (frames + control text) flows through one queue so
    // the socket is written by exactly one task.
    let (ws_tx, mut ws_rx) = mpsc::channel::<Message>(WS_QUEUE_CAP);
    let (kill_tx, mut kill_rx) = watch::channel(None);
    let (mut sink, mut stream) = ws.split();

    // Writer: drains the queue into the socket. Exits when every sender has
    // dropped (mux + all stream pumps), which closes the WS.
    let mut writer = tokio::spawn(async move {
        while let Some(msg) = ws_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    // --- register handshake -------------------------------------------------
    let register = match tokio::time::timeout(REGISTER_TIMEOUT, async {
        while let Some(Ok(Message::Text(t))) = stream.next().await {
            match serde_json::from_str::<Control>(t.as_str()) {
                Ok(Control::Register {
                    token,
                    want_tcp,
                    want_http,
                    want_udp,
                    udp_port,
                    subdomain_hint,
                }) => {
                    return Some((
                        token,
                        want_tcp,
                        want_http,
                        want_udp,
                        udp_port,
                        subdomain_hint,
                    ));
                }
                _ => continue, // ignore non-register frames pre-handshake
            }
        }
        None
    })
    .await
    {
        Ok(Some(r)) => r,
        _ => return, // timeout or closed without a valid register
    };

    // One-time setup codes (`sc_...`) resolve to their bound token: the
    // download-my-client script carries a code instead of the token secret,
    // so the raw secret never leaves the broker. Single-use + expiry enforced
    // by SetupStore::consume.
    // One-time setup codes (`sc_...`) resolve to their bound token. `peek`
    // resolves without consuming; the code is atomically claimed only AFTER
    // the token-enabled and token-balance gates pass, so a rejected connect
    // never burns the code AND two concurrent connects with one code yield
    // exactly one winner.
    let (token_record, setup_code) = if register.0.starts_with("sc_") {
        let Some(code) = state.setup.peek(&register.0) else {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::TokenInvalid,
                })))
                .await;
            return;
        };
        let Some(record) = state.config.token_store.get(&code.token_id).await else {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::TokenInvalid,
                })))
                .await;
            return;
        };
        if !record.enabled {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::TokenInvalid,
                })))
                .await;
            return;
        }
        (record, Some(register.0.clone()))
    } else {
        let Some(record) = state.config.token_store.validate(&register.0).await else {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::TokenInvalid,
                })))
                .await;
            return;
        };
        (record, None)
    };
    // Entitlement: tokens carry their own operator-set limits.
    let limits = state.entitle(&token_record).await;
    if limits.rate_limit_rpm > 0 && state.config.redis_url.is_none() {
        tracing::warn!(
            token = %token_record.id,
            rpm = limits.rate_limit_rpm,
            "token has rate_limit_rpm but Redis is not configured — per-tunnel \
             rpm is NOT enforced in SQLite-only mode"
        );
    }
    // Atomically claim the one-shot code — a concurrent connect that already
    // consumed it loses here and is rejected.
    if let Some(code) = &setup_code
        && !state.setup.consume_claimed(code)
    {
        let _ = ws_tx
            .send(Message::Text(control_json(&Control::Error {
                code: ErrorCode::TokenInvalid,
            })))
            .await;
        return;
    }

    // Resolve the token's tunnel profile: fixed slug + custom host + HTTP
    // options from the profile store; fall back to random slug + defaults.
    let (preferred_slug, custom_host, http_options) = {
        let profile = state
            .tunnels
            .resolve_for_token(&token_record.id, register.5.as_deref())
            .await
            .unwrap_or(None);
        match profile {
            Some(p) => (p.subdomain, p.custom_hostname, p.options),
            None => (None, None, tunnel::HttpOptions::default()),
        }
    };

    let session = match state.registry.allocate(
        token_record.id.clone(),
        register.1,
        register.2,
        register.3,
        register.4,
        limits,
        ws_tx.clone(),
        kill_tx,
        preferred_slug,
        custom_host,
        http_options,
    ) {
        Ok(s) => s,
        Err(AllocError::ServerFull { .. }) => {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::ServerFull,
                })))
                .await;
            let s = state
                .settings
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            settings::send_webhook(
                &s,
                "server_full",
                settings::server_full_payload(&state.config.domain, state.registry.max_sessions()),
            );
            return;
        }
        Err(AllocError::Exhausted { .. }) | Err(AllocError::Taken) => {
            let _ = ws_tx
                .send(Message::Text(control_json(&Control::Error {
                    code: ErrorCode::NoSubdomainAvailable,
                })))
                .await;
            return;
        }
    };
    session.set_peer_ip(peer.ip());

    let reply = Control::Registered {
        http_url: session
            .want_http
            .then(|| state.config.http_url_for(&session.slug)),
        tcp_addr: session
            .want_tcp
            .then(|| state.config.tcp_addr_for(&session.slug)),
        session_secret: URL_SAFE_NO_PAD.encode(session.session_secret()),
        broker_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    let _ = ws_tx.send(Message::Text(control_json(&reply))).await;

    tracing::info!(
        session = %session.id,
        slug = %session.slug,
        token = %token_record.id,
        "client registered"
    );

    let watchdog = tokio::spawn(quota::watch(
        session.clone(),
        state.config.watchdog_interval,
        state.settings.clone(),
    ));

    // --- main loop: route client frames + controls, observe kills ------------
    // Control-plane token bucket (text frames only): a client must not be
    // able to flood the JSON/Pong path at the expense of real traffic.
    // Binary frames are bounded by the stream + queue caps instead.
    let mut ctl = ControlLimiter::new(20.0, 10.0);
    // Heartbeats carry a monotonic seq; a lower-or-equal value is either a
    // misbehaving or a replaying client — protocol violation, close.
    let mut last_seq: u64 = 0;
    // Drain: watch sends true once (stop()). A subscribe() that lands after
    // the send captures the current version, so changed() would never fire —
    // check borrow() immediately to catch an already-signaled drain (e.g. a
    // session accepted in the accept-loop's poll window after stop()).
    let mut drain_rx = state.drain.subscribe();
    if *drain_rx.borrow() {
        let usage = session.usage();
        let _ = ws_tx
            .send(Message::Text(control_json(&Control::Quota { usage })))
            .await;
        let _ = ws_tx
            .send(Message::Text(control_json(&Control::Kill {
                reason: KillReason::Admin,
            })))
            .await;
        session.kill(KillReason::Admin);
        return;
    }
    {
        let s = state
            .settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let payload =
            settings::session_payload(&session, &state.config.domain, state.config.max_sessions);
        settings::send_webhook(&s, "session_started", payload);
        crate::http_app::email_alert(
            &s,
            &state,
            "Tunnel session started",
            &format!("Session {} (slug {}) started.", session.id, session.slug),
        );
    }
    loop {
        tokio::select! {
            biased;
            _ = drain_rx.changed() => {
                if *drain_rx.borrow() {
                    let usage = session.usage();
                    let _ = ws_tx.send(Message::Text(control_json(&Control::Quota { usage }))).await;
                    let _ = ws_tx.send(Message::Text(control_json(&Control::Kill { reason: KillReason::Admin }))).await;
                    session.kill(KillReason::Admin);
                    break;
                }
            }
            msg = tokio::time::timeout(READ_IDLE, stream.next()) => {
                match msg {
                    Err(_) => {
                        // No frame at all for 90 s — dead peer / NAT blackhole.
                        // The client heartbeats every 30 s, so this never trips
                        // on a healthy tunnel.
                        tracing::debug!("client read-idle timeout");
                        break;
                    }
                    Ok(Some(Ok(Message::Text(t)))) => {
                        match serde_json::from_str::<Control>(t.as_str()) {
                            Ok(Control::Heartbeat { seq }) => {
                                if seq <= last_seq {
                                    tracing::warn!(seq, last_seq, "non-monotonic heartbeat seq");
                                    break;
                                }
                                last_seq = seq;
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                let _ = ws_tx
                                    .send(Message::Text(control_json(&Control::Pong { seq })))
                                    .await;
                            }
                            Ok(Control::P2pAnswer { ticket, sdp, ice }) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                let json = serde_json::json!({
                                    "type": "answer",
                                    "sdp": sdp,
                                    "ice": ice,
                                })
                                .to_string();
                                if let Some(tx) = state.p2p_visitors.get(&ticket) {
                                    // try_send: a slow visitor never blocks the mux.
                                    let _ = tx.try_send(json);
                                }
                            }
                            Ok(Control::P2pIce { ticket, candidate }) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                let json = serde_json::json!({
                                    "type": "ice",
                                    "candidate": candidate,
                                })
                                .to_string();
                                if let Some(tx) = state.p2p_visitors.get(&ticket) {
                                    let _ = tx.try_send(json);
                                }
                            }
                            Ok(Control::P2pReady { ticket }) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                tracing::info!(ticket, "p2p channel ready");
                            }
                            Ok(Control::P2pFailed { ticket, reason }) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                tracing::warn!(ticket, %reason, "p2p failed");
                            }
                            Ok(Control::UsageReport { bytes_tx, bytes_rx, .. }) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                session.record_tx(bytes_tx as usize);
                                session.record_rx(bytes_rx as usize);
                            }
                            Ok(_) => {
                                if !ctl.allow() {
                                    tracing::warn!("control message flood");
                                    break;
                                }
                                /* post-register: nothing else expected */
                            }
                            Err(e) => tracing::warn!(error = %e, "bad control json from client"),
                        }
                    }
                    Ok(Some(Ok(Message::Binary(b)))) => {
                        match Frame::decode(&b) {
                            Ok(frame) => route_frame(&session, frame).await,
                            Err(e) => tracing::warn!(error = %e, "bad frame from client"),
                        }
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) => break,
                    Ok(Some(Ok(_))) => { /* WS ping/pong handled by the transport */ }
                    Ok(Some(Err(e))) => {
                        tracing::debug!(error = %e, "ws read error");
                        break;
                    }
                }
            }
            changed = kill_rx.changed() => {
                if changed.is_ok() {
                    let reason = *kill_rx.borrow();
                    if let Some(reason) = reason {
                        let usage = session.usage();
                        let _ = ws_tx.send(Message::Text(control_json(&Control::Quota { usage }))).await;
                        let _ = ws_tx.send(Message::Text(control_json(&Control::Kill { reason }))).await;
                    }
                }
                break;
            }
        }
    }

    // --- teardown ------------------------------------------------------------
    session.set_end_reason(match *kill_rx.borrow() {
        Some(KillReason::QuotaExceeded) => crate::session::EndReason::QuotaExceeded,
        Some(KillReason::TtlExpired) => crate::session::EndReason::TtlExpired,
        Some(KillReason::Admin) => crate::session::EndReason::Error("killed by admin".into()),
        Some(KillReason::TokenExhausted) => {
            crate::session::EndReason::Error("token exhausted".into())
        }
        None => crate::session::EndReason::ClientClosed,
    });
    watchdog.abort();
    state.registry.remove(&session.slug);
    // Free the dashboard traffic-ring entry for this slug — without this the
    // map grows one entry per session, forever.
    state.traffic.remove(&session.slug);
    // Clear the stream table first: pumps see their from-client channels close,
    // unwind, and drop their ws_tx clones. Then drop our own sender AND the
    // session reference (its `ws_tx` field would otherwise keep the writer's
    // queue open forever). No Close frame is needed — the client already
    // received `kill` (or saw the register fail).
    session.streams.clear();
    drop(ws_tx);
    {
        let s = state
            .settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let payload =
            settings::session_payload(&session, &state.config.domain, state.config.max_sessions);
        settings::send_webhook(&s, "session_ended", payload);
        crate::http_app::email_alert(
            &s,
            &state,
            "Tunnel session ended",
            &format!("Session {} (slug {}) ended.", session.id, session.slug),
        );
    }
    drop(session);
    // Drain whatever the writer still has (quota/kill frames), then make sure
    // the socket closes even if the client never responds.
    tokio::select! {
        _ = &mut writer => {}
        _ = tokio::time::sleep(CLOSE_GRACE) => writer.abort(),
    }
}

/// Route one client frame to its stream's sink; unknown streams are dropped.
async fn route_frame(session: &TunnelSession, frame: Frame) {
    let Some(tx) = session.streams.get(&frame.stream_id).map(|g| g.clone()) else {
        tracing::debug!(stream = frame.stream_id, "frame for unknown stream");
        return;
    };
    if frame.opcode == Opcode::Data {
        session.record_rx(frame.payload.len());
    }
    let _ = tx.send(frame).await;
}

pub(crate) fn control_json(c: &Control) -> Utf8Bytes {
    serde_json::to_string(c)
        .expect("control messages serialize")
        .into()
}

/// Per-session token bucket for control (text) frames. Distinct from the
/// per-IP `register_limiter`: this one is per connection, keyed on nothing
/// but the session itself, and starts full so a freshly registered client
/// can send its normal heartbeats without friction.
struct ControlLimiter {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: std::time::Instant,
}

impl ControlLimiter {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last: std::time::Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod control_limiter_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn burst_then_block() {
        let mut c = ControlLimiter::new(3.0, 1.0);
        assert!(c.allow());
        assert!(c.allow());
        assert!(c.allow());
        assert!(!c.allow(), "burst of 3 exhausted");
    }

    #[test]
    fn refills_over_time() {
        let mut c = ControlLimiter::new(1.0, 2.0);
        assert!(c.allow());
        assert!(!c.allow());
        // 0.6 s at 2/s → 1.2 tokens → allowed again.
        c.last -= Duration::from_millis(600);
        assert!(c.allow(), "refill after 600 ms at 2/s");
    }
}
