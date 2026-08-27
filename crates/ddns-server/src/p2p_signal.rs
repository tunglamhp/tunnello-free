//! Visitor-side signaling for the P2P data plane (spec §5.1). One short-lived
//! WebSocket per visitor attempt at `/__p2p/signal`: the broker issues a
//! `p2p_ticket`, relays the visitor's offer to the client's control WSS, and
//! relays the client's answer/ICE back to the visitor.
//!
//! Flow: visitor WS → `{hello|offer}` → broker → `Control::P2pVisitorOffer`
//!       client → `Control::P2pAnswer`/`P2pIce` → broker → `{answer|ice}` → visitor

use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::http::header;
use axum::response::Response;
use ddns_proto::Control;
use ddns_proto::ticket::issue_ticket;
use tokio::sync::mpsc;

use crate::http_app::BrokerState;
use crate::mux::control_json;
use crate::rate_limit::RateLimiter;

/// Visitor → broker signaling messages (snake_case type tags). `hello` carries
/// an explicit slug (used by the integration test and future native helpers);
/// the connector page sends `offer` and the slug is derived from `Host`.
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum VisitorMsg {
    Hello {
        slug: Option<String>,
        sdp: String,
        ice: Vec<String>,
        /// Visitor's WireGuard public key (exit-node mode; serde default so
        /// the browser connector's hello without it stays valid).
        #[serde(default)]
        wg_pubkey: Option<String>,
    },
    Offer {
        sdp: String,
        ice: Vec<String>,
    },
    Ice {
        candidate: String,
    },
}

/// Bound capacity of the ticket → visitor-sender queue. A slow visitor never
/// blocks the client's mux: relays use `try_send` and drop when full.
const VISITOR_QUEUE_CAP: usize = 8;

pub async fn signal_handler(
    State(state): State<BrokerState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    // The connector page always connects to `location.host` = `<slug>.<domain>`;
    // resolving the slug here is the same-origin check (the ticket still gates
    // the client). `hello` may also carry an explicit slug.
    let host_slug = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| visitor_slug(&state, h));
    ws.on_upgrade(move |socket| signal_run(socket, state, peer, host_slug))
}

/// Resolve a visitor's slug from a `Host` header value (port stripped,
/// lowercased): bound custom host first, then `slug.<active-apex>`.
fn visitor_slug(state: &BrokerState, host: &str) -> Option<String> {
    let host = crate::http_app::strip_port(host).to_ascii_lowercase();
    if let Some(s) = state.registry.custom_host(&host) {
        return Some(s.slug.clone());
    }
    let apex = state
        .active_apex
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()?;
    let suffix = format!(".{apex}");
    host.strip_suffix(&suffix)
        .filter(|s| !s.is_empty() && !s.contains('.'))
        .map(str::to_string)
}

async fn signal_run(
    mut ws: WebSocket,
    state: BrokerState,
    peer: std::net::SocketAddr,
    host_slug: Option<String>,
) {
    // Per-connection token bucket: a single visitor attempt must not be able to
    // flood the client's control WSS with ICE candidates.
    let limiter = RateLimiter::new(5, 5.0);

    // Phase 1: wait for the visitor's offer (`hello` or `offer`).
    let (ticket, session, mut rx) = loop {
        let Some(msg) = ws.recv().await else { return };
        let Ok(Message::Text(t)) = msg else { continue };
        if !limiter.allow(Some(peer.ip())) {
            tracing::warn!(peer = %peer.ip(), "p2p signal flood");
            return;
        }
        let Ok(vmsg) = serde_json::from_str::<VisitorMsg>(t.as_str()) else {
            continue;
        };
        let (slug, sdp, ice, wg_pubkey) = match vmsg {
            VisitorMsg::Hello {
                slug,
                sdp,
                ice,
                wg_pubkey,
            } => (slug.or_else(|| host_slug.clone()), sdp, ice, wg_pubkey),
            VisitorMsg::Offer { sdp, ice } => (host_slug.clone(), sdp, ice, None),
            VisitorMsg::Ice { .. } => {
                // ICE candidate before the offer: dropped (the connector page
                // always sends the offer first, then trickles candidates).
                continue;
            }
        };
        let Some(slug) = slug else { continue };
        let Some(session) = state.registry.lookup(&slug) else {
            let _ = ws.send(Message::Text(failed("session_gone"))).await;
            return;
        };
        // Format gate: a malformed pubkey is rejected up front (it can never
        // be a valid key, so key-age/store logic must not see it).
        if let Some(pk) = &wg_pubkey
            && !validate_wg_pubkey(pk)
        {
            let _ = ws.send(Message::Text(failed("bad_pubkey"))).await;
            return;
        }
        // Key-age enforcement: an exit-mode pubkey older than the policy
        // window is rejected until the visitor re-registers (spec §3.Broker).
        if let Some(pk) = &wg_pubkey
            && crate::keyage::key_age().expired(pk, crate::now_secs())
        {
            let _ = ws.send(Message::Text(failed("key_expired"))).await;
            return;
        }
        let ticket = issue_ticket(&session.session_secret(), &session.slug);
        let (tx, r) = mpsc::channel::<String>(VISITOR_QUEUE_CAP);
        state.p2p_visitors.insert(ticket.clone(), tx);
        if let Some(pk) = &wg_pubkey {
            crate::keyage::key_age().record(pk, crate::now_secs());
        }
        let control = Control::P2pVisitorOffer {
            ticket: ticket.clone(),
            sdp,
            ice,
            wg_pubkey,
        };
        if session
            .ws_tx()
            .send(Message::Text(control_json(&control)))
            .await
            .is_err()
        {
            // Client gone between lookup and relay.
            state.p2p_visitors.remove(&ticket);
            let _ = ws.send(Message::Text(failed("session_gone"))).await;
            return;
        }
        break (ticket, session, r);
    };

    // Phase 2: relay ICE (visitor → client) and answer/ICE (client → visitor).
    loop {
        tokio::select! {
            msg = ws.recv() => {
                let Some(msg) = msg else { break };
                let Ok(Message::Text(t)) = msg else { continue };
                if !limiter.allow(Some(peer.ip())) {
                    tracing::warn!(peer = %peer.ip(), "p2p signal flood");
                    break;
                }
                if let Ok(VisitorMsg::Ice { candidate }) =
                    serde_json::from_str::<VisitorMsg>(t.as_str())
                {
                    let control = Control::P2pIce { ticket: ticket.clone(), candidate };
                    if session
                        .ws_tx()
                        .send(Message::Text(control_json(&control)))
                        .await
                        .is_err()
                    {
                        break; // client gone
                    }
                }
            }
            relay = rx.recv() => {
                match relay {
                    Some(json) => {
                        let _ = ws.send(Message::Text(json.into())).await;
                    }
                    None => break, // client mux dropped the sender (session gone)
                }
            }
        }
    }

    state.p2p_visitors.remove(&ticket);
}

/// Serialize a visitor-facing `{type: failed, reason}` message.
/// Accept only well-formed WireGuard public keys: standard base64 decoding
/// to exactly 32 bytes (the client encodes `x25519` public keys that way).
/// Rejects junk before any key-age/store logic runs, so a malformed value
/// can neither poison the store nor be mistaken for a stale valid key.
fn validate_wg_pubkey(pk: &str) -> bool {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(pk)
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .is_some()
}

fn failed(reason: &str) -> Utf8Bytes {
    serde_json::json!({ "type": "failed", "reason": reason })
        .to_string()
        .into()
}
