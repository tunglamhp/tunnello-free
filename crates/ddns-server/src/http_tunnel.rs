//! HTTP(S) tunnel: a visitor request arriving at the broker with
//! `Host: <slug>.<domain>` is forwarded to the client's local service over a
//! mux stream. Request head + body flow server→client as OPEN + DATA; the
//! response head + body flow client→server as OPEN_ACK + DATA; CLOSE ends it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::header::{CONNECTION, HOST, RETRY_AFTER, TE, TRAILER, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use ddns_proto::frame::CLOSE_APP_ERROR;
use ddns_proto::{Frame, Opcode, OpenMeta, StreamKind};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::session::{DATA_CHUNK_MAX, STREAM_QUEUE_CAP, TunnelSession};

/// How long to wait for the client's OPEN_ACK (response head) after OPEN.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Marker extension attached to every response served through the tunnel.
/// The broker's outermost `security_headers` middleware skips its CSP/HSTS
/// header injection for these responses — they belong to the customer's own
/// site, not the broker UI, so the broker's CSP would break the customer's
/// external resources. The same-origin check is skipped from the request side
/// (`resolve_tunnel`) since it must run before the handler.
#[derive(Clone, Copy, Debug)]
pub struct TunneledResponse;

pub async fn serve_tunnel(
    req: Request<Body>,
    session: Arc<TunnelSession>,
    peer: SocketAddr,
    quota: Option<&crate::quota::RateLimiter>,
    account_id: Option<i64>,
) -> Response {
    let mut response = serve_tunnel_inner(req, session, peer, quota, account_id).await;
    response.extensions_mut().insert(TunneledResponse);
    response
}

async fn serve_tunnel_inner(
    mut req: Request<Body>,
    session: Arc<TunnelSession>,
    peer: SocketAddr,
    quota: Option<&crate::quota::RateLimiter>,
    account_id: Option<i64>,
) -> Response {
    if !session.want_http {
        return StatusCode::NOT_FOUND.into_response();
    }
    // One visitor request (even a rejected one) is metered usage.
    session.record_request();
    crate::metrics::requests_total()
        .with_label_values(&[&session.slug])
        .inc();
    // Per-tunnel HTTP options (auth, whitelist, header mutations) short-circuit
    // BEFORE any stream quota is consumed — rejected visitors never open a
    // stream on the client, and they never consume a rate-limit window tick
    // either, so an unauthenticated flood cannot exhaust a tenant's rpm budget.
    if let Some(resp) = crate::http_options::apply(&mut req, peer.ip(), session.http_options()) {
        return resp;
    }
    if let (Some(quota), Some(account_id)) = (quota, account_id) {
        let rpm = session.limits.rate_limit_rpm;
        if rpm > 0
            && let Err(limited) = quota.check(account_id, &session.slug, peer.ip(), rpm).await
        {
            crate::metrics::ratelimit_429_total().inc();
            return rate_limited_response(limited);
        }
    }
    if !session.register_stream() {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many streams").into_response();
    }
    let stream_id = session.next_stream_id();
    serve_inner(req, session, peer, stream_id).await
}

/// `429` + `Retry-After` (seconds until the window resets), plain-text body.
fn rate_limited_response(limited: crate::quota::RateLimited) -> Response {
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    resp.headers_mut().insert(
        RETRY_AFTER,
        HeaderValue::from_str(&limited.retry_after_secs.to_string())
            .expect("numeric Retry-After is a valid header value"),
    );
    resp
}

/// Abort the request-body pump and free the stream slot. Every error path in
/// `serve_inner` ends here; the success path hands both pumps to a background
/// cleanup task instead.
fn abort_stream(session: &TunnelSession, stream_id: u32, body_pump: &tokio::task::JoinHandle<()>) {
    body_pump.abort();
    session.streams.remove(&stream_id);
    session.release_stream();
}

async fn serve_inner(
    req: Request<Body>,
    session: Arc<TunnelSession>,
    peer: SocketAddr,
    stream_id: u32,
) -> Response {
    let debug_started = std::time::Instant::now();
    let capture = session.http_options().debug_capture;
    let captured_headers = if capture {
        crate::debug_capture::redact_headers(
            &req.headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    } else {
        Vec::new()
    };
    let captured_req: std::sync::Arc<parking_lot::Mutex<Vec<u8>>> = Default::default();
    let captured_resp: std::sync::Arc<parking_lot::Mutex<Vec<u8>>> = Default::default();
    // Cleanup-task handles first: the pumps below move their own clones.
    let cleanup_req = captured_req.clone();
    let cleanup_resp = captured_resp.clone();
    let debug_method = req.method().as_str().to_string();
    let debug_path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let debug_peer = peer.ip().to_string();

    // --- OPEN: request head --------------------------------------------------
    // Serialize the request head (hop-by-hop headers stripped; canonical Host
    // and X-Forwarded-For set) for the client to forward verbatim.
    let target = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    // Detect WebSocket upgrade: Connection has "Upgrade" AND Upgrade header is websocket.
    let is_ws_upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && req
            .headers()
            .get(CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);

    let keep_alive = HeaderName::from_static("keep-alive");
    let x_forwarded_for = HeaderName::from_static("x-forwarded-for");
    let x_tunnello_relay = HeaderName::from_static("x-tunnello-relay");
    let mut req_headers: Vec<(String, String)> = Vec::new();
    for (k, v) in req.headers() {
        if *k == HOST
            || *k == TRANSFER_ENCODING
            || *k == keep_alive
            || *k == TE
            || *k == TRAILER
            || *k == x_forwarded_for
            || *k == x_tunnello_relay
        {
            continue;
        }
        // For WS upgrades, forward Upgrade and Connection headers so the local
        // app sees a proper upgrade request.
        if is_ws_upgrade && (*k == CONNECTION || *k == UPGRADE) {
            continue;
        }
        req_headers.push((
            k.as_str().to_string(),
            String::from_utf8_lossy(v.as_bytes()).into_owned(),
        ));
    }
    req_headers.push(("Host".to_string(), req_host(&req)));
    req_headers.push(("X-Forwarded-For".to_string(), peer.ip().to_string()));
    let head = Bytes::from(ddns_proto::http::build_http_head(
        req.method().as_str(),
        target,
        &req_headers,
    ));
    let mut payload = Vec::new();
    let open_meta = OpenMeta {
        kind: StreamKind::Http,
        port: 0,
        head: Some(head.clone()),
    };
    if open_meta.encode(&mut payload).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (from_client_tx, mut from_client_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session.streams.insert(stream_id, from_client_tx);

    if !session
        .send_frame(&Frame {
            opcode: Opcode::Open,
            stream_id,
            payload: Bytes::from(payload),
        })
        .await
    {
        // Client is gone: free the slot we just reserved so a dead stream
        // cannot pin active_streams (and trip stream caps) until teardown.
        session.streams.remove(&stream_id);
        session.release_stream();
        return StatusCode::BAD_GATEWAY.into_response();
    }

    // --- request body pump (visitor → client) --------------------------------
    let session2 = session.clone();
    let captured_req = captured_req.clone();
    let body_pump = tokio::spawn(async move {
        let mut body = req.into_body();
        while let Some(Ok(frame)) = body.frame().await {
            let Ok(data) = frame.into_data() else {
                continue;
            }; // trailers: dropped in v1
            if capture {
                let mut buf = captured_req.lock();
                let room = crate::debug_capture::CAPTURE_LIMIT.saturating_sub(buf.len());
                if room > 0 {
                    buf.extend_from_slice(&data[..data.len().min(room)]);
                }
            }
            session2.record_tx(data.len());
            crate::metrics::bytes_total().inc_by(data.len() as u64);
            for chunk in data.chunks(DATA_CHUNK_MAX) {
                let f = Frame {
                    opcode: Opcode::Data,
                    stream_id,
                    payload: Bytes::copy_from_slice(chunk),
                };
                if !session2.send_frame(&f).await {
                    return;
                }
            }
        }
    });

    // --- response assembly (client → visitor) --------------------------------
    let head_frame = match tokio::time::timeout(HEAD_TIMEOUT, from_client_rx.recv()).await {
        Ok(Some(f)) => f,
        _ => {
            let _ = session
                .send_frame(&Frame {
                    opcode: Opcode::Close,
                    stream_id,
                    payload: Bytes::from_static(&[CLOSE_APP_ERROR]),
                })
                .await;
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let response_head = match head_frame.opcode {
        Opcode::OpenAck => head_frame.payload,
        Opcode::OpenReject => {
            let _ = session
                .send_frame(&Frame {
                    opcode: Opcode::Close,
                    stream_id,
                    payload: Bytes::from_static(&[CLOSE_APP_ERROR]),
                })
                .await;
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
        Opcode::Close => {
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
        other => {
            tracing::warn!(
                stream = stream_id,
                ?other,
                "unexpected first response frame"
            );
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // WebSocket upgrade: if the local app responded 101, switch to a
    // bidirectional byte relay. The visitor gets a 101 + streaming body
    // that carries DATA frames transparently.
    if response_head.starts_with(b"HTTP/1.1 101") || response_head.starts_with(b"HTTP/1.0 101") {
        // Forward the 101 head back to visitor via hyper's streaming body
        // (hyper handles sending the headers; we just need a persistent stream)
        //
        // Build a minimal 101 response and use the existing streaming mechanism.
        // The key insight: after 101, both sides speak WebSocket binary frames.
        // The broker relays: visitor TCP ←→ tunnel DATA frames.

        // Send 101 head to client's stream so it knows upgrade succeeded
        // (the local app already sent it via OpenAck).

        // Return a streaming response that acts as a raw pipe:
        // - from_client_rx → visitor body (client → visitor direction)
        // - body_pump → sends visitor bytes as DATA frames (visitor → client)

        // The existing body_pump already forwards visitor→client.
        // The `forward` task below already forwards client→visitor.
        // So we just need to return a streaming response with no content-length
        // and hyper will keep the connection alive for bidirectional relay.

        let resp = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .body(Body::empty())
            .unwrap();

        // Spawn cleanup: when either side disconnects, release the stream slot
        let session5 = session.clone();
        let sid = stream_id;
        tokio::spawn(async move {
            // Wait for the body_pump to finish (= visitor disconnected)
            let _ = body_pump.await;
            // Send CLOSE to client so it closes the local app connection
            let _ = session5
                .send_frame(&Frame {
                    opcode: Opcode::Close,
                    stream_id: sid,
                    payload: Bytes::from_static(&[0x00]), // ok
                })
                .await;
            session5.streams.remove(&sid);
            session5.release_stream();
        });

        return resp;
    }

    if !response_head.starts_with(b"HTTP/") {
        abort_stream(&session, stream_id, &body_pump);
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let (code, header_list) = match ddns_proto::http::parse_http_head(&response_head) {
        Some(p) => p,
        None => {
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let status = match StatusCode::from_u16(code) {
        Ok(s) => s,
        Err(_) => {
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let mut builder = Response::builder().status(status);
    // Hop-by-hop headers describe the client<->local-app hop, not the
    // broker<->visitor hop — strip them (mirrors the request-head builder).
    let keep_alive = HeaderName::from_static("keep-alive");
    for (k, v) in header_list {
        let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else {
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        };
        let Ok(value) = HeaderValue::from_str(&v) else {
            abort_stream(&session, stream_id, &body_pump);
            return StatusCode::BAD_GATEWAY.into_response();
        };
        if name == CONNECTION
            || name == TRANSFER_ENCODING
            || name == keep_alive
            || name == TE
            || name == TRAILER
            || name == UPGRADE
        {
            continue;
        }
        builder = builder.header(name, value);
    }

    // Response body: DATA frames → streamed body; CLOSE ends it.
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(STREAM_QUEUE_CAP);
    let session3 = session.clone();
    let captured_resp = captured_resp.clone();
    let forward = tokio::spawn(async move {
        while let Some(f) = from_client_rx.recv().await {
            match f.opcode {
                Opcode::Data => {
                    session3.record_rx(f.payload.len());
                    crate::metrics::bytes_total().inc_by(f.payload.len() as u64);
                    if capture {
                        let mut buf = captured_resp.lock();
                        let room = crate::debug_capture::CAPTURE_LIMIT.saturating_sub(buf.len());
                        if room > 0 {
                            buf.extend_from_slice(&f.payload[..f.payload.len().min(room)]);
                        }
                    }
                    if body_tx.send(f.payload).await.is_err() {
                        return;
                    }
                }
                Opcode::Close => return,
                _ => {}
            }
        }
    });
    let body_stream = ReceiverStream::new(body_rx).map(Ok::<_, std::io::Error>);
    let body = Body::from_stream(body_stream);
    let resp = match builder.body(body) {
        Ok(r) => r,
        Err(_) => {
            body_pump.abort();
            forward.abort();
            session.streams.remove(&stream_id);
            session.release_stream();
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // Return the response immediately so hyper can stream the body as DATA
    // frames arrive. The pumps drain in the background; the stream slot is
    // released when both finish (or when the session dies, which closes
    // from_client_rx and ends `forward`). Awaiting `forward` here would
    // deadlock once the client sends more than STREAM_QUEUE_CAP DATA frames —
    // nobody polls `body_rx` until the response is returned.
    let session4 = session.clone();
    let status = resp.status().as_u16();
    let captured_req = cleanup_req;
    let captured_resp = cleanup_resp;
    tokio::spawn(async move {
        let _ = body_pump.await;
        let _ = forward.await;
        // Record once both directions finish so captured bodies are complete.
        let (req_body, resp_body) = if capture {
            (
                Some(crate::debug_capture::truncate_body(&captured_req.lock())),
                Some(crate::debug_capture::truncate_body(&captured_resp.lock())),
            )
        } else {
            (None, None)
        };
        session4.record_debug(crate::session::DebugEntry {
            at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            method: debug_method,
            path: debug_path,
            status,
            duration_ms: debug_started.elapsed().as_millis() as u64,
            bytes_tx: 0,
            bytes_rx: 0,
            peer_ip: debug_peer,
            req_headers: captured_headers,
            req_body,
            resp_body,
        });
        session4.streams.remove(&stream_id);
        session4.release_stream();
    });
    resp
}

/// HTTP/1.1 keeps the host in the `Host` header; h2 carries it in the
/// `:authority` pseudo-header (which hyper exposes on the URI) — fall back to
/// that so h2 visitors get a correct forwarded `Host`.
fn req_host(req: &Request<Body>) -> String {
    req.headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
        .unwrap_or_default()
}
