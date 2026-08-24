//! One tunnel session = one registered WS connection from a client.
//! Owns quota counters, the TTL deadline, the per-stream frame table, and the
//! outbound WS queue handle (frames flow: pumps → ws_tx → writer task → socket).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::ws::Message;
use bytes::Bytes;
use dashmap::DashMap;
use ddns_proto::{Frame, KillReason, TokenLimits, Usage};
use rand::Rng;
use tokio::sync::mpsc;
use tokio::sync::watch;

use crate::tunnel::HttpOptions;

/// Max frames queued on the shared outbound WS queue.
/// Session-level outbound WS queue. 16 × 256 KiB = 4 MiB max in-flight per
/// session; the bounded channel back-pressures the visitor read when the
/// client is slow instead of buffering unboundedly.
pub const WS_QUEUE_CAP: usize = 16;
/// Max queued frames per stream (≈ 64 KiB in flight with 8 KiB chunks).
pub const STREAM_QUEUE_CAP: usize = 8;
/// Server → client DATA payload cap; bounds in-flight bytes per stream.
/// 256 KiB keeps per-frame overhead negligible on large transfers while
/// bounding in-flight memory (queue × chunk ≈ 4 MiB per session worst case).
/// Measured: 256 KiB ≈ 512 KiB throughput (the bottleneck is the network
/// bridge, not frame count), so the smaller chunk wins on memory.
pub const DATA_CHUNK_MAX: usize = 256 * 1024;

/// Why a session ended. Recorded for observability (Plan 3 surfaces it in the
/// operator dashboard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndReason {
    QuotaExceeded,
    TtlExpired,
    ClientClosed,
    ServerShutdown,
    Error(String),
}

pub struct TunnelSession {
    pub id: String,
    pub token_id: String,
    pub slug: String,
    pub want_tcp: bool,
    pub want_http: bool,
    pub limits: TokenLimits,
    /// Server-wide hard cap on concurrent streams (independent of the token's
    /// `max_streams`; 0 disables). Bounds broker memory even when a token is
    /// configured unlimited.
    server_max_streams: usize,
    pub created_at: Instant,
    /// Peak concurrent streams — observability for the dashboard.
    pub streams_peak: AtomicU32,
    /// Visitor HTTP requests handled this session (commercial metering).
    pub requests: AtomicU64,
    /// Direct peer address observed during client registration.
    peer_ip: std::sync::RwLock<Option<IpAddr>>,
    ttl_deadline: Instant,
    /// Visitor → client bytes (server sends).
    bytes_tx: AtomicU64,
    /// Client → visitor bytes (server receives).
    bytes_rx: AtomicU64,
    /// Watermarks of bytes already rolled into `usage_daily`; `take_usage_delta`
    /// swaps them with the live counters (monotonic, self-correcting).
    rolled_tx: AtomicU64,
    rolled_rx: AtomicU64,
    /// Watermark of requests already metered into `usage_daily`; mirrors the
    /// byte watermarks so the 5-min rollup and the session-end flush split
    /// request deltas without double-charging.
    rolled_requests: AtomicU64,
    active_streams: AtomicU32,
    next_stream_id: AtomicU32,
    /// Outbound WS queue (frames + control text messages → writer task).
    ws_tx: mpsc::Sender<Message>,
    /// stream_id → client-frame sink (the WS read loop routes incoming frames
    /// into the owning pump's channel via these senders).
    pub streams: DashMap<u32, mpsc::Sender<Frame>>,
    /// Kill signal; the mux loop owns the receiver half.
    kill_tx: watch::Sender<Option<KillReason>>,
    end_reason: std::sync::Mutex<Option<EndReason>>,
    /// Per-tunnel HTTP options (auth, whitelist, header mutations) applied
    /// in the HTTP bridge before forwarding.
    http_options: HttpOptions,
    /// Random 32-byte secret for this session, delivered to the client in
    /// `registered` and used to sign P2P visitor tickets. Memory-only.
    session_secret: [u8; 32],
}

impl TunnelSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: String,
        slug: String,
        want_tcp: bool,
        want_http: bool,
        limits: TokenLimits,
        ws_tx: mpsc::Sender<Message>,
        kill_tx: watch::Sender<Option<KillReason>>,
        http_options: HttpOptions,
        server_max_streams: usize,
    ) -> Arc<Self> {
        let id = format!("{:016x}", rand::rng().random::<u64>());
        let now = Instant::now();
        let mut session_secret = [0u8; 32];
        rand::rng().fill(&mut session_secret);
        Arc::new(Self {
            id,
            token_id,
            slug,
            want_tcp,
            want_http,
            limits,
            server_max_streams,
            created_at: now,
            streams_peak: AtomicU32::new(0),
            requests: AtomicU64::new(0),
            peer_ip: std::sync::RwLock::new(None),
            ttl_deadline: now + Duration::from_secs(limits.ttl_secs),
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            rolled_tx: AtomicU64::new(0),
            rolled_rx: AtomicU64::new(0),
            rolled_requests: AtomicU64::new(0),
            active_streams: AtomicU32::new(0),
            next_stream_id: AtomicU32::new(0),
            ws_tx,
            streams: DashMap::new(),
            kill_tx,
            end_reason: std::sync::Mutex::new(None),
            http_options,
            session_secret,
        })
    }

    pub fn http_options(&self) -> &HttpOptions {
        &self.http_options
    }

    pub fn session_secret(&self) -> [u8; 32] {
        self.session_secret
    }

    /// Outbound WS queue (frames + control text) — cloned for the signaling
    /// relay so `p2p_signal` can send `p2p_visitor_offer`/`p2p_ice` to the
    /// client over the same queue the mux writes to.
    pub(crate) fn ws_tx(&self) -> mpsc::Sender<Message> {
        self.ws_tx.clone()
    }

    pub fn usage(&self) -> Usage {
        Usage {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            streams: self.active_streams.load(Ordering::Relaxed),
        }
    }

    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_peer_ip(&self, peer_ip: IpAddr) {
        *self.peer_ip.write().unwrap_or_else(|p| p.into_inner()) = Some(peer_ip);
    }

    pub fn peer_ip(&self) -> Option<IpAddr> {
        *self.peer_ip.read().unwrap_or_else(|p| p.into_inner())
    }

    pub fn record_tx(&self, n: usize) {
        self.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn record_rx(&self, n: usize) {
        self.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Bytes recorded since the last rollup (tx, rx). Swaps the watermark with
    /// the current counters, so concurrent callers split the delta — never
    /// double-count, never lose bytes (a late increment is caught next pass).
    pub fn take_usage_delta(&self) -> (u64, u64) {
        let tx = self.bytes_tx.load(Ordering::Relaxed);
        let rx = self.bytes_rx.load(Ordering::Relaxed);
        let ptx = self.rolled_tx.swap(tx, Ordering::Relaxed);
        let prx = self.rolled_rx.swap(rx, Ordering::Relaxed);
        (tx - ptx, rx - prx)
    }

    /// Requests recorded since the last metering pass. Mirrors the byte
    /// watermark swap: concurrent callers split the delta, never double-count.
    pub fn take_requests_delta(&self) -> u64 {
        let cur = self.requests.load(Ordering::Relaxed);
        let prev = self.rolled_requests.swap(cur, Ordering::Relaxed);
        cur - prev
    }

    /// Monotonic stream id, starting at 1.
    pub fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reserve a stream slot; false when `max_streams` is already reached
    /// (0 = unlimited, never rejects) or the server-wide per-session cap is
    /// reached. Peak counter still tracks.
    pub fn register_stream(&self) -> bool {
        let cur = self.active_streams.fetch_add(1, Ordering::Relaxed);
        if self.limits.max_streams > 0 && cur >= self.limits.max_streams {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        if self.server_max_streams > 0 && cur as usize >= self.server_max_streams {
            self.active_streams.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        self.streams_peak.fetch_max(cur + 1, Ordering::Relaxed);
        true
    }

    pub fn expired(&self) -> bool {
        self.limits.ttl_secs > 0 && Instant::now() >= self.ttl_deadline
    }

    pub fn release_stream(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    /// tx + rx bytes metered, never throttled. 0 = unlimited, never over.
    pub fn over_quota(&self) -> bool {
        self.limits.max_bytes > 0
            && self
                .bytes_tx
                .load(Ordering::Relaxed)
                .saturating_add(self.bytes_rx.load(Ordering::Relaxed))
                >= self.limits.max_bytes
    }

    /// Request the mux loop to kill this session with the given reason.
    pub fn kill(&self, reason: KillReason) {
        let _ = self.kill_tx.send(Some(reason));
    }

    pub fn end_reason(&self) -> Option<EndReason> {
        self.end_reason.lock().unwrap().clone()
    }

    pub fn set_end_reason(&self, reason: EndReason) {
        *self.end_reason.lock().unwrap() = Some(reason);
    }

    /// Encode + queue one frame for the client. Best-effort: false when the
    /// outbound queue is gone (client disconnected) or the frame is invalid.
    pub async fn send_frame(&self, frame: &Frame) -> bool {
        let mut buf = Vec::with_capacity(9 + frame.payload.len());
        if frame.encode(&mut buf).is_err() {
            tracing::warn!("dropping oversized frame for stream {}", frame.stream_id);
            return false;
        }
        self.ws_tx
            .send(Message::Binary(Bytes::from(buf)))
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddns_proto::TokenLimits;

    fn unlimited() -> TokenLimits {
        TokenLimits {
            max_sessions: 0,
            max_streams: 0,
            max_bytes: 0,
            ttl_secs: 0,
            max_tunnels: 0,
            bandwidth_monthly: 0,
            max_clients: 0,
            rate_limit_rpm: 0,
        }
    }

    fn session(limits: TokenLimits) -> Arc<TunnelSession> {
        let (ws_tx, _ws_rx) = mpsc::channel(8);
        let (kill_tx, _kill_rx) = watch::channel(None);
        TunnelSession::new(
            "t-test".into(),
            "abc-12".into(),
            true,
            true,
            limits,
            ws_tx,
            kill_tx,
            Default::default(),
            512,
        )
    }

    #[test]
    fn unlimited_streams_never_reject_and_track_peak() {
        let s = session(unlimited());
        for _ in 0..100 {
            assert!(s.register_stream(), "max_streams=0 must never reject");
        }
        assert_eq!(s.streams_peak.load(Ordering::Relaxed), 100);
        for _ in 0..100 {
            s.release_stream();
        }
    }

    #[test]
    fn finite_streams_still_reject_at_cap() {
        let mut l = unlimited();
        l.max_streams = 2;
        let s = session(l);
        assert!(s.register_stream());
        assert!(s.register_stream());
        assert!(!s.register_stream(), "3rd stream must reject at cap 2");
    }

    #[test]
    fn server_wide_cap_bounds_unlimited_token() {
        // Token says unlimited; the server cap of 2 must still reject.
        let (ws_tx, _ws_rx) = mpsc::channel(8);
        let (kill_tx, _kill_rx) = watch::channel(None);
        let s = TunnelSession::new(
            "t".into(),
            "s".into(),
            true,
            true,
            unlimited(),
            ws_tx,
            kill_tx,
            Default::default(),
            2,
        );
        assert!(s.register_stream());
        assert!(s.register_stream());
        assert!(
            !s.register_stream(),
            "3rd stream must reject at server cap 2"
        );
    }

    #[test]
    fn unlimited_quota_never_over() {
        let s = session(unlimited());
        s.record_tx(u64::MAX as usize);
        s.record_rx(u64::MAX as usize);
        assert!(!s.over_quota(), "max_bytes=0 means no byte quota");
    }

    #[test]
    fn finite_quota_still_trips() {
        let mut l = unlimited();
        l.max_bytes = 100;
        let s = session(l);
        s.record_tx(60);
        s.record_rx(40);
        assert!(
            s.over_quota(),
            "100 metered bytes must trip a 100-byte quota"
        );
    }

    #[test]
    fn unlimited_ttl_never_expires() {
        let s = session(unlimited());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!s.expired(), "ttl_secs=0 means no expiry");
    }

    #[test]
    fn finite_ttl_still_expires() {
        let mut l = unlimited();
        l.ttl_secs = 1;
        let s = session(l);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(s.expired(), "1s TTL must expire after ~1.1s");
    }
}
