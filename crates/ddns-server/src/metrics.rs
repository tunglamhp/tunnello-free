//! Prometheus metrics registry for the broker.
//!
//! A single process-wide [`Registry`] holds the `ddns_*` counters and gauges.
//! The `prometheus` workspace dep is pulled in with `default-features = false`
//! (text exposition only — no push gateway or process collectors), so the
//! registry starts empty and we register exactly the metrics defined here.

use std::sync::LazyLock;

use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

/// Visitor HTTP requests handled by the tunnel, labeled by tunnel slug.
static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "ddns_requests_total",
            "Visitor HTTP requests handled by the tunnel, labeled by tunnel slug.",
        ),
        &["tunnel"],
    )
    .expect("ddns_requests_total is a valid metric")
});

/// HTTP tunnel body bytes transferred (both directions).
static BYTES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    IntCounter::new(
        "ddns_bytes_total",
        "HTTP tunnel body bytes transferred (both directions).",
    )
    .expect("ddns_bytes_total is a valid metric")
});

/// Number of live tunnel sessions.
static ACTIVE_SESSIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new("ddns_active_sessions", "Number of live tunnel sessions.")
        .expect("ddns_active_sessions is a valid metric")
});

/// Visitor requests rejected with HTTP 429 by the rate limiter.
static RATELIMIT_429_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    IntCounter::new(
        "ddns_ratelimit_429_total",
        "Visitor requests rejected with HTTP 429 by the rate limiter.",
    )
    .expect("ddns_ratelimit_429_total is a valid metric")
});

/// Active P2P data channels bridged by the gateway.
static P2P_CHANNELS_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "ddns_p2p_channels_active",
        "Active WebRTC P2P data channels.",
    )
    .expect("ddns_p2p_channels_active is a valid metric")
});

/// Total P2P tunnel bytes relayed (tx+rx combined).
static P2P_BYTES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    IntCounter::new(
        "ddns_p2p_bytes_total",
        "P2P tunnel bytes transferred (both directions).",
    )
    .expect("ddns_p2p_bytes_total is a valid metric")
});

/// The single registry every metric above is registered with.
static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let registry = Registry::new();
    registry
        .register(Box::new(REQUESTS_TOTAL.clone()))
        .expect("register ddns_requests_total");
    registry
        .register(Box::new(BYTES_TOTAL.clone()))
        .expect("register ddns_bytes_total");
    registry
        .register(Box::new(ACTIVE_SESSIONS.clone()))
        .expect("register ddns_active_sessions");
    registry
        .register(Box::new(RATELIMIT_429_TOTAL.clone()))
        .expect("register ddns_ratelimit_429_total");
    registry
        .register(Box::new(P2P_CHANNELS_ACTIVE.clone()))
        .expect("register ddns_p2p_channels_active");
    registry
        .register(Box::new(P2P_BYTES_TOTAL.clone()))
        .expect("register ddns_p2p_bytes_total");
    registry
});

pub fn registry() -> &'static Registry {
    &REGISTRY
}

pub fn requests_total() -> &'static IntCounterVec {
    &REQUESTS_TOTAL
}

pub fn bytes_total() -> &'static IntCounter {
    &BYTES_TOTAL
}

pub fn active_sessions() -> &'static IntGauge {
    &ACTIVE_SESSIONS
}

pub fn ratelimit_429_total() -> &'static IntCounter {
    &RATELIMIT_429_TOTAL
}

/// Render the current metric values in the Prometheus text exposition format.
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let mut buf: Vec<u8> = Vec::new();
    encoder
        .encode(&REGISTRY.gather(), &mut buf)
        .expect("encoding registered metrics cannot fail");
    // The text exposition format is plain ASCII; non-UTF8 bytes are impossible
    // for metric/label names and values we define.
    String::from_utf8(buf).expect("metrics exposition is UTF-8")
}
