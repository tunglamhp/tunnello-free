//! Shared island types and pure formatter helpers.
//!
//! Field names on `SessionView` match `api::SessionView` in
//! `crates/ddns-server/src/api.rs` exactly (verified). The formatters are
//! ports of the same-named helpers in `crates/ddns-server/src/http_app.rs`
//! so the island's output strings are byte-identical to the SSR fallback.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SessionView {
    pub slug: String,
    pub token_id: String,
    pub want_http: bool,
    pub want_tcp: bool,
    pub uptime_secs: u64,
    pub streams: u32,
    pub streams_peak: u32,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub ttl_secs: u64,
    pub expires_in_secs: u64,
    pub end_reason: Option<String>,
}

/// Minimal client view of `GET /api/config`. Extra fields returned by the
/// server (`domain`, `public_port`, …) are ignored by serde by default.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ServerConfigView {
    pub max_sessions: usize,
}

/// Human-readable byte count (1024-based). Port of `bytes_human` in
/// `crates/ddns-server/src/http_app.rs` — same output strings.
pub fn bytes_human(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit_idx])
    }
}

/// Human-readable duration. Port of `duration_human` in
/// `crates/ddns-server/src/http_app.rs` — same output strings.
pub fn duration_human(total_secs: u64) -> String {
    if total_secs < 60 {
        return format!("{}s", total_secs);
    }
    let mins = total_secs / 60;
    if mins < 60 {
        let secs = total_secs % 60;
        return format!("{mins}m {secs}s");
    }
    let hours = mins / 60;
    let mins = mins % 60;
    if hours < 24 {
        return format!("{hours}h {mins}m");
    }
    let days = hours / 24;
    let hours = hours % 24;
    format!("{days}d {hours}h")
}

/// Truncate `s` to at most `max` bytes without splitting a UTF-8 character.
pub fn truncate(s: &str, max: usize) -> String {
    let end = s.floor_char_boundary(max.min(s.len()));
    s[..end].to_string()
}

/// Inline SVG sparkline (100x24) from a ring buffer of byte-rate deltas.
/// Port of `sparkline_svg` in `crates/ddns-server/src/http_app.rs`; the empty
/// ring yields an empty string (renders nothing, per the island spec).
pub fn sparkline_svg(deltas: &[u64]) -> String {
    if deltas.is_empty() {
        return String::new();
    }
    let max = deltas.iter().copied().max().unwrap_or(1).max(1) as f64;
    let w = 100.0;
    let h = 24.0;
    let n = deltas.len() as f64;

    if deltas.iter().all(|&v| v == 0) {
        return r##"<svg width="100" height="24" class="sparkline"><polyline fill="none" stroke="#e94560" stroke-width="1.5" points="0,23 100,23"/></svg>"##.to_string();
    }

    let points: String = deltas
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = (i as f64) * w / (n - 1.0).max(1.0);
            let y = h - ((v as f64) / max * (h - 2.0)) - 1.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        r##"<svg width="100" height="24" class="sparkline"><polyline fill="none" stroke="#e94560" stroke-width="1.5" points="{points}"/></svg>"##
    )
}

// ---------------------------------------------------------------------------
// tunnel form island types — field names mirror `TokenView`, `DomainView`,
// `TunnelView` in crates/ddns-server/src/api.rs and `HttpOptions` in
// crates/ddns-server/src/tunnel.rs. Extra fields returned by the server are
// ignored by serde by default.
// ---------------------------------------------------------------------------

/// Minimal client view of `GET /api/tokens`. Other fields (`owner_id`,
/// `limits`, …) are ignored by serde.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TokenView {
    pub id: String,
    pub name: String,
}

/// Minimal client view of `GET /api/domains`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DomainView {
    pub id: String,
    pub name: String,
    pub kind: String,
}

/// Client view of a `TunnelView` from `GET /api/tunnels`. `token_name`,
/// `domain_name`, and `created_at` are ignored (the island looks the names up
/// from the tokens/domains lists instead).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TunnelView {
    pub id: String,
    pub name: String,
    pub token_id: String,
    pub domain_id: String,
    pub subdomain: Option<String>,
    pub custom_hostname: Option<String>,
    pub options: TunnelOptions,
    pub enabled: bool,
    #[serde(default)]
    pub ports: String,
}

fn default_true() -> bool {
    true
}

/// Mirrors `HttpOptions` in crates/ddns-server/src/tunnel.rs, including the
/// server default (`reverse_proxy_headers` on; everything else off/empty).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TunnelOptions {
    #[serde(default = "default_true")]
    pub reverse_proxy_headers: bool,
    #[serde(default)]
    pub basic_auth: Option<(String, String)>,
    #[serde(default)]
    pub key_auth: Option<String>,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub https_only: bool,
    #[serde(default)]
    pub host_rewrite: Option<String>,
    #[serde(default)]
    pub add_headers: Vec<(String, String)>,
    #[serde(default)]
    pub remove_headers: Vec<String>,
    #[serde(default)]
    pub pass_preflight: bool,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self {
            reverse_proxy_headers: true,
            basic_auth: None,
            key_auth: None,
            ip_whitelist: Vec::new(),
            https_only: false,
            host_rewrite: None,
            add_headers: Vec::new(),
            remove_headers: Vec::new(),
            pass_preflight: false,
        }
    }
}

/// Request body for `POST /api/tunnels` / `PUT /api/tunnels/{id}`. Field
/// names mirror `TunnelReq` in api.rs; `enabled` is intentionally absent
/// (the store defaults it, matching the SSR form).
#[derive(Clone, Debug, Serialize)]
pub struct TunnelReq {
    pub name: String,
    pub token_id: String,
    pub domain_id: String,
    #[serde(default)]
    pub subdomain: Option<String>,
    #[serde(default)]
    pub custom_hostname: Option<String>,
    #[serde(default)]
    pub options: TunnelOptions,
    #[serde(default)]
    pub ports: String,
}

// ---------------------------------------------------------------------------
// portal live gauges island types — field names mirror the shared `tunnels_json`
// serializer in crates/ddns-server/src/api.rs (`GET /api/v1/tunnels` and
// `GET /portal/tunnels/live` return the same shape).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PortalTunnelLive {
    pub connected: bool,
    pub bytes_transferred: u64,
    pub requests: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PortalTunnel {
    pub id: String,
    pub slug: String,
    pub host: String,
    pub request_count: i64,
    pub live: PortalTunnelLive,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PortalTunnels {
    pub tunnels: Vec<PortalTunnel>,
}
