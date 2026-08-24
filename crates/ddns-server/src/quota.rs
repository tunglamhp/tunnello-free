//! Quota enforcement, two halves:
//!
//! * **Per-session watchdog** ([`watch`]): runs while a session is live; on TTL
//!   expiry or byte-quota overrun it signals the mux loop, which sends
//!   `quota{usage}` + `kill{reason}` to the client and closes the WS.
//!   Metered, never throttled — throttling would corrupt TCP streams. Limit
//!   hits also emit a `quota_hit` webhook (fire-and-forget).
//! * **Request rate limiter** ([`RateLimiter`], Phase C): a fixed-minute Redis
//!   sliding window over the HTTP tunnel traffic path. Visitor requests beyond
//!   the plan's `rate_limit_rpm` get `429` + `Retry-After`. Redis is the
//!   enforcement hot path only; SQLite-mode (no Redis) passes through.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ddns_proto::KillReason;
use tokio::time::{MissedTickBehavior, interval};

use crate::hot::HotCounter;
use crate::session::TunnelSession;
use crate::settings::{self, Settings};

pub async fn watch(
    session: Arc<TunnelSession>,
    watchdog: Duration,
    settings: Arc<RwLock<Settings>>,
) {
    let mut tick = interval(watchdog);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if session.expired() {
            let s = settings.read().unwrap_or_else(|p| p.into_inner()).clone();
            settings::send_webhook(&s, "quota_hit", serde_json::json!({ "limit": "ttl" }));
            session.kill(KillReason::TtlExpired);
            return;
        }
        if session.over_quota() {
            let s = settings.read().unwrap_or_else(|p| p.into_inner()).clone();
            settings::send_webhook(&s, "quota_hit", serde_json::json!({ "limit": "max_bytes" }));
            session.kill(KillReason::QuotaExceeded);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Request rate limiter (Phase C): fixed-minute Redis sliding window.
// ---------------------------------------------------------------------------

/// TTL (seconds) for each window key. Two minutes: one full window plus slack
/// so a key survives just past the minute boundary it covers.
const WINDOW_TTL_SECS: u64 = 120;

/// Fixed-minute window id for `now` (Unix seconds, UTC): `YYYYMMDDHHMM`.
///
/// Civil-from-days (Howard Hinnant's algorithm — the same one `crate::fmt_ts`
/// uses), extended with the hour/minute of day. No chrono dependency.
pub fn minute_bucket(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let secs = now.rem_euclid(86_400);
    let (hh, mm) = (secs / 3600, (secs % 3600) / 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}{mo:02}{d:02}{hh:02}{mm:02}")
}

/// Whether a window count trips the per-minute limit. `rpm <= 0` is the
/// unlimited sentinel and never trips.
pub fn exceeds(count: i64, rpm: i64) -> bool {
    rpm > 0 && count > rpm
}

/// Seconds from `now` until the next minute boundary (the point the window
/// resets). In `[1, 60]`; a `Retry-After` of 0 would be useless.
pub fn retry_after(now: i64) -> u64 {
    (60 - now.rem_euclid(60) as u64).max(1)
}

/// A request exceeded its rate window; carry the `Retry-After` delay back to
/// the caller so the HTTP layer can answer `429`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited {
    pub retry_after_secs: u64,
}

/// Fixed-minute rate limiter over the tunnel traffic path.
///
/// Cheap to `Clone` (shares the [`HotCounter`] connection). Two windows per
/// request — per-tunnel (`rl:{account}:{tunnel}:{bucket}`) and per-IP
/// (`rl:{account}:ip:{ip}:{bucket}`) — so one abusive source can't drain a
/// tenant's whole tunnel budget and one tenant can't hide behind many IPs.
/// Every command goes through the hot counter's bounded timeout and
/// rate-limited warn; a downed Redis fails **open** (consistent with the B2
/// token-counter degradation), so SQLite-mode traffic is never throttled.
#[derive(Clone)]
pub struct RateLimiter {
    hot: HotCounter,
}

impl RateLimiter {
    pub fn new(hot: HotCounter) -> Self {
        Self { hot }
    }

    /// Consume one request for `account_id`'s tunnel + source IP. `Ok` allows
    /// the request (including unlimited `rpm == 0` and any Redis failure);
    /// `Err(RateLimited)` means the window is full and carries the retry delay.
    pub async fn check(
        &self,
        account_id: i64,
        tunnel_id: &str,
        peer_ip: IpAddr,
        rpm: u32,
    ) -> Result<(), RateLimited> {
        if rpm == 0 {
            return Ok(());
        }
        let now = crate::now_secs();
        let bucket = minute_bucket(now);
        let tunnel_key = format!("rl:{account_id}:{tunnel_id}:{bucket}");
        let ip_key = format!("rl:{account_id}:ip:{peer_ip}:{bucket}");

        let tunnel_count = match self.hot.incr_expire(&tunnel_key, WINDOW_TTL_SECS).await {
            Some(n) => n,
            None => return Ok(()), // Redis down: fail open
        };
        let ip_count = match self.hot.incr_expire(&ip_key, WINDOW_TTL_SECS).await {
            Some(n) => n,
            None => return Ok(()), // Redis down: fail open
        };

        let rpm = rpm as i64;
        if exceeds(tunnel_count, rpm) || exceeds(ip_count, rpm) {
            return Err(RateLimited {
                retry_after_secs: retry_after(now),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minute_bucket_formats_utc() {
        assert_eq!(minute_bucket(0), "197001010000");
        assert_eq!(minute_bucket(59), "197001010000");
        assert_eq!(minute_bucket(60), "197001010001");
        // 2024-07-03 09:46:40 UTC == 1720000000 (date matches crate::fmt_ts).
        assert_eq!(minute_bucket(1_720_000_000), "202407030946");
    }

    #[test]
    fn exceeds_boundaries_and_unlimited() {
        assert!(!exceeds(60, 0), "rpm 0 is unlimited");
        assert!(!exceeds(60, -1), "negative rpm is unlimited");
        assert!(!exceeds(60, 60), "exactly at the limit does not trip");
        assert!(exceeds(61, 60), "one over trips");
        assert!(!exceeds(0, 60), "zero requests never trip");
    }

    #[test]
    fn retry_after_spans_the_remaining_minute() {
        assert_eq!(retry_after(0), 60);
        assert_eq!(retry_after(1), 59);
        assert_eq!(retry_after(59), 1);
        assert_eq!(retry_after(60), 60);
        assert_eq!(retry_after(61), 59);
    }
}
