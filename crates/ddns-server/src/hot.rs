//! Redis-backed fast-path counter for the tunnel-traffic rate limiter.
//!
//! Free edition: only the fixed-minute window keys (`rl:*`) live here. Every
//! operation is bounded by a 250 ms timeout and degrades to `None` when Redis
//! is absent — SQLite-only deployments run without rate limiting entirely.
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::ConnectionManager;

/// Per-operation timeout; a slow Redis must not stall the metering path.
const OP_TIMEOUT: Duration = Duration::from_millis(250);
/// Minimum interval between error logs (one warning per minute).
const WARN_INTERVAL_SECS: i64 = 60;
/// Startup connect attempts and the pause between them.
const CONNECT_ATTEMPTS: u32 = 3;
const CONNECT_BACKOFF: Duration = Duration::from_secs(2);

/// Best-effort Redis counter proxy. `Clone` is cheap (shared connection).
#[derive(Clone)]
pub struct HotCounter {
    client: ConnectionManager,
    /// Epoch seconds of the last error log; caps warn spam at one per minute.
    last_warn: Arc<AtomicI64>,
}

impl HotCounter {
    /// Single connect attempt (no retry): open a client, establish the
    /// multiplexed connection (bounded by a 500 ms connection timeout), and
    /// probe it with PING so an unreachable Redis fails here rather than on
    /// the first command. Retries are the caller's concern (`connect_retry`).
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_millis(500)))
            .set_response_timeout(Some(OP_TIMEOUT))
            .set_number_of_retries(0);
        let manager = ConnectionManager::new_with_config(client, config).await?;
        let mut probe = manager.clone();
        let _: () = probe.ping().await?;
        Ok(Self {
            client: manager,
            last_warn: Arc::new(AtomicI64::new(0)),
        })
    }

    /// Startup connect with retries (3 attempts, 2 s apart). Failure → `None`
    /// (SQLite fallback) with a rate-limited warning.
    pub async fn connect_retry(url: &str) -> Option<Self> {
        for attempt in 1..=CONNECT_ATTEMPTS {
            match tokio::time::timeout(Duration::from_secs(5), Self::connect(url)).await {
                Ok(Ok(hot)) => {
                    tracing::info!("redis hot counter connected");
                    return Some(hot);
                }
                Ok(Err(e)) => {
                    tracing::warn!(attempt, ?e, "redis hot counter connect failed");
                }
                Err(_) => {
                    tracing::warn!(attempt, "redis hot counter connect timed out");
                }
            }
            if attempt < CONNECT_ATTEMPTS {
                tokio::time::sleep(CONNECT_BACKOFF).await;
            }
        }
        tracing::warn!(
            "redis hot counter unavailable after {CONNECT_ATTEMPTS} attempts; SQLite fallback active"
        );
        None
    }

    /// Bound a command with the op timeout and map errors to `None`,
    async fn run<T>(&self, fut: impl Future<Output = redis::RedisResult<T>>) -> Option<T> {
        match tokio::time::timeout(OP_TIMEOUT, fut).await {
            Ok(Ok(v)) => Some(v),
            Ok(Err(e)) => {
                self.warn(&e.to_string());
                None
            }
            Err(_) => {
                self.warn("redis command timed out");
                None
            }
        }
    }

    /// `INCR` a key and refresh its TTL (seconds), returning the new value
    /// (`None` on error/timeout). Used by the quota enforcer's fixed-minute
    /// windows: each request increments its window counter and keeps the key
    /// alive for two minutes (one full window + boundary slack).
    pub async fn incr_expire(&self, key: &str, ttl_secs: u64) -> Option<i64> {
        let mut conn = self.client.clone();
        self.run(async move {
            let n: i64 = redis::cmd("INCR").arg(key).query_async(&mut conn).await?;
            let _: () = redis::cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query_async(&mut conn)
                .await?;
            Ok(n)
        })
        .await
    }

    /// Rate-limited warn: at most one message per [`WARN_INTERVAL_SECS`].
    fn warn(&self, err: &str) {
        let now = crate::account::unix_now();
        let last = self.last_warn.load(Ordering::Relaxed);
        if now.saturating_sub(last) < WARN_INTERVAL_SECS {
            return;
        }
        if self
            .last_warn
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(%err, "redis hot counter unavailable; SQLite fallback active");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_dead_port_degrades_to_none() {
        // Nothing listens on port 1; the connection is refused. The contract
        // is "no panic, returns Err" — `connect_retry` maps that Err to None
        // (SQLite fallback). Bounded by the 500 ms connect timeout + zero
        // internal retries, so this fails fast.
        let dead = "redis://127.0.0.1:1";
        let result = HotCounter::connect(dead).await;
        assert!(result.is_err(), "dead port should fail to connect");
    }

    #[tokio::test]
    async fn connect_retry_unreachable_degrades_to_none() {
        // Exhausts the 3-attempt startup retry loop against a dead port and
        // returns None (SQLite fallback) without panicking or hanging. Each
        // attempt is bounded by the 500 ms connect timeout + 2 s backoff, so
        // the whole test finishes in a few seconds.
        let dead = "redis://127.0.0.1:1";
        let result = HotCounter::connect_retry(dead).await;
        assert!(result.is_none(), "retry loop should degrade to None");
    }
}
