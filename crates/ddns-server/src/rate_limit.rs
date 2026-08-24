//! Per-IP rate limiting for CPU-bound unauthenticated endpoints.
//!
//! `/connect` register verifies the presented token against every stored
//! argon2id hash (~50 ms per hash) and `/login` verifies the admin hash —
//! both are public by design, so an unauthenticated attacker must not be able
//! to drive unbounded argon2 work. A per-IP token bucket bounds each source
//! address; the accept loop's connection semaphore (lib.rs) bounds total
//! concurrency across all sources.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Per-IP token bucket. `capacity` = burst size; `refill_per_sec` = steady
/// replenishment rate. Buckets are per-source-IP and pruned once the map
/// grows past a bound (idle buckets are full, so pruning drops only idle
/// entries).
pub struct RateLimiter {
    inner: Mutex<Inner>,
    capacity: f64,
    refill_per_sec: f64,
}

struct Inner {
    buckets: HashMap<IpAddr, Bucket>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Max distinct source IPs tracked before pruning idle buckets.
const MAX_BUCKETS: usize = 10_000;

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
            }),
            capacity: capacity as f64,
            refill_per_sec,
        }
    }

    /// Whether a request from `ip` is allowed, consuming one token on success.
    /// `None` (no peer address — should not happen on real sockets) is
    /// allowed rather than silently blocking legitimate traffic.
    pub fn allow(&self, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else { return true };
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if inner.buckets.len() >= MAX_BUCKETS {
            // Drop idle (full) buckets to keep the map bounded.
            inner.buckets.retain(|_, b| b.tokens < self.capacity);
        }
        let bucket = inner.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.last = now;
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_capacity_consumed_then_blocked() {
        let limiter = RateLimiter::new(3, 1.0);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.allow(Some(ip)), "burst of 3 should pass");
        }
        assert!(
            !limiter.allow(Some(ip)),
            "4th within the same instant is blocked"
        );
        // No refill yet — still blocked immediately.
        assert!(!limiter.allow(Some(ip)));
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::new(1, 100.0); // fast refill for the test
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(limiter.allow(Some(ip)));
        assert!(!limiter.allow(Some(ip)), "token consumed, none left");
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(
            limiter.allow(Some(ip)),
            "after refill a token should be available"
        );
    }

    #[test]
    fn buckets_are_per_ip() {
        let limiter = RateLimiter::new(1, 0.0);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(limiter.allow(Some(a)));
        assert!(!limiter.allow(Some(a)));
        assert!(limiter.allow(Some(b)), "different IP has its own bucket");
    }

    #[test]
    fn no_ip_is_allowed() {
        let limiter = RateLimiter::new(1, 0.0);
        assert!(limiter.allow(None));
        assert!(limiter.allow(None));
    }
}
