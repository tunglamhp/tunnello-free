//! Reconnect policy: backoff, session-end classification.

use std::time::Duration;

use ddns_proto::{ErrorCode, KillReason, Usage};

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// Exponential backoff: 1 s, 2 s, 4 s, 8 s, 16 s, capped at 30 s.
pub struct Backoff {
    /// Current attempt number (readable by the outer loop).
    pub attempt: u32,
    cap: Duration,
}

impl Backoff {
    pub fn new() -> Self {
        Self {
            attempt: 0,
            cap: Duration::from_secs(30),
        }
    }

    /// Return the next delay and advance the internal counter.
    pub fn next_delay(&mut self) -> Duration {
        let exp = 1u64 << self.attempt.min(5); // 1,2,4,8,16,32
        self.attempt += 1;
        Duration::from_secs(exp.min(self.cap.as_secs()))
    }

    /// Reset after a successful registration: a later session drop must
    /// reconnect with the 1 s delay, not the accumulated pre-registration
    /// count.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SessionEnd — what run_mux returns
// ---------------------------------------------------------------------------

/// Why the mux recv loop exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// WebSocket closed cleanly or read error / stream end.
    WsClosed,
    /// Broker sent Kill. The `Usage` is from the most recent Quota message
    /// preceding the Kill (if any).
    Killed(KillReason, Option<Usage>),
    /// Broker sent Error with the given code.
    ServerError(ErrorCode),
}
