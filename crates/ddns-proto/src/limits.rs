use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenLimits {
    pub max_sessions: u32,
    pub max_streams: u32,
    pub max_bytes: u64,
    pub ttl_secs: u64,
    /// Maximum simultaneous tunnels (0 = unlimited).
    #[serde(default)]
    pub max_tunnels: u32,
    /// Monthly bandwidth budget in bytes (0 = unlimited).
    #[serde(default)]
    pub bandwidth_monthly: u64,
    /// Maximum connected clients (0 = unlimited).
    #[serde(default)]
    pub max_clients: u32,
    /// Per-token request rate limit, requests/minute (0 = unlimited).
    #[serde(default)]
    pub rate_limit_rpm: u32,
}

impl Default for TokenLimits {
    /// Free edition: everything unlimited by default. Operators can still set
    /// per-token limits via the dashboard when they want guard rails.
    fn default() -> Self {
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
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_edition_defaults_are_unlimited() {
        let l = TokenLimits::default();
        // Free edition: every limit defaults to the "0 = unlimited" sentinel.
        assert_eq!(l.max_sessions, 0);
        assert_eq!(l.max_streams, 0);
        assert_eq!(l.max_bytes, 0);
        assert_eq!(l.ttl_secs, 0);
        assert_eq!(l.max_tunnels, 0);
        assert_eq!(l.bandwidth_monthly, 0);
        assert_eq!(l.max_clients, 0);
        assert_eq!(l.rate_limit_rpm, 0);
    }

    #[test]
    fn serde_roundtrip() {
        let l = TokenLimits {
            max_sessions: 5,
            max_streams: 64,
            max_bytes: 12345,
            ttl_secs: 60,
            max_tunnels: 3,
            bandwidth_monthly: 987654321,
            max_clients: 40,
            rate_limit_rpm: 120,
        };
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(serde_json::from_str::<TokenLimits>(&json).unwrap(), l);
    }

    #[test]
    fn serde_defaults_missing_quota_fields_to_zero() {
        // Old plan JSON predates the commercial quota fields; they must read 0.
        let old = r#"{"max_sessions":2,"max_streams":32,"max_bytes":2147483648,"ttl_secs":28800}"#;
        let l: TokenLimits = serde_json::from_str(old).unwrap();
        assert_eq!(l.max_tunnels, 0);
        assert_eq!(l.bandwidth_monthly, 0);
        assert_eq!(l.max_clients, 0);
        assert_eq!(l.rate_limit_rpm, 0);
    }
}
