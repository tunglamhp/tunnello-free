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
    fn default() -> Self {
        TokenLimits {
            max_sessions: 2,
            max_streams: 32,
            max_bytes: 2 * 1024 * 1024 * 1024,
            ttl_secs: 8 * 3600,
            max_tunnels: 2,
            bandwidth_monthly: 5 * 1024 * 1024 * 1024,
            max_clients: 50,
            rate_limit_rpm: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_tier_defaults_match_spec() {
        let l = TokenLimits::default();
        assert_eq!(l.max_sessions, 2);
        assert_eq!(l.max_streams, 32);
        assert_eq!(l.max_bytes, 2 * 1024 * 1024 * 1024); // 2 GiB
        assert_eq!(l.ttl_secs, 8 * 3600); // 8 h
        assert_eq!(l.max_tunnels, 2);
        assert_eq!(l.bandwidth_monthly, 5 * 1024 * 1024 * 1024); // 5 GiB
        assert_eq!(l.max_clients, 50);
        assert_eq!(l.rate_limit_rpm, 60);
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
