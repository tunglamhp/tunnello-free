use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub streams: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillReason {
    QuotaExceeded,
    TtlExpired,
    Admin,
    TokenExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    TokenInvalid,
    NoSubdomainAvailable,
    ServerFull,
    TokenExhausted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    Register {
        token: String,
        want_tcp: bool,
        want_http: bool,
        #[serde(default)]
        subdomain_hint: Option<String>,
    },
    Registered {
        http_url: Option<String>,
        tcp_addr: Option<String>,
        session_secret: String,
        /// Broker software version for client compatibility checks.
        #[serde(default)]
        broker_version: Option<String>,
    },
    Quota {
        usage: Usage,
    },
    Kill {
        reason: KillReason,
    },
    Error {
        code: ErrorCode,
    },
    Heartbeat {
        seq: u64,
    },
    Pong {
        seq: u64,
    },
    P2pVisitorOffer {
        ticket: String,
        sdp: String,
        ice: Vec<String>,
    },
    P2pAnswer {
        ticket: String,
        sdp: String,
        ice: Vec<String>,
    },
    P2pIce {
        ticket: String,
        candidate: String,
    },
    P2pReady {
        ticket: String,
    },
    P2pFailed {
        ticket: String,
        reason: String,
    },
    UsageReport {
        bytes_tx: u64,
        bytes_rx: u64,
        streams: u32,
        since_ts: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_serializes_with_type_tag() {
        let msg = Control::Register {
            token: "tok_abc".into(),
            want_tcp: true,
            want_http: true,
            subdomain_hint: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"register\""));
        assert!(json.contains("\"token\":\"tok_abc\""));
        assert!(json.contains("\"want_tcp\":true"));
        let back: Control = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn all_variants_roundtrip() {
        let msgs = vec![
            Control::Registered {
                http_url: Some("https://vivid-otter-72.example.com".into()),
                tcp_addr: Some("vivid-otter-72.example.com:443".into()),
                session_secret: String::new(),
                broker_version: None,
            },
            Control::Quota {
                usage: Usage {
                    bytes_tx: 10,
                    bytes_rx: 20,
                    streams: 3,
                },
            },
            Control::Kill {
                reason: KillReason::QuotaExceeded,
            },
            Control::Kill {
                reason: KillReason::TtlExpired,
            },
            Control::Kill {
                reason: KillReason::Admin,
            },
            Control::Kill {
                reason: KillReason::TokenExhausted,
            },
            Control::Error {
                code: ErrorCode::TokenInvalid,
            },
            Control::Error {
                code: ErrorCode::NoSubdomainAvailable,
            },
            Control::Error {
                code: ErrorCode::ServerFull,
            },
            Control::Error {
                code: ErrorCode::TokenExhausted,
            },
            Control::Heartbeat { seq: 42 },
            Control::Pong { seq: 42 },
        ];
        for msg in msgs {
            let json = serde_json::to_string(&msg).unwrap();
            let back: Control = serde_json::from_str(&json).unwrap();
            assert_eq!(back, msg);
        }
    }

    #[test]
    fn registered_round_trips_with_session_secret() {
        let c = Control::Registered {
            http_url: Some("https://x.tunnel.example.com".into()),
            tcp_addr: None,
            session_secret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".into(),
            broker_version: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"session_secret\""));
        let back: Control = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn p2p_messages_round_trip() {
        for c in [
            Control::P2pVisitorOffer {
                ticket: "t.abc".into(),
                sdp: "v=0\r\n".into(),
                ice: vec!["candidate:1".into()],
            },
            Control::P2pAnswer {
                ticket: "t.abc".into(),
                sdp: "v=0\r\n".into(),
                ice: vec![],
            },
            Control::P2pIce {
                ticket: "t.abc".into(),
                candidate: "candidate:1 1 udp 1 1.2.3.4 5000 typ host".into(),
            },
            Control::P2pReady {
                ticket: "t.abc".into(),
            },
            Control::P2pFailed {
                ticket: "t.abc".into(),
                reason: "ice_failed".into(),
            },
        ] {
            let json = serde_json::to_string(&c).unwrap();
            assert!(json.starts_with("{\"type\":\"p2p_"), "tag mismatch: {json}");
            let back: Control = serde_json::from_str(&json).unwrap();
            assert_eq!(back, c);
        }

        // UsageReport serializes to the "usage_report" tag (not "p2p_*"), so it
        // is checked separately while still exercising the full round-trip.
        let c = Control::UsageReport {
            bytes_tx: 1024,
            bytes_rx: 2048,
            streams: 2,
            since_ts: 1_700_000_000,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(
            json.starts_with("{\"type\":\"usage_report\""),
            "tag mismatch: {json}"
        );
        let back: Control = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn reason_and_code_are_snake_case() {
        assert!(
            serde_json::to_string(&Control::Kill {
                reason: KillReason::QuotaExceeded
            })
            .unwrap()
            .contains("\"quota_exceeded\"")
        );
        assert!(
            serde_json::to_string(&Control::Error {
                code: ErrorCode::TokenInvalid
            })
            .unwrap()
            .contains("\"token_invalid\"")
        );
        assert!(
            serde_json::to_string(&Control::Kill {
                reason: KillReason::TokenExhausted
            })
            .unwrap()
            .contains("\"token_exhausted\"")
        );
        assert!(
            serde_json::to_string(&Control::Error {
                code: ErrorCode::TokenExhausted
            })
            .unwrap()
            .contains("\"token_exhausted\"")
        );
    }

    #[test]
    fn rejects_unknown_variant() {
        let err = serde_json::from_str::<Control>(r#"{"type":"bogus"}"#);
        assert!(err.is_err());
    }
}
