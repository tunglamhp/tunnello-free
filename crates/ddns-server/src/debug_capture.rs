//! Body/header capture helpers for the deep web debugger (spec Phase 2).
//! Pure functions — no session or I/O dependencies — so the capture path in
//! `http_tunnel` stays a thin call.

/// Max captured bytes per side (request, response).
pub const CAPTURE_LIMIT: usize = 4096;

/// Headers whose values must never be stored or replayed.
pub fn is_sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "authorization" || lower == "cookie" || lower == "set-cookie"
}

/// Copy `headers`, replacing sensitive values with `[REDACTED]`.
pub fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            let v = if is_sensitive_header(k) {
                "[REDACTED]".to_string()
            } else {
                v.clone()
            };
            (k.clone(), v)
        })
        .collect()
}

/// UTF-8-lossy body preview capped at [`CAPTURE_LIMIT`] bytes.
pub fn truncate_body(body: &[u8]) -> String {
    if body.len() <= CAPTURE_LIMIT {
        return String::from_utf8_lossy(body).into_owned();
    }
    let mut out = String::from_utf8_lossy(&body[..CAPTURE_LIMIT]).into_owned();
    out.push_str("…(truncated)");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_headers_redacted_case_insensitive() {
        let raw = vec![
            ("Authorization".to_string(), "Bearer sekret".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("COOKIE".to_string(), "session=abc".to_string()),
            ("Set-Cookie".to_string(), "a=1".to_string()),
        ];
        let out = redact_headers(&raw);
        assert_eq!(out[0].1, "[REDACTED]");
        assert_eq!(out[1].1, "application/json");
        assert_eq!(out[2].1, "[REDACTED]");
        assert_eq!(out[3].1, "[REDACTED]");
    }

    #[test]
    fn body_truncates_at_4kib_with_marker() {
        let small = b"hello".to_vec();
        assert_eq!(truncate_body(&small), "hello");
        let big = vec![b'x'; CAPTURE_LIMIT + 100];
        let out = truncate_body(&big);
        assert!(out.starts_with('x'));
        assert_eq!(out.len(), CAPTURE_LIMIT + "…(truncated)".len());
        assert!(out.ends_with("…(truncated)"));
    }

    #[test]
    fn invalid_utf8_is_lossy() {
        let bytes = vec![0x68, 0x69, 0xFF]; // "hi" + invalid byte
        assert!(truncate_body(&bytes).starts_with("hi"));
    }
}
