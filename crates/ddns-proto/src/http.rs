//! Pure HTTP/1.1 head serialization and parsing, shared by the broker
//! (`ddns-server`) and the client's WebRTC gateway (`ddns-client`).
//!
//! Deliberately axum/hyper-free: only `std` types. A "head" is the
//! status/request line plus headers, terminated by `\r\n\r\n`.

/// Serialize an HTTP/1.1 *request* head: `METHOD path HTTP/1.1\r\n` followed
/// by `Name: value\r\n` for each header and a final `\r\n`.
pub fn build_http_head(method: &str, path: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for (k, v) in headers {
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Parse an HTTP/1.1 *response* head (status line + headers ending at
/// `\r\n\r\n`) into the numeric status code and an ordered header list.
///
/// Returns `None` if the head is not UTF-8, lacks a status line, has a
/// non-numeric status code, or a header line without a `:` separator.
pub fn parse_http_head(head: &[u8]) -> Option<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    let code = code_str.parse::<u16>().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = line.split_once(':')?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Some((code, headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_head_exact_bytes() {
        let head = build_http_head("GET", "/", &[("Host".to_string(), "x".to_string())]);
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn build_request_head_multiple_headers_preserve_order() {
        let head = build_http_head(
            "POST",
            "/submit?a=1",
            &[
                ("Host".to_string(), "x".to_string()),
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
            ],
        );
        let expected = concat!(
            "POST /submit?a=1 HTTP/1.1\r\n",
            "Host: x\r\n",
            "Content-Length: 5\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
        );
        assert_eq!(head, expected.as_bytes());
    }

    #[test]
    fn build_request_head_with_no_headers() {
        let head = build_http_head("GET", "/", &[]);
        assert_eq!(head, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn parse_response_head_extracts_status_and_headers() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\n";
        let (status, headers) = parse_http_head(head).expect("valid response head");
        assert_eq!(status, 200);
        assert_eq!(
            headers,
            vec![
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
            ]
        );
    }

    #[test]
    fn parse_response_head_trims_header_whitespace() {
        let head = b"HTTP/1.1 404 Not Found\r\nX-Reason:  missing  \r\n\r\n";
        let (status, headers) = parse_http_head(head).expect("valid head");
        assert_eq!(status, 404);
        assert_eq!(
            headers,
            vec![("X-Reason".to_string(), "missing".to_string())]
        );
    }

    #[test]
    fn parse_response_head_rejects_non_numeric_status() {
        assert_eq!(parse_http_head(b"HTTP/1.1 OK\r\n\r\n"), None);
    }

    #[test]
    fn parse_response_head_rejects_missing_colon() {
        assert_eq!(
            parse_http_head(b"HTTP/1.1 200 OK\r\nbadheader\r\n\r\n"),
            None
        );
    }

    #[test]
    fn parse_response_head_rejects_non_utf8() {
        assert_eq!(
            parse_http_head(b"HTTP/1.1 200 OK\r\n\xff\xfe\r\n\r\n"),
            None
        );
    }
}
