//! Quickstart port helpers for the operator dashboard (free edition).
//!
//! feature and is not part of this build; only the pure port-parsing helper
//! used by the operator quickstart flow lives here.

/// Parse the tunnel's comma-separated ports into (http_port, tcp_port): the
/// first web-ish port becomes --port, the first other port becomes --tcp.
/// The client supports one HTTP + one TCP target per session (v1).
pub(crate) fn split_ports(ports: &str) -> (Option<u32>, Option<u32>) {
    let mut http = None;
    let mut tcp = None;
    for raw in ports.split(',') {
        let p: u32 = match raw.trim().parse() {
            Ok(p) if p > 0 && p <= 65535 => p,
            _ => continue,
        };
        let web = matches!(
            p,
            80 | 443 | 3000 | 5000 | 8000 | 8080 | 8888 | 9000 | 5173 | 4200
        );
        if web && http.is_none() {
            http = Some(p);
        } else if !web && tcp.is_none() {
            tcp = Some(p);
        }
    }
    (http, tcp)
}
