//! Local target resolution.

use ddns_proto::StreamKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTarget {
    pub kind: StreamKind,
    pub host: String,
    pub port: u16,
}

impl LocalTarget {
    pub fn http(port: u16) -> Self {
        Self {
            kind: StreamKind::Http,
            host: "127.0.0.1".into(),
            port,
        }
    }

    pub fn tcp(port: u16) -> Self {
        Self {
            kind: StreamKind::Tcp,
            host: "127.0.0.1".into(),
            port,
        }
    }

    /// Parse `http://host:port` or `tcp://host:port`.
    /// Handles IPv6 bracket notation: `http://[::1]:8080`.
    pub fn from_url(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or("target must be http://host:port, tcp://host:port, or udp://host:port")?;
        let kind = match scheme {
            "http" => StreamKind::Http,
            "tcp" => StreamKind::Tcp,
            "udp" => StreamKind::Udp,
            _ => return Err(format!("unknown scheme {scheme:?}")),
        };
        let (host, port) = if rest.starts_with('[') {
            let close = rest
                .find(']')
                .ok_or("missing closing ']' in IPv6 address")?;
            // Strip the brackets: "[::1]:8080" -> host "::1"
            let host = rest[1..close].to_string();
            let after = &rest[close + 1..];
            let port_str = after
                .strip_prefix(':')
                .ok_or("target must include :port after IPv6 address")?;
            (host.to_string(), port_str)
        } else {
            let (host, port_str) = rest.rsplit_once(':').ok_or("target must include :port")?;
            (host.to_string(), port_str)
        };
        let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
        Ok(Self { kind, host, port })
    }
}

impl LocalTarget {
    /// Resolve host + connect to port. Returns the connected TCP stream.
    pub async fn dial(&self) -> Result<tokio::net::TcpStream, String> {
        let addrs = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(|e| format!("resolve {}: {e}", self.host))?;
        let mut last: Option<std::io::Error> = None;
        for a in addrs {
            match tokio::net::TcpStream::connect(a).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(last
            .map(|e| e.to_string())
            .unwrap_or_else(|| format!("no address for {}", self.host)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_url() {
        let t = LocalTarget::from_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(t.kind, StreamKind::Http);
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn tcp_url() {
        let t = LocalTarget::from_url("tcp://10.0.0.1:5432").unwrap();
        assert_eq!(t.kind, StreamKind::Tcp);
        assert_eq!(t.host, "10.0.0.1");
        assert_eq!(t.port, 5432);
    }

    #[test]
    fn ipv6_bracket() {
        let t = LocalTarget::from_url("http://[::1]:3000").unwrap();
        assert_eq!(t.kind, StreamKind::Http);
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 3000);
    }

    #[test]
    fn bare_port_helpers() {
        let h = LocalTarget::http(3000);
        assert_eq!(h.kind, StreamKind::Http);
        assert_eq!(h.host, "127.0.0.1");
        assert_eq!(h.port, 3000);

        let t = LocalTarget::tcp(22);
        assert_eq!(t.kind, StreamKind::Tcp);
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 22);
    }
}
