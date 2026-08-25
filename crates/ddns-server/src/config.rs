use std::net::SocketAddr;
use std::time::Duration;

use crate::token::TokenStore;

/// ACME certificate provisioning options. When set, `tls_cert_pem` and
/// `tls_key_pem` MUST be empty — acme and explicit certs are mutually
/// exclusive (validated at `BrokerConfig` construction time).
#[derive(Debug, Clone)]
pub struct AcmeOptions {
    /// Domains to include in the certificate (first is primary/common name).
    pub domains: Vec<String>,
    /// Contact email (without `mailto:` prefix — added automatically).
    pub contact_email: Option<String>,
    /// DNS-01 provider for challenges that require it. The default validation
    /// method is TLS-ALPN-01 (handled automatically by rustls-acme on port
    /// 443); this provider is wired for the manual challenge store and for
    /// future DNS-01 integration.
    pub provider: AcmeProvider,
    /// ACME directory URL. `None` → Let's Encrypt production (the default in
    /// `tls.rs`); set to the staging URL for tests.
    pub directory_url: Option<String>,
}

/// DNS-01 challenge provider selection.
#[derive(Debug, Clone)]
pub enum AcmeProvider {
    /// Operator deploys TXT records manually via the dashboard.
    Manual,
    /// Cloudflare API v4 with zone-level API token.
    Cloudflare { api_token: String, zone_id: String },
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// Bind address. Tests use `127.0.0.1:0` (ephemeral).
    pub listen: SocketAddr,
    /// Tunnel apex domain, e.g. `tunnel.example.com`. Visitor routing and the
    /// `tcp_addr` advertisement are derived from it.
    pub domain: String,
    /// Port advertised in `registered.tcp_addr` (443 in production).
    pub public_port: u16,
    /// Public UDP listener port for UDP tunnels (0 = disabled).
    pub udp_port: u16,
    /// Local UDP target port the CLIENT dials for each flow (from --udp flag).
    pub udp_target_port: u16,
    /// Dedicated per-slug UDP ports: (slug, port). Each binds its own socket;
    /// datagrams route to the named slug's session without a prefix.
    pub udp_routes: Vec<(String, u16)>,
    /// Generic OIDC provider (visitor auth). `None` → `/__auth/oidc/*` 503.
    pub oidc: Option<crate::auth_oidc::OidcConfig>,
    /// PEM-encoded certificate chain. Must be empty when `acme` is `Some`.
    pub tls_cert_pem: Vec<u8>,
    /// PEM-encoded private key. Must be empty when `acme` is `Some`.
    pub tls_key_pem: Vec<u8>,
    /// Token → limits lookup. Tokens always carry their own limits.
    pub token_store: TokenStore,
    /// Global concurrent-session cap. Exceeded → `error{server_full}`.
    pub max_sessions: usize,
    /// Server-wide hard cap on concurrent streams per session, enforced on top
    /// of the token's own `max_streams` (0 = unlimited in the token becomes
    /// bounded by this). Protects broker memory from an unlimited token.
    pub max_streams_per_session: usize,
    /// Quota watchdog tick (5 s in production; tests use 200 ms).
    pub watchdog_interval: Duration,
    /// Plain-HTTP :80 listener. When `Some`, the broker binds a plain-text
    /// listener that 301-redirects to HTTPS and serves ACME HTTP-01 challenges.
    pub http_listen: Option<SocketAddr>,
    /// UDP listener for the embedded RFC 5389 STUN server (WebRTC ICE
    /// candidate gathering, P2P data plane). `None` = disabled.
    pub stun_listen: Option<SocketAddr>,
    /// ACME certificate provisioning. When `Some`, `tls_cert_pem` and
    /// `tls_key_pem` MUST be empty. Defaults to `None` (static certs).
    pub acme: Option<AcmeOptions>,
    /// Directory containing static binaries for `/download/{file}`. When
    /// `None`, `/download/` always returns 404.
    pub download_dir: Option<std::path::PathBuf>,
    /// `--dev` mode: self-signed cert + dev-mail link logging.
    pub dev: bool,
    /// External base URL for emailed links (env `DDNS_BASE_URL`).
    pub base_url: String,
    /// Directory containing the ddns-web bundle served by `/_assets/{path}`.
    /// Defaults to `dist/public` (the `dx bundle` web output directory).
    pub web_dist: std::path::PathBuf,
    /// Redis URL for the token-balance hot counter (`--redis-url` /
    /// `DDNS_REDIS_URL`). Unused until Phase C: the default deployment runs
    /// SQLite-only metering. `None` → no fast-path cache (and no connect cost).
    pub redis_url: Option<String>,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            domain: "localhost".to_string(),
            public_port: 443,
            udp_port: 0,
            udp_target_port: 0,
            udp_routes: Vec::new(),
            oidc: None,
            tls_cert_pem: Vec::new(),
            tls_key_pem: Vec::new(),
            token_store: TokenStore::new(),
            max_sessions: 256,
            watchdog_interval: Duration::from_secs(5),
            http_listen: None,
            stun_listen: None,
            acme: None,
            download_dir: None,
            dev: false,
            base_url: "http://127.0.0.1:8443".into(),
            web_dist: std::path::PathBuf::from("dist/public"),
            max_streams_per_session: 512,
            redis_url: None,
        }
    }
}

impl BrokerConfig {
    pub fn tcp_addr_for(&self, slug: &str) -> String {
        format!("{slug}.{}:{}", self.domain, self.public_port)
    }

    pub fn http_url_for(&self, slug: &str) -> String {
        if self.public_port == 443 {
            format!("https://{slug}.{}", self.domain)
        } else {
            format!("https://{slug}.{}:{}", self.domain, self.public_port)
        }
    }

    /// Validate mutual-exclusion: acme and explicit certs cannot both be set;
    /// wildcard ACME domains need DNS-01, which v1 cannot drive.
    pub fn validate(&self) -> Result<(), String> {
        if self.acme.is_some() && (!self.tls_cert_pem.is_empty() || !self.tls_key_pem.is_empty()) {
            return Err("acme and explicit tls_cert_pem/tls_key_pem are mutually exclusive".into());
        }
        if let Some(acme) = &self.acme
            && acme.domains.iter().any(|d| d.starts_with("*."))
        {
            return Err(
                "acme wildcard domains ('*.') require DNS-01 validation, which is not wired in \
                 v1 (rustls-acme 0.12 validates via TLS-ALPN-01 only, and ACME (automatic \
                 certificates) offers only DNS-01 for wildcards) — use apex-only domains with \
                 ACME, or static certificates"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_http_urls_include_nonstandard_ports() {
        let config = BrokerConfig {
            domain: "example.test".into(),
            ..BrokerConfig::default()
        };
        assert_eq!(config.http_url_for("app"), "https://app.example.test");
        let config = BrokerConfig {
            public_port: 8443,
            ..config
        };
        assert_eq!(config.http_url_for("app"), "https://app.example.test:8443");
    }
}
