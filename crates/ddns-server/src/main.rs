//! ddns-server — operator launcher for the tunnel broker.
//!
//! One process binds the TLS listener and serves the dashboard pages, the
//! REST API, the `/connect` WebSocket endpoint, `/install.sh` and
//! `/download/{file}`. Certificates come from static PEM files, ACME
//! (TLS-ALPN-01, apex domains), or a generated self-signed dev cert
//! (`--dev`) for local testing.
//!
//! Usage: ddns-server --domain tunnel.example.com [options]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ddns_server::{AcmeOptions, AcmeProvider, Broker, BrokerConfig, TokenStore};

const USAGE: &str = "\
Usage: ddns-server --domain DOMAIN [OPTIONS]

Operator launcher for the ddns tunnel broker.

Required:
  --domain DOMAIN         Tunnel apex domain (e.g. tunnel.example.com)

Certificate (exactly one source):
  --cert FILE --key FILE  Static PEM cert chain + private key
  --acme-email EMAIL      ACME (automatic certificates) via TLS-ALPN-01 (apex
                          domains only; wildcards need DNS-01, which v1 does
                          not drive)
  --dev                   Self-signed cert for DOMAIN, *.DOMAIN and loopback
                          addresses; writes <db>.dev-ca.pem for the client's
                          --ca-pem flag

Options:
  --listen ADDR           Bind address (default 0.0.0.0:443)
  --public-port N         Port advertised in registered tcp_addr (default 443)
  --http-listen ADDR      Optional plain-HTTP listener (301 -> HTTPS + HTTP-01)
  --db PATH               SQLite database path (default ddns.db)
  --max-sessions N        Server-wide session cap (default 256)
  --watchdog-ms N         Quota watchdog tick in ms (default 5000)
  --download-dir PATH     Directory served by /download/{file}
  --web-dist PATH         Directory served by /_assets/{path} (default dist/public)
  --acme-directory URL    ACME directory override (default: production LE)
  --max-streams-per-session N
                          Server-wide hard cap on concurrent streams per
                          session, independent of token limits (default 512)
  --redis-url URL         Cache URL for the token-balance hot counter
                          (default: none; SQLite-only metering)
  --stun-port N           UDP port for the embedded RFC 5389 STUN server
                          (WebRTC ICE candidate gathering; default: disabled)
  --udp-port N            Public UDP listener for UDP tunnels (0 = disabled,
                          default 0). Requires a client started with --udp.
  --help                  Show this help";

struct Args {
    domain: String,
    listen: SocketAddr,
    public_port: u16,
    http_listen: Option<SocketAddr>,
    db: PathBuf,
    max_sessions: usize,
    max_streams_per_session: usize,
    watchdog: Duration,
    download_dir: Option<PathBuf>,
    web_dist: PathBuf,
    cert: Option<(PathBuf, PathBuf)>,
    acme_email: Option<String>,
    acme_directory: Option<String>,
    dev: bool,
    redis_url: Option<String>,
    stun_port: Option<u16>,
    udp_port: u16,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut domain: Option<String> = None;
    let mut listen: Option<SocketAddr> = None;
    let mut public_port: Option<u16> = None;
    let mut http_listen: Option<SocketAddr> = None;
    let mut db: Option<PathBuf> = None;
    let mut max_sessions: Option<usize> = None;
    let mut max_streams_per_session: Option<usize> = None;
    let mut watchdog_ms: Option<u64> = None;
    let mut download_dir: Option<PathBuf> = None;
    let mut web_dist: Option<PathBuf> = None;
    let mut cert: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut acme_email: Option<String> = None;
    let mut acme_directory: Option<String> = None;
    let mut redis_url: Option<String> = None;
    let mut stun_port: Option<u16> = None;
    let mut udp_port: Option<u16> = None;
    let mut dev = false;

    let mut i = 0;
    while i < args.len() {
        let flag = &args[i];
        let value = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag {flag} requires a value"))
        };
        match flag.as_str() {
            "--help" => return Err(USAGE.to_string()),
            "--domain" => domain = Some(value(&mut i)?),
            "--listen" => listen = Some(value(&mut i)?.parse().map_err(|_| "bad --listen addr")?),
            "--public-port" => {
                public_port = Some(value(&mut i)?.parse().map_err(|_| "bad --public-port")?)
            }
            "--http-listen" => {
                http_listen = Some(
                    value(&mut i)?
                        .parse()
                        .map_err(|_| "bad --http-listen addr")?,
                )
            }
            "--db" => db = Some(value(&mut i)?.into()),
            "--max-sessions" => {
                max_sessions = Some(value(&mut i)?.parse().map_err(|_| "bad --max-sessions")?)
            }
            "--max-streams-per-session" => {
                max_streams_per_session = Some(
                    value(&mut i)?
                        .parse()
                        .map_err(|_| "bad --max-streams-per-session")?,
                )
            }
            "--watchdog-ms" => {
                watchdog_ms = Some(value(&mut i)?.parse().map_err(|_| "bad --watchdog-ms")?)
            }
            "--download-dir" => download_dir = Some(value(&mut i)?.into()),
            "--web-dist" => web_dist = Some(value(&mut i)?.into()),
            "--cert" => cert = Some(value(&mut i)?.into()),
            "--key" => key = Some(value(&mut i)?.into()),
            "--acme-email" => acme_email = Some(value(&mut i)?),
            "--acme-directory" => acme_directory = Some(value(&mut i)?),
            "--redis-url" => redis_url = Some(value(&mut i)?),
            "--stun-port" => {
                stun_port = Some(value(&mut i)?.parse().map_err(|_| "bad --stun-port")?)
            }
            "--udp-port" => udp_port = Some(value(&mut i)?.parse().map_err(|_| "bad --udp-port")?),
            "--dev" => dev = true,
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }

    let domain = domain.ok_or_else(|| "missing required --domain".to_string())?;
    let cert_sources = usize::from(cert.is_some() && key.is_some())
        + usize::from(acme_email.is_some())
        + usize::from(dev);
    if cert_sources == 0 {
        return Err("no certificate source: pass --cert/--key, --acme-email, or --dev".to_string());
    }
    if cert_sources > 1 {
        return Err("--cert/--key, --acme-email and --dev are mutually exclusive".to_string());
    }
    if cert.is_some() != key.is_some() {
        return Err("--cert and --key must be used together".to_string());
    }
    if acme_directory.is_some() && acme_email.is_none() {
        return Err("--acme-directory requires --acme-email".to_string());
    }

    Ok(Args {
        domain,
        listen: listen.unwrap_or_else(|| "0.0.0.0:443".parse().unwrap()),
        public_port: public_port.unwrap_or(443),
        http_listen,
        db: db.unwrap_or_else(|| PathBuf::from("ddns.db")),
        max_sessions: max_sessions.unwrap_or(256),
        max_streams_per_session: max_streams_per_session.unwrap_or(512),
        watchdog: Duration::from_millis(watchdog_ms.unwrap_or(5000)),
        download_dir,
        web_dist: web_dist.unwrap_or_else(|| PathBuf::from("dist/public")),
        cert: match (cert, key) {
            (Some(c), Some(k)) => Some((c, k)),
            _ => None,
        },
        acme_email,
        acme_directory,
        dev,
        redis_url,
        stun_port,
        udp_port: udp_port.unwrap_or(0),
    })
}

/// Generate a self-signed leaf cert covering the domain, its wildcard, and
/// loopback addresses so a client can dial `https://127.0.0.1:PORT` with the
/// same CA. The cert IS the trust anchor: `--ca-pem <db>.dev-ca.pem`.
fn dev_cert(domain: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    use rcgen::{CertificateParams, KeyPair};
    let sans = vec![
        domain.to_string(),
        format!("*.{domain}"),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "localhost".to_string(),
    ];
    let params = CertificateParams::new(sans).map_err(|e| format!("rcgen params: {e}"))?;
    let key = KeyPair::generate().map_err(|e| format!("rcgen keygen: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("rcgen sign: {e}"))?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

fn read_pem(path: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("ddns-server: {e}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let opts = match parse(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            if e == USAGE {
                println!("{USAGE}");
                return Ok(());
            }
            return Err(e);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let (tls_cert_pem, tls_key_pem, acme, dev_ca_path) = if let Some((c, k)) = &opts.cert {
        (read_pem(c)?, read_pem(k)?, None, None)
    } else if opts.dev {
        let (cert, key) = dev_cert(&opts.domain)?;
        let ca_path = {
            let mut p = opts.db.clone();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "ddns.db".into());
            p.pop();
            p.push(format!("{name}.dev-ca.pem"));
            p
        };
        std::fs::write(&ca_path, &cert).map_err(|e| format!("write {}: {e}", ca_path.display()))?;
        (cert, key, None, Some(ca_path))
    } else {
        // --acme-email, guaranteed by parse's cert-source validation.
        let email = opts.acme_email.clone().expect("acme email set");
        (
            Vec::new(),
            Vec::new(),
            Some(AcmeOptions {
                domains: vec![opts.domain.clone()],
                contact_email: Some(email),
                provider: AcmeProvider::Manual,
                directory_url: opts.acme_directory.clone(),
            }),
            None,
        )
    };

    let token_store =
        TokenStore::open(&opts.db).map_err(|e| format!("open {}: {e}", opts.db.display()))?;
    // Fail-fast guard: verification and password-reset emails carry account
    // tokens, so an SMTP-enabled
    // broker must never build those links on plain http (the default
    // DDNS_BASE_URL is http://127.0.0.1:<port>). --dev keeps loopback http.
    let smtp_enabled = std::env::var("DDNS_SMTP_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some();
    let base_url_env = std::env::var("DDNS_BASE_URL").ok();
    if smtp_enabled
        && !opts.dev
        && base_url_env
            .as_deref()
            .map(|u| u.starts_with("http://"))
            .unwrap_or(true)
    {
        eprintln!(
            "refusing to start: SMTP is enabled but DDNS_BASE_URL is {} — \
             verification/reset emails would carry account tokens as http:// links. \
             Set DDNS_BASE_URL=https://<public-host> (or pass --dev for loopback http).",
            base_url_env
                .as_deref()
                .unwrap_or("unset (defaults to http://127.0.0.1:<port>)")
        );
        std::process::exit(1);
    }

    let config = BrokerConfig {
        listen: opts.listen,
        domain: opts.domain.clone(),
        public_port: opts.public_port,
        udp_port: opts.udp_port,
        udp_target_port: 0,
        tls_cert_pem,
        tls_key_pem,
        token_store,
        max_sessions: opts.max_sessions,
        max_streams_per_session: opts.max_streams_per_session,
        watchdog_interval: opts.watchdog,
        http_listen: opts.http_listen,
        stun_listen: opts
            .stun_port
            .map(|p| format!("0.0.0.0:{p}").parse().unwrap()),
        acme,
        download_dir: opts.download_dir,
        web_dist: opts.web_dist,
        dev: opts.dev,
        base_url: std::env::var("DDNS_BASE_URL")
            .unwrap_or_else(|_| format!("http://127.0.0.1:{}", opts.listen.port())),
        redis_url: opts.redis_url.or_else(|| {
            std::env::var("DDNS_REDIS_URL")
                .ok()
                .filter(|s| !s.is_empty())
        }),
    };

    let broker = Broker::start(config).await.map_err(|e| e.to_string())?;
    println!(
        "ddns-server listening on {} (public port {})\n  domain: {}",
        broker.addr, opts.public_port, opts.domain
    );
    println!(
        "  dashboard: https://{}:{}/",
        broker.addr.ip(),
        broker.addr.port()
    );
    println!("  first run: open the dashboard and set the admin password on /setup");
    if let Some(ca) = dev_ca_path {
        println!("  dev CA (client --ca-pem): {}", ca.display());
    }
    println!("  ctrl-c to stop");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("ctrl_c: {e}"))?;
    broker.stop().await;
    println!("ddns-server stopped");
    Ok(())
}
