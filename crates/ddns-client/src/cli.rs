//! Hand-rolled flag parsing (single static binary; no clap dependency).
//!
//! Usage:
//!   ddns --token tok_xxx --port 8080
//!   ddns --token tok_xxx --tcp 22
//!   ddns --token tok_xxx --local tcp://192.168.1.50:5432
//!   ddns --token tok_xxx --port 8080 --name demo
//!
//! At least one of --port / --tcp / --local is required. --local may be
//! repeated (one http target + one tcp target). --server defaults to
//! `https://tunnel.example.com`. --name is accepted but NOT transmitted
//! (ddns-proto Register has no name field; frozen).

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use ddns_proto::HEARTBEAT_INTERVAL;

use crate::targets::LocalTarget;

#[derive(Debug, Clone)]
pub struct Cli {
    pub token: String,
    /// https://host[:port] — converted to wss://host[:port]/connect
    pub server: String,
    pub http_target: Option<LocalTarget>,
    pub tcp_target: Option<LocalTarget>,
    pub name: Option<String>,
    pub ca_pem: Option<PathBuf>,
    pub heartbeat_interval: Duration,
}

/// A parsed top-level command. `Tunnel` is the existing token-registered relay
/// mode; `Connect` is the `ddns connect` native-visitor P2P helper (no token,
/// no tunnel registration).
#[derive(Debug, Clone)]
pub enum Command {
    Tunnel(Cli),
    Connect {
        /// `https://host[:port]` (default `https://tunnel.example.com`).
        server: String,
        subdomain: String,
        ca_pem: Option<String>,
    },
}

/// Sentinal returned by `parse` when `--help` is requested.
/// The caller should print usage and exit 0.
pub const HELP_SENTINEL: &str = "__help_requested__";

pub const USAGE: &str = "\
Usage:
  ddns --token TOKEN [OPTIONS]
  ddns connect <sub> | <https://sub.domain[:port]> [--ca-pem PATH]

A static binary that either opens a WSS tunnel to the ddns broker (register
with a token) or connects to a tunnel's TCP target directly over WebRTC
(P2P; `connect` needs no token — on punch failure it prints the relay address).

Options:
  --token TOKEN    Authentication token (required for tunnel mode)
  --server URL     Broker URL (default: https://tunnel.example.com)
  --port N         Local HTTP port to forward (e.g. 8080)
  --tcp N          Local TCP port to forward (e.g. 22)
  --local URL      Local target as http://host:port or tcp://host:port
                   (repeatable; one per scheme)
  --name NAME      Friendly name (v1: not transmitted, reserved for future use)
  --ca-pem PATH    Extra CA certificate PEM file for custom TLS roots
  --help           Show this help message";

/// Parse CLI arguments.
///
/// Rules:
/// - Flags: --token, --server, --port, --tcp, --local, --name, --ca-pem
/// - --server must be https:// or wss://; defaults to https://tunnel.example.com
/// - At least one of --port/--tcp/--local required
/// - --local repeated: later occurrences overwrite the target for their scheme
/// - heartbeat_interval: env DDNS_HEARTBEAT_MS (ms override) else HEARTBEAT_INTERVAL
pub fn parse(args: &[String]) -> Result<Cli, String> {
    let mut token: Option<String> = None;
    let mut server: Option<String> = None;
    let mut http_target: Option<LocalTarget> = None;
    let mut tcp_target: Option<LocalTarget> = None;
    let mut name: Option<String> = None;
    let mut ca_pem: Option<PathBuf> = None;
    let mut i = 0;

    while i < args.len() {
        let flag = &args[i];
        let require_value = || Err(format!("flag {flag} requires a value"));

        match flag.as_str() {
            "--token" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                token = Some(args[i].clone());
            }
            "--server" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                let val = args[i].clone();
                if !val.starts_with("https://") && !val.starts_with("wss://") {
                    return Err("--server must be https:// or wss://".to_string());
                }
                // strip trailing /
                let val = val.trim_end_matches('/').to_string();
                server = Some(val);
            }
            "--port" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                let port: u16 = args[i]
                    .parse()
                    .map_err(|_| format!("invalid port: {}", args[i]))?;
                if port == 0 {
                    return Err("invalid port: 0".to_string());
                }
                http_target = Some(LocalTarget::http(port));
            }
            "--tcp" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                let port: u16 = args[i]
                    .parse()
                    .map_err(|_| format!("invalid port: {}", args[i]))?;
                if port == 0 {
                    return Err("invalid port: 0".to_string());
                }
                tcp_target = Some(LocalTarget::tcp(port));
            }
            "--local" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                let target = LocalTarget::from_url(&args[i])?;
                match target.kind {
                    ddns_proto::StreamKind::Http => http_target = Some(target),
                    ddns_proto::StreamKind::Tcp => tcp_target = Some(target),
                }
            }
            "--name" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                name = Some(args[i].clone());
            }
            "--ca-pem" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                ca_pem = Some(PathBuf::from(&args[i]));
            }
            "--help" => {
                return Err(HELP_SENTINEL.to_string());
            }
            other => {
                if other.starts_with('-') {
                    return Err(format!("unknown flag {other}"));
                }
                // non-flag argument — skip (could be the program name)
            }
        }
        i += 1;
    }

    let token = token.ok_or("flag --token is required")?;
    if token.is_empty() {
        return Err("--token must not be empty".to_string());
    }
    let server = server.unwrap_or_else(|| "https://tunnel.example.com".to_string());

    if http_target.is_none() && tcp_target.is_none() {
        return Err("at least one of --port, --tcp, or --local is required".to_string());
    }

    let heartbeat_interval = match env::var("DDNS_HEARTBEAT_MS") {
        Ok(val) => {
            let ms: u64 = val
                .parse()
                .map_err(|_| format!("invalid DDNS_HEARTBEAT_MS: {val}"))?;
            Duration::from_millis(ms)
        }
        Err(_) => HEARTBEAT_INTERVAL,
    };

    Ok(Cli {
        token,
        server,
        http_target,
        tcp_target,
        name,
        ca_pem,
        heartbeat_interval,
    })
}

/// Dispatch on the first argument: `connect` → `Command::Connect`; anything
/// else → `Command::Tunnel(parse(args)?)` (existing behavior, untouched).
///
/// Callers pass `&args[1..]` (argv without the program name).
pub fn parse_command(args: &[String]) -> Result<Command, String> {
    if args.first().map(String::as_str) == Some("connect") {
        parse_connect(&args[1..])
    } else {
        Ok(Command::Tunnel(parse(args)?))
    }
}

/// Parse the `connect` tail: `<target> [--ca-pem PATH]`.
fn parse_connect(args: &[String]) -> Result<Command, String> {
    let mut target: Option<String> = None;
    let mut ca_pem: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        let flag = &args[i];
        let require_value = || Err(format!("flag {flag} requires a value"));

        match flag.as_str() {
            "--ca-pem" => {
                i += 1;
                if i >= args.len() {
                    return require_value();
                }
                ca_pem = Some(args[i].clone());
            }
            "--help" => return Err(HELP_SENTINEL.to_string()),
            other if other.starts_with('-') => {
                return Err(format!("unknown flag {other}"));
            }
            other => {
                if target.is_some() {
                    return Err("connect accepts a single target".to_string());
                }
                target = Some(other.to_string());
            }
        }
        i += 1;
    }

    let target = target.ok_or_else(|| {
        "connect requires a target (subdomain or https://sub.domain[:port])".to_string()
    })?;
    let (subdomain, server) = parse_connect_target(&target)?;
    Ok(Command::Connect {
        server,
        subdomain,
        ca_pem,
    })
}

/// Default broker apex host when only a bare subdomain is given.
const DEFAULT_APEX: &str = "tunnel.example.com";
const DEFAULT_SERVER: &str = "https://tunnel.example.com";

/// Resolve a connect target into `(subdomain, server)`.
///
/// - `sub` → `(sub, "https://tunnel.example.com")`
/// - `https://sub.domain[:port]` → `(sub, "https://domain[:port]")`
fn parse_connect_target(target: &str) -> Result<(String, String), String> {
    let (scheme, rest) = if let Some(rest) = target.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = target.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = target.strip_prefix("wss://") {
        ("wss", rest)
    } else if let Some(rest) = target.strip_prefix("ws://") {
        ("ws", rest)
    } else {
        // Bare subdomain.
        let sub = target.trim().trim_end_matches('/');
        if sub.is_empty() || sub.contains('/') || sub.contains(':') {
            return Err(format!("invalid connect target: {target}"));
        }
        return Ok((sub.to_string(), DEFAULT_SERVER.to_string()));
    };

    let rest = rest.trim_end_matches('/');
    if rest.contains('/') {
        return Err(format!("connect target must be host[:port], got: {target}"));
    }

    let (host, port) = split_host_port(rest)?;
    let (subdomain, apex) = match host.split_once('.') {
        Some((sub, apex)) if !sub.is_empty() && !apex.is_empty() => {
            (sub.to_string(), apex.to_string())
        }
        _ => (host.clone(), DEFAULT_APEX.to_string()),
    };

    let server = match port {
        Some(port) => format!("{scheme}://{apex}:{port}"),
        None => format!("{scheme}://{apex}"),
    };
    Ok((subdomain, server))
}

/// Split `host[:port]` (or `[ipv6]:port`) into host and optional port.
pub(crate) fn split_host_port(hostport: &str) -> Result<(String, Option<u16>), String> {
    if hostport.starts_with('[') {
        let close = hostport
            .find(']')
            .ok_or_else(|| "invalid IPv6 in connect target".to_string())?;
        let host = hostport[..=close].to_string();
        let after = &hostport[close + 1..];
        let port = if let Some(port_str) = after.strip_prefix(':') {
            Some(
                port_str
                    .parse()
                    .map_err(|_| format!("invalid port: {port_str}"))?,
            )
        } else {
            None
        };
        return Ok((host, port));
    }
    if let Some((host, port_str)) = hostport.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port: {port_str}"))?;
        Ok((host.to_string(), Some(port)))
    } else {
        Ok((hostport.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_subdomain_and_server() {
        let cmd = parse_command(&["connect".into(), "myapp".into()]).unwrap();
        match cmd {
            Command::Connect {
                server, subdomain, ..
            } => {
                assert_eq!(server, "https://tunnel.example.com");
                assert_eq!(subdomain, "myapp");
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn parse_connect_full_url() {
        let cmd = parse_command(&[
            "connect".into(),
            "https://myapp.tunnel.example.com:8443".into(),
        ])
        .unwrap();
        match cmd {
            Command::Connect {
                server, subdomain, ..
            } => {
                assert_eq!(server, "https://tunnel.example.com:8443");
                assert_eq!(subdomain, "myapp");
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn parse_tunnel_unchanged() {
        let cmd = parse_command(&[
            "--token".into(),
            "tok_x".into(),
            "--port".into(),
            "8080".into(),
        ])
        .unwrap();
        assert!(matches!(cmd, Command::Tunnel(_)));
    }
}
