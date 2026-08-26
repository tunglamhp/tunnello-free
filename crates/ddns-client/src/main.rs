//! ddns-client binary entry point.
//!
//! Parse CLI, load TLS roots, run the session with event printing,
//! exit with the appropriate code.

use std::process;

use ddns_client::cli::{self, Cli, Command, HELP_SENTINEL, USAGE};
use ddns_client::targets::LocalTarget;
use ddns_client::{Event, ExitStatus, TunnelInfo};
use ddns_proto::KillReason;

/// Structured logging (RUST_LOG filter, e.g. `RUST_LOG=ddns_client=debug`).
/// The gateway and mux log via `tracing`; without a subscriber every
/// `tracing::info!/warn!` was silently dropped.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn main() {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();

    // --help is handled inside cli::parse_command (single mechanism): it
    // returns the HELP_SENTINEL error, which we turn into a usage print +
    // exit 0. No argv pre-scan — that would also match "--help" in
    // flag-value position.
    let command = match cli::parse_command(&args[1..]) {
        Ok(c) => c,
        Err(e) => {
            if e == HELP_SENTINEL {
                println!("{USAGE}");
                process::exit(0);
            }
            eprintln!("ddns: {e}");
            process::exit(2);
        }
    };

    // WebPKI roots are loaded internally by connect::client_config.
    // No extra test CAs in production.
    let roots: &[rustls::pki_types::CertificateDer<'static>] = &[];

    match command {
        Command::Tunnel(cli) => run_tunnel(cli, roots),
        Command::Connect {
            server,
            subdomain,
            ca_pem,
            udp,
        } => match udp {
            None => run_connect(&server, &subdomain, ca_pem.as_deref(), roots),
            Some(_port) => run_connect_udp(&server, &subdomain, ca_pem.as_deref(), roots),
        },
    }
}

/// Run the token-registered tunnel session (the pre-`connect` behavior).
fn run_tunnel(cli: Cli, roots: &[rustls::pki_types::CertificateDer<'static>]) -> ! {
    // --name v1 note
    if cli.name.is_some() {
        eprintln!("note: --name is reserved for a future protocol revision (not transmitted)");
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let status = rt.block_on(ddns_client::run(cli.clone(), roots, |event| {
        print_event(&event, &cli.http_target, &cli.tcp_target)
    }));

    match status {
        ExitStatus::Clean => process::exit(0),
        ExitStatus::Killed(reason) => {
            print_kill_hint(reason);
            process::exit(1);
        }
        ExitStatus::Fatal => process::exit(3),
    }
}

/// Run the `ddns connect` native-visitor helper: exit 0 on a clean stop
/// (channel closed), 2 on punch failure (relay hint printed to stderr).
fn run_connect(
    server: &str,
    subdomain: &str,
    ca_pem: Option<&str>,
    roots: &[rustls::pki_types::CertificateDer<'static>],
) -> ! {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(ddns_client::connect_p2p::run_connect(
        server, subdomain, ca_pem, roots,
    ));

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("ddns: {e}");
            process::exit(2);
        }
    }
}

/// Number of screen lines the most recent print wrote. Cleared via ANSI
/// escape sequences before the next block so a reconnected subdomain replaces
/// the stale one on screen (spec §8 "clears terminal state between"). Only
/// clears on a real terminal; piped output stays a plain log.
static PENDING_LINES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Run the `ddns connect --udp` native-visitor helper (same exit contract as
/// [`run_connect`]).
fn run_connect_udp(
    server: &str,
    subdomain: &str,
    ca_pem: Option<&str>,
    roots: &[rustls::pki_types::CertificateDer<'static>],
) -> ! {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(ddns_client::connect_p2p::run_connect_udp(
        server, subdomain, ca_pem, roots,
    ));

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("ddns: {e}");
            process::exit(2);
        }
    }
}

fn clear_pending_lines() {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return;
    }
    let n = PENDING_LINES.swap(0, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..n {
        print!("\x1b[1A\x1b[2K");
    }
}

fn print_event(event: &Event, http_target: &Option<LocalTarget>, tcp_target: &Option<LocalTarget>) {
    match event {
        Event::Registered(info) => {
            // Replace the retry line + any stale subdomain block.
            clear_pending_lines();
            let block = tunnel_block(info, http_target, tcp_target);
            print!("{block}");
            PENDING_LINES.store(block.lines().count(), std::sync::atomic::Ordering::Relaxed);
        }
        Event::Killed { reason, usage } => {
            clear_pending_lines();
            match usage {
                Some(usage) => {
                    println!(
                        "Tunnel killed: {:?} ({}/{})",
                        reason, usage.bytes_tx, usage.bytes_rx
                    );
                }
                None => {
                    println!("Tunnel killed: {:?}", reason);
                }
            }
            PENDING_LINES.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        Event::Retrying { attempt, delay } => {
            clear_pending_lines();
            println!(
                "reconnecting in {}s (attempt {attempt})...",
                delay.as_secs()
            );
            PENDING_LINES.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        Event::Fatal(msg) => {
            eprintln!("error: {msg}");
        }
    }
}

/// Build the spec §8 tunnel-is-live block.
///
/// One line per present target, followed by "Press Ctrl-C to stop."
///
/// HTTP target:   `  https://<slug>.<domain>  →  http://<host>:<port>`
/// TCP target:    `  <slug>.<domain>:443       →  tcp://<host>:<port>`
///
/// This is a pure function so it can be unit-tested.
pub(crate) fn tunnel_block(
    info: &TunnelInfo,
    http_target: &Option<LocalTarget>,
    tcp_target: &Option<LocalTarget>,
) -> String {
    let mut lines = vec!["Tunnel is live:".to_string()];

    if let (Some(url), Some(target)) = (&info.http_url, http_target) {
        lines.push(format!(
            "  {url}  →  http://{}:{}",
            fmt_host(&target.host),
            target.port
        ));
    }

    if let (Some(addr), Some(target)) = (&info.tcp_addr, tcp_target) {
        lines.push(format!(
            "  {addr}      →  tcp://{}:{}",
            fmt_host(&target.host),
            target.port
        ));
    }

    lines.push("Press Ctrl-C to stop.".to_string());

    lines.join("\n") + "\n"
}

/// Re-wrap a bracketed-IPv6 host stripped by `LocalTarget::from_url`:
/// `::1` → `[::1]` so the printed URL is a valid RFC 3986 URI. IPv4 and
/// hostname targets pass through unchanged.
fn fmt_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn print_kill_hint(reason: KillReason) {
    let hint = match reason {
        KillReason::QuotaExceeded => {
            "hint: the tunnel exceeded its quota — upgrade your plan for more data"
        }
        KillReason::TtlExpired => {
            "hint: the tunnel session expired — reconnect to get a new subdomain"
        }
        KillReason::Admin => "hint: the tunnel was stopped by an administrator",
        KillReason::TokenExhausted => {
            "hint: your token balance is exhausted — top up or upgrade your plan"
        }
    };
    eprintln!("{hint}");
    eprintln!("check your token limits or the broker dashboard");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ddns_client::targets::LocalTarget;
    use ddns_proto::StreamKind;

    #[test]
    fn tunnel_block_http_only() {
        let info = TunnelInfo {
            slug: "vivid-otter-72".into(),
            http_url: Some("https://vivid-otter-72.tunnel.example.com".into()),
            tcp_addr: None,
        };
        let http_target = Some(LocalTarget::http(8080));
        let tcp_target: Option<LocalTarget> = None;

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert!(block.starts_with("Tunnel is live:\n"));
        assert!(block.contains("https://vivid-otter-72.tunnel.example.com"));
        assert!(block.contains("→  http://127.0.0.1:8080"));
        assert!(block.ends_with("Press Ctrl-C to stop.\n"));
    }

    #[test]
    fn tunnel_block_tcp_only() {
        let info = TunnelInfo {
            slug: "quiet-badger-4".into(),
            http_url: None,
            tcp_addr: Some("quiet-badger-4.tunnel.example.com:443".into()),
        };
        let http_target: Option<LocalTarget> = None;
        let tcp_target = Some(LocalTarget::tcp(5432));

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert!(block.starts_with("Tunnel is live:\n"));
        assert!(block.contains("quiet-badger-4.tunnel.example.com:443"));
        assert!(block.contains("→  tcp://127.0.0.1:5432"));
        assert!(!block.contains("http://"));
        assert!(block.ends_with("Press Ctrl-C to stop.\n"));
    }

    #[test]
    fn tunnel_block_both_targets() {
        let info = TunnelInfo {
            slug: "bold-fox-99".into(),
            http_url: Some("https://bold-fox-99.tunnel.example.com".into()),
            tcp_addr: Some("bold-fox-99.tunnel.example.com:443".into()),
        };
        let http_target = Some(LocalTarget::http(3000));
        let tcp_target = Some(LocalTarget::tcp(2222));

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert!(block.contains("https://bold-fox-99.tunnel.example.com"));
        assert!(block.contains("http://127.0.0.1:3000"));
        assert!(block.contains("bold-fox-99.tunnel.example.com:443"));
        assert!(block.contains("tcp://127.0.0.1:2222"));
    }

    #[test]
    fn tunnel_block_custom_local_target() {
        let info = TunnelInfo {
            slug: "test-slug".into(),
            http_url: Some("https://test-slug.tunnel.example.com".into()),
            tcp_addr: Some("test-slug.tunnel.example.com:443".into()),
        };
        let http_target = Some(LocalTarget {
            kind: StreamKind::Http,
            host: "10.0.0.1".into(),
            port: 9000,
        });
        let tcp_target = Some(LocalTarget {
            kind: StreamKind::Tcp,
            host: "192.168.1.100".into(),
            port: 2222,
        });

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert!(block.contains("→  http://10.0.0.1:9000"));
        assert!(block.contains("→  tcp://192.168.1.100:2222"));
    }

    #[test]
    fn tunnel_block_neither_target() {
        let info = TunnelInfo {
            slug: "no-targets".into(),
            http_url: None,
            tcp_addr: None,
        };
        let http_target: Option<LocalTarget> = None;
        let tcp_target: Option<LocalTarget> = None;

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert_eq!(block, "Tunnel is live:\nPress Ctrl-C to stop.\n");
    }

    #[test]
    fn tunnel_block_ipv6_local_target_re_bracketed() {
        // --local http://[::1]:8080 strips the brackets in LocalTarget::host
        // ("::1"); the printed block must re-wrap them for a valid URI.
        let info = TunnelInfo {
            slug: "ipv6-slug".into(),
            http_url: Some("https://ipv6-slug.tunnel.example.com".into()),
            tcp_addr: Some("ipv6-slug.tunnel.example.com:443".into()),
        };
        let http_target = Some(LocalTarget {
            kind: StreamKind::Http,
            host: "::1".into(),
            port: 8080,
        });
        let tcp_target = Some(LocalTarget {
            kind: StreamKind::Tcp,
            host: "::1".into(),
            port: 2222,
        });

        let block = tunnel_block(&info, &http_target, &tcp_target);
        assert!(block.contains("→  http://[::1]:8080"), "got: {block}");
        assert!(block.contains("→  tcp://[::1]:2222"), "got: {block}");
        assert!(
            !block.contains("http://::1"),
            "unbracketed IPv6 leaked: {block}"
        );
    }

    #[test]
    fn fmt_host_rebrackets_ipv6_only() {
        assert_eq!(fmt_host("::1"), "[::1]");
        assert_eq!(fmt_host("10.0.0.1"), "10.0.0.1");
        assert_eq!(fmt_host("localhost"), "localhost");
    }
}
