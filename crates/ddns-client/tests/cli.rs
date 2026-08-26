//! Unit tests for CLI argument parsing.
//!
//! Pure unit tests — no broker, no async, no integration.

use ddns_client::cli;
use ddns_client::targets::LocalTarget;
use ddns_proto::StreamKind;

// ---------------------------------------------------------------------------
// Parse matrix (from the spec)
// ---------------------------------------------------------------------------

#[test]
fn defaults_token_port_8080() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--port".into(),
        "8080".into(),
    ])
    .unwrap();

    let ht = cli.http_target.as_ref().unwrap();
    assert_eq!(ht.port, 8080);
    assert_eq!(ht.host, "127.0.0.1");
    assert_eq!(ht.kind, StreamKind::Http);
    assert!(cli.tcp_target.is_none());
    assert_eq!(cli.server, "https://tunnel.example.com");
    assert_eq!(cli.heartbeat_interval, ddns_proto::HEARTBEAT_INTERVAL);
}

#[test]
fn tcp_22() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--tcp".into(),
        "22".into(),
    ])
    .unwrap();

    assert!(cli.http_target.is_none());
    let tt = cli.tcp_target.as_ref().unwrap();
    assert_eq!(tt.port, 22);
    assert_eq!(tt.host, "127.0.0.1");
    assert_eq!(tt.kind, StreamKind::Tcp);
}

#[test]
fn local_tcp_url() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--local".into(),
        "tcp://192.168.1.50:5432".into(),
    ])
    .unwrap();

    assert!(cli.http_target.is_none());
    let tt = cli.tcp_target.as_ref().unwrap();
    assert_eq!(tt.host, "192.168.1.50");
    assert_eq!(tt.port, 5432);
    assert_eq!(tt.kind, StreamKind::Tcp);
}

#[test]
fn local_http_ipv6_bracket_stripped() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--local".into(),
        "http://[::1]:8080".into(),
    ])
    .unwrap();

    assert!(cli.tcp_target.is_none());
    let ht = cli.http_target.as_ref().unwrap();
    // Brackets MUST be stripped: host is "::1", not "[::1]".
    assert_eq!(ht.host, "::1");
    assert_eq!(ht.port, 8080);
    assert_eq!(ht.kind, StreamKind::Http);
}

#[test]
fn port_and_tcp_both_set() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--port".into(),
        "8080".into(),
        "--tcp".into(),
        "22".into(),
    ])
    .unwrap();

    assert!(cli.http_target.is_some());
    assert!(cli.tcp_target.is_some());
    assert_eq!(cli.http_target.unwrap().port, 8080);
    assert_eq!(cli.tcp_target.unwrap().port, 22);
}

#[test]
fn port_zero_is_error() {
    let err = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--port".into(),
        "0".into(),
    ])
    .unwrap_err();

    assert!(
        err.to_lowercase().contains("port") || err.to_lowercase().contains("invalid"),
        "expected port/invalid error, got: {err}"
    );
}

#[test]
fn tcp_zero_is_error() {
    let err = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--tcp".into(),
        "0".into(),
    ])
    .unwrap_err();

    assert!(
        err.to_lowercase().contains("port") || err.to_lowercase().contains("invalid"),
        "expected port/invalid error, got: {err}"
    );
}

#[test]
fn name_accepted() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--port".into(),
        "8080".into(),
        "--name".into(),
        "demo".into(),
    ])
    .unwrap();

    assert_eq!(cli.name.as_deref(), Some("demo"));
}

#[test]
fn repeated_local_http_then_tcp() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--local".into(),
        "http://127.0.0.1:3000".into(),
        "--local".into(),
        "tcp://10.0.0.5:6000".into(),
    ])
    .unwrap();

    let ht = cli.http_target.as_ref().unwrap();
    assert_eq!(ht.port, 3000);
    assert_eq!(ht.kind, StreamKind::Http);

    let tt = cli.tcp_target.as_ref().unwrap();
    assert_eq!(tt.host, "10.0.0.5");
    assert_eq!(tt.port, 6000);
    assert_eq!(tt.kind, StreamKind::Tcp);
}

#[test]
fn server_wss_kept_verbatim() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--server".into(),
        "wss://h:8443".into(),
        "--port".into(),
        "8080".into(),
    ])
    .unwrap();

    assert_eq!(cli.server, "wss://h:8443");
}

#[test]
fn server_https_strip_trailing_slash() {
    let cli = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--server".into(),
        "https://tunnel.example.com/".into(),
        "--port".into(),
        "8080".into(),
    ])
    .unwrap();

    assert_eq!(cli.server, "https://tunnel.example.com");
}

#[test]
fn unknown_flag_is_error() {
    let err = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "t".into(),
        "--port".into(),
        "8080".into(),
        "--bogus".into(),
    ])
    .unwrap_err();

    assert!(
        err.contains("unknown"),
        "expected 'unknown flag' error, got: {err}"
    );
}

#[test]
fn missing_value_is_error() {
    let err = cli::parse(&["ddns".into(), "--token".into()]).unwrap_err();

    assert!(
        err.contains("requires a value") || err.contains("value"),
        "expected missing-value error, got: {err}"
    );
}

#[test]
fn empty_token_is_error() {
    let err = cli::parse(&[
        "ddns".into(),
        "--token".into(),
        "".into(),
        "--port".into(),
        "8080".into(),
    ])
    .unwrap_err();

    assert!(
        err.to_lowercase().contains("token") && err.to_lowercase().contains("empty"),
        "expected empty-token error, got: {err}"
    );
}

#[test]
fn help_flag_returns_sentinel() {
    let err = cli::parse(&["ddns".into(), "--help".into()]).unwrap_err();
    assert_eq!(err, cli::HELP_SENTINEL);
}

// ---------------------------------------------------------------------------
// LocalTarget::from_url error cases
// ---------------------------------------------------------------------------

#[test]
fn from_url_bad_scheme() {
    let err = LocalTarget::from_url("ftp://127.0.0.1:80").unwrap_err();
    assert!(
        err.to_lowercase().contains("scheme") || err.to_lowercase().contains("unknown"),
        "expected scheme error, got: {err}"
    );
}

#[test]
fn from_url_missing_port() {
    // "http://127.0.0.1" → rsplit_once(':') gives ("http://127.0.0", "1")
    // but that actually parses! Use a hostname to make it clear.
    let err = LocalTarget::from_url("http://hostname").unwrap_err();
    assert!(
        err.to_lowercase().contains("port") || err.contains(":"),
        "expected missing-port error, got: {err}"
    );
}

#[test]
fn from_url_non_numeric_port() {
    let err = LocalTarget::from_url("http://127.0.0.1:abc").unwrap_err();
    assert!(
        err.to_lowercase().contains("port") || err.to_lowercase().contains("invalid"),
        "expected non-numeric-port error, got: {err}"
    );
}

#[test]
fn from_url_no_scheme() {
    let err = LocalTarget::from_url("127.0.0.1:80").unwrap_err();
    assert!(
        err.contains("://") || err.contains("scheme") || err.contains("target"),
        "expected missing-scheme error, got: {err}"
    );
}

#[test]
fn from_url_ipv6_missing_bracket_close() {
    let err = LocalTarget::from_url("http://[::1:8080").unwrap_err();
    assert!(
        err.contains("]") || err.contains("IPv6"),
        "expected IPv6 bracket error, got: {err}"
    );
}

#[test]
fn from_url_ipv6_bare_no_port() {
    let err = LocalTarget::from_url("http://[::1]").unwrap_err();
    assert!(
        err.to_lowercase().contains("port") || err.contains(":"),
        "expected missing-port error for bare IPv6, got: {err}"
    );
}

#[test]
fn connect_parses_udp_flag() {
    let args = vec![
        "connect".into(),
        "myslug".into(),
        "--udp".into(),
        "53".into(),
    ];
    match cli::parse_command(&args).unwrap() {
        cli::Command::Connect { subdomain, udp, .. } => {
            assert_eq!(subdomain, "myslug");
            assert_eq!(udp, Some(53));
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[test]
fn connect_without_udp_is_tcp_mode() {
    let args = vec!["connect".into(), "myslug".into()];
    match cli::parse_command(&args).unwrap() {
        cli::Command::Connect { udp, .. } => assert_eq!(udp, None),
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[test]
fn connect_rejects_udp_port_zero() {
    let args = vec![
        "connect".into(),
        "myslug".into(),
        "--udp".into(),
        "0".into(),
    ];
    assert!(
        cli::parse_command(&args).is_err(),
        "port 0 must be rejected"
    );
}
