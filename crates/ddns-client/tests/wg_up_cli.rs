//! CLI parse tests for the `up` subcommand (plan Task 5).

use ddns_client::cli;

#[test]
fn up_parses_exit_node() {
    let args = vec!["up".into(), "myslug".into(), "--exit-node".into()];
    match cli::parse_command(&args).unwrap() {
        cli::Command::Up {
            subdomain,
            exit_node,
            cleanup,
            ..
        } => {
            assert_eq!(subdomain, "myslug");
            assert!(exit_node);
            assert!(!cleanup);
        }
        other => panic!("expected Up, got {other:?}"),
    }
}

#[test]
fn up_without_exit_node_flag() {
    let args = vec!["up".into(), "myslug".into()];
    match cli::parse_command(&args).unwrap() {
        cli::Command::Up { exit_node, .. } => assert!(!exit_node),
        other => panic!("expected Up, got {other:?}"),
    }
}

#[test]
fn up_parses_cleanup() {
    let args = vec!["up".into(), "--cleanup".into()];
    match cli::parse_command(&args).unwrap() {
        cli::Command::Up {
            cleanup, exit_node, ..
        } => {
            assert!(cleanup);
            assert!(!exit_node, "cleanup sweeps rules, no tunnel");
        }
        other => panic!("expected Up, got {other:?}"),
    }
}

#[test]
fn up_rejects_unknown_tuning_flags() {
    // Free edition: no tuning knobs (repo split rule).
    let args = vec![
        "up".into(),
        "myslug".into(),
        "--exit-node".into(),
        "--mtu".into(),
        "1280".into(),
    ];
    assert!(
        cli::parse_command(&args).is_err(),
        "tuning flags rejected in free"
    );
}
