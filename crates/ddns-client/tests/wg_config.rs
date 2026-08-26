//! WG key + config unit tests (plan Task 2).

use ddns_client::wg::config::{
    ExitPeerConfig, FirewallCmd, Platform, RouteCmd, VisitorWgConfig, WG_SUBNET,
};
use ddns_client::wg::keys::generate_keypair;
use std::net::{IpAddr, Ipv4Addr};

fn visitor_cfg_fixture() -> VisitorWgConfig {
    VisitorWgConfig {
        exit_pubkey_b64: "pk".into(),
        exit_endpoint: "127.0.0.1:51820".parse().unwrap(),
        tun_addr: Ipv4Addr::new(10, 200, 200, 2),
    }
}

fn exit_peer_fixture() -> ExitPeerConfig {
    ExitPeerConfig {
        visitor_pubkey_b64: "cHVi".into(), // base64("pub")
        visitor_tunnel_ip: Ipv4Addr::new(10, 200, 200, 2),
        psk: [7u8; 32].into(),
    }
}

fn broker_ip() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}

#[test]
fn keypair_roundtrip_and_distinctness() {
    let (sk1, pk1) = generate_keypair();
    let (sk2, pk2) = generate_keypair();
    assert_ne!(sk1.to_bytes(), sk2.to_bytes());
    assert_ne!(pk1.to_bytes(), pk2.to_bytes());
    assert_eq!(pk1.to_bytes().len(), 32);
    assert_eq!(sk1.public_key().to_bytes(), pk1.to_bytes());
}

#[test]
fn visitor_route_plan_order() {
    let cfg = visitor_cfg_fixture();
    let plan = cfg.render_route_plan(&[broker_ip()]);
    assert!(
        matches!(plan[0], RouteCmd::AddHostVia { dst, .. } if dst == broker_ip()),
        "host exception first"
    );
    assert!(matches!(plan[1], RouteCmd::AddDefaultVia(_)));
    assert!(matches!(plan[plan.len() - 1], RouteCmd::Restore(_)));
}

#[test]
fn visitor_kill_switch_is_install_remove_pair() {
    let cfg = visitor_cfg_fixture();
    let plan = cfg.render_kill_switch(Platform::Linux);
    assert_eq!(plan, vec![FirewallCmd::Install, FirewallCmd::Remove]);
}

#[test]
fn exit_peer_renders_slash32_and_psk() {
    let s = exit_peer_fixture().render_wg_set_peer();
    assert!(
        s.contains("allowed-ips 10.200.200.2/32"),
        "/32 routing: {s}"
    );
    assert!(s.contains("preshared-key"), "PSK present");
    assert!(s.starts_with("wg set wg0 peer "), "wg set shape");
}

#[test]
fn nft_ruleset_has_policy_drop_and_scoped_masquerade() {
    let s = ExitPeerConfig::render_nft_ruleset("wg0", "eth0", WG_SUBNET);
    assert!(s.contains("policy drop"), "forward default drop");
    assert!(s.contains("ip saddr 10.200.200.0/24"), "source-scoped");
    assert!(s.contains("masquerade"));
    assert!(s.contains("established,related"), "stateful replies");
    assert!(!s.contains("0.0.0.0/0"), "never broad NAT");
}
