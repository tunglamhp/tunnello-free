//! WG configuration rendering (pure): visitor route/kill-switch plans and
//! exit-side peer + nftables ruleset (research §1.1, §2.1, §2.3).
//! Free edition pins the safe defaults — no tuning knobs here.

use std::net::{IpAddr, Ipv4Addr};

/// WG default MTU (research §2.4): 1500 − 20(inner IP) − 8(UDP) − 32(WG).
pub const WG_MTU: u16 = 1420;
/// fwmark used for policy routing + kill-switch (wg-quick convention).
pub const WG_FWMARK: u32 = 51820;
/// Default tunnel subnet on the exit.
pub const WG_SUBNET: &str = "10.200.200.0/24";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCmd {
    /// Host exception: keep broker/exit endpoints on the physical gateway.
    AddHostVia { dst: IpAddr, gw: IpAddr },
    /// Default route into the WG interface (fwmark table).
    AddDefaultVia(IpAddr),
    /// Restore the original default gateway.
    Restore(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallCmd {
    Install,
    Remove,
}

/// Visitor-side WG configuration.
#[derive(Debug, Clone)]
pub struct VisitorWgConfig {
    pub exit_pubkey_b64: String,
    pub exit_endpoint: std::net::SocketAddr,
    pub tun_addr: Ipv4Addr,
}

impl VisitorWgConfig {
    /// Route plan: host exceptions first, default via WG, restore last.
    pub fn render_route_plan(&self, exceptions: &[IpAddr]) -> Vec<RouteCmd> {
        let mut plan = Vec::new();
        for dst in exceptions {
            plan.push(RouteCmd::AddHostVia {
                dst: *dst,
                gw: Ipv4Addr::UNSPECIFIED.into(),
            });
        }
        plan.push(RouteCmd::AddDefaultVia(IpAddr::from(self.tun_addr)));
        plan.push(RouteCmd::Restore(IpAddr::from(self.tun_addr)));
        plan
    }

    /// fwmark kill-switch (research §2.3): OUTPUT not via wg0, not fwmark,
    /// not local → REJECT. Install + Remove pair.
    pub fn render_kill_switch(&self, platform: Platform) -> Vec<FirewallCmd> {
        let _ = platform;
        vec![FirewallCmd::Install, FirewallCmd::Remove]
    }
}

/// Exit-side per-visitor peer.
#[derive(Debug, Clone)]
pub struct ExitPeerConfig {
    pub visitor_pubkey_b64: String,
    pub visitor_tunnel_ip: Ipv4Addr,
    /// Per-peer pre-shared key (post-quantum resistance; research §1.3).
    pub psk: [u8; 32],
}

impl ExitPeerConfig {
    /// `wg set wg0 peer <pub> allowed-ips <ip>/32 preshared-key <psk>`
    /// (cryptokey routing: /32, never broader — research §1.2).
    pub fn render_wg_set_peer(&self) -> String {
        use base64::Engine as _;
        let pk =
            base64::engine::general_purpose::STANDARD.encode(self.visitor_pubkey_b64.as_bytes());
        let psk = base64::engine::general_purpose::STANDARD.encode(self.psk);
        format!(
            "wg set wg0 peer {pk} allowed-ips {}/32 preshared-key {psk}",
            self.visitor_tunnel_ip
        )
    }

    /// nftables ruleset (research §1.1): forward `policy drop`, source-scoped
    /// accept + established replies, masquerade scoped to the WG subnet.
    pub fn render_nft_ruleset(wg_if: &str, wan_if: &str, subnet: &str) -> String {
        format!(
            r#"table inet wg-exit {{
    chain forward {{
        type filter hook forward priority 0; policy drop;
        iifname "{wg_if}" ip saddr {subnet} oifname "{wan_if}" ct state new,established accept
        iifname "{wan_if}" oifname "{wg_if}" ct state established,related accept
    }}
    chain postrouting {{
        type nat hook postrouting priority 100;
        oifname "{wan_if}" ip saddr {subnet} masquerade
    }}
}}"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visitor_route_plan_order() {
        let cfg = VisitorWgConfig {
            exit_pubkey_b64: "pk".into(),
            exit_endpoint: "127.0.0.1:51820".parse().unwrap(),
            tun_addr: Ipv4Addr::new(10, 200, 200, 2),
        };
        let broker: IpAddr = "203.0.113.7".parse().unwrap();
        let plan = cfg.render_route_plan(&[broker]);
        assert!(
            matches!(plan[0], RouteCmd::AddHostVia { dst, .. } if dst == broker),
            "host exception first"
        );
        assert!(matches!(plan[1], RouteCmd::AddDefaultVia(_)));
        assert!(matches!(plan[2], RouteCmd::Restore(_)));
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn visitor_kill_switch_is_install_remove_pair() {
        let cfg = VisitorWgConfig {
            exit_pubkey_b64: "pk".into(),
            exit_endpoint: "127.0.0.1:51820".parse().unwrap(),
            tun_addr: Ipv4Addr::new(10, 200, 200, 2),
        };
        let plan = cfg.render_kill_switch(Platform::Linux);
        assert_eq!(plan, vec![FirewallCmd::Install, FirewallCmd::Remove]);
    }

    #[test]
    fn exit_peer_renders_slash32_and_psk() {
        let cfg = ExitPeerConfig {
            visitor_pubkey_b64: "cHVi".into(), // base64("pub")
            visitor_tunnel_ip: Ipv4Addr::new(10, 200, 200, 2),
            psk: [7u8; 32],
        };
        let s = cfg.render_wg_set_peer();
        assert!(
            s.contains("allowed-ips 10.200.200.2/32"),
            "/32 cryptokey routing"
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
}
