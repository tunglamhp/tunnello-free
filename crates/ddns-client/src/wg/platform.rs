//! Platform layer planners (PURE, unit-tested) + real-execution notes.
//! Free edition: fwmark kill-switch + host exceptions + default route —
//! no tuning knobs (repo split rule).
//!
//! Execution (NOT exercised in CI — spec §9 manual checklist):
//! - Linux: `ip route`/`ip rule` via netlink or subprocess; nftables ruleset
//!   from `config::ExitPeerConfig::render_nft_ruleset` via `nft -f -`.
//! - Windows: `route ADD` + `netsh advfirewall` (admin required).
//! - Kill-switch (research §2.3): OUTPUT not via wg0, not fwmark, not local
//!   → REJECT. Tagged for idempotent sweep; `--cleanup` removes leftovers.

use std::net::IpAddr;

use super::config::{Platform, WG_FWMARK};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCmd {
    /// Host exception: keep broker/exit endpoints on the physical gateway
    /// (`ip route <dst> via <orig-gw>` / `route ADD <dst> MASK 255.255.255.255 <gw>`).
    AddHostVia { dst: IpAddr, gw: IpAddr },
    /// Policy routing: default via WG into the fwmark table
    /// (`ip route add default dev wg0 table 51820`).
    AddDefaultTable { table: u32 },
    /// fwmark rule (`ip rule add not fwmark 51820 table 51820`).
    AddFwmarkRule { fwmark: u32 },
    /// Suppress-prefix rule (keeps LAN reachable; research §2.1).
    AddSuppressRule { table: u32 },
    /// Restore the original default gateway on teardown.
    Restore(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallCmd {
    /// fwmark kill-switch REJECT rule (research §2.3).
    InstallReject { fwmark: u32 },
    /// Block IPv6 egress while tunneled (block-not-leak, research §2.2).
    InstallV6Block,
    /// Remove all tagged rules (clean exit + stale sweep).
    RemoveAll,
}

/// Route plan: exceptions → default table → fwmark rule → suppress → restore.
pub fn plan_routes(platform: Platform, exceptions: &[IpAddr], orig_gw: IpAddr) -> Vec<RouteCmd> {
    let mut plan = Vec::new();
    let _ = platform;
    for dst in exceptions {
        plan.push(RouteCmd::AddHostVia {
            dst: *dst,
            gw: orig_gw,
        });
    }
    plan.push(RouteCmd::AddDefaultTable { table: WG_FWMARK });
    plan.push(RouteCmd::AddFwmarkRule { fwmark: WG_FWMARK });
    plan.push(RouteCmd::AddSuppressRule { table: WG_FWMARK });
    plan.push(RouteCmd::Restore(orig_gw));
    plan
}

/// Firewall plan: install reject + v6 block, then remove (teardown/sweep).
pub fn plan_firewall(_platform: Platform) -> Vec<FirewallCmd> {
    vec![
        FirewallCmd::InstallReject { fwmark: WG_FWMARK },
        FirewallCmd::InstallV6Block,
        FirewallCmd::RemoveAll,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_route_plan_order_and_content() {
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let broker: IpAddr = "203.0.113.7".parse().unwrap();
        let plan = plan_routes(Platform::Linux, &[broker], gw);
        assert!(
            matches!(plan[0], RouteCmd::AddHostVia { dst, .. } if dst == broker),
            "host exception first"
        );
        assert!(matches!(
            plan[1],
            RouteCmd::AddDefaultTable { table: 51820 }
        ));
        assert!(matches!(plan[2], RouteCmd::AddFwmarkRule { fwmark: 51820 }));
        assert!(matches!(plan[3], RouteCmd::AddSuppressRule { .. }));
        assert_eq!(plan[4], RouteCmd::Restore(gw));
    }

    #[test]
    fn firewall_plan_has_fwmark_reject_and_v6_block() {
        let plan = plan_firewall(Platform::Windows);
        assert!(plan.contains(&FirewallCmd::InstallReject { fwmark: 51820 }));
        assert!(plan.contains(&FirewallCmd::InstallV6Block));
        assert!(plan.contains(&FirewallCmd::RemoveAll));
    }
}
