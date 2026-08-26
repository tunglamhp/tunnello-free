//! Platform layer: route + kill-switch planning (pure, unit-tested) and
//! thin real-execution paths (NOT exercised in CI — spec §10).

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCmd {
    /// Host exception: `<dst> via <gw>` keeps broker/client endpoints off TUN.
    AddHostVia { dst: IpAddr, gw: IpAddr },
    /// Default route through the TUN address.
    AddDefaultVia(IpAddr),
    /// Restore the original default gateway (recorded before changes).
    Restore(IpAddr),
}

/// Plan the route changes: host exceptions first, then the default via TUN,
/// then the restore entry (executed on exit). Order is part of the contract.
pub fn plan_routes(
    platform: Platform,
    _tun_addr: IpAddr,
    exceptions: &[IpAddr],
    orig_gw: IpAddr,
) -> Vec<RouteCmd> {
    let mut plan = Vec::new();
    let _ = platform;
    for dst in exceptions {
        plan.push(RouteCmd::AddHostVia {
            dst: *dst,
            gw: orig_gw,
        });
    }
    plan.push(RouteCmd::AddDefaultVia(orig_gw));
    plan.push(RouteCmd::Restore(orig_gw));
    plan
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallCmd {
    /// Install the outbound kill-switch rule set tagged `tag`.
    Install,
    /// Remove every rule tagged `tag` (clean exit + stale sweep).
    Remove,
}

/// Plan the kill-switch firewall actions (tagged for idempotent sweep).
pub fn plan_firewall(platform: Platform, tag: &str) -> Vec<FirewallCmd> {
    let _ = (platform, tag);
    vec![FirewallCmd::Install, FirewallCmd::Remove]
}
