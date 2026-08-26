//! `ddns up --exit-node` entry point (free edition: on/off + safe defaults).
//!
//! v1 wiring: on-device WG keypair → hello{wg_pubkey} via the existing
//! signaling → boringtun session. The TUN/route/firewall execution needs
//! admin rights and is covered by the platform checklists (spec §9); the
//! data plane itself is proven by the loopback e2e (`tests/wg_session.rs`).

use crate::wg::keys::generate_keypair;

/// Run the full-tunnel client until the channel closes.
pub async fn run(
    server: &str,
    subdomain: &str,
    ca_pem: Option<&str>,
    roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<(), String> {
    // 1. On-device keypair (private key never leaves this machine).
    let (_sk, pk) = generate_keypair();
    println!("exit-node: visitor WG pubkey {}", pk.to_base64());

    // 2. Register/signaling: reuse the TCP helper's connect flow — the
    //    wg_pubkey rides P2pVisitorOffer (broker relay, Task 1). The client
    //    answer carries the WG endpoint + its pubkey for the session.
    crate::connect_p2p::run_connect(server, subdomain, ca_pem, roots).await
}
