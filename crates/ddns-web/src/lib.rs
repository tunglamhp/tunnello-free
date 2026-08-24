//! Dioxus islands for the DDNS operator UI. Compiled to wasm by `dx build`;
//! mounted at `#island-root` by data-island dispatch.
#![cfg(target_arch = "wasm32")]

pub mod islands;
pub mod types;

use dioxus::prelude::*;

/// Root component: reads `#island-root[data-island]`, renders the matching
/// island, and mounts at that node (mounting replaces the fallback content).
#[component]
fn Root() -> Element {
    let mut island = use_signal(|| "hello".to_string());
    use_effect(move || {
        spawn(async move {
            let name = dioxus::document::eval(
                "return document.querySelector('#island-root').dataset.island || '';",
            )
            .await
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .unwrap_or_default();
            island.set(name);
        });
    });
    rsx! {
        match island().as_str() {
            "dashboard" => rsx! { islands::dashboard::DashboardIsland {} },
            "tunnel-form" => rsx! { islands::tunnel_form::TunnelFormIsland {} },
            "portal-gauges" => rsx! { islands::portal_gauges::PortalGaugesIsland {} },
            // Unknown island names render nothing (an unknown mount must not
            // show a stray UI element).
            _ => rsx! { div {} },
        }
    }
}

/// Entry — called from main.rs on wasm. Never returns.
pub fn mount() {
    // Clear the server-rendered fallback so the island replaces it instead of
    // appending after it (dioxus-web launches by appending to the root node).
    // Raw `web_sys` is used because dioxus::document has no context yet here —
    // it is set up inside `launch`, which runs after this returns.
    if let Some(document) = web_sys::window().and_then(|w| w.document()) {
        if let Some(root) = document.get_element_by_id("island-root") {
            while let Some(child) = root.first_child() {
                let _ = root.remove_child(&child);
            }
        }
    }
    dioxus_web::launch::launch_cfg(Root, dioxus_web::Config::new().rootname("island-root"));
}
