use dioxus::prelude::*;

use crate::types::{PortalTunnel, PortalTunnels, bytes_human};

const POLL_MS: u32 = 5000;

async fn fetch_tunnels() -> Result<Vec<PortalTunnel>, String> {
    let resp = gloo_net::http::Request::get("/portal/tunnels/live")
        .send()
        .await
        .map_err(|_| "Could not load tunnels.".to_string())?;
    // `/portal/tunnels/live` is a page path: an expired portal session makes
    // the auth middleware redirect (gloo follows it) rather than return a 401,
    // so detect the redirect directly (keep the 401 check for future-proofing).
    if resp.status() == 401 || resp.redirected() {
        return Err("Portal session expired — reload the page.".to_string());
    }
    if !resp.ok() {
        return Err("Could not load tunnels.".to_string());
    }
    resp.json::<PortalTunnels>()
        .await
        .map(|b| b.tunnels)
        .map_err(|_| "Could not load tunnels.".to_string())
}

#[component]
pub fn PortalGaugesIsland() -> Element {
    let mut tunnels = use_signal(Vec::<PortalTunnel>::new);
    let mut error = use_signal(|| None::<String>);

    use_effect(move || {
        spawn(async move {
            loop {
                // Pause while the tab is hidden (skip the fetch, still sleep).
                let hidden = dioxus::document::eval("return document.hidden;")
                    .await
                    .ok()
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if hidden {
                    gloo_timers::future::TimeoutFuture::new(POLL_MS).await;
                    continue;
                }

                match fetch_tunnels().await {
                    Ok(list) => {
                        error.set(None);
                        tunnels.set(list);
                    }
                    Err(msg) => error.set(Some(msg)),
                }

                gloo_timers::future::TimeoutFuture::new(POLL_MS).await;
            }
        });
    });

    let list = tunnels();

    rsx! {
        if let Some(msg) = error() {
            div { class: "msg-error", "{msg}" }
        }

        if list.is_empty() {
            div { class: "empty-state",
                div { class: "empty-title", "No tunnels yet" }
                div { class: "empty-text", "Create a tunnel to see live status here." }
            }
        } else {
            table {
                thead { tr {
                    th { "Tunnel" }
                    th { "Status" }
                    th { "Bytes" }
                    th { "Requests" }
                } }
                tbody {
                    { list.iter().map(|t| {
                        let badge = if t.live.connected {
                            "badge badge-connected"
                        } else {
                            "badge badge-idle"
                        };
                        let status = if t.live.connected { "Live" } else { "Offline" };
                        let bytes = bytes_human(t.live.bytes_transferred);
                        let slug = t.slug.clone();
                        let host = t.host.clone();
                        let requests = t.live.requests;
                        rsx! {
                            tr {
                                td {
                                    if host.is_empty() {
                                        span { class: "mono", "{slug}" }
                                    } else {
                                        a {
                                            class: "slug",
                                            href: "https://{host}",
                                            target: "_blank",
                                            title: "{host}",
                                            "{slug}"
                                        }
                                    }
                                }
                                td { span { class: "{badge}", "{status}" } }
                                td { class: "num", "{bytes}" }
                                td { class: "num", "{requests}" }
                            }
                        }
                    }) }
                }
            }
        }
    }
}
