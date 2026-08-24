use std::collections::HashMap;

use dioxus::prelude::*;

use crate::types::{
    ServerConfigView, SessionView, bytes_human, duration_human, sparkline_svg, truncate,
};

const POLL_MS: u32 = 5000;
const RING_CAP: usize = 12;

async fn fetch_sessions() -> Result<Vec<SessionView>, String> {
    let resp = gloo_net::http::Request::get("/api/sessions")
        .send()
        .await
        .map_err(|_| "Could not load sessions.".to_string())?;
    let status = resp.status();
    if status == 401 {
        return Err("Operator session expired — reload the page.".to_string());
    }
    if !resp.ok() {
        return Err("Could not load sessions.".to_string());
    }
    resp.json::<Vec<SessionView>>()
        .await
        .map_err(|_| "Could not load sessions.".to_string())
}

async fn fetch_max_sessions() -> Option<usize> {
    let resp = gloo_net::http::Request::get("/api/config")
        .send()
        .await
        .ok()?;
    if !resp.ok() {
        return None;
    }
    resp.json::<ServerConfigView>()
        .await
        .ok()
        .map(|c| c.max_sessions)
}

async fn kill_session(slug: &str) -> bool {
    let url = format!("/api/sessions/{slug}/kill");
    match gloo_net::http::Request::post(&url).send().await {
        // A 404 means the session already ended — treat it as success so a
        // second Kill click inside the poll window doesn't surface a
        // misleading "Failed to kill session." error.
        Ok(resp) => resp.ok() || resp.status() == 404,
        Err(_) => false,
    }
}

#[component]
pub fn DashboardIsland() -> Element {
    let mut sessions = use_signal(Vec::<SessionView>::new);
    let mut max_sessions = use_signal(|| 0usize);
    let mut config_loaded = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut refresh = use_signal(|| 0u64);
    let mut spark_ring = use_signal(HashMap::<String, Vec<u64>>::new);
    let mut last_totals = use_signal(HashMap::<String, u64>::new);

    use_effect(move || {
        spawn(async move {
            let mut seen_refresh = refresh();
            let mut first = true;
            let mut config_fetched = false;
            loop {
                // Immediate fetch on the first iteration and whenever the
                // kill handler bumps `refresh`; otherwise sleep 5s.
                let cur = refresh();
                if cur != seen_refresh || first {
                    seen_refresh = cur;
                    first = false;
                } else {
                    gloo_timers::future::TimeoutFuture::new(POLL_MS).await;
                }

                // Pause while the tab is hidden (skip the fetch, still sleep).
                let hidden = dioxus::document::eval("return document.hidden;")
                    .await
                    .ok()
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if hidden {
                    continue;
                }

                match fetch_sessions().await {
                    Ok(list) => {
                        error.set(None);

                        // Per-slug tx+rx byte-delta ring (cap 12 samples).
                        let mut last = last_totals();
                        let mut ring = spark_ring();
                        for s in &list {
                            let total = s.bytes_tx.saturating_add(s.bytes_rx);
                            if let Some(prev) = last.get(&s.slug) {
                                let delta = total.saturating_sub(*prev);
                                let entry = ring.entry(s.slug.clone()).or_default();
                                entry.push(delta);
                                if entry.len() > RING_CAP {
                                    let excess = entry.len() - RING_CAP;
                                    entry.drain(0..excess);
                                }
                            }
                            last.insert(s.slug.clone(), total);
                        }
                        // Drop stale entries for sessions that have ended.
                        last.retain(|k, _| list.iter().any(|s| &s.slug == k));
                        ring.retain(|k, _| list.iter().any(|s| &s.slug == k));
                        last_totals.set(last);
                        spark_ring.set(ring);

                        sessions.set(list);
                    }
                    Err(msg) => error.set(Some(msg)),
                }

                if !config_fetched && let Some(m) = fetch_max_sessions().await {
                    max_sessions.set(m);
                    config_loaded.set(true);
                    config_fetched = true;
                }
            }
        });
    });

    let list = sessions();
    let active = list.len();
    let total_bytes: u64 = list
        .iter()
        .map(|s| s.bytes_tx.saturating_add(s.bytes_rx))
        .sum();
    let total_streams: u32 = list.iter().map(|s| s.streams).sum();
    let ring_map = spark_ring();

    rsx! {
        if let Some(msg) = error() {
            div { class: "msg-error", "{msg}" }
        }

        div { class: "stats",
            div { class: "stat",
                div { class: "label", "Active Tunnels" }
                div { class: "value num", "{active}" }
            }
            div { class: "stat",
                div { class: "label", "Total Bytes" }
                div { class: "value num", "{bytes_human(total_bytes)}" }
            }
            div { class: "stat",
                div { class: "label", "Total Streams" }
                div { class: "value num", "{total_streams}" }
            }
        }

        p { class: "subtitle",
            if config_loaded() {
                "{active} of {max_sessions()} sessions active"
            } else {
                "{active} sessions active"
            }
        }

        if active == 0 {
            div { class: "empty-state",
                div { class: "empty-icon", "\u{1F4E1}" }
                div { class: "empty-title", "No live tunnels" }
                div { class: "empty-text", "Start a client with one of your tokens to open a tunnel." }
                div { class: "empty-cta",
                    a { class: "btn", href: "/tokens", "View tokens" }
                }
            }
        } else {
            div { class: "glass", style: "padding:6px 6px",
                table {
                    thead { tr {
                        th { "Subdomain" }
                        th { "Token" }
                        th { "Uptime" }
                        th { "Streams (peak)" }
                        th { "Bytes In" }
                        th { "Bytes Out" }
                        th { "Activity" }
                        th { "" }
                    } }
                    tbody {
                        { list.iter().map(|s| {
                            let slug = s.slug.clone();
                            let kill_slug = slug.clone();
                            let token = truncate(&s.token_id, 32);
                            let uptime = duration_human(s.uptime_secs);
                            let streams = s.streams;
                            let peak = s.streams_peak;
                            let bytes_in = bytes_human(s.bytes_tx);
                            let bytes_out = bytes_human(s.bytes_rx);
                            let ring = ring_map.get(&slug).cloned().unwrap_or_default();
                            rsx! {
                                tr {
                                    td { a { class: "slug", href: "/t/{slug}", "{slug}" } }
                                    td { class: "token", "{token}" }
                                    td { class: "num", "{uptime}" }
                                    td { class: "num", "{streams} / {peak}" }
                                    td { class: "bytes num", "{bytes_in}" }
                                    td { class: "bytes num", "{bytes_out}" }
                                    td { dangerous_inner_html: "{sparkline_svg(&ring)}" }
                                    td {
                                        button {
                                            class: "kill-btn",
                                            onclick: move |_| {
                                                let slug = kill_slug.clone();
                                                spawn(async move {
                                                    let ok = dioxus::document::eval("return confirm('Kill this session?');")
                                                        .await
                                                        .ok()
                                                        .and_then(|v| v.as_bool())
                                                        .unwrap_or(false);
                                                    if !ok {
                                                        return;
                                                    }
                                                    if kill_session(&slug).await {
                                                        // Inline refetch so the killed row disappears
                                                        // immediately: the poll loop may still sleep the
                                                        // full POLL_MS before its next fetch.
                                                        if let Ok(list) = fetch_sessions().await {
                                                            sessions.set(list);
                                                        }
                                                        refresh.set(refresh() + 1);
                                                    } else {
                                                        error.set(Some("Failed to kill session.".to_string()));
                                                    }
                                                });
                                            },
                                            "Kill"
                                        }
                                    }
                                }
                            }
                        }) }
                    }
                }
            }
        }
    }
}
