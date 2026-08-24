//! Tunnel create/edit form island. Replaces the SSR fallback rendered by
//! `render_tunnel_edit` in crates/ddns-server/src/http_app.rs when JS is on.
//!
//! Reads the edit id from `#island-root[data-props]` (`{"edit_id":"..."}`),
//! loads tokens/domains (and the tunnel record in edit mode), then drives the
//! same REST endpoints the SSR form POSTs to (`/api/tunnels`, `/api/tunnels/{id}`).
//! Option parsing matches `parse_options_from_form` in http_app.rs exactly, so
//! the wire body is equivalent to a form submit (minus the `enabled` checkbox,
//! which the store defaults).

use dioxus::prelude::*;

use crate::types::{DomainView, TokenView, TunnelOptions, TunnelReq, TunnelView};

// ---------------------------------------------------------------------------
// data fetch helpers
// ---------------------------------------------------------------------------

async fn fetch_json<T: for<'de> serde::Deserialize<'de>>(url: &str) -> Result<T, String> {
    let resp = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|_| "Could not reach the server.".to_string())?;
    if resp.status() == 401 {
        return Err("Operator session expired — reload the page.".to_string());
    }
    if !resp.ok() {
        return Err("Could not load the form data.".to_string());
    }
    resp.json::<T>()
        .await
        .map_err(|_| "Could not parse the server response.".to_string())
}

async fn fetch_tokens() -> Result<Vec<TokenView>, String> {
    fetch_json("/api/tokens").await
}

async fn fetch_domains() -> Result<Vec<DomainView>, String> {
    fetch_json("/api/domains").await
}

async fn fetch_tunnels() -> Result<Vec<TunnelView>, String> {
    fetch_json("/api/tunnels").await
}

async fn read_props() -> String {
    dioxus::document::eval("return (document.querySelector('#island-root').dataset.props || '');")
        .await
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn parse_edit_id(props: &str) -> Option<String> {
    if props.trim().is_empty() {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(props)
        .ok()
        .and_then(|v| {
            v.get("edit_id")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
}

// ---------------------------------------------------------------------------
// option parse helpers (mirror `parse_options_from_form` in http_app.rs)
// ---------------------------------------------------------------------------

fn opt_str(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_header_lines(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// client-side validation (looser than the server; the server's 4xx text still
// surfaces through the inline error path)
// ---------------------------------------------------------------------------

fn valid_subdomain(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

// ---------------------------------------------------------------------------
// component
// ---------------------------------------------------------------------------

#[component]
pub fn TunnelFormIsland() -> Element {
    // basics
    let mut name = use_signal(String::new);
    let mut token_id = use_signal(String::new);
    let mut domain_id = use_signal(String::new);
    let mut subdomain = use_signal(String::new);
    let mut custom_hostname = use_signal(String::new);
    let mut ports = use_signal(String::new);

    // option fields
    let mut ip_whitelist = use_signal(String::new);
    let mut basic_user = use_signal(String::new);
    let mut basic_pass = use_signal(String::new);
    let mut key_auth = use_signal(String::new);
    let mut host_rewrite = use_signal(String::new);
    let mut add_headers = use_signal(String::new);
    let mut remove_headers = use_signal(String::new);
    let mut reverse_proxy_headers = use_signal(|| true);
    let mut https_only = use_signal(|| false);
    let mut pass_preflight = use_signal(|| false);

    // meta
    let mut tokens = use_signal(Vec::<TokenView>::new);
    let mut domains = use_signal(Vec::<DomainView>::new);
    let mut loading = use_signal(|| true);
    let mut error = use_signal(|| None::<String>);
    let mut edit_id = use_signal(|| None::<String>);
    let mut prefill_ready = use_signal(|| true);
    let mut open_section = use_signal(|| None::<&'static str>);

    // touched flags for inline validation
    let mut name_touched = use_signal(|| false);
    let mut subdomain_touched = use_signal(|| false);
    let mut custom_touched = use_signal(|| false);

    use_effect(move || {
        spawn(async move {
            let props = read_props().await;
            let edit = parse_edit_id(&props);
            edit_id.set(edit.clone());

            // Load lookup lists sequentially (two small same-origin GETs).
            let tokens_res = fetch_tokens().await;
            let domains_res = fetch_domains().await;

            let mut load_err: Option<String> = None;
            match tokens_res {
                Ok(list) => tokens.set(list),
                Err(e) => load_err = Some(e),
            }
            match domains_res {
                Ok(list) => domains.set(list),
                Err(e) => {
                    if load_err.is_none() {
                        load_err = Some(e);
                    }
                }
            }

            // Edit mode: prefill from the matching tunnel record. Suppress
            // submit until the prefill has loaded so a failed fetch can't
            // leave an empty form that would overwrite the existing tunnel.
            if let Some(id) = edit {
                prefill_ready.set(false);
                match fetch_tunnels().await {
                    Ok(list) => {
                        if let Some(t) = list.into_iter().find(|t| t.id == id) {
                            name.set(t.name);
                            token_id.set(t.token_id);
                            domain_id.set(t.domain_id);
                            subdomain.set(t.subdomain.unwrap_or_default());
                            custom_hostname.set(t.custom_hostname.unwrap_or_default());
                            ports.set(t.ports.clone());

                            let o = t.options;
                            ip_whitelist.set(o.ip_whitelist.join(", "));
                            let (bu, bp) = o
                                .basic_auth
                                .as_ref()
                                .map(|(u, p)| (u.clone(), p.clone()))
                                .unwrap_or_default();
                            basic_user.set(bu);
                            basic_pass.set(bp);
                            key_auth.set(o.key_auth.unwrap_or_default());
                            host_rewrite.set(o.host_rewrite.unwrap_or_default());
                            add_headers.set(
                                o.add_headers
                                    .iter()
                                    .map(|(k, v)| format!("{k}: {v}"))
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                            );
                            remove_headers.set(o.remove_headers.join("\n"));
                            reverse_proxy_headers.set(o.reverse_proxy_headers);
                            https_only.set(o.https_only);
                            pass_preflight.set(o.pass_preflight);
                        }
                        prefill_ready.set(true);
                    }
                    Err(e) => {
                        if load_err.is_none() {
                            load_err = Some(e);
                        }
                        // prefill_ready stays false so an empty form can't
                        // clobber the existing tunnel; the load error below
                        // surfaces the reason in the inline msg-error.
                    }
                }
            }

            if let Some(e) = load_err {
                error.set(Some(e));
            }
            loading.set(false);
        });
    });

    // Submit: build the TunnelReq-shaped body and POST/PUT.
    let submit = move |evt: FormEvent| {
        evt.prevent_default();

        let name_v = name().trim().to_string();
        if name_v.is_empty() {
            error.set(Some("Name is required.".to_string()));
            return;
        }

        let options = TunnelOptions {
            reverse_proxy_headers: reverse_proxy_headers(),
            basic_auth: {
                let u = basic_user();
                if u.is_empty() {
                    None
                } else {
                    Some((u, basic_pass()))
                }
            },
            key_auth: {
                let k = key_auth();
                if k.is_empty() { None } else { Some(k) }
            },
            ip_whitelist: split_csv(&ip_whitelist()),
            https_only: https_only(),
            host_rewrite: opt_str(&host_rewrite()),
            add_headers: parse_header_lines(&add_headers()),
            remove_headers: split_lines(&remove_headers()),
            pass_preflight: pass_preflight(),
        };

        let req = TunnelReq {
            name: name_v,
            token_id: token_id(),
            domain_id: domain_id(),
            subdomain: opt_str(&subdomain()),
            custom_hostname: opt_str(&custom_hostname()),
            options,
            ports: ports().trim().to_string(),
        };

        let id = edit_id();
        let body = serde_json::to_string(&req).unwrap_or_default();

        spawn(async move {
            let (url, is_edit) = match &id {
                Some(id) => (format!("/api/tunnels/{id}"), true),
                None => ("/api/tunnels".to_string(), false),
            };

            let builder = if is_edit {
                gloo_net::http::Request::put(&url)
            } else {
                gloo_net::http::Request::post(&url)
            };
            let resp = builder
                .header("Content-Type", "application/json")
                .body(body)
                .expect("valid same-origin JSON request")
                .send()
                .await;

            match resp {
                Ok(r) if r.ok() => {
                    let flash = if is_edit {
                        "success|Tunnel updated"
                    } else {
                        "success|Tunnel created"
                    };
                    let js = format!(
                        r#"return (function () {{ var raw = '{flash}'; var b64 = btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); document.cookie = 'ddns_flash=' + b64 + '; Path=/; Max-Age=10; SameSite=Lax'; window.location.href = '/tunnels'; return true; }})();"#
                    );
                    let _ = dioxus::document::eval(&js).await;
                }
                Ok(r) => {
                    let text = r.text().await.unwrap_or_default();
                    error.set(Some(if text.is_empty() {
                        "Request failed.".to_string()
                    } else {
                        text
                    }));
                }
                Err(_) => {
                    error.set(Some("Could not reach the server.".to_string()));
                }
            }
        });
    };

    let domain_name = domains()
        .iter()
        .find(|d| d.id == domain_id())
        .map(|d| d.name.clone())
        .unwrap_or_default();
    let preview = if !subdomain().trim().is_empty() {
        format!("https://{}.{}", subdomain().trim(), domain_name)
    } else if !custom_hostname().trim().is_empty() {
        format!("https://{}", custom_hostname().trim())
    } else {
        "random per session".to_string()
    };

    let name_empty = name().trim().is_empty();
    let subdomain_invalid =
        subdomain_touched() && !subdomain().is_empty() && !valid_subdomain(&subdomain());
    let custom_invalid =
        custom_touched() && !custom_hostname().is_empty() && !valid_hostname(&custom_hostname());

    rsx! {
        div { class: "create-form glass", style: "max-width:640px",
            if let Some(msg) = error() {
                div { class: "msg-error", "{msg}" }
            }

            if loading() {
                div { class: "empty", "Loading tunnel form\u{2026}" }
            } else {
                form {
                    onsubmit: submit,
                    div { class: "form-group",
                        label { r#for: "name", "Name" }
                        input {
                            r#type: "text",
                            id: "name",
                            name: "name",
                            required: true,
                            maxlength: 64,
                            value: "{name()}",
                            oninput: move |e| {
                                name_touched.set(true);
                                name.set(e.value());
                            },
                        }
                        if name_touched() && name_empty {
                            span { class: "error", "Name is required." }
                        }
                    }
                    div { class: "form-row",
                        div { class: "form-group",
                            label { r#for: "token_id", "Token" }
                            select {
                                id: "token_id",
                                name: "token_id",
                                required: true,
                                value: "{token_id()}",
                                onchange: move |e| token_id.set(e.value()),
                                for t in tokens() {
                                    option { value: "{t.id}", "{t.name}" }
                                }
                            }
                        }
                        div { class: "form-group",
                            label { r#for: "domain_id", "Domain" }
                            select {
                                id: "domain_id",
                                name: "domain_id",
                                required: true,
                                value: "{domain_id()}",
                                onchange: move |e| domain_id.set(e.value()),
                                for d in domains() {
                                    option { value: "{d.id}", "{d.name}" }
                                }
                            }
                        }
                    }
                    div { class: "form-row",
                        div { class: "form-group",
                            label { r#for: "subdomain", "Fixed subdomain" }
                            input {
                                r#type: "text",
                                id: "subdomain",
                                name: "subdomain",
                                value: "{subdomain()}",
                                placeholder: "my-app",
                                oninput: move |e| subdomain.set(e.value()),
                                onblur: move |_| subdomain_touched.set(true),
                            }
                            if subdomain_invalid {
                                div { class: "msg-error", "Subdomain may only contain lowercase letters, digits, and hyphens." }
                            }
                        }
                        div { class: "form-group",
                            label { r#for: "custom_hostname", "Custom hostname" }
                            input {
                                r#type: "text",
                                id: "custom_hostname",
                                name: "custom_hostname",
                                value: "{custom_hostname()}",
                                placeholder: "app.example.com",
                                oninput: move |e| custom_hostname.set(e.value()),
                                onblur: move |_| custom_touched.set(true),
                            }
                            if custom_invalid {
                                div { class: "msg-error", "Hostname may only contain lowercase letters, digits, dots, and hyphens." }
                            }
                        }
                    }

                    div { class: "form-group",
                        div { class: "label", "Hostname preview" }
                        div { class: "slug", "{preview}" }
                    }

                    div { class: "section",
                        div { class: "chips",
                            button {
                                class: "btn btn-ghost btn-sm",
                                r#type: "button",
                                onclick: move |_| {
                                    if open_section() == Some("access") {
                                        open_section.set(None);
                                    } else {
                                        open_section.set(Some("access"));
                                    }
                                },
                                "Access control"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                r#type: "button",
                                onclick: move |_| {
                                    if open_section() == Some("headers") {
                                        open_section.set(None);
                                    } else {
                                        open_section.set(Some("headers"));
                                    }
                                },
                                "Headers"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                r#type: "button",
                                onclick: move |_| {
                                    if open_section() == Some("misc") {
                                        open_section.set(None);
                                    } else {
                                        open_section.set(Some("misc"));
                                    }
                                },
                                "Misc"
                            }
                        }

                        if open_section() == Some("access") {
                            div { class: "form-group",
                                label { "IP whitelist (IP or CIDR, comma-separated)" }
                                input {
                                    r#type: "text",
                                    name: "options_ip_whitelist",
                                    value: "{ip_whitelist()}",
                                    oninput: move |e| ip_whitelist.set(e.value()),
                                }
                            }
                            div { class: "form-row",
                                div { class: "form-group",
                                    label { "Basic auth user" }
                                    input {
                                        r#type: "text",
                                        name: "options_basic_user",
                                        value: "{basic_user()}",
                                        oninput: move |e| basic_user.set(e.value()),
                                    }
                                }
                                div { class: "form-group",
                                    label { "Basic auth password" }
                                    input {
                                        r#type: "password",
                                        name: "options_basic_pass",
                                        value: "{basic_pass()}",
                                        oninput: move |e| basic_pass.set(e.value()),
                                    }
                                }
                            }
                            div { class: "form-group",
                                label { "Key auth (Bearer)" }
                                input {
                                    r#type: "text",
                                    name: "options_key_auth",
                                    value: "{key_auth()}",
                                    oninput: move |e| key_auth.set(e.value()),
                                }
                            }
                        }

                        if open_section() == Some("headers") {
                            div { class: "form-group",
                                label { "Host rewrite (backend Host)" }
                                input {
                                    r#type: "text",
                                    name: "options_host_rewrite",
                                    value: "{host_rewrite()}",
                                    oninput: move |e| host_rewrite.set(e.value()),
                                }
                            }
                            div { class: "form-group",
                                label { "Add headers (Name: Value per line)" }
                                textarea {
                                    name: "options_add_headers",
                                    value: "{add_headers()}",
                                    oninput: move |e| add_headers.set(e.value()),
                                }
                            }
                            div { class: "form-group",
                                label { "Remove headers (one per line)" }
                                textarea {
                                    name: "options_remove_headers",
                                    value: "{remove_headers()}",
                                    oninput: move |e| remove_headers.set(e.value()),
                                }
                            }
                            div { class: "form-group",
                                label {
                                    input {
                                        r#type: "checkbox",
                                        name: "options_reverse_proxy_headers",
                                        checked: reverse_proxy_headers(),
                                        onchange: move |e| reverse_proxy_headers.set(e.checked()),
                                    }
                                    " Reverse-proxy headers"
                                }
                            }
                        }

                        if open_section() == Some("misc") {
                            div { class: "form-group",
                                label {
                                    input {
                                        r#type: "checkbox",
                                        name: "options_https_only",
                                        checked: https_only(),
                                        onchange: move |e| https_only.set(e.checked()),
                                    }
                                    " HTTPS-only redirect"
                                }
                            }
                            div { class: "form-group",
                                label {
                                    input {
                                        r#type: "checkbox",
                                        name: "options_pass_preflight",
                                        checked: pass_preflight(),
                                        onchange: move |e| pass_preflight.set(e.checked()),
                                    }
                                    " Pass CORS preflight through auth"
                                }
                            }
                        }
                    }

                    button {
                        class: "create-btn",
                        r#type: "submit",
                        disabled: name_empty || !prefill_ready(),
                        if edit_id().is_some() { "Update Tunnel" } else { "Create Tunnel" }
                    }
                }
            }
        }
    }
}
