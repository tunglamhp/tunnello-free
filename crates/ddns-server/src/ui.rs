//! Flat dark sidebar UI shell (Zoraxy-style): one `<style>` block and one
//! page frame reused by every operator + public page. No gradients anywhere —
//! flat solid fills only. Page handlers build only the `<main>` body HTML and
//! hand it to `page_shell`.

use std::sync::RwLock;

use axum::response::IntoResponse;
use base64::Engine as _;

/// Process-wide cached shell branding (instance name + support URL).
/// Refreshed on startup and whenever settings change.
struct InstanceBranding {
    name: String,
    support_url: String,
}

static BRANDING: RwLock<InstanceBranding> = RwLock::new(InstanceBranding {
    name: String::new(),
    support_url: String::new(),
});

/// Process-wide audit store, set once at startup so `page_shell` can append
/// a per-page activity log without every handler threading state through.
static AUDIT: std::sync::OnceLock<crate::audit::AuditStore> = std::sync::OnceLock::new();

/// Set the shared audit store (called once at startup from lib.rs).
pub fn set_audit(a: crate::audit::AuditStore) {
    let _ = AUDIT.set(a);
}

/// Update the cached branding (called from the settings refresh path).
pub fn set_branding(name: &str, support: &str) {
    let mut b = BRANDING.write().unwrap_or_else(|p| p.into_inner());
    b.name = name.to_string();
    b.support_url = support.to_string();
}

/// Cached branding read (name falls back to "Tunello" when unset).
fn branding() -> (String, String) {
    let b = BRANDING.read().unwrap_or_else(|p| p.into_inner());
    (
        if b.name.is_empty() {
            "Tunello".to_string()
        } else {
            b.name.clone()
        },
        b.support_url.clone(),
    )
}

/// Minimal standalone shell for auth pages (client portal signup/login/
/// forgot/reset/verify): instance brand + theme toggle, centered content.
/// No operator sidebar — clients must never see operator navigation.
pub fn auth_shell(title: &str, body: &str) -> String {
    let (name, _support) = branding();
    // Operator-set instance name is user input — never raw into HTML
    // (page_shell escapes via brand_name(); auth_shell must too).
    let name = crate::http_app::html_escape(&name);
    let theme_boot = THEME_BOOT;
    let theme_toggle = THEME_TOGGLE;
    let toast = TOAST_SHELL;
    let brand_logo = BRAND_LOGO;
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} — {name}</title>\
         {theme_boot}<style>{}</style></head>\
         <body><header class=\"auth-top\"><div class=\"brand\">{brand_logo}{name} <span>Account</span></div>{theme_toggle}</header>\
         <main class=\"auth-main\">{body}</main>{toast}</body></html>",
        GLASS_CSS
    )
}

// ---------------------------------------------------------------------------
// island bundle script path
// ---------------------------------------------------------------------------
//
// `dx bundle` names the web bundle differently per build profile: dev emits
// `wasm/ddns-web.js`, release emits content-hashed names under `assets/`
// (e.g. `assets/ddns-web-dxh67c67961911e372c.js`). The Dioxus-generated
// `index.html` in the bundle always references the real module script, so we
// discover the path there at startup instead of hardcoding it.

static BUNDLE_SCRIPT: RwLock<String> = RwLock::new(String::new());

/// Set the discovered bundle script URL (called once at startup).
pub fn set_bundle_script(url: &str) {
    let mut s = BUNDLE_SCRIPT.write().unwrap_or_else(|p| p.into_inner());
    *s = url.to_string();
}

/// The module-script URL to load the islands from, or the dev fallback when
/// no bundle index.html was found.
pub fn bundle_script() -> String {
    let s = BUNDLE_SCRIPT.read().unwrap_or_else(|p| p.into_inner());
    if s.is_empty() {
        "/_assets/wasm/ddns-web.js".to_string()
    } else {
        s.clone()
    }
}

/// Read `<web_dist>/index.html` and extract the island module script src
/// (`<script type="module"... src="...">`). Falls back to the dev path when
/// the bundle or index.html is absent.
pub fn discover_bundle_script(web_dist: &std::path::Path) -> String {
    let index = web_dist.join("index.html");
    if let Ok(html) = std::fs::read_to_string(&index)
        && let Some(src) = extract_module_script(&html)
    {
        return src;
    }
    "/_assets/wasm/ddns-web.js".to_string()
}

/// Extract the `src` of the first `<script type="module"` tag. Pure string
/// scan — the tag shape is fixed by dx's generated index.html.
fn extract_module_script(html: &str) -> Option<String> {
    let mut rest = html;
    while let Some(start) = rest.find("<script") {
        let end = rest[start..].find('>')? + start;
        let tag = &rest[start..end + 1];
        rest = &rest[end + 1..];
        if tag.contains("type=\"module\"") {
            let attr_start = tag.find("src=\"")? + 5;
            let attr_end = tag[attr_start..].find('"')? + attr_start;
            return Some(tag[attr_start..attr_end].to_string());
        }
    }
    None
}

/// Cached instance name (HTML-escaped); an empty name falls back to "Tunello".
pub fn brand_name() -> String {
    let b = BRANDING.read().unwrap_or_else(|p| p.into_inner());
    let name = if b.name.is_empty() {
        "Tunello".to_string()
    } else {
        b.name.clone()
    };
    crate::http_app::html_escape(&name)
}

/// Footer support link (empty when no support URL is set).
pub fn support_footer() -> String {
    let b = BRANDING.read().unwrap_or_else(|p| p.into_inner());
    if b.support_url.is_empty() {
        String::new()
    } else {
        format!(
            "<footer><a href=\"{}\" rel=\"noopener\">Support</a></footer>",
            crate::http_app::html_escape(&b.support_url)
        )
    }
}

/// Inline SVG brand mark (tunnel arch with traffic flowing through), used in
/// the sidebar and auth-shell brand blocks. 20px, stroke `currentColor` —
/// the brand CSS tints it with the accent.
pub(crate) const BRAND_LOGO: &str = r#"<svg class="brand-logo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 19V12a5 5 0 0 1 10 0v7"/><path d="M4 19h16"/><path d="M9.5 9.5 7 12l2.5 2.5M14.5 9.5 17 12l-2.5 2.5"/></svg>"#;

/// Full flat dark stylesheet. Solid dark panels, muted text, single accent.
pub const GLASS_CSS: &str = r#"
:root {
  --bg: #0b0e14;
  --panel: #141824;
  --panel-2: #1a2030;
  --panel-3: #202838;
  --border: #232a3a;
  --text: #e6e9f0;
  --muted: #8b93a7;
  --accent: #3B82F6;
  --accent-hover: #60A5FA;
  --info: #3d8bf0;
  --ok: #2fbf71;
  --warn: #e8a33d;
  --danger: #e5484d;
  --radius: 12px;
  --sidebar-w: 220px;
  --shadow: 0 1px 3px rgba(0, 0, 0, .35);
  --ring: rgba(59, 130, 246, .30);
  /* ---- button system tokens (dark) ---- */
  --btn-primary-bg: #3B82F6;
  --btn-primary-bg-hover: #4E8FF7;
  --btn-primary-bg-active: #2563EB;
  --btn-primary-text: #FFFFFF;
  --btn-secondary-bg: #1E293B;
  --btn-secondary-bg-hover: #334155;
  --btn-secondary-bg-active: #0F172A;
  --btn-secondary-text: #E2E8F0;
  --btn-secondary-text-hover: #FFFFFF;
  --btn-secondary-border: #475569;
  --btn-secondary-border-hover: #64748B;
  --btn-danger-bg: #EF4444;
  --btn-danger-bg-hover: #F05A5A;
  --btn-danger-bg-active: #DC2626;
  --btn-danger-text: #FFFFFF;
  --btn-warn-bg-hover: #33291A;
  --btn-focus: #93C5FD;
  --btn-disabled-bg: #334155;
  --btn-disabled-text: #64748B;
  --btn-disabled-border: #475569;
  --btn-disabled-opacity: .5;
  /* ---- status badge tokens (dark) ---- */
  --badge-ok-bg: #064E3B;
  --badge-ok-text: #4ADE80;
  --badge-ok-border: #059669;
  --badge-idle-bg: #334155;
  --badge-idle-text: #94A3B8;
  --badge-idle-border: #475569;
  --badge-warn-bg: #78350F;
  --badge-warn-text: #FBBF24;
  --badge-warn-border: #D97706;
}
html[data-theme="light"] {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --panel-2: #eef1f5;
  --panel-3: #e2e7ee;
  --border: #dde3ea;
  --text: #1c2430;
  --muted: #5b6b7f;
  --accent: #2563EB;
  --accent-hover: #1D4ED8;
  --info: #2f6fd0;
  --ok: #1e8e4e;
  --warn: #b87b1d;
  --danger: #d33a42;
  --shadow: 0 1px 3px rgba(16, 24, 40, .08);
  --ring: rgba(37, 99, 235, .25);
  /* ---- button system tokens (light) ---- */
  --btn-primary-bg: #2563EB;
  --btn-primary-bg-hover: #1D4ED8;
  --btn-primary-bg-active: #1E40AF;
  --btn-primary-text: #FFFFFF;
  --btn-secondary-bg: #FFFFFF;
  --btn-secondary-bg-hover: #F1F5F9;
  --btn-secondary-bg-active: #E2E8F0;
  --btn-secondary-text: #334155;
  --btn-secondary-text-hover: #0F172A;
  --btn-secondary-border: #CBD5E1;
  --btn-secondary-border-hover: #94A3B8;
  --btn-danger-bg: #DC2626;
  --btn-danger-bg-hover: #B91C1C;
  --btn-danger-bg-active: #991B1B;
  --btn-danger-text: #FFFFFF;
  --btn-warn-bg-hover: #FBF1DC;
  --btn-focus: #60A5FA;
  --btn-disabled-bg: #E2E8F0;
  --btn-disabled-text: #94A3B8;
  --btn-disabled-border: #CBD5E1;
  --btn-disabled-opacity: .6;
  /* ---- status badge tokens (light) ---- */
  --badge-ok-bg: #DCFCE7;
  --badge-ok-text: #15803D;
  --badge-ok-border: #86EFAC;
  --badge-idle-bg: #F1F5F9;
  --badge-idle-text: #475569;
  --badge-idle-border: #CBD5E1;
  --badge-warn-bg: #FEF3C7;
  --badge-warn-text: #B45309;
  --badge-warn-border: #FDE68A;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font: 14px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
  -webkit-tap-highlight-color: transparent;
  -webkit-text-size-adjust: 100%;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
/* ---- layout ---- */
.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: var(--sidebar-w);
  background: var(--panel); border-right: 1px solid var(--border);
  padding: 16px 12px; overflow-y: auto; z-index: 10;
  transition: transform .15s ease;
}
.sidebar .brand {
  display: flex; align-items: center; gap: 8px;
  font-size: 15px; font-weight: 700; letter-spacing: .3px;
  padding: 4px 10px 14px; color: var(--text);
}
.sidebar .brand svg.brand-logo { width: 20px; height: 20px; color: var(--accent); flex: none; }
.sidebar .brand span { color: var(--accent); }
.sidebar .group { font-size: 11px; text-transform: uppercase; letter-spacing: .8px;
  color: var(--muted); padding: 14px 10px 6px; }
.sidebar a.item {
  display: flex; align-items: center; gap: 10px; padding: 8px 10px; margin: 1px 0; border-radius: 8px;
  color: var(--muted); font-weight: 500;
  border-left: 3px solid transparent;
  transition: background .15s ease, color .15s ease, border-color .15s ease;
}
.sidebar a.item svg { flex: none; }
.sidebar a.item:hover { background: var(--panel-2); color: var(--text); text-decoration: none; }
.sidebar a.item.active {
  background: color-mix(in srgb, var(--accent) 12%, transparent);
  color: var(--text); border-left: 3px solid var(--accent); padding-left: 7px;
}
.sidebar a.item.active svg { color: var(--accent); }
.sidebar::-webkit-scrollbar { width: 8px; }
.sidebar::-webkit-scrollbar-thumb { background: var(--panel-3); border-radius: 4px; }
.sidebar::-webkit-scrollbar-thumb:hover { background: var(--border); }
main { margin-left: var(--sidebar-w); padding: 28px 36px; max-width: 1600px; margin-right: auto; }
main h1 { font-size: 22px; font-weight: 700; letter-spacing: -.02em; margin: 0 0 16px; }
::selection { background: var(--accent); color: #fff; }
/* ---- cards ---- */
.box {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 18px 20px; margin: 14px 0;
  box-shadow: var(--shadow);
}
.glass { /* legacy alias — flat panel, no translucency/gradients */ }
.box h1 { font-size: 1.4em; font-weight: 700; margin: 0 0 8px; }
.box h2, .box h3 { margin: 0 0 10px; font-size: 16px; }
.subtitle { color: var(--muted); margin: -6px 0 14px; font-size: 13px; }
/* ---- stat cards ---- */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 18px 20px; box-shadow: var(--shadow); position: relative; overflow: hidden; }
.stat::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--accent); }
.stat .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; }
.stat .value { font-size: 20px; font-weight: 600; margin-top: 4px; }
.stat .hint { color: var(--muted); font-size: 12px; margin-top: 2px; }
/* ---- button system: primary / secondary / danger × sm / md / lg; flat, WCAG AA ---- */
.btn, button, input[type="submit"] {
  display: inline-flex; align-items: center; justify-content: center;
  gap: var(--btn-gap, 8px);
  height: var(--btn-h, 40px); padding: 0 var(--btn-px, 16px);
  font-size: var(--btn-fs, 14px); font-weight: 600; line-height: 1;
  border-radius: var(--btn-r, 8px); border: 1px solid transparent;
  cursor: pointer; text-decoration: none; white-space: nowrap;
  background: var(--btn-primary-bg); color: var(--btn-primary-text);
  transition: background-color .15s ease-in-out, border-color .15s ease-in-out,
              box-shadow .15s ease-in-out, color .15s ease-in-out,
              transform .15s ease-in-out;
}
.btn:hover, button:hover, input[type="submit"]:hover { filter: brightness(1.08); text-decoration: none; }
html[data-theme="light"] .btn:hover, html[data-theme="light"] button:hover, html[data-theme="light"] input[type="submit"]:hover { filter: brightness(0.95); }
.btn:active, button:active, input[type="submit"]:active {
  background: var(--btn-primary-bg-active); transform: scale(.98);
}
.btn:focus-visible, button:focus-visible, input[type="submit"]:focus-visible {
  outline: 2px solid var(--btn-focus); outline-offset: 2px;
}
.btn svg { width: var(--btn-ic, 16px); height: var(--btn-ic, 16px); flex: none; }
/* sizes: sm 32 / md 40 (default) / lg 48 */
.btn-sm, .kill-btn {
  --btn-h: 32px; --btn-fs: 12px; --btn-px: 12px; --btn-gap: 6px; --btn-r: 6px; --btn-ic: 14px;
}
.btn-md { --btn-h: 40px; --btn-fs: 14px; --btn-px: 16px; --btn-gap: 8px; --btn-r: 8px; --btn-ic: 16px; }
.btn-lg { --btn-h: 48px; --btn-fs: 16px; --btn-px: 24px; --btn-gap: 10px; --btn-r: 8px; --btn-ic: 20px; }
/* icon-only: exactly 1:1 */
.btn-icon { width: var(--btn-h); padding: 0; }
/* variants */
.btn-secondary, .btn-ghost {
  background: var(--btn-secondary-bg); color: var(--btn-secondary-text);
  border-color: var(--btn-secondary-border);
}
.btn-secondary:hover, .btn-ghost:hover {
  background: var(--btn-secondary-bg-hover); color: var(--btn-secondary-text-hover);
  border-color: var(--btn-secondary-border-hover);
}
.btn-secondary:active, .btn-ghost:active { background: var(--btn-secondary-bg-active); }
.btn-danger, .kill-btn { background: var(--btn-danger-bg); color: var(--btn-danger-text); }
.btn-danger:hover, .kill-btn:hover { background: var(--btn-danger-bg-hover); }
.btn-danger:active, .kill-btn:active { background: var(--btn-danger-bg-active); }
.btn-warn { background: transparent; color: var(--warn); border-color: var(--warn); }
.btn-warn:hover { background: var(--btn-warn-bg-hover); }
/* disabled */
.btn:disabled, button:disabled, input[type="submit"]:disabled {
  background: var(--btn-disabled-bg); color: var(--btn-disabled-text);
  border-color: var(--btn-disabled-border); opacity: var(--btn-disabled-opacity);
  cursor: not-allowed; transform: none; pointer-events: none;
}
/* loading: embedded spinner on the left; button dimensions preserved */
.btn .spinner {
  width: 1em; height: 1em; flex: none;
  border: 2px solid currentColor; border-top-color: transparent;
  border-radius: 50%; animation: btn-spin .6s linear infinite;
}
.btn.is-loading { pointer-events: none; opacity: .85; }
@keyframes btn-spin { to { transform: rotate(360deg); } }
/* legacy aliases (primary md) */
.create-btn, .save-btn, .copy-btn { background: var(--btn-primary-bg); color: var(--btn-primary-text); }
.create-btn:hover, .save-btn:hover, .copy-btn:hover { background: var(--btn-primary-bg-hover); filter: none; }
/* ---- status badges (live tunnel indicators) ---- */
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  height: 24px; padding: 0 10px; border-radius: 999px;
  font-size: 12px; font-weight: 600; border: 1px solid; white-space: nowrap;
}
.badge::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge-connected { background: var(--badge-ok-bg); color: var(--badge-ok-text); border-color: var(--badge-ok-border); }
.badge-idle { background: var(--badge-idle-bg); color: var(--badge-idle-text); border-color: var(--badge-idle-border); }
.badge-warning { background: var(--badge-warn-bg); color: var(--badge-warn-text); border-color: var(--badge-warn-border); }
/* ---- auth pages (no sidebar) ---- */
.auth-top { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; }
.auth-top .brand { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 700; letter-spacing: .3px; color: var(--text); }
.auth-top .brand svg.brand-logo { width: 20px; height: 20px; color: var(--accent); flex: none; }
.auth-top .brand span { color: var(--accent); }
.auth-top .theme-toggle { margin: 0; }
.auth-main { max-width: 460px; margin: 40px auto; padding: 0 16px; }
/* ---- inline action groups (table rows) ---- */
.row-actions { display: inline-flex; align-items: center; gap: 8px; }
.row-actions form { display: inline-flex; margin: 0; }
/* ---- forms ---- */
input[type="text"], input[type="password"], input[type="email"], input[type="number"], select, textarea {
  background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: 10px 12px; font-size: 14px; width: 100%; max-width: 380px;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--ring); }
label { display: block; margin: 10px 0 6px; color: var(--muted); font-size: 13px; }
/* ---- tables ---- */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px;
  text-transform: uppercase; letter-spacing: .5px; padding: 10px 14px;
  border-bottom: 1px solid var(--border); background: var(--panel-2); }
td { padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
tr:hover td { background: var(--panel-2); }
/* ---- misc ---- */
.chip { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
  background: var(--panel-2); border: 1px solid var(--border); color: var(--muted); }
.chip.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, transparent); background: color-mix(in srgb, var(--ok) 14%, transparent); }
.chip.warn { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 45%, transparent); background: color-mix(in srgb, var(--warn) 14%, transparent); }
.chip.danger { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 45%, transparent); background: color-mix(in srgb, var(--danger) 14%, transparent); }
.error { color: var(--danger); font-size: 13px; margin: 8px 0; }
.empty { color: var(--muted); padding: 20px; text-align: center; }
.actions { margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap; }
.inline { display: inline-flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-all; }
/* ---- legacy/compat classes (flat aliases for existing templates) ---- */
.main { margin-left: var(--sidebar-w); padding: 28px 36px; max-width: 1600px; margin-right: auto; }
.main h1 { font-size: 1.55em; font-weight: 700; margin-bottom: 4px; }
.card, .section, .create-form, .stat-card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 18px 20px; box-shadow: var(--shadow);
}
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }
.cards .card { margin: 0; }
.section { margin-bottom: 24px; }
.section h2 { font-size: 1.05em; font-weight: 600; margin: 0 0 12px; color: var(--text); }
.create-form { margin-bottom: 24px; }
.create-form h2 { font-size: 1.05em; font-weight: 600; margin: 0 0 14px; }
.stat-card .label, .card .label, .label {
  color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; margin-bottom: 6px;
}
.stat-card .value { font-size: 1.9em; font-weight: 700; }
.card .value { font-size: 1.6em; font-weight: 600; }
.card .mono { font-family: ui-monospace, Consolas, monospace; font-size: .95em; }
.form-group { margin-bottom: 16px; }
.form-row { display: flex; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; align-items: flex-end; }
.form-row > .form-group { flex: 1 1 0; min-width: 0; }
.form-row input, .form-row select, .form-row textarea { max-width: none; }
.slider-row { display: flex; gap: 12px; align-items: center; margin-top: 10px; flex-wrap: wrap; }
.slider-row input[type=range] { flex: 1; min-width: 220px; }
.slider-row select { width: auto; }
.slider-row input[type=number] { min-width: 96px; }
/* value + unit row (plans editor) */
.unit-row { display: flex; gap: 8px; align-items: center; }
.unit-row input { flex: 1; min-width: 140px; }
.unit-row select { width: auto; }
.checkbox-inline { display: inline-flex; align-items: center; gap: 6px; margin-right: 12px; }
.checkbox-inline input { width: auto; }
.chips { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
.kv { display: flex; gap: 8px; justify-content: space-between; margin-bottom: 8px; }
.kv .k { color: var(--muted); }
.kv .v { color: var(--text); }
.status { display: inline-block; padding: 3px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.status-up { color: var(--ok); border: 1px solid var(--ok); }
.status-down { color: var(--danger); border: 1px solid var(--danger); }
.token, .bytes { font-family: ui-monospace, Consolas, monospace; color: var(--muted); font-size: .82em; }
a.slug, .slug { color: var(--accent); font-family: ui-monospace, Consolas, monospace; text-decoration: none; }
a.slug:hover { text-decoration: underline; }
.sparkline { width: 100px; height: 24px; } .sparkline svg { display: block; }
.back { color: var(--accent); text-decoration: none; font-size: 13px; }
.back:hover { text-decoration: underline; }
.kill-btn { background: var(--btn-danger-bg); color: var(--btn-danger-text); border: 0; text-decoration: none; }
.kill-btn:hover { background: var(--btn-danger-bg-hover); }
.btn-warn { background: transparent; color: var(--warn); border: 1px solid var(--warn); }
.btn-warn:hover { background: var(--btn-warn-bg-hover); }
.secret-box { padding: 18px 20px; margin-bottom: 20px; background: var(--panel-2);
  border: 1px solid var(--border); border-radius: var(--radius); }
.secret-warn { color: var(--warn); font-size: 13px; margin-bottom: 12px; }
.secret-code { display: block; background: var(--panel); padding: 10px 14px; border-radius: 8px;
  font-family: ui-monospace, Consolas, monospace; font-size: 13px; color: var(--text);
  word-break: break-all; margin-bottom: 12px; }
.copy-btn { background: var(--btn-primary-bg); color: var(--btn-primary-text); }
.copy-btn:hover { background: var(--btn-primary-bg-hover); filter: none; }
.msg-success { background: transparent; border: 1px solid var(--ok); border-radius: 8px;
  padding: 12px 16px; color: var(--ok); margin-bottom: 16px; font-size: 13px; }
.msg-error { background: transparent; border: 1px solid var(--danger); border-radius: 8px;
  padding: 12px 16px; color: var(--danger); margin-bottom: 16px; font-size: 13px; }
.msg-warn { background: transparent; border: 1px solid var(--warn); border-radius: 8px;
  padding: 12px 16px; color: var(--warn); margin-bottom: 16px; font-size: 13px; }
footer { margin-top: 32px; color: var(--muted); font-size: 13px; }
.logout { margin-top: 16px; padding-top: 12px; border-top: 1px solid var(--border); }
.logout a { color: var(--muted); text-decoration: none; display: block; padding: 8px 10px; border-radius: 6px; }
.logout a:hover { color: var(--danger); background: var(--panel-2); }
.theme-toggle {
  display: inline-flex; align-items: center; justify-content: center;
  width: 44px; height: 22px; padding: 0; margin: 8px 10px 12px;
  background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 999px; cursor: pointer; position: relative; box-shadow: none;
  transition: background .15s ease;
}
.theme-toggle:hover { background: var(--panel-3); }
.theme-toggle .tt-thumb {
  position: absolute; left: 2px; top: 1px; width: 18px; height: 18px;
  border-radius: 50%; background: var(--muted); color: var(--bg);
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; line-height: 1;
  transition: left .15s ease, background .15s ease;
}
html[data-theme="light"] .theme-toggle .tt-thumb { left: 22px; }
.chart { display: flex; align-items: flex-end; gap: 3px; height: 140px; margin-top: 14px; padding-bottom: 2px; border-bottom: 1px solid var(--border); }
.chart .bar { flex: 1; display: flex; align-items: flex-end; height: 100%; background: var(--panel-2); border-radius: 4px; cursor: default; transition: background .15s ease; }
.chart .bar:hover { background: var(--panel-3); }
.chart .fill { width: 100%; background: var(--accent); border-radius: 4px 4px 0 0; min-height: 3px; transition: filter .15s ease; }
.chart .bar:hover .fill { filter: brightness(1.25); }
.chart .bar.is-max .fill { background: var(--ok); }
.chart .bar.is-zero .fill { background: var(--panel-3); }
/* traffic sparklines (operator dashboard) */
.sparkline polyline { stroke: var(--accent); }
.sparkline path { fill: var(--accent); }
.sparkline circle { fill: var(--accent); }
.sparkline.is-flat polyline { stroke: var(--muted); }
/* ---- token meter (flat track + threshold-colored fill, 80/95% marks) ---- */
.meter { position: relative; height: 10px; background: var(--panel-2); border-radius: 6px; margin: 14px 0 6px; }
.meter .meter-fill { height: 100%; border-radius: 6px; background: var(--ok); }
.meter .meter-mark { position: absolute; top: -3px; bottom: -3px; width: 2px; background: var(--border); }
.meter .meter-labels { display: flex; justify-content: space-between; color: var(--muted); font-size: 12px; }
/* ---- empty states ---- */
.empty-state { background: var(--panel); border: 1px dashed var(--border); border-radius: var(--radius);
  padding: 36px 24px; text-align: center; margin: 14px 0; }
.empty-icon { font-size: 26px; line-height: 1; color: var(--muted); margin-bottom: 10px; }
.empty-title { font-weight: 600; font-size: 15px; margin-bottom: 6px; }
.empty-text { color: var(--muted); font-size: 13px; max-width: 420px; margin: 0 auto 14px; }
.empty-cta { margin-top: 4px; }
/* ---- toasts ---- */
.toast-stack { position: fixed; top: 16px; right: 16px; z-index: 100; display: flex; flex-direction: column; gap: 8px; max-width: 360px; }
.toast { background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--info);
  border-radius: 8px; padding: 10px 14px; font-size: 13px; box-shadow: var(--shadow);
  display: flex; gap: 10px; align-items: flex-start; animation: toast-in .15s ease; }
.toast-success { border-left-color: var(--ok); }
.toast-error { border-left-color: var(--danger); }
.toast-info { border-left-color: var(--info); }
.toast button { background: transparent; border: 0; color: var(--muted); cursor: pointer; font-size: 14px; padding: 0; line-height: 1; height: auto; display: inline-flex; align-items: center; }
@keyframes toast-in { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
/* ---- form grid (plans, wider forms) ---- */
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px 16px; }
.hint { color: var(--muted); font-size: 12px; margin-top: 2px; }
/* ---- scrollable wide tables (mobile) ---- */
.glass { overflow-x: auto; }
/* ---- tabular numbers ---- */
.num { text-align: right; font-variant-numeric: tabular-nums; }
/* ---- stat-card icon chip (optional; handlers opt in) ---- */
.stat-icon { width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center;
  justify-content: center; color: var(--accent);
  background: color-mix(in srgb, var(--accent) 14%, transparent); margin-bottom: 10px; }
.stat-icon svg { width: 18px; height: 18px; }
/* ---- footer support link (support_footer) ---- */
footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid var(--border);
  color: var(--muted); font-size: 12px; }
footer a { color: var(--muted); }
footer a:hover { color: var(--accent); }
/* ---- responsive drawer (shell task wires the markup) ---- */
.drawer-toggle { display: none; }
.drawer-overlay { display: none; }
/* ---- reduced motion ---- */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
/* ---- denser tables ---- */
th, td { padding: 8px 12px; }
thead th { position: sticky; top: 0; }
@media (max-width: 860px) {
  .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: var(--sidebar-w);
    transform: translateX(-100%); z-index: 20; }
  .sidebar.open { transform: none; }
  .drawer-toggle { position: sticky; top: 0; margin: 8px; z-index: 30;
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    width: 44px; height: 44px; padding: 0; font-size: 18px; }
  main { margin-left: 0; padding: 12px; }
  /* touch targets: bump buttons, and stop iOS auto-zoom on inputs (<16px zooms) */
  .btn-sm, .kill-btn { height: 36px; }
  input[type="text"], input[type="password"], input[type="email"], input[type="number"], select, textarea { font-size: 16px; }
  .toast-stack { left: 12px; right: 12px; max-width: none; }
}
@media (max-width: 860px) {
  .drawer-toggle { display: inline-block; }
  .drawer-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45); z-index: 9; }
  .drawer-overlay.open { display: block; }
}
"#;

/// Pre-paint theme bootstrap: localStorage override, else OS preference.
/// Also stamps the `.theme-toggle` thumb glyph for the active theme
/// (&#9728; = sun, &#9790; = moon — HTML entities, no non-ASCII literals).
pub const THEME_BOOT: &str = r#"<script>(function(){try{var h=document.documentElement;var t=localStorage.getItem("ddns-theme");if(t!=="light"&&t!=="dark"){t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}h.dataset.theme=t;function stamp(){var g=t==="light"?"&#9728;":"&#9790;";document.querySelectorAll(".theme-toggle").forEach(function(b){var th=b.querySelector(".tt-thumb");if(th)th.innerHTML=g;b.setAttribute("aria-checked",t==="dark");});}if(document.body){stamp();}else{document.addEventListener("DOMContentLoaded",stamp);}}catch(e){}})();</script>"#;

/// Sidebar theme toggle: small grey slider switch. Thumb shows the moon in
/// night mode and the sun in light mode; the thumb slides with the theme.
pub const THEME_TOGGLE: &str = r#"<button class="theme-toggle" type="button" role="switch" aria-checked="true" aria-label="Toggle light/dark theme" title="Toggle theme" onclick="(function(b){var h=document.documentElement;var t=h.dataset.theme==='light'?'dark':'light';h.dataset.theme=t;try{localStorage.setItem('ddns-theme',t);}catch(e){}var g=t==='light'?'&#9728;':'&#9790;';var th=b.querySelector('.tt-thumb');if(th)th.innerHTML=g;b.setAttribute('aria-checked',t==='dark');})(this)"><span class="tt-track"><span class="tt-thumb">&#9790;</span></span></button>"#;

/// Toast container + inline script. Reads the `ddns_flash` cookie
/// (`base64url("kind|msg")`), renders one toast, deletes the cookie, and
/// auto-dismisses after 4s. No JS file, no CSP change.
pub const TOAST_SHELL: &str = r#"<div id="toast-stack" class="toast-stack" aria-live="polite"></div>
<script>
(function () {
  function read() {
    var m = document.cookie.match(/(?:^|; )ddns_flash=([^;]+)/);
    if (!m) return null;
    document.cookie = 'ddns_flash=; Path=/; Max-Age=0';
    try {
      var bin = atob(m[1].replace(/-/g, '+').replace(/_/g, '/'));
      var bytes = new Uint8Array(bin.length);
      for (var j = 0; j < bin.length; j++) bytes[j] = bin.charCodeAt(j);
      var raw = new TextDecoder().decode(bytes);
      var i = raw.indexOf('|');
      return { kind: raw.slice(0, i), msg: raw.slice(i + 1) };
    } catch (e) { return null; }
  }
  var f = read();
  if (f && f.msg) {
    var stack = document.getElementById('toast-stack');
    var t = document.createElement('div');
    t.className = 'toast toast-' + (f.kind === 'success' ? 'success' : f.kind === 'error' ? 'error' : 'info');
    t.innerHTML = '<span></span><button type="button" aria-label="Dismiss">&#215;</button>';
    t.firstChild.textContent = f.msg;
    t.querySelector('button').onclick = function () { t.remove(); };
    stack.appendChild(t);
    setTimeout(function () { t.remove(); }, 4000);
  }
})();
</script>"#;

/// Flash toast severity, serialized as the `kind` prefix of the cookie value.
#[derive(Clone, Copy)]
pub enum FlashKind {
    Success,
    Error,
    Info,
}

impl FlashKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Info => "info",
        }
    }
}

/// Set-Cookie value for the flash toast. Value is `base64url("kind|msg")`.
pub fn flash_cookie(kind: FlashKind, msg: &str) -> String {
    let raw = format!("{}|{}", kind.as_str(), msg);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes());
    format!("ddns_flash={b64}; Path=/; Max-Age=10; SameSite=Lax")
}

/// 303 redirect that also sets the flash cookie.
pub fn flash_redirect(location: &str, kind: FlashKind, msg: &str) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location.to_string()),
            (header::SET_COOKIE, flash_cookie(kind, msg)),
        ],
    )
        .into_response()
}

/// Sidebar navigation item. `None` renders the frame with no active page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavItem {
    Dashboard,
    Tunnels,
    Domains,
    Tokens,
    Analytics,

    Audit,
    Settings,
    None,
}

impl NavItem {
    pub fn href(self) -> &'static str {
        match self {
            Self::Dashboard => "/",
            Self::Tunnels => "/tunnels",
            Self::Domains => "/domains",
            Self::Tokens => "/tokens",
            Self::Analytics => "/analytics",
            Self::Audit => "/audit",
            Self::Settings => "/settings",
            Self::None => "",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Tunnels => "Tunnels",
            Self::Domains => "Domains",
            Self::Tokens => "Tokens",
            Self::Analytics => "Analytics",
            Self::Audit => "Activity",
            Self::Settings => "Settings",
            Self::None => "",
        }
    }
}

/// Inline SVG nav icons keyed by nav label. 14px, `currentColor` stroke —
/// they inherit the item's text color (muted → text on hover/active).
const ICONS: &[(&str, &str)] = &[
    (
        "Dashboard",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1.5" y="1.5" width="6" height="6" rx="1"/><rect x="8.5" y="1.5" width="6" height="6" rx="1"/><rect x="1.5" y="8.5" width="6" height="6" rx="1"/><rect x="8.5" y="8.5" width="6" height="6" rx="1"/></svg>"#,
    ),
    (
        "Overview",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1.5" y="1.5" width="6" height="6" rx="1"/><rect x="8.5" y="1.5" width="6" height="6" rx="1"/><rect x="1.5" y="8.5" width="6" height="6" rx="1"/><rect x="8.5" y="8.5" width="6" height="6" rx="1"/></svg>"#,
    ),
    (
        "Tunnels",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1.5v13M3.5 4.5L8 1.5l4.5 3"/></svg>"#,
    ),
    (
        "Domains",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2 1.8 2 10.2 0 12M8 2c-2 1.8-2 10.2 0 12"/></svg>"#,
    ),
    (
        "Tokens",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1.5" y="6" width="13" height="7" rx="1.5"/><path d="M5 6V4.5a3 3 0 0 1 6 0V6"/></svg>"#,
    ),
    (
        "Clients",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="5" r="2.5"/><path d="M3 13.5c.6-2.5 2.7-4 5-4s4.4 1.5 5 4"/></svg>"#,
    ),
    (
        "Plans",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M5.5 2.5v11M10.5 2.5v11M1.5 7h13"/></svg>"#,
    ),
    (
        "Codes",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5"/></svg>"#,
    ),
    (
        "Analytics",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 13.5h12M4 11V7.5M8 11V4.5M12 11V6"/></svg>"#,
    ),
    (
        "Settings",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4"/></svg>"#,
    ),
    (
        "Usage",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 13.5h12M4 11V7.5M8 11V4.5M12 11V6"/></svg>"#,
    ),
    (
        "Upgrade",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2l1.8 4.2L14 7l-4.2.8L8 12l-1.8-4.2L2 7l4.2-.8z"/></svg>"#,
    ),
    (
        "API",
        r#"<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="5.5" cy="10.5" r="2.5"/><path d="M7.5 8.5L13.5 2.5M11 5l1.5 1.5M8.5 7.5l1.5 1.5"/></svg>"#,
    ),
];

/// Inline SVG for a nav label; empty string when no icon is defined.
pub fn nav_icon(label: &str) -> &'static str {
    ICONS
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, s)| *s)
        .unwrap_or("")
}

/// Complete HTML document: flat dark `<style>` in head, sidebar navigation
/// with `active` on the current page, and `body` inside `<main>`.
/// Bottom-of-page activity log (operator pages), filtered by the page's
/// action prefix. Every operator page gets it automatically; `/audit`
/// (NavItem::Audit) and non-operator shells skip it.
fn activity_block(active: NavItem) -> String {
    let prefixes: &[&str] = match active {
        NavItem::Tunnels => &["tunnel."],
        NavItem::Domains => &["domain."],
        NavItem::Tokens => &["token."],
        NavItem::Settings => &["settings."],
        NavItem::Dashboard | NavItem::Analytics => &[],
        NavItem::Audit | NavItem::None => return String::new(),
    };
    let Some(audit) = AUDIT.get() else {
        return String::new();
    };
    let rows = audit.recent(60);
    let mut out = String::new();
    let mut n = 0;
    for r in &rows {
        if !prefixes.is_empty() && !prefixes.iter().any(|p| r.action.starts_with(p)) {
            continue;
        }
        n += 1;
        out.push_str(&format!(
            "<tr><td class=\"mono\">{t}</td><td>{a}</td><td>{d}</td></tr>",
            t = crate::fmt_ts(r.created_at),
            a = crate::http_app::html_escape(&r.action),
            d = crate::http_app::html_escape(&r.detail),
        ));
    }
    if n == 0 {
        return String::new();
    }
    format!(
        "<div class=\"box\" style=\"margin-top:28px\"><h2>Activity</h2>\
         <p class=\"hint\">{n} latest · full log at <a href=\"/audit\">Activity</a></p>\
         <table><thead><tr><th>Time</th><th>Action</th><th>Detail</th></tr></thead><tbody>{out}</tbody></table></div>"
    )
}

pub fn page_shell(title: &str, active: NavItem, body: &str) -> String {
    let groups: &[(&str, &[NavItem])] = &[
        ("Overview", &[NavItem::Dashboard]),
        (
            "Routing",
            &[NavItem::Tunnels, NavItem::Domains, NavItem::Tokens],
        ),
        ("Operations", &[NavItem::Analytics, NavItem::Audit]),
        ("Account", &[NavItem::Settings]),
    ];
    let mut nav = String::new();
    for (group, items) in groups {
        nav.push_str(&format!(
            "<div class=\"group\">{group}</div>{}",
            items
                .iter()
                .map(|item| {
                    let cls = if *item == active {
                        "item active"
                    } else {
                        "item"
                    };
                    let icon = nav_icon(item.label());
                    format!(
                        "<a class=\"{cls}\" href=\"{}\">{icon}<span>{}</span></a>",
                        item.href(),
                        item.label()
                    )
                })
                .collect::<String>()
        ));
    }
    let brand = brand_name();
    let support = support_footer();
    let activity = activity_block(active);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} — {brand}</title>\
         {THEME_BOOT}<style>{}</style></head>\
         <body>\
         <button class=\"drawer-toggle\" type=\"button\" onclick=\"document.getElementById('sidebar').classList.toggle('open');document.querySelector('.drawer-overlay').classList.toggle('open')\" aria-label=\"Toggle navigation\">&#9776;</button>\
         <div class=\"drawer-overlay\" onclick=\"this.classList.remove('open');document.getElementById('sidebar').classList.remove('open')\"></div>\
         <aside class=\"sidebar\" id=\"sidebar\"><div class=\"brand\">{BRAND_LOGO}{brand} <span>Broker</span></div>{nav}\
         <div class=\"logout\">\
         {THEME_TOGGLE}\
         <a href=\"/logout\">Log out</a></div></aside>\
         <main>{body}{activity}{support}{TOAST_SHELL}</main></body></html>",
        GLASS_CSS,
        activity = activity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_script_discovery_handles_hashed_and_dev_layouts() {
        // Release: content-hashed name under assets/.
        let hashed = r#"<!DOCTYPE html><html><head>
<link rel="preload" as="script" href="/_assets/assets/ddns-web-dxh67c67961911e372c.js" crossorigin>
</head><body><div id="main"></div>
<script type="module" async src="/_assets/assets/ddns-web-dxh67c67961911e372c.js"></script>
</body></html>"#;
        assert_eq!(
            extract_module_script(hashed).as_deref(),
            Some("/_assets/assets/ddns-web-dxh67c67961911e372c.js")
        );

        // Dev: un-hashed name under wasm/.
        let dev = r#"<html><head></head><body><div id="main"></div>
<script type="module" src="/_assets/wasm/ddns-web.js"></script>
</body></html>"#;
        assert_eq!(
            extract_module_script(dev).as_deref(),
            Some("/_assets/wasm/ddns-web.js")
        );

        // No script tag → fallback.
        assert_eq!(extract_module_script("<html></html>"), None);

        // discover_bundle_script falls back when the bundle is absent.
        let tmp = std::env::temp_dir();
        assert_eq!(discover_bundle_script(&tmp), "/_assets/wasm/ddns-web.js");

        // bundle_script() returns the dev fallback until set.
        set_bundle_script("");
        assert_eq!(bundle_script(), "/_assets/wasm/ddns-web.js");
        set_bundle_script("/_assets/assets/ddns-web-dxh67c67961911e372c.js");
        assert_eq!(
            bundle_script(),
            "/_assets/assets/ddns-web-dxh67c67961911e372c.js"
        );
        set_bundle_script("");
    }
}
