/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The Dashboard: everything that ends up in the **firewall script**.
//!
//! That split is the same one the TUI documents — Site settings owns what
//! ends up in NGINX config, this owns the firewall — and it is what
//! decides which screen a given setting belongs on.

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::db::{Category, Db, GeoMode, Policy};
use crate::firewall::{FirewallBackend, LockoutStatus};
use crate::health;
use crate::protection::Detector;
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{back_with, internal_error, render, Auth, FlashQuery};
use crate::web::state::AppState;

/// Everything the page shows, read in one pass.
///
/// One struct filled by one `with_db` call rather than a dozen: each call
/// is a `spawn_blocking` hop and a lock acquisition, and a page assembled
/// from twelve of them could show two halves of two different states.
struct View {
    /// The last health probe, re-assessed against the database as it is
    /// now, and when that probe was taken. `None` until one has run.
    health: Option<(health::Report, i64)>,
    scanner: Policy,
    search: Policy,
    ai: Policy,
    geo_mode: GeoMode,
    selected_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    detectors: Vec<(Detector, bool, i64)>,
    feeds: Vec<crate::db::ReputationSource>,
    site_count: usize,
    sources_total: usize,
    sources_stale: usize,
    rule_count: usize,
    firewall_needs_update: bool,
    /// Where the "Write script" button writes, from `AppState`. Shown, not
    /// asked for — see [`render_firewall`] for why the console does not
    /// take a destination from the form.
    firewall_out: String,
    /// The remembered backend, so the dropdown opens on the one this host
    /// actually renders for.
    firewall_backend: FirewallBackend,
    /// Sites the console could be mounted under, for Path mode's dropdown.
    /// Empty means "no sites scanned yet", which the panel has to say
    /// rather than render an empty select.
    sites: Vec<(String, String)>,
    /// Where the console currently thinks it is reachable — the bind
    /// address, the path prefix and the host allowlist, all three of which
    /// this panel writes.
    bind: String,
    base_path: String,
    allowed_hosts: Vec<String>,
    jobs: Vec<crate::cron::JobStatus>,
}

/// A bot list older than this reads as needing a refresh. Matches the
/// TUI's Summary panel.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

fn load(db: &Db, firewall_out: Option<&std::path::Path>) -> anyhow::Result<View> {
    // Derived from the cron's last probe rather than probing here: the
    // probe shells out to `nft`, and a dashboard render is the last place
    // that should happen.
    let health = health::cached_report(db)?;
    let sources = db.list_sources()?;
    let now = now_secs();
    let sources_stale = sources
        .iter()
        .filter(|s| match s.last_fetched_at {
            None => true,
            Some(at) => now - at > STALE_AFTER_SECS,
        })
        .count();

    let rules = crate::firewall::all_rules(db)?;
    let signature = crate::firewall::rules_signature(&rules);

    Ok(View {
        health,
        scanner: db.get_category_default(Category::Scanner)?,
        search: db.get_category_default(Category::Search)?,
        ai: db.get_category_default(Category::Ai)?,
        geo_mode: db.get_geo_mode()?,
        selected_countries: db.list_selected_countries()?,
        fetched_countries: db.list_fetched_countries()?,
        detectors: Detector::ALL
            .into_iter()
            .map(|d| Ok((d, d.is_enabled(db)?, d.ttl_days(db)?)))
            .collect::<anyhow::Result<_>>()?,
        feeds: db.list_reputation_sources()?,
        site_count: db.list_sites()?.len(),
        sources_total: sources.len(),
        sources_stale,
        rule_count: rules.len(),
        // The path the *current* backend would write to, not a fixed one:
        // showing `firewall.nft` next to an iptables selection is how the
        // two drifted apart in the first place.
        firewall_out: crate::firewall::output_path(
            firewall_out,
            crate::firewall::stored_backend(db)?,
        )
        .display()
        .to_string(),
        firewall_backend: crate::firewall::stored_backend(db)?,
        sites: db
            .list_sites()?
            .into_iter()
            .map(|site| (site.server_name, site.config_path))
            .collect(),
        bind: crate::web::resolve_bind(db, None)
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| crate::web::DEFAULT_BIND.to_string()),
        base_path: db
            .get_text_setting(crate::web::BASE_PATH_KEY)?
            .unwrap_or_default(),
        allowed_hosts: crate::web::configured_hosts(db)?,
        firewall_needs_update: db.get_firewall_rendered_signature()?.as_deref()
            != Some(signature.as_str()),
        jobs: crate::cron::status(db)?,
    })
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(flash): Query<FlashQuery>,
) -> Response {
    let firewall_out = state.firewall_out.clone();
    let view = match state
        .with_db(move |db| load(db, firewall_out.as_deref()))
        .await
    {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::new(auth.csrf.clone(), state.base.clone());
    render(Tab::Dashboard, &ctx, flash.into_flash(), body(&view, &ctx))
}

fn body(view: &View, ctx: &Ctx) -> Markup {
    html! {
        .cols {
            (health_panel(view))
            (categories_panel(view, ctx))
            (geo_panel(view, ctx))
            (detectors_panel(view, ctx))
            (feeds_panel(view, ctx))
            (summary_panel(view, ctx))
            (web_access_panel(view, ctx))
            (jobs_panel(view))
        }
    }
}

// ---- is this host actually protected? ----

fn health_panel(view: &View) -> Markup {
    let Some((report, taken_at)) = &view.health else {
        return layout::panel(
            "System status",
            Some("Whether this host is actually protected"),
            html! {
                .panel-body {
                    p .hint {
                        "No check has run yet. The internal cron takes one every hour while "
                        "this console is open, or run "
                        code { "stop-bots status" }
                        " to take one now."
                    }
                }
            },
        );
    };

    layout::panel(
        "System status",
        Some(&format!(
            "{} \u{2014} checked {}",
            report.headline(),
            age(*taken_at)
        )),
        html! {
            table {
                tbody {
                    @for check in &report.checks {
                        tr {
                            td { (check.title) }
                            td { (level_pill(check.level)) }
                            td {
                                (check.detail)
                                @if let Some(fix) = &check.fix {
                                    br;
                                    span .hint { "\u{2192} " (fix) }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

fn level_pill(level: health::Level) -> Markup {
    // `Unknown` is neutral rather than green on purpose: a check that
    // could not run has not passed, and colouring it as if it had is how a
    // status panel starts lying.
    let kind = match level {
        health::Level::Ok => PillKind::Allowed,
        health::Level::Unknown => PillKind::Neutral,
        health::Level::Warn => PillKind::Warn,
        health::Level::Critical => PillKind::Blocked,
    };
    layout::pill(level.tag(), kind)
}

/// "12 minutes ago", for the panel's subtitle.
fn age(taken_at: i64) -> String {
    let seconds = (now_secs() - taken_at).max(0);
    match seconds {
        0..=90 => "just now".to_string(),
        91..=5400 => format!("{} minutes ago", seconds / 60),
        _ => format!("{} hours ago", seconds / 3600),
    }
}

// ---- system-wide category defaults ----

fn categories_panel(view: &View, ctx: &Ctx) -> Markup {
    let rows = [
        (Category::Scanner, view.scanner),
        (Category::Search, view.search),
        (Category::Ai, view.ai),
    ];
    layout::panel(
        "System-wide settings",
        Some("What each category of known bot gets by default"),
        html! {
            table {
                tbody {
                    @for (category, policy) in rows {
                        tr {
                            td { (category_label(category)) }
                            td { (policy_pill(policy)) }
                            td .right {
                                form .inline method="post" action=(ctx.url("/category")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="category" value=(category_id(category));
                                    input type="hidden" name="policy" value=(policy_id(flip(policy)));
                                    button type="submit" {
                                        @match flip(policy) {
                                            Policy::Blocked => "Block",
                                            Policy::Allowed => "Allow",
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            .panel-body {
                .row {
                    form .inline method="post" action=(ctx.url("/update-all")) {
                        (layout::csrf_field(ctx))
                        button .primary type="submit" { "Update everything" }
                    }
                    form .inline method="post" action=(ctx.url("/apply-all")) {
                        (layout::csrf_field(ctx))
                        button .primary type="submit" { "Apply everything" }
                    }
                }
                p .hint {
                    "\u{201c}Update everything\u{201d} downloads every bot list, every "
                    "enabled reputation feed, the crawler IP ranges, and the ranges for "
                    "every country you selected \u{2014} one source failing does not stop "
                    "the rest. \u{201c}Apply everything\u{201d} then writes and reloads "
                    "the NGINX config and writes and runs the firewall script, the same "
                    "two halves, and in the same order, as "
                    code { "stop-bots batch --apply" }
                    "."
                }
            }
        },
    )
}

fn flip(policy: Policy) -> Policy {
    match policy {
        Policy::Blocked => Policy::Allowed,
        Policy::Allowed => Policy::Blocked,
    }
}

fn policy_pill(policy: Policy) -> Markup {
    match policy {
        Policy::Blocked => layout::pill("BLOCKED", PillKind::Blocked),
        Policy::Allowed => layout::pill("ALLOWED", PillKind::Allowed),
    }
}

fn category_id(category: Category) -> &'static str {
    match category {
        Category::Scanner => "scanner",
        Category::Search => "search",
        Category::Ai => "ai",
    }
}

/// The name to put in a message about `category`.
fn category_label(category: Category) -> &'static str {
    match category {
        Category::Scanner => "Scanners",
        Category::Search => "Search bots",
        Category::Ai => "AI bots",
    }
}

fn category_from(id: &str) -> Option<Category> {
    match id {
        "scanner" => Some(Category::Scanner),
        "search" => Some(Category::Search),
        "ai" => Some(Category::Ai),
        _ => None,
    }
}

fn policy_id(policy: Policy) -> &'static str {
    match policy {
        Policy::Blocked => "blocked",
        Policy::Allowed => "allowed",
    }
}

fn policy_from(id: &str) -> Option<Policy> {
    match id {
        "blocked" => Some(Policy::Blocked),
        "allowed" => Some(Policy::Allowed),
        _ => None,
    }
}

// ---- geo ----

fn geo_panel(view: &View, ctx: &Ctx) -> Markup {
    let mode_label = match view.geo_mode {
        GeoMode::Blocklist => "Blocklist — the countries below are blocked",
        GeoMode::Allowlist => "Allowlist — only the countries below are allowed",
    };
    let counts: std::collections::HashMap<&str, i64> = view
        .fetched_countries
        .iter()
        .map(|(code, ranges, _)| (code.as_str(), *ranges))
        .collect();

    layout::panel(
        "Geo-blocking",
        Some(mode_label),
        html! {
            .panel-body {
                .row {
                    form .inline method="post" action=(ctx.url("/geo-mode")) {
                        (layout::csrf_field(ctx))
                        input type="hidden" name="mode" value=(match view.geo_mode {
                            GeoMode::Blocklist => "allowlist",
                            GeoMode::Allowlist => "blocklist",
                        });
                        button type="submit" {
                            @match view.geo_mode {
                                GeoMode::Blocklist => "Switch to allowlist",
                                GeoMode::Allowlist => "Switch to blocklist",
                            }
                        }
                    }
                    @if view.geo_mode == GeoMode::Allowlist {
                        span .hint {
                            "Allowlist blocks everything else host-wide. nftables only."
                        }
                    }
                }
            }
            @if view.selected_countries.is_empty() {
                (layout::empty("No countries selected."))
            } @else {
                table {
                    tbody {
                        @for code in &view.selected_countries {
                            tr {
                                td .mono { (code) }
                                td .num {
                                    @match counts.get(code.as_str()) {
                                        Some(n) => { (n) " range(s)" }
                                        None => { span .hint { "not fetched" } }
                                    }
                                }
                                td .right {
                                    form .inline method="post" action=(ctx.url("/geo-remove")) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="country" value=(code);
                                        button type="submit" { "Remove" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .panel-body {
                form .row method="post" action=(ctx.url("/geo-add")) {
                    (layout::csrf_field(ctx))
                    input type="text" name="country" placeholder="Country code, e.g. CN"
                        maxlength="2" size="4" required;
                    button .primary type="submit" { "Add" }
                    span .hint {
                        "Adding selects it. Fetching its ranges is "
                        code { "stop-bots update-country-ranges" }
                        "."
                    }
                }
            }
        },
    )
}

// ---- detectors ----

fn detectors_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Automatic blocking",
        Some("Detectors that write firewall rules from your logs"),
        html! {
            table {
                thead { tr {
                    th { "Detector" }
                    th { "State" }
                    th .right { "Block lasts" }
                    th { "" }
                    th .right { "Action" }
                } }
                tbody {
                    @for (detector, enabled, ttl_days) in &view.detectors {
                        tr {
                            td {
                                (detector.spec().label)
                                @if detector.spec().uses_ssh_log {
                                    span .hint { " (SSH log)" }
                                }
                            }
                            td {
                                @if *enabled {
                                    (layout::pill("ON", PillKind::Allowed))
                                } @else {
                                    (layout::pill("OFF", PillKind::Neutral))
                                }
                            }
                            td .num { (ttl_days) "d" }
                            td {
                                form .row method="post" action=(ctx.url("/detector-ttl")) style="gap:6px" {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="detector" value=(detector.id());
                                    input type="number" name="days" min="1" max="3650"
                                        value=(ttl_days) size="4" style="width:5.5em";
                                    button type="submit" { "Set" }
                                }
                            }
                            td .right {
                                form .inline method="post" action=(ctx.url("/detector")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="detector" value=(detector.id());
                                    input type="hidden" name="enabled" value=(if *enabled { "0" } else { "1" });
                                    button type="submit" {
                                        @if *enabled { "Turn off" } @else { "Turn on" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

// ---- third-party feeds ----

fn feeds_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Third-party IP feeds",
        Some("Published CIDR lists. Switching one on does not download it"),
        html! {
            @if view.feeds.is_empty() {
                (layout::empty("No feeds registered."))
            } @else {
                table {
                    thead { tr {
                        th { "Feed" }
                        th { "State" }
                        th .right { "Ranges" }
                        th .right { "Action" }
                    } }
                    tbody {
                        @for feed in &view.feeds {
                            tr {
                                td { (feed.name) }
                                td {
                                    @if feed.enabled {
                                        (layout::pill("ON", PillKind::Allowed))
                                    } @else {
                                        (layout::pill("OFF", PillKind::Neutral))
                                    }
                                }
                                td .num {
                                    @if feed.last_fetched_at.is_some() {
                                        (feed.range_count)
                                    } @else {
                                        span .hint { "not fetched" }
                                    }
                                }
                                td .right {
                                    form .inline method="post" action=(ctx.url("/feed")) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="feed" value=(feed.id);
                                        input type="hidden" name="enabled" value=(if feed.enabled { "0" } else { "1" });
                                        button type="submit" {
                                            @if feed.enabled { "Turn off" } @else { "Turn on" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

// ---- summary ----

fn summary_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Summary",
        None,
        html! {
            table {
                tbody {
                    tr {
                        td { "Sites discovered" }
                        td .num { (view.site_count) }
                        td {}
                    }
                    tr {
                        td { "Bot list sources" }
                        td .num { (view.sources_total) }
                        td {
                            @if view.sources_stale == 0 && view.sources_total > 0 {
                                (layout::pill("UP TO DATE", PillKind::Allowed))
                            } @else if view.sources_total == 0 {
                                span .hint { "none registered" }
                            } @else {
                                (layout::pill(&format!("{} NEED UPDATING", view.sources_stale), PillKind::Warn))
                            }
                        }
                    }
                    tr {
                        td { "Firewall rules" }
                        td .num { (view.rule_count) }
                        td {
                            @if view.rule_count == 0 {
                                span .hint { "nothing to write" }
                            } @else if view.firewall_needs_update {
                                (layout::pill("SCRIPT IS STALE", PillKind::Warn))
                            } @else {
                                (layout::pill("SCRIPT MATCHES", PillKind::Allowed))
                            }
                        }
                    }
                }
            }
            .panel-body {
                form .row method="post" action=(ctx.url("/render-firewall")) {
                    (layout::csrf_field(ctx))
                    label .field {
                        "Write the firewall script to"
                        code { (view.firewall_out) }
                    }
                    label .field {
                        "Backend"
                        select name="backend" {
                            @for backend in [FirewallBackend::Nftables, FirewallBackend::Iptables] {
                                option value=(backend.stored())
                                    selected[backend == view.firewall_backend] {
                                    (backend.stored())
                                }
                            }
                        }
                    }
                    label .field {
                        "Run it after writing"
                        input type="checkbox" name="apply" value="1";
                    }
                    button .primary type="submit" { "Write script" }
                }
                p .hint {
                    "Writing is inert — the script does nothing until it is run. Ticking "
                    "\u{201c}run it after writing\u{201d} enforces it immediately, after the same "
                    "anti-lockout check "
                    code { "stop-bots batch --apply" }
                    " runs: rules that would block a currently-connected SSH client are "
                    "refused rather than written."
                }

            }
        },
    )
}

// ---- web access ----

/// How to reach the console from outside, and the button that sets it up.
///
/// Path mode is offered first and is the default. A subdomain needs its own
/// certificate; a path attaches to a site that already has one, and this
/// console has a password form and a session cookie, so "inherits the
/// existing TLS" is worth more than "has a tidier URL".
fn web_access_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Web Access",
        Some("Reach this console from outside, through NGINX"),
        html! {
            table {
                tbody {
                    tr {
                        td { "Listening on" }
                        td .mono { (view.bind) }
                    }
                    tr {
                        td { "Path prefix" }
                        td .mono {
                            @if view.base_path.is_empty() { "/" } @else { "/" (view.base_path) }
                        }
                    }
                    tr {
                        td { "Answers to" }
                        td {
                            @if view.allowed_hosts.is_empty() {
                                span .hint { "localhost only" }
                            } @else {
                                span .mono { (view.allowed_hosts.join(", ")) }
                            }
                        }
                    }
                }
            }

            .panel-body {
                form method="post" action=(ctx.url("/web-access")) {
                    (layout::csrf_field(ctx))
                    label .field {
                        "Mode"
                        select name="mode" {
                            option value="path" { "Path on an existing site" }
                            option value="subdomain" { "Its own subdomain" }
                        }
                    }
                    label .field {
                        "Site (path mode)"
                        select name="site" {
                            @if view.sites.is_empty() {
                                option value="" { "no sites scanned yet" }
                            }
                            @for (name, _) in &view.sites {
                                option value=(name) { (name) }
                            }
                        }
                    }
                    label .field {
                        "Path prefix"
                        input type="text" name="prefix" value=(crate::webaccess::DEFAULT_PREFIX) size="18";
                    }
                    label .field {
                        "Subdomain host"
                        input type="text" name="host" placeholder="console.example.com" size="26";
                    }
                    button .primary type="submit" { "Set up NGINX" }
                }

                p .hint {
                    "Path mode adds a "
                    code { "location" }
                    " block to the site you pick, so the console inherits that site\u{2019}s "
                    "certificate. It also records the prefix and the host name, because this "
                    "server matches the full path including the prefix and refuses a request "
                    "carrying a host it was not told about."
                }
                p .hint {
                    "Subdomain mode writes a new "
                    code { "server" }
                    " block on port 80. Until you run "
                    code { "certbot --nginx -d <host>" }
                    ", the password form and the session cookie cross the network in the "
                    "clear \u{2014} which is why path mode is the default."
                }
            }
        },
    )
}

#[derive(Deserialize)]
struct WebAccessForm {
    mode: String,
    site: String,
    prefix: String,
    host: String,
}

/// Writes the NGINX config that makes this console reachable, plus the two
/// settings that have to agree with it.
///
/// All three or none: a `location` block without `web:base_path` serves a
/// console whose every link points outside it, and either mode without the
/// host in `web:allowed_hosts` serves a 403 to every proxied request. The
/// config is written last, because it is the one that can fail validation
/// and the one this can roll back.
async fn set_web_access(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<WebAccessForm>,
) -> Response {
    let request = match form.mode.as_str() {
        "subdomain" => crate::webaccess::Request::Subdomain { host: form.host },
        _ => crate::webaccess::Request::Path {
            site: form.site,
            prefix: form.prefix,
        },
    };

    // Plan, apply and record in one hop onto the blocking pool: all three
    // are synchronous, and the two that touch `Db` cannot cross an
    // `.await` anyway. The TUI splits them, because its `Db` lives on the
    // main thread; here the split would buy nothing.
    let root = state.nginx_root.clone();
    let written = state
        .with_db(move |db| {
            let plan = crate::webaccess::plan(db, &request)?;
            let path = crate::webaccess::apply(&plan, &root)?;
            crate::webaccess::record(db, &plan)?;
            anyhow::Ok(path)
        })
        .await;

    match written {
        Ok(path) => {
            let reload = reload_nginx(&state).await;
            let note = match reload {
                Ok(note) => note,
                Err(err) => format!("reload failed: {err:#}"),
            };
            back_with(
                &state.base,
                "/",
                &format!(
                    "Wrote {} and recorded the host. NGINX {note}. Restart the console for a \
                     changed path prefix to take effect.",
                    path.display()
                ),
                true,
            )
        }
        Err(err) => back_with(&state.base, "/", &format!("{err:#}"), false),
    }
}

// ---- scheduled jobs ----

fn jobs_panel(view: &View) -> Markup {
    layout::panel(
        "Scheduled tasks",
        Some("Run by the internal cron, which ticks while this server or the TUI is running"),
        html! {
            table {
                thead { tr {
                    th { "Task" }
                    th { "Last run" }
                    th { "Result" }
                    th { "" }
                } }
                tbody {
                    @for status in &view.jobs {
                        tr {
                            td { (status.job.label()) }
                            td {
                                @match status.last_run {
                                    Some(at) => { (relative(at)) }
                                    None => { span .hint { "never" } }
                                }
                            }
                            td { (status.last_summary.clone().unwrap_or_default()) }
                            td {
                                @if status.due { (layout::pill("DUE", PillKind::Warn)) }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// "3m ago", to the same rounding the TUI uses.
pub(crate) fn relative(at: i64) -> String {
    let delta = now_secs() - at;
    if delta < 60 {
        return "just now".to_string();
    }
    let minutes = delta / 60;
    if minutes < 60 {
        return format!("{minutes}m ago");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    format!("{}d ago", hours / 24)
}

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/category"), post(set_category))
        .route(&base.url("/geo-mode"), post(set_geo_mode))
        .route(&base.url("/geo-add"), post(add_country))
        .route(&base.url("/geo-remove"), post(remove_country))
        .route(&base.url("/detector"), post(set_detector))
        .route(&base.url("/detector-ttl"), post(set_detector_ttl))
        .route(&base.url("/feed"), post(set_feed))
        .route(&base.url("/render-firewall"), post(render_firewall))
        .route(&base.url("/update-all"), post(update_all))
        .route(&base.url("/apply-all"), post(apply_all))
        .route(&base.url("/web-access"), post(set_web_access))
}

#[derive(Deserialize)]
struct CategoryForm {
    category: String,
    policy: String,
}

async fn set_category(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<CategoryForm>,
) -> Response {
    let (Some(category), Some(policy)) = (category_from(&form.category), policy_from(&form.policy))
    else {
        return back_with(
            &state.base,
            "/",
            "That is not a category this tool knows.",
            false,
        );
    };

    match state
        .with_db(move |db| db.set_category_default(category, policy))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/",
            &format!(
                "{} are now {}. Apply on Site settings to write it into the site configs.",
                category_label(category),
                policy_id(policy)
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct GeoModeForm {
    mode: String,
}

async fn set_geo_mode(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<GeoModeForm>,
) -> Response {
    let mode = match form.mode.as_str() {
        "allowlist" => GeoMode::Allowlist,
        "blocklist" => GeoMode::Blocklist,
        _ => return back_with(&state.base, "/", "Unknown geo mode.", false),
    };
    match state.with_db(move |db| db.set_geo_mode(mode)).await {
        Ok(()) => back_with(&state.base, "/", "Geo mode changed.", true),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not change the geo mode: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct CountryForm {
    country: String,
}

async fn add_country(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<CountryForm>,
) -> Response {
    let code = form.country.trim().to_uppercase();
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        return back_with(
            &state.base,
            "/",
            "A country is a two-letter ISO code, like CN or RU.",
            false,
        );
    }
    // Records the selection; does not download.
    //
    // The TUI fetches the zone file when a country is selected, and the
    // asymmetry here is deliberate rather than an oversight. Two reasons:
    // an aggregated zone file is hundreds of kilobytes from a third party,
    // and blocking a request handler on that makes the button feel broken
    // on a slow link; and this project keeps its test suite free of
    // network access (see "Testing without nginx, iptables or the
    // network" in SPECS.md) — a handler that downloads on POST made
    // `the_geo_mode_and_country_selection_round_trip` reach ipdeny.com.
    //
    // What this used to do instead was tell the operator to go and run
    // `stop-bots update-country-ranges --country RU` themselves, which is
    // a console that knows what needs doing and asks you to do it. It now
    // names the button that does it.
    let stored = code.clone();
    match state
        .with_db(move |db| db.set_country_selected(&stored, true))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/",
            &format!(
                "Selected {code}. Press \u{201c}Update everything\u{201d} to download its \
                 ranges, then \u{201c}Apply everything\u{201d} to enforce them."
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not select {code}: {err}"),
            false,
        ),
    }
}

async fn remove_country(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<CountryForm>,
) -> Response {
    let code = form.country;
    let stored = code.clone();
    match state
        .with_db(move |db| db.set_country_selected(&stored, false))
        .await
    {
        Ok(()) => back_with(&state.base, "/", &format!("Removed {code}."), true),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not remove {code}: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct DetectorForm {
    detector: String,
    enabled: String,
}

async fn set_detector(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<DetectorForm>,
) -> Response {
    let Some(detector) = Detector::from_id(&form.detector) else {
        return back_with(&state.base, "/", "Unknown detector.", false);
    };
    let enabled = form.enabled == "1";
    match state
        .with_db(move |db| detector.set_enabled(db, enabled))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/",
            &format!(
                "{} is now {}.",
                detector.spec().label,
                if enabled { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not change that: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct TtlForm {
    detector: String,
    days: i64,
}

async fn set_detector_ttl(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<TtlForm>,
) -> Response {
    let Some(detector) = Detector::from_id(&form.detector) else {
        return back_with(&state.base, "/", "Unknown detector.", false);
    };
    if form.days < 1 {
        return back_with(
            &state.base,
            "/",
            "A block has to last at least a day.",
            false,
        );
    }
    let days = form.days;
    match state
        .with_db(move |db| detector.set_ttl_days(db, days))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/",
            &format!("{} now blocks for {days} day(s).", detector.spec().label),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not change that: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct FeedForm {
    feed: String,
    enabled: String,
}

async fn set_feed(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<FeedForm>,
) -> Response {
    let enabled = form.enabled == "1";
    let id = form.feed;
    let stored = id.clone();
    match state
        .with_db(move |db| db.set_reputation_source_enabled(&stored, enabled))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/",
            &format!("{id} is now {}.", if enabled { "on" } else { "off" }),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/",
            &format!("Could not change {id}: {err}"),
            false,
        ),
    }
}

/// Downloads every list this host uses — the console's half of what
/// `stop-bots batch` does, through the same `refresh::plan`.
///
/// One source failing is reported and the rest still run: these are eight
/// third parties, and a transient failure at one of them is not a reason to
/// leave the other seven stale.
async fn update_all(State(state): State<AppState>, _auth: Auth) -> Response {
    let plan = match state.with_db(crate::refresh::plan).await {
        Ok(plan) => plan,
        Err(err) => {
            return back_with(
                &state.base,
                "/",
                &format!("Could not work out what to update: {err}"),
                false,
            )
        }
    };

    let mut done = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut outcomes = Vec::new();
    for source in plan {
        // Fetch off the database lock, store on it — `Db` is not `Sync`,
        // so nothing holding it can cross an `.await`.
        let fetched = crate::refresh::fetch(&source).await;
        let source_for_store = source.clone();
        let outcome = match fetched {
            Ok(raw) => state
                .with_db(move |db| crate::refresh::store(db, &source_for_store, &raw))
                .await
                .map_err(|err| format!("{err:#}")),
            Err(err) => Err(format!("{err:#}")),
        };
        match &outcome {
            Ok(_) => done += 1,
            Err(err) => failures.push(format!("{}: {err}", source.label())),
        }
        outcomes.push((source, outcome));
    }

    // Only when all three crawler sources worked, for the reason
    // `refresh::crawler_ranges_all_succeeded` documents.
    if crate::refresh::crawler_ranges_all_succeeded(&outcomes) {
        let _ = state
            .with_db(|db| {
                crate::cron::record_run(
                    db,
                    crate::cron::CronJob::UpdateIpRanges,
                    "updated from the console",
                );
                anyhow::Ok(())
            })
            .await;
    }

    let message = if failures.is_empty() {
        format!("Updated {done} list(s).")
    } else {
        format!(
            "Updated {done} list(s). {} failed — {}",
            failures.len(),
            failures.join("; ")
        )
    };
    back_with(&state.base, "/", &message, failures.is_empty())
}

/// Writes and enforces both planes: the NGINX config, then the firewall.
///
/// The two are independent on purpose, same as `batch --apply`: whichever
/// fails, the other still gets its turn, because a half-applied host is
/// better than one where an NGINX syntax error also left the firewall
/// stale.
async fn apply_all(State(state): State<AppState>, _auth: Auth) -> Response {
    let mut parts: Vec<String> = Vec::new();
    let mut ok = true;

    let root = state.nginx_root.clone();
    match state
        .with_db(move |db| crate::nginx::apply_all_sites(db, &root))
        .await
    {
        Ok(outcome) => {
            parts.push(format!("NGINX: {} file(s) changed", outcome.changed));
            if outcome.changed > 0 {
                match reload_nginx(&state).await {
                    Ok(note) => parts.push(note),
                    Err(err) => {
                        ok = false;
                        parts.push(format!("reload failed: {err}"));
                    }
                }
            }
        }
        Err(err) => {
            ok = false;
            parts.push(format!("NGINX failed: {err:#}"));
        }
    }

    match write_and_apply_firewall(&state).await {
        Ok(note) => parts.push(note),
        Err(err) => {
            ok = false;
            parts.push(format!("firewall failed: {err:#}"));
        }
    }

    back_with(&state.base, "/", &parts.join(". "), ok)
}

/// Renders the firewall script, writes it, and runs it.
///
/// The console refusing to *apply* the script used to be one of its three
/// deliberate omissions. That was reversed on request, so this is the one
/// place it happens, and the guards are what make it defensible:
///
/// - `assess_lockout_risk` runs against the rules in the order the script
///   will evaluate them, before anything is written — the same guard
///   `batch --apply` runs, and a risk is a refusal, not a warning.
/// - `apply_for_real` gates the run itself, so `stop-bots web --no-apply`
///   keeps the old write-only behaviour.
/// - The script that runs is the one just written to `firewall_out`, not a
///   freshly derived one, so what executes is what the guard approved and
///   what the operator can read afterwards.
///
/// The lockout guard covers SSH, not this console: the console's own
/// address is protected separately by the "refusing to block the address
/// you are connected from" check on the block handlers, which is what
/// keeps a blocked rule from reaching the table in the first place.
async fn write_and_apply_firewall(state: &AppState) -> anyhow::Result<String> {
    write_firewall(state, true).await
}

/// Renders and writes the script, and runs it when `apply` is set.
async fn write_firewall(state: &AppState, apply: bool) -> anyhow::Result<String> {
    let out_override = state.firewall_out.clone();
    let ssh_log = state.ssh_log.clone();
    let (path, count, backend) = state
        .with_db(move |db| {
            let backend = crate::firewall::stored_backend(db)?;
            // Derived from the backend inside the same closure that chose
            // it, so the two cannot disagree — an iptables script in a
            // `.nft` file is what happens when they are decided apart.
            let out = crate::firewall::output_path(out_override.as_deref(), backend);
            let built = crate::firewall::build_script(db, backend)?;
            match crate::firewall::assess_lockout_risk(&built.rules, ssh_log.as_deref()) {
                LockoutStatus::Risks(risks) if !risks.is_empty() => {
                    let names: Vec<String> = risks
                        .into_iter()
                        .map(|(ip, rule)| format!("{ip} (by rule {rule})"))
                        .collect();
                    anyhow::bail!(
                        "refusing to write: these rules would block a currently-connected SSH \
                         client — {}. Unblock it first.",
                        names.join(", ")
                    )
                }
                LockoutStatus::Risks(_) | LockoutStatus::LogUnavailable => {}
            }
            crate::firewall::write_script(&out, &built.script)?;
            db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&built.rules))?;
            anyhow::Ok((out, built.rules.len(), backend))
        })
        .await?;

    if !apply {
        return Ok(format!(
            "Wrote {count} rule(s) to {}. Run it to apply.",
            path.display()
        ));
    }
    if !state.apply_for_real {
        return Ok(format!(
            "Wrote {count} rule(s) to {} (not applied: --no-apply)",
            path.display()
        ));
    }

    // Blocking: this runs `nft -f` or `sh`, which is a subprocess, and a
    // subprocess on the async runtime blocks whatever else that thread was
    // going to serve.
    let script = path.clone();
    let applied =
        tokio::task::spawn_blocking(move || crate::firewall::apply_script(backend, &script))
            .await
            .map_err(|err| anyhow::anyhow!("the apply thread panicked: {err}"))?;
    applied
        .map_err(|err| err.context(format!("wrote {count} rule(s), but applying them failed")))?;

    Ok(format!(
        "Wrote and applied {count} rule(s) to {}.",
        path.display()
    ))
}

/// Reloads NGINX, honouring `--no-apply`.
async fn reload_nginx(state: &AppState) -> anyhow::Result<String> {
    if !state.apply_for_real {
        return Ok("not reloaded (--no-apply)".to_string());
    }
    state
        .with_db(|db| {
            let commands = crate::nginx::NginxCommands::from_db(db)?;
            crate::nginx::reload_with(&commands)
        })
        .await?;
    Ok("reloaded".to_string())
}

#[derive(Deserialize)]
struct RenderForm {
    backend: String,
    /// Present only when the checkbox is ticked — HTML omits an unchecked
    /// box entirely rather than sending `false`.
    apply: Option<String>,
}

/// Writes the firewall script.
///
/// Writing only — this never runs it. That mirrors the CLI's default and
/// the reasoning behind it: a written script is inert, and putting "apply"
/// one click away in a browser, on the one operation that can take the
/// host off the network, is not a trade this UI makes. The lockout guard
/// still runs, because a script written now is a script someone will run
/// later.
async fn render_firewall(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<RenderForm>,
) -> Response {
    let backend = FirewallBackend::from_stored(&form.backend);
    // Remembered, so a one-click "Apply everything" has an answer and an
    // operator who chose iptables is not handed an nftables script next
    // time.
    if state
        .with_db(move |db| crate::firewall::store_backend(db, backend))
        .await
        .is_err()
    {
        // Not worth failing the render over: the choice for *this* render
        // is already in hand.
    }

    // Both paths go through one function. They used to be two copies of
    // build-guard-write that differed only in the last step, which is how
    // the write-only one kept deriving its destination separately from the
    // backend it rendered for.
    match write_firewall(&state, form.apply.is_some()).await {
        Ok(note) => back_with(&state.base, "/", &note, true),
        Err(err) => back_with(&state.base, "/", &format!("{err:#}"), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_ids_round_trip() {
        for category in [Category::Scanner, Category::Search, Category::Ai] {
            assert_eq!(category_from(category_id(category)), Some(category));
        }
        assert_eq!(category_from("nonsense"), None);
    }

    #[test]
    fn policy_ids_round_trip() {
        for policy in [Policy::Blocked, Policy::Allowed] {
            assert_eq!(policy_from(policy_id(policy)), Some(policy));
        }
        assert_eq!(policy_from(""), None);
    }

    #[test]
    fn the_button_offers_the_policy_you_do_not_have() {
        assert_eq!(flip(Policy::Blocked), Policy::Allowed);
        assert_eq!(flip(Policy::Allowed), Policy::Blocked);
    }

    #[test]
    fn relative_times_round_the_way_the_tui_does() {
        let now = now_secs();
        assert_eq!(relative(now), "just now");
        assert_eq!(relative(now - 90), "1m ago");
        assert_eq!(relative(now - 3 * 3600), "3h ago");
        assert_eq!(relative(now - 50 * 3600), "2d ago");
    }

    #[test]
    fn a_fresh_install_renders_without_panicking_and_says_what_is_missing() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();

        let view = load(&db, None).unwrap();
        let rendered = body(&view, &Ctx::for_tests()).into_string();

        assert!(rendered.contains("Sites discovered"));
        assert!(
            rendered.contains("nothing to write"),
            "with no rules the firewall row must not claim the script is stale: {rendered}"
        );
        assert!(
            rendered.contains("NEED UPDATING"),
            "a never-fetched bot list is stale"
        );
    }

    #[test]
    fn every_form_on_the_page_carries_the_csrf_token() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        let view = load(&db, None).unwrap();
        let rendered = body(&view, &Ctx::new("the-token", Default::default())).into_string();

        let forms = rendered.matches("<form").count();
        let tokens = rendered.matches(r#"name="csrf" value="the-token""#).count();
        assert_eq!(
            forms, tokens,
            "{forms} form(s) but {tokens} token(s) — one would be rejected on submit"
        );
    }

    #[test]
    fn the_firewall_row_reads_differently_at_zero_rules_and_when_stale() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "192.0.2.9".into(),
            port: None,
            action: crate::db::FirewallAction::Block,
        })
        .unwrap();

        let view = load(&db, None).unwrap();
        let rendered = body(&view, &Ctx::for_tests()).into_string();
        assert!(
            rendered.contains("SCRIPT IS STALE"),
            "a rule added since the last render makes the on-disk script stale"
        );
    }
    /// The panel must show the path the *current* backend would write to.
    /// Showing `firewall.nft` beside an iptables selection is how a real
    /// host ended up with a `#!/bin/sh` script in a `.nft` file.
    #[test]
    fn the_panel_shows_the_path_the_chosen_backend_writes_to() {
        let db = Db::open_in_memory().unwrap();

        crate::firewall::store_backend(&db, FirewallBackend::Iptables).unwrap();
        let iptables = load(&db, None).unwrap();
        crate::firewall::store_backend(&db, FirewallBackend::Nftables).unwrap();
        let nftables = load(&db, None).unwrap();

        assert!(
            iptables.firewall_out.ends_with(".sh"),
            "iptables should write a shell script, not {}",
            iptables.firewall_out
        );
        assert!(
            nftables.firewall_out.ends_with(".nft"),
            "nftables should write an nft script, not {}",
            nftables.firewall_out
        );
    }

    /// An operator who passed `--firewall-out` gets that path whichever
    /// backend renders.
    #[test]
    fn an_explicit_path_is_shown_unchanged_for_either_backend() {
        let db = Db::open_in_memory().unwrap();
        let chosen = std::path::Path::new("/srv/rules.txt");

        for backend in [FirewallBackend::Iptables, FirewallBackend::Nftables] {
            crate::firewall::store_backend(&db, backend).unwrap();
            assert_eq!(
                load(&db, Some(chosen)).unwrap().firewall_out,
                "/srv/rules.txt"
            );
        }
    }
}
