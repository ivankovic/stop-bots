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
//! That split is the same one the TUI documents — NGINX owns what
//! ends up in NGINX config, this owns the firewall — and it is what
//! decides which screen a given setting belongs on.

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::db::{Category, Db, GeoMode, Policy};
use crate::firewall::{FirewallBackend, ScriptState};
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
    /// Whether the humans-only mode is forcing the three above.
    humans_only: bool,
    geo_mode: GeoMode,
    selected_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    detectors: Vec<DetectorRow>,
    feeds: Vec<crate::db::ReputationSource>,
    /// Googlebot, Bingbot and GPTBot's published ranges.
    crawlers: Vec<crate::ipranges::CrawlerSource>,
    site_count: usize,
    sources_total: usize,
    sources_stale: usize,
    rule_count: usize,
    script_state: crate::firewall::ScriptState,
    auto_apply_firewall: bool,
    /// The applied script — what the boot unit loads — from `AppState`.
    /// Shown, not asked for — see [`render_firewall`] for why the console
    /// does not take a destination from the form.
    firewall_out: String,
    /// Where "Write script" writes, beside `firewall_out`.
    firewall_rendered: String,
    /// The remembered backend, so the dropdown opens on the one this host
    /// actually renders for.
    firewall_backend: FirewallBackend,
    /// Which backends this host can load a script with.
    installed: crate::firewall::Installed,
    /// Sites the console could be mounted under, for Path mode's dropdown.
    /// Empty means "no sites scanned yet", which the panel has to say
    /// rather than render an empty select.
    sites: Vec<(String, String)>,
    /// Where the console currently thinks it is reachable — the bind
    /// address, the path prefix and the host allowlist, all three of which
    /// this panel writes.
    bind: String,
    /// The prefix recorded in the database, normalised — `""` for the
    /// root, otherwise `/stop-bots`. Already carries its leading slash,
    /// which is the thing the panel used to add a second one to.
    base_path: String,
    /// The prefix this *process* is serving under. Read at start-up, so it
    /// differs from `base_path` exactly when a change has been recorded
    /// and not yet picked up — see [`web_access_panel`].
    serving_base_path: String,
    allowed_hosts: Vec<String>,
    jobs: Vec<crate::cron::JobStatus>,
}

/// A bot list older than this reads as needing a refresh. Matches the
/// TUI's Firewall script panel.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

fn load(
    db: &Db,
    firewall_out: Option<&std::path::Path>,
    serving: &crate::web::BasePath,
) -> anyhow::Result<View> {
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
    // The path the *current* backend would write to, not a fixed one:
    // showing `firewall.nft` next to an iptables selection is how the two
    // drifted apart in the first place.
    let applied = crate::firewall::output_path(firewall_out, crate::firewall::stored_backend(db)?);

    Ok(View {
        health,
        scanner: db.get_category_default(Category::Scanner)?,
        search: db.get_category_default(Category::Search)?,
        ai: db.get_category_default(Category::Ai)?,
        humans_only: db.get_humans_only()?,
        geo_mode: db.get_geo_mode()?,
        selected_countries: db.list_selected_countries()?,
        fetched_countries: db.list_fetched_countries()?,
        detectors: Detector::ALL
            .into_iter()
            .map(|detector| {
                Ok(DetectorRow {
                    detector,
                    enabled: detector.is_enabled(db)?,
                    ttl_days: detector.ttl_days(db)?,
                    new: detector.is_new_here(db)?,
                })
            })
            .collect::<anyhow::Result<_>>()?,
        feeds: db.list_reputation_sources()?,
        crawlers: crate::ipranges::crawler_sources(db)?,
        site_count: db.list_sites()?.len(),
        sources_total: sources.len(),
        sources_stale,
        rule_count: rules.len(),
        firewall_rendered: crate::firewall::rendered_path(&applied)
            .display()
            .to_string(),
        firewall_out: applied.display().to_string(),
        firewall_backend: crate::firewall::stored_backend(db)?,
        installed: crate::firewall::Installed::detect(),
        sites: db
            .list_sites()?
            .into_iter()
            .map(|site| (site.server_name, site.config_path))
            .collect(),
        bind: crate::web::resolve_bind(db, None)
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| crate::web::DEFAULT_BIND.to_string()),
        // Through `BasePath` rather than raw, so a setting written by
        // hand without a leading slash still displays as a path.
        base_path: crate::web::BasePath::from_db(db)?.as_str().to_string(),
        serving_base_path: serving.as_str().to_string(),
        allowed_hosts: crate::web::configured_hosts(db)?,
        auto_apply_firewall: db.get_auto_apply_firewall()?,
        script_state: crate::firewall::script_state(db)?,
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
    let serving = state.base.clone();
    let view = match state
        .with_db(move |db| load(db, firewall_out.as_deref(), &serving))
        .await
    {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Dashboard,
        &ctx,
        flash.into_flash(&state),
        body(&view, &ctx),
    )
}

fn body(view: &View, ctx: &Ctx) -> Markup {
    // Two columns that stack independently, not a grid: a grid aligns
    // its rows, so a three-row panel beside a nine-row one left a hole
    // the height of the difference. The left column is what the
    // operator decides (policy, geo, feeds, the script); the right is
    // what the host does on its own (detectors, cron) and how it is.
    html! {
        .cols {
            .col {
                (categories_panel(view, ctx))
                (geo_panel(view, ctx))
                (feeds_panel(view, ctx))
                (crawlers_panel(view, ctx))
                (firewall_panel(view, ctx))
                (web_access_panel(view, ctx))
            }
            .col {
                (detectors_panel(view, ctx))
                (jobs_panel(view))
                (health_panel(view))
            }
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

    // The header's chips already say which checks passed; this panel is
    // for the ones that did not, with what to do about them. A check that
    // could not run is kept too — "needs root" is worth a line.
    let attention = report.at_least(health::Level::Unknown);
    layout::panel(
        "System status",
        Some(&format!(
            "{} \u{2014} checked {}",
            report.headline(),
            crate::present::ago(*taken_at)
        )),
        html! {
            @if attention.is_empty() {
                .panel-body {
                    p .hint { "Every check passed. Nothing to do here." }
                }
            } @else {
            table {
                tbody {
                    @for check in attention {
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

// ---- system-wide category defaults ----

fn categories_panel(view: &View, ctx: &Ctx) -> Markup {
    let rows = [
        (Category::Scanner, view.scanner),
        (Category::Search, view.search),
        (Category::Ai, view.ai),
    ];
    layout::panel(
        "Policy",
        Some("What each category of known bot gets by default"),
        html! {
            .panel-body {
                .row {
                    (layout::pill(
                        if view.humans_only { "HUMANS ONLY" } else { "HUMANS ONLY: OFF" },
                        if view.humans_only { PillKind::Blocked } else { PillKind::Neutral },
                    ))
                    form .inline method="post" action=(ctx.url("/humans-only")) {
                        (layout::csrf_field(ctx))
                        input type="hidden" name="enabled" value=(if view.humans_only { "false" } else { "true" });
                        button .danger[!view.humans_only] type="submit" {
                            @if view.humans_only { "Turn off" } @else { "Turn on" }
                        }
                    }
                }
                @if view.humans_only {
                    p .hint {
                        "Every catalogued bot is blocked, whatever its category — and fetching "
                        code { "/robots.txt" }
                        " earns a one-day block for that address. Let's Encrypt is the one "
                        "exception, because blocking it breaks certificate renewal."
                    }
                }
            }
            table {
                tbody {
                    @for (category, policy) in rows {
                        tr {
                            td { (crate::present::category_label(category)) }
                            td { (policy_pill(policy)) }
                            td .right {
                                @if view.humans_only {
                                    // No form at all rather than a disabled
                                    // one: the POST is refused server-side
                                    // too, and a button that looks pressable
                                    // and is not is worse than none.
                                    span .hint { "forced by Humans only" }
                                } @else {
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
            }

            // What the policy is applied to and drawn from, in one line:
            // the two facts that used to be a Summary panel of their own.
            .panel-body {
                p .hint {
                    "Sites discovered: " span .mono { (view.site_count) }
                    " \u{00b7} Bot list sources: " span .mono { (view.sources_total) } " "
                    @if view.sources_stale == 0 && view.sources_total > 0 {
                        (layout::pill("UP TO DATE", PillKind::Allowed))
                    } @else if view.sources_total == 0 {
                        "none registered"
                    } @else {
                        (layout::pill(&format!("{} NEED UPDATING", view.sources_stale), PillKind::Warn))
                    }
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
                    input type="text" name="country" placeholder="CN" aria-label="Country code"
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

/// One row of the Automatic blocking panel.
struct DetectorRow {
    detector: Detector,
    enabled: bool,
    ttl_days: i64,
    /// Added since this database was created and not yet switched either
    /// way: off, and marked so the operator learns it exists. See
    /// `Detector::is_new_here`.
    new: bool,
}

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
                    @for DetectorRow { detector, enabled, ttl_days, new } in &view.detectors {
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
                                @if *new {
                                    " "
                                    span title="Added by an upgrade. Off until you turn it on" {
                                        (layout::pill("NEW", PillKind::Warn))
                                    }
                                }
                            }
                            td .num { (ttl_days) "d" }
                            td {
                                form .row.tight method="post" action=(ctx.url("/detector-ttl")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="detector" value=(detector.id());
                                    input .short type="number" name="days" min="1" max=(crate::protection::MAX_TTL_DAYS)
                                        value=(ttl_days) size="4";
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

// ---- crawler ranges ----

fn category_policy(view: &View, category: Category) -> Policy {
    match category {
        Category::Scanner => view.scanner,
        Category::Search => view.search,
        Category::Ai => view.ai,
    }
}

/// The three crawlers that publish their addresses. Not switches like the
/// feeds above: a crawler's ranges are blocked exactly when its category
/// is, and they are what tells a real Googlebot from a forged one either
/// way — so the column says which way its category points, and the one
/// action is a download.
fn crawlers_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Crawler IP ranges",
        Some("Blocked with the crawler's category; also how a forged crawler is told apart"),
        html! {
            table {
                thead { tr {
                    th { "Crawler" }
                    th { "Category" }
                    th .right { "Ranges" }
                    th { "Last fetched" }
                    th .right { "Action" }
                } }
                tbody {
                    @for source in &view.crawlers {
                        tr {
                            td { (source.short_name()) }
                            td {
                                (policy_pill(category_policy(view, source.kind.category())))
                                " "
                                span .hint { (crate::present::category_label(source.kind.category())) }
                            }
                            td .num { (source.range_count) }
                            td {
                                @match source.last_fetched_at {
                                    Some(at) => { (crate::present::ago(at)) }
                                    None => { (layout::pill("NEVER", PillKind::Warn)) }
                                }
                            }
                            td .right {
                                form .inline method="post" action=(ctx.url("/crawler-ranges")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="source" value=(source.kind.id());
                                    button type="submit" { "Refresh" }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

// ---- the firewall script ----

/// The one artifact the Dashboard exists to produce: how many rules it
/// holds, whether the copy on disk still matches, and the form that
/// writes it.
fn firewall_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Firewall script",
        Some(&format!(
            "{} \u{2192} {}",
            view.firewall_backend.stored(),
            view.firewall_out
        )),
        html! {
            table {
                tbody {
                    tr {
                        td { "Firewall rules" }
                        td .num { (view.rule_count) }
                        td {
                            @if view.rule_count == 0 {
                                span .hint { "nothing to write" }
                            } @else {
                                @match view.script_state {
                                    ScriptState::Applied => {
                                        (layout::pill("APPLIED", PillKind::Allowed))
                                    }
                                    ScriptState::RenderedNotApplied => {
                                        (layout::pill("RENDERED, NOT APPLIED", PillKind::Warn))
                                    }
                                    ScriptState::Changed => {
                                        (layout::pill("CHANGED, NOT APPLIED", PillKind::Warn))
                                    }
                                }
                            }
                        }
                    }
                    tr {
                        td {
                            "Auto-apply"
                            br;
                            span .hint {
                                "Lets the daily render run the script too. It refuses unless \
                                 the anti-lockout check actually ran \u{2014} which needs a \
                                 readable SSH log."
                            }
                        }
                        td {}
                        td {
                            .row {
                                @if view.auto_apply_firewall {
                                    (layout::pill("ON", PillKind::Allowed))
                                } @else {
                                    (layout::pill("OFF", PillKind::Neutral))
                                }
                                form .inline method="post"
                                    action=(ctx.url("/auto-apply-firewall")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="enabled"
                                        value=(if view.auto_apply_firewall { "0" } else { "1" });
                                    button type="submit" {
                                        @if view.auto_apply_firewall { "Turn off" } @else { "Turn on" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .panel-body {
                form .row method="post" action=(ctx.url("/render-firewall")) {
                    (layout::csrf_field(ctx))
                    label .field {
                        "Backend"
                        select name="backend" {
                            @for backend in [FirewallBackend::Nftables, FirewallBackend::Iptables] {
                                option value=(backend.stored())
                                    selected[backend == view.firewall_backend] {
                                    (view.installed.describe(backend))
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
                    "Writes " code { (view.firewall_rendered) } ", which is inert: nothing runs "
                    "it, and a reboot loads " code { (view.firewall_out) } ", the last script "
                    "applied. Ticking \u{201c}run it after writing\u{201d} enforces it now and "
                    "makes it the one loaded at boot, after the same anti-lockout check "
                    code { "stop-bots batch --apply" }
                    " runs: rules that would block a currently-connected SSH client are "
                    "refused, and so is running it when no SSH log could be read."
                }
                p .hint {
                    "nftables is recommended: addresses go in sets, and a timed block is "
                    "removed by the kernel when it expires. iptables loads IPv4 and IPv6 "
                    "(through ip6tables) one rule per address, keeps a timed block until the "
                    "script is run again, and cannot do allowlist geo mode."
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
                            @if view.base_path.is_empty() { "/" } @else { (view.base_path) }
                        }
                    }
                    // The prefix is read once, when the router is built,
                    // so recording a new one leaves this process still
                    // answering on the old one. Without this row that is
                    // invisible: the panel shows the new prefix, the
                    // console serves the old one, and every link is a 404
                    // with nothing to explain it.
                    @if view.base_path != view.serving_base_path {
                        tr {
                            td { "Restart needed" }
                            td {
                                (layout::pill("PENDING", PillKind::Warn))
                                " "
                                span .hint {
                                    "this console is still serving "
                                    code {
                                        @if view.serving_base_path.is_empty() {
                                            "/"
                                        } @else {
                                            (view.serving_base_path) "/"
                                        }
                                    }
                                    ". The prefix is read once, when the server starts. Run "
                                    code { "systemctl restart stop-bots-web.service" }
                                    " (or restart it however you started it) to pick up the new one."
                                }
                            }
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
                // Said where the choice is made. Path mode stays the
                // default for the certificate, but a script running in
                // any other app on that site is same-origin with this
                // console and can read its CSRF token.
                p .hint {
                    "Path mode also shares the site\u{2019}s origin: a flaw in any other app on "
                    "that site can drive this console as you. Use it only on a site that runs "
                    "nothing you do not fully trust; otherwise use a subdomain."
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
                &state,
                "/",
                &format!(
                    "Wrote {} and recorded the host. NGINX {note}. Restart the console for a \
                     changed path prefix to take effect.",
                    path.display()
                ),
                true,
            )
        }
        Err(err) => back_with(&state, "/", &format!("{err:#}"), false),
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
                    th .nowrap { "Last run" }
                    th { "Result" }
                    th { "" }
                } }
                tbody {
                    @for status in &view.jobs {
                        tr {
                            td { (status.job.label()) }
                            td .mono.nowrap {
                                @match status.last_run {
                                    Some(at) => { (crate::present::ago(at)) }
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

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/category"), post(set_category))
        .route(&base.url("/humans-only"), post(set_humans_only))
        .route(&base.url("/geo-mode"), post(set_geo_mode))
        .route(&base.url("/geo-add"), post(add_country))
        .route(&base.url("/geo-remove"), post(remove_country))
        .route(&base.url("/detector"), post(set_detector))
        .route(&base.url("/detector-ttl"), post(set_detector_ttl))
        .route(&base.url("/feed"), post(set_feed))
        .route(&base.url("/crawler-ranges"), post(update_crawler_ranges))
        .route(&base.url("/render-firewall"), post(render_firewall))
        .route(
            &base.url("/auto-apply-firewall"),
            post(set_auto_apply_firewall),
        )
        .route(&base.url("/update-all"), post(update_all))
        .route(
            &base.url("/apply-all"),
            axum::routing::get(confirm_apply_all).post(apply_all),
        )
        .route(&base.url("/web-access"), post(set_web_access))
}

#[derive(Deserialize)]
struct CategoryForm {
    category: String,
    policy: String,
}

#[derive(serde::Deserialize)]
struct HumansOnlyForm {
    enabled: String,
}

/// Turns the humans-only mode on or off.
///
/// Writes one setting and nothing else. The three category policies it
/// forces are left exactly as the operator had them, so turning this off
/// restores their choices rather than leaving three blocked categories
/// behind and no record of what they were.
async fn set_humans_only(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<HumansOnlyForm>,
) -> Response {
    let on = form.enabled == "true";
    match state.with_db(move |db| db.set_humans_only(on)).await {
        Ok(()) => back_with(
            &state,
            "/",
            if on {
                "Humans only is on: every catalogued bot is blocked except Let's Encrypt, and fetching /robots.txt now earns a one-day block. Apply on the NGINX screen to write it into the site configs."
            } else {
                "Humans only is off. The category policies you had before are back in force."
            },
            true,
        ),
        Err(err) => back_with(&state, "/", &err.to_string(), false),
    }
}

async fn set_category(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<CategoryForm>,
) -> Response {
    let (Some(category), Some(policy)) = (category_from(&form.category), policy_from(&form.policy))
    else {
        return back_with(
            &state,
            "/",
            "That is not a category this tool knows.",
            false,
        );
    };

    // Refused here as well as hidden in the markup. The button is gone
    // while the mode is on, but a form post is not a button — and a
    // setting written here would be read back by nothing, leaving the
    // operator with a screen that says Allowed and a config that blocks.
    match state
        .with_db(move |db| {
            if db.get_humans_only()? {
                anyhow::bail!(
                    "Humans only is on, so every category is blocked. Turn it off to set categories individually."
                );
            }
            db.set_category_default(category, policy)
        })
        .await
    {
        Ok(()) => back_with(
            &state,
            "/",
            &format!(
                "{} are now {}. Apply on the NGINX screen to write it into the site configs.",
                crate::present::category_label(category),
                policy_id(policy)
            ),
            true,
        ),
        Err(err) => back_with(
            &state,
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
        _ => return back_with(&state, "/", "Unknown geo mode.", false),
    };
    match state.with_db(move |db| db.set_geo_mode(mode)).await {
        Ok(()) => back_with(&state, "/", "Geo mode changed.", true),
        Err(err) => back_with(
            &state,
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
            &state,
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
    // network access — a handler that downloads on POST made
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
            &state,
            "/",
            &format!(
                "Selected {code}. Press \u{201c}Update everything\u{201d} to download its \
                 ranges, then \u{201c}Apply everything\u{201d} to enforce them."
            ),
            true,
        ),
        Err(err) => back_with(
            &state,
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
        Ok(()) => back_with(&state, "/", &format!("Removed {code}."), true),
        Err(err) => back_with(
            &state,
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
        return back_with(&state, "/", "Unknown detector.", false);
    };
    let enabled = form.enabled == "1";
    match state
        .with_db(move |db| detector.set_enabled(db, enabled))
        .await
    {
        Ok(()) => back_with(
            &state,
            "/",
            &format!(
                "{} is now {}.",
                detector.spec().label,
                if enabled { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(&state, "/", &format!("Could not change that: {err}"), false),
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
        return back_with(&state, "/", "Unknown detector.", false);
    };
    if form.days < 1 {
        return back_with(&state, "/", "A block has to last at least a day.", false);
    }
    if form.days > crate::protection::MAX_TTL_DAYS {
        return back_with(
            &state,
            "/",
            &format!(
                "A block can last at most {} days.",
                crate::protection::MAX_TTL_DAYS
            ),
            false,
        );
    }
    let days = form.days;
    match state
        .with_db(move |db| detector.set_ttl_days(db, days))
        .await
    {
        Ok(()) => back_with(
            &state,
            "/",
            &format!("{} now blocks for {days} day(s).", detector.spec().label),
            true,
        ),
        Err(err) => back_with(&state, "/", &format!("Could not change that: {err}"), false),
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
            &state,
            "/",
            &format!("{id} is now {}.", if enabled { "on" } else { "off" }),
            true,
        ),
        Err(err) => back_with(&state, "/", &format!("Could not change {id}: {err}"), false),
    }
}

/// Downloads every list this host uses — the console's half of what
/// `stop-bots batch` does, through the same `refresh::plan`, and the same
/// run as the console's weekly job (see [`crate::web::cron::update_everything`]).
///
/// On a task of its own: a browser that gives up waiting drops this
/// handler, and a download dropped half-way would leave the lease held
/// until it expires and the run unrecorded.
async fn update_all(State(state): State<AppState>, _auth: Auth) -> Response {
    use crate::web::cron::UpdateRun;
    let task = state.clone();
    let run = tokio::spawn(async move {
        crate::web::cron::update_everything(&task, "from the console").await
    })
    .await;
    match run {
        Ok(Ok(UpdateRun::Done { summary, all_ok })) => back_with(&state, "/", &summary, all_ok),
        Ok(Ok(UpdateRun::Busy { since })) => back_with(
            &state,
            "/",
            &crate::refresh::Claim::busy_message(since),
            false,
        ),
        Ok(Err(err)) => back_with(&state, "/", &format!("{err:#}"), false),
        Err(err) => back_with(
            &state,
            "/",
            &format!("The download stopped unexpectedly: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct CrawlerForm {
    source: String,
}

/// Downloads one crawler's published ranges — the console's
/// `update-ip-ranges`. Under the download lease like "Update everything",
/// and on a task of its own for the same reason.
async fn update_crawler_ranges(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<CrawlerForm>,
) -> Response {
    use crate::web::cron::OneRun;
    let Some(kind) = crate::ipranges::IpRangeSourceKind::from_id(&form.source) else {
        return back_with(
            &state,
            "/",
            &format!("Unknown crawler: {}", form.source),
            false,
        );
    };
    let task = state.clone();
    let run = tokio::spawn(async move {
        crate::web::cron::update_one(&task, crate::refresh::Source::CrawlerRanges(kind)).await
    })
    .await;
    match run {
        Ok(Ok(OneRun::Done(Ok(summary)))) => {
            back_with(&state, "/", &format!("{}: {summary}.", kind.name()), true)
        }
        Ok(Ok(OneRun::Done(Err(err)))) => {
            back_with(&state, "/", &format!("{}: {err}", kind.name()), false)
        }
        Ok(Ok(OneRun::Busy { since })) => back_with(
            &state,
            "/",
            &crate::refresh::Claim::busy_message(since),
            false,
        ),
        Ok(Err(err)) => back_with(&state, "/", &format!("{err:#}"), false),
        Err(err) => back_with(
            &state,
            "/",
            &format!("The download stopped unexpectedly: {err}"),
            false,
        ),
    }
}

/// Lines of diff the confirm page shows before it stops and says where the
/// rest is. A first apply on a host with reputation feeds is a 44,000-line
/// script; a page that size helps nobody review anything.
const DIFF_LINES_SHOWN: usize = 4_000;

#[derive(Deserialize)]
struct ConfirmQuery {
    diff: Option<String>,
}

/// "Apply everything"'s confirm page: what would change, and the button
/// that does it. A page of its own rather than a JavaScript `confirm()`,
/// so it works without script and can carry the summary and the diff.
///
/// A `GET`, and it changes nothing: the NGINX half reads files through the
/// functions the apply uses, and the firewall half is a dry run of the same
/// [`crate::firewall::FirewallRun`] the apply makes — guard included,
/// reading the SSH log outside the database lock.
async fn confirm_apply_all(
    State(state): State<AppState>,
    auth: Auth,
    Query(query): Query<ConfirmQuery>,
) -> Response {
    let root = state.nginx_root.clone();
    let out_override = state.firewall_out.clone();
    let for_real = state.apply_for_real;
    let ssh_log = state.ssh_log.clone();
    let read = state
        .with_db(move |db| {
            let nginx =
                crate::nginx::preview_all_sites(db, &root).map_err(|err| format!("{err:#}"));
            let backend = crate::firewall::stored_backend(db)?;
            let run = crate::firewall::FirewallRun::new(
                backend,
                crate::firewall::output_path(out_override.as_deref(), backend),
            )
            .apply(true)
            .for_real(for_real)
            .dry_run(true);
            let source = crate::logpaths::LogPaths::from_db(db)
                .unwrap_or_default()
                .ssh(ssh_log.as_deref());
            anyhow::Ok((
                nginx,
                crate::firewall::prepare(db, run).map_err(|err| format!("{err:#}")),
                source,
            ))
        })
        .await;
    let (nginx, prepared, source) = match read {
        Ok(read) => read,
        Err(err) => return internal_error(&err.to_string()),
    };
    let firewall = match prepared {
        Ok(prepared) => tokio::task::spawn_blocking(move || {
            crate::firewall::execute(prepared, crate::firewall::SshLog::Read(&source))
        })
        .await
        .map_err(|err| format!("the preview thread panicked: {err}")),
        Err(err) => Err(err),
    };
    let preview = crate::preview::ApplyPreview { nginx, firewall };

    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    let show_diff = query.diff.is_some();
    render(
        Tab::Dashboard,
        &ctx,
        None,
        confirm_body(&preview, show_diff, &ctx),
    )
}

fn confirm_body(preview: &crate::preview::ApplyPreview, show_diff: bool, ctx: &Ctx) -> Markup {
    let diff = if show_diff {
        let full = preview.diff();
        let total = full.lines().count();
        let mut shown: String = full
            .lines()
            .take(DIFF_LINES_SHOWN)
            .flat_map(|line| [line, "\n"])
            .collect();
        if total > DIFF_LINES_SHOWN {
            shown.push_str(&format!(
                "\u{2026} {} more line(s). `stop-bots batch --dry-run --diff` prints all of it.\n",
                total - DIFF_LINES_SHOWN
            ));
        }
        Some(shown)
    } else {
        None
    };
    layout::panel(
        "Apply everything?",
        Some("Nothing has changed yet"),
        html! {
            .panel-body {
                p {
                    "This writes the NGINX config for every site and reloads NGINX, then \
                     writes the firewall script and runs it as root. The two are independent: \
                     whichever fails, the other still gets its turn."
                }
                pre .preview { (preview.lines().join("\n")) }
                .row {
                    form .inline method="post" action=(ctx.url("/apply-all")) {
                        (layout::csrf_field(ctx))
                        button .primary type="submit" { "Apply everything" }
                    }
                    @if show_diff {
                        a href=(ctx.url("/apply-all")) { "Hide the diff" }
                    } @else {
                        a href=(ctx.url("/apply-all?diff=1")) { "Show the diff" }
                    }
                    a href=(ctx.url("/")) { "Cancel" }
                }
                @if let Some(diff) = diff {
                    @if diff.is_empty() {
                        p .hint { "Nothing would change." }
                    } @else {
                        pre .diff { (diff) }
                    }
                }
            }
        },
    )
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
    let for_real = state.apply_for_real;
    match state
        .with_db(move |db| {
            let commands = for_real
                .then(|| crate::nginx::NginxCommands::from_db(db))
                .transpose()?;
            crate::nginx::apply_all_sites_and_reload(db, &root, commands.as_ref())
        })
        .await
    {
        Ok(outcome) => {
            parts.push(format!("NGINX: {} file(s) changed", outcome.changed));
            if outcome.reloaded {
                parts.push("reloaded".to_string());
            } else if outcome.changed > 0 {
                parts.push("not reloaded (--no-apply)".to_string());
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

    back_with(&state, "/", &parts.join(". "), ok)
}

/// Renders the firewall script, writes it, and runs it.
///
/// The console refusing to *apply* the script used to be one of its three
/// deliberate omissions. That was reversed on request, and what makes it
/// defensible is that it goes through [`crate::firewall`]'s one path, with
/// the policy every front-end shares (see `FirewallRun`): a connected SSH
/// client the rules would block refuses the write and the apply, and a
/// guard that *could not run* refuses the apply. `apply_for_real` gates
/// the run itself, so `stop-bots web --no-apply` keeps the write-only
/// behaviour.
///
/// The lockout guard covers SSH, not this console: the console's own
/// address is protected separately by the "refusing to block the address
/// you are connected from" check on the block handlers, which is what
/// keeps a blocked rule from reaching the table in the first place.
async fn write_and_apply_firewall(state: &AppState) -> anyhow::Result<String> {
    write_firewall(state, true).await
}

/// Renders and writes the script, and runs it when `apply` is set.
///
/// Three hops rather than one: the database half under the lock, the guard,
/// write and `nft -f` outside it (a subprocess, and on a big ruleset a slow
/// one), and the signatures back under it.
async fn write_firewall(state: &AppState, apply: bool) -> anyhow::Result<String> {
    let out_override = state.firewall_out.clone();
    let for_real = state.apply_for_real;
    let ssh_log = state.ssh_log.clone();
    let (prepared, source) = state
        .with_db(move |db| {
            let backend = crate::firewall::stored_backend(db)?;
            // Derived from the backend inside the same closure that chose
            // it, so the two cannot disagree — an iptables script in a
            // `.nft` file is what happens when they are decided apart.
            let applied = crate::firewall::output_path(out_override.as_deref(), backend);
            let run = crate::firewall::FirewallRun::new(backend, applied)
                .apply(apply)
                .for_real(for_real);
            // Where the SSH log is, as `LogPaths` resolves it: the console's
            // `--ssh-log` first, then the stored path, then a search.
            let source = crate::logpaths::LogPaths::from_db(db)
                .unwrap_or_default()
                .ssh(ssh_log.as_deref());
            anyhow::Ok((crate::firewall::prepare(db, run)?, source))
        })
        .await?;

    let outcome = tokio::task::spawn_blocking(move || {
        crate::firewall::execute(prepared, crate::firewall::SshLog::Read(&source))
    })
    .await
    .map_err(|err| anyhow::anyhow!("the firewall thread panicked: {err}"))?;

    let recorded = outcome.clone();
    state
        .with_db(move |db| crate::firewall::record(db, &recorded))
        .await?;

    let summary = capitalised(&outcome.summary());
    if outcome.succeeded() {
        Ok(summary)
    } else {
        Err(anyhow::anyhow!("{summary}"))
    }
}

/// `text` with its first letter upper-cased, for a flash made of a
/// sentence written to be embedded in others.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
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

/// Turns automatic applying of the firewall script on or off.
///
/// The confirmation names the refusal this switch makes, because it is the
/// one that will most often stop it doing anything: a host whose SSH log
/// the cron cannot read renders daily and applies never, and without being
/// told so here the only sign is a summary line on the Scheduled tasks
/// panel a day later.
async fn set_auto_apply_firewall(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<AutoApplyForm>,
) -> Response {
    let on = form.enabled == "1";
    match state
        .with_db(move |db| db.set_auto_apply_firewall(on))
        .await
    {
        Ok(()) => back_with(
            &state,
            "/",
            if on {
                "Auto-apply on for the firewall. The daily render will run the script too \
                 \u{2014} unless the anti-lockout check cannot run, which needs a readable SSH \
                 log, in which case it writes and refuses."
            } else {
                "Auto-apply off for the firewall. The daily render writes the script and \
                 leaves running it to you."
            },
            true,
        ),
        Err(err) => back_with(&state, "/", &format!("Could not save that: {err}"), false),
    }
}

#[derive(Deserialize)]
struct AutoApplyForm {
    enabled: String,
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
        Ok(note) => back_with(&state, "/", &note, true),
        Err(err) => back_with(&state, "/", &format!("{err:#}"), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state whose SSH log is `ssh_log` and whose script goes into `dir`.
    fn firewall_state(dir: &std::path::Path, ssh_log: std::path::PathBuf) -> AppState {
        let db = Db::open_in_memory().unwrap();
        db.block_address_permanently("192.0.2.10", crate::db::RuleSource::Tui, None)
            .unwrap();
        let mut state = AppState::new(db, dir.join("nginx"), Some(ssh_log), false);
        state.firewall_out = Some(dir.join("firewall.nft"));
        state
    }

    /// The TUI, `batch --apply` and the internal cron all refuse to *run*
    /// the script when the lockout check could not run. The console used
    /// to take an unreadable log as a pass and run it anyway.
    #[tokio::test]
    async fn applying_is_refused_when_the_ssh_log_cannot_be_read() {
        let tmp = tempfile::tempdir().unwrap();
        let state = firewall_state(tmp.path(), tmp.path().join("no-such-auth.log"));

        let err = format!("{:#}", write_firewall(&state, true).await.unwrap_err());

        assert!(err.contains("SSH log"), "error was: {err}");
        assert!(err.contains("not applied"), "error was: {err}");
        assert!(
            tmp.path().join("firewall.next.nft").exists(),
            "writing is inert, so it still happens; only running it is refused"
        );
        assert!(
            !tmp.path().join("firewall.nft").exists(),
            "and the script the boot unit loads is left alone"
        );
    }

    #[tokio::test]
    async fn writing_alone_goes_ahead_when_the_ssh_log_cannot_be_read() {
        let tmp = tempfile::tempdir().unwrap();
        let state = firewall_state(tmp.path(), tmp.path().join("no-such-auth.log"));

        let note = write_firewall(&state, false).await.unwrap();
        assert!(note.contains("Wrote"), "note was: {note}");
    }

    #[tokio::test]
    async fn applying_goes_ahead_when_the_ssh_log_was_read() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("auth.log");
        std::fs::write(&log, "").unwrap();
        let state = firewall_state(tmp.path(), log);

        // `--no-apply` in tests, so this is as far as it can get: past the
        // guard, and stopped by the switch rather than by the refusal.
        let note = write_firewall(&state, true).await.unwrap();
        assert!(note.contains("--no-apply"), "note was: {note}");
    }

    /// Path mode is the default for good reasons, but it puts this console
    /// on the same origin as everything else on that site. The choice is
    /// made on this panel, so the trade has to be stated here.
    #[test]
    fn the_web_access_panel_says_path_mode_shares_the_site_s_origin() {
        let db = Db::open_in_memory().unwrap();
        let view = load(&db, None, &crate::web::BasePath::default()).unwrap();
        let rendered = web_access_panel(&view, &Ctx::for_tests()).into_string();

        assert!(
            rendered.contains("shares the site\u{2019}s origin"),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("use a subdomain"),
            "rendered was:\n{rendered}"
        );
    }

    /// The web twin of the TUI's "new" mark: a detector an upgrade added
    /// shows OFF and NEW until the operator switches it either way.
    #[test]
    fn a_detector_added_since_the_database_was_created_shows_off_and_new() {
        let db = Db::open_in_memory().unwrap();
        let panel = |db: &Db| {
            let view = load(db, None, &crate::web::BasePath::default()).unwrap();
            detectors_panel(&view, &Ctx::for_tests()).into_string()
        };
        assert!(
            !panel(&db).contains(">NEW<"),
            "nothing is new on a new database"
        );

        // Older than every detector, so each one is new here.
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 0)
            .unwrap();
        let rendered = panel(&db);
        assert!(!rendered.contains(">ON<"), "rendered was:\n{rendered}");
        let operator_controlled = Detector::ALL
            .iter()
            .filter(|d| d.is_operator_controlled())
            .count();
        assert_eq!(
            rendered.matches(">NEW<").count(),
            operator_controlled,
            "rendered was:\n{rendered}"
        );

        for d in Detector::ALL {
            d.set_enabled(&db, false).unwrap();
        }
        assert!(!panel(&db).contains(">NEW<"), "every one has been chosen");
    }

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
    fn a_fresh_install_renders_without_panicking_and_says_what_is_missing() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();

        let view = load(&db, None, &crate::web::BasePath::default()).unwrap();
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
        let view = load(&db, None, &crate::web::BasePath::default()).unwrap();
        let rendered = body(&view, &Ctx::new("the-token", Default::default())).into_string();

        let forms = rendered.matches("<form").count();
        let tokens = rendered.matches(r#"name="csrf" value="the-token""#).count();
        assert_eq!(
            forms, tokens,
            "{forms} form(s) but {tokens} token(s) — one would be rejected on submit"
        );
    }

    /// Three states, and the one that matters is the middle one: a script
    /// the cron rendered on its own is on disk and inert, and saying "up to
    /// date" about it is how an operator comes to believe it is enforced.
    #[test]
    fn the_firewall_row_says_whether_the_rules_were_applied_or_only_rendered() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "192.0.2.9".into(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        let signature = crate::firewall::rules_signature(&crate::firewall::all_rules(&db).unwrap());
        let row = |db: &Db| {
            let view = load(db, None, &crate::web::BasePath::default()).unwrap();
            firewall_panel(&view, &Ctx::for_tests()).into_string()
        };

        for (what, record, expected) in [
            ("changed since any render", None, "CHANGED, NOT APPLIED"),
            ("rendered only", Some(false), "RENDERED, NOT APPLIED"),
            ("applied", Some(true), "APPLIED"),
        ] {
            if let Some(applied) = record {
                db.set_firewall_rendered_signature(&signature).unwrap();
                if applied {
                    db.set_firewall_applied_signature(&signature).unwrap();
                }
            }
            let rendered = row(&db);
            assert!(
                rendered.contains(expected),
                "{what}: the panel was\n{rendered}"
            );
        }
    }
    /// The panel must show the path the *current* backend would write to.
    /// Showing `firewall.nft` beside an iptables selection is how a real
    /// host ended up with a `#!/bin/sh` script in a `.nft` file.
    #[test]
    fn the_panel_shows_the_path_the_chosen_backend_writes_to() {
        let db = Db::open_in_memory().unwrap();

        crate::firewall::store_backend(&db, FirewallBackend::Iptables).unwrap();
        let iptables = load(&db, None, &crate::web::BasePath::default()).unwrap();
        crate::firewall::store_backend(&db, FirewallBackend::Nftables).unwrap();
        let nftables = load(&db, None, &crate::web::BasePath::default()).unwrap();

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
                load(&db, Some(chosen), &crate::web::BasePath::default())
                    .unwrap()
                    .firewall_out,
                "/srv/rules.txt"
            );
        }
    }
}
