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
    jobs: Vec<crate::cron::JobStatus>,
}

/// A bot list older than this reads as needing a refresh. Matches the
/// TUI's Summary panel.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

fn load(db: &Db) -> anyhow::Result<View> {
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
    let view = match state.with_db(load).await {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::new(auth.csrf.clone(), state.base.clone());
    render(Tab::Dashboard, &ctx, flash.into_flash(), body(&view, &ctx))
}

fn body(view: &View, ctx: &Ctx) -> Markup {
    html! {
        .grid-2 {
            (categories_panel(view, ctx))
            (geo_panel(view, ctx))
        }
        (detectors_panel(view, ctx))
        (feeds_panel(view, ctx))
        (summary_panel(view, ctx))
        (jobs_panel(view))
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
                        input type="text" name="out" value="/etc/stop-bots/firewall.sh" size="34";
                    }
                    label .field {
                        "Backend"
                        select name="backend" {
                            option value="nftables" { "nftables" }
                            option value="iptables" { "iptables" }
                        }
                    }
                    button .primary type="submit" { "Write script" }
                }
                p .hint {
                    "Writing is inert — the script does nothing until it is run. Applying it "
                    "is deliberately not offered here; run it yourself, or use "
                    code { "stop-bots batch --apply" }
                    " from cron."
                }
            }
        },
    )
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
    let stored = code.clone();
    match state
        .with_db(move |db| db.set_country_selected(&stored, true))
        .await
    {
        Ok(()) => back_with(&state.base, "/",
            &format!("Selected {code}. Its ranges still need downloading with `stop-bots update-country-ranges --country {code}`."),
            true,
        ),
        Err(err) => back_with(&state.base, "/", &format!("Could not select {code}: {err}"), false),
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

#[derive(Deserialize)]
struct RenderForm {
    out: String,
    backend: String,
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
    use crate::firewall::{FirewallBackend, LockoutStatus};

    let backend = match form.backend.as_str() {
        "iptables" => FirewallBackend::Iptables,
        _ => FirewallBackend::Nftables,
    };
    let out = std::path::PathBuf::from(form.out.trim());
    if out.as_os_str().is_empty() {
        return back_with(
            &state.base,
            "/",
            "Give the script a path to be written to.",
            false,
        );
    }

    let ssh_log = state.ssh_log.clone();
    let written = state
        .with_db(move |db| {
            let built = crate::firewall::build_script(db, backend)?;
            // The same guard `render-firewall` and `batch --apply` run.
            // A written script is inert, but it is written to be run
            // later, and by then nobody is watching.
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
                // A missing log is not itself a risk, and refusing here
                // would make the button useless on a host whose auth log
                // this process cannot read.
                LockoutStatus::Risks(_) | LockoutStatus::LogUnavailable => {}
            }
            crate::firewall::write_script(&out, &built.script)?;
            db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&built.rules))?;
            Ok((out, built.rules.len()))
        })
        .await;

    match written {
        Ok((path, count)) => back_with(
            &state.base,
            "/",
            &format!(
                "Wrote {count} rule(s) to {}. Run it to apply.",
                path.display()
            ),
            true,
        ),
        Err(err) => back_with(&state.base, "/", &format!("{err}"), false),
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

        let view = load(&db).unwrap();
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
        let view = load(&db).unwrap();
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

        let view = load(&db).unwrap();
        let rendered = body(&view, &Ctx::for_tests()).into_string();
        assert!(
            rendered.contains("SCRIPT IS STALE"),
            "a rule added since the last render makes the on-disk script stale"
        );
    }
}
