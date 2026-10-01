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

//! NGINX: everything that ends up in **NGINX config**.
//!
//! The counterpart to the Dashboard, which owns the firewall script. A
//! setting belongs here if applying it rewrites a `server { ... }` block.
//!
//! Unlike the TUI, the status check runs inline. It reads and re-parses
//! every site's config file — files this console's user may not be able
//! to read — so it is the console's privileged operation (see
//! [`crate::privileged`]), like scanning and applying.

use std::path::{Path, PathBuf};

use axum::extract::{Path as UrlPath, Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::db::{BlockResponse, Bot, Category, Db, Policy, Site};
use crate::nginx::{RequestRule, SiteApplyStatus};
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{back_with, internal_error, render, Auth, FlashQuery};
use crate::web::state::AppState;

// ---- list ----

struct View {
    block_response: BlockResponse,
    serve_robots: bool,
    auto_apply: bool,
    rate_limit: bool,
    rate_rps: i64,
    rate_burst: i64,
    /// Each site, and its status: `None` when it could not be found out.
    sites: Vec<(Site, Option<SiteApplyStatus>)>,
    /// Why no status could be found out, if none could.
    status_problem: Option<String>,
    root: PathBuf,
}

/// The page, with each site's status worked out here.
#[cfg(test)]
fn load(db: &Db, root: &Path) -> anyhow::Result<View> {
    let statuses = crate::nginx::site_statuses(db, root)?;
    load_with(db, root, Ok(statuses))
}

/// The page, with the statuses the console's privileged operation gave.
fn load_with(
    db: &Db,
    root: &Path,
    statuses: Result<Vec<(i64, SiteApplyStatus)>, String>,
) -> anyhow::Result<View> {
    let (statuses, status_problem) = match statuses {
        Ok(statuses) => (statuses, None),
        Err(problem) => (Vec::new(), Some(problem)),
    };
    let with_status = db
        .list_sites()?
        .into_iter()
        .map(|site| {
            let status = status_of(&statuses, site.id);
            (site, status)
        })
        .collect();

    Ok(View {
        block_response: db.get_block_response()?,
        serve_robots: db.get_serve_robots_txt()?,
        auto_apply: db.get_auto_apply()?,
        rate_limit: db.get_rate_limit_enabled()?,
        rate_rps: db.get_rate_limit_rps()?,
        rate_burst: db.get_rate_limit_burst()?,
        sites: with_status,
        status_problem,
        root: root.to_path_buf(),
    })
}

fn status_of(statuses: &[(i64, SiteApplyStatus)], id: i64) -> Option<SiteApplyStatus> {
    statuses
        .iter()
        .find(|(site, _)| *site == id)
        .map(|(_, status)| *status)
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(flash): Query<FlashQuery>,
) -> Response {
    let root = state.nginx_root.clone();
    let statuses = state
        .privileged()
        .site_statuses()
        .await
        .map_err(|err| format!("{err:#}"));
    let view = match state
        .with_db(move |db| load_with(db, &root, statuses))
        .await
    {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Nginx,
        &ctx,
        flash.into_flash(&state),
        body(&view, &ctx),
    )
}

fn body(view: &View, ctx: &Ctx) -> Markup {
    html! {
        .cols {
            (nginx_settings_panel(view, ctx))
            (sites_panel(view, ctx))
        }
    }
}

/// Every block response, in the order the CLI documents them.
const RESPONSES: [(BlockResponse, &str); 7] = [
    (
        BlockResponse::Forbidden,
        "403 Forbidden — says no, and says why",
    ),
    (BlockResponse::NotFound, "404 Not Found — reveals nothing"),
    (
        BlockResponse::Gone,
        "410 Gone — asks crawlers to stop returning",
    ),
    (
        BlockResponse::Teapot,
        "418 Teapot — a joke code, unregistered",
    ),
    (
        BlockResponse::TooManyRequests,
        "429 Too Many Requests — invites a retry",
    ),
    (BlockResponse::Close, "444 — closes without answering"),
    (
        BlockResponse::Tarpit,
        "Tarpit — answers 403 at one byte a second",
    ),
];

fn nginx_settings_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "NGINX settings",
        Some("Host-wide, and applied to every site on the next Apply"),
        html! {
            table {
                tbody {
                    tr {
                        td { "Blocked requests get" }
                        td {
                            form .row method="post" action=(ctx.url("/nginx/block-response")) style="gap:8px" {
                                (layout::csrf_field(ctx))
                                select name="response" {
                                    @for (response, label) in RESPONSES {
                                        @if response == view.block_response {
                                            option value=(response.stored()) selected { (label) }
                                        } @else {
                                            option value=(response.stored()) { (label) }
                                        }
                                    }
                                }
                                button type="submit" { "Set" }
                            }
                        }
                    }
                    tr {
                        td {
                            "Generated robots.txt"
                            br;
                            span .hint { "Replaces whatever your sites serve at /robots.txt" }
                        }
                        td {
                            .row {
                                @if view.serve_robots {
                                    (layout::pill("ON", PillKind::Allowed))
                                } @else {
                                    (layout::pill("OFF", PillKind::Neutral))
                                }
                                form .inline method="post" action=(ctx.url("/nginx/robots")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="enabled" value=(if view.serve_robots { "0" } else { "1" });
                                    button type="submit" {
                                        @if view.serve_robots { "Turn off" } @else { "Turn on" }
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
                                "Lets the internal cron write these configs and reload NGINX \
                                 hourly, instead of waiting for Apply. NGINX only \u{2014} the \
                                 firewall script still needs you."
                            }
                        }
                        td {
                            .row {
                                @if view.auto_apply {
                                    (layout::pill("ON", PillKind::Allowed))
                                } @else {
                                    (layout::pill("OFF", PillKind::Neutral))
                                }
                                form .inline method="post" action=(ctx.url("/nginx/auto-apply")) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="enabled" value=(if view.auto_apply { "0" } else { "1" });
                                    button type="submit" {
                                        @if view.auto_apply { "Turn off" } @else { "Turn on" }
                                    }
                                }
                            }
                        }
                    }
                    tr {
                        td {
                            "Rate limiting"
                            br;
                            span .hint { "Enforced by NGINX at request time, unlike everything else here" }
                        }
                        td {
                            form .row method="post" action=(ctx.url("/nginx/rate-limit")) style="gap:8px" {
                                (layout::csrf_field(ctx))
                                @if view.rate_limit {
                                    (layout::pill("ON", PillKind::Allowed))
                                } @else {
                                    (layout::pill("OFF", PillKind::Neutral))
                                }
                                label .field {
                                    "Requests/second"
                                    input type="number" name="rps" min="1" max="10000"
                                        value=(view.rate_rps) style="width:7em";
                                }
                                label .field {
                                    "Burst"
                                    input type="number" name="burst" min="1" max="100000"
                                        value=(view.rate_burst) style="width:7em";
                                }
                                input type="hidden" name="enabled" value=(if view.rate_limit { "0" } else { "1" });
                                button type="submit" {
                                    @if view.rate_limit { "Save and turn off" } @else { "Save and turn on" }
                                }
                            }
                        }
                    }
                }
            }
            .panel-body {
                p .hint {
                    "Changing any of these makes every applied site "
                    (layout::pill("STALE", PillKind::Warn))
                    " — that is your cue to Apply again."
                }
            }
        },
    )
}

fn sites_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Sites",
        Some(&format!("Discovered under {}", view.root.display())),
        html! {
            .panel-body {
                .row {
                    form .inline method="post" action=(ctx.url("/nginx/scan")) {
                        (layout::csrf_field(ctx))
                        button type="submit" title=(format!("Look for server blocks under {}", view.root.display())) { "Rescan" }
                    }
                    form .inline method="post" action=(ctx.url("/nginx/apply-all")) {
                        (layout::csrf_field(ctx))
                        button .primary type="submit" { "Apply to every site" }
                    }
                }
            }
            @if let Some(problem) = &view.status_problem {
                p .hint { "Whether each site is up to date could not be checked: " (problem) }
            }
            @if view.sites.is_empty() {
                (layout::empty("No sites yet. Rescan to look for server blocks under the NGINX root."))
            } @else {
                table {
                    thead { tr {
                        th { "Site" }
                        th { "Status" }
                        th .right { "Action" }
                    } }
                    tbody {
                        @for (site, status) in &view.sites {
                            tr {
                                td {
                                    a href=(ctx.url(&format!("/nginx/{}", site.id))) { (site.server_name) }
                                    br;
                                    span .hint .mono { (site.config_path) }
                                }
                                td { (status_pill(*status)) }
                                td .right {
                                    form .inline method="post" action=(ctx.url("/nginx/apply")) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="id" value=(site.id);
                                        button type="submit" { "Apply" }
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

fn status_pill(status: Option<SiteApplyStatus>) -> Markup {
    match status {
        Some(SiteApplyStatus::UpToDate) => layout::pill("UP TO DATE", PillKind::Allowed),
        Some(SiteApplyStatus::Stale) => layout::pill("STALE", PillKind::Warn),
        Some(SiteApplyStatus::NotFound) => layout::pill("NOT FOUND", PillKind::Blocked),
        None => layout::pill("UNKNOWN", PillKind::Neutral),
    }
}

// ---- detail ----

struct Detail {
    site: Site,
    status: Option<SiteApplyStatus>,
    scanner: Option<Policy>,
    search: Option<Policy>,
    ai: Option<Policy>,
    rules: Vec<(RequestRule, bool)>,
    exemptions: Vec<String>,
    agent_exemptions: Vec<crate::db::AgentExemption>,
    /// The per-bot overrides panel: what was searched for, and the bots it
    /// shows — each with this site's override for it, if any, and what it
    /// gets here once every tier is taken into account.
    bot_query: String,
    bots: Vec<SiteBot>,
    bots_truncated: bool,
}

/// One row of the per-bot overrides panel.
struct SiteBot {
    bot: Bot,
    site_override: Option<Policy>,
    effective: Policy,
}

/// The query string that brings a site's detail page back with `query`
/// still in its search box — empty when there is none.
fn bot_query_suffix(query: &str) -> String {
    if query.is_empty() {
        String::new()
    } else {
        format!("?q={}", crate::web::server::percent_encode(query))
    }
}

/// The rows of the per-bot panel: the bots matching `query`, or, with no
/// query, every bot this site overrides — the ones worth seeing without
/// having to remember their names.
fn site_bots(
    db: &Db,
    site_id: i64,
    query: &str,
    categories: [Option<Policy>; 3],
) -> anyhow::Result<(Vec<SiteBot>, bool)> {
    let overrides = db.site_bot_overrides(site_id)?;
    let override_for = |bot: &Bot| {
        overrides
            .iter()
            .find(|o| o.bot_id == bot.id)
            .map(|o| o.policy)
    };
    let bots = db.list_bots()?;
    let (bots, truncated) = if query.trim().is_empty() {
        let overridden = bots
            .into_iter()
            .filter(|bot| override_for(bot).is_some())
            .collect();
        crate::web::bots::matching_bots(overridden, "")
    } else {
        crate::web::bots::matching_bots(bots, query)
    };
    let [scanner, search, ai] = categories;
    let scanner = scanner.unwrap_or(db.get_category_default(Category::Scanner)?);
    let search = search.unwrap_or(db.get_category_default(Category::Search)?);
    let ai = ai.unwrap_or(db.get_category_default(Category::Ai)?);
    let rows = bots
        .into_iter()
        .map(|bot| {
            let site_override = override_for(&bot);
            let effective =
                crate::db::effective_bot_policy(&bot, site_override, ai, search, scanner);
            SiteBot {
                bot,
                site_override,
                effective,
            }
        })
        .collect();
    Ok((rows, truncated))
}

/// The site page's view, or `None` if no site has that id, with its
/// status worked out here.
#[cfg(test)]
fn load_detail(db: &Db, id: i64, bot_query: &str) -> anyhow::Result<Option<Detail>> {
    // The site's own directory as the root: what the fixtures scan.
    let Some(site) = db.list_sites()?.into_iter().find(|s| s.id == id) else {
        return Ok(None);
    };
    let root = Path::new(&site.config_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("a scanned site has no directory"))?
        .to_path_buf();
    let status = status_of(&crate::nginx::site_statuses(db, &root)?, id);
    load_detail_with(db, id, bot_query, status)
}

/// The site page's view, or `None` if no site has that id, with the
/// status the console's privileged operation gave.
fn load_detail_with(
    db: &Db,
    id: i64,
    bot_query: &str,
    status: Option<SiteApplyStatus>,
) -> anyhow::Result<Option<Detail>> {
    let Some(site) = db.list_sites()?.into_iter().find(|s| s.id == id) else {
        return Ok(None);
    };
    let enabled = db.site_request_rules(site.id)?;
    let scanner = db.get_site_category_override(site.id, Category::Scanner)?;
    let search = db.get_site_category_override(site.id, Category::Search)?;
    let ai = db.get_site_category_override(site.id, Category::Ai)?;
    let (bots, bots_truncated) = site_bots(db, site.id, bot_query, [scanner, search, ai])?;

    Ok(Some(Detail {
        scanner,
        search,
        ai,
        bot_query: bot_query.to_string(),
        bots,
        bots_truncated,
        rules: RequestRule::ALL
            .into_iter()
            .map(|rule| (rule, enabled.iter().any(|id| id == rule.id())))
            .collect(),
        exemptions: db.site_path_exemptions(site.id)?,
        agent_exemptions: db.site_agent_exemptions(site.id)?,
        site,
        status,
    }))
}

#[derive(Debug, Default, Deserialize)]
pub struct DetailParams {
    /// The per-bot panel's search text.
    pub q: Option<String>,
    #[serde(flatten)]
    pub flash: FlashQuery,
}

pub async fn detail(
    State(state): State<AppState>,
    auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Query(params): Query<DetailParams>,
) -> Response {
    let query = params.q.unwrap_or_default();
    let flash = params.flash;
    let status = state
        .privileged()
        .site_statuses()
        .await
        .ok()
        .and_then(|statuses| status_of(&statuses, id));
    let detail = match state
        .with_db(move |db| load_detail_with(db, id, &query, status))
        .await
    {
        Ok(Some(detail)) => detail,
        // A site that was never scanned, or was removed by a rescan: the
        // URL names nothing, which is a 404, not a server fault.
        Ok(None) => return crate::web::server::not_found().await,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Nginx,
        &ctx,
        flash.into_flash(&state),
        detail_body(&detail, &ctx),
    )
}

fn detail_body(detail: &Detail, ctx: &Ctx) -> Markup {
    let id = detail.site.id;
    html! {
        p { a href=(ctx.url("/nginx")) { "← All sites" } }

        .cols {

        (layout::panel(
            &detail.site.server_name,
            Some(&detail.site.config_path),
            html! {
                .panel-body {
                    .row {
                        (status_pill(detail.status))
                        form .inline method="post" action=(ctx.url("/nginx/apply")) {
                            (layout::csrf_field(ctx))
                            input type="hidden" name="id" value=(id);
                            button .primary type="submit" { "Apply to this site" }
                        }
                    }
                }
            },
        ))

        (layout::panel(
            "Category overrides",
            Some("Only for this site. Otherwise it follows the system-wide default"),
            html! {
                table { tbody {
                    @for (category, label, current) in [
                        (Category::Scanner, "Scanners", detail.scanner),
                        (Category::Search, crate::present::category_label(Category::Search), detail.search),
                        (Category::Ai, crate::present::category_label(Category::Ai), detail.ai),
                    ] {
                        tr {
                            td { (label) }
                            td {
                                @match current {
                                    Some(Policy::Blocked) => (layout::pill("BLOCKED", PillKind::Blocked)),
                                    Some(Policy::Allowed) => (layout::pill("ALLOWED", PillKind::Allowed)),
                                    None => (layout::pill("SYSTEM DEFAULT", PillKind::Neutral)),
                                }
                            }
                            td .right {
                                form .inline method="post" action=(ctx.url(&format!("/nginx/{id}/category"))) {
                                    (layout::csrf_field(ctx))
                                    input type="hidden" name="category" value=(category_id(category));
                                    select name="policy" data-autosubmit {
                                        @for (value, text) in [
                                            ("default", "Follow the system default"),
                                            ("allowed", "Allow here"),
                                            ("blocked", "Block here"),
                                        ] {
                                            @if override_id(current) == value {
                                                option value=(value) selected { (text) }
                                            } @else {
                                                option value=(value) { (text) }
                                            }
                                        }
                                    }
                                    button type="submit" { "Set" }
                                }
                            }
                        }
                    }
                } }
            },
        ))

        (bot_overrides_panel(detail, ctx))

        (layout::panel(
            "Request-shape rules",
            Some("Each is off by default — one switch per rule, so you can tell which one broke something"),
            html! {
                table {
                    thead { tr {
                        th { "Rule" }
                        th { "Also turns away" }
                        th { "State" }
                        th .right { "Action" }
                    } }
                    tbody {
                        @for (rule, enabled) in &detail.rules {
                            tr {
                                td { (rule.label()) }
                                td { span .hint { (rule.caveat()) } }
                                td {
                                    @if *enabled {
                                        (layout::pill("ON", PillKind::Allowed))
                                    } @else {
                                        (layout::pill("OFF", PillKind::Neutral))
                                    }
                                }
                                td .right {
                                    form .inline method="post" action=(ctx.url(&format!("/nginx/{id}/rule"))) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="rule" value=(rule.id());
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
        ))

        (layout::panel(
            "Path exemptions",
            Some("Prefixes that are never blocked, so you can block AI crawlers everywhere except /blog. Give a user agent to exempt only that client there, e.g. okhttp for an app a bot list catches by its HTTP library"),
            html! {
                @if detail.exemptions.is_empty() && detail.agent_exemptions.is_empty() {
                    (layout::empty("No exemptions."))
                } @else {
                    table { tbody {
                        @for path in &detail.exemptions {
                            (exemption_row(ctx, id, path, None))
                        }
                        @for exemption in &detail.agent_exemptions {
                            (exemption_row(ctx, id, &exemption.path, Some(&exemption.user_agent)))
                        }
                    } }
                }
                .panel-body {
                    form .row method="post" action=(ctx.url(&format!("/nginx/{id}/exempt-add"))) {
                        (layout::csrf_field(ctx))
                        input type="text" name="path" placeholder="/blog" size="24" required;
                        input type="text" name="user_agent" placeholder="every client" size="20" aria-label="Only for user agent";
                        button .primary type="submit" { "Add" }
                    }
                }
            },
        ))

        }
    }
}

/// Per-bot overrides for this site: the TUI's site-detail bot search, and
/// the global Bot settings page's per-bot select, scoped to one site.
fn bot_overrides_panel(detail: &Detail, ctx: &Ctx) -> Markup {
    let id = detail.site.id;
    let suffix = bot_query_suffix(&detail.bot_query);
    layout::panel(
        "Bot overrides",
        Some("Only for this site. Wins over the bot's global override and every category"),
        html! {
            .panel-body {
                form .row method="get" action=(ctx.url(&format!("/nginx/{id}"))) {
                    input type="text" name="q" value=(detail.bot_query)
                        placeholder="Search by name or user-agent pattern" size="30";
                    button type="submit" { "Search" }
                    @if !detail.bot_query.is_empty() {
                        a .button href=(ctx.url(&format!("/nginx/{id}"))) { "Clear" }
                    }
                }
            }
            @if detail.bots.is_empty() {
                @if detail.bot_query.trim().is_empty() {
                    (layout::empty("No bot is overridden on this site. Search to add one."))
                } @else {
                    (layout::empty("No bots match that search."))
                }
            } @else {
                table {
                    thead { tr {
                        th { "Bot" }
                        th { "Categories" }
                        th { "Here" }
                        th .right { "Override" }
                    } }
                    tbody {
                        @for row in &detail.bots {
                            tr {
                                td {
                                    (row.bot.name)
                                    br;
                                    span .hint .mono { (row.bot.user_agent_pattern) }
                                }
                                td { (crate::web::bots::categories_of(&row.bot)) }
                                td {
                                    @match row.effective {
                                        Policy::Blocked => (layout::pill("BLOCKED", PillKind::Blocked)),
                                        Policy::Allowed => (layout::pill("ALLOWED", PillKind::Allowed)),
                                    }
                                    " "
                                    span .hint { (effective_source(row)) }
                                }
                                td .right {
                                    form .inline method="post" action=(ctx.url(&format!("/nginx/{id}/bot{suffix}"))) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="bot" value=(row.bot.id);
                                        select name="policy" data-autosubmit {
                                            @for (value, text) in [
                                                ("default", "Follow site & system"),
                                                ("allowed", "Allow here"),
                                                ("blocked", "Block here"),
                                            ] {
                                                @if override_id(row.site_override) == value {
                                                    option value=(value) selected { (text) }
                                                } @else {
                                                    option value=(value) { (text) }
                                                }
                                            }
                                        }
                                        button type="submit" { "Set" }
                                    }
                                }
                            }
                        }
                    }
                }
                @if detail.bots_truncated {
                    .panel-body {
                        p .hint { "Showing the first matches only. Narrow the search to see the rest." }
                    }
                }
            }
        },
    )
}

/// Which tier decided a bot's policy on this site — the question the
/// TUI answers with "(site override)" beside every row.
fn effective_source(row: &SiteBot) -> &'static str {
    if row.site_override.is_some() {
        "site override"
    } else if row.bot.status != crate::db::BotStatus::Default {
        "global override"
    } else {
        "category"
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

fn override_id(policy: Option<Policy>) -> &'static str {
    match policy {
        None => "default",
        Some(Policy::Allowed) => "allowed",
        Some(Policy::Blocked) => "blocked",
    }
}

fn override_from(id: &str) -> Option<Option<Policy>> {
    match id {
        "default" => Some(None),
        "allowed" => Some(Some(Policy::Allowed)),
        "blocked" => Some(Some(Policy::Blocked)),
        _ => None,
    }
}

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/nginx/{id}"), axum::routing::get(detail))
        .route(&base.url("/nginx/block-response"), post(set_block_response))
        .route(&base.url("/nginx/robots"), post(set_robots))
        .route(&base.url("/nginx/auto-apply"), post(set_auto_apply))
        .route(&base.url("/nginx/rate-limit"), post(set_rate_limit))
        .route(&base.url("/nginx/scan"), post(scan))
        .route(&base.url("/nginx/apply"), post(apply_one))
        .route(&base.url("/nginx/apply-all"), post(apply_all))
        .route(&base.url("/nginx/{id}/category"), post(set_site_category))
        .route(&base.url("/nginx/{id}/rule"), post(set_site_rule))
        .route(&base.url("/nginx/{id}/bot"), post(set_site_bot))
        .route(&base.url("/nginx/{id}/exempt-add"), post(add_exemption))
        .route(
            &base.url("/nginx/{id}/exempt-remove"),
            post(remove_exemption),
        )
}

#[derive(Deserialize)]
struct ResponseForm {
    response: String,
}

async fn set_block_response(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<ResponseForm>,
) -> Response {
    let response = BlockResponse::from_stored(&form.response);
    match state
        .with_db(move |db| db.set_block_response(response))
        .await
    {
        Ok(()) => back_with(
            &state,
            "/nginx",
            &format!(
                "Blocked requests now get {}. Apply to write it out.",
                response.label()
            ),
            true,
        ),
        Err(err) => back_with(
            &state,
            "/nginx",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct ToggleForm {
    enabled: String,
}

/// Turns automatic applying on or off.
///
/// Says *when* rather than just "saved": the switch's whole point is that
/// something happens later without anyone asking, and a confirmation that
/// did not mention the reload would be the last chance to say so.
async fn set_auto_apply(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<ToggleForm>,
) -> Response {
    let on = form.enabled == "1";
    match state.with_db(move |db| db.set_auto_apply(on)).await {
        Ok(()) => back_with(
            &state,
            "/nginx",
            if on {
                "Auto-apply on. The internal cron will write these configs and reload NGINX \
                 within the hour, and after every change from now on."
            } else {
                "Auto-apply off. Config changes wait for Apply again."
            },
            true,
        ),
        Err(err) => back_with(
            &state,
            "/nginx",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

async fn set_robots(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<ToggleForm>,
) -> Response {
    let on = form.enabled == "1";
    match state.with_db(move |db| db.set_serve_robots_txt(on)).await {
        Ok(()) => back_with(
            &state,
            "/nginx",
            if on {
                "robots.txt will be generated. Apply to write it out."
            } else {
                "robots.txt will no longer be generated. Apply to remove it."
            },
            true,
        ),
        Err(err) => back_with(
            &state,
            "/nginx",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct RateLimitForm {
    enabled: String,
    rps: i64,
    burst: i64,
}

async fn set_rate_limit(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<RateLimitForm>,
) -> Response {
    if form.rps < 1 || form.burst < 1 {
        return back_with(
            &state,
            "/nginx",
            "Rate and burst both have to be at least 1.",
            false,
        );
    }
    let on = form.enabled == "1";
    let (rps, burst) = (form.rps, form.burst);
    match state
        .with_db(move |db| {
            db.set_rate_limit_rps(rps)?;
            db.set_rate_limit_burst(burst)?;
            db.set_rate_limit_enabled(on)
        })
        .await
    {
        Ok(()) => back_with(
            &state,
            "/nginx",
            &format!(
                "Rate limiting {} at {rps}/s with a burst of {burst}. Apply to write it out.",
                if on { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(
            &state,
            "/nginx",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

async fn scan(State(state): State<AppState>, _auth: Auth) -> Response {
    match state.privileged().scan_sites().await {
        Ok(count) => back_with(&state, "/nginx", &format!("Found {count} site(s)."), true),
        Err(err) => back_with(&state, "/nginx", &format!("Scan failed: {err:#}"), false),
    }
}

#[derive(Deserialize)]
struct IdForm {
    id: i64,
}

async fn apply_one(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<IdForm>,
) -> Response {
    let applied = state.privileged().apply_site(form.id, true).await;

    match applied {
        Ok((name, changed, reloaded)) => {
            let message = if changed {
                format!("Applied to {name}.")
            } else {
                format!("{name} was already up to date.")
            };
            applied_message(&state, "/nginx", message, changed, reloaded)
        }
        Err(err) => back_with(&state, "/nginx", &format!("Apply failed: {err:#}"), false),
    }
}

async fn apply_all(State(state): State<AppState>, _auth: Auth) -> Response {
    let applied = state.privileged().apply_all(true).await;

    match applied {
        Ok(outcome) => applied_message(
            &state,
            "/nginx",
            format!("Applied: {} file(s) changed.", outcome.changed),
            outcome.changed > 0,
            outcome.reloaded,
        ),
        Err(err) => back_with(&state, "/nginx", &format!("Apply failed: {err:#}"), false),
    }
}

/// The flash for a finished apply. The reload itself happened inside the
/// apply (see `nginx::apply_all_sites_and_reload`), and only after the new
/// config passed the test, so all that is left is to say which it was.
fn applied_message(
    state: &AppState,
    back: &str,
    message: String,
    changed: bool,
    reloaded: bool,
) -> Response {
    let note = if reloaded {
        " NGINX reloaded."
    } else if !state.apply_for_real {
        " (NGINX not reloaded: --no-apply)"
    } else if changed {
        ""
    } else {
        " Nothing changed, so NGINX was not reloaded."
    };
    back_with(state, back, &format!("{message}{note}"), true)
}

#[derive(Deserialize)]
struct SiteCategoryForm {
    category: String,
    policy: String,
}

async fn set_site_category(
    State(state): State<AppState>,
    _auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Form(form): Form<SiteCategoryForm>,
) -> Response {
    let back = format!("/nginx/{id}");
    let (Some(category), Some(policy)) =
        (category_from(&form.category), override_from(&form.policy))
    else {
        return back_with(&state, &back, "Unknown category or policy.", false);
    };

    match state
        .with_db(move |db| db.set_site_category_override(id, category, policy))
        .await
    {
        Ok(()) => back_with(
            &state,
            &back,
            "Override saved. Apply to write it out.",
            true,
        ),
        Err(err) => back_with(&state, &back, &format!("Could not save that: {err}"), false),
    }
}

#[derive(Deserialize)]
struct SiteBotForm {
    bot: i64,
    policy: String,
}

/// The search the form was posted from, so the page comes back to it.
#[derive(Deserialize)]
struct BackQuery {
    #[serde(default)]
    q: String,
}

/// Sets, or clears, one bot's override on one site.
async fn set_site_bot(
    State(state): State<AppState>,
    _auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Query(back): Query<BackQuery>,
    Form(form): Form<SiteBotForm>,
) -> Response {
    let back = format!("/nginx/{id}{}", bot_query_suffix(&back.q));
    let Some(policy) = override_from(&form.policy) else {
        return back_with(&state, &back, "Unknown policy.", false);
    };
    let bot_id = form.bot;
    let stored = state
        .with_db(move |db| {
            let site = db
                .list_sites()?
                .into_iter()
                .find(|s| s.id == id)
                .ok_or_else(|| anyhow::anyhow!("no site with id {id}"))?;
            let bot = db
                .list_bots()?
                .into_iter()
                .find(|b| b.id == bot_id)
                .ok_or_else(|| anyhow::anyhow!("no bot with id {bot_id}"))?;
            db.set_site_bot_override(id, bot_id, policy)?;
            Ok((bot.name, site.server_name))
        })
        .await;
    match stored {
        Ok((bot, site)) => back_with(
            &state,
            &back,
            &format!(
                "{bot} on {site}: {}. Apply to write it out.",
                match policy {
                    None => "follows the site and system defaults",
                    Some(Policy::Allowed) => "allowed",
                    Some(Policy::Blocked) => "blocked",
                }
            ),
            true,
        ),
        Err(err) => back_with(&state, &back, &format!("Could not save that: {err}"), false),
    }
}

#[derive(Deserialize)]
struct RuleForm {
    rule: String,
    enabled: String,
}

async fn set_site_rule(
    State(state): State<AppState>,
    _auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Form(form): Form<RuleForm>,
) -> Response {
    let back = format!("/nginx/{id}");
    let Some(rule) = RequestRule::from_id(&form.rule) else {
        return back_with(&state, &back, "Unknown request rule.", false);
    };
    let on = form.enabled == "1";
    let rule_id = rule.id().to_string();

    match state
        .with_db(move |db| db.set_site_request_rule(id, &rule_id, on))
        .await
    {
        Ok(()) => back_with(
            &state,
            &back,
            &format!(
                "{} is now {}. Apply to write it out.",
                rule.label(),
                if on { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(&state, &back, &format!("Could not save that: {err}"), false),
    }
}

/// One exemption in the Site detail table, with its Remove button.
/// `user_agent` is `None` for a plain exemption, which covers every client.
fn exemption_row(ctx: &Ctx, id: i64, path: &str, user_agent: Option<&str>) -> Markup {
    html! {
        tr {
            td .mono { (path) }
            td {
                span .hint {
                    @match user_agent {
                        Some(user_agent) => { "only for " (user_agent) }
                        None => { "every client" }
                    }
                }
            }
            td .right {
                form .inline method="post" action=(ctx.url(&format!("/nginx/{id}/exempt-remove"))) {
                    (layout::csrf_field(ctx))
                    input type="hidden" name="path" value=(path);
                    @if let Some(user_agent) = user_agent {
                        input type="hidden" name="user_agent" value=(user_agent);
                    }
                    button type="submit" { "Remove" }
                }
            }
        }
    }
}

/// A path, and optionally the user agent it is limited to — empty (or
/// absent, from an older page) for a plain exemption.
#[derive(Deserialize)]
struct PathForm {
    path: String,
    #[serde(default)]
    user_agent: String,
}

async fn add_exemption(
    State(state): State<AppState>,
    _auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Form(form): Form<PathForm>,
) -> Response {
    let back = format!("/nginx/{id}");
    let path = form.path.trim().to_string();
    if !path.starts_with('/') {
        return back_with(
            &state,
            &back,
            "A path exemption has to start with `/`.",
            false,
        );
    }
    let stored = path.clone();
    let user_agent = form.user_agent.trim().to_string();
    let result = state
        .with_db(move |db| {
            if user_agent.is_empty() {
                db.add_site_path_exemption(id, &stored)?;
                Ok(format!("{stored} is now exempt"))
            } else {
                let user_agent = db.add_site_agent_exemption(id, &stored, &user_agent)?;
                Ok(format!("{stored} is now exempt for {user_agent}"))
            }
        })
        .await;
    match result {
        Ok(done) => back_with(
            &state,
            &back,
            &format!("{done}. Apply to write it out."),
            true,
        ),
        Err(err) => back_with(
            &state,
            &back,
            &format!("Could not add {path}: {err}"),
            false,
        ),
    }
}

async fn remove_exemption(
    State(state): State<AppState>,
    _auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Form(form): Form<PathForm>,
) -> Response {
    let back = format!("/nginx/{id}");
    let path = form.path;
    let stored = path.clone();
    let user_agent = form.user_agent;
    let result = state
        .with_db(move |db| {
            if user_agent.is_empty() {
                db.remove_site_path_exemption(id, &stored)?;
                Ok(format!("{stored} is no longer exempt."))
            } else {
                db.remove_site_agent_exemption(id, &stored, &user_agent)?;
                Ok(format!("{stored} is no longer exempt for {user_agent}."))
            }
        })
        .await;
    match result {
        Ok(done) => back_with(&state, &back, &done, true),
        Err(err) => back_with(
            &state,
            &back,
            &format!("Could not remove {path}: {err}"),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(root: &Path) -> Db {
        std::fs::create_dir_all(root.join("sites-enabled")).unwrap();
        std::fs::write(
            root.join("sites-enabled/example.com"),
            "server {\n    listen 80;\n    server_name example.com;\n}\n",
        )
        .unwrap();

        let db = Db::open_in_memory().unwrap();
        db.upsert_site(
            "example.com",
            root.join("sites-enabled/example.com").to_str().unwrap(),
        )
        .unwrap();
        db
    }

    #[test]
    fn category_and_override_ids_round_trip() {
        for category in [Category::Scanner, Category::Search, Category::Ai] {
            assert_eq!(category_from(category_id(category)), Some(category));
        }
        for policy in [None, Some(Policy::Allowed), Some(Policy::Blocked)] {
            assert_eq!(override_from(override_id(policy)), Some(policy));
        }
        assert_eq!(override_from("nonsense"), None);
    }

    #[test]
    fn a_site_with_no_rule_applied_reads_as_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());

        // A blocked bot means there is a rule to write, so the untouched
        // file on disk is out of date with what policy now says.
        crate::testing::blocked_bot(&db, "gptbot", "gptbot");

        let view = load(&db, tmp.path()).unwrap();
        assert_eq!(view.sites.len(), 1);
        assert_eq!(view.sites[0].1, Some(SiteApplyStatus::Stale));
    }

    #[test]
    fn a_site_whose_file_is_gone_reads_as_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        std::fs::remove_file(tmp.path().join("sites-enabled/example.com")).unwrap();

        let view = load(&db, tmp.path()).unwrap();
        assert_eq!(view.sites[0].1, Some(SiteApplyStatus::NotFound));
    }

    #[test]
    fn the_list_renders_with_no_sites_and_says_what_to_do() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let view = load(&db, tmp.path()).unwrap();
        let rendered = body(&view, &Ctx::for_tests()).into_string();

        assert!(rendered.contains("No sites yet"), "was: {rendered}");
        assert!(rendered.contains("Rescan"));
    }

    #[test]
    fn the_detail_page_lists_every_request_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;

        let detail = load_detail(&db, id, "").unwrap().unwrap();
        assert_eq!(detail.rules.len(), RequestRule::ALL.len());
        assert!(
            detail.rules.iter().all(|(_, enabled)| !enabled),
            "every request rule is off until switched on"
        );

        let rendered = detail_body(&detail, &Ctx::for_tests()).into_string();
        for (rule, _) in &detail.rules {
            assert!(
                rendered.contains(rule.label()),
                "{} missing from the page",
                rule.label()
            );
        }
    }

    #[test]
    fn a_detail_page_reflects_a_stored_override_and_exemption() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;

        db.set_site_category_override(id, Category::Ai, Some(Policy::Blocked))
            .unwrap();
        db.add_site_path_exemption(id, "/blog").unwrap();

        let detail = load_detail(&db, id, "").unwrap().unwrap();
        assert_eq!(detail.ai, Some(Policy::Blocked));
        assert_eq!(detail.exemptions, ["/blog"]);

        let rendered = detail_body(&detail, &Ctx::for_tests()).into_string();
        assert!(rendered.contains("/blog"));
    }

    #[test]
    fn an_agent_exemption_row_names_its_user_agent_and_removes_only_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;
        db.add_site_agent_exemption(id, "/remote.php/dav/", "okhttp")
            .unwrap();

        let rendered = detail_body(
            &load_detail(&db, id, "").unwrap().unwrap(),
            &Ctx::for_tests(),
        )
        .into_string();
        for expected in ["only for okhttp", r#"name="user_agent" value="okhttp""#] {
            assert!(
                rendered.contains(expected),
                "missing {expected}; page was:\n{rendered}"
            );
        }
    }

    /// Each row says what the bot gets on this site and which tier decided
    /// it: the site's own override beats the bot's global one, which beats
    /// its categories.
    #[test]
    fn a_bot_row_names_the_tier_that_decided_it() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;
        crate::testing::seed_source(&db, "test-source");
        for slug in ["pinned", "overridden", "plain"] {
            db.upsert_bot(&crate::testing::new_bot(slug, "test-source"))
                .unwrap();
        }
        db.set_bot_status("pinned", crate::db::BotStatus::Blocked)
            .unwrap();
        db.set_bot_status("overridden", crate::db::BotStatus::Blocked)
            .unwrap();
        let overridden = db
            .list_bots()
            .unwrap()
            .into_iter()
            .find(|b| b.slug == "overridden")
            .unwrap();
        db.set_site_bot_override(id, overridden.id, Some(Policy::Allowed))
            .unwrap();

        let rows: Vec<(String, Policy, &str)> = load_detail(&db, id, "e")
            .unwrap()
            .unwrap()
            .bots
            .iter()
            .map(|row| (row.bot.slug.clone(), row.effective, effective_source(row)))
            .collect();

        assert_eq!(
            rows,
            [
                ("overridden".to_string(), Policy::Allowed, "site override"),
                ("pinned".to_string(), Policy::Blocked, "global override"),
            ]
        );
        // "plain" has no "e"; with no search, only the overridden one shows.
        let unsearched: Vec<String> = load_detail(&db, id, "")
            .unwrap()
            .unwrap()
            .bots
            .into_iter()
            .map(|row| row.bot.slug)
            .collect();
        assert_eq!(unsearched, ["overridden"]);
    }

    /// A missing site is nothing to show, not a fault: the handler turns
    /// it into a 404 rather than a blank page or a 500.
    #[test]
    fn a_missing_site_is_none_rather_than_a_blank_page() {
        let db = Db::open_in_memory().unwrap();
        assert!(load_detail(&db, 999, "").unwrap().is_none());
    }

    #[test]
    fn every_post_form_carries_the_csrf_token() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;
        crate::testing::blocked_bot(&db, "badbot", "BadBot");

        for rendered in [
            body(
                &load(&db, tmp.path()).unwrap(),
                &Ctx::new("the-token", Default::default()),
            )
            .into_string(),
            detail_body(
                &load_detail(&db, id, "").unwrap().unwrap(),
                &Ctx::new("the-token", Default::default()),
            )
            .into_string(),
            // With a search, so the per-bot forms are on the page too.
            detail_body(
                &load_detail(&db, id, "bad").unwrap().unwrap(),
                &Ctx::new("the-token", Default::default()),
            )
            .into_string(),
        ] {
            let posts = rendered.matches(r#"method="post""#).count();
            let tokens = rendered.matches(r#"name="csrf" value="the-token""#).count();
            assert_eq!(posts, tokens, "{posts} POST form(s) but {tokens} token(s)");
        }
    }

    #[test]
    fn a_server_name_from_disk_cannot_inject_markup() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("<script>alert(1)</script>", "/etc/nginx/x")
            .unwrap();

        let rendered = body(&load(&db, tmp.path()).unwrap(), &Ctx::for_tests()).into_string();
        assert!(
            !rendered.contains("<script>alert(1)"),
            "server names come off disk and must be escaped: {rendered}"
        );
    }
}
