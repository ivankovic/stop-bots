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
//! every site's config file, which is why the TUI pushes it to a
//! background thread — but a web request is already off the async runtime
//! by the time a handler touches the database, so there is nothing to
//! protect here that `with_db` has not protected already.

use std::path::{Path, PathBuf};

use axum::extract::{Path as UrlPath, Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::db::{BlockResponse, Category, Db, Policy, Site};
use crate::nginx::{self, RequestRule, SiteApplyStatus};
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
    sites: Vec<(Site, SiteApplyStatus)>,
    root: PathBuf,
}

fn load(db: &Db, root: &Path) -> anyhow::Result<View> {
    let sites = db.list_sites()?;
    let conf_d = nginx::conf_d_dir(&nginx::root(db, None)?);
    let mut with_status = Vec::with_capacity(sites.len());
    for site in sites {
        let config = nginx::block_config_for_site(db, site.id)?;
        let status = nginx::site_apply_status(
            Path::new(&site.config_path),
            &site.server_name,
            &config,
            &conf_d,
        );
        with_status.push((site, status));
    }

    Ok(View {
        block_response: db.get_block_response()?,
        serve_robots: db.get_serve_robots_txt()?,
        auto_apply: db.get_auto_apply()?,
        rate_limit: db.get_rate_limit_enabled()?,
        rate_rps: db.get_rate_limit_rps()?,
        rate_burst: db.get_rate_limit_burst()?,
        sites: with_status,
        root: root.to_path_buf(),
    })
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(flash): Query<FlashQuery>,
) -> Response {
    let root = state.nginx_root.clone();
    let view = match state.with_db(move |db| load(db, &root)).await {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(Tab::Nginx, &ctx, flash.into_flash(), body(&view, &ctx))
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

fn status_pill(status: SiteApplyStatus) -> Markup {
    match status {
        SiteApplyStatus::UpToDate => layout::pill("UP TO DATE", PillKind::Allowed),
        SiteApplyStatus::Stale => layout::pill("STALE", PillKind::Warn),
        SiteApplyStatus::NotFound => layout::pill("NOT FOUND", PillKind::Blocked),
    }
}

// ---- detail ----

struct Detail {
    site: Site,
    status: SiteApplyStatus,
    scanner: Option<Policy>,
    search: Option<Policy>,
    ai: Option<Policy>,
    rules: Vec<(RequestRule, bool)>,
    exemptions: Vec<String>,
    agent_exemptions: Vec<crate::db::AgentExemption>,
}

fn load_detail(db: &Db, id: i64) -> anyhow::Result<Detail> {
    let site = db
        .list_sites()?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| anyhow::anyhow!("no site with id {id}"))?;

    let config = nginx::block_config_for_site(db, site.id)?;
    let status = nginx::site_apply_status(
        Path::new(&site.config_path),
        &site.server_name,
        &config,
        &nginx::conf_d_dir(&nginx::root(db, None)?),
    );
    let enabled = db.site_request_rules(site.id)?;

    Ok(Detail {
        scanner: db.get_site_category_override(site.id, Category::Scanner)?,
        search: db.get_site_category_override(site.id, Category::Search)?,
        ai: db.get_site_category_override(site.id, Category::Ai)?,
        rules: RequestRule::ALL
            .into_iter()
            .map(|rule| (rule, enabled.iter().any(|id| id == rule.id())))
            .collect(),
        exemptions: db.site_path_exemptions(site.id)?,
        agent_exemptions: db.site_agent_exemptions(site.id)?,
        site,
        status,
    })
}

pub async fn detail(
    State(state): State<AppState>,
    auth: Auth,
    UrlPath(id): UrlPath<i64>,
    Query(flash): Query<FlashQuery>,
) -> Response {
    let detail = match state.with_db(move |db| load_detail(db, id)).await {
        Ok(detail) => detail,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Nginx,
        &ctx,
        flash.into_flash(),
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
                        (Category::Search, "Search bots", detail.search),
                        (Category::Ai, "AI bots", detail.ai),
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
            &state.base,
            "/nginx",
            &format!(
                "Blocked requests now get {}. Apply to write it out.",
                response.label()
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
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
            &state.base,
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
            &state.base,
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
            &state.base,
            "/nginx",
            if on {
                "robots.txt will be generated. Apply to write it out."
            } else {
                "robots.txt will no longer be generated. Apply to remove it."
            },
            true,
        ),
        Err(err) => back_with(
            &state.base,
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
            &state.base,
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
            &state.base,
            "/nginx",
            &format!(
                "Rate limiting {} at {rps}/s with a burst of {burst}. Apply to write it out.",
                if on { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/nginx",
            &format!("Could not save that: {err}"),
            false,
        ),
    }
}

async fn scan(State(state): State<AppState>, _auth: Auth) -> Response {
    let root = state.nginx_root.clone();
    let found = state
        .with_db(move |db| {
            let sites = nginx::discover_sites(&root)?;
            for site in &sites {
                db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
            }
            Ok(sites.len())
        })
        .await;

    match found {
        Ok(count) => back_with(
            &state.base,
            "/nginx",
            &format!("Found {count} site(s)."),
            true,
        ),
        Err(err) => back_with(&state.base, "/nginx", &format!("Scan failed: {err}"), false),
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
    let id = form.id;
    let applied = state
        .with_db(move |db| {
            let site = db
                .list_sites()?
                .into_iter()
                .find(|s| s.id == id)
                .ok_or_else(|| anyhow::anyhow!("no site with id {id}"))?;
            nginx::write_managed_files(db, &nginx::root(db, None)?)?;
            let config = nginx::block_config_for_site(db, site.id)?;
            let changed = nginx::apply_block_for_site(
                Path::new(&site.config_path),
                &site.server_name,
                &config,
            )?;
            Ok((site.server_name, changed))
        })
        .await;

    match applied {
        Ok((name, changed)) => {
            let message = if changed {
                format!("Applied to {name}.")
            } else {
                format!("{name} was already up to date.")
            };
            reload_then(&state, "/nginx", message).await
        }
        Err(err) => back_with(
            &state.base,
            "/nginx",
            &format!("Apply failed: {err}"),
            false,
        ),
    }
}

async fn apply_all(State(state): State<AppState>, _auth: Auth) -> Response {
    let root = state.nginx_root.clone();
    let applied = state
        .with_db(move |db| nginx::apply_all_sites(db, &root))
        .await;

    match applied {
        Ok(outcome) => {
            reload_then(
                &state,
                "/nginx",
                format!("Applied: {} file(s) changed.", outcome.changed),
            )
            .await
        }
        Err(err) => back_with(
            &state.base,
            "/nginx",
            &format!("Apply failed: {err}"),
            false,
        ),
    }
}

/// Reloads NGINX after a successful apply, and folds the outcome into the
/// message.
///
/// A failed reload is appended rather than replacing what the apply said,
/// for the same reason `App::finish_nginx_reload` does it: the files
/// really were written, and that is worth knowing alongside the news that
/// NGINX is still serving the old ones.
async fn reload_then(state: &AppState, back: &str, message: String) -> Response {
    if !state.apply_for_real {
        return back_with(
            &state.base,
            back,
            &format!("{message} (NGINX not reloaded: --no-apply)"),
            true,
        );
    }

    let reloaded = state
        .with_db(|db| {
            let commands = nginx::NginxCommands::from_db(db)?;
            nginx::reload_with(&commands)
        })
        .await;

    match reloaded {
        Ok(()) => back_with(
            &state.base,
            back,
            &format!("{message} NGINX reloaded."),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            back,
            &format!("{message} Reload failed: {err}"),
            false,
        ),
    }
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
        return back_with(&state.base, &back, "Unknown category or policy.", false);
    };

    match state
        .with_db(move |db| db.set_site_category_override(id, category, policy))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            &back,
            "Override saved. Apply to write it out.",
            true,
        ),
        Err(err) => back_with(
            &state.base,
            &back,
            &format!("Could not save that: {err}"),
            false,
        ),
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
        return back_with(&state.base, &back, "Unknown request rule.", false);
    };
    let on = form.enabled == "1";
    let rule_id = rule.id().to_string();

    match state
        .with_db(move |db| db.set_site_request_rule(id, &rule_id, on))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            &back,
            &format!(
                "{} is now {}. Apply to write it out.",
                rule.label(),
                if on { "on" } else { "off" }
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            &back,
            &format!("Could not save that: {err}"),
            false,
        ),
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
            &state.base,
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
            &state.base,
            &back,
            &format!("{done}. Apply to write it out."),
            true,
        ),
        Err(err) => back_with(
            &state.base,
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
        Ok(done) => back_with(&state.base, &back, &done, true),
        Err(err) => back_with(
            &state.base,
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
        assert_eq!(view.sites[0].1, SiteApplyStatus::Stale);
    }

    #[test]
    fn a_site_whose_file_is_gone_reads_as_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        std::fs::remove_file(tmp.path().join("sites-enabled/example.com")).unwrap();

        let view = load(&db, tmp.path()).unwrap();
        assert_eq!(view.sites[0].1, SiteApplyStatus::NotFound);
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

        let detail = load_detail(&db, id).unwrap();
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

        let detail = load_detail(&db, id).unwrap();
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

        let rendered = detail_body(&load_detail(&db, id).unwrap(), &Ctx::for_tests()).into_string();
        for expected in ["only for okhttp", r#"name="user_agent" value="okhttp""#] {
            assert!(
                rendered.contains(expected),
                "missing {expected}; page was:\n{rendered}"
            );
        }
    }

    #[test]
    fn a_missing_site_is_an_error_rather_than_a_blank_page() {
        let db = Db::open_in_memory().unwrap();
        assert!(load_detail(&db, 999).is_err());
    }

    #[test]
    fn every_post_form_carries_the_csrf_token() {
        let tmp = tempfile::tempdir().unwrap();
        let db = seeded(tmp.path());
        let id = db.list_sites().unwrap()[0].id;

        for rendered in [
            body(
                &load(&db, tmp.path()).unwrap(),
                &Ctx::new("the-token", Default::default()),
            )
            .into_string(),
            detail_body(
                &load_detail(&db, id).unwrap(),
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
