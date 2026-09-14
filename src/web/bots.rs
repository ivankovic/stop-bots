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

//! Bot settings: where the bot lists come from, and what each individual
//! bot is allowed to do.

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::botlist::{self, SourceKind};
use crate::db::{Bot, BotStatus, Category, Db, Policy, Source};
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{back_with, internal_error, render, Auth, FlashQuery};
use crate::web::state::AppState;

/// How many matches to render.
///
/// The TUI shows results only once something is typed, for a reason that
/// applies here too: the merged list runs to a couple of thousand bots,
/// and a page listing all of them is neither useful nor fast. The web
/// version can afford to show a page of them, but not the lot.
const MAX_RESULTS: usize = 100;

#[derive(Debug, Default, Deserialize)]
pub struct Params {
    /// Search text. Empty shows the most-recently-updated bots instead of
    /// nothing, because a blank screen reads as "no data" rather than as
    /// "type something".
    pub q: Option<String>,
    #[serde(flatten)]
    pub flash: FlashQuery,
}

struct View {
    sources: Vec<Source>,
    matches: Vec<Bot>,
    total: usize,
    truncated: bool,
    query: String,
    scanner: Policy,
    search: Policy,
    ai: Policy,
}

fn load(db: &Db, query: &str) -> anyhow::Result<View> {
    let bots = db.list_bots()?;
    let total = bots.len();

    let needle = query.trim().to_lowercase();
    let mut matches: Vec<Bot> = if needle.is_empty() {
        bots
    } else {
        bots.into_iter()
            .filter(|bot| {
                bot.name.to_lowercase().contains(&needle)
                    || bot.slug.to_lowercase().contains(&needle)
                    || bot.user_agent_pattern.to_lowercase().contains(&needle)
            })
            .collect()
    };
    matches.sort_by_key(|bot| bot.name.to_lowercase());
    let truncated = matches.len() > MAX_RESULTS;
    matches.truncate(MAX_RESULTS);

    Ok(View {
        sources: db.list_sources()?,
        matches,
        total,
        truncated,
        query: query.to_string(),
        scanner: db.get_category_default(Category::Scanner)?,
        search: db.get_category_default(Category::Search)?,
        ai: db.get_category_default(Category::Ai)?,
    })
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(params): Query<Params>,
) -> Response {
    let query = params.q.clone().unwrap_or_default();
    let view = match state.with_db(move |db| load(db, &query)).await {
        Ok(view) => view,
        Err(err) => return internal_error(&err.to_string()),
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Bots,
        &ctx,
        params.flash.into_flash(),
        body(&view, &ctx),
    )
}

fn body(view: &View, ctx: &Ctx) -> Markup {
    html! {
        .cols {
            (sources_panel(view, ctx))
            (bots_panel(view, ctx))
        }
    }
}

fn sources_panel(view: &View, ctx: &Ctx) -> Markup {
    layout::panel(
        "Bot list sources",
        Some("Where the known-bot list comes from"),
        html! {
            @if view.sources.is_empty() {
                (layout::empty("No sources registered."))
            } @else {
                table {
                    thead { tr {
                        th { "Source" }
                        th .right { "Bots" }
                        th { "Last updated" }
                        th .right { "Action" }
                    } }
                    tbody {
                        @for source in &view.sources {
                            tr {
                                td { (source.name) }
                                td .num { (source.bot_count) }
                                td {
                                    @match source.last_fetched_at {
                                        Some(at) => { (crate::web::dashboard::relative(at)) }
                                        None => { (layout::pill("NEVER", PillKind::Warn)) }
                                    }
                                }
                                td .right {
                                    form .inline method="post" action=(ctx.url("/bots/update-source")) {
                                        (layout::csrf_field(ctx))
                                        input type="hidden" name="source" value=(source.id);
                                        button type="submit" { "Update" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .panel-body {
                p .hint {
                    "Updating downloads the list from its publisher. On a host with no outbound "
                    "access, use "
                    code { "stop-bots update-bot-lists --source <file>" }
                    " instead."
                }
            }
        },
    )
}

fn bots_panel(view: &View, ctx: &Ctx) -> Markup {
    let hint = format!("{} known bots", view.total);
    layout::panel(
        "Bots",
        Some(&hint),
        html! {
            .panel-body {
                form .row method="get" action=(ctx.url("/bots")) {
                    input type="text" name="q" value=(view.query)
                        placeholder="Search by name or user-agent pattern" size="34";
                    button type="submit" { "Search" }
                    @if !view.query.is_empty() {
                        a .button href=(ctx.url("/bots")) { "Clear" }
                    }
                }
            }
            @if view.matches.is_empty() {
                (layout::empty("No bots match that search."))
            } @else {
                table {
                    thead { tr {
                        th { "Bot" }
                        th { "Categories" }
                        th { "Effective" }
                        th .right { "Override" }
                    } }
                    tbody {
                        @for bot in &view.matches {
                            tr {
                                td {
                                    (bot.name)
                                    br;
                                    span .hint .mono { (bot.user_agent_pattern) }
                                }
                                td { (categories_of(bot)) }
                                td {
                                    (effective_pill(bot, view.scanner, view.search, view.ai))
                                }
                                td .right { (override_form(bot, ctx)) }
                            }
                        }
                    }
                }
                @if view.truncated {
                    .panel-body {
                        p .hint {
                            "Showing the first " (MAX_RESULTS) ". Narrow the search to see the rest."
                        }
                    }
                }
            }
        },
    )
}

fn categories_of(bot: &Bot) -> Markup {
    html! {
        @if bot.is_scanner { (layout::pill("scanner", PillKind::Neutral)) " " }
        @if bot.is_search_engine { (layout::pill("search", PillKind::Neutral)) " " }
        @if bot.is_ai { (layout::pill("AI", PillKind::Neutral)) " " }
        @if !bot.is_scanner && !bot.is_search_engine && !bot.is_ai {
            span .hint { "uncategorised" }
        }
    }
}

/// What this bot actually gets, and whether that came from its own
/// override or from its category's default.
///
/// The distinction is the point: the TUI shows `(override)` or `(system)`
/// beside every row for it, because "why is this one allowed?" is the
/// question this screen exists to answer.
fn effective_pill(bot: &Bot, scanner: Policy, search: Policy, ai: Policy) -> Markup {
    let (blocked, source) = match bot.status {
        BotStatus::Blocked => (true, "override"),
        BotStatus::Allowed => (false, "override"),
        BotStatus::Default => (
            (bot.is_scanner && scanner == Policy::Blocked)
                || (bot.is_search_engine && search == Policy::Blocked)
                || (bot.is_ai && ai == Policy::Blocked),
            "category default",
        ),
    };
    html! {
        @if blocked {
            (layout::pill("BLOCKED", PillKind::Blocked))
        } @else {
            (layout::pill("ALLOWED", PillKind::Allowed))
        }
        " "
        span .hint { (source) }
    }
}

fn override_form(bot: &Bot, ctx: &Ctx) -> Markup {
    html! {
        form .inline method="post" action=(ctx.url("/bots/status")) {
            (layout::csrf_field(ctx))
            input type="hidden" name="slug" value=(bot.slug);
            select name="status" data-autosubmit {
                @for (value, label) in [
                    ("default", "Follow category"),
                    ("allowed", "Always allow"),
                    ("blocked", "Always block"),
                ] {
                    @if status_id(bot.status) == value {
                        option value=(value) selected { (label) }
                    } @else {
                        option value=(value) { (label) }
                    }
                }
            }
                    // Always rendered, not tucked inside <noscript>: the
                    // auto-submit is an enhancement, and a control that
                    // silently does nothing when script is unavailable is
                    // worse than one extra button.
                    button type="submit" { "Set" }
        }
    }
}

fn status_id(status: BotStatus) -> &'static str {
    match status {
        BotStatus::Default => "default",
        BotStatus::Allowed => "allowed",
        BotStatus::Blocked => "blocked",
    }
}

fn status_from(id: &str) -> Option<BotStatus> {
    match id {
        "default" => Some(BotStatus::Default),
        "allowed" => Some(BotStatus::Allowed),
        "blocked" => Some(BotStatus::Blocked),
        _ => None,
    }
}

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/bots/status"), post(set_status))
        .route(&base.url("/bots/update-source"), post(update_source))
}

#[derive(Deserialize)]
struct StatusForm {
    slug: String,
    status: String,
}

async fn set_status(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<StatusForm>,
) -> Response {
    let Some(status) = status_from(&form.status) else {
        return back_with(&state.base, "/bots", "Unknown bot status.", false);
    };
    let slug = form.slug;
    let stored = slug.clone();
    match state
        .with_db(move |db| db.set_bot_status(&stored, status))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/bots",
            &format!(
                "{slug} now: {}. Apply on Site settings to write it out.",
                form.status
            ),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/bots",
            &format!("Could not change {slug}: {err}"),
            false,
        ),
    }
}

#[derive(Deserialize)]
struct SourceForm {
    source: String,
}

/// Downloads one bot list and stores it.
///
/// The fetch happens *outside* `with_db`, deliberately. `with_db` holds
/// the single database lock for the whole closure, and a network request
/// under that lock would stall every other request in the console for as
/// long as the publisher takes to answer. Fetch, parse, then take the lock
/// to store — the same split `App::start_source_update` makes for the TUI.
async fn update_source(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<SourceForm>,
) -> Response {
    let Some(kind) = SourceKind::from_id(&form.source) else {
        return back_with(
            &state.base,
            "/bots",
            &format!("Unknown source: {}", form.source),
            false,
        );
    };

    let raw = match kind.fetch().await {
        Ok(raw) => raw,
        Err(err) => {
            return back_with(
                &state.base,
                "/bots",
                &format!("Could not download {}: {err}", kind.name()),
                false,
            )
        }
    };

    let stored = state
        .with_db(move |db| {
            let bots = kind.parse(&raw)?;
            botlist::store(db, kind, &bots)
        })
        .await;

    match stored {
        Ok(count) => back_with(
            &state.base,
            "/bots",
            &format!("{}: {count} bot(s).", kind.name()),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/bots",
            &format!("Could not store {}: {err}", kind.name()),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewBot;

    fn seeded() -> Db {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        for (slug, name, ai, search, scanner) in [
            ("gptbot", "GPTBot", true, false, false),
            ("googlebot", "Googlebot", false, true, false),
            ("nikto", "Nikto", false, false, true),
        ] {
            db.upsert_bot(&NewBot {
                slug: slug.into(),
                name: name.into(),
                is_ai: ai,
                is_search_engine: search,
                is_scanner: scanner,
                user_agent_pattern: slug.into(),
                source_id: "well-known-bots".into(),
            })
            .unwrap();
        }
        db
    }

    #[test]
    fn status_ids_round_trip() {
        for status in [BotStatus::Default, BotStatus::Allowed, BotStatus::Blocked] {
            assert_eq!(status_from(status_id(status)), Some(status));
        }
        assert_eq!(status_from("nonsense"), None);
    }

    #[test]
    fn search_matches_name_slug_and_pattern() {
        let db = seeded();

        assert_eq!(load(&db, "GPT").unwrap().matches.len(), 1, "by name");
        assert_eq!(load(&db, "nikto").unwrap().matches.len(), 1, "by slug");
        assert_eq!(
            load(&db, "bot").unwrap().matches.len(),
            2,
            "GPTBot and Googlebot, not Nikto"
        );
        assert!(load(&db, "no-such-bot").unwrap().matches.is_empty());
    }

    #[test]
    fn an_empty_search_shows_bots_rather_than_an_empty_screen() {
        let db = seeded();
        let view = load(&db, "").unwrap();
        assert_eq!(view.matches.len(), 3);
        assert_eq!(view.total, 3);
    }

    #[test]
    fn results_are_ordered_by_name_regardless_of_insertion_order() {
        let db = seeded();
        let names: Vec<String> = load(&db, "")
            .unwrap()
            .matches
            .iter()
            .map(|b| b.name.clone())
            .collect();
        assert_eq!(names, ["Googlebot", "GPTBot", "Nikto"]);
    }

    #[test]
    fn an_override_is_labelled_differently_from_a_category_default() {
        let db = seeded();
        db.set_category_default(Category::Ai, Policy::Blocked)
            .unwrap();
        db.set_bot_status("googlebot", BotStatus::Blocked).unwrap();

        let view = load(&db, "").unwrap();
        let gptbot = view.matches.iter().find(|b| b.slug == "gptbot").unwrap();
        let googlebot = view.matches.iter().find(|b| b.slug == "googlebot").unwrap();

        let ai = effective_pill(gptbot, view.scanner, view.search, view.ai).into_string();
        assert!(
            ai.contains("BLOCKED") && ai.contains("category default"),
            "was: {ai}"
        );

        let manual = effective_pill(googlebot, view.scanner, view.search, view.ai).into_string();
        assert!(
            manual.contains("BLOCKED") && manual.contains("override"),
            "was: {manual}"
        );
    }

    #[test]
    fn the_result_list_is_capped() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        for i in 0..(MAX_RESULTS + 10) {
            db.upsert_bot(&NewBot {
                slug: format!("bot-{i:04}"),
                name: format!("Bot {i:04}"),
                is_ai: false,
                is_search_engine: false,
                is_scanner: false,
                user_agent_pattern: format!("bot-{i:04}"),
                source_id: "well-known-bots".into(),
            })
            .unwrap();
        }

        let view = load(&db, "").unwrap();
        assert_eq!(view.matches.len(), MAX_RESULTS);
        assert!(
            view.truncated,
            "the page must say it is not showing everything"
        );
    }

    #[test]
    fn every_form_carries_the_csrf_token() {
        let db = seeded();
        let view = load(&db, "").unwrap();
        let rendered = body(&view, &Ctx::new("the-token", Default::default())).into_string();

        // The search form is a GET and needs no token; every POST does.
        let posts = rendered.matches(r#"method="post""#).count();
        let tokens = rendered.matches(r#"name="csrf" value="the-token""#).count();
        assert_eq!(posts, tokens, "{posts} POST form(s) but {tokens} token(s)");
    }

    #[test]
    fn a_bot_name_from_a_downloaded_list_cannot_inject_markup() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        db.upsert_bot(&NewBot {
            slug: "evil".into(),
            name: "<img src=x onerror=alert(1)>".into(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "evil".into(),
            source_id: "well-known-bots".into(),
        })
        .unwrap();

        let view = load(&db, "").unwrap();
        let rendered = body(&view, &Ctx::for_tests()).into_string();
        assert!(
            !rendered.contains("<img src=x"),
            "bot names come from a third-party download and must be escaped: {rendered}"
        );
    }
}
