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

//! Blocks: every stored firewall rule, where it came from and why — the
//! TUI's screen 5 in a browser.
//!
//! A page of its own, like the TUI's screen, because it answers a
//! different question from Firewall (what the firewall holds, not what is
//! hitting the server) and can hold tens of thousands of rows. Those are
//! read [`PAGE`] at a time in the database (see `db::blocks`), so a page
//! costs the same on a host with fifty rules or fifty thousand.
//!
//! Everything is in the query string — source, search, page — so a view
//! can be linked to and survives a reload, and the actions post back to
//! the same view.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::blocks::{self, SourceFilter};
use crate::db::{BlockQuery, FirewallAction, FirewallRule};
use crate::web::firewall::percent_encode;
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{internal_error, render, Auth, FlashQuery};
use crate::web::state::AppState;

/// Rules per page.
pub const PAGE: usize = 100;

/// What the page is showing, from the query string.
#[derive(Debug, Default, Deserialize)]
pub struct Params {
    /// A source's name (`probe-paths`, `cli`, `before-0.1`, ...). Anything
    /// else shows every source.
    pub source: Option<String>,
    /// An address, part of one, or an address inside a blocked range.
    pub q: Option<String>,
    /// One-based.
    pub page: Option<usize>,
    /// Set by the "Unblock all" link: show the confirmation.
    pub confirm: Option<String>,
    #[serde(flatten)]
    pub flash: FlashQuery,
}

/// The view's state, as the form fields and links carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct View {
    source: Option<SourceFilter>,
    search: String,
    page: usize,
}

impl View {
    fn from_parts(source: Option<&str>, search: Option<&str>, page: Option<usize>) -> Self {
        View {
            source: source.and_then(SourceFilter::parse),
            search: search.unwrap_or_default().trim().to_string(),
            page: page.unwrap_or(1).max(1),
        }
    }

    fn query(&self) -> BlockQuery {
        BlockQuery {
            source: self.source,
            search: self.search.clone(),
        }
    }

    /// The URL of this view, with `page` in place of its own.
    fn url(&self, ctx: &Ctx, page: usize) -> String {
        let mut url = format!("/blocks?page={page}");
        if let Some(source) = self.source {
            url.push_str(&format!("&source={}", percent_encode(source.name())));
        }
        if !self.search.is_empty() {
            url.push_str(&format!("&q={}", percent_encode(&self.search)));
        }
        ctx.url(&url)
    }

    fn with_source(&self, source: Option<SourceFilter>) -> View {
        View {
            source,
            search: self.search.clone(),
            page: 1,
        }
    }
}

/// Everything one page shows, read in one `with_db`.
struct Loaded {
    rules: Vec<FirewallRule>,
    total: usize,
    sources: Vec<(SourceFilter, usize)>,
    unblocked: usize,
    logins: usize,
    trusted: usize,
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(params): Query<Params>,
) -> Response {
    let view = View::from_parts(params.source.as_deref(), params.q.as_deref(), params.page);
    let query = view.query();
    let page = view.page;
    let loaded = state
        .with_db(move |db| {
            let total = db.count_blocks(&query)?;
            // A page past the end — a stale link, or the last rule on it
            // just unblocked — shows the last page rather than nothing.
            let last = total.div_ceil(PAGE).max(1);
            let offset = (page.min(last) - 1) * PAGE;
            anyhow::Ok(Loaded {
                rules: db.blocks_page(&query, offset, PAGE)?,
                total,
                sources: db.block_source_counts()?,
                unblocked: db.unblocked_addresses()?.len(),
                logins: db.recent_ssh_login_ips()?.len(),
                trusted: db.list_trusted_addresses()?.len(),
            })
        })
        .await;
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(err) => return internal_error(&err.to_string()),
    };
    let view = View {
        page: view.page.min(loaded.total.div_ceil(PAGE).max(1)),
        ..view
    };
    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    let confirm = params.confirm.is_some();
    render(
        Tab::Blocks,
        &ctx,
        params.flash.into_flash(&state),
        body(&view, &loaded, confirm, &ctx),
    )
}

fn body(view: &View, loaded: &Loaded, confirm: bool, ctx: &Ctx) -> Markup {
    let now = blocks::now();
    let first = view.page.saturating_sub(1) * PAGE;
    let pages = loaded.total.div_ceil(PAGE).max(1);
    let source_count = view
        .source
        .and_then(|s| loaded.sources.iter().find(|(f, _)| *f == s))
        .map_or(0, |(_, count)| *count);
    html! {
        .filterbar {
            span .hint { "Source" }
            .seg.wrap {
                @let all = view.with_source(None);
                @if view.source.is_none() {
                    a .on href=(all.url(ctx, 1)) aria-current="true" { "All" }
                } @else {
                    a href=(all.url(ctx, 1)) { "All" }
                }
                @for (filter, count) in &loaded.sources {
                    @let link = view.with_source(Some(*filter)).url(ctx, 1);
                    @if view.source == Some(*filter) {
                        a .on href=(link) aria-current="true" { (filter.label()) " " (count) }
                    } @else {
                        a href=(link) { (filter.label()) " " (count) }
                    }
                }
            }
        }

        // The grid every screen uses, with both panels across its full
        // width: seven columns do not fit in half of it.
        .cols {
        @if confirm {
            @if let Some(source) = view.source {
                .span-all { (confirm_panel(view, source, source_count, ctx)) }
            }
        }

        .span-all { (layout::panel(
            "Blocks",
            Some("Every stored firewall rule, newest first, and why it is there"),
            html! {
                .panel-body {
                    form .row method="get" action=(ctx.url("/blocks")) {
                        @if let Some(source) = view.source {
                            input type="hidden" name="source" value=(source.name());
                        }
                        input type="search" name="q" value=(view.search)
                            placeholder="Address, or an address inside a blocked range" size="40";
                        button type="submit" { "Search" }
                        @if !view.search.is_empty() {
                            a .button href=(view.with_source(view.source).url_without_search(ctx)) { "Clear" }
                        }
                        @if let Some(source) = view.source {
                            @if source_count > 0 {
                                a .button.danger href=(format!("{}&confirm=1", view.url(ctx, view.page))) {
                                    "Unblock all " (source_count) " from " (source.label())
                                }
                            }
                        }
                    }
                    p .hint {
                        "Not listed here: " (loaded.logins) " SSH-login and " (loaded.trusted)
                        " trusted allow(s), which go ahead of every rule, and the downloaded lists and countries on the Dashboard. "
                        @if loaded.unblocked > 0 {
                            (loaded.unblocked) " address(es) unblocked by hand are left alone by the detectors for now."
                        }
                    }
                }
                @if loaded.rules.is_empty() {
                    (layout::empty(if loaded.total == 0 && view.source.is_none() && view.search.is_empty() {
                        "No firewall rules stored."
                    } else {
                        "No rules match."
                    }))
                } @else {
                    .table-wide {
                        table {
                            thead { tr {
                                th { "Address" }
                                th { "Verdict" }
                                th { "Source" }
                                th .right { "Added" }
                                th { "Expires" }
                                th { "Evidence" }
                                th .right { "Action" }
                            } }
                            tbody {
                                @for rule in &loaded.rules {
                                    (rule_row(rule, view, now, ctx))
                                }
                            }
                        }
                    }
                }
                .panel-body {
                    (pager(view, first, loaded.rules.len(), loaded.total, pages, ctx))
                }
            },
        )) }
        }
    }
}

impl View {
    fn url_without_search(&self, ctx: &Ctx) -> String {
        View {
            search: String::new(),
            ..self.clone()
        }
        .url(ctx, 1)
    }
}

fn rule_row(rule: &FirewallRule, view: &View, now: i64, ctx: &Ctx) -> Markup {
    let port = rule.port.map(|p| format!(":{p}")).unwrap_or_default();
    let (verdict, kind) = match rule.action {
        FirewallAction::Allow => ("allow", PillKind::Allowed),
        FirewallAction::Block => ("block", PillKind::Blocked),
        FirewallAction::Reject => ("reject", PillKind::Blocked),
    };
    html! {
        tr {
            td .mono.nowrap { (rule.address) (port) }
            td {
                (layout::pill(verdict, kind))
                @if !rule.enabled { " " span .hint { "off" } }
            }
            td .nowrap {
                a href=(view.with_source(Some(match rule.source {
                    Some(source) => SourceFilter::Source(source),
                    None => SourceFilter::Legacy,
                })).url(ctx, 1)) {
                    (blocks::source_label(rule.source))
                }
            }
            td .num.nowrap {
                @if let Some(at) = rule.created_at { (blocks::format_age(at, now)) " ago" }
            }
            td .nowrap {
                @match rule.expires_at {
                    Some(at) => { "in " (crate::dynamic::format_until(at)) }
                    None => span .hint { "never" },
                }
            }
            td .evidence {
                @match (&rule.evidence, rule.source) {
                    (Some(evidence), _) => (evidence),
                    (None, None) => span .hint { "before 0.1: not recorded" },
                    (None, Some(_)) => span .hint { "added by hand" },
                }
            }
            td .right {
                form .inline method="post" action=(ctx.url("/blocks/unblock")) {
                    (layout::csrf_field(ctx))
                    input type="hidden" name="id" value=(rule.id);
                    (view_fields(view))
                    button type="submit" {
                        @if rule.action == FirewallAction::Allow { "Remove" } @else { "Unblock" }
                    }
                }
            }
        }
    }
}

/// The view's state as hidden fields, so an action returns to it.
fn view_fields(view: &View) -> Markup {
    html! {
        @if let Some(source) = view.source {
            input type="hidden" name="source" value=(source.name());
        }
        @if !view.search.is_empty() {
            input type="hidden" name="q" value=(view.search);
        }
        input type="hidden" name="page" value=(view.page);
    }
}

fn pager(view: &View, first: usize, shown: usize, total: usize, pages: usize, ctx: &Ctx) -> Markup {
    html! {
        .row {
            span .hint {
                @if total == 0 { "0 rules" } @else {
                    "Rules " (first + 1) "\u{2013}" (first + shown) " of " (total)
                    ", page " (view.page) " of " (pages)
                }
            }
            @if view.page > 1 {
                a .button href=(view.url(ctx, 1)) { "First" }
                a .button href=(view.url(ctx, view.page - 1)) { "Previous" }
            }
            @if view.page < pages {
                a .button href=(view.url(ctx, view.page + 1)) { "Next" }
                a .button href=(view.url(ctx, pages)) { "Last" }
            }
        }
    }
}

/// "Unblock all from this source", asked with the count before anything
/// happens.
fn confirm_panel(view: &View, source: SourceFilter, count: usize, ctx: &Ctx) -> Markup {
    let by_detector = matches!(source, SourceFilter::Source(s) if s.detector().is_some())
        || source == SourceFilter::Legacy;
    layout::panel(
        &format!("Unblock all {count} rule(s) from {}?", source.label()),
        None,
        html! {
            .panel-body {
                p {
                    "Every rule from this source is removed, not only the ones this page shows. "
                    @if by_detector {
                        "The detector leaves each address alone for as long as its block was meant to last; trust an address to exempt it for good. "
                    }
                    "Nothing changes on the host until the firewall script is written and applied."
                }
                form .row method="post" action=(ctx.url("/blocks/unblock-all")) {
                    (layout::csrf_field(ctx))
                    input type="hidden" name="source" value=(source.name());
                    input type="hidden" name="expected" value=(count);
                    button .danger type="submit" { "Unblock all " (count) }
                    a .button href=(view.url(ctx, view.page)) { "Cancel" }
                }
            }
        },
    )
}

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/blocks/unblock"), post(unblock))
        .route(&base.url("/blocks/unblock-all"), post(unblock_all))
}

#[derive(Deserialize)]
pub struct UnblockForm {
    pub id: i64,
    pub source: Option<String>,
    pub q: Option<String>,
    pub page: Option<usize>,
}

#[derive(Deserialize)]
pub struct UnblockAllForm {
    pub source: String,
    /// The count the confirmation showed. If more rules have arrived
    /// since, the operator agreed to a different number, and is asked
    /// again rather than surprised.
    pub expected: usize,
}

/// Back to `view`, with a flash.
fn back_to(state: &AppState, view: &View, message: &str, ok: bool) -> Response {
    let mut url = format!("/blocks?page={}", view.page);
    if let Some(source) = view.source {
        url.push_str(&format!("&source={}", percent_encode(source.name())));
    }
    if !view.search.is_empty() {
        url.push_str(&format!("&q={}", percent_encode(&view.search)));
    }
    Redirect::to(&crate::web::server::with_flash(
        &state.base.url(&url),
        state,
        message,
        ok,
    ))
    .into_response()
}

async fn unblock(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<UnblockForm>,
) -> Response {
    let view = View::from_parts(form.source.as_deref(), form.q.as_deref(), form.page);
    let id = form.id;
    let removed = state.with_db(move |db| db.remove_firewall_rule(id)).await;
    match removed {
        Ok(rule) => {
            let mut message = format!("Removed the rule for {}.", rule.address);
            if rule.source.and_then(|s| s.detector()).is_some() {
                message.push_str(" Its detector leaves it alone for now.");
            }
            message.push_str(" Apply everything to lift it on the host.");
            back_to(&state, &view, &message, true)
        }
        Err(err) => back_to(
            &state,
            &view,
            &format!("Could not remove that rule: {err}"),
            false,
        ),
    }
}

async fn unblock_all(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<UnblockAllForm>,
) -> Response {
    let Some(source) = SourceFilter::parse(&form.source) else {
        return back_to(&state, &View::default(), "No such source.", false);
    };
    let view = View {
        source: Some(source),
        search: String::new(),
        page: 1,
    };
    let expected = form.expected;
    let result = state
        .with_db(move |db| {
            // Under the console's lock; only a `batch` from cron could add
            // one between the two, and then it is removed too, which is
            // what "all from this source" asked for.
            let count = db.remove_firewall_rules_from(source, true)?;
            if count != expected {
                return anyhow::Ok(Err(count));
            }
            Ok(Ok(db.remove_firewall_rules_from(source, false)?))
        })
        .await;
    match result {
        Ok(Ok(removed)) => back_to(
            &state,
            &View::default(),
            &format!(
                "Removed {removed} rule(s) from {}. Apply everything to lift them on the host.",
                source.label()
            ),
            true,
        ),
        Ok(Err(now)) => back_to(
            &state,
            &view,
            &format!(
                "{} has {now} rule(s) now, not the {expected} you confirmed. Nothing was removed; look again.",
                source.label()
            ),
            false,
        ),
        Err(err) => back_to(
            &state,
            &view,
            &format!("Could not remove them: {err}"),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::RuleSource;
    use crate::protection::Detector;

    fn rule(address: &str, source: Option<RuleSource>, evidence: Option<&str>) -> FirewallRule {
        FirewallRule {
            id: 7,
            address: address.to_string(),
            port: None,
            action: FirewallAction::Block,
            enabled: true,
            expires_at: None,
            source,
            created_at: Some(blocks::now() - 7_200),
            evidence: evidence.map(str::to_string),
        }
    }

    fn loaded(rules: Vec<FirewallRule>) -> Loaded {
        Loaded {
            total: rules.len(),
            rules,
            sources: vec![(
                SourceFilter::Source(RuleSource::Detector(Detector::ProbePaths)),
                1,
            )],
            unblocked: 0,
            logins: 0,
            trusted: 0,
        }
    }

    fn page_html(view: &View, rules: Vec<FirewallRule>, confirm: bool) -> String {
        body(view, &loaded(rules), confirm, &Ctx::for_tests()).into_string()
    }

    #[test]
    fn a_row_shows_its_source_age_and_evidence() {
        let html = page_html(
            &View::default(),
            vec![rule(
                "203.0.113.5",
                Some(RuleSource::Detector(Detector::ProbePaths)),
                Some("\"GET /.env HTTP/1.1\" 404"),
            )],
            false,
        );
        for needle in ["203.0.113.5", "Probe paths", "2h ago", "GET /.env HTTP/1.1"] {
            assert!(html.contains(needle), "{needle:?} missing:\n{html}");
        }
    }

    /// Escaped like every other value: evidence is the attacker's text.
    #[test]
    fn hostile_evidence_is_escaped() {
        let html = page_html(
            &View::default(),
            vec![rule(
                "203.0.113.5",
                Some(RuleSource::Detector(Detector::ProbePaths)),
                Some("\"GET /<script>alert(1)</script> HTTP/1.1\" 404"),
            )],
            false,
        );
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
    }

    #[test]
    fn a_rule_from_before_0_1_says_so() {
        let html = page_html(&View::default(), vec![rule("192.0.2.1", None, None)], false);
        assert!(html.contains("before 0.1"), "{html}");
    }

    /// Every POST form carries the token, which is what the server checks.
    #[test]
    fn every_action_form_carries_the_csrf_token() {
        let view = View {
            source: Some(SourceFilter::Source(RuleSource::Detector(
                Detector::ProbePaths,
            ))),
            search: String::new(),
            page: 1,
        };
        let html = page_html(
            &view,
            vec![
                rule("203.0.113.5", None, None),
                rule("203.0.113.6", None, None),
            ],
            true,
        );
        let forms = html.matches("method=\"post\"").count();
        assert_eq!(forms, 3, "two unblocks and the confirmation");
        assert_eq!(html.matches("name=\"csrf\"").count(), forms);
    }

    /// The count is in the question, and the link is only offered for one
    /// source at a time.
    #[test]
    fn unblock_all_is_offered_for_a_source_and_confirmed_with_its_count() {
        let probes = SourceFilter::Source(RuleSource::Detector(Detector::ProbePaths));
        let all = page_html(&View::default(), vec![], false);
        assert!(!all.contains("Unblock all"), "{all}");

        let view = View {
            source: Some(probes),
            ..View::default()
        };
        let offered = page_html(&view, vec![], false);
        assert!(
            offered.contains("Unblock all 1 from Probe paths"),
            "{offered}"
        );

        let asked = page_html(&view, vec![], true);
        assert!(
            asked.contains("Unblock all 1 rule(s) from Probe paths?"),
            "{asked}"
        );
        assert!(asked.contains("name=\"expected\" value=\"1\""), "{asked}");
    }

    #[test]
    fn the_view_survives_in_every_link_and_form() {
        let view = View {
            source: Some(SourceFilter::Legacy),
            search: "203.0.113.7".into(),
            page: 2,
        };
        assert_eq!(
            view.url(&Ctx::for_tests(), 3),
            "/blocks?page=3&source=before-0.1&q=203.0.113.7"
        );
        let fields = view_fields(&view).into_string();
        for needle in [
            "value=\"before-0.1\"",
            "value=\"203.0.113.7\"",
            "value=\"2\"",
        ] {
            assert!(fields.contains(needle), "{needle}: {fields}");
        }
    }
}
