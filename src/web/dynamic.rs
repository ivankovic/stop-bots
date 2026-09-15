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

//! Dynamic Protection: what is hitting the server right now, and one
//! click to block it.
//!
//! The model is [`crate::dynamic`], shared with the TUI screen of the same
//! name — see there for how a row's status is decided.

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::post;
use axum::{Form, Router};
use maud::{html, Markup};
use serde::Deserialize;

use crate::db::Category;
use crate::dynamic::{Filter, Live, RowStatus, SshRow, UaRow};
use crate::ipdetail::{AddressKind, IpDetail};
use crate::uadetail::UaDetail;
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{back_with, internal_error, render, Auth, ClientAddr, FlashQuery};
use crate::web::state::AppState;

/// Query parameters this screen understands.
#[derive(Debug, Default, Deserialize)]
pub struct Params {
    /// `all`, `pending` or `blocked` — the TUI's `f` key, as a link.
    pub filter: Option<String>,
    /// An address to show the detail panel for — the TUI's `i` key, as a
    /// link. A query parameter rather than an htmx fragment so the panel
    /// survives a reload and can be linked to, the same shape `filter`
    /// already uses. Untrusted: it is whatever is in the URL bar, and
    /// `IpDetail::load` is what decides whether it is an address at all.
    pub inspect: Option<String>,
    /// A user agent to show the detail panel for — the same idea as
    /// `inspect`, and a separate parameter rather than a shared one
    /// because the two resolve against different tables. Sharing it would
    /// mean a stale link looking an address up as a user agent, which
    /// answers a question nobody asked instead of failing.
    pub inspect_ua: Option<String>,
    #[serde(flatten)]
    pub flash: FlashQuery,
}

fn filter_from(name: Option<&str>) -> Filter {
    match name {
        Some("pending") => Filter::PendingOnly,
        Some("blocked") => Filter::BlockedOnly,
        _ => Filter::All,
    }
}

fn filter_name(filter: Filter) -> &'static str {
    match filter {
        Filter::All => "all",
        Filter::PendingOnly => "pending",
        Filter::BlockedOnly => "blocked",
    }
}

pub async fn page(
    State(state): State<AppState>,
    auth: Auth,
    Query(params): Query<Params>,
) -> Response {
    let filter = filter_from(params.filter.as_deref());
    let inspect = params.inspect.clone();
    let inspect_ua = params.inspect_ua.clone();
    let ssh_log = state.ssh_log.clone();

    // The log read happens inside the same blocking closure as the
    // database work. It has to be off the async runtime either way — on a
    // host with no readable auth.log this shells out to `journalctl`,
    // which the TUI measured at over half a second.
    let live = state
        .with_db(move |db| {
            let text = match &ssh_log {
                Some(path) => crate::sshlog::read_log_file(path),
                None => crate::sshlog::find_default_source(),
            };
            let text = match text {
                crate::sshlog::LogSource::Found(text) => Some(text),
                crate::sshlog::LogSource::Unavailable => None,
            };
            let live = Live::load(db, text.as_deref())?;
            // In the same closure as the row load, from the same read of
            // the log: a detail panel assembled from a second, later read
            // would describe a different moment than the table beside it.
            let detail = match &inspect {
                Some(address) => {
                    let status = live
                        .ssh
                        .iter()
                        .find(|row| &row.address == address)
                        .map(|row| row.status)
                        .unwrap_or(RowStatus::Pending);
                    // Scanned for this one address, from the same read of
                    // the log the table came from. Nobody pays for it on a
                    // page view that is not inspecting anything.
                    let usernames = text
                        .as_deref()
                        .map(|t| crate::sshlog::failed_attempt_usernames_for(t, address))
                        .unwrap_or_default();
                    Some(crate::ipdetail::IpDetail::load(
                        db, address, status, usernames,
                    )?)
                }
                None => None,
            };
            // Same bargain as the address detail above: assembled from
            // the rows already loaded, so the panel and the table beside
            // it describe one moment.
            let ua_detail = match &inspect_ua {
                Some(user_agent) => {
                    let status = live
                        .user_agents
                        .iter()
                        .find(|row| &row.user_agent == user_agent)
                        .map(|row| row.status)
                        .unwrap_or(RowStatus::Pending);
                    Some(UaDetail::load(db, user_agent, status)?)
                }
                None => None,
            };
            anyhow::Ok((live, detail, ua_detail))
        })
        .await;

    let (live, detail, ua_detail) = match live {
        Ok(triple) => triple,
        Err(err) => return internal_error(&err.to_string()),
    };

    let ctx = Ctx::for_request(&auth.csrf, &state).await;
    render(
        Tab::Dynamic,
        &ctx,
        params.flash.into_flash(),
        body(&live, filter, detail.as_ref(), ua_detail.as_ref(), &ctx),
    )
}

fn body(
    live: &Live,
    filter: Filter,
    detail: Option<&IpDetail>,
    ua_detail: Option<&UaDetail>,
    ctx: &Ctx,
) -> Markup {
    let ssh: Vec<&SshRow> = live
        .ssh
        .iter()
        .filter(|r| filter.matches(r.status))
        .collect();
    let uas: Vec<&UaRow> = live
        .user_agents
        .iter()
        .filter(|r| filter.matches(r.status))
        .collect();

    let ssh_max = ssh.iter().map(|r| r.count).max().unwrap_or(0);
    let ua_max = uas.iter().map(|r| r.count).max().unwrap_or(0);

    html! {
        (filter_bar(filter, ctx))

        @if let Some(detail) = detail {
            (detail_panel(detail, filter, ctx))
        }
        @if let Some(detail) = ua_detail {
            (ua_detail_panel(detail, filter, ctx))
        }

        .cols {

        (layout::panel(
            "Failed SSH logins",
            Some("Addresses that tried to log in and failed"),
            html! {
                @if ssh.is_empty() {
                    (layout::empty(if live.ssh.is_empty() {
                        "Nothing in the SSH log — or no SSH log could be read on this host."
                    } else {
                        "No addresses match this filter."
                    }))
                } @else {
                    .table-scroll {
                        table {
                            colgroup {
                                col .w-count;
                                col .w-state;
                                col;
                                col .w-action;
                            }
                            thead { tr {
                                th .right { "Attempts" }
                                th { "State" }
                                th { "Address" }
                                th .right { "Action" }
                            } }
                            tbody {
                                @for row in &ssh {
                                    tr {
                                        td .num { (meter(row.count, ssh_max)) }
                                        td { (status_pill(row.status)) }
                                        td .mono {
                                            // The address itself is the
                                            // link: one less column to fit
                                            // at phone width, and the
                                            // thing you want to know more
                                            // about is the thing you click.
                                            a href=(inspect_url(&row.address, filter, ctx)) {
                                                (row.address)
                                            }
                                        }
                                        td .right { (address_action(row, ctx)) }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        ))

        (layout::panel(
            "Top user agents",
            Some("What is getting through, most-seen first"),
            html! {
                @if uas.is_empty() {
                    (layout::empty(if live.user_agents.is_empty() {
                        "No access-log statistics recorded yet. Run `stop-bots record-access-stats`, or wait for the scheduled pass."
                    } else {
                        "No user agents match this filter."
                    }))
                } @else {
                    .table-scroll {
                        table {
                            colgroup {
                                col .w-count;
                                col .w-state;
                                col;
                                col .w-action;
                            }
                            thead { tr {
                                th .right { "Hits" }
                                th { "State" }
                                th { "User agent" }
                                th .right { "Action" }
                            } }
                            tbody {
                                @for row in &uas {
                                    tr {
                                        // One line, truncated with an
                                        // ellipsis when it doesn't fit —
                                        // a wrapped user agent is three
                                        // rows tall and makes "twenty
                                        // rows" unpredictable. `title`
                                        // keeps the whole string a hover
                                        // away, and in the DOM.
                                        td .num { (meter(row.count, ua_max)) }
                                        td { (status_pill(row.status)) }
                                        td .mono title=(row.user_agent) {
                                            // The string itself is the
                                            // link, for the reason the
                                            // address is one above.
                                            a href=(inspect_ua_url(&row.user_agent, filter, ctx)) {
                                                (row.user_agent)
                                            }
                                        }
                                        td .right { (ua_action(row, ctx)) }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        ))

        }
    }
}

/// The shared display filter, as a segmented control. One control for
/// both tables because it is one filter — the TUI's `f` — and the
/// current segment is a class, not an inline style: the CSP's
/// `style-src 'self'` drops a `style` attribute on the floor.
fn filter_bar(current: Filter, ctx: &Ctx) -> Markup {
    html! {
        .filterbar {
            span .hint { "Show" }
            .seg {
                @for (filter, label) in [
                    (Filter::All, "All"),
                    (Filter::PendingOnly, "Not blocked"),
                    (Filter::BlockedOnly, "Blocked"),
                ] {
                    @if filter == current {
                        a .on href=(ctx.url(&format!("/dynamic?filter={}", filter_name(filter)))) aria-current="true" { (label) }
                    } @else {
                        a href=(ctx.url(&format!("/dynamic?filter={}", filter_name(filter)))) { (label) }
                    }
                }
            }
        }
    }
}

/// A count with a bar beside it, scaled to the largest count in the same
/// table, so the shape of the traffic reads before the digits do.
///
/// The width is one of twenty classes rather than an inline `style`,
/// which the CSP would discard — see [`filter_bar`]. Twenty steps is as
/// fine as a 60px track can show.
fn meter(count: u64, max: u64) -> Markup {
    let step = if max == 0 || count == 0 {
        0
    } else {
        (count * 20).div_ceil(max).clamp(1, 20)
    };
    html! {
        (count)
        span .meter aria-hidden="true" {
            span class=(format!("bar p{step}")) {}
        }
    }
}

/// The link that opens the detail panel for `address`, keeping the current
/// filter so closing the panel returns to the same view.
///
/// Percent-encodes the address rather than trusting it to be one: these
/// come from a parsed log today, but this builds a URL, and a value
/// carrying `&` or `#` would otherwise silently become a different
/// parameter.
fn inspect_url(address: &str, filter: Filter, ctx: &Ctx) -> String {
    ctx.url(&format!(
        "/dynamic?filter={}&inspect={}",
        filter_name(filter),
        percent_encode(address)
    ))
}

/// The link that opens the user-agent detail panel, alongside
/// [`inspect_url`] rather than sharing it — see `Params::inspect_ua`.
///
/// The percent-encoding matters more here than it does for an address: a
/// user agent routinely contains `+`, `;` and `/`, and an attacker picks
/// the string, so anything less than encoding the whole unreserved-set
/// complement is a way to write a second query parameter.
fn inspect_ua_url(user_agent: &str, filter: Filter, ctx: &Ctx) -> String {
    ctx.url(&format!(
        "/dynamic?filter={}&inspect_ua={}",
        filter_name(filter),
        percent_encode(user_agent)
    ))
}

/// Percent-encodes everything outside the unreserved set. Deliberately
/// conservative and hand-rolled: one query parameter does not justify a
/// dependency, and the only way to get this wrong is to be too permissive.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn status_pill(status: RowStatus) -> Markup {
    let kind = match status {
        RowStatus::Pending => PillKind::Neutral,
        RowStatus::Blocked { .. } => PillKind::Blocked,
        // Distinct from a manual block on purpose: a blocklist match is
        // something a list decided, and un-blocking it here would not
        // stick — the next refresh of that list puts it back.
        RowStatus::Blocklist => PillKind::Warn,
        // Not a verdict, a gap: nothing on this host has an opinion about
        // it yet. `Neutral` would read as "allowed on purpose", which is
        // the one thing it is not.
        RowStatus::Unknown => PillKind::Warn,
    };
    layout::pill(&status.label(), kind)
}

/// The button for one SSH row.
///
/// A `BLOCKLIST` row gets none: the block came from a downloaded list, and
/// offering an "unblock" that the next list refresh silently undoes would
/// be a lie about what the button does.
/// The detail panel for one address.
///
/// Everything on it is already in this host's database — see
/// [`crate::ipdetail`] for why a console that can reach the network
/// deliberately does not do a reverse DNS lookup here.
fn detail_panel(detail: &IpDetail, filter: Filter, ctx: &Ctx) -> Markup {
    let close = ctx.url(&format!("/dynamic?filter={}", filter_name(filter)));
    layout::panel(
        &format!("About {}", detail.address),
        Some("From lists this host already downloads — nothing was looked up over the network"),
        html! {
            .row {
                (status_pill(detail.status))
                a .button href=(close) { "Close" }
            }

            @match detail.kind {
                AddressKind::LocalOrPrivate => {
                    p .hint {
                        "A loopback or private address. No reputation or crawler feed lists "
                        "these, so there is nothing to look up."
                    }
                }
                AddressKind::Malformed => {
                    p .hint { "Not a valid IP address or range." }
                }
                AddressKind::Public => {
                    @if detail.is_unknown() {
                        p .hint {
                            "In none of the crawler or reputation feeds this host has fetched."
                        }
                    }
                    @if !detail.crawlers.is_empty() || !detail.reputation.is_empty() {
                        table {
                            tbody {
                                @for hit in &detail.crawlers {
                                    tr {
                                        td { "Crawler" }
                                        td { (hit.source) }
                                        td .mono { (hit.range) }
                                    }
                                }
                                @for hit in &detail.reputation {
                                    tr {
                                        td { "Feed" }
                                        td { (hit.source) }
                                        td .mono { (hit.range) }
                                    }
                                }
                            }
                        }
                    }
                    p .hint {
                        @match (&detail.country, detail.country_data_available) {
                            (Some(code), _) => { "Country: " (code) }
                            // Not the same statement: with no zone file
                            // fetched this is a fact about the host's data,
                            // not about the address.
                            (None, true) => { "Not inside any country this host has fetched." }
                            (None, false) => { "No country data has been fetched on this host." }
                        }
                    }
                }
            }

            @if !detail.usernames.is_empty() {
                h3 { "Tried to log in as" }
                .table-scroll {
                    table {
                        colgroup { col .w-count; col; }
                        thead { tr {
                            th .right { "Attempts" }
                            th { "Account" }
                        } }
                        tbody {
                            @for (user, count) in &detail.usernames {
                                tr {
                                    td .num { (count) }
                                    // Attacker-chosen text. maud escapes
                                    // it, and `sshlog` has already capped
                                    // its length and replaced control
                                    // characters.
                                    td .mono { (user) }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// The detail panel for one user agent.
///
/// The counterpart to [`detail_panel`], and deliberately a different
/// shape: an address can be checked against a published range, while a
/// user agent is a string the client chose. Everything here is therefore
/// phrased as what the lists on this host say, not as what the client is
/// — see [`crate::uadetail`].
fn ua_detail_panel(detail: &UaDetail, filter: Filter, ctx: &Ctx) -> Markup {
    let close = ctx.url(&format!("/dynamic?filter={}", filter_name(filter)));
    layout::panel(
        "About this user agent",
        Some("What the bot lists on this host say about this string — a client can claim anything"),
        html! {
            .row {
                (status_pill(detail.status))
                a .button href=(close) { "Close" }
            }

            // Capped and stripped by `uadetail`; maud escapes it on top
            // of that.
            p .mono { (detail.user_agent) }
            @if detail.truncated {
                p .hint { "Shown truncated — the client sent a longer string." }
            }

            table {
                tbody {
                    tr {
                        td { "Requests" }
                        td {
                            @match detail.hits {
                                Some(hits) => { (hits) }
                                // Not "0": the tally is pruned on a
                                // schedule, and a row can go between the
                                // table being drawn and this click.
                                None => { "no longer counted" }
                            }
                        }
                    }
                    @if let Some(seen) = detail.last_seen_at {
                        tr {
                            td { "Last seen" }
                            td { (crate::health::format_utc(seen)) }
                        }
                    }
                    @if detail.blocked_by_hand {
                        tr {
                            td { "Blocked" }
                            td { "by hand, from this screen" }
                        }
                    }
                }
            }

            @if detail.matches.is_empty() {
                @if detail.self_declared_bot {
                    p .hint {
                        "This string calls itself a bot, and no list on this host has a "
                        "pattern for it. Blocking it here blocks this exact string."
                    }
                } @else {
                    p .hint { "No bot list on this host has a pattern matching this string." }
                }
            } @else {
                h3 { "Matched by" }
                .table-scroll {
                    table {
                        thead { tr {
                            th { "Bot" }
                            th { "Pattern" }
                            th { "Categories" }
                            th { "Lists" }
                            th { "Effect" }
                        } }
                        tbody {
                            @for hit in &detail.matches {
                                tr {
                                    td { (hit.name) }
                                    td .mono { (hit.pattern) }
                                    td { (category_names(&hit.categories)) }
                                    td { (hit.sources.join(", ")) }
                                    td {
                                        (layout::pill(
                                            hit.verdict.label(),
                                            if hit.verdict.is_blocked() {
                                                PillKind::Blocked
                                            } else {
                                                PillKind::Neutral
                                            },
                                        ))
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

/// The categories a matched bot carries, as prose. Empty is possible — a
/// list can catalogue something without filing it anywhere — and says so
/// rather than rendering a blank cell that reads as a bug.
fn category_names(categories: &[Category]) -> String {
    if categories.is_empty() {
        return "uncategorised".to_string();
    }
    categories
        .iter()
        .map(|category| match category {
            Category::Ai => "AI",
            Category::Search => "Search",
            Category::Scanner => "Scanner",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn address_action(row: &SshRow, ctx: &Ctx) -> Markup {
    match row.status {
        RowStatus::Blocklist => html! { span .hint { "from a blocklist" } },
        RowStatus::Blocked { .. } => html! {
            form .inline method="post" action=(ctx.url("/dynamic/unblock-address")) {
                (layout::csrf_field(ctx))
                input type="hidden" name="address" value=(row.address);
                button type="submit" { "Unblock" }
            }
        },
        // `Unknown` is about a user agent, and these rows are addresses,
        // so it cannot arise here — it gets the same Block button as
        // `Pending` rather than its own arm, which would be dead code
        // pretending to be a decision.
        RowStatus::Pending | RowStatus::Unknown => html! {
            form .inline method="post" action=(ctx.url("/dynamic/block-address")) {
                (layout::csrf_field(ctx))
                input type="hidden" name="address" value=(row.address);
                button .danger type="submit" { "Block" }
            }
        },
    }
}

fn ua_action(row: &UaRow, ctx: &Ctx) -> Markup {
    match row.status {
        RowStatus::Blocklist => html! { span .hint { "from a bot list" } },
        RowStatus::Blocked { .. } => html! {
            form .inline method="post" action=(ctx.url("/dynamic/unblock-ua")) {
                (layout::csrf_field(ctx))
                input type="hidden" name="user_agent" value=(row.user_agent);
                button type="submit" { "Unblock" }
            }
        },
        // Same action either way — the tag says why it is worth looking
        // at, the button does the same thing.
        RowStatus::Pending | RowStatus::Unknown => html! {
            form .inline method="post" action=(ctx.url("/dynamic/block-ua")) {
                (layout::csrf_field(ctx))
                input type="hidden" name="user_agent" value=(row.user_agent);
                button .danger type="submit" { "Block" }
            }
        },
    }
}

// ---- actions ----

pub fn actions(base: &crate::web::BasePath) -> Router<AppState> {
    Router::new()
        .route(&base.url("/dynamic/block-address"), post(block_address))
        .route(&base.url("/dynamic/unblock-address"), post(unblock_address))
        .route(&base.url("/dynamic/block-ua"), post(block_ua))
        .route(&base.url("/dynamic/unblock-ua"), post(unblock_ua))
}

#[derive(Deserialize)]
pub struct AddressForm {
    pub address: String,
}

#[derive(Deserialize)]
pub struct UserAgentForm {
    pub user_agent: String,
}

/// Blocks an address, unless it is the one asking.
///
/// The anti-lockout guard, and the web equivalent of
/// `firewall::assess_lockout_risk`. Blocking the address your own browser
/// is connecting from takes away the console you would use to undo it —
/// and unlike the SSH case there is no second way in that this tool is not
/// also managing.
async fn block_address(
    State(state): State<AppState>,
    axum::Extension(client): axum::Extension<ClientAddr>,
    _auth: Auth,
    Form(form): Form<AddressForm>,
) -> Response {
    let address = form.address;

    if let Some(reason) = would_lock_out(&client, &address) {
        return back_with(&state.base, "/dynamic", &reason, false);
    }

    let stored = address.clone();
    match state
        .with_db(move |db| db.block_address_permanently(&stored))
        .await
    {
        Ok(()) => back_with(
            &state.base,
            "/dynamic",
            &format!("Blocked {address}."),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/dynamic",
            &format!("Could not block {address}: {err}"),
            false,
        ),
    }
}

/// Whether blocking `address` would cut off the browser that asked, and
/// why.
///
/// The web equivalent of `firewall::assess_lockout_risk`, and needed for a
/// sharper reason than the SSH one: blocking the address your own browser
/// is connected from takes away the console you would use to undo it.
///
/// A `None` client address means this server could not tell where the
/// request came from, and the block goes ahead. That is the honest
/// behaviour — refusing every block because the address is unknown would
/// make the tool useless in exactly the deployment (behind a proxy, header
/// untrusted) where it is most wanted.
fn would_lock_out(client: &ClientAddr, address: &str) -> Option<String> {
    match client.0.as_deref() {
        Some(client) if client == address => Some(format!(
            "Refusing to block {address} — that is where this request came from, and blocking \
             it would lock you out of this console."
        )),
        _ => None,
    }
}

async fn unblock_address(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<AddressForm>,
) -> Response {
    let address = form.address;
    let stored = address.clone();
    match state.with_db(move |db| db.unblock_address(&stored)).await {
        Ok(()) => back_with(
            &state.base,
            "/dynamic",
            &format!("Unblocked {address}."),
            true,
        ),
        Err(err) => back_with(
            &state.base,
            "/dynamic",
            &format!("Could not unblock {address}: {err}"),
            false,
        ),
    }
}

async fn block_ua(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<UserAgentForm>,
) -> Response {
    let ua = form.user_agent;
    let stored = ua.clone();
    match state.with_db(move |db| db.block_user_agent(&stored)).await {
        Ok(()) => back_with(&state.base, "/dynamic", "Blocked that user agent.", true),
        Err(err) => back_with(
            &state.base,
            "/dynamic",
            &format!("Could not block that user agent: {err}"),
            false,
        ),
    }
}

async fn unblock_ua(
    State(state): State<AppState>,
    _auth: Auth,
    Form(form): Form<UserAgentForm>,
) -> Response {
    let ua = form.user_agent;
    let stored = ua.clone();
    match state
        .with_db(move |db| db.unblock_user_agent(&stored))
        .await
    {
        Ok(()) => back_with(&state.base, "/dynamic", "Unblocked that user agent.", true),
        Err(err) => back_with(
            &state.base,
            "/dynamic",
            &format!("Could not unblock that user agent: {err}"),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_query_maps_to_the_shared_filter() {
        assert_eq!(filter_from(None), Filter::All);
        assert_eq!(filter_from(Some("all")), Filter::All);
        assert_eq!(filter_from(Some("pending")), Filter::PendingOnly);
        assert_eq!(filter_from(Some("blocked")), Filter::BlockedOnly);
        assert_eq!(
            filter_from(Some("nonsense")),
            Filter::All,
            "an unknown filter shows everything rather than nothing"
        );
    }

    #[test]
    fn filter_names_round_trip() {
        for filter in [Filter::All, Filter::PendingOnly, Filter::BlockedOnly] {
            assert_eq!(filter_from(Some(filter_name(filter))), filter);
        }
    }

    #[test]
    fn a_blocklist_row_offers_no_button_that_would_not_stick() {
        let row = SshRow {
            address: "192.0.2.1".into(),
            count: 3,
            status: RowStatus::Blocklist,
        };
        let rendered = address_action(&row, &Ctx::for_tests()).into_string();

        assert!(
            !rendered.contains("<form"),
            "an unblock the next list refresh undoes must not be offered: {rendered}"
        );
        assert!(rendered.contains("from a blocklist"));
    }

    #[test]
    fn a_pending_row_offers_block_and_a_blocked_row_offers_unblock() {
        let pending = SshRow {
            address: "192.0.2.1".into(),
            count: 3,
            status: RowStatus::Pending,
        };
        let blocked = SshRow {
            status: RowStatus::Blocked { until: None },
            ..pending.clone()
        };

        assert!(address_action(&pending, &Ctx::for_tests())
            .into_string()
            .contains("/dynamic/block-address"));
        assert!(address_action(&blocked, &Ctx::for_tests())
            .into_string()
            .contains("/dynamic/unblock-address"));
    }

    #[test]
    fn every_action_form_carries_the_csrf_token() {
        let row = SshRow {
            address: "192.0.2.1".into(),
            count: 1,
            status: RowStatus::Pending,
        };
        let ua = UaRow {
            user_agent: "curl/8".into(),
            count: 1,
            status: RowStatus::Pending,
        };

        for rendered in [
            address_action(&row, &Ctx::new("the-token", Default::default())).into_string(),
            ua_action(&ua, &Ctx::new("the-token", Default::default())).into_string(),
        ] {
            assert!(
                rendered.contains(r#"name="csrf" value="the-token""#),
                "a form without the token would be rejected: {rendered}"
            );
        }
    }

    fn live_with(ssh: usize, uas: usize) -> Live {
        Live {
            ssh: (0..ssh)
                .map(|i| SshRow {
                    address: format!("192.0.2.{i}"),
                    count: i as u64,
                    status: RowStatus::Pending,
                })
                .collect(),
            user_agents: (0..uas)
                .map(|i| UaRow {
                    user_agent: format!("SomeCrawler/{i}.0"),
                    count: i as u64,
                    status: RowStatus::Pending,
                })
                .collect(),
        }
    }

    /// Both long tables scroll inside their panel rather than running the
    /// page down to whatever the logs happened to contain. The row cap
    /// itself is CSS (`--table-rows-visible`); what has to be true of the
    /// markup is that the wrapper and the fixed-layout column widths are
    /// there, because without them the cap has nothing to apply to and
    /// the truncation has no width to truncate against.
    #[test]
    fn both_long_tables_are_wrapped_in_a_scroll_container() {
        let rendered = body(
            &live_with(40, 40),
            Filter::All,
            None,
            None,
            &Ctx::for_tests(),
        )
        .into_string();

        assert_eq!(
            rendered.matches(r#"class="table-scroll""#).count(),
            2,
            "both tables scroll, or neither does: {rendered}"
        );
        assert_eq!(rendered.matches(r#"<col class="w-count">"#).count(), 2);
        assert_eq!(rendered.matches(r#"<col class="w-action">"#).count(), 2);
    }

    /// A user agent is truncated to one line so that a row's height is
    /// predictable, which is only acceptable because the whole string
    /// stays in the document as the cell's `title`. If that attribute
    /// ever stops being emitted, truncation starts losing information.
    #[test]
    fn a_truncated_user_agent_keeps_the_whole_string_in_its_title() {
        let long = "Mozilla/5.0 (compatible; SomeVeryLongCrawlerName/9.9; +https://example.com/a-page-about-the-crawler)";
        let live = Live {
            ssh: vec![],
            user_agents: vec![UaRow {
                user_agent: long.into(),
                count: 7,
                status: RowStatus::Pending,
            }],
        };

        let rendered = body(&live, Filter::All, None, None, &Ctx::for_tests()).into_string();

        assert!(
            rendered.contains(&format!(r#"title="{long}""#)),
            "was: {rendered}"
        );
    }

    /// The `title` attribute is a second place attacker-controlled text
    /// reaches markup, and it was added after the escaping test below.
    #[test]
    fn a_hostile_user_agent_cannot_break_out_of_the_title_attribute() {
        let live = Live {
            ssh: vec![],
            user_agents: vec![UaRow {
                user_agent: r#"" autofocus onfocus="alert(1)"#.into(),
                count: 1,
                status: RowStatus::Pending,
            }],
        };

        let rendered = body(&live, Filter::All, None, None, &Ctx::for_tests()).into_string();

        assert!(
            !rendered.contains(r#"onfocus="alert(1)"#),
            "the quote must be escaped, not closed: {rendered}"
        );
    }

    #[test]
    fn a_hostile_user_agent_cannot_break_out_of_the_value_attribute() {
        // Every string on this screen is attacker-supplied. The one that
        // reaches an HTML attribute is the interesting case.
        let ua = UaRow {
            user_agent: r#"" autofocus onfocus="alert(1)"#.into(),
            count: 1,
            status: RowStatus::Pending,
        };
        let rendered = ua_action(&ua, &Ctx::for_tests()).into_string();

        assert!(
            !rendered.contains("onfocus=\"alert(1)"),
            "the quote must be escaped, not closed: {rendered}"
        );
        assert!(rendered.contains("&quot;"), "was: {rendered}");
    }
    #[test]
    fn percent_encode_escapes_everything_that_could_start_a_new_parameter() {
        assert_eq!(percent_encode("198.51.100.9"), "198.51.100.9");
        assert_eq!(percent_encode("2001:db8::1"), "2001%3Adb8%3A%3A1");
        assert_eq!(percent_encode("a&b=c#d"), "a%26b%3Dc%23d");
    }

    /// Closing the panel must land back on the view it was opened from,
    /// not on the unfiltered default.
    #[test]
    fn the_inspect_link_carries_the_current_filter() {
        let url = inspect_url("198.51.100.9", Filter::BlockedOnly, &Ctx::for_tests());

        assert!(url.contains("filter=blocked"), "url was: {url}");
        assert!(url.contains("inspect=198.51.100.9"), "url was: {url}");
    }

    fn ua_detail(matches: Vec<crate::uadetail::BotMatch>) -> UaDetail {
        UaDetail {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string(),
            truncated: false,
            status: RowStatus::Blocklist,
            hits: Some(412),
            last_seen_at: Some(1_700_000_000),
            blocked_by_hand: false,
            matches,
            self_declared_bot: true,
        }
    }

    fn bot_match(verdict: crate::uadetail::BotVerdict) -> crate::uadetail::BotMatch {
        crate::uadetail::BotMatch {
            slug: "googlebot".to_string(),
            name: "Googlebot".to_string(),
            pattern: "Googlebot".to_string(),
            categories: vec![Category::Search],
            sources: vec!["Well-known bots".to_string()],
            verdict,
        }
    }

    /// The user agent's cell is the link, the same shape the address
    /// column uses — the thing you want to know more about is the thing
    /// you click.
    #[test]
    fn the_user_agent_cell_links_to_its_own_detail_panel() {
        let live = live_with(0, 1);

        let rendered = body(&live, Filter::All, None, None, &Ctx::for_tests()).into_string();

        assert!(
            rendered.contains("inspect_ua=SomeCrawler%2F0.0"),
            "no user-agent link: {rendered}"
        );
    }

    /// A user agent routinely carries `+`, `;` and `/`, and the client
    /// picks the string — anything less than encoding the whole
    /// complement of the unreserved set is a way to write a second query
    /// parameter.
    #[test]
    fn the_user_agent_link_encodes_a_string_that_could_forge_a_parameter() {
        let url = inspect_ua_url("a&inspect=1.2.3.4", Filter::PendingOnly, &Ctx::for_tests());

        assert!(url.contains("filter=pending"), "url was: {url}");
        assert!(!url.contains("&inspect=1.2.3.4"), "url was: {url}");
        assert!(
            url.contains("inspect_ua=a%26inspect%3D1.2.3.4"),
            "url was: {url}"
        );
    }

    /// The four-way verdict is the reason the panel exists: "blocked"
    /// alone does not say whether un-blocking means clearing an override
    /// or changing a category default.
    #[test]
    fn the_user_agent_panel_says_which_list_matched_and_why_it_blocks() {
        let detail = ua_detail(vec![bot_match(
            crate::uadetail::BotVerdict::BlockedByCategory,
        )]);

        let rendered = ua_detail_panel(&detail, Filter::All, &Ctx::for_tests()).into_string();

        for needle in [
            "Googlebot",
            "Well-known bots",
            "Search",
            "blocked by category",
            "412",
        ] {
            assert!(rendered.contains(needle), "missing {needle}:\n{rendered}");
        }
    }

    /// An empty match list is not the same statement as a blocked one,
    /// and with a bot-shaped string it is the case the `UNKNOWN` tag
    /// exists to surface.
    #[test]
    fn a_user_agent_no_list_knows_says_so_rather_than_showing_an_empty_table() {
        let rendered =
            ua_detail_panel(&ua_detail(vec![]), Filter::All, &Ctx::for_tests()).into_string();

        assert!(
            rendered.contains("calls itself a bot"),
            "rendered:\n{rendered}"
        );
    }

    /// The whole string is client-chosen, which makes this panel the
    /// largest piece of attacker-authored text on the screen.
    #[test]
    fn a_hostile_user_agent_cannot_break_out_of_the_detail_panel() {
        let mut detail = ua_detail(vec![]);
        detail.user_agent = "<script>alert(1)</script>".to_string();

        let rendered = ua_detail_panel(&detail, Filter::All, &Ctx::for_tests()).into_string();

        assert!(!rendered.contains("<script>"), "rendered:\n{rendered}");
        assert!(rendered.contains("&lt;script&gt;"), "rendered:\n{rendered}");
    }

    /// The tally is pruned on a schedule, so a row can go between the
    /// table being drawn and the click. "No count" is not "zero hits".
    #[test]
    fn a_user_agent_with_no_tally_left_is_not_reported_as_zero_hits() {
        let mut detail = ua_detail(vec![]);
        detail.hits = None;
        detail.last_seen_at = None;

        let rendered = ua_detail_panel(&detail, Filter::All, &Ctx::for_tests()).into_string();

        assert!(
            rendered.contains("no longer counted"),
            "rendered:\n{rendered}"
        );
    }

    #[test]
    fn the_detail_panel_names_the_feeds_and_the_accounts_tried() {
        let detail = IpDetail {
            address: "185.220.101.7".to_string(),
            kind: AddressKind::Public,
            reputation: vec![crate::ipdetail::RangeHit {
                source: "Tor exit nodes".to_string(),
                range: "185.220.101.0/24".to_string(),
            }],
            crawlers: vec![],
            country: Some("NL".to_string()),
            country_data_available: true,
            status: RowStatus::Pending,
            usernames: vec![("root".to_string(), 9)],
        };

        let rendered = detail_panel(&detail, Filter::All, &Ctx::for_tests()).into_string();

        for needle in [
            "185.220.101.7",
            "Tor exit nodes",
            "185.220.101.0/24",
            "NL",
            "root",
        ] {
            assert!(rendered.contains(needle), "missing {needle}:\n{rendered}");
        }
    }

    /// The username is whatever the client offered, so it reaches the page
    /// as attacker-authored text.
    #[test]
    fn a_hostile_username_cannot_break_out_of_the_detail_table() {
        let detail = IpDetail {
            address: "198.51.100.9".to_string(),
            kind: AddressKind::Public,
            reputation: vec![],
            crawlers: vec![],
            country: None,
            country_data_available: false,
            status: RowStatus::Pending,
            usernames: vec![("<script>alert(1)</script>".to_string(), 1)],
        };

        let rendered = detail_panel(&detail, Filter::All, &Ctx::for_tests()).into_string();

        assert!(
            !rendered.contains("<script>"),
            "the username was not escaped:\n{rendered}"
        );
        assert!(rendered.contains("&lt;script&gt;"), "rendered:\n{rendered}");
    }

    /// "Not in any feed" and "no feed data on this host" are different
    /// claims, and only one of them is about the address.
    #[test]
    fn an_absent_country_is_not_reported_as_a_fact_about_the_address() {
        let base = IpDetail {
            address: "198.51.100.9".to_string(),
            kind: AddressKind::Public,
            reputation: vec![],
            crawlers: vec![],
            country: None,
            country_data_available: false,
            status: RowStatus::Pending,
            usernames: vec![],
        };

        let without_data = detail_panel(&base, Filter::All, &Ctx::for_tests()).into_string();
        let with_data = detail_panel(
            &IpDetail {
                country_data_available: true,
                ..base
            },
            Filter::All,
            &Ctx::for_tests(),
        )
        .into_string();

        assert!(
            without_data.contains("No country data has been fetched"),
            "rendered:\n{without_data}"
        );
        assert!(
            with_data.contains("Not inside any country"),
            "rendered:\n{with_data}"
        );
    }
}
