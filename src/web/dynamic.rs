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

use crate::dynamic::{Filter, Live, RowStatus, SshRow, UaRow};
use crate::web::layout::{self, Ctx, PillKind, Tab};
use crate::web::server::{back_with, internal_error, render, Auth, ClientAddr, FlashQuery};
use crate::web::state::AppState;

/// Query parameters this screen understands.
#[derive(Debug, Default, Deserialize)]
pub struct Params {
    /// `all`, `pending` or `blocked` — the TUI's `f` key, as a link.
    pub filter: Option<String>,
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
            Live::load(db, text.as_deref())
        })
        .await;

    let live = match live {
        Ok(live) => live,
        Err(err) => return internal_error(&err.to_string()),
    };

    let ctx = Ctx::new(auth.csrf.clone(), state.base.clone());
    render(
        Tab::Dynamic,
        &ctx,
        params.flash.into_flash(),
        body(&live, filter, &ctx),
    )
}

fn body(live: &Live, filter: Filter, ctx: &Ctx) -> Markup {
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

    html! {
        (filter_bar(filter, ctx))

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
                    table {
                        thead { tr {
                            th .right { "Attempts" }
                            th { "State" }
                            th { "Address" }
                            th .right { "Action" }
                        } }
                        tbody {
                            @for row in &ssh {
                                tr {
                                    td .num { (row.count) }
                                    td { (status_pill(row.status)) }
                                    td .mono { (row.address) }
                                    td .right { (address_action(row, ctx)) }
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
                    table {
                        thead { tr {
                            th .right { "Hits" }
                            th { "State" }
                            th { "User agent" }
                            th .right { "Action" }
                        } }
                        tbody {
                            @for row in &uas {
                                tr {
                                    td .num { (row.count) }
                                    td { (status_pill(row.status)) }
                                    td .wrap .mono { (row.user_agent) }
                                    td .right { (ua_action(row, ctx)) }
                                }
                            }
                        }
                    }
                }
            },
        ))
    }
}

fn filter_bar(current: Filter, ctx: &Ctx) -> Markup {
    html! {
        .row style="margin-bottom:16px" {
            span .hint { "Show:" }
            @for (filter, label) in [
                (Filter::All, "All"),
                (Filter::PendingOnly, "Not blocked"),
                (Filter::BlockedOnly, "Blocked"),
            ] {
                @if filter == current {
                    a .button href=(ctx.url(&format!("/dynamic?filter={}", filter_name(filter))))
                        style="border-color:var(--accent);color:var(--accent);font-weight:600" { (label) }
                } @else {
                    a .button href=(ctx.url(&format!("/dynamic?filter={}", filter_name(filter)))) { (label) }
                }
            }
        }
    }
}

fn status_pill(status: RowStatus) -> Markup {
    let kind = match status {
        RowStatus::Pending => PillKind::Neutral,
        RowStatus::Blocked { .. } => PillKind::Blocked,
        // Distinct from a manual block on purpose: a blocklist match is
        // something a list decided, and un-blocking it here would not
        // stick — the next refresh of that list puts it back.
        RowStatus::Blocklist => PillKind::Warn,
    };
    layout::pill(&status.label(), kind)
}

/// The button for one SSH row.
///
/// A `BLOCKLIST` row gets none: the block came from a downloaded list, and
/// offering an "unblock" that the next list refresh silently undoes would
/// be a lie about what the button does.
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
        RowStatus::Pending => html! {
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
        RowStatus::Pending => html! {
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
}
