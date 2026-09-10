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

//! The Dynamic Protection screen: a live, actionable view of what's
//! currently hitting the server, split into two panels — "Top IPs
//! attempting SSH connection" and "Top User Agents" — each ranked by count
//! and tagged `NOT BLOCKED` or `BLOCKED` (rendered in red). `Tab`/`Shift+Tab`
//! switch which panel `Up`/`Down` (or `j`/`k`) move through; `f` cycles a
//! shared display filter (All / Not blocked only / Blocked only) applied to
//! both panels; `Enter` toggles the selected row's block state — blocks a
//! `NOT BLOCKED` row, unblocks a `BLOCKED` one. All of this is storage-only,
//! same as everywhere else in this codebase: (un)blocking an IP only adds
//! or removes a `firewall_rules` row (`render-firewall`, then applying the
//! script, is what actually enforces it — and its lockout-safety check
//! already guards against self-blocking a currently-connected SSH session,
//! so this screen doesn't duplicate that guard); (un)blocking a user agent
//! only adds or removes a row in `blocked_user_agents` (`apply-blocks`, or
//! Site settings' `a`/`A`, is what injects/removes it in NGINX config).
//!
//! Unlike the Dashboard's `cron_status`/`user_agent_stats` (both read
//! straight from `Db`), the SSH panel is populated by re-parsing the live
//! SSH log, which `App` reads in the background and hands to `refresh`
//! as text — there's no persisted "SSH attempt stats"
//! table, deliberately: this screen is a real-time view of the current
//! log, not a lifetime tally (that's what `sshlog::scanning_ips`/
//! `block-scanners` already handle, on their own cron cadence). The
//! User Agent panel *does* read from `Db::list_user_agent_stats` (the
//! same table `record-access-stats`/`RecordAccessStats` populate) since
//! that's already a cheap, pre-aggregated lifetime count — counting only
//! *successful* (non-4xx/5xx) requests, so a user agent already blocked by
//! an existing bot-category rule (and so 403'd before ever reaching this
//! tally) won't show up here; this panel is about traffic that's *getting
//! through*, not a complete traffic log.
//!
//! Both panels use the same `RowStatus`: `Pending` (no block on file yet,
//! rendered as "NOT BLOCKED") or `Blocked` (`until: Some(t)` for a temporary
//! `firewall_rules` block — e.g. one `block-scanners` already added — `None`
//! for permanent). Only the SSH panel can show a temporary `Blocked`; a
//! manually-blocked user agent is always permanent, since
//! [`crate::db::Db::block_user_agent`] has no TTL concept.
//!
//! `refresh` itself is deliberately thin: all the actual row-building logic lives
//! in [`build_ssh_rows`]/[`build_ua_rows`], pure functions tested directly
//! against synthetic counts below rather than through a real or faked log
//! file.

use crate::db::Db;
// The row model and the "is this already blocked?" decision live in
// `crate::dynamic`, shared with the web UI — see that module for why.
use crate::dynamic::{Filter, Live, RowStatus, SshRow, UaRow};
use crate::tui::{KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Style, Stylize},
    text::Line,
    widgets::{Block, List, ListItem, ListState},
    Frame,
};

/// Which of the two panels `Up`/`Down`/`Enter` currently apply to. Switched
/// with `Tab`/`Shift+Tab` (see the module doc comment for why that claims
/// the key on this screen instead of cycling top-level screens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Ssh,
    UserAgents,
}

#[derive(Debug, Default)]
pub struct DynamicProtection {
    ssh_rows: Vec<SshRow>,
    ua_rows: Vec<UaRow>,
    ssh_state: ListState,
    ua_state: ListState,
    focus: Focus,
    filter: Filter,
}

impl DynamicProtection {
    /// Reloads both panels. See the module doc comment for why the actual
    /// row-building logic lives in [`build_ssh_rows`]/[`build_ua_rows`]
    /// instead of here.
    ///
    /// `ssh_log_text` is the log itself, already read — this screen used to
    /// resolve and read it here, which meant a `journalctl` subprocess on
    /// every reload on any host without a readable `auth.log`. `App` owns
    /// that read now and does it in the background (`App::read_ssh_log`);
    /// `None` means it hasn't arrived yet, and renders as an empty SSH
    /// panel rather than as a wait.
    pub fn refresh(&mut self, db: &Db, ssh_log_text: Option<&str>) -> Result<()> {
        let live = Live::load(db, ssh_log_text)?;
        self.ssh_rows = live.ssh;
        self.ua_rows = live.user_agents;
        self.clamp_selections();
        Ok(())
    }

    /// Every SSH row currently passing [`Self::filter`], in display order —
    /// shared by rendering and by resolving which row `ssh_state`'s
    /// selected index actually points at, so the two can never disagree
    /// about what's on screen.
    fn visible_ssh_rows(&self) -> Vec<&SshRow> {
        self.ssh_rows
            .iter()
            .filter(|row| self.filter.matches(row.status))
            .collect()
    }

    /// The User Agent panel's equivalent of [`Self::visible_ssh_rows`].
    fn visible_ua_rows(&self) -> Vec<&UaRow> {
        self.ua_rows
            .iter()
            .filter(|row| self.filter.matches(row.status))
            .collect()
    }

    /// Re-clamps both panels' selections against their *filtered* (visible)
    /// lengths, not the full underlying row count — called after a reload
    /// and after the filter itself changes, since either can shrink or grow
    /// what's actually on screen out from under an existing selection.
    fn clamp_selections(&mut self) {
        let ssh_len = self.visible_ssh_rows().len();
        clamp_selection(&mut self.ssh_state, ssh_len);
        let ua_len = self.visible_ua_rows().len();
        clamp_selection(&mut self.ua_state, ua_len);
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Ssh => Focus::UserAgents,
                    Focus::UserAgents => Focus::Ssh,
                };
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.clamp_selections();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.active_state().select_previous();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.active_state().select_next();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter => self.toggle_block_selected(db, message),
            _ => Ok(KeyOutcome::Ignored),
        }
    }

    fn active_state(&mut self) -> &mut ListState {
        match self.focus {
            Focus::Ssh => &mut self.ssh_state,
            Focus::UserAgents => &mut self.ua_state,
        }
    }

    /// Toggles whichever row is selected in the currently focused panel
    /// (resolved against that panel's *filtered* rows — see
    /// [`Self::visible_ssh_rows`]/[`Self::visible_ua_rows`], since the
    /// selection index refers to a position on screen, not in the full
    /// underlying `ssh_rows`/`ua_rows`): a `NOT BLOCKED` row gets permanently
    /// blocked, a `Blocked` one gets unblocked. A no-op (still `Consumed`,
    /// not `Mutated`) if the panel is empty (or fully filtered out) —
    /// there's nothing to select. `Blocklist` rows are skipped (do nothing).
    fn toggle_block_selected(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        match self.focus {
            Focus::Ssh => {
                let Some(row) = self
                    .ssh_state
                    .selected()
                    .and_then(|i| self.visible_ssh_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                if row.status.is_blocklist() {
                    // Blocklist items cannot be toggled
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_blocked() {
                    db.unblock_address(&row.address)?;
                    *message = Some(format!(
                        "Unblocked {} — run render-firewall (then apply the script) to lift the enforced block.",
                        row.address
                    ));
                } else {
                    db.block_address_permanently(&row.address)?;
                    *message = Some(format!(
                        "Permanently blocked {} — run render-firewall (then apply the script) to enforce it.",
                        row.address
                    ));
                }
                Ok(KeyOutcome::Mutated)
            }
            Focus::UserAgents => {
                let Some(row) = self
                    .ua_state
                    .selected()
                    .and_then(|i| self.visible_ua_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                if row.status.is_blocklist() {
                    // Blocklist items cannot be toggled
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_blocked() {
                    db.unblock_user_agent(&row.user_agent)?;
                    *message = Some(format!(
                        "Unblocked user agent \"{}\" — run apply-blocks to remove it from NGINX config.",
                        row.user_agent
                    ));
                } else {
                    db.block_user_agent(&row.user_agent)?;
                    *message = Some(format!(
                        "Permanently blocked user agent \"{}\" — run apply-blocks to enforce it.",
                        row.user_agent
                    ));
                }
                Ok(KeyOutcome::Mutated)
            }
        }
    }

    /// `jobs` is `App`'s in-flight set, so the SSH panel can say when its
    /// contents are still on the way — the log read happens in the
    /// background now, and an empty panel with no explanation reads as
    /// "nothing to show" rather than "not here yet".
    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        jobs: &std::collections::HashSet<crate::app::Job>,
    ) {
        let [ssh_area, ua_area] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

        let reversed = Style::new().reversed();

        let reading = jobs.contains(&crate::app::Job::ReadSshLog);
        let ssh_items: Vec<ListItem> = empty_or(
            self.visible_ssh_rows()
                .into_iter()
                .map(ssh_row_line)
                .map(ListItem::new)
                .collect(),
            if reading {
                "Reading the SSH log…"
            } else if self.ssh_rows.is_empty() {
                "No failed SSH logins in the current log. Nothing to block — this is the good case."
            } else {
                "Nothing matches this filter. Press f to change it."
            },
        );
        let ssh_list = List::new(ssh_items)
            .block(
                Block::bordered()
                    .title(panel_title(
                        "Failed SSH logins",
                        self.filter.label(),
                        ssh_area.width,
                    ))
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::Ssh {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(ssh_list, ssh_area, &mut self.ssh_state);

        let ua_items: Vec<ListItem> = empty_or(
            self.visible_ua_rows()
                .into_iter()
                .map(ua_row_line)
                .map(ListItem::new)
                .collect(),
            if self.ua_rows.is_empty() {
                "No successful requests tallied yet. This fills in as traffic arrives,                  or run `stop-bots record-access-stats`."
            } else {
                "Nothing matches this filter. Press f to change it."
            },
        );
        let ua_list = List::new(ua_items)
            .block(
                Block::bordered()
                    .title(panel_title(
                        "Top user agents",
                        self.filter.label(),
                        ua_area.width,
                    ))
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::UserAgents {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(ua_list, ua_area, &mut self.ua_state);
    }
}

/// A panel title, with its key hints dropped when the terminal is too
/// narrow to hold them.
///
/// At 80 columns — the width this project documents as its minimum — the
/// old titles ran past the border and were cut mid-word, so the last
/// thing on screen was half a hint. What has to survive is the name of
/// the panel and which filter is on; the hints are in `?` too.
fn panel_title(name: &str, filter: &str, width: u16) -> String {
    let short = format!("{name} ({filter})");
    let full = format!("{short} — Enter block/unblock, f filter");
    if full.chars().count() + 2 <= width as usize {
        full
    } else {
        short
    }
}

/// A list's items, or a single dimmed line saying why there are none.
///
/// An empty bordered box reads as "this is broken", not as "nothing to
/// show" — and on this screen the second is the *good* outcome, so it is
/// worth saying out loud. Site settings already does this for its own
/// empty list; this is the same idea.
fn empty_or(items: Vec<ListItem<'static>>, message: &str) -> Vec<ListItem<'static>> {
    if items.is_empty() {
        vec![ListItem::new(Line::from(message.to_string()).dim())]
    } else {
        items
    }
}

fn ssh_row_line(row: &SshRow) -> Line<'static> {
    let line = Line::from(format!(
        "{:>8}  {:<24}  {}",
        row.count,
        row.status.label(),
        row.address
    ));
    style_by_status(line, row.status)
}

fn ua_row_line(row: &UaRow) -> Line<'static> {
    let line = Line::from(format!(
        "{:>8}  {:<24}  {}",
        row.count,
        row.status.label(),
        row.user_agent
    ));
    style_by_status(line, row.status)
}

/// Red for a blocked row, unstyled for a pending one — shared by both
/// panels so "blocked" reads the same way everywhere in this app (matches
/// `dashboard.rs::policy_tag`'s fixed, theme-independent red/green, not
/// varied per light/dark theme). Blocklist items are shown in red on gray
/// background.
fn style_by_status(line: Line<'static>, status: RowStatus) -> Line<'static> {
    use ratatui::style::Color;
    match status {
        RowStatus::Blocklist => line.fg(Color::Red).bg(Color::Gray),
        _ if status.is_blocked() => line.red(),
        _ => line,
    }
}

/// `list_state`'s selection must always point at a valid row once `len`
/// rows exist (so the first arrow key press doesn't need to "discover" a
/// selection first), and never point at all once emptied — same convention
/// `Dashboard`'s two lists already use.
fn clamp_selection(list_state: &mut ListState, len: usize) {
    if len == 0 {
        list_state.select(None);
    } else if list_state.selected().is_none_or(|s| s >= len) {
        list_state.select(Some(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FirewallAction;
    use crate::db::NewBot;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;
    use ratatui::Terminal;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn refresh_populates_ua_rows_from_the_database() {
        let db = Db::open_in_memory().unwrap();
        // upsert_bot requires a source; not needed here, just documents
        // that this screen doesn't touch `bots` at all.
        let _ = NewBot {
            slug: "unused".to_string(),
            name: "unused".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "unused".to_string(),
            source_id: "unused".to_string(),
        };
        let mut counts = HashMap::new();
        counts.insert("Mozilla/5.0".to_string(), 5u64);
        db.record_user_agent_hits(&counts, 1000).unwrap();
        db.block_user_agent("Mozilla/5.0").unwrap();

        let mut screen = DynamicProtection::default();
        screen.refresh(&db, None).unwrap();

        assert_eq!(screen.ua_rows.len(), 1);
        assert_eq!(screen.ua_rows[0].user_agent, "Mozilla/5.0");
        assert_eq!(screen.ua_rows[0].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn tab_toggles_focus_between_panels() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection::default();
        let mut message = None;
        assert_eq!(screen.focus, Focus::Ssh);

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        assert_eq!(screen.focus, Focus::UserAgents);

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        assert_eq!(screen.focus, Focus::Ssh);
    }

    #[test]
    fn enter_permanently_blocks_the_selected_ssh_row() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Pending,
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "198.51.100.9");
        assert_eq!(rules[0].expires_at, None);
        assert!(message.unwrap().contains("198.51.100.9"));
    }

    #[test]
    fn enter_permanently_blocks_the_selected_user_agent() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection {
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Pending,
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(
            db.list_blocked_user_agents().unwrap(),
            vec!["curl/8.0".to_string()]
        );
        assert!(message.unwrap().contains("curl/8.0"));
    }

    /// Enter is a toggle, not just "ensure blocked": pressing it on a row
    /// already showing `BLOCKED` (temporary or permanent) unblocks it —
    /// this is `unblock_address`, the reverse of the previous test's
    /// `block_address_permanently`.
    #[test]
    fn enter_unblocks_an_already_blocked_ssh_row() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule_with_ttl(
            &crate::db::NewFirewallRule {
                address: "198.51.100.9".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            3600,
        )
        .unwrap();
        let mut screen = DynamicProtection {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Blocked { until: Some(0) },
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_firewall_rules().unwrap().is_empty());
        assert!(message.unwrap().contains("Unblocked"));
    }

    #[test]
    fn enter_unblocks_an_already_blocked_user_agent() {
        let db = Db::open_in_memory().unwrap();
        db.block_user_agent("curl/8.0").unwrap();
        let mut screen = DynamicProtection {
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Blocked { until: None },
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_blocked_user_agents().unwrap().is_empty());
        assert!(message.unwrap().contains("Unblocked"));
    }

    #[test]
    fn f_key_cycles_through_all_pending_and_blocked_filters() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection::default();
        assert_eq!(screen.filter, Filter::All);

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::PendingOnly);

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::BlockedOnly);

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::All);
    }

    /// The headline ask this change exists for: a `BLOCKED` row must
    /// actually render red, not just show the word "BLOCKED" in plain
    /// text. Uses digits that appear nowhere else on screen (neither
    /// address, count, nor status label repeats them) so each fetched cell
    /// is unambiguously from that one row.
    #[test]
    fn blocked_rows_render_red_and_pending_rows_do_not() {
        let mut screen = DynamicProtection {
            ssh_rows: vec![
                SshRow {
                    address: "1.1.1.1".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "9.9.9.9".to_string(),
                    count: 5,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        let buffer = terminal.backend().buffer();
        let pending_cell = buffer
            .content
            .iter()
            .find(|cell| cell.symbol() == "1")
            .expect("the pending row's address digit should be on screen");
        let blocked_cell = buffer
            .content
            .iter()
            .find(|cell| cell.symbol() == "9")
            .expect("the blocked row's address digit should be on screen");

        assert_eq!(blocked_cell.fg, Color::Red, "blocked row must render red");
        assert_ne!(
            pending_cell.fg,
            Color::Red,
            "pending row must not render red"
        );
    }

    #[test]
    fn blocked_only_filter_hides_pending_rows_from_render() {
        let mut screen = DynamicProtection {
            ssh_rows: vec![
                SshRow {
                    address: "198.51.100.9".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "203.0.113.5".to_string(),
                    count: 1,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            filter: Filter::BlockedOnly,
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("203.0.113.5"), "content was:\n{content}");
        assert!(!content.contains("198.51.100.9"), "content was:\n{content}");
        assert!(content.contains("blocked only"), "content was:\n{content}");
    }

    /// Changing the filter must re-clamp each panel's selection against the
    /// new *visible* length, not the full row count — otherwise switching
    /// to a filter with fewer visible rows than the current selection index
    /// would leave the selection pointing at nothing on screen.
    #[test]
    fn changing_the_filter_reclamps_the_selection_to_the_visible_rows() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection {
            ssh_rows: vec![
                SshRow {
                    address: "198.51.100.9".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "203.0.113.5".to_string(),
                    count: 1,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            ..Default::default()
        };
        screen.ssh_state.select(Some(1));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::PendingOnly);
        // Only one row is visible under this filter now, so the selection
        // must have been pulled back to index 0.
        assert_eq!(screen.ssh_state.selected(), Some(0));
    }

    #[test]
    fn enter_on_an_empty_panel_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection::default();

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn render_shows_both_panels() {
        let mut screen = DynamicProtection {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Pending,
            }],
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Pending,
            }],
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Failed SSH logins"),
            "content was:\n{content}"
        );
        assert!(content.contains("198.51.100.9"), "content was:\n{content}");
        assert!(content.contains("NOT BLOCKED"), "content was:\n{content}");
        assert!(
            content.contains("Top user agents"),
            "content was:\n{content}"
        );
        assert!(content.contains("curl/8.0"), "content was:\n{content}");
    }

    #[test]
    fn enter_on_blocklist_row_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection {
            ssh_rows: vec![SshRow {
                address: "192.168.1.5".to_string(),
                count: 3,
                status: RowStatus::Blocklist,
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.is_none());
        // Verify no firewall rules were added
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn enter_on_blocklist_ua_row_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = DynamicProtection {
            ua_rows: vec![UaRow {
                user_agent: "Googlebot".to_string(),
                count: 2,
                status: RowStatus::Blocklist,
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.is_none());
        // Verify no user agents were blocked
        assert!(db.list_blocked_user_agents().unwrap().is_empty());
    }

    #[test]
    fn blocklist_status_label_is_blocklist() {
        assert_eq!(RowStatus::Blocklist.label(), "BLOCKLIST");
    }

    #[test]
    fn blocklist_status_is_blocked() {
        assert!(RowStatus::Blocklist.is_blocked());
    }

    #[test]
    fn blocklist_status_is_blocklist() {
        assert!(RowStatus::Blocklist.is_blocklist());
        assert!(!RowStatus::Pending.is_blocklist());
        assert!(!RowStatus::Blocked { until: None }.is_blocklist());
    }
}
