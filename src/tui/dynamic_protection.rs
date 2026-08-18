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
//! SSH log on every `refresh` — there's no persisted "SSH attempt stats"
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
//! `refresh` itself (which resolves the live SSH log — the `tui --ssh-log`
//! override if one was given, else the same fixed-paths-or-journalctl
//! lookup the cron jobs use) is deliberately thin: all the actual row-building logic lives
//! in [`build_ssh_rows`]/[`build_ua_rows`], pure functions tested directly
//! against synthetic counts below rather than through a real or faked log
//! file.

use crate::db::{Bot, Category, Db, FirewallAction, Policy, UserAgentStat};
use crate::ipranges;
use crate::sshlog;
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
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Which of the two panels `Up`/`Down`/`Enter` currently apply to. Switched
/// with `Tab`/`Shift+Tab` (see the module doc comment for why that claims
/// the key on this screen instead of cycling top-level screens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Ssh,
    UserAgents,
}

/// Whether a row's address/user agent is already covered by a stored
/// block. `Blocked { until: None }` renders as `BLOCKED`; `Some(t)`
/// (a temporary `firewall_rules` row, e.g. from `block-scanners`) renders
/// as `BLOCKED until <relative time>`. `Blocklist` means the item is blocked
/// by the botlist configuration (bot patterns or IP ranges), not by a manual
/// block action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowStatus {
    Pending,
    Blocked { until: Option<i64> },
    Blocklist,
}

impl RowStatus {
    fn label(self) -> String {
        match self {
            RowStatus::Pending => "NOT BLOCKED".to_string(),
            RowStatus::Blocked { until: None } => "BLOCKED".to_string(),
            RowStatus::Blocked {
                until: Some(expires_at),
            } => format!("BLOCKED until {}", format_until(expires_at)),
            RowStatus::Blocklist => "BLOCKLIST".to_string(),
        }
    }

    fn is_blocked(self) -> bool {
        matches!(self, RowStatus::Blocked { .. } | RowStatus::Blocklist)
    }

    fn is_blocklist(self) -> bool {
        matches!(self, RowStatus::Blocklist)
    }
}

/// A shared display filter applied to both panels — cycled with `f`
/// (`All` -> `NotBlockedOnly` -> `BlockedOnly` -> `All`). One filter for both
/// panels rather than a separate one each: this screen only ever shows one
/// filter's worth of state at a time in its titles, and both panels share
/// the same "what am I looking for right now" question (either "what's
/// still unblocked" or "what's already enforced").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Filter {
    #[default]
    All,
    PendingOnly,
    BlockedOnly,
}

impl Filter {
    fn matches(self, status: RowStatus) -> bool {
        match self {
            Filter::All => true,
            Filter::PendingOnly => !status.is_blocked(),
            Filter::BlockedOnly => status.is_blocked(),
        }
    }

    fn next(self) -> Self {
        match self {
            Filter::All => Filter::PendingOnly,
            Filter::PendingOnly => Filter::BlockedOnly,
            Filter::BlockedOnly => Filter::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::PendingOnly => "not blocked only",
            Filter::BlockedOnly => "blocked only",
        }
    }
}

/// One ranked IP row in the SSH panel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SshRow {
    address: String,
    count: u64,
    status: RowStatus,
}

/// One ranked user agent row in the User Agents panel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UaRow {
    user_agent: String,
    count: u64,
    status: RowStatus,
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
    /// Reloads both panels. See the module doc comment for the SSH panel's
    /// live-log-read caveat and why the actual row-building logic lives in
    /// [`build_ssh_rows`]/[`build_ua_rows`] instead of here.
    /// `ssh_log` overrides SSH-log auto-detection (see `App`'s field of the
    /// same name) — auto-detection can shell out to `journalctl`, and this
    /// runs on every refresh.
    pub fn refresh(&mut self, db: &Db, ssh_log: Option<&std::path::Path>) -> Result<()> {
        let firewall_blocks: HashMap<String, Option<i64>> = db
            .list_firewall_rules()?
            .into_iter()
            .filter(|rule| rule.action == FirewallAction::Block)
            .map(|rule| (rule.address, rule.expires_at))
            .collect();
        let blocked_ip_ranges = db.blocked_ip_ranges()?;
        let source = match ssh_log {
            Some(path) => sshlog::read_log_file(path),
            None => sshlog::find_default_source(),
        };
        let ssh_counts = match source {
            sshlog::LogSource::Found(log_text) => sshlog::failed_attempt_counts(&log_text),
            sshlog::LogSource::Unavailable => HashMap::new(),
        };
        self.ssh_rows = build_ssh_rows(ssh_counts, &firewall_blocks, &blocked_ip_ranges);

        let blocked_uas: HashSet<String> = db.list_blocked_user_agents()?.into_iter().collect();
        let bots = db.list_bots()?;
        let ai_policy = db.get_category_default(Category::Ai)?;
        let search_policy = db.get_category_default(Category::Search)?;
        let scanner_policy = db.get_category_default(Category::Scanner)?;
        self.ua_rows = build_ua_rows(
            db.list_user_agent_stats()?,
            &blocked_uas,
            &bots,
            ai_policy,
            search_policy,
            scanner_policy,
        );

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

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let [ssh_area, ua_area] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);

        let reversed = Style::new().reversed();

        let ssh_items: Vec<ListItem> = self
            .visible_ssh_rows()
            .into_iter()
            .map(ssh_row_line)
            .map(ListItem::new)
            .collect();
        let ssh_list = List::new(ssh_items)
            .block(
                Block::bordered()
                    .title(format!(
                        "Top IPs attempting SSH connection — Enter block/unblock, f filter ({})",
                        self.filter.label()
                    ))
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::Ssh {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(ssh_list, ssh_area, &mut self.ssh_state);

        let ua_items: Vec<ListItem> = self
            .visible_ua_rows()
            .into_iter()
            .map(ua_row_line)
            .map(ListItem::new)
            .collect();
        let ua_list = List::new(ua_items)
            .block(
                Block::bordered()
                    .title(format!(
                        "Top User Agents — Enter block/unblock, f filter ({})",
                        self.filter.label()
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

/// Checks if a user agent string matches any blocked bot pattern.
/// Uses a simple case-insensitive substring check since we don't have
/// the regex crate available. This is a best-effort check that may have
/// false positives/negatives compared to proper regex matching.
fn ua_matches_blocked_bot_patterns(
    ua: &str,
    bots: &[Bot],
    ai_policy: Policy,
    search_policy: Policy,
    scanner_policy: Policy,
) -> bool {
    // For each bot that is currently blocked (based on its status and category policies),
    // check if the UA contains the bot's pattern (case-insensitive).
    for bot in bots {
        // Check if this bot is currently blocked
        let bot_blocked = match bot.status {
            crate::db::BotStatus::Blocked => true,
            crate::db::BotStatus::Allowed => false,
            crate::db::BotStatus::Default => {
                (bot.is_ai && ai_policy == Policy::Blocked)
                    || (bot.is_search_engine && search_policy == Policy::Blocked)
                    || (bot.is_scanner && scanner_policy == Policy::Blocked)
            }
        };

        if bot_blocked {
            // Simple case-insensitive substring check
            let ua_lower = ua.to_lowercase();
            let pattern_lower = bot.user_agent_pattern.to_lowercase();
            // Split pattern by | and check if any alternative matches
            for alternative in pattern_lower.split('|') {
                if ua_lower.contains(alternative) {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if an IP address is in any blocked IP range (crawler ranges).
fn ip_in_blocked_range(ip_str: &str, blocked_ranges: &[String]) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        for cidr in blocked_ranges {
            if ipranges::cidr_contains(cidr, ip) {
                return true;
            }
        }
    }
    false
}

/// Turns raw failed-attempt `counts` (see [`sshlog::failed_attempt_counts`])
/// into ranked, status-tagged rows: an address present (with a Block
/// action) in `firewall_blocks` is `Blocked` (its `Option<i64>` is the
/// rule's `expires_at`, `None` meaning permanent); everything else is
/// `NOT BLOCKED`. Sorted by count descending, address ascending as a
/// deterministic tiebreaker.
fn build_ssh_rows(
    counts: HashMap<String, u64>,
    firewall_blocks: &HashMap<String, Option<i64>>,
    blocked_ip_ranges: &[String],
) -> Vec<SshRow> {
    let mut rows: Vec<SshRow> = counts
        .into_iter()
        .map(|(address, count)| {
            // Manual blocks take precedence over blocklist
            let status = if let Some(until) = firewall_blocks.get(&address) {
                RowStatus::Blocked { until: *until }
            } else if ip_in_blocked_range(&address, blocked_ip_ranges) {
                RowStatus::Blocklist
            } else {
                RowStatus::Pending
            };
            SshRow {
                address,
                count,
                status,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.address.cmp(&b.address))
    });
    rows
}

/// Turns `stats` (already sorted by `Db::list_user_agent_stats`) into
/// status-tagged rows: a user agent present in `blocked` is permanently
/// `Blocked` (manual blocks have no TTL and take precedence); a user agent
/// matching a blocked bot pattern is `Blocklist`; everything else is `NOT BLOCKED`.
fn build_ua_rows(
    stats: Vec<UserAgentStat>,
    blocked: &HashSet<String>,
    bots: &[Bot],
    ai_policy: Policy,
    search_policy: Policy,
    scanner_policy: Policy,
) -> Vec<UaRow> {
    stats
        .into_iter()
        .map(|stat| {
            // Manual blocks take precedence over blocklist
            let status = if blocked.contains(&stat.user_agent) {
                RowStatus::Blocked { until: None }
            } else if ua_matches_blocked_bot_patterns(
                &stat.user_agent,
                bots,
                ai_policy,
                search_policy,
                scanner_policy,
            ) {
                RowStatus::Blocklist
            } else {
                RowStatus::Pending
            };
            UaRow {
                user_agent: stat.user_agent,
                count: stat.hit_count as u64,
                status,
            }
        })
        .collect()
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

/// Formats a future Unix timestamp `expires_at` as a short "Nd"/"Nh"
/// relative string for a `RowStatus::Blocked`'s "until" text — same
/// rounding convention as `main.rs::format_expiry` (that one isn't
/// reachable from the library crate, hence this small local twin).
fn format_until(expires_at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seconds_left = (expires_at - now).max(0);
    let days = seconds_left / 86_400;
    if days > 0 {
        format!("{days}d")
    } else {
        let hours = (seconds_left / 3_600).max(1);
        format!("{hours}h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewBot;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;
    use ratatui::Terminal;

    fn counts(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(ip, n)| (ip.to_string(), *n)).collect()
    }

    #[test]
    fn build_ssh_rows_ranks_by_count_descending() {
        let rows = build_ssh_rows(
            counts(&[("198.51.100.9", 3), ("198.51.100.2", 9)]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(rows[0].address, "198.51.100.2");
        assert_eq!(rows[0].count, 9);
        assert_eq!(rows[0].status, RowStatus::Pending);
        assert_eq!(rows[1].address, "198.51.100.9");
        assert_eq!(rows[1].count, 3);
    }

    #[test]
    fn build_ssh_rows_breaks_ties_by_address_for_determinism() {
        let rows = build_ssh_rows(
            counts(&[("198.51.100.9", 5), ("198.51.100.2", 5)]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(rows[0].address, "198.51.100.2");
        assert_eq!(rows[1].address, "198.51.100.9");
    }

    #[test]
    fn build_ssh_rows_marks_a_permanently_blocked_address() {
        let mut blocks = HashMap::new();
        blocks.insert("198.51.100.9".to_string(), None);
        let rows = build_ssh_rows(counts(&[("198.51.100.9", 3)]), &blocks, &[]);
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
        assert_eq!(rows[0].status.label(), "BLOCKED");
    }

    #[test]
    fn build_ssh_rows_marks_a_temporarily_blocked_address_with_its_expiry() {
        let mut blocks = HashMap::new();
        blocks.insert("198.51.100.9".to_string(), Some(999_999_999_999));
        let rows = build_ssh_rows(counts(&[("198.51.100.9", 3)]), &blocks, &[]);
        assert!(matches!(
            rows[0].status,
            RowStatus::Blocked { until: Some(_) }
        ));
        assert!(rows[0].status.label().starts_with("BLOCKED until"));
    }

    #[test]
    fn build_ua_rows_preserves_incoming_order_and_tags_blocked_ones() {
        let stats = vec![
            UserAgentStat {
                user_agent: "Mozilla/5.0".to_string(),
                hit_count: 42,
                last_seen_at: 1000,
            },
            UserAgentStat {
                user_agent: "curl/8.0".to_string(),
                hit_count: 3,
                last_seen_at: 1000,
            },
        ];
        let mut blocked = HashSet::new();
        blocked.insert("curl/8.0".to_string());

        let rows = build_ua_rows(
            stats,
            &blocked,
            &[],
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(rows[0].user_agent, "Mozilla/5.0");
        assert_eq!(rows[0].status, RowStatus::Pending);
        assert_eq!(rows[1].user_agent, "curl/8.0");
        assert_eq!(rows[1].status, RowStatus::Blocked { until: None });
    }

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
        screen
            .refresh(
                &db,
                Some(std::path::Path::new("/nonexistent/test-auth.log")),
            )
            .unwrap();

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
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
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
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("203.0.113.5"));
        assert!(!content.contains("198.51.100.9"));
        assert!(content.contains("blocked only"));
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
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Top IPs attempting SSH connection"));
        assert!(content.contains("198.51.100.9"));
        assert!(content.contains("NOT BLOCKED"));
        assert!(content.contains("Top User Agents"));
        assert!(content.contains("curl/8.0"));
    }

    #[test]
    fn build_ssh_rows_marks_ip_in_blocked_range_as_blocklist() {
        let rows = build_ssh_rows(
            counts(&[("192.168.1.5", 3)]),
            &HashMap::new(),
            &["192.168.1.0/24".to_string()],
        );
        assert_eq!(rows[0].address, "192.168.1.5");
        assert_eq!(rows[0].status, RowStatus::Blocklist);
        assert_eq!(rows[0].status.label(), "BLOCKLIST");
    }

    #[test]
    fn build_ssh_rows_prioritizes_manual_block_over_blocklist() {
        let mut blocks = HashMap::new();
        blocks.insert("192.168.1.5".to_string(), None);
        let rows = build_ssh_rows(
            counts(&[("192.168.1.5", 3)]),
            &blocks,
            &["192.168.1.0/24".to_string()],
        );
        assert_eq!(rows[0].address, "192.168.1.5");
        // Manual block takes precedence over blocklist
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn build_ua_rows_marks_ua_matching_bot_pattern_as_blocklist() {
        let stats = vec![UserAgentStat {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string(),
            hit_count: 42,
            last_seen_at: 1000,
        }];
        let blocked = HashSet::new();
        let bots = vec![Bot {
            id: 1,
            slug: "googlebot".to_string(),
            name: "Googlebot".to_string(),
            is_ai: false,
            is_search_engine: true,
            is_scanner: false,
            user_agent_pattern: "Googlebot".to_string(),
            status: crate::db::BotStatus::Default,
            source_id: "test".to_string(),
            updated_at: 1000,
        }];

        let rows = build_ua_rows(
            stats,
            &blocked,
            &bots,
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(
            rows[0].user_agent,
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        );
        assert_eq!(rows[0].status, RowStatus::Blocklist);
        assert_eq!(rows[0].status.label(), "BLOCKLIST");
    }

    #[test]
    fn build_ua_rows_prioritizes_manual_block_over_blocklist() {
        let stats = vec![UserAgentStat {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string(),
            hit_count: 42,
            last_seen_at: 1000,
        }];
        let mut blocked = HashSet::new();
        blocked.insert("Mozilla/5.0 (compatible; Googlebot/2.1)".to_string());
        let bots = vec![Bot {
            id: 1,
            slug: "googlebot".to_string(),
            name: "Googlebot".to_string(),
            is_ai: false,
            is_search_engine: true,
            is_scanner: false,
            user_agent_pattern: "Googlebot".to_string(),
            status: crate::db::BotStatus::Default,
            source_id: "test".to_string(),
            updated_at: 1000,
        }];

        let rows = build_ua_rows(
            stats,
            &blocked,
            &bots,
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(
            rows[0].user_agent,
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        );
        // Manual block takes precedence over blocklist
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
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
