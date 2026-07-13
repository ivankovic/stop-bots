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

//! The Dashboard: the default screen on app start. An overview of global
//! settings (Scanners/Search Bots/AI Bots defaults, navigable and editable
//! via a popup, mirroring how Bot settings edits a single bot's override),
//! how many sites are known, whether bot-list sources are up to date, and
//! host-wide geo-blocking (see "Geo-blocking" below). The "Summary" panel is
//! deliberately just a glance — it used to also fold in top user agents
//! seen in successful traffic, but that's moved to its own dedicated
//! "Dynamic Protection" screen (`crate::tui::dynamic_protection`), which
//! also lets an admin act on it (permanently block one), not just look at
//! it.
//!
//! ## Geo-blocking
//!
//! A second, independently-focused list (`countries_state`, switched to via
//! `Down` past the last category row or `Up` above the first country
//! row — no dedicated focus key, since these are just two vertically
//! stacked lists, not a list-plus-search-box pair like Bot settings'
//! `Focus`) shows every host-wide selected country (`Db::list_selected_countries`)
//! plus a fixed "+ Add a country" action row at the top. What being
//! "selected" *means* depends on the geo mode, shown in the panel's title
//! and toggled with `m` (a popup, unlike the direct actions below, since
//! switching to Allowlist is meaningfully higher-stakes — see
//! [`Popup::GeoMode`]):
//!
//! - **Blocklist** (the default): selected countries are blocked,
//!   everything else is allowed.
//! - **Allowlist**: selected countries are the *only* ones allowed,
//!   everything else is blocked host-wide once `render-firewall` runs (see
//!   `Db::geo_firewall_rules` and its nftables-only guard in `main.rs`).
//!
//! Enter on the "Add" row opens a text-input popup for a two-letter code;
//! Enter on an existing country row removes it directly (no confirmation
//! popup — unlike a category default, removing a country isn't "choose one
//! of several options", it's a single reversible action, the same
//! reasoning Site settings' apply/apply-all actions already use).
//! Confirming the input popup with a code whose ranges are already fetched
//! adds it immediately (`Mutated`); a not-yet-fetched code returns
//! `KeyOutcome::SelectCountry` so `App` can fetch it first
//! (`App::start_country_select`) — see that function's doc comment for why
//! fetching can't happen here directly.

use crate::db::{Category, Db, GeoMode, Policy, Source};
use crate::ipranges;
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source is considered stale (needs updating) if it's never been fetched,
/// or wasn't fetched in the last week.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

/// The rows of the editable "System-wide settings" list, in display order.
const CATEGORIES: [Category; 3] = [Category::Scanner, Category::Search, Category::Ai];

/// Which of the Dashboard's two lists arrow keys currently move through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Categories,
    Countries,
}

/// The popup opened by the Dashboard: editing a category default (cycles
/// between Allowed (0) and Blocked (1), mirroring Bot settings' category
/// popup before it moved here), entering a country code to add to the geo
/// selection, or switching the geo mode itself.
#[derive(Debug, Clone)]
enum Popup {
    Category {
        category: Category,
        selected: usize,
    },
    AddCountry {
        input: String,
        error: Option<String>,
    },
    /// Cycles between Blocklist (0) and Allowlist (1) — a popup, not a
    /// direct toggle like removing a country, because flipping to
    /// Allowlist is a materially bigger decision: it turns host-wide geo
    /// enforcement into a default-deny gate for the whole box once
    /// `render-firewall` runs, not just "one more blocked country".
    GeoMode {
        selected: usize,
    },
    /// Firewall rendering: select backend (0 = iptables, 1 = nftables),
    /// enter the output path, and optionally toggle `apply_after_write`
    /// (Space) so confirming with Enter also actually enforces the script
    /// (`firewall::apply_script`, gated by `App::apply_firewall`) instead of
    /// only writing it for the admin to apply by hand.
    RenderFirewall {
        backend_selected: usize,
        out_path: String,
        apply_after_write: bool,
        error: Option<String>,
    },
}

#[derive(Debug, Default)]
pub struct Dashboard {
    site_count: usize,
    sources: Vec<Source>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
    list_state: ListState,
    popup: Option<Popup>,
    geo_mode: GeoMode,
    selected_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    countries_state: ListState,
    focus: Focus,
    /// The internal cron's per-job state (see `crate::cron`), read-only
    /// here — this panel only displays it, `App` is what actually runs due
    /// jobs.
    cron_status: Vec<crate::cron::JobStatus>,
    /// Whether the current rule set (`firewall::all_rules`) differs from
    /// what was in effect the last time the firewall was actually rendered
    /// (`firewall::rules_signature`, compared via
    /// `Db::get_firewall_rendered_signature`) — shown as a Summary panel
    /// row so an admin can tell, without opening the render popup, whether
    /// e.g. a scanner blocked since the last daily `RenderFirewall` cron
    /// tick is actually reflected in the on-disk script yet.
    firewall_needs_update: bool,
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.site_count = db.list_sites()?.len();
        self.sources = db.list_sources()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        self.geo_mode = db.get_geo_mode()?;
        self.selected_countries = db.list_selected_countries()?;
        self.fetched_countries = db.list_fetched_countries()?;
        self.cron_status = crate::cron::status(db)?;
        self.firewall_needs_update = firewall_needs_update(db)?;
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        if self.countries_state.selected().is_none() {
            self.countries_state.select(Some(0));
        }
        // Removing a country shrinks `selected_countries`; without this the
        // selection could be left pointing past the new last row (stale
        // until the next arrow press re-clamps it via `select_previous`/
        // `select_next`) if the row that was just removed wasn't the last
        // one selected.
        let max_row = self.selected_countries.len(); // +1 (the "Add" row) - 1 (0-indexed)
        if self.countries_state.selected().is_some_and(|s| s > max_row) {
            self.countries_state.select(Some(max_row));
        }
        Ok(())
    }

    /// How many CIDRs are currently known for `country_code`, if it's ever
    /// been fetched — `None` for a country that was selected (e.g. via the
    /// CLI's `add-country`) before its ranges were ever fetched.
    fn range_count(&self, country_code: &str) -> Option<i64> {
        self.fetched_countries
            .iter()
            .find(|(cc, _, _)| cc == country_code)
            .map(|(_, count, _)| *count)
    }

    fn category_default(&self, category: Category) -> Policy {
        match category {
            Category::Scanner => self.scanner_default,
            Category::Search => self.search_default,
            Category::Ai => self.ai_default,
        }
    }

    fn up_to_date_count(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| !is_stale(s.last_fetched_at))
            .count()
    }

    /// Whether the Summary panel's firewall row currently reads "needs
    /// updating" — `pub(crate)` and test-only, purely so `App`'s own tests
    /// (a different module) can assert that a render triggered through the
    /// key/outcome flow actually refreshes this cached value, not just the
    /// underlying `Db` signature (see `App::handle_key_event`'s
    /// `RenderFirewall` arm).
    #[cfg(test)]
    pub(crate) fn firewall_needs_update(&self) -> bool {
        self.firewall_needs_update
    }

    fn needs_update_count(&self) -> usize {
        self.sources.len() - self.up_to_date_count()
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        message: &Option<String>,
        running_jobs: &std::collections::HashSet<crate::cron::CronJob>,
    ) {
        // Geo-blocking gives up 1 row (8 -> 7) to Summary (4 -> 5, for the
        // new firewall-status line below) so the total stays exactly what
        // it was — this project's documented 30-row minimum terminal size
        // leaves the Messages panel (`Constraint::Min(1)`) no slack to
        // absorb a net increase (see SPECS.md's "Successful-access
        // user-agent tracking" entry, which hit the same ceiling and
        // rebalanced the same way). Geo-blocking is the one to shrink, not
        // Messages or Bot list sources: it's a scrollable `List`, which
        // degrades gracefully by scrolling to the selected row when its
        // viewport shrinks, unlike `Paragraph`'s fixed lines, which would
        // just silently lose whichever line no longer fits.
        let [settings_area, geo_area, stats_area, cron_area, message_area] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(5),
            // 2 border lines + one line per known job.
            Constraint::Length(2 + crate::cron::CronJob::ALL.len() as u16),
            Constraint::Min(1),
        ])
        .areas(area);

        let reversed = Style::new().reversed();

        let items: Vec<ListItem> = CATEGORIES
            .iter()
            .map(|&category| ListItem::new(self.row_line(category)))
            .collect();
        let list = List::new(items)
            .block(
                Block::bordered()
                    .title("System-wide settings")
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::Categories {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(list, settings_area, &mut self.list_state);

        let country_items: Vec<ListItem> =
            std::iter::once(ListItem::new(Line::from("+ Add a country").italic()))
                .chain(
                    self.selected_countries
                        .iter()
                        .map(|cc| ListItem::new(self.country_row_line(cc))),
                )
                .collect();
        let mode_label = match self.geo_mode {
            GeoMode::Blocklist => "Blocklist",
            GeoMode::Allowlist => "Allowlist",
        };
        let country_list = List::new(country_items)
            .block(
                Block::bordered()
                    .title(format!(
                        "Geo-blocking (host-wide) — {mode_label} — Enter to add/remove, m for mode"
                    ))
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::Countries {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(country_list, geo_area, &mut self.countries_state);

        let summary = Paragraph::new(vec![
            Line::from(format!("Sites discovered: {}", self.site_count)),
            Line::from(format!(
                "Bot list sources: {} up to date, {} need updating",
                self.up_to_date_count(),
                self.needs_update_count()
            )),
            Line::from(if self.firewall_needs_update {
                "Firewall rules: needs updating (press f to update)".to_string()
            } else {
                "Firewall rules: up to date".to_string()
            }),
        ])
        .block(Block::bordered().title("Summary"));
        frame.render_widget(summary, stats_area);

        let cron_lines: Vec<Line> = self
            .cron_status
            .iter()
            .map(|status| cron_status_line(status, running_jobs.contains(&status.job)))
            .collect();
        let cron_panel = Paragraph::new(cron_lines).block(
            Block::bordered()
                .title("Scheduled tasks (internal cron — runs only while this TUI is open)"),
        );
        frame.render_widget(cron_panel, cron_area);

        let message_text = message.as_deref().unwrap_or("No recent actions.");
        let messages = Paragraph::new(message_text).block(Block::bordered().title("Messages"));
        frame.render_widget(messages, message_area);

        if let Some(popup) = self.popup.clone() {
            self.render_popup(frame, area, popup);
        }
    }

    fn row_line(&self, category: Category) -> Line<'static> {
        let mut line = vec![Span::from(format!("{:<14}", category_label(category)))];
        line.push(policy_tag(self.category_default(category)));
        Line::from(line)
    }

    fn country_row_line(&self, country_code: &str) -> Line<'static> {
        let ranges = match self.range_count(country_code) {
            Some(count) => format!("{count} range(s)"),
            None => "not yet fetched".to_string(),
        };
        // Every row currently in the list is enforced the same way — the
        // mode governs all of them at once — so the tag is a direct
        // reflection of `geo_mode`, not a per-row setting.
        let policy = match self.geo_mode {
            GeoMode::Blocklist => Policy::Blocked,
            GeoMode::Allowlist => Policy::Allowed,
        };
        Line::from(vec![
            Span::from(format!("{:<8}", country_code.to_uppercase())),
            policy_tag(policy),
            Span::from(format!(" {ranges}")),
        ])
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: Popup) {
        match popup {
            Popup::Category { category, selected } => {
                let title = format!("{} default", category_label(category));
                let options = ["Allowed", "Blocked"];
                let content_width = options
                    .iter()
                    .map(|o| o.len())
                    .max()
                    .unwrap_or(0)
                    .max(title.len());
                let popup_area =
                    centered_rect(content_width as u16 + 4, options.len() as u16 + 2, area);
                let items: Vec<ListItem> = options
                    .iter()
                    .enumerate()
                    .map(|(i, label)| {
                        let line = if i == selected {
                            Line::from(*label).reversed()
                        } else {
                            Line::from(*label)
                        };
                        ListItem::new(line)
                    })
                    .collect();
                let list = List::new(items).block(Block::bordered().title(title));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(list, popup_area);
            }
            Popup::AddCountry { input, error } => {
                let title = "Add a country (2-letter code)";
                let width = 40u16;
                let height = if error.is_some() { 5 } else { 4 };
                let popup_area = centered_rect(width, height, area);
                let mut lines = vec![Line::from(format!("{input}\u{2588}"))];
                if let Some(err) = &error {
                    lines.push(Line::from(err.as_str()).red());
                }
                lines.push(Line::from("Enter confirm  Esc cancel").dim());
                let paragraph = Paragraph::new(lines).block(Block::bordered().title(title));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(paragraph, popup_area);
            }
            Popup::GeoMode { selected } => {
                let title = "Geo mode";
                let options = [
                    "Blocklist (block selected countries)",
                    "Allowlist (block everything except selected)",
                ];
                let content_width = options.iter().map(|o| o.len()).max().unwrap_or(0);
                let popup_area =
                    centered_rect(content_width as u16 + 4, options.len() as u16 + 2, area);
                let items: Vec<ListItem> = options
                    .iter()
                    .enumerate()
                    .map(|(i, label)| {
                        let line = if i == selected {
                            Line::from(*label).reversed()
                        } else {
                            Line::from(*label)
                        };
                        ListItem::new(line)
                    })
                    .collect();
                let list = List::new(items).block(Block::bordered().title(title));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(list, popup_area);
            }
            Popup::RenderFirewall {
                backend_selected,
                out_path,
                apply_after_write,
                error,
            } => {
                let title = "Render firewall rules";
                let width = 56u16;
                let height = if error.is_some() { 10 } else { 9 };
                let popup_area = centered_rect(width, height, area);

                let mut lines = vec![
                    Line::from("Backend:").bold(),
                    Line::from(vec![
                        Span::from("  [ "),
                        Span::from(match backend_selected {
                            0 => "nftables (recommended)",
                            1 => "iptables (IPv4 only)",
                            _ => "unknown",
                        })
                        .reversed(),
                        Span::from(" ]"),
                    ]),
                    Line::from(""),
                    Line::from(format!("Output: {}_", out_path)),
                    Line::from(vec![
                        Span::from("Apply after writing: "),
                        Span::from(if apply_after_write { "[x]" } else { "[ ]" }),
                    ]),
                ];
                if let Some(err) = &error {
                    lines.push(Line::from(err.as_str()).red());
                }
                lines.push(Line::from("").dim());
                lines.push(
                    Line::from("↑/↓ backend  Space apply toggle  Enter confirm  Esc cancel").dim(),
                );

                let paragraph = Paragraph::new(lines).block(Block::bordered().title(title));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(paragraph, popup_area);
            }
        }
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if let Some(popup) = &mut self.popup {
            match popup {
                Popup::Category { selected, .. } => match key.code {
                    KeyCode::Esc => {
                        self.popup = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1).min(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        let Some(Popup::Category { category, selected }) = self.popup.take() else {
                            unreachable!("checked above")
                        };
                        let policy = match selected {
                            0 => Policy::Allowed,
                            _ => Policy::Blocked,
                        };
                        db.set_category_default(category, policy)?;
                        *message = Some(format!(
                            "{} default set to {policy:?}",
                            category_label(category)
                        ));
                        return Ok(KeyOutcome::Mutated);
                    }
                    _ => return Ok(KeyOutcome::Consumed),
                },
                Popup::AddCountry { input, error } => match key.code {
                    KeyCode::Esc => {
                        self.popup = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Backspace => {
                        input.pop();
                        *error = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Char(c) if c.is_ascii_alphabetic() && input.len() < 2 => {
                        input.push(c.to_ascii_lowercase());
                        *error = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Enter => {
                        let code = input.clone();
                        match ipranges::validate_country_code(&code) {
                            Err(_) => {
                                *error = Some("Enter a 2-letter country code".to_string());
                                return Ok(KeyOutcome::Consumed);
                            }
                            Ok(cc) => {
                                self.popup = None;
                                if self.selected_countries.iter().any(|b| b == &cc) {
                                    *message =
                                        Some(format!("{} is already selected", cc.to_uppercase()));
                                    return Ok(KeyOutcome::Consumed);
                                }
                                if self.fetched_countries.iter().any(|(c, _, _)| c == &cc) {
                                    db.set_country_selected(&cc, true)?;
                                    let verb = match self.geo_mode {
                                        GeoMode::Blocklist => "Blocked",
                                        GeoMode::Allowlist => "Allowed",
                                    };
                                    *message = Some(format!("{verb} {}", cc.to_uppercase()));
                                    return Ok(KeyOutcome::Mutated);
                                }
                                return Ok(KeyOutcome::SelectCountry(cc));
                            }
                        }
                    }
                    _ => return Ok(KeyOutcome::Consumed),
                },
                Popup::GeoMode { selected } => match key.code {
                    KeyCode::Esc => {
                        self.popup = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        *selected = selected.saturating_sub(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *selected = (*selected + 1).min(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        let Some(Popup::GeoMode { selected }) = self.popup.take() else {
                            unreachable!("checked above")
                        };
                        let mode = match selected {
                            0 => GeoMode::Blocklist,
                            _ => GeoMode::Allowlist,
                        };
                        db.set_geo_mode(mode)?;
                        *message = Some(match mode {
                            GeoMode::Blocklist => {
                                "Geo mode set to Blocklist: selected countries are blocked, everything else is allowed".to_string()
                            }
                            GeoMode::Allowlist => {
                                "Geo mode set to Allowlist: selected countries are the ONLY ones allowed, everything else will be blocked host-wide once render-firewall runs".to_string()
                            }
                        });
                        return Ok(KeyOutcome::Mutated);
                    }
                    _ => return Ok(KeyOutcome::Consumed),
                },
                Popup::RenderFirewall {
                    backend_selected,
                    out_path,
                    apply_after_write,
                    error,
                } => match key.code {
                    KeyCode::Esc => {
                        self.popup = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    // Arrow keys only here, deliberately no `j`/`k` vim
                    // aliases (unlike every other popup/list in this app):
                    // this popup has a free-text output-path field, and
                    // `j`/`k` are common path characters — aliasing them to
                    // navigation would silently eat any literal 'j'/'k' the
                    // admin tries to type instead of appending it (caught by
                    // `pressing_f_then_enter_refreshes_the_dashboards_stale_indicator`
                    // flaking whenever a temp-dir path happened to contain
                    // one).
                    KeyCode::Up => {
                        *backend_selected = backend_selected.saturating_sub(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Down => {
                        *backend_selected = (*backend_selected + 1).min(1);
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Char(' ') => {
                        *apply_after_write = !*apply_after_write;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Char(c) if c.is_ascii_punctuation() || c.is_ascii_alphanumeric() => {
                        out_path.push(c);
                        *error = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Backspace => {
                        out_path.pop();
                        *error = None;
                        return Ok(KeyOutcome::Consumed);
                    }
                    KeyCode::Enter => {
                        let Some(Popup::RenderFirewall {
                            backend_selected,
                            out_path,
                            apply_after_write,
                            ..
                        }) = self.popup.take()
                        else {
                            unreachable!("checked above")
                        };
                        let backend = match backend_selected {
                            0 => crate::firewall::FirewallBackend::Nftables,
                            _ => crate::firewall::FirewallBackend::Iptables,
                        };
                        // Validate the path is not empty
                        if out_path.is_empty() {
                            self.popup = Some(Popup::RenderFirewall {
                                backend_selected,
                                out_path,
                                apply_after_write,
                                error: Some("Enter an output path".to_string()),
                            });
                            return Ok(KeyOutcome::Consumed);
                        }
                        return Ok(KeyOutcome::RenderFirewall {
                            backend,
                            out_path,
                            force: false,
                            apply: apply_after_write,
                        });
                    }
                    _ => return Ok(KeyOutcome::Consumed),
                },
            }
        }

        if key.code == KeyCode::Char('m') {
            self.popup = Some(Popup::GeoMode {
                selected: match self.geo_mode {
                    GeoMode::Blocklist => 0,
                    GeoMode::Allowlist => 1,
                },
            });
            return Ok(KeyOutcome::Consumed);
        }

        // 'f' key opens the firewall render popup
        if key.code == KeyCode::Char('f') {
            self.popup = Some(Popup::RenderFirewall {
                backend_selected: 0, // default to nftables (recommended)
                out_path: crate::firewall::DEFAULT_OUTPUT_PATH.to_string(),
                apply_after_write: false,
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }

        match self.focus {
            Focus::Categories => match key.code {
                // No popup open: let `App`'s global handling decide (Esc/q
                // quit from the Dashboard).
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.list_state.selected() == Some(CATEGORIES.len() - 1) {
                        self.focus = Focus::Countries;
                        self.countries_state.select(Some(0));
                    } else {
                        self.list_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.open_category_popup(),
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Countries => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.countries_state.selected() == Some(0) {
                        self.focus = Focus::Categories;
                        self.list_state.select(Some(CATEGORIES.len() - 1));
                    } else {
                        self.countries_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => self.countries_state.select_next(),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return self.activate_country_row(message, db);
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
        }
        Ok(KeyOutcome::Consumed)
    }

    fn open_category_popup(&mut self) {
        let Some(selected) = self.list_state.selected() else {
            return;
        };
        let Some(&category) = CATEGORIES.get(selected) else {
            return;
        };
        let selected_option = match self.category_default(category) {
            Policy::Allowed => 0,
            Policy::Blocked => 1,
        };
        self.popup = Some(Popup::Category {
            category,
            selected: selected_option,
        });
    }

    /// Handles Enter/Space on the Countries list: opens the add-country
    /// input popup on row 0, or directly unblocks the selected country
    /// (see this module's doc comment for why that's a direct action rather
    /// than a popup).
    fn activate_country_row(
        &mut self,
        message: &mut Option<String>,
        db: &Db,
    ) -> Result<KeyOutcome> {
        let Some(selected) = self.countries_state.selected() else {
            return Ok(KeyOutcome::Consumed);
        };
        if selected == 0 {
            self.popup = Some(Popup::AddCountry {
                input: String::new(),
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }
        let Some(country_code) = self.selected_countries.get(selected - 1) else {
            return Ok(KeyOutcome::Consumed);
        };
        db.set_country_selected(country_code, false)?;
        *message = Some(format!("Removed {}", country_code.to_uppercase()));
        Ok(KeyOutcome::Mutated)
    }
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Scanner => "Scanners",
        Category::Search => "Search Bots",
        Category::Ai => "AI Bots",
    }
}

fn policy_tag(policy: Policy) -> Span<'static> {
    match policy {
        Policy::Allowed => " [ ALLOWED ] ".green(),
        Policy::Blocked => " [ BLOCKED ] ".red(),
    }
}

/// Braille "dots" spinner frames for the "Running now" indicator.
const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Picks the current spinner frame from wall-clock time rather than a
/// counter `Dashboard` would need to own and advance itself — since
/// `render` is called on every redraw of the TUI's draw loop, this alone
/// is enough to animate smoothly.
fn spinner_frame() -> char {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let frame = (millis / 80) % SPINNER_FRAMES.len() as u128;
    SPINNER_FRAMES[frame as usize]
}

/// Renders one line of the "Scheduled tasks" panel: the job's label, when
/// it last ran (or "never"), and its last outcome — or, if it's currently
/// running in the background (`running`) or due but not yet started, that
/// instead (the outcome shown would otherwise be stale the moment a job
/// becomes due again, misleadingly implying nothing's changed since).
fn cron_status_line(status: &crate::cron::JobStatus, running: bool) -> Line<'static> {
    let last_run = match status.last_run {
        Some(t) => format_relative_time(t),
        None => "never".to_string(),
    };
    let outcome = if running {
        format!("{} Running now", spinner_frame())
    } else if status.due {
        "due now".to_string()
    } else {
        status
            .last_summary
            .clone()
            .unwrap_or_else(|| "-".to_string())
    };
    // Deliberately compact (no fixed-width padding): the panel is a fixed
    // 4-line block with no wrapping, so a long label/summary combination
    // must fit the terminal's width rather than get silently clipped.
    Line::from(format!(
        "{}: last ran {last_run}, {outcome}",
        status.job.label()
    ))
}

/// Formats a Unix timestamp `t` (assumed to be in the past) as a short
/// "Nd"/"Nh"/"Nm"/"just now" relative-time string for the "Scheduled
/// tasks" panel — coarser precision the further back `t` is, matching how
/// `main.rs::format_expiry` rounds an upcoming expiry the same way.
fn format_relative_time(t: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let elapsed = (now - t).max(0);
    if elapsed < 60 {
        "just now".to_string()
    } else if elapsed < 3_600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("{}h ago", elapsed / 3_600)
    } else {
        format!("{}d ago", elapsed / 86_400)
    }
}

/// Whether the firewall's current rule set differs from what was in effect
/// at the last successful render — see the `Dashboard::firewall_needs_update`
/// field doc for what this drives. Never reads the on-disk script itself:
/// comparing a signature the app itself persisted on the last successful
/// write (`Db::get_firewall_rendered_signature`) keeps this hermetic (no
/// dependency on a real system path existing) and correctly reflects "did
/// the desired rules change since our own last render", not "does some
/// file's bytes happen to match", which is also unaffected by which
/// backend/output path that last render used (see `rules_signature`'s doc).
fn firewall_needs_update(db: &Db) -> Result<bool> {
    let current = crate::firewall::rules_signature(&crate::firewall::all_rules(db)?);
    Ok(db.get_firewall_rendered_signature()?.as_deref() != Some(current.as_str()))
}

fn is_stale(last_fetched_at: Option<i64>) -> bool {
    let Some(last_fetched_at) = last_fetched_at else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now - last_fetched_at > STALE_AFTER_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, NewBot};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn is_stale_treats_never_fetched_as_stale() {
        assert!(is_stale(None));
    }

    #[test]
    fn is_stale_treats_recent_fetch_as_fresh() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(!is_stale(Some(now)));
    }

    #[test]
    fn is_stale_treats_old_fetch_as_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(is_stale(Some(now - STALE_AFTER_SECS - 1)));
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn format_relative_time_rounds_to_the_coarsest_useful_unit() {
        assert_eq!(format_relative_time(now_secs() - 30), "just now");
        assert_eq!(format_relative_time(now_secs() - 5 * 60), "5m ago");
        assert_eq!(format_relative_time(now_secs() - 3 * 3_600), "3h ago");
        assert_eq!(format_relative_time(now_secs() - 2 * 86_400), "2d ago");
    }

    #[test]
    fn cron_status_line_shows_never_and_due_now_for_an_unrun_job() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::BlockScanners,
            last_run: None,
            last_summary: None,
            due: true,
        };
        let rendered = cron_status_line(&status, false).to_string();
        assert!(rendered.contains("never"));
        assert!(rendered.contains("due now"));
    }

    #[test]
    fn cron_status_line_shows_last_run_and_summary_for_a_completed_job() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::BlockWebScanners,
            last_run: Some(now_secs() - 3_600),
            last_summary: Some("blocked 2 IP(s)".to_string()),
            due: false,
        };
        let rendered = cron_status_line(&status, false).to_string();
        assert!(rendered.contains("1h ago"));
        assert!(rendered.contains("blocked 2 IP(s)"));
        assert!(!rendered.contains("due now"));
    }

    /// `running` must override both "due now" and any stale summary with a
    /// "Running now" indicator — the frame character itself is
    /// time-derived, so only the fixed label is asserted here, not a
    /// specific spinner glyph.
    #[test]
    fn cron_status_line_shows_running_now_when_a_job_is_in_flight() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::RenderFirewall,
            last_run: Some(now_secs() - 3_600),
            last_summary: Some("wrote 3 rule(s) to /etc/stop-bots/firewall.nft".to_string()),
            due: true,
        };
        let rendered = cron_status_line(&status, true).to_string();
        assert!(rendered.contains("Running now"), "rendered was: {rendered}");
        assert!(!rendered.contains("due now"), "rendered was: {rendered}");
        assert!(
            !rendered.contains("wrote 3 rule(s)"),
            "rendered was: {rendered}"
        );
    }

    #[test]
    fn render_shows_the_scheduled_tasks_panel() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(
            crate::cron::CronJob::BlockScanners.id(),
            now_secs(),
            "blocked 3 IP(s)",
        )
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &None,
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Scheduled tasks"));
        assert!(content.contains("Block SSH scanners"));
        assert!(content.contains("blocked 3 IP(s)"));
        assert!(content.contains("Update crawler IP ranges"));
        assert!(content.contains("due now"));
    }

    #[test]
    fn render_shows_running_now_for_a_job_in_the_running_set() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(
            crate::cron::CronJob::BlockScanners.id(),
            now_secs(),
            "blocked 3 IP(s)",
        )
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let running_jobs = std::collections::HashSet::from([crate::cron::CronJob::BlockScanners]);
        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| dashboard.render(frame, frame.area(), Theme::Dark, &None, &running_jobs))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Running now"), "content was: {content}");
        assert!(
            !content.contains("blocked 3 IP(s)"),
            "content was: {content}"
        );
    }

    #[test]
    fn render_shows_the_summary_panel() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &None,
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Summary"));
        assert!(content.contains("Sites discovered: 1"));
    }

    #[test]
    fn refresh_loads_counts_from_db() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        assert_eq!(dashboard.site_count, 1);
        assert_eq!(dashboard.scanner_default, Policy::Blocked);
        assert_eq!(dashboard.search_default, Policy::Allowed);
        assert_eq!(dashboard.ai_default, Policy::Blocked);
        assert_eq!(dashboard.list_state.selected(), Some(0));
    }

    #[test]
    fn refresh_counts_stale_and_fresh_sources_separately() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "fresh".to_string(),
            name: "Fresh Source".to_string(),
            url: "https://example.invalid/fresh".to_string(),
            last_fetched_at: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            ),
            bot_count: 1,
        })
        .unwrap();
        db.upsert_source(&Source {
            id: "stale".to_string(),
            name: "Stale Source".to_string(),
            url: "https://example.invalid/stale".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        assert_eq!(dashboard.up_to_date_count(), 1);
        assert_eq!(dashboard.needs_update_count(), 1);
    }

    #[test]
    fn render_shows_overview_stats_and_messages() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();
        // upsert_bot requires a source to exist (foreign key); not needed here.
        let _ = NewBot {
            slug: "unused".to_string(),
            name: "unused".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "unused".to_string(),
            source_id: "unused".to_string(),
        };

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &Some("Stored 4 bot(s)".to_string()),
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Scanners"));
        assert!(content.contains("BLOCKED"));
        assert!(content.contains("Sites discovered: 1"));
        assert!(content.contains("Stored 4 bot(s)"));
    }

    #[test]
    fn down_then_up_moves_selection_and_back() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.list_state.selected(), Some(1));

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.list_state.selected(), Some(0));
    }

    #[test]
    fn enter_opens_popup_at_current_value() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        // Row 0 is Scanners, default Blocked.

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::Category { category, selected } => {
                assert_eq!(category, Category::Scanner);
                assert_eq!(selected, 1); // Blocked
            }
            other => panic!("expected a Category popup, got {other:?}"),
        }
    }

    #[test]
    fn confirming_popup_writes_through_and_closes() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        // Move selection to "Allowed" and confirm.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Allowed
        );
        assert!(message.unwrap().contains("Scanners"));
    }

    #[test]
    fn escape_closes_popup_without_saving() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Blocked
        );
    }

    #[test]
    fn escape_with_no_popup_is_ignored_so_app_can_quit() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Ignored);
    }

    #[test]
    fn down_past_the_last_category_moves_focus_into_countries() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        for _ in 0..CATEGORIES.len() - 1 {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
                .unwrap();
        }
        assert_eq!(dashboard.focus, Focus::Categories);

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.focus, Focus::Countries);
        assert_eq!(dashboard.countries_state.selected(), Some(0));
    }

    #[test]
    fn up_from_the_first_country_row_moves_focus_back_to_categories() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(0));

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();

        assert_eq!(dashboard.focus, Focus::Categories);
        assert_eq!(dashboard.list_state.selected(), Some(CATEGORIES.len() - 1));
    }

    #[test]
    fn enter_on_add_country_row_opens_the_input_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(0));

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::AddCountry { input, error } => {
                assert!(input.is_empty());
                assert!(error.is_none());
            }
            other => panic!("expected an AddCountry popup, got {other:?}"),
        }
    }

    #[test]
    fn add_country_popup_rejects_an_invalid_code_and_stays_open() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "u".to_string(),
            error: None,
        });

        let mut message = None;
        // Only one character typed: Enter should reject it as too short.
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.unwrap() {
            Popup::AddCountry { error, .. } => assert!(error.is_some()),
            other => panic!("expected an AddCountry popup, got {other:?}"),
        }
    }

    #[test]
    fn add_country_popup_confirming_an_unfetched_code_returns_select_country() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::SelectCountry("nl".to_string()));
        assert!(dashboard.popup.is_none());
    }

    #[test]
    fn add_country_popup_confirming_an_already_fetched_code_selects_it_directly() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.list_selected_countries().unwrap(),
            vec!["nl".to_string()]
        );
        // Default geo mode is Blocklist, so selecting a country blocks it.
        assert!(message.unwrap().contains("Blocked NL"));
    }

    #[test]
    fn add_country_popup_confirming_an_already_selected_code_is_a_noop_with_a_message() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.unwrap().contains("already selected"));
    }

    #[test]
    fn typing_and_backspacing_in_the_add_country_popup_edits_the_input() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: String::new(),
            error: None,
        });

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('N')), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('L')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::AddCountry { input, .. }) => assert_eq!(input, "nl"),
            _ => panic!("expected an AddCountry popup"),
        }

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Backspace), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::AddCountry { input, .. }) => assert_eq!(input, "n"),
            _ => panic!("expected an AddCountry popup"),
        }
    }

    #[test]
    fn enter_on_a_selected_country_row_removes_it_directly() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(1)); // row 0 is "Add", row 1 is "nl"

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_selected_countries().unwrap().is_empty());
        assert!(message.unwrap().contains("Removed NL"));
    }

    /// Regression test: unblocking the *last* selected row must not leave
    /// `countries_state` pointing past the new last row. `refresh()` only
    /// reseeds the selection when it's `None`, so a naive implementation
    /// leaves a stale out-of-range index after the list shrinks out from
    /// under it.
    #[test]
    fn removing_the_last_selected_country_clamps_the_selection() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        // Rows: 0 = Add, 1 = nl, 2 = us. Select the last one and remove it.
        dashboard.countries_state.select(Some(2));

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Mutated);
        dashboard.refresh(&db).unwrap();

        // Only "Add" (0) and "nl" (1) remain; the stale index 2 must have
        // been clamped down to 1, not left pointing past the end.
        assert_eq!(dashboard.countries_state.selected(), Some(1));
    }

    #[test]
    fn render_shows_the_geo_blocking_panel_and_selected_countries() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &None,
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Geo-blocking"));
        assert!(content.contains("Blocklist"));
        assert!(content.contains("Add a country"));
        assert!(content.contains("NL"));
        assert!(content.contains("1 range(s)"));
    }

    #[test]
    fn m_key_opens_the_geo_mode_popup_at_the_current_mode() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('m')), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::GeoMode { selected } => assert_eq!(selected, 0), // Blocklist
            other => panic!("expected a GeoMode popup, got {other:?}"),
        }
    }

    #[test]
    fn confirming_the_geo_mode_popup_switches_mode_and_reflects_in_new_messages() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode { selected: 0 });

        let mut message = None;
        // Move to "Allowlist" and confirm.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Allowlist);
        assert!(message.unwrap().contains("Allowlist"));

        // Selecting a country now reads "Allowed", not "Blocked".
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(message.unwrap().contains("Allowed NL"));
    }

    #[test]
    fn escape_closes_the_geo_mode_popup_without_changing_it() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode { selected: 1 });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.popup.is_none());
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Blocklist);
    }

    #[test]
    fn f_key_opens_the_render_firewall_popup_with_defaults() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::RenderFirewall {
                backend_selected,
                out_path,
                apply_after_write,
                error,
            } => {
                assert_eq!(backend_selected, 0);
                assert_eq!(out_path, crate::firewall::DEFAULT_OUTPUT_PATH);
                assert!(!apply_after_write);
                assert!(error.is_none());
            }
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    /// Regression test: `j`/`k` are common path characters, but every other
    /// popup/list in this app treats them as vim-style Down/Up aliases.
    /// This popup has a free-text output-path field, so those aliases must
    /// NOT apply here — otherwise typing a path containing 'j' or 'k'
    /// silently drops that character instead of appending it (found via
    /// `App`'s `pressing_f_then_enter_refreshes_the_dashboards_stale_indicator`
    /// flaking whenever a temp-dir path happened to contain one).
    #[test]
    fn render_firewall_popup_accepts_literal_j_and_k_in_the_output_path() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: String::new(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        for c in "/tmp/jk-test.nft".chars() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char(c)), &db, &mut message)
                .unwrap();
        }

        match &dashboard.popup {
            Some(Popup::RenderFirewall { out_path, .. }) => {
                assert_eq!(out_path, "/tmp/jk-test.nft")
            }
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn space_toggles_apply_after_write_in_the_render_firewall_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: "/tmp/fw.nft".to_string(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::RenderFirewall {
                apply_after_write, ..
            }) => assert!(apply_after_write),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }

        // Toggling again flips it back off.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::RenderFirewall {
                apply_after_write, ..
            }) => assert!(!apply_after_write),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn enter_in_render_firewall_popup_carries_the_apply_toggle_through() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: "/tmp/fw.nft".to_string(),
            apply_after_write: true,
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match outcome {
            KeyOutcome::RenderFirewall {
                out_path, apply, ..
            } => {
                assert_eq!(out_path, "/tmp/fw.nft");
                assert!(apply);
            }
            other => panic!("expected a RenderFirewall outcome, got {other:?}"),
        }
        assert!(dashboard.popup.is_none());
    }

    #[test]
    fn render_firewall_popup_rejects_an_empty_output_path_and_stays_open() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: String::new(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.unwrap() {
            Popup::RenderFirewall { error, .. } => assert!(error.is_some()),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn firewall_needs_update_is_true_before_any_render() {
        let db = Db::open_in_memory().unwrap();
        assert!(firewall_needs_update(&db).unwrap());
    }

    #[test]
    fn firewall_needs_update_is_false_right_after_a_matching_render() {
        let db = Db::open_in_memory().unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();
        assert!(!firewall_needs_update(&db).unwrap());
    }

    #[test]
    fn firewall_needs_update_is_true_again_after_the_rule_set_changes() {
        let db = Db::open_in_memory().unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();

        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "9.9.9.9".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
        })
        .unwrap();

        assert!(firewall_needs_update(&db).unwrap());
    }

    #[test]
    fn render_shows_the_firewall_summary_row() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &None,
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Firewall rules: needs updating"));
        assert!(content.contains("press f to update"));
    }

    #[test]
    fn render_shows_the_firewall_summary_row_as_up_to_date_after_a_render() {
        let db = Db::open_in_memory().unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &None,
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Firewall rules: up to date"));
        assert!(!content.contains("needs updating"));
    }
}
