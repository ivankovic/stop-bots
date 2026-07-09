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
//! host-wide geo-blocking (see "Geo-blocking" below). No per-request traffic
//! metrics yet (see TODO.md) — there is no log analysis backend to source
//! them from.
//!
//! ## Geo-blocking
//!
//! A second, independently-focused list (`countries_state`, switched to via
//! `Down` past the last category row or `Up` above the first country
//! row — no dedicated focus key, since these are just two vertically
//! stacked lists, not a list-plus-search-box pair like Bot settings'
//! `Focus`) shows every host-wide blocked country (`Db::list_blocked_countries`)
//! plus a fixed "+ Add a country to block" action row at the top. Enter on
//! that row opens a text-input popup for a two-letter code; Enter on an
//! existing country row unblocks it directly (no confirmation popup — unlike
//! a category default, unblocking a country isn't "choose one of several
//! options", it's a single reversible action, the same reasoning Site
//! settings' apply/apply-all actions already use). Confirming the input
//! popup with a code whose ranges are already fetched blocks it immediately
//! (`Mutated`); a not-yet-fetched code returns `KeyOutcome::BlockCountry` so
//! `App` can fetch it first (`App::start_country_block`) — see that
//! function's doc comment for why fetching can't happen here directly.

use crate::db::{Category, Db, Policy, Source};
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

/// The popup opened by the Dashboard: either editing a category default
/// (cycles between Allowed (0) and Blocked (1), mirroring Bot settings'
/// category popup before it moved here) or entering a country code to block.
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
    blocked_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    countries_state: ListState,
    focus: Focus,
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.site_count = db.list_sites()?.len();
        self.sources = db.list_sources()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        self.blocked_countries = db.list_blocked_countries()?;
        self.fetched_countries = db.list_fetched_countries()?;
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        if self.countries_state.selected().is_none() {
            self.countries_state.select(Some(0));
        }
        // Unblocking shrinks `blocked_countries`; without this the
        // selection could be left pointing past the new last row (stale
        // until the next arrow press re-clamps it via `select_previous`/
        // `select_next`) if the row that was just removed wasn't the last
        // one selected.
        let max_row = self.blocked_countries.len(); // +1 (the "Add" row) - 1 (0-indexed)
        if self.countries_state.selected().is_some_and(|s| s > max_row) {
            self.countries_state.select(Some(max_row));
        }
        Ok(())
    }

    /// How many CIDRs are currently known for `country_code`, if it's ever
    /// been fetched — `None` for a country that was blocked (e.g. via the
    /// CLI's `block-country`) before its ranges were ever fetched.
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

    fn needs_update_count(&self) -> usize {
        self.sources.len() - self.up_to_date_count()
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        message: &Option<String>,
    ) {
        let [settings_area, geo_area, stats_area, message_area] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(4),
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

        let country_items: Vec<ListItem> = std::iter::once(ListItem::new(
            Line::from("+ Add a country to block").italic(),
        ))
        .chain(
            self.blocked_countries
                .iter()
                .map(|cc| ListItem::new(self.country_row_line(cc))),
        )
        .collect();
        let country_list = List::new(country_items)
            .block(
                Block::bordered()
                    .title("Geo-blocking (host-wide) — Enter to add/remove")
                    .fg(theme.accent()),
            )
            .highlight_style(if self.focus == Focus::Countries {
                reversed
            } else {
                Style::default()
            });
        frame.render_stateful_widget(country_list, geo_area, &mut self.countries_state);

        let stats = Paragraph::new(vec![
            Line::from(format!("Sites discovered: {}", self.site_count)),
            Line::from(format!(
                "Bot list sources: {} up to date, {} need updating",
                self.up_to_date_count(),
                self.needs_update_count()
            )),
        ])
        .block(Block::bordered().title("Stats"));
        frame.render_widget(stats, stats_area);

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
        Line::from(format!("{:<8}{}", country_code.to_uppercase(), ranges))
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
                let title = "Block a country (2-letter code)";
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
                                if self.blocked_countries.iter().any(|b| b == &cc) {
                                    *message =
                                        Some(format!("{} is already blocked", cc.to_uppercase()));
                                    return Ok(KeyOutcome::Consumed);
                                }
                                if self.fetched_countries.iter().any(|(c, _, _)| c == &cc) {
                                    db.set_country_blocked(&cc, true)?;
                                    *message = Some(format!("Blocked {}", cc.to_uppercase()));
                                    return Ok(KeyOutcome::Mutated);
                                }
                                return Ok(KeyOutcome::BlockCountry(cc));
                            }
                        }
                    }
                    _ => return Ok(KeyOutcome::Consumed),
                },
            }
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
        let Some(country_code) = self.blocked_countries.get(selected - 1) else {
            return Ok(KeyOutcome::Consumed);
        };
        db.set_country_blocked(country_code, false)?;
        *message = Some(format!("Unblocked {}", country_code.to_uppercase()));
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

        let backend = TestBackend::new(60, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &Some("Stored 4 bot(s)".to_string()),
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
            Popup::AddCountry { .. } => panic!("expected a Category popup"),
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
            Popup::Category { .. } => panic!("expected an AddCountry popup"),
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
            Popup::Category { .. } => panic!("expected an AddCountry popup"),
        }
    }

    #[test]
    fn add_country_popup_confirming_an_unfetched_code_returns_block_country() {
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

        assert_eq!(outcome, KeyOutcome::BlockCountry("nl".to_string()));
        assert!(dashboard.popup.is_none());
    }

    #[test]
    fn add_country_popup_confirming_an_already_fetched_code_blocks_it_directly() {
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
        assert_eq!(db.list_blocked_countries().unwrap(), vec!["nl".to_string()]);
        assert!(message.unwrap().contains("NL"));
    }

    #[test]
    fn add_country_popup_confirming_an_already_blocked_code_is_a_noop_with_a_message() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_blocked("nl", true).unwrap();
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
        assert!(message.unwrap().contains("already blocked"));
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
    fn enter_on_a_blocked_country_row_unblocks_it_directly() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_blocked("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(1)); // row 0 is "Add", row 1 is "nl"

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_blocked_countries().unwrap().is_empty());
        assert!(message.unwrap().contains("Unblocked NL"));
    }

    /// Regression test: unblocking the *last* selected row must not leave
    /// `countries_state` pointing past the new last row. `refresh()` only
    /// reseeds the selection when it's `None`, so a naive implementation
    /// leaves a stale out-of-range index after the list shrinks out from
    /// under it.
    #[test]
    fn unblocking_the_last_selected_country_clamps_the_selection() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_blocked("nl", true).unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_blocked("us", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        // Rows: 0 = Add, 1 = nl, 2 = us. Select the last one and unblock it.
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
    fn render_shows_the_geo_blocking_panel_and_blocked_countries() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_blocked("nl", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| dashboard.render(frame, frame.area(), Theme::Dark, &None))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Geo-blocking"));
        assert!(content.contains("Add a country to block"));
        assert!(content.contains("NL"));
        assert!(content.contains("1 range(s)"));
    }
}
