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
//! how many sites are known, and whether bot-list sources are up to date.
//! No per-request traffic metrics yet (see TODO.md) — there is no log
//! analysis backend to source them from.

use crate::db::{Category, Db, Policy, Source};
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
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

/// The popup opened on a category row: cycles between Allowed (0) and
/// Blocked (1), mirroring Bot settings' category popup before it moved here.
#[derive(Debug, Clone, Copy)]
struct Popup {
    category: Category,
    selected: usize,
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
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.site_count = db.list_sites()?.len();
        self.sources = db.list_sources()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        Ok(())
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
        let [settings_area, stats_area, message_area] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Min(1),
        ])
        .areas(area);

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
            .highlight_style(ratatui::style::Style::new().reversed());
        frame.render_stateful_widget(list, settings_area, &mut self.list_state);

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

        if let Some(popup) = self.popup {
            self.render_popup(frame, area, popup);
        }
    }

    fn row_line(&self, category: Category) -> Line<'static> {
        let mut line = vec![Span::from(format!("{:<14}", category_label(category)))];
        line.push(policy_tag(self.category_default(category)));
        Line::from(line)
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: Popup) {
        let title = format!("{} default", category_label(popup.category));
        let options = ["Allowed", "Blocked"];
        let content_width = options
            .iter()
            .map(|o| o.len())
            .max()
            .unwrap_or(0)
            .max(title.len());
        let popup_area = centered_rect(content_width as u16 + 4, options.len() as u16 + 2, area);
        let items: Vec<ListItem> = options
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let line = if i == popup.selected {
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

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if let Some(popup) = &mut self.popup {
            match key.code {
                KeyCode::Esc => {
                    self.popup = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    popup.selected = popup.selected.saturating_sub(1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    popup.selected = (popup.selected + 1).min(1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let popup = self.popup.take().expect("checked above");
                    let policy = match popup.selected {
                        0 => Policy::Allowed,
                        _ => Policy::Blocked,
                    };
                    db.set_category_default(popup.category, policy)?;
                    *message = Some(format!(
                        "{} default set to {policy:?}",
                        category_label(popup.category)
                    ));
                    return Ok(KeyOutcome::Mutated);
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }

        match key.code {
            // No popup open: let `App`'s global handling decide (Esc/q quit
            // from the Dashboard).
            KeyCode::Esc => return Ok(KeyOutcome::Ignored),
            KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
            KeyCode::Enter | KeyCode::Char(' ') => self.open_popup(),
            _ => return Ok(KeyOutcome::Ignored),
        }
        Ok(KeyOutcome::Consumed)
    }

    fn open_popup(&mut self) {
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
        self.popup = Some(Popup {
            category,
            selected: selected_option,
        });
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

        let backend = TestBackend::new(60, 14);
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

        let popup = dashboard.popup.unwrap();
        assert_eq!(popup.category, Category::Scanner);
        assert_eq!(popup.selected, 1); // Blocked
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
}
