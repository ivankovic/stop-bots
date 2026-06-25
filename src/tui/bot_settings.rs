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

//! The Bot settings screen: the three global category defaults (Scanners,
//! Search Bots, AI Bots) plus every known bot and its effective status.
//! Enter/Space opens a popup to change the selected row; Escape closes the
//! popup without saving.

use crate::db::{Bot, BotStatus, Category, Db, Policy};
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::Stylize,
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState},
    Frame,
};

/// A row in the combined category + bot list.
#[derive(Debug, Clone, Copy)]
enum Row {
    Category(Category),
    Bot(usize),
}

/// What's being changed in the open popup, and the options to cycle through.
#[derive(Debug, Clone)]
enum PopupTarget {
    Category(Category),
    Bot(String),
}

#[derive(Debug)]
struct Popup {
    target: PopupTarget,
    options: Vec<&'static str>,
    selected: usize,
}

#[derive(Debug, Default)]
pub struct BotSettings {
    bots: Vec<Bot>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
    list_state: ListState,
    popup: Option<Popup>,
}

impl BotSettings {
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.bots = db.list_bots()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        Ok(())
    }

    fn rows(&self) -> Vec<Row> {
        let mut rows = vec![
            Row::Category(Category::Scanner),
            Row::Category(Category::Search),
            Row::Category(Category::Ai),
        ];
        rows.extend((0..self.bots.len()).map(Row::Bot));
        rows
    }

    fn category_default(&self, category: Category) -> Policy {
        match category {
            Category::Scanner => self.scanner_default,
            Category::Search => self.search_default,
            Category::Ai => self.ai_default,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let rows = self.rows();
        let items: Vec<ListItem> = rows
            .iter()
            .map(|row| ListItem::new(self.row_line(*row)))
            .collect();

        let list = List::new(items)
            .block(
                Block::bordered()
                    .title("Categories & bots")
                    .fg(theme.accent()),
            )
            .highlight_style(ratatui::style::Style::new().reversed());
        frame.render_stateful_widget(list, area, &mut self.list_state);

        if let Some(popup) = &self.popup {
            self.render_popup(frame, area, popup);
        }
    }

    fn row_line(&self, row: Row) -> Line<'static> {
        match row {
            Row::Category(category) => {
                let label = match category {
                    Category::Scanner => "Scanners",
                    Category::Search => "Search Bots",
                    Category::Ai => "AI Bots",
                };
                let mut line = vec![Span::from(format!("{label:<24}")).bold()];
                line.push(policy_tag(self.category_default(category)));
                Line::from(line)
            }
            Row::Bot(index) => {
                let bot = &self.bots[index];
                let effective = effective_policy(
                    bot,
                    self.ai_default,
                    self.search_default,
                    self.scanner_default,
                );
                let mut line = vec![Span::from(format!("  {:<22}", bot.name))];
                line.push(policy_tag(effective));
                if bot.status != BotStatus::Default {
                    line.push(Span::from(" (override)").dim());
                }
                Line::from(line)
            }
        }
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: &Popup) {
        let title = match &popup.target {
            PopupTarget::Category(category) => match category {
                Category::Scanner => "Scanners default",
                Category::Search => "Search Bots default",
                Category::Ai => "AI Bots default",
            }
            .to_string(),
            PopupTarget::Bot(slug) => format!("Override: {slug}"),
        };

        let content_width = popup
            .options
            .iter()
            .map(|o| o.len())
            .max()
            .unwrap_or(0)
            .max(title.len());
        let popup_area = centered_rect(
            content_width as u16 + 4,
            popup.options.len() as u16 + 2,
            area,
        );
        let items: Vec<ListItem> = popup
            .options
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
                    popup.selected = (popup.selected + 1).min(popup.options.len() - 1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let popup = self.popup.take().expect("checked above");
                    *message = Some(self.apply_popup(db, popup)?);
                    // The caller (`App`) reloads every screen on `Mutated`,
                    // so no need to refresh `self` here too.
                    return Ok(KeyOutcome::Mutated);
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }

        match key.code {
            KeyCode::Esc => return Ok(KeyOutcome::Back),
            KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
            KeyCode::Down | KeyCode::Char('j') => self.list_state.select_next(),
            KeyCode::Enter | KeyCode::Char(' ') => self.open_popup(),
            _ => return Ok(KeyOutcome::Ignored),
        }
        Ok(KeyOutcome::Consumed)
    }

    fn open_popup(&mut self) {
        let rows = self.rows();
        let Some(selected) = self.list_state.selected() else {
            return;
        };
        let Some(row) = rows.get(selected) else {
            return;
        };
        self.popup = Some(match *row {
            Row::Category(category) => Popup {
                target: PopupTarget::Category(category),
                options: vec!["Allowed", "Blocked"],
                selected: match self.category_default(category) {
                    Policy::Allowed => 0,
                    Policy::Blocked => 1,
                },
            },
            Row::Bot(index) => {
                let bot = &self.bots[index];
                Popup {
                    target: PopupTarget::Bot(bot.slug.clone()),
                    options: vec!["Default", "Allowed", "Blocked"],
                    selected: match bot.status {
                        BotStatus::Default => 0,
                        BotStatus::Allowed => 1,
                        BotStatus::Blocked => 2,
                    },
                }
            }
        });
    }

    /// Writes the popup's selected option to `db` and returns a status message.
    fn apply_popup(&self, db: &Db, popup: Popup) -> Result<String> {
        match popup.target {
            PopupTarget::Category(category) => {
                let policy = match popup.selected {
                    0 => Policy::Allowed,
                    _ => Policy::Blocked,
                };
                db.set_category_default(category, policy)?;
                Ok(format!(
                    "{} default set to {policy:?}",
                    category_label(category)
                ))
            }
            PopupTarget::Bot(slug) => {
                let status = match popup.selected {
                    0 => BotStatus::Default,
                    1 => BotStatus::Allowed,
                    _ => BotStatus::Blocked,
                };
                db.set_bot_status(&slug, status)?;
                Ok(format!("{slug} set to {status:?}"))
            }
        }
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

/// Mirrors the precedence in `Db::blocked_user_agent_patterns`: an explicit
/// override wins, otherwise the bot follows whichever of its categories'
/// defaults apply.
fn effective_policy(
    bot: &Bot,
    ai_default: Policy,
    search_default: Policy,
    scanner_default: Policy,
) -> Policy {
    match bot.status {
        BotStatus::Allowed => Policy::Allowed,
        BotStatus::Blocked => Policy::Blocked,
        BotStatus::Default => {
            let blocked = (bot.is_ai && ai_default == Policy::Blocked)
                || (bot.is_search_engine && search_default == Policy::Blocked)
                || (bot.is_scanner && scanner_default == Policy::Blocked);
            if blocked {
                Policy::Blocked
            } else {
                Policy::Allowed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewBot;

    fn test_db_with_bot(slug: &str, is_ai: bool) -> Db {
        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&crate::db::Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&NewBot {
            slug: slug.to_string(),
            name: slug.to_string(),
            is_ai,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: format!("{slug}-ua"),
            source_id: "test".to_string(),
        })
        .unwrap();
        db
    }

    #[test]
    fn refresh_loads_bots_and_category_defaults() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        assert_eq!(screen.bots.len(), 1);
        assert_eq!(screen.ai_default, Policy::Blocked);
        assert_eq!(screen.list_state.selected(), Some(0));
    }

    #[test]
    fn rows_lists_categories_before_bots() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        let rows = screen.rows();
        assert_eq!(rows.len(), 4);
        assert!(matches!(rows[0], Row::Category(Category::Scanner)));
        assert!(matches!(rows[3], Row::Bot(0)));
    }

    #[test]
    fn effective_policy_follows_category_default_unless_overridden() {
        let bot = Bot {
            id: 1,
            slug: "gptbot".to_string(),
            name: "gptbot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "gptbot-ua".to_string(),
            status: BotStatus::Default,
            source_id: "test".to_string(),
            updated_at: 0,
        };
        assert_eq!(
            effective_policy(&bot, Policy::Blocked, Policy::Allowed, Policy::Blocked),
            Policy::Blocked
        );

        let mut allowed_bot = bot.clone();
        allowed_bot.status = BotStatus::Allowed;
        assert_eq!(
            effective_policy(
                &allowed_bot,
                Policy::Blocked,
                Policy::Allowed,
                Policy::Blocked
            ),
            Policy::Allowed
        );
    }

    #[test]
    fn enter_on_category_row_opens_popup_at_current_value() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.list_state.select(Some(0)); // Scanner row, default Blocked

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let popup = screen.popup.as_ref().unwrap();
        assert!(matches!(
            popup.target,
            PopupTarget::Category(Category::Scanner)
        ));
        assert_eq!(popup.selected, 1); // Blocked
    }

    #[test]
    fn confirming_category_popup_writes_through_and_closes() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.list_state.select(Some(0)); // Scanner row

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        // Move selection to "Allowed" and confirm.
        screen
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert!(screen.popup.is_none());
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Allowed
        );
        assert!(message.unwrap().contains("Scanners"));
    }

    #[test]
    fn escape_closes_popup_without_saving() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.list_state.select(Some(0));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
        // Unchanged: escape must not have written the in-progress selection.
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Blocked
        );
    }

    #[test]
    fn escape_with_no_popup_backs_out_to_dashboard() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Back);
    }

    #[test]
    fn confirming_bot_popup_sets_override_and_returns_mutated() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.list_state.select(Some(3)); // the gptbot row

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Default -> Allowed
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        // The screen itself doesn't self-refresh after a write (the caller
        // does, on `Mutated`); what matters is the write actually landed.
        assert_eq!(outcome, KeyOutcome::Mutated);
        let bots = db.list_bots().unwrap();
        assert_eq!(bots[0].status, BotStatus::Allowed);
        assert!(message.unwrap().contains("gptbot"));
    }
}
