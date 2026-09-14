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

//! The Bot settings screen: two panels, since the combined source+bot list
//! got too long to scan once a source actually had hundreds of bots in it.
//! "Bot list sources" (top) lists every bot-list source — name, last
//! fetched, signal/bot count — with Enter opening a Cancel/Update-now
//! confirmation popup. "Bot details" (bottom) holds a search box: press `/`
//! to focus it, type (part of) a bot's name, and Enter on a match opens a
//! popup to set that bot's status: "Use system settings" (the default —
//! follows whichever category default applies, see the Dashboard), or an
//! explicit "Allowed"/"Blocked" override. Every matched bot's row always
//! shows a `(system)` or `(override)` tag alongside its effective
//! `[ ALLOWED ]`/`[ BLOCKED ]` state, so it's never ambiguous which one is
//! actually driving that state. The three global category defaults used to
//! live here too; they've moved to the Dashboard.
//!
//! Only one of the two panels has keyboard focus at a time ([`Focus`]).
//! While the search box is focused, every printable key is query text (bot
//! names can contain spaces, digits, anything) rather than a shortcut —
//! Escape is what returns focus to the sources panel. Escape with no popup
//! and no search focus backs out to the Dashboard, matching every other
//! screen.

use crate::db::{Bot, BotStatus, Category, Db, Policy, Source};
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Which panel keyboard input currently goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Sources,
    Search,
}

/// What's being changed in the open popup, and the options to cycle through.
#[derive(Debug, Clone)]
enum PopupTarget {
    /// Confirming a refresh of the source with this id (`Source.id`, e.g.
    /// `"well-known-bots"` — not its display name, since this is what
    /// `KeyOutcome::UpdateSource` carries on to `App`, which needs the
    /// stable id to resolve a `botlist::SourceKind`).
    Source(String),
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
    sources: Vec<Source>,
    bots: Vec<Bot>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
    sources_state: ListState,
    query: String,
    results_state: ListState,
    focus: Focus,
    popup: Option<Popup>,
}

impl BotSettings {
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.sources = db.list_sources()?;
        self.bots = db.list_bots()?;
        // Not shown here anymore (see the Dashboard), but still needed to
        // compute each bot's effective policy below.
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        if self.sources_state.selected().is_none() {
            self.sources_state.select(Some(0));
        }
        Ok(())
    }

    /// Bots whose name or slug contains the current search query
    /// (case-insensitive). Empty until something is typed — the whole point
    /// of the search box is to avoid ever dumping the full bot list on
    /// screen at once.
    fn filtered_bots(&self) -> Vec<&Bot> {
        if self.query.is_empty() {
            return Vec::new();
        }
        let query = self.query.to_lowercase();
        self.bots
            .iter()
            .filter(|bot| {
                bot.name.to_lowercase().contains(&query) || bot.slug.to_lowercase().contains(&query)
            })
            .collect()
    }

    /// Snaps the results selection back to the top match, or clears it if
    /// the query no longer has any. Called whenever the query text changes.
    fn reset_results_selection(&mut self) {
        if self.filtered_bots().is_empty() {
            self.results_state.select(None);
        } else {
            self.results_state.select(Some(0));
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let sources_height = (self.sources.len() as u16 + 2).clamp(3, 8);
        let [sources_area, details_area] =
            Layout::vertical([Constraint::Length(sources_height), Constraint::Min(3)]).areas(area);

        self.render_sources(frame, sources_area, theme);
        self.render_details(frame, details_area, theme);

        if let Some(popup) = &self.popup {
            self.render_popup(frame, area, popup, theme);
        }
    }

    fn render_sources(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        // Measured, not a fixed 28: "Nginx Ultimate Bad Bot Blocker" is 30
        // and overflowed its column, so the counts beside it didn't line up
        // with the other two rows'.
        let name_width = self
            .sources
            .iter()
            .map(|source| source.name.chars().count())
            .max()
            .unwrap_or(0);
        let items: Vec<ListItem> = self
            .sources
            .iter()
            .map(|source| ListItem::new(source_line(source, name_width)))
            .collect();

        let focused = self.focus == Focus::Sources;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Bot list sources", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.sources_state);
    }

    fn render_details(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let focused = self.focus == Focus::Search;
        let block = crate::tui::panel("Bot details", focused, theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [search_area, results_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
        frame.render_widget(Paragraph::new(self.search_line()), search_area);

        let matches = self.filtered_bots();
        if matches.is_empty() {
            // No third "type something to search" hint here when the query
            // is empty and there are bots to search: `search_line()` above
            // already renders "Press / to search bots by name" in that
            // case, so a second hint would just repeat it.
            let hint = if !self.query.is_empty() {
                Some(format!("No bots match \"{}\".", self.query))
            } else if self.bots.is_empty() {
                Some(
                    "No bots yet — pick a source above and \"Update now\" to download some."
                        .to_string(),
                )
            } else {
                None
            };
            if let Some(hint) = hint {
                frame.render_widget(Paragraph::new(hint).dim(), results_area);
            }
            return;
        }

        let items: Vec<ListItem> = matches
            .iter()
            .map(|bot| {
                ListItem::new(bot_line(
                    bot,
                    self.ai_default,
                    self.search_default,
                    self.scanner_default,
                ))
            })
            .collect();
        let list = crate::tui::select_in(List::new(items), focused, theme);
        frame.render_stateful_widget(list, results_area, &mut self.results_state);
    }

    /// The footer's key hints for the focused panel.
    pub fn hints(&self) -> crate::tui::Hints {
        if self.popup.is_some() {
            return (
                "Popup",
                vec![
                    ("\u{2191}\u{2193}", "choose"),
                    ("Enter", "confirm"),
                    ("Esc", "cancel"),
                ],
            );
        }
        match self.focus {
            Focus::Sources => (
                "Sources",
                vec![
                    ("\u{2191}\u{2193}", "move"),
                    ("Enter", "update"),
                    ("/", "search bots"),
                    ("Tab", "next panel"),
                ],
            ),
            Focus::Search => (
                "Bots",
                vec![
                    ("type", "filter"),
                    ("\u{2191}\u{2193}", "move"),
                    ("Enter", "override"),
                    ("Esc", "leave search"),
                    ("Tab", "next panel"),
                ],
            ),
        }
    }

    fn search_line(&self) -> Line<'static> {
        match self.focus {
            Focus::Search => format!("/{}\u{2588}", self.query).into(),
            Focus::Sources if self.query.is_empty() => {
                Line::from(Span::from("Press / to search bots by name").dim())
            }
            Focus::Sources => Line::from(Span::from(format!("/{}", self.query)).dim()),
        }
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: &Popup, theme: Theme) {
        let title = match &popup.target {
            PopupTarget::Source(id) => {
                let name = self
                    .sources
                    .iter()
                    .find(|s| &s.id == id)
                    .map_or(id.as_str(), |s| s.name.as_str());
                format!("Update {name}?")
            }
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
        let list = List::new(items).block(crate::tui::popup(title, theme));
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
                    if matches!(popup.target, PopupTarget::Source(_)) {
                        let confirmed = popup.selected == 1;
                        let PopupTarget::Source(name) = popup.target else {
                            unreachable!("checked above")
                        };
                        return Ok(if confirmed {
                            KeyOutcome::UpdateSource(name)
                        } else {
                            KeyOutcome::Consumed
                        });
                    }
                    *message = Some(self.apply_popup(db, popup)?);
                    // The caller (`App`) reloads every screen on `Mutated`,
                    // so no need to refresh `self` here too.
                    return Ok(KeyOutcome::Mutated);
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }

        // Tab hops between the two panels without touching the query, so
        // a half-typed search survives a look at the sources.
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.focus = match self.focus {
                Focus::Sources => Focus::Search,
                Focus::Search => Focus::Sources,
            };
            return Ok(KeyOutcome::Consumed);
        }

        match self.focus {
            Focus::Sources => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Back),
                KeyCode::Up | KeyCode::Char('k') => self.sources_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => self.sources_state.select_next(),
                KeyCode::Enter | KeyCode::Char(' ') => self.open_source_popup(),
                KeyCode::Char('/') => self.focus = Focus::Search,
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Search => match key.code {
                // Esc leaves the search box rather than backing out to the
                // Dashboard — a second Esc (now with Sources focused and no
                // popup open) does that instead, same nested-back-out
                // pattern popups already use.
                KeyCode::Esc => self.focus = Focus::Sources,
                KeyCode::Up => self.results_state.select_previous(),
                KeyCode::Down => self.results_state.select_next(),
                KeyCode::Enter => self.open_bot_popup(),
                KeyCode::Backspace => {
                    self.query.pop();
                    self.reset_results_selection();
                }
                // Includes Space: bot names can contain one, so it's query
                // text here rather than the "confirm" shortcut Space is
                // everywhere else in this app.
                KeyCode::Char(c) => {
                    self.query.push(c);
                    self.reset_results_selection();
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
        }
        Ok(KeyOutcome::Consumed)
    }

    fn open_source_popup(&mut self) {
        let Some(selected) = self.sources_state.selected() else {
            return;
        };
        let Some(source) = self.sources.get(selected) else {
            return;
        };
        self.popup = Some(Popup {
            target: PopupTarget::Source(source.id.clone()),
            options: vec!["Cancel", "Update now"],
            selected: 0,
        });
    }

    fn open_bot_popup(&mut self) {
        let Some(selected) = self.results_state.selected() else {
            return;
        };
        let matches = self.filtered_bots();
        let Some(bot) = matches.get(selected) else {
            return;
        };
        self.popup = Some(Popup {
            target: PopupTarget::Bot(bot.slug.clone()),
            options: vec!["Use system settings", "Allowed", "Blocked"],
            selected: match bot.status {
                BotStatus::Default => 0,
                BotStatus::Allowed => 1,
                BotStatus::Blocked => 2,
            },
        });
    }

    /// Writes the popup's selected option to `db` and returns a status
    /// message. Only ever called for a [`PopupTarget::Bot`] popup — a
    /// [`PopupTarget::Source`] confirmation is handled in `handle_key`
    /// before reaching here, since it triggers an async fetch rather than a
    /// direct write.
    fn apply_popup(&self, db: &Db, popup: Popup) -> Result<String> {
        let PopupTarget::Bot(slug) = popup.target else {
            unreachable!("Source popups are handled before reaching apply_popup")
        };
        let status = match popup.selected {
            0 => BotStatus::Default,
            1 => BotStatus::Allowed,
            _ => BotStatus::Blocked,
        };
        db.set_bot_status(&slug, status)?;
        Ok(format!("{slug} set to {}", status_label(status)))
    }
}

fn source_line(source: &Source, name_width: usize) -> Line<'static> {
    Line::from(vec![
        Span::from(format!("{:<name_width$}  ", source.name)).bold(),
        Span::from(format!("{:>5} bots  ", source.bot_count)).dim(),
        Span::from(humanize_age(source.last_fetched_at)).dim(),
    ])
}

fn bot_line(
    bot: &Bot,
    ai_default: Policy,
    search_default: Policy,
    scanner_default: Policy,
) -> Line<'static> {
    let effective = effective_policy(bot, ai_default, search_default, scanner_default);
    let mut line = vec![Span::from(format!("  {:<22}", bot.name))];
    line.push(policy_tag(effective));
    // Always shown, not just on override: the point is to make it
    // unambiguous whether this bot is following the system default or has
    // its own explicit setting, not just to flag the exceptional case.
    let annotation = match bot.status {
        BotStatus::Default => " (system)",
        BotStatus::Allowed | BotStatus::Blocked => " (override)",
    };
    line.push(Span::from(annotation).dim());
    Line::from(line)
}

/// The label shown for each `BotStatus` in the override popup and in the
/// confirmation message after picking one.
fn status_label(status: BotStatus) -> &'static str {
    match status {
        BotStatus::Default => "use system settings",
        BotStatus::Allowed => "Allowed",
        BotStatus::Blocked => "Blocked",
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

/// A short "updated Xs/Xm/Xh/Xd ago" (or "never updated") label.
fn humanize_age(last_fetched_at: Option<i64>) -> String {
    let Some(last_fetched_at) = last_fetched_at else {
        return "never updated".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let age = (now - last_fetched_at).max(0);
    if age < 60 {
        format!("updated {age}s ago")
    } else if age < 3600 {
        format!("updated {}m ago", age / 60)
    } else if age < 86400 {
        format!("updated {}h ago", age / 3600)
    } else {
        format!("updated {}d ago", age / 86400)
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

    fn search_for(screen: &mut BotSettings, db: &Db, query: &str) {
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('/')), db, &mut message)
            .unwrap();
        for c in query.chars() {
            screen
                .handle_key(KeyEvent::from(KeyCode::Char(c)), db, &mut message)
                .unwrap();
        }
    }

    #[test]
    fn refresh_loads_sources_bots_and_category_defaults() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        assert_eq!(screen.sources.len(), 1);
        assert_eq!(screen.bots.len(), 1);
        assert_eq!(screen.ai_default, Policy::Blocked);
        assert_eq!(screen.sources_state.selected(), Some(0));
        assert_eq!(screen.focus, Focus::Sources);
    }

    #[test]
    fn filtered_bots_is_empty_until_something_is_typed() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        assert!(screen.filtered_bots().is_empty());
    }

    #[test]
    fn slash_focuses_search_and_typing_filters_by_name_case_insensitively() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        search_for(&mut screen, &db, "GPT");

        assert_eq!(screen.focus, Focus::Search);
        let matches = screen.filtered_bots();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].slug, "gptbot");
        assert_eq!(screen.results_state.selected(), Some(0));
    }

    #[test]
    fn search_with_no_matches_clears_the_results_selection() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        search_for(&mut screen, &db, "nonexistent-bot");

        assert!(screen.filtered_bots().is_empty());
        assert_eq!(screen.results_state.selected(), None);
    }

    #[test]
    fn backspace_shrinks_the_query_and_refilters() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        search_for(&mut screen, &db, "gptbotx"); // no match
        assert!(screen.filtered_bots().is_empty());

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Backspace), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filtered_bots().len(), 1); // "gptbot" matches again
    }

    #[test]
    fn escape_in_search_returns_focus_to_sources_without_backing_out() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        search_for(&mut screen, &db, "gpt");

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert_eq!(screen.focus, Focus::Sources);
        // The query itself is untouched, so re-focusing resumes the search.
        assert_eq!(screen.query, "gpt");
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
    fn humanize_age_handles_never_and_recent() {
        assert_eq!(humanize_age(None), "never updated");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(humanize_age(Some(now)), "updated 0s ago");
    }

    #[test]
    fn enter_on_source_row_opens_confirmation_popup_defaulting_to_cancel() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.sources_state.select(Some(0));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let popup = screen.popup.as_ref().unwrap();
        assert!(matches!(popup.target, PopupTarget::Source(_)));
        assert_eq!(popup.selected, 0); // Cancel
    }

    #[test]
    fn confirming_cancel_on_source_popup_does_not_trigger_an_update() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.sources_state.select(Some(0));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
    }

    #[test]
    fn confirming_update_now_on_source_popup_returns_update_source() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        screen.sources_state.select(Some(0));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Cancel -> Update now
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        // The source's id ("test"), not its display name ("Test") — see
        // `PopupTarget::Source`'s doc comment for why.
        assert_eq!(outcome, KeyOutcome::UpdateSource("test".to_string()));
        assert!(screen.popup.is_none());
    }

    #[test]
    fn escape_closes_popup_without_saving() {
        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        search_for(&mut screen, &db, "gptbot");

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
        // Unchanged: escape must not have written the in-progress selection.
        let bots = db.list_bots().unwrap();
        assert_eq!(bots[0].status, BotStatus::Default);
    }

    #[test]
    fn escape_with_no_popup_and_sources_focused_backs_out_to_dashboard() {
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
        search_for(&mut screen, &db, "gptbot");

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

    #[test]
    fn confirming_bot_popup_back_to_default_reports_use_system_settings() {
        let db = test_db_with_bot("gptbot", true);
        db.set_bot_status("gptbot", BotStatus::Allowed).unwrap();
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();
        search_for(&mut screen, &db, "gptbot");

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        // The popup opens on the bot's current status (Allowed); Up moves
        // back to "Use system settings".
        screen
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots[0].status, BotStatus::Default);
        assert_eq!(message.unwrap(), "gptbot set to use system settings");
    }

    #[test]
    fn bot_row_is_tagged_system_or_override_depending_on_its_status() {
        let default_bot = Bot {
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
        let system_line = bot_line(
            &default_bot,
            Policy::Blocked,
            Policy::Allowed,
            Policy::Blocked,
        );
        assert!(system_line
            .spans
            .iter()
            .any(|s| s.content.contains("(system)")));

        let mut overridden_bot = default_bot.clone();
        overridden_bot.status = BotStatus::Allowed;
        let override_line = bot_line(
            &overridden_bot,
            Policy::Blocked,
            Policy::Allowed,
            Policy::Blocked,
        );
        assert!(override_line
            .spans
            .iter()
            .any(|s| s.content.contains("(override)")));
    }

    /// Regression test for a real bug: with an empty query and at least one
    /// bot loaded, the header search line and the (then-empty) results area
    /// both rendered a "press /" hint at once — the header's own "Press /
    /// to search bots by name" made the results area's "Press / then type a
    /// bot name to search." entirely redundant.
    #[test]
    fn press_slash_hint_renders_only_once_with_an_empty_query() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let db = test_db_with_bot("gptbot", true);
        let mut screen = BotSettings::default();
        screen.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 12);
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
        assert_eq!(content.matches("Press /").count(), 1);
    }
}
