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

//! The command palette: every action in the app by name, opened with `:`
//! from any screen and fuzzy-filtered as you type.
//!
//! It is the discoverability layer the Help screen tries to be, and the
//! escape hatch for actions that would otherwise each need a letter:
//! "put this console behind NGINX" is one row here rather than a key
//! nobody remembers. The palette owns its state, matching and drawing;
//! what the commands *are* and what running one does is `App`'s, because
//! every one of them touches a screen or the database — see
//! `App::commands` and `App::run_command`.

use crate::tui::{Screen, Theme};
use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::Stylize,
    text::Line,
    widgets::{Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

/// What running a command does. Most are "go to a screen and press a
/// key": that reuses every popup, guard and background job the key
/// already has, so the palette can never do something a key cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Switch to a screen.
    Screen(Screen),
    /// Switch to a screen, then press this key on it.
    Key(Screen, KeyCode),
    /// Toggle the theme.
    Theme,
    /// Quit.
    Quit,
    /// Switch a detector on or off.
    Detector(crate::protection::Detector, bool),
}

/// One row of the palette.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// What the row says. Matched against the query.
    pub label: String,
    /// The key that does the same thing, or empty — shown dimmed on the
    /// right, which is how the palette teaches the key map.
    pub hint: &'static str,
    pub action: Action,
}

/// The open palette: the query so far and which match is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    pub query: String,
    pub selected: usize,
    /// Snapshotted when the palette opens, because the detector rows say
    /// "Turn on" or "Turn off" depending on the state at that moment.
    pub commands: Vec<Command>,
}

/// The most rows the list shows at once; the rest scroll.
const VISIBLE_ROWS: u16 = 10;

impl Palette {
    pub fn new(commands: Vec<Command>) -> Self {
        Self {
            query: String::new(),
            selected: 0,
            commands,
        }
    }

    /// The commands matching the query, best first.
    pub fn matches(&self) -> Vec<&Command> {
        let mut scored: Vec<(u32, usize, &Command)> = self
            .commands
            .iter()
            .enumerate()
            .filter_map(|(i, c)| score(&c.label, &self.query).map(|s| (s, i, c)))
            .collect();
        // Best score first; ties keep the order the commands were listed
        // in, which puts navigation before host actions.
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, c)| c).collect()
    }

    /// The command Enter would run.
    pub fn selected_action(&self) -> Option<Action> {
        self.matches().get(self.selected).map(|c| c.action)
    }

    /// Edits the query, or moves the selection. Returns `true` when the
    /// key was one of the palette's own.
    pub fn handle_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                let last = self.matches().len().saturating_sub(1);
                self.selected = (self.selected + 1).min(last);
            }
            KeyCode::Backspace => {
                self.query.pop();
                self.selected = 0;
            }
            KeyCode::Char(c) => {
                self.query.push(c);
                self.selected = 0;
            }
            _ => return false,
        }
        true
    }

    /// The footer's key hints while the palette is open.
    pub fn hints(&self) -> crate::tui::Hints {
        (
            "Commands",
            vec![
                ("type", "filter"),
                ("\u{2191}\u{2193}", "move"),
                ("Enter", "run"),
                ("Esc", "close"),
            ],
        )
    }

    /// Draws the palette over `area`: a query line and the matches, in a
    /// popup near the top of the screen so the list reads downward like
    /// a menu rather than sitting on top of whatever was being read.
    pub fn render(&self, frame: &mut Frame, area: Rect, theme: Theme) {
        let matches = self.matches();
        let width = 64.min(area.width.saturating_sub(4)).max(20);
        let rows = (matches.len() as u16).clamp(1, VISIBLE_ROWS);
        let height = (rows + 3).min(area.height);
        let popup = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height.saturating_sub(height)) / 6,
            width,
            height,
        );
        frame.render_widget(Clear, popup);
        let block = crate::tui::popup("Commands", theme);
        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        let [query_area, list_area] = ratatui::layout::Layout::vertical([
            ratatui::layout::Constraint::Length(1),
            ratatui::layout::Constraint::Min(0),
        ])
        .areas(inner);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                ":".fg(theme.accent()).bold(),
                format!(" {}", self.query).into(),
                "\u{2588}".fg(theme.accent()),
            ])),
            query_area,
        );

        if matches.is_empty() {
            frame.render_widget(
                Paragraph::new(Line::from(" no command matches").fg(theme.dim())),
                list_area,
            );
            return;
        }
        // The hint sits at the right edge; the label gets the rest.
        let label_width = usize::from(list_area.width.saturating_sub(8));
        let items: Vec<ListItem> = matches
            .iter()
            .map(|c| {
                let label: String = c.label.chars().take(label_width).collect();
                ListItem::new(Line::from(vec![
                    format!("{label:<label_width$}").into(),
                    format!(" {:>5}", c.hint).fg(theme.dim()),
                ]))
            })
            .collect();
        let mut state = ListState::default().with_selected(Some(self.selected));
        let list = crate::tui::select_in(List::new(items), true, theme);
        frame.render_stateful_widget(list, list_area, &mut state);
    }
}

/// Fuzzy match: every character of `query` in order somewhere in
/// `label`, case-insensitively. The score rewards a run of consecutive
/// hits most, then a hit at the start of a word, and a scattered hit not
/// at all — so "quit" beats "q u i t" and "ae" ranks "Apply everything"
/// above a label where the `e` is buried mid-word. `None` when a
/// character is missing.
pub fn score(label: &str, query: &str) -> Option<u32> {
    let label: Vec<char> = label.to_lowercase().chars().collect();
    let mut score = 0;
    let mut at = 0;
    let mut previous_hit: Option<usize> = None;
    for q in query.to_lowercase().chars().filter(|c| !c.is_whitespace()) {
        let i = (at..label.len()).find(|&i| label[i] == q)?;
        let word_start = i == 0 || !label[i - 1].is_alphanumeric();
        if previous_hit == Some(i.wrapping_sub(1)) {
            score += 3;
        } else if word_start {
            score += 2;
        }
        previous_hit = Some(i);
        at = i + 1;
    }
    Some(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn palette() -> Palette {
        Palette::new(vec![
            Command {
                label: "Go to Dashboard".into(),
                hint: "1",
                action: Action::Screen(Screen::Dashboard),
            },
            Command {
                label: "Apply everything: NGINX, then the firewall".into(),
                hint: "a",
                action: Action::Key(Screen::Dashboard, KeyCode::Char('a')),
            },
            Command {
                label: "Apply blocking to every site".into(),
                hint: "A",
                action: Action::Key(Screen::SiteSettings, KeyCode::Char('A')),
            },
            Command {
                label: "Quit".into(),
                hint: "q",
                action: Action::Quit,
            },
        ])
    }

    #[test]
    fn every_query_character_must_appear_in_order() {
        assert!(score("Apply everything", "apev").is_some());
        assert_eq!(score("Apply everything", "evap"), None);
        assert_eq!(score("Apply everything", "z"), None);
        assert_eq!(score("anything", ""), Some(0));
    }

    #[test]
    fn word_starts_and_runs_outscore_scattered_hits() {
        // "ae" hits two word starts in "Apply everything".
        let starts = score("Apply everything", "ae").unwrap();
        // ...and only one, then a mid-word 'e', in "Apply the rest".
        let scattered = score("Apply the rest", "ae").unwrap();
        assert!(starts > scattered, "{starts} vs {scattered}");
        assert!(score("quit", "qui").unwrap() > score("q u i", "qui").unwrap());
    }

    #[test]
    fn an_empty_query_lists_everything_in_the_given_order() {
        let p = palette();
        let labels: Vec<&str> = p.matches().iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Go to Dashboard",
                "Apply everything: NGINX, then the firewall",
                "Apply blocking to every site",
                "Quit"
            ]
        );
    }

    #[test]
    fn typing_filters_and_resets_the_selection() {
        let mut p = palette();
        assert!(p.handle_key(KeyCode::Down));
        assert_eq!(p.selected, 1);
        for c in "apply".chars() {
            p.handle_key(KeyCode::Char(c));
        }
        assert_eq!(p.selected, 0);
        let labels: Vec<&str> = p.matches().iter().map(|c| c.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "Apply everything: NGINX, then the firewall",
                "Apply blocking to every site"
            ]
        );
        assert_eq!(
            p.selected_action(),
            Some(Action::Key(Screen::Dashboard, KeyCode::Char('a')))
        );
    }

    #[test]
    fn the_selection_stays_inside_the_matches() {
        let mut p = palette();
        for c in "qu".chars() {
            p.handle_key(KeyCode::Char(c));
        }
        p.handle_key(KeyCode::Down);
        p.handle_key(KeyCode::Down);
        assert_eq!(p.selected, 0);
        assert_eq!(p.selected_action(), Some(Action::Quit));
        p.handle_key(KeyCode::Backspace);
        p.handle_key(KeyCode::Backspace);
        p.handle_key(KeyCode::Up);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn keys_the_palette_does_not_own_are_reported_as_such() {
        let mut p = palette();
        assert!(!p.handle_key(KeyCode::Enter));
        assert!(!p.handle_key(KeyCode::Esc));
        assert!(!p.handle_key(KeyCode::Tab));
    }

    #[test]
    fn render_shows_the_query_and_the_matches() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut p = palette();
        for c in "qu".chars() {
            p.handle_key(KeyCode::Char(c));
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| p.render(frame, frame.area(), Theme::Dark))
            .unwrap();
        let content: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(content.contains("Commands"), "content was:\n{content}");
        assert!(content.contains(": qu"), "content was:\n{content}");
        assert!(content.contains("Quit"), "content was:\n{content}");
        assert!(!content.contains("Dashboard"), "content was:\n{content}");
    }
}
