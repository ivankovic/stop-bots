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

//! The Site settings screen: the NGINX sites `scan-sites` has discovered.
//! Read-only for now — there's no per-site bot-override storage yet (see
//! TODO.md), so every site just follows the global Bot settings policy.

use crate::db::{Db, Site};
use crate::tui::{KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Rect,
    style::Stylize,
    text::Line,
    widgets::{Block, List, ListItem, ListState},
    Frame,
};

#[derive(Debug, Default)]
pub struct SiteSettings {
    sites: Vec<Site>,
    list_state: ListState,
}

impl SiteSettings {
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.sites = db.list_sites()?;
        if !self.sites.is_empty() && self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        if self.sites.is_empty() {
            let placeholder = ratatui::widgets::Paragraph::new(
                "No sites discovered yet. Run `stop-bots scan-sites` to find them.",
            )
            .block(Block::bordered().title("Sites").fg(theme.accent()));
            frame.render_widget(placeholder, area);
            return;
        }

        let items: Vec<ListItem> = self
            .sites
            .iter()
            .map(|site| {
                ListItem::new(Line::from(vec![
                    site.server_name.clone().bold(),
                    format!("  ({})", site.config_path).dim(),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::bordered()
                    .title("Sites (follow the global Bot settings policy)")
                    .fg(theme.accent()),
            )
            .highlight_style(ratatui::style::Style::new().reversed());
        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        _db: &Db,
        _message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        match key.code {
            KeyCode::Esc => Ok(KeyOutcome::Back),
            KeyCode::Up | KeyCode::Char('k') => {
                self.list_state.select_previous();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.list_state.select_next();
                Ok(KeyOutcome::Consumed)
            }
            _ => Ok(KeyOutcome::Ignored),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn refresh_loads_sites_and_selects_first() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = SiteSettings::default();
        screen.refresh(&db).unwrap();

        assert_eq!(screen.sites.len(), 1);
        assert_eq!(screen.list_state.selected(), Some(0));
    }

    #[test]
    fn escape_backs_out_to_dashboard() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = SiteSettings::default();
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Back);
    }

    #[test]
    fn render_with_no_sites_shows_a_hint_instead_of_an_empty_list() {
        let mut screen = SiteSettings::default();
        let backend = TestBackend::new(60, 10);
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
        assert!(content.contains("scan-sites"));
    }

    #[test]
    fn render_with_sites_shows_server_name_and_config_path() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = SiteSettings::default();
        screen.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 10);
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
        assert!(content.contains("example.com"));
    }
}
