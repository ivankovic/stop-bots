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

//! The Dashboard: the default screen on app start. A read-only overview of
//! global settings, how many sites are known, and whether bot-list sources
//! are up to date. No per-request traffic metrics yet (see TODO.md) — there
//! is no log analysis backend to source them from.

use crate::db::{Category, Db, Policy, Source};
use crate::tui::Theme;
use anyhow::Result;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::Line,
    widgets::{Block, Paragraph},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source is considered stale (needs updating) if it's never been fetched,
/// or wasn't fetched in the last week.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Default)]
pub struct Dashboard {
    site_count: usize,
    sources: Vec<Source>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.site_count = db.list_sites()?.len();
        self.sources = db.list_sources()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        Ok(())
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

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: Theme, message: &Option<String>) {
        let [settings_area, stats_area, message_area] = Layout::vertical([
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Min(1),
        ])
        .areas(area);

        let settings = Paragraph::new(vec![
            Line::from("System-wide settings"),
            policy_line("  Scanners", self.scanner_default),
            policy_line("  Search Bots", self.search_default),
            policy_line("  AI Bots", self.ai_default),
        ])
        .block(Block::bordered().title("Overview").fg(theme.accent()));
        frame.render_widget(settings, settings_area);

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
    }
}

fn policy_line(label: &str, policy: Policy) -> Line<'static> {
    let tag = match policy {
        Policy::Allowed => "[ ALLOWED ]".green(),
        Policy::Blocked => "[ BLOCKED ]".red(),
    };
    Line::from(vec![format!("{label} ").into(), tag])
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
}
