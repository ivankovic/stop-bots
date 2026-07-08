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

//! The app controller: owns all TUI state, runs the event loop, and routes
//! key presses to the active screen (falling back to global key handling).

use crate::botlist;
use crate::db::Db;
use crate::event::{AppEvent, Event, EventHandler};
use crate::tui::{self, KeyOutcome, Screen, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

pub struct App {
    pub running: bool,
    pub events: EventHandler,
    pub theme: Theme,
    pub screen: Screen,
    /// The screen to return to when the Help screen is closed.
    before_help: Screen,
    pub message: Option<String>,
    pub db: Db,
    pub dashboard: tui::dashboard::Dashboard,
    pub bot_settings: tui::bot_settings::BotSettings,
    pub site_settings: tui::site_settings::SiteSettings,
}

impl App {
    /// Constructs a new [`App`], loading initial state from `db`.
    pub fn new(db: Db) -> Result<Self> {
        let mut app = Self {
            running: true,
            events: EventHandler::new(),
            theme: Theme::detect(),
            screen: Screen::default(),
            before_help: Screen::default(),
            message: None,
            db,
            dashboard: tui::dashboard::Dashboard::default(),
            bot_settings: tui::bot_settings::BotSettings::default(),
            site_settings: tui::site_settings::SiteSettings::default(),
        };
        botlist::register_source(&app.db)?;
        app.refresh()?;
        Ok(app)
    }

    /// Reloads every screen's state from the database.
    fn refresh(&mut self) -> Result<()> {
        self.dashboard.refresh(&self.db)?;
        self.bot_settings.refresh(&self.db)?;
        self.site_settings.refresh(&self.db)?;
        Ok(())
    }

    /// Runs the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while self.running {
            terminal.draw(|frame| tui::render(&mut self, frame))?;
            match self.events.next().await? {
                Event::Tick => {}
                Event::Crossterm(crossterm::event::Event::Key(key_event))
                    if key_event.kind == KeyEventKind::Press =>
                {
                    self.handle_key_event(key_event)?;
                }
                Event::Crossterm(_) => {}
                Event::App(AppEvent::Quit) => self.running = false,
                Event::App(AppEvent::SourceUpdateFinished { name, result }) => {
                    self.finish_source_update(name, result)?;
                }
            }
        }
        Ok(())
    }

    /// Starts a background fetch+parse of the named bot-list source (there's
    /// only one today, `botlist::SOURCE_ID`, so it's the only fetcher this
    /// reaches for). Runs off the main thread because `Db`'s connection isn't
    /// `Sync` — the spawned task only fetches and parses; storing the result
    /// happens back on the main thread in `finish_source_update`.
    fn start_source_update(&mut self, name: String) {
        self.message = Some(format!("Updating {name}…"));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let json = botlist::fetch().await?;
                botlist::parse(&json)
            }
            .await
            .map_err(|err| err.to_string());
            let _ = sender.send(Event::App(AppEvent::SourceUpdateFinished { name, result }));
        });
    }

    /// Stores the fetched bots (on success) and reports the outcome, run
    /// back on the main thread once the background fetch in
    /// `start_source_update` completes.
    fn finish_source_update(
        &mut self,
        name: String,
        result: Result<Vec<crate::db::NewBot>, String>,
    ) -> Result<()> {
        match result {
            Ok(bots) => {
                let count = botlist::store(&self.db, &bots)?;
                self.message = Some(format!("Stored {count} bot(s) from {name}"));
                self.refresh()?;
            }
            Err(err) => {
                self.message = Some(format!("Failed to update {name}: {err}"));
            }
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.events.send(AppEvent::Quit);
            return Ok(());
        }

        if self.screen == Screen::Help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | '?')) {
                self.screen = self.before_help;
            }
            return Ok(());
        }

        let outcome = match self.screen {
            Screen::Dashboard => self
                .dashboard
                .handle_key(key, &self.db, &mut self.message)?,
            Screen::BotSettings => {
                self.bot_settings
                    .handle_key(key, &self.db, &mut self.message)?
            }
            Screen::SiteSettings => {
                self.site_settings
                    .handle_key(key, &self.db, &mut self.message)?
            }
            Screen::Help => unreachable!("handled above"),
        };
        match outcome {
            KeyOutcome::Consumed => return Ok(()),
            KeyOutcome::Mutated => {
                // A screen wrote to the database; reload every screen so
                // none of them (e.g. the Dashboard's summary) goes stale.
                self.refresh()?;
                return Ok(());
            }
            KeyOutcome::Back => {
                self.screen = Screen::Dashboard;
                return Ok(());
            }
            KeyOutcome::UpdateSource(name) => {
                self.start_source_update(name);
                return Ok(());
            }
            KeyOutcome::Ignored => {}
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') if self.screen == Screen::Dashboard => {
                self.events.send(AppEvent::Quit);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Dashboard,
            KeyCode::Char('c') => self.theme = self.theme.toggle(),
            KeyCode::Char('?') => {
                self.before_help = self.screen;
                self.screen = Screen::Help;
            }
            KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('b') => self.screen = Screen::BotSettings,
            KeyCode::Char('s') => self.screen = Screen::SiteSettings,
            KeyCode::Tab => self.screen = self.screen.next(),
            KeyCode::BackTab => self.screen = self.screen.previous(),
            _ => {}
        }
        Ok(())
    }
}
