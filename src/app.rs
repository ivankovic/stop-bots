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
use crate::ipranges;
use crate::tui::{self, KeyOutcome, Screen, Theme};
use anyhow::{Context, Result};
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
    /// Constructs a new [`App`], loading initial state from `db`. `root` is
    /// the NGINX config root Site settings scans when the user triggers a
    /// rescan from the TUI.
    pub fn new(db: Db, root: std::path::PathBuf) -> Result<Self> {
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
            site_settings: tui::site_settings::SiteSettings::new(root),
        };
        botlist::register_all_sources(&app.db)?;
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
                Event::App(AppEvent::SourceUpdateFinished { source_id, result }) => {
                    self.finish_source_update(source_id, result)?;
                }
                Event::App(AppEvent::CountryBlockFinished {
                    country_code,
                    result,
                }) => {
                    self.finish_country_block(country_code, result)?;
                }
            }
        }
        Ok(())
    }

    /// Starts a background fetch+parse of the bot-list source identified by
    /// `source_id` (resolved to a `botlist::SourceKind`, which knows how to
    /// fetch and parse its own format). Runs off the main thread because
    /// `Db`'s connection isn't `Sync` — the spawned task only fetches and
    /// parses; storing the result happens back on the main thread in
    /// `finish_source_update`.
    fn start_source_update(&mut self, source_id: String) {
        self.message = Some(format!("Updating {}…", source_display_name(&source_id)));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .with_context(|| format!("unknown bot-list source: {source_id}"))?;
                let raw = kind.fetch().await?;
                kind.parse(&raw)
            }
            .await
            .map_err(|err| err.to_string());
            let _ = sender.send(Event::App(AppEvent::SourceUpdateFinished {
                source_id,
                result,
            }));
        });
    }

    /// Stores the fetched bots (on success) and reports the outcome, run
    /// back on the main thread once the background fetch in
    /// `start_source_update` completes.
    fn finish_source_update(
        &mut self,
        source_id: String,
        result: Result<Vec<crate::db::NewBot>, String>,
    ) -> Result<()> {
        let name = source_display_name(&source_id);
        match result {
            Ok(bots) => {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .expect("source_id always came from a known SourceKind::id()");
                let count = botlist::store(&self.db, kind, &bots)?;
                self.message = Some(format!("Stored {count} bot(s) from {name}"));
                self.refresh()?;
            }
            Err(err) => {
                self.message = Some(format!("Failed to update {name}: {err}"));
            }
        }
        Ok(())
    }

    /// Starts a background fetch of `country_code`'s IP ranges, spawned from
    /// the Dashboard's "add a country to block" popup for a country that
    /// isn't fetched yet. Only fetches and parses on the spawned task, same
    /// reason as `start_source_update`: storing (and blocking the country)
    /// happens back on the main thread in `finish_country_block`.
    fn start_country_block(&mut self, country_code: String) {
        self.message = Some(format!(
            "Fetching IP ranges for {}…",
            country_code.to_uppercase()
        ));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let raw = ipranges::fetch_country(&country_code).await?;
                Ok(ipranges::parse_zone_file(&raw))
            }
            .await
            .map_err(|err: anyhow::Error| err.to_string());
            let _ = sender.send(Event::App(AppEvent::CountryBlockFinished {
                country_code,
                result,
            }));
        });
    }

    /// Stores the fetched CIDRs (on success) and blocks the country — this
    /// completes the intent behind the Dashboard action that started this
    /// fetch, which was always "block this country", not just "fetch its
    /// ranges". Run back on the main thread once `start_country_block`'s
    /// background fetch completes.
    fn finish_country_block(
        &mut self,
        country_code: String,
        result: Result<Vec<String>, String>,
    ) -> Result<()> {
        let label = country_code.to_uppercase();
        match result {
            Ok(cidrs) => {
                let count = self.db.replace_country_ranges(&country_code, &cidrs)?;
                self.db.set_country_blocked(&country_code, true)?;
                self.message = Some(format!("Blocked {label} ({count} range(s))"));
                self.refresh()?;
            }
            Err(err) => {
                self.message = Some(format!("Failed to fetch IP ranges for {label}: {err}"));
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
            KeyOutcome::BlockCountry(country_code) => {
                self.start_country_block(country_code);
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

/// The display name for a bot-list source id, falling back to the id
/// itself if it's somehow not one of `botlist::SourceKind::ALL` — status
/// messages should never panic over a display string.
fn source_display_name(source_id: &str) -> String {
    botlist::SourceKind::from_id(source_id)
        .map(|kind| kind.name().to_string())
        .unwrap_or_else(|| source_id.to_string())
}
