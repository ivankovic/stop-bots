//! Application state and logic for the TUI.
//!
//! This module contains the main App struct that manages the application state
//! and handles user input and rendering.

use crate::db::Database;
use crate::source_fetch::{KnownSources, SourceFetcher};
use crate::tui::{
    screens::{BotDetailScreen, BotListScreen, DashboardScreen, HelpScreen, QuitConfirmScreen, Screen, ScreenState, SourcesScreen},
    key_event_to_tui_event, Theme, TuiEvent,
};
use anyhow::Result;
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};
use crossterm::{
    event::{self, Event, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{prelude::*, Terminal};

// ============================================================================
// Application State
// ============================================================================

/// Main application state.
pub struct App {
    /// Screen state (navigation, theme, etc.)
    pub screen_state: ScreenState,
    /// Database connection
    pub db: Database,
    /// Dashboard screen
    pub dashboard: DashboardScreen,
    /// Bot list screen
    pub bot_list: BotListScreen,
    /// Sources screen
    pub sources: SourcesScreen,
    /// Bot detail screen
    pub bot_detail: Option<BotDetailScreen>,
    /// Help screen
    pub help: HelpScreen,
    /// Quit confirmation screen
    pub quit_confirm: QuitConfirmScreen,
    /// Whether the application is running
    pub running: bool,
    /// Last tick time (for animations, etc.)
    pub last_tick: Instant,
    /// Tick rate
    pub tick_rate: Duration,
    /// Source fetcher for async operations
    pub source_fetcher: Option<SourceFetcher>,
    /// Messages to display on dashboard
    pub messages: Vec<String>,
}

impl App {
    /// Creates a new application.
    pub fn new(db: Database) -> Result<Self> {
        let screen_state = ScreenState::new();

        // Load initial data from database
        let bots = db.get_all_bots().ok().unwrap_or_default();
        let sources = db.get_all_data_sources().ok().unwrap_or_default();

        // Check which sources need updating
        let needs_update: Vec<bool> = sources
            .iter()
            .map(|s| db.data_source_needs_update(s).ok().unwrap_or(false))
            .collect();

        // Build statistics
        let mut bots_by_status = HashMap::new();
        let mut bots_by_category = HashMap::new();

        for bot in &bots {
            *bots_by_status.entry(bot.status).or_insert(0) += 1;
            for category in &bot.categories {
                *bots_by_category.entry(*category).or_insert(0) += 1;
            }
        }

        // Count sources needing update
        let sources_needing_update = needs_update.iter().filter(|&&n| n).count();

        Ok(Self {
            screen_state,
            db,
            dashboard: DashboardScreen {
                total_bots: bots.len(),
                bots_by_status,
                bots_by_category,
                source_count: sources.len(),
                sources_needing_update,
                messages: Vec::new(),
            },
            bot_list: BotListScreen::new(bots),
            sources: SourcesScreen::new(sources, needs_update),
            bot_detail: None,
            help: HelpScreen::new(),
            quit_confirm: QuitConfirmScreen::new(),
            running: true,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250),
            source_fetcher: None,
            messages: Vec::new(),
        })
    }

    /// Initializes the application.
    pub async fn init(&mut self) -> Result<()> {
        // Initialize source fetcher
        self.source_fetcher = Some(SourceFetcher::new()?);

        // Add welcome message
        self.add_message("Welcome to Stop Bots!".to_string());
        self.add_message("Press ? for help".to_string());

        Ok(())
    }

    /// Adds a message to the message queue.
    pub fn add_message(&mut self, message: String) {
        self.messages.push(message);
        // Keep only the last 10 messages
        if self.messages.len() > 10 {
            self.messages.remove(0);
        }
        // Also update dashboard messages
        self.dashboard.messages = self.messages.clone();
    }

    /// Handles a tick event.
    pub fn on_tick(&mut self) -> Result<()> {
        // Update dashboard messages
        self.dashboard.messages = self.messages.clone();
        Ok(())
    }

    /// Handles a key event.
    pub fn on_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        let event = key_event_to_tui_event(key);

        if let Some(event) = event {
            self.handle_event(event)?;
        }

        Ok(())
    }

    /// Handles a TUI event.
    pub fn handle_event(&mut self, event: TuiEvent) -> Result<()> {
        match event {
            TuiEvent::Quit => {
                self.screen_state.navigate_to(Screen::QuitConfirm);
            }
            TuiEvent::ToggleTheme => {
                self.screen_state.theme = self.screen_state.theme.toggle();
                self.screen_state.update_theme();
                self.add_message(format!(
                    "Theme switched to {}",
                    match self.screen_state.theme {
                        Theme::Light => "Light",
                        Theme::Dark => "Dark",
                    }
                ));
            }
            TuiEvent::Refresh => {
                self.refresh_current_screen()?;
            }
            TuiEvent::Back => {
                self.screen_state.go_back();
            }
            TuiEvent::Confirm => {
                // On quit confirm screen, Y confirms quit
                if self.screen_state.current_screen == Screen::QuitConfirm {
                    self.running = false;
                }
            }
            TuiEvent::Cancel => {
                // On quit confirm screen, N cancels quit
                if self.screen_state.current_screen == Screen::QuitConfirm {
                    self.screen_state.go_back();
                }
            }
            TuiEvent::Select => {
                self.on_select()?;
            }
            TuiEvent::Up | TuiEvent::Down | TuiEvent::Left | TuiEvent::Right => {
                self.screen_state.handle_navigation(event)?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Handles the select action based on current screen.
    pub fn on_select(&mut self) -> Result<()> {
        match self.screen_state.current_screen {
            Screen::Dashboard => {
                // On dashboard, number keys switch screens
                // This would be handled by key events directly
            }
            Screen::BotList => {
                if let Some(bot) = self
                    .bot_list
                    .get_selected_bot(self.screen_state.selected_index)
                {
                    self.bot_detail = Some(BotDetailScreen::new(bot.clone()));
                    self.screen_state
                        .navigate_to(Screen::BotDetail(self.screen_state.selected_index));
                }
            }
            Screen::Sources => {
                if let Some((source, needs_update)) = self
                    .sources
                    .get_selected_source(self.screen_state.selected_index)
                {
                    // For now, just show a message
                    self.add_message(format!(
                        "Selected: {} (needs update: {})",
                        source.name, needs_update
                    ));
                }
            }
            Screen::BotDetail(_) => {
                // On bot detail, select toggles status
                if let Some(bot_detail) = &mut self.bot_detail {
                    // Toggle the bot's status
                    let new_status = bot_detail.bot.status.toggle();
                    // Update in database
                    let mut updated_bot = bot_detail.bot.clone();
                    updated_bot.status = new_status;
                    self.db.upsert_bot(&updated_bot)?;
                    // Update the bot detail
                    bot_detail.bot.status = new_status;
                    // Add message after releasing the borrow
                    self.add_message(format!(
                        "Toggled {} to {}",
                        updated_bot.name, new_status
                    ));
                }
            }
            Screen::Help => {
                self.screen_state.go_back();
            }
            Screen::QuitConfirm => {
                self.running = false;
            }
            _ => {}
        }

        Ok(())
    }

    /// Refreshes the current screen.
    pub fn refresh_current_screen(&mut self) -> Result<()> {
        match self.screen_state.current_screen {
            Screen::Dashboard => {
                self.refresh_dashboard()?;
            }
            Screen::BotList => {
                self.refresh_bot_list()?;
            }
            Screen::Sources => {
                self.refresh_sources()?;
            }
            _ => {}
        }

        self.add_message("Refreshed".to_string());
        Ok(())
    }

    /// Refreshes the dashboard screen.
    pub fn refresh_dashboard(&mut self) -> Result<()> {
        let bots = self.db.get_all_bots()?;
        let sources = self.db.get_all_data_sources()?;

        let mut bots_by_status = HashMap::new();
        let mut bots_by_category = HashMap::new();

        for bot in &bots {
            *bots_by_status.entry(bot.status).or_insert(0) += 1;
            for category in &bot.categories {
                *bots_by_category.entry(*category).or_insert(0) += 1;
            }
        }

        let needs_update: Vec<bool> = sources
            .iter()
            .map(|s| self.db.data_source_needs_update(s).unwrap_or(false))
            .collect();

        let sources_needing_update = needs_update.iter().filter(|&&n| n).count();

        self.dashboard = DashboardScreen {
            total_bots: bots.len(),
            bots_by_status,
            bots_by_category,
            source_count: sources.len(),
            sources_needing_update,
            messages: self.messages.clone(),
        };

        Ok(())
    }

    /// Refreshes the bot list screen.
    pub fn refresh_bot_list(&mut self) -> Result<()> {
        let bots = self.db.get_all_bots()?;
        self.bot_list = BotListScreen::new(bots);
        Ok(())
    }

    /// Refreshes the sources screen.
    pub fn refresh_sources(&mut self) -> Result<()> {
        let sources = self.db.get_all_data_sources()?;
        let needs_update: Vec<bool> = sources
            .iter()
            .map(|s| self.db.data_source_needs_update(s).unwrap_or(false))
            .collect();
        self.sources = SourcesScreen::new(sources, needs_update);
        Ok(())
    }

    /// Refreshes all data sources from the network.
    pub async fn refresh_all_sources(&mut self) -> Result<()> {
        let Some(fetcher) = &self.source_fetcher else {
            return Ok(());
        };
        let all_sources = KnownSources::all();
        let mut messages = Vec::new();

        for source in all_sources {
            let result = fetcher.fetch_from_source(&source.id).await;
            match result {
                Ok(bots) => {
                    let bot_ids = self.db.upsert_bots_from_source(&source.id, bots)?;
                    messages.push(format!("Refreshed {}: {} bots", source.name, bot_ids.len()));
                }
                Err(e) => {
                    messages.push(format!("Error refreshing {}: {}", source.name, e));
                }
            }
        }

        // Refresh screens
        self.refresh_dashboard()?;
        self.refresh_bot_list()?;
        self.refresh_sources()?;

        for msg in messages {
            self.add_message(msg);
        }
        self.add_message("All sources refreshed".to_string());

        Ok(())
    }

    /// Runs the application.
    pub async fn run(&mut self) -> Result<()> {
        // Initialize
        self.init().await?;

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main loop
        while self.running {
            // Draw the UI
            terminal.draw(|f| self.draw(f))?;

            // Handle events
            if event::poll(self.tick_rate.saturating_sub(self.last_tick.elapsed()))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.on_key(key)?;
                    }
                }
            }

            // Handle tick
            if self.last_tick.elapsed() >= self.tick_rate {
                self.on_tick()?;
                self.last_tick = Instant::now();
            }
        }

        // Cleanup terminal
        disable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    /// Draws the current screen.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.size();

        match self.screen_state.current_screen {
            Screen::Dashboard => {
                self.dashboard.render(frame, &self.screen_state, area);
            }
            Screen::BotList => {
                self.bot_list.render(frame, &self.screen_state, area);
            }
            Screen::BotDetail(_) => {
                if let Some(ref bot_detail) = self.bot_detail {
                    bot_detail.render(frame, &self.screen_state, area);
                }
            }
            Screen::SourceDetail(_) => {
                // Source detail screen not yet implemented
            }
            Screen::Sources => {
                self.sources.render(frame, &self.screen_state, area);
            }
            Screen::Settings => {
                // Settings screen not yet implemented
            }
            Screen::Help => {
                self.help.render(frame, &self.screen_state, area);
            }
            Screen::QuitConfirm => {
                self.quit_confirm.render(frame, &self.screen_state, area);
            }
        }
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Runs the TUI application.
pub async fn run_tui() -> Result<()> {
    // Initialize database
    let mut db = Database::open_default()?;
    db.initialize()?;
    db.ensure_categories()?;
    db.ensure_signals()?;
    db.initialize_data_sources()?;

    // Create and run the application
    let mut app = App::new(db)?;
    app.run().await?;

    Ok(())
}
