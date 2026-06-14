//! Application state and logic for the TUI.
//!
//! This module contains the main App struct that manages the application state
//! and handles user input and rendering, following the ratatui event-driven-async template.

use anyhow::Result;
use crossterm::event::{Event as CrosstermEvent, KeyEvent, KeyEventKind};
use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};

use crate::db::{BotStatus, DataSource, Database};
use crate::firewall::FirewallAddress;
use crate::nginx::discover_nginx_sites;
use crate::source_fetch::SourceFetcher;
use crate::tui::{
    event::{key_event_to_app_event, AppEvent, Event, EventHandler},
    screens::{
        BotDetailScreen, BotListScreen, DashboardScreen, FirewallScreen, HelpScreen,
        QuitConfirmScreen, Screen, ScreenState, SettingsScreen, SourcesScreen,
    },
    Theme,
};
use ratatui::{
    backend::CrosstermBackend,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

// ============================================================================
// Application State
// ============================================================================

/// Main application state.
pub struct App {
    /// Screen state (navigation, theme, etc.)
    pub screen_state: ScreenState,
    /// Database connection
    pub db: Database,
    /// Settings screen (main screen)
    pub settings: SettingsScreen,
    /// Dashboard screen
    pub dashboard: DashboardScreen,
    /// Bot list screen
    pub bot_list: BotListScreen,
    /// Sources screen
    pub sources: SourcesScreen,
    /// Firewall screen
    pub firewall: FirewallScreen,
    /// Bot detail screen
    pub bot_detail: Option<BotDetailScreen>,
    /// Help screen
    pub help: HelpScreen,
    /// Quit confirmation screen
    pub quit_confirm: QuitConfirmScreen,
    /// Whether the application is running
    pub running: bool,
    /// Event handler
    pub events: EventHandler,
    /// Source fetcher for network operations
    pub source_fetcher: SourceFetcher,
    /// Messages to display on dashboard
    pub messages: Vec<String>,
}

impl App {
    /// Creates a new application.
    pub fn new(db: Database) -> Result<Self> {
        let screen_state = ScreenState::new();
        let events = EventHandler::new();
        let source_fetcher = SourceFetcher::new()?;

        // Load initial data from database
        let bots = db.get_all_bots().ok().unwrap_or_default();
        let sources = db.get_all_data_sources().ok().unwrap_or_default();

        // Check which sources need updating
        let needs_update: Vec<bool> = sources
            .iter()
            .map(|s| db.data_source_needs_update(s).ok().unwrap_or(false))
            .collect();

        // Build statistics
        let mut bots_by_status = std::collections::HashMap::new();
        let mut bots_by_category = std::collections::HashMap::new();

        for bot in &bots {
            *bots_by_status.entry(bot.status).or_insert(0) += 1;
            for category in &bot.categories {
                *bots_by_category.entry(*category).or_insert(0) += 1;
            }
        }

        // Create sources with their update status for dashboard
        let sources_with_status: Vec<(DataSource, bool)> = sources
            .clone()
            .into_iter()
            .zip(needs_update.clone().into_iter())
            .collect();

        Ok(Self {
            screen_state,
            db,
            settings: SettingsScreen::new(),
            dashboard: DashboardScreen {
                total_bots: bots.len(),
                bots_by_status,
                bots_by_category,
                sources: sources_with_status,
                messages: Vec::new(),
            },
            bot_list: BotListScreen::new(bots),
            sources: SourcesScreen::new(sources, needs_update),
            firewall: FirewallScreen::new(),
            bot_detail: None,
            help: HelpScreen::new(),
            quit_confirm: QuitConfirmScreen::new(),
            running: true,
            events,
            source_fetcher,
            messages: Vec::new(),
        })
    }

    /// Run the application's main loop.
    pub async fn run(
        mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> anyhow::Result<()> {
        // Start initial refresh as a background task (non-blocking)
        // This allows the TUI to render immediately while data loads in the background
        let db_clone = self.db.clone();
        let event_sender = self.events.sender.clone();

        tokio::spawn(async move {
            // First, discover and store nginx sites
            let mut db_mut = db_clone;
            let site_count = match Self::discover_and_store_nginx_sites_in_db(&mut db_mut) {
                Ok(count) => count,
                Err(e) => {
                    eprintln!("Background nginx site discovery failed: {}", e);
                    0
                }
            };

            if site_count > 0 {
                let _ =
                    event_sender.send(Event::App(AppEvent::SitesDiscovered { count: site_count }));
            }

            // Then refresh sources
            if let Err(e) = Self::refresh_all_sources_background(db_mut, event_sender).await {
                eprintln!("Background refresh failed: {}", e);
            }
        });

        while self.running {
            terminal.draw(|frame| self.draw(frame))?;

            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(event) => match event {
                    CrosstermEvent::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                        self.handle_key_events(key_event)?;
                    }
                    CrosstermEvent::Resize(_width, _height) => {
                        // Handle resize if needed
                    }
                    _ => {}
                },
                Event::App(app_event) => self.handle_app_event(app_event).await?,
            }
        }

        Ok(())
    }

    /// Background task to refresh all sources (runs in a spawned task).
    async fn refresh_all_sources_background(
        db: Database,
        event_sender: mpsc::UnboundedSender<Event>,
    ) -> Result<()> {
        let all_sources = crate::source_fetch::KnownSources::all();
        let mut messages = Vec::new();
        let mut updated_sources = Vec::new();

        // Use a semaphore to limit concurrent fetches
        let semaphore = Arc::new(Semaphore::new(5)); // Max 5 concurrent fetches

        let mut fetch_tasks = Vec::new();

        for source in all_sources {
            let permit = semaphore.clone().acquire_owned().await?;
            let db_clone = db.clone();
            let source_id = source.id.clone();
            let source_name = source.name.clone();

            let task = tokio::spawn(async move {
                let result = Self::fetch_and_store_source(db_clone, source_id, source_name).await;
                drop(permit); // Release the permit when done
                result
            });

            fetch_tasks.push(task);
        }

        // Wait for all fetch tasks to complete
        for task in fetch_tasks {
            match task.await {
                Ok(Ok((_bot_ids, updated_source, msg))) => {
                    if let Some(src) = updated_source {
                        updated_sources.push(src);
                    }
                    messages.push(msg);
                }
                Ok(Err(e)) => {
                    messages.push(format!("Error: {}", e));
                }
                Err(e) => {
                    messages.push(format!("Task failed: {}", e));
                }
            }
        }

        // Send the refresh complete event
        let _ = event_sender.send(Event::App(AppEvent::SourcesRefreshed {
            sources: updated_sources,
            messages,
        }));

        Ok(())
    }

    /// Fetches from a single source and stores in database.
    async fn fetch_and_store_source(
        db: Database,
        source_id: String,
        source_name: String,
    ) -> Result<(Vec<i64>, Option<DataSource>, String)> {
        // Create a new SourceFetcher for this task
        let source_fetcher = SourceFetcher::new()
            .map_err(|e| anyhow::anyhow!("Failed to create SourceFetcher: {}", e))?;

        match source_fetcher.fetch_from_source(&source_id).await {
            Ok(bots) => {
                // Store bots in database using spawn_blocking
                let mut db_for_store = db.clone();
                let source_id_for_store = source_id.clone();
                let bots_for_store = bots.clone();
                let bot_ids = tokio::task::spawn_blocking(move || {
                    db_for_store.upsert_bots_from_source(&source_id_for_store, bots_for_store)
                })
                .await??;

                // Get the updated source from DB
                let db_for_get = db.clone();
                let source_id_for_get = source_id.clone();
                let updated_source = tokio::task::spawn_blocking(move || {
                    db_for_get.get_data_source(&source_id_for_get)
                })
                .await??;

                Ok((
                    bot_ids.clone(),
                    updated_source,
                    format!("Refreshed {}: {} bots", source_name, bot_ids.len()),
                ))
            }
            Err(e) => Ok((
                Vec::new(),
                None,
                format!("Error refreshing {}: {}", source_name, e),
            )),
        }
    }

    /// Draws the current screen.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.size();

        // Split area to leave room for status bar at the bottom
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Min(0),    // Main content
                Constraint::Length(1), // Status bar
            ])
            .split(area);

        // Render the current screen in the main area
        match self.screen_state.current_screen {
            Screen::Dashboard => {
                self.dashboard.render(frame, &self.screen_state, rows[0]);
            }
            Screen::Settings => {
                self.settings.render(frame, &self.screen_state, rows[0]);
            }
            Screen::BotList => {
                self.bot_list.render(frame, &self.screen_state, rows[0]);
            }
            Screen::Firewall => {
                self.firewall.render(frame, &self.screen_state, rows[0]);
            }
            Screen::Sources => {
                self.sources.render(frame, &self.screen_state, rows[0]);
            }
            Screen::Help => {
                self.help.render(frame, &self.screen_state, rows[0]);
            }
            Screen::QuitConfirm => {
                self.quit_confirm.render(frame, &self.screen_state, rows[0]);
            }
            Screen::BotDetail(_) => {
                if let Some(ref bot_detail) = self.bot_detail {
                    bot_detail.render(frame, &self.screen_state, rows[0]);
                }
            }
            Screen::SourceDetail(_) => {
                // Source detail screen not yet implemented
            }
        }

        // Render status bar
        self.render_status_bar(frame, rows[1]);
    }

    /// Renders the status bar at the bottom of the screen.
    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let colors = self.screen_state.colors;

        // Get current screen name
        let screen_name = match self.screen_state.current_screen {
            Screen::Dashboard => "Dashboard",
            Screen::Settings => "Settings",
            Screen::BotList => "Bot List",
            Screen::Firewall => "Firewall",
            Screen::Sources => "Data Sources",
            Screen::Help => "Help",
            Screen::QuitConfirm => "Quit Confirmation",
            Screen::BotDetail(_) => "Bot Detail",
            Screen::SourceDetail(_) => "Source Details",
        };

        // Build help text
        let help_text = match self.screen_state.current_screen {
            Screen::Dashboard => {
                "d: Dashboard | s: Settings | l: Bot List | f: Firewall | S: Scan NGINX | ?: Help | q: Quit"
            }
            Screen::Settings => "↑/↓: Navigate | Enter/Space: Select | b: Back | ?: Help | q: Quit",
            Screen::BotList => "↑/↓: Navigate | Enter: Detail | b: Back | ?: Help | q: Quit",
            Screen::Firewall => {
                "↑/↓: Navigate | +: Add | -: Remove | *: Sync | b: Back | ?: Help | q: Quit"
            }
            Screen::Sources => {
                "↑/↓: Navigate | Enter: Select | b: Back | r: Refresh | ?: Help | q: Quit"
            }
            Screen::Help => "Any key: Back",
            Screen::QuitConfirm => "y: Yes | n: No",
            Screen::BotDetail(_) => "Enter: Toggle Status | b: Back | ?: Help | q: Quit",
            Screen::SourceDetail(_) => "b: Back | ?: Help | q: Quit",
        };

        let status_line = Line::from(vec![
            Span::styled(format!(" {} ", screen_name), colors.title().bold()),
            Span::styled(format!(" | {} ", help_text), colors.secondary()),
        ]);

        let block = Block::default()
            .borders(Borders::TOP)
            .border_style(colors.border());

        let paragraph = Paragraph::new(status_line)
            .block(block)
            .alignment(Alignment::Left);

        frame.render_widget(paragraph, area);
    }

    /// Handles the tick event of the terminal.
    pub fn tick(&mut self) {
        // Update dashboard messages
        self.dashboard.messages = self.messages.clone();
    }

    /// Handles key events.
    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> Result<()> {
        // Convert crossterm key event to our app event
        if let Some(app_event) = key_event_to_app_event(key_event) {
            // For quit confirm screen, handle y/n directly
            if self.screen_state.current_screen == Screen::QuitConfirm {
                match app_event {
                    AppEvent::Confirm => {
                        self.running = false;
                        return Ok(());
                    }
                    AppEvent::Cancel => {
                        self.screen_state.go_back();
                        return Ok(());
                    }
                    _ => {}
                }
            }

            // Send the app event to be processed
            self.events.send(app_event);
        }

        Ok(())
    }

    /// Handles application events.
    pub async fn handle_app_event(&mut self, event: AppEvent) -> Result<()> {
        match event {
            AppEvent::Quit => {
                self.screen_state.navigate_to(Screen::QuitConfirm);
            }
            AppEvent::ToggleTheme => {
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
            AppEvent::OpenSettings => {
                self.screen_state.navigate_to(Screen::Settings);
            }
            AppEvent::OpenBotList => {
                self.screen_state.navigate_to(Screen::BotList);
            }
            AppEvent::OpenFirewall => {
                self.screen_state.navigate_to(Screen::Firewall);
            }
            AppEvent::OpenDashboard => {
                self.screen_state.navigate_to(Screen::Dashboard);
            }
            AppEvent::OpenSources => {
                self.screen_state.navigate_to(Screen::Sources);
            }
            AppEvent::DiscoverSites => {
                // Discover nginx sites in background
                let db_clone = self.db.clone();
                let event_sender = self.events.sender.clone();

                tokio::spawn(async move {
                    let mut db_mut = db_clone;
                    let site_count = match Self::discover_and_store_nginx_sites_in_db(&mut db_mut) {
                        Ok(count) => count,
                        Err(e) => {
                            eprintln!("Site discovery failed: {}", e);
                            0
                        }
                    };

                    if site_count > 0 {
                        let _ = event_sender
                            .send(Event::App(AppEvent::SitesDiscovered { count: site_count }));
                    }
                });

                self.add_message("Scanning for NGINX sites...".to_string());
            }
            AppEvent::Help => {
                self.screen_state.navigate_to(Screen::Help);
            }
            AppEvent::Refresh | AppEvent::RefreshAllSources => {
                // Start async refresh in background (non-blocking)
                let db_clone = self.db.clone();
                let event_sender = self.events.sender.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        Self::refresh_all_sources_background(db_clone, event_sender).await
                    {
                        eprintln!("Background refresh failed: {}", e);
                    }
                });

                self.add_message("Starting refresh of all sources...".to_string());
            }
            AppEvent::Back => {
                // If category popup is open, close it
                if self.settings.category_popup.is_some() {
                    self.settings.close_category_config();
                } else {
                    self.screen_state.go_back();
                }
            }
            AppEvent::Confirm => {
                // On quit confirm screen, confirm quits
                if self.screen_state.current_screen == Screen::QuitConfirm {
                    self.running = false;
                }
            }
            AppEvent::Cancel => {
                // On quit confirm screen, cancel goes back
                if self.screen_state.current_screen == Screen::QuitConfirm {
                    self.screen_state.go_back();
                }
            }
            AppEvent::ToggleCategory => {
                // On settings screen, toggle the selected category status
                if self.screen_state.current_screen == Screen::Settings {
                    self.settings.toggle_selected_category();
                    self.add_message(format!(
                        "Toggled category to {}",
                        self.settings
                            .system_settings
                            .get(self.settings.selected_category.unwrap_or(0))
                            .map(|s| s.status)
                            .unwrap_or(BotStatus::Blocked)
                    ));
                }
            }
            AppEvent::AddFirewallRule => {
                // On firewall screen, add a rule
                if self.screen_state.current_screen == Screen::Firewall {
                    self.add_message(
                        "Press '+' to add a rule (input not yet implemented)".to_string(),
                    );
                }
            }
            AppEvent::RemoveFirewallRule => {
                // On firewall screen, remove the selected rule
                if self.screen_state.current_screen == Screen::Firewall {
                    if let Some(index) = self.screen_state.selected_index.checked_sub(1) {
                        if index < self.firewall.blocked_ips.len() {
                            if let Err(e) = self.firewall.remove_block_rule(index) {
                                self.add_message(format!("Failed to remove rule: {}", e));
                            } else {
                                self.add_message("Rule removed".to_string());
                            }
                        }
                    }
                }
            }
            AppEvent::SyncFirewall => {
                // On firewall screen, sync with database
                if self.screen_state.current_screen == Screen::Firewall {
                    self.sync_firewall().await?;
                }
            }
            AppEvent::Select => {
                self.on_select().await?;
            }
            AppEvent::Up | AppEvent::Down | AppEvent::Left | AppEvent::Right => {
                self.handle_navigation(event).await?;
            }
            AppEvent::ContextMenu => {}
            AppEvent::SitesDiscovered { count } => {
                self.add_message(format!("Discovered {} nginx sites", count));
                // Refresh settings to show the new sites
                self.refresh_settings()?;
            }
            AppEvent::SourcesRefreshed { sources, messages } => {
                // Update the sources list
                let needs_update: Vec<bool> = sources
                    .iter()
                    .map(|s| self.db.data_source_needs_update(s).unwrap_or(false))
                    .collect();

                self.sources = SourcesScreen::new(sources, needs_update);

                for msg in messages {
                    self.add_message(msg);
                }

                // Refresh dashboard to show updated source status
                self.refresh_dashboard()?;
            }
            AppEvent::BotDataFetched { source_id, bots } => {
                // Store bots in database
                let bot_ids = self.db.upsert_bots_from_source(&source_id, bots)?;
                self.add_message(format!("Stored {} bots from {}", bot_ids.len(), source_id));

                // Refresh bot list
                self.refresh_bot_list()?;
            }
        }

        Ok(())
    }

    /// Handles navigation events.
    pub async fn handle_navigation(&mut self, event: AppEvent) -> Result<()> {
        use AppEvent::*;

        // If category popup is open, navigate within it
        if self.settings.category_popup.is_some() {
            match event {
                Up => {
                    if let Some(ref mut popup) = self.settings.category_popup {
                        popup.navigate(-1);
                    }
                }
                Down => {
                    if let Some(ref mut popup) = self.settings.category_popup {
                        popup.navigate(1);
                    }
                }
                _ => {
                    self.screen_state.handle_navigation_from_app_event(event)?;
                }
            }
        } else {
            // Navigate between categories
            self.screen_state.handle_navigation_from_app_event(event)?;
            // Sync selected_index with settings.selected_category
            self.settings.selected_category = Some(self.screen_state.selected_index);
        }

        Ok(())
    }

    /// Handles the select action based on current screen.
    pub async fn on_select(&mut self) -> Result<()> {
        match self.screen_state.current_screen {
            Screen::Dashboard => {}
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
                    self.add_message(format!(
                        "Selected: {} (needs update: {})",
                        source.name, needs_update
                    ));
                }
            }
            Screen::BotDetail(_) => {
                // On bot detail, select toggles status
                if let Some(bot_detail) = &mut self.bot_detail {
                    let new_status = bot_detail.bot.status.toggle();
                    let mut updated_bot = bot_detail.bot.clone();
                    updated_bot.status = new_status;
                    self.db.upsert_bot(&updated_bot)?;
                    bot_detail.bot.status = new_status;
                    self.add_message(format!("Toggled {} to {}", updated_bot.name, new_status));
                }
            }
            Screen::Settings => {
                // If category popup is open, toggle the selected bot
                if let Some(ref mut popup) = self.settings.category_popup {
                    if let Some(bot) = popup.selected_bot() {
                        let new_status = bot.status.toggle();
                        let mut updated_bot = bot.clone();
                        updated_bot.status = new_status;
                        self.db.upsert_bot(&updated_bot)?;
                        self.add_message(format!("Toggled {} to {}", updated_bot.name, new_status));
                    }
                } else {
                    // Open category config popup for selected category
                    let bots = self.db.get_all_bots().ok().unwrap_or_default();
                    self.settings.open_category_config(bots);
                }
            }
            Screen::Firewall => {}
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

    /// Syncs firewall with database.
    pub async fn sync_firewall(&mut self) -> Result<()> {
        if self.screen_state.current_screen == Screen::Firewall {
            match self.db.get_all_bots() {
                Ok(bots) => {
                    let addresses: Vec<_> = bots
                        .into_iter()
                        .filter(|b| b.status == BotStatus::Blocked)
                        .flat_map(|b| b.ip_ranges.into_iter())
                        .map(|r| FirewallAddress::new(r.address))
                        .collect();

                    if let Err(e) = self.firewall.firewall.sync_block_rules(&addresses) {
                        self.add_message(format!("Failed to sync firewall: {}", e));
                    } else {
                        self.firewall.refresh();
                        self.add_message(format!(
                            "Synced {} addresses to firewall",
                            addresses.len()
                        ));
                    }
                }
                Err(e) => {
                    self.add_message(format!("Failed to get bots: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Refreshes the dashboard screen.
    pub fn refresh_dashboard(&mut self) -> Result<()> {
        let bots = self.db.get_all_bots()?;
        let sources = self.db.get_all_data_sources()?;

        let mut bots_by_status = std::collections::HashMap::new();
        let mut bots_by_category = std::collections::HashMap::new();

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

        let sources_with_status: Vec<(DataSource, bool)> =
            sources.into_iter().zip(needs_update.into_iter()).collect();

        self.dashboard = DashboardScreen {
            total_bots: bots.len(),
            bots_by_status,
            bots_by_category,
            sources: sources_with_status,
            messages: self.messages.clone(),
        };

        Ok(())
    }

    /// Refreshes the settings screen.
    pub fn refresh_settings(&mut self) -> Result<()> {
        // Load sites from database
        let sites = self.db.get_all_sites()?;

        // Convert database sites to SiteSetting structs
        let site_settings: Vec<crate::tui::screens::SiteSetting> = sites
            .into_iter()
            .map(|site| crate::tui::screens::SiteSetting {
                name: site.name,
                nginx_path: Some(site.config_path),
                category_settings: Vec::new(), // TODO: Load category settings for this site
            })
            .collect();

        self.settings = SettingsScreen::with_sites(site_settings);
        Ok(())
    }

    /// Discovers NGINX sites and stores them in the database.
    pub fn discover_and_store_nginx_sites(&mut self) -> Result<usize> {
        Self::discover_and_store_nginx_sites_in_db(&mut self.db)
    }

    /// Standalone function to discover and store nginx sites in a database.
    fn discover_and_store_nginx_sites_in_db(db: &mut Database) -> Result<usize> {
        // Discover nginx sites
        let sites = match discover_nginx_sites() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error discovering nginx sites: {}", e);
                return Ok(0);
            }
        };

        let mut count = 0;
        for site in &sites {
            for server_name in &site.server_names {
                let config_path = site.config_path.to_string_lossy().into_owned();
                // Store each server name as a site
                db.upsert_site(server_name, &config_path, Some(site.line_number))?;
                count += 1;
            }
        }

        Ok(count)
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

    /// Adds a message to the message queue.
    pub fn add_message(&mut self, message: String) {
        self.messages.push(message);
        // Keep only the last 10 messages
        if self.messages.len() > 10 {
            self.messages.remove(0);
        }
        self.dashboard.messages = self.messages.clone();
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

/// Runs the TUI application.
pub async fn run_tui() -> anyhow::Result<()> {
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use crossterm::ExecutableCommand;
    use std::io;

    // Initialize database
    let mut db = Database::open_default()?;
    db.initialize()?;
    db.ensure_categories()?;
    db.ensure_signals()?;
    db.initialize_data_sources()?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create and run the application
    let app = App::new(db)?;
    let result = app.run(&mut terminal).await.map_err(|e| {
        eprintln!("Error in app.run(): {}", e);
        if let Some(source) = e.source() {
            eprintln!("Caused by: {}", source);
        }
        e
    });

    // Cleanup terminal
    disable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}
