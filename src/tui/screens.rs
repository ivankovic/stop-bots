//! Screen definitions for the TUI.
//!
//! This module defines the different screens in the application and their
//! rendering logic.

use crate::db::{Bot, BotCategory, BotStatus, DataSource};
use crate::tui::{ColorScheme, Theme, TuiEvent};
use anyhow::Result;
use ratatui::{
    prelude::*,
    widgets::*,
};

// ============================================================================
// Screen Types
// ============================================================================

/// Different screens in the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// Main dashboard screen showing overview
    #[default]
    Dashboard,
    /// List of all bots
    BotList,
    /// Details of a specific bot
    BotDetail(usize),
    /// List of data sources
    Sources,
    /// Details of a specific source
    SourceDetail(usize),
    /// Settings screen
    Settings,
    /// Help screen
    Help,
    /// Quit confirmation
    QuitConfirm,
}

// ============================================================================
// Screen State
// ============================================================================

/// Shared state for all screens.
#[derive(Debug, Clone)]
pub struct ScreenState {
    /// Currently selected screen
    pub current_screen: Screen,
    /// Previous screen (for back navigation)
    pub previous_screen: Option<Screen>,
    /// Selected index in list screens
    pub selected_index: usize,
    /// Scroll offset for list screens
    pub scroll_offset: usize,
    /// Filter text for list screens
    pub filter: String,
    /// Theme
    pub theme: Theme,
    /// Color scheme (derived from theme)
    pub colors: ColorScheme,
}

impl ScreenState {
    /// Creates a new screen state.
    pub fn new() -> Self {
        Self {
            current_screen: Screen::default(),
            previous_screen: None,
            selected_index: 0,
            scroll_offset: 0,
            filter: String::new(),
            theme: Theme::default(),
            colors: Theme::default().color_scheme(),
        }
    }

    /// Updates the theme and color scheme.
    pub fn update_theme(&mut self) {
        self.colors = self.theme.color_scheme();
    }

    /// Navigates to a new screen.
    pub fn navigate_to(&mut self, screen: Screen) {
        self.previous_screen = Some(self.current_screen);
        self.current_screen = screen;
        self.selected_index = 0;
        self.scroll_offset = 0;
        self.filter.clear();
    }

    /// Goes back to the previous screen.
    pub fn go_back(&mut self) {
        if let Some(previous) = self.previous_screen {
            self.current_screen = previous;
            self.selected_index = 0;
            self.scroll_offset = 0;
            self.filter.clear();
        }
    }

    /// Handles navigation events.
    pub fn handle_navigation(&mut self, event: TuiEvent) -> Result<()> {
        match event {
            TuiEvent::Up => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                    if self.selected_index < self.scroll_offset {
                        self.scroll_offset = self.selected_index;
                    }
                }
            }
            TuiEvent::Down => {
                self.selected_index += 1;
            }
            TuiEvent::Left => {}
            TuiEvent::Right => {}
            TuiEvent::Select => {}
            TuiEvent::Back => {
                self.go_back();
            }
            TuiEvent::ToggleTheme => {
                self.theme = self.theme.toggle();
                self.update_theme();
            }
            TuiEvent::Refresh => {}
            TuiEvent::ContextMenu => {}
            _ => {}
        }
        Ok(())
    }
}

// ============================================================================
// Dashboard Screen
// ============================================================================

/// Dashboard screen showing overview of bot protection.
#[derive(Debug)]
pub struct DashboardScreen {
    /// Total number of bots
    pub total_bots: usize,
    /// Number of bots by status
    pub bots_by_status: std::collections::HashMap<BotStatus, usize>,
    /// Number of bots by category
    pub bots_by_category: std::collections::HashMap<BotCategory, usize>,
    /// Number of configured data sources
    pub source_count: usize,
    /// Number of sources that need updating
    pub sources_needing_update: usize,
    /// Recent events or messages
    pub messages: Vec<String>,
}

impl DashboardScreen {
    /// Creates a new dashboard screen with default values.
    pub fn new() -> Self {
        Self {
            total_bots: 0,
            bots_by_status: std::collections::HashMap::new(),
            bots_by_category: std::collections::HashMap::new(),
            source_count: 0,
            sources_needing_update: 0,
            messages: Vec::new(),
        }
    }

    /// Renders the dashboard screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;
        let block = Block::default()
            .title(Line::from(" Stop Bots ").style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(1, 1));

        // Split into sections
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Stats row
                Constraint::Length(3),  // Status breakdown
                Constraint::Length(3),  // Category breakdown
                Constraint::Min(0),     // Messages
            ])
            .split(inner);

        // Stats row
        self.render_stats(frame, colors, rows[0]);

        // Status breakdown
        self.render_status_breakdown(frame, colors, rows[1]);

        // Category breakdown
        self.render_category_breakdown(frame, colors, rows[2]);

        // Messages
        self.render_messages(frame, colors, rows[3]);
    }

    fn render_stats(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let stats = vec![
            ("Total Bots", self.total_bots.to_string()),
            ("Data Sources", self.source_count.to_string()),
            ("Needs Update", self.sources_needing_update.to_string()),
        ];

        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
            ])
            .split(area);

        for (i, (label, value)) in stats.into_iter().enumerate() {
            let stat_block = Block::default()
                .title(Line::from(label).style(colors.secondary()))
                .borders(Borders::NONE);
            frame.render_widget(stat_block, columns[i]);

            let value_para = Paragraph::new(Line::from(value).style(colors.title().bold()))
                .alignment(Alignment::Center);
            frame.render_widget(value_para, columns[i].inner(Margin::new(0, 1)));
        }
    }

    fn render_status_breakdown(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let block = Block::default()
            .title(Line::from(" Bot Status ").style(colors.title()))
            .borders(Borders::NONE);
        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(0, 1));
        let mut constraints = Vec::new();
        let mut status_items = Vec::new();

        for status in [BotStatus::Allowed, BotStatus::Blocked] {
            let count = self.bots_by_status.get(&status).copied().unwrap_or(0);
            if count > 0 {
                constraints.push(Constraint::Length(1));
                let color = match status {
                    BotStatus::Allowed => colors.success(),
                    BotStatus::Blocked => colors.error(),
                };
                status_items.push((format!("{}", status), count, color));
            }
        }

        if constraints.is_empty() {
            constraints.push(Constraint::Length(1));
            status_items.push(("No bots".to_string(), 0, colors.text()));
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints(constraints)
            .split(inner);

        for (i, (label, count, color)) in status_items.into_iter().enumerate() {
            let gauge = Gauge::default()
                .label(Span::styled(label, color))
                .ratio(count as f64 / self.total_bots.max(1) as f64)
                .fg(color.fg.unwrap_or(Color::White))
                .bg(Color::DarkGray);
            frame.render_widget(gauge, rows[i]);
        }
    }

    fn render_category_breakdown(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let block = Block::default()
            .title(Line::from(" Bot Categories ").style(colors.title()))
            .borders(Borders::NONE);
        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(0, 1));

        if self.bots_by_category.is_empty() {
            let para = Paragraph::new("No categories").style(colors.inactive());
            frame.render_widget(para, inner);
            return;
        }

        // Sort categories by count (descending)
        let mut categories: Vec<_> = self.bots_by_category.iter().collect();
        categories.sort_by(|a, b| b.1.cmp(a.1));

        let constraints: Vec<Constraint> = categories
            .iter()
            .map(|(_, &count)| {
                if count > 0 {
                    Constraint::Ratio(count as u32, self.total_bots as u32)
                } else {
                    Constraint::Length(0)
                }
            })
            .collect();

        let rows = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints(constraints)
            .split(inner);

        for ((category, &count), area) in categories.into_iter().zip(rows.iter().copied()) {
            if count == 0 {
                continue;
            }
            let bar_color = match category {
                BotCategory::Scanner | BotCategory::SecurityScanner => colors.error(),
                BotCategory::AiScraper => colors.warning(),
                BotCategory::AdBot => colors.warning(),
                BotCategory::SearchEngine => colors.success(),
                _ => colors.primary(),
            };
            frame.render_widget(
                Block::default()
                    .title(Line::from(format!("{}: {}", category, count)).style(bar_color))
                    .borders(Borders::NONE),
                area,
            );
        }
    }

    fn render_messages(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        if self.messages.is_empty() {
            return;
        }

        let block = Block::default()
            .title(Line::from(" Messages ").style(colors.title()))
            .borders(Borders::TOP)
            .border_style(colors.border());
        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(0, 1));
        let messages: Vec<Line> = self
            .messages
            .iter()
            .map(|msg| Line::from(msg.as_str()).style(colors.text()))
            .collect();
        let para = Paragraph::new(messages).scroll((0, 0));
        frame.render_widget(para, inner);
    }
}

// ============================================================================
// Bot List Screen
// ============================================================================

/// Bot list screen showing all bots.
#[derive(Debug)]
pub struct BotListScreen {
    /// All bots to display
    pub bots: Vec<Bot>,
    /// Filtered bots (based on current filter)
    pub filtered_bots: Vec<usize>,
}

impl BotListScreen {
    /// Creates a new bot list screen.
    pub fn new(bots: Vec<Bot>) -> Self {
        Self {
            filtered_bots: (0..bots.len()).collect(),
            bots,
        }
    }

    /// Updates the filter.
    pub fn update_filter(&mut self, filter: &str) {
        self.filtered_bots.clear();
        let filter_lower = filter.to_lowercase();

        for (i, bot) in self.bots.iter().enumerate() {
            if filter.is_empty() || bot.name.to_lowercase().contains(&filter_lower) {
                self.filtered_bots.push(i);
            }
        }
    }

    /// Gets the current bot at the selected index.
    pub fn get_selected_bot(&self, index: usize) -> Option<&Bot> {
        self.filtered_bots
            .get(index)
            .and_then(|&i| self.bots.get(i))
    }

    /// Renders the bot list screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;
        let block = Block::default()
            .title(Line::from(" Bot List ").style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(1, 1));

        // Filter input (if filter is active)
        let has_filter = !state.filter.is_empty();
        let filter_height = if has_filter { 1 } else { 0 };

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Length(filter_height),
                Constraint::Min(0),
                Constraint::Length(1), // Help
            ])
            .split(inner);

        // Filter display
        if has_filter {
            let filter_text = Paragraph::new(format!("Filter: {}", state.filter))
                .style(colors.secondary());
            frame.render_widget(filter_text, rows[0]);
        }

        // Bot list
        let list_area = if has_filter { rows[1] } else { rows[0] };
        self.render_bot_list(frame, colors, list_area, state);

        // Help
        let help_area = if has_filter { rows[2] } else { rows[1] };
        self.render_help(frame, colors, help_area);
    }

    fn render_bot_list(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect, state: &ScreenState) {
        if self.filtered_bots.is_empty() {
            let para = Paragraph::new("No bots found")
                .style(colors.inactive())
                .alignment(Alignment::Center);
            frame.render_widget(para, area);
            return;
        }

        // Calculate visible range
        let items_per_page = area.height as usize;
        let start_idx = state.scroll_offset.min(self.filtered_bots.len().saturating_sub(1));
        let end_idx = (start_idx + items_per_page).min(self.filtered_bots.len());

        // Create list items
        let items: Vec<ListItem> = (start_idx..end_idx)
            .filter_map(|i| self.filtered_bots.get(i).and_then(|&bot_idx| self.bots.get(bot_idx)))
            .map(|bot| {
                let status_style = match bot.status {
                    BotStatus::Allowed => colors.success(),
                    BotStatus::Blocked => colors.error(),
                };
                let line = Line::from(vec![
                    Span::styled(
                        &bot.name,
                        Style::new().bold(),
                    ),
                    Span::raw(" - "),
                    Span::styled(
                        format!("{}", bot.status),
                        status_style,
                    ),
                    Span::raw(" - "),
                    Span::styled(
                        bot.categories
                            .iter()
                            .map(|c| format!("{}", c))
                            .collect::<Vec<_>>()
                            .join(", "),
                        colors.secondary(),
                    ),
                ]);
                ListItem::new(line).style(colors.text())
            })
            .collect();

        let list = List::new(items)
            .highlight_style(colors.selected())
            .highlight_symbol("> ");

        // Render the list items
        let list_area = area.inner(Margin::new(0, 0));
        frame.render_stateful_widget(
            list,
            list_area,
            &mut ListState::default().with_selected(Some(
                state.selected_index.saturating_sub(start_idx)
            )),
        );
    }

    fn render_help(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let help_text = vec![
            Line::from("↑↓/kj: Navigate"),
            Line::from("Enter/Space: Select"),
            Line::from("b: Back"),
            Line::from("c: Toggle theme"),
            Line::from("r: Refresh"),
            Line::from("/: Filter"),
            Line::from("q: Quit"),
        ];

        let help_para = Paragraph::new(help_text)
            .style(colors.inactive())
            .alignment(Alignment::Center);
        frame.render_widget(help_para, area);
    }
}

// ============================================================================
// Sources Screen
// ============================================================================

/// Sources screen showing all data sources.
#[derive(Debug)]
pub struct SourcesScreen {
    /// All data sources
    pub sources: Vec<DataSource>,
    /// Filtered sources
    pub filtered_sources: Vec<usize>,
    /// Which sources need updating
    pub needs_update: Vec<bool>,
}

impl SourcesScreen {
    /// Creates a new sources screen.
    pub fn new(sources: Vec<DataSource>, needs_update: Vec<bool>) -> Self {
        Self {
            filtered_sources: (0..sources.len()).collect(),
            sources,
            needs_update,
        }
    }

    /// Updates the filter.
    pub fn update_filter(&mut self, filter: &str) {
        self.filtered_sources.clear();
        let filter_lower = filter.to_lowercase();

        for (i, source) in self.sources.iter().enumerate() {
            if filter.is_empty() || source.name.to_lowercase().contains(&filter_lower) {
                self.filtered_sources.push(i);
            }
        }
    }

    /// Gets the current source at the selected index.
    pub fn get_selected_source(&self, index: usize) -> Option<(&DataSource, bool)> {
        self.filtered_sources
            .get(index)
            .and_then(|&i| {
                self.sources
                    .get(i)
                    .zip(self.needs_update.get(i).copied())
            })
    }

    /// Renders the sources screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;
        let block = Block::default()
            .title(Line::from(" Data Sources ").style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(1, 1));

        // Split into filter, list, and help
        let has_filter = !state.filter.is_empty();
        let filter_height = if has_filter { 1 } else { 0 };

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Length(filter_height),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(inner);

        // Filter display
        if has_filter {
            let filter_text = Paragraph::new(format!("Filter: {}", state.filter))
                .style(colors.secondary());
            frame.render_widget(filter_text, rows[0]);
        }

        // Sources list
        let list_area = if has_filter { rows[1] } else { rows[0] };
        self.render_sources_list(frame, colors, list_area, state);

        // Help
        let help_area = if has_filter { rows[2] } else { rows[1] };
        self.render_help(frame, colors, help_area);
    }

    fn render_sources_list(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect, state: &ScreenState) {
        if self.filtered_sources.is_empty() {
            let para = Paragraph::new("No sources found")
                .style(colors.inactive())
                .alignment(Alignment::Center);
            frame.render_widget(para, area);
            return;
        }

        // Calculate visible range
        let items_per_page = area.height as usize;
        let start_idx = state.scroll_offset.min(self.filtered_sources.len().saturating_sub(1));
        let end_idx = (start_idx + items_per_page).min(self.filtered_sources.len());

        // Create list items
        let items: Vec<ListItem> = (start_idx..end_idx)
            .filter_map(|i| {
                self.filtered_sources.get(i).and_then(|&src_idx| {
                    self.sources.get(src_idx).zip(self.needs_update.get(src_idx).copied())
                })
            })
            .map(|(source, needs_update)| {
                let status_style = if needs_update {
                    colors.warning()
                } else {
                    colors.success()
                };
                let official_marker = if source.is_official { "*" } else { "" };
                let line = Line::from(vec![
                    Span::styled(
                        &source.name,
                        Style::new().bold(),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        official_marker,
                        colors.primary(),
                    ),
                    Span::raw(" - "),
                    Span::styled(
                        source.data_type.as_db_str(),
                        colors.secondary(),
                    ),
                    Span::raw(" - "),
                    Span::styled(
                        if needs_update {
                            "Needs update"
                        } else {
                            "Up to date"
                        },
                        status_style,
                    ),
                ]);
                ListItem::new(line).style(colors.text())
            })
            .collect();

        let list = List::new(items)
            .highlight_style(colors.selected())
            .highlight_symbol("> ");

        let list_area = area.inner(Margin::new(0, 0));
        frame.render_stateful_widget(
            list,
            list_area,
            &mut ListState::default().with_selected(Some(
                state.selected_index.saturating_sub(start_idx)
            )),
        );
    }

    fn render_help(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let help_text = vec![
            Line::from("↑↓/kj: Navigate"),
            Line::from("Enter: Select"),
            Line::from("r: Refresh selected"),
            Line::from("R: Refresh all"),
            Line::from("b: Back"),
            Line::from("c: Toggle theme"),
            Line::from("q: Quit"),
        ];

        let help_para = Paragraph::new(help_text)
            .style(colors.inactive())
            .alignment(Alignment::Center);
        frame.render_widget(help_para, area);
    }
}

// ============================================================================
// Bot Detail Screen
// ============================================================================

/// Bot detail screen showing detailed information about a specific bot.
#[derive(Debug)]
pub struct BotDetailScreen {
    /// The bot to display
    pub bot: Bot,
}

impl BotDetailScreen {
    /// Creates a new bot detail screen.
    pub fn new(bot: Bot) -> Self {
        Self { bot }
    }

    /// Renders the bot detail screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;
        let block = Block::default()
            .title(Line::from(format!(" {} ", self.bot.name)).style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(1, 1));

        // Split into sections
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Min(0), // Main info
                Constraint::Length(3), // Actions
            ])
            .split(inner);

        // Main info
        self.render_main_info(frame, colors, rows[0]);

        // Actions
        self.render_actions(frame, colors, rows[1]);
    }

    fn render_main_info(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let mut lines = Vec::new();

        // Status
        let status_style = match self.bot.status {
            BotStatus::Allowed => colors.success(),
            BotStatus::Blocked => colors.error(),
        };
        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::new().bold()),
            Span::styled(format!("{}", self.bot.status), status_style),
        ]));

        // Categories
        if !self.bot.categories.is_empty() {
            let categories: Vec<String> = self.bot.categories.iter().map(|c| format!("{}", c)).collect();
            lines.push(Line::from(vec![
                Span::styled("Categories: ", Style::new().bold()),
                Span::styled(categories.join(", "), colors.primary()),
            ]));
        }

        // Type flags
        let mut flags = Vec::new();
        if self.bot.is_ai_bot {
            flags.push("AI Bot");
        }
        if self.bot.is_scanner {
            flags.push("Scanner");
        }
        if !flags.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Type: ", Style::new().bold()),
                Span::styled(flags.join(", "), colors.warning()),
            ]));
        }

        // IP Ranges
        if !self.bot.ip_ranges.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("IP Ranges: ", Style::new().bold()),
            ]));
            for range in &self.bot.ip_ranges {
                lines.push(Line::from(vec![
                    Span::raw("  - "),
                    Span::styled(&range.address, colors.secondary()),
                ]));
            }
        }

        // User Agent Patterns
        if !self.bot.user_agent_patterns.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("User Agent Patterns: ", Style::new().bold()),
            ]));
            for pattern in &self.bot.user_agent_patterns {
                lines.push(Line::from(vec![
                    Span::raw("  - "),
                    Span::styled(&pattern.pattern, colors.secondary()),
                ]));
            }
        }

        // Notes
        if let Some(notes) = &self.bot.notes {
            lines.push(Line::from(vec![
                Span::styled("Notes: ", Style::new().bold()),
                Span::styled(notes, colors.text()),
            ]));
        }

        let para = Paragraph::new(lines).style(colors.text());
        frame.render_widget(para, area);
    }

    fn render_actions(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let block = Block::default()
            .title(Line::from(" Actions ").style(colors.title()))
            .borders(Borders::TOP)
            .border_style(colors.border());
        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(0, 1));
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
            ])
            .split(inner);

        let actions = [
            ("Toggle Status", "s"),
            ("Edit", "e"),
            ("Delete", "d"),
        ];

        for (i, (action, key)) in actions.into_iter().enumerate() {
            let para = Paragraph::new(Line::from(vec![
                Span::styled(format!("[{}] ", key), colors.primary().bold()),
                Span::styled(action, colors.text()),
            ]))
            .alignment(Alignment::Center);
            frame.render_widget(para, columns[i]);
        }
    }
}

// ============================================================================
// Help Screen
// ============================================================================

/// Help screen showing keyboard shortcuts and usage information.
#[derive(Debug)]
pub struct HelpScreen {
    /// Help text to display
    pub help_text: Vec<Vec<Span<'static>>>,
}

impl HelpScreen {
    /// Creates a new help screen.
    pub fn new() -> Self {
        Self {
            help_text: vec![
                vec![
                    Span::raw("Stop Bots - Keyboard Shortcuts"),
                ],
                vec![],
                vec![
                    Span::raw("Navigation:"),
                ],
                vec![
                    Span::raw("  ↑/↓/k/j     "),
                    Span::raw("Navigate up/down"),
                ],
                vec![
                    Span::raw("  ←/h          "),
                    Span::raw("Navigate left"),
                ],
                vec![
                    Span::raw("  →/l          "),
                    Span::raw("Navigate right"),
                ],
                vec![
                    Span::raw("  Enter/Space  "),
                    Span::raw("Select item"),
                ],
                vec![
                    Span::raw("  b            "),
                    Span::raw("Go back"),
                ],
                vec![
                    Span::raw("  Esc/q        "),
                    Span::raw("Quit"),
                ],
                vec![],
                vec![
                    Span::raw("Actions:"),
                ],
                vec![
                    Span::raw("  c            "),
                    Span::raw("Toggle theme (dark/light)"),
                ],
                vec![
                    Span::raw("  r            "),
                    Span::raw("Refresh current view"),
                ],
                vec![
                    Span::raw("  R            "),
                    Span::raw("Refresh all sources"),
                ],
                vec![],
                vec![
                    Span::raw("Views:"),
                ],
                vec![
                    Span::raw("  1            "),
                    Span::raw("Dashboard"),
                ],
                vec![
                    Span::raw("  2            "),
                    Span::raw("Bot List"),
                ],
                vec![
                    Span::raw("  3            "),
                    Span::raw("Data Sources"),
                ],
                vec![
                    Span::raw("  4            "),
                    Span::raw("Settings"),
                ],
                vec![
                    Span::raw("  ?            "),
                    Span::raw("Help (this screen)"),
                ],
            ],
        }
    }

    /// Renders the help screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;
        let block = Block::default()
            .title(Line::from(" Help ").style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(1, 1));

        // Convert static spans to styled spans with current colors
        let lines: Vec<Line> = self
            .help_text
            .iter()
            .map(|spans| {
                Line::from(
                    spans
                        .iter()
                        .map(|s| Span::styled(s.content.clone(), colors.text()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let para = Paragraph::new(lines).style(colors.text());
        frame.render_widget(para, inner);
    }
}

// ============================================================================
// Quit Confirmation Screen
// ============================================================================

/// Quit confirmation screen.
#[derive(Debug)]
pub struct QuitConfirmScreen;

impl QuitConfirmScreen {
    /// Creates a new quit confirmation screen.
    pub fn new() -> Self {
        Self
    }

    /// Renders the quit confirmation screen.
    pub fn render(&self, frame: &mut Frame, state: &ScreenState, area: Rect) {
        let colors = &state.colors;

        // Centered block
        let block = Block::default()
            .title(Line::from(" Confirm Quit ").style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        // Calculate centered position
        let width = 40.min(area.width);
        let height = 7.min(area.height);
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let centered_area = Rect {
            x,
            y,
            width,
            height,
        };

        frame.render_widget(block, centered_area);

        let inner = centered_area.inner(Margin::new(1, 1));

        let lines = vec![
            Line::from("Are you sure you want to quit?").style(colors.text()),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Y]", colors.success().bold()),
                Span::raw(" Yes   "),
                Span::styled("[N]", colors.error().bold()),
                Span::raw(" No"),
            ]),
        ];

        let para = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(para, inner);
    }
}
