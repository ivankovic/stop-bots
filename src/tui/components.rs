//! Reusable UI components for the TUI.
//!
//! This module provides reusable components like popups, confirmations, inputs, etc.

use ratatui::prelude::*;
use ratatui::widgets::*;
use std::time::{Duration, SystemTime};
use unicode_width::UnicodeWidthStr;

use crate::tui::ColorScheme;

// ============================================================================
// Popup Component
// ============================================================================

/// A generic popup component.
pub struct Popup<'a> {
    /// Title of the popup
    pub title: &'a str,
    /// Content of the popup (can be multi-line)
    pub content: Vec<Line<'a>>,
    /// Buttons to display at the bottom
    pub buttons: Vec<(&'a str, char)>, // (label, shortcut)
    /// Style for the popup
    pub style: Style,
}

impl<'a> Popup<'a> {
    /// Creates a new popup.
    pub fn new(title: &'a str, content: Vec<Line<'a>>) -> Self {
        Self {
            title,
            content,
            buttons: Vec::new(),
            style: Style::new(),
        }
    }

    /// Adds a button to the popup.
    pub fn with_button(mut self, label: &'a str, shortcut: char) -> Self {
        self.buttons.push((label, shortcut));
        self
    }

    /// Sets the style for the popup.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Renders the popup centered in the given area.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        // Calculate popup size based on content
        let content_height = self.content.len().min(20) as u16;
        let button_height = if !self.buttons.is_empty() { 1 } else { 0 };
        let total_height = content_height + 2 + button_height; // +2 for title and padding
        let width = 60.min(area.width);
        let height = total_height.min(area.height);

        // Center the popup
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let popup_area = Rect {
            x,
            y,
            width,
            height,
        };

        // Draw the popup
        let block = Block::default()
            .title(Line::from(self.title).style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border())
            .style(self.style);

        frame.render_widget(Clear, popup_area);
        frame.render_widget(block, popup_area);

        let inner = popup_area.inner(Margin::new(1, 1));

        // Split into content and buttons
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Length(content_height),
                Constraint::Length(button_height),
            ])
            .split(inner);

        // Content
        let content_area = rows[0];
        let para = Paragraph::new(self.content.clone()).style(colors.text());
        frame.render_widget(para, content_area);

        // Buttons
        if !self.buttons.is_empty() {
            let button_area = rows[1];
            self.render_buttons(frame, colors, button_area);
        }
    }

    fn render_buttons(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let columns: Vec<Constraint> = self
            .buttons
            .iter()
            .map(|_| Constraint::Ratio(1, self.buttons.len() as u32))
            .collect();

        let split = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints(columns)
            .split(area);

        for (i, (label, shortcut)) in self.buttons.iter().enumerate() {
            let shortcut_span = Span::styled(format!("[{}] ", shortcut), colors.primary().bold());
            let label_span = Span::styled(*label, colors.text());
            let line = Line::from(vec![shortcut_span, label_span]);
            let para = Paragraph::new(line).alignment(Alignment::Center);
            frame.render_widget(para, split[i]);
        }
    }
}

// ============================================================================
// Confirmation Dialog
// ============================================================================

/// A confirmation dialog popup.
pub struct ConfirmationDialog<'a> {
    /// Message to display
    pub message: &'a str,
    /// Action being confirmed
    pub action: &'a str,
    /// Style
    pub style: Style,
}

impl<'a> ConfirmationDialog<'a> {
    /// Creates a new confirmation dialog.
    pub fn new(message: &'a str, action: &'a str) -> Self {
        Self {
            message,
            action,
            style: Style::new(),
        }
    }

    /// Sets the style.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Renders the confirmation dialog.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let content = vec![
            Line::from(self.message),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Y]", colors.success().bold()),
                Span::raw(" Yes   "),
                Span::styled("[N]", colors.error().bold()),
                Span::raw(" No"),
            ]),
        ];

        let popup = Popup::new(self.action, content).with_style(self.style);
        popup.render(frame, colors, area);
    }
}

// ============================================================================
// Input Component
// ============================================================================

/// A text input component.
pub struct Input<'a> {
    /// Label for the input
    pub label: &'a str,
    /// Current value
    pub value: String,
    /// Cursor position
    pub cursor_pos: usize,
    /// Whether the input is active
    pub active: bool,
    /// Style
    pub style: Style,
}

impl<'a> Input<'a> {
    /// Creates a new input.
    pub fn new(label: &'a str) -> Self {
        Self {
            label,
            value: String::new(),
            cursor_pos: 0,
            active: false,
            style: Style::new(),
        }
    }

    /// Sets the value.
    pub fn with_value(mut self, value: String) -> Self {
        self.value = value;
        self.cursor_pos = self.value.len();
        self
    }

    /// Sets whether the input is active.
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// Sets the style.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Handles a character input.
    pub fn input_char(&mut self, c: char) {
        if !self.active {
            return;
        }
        let cursor_byte_pos = self
            .value
            .char_indices()
            .nth(self.cursor_pos)
            .map(|(pos, _)| pos)
            .unwrap_or(self.value.len());
        self.value.insert(cursor_byte_pos, c);
        self.cursor_pos += 1;
    }

    /// Handles backspace.
    pub fn backspace(&mut self) {
        if !self.active || self.value.is_empty() {
            return;
        }
        let cursor_byte_pos = self
            .value
            .char_indices()
            .nth(self.cursor_pos.saturating_sub(1))
            .map(|(pos, _)| pos)
            .unwrap_or(0);
        if cursor_byte_pos < self.value.len() {
            self.value.remove(cursor_byte_pos);
            self.cursor_pos = self.cursor_pos.saturating_sub(1);
        }
    }

    /// Handles delete.
    pub fn delete(&mut self) {
        if !self.active || self.value.is_empty() {
            return;
        }
        let cursor_byte_pos = self
            .value
            .char_indices()
            .nth(self.cursor_pos)
            .map(|(pos, _)| pos)
            .unwrap_or(self.value.len());
        if cursor_byte_pos < self.value.len() {
            self.value.remove(cursor_byte_pos);
        }
    }

    /// Handles left arrow.
    pub fn left(&mut self) {
        if !self.active {
            return;
        }
        self.cursor_pos = self.cursor_pos.saturating_sub(1);
    }

    /// Handles right arrow.
    pub fn right(&mut self) {
        if !self.active {
            return;
        }
        self.cursor_pos = self.cursor_pos.min(self.value.len());
    }

    /// Handles home.
    pub fn home(&mut self) {
        if !self.active {
            return;
        }
        self.cursor_pos = 0;
    }

    /// Handles end.
    pub fn end(&mut self) {
        if !self.active {
            return;
        }
        self.cursor_pos = self.value.len();
    }

    /// Renders the input.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let label_line = Line::from(self.label).style(colors.secondary());
        let value_line = Line::from(self.value.as_str()).style(colors.text());

        let lines = vec![label_line, value_line];
        let para = Paragraph::new(lines).style(self.style);
        frame.render_widget(para, area);

        // Draw cursor if active
        if self.active {
            let cursor_byte_pos = self
                .value
                .char_indices()
                .nth(self.cursor_pos)
                .map(|(pos, _)| pos)
                .unwrap_or(self.value.len());
            let text_width = self.value[..cursor_byte_pos].width() as u16;
            let x = area.x + 1 + text_width; // +1 for label width
            let y = area.y + 2; // Label is on line 1, value on line 2
            frame.set_cursor(x, y);
        }
    }
}

// ============================================================================
// Status Bar Component
// ============================================================================

/// A status bar at the bottom of the screen.
pub struct StatusBar<'a> {
    /// Left-aligned text
    pub left: Vec<Span<'a>>,
    /// Center text
    pub center: Vec<Span<'a>>,
    /// Right-aligned text
    pub right: Vec<Span<'a>>,
    /// Style
    pub style: Style,
}

impl<'a> StatusBar<'a> {
    /// Creates a new empty status bar.
    pub fn new() -> Self {
        Self {
            left: Vec::new(),
            center: Vec::new(),
            right: Vec::new(),
            style: Style::new(),
        }
    }

    /// Sets the left text.
    pub fn with_left(mut self, text: Vec<Span<'a>>) -> Self {
        self.left = text;
        self
    }

    /// Sets the center text.
    pub fn with_center(mut self, text: Vec<Span<'a>>) -> Self {
        self.center = text;
        self
    }

    /// Sets the right text.
    pub fn with_right(mut self, text: Vec<Span<'a>>) -> Self {
        self.right = text;
        self
    }

    /// Sets the style.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Renders the status bar.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let block = Block::default()
            .borders(Borders::TOP)
            .border_style(colors.border())
            .style(self.style);

        frame.render_widget(block, area);

        let inner = area.inner(Margin::new(0, 1));

        // Split into left, center, right
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
                Constraint::Ratio(1, 3),
            ])
            .split(inner);

        // Left
        let left_para = Paragraph::new(Line::from(self.left.clone())).style(colors.text());
        frame.render_widget(left_para, layout[0]);

        // Center
        let center_para = Paragraph::new(Line::from(self.center.clone()))
            .style(colors.text())
            .alignment(Alignment::Center);
        frame.render_widget(center_para, layout[1]);

        // Right
        let right_para = Paragraph::new(Line::from(self.right.clone()))
            .style(colors.text())
            .alignment(Alignment::Right);
        frame.render_widget(right_para, layout[2]);
    }
}

// ============================================================================
// Loading Indicator
// ============================================================================

/// A loading spinner indicator.
pub struct LoadingIndicator {
    /// Current progress
    pub progress: f64,
    /// Message to display
    pub message: String,
    /// Spinner frames
    pub spinner_frames: Vec<&'static str>,
    /// Current spinner frame index
    pub current_frame: usize,
    /// Last update time
    pub last_update: SystemTime,
    /// Update interval
    pub update_interval: Duration,
}

impl LoadingIndicator {
    /// Creates a new loading indicator.
    pub fn new(message: String) -> Self {
        Self {
            progress: 0.0,
            message,
            spinner_frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current_frame: 0,
            last_update: SystemTime::now(),
            update_interval: Duration::from_millis(100),
        }
    }

    /// Updates the spinner frame if enough time has passed.
    pub fn update(&mut self) {
        if SystemTime::now()
            .duration_since(self.last_update)
            .unwrap_or(Duration::ZERO)
            >= self.update_interval
        {
            self.current_frame = (self.current_frame + 1) % self.spinner_frames.len();
            self.last_update = SystemTime::now();
        }
    }

    /// Sets the progress (0.0 to 1.0).
    pub fn with_progress(mut self, progress: f64) -> Self {
        self.progress = progress.clamp(0.0, 1.0);
        self
    }

    /// Renders the loading indicator.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let spinner = self.spinner_frames[self.current_frame];
        let text = format!("{} {}", spinner, self.message);
        let line = Line::from(text).style(colors.primary());
        let para = Paragraph::new(line).alignment(Alignment::Center);
        frame.render_widget(para, area);
    }
}

// ============================================================================
// Notification Component
// ============================================================================

/// A notification toast at the top or bottom of the screen.
pub struct Notification<'a> {
    /// Message to display
    pub message: Vec<Span<'a>>,
    /// Type of notification (info, success, warning, error)
    pub notification_type: NotificationType,
    /// Style
    pub style: Style,
}

/// Type of notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationType {
    /// Informational message
    Info,
    /// Success message
    Success,
    /// Warning message
    Warning,
    /// Error message
    Error,
}

impl<'a> Notification<'a> {
    /// Creates a new notification.
    pub fn new(message: Vec<Span<'a>>, notification_type: NotificationType) -> Self {
        Self {
            message,
            notification_type,
            style: Style::new(),
        }
    }

    /// Sets the style.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Renders the notification at the bottom of the screen.
    pub fn render(&self, frame: &mut Frame, _colors: &ColorScheme, area: Rect) {
        let bg_color = match self.notification_type {
            NotificationType::Info => Color::Blue,
            NotificationType::Success => Color::Green,
            NotificationType::Warning => Color::Yellow,
            NotificationType::Error => Color::Red,
        };

        let fg_color = Color::White; // Use white text on colored background for better visibility

        let block = Block::default()
            .borders(Borders::NONE)
            .style(Style::new().bg(bg_color).fg(fg_color));

        let notification_area = Rect {
            x: area.x,
            y: area.bottom().saturating_sub(1),
            width: area.width,
            height: 1,
        };

        frame.render_widget(block, notification_area);

        let line =
            Line::from(self.message.clone()).style(Style::new().fg(fg_color).bg(bg_color).bold());
        let para = Paragraph::new(line).alignment(Alignment::Center);
        frame.render_widget(para, notification_area);
    }
}

// ============================================================================
// Category Configuration Popup
// ============================================================================

use crate::db::{Bot, BotCategory, BotStatus};

/// A popup for configuring a bot category.
/// Shows category status and allows toggling between ALLOWED and BLOCKED.
/// Also shows individual bots in the category that can be overridden.
#[derive(Debug, Clone)]
pub struct CategoryConfigPopup {
    /// The category being configured
    pub category: BotCategory,
    /// Current status of the category
    pub status: BotStatus,
    /// Bots in this category
    pub bots: Vec<Bot>,
    /// Currently selected index in bot list
    pub selected_index: usize,
    /// Whether the popup is active
    pub active: bool,
}

impl CategoryConfigPopup {
    /// Creates a new category configuration popup.
    pub fn new(category: BotCategory, status: BotStatus, bots: Vec<Bot>) -> Self {
        Self {
            category,
            status,
            bots,
            selected_index: 0,
            active: true,
        }
    }

    /// Toggles the category status.
    pub fn toggle_status(&mut self) -> BotStatus {
        self.status = self.status.toggle();
        self.status
    }

    /// Handles navigation (up/down).
    pub fn navigate(&mut self, direction: i32) {
        if self.bots.is_empty() {
            return;
        }

        let len = self.bots.len();
        if direction > 0 {
            self.selected_index = (self.selected_index + 1) % len;
        } else if direction < 0 {
            self.selected_index = (self.selected_index + len - 1) % len;
        }
    }

    /// Gets the currently selected bot.
    pub fn selected_bot(&self) -> Option<&Bot> {
        self.bots.get(self.selected_index)
    }

    /// Renders the category configuration popup.
    pub fn render(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        // Calculate popup dimensions
        let width = 80.min(area.width);
        let height = 20.min(area.height);

        // Center the popup
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let popup_area = Rect {
            x,
            y,
            width,
            height,
        };

        // Draw the popup background
        let block = Block::default()
            .title(Line::from(format!(" {} ", self.category)).style(colors.title()))
            .borders(Borders::ALL)
            .border_style(colors.border());

        frame.render_widget(Clear, popup_area);
        frame.render_widget(block, popup_area);

        let inner = popup_area.inner(Margin::new(1, 1));

        // Split into header, bot list, and footer
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([
                Constraint::Length(3), // Header with status toggle
                Constraint::Min(0),    // Bot list
                Constraint::Length(1), // Footer
            ])
            .split(inner);

        // Header: Category status
        self.render_header(frame, colors, rows[0]);

        // Middle: Bot list
        self.render_bot_list(frame, colors, rows[1]);

        // Footer: Help
        self.render_footer(frame, colors, rows[2]);
    }

    fn render_header(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        let status_style = match self.status {
            BotStatus::Allowed => colors.success(),
            BotStatus::Blocked => colors.error(),
        };

        let lines = vec![
            Line::from(vec![
                Span::styled("Status: ", Style::new().bold()),
                Span::styled(format!("{}", self.status), status_style.bold()),
            ]),
            Line::from("(Press s to toggle, ↑↓ to select bot, Enter to override)"),
        ];

        let para = Paragraph::new(lines).style(colors.text());
        frame.render_widget(para, area);
    }

    fn render_bot_list(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        if self.bots.is_empty() {
            let para = Paragraph::new("No bots in this category")
                .style(colors.inactive())
                .alignment(Alignment::Center);
            frame.render_widget(para, area);
            return;
        }

        // Calculate visible range
        let items_per_page = area.height as usize;
        let start_idx = self
            .selected_index
            .min(self.bots.len().saturating_sub(items_per_page / 2));
        let end_idx = (start_idx + items_per_page).min(self.bots.len());

        // Create list items
        let items: Vec<ListItem> = (start_idx..end_idx)
            .map(|i| {
                let bot = &self.bots[i];
                let status_style = match bot.status {
                    BotStatus::Allowed => colors.success(),
                    BotStatus::Blocked => colors.error(),
                };

                let name = bot.name.clone();
                let line = Line::from(vec![
                    Span::raw("  "),
                    Span::styled(name, Style::new().bold()),
                    Span::raw(" - "),
                    Span::styled(format!("{}", bot.status), status_style),
                ]);

                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .highlight_style(colors.selected())
            .highlight_symbol("> ");

        frame.render_stateful_widget(
            list,
            area,
            &mut ListState::default().with_selected(Some(self.selected_index - start_idx)),
        );
    }

    fn render_footer(&self, frame: &mut Frame, colors: &ColorScheme, area: Rect) {
        // Show help
        let help = if let Some(bot) = self.selected_bot() {
            format!(
                "Selected: {} - Press Enter to override, s to toggle category",
                bot.name
            )
        } else {
            String::from("Press s to toggle category status")
        };

        let para = Paragraph::new(help)
            .style(colors.inactive())
            .alignment(Alignment::Center);
        frame.render_widget(para, area);
    }
}
