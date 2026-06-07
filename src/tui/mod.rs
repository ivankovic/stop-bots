//! TUI module for Stop Bots.
//!
//! This module provides the Terminal User Interface for the stop-bots application,
//! built using Ratatui and Crossterm.

pub mod app;
pub mod components;
pub mod screens;
pub mod ui;
use ratatui::prelude::*;

/// Theme for the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    /// Light theme for terminals with light backgrounds
    Light,
    /// Dark theme for terminals with dark backgrounds
    Dark,
}

impl Theme {
    /// Returns the color scheme for this theme.
    pub fn color_scheme(&self) -> ColorScheme {
        match self {
            Theme::Light => ColorScheme::light(),
            Theme::Dark => ColorScheme::dark(),
        }
    }

    /// Toggles between light and dark theme.
    pub fn toggle(&self) -> Self {
        match self {
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Light,
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        // Try to detect the terminal theme automatically
        detect_terminal_theme()
    }
}

/// Attempts to detect whether the terminal has a light or dark background.
/// Returns Theme::Light if a light theme is detected, otherwise Theme::Dark.
fn detect_terminal_theme() -> Theme {
    // Check for common environment variables that indicate a light theme
    
    // Try to detect from standard terminal color environment variables
    // Note: Detection is best-effort; users can always toggle with 'c' key
    
    // Check if TERM_PROGRAM or similar indicates a light terminal
    if let Ok(term_program) = std::env::var("TERM_PROGRAM") {
        if term_program.to_lowercase().contains("light") {
            return Theme::Light;
        }
    }
    
    // Many terminal emulators and IDEs set this
    if let Ok(scheme) = std::env::var("COLOR_SCHEME") {
        if scheme.to_lowercase().contains("light") {
            return Theme::Light;
        }
    }
    
    // VS Code and other editors use this
    if let Ok(theme) = std::env::var("VSCODE_DEFAULT_COLOR_THEME") {
        if theme.to_lowercase().contains("light") {
            return Theme::Light;
        }
    }
    
    // Alacritty, WezTerm, etc. may have their own variables
    if let Ok(alacritty_colors) = std::env::var("ALACRITTY_COLORS") {
        if alacritty_colors.to_lowercase().contains("light") {
            return Theme::Light;
        }
    }
    
    // Check TERM for light terminal variants
    if let Ok(term) = std::env::var("TERM") {
        let term_lower = term.to_lowercase();
        if term_lower.contains("light") 
            || term_lower.contains("bright")
            || term_lower == "xterm-256color-light"
        {
            return Theme::Light;
        }
    }
    
    // Check for Windows Terminal settings
    if let Ok(theme) = std::env::var("WT_PROFILE_ID") {
        if theme.to_lowercase().contains("light") {
            return Theme::Light;
        }
    }
    
    // Default to light theme for better visibility
    // Users can always toggle with 'c' key
    Theme::Light
}

/// Color scheme for the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorScheme {
    pub background: Color,
    pub foreground: Color,
    pub primary: Color,
    pub secondary: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub border: Color,
    pub title: Color,
    pub selected: Color,
    pub highlighted: Color,
    pub inactive: Color,
}

impl ColorScheme {
    /// Light color scheme (for light terminal backgrounds).
    /// Uses dark colors on light background for readability.
    pub fn light() -> Self {
        Self {
            background: Color::Reset,  // Use terminal's default background (light)
            foreground: Color::Black,
            primary: Color::Indexed(4),  // Blue (works on light bg)
            secondary: Color::Indexed(8), // Dark gray
            success: Color::Indexed(2),  // Green (works on light bg)
            warning: Color::Indexed(11), // Bright yellow
            error: Color::Indexed(1),   // Red (works on light bg)
            border: Color::Indexed(8),  // Dark gray
            title: Color::Indexed(6),   // Cyan/Dark cyan (works on light bg)
            selected: Color::Indexed(15), // White
            highlighted: Color::Indexed(11), // Bright yellow
            inactive: Color::Indexed(8), // Dark gray
        }
    }

    /// Dark color scheme (for dark terminal backgrounds).
    /// Uses light/bright colors on dark background for readability.
    pub fn dark() -> Self {
        Self {
            background: Color::Reset,  // Use terminal's default background (dark)
            foreground: Color::White,
            primary: Color::Indexed(6),  // Cyan (works on dark bg)
            secondary: Color::Indexed(7), // Light gray
            success: Color::Indexed(10), // Bright green
            warning: Color::Indexed(11), // Bright yellow
            error: Color::Indexed(9),   // Bright red
            border: Color::Indexed(8),  // Dark gray
            title: Color::Indexed(14),  // Light cyan
            selected: Color::Indexed(12), // Light blue
            highlighted: Color::Indexed(11), // Bright yellow
            inactive: Color::Indexed(8), // Dark gray
        }
    }

    /// Returns a style for normal text.
    pub fn text(&self) -> Style {
        Style::new().fg(self.foreground).bg(self.background)
    }

    /// Returns a style for title text.
    pub fn title(&self) -> Style {
        Style::new()
            .fg(self.title)
            .bg(self.background)
            .bold()
    }

    /// Returns a style for selected items.
    pub fn selected(&self) -> Style {
        Style::new()
            .fg(self.selected)
            .bg(self.background)
            .bold()
    }

    /// Returns a style for success messages.
    pub fn success(&self) -> Style {
        Style::new().fg(self.success)
    }

    /// Returns a style for warning messages.
    pub fn warning(&self) -> Style {
        Style::new().fg(self.warning)
    }

    /// Returns a style for error messages.
    pub fn error(&self) -> Style {
        Style::new().fg(self.error).bold()
    }

    /// Returns a style for borders.
    pub fn border(&self) -> Style {
        Style::new().fg(self.border)
    }

    /// Returns a style for inactive/disabled items.
    pub fn inactive(&self) -> Style {
        Style::new().fg(self.inactive)
    }

    /// Returns a style for primary items.
    pub fn primary(&self) -> Style {
        Style::new().fg(self.primary)
    }

    /// Returns a style for secondary items.
    pub fn secondary(&self) -> Style {
        Style::new().fg(self.secondary)
    }
}

/// Event types for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiEvent {
    /// A key was pressed.
    Key(crossterm::event::KeyEvent),
    /// The terminal was resized.
    Resize(u16, u16),
    /// A tick event (for animations, etc.).
    Tick,
    /// Quit the application.
    Quit,
    /// Toggle theme.
    ToggleTheme,
    /// Refresh data.
    Refresh,
    /// Navigate up.
    Up,
    /// Navigate down.
    Down,
    /// Navigate left.
    Left,
    /// Navigate right.
    Right,
    /// Select current item.
    Select,
    /// Go back.
    Back,
    /// Open context menu.
    ContextMenu,
    /// Confirm action (Yes).
    Confirm,
    /// Cancel action (No).
    Cancel,
}

/// Converts a crossterm key event to a TuiEvent.
pub fn key_event_to_tui_event(key_event: crossterm::event::KeyEvent) -> Option<TuiEvent> {
    use crossterm::event::KeyCode;

    match key_event.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc if key_event.modifiers.is_empty() => {
            Some(TuiEvent::Quit)
        }
        // Theme toggle
        KeyCode::Char('c') | KeyCode::Char('C') => Some(TuiEvent::ToggleTheme),
        // Refresh
        KeyCode::Char('r') | KeyCode::Char('R') => Some(TuiEvent::Refresh),
        // Navigation
        KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => Some(TuiEvent::Up),
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => Some(TuiEvent::Down),
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => Some(TuiEvent::Left),
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => Some(TuiEvent::Right),
        // Select
        KeyCode::Enter | KeyCode::Char(' ') => Some(TuiEvent::Select),
        // Back
        KeyCode::Backspace | KeyCode::Char('b') | KeyCode::Char('B') => Some(TuiEvent::Back),
        // Confirm (Yes)
        KeyCode::Char('y') | KeyCode::Char('Y') => Some(TuiEvent::Confirm),
        // Cancel (No)
        KeyCode::Char('n') | KeyCode::Char('N') => Some(TuiEvent::Cancel),
        // Context menu
        KeyCode::Char('m') | KeyCode::Char('M') => Some(TuiEvent::ContextMenu),
        _ => None,
    }
}
