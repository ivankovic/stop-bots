//! UI utilities and rendering helpers for the TUI.
//!
//! This module provides helper functions and types for rendering the UI.

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table};
use unicode_width::UnicodeWidthChar;
use std::time::Duration;

/// Helper trait for creating styled spans.
pub trait StyledSpan {
    /// Creates a styled span with the given style.
    fn styled_span(self, style: Style) -> Span<'static>;
}

impl StyledSpan for &str {
    fn styled_span(self, style: Style) -> Span<'static> {
        Span::styled(self.to_string(), style)
    }
}

impl StyledSpan for String {
    fn styled_span(self, style: Style) -> Span<'static> {
        Span::styled(self, style)
    }
}

/// Creates a block with a title and borders.
pub fn titled_block<'a>(title: &'a str, style: Style) -> Block<'a> {
    Block::default()
        .title(Line::from(title).style(style))
        .borders(Borders::ALL)
}

/// Creates a paragraph with centered text.
pub fn centered_paragraph<'a>(text: &'a str, style: Style) -> Paragraph<'a> {
    Paragraph::new(Line::from(text).style(style)).alignment(Alignment::Center)
}

/// Creates a list of items.
pub fn create_list<'a>(items: Vec<Line<'a>>, _selected: Option<usize>) -> List<'a> {
    List::new(
        items
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>(),
    )
}

/// Creates a gauge widget with the given ratio and style.
pub fn gauge<'a>(ratio: f64, label: &'a str, style: Style) -> Gauge<'a> {
    Gauge::default()
        .ratio(ratio.clamp(0.0, 1.0))
        .label(Span::styled(label, style))
}

/// Creates a table widget with headers.
pub fn table<'a>(
    headers: Vec<&'a str>,
    rows: Vec<Vec<&'a str>>,
    widths: &[Constraint],
) -> Table<'a> {
    let header_row = Row::new(
        headers
            .into_iter()
            .map(|h| Cell::from(h).style(Style::new().bold()))
            .collect::<Vec<_>>(),
    );

    let table_rows: Vec<Row<'a>> = rows
        .into_iter()
        .map(|cells| Row::new(cells.into_iter().map(Cell::from).collect::<Vec<_>>()))
        .collect();

    Table::new(table_rows, widths)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL))
}

/// Formats a duration for display.
pub fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        format!("{}m {}s", total_secs / 60, total_secs % 60)
    } else if total_secs < 86400 {
        format!(
            "{}h {}m",
            total_secs / 3600,
            (total_secs % 3600) / 60
        )
    } else {
        format!("{}d {}h", total_secs / 86400, (total_secs % 86400) / 3600)
    }
}

/// Formats a timestamp for display.
pub fn format_timestamp(timestamp: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;

    let duration = timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let secs = duration.as_secs();

    // Simple date formatting
    // This could be enhanced with chrono or similar if needed
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;
    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;

    format!(
        "{}d {:02}:{:02}:{:02}",
        days_since_epoch, hours, minutes, seconds
    )
}

/// Creates a centered rectangle.
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Truncates text to fit in the given width.
pub fn truncate_text(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        text.to_string()
    } else {
        let mut result = String::new();
        let mut char_count = 0;
        for c in chars {
            let c_width = c.width().unwrap_or(1);
            if char_count + c_width > width - 2 {
                // Leave room for ".."
                break;
            }
            result.push(c);
            char_count += c_width;
        }
        format!("{}..", result)
    }
}

/// Pads text to the given width.
pub fn pad_text(text: &str, width: usize, alignment: Alignment) -> String {
    let text_width: usize = text.chars().map(|c| c.width().unwrap_or(1)).sum();
    let padding = width.saturating_sub(text_width);

    match alignment {
        Alignment::Left => {
            format!("{}{}", text, " ".repeat(padding))
        }
        Alignment::Right => {
            format!("{}{}", " ".repeat(padding), text)
        }
        Alignment::Center => {
            let left_pad = padding / 2;
            let right_pad = padding - left_pad;
            format!("{}{}{}", " ".repeat(left_pad), text, " ".repeat(right_pad))
        }
    }
}


