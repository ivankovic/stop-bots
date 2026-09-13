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

//! The Help screen: a static reference of key bindings. No state, no key
//! handling beyond what `App` already does to open/close it.

use ratatui::{
    layout::Rect,
    text::Line,
    widgets::{Block, Paragraph},
    Frame,
};

/// The most lines [`render`] may emit.
///
/// This renders as a plain `Paragraph` with no scrolling, so anything past
/// the screen area is silently cut off — and what goes first is the
/// "Global" section at the bottom, including how to close this very
/// screen. The budget is the body area of the smallest terminal the pty
/// tests drive (32 rows, less a 2-row header, a 1-row footer and the
/// block's two borders).
///
/// It is a constant with a test behind it because the comment that used to
/// say this was not enough: adding the Dynamic Protection inspect key
/// pushed the last line off, and the only thing that noticed was an
/// end-to-end pty test failing 15 seconds later with a timeout. Adding an
/// entry here still means merging or dropping another — now you find that
/// out in milliseconds.
const MAX_LINES: usize = 27;

pub fn render(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Navigation"),
        Line::from("  Up/Down, j/k       move selection (on the Dashboard it flows across all three panels)"),
        Line::from("  Enter, Space       open/change the focused setting"),
        Line::from("  Tab, Shift+Tab     switch screen (also Left/Right, h/l) — or panel, where a screen has two"),
        Line::from("  d / b / s / p      jump to Dashboard / Bot settings / Site settings / Dynamic Protection"),
        Line::from(""),
        Line::from("Dashboard"),
        Line::from("  m / f              switch geo mode (Blocklist / Allowlist) / render the firewall script"),
        Line::from("  u / a              download every list / apply both planes (NGINX, then the firewall)"),
        Line::from("  w                  put this console behind NGINX (a subdomain, or a path on a site)"),
        Line::from(""),
        Line::from("Bot settings"),
        Line::from("  /                  search the Bot details panel; type to filter, Enter opens, Esc stops"),
        Line::from(""),
        Line::from("Site settings"),
        Line::from("  Tab                switch between the NGINX settings panel and the site list"),
        Line::from("  r / a / A          scan for sites / apply this site / apply every site"),
        Line::from("  Enter, Space       open the selected site's category & bot overrides"),
        Line::from("  (inside a site)    / searches its bots; Enter opens a setting; Esc backs out"),
        Line::from(""),
        Line::from("Dynamic Protection"),
        Line::from("  Enter              block the selected NOT BLOCKED row, or unblock a BLOCKED one"),
        Line::from("  i / f              inspect the selected SSH address / cycle the display filter"),
        Line::from(""),
        Line::from("Global"),
        Line::from("  q, Esc             quit (from a screen: go back; from a popup: close it)"),
        Line::from("  c / ?              toggle light/dark theme / toggle this help screen"),
    ];
    debug_assert!(lines.len() <= MAX_LINES);
    let paragraph = Paragraph::new(lines).block(Block::bordered().title("Help"));
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// The whole point of [`MAX_LINES`]: the last line tells you how to
    /// close this screen, and losing it is invisible from inside the code.
    #[test]
    fn every_help_line_fits_the_smallest_terminal_the_tests_drive() {
        // The body area the app hands this screen at the pty tests' 32x100:
        // 32 rows less a 2-row header and a 1-row footer.
        let mut terminal = Terminal::new(TestBackend::new(100, 29)).unwrap();
        terminal.draw(|frame| render(frame, frame.area())).unwrap();

        let content: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();

        assert!(
            content.contains("toggle this help screen"),
            "the last help line was cut off:\n{content}"
        );
    }
}
