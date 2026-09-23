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

use ratatui::{layout::Rect, text::Line, widgets::Paragraph, Frame};

/// The most lines [`render`] may emit.
///
/// This renders as a plain `Paragraph` with no scrolling, so anything past
/// the screen area is silently cut off — and what goes first is the
/// "Global" section at the bottom, including how to close this very
/// screen. The budget is the body area of the smallest terminal the pty
/// tests drive (32 rows, less a 3-row header, a 1-row footer and the
/// block's two borders).
///
/// It is a constant with a test behind it because the comment that used to
/// say this was not enough: adding the Firewall screen's inspect key
/// pushed the last line off, and the only thing that noticed was an
/// end-to-end pty test failing 15 seconds later with a timeout. Adding an
/// entry here still means merging or dropping another — now you find that
/// out in milliseconds.
const MAX_LINES: usize = 26;

pub fn render(frame: &mut Frame, area: Rect, theme: crate::tui::Theme) {
    let lines = vec![
        Line::from("Navigation"),
        Line::from("  1 2 3 4, d b f n   jump to a screen (Left/Right and h/l step through them)"),
        Line::from("  :                  command palette: every action here by name, fuzzy-matched"),
        Line::from("  Tab, Shift+Tab     next / previous panel on this screen"),
        Line::from("  Up/Down, j/k       move selection (it also flows from one panel into the next)"),
        Line::from("  Enter              open or change the selected item;  Space toggles an on/off row"),
        Line::from(""),
        Line::from("Dashboard"),
        Line::from("  m / F              switch geo mode (Blocklist / Allowlist) / write the firewall script"),
        Line::from("  u / a              download every list / apply both planes (NGINX, then the firewall)"),
        Line::from("  w                  put this console behind NGINX (a subdomain, or a path on a site)"),
        Line::from(""),
        Line::from("Bot settings         /  searches the bots; type to filter, Enter opens, Esc leaves the box"),
        Line::from(""),
        Line::from("Firewall"),
        Line::from("  Enter / T          block or unblock the selected row / trust it, never to be blocked"),
        Line::from("  i / y / R          inspect the selected row / copy it / re-read the log"),
        Line::from("  f                  cycle the display filter (all / not blocked / blocked)"),
        Line::from(""),
        Line::from("NGINX"),
        Line::from("  r / a / A          scan for sites / apply this site / apply every site"),
        Line::from("  Enter              open the selected site's category, request-rule and bot overrides"),
        Line::from(""),
        Line::from("Global"),
        Line::from("  q, Esc             quit (from a screen: go back; from a popup: close it)"),
        Line::from("  t / ?              toggle light/dark theme / toggle this help screen"),
    ];
    debug_assert!(lines.len() <= MAX_LINES);
    let paragraph = Paragraph::new(lines).block(crate::tui::panel("Help", true, theme));
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
        // 32 rows less a 3-row header and a 1-row footer.
        let mut terminal = Terminal::new(TestBackend::new(100, 28)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), crate::tui::Theme::Dark))
            .unwrap();

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
