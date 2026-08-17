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

pub fn render(frame: &mut Frame, area: Rect) {
    // Kept to 26 lines on purpose: this renders as a plain `Paragraph`
    // with no scrolling, so anything past the screen area is silently cut
    // off — and the lines most likely to be lost are the "Global" ones at
    // the bottom, including how to close this very screen. Adding an entry
    // here means merging or dropping another.
    let lines = vec![
        Line::from("Navigation"),
        Line::from("  Up/Down, j/k       move selection"),
        Line::from("  Enter, Space       open/change the focused setting"),
        Line::from("  Tab, Shift+Tab     switch screen (also Left/Right, h/l) — or panel, where a screen has two"),
        Line::from("  d / b / s / p      jump to Dashboard / Bot settings / Site settings / Dynamic Protection"),
        Line::from(""),
        Line::from("Dashboard"),
        Line::from("  m                  switch geo mode (Blocklist / Allowlist)"),
        Line::from("  f                  render the firewall script (optionally applying it)"),
        Line::from("  (focus)            Up/Down flows: System-wide settings -> Geo-blocking -> Automatic blocking"),
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
        Line::from("  f                  cycle the display filter: all / not blocked only / blocked only"),
        Line::from(""),
        Line::from("Global"),
        Line::from("  q, Esc             quit (from a screen: go back; from a popup: close it)"),
        Line::from("  c / ?              toggle light/dark theme / toggle this help screen"),
    ];
    let paragraph = Paragraph::new(lines).block(Block::bordered().title("Help"));
    frame.render_widget(paragraph, area);
}
