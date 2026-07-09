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
    let lines = vec![
        Line::from("Navigation"),
        Line::from("  Up/Down, j/k       move selection"),
        Line::from("  Enter, Space       open a setting"),
        Line::from("  Tab, Shift+Tab     switch screen"),
        Line::from("  d / b / s          jump to Dashboard / Bot settings / Site settings"),
        Line::from(""),
        Line::from("Bot settings"),
        Line::from("  /                  search the Bot details panel by name"),
        Line::from("  (while searching)  type to filter; Enter opens a match; Esc stops searching"),
        Line::from(""),
        Line::from("Site settings"),
        Line::from("  r                  scan for NGINX sites now (Cancel/Scan now popup)"),
        Line::from("  a                  apply the selected site's rule to its config file now"),
        Line::from("  A                  apply every known site's rule to its own config file"),
        Line::from("  Enter, Space       open the selected site's category/bot overrides"),
        Line::from(
            "  (inside a site)    / searches its bots; Enter opens a setting; Esc backs out",
        ),
        Line::from(""),
        Line::from("Global"),
        Line::from("  q, Esc             quit (from a screen: go back; from a popup: close it)"),
        Line::from("  c                  toggle light/dark theme"),
        Line::from("  ?                  toggle this help screen"),
    ];
    let paragraph = Paragraph::new(lines).block(Block::bordered().title("Help"));
    frame.render_widget(paragraph, area);
}
