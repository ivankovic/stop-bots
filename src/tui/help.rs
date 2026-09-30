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

/// Every line of the reference, in order. A section starts at column 0;
/// a key sits in the columns before the description.
const LINES: [&str; MAX_LINES] = [
    "Navigation",
    "  1-5, d b f n x     jump to a screen (Left/Right and h/l step through them)",
    "  :                  command palette: every action here by name, fuzzy-matched",
    "  Tab, Shift+Tab     next / previous panel on this screen",
    "  Up/Down, j/k       move selection (it also flows from one panel into the next)",
    "  Enter              open, change or download the selected item;  Space toggles an on/off row",
    "",
    "Dashboard",
    "  m / F              switch geo mode (Blocklist / Allowlist) / write the firewall script",
    "  u / a              download every list / apply both planes (NGINX, then the firewall)",
    "  w                  put this console behind NGINX (a subdomain, or a path on a site)",
    "",
    "Bot settings         /  searches the bots; type to filter, Enter opens, Esc leaves the box",
    "Blocks               every rule and why: f source, / address, Enter unblock, U all from source",
    "",
    "Firewall",
    "  Enter / T          block or unblock the selected row / trust it, never to be blocked",
    "  i / y / R          inspect the selected row / copy it / re-read the log",
    "  f                  cycle the display filter (all / not blocked / blocked)",
    "",
    "NGINX",
    "  r / a / A          scan for sites / apply this site / apply every site",
    "  Enter, /           open a site's category, request-rule and bot overrides; / searches bots",
    "",
    "Global",
    "  q Esc / t / ?      quit, go back or close a popup / light/dark theme / toggle this help screen",
];

pub fn render(frame: &mut Frame, area: Rect, theme: crate::tui::Theme) {
    let lines: Vec<Line> = LINES.iter().map(|line| Line::from(*line)).collect();
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

    /// The keys the reference lists for `section`, and for the Global
    /// section every screen shares. With `navigation`, the screen-jump and
    /// movement keys as well.
    fn keys_in(section: &str, navigation: bool) -> Vec<String> {
        let mut keys = Vec::new();
        let mut current = "";
        for line in LINES {
            if !line.starts_with(' ') {
                current = line.split("  ").next().unwrap_or_default().trim();
                // A one-line section carries its key after the title.
                if let Some(rest) = line.get(KEY_COLUMNS..) {
                    if current == section {
                        keys.extend(split_keys(rest.split("  ").next().unwrap_or_default()));
                    }
                }
                continue;
            }
            if current == section || current == "Global" || (navigation && current == "Navigation")
            {
                keys.extend(split_keys(line.get(2..KEY_COLUMNS).unwrap_or(line)));
            }
        }
        keys
    }

    /// Where the description starts on a help line.
    const KEY_COLUMNS: usize = 21;

    /// "Up/Down, j/k" is four keys and "m / F" two. A "/" of its own is a
    /// separator between two keys, and the `/` key itself where it starts
    /// the column or follows a comma: "/" alone, or "Enter, /".
    fn split_keys(column: &str) -> Vec<String> {
        let mut keys = Vec::new();
        let mut after_separator = true;
        for token in column.split_whitespace() {
            if token == "/" {
                if after_separator {
                    keys.push(token.to_string());
                }
                after_separator = false;
                continue;
            }
            after_separator = token.ends_with(',');
            keys.extend(
                token
                    .trim_end_matches(',')
                    .split(['/', ','])
                    .filter(|key| !key.is_empty())
                    .map(str::to_string),
            );
        }
        keys
    }

    /// The keys a message names: `(F)`, `(a/A)` — the key that does this,
    /// here — and `press n, then r` — which may be a jump to another screen.
    /// Only on lines holding a string literal, and only outside tests.
    fn named_keys(source: &str) -> Vec<(String, bool)> {
        let code = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut named = Vec::new();
        for line in code.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !line.contains('"') {
                continue;
            }
            let mut rest = line;
            while let Some(at) = rest.find(" (") {
                rest = &rest[at + 2..];
                if let Some(end) = rest.find(')') {
                    let inner = &rest[..end];
                    if !inner.is_empty()
                        && inner.len() <= 5
                        && inner.chars().all(|c| c.is_ascii_alphabetic() || c == '/')
                    {
                        named.extend(inner.split('/').map(|k| (k.to_string(), false)));
                    }
                }
            }
            for word in ["press ", "Press "] {
                let mut rest = line;
                while let Some(at) = rest.find(word) {
                    rest = &rest[at + word.len()..];
                    for part in rest.split(", then ").take(2) {
                        let key: String = part
                            .chars()
                            .take_while(|c| {
                                !c.is_whitespace() && !matches!(c, ',' | '.' | ')' | '"')
                            })
                            .collect();
                        if !key.is_empty() {
                            named.push((key, true));
                        }
                    }
                }
            }
        }
        named
    }

    /// A message that says "render the firewall (f)" on a screen where the
    /// key is `F` sends someone to the wrong key — `f` there jumps to the
    /// Firewall screen. So every key a screen's messages name has to be one
    /// the reference lists for that screen: the one place a person would
    /// check, and the one this test can read.
    #[test]
    fn every_key_a_message_names_is_in_the_help_for_its_screen() {
        let sources = [
            ("app.rs", include_str!("../app.rs"), "Dashboard"),
            (
                "tui/dashboard.rs",
                include_str!("dashboard.rs"),
                "Dashboard",
            ),
            (
                "tui/bot_settings.rs",
                include_str!("bot_settings.rs"),
                "Bot settings",
            ),
            ("tui/firewall.rs", include_str!("firewall.rs"), "Firewall"),
            ("tui/nginx.rs", include_str!("nginx.rs"), "NGINX"),
            (
                "tui/site_detail.rs",
                include_str!("site_detail.rs"),
                "NGINX",
            ),
        ];
        let mut wrong = Vec::new();
        let mut checked = 0;
        for (file, source, section) in sources {
            for (key, may_jump) in named_keys(source) {
                checked += 1;
                if !keys_in(section, may_jump).contains(&key) {
                    wrong.push(format!("{file}: \"{key}\" is not a {section} key"));
                }
            }
        }
        assert!(checked > 5, "the scan found almost nothing: {checked}");
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn the_key_column_parses_as_the_keys_it_lists() {
        let dashboard = keys_in("Dashboard", false);
        for key in ["m", "F", "u", "a", "w", "q", "Esc", "?"] {
            assert!(dashboard.contains(&key.to_string()), "{key}: {dashboard:?}");
        }
        assert!(!dashboard.contains(&"f".to_string()), "{dashboard:?}");
        assert!(keys_in("Bot settings", false).contains(&"/".to_string()));
        assert!(keys_in("NGINX", false).contains(&"/".to_string()));
        assert!(
            !keys_in("Firewall", false).contains(&"/".to_string()),
            "the separator in \"Enter / T\" is not a key"
        );
    }
}
