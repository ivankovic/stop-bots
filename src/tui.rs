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

//! The view: draws the outer chrome (tab bar, footer) and delegates the body
//! area to whichever screen is active. Screens themselves live under
//! `src/tui/` — each one encapsulates its own state, key handling and
//! rendering.

pub mod bot_settings;
pub mod dashboard;
pub mod dynamic_protection;
pub mod help;
pub mod site_detail;
pub mod site_settings;

use crate::app::App;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Style, Stylize},
    widgets::{Block, Paragraph, Tabs},
    Frame,
};

/// Light/dark accent theme. Body text always uses the terminal's default
/// foreground/background (see AGENTS.md) — this only picks an accent color
/// with enough contrast for highlights, titles and borders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

impl Theme {
    /// Best-effort detection from `COLORFGBG`, which some terminals/multiplexers
    /// set to "fg;bg" color-index pairs. There isn't always enough information
    /// to get this right (see README) — hence the manual 'c' toggle.
    pub fn detect() -> Self {
        if let Ok(colorfgbg) = std::env::var("COLORFGBG") {
            if let Some(bg) = colorfgbg.split(';').next_back() {
                if let Ok(bg) = bg.parse::<u8>() {
                    // Background color indices 7 (white) and 15 (bright white)
                    // are the common "light terminal" signal.
                    return if bg == 7 || bg == 15 {
                        Theme::Light
                    } else {
                        Theme::Dark
                    };
                }
            }
        }
        Theme::default()
    }

    pub fn toggle(self) -> Self {
        match self {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Dark,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }

    /// The accent color used for titles, selections and active tabs.
    pub fn accent(self) -> ratatui::style::Color {
        match self {
            Theme::Dark => ratatui::style::Color::Cyan,
            Theme::Light => ratatui::style::Color::Blue,
        }
    }
}

/// The screens the TUI can show. Cycled with Tab/Shift+Tab, Left/Right, or
/// their vim `h`/`l` aliases (see `App::handle_key_event`'s global fallback
/// match — all four only fire once the active screen itself has ignored the
/// key), jumped to directly with `d`/`b`/`s`/`p`, with Help reachable via
/// `?` from anywhere. Dynamic Protection itself uses Tab/Shift+Tab
/// internally (to switch between its SSH/User Agent panels — see
/// `crate::tui::dynamic_protection`), so it consumes those two keys rather
/// than cycling screens while it's active; Left/Right/`h`/`l`/`d`/`b`/`s`/
/// `p`/Esc still work as the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Screen {
    #[default]
    Dashboard,
    BotSettings,
    SiteSettings,
    DynamicProtection,
    Help,
}

impl Screen {
    pub const TABS: [Screen; 4] = [
        Screen::Dashboard,
        Screen::BotSettings,
        Screen::SiteSettings,
        Screen::DynamicProtection,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::BotSettings => "Bot settings",
            Screen::SiteSettings => "Site settings",
            Screen::DynamicProtection => "Dynamic Protection",
            Screen::Help => "Help",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Screen::Dashboard => Screen::BotSettings,
            Screen::BotSettings => Screen::SiteSettings,
            Screen::SiteSettings => Screen::DynamicProtection,
            Screen::DynamicProtection | Screen::Help => Screen::Dashboard,
        }
    }

    pub fn previous(self) -> Self {
        match self {
            Screen::Dashboard => Screen::DynamicProtection,
            Screen::BotSettings => Screen::Dashboard,
            Screen::SiteSettings => Screen::BotSettings,
            Screen::DynamicProtection => Screen::SiteSettings,
            Screen::Help => Screen::Dashboard,
        }
    }
}

/// What a screen's key handler did with a key press, so [`App`] knows
/// whether to fall back to global key handling (quit, theme toggle, screen
/// switching, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOutcome {
    /// The key was handled (e.g. list navigation) with no change other
    /// screens need to know about.
    Consumed,
    /// The key changed something in the database (e.g. confirming a popup):
    /// every screen should reload before the next render, since e.g. the
    /// Dashboard's category-default summary may now be stale.
    Mutated,
    /// The screen wants to back out to the Dashboard (e.g. Escape with no
    /// popup open).
    Back,
    /// Not relevant to this screen; let the caller handle it.
    Ignored,
    /// The Bot settings screen confirmed updating a bot-list source,
    /// identified by its stable id (e.g. `"well-known-bots"`, not its
    /// display name) so `App` can resolve which `botlist::SourceKind` to
    /// fetch and parse with. `App` owns the event loop, so it's the one
    /// that spawns the fetch.
    UpdateSource(String),
    /// The Dashboard's "add a country" popup confirmed a validated,
    /// not-yet-fetched two-letter country code. `App` spawns a background
    /// fetch of that country's IP ranges and, once it succeeds, adds it to
    /// the geo selection — see `App::start_country_select`. A country whose
    /// ranges are already fetched never produces this: the Dashboard adds
    /// it directly and returns `Mutated` instead, since no network
    /// round-trip is needed.
    SelectCountry(String),
    /// The Dashboard enabled a reputation/cloud-provider CIDR feed that
    /// has never been fetched, identified by its stable id. `App` spawns
    /// the download and stores the result — same shape as
    /// [`Self::SelectCountry`], and for the same reason: the screen's key
    /// handler must stay free of network I/O so its tests stay fast and
    /// offline. Enabling an already-fetched feed returns `Mutated`
    /// instead, since nothing needs downloading.
    FetchReputationSource(String),
    /// The Dashboard's firewall render action was triggered. Carries the
    /// selected backend and output path for `App` to call the render
    /// function (see `App::render_firewall`). `apply` is the render popup's
    /// "apply after writing" toggle (Space, see `Popup::RenderFirewall`) —
    /// when set, `App` also runs `firewall::apply_script` once the write
    /// succeeds, not just writes the script for the admin to apply by hand.
    RenderFirewall {
        backend: crate::firewall::FirewallBackend,
        out_path: String,
        force: bool,
        apply: bool,
    },
    /// Site settings wrote at least one changed NGINX config file on disk
    /// (`apply now` / `apply all`). Reloading is a real side effect (shells
    /// out to `nginx -t` and `systemctl reload nginx`), so — same reasoning
    /// as `RenderFirewall`/`UpdateSource` — it stays with `App` rather than
    /// running inline in the screen's own `handle_key`, keeping that code
    /// free of real process execution so its tests stay fast and
    /// deterministic (see `crate::nginx::reload`).
    ReloadNginx,
}

/// Braille "dots" spinner frames, in rotation order.
pub const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// The spinner frame to draw right now, picked from wall-clock time rather
/// than from a counter each screen would have to own and advance. The draw
/// loop redraws on every `Event::Tick` (30fps), so reading the clock at
/// render time is all the animation any of them needs — and every spinner
/// on screen turns in step, which a per-widget counter would not guarantee.
pub fn spinner_frame() -> char {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    SPINNER_FRAMES[(millis / 80) as usize % SPINNER_FRAMES.len()]
}

/// Returns a `Rect` of exactly `width` x `height` cells, centered within
/// `area` (clamped so it never exceeds `area`'s bounds). Used to place
/// popups, which need a specific size in rows/columns rather than a
/// proportion of however big the terminal happens to be.
pub fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width - width) / 2;
    let y = area.y + (area.height - height) / 2;
    Rect::new(x, y, width, height)
}

/// Renders the whole UI: tab bar, the active screen's body, and the footer.
pub fn render(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(app, frame, header);

    match app.screen {
        Screen::Dashboard => {
            app.dashboard
                .render(frame, body, app.theme, &app.message, &app.jobs_in_flight)
        }
        Screen::BotSettings => app.bot_settings.render(frame, body, app.theme),
        Screen::SiteSettings => app.site_settings.render(frame, body, app.theme),
        Screen::DynamicProtection => {
            app.dynamic_protection
                .render(frame, body, app.theme, &app.jobs_in_flight)
        }
        Screen::Help => help::render(frame, body),
    }

    render_footer(app, frame, footer);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let titles = Screen::TABS.iter().map(|s| s.title());
    let selected = Screen::TABS.iter().position(|&s| s == app.screen);
    let tabs = Tabs::new(titles)
        .select(selected)
        .highlight_style(Style::new().fg(app.theme.accent()).bold())
        .block(Block::new().title("stop-bots".bold()));
    frame.render_widget(tabs, area);
}

fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let hint = match app.screen {
        Screen::Help => "Esc/q/? back to where you were".to_string(),
        _ => format!(
            "q quit  Tab/Shift+Tab/\u{2190}\u{2192} switch  d/b/s/p jump  ? help  c theme ({})",
            app.theme.label()
        ),
    };
    frame.render_widget(Paragraph::new(hint).dim(), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_toggle_round_trips() {
        assert_eq!(Theme::Dark.toggle(), Theme::Light);
        assert_eq!(Theme::Light.toggle(), Theme::Dark);
        assert_eq!(Theme::Dark.toggle().toggle(), Theme::Dark);
    }

    #[test]
    fn theme_detect_falls_back_to_dark_without_a_signal() {
        // Safe to clear: this test doesn't run concurrently with anything
        // else that reads COLORFGBG, and we restore it isn't set afterward.
        unsafe { std::env::remove_var("COLORFGBG") };
        assert_eq!(Theme::detect(), Theme::Dark);
    }

    #[test]
    fn theme_detect_reads_colorfgbg_background_index() {
        unsafe { std::env::set_var("COLORFGBG", "15;0") };
        assert_eq!(Theme::detect(), Theme::Dark);
        unsafe { std::env::set_var("COLORFGBG", "0;15") };
        assert_eq!(Theme::detect(), Theme::Light);
        unsafe { std::env::remove_var("COLORFGBG") };
    }

    #[test]
    fn screen_next_cycles_through_every_tab_back_to_dashboard() {
        assert_eq!(Screen::Dashboard.next(), Screen::BotSettings);
        assert_eq!(Screen::BotSettings.next(), Screen::SiteSettings);
        assert_eq!(Screen::SiteSettings.next(), Screen::DynamicProtection);
        assert_eq!(Screen::DynamicProtection.next(), Screen::Dashboard);
    }

    #[test]
    fn screen_previous_is_the_inverse_of_next_for_every_tab() {
        for screen in Screen::TABS {
            assert_eq!(screen.next().previous(), screen);
        }
    }

    #[test]
    fn centered_rect_centers_a_fixed_size_box() {
        let area = Rect::new(0, 0, 100, 40);
        assert_eq!(centered_rect(20, 4, area), Rect::new(40, 18, 20, 4));
    }

    #[test]
    fn centered_rect_clamps_to_area_when_larger_than_it() {
        let area = Rect::new(0, 0, 50, 20);
        assert_eq!(centered_rect(200, 100, area), Rect::new(0, 0, 50, 20));
    }

    #[test]
    fn centered_rect_respects_a_nonzero_area_origin() {
        let area = Rect::new(10, 5, 20, 10);
        assert_eq!(centered_rect(10, 4, area), Rect::new(15, 8, 10, 4));
    }
}
