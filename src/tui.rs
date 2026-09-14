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
pub mod palette;
pub mod site_detail;
pub mod site_settings;

use crate::app::App;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, HighlightSpacing, List, Paragraph},
    Frame,
};

/// Light/dark theme. Body text always uses the terminal's default
/// foreground/background (see AGENTS.md) — the theme only picks the
/// handful of role colours (accent, live, dim, selection) the chrome is
/// drawn with. "Night Grid" is the dark one, "Greenhouse" the light one;
/// the web console defines the same roles in `style.css`.
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

    /// The accent color: focused borders, panel titles, the active tab and
    /// the selection stripe. Phosphor cyan on a dark terminal, deep
    /// teal-green on a light one — or the terminal's own cyan/blue when it
    /// cannot do 24-bit colour, so a curated terminal scheme still wins.
    pub fn accent(self) -> Color {
        match (self, truecolor()) {
            (Theme::Dark, true) => Color::Rgb(0x2e, 0xe6, 0xd6),
            (Theme::Light, true) => Color::Rgb(0x0f, 0x7a, 0x6a),
            (Theme::Dark, false) => Color::Cyan,
            (Theme::Light, false) => Color::Blue,
        }
    }

    /// The colour for things that are happening *right now*: the spinner,
    /// the job named beside it, the newest log line. Magenta on dark,
    /// copper on light. Nothing static is ever painted with it, which is
    /// what lets it mean "live".
    pub fn live(self) -> Color {
        match (self, truecolor()) {
            (Theme::Dark, true) => Color::Rgb(0xff, 0x5f, 0xd2),
            (Theme::Light, true) => Color::Rgb(0xb8, 0x55, 0x1c),
            (_, false) => Color::Magenta,
        }
    }

    /// Unfocused borders, hints, paths and timestamps.
    pub fn dim(self) -> Color {
        match (self, truecolor()) {
            (Theme::Dark, true) => Color::Rgb(0x6b, 0x7c, 0x8c),
            (Theme::Light, true) => Color::Rgb(0x5d, 0x6a, 0x60),
            (_, false) => Color::DarkGray,
        }
    }

    /// The background tint of the selected row in the focused list. A
    /// tint rather than reverse video so a red `[ BLOCKED ]` on the
    /// selected row is still red — focus and state no longer fight for
    /// the same cells.
    pub fn selection_bg(self) -> Color {
        match (self, truecolor()) {
            (Theme::Dark, true) => Color::Rgb(0x10, 0x26, 0x2a),
            (Theme::Light, true) => Color::Rgb(0xe2, 0xec, 0xe6),
            (Theme::Dark, false) => Color::Indexed(236),
            (Theme::Light, false) => Color::Indexed(254),
        }
    }

    /// The style of the selected row in a list that has focus.
    pub fn selection(self) -> Style {
        Style::new().bg(self.selection_bg()).bold()
    }

    /// The ground a popup is drawn on: one step off the terminal's own
    /// background, so a popup reads as a surface lifted off the screen
    /// rather than as a box drawn onto it.
    pub fn surface(self) -> Color {
        match (self, truecolor()) {
            (Theme::Dark, true) => Color::Rgb(0x13, 0x1b, 0x24),
            (Theme::Light, true) => Color::Rgb(0xf3, 0xf0, 0xe4),
            (Theme::Dark, false) => Color::Indexed(235),
            (Theme::Light, false) => Color::Indexed(255),
        }
    }
}

/// Whether the terminal advertises 24-bit colour. Read once: it is an
/// environment variable, and every list on every frame asks.
fn truecolor() -> bool {
    static TRUECOLOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRUECOLOR.get_or_init(|| {
        std::env::var("COLORTERM")
            .map(|v| v == "truecolor" || v == "24bit")
            .unwrap_or(false)
    })
}

/// The stripe drawn in front of the selected row of the focused list.
pub const SELECTION_MARK: &str = "\u{258e}";

/// A bordered panel. The focused one gets the accent on its border and a
/// bold accent title; every other panel is dim-bordered with a plain
/// title, so a glance says where the keys will land. Body text is never
/// coloured by the panel — it keeps the terminal's default foreground.
pub fn panel(title: impl Into<String>, focused: bool, theme: Theme) -> Block<'static> {
    let title: String = title.into();
    if focused {
        Block::bordered()
            .border_style(Style::new().fg(theme.accent()))
            .title(format!(" {title} ").fg(theme.accent()).bold())
    } else {
        Block::bordered()
            .border_style(Style::new().fg(theme.dim()))
            .title(format!(" {title} "))
    }
}

/// A popup's frame: always the focused treatment (a popup is where the
/// keys go), on the lifted [`Theme::surface`] ground. Callers still
/// `Clear` the area first, so nothing underneath shows through.
pub fn popup(title: impl Into<String>, theme: Theme) -> Block<'static> {
    panel(title, true, theme).style(Style::new().bg(theme.surface()))
}

/// A list's selection treatment. The focused list draws [`SELECTION_MARK`]
/// and the tint; an unfocused one reserves the same column and draws
/// nothing, so rows don't shift sideways when focus moves.
pub fn select_in<'a>(list: List<'a>, focused: bool, theme: Theme) -> List<'a> {
    let list = list.highlight_spacing(HighlightSpacing::Always);
    if focused {
        list.highlight_symbol(SELECTION_MARK)
            .highlight_style(theme.selection())
    } else {
        list.highlight_symbol(" ").highlight_style(Style::default())
    }
}

/// The screens the TUI can show. Jumped to with the digit the tab bar
/// shows (`1`–`4`, or the `d`/`b`/`s`/`p` aliases), stepped through with
/// Left/Right or their vim `h`/`l` aliases (see `App::handle_key_event`'s
/// global fallback match — these only fire once the active screen itself
/// has ignored the key), with Help reachable via `?` and the command
/// palette via `:` from anywhere. Tab is never a screen key: on every
/// screen it moves between that screen's panels.
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

    /// The key that jumps straight to this screen, shown in the tab bar.
    pub fn digit(self) -> char {
        match self {
            Screen::Dashboard => '1',
            Screen::BotSettings => '2',
            Screen::SiteSettings => '3',
            Screen::DynamicProtection => '4',
            Screen::Help => '?',
        }
    }

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
    /// The Dynamic Protection screen wants the detail for one address.
    /// `App` assembles it, because the failed-login usernames come from
    /// the SSH log text `App` read in the background and the screen does
    /// not keep a copy — see `ipdetail` for what goes into the answer.
    InspectAddress(String),
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
    /// function (see `App::start_firewall_render`). `apply` is the render popup's
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
    /// Site settings confirmed one of its filesystem actions: a scan of
    /// the NGINX config root, or an apply to one site or to all of them.
    /// All three walk or rewrite files under `/etc/nginx`, so — same
    /// reasoning as [`Self::ReloadNginx`] and [`Self::RenderFirewall`] —
    /// `App` performs them, off the event loop, rather than the screen's
    /// key handler doing it inline.
    SiteAction(crate::tui::site_settings::SiteAction),
    /// The Dashboard's `u` key: download every list this host uses. Eight
    /// or more network round-trips, so it goes to `App` for exactly the
    /// reason [`Self::UpdateSource`] does — the screen's key handler stays
    /// free of I/O, and its tests stay fast and offline.
    UpdateEverything,
    /// The Dashboard's `a` key: write and reload the NGINX config, then
    /// write and run the firewall script. Both halves shell out, so — same
    /// reasoning as [`Self::ReloadNginx`] and [`Self::RenderFirewall`] —
    /// `App` performs them.
    ApplyEverything,
    /// The Dashboard's Web Access popup was confirmed. `App` validates it
    /// against the database, rewrites the NGINX config and reloads — all
    /// three are things the screen's key handler must not do, same as
    /// [`Self::SiteAction`].
    SetWebAccess(crate::webaccess::Request),
    /// Dynamic Protection's `R`: read the SSH log again now, rather than
    /// when the 30-second cache says so. `App` owns that read (see
    /// `App::start_ssh_log_read`), for the same reason it owns every
    /// other blocking one.
    RereadLogs,
}

/// Puts `text` on the clipboard with OSC 52, the escape sequence a
/// terminal forwards to the local clipboard — through SSH and tmux, which
/// is where this tool is run from. Written straight to stdout, past
/// ratatui, because it is not a cell on screen. A terminal that does not
/// implement it drops the sequence; nothing is printed either way.
pub fn copy_to_clipboard(text: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let _ = out.flush();
}

/// Standard base64 with padding. Twenty lines here rather than a
/// dependency for one escape sequence.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
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
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(app, frame, header);

    match app.screen {
        Screen::Dashboard => {
            app.dashboard
                .render(frame, body, app.theme, &app.log, &app.jobs_in_flight)
        }
        Screen::BotSettings => app.bot_settings.render(frame, body, app.theme),
        Screen::SiteSettings => app.site_settings.render(frame, body, app.theme),
        Screen::DynamicProtection => {
            app.dynamic_protection
                .render(frame, body, app.theme, &app.jobs_in_flight)
        }
        Screen::Help => help::render(frame, body, app.theme),
    }

    // Over the body, under the footer: the footer is what tells you the
    // palette's keys.
    if let Some(palette) = &app.palette {
        palette.render(frame, body, app.theme);
    }

    render_footer(app, frame, footer);
}

fn render_header(app: &App, frame: &mut Frame, area: Rect) {
    let [brand_area, tabs_area, status_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let theme = app.theme;

    // Brand, version and host on the left; whatever is running right now
    // on the right, in the live colour. The version is here rather than
    // only behind `--version` because the TUI is where someone is
    // standing when they decide to report something.
    let mut brand = vec![
        "stop-bots".fg(theme.accent()).bold(),
        format!(" {}", env!("CARGO_PKG_VERSION")).fg(theme.dim()),
    ];
    if let Some(host) = crate::host::name() {
        brand.push(format!("  {host}").fg(theme.dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(brand)), brand_area);
    if let Some(busy) = busy_label(&app.jobs_in_flight) {
        let activity =
            Line::from(format!("{} {busy}", spinner_frame()).fg(theme.live())).right_aligned();
        frame.render_widget(Paragraph::new(activity), brand_area);
    }

    // The tab bar: each screen with the key that jumps to it, the active
    // one underlined in the accent. Hand-built rather than `Tabs`, which
    // cannot colour the digit separately from the name.
    let mut tabs: Vec<Span> = Vec::new();
    for (i, screen) in Screen::TABS.iter().chain([&Screen::Help]).enumerate() {
        if i > 0 {
            tabs.push("   ".into());
        }
        let active = app.screen == *screen;
        tabs.push(
            screen
                .digit()
                .to_string()
                .fg(theme.accent())
                .add_modifier(if active {
                    Modifier::BOLD | Modifier::UNDERLINED
                } else {
                    Modifier::empty()
                }),
        );
        tabs.push(" ".into());
        tabs.push(if active {
            screen.title().fg(theme.accent()).bold().underlined()
        } else {
            screen.title().fg(theme.dim())
        });
    }
    frame.render_widget(Paragraph::new(Line::from(tabs)), tabs_area);

    frame.render_widget(Paragraph::new(status_line(app)), status_area);
}

/// One line under the tabs answering "is this host protected", check by
/// check, with a symbol and a colour per level. Every screen gets it, not
/// just the Dashboard: a host that quietly stopped being protected should
/// show on whatever screen the operator happens to have open.
fn status_line(app: &App) -> Line<'static> {
    use crate::health::Level;
    let theme = app.theme;
    let mut spans: Vec<Span> = vec!["status".fg(theme.dim()), "  ".into()];
    let Some((report, _)) = app.dashboard.health() else {
        spans.push("not checked yet".fg(theme.dim()));
        return Line::from(spans);
    };
    for (i, check) in report.checks.iter().enumerate() {
        if i > 0 {
            spans.push("  ".into());
        }
        let (mark, colour) = match check.level {
            Level::Ok => ("\u{25cf}", Color::Green),
            Level::Warn => ("\u{25b2}", Color::Yellow),
            Level::Critical => ("\u{25b2}", Color::Red),
            Level::Unknown => ("\u{25cb}", theme.dim()),
        };
        spans.push(mark.fg(colour));
        spans.push(" ".into());
        let label = short_check_label(check.id);
        spans.push(match check.level {
            Level::Ok | Level::Unknown => label.fg(theme.dim()),
            Level::Warn | Level::Critical => label.into(),
        });
    }
    Line::from(spans)
}

/// A one-word name for a health check, because the strip is one line and
/// the checks' titles are sentences. Falls back to the id itself for a
/// check this table has not heard of, which is still readable.
fn short_check_label(id: &str) -> String {
    match id {
        "firewall-enforced" => "kernel",
        "firewall-persists" => "reboot",
        "script-fresh" => "script",
        "nginx-applied" => "nginx",
        "service-health" => "console",
        "disk-room" => "disk",
        "log-sources" => "logs",
        other => other,
    }
    .to_string()
}

/// The footer: which panel the keys go to, then the keys of the active
/// screen and panel, then the ones that work everywhere. Context-sensitive
/// so that panel titles can be titles — the hint for `r` belongs beside
/// the site list only while the site list has focus.
fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let theme = app.theme;
    let (panel, hints) = match (&app.palette, app.screen) {
        (Some(palette), _) => palette.hints(),
        (None, Screen::Dashboard) => app.dashboard.hints(),
        (None, Screen::BotSettings) => app.bot_settings.hints(),
        (None, Screen::SiteSettings) => app.site_settings.hints(),
        (None, Screen::DynamicProtection) => app.dynamic_protection.hints(),
        (None, Screen::Help) => ("Help", vec![("Esc", "back")]),
    };
    let mut spans: Vec<Span> = vec![panel.fg(theme.accent()).bold(), "  ".into()];
    let globals: &[(&str, &str)] = match (&app.palette, app.screen) {
        (Some(_), _) | (None, Screen::Help) => &[],
        _ => &[
            (":", "commands"),
            ("?", "help"),
            ("t", "theme"),
            ("q", "quit"),
        ],
    };
    for (i, (key, label)) in hints.iter().chain(globals).enumerate() {
        if i > 0 {
            spans.push("  ".into());
        }
        spans.push((*key).fg(theme.accent()));
        spans.push(" ".into());
        spans.push((*label).fg(theme.dim()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A screen's key hints for the footer: the name of the focused panel and
/// `(key, what it does)` pairs, most used first.
pub type Hints = (&'static str, Vec<(&'static str, &'static str)>);

/// What the footer says is happening, or `None` when nothing is.
///
/// Only one job is named even when several are out, because the footer is
/// one line and the count is what matters past the first — an admin
/// waiting on an NGINX reload does not need the scheduled log read
/// itemised. Sorted so which one gets named doesn't flicker between
/// redraws of the same set, `HashSet` iteration order being arbitrary.
fn busy_label(jobs: &std::collections::HashSet<crate::app::Job>) -> Option<String> {
    let mut labels: Vec<String> = jobs.iter().map(crate::app::Job::label).collect();
    labels.sort();
    let first = labels.first()?;
    Some(match labels.len() {
        1 => first.clone(),
        n => format!("{first} (+{} more)", n - 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which job gets named when several are out has to be stable across
    /// redraws — `HashSet` iteration order is arbitrary, so without the
    /// sort the footer would flicker between two labels 30 times a second
    /// while nothing had actually changed.
    #[test]
    fn the_footer_names_one_job_stably_and_counts_the_rest() {
        use crate::app::Job;
        use crate::cron::CronJob;

        assert_eq!(busy_label(&std::collections::HashSet::new()), None);

        let one = std::collections::HashSet::from([Job::ReloadNginx]);
        assert_eq!(busy_label(&one).as_deref(), Some("reloading NGINX"));

        let several = std::collections::HashSet::from([
            Job::ReloadNginx,
            Job::ReadSshLog,
            Job::Cron(CronJob::UpdateIpRanges),
        ]);
        // Sorted, so this is the answer every time and not just this time.
        for _ in 0..10 {
            assert_eq!(
                busy_label(&several).as_deref(),
                Some("Update crawler IP ranges (scheduled) (+2 more)")
            );
        }
    }

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"192.0.2.44"), "MTkyLjAuMi40NA==");
    }

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
