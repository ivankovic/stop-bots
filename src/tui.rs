/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
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

pub mod blocks;
pub mod bot_settings;
pub mod dashboard;
pub mod explain;
pub mod firewall;
pub mod help;
pub mod keep_firewall;
pub mod nginx;
pub mod palette;
pub mod site_detail;

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
/// drawn with. "Night Grid" is the dark one, "Greenhouse" the light one.
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
/// shows (`1`–`5`, or the `d`/`b`/`f`/`n`/`x` aliases), stepped through with
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
    Firewall,
    Nginx,
    /// Every stored firewall rule and why it is there. After NGINX rather
    /// than beside Firewall so that the four digits people already know
    /// keep their screens.
    Blocks,
    Help,
}

impl Screen {
    pub const TABS: [Screen; 5] = [
        Screen::Dashboard,
        Screen::BotSettings,
        Screen::Firewall,
        Screen::Nginx,
        Screen::Blocks,
    ];

    /// The screens the simple mode has: its own, and Blocks, which is
    /// where a block is undone. The rest are a `v` away.
    pub const SIMPLE_TABS: [Screen; 2] = [Screen::Dashboard, Screen::Blocks];

    /// The key that jumps straight to this screen, shown in the tab bar.
    pub fn digit(self) -> char {
        match self {
            Screen::Dashboard => '1',
            Screen::BotSettings => '2',
            Screen::Firewall => '3',
            Screen::Nginx => '4',
            Screen::Blocks => '5',
            Screen::Help => '?',
        }
    }

    /// The tab's name. The sites screen is named for the web server it
    /// manages, so the name needs it: there is no answer without one.
    pub fn title(self, server: crate::webserver::WebServer) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::BotSettings => "Bot settings",
            Screen::Firewall => "Firewall",
            Screen::Nginx => server.label(),
            Screen::Blocks => "Blocks",
            Screen::Help => "Help",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Screen::Dashboard => Screen::BotSettings,
            Screen::BotSettings => Screen::Firewall,
            Screen::Firewall => Screen::Nginx,
            Screen::Nginx => Screen::Blocks,
            Screen::Blocks | Screen::Help => Screen::Dashboard,
        }
    }

    pub fn previous(self) -> Self {
        match self {
            Screen::Dashboard => Screen::Blocks,
            Screen::BotSettings => Screen::Dashboard,
            Screen::Firewall => Screen::BotSettings,
            Screen::Nginx => Screen::Firewall,
            Screen::Blocks => Screen::Nginx,
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
    /// The Firewall screen wants the detail for one address.
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
    /// The Dashboard switched on a C&C feed that has never been
    /// downloaded. `App` runs the schedule's feed job, which downloads
    /// every feed that is on, now.
    UpdateEgressFeeds,
    /// The Dashboard chose hosting providers to block, these AS numbers
    /// among them with no ranges yet. `App` downloads the ASN table once
    /// for all of them and stores their ranges (`App::start_hosting_asn_fetch`).
    FetchHostingAsns(Vec<u32>),
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
    /// NGINX wrote at least one changed NGINX config file on disk
    /// (`apply now` / `apply all`). Reloading is a real side effect (shells
    /// out to `nginx -t` and `systemctl reload nginx`), so — same reasoning
    /// as `RenderFirewall`/`UpdateSource` — it stays with `App` rather than
    /// running inline in the screen's own `handle_key`, keeping that code
    /// free of real process execution so its tests stay fast and
    /// deterministic (see `crate::nginx::reload`).
    ReloadNginx,
    /// NGINX confirmed one of its filesystem actions: a scan of
    /// the NGINX config root, or an apply to one site or to all of them.
    /// All three walk or rewrite files under `/etc/nginx`, so — same
    /// reasoning as [`Self::ReloadNginx`] and [`Self::RenderFirewall`] —
    /// `App` performs them, off the event loop, rather than the screen's
    /// key handler doing it inline.
    SiteAction(crate::tui::nginx::SiteAction),
    /// The Dashboard's `u` key: download every list this host uses. Eight
    /// or more network round-trips, so it goes to `App` for exactly the
    /// reason [`Self::UpdateSource`] does — the screen's key handler stays
    /// free of I/O, and its tests stay fast and offline.
    UpdateEverything,
    /// Enter on one of the Dashboard's crawler ranges: download just that
    /// one. A network round-trip, so `App` does it, for the reason
    /// [`Self::UpdateEverything`] gives.
    RefreshCrawlerRanges(crate::ipranges::IpRangeSourceKind),
    /// The Dashboard's `a` key: work out what "Apply everything" would
    /// change, and ask. Reading every site file and the SSH log is I/O, so
    /// `App` does it, and hands the answer back for the Dashboard's
    /// confirmation popup.
    PreviewApplyEverything,
    /// That popup, confirmed: write and reload the NGINX config, then write
    /// and run the firewall script. Both halves shell out, so — same
    /// reasoning as [`Self::ReloadNginx`] and [`Self::RenderFirewall`] —
    /// `App` performs them.
    ApplyEverything,
    /// The simple screen's "Keep running by itself": on writes the cron
    /// file and switches both auto-applies on, off switches them off (see
    /// `install::keep_running`). On writes to `/etc` as root, so `App` does
    /// it, for the reason [`Self::ReloadNginx`] gives.
    KeepRunning(bool),
    /// The simple screen's "Block attackers in logs" row was opened: show
    /// the checks themselves, which are the advanced Dashboard's
    /// Automatic blocking list.
    ShowDetectors,
    /// Firewall's `R`: read the SSH log again now, rather than
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
// A deliberate escape sequence, around base64 that cannot carry one.
#[allow(clippy::disallowed_methods)]
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
        Screen::Firewall => app
            .firewall
            .render(frame, body, app.theme, &app.jobs_in_flight),
        Screen::Nginx => app.nginx.render(frame, body, app.theme),
        Screen::Blocks => app.blocks.render(frame, body, app.theme),
        Screen::Help => help::render(frame, body, app.theme, app.nginx.server()),
    }

    // Over the body, under the footer: the footer is what tells you the
    // palette's keys.
    if let Some(palette) = &app.palette {
        palette.render(frame, body, app.theme);
    }
    if let Some(explain) = &app.explain {
        explain.render(frame, body, app.theme);
    }
    // Over everything: until it is answered, nothing else takes a key.
    if let Some(keep) = &app.keep_firewall {
        let settling = app
            .jobs_in_flight
            .contains(&crate::app::Job::SettleFirewall);
        keep.render(frame, body, app.theme, settling);
    }

    render_footer(app, frame, footer);

    if no_color() {
        without_colour(frame.buffer_mut());
    }
}

/// Whether the environment asks for no colour: `NO_COLOR` set to anything
/// but nothing, as <https://no-color.org> has it.
fn no_color() -> bool {
    static NO_COLOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NO_COLOR.get_or_init(|| std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()))
}

/// Takes every colour out of what was drawn, once, here, rather than at
/// each of the few hundred places a colour is chosen. Bold, dim and
/// underline stay, and a cell that had a background (the selected row, a
/// tag) is reversed instead, so that what the colour was saying is still
/// said. Every state a colour marks also has a word or a shape beside it.
fn without_colour(buffer: &mut ratatui::buffer::Buffer) {
    use ratatui::style::Modifier;
    for cell in &mut buffer.content {
        if cell.bg != Color::Reset {
            cell.modifier.insert(Modifier::REVERSED);
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
    }
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
    // Not the system database: the note that used to go to stderr, where
    // the alternate screen hid it the moment the TUI started. On the brand
    // line, which is otherwise mostly empty, rather than a line of its
    // own: every screen's body is laid out to the row, and Help's is full.
    if let Some(notice) = &app.db_notice {
        brand.push("  \u{25b2} ".fg(Color::Yellow));
        brand.push(notice.clone().fg(Color::Yellow));
    }
    frame.render_widget(Paragraph::new(Line::from(brand)), brand_area);
    if let Some(busy) = busy_label(&app.jobs_in_flight, app.nginx.server()) {
        let activity =
            Line::from(format!("{} {busy}", spinner_frame()).fg(theme.live())).right_aligned();
        frame.render_widget(Paragraph::new(activity), brand_area);
    }

    // The tab bar: each screen with the key that jumps to it, the active
    // one underlined in the accent. Hand-built rather than `Tabs`, which
    // cannot colour the digit separately from the name.
    let mut tabs: Vec<Span> = Vec::new();
    let simple = app.dashboard.is_simple();
    let shown: &[Screen] = if simple {
        &Screen::SIMPLE_TABS
    } else {
        &Screen::TABS
    };
    for (i, screen) in shown.iter().chain([&Screen::Help]).enumerate() {
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
        let title = match screen {
            Screen::Dashboard if simple => "Overview",
            _ => screen.title(app.nginx.server()),
        };
        tabs.push(if active {
            title.fg(theme.accent()).bold().underlined()
        } else {
            title.fg(theme.dim())
        });
    }
    // The simple screen's way to everything it leaves out, spelled out
    // beside its tabs: the person it is for does not yet know there is
    // more. Every screen has the way back where the tabs end.
    if simple {
        tabs.extend([
            "   Press '".fg(theme.dim()),
            "v".fg(theme.accent()).bold(),
            "' to enable advanced mode".fg(theme.dim()),
        ]);
    } else {
        let mode =
            Line::from(vec!["v".fg(theme.accent()), " simple".fg(theme.dim())]).right_aligned();
        frame.render_widget(Paragraph::new(mode), tabs_area);
    }
    frame.render_widget(Paragraph::new(Line::from(tabs)), tabs_area);

    // The simple screen says the same thing once, in its Status panel.
    if !simple || app.screen != Screen::Dashboard {
        frame.render_widget(Paragraph::new(status_line(app)), status_area);
    }
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
    // What is wrong first. The line is cut at the terminal's width, and
    // in the order the checks run the cut took `logs` and `log format`
    // off an 80-column terminal whether or not they were the problem.
    let mut checks: Vec<&crate::health::Check> = report.checks.iter().collect();
    checks.sort_by_key(|check| match check.level {
        Level::Critical => 0,
        Level::Warn => 1,
        Level::Unknown => 2,
        Level::Ok => 3,
    });
    for (i, check) in checks.into_iter().enumerate() {
        if i > 0 {
            spans.push("  ".into());
        }
        // A shape for each level as well as a colour: a critical check
        // and a warning were the same triangle in red and in yellow,
        // which a terminal without colour, or an eye without that
        // distinction, shows as the same thing.
        let (mark, colour) = match check.level {
            Level::Ok => ("\u{25cf}", Color::Green),
            Level::Warn => ("\u{25b2}", Color::Yellow),
            Level::Critical => ("\u{2716}", Color::Red),
            Level::Unknown => ("\u{25cb}", theme.dim()),
        };
        spans.push(mark.fg(colour));
        spans.push(" ".into());
        let label = crate::present::check_label(check);
        spans.push(match check.level {
            Level::Ok | Level::Unknown => label.fg(theme.dim()),
            Level::Warn | Level::Critical => label.into(),
        });
    }
    Line::from(spans)
}

/// The footer: which panel the keys go to, then the keys of the active
/// screen and panel, then the ones that work everywhere. Context-sensitive
/// so that panel titles can be titles — the hint for `r` belongs beside
/// the site list only while the site list has focus.
fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    let theme = app.theme;
    let overlay = app.palette.is_some() || app.explain.is_some();
    let (panel, hints) = match (&app.palette, &app.explain) {
        (Some(palette), _) => palette.hints(),
        (None, Some(explain)) => explain.hints(),
        (None, None) => app.hints(),
    };
    let mut spans: Vec<Span> = vec![panel.fg(theme.accent()).bold(), "  ".into()];
    // The last thing that happened, on whatever screen is open, until the
    // next key press brings the hints back. It used to reach only the
    // Dashboard, so the outcome of a fetch started from Bot settings, or
    // of an apply on NGINX, was on a screen nobody was looking at.
    if let (Some(message), true, false) = (&app.message, app.message_in_footer, overlay) {
        spans.push(
            message
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
                .fg(theme.live()),
        );
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    let globals: &[(&str, &str)] = match (overlay, app.screen) {
        (true, _) | (false, Screen::Help) => &[],
        // Fewer on the simple screen, whose footer has to fit beside its
        // own keys on a narrow terminal; `:` and `t` still work there.
        (false, Screen::Dashboard) if app.dashboard.is_simple() => {
            &[("?", "explain"), ("q", "quit")]
        }
        _ => &[
            (":", "commands"),
            ("?", "explain"),
            ("t", "theme"),
            ("q", "quit"),
        ],
    };
    // A box that is taking every key typed, or a popup waiting for its
    // answer: `?` there is a question mark in the search, and `q` closes
    // the popup, so neither is offered as what it is elsewhere.
    let modal = hints
        .iter()
        .any(|(key, label)| *key == "Esc" && MODAL_ESCAPES.contains(label));
    let globals = if modal { &[] } else { globals };
    let all: Vec<(&str, &str)> = hints.iter().chain(globals).copied().collect();
    let used: usize = spans.iter().map(Span::width).sum();
    let room = usize::from(area.width).saturating_sub(used);
    for (i, (key, label)) in fitted(&all, hints.len(), room).into_iter().enumerate() {
        if i > 0 {
            spans.push("  ".into());
        }
        spans.push(key.fg(theme.accent()));
        if !label.is_empty() {
            spans.push(" ".into());
            spans.push(label.fg(theme.dim()));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// What `Esc` is labelled while something has taken the keyboard.
const MODAL_ESCAPES: [&str; 3] = ["cancel", "close", "leave search"];

/// The width of one hint as the footer draws it.
fn hint_width((key, label): &(&str, &str)) -> usize {
    let width = |text: &str| Span::from(text).width();
    width(key)
        + if label.is_empty() {
            0
        } else {
            1 + width(label)
        }
}

/// `hints` as they fit in `room` columns, two spaces apart. The first
/// `own` are the screen's and the rest work everywhere.
///
/// All of them where there is room. Where there is not, the line used to
/// be cut at the right edge, and the right edge is where `? explain` and
/// `q quit` are: the two keys that say what the others do and how to
/// leave went first. Now the screen's own hints give way from the end,
/// an ellipsis says so, and `?` and `q` stay.
fn fitted<'a>(hints: &[(&'a str, &'a str)], own: usize, room: usize) -> Vec<(&'a str, &'a str)> {
    let width = |hints: &[(&str, &str)]| {
        hints.iter().map(hint_width).sum::<usize>() + 2 * hints.len().saturating_sub(1)
    };
    if width(hints) <= room {
        return hints.to_vec();
    }
    let (own, global) = hints.split_at(own.min(hints.len()));
    let kept: Vec<(&str, &str)> = global
        .iter()
        .filter(|(key, _)| matches!(*key, "?" | "q"))
        .copied()
        .collect();
    let mut fitted: Vec<(&str, &str)> = Vec::new();
    for hint in own {
        let mut with = fitted.clone();
        with.push(*hint);
        with.push(("\u{2026}", ""));
        with.extend(&kept);
        if width(&with) > room {
            break;
        }
        fitted.push(*hint);
    }
    fitted.push(("\u{2026}", ""));
    fitted.extend(kept);
    fitted
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
fn busy_label(
    jobs: &std::collections::HashSet<crate::app::Job>,
    server: crate::webserver::WebServer,
) -> Option<String> {
    let mut labels: Vec<String> = jobs.iter().map(|job| job.label(server)).collect();
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

    #[test]
    fn hints_that_fit_are_all_shown() {
        let hints = [("a", "apply"), ("?", "explain"), ("q", "quit")];
        assert_eq!(fitted(&hints, 1, 80), hints.to_vec());
    }

    /// The keys that explain the others, and that leave, are the last to go.
    #[test]
    fn hints_that_do_not_fit_give_way_from_the_screen_s_own_end() {
        let hints = [
            ("Enter", "block/unblock"),
            ("T", "trust"),
            ("i", "inspect"),
            (":", "commands"),
            ("?", "explain"),
            ("t", "theme"),
            ("q", "quit"),
        ];
        let shown = fitted(&hints, 3, 50);
        assert_eq!(
            shown,
            vec![
                ("Enter", "block/unblock"),
                ("T", "trust"),
                ("\u{2026}", ""),
                ("?", "explain"),
                ("q", "quit"),
            ]
        );
        let width: usize = shown.iter().map(hint_width).sum::<usize>() + 2 * (shown.len() - 1);
        assert!(width <= 50, "{width} columns: {shown:?}");
    }

    #[test]
    fn without_colour_a_background_becomes_reverse_video() {
        use ratatui::style::Modifier;
        let mut buffer = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 2, 1));
        buffer.content[0].set_fg(Color::Red).set_bg(Color::Blue);
        buffer.content[1].set_fg(Color::Green);

        without_colour(&mut buffer);

        let colours: Vec<_> = buffer.content.iter().map(|c| (c.fg, c.bg)).collect();
        assert_eq!(colours, vec![(Color::Reset, Color::Reset); 2]);
        assert!(buffer.content[0].modifier.contains(Modifier::REVERSED));
        assert!(!buffer.content[1].modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn the_sites_screen_is_named_for_the_hosts_web_server() {
        use crate::webserver::WebServer;
        for server in WebServer::ALL {
            assert_eq!(Screen::Nginx.title(server), server.label());
        }
        assert_eq!(Screen::Firewall.title(WebServer::Apache), "Firewall");
    }

    /// Which job gets named when several are out has to be stable across
    /// redraws — `HashSet` iteration order is arbitrary, so without the
    /// sort the footer would flicker between two labels 30 times a second
    /// while nothing had actually changed.
    #[test]
    fn the_footer_names_one_job_stably_and_counts_the_rest() {
        use crate::app::Job;
        use crate::cron::CronJob;
        use crate::webserver::WebServer::Nginx;

        assert_eq!(busy_label(&std::collections::HashSet::new(), Nginx), None);

        let one = std::collections::HashSet::from([Job::ReloadNginx]);
        assert_eq!(busy_label(&one, Nginx).as_deref(), Some("reloading NGINX"));

        let several = std::collections::HashSet::from([
            Job::ReloadNginx,
            Job::ReadSshLog,
            Job::Cron(CronJob::UpdateIpRanges),
        ]);
        // Sorted, so this is the answer every time and not just this time.
        for _ in 0..10 {
            assert_eq!(
                busy_label(&several, Nginx).as_deref(),
                Some("Update crawler IP ranges (scheduled) (+2 more)")
            );
        }
    }

    #[test]
    fn the_footer_names_the_web_server_the_host_runs() {
        use crate::app::Job;
        use crate::webserver::WebServer::Apache;
        for (job, expected) in [
            (Job::ReloadNginx, "reloading Apache"),
            (Job::ScanSites, "scanning the Apache config"),
        ] {
            let jobs = std::collections::HashSet::from([job]);
            assert_eq!(busy_label(&jobs, Apache).as_deref(), Some(expected));
        }
    }

    /// The whole screen as text, one line per row.
    fn drawn(app: &mut App) -> Vec<String> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 20)).unwrap();
        terminal.draw(|frame| render(app, frame)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn app() -> App {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_ui_mode(crate::db::UiMode::Advanced).unwrap();
        App::new(
            db,
            std::path::PathBuf::from("/etc/nginx"),
            false,
            Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
        )
        .unwrap()
    }

    /// The fallback's note used to go to stderr, and the alternate screen
    /// hid it at once. Now it is on the header's first line, on every
    /// screen, and takes no row from the screen below it.
    #[tokio::test]
    async fn a_database_other_than_the_system_one_is_named_in_the_header() {
        let mut app = app();
        let notice = "Not root: settings go to your user database, not the system one";
        app.db_notice = Some(notice.to_string());

        for screen in [Screen::Dashboard, Screen::Nginx, Screen::Help] {
            app.screen = screen;
            let lines = drawn(&mut app);
            assert!(
                lines[0].contains(notice),
                "{screen:?}:\n{}",
                lines.join("\n")
            );
            assert!(lines[1].contains("Dashboard"), "{screen:?}: the tabs moved");
        }
    }

    #[tokio::test]
    async fn the_system_database_gets_no_notice() {
        let mut app = app();
        let screen = drawn(&mut app).join("\n");
        assert!(!screen.contains("system one"), "{screen}");
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
        assert_eq!(Screen::BotSettings.next(), Screen::Firewall);
        assert_eq!(Screen::Firewall.next(), Screen::Nginx);
        assert_eq!(Screen::Nginx.next(), Screen::Blocks);
        assert_eq!(Screen::Blocks.next(), Screen::Dashboard);
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
