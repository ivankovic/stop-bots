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

//! The Dashboard: the default screen on app start. An overview of global
//! settings (Scanners/Search Bots/AI Bots defaults, navigable and editable
//! via a popup, mirroring how Bot settings edits a single bot's override),
//! how many sites are known, whether bot-list sources are up to date, and
//! host-wide geo-blocking (see "Geo-blocking" below). The "Summary" panel is
//! deliberately just a glance — it used to also fold in top user agents
//! seen in successful traffic, but that's moved to its own dedicated
//! "Dynamic Protection" screen (`crate::tui::dynamic_protection`), which
//! also lets an admin act on it (permanently block one), not just look at
//! it.
//!
//! ## Layout
//!
//! "System-wide settings" and "Geo-blocking" share the top row — one is
//! three fixed rows and the other a list of country codes, so between them
//! they were using a quarter of the width. "Automatic blocking" gets the
//! full width below them, and deals its rows into as many columns as that
//! width allows so that all of them are visible at once. It used to share
//! a row with Geo-blocking and show five of its fourteen.
//!
//! Focus still flows *linearly* through the three lists (Categories ->
//! Countries -> Protection) via Up/Down, and only the focused one draws a
//! highlight, so there's never ambiguity about which list the arrows move.
//! Within Automatic blocking the rows fill one column before starting the
//! next, so a single selection index still walks them in reading order:
//! Down at the foot of one column arrives at the head of the next.
//!
//! ## The host-wide actions
//!
//! Three keys here act on the whole host rather than on the selected row,
//! and each is the TUI's half of something the console has as a button or
//! a panel:
//!
//! - `u` downloads every list this host uses ([`crate::refresh`]), one
//!   source at a time — `KeyOutcome::UpdateEverything`.
//! - `a` writes the NGINX config and then writes and runs the firewall
//!   script — `KeyOutcome::ApplyEverything`. Two independent halves, the
//!   same two `batch --apply` does. The NGINX reload it triggers overlaps
//!   the firewall render rather than preceding it: both are started from
//!   `App::finish_site_apply`, and neither reads what the other writes.
//! - `w` opens the Web Access form ([`Popup::WebAccess`]), which puts this
//!   console behind NGINX on a subdomain or a path prefix
//!   ([`crate::webaccess`]).
//!
//! None of the three is behind a confirmation popup, matching the
//! console's one-click buttons: an update only downloads, and the apply
//! goes through the same anti-lockout guard the render popup does.
//!
//! They are hinted in the *Summary* panel's title rather than in
//! "System-wide settings"', where they belong by meaning. That panel is
//! half-width — 37 title columns on an 80-column terminal — and ratatui
//! truncates a longer `Block` title silently, which loses most of a hint
//! that says what the keys do. A title short enough to fit names the keys
//! and nothing else. Summary is full-width and already the panel that
//! says "press f".
//!
//! ## Geo-blocking
//!
//! A second, independently-focused list (`countries_state`, switched to via
//! `Down` past the last category row or `Up` above the first country
//! row — no dedicated focus key, since these are just two vertically
//! stacked lists, not a list-plus-search-box pair like Bot settings'
//! `Focus`) shows every host-wide selected country (`Db::list_selected_countries`)
//! plus a fixed "+ Add a country" action row at the top. What being
//! "selected" *means* depends on the geo mode, shown in the panel's title
//! and toggled with `m` (a popup, unlike the direct actions below, since
//! switching to Allowlist is meaningfully higher-stakes — see
//! [`Popup::GeoMode`]):
//!
//! - **Blocklist** (the default): selected countries are blocked,
//!   everything else is allowed.
//! - **Allowlist**: selected countries are the *only* ones allowed,
//!   everything else is blocked host-wide once `render-firewall` runs (see
//!   `Db::geo_firewall_rules` and its nftables-only guard in `main.rs`).
//!
//! Enter on the "Add" row opens a text-input popup for a two-letter code;
//! Enter on an existing country row removes it directly (no confirmation
//! popup — unlike a category default, removing a country isn't "choose one
//! of several options", it's a single reversible action, the same
//! reasoning Site settings' apply/apply-all actions already use).
//! Confirming the input popup with a code whose ranges are already fetched
//! adds it immediately (`Mutated`); a not-yet-fetched code returns
//! `KeyOutcome::SelectCountry` so `App` can fetch it first
//! (`App::start_country_select`) — see that function's doc comment for why
//! fetching can't happen here directly.

use crate::db::{Category, Db, GeoMode, Policy, Source};
use crate::ipranges;
use crate::protection::Detector;
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, ListState, Paragraph},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source is considered stale (needs updating) if it's never been fetched,
/// or wasn't fetched in the last week.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

/// The rows of the editable "System-wide settings" list, in display order.
const CATEGORIES: [Category; 3] = [Category::Scanner, Category::Search, Category::Ai];

/// Which of the Dashboard's three lists arrow keys currently move through.
/// Ordered as focus flows: `Down` past the last row of one moves into the
/// next, `Up` above the first row moves back — no dedicated focus key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Categories,
    Countries,
    Protection,
}

/// The rows of the "Automatic blocking" list, in display order. Each is a
/// detector that adds `firewall_rules` rows on its own — which is why they
/// live on the Dashboard rather than Site settings: this project puts
/// everything that ends up in the *firewall script* here, and everything
/// that ends up in *NGINX config* on Site settings.
/// A row in the "Automatic blocking" list: either a log-analysis detector
/// or a third-party CIDR feed. They share one panel because they answer
/// the same question — "what adds firewall blocks without me doing
/// anything?" — and splitting them would mean a fifth Dashboard panel
/// there is no room for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectionRow {
    /// One log-analysis detector. Every detector shares this variant —
    /// the per-detector facts live on `DetectorSpec`, so adding one costs
    /// nothing here.
    Detect(Detector),
    /// A `reputation_sources` row, by index into
    /// `Dashboard::reputation` (which is ordered by id, as
    /// `Db::list_reputation_sources` returns it).
    Feed(usize),
}

impl ProtectionRow {
    /// Whether this row is a detector (whose popup offers Off plus a TTL
    /// choice) rather than a feed (a plain Off/On, with no TTL — a feed's
    /// blocks are derived at render time and never expire on their own).
    fn is_detector(self) -> bool {
        !matches!(self, ProtectionRow::Feed(_))
    }
}

/// The TTLs offered for a detector, in the order the popup lists them
/// after its "Off" row. Folding the TTL into the same one-of-N popup as the
/// on/off choice keeps this screen to a single interaction pattern (every
/// other Dashboard setting is already "Enter, pick one") instead of adding
/// a second key and a free-text number entry for one field.
const PROTECTION_TTL_CHOICES: [i64; 3] = [1, 7, 30];

/// The popup opened by the Dashboard: editing a category default (cycles
/// between Allowed (0) and Blocked (1), mirroring Bot settings' category
/// popup before it moved here), entering a country code to add to the geo
/// selection, or switching the geo mode itself.
#[derive(Debug, Clone)]
enum Popup {
    Category {
        category: Category,
        selected: usize,
    },
    AddCountry {
        input: String,
        error: Option<String>,
    },
    /// Cycles between Blocklist (0) and Allowlist (1) — a popup, not a
    /// direct toggle like removing a country, because flipping to
    /// Allowlist is a materially bigger decision: it turns host-wide geo
    /// enforcement into a default-deny gate for the whole box once
    /// `render-firewall` runs, not just "one more blocked country".
    GeoMode {
        selected: usize,
    },
    /// One "Automatic blocking" row: option 0 is Off, options 1..=N are On
    /// with each of [`PROTECTION_TTL_CHOICES`]' TTLs. A popup rather than a
    /// bare Space-toggle so the TTL is visible and settable at the same
    /// time, and because enabling a detector that adds firewall rules on
    /// its own deserves a deliberate confirmation.
    Protection {
        row: ProtectionRow,
        selected: usize,
    },
    /// Firewall rendering: select backend (0 = iptables, 1 = nftables),
    /// enter the output path, and optionally toggle `apply_after_write`
    /// (Space) so confirming with Enter also actually enforces the script
    /// (`firewall::apply_script`, gated by `App::apply_firewall`) instead of
    /// only writing it for the admin to apply by hand.
    RenderFirewall {
        backend_selected: usize,
        out_path: String,
        apply_after_write: bool,
        error: Option<String>,
    },
    /// Putting this console behind NGINX: path mode on a scanned site, or
    /// a subdomain of its own. The console's "Web Access" panel is the
    /// same form, and both hand the answer to [`crate::webaccess`].
    ///
    /// Two text fields rather than one that changes meaning with the
    /// mode: switching modes to see what the other one looks like must
    /// not throw away what was already typed.
    WebAccess {
        subdomain: bool,
        /// Index into [`Dashboard::sites`].
        site: usize,
        prefix: String,
        host: String,
        error: Option<String>,
    },
}

#[derive(Debug, Default)]
pub struct Dashboard {
    site_count: usize,
    sources: Vec<Source>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
    list_state: ListState,
    popup: Option<Popup>,
    geo_mode: GeoMode,
    selected_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    countries_state: ListState,
    protection_state: ListState,
    /// The automatic-detection toggles, reloaded on every `refresh` — the
    /// panel only displays them; `crate::cron`'s jobs read the same values
    /// straight from `Db` when they run.
    /// Each detector's (enabled, ttl_days), reloaded on every `refresh`.
    /// A map rather than a struct of named fields, so a new detector is a
    /// row in `Detector::ALL` and nothing here.
    detectors: std::collections::HashMap<Detector, (bool, i64)>,
    /// Every third-party CIDR feed, ordered by id — the order
    /// `ProtectionRow::Feed`'s index refers to.
    reputation: Vec<crate::db::ReputationSource>,
    focus: Focus,
    /// The internal cron's per-job state (see `crate::cron`), read-only
    /// here — this panel only displays it, `App` is what actually runs due
    /// jobs.
    cron_status: Vec<crate::cron::JobStatus>,
    /// Whether the current rule set (`firewall::all_rules`) differs from
    /// what was in effect the last time the firewall was actually rendered
    /// (`firewall::rules_signature`, compared via
    /// `Db::get_firewall_rendered_signature`) — shown as a Summary panel
    /// row so an admin can tell, without opening the render popup, whether
    /// e.g. a scanner blocked since the last daily `RenderFirewall` cron
    /// tick is actually reflected in the on-disk script yet.
    firewall_needs_update: bool,
    /// How many rules a render would write, for the Summary panel — see
    /// its three-state line, which reads differently at zero.
    rule_count: usize,
    /// The last health probe, re-assessed on every refresh. `None` until
    /// the internal cron has taken one — see [`crate::health`].
    health: Option<(crate::health::Report, i64)>,
    /// Every scanned site's `server_name`, for the Web Access popup to
    /// offer. Names rather than rows: the popup only needs to hand one
    /// back, and `webaccess::plan` looks the rest up itself.
    sites: Vec<String>,
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        // Cheap: the expensive half (shelling out to `nft`) is the cron's
        // job, and this only re-derives the report from what it stored.
        self.health = crate::health::cached_report(db)?;
        let sites = db.list_sites()?;
        self.site_count = sites.len();
        self.sites = sites.into_iter().map(|s| s.server_name).collect();
        self.sources = db.list_sources()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        self.geo_mode = db.get_geo_mode()?;
        self.selected_countries = db.list_selected_countries()?;
        self.fetched_countries = db.list_fetched_countries()?;
        self.detectors = Detector::ALL
            .into_iter()
            .map(|d| Ok((d, (d.is_enabled(db)?, d.ttl_days(db)?))))
            .collect::<Result<_>>()?;
        self.reputation = db.list_reputation_sources()?;
        self.cron_status = crate::cron::status(db)?;
        self.firewall_needs_update = firewall_needs_update(db)?;
        self.rule_count = crate::firewall::all_rules(db)?.len();
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        if self.countries_state.selected().is_none() {
            self.countries_state.select(Some(0));
        }
        if self.protection_state.selected().is_none() {
            self.protection_state.select(Some(0));
        }
        // Removing a country shrinks `selected_countries`; without this the
        // selection could be left pointing past the new last row (stale
        // until the next arrow press re-clamps it via `select_previous`/
        // `select_next`) if the row that was just removed wasn't the last
        // one selected.
        let max_row = self.selected_countries.len(); // +1 (the "Add" row) - 1 (0-indexed)
        if self.countries_state.selected().is_some_and(|s| s > max_row) {
            self.countries_state.select(Some(max_row));
        }
        Ok(())
    }

    /// How many CIDRs are currently known for `country_code`, if it's ever
    /// been fetched — `None` for a country that was selected (e.g. via the
    /// CLI's `add-country`) before its ranges were ever fetched.
    fn range_count(&self, country_code: &str) -> Option<i64> {
        self.fetched_countries
            .iter()
            .find(|(cc, _, _)| cc == country_code)
            .map(|(_, count, _)| *count)
    }

    fn category_default(&self, category: Category) -> Policy {
        match category {
            Category::Scanner => self.scanner_default,
            Category::Search => self.search_default,
            Category::Ai => self.ai_default,
        }
    }

    fn up_to_date_count(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| !is_stale(s.last_fetched_at))
            .count()
    }

    /// Whether the Summary panel's firewall row currently reads "needs
    /// updating" — `pub(crate)` and test-only, purely so `App`'s own tests
    /// (a different module) can assert that a render triggered through the
    /// key/outcome flow actually refreshes this cached value, not just the
    /// underlying `Db` signature (see `App::handle_key_event`'s
    /// `RenderFirewall` arm).
    #[cfg(test)]
    pub(crate) fn firewall_needs_update(&self) -> bool {
        self.firewall_needs_update
    }

    #[cfg(test)]
    pub(crate) fn render_popup_is_open(&self) -> bool {
        matches!(self.popup, Some(Popup::RenderFirewall { .. }))
    }

    #[cfg(test)]
    fn needs_update_count(&self) -> usize {
        self.sources.len() - self.up_to_date_count()
    }

    /// The last health report, for the status strip every screen shows.
    pub fn health(&self) -> Option<&(crate::health::Report, i64)> {
        self.health.as_ref()
    }

    /// The footer's key hints for the focused panel.
    pub fn hints(&self) -> crate::tui::Hints {
        if self.popup.is_some() {
            return (
                "Popup",
                vec![
                    ("\u{2191}\u{2193}", "choose"),
                    ("Enter", "confirm"),
                    ("Esc", "cancel"),
                ],
            );
        }
        let host = [
            ("Tab", "next panel"),
            ("u", "update all"),
            ("a", "apply all"),
            ("F", "firewall"),
            ("w", "web access"),
        ];
        let (name, own): (&'static str, Vec<(&'static str, &'static str)>) = match self.focus {
            Focus::Categories => (
                "Policy",
                vec![("\u{2191}\u{2193}", "move"), ("Enter", "change")],
            ),
            Focus::Countries => (
                "Geo",
                vec![
                    ("\u{2191}\u{2193}", "move"),
                    ("Enter", "add/remove"),
                    ("m", "mode"),
                ],
            ),
            Focus::Protection => (
                "Automatic",
                vec![
                    ("\u{2191}\u{2193}", "move"),
                    ("Space", "on/off"),
                    ("Enter", "change"),
                ],
            ),
        };
        (name, own.into_iter().chain(host).collect())
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        log: &[(i64, String)],
        running_jobs: &std::collections::HashSet<crate::app::Job>,
    ) {
        // Two columns over a log. The left column is *policy* — what this
        // host blocks by category, by country, and the script those become;
        // the right column is what the host does on its own — the
        // detectors and feeds, and the cron that runs them. The log at
        // the foot is the one panel that spans both, because a message
        // can come from either side.
        //
        // On a short terminal the panel that gives is Automatic blocking
        // (`Max`), which falls back to scrolling; Scheduled tasks below it
        // holds `Min(3)` so that it is never the one that vanishes — it
        // is the panel reporting what the detectors just did.
        let [columns_area, log_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(LOG_HEIGHT)]).areas(area);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
                .areas(columns_area);

        let [settings_area, geo_area, firewall_area] = Layout::vertical([
            Constraint::Length(CATEGORIES.len() as u16 + 2),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .areas(left);
        let protection_height = self.protection_panel_height(right.width);
        let [protection_area, cron_area] =
            Layout::vertical([Constraint::Max(protection_height), Constraint::Min(3)]).areas(right);

        self.render_categories(frame, settings_area, theme);
        self.render_geo(frame, geo_area, theme);
        self.render_firewall(frame, firewall_area, theme);
        self.render_protection(frame, protection_area, theme);
        self.render_cron(frame, cron_area, theme, running_jobs);
        self.render_log(frame, log_area, theme, log);

        if let Some(popup) = self.popup.clone() {
            self.render_popup(frame, area, popup, theme);
        }
    }

    fn render_categories(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = CATEGORIES
            .iter()
            .map(|&category| ListItem::new(self.row_line(category)))
            .collect();
        let focused = self.focus == Focus::Categories;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Policy", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_geo(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> =
            std::iter::once(ListItem::new(Line::from("+ Add a country").italic()))
                .chain(
                    self.selected_countries
                        .iter()
                        .map(|cc| ListItem::new(self.country_row_line(cc))),
                )
                .collect();
        // The *mode* is in the title and nothing else is: Allowlist turns
        // the host into default-deny, so it must never be what a narrow
        // panel truncates away.
        let mode_label = match self.geo_mode {
            GeoMode::Blocklist => "blocklist",
            GeoMode::Allowlist => "allowlist",
        };
        let focused = self.focus == Focus::Countries;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel(
                format!("Geo \u{00b7} {mode_label}"),
                focused,
                theme,
            )),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.countries_state);
    }

    /// How wide one column of Automatic blocking rows has to be, and how
    /// many of them fit in `width`.
    ///
    /// Measured from the rows actually on screen rather than fixed, so a
    /// detector with a longer label than any of today's widens its column
    /// instead of being cut off. At least one column, so a terminal too
    /// narrow for even that scrolls rather than dividing by zero. The
    /// selection column ([`crate::tui::select_in`] reserves one cell) is
    /// counted in, or the last character of every row would be clipped.
    fn protection_columns(&self, width: u16) -> (u16, u16) {
        let rows = self.protection_rows();
        let widest = |f: fn(&Self, ProtectionRow) -> String| {
            rows.iter()
                .map(|row| f(self, *row).chars().count() as u16)
                .max()
                .unwrap_or(0)
        };
        let label_width = widest(Self::protection_label);
        let column_width = 1 + label_width + PROTECTION_TAG_WIDTH + widest(Self::protection_detail);
        let columns =
            (width.saturating_sub(2) / column_width.max(1)).clamp(1, rows.len().max(1) as u16);
        (label_width, columns)
    }

    /// How tall the Automatic blocking panel wants to be at this width:
    /// two border lines plus however many rows survive being dealt into
    /// columns. Asked before the layout is solved, so it takes its
    /// column's width.
    fn protection_panel_height(&self, width: u16) -> u16 {
        let (_, columns) = self.protection_columns(width);
        (self.protection_rows().len() as u16).div_ceil(columns) + 2
    }

    /// Draws the rows in as many columns as the width allows, so all of
    /// them are visible at once instead of five of fourteen.
    ///
    /// One `List` per column, filled top to bottom and then left to right,
    /// so the single selection index the key handler moves still walks
    /// them in reading order: Down at the foot of one column arrives at the
    /// head of the next. Only the column holding the selection draws a
    /// highlight, and it draws it at the row's index *within that column*.
    fn render_protection(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let rows = self.protection_rows();
        let (label_width, columns) = self.protection_columns(area.width);
        let per_column = (rows.len() as u16).div_ceil(columns) as usize;

        // The block is drawn once, around the lot; the columns are laid
        // out inside it. Rendering a bordered block per column would put a
        // line between every pair of them.
        let focused = self.focus == Focus::Protection;
        let block = crate::tui::panel("Automatic blocking", focused, theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let column_areas = Layout::horizontal(
            std::iter::repeat_n(Constraint::Ratio(1, u32::from(columns)), columns as usize)
                .collect::<Vec<_>>(),
        )
        .split(inner);

        let selected = self.protection_state.selected();
        for (column, column_area) in column_areas.iter().enumerate() {
            let first = column * per_column;
            let Some(chunk) = rows.get(first..(first + per_column).min(rows.len())) else {
                continue;
            };
            let items: Vec<ListItem> = chunk
                .iter()
                .map(|row| ListItem::new(self.protection_row_line(*row, label_width as usize)))
                .collect();
            // `Some(index)` only for the column the selection is in;
            // `None` everywhere else, so exactly one row is highlighted.
            let mut state = ListState::default();
            let in_column = selected
                .filter(|i| (first..first + chunk.len()).contains(i))
                .map(|i| i - first);
            state.select(in_column);
            let list =
                crate::tui::select_in(List::new(items), focused && in_column.is_some(), theme);
            frame.render_stateful_widget(list, *column_area, &mut state);
        }
    }

    /// What the rules become: the script, and whether the one on disk is
    /// still the one these rules would write. The summary the old Summary
    /// panel carried (sites found, bot-list freshness) is the second line,
    /// because those are the inputs the script is rendered from.
    fn render_firewall(&self, frame: &mut Frame, area: Rect, theme: Theme) {
        // Three states, not two. A fresh install has no rules at all,
        // and telling someone to press `F` there sends them to render
        // an empty script — which looks like the tool doing nothing.
        let script = match (self.rule_count, self.firewall_needs_update) {
            (0, _) => Line::from(vec![
                " no rules yet".into(),
                " \u{2014} enable a detector".fg(theme.dim()),
            ]),
            (n, true) => Line::from(vec![
                format!(" {n} rules  ").into(),
                "[ STALE ]".yellow(),
                "  F to write".fg(theme.dim()),
            ]),
            (n, false) => Line::from(vec![
                format!(" {n} rules  ").into(),
                "[ UP TO DATE ]".green(),
            ]),
        };
        let inputs = Line::from(vec![
            format!(" {} site(s)", self.site_count).into(),
            "  \u{00b7}  ".fg(theme.dim()),
            format!(
                "{}/{} bot lists fresh",
                self.up_to_date_count(),
                self.sources.len()
            )
            .into(),
        ]);
        let panel = Paragraph::new(vec![script, inputs]).block(crate::tui::panel(
            "Firewall script",
            false,
            theme,
        ));
        frame.render_widget(panel, area);
    }

    fn render_cron(
        &self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        running_jobs: &std::collections::HashSet<crate::app::Job>,
    ) {
        let lines: Vec<Line> = self
            .cron_status
            .iter()
            .map(|status| {
                let running = running_jobs.contains(&crate::app::Job::Cron(status.job));
                cron_status_line(status, running, theme)
            })
            .collect();
        let panel = Paragraph::new(lines).block(crate::tui::panel("Scheduled", false, theme));
        frame.render_widget(panel, area);
    }

    /// The newest messages, newest first, each with how long ago it
    /// appeared. The newest is drawn in the live colour: it is the one
    /// that answers "what just happened".
    fn render_log(&self, frame: &mut Frame, area: Rect, theme: Theme, log: &[(i64, String)]) {
        let rows = usize::from(area.height.saturating_sub(2)).max(1);
        let mut lines: Vec<Line> = log
            .iter()
            .rev()
            .take(rows)
            .enumerate()
            .map(|(i, (at, text))| {
                let when = format!(" {:<9}", format_relative_time(*at));
                if i == 0 {
                    Line::from(vec![when.fg(theme.live()), text.clone().into()])
                } else {
                    Line::from(vec![when.fg(theme.dim()), text.clone().fg(theme.dim())])
                }
            })
            .collect();
        if lines.is_empty() {
            lines.push(Line::from(" No recent actions.").fg(theme.dim()));
        }
        frame.render_widget(
            Paragraph::new(lines).block(crate::tui::panel("Log", false, theme)),
            area,
        );
    }

    fn row_line(&self, category: Category) -> Line<'static> {
        let mut line = vec![Span::from(format!("{:<14}", category_label(category)))];
        line.push(policy_tag(self.category_default(category)));
        Line::from(line)
    }

    fn country_row_line(&self, country_code: &str) -> Line<'static> {
        let ranges = match self.range_count(country_code) {
            Some(count) => format!("{count} range(s)"),
            None => "not yet fetched".to_string(),
        };
        // Every row currently in the list is enforced the same way — the
        // mode governs all of them at once — so the tag is a direct
        // reflection of `geo_mode`, not a per-row setting.
        let policy = match self.geo_mode {
            GeoMode::Blocklist => Policy::Blocked,
            GeoMode::Allowlist => Policy::Allowed,
        };
        Line::from(vec![
            Span::from(format!("{:<8}", country_code.to_uppercase())),
            policy_tag(policy),
            Span::from(format!(" {ranges}")),
        ])
    }

    /// The full "Automatic blocking" list: the fixed detectors followed by
    /// one row per known feed. Recomputed rather than cached so it can
    /// never disagree with `self.reputation` about how many rows exist —
    /// a stale count here would let the selection index point past the end.
    fn protection_rows(&self) -> Vec<ProtectionRow> {
        Detector::ALL
            .into_iter()
            .map(ProtectionRow::Detect)
            .chain((0..self.reputation.len()).map(ProtectionRow::Feed))
            .collect()
    }

    fn protection_label(&self, row: ProtectionRow) -> String {
        match row {
            ProtectionRow::Detect(detector) => detector.spec().label.to_string(),
            ProtectionRow::Feed(i) => self
                .reputation
                .get(i)
                .map(|s| s.name.clone())
                .unwrap_or_default(),
        }
    }

    fn protection_enabled(&self, row: ProtectionRow) -> bool {
        match row {
            ProtectionRow::Detect(detector) => self
                .detectors
                .get(&detector)
                .map(|(enabled, _)| *enabled)
                .unwrap_or(false),
            ProtectionRow::Feed(i) => self.reputation.get(i).is_some_and(|s| s.enabled),
        }
    }

    fn protection_ttl_days(&self, row: ProtectionRow) -> i64 {
        match row {
            ProtectionRow::Detect(detector) => self
                .detectors
                .get(&detector)
                .map(|(_, ttl)| *ttl)
                .unwrap_or(0),
            // Feeds have no TTL: their blocks are derived fresh at
            // render time from the stored ranges, so there's nothing to
            // expire.
            ProtectionRow::Feed(_) => 0,
        }
    }

    /// What follows a row's tag: a feed's range count (or that it has none
    /// yet), or an enabled detector's TTL. Its own method so
    /// [`Self::protection_columns`] can measure it.
    fn protection_detail(&self, row: ProtectionRow) -> String {
        match row {
            ProtectionRow::Feed(i) => match self.reputation.get(i) {
                // "not fetched" is the important state to surface: an
                // enabled feed with no ranges is silently doing nothing.
                Some(s) if s.last_fetched_at.is_none() => " not fetched".to_string(),
                Some(s) => format!(" {}", s.range_count),
                None => String::new(),
            },
            _ if self.protection_enabled(row) => format!(" {}d", self.protection_ttl_days(row)),
            _ => String::new(),
        }
    }

    fn protection_row_line(&self, row: ProtectionRow, label_width: usize) -> Line<'static> {
        let enabled = self.protection_enabled(row);
        // A dedicated ON/OFF tag rather than reusing `policy_tag`: that one
        // means "traffic is allowed/blocked", and rendering an *enabled*
        // detector as `[ BLOCKED ]` (or a disabled one as `[ ALLOWED ]`)
        // would read as the opposite of what it says. Same
        // theme-independent green as `policy_tag`'s allowed state, so the
        // two still look like one system.
        let tag = if enabled {
            Span::from("[ ON  ]").green()
        } else {
            Span::from("[ OFF ]").dim()
        };
        Line::from(vec![
            Span::from(format!(
                "{:<label_width$} ",
                self.protection_label(row),
                label_width = label_width
            )),
            tag,
            Span::from(self.protection_detail(row)),
        ])
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: Popup, theme: Theme) {
        match popup {
            // Three of the five popups are the same widget with different
            // strings: a centred list, one row per option, the selected row
            // reversed. Only the two that are *not* option lists — a text
            // field, and a multi-field form — get their own arm.
            Popup::Protection { row, selected } => render_option_list(
                frame,
                area,
                &self.protection_label(row),
                &protection_options(row.is_detector()),
                selected,
                theme,
            ),
            Popup::Category { category, selected } => render_option_list(
                frame,
                area,
                &format!("{} default", category_label(category)),
                &["Allowed".to_string(), "Blocked".to_string()],
                selected,
                theme,
            ),
            Popup::GeoMode { selected } => render_option_list(
                frame,
                area,
                "Geo mode",
                &[
                    "Blocklist (block selected countries)".to_string(),
                    "Allowlist (block everything except selected)".to_string(),
                ],
                selected,
                theme,
            ),
            Popup::AddCountry { input, error } => {
                let title = "Add a country (2-letter code)";
                let mut lines = vec![Line::from(format!("{input}\u{2588}"))];
                if let Some(err) = &error {
                    lines.push(Line::from(err.as_str()).red());
                }
                lines.push(Line::from("Enter confirm  Esc cancel").dim());
                // Same content-sized rule as the render popup below: a
                // long enough validation message would otherwise be cut
                // off exactly when it most needs reading.
                let popup_area = centered_rect(
                    widest_line(&lines).max(title.chars().count() as u16) + 4,
                    lines.len() as u16 + 2,
                    area,
                );
                let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(paragraph, popup_area);
            }
            Popup::RenderFirewall {
                backend_selected,
                out_path,
                apply_after_write,
                error,
            } => {
                let title = "Render firewall rules";

                let mut lines = vec![
                    Line::from("Backend:").bold(),
                    Line::from(vec![
                        Span::from("  [ "),
                        Span::from(match backend_selected {
                            0 => "nftables (recommended)",
                            1 => "iptables (IPv4 only)",
                            _ => "unknown",
                        })
                        .reversed(),
                        Span::from(" ]"),
                    ]),
                    Line::from(""),
                    Line::from(format!("Output: {}_", out_path)),
                    Line::from(vec![
                        Span::from("Apply after writing: "),
                        Span::from(if apply_after_write { "[x]" } else { "[ ]" }),
                    ]),
                ];
                if let Some(err) = &error {
                    lines.push(Line::from(err.as_str()).red());
                }
                lines.push(Line::from("").dim());
                lines.push(
                    Line::from("↑/↓ backend  Space apply toggle  Enter confirm  Esc cancel").dim(),
                );

                // Sized to its own content rather than to a fixed 56,
                // which was two columns short of its own key hint and cut
                // "Esc cancel" in half — and would have clipped any output
                // path longer than the default.
                let popup_area =
                    centered_rect(widest_line(&lines) + 4, lines.len() as u16 + 2, area);
                let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(paragraph, popup_area);
            }
            Popup::WebAccess {
                subdomain,
                site,
                prefix,
                host,
                error,
            } => {
                let title = "Reach this console from outside";
                // Marked with a caret as well as reversed: the selected
                // row must still be identifiable on a terminal that
                // renders reverse video poorly, or over a connection that
                // drops the attribute.
                let chosen = |on: bool, text: &str| {
                    let span = Span::from(format!("{} {text}", if on { ">" } else { " " }));
                    if on {
                        span.reversed()
                    } else {
                        span.dim()
                    }
                };
                let site_label = match self.sites.get(site) {
                    Some(name) => format!("  < {name} >"),
                    None => "  (no sites scanned yet — press s, then r)".to_string(),
                };

                let mut lines = vec![
                    Line::from("Mode:").bold(),
                    Line::from(vec![
                        Span::from("  "),
                        chosen(!subdomain, "Path on an existing site"),
                    ]),
                    Line::from(vec![
                        Span::from("  "),
                        chosen(subdomain, "Its own subdomain"),
                    ]),
                    Line::from(""),
                ];
                if subdomain {
                    lines.push(Line::from(format!("Host: {host}_")));
                    lines.push(
                        Line::from(
                            "Port 80 until certbot runs; the password would be in the clear.",
                        )
                        .dim(),
                    );
                } else {
                    lines.push(Line::from("Site:").bold());
                    lines.push(Line::from(site_label));
                    lines.push(Line::from(format!("Prefix: {prefix}_")));
                }
                if let Some(err) = &error {
                    lines.push(Line::from(err.as_str()).red());
                }
                lines.push(Line::from("").dim());
                lines.push(Line::from("↑/↓ mode  ←/→ site  Enter confirm  Esc cancel").dim());

                let popup_area = centered_rect(
                    widest_line(&lines).max(title.chars().count() as u16) + 4,
                    lines.len() as u16 + 2,
                    area,
                );
                let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
                frame.render_widget(Clear, popup_area);
                frame.render_widget(paragraph, popup_area);
            }
        }
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        // One method per popup variant. They are genuinely different
        // interactions — two of them are text fields that must swallow every
        // printable key, the rest are option lists with different clamps —
        // so this dispatches rather than trying to share a handler. What is
        // shared is the shape: each returns early, and each owns its own
        // commit.
        if self.popup.is_some() {
            return match self.popup.as_mut().expect("checked above") {
                Popup::Category { .. } => self.handle_category_popup_key(key, db, message),
                Popup::AddCountry { .. } => self.handle_add_country_popup_key(key, db, message),
                Popup::Protection { .. } => self.handle_protection_popup_key(key, db, message),
                Popup::GeoMode { .. } => self.handle_geo_mode_popup_key(key, db, message),
                Popup::RenderFirewall { .. } => self.handle_render_firewall_popup_key(key),
                Popup::WebAccess { .. } => self.handle_web_access_popup_key(key),
            };
        }

        if key.code == KeyCode::Char('m') {
            self.popup = Some(Popup::GeoMode {
                selected: match self.geo_mode {
                    GeoMode::Blocklist => 0,
                    GeoMode::Allowlist => 1,
                },
            });
            return Ok(KeyOutcome::Consumed);
        }

        // Host-wide, one key each, and deliberately not behind a popup:
        // they mirror the console's two buttons, which are one click each
        // too. Neither is irreversible — an update only downloads, and the
        // apply goes through the same anti-lockout guard the render popup
        // does (see `App::start_everything_firewall`).
        if key.code == KeyCode::Char('u') {
            return Ok(KeyOutcome::UpdateEverything);
        }
        if key.code == KeyCode::Char('a') {
            return Ok(KeyOutcome::ApplyEverything);
        }

        // 'w' opens the Web Access form — the TUI's half of the
        // console's panel of the same name.
        if key.code == KeyCode::Char('w') {
            self.popup = Some(Popup::WebAccess {
                subdomain: false,
                site: 0,
                prefix: crate::webaccess::DEFAULT_PREFIX.to_string(),
                host: String::new(),
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }

        // Tab always means "next panel" on this screen (BackTab the
        // previous), so it means the same thing it does on Site settings
        // and Dynamic Protection. Up/Down still flow across the panels
        // too, for hands that never learned Tab.
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            let forward = key.code == KeyCode::Tab;
            self.focus = match (self.focus, forward) {
                (Focus::Categories, true) | (Focus::Protection, false) => Focus::Countries,
                (Focus::Countries, true) | (Focus::Categories, false) => Focus::Protection,
                (Focus::Protection, true) | (Focus::Countries, false) => Focus::Categories,
            };
            match self.focus {
                Focus::Categories if self.list_state.selected().is_none() => {
                    self.list_state.select(Some(0));
                }
                Focus::Countries if self.countries_state.selected().is_none() => {
                    self.countries_state.select(Some(0));
                }
                Focus::Protection if self.protection_state.selected().is_none() => {
                    self.protection_state.select(Some(0));
                }
                _ => {}
            }
            return Ok(KeyOutcome::Consumed);
        }

        // Capital F: it writes to the host. Lower-case `f` is "filter" on
        // every screen that has a list worth filtering, and this one does
        // not, so the key is free rather than overloaded.
        if key.code == KeyCode::Char('F') {
            self.popup = Some(Popup::RenderFirewall {
                backend_selected: 0, // default to nftables (recommended)
                out_path: crate::firewall::DEFAULT_OUTPUT_PATH.to_string(),
                apply_after_write: false,
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }

        match self.focus {
            Focus::Categories => match key.code {
                // No popup open: let `App`'s global handling decide (Esc/q
                // quit from the Dashboard).
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.list_state.selected() == Some(CATEGORIES.len() - 1) {
                        self.focus = Focus::Countries;
                        self.countries_state.select(Some(0));
                    } else {
                        self.list_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.open_category_popup(),
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Countries => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.countries_state.selected() == Some(0) {
                        self.focus = Focus::Categories;
                        self.list_state.select(Some(CATEGORIES.len() - 1));
                    } else {
                        self.countries_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    // The Countries list has one row per selected country
                    // plus the fixed "+ Add a country" row at index 0, so
                    // its last index is `len()`, not `len() - 1`.
                    if self.countries_state.selected() == Some(self.selected_countries.len()) {
                        self.focus = Focus::Protection;
                        self.protection_state.select(Some(0));
                    } else {
                        self.countries_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return self.activate_country_row(message, db);
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Protection => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.protection_state.selected() == Some(0) {
                        self.focus = Focus::Countries;
                        self.countries_state
                            .select(Some(self.selected_countries.len()));
                    } else {
                        self.protection_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.protection_state.selected().unwrap_or(0) + 1
                        < self.protection_rows().len()
                    {
                        self.protection_state.select_next();
                    }
                }
                KeyCode::Enter => self.open_protection_popup(),
                // Space flips the switch where it stands. Detectors and
                // feeds are booleans first and a TTL second; Enter is
                // still there for the TTL.
                KeyCode::Char(' ') => return self.toggle_protection_row(db, message),
                _ => return Ok(KeyOutcome::Ignored),
            },
        }
        Ok(KeyOutcome::Consumed)
    }

    /// Space on an "Automatic blocking" row: off if it is on, on if it is
    /// off — keeping a detector's TTL, so switching one back on restores
    /// what was there. Goes through [`Self::commit_protection`] so a feed
    /// that has never been fetched still gets its download.
    fn toggle_protection_row(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(row) = self
            .protection_state
            .selected()
            .and_then(|i| self.protection_rows().get(i).copied())
        else {
            return Ok(KeyOutcome::Consumed);
        };
        let selected = if self.protection_enabled(row) {
            0
        } else if !row.is_detector() {
            1
        } else {
            let ttl = self.protection_ttl_days(row);
            PROTECTION_TTL_CHOICES
                .iter()
                .position(|choice| *choice == ttl)
                .map(|i| i + 1)
                .unwrap_or(1)
        };
        self.commit_protection(db, row, selected, message)
    }

    /// Opens the edit popup for the focused "Automatic blocking" row,
    /// pre-selected on its current state so confirming without moving is a
    /// no-op. A currently-enabled detector whose TTL isn't one of
    /// [`PROTECTION_TTL_CHOICES`] (set via the CLI, which takes any number
    /// of days) still shows as enabled: it lands on the closest offered
    /// choice rather than falling back to "Off", which would misrepresent
    /// the detector as switched off.
    fn open_protection_popup(&mut self) {
        let Some(row) = self
            .protection_state
            .selected()
            .and_then(|i| self.protection_rows().get(i).copied())
        else {
            return;
        };
        let selected = if !self.protection_enabled(row) {
            0
        } else if !row.is_detector() {
            1
        } else {
            let ttl = self.protection_ttl_days(row);
            let closest = PROTECTION_TTL_CHOICES
                .iter()
                .enumerate()
                .min_by_key(|(_, choice)| (*choice - ttl).abs())
                .map(|(i, _)| i)
                .unwrap_or(0);
            closest + 1
        };
        self.popup = Some(Popup::Protection { row, selected });
    }

    /// Persists a confirmed "Automatic blocking" popup. Option 0 disables
    /// the detector and leaves its TTL alone (so re-enabling restores what
    /// was there rather than resetting it); any other option enables it and
    /// writes that TTL.
    fn commit_protection(
        &mut self,
        db: &Db,
        row: ProtectionRow,
        selected: usize,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if let ProtectionRow::Feed(i) = row {
            return self.commit_feed(db, i, selected == 1, message);
        }
        let ProtectionRow::Detect(detector) = row else {
            unreachable!("feeds are committed by commit_feed")
        };
        let label = self.protection_label(row);
        if selected == 0 {
            detector.set_enabled(db, false)?;
            *message = Some(format!("{label} detection off"));
            return Ok(KeyOutcome::Mutated);
        }
        let ttl = PROTECTION_TTL_CHOICES
            .get(selected - 1)
            .copied()
            .unwrap_or(PROTECTION_TTL_CHOICES[0]);
        detector.set_enabled(db, true)?;
        detector.set_ttl_days(db, ttl)?;
        *message = Some(format!("{label} detection on, blocking for {ttl} day(s)"));
        Ok(KeyOutcome::Mutated)
    }

    /// Switches one third-party CIDR feed on or off. Enabling a feed that
    /// has never been fetched also asks `App` to download it
    /// (`KeyOutcome::FetchReputationSource`) — enabling something with no
    /// data would otherwise look like it worked while doing nothing at
    /// all. Enabling an already-fetched feed needs no network round trip
    /// and just returns `Mutated`, the same split the country-select
    /// action already makes.
    ///
    /// Disabling never deletes the stored ranges, so switching a feed back
    /// on is instant.
    fn commit_feed(
        &mut self,
        db: &Db,
        index: usize,
        enabled: bool,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(source) = self.reputation.get(index).cloned() else {
            return Ok(KeyOutcome::Consumed);
        };
        if source.enabled == enabled {
            return Ok(KeyOutcome::Consumed);
        }
        db.set_reputation_source_enabled(&source.id, enabled)?;
        if !enabled {
            *message = Some(format!("{} off", source.name));
            return Ok(KeyOutcome::Mutated);
        }

        // Surfaced on enable, not buried in a doc comment: the provider
        // feeds block every visitor hosted there, and unlike a detector
        // there's no behavioural evidence behind it.
        let warning = crate::ipranges::reputation::ReputationSourceKind::from_id(&source.id)
            .and_then(|k| k.warning())
            .map(|w| format!(" — {w}"))
            .unwrap_or_default();

        if source.last_fetched_at.is_none() {
            *message = Some(format!("{} on, fetching…{warning}", source.name));
            return Ok(KeyOutcome::FetchReputationSource(source.id));
        }
        *message = Some(format!(
            "{} on ({} range(s)) — render the firewall (f) to apply{warning}",
            source.name, source.range_count
        ));
        Ok(KeyOutcome::Mutated)
    }

    /// One category default: Allowed (0) or Blocked (1).
    fn handle_category_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::Category { selected, .. }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = (*selected + 1).min(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let Some(Popup::Category { category, selected }) = self.popup.take() else {
                    unreachable!("checked above")
                };
                let policy = match selected {
                    0 => Policy::Allowed,
                    _ => Policy::Blocked,
                };
                db.set_category_default(category, policy)?;
                *message = Some(format!(
                    "{} default set to {policy:?}",
                    category_label(category)
                ));
                Ok(KeyOutcome::Mutated)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// The add-a-country text field. Owns every printable key, so it
    /// must be matched before anything that reads a bare `Char` as a
    /// command.
    fn handle_add_country_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::AddCountry { input, error }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Backspace => {
                input.pop();
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char(c) if c.is_ascii_alphabetic() && input.len() < 2 => {
                input.push(c.to_ascii_lowercase());
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter => {
                let code = input.clone();
                match ipranges::validate_country_code(&code) {
                    Err(_) => {
                        *error = Some("Enter a 2-letter country code".to_string());
                        Ok(KeyOutcome::Consumed)
                    }
                    Ok(cc) => {
                        self.popup = None;
                        if self.selected_countries.iter().any(|b| b == &cc) {
                            *message = Some(format!("{} is already selected", cc.to_uppercase()));
                            return Ok(KeyOutcome::Consumed);
                        }
                        if self.fetched_countries.iter().any(|(c, _, _)| c == &cc) {
                            db.set_country_selected(&cc, true)?;
                            let verb = match self.geo_mode {
                                GeoMode::Blocklist => "Blocked",
                                GeoMode::Allowlist => "Allowed",
                            };
                            *message = Some(format!("{verb} {}", cc.to_uppercase()));
                            return Ok(KeyOutcome::Mutated);
                        }
                        Ok(KeyOutcome::SelectCountry(cc))
                    }
                }
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// One "Automatic blocking" row. Its option count varies by row kind
    /// — a detector offers Off plus a TTL per choice, a feed only Off/On —
    /// so the down-clamp is computed rather than a literal.
    fn handle_protection_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::Protection { row, selected }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let last = protection_options(row.is_detector()).len() - 1;
                *selected = (*selected + 1).min(last);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let (row, selected) = (*row, *selected);
                self.popup = None;
                self.commit_protection(db, row, selected, message)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Blocklist (0) or Allowlist (1).
    fn handle_geo_mode_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::GeoMode { selected }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = (*selected + 1).min(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let Some(Popup::GeoMode { selected }) = self.popup.take() else {
                    unreachable!("checked above")
                };
                let mode = match selected {
                    0 => GeoMode::Blocklist,
                    _ => GeoMode::Allowlist,
                };
                db.set_geo_mode(mode)?;
                *message = Some(match mode {
                    GeoMode::Blocklist => {
                        "Geo mode set to Blocklist: selected countries are blocked, everything else is allowed".to_string()
                    }
                    GeoMode::Allowlist => {
                        "Geo mode set to Allowlist: selected countries are the ONLY ones allowed, everything else will be blocked host-wide once render-firewall runs".to_string()
                    }
                });
                Ok(KeyOutcome::Mutated)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// The firewall render form: a backend choice, an editable output
    /// path, and an apply-after-write toggle. The only popup here whose
    /// `Char` handling is text entry rather than navigation, which is why
    /// `j`/`k` must reach the path field — there is a regression test for
    /// exactly that.
    fn handle_render_firewall_popup_key(&mut self, key: KeyEvent) -> Result<KeyOutcome> {
        let Some(Popup::RenderFirewall {
            backend_selected,
            out_path,
            apply_after_write,
            error,
        }) = &mut self.popup
        else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            // Arrow keys only here, deliberately no `j`/`k` vim
            // aliases (unlike every other popup/list in this app):
            // this popup has a free-text output-path field, and
            // `j`/`k` are common path characters — aliasing them to
            // navigation would silently eat any literal 'j'/'k' the
            // admin tries to type instead of appending it (caught by
            // `pressing_f_then_enter_refreshes_the_dashboards_stale_indicator`
            // flaking whenever a temp-dir path happened to contain
            // one).
            KeyCode::Up => {
                *backend_selected = backend_selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down => {
                *backend_selected = (*backend_selected + 1).min(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char(' ') => {
                *apply_after_write = !*apply_after_write;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char(c) if c.is_ascii_punctuation() || c.is_ascii_alphanumeric() => {
                out_path.push(c);
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Backspace => {
                out_path.pop();
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter => {
                let Some(Popup::RenderFirewall {
                    backend_selected,
                    out_path,
                    apply_after_write,
                    ..
                }) = self.popup.take()
                else {
                    unreachable!("checked above")
                };
                let backend = match backend_selected {
                    0 => crate::firewall::FirewallBackend::Nftables,
                    _ => crate::firewall::FirewallBackend::Iptables,
                };
                // Validate the path is not empty
                if out_path.is_empty() {
                    self.popup = Some(Popup::RenderFirewall {
                        backend_selected,
                        out_path,
                        apply_after_write,
                        error: Some("Enter an output path".to_string()),
                    });
                    return Ok(KeyOutcome::Consumed);
                }
                Ok(KeyOutcome::RenderFirewall {
                    backend,
                    out_path,
                    force: false,
                    apply: apply_after_write,
                })
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Mode with Up/Down, the site with Left/Right, and one text field
    /// whose meaning follows the mode.
    ///
    /// Arrow keys only, no `j`/`k` aliases, for the reason the render
    /// popup's handler spells out: both fields here are free text, and a
    /// host name or a path prefix may contain either letter.
    fn handle_web_access_popup_key(&mut self, key: KeyEvent) -> Result<KeyOutcome> {
        let site_count = self.sites.len();
        let Some(Popup::WebAccess {
            subdomain,
            site,
            prefix,
            host,
            error,
        }) = &mut self.popup
        else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up => {
                *subdomain = false;
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down => {
                *subdomain = true;
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Left => {
                *site = site.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Right => {
                *site = (*site + 1).min(site_count.saturating_sub(1));
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char(c) if c.is_ascii_punctuation() || c.is_ascii_alphanumeric() => {
                if *subdomain { host } else { prefix }.push(c);
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Backspace => {
                if *subdomain { host } else { prefix }.pop();
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter => {
                if *subdomain {
                    let request = crate::webaccess::Request::Subdomain { host: host.clone() };
                    self.popup = None;
                    return Ok(KeyOutcome::SetWebAccess(request));
                }
                // Refused here rather than in `webaccess::plan`, which
                // never sees the empty list: with nothing scanned there is
                // no site to name, and the honest answer is to say so and
                // leave the form open.
                let Some(site) = self.sites.get(*site).cloned() else {
                    *error = Some("No sites scanned yet — press s, then r.".to_string());
                    return Ok(KeyOutcome::Consumed);
                };
                let request = crate::webaccess::Request::Path {
                    site,
                    prefix: prefix.clone(),
                };
                self.popup = None;
                Ok(KeyOutcome::SetWebAccess(request))
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    fn open_category_popup(&mut self) {
        let Some(selected) = self.list_state.selected() else {
            return;
        };
        let Some(&category) = CATEGORIES.get(selected) else {
            return;
        };
        let selected_option = match self.category_default(category) {
            Policy::Allowed => 0,
            Policy::Blocked => 1,
        };
        self.popup = Some(Popup::Category {
            category,
            selected: selected_option,
        });
    }

    /// Handles Enter/Space on the Countries list: opens the add-country
    /// input popup on row 0, or directly unblocks the selected country
    /// (see this module's doc comment for why that's a direct action rather
    /// than a popup).
    fn activate_country_row(
        &mut self,
        message: &mut Option<String>,
        db: &Db,
    ) -> Result<KeyOutcome> {
        let Some(selected) = self.countries_state.selected() else {
            return Ok(KeyOutcome::Consumed);
        };
        if selected == 0 {
            self.popup = Some(Popup::AddCountry {
                input: String::new(),
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }
        let Some(country_code) = self.selected_countries.get(selected - 1) else {
            return Ok(KeyOutcome::Consumed);
        };
        db.set_country_selected(country_code, false)?;
        *message = Some(format!("Removed {}", country_code.to_uppercase()));
        Ok(KeyOutcome::Mutated)
    }
}

/// Renders a centred "pick one of these" popup: one row per option, the
/// selected row reversed, sized to the widest of the options and the title.
///
/// Shared by every option-list popup on this screen. The two that are not
/// option lists — the country text field and the firewall render form —
/// deliberately keep their own rendering, since neither is a list and
/// forcing them through here would mean parameters that only one caller
/// ever uses.
/// A popup that is a list of choices, one of them selected.
///
/// Shared with Site settings rather than copied: there were two of these,
/// and only one of them grew the "Esc cancel" hint.
pub(crate) fn render_option_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    options: &[String],
    selected: usize,
    theme: Theme,
) {
    let content_width = options
        .iter()
        .map(|o| o.len())
        .max()
        .unwrap_or(0)
        .max(title.len());
    // The way out, in the frame. Every *form* popup already says this;
    // the option lists did not, so the one popup shape with no text
    // besides its choices was also the one that never mentioned Esc.
    const HINT: &str = "Enter choose  Esc cancel";
    let popup_area = centered_rect(
        (content_width.max(HINT.len()) as u16) + 4,
        options.len() as u16 + 3,
        area,
    );
    let items: Vec<ListItem> = options
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let line = Line::from(label.clone());
            ListItem::new(if i == selected { line.reversed() } else { line })
        })
        .chain(std::iter::once(ListItem::new(Line::from(HINT).dim())))
        .collect();
    let list = List::new(items).block(crate::tui::popup(title, theme));
    frame.render_widget(Clear, popup_area);
    frame.render_widget(list, popup_area);
}

/// The "Automatic blocking" popup's options: "Off", then one "On" row per
/// [`PROTECTION_TTL_CHOICES`] entry. Built in one place so the renderer and
/// the key handler can never disagree about how many rows there are or what
/// index means what — the same reason Site settings has its own
/// `setting_options`.
fn protection_options(is_detector: bool) -> Vec<String> {
    if !is_detector {
        // A feed has no TTL to choose: its blocks are derived fresh from
        // the stored ranges every time the firewall is rendered, so there
        // is nothing that expires.
        return vec!["Off".to_string(), "On".to_string()];
    }
    std::iter::once("Off".to_string())
        .chain(PROTECTION_TTL_CHOICES.iter().map(|days| {
            if *days == 1 {
                "On — block for 1 day".to_string()
            } else {
                format!("On — block for {days} days")
            }
        }))
        .collect()
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Scanner => "Scanners",
        Category::Search => "Search Bots",
        Category::Ai => "AI Bots",
    }
}

fn policy_tag(policy: Policy) -> Span<'static> {
    match policy {
        Policy::Allowed => " [ ALLOWED ] ".green(),
        Policy::Blocked => " [ BLOCKED ] ".red(),
    }
}

/// Renders one line of the "Scheduled tasks" panel: the job's label, when
/// it last ran (or "never"), and its last outcome — or, if it's currently
/// running in the background (`running`) or due but not yet started, that
/// instead (the outcome shown would otherwise be stale the moment a job
/// becomes due again, misleadingly implying nothing's changed since).
/// The width of the longest of `lines`, for sizing a popup to hold them.
///
/// Popups used to carry hardcoded widths, which is fine right up until
/// someone edits the text inside one — and then the thing that gets cut
/// off is a key hint or a validation message, i.e. the part that was
/// there to be read.
fn widest_line(lines: &[Line<'_>]) -> u16 {
    lines
        .iter()
        .map(|line| line.width() as u16)
        .max()
        .unwrap_or(0)
}

/// The `[ ON  ]`/`[ OFF ]` tag, plus the gutter either side of it.
/// The Log panel: two border lines and two messages. The newest is the
/// one that matters; the one before it is context.
const LOG_HEIGHT: u16 = 4;

const PROTECTION_TAG_WIDTH: u16 = 9;

fn cron_status_line(status: &crate::cron::JobStatus, running: bool, theme: Theme) -> Line<'static> {
    let last_run = match status.last_run {
        Some(t) => format_relative_time(t),
        None => "never".to_string(),
    };
    // Deliberately compact (no fixed-width padding): the panel has no
    // wrapping, so a long label/summary combination must fit the column's
    // width rather than get silently clipped.
    let mut line = vec![
        format!(" {}: ", status.job.label()).into(),
        format!("{last_run}, ").fg(theme.dim()),
    ];
    line.push(if running {
        format!("{} running now", crate::tui::spinner_frame()).fg(theme.live())
    } else if status.due {
        "due now".into()
    } else {
        status
            .last_summary
            .clone()
            .unwrap_or_else(|| "-".to_string())
            .into()
    });
    Line::from(line)
}

/// Formats a Unix timestamp `t` (assumed to be in the past) as a short
/// "Nd"/"Nh"/"Nm"/"just now" relative-time string for the "Scheduled
/// tasks" panel — coarser precision the further back `t` is, matching how
/// `main.rs::format_expiry` rounds an upcoming expiry the same way.
fn format_relative_time(t: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let elapsed = (now - t).max(0);
    if elapsed < 60 {
        "just now".to_string()
    } else if elapsed < 3_600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("{}h ago", elapsed / 3_600)
    } else {
        format!("{}d ago", elapsed / 86_400)
    }
}

/// Whether the firewall's current rule set differs from what was in effect
/// at the last successful render — see the `Dashboard::firewall_needs_update`
/// field doc for what this drives. Never reads the on-disk script itself:
/// comparing a signature the app itself persisted on the last successful
/// write (`Db::get_firewall_rendered_signature`) keeps this hermetic (no
/// dependency on a real system path existing) and correctly reflects "did
/// the desired rules change since our own last render", not "does some
/// file's bytes happen to match", which is also unaffected by which
/// backend/output path that last render used (see `rules_signature`'s doc).
fn firewall_needs_update(db: &Db) -> Result<bool> {
    let current = crate::firewall::rules_signature(&crate::firewall::all_rules(db)?);
    Ok(db.get_firewall_rendered_signature()?.as_deref() != Some(current.as_str()))
}

fn is_stale(last_fetched_at: Option<i64>) -> bool {
    let Some(last_fetched_at) = last_fetched_at else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now - last_fetched_at > STALE_AFTER_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Db, NewBot};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn is_stale_treats_never_fetched_as_stale() {
        assert!(is_stale(None));
    }

    #[test]
    fn is_stale_treats_recent_fetch_as_fresh() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(!is_stale(Some(now)));
    }

    #[test]
    fn is_stale_treats_old_fetch_as_stale() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(is_stale(Some(now - STALE_AFTER_SECS - 1)));
    }

    /// The size every render test in this file draws at.
    ///
    /// Comfortably above the 80x30 the README documents as the minimum.
    /// Several of these used to draw at 60x28 — below what the product
    /// claims to support — and only said so the day a panel grew tall
    /// enough to push another one off a screen no user has.
    fn test_terminal() -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(100, 32)).unwrap()
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn format_relative_time_rounds_to_the_coarsest_useful_unit() {
        assert_eq!(format_relative_time(now_secs() - 30), "just now");
        assert_eq!(format_relative_time(now_secs() - 5 * 60), "5m ago");
        assert_eq!(format_relative_time(now_secs() - 3 * 3_600), "3h ago");
        assert_eq!(format_relative_time(now_secs() - 2 * 86_400), "2d ago");
    }

    #[test]
    fn cron_status_line_shows_never_and_due_now_for_an_unrun_job() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::Detect(Detector::SshScanners),
            last_run: None,
            last_summary: None,
            due: true,
        };
        let rendered = cron_status_line(&status, false, Theme::Dark).to_string();
        assert!(rendered.contains("never"), "rendered was:\n{rendered}");
        assert!(rendered.contains("due now"), "rendered was:\n{rendered}");
    }

    #[test]
    fn cron_status_line_shows_last_run_and_summary_for_a_completed_job() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::Detect(Detector::WebScanners),
            last_run: Some(now_secs() - 3_600),
            last_summary: Some("blocked 2 IP(s)".to_string()),
            due: false,
        };
        let rendered = cron_status_line(&status, false, Theme::Dark).to_string();
        assert!(rendered.contains("1h ago"), "rendered was:\n{rendered}");
        assert!(
            rendered.contains("blocked 2 IP(s)"),
            "rendered was:\n{rendered}"
        );
        assert!(!rendered.contains("due now"), "rendered was:\n{rendered}");
    }

    /// `running` must override both "due now" and any stale summary with a
    /// "Running now" indicator — the frame character itself is
    /// time-derived, so only the fixed label is asserted here, not a
    /// specific spinner glyph.
    #[test]
    fn cron_status_line_shows_running_now_when_a_job_is_in_flight() {
        let status = crate::cron::JobStatus {
            job: crate::cron::CronJob::RenderFirewall,
            last_run: Some(now_secs() - 3_600),
            last_summary: Some("wrote 3 rule(s) to /etc/stop-bots/firewall.nft".to_string()),
            due: true,
        };
        let rendered = cron_status_line(&status, true, Theme::Dark).to_string();
        assert!(rendered.contains("running now"), "rendered was: {rendered}");
        assert!(!rendered.contains("due now"), "rendered was: {rendered}");
        assert!(
            !rendered.contains("wrote 3 rule(s)"),
            "rendered was: {rendered}"
        );
    }

    #[test]
    fn render_shows_the_scheduled_tasks_panel() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(
            crate::cron::CronJob::Detect(Detector::SshScanners).id(),
            now_secs(),
            "blocked 3 IP(s)",
        )
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Scheduled"), "content was:\n{content}");
        assert!(
            content.contains("Block SSH scanners"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("blocked 3 IP(s)"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("Update crawler IP ranges"),
            "content was:\n{content}"
        );
        assert!(content.contains("due now"), "content was:\n{content}");
    }

    #[test]
    fn render_shows_running_now_for_a_job_in_the_running_set() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(
            crate::cron::CronJob::Detect(Detector::SshScanners).id(),
            now_secs(),
            "blocked 3 IP(s)",
        )
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let running_jobs = std::collections::HashSet::from([crate::app::Job::Cron(
            crate::cron::CronJob::Detect(Detector::SshScanners),
        )]);
        let mut terminal = test_terminal();
        terminal
            .draw(|frame| dashboard.render(frame, frame.area(), Theme::Dark, &[], &running_jobs))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("running now"), "content was: {content}");
        assert!(
            !content.contains("blocked 3 IP(s)"),
            "content was: {content}"
        );
    }

    #[test]
    fn render_shows_the_summary_panel() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Firewall script"),
            "content was:\n{content}"
        );
        assert!(content.contains("1 site(s)"), "content was:\n{content}");
    }

    #[test]
    fn refresh_loads_counts_from_db() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        assert_eq!(dashboard.site_count, 1);
        assert_eq!(dashboard.scanner_default, Policy::Blocked);
        assert_eq!(dashboard.search_default, Policy::Allowed);
        assert_eq!(dashboard.ai_default, Policy::Blocked);
        assert_eq!(dashboard.list_state.selected(), Some(0));
    }

    #[test]
    fn refresh_counts_stale_and_fresh_sources_separately() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "fresh".to_string(),
            name: "Fresh Source".to_string(),
            url: "https://example.invalid/fresh".to_string(),
            last_fetched_at: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            ),
            bot_count: 1,
        })
        .unwrap();
        db.upsert_source(&Source {
            id: "stale".to_string(),
            name: "Stale Source".to_string(),
            url: "https://example.invalid/stale".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        assert_eq!(dashboard.up_to_date_count(), 1);
        assert_eq!(dashboard.needs_update_count(), 1);
    }

    #[test]
    fn render_shows_overview_stats_and_messages() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();
        // upsert_bot requires a source to exist (foreign key); not needed here.
        let _ = NewBot {
            slug: "unused".to_string(),
            name: "unused".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "unused".to_string(),
            source_id: "unused".to_string(),
        };

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[(now_secs(), "Stored 4 bot(s)".to_string())],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Scanners"), "content was:\n{content}");
        assert!(content.contains("BLOCKED"), "content was:\n{content}");
        assert!(content.contains("1 site(s)"), "content was:\n{content}");
        assert!(
            content.contains("Stored 4 bot(s)"),
            "content was:\n{content}"
        );
    }

    #[test]
    fn down_then_up_moves_selection_and_back() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.list_state.selected(), Some(1));

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.list_state.selected(), Some(0));
    }

    #[test]
    fn enter_opens_popup_at_current_value() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        // Row 0 is Scanners, default Blocked.

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::Category { category, selected } => {
                assert_eq!(category, Category::Scanner);
                assert_eq!(selected, 1); // Blocked
            }
            other => panic!("expected a Category popup, got {other:?}"),
        }
    }

    #[test]
    fn confirming_popup_writes_through_and_closes() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        // Move selection to "Allowed" and confirm.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Allowed
        );
        assert!(message.unwrap().contains("Scanners"));
    }

    #[test]
    fn escape_closes_popup_without_saving() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Blocked
        );
    }

    #[test]
    fn escape_with_no_popup_is_ignored_so_app_can_quit() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Ignored);
    }

    #[test]
    fn down_past_the_last_category_moves_focus_into_countries() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        for _ in 0..CATEGORIES.len() - 1 {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
                .unwrap();
        }
        assert_eq!(dashboard.focus, Focus::Categories);

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(dashboard.focus, Focus::Countries);
        assert_eq!(dashboard.countries_state.selected(), Some(0));
    }

    #[test]
    fn up_from_the_first_country_row_moves_focus_back_to_categories() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(0));

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();

        assert_eq!(dashboard.focus, Focus::Categories);
        assert_eq!(dashboard.list_state.selected(), Some(CATEGORIES.len() - 1));
    }

    #[test]
    fn enter_on_add_country_row_opens_the_input_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(0));

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::AddCountry { input, error } => {
                assert!(input.is_empty());
                assert!(error.is_none());
            }
            other => panic!("expected an AddCountry popup, got {other:?}"),
        }
    }

    #[test]
    fn add_country_popup_rejects_an_invalid_code_and_stays_open() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "u".to_string(),
            error: None,
        });

        let mut message = None;
        // Only one character typed: Enter should reject it as too short.
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.unwrap() {
            Popup::AddCountry { error, .. } => assert!(error.is_some()),
            other => panic!("expected an AddCountry popup, got {other:?}"),
        }
    }

    #[test]
    fn add_country_popup_confirming_an_unfetched_code_returns_select_country() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::SelectCountry("nl".to_string()));
        assert!(dashboard.popup.is_none());
    }

    #[test]
    fn add_country_popup_confirming_an_already_fetched_code_selects_it_directly() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(
            db.list_selected_countries().unwrap(),
            vec!["nl".to_string()]
        );
        // Default geo mode is Blocklist, so selecting a country blocks it.
        assert!(message.unwrap().contains("Blocked NL"));
    }

    #[test]
    fn add_country_popup_confirming_an_already_selected_code_is_a_noop_with_a_message() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.unwrap().contains("already selected"));
    }

    #[test]
    fn typing_and_backspacing_in_the_add_country_popup_edits_the_input() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: String::new(),
            error: None,
        });

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('N')), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('L')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::AddCountry { input, .. }) => assert_eq!(input, "nl"),
            _ => panic!("expected an AddCountry popup"),
        }

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Backspace), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::AddCountry { input, .. }) => assert_eq!(input, "n"),
            _ => panic!("expected an AddCountry popup"),
        }
    }

    #[test]
    fn enter_on_a_selected_country_row_removes_it_directly() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(1)); // row 0 is "Add", row 1 is "nl"

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_selected_countries().unwrap().is_empty());
        assert!(message.unwrap().contains("Removed NL"));
    }

    /// Regression test: unblocking the *last* selected row must not leave
    /// `countries_state` pointing past the new last row. `refresh()` only
    /// reseeds the selection when it's `None`, so a naive implementation
    /// leaves a stale out-of-range index after the list shrinks out from
    /// under it.
    #[test]
    fn removing_the_last_selected_country_clamps_the_selection() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        // Rows: 0 = Add, 1 = nl, 2 = us. Select the last one and remove it.
        dashboard.countries_state.select(Some(2));

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Mutated);
        dashboard.refresh(&db).unwrap();

        // Only "Add" (0) and "nl" (1) remain; the stale index 2 must have
        // been clamped down to 1, not left pointing past the end.
        assert_eq!(dashboard.countries_state.selected(), Some(1));
    }

    #[test]
    fn render_shows_the_geo_blocking_panel_and_selected_countries() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("Geo"), "content was:\n{content}");
        assert!(content.contains("blocklist"), "content was:\n{content}");
        assert!(content.contains("Add a country"), "content was:\n{content}");
        assert!(content.contains("NL"), "content was:\n{content}");
        assert!(content.contains("1 range(s)"), "content was:\n{content}");
    }

    #[test]
    fn m_key_opens_the_geo_mode_popup_at_the_current_mode() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('m')), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::GeoMode { selected } => assert_eq!(selected, 0), // Blocklist
            other => panic!("expected a GeoMode popup, got {other:?}"),
        }
    }

    #[test]
    fn confirming_the_geo_mode_popup_switches_mode_and_reflects_in_new_messages() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode { selected: 0 });

        let mut message = None;
        // Move to "Allowlist" and confirm.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(dashboard.popup.is_none());
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Allowlist);
        assert!(message.unwrap().contains("Allowlist"));

        // Selecting a country now reads "Allowed", not "Blocked".
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: "nl".to_string(),
            error: None,
        });
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(message.unwrap().contains("Allowed NL"));
    }

    #[test]
    fn escape_closes_the_geo_mode_popup_without_changing_it() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode { selected: 1 });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.popup.is_none());
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Blocklist);
    }

    /// The popup is sized from its own content, and the thing that goes
    /// first when it is not is the key hint on the last line — which is
    /// how the render popup once shipped with "Esc cancel" cut in half.
    #[test]
    fn the_web_access_popup_draws_its_whole_key_hint_in_both_modes() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example")
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        for keys in [vec!['w'], vec!['w', 'x']] {
            dashboard.popup = None;
            for key in keys {
                let code = if key == 'w' {
                    KeyCode::Char('w')
                } else {
                    KeyCode::Down
                };
                dashboard
                    .handle_key(KeyEvent::from(code), &db, &mut message)
                    .unwrap();
            }

            let mut terminal = test_terminal();
            terminal
                .draw(|frame| {
                    dashboard.render(
                        frame,
                        frame.area(),
                        Theme::Dark,
                        &[],
                        &std::collections::HashSet::new(),
                    )
                })
                .unwrap();
            let content = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();

            assert!(content.contains("Esc cancel"), "content was:\n{content}");
            assert!(
                content.contains("Reach this console from outside"),
                "content was:\n{content}"
            );
        }
    }

    /// The Web Access popup in path mode hands back the site it is
    /// pointing at, not the one the operator typed — there is nothing to
    /// type, which is the point of picking from the scanned list.
    #[test]
    fn w_then_enter_asks_to_mount_the_console_on_the_selected_site() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("a.example.com", "/etc/nginx/sites-enabled/a")
            .unwrap();
        db.upsert_site("b.example.com", "/etc/nginx/sites-enabled/b")
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('w')), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Right), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(
            outcome,
            KeyOutcome::SetWebAccess(crate::webaccess::Request::Path {
                site: "b.example.com".to_string(),
                prefix: crate::webaccess::DEFAULT_PREFIX.to_string(),
            })
        );
        assert!(dashboard.popup.is_none());
    }

    /// Switching modes must not throw away what was typed in the other
    /// one, which is why the popup keeps two fields rather than one.
    #[test]
    fn the_web_access_popup_keeps_both_fields_across_a_mode_switch() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('w')), &db, &mut message)
            .unwrap();
        // Clear the default prefix and type another.
        for _ in 0..crate::webaccess::DEFAULT_PREFIX.len() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Backspace), &db, &mut message)
                .unwrap();
        }
        for c in "/admin/".chars() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char(c)), &db, &mut message)
                .unwrap();
        }
        // Down to subdomain mode, type a host, back up again.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        for c in "console.example.com".chars() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char(c)), &db, &mut message)
                .unwrap();
        }
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();

        match dashboard.popup.as_ref().unwrap() {
            Popup::WebAccess {
                subdomain,
                prefix,
                host,
                ..
            } => {
                assert!(!subdomain);
                assert_eq!(prefix, "/admin/");
                assert_eq!(host, "console.example.com");
            }
            other => panic!("the popup changed: {other:?}"),
        }
    }

    /// With nothing scanned there is no site to name, and the form says so
    /// rather than sending `App` a request that cannot be planned.
    #[test]
    fn the_web_access_popup_refuses_path_mode_with_no_scanned_sites() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('w')), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.as_ref().unwrap() {
            Popup::WebAccess { error, .. } => {
                assert!(error.as_deref().unwrap_or_default().contains("No sites"))
            }
            other => panic!("the popup changed: {other:?}"),
        }
    }

    /// Subdomain mode is the other half: one typed host, no site list.
    #[test]
    fn the_web_access_popup_asks_for_a_subdomain_when_that_mode_is_picked() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('w')), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        for c in "console.example.com".chars() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char(c)), &db, &mut message)
                .unwrap();
        }
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(
            outcome,
            KeyOutcome::SetWebAccess(crate::webaccess::Request::Subdomain {
                host: "console.example.com".to_string(),
            })
        );
    }

    /// The two host-wide actions the console has as buttons. They hand
    /// off to `App` rather than acting here, for the same reason every
    /// other network- or process-touching key does: this handler stays
    /// free of I/O.
    #[test]
    fn u_and_a_hand_the_host_wide_actions_to_app() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        assert_eq!(
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char('u')), &db, &mut message)
                .unwrap(),
            KeyOutcome::UpdateEverything
        );
        assert_eq!(
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
                .unwrap(),
            KeyOutcome::ApplyEverything
        );
        assert!(
            dashboard.popup.is_none(),
            "neither is behind a popup, the same as the console's buttons"
        );
    }

    /// A popup owns every key while it is open — `a` is a letter someone
    /// types into the country field, not an apply of the whole host.
    #[test]
    fn a_popup_swallows_the_host_wide_action_keys() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::AddCountry {
            input: String::new(),
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.as_ref().unwrap() {
            Popup::AddCountry { input, .. } => assert_eq!(input, "a"),
            other => panic!("the popup changed: {other:?}"),
        }
    }

    #[test]
    fn f_key_opens_the_render_firewall_popup_with_defaults() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('F')), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::RenderFirewall {
                backend_selected,
                out_path,
                apply_after_write,
                error,
            } => {
                assert_eq!(backend_selected, 0);
                assert_eq!(out_path, crate::firewall::DEFAULT_OUTPUT_PATH);
                assert!(!apply_after_write);
                assert!(error.is_none());
            }
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    /// Regression test: `j`/`k` are common path characters, but every other
    /// popup/list in this app treats them as vim-style Down/Up aliases.
    /// This popup has a free-text output-path field, so those aliases must
    /// NOT apply here — otherwise typing a path containing 'j' or 'k'
    /// silently drops that character instead of appending it (found via
    /// `App`'s `pressing_f_then_enter_refreshes_the_dashboards_stale_indicator`
    /// flaking whenever a temp-dir path happened to contain one).
    #[test]
    fn render_firewall_popup_accepts_literal_j_and_k_in_the_output_path() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: String::new(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        for c in "/tmp/jk-test.nft".chars() {
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char(c)), &db, &mut message)
                .unwrap();
        }

        match &dashboard.popup {
            Some(Popup::RenderFirewall { out_path, .. }) => {
                assert_eq!(out_path, "/tmp/jk-test.nft")
            }
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn space_toggles_apply_after_write_in_the_render_firewall_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: "/tmp/fw.nft".to_string(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::RenderFirewall {
                apply_after_write, ..
            }) => assert!(apply_after_write),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }

        // Toggling again flips it back off.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::RenderFirewall {
                apply_after_write, ..
            }) => assert!(!apply_after_write),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn enter_in_render_firewall_popup_carries_the_apply_toggle_through() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: "/tmp/fw.nft".to_string(),
            apply_after_write: true,
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        match outcome {
            KeyOutcome::RenderFirewall {
                out_path, apply, ..
            } => {
                assert_eq!(out_path, "/tmp/fw.nft");
                assert!(apply);
            }
            other => panic!("expected a RenderFirewall outcome, got {other:?}"),
        }
        assert!(dashboard.popup.is_none());
    }

    #[test]
    fn render_firewall_popup_rejects_an_empty_output_path_and_stays_open() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::RenderFirewall {
            backend_selected: 0,
            out_path: String::new(),
            apply_after_write: false,
            error: None,
        });

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        match dashboard.popup.unwrap() {
            Popup::RenderFirewall { error, .. } => assert!(error.is_some()),
            other => panic!("expected a RenderFirewall popup, got {other:?}"),
        }
    }

    #[test]
    fn firewall_needs_update_is_true_before_any_render() {
        let db = Db::open_in_memory().unwrap();
        assert!(firewall_needs_update(&db).unwrap());
    }

    #[test]
    fn firewall_needs_update_is_false_right_after_a_matching_render() {
        let db = Db::open_in_memory().unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();
        assert!(!firewall_needs_update(&db).unwrap());
    }

    #[test]
    fn firewall_needs_update_is_true_again_after_the_rule_set_changes() {
        let db = Db::open_in_memory().unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();

        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "9.9.9.9".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
        })
        .unwrap();

        assert!(firewall_needs_update(&db).unwrap());
    }

    /// With no rules at all — a fresh install — the panel must not say
    /// "needs updating (press f)". Pressing `f` there renders an empty
    /// script, which looks like the tool doing nothing, and it is the
    /// first screen a new user sees.
    #[test]
    fn the_firewall_summary_row_does_not_send_a_fresh_install_to_render_nothing() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("no rules yet"), "content was:\n{content}");
        assert!(!content.contains("F to write"), "content was:\n{content}");
    }

    #[test]
    fn render_shows_the_firewall_summary_row() {
        let db = Db::open_in_memory().unwrap();
        // A rule to write. Without one the panel says something else
        // entirely, and deliberately — see the test below.
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "203.0.113.9".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
        })
        .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("1 rules"), "content was:\n{content}");
        assert!(content.contains("STALE"), "content was:\n{content}");
        assert!(content.contains("F to write"), "content was:\n{content}");
    }

    #[test]
    fn render_shows_the_firewall_summary_row_as_up_to_date_after_a_render() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "203.0.113.9".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
        })
        .unwrap();
        let rules = crate::firewall::all_rules(&db).unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&rules))
            .unwrap();

        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("UP TO DATE"), "content was:\n{content}");
        assert!(
            !content.contains("needs updating"),
            "content was:\n{content}"
        );
    }

    // ---- Automatic blocking panel ----

    fn press(dashboard: &mut Dashboard, db: &Db, code: KeyCode) -> KeyOutcome {
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(code), db, &mut message)
            .unwrap()
    }

    /// Walks focus from its default (Categories) all the way into the
    /// Automatic blocking panel, the way a user actually would.
    fn focus_protection(dashboard: &mut Dashboard, db: &Db) {
        while dashboard.focus != Focus::Protection {
            press(dashboard, db, KeyCode::Down);
        }
    }

    #[test]
    fn focus_flows_from_countries_into_the_protection_panel_and_back() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        focus_protection(&mut dashboard, &db);
        assert_eq!(dashboard.protection_state.selected(), Some(0));

        press(&mut dashboard, &db, KeyCode::Up);
        assert_eq!(dashboard.focus, Focus::Countries);
    }

    #[test]
    fn down_does_not_move_past_the_last_protection_row() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        for _ in 0..dashboard.protection_rows().len() + 3 {
            press(&mut dashboard, &db, KeyCode::Down);
        }
        assert_eq!(
            dashboard.protection_state.selected(),
            Some(dashboard.protection_rows().len() - 1)
        );
        assert_eq!(dashboard.focus, Focus::Protection);
    }

    #[test]
    fn turning_a_detector_off_persists_it() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_detector(&mut dashboard, Detector::SpoofedCrawlers);

        // Enabled by default, so the popup opens on an "On" row; Up lands
        // on "Off" at index 0.
        press(&mut dashboard, &db, KeyCode::Enter);
        assert!(matches!(dashboard.popup, Some(Popup::Protection { .. })));
        press(&mut dashboard, &db, KeyCode::Up);
        let outcome = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(!Detector::SpoofedCrawlers.is_enabled(&db).unwrap());
    }

    #[test]
    fn choosing_an_on_option_stores_both_the_toggle_and_its_ttl() {
        let db = Db::open_in_memory().unwrap();
        Detector::SpoofedCrawlers.set_enabled(&db, false).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_detector(&mut dashboard, Detector::SpoofedCrawlers);

        // Opens on "Off" (index 0); two Downs reach the second TTL choice.
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Down);
        press(&mut dashboard, &db, KeyCode::Down);
        press(&mut dashboard, &db, KeyCode::Enter);

        assert!(Detector::SpoofedCrawlers.is_enabled(&db).unwrap());
        assert_eq!(
            Detector::SpoofedCrawlers.ttl_days(&db).unwrap(),
            PROTECTION_TTL_CHOICES[1]
        );
    }

    /// Turning a detector off must not throw away its TTL — re-enabling
    /// should restore what was configured, not silently reset it.
    #[test]
    fn disabling_a_detector_preserves_its_ttl() {
        let db = Db::open_in_memory().unwrap();
        Detector::SpoofedCrawlers.set_ttl_days(&db, 30).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_detector(&mut dashboard, Detector::SpoofedCrawlers);
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Up);
        press(&mut dashboard, &db, KeyCode::Up);
        press(&mut dashboard, &db, KeyCode::Up);
        press(&mut dashboard, &db, KeyCode::Enter);

        assert!(!Detector::SpoofedCrawlers.is_enabled(&db).unwrap());
        assert_eq!(Detector::SpoofedCrawlers.ttl_days(&db).unwrap(), 30);
    }

    /// A TTL set outside the offered choices (via the CLI, which takes any
    /// number) must still open as *enabled* rather than reading as "Off".
    #[test]
    fn the_popup_opens_enabled_for_a_ttl_that_is_not_an_offered_choice() {
        let db = Db::open_in_memory().unwrap();
        Detector::SpoofedCrawlers.set_enabled(&db, true).unwrap();
        Detector::SpoofedCrawlers.set_ttl_days(&db, 3).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_detector(&mut dashboard, Detector::SpoofedCrawlers);
        press(&mut dashboard, &db, KeyCode::Enter);
        let Some(Popup::Protection { selected, .. }) = dashboard.popup else {
            panic!("expected the protection popup");
        };
        assert_ne!(selected, 0, "3 days must not read as Off");
    }

    #[test]
    fn escape_closes_the_protection_popup_without_changing_anything() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_detector(&mut dashboard, Detector::SpoofedCrawlers);
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Up);
        press(&mut dashboard, &db, KeyCode::Esc);

        assert!(dashboard.popup.is_none());
        assert!(Detector::SpoofedCrawlers.is_enabled(&db).unwrap());
    }

    /// Each row must drive its *own* settings keys — a copy-paste slip in
    /// `commit_protection`'s match would silently make one detector's
    /// popup rewrite another's.
    #[test]
    fn each_protection_row_writes_only_its_own_settings() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        // Switch Probe paths off, and assert nothing else moved.
        select_detector(&mut dashboard, Detector::ProbePaths);
        press(&mut dashboard, &db, KeyCode::Enter);
        for _ in 0..PROTECTION_TTL_CHOICES.len() {
            press(&mut dashboard, &db, KeyCode::Up);
        }
        press(&mut dashboard, &db, KeyCode::Enter);

        assert!(!Detector::ProbePaths.is_enabled(&db).unwrap());
        assert!(
            Detector::SpoofedCrawlers.is_enabled(&db).unwrap(),
            "the other detector must be untouched"
        );
    }

    // ---- reputation / provider feed rows ----

    use crate::ipranges::reputation::{register_all_reputation_sources, ReputationSourceKind};

    /// Selects `detector`'s row, by searching rather than by assuming a
    /// position — the list is `Detector::ALL` plus one row per feed, so
    /// any new detector would otherwise silently shift these tests onto a
    /// different row and keep passing.
    fn select_detector(dashboard: &mut Dashboard, detector: Detector) {
        let index = dashboard
            .protection_rows()
            .iter()
            .position(|row| *row == ProtectionRow::Detect(detector))
            .expect("detector row should exist");
        dashboard.protection_state.select(Some(index));
    }

    fn feed_row_index(dashboard: &Dashboard, id: &str) -> usize {
        dashboard
            .protection_rows()
            .iter()
            .position(|row| match row {
                ProtectionRow::Feed(i) => dashboard.reputation[*i].id == id,
                _ => false,
            })
            .expect("feed row should exist")
    }

    #[test]
    fn feeds_appear_as_rows_after_the_detectors() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let rows = dashboard.protection_rows();
        assert_eq!(
            rows.len(),
            Detector::ALL.len() + ReputationSourceKind::ALL.len()
        );
        assert!(rows[..Detector::ALL.len()].iter().all(|r| r.is_detector()));
        assert!(rows[Detector::ALL.len()..].iter().all(|r| !r.is_detector()));
    }

    /// Enabling a never-fetched feed must ask `App` to download it —
    /// switching one on with no ranges stored looks like it worked while
    /// doing nothing at all.
    #[test]
    fn enabling_an_unfetched_feed_asks_for_a_fetch() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        let target = feed_row_index(&dashboard, ReputationSourceKind::TorExits.id());
        dashboard.protection_state.select(Some(target));
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Down); // Off -> On
        let outcome = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(
            outcome,
            KeyOutcome::FetchReputationSource(ReputationSourceKind::TorExits.id().to_string())
        );
        // Already switched on, so a failed download leaves it enabled-and-
        // empty (inert) rather than silently undoing the choice.
        let source = db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == ReputationSourceKind::TorExits.id())
            .unwrap();
        assert!(source.enabled);
    }

    /// An already-fetched feed needs no network round trip.
    #[test]
    fn enabling_an_already_fetched_feed_does_not_ask_for_a_fetch() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        db.replace_reputation_ranges(
            ReputationSourceKind::TorExits.id(),
            &["1.2.3.4".to_string()],
        )
        .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        let target = feed_row_index(&dashboard, ReputationSourceKind::TorExits.id());
        dashboard.protection_state.select(Some(target));
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Down);
        let outcome = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.enabled_reputation_ranges().unwrap(), vec!["1.2.3.4"]);
    }

    /// A feed's popup has no TTL rows — there's nothing that expires.
    #[test]
    fn a_feed_popup_offers_only_off_and_on() {
        assert_eq!(protection_options(false).len(), 2);
        assert!(protection_options(true).len() > 2);
    }

    #[test]
    fn disabling_a_feed_keeps_its_ranges_for_next_time() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        db.replace_reputation_ranges(ReputationSourceKind::Aws.id(), &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_reputation_source_enabled(ReputationSourceKind::Aws.id(), true)
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        let target = feed_row_index(&dashboard, ReputationSourceKind::Aws.id());
        dashboard.protection_state.select(Some(target));
        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Up); // On -> Off
        press(&mut dashboard, &db, KeyCode::Enter);

        assert!(db.enabled_reputation_ranges().unwrap().is_empty());
        let source = db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == ReputationSourceKind::Aws.id())
            .unwrap();
        assert_eq!(
            source.range_count, 1,
            "ranges must survive being switched off"
        );
    }

    /// The provider feeds block real visitors; enabling one must say so.
    /// The selection follows the eye across the columns: with the rows
    /// dealt down one column and then the next, the highlight has to land
    /// in the right column at the right row — and in exactly one place.
    ///
    /// Nothing else would notice getting this wrong. Each column is its
    /// own `List` with its own state, so a selection off the end of the
    /// first column simply highlights nothing, and every other test here
    /// asserts on text rather than on style.
    #[test]
    fn the_highlight_lands_in_the_column_holding_the_selected_row() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Protection;
        // Row 9 of 14: with seven to a column, the third row of the second
        // column — a spot only reachable if the split is right.
        dashboard.protection_state.select(Some(9));

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let highlighted: Vec<String> = (0..buffer.area.height)
            .filter(|&y| {
                (0..buffer.area.width)
                    .any(|x| buffer[(x, y)].style().bg == Some(Theme::Dark.selection_bg()))
            })
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();

        assert_eq!(highlighted.len(), 1, "exactly one row is highlighted");
        let label = dashboard.protection_label(dashboard.protection_rows()[9]);
        assert!(
            highlighted[0].contains(&label),
            "expected {label:?} highlighted, got: {:?}",
            highlighted[0]
        );
    }

    #[test]
    fn enabling_a_provider_feed_warns_about_blocking_real_visitors() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        db.replace_reputation_ranges(ReputationSourceKind::Aws.id(), &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        let target = feed_row_index(&dashboard, ReputationSourceKind::Aws.id());
        dashboard.protection_state.select(Some(target));
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let message = message.unwrap();
        assert!(message.contains("not just bots"), "message was: {message}");
    }

    /// Every automatic-blocking option is on screen at once. There are
    /// fourteen of them and the panel is nine rows tall, which only works
    /// because they are dealt into columns — so this is really a test that
    /// the column layout is still doing its job. It used to show five of
    /// the fourteen, in half the width, and the other nine were a scroll
    /// away with nothing saying they existed.
    #[test]
    fn every_automatic_blocking_option_is_visible_without_scrolling() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        let rows = dashboard.protection_rows();
        assert_eq!(rows.len(), 14, "if this changes, so does the panel height");
        for row in rows {
            let label = dashboard.protection_label(row);
            assert!(content.contains(&label), "{label:?} is not on screen");
        }
    }

    #[test]
    fn render_shows_the_automatic_blocking_panel() {
        let db = Db::open_in_memory().unwrap();
        Detector::SpoofedCrawlers.set_enabled(&db, false).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Automatic blocking"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("Forged crawler"),
            "content was:\n{content}"
        );
        assert!(content.contains("Probe paths"), "content was:\n{content}");
        assert!(content.contains("[ OFF ]"), "content was:\n{content}");
    }

    /// The render-firewall popup, rendered rather than only key-driven —
    /// this arm of `render_popup` had no rendering test, which let a pty
    /// test failure point suspicion at it for a while.
    #[test]
    fn pressing_f_opens_a_render_firewall_popup_that_actually_renders() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('F')), &db, &mut message)
            .unwrap();

        let mut terminal = test_terminal();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
            .unwrap();
        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Apply after writing"),
            "popup did not render"
        );
    }
}
