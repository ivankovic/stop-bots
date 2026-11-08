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

//! The Dashboard: the default screen on app start. An overview of global
//! settings (Scanners/Search bots/AI bots defaults, navigable and editable
//! via a popup, mirroring how Bot settings edits a single bot's override),
//! host-wide geo-blocking (see "Geo-blocking" below), the detectors and
//! feeds that block on their own, and what the rules become. Top user
//! agents seen in successful traffic used to be folded in here too, but
//! that has its own "Firewall" screen
//! (`crate::tui::firewall`), which also lets an admin act on
//! them, not just look.
//!
//! ## Layout
//!
//! Two columns over a log. The left column is *policy* — "Policy" (the
//! category defaults), "Geo" (the country list, with the mode in its
//! title) and "Firewall script" (rule count, whether the script on disk
//! is stale, and the inputs it is rendered from). The right column is
//! what the host does on its own — "Automatic blocking", one row per
//! switch in a single column, and "Scheduled". The "Log" at the foot spans
//! both: every message `App` has shown, newest first. On a short terminal
//! Automatic blocking is the panel that gives (it falls back to
//! scrolling); Scheduled never vanishes, because it reports what the
//! detectors just did.
//!
//! Focus flows *linearly* through the three lists (Categories ->
//! Countries -> Protection) via Up/Down, and Tab/Shift+Tab step between
//! them; only the focused one draws a highlight, so there's never
//! ambiguity about which list the arrows move.
//!
//! ## The host-wide actions
//!
//! Three keys here act on the whole host rather than on the selected row:
//!
//! - `u` downloads every list this host uses ([`crate::refresh`]), one
//!   source at a time — `KeyOutcome::UpdateEverything`.
//! - `a` shows what applying would change and asks
//!   (`KeyOutcome::PreviewApplyEverything`, then [`Popup::ConfirmApply`]);
//!   Enter there writes the NGINX config and then writes and runs the
//!   firewall script — `KeyOutcome::ApplyEverything`. Two independent
//!   halves, the same two `batch --apply` does. The NGINX reload it
//!   triggers overlaps the firewall render rather than preceding it: both
//!   are started from `App::finish_site_apply`, and neither reads what the
//!   other writes.
//! - `F` opens the render popup ([`Popup::RenderFirewall`]) — capital,
//!   like `A` on NGINX, because it writes to the host.
//!
//! Only `a` asks first: it rewrites every site and runs a script as root
//! on one keypress, and the confirmation shows the files, the rules added
//! and removed and the lockout guard's verdict, with the diff on `d`. The
//! three are hinted in the footer (see
//! [`Dashboard::hints`]), which is context-sensitive, so panel titles stay
//! titles.
//!
//! ## Geo-blocking
//!
//! A second, independently-focused list (`countries_state`, switched to via
//! `Down` past the last category row or `Up` above the first country
//! row — no dedicated focus key, since these are just two vertically
//! stacked lists, not a list-plus-search-box pair like Bot settings'
//! `Focus`) shows every host-wide selected country (`Db::list_selected_countries`)
//! plus a fixed action row at the top, "Enter to add a country, m to change
//! mode", which is also where the mode key is announced. What being
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
//! - **Only trusted IPs**: Allowlist with no country selected, offered as a
//!   mode of its own so that it can be seen and chosen. With no country to
//!   allow, what gets through is what the firewall lets past every rule:
//!   trusted addresses, recent SSH logins and private networks. Choosing it
//!   deselects every country; adding one turns it back into Allowlist.
//!
//! Enter on the "Add" row opens a text-input popup for a two-letter code;
//! Delete or Backspace on an existing country row removes it directly, and
//! Enter there only says so: Enter adds on the row above, and a key that
//! adds on one row should not delete on the next (no confirmation
//! popup — unlike a category default, removing a country isn't "choose one
//! of several options", it's a single reversible action, the same
//! reasoning the NGINX screen's apply/apply-all actions already use).
//! Confirming the input popup with a code whose ranges are already fetched
//! adds it immediately (`Mutated`); a not-yet-fetched code returns
//! `KeyOutcome::SelectCountry` so `App` can fetch it first
//! (`App::start_country_select`) — see that function's doc comment for why
//! fetching can't happen here directly.

use crate::db::{Category, Db, GeoMode, Policy, Source};
use crate::ipranges;
use crate::present::category_label;
use crate::protection::Detector;
use crate::tui::explain::Explanation;
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

mod simple;

/// A source is considered stale (needs updating) if it's never been fetched,
/// or wasn't fetched in the last week.
const STALE_AFTER_SECS: i64 = 7 * 24 * 60 * 60;

/// The rows of the editable "Policy" list, in display order.
const CATEGORIES: [Category; 3] = [Category::Scanner, Category::Search, Category::Ai];

/// Rows in the Policy list: the humans-only switch, then the three
/// categories it forces, then the old-browser and HTTP-library switches.
/// Humans only leads because it decides whether the three below it can be
/// touched at all; the two lists come last because they decide nothing
/// about them.
const POLICY_ROWS: usize = CATEGORIES.len() + 3;

/// Which of the Dashboard's three lists arrow keys currently move through.
/// Ordered as focus flows: `Down` past the last row of one moves into the
/// next, `Up` above the first row moves back — no dedicated focus key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Categories,
    Countries,
    /// The three published crawler ranges, under Geo.
    Crawlers,
    Protection,
    /// The simple screen's last panel: what the detectors do, and whether
    /// it keeps running by itself (see `simple`). Never focused on the
    /// advanced one.
    Essentials,
}

/// The rows of the "Automatic blocking" list, in display order. Each is a
/// detector that adds `firewall_rules` rows on its own — which is why they
/// live on the Dashboard rather than NGINX: this project puts
/// everything that ends up in the *firewall script* here, and everything
/// that ends up in *NGINX config* on NGINX.
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
    /// The hosting providers blocked by AS number (`ipranges::hosting`):
    /// one row for the whole list, whose Enter opens
    /// [`Popup::HostingProviders`] to choose them, rather than a row per
    /// provider in a panel that has no room for sixteen more.
    HostingProviders,
    /// Whether a detector blocks an address it blocked before for longer
    /// (`protection::repeat_escalation`). Beside the detectors, because it
    /// changes how long each of their blocks lasts; a plain Off/On, since
    /// the lengths are fixed (`protection::escalated_ttl_days`).
    RepeatOffenders,
    /// Whether the probe-paths detector also counts the paths of an
    /// application no site runs (`protection::app_probe_paths`). Beside
    /// repeat offenders, for the same reason: it changes what one of the
    /// detectors above does, and is a plain Off/On.
    AppProbePaths,
    /// Whether the daily render also *runs* the script it writes
    /// (`Db::get_auto_apply_firewall`).
    ///
    /// The one row here that adds no blocks of its own. It earns its place
    /// anyway: every other row in this panel decides what ends up in the
    /// firewall script, and this is the answer to what happens to that
    /// script afterwards — which is the question an admin has right after
    /// switching one of the others on. The NGINX half of the same
    /// question lives on NGINX, beside the config it applies.
    AutoApplyFirewall,
    /// Whether every apply is checked against the addresses that log in
    /// over SSH (`Db::get_ssh_lockout_check`). Beside auto-apply because
    /// it is the other half of the same question: what stands between a
    /// rendered script and the kernel. Switching it off asks first — see
    /// [`Popup::NoLogins`].
    LockoutCheck,
    /// Outbound checks (`egress::Mode`): Off, Watch or Block. Space steps
    /// through them; Enter chooses in a popup. The C&C feeds and
    /// containment rows under it appear once it is not Off.
    Outbound,
    /// One C&C feed, by index into `Dashboard::egress_feeds`.
    EgressFeed(usize),
    /// Whether a hit contains the container that made it
    /// (`contain::Settings::auto`). Switching it on asks first.
    AutoContain,
}

/// The headings the "Automatic blocking" rows are listed under, in order.
/// Display only: a heading is never selected, and the selection index
/// walks [`Dashboard::protection_rows`] as it always did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectionGroup {
    /// The detectors, and the two switches that change what they do.
    Detectors,
    /// Lists of addresses blocked whatever they do: the reputation and
    /// cloud feeds, and hosting providers by AS number.
    Addresses,
    /// Outbound checks, their feeds and containment.
    Outbound,
    /// What happens to the script once it is written.
    Apply,
}

impl ProtectionGroup {
    fn heading(self) -> &'static str {
        match self {
            ProtectionGroup::Detectors => "Log detectors",
            ProtectionGroup::Addresses => "Blocked by address",
            ProtectionGroup::Outbound => "Outbound C&C checks",
            ProtectionGroup::Apply => "Firewall apply",
        }
    }

    fn of(row: ProtectionRow) -> ProtectionGroup {
        match row {
            ProtectionRow::Detect(_)
            | ProtectionRow::RepeatOffenders
            | ProtectionRow::AppProbePaths => ProtectionGroup::Detectors,
            ProtectionRow::Feed(_) | ProtectionRow::HostingProviders => ProtectionGroup::Addresses,
            ProtectionRow::Outbound | ProtectionRow::EgressFeed(_) | ProtectionRow::AutoContain => {
                ProtectionGroup::Outbound
            }
            ProtectionRow::AutoApplyFirewall | ProtectionRow::LockoutCheck => {
                ProtectionGroup::Apply
            }
        }
    }
}

/// How far a row is indented under its heading.
const PROTECTION_INDENT: usize = 2;

impl ProtectionRow {
    /// Whether this row is a detector (whose popup offers Off plus a TTL
    /// choice) rather than a feed (a plain Off/On, with no TTL — a feed's
    /// blocks are derived at render time and never expire on their own).
    fn is_detector(self) -> bool {
        matches!(self, ProtectionRow::Detect(_))
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
    /// "Apply everything"'s confirmation: what would change, the lockout
    /// guard's verdict, and the diff on `d`. Enter applies; Esc changes
    /// nothing. Behind `Arc`s because the popup is cloned every frame and
    /// a first apply's firewall diff is tens of thousands of lines.
    ConfirmApply {
        /// The web server the sites are written for, which the popup
        /// names.
        server: crate::webserver::WebServer,
        lines: std::sync::Arc<[String]>,
        diff: std::sync::Arc<[String]>,
        show_diff: bool,
        scroll: usize,
    },
    /// "Do you log into this server over SSH?": keep the lock-out check on
    /// (0), or turn it off (1). Asked before the apply preview when the
    /// SSH log was read and no one has logged in over SSH, as the check
    /// then has no one to protect, and asked by the
    /// [`ProtectionRow::LockoutCheck`] row before switching it off.
    /// `preview` is the apply this came from, which keeping the check
    /// goes on to show; `None` from the row.
    NoLogins {
        preview: Option<std::sync::Arc<crate::preview::ApplyPreview>>,
        selected: usize,
    },
    /// A change that deserves a second look, with what it does spelled
    /// out: go ahead (0) or cancel (1). See [`Confirm`].
    Confirm {
        what: Confirm,
        selected: usize,
    },
    Category {
        category: Category,
        selected: usize,
    },
    AddCountry {
        input: String,
        error: Option<String>,
    },
    /// Blocklist (0), Allowlist (1) or Only trusted IPs (2) — a popup, not a
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
    /// Switching the AWS feed on, which Let's Encrypt validates from:
    /// block it but leave port 80 open (0), or block port 80 too (1). Esc
    /// leaves the feed off. `feed` indexes `Dashboard::reputation`.
    CloudPort80 {
        feed: usize,
        selected: usize,
    },
    /// Which hosting providers to block: every one on the built-in list,
    /// and any other AS number already blocked. Space ticks the row under
    /// `cursor` in `chosen`; Enter blocks what is ticked and stops blocking
    /// what is not, in one go, so one download fetches every newly ticked
    /// provider; Esc changes nothing.
    HostingProviders {
        cursor: usize,
        chosen: std::collections::BTreeSet<u32>,
    },
    /// Firewall rendering: select backend (0 = nftables, 1 = iptables),
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
}

/// The geo mode popup's options, in order. The last is Allowlist with no
/// country selected, which is how the database stores it.
const GEO_BLOCKLIST: usize = 0;
const GEO_ALLOWLIST: usize = 1;
const GEO_TRUSTED_ONLY: usize = 2;

/// What a [`Popup::Confirm`] asks about. Each is a change that is one
/// keypress to make and does more than its label says: the geo modes reuse
/// or empty the country list, and auto-apply takes the preview out of
/// every later apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirm {
    /// Switching the geo mode to this choice (`GEO_*`) while countries are
    /// on the list, or to an Allowlist with none.
    GeoMode(usize),
    /// Switching auto-apply of the firewall script on.
    AutoApplyFirewall,
    /// Switching humans only on, from the simple screen: it takes the
    /// site out of search engines, which nothing else on that screen does.
    HumansOnly,
    /// The simple screen's "Keep running by itself", switched on: a cron
    /// file written as root, and both auto-applies.
    KeepRunning,
    /// Containing what calls a C&C server, without asking each time.
    AutoContain,
}

#[derive(Debug, Default)]
pub struct Dashboard {
    /// Which firewall backends this host has, as `App` found at start-up;
    /// `None` when nobody looked, which marks and refuses nothing.
    pub installed: Option<crate::firewall::Installed>,
    site_count: usize,
    sources: Vec<Source>,
    scanner_default: Policy,
    search_default: Policy,
    ai_default: Policy,
    list_state: ListState,
    popup: Option<Popup>,
    geo_mode: GeoMode,
    /// How many addresses are trusted by hand: in Only trusted IPs, what
    /// the host still lets in from the internet besides recent SSH logins.
    trusted_addresses: usize,
    selected_countries: Vec<String>,
    fetched_countries: Vec<(String, i64, i64)>,
    countries_state: ListState,
    /// Googlebot, Bingbot and GPTBot's published ranges: what each holds
    /// and when it was fetched. Enter downloads one.
    crawlers: Vec<crate::ipranges::CrawlerSource>,
    crawlers_state: ListState,
    protection_state: ListState,
    /// The automatic-detection toggles, reloaded on every `refresh` — the
    /// panel only displays them; `crate::cron`'s jobs read the same values
    /// straight from `Db` when they run.
    /// Each detector's (enabled, ttl_days), reloaded on every `refresh`.
    /// A map rather than a struct of named fields, so a new detector is a
    /// row in `Detector::ALL` and nothing here.
    detectors: std::collections::HashMap<Detector, (bool, i64)>,
    /// Detectors that arrived after this database was created and that
    /// nobody has switched yet: off, and marked "new" so the operator
    /// learns they exist. See `Detector::is_new_here`.
    new_detectors: std::collections::HashSet<Detector>,
    /// `protection::repeat_escalation`, for the
    /// `ProtectionRow::RepeatOffenders` row.
    repeat_offenders: bool,
    /// Whether that row is new here, as a new detector's is
    /// (`protection::repeat_escalation_is_new_here`).
    repeat_offenders_new: bool,
    /// `protection::app_probe_paths`, for `ProtectionRow::AppProbePaths`.
    app_probe_paths: bool,
    /// Whether that row is new here
    /// (`protection::app_probe_paths_is_new_here`).
    app_probe_paths_new: bool,
    /// Every third-party CIDR feed, ordered by id — the order
    /// `ProtectionRow::Feed`'s index refers to.
    reputation: Vec<crate::db::ReputationSource>,
    /// The hosting providers blocked by AS number, for the
    /// `ProtectionRow::HostingProviders` row and its popup.
    hosting_asns: Vec<crate::db::HostingAsn>,
    /// `Db::get_auto_apply_firewall`, mirrored here for the
    /// `ProtectionRow::AutoApplyFirewall` row, the same way every other
    /// value this panel shows is loaded in `refresh`.
    auto_apply_firewall: bool,
    /// `Db::get_ssh_lockout_check`, for the `ProtectionRow::LockoutCheck`
    /// row.
    ssh_lockout_check: bool,
    /// Outbound checks, the C&C feeds, and whether a hit contains: the
    /// "Automatic blocking" rows for [`crate::egress`].
    egress_mode: crate::egress::Mode,
    egress_feeds: Vec<crate::db::egress::EgressFeed>,
    auto_contain: bool,
    /// Whether this host serves humans only. Drives both the extra
    /// detector row and the greying of the three category rows.
    humans_only: bool,
    /// Whether the old-browser list is blocked: the Policy list's second
    /// to last row.
    old_browsers: bool,
    /// Whether the HTTP-library switch is on: the Policy list's last row.
    /// Humans only blocks the list with it off, which the row shows.
    http_libraries: bool,
    focus: Focus,
    /// The internal cron's per-job state (see `crate::cron`), read-only
    /// here — this panel only displays it, `App` is what actually runs due
    /// jobs.
    cron_status: Vec<crate::cron::JobStatus>,
    /// Whether the current rule set is the one last applied, only
    /// rendered, or changed since either (`firewall::script_state`) —
    /// shown as the Firewall script panel's tag, so an admin can tell
    /// without opening the render popup whether e.g. a scanner blocked a
    /// minute ago is enforced, or only sitting in a script the cron wrote.
    script_state: crate::firewall::ScriptState,
    /// How many rules a render would write, for the Firewall script panel
    /// — see its three-state line, which reads differently at zero.
    rule_count: usize,
    /// The last health probe, re-assessed on every refresh. `None` until
    /// the internal cron has taken one — see [`crate::health`].
    health: Option<(crate::health::Report, i64)>,
    /// Whether this is the simple screen (see `simple`) rather than every
    /// panel. `App` owns the choice, which is stored in the database, and
    /// sets it with [`Self::set_simple`].
    simple: bool,
    /// The simple screen's Essentials list.
    essentials_state: ListState,
    /// `Db::get_auto_apply`, the web-server half of keeping running.
    auto_apply: bool,
    /// Whether `/etc/cron.d/stop-bots` was there at the last health probe;
    /// `None` before the first.
    cron_installed: Option<bool>,
    /// Addresses the firewall blocks now, by rule, and how many of those
    /// blocks are from the last day: the simple screen's status line.
    blocked_now: usize,
    blocked_today: usize,
    /// Outbound checks, when they are on or something is contained: the
    /// Firewall script panel's third line. See [`crate::egress`].
    egress: Option<Outbound>,
}

/// What the Firewall script panel says about outbound traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outbound {
    mode: crate::egress::Mode,
    /// Attempts to listed addresses seen in the last week.
    recent_hits: usize,
    contained: usize,
}

impl Dashboard {
    /// Reloads everything shown on the dashboard from `db`.
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        // Cheap: the expensive half (shelling out to `nft`) is the cron's
        // job, and this only re-derives the report from what it stored.
        self.health = crate::health::cached_report(db)?;
        let sites = db.list_sites()?;
        self.site_count = sites.len();
        self.sources = db.list_sources()?;
        self.humans_only = db.get_humans_only()?;
        self.old_browsers = db.get_block_old_browsers()?;
        self.http_libraries = db.get_block_http_libraries()?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.ai_default = db.get_category_default(Category::Ai)?;
        self.geo_mode = db.get_geo_mode()?;
        self.trusted_addresses = db.list_trusted_addresses()?.len();
        self.selected_countries = db.list_selected_countries()?;
        self.fetched_countries = db.list_fetched_countries()?;
        self.detectors = Detector::ALL
            .into_iter()
            .map(|d| Ok((d, (d.is_enabled(db)?, d.ttl_days(db)?))))
            .collect::<Result<_>>()?;
        self.new_detectors = Detector::ALL
            .into_iter()
            .filter_map(|d| d.is_new_here(db).map(|new| new.then_some(d)).transpose())
            .collect::<Result<_>>()?;
        self.repeat_offenders = crate::protection::repeat_escalation(db)?;
        self.repeat_offenders_new = crate::protection::repeat_escalation_is_new_here(db)?;
        self.app_probe_paths = crate::protection::app_probe_paths(db)?;
        self.app_probe_paths_new = crate::protection::app_probe_paths_is_new_here(db)?;
        self.reputation = db.list_reputation_sources()?;
        self.hosting_asns = db.list_hosting_asns()?;
        self.crawlers = ipranges::crawler_sources(db)?;
        self.auto_apply_firewall = db.get_auto_apply_firewall()?;
        self.ssh_lockout_check = db.get_ssh_lockout_check()?;
        self.egress_mode = crate::egress::Mode::get(db)?;
        self.egress_feeds = db.list_egress_feeds()?;
        self.auto_contain = crate::contain::Settings::get(db)?.auto;
        self.cron_status = crate::cron::status(db)?;
        self.script_state = crate::firewall::script_state(db)?;
        self.rule_count = crate::firewall::all_rules(db)?.len();
        self.auto_apply = db.get_auto_apply()?;
        self.cron_installed =
            crate::health::cached_probe(db)?.and_then(|(probe, _)| probe.cron_installed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mode = crate::egress::Mode::get(db)?;
        let contained = db.open_containments()?.len();
        let recent_hits = db
            .list_egress_hits()?
            .iter()
            .filter(|hit| hit.last_seen > now - 7 * 24 * 60 * 60)
            .count();
        self.egress = (mode != crate::egress::Mode::Off || contained > 0 || recent_hits > 0)
            .then_some(Outbound {
                mode,
                recent_hits,
                contained,
            });
        let blocking: Vec<crate::db::FirewallRule> = db
            .list_firewall_rules()?
            .into_iter()
            .filter(|rule| {
                rule.enabled
                    && rule.action == crate::db::FirewallAction::Block
                    && rule.expires_at.is_none_or(|at| at > now)
            })
            .collect();
        self.blocked_now = blocking.len();
        self.blocked_today = blocking
            .iter()
            .filter(|rule| rule.created_at.is_some_and(|at| at > now - 24 * 60 * 60))
            .count();
        if self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        if self.countries_state.selected().is_none() {
            self.countries_state.select(Some(0));
        }
        if self.crawlers_state.selected().is_none() {
            self.crawlers_state.select(Some(0));
        }
        if self.protection_state.selected().is_none() {
            self.protection_state.select(Some(0));
        }
        if self.essentials_state.selected().is_none() {
            self.essentials_state.select(Some(0));
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

    /// What the Firewall script panel's tag currently says — `pub(crate)`
    /// and test-only, purely so `App`'s own tests (a different module) can
    /// assert that a render triggered through the key/outcome flow actually
    /// refreshes this cached value, not just the underlying `Db` signature
    /// (see `App::handle_key_event`'s `RenderFirewall` arm).
    #[cfg(test)]
    pub(crate) fn script_state(&self) -> crate::firewall::ScriptState {
        self.script_state
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
        if matches!(self.popup, Some(Popup::HostingProviders { .. })) {
            return (
                "Popup",
                vec![
                    ("\u{2191}\u{2193}", "move"),
                    ("Space", "tick"),
                    ("Enter", "save"),
                    ("Esc", "cancel"),
                ],
            );
        }
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
        if self.simple {
            return self.simple_hints();
        }
        let host = [
            ("Tab", "next panel"),
            ("u", "update all"),
            ("a", "apply all"),
            ("F", "firewall"),
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
                    ("Enter", "add"),
                    ("Del", "remove"),
                    ("m", "mode"),
                ],
            ),
            Focus::Crawlers => (
                "Crawler ranges",
                vec![("\u{2191}\u{2193}", "move"), ("Enter", "download")],
            ),
            Focus::Protection | Focus::Essentials => (
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

    /// What the row under the cursor is, for `?`.
    pub fn explain(&self) -> Explanation {
        if self.simple {
            return self.explain_simple();
        }
        match self.focus {
            Focus::Categories => match self.list_state.selected().unwrap_or(0) {
                0 => self.explain_humans_only(),
                i if i <= CATEGORIES.len() => self.explain_category(CATEGORIES[i - 1]),
                i if i == POLICY_ROWS - 1 => Explanation::new("HTTP libraries")
                    .para(
                        "Blocks the user agents a program sends when nobody gave it one of \
                         its own: python-requests, aiohttp, Go-http-client, Java, OkHttp, \
                         axios, curl, Wget and the like, at any version. A site with nothing \
                         for a program to call sees them only probing and scraping.",
                    )
                    .now(match (self.http_libraries, self.humans_only) {
                        (true, _) => "blocked.",
                        (false, true) => "blocked, by humans only.",
                        (false, false) => "allowed.",
                    })
                    .warn(
                        "A site with an API is called by these. Off by default for that \
                         reason; a client of your own goes through once trusted.",
                    )
                    .para("Enter switches it. It applies to every site, in the web server.")
                    .takes_effect(false),
                _ => Explanation::new("Old browsers")
                    .para(
                        "Blocks the user agents of browsers too old for anyone to still run: \
                         Internet Explorer 9 and older, Firefox before 10, Chrome before 40, \
                         old Opera, feature phones. Scanners send these strings to look like \
                         people, and no bot list can carry them, as none is a bot's name.",
                    )
                    .now(if self.old_browsers {
                        "blocked."
                    } else {
                        "allowed."
                    })
                    .warn(
                        "A few are still a person somewhere: Opera Mini, for one, still \
                         sends Opera/9.80. Off by default for that reason.",
                    )
                    .para("Enter switches it. It applies to every site, in the web server.")
                    .takes_effect(false),
            },
            Focus::Countries => match self.countries_state.selected().unwrap_or(0) {
                0 => self.explain_geo_mode(),
                i => match self.selected_countries.get(i - 1) {
                    Some(country) => self.explain_country(country),
                    None => self.explain_geo_mode(),
                },
            },
            Focus::Crawlers => match self
                .crawlers_state
                .selected()
                .and_then(|i| self.crawlers.get(i))
            {
                Some(source) => self.explain_crawler(source),
                None => Explanation::new("Crawler IP ranges"),
            },
            Focus::Protection | Focus::Essentials => match self
                .protection_state
                .selected()
                .and_then(|i| self.protection_rows().get(i).copied())
            {
                Some(row) => self.explain_protection(row),
                None => Explanation::new("Automatic blocking"),
            },
        }
    }

    fn explain_humans_only(&self) -> Explanation {
        Explanation::new("Humans only")
            .para(
                "Serves people and nothing else. Every bot on the bot lists is blocked, \
                 whatever its category, so the three categories below are forced to Blocked. \
                 Any address that fetches /robots.txt, which people never do, is blocked \
                 for a day.",
            )
            .now(if self.humans_only { "on." } else { "off." })
            .warn(
                "Search engines are blocked too, so the site drops out of search results. So \
                 are uptime monitors and link previews that call themselves bots: trust one by \
                 its user agent on the Firewall screen to let it in.",
            )
            .para(
                "Let's Encrypt is the one bot still allowed, so certificates keep renewing. \
                 Turning this off brings back the categories as they were.",
            )
            .takes_effect(false)
    }

    fn explain_category(&self, category: Category) -> Explanation {
        let (about, firewall) = match category {
            Category::Scanner => (
                "Bots that look for weaknesses: vulnerability and port scanners, and security \
                 and SEO crawlers that probe sites they were not asked to.",
                None,
            ),
            Category::Search => (
                "Search engine crawlers: Googlebot, Bingbot and the rest. Blocking them takes \
                 the site out of their search results.",
                Some("Googlebot and Bingbot"),
            ),
            Category::Ai => (
                "Crawlers that collect pages for AI models, such as GPTBot and CCBot. Blocking \
                 them keeps the site's text out of their training data and answers.",
                Some("GPTBot"),
            ),
        };
        let policy = match self.category_default(category) {
            Policy::Allowed => "allowed",
            Policy::Blocked => "blocked",
        };
        let mut explanation = Explanation::new(category_label(category))
            .para(about)
            .now(if self.humans_only {
                format!("{policy}, forced by Humans only, which must be off to change it.")
            } else {
                format!("{policy}.")
            })
            .para(
                "A blocked bot is matched by its user agent in the web server, and gets the \
                 block response set on the web server's screen. A site can override this, on \
                 that screen.",
            );
        if let Some(crawlers) = firewall {
            explanation = explanation.para(format!(
                "While blocked, the addresses {crawlers} publish (Crawler IP ranges, below) \
                 are blocked in the firewall as well, so a crawler that changes its user agent \
                 is still kept out."
            ));
        }
        explanation.takes_effect(self.auto_apply_firewall)
    }

    fn explain_geo_mode(&self) -> Explanation {
        let list = if self.selected_countries.is_empty() {
            "No country is on the list.".to_string()
        } else {
            format!(
                "On the list: {}.",
                self.selected_countries.join(" ").to_uppercase()
            )
        };
        let explanation = match self.geo_choice() {
            GEO_BLOCKLIST => Explanation::new("Geo: Blocklist")
                .para(
                    "Blocks every address in the countries on this list, in the firewall, on \
                     every port. Everyone else gets in.",
                )
                .now(list),
            GEO_ALLOWLIST => Explanation::new("Geo: Allowlist")
                .para(
                    "Lets in only the countries on this list, and blocks every other address \
                     in the firewall, on every port. Trusted addresses, SSH logins from the \
                     last week and private networks still get in.",
                )
                .now(list)
                .warn(
                    "Keep the country you connect from on the list, and an address you \
                     connect from trusted (Firewall screen), or the next apply can lock you out.",
                ),
            _ => Explanation::new("Geo: Only trusted IPs")
                .para(
                    "Blocks every address in the firewall, on every port, except trusted \
                     addresses (Firewall screen), SSH logins from the last week and private \
                     networks. For a server only a few known people use.",
                )
                .now(format!("{} trusted address(es).", self.trusted_addresses))
                .warn(
                    "Trust every address you connect from before you apply. One that changes \
                     (home broadband, a phone) is locked out once its last SSH login is a \
                     week old.",
                ),
        };
        explanation
            .para(
                "Enter adds a country by its two-letter code, and downloads its address \
                 ranges. m changes the mode; Delete removes the selected country.",
            )
            .takes_effect(self.auto_apply_firewall)
    }

    fn explain_country(&self, country: &str) -> Explanation {
        let code = country.to_uppercase();
        let ranges = match self.range_count(country) {
            Some(count) => format!("{count} address ranges downloaded."),
            None => "its ranges are not downloaded yet, so it blocks nothing.".to_string(),
        };
        let effect = match self.geo_mode {
            GeoMode::Blocklist => format!("Every address in {code} is blocked in the firewall."),
            GeoMode::Allowlist => {
                format!("{code} is one of the countries allowed in; every other one is blocked.")
            }
        };
        Explanation::new(format!("Country {code}"))
            .para(effect)
            .now(ranges)
            .para("Delete or Backspace removes it from the list; m changes what the list means.")
            .takes_effect(self.auto_apply_firewall)
    }

    fn explain_crawler(&self, source: &crate::ipranges::CrawlerSource) -> Explanation {
        let category = source.kind.category();
        let policy = match self.category_default(category) {
            Policy::Allowed => "allowed, so these addresses are not blocked",
            Policy::Blocked => "blocked, so these addresses are blocked in the firewall",
        };
        Explanation::new(source.kind.name())
            .para(format!(
                "The addresses {} crawls from, as its owner publishes them. They do two \
                 things: while its category ({}) is blocked, they are blocked in the \
                 firewall, so the crawler cannot get past by changing its user agent; and \
                 the Forged crawler detector uses them to tell the real crawler from a client \
                 only calling itself that.",
                source.short_name(),
                category_label(category)
            ))
            .now(match source.last_fetched_at {
                Some(at) => format!(
                    "{} ranges, downloaded {}; {} is {policy}.",
                    source.range_count,
                    crate::present::ago(at),
                    category_label(category)
                ),
                None => format!(
                    "not downloaded yet; {} is {policy}.",
                    category_label(category)
                ),
            })
            .para(
                "Enter downloads them again. The lists are also updated every week by the \
                 schedule.",
            )
            .takes_effect(self.auto_apply_firewall)
    }

    fn explain_protection(&self, row: ProtectionRow) -> Explanation {
        let label = self.protection_label(row);
        match row {
            ProtectionRow::Detect(detector) => {
                let mut explanation = Explanation::new(label)
                    .para(detector.about())
                    .now(if self.protection_enabled(row) {
                        format!(
                            "on, blocking each address it catches for {} day(s).",
                            self.protection_ttl_days(row)
                        )
                    } else if self.new_detectors.contains(&detector) {
                        "off. New since this database was created, so it has not been \
                         switched on for you."
                            .to_string()
                    } else {
                        "off.".to_string()
                    })
                    .warn_if(detector.risk());
                if detector == Detector::ProbePaths {
                    explanation = explanation.para(format!(
                        "Probes for absent apps, further down this list, is {}: with it on, \
                         /wp-login.php, /phpmyadmin and the like also count, but only where no \
                         site runs WordPress or phpMyAdmin. `stop-bots list-probe-paths` shows \
                         each path and why it counts here or not.",
                        if self.app_probe_paths { "on" } else { "off" }
                    ));
                }
                explanation
                    .para(
                        "It reads the log every minute while the TUI is open, or from cron. \
                         Each block records the log line behind it, on the Blocks screen. \
                         Space switches it; Enter also sets for how long it blocks.",
                    )
                    .takes_effect(self.auto_apply_firewall)
            }
            ProtectionRow::AppProbePaths => Explanation::new(label)
                .para(
                    "Paths that are a scanner's on a host without the application they belong \
                     to: /wp-login.php, /wp-admin and /xmlrpc.php without WordPress, \
                     /phpmyadmin without phpMyAdmin. With this on, the Probe paths detector \
                     blocks a request for one of them, on a site that does not run the \
                     application. Where the log line does not say which site it was for, \
                     only when no site here runs it.",
                )
                .now(if self.app_probe_paths {
                    "on."
                } else if self.app_probe_paths_new {
                    "off. New since this database was created, so it has not been switched \
                     on for you."
                } else {
                    "off: only the built-in and extra probe paths count."
                })
                .para(
                    "A site whose files this cannot see, such as one that passes requests to \
                     another server, counts as running every application. `stop-bots \
                     list-probe-paths` shows each path and why it counts here or not.",
                )
                .takes_effect(self.auto_apply_firewall),
            ProtectionRow::Feed(i) => {
                let Some(source) = self.reputation.get(i) else {
                    return Explanation::new(label);
                };
                let kind = ipranges::reputation::ReputationSourceKind::from_id(&source.id);
                let mut explanation = Explanation::new(label)
                    .para(kind.map(|k| k.about()).unwrap_or_default())
                    .now(match (source.enabled, source.last_fetched_at) {
                        (false, _) => "off.".to_string(),
                        (true, None) => {
                            "on, but not downloaded yet, so it blocks nothing.".to_string()
                        }
                        (true, Some(at)) => format!(
                            "on, {} ranges, downloaded {}.",
                            source.range_count,
                            crate::present::ago(at)
                        ),
                    })
                    .warn_if(kind.and_then(|k| k.warning()));
                if kind.is_some_and(|k| k.blocks_infrastructure()) {
                    explanation = explanation.para(
                        "Port 80 stays open to these ranges unless you chose otherwise when \
                         turning AWS on, because Let's Encrypt checks certificates from AWS.",
                    );
                }
                explanation
                    .para("Space switches it. It is downloaded again every week.")
                    .takes_effect(self.auto_apply_firewall)
            }
            ProtectionRow::HostingProviders => self.explain_hosting_providers(label),
            ProtectionRow::RepeatOffenders => {
                use crate::protection::{
                    ESCALATION_MAX_DAYS, ESCALATION_MAX_MULTIPLIER, OFFENCE_MEMORY_DAYS,
                };
                Explanation::new(label)
                    .para(format!(
                        "An address a detector blocks again, after an earlier block from any \
                         detector, is blocked for longer: twice the detector's time on the \
                         second offence, four times on the third, up to {ESCALATION_MAX_MULTIPLIER} \
                         times and at most {ESCALATION_MAX_DAYS} days. An address is forgotten \
                         {OFFENCE_MEMORY_DAYS} days after its last block ends."
                    ))
                    .now(if self.repeat_offenders {
                        "on."
                    } else if self.repeat_offenders_new {
                        "off. New since this database was created, so it has not been switched \
                         on for you."
                    } else {
                        "off: every block lasts its detector's own time."
                    })
                    .para(
                        "Offences are counted even while this is off, so turning it on uses the \
                         history. Unblocking an address by hand forgets its offences. The Blocks \
                         screen shows which offence each block is.",
                    )
                    .takes_effect(self.auto_apply_firewall)
            }
            ProtectionRow::AutoApplyFirewall => Explanation::new(label)
                .para(
                    "Whether the scheduled render also runs the firewall script it writes. \
                     The render runs within a minute of any change to the rules (five, after \
                     one that failed) and at least once a day, while the TUI is open or from \
                     cron.",
                )
                .now(if self.auto_apply_firewall {
                    "on: new blocks reach the firewall within minutes, with no preview."
                } else {
                    "off: the script is written, and runs when you apply (a)."
                })
                .para(
                    "Every apply still goes through the SSH lock-out check, and is refused \
                     when the SSH log cannot be read.",
                ),
            ProtectionRow::LockoutCheck => Explanation::new(label)
                .para(
                    "Before any firewall apply, checks the new rules against every address \
                     that logged in over SSH in the last week, and the SSH session this runs \
                     in, and refuses an apply that would block one.",
                )
                .now(if self.ssh_lockout_check {
                    "on."
                } else {
                    "off: applies are not checked. Addresses that log in over SSH are still \
                     let through ahead of every block."
                })
                .para(
                    "Turn it off only on a server you never log into over SSH, such as one \
                     you reach through your provider's console. stop-bots status warns if \
                     anyone logs in over SSH while it is off.",
                ),
            ProtectionRow::Outbound => Explanation::new(label)
                .para(
                    "Checks connections this host and its containers start, to the \
                     command-and-control servers the feeds below list. A connection to one \
                     means something here is probably compromised. Watch logs it and lets it \
                     through; Block logs it and drops it. Each one is read back every minute, \
                     with the user or container that made it.",
                )
                .now(format!("{}.", self.egress_mode.describe()))
                .para(
                    "Whatever would cut this host off is left out of every feed: private and \
                     reserved ranges, its resolvers, apt mirrors, Let's Encrypt and the feeds' \
                     own servers. Trusted addresses are never stopped.",
                )
                .para(
                    "Space steps through Off, Watch and Block; Enter chooses. The feeds \
                     (Feodo Tracker is the one to start with) and containment are listed under \
                     it once it is on.",
                )
                .takes_effect(self.auto_apply_firewall),
            ProtectionRow::EgressFeed(i) => {
                let Some(feed) = self.egress_feeds.get(i) else {
                    return Explanation::new(label);
                };
                let about = crate::egress::FeedKind::from_id(&feed.id)
                    .filter(|_| feed.builtin)
                    .map(|k| k.about().to_string())
                    .unwrap_or_else(|| {
                        format!(
                            "Added by URL, from {}.",
                            crate::egress::masked_url(&feed.url)
                        )
                    });
                Explanation::new(label)
                    .para(about)
                    .now(match (feed.enabled, feed.last_fetched_at) {
                        (false, _) => "off.".to_string(),
                        (true, None) => {
                            "on, but not downloaded yet, so it checks nothing.".to_string()
                        }
                        (true, Some(at)) => format!(
                            "on, {} entries, downloaded {}{}.",
                            feed.entry_count,
                            crate::present::ago(at),
                            if feed.contain {
                                ", and a hit on it may contain"
                            } else {
                                ""
                            }
                        ),
                    })
                    .para("Space switches it. It is downloaded again every day.")
                    .takes_effect(self.auto_apply_firewall)
            }
            ProtectionRow::AutoContain => Explanation::new(label)
                .para(
                    "Cuts off and pauses a container that calls a C&C server, within the \
                     minute, in Block mode only, and only for a feed allowed to contain. A \
                     breaker stops it after three in an hour. Root, a user logged in now and \
                     anything on the never-contain list are never contained.",
                )
                .now(if self.auto_contain {
                    "on: containers are contained automatically."
                } else {
                    "off: hits are reported, nothing is contained."
                })
                .para(
                    "Users on the host, other actions and the never-contain list are set with \
                     `stop-bots set-containment`; `stop-bots release` lets one go.",
                ),
        }
    }

    fn explain_hosting_providers(&self, label: String) -> Explanation {
        use ipranges::hosting;
        let unfetched: Vec<String> = self
            .hosting_asns
            .iter()
            .filter(|asn| asn.last_fetched_at.is_none())
            .map(|asn| hosting::label(asn.asn, asn.description.as_deref()))
            .collect();
        let names: Vec<String> = self
            .hosting_asns
            .iter()
            .map(|asn| hosting::label(asn.asn, asn.description.as_deref()))
            .collect();
        let ranges: i64 = self.hosting_asns.iter().map(|asn| asn.range_count).sum();
        Explanation::new(label)
            .para(hosting::about())
            .now(if names.is_empty() {
                "none blocked.".to_string()
            } else if unfetched.is_empty() {
                format!("blocking {}, {ranges} ranges.", names.join(", "))
            } else {
                format!(
                    "blocking {}; not downloaded yet, so not blocked: {}.",
                    names.join(", "),
                    unfetched.join(", ")
                )
            })
            .warn(format!("It {}.", hosting::warning()))
            .para(
                "Port 80 stays open to these ranges, as to the cloud feeds, unless you chose \
                 otherwise when turning AWS on, so Let's Encrypt can still renew.",
            )
            .para(
                "Enter or Space opens the list: Space ticks a provider, Enter saves and \
                 downloads what is new. AWS, Google Cloud and DigitalOcean are feeds of \
                 their own, above. Downloaded again every week.",
            )
            .takes_effect(self.auto_apply_firewall)
    }

    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        log: &[(i64, String)],
        running_jobs: &std::collections::HashSet<crate::app::Job>,
    ) {
        if self.simple {
            self.render_simple(frame, area, theme, log);
            if let Some(popup) = self.popup.clone() {
                self.render_popup(frame, area, popup, theme);
            }
            return;
        }
        // Two columns over a log. The left column is *policy* — what this
        // host blocks by category, by country, and the script those become —
        // with the schedule that writes and applies it under it; the right
        // column is what the host does on its own: every detector and feed.
        // The log at the foot is the one panel that spans both, because a
        // message can come from either side.
        //
        // Automatic blocking has the right column to itself because it is
        // the panel that grows: a row per detector and feed, in one column.
        // On a terminal too short for every row it scrolls. Scheduled tasks holds `Min(3)` on the left, beside the
        // script it runs, so it never vanishes: it is the panel reporting
        // what the detectors just did.
        let [columns_area, log_area] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(LOG_HEIGHT)]).areas(area);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(columns_area);

        let [settings_area, geo_area, crawlers_area, firewall_area, cron_area] =
            Layout::vertical([
                Constraint::Length(POLICY_ROWS as u16 + 2),
                Constraint::Min(4),
                Constraint::Length(ipranges::IpRangeSourceKind::ALL.len() as u16 + 2),
                Constraint::Length(if self.egress.is_some() { 5 } else { 4 }),
                Constraint::Min(3),
            ])
            .areas(left);
        let label_width = self.protection_label_width();
        let rows = self.protection_rows();
        let mut headings: Vec<ProtectionGroup> =
            rows.iter().map(|r| ProtectionGroup::of(*r)).collect();
        headings.dedup();
        let protection_height = (rows.len() + headings.len()) as u16 + 2;
        let [protection_area, _] =
            Layout::vertical([Constraint::Max(protection_height), Constraint::Min(0)]).areas(right);

        self.render_categories(frame, settings_area, theme);
        self.render_geo(frame, geo_area, theme);
        self.render_crawlers(frame, crawlers_area, theme);
        self.render_firewall(frame, firewall_area, theme);
        self.render_protection(frame, protection_area, theme, label_width);
        self.render_cron(frame, cron_area, theme, running_jobs);
        self.render_log(frame, log_area, theme, log);

        if let Some(popup) = self.popup.clone() {
            self.render_popup(frame, area, popup, theme);
        }
    }

    fn render_categories(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = std::iter::once(ListItem::new(self.humans_only_line()))
            .chain(
                CATEGORIES
                    .iter()
                    .map(|&category| ListItem::new(self.row_line(category))),
            )
            .chain(std::iter::once(ListItem::new(self.old_browsers_line())))
            .chain(std::iter::once(ListItem::new(self.http_libraries_line())))
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
        let items: Vec<ListItem> = std::iter::once(ListItem::new(
            Line::from("Enter to add a country, m to change mode").italic(),
        ))
        .chain(
            self.selected_countries
                .iter()
                .map(|cc| ListItem::new(self.country_row_line(cc))),
        )
        .collect();
        // The *mode* is in the title and nothing else is: Allowlist turns
        // the host into default-deny, so it must never be what a narrow
        // panel truncates away.
        let mode_label = match (self.geo_choice(), self.simple) {
            (GEO_BLOCKLIST, false) => "blocklist".to_string(),
            (GEO_ALLOWLIST, false) => "allowlist".to_string(),
            (GEO_BLOCKLIST, true) => "these are blocked".to_string(),
            (GEO_ALLOWLIST, true) => "only these are allowed".to_string(),
            _ => format!("only trusted IPs ({})", self.trusted_addresses),
        };
        let focused = self.focus == Focus::Countries;
        let title = if self.simple { "Countries" } else { "Geo" };
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel(
                format!("{title} \u{00b7} {mode_label}"),
                focused,
                theme,
            )),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.countries_state);
    }

    /// One row per published crawler range: whether its category blocks
    /// it — which is what decides whether these addresses reach the
    /// firewall script — how many ranges it holds, and how old they are.
    fn render_crawlers(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = self
            .crawlers
            .iter()
            .map(|source| ListItem::new(self.crawler_row_line(source, theme)))
            .collect();
        let focused = self.focus == Focus::Crawlers;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Crawler IP ranges", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.crawlers_state);
    }

    fn crawler_row_line(
        &self,
        source: &crate::ipranges::CrawlerSource,
        theme: Theme,
    ) -> Line<'static> {
        let fetched = match source.last_fetched_at {
            Some(at) => Span::from(format!(
                "{} \u{00b7} {}",
                source.range_count,
                crate::present::ago(at)
            )),
            None => Span::from("not fetched").fg(theme.dim()),
        };
        Line::from(vec![
            Span::from(format!("{:<9}", source.short_name())),
            policy_tag(self.category_default(source.kind.category())),
            fetched,
        ])
    }

    /// How wide the widest row label is, so every tag lines up beneath
    /// the one above it. Measured from the rows on screen rather than
    /// fixed, so a longer label widens the column instead of being cut off.
    fn protection_label_width(&self) -> u16 {
        self.protection_rows()
            .iter()
            .map(|row| self.protection_label(*row).chars().count() as u16)
            .max()
            .unwrap_or(0)
    }

    /// Draws the rows in one column. It used to deal them into as many
    /// columns as the width allowed; one reads better, and on a terminal
    /// too short for every row the list scrolls to the selection.
    fn render_protection(&mut self, frame: &mut Frame, area: Rect, theme: Theme, label_width: u16) {
        let focused = self.focus == Focus::Protection;
        let mut items: Vec<ListItem> = Vec::new();
        let mut selected_line = None;
        let mut group = None;
        for (index, row) in self.protection_rows().into_iter().enumerate() {
            let this = ProtectionGroup::of(row);
            if group != Some(this) {
                group = Some(this);
                items.push(ListItem::new(Line::from(this.heading().bold())));
            }
            if self.protection_state.selected() == Some(index) {
                selected_line = Some(items.len());
            }
            items.push(ListItem::new(
                self.protection_row_line(row, label_width as usize),
            ));
        }
        // The headings are lines of their own, so the list is drawn with
        // the selection moved to the line its row landed on.
        let mut state = ListState::default().with_selected(selected_line);
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Automatic blocking", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut state);
    }

    /// What the rules become: the script, and whether the one on disk is
    /// still the one these rules would write. What used to be a Summary
    /// panel of its own (sites found, bot-list freshness) is the second line,
    /// because those are the inputs the script is rendered from.
    fn render_firewall(&self, frame: &mut Frame, area: Rect, theme: Theme) {
        // Three states, not two. A fresh install has no rules at all,
        // and telling someone to press `F` there sends them to render
        // an empty script — which looks like the tool doing nothing.
        use crate::firewall::ScriptState;
        let script = match (self.rule_count, self.script_state) {
            (0, _) => Line::from(vec![
                " no rules yet".into(),
                " \u{2014} enable a detector".fg(theme.dim()),
            ]),
            (n, ScriptState::Changed) => Line::from(vec![
                format!(" {n} rules  ").into(),
                "[ CHANGED ]".yellow(),
                "  a to apply".fg(theme.dim()),
            ]),
            // The state the internal cron leaves behind on its own: the
            // script is on disk and inert. Saying "up to date" here is how
            // an operator comes to believe it is enforced.
            (n, ScriptState::RenderedNotApplied) => Line::from(vec![
                format!(" {n} rules  ").into(),
                "[ NOT APPLIED ]".yellow(),
                "  a to apply".fg(theme.dim()),
            ]),
            (n, ScriptState::Applied) => {
                Line::from(vec![format!(" {n} rules  ").into(), "[ APPLIED ]".green()])
            }
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
        let mut lines = vec![script, inputs];
        if let Some(outbound) = &self.egress {
            let mut line = vec![
                " outbound ".into(),
                outbound.mode.as_str().to_string().bold(),
            ];
            if outbound.contained > 0 {
                line.push("  \u{00b7}  ".fg(theme.dim()));
                line.push(format!("{} contained", outbound.contained).yellow());
            }
            if outbound.recent_hits > 0 {
                line.push("  ".into());
                line.push(
                    format!("[ {} C&C HIT(S) ]", outbound.recent_hits)
                        .red()
                        .bold(),
                );
            }
            lines.push(Line::from(line));
        }
        let panel = Paragraph::new(lines).block(crate::tui::panel("Firewall script", false, theme));
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
                let when = format!(" {:<9}", crate::present::ago(*at));
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

    /// The switch's own row. Says what it does rather than just naming
    /// itself, because "Humans only" alone does not tell an operator that
    /// it is about to block every crawler they have.
    fn humans_only_line(&self) -> Line<'static> {
        let mut line = vec![Span::from(format!("{:<14}", "Humans only"))];
        line.push(if self.humans_only {
            Span::from("[ ON ]").red().bold()
        } else {
            Span::from("[ off ]").dim()
        });
        Line::from(line)
    }

    /// The old-browser switch, tagged as a category is: it allows or
    /// blocks, and humans only leaves it alone.
    fn old_browsers_line(&self) -> Line<'static> {
        vec![
            Span::from(format!("{:<14}", "Old browsers")),
            policy_tag(if self.old_browsers {
                Policy::Blocked
            } else {
                Policy::Allowed
            }),
        ]
        .into()
    }

    /// The HTTP-library switch, tagged as old browsers is, but blocked
    /// while humans only is on whatever the switch says.
    fn http_libraries_line(&self) -> Line<'static> {
        vec![
            Span::from(format!("{:<14}", "HTTP libraries")),
            policy_tag(if self.http_libraries || self.humans_only {
                Policy::Blocked
            } else {
                Policy::Allowed
            }),
        ]
        .into()
    }

    fn row_line(&self, category: Category) -> Line<'static> {
        let mut line = vec![Span::from(format!("{:<14}", category_label(category)))];
        line.push(policy_tag(self.category_default(category)));
        // Dimmed and labelled rather than hidden: the policy in force is
        // still the useful thing to read, and the operator needs to know
        // why it cannot be changed here.
        if self.humans_only {
            line.push(Span::from("  forced").dim());
        }
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
            // The robots.txt rule belongs to the humans-only switch, not to
            // this panel: outside that mode it can never fire, and a row
            // that is permanently off with a toggle that does nothing is
            // the "enabled detector that can never fire" the Honeypot
            // default already argues against. It also keeps the panel the
            // height it was for every host that does not use the mode.
            .filter(|detector| *detector != Detector::RobotsTxt || self.humans_only)
            .map(ProtectionRow::Detect)
            .chain([ProtectionRow::RepeatOffenders, ProtectionRow::AppProbePaths])
            .chain((0..self.reputation.len()).map(ProtectionRow::Feed))
            .chain([ProtectionRow::HostingProviders, ProtectionRow::Outbound])
            // Only once outbound checks are on: until then a feed would
            // check nothing.
            .chain(
                (0..self.egress_feeds.len())
                    .map(ProtectionRow::EgressFeed)
                    .chain([ProtectionRow::AutoContain])
                    .filter(|_| self.egress_mode != crate::egress::Mode::Off),
            )
            .chain([
                ProtectionRow::AutoApplyFirewall,
                ProtectionRow::LockoutCheck,
            ])
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
            ProtectionRow::RepeatOffenders => "Repeat offenders".to_string(),
            ProtectionRow::HostingProviders => "Hosting providers".to_string(),
            ProtectionRow::AppProbePaths => "Probes for absent apps".to_string(),
            ProtectionRow::AutoApplyFirewall => "Auto-apply the script".to_string(),
            ProtectionRow::LockoutCheck => "SSH lock-out check".to_string(),
            ProtectionRow::Outbound => "Checks".to_string(),
            ProtectionRow::EgressFeed(i) => self
                .egress_feeds
                .get(i)
                .map(|f| f.name.clone())
                .unwrap_or_default(),
            ProtectionRow::AutoContain => "Contain on a hit".to_string(),
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
            ProtectionRow::RepeatOffenders => self.repeat_offenders,
            ProtectionRow::HostingProviders => !self.hosting_asns.is_empty(),
            ProtectionRow::AppProbePaths => self.app_probe_paths,
            ProtectionRow::AutoApplyFirewall => self.auto_apply_firewall,
            ProtectionRow::LockoutCheck => self.ssh_lockout_check,
            ProtectionRow::Outbound => self.egress_mode != crate::egress::Mode::Off,
            ProtectionRow::EgressFeed(i) => self.egress_feeds.get(i).is_some_and(|f| f.enabled),
            ProtectionRow::AutoContain => self.auto_contain,
        }
    }

    /// Whether `row` arrived after this database was created and nobody
    /// has switched it: the rows that show a yellow "new".
    fn protection_is_new(&self, row: ProtectionRow) -> bool {
        match row {
            ProtectionRow::Detect(detector) => self.new_detectors.contains(&detector),
            ProtectionRow::RepeatOffenders => self.repeat_offenders_new,
            ProtectionRow::AppProbePaths => self.app_probe_paths_new,
            _ => false,
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
            ProtectionRow::Feed(_)
            | ProtectionRow::HostingProviders
            | ProtectionRow::RepeatOffenders
            | ProtectionRow::AppProbePaths
            | ProtectionRow::AutoApplyFirewall
            | ProtectionRow::LockoutCheck
            | ProtectionRow::Outbound
            | ProtectionRow::EgressFeed(_)
            | ProtectionRow::AutoContain => 0,
        }
    }

    /// What follows a row's tag: a feed's range count (or that it has none
    /// yet), or an enabled detector's TTL. Its own method so
    /// [`Self::protection_label_width`]'s rows can line up.
    fn protection_detail(&self, row: ProtectionRow) -> String {
        match row {
            ProtectionRow::Feed(i) => match self.reputation.get(i) {
                // "not fetched" is the important state to surface: an
                // enabled feed with no ranges is silently doing nothing.
                Some(s) if s.last_fetched_at.is_none() => " not fetched".to_string(),
                Some(s) => format!(" {}", s.range_count),
                None => String::new(),
            },
            // How many, which is what the row cannot show by name; and,
            // as for a feed, whether any is doing nothing for want of a
            // download.
            ProtectionRow::HostingProviders if self.hosting_asns.is_empty() => String::new(),
            ProtectionRow::HostingProviders
                if self
                    .hosting_asns
                    .iter()
                    .any(|asn| asn.last_fetched_at.is_none()) =>
            {
                " not fetched".to_string()
            }
            ProtectionRow::HostingProviders => format!(" {} blocked", self.hosting_asns.len()),
            // No TTL and no count — the state is the whole story, and the
            // tag already carries it.
            ProtectionRow::AutoApplyFirewall | ProtectionRow::LockoutCheck => String::new(),
            // How many feeds, the one thing the tag cannot say, and that
            // a hit contains.
            ProtectionRow::Outbound if self.egress_mode == crate::egress::Mode::Off => {
                String::new()
            }
            ProtectionRow::Outbound => {
                if self.egress_feeds.iter().any(|f| f.enabled) {
                    String::new()
                } else {
                    " no feed on".to_string()
                }
            }
            ProtectionRow::AutoContain => String::new(),
            ProtectionRow::EgressFeed(i) => match self.egress_feeds.get(i) {
                Some(f) if f.last_fetched_at.is_none() => " not fetched".to_string(),
                Some(f) => format!(" {}", f.entry_count),
                None => String::new(),
            },
            _ if self.protection_is_new(row) => " new".to_string(),
            // How much longer, at most: the whole rule is in the message
            // switching it on leaves.
            ProtectionRow::RepeatOffenders if self.repeat_offenders => {
                format!(" up to {}x", crate::protection::ESCALATION_MAX_MULTIPLIER)
            }
            ProtectionRow::RepeatOffenders | ProtectionRow::AppProbePaths => String::new(),
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
        let tag = match (row, self.egress_mode) {
            // Three states, so the tag says which.
            (ProtectionRow::Outbound, crate::egress::Mode::Watch) => Span::from("[WATCH]").yellow(),
            (ProtectionRow::Outbound, crate::egress::Mode::Block) => Span::from("[BLOCK]").green(),
            _ if enabled => Span::from("[ ON  ]").green(),
            _ => Span::from("[ OFF ]").dim(),
        };
        Line::from(vec![
            Span::from(format!(
                "{:indent$}{:<label_width$} ",
                "",
                self.protection_label(row),
                indent = PROTECTION_INDENT,
                label_width = label_width
            )),
            tag,
            // "new" is the one detail worth catching the eye: something an
            // upgrade added and left off, which nobody has looked at yet.
            if self.protection_is_new(row) {
                Span::from(self.protection_detail(row)).yellow()
            } else {
                Span::from(self.protection_detail(row))
            },
        ])
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: Popup, theme: Theme) {
        match popup {
            Popup::ConfirmApply {
                server,
                lines,
                diff,
                show_diff,
                scroll,
            } => render_confirm_apply(
                frame,
                area,
                server,
                &lines,
                show_diff.then_some(&diff[..]),
                scroll,
                theme,
            ),
            // Three of the five popups are the same widget with different
            // strings: a centred list, one row per option, the selected row
            // reversed. Only the two that are *not* option lists — a text
            // field, and a multi-field form — get their own arm.
            Popup::Protection { row, selected } => render_option_list(
                frame,
                area,
                &self.protection_label(row),
                &protection_options(row),
                selected,
                theme,
            ),
            Popup::HostingProviders { cursor, chosen } => {
                self.render_hosting_providers(frame, area, cursor, &chosen, theme);
            }
            Popup::CloudPort80 { selected, .. } => render_option_list(
                frame,
                area,
                "Let's Encrypt validates from AWS",
                &[
                    "Block AWS, keep port 80 open for renewals".to_string(),
                    "Block AWS on port 80 too: renewals fail".to_string(),
                ],
                selected,
                theme,
            ),
            Popup::NoLogins { preview, selected } => {
                let catch_all = preview.as_ref().and_then(|preview| {
                    match &preview.firewall.as_ref().ok()?.guard {
                        crate::firewall::Guard::NoLogins { catch_all } => catch_all.clone(),
                        _ => None,
                    }
                });
                render_no_logins(frame, area, preview.is_some(), catch_all, selected, theme)
            }
            Popup::Confirm { what, selected } => {
                let (title, text, options) = self.confirm_text(what);
                render_question(frame, area, &title, text, &options, selected, theme)
            }
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
                    "Only trusted IPs (block everything else)".to_string(),
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
                            1 => "iptables (no kernel expiry, no allowlist)",
                            _ => "unknown",
                        })
                        .reversed(),
                        Span::from(" ]"),
                        match self.installed {
                            Some(installed) if !installed.has(popup_backend(backend_selected)) => {
                                Span::from(" not installed").red()
                            }
                            _ => Span::from(""),
                        },
                    ]),
                    Line::from(""),
                    Line::from(format!("Output: {}_", out_path)),
                    Line::from(format!(
                        // Not "applied": that word is how a test tells
                        // the render's own message has arrived.
                        "  writes {} first; this path once it has run",
                        crate::firewall::rendered_path(std::path::Path::new(&out_path)).display()
                    ))
                    .fg(theme.dim()),
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
                Popup::CloudPort80 { .. } => self.handle_cloud_port_80_popup_key(key, db, message),
                Popup::HostingProviders { .. } => {
                    self.handle_hosting_providers_popup_key(key, db, message)
                }
                Popup::GeoMode { .. } => self.handle_geo_mode_popup_key(key, db, message),
                Popup::RenderFirewall { .. } => self.handle_render_firewall_popup_key(key),
                Popup::ConfirmApply { .. } => self.handle_confirm_apply_popup_key(key, message),
                Popup::NoLogins { .. } => self.handle_no_logins_popup_key(key, db, message),
                Popup::Confirm { .. } => self.handle_confirm_popup_key(key, db, message),
            };
        }

        if key.code == KeyCode::Char('m') {
            self.popup = Some(Popup::GeoMode {
                selected: self.geo_choice(),
            });
            return Ok(KeyOutcome::Consumed);
        }

        // Host-wide, one key each. An update only downloads, so it just
        // runs. An apply rewrites every site and runs the firewall script
        // as root, so it asks first, with what would change in front of
        // the operator — see `Popup::ConfirmApply`.
        if key.code == KeyCode::Char('u') {
            return Ok(KeyOutcome::UpdateEverything);
        }
        if key.code == KeyCode::Char('a') {
            return Ok(KeyOutcome::PreviewApplyEverything);
        }

        // Capital F: it writes to the host. Lower-case `f` is "filter" on
        // every screen that has a list worth filtering, and this one does
        // not, so the key is free rather than overloaded.
        if key.code == KeyCode::Char('F') {
            // Opens on the backend this host renders for, and that
            // backend's applied script — an iptables host offered
            // `firewall.nft` ends up with a shell script in it.
            let backend = crate::firewall::stored_backend(db)?;
            self.popup = Some(Popup::RenderFirewall {
                backend_selected: match backend {
                    crate::firewall::FirewallBackend::Nftables => 0,
                    crate::firewall::FirewallBackend::Iptables => 1,
                },
                out_path: crate::firewall::default_output_path(backend)
                    .display()
                    .to_string(),
                apply_after_write: false,
                error: None,
            });
            return Ok(KeyOutcome::Consumed);
        }

        // The rest is per panel, and the simple screen has panels of its
        // own; the host-wide keys above are the same on both.
        if self.simple {
            return self.handle_simple_key(key, db, message);
        }

        // Tab always means "next panel" on this screen (BackTab the
        // previous), so it means the same thing it does on NGINX
        // and Firewall. Up/Down still flow across the panels
        // too, for hands that never learned Tab.
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            let forward = key.code == KeyCode::Tab;
            self.focus = match (self.focus, forward) {
                (Focus::Categories, true) | (Focus::Crawlers, false) => Focus::Countries,
                (Focus::Countries, true) | (Focus::Protection, false) => Focus::Crawlers,
                (Focus::Crawlers, true) | (Focus::Categories, false) => Focus::Protection,
                (Focus::Protection | Focus::Essentials, true) | (Focus::Countries, false) => {
                    Focus::Categories
                }
                (Focus::Essentials, false) => Focus::Protection,
            };
            match self.focus {
                Focus::Categories if self.list_state.selected().is_none() => {
                    self.list_state.select(Some(0));
                }
                Focus::Countries if self.countries_state.selected().is_none() => {
                    self.countries_state.select(Some(0));
                }
                Focus::Crawlers if self.crawlers_state.selected().is_none() => {
                    self.crawlers_state.select(Some(0));
                }
                Focus::Protection if self.protection_state.selected().is_none() => {
                    self.protection_state.select(Some(0));
                }
                _ => {}
            }
            return Ok(KeyOutcome::Consumed);
        }

        match self.focus {
            Focus::Categories => match key.code {
                // No popup open: let `App`'s global handling decide (Esc/q
                // quit from the Dashboard).
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.list_state.selected() == Some(POLICY_ROWS - 1) {
                        self.focus = Focus::Countries;
                        self.countries_state.select(Some(0));
                    } else {
                        self.list_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return self.activate_policy_row(db, message)
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Countries => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.countries_state.selected() == Some(0) {
                        self.focus = Focus::Categories;
                        self.list_state.select(Some(POLICY_ROWS - 1));
                    } else {
                        self.countries_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    // The Countries list has one row per selected country
                    // plus the fixed "add a country" row at index 0, so
                    // its last index is `len()`, not `len() - 1`.
                    if self.countries_state.selected() == Some(self.selected_countries.len()) {
                        self.focus = Focus::Crawlers;
                        self.crawlers_state.select(Some(0));
                    } else {
                        self.countries_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return Ok(self.activate_country_row(message));
                }
                KeyCode::Delete | KeyCode::Backspace => {
                    return self.remove_country_row(message, db);
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Crawlers => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.crawlers_state.selected() == Some(0) {
                        self.focus = Focus::Countries;
                        self.countries_state
                            .select(Some(self.selected_countries.len()));
                    } else {
                        self.crawlers_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.crawlers_state.selected().unwrap_or(0) + 1 >= self.crawlers.len() {
                        self.focus = Focus::Protection;
                        self.protection_state.select(Some(0));
                    } else {
                        self.crawlers_state.select_next();
                    }
                }
                // A download, which `App` owns: the key handler stays free
                // of network I/O, as it does for `u`.
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if let Some(source) = self
                        .crawlers_state
                        .selected()
                        .and_then(|i| self.crawlers.get(i))
                    {
                        return Ok(KeyOutcome::RefreshCrawlerRanges(source.kind));
                    }
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Protection => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Ignored),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.protection_state.selected() == Some(0) {
                        self.focus = Focus::Crawlers;
                        self.crawlers_state
                            .select(Some(self.crawlers.len().saturating_sub(1)));
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
            // The simple screen's; `set_simple` moves focus off it.
            Focus::Essentials => return Ok(KeyOutcome::Ignored),
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
        // A list, not a switch: there is no one thing to flip.
        if row == ProtectionRow::HostingProviders {
            self.open_hosting_providers_popup();
            return Ok(KeyOutcome::Consumed);
        }
        if row == ProtectionRow::Outbound {
            self.cycle_outbound(db, message)?;
            return Ok(KeyOutcome::Mutated);
        }
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
        if row == ProtectionRow::HostingProviders {
            self.open_hosting_providers_popup();
            return;
        }
        if row == ProtectionRow::Outbound {
            let selected = crate::egress::Mode::ALL
                .iter()
                .position(|mode| *mode == self.egress_mode)
                .unwrap_or(0);
            self.popup = Some(Popup::Protection { row, selected });
            return;
        }
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
        if row == ProtectionRow::Outbound {
            let mode = crate::egress::Mode::ALL
                .get(selected)
                .copied()
                .unwrap_or_default();
            while self.egress_mode != mode {
                self.cycle_outbound(db, message)?;
            }
            return Ok(KeyOutcome::Mutated);
        }
        if let ProtectionRow::EgressFeed(i) = row {
            if self.protection_enabled(row) == (selected == 1) {
                return Ok(KeyOutcome::Consumed);
            }
            return Ok(if self.toggle_egress_feed(db, i, message)? {
                KeyOutcome::UpdateEgressFeeds
            } else {
                KeyOutcome::Mutated
            });
        }
        if row == ProtectionRow::AutoContain {
            if selected == 1 && !self.auto_contain {
                self.popup = Some(Popup::Confirm {
                    what: Confirm::AutoContain,
                    selected: 0,
                });
                return Ok(KeyOutcome::Consumed);
            }
            return self.commit_auto_contain(db, selected == 1, message);
        }

        if row == ProtectionRow::LockoutCheck {
            if selected == 0 {
                // Off only once asked: see `Popup::NoLogins`.
                self.popup = Some(Popup::NoLogins {
                    preview: None,
                    selected: 0,
                });
                return Ok(KeyOutcome::Consumed);
            }
            db.set_ssh_lockout_check(true)?;
            self.ssh_lockout_check = true;
            *message = Some(
                "SSH lock-out check on \u{2014} every apply is checked against the addresses \
                 that log in over SSH"
                    .to_string(),
            );
            return Ok(KeyOutcome::Mutated);
        }
        if row == ProtectionRow::AutoApplyFirewall {
            let on = selected == 1;
            if on && !self.auto_apply_firewall {
                self.popup = Some(Popup::Confirm {
                    what: Confirm::AutoApplyFirewall,
                    selected: 0,
                });
                return Ok(KeyOutcome::Consumed);
            }
            return self.commit_auto_apply_firewall(db, on, message);
        }
        if row == ProtectionRow::RepeatOffenders {
            let on = selected == 1;
            crate::protection::set_repeat_escalation(db, on)?;
            self.repeat_offenders = on;
            self.repeat_offenders_new = false;
            *message = Some(if on {
                format!(
                    "Repeat offenders on \u{2014} {}",
                    crate::protection::repeat_escalation_summary()
                )
            } else {
                "Repeat offenders off \u{2014} an address blocked again gets its detector's \
                 TTL, however often it comes back"
                    .to_string()
            });
            return Ok(KeyOutcome::Mutated);
        }
        if row == ProtectionRow::AppProbePaths {
            let on = selected == 1;
            crate::protection::set_app_probe_paths(db, on)?;
            self.app_probe_paths = on;
            self.app_probe_paths_new = false;
            *message = Some(if on {
                format!(
                    "Probes for absent apps on \u{2014} {}",
                    crate::protection::app_probe_paths_summary()
                )
            } else {
                "Probes for absent apps off \u{2014} only the built-in and extra probe paths \
                 count"
                    .to_string()
            });
            return Ok(KeyOutcome::Mutated);
        }
        let ProtectionRow::Detect(detector) = row else {
            unreachable!("feeds are committed by commit_feed, hosting providers by their popup")
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
        // Asked first, because the AWS feed takes this host's certificates
        // with it unless port 80 stays open, and whether it does is a
        // setting nobody would think to look for.
        if enabled && source.id == ipranges::reputation::ReputationSourceKind::Aws.id() {
            let open = db.get_cloud_port_80_open()?;
            self.popup = Some(Popup::CloudPort80 {
                feed: index,
                selected: if open { 0 } else { 1 },
            });
            return Ok(KeyOutcome::Consumed);
        }
        self.switch_feed(db, &source, enabled, "", message)
    }

    /// [`Self::commit_feed`] once nothing is left to ask. `note` follows
    /// "on" in the message, ahead of the warning that can run off the
    /// Log panel's edge.
    fn switch_feed(
        &mut self,
        db: &Db,
        source: &crate::db::ReputationSource,
        enabled: bool,
        note: &str,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        db.set_reputation_source_enabled(&source.id, enabled)?;
        if !enabled {
            *message = Some(format!("{} off", source.name));
            return Ok(KeyOutcome::Mutated);
        }

        // Surfaced on enable, not buried in a doc comment: the provider
        // feeds block every visitor hosted there, and unlike a detector
        // there's no behavioural evidence behind it.
        let warning = ipranges::reputation::ReputationSourceKind::from_id(&source.id)
            .and_then(|k| k.warning())
            .map(|w| format!(" — {w}"))
            .unwrap_or_default();

        if source.last_fetched_at.is_none() {
            *message = Some(format!("{} on{note}, fetching…{warning}", source.name));
            return Ok(KeyOutcome::FetchReputationSource(source.id.clone()));
        }
        *message = Some(format!(
            "{} on{note} ({} range(s)) — apply (a) to enforce them{warning}",
            source.name, source.range_count
        ));
        Ok(KeyOutcome::Mutated)
    }

    /// The next mode after the current one, Off -> Watch -> Block -> Off,
    /// and what it takes to enforce: the rules reach the kernel on the
    /// next apply, and check nothing until a feed is on.
    fn cycle_outbound(&mut self, db: &Db, message: &mut Option<String>) -> Result<()> {
        let mode = match self.egress_mode {
            crate::egress::Mode::Off => crate::egress::Mode::Watch,
            crate::egress::Mode::Watch => crate::egress::Mode::Block,
            crate::egress::Mode::Block => crate::egress::Mode::Off,
        };
        mode.set(db)?;
        self.egress_mode = mode;
        let any_feed = self
            .egress_feeds
            .iter()
            .any(|f| f.enabled && f.kind == crate::egress::EntryKind::Ip);
        *message = Some(match mode {
            crate::egress::Mode::Off => {
                "Outbound checks off \u{2014} apply (a) to take them out of the firewall"
                    .to_string()
            }
            _ if !any_feed => format!(
                "Outbound checks: {} \u{2014} tick a C&C feed, then apply (a)",
                mode.as_str()
            ),
            _ => format!(
                "Outbound checks: {} \u{2014} apply (a) to load them",
                mode.as_str()
            ),
        });
        Ok(())
    }

    /// Switches C&C feed `index`, and says whether it needs a first
    /// download, which `App` runs once the popup closes
    /// (`KeyOutcome::UpdateEgressFeeds`), for the reason
    /// [`Self::commit_feed`] gives.
    fn toggle_egress_feed(
        &mut self,
        db: &Db,
        index: usize,
        message: &mut Option<String>,
    ) -> Result<bool> {
        let Some(feed) = self.egress_feeds.get_mut(index) else {
            return Ok(false);
        };
        feed.enabled = !feed.enabled;
        db.set_egress_feed_enabled(&feed.id, feed.enabled)?;
        let feed = feed.clone();
        if !feed.enabled {
            *message = Some(format!(
                "{} off \u{2014} apply (a) to stop checking it",
                feed.name
            ));
            return Ok(false);
        }
        let resolver = if feed.kind == crate::egress::EntryKind::Domain {
            " Domains reach the resolver once `stop-bots set-egress-dns` chooses one."
        } else {
            ""
        };
        if feed.last_fetched_at.is_none() {
            *message = Some(format!("{} on, fetching\u{2026}{resolver}", feed.name));
            return Ok(true);
        }
        *message = Some(format!(
            "{} on ({} entries) \u{2014} apply (a) to check them.{resolver}",
            feed.name, feed.entry_count
        ));
        Ok(false)
    }

    fn commit_auto_contain(
        &mut self,
        db: &Db,
        on: bool,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        db.set_bool_setting(crate::db::keys::EGRESS_AUTO_CONTAIN, on)?;
        self.auto_contain = on;
        *message = Some(if !on {
            "Containment off \u{2014} a hit is reported, and nothing is contained".to_string()
        } else if self.egress_mode != crate::egress::Mode::Block {
            "Containment on \u{2014} it acts in Block mode only, and this host is watching"
                .to_string()
        } else {
            "Containment on \u{2014} a container that calls a C&C server is cut off and paused"
                .to_string()
        });
        Ok(KeyOutcome::Mutated)
    }

    /// The AS numbers [`Popup::HostingProviders`] lists, in order: the
    /// built-in list, then any other one blocked, by number.
    fn hosting_choices(&self) -> Vec<u32> {
        ipranges::hosting::HOSTING_PROVIDERS
            .iter()
            .map(|p| p.asn)
            .chain(
                self.hosting_asns
                    .iter()
                    .map(|asn| asn.asn)
                    .filter(|asn| ipranges::hosting::curated(*asn).is_none()),
            )
            .collect()
    }

    fn open_hosting_providers_popup(&mut self) {
        self.popup = Some(Popup::HostingProviders {
            cursor: 0,
            chosen: self.hosting_asns.iter().map(|asn| asn.asn).collect(),
        });
    }

    fn handle_hosting_providers_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let last = self.hosting_choices().len().saturating_sub(1);
        let choices = self.hosting_choices();
        let Some(Popup::HostingProviders { cursor, chosen }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => self.popup = None,
            KeyCode::Up | KeyCode::Char('k') => *cursor = cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => *cursor = (*cursor + 1).min(last),
            KeyCode::Char(' ') => {
                if let Some(asn) = choices.get(*cursor) {
                    if !chosen.remove(asn) {
                        chosen.insert(*asn);
                    }
                }
            }
            KeyCode::Enter => {
                let Some(Popup::HostingProviders { chosen, .. }) = self.popup.take() else {
                    unreachable!("checked above")
                };
                return self.commit_hosting_providers(db, &chosen, message);
            }
            _ => {}
        }
        Ok(KeyOutcome::Consumed)
    }

    /// Blocks every provider in `chosen` and stops blocking every other
    /// one. A provider whose ranges were never downloaded is fetched, all
    /// of them in one download (`KeyOutcome::FetchHostingAsns`); with
    /// nothing to fetch the change is already complete.
    fn commit_hosting_providers(
        &mut self,
        db: &Db,
        chosen: &std::collections::BTreeSet<u32>,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        use ipranges::hosting;
        let before: std::collections::BTreeSet<u32> =
            self.hosting_asns.iter().map(|asn| asn.asn).collect();
        if *chosen == before {
            return Ok(KeyOutcome::Consumed);
        }
        let name = |asn: &u32| hosting::display_name(*asn, None);
        let added: Vec<u32> = chosen.difference(&before).copied().collect();
        let removed: Vec<u32> = before.difference(chosen).copied().collect();
        for asn in &removed {
            db.remove_hosting_asn(*asn)?;
        }
        for asn in &added {
            db.add_hosting_asn(*asn)?;
        }

        let mut parts = Vec::new();
        if !added.is_empty() {
            let names: Vec<String> = added.iter().map(name).collect();
            parts.push(format!("Blocking {}", names.join(", ")));
        }
        if !removed.is_empty() {
            let names: Vec<String> = removed.iter().map(name).collect();
            parts.push(format!("no longer blocking {}", names.join(", ")));
        }
        let mut text = parts.join("; ");
        if let Some(first) = text.get(..1) {
            text = first.to_uppercase() + &text[1..];
        }
        // Everything chosen that has no ranges yet: the ones just added,
        // and any added before whose download never happened.
        let fetch: Vec<u32> = chosen
            .iter()
            .copied()
            .filter(|asn| {
                !self
                    .hosting_asns
                    .iter()
                    .any(|stored| stored.asn == *asn && stored.last_fetched_at.is_some())
            })
            .collect();
        let warning = if added.is_empty() {
            String::new()
        } else {
            format!(" \u{2014} {}", hosting::warning())
        };
        if fetch.is_empty() {
            *message = Some(format!("{text} \u{2014} apply (a) to enforce it{warning}"));
            return Ok(KeyOutcome::Mutated);
        }
        *message = Some(format!("{text}, fetching\u{2026}{warning}"));
        Ok(KeyOutcome::FetchHostingAsns(fetch))
    }

    fn render_hosting_providers(
        &self,
        frame: &mut Frame,
        area: Rect,
        cursor: usize,
        chosen: &std::collections::BTreeSet<u32>,
        theme: Theme,
    ) {
        use ipranges::hosting;
        let title = "Hosting providers to block";
        let choices = self.hosting_choices();
        let mut lines: Vec<Line<'static>> = choices
            .iter()
            .enumerate()
            .map(|(i, asn)| {
                let stored = self.hosting_asns.iter().find(|a| a.asn == *asn);
                let name =
                    hosting::display_name(*asn, stored.and_then(|a| a.description.as_deref()));
                let ranges = match stored {
                    Some(a) if a.last_fetched_at.is_some() => format!("{} range(s)", a.range_count),
                    Some(_) => "not fetched".to_string(),
                    None => String::new(),
                };
                let tick = if chosen.contains(asn) { "[x]" } else { "[ ]" };
                let line = Line::from(format!(
                    "{tick} {:<9} {:<18} {ranges}",
                    format!("AS{asn}"),
                    crate::present::terminal_safe(&name)
                ));
                if i == cursor {
                    line.reversed()
                } else {
                    line
                }
            })
            .collect();
        // As wide as the list, not the warning below it, which wraps.
        let width = widest_line(&lines).max(title.chars().count() as u16 + 4);
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Each {}.", hosting::warning())).yellow());
        if let Some(note) = choices
            .get(cursor)
            .and_then(|asn| hosting::curated(*asn))
            .and_then(|p| p.note)
        {
            lines.push(Line::from(note).yellow());
        }
        lines.push(Line::from("Space tick  Enter save  Esc cancel").dim());

        // Tall enough for the caution lines once wrapped to that width.
        let inner = width.saturating_add(2).max(1);
        let height: u16 = lines
            .iter()
            .map(|line| (line.width() as u16).div_ceil(inner).max(1))
            .sum();
        // One spare row: word wrapping can need one more than the division.
        let popup_area = centered_rect(width + 4, height + 3, area);
        let paragraph = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(crate::tui::popup(title, theme));
        frame.render_widget(Clear, popup_area);
        frame.render_widget(paragraph, popup_area);
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
                let last = protection_options(*row).len() - 1;
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

    /// See [`Popup::CloudPort80`]. The choice is stored before the feed is
    /// switched on, so the message that follows says what was chosen.
    fn handle_cloud_port_80_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::CloudPort80 { feed, selected }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                *message = Some("AWS ranges left off".to_string());
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *selected = 0;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *selected = 1;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let (feed, open) = (*feed, *selected == 0);
                self.popup = None;
                db.set_cloud_port_80_open(open)?;
                let Some(source) = self.reputation.get(feed).cloned() else {
                    return Ok(KeyOutcome::Consumed);
                };
                let note = if open {
                    ", port 80 open for Let's Encrypt"
                } else {
                    ", port 80 too: Let's Encrypt renewals over HTTP will fail"
                };
                self.switch_feed(db, &source, true, note, message)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Which of the geo mode popup's options the host is in: Allowlist
    /// with no country is Only trusted IPs.
    fn geo_choice(&self) -> usize {
        match self.geo_mode {
            GeoMode::Blocklist => GEO_BLOCKLIST,
            GeoMode::Allowlist if self.selected_countries.is_empty() => GEO_TRUSTED_ONLY,
            GeoMode::Allowlist => GEO_ALLOWLIST,
        }
    }

    /// Blocklist, Allowlist or Only trusted IPs; see [`Popup::GeoMode`].
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
                *selected = (*selected + 1).min(GEO_TRUSTED_ONLY);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let Some(Popup::GeoMode { selected }) = self.popup.take() else {
                    unreachable!("checked above")
                };
                if self.geo_needs_confirming(selected) {
                    self.popup = Some(Popup::Confirm {
                        what: Confirm::GeoMode(selected),
                        selected: 0,
                    });
                    return Ok(KeyOutcome::Consumed);
                }
                self.commit_geo_mode(db, selected, message)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Whether switching to geo choice `choice` asks first: it changes what
    /// the countries on the list mean, empties it, or starts an Allowlist
    /// that, with no country on it, blocks every address not trusted.
    fn geo_needs_confirming(&self, choice: usize) -> bool {
        choice != self.geo_choice()
            && (!self.selected_countries.is_empty() || choice == GEO_ALLOWLIST)
    }

    /// Stores geo choice `choice`, and says what it now does.
    fn commit_geo_mode(
        &mut self,
        db: &Db,
        choice: usize,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if choice == GEO_BLOCKLIST {
            db.set_geo_mode(GeoMode::Blocklist)?;
            *message = Some("Geo mode set to Blocklist: selected countries are blocked, everything else is allowed".to_string());
            return Ok(KeyOutcome::Mutated);
        }
        db.set_geo_mode(GeoMode::Allowlist)?;
        if choice == GEO_ALLOWLIST {
            *message = Some(if self.selected_countries.is_empty() {
                "Geo mode set to Allowlist, with no country yet: add the countries you allow (Enter on the Geo list) before you apply".to_string()
            } else {
                "Geo mode set to Allowlist: selected countries are the ONLY ones allowed, everything else is blocked host-wide once applied".to_string()
            });
            return Ok(KeyOutcome::Mutated);
        }
        for country in &self.selected_countries {
            db.set_country_selected(country, false)?;
        }
        let removed = if self.selected_countries.is_empty() {
            String::new()
        } else {
            format!(
                " Removed from the Geo list: {}.",
                self.selected_countries.join(" ").to_uppercase()
            )
        };
        // The warning first: the Log panel cuts a long line short.
        *message = Some(match self.trusted_addresses {
            0 => format!("Only trusted IPs, and nothing is trusted yet: trust your addresses on the Firewall screen before you apply, or only SSH logins from the last week and private networks get in.{removed}"),
            n => format!("Geo mode set to Only trusted IPs: once applied, everything is blocked host-wide except {n} trusted address(es), SSH logins from the last week and private networks.{removed}"),
        });
        Ok(KeyOutcome::Mutated)
    }

    /// Stores auto-apply of the firewall script, once confirmed when it
    /// goes on.
    fn commit_auto_apply_firewall(
        &mut self,
        db: &Db,
        on: bool,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        db.set_auto_apply_firewall(on)?;
        self.auto_apply_firewall = on;
        // Names the refusal, because it is what will most often stop this
        // doing anything: a host whose SSH log the cron cannot read
        // renders and never applies.
        *message = Some(if on {
            "Auto-apply on \u{2014} the scheduled render runs the script too, within minutes of a \
             change, unless the anti-lockout check cannot run (it needs a readable SSH log)"
                .to_string()
        } else {
            "Auto-apply off \u{2014} the scheduled render writes the script and leaves running it \
             to you"
                .to_string()
        });
        Ok(KeyOutcome::Mutated)
    }

    /// See [`Popup::Confirm`]: Enter on the first option goes ahead,
    /// anything that cancels changes nothing.
    fn handle_confirm_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::Confirm { what, selected }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => *selected = 0,
            KeyCode::Down | KeyCode::Char('j') => *selected = 1,
            KeyCode::Enter | KeyCode::Char(' ') if *selected == 0 => {
                let what = *what;
                self.popup = None;
                return match what {
                    Confirm::GeoMode(choice) => self.commit_geo_mode(db, choice, message),
                    Confirm::AutoApplyFirewall => {
                        self.commit_auto_apply_firewall(db, true, message)
                    }
                    Confirm::HumansOnly => self.commit_humans_only(db, true, message),
                    Confirm::KeepRunning => Ok(KeyOutcome::KeepRunning(true)),
                    Confirm::AutoContain => self.commit_auto_contain(db, true, message),
                };
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter | KeyCode::Char(' ') => {
                self.popup = None;
                *message = Some("Nothing changed.".to_string());
            }
            _ => {}
        }
        Ok(KeyOutcome::Consumed)
    }

    /// The title, explanation and two answers of a [`Popup::Confirm`].
    fn confirm_text(&self, what: Confirm) -> (String, Vec<Line<'static>>, [String; 2]) {
        let countries = self.selected_countries.join(" ").to_uppercase();
        match what {
            Confirm::GeoMode(choice) => {
                let (title, go) = match choice {
                    GEO_BLOCKLIST => ("Switch to Blocklist?", "Switch to Blocklist"),
                    GEO_ALLOWLIST => ("Switch to Allowlist?", "Switch to Allowlist"),
                    _ => ("Switch to Only trusted IPs?", "Switch to Only trusted IPs"),
                };
                let mut text: Vec<Line<'static>> = Vec::new();
                match choice {
                    GEO_BLOCKLIST => text.push(
                        format!(
                            "Allowed now: {countries}. In Blocklist these become the \
                             blocked countries: visitors from them are turned away, and everyone \
                             else gets in."
                        )
                        .into(),
                    ),
                    GEO_ALLOWLIST if self.selected_countries.is_empty() => text.push(
                        "No country is on the Geo list yet. Until you add one, Allowlist blocks \
                         every address on every port, except trusted addresses, SSH logins from \
                         the last week and private networks."
                            .into(),
                    ),
                    GEO_ALLOWLIST => {
                        text.push(
                            format!(
                                "Blocked now: {countries}. In Allowlist these become the \
                                 ONLY countries allowed: every other country is blocked, on \
                                 every port."
                            )
                            .into(),
                        );
                        text.push("".into());
                        text.push(
                            "Make sure the country you connect from is on the list."
                                .yellow()
                                .into(),
                        );
                    }
                    _ => {
                        text.push(
                            format!(
                                "This takes {countries} off the Geo list: Only trusted IPs \
                                 is Allowlist with no country. Write them down if you want them \
                                 back."
                            )
                            .into(),
                        );
                        text.push("".into());
                        text.push(
                            format!(
                                "Everything is then blocked except {} trusted address(es), SSH \
                                 logins from the last week and private networks.",
                                self.trusted_addresses
                            )
                            .into(),
                        );
                    }
                }
                text.push("".into());
                text.push(if self.auto_apply_firewall {
                    "Auto-apply is on: this reaches the firewall within minutes."
                        .yellow()
                        .into()
                } else {
                    "Nothing changes on the host until you apply (a).".into()
                });
                (
                    title.to_string(),
                    text,
                    [go.to_string(), "Cancel".to_string()],
                )
            }
            Confirm::AutoApplyFirewall => (
                "Apply the firewall script automatically?".to_string(),
                vec![
                    "The scheduled render runs within a minute of any change to the rules, \
                     such as a detector's block or a setting changed here, and at least once a \
                     day. With this on, it also runs the script as root, with no preview."
                        .into(),
                    "".into(),
                    "Every apply still goes through the SSH lock-out check, and is refused when \
                     the SSH log cannot be read. It runs only while this TUI is open, or from \
                     cron (`stop-bots install cron`)."
                        .into(),
                ],
                [
                    "Turn auto-apply on".to_string(),
                    "Keep applying by hand".to_string(),
                ],
            ),
            Confirm::AutoContain => (
                "Contain what calls a C&C server?".to_string(),
                vec![
                    "When a container connects to an address a feed allowed to contain lists \
                     (Feodo Tracker's, by default), it is cut off from the network both ways \
                     and paused, within the minute. Only in Block mode."
                        .into(),
                    "".into(),
                    "More than three in an hour, or one address reached from several at once, \
                     trips a breaker instead. `stop-bots release` lets one go; users on the host \
                     are contained only with `stop-bots set-containment --users true`."
                        .into(),
                ],
                [
                    "Contain automatically".to_string(),
                    "Only report hits".to_string(),
                ],
            ),
            Confirm::HumansOnly => (
                "Serve humans only?".to_string(),
                vec![
                    "Every bot is turned away, search engines among them: your sites drop out \
                     of Google and Bing, and link previews and uptime monitors stop working."
                        .into(),
                    "".into(),
                    "Let's Encrypt is still let in, so certificates keep renewing. Turning this \
                     off brings back the settings below as they were."
                        .into(),
                ],
                ["Turn humans only on".to_string(), "Keep it off".to_string()],
            ),
            Confirm::KeepRunning => (
                "Keep running by itself?".to_string(),
                vec![
                    format!(
                        "This writes /etc/cron.d/{}, which runs stop-bots every minute, \
                         whether this screen is open or not.",
                        crate::install::CRON_FILE
                    )
                    .into(),
                    "".into(),
                    "What it finds, and what you change here, is then applied on its own: \
                     the web server's config, and the firewall. Every firewall apply is \
                     checked first, and refused if it would block anyone who logs in over SSH."
                        .into(),
                ],
                [
                    "Keep it running".to_string(),
                    "Only while this screen is open".to_string(),
                ],
            ),
        }
    }

    /// "Apply everything"'s confirmation. Enter is the only key that
    /// applies; everything else reads, scrolls or leaves.
    fn handle_confirm_apply_popup_key(
        &mut self,
        key: KeyEvent,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::ConfirmApply {
            diff,
            show_diff,
            scroll,
            ..
        }) = &mut self.popup
        else {
            unreachable!("dispatched on this variant")
        };
        let last = diff.len().saturating_sub(1);
        match key.code {
            KeyCode::Enter => {
                self.popup = None;
                return Ok(KeyOutcome::ApplyEverything);
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.popup = None;
                *message = Some("Nothing applied.".to_string());
            }
            KeyCode::Char('d') => {
                *show_diff = !*show_diff;
                *scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => *scroll = (*scroll + 1).min(last),
            KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => *scroll = (*scroll + 20).min(last),
            KeyCode::PageUp => *scroll = scroll.saturating_sub(20),
            _ => {}
        }
        Ok(KeyOutcome::Consumed)
    }

    /// Opens "Apply everything"'s confirmation with `preview` in it — `App`
    /// works the preview out off the event loop and hands it back here.
    /// When the lock-out check found no one to check, it asks about that
    /// first: see [`Popup::NoLogins`].
    pub fn show_apply_preview(&mut self, preview: &crate::preview::ApplyPreview) {
        if preview
            .firewall
            .as_ref()
            .is_ok_and(|outcome| matches!(outcome.guard, crate::firewall::Guard::NoLogins { .. }))
        {
            self.popup = Some(Popup::NoLogins {
                preview: Some(std::sync::Arc::new(preview.clone())),
                selected: 0,
            });
            return;
        }
        self.show_confirm_apply(preview);
    }

    fn show_confirm_apply(&mut self, preview: &crate::preview::ApplyPreview) {
        self.popup = Some(Popup::ConfirmApply {
            server: preview.server,
            lines: preview.lines().into(),
            diff: preview.diff().lines().map(str::to_string).collect(),
            show_diff: false,
            scroll: 0,
        });
    }

    /// See [`Popup::NoLogins`]. Keeping the check goes on to the preview
    /// it came from; turning it off previews again, so the verdict shown is
    /// the one the apply will get.
    fn handle_no_logins_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup::NoLogins { preview, selected }) = &mut self.popup else {
            unreachable!("dispatched on this variant")
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                let applying = preview.is_some();
                self.popup = None;
                *message = Some(
                    if applying {
                        "Nothing applied."
                    } else {
                        "SSH lock-out check left on."
                    }
                    .to_string(),
                );
            }
            KeyCode::Up | KeyCode::Char('k') => *selected = 0,
            KeyCode::Down | KeyCode::Char('j') => *selected = 1,
            KeyCode::Enter | KeyCode::Char(' ') if *selected == 0 => {
                let preview = preview.take();
                self.popup = None;
                match preview {
                    Some(preview) => self.show_confirm_apply(&preview),
                    None => *message = Some("SSH lock-out check left on.".to_string()),
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let applying = preview.is_some();
                self.popup = None;
                db.set_ssh_lockout_check(false)?;
                self.ssh_lockout_check = false;
                *message = Some(
                    "SSH lock-out check off \u{2014} addresses that log in over SSH are still let \
                     through, and `stop-bots status` warns if anyone does"
                        .to_string(),
                );
                return Ok(if applying {
                    KeyOutcome::PreviewApplyEverything
                } else {
                    KeyOutcome::Mutated
                });
            }
            _ => {}
        }
        Ok(KeyOutcome::Consumed)
    }

    #[cfg(test)]
    pub(crate) fn confirm_apply_is_open(&self) -> bool {
        matches!(self.popup, Some(Popup::ConfirmApply { .. }))
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
                let backend = popup_backend(backend_selected);
                // Validate the path is not empty
                let refusal = if out_path.is_empty() {
                    Some("Enter an output path".to_string())
                } else if apply_after_write {
                    // Refused here, with the popup still open, rather than
                    // by the apply after the script has been written.
                    self.installed
                        .and_then(|installed| installed.check(backend).err())
                        .map(|err| format!("{err}. Untick \u{201c}apply after writing\u{201d} to only write it."))
                } else {
                    None
                };
                if let Some(error) = refusal {
                    self.popup = Some(Popup::RenderFirewall {
                        backend_selected,
                        out_path,
                        apply_after_write,
                        error: Some(error),
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

    /// Enter on a Policy row: row 0 toggles humans-only, the last two
    /// toggle old browsers and HTTP libraries, and the rest open a
    /// category popup — unless humans-only is on, in which case there is
    /// nothing to open.
    fn activate_policy_row(&mut self, db: &Db, message: &mut Option<String>) -> Result<KeyOutcome> {
        if self.list_state.selected() == Some(POLICY_ROWS - 1) {
            let on = !self.http_libraries;
            db.set_block_http_libraries(on)?;
            let server = crate::webserver::WebServer::configured().label();
            *message = Some(match (on, self.humans_only) {
                (true, _) => format!(
                    "HTTP libraries are blocked on every site. Apply on the {server} screen \
                     to enforce it."
                ),
                (false, true) => "HTTP libraries stay blocked while humans only is on.".to_string(),
                (false, false) => "HTTP libraries are allowed again.".to_string(),
            });
            return Ok(KeyOutcome::Mutated);
        }
        if self.list_state.selected() == Some(POLICY_ROWS - 2) {
            let on = !self.old_browsers;
            db.set_block_old_browsers(on)?;
            *message = Some(if on {
                format!(
                    "Old browsers are blocked on every site. Apply on the {} screen to \
                     enforce it.",
                    crate::webserver::WebServer::configured().label()
                )
            } else {
                "Old browsers are allowed again.".to_string()
            });
            return Ok(KeyOutcome::Mutated);
        }
        if self.list_state.selected() == Some(0) {
            return self.commit_humans_only(db, !self.humans_only, message);
        }
        self.open_category_popup(message);
        Ok(KeyOutcome::Consumed)
    }

    /// Stores humans only, and says what it now does.
    fn commit_humans_only(
        &mut self,
        db: &Db,
        on: bool,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        db.set_humans_only(on)?;
        let apply = if self.simple {
            "Press a to apply it.".to_string()
        } else {
            format!(
                "Apply on the {} screen to enforce it.",
                crate::webserver::WebServer::configured().label()
            )
        };
        *message = Some(if on {
            format!(
                "Humans only is on: every catalogued bot is blocked except Let's Encrypt, and \
                 fetching /robots.txt now earns a one-day block. {apply}"
            )
        } else {
            "Humans only is off. The category policies you had before are back in force."
                .to_string()
        });
        Ok(KeyOutcome::Mutated)
    }

    fn open_category_popup(&mut self, message: &mut Option<String>) {
        // Refused rather than offered-and-ignored. Humans-only forces all
        // three, so a popup here would write a setting that
        // `get_category_default` never returns — the screen would say
        // Allowed and the config would block.
        if self.humans_only {
            *message = Some(
                "Humans only is on, so every category is blocked. Turn it off to set categories individually."
                    .to_string(),
            );
            return;
        }
        let Some(selected) = self.list_state.selected() else {
            return;
        };
        // Row 0 is the switch, so the categories start one later.
        let Some(&category) = CATEGORIES.get(selected.wrapping_sub(1)) else {
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
    /// Enter on the Geo list: the add row opens the code popup, and a
    /// country row says which key removes it.
    fn activate_country_row(&mut self, message: &mut Option<String>) -> KeyOutcome {
        match self.countries_state.selected() {
            Some(0) => {
                self.popup = Some(Popup::AddCountry {
                    input: String::new(),
                    error: None,
                });
            }
            Some(selected) => {
                if let Some(country_code) = self.selected_countries.get(selected - 1) {
                    *message = Some(format!(
                        "Press Delete or Backspace to remove {}",
                        country_code.to_uppercase()
                    ));
                }
            }
            None => {}
        }
        KeyOutcome::Consumed
    }

    /// Delete or Backspace on a country row: deselects it at once.
    fn remove_country_row(&mut self, message: &mut Option<String>, db: &Db) -> Result<KeyOutcome> {
        let Some(country_code) = self
            .countries_state
            .selected()
            .and_then(|selected| selected.checked_sub(1))
            .and_then(|index| self.selected_countries.get(index))
        else {
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
/// Shared with NGINX rather than copied: there were two of these,
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
/// index means what — the same reason NGINX has its own
/// `setting_options`.
fn protection_options(row: ProtectionRow) -> Vec<String> {
    if row == ProtectionRow::Outbound {
        return crate::egress::Mode::ALL
            .into_iter()
            .map(|mode| match mode {
                crate::egress::Mode::Off => "Off".to_string(),
                crate::egress::Mode::Watch => "Watch \u{2014} log, and let through".to_string(),
                crate::egress::Mode::Block => "Block \u{2014} log, and drop".to_string(),
            })
            .collect();
    }
    if !row.is_detector() {
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

/// The backend the render popup's row `selected` stands for.
fn popup_backend(selected: usize) -> crate::firewall::FirewallBackend {
    match selected {
        0 => crate::firewall::FirewallBackend::Nftables,
        _ => crate::firewall::FirewallBackend::Iptables,
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
/// [`Popup::NoLogins`]: why it asks, then the two answers. `applying` when
/// it stands in front of an apply's preview, rather than the Dashboard
/// row; `catch_all` is the rule that would block whoever connects next.
fn render_no_logins(
    frame: &mut Frame,
    area: Rect,
    applying: bool,
    catch_all: Option<String>,
    selected: usize,
    theme: Theme,
) {
    let days = crate::db::SSH_LOGIN_WINDOW_SECONDS / 86_400;
    let mut text: Vec<Line> = Vec::new();
    if applying {
        text.push(
            format!(
                "No one has logged in over SSH in the last {days} days, so the lock-out check \
                 has no address of yours to keep open."
            )
            .into(),
        );
        if let Some(rule) = catch_all {
            text.push("".into());
            text.push(
                format!(
                    "These rules end in {rule}, which blocks every address not allowed ahead of \
                     it: whoever connects next over SSH is blocked, so the firewall half of this \
                     apply is refused while the check is on. Trust your address on the Firewall \
                     screen first."
                )
                .yellow()
                .into(),
            );
        }
    } else {
        text.push(
            "The lock-out check stops any apply that would block an address that logged in over \
             SSH in the last week."
                .into(),
        );
    }
    text.push("".into());
    text.push(
        "If you never log in over SSH, because you use your provider's console, you can turn it \
         off. Addresses that do log in are still let through."
            .into(),
    );
    text.push("".into());
    text.push("Do you log into this server over SSH?".bold().into());
    render_question(
        frame,
        area,
        "No successful SSH logins",
        text,
        &[
            "Yes, keep the check on".to_string(),
            "No, I never log in over SSH: turn the check off".to_string(),
        ],
        selected,
        theme,
    );
}

/// A popup that explains before it asks: `text`, wrapped, then `options`,
/// the selected one reversed, then the keys. Sized to its text, up to 76
/// columns.
fn render_question(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    mut text: Vec<Line<'static>>,
    options: &[String],
    selected: usize,
    theme: Theme,
) {
    text.push("".into());
    for (i, option) in options.iter().enumerate() {
        let line = Line::from(format!("  {option}"));
        text.push(if i == selected { line.reversed() } else { line });
    }
    text.push("".into());
    text.push(Line::from("\u{2191}/\u{2193} choose  Enter confirm  Esc cancel").fg(theme.dim()));

    let width = area.width.saturating_sub(4).min(76);
    let inner = width.saturating_sub(2).max(1) as usize;
    let height: usize = text
        .iter()
        .map(|line| line.width().div_ceil(inner).max(1))
        .sum();
    let popup_area = centered_rect(width, height as u16 + 2, area);
    let paragraph = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(crate::tui::popup(title, theme));
    frame.render_widget(Clear, popup_area);
    frame.render_widget(paragraph, popup_area);
}

/// "Apply everything"'s confirmation: the summary on top, wrapped, and the
/// diff below it when asked for, drawn a screenful at a time from `scroll`
/// — a first apply's firewall diff is tens of thousands of lines, and only
/// the visible ones become `Line`s.
fn render_confirm_apply(
    frame: &mut Frame,
    area: Rect,
    server: crate::webserver::WebServer,
    lines: &[String],
    diff: Option<&[String]>,
    scroll: usize,
    theme: Theme,
) {
    let popup_area = crate::tui::centered_rect(
        area.width.saturating_sub(4).min(120),
        area.height.saturating_sub(2),
        area,
    );
    frame.render_widget(Clear, popup_area);
    let block = crate::tui::popup("Apply everything?", theme);
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let width = inner.width.max(1) as usize;
    let summary_height: usize = lines
        .iter()
        .map(|line| line.chars().count().div_ceil(width).max(1))
        .sum();
    let [summary, rest, hint] = Layout::vertical([
        Constraint::Length(summary_height as u16 + 1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(inner);

    let summary_lines: Vec<Line> = lines.iter().map(|line| Line::from(line.as_str())).collect();
    frame.render_widget(
        Paragraph::new(summary_lines).wrap(Wrap { trim: false }),
        summary,
    );

    let (body, keys): (Vec<Line>, &str) = match diff {
        None => (
            vec![format!(
                "This writes the {server} config for every site and reloads {server}, then \
                 writes the firewall script and runs it as root.",
                server = server.label()
            )
            .into()],
            "Enter apply  d show the diff  Esc cancel",
        ),
        Some([]) => (
            vec!["Nothing would change.".fg(theme.dim()).into()],
            "Enter apply  d hide the diff  Esc cancel",
        ),
        Some(diff) => (
            diff.iter()
                .skip(scroll)
                .take(rest.height as usize)
                .map(|line| {
                    let span = Span::from(line.as_str());
                    match line.as_bytes().first() {
                        Some(b'+') if !line.starts_with("+++") => span.green(),
                        Some(b'-') if !line.starts_with("---") => span.red(),
                        Some(b'@') => span.cyan(),
                        _ => span,
                    }
                    .into()
                })
                .collect(),
            "Enter apply  d hide the diff  \u{2191}/\u{2193} PgUp/PgDn scroll  Esc cancel",
        ),
    };
    let body = Paragraph::new(body);
    frame.render_widget(
        if diff.is_none() {
            body.wrap(Wrap { trim: false })
        } else {
            body
        },
        rest,
    );
    frame.render_widget(Paragraph::new(Line::from(keys).fg(theme.dim())), hint);
}

fn widest_line(lines: &[Line<'_>]) -> u16 {
    lines
        .iter()
        .map(|line| line.width() as u16)
        .max()
        .unwrap_or(0)
}

/// The Log panel: two border lines and two messages. The newest is the
/// one that matters; the one before it is context.
const LOG_HEIGHT: u16 = 4;

fn cron_status_line(status: &crate::cron::JobStatus, running: bool, theme: Theme) -> Line<'static> {
    let last_run = match status.last_run {
        Some(t) => crate::present::ago(t),
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

        // A line taller than `test_terminal`: at 32 the Policy panel's
        // seven rows leave the schedule room for three jobs, and this
        // checks the fourth's "due now".
        let mut terminal = Terminal::new(TestBackend::new(100, 33)).unwrap();
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

    /// A call to a C&C server is the one thing on this screen that means
    /// the host is already compromised, so it is said in the panel beside
    /// the firewall it got past, not only in the status strip.
    #[test]
    fn a_c_and_c_hit_is_shown_beside_the_firewall_script() {
        let db = Db::open_in_memory().unwrap();
        crate::egress::Mode::Block.set(&db).unwrap();
        let now = crate::testing::now_secs();
        db.upsert_egress_hits(&[crate::db::egress::NewEgressHit {
            path: crate::egress::Path::Forward,
            source: "172.18.0.5".to_string(),
            destination: "198.51.100.7".to_string(),
            port: Some(443),
            protocol: "TCP".to_string(),
            uid: None,
            count: 1,
            first_seen: now,
            last_seen: now,
            evidence: "a line".to_string(),
        }])
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
            content.contains("outbound block"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("[ 1 C&C HIT(S) ]"),
            "content was:\n{content}"
        );
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
        select_first_category(&mut dashboard);
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

    /// Selects the first *category* row. Row 0 is the humans-only switch
    /// now, so a test about categories has to say which row it means
    /// rather than relying on where the cursor happens to start.
    fn select_first_category(dashboard: &mut Dashboard) {
        dashboard.list_state.select(Some(1));
    }

    #[test]
    fn confirming_popup_writes_through_and_closes() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        select_first_category(&mut dashboard);

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
        select_first_category(&mut dashboard);

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
        for _ in 0..POLICY_ROWS - 1 {
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
    fn enter_on_the_old_browsers_row_toggles_old_browsers() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.list_state.select(Some(POLICY_ROWS - 2));

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.get_block_old_browsers().unwrap(), "message: {message:?}");

        // Humans only locks the categories, not this.
        db.set_humans_only(true).unwrap();
        dashboard.refresh(&db).unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(
            !db.get_block_old_browsers().unwrap(),
            "humans only kept the switch from turning off. message: {message:?}"
        );
    }

    /// The last row is the HTTP-library switch: Enter turns it on, and
    /// with humans only on it reads as blocked even once turned off.
    #[test]
    fn enter_on_the_last_policy_row_toggles_http_libraries() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.list_state.select(Some(POLICY_ROWS - 1));

        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(
            db.get_block_http_libraries().unwrap(),
            "message: {message:?}"
        );

        db.set_humans_only(true).unwrap();
        dashboard.refresh(&db).unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(
            !db.get_block_http_libraries().unwrap(),
            "message: {message:?}"
        );
        assert!(
            dashboard
                .http_libraries_line()
                .to_string()
                .contains("BLOCKED"),
            "humans only is on, and the row says otherwise: {message:?}"
        );
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
        assert_eq!(dashboard.list_state.selected(), Some(POLICY_ROWS - 1));
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

    /// A dashboard on the Geo list with NL selected, on NL's row.
    fn on_a_country_row(db: &Db) -> Dashboard {
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(db).unwrap();
        dashboard.focus = Focus::Countries;
        dashboard.countries_state.select(Some(1)); // row 0 is "Add", row 1 is "nl"
        dashboard
    }

    #[test]
    fn delete_or_backspace_on_a_country_row_removes_it_directly() {
        for key in [KeyCode::Delete, KeyCode::Backspace] {
            let db = Db::open_in_memory().unwrap();
            let mut dashboard = on_a_country_row(&db);

            let mut message = None;
            let outcome = dashboard
                .handle_key(KeyEvent::from(key), &db, &mut message)
                .unwrap();

            assert_eq!(outcome, KeyOutcome::Mutated, "{key:?}");
            assert!(db.list_selected_countries().unwrap().is_empty(), "{key:?}");
            assert_eq!(message.as_deref(), Some("Removed NL"), "{key:?}");
        }
    }

    /// Enter adds on the row above; on a country it removes nothing, and
    /// says which key does.
    #[test]
    fn enter_on_a_country_row_names_the_key_that_removes_it() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_a_country_row(&db);

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(db.list_selected_countries().unwrap(), vec!["nl"]);
        let message = message.unwrap_or_default();
        assert!(message.contains("Delete"), "message was: {message}");
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
            .handle_key(KeyEvent::from(KeyCode::Delete), &db, &mut message)
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
        assert!(
            content.contains("Enter to add a country, m to change mode"),
            "content was:\n{content}"
        );
        assert!(content.contains("NL"), "content was:\n{content}");
        assert!(content.contains("1 range(s)"), "content was:\n{content}");
    }

    /// Every crawler gets a row — fetched or not, since the row is where
    /// the first fetch is offered — with its range count and age, and the
    /// policy its category gives those addresses.
    #[test]
    fn render_shows_every_crawler_range_with_its_count_and_age() {
        let db = Db::open_in_memory().unwrap();
        ipranges::store(
            &db,
            ipranges::IpRangeSourceKind::GptBot,
            &["20.171.206.0/24".to_string(), "52.230.152.0/24".to_string()],
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
        let buffer = terminal.backend().buffer();
        let rows: Vec<String> = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect()
            })
            .collect();
        let row = |name: &str| {
            rows.iter()
                .find(|row| row.contains(name))
                .cloned()
                .unwrap_or_else(|| panic!("no {name} row in:\n{}", rows.join("\n")))
        };

        assert!(
            rows.iter().any(|r| r.contains("Crawler IP ranges")),
            "{}",
            rows.join("\n")
        );
        for (name, expected) in [
            ("Googlebot", "[ ALLOWED ] not fetched"),
            ("Bingbot", "[ ALLOWED ] not fetched"),
            ("GPTBot", "[ BLOCKED ] 2 \u{00b7} just now"),
        ] {
            let row = row(name);
            assert!(row.contains(expected), "{name}: {row}");
        }
    }

    /// Enter on a crawler row hands its download to `App`, and Down walks
    /// from the last country through the three crawlers.
    #[test]
    fn enter_on_a_crawler_row_asks_for_that_download() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Countries;
        let mut message = None;
        let mut press = |code| {
            dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap()
        };

        press(KeyCode::Down);
        press(KeyCode::Down);
        let outcome = press(KeyCode::Enter);

        assert_eq!(
            outcome,
            KeyOutcome::RefreshCrawlerRanges(ipranges::IpRangeSourceKind::BingBot)
        );
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
        // Move to "Allowlist", choose it, and confirm: with no country
        // on the list, it blocks everything not trusted, so it asks.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(
            matches!(dashboard.popup, Some(Popup::Confirm { .. })),
            "{:?}",
            dashboard.popup
        );
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

    /// Only trusted IPs is Allowlist with no country: choosing it
    /// deselects every country, and the panel and the popup both name it.
    #[test]
    fn only_trusted_ips_is_an_allowlist_with_no_country() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        db.trust_address("198.51.100.7").unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode {
            selected: GEO_TRUSTED_ONLY,
        });

        let mut message = None;
        // Choose it, then confirm taking NL off the list.
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        dashboard.refresh(&db).unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Allowlist);
        assert!(
            db.list_selected_countries().unwrap().is_empty(),
            "NL is still selected"
        );
        let message = message.unwrap_or_default();
        assert!(
            message.contains("Only trusted IPs") && message.contains("1 trusted address"),
            "message was: {message}"
        );
        assert_eq!(dashboard.geo_choice(), GEO_TRUSTED_ONLY);
    }

    /// Blocklist to Allowlist keeps the list and turns it inside out: the
    /// countries that were blocked become the only ones allowed. It says
    /// so, naming them, before anything changes.
    #[test]
    fn switching_blocklist_to_allowlist_asks_first_and_names_the_countries() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("cn", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("cn", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode {
            selected: GEO_ALLOWLIST,
        });
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let Some(Popup::Confirm { what, .. }) = dashboard.popup.clone() else {
            panic!("expected a confirmation, got {:?}", dashboard.popup);
        };
        let (_, text, _) = dashboard.confirm_text(what);
        let text: String = text.iter().map(|line| line.to_string()).collect();
        assert!(
            text.contains("CN") && text.contains("ONLY countries allowed"),
            "{text}"
        );
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Blocklist, "not yet");

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(
            db.get_geo_mode().unwrap(),
            GeoMode::Blocklist,
            "Esc changed it"
        );
        assert!(dashboard.popup.is_none(), "{:?}", dashboard.popup);
    }

    /// The same mode, or a switch that changes nothing about the list,
    /// does not ask.
    #[test]
    fn a_geo_switch_with_no_countries_to_lose_does_not_ask() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        for (choice, asks) in [
            (GEO_BLOCKLIST, false),
            (GEO_TRUSTED_ONLY, false),
            (GEO_ALLOWLIST, true),
        ] {
            assert_eq!(
                dashboard.geo_needs_confirming(choice),
                asks,
                "choice {choice} from Blocklist with no country"
            );
        }
    }

    /// Auto-apply takes the preview out of every later apply, so switching
    /// it on asks; switching it off does not.
    #[test]
    fn auto_apply_asks_before_switching_on_and_not_off() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        dashboard
            .commit_protection(&db, ProtectionRow::AutoApplyFirewall, 1, &mut message)
            .unwrap();
        assert!(
            !db.get_auto_apply_firewall().unwrap(),
            "on before the answer"
        );
        assert!(
            matches!(
                dashboard.popup,
                Some(Popup::Confirm {
                    what: Confirm::AutoApplyFirewall,
                    ..
                })
            ),
            "{:?}",
            dashboard.popup
        );
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(db.get_auto_apply_firewall().unwrap(), "{message:?}");
        assert!(
            message
                .as_deref()
                .is_some_and(|m| m.contains("within minutes")),
            "{message:?}"
        );

        dashboard
            .commit_protection(&db, ProtectionRow::AutoApplyFirewall, 0, &mut message)
            .unwrap();
        assert!(!db.get_auto_apply_firewall().unwrap());
        assert!(dashboard.popup.is_none(), "{:?}", dashboard.popup);
    }

    /// With nothing trusted, the message says so before the firewall is
    /// rendered, rather than leaving the lockout guard to find out.
    #[test]
    fn only_trusted_ips_with_nothing_trusted_says_so() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.popup = Some(Popup::GeoMode {
            selected: GEO_TRUSTED_ONLY,
        });

        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let message = message.unwrap_or_default();
        assert!(
            message.contains("nothing is trusted yet"),
            "message was: {message}"
        );
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

    /// The two host-wide actions that start at once. They hand
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
        // `a` asks for the preview; the apply is only ever the answer to it.
        assert_eq!(
            dashboard
                .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
                .unwrap(),
            KeyOutcome::PreviewApplyEverything
        );
    }

    /// Every row of every Dashboard list has its own explanation: titled
    /// after the row, with text, and a warning where the row can block
    /// people.
    #[test]
    fn every_dashboard_row_explains_itself() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let mut seen = std::collections::HashSet::new();
        dashboard.focus = Focus::Categories;
        for i in 0..POLICY_ROWS {
            dashboard.list_state.select(Some(i));
            seen.insert(dashboard.explain().title);
        }
        dashboard.focus = Focus::Countries;
        for i in 0..=dashboard.selected_countries.len() {
            dashboard.countries_state.select(Some(i));
            seen.insert(dashboard.explain().title);
        }
        dashboard.focus = Focus::Crawlers;
        for i in 0..dashboard.crawlers.len() {
            dashboard.crawlers_state.select(Some(i));
            seen.insert(dashboard.explain().title);
        }
        dashboard.focus = Focus::Protection;
        for (i, row) in dashboard.protection_rows().into_iter().enumerate() {
            dashboard.protection_state.select(Some(i));
            let explanation = dashboard.explain();
            assert_eq!(explanation.title, dashboard.protection_label(row));
            assert!(explanation.body.len() > 2, "{explanation:?}");
            let warns = explanation
                .body
                .iter()
                .any(|line| line.to_string().starts_with('\u{26a0}'));
            if let ProtectionRow::Detect(detector) = row {
                assert_eq!(warns, detector.risk().is_some(), "{row:?}");
            }
            seen.insert(explanation.title);
        }

        let rows = POLICY_ROWS
            + 1
            + dashboard.selected_countries.len()
            + dashboard.crawlers.len()
            + dashboard.protection_rows().len();
        assert_eq!(seen.len(), rows, "two rows share an explanation: {seen:?}");
    }

    /// A preview whose lock-out check read an SSH log with no login in it.
    fn preview_with_no_logins(db: &Db, dir: &std::path::Path) -> crate::preview::ApplyPreview {
        let run = crate::firewall::FirewallRun::new(
            crate::firewall::FirewallBackend::Nftables,
            dir.join("firewall.nft"),
        )
        .apply(true)
        .dry_run(true);
        crate::preview::ApplyPreview {
            server: crate::webserver::WebServer::Nginx,
            nginx: Ok(Vec::new()),
            firewall: crate::firewall::render_and_apply(
                db,
                run,
                crate::firewall::SshLog::Text(Some("")),
            )
            .map_err(|err| format!("{err:#}")),
        }
    }

    /// With no SSH login to check against, the apply asks whether anyone
    /// logs in over SSH before it shows what it would change; keeping the
    /// check goes on to that preview.
    #[test]
    fn an_apply_with_no_ssh_logins_asks_first_and_keeping_the_check_shows_the_preview() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        let mut message = None;

        dashboard.show_apply_preview(&preview_with_no_logins(&db, dir.path()));
        assert!(
            matches!(dashboard.popup, Some(Popup::NoLogins { .. })),
            "{:?}",
            dashboard.popup
        );

        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.confirm_apply_is_open(), "{:?}", dashboard.popup);
        assert!(db.get_ssh_lockout_check().unwrap(), "keeping it left it on");
    }

    /// Turning it off previews again, so the confirmation shows the
    /// verdict the apply will get.
    #[test]
    fn answering_no_ssh_turns_the_check_off_and_previews_again() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        let mut message = None;
        dashboard.show_apply_preview(&preview_with_no_logins(&db, dir.path()));

        for code in [KeyCode::Down, KeyCode::Enter] {
            let outcome = dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap();
            if code == KeyCode::Enter {
                assert_eq!(outcome, KeyOutcome::PreviewApplyEverything);
            }
        }

        assert!(!db.get_ssh_lockout_check().unwrap());
        assert!(dashboard.popup.is_none(), "{:?}", dashboard.popup);
    }

    /// The question, both answers and the way out all fit the smallest
    /// terminal the pty tests drive, with the catch-all warning in.
    #[test]
    fn the_no_logins_question_fits_with_its_answers() {
        let mut terminal = Terminal::new(TestBackend::new(100, 28)).unwrap();
        terminal
            .draw(|frame| {
                render_no_logins(
                    frame,
                    frame.area(),
                    true,
                    Some("0.0.0.0/0".to_string()),
                    0,
                    Theme::Dark,
                )
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let content: String = (0..buffer.area.height)
            .map(|y| {
                let row: String = (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect();
                row + "\n"
            })
            .collect();
        for needle in [
            "No successful SSH logins",
            "0.0.0.0/0",
            "Do you log into this server over SSH?",
            "Yes, keep the check on",
            "No, I never log in over SSH",
            "Esc cancel",
        ] {
            assert!(content.contains(needle), "{needle:?} missing:\n{content}");
        }
    }

    /// The Dashboard row turns the check on at once, and off only once
    /// asked.
    #[test]
    fn the_lockout_check_row_asks_before_switching_off() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let mut message = None;

        let outcome = dashboard
            .commit_protection(&db, ProtectionRow::LockoutCheck, 0, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(
            db.get_ssh_lockout_check().unwrap(),
            "not off before the answer"
        );
        for code in [KeyCode::Down, KeyCode::Enter] {
            dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap();
        }
        assert!(!db.get_ssh_lockout_check().unwrap(), "{message:?}");

        dashboard
            .commit_protection(&db, ProtectionRow::LockoutCheck, 1, &mut message)
            .unwrap();
        assert!(db.get_ssh_lockout_check().unwrap(), "{message:?}");
    }

    /// In the confirmation, Enter is the only key that applies; the others
    /// read, scroll or leave.
    #[test]
    fn only_enter_in_the_confirmation_applies() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        let preview = crate::preview::ApplyPreview {
            server: crate::webserver::WebServer::Nginx,
            nginx: Ok(Vec::new()),
            firewall: Err("not needed here".to_string()),
        };
        let mut message = None;
        let mut press = |dashboard: &mut Dashboard, code| {
            dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap()
        };

        dashboard.show_apply_preview(&preview);
        for code in [
            KeyCode::Char('a'),
            KeyCode::Char('d'),
            KeyCode::Down,
            KeyCode::PageDown,
            KeyCode::Char('d'),
        ] {
            assert_eq!(
                press(&mut dashboard, code),
                KeyOutcome::Consumed,
                "{code:?}"
            );
            assert!(dashboard.confirm_apply_is_open(), "{code:?} closed it");
        }
        assert_eq!(
            press(&mut dashboard, KeyCode::Enter),
            KeyOutcome::ApplyEverything
        );
        assert!(!dashboard.confirm_apply_is_open());

        dashboard.show_apply_preview(&preview);
        assert_eq!(press(&mut dashboard, KeyCode::Esc), KeyOutcome::Consumed);
        assert!(!dashboard.confirm_apply_is_open());
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

    /// On a host set to iptables the popup opens on iptables and its own
    /// script, not on nftables' file.
    #[test]
    fn f_key_opens_on_the_stored_backend_and_its_path() {
        let db = Db::open_in_memory().unwrap();
        crate::firewall::store_backend(&db, crate::firewall::FirewallBackend::Iptables).unwrap();
        let mut dashboard = Dashboard::default();
        let mut message = None;

        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('F')), &db, &mut message)
            .unwrap();

        match dashboard.popup.unwrap() {
            Popup::RenderFirewall {
                backend_selected,
                out_path,
                ..
            } => {
                assert_eq!(backend_selected, 1, "iptables");
                assert_eq!(out_path, "/etc/stop-bots/firewall.sh");
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

    /// On a host without `nft`, "apply after writing" with nftables is
    /// refused while the popup is still open, and says what is missing —
    /// rather than writing the script and then failing to spawn `nft`.
    #[test]
    fn applying_with_a_backend_that_is_not_installed_is_refused_in_the_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.installed = Some(crate::firewall::Installed {
            nftables: false,
            iptables: true,
        });
        let popup = |apply_after_write| Popup::RenderFirewall {
            backend_selected: 0,
            out_path: "/tmp/fw.nft".to_string(),
            apply_after_write,
            error: None,
        };

        dashboard.popup = Some(popup(true));
        let mut message = None;
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        match &dashboard.popup {
            Some(Popup::RenderFirewall {
                error: Some(error), ..
            }) => assert!(error.contains("nft is not installed"), "error: {error}"),
            other => panic!("the popup should stay open with an error, got {other:?}"),
        }

        // Only writing it is still fine: the script may be for another host.
        dashboard.popup = Some(popup(false));
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(
            matches!(outcome, KeyOutcome::RenderFirewall { apply: false, .. }),
            "got {outcome:?}"
        );
    }

    #[test]
    fn the_render_popup_marks_a_backend_that_is_not_installed() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.installed = Some(crate::firewall::Installed {
            nftables: false,
            iptables: true,
        });
        dashboard
            .handle_key(KeyEvent::from(KeyCode::Char('F')), &db, &mut None)
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
        let content: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();

        assert!(content.contains("not installed"), "content was:\n{content}");
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

    /// With no rules at all — a fresh install — the panel must not say
    /// "F to write". Pressing `F` there renders an empty script, which
    /// looks like the tool doing nothing, and it is the first screen a
    /// new user sees.
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

    /// The panel's tag in each of its three states. The middle one is what
    /// the internal cron leaves behind on its own — a script on disk that
    /// nothing loads — and it must not read as up to date.
    #[test]
    fn the_firewall_summary_row_says_applied_only_when_it_was() {
        let db = Db::open_in_memory().unwrap();
        // A rule to write. Without one the panel says something else
        // entirely, and deliberately — see the test above.
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "203.0.113.9".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        let signature = crate::firewall::rules_signature(&crate::firewall::all_rules(&db).unwrap());
        let row = |db: &Db| {
            let mut dashboard = Dashboard::default();
            dashboard.refresh(db).unwrap();
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
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>()
        };

        let content = row(&db);
        assert!(content.contains("1 rules"), "content was:\n{content}");
        assert!(content.contains("CHANGED"), "content was:\n{content}");
        assert!(content.contains("a to apply"), "content was:\n{content}");

        db.set_firewall_rendered_signature(&signature).unwrap();
        let content = row(&db);
        assert!(content.contains("NOT APPLIED"), "content was:\n{content}");

        db.set_firewall_applied_signature(&signature).unwrap();
        let content = row(&db);
        assert!(content.contains("[ APPLIED ]"), "content was:\n{content}");
        assert!(!content.contains("a to apply"), "content was:\n{content}");
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
    fn focus_flows_from_the_crawler_ranges_into_the_protection_panel_and_back() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        focus_protection(&mut dashboard, &db);
        assert_eq!(dashboard.protection_state.selected(), Some(0));

        press(&mut dashboard, &db, KeyCode::Up);
        assert_eq!(dashboard.focus, Focus::Crawlers);
        assert_eq!(dashboard.crawlers_state.selected(), Some(2));
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

    fn select_repeat_offenders(dashboard: &mut Dashboard) {
        let index = dashboard
            .protection_rows()
            .iter()
            .position(|row| *row == ProtectionRow::RepeatOffenders)
            .expect("the repeat offenders row should exist");
        dashboard.protection_state.select(Some(index));
    }

    /// On a database from before it, the row is off and says "new", the
    /// way a new detector's does, until the operator chooses.
    #[test]
    fn repeat_offenders_is_new_on_an_older_database_until_switched() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 1)
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let row = ProtectionRow::RepeatOffenders;
        assert!(!dashboard.protection_enabled(row), "on after an upgrade");
        assert_eq!(dashboard.protection_detail(row), " new");

        focus_protection(&mut dashboard, &db);
        select_repeat_offenders(&mut dashboard);
        let outcome = press(&mut dashboard, &db, KeyCode::Char(' '));

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(crate::protection::repeat_escalation(&db).unwrap());
        assert_eq!(dashboard.protection_detail(row), " up to 8x");
    }

    /// The detectors added after 0.3, on a database 0.3 created: each row
    /// is off and says "new", and `?` says what it blocks, who it might
    /// catch, and why it is off.
    #[test]
    fn a_detector_added_since_0_3_is_new_and_explained_on_an_older_database() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 2)
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        for detector in [
            Detector::LoginAttempts,
            Detector::RequestRate,
            Detector::RobotsViolators,
        ] {
            let row = ProtectionRow::Detect(detector);
            let id = detector.id();
            assert!(
                !dashboard.protection_enabled(row),
                "{id} on after an upgrade"
            );
            assert_eq!(dashboard.protection_detail(row), " new", "{id}");

            select_detector(&mut dashboard, detector);
            let text: Vec<String> = dashboard
                .explain()
                .body
                .iter()
                .map(|line| line.to_string())
                .collect();
            let text = text.join("\n");
            for expected in [
                detector.about(),
                detector.risk().unwrap_or_default(),
                "New since this database was created",
            ] {
                assert!(text.contains(expected), "{id}: {expected:?} in:\n{text}");
            }
        }
    }

    #[test]
    fn turning_repeat_offenders_off_persists_it() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);
        select_repeat_offenders(&mut dashboard);

        let mut message = None;
        dashboard
            .commit_protection(&db, ProtectionRow::RepeatOffenders, 0, &mut message)
            .unwrap();

        assert!(!crate::protection::repeat_escalation(&db).unwrap());
        let message = message.unwrap_or_default();
        assert!(
            message.starts_with("Repeat offenders off"),
            "message: {message}"
        );
    }

    /// On a database from 0.3.0, probes for absent apps are off and say
    /// "new", as a new detector does, until the operator chooses.
    #[test]
    fn app_probe_paths_are_new_on_an_older_database_until_switched() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 2)
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let row = ProtectionRow::AppProbePaths;
        assert!(!dashboard.protection_enabled(row), "on after an upgrade");
        assert_eq!(dashboard.protection_detail(row), " new");

        let mut message = None;
        dashboard
            .commit_protection(&db, row, 1, &mut message)
            .unwrap();

        assert!(crate::protection::app_probe_paths(&db).unwrap());
        assert_eq!(dashboard.protection_detail(row), "");
    }

    #[test]
    fn the_probe_paths_explanation_says_whether_absent_apps_count() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let explanation = dashboard.explain_protection(ProtectionRow::Detect(Detector::ProbePaths));

        let text = format!("{explanation:?}");
        assert!(
            text.contains("Probes for absent apps, further down this list, is on"),
            "{text}"
        );
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

    fn detector_row_text(dashboard: &Dashboard, detector: Detector) -> String {
        dashboard
            .protection_row_line(ProtectionRow::Detect(detector), 20)
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    /// A detector an upgrade added stays off on an existing database, and
    /// the panel says why it is there: "new", until the operator chooses.
    #[test]
    fn a_detector_added_since_the_database_was_created_is_marked_new_and_off() {
        let db = Db::open_in_memory().unwrap();
        // Older than every detector, so each one is new here.
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 0)
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        let text = detector_row_text(&dashboard, Detector::Injection);
        assert!(text.ends_with("[ OFF ] new"), "row was: {text:?}");

        Detector::Injection.set_enabled(&db, false).unwrap();
        dashboard.refresh(&db).unwrap();
        let text = detector_row_text(&dashboard, Detector::Injection);
        assert!(
            text.ends_with("[ OFF ]"),
            "chosen, so no longer new: {text:?}"
        );
    }

    #[test]
    fn nothing_is_marked_new_on_a_database_this_release_created() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();

        for detector in Detector::ALL {
            let text = detector_row_text(&dashboard, detector);
            assert!(!text.contains("new"), "row was: {text:?}");
        }
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
        // Every detector but the robots.txt one, which only appears under
        // humans-only...
        let detectors = Detector::ALL.len() - 1;
        assert_eq!(
            rows.len(),
            // ...plus `RepeatOffenders` and `AppProbePaths`, between the
            // detectors and the feeds, and the `HostingProviders`,
            // `Outbound`, `AutoApplyFirewall` and `LockoutCheck` rows, which
            // sit after the feeds. None of the six is a detector.
            detectors + ReputationSourceKind::ALL.len() + 6
        );
        assert_eq!(rows[detectors], ProtectionRow::RepeatOffenders);
        assert_eq!(rows[detectors + 1], ProtectionRow::AppProbePaths);
        assert!(rows[..detectors].iter().all(|r| r.is_detector()));
        assert!(rows[detectors..].iter().all(|r| !r.is_detector()));
    }

    /// The mode brings its own rule with it, and takes it away again.
    #[test]
    fn the_robots_txt_row_appears_only_under_humans_only() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        assert!(
            !dashboard
                .protection_rows()
                .contains(&ProtectionRow::Detect(Detector::RobotsTxt)),
            "the row is there with the mode off"
        );

        db.set_humans_only(true).unwrap();
        dashboard.refresh(&db).unwrap();

        assert!(
            dashboard
                .protection_rows()
                .contains(&ProtectionRow::Detect(Detector::RobotsTxt)),
            "the row is missing with the mode on"
        );
    }

    /// A Dashboard with the Automatic blocking panel focused on `row`.
    fn focused_on(db: &Db, row: ProtectionRow) -> Dashboard {
        crate::egress::register_builtin_feeds(db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(db).unwrap();
        focus_protection(&mut dashboard, db);
        let index = dashboard
            .protection_rows()
            .iter()
            .position(|r| *r == row)
            .unwrap_or_else(|| panic!("no {row:?} row"));
        dashboard.protection_state.select(Some(index));
        dashboard
    }

    fn feodo(db: &Db) -> ProtectionRow {
        crate::egress::register_builtin_feeds(db).unwrap();
        ProtectionRow::EgressFeed(
            db.list_egress_feeds()
                .unwrap()
                .iter()
                .position(|f| f.id == "feodo")
                .unwrap(),
        )
    }

    /// Everything a frame drew, row by row.
    fn screen(dashboard: &mut Dashboard, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(100, height)).unwrap();
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
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn space_on_outbound_checks_steps_through_the_modes() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = focused_on(&db, ProtectionRow::Outbound);
        let mut seen = Vec::new();
        for _ in 0..3 {
            press(&mut dashboard, &db, KeyCode::Char(' '));
            seen.push(crate::egress::Mode::get(&db).unwrap());
        }
        use crate::egress::Mode;
        assert_eq!(seen, [Mode::Watch, Mode::Block, Mode::Off]);
    }

    /// Until outbound checks are on, a feed would check nothing.
    #[test]
    fn the_c2_feeds_are_listed_once_outbound_checks_are_on() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = focused_on(&db, ProtectionRow::Outbound);
        let listed = |d: &Dashboard| {
            d.protection_rows()
                .iter()
                .filter(|r| matches!(r, ProtectionRow::EgressFeed(_) | ProtectionRow::AutoContain))
                .count()
        };
        assert_eq!(listed(&dashboard), 0);
        press(&mut dashboard, &db, KeyCode::Char(' '));
        dashboard.refresh(&db).unwrap();
        assert_eq!(listed(&dashboard), crate::egress::FeedKind::ALL.len() + 1);
    }

    #[test]
    fn switching_on_an_unfetched_c2_feed_asks_for_the_feed_job() {
        let db = Db::open_in_memory().unwrap();
        crate::egress::Mode::Watch.set(&db).unwrap();
        let row = feodo(&db);
        let mut dashboard = focused_on(&db, row);
        assert_eq!(
            press(&mut dashboard, &db, KeyCode::Char(' ')),
            KeyOutcome::UpdateEgressFeeds
        );
        assert!(db.get_egress_feed("feodo").unwrap().unwrap().enabled);
    }

    /// Containing a container is a bigger step than reporting a hit.
    #[test]
    fn automatic_containment_is_switched_on_only_once_confirmed() {
        let db = Db::open_in_memory().unwrap();
        crate::egress::Mode::Block.set(&db).unwrap();
        let mut dashboard = focused_on(&db, ProtectionRow::AutoContain);
        press(&mut dashboard, &db, KeyCode::Char(' '));
        assert!(
            !crate::contain::Settings::get(&db).unwrap().auto,
            "on before confirming"
        );
        press(&mut dashboard, &db, KeyCode::Enter);
        assert!(
            crate::contain::Settings::get(&db).unwrap().auto,
            "still off after confirming"
        );
    }

    /// Each row is drawn indented under its group's heading, in order.
    #[test]
    fn the_rows_are_listed_under_their_headings() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        crate::egress::Mode::Watch.set(&db).unwrap();
        let mut dashboard = focused_on(&db, ProtectionRow::Outbound);
        let lines = screen(&mut dashboard, 48);
        let line_of = |needle: &str| {
            lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no {needle:?} in:\n{}", lines.join("\n")))
        };
        let order = [
            "Log detectors",
            "  SSH scanners",
            "Blocked by address",
            "  FireHOL level 1",
            "Outbound C&C checks",
            "  Checks",
            "  abuse.ch Feodo Tracker",
            "  Contain on a hit",
            "Firewall apply",
            "  SSH lock-out check",
        ];
        let at: Vec<usize> = order.iter().map(|needle| line_of(needle)).collect();
        assert!(
            at.windows(2).all(|pair| pair[0] < pair[1]),
            "out of order: {:?}\n{}",
            order.iter().zip(&at).collect::<Vec<_>>(),
            lines.join("\n")
        );
    }

    /// A heading is a line of its own, never a row: the highlight lands
    /// on the row selected, below the heading it sits under.
    #[test]
    fn a_heading_is_never_highlighted() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = focused_on(&db, ProtectionRow::Outbound);
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
                    .collect()
            })
            .collect();
        assert_eq!(highlighted.len(), 1, "{highlighted:?}");
        assert!(highlighted[0].contains("  Checks"), "{highlighted:?}");
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
        assert_eq!(protection_options(ProtectionRow::LockoutCheck).len(), 2);
        assert!(protection_options(ProtectionRow::Detect(Detector::ALL[0])).len() > 2);
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
    /// The highlight lands on the selected row, and in exactly one place:
    /// every other test here asserts on text rather than on style.
    #[test]
    fn the_highlight_lands_on_the_selected_row() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        dashboard.focus = Focus::Protection;
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
        db.replace_reputation_ranges(
            ReputationSourceKind::GoogleCloud.id(),
            &["1.2.3.0/24".to_string()],
        )
        .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        focus_protection(&mut dashboard, &db);

        let target = feed_row_index(&dashboard, ReputationSourceKind::GoogleCloud.id());
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

    // ---- hosting providers by ASN ----

    fn on_the_hosting_row(db: &Db) -> Dashboard {
        let mut dashboard = Dashboard::default();
        dashboard.refresh(db).unwrap();
        focus_protection(&mut dashboard, db);
        let target = dashboard
            .protection_rows()
            .iter()
            .position(|row| *row == ProtectionRow::HostingProviders)
            .expect("the hosting providers row");
        dashboard.protection_state.select(Some(target));
        dashboard
    }

    /// Moves the popup's cursor onto `asn` by keypress.
    fn move_to(dashboard: &mut Dashboard, db: &Db, asn: u32) {
        let at = dashboard
            .hosting_choices()
            .iter()
            .position(|a| *a == asn)
            .expect("listed");
        for _ in 0..at {
            press(dashboard, db, KeyCode::Down);
        }
    }

    /// Ticking a provider and saving blocks it, warns, and asks `App` for
    /// one download of everything chosen that has no ranges yet.
    #[test]
    fn ticking_a_provider_and_saving_blocks_it_and_asks_for_its_ranges() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_the_hosting_row(&db);

        press(&mut dashboard, &db, KeyCode::Enter);
        assert!(matches!(
            dashboard.popup,
            Some(Popup::HostingProviders { .. })
        ));
        move_to(&mut dashboard, &db, 24940);
        press(&mut dashboard, &db, KeyCode::Char(' '));
        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::FetchHostingAsns(vec![24940]));
        assert!(dashboard.popup.is_none());
        let selected: Vec<u32> = db
            .list_hosting_asns()
            .unwrap()
            .iter()
            .map(|a| a.asn)
            .collect();
        assert_eq!(selected, [24940]);
        let message = message.unwrap_or_default();
        assert!(
            message.contains("Blocking Hetzner") && message.contains("not just bots"),
            "message was: {message}"
        );
    }

    #[test]
    fn escape_leaves_the_hosting_providers_as_they_were() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_the_hosting_row(&db);

        press(&mut dashboard, &db, KeyCode::Char(' '));
        press(&mut dashboard, &db, KeyCode::Char(' '));
        let outcome = press(&mut dashboard, &db, KeyCode::Esc);

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(dashboard.popup.is_none());
        assert!(db.list_hosting_asns().unwrap().is_empty());
    }

    /// Unticking one whose ranges are stored needs no download, and its
    /// ranges go with it.
    #[test]
    fn unticking_a_blocked_provider_unblocks_it_without_a_download() {
        let db = Db::open_in_memory().unwrap();
        db.add_hosting_asn(16276).unwrap();
        db.replace_hosting_asn_ranges(16276, "OVH", &["51.68.0.0/23".to_string()])
            .unwrap();
        let mut dashboard = on_the_hosting_row(&db);

        press(&mut dashboard, &db, KeyCode::Char(' '));
        move_to(&mut dashboard, &db, 16276);
        press(&mut dashboard, &db, KeyCode::Char(' '));
        let outcome = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_hosting_asns().unwrap().is_empty());
        assert!(db.hosting_asn_ranges().unwrap().is_empty());
    }

    /// The row counts what is blocked, and the popup lists the built-in
    /// providers with what each holds.
    #[test]
    fn the_row_counts_the_blocked_providers_and_the_popup_lists_them() {
        let db = Db::open_in_memory().unwrap();
        db.add_hosting_asn(16276).unwrap();
        db.replace_hosting_asn_ranges(16276, "OVH", &["51.68.0.0/23".to_string()])
            .unwrap();
        let mut dashboard = on_the_hosting_row(&db);
        assert_eq!(
            dashboard.protection_detail(ProtectionRow::HostingProviders),
            " 1 blocked"
        );

        press(&mut dashboard, &db, KeyCode::Enter);
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
        let screen = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "[x] AS16276",
            "OVHcloud",
            "1 range(s)",
            "[ ] AS24940",
            "Hetzner",
        ] {
            assert!(screen.contains(expected), "{expected:?} not in:\n{screen}");
        }
    }

    #[test]
    fn a_chosen_provider_with_no_ranges_yet_says_not_fetched() {
        let db = Db::open_in_memory().unwrap();
        db.add_hosting_asn(24940).unwrap();
        let dashboard = on_the_hosting_row(&db);

        assert_eq!(
            dashboard.protection_detail(ProtectionRow::HostingProviders),
            " not fetched"
        );
        let explained = dashboard
            .explain()
            .body
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            explained.contains("not downloaded yet"),
            "explained as:\n{explained}"
        );
    }

    /// A dashboard on the Automatic blocking panel, with the AWS feed
    /// fetched, off, and selected.
    fn on_the_aws_row(db: &Db) -> Dashboard {
        register_all_reputation_sources(db).unwrap();
        db.replace_reputation_ranges(ReputationSourceKind::Aws.id(), &["1.2.3.0/24".to_string()])
            .unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(db).unwrap();
        focus_protection(&mut dashboard, db);
        let target = feed_row_index(&dashboard, ReputationSourceKind::Aws.id());
        dashboard.protection_state.select(Some(target));
        dashboard
    }

    fn aws_enabled(db: &Db) -> bool {
        db.list_reputation_sources()
            .unwrap()
            .iter()
            .any(|s| s.id == ReputationSourceKind::Aws.id() && s.enabled)
    }

    /// Let's Encrypt validates from AWS, so switching the feed on asks
    /// about port 80 first, and backing out of that leaves it off.
    #[test]
    fn switching_aws_on_asks_about_port_80_and_esc_leaves_it_off() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_the_aws_row(&db);

        press(&mut dashboard, &db, KeyCode::Char(' '));
        assert!(
            matches!(
                dashboard.popup,
                Some(Popup::CloudPort80 { selected: 0, .. })
            ),
            "popup was {:?}",
            dashboard.popup
        );
        assert!(!aws_enabled(&db), "AWS was switched on before the answer");

        press(&mut dashboard, &db, KeyCode::Esc);
        assert!(!aws_enabled(&db), "Esc switched AWS on");
    }

    #[test]
    fn keeping_port_80_open_switches_aws_on_and_says_so() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_the_aws_row(&db);
        let mut message = None;
        for code in [KeyCode::Char(' '), KeyCode::Enter] {
            dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap();
        }

        assert!(aws_enabled(&db));
        assert!(db.get_cloud_port_80_open().unwrap());
        let message = message.unwrap();
        assert!(message.contains("port 80 open"), "message was: {message}");
    }

    #[test]
    fn blocking_port_80_too_is_stored_and_says_renewals_will_fail() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_the_aws_row(&db);
        let mut message = None;
        for code in [KeyCode::Char(' '), KeyCode::Down, KeyCode::Enter] {
            dashboard
                .handle_key(KeyEvent::from(code), &db, &mut message)
                .unwrap();
        }

        assert!(aws_enabled(&db));
        assert!(!db.get_cloud_port_80_open().unwrap());
        let message = message.unwrap();
        assert!(
            message.contains("renewals over HTTP will fail"),
            "message was: {message}"
        );
    }

    /// Every automatic-blocking option is on screen at once, in one
    /// column under its heading, on a 100x36 terminal: a row more and this
    /// is the test that says the panel no longer fits. Shorter than that,
    /// it scrolls.
    #[test]
    fn every_automatic_blocking_option_is_visible_without_scrolling() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        let mut dashboard = Dashboard::default();
        dashboard.refresh(&db).unwrap();
        let content = screen(&mut dashboard, 36).join("\n");
        let rows = dashboard.protection_rows();
        assert_eq!(rows.len(), 26, "if this changes, so does the panel height");
        for row in rows {
            let label = dashboard.protection_label(row);
            assert!(
                content.contains(&label),
                "{label:?} is not on screen:\n{content}"
            );
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
