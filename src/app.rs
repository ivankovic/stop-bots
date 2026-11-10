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

//! The app controller: owns all TUI state, runs the event loop, and routes
//! key presses to the active screen (falling back to global key handling).

use crate::botlist;
use crate::cron::CronJob;
use crate::db::Db;
use crate::event::{AppEvent, Event, EventHandler};
use crate::ipranges;
use crate::tui::{self, KeyOutcome, Screen, Theme};
use crate::webserver;
use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

/// How often the internal cron re-checks which jobs are due (see
/// `crate::cron`) — not the jobs' own intervals, just how often
/// `Event::Tick` (which fires at 30fps) bothers asking. This is now the
/// practical floor for the detection jobs (`BlockScanners`/
/// `BlockWebScanners`/`RecordAccessStats` all run every 60s, see
/// `CronJob::interval`): a job can't run before its own due-check happens,
/// so shortening this constant is the only way to make them fire sooner
/// than once a minute. Cheap either way (a handful of `settings` table
/// reads), so there'd be room to tighten it further if once-a-minute
/// detection latency ever isn't fast enough.
use crate::cron::CHECK_INTERVAL as CRON_CHECK_INTERVAL;

/// Everything that can be running in the background, and the key
/// [`App::jobs_in_flight`] is keyed by.
///
/// One set covers the internal cron's jobs and the actions an admin
/// triggers, because both want the same two things from it: a spinner
/// while the work is out, and a guard against starting the same work
/// twice. `due_jobs` can't provide the second on its own (a job's
/// `last_run` doesn't move until it finishes), and neither can a key
/// handler — holding Enter on "apply" would otherwise stack up one
/// `systemctl reload nginx` per repeat.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Job {
    /// A scheduled job from [`crate::cron`].
    Cron(CronJob),
    /// Reading the SSH log that Firewall's SSH panel is built
    /// from. See [`App::start_ssh_log_read`].
    ReadSshLog,
    /// `nginx -t` followed by `systemctl reload nginx`, after Site
    /// settings has written a config file. See [`App::start_nginx_reload`].
    ReloadNginx,
    /// Writing the firewall script and, if asked, applying it. See
    /// [`App::start_firewall_render`].
    RenderFirewall,
    /// Walking the NGINX config root. See [`App::start_site_action`].
    ScanSites,
    /// Rewriting site config files. See [`App::start_site_action`].
    ApplySites,
    /// Reading each site's config file to work out whether its block is
    /// current. See [`App::start_site_status_check`].
    CheckSiteStatuses,
    /// Downloading every list this host uses, one source at a time. See
    /// [`App::start_update_everything`].
    UpdateEverything,
    /// Downloading one crawler's published ranges. See
    /// [`App::start_crawler_ranges_refresh`].
    RefreshCrawlerRanges(crate::ipranges::IpRangeSourceKind),
    /// Working out what "Apply everything" would change, before asking.
    /// See [`App::start_apply_preview`].
    PreviewApply,
    /// Keeping or reverting an apply that was waiting for an answer. See
    /// [`App::start_firewall_settle`].
    SettleFirewall,
}

impl Job {
    /// What the footer calls this while it is running. Phrased as what is
    /// happening, not as the name of a function, since this is the only
    /// thing on screen explaining why the admin is waiting — and so naming
    /// the web server the host runs, which is not always NGINX.
    pub fn label(&self, server: crate::webserver::WebServer) -> String {
        let server = server.label();
        match self {
            Job::Cron(job) => format!("{} (scheduled)", job.label()),
            Job::ReadSshLog => "reading the SSH log".to_string(),
            Job::ReloadNginx => format!("reloading {server}"),
            Job::RenderFirewall => "writing the firewall script".to_string(),
            Job::ScanSites => format!("scanning the {server} config"),
            Job::ApplySites => "writing site config".to_string(),
            Job::CheckSiteStatuses => "checking site config".to_string(),
            Job::UpdateEverything => "downloading every list".to_string(),
            Job::RefreshCrawlerRanges(kind) => format!("downloading {}", kind.name()),
            Job::PreviewApply => "working out what applying would change".to_string(),
            Job::SettleFirewall => "settling the firewall change".to_string(),
        }
    }
}

/// How long a read of the SSH log stays good enough to rebuild Dynamic
/// Protection's SSH panel from.
///
/// The log is append-only and this screen is a live view of it, so the
/// only cost of a stale cache is that an attempt from the last few seconds
/// is missing from the counts — while the cost of no cache at all was a
/// `journalctl` subprocess, upwards of half a second, on every reload of
/// the screen.
const SSH_LOG_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30);

pub struct App {
    pub running: bool,
    pub events: EventHandler,
    pub theme: Theme,
    pub screen: Screen,
    /// The screen to return to when the Help screen is closed.
    before_help: Screen,
    pub message: Option<String>,
    /// Whether the footer shows `message` in place of the key hints: from
    /// the moment a message appears until the next key press, on whichever
    /// screen is open. The Dashboard's Log keeps every message after that.
    pub message_in_footer: bool,
    /// Every message the screens have produced, newest last, with the
    /// unix time it appeared: the Dashboard's Log panel. `message` is
    /// still what a screen writes to — this is `App` watching it, so the
    /// hundred places that set a message did not each have to learn about
    /// a log.
    pub log: Vec<(i64, String)>,
    db_last_logged: Option<String>,
    /// The command palette, while it is open. See [`crate::tui::palette`].
    pub palette: Option<tui::palette::Palette>,
    /// What the row under the cursor is, while `?` has it open. See
    /// [`crate::tui::explain`].
    pub explain: Option<tui::explain::Explain>,
    pub db: Db,
    /// Shown above the status strip when the database is not the system
    /// one: see [`crate::db::location_notice`]. Set by `main.rs`, which is
    /// the only place that knows whether the path was chosen for the user.
    pub db_notice: Option<String>,
    pub dashboard: tui::dashboard::Dashboard,
    pub bot_settings: tui::bot_settings::BotSettings,
    pub nginx: tui::nginx::Nginx,
    pub firewall: tui::firewall::Firewall,
    pub blocks: tui::blocks::Blocks,
    /// When the internal cron last checked for due jobs — throttles the
    /// check against `Event::Tick`'s 30fps rate (see
    /// [`CRON_CHECK_INTERVAL`]).
    last_cron_check: std::time::Instant,
    /// The SSH log as last read, and when. Firewall's SSH panel
    /// is rebuilt from this rather than from a fresh read — see
    /// [`SSH_LOG_MAX_AGE`] and [`App::start_ssh_log_read`]. `None` means no read
    /// has come back yet.
    ///
    /// Deliberately *not* what the lockout guard in
    /// [`App::start_firewall_render`] consults: that one reads live, every time.
    /// A cached answer there is the difference between "this would cut off
    /// the admin" and finding out afterwards.
    ssh_log_text: Option<String>,
    ssh_log_read_at: Option<std::time::Instant>,
    /// Set when an apply asked for an NGINX reload while one was already
    /// running, so [`App::finish_nginx_reload`] knows to start one more.
    /// See [`App::start_nginx_reload`] for why dropping it instead is wrong.
    reload_nginx_pending: bool,
    /// Set when the site list or its settings changed while a status check
    /// was already out. Coalesced rather than dropped for the same reason
    /// a reload is: nothing else would ever catch up, so the tags would
    /// keep describing the settings from before the change.
    site_statuses_pending: bool,
    /// Screens whose cached state something has invalidated since they
    /// were last drawn — see [`Self::refresh`].
    stale: std::collections::HashSet<Screen>,
    /// Which background work is currently out — see [`Job`] for what goes
    /// in here and why one set serves both purposes. Also what every
    /// spinner on screen is drawn from.
    pub jobs_in_flight: std::collections::HashSet<Job>,
    /// Whether `KeyOutcome::ReloadNginx` actually calls `nginx::reload()`.
    /// Always `true` for real usage; `false` only for the end-to-end TUI
    /// tests in `tests/tui.rs`, which drive a real NGINX "apply"
    /// through a real spawned binary — without this, that would shell out
    /// to the real `nginx -t`/`systemctl reload nginx` on whatever machine
    /// runs the test suite (see `main.rs`'s `tui --no-reload` flag, the
    /// same escape hatch `apply-blocks --no-reload` uses).
    reload_nginx_for_real: bool,
    /// SSH log override (`tui --ssh-log`). `None` auto-detects, which can
    /// mean shelling out to `journalctl` — on some hosts more than half a
    /// second per call, and this is consulted on every refresh of the
    /// Firewall screen, every `BlockScanners` cron pass and every
    /// firewall render's lockout check. The override makes all three
    /// deterministic (and fast) for tests, and usable on hosts with a
    /// non-standard log path.
    ssh_log: Option<std::path::PathBuf>,
    /// The address this TUI's own SSH session comes from, read once at
    /// start ([`crate::sshlog::session_client`]): every firewall run's
    /// lockout check counts it as connected, whatever the log says.
    session_client: Option<String>,
    /// Whether a render popup confirmed with "apply after writing" actually
    /// calls `firewall::apply_script()`. Same shape and same reason as
    /// `reload_nginx_for_real`: always `true` for real usage, `false` only for tests
    /// — without this, a test requesting `apply: true` would shell out to
    /// the real `nft -f`/`sh` against whatever host runs the suite. Shares
    /// `main.rs`'s `--no-reload` flag rather than getting its own, since
    /// both exist for exactly the same "don't really execute system-
    /// changing commands under test" reason.
    apply_firewall: bool,
    /// Where "Apply everything" and the scheduled render write the firewall
    /// script. `None` means "follow the backend", which is what
    /// [`crate::firewall::output_path`] does: an nftables render lands in
    /// `.nft` and an iptables one in `.sh`.
    ///
    /// A field rather than a call at the point of use because the default
    /// is a real path under `/etc`, and a test that presses the key must be able to point it somewhere
    /// harmless. The render *popup* takes its path from the admin instead,
    /// which is why this only covers the one-key path.
    pub firewall_out: Option<std::path::PathBuf>,
    /// The host settings file ([`crate::hostconf`]): the NGINX commands and
    /// the logs. A field, read at each use, so a test can point it at a
    /// file of its own and `set-web-server` takes effect without a
    /// restart.
    pub host_conf: std::path::PathBuf,
    /// The download lease a one-source crawler refresh holds while its
    /// fetch is out — see [`App::start_crawler_ranges_refresh`].
    crawler_refresh_lease: Option<crate::refresh::Lease>,
    /// Set while "Apply everything" is waiting on its NGINX half, so
    /// [`App::finish_site_apply`] knows to start the firewall half after
    /// it. The two are independent — whichever fails, the other still gets
    /// its turn — they are merely sequenced so that their messages do not
    /// overwrite each other.
    apply_everything: bool,
    /// Set while the internal cron's `ApplyNginx` job is waiting on the
    /// site apply it started, so `finish_site_apply` knows to record the
    /// outcome against that job rather than leaving it looking like it
    /// never ran. Same flag-then-finish shape as `apply_everything`.
    cron_apply_nginx: bool,
    /// An apply that is loaded and waiting for "keep these firewall
    /// rules?" — see [`crate::revert`]. Asked over every screen.
    pub keep_firewall: Option<tui::keep_firewall::KeepFirewall>,
    /// How long that question waits before the previous rules come back
    /// (`tui --confirm-timeout`).
    pub confirm_timeout: std::time::Duration,
    /// The programs a keep or a revert runs. A field so a test can hand
    /// it fakes.
    pub revert_tools: crate::revert::Tools,
}

/// The key a scheduled job's work is in flight under: its own, except for
/// the download `u` asks for, which is `Job::UpdateEverything` so that the
/// Scheduled tasks panel does not show it as the weekly job running.
fn cron_job_key(job: CronJob, by_hand: bool) -> Job {
    if by_hand {
        Job::UpdateEverything
    } else {
        Job::Cron(job)
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Runs a downloaded body's parser on the blocking pool.
///
/// The download itself yields at every `await`, so it never held the event
/// loop up — but the parse that follows is plain CPU work with no await in
/// it, and `tokio::spawn` puts it on a runtime worker. On a one-core
/// server there is exactly one of those, shared with the draw loop, so a
/// megabyte of AWS `ip-ranges.json` was a megabyte of frozen interface.
///
/// A parse can't fail in a way worth distinguishing from a panic, so a
/// `JoinError` is reported as one.
async fn parse_off_thread<T: Send + 'static>(
    parse: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(parse)
        .await
        .context("the parser thread panicked")?
}

/// What the TUI says about a firewall run: the shared summary, plus the
/// one thing only this front-end can say — how to get the guard an SSH log
/// when it could not read one.
///
/// There is no `--force` here. Someone who knows the log is missing and
/// means it anyway has `stop-bots render-firewall --apply --force`.
pub fn firewall_message(outcome: &crate::firewall::FirewallOutcome) -> String {
    let mut message = format!("Firewall: {}", outcome.summary());
    if outcome.refused() && outcome.guard == crate::firewall::Guard::LogUnreadable {
        message.push_str(". Start the TUI with --ssh-log <path>, or run it as root");
    } else if outcome.refused() && matches!(outcome.guard, crate::firewall::Guard::NoLogins { .. })
    {
        message.push_str(
            ". Trust your address on the Firewall screen, or, if you never log in over SSH, turn \
             the SSH lock-out check off on the Dashboard",
        );
    } else if outcome.apply != crate::firewall::ApplyStep::NotAsked && outcome.guard.passed() {
        // The verdict the confirmation showed, said again once it held.
        message.push_str(". The lockout check passed");
    }
    message.push('.');
    message
}

/// The last day of what the schedule did (see `crate::activity`), as the
/// Log's opening lines: the newest few, oldest first as the Log is kept.
fn recent_activity(db: &Db) -> Vec<(i64, String)> {
    const SHOWN: usize = 20;
    let day_ago = crate::blocks::now() - 86_400;
    let events = crate::activity::since(db, day_ago).unwrap_or_default();
    let skip = events.len().saturating_sub(SHOWN);
    events
        .into_iter()
        .skip(skip)
        .map(|event| (event.at, format!("{}: {}", event.label(), event.summary)))
        .collect()
}

impl App {
    /// The active screen's footer hints: the focused panel's name and its
    /// keys. Shared by the footer and by `?`, so the two list the same keys.
    pub fn hints(&self) -> tui::Hints {
        match self.screen {
            Screen::Dashboard => self.dashboard.hints(),
            Screen::BotSettings => self.bot_settings.hints(),
            Screen::Firewall => self.firewall.hints(),
            Screen::Nginx => self.nginx.hints(),
            Screen::Blocks => self.blocks.hints(),
            Screen::Help => ("Help", vec![("Esc", "back")]),
        }
    }

    /// What the row under the cursor on the active screen is, for `?`.
    fn explanation(&self) -> tui::explain::Explanation {
        match self.screen {
            Screen::Dashboard => self.dashboard.explain(),
            Screen::BotSettings => self.bot_settings.explain(),
            Screen::Firewall => self.firewall.explain(),
            Screen::Nginx => self.nginx.explain(),
            Screen::Blocks => self.blocks.explain(),
            Screen::Help => tui::explain::Explanation::new("Help"),
        }
    }

    /// Constructs a new [`App`], loading initial state from `db`. `root` is
    /// the NGINX config root NGINX scans when the user triggers a
    /// rescan from the TUI. `reload_nginx_for_real` gates whether a successful Site
    /// settings apply actually reloads NGINX, and whether a firewall render
    /// popup confirmed with "apply after writing" actually applies it (see
    /// both fields' doc comments) — one flag for both, since they exist for
    /// the same reason.
    pub fn new(
        db: Db,
        root: std::path::PathBuf,
        reload_nginx: bool,
        ssh_log: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        let mut app = Self {
            running: true,
            events: EventHandler::new(),
            theme: Theme::detect(),
            screen: Screen::default(),
            before_help: Screen::default(),
            message: None,
            message_in_footer: false,
            // What the schedule did since this screen was last open, not
            // nothing: the Log used to start empty every time, as if the
            // night had been quiet.
            log: recent_activity(&db),
            db_last_logged: None,
            palette: None,
            explain: None,
            db,
            db_notice: None,
            dashboard: tui::dashboard::Dashboard::default(),
            bot_settings: tui::bot_settings::BotSettings::default(),
            nginx: tui::nginx::Nginx::new(crate::webserver::WebServer::configured(), root),
            firewall: tui::firewall::Firewall::default(),
            blocks: tui::blocks::Blocks::default(),
            // Backdated by a full `CRON_CHECK_INTERVAL` so the very first
            // `Event::Tick` (a fraction of a second after startup, not up to
            // a minute later) already passes `check_cron`'s throttle check.
            // Without this, a job that's due the instant the TUI opens (the
            // common case for a fresh database, or now that the detection
            // jobs' own interval — see `CronJob::interval` — is the same 60s
            // as this throttle) would sit there showing "due now" without
            // actually running for up to a full minute, the same
            // never-run-yet-so-do-it-now convention `ipranges` staleness
            // already uses, just not applied to the check's own timer
            // before now. `checked_sub` guards a process started within
            // `CRON_CHECK_INTERVAL` of system boot, where the subtraction
            // would otherwise underflow `Instant`'s monotonic clock.
            last_cron_check: std::time::Instant::now()
                .checked_sub(CRON_CHECK_INTERVAL)
                .unwrap_or_else(std::time::Instant::now),
            ssh_log_text: None,
            ssh_log_read_at: None,
            reload_nginx_pending: false,
            site_statuses_pending: false,
            stale: std::collections::HashSet::new(),
            jobs_in_flight: std::collections::HashSet::new(),
            reload_nginx_for_real: reload_nginx,
            apply_firewall: reload_nginx,
            ssh_log,
            session_client: crate::sshlog::session_client(),
            firewall_out: None,
            host_conf: crate::hostconf::path(),
            crawler_refresh_lease: None,
            apply_everything: false,
            cron_apply_nginx: false,
            keep_firewall: None,
            confirm_timeout: crate::revert::DEFAULT_TIMEOUT,
            revert_tools: crate::revert::Tools::host(),
        };
        botlist::register_all_sources(&app.db)?;
        // Same reason bot-list sources are registered here: the Dashboard's
        // feed rows need something to show before any fetch has ever run,
        // otherwise a fresh install offers no way to turn one on. Safe to
        // repeat every startup — registration never touches an existing
        // row's `enabled` flag.
        crate::ipranges::reputation::register_all_reputation_sources(&app.db)?;
        crate::egress::register_builtin_feeds(&app.db)?;
        app.dashboard.installed = Some(crate::firewall::Installed::detect());
        let simple = app.db.get_ui_mode()? == crate::db::UiMode::Simple;
        app.dashboard.set_simple(simple);
        app.refresh_all()?;
        Ok(app)
    }

    /// Switches to the simple screen or to every screen, and remembers it.
    /// Lands on the Dashboard, the one screen both have, unless this is
    /// the simple mode and the screen open is Blocks, which it has too.
    fn set_ui_mode(&mut self, mode: crate::db::UiMode) -> Result<()> {
        self.db.set_ui_mode(mode)?;
        let simple = mode == crate::db::UiMode::Simple;
        self.dashboard.set_simple(simple);
        if !(simple && Screen::SIMPLE_TABS.contains(&self.screen)) {
            self.screen = Screen::Dashboard;
        }
        self.message = Some(if simple {
            "The simple screen. v shows every screen again.".to_string()
        } else {
            "Every screen. v goes back to the simple one.".to_string()
        });
        self.refresh()
    }

    /// Goes to `screen`, leaving the simple mode first when it does not
    /// have that screen: a palette command or a key that names one is
    /// asking for it.
    fn show(&mut self, screen: Screen) -> Result<()> {
        if self.dashboard.is_simple()
            && screen != Screen::Help
            && !Screen::SIMPLE_TABS.contains(&screen)
        {
            self.set_ui_mode(crate::db::UiMode::Advanced)?;
        }
        self.screen = screen;
        Ok(())
    }

    /// "Keep running by itself" from the simple screen: see
    /// [`crate::install::keep_running`]. Writing one small file is not
    /// slow, so this is not a `start_`/`finish_` pair. On success the
    /// health check runs again at once, so the status stops saying that
    /// nothing runs the schedule an hour before the next one would.
    fn set_keep_running(&mut self, on: bool) -> Result<()> {
        let outcome = if on {
            self.keep_running_layout().and_then(|layout| {
                crate::install::keep_running(&self.db, &layout, crate::hint::is_root())
            })
        } else {
            crate::install::stop_keep_running(&self.db)
        };
        let started = outcome.is_ok() && on;
        self.message = Some(match outcome {
            Ok(message) => message,
            Err(err) => format!("{err:#}"),
        });
        if started {
            self.start_cron_job(crate::cron::Task::Job(CronJob::HealthCheck))?;
        }
        self.refresh()
    }

    /// Where the cron file goes and what it runs: this binary, against
    /// this database.
    fn keep_running_layout(&self) -> Result<crate::install::Layout> {
        let binary = std::env::current_exe().context("could not tell which binary this is")?;
        let mut layout = crate::install::Layout::system(binary);
        layout.db_path = self
            .db
            .path()
            .context("this database is in memory, and cron could not open it")?;
        Ok(layout)
    }

    /// On the simple screen, which has no sites screen to scan from: find
    /// the sites once at start, when none are known. Only the database is
    /// written; nothing on the host changes until an apply.
    fn scan_if_simple_and_empty(&mut self) -> Result<()> {
        if self.dashboard.is_simple() && self.db.list_sites()?.is_empty() {
            self.start_site_action(crate::tui::nginx::SiteAction::Scan)?;
        }
        Ok(())
    }

    /// Reloads the screen on display and marks the rest stale, to be
    /// reloaded when they next come into view.
    ///
    /// This used to reload all four eagerly, on every single mutation, and
    /// most of that work was then thrown away unlooked at: toggling one
    /// category default on the Dashboard also made Firewall
    /// re-read the SSH log (a `journalctl` subprocess, on hosts without a
    /// readable `auth.log`) and Bot settings re-list every one of ~700
    /// bots. On a small server that was most of the pause after a
    /// keypress. Deferring is not a heuristic here — a screen's cached
    /// state cannot be observed until it is drawn.
    fn refresh(&mut self) -> Result<()> {
        self.stale = Screen::TABS
            .into_iter()
            .filter(|&screen| screen != self.screen)
            .collect();
        self.refresh_screen(self.screen)
    }

    /// Reloads the screen about to be drawn if anything invalidated it
    /// while it was off display. Driven from the draw loop rather than
    /// from each place that assigns `self.screen`, so it covers every
    /// route into a screen — the Tab keys, the `d`/`b`/`s`/`p` jumps,
    /// backing out of a detail view — without any of them remembering to.
    fn refresh_if_stale(&mut self) -> Result<()> {
        if self.stale.remove(&self.screen) {
            self.refresh_screen(self.screen)?;
        }
        Ok(())
    }

    /// Reloads one screen's state from the database. `Help` has none.
    fn refresh_screen(&mut self, screen: Screen) -> Result<()> {
        match screen {
            Screen::Dashboard => self.dashboard.refresh(&self.db),
            Screen::BotSettings => self.bot_settings.refresh(&self.db),
            Screen::Nginx => {
                self.nginx.refresh(&self.db)?;
                // Same shape as the SSH log read above: `refresh` no
                // longer reads every site's config file itself, so kick
                // off the check that does.
                self.start_site_status_check()
            }
            Screen::Firewall => {
                // Kicked off here rather than on entering the screen: this
                // is the one place every route to a visible SSH panel goes
                // through, and the freshness check makes repeating it
                // harmless.
                self.start_ssh_log_read();
                self.firewall
                    .refresh(&self.db, self.ssh_log_text.as_deref())
            }
            Screen::Blocks => self.blocks.refresh(&self.db),
            Screen::Help => Ok(()),
        }
    }

    /// Reloads every screen, for startup — where there is no "currently
    /// displayed" screen to privilege, and nothing on screen yet for the
    /// wait to interrupt.
    fn refresh_all(&mut self) -> Result<()> {
        self.stale.clear();
        for screen in Screen::TABS {
            self.refresh_screen(screen)?;
        }
        Ok(())
    }

    /// Runs the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        self.scan_if_simple_and_empty()?;
        while self.running {
            self.refresh_if_stale()?;
            self.note_message();
            terminal.draw(|frame| tui::render(&mut self, frame))?;
            let event = self.events.next().await?;
            self.handle_event(event)?;
        }
        Ok(())
    }

    /// Appends `message` to the log if it is new since the last frame.
    /// Called once per frame rather than from every place that sets a
    /// message, so the log needs no plumbing through the screens. The
    /// cap keeps a console left open for a month from growing without
    /// bound; nobody scrolls past the last hundred anyway.
    pub fn note_message(&mut self) {
        if self.message.is_some() && self.message != self.db_last_logged {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            self.log
                .push((now, self.message.clone().unwrap_or_default()));
            if self.log.len() > 100 {
                self.log.remove(0);
            }
            self.db_last_logged.clone_from(&self.message);
            self.message_in_footer = true;
        }
    }

    /// Dispatches a single event. Split out of `run` so tests can drive the
    /// event loop one event at a time (e.g. to apply a background cron
    /// job's result) without needing a real terminal.
    fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Tick => {
                self.check_keep_firewall();
                self.check_cron()?;
            }
            Event::Crossterm(crossterm::event::Event::Key(key_event))
                if key_event.kind == KeyEventKind::Press =>
            {
                self.handle_key_press(key_event)?;
            }
            Event::Crossterm(_) => {}
            Event::App(AppEvent::Quit) => self.running = false,
            Event::App(AppEvent::SourceUpdateFinished { source_id, result }) => {
                self.finish_source_update(source_id, result)?;
            }
            Event::App(AppEvent::CountrySelectFinished {
                country_code,
                result,
            }) => {
                self.finish_country_select(country_code, result)?;
            }
            Event::App(AppEvent::HostingAsnsFetched { asns, result }) => {
                self.finish_hosting_asn_fetch(&asns, result)?;
            }
            Event::App(AppEvent::ReputationFetchFinished { source_id, result }) => {
                self.finish_reputation_fetch(source_id, result)?;
            }
            Event::App(AppEvent::CronWorkDone { done }) => self.finish_cron_job(*done)?,
            Event::App(AppEvent::SshLogRead { text }) => self.finish_ssh_log_read(text)?,
            Event::App(AppEvent::NginxReloaded { result }) => self.finish_nginx_reload(result),
            Event::App(AppEvent::FirewallRendered { outcome }) => {
                self.finish_firewall_render(*outcome)?
            }
            Event::App(AppEvent::FirewallSettled { result }) => {
                self.finish_firewall_settle(result)?
            }
            Event::App(AppEvent::ApplyPreviewed { preview }) => self.finish_apply_preview(&preview),
            Event::App(AppEvent::SitesScanned { sites }) => self.finish_site_scan(sites)?,
            Event::App(AppEvent::SiteStatusesChecked { statuses }) => {
                self.finish_site_status_check(statuses)?
            }
            Event::App(AppEvent::SitesApplied { outcome }) => {
                // Unwrapped rather than cloned, since only one handler
                // ever sees a given event and the `Arc` is unshared by the
                // time it lands here. Falling back to a clone rather than
                // asserting that: `AppEvent` is `Clone`, so the day
                // someone copies an event for a log line, a panic here
                // would take down a TUI on a live server.
                let outcome =
                    std::sync::Arc::try_unwrap(outcome).unwrap_or_else(|shared| (*shared).clone());
                self.finish_site_apply(outcome)?;
            }
            Event::App(AppEvent::CrawlerRangesFetched { kind, result }) => {
                self.finish_crawler_ranges_refresh(kind, result)?
            }
        }
        Ok(())
    }
    // ---- background work: every `start_` has a `finish_` ----
    //
    // The shape is the same every time, and it is the reason the
    // TUI never blocks. A `start_` method does the `Db` reads on the main
    // thread, puts the slow half on a runtime or blocking-pool task, and
    // returns immediately; the task sends an `AppEvent`; the matching
    // `finish_` method applies the result back on the main thread, where
    // `Db` can be touched again (`rusqlite::Connection` is `Send` but not
    // `Sync`).
    //
    // They are named as pairs on purpose. Several of these used to read
    // `reload_nginx`, `read_ssh_log`, `check_site_statuses` — accurate
    // about the subject and wrong about the tense, since none of them does
    // the thing, they all only start it. `start_` says "this returns
    // before the work does", which is the invariant a reader needs.

    /// Starts a background fetch+parse of the bot-list source identified by
    /// `source_id` (resolved to a `botlist::SourceKind`, which knows how to
    /// fetch and parse its own format). Runs off the main thread because
    /// `Db`'s connection isn't `Sync` — the spawned task only fetches and
    /// parses; storing the result happens back on the main thread in
    /// `finish_source_update`.
    /// Assembles the per-address detail the Firewall screen
    /// asked for, and hands it back to that screen.
    ///
    /// Synchronous, unlike its `start_`/`finish_` neighbours, because it
    /// touches nothing slow: the SSH log is already read and in memory,
    /// and the rest is a database scan the surrounding screen already does
    /// per render. The username breakdown is computed here, for this one
    /// address, rather than for every address on every refresh — which
    /// measured 138ms on a 120,000-line auth.log, paid whether or not
    /// anyone ever pressed `i`.
    fn inspect_address(&mut self, address: &str) -> Result<()> {
        let usernames = self
            .ssh_log_text
            .as_deref()
            .map(|text| crate::sshlog::failed_attempt_usernames_for(text, address))
            .unwrap_or_default();
        let status = self.firewall.status_of(address);
        let detail = crate::ipdetail::IpDetail::load(&self.db, address, status, usernames)?;
        self.firewall.show_detail(detail);
        Ok(())
    }

    fn start_source_update(&mut self, source_id: String) {
        self.message = Some(format!("Updating {}…", source_display_name(&source_id)));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .with_context(|| format!("unknown bot-list source: {source_id}"))?;
                let raw = kind.fetch().await?;
                parse_off_thread(move || kind.parse_counted(&raw)).await
            }
            .await
            .map_err(|err| err.to_string());
            let _ = sender.send(Event::App(AppEvent::SourceUpdateFinished {
                source_id,
                result,
            }));
        });
    }

    /// Stores the fetched bots (on success) and reports the outcome, run
    /// back on the main thread once the background fetch in
    /// `start_source_update` completes.
    fn finish_source_update(
        &mut self,
        source_id: String,
        result: Result<botlist::Parsed, String>,
    ) -> Result<()> {
        let name = source_display_name(&source_id);
        match result {
            Ok(parsed) => {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .expect("source_id always came from a known SourceKind::id()");
                let count = botlist::store(&self.db, kind, &parsed.bots)?;
                self.message = Some(match botlist::left_out_note(parsed.skipped) {
                    None => format!("Stored {count} bot(s) from {name}"),
                    Some(note) => format!("Stored {count} bot(s) from {name}; {note}"),
                });
                self.refresh()?;
            }
            Err(err) => {
                self.message = Some(format!("Failed to update {name}: {err}"));
            }
        }
        Ok(())
    }

    /// Starts a background fetch of `country_code`'s IP ranges, spawned from
    /// the Dashboard's "add a country" popup for a country that isn't
    /// fetched yet. Only fetches and parses on the spawned task, same
    /// reason as `start_source_update`: storing (and adding the country to
    /// the geo selection) happens back on the main thread in
    /// `finish_country_select`.
    fn start_country_select(&mut self, country_code: String) {
        self.message = Some(format!(
            "Fetching IP ranges for {}…",
            country_code.to_uppercase()
        ));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let raw = ipranges::fetch_country(&country_code).await?;
                Ok(ipranges::parse_zone_file(&raw))
            }
            .await
            .map_err(|err: anyhow::Error| err.to_string());
            let _ = sender.send(Event::App(AppEvent::CountrySelectFinished {
                country_code,
                result,
            }));
        });
    }

    /// Starts a background download of one reputation/cloud-provider feed
    /// that the Dashboard just switched on but has never fetched. Only the
    /// fetch and parse run off-thread; storing happens back on the main
    /// thread in [`Self::finish_reputation_fetch`], the same
    /// `Db`-isn't-`Sync` split every other background task here uses.
    fn start_reputation_fetch(&mut self, source_id: String) {
        use crate::ipranges::reputation::ReputationSourceKind;

        let name = ReputationSourceKind::from_id(&source_id)
            .map(|k| k.name().to_string())
            .unwrap_or_else(|| source_id.clone());
        self.message = Some(format!("Fetching {name}…"));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let kind = ReputationSourceKind::from_id(&source_id)
                    .with_context(|| format!("unknown reputation source: {source_id}"))?;
                let raw = kind.fetch().await?;
                parse_off_thread(move || kind.parse(&raw)).await
            }
            .await
            .map_err(|err: anyhow::Error| err.to_string());
            let _ = sender.send(Event::App(AppEvent::ReputationFetchFinished {
                source_id,
                result,
            }));
        });
    }

    /// Stores a completed reputation-feed download. The source was already
    /// switched on before the fetch started (that's what triggered it), so
    /// a failure here leaves a feed that's enabled with nothing in it —
    /// which is inert rather than wrong, and the message says so. Turning
    /// it back off on failure would silently undo an explicit choice for a
    /// reason (a transient network error) that may not recur.
    fn finish_reputation_fetch(
        &mut self,
        source_id: String,
        result: Result<Vec<String>, String>,
    ) -> Result<()> {
        use crate::ipranges::reputation::ReputationSourceKind;

        let name = ReputationSourceKind::from_id(&source_id)
            .map(|k| k.name().to_string())
            .unwrap_or_else(|| source_id.clone());
        match result {
            Ok(cidrs) if cidrs.is_empty() => {
                // Same guard as `reputation::update`: an empty parse almost
                // always means the upstream format moved, and storing it
                // would wipe whatever was there before.
                self.message = Some(format!(
                    "{name} returned no usable addresses — upstream format may have changed"
                ));
            }
            // A store failure is a message, not a `?`: storing now refuses
            // a fetch with nothing usable in it, and a bad feed must not be
            // able to take the TUI down with it.
            Ok(cidrs) => match self.db.replace_reputation_ranges(&source_id, &cidrs) {
                Ok(count) => {
                    self.message = Some(format!(
                        "{name}: {count} range(s) stored — apply (a) to enforce them"
                    ));
                }
                Err(err) => self.message = Some(format!("{name}: {err}")),
            },
            Err(err) => {
                self.message = Some(format!("{name} update failed: {err}"));
            }
        }
        self.refresh()?;
        Ok(())
    }

    /// Starts one download of the ASN table for hosting providers the
    /// Dashboard just chose but has no ranges for. Only the download and
    /// the unpacking run off-thread, and only the chosen ASNs' lines come
    /// back; storing them is [`Self::finish_hosting_asn_fetch`]'s, on the
    /// main thread, as for every other feed.
    fn start_hosting_asn_fetch(&mut self, asns: Vec<u32>) {
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = ipranges::hosting::fetch(&asns)
                .await
                .map_err(|err| format!("{err:#}"));
            let _ = sender.send(Event::App(AppEvent::HostingAsnsFetched { asns, result }));
        });
    }

    /// Stores what [`Self::start_hosting_asn_fetch`] downloaded. A failure
    /// leaves the providers chosen with nothing in them, which blocks
    /// nothing, and says so; the weekly update tries again, as `status`
    /// reminds.
    fn finish_hosting_asn_fetch(
        &mut self,
        asns: &[u32],
        result: Result<String, String>,
    ) -> Result<()> {
        self.message = Some(
            match result.and_then(|lines| {
                ipranges::hosting::store(&self.db, asns, &lines).map_err(|err| format!("{err:#}"))
            }) {
                Ok(stored) if stored.stored.is_empty() => {
                    format!(
                        "Hosting providers: nothing stored \u{2014} {}",
                        stored.summary()
                    )
                }
                Ok(stored) => format!(
                    "Hosting providers: {} \u{2014} apply (a) to enforce them",
                    stored.summary()
                ),
                Err(err) => format!("Hosting providers: download failed: {err}"),
            },
        );
        self.refresh()
    }

    /// Stores the fetched CIDRs (on success) and adds the country to the
    /// geo selection — this completes the intent behind the Dashboard
    /// action that started this fetch, which was always "add this
    /// country", not just "fetch its ranges". Run back on the main thread
    /// once `start_country_select`'s background fetch completes. The
    /// message says "Blocked"/"Allowed" depending on the *current* geo
    /// mode, same mode-relative wording `Dashboard` already uses for the
    /// synchronous (already-fetched) path.
    fn finish_country_select(
        &mut self,
        country_code: String,
        result: Result<Vec<String>, String>,
    ) -> Result<()> {
        let label = country_code.to_uppercase();
        match result {
            Ok(cidrs) => {
                // Same reasoning as `finish_reputation_fetch`: a country
                // zone file that came back unusable is reported, and the
                // country is not selected on the strength of ranges that
                // were never stored.
                let count = match self.db.replace_country_ranges(&country_code, &cidrs) {
                    Ok(count) => count,
                    Err(err) => {
                        self.message = Some(format!("{label}: {err}"));
                        self.refresh()?;
                        return Ok(());
                    }
                };
                self.db.set_country_selected(&country_code, true)?;
                let verb = match self.db.get_geo_mode()? {
                    crate::db::GeoMode::Blocklist => "Blocked",
                    crate::db::GeoMode::Allowlist => "Allowed",
                };
                self.message = Some(format!("{verb} {label} ({count} range(s))"));
                self.refresh()?;
            }
            Err(err) => {
                self.message = Some(format!("Failed to fetch IP ranges for {label}: {err}"));
            }
        }
        Ok(())
    }

    /// The internal cron's tick handler (see `crate::cron`'s module docs
    /// for the overall design): throttled against `Event::Tick`'s 30fps
    /// rate via [`CRON_CHECK_INTERVAL`], starts whichever jobs are
    /// currently due. Never surfaces a `Result` error out of a single job
    /// to the user as a hard failure — a background job failing (e.g. the
    /// SSH log being unreadable) is recorded as that job's own summary, not
    /// something that should interrupt the TUI.
    fn check_cron(&mut self) -> Result<()> {
        if self.last_cron_check.elapsed() < CRON_CHECK_INTERVAL {
            return Ok(());
        }
        self.last_cron_check = std::time::Instant::now();

        let due = crate::cron::due_jobs(&self.db)?;
        if due.is_empty() {
            return Ok(());
        }
        for task in crate::cron::tasks(due) {
            self.start_cron_job(task)?;
        }
        self.refresh()?;
        Ok(())
    }

    /// Starts one of the schedule's tasks through [`crate::cron::start`],
    /// the same dispatch `tick` uses: the `Db` half here, the slow half on
    /// a task of its own, and [`Self::finish_cron_job`] back here when it
    /// returns.
    ///
    /// A task that would run beside the same work already out waits for
    /// the next check instead (see [`Self::cron_job_waits`]). `due_jobs`
    /// cannot say so itself: a job's `last_run` does not move until it
    /// finishes.
    fn start_cron_job(&mut self, task: crate::cron::Task) -> Result<()> {
        if self.cron_job_waits(&task) {
            return Ok(());
        }
        let host = self.host().unwrap_or_default();
        let settings = crate::cron::Settings {
            host: &host,
            ssh_log: self.ssh_log.as_deref(),
            // `None` in real use, so the path follows the stored backend:
            // an nftables render lands in `.nft` and an iptables one in
            // `.sh`.
            firewall_out: self.firewall_out.as_deref(),
            for_real: self.apply_firewall,
        };
        match crate::cron::start(&self.db, &task, &settings) {
            Ok(next) => self.carry_on_cron_job(next),
            Err(err) => {
                self.message = Some(match task {
                    crate::cron::Task::LogPass(_) => {
                        format!("The scheduled log scan could not start: {err:#}")
                    }
                    crate::cron::Task::Job(job) => {
                        format!("{} (scheduled) could not start: {err:#}", job.label())
                    }
                });
                Ok(())
            }
        }
    }

    /// Whether `task` has to wait for work this process already has out:
    ///
    /// - the same job, which would only do the same thing twice;
    /// - any log pass, for a log pass. One pass at a time: this used to
    ///   start one read per job, all at once, so a fresh start ran a dozen
    ///   full reads of the access log together, 2.9 GB of memory for a
    ///   200 MB log. The pass a due job would have joined is reading the
    ///   same lines anyway;
    /// - any download, `u`'s included, for a download. The lease (see
    ///   [`crate::refresh::Lease`]) would refuse it too; this says so
    ///   before asking the database.
    fn cron_job_waits(&self, task: &crate::cron::Task) -> bool {
        use crate::cron::{is_download, is_log_job};
        let out: Vec<CronJob> = self
            .jobs_in_flight
            .iter()
            .filter_map(|job| match job {
                Job::Cron(job) => Some(*job),
                Job::UpdateEverything => Some(CronJob::UpdateEverything),
                _ => None,
            })
            .collect();
        task.jobs().iter().any(|&wanted| {
            out.iter().any(|&out| {
                out == wanted
                    || (is_log_job(out) && is_log_job(wanted))
                    || (is_download(out) && is_download(wanted))
            })
        })
    }

    /// Does what [`crate::cron::start`] or [`crate::cron::finish`] said
    /// comes next: put the slow half on a task of its own, or start the
    /// site apply.
    fn carry_on_cron_job(&mut self, next: crate::cron::Next) -> Result<()> {
        let work = match next {
            crate::cron::Next::Ran(_) | crate::cron::Next::Waiting => return Ok(()),
            crate::cron::Next::ApplySites => return self.start_cron_apply_nginx(),
            crate::cron::Next::Work(work) => work,
        };
        if let Some(progress) = work.progress() {
            self.message = Some(progress);
        }
        let by_hand = work.by_hand();
        for job in work.jobs() {
            self.jobs_in_flight.insert(cron_job_key(job, by_hand));
        }
        let sender = self.events.sender();
        // A runtime task rather than the blocking pool: a download is
        // `async` all the way down, and `Work::run` puts the read of a log
        // and the probe of the host on the blocking pool itself.
        tokio::spawn(async move {
            let done = work.run().await;
            let _ = sender.send(Event::App(AppEvent::CronWorkDone {
                done: Box::new(done),
            }));
        });
        Ok(())
    }

    /// Stores what a scheduled job's slow half found, through
    /// [`crate::cron::finish`], and carries on with whatever comes next:
    /// for a download, the next list.
    ///
    /// The weekly download says nothing on the message line; `u`'s says
    /// what it did, since someone asked.
    fn finish_cron_job(&mut self, done: crate::cron::Done) -> Result<()> {
        let by_hand = done.by_hand();
        for job in done.jobs() {
            self.jobs_in_flight.remove(&cron_job_key(job, by_hand));
        }
        let next = crate::cron::finish(&self.db, done)?;
        if let (true, crate::cron::Next::Ran(ran)) = (by_hand, &next) {
            if let Some((_, summary)) = ran.last() {
                self.message = Some(summary.clone());
            }
        }
        self.carry_on_cron_job(next)?;
        self.refresh()
    }

    /// The internal cron's auto-apply, with the switch on: in the TUI the
    /// same work the operator's own "Apply everything" does — so it is
    /// started the same way rather than through `cron::apply_sites`.
    ///
    /// That function takes a `&Db` and does the whole job inline, which is
    /// right for `tick` (which has nothing to redraw) and wrong here: `apply_all_sites` walks the config root and the
    /// reload shells out to `nginx -t` and `systemctl`, which is seconds
    /// with nothing redrawing. `start_site_action` already splits that the
    /// way every other background job here does — the `Db` reads happen on
    /// this thread and produce an `ApplyPlan`, the file writes happen on
    /// the blocking pool — and `finish_site_apply` already chains the
    /// reload, gated by the `reload_nginx_for_real` flag. Reimplementing any of that would mean a
    /// second copy of the plan/run split.
    ///
    /// The switch itself is read in `cron::start`, before this, so a host
    /// with it off does no work at all.
    fn start_cron_apply_nginx(&mut self) -> Result<()> {
        self.cron_apply_nginx = true;
        self.start_site_action(crate::tui::nginx::SiteAction::ApplyAll)?;
        if !self.jobs_in_flight.contains(&Job::ApplySites) {
            // Refused before it started — an apply already running, or a
            // plan that could not be built. No `SitesApplied` event is
            // coming, so the flag has to come back down here or the next
            // apply the *operator* asks for would be recorded as this
            // job's run. Same reasoning as `start_apply_everything`'s own
            // did-it-start check.
            self.cron_apply_nginx = false;
            crate::cron::record_run(
                &self.db,
                CronJob::ApplyNginx,
                "an apply was already running",
            );
        }
        Ok(())
    }

    /// Works out each site's UP TO DATE / STALE tag in the background.
    ///
    /// One config file read and one block re-render per site, which used
    /// to happen inside `Nginx::refresh` — so every change to
    /// anything on that screen paid for all of them before redrawing. The
    /// `Db` half (each site's resolved `BlockConfig`) stays here.
    fn start_site_status_check(&mut self) -> Result<()> {
        if self.jobs_in_flight.contains(&Job::CheckSiteStatuses) {
            self.site_statuses_pending = true;
            return Ok(());
        }
        let plan = self.nginx.plan_status_check(&self.db)?;
        if plan.is_empty() {
            // No sites, so nothing to read and nothing to wait for. Said
            // explicitly because an empty check would otherwise leave the
            // tags reading "checking" forever.
            self.nginx.finish_status_check(Vec::new());
            return Ok(());
        }
        let (server, root) = (self.nginx.server(), self.nginx.root().to_path_buf());
        self.jobs_in_flight.insert(Job::CheckSiteStatuses);
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let statuses = crate::tui::nginx::run_status_check(server, &plan, &root);
            let _ = sender.send(Event::App(AppEvent::SiteStatusesChecked { statuses }));
        });
        Ok(())
    }

    /// Adopts a finished background status check, and starts another if
    /// something changed while it was out.
    fn finish_site_status_check(
        &mut self,
        statuses: Vec<crate::webserver::SiteApplyStatus>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::CheckSiteStatuses);
        self.nginx.finish_status_check(statuses);
        if std::mem::take(&mut self.site_statuses_pending) {
            self.start_site_status_check()?;
        }
        Ok(())
    }

    /// Starts one of the NGINX screen's filesystem actions in the background.
    ///
    /// The `Db` half happens here — a scan needs the root, an apply needs
    /// every affected site's resolved `BlockConfig` — and the filesystem
    /// half goes to the blocking pool. A scan walks the whole config root;
    /// an apply reads and rewrites one config file per site, plus the
    /// generated `robots.txt` and rate-limit zone. Neither is fast on a
    /// small server, and both used to run inside the keypress.
    ///
    /// A second request while one is out is reported rather than dropped:
    /// like a firewall render, these are only reachable by confirming a
    /// popup, so someone is watching and can press it again.
    fn start_site_action(&mut self, action: crate::tui::nginx::SiteAction) -> Result<()> {
        use crate::tui::nginx::SiteAction;

        let job = match action {
            SiteAction::Scan => Job::ScanSites,
            SiteAction::Apply(_) | SiteAction::ApplyAll => Job::ApplySites,
        };
        if self.jobs_in_flight.contains(&job) {
            self.message = Some(format!("Already {}.", job.label(self.nginx.server())));
            return Ok(());
        }

        let sender = self.events.sender();
        match action {
            SiteAction::Scan => {
                self.jobs_in_flight.insert(job);
                let (server, root) = (self.nginx.server(), self.nginx.root().to_path_buf());
                tokio::task::spawn_blocking(move || {
                    let sites = server.discover_sites(&root).map_err(|err| err.to_string());
                    let _ = sender.send(Event::App(AppEvent::SitesScanned { sites }));
                });
            }
            SiteAction::Apply(_) | SiteAction::ApplyAll => {
                // The test runs inside the apply, so a config NGINX rejects
                // is put back before anything can reload it — resolved
                // here, like every other `Db` read the apply needs.
                let validate = self
                    .reload_nginx_for_real
                    .then(|| self.host().and_then(|host| host.commands()))
                    .transpose();
                let plan = match (self.nginx.plan_apply(&self.db, action), validate) {
                    (Ok(plan), Ok(validate)) => crate::tui::nginx::ApplyPlan { validate, ..plan },
                    (Err(err), _) | (_, Err(err)) => {
                        self.message = Some(format!("Apply failed: {err}"));
                        return Ok(());
                    }
                };
                self.jobs_in_flight.insert(job);
                tokio::task::spawn_blocking(move || {
                    let outcome = crate::tui::nginx::run_apply(plan);
                    let _ = sender.send(Event::App(AppEvent::SitesApplied {
                        outcome: std::sync::Arc::new(outcome),
                    }));
                });
            }
        }
        Ok(())
    }

    /// Records a finished background scan: the `Db` writes it implies, and
    /// the count to report.
    fn finish_site_scan(
        &mut self,
        sites: Result<Vec<webserver::DiscoveredSite>, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ScanSites);
        self.message = Some(self.nginx.finish_scan(&self.db, sites));
        self.refresh()
    }

    /// Records a finished background apply, and reloads NGINX if any file
    /// actually changed — the same condition the inline version used, just
    /// evaluated here rather than in the key handler.
    fn finish_site_apply(&mut self, outcome: crate::tui::nginx::ApplyOutcome) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ApplySites);
        let (message, changed_a_file) = self.nginx.finish_apply(outcome);
        if std::mem::take(&mut self.cron_apply_nginx) {
            crate::cron::record_run(&self.db, CronJob::ApplyNginx, &message);
        }
        self.message = Some(message);
        // Before the reload, so the status tags reflect the files that
        // were just written rather than waiting on `systemctl`.
        self.refresh()?;
        if changed_a_file {
            self.start_nginx_reload();
        }
        if self.apply_everything {
            self.start_everything_firewall();
        }
        Ok(())
    }

    /// Reloads NGINX in the background, after NGINX has written a
    /// config file.
    ///
    /// `nginx -t` parses every file in the install and `systemctl reload
    /// nginx` waits on the master process; together they are seconds on a
    /// small server, and they used to run inside the keypress that asked
    /// for them. No `Db` is involved, so the whole thing moves.
    ///
    /// Only one reload runs at a time — holding Enter on "apply" would
    /// otherwise start one per repeat, all racing on the same NGINX
    /// master. A request that arrives while one is out is *coalesced*, not
    /// dropped: this is a write-then-act pair, and the act has to happen
    /// at least once after the last write. Dropping it would mean applying
    /// a second site while the first site's reload was still running and
    /// having NGINX never pick the second one up — "I applied it and
    /// nothing happened", which is worse than the pause this replaced.
    fn start_nginx_reload(&mut self) {
        if !self.reload_nginx_for_real {
            return;
        }
        if !self.jobs_in_flight.insert(Job::ReloadNginx) {
            self.reload_nginx_pending = true;
            return;
        }
        // Resolved here, on the main thread, because the spawned half
        // cannot reach a `Db` — the same split every other `start_*` makes.
        // A malformed stored command surfaces as the reload failing, which
        // is where the admin is already looking.
        let commands = self
            .host()
            .and_then(|host| Ok((host.web_server(), host.commands()?)));
        let (server, commands) = match commands {
            Ok(commands) => commands,
            Err(err) => {
                self.jobs_in_flight.remove(&Job::ReloadNginx);
                self.message = Some(format!(
                    "failed to reload {}: {err}",
                    self.nginx.server().label()
                ));
                return;
            }
        };
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let result = webserver::reload_with(server, &commands).map_err(|err| err.to_string());
            let _ = sender.send(Event::App(AppEvent::NginxReloaded { result }));
        });
    }

    /// Reports how the background NGINX reload went. A failure is appended
    /// to whatever the apply itself said rather than replacing it: the
    /// files really were written, and that is worth knowing alongside the
    /// news that NGINX is still serving the old ones.
    fn finish_nginx_reload(&mut self, result: Result<(), String>) {
        self.jobs_in_flight.remove(&Job::ReloadNginx);
        if let Err(err) = result {
            let applied = self.message.take().unwrap_or_default();
            self.message = Some(format!(
                "{applied} — failed to reload {}: {err}",
                self.nginx.server().label()
            ));
        }
        if std::mem::take(&mut self.reload_nginx_pending) {
            self.start_nginx_reload();
        }
    }

    /// The host settings, read now: see [`App::host_conf`].
    fn host(&self) -> Result<crate::hostconf::HostConf> {
        crate::hostconf::HostConf::load_from(&self.host_conf)
    }

    /// Reads the SSH log into [`App::ssh_log_text`], in the background, if
    /// the copy on hand has gone stale ([`SSH_LOG_MAX_AGE`]) and no read is
    /// already out.
    ///
    /// The read itself is what has to move off the event loop: with no
    /// `--ssh-log` override and no readable `auth.log`, resolving the log
    /// means a `journalctl` subprocess. Doing that inline, on every reload
    /// of Firewall, is what made this screen the slowest in the
    /// TUI. Parsing the text into rows stays on the main thread with every
    /// other `Db` access (`Db` isn't `Sync`) — it is an in-memory line
    /// scan, and moving it would buy nothing.
    fn start_ssh_log_read(&mut self) {
        let fresh_enough = self
            .ssh_log_read_at
            .is_some_and(|at| at.elapsed() < SSH_LOG_MAX_AGE);
        if fresh_enough || !self.jobs_in_flight.insert(Job::ReadSshLog) {
            return;
        }
        let sender = self.events.sender();
        // Through the stored paths, like every other reader of this log:
        // `set-log-paths --ssh-log` used to be ignored here.
        let source = self
            .host()
            .unwrap_or_default()
            .log_paths()
            .ssh(self.ssh_log.as_deref());
        tokio::task::spawn_blocking(move || {
            let text = match source.read(crate::sshlog::recent_since()) {
                crate::sshlog::LogSource::Found(text) => Some(text),
                crate::sshlog::LogSource::Unavailable => None,
            };
            let _ = sender.send(Event::App(AppEvent::SshLogRead { text }));
        });
    }

    /// Stores a background SSH-log read and rebuilds the SSH panel from it.
    ///
    /// Marks the read as done even when the log was unavailable, so a host
    /// with no readable log retries once every [`SSH_LOG_MAX_AGE`] rather
    /// than starting a fresh subprocess on every reload of the screen.
    fn finish_ssh_log_read(&mut self, text: Option<String>) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ReadSshLog);
        self.ssh_log_text = text;
        self.ssh_log_read_at = Some(std::time::Instant::now());
        if self.screen == Screen::Firewall {
            self.firewall
                .refresh(&self.db, self.ssh_log_text.as_deref())?;
        } else {
            self.stale.insert(Screen::Firewall);
        }
        Ok(())
    }

    /// Renders firewall rules through the one path every front-end uses
    /// (`firewall::prepare`/`execute`/`record`) — the allowlist/iptables
    /// guard, the lockout check and the policy on what it may refuse.
    /// `out_path` is the *applied* script; the render is written beside it
    /// and replaces it only when an apply succeeds. `apply`, from the
    /// render popup's "apply after writing" toggle
    /// (`Popup::RenderFirewall::apply_after_write`) or "Apply everything",
    /// runs the script once written — but only when `self.apply_firewall`
    /// is set (see that field's doc comment); when it isn't (tests), the
    /// outcome says so rather than claiming a subprocess it never ran.
    fn start_firewall_render(
        &mut self,
        backend: crate::firewall::FirewallBackend,
        out_path: String,
        force: bool,
        apply: bool,
    ) {
        if self.jobs_in_flight.contains(&Job::RenderFirewall) {
            // Said rather than silently dropped, and not coalesced: this
            // one is only reachable by confirming a popup, so there is
            // always someone watching who can press it again. Coalescing
            // would also mean deciding which of two `out_path`s wins.
            self.message = Some("A firewall render is already running.".to_string());
            return;
        }

        // Prepared here, on the main thread, because it reads the whole
        // rule set out of `Db` — which isn't `Sync`. What goes to the
        // background is everything after: the lockout check (a live SSH
        // log read, which is the slow part, and must never be
        // `App::ssh_log_text`, the cached copy Firewall draws from), the
        // write, and `nft -f`. The policy is `firewall::FirewallRun`'s,
        // shared with every other front-end.
        // Always confirm-or-revert: someone is at this terminal, and an
        // apply that cuts them off is what it is there for.
        let run = crate::firewall::FirewallRun::new(backend, out_path)
            .apply(apply)
            .for_real(self.apply_firewall)
            .force(force)
            .confirm(Some(self.confirm_timeout))
            .protect(self.session_client.clone());
        let prepared = match crate::firewall::prepare(&self.db, run) {
            Ok(prepared) => prepared,
            Err(err) => {
                self.message = Some(format!("Failed to render firewall rules: {err}"));
                return;
            }
        };

        self.jobs_in_flight.insert(Job::RenderFirewall);
        // Through the stored paths, like every other reader of this log.
        let ssh_log = self
            .host()
            .unwrap_or_default()
            .log_paths()
            .ssh(self.ssh_log.as_deref());
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let outcome =
                crate::firewall::execute(prepared, crate::firewall::SshLog::Read(&ssh_log));
            let _ = sender.send(Event::App(AppEvent::FirewallRendered {
                outcome: Box::new(outcome),
            }));
        });
    }

    /// Applies a finished background render: the message, and the rendered
    /// and applied signatures for what really was written and run. Those
    /// are what the Dashboard's script row compares against, and they are
    /// `Db` writes, so they wait for the main thread like every other one.
    fn finish_firewall_render(&mut self, outcome: crate::firewall::FirewallOutcome) -> Result<()> {
        self.jobs_in_flight.remove(&Job::RenderFirewall);
        crate::firewall::record(&self.db, &outcome)?;
        self.message = Some(firewall_message(&outcome));
        if let Some(pending) = outcome.pending() {
            let left = pending.seconds_left(now_secs()).max(0) as u64;
            self.keep_firewall = Some(tui::keep_firewall::KeepFirewall::new(
                pending.clone(),
                outcome.script.clone(),
                outcome.signature.clone(),
                std::time::Duration::from_secs(left),
            ));
        }
        // The signature the Dashboard's script row compares against has
        // just moved, so that row is stale wherever it is.
        self.refresh()
    }

    /// Reverts an apply nobody answered for in time. The timer outside
    /// this process fires at the same moment; whichever runs first
    /// settles it, and the other finds nothing to do.
    fn check_keep_firewall(&mut self) {
        if self
            .keep_firewall
            .as_ref()
            .is_some_and(|keep| keep.expired())
        {
            self.start_firewall_settle(crate::revert::Answer::NoAnswer);
        }
    }

    /// Keeps or reverts the apply waiting in [`Self::keep_firewall`], as
    /// `answer` says, on the blocking pool: a revert runs `nft -f`, and
    /// both wait for the apply lock. No `Db` is involved until
    /// [`Self::finish_firewall_settle`].
    fn start_firewall_settle(&mut self, answer: crate::revert::Answer) {
        let Some(keep) = &self.keep_firewall else {
            return;
        };
        if self.jobs_in_flight.contains(&Job::SettleFirewall) {
            return;
        }
        self.jobs_in_flight.insert(Job::SettleFirewall);
        let (pending, script) = (keep.pending.clone(), keep.script.clone());
        let tools = self.revert_tools.clone();
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let result = crate::revert::settle(&tools, &pending, &script, answer)
                .map_err(|err| format!("{err:#}"));
            let _ = sender.send(Event::App(AppEvent::FirewallSettled { result }));
        });
    }

    /// Closes the question and says how it ended. A kept apply is recorded
    /// as applied now, which the Dashboard's script row reads.
    fn finish_firewall_settle(
        &mut self,
        result: Result<crate::revert::Settled, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::SettleFirewall);
        let keep = self.keep_firewall.take();
        self.message = Some(match result {
            Ok(crate::revert::Settled::Kept(message)) => {
                if let Some(keep) = keep {
                    self.db.set_firewall_applied_signature(&keep.signature)?;
                }
                format!("{message}.")
            }
            Ok(settled) => format!("{}.", settled.message()),
            Err(err) => format!("Firewall: {err}"),
        });
        self.refresh()
    }

    /// Downloads every list this host uses, one source at a time — `u`,
    /// the TUI's half of what `stop-bots batch` does, through the same
    /// [`crate::refresh::plan`]. It is the weekly `UpdateEverything` job
    /// run by hand, so it runs as that job does, through
    /// [`crate::cron::download`] and [`Self::finish_cron_job`]; only the
    /// message line, which says what it is doing, is its own.
    ///
    /// One source failing is reported and the rest still run: these are
    /// eight third parties, and a transient failure at one of them is not
    /// a reason to leave the other seven stale.
    ///
    /// **One download at a time, across every stop-bots.** A run holds the
    /// download lease (see [`crate::refresh::Lease`]), so `u` while the
    /// weekly job, the crawler-range job or another process's download is
    /// out says so and fetches nothing, and the scheduled jobs wait for
    /// `u`'s run in the same way.
    fn start_update_everything(&mut self) -> Result<()> {
        if self.jobs_in_flight.contains(&Job::UpdateEverything)
            || self
                .jobs_in_flight
                .contains(&Job::Cron(CronJob::UpdateEverything))
        {
            self.message = Some("Already downloading every list.".to_string());
            return Ok(());
        }
        // Planning reads `Db`, so it happens here, on the main thread.
        match crate::refresh::begin(&self.db, now_secs(), false) {
            Ok(crate::refresh::Begin::Started(run)) => {
                let next = crate::cron::download(&self.db, run);
                self.carry_on_cron_job(next)
            }
            Ok(crate::refresh::Begin::Busy { since }) => {
                self.message = Some(crate::refresh::Claim::busy_message(since));
                Ok(())
            }
            Err(err) => {
                self.message = Some(format!("Could not start the download: {err:#}"));
                Ok(())
            }
        }
    }

    /// Downloads one crawler's published ranges — Enter on a row of the
    /// Dashboard's Crawler IP ranges panel, the TUI's `update-crawler-ranges`.
    ///
    /// Under the download lease, like `u`: while "update everything", the
    /// scheduled crawler job or another process's download is out it says
    /// so and fetches nothing, and they in turn wait for this one. It
    /// records no cron job — one source is not what the daily job means
    /// by "done".
    fn start_crawler_ranges_refresh(&mut self, kind: ipranges::IpRangeSourceKind) {
        if self.crawler_refresh_lease.is_some() {
            self.message = Some("Already downloading a crawler's ranges.".to_string());
            return;
        }
        let lease = match crate::refresh::claim(&self.db, now_secs()) {
            Ok(crate::refresh::Claim::Granted(lease)) => lease,
            Ok(crate::refresh::Claim::Busy { since }) => {
                self.message = Some(crate::refresh::Claim::busy_message(since));
                return;
            }
            Err(err) => {
                self.message = Some(format!("Could not start the download: {err:#}"));
                return;
            }
        };
        self.crawler_refresh_lease = Some(lease);
        self.jobs_in_flight.insert(Job::RefreshCrawlerRanges(kind));
        self.message = Some(format!("Downloading {}\u{2026}", kind.name()));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let source = crate::refresh::Source::CrawlerRanges(kind);
            let result = crate::refresh::fetch(&source)
                .await
                .map_err(|err| format!("{err:#}"));
            let _ = sender.send(Event::App(AppEvent::CrawlerRangesFetched { kind, result }));
        });
    }

    /// Stores what [`Self::start_crawler_ranges_refresh`] downloaded, says
    /// how it went and gives the lease back.
    fn finish_crawler_ranges_refresh(
        &mut self,
        kind: ipranges::IpRangeSourceKind,
        result: Result<String, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::RefreshCrawlerRanges(kind));
        let source = crate::refresh::Source::CrawlerRanges(kind);
        let outcome = result.and_then(|raw| {
            crate::refresh::store(&self.db, &source, &raw).map_err(|err| format!("{err:#}"))
        });
        if let Some(lease) = self.crawler_refresh_lease.take() {
            crate::refresh::release(&self.db, &lease)?;
        }
        self.message = Some(match outcome {
            Ok(summary) => format!("{}: {summary}.", kind.name()),
            Err(err) => format!("{} update failed: {err}", kind.name()),
        });
        self.refresh()
    }

    /// Works out what "Apply everything" would do, for the Dashboard to ask
    /// about before doing it: the site files that would change, the rules
    /// added and removed against the applied script, and the lockout
    /// guard's verdict — with the diffs, for `d`.
    ///
    /// The plans are the ones the apply itself would make, built here from
    /// `Db`; reading every site file and the SSH log happens on the
    /// blocking pool, like the apply's own writes. The firewall half is the
    /// same [`crate::firewall::FirewallRun`] as [`Self::start_everything_firewall`]'s,
    /// as a dry run, so the verdict shown is the one the apply will get
    /// unless something changes in between.
    fn start_apply_preview(&mut self) {
        if self.jobs_in_flight.contains(&Job::PreviewApply) {
            return;
        }
        let nginx = self
            .nginx
            .plan_apply(&self.db, crate::tui::nginx::SiteAction::ApplyAll);
        let firewall = crate::firewall::stored_backend(&self.db).and_then(|backend| {
            let run = crate::firewall::FirewallRun::new(
                backend,
                crate::firewall::output_path(self.firewall_out.as_deref(), backend),
            )
            .apply(true)
            .for_real(self.apply_firewall)
            .dry_run(true)
            .protect(self.session_client.clone());
            crate::firewall::prepare(&self.db, run)
        });

        self.jobs_in_flight.insert(Job::PreviewApply);
        let ssh_log = self
            .host()
            .unwrap_or_default()
            .log_paths()
            .ssh(self.ssh_log.as_deref());
        let server = self.nginx.server();
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let preview = crate::preview::ApplyPreview {
                server,
                nginx: nginx
                    .map(|plan| crate::tui::nginx::preview_apply(&plan))
                    .map_err(|err| format!("{err:#}")),
                firewall: firewall
                    .map(|prepared| {
                        crate::firewall::execute(prepared, crate::firewall::SshLog::Read(&ssh_log))
                    })
                    .map_err(|err| format!("{err:#}")),
            };
            let _ = sender.send(Event::App(AppEvent::ApplyPreviewed {
                preview: Box::new(preview),
            }));
        });
    }

    /// Puts the preview in front of the operator, on the Dashboard, where
    /// Enter confirms it (and starts [`Self::start_apply_everything`]) and
    /// Esc leaves everything as it was.
    fn finish_apply_preview(&mut self, preview: &crate::preview::ApplyPreview) {
        self.jobs_in_flight.remove(&Job::PreviewApply);
        self.screen = Screen::Dashboard;
        self.dashboard.show_apply_preview(preview);
    }

    /// Writes and enforces both planes: the NGINX config, then the
    /// firewall — the TUI's "Apply everything", once its preview has been
    /// confirmed.
    ///
    /// The two are independent, same as `batch --apply`: whichever fails,
    /// the other still gets its turn, because a half-applied host is
    /// better than one where an NGINX syntax error also left the firewall
    /// stale. The *writes* are sequenced rather than concurrent only
    /// because the TUI has one message line and two jobs finishing at once
    /// would overwrite each other's answer. The NGINX reload that follows
    /// the site apply does overlap the firewall render — both are started
    /// from `finish_site_apply` — which is fine, because neither reads
    /// what the other writes.
    fn start_apply_everything(&mut self) -> Result<()> {
        if self.jobs_in_flight.contains(&Job::ApplySites)
            || self.jobs_in_flight.contains(&Job::RenderFirewall)
        {
            self.message = Some("An apply is already running.".to_string());
            return Ok(());
        }

        self.apply_everything = true;
        self.start_site_action(crate::tui::nginx::SiteAction::ApplyAll)?;
        if !self.jobs_in_flight.contains(&Job::ApplySites) {
            // The NGINX half refused before it started, so no
            // `SitesApplied` event is coming to chain off. The firewall
            // half is independent and still gets its turn.
            self.start_everything_firewall();
        }
        Ok(())
    }

    /// The firewall half of "Apply everything": the stored backend, the
    /// path that backend implies, and the same anti-lockout guard every
    /// other render goes through.
    fn start_everything_firewall(&mut self) {
        self.apply_everything = false;
        let backend = match crate::firewall::stored_backend(&self.db) {
            Ok(backend) => backend,
            Err(err) => {
                self.message = Some(format!("Failed to read the firewall backend: {err}"));
                return;
            }
        };
        let out = crate::firewall::output_path(self.firewall_out.as_deref(), backend);
        // `force: false`: one key must not be able to talk its way past
        // the lockout check. Someone who knows the log is unreadable uses
        // the render popup, which asks.
        self.start_firewall_render(backend, out.display().to_string(), false, true);
    }

    /// A key press, with what it does to the footer's message: any key
    /// puts the key hints back, and a message the key itself produced
    /// shows in their place — even one that reads the same as the last,
    /// which is still news that the action ran again.
    fn handle_key_press(&mut self, key: KeyEvent) -> Result<()> {
        self.message_in_footer = false;
        let previous = self.message.take();
        let result = self.handle_key_event(key);
        if self.message.is_none() {
            self.message = previous;
        } else {
            // Logged again even if the text repeats the last message.
            self.db_last_logged = None;
        }
        result
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.events.send(AppEvent::Quit);
            return Ok(());
        }

        if self.keep_firewall.is_some() {
            if let Some(answer) = tui::keep_firewall::KeepFirewall::answer(key) {
                self.start_firewall_settle(answer);
            }
            return Ok(());
        }

        if let Some(palette) = &mut self.palette {
            match key.code {
                KeyCode::Esc => self.palette = None,
                KeyCode::Enter => {
                    let action = palette.selected_action();
                    self.palette = None;
                    if let Some(action) = action {
                        self.run_command(action)?;
                    }
                }
                other => {
                    palette.handle_key(other);
                }
            }
            return Ok(());
        }

        if let Some(explain) = &mut self.explain {
            match explain.handle_key(key.code) {
                tui::explain::ExplainKey::Stay => {}
                tui::explain::ExplainKey::Close => self.explain = None,
                tui::explain::ExplainKey::AllKeys => {
                    self.explain = None;
                    self.before_help = self.screen;
                    self.screen = Screen::Help;
                }
            }
            return Ok(());
        }

        if self.screen == Screen::Help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q' | '?')) {
                self.screen = self.before_help;
            }
            return Ok(());
        }

        let outcome = match self.screen {
            Screen::Dashboard => self
                .dashboard
                .handle_key(key, &self.db, &mut self.message)?,
            Screen::BotSettings => {
                self.bot_settings
                    .handle_key(key, &self.db, &mut self.message)?
            }
            Screen::Nginx => self.nginx.handle_key(key, &self.db, &mut self.message)?,
            Screen::Firewall => self.firewall.handle_key(key, &self.db, &mut self.message)?,
            Screen::Blocks => self.blocks.handle_key(key, &self.db, &mut self.message)?,
            Screen::Help => unreachable!("handled above"),
        };
        match outcome {
            KeyOutcome::Consumed => return Ok(()),
            KeyOutcome::Mutated => {
                // A screen wrote to the database; reload every screen so
                // none of them (e.g. the Dashboard's summary) goes stale.
                self.refresh()?;
                return Ok(());
            }
            KeyOutcome::Back => {
                self.screen = Screen::Dashboard;
                return Ok(());
            }
            KeyOutcome::InspectAddress(address) => {
                self.inspect_address(&address)?;
                return Ok(());
            }
            KeyOutcome::UpdateSource(name) => {
                self.start_source_update(name);
                return Ok(());
            }
            KeyOutcome::SelectCountry(country_code) => {
                self.start_country_select(country_code);
                return Ok(());
            }
            KeyOutcome::FetchReputationSource(source_id) => {
                self.start_reputation_fetch(source_id);
                return Ok(());
            }
            KeyOutcome::UpdateEgressFeeds => {
                self.refresh()?;
                self.start_cron_job(crate::cron::Task::Job(
                    crate::cron::CronJob::UpdateEgressFeeds,
                ))?;
                return Ok(());
            }
            KeyOutcome::FetchHostingAsns(asns) => {
                // The selection itself changed before the download.
                self.refresh()?;
                self.start_hosting_asn_fetch(asns);
                return Ok(());
            }
            KeyOutcome::RenderFirewall {
                backend,
                out_path,
                force,
                apply,
            } => {
                // Remembered, as `set-firewall-backend` does, so that
                // "Apply everything", the cron and `batch` render for the
                // backend the operator last chose rather than the other.
                crate::firewall::store_backend(&self.db, backend)?;
                // The refresh that used to follow this line now happens
                // in `finish_firewall_render`, once the signature the
                // Dashboard compares against has actually been written.
                self.start_firewall_render(backend, out_path, force, apply);
                return Ok(());
            }
            KeyOutcome::ReloadNginx => {
                self.refresh()?;
                self.start_nginx_reload();
                return Ok(());
            }
            KeyOutcome::SiteAction(action) => {
                self.start_site_action(action)?;
                return Ok(());
            }
            KeyOutcome::UpdateEverything => {
                return self.start_update_everything();
            }
            KeyOutcome::RefreshCrawlerRanges(kind) => {
                self.start_crawler_ranges_refresh(kind);
                return Ok(());
            }
            KeyOutcome::PreviewApplyEverything => {
                self.start_apply_preview();
                return Ok(());
            }
            KeyOutcome::ApplyEverything => {
                self.start_apply_everything()?;
                return Ok(());
            }
            KeyOutcome::ShowDetectors => {
                self.set_ui_mode(crate::db::UiMode::Advanced)?;
                self.dashboard.focus_detectors();
                self.message = Some(
                    "Every check, each with its own switch. v goes back to the simple screen."
                        .to_string(),
                );
                return Ok(());
            }
            KeyOutcome::KeepRunning(on) => {
                self.set_keep_running(on)?;
                return Ok(());
            }
            KeyOutcome::RereadLogs => {
                self.ssh_log_read_at = None;
                self.start_ssh_log_read();
                self.message = Some("Re-reading the SSH log\u{2026}".to_string());
                return Ok(());
            }
            KeyOutcome::Ignored => {}
        }

        match key.code {
            KeyCode::Char('q') if self.screen == Screen::Dashboard => {
                self.events.send(AppEvent::Quit);
            }
            // Esc closes every popup, the palette, a search and each other
            // screen, so the press after the last of those arrives here by
            // momentum. It used to quit, and with it stopped the schedule
            // on a host where only this screen runs it.
            KeyCode::Esc if self.screen == Screen::Dashboard => {
                self.message = Some("Nothing left to go back from. q quits.".to_string());
            }
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Dashboard,
            // `t` is the documented theme key; `c` stays as the alias it
            // used to be, for hands that learned it.
            KeyCode::Char('t' | 'c') => self.theme = self.theme.toggle(),
            // What the row under the cursor is; `?` again, from there,
            // is the full key reference.
            KeyCode::Char('?') => {
                self.explain = Some(tui::explain::Explain::new(self.explanation(), self.hints()));
            }
            KeyCode::Char(':') => self.palette = Some(tui::palette::Palette::new(self.commands())),
            // The simple screen, or every screen: see `tui::dashboard::simple`.
            KeyCode::Char('v') => {
                let mode = self.db.get_ui_mode()?.toggle();
                self.set_ui_mode(mode)?;
            }
            // Digits, as every tabbed terminal tool has them and as the tab
            // bar shows them; the mnemonic letters stay as aliases. The
            // simple mode has two tabs, and the keys for the others are
            // left alone there rather than leaving it.
            KeyCode::Char('d' | '1') => self.screen = Screen::Dashboard,
            KeyCode::Char('x' | '5') => self.screen = Screen::Blocks,
            KeyCode::Char('b' | '2' | 'f' | '3' | 'n' | '4') if self.dashboard.is_simple() => {
                self.message =
                    Some("That screen is one of the advanced ones: press v to see it.".to_string());
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Left | KeyCode::Char('h')
                if self.dashboard.is_simple() =>
            {
                self.screen = match self.screen {
                    Screen::Dashboard => Screen::Blocks,
                    _ => Screen::Dashboard,
                };
            }
            KeyCode::Char('b' | '2') => self.screen = Screen::BotSettings,
            KeyCode::Char('f' | '3') => self.screen = Screen::Firewall,
            KeyCode::Char('n' | '4') => self.screen = Screen::Nginx,
            // Left/Right and their vim h/l aliases cycle screens. Tab is
            // *not* among them any more: it always means "next panel on
            // this screen", so that it means one thing everywhere (it used
            // to switch screens on the two screens with one list and
            // panels on the two with several). All of these only reach
            // here when the active screen's own `handle_key` returned
            // `Ignored` for the key (see `KeyOutcome`'s doc comment), so a
            // search/text-entry focus that owns every `Char` already stops
            // 'h'/'l' and the digits from leaking through mid-search.
            KeyCode::Right | KeyCode::Char('l') => self.screen = self.screen.next(),
            KeyCode::Left | KeyCode::Char('h') => self.screen = self.screen.previous(),
            _ => {}
        }
        Ok(())
    }
}

impl App {
    /// Everything the command palette can do, in the order it lists them
    /// with an empty query: navigation, then the host-wide actions, then
    /// one row per detector saying which way it would flip.
    fn commands(&self) -> Vec<tui::palette::Command> {
        use tui::palette::{Action, Command};
        let key = |screen: Screen, c: char| Action::Key(screen, KeyCode::Char(c));
        let mut commands = vec![
            ("Go to Dashboard", "1", Action::Screen(Screen::Dashboard)),
            (
                "Go to Bot settings",
                "2",
                Action::Screen(Screen::BotSettings),
            ),
            ("Go to Firewall", "3", Action::Screen(Screen::Firewall)),
            ("Go to NGINX", "4", Action::Screen(Screen::Nginx)),
            (
                "Go to Blocks: every firewall rule and why",
                "5",
                Action::Screen(Screen::Blocks),
            ),
            ("Help: the key map", "?", Action::Screen(Screen::Help)),
            (
                "Update everything: download every list",
                "u",
                key(Screen::Dashboard, 'u'),
            ),
            (
                "Apply everything: NGINX, then the firewall",
                "a",
                key(Screen::Dashboard, 'a'),
            ),
            (
                "Write the firewall script",
                "F",
                key(Screen::Dashboard, 'F'),
            ),
            (
                "Geo mode: blocklist or allowlist",
                "m",
                key(Screen::Dashboard, 'm'),
            ),
            ("Search bots", "/", key(Screen::BotSettings, '/')),
            ("Re-read the SSH log", "R", key(Screen::Firewall, 'R')),
            (
                "Trust the selected row: never block it",
                "T",
                key(Screen::Firewall, 'T'),
            ),
            (
                "Unblock all from the filtered source",
                "U",
                key(Screen::Blocks, 'U'),
            ),
            ("Rescan for NGINX sites", "r", key(Screen::Nginx, 'r')),
            ("Apply blocking to every site", "A", key(Screen::Nginx, 'A')),
            ("Toggle light/dark theme", "t", Action::Theme),
            (
                if self.dashboard.is_simple() {
                    "Show every screen and setting"
                } else {
                    "Go back to the simple screen"
                },
                "v",
                Action::UiMode,
            ),
            ("Quit", "q", Action::Quit),
        ]
        .into_iter()
        // The rows that name the sites screen name it as its tab does: for
        // the server the host runs.
        .map(|(label, hint, action)| Command {
            label: label.replace("NGINX", self.nginx.server().label()),
            hint,
            action,
        })
        .collect::<Vec<_>>();
        for detector in crate::protection::Detector::ALL {
            let on = detector.is_enabled(&self.db).unwrap_or(false);
            commands.push(Command {
                label: format!(
                    "Turn {} {}",
                    if on { "off" } else { "on" },
                    detector.spec().label
                ),
                hint: "",
                action: Action::Detector(detector, !on),
            });
        }
        commands
    }

    /// Runs a palette command. `Key` goes through [`Self::handle_key_event`]
    /// as if the key had been pressed on that screen, so a command can
    /// never do something its key cannot — same popups, same guards.
    fn run_command(&mut self, action: tui::palette::Action) -> Result<()> {
        use tui::palette::Action;
        match action {
            Action::Screen(Screen::Help) => {
                self.before_help = self.screen;
                self.screen = Screen::Help;
            }
            Action::Screen(screen) => self.show(screen)?,
            Action::Key(screen, code) => {
                self.show(screen)?;
                if screen == Screen::Nginx {
                    // `r` and `A` are keys of the site list, not of the
                    // settings panel above it or of an open site's detail.
                    self.nginx.show_sites();
                }
                self.handle_key_event(KeyEvent::from(code))?;
            }
            Action::Theme => self.theme = self.theme.toggle(),
            Action::UiMode => {
                let mode = self.db.get_ui_mode()?.toggle();
                self.set_ui_mode(mode)?;
            }
            Action::Quit => self.events.send(AppEvent::Quit),
            Action::Detector(detector, on) => {
                detector.set_enabled(&self.db, on)?;
                self.message = Some(format!(
                    "{} detection {}",
                    detector.spec().label,
                    if on { "on" } else { "off" }
                ));
                self.refresh()?;
            }
        }
        Ok(())
    }
}

/// The display name for a bot-list source id, falling back to the id
/// itself if it's somehow not one of `botlist::SourceKind::ALL` — status
/// messages should never panic over a display string.
fn source_display_name(source_id: &str) -> String {
    botlist::SourceKind::from_id(source_id)
        .map(|kind| kind.name().to_string())
        .unwrap_or_else(|| source_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallBackend, ScriptState};
    use crate::protection::Detector;

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn test_app() -> App {
        // `reload_nginx: false` — no test here drives a NGINX apply
        // through `handle_key_event`, but this keeps it that way even if
        // one is added later, rather than relying on that staying true.
        let app = App::new(
            Db::open_in_memory().unwrap(),
            std::path::PathBuf::from("/etc/nginx"),
            false,
            // A fixture log rather than `None`: auto-detection would read
            // whatever SSH log the machine running the tests happens to
            // have, or shell out to `journalctl` — nondeterministic and,
            // on some hosts, slow enough to blow the unit-test budget on
            // its own.
            //
            // A *readable* one rather than a nonexistent path, because
            // `start_firewall_render` now refuses when the lockout check can't
            // run at all. Its single Accepted line is for 192.0.2.10,
            // which nothing in these tests blocks.
            Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
        )
        .unwrap();
        // The health probe asks the host itself — `systemctl`, `nft`,
        // `docker ps` — so a test whose cron tick ran it read this
        // machine's services and Docker socket. Marked just run; a test
        // about the health job itself sets its own state.
        app.db
            .set_cron_last_run(CronJob::HealthCheck.id(), now_secs(), "skipped for test")
            .unwrap();
        // Every screen: these tests are about the advanced ones, and the
        // simple mode a new database opens in has its own below.
        app.db.set_ui_mode(crate::db::UiMode::Advanced).unwrap();
        let mut app = app;
        app.dashboard.set_simple(false);
        app
    }

    #[tokio::test]
    async fn the_palette_names_the_sites_screen_for_the_hosts_web_server() {
        let mut app = test_app();
        app.nginx = tui::nginx::Nginx::new(
            crate::webserver::WebServer::Apache,
            std::path::PathBuf::from("/etc/apache2"),
        );
        let labels: Vec<String> = app.commands().into_iter().map(|c| c.label).collect();
        for expected in [
            "Go to Apache",
            "Apply everything: Apache, then the firewall",
            "Rescan for Apache sites",
        ] {
            assert!(
                labels.iter().any(|label| label == expected),
                "no {expected:?} among:\n{labels:#?}"
            );
        }
        assert!(
            !labels.iter().any(|label| label.contains("NGINX")),
            "an Apache host's palette names NGINX:\n{labels:#?}"
        );
    }

    /// `v` goes to the simple screen and back, and the choice outlives
    /// the TUI: it is in the database the next start reads.
    #[tokio::test]
    async fn v_switches_between_the_simple_screen_and_every_screen_and_is_remembered() {
        let mut app = test_app();
        app.screen = Screen::Firewall;

        app.handle_key_event(KeyEvent::from(KeyCode::Char('v')))
            .unwrap();

        assert!(app.dashboard.is_simple());
        assert_eq!(
            app.screen,
            Screen::Dashboard,
            "Firewall is not a simple tab"
        );
        assert_eq!(app.db.get_ui_mode().unwrap(), crate::db::UiMode::Simple);

        app.handle_key_event(KeyEvent::from(KeyCode::Char('v')))
            .unwrap();

        assert!(!app.dashboard.is_simple());
        assert_eq!(app.db.get_ui_mode().unwrap(), crate::db::UiMode::Advanced);
    }

    /// The simple mode's tabs are its own and Blocks. A key for one of
    /// the others says where it is rather than leaving the simple mode.
    #[tokio::test]
    async fn an_advanced_screens_key_on_the_simple_screen_points_at_v() {
        let mut app = test_app();
        app.set_ui_mode(crate::db::UiMode::Simple).unwrap();

        app.handle_key_event(KeyEvent::from(KeyCode::Char('3')))
            .unwrap();
        assert_eq!(app.screen, Screen::Dashboard);
        assert!(
            app.message
                .as_deref()
                .is_some_and(|m| m.contains("press v")),
            "message: {:?}",
            app.message
        );

        app.handle_key_event(KeyEvent::from(KeyCode::Char('x')))
            .unwrap();
        assert_eq!(app.screen, Screen::Blocks);
    }

    /// A palette command for a screen the simple mode does not have is
    /// asking for that screen: it leaves the simple mode to show it.
    #[tokio::test]
    async fn the_palette_leaves_the_simple_mode_for_an_advanced_screen() {
        let mut app = test_app();
        app.set_ui_mode(crate::db::UiMode::Simple).unwrap();

        app.run_command(tui::palette::Action::Screen(Screen::Firewall))
            .unwrap();

        assert_eq!(app.screen, Screen::Firewall);
        assert!(!app.dashboard.is_simple());
    }

    /// Off needs no root and writes no file: both auto-applies go off.
    #[tokio::test]
    async fn keep_running_off_turns_both_auto_applies_off() {
        let mut app = test_app();
        app.db.set_auto_apply(true).unwrap();
        app.db.set_auto_apply_firewall(true).unwrap();

        app.set_keep_running(false).unwrap();

        assert!(!app.db.get_auto_apply().unwrap(), "{:?}", app.message);
        assert!(
            !app.db.get_auto_apply_firewall().unwrap(),
            "{:?}",
            app.message
        );
    }

    /// On that cannot write the cron file says why and switches nothing
    /// on: an auto-apply with nothing to run it would read as running.
    /// The test database is in memory, which cron could not open.
    #[tokio::test]
    async fn keep_running_on_that_fails_says_why_and_switches_nothing_on() {
        let mut app = test_app();

        app.set_keep_running(true).unwrap();

        assert!(
            app.message.as_deref().is_some_and(|m| m.contains("memory")),
            "message: {:?}",
            app.message
        );
        assert!(!app.db.get_auto_apply().unwrap(), "{:?}", app.message);
        assert!(
            !app.db.get_auto_apply_firewall().unwrap(),
            "{:?}",
            app.message
        );
    }

    /// The simple mode has two tabs, and Left/Right go between them in
    /// either direction rather than through the screens it does not have.
    #[tokio::test]
    async fn left_and_right_on_the_simple_screen_go_between_its_two_tabs() {
        let mut app = test_app();
        app.set_ui_mode(crate::db::UiMode::Simple).unwrap();

        for (key, expected) in [
            (KeyCode::Right, Screen::Blocks),
            (KeyCode::Right, Screen::Dashboard),
            (KeyCode::Left, Screen::Blocks),
            (KeyCode::Char('h'), Screen::Dashboard),
        ] {
            app.handle_key_event(KeyEvent::from(key)).unwrap();
            assert_eq!(app.screen, expected, "after {key:?}");
        }
    }

    /// The simple mode has no sites screen to scan from, so it scans at
    /// start when no site is known; every screen leaves that to the Sites
    /// screen, as before.
    #[tokio::test]
    async fn the_simple_screen_scans_for_sites_at_start_when_none_are_known() {
        let empty = tempfile::tempdir().unwrap();
        for (mode, scans) in [
            (crate::db::UiMode::Simple, true),
            (crate::db::UiMode::Advanced, false),
        ] {
            let db = Db::open_in_memory().unwrap();
            db.set_ui_mode(mode).unwrap();
            let mut app = App::new(
                db,
                empty.path().to_path_buf(),
                false,
                Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
            )
            .unwrap();

            app.scan_if_simple_and_empty().unwrap();

            assert_eq!(
                app.jobs_in_flight.contains(&Job::ScanSites),
                scans,
                "{mode:?}"
            );
        }
    }

    /// Marks both download jobs just run, so that no test's cron check
    /// reaches the network.
    fn mark_downloads_run(app: &App) {
        for job in [CronJob::UpdateIpRanges, CronJob::UpdateEverything] {
            app.db
                .set_cron_last_run(job.id(), now_secs(), "skipped for test")
                .unwrap();
        }
    }

    /// The bottom row of the whole UI, as drawn.
    fn footer(app: &mut App) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 32)).unwrap();
        terminal
            .draw(|frame| crate::tui::render(app, frame))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..120)
            .map(|x| buffer[(x, 31)].symbol().to_string())
            .collect()
    }

    /// A message used to reach only the Dashboard, so a fetch finishing
    /// while the operator sat on Bot settings said nothing where they were
    /// looking. It shows in the footer of whatever screen is open, until
    /// the next key press brings the key hints back.
    #[tokio::test]
    async fn a_message_shows_in_the_footer_of_any_screen_until_the_next_key() {
        let mut app = test_app();
        app.screen = Screen::BotSettings;

        // As a background job's `finish_` would.
        app.message = Some("Stored 4 bot(s) from ai-robots-txt".to_string());
        app.note_message();
        assert!(
            footer(&mut app).contains("Stored 4 bot(s)"),
            "footer: {}",
            footer(&mut app)
        );

        app.handle_key_press(KeyEvent::from(KeyCode::Down)).unwrap();
        let after = footer(&mut app);
        assert!(
            !after.contains("Stored 4") && after.contains("explain"),
            "the hints did not come back: {after}"
        );
        assert_eq!(
            app.message.as_deref(),
            Some("Stored 4 bot(s) from ai-robots-txt"),
            "a key that says nothing keeps the last message"
        );
    }

    /// Pressing the same key twice is two actions, and the second says so
    /// even though its message reads exactly like the first.
    #[tokio::test]
    async fn a_key_that_repeats_the_last_message_shows_it_again() {
        let mut app = test_app();
        app.jobs_in_flight.insert(Job::UpdateEverything);

        for _ in 0..2 {
            app.handle_key_press(KeyEvent::from(KeyCode::Char('u')))
                .unwrap();
            app.note_message();
            assert!(app.message_in_footer, "the message was not shown");
        }

        let said: Vec<&str> = app.log.iter().map(|(_, text)| text.as_str()).collect();
        assert_eq!(said, ["Already downloading every list."; 2]);
    }

    /// `u` while another download holds the lease — the weekly job, the
    /// crawler job, or another stop-bots — fetches nothing and says why.
    #[tokio::test]
    async fn u_while_another_download_runs_fetches_nothing_and_says_so() {
        let mut app = test_app();
        crate::refresh::claim(&app.db, now_secs()).unwrap();

        app.handle_key_press(KeyEvent::from(KeyCode::Char('u')))
            .unwrap();

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Another update"), "was: {message}");
        assert!(
            !app.jobs_in_flight.contains(&Job::UpdateEverything),
            "{:?}",
            app.jobs_in_flight
        );
    }

    /// Refreshing one crawler's ranges waits for a download someone else
    /// holds, the same as `u` — nothing starts, and the message says why.
    #[tokio::test]
    async fn a_crawler_refresh_while_another_download_runs_fetches_nothing() {
        let mut app = test_app();
        crate::refresh::claim(&app.db, now_secs()).unwrap();

        app.start_crawler_ranges_refresh(ipranges::IpRangeSourceKind::GoogleBot);

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Another update"), "was: {message}");
        assert!(app.crawler_refresh_lease.is_none());
        assert!(!app.jobs_in_flight.contains(&Job::RefreshCrawlerRanges(
            ipranges::IpRangeSourceKind::GoogleBot
        )));
    }

    /// A finished crawler refresh stores what arrived, says so, and gives
    /// the lease back so the next download can start. The daily crawler
    /// job is left alone: one source is not all three.
    #[tokio::test]
    async fn a_finished_crawler_refresh_stores_the_ranges_and_frees_the_lease() {
        let mut app = test_app();
        let kind = ipranges::IpRangeSourceKind::GptBot;
        let lease = match crate::refresh::claim(&app.db, now_secs()).unwrap() {
            crate::refresh::Claim::Granted(lease) => lease,
            busy => panic!("{busy:?}"),
        };
        app.crawler_refresh_lease = Some(lease);
        app.jobs_in_flight.insert(Job::RefreshCrawlerRanges(kind));

        app.finish_crawler_ranges_refresh(
            kind,
            Ok(r#"{"prefixes":[{"ipv4Prefix":"20.171.206.0/24"}]}"#.to_string()),
        )
        .unwrap();

        assert_eq!(
            app.message.as_deref(),
            Some("GPTBot IP ranges: 1 range(s).")
        );
        assert_eq!(
            app.db.ip_ranges_for_source("gptbot").unwrap(),
            vec!["20.171.206.0/24".to_string()]
        );
        assert!(!app
            .jobs_in_flight
            .contains(&Job::RefreshCrawlerRanges(kind)));
        assert!(
            matches!(
                crate::refresh::claim(&app.db, now_secs()).unwrap(),
                crate::refresh::Claim::Granted(_)
            ),
            "the lease was not given back"
        );
        assert_eq!(
            app.db
                .get_cron_last_run(CronJob::UpdateIpRanges.id())
                .unwrap(),
            None
        );
    }

    /// A failed download is a message, and still frees the lease.
    #[tokio::test]
    async fn a_failed_crawler_refresh_says_so_and_frees_the_lease() {
        let mut app = test_app();
        let kind = ipranges::IpRangeSourceKind::BingBot;
        let lease = match crate::refresh::claim(&app.db, now_secs()).unwrap() {
            crate::refresh::Claim::Granted(lease) => lease,
            busy => panic!("{busy:?}"),
        };
        app.crawler_refresh_lease = Some(lease);

        app.finish_crawler_ranges_refresh(kind, Err("timed out".to_string()))
            .unwrap();

        assert_eq!(
            app.message.as_deref(),
            Some("Bingbot IP ranges update failed: timed out")
        );
        assert!(matches!(
            crate::refresh::claim(&app.db, now_secs()).unwrap(),
            crate::refresh::Claim::Granted(_)
        ));
    }

    /// And the scheduled jobs wait for `u`'s run in the same process:
    /// neither the weekly download nor the crawler job starts beside it.
    #[tokio::test]
    async fn the_scheduled_downloads_wait_for_one_started_by_hand() {
        let mut app = test_app();
        // `u`'s run, which has the lease in a real run; it does not here, so
        // only the in-process check stands between this test and a fetch.
        app.jobs_in_flight.insert(Job::UpdateEverything);

        for job in [CronJob::UpdateEverything, CronJob::UpdateIpRanges] {
            app.start_cron_job(crate::cron::Task::Job(job)).unwrap();
            assert!(
                !app.jobs_in_flight.contains(&Job::Cron(job)),
                "{} started beside `u`: {:?}",
                job.id(),
                app.jobs_in_flight
            );
        }
    }

    /// The weekly run works in the background: its outcome goes to the
    /// Scheduled panel, not over whatever the operator is doing.
    #[tokio::test]
    async fn a_scheduled_download_reports_to_the_schedule_not_the_message_line() {
        let mut app = test_app();
        let lease = match crate::refresh::claim(&app.db, now_secs()).unwrap() {
            crate::refresh::Claim::Granted(lease) => lease,
            busy => panic!("{busy:?}"),
        };
        app.jobs_in_flight
            .insert(Job::Cron(CronJob::UpdateEverything));
        let run = crate::refresh::Run::with_nothing_left(Vec::new(), Some(lease), true);

        app.finish_cron_job(crate::cron::Done::downloaded(
            run,
            crate::refresh::Source::Country("ru".to_string()),
            Ok("5.8.0.0/19\n".to_string()),
        ))
        .unwrap();

        assert_eq!(app.message, None);
        assert!(
            !app.jobs_in_flight
                .contains(&Job::Cron(CronJob::UpdateEverything)),
            "{:?}",
            app.jobs_in_flight
        );
        assert_eq!(
            app.db
                .get_cron_last_summary(CronJob::UpdateEverything.id())
                .unwrap()
                .as_deref(),
            Some("Updated 1 list(s).")
        );
        assert!(
            matches!(
                crate::refresh::claim(&app.db, now_secs()).unwrap(),
                crate::refresh::Claim::Granted(_)
            ),
            "the lease was not given back"
        );
    }

    /// `?` explains the row under the cursor; `?` from there opens the
    /// full key reference, and Esc from the explanation goes back to the
    /// screen it was opened on.
    #[tokio::test]
    async fn question_mark_explains_then_lists_every_key() {
        let mut app = test_app();
        let press = |app: &mut App, code| app.handle_key_event(KeyEvent::from(code)).unwrap();

        press(&mut app, KeyCode::Char('?'));
        let title = app
            .explain
            .as_ref()
            .map(|explain| explain.explanation().title.clone());
        assert_eq!(
            title.as_deref(),
            Some("Humans only"),
            "the Dashboard's first row"
        );
        press(&mut app, KeyCode::Esc);
        assert!(app.explain.is_none());
        assert_eq!(app.screen, Screen::Dashboard, "Esc closed it, and only it");

        press(&mut app, KeyCode::Char('?'));
        press(&mut app, KeyCode::Char('?'));
        assert!(app.explain.is_none());
        assert_eq!(app.screen, Screen::Help);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.screen, Screen::Dashboard);
    }

    /// Every screen has something to say on `?`, even with nothing on it.
    #[tokio::test]
    async fn every_screen_explains_something_when_empty() {
        let mut app = test_app();
        for screen in Screen::TABS {
            app.screen = screen;
            let explanation = app.explanation();
            assert!(
                !explanation.title.is_empty() && !explanation.body.is_empty(),
                "{screen:?} explained nothing: {explanation:?}"
            );
        }
    }

    /// Types `text` into the open palette and presses Enter.
    fn run_palette(app: &mut App, text: &str) {
        app.handle_key_event(KeyEvent::from(KeyCode::Char(':')))
            .unwrap();
        assert!(app.palette.is_some(), "`:` should open the palette");
        for c in text.chars() {
            app.handle_key_event(KeyEvent::from(KeyCode::Char(c)))
                .unwrap();
        }
        app.handle_key_event(KeyEvent::from(KeyCode::Enter))
            .unwrap();
        assert!(app.palette.is_none(), "Enter should close the palette");
    }

    #[tokio::test]
    async fn the_palette_runs_the_best_match_for_what_was_typed() {
        let mut app = test_app();
        let before = app.theme;
        run_palette(&mut app, "theme");
        assert_eq!(app.theme, before.toggle());

        run_palette(&mut app, "go to fire");
        assert_eq!(app.screen, Screen::Firewall);
    }

    /// A `Key` command is the key: it lands on the right screen and goes
    /// through the screen's own handler, popup and all.
    #[tokio::test]
    async fn the_palette_presses_a_screens_key_from_any_screen() {
        let mut app = test_app();
        app.screen = Screen::BotSettings;
        run_palette(&mut app, "write fire");
        assert_eq!(app.screen, Screen::Dashboard);
        assert!(
            app.dashboard.render_popup_is_open(),
            "the render popup should be open"
        );
    }

    #[tokio::test]
    async fn the_palette_flips_a_detector_and_says_so() {
        use crate::protection::Detector;
        let mut app = test_app();
        assert!(!Detector::Honeypot.is_enabled(&app.db).unwrap());
        run_palette(&mut app, "honeypot");
        assert!(Detector::Honeypot.is_enabled(&app.db).unwrap());
        assert_eq!(app.message.as_deref(), Some("Honeypot path detection on"));
        // Reopened, the same row now offers the other direction.
        run_palette(&mut app, "honeypot");
        assert!(!Detector::Honeypot.is_enabled(&app.db).unwrap());
    }

    #[tokio::test]
    async fn escape_closes_the_palette_and_runs_nothing() {
        let mut app = test_app();
        let before = app.theme;
        app.handle_key_event(KeyEvent::from(KeyCode::Char(':')))
            .unwrap();
        for c in "theme".chars() {
            app.handle_key_event(KeyEvent::from(KeyCode::Char(c)))
                .unwrap();
        }
        app.handle_key_event(KeyEvent::from(KeyCode::Esc)).unwrap();
        assert!(app.palette.is_none());
        assert_eq!(app.theme, before);
        assert_eq!(app.screen, Screen::Dashboard);
    }

    #[tokio::test]
    async fn escape_on_the_dashboard_does_not_quit() {
        let mut app = test_app();
        app.handle_key_event(KeyEvent::from(KeyCode::Esc)).unwrap();
        assert!(
            app.message
                .as_deref()
                .is_some_and(|m| m.contains("q quits")),
            "message was: {:?}",
            app.message
        );
    }

    #[tokio::test]
    async fn right_arrow_cycles_screens_forward_like_tab() {
        let mut app = test_app();
        assert_eq!(app.screen, Screen::Dashboard);

        app.handle_key_event(KeyEvent::from(KeyCode::Right))
            .unwrap();
        assert_eq!(app.screen, Screen::BotSettings);
    }

    #[tokio::test]
    async fn left_arrow_cycles_screens_backward_like_shift_tab() {
        let mut app = test_app();
        assert_eq!(app.screen, Screen::Dashboard);

        app.handle_key_event(KeyEvent::from(KeyCode::Left)).unwrap();
        assert_eq!(app.screen, Screen::Blocks);
    }

    #[tokio::test]
    async fn l_key_cycles_screens_forward_exactly_like_right_arrow() {
        let mut app = test_app();
        app.handle_key_event(KeyEvent::from(KeyCode::Char('l')))
            .unwrap();
        assert_eq!(app.screen, Screen::BotSettings);
    }

    #[tokio::test]
    async fn h_key_cycles_screens_backward_exactly_like_left_arrow() {
        let mut app = test_app();
        app.handle_key_event(KeyEvent::from(KeyCode::Char('h')))
            .unwrap();
        assert_eq!(app.screen, Screen::Blocks);
    }

    // ---- the `finish_` half of every network fetch ----
    //
    // These are the only part of a download this suite can reach: the
    // `start_` halves make a real HTTP request, and no test here touches
    // the network. That split is worth knowing, because the `finish_`
    // half is where the interesting decisions are — what gets stored, what
    // the admin is told, and what happens on failure — while the `start_`
    // half is a spawn.
    //
    // Each takes the same `Result<T, String>` its background task would
    // have sent, so a synthetic payload exercises it exactly as the real
    // event does.

    /// `h`/`l` must not steal a keystroke that a screen's own search/text
    /// focus wants — Bot settings' search box (`/`) accepts any character,
    /// including 'h'/'l', as literal query text, e.g. typing "arclejot" to
    /// filter by name must not jump screens partway through.
    /// A finished bot-list download stores the bots and says how many.
    #[tokio::test]
    async fn a_finished_bot_list_download_is_stored_and_counted() {
        let mut app = test_app();

        let source_id = botlist::SourceKind::WellKnownBots.id();
        app.finish_source_update(
            source_id.to_string(),
            Ok(botlist::Parsed {
                bots: vec![crate::testing::new_bot("badbot", source_id)],
                skipped: 0,
            }),
        )
        .unwrap();

        // Counted against *this* source, not the whole table: the
        // built-in `stop-bots-extras` list is seeded at startup, so
        // "every bot there is" has not meant "the ones this download
        // brought" since it landed.
        assert_eq!(app.db.count_bot_source_entries(source_id).unwrap(), 1);
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Stored 1 bot"), "message was: {message}");
    }

    /// A failed one says so and changes nothing. The distinction matters:
    /// a transient network error must not look like "this source is empty".
    #[tokio::test]
    async fn a_failed_bot_list_download_reports_it_and_stores_nothing() {
        let mut app = test_app();

        app.finish_source_update(
            botlist::SourceKind::WellKnownBots.id().to_string(),
            Err("connection refused".to_string()),
        )
        .unwrap();

        // Nothing from the source that failed. The built-in list is
        // seeded at startup and is not what this test is about.
        assert_eq!(
            app.db
                .count_bot_source_entries(botlist::SourceKind::WellKnownBots.id())
                .unwrap(),
            0
        );
        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            message.contains("Failed to update"),
            "message was: {message}"
        );
        assert!(
            message.contains("connection refused"),
            "message was: {message}"
        );
    }

    /// Fetching a country's ranges is only half of what the admin asked
    /// for — they picked a country to *act on*, so a successful fetch also
    /// adds it to the geo selection.
    #[tokio::test]
    async fn a_finished_country_fetch_also_selects_the_country() {
        let mut app = test_app();

        app.finish_country_select("nl".to_string(), Ok(vec!["1.2.3.0/24".to_string()]))
            .unwrap();

        assert_eq!(app.db.list_selected_countries().unwrap(), vec!["nl"]);
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Blocked NL"), "message was: {message}");
    }

    /// And the message follows the current geo mode rather than assuming
    /// one: in Allowlist mode, selecting a country *permits* it, and
    /// saying "Blocked" there would be exactly backwards.
    #[tokio::test]
    async fn a_finished_country_fetch_says_allowed_in_allowlist_mode() {
        let mut app = test_app();
        app.db.set_geo_mode(crate::db::GeoMode::Allowlist).unwrap();

        app.finish_country_select("nl".to_string(), Ok(vec!["1.2.3.0/24".to_string()]))
            .unwrap();

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Allowed NL"), "message was: {message}");
    }

    #[tokio::test]
    async fn a_failed_country_fetch_leaves_the_country_unselected() {
        let mut app = test_app();

        app.finish_country_select("nl".to_string(), Err("404".to_string()))
            .unwrap();

        assert!(app.db.list_selected_countries().unwrap().is_empty());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            message.contains("Failed to fetch"),
            "message was: {message}"
        );
    }

    #[tokio::test]
    async fn a_finished_hosting_asn_download_stores_the_chosen_ranges() {
        let mut app = test_app();
        app.db.add_hosting_asn(24940).unwrap();
        let lines = "5.9.0.0\t5.9.255.255\t24940\tDE\tHETZNER-AS\n".to_string();

        app.finish_hosting_asn_fetch(&[24940], Ok(lines)).unwrap();

        assert_eq!(
            app.db.hosting_asn_ranges().unwrap(),
            [(24940, "5.9.0.0/16".to_string())]
        );
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("1 range(s)"), "message was: {message}");
    }

    /// A failed download leaves the provider chosen and says why; the
    /// weekly update and `status` pick it up from there.
    #[tokio::test]
    async fn a_failed_hosting_asn_download_says_so_and_keeps_the_choice() {
        let mut app = test_app();
        app.db.add_hosting_asn(24940).unwrap();

        app.finish_hosting_asn_fetch(&[24940], Err("timed out".to_string()))
            .unwrap();

        assert_eq!(app.db.list_hosting_asns().unwrap().len(), 1);
        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            message.contains("download failed: timed out"),
            "message was: {message}"
        );
    }

    #[tokio::test]
    async fn a_finished_reputation_fetch_stores_its_ranges() {
        let mut app = test_app();
        let source_id = crate::ipranges::reputation::ReputationSourceKind::Aws.id();

        app.finish_reputation_fetch(source_id.to_string(), Ok(vec!["1.2.3.0/24".to_string()]))
            .unwrap();

        let stored = app
            .db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == source_id)
            .unwrap();
        assert_eq!(stored.range_count, 1);
    }

    /// An empty parse is refused rather than stored. It almost always
    /// means the upstream format moved or an error page was served, and
    /// storing it would silently un-block everything the feed covered.
    #[tokio::test]
    async fn a_reputation_fetch_that_parsed_to_nothing_is_not_stored() {
        let mut app = test_app();
        let source_id = crate::ipranges::reputation::ReputationSourceKind::Aws.id();

        app.finish_reputation_fetch(source_id.to_string(), Ok(Vec::new()))
            .unwrap();

        let stored = app
            .db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == source_id)
            .unwrap();
        assert_eq!(stored.range_count, 0);
        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            message.contains("no usable addresses"),
            "message was: {message}"
        );
    }

    #[tokio::test]
    async fn a_failed_reputation_fetch_reports_it() {
        let mut app = test_app();

        app.finish_reputation_fetch(
            crate::ipranges::reputation::ReputationSourceKind::Aws
                .id()
                .to_string(),
            Err("timed out".to_string()),
        )
        .unwrap();

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("timed out"), "message was: {message}");
    }

    /// One crawler source failing must not discard what the other two
    /// fetched — the job stores whatever worked and summarises the rest.
    #[tokio::test]
    async fn a_partly_failed_crawler_range_update_keeps_what_worked() {
        use crate::ipranges::IpRangeSourceKind;
        let mut app = test_app();
        app.jobs_in_flight
            .insert(Job::Cron(CronJob::UpdateIpRanges));
        let lease = match crate::refresh::claim(&app.db, now_secs()).unwrap() {
            crate::refresh::Claim::Granted(lease) => lease,
            busy => panic!("{busy:?}"),
        };

        app.finish_cron_job(crate::cron::Done::crawler_ranges(
            lease,
            vec![
                (
                    IpRangeSourceKind::GoogleBot,
                    Ok(vec!["8.8.8.0/24".to_string()]),
                ),
                (IpRangeSourceKind::BingBot, Err("timed out".to_string())),
            ],
        ))
        .unwrap();

        assert!(!app
            .jobs_in_flight
            .contains(&Job::Cron(CronJob::UpdateIpRanges)));
        let summary = app
            .db
            .get_cron_last_summary(CronJob::UpdateIpRanges.id())
            .unwrap()
            .unwrap_or_default();
        assert!(summary.contains("updated 1"), "summary was: {summary}");
        assert!(summary.contains("1 failed"), "summary was: {summary}");
    }

    #[tokio::test]
    async fn h_and_l_are_literal_query_text_while_bot_settings_search_is_focused() {
        let mut app = test_app();
        app.screen = Screen::BotSettings;

        app.handle_key_event(KeyEvent::from(KeyCode::Char('/')))
            .unwrap();
        app.handle_key_event(KeyEvent::from(KeyCode::Char('h')))
            .unwrap();
        app.handle_key_event(KeyEvent::from(KeyCode::Char('l')))
            .unwrap();

        assert_eq!(app.screen, Screen::BotSettings);
    }

    /// The log-based cron jobs read their logs in one pass on a
    /// background thread (see `App::start_cron_job`) rather than
    /// running inline, so tests that trigger them via `check_cron` must
    /// drive the resulting `CronWorkDone` event through the same
    /// `handle_event` dispatch `App::run` uses before asserting on `Db`
    /// state. Drains until `jobs_in_flight` (populated synchronously
    /// by `check_cron` before this is called) is empty again, rather than a
    /// fixed event count: `EventHandler`'s background `EventTask` also
    /// pushes `Event::Tick` into the same channel at 30fps, so a tick can
    /// land ahead of a slower job's result (e.g. the SSH log falling back
    /// to a `journalctl` subprocess) — a fixed count would then stop one
    /// event short. Ticks dispatch through `handle_event` as harmless
    /// no-ops here (`check_cron` throttles itself right back out).
    async fn drain_background_work(app: &mut App) {
        while !app.jobs_in_flight.is_empty() {
            let event = app.events.next().await.unwrap();
            app.handle_event(event).unwrap();
        }
    }

    /// A mutation still reaches every screen — just at the moment each
    /// one is next drawn, rather than in the keypress that caused it. The
    /// user-visible contract is unchanged; what changed is that a keypress
    /// no longer pays for three screens nobody is looking at.
    #[tokio::test]
    async fn a_mutation_defers_the_other_screens_reload_until_each_is_next_drawn() {
        let mut app = test_app();
        assert!(
            app.stale.is_empty(),
            "startup loads all five, so nothing starts out stale"
        );

        app.screen = Screen::Dashboard;
        app.refresh().unwrap();

        assert_eq!(
            app.stale,
            std::collections::HashSet::from([
                Screen::BotSettings,
                Screen::Nginx,
                Screen::Firewall,
                Screen::Blocks,
            ]),
            "every screen except the one being looked at"
        );

        app.screen = Screen::BotSettings;
        app.refresh_if_stale().unwrap();

        assert!(
            !app.stale.contains(&Screen::BotSettings),
            "coming into view reloads it"
        );
        assert!(
            app.stale.contains(&Screen::Nginx),
            "and leaves the ones still off screen alone"
        );
    }

    /// The direct `stop_bots::firewall` call this method now makes (instead
    /// of shelling out to a `stop-bots` binary that might not be on `$PATH`
    /// — see the doc comment on `start_firewall_render`) must still actually
    /// write the script and report success.
    // `App::new` spawns a background task via `EventHandler::new`, so
    // constructing one needs an actual Tokio runtime, not just `#[test]`.
    #[tokio::test]
    async fn render_firewall_writes_the_script_and_sets_a_success_message() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft").to_str().unwrap().to_string();

        app.start_firewall_render(FirewallBackend::Nftables, out_path.clone(), false, false);
        drain_background_work(&mut app).await;

        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            crate::firewall::rendered_path(std::path::Path::new(&out_path)).exists(),
            "message was: {message}"
        );
        assert!(
            !std::path::Path::new(&out_path).exists(),
            "an unapplied render reached the script the boot unit loads"
        );
        assert!(message.contains("wrote"), "message was: {message}");
    }

    /// `apply: true` requests the render popup's "apply after writing"
    /// shortcut, but only real usage should ever actually shell out to
    /// `nft`/`sh` — `test_app()` sets `apply_firewall: false` for exactly
    /// the same reason `reload_nginx: false` exists (see that field's doc
    /// comment): a test that really invoked `nft -f`/`sh` against a
    /// generated script would mutate whatever host runs the suite. This
    /// asserts the guard is honored: the script is still written, but the
    /// message reports it as written only, never claiming "applied" for a
    /// subprocess that didn't run.
    #[tokio::test]
    async fn render_firewall_with_apply_is_write_only_when_apply_firewall_is_disabled() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft").to_str().unwrap().to_string();

        app.start_firewall_render(FirewallBackend::Nftables, out_path.clone(), false, true);
        drain_background_work(&mut app).await;

        let message = app.message.as_deref().unwrap_or_default();
        assert!(
            crate::firewall::rendered_path(std::path::Path::new(&out_path)).exists(),
            "message was: {message}"
        );
        assert!(message.contains("wrote"), "message was: {message}");
        assert!(
            message.contains("not applied: --no-apply"),
            "message was: {message}"
        );
        assert_eq!(
            app.db.get_firewall_applied_signature().unwrap(),
            None,
            "nothing ran, so nothing may be recorded as applied"
        );
    }

    /// One source failing must not take the run down with it: the rest
    /// still get their turn, and the failure is named in the summary.
    #[tokio::test]
    async fn update_everything_names_a_failed_source_and_still_finishes() {
        let mut app = test_app();
        let stored = |source| (source, Ok("1 range(s)".to_string()));
        app.jobs_in_flight.insert(Job::UpdateEverything);
        let run = crate::refresh::Run::with_nothing_left(
            vec![
                stored(crate::refresh::Source::Country("ru".to_string())),
                stored(crate::refresh::Source::Country("cn".to_string())),
            ],
            None,
            false,
        );

        app.finish_cron_job(crate::cron::Done::downloaded(
            run,
            crate::refresh::Source::CrawlerRanges(crate::ipranges::IpRangeSourceKind::GoogleBot),
            Err("timed out".to_string()),
        ))
        .unwrap();

        assert!(!app.jobs_in_flight.contains(&Job::UpdateEverything));
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Updated 2 list(s)"), "was: {message}");
        assert!(message.contains("timed out"), "was: {message}");
        assert!(message.contains("crawler ranges"), "was: {message}");
        // A crawler source failed, so the job that covers all three must
        // *not* be recorded as done — otherwise the internal cron would
        // skip re-fetching it until tomorrow.
        assert_eq!(
            app.db
                .get_cron_last_summary(CronJob::UpdateIpRanges.id())
                .unwrap(),
            None
        );
    }

    /// The happy path: a downloaded body is parsed and stored on the main
    /// thread.
    ///
    /// No assertion here about the `UpdateIpRanges` cron job. One crawler
    /// source in `outcomes` makes `crawler_ranges_all_succeeded` true
    /// vacuously, and `refresh::plan` always emits all three — so an
    /// assertion would pass for a reason production never reaches. That
    /// rule has its own tests in `refresh`.
    #[tokio::test]
    async fn update_everything_stores_what_it_downloaded() {
        let mut app = test_app();
        let raw = std::fs::read_to_string("tests/fixtures/ipranges/googlebot-sample.json").unwrap();
        app.jobs_in_flight.insert(Job::UpdateEverything);
        let run = crate::refresh::Run::with_nothing_left(Vec::new(), None, false);

        app.finish_cron_job(crate::cron::Done::downloaded(
            run,
            crate::refresh::Source::CrawlerRanges(crate::ipranges::IpRangeSourceKind::GoogleBot),
            Ok(raw),
        ))
        .unwrap();

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("Updated 1 list(s)"), "was: {message}");
        assert!(!message.contains("failed"), "was: {message}");
        assert!(
            !app.db.ip_ranges_by_source_name().unwrap().is_empty(),
            "the downloaded ranges never reached the database"
        );
    }

    /// `a` on the Dashboard is the TUI's "Apply everything": both planes,
    /// the NGINX one and then the firewall one. The script it writes has
    /// to be in the *stored backend's* syntax — the drift that once had a
    /// cron writing nftables rules into a file an operator was running
    /// with `sh`. (The path here is an explicit override, which wins
    /// outright; that the *default* path follows the backend is
    /// `firewall::output_path`'s own test.)
    #[tokio::test]
    async fn pressing_a_writes_a_script_in_the_stored_backend_s_syntax() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        crate::firewall::store_backend(&app.db, FirewallBackend::Iptables).unwrap();
        // `None` would mean the real `/etc/stop-bots/firewall.sh` on the
        // machine running the suite.
        app.firewall_out = Some(dir.path().join("firewall.sh"));

        app.handle_key_event(KeyEvent::from(KeyCode::Char('a')))
            .unwrap();
        drain_background_work(&mut app).await;
        app.handle_key_event(KeyEvent::from(KeyCode::Enter))
            .unwrap();
        drain_background_work(&mut app).await;

        // The rendered one: `test_app` cannot apply, so nothing is
        // promoted to `firewall.sh`.
        let written = dir.path().join("firewall.next.sh");
        assert!(
            written.exists(),
            "no script at {written:?}; message was: {:?}",
            app.message.as_deref()
        );
        assert!(
            std::fs::read_to_string(&written)
                .unwrap()
                .contains("#!/bin/sh"),
            "the stored backend was iptables, so the script must be a shell script"
        );
        assert!(!app.apply_everything, "the chain flag must be cleared");
    }

    /// An apply that has run with a revert armed — for real, against the
    /// fakes in `dir` — as `finish_firewall_render` receives it. The apply
    /// itself is the one step a unit test cannot run (`nft` is found on
    /// `PATH`), so it is the one step set by hand.
    fn awaiting_outcome(app: &mut App, dir: &std::path::Path) -> crate::firewall::FirewallOutcome {
        app.revert_tools = crate::testing::fake_revert_tools(dir);
        let applied = dir.join("fw.nft");
        let run = crate::firewall::FirewallRun::new(FirewallBackend::Nftables, &applied)
            .apply(true)
            .for_real(false);
        let prepared = crate::firewall::prepare(&app.db, run).unwrap();
        let mut outcome =
            crate::firewall::execute(prepared, crate::firewall::SshLog::Connected(Some(&[])));
        let pending = crate::revert::arm(
            &app.revert_tools,
            FirewallBackend::Nftables,
            &applied,
            crate::revert::DEFAULT_TIMEOUT,
            now_secs(),
        )
        .unwrap();
        outcome.apply = crate::firewall::ApplyStep::AwaitingConfirmation(pending);
        outcome
    }

    /// The apply comes back, wherever the operator is, and asks.
    async fn applied_and_asking(app: &mut App, dir: &std::path::Path) {
        let outcome = awaiting_outcome(app, dir);
        app.handle_event(Event::App(AppEvent::FirewallRendered {
            outcome: Box::new(outcome),
        }))
        .unwrap();
        assert!(app.keep_firewall.is_some(), "the question should be open");
    }

    #[tokio::test]
    async fn y_keeps_a_waiting_apply_and_records_it_as_applied() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        app.screen = Screen::Blocks;
        applied_and_asking(&mut app, dir.path()).await;
        let signature = app.keep_firewall.as_ref().unwrap().signature.clone();

        app.handle_key_event(KeyEvent::from(KeyCode::Char('y')))
            .unwrap();
        drain_background_work(&mut app).await;

        let message = app.message.clone().unwrap_or_default();
        assert!(
            message.starts_with("Kept the new firewall rules"),
            "message was: {message}"
        );
        assert!(app.keep_firewall.is_none(), "the question should be closed");
        assert!(dir.path().join("fw.nft").exists(), "message was: {message}");
        assert_eq!(
            app.db.get_firewall_applied_signature().unwrap(),
            Some(signature)
        );
    }

    #[tokio::test]
    async fn escape_reverts_a_waiting_apply_now() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        applied_and_asking(&mut app, dir.path()).await;

        app.handle_key_event(KeyEvent::from(KeyCode::Esc)).unwrap();
        drain_background_work(&mut app).await;

        assert_eq!(
            app.message.as_deref(),
            Some(
                "Reverted to no stop-bots firewall rules, as there were none before (you said no)."
            )
        );
        assert!(!dir.path().join("fw.nft").exists(), "nothing was kept");
        assert_eq!(app.db.get_firewall_applied_signature().unwrap(), None);
    }

    #[tokio::test]
    async fn nobody_answering_by_the_deadline_reverts() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        applied_and_asking(&mut app, dir.path()).await;
        let keep = app.keep_firewall.take().unwrap();
        app.keep_firewall = Some(tui::keep_firewall::KeepFirewall::new(
            keep.pending,
            keep.script,
            keep.signature,
            std::time::Duration::ZERO,
        ));

        app.check_keep_firewall();
        drain_background_work(&mut app).await;

        let message = app.message.clone().unwrap_or_default();
        assert!(
            message.contains("(no confirmation within 60 s)"),
            "message was: {message}"
        );
    }

    #[tokio::test]
    async fn while_asking_no_other_key_does_anything() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        applied_and_asking(&mut app, dir.path()).await;

        app.handle_key_event(KeyEvent::from(KeyCode::Char('5')))
            .unwrap();

        assert_eq!(app.screen, Screen::Dashboard, "the key went through");
        assert!(app.keep_firewall.is_some(), "the question was closed");
        assert!(
            !app.jobs_in_flight.contains(&Job::SettleFirewall),
            "the key answered the question"
        );
    }

    /// `a` rewrites every site and runs the firewall script as root, so it
    /// asks first: one keypress opens a summary of what would change and
    /// touches nothing, and Esc leaves it that way.
    #[tokio::test]
    async fn pressing_a_asks_first_and_escape_changes_nothing() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        app.firewall_out = Some(dir.path().join("firewall.nft"));
        app.db
            .block_address_permanently("192.0.2.77", crate::db::RuleSource::Tui, None)
            .unwrap();

        app.handle_key_event(KeyEvent::from(KeyCode::Char('a')))
            .unwrap();
        drain_background_work(&mut app).await;

        assert!(app.dashboard.confirm_apply_is_open(), "no confirmation");
        let written: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(written.is_empty(), "a preview wrote {written:?}");
        assert_eq!(app.db.get_firewall_rendered_signature().unwrap(), None);

        app.handle_key_event(KeyEvent::from(KeyCode::Esc)).unwrap();
        drain_background_work(&mut app).await;

        assert!(!app.dashboard.confirm_apply_is_open());
        assert_eq!(app.message.as_deref(), Some("Nothing applied."));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// What the confirmation shows is the verdict the apply will get: the
    /// rules added, and whether the lockout check could run.
    #[tokio::test]
    async fn the_confirmation_shows_the_rules_and_the_guard_s_verdict() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        app.firewall_out = Some(dir.path().join("firewall.nft"));
        app.db
            .block_address_permanently("192.0.2.77", crate::db::RuleSource::Tui, None)
            .unwrap();

        app.handle_key_event(KeyEvent::from(KeyCode::Char('a')))
            .unwrap();
        drain_background_work(&mut app).await;
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 40)).unwrap();
        terminal
            .draw(|frame| crate::tui::render(&mut app, frame))
            .unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();

        // Short needles: the summary wraps at the popup's width, and a
        // phrase across a wrap is two rows apart in the flattened buffer.
        for expected in [
            "Apply everything?",
            "no applied script",
            "lockout check passed",
        ] {
            assert!(screen.contains(expected), "no {expected:?} on:\n{screen}");
        }
    }

    /// A successful write must persist the rendered rule-set signature
    /// (`Db::get_firewall_rendered_signature`), which is what the
    /// Dashboard's Firewall script panel compares against to show
    /// `[ UP TO DATE ]` instead of `[ STALE ]` right after a render.
    #[tokio::test]
    async fn render_firewall_persists_the_rendered_signature() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft").to_str().unwrap().to_string();

        assert_eq!(app.db.get_firewall_rendered_signature().unwrap(), None);
        app.start_firewall_render(FirewallBackend::Nftables, out_path, false, false);
        drain_background_work(&mut app).await;
        assert!(app.db.get_firewall_rendered_signature().unwrap().is_some());
    }

    /// Regression test: `start_firewall_render` alone only updates `Db`; the
    /// Dashboard's "needs updating" row is a value cached on `Dashboard`
    /// itself, only recomputed by `Dashboard::refresh`. Confirming the
    /// render popup drives through `KeyOutcome::RenderFirewall`, not
    /// `start_firewall_render` directly, so this exercises `App::handle_key_event`
    /// end to end (via the real `F` keypress, backspacing the default path
    /// out and typing a writable temp one, then Enter) to prove that arm
    /// actually calls `self.refresh()` afterward — without it, the Firewall
    /// script panel would keep reading `[ STALE ]` right after the admin did
    /// exactly what its own hint told them to do.
    #[tokio::test]
    async fn pressing_f_then_enter_refreshes_the_dashboards_stale_indicator() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft");
        let out_path_str = out_path.to_str().unwrap().to_string();

        assert_eq!(app.dashboard.script_state(), ScriptState::Changed);

        app.handle_key_event(KeyEvent::from(KeyCode::Char('F')))
            .unwrap();
        for _ in 0..crate::firewall::DEFAULT_OUTPUT_PATH.len() {
            app.handle_key_event(KeyEvent::from(KeyCode::Backspace))
                .unwrap();
        }
        for c in out_path_str.chars() {
            app.handle_key_event(KeyEvent::from(KeyCode::Char(c)))
                .unwrap();
        }
        app.handle_key_event(KeyEvent::from(KeyCode::Enter))
            .unwrap();
        drain_background_work(&mut app).await;

        assert!(
            crate::firewall::rendered_path(&out_path).exists(),
            "message was: {:?}",
            app.message.as_deref()
        );
        assert_eq!(
            app.dashboard.script_state(),
            ScriptState::RenderedNotApplied,
            "written and not applied, and the row has to say so right away"
        );
    }

    /// The allowlist/iptables guard in `firewall::build_script` must
    /// surface as a status message rather than silently doing nothing or
    /// panicking, and the script must not be written.
    #[tokio::test]
    async fn render_firewall_reports_the_allowlist_iptables_conflict() {
        let mut app = test_app();
        app.db.set_geo_mode(crate::db::GeoMode::Allowlist).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.sh").to_str().unwrap().to_string();

        app.start_firewall_render(FirewallBackend::Iptables, out_path.clone(), false, false);
        drain_background_work(&mut app).await;

        assert!(!std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("nftables"), "message was: {message}");
    }

    // The lockout policy itself — what a risk or an unreadable log refuses —
    // is tested once, against `firewall::execute`, in `firewall.rs`. What
    // is left to test here is that this front-end goes through it.

    /// Regression test for a real bug: a freshly-constructed `App` used to
    /// set `last_cron_check` to `Instant::now()`, so the very first
    /// `check_cron` call (on the first `Event::Tick`, a fraction of a
    /// second after startup) was throttled away for a full
    /// `CRON_CHECK_INTERVAL` — a never-run job would show "due now" on the
    /// Dashboard immediately but not actually run for up to a minute. Here,
    /// with no manual backdating of `last_cron_check` at all (unlike the
    /// tests below, which simulate a later tick), the first `check_cron`
    /// call right after construction must already run every never-run
    /// synchronous job.
    #[tokio::test]
    async fn a_freshly_constructed_app_runs_due_jobs_on_its_first_check() {
        let mut app = test_app();
        mark_downloads_run(&app);

        app.check_cron().unwrap();
        drain_background_work(&mut app).await;

        assert!(app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::SshScanners).id())
            .unwrap()
            .is_some());
        assert!(app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::WebScanners).id())
            .unwrap()
            .is_some());
    }

    /// The TUI's half of the auto-apply switch. Off — which is every
    /// install until someone says otherwise — it must record that it ran
    /// and start nothing at all: no site apply, and so no walk of the
    /// config root, which on a test host does not exist.
    #[tokio::test]
    async fn the_auto_apply_job_starts_nothing_while_the_switch_is_off() {
        let mut app = test_app();
        assert!(!app.db.get_auto_apply().unwrap(), "off is the default");

        app.start_cron_job(crate::cron::Task::Job(CronJob::ApplyNginx))
            .unwrap();

        assert_eq!(
            app.db
                .get_cron_last_summary(CronJob::ApplyNginx.id())
                .unwrap()
                .as_deref(),
            Some("auto-apply is off"),
            "the panel should say why nothing happened"
        );
        assert!(
            !app.jobs_in_flight.contains(&Job::ApplySites),
            "an apply was started with the switch off"
        );
    }

    /// `check_cron` must run every currently-due log-based job
    /// (`BlockScanners`/`BlockWebScanners`/`RecordAccessStats`/
    /// `RenderFirewall` — no network I/O, so safe to exercise directly
    /// rather than mocking) and record each one's state, once their
    /// background `CronWorkDone` event is drained. `UpdateIpRanges` is
    /// deliberately pre-marked as just-run so this test never triggers its
    /// real network fetch.
    #[tokio::test]
    async fn check_cron_runs_every_due_synchronous_job() {
        let mut app = test_app();
        mark_downloads_run(&app);
        app.last_cron_check =
            std::time::Instant::now() - CRON_CHECK_INTERVAL - std::time::Duration::from_secs(1);

        app.check_cron().unwrap();
        drain_background_work(&mut app).await;

        assert!(app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::SshScanners).id())
            .unwrap()
            .is_some());
        assert!(app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::WebScanners).id())
            .unwrap()
            .is_some());
        assert!(app
            .db
            .get_cron_last_run(CronJob::RecordAccessStats.id())
            .unwrap()
            .is_some());
        assert!(app
            .db
            .get_cron_last_run(CronJob::RenderFirewall.id())
            .unwrap()
            .is_some());
    }

    /// Every due log job goes in one pass, and a second check while that
    /// pass is out starts no other: the TUI used to start one full read
    /// per job, all at once, which on a 200 MB log was 2.9 GB of memory.
    #[tokio::test]
    async fn due_log_jobs_share_one_pass_and_a_pass_never_overlaps_another() {
        let mut app = test_app();
        mark_downloads_run(&app);
        let backdate = |app: &mut App| {
            app.last_cron_check =
                std::time::Instant::now() - CRON_CHECK_INTERVAL - std::time::Duration::from_secs(1);
        };

        backdate(&mut app);
        app.check_cron().unwrap();
        let in_flight = app.jobs_in_flight.clone();
        backdate(&mut app);
        app.check_cron().unwrap();

        let mut passes = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(150);
        while !app.jobs_in_flight.is_empty() || std::time::Instant::now() < deadline {
            let Ok(Some(event)) =
                tokio::time::timeout(std::time::Duration::from_millis(50), app.events.next())
                    .await
                    .map(Result::ok)
            else {
                continue;
            };
            if let Event::App(AppEvent::CronWorkDone { done }) = &event {
                if done.jobs().iter().any(|job| crate::cron::is_log_job(*job)) {
                    passes += 1;
                }
            }
            app.handle_event(event).unwrap();
        }

        assert_eq!(passes, 1, "one pass for every due log job");
        for job in CronJob::all()
            .into_iter()
            .filter(|j| crate::cron::is_log_job(*j))
        {
            assert!(
                in_flight.contains(&Job::Cron(job)),
                "{} was not in it",
                job.id()
            );
        }
    }

    /// `check_cron` throttles against `Event::Tick`'s 30fps rate: two
    /// calls in immediate succession (as real ticks would produce) must
    /// only actually run due jobs once.
    #[tokio::test]
    async fn check_cron_is_throttled_against_rapid_repeated_ticks() {
        let mut app = test_app();
        mark_downloads_run(&app);
        app.last_cron_check =
            std::time::Instant::now() - CRON_CHECK_INTERVAL - std::time::Duration::from_secs(1);

        app.check_cron().unwrap();
        drain_background_work(&mut app).await;
        let first = app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::SshScanners).id())
            .unwrap();
        assert!(first.is_some());

        // A second call immediately after (simulating the next few ticks
        // at 30fps) must be a no-op: `last_cron_check` was just reset to
        // "now" inside the first call, so this one is still well within
        // `CRON_CHECK_INTERVAL`.
        app.check_cron().unwrap();
        let second = app
            .db
            .get_cron_last_run(CronJob::Detect(Detector::SshScanners).id())
            .unwrap();
        assert_eq!(first, second);
    }

    /// A scheduled job never starts beside itself: `due_jobs` still says
    /// it is due while its work is out, since `last_run` only moves when it
    /// finishes. Seen through the lease, which a crawler job that started
    /// would have taken.
    #[tokio::test]
    async fn a_scheduled_job_does_not_start_while_its_own_work_is_out() {
        let mut app = test_app();
        app.jobs_in_flight
            .insert(Job::Cron(CronJob::UpdateIpRanges));

        app.start_cron_job(crate::cron::Task::Job(CronJob::UpdateIpRanges))
            .unwrap();

        let claim = crate::refresh::claim(&app.db, now_secs()).unwrap();
        assert!(
            matches!(claim, crate::refresh::Claim::Granted(_)),
            "a second crawler job took the lease: {claim:?}"
        );
    }

    /// The property one job layer exists for: whatever is due, the TUI
    /// runs it and records what `tick` would. Both are handed the same
    /// database state and the same logs, and every job's summary is
    /// compared — so a job one of them skips, or runs differently, shows
    /// up here by name.
    #[tokio::test]
    async fn the_tui_records_what_tick_records_for_every_due_job() {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access.log");
        std::fs::write(
            &access,
            format!(
                "203.0.113.50 - - [{}] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n",
                crate::testing::nginx_time(now_secs() - 60)
            ),
        )
        .unwrap();
        let ssh = dir.path().join("auth.log");
        std::fs::write(&ssh, "").unwrap();
        let host = crate::hostconf::HostConf {
            access_log: Some(access),
            ..Default::default()
        };
        let host_conf = dir.path().join("host.conf");
        host.save_to(&host_conf).unwrap();
        let firewall_out = dir.path().join("firewall.nft");
        // The jobs that reach the network or the host itself, marked just
        // run in both: everything else is due on a fresh database.
        let seed = |db: &Db| {
            for job in [
                CronJob::UpdateIpRanges,
                CronJob::UpdateEverything,
                CronJob::HealthCheck,
            ] {
                db.set_cron_last_run(job.id(), now_secs(), "skipped for test")
                    .unwrap();
            }
        };

        let mut app = App::new(
            Db::open_in_memory().unwrap(),
            dir.path().to_path_buf(),
            false,
            Some(ssh.clone()),
        )
        .unwrap();
        app.host_conf = host_conf;
        app.firewall_out = Some(firewall_out.clone());
        seed(&app.db);
        app.check_cron().unwrap();
        drain_background_work(&mut app).await;

        let db = Db::open_in_memory().unwrap();
        seed(&db);
        let settings = crate::cron::TickSettings {
            host: &host,
            root: dir.path(),
            ssh_log: Some(ssh),
            firewall_out: Some(&firewall_out),
        };
        crate::cron::tick(&db, &settings).await.unwrap();

        let summaries = |db: &Db| -> Vec<(&'static str, Option<String>)> {
            crate::cron::status(db)
                .unwrap()
                .into_iter()
                .map(|status| (status.job.id(), status.last_summary))
                .collect()
        };
        let (tui, tick) = (summaries(&app.db), summaries(&db));
        for ((job, by_tui), (_, by_tick)) in tui.iter().zip(&tick) {
            assert_eq!(by_tui, by_tick, "{job}: the TUI and tick disagree");
        }
        assert!(
            tui.iter().any(|(job, summary)| *job == "block_probe_paths"
                && summary.as_deref() == Some("blocked 1 IP(s)")),
            "the probe was not blocked, so this compared nothing: {tui:?}"
        );
    }

    // ---- the lockout guard on the apply path ----

    /// The bug that took a real server off the network.
    ///
    /// `LogUnavailable` used to fall through the check silently, so on any
    /// host where the SSH log isn't readable the script was written — and,
    /// with the render popup's "apply after writing" toggle, *applied* —
    /// with no lockout check and no warning.
    #[tokio::test]
    async fn an_apply_is_refused_when_the_lockout_check_cannot_run() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("firewall.nft");
        let mut app = App::new(
            Db::open_in_memory().unwrap(),
            std::path::PathBuf::from("/etc/nginx"),
            false,
            Some(std::path::PathBuf::from("/nonexistent/auth.log")),
        )
        .unwrap();

        app.start_firewall_render(
            crate::firewall::FirewallBackend::Nftables,
            out.to_str().unwrap().to_string(),
            false,
            true,
        );
        drain_background_work(&mut app).await;

        let message = app.message.clone().unwrap();
        assert!(
            crate::firewall::rendered_path(&out).exists(),
            "writing is inert, so it still happens: {message}"
        );
        assert!(!out.exists(), "nothing applied, so no boot script");
        assert!(message.contains("not applied"), "message was: {message}");
        assert!(message.contains("lockout"), "message was: {message}");
        assert!(message.contains("--ssh-log"), "message was: {message}");
    }

    /// Forcing is still the way through for someone who knows the log is
    /// missing and means it — here as far as `--no-apply` lets it go.
    #[tokio::test]
    async fn force_gets_an_apply_past_a_lockout_check_that_cannot_run() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("firewall.nft");
        let mut app = App::new(
            Db::open_in_memory().unwrap(),
            std::path::PathBuf::from("/etc/nginx"),
            false,
            Some(std::path::PathBuf::from("/nonexistent/auth.log")),
        )
        .unwrap();

        app.start_firewall_render(
            crate::firewall::FirewallBackend::Nftables,
            out.to_str().unwrap().to_string(),
            true,
            true,
        );
        drain_background_work(&mut app).await;

        let message = app.message.clone().unwrap();
        assert!(
            message.contains("not applied: --no-apply"),
            "past the guard, stopped only by the switch: {message}"
        );
    }

    /// The check has to actually use the configured log — it was passing
    /// `None` and auto-detecting, so the `--ssh-log` override never
    /// reached it.
    #[tokio::test]
    async fn render_firewall_refuses_to_block_the_connected_admin() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("firewall.nft");
        let db = Db::open_in_memory().unwrap();
        // The fixture log's Accepted line is for 192.0.2.10.
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "192.0.2.0/24".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        let mut app = App::new(
            db,
            std::path::PathBuf::from("/etc/nginx"),
            false,
            Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
        )
        .unwrap();

        app.start_firewall_render(
            crate::firewall::FirewallBackend::Nftables,
            out.to_str().unwrap().to_string(),
            false,
            false,
        );
        drain_background_work(&mut app).await;

        assert!(!out.exists(), "message was: {:?}", app.message);
        let message = app.message.clone().unwrap();
        assert!(message.contains("192.0.2.10"), "message was: {message}");
    }
}
