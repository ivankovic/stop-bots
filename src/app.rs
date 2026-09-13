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

//! The app controller: owns all TUI state, runs the event loop, and routes
//! key presses to the active screen (falling back to global key handling).

use crate::botlist;
use crate::cron::CronJob;
use crate::db::Db;
use crate::event::{AppEvent, Event, EventHandler};
use crate::ipranges;
use crate::nginx;
use crate::tui::{self, KeyOutcome, Screen, Theme};
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
    /// Reading the SSH log that Dynamic Protection's SSH panel is built
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
    /// Writing the NGINX config that serves this console, and running
    /// `nginx -t` over it. See [`App::start_web_access`].
    ApplyWebAccess,
    /// Reading each site's config file to work out whether its block is
    /// current. See [`App::start_site_status_check`].
    CheckSiteStatuses,
    /// Downloading every list this host uses, one source at a time. See
    /// [`App::start_update_everything`].
    UpdateEverything,
}

impl Job {
    /// What the footer calls this while it is running. Phrased as what is
    /// happening, not as the name of a function, since this is the only
    /// thing on screen explaining why the admin is waiting.
    pub fn label(&self) -> String {
        match self {
            Job::Cron(job) => format!("{} (scheduled)", job.label()),
            Job::ReadSshLog => "reading the SSH log".to_string(),
            Job::ReloadNginx => "reloading NGINX".to_string(),
            Job::RenderFirewall => "writing the firewall script".to_string(),
            Job::ScanSites => "scanning the NGINX config".to_string(),
            Job::ApplySites => "writing site config".to_string(),
            Job::ApplyWebAccess => "setting up NGINX for this console".to_string(),
            Job::CheckSiteStatuses => "checking site config".to_string(),
            Job::UpdateEverything => "downloading every list".to_string(),
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
    pub db: Db,
    pub dashboard: tui::dashboard::Dashboard,
    pub bot_settings: tui::bot_settings::BotSettings,
    pub site_settings: tui::site_settings::SiteSettings,
    pub dynamic_protection: tui::dynamic_protection::DynamicProtection,
    /// When the internal cron last checked for due jobs — throttles the
    /// check against `Event::Tick`'s 30fps rate (see
    /// [`CRON_CHECK_INTERVAL`]).
    last_cron_check: std::time::Instant,
    /// The SSH log as last read, and when. Dynamic Protection's SSH panel
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
    /// tests in `tests/tui.rs`, which drive a real Site settings "apply"
    /// through a real spawned binary — without this, that would shell out
    /// to the real `nginx -t`/`systemctl reload nginx` on whatever machine
    /// runs the test suite (see `main.rs`'s `tui --no-reload` flag, the
    /// same escape hatch `apply-blocks --no-reload` uses).
    reload_nginx_for_real: bool,
    /// SSH log override (`tui --ssh-log`). `None` auto-detects, which can
    /// mean shelling out to `journalctl` — on some hosts more than half a
    /// second per call, and this is consulted on every refresh of the
    /// Dynamic Protection screen, every `BlockScanners` cron pass and every
    /// firewall render's lockout check. The override makes all three
    /// deterministic (and fast) for tests, and usable on hosts with a
    /// non-standard log path.
    ssh_log: Option<std::path::PathBuf>,
    /// Whether a render popup confirmed with "apply after writing" actually
    /// calls `firewall::apply_script()`. Same shape and same reason as
    /// `reload_nginx_for_real`: always `true` for real usage, `false` only for tests
    /// — without this, a test requesting `apply: true` would shell out to
    /// the real `nft -f`/`sh` against whatever host runs the suite. Shares
    /// `main.rs`'s `--no-reload` flag rather than getting its own, since
    /// both exist for exactly the same "don't really execute system-
    /// changing commands under test" reason.
    apply_firewall: bool,
    /// Where "Apply everything" writes the firewall script. `None` means
    /// "follow the backend", which is what [`crate::firewall::output_path`]
    /// does: an nftables render lands in `.nft` and an iptables one in
    /// `.sh`.
    ///
    /// A field rather than a call at the point of use for the same reason
    /// the console has one: the default is a real path under `/etc`, and a
    /// test that presses the key must be able to point it somewhere
    /// harmless. The render *popup* takes its path from the admin instead,
    /// which is why this only covers the one-key path.
    pub firewall_out: Option<std::path::PathBuf>,
    /// An "update everything" run in progress: the sources still to fetch
    /// and what the finished ones came to. `None` when none is running.
    ///
    /// One source at a time, deliberately. The whole plan is eight or more
    /// downloads of several megabytes each; fetching them all at once
    /// would hold every payload in memory and show nothing until the last
    /// one landed, while one-at-a-time keeps it to a single body and gives
    /// the message line something true to say throughout.
    update_all: Option<UpdateAllRun>,
    /// Set while "Apply everything" is waiting on its NGINX half, so
    /// [`App::finish_site_apply`] knows to start the firewall half after
    /// it. The two are independent — whichever fails, the other still gets
    /// its turn — they are merely sequenced so that their messages do not
    /// overwrite each other.
    apply_everything: bool,
}

/// The state of one "Apply everything"/"Update everything"'s update half.
struct UpdateAllRun {
    /// Sources not yet fetched, in plan order, popped from the front.
    remaining: std::collections::VecDeque<crate::refresh::Source>,
    /// How many stored cleanly so far.
    done: usize,
    /// `"<source>: <error>"` for each that did not, to report at the end.
    failures: Vec<String>,
    /// Every outcome so far, which is what
    /// [`crate::refresh::crawler_ranges_all_succeeded`] needs to decide
    /// whether the `UpdateIpRanges` job can be marked run.
    outcomes: Vec<(crate::refresh::Source, Result<String, String>)>,
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

/// What [`App::start_firewall_render`] hands to the background thread. A struct
/// rather than five positional parameters, three of which are flags.
struct RenderRequest {
    backend: crate::firewall::FirewallBackend,
    out_path: String,
    force: bool,
    apply: bool,
    ssh_log: Option<std::path::PathBuf>,
}

/// A successful background render, for the main thread to record.
#[derive(Clone, Debug)]
pub struct RenderOutcome {
    /// What to show the admin. Carries whether the script was also
    /// applied, and how to apply it by hand when it wasn't.
    pub message: String,
}

/// The blocking half of a firewall render: the lockout check, the write,
/// and — if asked — `nft -f`/`sh`.
///
/// Runs on the blocking pool, so it touches no `Db`. The lockout check
/// reads the SSH log *live*, every time, and must keep doing so: it is the
/// one guard standing between a keypress and a server that can no longer
/// be reached. `App::ssh_log_text`, the cached copy Dynamic Protection
/// draws from, must never reach this.
fn render_firewall_off_thread(
    request: RenderRequest,
    built: &crate::firewall::BuiltFirewall,
) -> Result<RenderOutcome, String> {
    let RenderRequest {
        backend,
        out_path,
        force,
        apply,
        ssh_log,
    } = request;

    // Both outcomes have to be handled, and the second one is why this is
    // a `match` rather than an `if let`.
    //
    // `LogUnavailable` used to fall straight through: on any host where
    // the SSH log isn't readable — not running as root, or a journald-only
    // system where `journalctl` returns nothing — the guard silently did
    // nothing and the script was written *and applied* with no warning at
    // all. That is the one path in this project that can take a server off
    // the network, and it was the path with no check on it.
    //
    // The CLI has always printed a note and continued, which is defensible
    // there: a human is watching the terminal. Here the same key press can
    // apply the script immediately, so it refuses instead. `--force`, or
    // the CLI, remains the way through for someone who knows the log is
    // missing and means it anyway.
    match crate::firewall::assess_lockout_risk(&built.rules, ssh_log.as_deref()) {
        crate::firewall::LockoutStatus::LogUnavailable if !force => {
            return Err(
                "refusing to write: no SSH log could be read, so the lockout safety \
                        check could not run. Start the TUI with --ssh-log <path>, or run \
                        `stop-bots render-firewall` as root, which reports this and continues."
                    .to_string(),
            );
        }
        crate::firewall::LockoutStatus::Risks(risks) if !risks.is_empty() && !force => {
            let ips = risks
                .iter()
                .map(|(ip, cidr)| format!("{ip} (blocked by {cidr})"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "refusing to write: would block {} currently-connected SSH client \
                 IP address(es): {ips}",
                risks.len()
            ));
        }
        _ => {}
    }

    crate::firewall::write_script(std::path::Path::new(&out_path), &built.script)
        .map_err(|err| err.to_string())?;

    let message = if apply {
        match crate::firewall::apply_script(backend, std::path::Path::new(&out_path)) {
            Ok(()) => format!(
                "Firewall rules written to {out_path} and applied ({} rule(s)).",
                built.written
            ),
            Err(err) => format!(
                "Firewall rules written to {out_path}, but applying failed: {err}. \
                 Apply manually with: {} {out_path}",
                backend.apply_command()
            ),
        }
    } else {
        format!(
            "Firewall rules written to {out_path}. Review it, then apply with: {} {out_path}",
            backend.apply_command()
        )
    };
    Ok(RenderOutcome { message })
}

impl App {
    /// Constructs a new [`App`], loading initial state from `db`. `root` is
    /// the NGINX config root Site settings scans when the user triggers a
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
            db,
            dashboard: tui::dashboard::Dashboard::default(),
            bot_settings: tui::bot_settings::BotSettings::default(),
            site_settings: tui::site_settings::SiteSettings::new(root),
            dynamic_protection: tui::dynamic_protection::DynamicProtection::default(),
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
            firewall_out: None,
            update_all: None,
            apply_everything: false,
        };
        botlist::register_all_sources(&app.db)?;
        // Same reason bot-list sources are registered here: the Dashboard's
        // feed rows need something to show before any fetch has ever run,
        // otherwise a fresh install offers no way to turn one on. Safe to
        // repeat every startup — registration never touches an existing
        // row's `enabled` flag.
        crate::ipranges::reputation::register_all_reputation_sources(&app.db)?;
        app.refresh_all()?;
        Ok(app)
    }

    /// Reloads the screen on display and marks the rest stale, to be
    /// reloaded when they next come into view.
    ///
    /// This used to reload all four eagerly, on every single mutation, and
    /// most of that work was then thrown away unlooked at: toggling one
    /// category default on the Dashboard also made Dynamic Protection
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
            Screen::SiteSettings => {
                self.site_settings.refresh(&self.db)?;
                // Same shape as the SSH log read above: `refresh` no
                // longer reads every site's config file itself, so kick
                // off the check that does.
                self.start_site_status_check()
            }
            Screen::DynamicProtection => {
                // Kicked off here rather than on entering the screen: this
                // is the one place every route to a visible SSH panel goes
                // through, and the freshness check makes repeating it
                // harmless.
                self.start_ssh_log_read();
                self.dynamic_protection
                    .refresh(&self.db, self.ssh_log_text.as_deref())
            }
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
        while self.running {
            self.refresh_if_stale()?;
            terminal.draw(|frame| tui::render(&mut self, frame))?;
            let event = self.events.next().await?;
            self.handle_event(event)?;
        }
        Ok(())
    }

    /// Dispatches a single event. Split out of `run` so tests can drive the
    /// event loop one event at a time (e.g. to apply a background cron
    /// job's result) without needing a real terminal.
    fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Tick => self.check_cron()?,
            Event::Crossterm(crossterm::event::Event::Key(key_event))
                if key_event.kind == KeyEventKind::Press =>
            {
                self.handle_key_event(key_event)?;
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
            Event::App(AppEvent::ReputationFetchFinished { source_id, result }) => {
                self.finish_reputation_fetch(source_id, result)?;
            }
            Event::App(AppEvent::CronIpRangesFetched { results }) => {
                self.finish_cron_update_ip_ranges(results)?;
            }
            Event::App(AppEvent::CronLogFetched { job, log_text }) => {
                self.finish_cron_log_job(job, log_text)?;
            }
            Event::App(AppEvent::SshLogRead { text }) => self.finish_ssh_log_read(text)?,
            Event::App(AppEvent::NginxReloaded { result }) => self.finish_nginx_reload(result),
            Event::App(AppEvent::FirewallRendered { signature, outcome }) => {
                self.finish_firewall_render(signature, outcome)?
            }
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
            Event::App(AppEvent::EverythingSourceFetched { source, result }) => {
                self.finish_update_everything_source(source, result)?
            }
            Event::App(AppEvent::WebAccessApplied { plan, result }) => {
                self.finish_web_access(*plan, result)?
            }
            Event::App(AppEvent::HealthProbed { probe }) => {
                self.finish_cron_health_check(*probe)?
            }
        }
        Ok(())
    }
    // ---- background work: every `start_` has a `finish_` ----
    //
    // The shape is the same fourteen times over, and it is the reason the
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
    /// Assembles the per-address detail the Dynamic Protection screen
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
        let status = self.dynamic_protection.status_of(address);
        let detail = crate::ipdetail::IpDetail::load(&self.db, address, status, usernames)?;
        self.dynamic_protection.show_detail(detail);
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
                parse_off_thread(move || kind.parse(&raw)).await
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
        result: Result<Vec<crate::db::NewBot>, String>,
    ) -> Result<()> {
        let name = source_display_name(&source_id);
        match result {
            Ok(bots) => {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .expect("source_id always came from a known SourceKind::id()");
                let count = botlist::store(&self.db, kind, &bots)?;
                self.message = Some(format!("Stored {count} bot(s) from {name}"));
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
                        "{name}: {count} range(s) stored — render the firewall (f) to apply"
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
    /// rate via [`CRON_CHECK_INTERVAL`], runs whichever jobs are currently
    /// due. Never surfaces a `Result` error out of a single job to the
    /// user as a hard failure — a background job failing (e.g. the SSH log
    /// being unreadable) is recorded as that job's own summary, not
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
        for job in due {
            self.run_cron_job(job)?;
        }
        self.refresh()?;
        Ok(())
    }

    fn run_cron_job(&mut self, job: CronJob) -> Result<()> {
        match job {
            CronJob::UpdateIpRanges => self.start_cron_update_ip_ranges(),
            CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::RenderFirewall => {
                self.start_cron_log_job(job)
            }
            CronJob::HealthCheck => self.start_cron_health_check(),
        }
        Ok(())
    }

    /// Starts the `UpdateIpRanges` job's background fetch (Googlebot,
    /// Bingbot, GPTBot — the same three `ipranges::IpRangeSourceKind::ALL`
    /// sources `update-ip-ranges` fetches). Guarded by
    /// `jobs_in_flight` so a slow round-trip to all three hosts can't
    /// overlap with itself if `check_cron` finds the job still "due" (its
    /// `last_run` doesn't update until it actually finishes) on a later
    /// tick. Only fetches and parses in the background, same
    /// `Db`-isn't-`Sync` reasoning as `start_source_update`/
    /// `start_country_select`: storing happens back on the main thread in
    /// `finish_cron_update_ip_ranges`.
    fn start_cron_update_ip_ranges(&mut self) {
        if !self
            .jobs_in_flight
            .insert(Job::Cron(CronJob::UpdateIpRanges))
        {
            return;
        }
        let sender = self.events.sender();
        tokio::spawn(async move {
            let results = crate::cron::fetch_ip_ranges().await;
            let _ = sender.send(Event::App(AppEvent::CronIpRangesFetched { results }));
        });
    }

    /// Stores whichever of the three crawler sources' fetches succeeded
    /// (one failing, e.g. a transient network error, shouldn't discard
    /// what the other two got) and records the job's outcome, run back on
    /// the main thread once `start_cron_update_ip_ranges`'s background
    /// fetch completes.
    fn finish_cron_update_ip_ranges(
        &mut self,
        results: Vec<(ipranges::IpRangeSourceKind, Result<Vec<String>, String>)>,
    ) -> Result<()> {
        self.jobs_in_flight
            .remove(&Job::Cron(CronJob::UpdateIpRanges));

        crate::cron::store_ip_ranges(&self.db, results)?;
        self.refresh()?;
        Ok(())
    }

    /// Starts the log-resolution step of a `BlockScanners`/
    /// `BlockWebScanners`/`RecordAccessStats`/`RenderFirewall` cron job on
    /// a background thread. `find_default_source` (`sshlog`/`accesslog`) is
    /// blocking I/O — reading the log file directly, and for the SSH log,
    /// shelling out to `journalctl` as a fallback when no log file exists —
    /// which was hanging the whole TUI (nothing redraws or handles input
    /// while the main thread blocks on it). `tokio::task::spawn_blocking`
    /// runs this on Tokio's separate blocking-thread pool rather than a
    /// worker thread the event loop needs, unlike `start_cron_update_ip_ranges`
    /// (real async I/O, so a plain `tokio::spawn` task is enough there).
    /// Guarded by `jobs_in_flight`, same reasoning as `UpdateIpRanges`.
    /// Only the log *read* moves off-thread: the parsing/counting/`Db`
    /// writes that follow stay on the main thread in `finish_cron_log_job`,
    /// same `Db`-isn't-`Sync` pattern as every other background task here —
    /// they're fast (in-memory line scans), so there's no benefit to moving
    /// them and a second `Db` connection would fight that pattern for no
    /// reason.
    fn start_cron_log_job(&mut self, job: CronJob) {
        if !self.jobs_in_flight.insert(Job::Cron(job)) {
            return;
        }
        let sender = self.events.sender();
        let ssh_log = self.ssh_log.clone();
        tokio::task::spawn_blocking(move || {
            let log_text = crate::cron::read_log_for(job, ssh_log.as_deref());
            let _ = sender.send(Event::App(AppEvent::CronLogFetched { job, log_text }));
        });
    }

    /// Works out each site's UP TO DATE / STALE tag in the background.
    ///
    /// One config file read and one block re-render per site, which used
    /// to happen inside `SiteSettings::refresh` — so every change to
    /// anything on that screen paid for all of them before redrawing. The
    /// `Db` half (each site's resolved `BlockConfig`) stays here.
    fn start_site_status_check(&mut self) -> Result<()> {
        if self.jobs_in_flight.contains(&Job::CheckSiteStatuses) {
            self.site_statuses_pending = true;
            return Ok(());
        }
        let plan = self.site_settings.plan_status_check(&self.db)?;
        if plan.is_empty() {
            // No sites, so nothing to read and nothing to wait for. Said
            // explicitly because an empty check would otherwise leave the
            // tags reading "checking" forever.
            self.site_settings.finish_status_check(Vec::new());
            return Ok(());
        }
        self.jobs_in_flight.insert(Job::CheckSiteStatuses);
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let statuses = crate::tui::site_settings::run_status_check(&plan);
            let _ = sender.send(Event::App(AppEvent::SiteStatusesChecked { statuses }));
        });
        Ok(())
    }

    /// Adopts a finished background status check, and starts another if
    /// something changed while it was out.
    fn finish_site_status_check(
        &mut self,
        statuses: Vec<crate::nginx::SiteApplyStatus>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::CheckSiteStatuses);
        self.site_settings.finish_status_check(statuses);
        if std::mem::take(&mut self.site_statuses_pending) {
            self.start_site_status_check()?;
        }
        Ok(())
    }

    /// Starts one of Site settings' filesystem actions in the background.
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
    fn start_site_action(&mut self, action: crate::tui::site_settings::SiteAction) -> Result<()> {
        use crate::tui::site_settings::SiteAction;

        let job = match action {
            SiteAction::Scan => Job::ScanSites,
            SiteAction::Apply(_) | SiteAction::ApplyAll => Job::ApplySites,
        };
        if self.jobs_in_flight.contains(&job) {
            self.message = Some(format!("Already {}.", job.label()));
            return Ok(());
        }

        let sender = self.events.sender();
        match action {
            SiteAction::Scan => {
                self.jobs_in_flight.insert(job);
                let root = self.site_settings.root().to_path_buf();
                tokio::task::spawn_blocking(move || {
                    let sites = nginx::discover_sites(&root).map_err(|err| err.to_string());
                    let _ = sender.send(Event::App(AppEvent::SitesScanned { sites }));
                });
            }
            SiteAction::Apply(_) | SiteAction::ApplyAll => {
                let plan = match self.site_settings.plan_apply(&self.db, action) {
                    Ok(plan) => plan,
                    Err(err) => {
                        self.message = Some(format!("Apply failed: {err}"));
                        return Ok(());
                    }
                };
                self.jobs_in_flight.insert(job);
                tokio::task::spawn_blocking(move || {
                    let outcome = crate::tui::site_settings::run_apply(plan);
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
        sites: Result<Vec<nginx::DiscoveredSite>, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ScanSites);
        self.message = Some(self.site_settings.finish_scan(&self.db, sites));
        self.refresh()
    }

    /// Records a finished background apply, and reloads NGINX if any file
    /// actually changed — the same condition the inline version used, just
    /// evaluated here rather than in the key handler.
    fn finish_site_apply(
        &mut self,
        outcome: crate::tui::site_settings::ApplyOutcome,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ApplySites);
        let (message, changed_a_file) = self.site_settings.finish_apply(outcome);
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

    /// Reloads NGINX in the background, after Site settings has written a
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
        let commands = match nginx::NginxCommands::from_db(&self.db) {
            Ok(commands) => commands,
            Err(err) => {
                self.jobs_in_flight.remove(&Job::ReloadNginx);
                self.message = Some(format!("failed to reload NGINX: {err}"));
                return;
            }
        };
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let result = nginx::reload_with(&commands).map_err(|err| err.to_string());
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
            self.message = Some(format!("{applied} — failed to reload NGINX: {err}"));
        }
        if std::mem::take(&mut self.reload_nginx_pending) {
            self.start_nginx_reload();
        }
    }

    /// Reads the SSH log into [`App::ssh_log_text`], in the background, if
    /// the copy on hand has gone stale ([`SSH_LOG_MAX_AGE`]) and no read is
    /// already out.
    ///
    /// The read itself is what has to move off the event loop: with no
    /// `--ssh-log` override and no readable `auth.log`, resolving the log
    /// means a `journalctl` subprocess. Doing that inline, on every reload
    /// of Dynamic Protection, is what made this screen the slowest in the
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
        let ssh_log = self.ssh_log.clone();
        tokio::task::spawn_blocking(move || {
            let source = match ssh_log.as_deref() {
                Some(path) => crate::sshlog::read_log_file(path),
                None => crate::sshlog::find_default_source(),
            };
            let text = match source {
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
        if self.screen == Screen::DynamicProtection {
            self.dynamic_protection
                .refresh(&self.db, self.ssh_log_text.as_deref())?;
        } else {
            self.stale.insert(Screen::DynamicProtection);
        }
        Ok(())
    }

    /// Applies a log cron job's background-resolved log text (`None` if
    /// the log was unavailable) back on the main thread, then refreshes
    /// every screen — mirroring `finish_cron_update_ip_ranges`. The job
    /// itself, and the recording of its outcome, is
    /// [`crate::cron::run_log_job`]: shared with the web front-end so that
    /// the two can't drift.
    fn finish_cron_log_job(&mut self, job: CronJob, log_text: Option<String>) -> Result<()> {
        self.jobs_in_flight.remove(&Job::Cron(job));
        // `None`: no override, so the path follows the stored backend —
        // an nftables render lands in `.nft` and an iptables one in `.sh`.
        crate::cron::run_log_job(&self.db, job, log_text.as_deref(), None)?;
        self.refresh()?;
        Ok(())
    }

    /// Renders firewall rules to a script file, calling the same
    /// `stop_bots::firewall` logic the CLI's `render-firewall` subcommand
    /// uses directly — including the allowlist/iptables guard and the
    /// lockout safety check — rather than shelling out to a `stop-bots`
    /// binary that may not even be the one currently running (e.g. under
    /// `cargo run`, or any install not on `$PATH` under that exact name).
    /// `apply`, from the render popup's "apply after writing" toggle
    /// (`Popup::RenderFirewall::apply_after_write`), additionally runs
    /// `firewall::apply_script` once the write succeeds — but only when
    /// `self.apply_firewall` is set (see that field's doc comment); when
    /// it isn't (tests), this behaves exactly like `apply: false` rather
    /// than silently claiming success for a subprocess it never ran.
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

        // Built here, on the main thread, because it reads the whole rule
        // set out of `Db` — which isn't `Sync`. What goes to the
        // background is everything after: the lockout check (a live SSH
        // log read, which is the slow part), the write, and `nft -f`.
        let built = match crate::firewall::build_script(&self.db, backend) {
            Ok(built) => built,
            Err(err) => {
                self.message = Some(format!("Failed to render firewall rules: {err}"));
                return;
            }
        };

        self.jobs_in_flight.insert(Job::RenderFirewall);
        let signature = crate::firewall::rules_signature(&built.rules);
        let apply = apply && self.apply_firewall;
        let ssh_log = self.ssh_log.clone();
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let outcome = render_firewall_off_thread(
                RenderRequest {
                    backend,
                    out_path,
                    force,
                    apply,
                    ssh_log,
                },
                &built,
            );
            let _ = sender.send(Event::App(AppEvent::FirewallRendered {
                signature,
                outcome,
            }));
        });
    }

    /// Applies a finished background render: the message either way, and
    /// the rendered-rules signature when a script really was written. The
    /// signature is what the Dashboard's "needs updating" row compares
    /// against, and it is a `Db` write, so it waits for the main thread
    /// like every other one.
    fn finish_firewall_render(
        &mut self,
        signature: String,
        outcome: Result<RenderOutcome, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::RenderFirewall);
        match outcome {
            Ok(outcome) => {
                self.db.set_firewall_rendered_signature(&signature)?;
                self.message = Some(outcome.message);
            }
            Err(err) => self.message = Some(format!("Failed to render firewall rules: {err}")),
        }
        // The signature the Dashboard's "needs updating" row compares
        // against has just moved, so that row is stale wherever it is.
        self.refresh()
    }

    /// Downloads every list this host uses, one source at a time — the
    /// TUI's half of what `stop-bots batch` and the console's "Update
    /// everything" button do, through the same [`crate::refresh::plan`].
    ///
    /// One source failing is reported and the rest still run: these are
    /// eight third parties, and a transient failure at one of them is not
    /// a reason to leave the other seven stale.
    fn start_update_everything(&mut self) {
        if self.jobs_in_flight.contains(&Job::UpdateEverything) {
            self.message = Some("Already downloading every list.".to_string());
            return;
        }

        // Planning reads `Db`, so it happens here, on the main thread.
        let plan = match crate::refresh::plan(&self.db) {
            Ok(plan) => plan,
            Err(err) => {
                self.message = Some(format!("Could not work out what to update: {err}"));
                return;
            }
        };
        self.jobs_in_flight.insert(Job::UpdateEverything);
        self.update_all = Some(UpdateAllRun {
            remaining: plan.into(),
            done: 0,
            failures: Vec::new(),
            outcomes: Vec::new(),
        });
        self.fetch_next_everything_source();
    }

    /// Sends the next source of an in-flight "update everything" to the
    /// network, or finishes the run when there is none left.
    fn fetch_next_everything_source(&mut self) {
        let Some(run) = self.update_all.as_mut() else {
            return;
        };
        let Some(source) = run.remaining.pop_front() else {
            self.finish_update_everything();
            return;
        };

        self.message = Some(format!("Downloading {}\u{2026}", source.label()));
        let sender = self.events.sender();
        // A runtime task rather than the blocking pool: `refresh::fetch`
        // is `async` all the way down, and it touches no `Db`.
        tokio::spawn(async move {
            let result = crate::refresh::fetch(&source)
                .await
                .map_err(|err| format!("{err:#}"));
            let _ = sender.send(Event::App(AppEvent::EverythingSourceFetched {
                source,
                result,
            }));
        });
    }

    /// Stores one downloaded source and starts the next.
    ///
    /// Storing is a `Db` write, so it waits for the main thread like every
    /// other one — which is also why the event carries the raw body rather
    /// than parsed rows.
    fn finish_update_everything_source(
        &mut self,
        source: crate::refresh::Source,
        result: Result<String, String>,
    ) -> Result<()> {
        // A run that was never started (or already finished) has nothing
        // to record. Reachable only if an event outlives its run, but
        // dropping it beats panicking on a live server.
        if self.update_all.is_none() {
            return Ok(());
        }

        let outcome = match result {
            Ok(raw) => {
                crate::refresh::store(&self.db, &source, &raw).map_err(|err| format!("{err:#}"))
            }
            Err(err) => Err(err),
        };
        let run = self.update_all.as_mut().expect("checked above");
        match &outcome {
            Ok(_) => run.done += 1,
            Err(err) => run.failures.push(format!("{}: {err}", source.label())),
        }
        run.outcomes.push((source, outcome));

        self.fetch_next_everything_source();
        // Every source is a list something on screen counts or dates, so
        // the screens are stale whether this one stored or not.
        self.refresh()
    }

    /// Reports a finished "update everything" and clears its state.
    fn finish_update_everything(&mut self) {
        self.jobs_in_flight.remove(&Job::UpdateEverything);
        let Some(run) = self.update_all.take() else {
            return;
        };

        // Only when all three crawler sources worked, for the reason
        // `refresh::crawler_ranges_all_succeeded` documents.
        if crate::refresh::crawler_ranges_all_succeeded(&run.outcomes) {
            crate::cron::record_run(
                &self.db,
                crate::cron::CronJob::UpdateIpRanges,
                "updated from the Dashboard",
            );
        }

        self.message = Some(if run.failures.is_empty() {
            format!("Updated {} list(s).", run.done)
        } else {
            format!(
                "Updated {} list(s). {} failed \u{2014} {}",
                run.done,
                run.failures.len(),
                run.failures.join("; ")
            )
        });
    }

    /// Writes and enforces both planes: the NGINX config, then the
    /// firewall — the TUI's half of the console's "Apply everything".
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
        self.start_site_action(crate::tui::site_settings::SiteAction::ApplyAll)?;
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

    /// Puts this console behind NGINX, on a subdomain or a path prefix.
    ///
    /// Split across the thread boundary exactly the way
    /// [`crate::webaccess`]'s three functions are: plan here, where `Db`
    /// lives; write and `nginx -t` on the blocking pool; record the new
    /// address back here once it validated.
    fn start_web_access(&mut self, request: crate::webaccess::Request) {
        if self.jobs_in_flight.contains(&Job::ApplyWebAccess) {
            self.message = Some("Already setting NGINX up for this console.".to_string());
            return;
        }

        let plan = match crate::webaccess::plan(&self.db, &request) {
            Ok(plan) => plan,
            Err(err) => {
                self.message = Some(format!("{err:#}"));
                return;
            }
        };

        self.jobs_in_flight.insert(Job::ApplyWebAccess);
        let root = self.site_settings.root().to_path_buf();
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let result = crate::webaccess::apply(&plan, &root).map_err(|err| format!("{err:#}"));
            let _ = sender.send(Event::App(AppEvent::WebAccessApplied {
                plan: Box::new(plan),
                result,
            }));
        });
    }

    /// Records the address the console now answers to, and reloads NGINX.
    fn finish_web_access(
        &mut self,
        plan: crate::webaccess::Plan,
        result: Result<std::path::PathBuf, String>,
    ) -> Result<()> {
        self.jobs_in_flight.remove(&Job::ApplyWebAccess);
        match result {
            Ok(path) => {
                crate::webaccess::record(&self.db, &plan)?;
                self.message = Some(format!(
                    "Wrote {} and recorded the host. Restart the console for a changed path \
                     prefix to take effect.",
                    path.display()
                ));
                self.start_nginx_reload();
            }
            Err(err) => self.message = Some(format!("Web access setup failed: {err}")),
        }
        self.refresh()
    }

    /// Probes the host for the internal cron's health check.
    ///
    /// The probe shells out to `nft`, `systemctl` and `df` — `nft list` on
    /// a large ruleset is megabytes of text — so it goes to the blocking
    /// pool. The database reads it needs (which backend, where the file
    /// is) happen here first, on the main thread, like every other pair.
    fn start_cron_health_check(&mut self) {
        let job = Job::Cron(CronJob::HealthCheck);
        if self.jobs_in_flight.contains(&job) {
            return;
        }
        let backend = match crate::firewall::stored_backend(&self.db) {
            Ok(backend) => backend,
            Err(err) => {
                self.message = Some(format!("Could not read the firewall backend: {err}"));
                return;
            }
        };
        let db_path = self
            .db
            .path()
            .unwrap_or_else(|| std::path::PathBuf::from("./stop-bots.sqlite3"));

        self.jobs_in_flight.insert(job);
        let ssh_log = self.ssh_log.clone();
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let probe = crate::health::probe(backend, &db_path, ssh_log.as_deref());
            let _ = sender.send(Event::App(AppEvent::HealthProbed {
                probe: Box::new(probe),
            }));
        });
    }

    /// Records a finished probe and the one-line summary the Scheduled
    /// tasks panel shows.
    fn finish_cron_health_check(&mut self, probe: crate::health::Probe) -> Result<()> {
        self.jobs_in_flight.remove(&Job::Cron(CronJob::HealthCheck));
        crate::health::store_probe(&self.db, &probe)?;
        let summary = crate::health::assess(&self.db, &probe)?.headline();
        crate::cron::record_run(&self.db, CronJob::HealthCheck, &summary);
        self.refresh()
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
            self.events.send(AppEvent::Quit);
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
            Screen::SiteSettings => {
                self.site_settings
                    .handle_key(key, &self.db, &mut self.message)?
            }
            Screen::DynamicProtection => {
                self.dynamic_protection
                    .handle_key(key, &self.db, &mut self.message)?
            }
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
            KeyOutcome::RenderFirewall {
                backend,
                out_path,
                force,
                apply,
            } => {
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
                self.start_update_everything();
                return Ok(());
            }
            KeyOutcome::ApplyEverything => {
                self.start_apply_everything()?;
                return Ok(());
            }
            KeyOutcome::SetWebAccess(request) => {
                self.start_web_access(request);
                return Ok(());
            }
            KeyOutcome::Ignored => {}
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') if self.screen == Screen::Dashboard => {
                self.events.send(AppEvent::Quit);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Dashboard,
            KeyCode::Char('c') => self.theme = self.theme.toggle(),
            KeyCode::Char('?') => {
                self.before_help = self.screen;
                self.screen = Screen::Help;
            }
            KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('b') => self.screen = Screen::BotSettings,
            KeyCode::Char('s') => self.screen = Screen::SiteSettings,
            KeyCode::Char('p') => self.screen = Screen::DynamicProtection,
            // Left/Right and their vim h/l aliases cycle screens exactly
            // like Tab/Shift+Tab — all four only ever reach here when the
            // active screen's own `handle_key` returned `Ignored` for the
            // key (see `KeyOutcome`'s doc comment), so a screen that gives
            // Left/Right/h/l its own meaning (none currently do — Dynamic
            // Protection's own Tab/Shift+Tab panel switch is a separate,
            // narrower case, see `Screen`'s doc comment) would still take
            // priority, and a search/text-entry focus that owns every
            // `Char` already stops 'h'/'l' from leaking through, the same
            // way it already stops 'd'/'b'/'s'/'p' from jumping screens
            // mid-search.
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.screen = self.screen.next(),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.screen = self.screen.previous()
            }
            _ => {}
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
    use crate::firewall::FirewallBackend;
    use crate::protection::Detector;

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn test_app() -> App {
        // `reload_nginx: false` — no test here drives a Site settings apply
        // through `handle_key_event`, but this keeps it that way even if
        // one is added later, rather than relying on that staying true.
        App::new(
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
        .unwrap()
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
        assert_eq!(app.screen, Screen::DynamicProtection);
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
        assert_eq!(app.screen, Screen::DynamicProtection);
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
            Ok(vec![crate::testing::new_bot("badbot", source_id)]),
        )
        .unwrap();

        assert_eq!(app.db.list_bots().unwrap().len(), 1);
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

        assert!(app.db.list_bots().unwrap().is_empty());
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

        app.finish_cron_update_ip_ranges(vec![
            (
                IpRangeSourceKind::GoogleBot,
                Ok(vec!["8.8.8.0/24".to_string()]),
            ),
            (IpRangeSourceKind::BingBot, Err("timed out".to_string())),
        ])
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

    /// The four log-based cron jobs now resolve their log source on a
    /// background thread (see `App::start_cron_log_job`) rather than
    /// running inline, so tests that trigger them via `check_cron` must
    /// drive the resulting `CronLogFetched` events through the same
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
            "startup loads all four, so nothing starts out stale"
        );

        app.screen = Screen::Dashboard;
        app.refresh().unwrap();

        assert_eq!(
            app.stale,
            std::collections::HashSet::from([
                Screen::BotSettings,
                Screen::SiteSettings,
                Screen::DynamicProtection,
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
            app.stale.contains(&Screen::SiteSettings),
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

        assert!(std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("written"), "message was: {message}");
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

        assert!(std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("written"), "message was: {message}");
        assert!(!message.contains("applied"), "message was: {message}");
    }

    /// One source failing must not take the run down with it: the rest
    /// still get their turn, and the failure is named in the summary.
    #[tokio::test]
    async fn update_everything_names_a_failed_source_and_still_finishes() {
        let mut app = test_app();
        app.jobs_in_flight.insert(Job::UpdateEverything);
        app.update_all = Some(UpdateAllRun {
            remaining: std::collections::VecDeque::new(),
            done: 2,
            failures: Vec::new(),
            outcomes: Vec::new(),
        });

        app.finish_update_everything_source(
            crate::refresh::Source::CrawlerRanges(crate::ipranges::IpRangeSourceKind::GoogleBot),
            Err("timed out".to_string()),
        )
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
        app.update_all = Some(UpdateAllRun {
            remaining: std::collections::VecDeque::new(),
            done: 0,
            failures: Vec::new(),
            outcomes: Vec::new(),
        });

        app.finish_update_everything_source(
            crate::refresh::Source::CrawlerRanges(crate::ipranges::IpRangeSourceKind::GoogleBot),
            Ok(raw),
        )
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

        let written = dir.path().join("firewall.sh");
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

    /// The whole Web Access chain, in the order the split demands: plan
    /// on the main thread, write and validate off it, record the new
    /// address back on it. Recording only after the config validated is
    /// the part that matters — a host allowlist naming somewhere NGINX
    /// never got would lock the operator out of the page they were on.
    #[tokio::test]
    async fn w_mounts_the_console_on_a_site_and_then_records_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("example.conf");
        std::fs::write(
            &site,
            "server {\n    server_name example.com;\n    listen 443 ssl;\n}\n",
        )
        .unwrap();

        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", site.to_str().unwrap())
            .unwrap();
        // `nginx -t` would be the real one on whatever host runs the
        // suite, so point the check at a command that always agrees.
        db.set_text_setting(crate::nginx::NginxCommands::TEST_KEY, "/bin/true")
            .unwrap();
        let mut app = App::new(
            db,
            dir.path().to_path_buf(),
            false,
            Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
        )
        .unwrap();

        app.start_web_access(crate::webaccess::Request::Path {
            site: "example.com".to_string(),
            prefix: "/stop-bots/".to_string(),
        });
        drain_background_work(&mut app).await;

        let written = std::fs::read_to_string(&site).unwrap();
        assert!(
            written.contains("location /stop-bots/"),
            "the console location never landed:\n{written}"
        );
        assert_eq!(
            app.db
                .get_text_setting(crate::web::BASE_PATH_KEY)
                .unwrap()
                .as_deref(),
            Some("/stop-bots")
        );
        assert!(crate::web::configured_hosts(&app.db)
            .unwrap()
            .contains(&"example.com".to_string()));
    }

    /// A refusal from `nginx -t` must leave the console's own settings
    /// alone: the address it answers to is only true once NGINX agrees.
    #[tokio::test]
    async fn a_rejected_web_access_config_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("example.conf");
        std::fs::write(&site, "server {\n    server_name example.com;\n}\n").unwrap();

        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", site.to_str().unwrap())
            .unwrap();
        db.set_text_setting(crate::nginx::NginxCommands::TEST_KEY, "/bin/false")
            .unwrap();
        let mut app = App::new(
            db,
            dir.path().to_path_buf(),
            false,
            Some(std::path::PathBuf::from("tests/fixtures/logs/auth.log")),
        )
        .unwrap();

        app.start_web_access(crate::webaccess::Request::Path {
            site: "example.com".to_string(),
            prefix: "/stop-bots/".to_string(),
        });
        drain_background_work(&mut app).await;

        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("failed"), "message was: {message}");
        assert_eq!(
            app.db.get_text_setting(crate::web::BASE_PATH_KEY).unwrap(),
            None
        );
        assert!(crate::web::configured_hosts(&app.db).unwrap().is_empty());
        assert!(
            !std::fs::read_to_string(&site)
                .unwrap()
                .contains("stop-bots"),
            "a refused config must be rolled back"
        );
    }

    /// A successful write must persist the rendered rule-set signature
    /// (`Db::get_firewall_rendered_signature`), which is what the
    /// Dashboard's Summary panel compares against to show "up to date"
    /// instead of "needs updating" right after a render.
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
    /// end to end (via the real 'f' keypress, backspacing the default path
    /// out and typing a writable temp one, then Enter) to prove that arm
    /// actually calls `self.refresh()` afterward — without it, the Summary
    /// panel would keep reading "needs updating" right after the admin did
    /// exactly what its own hint told them to do.
    #[tokio::test]
    async fn pressing_f_then_enter_refreshes_the_dashboards_stale_indicator() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft");
        let out_path_str = out_path.to_str().unwrap().to_string();

        assert!(app.dashboard.firewall_needs_update());

        app.handle_key_event(KeyEvent::from(KeyCode::Char('f')))
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
            out_path.exists(),
            "message was: {:?}",
            app.message.as_deref()
        );
        assert!(!app.dashboard.firewall_needs_update());
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

    // The lockout-risk branch itself (skip if `LockoutStatus::Risks` is
    // non-empty and not forced) is exercised thoroughly against
    // `firewall::assess_lockout_risk`/`lockout_risks` directly in
    // `firewall.rs`'s tests. It isn't re-tested here: `start_firewall_render`
    // always checks the auto-detected SSH log (`assess_lockout_risk(_,
    // None)`, matching the CLI's no-`--ssh-log` default), which isn't
    // something a unit test can point at a fixture without either reading
    // whatever real log happens to be on the machine running the test or
    // adding an `--ssh-log`-style override this method doesn't have yet.

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
        app.db
            .set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), "skipped for test")
            .unwrap();

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

    /// `check_cron` must run every currently-due log-based job
    /// (`BlockScanners`/`BlockWebScanners`/`RecordAccessStats`/
    /// `RenderFirewall` — no network I/O, so safe to exercise directly
    /// rather than mocking) and record each one's state, once their
    /// background `CronLogFetched` events are drained. `UpdateIpRanges` is
    /// deliberately pre-marked as just-run so this test never triggers its
    /// real network fetch.
    #[tokio::test]
    async fn check_cron_runs_every_due_synchronous_job() {
        let mut app = test_app();
        app.db
            .set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), "skipped for test")
            .unwrap();
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

    /// `check_cron` throttles against `Event::Tick`'s 30fps rate: two
    /// calls in immediate succession (as real ticks would produce) must
    /// only actually run due jobs once.
    #[tokio::test]
    async fn check_cron_is_throttled_against_rapid_repeated_ticks() {
        let mut app = test_app();
        app.db
            .set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), "skipped for test")
            .unwrap();
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

    // `start_cron_update_ip_ranges`'s in-flight guard (skip spawning a
    // second fetch while one is already running) isn't separately unit
    // tested: proving a *real* network task wasn't spawned would mean
    // either mocking the network layer or racing a timeout against
    // whatever latency `reqwest::get` happens to have on the test
    // machine, neither of which is worth it for a one-line early return.
    // Covered by inspection instead.

    // ---- the lockout guard on the apply path ----

    /// The bug that took a real server off the network.
    ///
    /// `LogUnavailable` used to fall through the check silently, so on any
    /// host where the SSH log isn't readable the script was written — and,
    /// with the render popup's "apply after writing" toggle, *applied* —
    /// with no lockout check and no warning.
    #[tokio::test]
    async fn render_firewall_refuses_when_the_lockout_check_cannot_run() {
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
            false,
        );
        drain_background_work(&mut app).await;

        assert!(
            !out.exists(),
            "no script may be written when the guard couldn't run"
        );
        let message = app.message.clone().unwrap();
        assert!(message.contains("lockout"), "message was: {message}");
        assert!(message.contains("--ssh-log"), "message was: {message}");
    }

    /// `--force` is still the way through for someone who knows the log is
    /// missing and means it.
    #[tokio::test]
    async fn force_still_writes_when_the_lockout_check_cannot_run() {
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
            false,
        );
        drain_background_work(&mut app).await;

        assert!(out.exists(), "message was: {:?}", app.message);
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
