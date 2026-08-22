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
use crate::protection::Detector;
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
const CRON_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// from. See [`App::read_ssh_log`].
    ReadSshLog,
    /// `nginx -t` followed by `systemctl reload nginx`, after Site
    /// settings has written a config file. See [`App::reload_nginx`].
    ReloadNginx,
    /// Writing the firewall script and, if asked, applying it. See
    /// [`App::render_firewall`].
    RenderFirewall,
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
    /// [`SSH_LOG_MAX_AGE`] and [`App::read_ssh_log`]. `None` means no read
    /// has come back yet.
    ///
    /// Deliberately *not* what the lockout guard in
    /// [`App::render_firewall`] consults: that one reads live, every time.
    /// A cached answer there is the difference between "this would cut off
    /// the admin" and finding out afterwards.
    ssh_log_text: Option<String>,
    ssh_log_read_at: Option<std::time::Instant>,
    /// Set when an apply asked for an NGINX reload while one was already
    /// running, so [`App::finish_nginx_reload`] knows to start one more.
    /// See [`App::reload_nginx`] for why dropping it instead is wrong.
    reload_nginx_pending: bool,
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
}

/// What [`App::render_firewall`] hands to the background thread. A struct
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
            stale: std::collections::HashSet::new(),
            jobs_in_flight: std::collections::HashSet::new(),
            reload_nginx_for_real: reload_nginx,
            apply_firewall: reload_nginx,
            ssh_log,
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
            Screen::SiteSettings => self.site_settings.refresh(&self.db),
            Screen::DynamicProtection => {
                // Kicked off here rather than on entering the screen: this
                // is the one place every route to a visible SSH panel goes
                // through, and the freshness check makes repeating it
                // harmless.
                self.read_ssh_log();
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
                self.finish_render_firewall(signature, outcome)?
            }
        }
        Ok(())
    }

    /// Starts a background fetch+parse of the bot-list source identified by
    /// `source_id` (resolved to a `botlist::SourceKind`, which knows how to
    /// fetch and parse its own format). Runs off the main thread because
    /// `Db`'s connection isn't `Sync` — the spawned task only fetches and
    /// parses; storing the result happens back on the main thread in
    /// `finish_source_update`.
    fn start_source_update(&mut self, source_id: String) {
        self.message = Some(format!("Updating {}…", source_display_name(&source_id)));
        let sender = self.events.sender();
        tokio::spawn(async move {
            let result = async {
                let kind = botlist::SourceKind::from_id(&source_id)
                    .with_context(|| format!("unknown bot-list source: {source_id}"))?;
                let raw = kind.fetch().await?;
                kind.parse(&raw)
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
                kind.parse(&raw)
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
            Ok(cidrs) => {
                let count = self.db.replace_reputation_ranges(&source_id, &cidrs)?;
                self.message = Some(format!(
                    "{name}: {count} range(s) stored — render the firewall (f) to apply"
                ));
            }
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
                let count = self.db.replace_country_ranges(&country_code, &cidrs)?;
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
            let mut results = Vec::new();
            for kind in ipranges::IpRangeSourceKind::ALL {
                let result = async {
                    let raw = kind.fetch().await?;
                    kind.parse(&raw)
                }
                .await
                .map_err(|err: anyhow::Error| err.to_string());
                results.push((kind, result));
            }
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

        let mut updated = 0;
        let mut failed = 0;
        for (kind, result) in results {
            match result {
                Ok(cidrs) => {
                    ipranges::store(&self.db, kind, &cidrs)?;
                    updated += 1;
                }
                Err(_) => failed += 1,
            }
        }
        let summary = if failed == 0 {
            format!("updated {updated} crawler source(s)")
        } else {
            format!("updated {updated} crawler source(s), {failed} failed")
        };
        self.db
            .set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), &summary)?;
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
        let uses_ssh_log = match job {
            CronJob::Detect(detector) => detector.spec().uses_ssh_log,
            CronJob::RenderFirewall => true,
            _ => false,
        };
        let ssh_log = self.ssh_log.clone();
        tokio::task::spawn_blocking(move || {
            let log_text = if uses_ssh_log {
                let source = match ssh_log.as_deref() {
                    Some(path) => crate::sshlog::read_log_file(path),
                    None => crate::sshlog::find_default_source(),
                };
                match source {
                    crate::sshlog::LogSource::Found(text) => Some(text),
                    crate::sshlog::LogSource::Unavailable => None,
                }
            } else {
                match crate::accesslog::find_default_source() {
                    crate::accesslog::LogSource::Found(text) => Some(text),
                    crate::accesslog::LogSource::Unavailable => None,
                }
            };
            let _ = sender.send(Event::App(AppEvent::CronLogFetched { job, log_text }));
        });
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
    fn reload_nginx(&mut self) {
        if !self.reload_nginx_for_real {
            return;
        }
        if !self.jobs_in_flight.insert(Job::ReloadNginx) {
            self.reload_nginx_pending = true;
            return;
        }
        let sender = self.events.sender();
        tokio::task::spawn_blocking(move || {
            let result = nginx::reload().map_err(|err| err.to_string());
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
            self.reload_nginx();
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
    fn read_ssh_log(&mut self) {
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
    /// the log was unavailable) back on the main thread: the same
    /// detection/tally/render logic each job used to run inline with, then
    /// records the job's outcome and refreshes every screen — mirroring
    /// `finish_cron_update_ip_ranges`.
    fn finish_cron_log_job(&mut self, job: CronJob, log_text: Option<String>) -> Result<()> {
        self.jobs_in_flight.remove(&Job::Cron(job));

        let summary = match job {
            // Every detector runs through one arm. What differs between
            // them — the log they read, the threshold, the function — is
            // either on the spec or in `run_detector`, so a new detector
            // adds no code here at all.
            CronJob::Detect(detector) => self.run_detector(detector, log_text.as_deref())?,
            CronJob::RecordAccessStats => match log_text {
                Some(text) => match crate::accessstats::record_access_stats(
                    &self.db,
                    crate::accesslog::DEFAULT_LOG_PATH,
                    &text,
                ) {
                    Ok(outcome) => outcome.summary(),
                    Err(err) => format!("error: {err}"),
                },
                None => "NGINX access log unavailable".to_string(),
            },
            CronJob::RenderFirewall => self.render_firewall_for_cron(
                crate::firewall::DEFAULT_OUTPUT_PATH,
                log_text.as_deref(),
            ),
            CronJob::UpdateIpRanges => {
                unreachable!(
                    "UpdateIpRanges is fetched/applied via CronIpRangesFetched, not this event"
                )
            }
        };
        self.db.set_cron_last_run(job.id(), now_secs(), &summary)?;
        self.refresh()?;
        Ok(())
    }

    /// Runs one detector, if it is switched on, and turns the result into
    /// the one-line summary the Dashboard's "Scheduled tasks" panel shows.
    ///
    /// **A disabled detector still records a summary.** Skipping the write
    /// entirely would leave the job looking permanently overdue in the
    /// panel rather than saying why nothing happened.
    fn run_detector(&self, detector: Detector, log_text: Option<&str>) -> Result<String> {
        use crate::protection::Detector as D;

        if !detector.is_enabled(&self.db)? {
            return Ok("disabled".to_string());
        }
        let Some(text) = log_text else {
            return Ok(if detector.spec().uses_ssh_log {
                "SSH log unavailable".to_string()
            } else {
                "NGINX access log unavailable".to_string()
            });
        };
        let ttl = detector.ttl_days(&self.db)?;
        let db = &self.db;
        let outcome = match detector {
            D::SshScanners => crate::scanblock::block_ssh_scanners(db, 20, ttl, text, false),
            D::WebScanners => crate::scanblock::block_web_scanners(db, 7, ttl, text, false),
            D::SpoofedCrawlers => crate::scanblock::block_spoofed_crawlers(db, ttl, text, false),
            D::ProbePaths => crate::scanblock::block_probe_paths(db, ttl, text, false),
            D::Honeypot => crate::scanblock::block_honeypot(db, ttl, text, false),
            D::AssetRatio => crate::scanblock::block_asset_ratio(db, ttl, text, false),
            D::RotatingUserAgent => crate::scanblock::block_rotating_ua(db, ttl, text, false),
            D::RefererlessCrawl => crate::scanblock::block_refererless(db, ttl, text, false),
        };
        Ok(match outcome {
            Ok(outcome) => outcome.summary(),
            Err(err) => format!("error: {err}"),
        })
    }

    /// The actual work behind the `RenderFirewall` job: writes the current
    /// firewall rules to `out_path` (a parameter, rather than reading
    /// `crate::firewall::DEFAULT_OUTPUT_PATH` directly, purely so tests can
    /// point it at a temp file) using the nftables backend (handles
    /// allowlist geo mode, unlike iptables — see `firewall::build_script`),
    /// skipping the write (recorded as the job's summary, not an error) if
    /// doing so would risk locking out a currently-connected SSH client —
    /// same safety check `App::render_firewall`'s manual path runs, except
    /// `ssh_log_text` is already resolved by `start_cron_log_job` rather
    /// than being re-resolved here via `assess_lockout_risk`, so this
    /// applies `sshlog::parse_accepted_ips`/`firewall::lockout_risks`
    /// directly; `None` (log unavailable) skips the check entirely, same as
    /// `assess_lockout_risk`'s `LogUnavailable` case. Never propagates an
    /// error: any failure becomes the returned summary string instead,
    /// since a cron job recording "what went wrong" is the whole point —
    /// there's no interactive caller here to hand a `Result` to.
    fn render_firewall_for_cron(&self, out_path: &str, ssh_log_text: Option<&str>) -> String {
        let result: anyhow::Result<String> = (|| {
            let built = crate::firewall::build_script(
                &self.db,
                crate::firewall::FirewallBackend::Nftables,
            )?;
            if let Some(text) = ssh_log_text {
                let connected_ips = crate::sshlog::parse_accepted_ips(text);
                let risks = crate::firewall::lockout_risks(&built.rules, &connected_ips);
                if !risks.is_empty() {
                    anyhow::bail!(
                        "skipped: would block {} currently-connected SSH client IP address(es)",
                        risks.len()
                    );
                }
            }
            crate::firewall::write_script(std::path::Path::new(out_path), &built.script)?;
            self.db
                .set_firewall_rendered_signature(&crate::firewall::rules_signature(&built.rules))?;
            Ok(format!("wrote {} rule(s) to {out_path}", built.written))
        })();
        match result {
            Ok(summary) => summary,
            Err(err) => format!("error: {err}"),
        }
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
    fn render_firewall(
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
    fn finish_render_firewall(
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
                // in `finish_render_firewall`, once the signature the
                // Dashboard compares against has actually been written.
                self.render_firewall(backend, out_path, force, apply);
                return Ok(());
            }
            KeyOutcome::ReloadNginx => {
                self.refresh()?;
                self.reload_nginx();
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

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::FirewallBackend;

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
            // `render_firewall` now refuses when the lockout check can't
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

    /// `h`/`l` must not steal a keystroke that a screen's own search/text
    /// focus wants — Bot settings' search box (`/`) accepts any character,
    /// including 'h'/'l', as literal query text, e.g. typing "arclejot" to
    /// filter by name must not jump screens partway through.
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
    /// — see the doc comment on `render_firewall`) must still actually
    /// write the script and report success.
    // `App::new` spawns a background task via `EventHandler::new`, so
    // constructing one needs an actual Tokio runtime, not just `#[test]`.
    #[tokio::test]
    async fn render_firewall_writes_the_script_and_sets_a_success_message() {
        let mut app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft").to_str().unwrap().to_string();

        app.render_firewall(FirewallBackend::Nftables, out_path.clone(), false, false);
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

        app.render_firewall(FirewallBackend::Nftables, out_path.clone(), false, true);
        drain_background_work(&mut app).await;

        assert!(std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("written"), "message was: {message}");
        assert!(!message.contains("applied"), "message was: {message}");
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
        app.render_firewall(FirewallBackend::Nftables, out_path, false, false);
        drain_background_work(&mut app).await;
        assert!(app.db.get_firewall_rendered_signature().unwrap().is_some());
    }

    /// Regression test: `render_firewall` alone only updates `Db`; the
    /// Dashboard's "needs updating" row is a value cached on `Dashboard`
    /// itself, only recomputed by `Dashboard::refresh`. Confirming the
    /// render popup drives through `KeyOutcome::RenderFirewall`, not
    /// `render_firewall` directly, so this exercises `App::handle_key_event`
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

        app.render_firewall(FirewallBackend::Iptables, out_path.clone(), false, false);
        drain_background_work(&mut app).await;

        assert!(!std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("nftables"), "message was: {message}");
    }

    // The lockout-risk branch itself (skip if `LockoutStatus::Risks` is
    // non-empty and not forced) is exercised thoroughly against
    // `firewall::assess_lockout_risk`/`lockout_risks` directly in
    // `firewall.rs`'s tests. It isn't re-tested here: `render_firewall`
    // always checks the auto-detected SSH log (`assess_lockout_risk(_,
    // None)`, matching the CLI's no-`--ssh-log` default), which isn't
    // something a unit test can point at a fixture without either reading
    // whatever real log happens to be on the machine running the test or
    // adding an `--ssh-log`-style override this method doesn't have yet.

    #[tokio::test]
    async fn render_firewall_for_cron_writes_the_script_and_reports_success() {
        let app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft");

        let summary = app.render_firewall_for_cron(out_path.to_str().unwrap(), None);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

    /// The real default path (`/etc/stop-bots/firewall.nft`) has no parent
    /// directory created anywhere else in the codebase, unlike the
    /// database's `/var/lib/stop-bots`. Since this cron job runs
    /// unattended, it must create its own parent directory rather than
    /// failing with "No such file or directory" forever on a fresh host.
    #[tokio::test]
    async fn render_firewall_for_cron_creates_missing_parent_directories() {
        let app = test_app();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("nested/does/not/exist/fw.nft");

        let summary = app.render_firewall_for_cron(out_path.to_str().unwrap(), None);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

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

        app.render_firewall(
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

        app.render_firewall(
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

        app.render_firewall(
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
