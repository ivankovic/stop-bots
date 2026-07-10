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
/// `crate::cron`) — not the jobs' own intervals (hours to a day), just how
/// often `Event::Tick` (which fires at 30fps) bothers asking. Cheap either
/// way (a handful of `settings` table reads), but there's no reason to ask
/// 30 times a second when once a minute already means "at most ~60s later
/// than a job's exact due time", which is plenty precise for jobs measured
/// in hours.
const CRON_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// When the internal cron last checked for due jobs — throttles the
    /// check against `Event::Tick`'s 30fps rate (see
    /// [`CRON_CHECK_INTERVAL`]).
    last_cron_check: std::time::Instant,
    /// Whether the `UpdateIpRanges` cron job's background fetch is
    /// currently in flight — guards against starting a second one before
    /// the first (a network round-trip to three hosts) has finished, which
    /// `due_jobs` alone can't prevent since `last_run` only updates once
    /// the job actually completes.
    cron_update_ip_ranges_in_flight: bool,
    /// Whether `KeyOutcome::ReloadNginx` actually calls `nginx::reload()`.
    /// Always `true` for real usage; `false` only for the end-to-end TUI
    /// tests in `tests/tui.rs`, which drive a real Site settings "apply"
    /// through a real spawned binary — without this, that would shell out
    /// to the real `nginx -t`/`systemctl reload nginx` on whatever machine
    /// runs the test suite (see `main.rs`'s `tui --no-reload` flag, the
    /// same escape hatch `apply-blocks --no-reload` uses).
    reload_nginx: bool,
}

impl App {
    /// Constructs a new [`App`], loading initial state from `db`. `root` is
    /// the NGINX config root Site settings scans when the user triggers a
    /// rescan from the TUI. `reload_nginx` gates whether a successful Site
    /// settings apply actually reloads NGINX (see the field doc comment).
    pub fn new(db: Db, root: std::path::PathBuf, reload_nginx: bool) -> Result<Self> {
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
            last_cron_check: std::time::Instant::now(),
            cron_update_ip_ranges_in_flight: false,
            reload_nginx,
        };
        botlist::register_all_sources(&app.db)?;
        app.refresh()?;
        Ok(app)
    }

    /// Reloads every screen's state from the database.
    fn refresh(&mut self) -> Result<()> {
        self.dashboard.refresh(&self.db)?;
        self.bot_settings.refresh(&self.db)?;
        self.site_settings.refresh(&self.db)?;
        Ok(())
    }

    /// Runs the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while self.running {
            terminal.draw(|frame| tui::render(&mut self, frame))?;
            match self.events.next().await? {
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
                Event::App(AppEvent::CronIpRangesFetched { results }) => {
                    self.finish_cron_update_ip_ranges(results)?;
                }
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
            CronJob::UpdateIpRanges => {
                self.start_cron_update_ip_ranges();
                Ok(())
            }
            CronJob::BlockScanners => self.run_cron_block_scanners(),
            CronJob::BlockWebScanners => self.run_cron_block_web_scanners(),
            CronJob::RenderFirewall => self.run_cron_render_firewall(),
        }
    }

    /// Starts the `UpdateIpRanges` job's background fetch (Googlebot,
    /// Bingbot, GPTBot — the same three `ipranges::IpRangeSourceKind::ALL`
    /// sources `update-ip-ranges` fetches). Guarded by
    /// `cron_update_ip_ranges_in_flight` so a slow round-trip to all three
    /// hosts can't overlap with itself if `check_cron` finds the job still
    /// "due" (its `last_run` doesn't update until it actually finishes) on
    /// a later tick. Only fetches and parses in the background, same
    /// `Db`-isn't-`Sync` reasoning as `start_source_update`/
    /// `start_country_select`: storing happens back on the main thread in
    /// `finish_cron_update_ip_ranges`.
    fn start_cron_update_ip_ranges(&mut self) {
        if self.cron_update_ip_ranges_in_flight {
            return;
        }
        self.cron_update_ip_ranges_in_flight = true;
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
        self.cron_update_ip_ranges_in_flight = false;

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

    /// Runs the `BlockScanners` job: the same detection/insertion logic as
    /// the CLI's `block-scanners` subcommand
    /// (`stop_bots::scanblock::block_ssh_scanners`), against whichever SSH
    /// log `sshlog::find_default_source` finds (never a `--ssh-log`
    /// override — there's no per-job configuration surface yet), using the
    /// same threshold/TTL defaults as the CLI. Purely local (log read +
    /// synchronous `Db` calls), so unlike `UpdateIpRanges` this runs inline
    /// rather than needing a spawned background task.
    fn run_cron_block_scanners(&mut self) -> Result<()> {
        const THRESHOLD: usize = 20;
        const TTL_DAYS: i64 = 5;
        let summary = match crate::sshlog::find_default_source() {
            crate::sshlog::LogSource::Found(log_text) => {
                match crate::scanblock::block_ssh_scanners(&self.db, THRESHOLD, TTL_DAYS, &log_text, false) {
                    Ok(outcome) => outcome.summary(),
                    Err(err) => format!("error: {err}"),
                }
            }
            crate::sshlog::LogSource::Unavailable => "SSH log unavailable".to_string(),
        };
        self.db
            .set_cron_last_run(CronJob::BlockScanners.id(), now_secs(), &summary)?;
        Ok(())
    }

    /// Runs the `BlockWebScanners` job: the same detection/exclusion/
    /// insertion logic as the CLI's `block-web-scanners` subcommand
    /// (`stop_bots::scanblock::block_web_scanners`), against whichever
    /// NGINX access log `accesslog::find_default_source` finds, using the
    /// same threshold/TTL defaults as the CLI. Purely local, same as
    /// `run_cron_block_scanners`.
    fn run_cron_block_web_scanners(&mut self) -> Result<()> {
        const THRESHOLD: usize = 15;
        const TTL_DAYS: i64 = 1;
        let summary = match crate::accesslog::find_default_source() {
            crate::accesslog::LogSource::Found(log_text) => {
                match crate::scanblock::block_web_scanners(&self.db, THRESHOLD, TTL_DAYS, &log_text, false) {
                    Ok(outcome) => outcome.summary(),
                    Err(err) => format!("error: {err}"),
                }
            }
            crate::accesslog::LogSource::Unavailable => "NGINX access log unavailable".to_string(),
        };
        self.db
            .set_cron_last_run(CronJob::BlockWebScanners.id(), now_secs(), &summary)?;
        Ok(())
    }

    /// Runs the `RenderFirewall` job: writes the current firewall rules to
    /// `crate::firewall::DEFAULT_OUTPUT_PATH` using the nftables backend
    /// (handles allowlist geo mode, unlike iptables — see
    /// `firewall::build_script`), skipping the write (recorded as the
    /// job's summary, not an error) if doing so would risk locking out a
    /// currently-connected SSH client, same safety check
    /// `App::render_firewall`'s manual path already runs. Writing here is
    /// the only thing this job does — actually applying the script to the
    /// host remains a manual step, same "generate-only" design as every
    /// other path that touches `firewall_rules` (see `crate::cron`'s
    /// module docs).
    fn run_cron_render_firewall(&mut self) -> Result<()> {
        let summary = self.render_firewall_for_cron(crate::firewall::DEFAULT_OUTPUT_PATH);
        self.db
            .set_cron_last_run(CronJob::RenderFirewall.id(), now_secs(), &summary)?;
        Ok(())
    }

    /// The actual work behind [`Self::run_cron_render_firewall`], taking
    /// `out_path` as a parameter (rather than reading
    /// `crate::firewall::DEFAULT_OUTPUT_PATH` directly) purely so tests can
    /// point it at a temp file instead of the real
    /// `/etc/stop-bots/firewall.nft`. Never propagates an error: any
    /// failure (the lockout check finding a risk, a permission error
    /// writing the file, ...) becomes the returned summary string instead,
    /// since a cron job recording "what went wrong" is the whole point —
    /// there's no interactive caller here to hand a `Result` to.
    fn render_firewall_for_cron(&self, out_path: &str) -> String {
        let result: anyhow::Result<String> = (|| {
            let built = crate::firewall::build_script(
                &self.db,
                crate::firewall::FirewallBackend::Nftables,
            )?;
            if let crate::firewall::LockoutStatus::Risks(risks) =
                crate::firewall::assess_lockout_risk(&built.rules, None)
            {
                if !risks.is_empty() {
                    anyhow::bail!(
                        "skipped: would block {} currently-connected SSH client IP address(es)",
                        risks.len()
                    );
                }
            }
            crate::firewall::write_script(std::path::Path::new(out_path), &built.script)?;
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
    fn render_firewall(&mut self, backend: crate::firewall::FirewallBackend, out_path: String, force: bool) {
        let result = (|| -> anyhow::Result<String> {
            let built = crate::firewall::build_script(&self.db, backend)?;
            if let crate::firewall::LockoutStatus::Risks(risks) =
                crate::firewall::assess_lockout_risk(&built.rules, None)
            {
                if !risks.is_empty() && !force {
                    let ips = risks
                        .iter()
                        .map(|(ip, cidr)| format!("{ip} (blocked by {cidr})"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    anyhow::bail!(
                        "refusing to write: would block {} currently-connected SSH client \
                         IP address(es): {ips}",
                        risks.len()
                    );
                }
            }
            crate::firewall::write_script(std::path::Path::new(&out_path), &built.script)?;
            Ok(format!(
                "Firewall rules written to {out_path}. Review it, then apply with: {} {out_path}",
                backend.apply_command()
            ))
        })();

        self.message = Some(match result {
            Ok(message) => message,
            Err(err) => format!("Failed to render firewall rules: {err}"),
        });
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
            KeyOutcome::RenderFirewall {
                backend,
                out_path,
                force,
            } => {
                self.render_firewall(backend, out_path, force);
                return Ok(());
            }
            KeyOutcome::ReloadNginx => {
                self.refresh()?;
                if self.reload_nginx {
                    if let Err(err) = nginx::reload() {
                        let applied = self.message.take().unwrap_or_default();
                        self.message = Some(format!("{applied} — failed to reload NGINX: {err}"));
                    }
                }
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
            KeyCode::Tab => self.screen = self.screen.next(),
            KeyCode::BackTab => self.screen = self.screen.previous(),
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
        )
        .unwrap()
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

        app.render_firewall(FirewallBackend::Nftables, out_path.clone(), false);

        assert!(std::path::Path::new(&out_path).exists());
        let message = app.message.as_deref().unwrap_or_default();
        assert!(message.contains("written"), "message was: {message}");
    }

    /// The allowlist/iptables guard in `firewall::build_script` must
    /// surface as a status message rather than silently doing nothing or
    /// panicking, and the script must not be written.
    #[tokio::test]
    async fn render_firewall_reports_the_allowlist_iptables_conflict() {
        let mut app = test_app();
        app.db
            .set_geo_mode(crate::db::GeoMode::Allowlist)
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.sh").to_str().unwrap().to_string();

        app.render_firewall(FirewallBackend::Iptables, out_path.clone(), false);

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

        let summary = app.render_firewall_for_cron(out_path.to_str().unwrap());

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

        let summary = app.render_firewall_for_cron(out_path.to_str().unwrap());

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

    /// `check_cron` must run every currently-due *synchronous* job
    /// (`BlockScanners`/`BlockWebScanners`/`RenderFirewall` — no network
    /// I/O, so safe to exercise directly rather than mocking) and record
    /// each one's state. `UpdateIpRanges` is deliberately pre-marked as
    /// just-run so this test never triggers its real network fetch.
    #[tokio::test]
    async fn check_cron_runs_every_due_synchronous_job() {
        let mut app = test_app();
        app.db
            .set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), "skipped for test")
            .unwrap();
        app.last_cron_check = std::time::Instant::now() - CRON_CHECK_INTERVAL - std::time::Duration::from_secs(1);

        app.check_cron().unwrap();

        assert!(app
            .db
            .get_cron_last_run(CronJob::BlockScanners.id())
            .unwrap()
            .is_some());
        assert!(app
            .db
            .get_cron_last_run(CronJob::BlockWebScanners.id())
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
        app.last_cron_check = std::time::Instant::now() - CRON_CHECK_INTERVAL - std::time::Duration::from_secs(1);

        app.check_cron().unwrap();
        let first = app.db.get_cron_last_run(CronJob::BlockScanners.id()).unwrap();
        assert!(first.is_some());

        // A second call immediately after (simulating the next few ticks
        // at 30fps) must be a no-op: `last_cron_check` was just reset to
        // "now" inside the first call, so this one is still well within
        // `CRON_CHECK_INTERVAL`.
        app.check_cron().unwrap();
        let second = app.db.get_cron_last_run(CronJob::BlockScanners.id()).unwrap();
        assert_eq!(first, second);
    }

    // `start_cron_update_ip_ranges`'s in-flight guard (skip spawning a
    // second fetch while one is already running) isn't separately unit
    // tested: proving a *real* network task wasn't spawned would mean
    // either mocking the network layer or racing a timeout against
    // whatever latency `reqwest::get` happens to have on the test
    // machine, neither of which is worth it for a one-line early return.
    // Covered by inspection instead.
}
