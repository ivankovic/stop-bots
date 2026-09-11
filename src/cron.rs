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

//! The internal cron: replaces relying on an external `cron`/systemd-timer
//! to keep scan detection and crawler-range data fresh, by having a
//! long-running stop-bots process periodically check which background jobs
//! are due and run them. The Dashboard's "Scheduled tasks" panel — in both
//! front-ends — is where their state is shown.
//!
//! **This only automates while a front-end is running.** Unlike a real
//! cron entry, nothing here runs when no stop-bots process is: closing
//! both the TUI and the web server pauses every job until one is reopened.
//! A job that's overdue when one (re)starts just runs as soon as it's next
//! checked, the same never-run-yet-so-do-it-now convention `ipranges`
//! sources already use for staleness, rather than trying to "catch up" on
//! however many intervals were missed.
//!
//! ## One schedule, however many front-ends
//!
//! The TUI (`App::check_cron` in `crate::app`), the web server
//! (`crate::web::cron`) and a real crontab entry running `stop-bots batch`
//! all record through the same `Db::set_cron_last_run` keys. So running
//! two of them at once doesn't double the work: whichever gets there first
//! marks the job done, and the other finds it no longer due. That is also
//! why the per-job work lives here rather than in either front-end — two
//! schedulers computing "what this job does" separately are two
//! schedulers that will eventually disagree.
//!
//! **Each job only does what its equivalent CLI subcommand does — nothing
//! here applies a firewall script.** `RenderFirewall` writes the script to
//! disk on a timer, same as `render-firewall`; actually applying it
//! (`sh`/`nft -f`) remains a manual step for the admin, on purpose (see
//! `src/iptables.rs`/`src/nftables.rs`'s "generate-only" module docs) — an
//! internal cron that silently executed firewall changes would be a very
//! different, much riskier feature than this one.

use crate::db::Db;
use crate::protection::Detector;
use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One of the background jobs the internal cron schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CronJob {
    /// Refetches Googlebot/Bingbot/GPTBot's published CIDR ranges.
    UpdateIpRanges,
    /// One switchable log-analysis detector — see [`crate::protection::Detector`].
    /// Every detector shares this variant rather than adding its own, which
    /// is what stopped a new detector meaning three more match arms here.
    Detect(Detector),
    /// Tallies successful-request user agents into `user_agent_stats`.
    RecordAccessStats,
    /// Renders the current firewall rules to disk. Does not apply them.
    RenderFirewall,
}

impl CronJob {
    /// Every job: the two fixed ones on either side of every detector.
    pub fn all() -> Vec<CronJob> {
        std::iter::once(CronJob::UpdateIpRanges)
            .chain(Detector::ALL.into_iter().map(CronJob::Detect))
            .chain([CronJob::RecordAccessStats, CronJob::RenderFirewall])
            .collect()
    }

    /// The key this job's state is stored under in `Db`'s cron methods —
    /// stable across releases (used as a `settings` table key), so never
    /// change an existing id without a migration thought. The detector ids
    /// come from `DetectorSpec::id` and are the exact strings this enum
    /// used before detectors were table-driven.
    pub fn id(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "update_ip_ranges",
            CronJob::Detect(detector) => detector.id(),
            CronJob::RecordAccessStats => "record_access_stats",
            CronJob::RenderFirewall => "render_firewall",
        }
    }

    /// A short label for the Dashboard's job list.
    pub fn label(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "Update crawler IP ranges",
            CronJob::Detect(detector) => detector.spec().job_label,
            CronJob::RecordAccessStats => "Record access-log stats",
            CronJob::RenderFirewall => "Render firewall script",
        }
    }

    /// How often this job should run.
    ///
    /// - `UpdateIpRanges`: daily — crawler ranges change slowly.
    /// - every detector: every minute. Detection exists to catch an attack
    ///   while it is still happening, and a minute is the practical floor
    ///   anyway (`App::check_cron` only re-checks that often).
    /// - `RecordAccessStats`: every minute, same log as most detectors.
    /// - `RenderFirewall`: daily — nothing about it is time-sensitive.
    pub fn interval(self) -> Duration {
        match self {
            CronJob::UpdateIpRanges | CronJob::RenderFirewall => Duration::from_secs(24 * 60 * 60),
            CronJob::Detect(_) | CronJob::RecordAccessStats => Duration::from_secs(60),
        }
    }
}

/// A job's persisted state, for the Dashboard's "Scheduled tasks" panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStatus {
    pub job: CronJob,
    /// `None` if the job has never run.
    pub last_run: Option<i64>,
    /// `None` if the job has never run.
    pub last_summary: Option<String>,
    /// Whether the job is due to run the next time it's checked.
    pub due: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Whether `job` is due: it's never run, or its interval has elapsed since
/// it last did.
pub fn is_due(db: &Db, job: CronJob) -> Result<bool> {
    let last_run = db.get_cron_last_run(job.id())?;
    Ok(match last_run {
        None => true,
        Some(last_run) => now() - last_run >= job.interval().as_secs() as i64,
    })
}

/// Every job that's currently due, in [`CronJob::all()`] order.
pub fn due_jobs(db: &Db) -> Result<Vec<CronJob>> {
    CronJob::all()
        .into_iter()
        .filter_map(|job| match is_due(db, job) {
            Ok(true) => Some(Ok(job)),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

/// Every job's current state, for display — always all four, in
/// [`CronJob::all()`] order, regardless of due-ness.
pub fn status(db: &Db) -> Result<Vec<JobStatus>> {
    CronJob::all()
        .into_iter()
        .map(|job| {
            Ok(JobStatus {
                job,
                last_run: db.get_cron_last_run(job.id())?,
                last_summary: db.get_cron_last_summary(job.id())?,
                due: is_due(db, job)?,
            })
        })
        .collect()
}

/// How often a front-end re-checks which jobs are due.
///
/// Not how often any job *runs* — that is [`CronJob::interval`]. This is
/// the resolution of the check itself, and so the practical floor on every
/// interval: a job that wants to run every second still only gets looked
/// at once a minute. Shared by both front-ends so that "every minute"
/// means the same thing whichever one is open.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Whether this job reads the SSH log rather than the NGINX access log.
///
/// `RenderFirewall` reads the SSH log without being a detector: it needs
/// the currently-connected clients for its lockout guard, not a log to
/// scan for attackers.
pub fn uses_ssh_log(job: CronJob) -> bool {
    match job {
        CronJob::Detect(detector) => detector.spec().uses_ssh_log,
        CronJob::RenderFirewall => true,
        CronJob::RecordAccessStats | CronJob::UpdateIpRanges => false,
    }
}

/// Reads whichever log `job` needs, `None` if it isn't available.
///
/// **Blocking I/O, and slower than it looks** — reading the log file, and
/// for the SSH log shelling out to `journalctl` when no file exists. Both
/// front-ends run it off their main thread (`tokio::task::spawn_blocking`)
/// rather than inline; the TUI stops redrawing otherwise, and the web
/// server must not do it while holding the database lock.
///
/// Takes no `Db` for exactly that reason: this half can be hoisted out of
/// the lock, and a signature that can't reach the database is what keeps
/// it that way.
pub fn read_log_for(job: CronJob, ssh_log: Option<&std::path::Path>) -> Option<String> {
    if uses_ssh_log(job) {
        let source = match ssh_log {
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
    }
}

/// Runs one log-backed job against already-read log text and records what
/// happened, returning the summary the Dashboard's "Scheduled tasks" panel
/// will show.
///
/// The `Result` covers only the bookkeeping write. **The job's own failure
/// is never an error** — it becomes the recorded summary instead. A cron
/// job exists to say what it did without anyone watching, so "the SSH log
/// was unreadable" is an outcome to record, not something to hand back to
/// a caller who has no one to tell.
///
/// `firewall_out` is a parameter rather than
/// [`crate::firewall::DEFAULT_OUTPUT_PATH`] read directly so that tests,
/// and any front-end that shouldn't write to `/etc`, can point it
/// somewhere else.
///
/// Panics on [`CronJob::UpdateIpRanges`], which fetches over the network
/// and goes through [`fetch_ip_ranges`]/[`store_ip_ranges`] instead.
pub fn run_log_job(
    db: &Db,
    job: CronJob,
    log_text: Option<&str>,
    firewall_out: &std::path::Path,
) -> Result<String> {
    let summary = match job {
        // Every detector runs through one arm. What differs between them —
        // the log they read, the threshold, the function — is either on the
        // spec or in `run_detector`, so a new detector adds no code here.
        CronJob::Detect(detector) => run_detector(db, detector, log_text),
        CronJob::RecordAccessStats => match log_text {
            Some(text) => match crate::accessstats::record_access_stats(
                db,
                crate::accesslog::DEFAULT_LOG_PATH,
                text,
            ) {
                Ok(outcome) => outcome.summary(),
                Err(err) => format!("error: {err}"),
            },
            None => "NGINX access log unavailable".to_string(),
        },
        CronJob::RenderFirewall => render_firewall(db, firewall_out, log_text),
        CronJob::UpdateIpRanges => {
            unreachable!("UpdateIpRanges is run via fetch_ip_ranges/store_ip_ranges")
        }
    };
    db.set_cron_last_run(job.id(), now(), &summary)?;
    Ok(summary)
}

/// Runs one detector, if it is switched on, and turns the result into a
/// one-line summary.
///
/// **A disabled detector still produces a summary.** Recording nothing
/// would leave the job looking permanently overdue in the panel rather
/// than saying why nothing happened. Every failure — including reading the
/// detector's own settings — becomes text for the same reason.
fn run_detector(db: &Db, detector: Detector, log_text: Option<&str>) -> String {
    let enabled = match detector.is_enabled(db) {
        Ok(enabled) => enabled,
        Err(err) => return format!("error: {err}"),
    };
    if !enabled {
        return "disabled".to_string();
    }
    let Some(text) = log_text else {
        return if detector.spec().uses_ssh_log {
            "SSH log unavailable".to_string()
        } else {
            "NGINX access log unavailable".to_string()
        };
    };
    let ttl = match detector.ttl_days(db) {
        Ok(ttl) => ttl,
        Err(err) => return format!("error: {err}"),
    };
    match crate::scanblock::run_detector(db, detector, ttl, text, false) {
        Ok(outcome) => outcome.summary(),
        Err(err) => format!("error: {err}"),
    }
}

/// The work behind the `RenderFirewall` job: writes the current firewall
/// rules to `out_path` using the nftables backend (which handles allowlist
/// geo mode, unlike iptables — see `firewall::build_script`), skipping the
/// write if doing so would risk locking out a currently-connected SSH
/// client.
///
/// Same safety check the interactive render runs, except `ssh_log_text` is
/// already resolved by [`read_log_for`] rather than being re-resolved
/// here, so this applies `sshlog::parse_accepted_ips`/
/// `firewall::lockout_risks` directly. `None` (log unavailable) skips the
/// check entirely, matching the interactive path's `LogUnavailable` case.
///
/// **Writes, never applies.** A script on disk does nothing until someone
/// runs it; see this module's docs for why that line is where it is.
fn render_firewall(db: &Db, out_path: &std::path::Path, ssh_log_text: Option<&str>) -> String {
    let result: Result<String> = (|| {
        let built = crate::firewall::build_script(db, crate::firewall::FirewallBackend::Nftables)?;
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
        crate::firewall::write_script(out_path, &built.script)?;
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&built.rules))?;
        Ok(format!(
            "wrote {} rule(s) to {}",
            built.written,
            out_path.display()
        ))
    })();
    match result {
        Ok(summary) => summary,
        Err(err) => format!("error: {err}"),
    }
}

/// The network half of `UpdateIpRanges`: fetches and parses all three
/// crawler sources, holding no database handle at all.
///
/// Split from [`store_ip_ranges`] because `Db` is not `Sync` — nothing
/// that touches it can be held across an `.await` — and because a fetch of
/// three remote hosts has no business keeping the database locked. One
/// source failing is carried as its own `Err` rather than failing the
/// batch: a transient network error on one shouldn't discard what the
/// other two got.
pub async fn fetch_ip_ranges() -> Vec<(
    crate::ipranges::IpRangeSourceKind,
    std::result::Result<Vec<String>, String>,
)> {
    let mut results = Vec::new();
    for kind in crate::ipranges::IpRangeSourceKind::ALL {
        let result = async {
            let raw = kind.fetch().await?;
            tokio::task::spawn_blocking(move || kind.parse(&raw))
                .await
                .map_err(|err| anyhow::anyhow!("the parser thread panicked: {err}"))?
        }
        .await
        .map_err(|err: anyhow::Error| err.to_string());
        results.push((kind, result));
    }
    results
}

/// Stores whatever [`fetch_ip_ranges`] managed to get and records the
/// job's outcome, returning its summary.
pub fn store_ip_ranges(
    db: &Db,
    results: Vec<(
        crate::ipranges::IpRangeSourceKind,
        std::result::Result<Vec<String>, String>,
    )>,
) -> Result<String> {
    let mut updated = 0;
    let mut failed = 0;
    for (kind, result) in results {
        match result {
            Ok(cidrs) => {
                crate::ipranges::store(db, kind, &cidrs)?;
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
    db.set_cron_last_run(CronJob::UpdateIpRanges.id(), now(), &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    /// `RenderFirewall` reads the SSH log without being a detector — it
    /// needs the currently-connected clients for its lockout guard. A
    /// change that lumped it in with the access-log jobs would silently
    /// disable that guard rather than fail.
    #[test]
    fn only_the_ssh_detectors_and_the_firewall_job_read_the_ssh_log() {
        assert!(uses_ssh_log(CronJob::RenderFirewall));
        assert!(!uses_ssh_log(CronJob::RecordAccessStats));
        assert!(!uses_ssh_log(CronJob::UpdateIpRanges));
        for detector in Detector::ALL {
            assert_eq!(
                uses_ssh_log(CronJob::Detect(detector)),
                detector.spec().uses_ssh_log,
                "{} disagreed with its own spec",
                detector.id()
            );
        }
    }

    #[test]
    fn read_log_for_reads_the_ssh_log_it_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.log");
        std::fs::write(&path, "a line from the fixture\n").unwrap();

        let text = read_log_for(CronJob::Detect(Detector::SshScanners), Some(&path));

        assert_eq!(text.as_deref(), Some("a line from the fixture\n"));
    }

    /// A path that isn't there is "unavailable", not a panic and not a
    /// fallback to whatever log the host happens to have — an explicit
    /// `--ssh-log` that is wrong should say so through the job's summary
    /// rather than quietly reading something else.
    #[test]
    fn read_log_for_reports_a_missing_ssh_log_as_unavailable() {
        let dir = tempfile::tempdir().unwrap();

        let text = read_log_for(
            CronJob::Detect(Detector::SshScanners),
            Some(&dir.path().join("nope.log")),
        );

        assert_eq!(text, None);
    }

    /// The summary is the whole point of the job: it is what the
    /// Dashboard shows, and "nothing recorded" reads as permanently
    /// overdue. So both the disabled case and the no-log case must still
    /// write one.
    #[test]
    fn a_job_that_could_not_do_anything_still_records_why() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("fw.nft");
        let detector = Detector::SshScanners;

        detector.set_enabled(&db, false).unwrap();
        let summary = run_log_job(&db, CronJob::Detect(detector), None, &out).unwrap();
        assert_eq!(summary, "disabled");

        detector.set_enabled(&db, true).unwrap();
        let summary = run_log_job(&db, CronJob::Detect(detector), None, &out).unwrap();
        assert_eq!(summary, "SSH log unavailable");

        let summary = run_log_job(&db, CronJob::RecordAccessStats, None, &out).unwrap();
        assert_eq!(summary, "NGINX access log unavailable");

        // Recorded, not just returned — a job that ran and reported
        // nothing is indistinguishable from one that never ran.
        assert!(db
            .get_cron_last_run(CronJob::RecordAccessStats.id())
            .unwrap()
            .is_some());
        assert_eq!(
            db.get_cron_last_summary(CronJob::Detect(detector).id())
                .unwrap()
                .as_deref(),
            Some("SSH log unavailable")
        );
    }

    #[test]
    fn render_firewall_writes_the_script_and_reports_success() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft");

        let summary = render_firewall(&db, &out_path, None);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

    /// The real default path (`/etc/stop-bots/firewall.nft`) has no parent
    /// directory created anywhere else in the codebase, unlike the
    /// database's `/var/lib/stop-bots`. Since this cron job runs
    /// unattended, it must create its own parent directory rather than
    /// failing with "No such file or directory" forever on a fresh host.
    #[test]
    fn render_firewall_creates_missing_parent_directories() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("nested/does/not/exist/fw.nft");

        let summary = render_firewall(&db, &out_path, None);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

    #[test]
    fn a_job_that_has_never_run_is_due() {
        let db = Db::open_in_memory().unwrap();
        assert!(is_due(&db, CronJob::Detect(Detector::SshScanners)).unwrap());
    }

    #[test]
    fn a_job_run_just_now_is_not_due() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(CronJob::Detect(Detector::SshScanners).id(), now(), "ran")
            .unwrap();
        assert!(!is_due(&db, CronJob::Detect(Detector::SshScanners)).unwrap());
    }

    #[test]
    fn a_job_run_past_its_interval_is_due_again() {
        let db = Db::open_in_memory().unwrap();
        let interval = CronJob::Detect(Detector::WebScanners).interval().as_secs() as i64;
        db.set_cron_last_run(
            CronJob::Detect(Detector::WebScanners).id(),
            now() - interval - 60,
            "ran",
        )
        .unwrap();
        assert!(is_due(&db, CronJob::Detect(Detector::WebScanners)).unwrap());
    }

    #[test]
    fn a_job_run_within_its_interval_is_not_due() {
        let db = Db::open_in_memory().unwrap();
        let interval = CronJob::Detect(Detector::WebScanners).interval().as_secs() as i64;
        db.set_cron_last_run(
            CronJob::Detect(Detector::WebScanners).id(),
            now() - interval + 60,
            "ran",
        )
        .unwrap();
        assert!(!is_due(&db, CronJob::Detect(Detector::WebScanners)).unwrap());
    }

    #[test]
    fn due_jobs_on_a_fresh_database_includes_every_job() {
        let db = Db::open_in_memory().unwrap();
        let due = due_jobs(&db).unwrap();
        assert_eq!(due.len(), CronJob::all().len());
    }

    #[test]
    fn due_jobs_excludes_a_job_that_just_ran() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(CronJob::UpdateIpRanges.id(), now(), "ran")
            .unwrap();
        let due = due_jobs(&db).unwrap();
        assert!(!due.contains(&CronJob::UpdateIpRanges));
        assert_eq!(due.len(), CronJob::all().len() - 1);
    }

    #[test]
    fn status_reports_every_job_with_its_persisted_state() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(
            CronJob::Detect(Detector::SshScanners).id(),
            now(),
            "blocked 2 IP(s)",
        )
        .unwrap();

        let statuses = status(&db).unwrap();
        assert_eq!(statuses.len(), CronJob::all().len());

        let ssh = statuses
            .iter()
            .find(|s| s.job == CronJob::Detect(Detector::SshScanners))
            .unwrap();
        assert_eq!(ssh.last_run, Some(now()));
        assert_eq!(ssh.last_summary, Some("blocked 2 IP(s)".to_string()));
        assert!(!ssh.due);

        let web = statuses
            .iter()
            .find(|s| s.job == CronJob::Detect(Detector::WebScanners))
            .unwrap();
        assert_eq!(web.last_run, None);
        assert!(web.due);
    }

    #[test]
    fn every_job_id_is_distinct() {
        let mut ids: Vec<&str> = CronJob::all().iter().map(|j| j.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CronJob::all().len());
    }
}
