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
use anyhow::{Context, Result};
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
    /// Looks at the host — the live ruleset, the units, the disk — and
    /// records what it found for the dashboards to read. See
    /// [`crate::health`].
    HealthCheck,
    /// Keeps the database from growing without bound: prunes the one table
    /// that accumulates forever and hands back the free pages that churn
    /// leaves behind. See [`maintenance`].
    Maintenance,
}

impl CronJob {
    /// Every job: the two fixed ones on either side of every detector.
    pub fn all() -> Vec<CronJob> {
        std::iter::once(CronJob::UpdateIpRanges)
            .chain(Detector::ALL.into_iter().map(CronJob::Detect))
            .chain([
                CronJob::RecordAccessStats,
                CronJob::RenderFirewall,
                CronJob::HealthCheck,
                CronJob::Maintenance,
            ])
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
            CronJob::HealthCheck => "health_check",
            CronJob::Maintenance => "maintenance",
        }
    }

    /// A short label for the Dashboard's job list.
    pub fn label(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "Update crawler IP ranges",
            CronJob::Detect(detector) => detector.spec().job_label,
            CronJob::RecordAccessStats => "Record access-log stats",
            CronJob::RenderFirewall => "Render firewall script",
            CronJob::HealthCheck => "Check system health",
            CronJob::Maintenance => "Prune and compact the database",
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
            CronJob::UpdateIpRanges | CronJob::RenderFirewall | CronJob::Maintenance => {
                Duration::from_secs(24 * 60 * 60)
            }
            // Hourly. `nft list` on a large ruleset is megabytes of text,
            // so this is not something to do per render — but a host that
            // silently stopped being protected should not stay that way
            // for a day either.
            CronJob::HealthCheck => Duration::from_secs(60 * 60),
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
/// Records that `job` just ran, ignoring a failure to write it.
///
/// Ignored deliberately, and it was `batch`'s private helper before the
/// console needed the same thing: the work has already happened by the
/// time this is called, so failing the caller over the bookkeeping would
/// report a successful update as a failure. Shared so the three
/// front-ends cannot drift on which key they stamp — that key is what
/// makes one schedule apply to all of them.
pub fn record_run(db: &Db, job: CronJob, summary: &str) {
    let _ = db.set_cron_last_run(job.id(), now(), summary);
}

pub fn uses_ssh_log(job: CronJob) -> bool {
    match job {
        CronJob::Detect(detector) => detector.spec().uses_ssh_log,
        CronJob::RenderFirewall => true,
        CronJob::RecordAccessStats
        | CronJob::UpdateIpRanges
        | CronJob::HealthCheck
        | CronJob::Maintenance => false,
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
    firewall_out: Option<&std::path::Path>,
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
        CronJob::HealthCheck => {
            unreachable!("HealthCheck is run via health_check, which needs no log")
        }
        CronJob::Maintenance => {
            unreachable!("Maintenance is run via maintenance, which needs no log")
        }
    };
    db.set_cron_last_run(job.id(), now(), &summary)?;
    Ok(summary)
}

/// How long a user agent may go unseen before its `user_agent_stats` row
/// is dropped. Ninety days is well past any window the detectors look at
/// (they read the current log, not this table) while still being long
/// enough that a quarterly-crawling agent keeps its lifetime tally.
pub const USER_AGENT_STATS_MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// The hard ceiling on `user_agent_stats` rows, enforced after the age
/// window. Chosen to sit far above what an ordinary host accumulates — a
/// real one held ~3,200 rows after two months — so that reaching it means
/// a rotating-user-agent flood, which is the case the age window alone
/// cannot contain.
pub const USER_AGENT_STATS_MAX_ROWS: usize = 20_000;

/// Don't rewrite the whole database to reclaim less than this.
const VACUUM_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// ...or to reclaim less than this share of the file. Both thresholds
/// have to be met: the absolute one stops a small database being rewritten
/// over a trivial amount, the proportional one stops a large one being
/// rewritten daily over a freelist it is about to reuse anyway.
const VACUUM_MIN_FRACTION: f64 = 0.20;

/// Whether `size`'s free pages are worth the cost of rewriting the file to
/// get back — see [`Db::vacuum`] for what that cost is.
///
/// Split out from [`maintenance`] so the thresholds can be tested as
/// arithmetic. Proving the same boundaries through `maintenance` would
/// mean building a real multi-megabyte database per case, which is both
/// slower than this file's test budget allows and a worse test: it would
/// be measuring SQLite's page allocator as much as this policy.
fn worth_compacting(size: crate::db::DbSize) -> bool {
    size.free_bytes >= VACUUM_MIN_BYTES
        && size.free_bytes as f64 >= size.bytes as f64 * VACUUM_MIN_FRACTION
}

/// Prunes what has accumulated and compacts the file if that left enough
/// slack to be worth reclaiming, returning the one-line summary the
/// Dashboard's "Scheduled tasks" panel shows.
///
/// Both halves matter, and only together: pruning rows frees *pages*,
/// which SQLite keeps on its freelist for its own reuse and never returns
/// to the filesystem by itself (`auto_vacuum` is off — see `Db::vacuum`).
/// A cleanup that only deleted rows would leave the file exactly as large
/// as the day it peaked, which is not what anyone who looked at `du` and
/// asked for a cleanup means.
///
/// Never fails: like every other cron job here, an error becomes the
/// recorded summary rather than something handed back to a caller who has
/// no one to tell. Deliberately a `&Db` and nothing else — no log, no
/// network, no filesystem beyond the database — so there is no reason for
/// either front-end to run it off-thread.
pub fn maintenance(db: &Db) -> String {
    let mut parts: Vec<String> = Vec::new();

    let keep_since = now() - USER_AGENT_STATS_MAX_AGE.as_secs() as i64;
    match db.prune_user_agent_stats(keep_since, USER_AGENT_STATS_MAX_ROWS) {
        Ok(0) => parts.push("nothing stale to prune".to_string()),
        Ok(pruned) => parts.push(format!("pruned {pruned} stale user agents")),
        Err(err) => return format!("error: {err}"),
    }

    // Expired firewall rules are pruned on every read
    // (`list_firewall_rules`), so this is belt-and-braces for a host whose
    // rules nothing has listed in a while — a render, a dashboard or a
    // detector would all have done it already.
    if let Ok(pruned @ 1..) = db.prune_expired_firewall_rules() {
        parts.push(format!("{pruned} expired rules"));
    }

    match db.size_on_disk() {
        Err(err) => return format!("error: {err}"),
        // In-memory: nothing to compact, and nothing to report about a
        // file that does not exist.
        Ok(None) => {}
        Ok(Some(size)) => {
            if worth_compacting(size) {
                match db.vacuum() {
                    Ok(reclaimed) => parts.push(format!(
                        "reclaimed {}",
                        crate::health::human_bytes(reclaimed)
                    )),
                    Err(err) => parts.push(format!("could not compact: {err}")),
                }
            }
            let now_bytes = db
                .size_on_disk()
                .ok()
                .flatten()
                .map(|size| size.bytes)
                .unwrap_or(size.bytes);
            parts.push(format!(
                "database {}",
                crate::health::human_bytes(now_bytes)
            ));
        }
    }

    parts.join(", ")
}

/// Takes a health probe and records it, for the dashboards to read.
///
/// Split across [`crate::health::probe`] and [`crate::health::store_probe`]
/// rather than storing a finished report: the probe is the expensive half
/// and the slow-moving half, and re-deriving the report at render time is
/// what keeps the panel agreeing with the rules on the screen above it.
pub fn health_check(db: &Db, ssh_log: Option<&std::path::Path>) -> String {
    let backend = match crate::firewall::stored_backend(db) {
        Ok(backend) => backend,
        Err(err) => return format!("error: {err}"),
    };
    // An in-memory database has no filesystem to run out of, so the free
    // space check is asked about the working directory instead of being
    // skipped — it still answers "can this host write anything at all".
    let db_path = db
        .path()
        .unwrap_or_else(|| std::path::PathBuf::from("./stop-bots.sqlite3"));

    let probe = crate::health::probe(backend, &db_path, ssh_log);
    if let Err(err) = crate::health::store_probe(db, &probe) {
        return format!("error: {err}");
    }
    match crate::health::assess(db, &probe) {
        Ok(report) => report.headline(),
        Err(err) => format!("error: {err}"),
    }
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
fn render_firewall(
    db: &Db,
    out_override: Option<&std::path::Path>,
    ssh_log_text: Option<&str>,
) -> String {
    let result: Result<String> = (|| {
        // The *stored* backend, not a hardcoded one. This used to always
        // render nftables while the console applied with whatever the
        // operator had chosen — so on a host set to iptables, each tick
        // quietly replaced their iptables script with an nftables one at
        // the same path, and the next apply ran `sh` over nftables syntax.
        let backend = crate::firewall::stored_backend(db)?;
        let out_path = crate::firewall::output_path(out_override, backend);
        let out_path = out_path.as_path();
        let built = crate::firewall::build_script(db, backend)?;
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
        // Named in the error, because this is the one failure here an
        // operator has to act on outside stop-bots, and "Permission
        // denied (os error 13)" on its own doesn't say which file to fix.
        // The default is under `/etc`, so an unprivileged `stop-bots web`
        // hits this on every daily run until someone grants the write or
        // points `render-firewall` somewhere else.
        crate::firewall::write_script(out_path, &built.script)
            .with_context(|| format!("could not write {}", out_path.display()))?;
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(&built.rules))?;
        Ok(format!(
            "wrote {} rule(s) to {}",
            built.written,
            out_path.display()
        ))
    })();
    match result {
        Ok(summary) => summary,
        // `{err:#}` rather than `{err}`: the whole chain, since the
        // outermost message is the context and the cause is what says
        // what actually went wrong.
        Err(err) => format!("error: {err:#}"),
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
            // Storing can fail on the feed as well as on the database: it
            // refuses a fetch with nothing usable in it, rather than
            // replacing a working list with an empty one. Counted as a
            // failure like any other rather than propagated — a `?` here
            // would abandon the loop *and* skip `set_cron_last_run` below,
            // which leaves the job permanently due and re-fetching every
            // one of these sources on every tick.
            Ok(cidrs) if crate::ipranges::store(db, kind, &cidrs).is_ok() => updated += 1,
            _ => failed += 1,
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

    #[test]
    fn maintenance_prunes_a_stale_user_agent_and_says_so() {
        let db = test_db();
        let mut counts = std::collections::HashMap::new();
        counts.insert("long-gone".to_string(), 1);
        // Last seen a day before the window even opens.
        let long_ago = now() - USER_AGENT_STATS_MAX_AGE.as_secs() as i64 - 86_400;
        db.record_user_agent_hits(&counts, long_ago).unwrap();

        let summary = maintenance(&db);

        assert!(db.list_user_agent_stats().unwrap().is_empty());
        assert!(
            summary.contains("pruned 1 stale user agents"),
            "the summary should say what went: {summary}"
        );
    }

    #[test]
    fn maintenance_keeps_a_user_agent_seen_inside_the_window() {
        let db = test_db();
        let mut counts = std::collections::HashMap::new();
        counts.insert("still-here".to_string(), 1);
        db.record_user_agent_hits(&counts, now()).unwrap();

        let summary = maintenance(&db);

        assert_eq!(db.list_user_agent_stats().unwrap().len(), 1);
        assert!(
            summary.contains("nothing stale"),
            "a clean database should say so plainly: {summary}"
        );
    }

    /// The compaction thresholds, as arithmetic. Both have to be met, so
    /// each case here fails exactly one of them — a single "yes" case
    /// would pass against a policy that had dropped either check.
    #[test]
    fn worth_compacting_needs_both_a_large_and_a_proportionate_freelist() {
        let mb = 1024 * 1024;
        let size = |bytes, free_bytes| crate::db::DbSize { bytes, free_bytes };

        // 11MB of 15MB: the state the host that prompted this was in.
        assert!(worth_compacting(size(15 * mb, 11 * mb)));
        // Proportionate (50%) but trivial in absolute terms — rewriting a
        // 6MB file to win 3MB is not worth a daily rewrite.
        assert!(!worth_compacting(size(6 * mb, 3 * mb)));
        // Large in absolute terms (8MB) but only 8% of a 100MB file, which
        // SQLite is about to reuse anyway.
        assert!(!worth_compacting(size(100 * mb, 8 * mb)));
        // A tight database is the common case and must never be rewritten.
        assert!(!worth_compacting(size(4 * mb, 0)));
    }

    /// `maintenance` takes only a `&Db`, and an in-memory one has no file
    /// — it must still report what it pruned and say nothing about a size
    /// that does not exist. Both front-ends' own test suites run against
    /// in-memory databases, so this is the path they take.
    #[test]
    fn maintenance_reports_no_size_for_an_in_memory_database() {
        let summary = maintenance(&test_db());

        assert!(!summary.contains("database "), "{summary}");
        assert!(!summary.contains("reclaimed"), "{summary}");
    }

    /// A job missing from `all()` is one the internal cron never runs and
    /// the dashboards never list — the failure mode of a variant added to
    /// the enum and nowhere else.
    #[test]
    fn maintenance_is_a_scheduled_job() {
        assert!(CronJob::all().contains(&CronJob::Maintenance));
        assert!(!uses_ssh_log(CronJob::Maintenance));
        assert_eq!(CronJob::Maintenance.id(), "maintenance");
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
        let summary = run_log_job(&db, CronJob::Detect(detector), None, Some(&out)).unwrap();
        assert_eq!(summary, "disabled");

        detector.set_enabled(&db, true).unwrap();
        let summary = run_log_job(&db, CronJob::Detect(detector), None, Some(&out)).unwrap();
        assert_eq!(summary, "SSH log unavailable");

        let summary = run_log_job(&db, CronJob::RecordAccessStats, None, Some(&out)).unwrap();
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

        let summary = render_firewall(&db, Some(&out_path), None);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(out_path.exists());
    }

    /// An unprivileged `stop-bots web` hits this once a day, forever, so
    /// the summary the Dashboard shows has to name the file rather than
    /// leaving the operator with a bare "Permission denied".
    #[test]
    fn a_firewall_script_that_cannot_be_written_says_which_path_failed() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        // A file where the job wants a directory: the same "cannot write
        // there" shape as a read-only `/etc`, without needing to drop
        // privileges inside a test.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "").unwrap();
        let out_path = blocker.join("fw.nft");

        let summary = render_firewall(&db, Some(&out_path), None);

        assert!(summary.starts_with("error: "), "summary was: {summary}");
        assert!(
            summary.contains(&out_path.display().to_string()),
            "summary named no path: {summary}"
        );
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

        let summary = render_firewall(&db, Some(&out_path), None);

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
    /// Storing can now fail on the *feed* — it refuses a fetch with nothing
    /// usable in it rather than replacing a working list with an empty one.
    /// That must stay a counted failure: propagating it would abandon the
    /// loop before `set_cron_last_run`, leaving the job permanently due and
    /// re-fetching every source on every tick.
    #[test]
    fn one_unusable_source_is_counted_rather_than_stalling_the_whole_job() {
        use crate::ipranges::IpRangeSourceKind;

        let db = test_db();
        let results = vec![
            (
                IpRangeSourceKind::GoogleBot,
                Ok(vec!["<!DOCTYPE html>".to_string()]),
            ),
            (
                IpRangeSourceKind::GptBot,
                Ok(vec!["1.2.3.0/24".to_string()]),
            ),
        ];

        let summary = store_ip_ranges(&db, results).unwrap();

        assert!(
            summary.contains("updated 1 crawler source(s), 1 failed"),
            "summary was: {summary}"
        );
        assert!(
            db.get_cron_last_run(CronJob::UpdateIpRanges.id())
                .unwrap()
                .is_some(),
            "the run must be recorded, or the job stays due forever"
        );
        assert_eq!(
            db.ip_ranges_for_source(IpRangeSourceKind::GptBot.id())
                .unwrap(),
            vec!["1.2.3.0/24".to_string()],
            "the source that worked must still have been stored"
        );
    }
}
