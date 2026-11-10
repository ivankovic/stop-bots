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

//! The schedule: which background jobs are due, and what each one does.
//! Two things run it — the TUI, checking every minute while it is open,
//! and [`tick`], which the cron file `stop-bots install cron` writes runs
//! once a minute. The TUI Dashboard's "Scheduled tasks" panel is where
//! their state is shown.
//!
//! **Nothing here runs by itself.** With no cron file installed and the
//! TUI closed, every job waits until one of them runs again. A job that's
//! overdue then just runs as soon as it's next checked, the same never-run-yet-so-do-it-now convention `ipranges`
//! sources already use for staleness, rather than trying to "catch up" on
//! however many intervals were missed.
//!
//! ## One schedule, however many front-ends
//!
//! The TUI (`App::check_cron` in `crate::app`), `stop-bots tick` from the
//! cron file `install cron` writes ([`tick`]), and a crontab entry of the
//! operator's own running `stop-bots batch` all record through the same
//! `Db::set_cron_last_run` keys. So running
//! two of them at once doesn't double the work: whichever gets there first
//! marks the job done, and the other finds it no longer due. That is also
//! why the per-job work lives here rather than in either front-end — two
//! schedulers computing "what this job does" separately are two
//! schedulers that will eventually disagree.
//!
//! ## One dispatch, two ways of waiting
//!
//! Which job does what is decided once, in [`start`] and [`finish`]. What
//! the two front-ends do differently is only *where the slow half runs*:
//! [`start`] does the database half and hands back a [`Work`] that holds no
//! database, [`Work::run`] does the reading, downloading or probing, and
//! [`finish`] stores what it found. [`tick`] runs the three in line; the
//! TUI runs [`Work::run`] on another task and [`finish`] back on the thread
//! that owns its `Db`, the same split as every other `start_`/`finish_`
//! pair there. A job added to [`CronJob`] gets an arm in [`start`], and
//! both front-ends run it.
//!
//! The one job each front-end runs its own way is `ApplyNginx` with the
//! switch on ([`Next::ApplySites`]): in the TUI it is the site apply the
//! operator's own "Apply everything" starts, so it shares that apply's
//! one-at-a-time guard and its reload, rather than racing it.
//!
//! **Each job only does what its equivalent CLI subcommand does, and by
//! default that stops at writing.** `RenderFirewall` writes the script to
//! disk on a timer, same as `render-firewall` — beside the applied script
//! the boot unit loads, never over it, so a reboot does not enforce what
//! nobody applied. Running it (`sh`/`nft -f`) is the admin's, on purpose —
//! see `src/iptables.rs`/`src/nftables.rs`'s "generate-only" module docs.
//!
//! Two switches move that line, and only for the admin who sets them.
//! `Db::get_auto_apply` lets `ApplyNginx` write site configs and reload
//! NGINX; `Db::get_auto_apply_firewall` lets `RenderFirewall` run the
//! script it just wrote. Both are off by default and each is set
//! separately, because the risks are not comparable: a bad NGINX config is
//! caught by `nginx -t` and costs a failed reload, while a bad firewall
//! ruleset locks you out of the host. The firewall one goes through the
//! same guard as every other apply (see `firewall::FirewallRun`), which
//! refuses when the anti-lockout check could not read an SSH log: "the
//! check could not run" is not "the check passed".
//!
//! **No confirm-or-revert here.** An apply someone is watching arms a
//! revert and asks "keep these firewall rules?" (see `crate::revert`);
//! a job has nobody to ask, and a revert would undo every unattended
//! apply a minute later. It does refuse to apply while an interactive
//! apply is still waiting for its answer.

use crate::db::Db;
use crate::protection::Detector;
use crate::webserver::ServerCommands;
use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One of the background jobs the internal cron schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CronJob {
    /// Refetches Googlebot/Bingbot/GPTBot's published CIDR ranges.
    UpdateIpRanges,
    /// Downloads every list this host uses — the same plan as "Update
    /// everything" (see [`crate::refresh`]) — once a week, so bot lists,
    /// the enabled feeds and the selected countries do not go stale on a
    /// host where nobody presses `u` and no `batch` runs.
    UpdateEverything,
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
    /// Re-applies site configs that have fallen behind the database, and
    /// reloads NGINX — but only when the admin has switched
    /// `Db::get_auto_apply` on. See [`apply_nginx`].
    ApplyNginx,
    /// Reads the outbound attempts the kernel logged, says who made them,
    /// contains them when that is switched on, and keeps every open
    /// containment true to what is running. See [`crate::contain`].
    Egress,
    /// Downloads the command-and-control feeds that are switched on, and
    /// rewrites the resolver's sinkhole file when one is chosen. Daily:
    /// these lists change by the hour. See [`crate::egress`].
    UpdateEgressFeeds,
}

impl CronJob {
    /// Every job: the two fixed ones on either side of every detector.
    pub fn all() -> Vec<CronJob> {
        [CronJob::UpdateIpRanges, CronJob::UpdateEverything]
            .into_iter()
            .chain(Detector::ALL.into_iter().map(CronJob::Detect))
            .chain([
                // Before the render, so what it contains is in the script
                // the same pass writes.
                CronJob::Egress,
                CronJob::RecordAccessStats,
                CronJob::RenderFirewall,
                CronJob::HealthCheck,
                CronJob::Maintenance,
                CronJob::ApplyNginx,
                CronJob::UpdateEgressFeeds,
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
            CronJob::UpdateEverything => "update_everything",
            CronJob::Detect(detector) => detector.id(),
            CronJob::RecordAccessStats => "record_access_stats",
            CronJob::RenderFirewall => "render_firewall",
            CronJob::HealthCheck => "health_check",
            CronJob::Maintenance => "maintenance",
            CronJob::ApplyNginx => "apply_nginx",
            CronJob::Egress => "egress",
            CronJob::UpdateEgressFeeds => "update_egress_feeds",
        }
    }

    /// A short label for the Dashboard's job list.
    pub fn label(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "Update crawler IP ranges",
            CronJob::UpdateEverything => "Update every list",
            CronJob::Detect(detector) => detector.spec().job_label,
            CronJob::RecordAccessStats => "Record access-log stats",
            CronJob::RenderFirewall => "Render firewall script",
            CronJob::HealthCheck => "Check system health",
            CronJob::Maintenance => "Prune and compact the database",
            CronJob::ApplyNginx => "Auto-apply site configs",
            CronJob::Egress => "Answer outbound attempts",
            CronJob::UpdateEgressFeeds => "Update C&C feeds",
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
            CronJob::UpdateIpRanges
            | CronJob::RenderFirewall
            | CronJob::Maintenance
            | CronJob::UpdateEgressFeeds => Duration::from_secs(24 * 60 * 60),
            // Hourly. `nft list` on a large ruleset is megabytes of text,
            // so this is not something to do per render — but a host that
            // silently stopped being protected should not stay that way
            // for a day either.
            // Hourly, and deliberately not faster. The detectors run every
            // minute and each new block changes the generated config, so a
            // one-minute interval here would mean reloading a live NGINX
            // every time one bot arrived. An hour bounds the reloads while
            // still being far inside "I turned the switch on and it
            // happened".
            CronJob::HealthCheck | CronJob::ApplyNginx => Duration::from_secs(60 * 60),
            CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::Egress => {
                Duration::from_secs(60)
            }
            CronJob::UpdateEverything => Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    /// How long after a run at `last_run` this job is due again: its
    /// [`Self::interval`], plus, for the weekly download, up to
    /// [`UPDATE_JITTER`] more.
    ///
    /// The jitter is worked out from `last_run` rather than drawn at random
    /// so that every front-end, and the Dashboard projecting the next run,
    /// agree on it without storing it. It still moves: each run lands at a
    /// different minute, so the week after lands somewhere else again, and
    /// hosts that upgraded at the same moment drift apart instead of
    /// asking the same feeds for the same files at the same time forever.
    pub fn due_after(self, last_run: i64) -> Duration {
        let jitter = match self {
            CronJob::UpdateEverything => {
                let mixed = (last_run as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
                Duration::from_secs(mixed % UPDATE_JITTER.as_secs())
            }
            _ => Duration::ZERO,
        };
        self.interval() + jitter
    }
}

/// The most the weekly download is pushed back past its week — see
/// [`CronJob::due_after`].
pub const UPDATE_JITTER: Duration = Duration::from_secs(12 * 60 * 60);

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

/// The shortest gap between two renders triggered by a rule *change*
/// rather than by the clock, after one that failed or was refused.
///
/// Without a floor, a render that keeps failing — an unwritable
/// `/etc/stop-bots`, which is the common one — would leave the rules
/// permanently unrendered and so permanently "changed", and the cron would
/// retry it on every tick, forever, once a minute. The floor turns that
/// into a retry every five minutes.
///
/// It once held after a render that worked too, which is the wrong place
/// for it: one address sent a host 1,133 requests over five minutes, and
/// a block found in its first minute could wait out the floor from
/// whatever render came before. After a render that worked, a change now
/// renders on the next tick; on that host, with 52,000 rules, that is
/// under two seconds of render and load a minute, and only while the
/// rules keep changing.
const RENDER_MIN_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Whether `job` is due: it's never run, or its interval has elapsed since
/// it last did.
///
/// [`CronJob::RenderFirewall`] has one extra way to become due, and it is
/// the difference between a block being enforced in minutes and in a day.
/// Its interval is 24 hours because nothing about rendering is
/// time-sensitive — but the *rules* are: the detectors add blocks every
/// minute, and on a real host fifteen of them sat in the database for
/// twenty-one hours, detected and unenforced, waiting for a clock. So a
/// changed rule set makes the render due too, subject to
/// [`RENDER_MIN_INTERVAL`].
///
/// The interval stays the *maximum* staleness rather than becoming the
/// only trigger: a render also refreshes rules that expired since the last
/// one, and those change no signature — a lapsed rule simply stops being
/// returned, which `firewall::needs_render` cannot distinguish from
/// nothing having happened until something else changes too.
pub fn is_due(db: &Db, job: CronJob) -> Result<bool> {
    let Some(last_run) = db.get_cron_last_run(job.id())? else {
        return Ok(match job {
            CronJob::UpdateEverything | CronJob::UpdateIpRanges => first_download_base(db, job)?
                .is_some_and(|base| now() - base >= job.due_after(base).as_secs() as i64),
            _ => true,
        });
    };
    let elapsed = now() - last_run;
    if elapsed >= job.due_after(last_run).as_secs() as i64 {
        return Ok(true);
    }
    // Only asked of the one job that has this trigger, and only once the
    // cheap time check has already said no — `needs_render` walks every
    // rule, and there is no reason to pay that for a job that is due
    // anyway or for one this does not apply to.
    if job == CronJob::RenderFirewall {
        let backing_off = db
            .get_cron_last_summary(job.id())?
            .is_some_and(|summary| render_failed(&summary));
        if !backing_off || elapsed >= RENDER_MIN_INTERVAL.as_secs() as i64 {
            return crate::firewall::needs_render(db);
        }
    }
    Ok(false)
}

/// When `job` is next expected to run — its last run plus its interval —
/// or `None` if it has never run, since nothing can be projected from a
/// job with no history.
///
/// A returned time in the *past* means the job is overdue rather than
/// scheduled: it runs at the next tick if a front-end is driving the
/// internal cron, and never if one is not. Callers that want to promise a
/// time to a reader have to check that for themselves — see
/// `health::script_freshness`, which is the reason this exists.
///
/// Deliberately next to [`is_due`] and built from the same two values, so
/// the projected time and the due-check can never disagree about what
/// [`CronJob::interval`] means.
pub fn next_run_at(db: &Db, job: CronJob) -> Result<Option<i64>> {
    let last_run = match db.get_cron_last_run(job.id())? {
        Some(at) => Some(at),
        None if is_download(job) => first_download_base(db, job)?,
        None => None,
    };
    Ok(last_run.map(|last_run| last_run + job.due_after(last_run).as_secs() as i64))
}

/// Whether `job` downloads something, and so waits for the operator's
/// first download before it ever runs (see [`first_download_base`]) and
/// for the download lease every time (see [`crate::refresh::Lease`]).
pub fn is_download(job: CronJob) -> bool {
    matches!(job, CronJob::UpdateEverything | CronJob::UpdateIpRanges)
}

/// What a download job counts from before it has ever run: when this
/// host's oldest downloaded list was fetched, or `None` if it has fetched
/// none. For the weekly download, a bot list; for the daily crawler
/// ranges, a bot list or one of the crawler range lists.
///
/// Not "never run, so run now" like every other job. On a database that
/// has fetched nothing, that would download the first time a front-end
/// opened, which is the operator's first `u` (or "Update everything", or a
/// `batch`) to press, not the cron's; so the job waits for the first
/// download and counts its interval from it. On one upgraded from before
/// the job existed, the lists are as old as their last fetch, and a
/// month-old list is due at once. The built-in list is left out: it is
/// stored at every start-up.
fn first_download_base(db: &Db, job: CronJob) -> Result<Option<i64>> {
    let bot_lists = db
        .list_sources()?
        .into_iter()
        .filter(|source| source.id != crate::botlist::SourceKind::StopBotsExtras.id())
        .filter_map(|source| source.last_fetched_at)
        .min();
    if job != CronJob::UpdateIpRanges {
        return Ok(bot_lists);
    }
    let crawler_ranges = db
        .list_ip_range_sources()?
        .into_iter()
        .filter_map(|source| source.last_fetched_at)
        .min();
    Ok(bot_lists.into_iter().chain(crawler_ranges).min())
}

/// Every job that's currently due, in [`CronJob::all()`] order.
///
/// `UpdateIpRanges` is left out while `UpdateEverything` is due: the
/// weekly download fetches the crawler ranges too, and records both jobs,
/// so running the two would fetch those three files twice in one tick.
pub fn due_jobs(db: &Db) -> Result<Vec<CronJob>> {
    let due: Vec<CronJob> = CronJob::all()
        .into_iter()
        .filter_map(|job| match is_due(db, job) {
            Ok(true) => Some(Ok(job)),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<_>>()?;
    let everything = due.contains(&CronJob::UpdateEverything);
    Ok(due
        .into_iter()
        .filter(|job| !(everything && *job == CronJob::UpdateIpRanges))
        .collect())
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
    crate::activity::note(db, job, summary, now());
}

/// Whether this job reads the SSH log rather than the NGINX access log.
///
/// `RenderFirewall` reads the SSH log without being a detector: it needs
/// the currently-connected clients for its lockout guard, not a log to
/// scan for attackers.
pub fn uses_ssh_log(job: CronJob) -> bool {
    match job {
        CronJob::Detect(detector) => detector.spec().log == crate::protection::DetectorLog::Ssh,
        CronJob::RenderFirewall => true,
        CronJob::RecordAccessStats
        | CronJob::Egress
        | CronJob::UpdateEgressFeeds
        | CronJob::UpdateIpRanges
        | CronJob::UpdateEverything
        | CronJob::HealthCheck
        | CronJob::Maintenance
        | CronJob::ApplyNginx => false,
    }
}

/// Whether `job` is one of the jobs a log pass serves (see
/// [`crate::logscan`]): every detector, the access-stats tally and the
/// firewall render, whose guard wants the SSH log.
pub fn is_log_job(job: CronJob) -> bool {
    matches!(
        job,
        CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::RenderFirewall | CronJob::Egress
    )
}

/// Runs each of `jobs` on what one log pass read and stored, and records
/// what each did, returning the summaries the Dashboard's "Scheduled
/// tasks" panel will show.
///
/// The log was read once for all of them, before this, by
/// [`crate::logscan`]; nothing here reads a log. A detector decides on the
/// evidence stored for it inside its window, which is every line of it
/// however many passes it took to read them.
///
/// The `Result` covers only the bookkeeping. **A job's own failure is
/// never an error** -- it becomes the recorded summary instead. A cron job
/// exists to say what it did without anyone watching, so "the SSH log was
/// unreadable" is an outcome to record, not something to hand back to a
/// caller who has no one to tell.
///
/// `firewall_out` is a parameter rather than
/// [`crate::firewall::DEFAULT_OUTPUT_PATH`] read directly so that tests,
/// and any front-end that shouldn't write to `/etc`, can point it
/// somewhere else.
///
/// Panics on a job that is not [`is_log_job`]: those go through their own
/// functions here.
pub fn run_log_jobs(
    db: &Db,
    jobs: &[CronJob],
    applied: &crate::logscan::Applied,
    firewall_out: Option<&std::path::Path>,
    apply_for_real: bool,
    egress: Option<&EgressInputs>,
) -> Result<Vec<(CronJob, String)>> {
    let mut summaries = Vec::new();
    for &job in jobs {
        let summary = match job {
            // Every detector runs through one arm. What differs between
            // them -- the log, the threshold, the window -- is on the spec
            // or in `scanblock::run_detector`, so a new detector adds no
            // code here.
            CronJob::Detect(detector) => run_detector(db, detector, applied),
            CronJob::RecordAccessStats => {
                if applied.access.is_readable() {
                    format!("{}{}", applied.stats.summary(), applied.unreadable_note())
                } else {
                    "access log unavailable".to_string()
                }
            }
            CronJob::RenderFirewall => {
                // The guard's clients: everyone who logged in, in what this
                // pass read and in the week the window keeps. `None` when
                // the SSH log could not be read, which is not the same as
                // "read, and nobody is connected".
                let connected = if applied.ssh.is_readable() {
                    let mut all = db.recent_ssh_login_ips()?;
                    all.extend(applied.logins.iter().cloned());
                    all.sort();
                    all.dedup();
                    Some(all)
                } else {
                    None
                };
                render_firewall(db, firewall_out, connected.as_deref(), apply_for_real)
            }
            CronJob::Egress => run_egress(db, applied, egress, apply_for_real),
            CronJob::UpdateEgressFeeds
            | CronJob::UpdateIpRanges
            | CronJob::UpdateEverything
            | CronJob::HealthCheck
            | CronJob::Maintenance
            | CronJob::ApplyNginx => {
                unreachable!("{} reads no log, so `start` runs it on its own", job.id())
            }
        };
        db.set_cron_last_run(job.id(), now(), &summary)?;
        crate::activity::note(db, job, &summary, now());
        summaries.push((job, summary));
    }
    Ok(summaries)
}

/// How long a user agent may go unseen before its `user_agent_stats` row
/// is dropped. Ninety days is well past any window the detectors look at
/// (they read the current log, not this table) while still being long
/// enough that a quarterly-crawling agent keeps its lifetime tally.
pub const USER_AGENT_STATS_MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// The hard ceiling on `user_agent_stats` rows, enforced after the age
/// window here, and as rows are written too (see
/// `Db::upsert_user_agent_hits`): a rotating-user-agent flood is the case
/// the age window alone cannot contain, and it arrives between two daily
/// runs of this.
pub const USER_AGENT_STATS_MAX_ROWS: usize = crate::db::USER_AGENT_STATS_MAX_ROWS;

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

/// Re-applies every known site's config and reloads NGINX, when — and
/// only when — `Db::get_auto_apply` is on.
///
/// The gap this closes: a detector blocking one new user agent changes
/// the generated sentinel block, which puts every applied site back to
/// `STALE` within the minute. Nothing in the internal cron applied that,
/// so a host left to itself drifted further from its own configuration
/// every day, and the health report's "NGINX blocks are applied" warning
/// was the only sign.
///
/// **The toggle is read before any work, not after.** `apply_all_sites`
/// walks every config file under `root`; on a host with the switch off
/// that should not happen hourly. Same convention the detectors follow —
/// see `protection`'s module docs.
///
/// `reload` is the front-end's "do things for real" flag (the TUI's
/// `reload_nginx`; `tick` always passes `true`). False still writes the config,
/// because a written config is inert until something reloads it — the
/// same split every other apply path here makes.
///
/// Never fails, like every other job: a reload that NGINX rejects becomes
/// the recorded summary, which is what puts it in front of an admin on
/// the Scheduled tasks panel. Returning an error instead would only be
/// printed to stderr by the caller, which moves on — so on the one host
/// where this matters, a broken config would fail silently every hour.
///
/// The commands come from `host`, the host settings, never from `db`.
pub fn apply_nginx(
    db: &Db,
    host: &crate::hostconf::HostConf,
    root: &std::path::Path,
    reload: bool,
) -> String {
    match auto_apply_is_off(db) {
        Some(summary) => summary,
        None => apply_sites(db, host, root, reload),
    }
}

/// Why `ApplyNginx` does nothing this time — the switch is off, or could
/// not be read — or `None` when it is on. Asked by both front-ends before
/// they do any work, for the reason [`apply_nginx`] gives.
fn auto_apply_is_off(db: &Db) -> Option<String> {
    match db.get_auto_apply() {
        Ok(false) => Some("auto-apply is off".to_string()),
        Ok(true) => None,
        Err(err) => Some(format!("error: {err}")),
    }
}

/// `ApplyNginx`'s work once the switch is on, done in line: `tick`'s half
/// of [`Next::ApplySites`].
pub fn apply_sites(
    db: &Db,
    host: &crate::hostconf::HostConf,
    root: &std::path::Path,
    reload: bool,
) -> String {
    let commands = match reload.then(|| ServerCommands::from_host(host)).transpose() {
        Ok(commands) => commands,
        Err(err) => return format!("error: {err:#}"),
    };
    // Tested before the reload, and put back if the test fails — see
    // `apply_all_sites_and_reload`. Unattended is where that matters most.
    match crate::webserver::apply_all_sites_and_reload(
        host.web_server(),
        db,
        root,
        commands.as_ref(),
    ) {
        Ok(applied) => apply_nginx_summary(&applied),
        Err(err) => format!("error: {err:#}"),
    }
}

/// The `ApplyNginx` job's summary of what an apply did.
pub fn apply_nginx_summary(applied: &crate::webserver::ApplyAllOutcome) -> String {
    // Writing the sentinel block does nothing until NGINX re-reads it, so
    // there is nothing to reload when nothing changed on disk — the same
    // condition `apply-blocks` and `batch` both gate on, and the reason
    // an hourly job on a quiet host costs one directory walk rather than
    // one `systemctl reload`.
    if applied.changed == 0 {
        return format!("{} site(s) already up to date", applied.sites);
    }

    let mut summary = format!(
        "applied {} site(s), {} file(s) changed",
        applied.sites, applied.changed
    );
    summary.push_str(if applied.reloaded {
        ", reloaded"
    } else {
        ", not reloaded"
    });
    summary
}

/// What the `HealthCheck` probe needs from the database, read before it
/// runs: the probe shells out to `nft`, `systemctl` and `df` — `nft list`
/// on a large ruleset is megabytes of text — and so runs where no `Db`
/// can reach.
#[derive(Debug)]
struct ProbeInputs {
    backend: crate::firewall::FirewallBackend,
    db_path: std::path::PathBuf,
    ssh_log: Option<std::path::PathBuf>,
    host: crate::hostconf::HostConf,
    block_status: u16,
    claims: Vec<crate::accesslog::CrawlerClaim>,
}

impl ProbeInputs {
    /// `Err` is the summary to record: with no backend there is no
    /// ruleset to ask about.
    fn read(db: &Db, settings: &Settings) -> std::result::Result<ProbeInputs, String> {
        let backend = crate::firewall::stored_backend(db).map_err(|err| format!("error: {err}"))?;
        // An in-memory database has no filesystem to run out of, so the
        // free space check is asked about the working directory instead of
        // being skipped — it still answers "can this host write anything
        // at all".
        let db_path = db
            .path()
            .unwrap_or_else(|| std::path::PathBuf::from("./stop-bots.sqlite3"));
        let block_status = db
            .get_block_response()
            .map(|r| r.status_code())
            .unwrap_or_else(|_| crate::db::BlockResponse::default().status_code());
        Ok(ProbeInputs {
            backend,
            db_path,
            ssh_log: settings.ssh_log.map(std::path::Path::to_path_buf),
            host: settings.host.clone(),
            block_status,
            claims: crate::scanblock::crawler_claims(db).unwrap_or_default(),
        })
    }

    fn probe(self) -> crate::health::Probe {
        crate::health::probe(
            self.backend,
            &self.db_path,
            self.ssh_log.as_deref(),
            &self.host,
            self.block_status,
            self.claims,
        )
    }
}

/// Records a health probe, for the dashboards to read, and returns the
/// `HealthCheck` job's summary.
///
/// Split across [`crate::health::probe`] and [`crate::health::store_probe`]
/// rather than storing a finished report: the probe is the expensive half
/// and the slow-moving half, and re-deriving the report at render time is
/// what keeps the panel agreeing with the rules on the screen above it.
fn store_health(db: &Db, probe: &crate::health::Probe) -> String {
    if let Err(err) = crate::health::store_probe(db, probe) {
        return format!("error: {err}");
    }
    match crate::health::assess(db, probe) {
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
fn run_detector(db: &Db, detector: Detector, applied: &crate::logscan::Applied) -> String {
    let enabled = match detector.is_enabled(db) {
        Ok(enabled) => enabled,
        Err(err) => return format!("error: {err}"),
    };
    if !enabled {
        return "disabled".to_string();
    }
    if !applied.log_for(detector).is_readable() {
        return format!("{} unavailable", detector.spec().log.name());
    }
    let ttl = match detector.ttl_days(db) {
        Ok(ttl) => ttl,
        Err(err) => return format!("error: {err}"),
    };
    match crate::scanblock::run_detector(db, detector, ttl, applied.now, false) {
        Ok(outcome) => outcome.summary(),
        Err(err) => format!("error: {err}"),
    }
}

/// What the `Egress` job is given, besides the log pass: the host as it
/// looked from the slow half, where asking the container runtime belongs,
/// and the runtime to pause with.
#[derive(Debug, Clone)]
pub struct EgressInputs {
    pub host: crate::contain::Host,
    pub runtime: Option<crate::contain::Runtime>,
}

/// The work behind the `Egress` job. Answers what the kernel logged when
/// it could be read, and keeps the containments true either way: a
/// container a restart brought back is paused again whether or not the
/// log could be read this minute.
fn run_egress(
    db: &Db,
    applied: &crate::logscan::Applied,
    inputs: Option<&EgressInputs>,
    for_real: bool,
) -> String {
    let result: Result<String> = (|| {
        let mode = crate::egress::Mode::get(db)?;
        let open = db.open_containments()?.len();
        if mode == crate::egress::Mode::Off && open == 0 {
            return Ok("outbound checks are off".to_string());
        }
        let firewall = crate::contain::LiveFirewall {
            backend: crate::firewall::stored_backend(db)?,
        };
        let empty = EgressInputs {
            host: crate::contain::Host::default(),
            runtime: None,
        };
        let inputs = inputs.unwrap_or(&empty);
        let ctx = crate::contain::Ctx {
            firewall: &firewall,
            runtime: inputs.runtime.as_ref(),
            for_real,
        };
        if mode != crate::egress::Mode::Off && !applied.kernel.is_readable() {
            let mut said = vec!["kernel log unavailable".to_string()];
            said.extend(crate::contain::maintain(db, &ctx, &inputs.host)?);
            return Ok(said.join("; "));
        }
        Ok(crate::contain::respond(db, &ctx, &inputs.host, applied.now)?.summary())
    })();
    result.unwrap_or_else(|err| format!("error: {err:#}"))
}

/// The work behind the `RenderFirewall` job: renders the current rules for
/// the stored backend and writes them beside the applied script (see
/// [`crate::firewall::rendered_path`]) — never over it, so what the boot
/// unit loads stays what was last applied.
///
/// Goes through [`crate::firewall::render_and_apply`] like every other
/// front-end, with the connected clients already known from the pass that read the
/// SSH log; `None` means the log could not be read, so the guard could not
/// run.
///
/// **Writes, and applies only when told to twice.** A script on disk does
/// nothing until someone runs it, and that stays the default; see this
/// module's docs for why the line is where it is.
/// `Db::get_auto_apply_firewall` moves it, and the shared policy then
/// refuses unless the lockout guard actually *ran*. A person reading a
/// refusal can get back into the host; a cron job at 3am cannot.
fn render_firewall(
    db: &Db,
    out_override: Option<&std::path::Path>,
    connected: Option<&[String]>,
    apply_for_real: bool,
) -> String {
    let result: Result<String> = (|| {
        // The *stored* backend, not a hardcoded one. This used to always
        // render nftables while every apply by hand used whatever the
        // operator had chosen — so on a host set to iptables, each tick
        // quietly replaced their iptables script with an nftables one at
        // the same path, and the next apply ran `sh` over nftables syntax.
        let backend = crate::firewall::stored_backend(db)?;
        let run = crate::firewall::FirewallRun::new(
            backend,
            crate::firewall::output_path(out_override, backend),
        )
        .apply(db.get_auto_apply_firewall()?)
        .for_real(apply_for_real);
        let outcome = crate::firewall::render_and_apply(
            db,
            run,
            crate::firewall::SshLog::Connected(connected),
        )?;
        Ok(render_summary(&outcome.write, &outcome.summary()))
    })();
    match result {
        Ok(summary) => summary,
        // `{err:#}` rather than `{err}`: the whole chain, since the
        // outermost message is the context and the cause is what says
        // what actually went wrong.
        Err(err) => format!("error: {err:#}"),
    }
}

/// The `RenderFirewall` job's summary of a run that wrote (or did not
/// write) `summary`.
///
/// The write's own failure names the file, because this is the one
/// failure here an operator has to act on outside stop-bots.
pub fn render_summary(write: &crate::firewall::WriteStep, summary: &str) -> String {
    match write {
        crate::firewall::WriteStep::Written => summary.to_string(),
        crate::firewall::WriteStep::Refused => format!("skipped: {summary}"),
        crate::firewall::WriteStep::Failed(_) => format!("error: {summary}"),
    }
}

/// Whether a `RenderFirewall` summary is one that wrote nothing: a write
/// that failed or was refused ([`render_summary`]), or an error before it
/// ([`render_firewall`]). What [`RENDER_MIN_INTERVAL`] backs off after.
fn render_failed(summary: &str) -> bool {
    summary.starts_with("error:") || summary.starts_with("skipped:")
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
async fn fetch_ip_ranges() -> Vec<(
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
fn store_ip_ranges(
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
    crate::activity::note(db, CronJob::UpdateIpRanges, &summary, now());
    Ok(summary)
}

/// How the due jobs are started: every log job in one pass (see
/// [`crate::logscan`]), which reads each log once for all of them, and
/// every other job on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Task {
    LogPass(Vec<CronJob>),
    Job(CronJob),
}

impl Task {
    /// The jobs this task runs.
    pub fn jobs(&self) -> &[CronJob] {
        match self {
            Task::LogPass(jobs) => jobs,
            Task::Job(job) => std::slice::from_ref(job),
        }
    }
}

/// The due jobs, as the [`Task`]s that start them: the log pass first,
/// then the rest in [`CronJob::all()`] order.
pub fn tasks(due: Vec<CronJob>) -> Vec<Task> {
    let (log_jobs, others): (Vec<CronJob>, Vec<CronJob>) =
        due.into_iter().partition(|job| is_log_job(*job));
    let pass = (!log_jobs.is_empty()).then_some(Task::LogPass(log_jobs));
    pass.into_iter()
        .chain(others.into_iter().map(Task::Job))
        .collect()
}

/// What a front-end tells [`start`] about where the host is and what it may
/// do there.
pub struct Settings<'a> {
    pub host: &'a crate::hostconf::HostConf,
    /// An SSH log to read in place of the stored one or the search.
    pub ssh_log: Option<&'a std::path::Path>,
    /// Where the applied firewall script is; `None` for the backend's own.
    pub firewall_out: Option<&'a std::path::Path>,
    /// Whether this process may change the host: run the firewall script
    /// when `Db::get_auto_apply_firewall` says to. `false` only under the
    /// TUI's `--no-reload`, which its end-to-end tests use.
    pub for_real: bool,
}

/// Where a task is after [`start`] or [`finish`].
#[derive(Debug)]
pub enum Next {
    /// Finished, and recorded: what each job did.
    Ran(Vec<(CronJob, String)>),
    /// Not started, because another download holds the lease. Nothing is
    /// recorded, so the job is still due and the next check asks again.
    Waiting,
    /// The slow half, to [`Work::run`] and then hand to [`finish`].
    Work(Work),
    /// `ApplyNginx`, with the switch on: apply every site's config in the
    /// front-end's own way (see this module's docs), and record what that
    /// did against the job. `tick` uses [`apply_sites`].
    ApplySites,
}

/// The slow half of a job: reading the logs, downloading a list, probing
/// the host. It holds no database, so it can go to another thread; what
/// [`Work::run`] returns goes to [`finish`], back where the database is.
#[derive(Debug)]
pub struct Work(Slow);

#[derive(Debug)]
enum Slow {
    LogPass {
        jobs: Vec<CronJob>,
        plan: Box<crate::logscan::Plan>,
        firewall_out: Option<std::path::PathBuf>,
        for_real: bool,
        egress: Option<EgressLook>,
    },
    CrawlerRanges {
        lease: crate::refresh::Lease,
    },
    Download {
        run: crate::refresh::Run,
        source: crate::refresh::Source,
    },
    Probe(Box<ProbeInputs>),
    EgressFeeds {
        lease: crate::refresh::Lease,
        feeds: Vec<crate::db::egress::EgressFeed>,
        for_real: bool,
    },
}

/// What the `Egress` job's slow half asks of the host.
#[derive(Debug, Clone)]
struct EgressLook {
    runtime: Option<crate::contain::Runtime>,
    /// Whether to ask the runtime which containers there are: only when a
    /// hit may need it or a container is contained.
    containers: bool,
}

/// A [`Work`] that has run, for [`finish`]. `Clone` because the TUI's
/// events are.
#[derive(Debug, Clone)]
pub struct Done(Finished);

#[derive(Debug, Clone)]
enum Finished {
    LogPass {
        jobs: Vec<CronJob>,
        read: Box<crate::logscan::Read>,
        firewall_out: Option<std::path::PathBuf>,
        for_real: bool,
        egress: Option<Box<EgressInputs>>,
    },
    CrawlerRanges {
        lease: crate::refresh::Lease,
        results: Vec<(
            crate::ipranges::IpRangeSourceKind,
            std::result::Result<Vec<String>, String>,
        )>,
    },
    Download {
        run: crate::refresh::Run,
        source: crate::refresh::Source,
        fetched: std::result::Result<String, String>,
    },
    Probe(Box<crate::health::Probe>),
    EgressFeeds {
        lease: crate::refresh::Lease,
        fetched: Vec<(
            crate::db::egress::EgressFeed,
            std::result::Result<String, String>,
        )>,
        protected: Vec<crate::egress::Protected>,
        for_real: bool,
    },
}

impl Work {
    /// The jobs this is the slow half of: what the TUI shows as running.
    pub fn jobs(&self) -> Vec<CronJob> {
        match &self.0 {
            Slow::LogPass { jobs, .. } => jobs.clone(),
            Slow::CrawlerRanges { .. } => vec![CronJob::UpdateIpRanges],
            Slow::Download { .. } => vec![CronJob::UpdateEverything],
            Slow::Probe(_) => vec![CronJob::HealthCheck],
            Slow::EgressFeeds { .. } => vec![CronJob::UpdateEgressFeeds],
        }
    }

    /// Whether someone asked for this: `u`, rather than the weekly job.
    pub fn by_hand(&self) -> bool {
        matches!(&self.0, Slow::Download { run, .. } if !run.scheduled())
    }

    /// What to tell whoever asked for this while it runs.
    pub fn progress(&self) -> Option<String> {
        match &self.0 {
            Slow::Download { run, source } if !run.scheduled() => {
                Some(format!("Downloading {}\u{2026}", source.label()))
            }
            _ => None,
        }
    }

    /// Does the slow half. Reading a log and probing the host are blocking
    /// work and go to the blocking pool; a download is `async` all the way
    /// down.
    pub async fn run(self) -> Done {
        Done(match self.0 {
            Slow::LogPass {
                jobs,
                plan,
                firewall_out,
                for_real,
                egress,
            } => Finished::LogPass {
                jobs,
                read: Box::new(
                    off_thread(move || crate::logscan::read(&plan, plan.sources())).await,
                ),
                firewall_out,
                for_real,
                egress: match egress {
                    Some(look) => Some(Box::new(
                        off_thread(move || EgressInputs {
                            host: crate::contain::Host::look(
                                look.runtime.as_ref(),
                                look.containers,
                            ),
                            runtime: look.runtime,
                        })
                        .await,
                    )),
                    None => None,
                },
            },
            Slow::CrawlerRanges { lease } => Finished::CrawlerRanges {
                lease,
                results: fetch_ip_ranges().await,
            },
            Slow::Download { run, source } => {
                let fetched = crate::refresh::fetch(&source)
                    .await
                    .map_err(|err| format!("{err:#}"));
                Finished::Download {
                    run,
                    source,
                    fetched,
                }
            }
            Slow::Probe(inputs) => Finished::Probe(Box::new(off_thread(|| inputs.probe()).await)),
            Slow::EgressFeeds {
                lease,
                feeds,
                for_real,
            } => {
                let mut fetched = Vec::new();
                for feed in feeds {
                    let raw = crate::egress::fetch(&feed)
                        .await
                        .map_err(|err| format!("{err:#}"));
                    fetched.push((feed, raw));
                }
                let urls: Vec<String> = fetched
                    .iter()
                    .flat_map(|(feed, _)| crate::egress::feed_urls(feed))
                    .collect();
                // Resolving is the network too.
                let protected = off_thread(move || {
                    crate::egress::protected_destinations(
                        &crate::egress::Surroundings {
                            root: std::path::Path::new("/"),
                            resolve: &crate::egress::system_resolve,
                        },
                        &urls,
                    )
                })
                .await;
                Finished::EgressFeeds {
                    lease,
                    fetched,
                    protected,
                    for_real,
                }
            }
        })
    }
}

impl Done {
    /// The jobs this finished the slow half of.
    pub fn jobs(&self) -> Vec<CronJob> {
        match &self.0 {
            Finished::LogPass { jobs, .. } => jobs.clone(),
            Finished::CrawlerRanges { .. } => vec![CronJob::UpdateIpRanges],
            Finished::Download { .. } => vec![CronJob::UpdateEverything],
            Finished::Probe(_) => vec![CronJob::HealthCheck],
            Finished::EgressFeeds { .. } => vec![CronJob::UpdateEgressFeeds],
        }
    }

    /// See [`Work::by_hand`].
    pub fn by_hand(&self) -> bool {
        matches!(&self.0, Finished::Download { run, .. } if !run.scheduled())
    }

    /// A download that has fetched `source`.
    #[cfg(test)]
    pub(crate) fn downloaded(
        run: crate::refresh::Run,
        source: crate::refresh::Source,
        fetched: std::result::Result<String, String>,
    ) -> Done {
        Done(Finished::Download {
            run,
            source,
            fetched,
        })
    }

    /// The crawler job's fetches, back with `results`.
    #[cfg(test)]
    pub(crate) fn crawler_ranges(
        lease: crate::refresh::Lease,
        results: Vec<(
            crate::ipranges::IpRangeSourceKind,
            std::result::Result<Vec<String>, String>,
        )>,
    ) -> Done {
        Done(Finished::CrawlerRanges { lease, results })
    }
}

/// Runs `work` on the blocking pool. A panic there is a panic here, as it
/// was when this work ran in line.
async fn off_thread<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => value,
        Err(err) => std::panic::resume_unwind(err.into_panic()),
    }
}

/// Starts `task`: every database read it needs, and then either the job
/// itself, when nothing about it is slow, or the [`Work`] that is.
///
/// The one place a job is matched to what it does, for every front-end:
/// a job missing here is a compile error, not a job one of them forgot.
///
/// `Err` only for what stops the task starting at all: the logs could not
/// be planned, the lease could not be read. A job's own failure becomes
/// its recorded summary, as everywhere here.
pub fn start(db: &Db, task: &Task, settings: &Settings) -> Result<Next> {
    let job = match task {
        Task::LogPass(jobs) => return start_log_pass(db, jobs.clone(), settings),
        Task::Job(job) => *job,
    };
    Ok(match job {
        // A log job on its own is a pass of one.
        CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::RenderFirewall => {
            return start_log_pass(db, vec![job], settings)
        }
        CronJob::UpdateIpRanges => match crate::refresh::claim(db, now())? {
            crate::refresh::Claim::Busy { .. } => Next::Waiting,
            crate::refresh::Claim::Granted(lease) => {
                Next::Work(Work(Slow::CrawlerRanges { lease }))
            }
        },
        CronJob::UpdateEverything => match crate::refresh::begin(db, now(), true)? {
            crate::refresh::Begin::Busy { .. } => Next::Waiting,
            crate::refresh::Begin::Started(run) => download(db, run),
        },
        CronJob::HealthCheck => match ProbeInputs::read(db, settings) {
            Ok(inputs) => Next::Work(Work(Slow::Probe(Box::new(inputs)))),
            Err(summary) => ran(db, job, summary),
        },
        // In line in every front-end: it touches nothing but the database,
        // and `Db` isn't `Sync`, so moving it off-thread would mean moving
        // the handle, not just the slow half. A prune is a pair of
        // statements and a compaction only happens on a file already known
        // to be mostly slack.
        CronJob::Maintenance => ran(db, job, maintenance(db)),
        CronJob::ApplyNginx => match auto_apply_is_off(db) {
            Some(summary) => ran(db, job, summary),
            None => Next::ApplySites,
        },
        CronJob::Egress => return start_log_pass(db, vec![job], settings),
        CronJob::UpdateEgressFeeds => {
            let feeds: Vec<_> = db
                .list_egress_feeds()?
                .into_iter()
                .filter(|feed| feed.enabled)
                .collect();
            if feeds.is_empty() {
                return Ok(ran(db, job, "no C&C feed is switched on".to_string()));
            }
            match crate::refresh::claim(db, now())? {
                crate::refresh::Claim::Busy { .. } => Next::Waiting,
                crate::refresh::Claim::Granted(lease) => Next::Work(Work(Slow::EgressFeeds {
                    lease,
                    feeds,
                    for_real: settings.for_real,
                })),
            }
        }
    })
}

fn start_log_pass(db: &Db, jobs: Vec<CronJob>, settings: &Settings) -> Result<Next> {
    let flags = crate::logscan::Flags {
        ssh_log: settings.ssh_log.map(std::path::Path::to_path_buf),
        access_log: None,
        kernel_log: None,
        stored: settings.host.log_paths(),
    };
    let plan = crate::logscan::plan(db, &jobs, &flags)?;
    // Nothing is asked of the host while there is nothing to answer or
    // keep: no `who`, no `docker ps`, once a minute on every host.
    let watching = crate::egress::Mode::get(db)? != crate::egress::Mode::Off;
    let open = db.open_containments()?;
    let egress =
        (jobs.contains(&CronJob::Egress) && (watching || !open.is_empty())).then(|| EgressLook {
            runtime: crate::contain::Runtime::find(settings.host),
            containers: watching
                || open
                    .iter()
                    .any(|c| c.kind == crate::db::egress::ContainmentKind::Container),
        });
    Ok(Next::Work(Work(Slow::LogPass {
        jobs,
        plan: Box::new(plan),
        firewall_out: settings.firewall_out.map(std::path::Path::to_path_buf),
        for_real: settings.for_real,
        egress,
    })))
}

/// Records `summary` against `job`, which has just run.
fn ran(db: &Db, job: CronJob, summary: String) -> Next {
    record_run(db, job, &summary);
    Next::Ran(vec![(job, summary)])
}

/// Carries `run` on: the next source to fetch, or, with none left, the
/// run's end. The weekly job goes through here, and so does `u` in the
/// TUI, with a run it began itself.
pub fn download(db: &Db, mut run: crate::refresh::Run) -> Next {
    match run.next_source() {
        Some(source) => Next::Work(Work(Slow::Download { run, source })),
        // `end` keeps the job's books itself.
        None => Next::Ran(vec![(CronJob::UpdateEverything, run.end(db))]),
    }
}

/// Stores what `done` found and decides each job on it: the database half
/// after the slow one. Hands back more [`Work`] while there is more to do,
/// which is the next list of a download.
pub fn finish(db: &Db, done: Done) -> Result<Next> {
    Ok(match done.0 {
        Finished::LogPass {
            jobs,
            read,
            firewall_out,
            for_real,
            egress,
        } => {
            let applied = crate::logscan::apply(db, *read)?;
            Next::Ran(run_log_jobs(
                db,
                &jobs,
                &applied,
                firewall_out.as_deref(),
                for_real,
                egress.as_deref(),
            )?)
        }
        Finished::EgressFeeds {
            lease,
            fetched,
            protected,
            for_real,
        } => {
            let (mut summary, _) = crate::egress::store_fetched(db, &protected, fetched);
            match crate::sinkhole::apply(db, std::path::Path::new("/"), for_real) {
                Ok(Some(written)) if for_real => {
                    summary.push_str(&format!("; {}", written.summary()))
                }
                Ok(_) => {}
                Err(err) => summary.push_str(&format!("; sinkhole: {err:#}")),
            }
            crate::refresh::release(db, &lease)?;
            ran(db, CronJob::UpdateEgressFeeds, summary)
        }
        Finished::CrawlerRanges { lease, results } => {
            let stored = store_ip_ranges(db, results);
            crate::refresh::release(db, &lease)?;
            // `store_ip_ranges` keeps the job's books itself.
            Next::Ran(vec![(CronJob::UpdateIpRanges, stored?)])
        }
        Finished::Download {
            mut run,
            source,
            fetched,
        } => {
            run.stored(db, source, fetched, now())?;
            download(db, run)
        }
        Finished::Probe(probe) => {
            let summary = store_health(db, &probe);
            ran(db, CronJob::HealthCheck, summary)
        }
    })
}

/// What [`tick`] needs from its caller: where the host is and what it may
/// do there.
pub struct TickSettings<'a> {
    pub host: &'a crate::hostconf::HostConf,
    /// The web server's config root, from the host settings.
    pub root: &'a std::path::Path,
    /// An SSH log to read in place of the stored one or the search.
    pub ssh_log: Option<std::path::PathBuf>,
    /// Where the applied firewall script is; `None` for the backend's own.
    pub firewall_out: Option<&'a std::path::Path>,
}

/// Runs every job that is due, once, and returns each one's summary: one
/// tick of the schedule, for `stop-bots tick` under `/etc/cron.d`, which
/// is what keeps a host protected with no front-end open.
///
/// Each task through [`start`], [`Work::run`] and [`finish`], in line: the
/// log jobs in one pass that reads each log once, then the rest one at a
/// time. A job only does what its switches allow, exactly as under the
/// TUI — auto-apply for the web server and the firewall stays off until
/// the operator turns it on. A job's failure becomes its recorded summary;
/// only a schedule that cannot be read at all is an error.
pub async fn tick(db: &Db, settings: &TickSettings<'_>) -> Result<Vec<(CronJob, String)>> {
    // The list built into this binary, as the TUI stores it when it starts:
    // after an upgrade, what the new binary added is what the next apply
    // and every staleness check have to see.
    crate::botlist::register_all_sources(db)?;
    let shared = Settings {
        host: settings.host,
        ssh_log: settings.ssh_log.as_deref(),
        firewall_out: settings.firewall_out,
        // Unlike the TUI, `tick` has no `--no-reload`: the switches alone
        // decide what it changes.
        for_real: true,
    };
    let mut ran = Vec::new();
    for task in tasks(due_jobs(db)?) {
        let mut next = start(db, &task, &shared)?;
        while let Next::Work(work) = next {
            next = finish(db, work.run().await)?;
        }
        match next {
            Next::Ran(summaries) => ran.extend(summaries),
            Next::Waiting => {}
            Next::ApplySites => {
                let summary = apply_sites(db, settings.host, settings.root, true);
                record_run(db, CronJob::ApplyNginx, &summary);
                ran.push((CronJob::ApplyNginx, summary));
            }
            Next::Work(_) => unreachable!("the loop above runs every piece of work"),
        }
    }
    Ok(ran)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    /// What a front-end tells `start`, with every log in `dir`: nothing
    /// here reads the host's own.
    fn with_settings<T>(dir: &std::path::Path, then: impl FnOnce(&Settings) -> T) -> T {
        let host = crate::hostconf::HostConf {
            access_log: Some(dir.join("access.log")),
            ..Default::default()
        };
        let ssh = dir.join("auth.log");
        let firewall_out = dir.join("fw.nft");
        then(&Settings {
            host: &host,
            ssh_log: Some(&ssh),
            firewall_out: Some(&firewall_out),
            for_real: false,
        })
    }

    /// The property the one dispatch exists for: every job, including any
    /// added after this was written, is started by `start` — which `tick`
    /// and the TUI both drive — and comes back as having run, recorded, or
    /// as the slow half of that same job. Nothing slow is run here: no
    /// download, no probe of the host.
    #[test]
    fn every_job_is_started_by_the_one_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        with_settings(dir.path(), |settings| {
            for job in CronJob::all() {
                let db = test_db();
                match start(&db, &Task::Job(job), settings).unwrap() {
                    Next::Work(work) => {
                        assert_eq!(work.jobs(), [job], "{}: someone else's work", job.id())
                    }
                    Next::Ran(ran) => {
                        assert_eq!(ran.len(), 1, "{}: ran {ran:?}", job.id());
                        assert_eq!(ran[0].0, job, "{}: ran {ran:?}", job.id());
                        assert_eq!(
                            db.get_cron_last_summary(job.id()).unwrap().as_ref(),
                            Some(&ran[0].1),
                            "{}: ran but did not record it",
                            job.id()
                        );
                    }
                    other => panic!("{}: {other:?} on a fresh database", job.id()),
                }
            }
        });
    }

    /// The jobs that read a log share one read of it, ahead of the rest,
    /// and every other job starts on its own.
    #[test]
    fn the_due_log_jobs_start_as_one_pass_ahead_of_the_rest() {
        let due = CronJob::all();
        let (log_jobs, others): (Vec<CronJob>, Vec<CronJob>) =
            due.iter().partition(|job| is_log_job(**job));

        let tasks = tasks(due);

        assert_eq!(tasks[0], Task::LogPass(log_jobs), "{tasks:?}");
        assert_eq!(
            tasks[1..],
            others.into_iter().map(Task::Job).collect::<Vec<_>>(),
            "{tasks:?}"
        );
    }

    /// A scheduled download while another holds the lease starts nothing
    /// and records nothing, so it is still due when the next check comes.
    #[test]
    fn a_download_waits_while_another_holds_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let db = test_db();
        crate::refresh::claim(&db, now()).unwrap();

        with_settings(dir.path(), |settings| {
            for job in [CronJob::UpdateIpRanges, CronJob::UpdateEverything] {
                let next = start(&db, &Task::Job(job), settings).unwrap();
                assert!(matches!(next, Next::Waiting), "{}: {next:?}", job.id());
                assert_eq!(
                    db.get_cron_last_run(job.id()).unwrap(),
                    None,
                    "{} was recorded, so the next check would not retry it",
                    job.id()
                );
            }
        });
    }

    /// The switch is read before anything else, for both front-ends:
    /// off, `ApplyNginx` records why it did nothing; on, it goes on to
    /// the sites, and records nothing until that apply has said how it
    /// went.
    #[test]
    fn the_auto_apply_switch_decides_whether_apply_nginx_reaches_the_sites() {
        let dir = tempfile::tempdir().unwrap();
        let db = test_db();
        let job = Task::Job(CronJob::ApplyNginx);

        with_settings(dir.path(), |settings| {
            let off = start(&db, &job, settings).unwrap();
            assert!(
                matches!(&off, Next::Ran(ran) if ran[0].1 == "auto-apply is off"),
                "{off:?}"
            );

            db.set_auto_apply(true).unwrap();
            db.set_cron_last_run(CronJob::ApplyNginx.id(), 0, "before")
                .unwrap();
            let on = start(&db, &job, settings).unwrap();
            assert!(matches!(on, Next::ApplySites), "{on:?}");
            assert_eq!(
                db.get_cron_last_summary(CronJob::ApplyNginx.id())
                    .unwrap()
                    .as_deref(),
                Some("before"),
                "ApplyNginx was recorded before its apply had run"
            );
        });
    }

    /// Weekly, pushed back by a jitter that stays inside its bound and
    /// moves with the last run — so hosts that ran at the same moment once
    /// do not keep asking the same feeds at the same moment every week.
    /// One tick runs the due detectors against the logs and blocks what
    /// they find; the next, a moment later, finds nothing due. The jobs that
    /// fetch or probe the host are marked just run, so nothing leaves this
    /// machine.
    #[tokio::test]
    async fn a_tick_runs_what_is_due_and_then_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access.log");
        let now = crate::testing::nginx_time(super::now());
        std::fs::write(
            &access,
            format!("203.0.113.50 - - [{now}] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n"),
        )
        .unwrap();
        let ssh = dir.path().join("auth.log");
        std::fs::write(&ssh, "").unwrap();
        let db = test_db();
        for job in [
            CronJob::UpdateIpRanges,
            CronJob::UpdateEverything,
            CronJob::HealthCheck,
            CronJob::ApplyNginx,
        ] {
            db.set_cron_last_run(job.id(), super::now(), "skipped for test")
                .unwrap();
        }
        let host = crate::hostconf::HostConf {
            access_log: Some(access),
            ..Default::default()
        };
        let firewall_out = dir.path().join("fw.nft");
        let settings = TickSettings {
            host: &host,
            root: dir.path(),
            ssh_log: Some(ssh),
            firewall_out: Some(&firewall_out),
        };

        let ran = tick(&db, &settings).await.unwrap();

        assert!(
            ran.iter()
                .any(|(job, _)| *job == CronJob::Detect(crate::protection::Detector::ProbePaths)),
            "the probe-path detector did not run: {ran:?}"
        );
        let rules = db.list_firewall_rules().unwrap();
        assert!(
            rules.iter().any(|rule| rule.address == "203.0.113.50"),
            "the prober was not blocked: {rules:?}"
        );
        let again = tick(&db, &settings).await.unwrap();
        assert!(again.is_empty(), "ran again with nothing due: {again:?}");
    }

    #[test]
    fn the_weekly_download_is_due_a_week_and_some_jitter_after_it_ran() {
        let week = 7 * 24 * 60 * 60;
        let mut seen = std::collections::HashSet::new();
        for last_run in (0..50).map(|i| 1_790_000_000 + i * 3_607) {
            let after = CronJob::UpdateEverything.due_after(last_run).as_secs();
            assert!(
                (week..week + UPDATE_JITTER.as_secs()).contains(&after),
                "{after}s after {last_run}"
            );
            seen.insert(after);
        }
        assert!(seen.len() > 40, "the jitter barely moves: {seen:?}");
        assert_eq!(
            CronJob::UpdateIpRanges.due_after(1_790_000_000),
            CronJob::UpdateIpRanges.interval(),
            "no other job is jittered"
        );
    }

    /// The Dashboard's projected next run and the due check read the same
    /// jitter, so "next run" is never a time at which nothing happens.
    #[test]
    fn the_weekly_download_is_due_exactly_when_its_next_run_says() {
        let db = test_db();
        let job = CronJob::UpdateEverything;

        let ran = now() - 6 * 24 * 60 * 60;
        db.set_cron_last_run(job.id(), ran, "").unwrap();
        assert!(!is_due(&db, job).unwrap(), "six days on");
        assert!(next_run_at(&db, job).unwrap().unwrap() > now());

        let ran = now() - 7 * 24 * 60 * 60 - UPDATE_JITTER.as_secs() as i64;
        db.set_cron_last_run(job.id(), ran, "").unwrap();
        assert!(is_due(&db, job).unwrap(), "a week and the whole jitter on");
        assert!(next_run_at(&db, job).unwrap().unwrap() <= now());
    }

    /// The weekly download fetches the crawler ranges too, so the two are
    /// never started in the same tick.
    #[test]
    fn the_crawler_job_is_not_run_beside_the_weekly_download() {
        let db = test_db();
        let week_ago = now() - 8 * 24 * 60 * 60;
        for job in [CronJob::UpdateEverything, CronJob::UpdateIpRanges] {
            db.set_cron_last_run(job.id(), week_ago, "").unwrap();
        }

        let due = due_jobs(&db).unwrap();
        assert!(due.contains(&CronJob::UpdateEverything));
        assert!(!due.contains(&CronJob::UpdateIpRanges), "{due:?}");

        db.set_cron_last_run(CronJob::UpdateEverything.id(), now(), "")
            .unwrap();
        assert!(due_jobs(&db).unwrap().contains(&CronJob::UpdateIpRanges));
    }

    /// The safety property the whole switch rests on: off means *nothing
    /// happens*, not "happens and is discarded".
    ///
    /// The root here does not exist, so `discover_sites` would bail the
    /// moment anything walked it and the summary would start with
    /// "error:". Getting the plain off message back is proof the toggle
    /// was read first — which is what keeps an hourly job on a host that
    /// never asked for it from walking the config tree twenty-four times
    /// a day.
    #[test]
    fn apply_nginx_does_nothing_at_all_when_the_switch_is_off() {
        let db = test_db();
        assert!(!db.get_auto_apply().unwrap(), "off is the default");

        let summary = apply_nginx(
            &db,
            &crate::hostconf::HostConf::default(),
            std::path::Path::new("/nonexistent/nginx"),
            false,
        );

        assert_eq!(summary, "auto-apply is off");
    }

    /// The refusal this switch exists to make: with auto-apply on but no
    /// SSH log, the script is still written and is deliberately *not*
    /// run. The interactive paths treat "the check could not run" as a
    /// pass; unattended that is how a host is lost, so this refuses and
    /// says which condition stopped it.
    #[test]
    fn the_firewall_is_not_applied_when_the_lockout_check_could_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("rules.nft");
        let db = test_db();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        db.set_auto_apply_firewall(true).unwrap();

        // `None` is what a pass hands over when no SSH log could be read
        // -- a file that is not there, or a `journalctl` with nothing in
        // it.
        let summary = render_firewall(&db, Some(&out), None, true);

        assert!(
            crate::firewall::rendered_path(&out).exists(),
            "the script should still be written"
        );
        assert!(
            !out.exists(),
            "and not put where the boot unit would load it"
        );
        assert!(
            summary.contains("not applied"),
            "it should refuse, not apply: {summary}"
        );
        assert!(
            summary.contains("lockout check"),
            "it should say which check stopped it: {summary}"
        );
    }

    /// And with the switch off, a readable log changes nothing: writing
    /// without applying stays the default — to the rendered script, which
    /// nothing loads, never to the applied one the boot unit does.
    #[test]
    fn the_firewall_is_only_written_while_auto_apply_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("rules.nft");
        let db = test_db();
        assert!(!db.get_auto_apply_firewall().unwrap(), "off is the default");

        let summary = render_firewall(&db, Some(&out), Some(&[]), true);

        assert!(crate::firewall::rendered_path(&out).exists());
        assert!(!out.exists(), "an unapplied render reached the boot script");
        assert!(summary.starts_with("wrote "), "{summary}");
        assert!(summary.contains("not applied"), "{summary}");
    }

    /// `--no-apply` outranks the switch, the same way it outranks every
    /// other apply in this project.
    #[test]
    fn the_firewall_is_not_applied_under_no_apply_even_with_the_switch_on() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("rules.nft");
        let db = test_db();
        db.set_auto_apply_firewall(true).unwrap();

        // An empty log reads as "no connected clients", so the guard runs
        // and finds nothing — the one case that would otherwise apply.
        let summary = render_firewall(&db, Some(&out), Some(&[]), false);

        assert!(summary.contains("not applied: --no-apply"), "{summary}");
    }

    /// The switched-*on* path is covered in `tests/cli.rs`, not here.
    /// Exercising it means calling `apply_all_sites`, which resolves the
    /// managed directory from `STOP_BOTS_NGINX_DIR` and would delete
    /// `/etc/stop-bots/nginx/robots.txt` on a machine that has one — so a
    /// test has to point that variable somewhere safe. The variable is
    /// process-global, this binary runs its tests in threads under plain
    /// `cargo test`, and `nginx::tests::kitchen_sink_block_matches_the_golden`
    /// asserts against a golden holding the *default* path. Setting it
    /// anywhere in this binary breaks that golden, which is exactly how
    /// this was found.
    ///
    /// A job missing from `all()` is one the internal cron never runs and
    /// the dashboards never list.
    #[test]
    fn apply_nginx_is_a_scheduled_job() {
        assert!(CronJob::all().contains(&CronJob::ApplyNginx));
        assert!(!uses_ssh_log(CronJob::ApplyNginx));
        assert_eq!(CronJob::ApplyNginx.id(), "apply_nginx");
        // Hourly, not per-minute: every block a detector adds changes the
        // generated config, and a minute-interval job would reload a live
        // NGINX every time one bot arrived.
        assert_eq!(CronJob::ApplyNginx.interval().as_secs(), 60 * 60);
    }

    /// A rule added a minute ago must not wait for tomorrow's clock. This
    /// is the whole point of the change trigger: on a real host fifteen
    /// detected blocks sat undetectably-to-nftables for twenty-one hours,
    /// because the only thing that could render them ran daily.
    #[test]
    fn a_changed_rule_set_makes_the_render_due_before_its_interval() {
        let db = test_db();
        // Rendered ten minutes ago: far inside the 24h interval, and past
        // the five-minute floor.
        db.set_cron_last_run(CronJob::RenderFirewall.id(), now() - 600, "rendered")
            .unwrap();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(
            &crate::firewall::all_rules(&db).unwrap(),
        ))
        .unwrap();
        assert!(
            !is_due(&db, CronJob::RenderFirewall).unwrap(),
            "nothing changed, so nothing is due"
        );

        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        assert!(
            is_due(&db, CronJob::RenderFirewall).unwrap(),
            "a new block should make the render due"
        );
    }

    /// The floor, which is what stops a render that cannot write turning
    /// into a once-a-minute retry forever: a failed render leaves the
    /// rules still unrendered and so still "changed", and without this it
    /// would be due again on the very next tick.
    #[test]
    fn a_change_does_not_make_the_render_due_again_within_five_minutes() {
        let db = test_db();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        // Ran one minute ago and left no signature — exactly what a render
        // that failed to write its file looks like.
        db.set_cron_last_run(CronJob::RenderFirewall.id(), now() - 60, "error: denied")
            .unwrap();

        assert!(
            !is_due(&db, CronJob::RenderFirewall).unwrap(),
            "a failing render must back off, not spin"
        );
    }

    /// A refused write backs off the same way: the guard that refused it
    /// will refuse again a minute later.
    #[test]
    fn a_refused_render_backs_off_too() {
        let db = test_db();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        db.set_cron_last_run(
            CronJob::RenderFirewall.id(),
            now() - 60,
            "skipped: the SSH log could not be read",
        )
        .unwrap();

        assert!(!is_due(&db, CronJob::RenderFirewall).unwrap());
    }

    /// After a render that worked, a block found a minute later is
    /// rendered on the next tick rather than four minutes on: the floor is
    /// for retrying failures, not for a burst that is still arriving.
    #[test]
    fn a_change_a_minute_after_a_render_that_worked_is_due_at_once() {
        let db = test_db();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(
            &crate::firewall::all_rules(&db).unwrap(),
        ))
        .unwrap();
        db.set_cron_last_run(CronJob::RenderFirewall.id(), now() - 60, "rendered")
            .unwrap();
        assert!(
            !is_due(&db, CronJob::RenderFirewall).unwrap(),
            "nothing changed, so nothing is due"
        );

        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        assert!(
            is_due(&db, CronJob::RenderFirewall).unwrap(),
            "a block found a minute after a good render waited out the floor"
        );
    }

    /// The interval stays the ceiling. A rule that lapsed since the last
    /// render changes no signature — it just stops being returned — so
    /// without the clock a host whose rules only ever *expire* would never
    /// re-render.
    #[test]
    fn the_daily_interval_still_makes_the_render_due_with_nothing_changed() {
        let db = test_db();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(
            &crate::firewall::all_rules(&db).unwrap(),
        ))
        .unwrap();
        db.set_cron_last_run(
            CronJob::RenderFirewall.id(),
            now() - 25 * 60 * 60,
            "rendered",
        )
        .unwrap();

        assert!(is_due(&db, CronJob::RenderFirewall).unwrap());
    }

    /// The trigger belongs to one job. Asking every job would mean walking
    /// all 44,000 rules once a minute per job, for jobs that render
    /// nothing.
    #[test]
    fn no_other_job_is_made_due_by_a_changed_rule_set() {
        let db = test_db();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.7".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        for job in CronJob::all() {
            if job == CronJob::RenderFirewall {
                continue;
            }
            // Just ran, so nothing but a change trigger could make it
            // due — the detectors' own interval is sixty seconds, so an
            // older timestamp would make them due on the clock alone and
            // prove nothing.
            db.set_cron_last_run(job.id(), now(), "ran").unwrap();
            assert!(
                !is_due(&db, job).unwrap(),
                "{} became due because the firewall rules changed",
                job.id()
            );
        }
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
                detector.spec().log == crate::protection::DetectorLog::Ssh,
                "{} disagreed with its own spec",
                detector.id()
            );
        }
    }

    /// A log pass over `jobs`, with both logs pointed at files in `dir`.
    fn pass(db: &Db, dir: &std::path::Path, jobs: &[CronJob]) -> Vec<(CronJob, String)> {
        let flags = crate::logscan::Flags {
            ssh_log: Some(dir.join("auth.log")),
            access_log: Some(dir.join("access.log")),
            ..Default::default()
        };
        let applied = crate::logscan::run(db, jobs, &flags).unwrap();
        run_log_jobs(db, jobs, &applied, Some(&dir.join("fw.nft")), false, None).unwrap()
    }

    /// Recording happens on every pass that reads the SSH log, not in one
    /// designated place -- that is what keeps the window fed minute by
    /// minute, and what makes an address survive the rotation that drops
    /// the log line proving the login.
    #[test]
    fn an_ssh_log_pass_records_the_addresses_it_saw_logins_from() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("auth.log"),
            "Accepted publickey for m from 203.0.113.5 port 55000 ssh2\n",
        )
        .unwrap();

        pass(&db, dir.path(), &[CronJob::Detect(Detector::SshScanners)]);

        assert_eq!(db.recent_ssh_login_ips().unwrap(), vec!["203.0.113.5"]);
    }

    /// A pass that reads only the *access* log must not touch this table:
    /// its text has nothing to do with SSH, and parsing it as if it did
    /// would be how a stray "Accepted " in a request path becomes an
    /// allowlist entry.
    #[test]
    fn an_access_log_pass_records_no_ssh_logins() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("access.log"),
            "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \
             \"GET /Accepted%20for%20x%20from%20y HTTP/1.1\" 200 1 \"-\" \"UA\"\n",
        )
        .unwrap();

        pass(&db, dir.path(), &[CronJob::RecordAccessStats]);

        assert!(db.recent_ssh_login_ips().unwrap().is_empty());
    }

    /// The summary is the whole point of the job: it is what the
    /// Dashboard shows, and "nothing recorded" reads as permanently
    /// overdue. So both the disabled case and the no-log case must still
    /// write one.
    #[test]
    fn a_job_that_could_not_do_anything_still_records_why() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let detector = Detector::SshScanners;
        let summary_of = |db: &Db, job: CronJob| pass(db, dir.path(), &[job])[0].1.clone();

        detector.set_enabled(&db, false).unwrap();
        assert_eq!(summary_of(&db, CronJob::Detect(detector)), "disabled");

        detector.set_enabled(&db, true).unwrap();
        assert_eq!(
            summary_of(&db, CronJob::Detect(detector)),
            "SSH log unavailable"
        );
        assert_eq!(
            summary_of(&db, CronJob::RecordAccessStats),
            "access log unavailable"
        );

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

    /// The guard of a scheduled render is fed by the pass that read the
    /// SSH log: a client that logged in is never cut off, whatever rule
    /// covers it.
    #[test]
    fn a_scheduled_render_refuses_to_cut_off_a_client_it_saw_log_in() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("auth.log"), "").unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "203.0.113.0/24".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        // Readable and empty: the guard runs and passes.
        let summaries = pass(&db, dir.path(), &[CronJob::RenderFirewall]);
        assert!(summaries[0].1.starts_with("wrote "), "{summaries:?}");

        // A login from inside the block, since the last pass: recorded,
        // and so allowed ahead of the block rather than refused.
        std::fs::write(
            dir.path().join("auth.log"),
            "Accepted publickey for m from 203.0.113.5 port 1 ssh2\n",
        )
        .unwrap();
        let summaries = pass(&db, dir.path(), &[CronJob::RenderFirewall]);
        assert!(summaries[0].1.starts_with("wrote "), "{summaries:?}");
        assert_eq!(db.recent_ssh_login_ips().unwrap(), ["203.0.113.5"]);
    }

    /// The whole loop end to end, through real files: a probe is blocked,
    /// the block lapses, the next minute's pass reads the same log and
    /// blocks nothing, and a new probe is blocked again.
    #[test]
    fn a_lapsed_block_is_re_added_only_when_the_offence_is_repeated() {
        use crate::testing::{nginx_time, now_secs};
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        let probe = |at: i64| {
            format!(
                "203.0.113.5 - - [{}] \"GET /.env HTTP/1.1\" 404 1 \"-\" \"curl/8\"\n",
                nginx_time(at)
            )
        };
        std::fs::write(&log, probe(now_secs() - 60)).unwrap();
        let job = [CronJob::Detect(Detector::ProbePaths)];

        assert_eq!(pass(&db, dir.path(), &job)[0].1, "blocked 1 IP(s)");

        // The block lapses: pruned, as `list_firewall_rules` does once its
        // time is up.
        let id = db.list_firewall_rules().unwrap()[0].id;
        db.let_firewall_rule_lapse(id);
        assert_eq!(
            pass(&db, dir.path(), &job)[0].1,
            "no probing IPs found",
            "the old line brought it back"
        );

        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut file, probe(now_secs()).as_bytes()).unwrap();
        assert_eq!(
            pass(&db, dir.path(), &job)[0].1,
            "blocked 1 IP(s), 1 for longer as repeat offender(s)"
        );
    }

    /// The scheduled pass judges `/wp-login.php` by the site the line
    /// names, where the format logs `$host`: a probe on the static site,
    /// the administrator's own login on the WordPress one.
    #[test]
    fn the_scheduled_pass_judges_the_wordpress_login_by_the_site_it_was_for() {
        use crate::testing::{nginx_time, now_secs, site_serving};
        let db = test_db();
        let _static = site_serving(&db, "static.example", &["index.html"]);
        let _blog = site_serving(&db, "blog.example", &["wp-login.php"]);
        let dir = tempfile::tempdir().unwrap();
        let login = |ip: &str, site: &str| {
            format!(
                "{ip} - - [{}] \"GET /wp-login.php HTTP/1.1\" 200 1 \"-\" \"curl/8\" \"{site}\"\n",
                nginx_time(now_secs() - 60)
            )
        };
        std::fs::write(
            dir.path().join("access.log"),
            login("203.0.113.5", "static.example") + &login("198.51.100.7", "blog.example"),
        )
        .unwrap();

        pass(&db, dir.path(), &[CronJob::Detect(Detector::ProbePaths)]);

        let blocked: Vec<String> = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .map(|rule| rule.address)
            .collect();
        assert_eq!(blocked, ["203.0.113.5"]);
    }

    #[test]
    fn render_firewall_writes_the_script_and_reports_success() {
        let db = test_db();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("fw.nft");

        let summary = render_firewall(&db, Some(&out_path), None, false);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(crate::firewall::rendered_path(&out_path).exists());
    }

    /// An unprivileged TUI hits this once a day, forever, so
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

        let summary = render_firewall(&db, Some(&out_path), None, false);

        assert!(summary.starts_with("error: "), "summary was: {summary}");
        assert!(
            summary.contains(
                &crate::firewall::rendered_path(&out_path)
                    .display()
                    .to_string()
            ),
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

        let summary = render_firewall(&db, Some(&out_path), None, false);

        assert!(summary.contains("wrote"), "summary was: {summary}");
        assert!(crate::firewall::rendered_path(&out_path).exists());
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

    /// A fresh database has downloaded nothing, and its first download is
    /// the operator's to start, not the cron's first tick.
    #[test]
    fn due_jobs_on_a_fresh_database_includes_every_job_but_the_downloads() {
        let db = Db::open_in_memory().unwrap();
        let due = due_jobs(&db).unwrap();
        assert_eq!(due.len(), CronJob::all().len() - 2, "{due:?}");
        assert!(!due.contains(&CronJob::UpdateEverything), "{due:?}");
        assert!(!due.contains(&CronJob::UpdateIpRanges), "{due:?}");
        assert_eq!(next_run_at(&db, CronJob::UpdateIpRanges).unwrap(), None);
    }

    /// Before its first run the daily crawler-range job counts from the
    /// oldest list this host fetched, the crawler ranges included.
    #[test]
    fn the_crawler_job_first_counts_from_the_oldest_fetched_list() {
        let fetched = |ago: i64| {
            let db = test_db();
            db.register_ip_range_source(&crate::db::IpRangeSource {
                id: "googlebot".to_string(),
                name: "Googlebot IP ranges".to_string(),
                url: "https://example.invalid/googlebot.json".to_string(),
                category: crate::db::Category::Search,
                last_fetched_at: Some(now() - ago),
                range_count: 1,
            })
            .unwrap();
            is_due(&db, CronJob::UpdateIpRanges).unwrap()
        };

        assert!(!fetched(60), "fetched a minute ago");
        assert!(fetched(2 * 24 * 60 * 60), "fetched two days ago");
    }

    /// Before its first run the weekly download counts from the oldest
    /// list this host fetched: a fresh database, which has fetched nothing,
    /// leaves the first download to the operator; an upgraded one whose
    /// lists are a month old is due at once.
    #[test]
    fn the_weekly_download_first_counts_from_the_oldest_fetched_list() {
        let db = test_db();
        crate::botlist::register_all_sources(&db).unwrap();
        assert!(!is_due(&db, CronJob::UpdateEverything).unwrap(), "fresh");
        assert_eq!(next_run_at(&db, CronJob::UpdateEverything).unwrap(), None);

        let mut source = db
            .list_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == crate::botlist::SourceKind::WellKnownBots.id())
            .unwrap();
        source.last_fetched_at = Some(now() - 2 * 24 * 60 * 60);
        db.upsert_source(&source).unwrap();
        assert!(
            !is_due(&db, CronJob::UpdateEverything).unwrap(),
            "two days old"
        );

        source.last_fetched_at = Some(now() - 30 * 24 * 60 * 60);
        db.upsert_source(&source).unwrap();
        assert!(
            is_due(&db, CronJob::UpdateEverything).unwrap(),
            "a month old"
        );
    }

    #[test]
    fn due_jobs_excludes_a_job_that_just_ran() {
        let db = Db::open_in_memory().unwrap();
        let before = due_jobs(&db).unwrap().len();
        db.set_cron_last_run(CronJob::Maintenance.id(), now(), "ran")
            .unwrap();
        let due = due_jobs(&db).unwrap();
        assert!(!due.contains(&CronJob::Maintenance));
        assert_eq!(due.len(), before - 1);
    }

    #[test]
    fn status_reports_every_job_with_its_persisted_state() {
        let db = Db::open_in_memory().unwrap();
        // One reading of the clock: two could fall either side of a second.
        let at = now();
        db.set_cron_last_run(
            CronJob::Detect(Detector::SshScanners).id(),
            at,
            "blocked 2 IP(s)",
        )
        .unwrap();

        let statuses = status(&db).unwrap();
        assert_eq!(statuses.len(), CronJob::all().len());

        let ssh = statuses
            .iter()
            .find(|s| s.job == CronJob::Detect(Detector::SshScanners))
            .unwrap();
        assert_eq!(ssh.last_run, Some(at));
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
