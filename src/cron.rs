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
//! to keep scan detection and crawler-range data fresh, by having the TUI
//! itself (the only long-running process this project has) periodically
//! check which background jobs are due and run them — see `App`'s event
//! loop in `crate::app` for where these actually get invoked, and the
//! Dashboard's "Scheduled tasks" panel for where their state is shown.
//!
//! **This only automates while the TUI is open.** Unlike a real cron
//! entry, nothing here runs when the process isn't running — closing the
//! TUI pauses every job until it's reopened. A job that's overdue when the
//! TUI (re)starts just runs as soon as it's next checked, the same
//! never-run-yet-so-do-it-now convention `ipranges` sources already use
//! for staleness, rather than trying to "catch up" on however many
//! intervals were missed.
//!
//! **Each job only does what its equivalent CLI subcommand does — nothing
//! here applies a firewall script.** `RenderFirewall` writes the script to
//! disk on a timer, same as `render-firewall`; actually applying it
//! (`sh`/`nft -f`) remains a manual step for the admin, on purpose (see
//! `src/iptables.rs`/`src/nftables.rs`'s "generate-only" module docs) — an
//! internal cron that silently executed firewall changes would be a very
//! different, much riskier feature than this one.

use crate::db::Db;
use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// One of the background jobs the internal cron schedules. Each variant
/// name matches (mod case) the CLI subcommand or lib function it wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CronJob {
    /// Refetches Googlebot/Bingbot/GPTBot's published CIDR ranges — see
    /// `ipranges::update`. Keeps `block_web_scanners`'s known-crawler
    /// exclusion from silently going stale (documented as a manual
    /// "automate both together" caveat before this feature existed).
    UpdateIpRanges,
    /// Runs `scanblock::block_ssh_scanners` against the auto-detected SSH
    /// log.
    BlockScanners,
    /// Runs `scanblock::block_web_scanners` against the auto-detected
    /// NGINX access log.
    BlockWebScanners,
    /// Renders the current firewall rules to the same default path the
    /// Dashboard's `f`-key popup defaults to, using the nftables backend
    /// (handles allowlist geo mode; iptables doesn't — see
    /// `firewall::build_script`). Does not apply it.
    RenderFirewall,
}

impl CronJob {
    pub const ALL: [CronJob; 4] = [
        CronJob::UpdateIpRanges,
        CronJob::BlockScanners,
        CronJob::BlockWebScanners,
        CronJob::RenderFirewall,
    ];

    /// The key this job's state is stored under in `Db`'s cron methods —
    /// stable across releases (used as a `settings` table key), so never
    /// rename an existing variant's id without a migration thought.
    pub fn id(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "update_ip_ranges",
            CronJob::BlockScanners => "block_scanners",
            CronJob::BlockWebScanners => "block_web_scanners",
            CronJob::RenderFirewall => "render_firewall",
        }
    }

    /// A short label for the Dashboard's job list.
    pub fn label(self) -> &'static str {
        match self {
            CronJob::UpdateIpRanges => "Update crawler IP ranges",
            CronJob::BlockScanners => "Block SSH scanners",
            CronJob::BlockWebScanners => "Block web scanners",
            CronJob::RenderFirewall => "Render firewall script",
        }
    }

    /// How often this job should run. Chosen per-job rather than one
    /// blanket interval:
    /// - `UpdateIpRanges`: daily — crawler ranges change slowly; this only
    ///   needs to stay roughly current.
    /// - `BlockScanners`: every 4 hours — SSH brute-forcing tends to be an
    ///   ongoing campaign, not a single burst, so there's less urgency
    ///   than the web case.
    /// - `BlockWebScanners`: hourly — a URL-enumeration scan is typically
    ///   a single short automated pass (minutes), so catching it sooner
    ///   matters more, and its Block rules already expire in a day anyway.
    /// - `RenderFirewall`: daily — just needs to stay reasonably in sync
    ///   with whatever's accumulated in `firewall_rules` since the last
    ///   render; nothing about it is time-sensitive the way detection is.
    pub fn interval(self) -> Duration {
        match self {
            CronJob::UpdateIpRanges => Duration::from_secs(24 * 60 * 60),
            CronJob::BlockScanners => Duration::from_secs(4 * 60 * 60),
            CronJob::BlockWebScanners => Duration::from_secs(60 * 60),
            CronJob::RenderFirewall => Duration::from_secs(24 * 60 * 60),
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

/// Every job that's currently due, in [`CronJob::ALL`] order.
pub fn due_jobs(db: &Db) -> Result<Vec<CronJob>> {
    CronJob::ALL
        .into_iter()
        .filter_map(|job| match is_due(db, job) {
            Ok(true) => Some(Ok(job)),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

/// Every job's current state, for display — always all four, in
/// [`CronJob::ALL`] order, regardless of due-ness.
pub fn status(db: &Db) -> Result<Vec<JobStatus>> {
    CronJob::ALL
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_that_has_never_run_is_due() {
        let db = Db::open_in_memory().unwrap();
        assert!(is_due(&db, CronJob::BlockScanners).unwrap());
    }

    #[test]
    fn a_job_run_just_now_is_not_due() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(CronJob::BlockScanners.id(), now(), "ran")
            .unwrap();
        assert!(!is_due(&db, CronJob::BlockScanners).unwrap());
    }

    #[test]
    fn a_job_run_past_its_interval_is_due_again() {
        let db = Db::open_in_memory().unwrap();
        let interval = CronJob::BlockWebScanners.interval().as_secs() as i64;
        db.set_cron_last_run(
            CronJob::BlockWebScanners.id(),
            now() - interval - 60,
            "ran",
        )
        .unwrap();
        assert!(is_due(&db, CronJob::BlockWebScanners).unwrap());
    }

    #[test]
    fn a_job_run_within_its_interval_is_not_due() {
        let db = Db::open_in_memory().unwrap();
        let interval = CronJob::BlockWebScanners.interval().as_secs() as i64;
        db.set_cron_last_run(
            CronJob::BlockWebScanners.id(),
            now() - interval + 60,
            "ran",
        )
        .unwrap();
        assert!(!is_due(&db, CronJob::BlockWebScanners).unwrap());
    }

    #[test]
    fn due_jobs_on_a_fresh_database_includes_every_job() {
        let db = Db::open_in_memory().unwrap();
        let due = due_jobs(&db).unwrap();
        assert_eq!(due.len(), CronJob::ALL.len());
    }

    #[test]
    fn due_jobs_excludes_a_job_that_just_ran() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(CronJob::UpdateIpRanges.id(), now(), "ran")
            .unwrap();
        let due = due_jobs(&db).unwrap();
        assert!(!due.contains(&CronJob::UpdateIpRanges));
        assert_eq!(due.len(), CronJob::ALL.len() - 1);
    }

    #[test]
    fn status_reports_every_job_with_its_persisted_state() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run(CronJob::BlockScanners.id(), now(), "blocked 2 IP(s)")
            .unwrap();

        let statuses = status(&db).unwrap();
        assert_eq!(statuses.len(), CronJob::ALL.len());

        let ssh = statuses
            .iter()
            .find(|s| s.job == CronJob::BlockScanners)
            .unwrap();
        assert_eq!(ssh.last_run, Some(now()));
        assert_eq!(ssh.last_summary, Some("blocked 2 IP(s)".to_string()));
        assert!(!ssh.due);

        let web = statuses
            .iter()
            .find(|s| s.job == CronJob::BlockWebScanners)
            .unwrap();
        assert_eq!(web.last_run, None);
        assert!(web.due);
    }

    #[test]
    fn every_job_id_is_distinct() {
        let mut ids: Vec<&str> = CronJob::ALL.iter().map(|j| j.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CronJob::ALL.len());
    }
}
