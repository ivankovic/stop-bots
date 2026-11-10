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

//! What the schedule did while nobody was looking: a short, kept record of
//! every scheduled job's outcome that is worth reading the next morning.
//!
//! ## Why it exists
//!
//! `tick` prints nothing when it succeeds, the cron file sends its output
//! nowhere, each job keeps only its *last* summary (`cron_last_summary`,
//! overwritten at its next run, a minute later for a detector), and the
//! TUI's Log is in memory and starts empty. So an apply that failed at
//! 03:12 was visible until 03:13, and "what happened overnight" had no
//! answer anywhere. This is the answer: `stop-bots log`, and the lines the
//! Dashboard's Log opens with.
//!
//! ## What is kept
//!
//! Not every run. A detector runs every minute and nearly always finds
//! nothing, which is 1,440 lines a day each of no news. [`noteworthy`]
//! decides: a block, an apply, an error, something skipped or refused, and
//! whatever the jobs that run hourly or less often did when they did
//! anything. And never the same thing twice running from one job: a log
//! that cannot be read says so once, not every minute until it can.
//!
//! ## Where
//!
//! One `settings` row holding the last [`MAX_EVENTS`] as JSON, not a table
//! of its own. A table is a schema version, and a schema version is a
//! database the previous release refuses to open; this is a few kilobytes
//! an older binary ignores.

use crate::cron::CronJob;
use crate::db::Db;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// How many events are kept. At a few an hour on a busy host, weeks.
pub const MAX_EVENTS: usize = 300;

/// One thing a scheduled job did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// When, in Unix seconds.
    pub at: i64,
    /// The job's `CronJob::id`.
    pub job: String,
    /// Its one-line outcome, as `cron_last_summary` had it.
    pub summary: String,
}

impl Event {
    /// The job's name as the Dashboard shows it, or its id for a job a
    /// newer version ran and this one does not know.
    pub fn label(&self) -> &str {
        let known: Option<&'static str> = CronJob::all()
            .into_iter()
            .find(|job| job.id() == self.job)
            .map(CronJob::label);
        known.unwrap_or(&self.job)
    }

    /// Whether something went wrong, for the readers that mark it.
    pub fn failed(&self) -> bool {
        let summary = self.summary.to_lowercase();
        ["error", "failed", "could not", "unavailable", "alert"]
            .iter()
            .any(|word| summary.contains(word))
    }
}

/// Whether `job` ending with `summary` is worth keeping: see the module
/// docs. What a summary says is all there is to go on, because a summary
/// is all a job leaves behind.
pub fn noteworthy(job: CronJob, summary: &str) -> bool {
    let summary = summary.to_lowercase();
    let says = |words: &[&str]| words.iter().any(|word| summary.contains(word));
    if says(&[
        "error",
        "failed",
        "could not",
        "unavailable",
        "skipped",
        "refused",
        "alert",
    ]) {
        return true;
    }
    // A switch that is off, and work that found nothing to do.
    if summary.is_empty()
        || says(&[
            "is off",
            "are off",
            "disabled",
            "switched on",
            "already up to date",
            "nothing",
            "would block",
        ])
    {
        return false;
    }
    if says(&["blocked", "applied", "contained", "released", "reloaded"]) {
        return true;
    }
    job.interval() >= std::time::Duration::from_secs(3_600)
}

/// Keeps `job`'s outcome if it is [`noteworthy`] and not what the job said
/// last time. A failure to write it is ignored, for the reason
/// `cron::record_run` gives: the work is done, and the bookkeeping must
/// not turn it into a failure.
pub fn note(db: &Db, job: CronJob, summary: &str, at: i64) {
    if !noteworthy(job, summary) {
        return;
    }
    // No transaction of its own: some callers are inside one already, and
    // the two writers (a `tick` and an open TUI) losing one line to each
    // other once in a while costs less than a job failing over its notes.
    let _ = (|| -> Result<()> {
        let mut events = list(db)?;
        let summary = summary.lines().next().unwrap_or_default();
        let last = events.iter().rev().find(|event| event.job == job.id());
        if last.is_some_and(|event| event.summary == summary) {
            return Ok(());
        }
        events.push(Event {
            at,
            job: job.id().to_string(),
            summary: summary.to_string(),
        });
        let excess = events.len().saturating_sub(MAX_EVENTS);
        events.drain(..excess);
        db.set_activity_log(&serde_json::to_string(&events)?)
    })();
}

/// Every kept event, oldest first. A value this version cannot read, which
/// only a later one could have written, is nothing kept.
pub fn list(db: &Db) -> Result<Vec<Event>> {
    Ok(db
        .get_activity_log()?
        .and_then(|stored| serde_json::from_str(&stored).ok())
        .unwrap_or_default())
}

/// The events at or after `since`, oldest first.
pub fn since(db: &Db, since: i64) -> Result<Vec<Event>> {
    Ok(list(db)?
        .into_iter()
        .filter(|event| event.at >= since)
        .collect())
}

/// `24h`, `7d`, `90m` or a bare number of hours, as seconds.
pub fn parse_span(text: &str) -> Option<i64> {
    let text = text.trim();
    let (number, unit) = match text.char_indices().last()? {
        (at, 'm') => (&text[..at], 60),
        (at, 'h') => (&text[..at], 3_600),
        (at, 'd') => (&text[..at], 86_400),
        _ => (text, 3_600),
    };
    let number: i64 = number.parse().ok().filter(|n| *n > 0)?;
    number.checked_mul(unit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::Detector;

    const SSH: CronJob = CronJob::Detect(Detector::SshScanners);

    fn summaries(db: &Db) -> Vec<String> {
        list(db).unwrap().into_iter().map(|e| e.summary).collect()
    }

    #[test]
    fn a_block_an_error_and_a_skip_are_kept_and_no_news_is_not() {
        let cases = [
            (SSH, "blocked 2 IP(s)", true),
            (SSH, "no scanners found", false),
            (SSH, "found 3 scanner(s), all already covered", false),
            (SSH, "SSH log unavailable", true),
            (CronJob::ApplyNginx, "error: nginx -t failed", true),
            (CronJob::ApplyNginx, "auto-apply is off", false),
            (CronJob::ApplyNginx, "2 site(s) already up to date", false),
            (
                CronJob::RenderFirewall,
                "skipped: would lock out 203.0.113.5",
                true,
            ),
            (CronJob::UpdateIpRanges, "updated 4 crawler source(s)", true),
            (CronJob::Maintenance, "nothing stale to prune", false),
        ];
        for (job, summary, kept) in cases {
            assert_eq!(noteworthy(job, summary), kept, "{}: {summary}", job.id());
        }
    }

    /// A log that cannot be read is unreadable every minute.
    #[test]
    fn a_job_saying_the_same_thing_again_is_kept_once() {
        let db = Db::open_in_memory().unwrap();
        for at in [100, 160, 220] {
            note(&db, SSH, "SSH log unavailable", at);
        }
        note(&db, SSH, "blocked 1 IP(s)", 280);
        note(&db, SSH, "SSH log unavailable", 340);

        assert_eq!(
            summaries(&db),
            [
                "SSH log unavailable",
                "blocked 1 IP(s)",
                "SSH log unavailable"
            ]
        );
        assert_eq!(list(&db).unwrap()[0].at, 100, "the first time it said so");
    }

    #[test]
    fn only_the_newest_events_are_kept() {
        let db = Db::open_in_memory().unwrap();
        for n in 0..MAX_EVENTS + 5 {
            note(&db, SSH, &format!("blocked {n} IP(s)"), n as i64);
        }

        let events = list(&db).unwrap();
        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(events[0].summary, "blocked 5 IP(s)");
    }

    #[test]
    fn since_leaves_out_what_is_older() {
        let db = Db::open_in_memory().unwrap();
        note(&db, SSH, "blocked 1 IP(s)", 100);
        note(&db, SSH, "blocked 2 IP(s)", 200);

        let recent: Vec<String> = since(&db, 150)
            .unwrap()
            .into_iter()
            .map(|e| e.summary)
            .collect();
        assert_eq!(recent, ["blocked 2 IP(s)"]);
    }

    #[test]
    fn a_span_is_minutes_hours_or_days() {
        let cases = [
            ("90m", Some(5_400)),
            ("24h", Some(86_400)),
            ("7d", Some(604_800)),
            ("12", Some(43_200)),
            ("0h", None),
            ("-1d", None),
            ("soon", None),
            ("", None),
        ];
        for (text, seconds) in cases {
            assert_eq!(parse_span(text), seconds, "{text:?}");
        }
    }

    #[test]
    fn an_event_is_named_as_the_dashboard_names_its_job() {
        let event = |job: &str, summary: &str| Event {
            at: 0,
            job: job.to_string(),
            summary: summary.to_string(),
        };
        assert_eq!(event(SSH.id(), "").label(), SSH.label());
        assert_eq!(
            event("a_job_from_the_future", "").label(),
            "a_job_from_the_future"
        );
        assert!(event(SSH.id(), "error: denied").failed());
        assert!(!event(SSH.id(), "blocked 2 IP(s)").failed());
    }
}
