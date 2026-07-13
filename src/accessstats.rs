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

//! Shared "tally successful-access user agents, persist the counts" logic
//! behind the CLI's `record-access-stats` subcommand and the internal
//! cron's `RecordAccessStats` job (see [`crate::cron`]) — the same
//! one-implementation-for-both-callers shape [`crate::scanblock`] uses for
//! the block-detection commands, kept in its own module rather than folded
//! into `scanblock` since this isn't a blocking decision (no threshold,
//! TTL, dry-run or known-crawler exclusion to share with those): it's
//! [`crate::accesslog::scanning_ips`]'s complement, [`crate::accesslog::
//! successful_user_agent_counts`], turned into stored rows.

use crate::accesslog;
use crate::db::Db;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

/// What one record-access-stats pass counted, for both the CLI to print and
/// the cron job to store as its summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessStatsOutcome {
    pub distinct_user_agents: usize,
    pub total_hits: u64,
}

impl AccessStatsOutcome {
    /// A one-line summary suitable for a status display (the Dashboard's
    /// "Scheduled tasks" panel, `Db::set_cron_last_run`'s `summary`
    /// argument), mirroring `ScanBlockOutcome::summary`'s role.
    pub fn summary(&self) -> String {
        if self.total_hits == 0 {
            return "no successful requests found".to_string();
        }
        format!(
            "recorded {} hit(s) across {} distinct user agent(s)",
            self.total_hits, self.distinct_user_agents
        )
    }
}

/// Parses `log_text` (`log_path`'s entire current contents — the caller
/// always re-reads the whole file, since neither the cron job nor the CLI
/// keeps a file handle open between passes) for successful (non-4xx/5xx)
/// requests, tallies each distinct user agent's hit count (see
/// [`accesslog::successful_user_agent_counts`] for exactly what counts),
/// and adds those counts onto `user_agent_stats` via
/// [`Db::record_user_agent_hits`] — additive across repeated calls, same as
/// that method.
///
/// Only the portion of `log_text` appended since the last pass over
/// `log_path` is actually tallied (see [`new_content`]): since every pass
/// re-reads the log from the start, counting the whole thing every time
/// would re-tally the same still-present requests on every single cron
/// tick, inflating `hit_count` far past reality for as long as the log
/// goes un-rotated. `log_path` is just a cache key here (nothing is read
/// from disk again) — pass whatever path `log_text` actually came from.
pub fn record_access_stats(db: &Db, log_path: &str, log_text: &str) -> Result<AccessStatsOutcome> {
    let last_offset = db.get_access_log_offset(log_path)?.unwrap_or(0);
    let (new_text, new_offset) = new_content(log_text, last_offset);

    let counts = accesslog::successful_user_agent_counts(new_text);
    let total_hits: u64 = counts.values().sum();
    let distinct_user_agents = counts.len();

    db.record_user_agent_hits(&counts, now())?;
    db.set_access_log_offset(log_path, new_offset)?;

    Ok(AccessStatsOutcome {
        distinct_user_agents,
        total_hits,
    })
}

/// Splits `full` into the slice appended since `last_offset` bytes were
/// already tallied, and the byte length to remember for next time. A file
/// shorter than `last_offset` means it was rotated or truncated since the
/// last pass — logrotate's `copytruncate`, or a fresh file after a plain
/// rotate — so the entire current content is treated as new rather than
/// partially (or wrongly) skipped. Guards against slicing mid-character on
/// a `last_offset` that (in principle, if the file were ever rewritten
/// rather than only appended to) no longer falls on a UTF-8 boundary, by
/// falling back to treating the whole file as new in that case too.
fn new_content(full: &str, last_offset: u64) -> (&str, u64) {
    let full_len = full.len() as u64;
    if last_offset >= full_len {
        return if last_offset == full_len {
            ("", full_len)
        } else {
            (full, full_len)
        };
    }
    let offset = last_offset as usize;
    if !full.is_char_boundary(offset) {
        return (full, full_len);
    }
    (&full[offset..], full_len)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_line(ip: &str, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn record_access_stats_persists_counts_and_reports_totals() {
        let db = Db::open_in_memory().unwrap();
        let mut log = String::new();
        log.push_str(&ok_line("203.0.113.5", "Mozilla/5.0"));
        log.push_str(&ok_line("203.0.113.6", "Mozilla/5.0"));
        log.push_str(&ok_line("203.0.113.7", "curl/8.0"));

        let outcome = record_access_stats(&db, "access.log", &log).unwrap();

        assert_eq!(outcome.total_hits, 3);
        assert_eq!(outcome.distinct_user_agents, 2);

        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].user_agent, "Mozilla/5.0");
        assert_eq!(stats[0].hit_count, 2);
    }

    /// The correctness bug this module exists to avoid: every cron tick
    /// re-reads the *entire* log from disk, so passing the same full text
    /// twice must NOT double the count — only genuinely new lines
    /// (appended between passes) should ever be tallied.
    #[test]
    fn record_access_stats_does_not_recount_lines_already_seen() {
        let db = Db::open_in_memory().unwrap();
        let log = ok_line("203.0.113.5", "Mozilla/5.0");

        record_access_stats(&db, "access.log", &log).unwrap();
        record_access_stats(&db, "access.log", &log).unwrap();

        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].hit_count, 1);
    }

    #[test]
    fn record_access_stats_accumulates_only_newly_appended_lines() {
        let db = Db::open_in_memory().unwrap();
        let mut log = ok_line("203.0.113.5", "Mozilla/5.0");
        record_access_stats(&db, "access.log", &log).unwrap();

        log.push_str(&ok_line("203.0.113.6", "Mozilla/5.0"));
        record_access_stats(&db, "access.log", &log).unwrap();

        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].hit_count, 2);
    }

    /// A log shorter than what was already tallied (rotated, or truncated
    /// by `copytruncate`) must be treated as entirely new rather than
    /// silently skipped or panicking on an out-of-range slice.
    #[test]
    fn record_access_stats_treats_a_shrunk_log_as_entirely_new() {
        let db = Db::open_in_memory().unwrap();
        let mut long_log = String::new();
        for i in 0..5 {
            long_log.push_str(&ok_line(&format!("203.0.113.{i}"), "Mozilla/5.0"));
        }
        record_access_stats(&db, "access.log", &long_log).unwrap();

        let rotated_log = ok_line("203.0.113.9", "curl/8.0");
        let outcome = record_access_stats(&db, "access.log", &rotated_log).unwrap();

        assert_eq!(outcome.total_hits, 1);
        let stats = db.list_user_agent_stats().unwrap();
        let curl = stats.iter().find(|s| s.user_agent == "curl/8.0").unwrap();
        assert_eq!(curl.hit_count, 1);
    }

    /// Different log paths (the CLI's `--access-log` override vs. the
    /// cron's fixed default) must each track their own read progress
    /// independently rather than sharing one offset.
    #[test]
    fn record_access_stats_tracks_offsets_independently_per_path() {
        let db = Db::open_in_memory().unwrap();
        let log = ok_line("203.0.113.5", "Mozilla/5.0");

        record_access_stats(&db, "path-a.log", &log).unwrap();
        let outcome = record_access_stats(&db, "path-b.log", &log).unwrap();

        assert_eq!(outcome.total_hits, 1);
        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats[0].hit_count, 2);
    }

    #[test]
    fn record_access_stats_reports_none_found_for_an_empty_log() {
        let db = Db::open_in_memory().unwrap();
        let outcome = record_access_stats(&db, "access.log", "").unwrap();
        assert_eq!(outcome.summary(), "no successful requests found");
        assert!(db.list_user_agent_stats().unwrap().is_empty());
    }

    #[test]
    fn new_content_skips_bytes_already_tallied() {
        let full = "AAAABBBB";
        assert_eq!(new_content(full, 4), ("BBBB", 8));
    }

    #[test]
    fn new_content_returns_nothing_new_when_offset_matches_file_length() {
        let full = "AAAA";
        assert_eq!(new_content(full, 4), ("", 4));
    }

    #[test]
    fn new_content_treats_a_shrunk_file_as_entirely_new() {
        let full = "BB";
        assert_eq!(new_content(full, 100), ("BB", 2));
    }
}
