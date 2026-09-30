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

//! The stored half of [`crate::evidence`]: the `log_evidence` table, and
//! the cursor that says how much of each log it already holds.
//!
//! The two only mean something together. Evidence stored without its
//! cursor moving would be counted again by the next read, from the same
//! lines; so the cursor moves first, in the same transaction as the check
//! that nobody else moved it and the first chunk of the evidence, and the
//! rest follows a chunk at a time ([`Ingest`]).

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

use super::{keys, Db};
use crate::evidence::{Evidence, Item, Row, Rule, Tally};
use crate::protection::Detector;

/// One read of one log, ready to store.
pub struct Ingested<'a> {
    /// Which log: the key its cursor is stored under (see
    /// [`keys::log_cursor`]).
    pub source: &'a str,
    /// The cursor the read started from, as it was stored. `None` for a
    /// log never read before.
    pub from: Option<&'a str>,
    /// Where the next read resumes. `None` leaves the stored cursor as it
    /// is, which is what a journal read that found nothing new wants.
    pub to: Option<&'a str>,
    pub evidence: &'a Evidence,
    /// Successful requests by user agent, for `user_agent_stats`.
    pub user_agents: &'a HashMap<String, u64>,
    /// Addresses that logged in over SSH, for the anti-lockout window.
    pub logins: &'a [String],
    pub now: i64,
}

/// The most rows one step of an [`Ingest`] writes: evidence rows and user
/// agents together. A step is one transaction under the web console's
/// database lock, and a pass over 200,000 lines stored whole held that
/// lock, `/login` included, for seven seconds.
pub const INGEST_CHUNK: usize = 5_000;

/// One read's findings, stored a chunk at a time, so that storing a large
/// read does not hold the database for all of it.
///
/// **The first step claims the read.** In one `BEGIN IMMEDIATE`
/// transaction it checks that the stored cursor is still the one the read
/// started from, moves it to where the read stopped, records the logins
/// and writes the first chunk. Another process that read the same lines
/// (the console and a `batch` from cron, say) finds the cursor moved and
/// stores nothing, so of two readers exactly one gets in and nothing is
/// counted twice, however their steps interleave. Each later step writes
/// the next chunk.
///
/// The cursor moves before the last chunk is written, so a process that
/// stops between steps loses what it had not written yet rather than
/// counting it twice on the next read. Losing a few lines' evidence can
/// only make a count smaller, which is the side the detectors err on.
pub struct Ingest {
    source: String,
    from: Option<String>,
    to: Option<String>,
    evidence: Vec<(Detector, String, Item, Tally)>,
    user_agents: Vec<(String, u64)>,
    logins: Vec<String>,
    now: i64,
    claim: Claim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    NotYet,
    Ours,
    Theirs,
}

/// What one [`Ingest::step`] left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestStep {
    /// There is more to write.
    More,
    /// Finished. `stored` is false when another process had already
    /// claimed the same lines, and this stored nothing.
    Done { stored: bool },
}

impl Ingest {
    /// A read of `source` from cursor `from` to `to`, as [`Ingested`]
    /// describes them, with what it found.
    pub fn new(
        source: &str,
        from: Option<&str>,
        to: Option<&str>,
        evidence: Evidence,
        user_agents: HashMap<String, u64>,
        logins: Vec<String>,
        now: i64,
    ) -> Ingest {
        Ingest {
            source: source.to_string(),
            from: from.map(str::to_string),
            to: to.map(str::to_string),
            evidence: evidence.into_rows(),
            user_agents: user_agents.into_iter().collect(),
            logins,
            now,
            claim: Claim::NotYet,
        }
    }

    /// Writes the next chunk of at most `chunk` rows, claiming the read
    /// first if this is the first step. One transaction.
    pub fn step(&mut self, db: &Db, chunk: usize) -> Result<IngestStep> {
        if self.claim == Claim::Theirs {
            return Ok(IngestStep::Done { stored: false });
        }
        let chunk = chunk.max(1);
        let claimed = db.batch(|| {
            if self.claim == Claim::NotYet {
                let stored = db.get_log_cursor(&self.source)?;
                if stored != self.from {
                    return Ok(false);
                }
                if let Some(to) = &self.to {
                    db.set_raw_setting(&keys::log_cursor(&self.source), to)?;
                }
                db.record_ssh_login_ips(&self.logins)?;
            }
            let evidence = self.evidence.len().min(chunk);
            let evidence = self.evidence.split_off(self.evidence.len() - evidence);
            db.upsert_evidence(&evidence)?;
            let agents = self.user_agents.len().min(chunk - evidence.len());
            let agents = self.user_agents.split_off(self.user_agents.len() - agents);
            if !agents.is_empty() {
                db.upsert_user_agent_hits(agents.iter().map(|(a, n)| (a, n)), self.now)?;
            }
            Ok(true)
        })?;
        if !claimed {
            self.claim = Claim::Theirs;
            return Ok(IngestStep::Done { stored: false });
        }
        self.claim = Claim::Ours;
        Ok(if self.evidence.is_empty() && self.user_agents.is_empty() {
            IngestStep::Done { stored: true }
        } else {
            IngestStep::More
        })
    }
}

impl Db {
    /// Adds `rows` onto what `log_evidence` holds.
    fn upsert_evidence(&self, rows: &[(Detector, String, Item, Tally)]) -> Result<()> {
        let mut upsert = self.conn.prepare_cached(
            "INSERT INTO log_evidence
                 (detector, address, item, count, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(detector, address, item) DO UPDATE SET
                 count = count + excluded.count,
                 first_seen = min(first_seen, excluded.first_seen),
                 last_seen = max(last_seen, excluded.last_seen)",
        )?;
        for (detector, address, item, tally) in rows {
            upsert.execute(params![
                detector.id(),
                address,
                item.key(),
                tally.count as i64,
                tally.first,
                tally.last
            ])?;
        }
        Ok(())
    }

    /// Where the next read of `source` resumes, as stored.
    pub fn get_log_cursor(&self, source: &str) -> Result<Option<String>> {
        self.get_raw_setting(&keys::log_cursor(source))
    }

    /// Stores one read's findings and moves its cursor, all at once.
    ///
    /// Returns `false`, having stored nothing, when the stored cursor is no
    /// longer `read.from`: see [`Ingest`]. For a caller that has nothing
    /// to gain from letting the database go between chunks; the web
    /// console's cron steps an [`Ingest`] itself.
    pub fn ingest(&self, read: &Ingested) -> Result<bool> {
        let mut ingest = Ingest::new(
            read.source,
            read.from,
            read.to,
            read.evidence.clone(),
            read.user_agents.clone(),
            read.logins.to_vec(),
            read.now,
        );
        loop {
            if let IngestStep::Done { stored } = ingest.step(self, INGEST_CHUNK)? {
                return Ok(stored);
            }
        }
    }

    /// What `detector` has stored, seen at or after `since`, for every
    /// address that could meet `rule`.
    ///
    /// The rule narrows the read, never the decision: an address with
    /// fewer rows than a distinct-count threshold, or fewer lines than a
    /// line-count one, cannot meet it, so its rows are left in the
    /// database rather than loaded to be discarded. [`crate::evidence::decide`]
    /// still makes the decision on what is read. On a day's worth of 404s
    /// that is a few hundred rows instead of a hundred thousand.
    pub fn evidence_rows(&self, detector: Detector, since: i64, rule: Rule) -> Result<Vec<Row>> {
        let (least, measure) = match rule {
            Rule::Once => (1, "COUNT(*)"),
            Rule::Distinct(n) => (n as i64, "COUNT(*)"),
            Rule::AtLeast(n) => (n as i64, "SUM(count)"),
        };
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT address, item, count, first_seen, last_seen FROM log_evidence
             WHERE detector = ?1 AND last_seen >= ?2 AND address IN (
                 SELECT address FROM log_evidence
                 WHERE detector = ?1 AND last_seen >= ?2
                 GROUP BY address HAVING {measure} >= ?3)"
        ))?;
        let rows = stmt.query_map(params![detector.id(), since, least], |row| {
            Ok(Row {
                address: row.get(0)?,
                item: Item::from_key(&row.get::<_, String>(1)?),
                tally: Tally {
                    count: row.get::<_, i64>(2)?.max(0) as u64,
                    first: row.get(3)?,
                    last: row.get(4)?,
                },
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to read the stored evidence")
    }

    /// Drops `detector`'s evidence last seen before `before`: outside its
    /// window, so it can never count again.
    pub fn prune_evidence(&self, detector: Detector, before: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM log_evidence WHERE detector = ?1 AND last_seen < ?2",
            params![detector.id(), before],
        )?)
    }

    /// Drops every detector's evidence against `address` from before
    /// `before`.
    ///
    /// Called when `address` is blocked, with `before` the moment the block
    /// was made. What it did before then has been answered; if the block
    /// expires, only what it does *after* the block was made can bring it
    /// back. That is the difference between a block that expires and one
    /// that is re-added from its own evidence on the minute it lapses.
    ///
    /// A row that straddles the moment goes too, which can only make a
    /// later count smaller.
    pub fn forget_evidence_before(&self, address: &str, before: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM log_evidence WHERE address = ?1 AND first_seen <= ?2",
            params![address, before],
        )?)
    }

    /// When the newest Block rule for exactly `address` was made, if there
    /// is one.
    pub fn block_created_at(&self, address: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT MAX(created_at) FROM firewall_rules
                 WHERE address = ?1 AND action = 'block'",
                params![address],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(address: &str, path: &str, at: i64) -> Evidence {
        let mut evidence = Evidence::default();
        evidence.add(
            Detector::ProbePaths,
            address.parse().unwrap(),
            Item::seen(path),
            at,
        );
        evidence
    }

    fn ingest(db: &Db, from: Option<&str>, to: &str, evidence: &Evidence) -> bool {
        db.ingest(&Ingested {
            source: "/var/log/nginx/access.log",
            from,
            to: Some(to),
            evidence,
            user_agents: &HashMap::new(),
            logins: &[],
            now: 1_000,
        })
        .unwrap()
    }

    #[test]
    fn ingested_evidence_and_its_cursor_are_stored_together() {
        let db = Db::open_in_memory().unwrap();
        assert!(ingest(
            &db,
            None,
            "c1",
            &evidence("203.0.113.5", "/.env", 100)
        ));

        assert_eq!(
            db.get_log_cursor("/var/log/nginx/access.log")
                .unwrap()
                .as_deref(),
            Some("c1")
        );
        let rows = db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].address, "203.0.113.5");
    }

    /// Two processes that read the same lines: the second must not store
    /// them again.
    #[test]
    fn a_read_from_a_cursor_someone_else_moved_on_stores_nothing() {
        let db = Db::open_in_memory().unwrap();
        let lines = evidence("203.0.113.5", "/.env", 100);
        assert!(ingest(&db, None, "c1", &lines));

        assert!(
            !ingest(&db, None, "c1", &lines),
            "the second reader started from no cursor too"
        );
        let rows = db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows[0].tally.count, 1, "counted once");
    }

    #[test]
    fn repeated_evidence_adds_up_across_reads() {
        let db = Db::open_in_memory().unwrap();
        ingest(&db, None, "c1", &evidence("203.0.113.5", "/.env", 100));
        ingest(
            &db,
            Some("c1"),
            "c2",
            &evidence("203.0.113.5", "/.env", 200),
        );

        let rows = db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(
            rows[0].tally,
            Tally {
                count: 2,
                first: 100,
                last: 200
            }
        );
    }

    #[test]
    fn evidence_older_than_a_window_is_pruned_and_no_longer_read() {
        let db = Db::open_in_memory().unwrap();
        ingest(&db, None, "c1", &evidence("203.0.113.5", "/.env", 100));
        ingest(
            &db,
            Some("c1"),
            "c2",
            &evidence("198.51.100.1", "/.env", 300),
        );

        assert_eq!(
            db.evidence_rows(Detector::ProbePaths, 200, Rule::Once)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(db.prune_evidence(Detector::ProbePaths, 200).unwrap(), 1);
        assert_eq!(
            db.evidence_rows(Detector::ProbePaths, 0, Rule::Once)
                .unwrap()
                .len(),
            1
        );
    }

    /// The read is narrowed to addresses that could meet the rule; the
    /// rest stay stored, still counting towards the next read.
    #[test]
    fn only_addresses_that_could_meet_the_rule_are_read() {
        let db = Db::open_in_memory().unwrap();
        let mut evidence = Evidence::default();
        for (address, paths) in [("203.0.113.5", 3), ("198.51.100.1", 1)] {
            for n in 0..paths {
                evidence.add(
                    Detector::WebScanners,
                    address.parse().unwrap(),
                    Item::seen(&format!("/p{n}")),
                    100,
                );
            }
        }
        ingest(&db, None, "c1", &evidence);

        let rows = db
            .evidence_rows(Detector::WebScanners, 0, Rule::Distinct(2))
            .unwrap();
        assert!(rows.iter().all(|r| r.address == "203.0.113.5"), "{rows:?}");
        assert_eq!(rows.len(), 3);
        assert_eq!(
            db.evidence_rows(Detector::WebScanners, 0, Rule::Once)
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn a_block_forgets_what_its_address_did_before_it() {
        let db = Db::open_in_memory().unwrap();
        ingest(&db, None, "c1", &evidence("203.0.113.5", "/.env", 100));
        ingest(
            &db,
            Some("c1"),
            "c2",
            &evidence("203.0.113.5", "/.git/", 300),
        );

        db.forget_evidence_before("203.0.113.5", 200).unwrap();

        let rows = db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].item, Item::seen("/.git/"));
    }

    fn many_paths(address: &str, n: usize) -> Evidence {
        let mut evidence = Evidence::default();
        for i in 0..n {
            evidence.add(
                Detector::WebScanners,
                address.parse().unwrap(),
                Item::seen(&format!("/p{i}")),
                100,
            );
        }
        evidence
    }

    fn ingest_of(evidence: Evidence, from: Option<&str>, to: &str) -> Ingest {
        let agents = HashMap::from([("Mozilla/5.0".to_string(), 4), ("curl/8".to_string(), 1)]);
        let logins = vec!["192.0.2.10".to_string()];
        Ingest::new("log", from, Some(to), evidence, agents, logins, 1_000)
    }

    /// A chunked store ends where a whole one would: every row, the user
    /// agents, the logins and the cursor.
    #[test]
    fn a_read_stored_a_chunk_at_a_time_stores_all_of_it_once() {
        let db = Db::open_in_memory().unwrap();
        let mut ingest = ingest_of(many_paths("203.0.113.5", 7), None, "c1");

        let mut steps = 1;
        while ingest.step(&db, 3).unwrap() == IngestStep::More {
            steps += 1;
        }

        assert_eq!(steps, 3, "7 rows and 2 agents in chunks of 3");
        assert_eq!(db.get_log_cursor("log").unwrap().as_deref(), Some("c1"));
        let rows = db
            .evidence_rows(Detector::WebScanners, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows.len(), 7);
        assert!(rows.iter().all(|r| r.tally.count == 1), "{rows:?}");
        assert_eq!(db.list_user_agent_stats().unwrap().len(), 2);
        assert_eq!(db.recent_ssh_login_ips().unwrap(), ["192.0.2.10"]);
    }

    /// The first step claims the lines by moving the cursor, so a second
    /// reader of them stores nothing even while the first is part-way
    /// through.
    #[test]
    fn a_second_reader_stores_nothing_while_the_first_is_part_way_through() {
        let db = Db::open_in_memory().unwrap();
        let mut first = ingest_of(many_paths("203.0.113.5", 5), None, "c1");
        let mut second = ingest_of(many_paths("203.0.113.5", 5), None, "c1");

        assert_eq!(first.step(&db, 2).unwrap(), IngestStep::More);
        assert_eq!(
            second.step(&db, 2).unwrap(),
            IngestStep::Done { stored: false }
        );
        while first.step(&db, 2).unwrap() == IngestStep::More {}

        let rows = db
            .evidence_rows(Detector::WebScanners, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().all(|r| r.tally.count == 1), "{rows:?}");
        let mozilla = db.user_agent_stat("Mozilla/5.0").unwrap().unwrap();
        assert_eq!(mozilla.hit_count, 4, "counted once");
    }
}
