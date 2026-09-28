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
//! The two are written together, in one transaction ([`Db::ingest`]),
//! because they only mean something together. Evidence stored without its
//! cursor would be counted again on the next read; a cursor stored without
//! its evidence would lose those lines for good.

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

impl Db {
    /// Where the next read of `source` resumes, as stored.
    pub fn get_log_cursor(&self, source: &str) -> Result<Option<String>> {
        self.get_raw_setting(&keys::log_cursor(source))
    }

    /// Stores one read's findings and its cursor, or nothing at all.
    ///
    /// Returns `false`, having stored nothing, when the stored cursor is no
    /// longer `read.from`: another process (the console and a `batch` from
    /// cron, say) read the same lines first and has already stored them.
    /// Storing them again would count every one of them twice. The check
    /// and the write are one `BEGIN IMMEDIATE` transaction, so of two
    /// readers exactly one gets in.
    pub fn ingest(&self, read: &Ingested) -> Result<bool> {
        self.batch(|| {
            let stored = self.get_log_cursor(read.source)?;
            if stored.as_deref() != read.from {
                return Ok(false);
            }
            let mut upsert = self.conn.prepare_cached(
                "INSERT INTO log_evidence
                     (detector, address, item, count, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(detector, address, item) DO UPDATE SET
                     count = count + excluded.count,
                     first_seen = min(first_seen, excluded.first_seen),
                     last_seen = max(last_seen, excluded.last_seen)",
            )?;
            for (detector, address, item, tally) in read.evidence.iter() {
                upsert.execute(params![
                    detector.id(),
                    address,
                    item.key(),
                    tally.count as i64,
                    tally.first,
                    tally.last
                ])?;
            }
            self.upsert_user_agent_hits(read.user_agents, read.now)?;
            self.record_ssh_login_ips(read.logins)?;
            if let Some(to) = read.to {
                self.set_raw_setting(&keys::log_cursor(read.source), to)?;
            }
            Ok(true)
        })
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
}
