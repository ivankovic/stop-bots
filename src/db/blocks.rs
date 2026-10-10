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

//! The stored half of [`crate::blocks`]: the Blocks views' queries over
//! `firewall_rules`, removing by source, and `unblocked_addresses`, the
//! record that keeps an operator's unblock from being undone by the next
//! detector pass.
//!
//! The views page in the database rather than loading the table: a host
//! with every detector on can hold tens of thousands of rules, and both
//! front-ends redraw often.

use std::collections::HashMap;

use anyhow::{Context, Result};
use rusqlite::params;

use super::{firewall_rule_from_row, now, Db, FirewallAction, FirewallRule, FIREWALL_RULE_COLUMNS};
use crate::blocks::{RuleSource, SourceFilter};

/// The shortest time an unblock keeps the detectors off an address.
///
/// It otherwise lasts as long as the block was meant to (see
/// [`Db::record_unblocks`]); this floor is for a block made moments before
/// it expired, whose evidence is still in the log.
pub const UNBLOCK_MIN_SECONDS: i64 = 86_400;

/// Which rules a Blocks view shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockQuery {
    /// Only rules from this source; `None` for every source.
    pub source: Option<SourceFilter>,
    /// Only rules whose address contains this text, or, when it is an
    /// address, whose range contains it: "why is 203.0.113.7 blocked?"
    /// has to find the /24 it is in. Empty for every address.
    pub search: String,
}

impl BlockQuery {
    /// The `WHERE` clause for everything but the search, taking the time
    /// as `?1` and the source, if any, as `?2`. Expired rows are left out
    /// rather than pruned: this is a read, and it runs on every page view.
    fn condition(&self) -> (String, Option<String>) {
        let live = "(expires_at IS NULL OR expires_at > ?1)";
        match self.source {
            // `?2` is always named, so every query takes the same two.
            None => (format!("{live} AND ?2 IS NULL"), None),
            Some(SourceFilter::Legacy) => {
                (format!("{live} AND source IS NULL AND ?2 IS NULL"), None)
            }
            Some(SourceFilter::Source(source)) => (
                format!("{live} AND source = ?2"),
                Some(source.stored().to_string()),
            ),
        }
    }

    fn search_matches(&self, address: &str) -> bool {
        let needle = self.search.trim();
        if address.to_lowercase().contains(&needle.to_lowercase()) {
            return true;
        }
        needle
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| crate::ipranges::cidr_contains(address, ip))
    }
}

impl Db {
    /// How many rules `query` matches.
    pub fn count_blocks(&self, query: &BlockQuery) -> Result<usize> {
        if !query.search.trim().is_empty() {
            return Ok(self.searched_ids(query)?.len());
        }
        let (condition, source) = query.condition();
        let count: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM firewall_rules WHERE {condition}"),
            params![now(), source],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Up to `limit` of the rules `query` matches, newest first, skipping
    /// the first `offset`.
    pub fn blocks_page(
        &self,
        query: &BlockQuery,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<FirewallRule>> {
        if !query.search.trim().is_empty() {
            let ids: Vec<i64> = self
                .searched_ids(query)?
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect();
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let list = ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",");
            let mut rules = self.firewall_rules_where(&format!("id IN ({list})"), [])?;
            rules.sort_by_key(|rule| std::cmp::Reverse(rule.id));
            return Ok(rules);
        }
        let (condition, source) = query.condition();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {FIREWALL_RULE_COLUMNS} FROM firewall_rules WHERE {condition}
             ORDER BY id DESC LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = stmt.query_map(
            params![now(), source, limit as i64, offset as i64],
            firewall_rule_from_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list firewall rules")
    }

    /// The ids of every rule `query` matches, search included, newest
    /// first. The search is done here rather than in SQL because it has
    /// to parse ranges; reading two columns of every row is a few
    /// milliseconds on 50,000.
    fn searched_ids(&self, query: &BlockQuery) -> Result<Vec<i64>> {
        let (condition, source) = query.condition();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT id, address FROM firewall_rules WHERE {condition} ORDER BY id DESC"
        ))?;
        let rows = stmt.query_map(params![now(), source], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut ids = Vec::new();
        for row in rows {
            let (id, address) = row?;
            if query.search_matches(&address) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    /// How many live rules each source has, largest first. What the
    /// Blocks views offer as filters, and the count "unblock all" confirms.
    pub fn block_source_counts(&self) -> Result<Vec<(SourceFilter, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT source, COUNT(*) FROM firewall_rules
             WHERE expires_at IS NULL OR expires_at > ?1 GROUP BY source",
        )?;
        let rows = stmt.query_map(params![now()], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?))
        })?;
        // Merged after parsing: two stored spellings this version does not
        // know both read as `Unknown`, and must not be two filters.
        let mut counts: HashMap<SourceFilter, usize> = HashMap::new();
        for row in rows {
            let (stored, count) = row?;
            let filter = match stored {
                Some(stored) => SourceFilter::Source(RuleSource::from_stored(&stored)),
                None => SourceFilter::Legacy,
            };
            *counts.entry(filter).or_default() += count as usize;
        }
        let mut counts: Vec<(SourceFilter, usize)> = counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name().cmp(b.0.name())));
        Ok(counts)
    }

    /// Removes every rule from `filter`'s source and returns how many.
    /// `dry_run` counts them and removes nothing. Detectors' blocks are
    /// recorded as unblocked by hand, as for a single removal.
    pub fn remove_firewall_rules_from(&self, filter: SourceFilter, dry_run: bool) -> Result<usize> {
        let query = BlockQuery {
            source: Some(filter),
            search: String::new(),
        };
        if dry_run {
            return self.count_blocks(&query);
        }
        let (condition, source) = query.condition();
        self.batch(|| {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT {FIREWALL_RULE_COLUMNS} FROM firewall_rules WHERE {condition}"
            ))?;
            let rules = stmt
                .query_map(params![now(), source], firewall_rule_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            self.conn.execute(
                &format!("DELETE FROM firewall_rules WHERE {condition}"),
                params![now(), source],
            )?;
            self.record_unblocks(&rules)?;
            Ok(rules.len())
        })
    }

    /// Records that an operator removed `rules`, so the detectors leave
    /// those addresses alone for a while (see [`crate::blocks`]).
    ///
    /// Only a detector's block needs it: nothing re-adds a rule a person
    /// wrote. A rule from before 0.1 has no source, but only a detector
    /// ever gave one an expiry, so that is what identifies one.
    ///
    /// For as long as the block was meant to last, counted from now, and
    /// at least [`UNBLOCK_MIN_SECONDS`]. An address already recorded keeps
    /// the later of the two ends.
    pub(super) fn record_unblocks(&self, rules: &[FirewallRule]) -> Result<()> {
        let now = now();
        let mut stmt = self.conn.prepare(
            "INSERT INTO unblocked_addresses (address, source, unblocked_at, until)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (address) DO UPDATE SET
                 source = excluded.source,
                 unblocked_at = excluded.unblocked_at,
                 until = MAX(until, excluded.until)",
        )?;
        for rule in rules {
            let by_detector = match rule.source {
                Some(source) => source.detector().is_some(),
                None => rule.expires_at.is_some(),
            };
            if rule.action == FirewallAction::Allow || !by_detector {
                continue;
            }
            let lifetime = match (rule.created_at, rule.expires_at) {
                (Some(created), Some(expires)) => expires.saturating_sub(created),
                _ => 0,
            };
            stmt.execute(params![
                rule.address,
                rule.source.map(RuleSource::stored),
                now,
                now.saturating_add(lifetime.max(UNBLOCK_MIN_SECONDS))
            ])?;
            // And what the address did up to now is answered, as a block
            // answers it (see `Db::forget_evidence_before`): after the
            // record above lapses, only a new offence brings it back. A
            // range's evidence is kept per address inside it, which the
            // record's overlap check covers instead.
            self.forget_evidence_before(&rule.address, now)?;
        }
        Ok(())
    }

    /// Every address an operator unblocked that the detectors must still
    /// leave alone, with when that ends. Lapsed rows are deleted first.
    pub fn unblocked_addresses(&self) -> Result<Vec<(String, i64)>> {
        let now = now();
        self.conn.execute(
            "DELETE FROM unblocked_addresses WHERE until <= ?1",
            params![now],
        )?;
        let mut stmt = self
            .conn
            .prepare("SELECT address, until FROM unblocked_addresses ORDER BY address")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list unblocked addresses")
    }
}

#[cfg(test)]
impl Db {
    /// A Block for `address` as a 0.0.x release wrote it: no source, no
    /// evidence. For the screens' tests, which cannot reach the table.
    /// Lets rule `id` lapse now, the way its expiry would: pruned, and not
    /// removed by an operator, which the detectors would then respect.
    pub(crate) fn let_firewall_rule_lapse(&self, id: i64) {
        self.conn
            .execute(
                "UPDATE firewall_rules SET expires_at = ?1 WHERE id = ?2",
                params![now() - 1, id],
            )
            .unwrap();
        self.prune_expired_firewall_rules().unwrap();
    }

    pub(crate) fn insert_rule_from_before_0_1(&self, address: &str) {
        self.conn
            .execute(
                "INSERT INTO firewall_rules (address, action, enabled, created_at)
                 VALUES (?1, 'block', 1, ?2)",
                params![address, now()],
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewFirewallRule;
    use crate::protection::Detector;

    fn detector_block(db: &Db, address: &str, detector: Detector) -> i64 {
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: address.to_string(),
                port: None,
                action: FirewallAction::Block,
                source: RuleSource::Detector(detector),
                evidence: Some(format!("GET /.env from {address}")),
            },
            86_400 * 3,
        )
        .unwrap()
    }

    fn hand_block(db: &Db, address: &str) -> i64 {
        db.add_firewall_rule(&NewFirewallRule {
            address: address.to_string(),
            port: None,
            action: FirewallAction::Block,
            source: RuleSource::Cli,
            evidence: None,
        })
        .unwrap()
    }

    fn addresses(rules: &[FirewallRule]) -> Vec<&str> {
        rules.iter().map(|r| r.address.as_str()).collect()
    }

    #[test]
    fn a_page_is_newest_first_and_counts_what_the_filter_matches() {
        let db = Db::open_in_memory().unwrap();
        detector_block(&db, "198.51.100.1", Detector::ProbePaths);
        hand_block(&db, "198.51.100.2");
        detector_block(&db, "198.51.100.3", Detector::ProbePaths);

        let probes = BlockQuery {
            source: Some(SourceFilter::Source(RuleSource::Detector(
                Detector::ProbePaths,
            ))),
            search: String::new(),
        };
        assert_eq!(db.count_blocks(&probes).unwrap(), 2);
        assert_eq!(
            addresses(&db.blocks_page(&probes, 0, 10).unwrap()),
            ["198.51.100.3", "198.51.100.1"]
        );
        assert_eq!(
            addresses(&db.blocks_page(&BlockQuery::default(), 1, 1).unwrap()),
            ["198.51.100.2"],
            "the second page of one"
        );
    }

    /// "Why is this address blocked?" is asked with the address, and the
    /// answer may be a range around it.
    #[test]
    fn searching_for_an_address_finds_the_range_it_is_in() {
        let db = Db::open_in_memory().unwrap();
        hand_block(&db, "203.0.113.0/24");
        hand_block(&db, "2001:db8:1:2::/64");
        hand_block(&db, "198.51.100.9");

        for (search, expected) in [
            ("203.0.113.77", vec!["203.0.113.0/24"]),
            ("2001:DB8:1:2::5", vec!["2001:db8:1:2::/64"]),
            ("198.51", vec!["198.51.100.9"]),
            ("192.0.2.1", vec![]),
        ] {
            let query = BlockQuery {
                source: None,
                search: search.to_string(),
            };
            assert_eq!(
                addresses(&db.blocks_page(&query, 0, 10).unwrap()),
                expected,
                "searching {search}"
            );
            assert_eq!(db.count_blocks(&query).unwrap(), expected.len());
        }
    }

    #[test]
    fn source_counts_name_rules_from_before_0_1_separately() {
        let db = Db::open_in_memory().unwrap();
        detector_block(&db, "198.51.100.1", Detector::Injection);
        detector_block(&db, "198.51.100.2", Detector::Injection);
        db.conn
            .execute(
                "INSERT INTO firewall_rules (address, action, enabled, created_at)
                 VALUES ('192.0.2.1', 'block', 1, 1)",
                [],
            )
            .unwrap();

        assert_eq!(
            db.block_source_counts().unwrap(),
            [
                (
                    SourceFilter::Source(RuleSource::Detector(Detector::Injection)),
                    2
                ),
                (SourceFilter::Legacy, 1),
            ]
        );
    }

    #[test]
    fn removing_by_source_takes_only_that_source_and_a_dry_run_takes_nothing() {
        let db = Db::open_in_memory().unwrap();
        detector_block(&db, "198.51.100.1", Detector::WebScanners);
        detector_block(&db, "198.51.100.2", Detector::WebScanners);
        hand_block(&db, "198.51.100.3");
        let scanners = SourceFilter::Source(RuleSource::Detector(Detector::WebScanners));

        assert_eq!(db.remove_firewall_rules_from(scanners, true).unwrap(), 2);
        assert_eq!(db.list_firewall_rules().unwrap().len(), 3, "dry run");

        assert_eq!(db.remove_firewall_rules_from(scanners, false).unwrap(), 2);
        assert_eq!(
            addresses(&db.list_firewall_rules().unwrap()),
            ["198.51.100.3"]
        );
    }

    /// The point of recording it: the lines that earned the block are
    /// still in the log on the next pass.
    #[test]
    fn unblocking_a_detector_s_block_is_remembered_and_a_hand_block_is_not() {
        let db = Db::open_in_memory().unwrap();
        let by_detector = detector_block(&db, "198.51.100.1", Detector::ProbePaths);
        let by_hand = hand_block(&db, "198.51.100.2");

        db.remove_firewall_rule(by_detector).unwrap();
        db.remove_firewall_rule(by_hand).unwrap();

        let unblocked = db.unblocked_addresses().unwrap();
        assert_eq!(
            unblocked
                .iter()
                .map(|(a, _)| a.as_str())
                .collect::<Vec<_>>(),
            ["198.51.100.1"]
        );
        // As long as the three-day block was meant to last, from now.
        let lasts = unblocked[0].1 - now();
        assert!(
            (3 * 86_400 - 5..=3 * 86_400).contains(&lasts),
            "lasts {lasts}s"
        );
    }

    #[test]
    fn an_unblock_lasts_at_least_a_day_and_lapses_after() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "198.51.100.1".into(),
                port: None,
                action: FirewallAction::Block,
                source: RuleSource::Detector(Detector::WebScanners),
                evidence: None,
            },
            60,
        )
        .unwrap();
        db.unblock_address("198.51.100.1").unwrap();
        let until = db.unblocked_addresses().unwrap()[0].1;
        assert!(until - now() >= UNBLOCK_MIN_SECONDS - 5);

        db.conn
            .execute("UPDATE unblocked_addresses SET until = ?1", params![now()])
            .unwrap();
        assert!(db.unblocked_addresses().unwrap().is_empty());
    }

    /// A rule from before 0.1 has no source, but only a detector ever
    /// wrote one with an expiry.
    #[test]
    fn a_pre_0_1_rule_with_an_expiry_is_taken_for_a_detector_s() {
        let db = Db::open_in_memory().unwrap();
        db.conn
            .execute_batch(
                "INSERT INTO firewall_rules (address, action, enabled, created_at, expires_at)
                 VALUES ('198.51.100.1', 'block', 1, 1, 4102444800),
                        ('198.51.100.2', 'block', 1, 1, NULL);",
            )
            .unwrap();

        assert_eq!(
            db.remove_firewall_rules_from(SourceFilter::Legacy, false)
                .unwrap(),
            2
        );
        let unblocked = db.unblocked_addresses().unwrap();
        assert_eq!(unblocked.len(), 1, "{unblocked:?}");
        assert_eq!(unblocked[0].0, "198.51.100.1");
    }
}
