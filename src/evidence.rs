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

//! What the logs have shown about each address, and when: the evidence a
//! detector decides on.
//!
//! ## Why evidence is kept rather than re-read
//!
//! The detectors used to re-read the whole log every minute and count over
//! everything in it. That had two costs. Memory and CPU, about ten full
//! reads a minute; and correctness, because a count over the whole file
//! ignores *when*: a block expired, the lines that earned it were still in
//! the file, and the next pass added it again, until logrotate.
//!
//! The log is now read once, incrementally (see [`crate::logscan`]), so
//! each pass sees only what was appended. A detector that needs twenty
//! failed logins cannot decide on one minute's lines, so what each line
//! says is kept here, per address, with the time the line carries, and
//! kept only as long as the detector's window. Stored in the database
//! (`log_evidence`, see `db::evidence`), which is what makes it survive a
//! restart and a rotation: the file can be replaced under us, the evidence
//! it produced is already recorded.
//!
//! The alternative was to re-read a bounded tail of the log (the last
//! window's worth) each pass. It needs no table, but it is not correct
//! across a rotation, when the tail is in the previous file, and it is not
//! incremental: a day's window is a day's log, every minute.
//!
//! ## Three kinds of evidence
//!
//! Each detector counts one of three things, which is what [`Rule`] says:
//!
//! - **lines** ([`Rule::AtLeast`]): the SSH scanner counts failed logins.
//!   Kept as ten-minute buckets ([`Item::Bucket`]), so a window can slide
//!   over them without keeping every line;
//! - **distinct things** ([`Rule::Distinct`]): paths that 404'd, pages,
//!   user agents. Each is one [`Item::Seen`] with the last time it was
//!   seen. Two of them also have a *clearing* observation ([`Item::Clear`]):
//!   one fetched asset, one sent referer, and the address is not a
//!   suspect for as long as that is inside the window;
//! - **one line is enough** ([`Rule::Once`]): a probe path, a payload, the
//!   honeypot.
//!
//! [`decide`] is the whole decision, and the same function serves the
//! evidence stored here and the evidence built in memory from a log given
//! whole, which is what the one-off CLI commands read. There is one
//! implementation of "what counts" per detector, not one per caller.

use crate::protection::Detector;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// The width of a line-count bucket. A window slides over these a bucket
/// at a time, and a bucket that is partly outside the window does not
/// count at all, so a count can fall short by up to this much of the
/// window's oldest edge. Short of, never over: that is the side to err on.
pub const BUCKET_SECONDS: i64 = 600;

/// The longest item kept, in characters. Paths and user agents are the
/// client's, and unbounded; two that agree on their first two hundred
/// characters count as one, which can only make a count smaller.
pub const MAX_ITEM_CHARS: usize = 200;

/// One thing a line said about its sender, for one detector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Item {
    /// A distinct thing it asked for or sent: a path, a user agent, the
    /// crawler it claimed to be, the payload it carried.
    Seen(String),
    /// Something that clears it: an asset fetched, a referer sent.
    Clear,
    /// A line counted into the bucket starting at this time.
    Bucket(i64),
}

impl Item {
    /// A seen item, truncated to [`MAX_ITEM_CHARS`].
    pub fn seen(text: &str) -> Item {
        match text.char_indices().nth(MAX_ITEM_CHARS) {
            Some((at, _)) => Item::Seen(text[..at].to_string()),
            None => Item::Seen(text.to_string()),
        }
    }

    /// The bucket `at` falls in.
    pub fn bucket(at: i64) -> Item {
        Item::Bucket(at.div_euclid(BUCKET_SECONDS) * BUCKET_SECONDS)
    }

    /// How this is stored. A log line cannot contain a newline, so a
    /// leading one marks the two kinds a client cannot spell.
    pub fn key(&self) -> String {
        match self {
            Item::Seen(text) => text.clone(),
            Item::Clear => "\nclear".to_string(),
            Item::Bucket(start) => format!("\nbucket {start}"),
        }
    }

    pub fn from_key(key: &str) -> Item {
        if key == "\nclear" {
            return Item::Clear;
        }
        match key
            .strip_prefix("\nbucket ")
            .and_then(|n| n.parse::<i64>().ok())
        {
            Some(start) => Item::Bucket(start),
            None => Item::Seen(key.to_string()),
        }
    }
}

/// How often, and between when and when, an item was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub count: u64,
    pub first: i64,
    pub last: i64,
}

impl Tally {
    pub fn once(at: i64) -> Tally {
        Tally {
            count: 1,
            first: at,
            last: at,
        }
    }

    /// Both tallies as one.
    pub fn merge(&mut self, other: Tally) {
        self.count += other.count;
        self.first = self.first.min(other.first);
        self.last = self.last.max(other.last);
    }
}

/// One stored or collected row: `address` saw `item`, `tally` times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub address: String,
    pub item: Item,
    pub tally: Tally,
}

/// Evidence collected in memory, from one read of a log.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    rows: HashMap<(Detector, IpAddr, Item), Tally>,
}

impl Evidence {
    pub fn add(&mut self, detector: Detector, address: IpAddr, item: Item, at: i64) {
        self.rows
            .entry((detector, address, item))
            .and_modify(|tally| tally.merge(Tally::once(at)))
            .or_insert_with(|| Tally::once(at));
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Every row, for storing.
    pub fn iter(&self) -> impl Iterator<Item = (Detector, String, &Item, Tally)> + '_ {
        self.rows.iter().map(|((detector, address, item), tally)| {
            (*detector, address.to_string(), item, *tally)
        })
    }

    /// The rows one detector collected.
    pub fn rows_for(&self, detector: Detector) -> Vec<Row> {
        self.rows
            .iter()
            .filter(|((d, _, _), _)| *d == detector)
            .map(|((_, address, item), tally)| Row {
                address: address.to_string(),
                item: item.clone(),
                tally: *tally,
            })
            .collect()
    }
}

/// What a detector needs to see before it acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// At least this many lines.
    AtLeast(usize),
    /// At least this many distinct items, and nothing that clears the
    /// address.
    Distinct(usize),
    /// One line.
    Once,
}

/// Every address `rows` convicts under `rule`, counting only what was seen
/// at or after `cutoff` (everything, with `None`), each with the earliest
/// item that did it. Sorted by address.
///
/// "At or after the cutoff" means different things for the three rules,
/// and each errs towards not blocking:
///
/// - a bucket counts only if it *started* inside the window, so a count
///   never includes a line from before it;
/// - a distinct item counts if it was seen inside the window at all, and
///   so does a clearing observation;
/// - a single line counts if it was inside the window.
pub fn decide(rows: &[Row], rule: Rule, cutoff: Option<i64>) -> Vec<(String, String)> {
    let inside = |at: i64| cutoff.is_none_or(|c| at >= c);
    let mut by_address: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
    for row in rows {
        by_address
            .entry(row.address.as_str())
            .or_default()
            .push(row);
    }

    let mut convicted = Vec::new();
    for (address, rows) in by_address {
        // The earliest item inside the window, which is what a report
        // names as the reason.
        let mut earliest: Option<(i64, &str)> = None;
        let guilty = match rule {
            Rule::AtLeast(threshold) => {
                let mut lines = 0u64;
                for row in &rows {
                    let start = match row.item {
                        Item::Bucket(start) => start,
                        _ => row.tally.first,
                    };
                    if inside(start) {
                        lines += row.tally.count;
                    }
                }
                lines >= threshold as u64
            }
            Rule::Distinct(threshold) => {
                let cleared = rows
                    .iter()
                    .any(|row| row.item == Item::Clear && inside(row.tally.last));
                let mut distinct = 0usize;
                for row in &rows {
                    if matches!(row.item, Item::Seen(_)) && inside(row.tally.last) {
                        distinct += 1;
                        note(&mut earliest, row);
                    }
                }
                !cleared && distinct >= threshold
            }
            Rule::Once => {
                let mut any = false;
                for row in &rows {
                    if matches!(row.item, Item::Seen(_)) && inside(row.tally.last) {
                        any = true;
                        note(&mut earliest, row);
                    }
                }
                any
            }
        };
        if guilty {
            let reason = earliest
                .map(|(_, text)| text.to_string())
                .unwrap_or_default();
            convicted.push((address.to_string(), reason));
        }
    }
    convicted
}

/// Keeps whichever of `earliest` and `row`'s item was seen first.
fn note<'a>(earliest: &mut Option<(i64, &'a str)>, row: &'a Row) {
    if let Item::Seen(text) = &row.item {
        let candidate = (row.tally.first, text.as_str());
        if earliest.is_none_or(|e| candidate < e) {
            *earliest = Some(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(address: &str, item: Item, first: i64, last: i64, count: u64) -> Row {
        Row {
            address: address.to_string(),
            item,
            tally: Tally { count, first, last },
        }
    }

    fn seen(address: &str, text: &str, at: i64) -> Row {
        row(address, Item::seen(text), at, at, 1)
    }

    #[test]
    fn an_item_round_trips_through_its_stored_form() {
        for item in [
            Item::seen("/wp-login.php"),
            Item::Clear,
            Item::bucket(1_790_577_181),
            Item::seen(""),
            Item::seen("\nbucket nonsense"),
        ] {
            assert_eq!(Item::from_key(&item.key()), item, "{item:?}");
        }
    }

    #[test]
    fn a_bucket_starts_on_its_boundary() {
        assert_eq!(Item::bucket(1_201), Item::Bucket(1_200));
        assert_eq!(Item::bucket(1_200), Item::Bucket(1_200));
    }

    /// A client chooses its own user agent; one of a megabyte must not
    /// become a megabyte row.
    #[test]
    fn a_long_item_is_truncated() {
        let Item::Seen(text) = Item::seen(&"é".repeat(1_000)) else {
            unreachable!()
        };
        assert_eq!(text.chars().count(), MAX_ITEM_CHARS);
    }

    #[test]
    fn lines_are_counted_only_from_buckets_inside_the_window() {
        let rows = [
            row("203.0.113.5", Item::Bucket(0), 10, 500, 15),
            row("203.0.113.5", Item::Bucket(600), 600, 700, 10),
        ];
        assert_eq!(
            decide(&rows, Rule::AtLeast(20), None).len(),
            1,
            "25 lines in all"
        );
        assert!(
            decide(&rows, Rule::AtLeast(20), Some(300)).is_empty(),
            "the first bucket began before the window, so only 10 count"
        );
    }

    #[test]
    fn distinct_items_count_once_however_often_they_were_seen() {
        let rows = [
            row("203.0.113.5", Item::seen("/a"), 1, 9, 50),
            seen("203.0.113.5", "/b", 2),
        ];
        assert!(decide(&rows, Rule::Distinct(3), None).is_empty());
        assert_eq!(decide(&rows, Rule::Distinct(2), None).len(), 1);
    }

    #[test]
    fn a_distinct_item_seen_last_before_the_window_does_not_count() {
        let rows = [
            seen("203.0.113.5", "/a", 100),
            seen("203.0.113.5", "/b", 200),
        ];
        assert!(decide(&rows, Rule::Distinct(2), Some(150)).is_empty());
    }

    #[test]
    fn a_clearing_observation_inside_the_window_clears_the_address() {
        let pages: Vec<Row> = (0..20)
            .map(|i| seen("203.0.113.5", &format!("/p{i}"), 100 + i))
            .collect();
        let mut rows = pages.clone();
        rows.push(row("203.0.113.5", Item::Clear, 50, 150, 1));
        assert!(decide(&rows, Rule::Distinct(15), Some(100)).is_empty());

        // The same asset fetch, before the window: no longer an alibi.
        let mut rows = pages;
        rows.push(row("203.0.113.5", Item::Clear, 50, 60, 1));
        assert_eq!(decide(&rows, Rule::Distinct(15), Some(100)).len(), 1);
    }

    #[test]
    fn one_line_inside_the_window_is_enough_and_names_the_earliest() {
        let rows = [
            seen("203.0.113.5", "/.git/config", 300),
            seen("203.0.113.5", "/.env", 200),
            seen("198.51.100.1", "/.env", 10),
        ];
        assert_eq!(
            decide(&rows, Rule::Once, Some(100)),
            [("203.0.113.5".to_string(), "/.env".to_string())]
        );
    }

    #[test]
    fn convictions_are_sorted_by_address() {
        let rows = [
            seen("203.0.113.5", "/.env", 1),
            seen("198.51.100.1", "/.env", 1),
        ];
        let found: Vec<String> = decide(&rows, Rule::Once, None)
            .into_iter()
            .map(|(address, _)| address)
            .collect();
        assert_eq!(found, ["198.51.100.1", "203.0.113.5"]);
    }

    #[test]
    fn collected_evidence_merges_repeats_into_one_row() {
        let mut evidence = Evidence::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        evidence.add(Detector::ProbePaths, ip, Item::seen("/.env"), 20);
        evidence.add(Detector::ProbePaths, ip, Item::seen("/.env"), 10);
        evidence.add(Detector::WebScanners, ip, Item::seen("/.env"), 10);

        let rows = evidence.rows_for(Detector::ProbePaths);
        assert_eq!(
            rows,
            [row("203.0.113.5", Item::seen("/.env"), 10, 20, 2)],
            "one row per detector, address and item"
        );
    }
}
