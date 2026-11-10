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
//! - **lines** ([`Rule::AtLeast`]): the SSH scanner counts failed logins,
//!   the login brute-force detector POSTs to a login page. Kept as
//!   ten-minute buckets ([`Item::Bucket`]), so a window can slide over
//!   them without keeping every line. Only buckets are counted; a seen
//!   item beside them (the login page posted to) only names the reason;
//! - **distinct things** ([`Rule::Distinct`]): paths that 404'd, pages,
//!   user agents. Each is one [`Item::Seen`] with the last time it was
//!   seen. Two of them also have a *clearing* observation ([`Item::Clear`]):
//!   one fetched asset, one sent referer, and the address is not a
//!   suspect for as long as that is inside the window;
//! - **one line is enough** ([`Rule::Once`]): a probe path, a payload, the
//!   honeypot. Or one line unless the address was also answered normally
//!   ([`Rule::OnceUnlessCleared`]): a request in another protocol.
//!
//! And two that are a little of each. One line after a warning
//! ([`Rule::AfterWarning`]): the robots.txt-violator detector, where a
//! request for a forbidden page counts only once the client has fetched
//! the robots.txt that forbids it ([`Item::Warned`]). And one that counts
//! lines two ways at once ([`Rule::Rate`]): the
//! request-rate detector, which counts every request in buckets and the
//! ones NGINX's own rate limit refused in buckets of their own
//! ([`Item::Refused`]), and acts on either.
//!
//! [`decide`] is the whole decision, and the same function serves the
//! evidence stored here and the evidence built in memory from a log given
//! whole, which is what the one-off CLI commands read. There is one
//! implementation of "what counts" per detector, not one per caller.

use crate::protection::Detector;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    /// A line counted into the bucket starting at this time that was also
    /// refused by a rate limit (a 429). Counted as a line too.
    Refused(i64),
    /// It was told the rules it is judged by: it fetched robots.txt.
    Warned,
}

impl Item {
    /// A seen item, truncated to [`MAX_ITEM_CHARS`], with every control
    /// character replaced (see [`Self::key`] for why).
    pub fn seen(text: &str) -> Item {
        let text = match text.char_indices().nth(MAX_ITEM_CHARS) {
            Some((at, _)) => &text[..at],
            None => text,
        };
        Item::Seen(crate::present::without_controls(text).into_owned())
    }

    /// The bucket `at` falls in.
    pub fn bucket(at: i64) -> Item {
        Item::Bucket(bucket_start(at))
    }

    /// The refused-lines bucket `at` falls in.
    pub fn refused(at: i64) -> Item {
        Item::Refused(bucket_start(at))
    }

    /// How this is stored. A leading newline marks the two kinds a client
    /// cannot spell, because a seen item's control characters are
    /// replaced, here as well as in [`Self::seen`].
    ///
    /// The replacing is what makes that true. A combined-format line
    /// cannot hold a newline, but a JSON one can: serde decodes `"\n"` in
    /// a user agent to a real one, and a user agent of `"\nclear"` stored
    /// as it came was read back as the observation that clears an address.
    pub fn key(&self) -> String {
        match self {
            Item::Seen(text) => crate::present::without_controls(text).into_owned(),
            Item::Clear => "\nclear".to_string(),
            Item::Bucket(start) => format!("\nbucket {start}"),
            Item::Refused(start) => format!("\nrefused {start}"),
            Item::Warned => "\nwarned".to_string(),
        }
    }

    pub fn from_key(key: &str) -> Item {
        if key == "\nclear" {
            return Item::Clear;
        }
        if key == "\nwarned" {
            return Item::Warned;
        }
        let start = |prefix: &str| key.strip_prefix(prefix)?.parse::<i64>().ok();
        if let Some(start) = start("\nbucket ") {
            Item::Bucket(start)
        } else if let Some(start) = start("\nrefused ") {
            Item::Refused(start)
        } else {
            Item::Seen(key.to_string())
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

/// The start of the bucket `at` falls in.
fn bucket_start(at: i64) -> i64 {
    at.div_euclid(BUCKET_SECONDS) * BUCKET_SECONDS
}

/// One stored or collected row: `address` saw `item`, `tally` times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub address: String,
    pub item: Item,
    pub tally: Tally,
}

/// What a block of `address` would cover, as one address: the address
/// itself for IPv4, and for IPv6 the first address of its `/64`.
///
/// A block is written for the `/64` (see
/// [`crate::scanblock::blockable_address`]), because that is what one
/// customer holds. Counting per `/128` while blocking per `/64` meant a
/// client that took a new address for every request never reached a
/// threshold: sixty addresses with six missing pages each were sixty
/// clients under the limit, not one far over it. Evidence is kept under
/// this, so the count and the block are about the same thing.
///
/// An IPv4-mapped address is its IPv4 address.
pub fn unit(address: IpAddr) -> IpAddr {
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        v4 => v4,
    }
}

/// Evidence collected in memory, from one read of a log.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    rows: HashMap<(Detector, IpAddr, Item), Tally>,
}

impl Evidence {
    /// Records `item` against the [`unit`] `address` is in, not against
    /// the address itself: what is counted is what would be blocked.
    pub fn add(&mut self, detector: Detector, address: IpAddr, item: Item, at: i64) {
        self.rows
            .entry((detector, unit(address), item))
            .and_modify(|tally| tally.merge(Tally::once(at)))
            .or_insert_with(|| Tally::once(at));
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Every row, given up for storing.
    pub fn into_rows(self) -> Vec<(Detector, String, Item, Tally)> {
        self.rows
            .into_iter()
            .map(|((detector, address, item), tally)| (detector, address.to_string(), item, tally))
            .collect()
    }

    /// Every row, for storing.
    pub fn iter(&self) -> impl Iterator<Item = (Detector, String, &Item, Tally)> + '_ {
        self.rows.iter().map(|((detector, address, item), tally)| {
            (*detector, address.to_string(), item, *tally)
        })
    }

    /// Drops `detector`'s clearing rows for every address it has nothing
    /// else against. For a detector that clears on an ordinary answer,
    /// that is nearly every visitor, and storing a row for each of them
    /// tripled the time a large log took to scan; one only matters beside
    /// something it clears.
    pub fn keep_clears_only_beside_suspicion(&mut self, detector: Detector) {
        let suspects: std::collections::HashSet<IpAddr> = self
            .rows
            .keys()
            .filter(|(d, _, item)| *d == detector && *item != Item::Clear)
            .map(|(_, address, _)| *address)
            .collect();
        self.rows.retain(|(d, address, item), _| {
            *d != detector || *item != Item::Clear || suspects.contains(address)
        });
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
    /// At least this many lines, counted from [`Item::Bucket`]s.
    AtLeast(usize),
    /// At least this many distinct items, and nothing that clears the
    /// address.
    Distinct(usize),
    /// [`Rule::Distinct`], or one page asked for at least `repeated`
    /// times, every time inside the window. For `web-scanners`, which
    /// counts distinct missing paths: a scanner that asks for the same one
    /// over and over never adds up to many. Only a page counts this way,
    /// never an asset or a well-known file (see
    /// [`crate::accesslog::is_page`]): a browser asks for a missing favicon
    /// with every page it shows, and a crawler for a missing robots.txt
    /// every time it comes back.
    DistinctOrRepeated { distinct: usize, repeated: u64 },
    /// One line.
    Once,
    /// One line, and nothing that clears the address. For
    /// `protocol-probes`: a client that also got an ordinary answer is one
    /// the site talks to, whatever else it sent, and a server that speaks
    /// plain HTTP where its visitors expect TLS is mistaken, not attacked.
    OnceUnlessCleared,
    /// At least `lines` lines, or at least `refused` of them refused by a
    /// rate limit, counted from [`Item::Bucket`]s and [`Item::Refused`]s.
    Rate { lines: usize, refused: usize },
    /// One line, seen at or after the first time the address was
    /// [`Item::Warned`].
    AfterWarning,
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
/// - a repeated item counts only if it was *first* seen inside the window.
///   Its count runs from then to the last time, and is only all inside the
///   window if its start is, so one asked for a few times a day for weeks
///   never adds up;
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
                    match row.item {
                        Item::Bucket(start) if inside(start) => lines += row.tally.count,
                        // What the lines were, for the report: the login
                        // page a brute-forcer posted to.
                        Item::Seen(_) if inside(row.tally.last) => note(&mut earliest, row),
                        _ => {}
                    }
                }
                lines >= threshold as u64
            }
            Rule::Distinct(threshold) => {
                !cleared(&rows, &inside) && distinct(&rows, &inside, &mut earliest) >= threshold
            }
            Rule::DistinctOrRepeated {
                distinct: threshold,
                repeated,
            } => {
                if cleared(&rows, &inside) {
                    false
                } else if distinct(&rows, &inside, &mut earliest) >= threshold {
                    true
                } else if let Some((page, times)) = repeated_page(&rows, &inside, repeated) {
                    // The count is the reason, as for a rate.
                    convicted.push((
                        address.to_string(),
                        format!("{page} asked for {times} times"),
                    ));
                    continue;
                } else {
                    false
                }
            }
            Rule::Rate {
                lines: most,
                refused: most_refused,
            } => {
                let (mut lines, mut refused) = (0u64, 0u64);
                for row in &rows {
                    match row.item {
                        Item::Bucket(start) if inside(start) => lines += row.tally.count,
                        Item::Refused(start) if inside(start) => {
                            lines += row.tally.count;
                            refused += row.tally.count;
                        }
                        _ => {}
                    }
                }
                // The count is the reason: there is no one line to name.
                let reason = if lines >= most as u64 {
                    Some(format!("{lines} requests"))
                } else if refused >= most_refused as u64 {
                    Some(format!("{refused} requests refused with 429"))
                } else {
                    None
                };
                match reason {
                    Some(reason) => {
                        convicted.push((address.to_string(), reason));
                        continue;
                    }
                    None => false,
                }
            }
            Rule::AfterWarning => {
                let warned = rows
                    .iter()
                    .filter(|row| row.item == Item::Warned && inside(row.tally.last))
                    .map(|row| row.tally.first)
                    .min();
                let mut any = false;
                if let Some(warned) = warned {
                    for row in &rows {
                        if matches!(row.item, Item::Seen(_))
                            && inside(row.tally.last)
                            && row.tally.last >= warned
                        {
                            any = true;
                            note(&mut earliest, row);
                        }
                    }
                }
                any
            }
            Rule::Once | Rule::OnceUnlessCleared => {
                if rule == Rule::OnceUnlessCleared && cleared(&rows, &inside) {
                    continue;
                }
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

/// How many times a detector's own threshold a `/24` has to reach,
/// added up over its addresses, to be convicted as one: see
/// [`decide_subnets`].
pub const SUBNET_FACTOR: usize = 2;

/// Every IPv4 `/24` that `rows` convict as a whole: at least
/// `min_addresses` of its addresses have evidence against them, and
/// together they reach [`SUBNET_FACTOR`] times what `rule` asks of one.
/// Each comes back as `a.b.c.0/24` with the earliest thing seen from it.
///
/// What [`decide`] cannot see. It judges an address at a time, so forty
/// addresses of one network asking for six missing pages each, 240 in
/// all, were forty clients each under a limit of seven. A scan spread
/// over a subnet the scanner holds is the same scan; this adds it up.
///
/// Twice the threshold, from several addresses, and only for the rules
/// that count (never for one that acts on a single line: a `/24` is not
/// blocked for one address's one request). Blocking 256 addresses is
/// collateral by design, which is why the caller asks only where the
/// operator switched subnet escalation on.
pub fn decide_subnets(
    rows: &[Row],
    rule: Rule,
    cutoff: Option<i64>,
    min_addresses: usize,
) -> Vec<(String, String)> {
    let rule = match rule {
        Rule::AtLeast(n) => Rule::AtLeast(n.saturating_mul(SUBNET_FACTOR)),
        Rule::Distinct(n) | Rule::DistinctOrRepeated { distinct: n, .. } => {
            Rule::Distinct(n.saturating_mul(SUBNET_FACTOR))
        }
        Rule::Once | Rule::OnceUnlessCleared | Rule::Rate { .. } | Rule::AfterWarning => {
            return Vec::new();
        }
    };
    let inside = |at: i64| cutoff.is_none_or(|c| at >= c);
    // Per /24: who was seen, and each item once with its tallies merged,
    // so that one page asked for from ten addresses is one distinct page.
    type Subnet<'a> = (BTreeSet<&'a str>, HashMap<&'a Item, Tally>);
    let mut subnets: BTreeMap<[u8; 3], Subnet> = BTreeMap::new();
    for row in rows {
        let Ok(IpAddr::V4(v4)) = row.address.parse::<IpAddr>() else {
            continue;
        };
        if !inside(row.tally.last) {
            continue;
        }
        let [a, b, c, _] = v4.octets();
        let (addresses, items) = subnets.entry([a, b, c]).or_default();
        if row.item != Item::Clear {
            addresses.insert(row.address.as_str());
        }
        items
            .entry(&row.item)
            .and_modify(|tally| tally.merge(row.tally))
            .or_insert(row.tally);
    }
    let mut convicted = Vec::new();
    for ([a, b, c], (addresses, items)) in subnets {
        if addresses.len() < min_addresses.max(2) {
            continue;
        }
        let subnet = format!("{a}.{b}.{c}.0/24");
        let merged: Vec<Row> = items
            .into_iter()
            .map(|(item, tally)| Row {
                address: subnet.clone(),
                item: item.clone(),
                tally,
            })
            .collect();
        for (subnet, reason) in decide(&merged, rule, cutoff) {
            let from = format!("from {} addresses", addresses.len());
            convicted.push((
                subnet,
                if reason.is_empty() {
                    from
                } else {
                    format!("{reason} ({from})")
                },
            ));
        }
    }
    convicted
}

/// Whether something inside the window clears the address.
fn cleared(rows: &[&Row], inside: &impl Fn(i64) -> bool) -> bool {
    rows.iter()
        .any(|row| row.item == Item::Clear && inside(row.tally.last))
}

/// How many distinct items were seen inside the window, noting the
/// earliest of them in `earliest`.
fn distinct<'a>(
    rows: &[&'a Row],
    inside: &impl Fn(i64) -> bool,
    earliest: &mut Option<(i64, &'a str)>,
) -> usize {
    let mut count = 0;
    for row in rows {
        if matches!(row.item, Item::Seen(_)) && inside(row.tally.last) {
            count += 1;
            note(earliest, row);
        }
    }
    count
}

/// The page asked for most, if it was asked for at least `repeated` times,
/// all of them inside the window: see [`Rule::DistinctOrRepeated`].
fn repeated_page<'a>(
    rows: &[&'a Row],
    inside: &impl Fn(i64) -> bool,
    repeated: u64,
) -> Option<(&'a str, u64)> {
    rows.iter()
        .filter_map(|row| match &row.item {
            Item::Seen(page)
                if inside(row.tally.first)
                    && row.tally.count >= repeated
                    && crate::accesslog::is_page(page) =>
            {
                Some((page.as_str(), row.tally.count))
            }
            _ => None,
        })
        .max_by_key(|(page, times)| (*times, std::cmp::Reverse(*page)))
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

    /// Forty addresses of one network, six missing pages each: nobody
    /// over the limit of seven, and 240 requests for what is not there.
    #[test]
    fn a_scan_spread_over_a_subnet_convicts_the_subnet() {
        let rule = Rule::DistinctOrRepeated {
            distinct: 7,
            repeated: 50,
        };
        let rows: Vec<Row> = (1..=40)
            .flat_map(|host| {
                (0..6)
                    .map(move |n| seen(&format!("203.0.113.{host}"), &format!("/p{host}-{n}"), 10))
            })
            .collect();

        assert_eq!(decide(&rows, rule, None), Vec::new(), "none alone");
        let subnets = decide_subnets(&rows, rule, None, 3);
        assert_eq!(subnets.len(), 1, "{subnets:?}");
        assert_eq!(subnets[0].0, "203.0.113.0/24");
        assert!(subnets[0].1.contains("from 40 addresses"), "{subnets:?}");
    }

    #[test]
    fn a_subnet_is_not_convicted_by_too_few_addresses_or_too_little() {
        let rule = Rule::Distinct(7);
        let from = |hosts: std::ops::RangeInclusive<u8>, each: usize| -> Vec<Row> {
            hosts
                .flat_map(|host| {
                    (0..each).map(move |n| {
                        seen(&format!("203.0.113.{host}"), &format!("/p{host}-{n}"), 10)
                    })
                })
                .collect()
        };
        let cases = [
            ("two addresses where three are asked for", from(1..=2, 6), 3),
            ("three addresses, under twice the limit", from(1..=3, 4), 3),
            (
                "the same page from every address is one page",
                {
                    (1..=30)
                        .map(|host| seen(&format!("203.0.113.{host}"), "/same", 10))
                        .collect()
                },
                3,
            ),
        ];
        for (what, rows, min) in cases {
            assert_eq!(decide_subnets(&rows, rule, None, min), Vec::new(), "{what}");
        }
        let one_line = from(1..=30, 1);
        assert_eq!(
            decide_subnets(&one_line, Rule::Once, None, 3),
            Vec::new(),
            "a rule that acts on one line never widens"
        );
    }

    #[test]
    fn an_item_round_trips_through_its_stored_form() {
        for item in [
            Item::seen("/wp-login.php"),
            Item::Clear,
            Item::bucket(1_790_577_181),
            Item::refused(1_790_577_181),
            Item::Warned,
            Item::seen("\nwarned"),
            Item::seen("\nrefused nonsense"),
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

    const REPEATED: Rule = Rule::DistinctOrRepeated {
        distinct: 7,
        repeated: 50,
    };

    #[test]
    fn one_page_asked_for_often_enough_inside_the_window_convicts_and_is_named() {
        let rows = [row(
            "203.0.113.5",
            Item::seen("/SDK/webLanguage"),
            100,
            900,
            50,
        )];

        assert_eq!(
            decide(&rows, REPEATED, Some(100)),
            [(
                "203.0.113.5".to_string(),
                "/SDK/webLanguage asked for 50 times".to_string()
            )]
        );
    }

    /// Its count runs from its first sighting, so one that began before the
    /// window may have most of its count from outside it.
    #[test]
    fn a_page_first_asked_for_before_the_window_is_not_counted_as_repeated() {
        let rows = [row(
            "203.0.113.5",
            Item::seen("/SDK/webLanguage"),
            50,
            900,
            500,
        )];

        assert_eq!(decide(&rows, REPEATED, Some(100)), Vec::new());
    }

    #[test]
    fn an_asset_asked_for_over_and_over_is_not_counted_as_repeated() {
        let rows = [row(
            "203.0.113.5",
            Item::seen("/favicon.ico"),
            100,
            900,
            500,
        )];

        assert_eq!(decide(&rows, REPEATED, Some(100)), Vec::new());
    }

    /// A brute-forcer's buckets count its POSTs; the page it posted to
    /// rides along to name the reason, and counts for nothing itself.
    #[test]
    fn a_line_count_is_named_by_its_seen_item_without_counting_it() {
        let rows = [
            row("203.0.113.5", Item::Bucket(600), 600, 700, 19),
            row("203.0.113.5", Item::seen("/wp-login.php"), 600, 700, 19),
        ];
        assert!(
            decide(&rows, Rule::AtLeast(20), None).is_empty(),
            "19 lines, whatever the seen item's tally says"
        );
        assert_eq!(
            decide(&rows, Rule::AtLeast(19), None),
            [("203.0.113.5".to_string(), "/wp-login.php".to_string())]
        );
    }

    #[test]
    fn a_rate_convicts_on_requests_or_on_refusals_and_says_which() {
        let cases = [
            ("enough requests", 60, 0, Some("60 requests")),
            ("refusals count as requests", 30, 30, Some("60 requests")),
            (
                "enough refusals",
                0,
                10,
                Some("10 requests refused with 429"),
            ),
            ("neither", 40, 9, None),
        ];
        for (what, served, refused, expected) in cases {
            let rows = [
                row("203.0.113.5", Item::Bucket(600), 600, 700, served),
                row("203.0.113.5", Item::Refused(600), 600, 700, refused),
            ];
            let found = decide(
                &rows,
                Rule::Rate {
                    lines: 60,
                    refused: 10,
                },
                None,
            );
            let reason = found.first().map(|(_, reason)| reason.as_str());
            assert_eq!(reason, expected, "{what}");
        }
    }

    #[test]
    fn a_rate_counts_only_buckets_that_began_inside_the_window() {
        let rows = [
            row("203.0.113.5", Item::Bucket(0), 10, 500, 50),
            row("203.0.113.5", Item::Refused(0), 10, 500, 50),
            row("203.0.113.5", Item::Bucket(600), 600, 700, 10),
        ];
        let rule = Rule::Rate {
            lines: 20,
            refused: 20,
        };
        assert_eq!(decide(&rows, rule, None).len(), 1, "110 in all");
        assert!(decide(&rows, rule, Some(300)).is_empty(), "10 inside");
    }

    /// A forbidden page fetched before robots.txt was read may be a guess;
    /// after it, it is defiance.
    #[test]
    fn a_line_after_a_warning_counts_and_one_before_it_does_not() {
        let warned = |at| row("203.0.113.5", Item::Warned, at, at, 1);
        let cases = [
            (
                "after",
                vec![warned(100), seen("203.0.113.5", "/trap/", 200)],
                true,
            ),
            (
                "before",
                vec![seen("203.0.113.5", "/trap/", 50), warned(100)],
                false,
            ),
            (
                "never warned",
                vec![seen("203.0.113.5", "/trap/", 200)],
                false,
            ),
            ("warned and nothing more", vec![warned(100)], false),
        ];
        for (what, rows, expected) in cases {
            let found = decide(&rows, Rule::AfterWarning, None);
            assert_eq!(!found.is_empty(), expected, "{what}: {found:?}");
        }
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
    fn one_line_convicts_unless_the_address_was_cleared_inside_the_window() {
        let probe = seen("203.0.113.5", "tls handshake", 200);
        let cases = [
            ("no clearing", None, true),
            ("cleared inside the window", Some(150), false),
            ("cleared before it", Some(60), true),
        ];
        for (what, cleared_at, convicted) in cases {
            let mut rows = vec![probe.clone()];
            rows.extend(cleared_at.map(|at| row("203.0.113.5", Item::Clear, 50, at, 1)));
            assert_eq!(
                decide(&rows, Rule::OnceUnlessCleared, Some(100)).len(),
                usize::from(convicted),
                "{what}"
            );
        }
    }

    /// A visitor's clearing row is dropped; a suspect's is kept, and so
    /// is every other detector's.
    #[test]
    fn only_a_clearing_row_beside_suspicion_is_kept() {
        let mut evidence = Evidence::default();
        let (visitor, suspect): (IpAddr, IpAddr) = (
            "198.51.100.1".parse().unwrap(),
            "203.0.113.5".parse().unwrap(),
        );
        let probes = Detector::ProtocolProbes;
        evidence.add(probes, visitor, Item::Clear, 10);
        evidence.add(probes, suspect, Item::Clear, 10);
        evidence.add(probes, suspect, Item::seen("tls handshake"), 10);
        evidence.add(Detector::AssetRatio, visitor, Item::Clear, 10);

        evidence.keep_clears_only_beside_suspicion(probes);

        let mut kept: Vec<(Detector, String, Item)> = evidence
            .into_rows()
            .into_iter()
            .map(|(detector, address, item, _)| (detector, address, item))
            .collect();
        kept.sort_by_key(|(detector, address, item)| (detector.id(), address.clone(), item.key()));
        assert_eq!(
            kept,
            [
                (Detector::AssetRatio, visitor.to_string(), Item::Clear),
                (probes, suspect.to_string(), Item::Clear),
                (probes, suspect.to_string(), Item::seen("tls handshake")),
            ]
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
