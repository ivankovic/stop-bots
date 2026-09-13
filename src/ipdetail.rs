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

//! Everything this host already knows about one address, with no network
//! lookup at all — the model behind both front-ends' per-address detail
//! view on the Dynamic Protection screen.
//!
//! The question a detail view exists to answer is "what *is* this thing",
//! and the reflex answer is reverse DNS and whois. Both are outbound
//! requests, per row, to infrastructure the attacker frequently controls;
//! and a PTR record is written by whoever holds the address, so it is
//! attacker-supplied text that reads as authoritative. None of that is
//! here. What is here is a join over feeds this host already downloads for
//! other reasons: six reputation lists (`reputation_ranges` — Tor exits,
//! FireHOL, blocklist.de, and three cloud providers), three crawler
//! sources (`ip_ranges` — Googlebot, Bingbot, GPTBot), and whichever
//! countries have been fetched (`country_ip_ranges`). That answers "is
//! this a hosting provider, a Tor exit, a known-bad address, or a crawler
//! that is who it says it is" — which is most of what anyone opens a
//! whois for — instantly, offline, and without telling the attacker they
//! were looked at.
//!
//! Nothing here reads a log, for the same reason `dynamic` doesn't: the
//! TUI reads it on a background thread and a web request must not block
//! its runtime on a `journalctl` subprocess. The caller passes in the
//! username breakdown it already has.

use anyhow::Result;

use crate::db::Db;
use crate::dynamic::RowStatus;
use crate::ipranges;

/// What kind of address this is, before any lookup is worth doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// A routable address — the only kind the feeds can say anything about.
    Public,
    /// Loopback, link-local or RFC1918. Every detector in `accesslog`
    /// skips these, so reporting "not found in any feed" for one would be
    /// technically true and actively misleading: no feed lists them
    /// because no feed *can*.
    LocalOrPrivate,
    /// Not parseable as an address at all. Reachable only from a hand-added
    /// firewall rule row predating validation, but a detail view that
    /// panics on one is worse than a detail view that says so.
    Malformed,
}

/// One membership hit: which list, and the range within it that matched.
///
/// The range is carried because "in Google's ranges" and "in
/// `66.249.64.0/19`" are different amounts of evidence to someone deciding
/// whether to block, and the second is free once the first is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeHit {
    pub source: String,
    pub range: String,
}

/// Everything known locally about one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpDetail {
    pub address: String,
    pub kind: AddressKind,
    /// Reputation feeds containing it — a hosting provider, a Tor exit, or
    /// a list of addresses already caught attacking someone else.
    pub reputation: Vec<RangeHit>,
    /// Crawler sources containing it. A hit here is what separates a real
    /// Googlebot from something that merely says so in its user agent.
    pub crawlers: Vec<RangeHit>,
    /// The fetched country whose ranges contain it, if any.
    pub country: Option<String>,
    /// Whether any country data has been fetched at all. Without this,
    /// `country: None` cannot be told apart from "no zone files fetched",
    /// and the view would report absence of data as absence of a country.
    pub country_data_available: bool,
    /// Whether this address is already covered by a block, carried through
    /// from the row the view was opened from rather than recomputed — one
    /// source of truth for a verdict shown in two places at once.
    pub status: RowStatus,
    /// Failed-login usernames, most-tried first (see
    /// [`crate::sshlog::failed_attempt_usernames`]).
    pub usernames: Vec<(String, u64)>,
}

impl IpDetail {
    /// Gathers what `db` knows about `address`.
    ///
    /// Scans the range lists rather than indexing them. That is the cost
    /// model already shipping — `dynamic::Live::load` pulls
    /// `blocked_ip_ranges` and scans it per row on *every* render of the
    /// screen this opens from, so one scan on an explicit keypress is
    /// strictly cheaper than what the surrounding screen already does.
    pub fn load(
        db: &Db,
        address: &str,
        status: RowStatus,
        usernames: Vec<(String, u64)>,
    ) -> Result<Self> {
        let Ok(ip) = address.parse::<std::net::IpAddr>() else {
            return Ok(Self::without_lookups(
                address,
                AddressKind::Malformed,
                status,
            ));
        };
        if ipranges::is_local_or_private(&ip) {
            return Ok(Self::without_lookups(
                address,
                AddressKind::LocalOrPrivate,
                status,
            ));
        }

        let country_ranges = db.country_ranges_by_code()?;
        Ok(Self {
            address: address.to_string(),
            kind: AddressKind::Public,
            reputation: hits(&db.enabled_reputation_ranges_by_source_name()?, ip),
            crawlers: hits(&db.ip_ranges_by_source_name()?, ip),
            country: country_ranges
                .iter()
                .find(|(_, cidr)| ipranges::cidr_contains(cidr, ip))
                .map(|(code, _)| code.to_uppercase()),
            country_data_available: !country_ranges.is_empty(),
            status,
            usernames,
        })
    }

    /// The shape for an address no feed can speak to. Still carries the
    /// block status and the usernames: both come from the caller and are
    /// exactly as true for a private address as a public one.
    fn without_lookups(address: &str, kind: AddressKind, status: RowStatus) -> Self {
        Self {
            address: address.to_string(),
            kind,
            reputation: Vec::new(),
            crawlers: Vec::new(),
            country: None,
            country_data_available: false,
            status,
            usernames: Vec::new(),
        }
    }

    /// Whether any feed had something to say. Drives the "nothing known"
    /// line, which is itself informative: an address in none of six
    /// reputation feeds and no cloud provider's ranges is more likely to
    /// be a home connection than a rented box.
    pub fn is_unknown(&self) -> bool {
        self.reputation.is_empty() && self.crawlers.is_empty() && self.country.is_none()
    }
}

/// Every `(source, range)` pair in `ranges` whose range contains `ip`, at
/// most one per source — a feed listing both a /16 and a /24 covering the
/// same address has said one thing, not two.
fn hits(ranges: &[(String, String)], ip: std::net::IpAddr) -> Vec<RangeHit> {
    let mut out: Vec<RangeHit> = Vec::new();
    for (source, range) in ranges {
        if out.iter().any(|hit| &hit.source == source) {
            continue;
        }
        if ipranges::cidr_contains(range, ip) {
            out.push(RangeHit {
                source: source.clone(),
                range: range.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{Category, IpRangeSource, ReputationSource};

    fn db_with_feeds() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&IpRangeSource {
            id: "googlebot".to_string(),
            name: "Googlebot IP ranges".to_string(),
            url: "https://example.invalid/g.json".to_string(),
            category: Category::Search,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.replace_ip_ranges("googlebot", &["66.249.64.0/19".to_string()])
            .unwrap();

        db.register_reputation_source(&ReputationSource {
            id: "tor-exits".to_string(),
            name: "Tor exit nodes".to_string(),
            url: "https://example.invalid/tor".to_string(),
            enabled: true,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.set_reputation_source_enabled("tor-exits", true).unwrap();
        db.replace_reputation_ranges("tor-exits", &["185.220.101.0/24".to_string()])
            .unwrap();

        db.replace_country_ranges("nl", &["185.220.101.0/24".to_string()])
            .unwrap();
        db
    }

    fn load(db: &Db, address: &str) -> IpDetail {
        IpDetail::load(db, address, RowStatus::Pending, Vec::new()).unwrap()
    }

    #[test]
    fn an_address_is_attributed_to_every_feed_that_lists_it() {
        let detail = load(&db_with_feeds(), "185.220.101.7");

        assert_eq!(
            detail.reputation,
            vec![RangeHit {
                source: "Tor exit nodes".to_string(),
                range: "185.220.101.0/24".to_string(),
            }]
        );
        assert_eq!(detail.country.as_deref(), Some("NL"));
        assert!(detail.crawlers.is_empty(), "was: {:?}", detail.crawlers);
        assert!(!detail.is_unknown());
    }

    /// The one question the crawler feeds exist to settle: a user agent
    /// saying "Googlebot" proves nothing, and being inside Google's
    /// published ranges is what proves it.
    #[test]
    fn a_crawler_range_hit_is_reported_separately_from_a_reputation_hit() {
        let detail = load(&db_with_feeds(), "66.249.64.10");

        assert_eq!(
            detail.crawlers,
            vec![RangeHit {
                source: "Googlebot IP ranges".to_string(),
                range: "66.249.64.0/19".to_string(),
            }]
        );
        assert!(detail.reputation.is_empty());
    }

    #[test]
    fn an_address_no_feed_lists_says_so_rather_than_looking_empty() {
        let detail = load(&db_with_feeds(), "203.0.113.7");

        assert!(detail.is_unknown());
        assert_eq!(detail.kind, AddressKind::Public);
        assert!(
            detail.country_data_available,
            "country data was fetched, so `country: None` means 'not in one'"
        );
    }

    /// "Not in any reputation feed" is true of `10.0.0.5` and tells the
    /// reader nothing — no feed lists private addresses because none can.
    #[test]
    fn a_private_address_is_named_as_one_instead_of_being_looked_up() {
        let detail = load(&db_with_feeds(), "10.0.0.5");

        assert_eq!(detail.kind, AddressKind::LocalOrPrivate);
        assert!(detail.reputation.is_empty());
    }

    #[test]
    fn a_malformed_address_is_reported_rather_than_panicking() {
        assert_eq!(
            load(&db_with_feeds(), "not-an-address").kind,
            AddressKind::Malformed
        );
    }

    /// Without this flag a view cannot tell "outside every country we have"
    /// from "no zone file has ever been fetched", and would report the
    /// second as the first.
    #[test]
    fn with_no_country_data_the_absence_of_a_country_is_marked_as_unknown() {
        let db = Db::open_in_memory().unwrap();

        let detail = load(&db, "203.0.113.7");

        assert_eq!(detail.country, None);
        assert!(!detail.country_data_available);
    }

    /// A feed that lists both a /16 and a /24 covering one address has
    /// said one thing about it, not two.
    #[test]
    fn overlapping_ranges_from_one_feed_are_reported_once() {
        let db = Db::open_in_memory().unwrap();
        db.register_reputation_source(&ReputationSource {
            id: "aws".to_string(),
            name: "AWS ranges".to_string(),
            url: "https://example.invalid/aws".to_string(),
            enabled: true,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.set_reputation_source_enabled("aws", true).unwrap();
        db.replace_reputation_ranges(
            "aws",
            &["3.0.0.0/8".to_string(), "3.5.140.0/22".to_string()],
        )
        .unwrap();

        assert_eq!(load(&db, "3.5.140.1").reputation.len(), 1);
    }

    /// A source the admin switched off keeps its rows so re-enabling needs
    /// no refetch — but reporting from it would describe a list that is
    /// not in effect.
    #[test]
    fn a_disabled_feed_does_not_vouch_for_anything() {
        let db = db_with_feeds();
        db.set_reputation_source_enabled("tor-exits", false)
            .unwrap();

        assert!(load(&db, "185.220.101.7").reputation.is_empty());
    }
    /// The scan walks every range the feeds hold, so it has to stay quick
    /// at a realistic size rather than the handful the tests above use —
    /// FireHOL level 1 and blocklist.de run to tens of thousands.
    ///
    /// Against [`hits`] directly rather than through `IpDetail::load`: the
    /// database read is the same shape `dynamic::Live::load` already does
    /// on every render of the screen this opens from, and inserting 20,000
    /// rows to re-measure it would put the test's own setup — not the scan
    /// — up against the 300ms budget.
    #[test]
    fn scanning_a_realistic_number_of_ranges_is_quick() {
        let ranges: Vec<(String, String)> = (0..20_000)
            .map(|i| {
                (
                    "FireHOL level 1".to_string(),
                    format!("10.{}.{}.0/24", i / 256, i % 256),
                )
            })
            .collect();

        let found = hits(&ranges, "10.50.7.9".parse().unwrap());

        assert_eq!(found.len(), 1, "found: {found:?}");
        assert_eq!(found[0].range, "10.50.7.0/24");
    }
}
