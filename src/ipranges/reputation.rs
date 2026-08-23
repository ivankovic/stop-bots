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

//! Third-party CIDR feeds: abuse/reputation lists, and cloud providers'
//! published address space. Structurally the same fetch → parse → store →
//! derive-a-Block-rule path the IPdeny country lists already use, just
//! with a per-source on/off switch instead of a country selection.
//!
//! **Kept strictly apart from [`super::IpRangeSourceKind`]**, which is the
//! *crawler* range list (Googlebot/Bingbot/GPTBot). Two reasons, and both
//! would be silent bugs rather than compile errors:
//!
//! 1. `Db::blocked_ip_ranges` decides whether an `ip_range_sources` row
//!    applies by looking up its **bot category**'s default. A reputation
//!    feed has no bot category, and giving it a borrowed one would tie
//!    "block Spamhaus-listed addresses" to "block AI crawlers".
//! 2. `scanblock::known_crawler_ranges` iterates `IpRangeSourceKind::ALL`
//!    to build the *exemption* list for web-scanner detection. A feed
//!    added there would start **exempting** known-abusive addresses from
//!    being flagged — the exact opposite of the intent.
//!
//! **Every feed is off by default.** These block by address with no
//! behavioural evidence at all, so a false positive is invisible: the
//! visitor simply can't reach the site and nothing in any log says why.
//! The cloud-provider feeds are the sharpest edge — see
//! [`ReputationSourceKind::warning`].
//!
//! **Why no Spamhaus DROP entry**, despite it being the obvious name to
//! reach for: Spamhaus has moved its published format more than once
//! (the classic `drop.txt` is deprecated in favour of a JSON endpoint),
//! and FireHOL level 1 already *includes* DROP alongside several other
//! lists in one stable plain-text format. One well-maintained aggregate
//! beats three parsers chasing three upstreams.

use crate::db::{Db, ReputationSource};
use anyhow::{Context, Result};
use serde::Deserialize;

/// One built-in third-party feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationSourceKind {
    /// FireHOL's level-1 aggregate: Spamhaus DROP/EDROP, Team Cymru's
    /// bogons, and other lists its maintainers consider safe enough to
    /// block outright with no false positives expected.
    FireholLevel1,
    /// Current Tor exit nodes.
    TorExits,
    /// blocklist.de: addresses reported for SSH/mail/web attacks in the
    /// last 48 hours.
    BlocklistDe,
    /// Amazon Web Services' published address space.
    Aws,
    /// Google Cloud's published address space (not Google's crawlers —
    /// those are `IpRangeSourceKind::GoogleBot`, and blocking this feed
    /// does **not** block Googlebot).
    GoogleCloud,
    /// DigitalOcean's published address space.
    DigitalOcean,
}

impl ReputationSourceKind {
    pub const ALL: [ReputationSourceKind; 6] = [
        ReputationSourceKind::FireholLevel1,
        ReputationSourceKind::TorExits,
        ReputationSourceKind::BlocklistDe,
        ReputationSourceKind::Aws,
        ReputationSourceKind::GoogleCloud,
        ReputationSourceKind::DigitalOcean,
    ];

    /// Stable across releases — it's a `reputation_sources` primary key.
    pub fn id(self) -> &'static str {
        match self {
            ReputationSourceKind::FireholLevel1 => "firehol-level1",
            ReputationSourceKind::TorExits => "tor-exits",
            ReputationSourceKind::BlocklistDe => "blocklist-de",
            ReputationSourceKind::Aws => "aws",
            ReputationSourceKind::GoogleCloud => "google-cloud",
            ReputationSourceKind::DigitalOcean => "digitalocean",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ReputationSourceKind::FireholLevel1 => "FireHOL level 1",
            ReputationSourceKind::TorExits => "Tor exit nodes",
            ReputationSourceKind::BlocklistDe => "blocklist.de",
            ReputationSourceKind::Aws => "AWS ranges",
            ReputationSourceKind::GoogleCloud => "Google Cloud ranges",
            ReputationSourceKind::DigitalOcean => "DigitalOcean ranges",
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            ReputationSourceKind::FireholLevel1 => {
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
            }
            ReputationSourceKind::TorExits => "https://check.torproject.org/torbulkexitlist",
            ReputationSourceKind::BlocklistDe => "https://lists.blocklist.de/lists/all.txt",
            ReputationSourceKind::Aws => "https://ip-ranges.amazonaws.com/ip-ranges.json",
            ReputationSourceKind::GoogleCloud => "https://www.gstatic.com/ipranges/cloud.json",
            ReputationSourceKind::DigitalOcean => "https://digitalocean.com/geo/google.csv",
        }
    }

    /// Whether this feed blocks *infrastructure* rather than *behaviour* —
    /// i.e. whether switching it on will also block legitimate visitors.
    ///
    /// This is the honest distinction between the two halves of the list,
    /// and it's surfaced in the UI rather than buried here. An abuse list
    /// names addresses that did something; a cloud-provider list names
    /// every address a provider owns, which includes every VPN endpoint,
    /// corporate egress, CI runner and API integration hosted there. Real
    /// people browse from AWS IPs.
    pub fn blocks_infrastructure(self) -> bool {
        matches!(
            self,
            ReputationSourceKind::Aws
                | ReputationSourceKind::GoogleCloud
                | ReputationSourceKind::DigitalOcean
        )
    }

    /// A one-line caution shown next to the more dangerous feeds, or
    /// `None` for the abuse lists.
    pub fn warning(self) -> Option<&'static str> {
        self.blocks_infrastructure().then_some(
            "blocks every visitor hosted there, not just bots — including VPNs and API clients",
        )
    }

    pub fn from_id(id: &str) -> Option<ReputationSourceKind> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// Each upstream publishes a different shape; see the individual
    /// parsers for what each one looks like.
    pub fn parse(self, raw: &str) -> Result<Vec<String>> {
        match self {
            ReputationSourceKind::FireholLevel1
            | ReputationSourceKind::TorExits
            | ReputationSourceKind::BlocklistDe => Ok(parse_plain_list(raw)),
            ReputationSourceKind::Aws => parse_aws_json(raw),
            ReputationSourceKind::GoogleCloud => super::parse_prefixes_json(raw),
            ReputationSourceKind::DigitalOcean => Ok(parse_csv_first_column(raw)),
        }
    }

    pub async fn fetch(self) -> Result<String> {
        let body = reqwest::get(self.url())
            .await
            .with_context(|| format!("failed to fetch {}", self.name()))?
            .error_for_status()
            .with_context(|| format!("{} request failed", self.name()))?
            .text()
            .await
            .with_context(|| format!("failed to read {} response body", self.name()))?;
        Ok(body)
    }

    pub fn as_source(self) -> ReputationSource {
        ReputationSource {
            id: self.id().to_string(),
            name: self.name().to_string(),
            url: self.url().to_string(),
            enabled: false,
            last_fetched_at: None,
            range_count: 0,
        }
    }
}

/// One entry per line, with `#` and `;` comments and blank lines dropped.
/// Covers FireHOL's `.netset` (CIDRs), Tor's bulk exit list (bare IPs) and
/// blocklist.de's `all.txt` (bare IPs). Bare addresses are kept verbatim
/// rather than being given an explicit `/32`: `ipranges::cidr_contains`
/// already treats an address with no prefix as an exact match, and both
/// firewall backends accept a bare address, so normalising here would only
/// add a way to get IPv4/IPv6 prefix lengths wrong.
///
/// Anything that isn't plausibly an address is dropped rather than stored:
/// these feeds are fetched unattended, and a stray line that reached a
/// generated firewall script would make the whole script fail to apply —
/// taking every *other* rule down with it.
fn parse_plain_list(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|line| {
            let line = line.split('#').next().unwrap_or("");
            let line = line.split(';').next().unwrap_or("");
            line.trim()
        })
        .filter(|line| !line.is_empty())
        .filter(|line| looks_like_address(line))
        .map(str::to_string)
        .collect()
}

/// A cheap sanity check, not a validator: the address is only ever
/// re-emitted into a firewall script, and both backends do their own
/// parsing. This exists to keep obvious junk (a stray HTML error page
/// served instead of the list, a header line) out of the database.
fn looks_like_address(s: &str) -> bool {
    let base = s.split('/').next().unwrap_or(s);
    !base.is_empty()
        && base
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
        && (base.contains('.') || base.contains(':'))
}

#[derive(Debug, Deserialize)]
struct AwsDoc {
    #[serde(default)]
    prefixes: Vec<AwsV4Prefix>,
    #[serde(default, rename = "ipv6_prefixes")]
    ipv6_prefixes: Vec<AwsV6Prefix>,
}

#[derive(Debug, Deserialize)]
struct AwsV4Prefix {
    ip_prefix: String,
}

#[derive(Debug, Deserialize)]
struct AwsV6Prefix {
    ipv6_prefix: String,
}

/// AWS publishes IPv4 and IPv6 under two differently-named keys with two
/// differently-named fields, unlike the `{"prefixes":[{"ipv4Prefix"...}]}`
/// shape Google and OpenAI share — hence its own parser rather than a
/// reuse of `super::parse_prefixes_json`.
fn parse_aws_json(raw: &str) -> Result<Vec<String>> {
    let doc: AwsDoc = serde_json::from_str(raw).context("failed to parse AWS ip-ranges.json")?;
    let mut cidrs: Vec<String> = doc.prefixes.into_iter().map(|p| p.ip_prefix).collect();
    cidrs.extend(doc.ipv6_prefixes.into_iter().map(|p| p.ipv6_prefix));
    cidrs.sort();
    cidrs.dedup();
    Ok(cidrs)
}

/// DigitalOcean publishes a headerless CSV whose first column is the CIDR
/// and whose remaining columns are geo metadata this project has no use
/// for.
fn parse_csv_first_column(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|line| line.split(',').next().unwrap_or("").trim())
        .filter(|field| !field.is_empty())
        .filter(|field| looks_like_address(field))
        .map(str::to_string)
        .collect()
}

/// Registers every built-in feed that isn't already known, without
/// touching an existing row — so this can run on every startup without
/// resetting an admin's enabled flags.
pub fn register_all_reputation_sources(db: &Db) -> Result<()> {
    // One transaction, not six: this runs on every single TUI startup, and
    // an autocommit per source is an fsync per source for writes that are
    // almost always no-ops.
    db.batch(|| {
        for kind in ReputationSourceKind::ALL {
            db.register_reputation_source(&kind.as_source())?;
        }
        Ok(())
    })
}

/// Stores `cidrs` under `kind`, registering the source first if needed.
pub fn store(db: &Db, kind: ReputationSourceKind, cidrs: &[String]) -> Result<usize> {
    db.register_reputation_source(&kind.as_source())?;
    db.replace_reputation_ranges(kind.id(), cidrs)
}

/// Fetches `kind` over the network, parses it and stores it. Does **not**
/// enable the source: fetching and switching on are separate steps
/// everywhere, so refreshing a feed you've deliberately switched off never
/// silently turns it back on.
pub async fn update(db: &Db, kind: ReputationSourceKind) -> Result<usize> {
    let raw = kind
        .fetch()
        .await
        .with_context(|| format!("failed to update {}", kind.name()))?;
    let cidrs = kind.parse(&raw)?;
    if cidrs.is_empty() {
        // An empty parse almost always means the upstream format moved or
        // an error page was served, not that the list is genuinely empty.
        // Storing it would silently un-block everything the feed covered.
        anyhow::bail!(
            "{} returned no usable addresses — the upstream format may have changed; \
             keeping the previously stored ranges",
            kind.name()
        );
    }
    store(db, kind, &cidrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_list_reads_cidrs_and_bare_ips_ignoring_comments() {
        let raw = "# FireHOL level 1\n\
                   1.2.3.0/24\n\
                   \n\
                   4.5.6.7\n\
                   5.6.7.0/24 ; SBL123\n\
                   2001:db8::/32\n";
        assert_eq!(
            parse_plain_list(raw),
            vec![
                "1.2.3.0/24".to_string(),
                "4.5.6.7".to_string(),
                "5.6.7.0/24".to_string(),
                "2001:db8::/32".to_string(),
            ]
        );
    }

    /// If an upstream serves an HTML error page instead of a list, none of
    /// it may reach a generated firewall script — one bad line makes the
    /// whole script fail to apply, taking every other rule with it.
    #[test]
    fn parse_plain_list_drops_lines_that_are_not_addresses() {
        let raw = "<!DOCTYPE html>\n<html><body>404 Not Found</body></html>\n";
        assert!(parse_plain_list(raw).is_empty());
    }

    #[test]
    fn parse_aws_json_merges_both_address_families() {
        let raw = r#"{
            "prefixes": [{"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2"}],
            "ipv6_prefixes": [{"ipv6_prefix": "2600:1f13::/36", "region": "us-west-2"}]
        }"#;
        assert_eq!(
            parse_aws_json(raw).unwrap(),
            vec!["2600:1f13::/36".to_string(), "3.5.140.0/22".to_string()]
        );
    }

    #[test]
    fn parse_aws_json_deduplicates() {
        let raw = r#"{"prefixes": [
            {"ip_prefix": "3.5.140.0/22"},
            {"ip_prefix": "3.5.140.0/22"}
        ]}"#;
        assert_eq!(parse_aws_json(raw).unwrap().len(), 1);
    }

    #[test]
    fn parse_csv_first_column_takes_only_the_cidr() {
        let raw = "1.2.3.0/24,US,CA,San Francisco,94124\n5.6.7.0/24,NL,,,\n";
        assert_eq!(
            parse_csv_first_column(raw),
            vec!["1.2.3.0/24".to_string(), "5.6.7.0/24".to_string()]
        );
    }

    #[test]
    fn every_kind_has_a_distinct_id_and_round_trips_through_from_id() {
        let mut ids: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count);

        for kind in ReputationSourceKind::ALL {
            assert_eq!(ReputationSourceKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(ReputationSourceKind::from_id("nope"), None);
    }

    /// The provider feeds are the ones that block real visitors, and the
    /// UI relies on this flag to say so.
    #[test]
    fn only_the_cloud_provider_feeds_are_marked_as_blocking_infrastructure() {
        assert!(ReputationSourceKind::Aws.blocks_infrastructure());
        assert!(ReputationSourceKind::GoogleCloud.blocks_infrastructure());
        assert!(ReputationSourceKind::DigitalOcean.blocks_infrastructure());
        assert!(!ReputationSourceKind::FireholLevel1.blocks_infrastructure());
        assert!(!ReputationSourceKind::TorExits.blocks_infrastructure());
        assert!(!ReputationSourceKind::BlocklistDe.blocks_infrastructure());

        assert!(ReputationSourceKind::Aws.warning().is_some());
        assert!(ReputationSourceKind::FireholLevel1.warning().is_none());
    }

    #[test]
    fn registering_twice_does_not_reset_an_enabled_flag() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        db.set_reputation_source_enabled(ReputationSourceKind::TorExits.id(), true)
            .unwrap();

        register_all_reputation_sources(&db).unwrap();

        let source = db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == ReputationSourceKind::TorExits.id())
            .unwrap();
        assert!(source.enabled);
    }

    #[test]
    fn only_enabled_sources_contribute_ranges() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        store(
            &db,
            ReputationSourceKind::TorExits,
            &["1.2.3.4".to_string()],
        )
        .unwrap();

        assert!(db.enabled_reputation_ranges().unwrap().is_empty());

        db.set_reputation_source_enabled(ReputationSourceKind::TorExits.id(), true)
            .unwrap();
        assert_eq!(
            db.enabled_reputation_ranges().unwrap(),
            vec!["1.2.3.4".to_string()]
        );
    }

    /// Switching a feed off keeps its downloaded ranges, so turning it back
    /// on doesn't need another download.
    #[test]
    fn disabling_a_source_keeps_its_stored_ranges() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        store(&db, ReputationSourceKind::Aws, &["1.2.3.0/24".to_string()]).unwrap();
        db.set_reputation_source_enabled(ReputationSourceKind::Aws.id(), true)
            .unwrap();
        db.set_reputation_source_enabled(ReputationSourceKind::Aws.id(), false)
            .unwrap();

        let source = db
            .list_reputation_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == ReputationSourceKind::Aws.id())
            .unwrap();
        assert_eq!(source.range_count, 1);
        assert!(db.enabled_reputation_ranges().unwrap().is_empty());
    }

    #[test]
    fn refetching_replaces_rather_than_accumulates() {
        let db = Db::open_in_memory().unwrap();
        register_all_reputation_sources(&db).unwrap();
        store(
            &db,
            ReputationSourceKind::TorExits,
            &["1.1.1.1".to_string(), "2.2.2.2".to_string()],
        )
        .unwrap();
        let count = store(
            &db,
            ReputationSourceKind::TorExits,
            &["3.3.3.3".to_string()],
        )
        .unwrap();

        assert_eq!(count, 1);
        db.set_reputation_source_enabled(ReputationSourceKind::TorExits.id(), true)
            .unwrap();
        assert_eq!(
            db.enabled_reputation_ranges().unwrap(),
            vec!["3.3.3.3".to_string()]
        );
    }
}
