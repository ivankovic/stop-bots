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

//! IP-range data, as opposed to `botlist`'s user-agent data: published
//! crawler CIDR lists (Google, Bing, OpenAI's GPTBot) and, separately,
//! IPdeny's per-country CIDR blocks. Both end up feeding
//! `Db::derived_block_addresses`, which `main.rs::render_firewall` layers
//! on top of the admin-managed `firewall_rules` table.
//!
//! Unlike `botlist`'s three sources, Google, Bing and GPTBot all publish the
//! *exact same* JSON shape (`{"prefixes": [{"ipv4Prefix": "..."} |
//! {"ipv6Prefix": "..."}]}`), so [`IpRangeSourceKind`] shares one parser
//! instead of dispatching to per-source modules the way `botlist::SourceKind`
//! does.

pub mod reputation;

use crate::db::{Category, Db, IpRangeSource};
use anyhow::{Context, Result};
use serde::Deserialize;

/// A published crawler IP-range source. See this module's doc comment for
/// why all three share one parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRangeSourceKind {
    GoogleBot,
    BingBot,
    GptBot,
}

impl IpRangeSourceKind {
    pub const ALL: [IpRangeSourceKind; 3] = [
        IpRangeSourceKind::GoogleBot,
        IpRangeSourceKind::BingBot,
        IpRangeSourceKind::GptBot,
    ];

    pub fn id(self) -> &'static str {
        match self {
            IpRangeSourceKind::GoogleBot => "googlebot",
            IpRangeSourceKind::BingBot => "bingbot",
            IpRangeSourceKind::GptBot => "gptbot",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            IpRangeSourceKind::GoogleBot => "Googlebot IP ranges",
            IpRangeSourceKind::BingBot => "Bingbot IP ranges",
            IpRangeSourceKind::GptBot => "GPTBot IP ranges",
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            IpRangeSourceKind::GoogleBot => {
                "https://developers.google.com/search/apis/ipranges/googlebot.json"
            }
            IpRangeSourceKind::BingBot => "https://www.bing.com/toolbox/bingbot.json",
            IpRangeSourceKind::GptBot => "https://openai.com/gptbot.json",
        }
    }

    /// Which category's global default governs whether this source's
    /// ranges are currently blocked (see `Db::blocked_ip_ranges`). Google
    /// and Bing are search engines (Allowed by default — these sources are
    /// inert until Search is blocked); GPTBot is an AI crawler (Blocked by
    /// default).
    pub fn category(self) -> Category {
        match self {
            IpRangeSourceKind::GoogleBot | IpRangeSourceKind::BingBot => Category::Search,
            IpRangeSourceKind::GptBot => Category::Ai,
        }
    }

    pub fn from_id(id: &str) -> Option<IpRangeSourceKind> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    pub fn parse(self, raw: &str) -> Result<Vec<String>> {
        parse_prefixes_json(raw)
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

    fn as_source(self) -> IpRangeSource {
        IpRangeSource {
            id: self.id().to_string(),
            name: self.name().to_string(),
            url: self.url().to_string(),
            category: self.category(),
            last_fetched_at: None,
            range_count: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawPrefixDoc {
    prefixes: Vec<RawPrefix>,
}

#[derive(Debug, Deserialize)]
struct RawPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6_prefix: Option<String>,
}

/// Parses the `{"prefixes": [...]}` shape Google, Bing and OpenAI all
/// publish into a flat list of CIDR strings (IPv4 and IPv6 mixed together —
/// same "just a CIDR string" shape `firewall_rules.address` and
/// `iptables::render`'s `:`-based IPv6 filter already expect).
pub(crate) fn parse_prefixes_json(raw: &str) -> Result<Vec<String>> {
    let doc: RawPrefixDoc = serde_json::from_str(raw).context("failed to parse IP range JSON")?;
    Ok(doc
        .prefixes
        .into_iter()
        .filter_map(|p| p.ipv4_prefix.or(p.ipv6_prefix))
        .collect())
}

/// Registers every known IP-range source in `db` that isn't there yet, same
/// never-clobber convention as `botlist::register_all_sources`.
pub fn register_all_ip_range_sources(db: &Db) -> Result<()> {
    for kind in IpRangeSourceKind::ALL {
        db.register_ip_range_source(&kind.as_source())?;
    }
    Ok(())
}

/// Stores `cidrs` under `kind`'s source row, registering it first if this is
/// the first time it's been fetched. Returns the count now stored.
pub fn store(db: &Db, kind: IpRangeSourceKind, cidrs: &[String]) -> Result<usize> {
    db.register_ip_range_source(&kind.as_source())?;
    db.replace_ip_ranges(kind.id(), cidrs)
}

/// Fetches `kind`'s list over the network, parses it and stores it in `db`.
pub async fn update(db: &Db, kind: IpRangeSourceKind) -> Result<usize> {
    let raw = kind
        .fetch()
        .await
        .with_context(|| format!("failed to update {}", kind.name()))?;
    let cidrs = kind.parse(&raw)?;
    store(db, kind, &cidrs)
}

/// The URL for a given country's aggregated (i.e. consolidated into fewer,
/// larger CIDR blocks — IPdeny also publishes an unaggregated version with
/// many more, smaller blocks) IPv4 zone file. Aggregated is used
/// deliberately: even aggregated, a large country's list can run into the
/// tens of thousands of CIDRs (e.g. `us-aggregated.zone` has ~29,000 lines);
/// the unaggregated version would be several times that.
fn country_zone_url(country_code: &str) -> String {
    format!("https://www.ipdeny.com/ipblocks/data/aggregated/{country_code}-aggregated.zone")
}

/// Normalizes and validates a country code into IPdeny's expected lowercase
/// two-letter form, rejecting anything else before it's used to build a URL.
/// `pub` so the Dashboard's "add a country to block" popup can validate
/// what's typed before ever dispatching a fetch.
pub fn validate_country_code(country_code: &str) -> Result<String> {
    let cc = country_code.trim().to_ascii_lowercase();
    if cc.len() == 2 && cc.chars().all(|c| c.is_ascii_lowercase()) {
        Ok(cc)
    } else {
        anyhow::bail!(
            "invalid country code: {country_code:?} (expected a 2-letter ISO code, e.g. \"us\")"
        )
    }
}

/// Downloads `country_code`'s aggregated zone file from IPdeny over HTTP.
pub async fn fetch_country(country_code: &str) -> Result<String> {
    let cc = validate_country_code(country_code)?;
    let url = country_zone_url(&cc);
    let body = reqwest::get(&url)
        .await
        .with_context(|| format!("failed to fetch IP ranges for country {cc}"))?
        .error_for_status()
        .with_context(|| format!("IP range request for country {cc} failed (unknown code?)"))?
        .text()
        .await
        .with_context(|| format!("failed to read IP range response body for country {cc}"))?;
    Ok(body)
}

/// Parses an IPdeny zone file (one CIDR per line, blank lines allowed) into
/// a flat list of CIDR strings.
pub fn parse_zone_file(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether `ip` falls inside `cidr`. Used only for the lockout safety check
/// in `main.rs::render_firewall` (cross-referencing recently-connected SSH
/// client IPs against everything about to be blocked) — not on any path
/// that decides what to block, so it deliberately treats a malformed CIDR
/// or a family mismatch (an IPv4 `ip` against an IPv6 `cidr`, or vice versa)
/// as simply "no match" rather than an error worth propagating.
pub fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    // `firewall_rules.address` (unlike a fetched IP-range CIDR) is
    // routinely a bare IP with no "/len" at all — e.g. an admin's own
    // `add-firewall-rule --address 4.5.6.7`. Treat that as an exact match
    // rather than "no CIDR here, so never matches": a bare address is
    // functionally a /32 (or /128), and the lockout check must recognize
    // it as covering the corresponding connected IP.
    let Some((base, prefix_len)) = cidr.split_once('/') else {
        return cidr.parse::<IpAddr>().is_ok_and(|base| base == ip);
    };
    let Ok(prefix_len) = prefix_len.parse::<u32>() else {
        return false;
    };
    let Ok(base) = base.parse::<IpAddr>() else {
        return false;
    };

    match (base, ip) {
        (IpAddr::V4(base), IpAddr::V4(ip)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (u32::from(base) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (u128::from(base) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
}

/// Whether `ip` is loopback, RFC1918 (IPv4 private) or IPv6 unique-local
/// (`fc00::/7`) — never worth suggesting as a firewall block, since it's
/// necessarily either this host talking to itself or a client on the same
/// private network (a monitoring box, a jump host, ...), not an internet
/// scanner/bot. Shared by `sshlog::scanning_ips` and
/// `accesslog::scanning_ips`. Best-effort: doesn't attempt every
/// documented/reserved range, just the ones a scanner could never
/// plausibly connect from.
pub fn is_local_or_private(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Fetches, parses and stores `country_code`'s current CIDR list. Returns
/// the count now stored.
pub async fn update_country(db: &Db, country_code: &str) -> Result<usize> {
    let raw = fetch_country(&validate_country_code(country_code)?).await?;
    store_country(db, country_code, &raw)
}

/// Parses an already-obtained zone file and stores it under `country_code`.
///
/// Split from [`update_country`] the same way [`store`] is split from
/// [`update`]: it is the half that needs no network, which is what makes a
/// `--source` override — and the tests that use one — possible.
pub fn store_country(db: &Db, country_code: &str, raw: &str) -> Result<usize> {
    let cc = validate_country_code(country_code)?;
    db.replace_country_ranges(&cc, &parse_zone_file(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLEBOT_SAMPLE: &str =
        include_str!("../../tests/fixtures/ipranges/googlebot-sample.json");
    const COUNTRY_SAMPLE: &str = include_str!("../../tests/fixtures/ipranges/country-sample.zone");

    #[test]
    fn parse_prefixes_json_extracts_both_ipv4_and_ipv6() {
        let cidrs = parse_prefixes_json(GOOGLEBOT_SAMPLE).unwrap();
        assert_eq!(
            cidrs,
            vec![
                "192.178.4.0/27".to_string(),
                "2001:4860:4801:10::/64".to_string(),
                "192.178.5.0/27".to_string(),
            ]
        );
    }

    #[test]
    fn from_id_resolves_every_known_source_and_rejects_unknown_ones() {
        for kind in IpRangeSourceKind::ALL {
            assert_eq!(IpRangeSourceKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(IpRangeSourceKind::from_id("unknown"), None);
    }

    #[test]
    fn google_and_bing_are_governed_by_search_gptbot_by_ai() {
        assert_eq!(IpRangeSourceKind::GoogleBot.category(), Category::Search);
        assert_eq!(IpRangeSourceKind::BingBot.category(), Category::Search);
        assert_eq!(IpRangeSourceKind::GptBot.category(), Category::Ai);
    }

    #[test]
    fn register_all_ip_range_sources_registers_every_kind_exactly_once() {
        let db = Db::open_in_memory().unwrap();
        register_all_ip_range_sources(&db).unwrap();

        let mut ids: Vec<_> = db
            .list_ip_range_sources()
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        ids.sort();
        let mut expected: Vec<_> = IpRangeSourceKind::ALL
            .iter()
            .map(|k| k.id().to_string())
            .collect();
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn store_populates_the_right_source_and_count() {
        let db = Db::open_in_memory().unwrap();
        let cidrs = parse_prefixes_json(GOOGLEBOT_SAMPLE).unwrap();
        let count = store(&db, IpRangeSourceKind::GoogleBot, &cidrs).unwrap();
        assert_eq!(count, 3);

        let source = db
            .list_ip_range_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == "googlebot")
            .unwrap();
        assert_eq!(source.range_count, 3);
        assert!(source.last_fetched_at.is_some());
    }

    #[test]
    fn validate_country_code_accepts_two_letter_codes_case_insensitively() {
        assert_eq!(validate_country_code("US").unwrap(), "us");
        assert_eq!(validate_country_code(" nl ").unwrap(), "nl");
        assert!(validate_country_code("USA").is_err());
        assert!(validate_country_code("1x").is_err());
        assert!(validate_country_code("").is_err());
    }

    #[test]
    fn country_zone_url_is_the_aggregated_variant() {
        assert_eq!(
            country_zone_url("nl"),
            "https://www.ipdeny.com/ipblocks/data/aggregated/nl-aggregated.zone"
        );
    }

    #[test]
    fn parse_zone_file_skips_blank_lines() {
        let cidrs = parse_zone_file(COUNTRY_SAMPLE);
        assert_eq!(
            cidrs,
            vec![
                "86.48.240.0/20".to_string(),
                "91.222.132.0/22".to_string(),
                "103.71.56.0/24".to_string(),
            ]
        );
    }

    #[test]
    fn cidr_contains_matches_ipv4_within_range_and_rejects_outside_it() {
        let ip: std::net::IpAddr = "192.168.1.42".parse().unwrap();
        assert!(cidr_contains("192.168.1.0/24", ip));
        assert!(!cidr_contains("192.168.2.0/24", ip));
    }

    #[test]
    fn cidr_contains_handles_the_full_prefix_length_range() {
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        // /32 only matches the exact address.
        assert!(cidr_contains("10.0.0.1/32", ip));
        assert!(!cidr_contains("10.0.0.2/32", ip));
        // /0 matches everything.
        assert!(cidr_contains("0.0.0.0/0", ip));
    }

    #[test]
    fn cidr_contains_matches_ipv6() {
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(cidr_contains("2001:db8::/32", ip));
        assert!(!cidr_contains("2001:db9::/32", ip));
        assert!(cidr_contains("::/0", ip));
    }

    #[test]
    fn cidr_contains_never_matches_across_address_families() {
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let v6: std::net::IpAddr = "::1".parse().unwrap();
        assert!(!cidr_contains("::/0", v4));
        assert!(!cidr_contains("0.0.0.0/0", v6));
    }

    #[test]
    fn cidr_contains_is_false_not_an_error_for_malformed_input() {
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert!(!cidr_contains("not-a-cidr", ip));
        assert!(!cidr_contains("1.2.3.4/not-a-number", ip));
        assert!(!cidr_contains("1.2.3.4/99", ip));
    }

    /// `firewall_rules.address` is routinely a bare IP with no "/len" at
    /// all (e.g. `add-firewall-rule --address 4.5.6.7`) — must be treated
    /// as an exact match, not "no CIDR here, so never matches", or the
    /// lockout check in `main.rs` would never recognize an admin's own
    /// plain-IP Allow rule as covering their connected IP.
    #[test]
    fn cidr_contains_treats_a_bare_address_as_an_exact_match() {
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        assert!(cidr_contains("1.2.3.4", ip));
        assert!(!cidr_contains("1.2.3.5", ip));

        let ip6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert!(cidr_contains("2001:db8::1", ip6));
        assert!(!cidr_contains("2001:db8::2", ip6));
    }

    #[test]
    fn is_local_or_private_flags_loopback_and_rfc1918_ipv4() {
        for addr in ["127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.5"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(is_local_or_private(&ip), "{addr} should be local/private");
        }
    }

    #[test]
    fn is_local_or_private_flags_loopback_and_unique_local_ipv6() {
        for addr in ["::1", "fc00::1", "fd12:3456::1"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(is_local_or_private(&ip), "{addr} should be local/private");
        }
    }

    #[test]
    fn is_local_or_private_does_not_flag_public_addresses() {
        for addr in ["198.51.100.9", "2001:db8::1"] {
            let ip: std::net::IpAddr = addr.parse().unwrap();
            assert!(!is_local_or_private(&ip), "{addr} should be public");
        }
    }
}
