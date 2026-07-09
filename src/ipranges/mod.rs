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
fn parse_prefixes_json(raw: &str) -> Result<Vec<String>> {
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
fn validate_country_code(country_code: &str) -> Result<String> {
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

/// Fetches, parses and stores `country_code`'s current CIDR list. Returns
/// the count now stored.
pub async fn update_country(db: &Db, country_code: &str) -> Result<usize> {
    let cc = validate_country_code(country_code)?;
    let raw = fetch_country(&cc).await?;
    let cidrs = parse_zone_file(&raw);
    db.replace_country_ranges(&cc, &cidrs)
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
}
