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

//! Whole hosting providers, by autonomous system number (ASN).
//!
//! AWS, Google Cloud and DigitalOcean publish their own address space,
//! and are [reputation feeds](super::reputation) of their own. Hetzner,
//! OVH and most of the rest do not: the only list of what they hold is the
//! routing table, which says which network (AS) announces which range.
//! [iptoasn.com](https://iptoasn.com) publishes that table as a public
//! domain download, one line per range:
//!
//! ```text
//! range_start  range_end  AS_number  country_code  AS_description
//! ```
//!
//! **One download feeds every selected ASN.** The table covers the whole
//! internet (about 720,000 lines, 9 MB gzipped, 46 MB unpacked), and this
//! keeps only the lines of the ASNs selected here, in [`select_lines`],
//! before anything reaches the database or crosses a channel. Its ranges
//! are start–end, not CIDR, so [`range_to_cidrs`] turns each into the
//! fewest CIDR blocks that cover exactly it.
//!
//! **A selected ASN is blocked like a cloud-provider feed**, because it is
//! one: every visitor hosted there is turned away, not only bots, and the
//! same warning and the same port-80 opening for Let's Encrypt apply (see
//! `Db::derived_firewall_entries`). Nothing is selected by default.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};

use crate::db::Db;

/// One hosting provider's network, as the curated list names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostingProvider {
    pub asn: u32,
    pub name: &'static str,
    /// What blocking it takes with it beyond rented servers, where that is
    /// more than the general warning says.
    pub note: Option<&'static str>,
}

/// The hosting providers offered by name: the ones bot traffic comes from
/// most, which publish no list of their own.
///
/// Each number was checked against the iptoasn table of 2026-10-16, where
/// it is announced under the name in the comment. AWS, Google Cloud and
/// DigitalOcean are not here: they publish their ranges themselves, and
/// are feeds (`set-reputation-source`).
pub const HOSTING_PROVIDERS: &[HostingProvider] = &[
    // ALIBABA-CN-NET Alibaba US Technology Co., Ltd.
    provider(45102, "Alibaba Cloud"),
    // BYTEPLUS-AS-AP Byteplus Pte. Ltd., ByteDance's cloud. Checked on
    // 2026-11-08, after eight of its addresses, in Singapore and
    // Indonesia, sent one host about 2,400 requests probing for cloud
    // configuration and credentials in October.
    provider(150436, "BytePlus"),
    // CONTABO
    provider(51167, "Contabo"),
    // CONTABO-40021
    provider(40021, "Contabo US"),
    // HETZNER-AS
    provider(24940, "Hetzner"),
    // HETZNER-CLOUD2-AS
    provider(213230, "Hetzner Cloud"),
    // AS-HOSTINGER
    provider(47583, "Hostinger"),
    // LEASEWEB-NL-AMS-01 Netherlands
    provider(60781, "Leaseweb NL"),
    // LEASEWEB-DE-FRA-10
    provider(28753, "Leaseweb DE"),
    // AKAMAI-LINODE-AP Akamai Connected Cloud
    provider(63949, "Akamai Linode"),
    // M247
    provider(9009, "M247"),
    // Microsoft (AS8075) is left out on purpose: it is all of Microsoft,
    // not only Azure, so Bingbot crawls from it and Outlook and Microsoft
    // 365 send from it. `add-hosting-asn --asn 8075` adds it for someone
    // who means that.
    // ORACLE-BMC-31898
    provider(31898, "Oracle Cloud"),
    // OVH
    provider(16276, "OVHcloud"),
    // Online SAS
    provider(12876, "Scaleway"),
    // TENCENT-NET-AP-CN Tencent Building, Kejizhongyi Avenue
    provider(132203, "Tencent Cloud"),
    // AS-VULTR
    provider(20473, "Vultr"),
];

const fn provider(asn: u32, name: &'static str) -> HostingProvider {
    HostingProvider {
        asn,
        name,
        note: None,
    }
}

/// The curated entry for `asn`, if it is one.
pub fn curated(asn: u32) -> Option<&'static HostingProvider> {
    HOSTING_PROVIDERS.iter().find(|p| p.asn == asn)
}

/// How `asn` is named to a person: the curated name, or else what the
/// table calls it, or else just the number.
pub fn display_name(asn: u32, description: Option<&str>) -> String {
    match (curated(asn), description) {
        (Some(provider), _) => provider.name.to_string(),
        (None, Some(description)) if !description.is_empty() => description.to_string(),
        (None, _) => format!("AS{asn}"),
    }
}

/// `asn` with its name, for a sentence: "AS24940 (Hetzner)", or just
/// "AS64500" when nothing names it.
pub fn label(asn: u32, description: Option<&str>) -> String {
    let name = display_name(asn, description);
    if name == format!("AS{asn}") {
        name
    } else {
        format!("AS{asn} ({name})")
    }
}

/// Where the table comes from: IPv4 and IPv6 in one file, so one download
/// covers both.
pub const IP2ASN_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

/// The table as an error message or a log names it.
pub const SOURCE_NAME: &str = "the iptoasn.com ASN table";

/// The largest table [`select_lines`] will unpack: 256 MiB, about five
/// times today's. Checked as it unpacks, so a small download that unpacks
/// into gigabytes is refused rather than read to the end.
pub const MAX_TABLE_BYTES: u64 = 256 * 1024 * 1024;

/// What blocking a hosting provider does, for the TUI's `?` and the help.
pub fn about() -> &'static str {
    "Every address a hosting provider's network announces, by its AS number, from the \
     public iptoasn.com table. Much bot traffic comes from rented servers, but so do VPNs, \
     company networks, monitoring and API clients."
}

/// The caution shown wherever a provider is switched on: the same as the
/// cloud-provider feeds', because it is the same kind of block.
pub fn warning() -> &'static str {
    super::reputation::INFRASTRUCTURE_WARNING
}

/// Whether `asn` can name a network at all. 0 is "not routed" in the
/// table, and reserved for exactly that.
pub fn check_asn(asn: u32) -> Result<()> {
    if asn == 0 {
        anyhow::bail!("AS0 is not a network: the table uses it for addresses nobody announces");
    }
    Ok(())
}

/// Reads an AS number as an operator types it: `24940` or `AS24940`.
pub fn parse_asn(text: &str) -> Result<u32, String> {
    let digits = text
        .trim()
        .strip_prefix("AS")
        .or_else(|| text.trim().strip_prefix("as"))
        .unwrap_or(text.trim());
    let asn: u32 = digits
        .parse()
        .map_err(|_| format!("{text:?} is not an AS number, like 24940 or AS24940"))?;
    check_asn(asn).map_err(|err| err.to_string())?;
    Ok(asn)
}

/// The fewest CIDR blocks that cover exactly `start..=end`.
///
/// Each step takes the largest block that both starts at `start` (so is
/// aligned there) and ends at or before `end`, which is the standard
/// greedy split and the minimal one. Both ends must be the same family,
/// and `start` must not be after `end`.
pub fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Result<Vec<String>> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let blocks = split_range(u32::from(start).into(), u32::from(end).into(), 32)
                .with_context(|| format!("{start}-{end}"))?;
            Ok(blocks
                .into_iter()
                .map(|(base, len)| format!("{}/{len}", Ipv4Addr::from(base as u32)))
                .collect())
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let blocks = split_range(u128::from(start), u128::from(end), 128)
                .with_context(|| format!("{start}-{end}"))?;
            Ok(blocks
                .into_iter()
                .map(|(base, len)| format!("{}/{len}", Ipv6Addr::from(base)))
                .collect())
        }
        _ => anyhow::bail!("{start}-{end} mixes IPv4 and IPv6"),
    }
}

/// [`range_to_cidrs`] on plain numbers, in an address space `bits` wide:
/// `(base, prefix length)` pairs.
fn split_range(mut start: u128, end: u128, bits: u32) -> Result<Vec<(u128, u32)>> {
    if start > end {
        anyhow::bail!("the range ends before it starts");
    }
    let mut blocks = Vec::new();
    loop {
        // The largest block aligned at `start`...
        let aligned = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits)
        };
        // ...and the largest that fits before `end`: 2^fits addresses,
        // where 2^fits <= end - start + 1.
        let span = end - start;
        let fits = if span == u128::MAX {
            128
        } else {
            127 - (span + 1).leading_zeros()
        };
        let size_bits = aligned.min(fits);
        blocks.push((start, bits - size_bits));
        if size_bits == 128 {
            break;
        }
        let last = start + ((1u128 << size_bits) - 1);
        if last >= end {
            break;
        }
        start = last + 1;
    }
    Ok(blocks)
}

/// The lines of an ip2asn table (gzipped or plain) that belong to one of
/// `asns`, as plain text in the same format.
///
/// This is how a 46 MB table becomes the few kilobytes this host uses,
/// before any of it is kept: the download is unpacked a line at a time
/// and every other line dropped. Refuses a table in which no line reads
/// as an ip2asn line at all, which is what an error page or a moved file
/// looks like, so that it cannot pass as "no ranges for anyone".
pub fn select_lines(raw: &[u8], asns: &[u32]) -> Result<String> {
    let wanted: BTreeSet<u32> = asns.iter().copied().collect();
    let gzipped = raw.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read + '_> = if gzipped {
        Box::new(flate2::read::MultiGzDecoder::new(raw))
    } else {
        Box::new(raw)
    };
    // One byte past the limit, so reaching it is distinguishable from
    // ending exactly on it.
    let mut reader = std::io::BufReader::new(reader.take(MAX_TABLE_BYTES + 1));

    let mut kept = String::new();
    let mut recognised = 0usize;
    let mut read = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_until(b'\n', &mut line)
            .with_context(|| format!("{SOURCE_NAME} could not be unpacked"))?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > MAX_TABLE_BYTES {
            anyhow::bail!(
                "{SOURCE_NAME} unpacks to more than {MAX_TABLE_BYTES} bytes, far more than the \
                 real one; refused"
            );
        }
        let mut fields = line.split(|b| *b == b'\t');
        let (Some(start), Some(_end), Some(asn)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Some(asn) = std::str::from_utf8(asn).ok().and_then(|a| a.parse().ok()) else {
            continue;
        };
        if std::str::from_utf8(start)
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .is_none()
        {
            continue;
        }
        recognised += 1;
        if wanted.contains(&asn) {
            kept.push_str(String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']));
            kept.push('\n');
        }
    }
    if recognised == 0 {
        anyhow::bail!(
            "{SOURCE_NAME} has no line of the form range_start, range_end, AS_number: the \
             download is not the table, or its format changed"
        );
    }
    Ok(kept)
}

/// One ASN's share of the table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsnRanges {
    /// What the table calls the network, cleaned for a terminal.
    pub description: String,
    /// Its ranges as CIDR blocks, adjacent and overlapping ranges merged
    /// first, so the list is as short as it can be.
    pub cidrs: Vec<String>,
}

/// One range as numbers: whether it is IPv6, its first and its last
/// address.
type NumericRange = (bool, u128, u128);

/// Every ASN's ranges in an ip2asn table, keyed by AS number. Lines that
/// do not parse are skipped: one bad line costs that line.
pub fn parse(text: &str) -> BTreeMap<u32, AsnRanges> {
    // Each ASN's description and ranges, as numbers, to merge before
    // splitting.
    let mut ranges: BTreeMap<u32, (String, Vec<NumericRange>)> = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split('\t');
        let (Some(start), Some(end), Some(asn)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let _country = fields.next();
        let description = fields.next().unwrap_or("");
        let Ok(asn) = asn.trim().parse::<u32>() else {
            continue;
        };
        let range = match (start.trim().parse(), end.trim().parse()) {
            (Ok(IpAddr::V4(s)), Ok(IpAddr::V4(e))) => {
                (false, u32::from(s).into(), u32::from(e).into())
            }
            (Ok(IpAddr::V6(s)), Ok(IpAddr::V6(e))) => (true, u128::from(s), u128::from(e)),
            _ => continue,
        };
        if range.1 > range.2 || asn == 0 {
            continue;
        }
        let entry = ranges.entry(asn).or_default();
        if entry.0.is_empty() {
            entry.0 = clean_description(description);
        }
        entry.1.push(range);
    }

    ranges
        .into_iter()
        .map(|(asn, (description, mut spans))| {
            spans.sort_unstable();
            let mut merged: Vec<NumericRange> = Vec::new();
            for (v6, start, end) in spans {
                match merged.last_mut() {
                    Some((last_v6, _, last_end))
                        if *last_v6 == v6 && start <= last_end.saturating_add(1) =>
                    {
                        *last_end = (*last_end).max(end);
                    }
                    _ => merged.push((v6, start, end)),
                }
            }
            let cidrs = merged
                .into_iter()
                .flat_map(|(v6, start, end)| {
                    let (start, end) = if v6 {
                        (
                            IpAddr::V6(Ipv6Addr::from(start)),
                            IpAddr::V6(Ipv6Addr::from(end)),
                        )
                    } else {
                        (
                            IpAddr::V4(Ipv4Addr::from(start as u32)),
                            IpAddr::V4(Ipv4Addr::from(end as u32)),
                        )
                    };
                    range_to_cidrs(start, end).unwrap_or_default()
                })
                .collect();
            (asn, AsnRanges { description, cidrs })
        })
        .collect()
}

/// A network's name from the table, safe to print: no control or
/// formatting characters, and no longer than any real one.
fn clean_description(description: &str) -> String {
    description
        .chars()
        .filter(|c| !c.is_control() && !crate::present::is_invisible_format(*c))
        .take(100)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Downloads the table and keeps the lines of `asns` (see
/// [`select_lines`]). Touches no database, so it can run where `Db`
/// cannot go; [`store`] is the other half.
pub async fn fetch(asns: &[u32]) -> Result<String> {
    let raw = crate::fetch::bytes(IP2ASN_URL, SOURCE_NAME).await?;
    let asns = asns.to_vec();
    // Unpacking 46 MB is a few hundred milliseconds of CPU: off the
    // runtime's threads, which the TUI's other work shares.
    tokio::task::spawn_blocking(move || select_lines(&raw, &asns))
        .await
        .context("unpacking the ASN table stopped")?
}

/// What [`store`] did with each ASN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stored {
    /// Stored, with how many ranges each now has.
    pub stored: Vec<(u32, usize)>,
    /// Selected, but the table has no line for it.
    pub missing: Vec<u32>,
    /// Refused by the database's checks on a fetched list, with why.
    pub refused: Vec<(u32, String)>,
}

impl Stored {
    /// One line for a log or the TUI: "2 hosting ASN(s), 779 range(s)", and
    /// what was not stored.
    pub fn summary(&self) -> String {
        let ranges: usize = self.stored.iter().map(|(_, count)| count).sum();
        let mut summary = format!("{} hosting ASN(s), {ranges} range(s)", self.stored.len());
        if !self.missing.is_empty() {
            let missing: Vec<String> = self.missing.iter().map(|asn| format!("AS{asn}")).collect();
            summary.push_str(&format!("; not in the table: {}", missing.join(", ")));
        }
        for (asn, why) in &self.refused {
            summary.push_str(&format!("; AS{asn}: {why}"));
        }
        summary
    }

    /// Whether every ASN asked for was stored.
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty() && self.refused.is_empty()
    }
}

/// Stores the ranges of each of `asns` that `text` (an ip2asn table, or
/// the lines [`select_lines`] kept of one) holds.
///
/// Only an ASN that is still selected is stored: one removed while the
/// download was out stays removed, and its ranges are not kept. An ASN the
/// table has no line for keeps whatever it had, and is reported.
pub fn store(db: &Db, asns: &[u32], text: &str) -> Result<Stored> {
    let selected: BTreeSet<u32> = db
        .list_hosting_asns()?
        .into_iter()
        .map(|asn| asn.asn)
        .collect();
    let mut parsed = parse(text);
    let mut outcome = Stored::default();
    for &asn in asns.iter().filter(|asn| selected.contains(asn)) {
        let Some(ranges) = parsed.remove(&asn).filter(|r| !r.cidrs.is_empty()) else {
            outcome.missing.push(asn);
            continue;
        };
        match db.replace_hosting_asn_ranges(asn, &ranges.description, &ranges.cidrs) {
            Ok(count) => outcome.stored.push((asn, count)),
            Err(err) => outcome.refused.push((asn, format!("{err:#}"))),
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs(start: &str, end: &str) -> Vec<String> {
        range_to_cidrs(start.parse().unwrap(), end.parse().unwrap()).unwrap()
    }

    /// The table's ranges are start–end; a firewall wants CIDR blocks,
    /// and as few as cover each range exactly.
    #[test]
    fn a_range_becomes_the_fewest_cidr_blocks_that_cover_it_exactly() {
        let cases: &[(&str, &str, &str, &[&str])] = &[
            ("one address", "1.2.3.4", "1.2.3.4", &["1.2.3.4/32"]),
            ("an aligned /24", "1.2.3.0", "1.2.3.255", &["1.2.3.0/24"]),
            (
                "an aligned pair of /24s",
                "1.2.2.0",
                "1.2.3.255",
                &["1.2.2.0/23"],
            ),
            (
                "two /24s that straddle a /23 boundary",
                "1.2.3.0",
                "1.2.4.255",
                &["1.2.3.0/24", "1.2.4.0/24"],
            ),
            (
                "an unaligned start and end",
                "10.0.0.1",
                "10.0.0.6",
                &["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"],
            ),
            (
                "the whole IPv4 space",
                "0.0.0.0",
                "255.255.255.255",
                &["0.0.0.0/0"],
            ),
            (
                "up to the last IPv4 address",
                "255.255.255.254",
                "255.255.255.255",
                &["255.255.255.254/31"],
            ),
            (
                "one IPv6 address",
                "2001:db8::1",
                "2001:db8::1",
                &["2001:db8::1/128"],
            ),
            (
                "an aligned IPv6 /32",
                "2a01:4f8::",
                "2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff",
                &["2a01:4f8::/32"],
            ),
            (
                "an unaligned IPv6 range",
                "2001:db8::1",
                "2001:db8::3",
                &["2001:db8::1/128", "2001:db8::2/127"],
            ),
            (
                "the whole IPv6 space",
                "::",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                &["::/0"],
            ),
            (
                "up to the last IPv6 address",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                &["ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"],
            ),
        ];
        for (what, start, end, expected) in cases {
            assert_eq!(cidrs(start, end), *expected, "{what}: {start}-{end}");
        }
    }

    #[test]
    fn a_backwards_or_mixed_range_is_refused() {
        for (start, end) in [("1.2.3.5", "1.2.3.4"), ("1.2.3.4", "2001:db8::1")] {
            let result = range_to_cidrs(start.parse().unwrap(), end.parse().unwrap());
            assert!(result.is_err(), "{start}-{end} gave {result:?}");
        }
    }

    const SAMPLE: &str = include_str!("../../tests/fixtures/ipranges/ip2asn-sample.tsv");

    #[test]
    fn the_sample_table_parses_into_each_asns_cidrs() {
        let parsed = parse(SAMPLE);

        let hetzner = &parsed[&24940];
        assert_eq!(hetzner.description, "HETZNER-AS");
        assert_eq!(
            hetzner.cidrs,
            [
                // 5.9.0.0-5.9.255.255 and 5.9.0.0-5.9.127.255 overlap, and
                // 78.46.0.0-78.47.255.255 is one aligned /15.
                "5.9.0.0/16",
                "78.46.0.0/15",
                "2a01:4f8::/32",
            ],
            "Hetzner was: {hetzner:?}"
        );
        // Two adjacent lines merge before splitting: one /23, not two /24s.
        assert_eq!(parsed[&16276].cidrs, ["51.68.0.0/23"]);
        assert!(
            !parsed.contains_key(&0),
            "AS0 is unrouted space, not a network"
        );
    }

    #[test]
    fn select_lines_keeps_only_the_asked_for_asns_from_plain_or_gzipped() {
        use std::io::Write as _;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(SAMPLE.as_bytes()).unwrap();
        let gzipped = gz.finish().unwrap();

        for (what, raw) in [("plain", SAMPLE.as_bytes()), ("gzipped", &gzipped[..])] {
            let kept = select_lines(raw, &[16276]).unwrap();
            assert_eq!(
                kept.lines().count(),
                2,
                "{what}: only OVH's two lines, was:\n{kept}"
            );
            assert!(
                kept.lines().all(|l| l.contains("\t16276\t")),
                "{what}:\n{kept}"
            );
        }
    }

    /// An error page instead of the table must not read as "no ranges for
    /// anyone", which would look like a clean update.
    #[test]
    fn select_lines_refuses_something_that_is_not_the_table() {
        let err = select_lines(b"<html><body>503</body></html>\n", &[24940]).unwrap_err();
        assert!(err.to_string().contains("not the table"), "was: {err:#}");
    }

    #[test]
    fn a_description_cannot_carry_terminal_controls() {
        let parsed = parse("1.2.3.0\t1.2.3.255\t64500\tXX\tEVIL\u{1b}[2J\u{202e}NET\n");
        assert_eq!(parsed[&64500].description, "EVIL[2JNET");
    }

    #[test]
    fn an_asn_is_read_with_or_without_its_prefix() {
        assert_eq!(parse_asn("24940"), Ok(24940));
        assert_eq!(parse_asn("AS24940"), Ok(24940));
        assert_eq!(parse_asn("as24940"), Ok(24940));
        assert!(parse_asn("0").is_err());
        assert!(parse_asn("hetzner").is_err());
    }

    #[test]
    fn every_curated_asn_is_listed_once() {
        let mut asns: Vec<u32> = HOSTING_PROVIDERS.iter().map(|p| p.asn).collect();
        let count = asns.len();
        asns.sort_unstable();
        asns.dedup();
        assert_eq!(asns.len(), count, "an ASN is listed twice");
    }

    /// Only what is selected is stored, and an ASN the table does not have
    /// is reported rather than silently left empty.
    #[test]
    fn store_keeps_only_selected_asns_and_reports_missing_ones() {
        let db = Db::open_in_memory().unwrap();
        db.add_hosting_asn(24940).unwrap();
        db.add_hosting_asn(64999).unwrap();

        let outcome = store(&db, &[24940, 16276, 64999], SAMPLE).unwrap();

        assert_eq!(outcome.stored, [(24940, 3)]);
        assert_eq!(outcome.missing, [64999]);
        let stored: Vec<u32> = db
            .hosting_asn_ranges()
            .unwrap()
            .iter()
            .map(|(a, _)| *a)
            .collect();
        assert!(stored.iter().all(|asn| *asn == 24940), "stored: {stored:?}");
        assert_eq!(
            outcome.summary(),
            "1 hosting ASN(s), 3 range(s); not in the table: AS64999"
        );
    }
}
