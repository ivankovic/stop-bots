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

//! A CDN's edge addresses, which the detectors must never block.
//!
//! Behind Cloudflare, every request NGINX logs arrives from one of a few
//! hundred Cloudflare addresses unless NGINX is told to take the visitor's
//! from a header (`set_real_ip_from` and `real_ip_header`). The detectors
//! would then see Cloudflare: one scanner among a million visitors gets the
//! edge it came through blocked, and with it everyone else who uses that
//! edge. So an address in these ranges is never blocked by a detector
//! (`scanblock`), and `health` warns when most of the access log comes from
//! them, which is the sign that NGINX is logging the CDN, not the visitor.
//!
//! **A compiled-in snapshot, not a feed.** Cloudflare publishes the list at
//! <https://www.cloudflare.com/ips-v4> and `/ips-v6`, and it has changed
//! rarely. Fetching it would mean a source kind of its own: the two feed
//! families here both *block* what they fetch, and this list must only ever
//! exempt. Refresh the snapshot below from those two URLs when they change.

use std::net::IpAddr;
use std::sync::OnceLock;

/// The CDN these ranges belong to, as a report names it.
pub const NAME: &str = "Cloudflare";

/// Cloudflare's published edge ranges, IPv4 then IPv6, as of 2026-09.
pub const RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// A range as a network and a mask, over IPv6's width: an IPv4 range is
/// held as its IPv4-mapped IPv6 form, so one comparison serves both.
struct Net {
    base: u128,
    mask: u128,
}

fn as_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// [`RANGES`], parsed once. The health probe asks about every line of a
/// 32 MB log tail, which is too many to parse twenty CIDRs for each.
fn nets() -> &'static [Net] {
    static NETS: OnceLock<Vec<Net>> = OnceLock::new();
    NETS.get_or_init(|| {
        RANGES
            .iter()
            .filter_map(|cidr| {
                let (base, len) = cidr.split_once('/')?;
                let base: IpAddr = base.parse().ok()?;
                let len: u32 = len.parse().ok()?;
                let len = if base.is_ipv4() { len + 96 } else { len };
                let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
                Some(Net {
                    base: as_u128(base) & mask,
                    mask,
                })
            })
            .collect()
    })
}

/// Whether `ip` is one of the CDN's edge addresses. Anything that does not
/// parse as an address is not.
pub fn is_edge(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok_and(is_edge_addr)
}

/// [`is_edge`], for an address already parsed.
pub fn is_edge_addr(ip: IpAddr) -> bool {
    let ip = as_u128(ip);
    nets().iter().any(|net| ip & net.mask == net.base)
}

/// The NGINX lines that make `$remote_addr` the visitor again behind this
/// CDN, for a report to quote.
pub fn real_ip_config() -> String {
    let mut out: String = RANGES
        .iter()
        .map(|cidr| format!("set_real_ip_from {cidr}; "))
        .collect();
    out.push_str("real_ip_header CF-Connecting-IP;");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_range_in_the_snapshot_parses() {
        assert_eq!(nets().len(), RANGES.len());
    }

    /// Both ends of a range are inside it and the addresses either side are
    /// not, in both families — the check is a mask, and an off-by-one in a
    /// mask is the whole risk.
    #[test]
    fn an_edge_address_is_recognised_to_the_edge_of_its_range() {
        for (ip, expected) in [
            ("173.245.48.0", true),
            ("173.245.63.255", true),
            ("173.245.64.0", false),
            ("173.245.47.255", false),
            ("104.16.0.1", true),
            ("2606:4700::1", true),
            ("2606:4701::1", false),
            ("2a06:98c7:ffff::1", true),
            ("2a06:98c8::1", false),
            ("203.0.113.7", false),
            // The IPv4-mapped form of an edge address is that address.
            ("::ffff:173.245.48.1", true),
            ("not an address", false),
        ] {
            assert_eq!(is_edge(ip), expected, "{ip}");
        }
    }

    #[test]
    fn the_nginx_config_names_every_range_and_the_header() {
        let config = real_ip_config();

        assert_eq!(config.matches("set_real_ip_from").count(), RANGES.len());
        assert!(config.ends_with("real_ip_header CF-Connecting-IP;"));
    }
}
