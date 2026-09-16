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

//! Best-effort, read-only integration with NGINX access logs — mirrors
//! `sshlog`'s role for SSH, but for HTTP: finds client IPs that look like
//! automated URL scanners (probing many nonexistent paths — `/wp-login.php`,
//! `/.env`, `/phpmyadmin`, ...) so `main.rs::block_web_scanners` can add
//! firewall Block rules for them. This module never writes to, rotates or
//! truncates any log — it only ever reads.
//!
//! Deliberately doesn't share `sshlog`'s "never flag an IP that also
//! succeeded" exclusion: a scanner's own recon almost always includes at
//! least one 200 (`/`, `/robots.txt`, ...), so requiring "never succeeded"
//! would exclude nearly every real scanner, not just legitimate clients.
//! What *is* shared: [`crate::ipranges::is_local_or_private`], since a
//! monitoring probe or health check hammering a stale internal endpoint
//! isn't an internet scanner on either log.

use crate::ipranges::{cidr_contains, is_local_or_private};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

/// The conventional NGINX access-log location; unlike SSH logs there's no
/// second common layout to also try, and no journald fallback — NGINX logs
/// to a file whether or not the system boots under systemd. Public so
/// `accessstats::record_access_stats` can key its persisted read-offset by
/// path even when the cron job (which only ever uses this default) never
/// resolves one explicitly itself.
pub const DEFAULT_LOG_PATH: &str = "/var/log/nginx/access.log";

/// The result of looking for access-log data: distinguishes "found and
/// read it, here's its text" from "nothing was even readable" (missing
/// file, permission denied — these are often only readable by
/// `root`/`adm`) — mirrors `sshlog::LogSource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    Found(String),
    Unavailable,
}

/// Reads `path` directly, bypassing auto-detection — backs the CLI's
/// `--access-log` override, for non-default log locations and for
/// deterministic tests.
pub fn read_log_file(path: &Path) -> LogSource {
    match std::fs::read_to_string(path) {
        Ok(content) => LogSource::Found(content),
        Err(_) => LogSource::Unavailable,
    }
}

/// Tries [`DEFAULT_LOG_PATH`]. Best-effort: a missing file or permission
/// error just means "couldn't check", same as `sshlog::find_default_source`.
pub fn find_default_source() -> LogSource {
    read_log_file(Path::new(DEFAULT_LOG_PATH))
}

/// Parses a single line of NGINX's default "combined" log format:
/// `<ip> - <remote_user> [<time_local>] "<method> <path> <proto>" <status>
/// <bytes> "<referer>" "<user_agent>"`. Returns `None` for anything that
/// doesn't parse cleanly (a custom log format, a line truncated at the
/// start/end of a rotated file, ...) rather than guessing — splitting on
/// `"` isolates the quoted request field from the unquoted ip/user/time
/// prefix and the status/bytes that follow it, which works regardless of
/// what the timestamp or remote_user contain, since neither can itself
/// contain a `"`. The trailing `"referer" "user_agent"` pair is extracted
/// the same way: `after_request` still has both quoted fields verbatim, so
/// splitting *it* on `"` isolates `user_agent` as the second quoted field.
/// A line with no trailing quoted pair at all (a stripped-down custom log
/// format) yields an empty `user_agent` rather than failing the whole
/// parse — status/path are still useful to `scanning_ips` either way.
fn parse_line(line: &str) -> Option<ParsedLine> {
    let ip: IpAddr = line.split_whitespace().next()?.parse().ok()?;

    let mut fields = line.splitn(3, '"');
    fields.next()?; // unquoted prefix (ip/user/time) — ip already captured above
    let request = fields.next()?;
    let after_request = fields.next()?;

    let mut request_parts = request.split_whitespace();
    request_parts.next()?; // HTTP method
    let target = request_parts.next()?;
    // Strip any query string: `/foo?a=1` and `/foo?a=2` are the same path
    // as far as "is this a valid URL on this site" goes, and counting them
    // as distinct would let a real, repeatedly-hit-with-varying-params 404
    // endpoint masquerade as many different invalid URLs.
    let path = target.split('?').next().unwrap_or(target).to_string();

    // `after_request` is ` <status> <bytes> "<referer>" "<user_agent>"`;
    // splitting it on `"` yields [status/bytes, referer, the space between
    // the two quoted fields, user_agent, ""] — index 3 is the field we want.
    let quoted: Vec<&str> = after_request.split('"').collect();
    let status: u16 = quoted.first()?.split_whitespace().next()?.parse().ok()?;
    let referer = quoted.get(1).copied().unwrap_or("").to_string();
    let user_agent = quoted.get(3).copied().unwrap_or("").to_string();

    Some(ParsedLine {
        ip,
        status,
        path,
        referer,
        user_agent,
    })
}

/// One parsed access-log line. A struct rather than a tuple since it grew
/// past three fields — `line.status` reads where `line.1` doesn't.
#[derive(Debug, PartialEq, Eq)]
struct ParsedLine {
    ip: IpAddr,
    status: u16,
    path: String,
    /// NGINX logs a missing `Referer` as `-`, which is what
    /// [`refererless_crawl_ips`] treats as absent.
    referer: String,
    user_agent: String,
}

/// Every IP with at least `threshold` *distinct* paths that returned 404
/// ("Not Found" — an invalid URL for this site) anywhere in `log_text`.
/// Distinct paths, not raw hit count: a real client repeatedly retrying
/// the same dead link must not look like a scanner, while a client probing
/// dozens of different well-known vulnerable paths is exactly the
/// signature this exists to catch. As with `sshlog::scanning_ips`, the
/// threshold is a count over *however much of the log `log_text` happens
/// to hold*, not a rate over a time window — this module doesn't parse
/// timestamps either. Loopback/private source IPs are excluded outright
/// (see the module docs for why there's no "had a 200" exclusion to go
/// with it). Deduplicated and sorted for deterministic output.
pub fn scanning_ips(log_text: &str, threshold: usize) -> Vec<String> {
    let mut not_found_paths: HashMap<IpAddr, HashSet<String>> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        if line.status == 404 {
            not_found_paths
                .entry(line.ip)
                .or_default()
                .insert(line.path);
        }
    }

    let mut ips: Vec<String> = not_found_paths
        .into_iter()
        .filter(|(ip, paths)| paths.len() >= threshold && !is_local_or_private(ip))
        .map(|(ip, _)| ip.to_string())
        .collect();
    ips.sort();
    ips
}

/// One crawler that can be impersonated: a marker that identifies it in a
/// `User-Agent` string, plus the CIDRs its operator actually publishes.
/// Built by `crate::scanblock::crawler_claims` from the same
/// `ipranges::IpRangeSourceKind` data `update-ip-ranges` fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerClaim {
    /// Lowercase substring that identifies a claim to be this crawler
    /// (`"googlebot"`, `"bingbot"`, `"gptbot"`). A substring rather than a
    /// full pattern because that's exactly what an impersonator copies —
    /// the recognisable token, embedded in whatever surrounding string
    /// they please.
    pub marker: &'static str,
    /// A human-readable name, for the "why was this blocked" message.
    pub name: &'static str,
    /// Every CIDR the operator publishes for this crawler. **Never empty**
    /// — see [`spoofed_crawler_ips`] for why an empty list must mean "skip
    /// this crawler entirely" rather than "nothing is legitimate".
    pub ranges: Vec<String>,
}

/// Every IP that claimed to be one of `claims`' crawlers from an address
/// that crawler's operator doesn't publish. This is the offline stand-in
/// for forward-confirmed reverse DNS: real rDNS needs a lookup per request,
/// which nothing in this codebase sits in a position to do, but the
/// published CIDR lists answer the same question — "is this actually
/// Google?" — against a log after the fact.
///
/// Unlike [`scanning_ips`] there is no threshold: a single request claiming
/// to be Googlebot from a non-Google address is already conclusive. Nothing
/// legitimate has a reason to put `googlebot` in its user agent from an
/// address Google doesn't own, and the published lists are complete by
/// construction (that's what publishing them is *for*).
///
/// **A crawler with no fetched ranges is skipped, not treated as
/// all-spoofed.** `CrawlerClaim::ranges` being empty means
/// `update-ip-ranges` has never successfully run for that source, in which
/// case every real crawler request would look like an impersonation — the
/// single worst failure this detector could have, since it would block the
/// actual Googlebot on a fresh install. The caller
/// (`crate::scanblock::crawler_claims`) filters those out, and this
/// function defends against it a second time rather than trusting that.
///
/// Loopback/private source IPs are excluded, same as [`scanning_ips`].
/// Deduplicated and sorted for deterministic output.
pub fn spoofed_crawler_ips(log_text: &str, claims: &[CrawlerClaim]) -> Vec<(String, String)> {
    let active: Vec<&CrawlerClaim> = claims.iter().filter(|c| !c.ranges.is_empty()).collect();
    if active.is_empty() {
        return Vec::new();
    }

    let mut found: HashMap<IpAddr, &'static str> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        let ip = line.ip;
        if is_local_or_private(&ip) {
            continue;
        }
        let ua_lower = line.user_agent.to_lowercase();
        let matched: Vec<&&CrawlerClaim> = active
            .iter()
            .filter(|claim| ua_lower.contains(claim.marker))
            .collect();
        if matched.is_empty() {
            continue;
        }
        // Verification is per *request*, not per claim: if any crawler this
        // user agent named vouches for the address, the request is
        // legitimate and the other names it happens to mention prove
        // nothing on their own. Checking per claim instead would flag the
        // real Googlebot the moment its UA string contained some other
        // crawler's token.
        if matched
            .iter()
            .any(|claim| claim.ranges.iter().any(|cidr| cidr_contains(cidr, ip)))
        {
            continue;
        }
        if let Some(first) = matched.first() {
            found.entry(ip).or_insert(first.name);
        }
    }

    let mut ips: Vec<(String, String)> = found
        .into_iter()
        .map(|(ip, name)| (ip.to_string(), name.to_string()))
        .collect();
    ips.sort();
    ips
}

/// Request paths that no human, browser or legitimate crawler ever asks
/// for, matched case-insensitively as a prefix of the request path.
///
/// The selection rule is strict, because this detector blocks on a
/// **single** request with no threshold: a path only belongs here if it is
/// never legitimate *on any site*, not merely suspicious. That rules out
/// several of the most commonly probed paths on purpose —
/// `/wp-login.php` and `/wp-admin/` are how real WordPress admins sign in,
/// `/xmlrpc.php` is how Jetpack and pingbacks work, `/phpmyadmin` exists
/// on plenty of hosts that installed it deliberately. Blocking a site's
/// own administrator on their first login attempt would be a far worse
/// bug than missing one scanner, which the ≥7-distinct-404s detector
/// catches anyway.
///
/// What's left is credential and source-tree exposure — files that only
/// ever exist because of a deployment mistake, and that only ever get
/// requested by something looking for that mistake.
pub const DEFAULT_PROBE_PATHS: [&str; 13] = [
    "/.env",            // and /.env.local, /api/.env, ... (see the matching note)
    "/.git/",           // /.git/config, /.git/HEAD, ...
    "/.svn/",           //
    "/.hg/",            //
    "/.aws/",           // /.aws/credentials
    "/.ssh/",           // /.ssh/id_rsa
    "/wp-config.php",   // never served as content, only ever probed
    "/vendor/phpunit/", // the eval-stdin.php RCE probe and friends
    "/.DS_Store",       // leaks a directory listing
    "/.htpasswd",       //
    // A WordPress "plugin" that is a file-manager backdoor. Nobody
    // installs it on purpose, and it was the single most-requested path
    // from clients sending no user agent at all on the host this came
    // from — 1,001 requests, not one of them answered with content.
    "/wp-content/plugins/hellopress/",
    // Percent-encoded dots, in both the single- and double-encoded forms
    // actually seen. A `.` needs no encoding, so encoding one has exactly
    // one purpose: getting a `../` past something that is looking for
    // `../`. 22,762 requests on that host, in paths like
    // `/$(pwd)/%2eenv%2elocal` and
    // `/cgi-bin/.%2e/.%2e/.%2e/bin/sh` (CVE-2021-41773). The only five
    // that were answered at all were `/%2frobots%2etxt` and
    // `/%2f%2eds_store` — the same evasion, aimed at files that happen to
    // exist. `%252e` is listed separately because it does not contain
    // `%2e` as a substring: the characters are `%`,`2`,`5`,`2`,`e`.
    "%2e",
    "%252e",
];

/// Every IP that requested one of `probe_paths`, paired with the path it
/// asked for. No threshold and no status-code filter: one request is
/// conclusive (see [`DEFAULT_PROBE_PATHS`] for how strictly that list is
/// chosen), and the *response* is irrelevant — an attacker who gets a 200
/// for `/.env` is a bigger problem than one who gets a 404, so keying on
/// 404 like [`scanning_ips`] does would skip exactly the worst case.
///
/// Matching is a case-insensitive *substring* test against the request
/// path, which is already query-string-stripped by `parse_line`.
///
/// **It used to be anchored at the start, and that was wrong.** The anchor
/// was there so a legitimate path merely containing one of these strings
/// later on — `/blog/how-to-secure-your-env` — could not match. But that
/// path does not contain `/.env` at all; the leading slash in every needle
/// was already doing that work. What the anchor actually excluded was
/// `/api/.env`, `/backend/.env`, `/laravel/.env` and every path-traversal
/// attempt, which is 3,391 distinct paths and 39,675 requests on one
/// host's log — *none* of which were answered with content.
///
/// The widening is real and worth stating: a path segment that *begins*
/// with a needle now matches, so a URL whose last segment is `.env-file`
/// would be flagged where it was not before. That is accepted. Serving a
/// path segment that starts with a dot is not something sites do — most
/// web servers deny dotfiles outright — and the evidence is one-sided: of
/// every newly matched request in that log, zero returned 2xx.
///
/// Note that a traversal payload in the *query string*
/// (`/?file=%252e%252e/.aws/credentials`) is invisible here, because
/// `parse_line` strips the query before this sees it. Those requests are
/// answered 200 by the homepage and are somebody else's problem — this
/// detector is about the path.
///
/// Loopback/private source IPs are excluded, same as [`scanning_ips`] —
/// an internal backup job walking a checkout isn't an attacker.
/// Deduplicated (first matching path wins per IP) and sorted.
pub fn probe_path_ips(log_text: &str, probe_paths: &[String]) -> Vec<(String, String)> {
    if probe_paths.is_empty() {
        return Vec::new();
    }
    let needles: Vec<String> = probe_paths.iter().map(|p| p.to_lowercase()).collect();

    let mut found: HashMap<IpAddr, String> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        if is_local_or_private(&line.ip) {
            continue;
        }
        let path_lower = line.path.to_lowercase();
        if needles.iter().any(|n| path_lower.contains(n.as_str())) {
            found.entry(line.ip).or_insert(line.path);
        }
    }

    let mut ips: Vec<(String, String)> = found
        .into_iter()
        .map(|(ip, path)| (ip.to_string(), path))
        .collect();
    ips.sort();
    ips
}

/// Filename extensions treated as "an asset a browser fetches alongside a
/// page". Deliberately generous — a miss here means a real browser looks
/// asset-less, which is the false positive that matters.
const ASSET_EXTENSIONS: [&str; 18] = [
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".map",
    ".webmanifest",
];

fn is_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    ASSET_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Every IP that fetched at least `min_pages` *distinct* pages and not one
/// asset. Browsers load the CSS, JS, fonts and images that go with a page;
/// scrapers pull the HTML and leave.
///
/// Three deliberate choices, each guarding a specific false positive:
///
/// - **Distinct pages, not request count.** The client this could wrongly
///   catch is a legitimate API consumer, which hammers a handful of
///   endpoints. A high distinct-URL count means something walked the site.
/// - **An asset counts at any status below 400, including 304.** A
///   returning browser with a warm cache gets `304 Not Modified` for every
///   asset. Counting only 200s would make well-cached real visitors look
///   exactly like scrapers.
/// - **Only successful page requests count**, so this doesn't re-flag the
///   404-sweeping already covered by [`scanning_ips`].
///
/// The false positive it *cannot* rule out: a site that serves no assets
/// at all — a pure JSON API — where every client looks like this. That is
/// why the detector is off by default.
pub fn asset_less_ips(log_text: &str, min_pages: usize) -> Vec<String> {
    let mut pages: HashMap<IpAddr, HashSet<String>> = HashMap::new();
    let mut fetched_asset: HashSet<IpAddr> = HashSet::new();

    for line in log_text.lines().filter_map(parse_line) {
        if is_local_or_private(&line.ip) || line.status >= 400 {
            continue;
        }
        if is_asset(&line.path) {
            fetched_asset.insert(line.ip);
        } else {
            pages.entry(line.ip).or_default().insert(line.path);
        }
    }

    let mut ips: Vec<String> = pages
        .into_iter()
        .filter(|(ip, paths)| paths.len() >= min_pages && !fetched_asset.contains(ip))
        .map(|(ip, _)| ip.to_string())
        .collect();
    ips.sort();
    ips
}

/// Every IP that presented at least `min_agents` distinct user agents.
/// A single client has one; rotating them is a deliberate evasion.
///
/// **The false positive this cannot rule out is large: NAT.** A corporate
/// gateway, a university, or any mobile carrier doing CGNAT presents
/// hundreds of real users behind one address, each with their own browser.
/// Without timestamps (see TODO.md) there is no way to distinguish "twenty
/// agents over a day from a campus" from "twenty agents in ten seconds
/// from one scraper", and a threshold is the only control available.
/// Off by default, and the threshold should be read as "how many distinct
/// browsers might legitimately share one address here".
pub fn rotating_user_agent_ips(log_text: &str, min_agents: usize) -> Vec<String> {
    let mut agents: HashMap<IpAddr, HashSet<String>> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        if is_local_or_private(&line.ip) || line.user_agent.is_empty() || line.user_agent == "-" {
            continue;
        }
        agents.entry(line.ip).or_default().insert(line.user_agent);
    }

    let mut ips: Vec<String> = agents
        .into_iter()
        .filter(|(_, seen)| seen.len() >= min_agents)
        .map(|(ip, _)| ip.to_string())
        .collect();
    ips.sort();
    ips
}

/// Every IP that fetched at least `min_paths` distinct *deep* pages (not
/// `/`) without ever sending a `Referer`. A person browsing arrives at
/// deep pages by following links, which sets one; a crawler working from
/// a sitemap or a URL list doesn't.
///
/// **Weaker than it looks, and off by default.** `Referrer-Policy:
/// no-referrer` is increasingly common, privacy tooling strips the header,
/// and typing a URL or opening a bookmark legitimately sends none — so
/// this is really "arrived at many distinct deep pages, every time with no
/// referer". The distinct-path threshold is doing all the work: one or two
/// referer-less deep hits are ordinary, twenty-five are a crawl.
pub fn refererless_crawl_ips(log_text: &str, min_paths: usize) -> Vec<String> {
    let mut deep_no_referer: HashMap<IpAddr, HashSet<String>> = HashMap::new();
    let mut sent_referer: HashSet<IpAddr> = HashSet::new();

    for line in log_text.lines().filter_map(parse_line) {
        if is_local_or_private(&line.ip) || line.status >= 400 {
            continue;
        }
        // NGINX logs a missing Referer as "-".
        let has_referer = !line.referer.is_empty() && line.referer != "-";
        if has_referer {
            sent_referer.insert(line.ip);
        } else if line.path != "/" {
            deep_no_referer
                .entry(line.ip)
                .or_default()
                .insert(line.path);
        }
    }

    let mut ips: Vec<String> = deep_no_referer
        .into_iter()
        .filter(|(ip, paths)| paths.len() >= min_paths && !sent_referer.contains(ip))
        .map(|(ip, _)| ip.to_string())
        .collect();
    ips.sort();
    ips
}

/// The complement to [`scanning_ips`]: instead of flagging bad traffic,
/// tallies who's actually browsing the site successfully. Counts every
/// distinct user agent's hits across every *successful* (status < 400 —
/// 2xx/3xx) line in `log_text`, from a non-local/private source IP (the
/// same [`is_local_or_private`] exclusion `scanning_ips` uses: an internal
/// health check or monitoring probe isn't a real visitor). Lines with no
/// user agent at all, or the conventional `-` NGINX logs for a missing
/// `User-Agent` header, are excluded — neither identifies an actual client.
/// How many parsed lines carried a **public** client address, and how many
/// lines parsed at all.
///
/// Exists to catch a silent failure rather than a noisy one. Every
/// detector in this module skips private sources — see the four
/// `is_local_or_private` guards above — so a deployment where NGINX
/// records its proxy's address instead of the client's does not produce
/// wrong blocks. It produces *no* blocks, from a log that looks perfectly
/// healthy and a report that says "checked and clear". That is the shape
/// of the `--ssh-log` bug: the detector most needed on an exposed host,
/// switched off by a path nobody chose, with nothing on screen to say so.
///
/// The usual cause is NGINX behind something that terminates the
/// connection itself — a container's port mapping, a load balancer, a CDN
/// — without `set_real_ip_from`/`real_ip_header` to recover the original
/// address.
///
/// Counts lines, not distinct addresses: one proxy in front of everything
/// is exactly the case worth catching, and it has one address.
pub fn client_address_mix(log_text: &str) -> (usize, usize) {
    let mut public = 0;
    let mut parsed = 0;
    for line in log_text.lines() {
        let Some(entry) = parse_line(line) else {
            continue;
        };
        parsed += 1;
        if !is_local_or_private(&entry.ip) {
            public += 1;
        }
    }
    (public, parsed)
}

/// Feeds [`crate::db::Db::record_user_agent_hits`] via
/// `crate::accessstats::record_access_stats`.
pub fn successful_user_agent_counts(log_text: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        if line.status < 400
            && !line.user_agent.is_empty()
            && line.user_agent != "-"
            && !is_local_or_private(&line.ip)
        {
            *counts.entry(line.user_agent).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"\n"
        )
    }

    fn ok_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n"
        )
    }

    #[test]
    fn parse_line_extracts_every_field_including_the_referer() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162 \"https://ref.example/from\" \"Mozilla/5.0\"";
        let parsed = parse_line(line).expect("the standard combined format should parse");
        assert_eq!(parsed.ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.path, "/wp-login.php");
        assert_eq!(parsed.referer, "https://ref.example/from");
        assert_eq!(parsed.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn parse_line_reads_a_missing_referer_as_nginx_writes_it() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"curl/8\"";
        assert_eq!(parse_line(line).unwrap().referer, "-");
    }

    #[test]
    fn parse_line_strips_the_query_string() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /foo?a=1&b=2 HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"";
        assert_eq!(parse_line(line).map(|l| l.path), Some("/foo".to_string()));
    }

    #[test]
    fn parse_line_handles_ipv6_addresses() {
        let line =
            "2001:db8::1 - - [10/Jul/2026:12:00:00 +0000] \"GET /x HTTP/1.1\" 404 1 \"-\" \"UA\"";
        assert_eq!(
            parse_line(line).map(|l| l.ip),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_line_rejects_malformed_lines() {
        assert_eq!(parse_line("not a log line at all"), None);
        assert_eq!(parse_line(""), None);
        // A remote_addr that isn't a real IP (e.g. a hostname from a
        // misconfigured log_format) must not be silently accepted.
        assert_eq!(
            parse_line("not-an-ip - - [t] \"GET /x HTTP/1.1\" 404 1 \"-\" \"UA\""),
            None
        );
    }

    /// The core discriminator this module exists to get right: repeatedly
    /// hitting the *same* dead path must never look like scanning, no
    /// matter how many times, while hitting many *different* dead paths
    /// must, even at a lower total count.
    #[test]
    fn scanning_ips_distinguishes_repeated_from_distinct_not_found_paths() {
        let repeated: String = (0..50)
            .map(|_| not_found_line("198.51.100.9", "/missing"))
            .collect();
        assert!(scanning_ips(&repeated, 10).is_empty());

        let distinct: String = (0..10)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        assert_eq!(
            scanning_ips(&distinct, 10),
            vec!["198.51.100.9".to_string()]
        );
    }

    #[test]
    fn scanning_ips_ignores_an_ip_below_the_threshold() {
        let log: String = (0..9)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        assert!(scanning_ips(&log, 10).is_empty());
    }

    /// Unlike `sshlog::scanning_ips`, a 200 elsewhere in the log must NOT
    /// exempt an IP — a scanner's own recon traffic almost always includes
    /// at least one successful hit.
    #[test]
    fn scanning_ips_still_flags_an_ip_that_also_got_a_200() {
        let mut log: String = (0..10)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        log.push_str(&ok_line("198.51.100.9", "/"));
        assert_eq!(scanning_ips(&log, 10), vec!["198.51.100.9".to_string()]);
    }

    #[test]
    fn scanning_ips_excludes_loopback_and_private_addresses() {
        let mut log = String::new();
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.5", "fc00::1"] {
            for i in 0..10 {
                log.push_str(&not_found_line(ip, &format!("/missing-{i}")));
            }
        }
        assert!(scanning_ips(&log, 10).is_empty());
    }

    #[test]
    fn scanning_ips_is_sorted_and_deduplicated() {
        let mut log = String::new();
        for i in 0..10 {
            log.push_str(&not_found_line("198.51.100.9", &format!("/a-{i}")));
        }
        for i in 0..10 {
            log.push_str(&not_found_line("198.51.100.2", &format!("/b-{i}")));
        }
        assert_eq!(
            scanning_ips(&log, 10),
            vec!["198.51.100.2".to_string(), "198.51.100.9".to_string()]
        );
    }

    fn line_with(ip: &str, status: u16, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" {status} 512 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn successful_user_agent_counts_tallies_each_distinct_agent() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 200, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.6", 200, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.7", 304, "curl/8.0"));

        let counts = successful_user_agent_counts(&log);
        assert_eq!(counts.get("Mozilla/5.0"), Some(&2));
        assert_eq!(counts.get("curl/8.0"), Some(&1));
    }

    #[test]
    fn successful_user_agent_counts_excludes_client_and_server_errors() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 404, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.5", 500, "Mozilla/5.0"));

        assert!(successful_user_agent_counts(&log).is_empty());
    }

    #[test]
    fn successful_user_agent_counts_excludes_missing_user_agent() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 200, "-"));
        log.push_str(&ok_line("203.0.113.6", "/")); // has a real UA, sanity check

        let counts = successful_user_agent_counts(&log);
        assert!(!counts.contains_key("-"));
        assert_eq!(counts.get("Mozilla/5.0"), Some(&1));
    }

    #[test]
    fn successful_user_agent_counts_excludes_loopback_and_private_addresses() {
        let mut log = String::new();
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.5", "fc00::1"] {
            log.push_str(&line_with(ip, 200, "curl/8.0"));
        }
        assert!(successful_user_agent_counts(&log).is_empty());
    }

    #[test]
    fn read_log_file_reports_unavailable_for_a_missing_path() {
        assert_eq!(
            read_log_file(Path::new("/nonexistent/does-not-exist.log")),
            LogSource::Unavailable
        );
    }

    #[test]
    fn read_log_file_reads_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        std::fs::write(&path, not_found_line("1.2.3.4", "/x")).unwrap();

        match read_log_file(&path) {
            LogSource::Found(content) => assert!(content.contains("1.2.3.4")),
            LogSource::Unavailable => panic!("expected the file to be readable"),
        }
    }

    // ---- spoofed crawler detection ----

    fn claim(marker: &'static str, name: &'static str, ranges: &[&str]) -> CrawlerClaim {
        CrawlerClaim {
            marker,
            name,
            ranges: ranges.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn ua_line(ip: &str, ua: &str) -> String {
        format!("{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{ua}\"\n")
    }

    fn googlebot_claim() -> CrawlerClaim {
        claim("googlebot", "Googlebot IP ranges", &["66.249.64.0/19"])
    }

    #[test]
    fn spoofed_crawler_ips_flags_a_googlebot_claim_from_outside_googles_ranges() {
        let log = ua_line("203.0.113.9", "Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(
            spoofed_crawler_ips(&log, &[googlebot_claim()]),
            vec![("203.0.113.9".to_string(), "Googlebot IP ranges".to_string())]
        );
    }

    #[test]
    fn spoofed_crawler_ips_leaves_the_real_googlebot_alone() {
        let log = ua_line("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_ignores_a_user_agent_that_claims_nothing() {
        let log = ua_line("203.0.113.9", "Mozilla/5.0 (X11; Linux x86_64)");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_matches_the_marker_case_insensitively() {
        let log = ua_line("203.0.113.9", "GOOGLEBOT");
        assert_eq!(spoofed_crawler_ips(&log, &[googlebot_claim()]).len(), 1);
    }

    /// The single most important property here: with no ranges fetched,
    /// every real crawler request looks forged. Skipping the crawler
    /// entirely is the only safe reading of "we have no data".
    #[test]
    fn spoofed_crawler_ips_skips_a_crawler_with_no_fetched_ranges() {
        let empty = claim("googlebot", "Googlebot IP ranges", &[]);
        let log = ua_line("203.0.113.9", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[empty]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_is_empty_with_no_claims_at_all() {
        let log = ua_line("203.0.113.9", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_excludes_local_and_private_sources() {
        let log = ua_line("10.0.0.5", "Googlebot/2.1") + &ua_line("127.0.0.1", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_deduplicates_and_sorts() {
        let log = ua_line("203.0.113.9", "Googlebot/2.1")
            + &ua_line("203.0.113.9", "Googlebot/2.1")
            + &ua_line("198.51.100.2", "bingbot/2.0");
        let found = spoofed_crawler_ips(
            &log,
            &[
                googlebot_claim(),
                claim("bingbot", "Bingbot IP ranges", &["40.77.167.0/24"]),
            ],
        );
        let ips: Vec<&str> = found.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(ips, vec!["198.51.100.2", "203.0.113.9"]);
    }

    /// An IP verified against one crawler's ranges must not be flagged by a
    /// *different* claim it also happens to mention.
    #[test]
    fn spoofed_crawler_ips_does_not_flag_a_verified_ip_for_another_claim() {
        let log = ua_line("66.249.66.1", "Googlebot/2.1 bingbot/2.0");
        let found = spoofed_crawler_ips(
            &log,
            &[
                googlebot_claim(),
                claim("bingbot", "Bingbot IP ranges", &["40.77.167.0/24"]),
            ],
        );
        // Verified as Googlebot, so the stray "bingbot" token isn't
        // treated as an impersonation of Bing on its own.
        assert!(found.is_empty(), "unexpectedly flagged: {found:?}");
    }

    // ---- probe-path detection ----

    fn probe_line(ip: &str, path: &str, status: u16) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 0 \"-\" \"curl/8\"\n"
        )
    }

    fn default_probes() -> Vec<String> {
        DEFAULT_PROBE_PATHS.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn probe_path_ips_flags_a_single_dotenv_request() {
        let log = probe_line("203.0.113.9", "/.env", 404);
        assert_eq!(
            probe_path_ips(&log, &default_probes()),
            vec![("203.0.113.9".to_string(), "/.env".to_string())]
        );
    }

    /// The response is irrelevant — a 200 for `/.env` is the *worse* case,
    /// so keying on 404 the way `scanning_ips` does would skip it.
    #[test]
    fn probe_path_ips_flags_a_successful_probe_too() {
        let log = probe_line("203.0.113.9", "/.env", 200);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    #[test]
    fn probe_path_ips_matches_by_prefix_and_case_insensitively() {
        let log = probe_line("203.0.113.9", "/.ENV.local", 404)
            + &probe_line("198.51.100.2", "/.git/config", 404);
        let found = probe_path_ips(&log, &default_probes());
        let ips: Vec<&str> = found.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(ips, vec!["198.51.100.2", "203.0.113.9"]);
    }

    /// Anchored at the start, so an ordinary page whose URL merely contains
    /// one of these strings is not a probe.
    ///
    /// The example is the one the leading slash in every needle protects:
    /// `-env` is not `/.env`. It used to be
    /// `/blog/how-to-secure-your/.env-file`, which the anchoring also
    /// excluded — and so did the anchoring exclude `/api/.env`, which is
    /// why the anchoring is gone. A path segment beginning with a dot is
    /// not something sites serve; a word ending in "env" is.
    #[test]
    fn probe_path_ips_does_not_match_a_word_that_merely_ends_in_the_needle() {
        let log = probe_line("203.0.113.9", "/blog/how-to-secure-your-env", 200);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    /// The gap the anchoring left: every one of these was being missed,
    /// and between them they are most of what actually probes a server.
    #[test]
    fn probe_path_ips_flags_a_dotfile_below_the_root() {
        for path in [
            "/api/.env",
            "/backend/.env",
            "/laravel/.env",
            "/var/www/html/wp-config.php",
            "/%252e%252e/%252e%252e/home/ubuntu/.ssh/id_ed25519",
        ] {
            let log = probe_line("203.0.113.9", path, 404);
            assert_eq!(
                probe_path_ips(&log, &default_probes()).len(),
                1,
                "missed {path}"
            );
        }
    }

    /// The two entries added from that log, each with the request that
    /// earned it.
    #[test]
    fn probe_path_ips_flags_the_backdoor_plugin_and_encoded_dots() {
        for path in [
            "/wp-content/plugins/hellopress/wp_filemanager.php",
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
            "/$(pwd)/%2eenv%2elocal",
            "/%2frobots%2etxt",
        ] {
            let log = probe_line("203.0.113.9", path, 404);
            assert_eq!(
                probe_path_ips(&log, &default_probes()).len(),
                1,
                "missed {path}"
            );
        }
    }

    #[test]
    fn probe_path_ips_ignores_ordinary_requests() {
        let log = probe_line("203.0.113.9", "/", 200) + &probe_line("203.0.113.9", "/about", 200);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    #[test]
    fn probe_path_ips_excludes_local_and_private_sources() {
        let log = probe_line("127.0.0.1", "/.env", 404) + &probe_line("10.0.0.5", "/.git/", 404);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    #[test]
    fn probe_path_ips_is_empty_with_no_configured_paths() {
        let log = probe_line("203.0.113.9", "/.env", 404);
        assert!(probe_path_ips(&log, &[]).is_empty());
    }

    #[test]
    fn probe_path_ips_reports_one_row_per_ip() {
        let log = probe_line("203.0.113.9", "/.env", 404)
            + &probe_line("203.0.113.9", "/.git/config", 404);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    #[test]
    fn probe_path_ips_honours_an_extra_configured_path() {
        let log = probe_line("203.0.113.9", "/my-secret/key", 404);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
        assert_eq!(probe_path_ips(&log, &["/my-secret".to_string()]).len(), 1);
    }

    /// Query strings are already stripped by `parse_line`, so a probe that
    /// tacks one on is still caught.
    #[test]
    fn probe_path_ips_matches_despite_a_query_string() {
        let log = probe_line("203.0.113.9", "/.env?cachebust=1", 404);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    // ---- behavioural detectors ----

    fn line(ip: &str, path: &str, status: u16, referer: &str, ua: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 9 \"{referer}\" \"{ua}\"\n"
        )
    }

    fn pages(ip: &str, n: usize) -> String {
        (0..n)
            .map(|i| line(ip, &format!("/page{i}"), 200, "-", "UA"))
            .collect()
    }

    #[test]
    fn asset_less_ips_flags_a_client_that_fetched_pages_and_no_assets() {
        let log = pages("203.0.113.9", 20);
        assert_eq!(asset_less_ips(&log, 15), vec!["203.0.113.9".to_string()]);
    }

    #[test]
    fn asset_less_ips_ignores_a_client_below_the_page_threshold() {
        let log = pages("203.0.113.9", 5);
        assert!(asset_less_ips(&log, 15).is_empty());
    }

    /// A browser fetches the CSS that goes with the page. One asset is
    /// enough to clear the client.
    #[test]
    fn asset_less_ips_clears_a_client_that_fetched_any_asset() {
        let log = pages("203.0.113.9", 20) + &line("203.0.113.9", "/style.css", 200, "-", "UA");
        assert!(asset_less_ips(&log, 15).is_empty());
    }

    /// The false positive that would hit real, well-behaved visitors: a
    /// returning browser gets 304 Not Modified for every cached asset.
    /// Counting only 200s would make them indistinguishable from scrapers.
    #[test]
    fn asset_less_ips_counts_a_304_as_a_fetched_asset() {
        let log = pages("203.0.113.9", 20) + &line("203.0.113.9", "/app.js", 304, "-", "UA");
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "a cached asset still means the client fetches assets"
        );
    }

    /// Distinct paths, not request count — the client this must not catch
    /// is an API consumer hammering a handful of endpoints.
    #[test]
    fn asset_less_ips_counts_distinct_paths_not_requests() {
        let log: String = (0..50)
            .map(|_| line("203.0.113.9", "/api/status", 200, "-", "UA"))
            .collect();
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "50 hits on one endpoint is not a site crawl"
        );
    }

    #[test]
    fn asset_less_ips_ignores_failed_requests() {
        let log: String = (0..20)
            .map(|i| line("203.0.113.9", &format!("/missing{i}"), 404, "-", "UA"))
            .collect();
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "404 sweeping is scanning_ips' job, not this one"
        );
    }

    #[test]
    fn asset_less_ips_excludes_local_and_private_sources() {
        assert!(asset_less_ips(&pages("10.0.0.5", 20), 15).is_empty());
    }

    #[test]
    fn rotating_user_agent_ips_flags_many_agents_from_one_address() {
        let log: String = (0..10)
            .map(|i| line("203.0.113.9", "/", 200, "-", &format!("Agent{i}")))
            .collect();
        assert_eq!(
            rotating_user_agent_ips(&log, 8),
            vec!["203.0.113.9".to_string()]
        );
    }

    #[test]
    fn rotating_user_agent_ips_ignores_one_agent_used_many_times() {
        let log: String = (0..50)
            .map(|_| line("203.0.113.9", "/", 200, "-", "Mozilla/5.0"))
            .collect();
        assert!(rotating_user_agent_ips(&log, 8).is_empty());
    }

    #[test]
    fn rotating_user_agent_ips_ignores_a_missing_user_agent() {
        // "-" is how NGINX writes an absent header; it isn't an identity.
        let log: String = (0..10)
            .map(|_| line("203.0.113.9", "/", 200, "-", "-"))
            .collect();
        assert!(rotating_user_agent_ips(&log, 8).is_empty());
    }

    #[test]
    fn refererless_crawl_ips_flags_a_deep_crawl_with_no_referer() {
        let log = pages("203.0.113.9", 30);
        assert_eq!(
            refererless_crawl_ips(&log, 25),
            vec!["203.0.113.9".to_string()]
        );
    }

    /// Someone who follows a link has sent a referer at least once; that
    /// clears them entirely, which is what keeps ordinary direct
    /// navigation from accumulating into a false positive.
    #[test]
    fn refererless_crawl_ips_clears_a_client_that_ever_sent_a_referer() {
        let log = pages("203.0.113.9", 30)
            + &line("203.0.113.9", "/other", 200, "https://example.test/", "UA");
        assert!(refererless_crawl_ips(&log, 25).is_empty());
    }

    /// Hitting the front page with no referer is what every bookmark and
    /// typed URL looks like.
    #[test]
    fn refererless_crawl_ips_ignores_the_root_path() {
        let log: String = (0..40)
            .map(|_| line("203.0.113.9", "/", 200, "-", "UA"))
            .collect();
        assert!(refererless_crawl_ips(&log, 25).is_empty());
    }

    #[test]
    fn refererless_crawl_ips_ignores_a_client_below_the_threshold() {
        assert!(refererless_crawl_ips(&pages("203.0.113.9", 5), 25).is_empty());
    }
}
