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

use crate::ipranges::is_local_or_private;
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
fn parse_line(line: &str) -> Option<(IpAddr, u16, String, String)> {
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
    let user_agent = quoted.get(3).copied().unwrap_or("").to_string();

    Some((ip, status, path, user_agent))
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
    for (ip, status, path, _user_agent) in log_text.lines().filter_map(parse_line) {
        if status == 404 {
            not_found_paths.entry(ip).or_default().insert(path);
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

/// The complement to [`scanning_ips`]: instead of flagging bad traffic,
/// tallies who's actually browsing the site successfully. Counts every
/// distinct user agent's hits across every *successful* (status < 400 —
/// 2xx/3xx) line in `log_text`, from a non-local/private source IP (the
/// same [`is_local_or_private`] exclusion `scanning_ips` uses: an internal
/// health check or monitoring probe isn't a real visitor). Lines with no
/// user agent at all, or the conventional `-` NGINX logs for a missing
/// `User-Agent` header, are excluded — neither identifies an actual client.
/// Feeds [`crate::db::Db::record_user_agent_hits`] via
/// `crate::accessstats::record_access_stats`.
pub fn successful_user_agent_counts(log_text: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for (ip, status, _path, user_agent) in log_text.lines().filter_map(parse_line) {
        if status < 400 && !user_agent.is_empty() && user_agent != "-" && !is_local_or_private(&ip)
        {
            *counts.entry(user_agent).or_insert(0) += 1;
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
    fn parse_line_extracts_ip_status_path_and_user_agent() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"";
        assert_eq!(
            parse_line(line),
            Some((
                "203.0.113.5".parse().unwrap(),
                404,
                "/wp-login.php".to_string(),
                "Mozilla/5.0".to_string()
            ))
        );
    }

    #[test]
    fn parse_line_strips_the_query_string() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /foo?a=1&b=2 HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"";
        assert_eq!(
            parse_line(line).map(|(_, _, path, _)| path),
            Some("/foo".to_string())
        );
    }

    #[test]
    fn parse_line_handles_ipv6_addresses() {
        let line =
            "2001:db8::1 - - [10/Jul/2026:12:00:00 +0000] \"GET /x HTTP/1.1\" 404 1 \"-\" \"UA\"";
        assert_eq!(
            parse_line(line).map(|(ip, _, _, _)| ip),
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
}
