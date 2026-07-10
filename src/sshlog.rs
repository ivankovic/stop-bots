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

//! Best-effort, read-only integration with common Linux SSH server logs.
//! Two consumers: `main.rs::render_firewall`'s lockout safety check (before
//! writing a firewall script that would block an IP address with a recent
//! successful SSH login, warn loudly rather than silently generating
//! something that could cut off remote access) and `main.rs::block_scanners`
//! (find IPs with a pile of failed authentication attempts — the signature
//! of an automated scanner/brute-force bot — and add them as firewall Block
//! rules). This module never writes to, rotates, truncates or otherwise
//! touches any log — it only ever reads.

use crate::ipranges::is_local_or_private;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

/// Log file paths covering the two dominant Linux SSH log layouts,
/// tried in order: Debian/Ubuntu write to `auth.log`, RHEL/CentOS/Fedora
/// write to `secure`. Neither exists on a systemd-only host that never set
/// up a syslog-to-file bridge — [`find_default_source`] falls back to
/// `journalctl` for that case.
const DEFAULT_LOG_PATHS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

/// sshd's systemd unit is named `sshd` on RHEL-derived distros and `ssh` on
/// Debian-derived ones.
const SSHD_UNIT_NAMES: &[&str] = &["sshd", "ssh"];

/// The result of looking for SSH log data: distinguishes "we found and read
/// a source, here's its text" from "nothing was even readable" — the
/// caller treats the latter as "couldn't check" (worth telling the admin
/// about) rather than "checked and it's clear".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    Found(String),
    Unavailable,
}

/// Reads `path` directly, bypassing auto-detection entirely — backs the
/// CLI's `--ssh-log` override, for containers/non-standard log locations
/// and for deterministic tests that can't rely on whatever happens to be in
/// the real system logs.
pub fn read_log_file(path: &Path) -> LogSource {
    match std::fs::read_to_string(path) {
        Ok(content) => LogSource::Found(content),
        Err(_) => LogSource::Unavailable,
    }
}

/// Tries every default log file path, then falls back to `journalctl` for
/// each common sshd unit name. Best-effort throughout: a missing file, a
/// permission error (these logs are typically root/`adm`-group-only), or a
/// missing `journalctl` binary all just mean "try the next one" — none of
/// them is treated as a hard error.
pub fn find_default_source() -> LogSource {
    for path in DEFAULT_LOG_PATHS {
        if let LogSource::Found(content) = read_log_file(Path::new(path)) {
            return LogSource::Found(content);
        }
    }
    for unit in SSHD_UNIT_NAMES {
        if let Ok(output) = Command::new("journalctl")
            .args(["-u", unit, "-o", "cat", "--no-pager"])
            .output()
        {
            if output.status.success() && !output.stdout.is_empty() {
                return LogSource::Found(String::from_utf8_lossy(&output.stdout).into_owned());
            }
        }
    }
    LogSource::Unavailable
}

/// Finds `marker` in `line`, then extracts the address between the next
/// `" from "` and `" port "` after it — the shape sshd uses for both
/// successful and failed auth lines alike (`Accepted ... from <ip> port
/// ...`, `Failed ... for ... from <ip> port ...`, `Invalid user ... from
/// <ip> port ...`). Requires `marker` to appear *before* `" from "` so e.g.
/// a `"Failed "` search never matches straight past an unrelated later
/// occurrence in the same line. Parses the extracted token as an actual
/// [`IpAddr`] (not just "non-empty") so callers that go on to store this as
/// a firewall rule address never hand a malformed value to
/// [`crate::db::Db::add_firewall_rule`].
fn ip_after(line: &str, marker: &str) -> Option<IpAddr> {
    let marker_at = line.find(marker)?;
    let rest = &line[marker_at..];
    let from_at = rest.find(" from ")? + " from ".len();
    let after_from = &rest[from_at..];
    let end = after_from.find(" port ")?;
    after_from[..end].trim().parse().ok()
}

/// Extracts the client IP from every successful-login line in `log_text`,
/// deduplicated and sorted for deterministic output. Matches sshd's own
/// `Accepted <method> for <user> from <ip> port <port> ...` message —
/// identical whether it arrives via classic syslog (with a leading
/// timestamp/hostname/pid prefix, as in `/var/log/auth.log` or
/// `/var/log/secure`) or `journalctl -o cat` (which strips that prefix),
/// since both just carry sshd's own message text verbatim; one parser
/// covers both. Deliberately keyed on the literal `"Accepted "` prefix, not
/// just `" from "` — sshd also logs *failed* attempts and disconnects with
/// their own `from <ip>` text (`Failed password for ... from ...`,
/// `Received disconnect from ...`), which must never count as a successful,
/// currently-reachable session.
pub fn parse_accepted_ips(log_text: &str) -> Vec<String> {
    let mut ips: Vec<String> = log_text
        .lines()
        .filter_map(|line| ip_after(line, "Accepted "))
        .map(|ip| ip.to_string())
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

/// Extracts the client IP (as a real [`IpAddr`], not yet stringified) from
/// every failed-authentication line in `log_text`, one entry per line (not
/// deduplicated — [`scanning_ips`] counts these). Covers sshd's two failure
/// shapes: `Failed password/publickey/keyboard-interactive/none for
/// [invalid user] <user> from <ip> port <port> ssh2` and the standalone
/// `Invalid user <user> from <ip> port <port>` logged before any auth
/// method is even tried. A single invalid-user attempt typically produces
/// *both* lines (sshd logs the `Invalid user` notice, then still runs —
/// and fails — the auth exchange), so this deliberately counts each log
/// line rather than each attempt: it's a cruder signal, but consistent with
/// [`scanning_ips`] treating its threshold as "log lines seen", not
/// "distinct connection attempts".
fn failed_attempt_ips(log_text: &str) -> Vec<IpAddr> {
    log_text
        .lines()
        .filter_map(|line| ip_after(line, "Failed ").or_else(|| ip_after(line, "Invalid user ")))
        .collect()
}

/// The `String` form of [`failed_attempt_ips`], for callers outside this
/// module (e.g. tests, or a future CLI inspection command) that don't need
/// the parsed [`IpAddr`].
pub fn parse_failed_attempt_ips(log_text: &str) -> Vec<String> {
    failed_attempt_ips(log_text)
        .into_iter()
        .map(|ip| ip.to_string())
        .collect()
}

/// Every IP address with at least `threshold` failed-authentication log
/// lines in `log_text` (see [`parse_failed_attempt_ips`] for exactly what
/// counts, and note the threshold is a count over *however much of the log
/// `log_text` happens to hold* — could be a day or a month — not a rate
/// over a time window; this module doesn't parse timestamps, so pick a
/// threshold high enough that ordinary typos never reach it. Real scanners
/// produce dozens to thousands of attempts, not a handful. Two safety
/// exclusions on top of the threshold: an IP that also has a successful
/// login anywhere in the same log (see [`parse_accepted_ips`]) is never
/// included — a few failed attempts before finally getting the password
/// right is a clumsy human, not a bot, and this must never suggest blocking
/// a client that's proven itself legitimate — and loopback/private IPs (see
/// [`is_local_or_private`]) are excluded outright. Deduplicated and sorted
/// for deterministic output.
pub fn scanning_ips(log_text: &str, threshold: usize) -> Vec<String> {
    let mut counts: std::collections::HashMap<IpAddr, usize> = std::collections::HashMap::new();
    for ip in failed_attempt_ips(log_text) {
        *counts.entry(ip).or_insert(0) += 1;
    }

    let accepted: HashSet<String> = parse_accepted_ips(log_text).into_iter().collect();

    let mut ips: Vec<String> = counts
        .into_iter()
        .filter(|(ip, count)| *count >= threshold && !is_local_or_private(ip))
        .map(|(ip, _)| ip.to_string())
        .filter(|ip| !accepted.contains(ip))
        .collect();
    ips.sort();
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepted_ips_extracts_from_syslog_style_lines() {
        let log = "\
Jun 12 01:02:03 host sshd[111]: Accepted publickey for alice from 203.0.113.5 port 54321 ssh2: ED25519 SHA256:abc
Jun 12 01:03:00 host sshd[112]: Accepted password for bob from 198.51.100.7 port 22334 ssh2
";
        assert_eq!(
            parse_accepted_ips(log),
            vec!["198.51.100.7".to_string(), "203.0.113.5".to_string()]
        );
    }

    #[test]
    fn parse_accepted_ips_extracts_from_journalctl_style_lines_with_no_prefix() {
        // journalctl -o cat strips the timestamp/hostname/pid prefix but
        // keeps sshd's own message text verbatim.
        let log = "Accepted publickey for root from 192.0.2.9 port 443 ssh2: RSA SHA256:xyz";
        assert_eq!(parse_accepted_ips(log), vec!["192.0.2.9".to_string()]);
    }

    #[test]
    fn parse_accepted_ips_ignores_failed_attempts_and_disconnects() {
        let log = "\
Jun 12 01:00:00 host sshd[100]: Failed password for root from 198.51.100.1 port 4444 ssh2
Jun 12 01:00:01 host sshd[100]: Received disconnect from 198.51.100.1 port 4444:11: disconnected by user
Jun 12 01:00:02 host sshd[100]: Connection closed by authenticating user root 198.51.100.1 port 4444 [preauth]
";
        assert!(parse_accepted_ips(log).is_empty());
    }

    #[test]
    fn parse_accepted_ips_dedupes_repeated_logins_from_the_same_ip() {
        let log = "\
Accepted publickey for alice from 203.0.113.5 port 1 ssh2
Accepted publickey for alice from 203.0.113.5 port 2 ssh2
";
        assert_eq!(parse_accepted_ips(log), vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn parse_accepted_ips_handles_ipv6_addresses() {
        let log = "Accepted publickey for alice from 2001:db8::1 port 54321 ssh2: ED25519";
        assert_eq!(parse_accepted_ips(log), vec!["2001:db8::1".to_string()]);
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
        let path = dir.path().join("auth.log");
        std::fs::write(&path, "Accepted publickey for a from 1.2.3.4 port 1 ssh2\n").unwrap();

        match read_log_file(&path) {
            LogSource::Found(content) => assert!(content.contains("1.2.3.4")),
            LogSource::Unavailable => panic!("expected the file to be readable"),
        }
    }

    #[test]
    fn parse_failed_attempt_ips_extracts_valid_and_invalid_user_variants() {
        let log = "\
Jun 12 01:00:00 host sshd[1]: Failed password for root from 198.51.100.1 port 4444 ssh2
Jun 12 01:00:01 host sshd[2]: Failed password for invalid user admin from 198.51.100.2 port 4445 ssh2
";
        assert_eq!(
            parse_failed_attempt_ips(log),
            vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()]
        );
    }

    #[test]
    fn parse_failed_attempt_ips_extracts_standalone_invalid_user_lines() {
        // Logged before any auth method is even attempted — no "Failed "
        // prefix at all, just "Invalid user ... from <ip> port <port>".
        let log = "Jun 12 01:00:00 host sshd[1]: Invalid user test from 198.51.100.3 port 4446";
        assert_eq!(
            parse_failed_attempt_ips(log),
            vec!["198.51.100.3".to_string()]
        );
    }

    #[test]
    fn parse_failed_attempt_ips_handles_ipv6_addresses() {
        let log = "Failed password for root from 2001:db8::dead port 4444 ssh2";
        assert_eq!(
            parse_failed_attempt_ips(log),
            vec!["2001:db8::dead".to_string()]
        );
    }

    #[test]
    fn parse_failed_attempt_ips_ignores_garbage_that_cant_parse_as_an_ip() {
        // ip_after now parses the extracted token as a real IpAddr, so a
        // malformed or DNS-name "from" field (shouldn't happen with sshd's
        // real output, but defends against it anyway) is simply skipped
        // rather than handed on to a firewall rule insert.
        let log = "Failed password for root from not-an-ip port 4444 ssh2";
        assert!(parse_failed_attempt_ips(log).is_empty());
    }

    fn repeat_failed_attempt(ip: &str, times: usize) -> String {
        format!("Failed password for root from {ip} port 4444 ssh2\n").repeat(times)
    }

    #[test]
    fn scanning_ips_flags_an_ip_at_or_above_the_threshold() {
        let log = repeat_failed_attempt("198.51.100.9", 10);
        assert_eq!(scanning_ips(&log, 10), vec!["198.51.100.9".to_string()]);
    }

    #[test]
    fn scanning_ips_ignores_an_ip_below_the_threshold() {
        let log = repeat_failed_attempt("198.51.100.9", 9);
        assert!(scanning_ips(&log, 10).is_empty());
    }

    /// The critical safety property: an IP that eventually logs in
    /// successfully must never be flagged, no matter how many failed
    /// attempts preceded it — it's proven itself a legitimate, currently-
    /// reachable client, and auto-blocking it would risk a lockout.
    #[test]
    fn scanning_ips_excludes_an_ip_that_eventually_logged_in() {
        let mut log = repeat_failed_attempt("198.51.100.9", 10);
        log.push_str("Accepted publickey for admin from 198.51.100.9 port 5555 ssh2\n");
        assert!(scanning_ips(&log, 10).is_empty());
    }

    #[test]
    fn scanning_ips_excludes_loopback_and_private_addresses() {
        let mut log = repeat_failed_attempt("127.0.0.1", 10);
        log.push_str(&repeat_failed_attempt("10.0.0.5", 10));
        log.push_str(&repeat_failed_attempt("192.168.1.5", 10));
        log.push_str(&repeat_failed_attempt("fc00::1", 10));
        log.push_str(&repeat_failed_attempt("::1", 10));
        assert!(scanning_ips(&log, 10).is_empty());
    }

    #[test]
    fn scanning_ips_is_sorted_and_deduplicated() {
        let mut log = repeat_failed_attempt("198.51.100.9", 10);
        log.push_str(&repeat_failed_attempt("198.51.100.2", 10));
        assert_eq!(
            scanning_ips(&log, 10),
            vec!["198.51.100.2".to_string(), "198.51.100.9".to_string()]
        );
    }
}
