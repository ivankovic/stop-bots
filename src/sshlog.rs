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
use std::collections::{HashMap, HashSet};
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

/// Longest username kept, in characters.
///
/// The username on a failed-auth line is whatever the client offered, so
/// it is attacker-controlled and unbounded — sshd will happily log a
/// kilobyte of it. Capped here rather than in each front-end so neither
/// has to remember: the TUI draws into fixed-width cells and the web UI
/// into a table column, and a row that pushes every other column off the
/// screen is a defacement even when it is correctly escaped.
const MAX_USERNAME_CHARS: usize = 48;

/// The username offered on a failed-auth line, as the client sent it.
///
/// Deliberately bounded by the *same* `" from "` [`ip_after`] uses, so a
/// line the IP parse rejects is rejected here too and the pair can never
/// come from two different readings of one line. (That boundary is the
/// first `" from "` after `marker`, which means a username containing the
/// literal `" from "` defeats both — see the note on
/// [`failed_attempt_usernames`].)
///
/// Control characters are replaced rather than passed through. sshd
/// escapes non-printables in modern versions, but this parser is pointed
/// at whatever file the admin names, and an escape sequence that reaches
/// the TUI's alternate screen is a corrupted display at best.
fn username_after<'a>(line: &'a str, marker: &str) -> Option<std::borrow::Cow<'a, str>> {
    let marker_at = line.find(marker)?;
    let rest = &line[marker_at..];
    let from_at = rest.find(" from ")?;
    let head = &rest[marker.len()..from_at];

    // `Invalid user <user> from ...` puts the name straight after the
    // marker; `Failed <method> for [invalid user] <user> from ...` puts it
    // after a ` for `, optionally behind sshd's own "invalid user" note.
    let raw = match head.find(" for ") {
        Some(at) => &head[at + " for ".len()..],
        None => head,
    };
    let raw = raw.trim();
    let raw = raw.strip_prefix("invalid user ").unwrap_or(raw).trim();
    if raw.is_empty() {
        return None;
    }

    // Borrowed on the path every real log takes — `root`, `admin`,
    // `oracle` — and rebuilt only for the attacker-authored case the cap
    // and the control-character replacement exist for.
    if raw.len() <= MAX_USERNAME_CHARS
        && raw.is_ascii()
        && !raw.bytes().any(|b| b.is_ascii_control())
    {
        return Some(std::borrow::Cow::Borrowed(raw));
    }

    let mut user: String = raw
        .chars()
        .take(MAX_USERNAME_CHARS)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if raw.chars().count() > MAX_USERNAME_CHARS {
        user.push('\u{2026}');
    }
    Some(std::borrow::Cow::Owned(user))
}

/// The failed-login usernames one address offered, most-tried first.
///
/// One address, not a map of every address, and computed only when a detail
/// view is actually opened. Building the whole map on every refresh cost
/// 138ms on a 120,000-line auth.log — paid by both front-ends on every
/// render, whether or not anyone ever pressed `i`. Scoping it to the one
/// address someone asked about makes the common case free and the rare
/// case a single pass.
///
/// "Which accounts did this client try" is the single most informative
/// thing an SSH log holds about an attacker, and this parser used to read
/// straight past it to get at the address.
///
/// Same exclusions as [`failed_attempt_counts`] — loopback and private
/// addresses, and any address that also logged in successfully — so this
/// can never produce a breakdown for a row the panel itself would not
/// list. An address that fails them comes back empty.
///
/// A username containing the literal `" from "` makes [`ip_after`] fail to
/// find an address at all, so such a line is dropped from *every* count in
/// this module, not merely from this breakdown. That is pre-existing and
/// is a detection weakness rather than a display one — it is recorded in
/// TODO.md rather than worked around here, because narrowing it means
/// changing which lines `scanning_ips` counts.
pub fn failed_attempt_usernames_for(log_text: &str, address: &str) -> Vec<(String, u64)> {
    let Ok(wanted) = address.parse::<IpAddr>() else {
        return Vec::new();
    };
    if is_local_or_private(&wanted) || parse_accepted_ips(log_text).iter().any(|ip| ip == address) {
        return Vec::new();
    }

    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in log_text.lines() {
        let Some(user) = failed_attempt_with_user(line, |ip| *ip == wanted) else {
            continue;
        };
        // Borrow-first: the same handful of account names repeat, and
        // `entry()` would allocate a `String` per repetition to throw away.
        match counts.get_mut(user.as_ref()) {
            Some(count) => *count += 1,
            None => {
                counts.insert(user.into_owned(), 1);
            }
        }
    }

    let mut users: Vec<(String, u64)> = counts.into_iter().collect();
    // Most-tried first, then alphabetical — the same count-descending,
    // key-ascending order the panels themselves use, so a detail view never
    // looks arbitrarily ordered.
    users.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    users
}

/// One failed-auth line's `(address, username)` pair, trying the two
/// markers in the same order [`failed_attempt_ips`] does.
///
/// `wanted` is applied to the address before the username is extracted, so
/// a line for an address the caller is not interested in costs a parse and
/// no allocation.
fn failed_attempt_with_user<'a>(
    line: &'a str,
    wanted: impl Fn(&IpAddr) -> bool,
) -> Option<std::borrow::Cow<'a, str>> {
    for marker in ["Failed ", "Invalid user "] {
        if let Some(ip) = ip_after(line, marker) {
            if !wanted(&ip) {
                return None;
            }
            return username_after(line, marker);
        }
    }
    None
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

/// Shared by [`scanning_ips`] and [`failed_attempt_counts`]: every IP's
/// failed-attempt count in `log_text`, excluding loopback/private addresses
/// (see [`is_local_or_private`]) and any IP that also has a successful
/// login anywhere in the same log (see [`parse_accepted_ips`]) — a few
/// failed attempts before finally getting the password right is a clumsy
/// human, not a bot, and neither caller must ever suggest blocking a client
/// that's proven itself legitimate.
fn candidate_failed_attempt_counts(log_text: &str) -> std::collections::HashMap<IpAddr, usize> {
    let mut counts: std::collections::HashMap<IpAddr, usize> = std::collections::HashMap::new();
    for ip in failed_attempt_ips(log_text) {
        *counts.entry(ip).or_insert(0) += 1;
    }

    let accepted: HashSet<String> = parse_accepted_ips(log_text).into_iter().collect();

    counts
        .into_iter()
        .filter(|(ip, _)| !is_local_or_private(ip) && !accepted.contains(&ip.to_string()))
        .collect()
}

/// Every IP address with at least `threshold` failed-authentication log
/// lines in `log_text` (see [`parse_failed_attempt_ips`] for exactly what
/// counts, and note the threshold is a count over *however much of the log
/// `log_text` happens to hold* — could be a day or a month — not a rate
/// over a time window; this module doesn't parse timestamps, so pick a
/// threshold high enough that ordinary typos never reach it. Real scanners
/// produce dozens to thousands of attempts, not a handful. See
/// [`candidate_failed_attempt_counts`] for the safety exclusions applied
/// before thresholding. Deduplicated and sorted for deterministic output.
pub fn scanning_ips(log_text: &str, threshold: usize) -> Vec<String> {
    let mut ips: Vec<String> = candidate_failed_attempt_counts(log_text)
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .map(|(ip, _)| ip.to_string())
        .collect();
    ips.sort();
    ips
}

/// Every candidate IP's failed-attempt count in `log_text`, with no
/// threshold applied — the raw material behind the Dashboard's "Dynamic
/// Protection" screen, which shows *every* attempting IP ranked by count
/// (not just ones that already cleared `scanning_ips`'s bar) so an admin
/// can act on a rising attacker before it does. Same safety exclusions as
/// `scanning_ips` (see [`candidate_failed_attempt_counts`]): a proven-
/// legitimate client (successful login anywhere in the log) or a
/// loopback/private address is never included, so this can never surface
/// something unsafe to block, only unthresholded.
pub fn failed_attempt_counts(log_text: &str) -> std::collections::HashMap<String, u64> {
    candidate_failed_attempt_counts(log_text)
        .into_iter()
        .map(|(ip, count)| (ip.to_string(), count as u64))
        .collect()
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

    #[test]
    fn failed_attempt_counts_reports_every_candidate_ip_with_no_threshold() {
        let mut log = repeat_failed_attempt("198.51.100.9", 3);
        log.push_str(&repeat_failed_attempt("198.51.100.2", 1));
        let counts = failed_attempt_counts(&log);
        assert_eq!(counts.get("198.51.100.9"), Some(&3));
        assert_eq!(counts.get("198.51.100.2"), Some(&1));
    }

    /// Same safety exclusions as `scanning_ips`, just with no threshold to
    /// also verify: a proven-legitimate client must never show up as a
    /// blockable candidate, no matter how many failed attempts it has.
    #[test]
    fn failed_attempt_counts_excludes_an_ip_that_eventually_logged_in() {
        let mut log = repeat_failed_attempt("198.51.100.9", 10);
        log.push_str("Accepted publickey for admin from 198.51.100.9 port 5555 ssh2\n");
        assert!(failed_attempt_counts(&log).is_empty());
    }

    #[test]
    fn failed_attempt_counts_excludes_loopback_and_private_addresses() {
        let log = repeat_failed_attempt("10.0.0.5", 5);
        assert!(failed_attempt_counts(&log).is_empty());
    }
    #[test]
    fn failed_attempt_usernames_ranks_the_accounts_a_client_tried() {
        let log = "\
Jun 12 01:00:00 h sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2
Jun 12 01:00:01 h sshd[2]: Failed password for root from 198.51.100.1 port 2 ssh2
Jun 12 01:00:02 h sshd[3]: Failed password for invalid user admin from 198.51.100.1 port 3 ssh2
Jun 12 01:00:03 h sshd[4]: Invalid user oracle from 198.51.100.1 port 4
";

        let users = failed_attempt_usernames_for(log, "198.51.100.1");

        assert_eq!(
            users,
            vec![
                ("root".to_string(), 2),
                ("admin".to_string(), 1),
                ("oracle".to_string(), 1),
            ],
            "users was: {users:?}"
        );
    }

    /// The same exclusions the panel itself applies: a client that also
    /// logged in successfully is a clumsy human, and the detail view must
    /// not show a breakdown for a row the panel would never list.
    #[test]
    fn failed_attempt_usernames_skips_a_client_that_also_logged_in() {
        let log = "\
Jun 12 01:00:00 h sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2
Jun 12 01:00:01 h sshd[2]: Accepted publickey for marko from 198.51.100.1 port 2 ssh2
";

        assert!(failed_attempt_usernames_for(log, "198.51.100.1").is_empty());
    }

    /// The username is whatever the client offered, so it is
    /// attacker-controlled: it can be long enough to push every other
    /// column off the screen, and can carry control characters that a
    /// terminal would act on rather than draw.
    #[test]
    fn an_attacker_controlled_username_is_capped_and_stripped_of_control_characters() {
        let log = format!(
            "Failed password for {}\x1b[2J from 198.51.100.1 port 1 ssh2\n",
            "a".repeat(200)
        );

        let users = failed_attempt_usernames_for(&log, "198.51.100.1");
        let name = &users[0].0;

        assert!(
            name.chars().count() <= MAX_USERNAME_CHARS + 1,
            "username was {} chars: {name:?}",
            name.chars().count()
        );
        assert!(
            !name.chars().any(char::is_control),
            "a control character survived: {name:?}"
        );
    }

    /// sshd puts the address last, but the boundary is the *first*
    /// `" from "`, so a username containing it defeats the address parse —
    /// and therefore drops the line from every count in this module, not
    /// just from the breakdown. Pinned as the current behaviour so a later
    /// change to `ip_after` has to decide about it deliberately.
    #[test]
    fn a_username_containing_from_defeats_the_whole_line() {
        let log = "Failed password for invalid user x from y from 198.51.100.1 port 1 ssh2\n";

        assert!(failed_attempt_usernames_for(log, "198.51.100.1").is_empty());
        assert!(parse_failed_attempt_ips(log).is_empty());
    }
}
