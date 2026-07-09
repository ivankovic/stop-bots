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
//! The only consumer is `main.rs::render_firewall`'s lockout safety check:
//! before writing a firewall script that would block an IP address with a
//! recent successful SSH login, warn loudly rather than silently generating
//! something that could cut off remote access. This module never writes to,
//! rotates, truncates or otherwise touches any log — it only ever reads.

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
        .filter_map(|line| {
            let accepted_at = line.find("Accepted ")?;
            let rest = &line[accepted_at..];
            let from_at = rest.find(" from ")? + " from ".len();
            let after_from = &rest[from_at..];
            let end = after_from.find(" port ")?;
            let ip = after_from[..end].trim();
            (!ip.is_empty()).then(|| ip.to_string())
        })
        .collect();
    ips.sort();
    ips.dedup();
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
}
