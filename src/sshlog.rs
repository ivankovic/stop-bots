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

use crate::evidence::{Evidence, Item};
use crate::ipranges::is_local_or_private;
use crate::protection::Detector;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Log file paths covering the two dominant Linux SSH log layouts,
/// tried in order: Debian/Ubuntu write to `auth.log`, RHEL/CentOS/Fedora
/// write to `secure`. Neither exists on a systemd-only host that never set
/// up a syslog-to-file bridge — [`SshSource::Search`] falls back to
/// journald for that case.
pub const DEFAULT_LOG_PATHS: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

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

/// Where the SSH log is to be read from.
///
/// Resolved by [`crate::logpaths::LogPaths::ssh`]: a flag, then the stored
/// path, then [`SshSource::Search`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSource {
    /// A file someone named. Read that and nothing else: an explicit path
    /// that is wrong should say so, not quietly read something else.
    File(PathBuf),
    /// Nothing named: the first of [`DEFAULT_LOG_PATHS`] that can be
    /// opened, and journald if none can.
    Search,
}

/// Where an [`SshSource`] turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    File(PathBuf),
    Journal,
}

/// The key the journal's read cursor is stored under (see
/// `db::keys::log_cursor`).
pub const JOURNAL_SOURCE: &str = "journald:sshd+ssh";

impl SshSource {
    /// Where to read. A named file is itself whether or not it can be
    /// opened; a search takes the first default file that can be, and
    /// otherwise the journal, which only a read can tell apart from
    /// nothing.
    pub fn locate(&self) -> Located {
        let defaults: Vec<PathBuf> = DEFAULT_LOG_PATHS.iter().map(PathBuf::from).collect();
        self.locate_among(&defaults)
    }

    /// [`Self::locate`], searching `search` rather than
    /// [`DEFAULT_LOG_PATHS`].
    pub fn locate_among(&self, search: &[PathBuf]) -> Located {
        match self {
            SshSource::File(path) => Located::File(path.clone()),
            SshSource::Search => search
                .iter()
                .find(|path| std::fs::File::open(path).is_ok())
                .map(|path| Located::File(path.clone()))
                .unwrap_or(Located::Journal),
        }
    }

    /// The authentication lines of this log, as one text, for the readers
    /// that want the whole of it once: the lockout guard, the Firewall
    /// screens and the one-off CLI commands.
    ///
    /// A file is read whole, since logrotate bounds it. The journal is not
    /// bounded by anything, and used to be read whole on every one of
    /// those calls; it is read from `since` on. Either way only the lines
    /// [`parse_auth_line`] reads are kept, which on a busy host is a small
    /// part of the log and is all any of these readers look at.
    pub fn read(&self, since: i64) -> LogSource {
        match self.locate() {
            Located::File(path) => {
                let mut text = String::new();
                match crate::logread::read_whole(&path, &mut |line| keep_auth(&mut text, line)) {
                    Ok(()) => LogSource::Found(text),
                    Err(_) => LogSource::Unavailable,
                }
            }
            Located::Journal => self.read_journal_with(Path::new("journalctl"), since),
        }
    }

    /// The journal half of [`Self::read`], with `journalctl` named, so a
    /// test can stand one in.
    fn read_journal_with(&self, journalctl: &Path, since: i64) -> LogSource {
        let query = crate::logread::JournalQuery {
            program: journalctl,
            units: SSHD_UNIT_NAMES,
            after_cursor: None,
            since: Some(since),
            last: None,
        };
        let mut text = String::new();
        // Nothing at all from journald is how an unprivileged `journalctl`
        // answers, so it is "could not read", as it always was, rather than
        // "read, and nobody logged in".
        match crate::logread::read_journal(&query, &mut |line| keep_auth(&mut text, line)) {
            Ok(read) if read.lines > 0 => LogSource::Found(text),
            _ => LogSource::Unavailable,
        }
    }

    /// Whether anything can be read from this log, without reading it: for
    /// the health check, which used to read the whole journal to find out.
    pub fn is_readable(&self) -> bool {
        match self.locate() {
            Located::File(path) => std::fs::File::open(path).is_ok(),
            Located::Journal => {
                let query = crate::logread::JournalQuery {
                    program: Path::new("journalctl"),
                    units: SSHD_UNIT_NAMES,
                    after_cursor: None,
                    since: None,
                    last: Some(1),
                };
                crate::logread::read_journal(&query, &mut |_| {}).is_ok_and(|read| read.lines > 0)
            }
        }
    }
}

/// How far back the whole-log readers ([`SshSource::read`]) look into the
/// journal: the anti-lockout window, a week, which is about what a
/// weekly-rotated `auth.log` holds and every login the guard protects.
pub fn recent_since() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    now - crate::db::SSH_LOGIN_WINDOW_SECONDS
}

/// Appends `line` to `text` if it is one [`parse_auth_line`] reads.
fn keep_auth(text: &mut String, line: &str) {
    if parse_auth_line(line).is_some() {
        text.push_str(line);
        text.push('\n');
    }
}

/// The units whose journal is the SSH log, for [`crate::logscan`].
pub fn journal_units() -> &'static [&'static str] {
    SSHD_UNIT_NAMES
}

/// Reads SSH log lines one at a time into what the pipeline keeps from
/// them: evidence for the scanner detector, and every address that logged
/// in.
pub struct Observer {
    /// The oldest time a failed login may carry and still count, or `None`
    /// when the scanner detector is off and no evidence is wanted.
    cutoff: Option<i64>,
    now: i64,
    /// When an undated line happened, if a read can say.
    undated: Option<i64>,
    /// The host's offset from UTC, taken once per read: a syslog time is
    /// local, and asking the C library for every line would cost more than
    /// the parse.
    offset: i64,
    evidence: Evidence,
    accepted: std::collections::BTreeSet<String>,
    lines: usize,
}

impl Observer {
    /// `cutoff`: see [`Observer::cutoff`]. `undated`: the time to give a
    /// line that carries none, which only a read of what was just
    /// appended can say; a first read passes `None` and such lines count
    /// for nothing.
    pub fn new(cutoff: Option<i64>, now: i64, undated: Option<i64>) -> Observer {
        Observer::with_offset(cutoff, now, undated, crate::logtime::local_offset(now))
    }

    fn with_offset(cutoff: Option<i64>, now: i64, undated: Option<i64>, offset: i64) -> Observer {
        Observer {
            cutoff,
            now,
            undated,
            offset,
            evidence: Evidence::default(),
            accepted: Default::default(),
            lines: 0,
        }
    }

    pub fn line(&mut self, text: &str) {
        let Some(auth) = parse_auth_line(text) else {
            return;
        };
        self.lines += 1;
        if auth.kind == AuthKind::Accepted {
            self.accepted.insert(auth.ip.to_string());
            return;
        }
        let Some(cutoff) = self.cutoff else {
            return;
        };
        if is_local_or_private(&auth.ip) {
            return;
        }
        let offset = self.offset;
        let at = crate::logtime::syslog_line(text, self.now, &|_| offset)
            .or(self.undated)
            .map(|at| at.min(self.now));
        if let Some(at) = at.filter(|at| *at >= cutoff) {
            self.evidence
                .add(Detector::SshScanners, auth.ip, Item::bucket(at), at);
        }
    }

    /// The evidence, every address that logged in (sorted), and how many
    /// authentication lines were read.
    pub fn finish(self) -> (Evidence, Vec<String>, usize) {
        (
            self.evidence,
            self.accepted.into_iter().collect(),
            self.lines,
        )
    }
}

/// The three sshd messages this module reads, by the word they open with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    /// `Accepted <method> for <user> from <ip> port <n> ssh2[: <key>]`
    Accepted,
    /// `Failed <method> for [invalid user ]<user> from <ip> port <n> ssh2`
    Failed,
    /// `Invalid user <user> from <ip> port <n>`, logged before any auth
    /// method is tried.
    InvalidUser,
}

/// One authentication line, read the way sshd wrote it.
struct AuthLine<'a> {
    kind: AuthKind,
    /// As the client sent it: unbounded, and possibly empty. See
    /// [`display_username`] before showing it to anyone.
    user: &'a str,
    ip: IpAddr,
}

/// Parses one line as an sshd authentication message, or `None` for any
/// other line.
///
/// **The username is attacker-chosen and sshd logs it verbatim, spaces
/// included**, so this reads the line from where sshd's message begins
/// rather than searching it for markers. A search is what this used to do,
/// and it let a failed login as the user `Accepted` read as a successful
/// login — a week-long Allow rule ahead of every other firewall rule — and
/// a username like `x from 198.51.100.50 port 22` credit its failures to
/// an uninvolved address for the scanner detector to block.
///
/// Two anchors do the work. The message must *begin* with its marker (see
/// [`sshd_message`] for where a message begins), and the address is the
/// *last* `from <ip> port <n>`: everything the client controls is to its
/// left, and what follows the port is sshd's own. The one exception is a
/// certificate ID in an `Accepted` line's key info, which is to the right
/// and is chosen by whoever the admin's own CA signed it for.
///
/// The address is parsed as a real [`IpAddr`] (not just "non-empty") so
/// callers that go on to store it as a firewall rule never hand a
/// malformed value to [`crate::db::Db::add_firewall_rule`]. Nothing here
/// indexes the line directly: it is attacker-shaped text, and a panic here
/// under the web console's database lock poisons it.
fn parse_auth_line(line: &str) -> Option<AuthLine<'_>> {
    let message = sshd_message(line)?;
    let (kind, rest) = if let Some(rest) = message.strip_prefix("Accepted ") {
        (AuthKind::Accepted, rest)
    } else if let Some(rest) = message.strip_prefix("Failed ") {
        (AuthKind::Failed, rest)
    } else {
        (
            AuthKind::InvalidUser,
            message.strip_prefix("Invalid user ")?,
        )
    };

    let (head, ip) = split_address(rest)?;
    let user = match kind {
        AuthKind::InvalidUser => head,
        AuthKind::Accepted | AuthKind::Failed => {
            // `<method> for <user>`. The method is sshd's own and has no
            // spaces (`password`, `keyboard-interactive/pam`), so the first
            // space ends it whatever the username holds.
            let (method, after) = head.split_once(' ')?;
            let user = after.strip_prefix("for ")?;
            if method.is_empty() {
                return None;
            }
            match kind {
                AuthKind::Failed => user.strip_prefix("invalid user ").unwrap_or(user),
                _ => user,
            }
        }
    };
    Some(AuthLine { kind, user, ip })
}

/// Splits `<head> from <ip> port <n>[ <tail>]` at its *last* ` from `,
/// returning the head and the address.
///
/// Only the last one is tried. sshd's own is always last and always parses,
/// so falling back to an earlier candidate could only ever find one the
/// client wrote.
fn split_address(rest: &str) -> Option<(&str, IpAddr)> {
    let at = rest.rfind(" from ")?;
    let after = rest.get(at + " from ".len()..)?;
    let (address, after_address) = after.split_once(" port ")?;
    let port_len = after_address
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_address.len());
    let tail = after_address.get(port_len..)?;
    if port_len == 0 || !(tail.is_empty() || tail.starts_with(' ')) {
        return None;
    }
    Some((rest.get(..at)?, address.parse().ok()?))
}

/// Where sshd's own message begins in `line`, if `line` came from sshd.
///
/// Two shapes. A bare message, as `journalctl -o cat` prints it, opens
/// with one of the markers and is taken whole: a file written that way is
/// one someone chose to point `--ssh-log` at. A syslog line (`auth.log`,
/// `secure`, and the journal as this project reads it, `-o short-iso`)
/// carries a prefix — `Jun 12 01:02:03 host sshd[123]: `, or an RFC 3339
/// timestamp in place of the first three fields — and the message starts
/// right after the first `": "`. Nothing before that is client-controlled,
/// and neither timestamp form contains `": "`, so the first one is the end
/// of the program tag, which must be `sshd[<pid>]` or, on newer OpenSSH,
/// `sshd-session[<pid>]`.
///
/// **Requiring the tag raises the bar; it does not make these lines
/// trustworthy.** Any local user can write to the auth log with `logger`,
/// and `logger -t 'sshd[1]'` produces a line this cannot tell from sshd's
/// own. Nothing reading a text file can. The tag keeps out the plain
/// `logger "Accepted ..."`, and lines other programs log about SSH.
///
/// rsyslog's `message repeated N times: [ ... ]` is unwrapped, so a burst
/// of identical failures still counts (once, as it did before this parser
/// read lines from their start).
fn sshd_message(line: &str) -> Option<&str> {
    const MARKERS: [&str; 3] = ["Accepted ", "Failed ", "Invalid user "];
    if MARKERS.iter().any(|marker| line.starts_with(marker)) {
        return Some(line);
    }

    let (prefix, message) = line.split_once(": ")?;
    let tag = prefix.rsplit(' ').next()?;
    let pid = tag
        .strip_prefix("sshd[")
        .or_else(|| tag.strip_prefix("sshd-session["))?
        .strip_suffix(']')?;
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let repeated = message
        .strip_prefix("message repeated ")
        .and_then(|rest| rest.split_once(" times: [ "))
        .filter(|(count, _)| !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|(_, inner)| inner.strip_suffix(']'));
    Some(repeated.unwrap_or(message))
}

/// Extracts the client IP from every successful-login line in `log_text`,
/// deduplicated and sorted for deterministic output. Matches sshd's own
/// `Accepted <method> for <user> from <ip> port <port> ...` message —
/// identical whether it arrives via classic syslog (with a leading
/// timestamp/hostname/pid prefix, as in `/var/log/auth.log`,
/// `/var/log/secure` or `journalctl -o short-iso`) or bare (`journalctl -o
/// cat`), since both just carry sshd's own message text verbatim; one
/// parser covers both. Deliberately keyed on a message that *opens with*
/// `"Accepted "` (see [`parse_auth_line`]), not on `" from "` or on the word
/// appearing anywhere — sshd also logs failed attempts and disconnects
/// with their own `from <ip>` text, and a client picks its own username,
/// and none of those must ever count as a successful, currently-reachable
/// session.
pub fn parse_accepted_ips(log_text: &str) -> Vec<String> {
    let mut ips: Vec<String> = log_text
        .lines()
        .filter_map(parse_auth_line)
        .filter(|auth| auth.kind == AuthKind::Accepted)
        .map(|auth| auth.ip.to_string())
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
        .filter_map(parse_auth_line)
        .filter(|auth| auth.kind != AuthKind::Accepted)
        .map(|auth| auth.ip)
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

/// A failed-auth line's username as it is safe to show: capped, with
/// control characters replaced and invisible ones written out
/// ([`crate::present::terminal_safe`]). `None` for an empty one.
///
/// Takes the username [`parse_auth_line`] split out, so the address and
/// the name always come from one reading of the line.
///
/// Control characters are replaced rather than passed through. sshd
/// escapes non-printables in modern versions, but this parser is pointed
/// at whatever file the admin names, and an escape sequence that reaches
/// the TUI's alternate screen is a corrupted display at best.
fn display_username(raw: &str) -> Option<std::borrow::Cow<'_, str>> {
    let raw = raw.trim();
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

    let mut user = String::with_capacity(raw.len().min(MAX_USERNAME_CHARS * 4));
    for c in raw.chars().take(MAX_USERNAME_CHARS) {
        crate::present::push_terminal_safe(&mut user, c);
    }
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
/// A username containing the literal `" from "` is listed whole: the
/// address is the *last* `from <ip> port <n>` on the line (see
/// [`parse_auth_line`]), so nothing the client typed can move it.
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

/// One failed-auth line's username, if its address is `wanted`.
///
/// `wanted` is applied to the address before the username is cleaned up,
/// so a line for an address the caller is not interested in costs a parse
/// and no allocation.
fn failed_attempt_with_user<'a>(
    line: &'a str,
    wanted: impl Fn(&IpAddr) -> bool,
) -> Option<std::borrow::Cow<'a, str>> {
    let auth = parse_auth_line(line)?;
    if auth.kind == AuthKind::Accepted || !wanted(&auth.ip) {
        return None;
    }
    display_username(auth.user)
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
/// `log_text` happens to hold* — could be a day or a month. This is the
/// one-off form behind `block-scanners`, which reads the log it is given;
/// the scheduled detector counts only inside its window (see
/// [`Observer`] and `crate::evidence`). Pick a threshold high enough that
/// ordinary typos never reach it. Real scanners
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

    /// A named file that is not there is unavailable: nothing else is
    /// read in its place.
    #[test]
    fn a_named_log_that_is_missing_is_unavailable() {
        assert_eq!(
            SshSource::File("/nonexistent/does-not-exist.log".into()).read(0),
            LogSource::Unavailable
        );
    }

    #[test]
    fn a_named_log_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.log");
        std::fs::write(&path, "Accepted publickey for a from 1.2.3.4 port 1 ssh2\n").unwrap();

        match SshSource::File(path).read(0) {
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

    /// sshd puts the address last, so a username containing `" from "` is
    /// read whole and the line still counts against the real address.
    #[test]
    fn a_username_containing_from_is_read_whole() {
        let log = "Failed password for invalid user x from y from 198.51.100.1 port 1 ssh2\n";

        assert_eq!(
            failed_attempt_usernames_for(log, "198.51.100.1"),
            vec![("x from y".to_string(), 1)]
        );
        assert_eq!(parse_failed_attempt_ips(log), vec!["198.51.100.1"]);
    }

    // ---- hostile usernames ----
    //
    // The username is the one field of these lines the client chooses, and
    // sshd logs it verbatim, spaces and all. Each case below is a username
    // shaped like the text around it, so that a parser that searches for
    // its markers rather than reading the line from the start credits the
    // wrong address — or, for `Accepted`, hands an attacker a week-long
    // Allow rule ahead of every other firewall rule.

    /// Where the line was logged from: bare (`journalctl -o cat`), classic
    /// syslog, and the RFC 3339 syslog Debian writes, with the
    /// `sshd-session` tag newer OpenSSH logs under.
    const PREFIXES: &[&str] = &[
        "",
        "Jun 12 01:00:00 host sshd[4242]: ",
        "2026-06-12T01:00:00.123456+00:00 host sshd-session[4242]: ",
    ];

    const HOSTILE_USERNAMES: &[&str] = &[
        "Accepted",
        "Failed",
        "Invalid user",
        "x from 198.51.100.50 port 22",
        "Accepted x from 203.0.113.66 port 1",
        "Accepted x for y from 203.0.113.66 port 1 ssh2",
    ];

    /// The address the connection really came from in every hostile case.
    const REAL: &str = "192.0.2.77";

    #[test]
    fn a_hostile_username_on_a_failed_line_is_credited_to_the_real_address() {
        for prefix in PREFIXES {
            for user in HOSTILE_USERNAMES {
                for line in [
                    format!("{prefix}Invalid user {user} from {REAL} port 5555"),
                    format!(
                        "{prefix}Failed password for invalid user {user} from {REAL} port 5555 ssh2"
                    ),
                    format!("{prefix}Failed password for {user} from {REAL} port 5555 ssh2"),
                ] {
                    assert_eq!(
                        parse_failed_attempt_ips(&line),
                        vec![REAL],
                        "line was: {line}"
                    );
                    assert!(
                        parse_accepted_ips(&line).is_empty(),
                        "a failed login read as a successful one: {line}"
                    );
                    assert_eq!(
                        failed_attempt_usernames_for(&line, REAL),
                        vec![(user.to_string(), 1)],
                        "line was: {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_hostile_username_on_an_accepted_line_still_names_the_real_address() {
        for prefix in PREFIXES {
            for user in HOSTILE_USERNAMES {
                let line =
                    format!("{prefix}Accepted password for {user} from {REAL} port 5555 ssh2");
                assert_eq!(parse_accepted_ips(&line), vec![REAL], "line was: {line}");
                assert!(
                    parse_failed_attempt_ips(&line).is_empty(),
                    "a successful login counted as a failure: {line}"
                );
            }
        }
    }

    /// The marker has to *begin* sshd's message. sshd logs plenty of other
    /// messages that carry the username too, and one of them spelling
    /// `Accepted ... from <ip> port <n>` is not a login.
    #[test]
    fn a_marker_that_does_not_begin_the_message_does_not_count() {
        let user = "Accepted publickey for x from 203.0.113.66 port 1 ssh2";
        for prefix in PREFIXES {
            let line =
                format!("{prefix}Disconnected from invalid user {user} {REAL} port 5555 [preauth]");
            assert!(parse_accepted_ips(&line).is_empty(), "line was: {line}");
            assert!(
                parse_failed_attempt_ips(&line).is_empty(),
                "line was: {line}"
            );
        }
    }

    /// Any local user can write to auth.log through `logger`. Requiring
    /// sshd's own program tag keeps a plain `logger "Accepted ..."` out;
    /// see [`sshd_message`] for what it cannot keep out.
    #[test]
    fn a_line_from_another_program_does_not_count() {
        for line in [
            "Jun 12 01:00:00 host marko: Accepted password for x from 203.0.113.66 port 1 ssh2",
            "Jun 12 01:00:00 host sudo[77]: Failed password for x from 203.0.113.66 port 1 ssh2",
            "Jun 12 01:00:00 host notsshd[77]: Invalid user x from 203.0.113.66 port 1",
            "Jun 12 01:00:00 host sshd[]: Invalid user x from 203.0.113.66 port 1",
        ] {
            assert!(parse_accepted_ips(line).is_empty(), "line was: {line}");
            assert!(
                parse_failed_attempt_ips(line).is_empty(),
                "line was: {line}"
            );
        }
    }

    /// rsyslog folds a burst of identical lines into one of these. The
    /// wrapped message still begins at a fixed place, so reading it keeps
    /// the anchor rather than loosening it.
    #[test]
    fn a_repeated_message_summary_is_read_as_the_message_it_repeats() {
        let log = "Jun 12 01:00:00 host sshd[1]: message repeated 5 times: \
                   [ Failed password for root from 198.51.100.8 port 22 ssh2]";

        assert_eq!(parse_failed_attempt_ips(log), vec!["198.51.100.8"]);
    }

    /// Slicing between the marker and the first `" from "` used to panic
    /// here, and a panic under the web console's database lock poisons it.
    #[test]
    fn a_username_that_is_itself_a_marker_does_not_panic() {
        let log = "Invalid user Failed from 203.0.113.9 port 5555\n\
                   Invalid user Invalid from 203.0.113.9 port 5555\n\
                   Invalid user  from 203.0.113.9 port 5555\n\
                   Failed none for invalid user  from 203.0.113.9 port 5555 ssh2\n\
                   Failed  from 203.0.113.9 port 5555\n\
                   Invalid user from 203.0.113.9 port 5555\n\
                   Invalid user\n\
                   Failed\n";

        let users = failed_attempt_usernames_for(log, "203.0.113.9");

        assert_eq!(
            users,
            vec![("Failed".to_string(), 1), ("Invalid".to_string(), 1)],
            "users was: {users:?}"
        );
    }

    /// An empty username is still a failed attempt from that address; it
    /// just has no name to list.
    #[test]
    fn an_empty_username_still_counts_the_attempt() {
        let log = "Invalid user  from 203.0.113.9 port 5555\n\
                   Failed none for invalid user  from 203.0.113.9 port 5555 ssh2\n";

        assert_eq!(parse_failed_attempt_ips(log).len(), 2);
    }

    /// A port that is not all digits is not sshd's `port <n>`, so that
    /// occurrence is not the address.
    #[test]
    fn the_address_must_be_followed_by_a_numeric_port() {
        let log = "Invalid user x from 203.0.113.9 port 22x";
        assert!(parse_failed_attempt_ips(log).is_empty());
    }

    /// One byte that is not UTF-8 — a client can put one in a username —
    /// must not make the whole log unreadable until it rotates.
    #[test]
    fn a_log_with_invalid_utf8_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.log");
        let mut bytes = b"Invalid user \xff\xfe from 198.51.100.4 port 1\n".to_vec();
        bytes.extend_from_slice(b"Accepted publickey for a from 192.0.2.4 port 1 ssh2\n");
        std::fs::write(&path, bytes).unwrap();

        let LogSource::Found(text) = SshSource::File(path).read(0) else {
            panic!("a log with one invalid byte was reported unavailable");
        };
        assert_eq!(parse_accepted_ips(&text), vec!["192.0.2.4"]);
        assert_eq!(parse_failed_attempt_ips(&text), vec!["198.51.100.4"]);
    }

    // ---- the observer the log pass reads with ----

    /// 2026-09-28T06:33:01Z.
    const SEP_28: i64 = 1_790_577_181;

    fn observed(lines: &[&str], observer: Observer) -> (Evidence, Vec<String>) {
        let mut observer = observer;
        for line in lines {
            observer.line(line);
        }
        let (evidence, logins, _) = observer.finish();
        (evidence, logins)
    }

    fn failures_kept(evidence: &Evidence) -> Vec<(String, i64)> {
        let mut rows: Vec<(String, i64)> = evidence
            .rows_for(Detector::SshScanners)
            .into_iter()
            .map(|row| (row.address, row.tally.first))
            .collect();
        rows.sort();
        rows
    }

    /// Syslog writes local time: two hours east of UTC, 08:33 is 06:33Z.
    #[test]
    fn a_syslog_line_is_dated_with_the_host_s_offset() {
        let (evidence, _) = observed(
            &["Sep 28 08:33:01 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"],
            Observer::with_offset(Some(0), SEP_28 + 60, None, 2 * 3600),
        );
        assert_eq!(
            failures_kept(&evidence),
            [("203.0.113.5".to_string(), SEP_28)]
        );
    }

    /// Read at ten past midnight on New Year's Day, a failure from a minute
    /// before midnight is eleven minutes old, not a year in the future.
    #[test]
    fn a_failure_from_last_year_s_last_minute_counts_on_new_year_s_day() {
        let new_year = 1_798_761_600 + 600; // 2027-01-01T00:10:00Z
        let (evidence, _) = observed(
            &["Dec 31 23:59:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"],
            Observer::with_offset(Some(new_year - 86_400), new_year, None, 0),
        );
        assert_eq!(
            failures_kept(&evidence),
            [("203.0.113.5".to_string(), new_year - 660)]
        );
    }

    #[test]
    fn a_failure_older_than_the_window_is_not_kept_but_a_login_always_is() {
        let (evidence, logins) = observed(
            &[
                "2026-09-26T06:33:01+00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
                "2026-09-26T06:33:02+00:00 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2",
                "2026-09-28T06:00:00+00:00 host sshd[1]: Invalid user x from 198.51.100.7 port 3",
            ],
            Observer::with_offset(Some(SEP_28 - 86_400), SEP_28, None, 0),
        );
        assert_eq!(
            failures_kept(&evidence),
            [("198.51.100.7".to_string(), SEP_28 - 1981)]
        );
        assert_eq!(logins, ["192.0.2.10"]);
    }

    /// `journalctl -o cat` wrote no time. On a first read that could be
    /// anything; on a later one, it was appended since the last.
    #[test]
    fn an_undated_failure_counts_only_when_the_read_can_date_it() {
        let line = "Failed password for root from 203.0.113.5 port 1 ssh2";
        let (first, _) = observed(&[line], Observer::with_offset(Some(0), SEP_28, None, 0));
        assert!(first.is_empty());
        let (later, _) = observed(
            &[line],
            Observer::with_offset(Some(0), SEP_28, Some(SEP_28), 0),
        );
        assert_eq!(failures_kept(&later).len(), 1);
    }

    /// With the scanner detector off, no evidence is kept at all; the
    /// logins are still wanted for the anti-lockout window.
    #[test]
    fn with_the_detector_off_only_logins_are_kept() {
        let (evidence, logins) = observed(
            &[
                "2026-09-28T06:00:00+00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2",
                "2026-09-28T06:00:01+00:00 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2",
            ],
            Observer::with_offset(None, SEP_28, None, 0),
        );
        assert!(evidence.is_empty());
        assert_eq!(logins, ["192.0.2.10"]);
    }

    /// The whole-log readers keep only the lines they read, so a busy
    /// auth.log costs its authentication lines, not the whole file.
    #[test]
    fn a_whole_read_keeps_only_authentication_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.log");
        std::fs::write(
            &path,
            "Sep 28 06:00:00 host CRON[9]: pam_unix(cron:session): session opened\n\
             Sep 28 06:00:01 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n",
        )
        .unwrap();

        let LogSource::Found(text) = SshSource::File(path).read(0) else {
            panic!("the file is there");
        };

        assert_eq!(
            text,
            "Sep 28 06:00:01 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n"
        );
    }

    /// The journal is read back only as far as it is asked, where it used
    /// to be read whole on every Firewall page view and every guard.
    #[test]
    fn a_whole_read_of_the_journal_asks_only_for_its_window() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("journalctl");
        std::fs::write(
            &program,
            "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args\"\n\
             echo '2026-09-28T06:00:01+0000 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2'\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let search = SshSource::Search;
        assert_eq!(
            search.locate_among(&[dir.path().join("no-auth.log")]),
            Located::Journal
        );

        let LogSource::Found(text) = search.read_journal_with(&program, 1_790_000_000) else {
            panic!("the fake journal answered");
        };

        assert!(text.contains("192.0.2.10"), "{text}");
        let args = std::fs::read_to_string(dir.path().join("args")).unwrap();
        assert!(args.contains("--since=@1790000000"), "{args}");
        assert!(args.contains("-o short-iso"), "{args}");
    }
}
