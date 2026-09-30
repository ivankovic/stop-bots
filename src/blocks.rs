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

//! Why a firewall rule exists: who wrote it, and the log line that made
//! them.
//!
//! Every stored rule carries a [`RuleSource`] and, where there was one, a
//! line of evidence. The Blocks screens in both front-ends and
//! `list-firewall-rules` show them; `remove-firewall-rule --source` and
//! "unblock all from this source" act on them.
//!
//! **An operator's unblock sticks.** Making a block spends the evidence
//! behind it (see `crate::evidence`), but what the address did *while*
//! blocked — the block not yet applied, or a range the kernel never saw —
//! is still inside the window, and the one-off `block-*` commands read a
//! whole log. Removing the block alone would see it re-added on the next
//! pass. Removing a rule a detector wrote therefore does two things: it
//! spends the address's evidence up to now, as a block would, and it
//! records the address as unblocked by hand (see
//! `Db::unblocked_addresses`), which every detector skips for as long as
//! the block was meant to last. After that only a new offence brings it
//! back. Trusting it is the permanent answer, and the screens say so.

use crate::protection::Detector;

/// The longest evidence line stored, in bytes.
///
/// It is the client's text — a request line, a user agent, a username
/// sshd logged verbatim — so it is capped at storage, where every writer
/// passes, rather than in each screen that shows it.
pub const MAX_EVIDENCE_BYTES: usize = 300;

/// Who wrote a firewall rule.
///
/// Stored as text in `firewall_rules.source` (see [`RuleSource::stored`]);
/// a rule written before 0.1 has none, which every screen shows as
/// "before 0.1" rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleSource {
    /// One of the log detectors.
    Detector(Detector),
    /// `add-firewall-rule`.
    Cli,
    /// A block key in the TUI.
    Tui,
    /// A block button in the web console.
    Web,
    /// Never stored: the Allow every recent successful SSH login gets
    /// (`firewall::ssh_allow_rules`).
    SshLogin,
    /// Never stored: the Allow a trusted address gets (`trust`).
    Trusted,
    /// Never stored: a range from a downloaded list or the geo selection.
    List,
    /// Never stored: the private ranges shielded from downloaded lists.
    Private,
    /// A stored value this version does not know. Nothing writes it; it
    /// is what an unrecognised row reads as, rather than a failed read.
    Unknown,
}

impl RuleSource {
    /// Every source a stored rule can have, for filters and help text, in
    /// the order a person would look for them: the detectors, then the
    /// three front-ends.
    pub fn stored_sources() -> Vec<RuleSource> {
        let mut all: Vec<RuleSource> = Detector::ALL.into_iter().map(Self::Detector).collect();
        all.extend([RuleSource::Cli, RuleSource::Tui, RuleSource::Web]);
        all
    }

    /// What goes in `firewall_rules.source`. A detector is stored by its
    /// id, which is already frozen as a settings key and a cron job id.
    pub fn stored(self) -> &'static str {
        match self {
            RuleSource::Detector(detector) => detector.id(),
            RuleSource::Cli => "cli",
            RuleSource::Tui => "tui",
            RuleSource::Web => "web",
            RuleSource::SshLogin => "ssh-login",
            RuleSource::Trusted => "trusted",
            RuleSource::List => "list",
            RuleSource::Private => "private",
            RuleSource::Unknown => "unknown",
        }
    }

    pub fn from_stored(stored: &str) -> RuleSource {
        if let Some(detector) = Detector::from_id(stored) {
            return RuleSource::Detector(detector);
        }
        match stored {
            "cli" => RuleSource::Cli,
            "tui" => RuleSource::Tui,
            "web" => RuleSource::Web,
            "ssh-login" => RuleSource::SshLogin,
            "trusted" => RuleSource::Trusted,
            "list" => RuleSource::List,
            "private" => RuleSource::Private,
            _ => RuleSource::Unknown,
        }
    }

    /// The name a person types and reads: a detector by the name
    /// `set-detector` takes, anything else as stored.
    pub fn name(self) -> &'static str {
        match self {
            RuleSource::Detector(detector) => detector_name(detector),
            other => other.stored(),
        }
    }

    /// Accepts [`Self::name`] or [`Self::stored`], for the command line.
    pub fn from_name(name: &str) -> Option<RuleSource> {
        let name = name.trim();
        if let Some(detector) = Detector::ALL
            .into_iter()
            .find(|d| detector_name(*d) == name || d.id() == name)
        {
            return Some(RuleSource::Detector(detector));
        }
        match RuleSource::from_stored(name) {
            RuleSource::Unknown => None,
            known => Some(known),
        }
    }

    /// A few words for a screen.
    pub fn label(self) -> &'static str {
        match self {
            RuleSource::Detector(detector) => detector.spec().label,
            RuleSource::Cli => "by hand (CLI)",
            RuleSource::Tui => "by hand (TUI)",
            RuleSource::Web => "by hand (web)",
            RuleSource::SshLogin => "SSH login",
            RuleSource::Trusted => "trusted",
            RuleSource::List => "downloaded list",
            RuleSource::Private => "private range",
            RuleSource::Unknown => "unknown",
        }
    }

    pub fn detector(self) -> Option<Detector> {
        match self {
            RuleSource::Detector(detector) => Some(detector),
            _ => None,
        }
    }
}

/// How the command line names a detector.
///
/// Exhaustive on purpose: a detector added to `Detector::ALL` without a
/// name is a compile error, not one `set-detector` and `--source` cannot
/// reach.
pub fn detector_name(detector: Detector) -> &'static str {
    match detector {
        Detector::SshScanners => "ssh-scanners",
        Detector::WebScanners => "web-scanners",
        Detector::SpoofedCrawlers => "spoofed-crawlers",
        Detector::ProbePaths => "probe-paths",
        Detector::Injection => "injection",
        Detector::Honeypot => "honeypot",
        Detector::AssetRatio => "asset-ratio",
        Detector::RotatingUserAgent => "rotating-ua",
        Detector::RefererlessCrawl => "refererless",
        Detector::RobotsTxt => "robots-txt",
    }
}

/// What a rule written before 0.1, with no source, is called — on screen
/// and as a `--source` value.
pub const LEGACY_NAME: &str = "before-0.1";

/// Which rules a Blocks view or a bulk removal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceFilter {
    Source(RuleSource),
    /// Rules with no source: written before 0.1.
    Legacy,
}

impl SourceFilter {
    /// Parses a `--source` value or a web filter: a source's name or
    /// stored id, or [`LEGACY_NAME`].
    pub fn parse(value: &str) -> Option<SourceFilter> {
        if value.trim() == LEGACY_NAME {
            return Some(SourceFilter::Legacy);
        }
        RuleSource::from_name(value).map(SourceFilter::Source)
    }

    pub fn name(self) -> &'static str {
        match self {
            SourceFilter::Source(source) => source.name(),
            SourceFilter::Legacy => LEGACY_NAME,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SourceFilter::Source(source) => source.label(),
            SourceFilter::Legacy => "before 0.1",
        }
    }

    pub fn matches(self, source: Option<RuleSource>) -> bool {
        match self {
            SourceFilter::Source(wanted) => source == Some(wanted),
            SourceFilter::Legacy => source.is_none(),
        }
    }
}

/// How a rule's source reads on screen, "before 0.1" for none.
pub fn source_label(source: Option<RuleSource>) -> &'static str {
    source.map_or("before 0.1", RuleSource::label)
}

/// How a rule's source reads where it has to be one token (the CLI, a
/// filter link): its name, or [`LEGACY_NAME`].
pub fn source_name(source: Option<RuleSource>) -> &'static str {
    source.map_or(LEGACY_NAME, RuleSource::name)
}

/// `text` as it is safe to store and show: one line, no control
/// characters, at most [`MAX_EVIDENCE_BYTES`].
///
/// Evidence is attacker-supplied. A request line or user agent can carry
/// escape sequences that would drive the operator's terminal, newlines
/// that would forge a second line in `list-firewall-rules`, and Unicode
/// direction overrides that make one address read as another. Each is
/// replaced by `?`, and runs of whitespace become one space. `None` when
/// nothing is left.
pub fn evidence_line(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len().min(MAX_EVIDENCE_BYTES));
    let mut last_space = true;
    for c in text.chars() {
        let c = if c.is_whitespace() {
            ' '
        } else if c.is_control() || is_direction_control(c) {
            '?'
        } else {
            c
        };
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        if out.len() + c.len_utf8() > MAX_EVIDENCE_BYTES - '…'.len_utf8() {
            out.push('…');
            return Some(out);
        }
        out.push(c);
    }
    let trimmed = out.trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The Unicode bidirectional formatting characters, which reorder what is
/// drawn without being drawn themselves.
fn is_direction_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// How long ago `at` (Unix seconds) was, as "5m", "3h" or "2d".
pub fn format_age(at: i64, now: i64) -> String {
    let seconds = (now - at).max(0);
    if seconds < 3_600 {
        format!("{}m", (seconds / 60).max(1))
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_round_trips_through_its_stored_form_and_its_name() {
        for source in RuleSource::stored_sources().into_iter().chain([
            RuleSource::SshLogin,
            RuleSource::Trusted,
            RuleSource::List,
            RuleSource::Private,
        ]) {
            assert_eq!(RuleSource::from_stored(source.stored()), source);
            assert_eq!(RuleSource::from_name(source.name()), Some(source));
            assert_eq!(RuleSource::from_name(source.stored()), Some(source));
        }
    }

    /// The stored form of a detector is its settings id, frozen since
    /// 0.0.x; the name is what `set-detector` takes.
    #[test]
    fn a_detector_is_stored_by_id_and_named_as_set_detector_names_it() {
        let source = RuleSource::Detector(Detector::SshScanners);
        assert_eq!(source.stored(), "block_scanners");
        assert_eq!(source.name(), "ssh-scanners");
    }

    #[test]
    fn an_unrecognised_stored_value_reads_as_unknown_and_is_not_a_name() {
        assert_eq!(
            RuleSource::from_stored("from-the-future"),
            RuleSource::Unknown
        );
        assert_eq!(RuleSource::from_name("from-the-future"), None);
        assert_eq!(RuleSource::from_name("unknown"), None);
    }

    #[test]
    fn a_rule_with_no_source_is_before_0_1_everywhere() {
        assert_eq!(source_label(None), "before 0.1");
        assert_eq!(source_name(None), LEGACY_NAME);
        assert_eq!(SourceFilter::parse(LEGACY_NAME), Some(SourceFilter::Legacy));
        assert!(SourceFilter::Legacy.matches(None));
        assert!(!SourceFilter::Legacy.matches(Some(RuleSource::Cli)));
    }

    #[test]
    fn evidence_is_one_line_with_no_control_characters() {
        for (raw, expected) in [
            ("GET /.env HTTP/1.1", Some("GET /.env HTTP/1.1")),
            ("GET /\x1b[2J HTTP/1.1", Some("GET /?[2J HTTP/1.1")),
            ("a\r\nforged line", Some("a forged line")),
            ("tab\there", Some("tab here")),
            ("\u{202e}1.2.3.4", Some("?1.2.3.4")),
            ("del\u{7f}", Some("del?")),
            ("   ", None),
            ("", None),
        ] {
            assert_eq!(evidence_line(raw).as_deref(), expected, "{raw:?}");
        }
    }

    #[test]
    fn long_evidence_is_cut_at_a_character_boundary_and_marked() {
        let long = "é".repeat(400);
        let line = evidence_line(&long).unwrap();
        assert!(line.len() <= MAX_EVIDENCE_BYTES, "{} bytes", line.len());
        assert!(line.ends_with('…'), "{line}");
    }

    #[test]
    fn ages_read_in_the_largest_whole_unit() {
        let now = 1_000_000;
        for (ago, expected) in [(10, "1m"), (600, "10m"), (7_200, "2h"), (3 * 86_400, "3d")] {
            assert_eq!(format_age(now - ago, now), expected, "{ago}s ago");
        }
    }
}
