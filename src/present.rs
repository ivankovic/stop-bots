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

//! How the front-ends put a value into words: relative times, category
//! names and the health strip's one-word labels.
//!
//! Each of these existed several times over — the relative time five times,
//! with three different roundings — and the copies had drifted: the TUI said
//! "Search Bots" where the console said "Search bots", and the two health
//! strips had different words for the same check and labels for different
//! sets of checks. One copy is the only way the CLI, the TUI and the console
//! keep saying the same thing.
//!
//! And how anything reaches a terminal at all: [`terminal_safe`] for one
//! value, and the [`say!`](crate::say) family, which every line the
//! program prints goes through. `clippy.toml` forbids `println!` and its
//! siblings, so a new command cannot print a database value raw.

use std::borrow::Cow;

use crate::db::Category;
use crate::health::Check;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// `at` (a unix time in the past) relative to now: "just now", "5m ago",
/// "3h ago", "2d ago" — coarser the further back it is.
pub fn ago(at: i64) -> String {
    ago_from(at, now_secs())
}

/// [`ago`], as of `now`. A time in the future reads as "just now": clocks
/// between two processes writing the same database disagree by seconds.
pub fn ago_from(at: i64, now: i64) -> String {
    let elapsed = (now - at).max(0);
    if elapsed < 60 {
        "just now".to_string()
    } else if elapsed < 3_600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("{}h ago", elapsed / 3_600)
    } else {
        format!("{}d ago", elapsed / 86_400)
    }
}

/// A category's name, as a row label or inside a message. Sentence case,
/// like every other label in both front-ends.
pub fn category_label(category: Category) -> &'static str {
    match category {
        Category::Scanner => "Scanners",
        Category::Search => "Search bots",
        Category::Ai => "AI bots",
    }
}

/// The one word a health check gets in the status strip under the tabs
/// and in the console's header chips, which have room for a word and not
/// for the check's title. Falls back to the title for a check this table
/// has not heard of; `every_health_check_has_a_short_label` is what stops
/// that fallback from being reached.
pub fn check_label(check: &Check) -> &'static str {
    match check.id {
        "firewall-enforced" => "kernel",
        "firewall-persists" => "reboot",
        "script-fresh" => "script",
        "nginx-applied" => "nginx",
        "generated-files-reachable" => "files",
        "turned-away-clients" => "refused",
        "service-health" => "console",
        "console-account" => "account",
        "console-helper" => "helper",
        "console-log-access" => "log access",
        "disk-room" => "disk",
        "database-size" => "database",
        "log-sources" => "logs",
        "access-log-format" => "log format",
        "access-log-clients" => "clients",
        "cdn-edges" => "cdn",
        "nginx-deployment" => "runtime",
        "firewall-reaches-containers" => "containers",
        "ssh-login-allowlist" => "ssh",
        "trusted" => "trusted",
        "skipped-entries" => "skipped",
        "web-proxy" => "proxy",
        _ => check.title,
    }
}

/// `text` with every control character replaced by U+FFFD, and every
/// invisible formatting character written out as `\u{200B}`, so that it
/// can be shown to a person in a terminal, pasted into a shell, or drawn
/// in a browser and mean what it looks like.
///
/// Every control character goes: C0 (newline and tab included), DEL and
/// C1. Much of what is printed is attacker-chosen: a user agent, a path,
/// a username from a log, or a row that the console (which runs
/// unprivileged) wrote into the database that root's CLI reads. An ESC
/// can carry an OSC 52 clipboard write or a title change into the
/// operator's shell, some terminals act on a lone U+009B as a CSI, a CR
/// makes `real\rfake` print as `fake`, and a newline forges a second row.
///
/// The invisible ones are shown rather than dropped, because they are the
/// point: a right-to-left override makes `Googlebot/2.1 (evil)` draw as
/// something else, and a zero-width space makes two strings that look
/// identical different. A browser escapes neither — both are text, not
/// markup — so this is the only place they are caught. See
/// [`is_invisible_format`].
///
/// Uncapped: the CLI's `list-*` commands print the whole string so an
/// operator can copy it into `trust`. Borrowed when there is nothing to
/// replace, which is nearly always.
pub fn terminal_safe(text: &str) -> Cow<'_, str> {
    rewrite(text, false)
}

/// [`terminal_safe`] for a whole message the program laid out: newlines
/// and tabs are kept, because the program put them there, and everything
/// else [`terminal_safe`] replaces is replaced.
///
/// What [`say!`](crate::say) and the top-level error printer apply. It
/// cannot tell a newline the program wrote from one a value carried, so a
/// value that must stay on its own line is also passed through
/// [`terminal_safe`] where it is formatted.
pub fn terminal_safe_text(text: &str) -> Cow<'_, str> {
    rewrite(text, true)
}

fn rewrite(text: &str, keep_layout: bool) -> Cow<'_, str> {
    let changes = |c: char| {
        (c.is_control() && !(keep_layout && matches!(c, '\n' | '\t'))) || is_invisible_format(c)
    };
    if !text.chars().any(changes) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if changes(c) {
            push_terminal_safe(&mut out, c);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// One character of [`terminal_safe`]'s output, for a caller that caps
/// the string as it goes.
pub(crate) fn push_terminal_safe(out: &mut String, c: char) {
    if c.is_control() {
        out.push('\u{fffd}');
    } else if is_invisible_format(c) {
        out.push_str(&format!("\\u{{{:X}}}", c as u32));
    } else {
        out.push(c);
    }
}

/// `text` with each control character replaced by U+FFFD and nothing else
/// changed. Not for showing: [`terminal_safe`] is. This is for a string
/// that is stored and compared, where a control character means something
/// to the format (a stored key that starts with a newline is not a
/// client's), and where writing an invisible character out would change
/// which keys that an older version stored still match.
pub fn without_controls(text: &str) -> Cow<'_, str> {
    if text.chars().any(char::is_control) {
        text.chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect::<String>()
            .into()
    } else {
        text.into()
    }
}

/// Characters that change how the text around them is drawn, or take up
/// no room at all, without being drawn themselves.
///
/// The bidirectional controls [`crate::blocks`] already strips from what
/// it stores, and then the rest of Unicode's format (`Cf`) category and
/// the other zero-width or blank-looking characters a spoof would reach
/// for: the zero-width space, joiners and word joiner, the byte-order
/// mark, the soft hyphen, line and paragraph separators, the Hangul
/// fillers, the invisible math operators and the tag characters. Not the
/// variation selectors, which an emoji legitimately carries and which
/// change nothing about the letters around them.
pub fn is_invisible_format(c: char) -> bool {
    crate::blocks::is_direction_control(c)
        || matches!(
            c,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{115f}'..='\u{1160}'
                | '\u{17b4}'..='\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{3164}'
                | '\u{feff}'
                | '\u{ffa0}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// Where [`say!`](crate::say) and its siblings write.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// What [`say!`](crate::say), [`say_err!`](crate::say_err) and
/// [`say_inline!`](crate::say_inline) expand to: the formatted message,
/// through [`terminal_safe_text`], to `stream`. A write that fails panics,
/// exactly as `println!` does.
#[doc(hidden)]
#[allow(clippy::disallowed_macros)]
pub fn write_safe(args: std::fmt::Arguments<'_>, stream: Stream, newline: bool) {
    let text = match args.as_str() {
        Some(literal) => Cow::Borrowed(literal),
        None => Cow::Owned(args.to_string()),
    };
    let safe = terminal_safe_text(&text);
    match (stream, newline) {
        (Stream::Stdout, true) => println!("{safe}"),
        (Stream::Stdout, false) => print!("{safe}"),
        (Stream::Stderr, true) => eprintln!("{safe}"),
        (Stream::Stderr, false) => eprint!("{safe}"),
    }
}

/// `println!`, made safe for a terminal: the formatted line goes through
/// [`terminal_safe_text`](crate::present::terminal_safe_text), so a control
/// character or a direction override that a value carried is replaced or
/// written out, while the newlines and tabs of the layout survive.
///
/// The program prints with this, never with `println!`, which
/// `clippy.toml` forbids, so the gate fails on a command that forgets.
/// A sanitising writer installed under stdout once in `main` was the
/// alternative, and std has no such hook: `println!` writes to a stdout
/// that cannot be replaced, short of piping file descriptor 1 through a
/// thread. That would take the terminal away from the TUI, lose whatever
/// is buffered when the process exits early, and strip the colour from
/// clap's `--help`, the one place this program emits escapes on purpose.
#[macro_export]
macro_rules! say {
    () => {
        $crate::present::write_safe(
            ::std::format_args!(""),
            $crate::present::Stream::Stdout,
            true,
        )
    };
    ($($arg:tt)*) => {
        $crate::present::write_safe(
            ::std::format_args!($($arg)*),
            $crate::present::Stream::Stdout,
            true,
        )
    };
}

/// [`say!`] without the newline: `print!`, made safe for a terminal.
#[macro_export]
macro_rules! say_inline {
    ($($arg:tt)*) => {
        $crate::present::write_safe(
            ::std::format_args!($($arg)*),
            $crate::present::Stream::Stdout,
            false,
        )
    };
}

/// [`say!`] to stderr: `eprintln!`, made safe for a terminal.
#[macro_export]
macro_rules! say_err {
    () => {
        $crate::present::write_safe(
            ::std::format_args!(""),
            $crate::present::Stream::Stderr,
            true,
        )
    };
    ($($arg:tt)*) => {
        $crate::present::write_safe(
            ::std::format_args!($($arg)*),
            $crate::present::Stream::Stderr,
            true,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C1 controls as well as C0: some terminals act on a lone U+009B as a
    /// CSI, which is as good as an ESC `[`. And a CR, which lets the end
    /// of a value print over its start.
    #[test]
    fn terminal_safe_replaces_every_control_character_and_nothing_else() {
        let cases = [
            (
                "Mozilla/5.0 (X11; Linux) Gecko/20100101 Firefox/128.0",
                None,
            ),
            ("a\u{1b}]0;title\u{7}b", Some("a\u{fffd}]0;title\u{fffd}b")),
            ("a\u{9b}2Jb", Some("a\u{fffd}2Jb")),
            ("tab\there", Some("tab\u{fffd}here")),
            ("real\rfake", Some("real\u{fffd}fake")),
            ("two\nlines", Some("two\u{fffd}lines")),
            ("del\u{7f}", Some("del\u{fffd}")),
            ("naïve café 日本 🙂\u{fe0f}", None),
        ];
        for (input, replaced) in cases {
            let out = terminal_safe(input);
            match replaced {
                None => assert!(
                    matches!(out, Cow::Borrowed(s) if s == input),
                    "a clean string should come back untouched: {out:?}"
                ),
                Some(expected) => assert_eq!(out, expected, "input was {input:?}"),
            }
        }
    }

    /// A right-to-left override makes a string draw in an order other than
    /// the one it has, and a zero-width space makes two strings that look
    /// the same different; a browser escapes neither. Both are written out
    /// where the operator can see them.
    #[test]
    fn invisible_formatting_characters_are_written_out_not_drawn() {
        for (input, expected) in [
            (
                "Googlebot/2.1\u{202e}lmth.tob",
                "Googlebot/2.1\\u{202E}lmth.tob",
            ),
            ("Google\u{200b}bot", "Google\\u{200B}bot"),
            ("\u{feff}curl/8", "\\u{FEFF}curl/8"),
            ("a\u{2066}b\u{2069}c", "a\\u{2066}b\\u{2069}c"),
            ("soft\u{ad}hyphen", "soft\\u{AD}hyphen"),
            ("line\u{2028}break", "line\\u{2028}break"),
            ("tag\u{e0041}", "tag\\u{E0041}"),
        ] {
            assert_eq!(terminal_safe(input), expected, "input was {input:?}");
            assert_eq!(terminal_safe_text(input), expected, "input was {input:?}");
        }
    }

    /// The layout a message was given survives the boundary; nothing else
    /// a value could carry does.
    #[test]
    fn a_whole_message_keeps_its_newlines_and_tabs_and_loses_the_rest() {
        for (input, expected) in [
            ("  [OK] title\n      detail\tmore", None),
            (
                "a\u{1b}]0;PWNED\u{7}\nb",
                Some("a\u{fffd}]0;PWNED\u{fffd}\nb"),
            ),
            ("real\rfake\n", Some("real\u{fffd}fake\n")),
            ("x\u{9b}31m\u{202e}y", Some("x\u{fffd}31m\\u{202E}y")),
        ] {
            let out = terminal_safe_text(input);
            match expected {
                None => assert!(matches!(out, Cow::Borrowed(_)), "was {out:?}"),
                Some(expected) => assert_eq!(out, expected, "input was {input:?}"),
            }
        }
    }

    /// For stored keys: a control character goes and an invisible one
    /// stays, so a key an older version stored still matches.
    #[test]
    fn without_controls_leaves_invisible_characters_alone() {
        assert_eq!(without_controls("a\nb\u{202e}c"), "a\u{fffd}b\u{202e}c");
        assert!(matches!(without_controls("plain"), Cow::Borrowed(_)));
    }

    #[test]
    fn a_relative_time_rounds_to_the_coarsest_useful_unit() {
        let now = 1_000_000;
        for (at, expected) in [
            (now, "just now"),
            (now - 59, "just now"),
            (now + 30, "just now"),
            (now - 90, "1m ago"),
            (now - 5 * 60, "5m ago"),
            (now - 3 * 3_600, "3h ago"),
            (now - 2 * 86_400, "2d ago"),
        ] {
            assert_eq!(ago_from(at, now), expected, "{} seconds back", now - at);
        }
    }

    /// One casing, whichever front-end asks: the TUI used to say "Search
    /// Bots" and the console "Search bots".
    #[test]
    fn category_labels_are_in_sentence_case() {
        assert_eq!(
            [Category::Scanner, Category::Search, Category::Ai].map(category_label),
            ["Scanners", "Search bots", "AI bots"]
        );
    }

    /// The checks a default probe produces are not all of them: several
    /// appear only on a host that has something to report. Every id
    /// `health` can produce, read from its source, has a word.
    #[test]
    fn every_check_id_in_health_has_a_short_label() {
        let source: &'static str = include_str!("health.rs");
        let ids: Vec<&'static str> = source
            .split("id: \"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert!(ids.len() > 15, "found only {ids:?}");
        for id in ids {
            let check = Check {
                id,
                title: "a title",
                level: crate::health::Level::Ok,
                detail: String::new(),
                fix: None,
            };
            assert_ne!(check_label(&check), "a title", "{id} has no label");
        }
    }

    /// Every check the report can produce needs a one-word name: the strip
    /// is a single line across every screen, and a title falling through
    /// is both longer than its neighbours and in a different style. The
    /// fallback keeps that readable rather than right, so without this
    /// nothing notices a new check arriving without a label — which is
    /// what happened when the database-size check was added.
    #[test]
    fn every_health_check_has_a_short_label() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let report = crate::health::assess(&db, &crate::health::Probe::default()).unwrap();

        assert!(!report.checks.is_empty(), "no checks to speak of");
        for check in &report.checks {
            assert_ne!(
                check_label(check),
                check.title,
                "{} fell through to its title",
                check.id
            );
        }
    }
}
