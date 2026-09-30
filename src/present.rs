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

//! How the front-ends put a value into words: relative times, category
//! names and the health strip's one-word labels.
//!
//! Each of these existed several times over — the relative time five times,
//! with three different roundings — and the copies had drifted: the TUI said
//! "Search Bots" where the console said "Search bots", and the two health
//! strips had different words for the same check and labels for different
//! sets of checks. One copy is the only way the CLI, the TUI and the console
//! keep saying the same thing.

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
        _ => check.title,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
