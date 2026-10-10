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

//! Downloads and normalizes the [ArcJet Well-Known Bots] list, the original
//! bot-list source used to populate the database with known scanners,
//! search engines and AI crawlers. See sibling modules (`ai_robots_txt`,
//! `nginx_bad_bots`) for the other sources `SourceKind` dispatches to.
//!
//! Fetching (network IO) and parsing (pure) are kept separate so that parsing
//! can be exercised in tests with a local fixture file, without ever hitting
//! the network.
//!
//! [ArcJet Well-Known Bots]: https://github.com/arcjet/well-known-bots

use crate::db::NewBot;
use anyhow::{Context, Result};
use serde::Deserialize;

pub const SOURCE_ID: &str = "well-known-bots";
pub const SOURCE_NAME: &str = "ArcJet Well-Known Bots";
pub const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json";

#[derive(Debug, Deserialize)]
struct RawBot {
    id: String,
    #[serde(default)]
    categories: Vec<String>,
    pattern: RawPattern,
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    #[serde(default)]
    accepted: Vec<String>,
}

/// Turns a bot slug such as `google-crawler` into a human-readable name such
/// as `Google Crawler`.
fn humanize(slug: &str) -> String {
    slug.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parses the raw well-known-bots JSON document into [`NewBot`] records.
/// Bots with no usable user-agent pattern are skipped. A pattern that
/// `botlist::keeps_pattern` refuses is dropped: one containing a `"`, one
/// that is not a regex NGINX would compile (ending in a backslash, `[z-a]`),
/// and one that would match every visitor, such as `""`.
/// Each accepted pattern is checked on its own, before they are joined, so
/// one bad entry costs that entry rather than the bot.
pub fn parse(json: &str) -> Result<Vec<NewBot>> {
    parse_counted(json).map(|parsed| parsed.bots)
}

/// [`parse`], and how many accepted patterns it left out.
pub fn parse_counted(json: &str) -> Result<crate::botlist::Parsed> {
    let raw: Vec<RawBot> = serde_json::from_str(json).context("failed to parse bot list JSON")?;

    let mut skipped = 0;
    let bots = raw
        .into_iter()
        .filter_map(|b| {
            let (patterns, left_out) = crate::botlist::kept_patterns(b.pattern.accepted);
            skipped += left_out;
            if patterns.is_empty() {
                return None;
            }
            Some(NewBot {
                slug: b.id.clone(),
                name: humanize(&b.id),
                is_ai: b.categories.iter().any(|c| c == "ai"),
                is_search_engine: b.categories.iter().any(|c| c == "search-engine"),
                is_scanner: false,
                user_agent_pattern: patterns.join("|"),
                source_id: SOURCE_ID.to_string(),
            })
        })
        .collect();

    Ok(crate::botlist::Parsed { bots, skipped })
}

/// Downloads the raw well-known-bots JSON document over HTTP.
pub async fn fetch() -> Result<String> {
    crate::fetch::text(SOURCE_URL, "the well-known-bots list").await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../tests/fixtures/botlists/well-known-bots-sample.json");

    #[test]
    fn parse_skips_bots_without_a_pattern() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.slug == "no-pattern-bot"));
    }

    #[test]
    fn parse_maps_categories_to_flags() {
        let bots = parse(SAMPLE).unwrap();

        let ai_bot = bots.iter().find(|b| b.slug == "ai-search-bot").unwrap();
        assert!(ai_bot.is_ai);
        assert!(!ai_bot.is_search_engine);
        assert_eq!(ai_bot.user_agent_pattern, "AISearchBot");

        let search_bot = bots.iter().find(|b| b.slug == "google-crawler").unwrap();
        assert!(!search_bot.is_ai);
        assert!(search_bot.is_search_engine);

        let unknown_bot = bots.iter().find(|b| b.slug == "jyxo-crawler").unwrap();
        assert!(!unknown_bot.is_ai);
        assert!(!unknown_bot.is_search_engine);
    }

    #[test]
    fn parse_drops_a_pattern_with_a_quote_in_it() {
        let bots = parse(SAMPLE).unwrap();

        // Only pattern has a quote: the whole bot is dropped.
        assert!(!bots.iter().any(|b| b.slug == "quote-bot"));

        // One of two patterns has a quote: the bot is kept with just the
        // remaining, safe pattern.
        let mixed = bots.iter().find(|b| b.slug == "mixed-pattern-bot").unwrap();
        assert_eq!(mixed.user_agent_pattern, "GoodBot");
    }

    /// `Trailing\\` is a regex for a literal backslash, and this list's
    /// patterns are regexes. It used to be dropped because a backslash at
    /// the end escaped the closing quote of the NGINX string; written by
    /// `nginx::nginx_quoted`, it cannot, so it is kept as the rule it is.
    #[test]
    fn parse_keeps_a_pattern_ending_in_an_escaped_backslash() {
        let bots = parse(SAMPLE).unwrap();
        let bot = bots
            .iter()
            .find(|b| b.slug == "trailing-backslash-bot")
            .expect("the escaped backslash is a valid regex");
        assert_eq!(bot.user_agent_pattern, r"Trailing\\");
    }

    /// An unpaired one is not a regex at all, and still dropped.
    #[test]
    fn parse_drops_a_pattern_ending_in_an_unpaired_backslash() {
        let json = r#"[{"id":"bad","categories":["ai"],"pattern":{"accepted":["Trailing\\","GoodBot"],"forbidden":[]}}]"#;
        let parsed = parse_counted(json).unwrap();
        assert_eq!(parsed.bots[0].user_agent_pattern, "GoodBot");
        assert_eq!(parsed.skipped, 1, "the dropped pattern is counted");
    }

    /// Patterns PCRE refuses to compile fail `nginx -t`, and with it every
    /// apply after the fetch that stored them. Each is left out, counted.
    #[test]
    fn parse_counts_and_drops_patterns_nginx_would_not_compile() {
        let json = r#"[{"id":"bad","categories":["ai"],"pattern":{"accepted":["Bot[z-a]x","Bot{2,1}x","Botx{99999}","Bot[[:nope:]]x","Evil(?<n>Bot)","GoodBot"],"forbidden":[]}}]"#;
        let parsed = parse_counted(json).unwrap();
        assert_eq!(parsed.bots[0].user_agent_pattern, "GoodBot");
        assert_eq!(parsed.skipped, 5);
    }

    /// `accepted: [""]` joined into the block is an empty alternative:
    /// every visitor of every site turned away.
    #[test]
    fn parse_drops_a_pattern_that_would_match_everyone() {
        let json = r#"[
            {"id": "empty-bot", "categories": [], "pattern": {"accepted": [""]}},
            {"id": "wild-bot", "categories": [], "pattern": {"accepted": [".*", "WildBot"]}}
        ]"#;
        let bots = parse(json).unwrap();
        let patterns: Vec<(&str, &str)> = bots
            .iter()
            .map(|b| (b.slug.as_str(), b.user_agent_pattern.as_str()))
            .collect();
        assert_eq!(patterns, [("wild-bot", "WildBot")]);
    }

    #[test]
    fn humanize_titlecases_each_word() {
        assert_eq!(humanize("google-crawler"), "Google Crawler");
        assert_eq!(humanize("gptbot"), "Gptbot");
    }
}
