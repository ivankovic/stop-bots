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
/// Bots with no usable user-agent pattern are skipped. Patterns containing a
/// `"`, or ending in a backslash, are dropped too: they end up embedded in a
/// double-quoted NGINX string (see `nginx::apply_blocks_to_file`), so an
/// untrusted pattern with a quote in it could break out and inject
/// directives into a config loaded as root, and one ending in a backslash
/// can escape NGINX's own closing quote instead (see `nginx::is_embeddable`
/// for the mechanics — confirmed against a real `nginx -t`). So is one that
/// would match every visitor, such as `""` — see `botlist::keeps_pattern`.
/// Each accepted pattern is checked on its own, before they are joined, so
/// one bad entry costs that entry rather than the bot.
pub fn parse(json: &str) -> Result<Vec<NewBot>> {
    let raw: Vec<RawBot> = serde_json::from_str(json).context("failed to parse bot list JSON")?;

    let bots = raw
        .into_iter()
        .filter_map(|b| {
            let patterns: Vec<String> = b
                .pattern
                .accepted
                .into_iter()
                .filter(|p| crate::botlist::keeps_pattern(p))
                .collect();
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

    Ok(bots)
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

    #[test]
    fn parse_drops_a_pattern_ending_in_a_backslash() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.slug == "trailing-backslash-bot"));
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
