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

//! Downloads and normalizes the [ai.robots.txt] list, a community-maintained
//! directory of AI-crawler user agents.
//!
//! Unlike well-known-bots' `pattern.accepted` array, this source has no
//! separate user-agent field at all: the JSON key *is* the identifier
//! upstream's own generated `nginx-block-ai-bots.conf` matches against
//! directly, so it's used verbatim here too, both as `name` and as
//! `user_agent_pattern` — there's nothing else to normalize it from. Every
//! entry is tagged `is_ai`, since that's this source's entire scope.
//!
//! [ai.robots.txt]: https://github.com/ai-robots-txt/ai.robots.txt

use crate::botlist::slugify;
use crate::db::NewBot;
use anyhow::{Context, Result};
use std::collections::BTreeMap;

pub const SOURCE_ID: &str = "ai-robots-txt";
pub const SOURCE_NAME: &str = "ai.robots.txt";
pub const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json";

/// Parses the raw ai.robots.txt JSON document — a flat object keyed by bot
/// name, e.g. `{"GPTBot": {...}, "ClaudeBot": {...}}` — into [`NewBot`]
/// records. The per-bot metadata (operator, respect, function, ...) isn't
/// modeled here; only the key is needed. A name `botlist::keeps_pattern`
/// refuses is dropped, as in `well_known_bots::parse`: one containing a
/// `"`, one ending in a backslash, and one that would match every visitor,
/// such as an empty key.
pub fn parse(json: &str) -> Result<Vec<NewBot>> {
    parse_counted(json).map(|parsed| parsed.bots)
}

/// [`parse`], and how many names it left out.
pub fn parse_counted(json: &str) -> Result<crate::botlist::Parsed> {
    let raw: BTreeMap<String, serde::de::IgnoredAny> =
        serde_json::from_str(json).context("failed to parse ai.robots.txt JSON")?;

    let (names, skipped) = crate::botlist::kept_patterns(raw.into_keys());
    let bots = names
        .into_iter()
        .map(|name| NewBot {
            slug: slugify(&name),
            user_agent_pattern: name.clone(),
            name,
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            source_id: SOURCE_ID.to_string(),
        })
        .collect();

    Ok(crate::botlist::Parsed { bots, skipped })
}

/// Downloads the raw ai.robots.txt JSON document over HTTP.
pub async fn fetch() -> Result<String> {
    crate::fetch::text(SOURCE_URL, "the ai.robots.txt list").await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../tests/fixtures/botlists/ai-robots-txt-sample.json");

    #[test]
    fn parse_extracts_bot_names_as_ai_bots() {
        let bots = parse(SAMPLE).unwrap();
        let gptbot = bots.iter().find(|b| b.name == "GPTBot").unwrap();
        assert!(gptbot.is_ai);
        assert!(!gptbot.is_search_engine);
        assert!(!gptbot.is_scanner);
        assert_eq!(gptbot.user_agent_pattern, "GPTBot");
        assert_eq!(gptbot.slug, "gptbot");
    }

    #[test]
    fn parse_slugifies_multi_word_names() {
        let bots = parse(SAMPLE).unwrap();
        let bot = bots.iter().find(|b| b.name == "ChatGPT Agent").unwrap();
        assert_eq!(bot.slug, "chatgpt-agent");
    }

    #[test]
    fn parse_drops_a_name_with_a_quote_in_it() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.name.contains('"')));
    }

    #[test]
    fn parse_drops_a_name_ending_in_a_backslash() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.name.ends_with('\\')));
    }

    /// The key is the pattern, so an empty key would block every visitor.
    #[test]
    fn parse_drops_a_name_that_would_match_everyone() {
        let bots = parse(r#"{"": {}, "  ": {}, ".*": {}, "|": {}, "GPTBot": {}}"#).unwrap();
        let names: Vec<&str> = bots.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["GPTBot"]);
    }
}
