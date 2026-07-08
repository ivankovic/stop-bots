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

//! Downloads and normalizes the [ArcJet Well-Known Bots] list, the bot-list
//! source used to populate the database with known scanners, search engines
//! and AI crawlers.
//!
//! Fetching (network IO) and parsing (pure) are kept separate so that parsing
//! can be exercised in tests with a local fixture file, without ever hitting
//! the network.
//!
//! [ArcJet Well-Known Bots]: https://github.com/arcjet/well-known-bots

use crate::db::{Db, NewBot, Source};
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
/// `"` are dropped too: they end up embedded in a double-quoted NGINX string
/// (see `nginx::apply_blocks_to_file`), so an untrusted pattern with a quote
/// in it could break out and inject directives into a config loaded as root.
pub fn parse(json: &str) -> Result<Vec<NewBot>> {
    let raw: Vec<RawBot> = serde_json::from_str(json).context("failed to parse bot list JSON")?;

    let bots = raw
        .into_iter()
        .filter_map(|b| {
            let patterns: Vec<String> = b
                .pattern
                .accepted
                .into_iter()
                .filter(|p| !p.contains('"'))
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
    let body = reqwest::get(SOURCE_URL)
        .await
        .context("failed to fetch well-known-bots list")?
        .error_for_status()
        .context("well-known-bots request failed")?
        .text()
        .await
        .context("failed to read well-known-bots response body")?;
    Ok(body)
}

/// Registers the well-known-bots source in `db` if it isn't there yet,
/// without touching an already-fetched source's state. Called on TUI
/// startup so the source shows up (as "never updated") and can be selected
/// to trigger a first fetch, even before anything has ever been downloaded.
pub fn register_source(db: &Db) -> Result<()> {
    db.register_source(&Source {
        id: SOURCE_ID.to_string(),
        name: SOURCE_NAME.to_string(),
        url: SOURCE_URL.to_string(),
        last_fetched_at: None,
        bot_count: 0,
    })
}

/// Stores `bots` in `db`, registering/refreshing the source entry. Returns
/// the number of bots stored.
pub fn store(db: &Db, bots: &[NewBot]) -> Result<usize> {
    db.upsert_source(&Source {
        id: SOURCE_ID.to_string(),
        name: SOURCE_NAME.to_string(),
        url: SOURCE_URL.to_string(),
        last_fetched_at: None,
        bot_count: 0,
    })?;
    for bot in bots {
        db.upsert_bot(bot)?;
    }
    db.touch_source(SOURCE_ID, bots.len() as i64)?;
    Ok(bots.len())
}

/// Fetches the well-known-bots list over the network, parses it and stores
/// it in `db`. Returns the number of bots stored.
pub async fn update(db: &Db) -> Result<usize> {
    let json = fetch().await?;
    let bots = parse(&json)?;
    store(db, &bots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BotStatus;

    const SAMPLE: &str = include_str!("../tests/fixtures/botlists/well-known-bots-sample.json");

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
    fn humanize_titlecases_each_word() {
        assert_eq!(humanize("google-crawler"), "Google Crawler");
        assert_eq!(humanize("gptbot"), "Gptbot");
    }

    #[test]
    fn register_source_makes_it_visible_before_any_fetch() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.list_sources().unwrap().is_empty());

        register_source(&db).unwrap();

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, SOURCE_ID);
        assert!(sources[0].last_fetched_at.is_none());
    }

    #[test]
    fn register_source_does_not_clobber_a_real_fetch() {
        let db = Db::open_in_memory().unwrap();
        let bots = parse(SAMPLE).unwrap();
        store(&db, &bots).unwrap();

        register_source(&db).unwrap();

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].bot_count, 4);
        assert!(sources[0].last_fetched_at.is_some());
    }

    #[test]
    fn store_registers_source_and_bots_and_preserves_overrides_on_refresh() {
        let db = Db::open_in_memory().unwrap();
        let bots = parse(SAMPLE).unwrap();

        let stored = store(&db, &bots).unwrap();
        assert_eq!(stored, 4);
        assert_eq!(db.list_bots().unwrap().len(), 4);

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].id, SOURCE_ID);
        assert_eq!(sources[0].bot_count, 4);
        assert!(sources[0].last_fetched_at.is_some());

        db.set_bot_status("ai-search-bot", BotStatus::Allowed)
            .unwrap();
        store(&db, &bots).unwrap();

        let refreshed = db
            .list_bots()
            .unwrap()
            .into_iter()
            .find(|b| b.slug == "ai-search-bot")
            .unwrap();
        assert_eq!(refreshed.status, BotStatus::Allowed);
    }
}
