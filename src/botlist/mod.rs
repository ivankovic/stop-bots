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

//! Bot-list sources: downloads and normalizes third-party lists of known
//! bot user agents into this app's `bots` table. Each source lives in its
//! own sibling module (`well_known_bots`, `ai_robots_txt`, `nginx_bad_bots`)
//! since their upstream formats are all different — one JSON shape with an
//! explicit pattern field, one JSON shape with no pattern field at all (the
//! key *is* the pattern), and one plain-text line-per-entry list.
//! [`SourceKind`] is the single place that knows about all of them; adding a
//! fourth source means adding a variant here plus one new sibling module.

pub mod ai_robots_txt;
pub mod nginx_bad_bots;
pub mod stop_bots_extras;
pub mod well_known_bots;

use crate::db::{Db, NewBot, Source};
use anyhow::{Context, Result};

/// Every bot-list source this tool knows how to fetch and parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    WellKnownBots,
    AiRobotsTxt,
    NginxBadBots,
    /// This project's own list — the only one compiled into the binary
    /// rather than downloaded. See [`stop_bots_extras`].
    StopBotsExtras,
}

impl SourceKind {
    pub const ALL: [SourceKind; 4] = [
        SourceKind::WellKnownBots,
        SourceKind::AiRobotsTxt,
        SourceKind::NginxBadBots,
        SourceKind::StopBotsExtras,
    ];

    pub fn id(self) -> &'static str {
        match self {
            SourceKind::WellKnownBots => well_known_bots::SOURCE_ID,
            SourceKind::AiRobotsTxt => ai_robots_txt::SOURCE_ID,
            SourceKind::NginxBadBots => nginx_bad_bots::SOURCE_ID,
            SourceKind::StopBotsExtras => stop_bots_extras::SOURCE_ID,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SourceKind::WellKnownBots => well_known_bots::SOURCE_NAME,
            SourceKind::AiRobotsTxt => ai_robots_txt::SOURCE_NAME,
            SourceKind::NginxBadBots => nginx_bad_bots::SOURCE_NAME,
            SourceKind::StopBotsExtras => stop_bots_extras::SOURCE_NAME,
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            SourceKind::WellKnownBots => well_known_bots::SOURCE_URL,
            SourceKind::AiRobotsTxt => ai_robots_txt::SOURCE_URL,
            SourceKind::NginxBadBots => nginx_bad_bots::SOURCE_URL,
            SourceKind::StopBotsExtras => stop_bots_extras::SOURCE_URL,
        }
    }

    /// Looks up a `SourceKind` by its stable `id()` (the same string stored
    /// in the `sources` table) — e.g. what `App`'s `UpdateSource` outcome
    /// carries back from a Bot settings confirmation, or the CLI's
    /// `--source-id` flag.
    pub fn from_id(id: &str) -> Option<SourceKind> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// Parses a downloaded list, and refuses one past [`MAX_SOURCE_ENTRIES`]
    /// or with a pattern past `nginx::MAX_PATTERN_LEN`.
    ///
    /// Refused whole rather than truncated, for the reason `fetch` refuses
    /// an oversized body: a list stored in part is one with entries
    /// silently missing, and the previous list stays in place while the
    /// error says why.
    pub fn parse(self, raw: &str) -> Result<Vec<NewBot>> {
        let bots = match self {
            SourceKind::WellKnownBots => well_known_bots::parse(raw),
            SourceKind::AiRobotsTxt => ai_robots_txt::parse(raw),
            SourceKind::NginxBadBots => nginx_bad_bots::parse(raw),
            SourceKind::StopBotsExtras => stop_bots_extras::parse(raw),
        }?;
        if bots.len() > MAX_SOURCE_ENTRIES {
            anyhow::bail!(
                "the {} list has {} entries, more than the {MAX_SOURCE_ENTRIES} accepted from \
                 one source; refusing it rather than storing part of it",
                self.name(),
                bots.len()
            );
        }
        if let Some(bot) = bots
            .iter()
            .find(|b| b.user_agent_pattern.len() > crate::nginx::MAX_PATTERN_LEN)
        {
            anyhow::bail!(
                "the {} list has a {}-byte pattern for {:?}, more than the {} bytes accepted; \
                 refusing it rather than storing part of it",
                self.name(),
                bot.user_agent_pattern.len(),
                bot.name,
                crate::nginx::MAX_PATTERN_LEN
            );
        }
        Ok(bots)
    }

    pub async fn fetch(self) -> Result<String> {
        match self {
            SourceKind::WellKnownBots => well_known_bots::fetch().await,
            SourceKind::AiRobotsTxt => ai_robots_txt::fetch().await,
            SourceKind::NginxBadBots => nginx_bad_bots::fetch().await,
            SourceKind::StopBotsExtras => stop_bots_extras::fetch().await,
        }
    }

    fn as_source(self) -> Source {
        Source {
            id: self.id().to_string(),
            name: self.name().to_string(),
            url: self.url().to_string(),
            last_fetched_at: None,
            bot_count: 0,
        }
    }
}

/// The most entries one source may deliver. The largest real list is under
/// 800 (well-known-bots, September 2026); this is over ten times that.
pub const MAX_SOURCE_ENTRIES: usize = 10_000;

/// Whether a parser keeps `pattern`: everything `nginx::pattern_problem`
/// accepts, and one that is only too long, so that [`SourceKind::parse`]
/// can refuse the whole list over it instead of quietly dropping a line.
///
/// Every parser filters through this, which keeps a pattern that would
/// match every visitor (an empty key, `accepted: [""]`, a lone `|` line)
/// out of the database. `nginx::block_text` checks the same thing again
/// for anything that reached the database some other way.
pub(crate) fn keeps_pattern(pattern: &str) -> bool {
    matches!(
        crate::nginx::pattern_problem(pattern),
        None | Some(crate::nginx::PatternProblem::TooLong)
    )
}

/// Turns an arbitrary bot-name string into a lowercase, hyphen-separated
/// slug for the `bots.slug` column (e.g. `"ChatGPT Agent"` ->
/// `"chatgpt-agent"`). Shared by the sources that have no ready-made id of
/// their own — unlike well-known-bots, whose upstream `id` field is already
/// slug-shaped. Runs of non-alphanumeric characters collapse to one hyphen;
/// leading/trailing hyphens are trimmed.
pub(crate) fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_hyphen = true; // avoids a leading hyphen
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            slug.push('-');
            last_was_hyphen = true;
        }
    }
    if slug.ends_with('-') {
        slug.pop();
    }
    slug
}

/// Registers every known source in `db` that isn't there yet, so they all
/// show up (as "never updated") on TUI/CLI startup even before a first
/// fetch. Doesn't touch a source that's already been fetched.
pub fn register_all_sources(db: &Db) -> Result<()> {
    // One transaction, for the same reason as
    // `reputation::register_all_reputation_sources`: this is startup cost
    // on every launch, paid in fsyncs for writes that rarely change
    // anything.
    db.batch(|| {
        for kind in SourceKind::ALL {
            db.register_source(&kind.as_source())?;
        }
        // The built-in list is *stored*, not just registered. Every other
        // source is empty until someone fetches it, which is right for a
        // download; this one is already in the binary, and leaving it
        // registered-but-empty would mean a fresh install shipped a list
        // it never used until an unrelated button was pressed. Cheap
        // enough to redo on every startup — forty-odd upserts inside the
        // transaction already open — and `upsert_bot` writes only to
        // `bot_source_entries`, so an admin's own per-bot status survives.
        store_inner(db, SourceKind::StopBotsExtras, &stop_bots_extras::bots())?;
        Ok(())
    })
}

/// Stores `bots` in `db` under `kind`'s source row, registering/refreshing
/// it, and *replaces* rather than layers onto whatever this source
/// contributed last time (see `Db::clear_source_bot_entries`) — a bot this
/// fetch no longer includes must stop being attributed to `kind`, not
/// linger forever just because a previous fetch once reported it. Returns
/// the accurate, post-merge count of bots this source currently
/// contributes (from `Db::count_bot_source_entries`), not `bots.len()`,
/// since a source can have internal duplicates that collapse to fewer
/// distinct slugs than it parsed.
pub fn store(db: &Db, kind: SourceKind, bots: &[NewBot]) -> Result<usize> {
    // One transaction for the whole store — see `Db::batch`: at one
    // autocommit fsync per row, a 700-bot list took seconds to store.
    db.batch(|| store_inner(db, kind, bots))
}

fn store_inner(db: &Db, kind: SourceKind, bots: &[NewBot]) -> Result<usize> {
    db.upsert_source(&kind.as_source())?;

    let previously_contributed = db.clear_source_bot_entries(kind.id())?;
    for bot in bots {
        db.upsert_bot(bot)?;
    }

    // A slug this source no longer contributes still needs its merged row
    // recomputed — it might fall back to another source's contribution,
    // or (if this was its only one) be deliberately left as-is; either
    // way `upsert_bot` above never touched it, since it's not in `bots`.
    let still_contributed: std::collections::HashSet<&str> =
        bots.iter().map(|b| b.slug.as_str()).collect();
    for slug in &previously_contributed {
        if !still_contributed.contains(slug.as_str()) {
            db.recompute_merged_bot(slug)?;
        }
    }

    let count = db.count_bot_source_entries(kind.id())?;
    db.touch_source(kind.id(), count)?;
    Ok(count as usize)
}

/// Fetches `kind`'s list over the network, parses it and stores it in
/// `db`. Returns the number of bots stored.
pub async fn update(db: &Db, kind: SourceKind) -> Result<usize> {
    let raw = kind
        .fetch()
        .await
        .with_context(|| format!("failed to update {}", kind.name()))?;
    let bots = kind.parse(&raw)?;
    store(db, kind, &bots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BotStatus;

    /// Far beyond any real list, so a source that crosses it has changed
    /// into something else, and storing part of it would be a list with
    /// entries silently missing.
    #[test]
    fn a_source_with_too_many_entries_is_refused_whole() {
        let list: String = (0..=MAX_SOURCE_ENTRIES)
            .map(|i| format!("Bot{i}Agent\n"))
            .collect();
        let err = SourceKind::NginxBadBots.parse(&list).unwrap_err();
        assert!(err.to_string().contains("entries"), "error was: {err}");
    }

    #[test]
    fn a_source_with_an_over_long_pattern_is_refused_whole() {
        let list = format!(
            "GoodBot\n{}\n",
            "E".repeat(crate::nginx::MAX_PATTERN_LEN + 1)
        );
        let err = SourceKind::NginxBadBots.parse(&list).unwrap_err();
        assert!(err.to_string().contains("bytes"), "error was: {err}");
    }

    #[test]
    fn a_source_within_the_limits_parses() {
        let bots = SourceKind::NginxBadBots
            .parse("GoodBot\nEvilBot\n")
            .unwrap();
        assert_eq!(bots.len(), 2);
    }

    #[test]
    fn slugify_lowercases_and_hyphenates() {
        assert_eq!(slugify("GPTBot"), "gptbot");
        assert_eq!(slugify("ChatGPT Agent"), "chatgpt-agent");
        assert_eq!(slugify("Claude-Code"), "claude-code");
        assert_eq!(slugify("1h4x.com"), "1h4x-com");
        assert_eq!(slugify("  leading and trailing  "), "leading-and-trailing");
    }

    #[test]
    fn from_id_resolves_every_known_source_and_rejects_unknown_ones() {
        for kind in SourceKind::ALL {
            assert_eq!(SourceKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(SourceKind::from_id("unknown-source"), None);
    }

    #[test]
    fn register_all_sources_registers_every_kind_exactly_once() {
        let db = Db::open_in_memory().unwrap();
        register_all_sources(&db).unwrap();

        let mut ids: Vec<_> = db
            .list_sources()
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        ids.sort();
        let mut expected: Vec<_> = SourceKind::ALL.iter().map(|k| k.id().to_string()).collect();
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn register_all_sources_does_not_clobber_an_already_fetched_source() {
        let db = Db::open_in_memory().unwrap();
        let bots = well_known_bots::parse(include_str!(
            "../../tests/fixtures/botlists/well-known-bots-sample.json"
        ))
        .unwrap();
        store(&db, SourceKind::WellKnownBots, &bots).unwrap();

        register_all_sources(&db).unwrap();

        let source = db
            .list_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == SourceKind::WellKnownBots.id())
            .unwrap();
        assert!(source.last_fetched_at.is_some());
        assert_eq!(source.bot_count, 4);
    }

    #[test]
    fn store_registers_the_right_source_row_and_bot_count() {
        let db = Db::open_in_memory().unwrap();
        let bots = vec![NewBot {
            slug: "test-scanner".to_string(),
            name: "Test Scanner".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: true,
            user_agent_pattern: "TestScanner".to_string(),
            source_id: SourceKind::NginxBadBots.id().to_string(),
        }];

        let count = store(&db, SourceKind::NginxBadBots, &bots).unwrap();
        assert_eq!(count, 1);

        let source = db
            .list_sources()
            .unwrap()
            .into_iter()
            .find(|s| s.id == SourceKind::NginxBadBots.id())
            .unwrap();
        assert_eq!(source.name, SourceKind::NginxBadBots.name());
        assert_eq!(source.bot_count, 1);
    }

    #[test]
    fn store_preserves_bot_overrides_on_refresh_regardless_of_source() {
        let db = Db::open_in_memory().unwrap();
        let bots = well_known_bots::parse(include_str!(
            "../../tests/fixtures/botlists/well-known-bots-sample.json"
        ))
        .unwrap();
        store(&db, SourceKind::WellKnownBots, &bots).unwrap();

        db.set_bot_status("ai-search-bot", BotStatus::Allowed)
            .unwrap();
        store(&db, SourceKind::WellKnownBots, &bots).unwrap();

        let refreshed = db
            .list_bots()
            .unwrap()
            .into_iter()
            .find(|b| b.slug == "ai-search-bot")
            .unwrap();
        assert_eq!(refreshed.status, BotStatus::Allowed);
    }

    /// End-to-end regression test for the actual bug this module's merge
    /// design fixes: the fixture lists for `ai_robots_txt` and
    /// `nginx_bad_bots` both include "GPTBot" (a real overlap this project
    /// hit fetching the live sources). Storing both real
    /// `SourceKind`s' parsed output, in either order, must land on one
    /// merged bot carrying *both* sources' flags — not whichever store()
    /// call happened to run last.
    #[test]
    fn storing_two_overlapping_sources_merges_rather_than_clobbers() {
        let ai_bots = ai_robots_txt::parse(include_str!(
            "../../tests/fixtures/botlists/ai-robots-txt-sample.json"
        ))
        .unwrap();
        let scanner_bots = nginx_bad_bots::parse(include_str!(
            "../../tests/fixtures/botlists/nginx-bad-bots-sample.list"
        ))
        .unwrap();
        assert!(
            ai_bots.iter().any(|b| b.name == "GPTBot"),
            "fixture must contain the overlapping name for this test to mean anything"
        );
        assert!(scanner_bots.iter().any(|b| b.name == "GPTBot"));

        for (first, second) in [
            (SourceKind::AiRobotsTxt, SourceKind::NginxBadBots),
            (SourceKind::NginxBadBots, SourceKind::AiRobotsTxt),
        ] {
            let db = Db::open_in_memory().unwrap();
            let (first_bots, second_bots) = if first == SourceKind::AiRobotsTxt {
                (&ai_bots, &scanner_bots)
            } else {
                (&scanner_bots, &ai_bots)
            };
            store(&db, first, first_bots).unwrap();
            store(&db, second, second_bots).unwrap();

            let gptbot = db
                .list_bots()
                .unwrap()
                .into_iter()
                .find(|b| b.name == "GPTBot")
                .unwrap();
            assert!(
                gptbot.is_ai,
                "lost is_ai when {first:?} was stored before {second:?}"
            );
            assert!(
                gptbot.is_scanner,
                "lost is_scanner when {first:?} was stored before {second:?}"
            );
        }
    }
}
