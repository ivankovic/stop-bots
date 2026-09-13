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

//! Downloads and normalizes the "bad user-agents" blocklist from
//! [nginx-ultimate-bad-bot-blocker], a community-maintained list of known
//! vulnerability scanners, security tools and other malicious bots. This is
//! the first source that actually populates `is_scanner` — the other two
//! sources in this module only ever cover AI/search crawlers (see TODO.md).
//!
//! [nginx-ultimate-bad-bot-blocker]: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker

use crate::botlist::slugify;
use crate::db::NewBot;
use anyhow::Result;

pub const SOURCE_ID: &str = "nginx-bad-bots";
pub const SOURCE_NAME: &str = "Nginx Ultimate Bad Bot Blocker";
pub const SOURCE_URL: &str = "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list";

/// Strips backslash-escapes from a regex-ready upstream line (e.g.
/// `1h4x\.com` -> `1h4x.com`, `ALittle\ Client` -> `ALittle Client`) for
/// display purposes. `user_agent_pattern` keeps the original, still-escaped
/// line — see `parse`'s doc comment for why.
fn unescape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses the raw bad-user-agents list: a plain-text file, one
/// already-regex-ready token per line (upstream backslash-escapes literal
/// spaces and dots so the whole file can be joined with `|` straight into
/// an NGINX regex — exactly the shape `Db::blocked_user_agent_patterns`
/// already produces), sorted alphabetically. Each line becomes one
/// [`NewBot`], tagged `is_scanner`; `user_agent_pattern` keeps the line
/// verbatim (still escaped) since that's what actually gets joined into
/// the regex, while `name`/`slug` use the unescaped, human-readable form.
/// Blank lines are skipped defensively (none are expected upstream, but
/// nothing guarantees that stays true); a line containing a `"`, or ending
/// in a backslash, is dropped, same reasoning as `well_known_bots::parse` —
/// it would break out of (or leave open) the double-quoted NGINX string it
/// ends up embedded in. A trailing backslash here means a raw, unpaired one
/// at the end of the line itself — routine mid-pattern escapes like
/// `1h4x\.com` are untouched, since the backslash there isn't at the end.
pub fn parse(text: &str) -> Result<Vec<NewBot>> {
    let bots = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.contains('"') && !line.ends_with('\\'))
        .map(|line| {
            let name = unescape(line);
            NewBot {
                slug: slugify(&name),
                name,
                is_ai: false,
                is_search_engine: false,
                is_scanner: true,
                user_agent_pattern: line.to_string(),
                source_id: SOURCE_ID.to_string(),
            }
        })
        .collect();
    Ok(bots)
}

/// Downloads the raw bad-user-agents list over HTTP.
pub async fn fetch() -> Result<String> {
    crate::fetch::text(SOURCE_URL, "the nginx-ultimate-bad-bot-blocker list").await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../tests/fixtures/botlists/nginx-bad-bots-sample.list");

    #[test]
    fn parse_tags_every_entry_as_a_scanner() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.is_empty());
        assert!(bots
            .iter()
            .all(|b| b.is_scanner && !b.is_ai && !b.is_search_engine));
    }

    #[test]
    fn parse_keeps_the_escaped_pattern_but_unescapes_the_display_name() {
        let bots = parse(SAMPLE).unwrap();
        let bot = bots
            .iter()
            .find(|b| b.user_agent_pattern == "1h4x\\.com")
            .unwrap();
        assert_eq!(bot.name, "1h4x.com");
        assert_eq!(bot.slug, "1h4x-com");
    }

    #[test]
    fn parse_unescapes_a_literal_space() {
        let bots = parse(SAMPLE).unwrap();
        let bot = bots
            .iter()
            .find(|b| b.user_agent_pattern == "ALittle\\ Client")
            .unwrap();
        assert_eq!(bot.name, "ALittle Client");
    }

    #[test]
    fn parse_skips_blank_lines() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.name.is_empty()));
    }

    #[test]
    fn parse_drops_a_line_with_a_quote_in_it() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots.iter().any(|b| b.name.contains('"')));
    }

    #[test]
    fn parse_drops_a_line_ending_in_a_backslash() {
        let bots = parse(SAMPLE).unwrap();
        assert!(!bots
            .iter()
            .any(|b| b.user_agent_pattern == "TrailingBackslash\\"));
    }

    #[test]
    fn parse_keeps_a_mid_pattern_escape_that_does_not_end_in_a_backslash() {
        let bots = parse(SAMPLE).unwrap();
        assert!(bots.iter().any(|b| b.user_agent_pattern == "1h4x\\.com"));
    }
}
