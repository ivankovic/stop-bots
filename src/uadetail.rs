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

//! Everything this host already knows about one user agent string — the
//! model behind both front-ends' per-user-agent detail view on the
//! Firewall screen, and the counterpart to [`crate::ipdetail`].
//!
//! The two views answer deliberately different questions, which is why
//! they are two modules rather than one generic one. An address can be
//! *checked*: it is either inside Google's published ranges or it is not,
//! and no amount of lying by the client changes that. A user agent cannot.
//! It is a string the client chose, it can say anything, and the only
//! honest thing this view can report is **what the lists on this host say
//! about that string** — never what the client "is".
//!
//! So nothing here goes near the network, for the reasons `ipdetail`
//! spells out and one more: there is nothing to ask. The answer is a join
//! over `bots`/`bot_source_entries`, the per-bot status overrides, and the
//! three category defaults — the same data `compute_blocked_patterns`
//! renders the NGINX map from, read back as a per-string explanation.
//!
//! What is deliberately *not* here is which addresses used this user
//! agent. Those rows come from `user_agent_stats`, a rolling tally; the
//! addresses are only in the access log, and reading it here would
//! describe a different moment than the table the view opened from — the
//! same reason `dynamic` takes its log text from the caller.

use anyhow::Result;

use crate::db::{Bot, BotStatus, Category, Db, Policy};
use crate::dynamic::{looks_like_a_bot, matched_alternative, RowStatus};

/// Longest user agent kept for display, in characters.
///
/// The string is whatever the client sent and nothing truncates it on the
/// way in — nginx will log a kilobyte of it happily. Capped here rather
/// than in each front-end so neither has to remember, the same bargain
/// [`crate::sshlog`] makes for attacker-chosen usernames.
const MAX_USER_AGENT_CHARS: usize = 300;

/// Why one matched bot is or is not blocked right now.
///
/// The four-way split is the whole point of the view: "blocked" alone
/// does not tell an admin whether un-blocking means clearing an override
/// they set once, or changing a category default that governs hundreds of
/// other bots too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotVerdict {
    /// An explicit per-bot `Blocked`, which wins over every category
    /// default.
    BlockedHere,
    /// An explicit per-bot `Allowed`. Also wins — a bot the admin let
    /// through stays through even when its whole category is blocked.
    AllowedHere,
    /// No override; at least one of its categories defaults to blocked.
    BlockedByCategory,
    /// No override, and no category of its blocks by default.
    AllowedByDefault,
}

impl BotVerdict {
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedHere | Self::BlockedByCategory)
    }

    /// A short phrase for a table cell or a popup line.
    pub fn label(self) -> &'static str {
        match self {
            Self::BlockedHere => "blocked (set here)",
            Self::AllowedHere => "allowed (set here)",
            Self::BlockedByCategory => "blocked by category",
            Self::AllowedByDefault => "not blocked",
        }
    }
}

/// One bot list entry whose pattern this user agent contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotMatch {
    pub slug: String,
    pub name: String,
    /// The single alternative that matched, not the merged row's whole
    /// `a|b|c` pattern — see [`matched_alternative`].
    pub pattern: String,
    /// Every category the merged row carries. More than one is normal:
    /// a source can call something both a scanner and an AI crawler.
    pub categories: Vec<Category>,
    /// The display names of the lists contributing this bot.
    pub sources: Vec<String>,
    pub verdict: BotVerdict,
}

/// Everything known locally about one user agent string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaDetail {
    /// The string, capped and stripped of control characters for display
    /// — [`MAX_USER_AGENT_CHARS`]. Not a lookup key; the caller keeps the
    /// original for that.
    pub user_agent: String,
    /// Whether the cap above actually cut anything.
    pub truncated: bool,
    /// The verdict the row was showing, carried through rather than
    /// recomputed, so the popup and the table beside it cannot disagree.
    pub status: RowStatus,
    /// Requests tallied under this exact string, and when it was last
    /// seen. `None` when the string is not in `user_agent_stats` at all —
    /// possible if the tally was pruned between the table and the click.
    pub hits: Option<u64>,
    pub last_seen_at: Option<i64>,
    /// Whether an admin blocked this exact string by hand from this
    /// screen. Separate from the matches below: it is an exact-string
    /// block in its own table, not a catalogued bot.
    pub blocked_by_hand: bool,
    /// Every bot list entry whose pattern this string contains, blocked
    /// ones first and then by name.
    pub matches: Vec<BotMatch>,
    /// Whether the string advertises itself as a bot — see
    /// [`looks_like_a_bot`]. With `matches` empty, this is what makes a
    /// row worth an admin's attention rather than just another visitor.
    pub self_declared_bot: bool,
}

impl UaDetail {
    /// Gathers what `db` knows about `user_agent`.
    ///
    /// `status` comes from the row the view was opened from, for the
    /// reason [`crate::ipdetail::IpDetail::load`] takes one too.
    pub fn load(db: &Db, user_agent: &str, status: RowStatus) -> Result<Self> {
        let policies = Policies {
            ai: db.get_category_default(Category::Ai)?,
            search: db.get_category_default(Category::Search)?,
            scanner: db.get_category_default(Category::Scanner)?,
        };
        let stat = db.user_agent_stat(user_agent)?;

        let mut matches = Vec::new();
        for bot in db.list_bots()? {
            let Some(pattern) = matched_alternative(user_agent, &bot) else {
                continue;
            };
            matches.push(BotMatch {
                sources: db.bot_source_names_for_slug(&bot.slug)?,
                verdict: verdict_for(&bot, policies),
                categories: categories_of(&bot),
                slug: bot.slug,
                name: bot.name,
                pattern,
            });
        }
        // Blocked first: an admin opening this wants to know what is
        // already stopping this string before what merely describes it.
        matches.sort_by(|a, b| {
            b.verdict
                .is_blocked()
                .cmp(&a.verdict.is_blocked())
                .then_with(|| a.name.cmp(&b.name))
        });

        let (display, truncated) = for_display(user_agent);
        Ok(Self {
            user_agent: display,
            truncated,
            status,
            hits: stat.as_ref().map(|s| s.hit_count.max(0) as u64),
            last_seen_at: stat.as_ref().map(|s| s.last_seen_at),
            blocked_by_hand: db
                .list_blocked_user_agents()?
                .iter()
                .any(|blocked| blocked == user_agent),
            matches,
            self_declared_bot: looks_like_a_bot(user_agent),
        })
    }

    /// Whether no list on this host has heard of this string. Informative
    /// in its own right: paired with `self_declared_bot` it is exactly the
    /// case the `UNKNOWN` tag exists to surface.
    pub fn is_unknown(&self) -> bool {
        self.matches.is_empty()
    }
}

/// The three category defaults, passed around as one value so a new
/// category cannot be added to the verdict without the compiler noticing.
#[derive(Debug, Clone, Copy)]
struct Policies {
    ai: Policy,
    search: Policy,
    scanner: Policy,
}

impl Policies {
    fn blocks(self, category: Category) -> bool {
        let policy = match category {
            Category::Ai => self.ai,
            Category::Search => self.search,
            Category::Scanner => self.scanner,
        };
        policy == Policy::Blocked
    }
}

fn categories_of(bot: &Bot) -> Vec<Category> {
    let mut out = Vec::new();
    if bot.is_ai {
        out.push(Category::Ai);
    }
    if bot.is_search_engine {
        out.push(Category::Search);
    }
    if bot.is_scanner {
        out.push(Category::Scanner);
    }
    out
}

/// The same precedence `compute_blocked_patterns` and
/// [`crate::dynamic::ua_matches_blocked_bot_patterns`] apply — an explicit
/// per-bot status wins, and only `Default` consults the categories —
/// stated once here as a reason rather than a boolean.
fn verdict_for(bot: &Bot, policies: Policies) -> BotVerdict {
    match bot.status {
        BotStatus::Blocked => BotVerdict::BlockedHere,
        BotStatus::Allowed => BotVerdict::AllowedHere,
        BotStatus::Default => {
            if categories_of(bot)
                .into_iter()
                .any(|category| policies.blocks(category))
            {
                BotVerdict::BlockedByCategory
            } else {
                BotVerdict::AllowedByDefault
            }
        }
    }
}

/// The string as it is safe to draw: capped, and with control characters
/// replaced.
///
/// Both halves matter and for different reasons. The cap keeps a client
/// that sent two kilobytes from owning the whole popup. The replacement is
/// because this reaches a TUI's alternate screen, where an escape sequence
/// in the data repaints the terminal — the web UI's own escaping does
/// nothing about that, and the string has passed through no sanitiser on
/// the way in.
fn for_display(user_agent: &str) -> (String, bool) {
    let mut out: String = user_agent
        .chars()
        .take(MAX_USER_AGENT_CHARS)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    let truncated = user_agent.chars().count() > MAX_USER_AGENT_CHARS;
    if truncated {
        out.push('\u{2026}');
    }
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewBot;

    fn db_with_bots() -> Db {
        let db = Db::open_in_memory().unwrap();
        for (id, name) in [
            ("well-known-bots", "Well-known bots"),
            ("extras", "stop-bots extras"),
        ] {
            db.register_source(&crate::db::Source {
                id: id.to_string(),
                name: name.to_string(),
                url: "https://example.invalid/list".to_string(),
                last_fetched_at: None,
                bot_count: 0,
            })
            .unwrap();
        }
        for source in ["well-known-bots", "extras"] {
            db.upsert_bot(&NewBot {
                slug: "googlebot".to_string(),
                name: "Googlebot".to_string(),
                is_ai: false,
                is_search_engine: true,
                is_scanner: false,
                user_agent_pattern: "Googlebot".to_string(),
                source_id: source.to_string(),
            })
            .unwrap();
        }
        db.upsert_bot(&NewBot {
            slug: "gptbot".to_string(),
            name: "GPTBot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "GPTBot".to_string(),
            source_id: "well-known-bots".to_string(),
        })
        .unwrap();
        db
    }

    fn load(db: &Db, ua: &str) -> UaDetail {
        UaDetail::load(db, ua, RowStatus::Pending).unwrap()
    }

    #[test]
    fn a_matching_bot_is_reported_with_the_alternative_that_matched() {
        let db = db_with_bots();

        let detail = load(&db, "Mozilla/5.0 (compatible; Googlebot/2.1)");

        assert_eq!(detail.matches.len(), 1, "matches: {:?}", detail.matches);
        assert_eq!(detail.matches[0].name, "Googlebot");
        assert_eq!(detail.matches[0].pattern, "Googlebot");
        assert_eq!(detail.matches[0].categories, vec![Category::Search]);
        assert!(!detail.is_unknown());
    }

    /// "Three lists carry this" and "one does" are different amounts of
    /// evidence, and the merged `bots` row's single `source_id` cannot
    /// tell them apart.
    #[test]
    fn every_list_contributing_a_bot_is_named() {
        let db = db_with_bots();

        let detail = load(&db, "Googlebot/2.1");

        assert_eq!(
            detail.matches[0].sources,
            vec![
                "Well-known bots".to_string(),
                "stop-bots extras".to_string()
            ]
        );
    }

    /// The distinction the whole view exists for: the same "blocked" with
    /// two different remedies behind it.
    #[test]
    fn a_category_default_and_a_per_bot_override_are_told_apart() {
        let db = db_with_bots();
        db.set_category_default(Category::Search, Policy::Blocked)
            .unwrap();

        assert_eq!(
            load(&db, "Googlebot/2.1").matches[0].verdict,
            BotVerdict::BlockedByCategory
        );

        db.set_bot_status("googlebot", BotStatus::Blocked).unwrap();
        assert_eq!(
            load(&db, "Googlebot/2.1").matches[0].verdict,
            BotVerdict::BlockedHere
        );
    }

    /// An allowed bot stays allowed even with its category blocked —
    /// which is the one case where a view reporting only the category
    /// default would tell an admin the opposite of the truth.
    #[test]
    fn an_allowed_bot_is_not_reported_as_blocked_by_its_category() {
        let db = db_with_bots();
        db.set_category_default(Category::Search, Policy::Blocked)
            .unwrap();
        db.set_bot_status("googlebot", BotStatus::Allowed).unwrap();

        let verdict = load(&db, "Googlebot/2.1").matches[0].verdict;

        assert_eq!(verdict, BotVerdict::AllowedHere);
        assert!(!verdict.is_blocked());
    }

    #[test]
    fn blocked_matches_are_listed_before_merely_known_ones() {
        let db = db_with_bots();
        db.set_category_default(Category::Ai, Policy::Blocked)
            .unwrap();

        // Contains both patterns; only the AI one is blocked.
        let detail = load(&db, "Googlebot GPTBot");

        assert_eq!(detail.matches.len(), 2);
        assert_eq!(detail.matches[0].name, "GPTBot");
        assert!(detail.matches[0].verdict.is_blocked());
    }

    /// The case the `UNKNOWN` tag exists for, and the reason the view
    /// carries `self_declared_bot` instead of leaving an empty match list
    /// to speak for itself.
    #[test]
    fn a_bot_shaped_string_no_list_knows_is_marked_as_one() {
        let detail = load(
            &db_with_bots(),
            "Mozilla/5.0 (compatible; Silovik/1.0; +http://silovik.invalid/)",
        );

        assert!(detail.is_unknown());
        assert!(detail.self_declared_bot);
    }

    #[test]
    fn an_ordinary_browser_is_neither_known_nor_bot_shaped() {
        let detail = load(
            &db_with_bots(),
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
        );

        assert!(detail.is_unknown());
        assert!(!detail.self_declared_bot);
    }

    #[test]
    fn a_hand_blocked_string_says_who_blocked_it() {
        let db = db_with_bots();
        db.block_user_agent("curl/8.0").unwrap();

        assert!(load(&db, "curl/8.0").blocked_by_hand);
        assert!(!load(&db, "wget/1.21").blocked_by_hand);
    }

    #[test]
    fn the_hit_count_and_last_seen_come_from_the_recorded_tally() {
        let db = db_with_bots();
        let mut counts = std::collections::HashMap::new();
        counts.insert("curl/8.0".to_string(), 42);
        db.record_user_agent_hits(&counts, 1_700_000_000).unwrap();

        let detail = load(&db, "curl/8.0");

        assert_eq!(detail.hits, Some(42));
        assert_eq!(detail.last_seen_at, Some(1_700_000_000));
    }

    /// The tally is pruned on a schedule, so a row can be gone between
    /// the table being drawn and the click that inspects it. "No count"
    /// and "a count of zero" are different claims.
    #[test]
    fn a_string_with_no_recorded_tally_reports_no_count_rather_than_zero() {
        let detail = load(&db_with_bots(), "never-seen/1.0");

        assert_eq!(detail.hits, None);
        assert_eq!(detail.last_seen_at, None);
    }

    /// The string is attacker-chosen and nothing truncates it on the way
    /// in: it can be long enough to own the whole popup, and can carry an
    /// escape sequence that repaints a terminal.
    #[test]
    fn an_attacker_chosen_string_is_capped_and_stripped_of_control_characters() {
        let db = db_with_bots();
        let hostile = format!("\u{1b}[2J{}", "A".repeat(4_000));

        let detail = load(&db, &hostile);

        assert!(
            detail.user_agent.chars().count() <= MAX_USER_AGENT_CHARS + 1,
            "was {} chars",
            detail.user_agent.chars().count()
        );
        assert!(detail.truncated);
        assert!(
            !detail.user_agent.chars().any(char::is_control),
            "a control character survived: {:?}",
            detail.user_agent
        );
    }

    /// The cap is for display only — the lookups still use the string the
    /// caller passed, or a long user agent would silently be reported on
    /// as some other one.
    #[test]
    fn a_capped_string_is_still_looked_up_in_full() {
        let db = db_with_bots();
        let long = format!("{} Googlebot/2.1", "A".repeat(MAX_USER_AGENT_CHARS));

        let detail = load(&db, &long);

        assert!(detail.truncated);
        assert_eq!(detail.matches.len(), 1);
        assert_eq!(detail.matches[0].name, "Googlebot");
    }
}
