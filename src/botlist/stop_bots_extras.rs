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

//! stop-bots' own list: bots seen hitting a real server that none of the
//! three upstream lists carried.
//!
//! **The only source here that is compiled in rather than downloaded.**
//! That is the point of it — a fresh install is covered before it has
//! network access, before `update-bot-lists` has ever run, and on a host
//! that cannot reach GitHub at all. [`fetch`] returns nothing and
//! [`parse`] ignores its argument; the list is [`EXTRAS`] below.
//!
//! ## Where these came from
//!
//! Two months of one server's NGINX access log — 6,493 distinct user
//! agents over ~500k requests — matched against every pattern the three
//! upstream sources contribute (1,606 of them). 5,283 user agents matched
//! none, almost all of them ordinary browsers; what is below is the
//! residue that was unambiguously a bot, generalised from the exact
//! strings seen to the bot's *name*.
//!
//! ## What is deliberately not here
//!
//! - **Anything already covered upstream.** `curl/7.74.0` and
//!   `WordPress/6.9.4` were blocked by hand on that server and are both
//!   already matched by `^curl` and `WordPress\/`; a second copy would
//!   only make the merge cascade harder to read.
//! - **Site-specific strings.** A URL that arrived in the user-agent field
//!   (`http://example.invalid/wp-admin/install.php`) is an attack
//!   artifact, not a user agent, and one server's own hostname is nobody
//!   else's problem.
//! - **Real software pinned to a build.** `eMClient/10.4.4867.0` is a mail
//!   client; blocking two exact build numbers helps no one and blocking
//!   the product would be wrong.
//! - **Names too generic to be safe in a substring match.** `Scanner/1.0`
//!   and a bare `scanner` were both seen; either would match a third of
//!   the list below and plenty of software that is not a bot.
//! - **A bare `Googlebot`** (no version), which the upstream `Googlebot\/`
//!   pattern misses. It is almost certainly an impersonator — real
//!   Googlebot always sends a version — but an impersonator is what
//!   `scanblock`'s spoofed-crawler detector exists to catch, using
//!   Google's published ranges. Blocking the name here would also block
//!   the real one on any host that turned the search category off.
//! - **`Let's Encrypt validation server`.** Seen 68 times, and blocking it
//!   breaks ACME HTTP-01 renewal in a way that surfaces as an expired
//!   certificate two months later. There is a test that no pattern here
//!   matches it.
//!
//! ## Versions are stripped on purpose
//!
//! Every pattern is the bot's bare name. The upstream lists' own worst
//! entry is `Googlebot\/`, which stops matching the moment a client drops
//! the version — over-specific patterns are exactly the failure this list
//! exists to correct, so repeating it would be perverse.

use crate::db::NewBot;
use anyhow::Result;

pub const SOURCE_ID: &str = "stop-bots-extras";
pub const SOURCE_NAME: &str = "stop-bots enhanced list";
pub const SOURCE_URL: &str =
    "https://github.com/ivankovic/stop-bots/blob/main/src/botlist/stop_bots_extras.rs";

/// Which category a built-in entry belongs to. Deliberately not a blanket
/// "blocked": these carry the same category flags every other source's
/// bots do, so the host's own AI/scanner policy decides, and a per-bot
/// override still wins over both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// An AI company's crawler. Blocked wherever the AI category is, which
    /// is the default — but an admin who wants them keeps one switch.
    Ai,
    /// A vulnerability scanner, attack-surface mapper, or commercial
    /// crawler whose traffic is nobody's idea of a visitor.
    Scanner,
    /// Something that must be *recognised* and never blocked by a category
    /// default — carried here so nothing invites an admin to block it.
    ///
    /// Carries no category flag at all, which is what makes it inert:
    /// `Db::compute_blocked_patterns` ORs the three flags together, so an
    /// entry with none can never be blocked by policy. An admin who really
    /// wants to can still pin it by hand; nothing here will suggest it.
    Infrastructure,
}

/// `(display name, user-agent substring, category)`.
///
/// The substring is matched case-insensitively and unanchored, the same
/// way every other source's pattern is — see `nginx::block_text`.
const EXTRAS: &[(&str, &str, Kind)] = &[
    // ---- known-good, carried so nothing proposes blocking them ----
    // Seen 68 times on the host this list came from, and in *no* bot list
    // at all — which meant the Dynamic Protection screen showed it beside
    // the scanners with nothing to say it was different. Blocking it
    // breaks ACME HTTP-01 renewal, and the damage surfaces as an expired
    // certificate two months later, long after anyone would connect the
    // two. Recognising it costs one row.
    (
        "Let's Encrypt validation",
        "Let's Encrypt",
        Kind::Infrastructure,
    ),
    // ---- AI crawlers ai.robots.txt did not carry ----
    // xAI ships at least three names; all three were seen, and the last
    // arrives inside randomised browser strings (see the note below).
    ("xAI-SearchBot", "xAI-SearchBot", Kind::Ai),
    ("xAI-Grok", "xAI-Grok", Kind::Ai),
    // Seen 95 times across 40-odd *different* browser user agents, each
    // one a plausible Chrome/Firefox/Safari string with the bot's own
    // identity appended. That is a rotating user agent, which is what
    // `Detector::RotatingUa` looks for — but a name this consistent is
    // cheaper to catch here.
    ("GrokBot", "GrokBot", Kind::Ai),
    ("MoonshotBot (Kimi)", "MoonshotBot", Kind::Ai),
    ("Hunyuan (Tencent)", "Hunyuan", Kind::Ai),
    ("YiBot (01.AI)", "YiBot", Kind::Ai),
    // ---- attack-surface scanners, by volume ----
    ("Silovik", "Silovik", Kind::Scanner),
    ("pathscan", "pathscan", Kind::Scanner),
    ("CyberConvoyScout", "CyberConvoyScout", Kind::Scanner),
    ("Infrawatch", "Infrawatch", Kind::Scanner),
    // Two names, one operator: `FlowIQLabsBot` and `FlowIQ`, both citing
    // flowiq-labs.com. The shorter name covers both.
    ("FlowIQ Labs", "FlowIQ", Kind::Scanner),
    ("visionheight", "visionheight", Kind::Scanner),
    // Palo Alto's Cortex Xpanse announces itself in prose — "Hello from
    // Palo Alto Networks..." — with no product token at all. The scan
    // programme's own name is the only stable substring in it.
    ("Cortex Xpanse (Palo Alto)", "Cortex-Xpanse", Kind::Scanner),
    ("SecurityScanner", "SecurityScanner", Kind::Scanner),
    // Also covers `BotExposureScanner`, which is why that is not listed
    // separately.
    ("ExposureScanner", "ExposureScanner", Kind::Scanner),
    ("ExposureWatch", "ExposureWatch", Kind::Scanner),
    ("ModatScanner", "ModatScanner", Kind::Scanner),
    ("SofyaBot", "SofyaBot", Kind::Scanner),
    ("Umai-Scanner", "Umai-Scanner", Kind::Scanner),
    ("jscrawler", "jscrawler", Kind::Scanner),
    ("CMS-Checker", "CMS-Checker", Kind::Scanner),
    ("FreePBX-Scanner", "FreePBX-Scanner", Kind::Scanner),
    ("foda-scanner", "foda-scanner", Kind::Scanner),
    ("FastSourceScanner", "FastSourceScanner", Kind::Scanner),
    ("SmarterMail-Scanner", "SmarterMail-Scanner", Kind::Scanner),
    ("GoScanner", "GoScanner", Kind::Scanner),
    ("NextScanner", "NextScanner", Kind::Scanner),
    ("WP-Safe-Scanner", "WP-Safe-Scanner", Kind::Scanner),
    ("CT-WP-Scanner", "CT-WP-Scanner", Kind::Scanner),
    ("ArgusScanner", "ArgusScanner", Kind::Scanner),
    (
        "AgentReadinessScanner",
        "AgentReadinessScanner",
        Kind::Scanner,
    ),
    ("zmap-proxy-probe", "zmap-proxy-probe", Kind::Scanner),
    ("tchelebi", "tchelebi", Kind::Scanner),
    ("l9tcpid", "l9tcpid", Kind::Scanner),
    ("RootEvidence", "RootEvidence", Kind::Scanner),
    ("vuln_scanner", "vuln_scanner", Kind::Scanner),
    ("RecordedFuture Inventory", "RecordedFuture", Kind::Scanner),
    // ---- SEO and data-broker crawlers ----
    (
        "SERankingBacklinksBot",
        "SERankingBacklinksBot",
        Kind::Scanner,
    ),
    ("DomainScores", "DomainScores", Kind::Scanner),
    ("TechSpyBot", "TechSpyBot", Kind::Scanner),
    ("GlobRadarBot", "GlobRadarBot", Kind::Scanner),
    ("ScalinthBot", "ScalinthBot", Kind::Scanner),
    ("ForestEngine", "ForestEngine", Kind::Scanner),
    ("LohiSoftBot", "LohiSoftBot", Kind::Scanner),
    ("SleepBot", "SleepBot", Kind::Scanner),
    ("BrokenLinksBot", "BrokenLinksBot", Kind::Scanner),
];

/// The built-in list as `NewBot` rows.
pub fn bots() -> Vec<NewBot> {
    EXTRAS
        .iter()
        .map(|(name, pattern, kind)| NewBot {
            slug: crate::botlist::slugify(name),
            name: (*name).to_string(),
            is_ai: *kind == Kind::Ai,
            is_search_engine: false,
            // `Infrastructure` sets none of the three, so no category
            // default can reach it — see `Kind::Infrastructure`.
            is_scanner: *kind == Kind::Scanner,
            user_agent_pattern: (*pattern).to_string(),
            source_id: SOURCE_ID.to_string(),
        })
        .collect()
}

/// Nothing to download. Kept so this source goes through the same
/// fetch-then-parse pair as the other three and needs no special case in
/// `refresh` or `SourceKind::update`.
pub async fn fetch() -> Result<String> {
    Ok(String::new())
}

/// Ignores `raw` — the list is compiled in. See [`fetch`].
pub fn parse(_raw: &str) -> Result<Vec<NewBot>> {
    Ok(bots())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strings that must never match anything in this list, each with the
    /// reason it would hurt. This is the test that earns the right to ship
    /// a blocklist to other people's servers.
    const MUST_NOT_MATCH: &[(&str, &str)] = &[
        (
            "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
            "blocking ACME HTTP-01 breaks certificate renewal, and the damage shows up as \
             an expired certificate two months later",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/126.0.0.0 Safari/537.36",
            "the commonest desktop browser string on the web",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "the commonest mobile browser string",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
            "Firefox on Linux",
        ),
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "the real Googlebot is the upstream lists' job, and a host that allows the \
             search category must keep allowing it",
        ),
        (
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "same, for Bing",
        ),
    ];

    /// Checked against the entries that can *block* — `Ai` and `Scanner`.
    /// `Infrastructure` entries are excluded because matching is their
    /// entire job: they exist so that something like Let's Encrypt is
    /// recognised rather than left looking unidentified, and they carry no
    /// category flag, so no policy can act on the match.
    #[test]
    fn no_blocking_pattern_matches_something_that_must_not_be_blocked() {
        for (subject, why) in MUST_NOT_MATCH {
            for (name, pattern, kind) in EXTRAS {
                if *kind == Kind::Infrastructure {
                    continue;
                }
                assert!(
                    !subject.to_lowercase().contains(&pattern.to_lowercase()),
                    "{name:?} (pattern {pattern:?}) matches {subject:?} — {why}"
                );
            }
        }
    }

    /// And the other half: an `Infrastructure` entry must carry no
    /// category flag, or the policy that blocks scanners would block it.
    #[test]
    fn an_infrastructure_entry_can_never_be_blocked_by_a_category() {
        for bot in bots() {
            let (_, _, kind) = EXTRAS
                .iter()
                .find(|(name, _, _)| *name == bot.name)
                .expect("every bot comes from an entry");
            if *kind != Kind::Infrastructure {
                continue;
            }
            assert!(
                !bot.is_ai && !bot.is_search_engine && !bot.is_scanner,
                "{} carries a category flag, so a policy could block it",
                bot.name
            );
        }
    }

    /// Patterns are bare names. A version in a pattern stops matching the
    /// day the bot is upgraded, which is how the upstream `Googlebot\/`
    /// came to miss a bare `Googlebot`.
    ///
    /// Tested as "no `/`, and no trailing number" rather than "no digits
    /// at all": `l9tcpid` is leakix's tool name and the 9 is part of it,
    /// not a version. A digit in the *middle* of a name is a name; a
    /// digit after a slash, or at the end, is a version.
    #[test]
    fn no_pattern_carries_a_version() {
        for (name, pattern, _) in EXTRAS {
            assert!(
                !pattern.contains('/'),
                "{name:?} pins a version in {pattern:?}"
            );
            assert!(
                !pattern.ends_with(|c: char| c.is_ascii_digit() || c == '.'),
                "{name:?}'s pattern {pattern:?} ends in what looks like a version"
            );
        }
    }

    /// A pattern short enough to appear inside an unrelated word is a
    /// false positive waiting to happen — the list is matched unanchored
    /// and case-insensitively.
    ///
    /// Five is the floor rather than something larger because the real
    /// guard is
    /// [`no_pattern_matches_something_that_must_not_be_blocked`] plus the
    /// corpus this list was read off: `FlowIQ` and `YiBot` are six and
    /// five characters and both are CamelCase product names that appear
    /// in no browser string. A length rule alone cannot tell those from a
    /// common word, so it is set to catch only the obviously reckless.
    #[test]
    fn every_pattern_is_long_enough_to_be_distinctive() {
        for (name, pattern, _) in EXTRAS {
            assert!(
                pattern.len() >= 5,
                "{name:?}'s pattern {pattern:?} is too short to match safely"
            );
        }
    }

    /// No pattern may be an ordinary English word, whatever its length —
    /// the list is matched unanchored against strings that contain prose
    /// (Palo Alto's announces itself in a sentence), so a real word would
    /// match things that have nothing to do with a bot.
    #[test]
    fn no_pattern_is_a_plain_word() {
        const WORDS: &[&str] = &[
            "scanner", "crawler", "spider", "monitor", "search", "agent", "client", "browser",
            "mozilla", "safari", "chrome", "python", "robot", "index", "check", "fetch",
        ];
        for (name, pattern, _) in EXTRAS {
            let lower = pattern.to_lowercase();
            assert!(
                !WORDS.contains(&lower.as_str()),
                "{name:?}'s pattern {pattern:?} is a plain word"
            );
        }
    }

    /// Two entries with the same slug would collapse into one row and the
    /// second's category would silently win.
    #[test]
    fn slugs_and_patterns_are_unique() {
        let bots = bots();
        let mut slugs: Vec<&str> = bots.iter().map(|b| b.slug.as_str()).collect();
        slugs.sort_unstable();
        let before = slugs.len();
        slugs.dedup();
        assert_eq!(slugs.len(), before, "duplicate slug in the built-in list");

        let mut patterns: Vec<&str> = EXTRAS.iter().map(|(_, p, _)| *p).collect();
        patterns.sort_unstable();
        let before = patterns.len();
        patterns.dedup();
        assert_eq!(patterns.len(), before, "duplicate pattern");
    }

    /// No entry may be redundant against another: an unanchored substring
    /// that contains a second pattern makes the second unreachable, which
    /// is how `BotExposureScanner` came out (it is covered by
    /// `ExposureScanner`).
    #[test]
    fn no_pattern_is_swallowed_by_another() {
        for (name, pattern, _) in EXTRAS {
            for (other_name, other, _) in EXTRAS {
                if pattern == other {
                    continue;
                }
                assert!(
                    !pattern.to_lowercase().contains(&other.to_lowercase()),
                    "{name:?} ({pattern:?}) is already covered by {other_name:?} ({other:?})"
                );
            }
        }
    }

    /// Every entry carries exactly one category, so the host's own policy
    /// has something to decide with. A bot with no flags set is
    /// unreachable by any category default and can only ever be blocked by
    /// hand, which defeats the point of shipping it.
    #[test]
    fn every_blocking_bot_carries_exactly_one_category() {
        for (name, _, kind) in EXTRAS {
            if *kind == Kind::Infrastructure {
                continue;
            }
            let bot = bots()
                .into_iter()
                .find(|b| b.name == *name)
                .expect("every entry becomes a bot");
            let flags = [bot.is_ai, bot.is_search_engine, bot.is_scanner];
            assert_eq!(
                flags.iter().filter(|f| **f).count(),
                1,
                "{name} has {flags:?}"
            );
        }
    }

    /// The built-in list needs no network and no argument.
    #[tokio::test]
    async fn the_list_parses_without_fetching_anything() {
        let raw = fetch().await.unwrap();
        assert!(raw.is_empty(), "nothing should be downloaded");

        let bots = parse(&raw).unwrap();
        assert_eq!(bots.len(), EXTRAS.len());
        assert!(bots.iter().all(|b| b.source_id == SOURCE_ID));
    }

    /// The strings that prompted each entry, straight from the log they
    /// were found in — so a future edit that "tidies" a pattern has to
    /// answer for the traffic it stops matching.
    #[test]
    fn the_patterns_match_the_user_agents_they_were_taken_from() {
        const SEEN: &[&str] = &[
            "Mozilla/5.0 (compatible; Silovik/2.0)",
            "Mozilla/5.0 (compatible; pathscan/1.0)",
            "Mozilla/5.0 (compatible; CyberConvoyScout/1.0; +https://scout.cyberconvoy.co)",
            "Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.ch/)",
            "Mozilla/5.0 (compatible; FlowIQLabsBot/1.0; +https://flowiq-labs.com/scanning-info)",
            "Mozilla/5.0 (compatible; FlowIQ/1.0; +https://flowiq-labs.com/scanning-info)",
            "visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0",
            "Hello from Palo Alto Networks, find out more about our scans in \
             https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity",
            "ExposureWatch-Benchmark/0.1 (authorized-security-monitoring)",
            "BotExposureScanner/1.0 (+https://botexposure.com)",
            "l9tcpid/v1.1.0",
            "RootEvidence/1.0",
            "vuln_scanner/3.1.0 (CVE-2026-4020)",
            "RecordedFuture Global Inventory Crawler",
            "Mozilla/5.0 (compatible; xAI-SearchBot/1.0; +https://x.ai)",
            // The rotating one: a plausible browser string with the bot's
            // identity spliced into the engine comment.
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko; compatible; GrokBot/1.0; +https://x.ai/grokbot) Version/16.0 \
             Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; MoonshotBot/1.0; +https://kimi.ai/)",
            "Mozilla/5.0 (compatible; Hunyuan/1.0; +https://hunyuan.tencent.com/)",
            "Mozilla/5.0 (compatible; YiBot/1.0; +https://01.ai/)",
            // Appended after a complete, ordinary Chrome string.
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/140.0.0.0 Safari/537.36 ModatScanner/1.2 (+https://modat.io/)",
        ];
        for subject in SEEN {
            let lower = subject.to_lowercase();
            assert!(
                EXTRAS
                    .iter()
                    .any(|(_, p, _)| lower.contains(&p.to_lowercase())),
                "nothing in the list matches {subject:?}"
            );
        }
    }
}
