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

//! What is hitting the server right now, and whether it is already
//! blocked — the model behind the TUI's "Firewall" screen and
//! the web UI's.
//!
//! Lifted out of `tui/firewall.rs` when the web UI needed the
//! same answers, for the reason `scanblock` and `accessstats` were lifted
//! out before it: the *decision* about whether an address counts as
//! blocked is product behaviour, not presentation, and two front-ends
//! computing it separately is two front-ends that will eventually
//! disagree. What stayed behind is everything about lists, selection and
//! key handling.
//!
//! Nothing here reads a log. `sshlog` does that, and the caller passes the
//! text in: the TUI reads it on a background thread, and a web request
//! must not block its runtime on a `journalctl` subprocess either.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::Result;

use crate::db::{Bot, Category, Db, FirewallAction, Policy, UserAgentStat};
use crate::{ipranges, sshlog};

/// Whether a row's address/user agent is already covered by a stored
/// block. `Blocked { until: None }` renders as `BLOCKED`; `Some(t)`
/// (a temporary `firewall_rules` row, e.g. from `block-scanners`) renders
/// as `BLOCKED for <relative time>`. `Blocklist` means the item is blocked
/// by the botlist configuration (bot patterns or IP ranges), not by a manual
/// block action.
///
/// "for", not "until": [`format_until`] returns a *duration* ("1d", "23h"),
/// so "BLOCKED until 1d" read as though the block lifted at some moment
/// called 1d. The word the sentence needed was the one that takes a
/// length of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    Pending,
    Blocked {
        until: Option<i64>,
    },
    Blocklist,
    /// Looks like a bot, and *no* bot list has a pattern for it — not
    /// "allowed", which is what `Pending` means, but "nothing here has an
    /// opinion". See [`build_ua_rows`].
    Unknown,
}

impl RowStatus {
    pub fn label(self) -> String {
        match self {
            RowStatus::Pending => "NOT BLOCKED".to_string(),
            RowStatus::Blocked { until: None } => "BLOCKED".to_string(),
            RowStatus::Blocked {
                until: Some(expires_at),
            } => format!("BLOCKED for {}", format_until(expires_at)),
            RowStatus::Blocklist => "BLOCKLIST".to_string(),
            RowStatus::Unknown => "UNKNOWN".to_string(),
        }
    }

    pub fn is_blocked(self) -> bool {
        matches!(self, RowStatus::Blocked { .. } | RowStatus::Blocklist)
    }

    pub fn is_blocklist(self) -> bool {
        matches!(self, RowStatus::Blocklist)
    }
}

/// A shared display filter applied to both panels — cycled with `f`
/// (`All` -> `NotBlockedOnly` -> `BlockedOnly` -> `All`). One filter for both
/// panels rather than a separate one each: this screen only ever shows one
/// filter's worth of state at a time in its titles, and both panels share
/// the same "what am I looking for right now" question (either "what's
/// still unblocked" or "what's already enforced").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    All,
    PendingOnly,
    BlockedOnly,
}

impl Filter {
    pub fn matches(self, status: RowStatus) -> bool {
        match self {
            Filter::All => true,
            Filter::PendingOnly => !status.is_blocked(),
            Filter::BlockedOnly => status.is_blocked(),
        }
    }

    pub fn next(self) -> Self {
        match self {
            Filter::All => Filter::PendingOnly,
            Filter::PendingOnly => Filter::BlockedOnly,
            Filter::BlockedOnly => Filter::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Filter::All => "all",
            Filter::PendingOnly => "not blocked only",
            Filter::BlockedOnly => "blocked only",
        }
    }
}

/// One ranked IP row in the SSH panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRow {
    pub address: String,
    pub count: u64,
    pub status: RowStatus,
}

/// One ranked user agent row in the User Agents panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaRow {
    pub user_agent: String,
    pub count: u64,
    pub status: RowStatus,
}

/// Turns raw failed-attempt `counts` (see [`sshlog::failed_attempt_counts`])
/// into ranked, status-tagged rows: an address present (with a Block
/// action) in `firewall_blocks` is `Blocked` (its `Option<i64>` is the
/// rule's `expires_at`, `None` meaning permanent); everything else is
/// `NOT BLOCKED`. Sorted by count descending, address ascending as a
/// deterministic tiebreaker.
pub fn build_ssh_rows(
    counts: HashMap<String, u64>,
    firewall_blocks: &HashMap<String, Option<i64>>,
    blocked_ip_ranges: &[String],
) -> Vec<SshRow> {
    let mut rows: Vec<SshRow> = counts
        .into_iter()
        .map(|(address, count)| {
            // Manual blocks take precedence over blocklist
            let status = if let Some(until) = firewall_blocks.get(&address) {
                RowStatus::Blocked { until: *until }
            } else if ip_in_blocked_range(&address, blocked_ip_ranges) {
                RowStatus::Blocklist
            } else {
                RowStatus::Pending
            };
            SshRow {
                address,
                count,
                status,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.address.cmp(&b.address))
    });
    rows
}

/// Turns `stats` (already sorted by `Db::list_user_agent_stats`) into
/// status-tagged rows: a user agent present in `blocked` is permanently
/// `Blocked` (manual blocks have no TTL and take precedence); a user agent
/// matching a blocked bot pattern is `Blocklist`; everything else is `NOT BLOCKED`.
pub fn build_ua_rows(
    stats: Vec<UserAgentStat>,
    blocked: &HashSet<String>,
    bots: &[Bot],
    ai_policy: Policy,
    search_policy: Policy,
    scanner_policy: Policy,
) -> Vec<UaRow> {
    stats
        .into_iter()
        .map(|stat| {
            // Manual blocks take precedence over blocklist
            let status = if blocked.contains(&stat.user_agent) {
                RowStatus::Blocked { until: None }
            } else if ua_matches_blocked_bot_patterns(
                &stat.user_agent,
                bots,
                ai_policy,
                search_policy,
                scanner_policy,
            ) {
                RowStatus::Blocklist
            } else if looks_like_a_bot(&stat.user_agent)
                && !ua_matches_any_bot_pattern(&stat.user_agent, bots)
            {
                RowStatus::Unknown
            } else {
                RowStatus::Pending
            };
            UaRow {
                user_agent: stat.user_agent,
                count: stat.hit_count as u64,
                status,
            }
        })
        .collect()
}

/// Whether `ua` advertises itself as a bot.
///
/// Deliberately a test of the *string*, not of behaviour — the detectors
/// already judge behaviour (`AssetRatio` and `RotatingUserAgent` both
/// report "non-browser IP"s), and this answers a different question: is
/// this thing telling us what it is? That is what makes a missing list
/// entry worth an admin's attention rather than just another visitor.
///
/// The tokens are the ones bots actually use, and `+http` is the
/// convention for citing a page about yourself. Checked against 6,493
/// distinct user agents from a real access log: it flagged 1,070, and
/// **none** of the 4,644 that carry an ordinary browser's product tokens.
/// The handful that looked like false positives were `Storebot-Google`
/// and browser strings claiming to be an iPhone on Linux — bots both.
///
/// False negatives are cheap here: a bot this misses simply gets no tag,
/// exactly as before. A false positive would put a misleading label on a
/// real visitor's row, which is why the list is short and none of the
/// words is one a browser might use about itself.
pub fn looks_like_a_bot(ua: &str) -> bool {
    const MARKERS: [&str; 7] = [
        "bot", "crawler", "spider", "scanner", "scraper", "probe", "+http",
    ];
    let lower = ua.to_lowercase();
    MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Whether *any* bot list has a pattern for `ua`, whatever its category or
/// status.
///
/// Distinct from [`ua_matches_blocked_bot_patterns`], which asks whether
/// the lists would block it right now. A bot that is known and allowed is
/// still known; only something no list has heard of is `Unknown`.
pub fn ua_matches_any_bot_pattern(ua: &str, bots: &[Bot]) -> bool {
    let ua_lower = ua.to_lowercase();
    bots.iter()
        .any(|bot| matched_alternative_lowered(&ua_lower, bot).is_some())
}

/// Which of `bot`'s accepted patterns `ua` contains, if any, in the
/// casing the list published it in.
///
/// The same comparison [`ua_matches_any_bot_pattern`] makes, but keeping
/// *which* alternative matched instead of discarding it. A detail view
/// saying "matched `Googlebot`" is worth more than one saying "matched
/// `Googlebot|Googlebot-Image|Googlebot-News|Storebot-Google`", which is
/// what a merged row's whole pattern often looks like after three lists
/// have contributed to it.
pub fn matched_alternative(ua: &str, bot: &Bot) -> Option<String> {
    matched_alternative_lowered(&ua.to_lowercase(), bot)
}

/// [`matched_alternative`] with the lowercasing already done, so a scan
/// over a thousand bots pays for it once rather than once per bot.
fn matched_alternative_lowered(ua_lower: &str, bot: &Bot) -> Option<String> {
    unescape_pattern(&bot.user_agent_pattern)
        .split('|')
        .find(|alternative| {
            !alternative.is_empty() && ua_lower.contains(&alternative.to_lowercase())
        })
        .map(str::to_string)
}

/// Strips regex backslash-escapes from a stored pattern so it can be
/// compared as a literal substring.
///
/// **Not cosmetic.** 217 of the 1,606 patterns on a real host come from
/// `nginx-bad-bots`, which ships them regex-ready: `Googlebot\/`,
/// `Mediapartners \(Googlebot\)`. A plain `contains` can never match any
/// of them, because the user agent has no backslash in it — so a screen
/// doing substring comparison silently believed the commonest crawler on
/// the web was in no list at all. `nginx_bad_bots::unescape` does the same
/// thing for display; this is the matching half.
///
/// Only the escapes are removed, so a pattern that is *genuinely* a regex
/// (`AdsBot-Google([^-]|$)`) still will not match as a literal. That is a
/// known limit of comparing without a regex engine, and it errs the safe
/// way for this screen: an unmatched pattern means a row is called unknown
/// when a list does know it, which is a missed hint, not a wrong block.
fn unescape_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                out.push(escaped);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Checks if a user agent string matches any blocked bot pattern.
/// Uses a simple case-insensitive substring check since we don't have
/// the regex crate available. This is a best-effort check that may have
/// false positives/negatives compared to proper regex matching.
pub fn ua_matches_blocked_bot_patterns(
    ua: &str,
    bots: &[Bot],
    ai_policy: Policy,
    search_policy: Policy,
    scanner_policy: Policy,
) -> bool {
    // For each bot that is currently blocked (based on its status and category policies),
    // check if the UA contains the bot's pattern (case-insensitive).
    for bot in bots {
        // Check if this bot is currently blocked
        let bot_blocked = match bot.status {
            crate::db::BotStatus::Blocked => true,
            crate::db::BotStatus::Allowed => false,
            crate::db::BotStatus::Default => {
                (bot.is_ai && ai_policy == Policy::Blocked)
                    || (bot.is_search_engine && search_policy == Policy::Blocked)
                    || (bot.is_scanner && scanner_policy == Policy::Blocked)
            }
        };

        if bot_blocked {
            // Simple case-insensitive substring check
            let ua_lower = ua.to_lowercase();
            let pattern_lower = bot.user_agent_pattern.to_lowercase();
            // Split pattern by | and check if any alternative matches
            for alternative in pattern_lower.split('|') {
                if ua_lower.contains(alternative) {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if an IP address is in any blocked IP range (crawler ranges).
pub fn ip_in_blocked_range(ip_str: &str, blocked_ranges: &[String]) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        for cidr in blocked_ranges {
            if ipranges::cidr_contains(cidr, ip) {
                return true;
            }
        }
    }
    false
}

/// Formats a future Unix timestamp `expires_at` as a short "Nd"/"Nh"
/// relative string for a `RowStatus::Blocked`'s "until" text — same
/// rounding convention as `main.rs::format_expiry` (that one isn't
/// reachable from the library crate, hence this small local twin).
pub fn format_until(expires_at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seconds_left = (expires_at - now).max(0);
    let days = seconds_left / 86_400;
    if days > 0 {
        format!("{days}d")
    } else {
        let hours = (seconds_left / 3_600).max(1);
        format!("{hours}h")
    }
}

/// Both panels' worth of rows, loaded together.
pub struct Live {
    pub ssh: Vec<SshRow>,
    pub user_agents: Vec<UaRow>,
}

impl Live {
    /// Reads everything both panels need from `db`.
    ///
    /// `ssh_log_text` is the log itself, already read. `None` means it was
    /// not available and the SSH half comes back empty, which is what the
    /// TUI shows while its background read is still in flight.
    pub fn load(db: &Db, ssh_log_text: Option<&str>) -> Result<Self> {
        let firewall_blocks: HashMap<String, Option<i64>> = db
            .list_firewall_rules()?
            .into_iter()
            .filter(|rule| rule.action == FirewallAction::Block)
            .map(|rule| (rule.address, rule.expires_at))
            .collect();
        let blocked_ip_ranges = db.blocked_ip_ranges()?;
        let ssh_counts = match ssh_log_text {
            Some(text) => sshlog::failed_attempt_counts(text),
            None => HashMap::new(),
        };
        let ssh = build_ssh_rows(ssh_counts, &firewall_blocks, &blocked_ip_ranges);

        let blocked_uas: HashSet<String> = db.list_blocked_user_agents()?.into_iter().collect();
        let bots = db.list_bots()?;
        let user_agents = build_ua_rows(
            db.list_user_agent_stats()?,
            &blocked_uas,
            &bots,
            db.get_category_default(Category::Ai)?,
            db.get_category_default(Category::Search)?,
            db.get_category_default(Category::Scanner)?,
        );

        Ok(Self { ssh, user_agents })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(ip, n)| (ip.to_string(), *n)).collect()
    }

    #[test]
    fn build_ssh_rows_ranks_by_count_descending() {
        let rows = build_ssh_rows(
            counts(&[("198.51.100.9", 3), ("198.51.100.2", 9)]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(rows[0].address, "198.51.100.2");
        assert_eq!(rows[0].count, 9);
        assert_eq!(rows[0].status, RowStatus::Pending);
        assert_eq!(rows[1].address, "198.51.100.9");
        assert_eq!(rows[1].count, 3);
    }

    #[test]
    fn build_ssh_rows_breaks_ties_by_address_for_determinism() {
        let rows = build_ssh_rows(
            counts(&[("198.51.100.9", 5), ("198.51.100.2", 5)]),
            &HashMap::new(),
            &[],
        );
        assert_eq!(rows[0].address, "198.51.100.2");
        assert_eq!(rows[1].address, "198.51.100.9");
    }

    #[test]
    fn build_ssh_rows_marks_a_permanently_blocked_address() {
        let mut blocks = HashMap::new();
        blocks.insert("198.51.100.9".to_string(), None);
        let rows = build_ssh_rows(counts(&[("198.51.100.9", 3)]), &blocks, &[]);
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
        assert_eq!(rows[0].status.label(), "BLOCKED");
    }

    #[test]
    fn build_ssh_rows_marks_a_temporarily_blocked_address_with_its_expiry() {
        let mut blocks = HashMap::new();
        blocks.insert("198.51.100.9".to_string(), Some(999_999_999_999));
        let rows = build_ssh_rows(counts(&[("198.51.100.9", 3)]), &blocks, &[]);
        assert!(matches!(
            rows[0].status,
            RowStatus::Blocked { until: Some(_) }
        ));
        // "for", not "until": `format_until` returns a duration, so the
        // preposition has to be the one that takes a length of time.
        // Only the prefix is asserted — the number is relative to now.
        let label = rows[0].status.label();
        assert!(label.starts_with("BLOCKED for "), "label was: {label}");
        assert!(!label.contains("until"), "label was: {label}");
    }

    /// The tag exists so the user agents nobody's list has heard of stop
    /// needing a script to find. A bot-shaped string no list matches is
    /// `Unknown`; the same string once a list carries it is not.
    #[test]
    fn a_bot_shaped_user_agent_no_list_knows_is_tagged_unknown() {
        let stats = vec![UserAgentStat {
            user_agent: "Mozilla/5.0 (compatible; CyberConvoyScout/1.0; +https://scout.example)"
                .to_string(),
            hit_count: 3476,
            last_seen_at: 0,
        }];

        let rows = build_ua_rows(
            stats.clone(),
            &HashSet::new(),
            &[],
            Policy::Blocked,
            Policy::Allowed,
            Policy::Blocked,
        );
        assert_eq!(rows[0].status, RowStatus::Unknown);
        assert_eq!(rows[0].status.label(), "UNKNOWN");

        // Now a list carries it — and it stops being unknown even though
        // this one is *allowed*, because "known" and "blocked" are
        // different questions.
        let known = [Bot {
            id: 1,
            slug: "cyberconvoyscout".to_string(),
            name: "CyberConvoyScout".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: true,
            user_agent_pattern: "CyberConvoyScout".to_string(),
            // Allowed, deliberately: "known" and "blocked" are different
            // questions, and only the first one decides `Unknown`.
            status: crate::db::BotStatus::Allowed,
            source_id: "test".to_string(),
            updated_at: 0,
        }];
        let rows = build_ua_rows(
            stats,
            &HashSet::new(),
            &known,
            Policy::Blocked,
            Policy::Allowed,
            Policy::Blocked,
        );
        assert_eq!(rows[0].status, RowStatus::Pending);
    }

    /// An ordinary browser is not tagged. It matches no bot pattern
    /// either, so without the bot-shape test every visitor on the screen
    /// would wear this label and it would mean nothing.
    #[test]
    fn an_ordinary_browser_is_not_tagged_unknown() {
        for ua in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
        ] {
            assert!(!looks_like_a_bot(ua), "flagged a browser: {ua}");
            let rows = build_ua_rows(
                vec![UserAgentStat {
                    user_agent: ua.to_string(),
                    hit_count: 1,
                    last_seen_at: 0,
                }],
                &HashSet::new(),
                &[],
                Policy::Blocked,
                Policy::Allowed,
                Policy::Blocked,
            );
            assert_eq!(rows[0].status, RowStatus::Pending, "for {ua}");
        }
    }

    /// The markers, each against a string actually seen in a log.
    #[test]
    fn looks_like_a_bot_recognises_how_bots_announce_themselves() {
        for ua in [
            "SofyaBot/1.0 (+https://sofya.example/bot)",
            "Mozilla/5.0 (compatible; jscrawler/0.1; +https://example.invalid/)",
            "Umai-Scanner/2.0 (+https://umai.example/methodology)",
            "zmap-proxy-probe/1.0",
            "IMJ-CompanyPage-Scraper/2.0",
            // No marker word at all, but it cites a page about itself,
            // which no browser does.
            "Mozilla/5.0 (compatible; Infrawatch/1.0; +https://infrawat.example/)",
        ] {
            assert!(looks_like_a_bot(ua), "missed: {ua}");
        }

        // And the honest limit: a bot whose name says nothing and that
        // cites nothing is indistinguishable from a browser by string
        // alone. `Silovik/2.0` is real, and this is what catches it
        // instead — the behavioural detectors, not this.
        assert!(!looks_like_a_bot("Mozilla/5.0 (compatible; Silovik/2.0)"));
    }

    /// A blocked or blocklisted row keeps its own tag: `Unknown` is for
    /// rows nothing has acted on, and saying "unknown" about something
    /// already blocked would be false.
    #[test]
    fn a_blocked_user_agent_is_never_tagged_unknown() {
        let ua = "SofyaBot/1.0 (+https://sofya.example/bot)";
        let mut blocked = HashSet::new();
        blocked.insert(ua.to_string());

        let rows = build_ua_rows(
            vec![UserAgentStat {
                user_agent: ua.to_string(),
                hit_count: 1,
                last_seen_at: 0,
            }],
            &blocked,
            &[],
            Policy::Blocked,
            Policy::Allowed,
            Policy::Blocked,
        );
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn build_ua_rows_preserves_incoming_order_and_tags_blocked_ones() {
        let stats = vec![
            UserAgentStat {
                user_agent: "Mozilla/5.0".to_string(),
                hit_count: 42,
                last_seen_at: 1000,
            },
            UserAgentStat {
                user_agent: "curl/8.0".to_string(),
                hit_count: 3,
                last_seen_at: 1000,
            },
        ];
        let mut blocked = HashSet::new();
        blocked.insert("curl/8.0".to_string());

        let rows = build_ua_rows(
            stats,
            &blocked,
            &[],
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(rows[0].user_agent, "Mozilla/5.0");
        assert_eq!(rows[0].status, RowStatus::Pending);
        assert_eq!(rows[1].user_agent, "curl/8.0");
        assert_eq!(rows[1].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn build_ssh_rows_marks_ip_in_blocked_range_as_blocklist() {
        let rows = build_ssh_rows(
            counts(&[("192.168.1.5", 3)]),
            &HashMap::new(),
            &["192.168.1.0/24".to_string()],
        );
        assert_eq!(rows[0].address, "192.168.1.5");
        assert_eq!(rows[0].status, RowStatus::Blocklist);
        assert_eq!(rows[0].status.label(), "BLOCKLIST");
    }

    #[test]
    fn build_ssh_rows_prioritizes_manual_block_over_blocklist() {
        let mut blocks = HashMap::new();
        blocks.insert("192.168.1.5".to_string(), None);
        let rows = build_ssh_rows(
            counts(&[("192.168.1.5", 3)]),
            &blocks,
            &["192.168.1.0/24".to_string()],
        );
        assert_eq!(rows[0].address, "192.168.1.5");
        // Manual block takes precedence over blocklist
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn build_ua_rows_marks_ua_matching_bot_pattern_as_blocklist() {
        let stats = vec![UserAgentStat {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string(),
            hit_count: 42,
            last_seen_at: 1000,
        }];
        let blocked = HashSet::new();
        let bots = vec![Bot {
            id: 1,
            slug: "googlebot".to_string(),
            name: "Googlebot".to_string(),
            is_ai: false,
            is_search_engine: true,
            is_scanner: false,
            user_agent_pattern: "Googlebot".to_string(),
            status: crate::db::BotStatus::Default,
            source_id: "test".to_string(),
            updated_at: 1000,
        }];

        let rows = build_ua_rows(
            stats,
            &blocked,
            &bots,
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(
            rows[0].user_agent,
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        );
        assert_eq!(rows[0].status, RowStatus::Blocklist);
        assert_eq!(rows[0].status.label(), "BLOCKLIST");
    }

    #[test]
    fn build_ua_rows_prioritizes_manual_block_over_blocklist() {
        let stats = vec![UserAgentStat {
            user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string(),
            hit_count: 42,
            last_seen_at: 1000,
        }];
        let mut blocked = HashSet::new();
        blocked.insert("Mozilla/5.0 (compatible; Googlebot/2.1)".to_string());
        let bots = vec![Bot {
            id: 1,
            slug: "googlebot".to_string(),
            name: "Googlebot".to_string(),
            is_ai: false,
            is_search_engine: true,
            is_scanner: false,
            user_agent_pattern: "Googlebot".to_string(),
            status: crate::db::BotStatus::Default,
            source_id: "test".to_string(),
            updated_at: 1000,
        }];

        let rows = build_ua_rows(
            stats,
            &blocked,
            &bots,
            Policy::Blocked,
            Policy::Blocked,
            Policy::Blocked,
        );
        assert_eq!(
            rows[0].user_agent,
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        );
        // Manual block takes precedence over blocklist
        assert_eq!(rows[0].status, RowStatus::Blocked { until: None });
    }
}
