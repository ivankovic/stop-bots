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
///
/// `by` names the detector that wrote the block, when one did: `BLOCKED
/// for 4d by ssh-scanners` answers "who did this" on the row itself, and
/// the Blocks screen has the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    Pending,
    Blocked {
        until: Option<i64>,
        by: Option<crate::protection::Detector>,
    },
    Blocklist,
    /// Looks like a bot, and *no* bot list has a pattern for it — not
    /// "allowed", which is what `Pending` means, but "nothing here has an
    /// opinion". See [`build_ua_rows`].
    Unknown,
    /// Trusted by hand (see [`Db::trust_address`]/[`Db::trust_user_agent`]):
    /// never blocked, whatever else matches. Outranks every other status,
    /// because it outranks every other rule — a trusted address with a
    /// Block row is not blocked, and a row saying `BLOCKED` would be wrong.
    Trusted,
}

impl RowStatus {
    pub fn label(self) -> String {
        match self {
            RowStatus::Pending => "NOT BLOCKED".to_string(),
            RowStatus::Blocked { until, by } => {
                let mut label = "BLOCKED".to_string();
                if let Some(expires_at) = until {
                    label.push_str(&format!(" for {}", format_until(expires_at)));
                }
                if let Some(detector) = by {
                    label.push_str(&format!(" by {}", crate::blocks::detector_name(detector)));
                }
                label
            }
            RowStatus::Blocklist => "BLOCKLIST".to_string(),
            RowStatus::Unknown => "UNKNOWN".to_string(),
            RowStatus::Trusted => "TRUSTED".to_string(),
        }
    }

    pub fn is_blocked(self) -> bool {
        matches!(self, RowStatus::Blocked { .. } | RowStatus::Blocklist)
    }

    pub fn is_blocklist(self) -> bool {
        matches!(self, RowStatus::Blocklist)
    }

    pub fn is_trusted(self) -> bool {
        matches!(self, RowStatus::Trusted)
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
                RowStatus::Blocked {
                    until: *until,
                    by: None,
                }
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
        .map(|stat| UaRow {
            status: ua_status(
                &stat.user_agent,
                blocked,
                bots,
                [ai_policy, search_policy, scanner_policy],
            ),
            user_agent: stat.user_agent,
            count: stat.hit_count.max(0) as u64,
        })
        .collect()
}

/// One user agent's status, before trust: a manual block first, then a
/// blocked list pattern, then "calls itself a bot and no list knows it".
/// `policies` are the AI, search and scanner defaults, in that order.
fn ua_status(
    ua: &str,
    blocked: &HashSet<String>,
    bots: &[Bot],
    policies: [Policy; 3],
) -> RowStatus {
    let [ai, search, scanner] = policies;
    // Manual blocks take precedence over blocklist
    if blocked.contains(ua) {
        RowStatus::Blocked {
            until: None,
            by: None,
        }
    } else if ua_matches_blocked_bot_patterns(ua, bots, ai, search, scanner) {
        RowStatus::Blocklist
    } else if looks_like_a_bot(ua) && !ua_matches_any_bot_pattern(ua, bots) {
        RowStatus::Unknown
    } else {
        RowStatus::Pending
    }
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

/// Whether `address` is inside anything in `trusted` (addresses and CIDRs,
/// as [`Db::list_trusted_addresses`] returns them).
pub fn address_is_trusted(address: &str, trusted: &[String]) -> bool {
    trusted
        .iter()
        .any(|range| ipranges::cidrs_overlap(range, address) && range_covers(range, address))
}

/// Overlap alone would call a /24 row "trusted" because one address in it
/// is. A row is trusted only when the whole of it is, i.e. when the trusted
/// range contains the row's base address *and* is at least as wide.
fn range_covers(range: &str, row: &str) -> bool {
    fn prefix(cidr: &str) -> u32 {
        match cidr.split_once('/') {
            Some((_, len)) => len.parse().unwrap_or(0),
            None if cidr.contains(':') => 128,
            None => 32,
        }
    }
    prefix(range) <= prefix(row)
}

/// Whether `user_agent` contains any of `trusted`, ignoring case — the
/// same substring comparison NGINX makes against the trust file's escaped
/// `~*` keys, so this tag and the enforcement agree.
pub fn user_agent_is_trusted(user_agent: &str, trusted: &[String]) -> bool {
    let lower = user_agent.to_lowercase();
    trusted
        .iter()
        .any(|t| !t.is_empty() && lower.contains(&t.to_lowercase()))
}

/// One thing an operator has trusted by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedEntry {
    Address(String),
    UserAgent(String),
}

impl TrustedEntry {
    pub fn value(&self) -> &str {
        match self {
            TrustedEntry::Address(value) | TrustedEntry::UserAgent(value) => value,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TrustedEntry::Address(_) => "address",
            TrustedEntry::UserAgent(_) => "user agent",
        }
    }
}

/// Every trusted entry, addresses first — what the Trusted panels in both
/// front-ends list.
pub fn trusted_entries(db: &Db) -> Result<Vec<TrustedEntry>> {
    let mut entries: Vec<TrustedEntry> = db
        .list_trusted_addresses()?
        .into_iter()
        .map(TrustedEntry::Address)
        .collect();
    entries.extend(
        db.list_trusted_user_agents()?
            .into_iter()
            .map(TrustedEntry::UserAgent),
    );
    Ok(entries)
}

/// Trusts whatever an operator typed into a single "address or user
/// agent" field, and says which it was taken as.
///
/// The one field is a convenience that needs a guard. Taken naively —
/// "an address if it parses, otherwise a user agent" — a mistyped
/// `10.0.0.1/33` would be quietly trusted as a user-agent substring,
/// which trusts nothing the operator meant and is never noticed. So
/// anything spelled only in address characters is held to being an
/// address, and fails as one.
pub fn trust_typed(db: &Db, input: &str) -> Result<TrustedEntry> {
    let input = input.trim();
    let looks_like_address = (input.contains('.') || input.contains(':'))
        && input
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'));
    if looks_like_address {
        Ok(TrustedEntry::Address(db.trust_address(input)?))
    } else {
        Ok(TrustedEntry::UserAgent(db.trust_user_agent(input)?))
    }
}

/// Removes a trusted entry. Returns whether it was there.
pub fn untrust(db: &Db, entry: &TrustedEntry) -> Result<bool> {
    match entry {
        TrustedEntry::Address(address) => db.untrust_address(address),
        TrustedEntry::UserAgent(user_agent) => db.untrust_user_agent(user_agent),
    }
}

/// The evidence line a block made from an SSH row records: what the
/// operator was looking at when they chose to block it.
pub fn attempts_evidence(count: u64) -> String {
    match count {
        1 => "1 failed SSH login when it was blocked".to_string(),
        n => format!("{n} failed SSH logins when it was blocked"),
    }
}

/// Formats a future Unix timestamp `expires_at` as a short "Nd"/"Nh"
/// duration for a `RowStatus::Blocked`'s "for" text, the Blocks screens
/// and `list-firewall-rules`.
///
/// Rounded to the *nearest* whole day (from 23½ hours up) or hour, never
/// below one hour. It used to round down, which made a five-day block
/// read "4d" a minute after it was made — beside a Dashboard that said
/// the TTL was five days.
pub fn format_until(expires_at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    format_duration_left(expires_at - now)
}

fn format_duration_left(seconds_left: i64) -> String {
    let seconds_left = seconds_left.max(0);
    if seconds_left >= 23 * 3_600 + 1_800 {
        format!("{}d", ((seconds_left + 43_200) / 86_400).max(1))
    } else {
        format!("{}h", ((seconds_left + 1_800) / 3_600).max(1))
    }
}

/// How many user agents a Firewall screen shows at once: the most-seen
/// ones, a page at a time.
///
/// `user_agent_stats` holds whatever strings clients chose to send, and a
/// flood of distinct ones is cheap to make. Twenty thousand 4–8 KB agents
/// made the console's Firewall page read every row, classify each against
/// every bot pattern with the database locked for nine seconds, and send
/// 418 MB of HTML. A page of this many is what a person reads anyway.
pub const UA_PAGE_ROWS: usize = 200;

/// Both panels' worth of rows, loaded together.
pub struct Live {
    pub ssh: Vec<SshRow>,
    pub user_agents: Vec<UaRow>,
}

impl Live {
    /// Reads everything both panels need from `db` and classifies it, with
    /// the user-agent panel holding the [`UA_PAGE_ROWS`] most-seen agents.
    ///
    /// `ssh_log_text` is the log itself, already read. `None` means it was
    /// not available and the SSH half comes back empty, which is what the
    /// TUI shows while its background read is still in flight.
    ///
    /// The TUI's form, where `Db` lives on the thread that draws anyway. A
    /// caller holding a lock others wait on calls [`LiveInputs::read`]
    /// under it and [`LiveInputs::classify`] after letting go.
    pub fn load(db: &Db, ssh_log_text: Option<&str>) -> Result<Self> {
        let page = db.user_agent_stats_page(UA_PAGE_ROWS, 0)?;
        let stats = page.into_iter().map(|(_, stat)| stat).collect();
        Ok(LiveInputs::read(db, stats)?.classify(ssh_log_text))
    }
}

/// What [`Live`] is computed from: the database's half, read in one go and
/// owning everything, so that the slow half — parsing the SSH log and
/// matching every agent against every bot pattern — can run where the
/// database is not locked.
pub struct LiveInputs {
    firewall_blocks: HashMap<String, Option<i64>>,
    detectors: HashMap<String, crate::protection::Detector>,
    blocked_ip_ranges: Vec<String>,
    trusted_addresses: Vec<String>,
    /// The user agents to classify, in display order: a page of them.
    stats: Vec<UserAgentStat>,
    ua: UaVerdicts,
}

/// Everything a user agent's [`RowStatus`] depends on.
pub struct UaVerdicts {
    blocked: HashSet<String>,
    bots: Vec<Bot>,
    ai: Policy,
    search: Policy,
    scanner: Policy,
    trusted: Vec<String>,
}

impl UaVerdicts {
    /// The status `user_agent` would have as a row: the same precedence
    /// [`build_ua_rows`] applies, and trust over all of it.
    pub fn status_of(&self, user_agent: &str) -> RowStatus {
        if user_agent_is_trusted(user_agent, &self.trusted) {
            return RowStatus::Trusted;
        }
        ua_status(
            user_agent,
            &self.blocked,
            &self.bots,
            [self.ai, self.search, self.scanner],
        )
    }
}

impl LiveInputs {
    /// The database's half of [`Live`], for the user agents in `stats` —
    /// a page from [`Db::user_agent_stats_page`], never the whole table.
    /// Reads only; nothing here is proportional to the log or the bot list
    /// times the agents.
    pub fn read(db: &Db, stats: Vec<UserAgentStat>) -> Result<Self> {
        let blocks: Vec<_> = db
            .list_firewall_rules()?
            .into_iter()
            .filter(|rule| rule.action == FirewallAction::Block)
            .collect();
        let firewall_blocks = blocks
            .iter()
            .map(|rule| (rule.address.clone(), rule.expires_at))
            .collect();
        let detectors = blocks
            .iter()
            .filter_map(|rule| Some((rule.address.clone(), rule.source?.detector()?)))
            .collect();
        Ok(Self {
            firewall_blocks,
            detectors,
            blocked_ip_ranges: db.blocked_ip_ranges()?,
            trusted_addresses: db.list_trusted_addresses()?,
            stats,
            ua: UaVerdicts {
                // As the stats cut them, so a user agent blocked whole
                // still shows as blocked against its row.
                blocked: db
                    .list_blocked_user_agents()?
                    .iter()
                    .map(|ua| crate::db::stored_user_agent(ua).to_string())
                    .collect(),
                bots: db.list_bots()?,
                ai: db.get_category_default(Category::Ai)?,
                search: db.get_category_default(Category::Search)?,
                scanner: db.get_category_default(Category::Scanner)?,
                trusted: db.list_trusted_user_agents()?,
            },
        })
    }

    /// The verdicts a user agent outside the page can be classified by —
    /// a detail view opened on one, say.
    pub fn verdicts(&self) -> &UaVerdicts {
        &self.ua
    }

    /// Both panels, classified. Touches no database.
    pub fn classify(self, ssh_log_text: Option<&str>) -> Live {
        let ssh_counts = match ssh_log_text {
            Some(text) => sshlog::failed_attempt_counts(text),
            None => HashMap::new(),
        };
        let mut ssh = build_ssh_rows(ssh_counts, &self.firewall_blocks, &self.blocked_ip_ranges);
        for row in &mut ssh {
            if let RowStatus::Blocked { by, .. } = &mut row.status {
                *by = self.detectors.get(&row.address).copied();
            }
            if address_is_trusted(&row.address, &self.trusted_addresses) {
                row.status = RowStatus::Trusted;
            }
        }

        let user_agents = self
            .stats
            .into_iter()
            .map(|stat| UaRow {
                status: self.ua.status_of(&stat.user_agent),
                user_agent: stat.user_agent,
                count: stat.hit_count.max(0) as u64,
            })
            .collect();

        Live { ssh, user_agents }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_left_rounds_to_the_nearest_day_or_hour() {
        let table = [
            ("a five-day block a minute old", 5 * 86_400 - 60, "5d"),
            ("just over three days", 3 * 86_400 + 100, "3d"),
            ("three and a half days", 3 * 86_400 + 43_200, "4d"),
            ("23h40m reads as a day", 23 * 3_600 + 2_400, "1d"),
            ("five hours", 5 * 3_600, "5h"),
            ("an imminent expiry", 30, "1h"),
            ("already past", -10, "1h"),
        ];
        for (what, seconds, expected) in table {
            assert_eq!(format_duration_left(seconds), expected, "{what}");
        }
    }

    #[test]
    fn a_typed_entry_is_an_address_only_if_it_is_spelled_like_one() {
        let db = Db::open_in_memory().unwrap();
        for (typed, expected) in [
            ("203.0.113.7", TrustedEntry::Address("203.0.113.7".into())),
            (
                "2001:db8::/48",
                TrustedEntry::Address("2001:db8::/48".into()),
            ),
            ("UptimeRobot", TrustedEntry::UserAgent("UptimeRobot".into())),
            (
                "Pingdom.com_bot",
                TrustedEntry::UserAgent("Pingdom.com_bot".into()),
            ),
        ] {
            assert_eq!(trust_typed(&db, typed).unwrap(), expected, "{typed}");
        }
    }

    /// Otherwise a typo in an address is quietly trusted as a user-agent
    /// substring, trusting nothing the operator meant.
    #[test]
    fn a_mistyped_address_is_refused_not_trusted_as_a_user_agent() {
        let db = Db::open_in_memory().unwrap();
        assert!(trust_typed(&db, "10.0.0.1/33").is_err());
        assert!(trust_typed(&db, "10.0.0.256").is_err());
        assert!(trusted_entries(&db).unwrap().is_empty());
    }

    #[test]
    fn an_address_row_is_trusted_only_when_all_of_it_is() {
        let trusted = vec!["198.51.100.0/24".to_string(), "2001:db8::5".to_string()];
        for (row, expected) in [
            ("198.51.100.9", true),
            ("198.51.100.0/25", true),
            ("198.51.0.0/16", false),
            ("198.51.101.9", false),
            ("2001:db8::5", true),
            ("2001:db8::/64", false),
        ] {
            assert_eq!(address_is_trusted(row, &trusted), expected, "{row}");
        }
    }

    #[test]
    fn a_user_agent_is_trusted_by_substring_ignoring_case() {
        let trusted = vec!["uptimerobot".to_string()];
        assert!(user_agent_is_trusted(
            "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
            &trusted
        ));
        assert!(!user_agent_is_trusted("curl/8.0", &trusted));
    }

    /// Trust outranks a manual block on the row, because it outranks the
    /// rule: the Allow goes first. Showing BLOCKED would be wrong.
    #[test]
    fn a_trusted_address_with_a_block_row_shows_as_trusted() {
        let db = Db::open_in_memory().unwrap();
        db.block_address_permanently("198.51.100.9", crate::db::RuleSource::Tui, None)
            .unwrap();
        db.trust_address("198.51.100.9").unwrap();
        let log = "Failed password for root from 198.51.100.9 port 4444 ssh2\n";

        let live = Live::load(&db, Some(log)).unwrap();

        assert_eq!(live.ssh[0].status, RowStatus::Trusted);
        assert!(!live.ssh[0].status.is_blocked());
    }

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
        assert_eq!(
            rows[0].status,
            RowStatus::Blocked {
                until: None,
                by: None
            }
        );
        assert_eq!(rows[0].status.label(), "BLOCKED");
    }

    #[test]
    fn build_ssh_rows_marks_a_temporarily_blocked_address_with_its_expiry() {
        let mut blocks = HashMap::new();
        blocks.insert("198.51.100.9".to_string(), Some(999_999_999_999));
        let rows = build_ssh_rows(counts(&[("198.51.100.9", 3)]), &blocks, &[]);
        assert!(matches!(
            rows[0].status,
            RowStatus::Blocked {
                until: Some(_),
                by: None
            }
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
        assert_eq!(
            rows[0].status,
            RowStatus::Blocked {
                until: None,
                by: None
            }
        );
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
        assert_eq!(
            rows[1].status,
            RowStatus::Blocked {
                until: None,
                by: None
            }
        );
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
        assert_eq!(
            rows[0].status,
            RowStatus::Blocked {
                until: None,
                by: None
            }
        );
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
        assert_eq!(
            rows[0].status,
            RowStatus::Blocked {
                until: None,
                by: None
            }
        );
    }

    /// A flood of distinct user agents is cheap to send, and both Firewall
    /// screens used to read and classify every one. They load a page of
    /// the most-seen, whatever the table holds.
    #[test]
    fn the_firewall_screens_load_one_page_of_the_most_seen_user_agents() {
        let db = Db::open_in_memory().unwrap();
        let counts: HashMap<String, u64> = (0..(UA_PAGE_ROWS as u64 + 50))
            .map(|i| (format!("agent-{i:04}"), i + 1))
            .collect();
        db.record_user_agent_hits(&counts, 1_000).unwrap();

        let live = Live::load(&db, None).unwrap();

        assert_eq!(live.user_agents.len(), UA_PAGE_ROWS);
        assert_eq!(live.user_agents[0].user_agent, "agent-0249");
        assert_eq!(live.user_agents[0].count, 250);
    }

    /// The verdict a detail view asks for one agent is the verdict its row
    /// shows: one precedence, in one place.
    #[test]
    fn one_agent_s_status_agrees_with_its_row() {
        let db = Db::open_in_memory().unwrap();
        db.block_user_agent("curl/8.0").unwrap();
        db.trust_user_agent("UptimeRobot").unwrap();
        let agents = [
            "curl/8.0",
            "UptimeRobot/2.0",
            "SomeNewBot/1.0",
            "Mozilla/5.0",
        ];
        let counts: HashMap<String, u64> = agents.iter().map(|ua| (ua.to_string(), 1)).collect();
        db.record_user_agent_hits(&counts, 1_000).unwrap();

        let stats = db.list_user_agent_stats().unwrap();
        let inputs = LiveInputs::read(&db, stats).unwrap();
        let expected: Vec<(String, RowStatus)> = agents
            .iter()
            .map(|ua| (ua.to_string(), inputs.verdicts().status_of(ua)))
            .collect();
        let live = inputs.classify(None);

        for (ua, status) in expected {
            let row = live
                .user_agents
                .iter()
                .find(|r| r.user_agent == ua)
                .unwrap();
            assert_eq!(row.status, status, "{ua}");
        }
        let status = |ua: &str| {
            live.user_agents
                .iter()
                .find(|r| r.user_agent == ua)
                .unwrap()
                .status
        };
        assert!(status("curl/8.0").is_blocked());
        assert_eq!(status("UptimeRobot/2.0"), RowStatus::Trusted);
        assert_eq!(status("SomeNewBot/1.0"), RowStatus::Unknown);
        assert_eq!(status("Mozilla/5.0"), RowStatus::Pending);
    }

    /// The row itself says which detector blocked it; a block by hand
    /// says nothing more than BLOCKED.
    #[test]
    fn a_detector_s_block_names_the_detector_on_the_row() {
        let db = Db::open_in_memory().unwrap();
        let log = "Failed password for root from 198.51.100.9 port 4444 ssh2\n\
                   Failed password for root from 198.51.100.10 port 4444 ssh2\n";
        db.add_firewall_rule_with_ttl(
            &crate::db::NewFirewallRule {
                address: "198.51.100.9".into(),
                port: None,
                action: FirewallAction::Block,
                source: crate::db::RuleSource::Detector(crate::protection::Detector::SshScanners),
                evidence: None,
            },
            5 * 86_400,
        )
        .unwrap();
        db.block_address_permanently("198.51.100.10", crate::db::RuleSource::Tui, None)
            .unwrap();

        let live = Live::load(&db, Some(log)).unwrap();
        let label = |address: &str| {
            live.ssh
                .iter()
                .find(|row| row.address == address)
                .unwrap()
                .status
                .label()
        };

        assert!(
            label("198.51.100.9").ends_with(" by ssh-scanners"),
            "{}",
            label("198.51.100.9")
        );
        assert_eq!(label("198.51.100.10"), "BLOCKED");
    }
}
