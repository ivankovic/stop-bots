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

//! Shared "detect scanning IPs, add temporary Block rules" logic behind the
//! CLI's `block-scanners`/`block-web-scanners` subcommands and the internal
//! cron's `BlockScanners`/`BlockWebScanners` jobs (see [`crate::cron`]) —
//! pulled out so neither caller can drift from the other, and so neither
//! ever needs to `println!` from inside detection logic that the TUI (which
//! owns the whole terminal via an alternate screen) might also be driving.
//! Callers get a plain [`ScanBlockOutcome`] back and decide for themselves
//! how to present it: the CLI reconstructs its existing wording, the cron
//! job turns it into a one-line summary for the Dashboard.

use crate::db::{Db, FirewallAction, NewFirewallRule};
use crate::{accesslog, ipranges, sshlog};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Which detector produced a [`ScanBlockOutcome`]. Only affects the noun
/// in [`ScanBlockOutcome::summary`] — "no scanning IPs found" would be
/// actively misleading on the Dashboard for a pass that was looking for
/// forged crawler user agents, not scanning behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanKind {
    #[default]
    Scanning,
    SpoofedCrawler,
    ProbePath,
    Honeypot,
    /// The three behavioural detectors share a noun: each finds a client
    /// that doesn't act like a browser, by a different tell.
    NonBrowser,
    RobotsTxt,
}

impl ScanKind {
    /// The noun this detector's findings are called, singular — the CLI's
    /// `print_scan_block_outcome` needs it too, so it isn't private.
    pub fn noun(self) -> &'static str {
        match self {
            ScanKind::Scanning => "scanning IP",
            ScanKind::SpoofedCrawler => "forged crawler IP",
            ScanKind::ProbePath => "probing IP",
            ScanKind::Honeypot => "trapped IP",
            ScanKind::NonBrowser => "non-browser IP",
            ScanKind::RobotsTxt => "robots.txt fetcher",
        }
    }
}

/// What one detection-and-block pass found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBlockOutcome {
    /// What was being looked for — see [`ScanKind`].
    pub kind: ScanKind,
    /// How many IPs the raw threshold-based detector flagged, before any
    /// known-crawler exclusion.
    pub candidates: usize,
    /// Of `candidates`, how many were skipped because they matched a known
    /// crawler's published IP range. Always 0 for
    /// [`block_ssh_scanners`], which has no such exclusion.
    pub skipped_known_crawlers: usize,
    /// Whether the known-crawler exclusion had any ranges to check
    /// against — `false` means `update-ip-ranges` has never been run for
    /// any of the three crawler sources, so the exclusion is a no-op.
    /// Always `true` (meaningless) for [`block_ssh_scanners`].
    pub crawler_exclusion_active: bool,
    /// Of the candidates that survived crawler exclusion, how many were
    /// already covered by an existing firewall rule of the same exact
    /// address (any action) and so weren't re-added.
    pub already_covered: usize,
    /// Of the candidates, how many were left alone because a successful
    /// SSH login has been seen from them inside the anti-lockout window
    /// (see [`crate::db::SSH_LOGIN_WINDOW_SECONDS`]).
    ///
    /// `firewall::all_rules` would have neutralised such a rule anyway, by
    /// putting an Allow ahead of it — this is about not *writing* it.
    /// A row saying Block against the operator's own address is alarming
    /// whether or not it has any effect, and the Dynamic Protection screen
    /// reads `firewall_rules` directly, so it would show that address as
    /// blocked when it is not.
    pub skipped_ssh_logins: usize,
    /// Addresses actually newly blocked — or, if `dry_run`, that would
    /// have been.
    pub newly_blocked: Vec<String>,
    pub ttl_days: i64,
    pub dry_run: bool,
}

impl ScanBlockOutcome {
    /// A one-line summary suitable for a status display (the Dashboard's
    /// "Scheduled tasks" panel, `Db::set_cron_last_run`'s `summary`
    /// argument) — deliberately terser than the CLI's multi-line output,
    /// which reconstructs its own wording directly from this struct's
    /// fields instead of using this method.
    pub fn summary(&self) -> String {
        let noun = self.kind.noun();
        if self.candidates == 0 {
            return format!("no {noun}s found");
        }
        if self.newly_blocked.is_empty() {
            let surviving = self.candidates - self.skipped_known_crawlers;
            if self.skipped_ssh_logins > 0 && self.already_covered == 0 {
                return format!("found {surviving} {noun}(s), all recent SSH logins — left alone");
            }
            return format!("found {surviving} {noun}(s), all already covered");
        }
        let verb = if self.dry_run {
            "would block"
        } else {
            "blocked"
        };
        format!("{verb} {} IP(s)", self.newly_blocked.len())
    }
}

/// The failed-SSH-attempt count above which an address is a scanner, and
/// the distinct-404 count above which one is a web scanner. Defaults for
/// every caller that doesn't have a reason to pick its own — the CLI's
/// `--min-attempts`/`--min-paths` flags do.
pub const DEFAULT_SSH_ATTEMPTS: usize = 20;
pub const DEFAULT_WEB_PATHS: usize = 7;

/// Runs whichever detector `detector` names against `log_text`.
///
/// The one place that maps a [`Detector`](crate::protection::Detector) onto
/// the function that implements it. Both schedulers go through here — the
/// TUI's internal cron and `crate::batch` — so a detector added to
/// `Detector::ALL` and forgotten here fails to compile rather than
/// silently never running from one of them.
pub fn run_detector(
    db: &Db,
    detector: crate::protection::Detector,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    use crate::protection::Detector as D;
    match detector {
        D::SshScanners => block_ssh_scanners(db, DEFAULT_SSH_ATTEMPTS, ttl_days, log_text, dry_run),
        D::WebScanners => block_web_scanners(db, DEFAULT_WEB_PATHS, ttl_days, log_text, dry_run),
        D::SpoofedCrawlers => block_spoofed_crawlers(db, ttl_days, log_text, dry_run),
        D::ProbePaths => block_probe_paths(db, ttl_days, log_text, dry_run),
        D::Honeypot => block_honeypot(db, ttl_days, log_text, dry_run),
        D::AssetRatio => block_asset_ratio(db, ttl_days, log_text, dry_run),
        D::RotatingUserAgent => block_rotating_ua(db, ttl_days, log_text, dry_run),
        D::RefererlessCrawl => block_refererless(db, ttl_days, log_text, dry_run),
        D::RobotsTxt => block_robots_txt(db, ttl_days, log_text, dry_run),
    }
}

/// Finds scanning IPs in `log_text` (an SSH log's contents — see
/// [`crate::sshlog::scanning_ips`] for exactly what counts) and adds a
/// Block rule, expiring after `ttl_days`, for each one not already covered
/// by an existing firewall rule of the same exact address. `dry_run`
/// leaves the database untouched but still reports what would have
/// happened via the returned [`ScanBlockOutcome`].
pub fn block_ssh_scanners(
    db: &Db,
    threshold: usize,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let candidates = sshlog::scanning_ips(log_text, threshold);
    let found = candidates.len();
    add_block_rules(
        db,
        ScanKind::Scanning,
        found,
        candidates,
        0,
        true,
        ttl_days,
        dry_run,
    )
}

/// Finds scanning IPs in `log_text` (an NGINX access log's contents — see
/// [`crate::accesslog::scanning_ips`]), excludes any that fall inside a
/// known crawler's published IP ranges (see [`known_crawler_ranges`] —
/// unlike [`block_ssh_scanners`], there's no "had a success" exclusion
/// here; see `accesslog`'s module docs for why), and adds a Block rule,
/// expiring after `ttl_days`, for each IP that's left and isn't already
/// covered by an existing firewall rule of the same exact address.
pub fn block_web_scanners(
    db: &Db,
    threshold: usize,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let candidates = accesslog::scanning_ips(log_text, threshold);
    let found = candidates.len();

    let crawler_ranges = known_crawler_ranges(db)?;
    let crawler_exclusion_active = !crawler_ranges.is_empty();
    let mut kept = Vec::new();
    let mut skipped_known_crawlers = 0;
    for ip in candidates {
        if known_crawler_match(&crawler_ranges, &ip) {
            skipped_known_crawlers += 1;
        } else {
            kept.push(ip);
        }
    }

    add_block_rules(
        db,
        ScanKind::Scanning,
        found,
        kept,
        skipped_known_crawlers,
        crawler_exclusion_active,
        ttl_days,
        dry_run,
    )
}

/// Every CIDR published by a known crawler source (Googlebot, Bingbot,
/// GPTBot — the same three [`ipranges::IpRangeSourceKind::ALL`] sources
/// `update-ip-ranges` fetches), regardless of `db`'s current category
/// defaults: this exclusion is about never misidentifying a *verified*
/// crawler as a scanner via behavioral heuristics, independent of whether
/// the admin has separately chosen to block that crawler's category
/// through the normal (range-complete, not heuristic) derived-firewall-rule
/// path. Empty if none of the three sources has ever been fetched.
pub fn known_crawler_ranges(db: &Db) -> Result<Vec<String>> {
    let mut ranges = Vec::new();
    for kind in ipranges::IpRangeSourceKind::ALL {
        ranges.extend(db.ip_ranges_for_source(kind.id())?);
    }
    Ok(ranges)
}

/// Builds the [`accesslog::CrawlerClaim`] list for
/// [`block_spoofed_crawlers`] from whatever crawler ranges `db` currently
/// holds. **Sources with no stored ranges are dropped**, not included
/// empty: an empty range list would make every real request from that
/// crawler look like an impersonation, so a fresh install (or one whose
/// `update-ip-ranges` has never succeeded) would block the actual
/// Googlebot. Dropping them makes the detector inert instead, which is the
/// only safe failure mode here.
///
/// The markers are the tokens an impersonator actually copies. They're
/// matched as lowercase substrings of the user agent, so `Googlebot/2.1`,
/// `compatible; Googlebot/2.1; +http://...` and a bare `googlebot` all
/// count — which is the point, since the whole population being detected
/// is "things that put this word in their UA".
pub fn crawler_claims(db: &Db) -> Result<Vec<accesslog::CrawlerClaim>> {
    let mut claims = Vec::new();
    for kind in ipranges::IpRangeSourceKind::ALL {
        let ranges = db.ip_ranges_for_source(kind.id())?;
        if ranges.is_empty() {
            continue;
        }
        let marker = match kind {
            ipranges::IpRangeSourceKind::GoogleBot => "googlebot",
            ipranges::IpRangeSourceKind::BingBot => "bingbot",
            ipranges::IpRangeSourceKind::GptBot => "gptbot",
        };
        claims.push(accesslog::CrawlerClaim {
            marker,
            name: kind.name(),
            ranges,
        });
    }
    Ok(claims)
}

/// Finds IPs in `log_text` (an NGINX access log) claiming to be a crawler
/// whose operator doesn't publish their address (see
/// [`accesslog::spoofed_crawler_ips`]) and adds a Block rule, expiring
/// after `ttl_days`, for each one not already covered by an existing rule
/// of the same exact address.
///
/// No threshold argument, unlike [`block_ssh_scanners`]/
/// [`block_web_scanners`]: one forged request is already conclusive, so
/// there's no count to tune. No known-crawler exclusion either — verifying
/// against exactly those ranges *is* the detection, so an IP that survives
/// it has already been checked against every range this project knows.
pub fn block_spoofed_crawlers(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let claims = crawler_claims(db)?;
    let spoofed = accesslog::spoofed_crawler_ips(log_text, &claims);
    let found = spoofed.len();
    let candidates: Vec<String> = spoofed.into_iter().map(|(ip, _name)| ip).collect();
    add_block_rules(
        db,
        ScanKind::SpoofedCrawler,
        found,
        candidates,
        0,
        !claims.is_empty(),
        ttl_days,
        dry_run,
    )
}

/// Finds IPs in `log_text` (an NGINX access log) that requested one of the
/// configured probe paths (see [`crate::protection::probe_paths`] and
/// [`accesslog::probe_path_ips`]) and adds a Block rule, expiring after
/// `ttl_days`, for each one not already covered.
///
/// Like [`block_spoofed_crawlers`] and unlike the two behavioural
/// detectors, there's no threshold: the path list is chosen so that a
/// single request to any entry is conclusive on its own.
///
/// No known-crawler exclusion, deliberately. A search crawler has no
/// business requesting `/.env` either — if one ever did, that request is
/// exactly as unwelcome as anyone else's, and unlike the 404-counting
/// detector there's no risk of mistaking ordinary link-chasing for it.
/// Blocks every public address that fetched `/robots.txt`.
///
/// Reached only under "humans only" — `Detector::is_enabled` answers for
/// this one from that switch — because outside it this rule blocks the
/// crawlers that were trying to find out what they were allowed to do.
/// See [`crate::accesslog::robots_txt_ips`].
pub fn block_robots_txt(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let candidates = accesslog::robots_txt_ips(log_text);
    let found = candidates.len();
    add_block_rules(
        db,
        ScanKind::RobotsTxt,
        found,
        candidates,
        0,
        true,
        ttl_days,
        dry_run,
    )
}

pub fn block_probe_paths(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let paths = crate::protection::probe_paths(db)?;
    let hits = accesslog::probe_path_ips(log_text, &paths);
    let found = hits.len();
    let candidates: Vec<String> = hits.into_iter().map(|(ip, _path)| ip).collect();
    add_block_rules(
        db,
        ScanKind::ProbePath,
        found,
        candidates,
        0,
        true,
        ttl_days,
        dry_run,
    )
}

/// Finds IPs in `log_text` that fetched the configured honeypot path (see
/// [`crate::protection::honeypot_path`]) and adds a Block rule expiring
/// after `ttl_days`.
///
/// Mechanically the same single-request match as [`block_probe_paths`],
/// and deliberately reusing [`accesslog::probe_path_ips`] rather than
/// growing a second matcher. What makes it a *honeypot* rather than one
/// more probe path is external to the matching: the path is published as
/// `Disallow:` in the robots.txt this project generates, so fetching it
/// proves the client read robots.txt and ignored it — or guessed a path
/// that exists for no other purpose. Kept as its own detector, with its
/// own toggle and cron job, because that signal is much stronger than a
/// generic probe and earns a much longer TTL.
pub fn block_honeypot(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let path = crate::protection::honeypot_path(db)?;
    let hits = accesslog::probe_path_ips(log_text, &[path]);
    let found = hits.len();
    let candidates: Vec<String> = hits.into_iter().map(|(ip, _path)| ip).collect();
    add_block_rules(
        db,
        ScanKind::Honeypot,
        found,
        candidates,
        0,
        true,
        ttl_days,
        dry_run,
    )
}

/// Blocks clients that fetched pages but never an asset — see
/// [`accesslog::asset_less_ips`] for the three guards that make this
/// usable and the one false positive it can't rule out.
pub fn block_asset_ratio(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_pages = crate::protection::threshold(
        db,
        crate::protection::ASSET_RATIO_MIN_PAGES,
        crate::protection::ASSET_RATIO_MIN_PAGES_DEFAULT,
    )?;
    let candidates = accesslog::asset_less_ips(log_text, min_pages);
    behavioural(db, candidates, ttl_days, dry_run)
}

/// Blocks clients presenting many distinct user agents — see
/// [`accesslog::rotating_user_agent_ips`], and note the NAT caveat there.
pub fn block_rotating_ua(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_agents = crate::protection::threshold(
        db,
        crate::protection::ROTATING_UA_MIN,
        crate::protection::ROTATING_UA_MIN_DEFAULT,
    )?;
    let candidates = accesslog::rotating_user_agent_ips(log_text, min_agents);
    behavioural(db, candidates, ttl_days, dry_run)
}

/// Blocks clients that walked many deep pages without ever sending a
/// `Referer` — see [`accesslog::refererless_crawl_ips`].
pub fn block_refererless(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_paths = crate::protection::threshold(
        db,
        crate::protection::REFERERLESS_MIN_PATHS,
        crate::protection::REFERERLESS_MIN_PATHS_DEFAULT,
    )?;
    let candidates = accesslog::refererless_crawl_ips(log_text, min_paths);
    behavioural(db, candidates, ttl_days, dry_run)
}

/// Shared tail for the three behavioural detectors.
///
/// Unlike the other access-log detectors these *do* apply the known-crawler
/// exclusion, and that is the whole reason this helper exists rather than
/// three copies. All three describe "doesn't behave like a browser", which
/// is exactly true of Googlebot: it fetches no CSS, it uses more than one
/// user agent, and it never sends a referer. Without the exclusion these
/// three detectors would block search engines by design.
fn behavioural(
    db: &Db,
    candidates: Vec<String>,
    ttl_days: i64,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let found = candidates.len();
    let crawler_ranges = known_crawler_ranges(db)?;
    let crawler_exclusion_active = !crawler_ranges.is_empty();
    let mut kept = Vec::new();
    let mut skipped_known_crawlers = 0;
    for ip in candidates {
        if known_crawler_match(&crawler_ranges, &ip) {
            skipped_known_crawlers += 1;
        } else {
            kept.push(ip);
        }
    }
    add_block_rules(
        db,
        ScanKind::NonBrowser,
        found,
        kept,
        skipped_known_crawlers,
        crawler_exclusion_active,
        ttl_days,
        dry_run,
    )
}

/// Whether `ip` falls inside any of `ranges`.
pub fn known_crawler_match(ranges: &[String], ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    ranges
        .iter()
        .any(|cidr| ipranges::cidr_contains(cidr, addr))
}

/// The address a detector should actually block, given the address it
/// observed.
///
/// **IPv4 is returned unchanged. IPv6 is widened to its `/64`.**
///
/// This is a correctness fix rather than a policy choice. The smallest
/// IPv6 allocation anyone receives is a `/64` — that is the standard
/// subnet for one LAN, one household, one mobile subscriber — so blocking
/// the single `/128` we happened to see is the equivalent of blocking one
/// TCP source port. An attacker holding a `/64` has 2^64 addresses to
/// rotate through and would cost one firewall rule per request while never
/// actually being blocked.
///
/// A `/64` is therefore the IPv6 counterpart of a single IPv4 address, not
/// an escalation: both block roughly "one customer". Widening further (to
/// the `/56` or `/48` a site may hold) *would* be an escalation, and is
/// deliberately not done here.
///
/// An unparseable address is passed through untouched — this runs on
/// strings that already came from a parsed log, and a detector should not
/// silently drop a candidate because this helper didn't recognise it.
pub fn blockable_address(observed: &str) -> String {
    let Ok(std::net::IpAddr::V6(v6)) = observed.parse::<std::net::IpAddr>() else {
        return observed.to_string();
    };
    let mut octets = v6.octets();
    // Zero the host half (the low 64 bits); the network half is the /64.
    octets[8..].fill(0);
    format!("{}/64", std::net::Ipv6Addr::from(octets))
}

/// Collapses IPv4 addresses into their `/24` where at least `min` of them
/// were flagged in the same pass, leaving everything else untouched.
///
/// Only ever called when the admin switched escalation on — see
/// [`crate::protection::subnet_escalation`] for why this is a policy knob
/// and IPv6 `/64` widening isn't. Scoped to one pass on purpose: "three
/// neighbours misbehaving right now" is evidence about the subnet,
/// whereas three over six months is just a busy ISP.
fn escalate_subnets(addresses: Vec<String>, min: usize) -> Vec<String> {
    use std::net::{IpAddr, Ipv4Addr};

    let mut by_subnet: HashMap<[u8; 3], Vec<String>> = HashMap::new();
    let mut untouched = Vec::new();
    for address in addresses {
        match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                let o = v4.octets();
                by_subnet
                    .entry([o[0], o[1], o[2]])
                    .or_default()
                    .push(address);
            }
            // IPv6 is already widened to its /64, and a bare CIDR or an
            // unparseable string has nothing to escalate.
            _ => untouched.push(address),
        }
    }

    let mut out = untouched;
    for (prefix, members) in by_subnet {
        if members.len() >= min {
            out.push(format!(
                "{}/24",
                Ipv4Addr::new(prefix[0], prefix[1], prefix[2], 0)
            ));
        } else {
            out.extend(members);
        }
    }
    out.sort();
    out
}

/// Adds a Block rule, expiring after `ttl_days`, for each of `kept` not
/// already covered by an existing firewall rule of the same exact address.
/// The existence check reads through [`Db::list_firewall_rules`], which
/// prunes expired rows before returning them — load-bearing here, not just
/// tidiness: without it, a scanner whose earlier block already lapsed
/// would still show up as "already covered" by the stale row and never get
/// re-flagged, and re-running this after a rule expires would otherwise
/// leave the address referenced by two rows (one dead, one freshly
/// inserted) instead of cleanly replacing it.
#[allow(clippy::too_many_arguments)]
fn add_block_rules(
    db: &Db,
    kind: ScanKind,
    found: usize,
    kept: Vec<String>,
    skipped_known_crawlers: usize,
    crawler_exclusion_active: bool,
    ttl_days: i64,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    // Seeded from what's already stored, then *added to as we go*. The
    // second part matters more than it used to: before IPv6 widening, two
    // candidates were only ever equal if the same address appeared twice
    // in the input (already deduped upstream). Now two different addresses
    // can collapse onto one /64, so a pass can produce a duplicate of its
    // own making unless it remembers what it just added.
    let mut existing: HashSet<String> = db
        .list_firewall_rules()?
        .into_iter()
        .map(|rule| rule.address)
        .collect();

    // Addresses the operator has actually logged in from recently. Parsed
    // once, and kept as `IpAddr` rather than strings because the comparison
    // below is containment, not equality.
    let ssh_logins: Vec<std::net::IpAddr> = db
        .recent_ssh_login_ips()?
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .collect();

    let kept = match crate::protection::subnet_escalation(db)? {
        Some(min) => escalate_subnets(kept, min),
        None => kept,
    };

    let ttl_seconds = ttl_days * 24 * 60 * 60;
    let mut newly_blocked = Vec::new();
    let mut already_covered = 0;
    let mut skipped_ssh_logins = 0;
    for observed in kept {
        // What gets stored is not always what was seen: an IPv6 address is
        // widened to its /64 (see `blockable_address`). Dedup happens on
        // the stored form, so a second address in the same /64 correctly
        // counts as already covered rather than adding a duplicate rule.
        //
        // One wrinkle on upgrade: a /128 row written before this change
        // won't match the /64 now computed for the same address, so both
        // can briefly exist. Harmless — the /128 is inside the /64, and it
        // expires on its own TTL.
        let ip = blockable_address(&observed);
        // Containment rather than string equality, and checked against the
        // *widened* address: an IPv6 candidate is stored as its /64, so an
        // exact-match test would happily write a /64 Block covering the
        // address the operator logs in from.
        if ssh_logins
            .iter()
            .any(|login| crate::ipranges::cidr_contains(&ip, *login))
        {
            skipped_ssh_logins += 1;
            continue;
        }
        if existing.contains(&ip) {
            already_covered += 1;
            continue;
        }
        if !dry_run {
            db.add_firewall_rule_with_ttl(
                &NewFirewallRule {
                    address: ip.clone(),
                    port: None,
                    action: FirewallAction::Block,
                },
                ttl_seconds,
            )?;
        }
        existing.insert(ip.clone());
        newly_blocked.push(ip);
    }

    Ok(ScanBlockOutcome {
        kind,
        candidates: found,
        skipped_known_crawlers,
        crawler_exclusion_active,
        already_covered,
        skipped_ssh_logins,
        newly_blocked,
        ttl_days,
        dry_run,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_failed_attempt(ip: &str, times: usize) -> String {
        format!("Failed password for root from {ip} port 4444 ssh2\n").repeat(times)
    }

    fn not_found_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 1 \"-\" \"UA\"\n"
        )
    }

    #[test]
    fn block_ssh_scanners_adds_a_new_rule() {
        let db = Db::open_in_memory().unwrap();
        let log = ssh_failed_attempt("198.51.100.9", 25);
        let outcome = block_ssh_scanners(&db, 20, 5, &log, false).unwrap();

        assert_eq!(outcome.candidates, 1);
        assert_eq!(outcome.newly_blocked, vec!["198.51.100.9".to_string()]);
        assert_eq!(outcome.already_covered, 0);
        assert_eq!(db.list_firewall_rules().unwrap().len(), 1);
    }

    #[test]
    fn block_ssh_scanners_dry_run_reports_without_writing() {
        let db = Db::open_in_memory().unwrap();
        let log = ssh_failed_attempt("198.51.100.9", 25);
        let outcome = block_ssh_scanners(&db, 20, 5, &log, true).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["198.51.100.9".to_string()]);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn block_ssh_scanners_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let log = ssh_failed_attempt("198.51.100.9", 25);
        block_ssh_scanners(&db, 20, 5, &log, false).unwrap();
        let second = block_ssh_scanners(&db, 20, 5, &log, false).unwrap();

        assert!(second.newly_blocked.is_empty());
        assert_eq!(second.already_covered, 1);
        assert_eq!(db.list_firewall_rules().unwrap().len(), 1);
    }

    #[test]
    fn block_web_scanners_excludes_known_crawler_ranges() {
        let db = Db::open_in_memory().unwrap();
        ipranges::store(
            &db,
            ipranges::IpRangeSourceKind::GoogleBot,
            &["198.51.100.0/24".to_string()],
        )
        .unwrap();

        let log: String = (0..20)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        let outcome = block_web_scanners(&db, 15, 1, &log, false).unwrap();

        assert_eq!(outcome.candidates, 1);
        assert_eq!(outcome.skipped_known_crawlers, 1);
        assert!(outcome.crawler_exclusion_active);
        assert!(outcome.newly_blocked.is_empty());
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn block_web_scanners_still_blocks_outside_known_crawler_ranges() {
        let db = Db::open_in_memory().unwrap();
        ipranges::store(
            &db,
            ipranges::IpRangeSourceKind::GoogleBot,
            &["198.51.100.0/24".to_string()],
        )
        .unwrap();

        let log: String = (0..20)
            .map(|i| not_found_line("203.0.113.9", &format!("/missing-{i}")))
            .collect();
        let outcome = block_web_scanners(&db, 15, 1, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
    }

    #[test]
    fn block_web_scanners_reports_inactive_exclusion_when_never_fetched() {
        let db = Db::open_in_memory().unwrap();
        let log: String = (0..20)
            .map(|i| not_found_line("203.0.113.9", &format!("/missing-{i}")))
            .collect();
        let outcome = block_web_scanners(&db, 15, 1, &log, false).unwrap();

        assert!(!outcome.crawler_exclusion_active);
        assert_eq!(outcome.skipped_known_crawlers, 0);
    }

    #[test]
    fn summary_describes_each_outcome_shape() {
        let none = ScanBlockOutcome {
            kind: ScanKind::Scanning,
            candidates: 0,
            skipped_known_crawlers: 0,
            crawler_exclusion_active: true,
            already_covered: 0,
            skipped_ssh_logins: 0,
            newly_blocked: vec![],
            ttl_days: 5,
            dry_run: false,
        };
        assert_eq!(none.summary(), "no scanning IPs found");

        let all_covered = ScanBlockOutcome {
            candidates: 2,
            already_covered: 2,
            ..none.clone()
        };
        assert!(all_covered.summary().contains("already covered"));

        let blocked = ScanBlockOutcome {
            candidates: 1,
            newly_blocked: vec!["1.2.3.4".to_string()],
            ..none
        };
        assert_eq!(blocked.summary(), "blocked 1 IP(s)");
    }

    // ---- spoofed crawler blocking ----

    fn seed_googlebot_ranges(db: &Db) {
        db.register_ip_range_source(&crate::db::IpRangeSource {
            id: "googlebot".to_string(),
            name: "Googlebot IP ranges".to_string(),
            url: "https://example.invalid/googlebot.json".to_string(),
            category: crate::db::Category::Search,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.replace_ip_ranges("googlebot", &["66.249.64.0/19".to_string()])
            .unwrap();
    }

    fn ua_line(ip: &str, ua: &str) -> String {
        format!("{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{ua}\"\n")
    }

    #[test]
    fn crawler_claims_drops_sources_with_no_fetched_ranges() {
        let db = Db::open_in_memory().unwrap();
        assert!(crawler_claims(&db).unwrap().is_empty());

        seed_googlebot_ranges(&db);
        let claims = crawler_claims(&db).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].marker, "googlebot");
        assert!(!claims[0].ranges.is_empty());
    }

    #[test]
    fn block_spoofed_crawlers_blocks_a_forged_googlebot() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        let log = ua_line("203.0.113.9", "Googlebot/2.1");

        let outcome = block_spoofed_crawlers(&db, 1, &log, false).unwrap();

        assert_eq!(outcome.kind, ScanKind::SpoofedCrawler);
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert!(outcome.crawler_exclusion_active);
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "203.0.113.9");
        assert_eq!(rules[0].action, FirewallAction::Block);
        assert!(rules[0].expires_at.is_some());
    }

    #[test]
    fn block_spoofed_crawlers_leaves_the_real_googlebot_alone() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        let log = ua_line("66.249.66.1", "Googlebot/2.1");

        let outcome = block_spoofed_crawlers(&db, 1, &log, false).unwrap();

        assert_eq!(outcome.candidates, 0);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// With nothing fetched the detector must do nothing at all — not
    /// treat every crawler request as forged. `crawler_exclusion_active`
    /// being false is what lets the CLI say "nothing was checked" rather
    /// than "nothing was found".
    #[test]
    fn block_spoofed_crawlers_is_inert_before_any_ranges_are_fetched() {
        let db = Db::open_in_memory().unwrap();
        let log = ua_line("203.0.113.9", "Googlebot/2.1");

        let outcome = block_spoofed_crawlers(&db, 1, &log, false).unwrap();

        assert_eq!(outcome.candidates, 0);
        assert!(!outcome.crawler_exclusion_active);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn block_spoofed_crawlers_dry_run_reports_without_writing() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        let log = ua_line("203.0.113.9", "Googlebot/2.1");

        let outcome = block_spoofed_crawlers(&db, 1, &log, true).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert!(outcome.dry_run);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// A detector must not even *write* a Block for an address the
    /// operator logs in from. `firewall::all_rules` would neutralise it,
    /// but the Dynamic Protection screen reads `firewall_rules` directly
    /// and would show the operator's own address as blocked.
    #[test]
    fn block_ssh_scanners_leaves_an_address_with_a_recent_ssh_login_alone() {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&["198.51.100.9".to_string()])
            .unwrap();
        let log = ssh_failed_attempt("198.51.100.9", 25);

        let outcome = block_ssh_scanners(&db, 20, 1, &log, false).unwrap();

        assert!(outcome.newly_blocked.is_empty());
        assert_eq!(outcome.skipped_ssh_logins, 1);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// IPv6 candidates are widened to their /64 before being stored, so an
    /// exact-string check would have written a /64 Block that contains the
    /// very address the operator logs in from.
    #[test]
    fn block_ssh_scanners_leaves_the_whole_64_alone_when_a_login_sits_inside_it() {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&["2001:db8::5".to_string()])
            .unwrap();
        let log = ssh_failed_attempt("2001:db8::99", 25);

        let outcome = block_ssh_scanners(&db, 20, 1, &log, false).unwrap();

        assert!(outcome.newly_blocked.is_empty());
        assert_eq!(outcome.skipped_ssh_logins, 1);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn block_spoofed_crawlers_skips_an_address_already_covered() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        db.add_firewall_rule(&NewFirewallRule {
            address: "203.0.113.9".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();
        let log = ua_line("203.0.113.9", "Googlebot/2.1");

        let outcome = block_spoofed_crawlers(&db, 1, &log, false).unwrap();

        assert!(outcome.newly_blocked.is_empty());
        assert_eq!(outcome.already_covered, 1);
        assert_eq!(db.list_firewall_rules().unwrap().len(), 1);
    }

    #[test]
    fn summary_uses_the_right_noun_for_each_kind() {
        let base = ScanBlockOutcome {
            kind: ScanKind::Scanning,
            candidates: 0,
            skipped_known_crawlers: 0,
            crawler_exclusion_active: true,
            already_covered: 0,
            skipped_ssh_logins: 0,
            newly_blocked: vec![],
            ttl_days: 1,
            dry_run: false,
        };
        assert_eq!(base.summary(), "no scanning IPs found");
        let spoofed = ScanBlockOutcome {
            kind: ScanKind::SpoofedCrawler,
            ..base
        };
        assert_eq!(spoofed.summary(), "no forged crawler IPs found");
    }

    // ---- probe-path blocking ----

    fn probe_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n"
        )
    }

    #[test]
    fn block_probe_paths_blocks_a_single_dotenv_request() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/.env");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.kind, ScanKind::ProbePath);
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules[0].address, "203.0.113.9");
        assert!(rules[0].expires_at.is_some());
    }

    #[test]
    fn block_probe_paths_ignores_ordinary_traffic() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/about");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.candidates, 0);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// Unlike spoofed-crawler detection this needs no fetched data, so it
    /// works on a completely fresh database.
    #[test]
    fn block_probe_paths_works_without_any_fetched_ranges() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/.git/config");
        assert_eq!(
            block_probe_paths(&db, 5, &log, false)
                .unwrap()
                .newly_blocked,
            vec!["203.0.113.9".to_string()]
        );
    }

    #[test]
    fn block_probe_paths_picks_up_extra_configured_paths() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/internal-only/dump");
        assert_eq!(block_probe_paths(&db, 5, &log, true).unwrap().candidates, 0);

        db.set_text_setting(crate::protection::PROBE_PATHS_EXTRA, "/internal-only")
            .unwrap();
        assert_eq!(block_probe_paths(&db, 5, &log, true).unwrap().candidates, 1);
    }

    #[test]
    fn block_probe_paths_dry_run_writes_nothing() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/.env");

        let outcome = block_probe_paths(&db, 5, &log, true).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    // ---- honeypot ----

    #[test]
    fn block_honeypot_blocks_a_fetch_of_the_default_trap_path() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", crate::protection::HONEYPOT_PATH_DEFAULT);

        let outcome = block_honeypot(&db, 30, &log, false).unwrap();

        assert_eq!(outcome.kind, ScanKind::Honeypot);
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert_eq!(outcome.summary(), "blocked 1 IP(s)");
    }

    #[test]
    fn block_honeypot_uses_a_configured_path() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(crate::protection::HONEYPOT_PATH, "/my-trap/")
            .unwrap();

        let default_hit = probe_line("203.0.113.9", crate::protection::HONEYPOT_PATH_DEFAULT);
        assert_eq!(
            block_honeypot(&db, 30, &default_hit, true)
                .unwrap()
                .candidates,
            0
        );

        let configured_hit = probe_line("203.0.113.9", "/my-trap/anything");
        assert_eq!(
            block_honeypot(&db, 30, &configured_hit, true)
                .unwrap()
                .candidates,
            1
        );
    }

    #[test]
    fn block_honeypot_ignores_ordinary_traffic() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/");
        assert_eq!(block_honeypot(&db, 30, &log, false).unwrap().candidates, 0);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// The honeypot and probe-path detectors share one matcher, so this
    /// guards against the trap path accidentally being folded into the
    /// probe list (which would give it the wrong TTL and the wrong label).
    #[test]
    fn the_probe_path_detector_does_not_also_catch_the_honeypot() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", crate::protection::HONEYPOT_PATH_DEFAULT);
        assert_eq!(block_probe_paths(&db, 5, &log, true).unwrap().candidates, 0);
    }

    // ---- IPv6 /64 aggregation ----

    #[test]
    fn ipv4_addresses_are_blocked_exactly_as_observed() {
        assert_eq!(blockable_address("203.0.113.9"), "203.0.113.9");
    }

    #[test]
    fn ipv6_addresses_are_widened_to_their_64() {
        assert_eq!(
            blockable_address("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            "2001:db8:1:2::/64"
        );
        assert_eq!(blockable_address("::1"), "::/64");
    }

    #[test]
    fn an_unparseable_address_passes_through_untouched() {
        // A detector must not silently lose a candidate because this
        // helper didn't recognise the string.
        assert_eq!(blockable_address("not-an-address"), "not-an-address");
        assert_eq!(blockable_address("1.2.3.0/24"), "1.2.3.0/24");
    }

    /// The point of the whole change: two different addresses in one /64
    /// are one block, not two — otherwise an attacker holding a /64 costs
    /// a firewall rule per request and is never actually stopped.
    #[test]
    fn two_addresses_in_one_ipv6_subnet_produce_a_single_block() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("2001:db8:1:2::1", "/.env") + &probe_line("2001:db8:1:2::2", "/.env");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["2001:db8:1:2::/64".to_string()]);
        assert_eq!(outcome.already_covered, 1);
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1, "rules were: {rules:?}");
        assert_eq!(rules[0].address, "2001:db8:1:2::/64");
    }

    #[test]
    fn addresses_in_different_ipv6_subnets_are_blocked_separately() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("2001:db8:1:2::1", "/.env") + &probe_line("2001:db8:1:3::1", "/.env");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(
            outcome.newly_blocked.len(),
            2,
            "{:?}",
            outcome.newly_blocked
        );
    }

    /// A /64 block covers far more than the address that was seen, so the
    /// lockout guard has to notice when the admin's own IPv6 session is
    /// inside it. This is the case where the widening could plausibly lock
    /// someone out, and the existing guard is what prevents it.
    #[test]
    fn the_lockout_check_sees_an_admin_inside_a_blocked_ipv6_64() {
        let rules = vec![crate::db::FirewallRule {
            id: 0,
            address: blockable_address("2001:db8:1:2::99"),
            port: None,
            action: FirewallAction::Block,
            enabled: true,
            expires_at: None,
        }];
        let connected = vec!["2001:db8:1:2::5".to_string()];

        let risks = crate::firewall::lockout_risks(&rules, &connected);

        assert_eq!(
            risks,
            vec![(
                "2001:db8:1:2::5".to_string(),
                "2001:db8:1:2::/64".to_string()
            )],
            "an admin connected from inside the blocked /64 must be flagged"
        );
    }

    // ---- behavioural detectors: the crawler exclusion ----

    fn page_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 200 9 \"-\" \"UA\"\n"
        )
    }

    fn asset_less_log(ip: &str) -> String {
        (0..20).map(|i| page_line(ip, &format!("/p{i}"))).collect()
    }

    #[test]
    fn block_asset_ratio_blocks_a_client_that_never_fetches_assets() {
        let db = Db::open_in_memory().unwrap();
        let outcome = block_asset_ratio(&db, 5, &asset_less_log("203.0.113.9"), false).unwrap();

        assert_eq!(outcome.kind, ScanKind::NonBrowser);
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
    }

    /// The reason these three share `behavioural()`. Googlebot fetches no
    /// CSS, uses several user agents and sends no referer — it matches all
    /// three by design. Without the known-crawler exclusion these
    /// detectors would block search engines, which is the opposite of what
    /// this project is for.
    #[test]
    fn the_behavioural_detectors_never_block_a_verified_crawler() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        // An address inside Google's published range.
        let log = asset_less_log("66.249.66.1");

        let outcome = block_asset_ratio(&db, 5, &log, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped_known_crawlers, 1);
        assert!(outcome.crawler_exclusion_active);
    }

    #[test]
    fn block_rotating_ua_respects_its_configured_threshold() {
        let db = Db::open_in_memory().unwrap();
        let log: String = (0..4)
            .map(|i| {
                format!(
                    "203.0.113.9 - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 9 \"-\" \"A{i}\"\n"
                )
            })
            .collect();

        // Four agents, default threshold is higher.
        assert_eq!(block_rotating_ua(&db, 5, &log, true).unwrap().candidates, 0);

        db.set_int_setting(crate::protection::ROTATING_UA_MIN, 3)
            .unwrap();
        assert_eq!(block_rotating_ua(&db, 5, &log, true).unwrap().candidates, 1);
    }

    #[test]
    fn block_refererless_blocks_a_deep_crawl_with_no_referer() {
        let db = Db::open_in_memory().unwrap();
        let log: String = (0..30)
            .map(|i| page_line("203.0.113.9", &format!("/p{i}")))
            .collect();

        let outcome = block_refererless(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
    }

    // ---- IPv4 /24 escalation ----

    fn probe_ip(ip: &str) -> String {
        probe_line(ip, "/.env")
    }

    #[test]
    fn escalation_is_off_unless_switched_on() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_ip("203.0.113.1") + &probe_ip("203.0.113.2") + &probe_ip("203.0.113.3");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(
            outcome.newly_blocked.len(),
            3,
            "{:?}",
            outcome.newly_blocked
        );
    }

    #[test]
    fn enough_neighbours_in_one_24_escalate_to_the_subnet() {
        let db = Db::open_in_memory().unwrap();
        db.set_bool_setting(crate::protection::SUBNET_ESCALATION, true)
            .unwrap();
        let log = probe_ip("203.0.113.1") + &probe_ip("203.0.113.2") + &probe_ip("203.0.113.3");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.0/24".to_string()]);
    }

    #[test]
    fn too_few_neighbours_are_left_as_individual_addresses() {
        let db = Db::open_in_memory().unwrap();
        db.set_bool_setting(crate::protection::SUBNET_ESCALATION, true)
            .unwrap();
        let log = probe_ip("203.0.113.1") + &probe_ip("203.0.113.2");

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(
            outcome.newly_blocked,
            vec!["203.0.113.1".to_string(), "203.0.113.2".to_string()]
        );
    }

    /// Escalation is IPv4-only: IPv6 is already widened to its /64, and
    /// widening further would be a second, unasked-for escalation.
    #[test]
    fn escalation_leaves_ipv6_alone() {
        let escalated = escalate_subnets(
            vec![
                "2001:db8:1:2::/64".to_string(),
                "2001:db8:1:3::/64".to_string(),
                "2001:db8:1:4::/64".to_string(),
            ],
            3,
        );
        assert_eq!(escalated.len(), 3, "{escalated:?}");
    }

    #[test]
    fn escalation_only_groups_addresses_actually_in_the_same_24() {
        let escalated = escalate_subnets(
            vec![
                "203.0.113.1".to_string(),
                "203.0.113.2".to_string(),
                "203.0.113.3".to_string(),
                "198.51.100.7".to_string(),
            ],
            3,
        );
        assert_eq!(
            escalated,
            vec!["198.51.100.7".to_string(), "203.0.113.0/24".to_string()]
        );
    }
}
