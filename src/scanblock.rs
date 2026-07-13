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
use std::collections::HashSet;

/// What one detection-and-block pass found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBlockOutcome {
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
        if self.candidates == 0 {
            return "no scanning IPs found".to_string();
        }
        if self.newly_blocked.is_empty() {
            return format!(
                "found {} scanning IP(s), all already covered",
                self.candidates - self.skipped_known_crawlers
            );
        }
        let verb = if self.dry_run {
            "would block"
        } else {
            "blocked"
        };
        format!("{verb} {} IP(s)", self.newly_blocked.len())
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
    add_block_rules(db, found, candidates, 0, true, ttl_days, dry_run)
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

/// Whether `ip` falls inside any of `ranges`.
pub fn known_crawler_match(ranges: &[String], ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    ranges
        .iter()
        .any(|cidr| ipranges::cidr_contains(cidr, addr))
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
fn add_block_rules(
    db: &Db,
    found: usize,
    kept: Vec<String>,
    skipped_known_crawlers: usize,
    crawler_exclusion_active: bool,
    ttl_days: i64,
    dry_run: bool,
) -> Result<ScanBlockOutcome> {
    let existing: HashSet<String> = db
        .list_firewall_rules()?
        .into_iter()
        .map(|rule| rule.address)
        .collect();

    let ttl_seconds = ttl_days * 24 * 60 * 60;
    let mut newly_blocked = Vec::new();
    let mut already_covered = 0;
    for ip in kept {
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
        newly_blocked.push(ip);
    }

    Ok(ScanBlockOutcome {
        candidates: found,
        skipped_known_crawlers,
        crawler_exclusion_active,
        already_covered,
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
            candidates: 0,
            skipped_known_crawlers: 0,
            crawler_exclusion_active: true,
            already_covered: 0,
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
}
