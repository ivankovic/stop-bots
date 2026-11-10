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

//! What `status --json` and every `list-* --json` print.
//!
//! **The field names here are part of the command-line contract** (see
//! `RELEASING.md`, "Versioning"): a field may be added in a minor release,
//! never renamed or removed. That is why these are their own structs
//! rather than `#[derive(Serialize)]` on the database's types: renaming a
//! field of [`crate::db::FirewallRule`] must never be able to break a
//! script by accident.
//!
//! The conventions, the same for every command:
//!
//! - One JSON object per run, never a bare array, so that a field can be
//!   added next to the list later.
//! - Field names are `snake_case`.
//! - A time is Unix seconds, an integer. An address is a string.
//! - An enum is a lowercase string, spelled the way the command line
//!   spells it where it takes one (`set-bot --policy default`).
//! - Something absent is `null`, never a missing field.

use crate::db::{FirewallAction, FirewallRule, GeoMode, Policy};
use crate::health::{Level, Report};
use serde::Serialize;

/// Prints `value` as one JSON document on stdout.
///
/// Through [`json_terminal_safe`] first, so a value that carries a control
/// character reaches a terminal as a JSON escape, which every parser reads
/// back as the character it was. `say!`'s own rewriting would turn it into
/// U+FFFD or a `\u{...}` that is not valid JSON.
pub fn print<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    crate::say!("{}", json_terminal_safe(&text));
    Ok(())
}

/// `json` with every character a terminal would act on, or that would
/// reorder or hide text, written as a `\uXXXX` escape.
///
/// serde_json escapes the C0 controls itself, but not DEL, the C1
/// controls (U+009B is a CSI to some terminals) or the bidirectional and
/// zero-width characters. Those can only appear inside a string, where
/// an escape means the same character, so this changes no value. The
/// newlines are the pretty-printer's own: a newline inside a string is
/// already `\n`.
pub fn json_terminal_safe(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        let unsafe_char = (c.is_control() && c != '\n') || crate::present::is_invisible_format(c);
        if unsafe_char {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A health level as JSON spells it.
pub fn level_name(level: Level) -> &'static str {
    match level {
        Level::Ok => "ok",
        Level::Unknown => "unknown",
        Level::Warn => "warn",
        Level::Critical => "critical",
    }
}

/// `status --json`.
#[derive(Debug, Serialize)]
pub struct Status {
    /// When the checks were assessed.
    pub checked_at: i64,
    /// When the host was looked at: `checked_at` for a live run, the
    /// stored probe's time with `--cached`.
    pub probed_at: i64,
    /// Whether this came from the last stored probe (`--cached`).
    pub cached: bool,
    pub summary: StatusSummary,
    pub checks: Vec<StatusCheck>,
    /// Every access log the detectors read, the stored or default one
    /// first. Empty in a probe taken before 0.5.0.
    pub access_logs: Vec<StatusAccessLog>,
}

/// One access log, in `status --json`.
#[derive(Debug, Serialize)]
pub struct StatusAccessLog {
    pub path: String,
    /// `stored` (`set-log-paths`), `default`, or `config` (an
    /// `access_log` or `CustomLog` in the web server's config).
    pub origin: String,
    /// Whether it could be opened when the probe was taken.
    pub readable: bool,
}

/// How many checks are at each level, and the worst of them, which is
/// what the exit status follows.
#[derive(Debug, Serialize)]
pub struct StatusSummary {
    pub worst: &'static str,
    pub total: usize,
    pub ok: usize,
    pub unknown: usize,
    pub warn: usize,
    pub critical: usize,
}

#[derive(Debug, Serialize)]
pub struct StatusCheck {
    pub id: &'static str,
    pub title: &'static str,
    pub level: &'static str,
    pub detail: String,
    pub fix: Option<String>,
}

impl Status {
    /// Every check in `report`. `probed_at` is the stored probe's time
    /// for `--cached`, `None` for a probe taken just now.
    pub fn new(report: &Report, probed_at: Option<i64>) -> Status {
        let count = |level| report.checks.iter().filter(|c| c.level == level).count();
        Status {
            checked_at: report.checked_at,
            probed_at: probed_at.unwrap_or(report.checked_at),
            cached: probed_at.is_some(),
            summary: StatusSummary {
                worst: level_name(report.worst()),
                total: report.checks.len(),
                ok: count(Level::Ok),
                unknown: count(Level::Unknown),
                warn: count(Level::Warn),
                critical: count(Level::Critical),
            },
            checks: report
                .checks
                .iter()
                .map(|check| StatusCheck {
                    id: check.id,
                    title: check.title,
                    level: level_name(check.level),
                    detail: check.detail.clone(),
                    fix: check.fix.clone(),
                })
                .collect(),
            access_logs: report
                .access_logs
                .iter()
                .map(|log| StatusAccessLog {
                    path: log.path.clone(),
                    origin: log.origin.clone(),
                    readable: log.readable,
                })
                .collect(),
        }
    }
}

/// `why --json`.
#[derive(Debug, Serialize)]
pub struct Why {
    pub address: String,
    /// The stored rules that cover it.
    pub rules: Vec<FirewallRuleRow>,
    /// Ranges of a country, feed, hosting provider or blocked crawler
    /// that cover it: enforced, and not stored as rules.
    pub lists: Vec<String>,
    /// The trusted addresses or ranges that cover it.
    pub trusted: Vec<String>,
    /// Whether it logged in over SSH recently, and is allowed for that.
    pub ssh_login: bool,
    /// When the detectors stop leaving it alone after an unblock by hand.
    pub unblocked_until: Option<i64>,
}

/// `list-firewall-rules --json`.
#[derive(Debug, Serialize)]
pub struct FirewallRules {
    pub rules: Vec<FirewallRuleRow>,
}

#[derive(Debug, Serialize)]
pub struct FirewallRuleRow {
    /// What `remove-firewall-rule --id` and `set-firewall-rule --id` take.
    pub id: i64,
    /// `block`, `allow` or `reject`.
    pub action: &'static str,
    /// An IP address or CIDR range.
    pub address: String,
    pub port: Option<u16>,
    pub enabled: bool,
    /// What `list-firewall-rules --source` takes: a detector's name,
    /// `cli`, `tui`, `web`, or `before-0.1`.
    pub source: &'static str,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
    /// The log line that triggered it.
    pub evidence: Option<String>,
}

impl From<&FirewallRule> for FirewallRuleRow {
    fn from(rule: &FirewallRule) -> Self {
        FirewallRuleRow {
            id: rule.id,
            action: match rule.action {
                FirewallAction::Allow => "allow",
                FirewallAction::Block => "block",
                FirewallAction::Reject => "reject",
            },
            address: rule.address.clone(),
            port: rule.port,
            enabled: rule.enabled,
            source: crate::blocks::source_name(rule.source),
            created_at: rule.created_at,
            expires_at: rule.expires_at,
            evidence: rule.evidence.clone(),
        }
    }
}

/// `list-probe-paths --json`.
#[derive(Debug, Serialize)]
pub struct ProbePaths {
    /// Always checked.
    pub built_in: Vec<String>,
    /// Added with `set-probe-paths`.
    pub extra: Vec<String>,
    /// Probes only where their application is absent
    /// (`set-detector probe-paths --app-aware`).
    pub conditional: ConditionalProbePaths,
}

#[derive(Debug, Serialize)]
pub struct ConditionalProbePaths {
    /// Whether the detector counts them at all.
    pub enabled: bool,
    /// Off on a database older than the feature, until someone chooses.
    pub new_in_this_release: bool,
    pub paths: Vec<ConditionalProbePath>,
}

/// One conditional path, as a request that names no site is judged.
#[derive(Debug, Serialize)]
pub struct ConditionalProbePath {
    pub path: String,
    /// The applications that make it legitimate.
    pub apps: Vec<&'static str>,
    /// Whether a request for it is a probe on this host now: on, and no
    /// site runs or might run any of `apps`.
    pub active: bool,
    /// Why it is not a probe here, when it is not; `null` when the only
    /// reason is that the setting is off.
    pub reason: Option<String>,
}

/// `list-detectors --json`.
#[derive(Debug, Serialize)]
pub struct Detectors {
    pub detectors: Vec<DetectorRow>,
    /// The port-scan detector's trap ports.
    pub trap_ports: TrapPorts,
    pub subnet_escalation: SubnetEscalation,
    pub repeat_offenders: RepeatOffenders,
}

/// The trap ports `set-detector port-scanners --ports` sets: what is
/// configured, before what listens is left out at render time.
#[derive(Debug, Serialize)]
pub struct TrapPorts {
    pub ports: Vec<u16>,
    /// Whether these are the built-in list.
    pub default: bool,
    /// Never trapped, whatever is configured.
    pub never: Vec<u16>,
}

/// `set-repeat-offenders`: a repeat block lasts the detector's TTL times
/// 2^(offences - 1), up to `max_multiplier` and `max_days`; an address is
/// forgotten `memory_days` after its last block ends.
#[derive(Debug, Serialize)]
pub struct RepeatOffenders {
    pub enabled: bool,
    /// Off on a database older than the feature, until someone chooses.
    pub new_in_this_release: bool,
    pub max_multiplier: i64,
    pub max_days: i64,
    pub memory_days: i64,
}

#[derive(Debug, Serialize)]
pub struct DetectorRow {
    /// As `set-detector` takes it.
    pub name: &'static str,
    pub label: &'static str,
    pub enabled: bool,
    /// Switched by `set-humans-only` rather than `set-detector`.
    pub follows_humans_only: bool,
    pub ttl_days: i64,
    /// `null` for a detector that has none.
    pub threshold: Option<usize>,
    pub window_hours: i64,
    /// Added since this database was created, and not switched on or off
    /// since: off until someone turns it on.
    pub new_in_this_release: bool,
}

#[derive(Debug, Serialize)]
pub struct SubnetEscalation {
    pub enabled: bool,
    pub min: usize,
}

/// `list-access-stats --json`.
#[derive(Debug, Serialize)]
pub struct AccessStats {
    pub user_agents: Vec<AccessStatRow>,
}

#[derive(Debug, Serialize)]
pub struct AccessStatRow {
    pub user_agent: String,
    pub hit_count: i64,
    pub last_seen_at: i64,
}

/// `list-reputation-sources --json`.
#[derive(Debug, Serialize)]
pub struct ReputationSources {
    pub sources: Vec<ReputationSourceRow>,
}

#[derive(Debug, Serialize)]
pub struct ReputationSourceRow {
    /// As `set-reputation-source --source-id` takes it.
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// `null` when it has never been fetched.
    pub last_fetched_at: Option<i64>,
    pub range_count: i64,
    /// What switching it on blocks besides bots, when that is a lot.
    pub warning: Option<&'static str>,
}

/// `list-hosting-asns --json`.
#[derive(Debug, Serialize)]
pub struct HostingAsns {
    pub asns: Vec<HostingAsnRow>,
    /// What blocking any of them blocks besides bots.
    pub warning: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HostingAsnRow {
    /// The AS number, as `add-hosting-asn --asn` takes it.
    pub asn: u32,
    /// The built-in list's name for it, else the table's, else `AS<n>`.
    pub name: String,
    /// What iptoasn.com's table calls the network, from the last
    /// download; `null` before one.
    pub description: Option<String>,
    /// Whether it is on the built-in list.
    pub curated: bool,
    pub blocked: bool,
    /// `null` when its ranges have never been downloaded.
    pub last_fetched_at: Option<i64>,
    pub range_count: i64,
    /// What blocking it takes with it beyond the general warning.
    pub note: Option<&'static str>,
}

/// `list-selected-countries --json`.
#[derive(Debug, Serialize)]
pub struct SelectedCountries {
    /// `blocklist` or `allowlist`, as `set-geo-mode --mode` takes it.
    pub geo_mode: &'static str,
    /// Two-letter codes.
    pub countries: Vec<String>,
}

/// A geo mode as JSON spells it.
pub fn geo_mode_name(mode: GeoMode) -> &'static str {
    match mode {
        GeoMode::Blocklist => "blocklist",
        GeoMode::Allowlist => "allowlist",
    }
}

/// A policy as JSON spells it.
pub fn policy_name(policy: Policy) -> &'static str {
    match policy {
        Policy::Allowed => "allowed",
        Policy::Blocked => "blocked",
    }
}

/// `list-categories --json`.
#[derive(Debug, Serialize)]
pub struct Categories {
    /// The host-wide policy of each category.
    pub categories: Vec<CategoryRow>,
    /// `blocked` or `allowed`, on every site (`set-old-browsers`).
    pub old_browsers: &'static str,
    /// `blocked` or `allowed`, on every site: blocked while
    /// `set-http-libraries` or humans only is on.
    pub http_libraries: &'static str,
    /// While on, every category is blocked whatever is stored.
    pub humans_only: bool,
    /// With `--site`, that site's overrides; `null` without.
    pub site: Option<SiteCategories>,
}

#[derive(Debug, Serialize)]
pub struct CategoryRow {
    /// `scanner`, `search` or `ai`.
    pub category: &'static str,
    /// `allowed` or `blocked`.
    pub policy: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SiteCategories {
    pub server_name: String,
    pub categories: Vec<SiteCategoryRow>,
    pub bot_overrides: Vec<BotOverrideRow>,
}

#[derive(Debug, Serialize)]
pub struct SiteCategoryRow {
    pub category: &'static str,
    /// `null` when the site follows the host-wide policy.
    pub policy: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct BotOverrideRow {
    /// The bot's slug.
    pub bot: String,
    pub policy: &'static str,
}

/// `list-bots --json`.
#[derive(Debug, Serialize)]
pub struct Bots {
    pub bots: Vec<BotRow>,
}

#[derive(Debug, Serialize)]
pub struct BotRow {
    pub slug: String,
    pub name: String,
    /// `default` (follows its categories), `allowed` or `blocked`, as
    /// `set-bot --policy` takes it.
    pub status: &'static str,
    /// Any of `scanner`, `search` and `ai`.
    pub categories: Vec<&'static str>,
}

/// `list-turned-away --json`.
#[derive(Debug, Serialize)]
pub struct TurnedAway {
    /// The block response's HTTP status, which the counts are of.
    pub block_status: u16,
    pub user_agents: Vec<TurnedAwayRow>,
}

#[derive(Debug, Serialize)]
pub struct TurnedAwayRow {
    pub user_agent: String,
    pub refused: u64,
    pub served: u64,
}

/// `list-trusted --json`.
#[derive(Debug, Serialize)]
pub struct Trusted {
    /// IP addresses and CIDR ranges.
    pub addresses: Vec<String>,
    /// Parts of a user agent, matched ignoring case.
    pub user_agents: Vec<String>,
}

/// `list-egress-feeds --json`.
#[derive(Debug, Serialize)]
pub struct EgressFeeds {
    pub feeds: Vec<EgressFeed>,
}

#[derive(Debug, Serialize)]
pub struct EgressFeed {
    pub id: String,
    pub name: String,
    /// Where it is downloaded from, with everything after the host left
    /// out: a URL added by hand can carry a key.
    pub url: Vec<String>,
    /// `ip` or `domain`.
    pub kind: &'static str,
    pub builtin: bool,
    pub enabled: bool,
    /// Whether a hit on it may contain what made it.
    pub contain: bool,
    pub last_fetched_at: Option<i64>,
    pub entries: usize,
    /// Entries the last fetch left out, to keep this host reachable.
    pub kept_off: usize,
}

/// `list-egress-hits --json`.
#[derive(Debug, Serialize)]
pub struct EgressHits {
    pub hits: Vec<EgressHit>,
}

#[derive(Debug, Serialize)]
pub struct EgressHit {
    /// `host`, from a process here, or `forward`, routed through.
    pub path: &'static str,
    pub source: String,
    pub destination: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub uid: Option<u32>,
    pub container: Option<String>,
    pub count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub evidence: String,
}

/// `list-containments --json`.
#[derive(Debug, Serialize)]
pub struct Containments {
    pub containments: Vec<Containment>,
}

#[derive(Debug, Serialize)]
pub struct Containment {
    pub id: i64,
    /// `container`, `user` or `address`.
    pub kind: &'static str,
    pub target: String,
    pub name: Option<String>,
    pub addresses: Vec<String>,
    pub action: String,
    pub reason: String,
    pub automatic: bool,
    pub created_at: i64,
    pub released_at: Option<i64>,
}

/// `list-modsecurity-findings --json`.
#[derive(Debug, Serialize)]
pub struct ModsecFindings {
    pub findings: Vec<ModsecFinding>,
}

#[derive(Debug, Serialize)]
pub struct ModsecFinding {
    /// The site's server_name, `None` for a request no site's block names.
    pub site: Option<String>,
    pub rule: u32,
    pub path: String,
    pub message: String,
    pub count: usize,
    /// Requests the Core Rule Set scored as attacks.
    pub over_threshold: usize,
    pub last_seen: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every character `say!` would rewrite comes out as an escape that
    /// parses back to itself, and the pretty-printer's newlines survive.
    #[test]
    fn json_terminal_safe_escapes_what_a_terminal_acts_on_without_changing_the_value() {
        let value = "a\u{9b}31m\u{7f}\u{202e}\u{200b}\u{e0041}\u{1b}]0;x\u{7}z";
        let json = serde_json::to_string_pretty(&serde_json::json!({ "v": [value] })).unwrap();

        let safe = json_terminal_safe(&json);

        let leftover: Vec<char> = safe
            .chars()
            .filter(|&c| (c.is_control() && c != '\n') || crate::present::is_invisible_format(c))
            .collect();
        assert!(leftover.is_empty(), "left {leftover:?} in:\n{safe}");
        let back: serde_json::Value = serde_json::from_str(&safe).unwrap();
        assert_eq!(back["v"][0], value, "the value changed:\n{safe}");
        assert!(safe.contains('\n'), "the layout's newlines went:\n{safe}");
    }
}
