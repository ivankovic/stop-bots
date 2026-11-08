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

//! Every key of the `settings` table, spelled once.
//!
//! The table is a flat key/value store, and a key is the only thing that
//! ties a stored value to the code that reads it. Before this module the
//! forty-odd keys were literals in nine modules, in three naming styles,
//! and a rename in one place would have silently orphaned the value every
//! installed database holds under the old name.
//!
//! **Never rename a key here.** The spellings are what 0.0.x wrote to real
//! hosts, and a database is only ever read back by the key it was written
//! under. The three styles (`humans_only`, `detect_honeypot_path`,
//! `nginx:root`) stay as they are for that reason. A key that must change is
//! a migration in [`super::schema`] that moves the row, not an edit here.
//!
//! **A new key** is a constant here, added to [`ALL`]; or, for a family
//! of keys with a parameter, a prefix in [`FAMILIES`] and a function that
//! builds the key. The tests below check that no two keys collide and that
//! no other source file spells a key out.
//!
//! Some modules also name the keys they own (`ServerCommands::TEST_KEY`)
//! so their call sites read in their own terms.
//! Those names are aliases of these constants, never a second spelling.

// ---- the database itself ----

/// The defaults generation the database was created at. Written once, by
/// [`super::schema`], when it creates a database.
pub const DEFAULTS_GENERATION: &str = "db:defaults_generation";

// ---- bot blocking policy ----

/// Stored `Policy` for bots flagged as scanners, seeded by the schema.
pub const DEFAULT_STATUS_SCANNER: &str = "default_status_scanner";
/// Stored `Policy` for search-engine crawlers, seeded by the schema.
pub const DEFAULT_STATUS_SEARCH: &str = "default_status_search";
/// Stored `Policy` for AI crawlers, seeded by the schema.
pub const DEFAULT_STATUS_AI: &str = "default_status_ai";
/// Whether this host serves humans and nothing else.
pub const HUMANS_ONLY: &str = "humans_only";
/// Whether [`crate::botlist::old_browsers`] is blocked. A setting of its
/// own rather than a category: those entries are not bots and have no
/// `bots` rows to carry a category flag.
pub const BLOCK_OLD_BROWSERS: &str = "block_old_browsers";
/// Whether [`crate::botlist::http_libraries`] is blocked, for the same
/// reason [`BLOCK_OLD_BROWSERS`] is a setting.
pub const BLOCK_HTTP_LIBRARIES: &str = "block_http_libraries";
/// `GeoMode`: what the selected countries mean. Seeded by the schema.
pub const GEO_MODE: &str = "geo_mode";

// ---- generated NGINX config ----

/// `BlockResponse`: how a blocked request is turned away.
pub const BLOCK_RESPONSE: &str = "block_response";
pub const SERVE_ROBOTS_TXT: &str = "serve_robots_txt";
pub const RATE_LIMIT_ENABLED: &str = "rate_limit_enabled";
pub const RATE_LIMIT_RPS: &str = "rate_limit_rps";
pub const RATE_LIMIT_BURST: &str = "rate_limit_burst";
pub const RATE_LIMIT_ZONE_MB: &str = "rate_limit_zone_mb";
/// Whether the internal cron re-applies stale site configs.
pub const AUTO_APPLY: &str = "auto_apply";
pub const NGINX_TEST_COMMAND: &str = "nginx:test_command";
pub const NGINX_RELOAD_COMMAND: &str = "nginx:reload_command";
/// Where this host's site configs live.
pub const NGINX_ROOT: &str = "nginx:root";

// ---- logs ----

pub const LOGS_ACCESS_PATH: &str = "logs:access_path";
pub const LOGS_SSH_PATH: &str = "logs:ssh_path";

// ---- firewall ----

/// The backend the last render was for.
pub const FIREWALL_BACKEND: &str = "firewall:backend";
/// Digest of the rule set as last rendered (see `firewall::rules_signature`).
pub const FIREWALL_RENDERED_SIGNATURE: &str = "firewall_rendered_signature";
/// Digest of the rule set as last applied: run, and copied to the script
/// the boot unit loads.
pub const FIREWALL_APPLIED_SIGNATURE: &str = "firewall:applied_signature";
/// Whether the internal cron applies the rendered firewall script.
pub const AUTO_APPLY_FIREWALL: &str = "auto_apply_firewall";
/// Whether a cloud-provider feed leaves port 80 open, so Let's Encrypt
/// can reach it (see `Db::derived_firewall_entries`).
pub const CLOUD_PORT_80_OPEN: &str = "firewall:cloud_port_80_open";
/// Whether every apply is checked against the addresses that log in over
/// SSH. Off only for someone who said they never log in over SSH.
pub const SSH_LOCKOUT_CHECK: &str = "firewall:ssh_lockout_check";

// ---- outbound traffic (see `egress` and `contain`) ----

/// `egress::Mode`: whether outbound connections to listed addresses are
/// checked, and whether they are stopped.
pub const EGRESS_MODE: &str = "egress:mode";
/// `sinkhole::Target`: which resolver is told about listed domains.
pub const EGRESS_DNS_TARGET: &str = "egress:dns_target";
/// The address listed domains resolve to.
pub const EGRESS_SINKHOLE: &str = "egress:sinkhole";
/// Whether a hit contains what made it, without asking.
pub const EGRESS_AUTO_CONTAIN: &str = "egress:auto_contain";
/// Whether automatic containment applies to containers.
pub const EGRESS_CONTAIN_CONTAINERS: &str = "egress:contain_containers";
/// Whether automatic containment applies to users on the host.
pub const EGRESS_CONTAIN_USERS: &str = "egress:contain_users";
/// `contain::Action`: what is done to a contained container.
pub const EGRESS_CONTAINER_ACTION: &str = "egress:container_action";
/// `contain::Action`: what is done to a contained user.
pub const EGRESS_USER_ACTION: &str = "egress:user_action";
/// Containers and users never contained automatically, comma-separated.
pub const EGRESS_NEVER_CONTAIN: &str = "egress:never_contain";
/// The most automatic containments in an hour before the breaker trips.
pub const EGRESS_BREAKER_MAX: &str = "egress:breaker_max";
/// When the breaker tripped, in Unix seconds; unset while it has not.
pub const EGRESS_BREAKER_TRIPPED: &str = "egress:breaker_tripped_at";

// ---- the web application firewall (see `exploits` and `modsecurity`) ----

/// Whether the exploit rules are on for every site that does not choose.
pub const WAF_EXPLOIT_RULES: &str = "waf:exploit_rules";
/// `modsecurity::Mode` for every site that does not choose.
pub const WAF_MODSECURITY: &str = "waf:modsecurity";
/// The CRS paranoia level for every site that does not choose.
pub const WAF_PARANOIA: &str = "waf:paranoia";

// ---- detectors ----
//
// A detector's on/off switch and TTL are the `detect:` family below; these
// are the detector parameters that are not per-detector.

pub const DETECT_PROBE_PATHS_EXTRA: &str = "detect_probe_paths_extra";
pub const DETECT_HONEYPOT_PATH: &str = "detect_honeypot_path";
pub const DETECT_SUBNET_ESCALATION: &str = "detect_subnet_escalation";
pub const DETECT_SUBNET_ESCALATION_MIN: &str = "detect_subnet_escalation_min";
/// Whether a repeat offender is blocked for longer each time (see
/// `protection::repeat_escalation`). Unset on a database nobody has
/// switched it on, which reads by the database's defaults generation.
pub const DETECT_REPEAT_OFFENDERS: &str = "detect_repeat_offenders";
/// Whether the probe-paths detector also counts the paths of applications
/// that are absent (see `protection::app_probe_paths`). Unset on a
/// database nobody has switched it on, which reads by the database's
/// defaults generation.
pub const DETECT_PROBE_PATHS_APP_AWARE: &str = "detect_probe_paths_app_aware";
pub const DETECT_ASSET_RATIO_MIN_PAGES: &str = "detect_asset_ratio_min_pages";
pub const DETECT_ROTATING_UA_MIN: &str = "detect_rotating_ua_min";
pub const DETECT_REFERERLESS_MIN_PATHS: &str = "detect_refererless_min_paths";
pub const DETECT_SSH_SCANNERS_MIN_ATTEMPTS: &str = "detect_ssh_scanners_min_attempts";
pub const DETECT_WEB_SCANNERS_MIN_PATHS: &str = "detect_web_scanners_min_paths";
pub const DETECT_LOGIN_ATTEMPTS_MIN: &str = "detect_login_attempts_min";
pub const DETECT_REQUEST_RATE_PER_MINUTE: &str = "detect_request_rate_per_minute";
/// The port-scan detector's trap ports, comma-separated (see
/// `portscan::configured_ports`). Unset is the built-in list.
pub const DETECT_PORT_SCANNERS_PORTS: &str = "detect_port_scanners_ports";
pub const DETECT_PORT_SCANNERS_MIN_PORTS: &str = "detect_port_scanners_min_ports";

// ---- downloads ----

/// Who is downloading the lists right now, and since when: see
/// `refresh::Lease`.
pub const REFRESH_LEASE: &str = "refresh:lease";

// ---- health ----

/// The last health probe, as JSON.
pub const HEALTH_PROBE: &str = "health:probe";
/// When it was taken, in Unix seconds.
pub const HEALTH_PROBE_AT: &str = "health:probe_at";

// ---- the TUI ----

/// Which TUI the operator chose, `simple` or `advanced` (see
/// `Db::get_ui_mode`). Unset follows the database's defaults generation.
pub const UI_MODE: &str = "ui:mode";

/// Every fixed key above. The tests check that each constant in this file
/// is listed, and that none collide.
pub const ALL: &[&str] = &[
    DEFAULTS_GENERATION,
    DEFAULT_STATUS_SCANNER,
    DEFAULT_STATUS_SEARCH,
    DEFAULT_STATUS_AI,
    HUMANS_ONLY,
    BLOCK_OLD_BROWSERS,
    BLOCK_HTTP_LIBRARIES,
    GEO_MODE,
    BLOCK_RESPONSE,
    SERVE_ROBOTS_TXT,
    RATE_LIMIT_ENABLED,
    RATE_LIMIT_RPS,
    RATE_LIMIT_BURST,
    RATE_LIMIT_ZONE_MB,
    AUTO_APPLY,
    NGINX_TEST_COMMAND,
    NGINX_RELOAD_COMMAND,
    NGINX_ROOT,
    LOGS_ACCESS_PATH,
    LOGS_SSH_PATH,
    FIREWALL_BACKEND,
    FIREWALL_RENDERED_SIGNATURE,
    FIREWALL_APPLIED_SIGNATURE,
    AUTO_APPLY_FIREWALL,
    CLOUD_PORT_80_OPEN,
    SSH_LOCKOUT_CHECK,
    EGRESS_MODE,
    EGRESS_DNS_TARGET,
    EGRESS_SINKHOLE,
    EGRESS_AUTO_CONTAIN,
    EGRESS_CONTAIN_CONTAINERS,
    EGRESS_CONTAIN_USERS,
    EGRESS_CONTAINER_ACTION,
    EGRESS_USER_ACTION,
    EGRESS_NEVER_CONTAIN,
    EGRESS_BREAKER_MAX,
    EGRESS_BREAKER_TRIPPED,
    WAF_EXPLOIT_RULES,
    WAF_MODSECURITY,
    WAF_PARANOIA,
    DETECT_PROBE_PATHS_EXTRA,
    DETECT_HONEYPOT_PATH,
    DETECT_SUBNET_ESCALATION,
    DETECT_SUBNET_ESCALATION_MIN,
    DETECT_REPEAT_OFFENDERS,
    DETECT_PROBE_PATHS_APP_AWARE,
    DETECT_ASSET_RATIO_MIN_PAGES,
    DETECT_ROTATING_UA_MIN,
    DETECT_REFERERLESS_MIN_PATHS,
    DETECT_SSH_SCANNERS_MIN_ATTEMPTS,
    DETECT_WEB_SCANNERS_MIN_PATHS,
    DETECT_LOGIN_ATTEMPTS_MIN,
    DETECT_REQUEST_RATE_PER_MINUTE,
    DETECT_PORT_SCANNERS_PORTS,
    DETECT_PORT_SCANNERS_MIN_PORTS,
    HEALTH_PROBE,
    HEALTH_PROBE_AT,
    REFRESH_LEASE,
    UI_MODE,
];

// ---- families: one key per detector, cron job or log file ----

const DETECT_PREFIX: &str = "detect:";
const CRON_LAST_RUN_PREFIX: &str = "cron_last_run:";
const CRON_LAST_SUMMARY_PREFIX: &str = "cron_last_summary:";
const ACCESS_LOG_OFFSET_PREFIX: &str = "access_log_offset:";
const LOG_CURSOR_PREFIX: &str = "log_cursor:";

/// The prefix of every parameterised key. A fixed key never starts with
/// one, so a family can take any parameter without colliding.
pub const FAMILIES: &[&str] = &[
    DETECT_PREFIX,
    CRON_LAST_RUN_PREFIX,
    CRON_LAST_SUMMARY_PREFIX,
    ACCESS_LOG_OFFSET_PREFIX,
    LOG_CURSOR_PREFIX,
];

/// A detector's on/off switch, `"true"` or `"false"`. `id` is its
/// `DetectorSpec::id`.
pub fn detector_enabled(id: &str) -> String {
    format!("{DETECT_PREFIX}{id}:enabled")
}

/// A detector's block TTL, in days.
pub fn detector_ttl_days(id: &str) -> String {
    format!("{DETECT_PREFIX}{id}:ttl_days")
}

/// How far back a detector's evidence counts, in hours.
pub fn detector_window_hours(id: &str) -> String {
    format!("{DETECT_PREFIX}{id}:window_hours")
}

/// When a cron job last ran, in Unix seconds. `id` is its `CronJob::id`.
pub fn cron_last_run(id: &str) -> String {
    format!("{CRON_LAST_RUN_PREFIX}{id}")
}

/// A cron job's last one-line outcome.
pub fn cron_last_summary(id: &str) -> String {
    format!("{CRON_LAST_SUMMARY_PREFIX}{id}")
}

/// How far into `log_path` the access-stats tally had read, in bytes of
/// decoded text. Written by 0.0.x; now only read, once per log, to start
/// that log's [`log_cursor`] where the old tally stopped rather than count
/// the whole file again.
pub fn access_log_offset(log_path: &str) -> String {
    format!("{ACCESS_LOG_OFFSET_PREFIX}{log_path}")
}

/// Where the next read of a log resumes: `source` is the path read, or
/// `journald:<units>` for the journal. The value is a
/// `logread::FileCursor` or a journal cursor, in their stored forms.
pub fn log_cursor(source: &str) -> String {
    format!("{LOG_CURSOR_PREFIX}{source}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_two_fixed_keys_are_the_same() {
        let mut seen = HashSet::new();
        for key in ALL {
            assert!(seen.insert(key), "{key:?} is listed twice");
        }
    }

    /// A fixed key inside a family's namespace could be the same row as
    /// some member of that family: `detect:x:enabled` for a detector
    /// named `x`.
    #[test]
    fn no_fixed_key_is_inside_a_family() {
        for key in ALL {
            for prefix in FAMILIES {
                assert!(!key.starts_with(prefix), "{key:?} is inside {prefix:?}");
            }
        }
        for a in FAMILIES {
            for b in FAMILIES {
                assert!(a == b || !a.starts_with(b), "{a:?} is inside {b:?}");
            }
        }
    }

    /// Every key a real database can hold today, spelled out, is distinct.
    #[test]
    fn every_concrete_key_is_distinct() {
        let mut keys: Vec<String> = ALL.iter().map(|k| k.to_string()).collect();
        for detector in crate::protection::Detector::ALL {
            keys.push(detector_enabled(detector.id()));
            keys.push(detector_ttl_days(detector.id()));
            keys.push(detector_window_hours(detector.id()));
        }
        for job in crate::cron::CronJob::all() {
            keys.push(cron_last_run(job.id()));
            keys.push(cron_last_summary(job.id()));
        }
        keys.push(access_log_offset("/var/log/nginx/access.log"));
        keys.push(log_cursor("/var/log/nginx/access.log"));
        keys.push(log_cursor("journald:ssh"));
        let mut seen = HashSet::new();
        for key in &keys {
            assert!(seen.insert(key), "{key:?} is produced twice");
        }
    }

    /// A constant added to this file but not to [`ALL`] would escape the
    /// collision checks above.
    #[test]
    fn every_constant_here_is_in_all() {
        let source = include_str!("keys.rs");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|line| line.strip_prefix("pub const "))
            .filter(|rest| rest.contains(": &str = \""))
            .filter_map(|rest| rest.split('"').nth(1))
            .collect();
        assert!(declared.len() > 30, "parsed only {declared:?}");
        for key in declared {
            assert!(ALL.contains(&key), "{key:?} is declared but not in ALL");
        }
    }

    /// The point of the module: a key is spelled here and nowhere else,
    /// so it cannot be spelled two ways. A quoted key in any other source
    /// file (`"geo_mode"`, or `'geo_mode'` inside SQL) fails this.
    #[test]
    fn no_other_source_file_spells_out_a_key() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") || path.ends_with("db/keys.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for key in ALL.iter().chain(FAMILIES) {
                    for quoted in [format!("\"{key}"), format!("'{key}")] {
                        // A family prefix is quoted at its start; a fixed
                        // key must also end there to count.
                        let hit = text.match_indices(&quoted).any(|(at, _)| {
                            FAMILIES.contains(key) || {
                                let next = text[at + quoted.len()..].chars().next();
                                next == quoted.chars().next()
                            }
                        });
                        if hit {
                            offenders.push(format!("{}: {quoted}", path.display()));
                        }
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "use db::keys instead of spelling these out:\n{}",
            offenders.join("\n")
        );
    }
}
