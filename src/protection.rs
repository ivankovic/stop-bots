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

//! The on/off switches (and their parameters) for every *automatic*
//! detector that adds firewall rules on its own — one place holding the
//! `settings` keys, their defaults, and the reasoning behind each default,
//! so the internal cron, the CLI and the Dashboard panel all read the same
//! values instead of three copies of the same literal.
//!
//! Everything here gates a detector that writes `firewall_rules` rows.
//! That's what makes it Dashboard-side rather than Site-settings-side (see
//! `tui/site_settings.rs`'s module doc for the other half of that split):
//! these end up in the generated firewall script, never in NGINX config.
//!
//! **A disabled detector is skipped entirely, not run-and-discarded.** The
//! cron job checks its toggle before reading a log at all, so turning one
//! off also stops the log parsing it implies — relevant on a box where
//! `/var/log/nginx/access.log` is large.
//!
//! Turning a detector *off* never removes rules it already added. They
//! expire on their own TTL (and `list_firewall_rules` prunes lapsed rows on
//! read), which keeps "stop detecting" distinct from "undo what was
//! detected" — the latter is the admin's call, via the Dynamic Protection
//! screen or `remove-firewall-rule`.

use crate::db::Db;
use anyhow::Result;

/// `settings` key: whether spoofed-crawler detection runs.
pub const SPOOFED_CRAWLERS_ENABLED: &str = "detect_spoofed_crawlers";
/// `settings` key: TTL in days for a block that detection adds.
pub const SPOOFED_CRAWLERS_TTL_DAYS: &str = "detect_spoofed_crawlers_ttl_days";

/// Spoofed-crawler detection defaults to **on**. Unlike the threshold-based
/// detectors this one has no false-positive tuning to get wrong: an IP is
/// only flagged when it puts a crawler's name in its user agent *and* sits
/// outside the CIDRs that crawler's own operator publishes, and the
/// published lists are complete by construction. It's also inert until
/// `update-ip-ranges` has actually fetched something (see
/// `scanblock::crawler_claims`), so enabling it by default can't do
/// anything on a fresh install before there's data to check against.
pub const SPOOFED_CRAWLERS_ENABLED_DEFAULT: bool = true;

/// One day, matching `block-web-scanners` rather than `block-scanners`'
/// five. The failure mode worth designing against is a crawler operator
/// adding a range faster than the daily `UpdateIpRanges` job picks it up:
/// a real Googlebot address could then be blocked for as long as the TTL.
/// A short TTL bounds that to a day, and a genuine impersonator gets
/// re-flagged on its very next request anyway.
pub const SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT: i64 = 1;

/// `settings` key: whether probe-path detection runs.
pub const PROBE_PATHS_ENABLED: &str = "detect_probe_paths";
/// `settings` key: TTL in days for a block that detection adds.
pub const PROBE_PATHS_TTL_DAYS: &str = "detect_probe_paths_ttl_days";
/// `settings` key: extra probe paths, one per line, appended to
/// [`crate::accesslog::DEFAULT_PROBE_PATHS`].
pub const PROBE_PATHS_EXTRA: &str = "detect_probe_paths_extra";

/// Probe-path detection defaults to **on**. The built-in list is chosen
/// strictly enough that a single request to any of them is conclusive (see
/// `accesslog::DEFAULT_PROBE_PATHS` — deliberately *not* including
/// `/wp-login.php` and friends, which real administrators use), so unlike
/// a threshold there is nothing to tune wrong.
pub const PROBE_PATHS_ENABLED_DEFAULT: bool = true;

/// Five days, matching `block-scanners` rather than the one day
/// spoofed-crawler detection uses. The difference is who can be caught by
/// mistake: a mis-detected crawler is a real service you want back
/// quickly, whereas anything requesting `/.env` has no legitimate business
/// here at all, so there's no reason to hurry it back.
pub const PROBE_PATHS_TTL_DAYS_DEFAULT: i64 = 5;

/// Every extra probe path configured on top of the built-in list: the
/// `PROBE_PATHS_EXTRA` setting split on newlines, with blank lines and
/// `#` comments dropped so an admin can annotate the list. Entries that
/// don't start with `/` are skipped rather than silently never matching —
/// [`crate::accesslog::probe_path_ips`] anchors at the start of the
/// request path, so a bare `wp-config.php` would match nothing and look
/// like the detector was broken.
pub fn extra_probe_paths(db: &Db) -> Result<Vec<String>> {
    let raw = db.get_text_setting(PROBE_PATHS_EXTRA)?.unwrap_or_default();
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.starts_with('/'))
        .map(str::to_string)
        .collect())
}

/// The full probe-path list actually used: the built-in defaults plus
/// [`extra_probe_paths`]. The built-ins are never removable — an admin who
/// wants the detector off turns the whole detector off, which is a clearer
/// thing to reason about than a partially disabled list.
pub fn probe_paths(db: &Db) -> Result<Vec<String>> {
    let mut paths: Vec<String> = crate::accesslog::DEFAULT_PROBE_PATHS
        .iter()
        .map(|p| p.to_string())
        .collect();
    paths.extend(extra_probe_paths(db)?);
    Ok(paths)
}

/// Every automatic-detection setting, read in one go. Cheap (a handful of
/// `settings` lookups) and read fresh at each use rather than cached, so a
/// toggle flipped in the TUI takes effect on the very next cron tick
/// without any invalidation plumbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionSettings {
    pub spoofed_crawlers_enabled: bool,
    pub spoofed_crawlers_ttl_days: i64,
    pub probe_paths_enabled: bool,
    pub probe_paths_ttl_days: i64,
}

/// Hand-written rather than derived: a derived `Default` would give
/// `false`/`0`, which is not what an unset database means. This must agree
/// with what [`ProtectionSettings::load`] produces for a database that has
/// never set anything, so the TUI's pre-`refresh` state matches what the
/// first refresh will show.
impl Default for ProtectionSettings {
    fn default() -> Self {
        ProtectionSettings {
            spoofed_crawlers_enabled: SPOOFED_CRAWLERS_ENABLED_DEFAULT,
            spoofed_crawlers_ttl_days: SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT,
            probe_paths_enabled: PROBE_PATHS_ENABLED_DEFAULT,
            probe_paths_ttl_days: PROBE_PATHS_TTL_DAYS_DEFAULT,
        }
    }
}

impl ProtectionSettings {
    pub fn load(db: &Db) -> Result<Self> {
        Ok(ProtectionSettings {
            spoofed_crawlers_enabled: db
                .get_bool_setting(SPOOFED_CRAWLERS_ENABLED, SPOOFED_CRAWLERS_ENABLED_DEFAULT)?,
            spoofed_crawlers_ttl_days: db
                .get_int_setting(SPOOFED_CRAWLERS_TTL_DAYS, SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT)?,
            probe_paths_enabled: db
                .get_bool_setting(PROBE_PATHS_ENABLED, PROBE_PATHS_ENABLED_DEFAULT)?,
            probe_paths_ttl_days: db
                .get_int_setting(PROBE_PATHS_TTL_DAYS, PROBE_PATHS_TTL_DAYS_DEFAULT)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_to_a_database_that_has_never_set_them() {
        let db = Db::open_in_memory().unwrap();
        let settings = ProtectionSettings::load(&db).unwrap();

        assert_eq!(
            settings.spoofed_crawlers_enabled,
            SPOOFED_CRAWLERS_ENABLED_DEFAULT
        );
        assert_eq!(
            settings.spoofed_crawlers_ttl_days,
            SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT
        );
    }

    /// `Default` is what the TUI shows before its first refresh; it
    /// drifting from `load`'s unset-database result would make the panel
    /// flicker between two values on startup.
    #[test]
    fn default_matches_load_on_an_untouched_database() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            ProtectionSettings::load(&db).unwrap(),
            ProtectionSettings::default()
        );
    }

    #[test]
    fn stored_values_override_the_defaults() {
        let db = Db::open_in_memory().unwrap();
        db.set_bool_setting(SPOOFED_CRAWLERS_ENABLED, false)
            .unwrap();
        db.set_int_setting(SPOOFED_CRAWLERS_TTL_DAYS, 9).unwrap();

        let settings = ProtectionSettings::load(&db).unwrap();
        assert!(!settings.spoofed_crawlers_enabled);
        assert_eq!(settings.spoofed_crawlers_ttl_days, 9);
    }

    /// A corrupt or hand-edited row must not take a detector down with it.
    #[test]
    fn an_unparseable_stored_value_falls_back_to_the_default() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(SPOOFED_CRAWLERS_ENABLED, "yes")
            .unwrap();
        db.set_text_setting(SPOOFED_CRAWLERS_TTL_DAYS, "soon")
            .unwrap();

        let settings = ProtectionSettings::load(&db).unwrap();
        assert_eq!(
            settings.spoofed_crawlers_enabled,
            SPOOFED_CRAWLERS_ENABLED_DEFAULT
        );
        assert_eq!(
            settings.spoofed_crawlers_ttl_days,
            SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT
        );
    }

    #[test]
    fn probe_paths_are_the_builtins_when_nothing_extra_is_configured() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            probe_paths(&db).unwrap().len(),
            crate::accesslog::DEFAULT_PROBE_PATHS.len()
        );
    }

    #[test]
    fn extra_probe_paths_appends_to_the_builtins_and_skips_noise() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(
            PROBE_PATHS_EXTRA,
            "/my-secret\n\n# a comment\n  /spaced  \nnot-anchored\n",
        )
        .unwrap();

        assert_eq!(
            extra_probe_paths(&db).unwrap(),
            vec!["/my-secret".to_string(), "/spaced".to_string()]
        );
        let all = probe_paths(&db).unwrap();
        assert_eq!(all.len(), crate::accesslog::DEFAULT_PROBE_PATHS.len() + 2);
        // The built-ins are never removed by configuring extras.
        assert!(all.contains(&"/.env".to_string()));
    }

    /// The built-in list must never contain a path a real administrator or
    /// integration uses — this detector blocks on one request.
    #[test]
    fn the_builtin_probe_paths_exclude_legitimate_admin_paths() {
        for legit in ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin"] {
            assert!(
                !crate::accesslog::DEFAULT_PROBE_PATHS.contains(&legit),
                "{legit} is legitimate on some sites and must not be instant-blocked"
            );
        }
    }

    #[test]
    fn a_negative_ttl_falls_back_to_the_default() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(SPOOFED_CRAWLERS_TTL_DAYS, -3).unwrap();

        assert_eq!(
            ProtectionSettings::load(&db)
                .unwrap()
                .spoofed_crawlers_ttl_days,
            SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT
        );
    }
}
