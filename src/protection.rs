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

/// `settings` key: the trap path itself.
pub const HONEYPOT_PATH: &str = "detect_honeypot_path";

/// Honeypot detection defaults to **off**, unlike the other two
/// path-based detectors. Not because it's risky — it's the most precise
/// signal available here — but because it does nothing useful until the
/// trap path is actually *published* as `Disallow:` in a robots.txt that
/// the site serves (see `nginx`'s robots.txt generation). Defaulting it on
/// would show an enabled detector that can never fire, which is worse than
/// an honest off.
pub const HONEYPOT_ENABLED_DEFAULT: bool = false;

/// Thirty days — the longest TTL of any detector here, because a honeypot
/// hit is the strongest signal this project can produce. Every other
/// detector infers intent from behaviour or from a claim that might be
/// mistaken; this one catches a client fetching a path that exists for no
/// reason other than being forbidden, which no crawler obeying robots.txt
/// and no human following a link can do by accident.
pub const HONEYPOT_TTL_DAYS_DEFAULT: i64 = 30;

/// The default trap path. Deliberately not something that looks valuable
/// (`/admin`, `/backup`) — a path that sounds like real loot would also be
/// guessed by scanners that never read robots.txt, which would turn a
/// precise "ignored robots.txt" signal into just another probe path. The
/// point is that the *only* way to learn this path is to read the
/// robots.txt that forbids it.
pub const HONEYPOT_PATH_DEFAULT: &str = "/stop-bots-trap/";

/// The configured trap path, falling back to [`HONEYPOT_PATH_DEFAULT`].
/// A stored value that doesn't start with `/`, or is blank, falls back
/// too: matching is anchored at the start of the request path, so such a
/// value could never fire and would leave the detector looking switched on
/// while doing nothing.
pub fn honeypot_path(db: &Db) -> Result<String> {
    Ok(db
        .get_text_setting(HONEYPOT_PATH)?
        .map(|p| p.trim().to_string())
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| HONEYPOT_PATH_DEFAULT.to_string()))
}

/// One switchable log-analysis detector, described rather than
/// hand-wired.
///
/// Before this existed, adding a detector meant editing seven files:
/// a settings-key pair here, a field on the settings struct, a `Default`
/// arm, a `load` arm, a `CronJob` variant with three match arms, a
/// `ProtectionRow` variant with four, and a CLI subcommand. The compiler
/// caught a missed arm, but the fifth detector cost what the fourth did.
/// Now a detector is one entry in [`Detector::ALL`] plus one arm where its
/// behaviour genuinely differs — running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detector {
    SshScanners,
    WebScanners,
    SpoofedCrawlers,
    ProbePaths,
    Honeypot,
    AssetRatio,
    RotatingUserAgent,
    RefererlessCrawl,
    /// Only ever on under "humans only" — see [`Detector::is_enabled`].
    RobotsTxt,
}

/// The static facts about a detector: how it's stored, what it's called,
/// and what it does if nobody changes anything.
pub struct DetectorSpec {
    /// Stable id. **Also the `settings` key suffix and the cron job id**,
    /// so renaming one silently orphans an installed database's stored
    /// toggle *and* its cron state. Never rename without a migration.
    pub id: &'static str,
    /// Short label for the Dashboard row.
    pub label: &'static str,
    /// Label for the Scheduled-tasks panel, which describes the job
    /// rather than the switch.
    pub job_label: &'static str,
    pub enabled_default: bool,
    pub ttl_days_default: i64,
    /// Whether this reads the SSH log rather than the NGINX access log.
    pub uses_ssh_log: bool,
}

impl Detector {
    pub const ALL: [Detector; 9] = [
        Detector::SshScanners,
        Detector::WebScanners,
        Detector::SpoofedCrawlers,
        Detector::ProbePaths,
        Detector::Honeypot,
        Detector::AssetRatio,
        Detector::RotatingUserAgent,
        Detector::RefererlessCrawl,
        Detector::RobotsTxt,
    ];

    pub fn spec(self) -> DetectorSpec {
        match self {
            // ids match the pre-existing `CronJob::id()` strings exactly:
            // they are live `settings` keys in every installed database.
            Detector::SshScanners => DetectorSpec {
                id: "block_scanners",
                label: "SSH scanners",
                job_label: "Block SSH scanners",
                enabled_default: true,
                ttl_days_default: 5,
                uses_ssh_log: true,
            },
            Detector::WebScanners => DetectorSpec {
                id: "block_web_scanners",
                label: "Web scanners",
                job_label: "Block web scanners",
                enabled_default: true,
                ttl_days_default: 1,
                uses_ssh_log: false,
            },
            Detector::SpoofedCrawlers => DetectorSpec {
                id: "block_spoofed_crawlers",
                label: "Forged crawler UAs",
                job_label: "Block forged crawler UAs",
                enabled_default: SPOOFED_CRAWLERS_ENABLED_DEFAULT,
                ttl_days_default: SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT,
                uses_ssh_log: false,
            },
            Detector::ProbePaths => DetectorSpec {
                id: "block_probe_paths",
                label: "Probe paths",
                job_label: "Block probe paths",
                enabled_default: PROBE_PATHS_ENABLED_DEFAULT,
                ttl_days_default: PROBE_PATHS_TTL_DAYS_DEFAULT,
                uses_ssh_log: false,
            },
            Detector::RobotsTxt => DetectorSpec {
                id: "block_robots_txt",
                label: "robots.txt fetchers",
                job_label: "Block robots.txt fetchers",
                // Never read: `is_enabled` answers for this one from the
                // humans-only switch instead. Stated as `false` anyway, so
                // that a future reader of the spec alone is not told the
                // wrong thing.
                enabled_default: false,
                ttl_days_default: 1,
                uses_ssh_log: false,
            },
            Detector::Honeypot => DetectorSpec {
                id: "block_honeypot",
                label: "Honeypot path",
                job_label: "Block honeypot hits",
                enabled_default: HONEYPOT_ENABLED_DEFAULT,
                ttl_days_default: HONEYPOT_TTL_DAYS_DEFAULT,
                uses_ssh_log: false,
            },
            // The three below are off by default. Each has a false
            // positive it cannot rule out on its own; see the detector
            // functions in `accesslog` for what and why.
            Detector::AssetRatio => DetectorSpec {
                id: "block_asset_ratio",
                label: "Fetches no assets",
                job_label: "Block asset-less clients",
                enabled_default: false,
                ttl_days_default: 5,
                uses_ssh_log: false,
            },
            Detector::RotatingUserAgent => DetectorSpec {
                id: "block_rotating_ua",
                label: "Rotating user agent",
                job_label: "Block rotating user agents",
                enabled_default: false,
                ttl_days_default: 5,
                uses_ssh_log: false,
            },
            Detector::RefererlessCrawl => DetectorSpec {
                id: "block_refererless",
                label: "Crawls with no referer",
                job_label: "Block referer-less crawling",
                enabled_default: false,
                ttl_days_default: 5,
                uses_ssh_log: false,
            },
        }
    }

    pub fn id(self) -> &'static str {
        self.spec().id
    }

    pub fn from_id(id: &str) -> Option<Detector> {
        Detector::ALL.into_iter().find(|d| d.id() == id)
    }

    /// `settings` key for this detector's on/off switch.
    pub fn enabled_key(self) -> String {
        format!("detect:{}:enabled", self.id())
    }

    /// `settings` key for its block TTL, in days.
    pub fn ttl_key(self) -> String {
        format!("detect:{}:ttl_days", self.id())
    }

    /// Whether this detector runs.
    ///
    /// [`Detector::RobotsTxt`] does not answer from its own setting: it is
    /// owned by the humans-only switch, on when that is on and off when it
    /// is not. A stored toggle would be a second place to say the same
    /// thing, and the two would disagree — which on this detector means
    /// either a day-long block per crawler on a host that never asked for
    /// one, or the mode's sharpest rule quietly not running.
    pub fn is_enabled(self, db: &Db) -> Result<bool> {
        if self == Detector::RobotsTxt {
            return db.get_humans_only();
        }
        db.get_bool_setting(&self.enabled_key(), self.spec().enabled_default)
    }

    /// Whether the operator can change [`Self::is_enabled`], or whether
    /// something else owns it. The UIs grey out a row that answers `false`
    /// rather than offering a toggle that writes a setting nothing reads.
    pub fn is_operator_controlled(self) -> bool {
        self != Detector::RobotsTxt
    }

    pub fn ttl_days(self, db: &Db) -> Result<i64> {
        db.get_int_setting(&self.ttl_key(), self.spec().ttl_days_default)
    }

    pub fn set_enabled(self, db: &Db, enabled: bool) -> Result<()> {
        db.set_bool_setting(&self.enabled_key(), enabled)
    }

    pub fn set_ttl_days(self, db: &Db, days: i64) -> Result<()> {
        db.set_int_setting(&self.ttl_key(), days)
    }
}

/// `settings` key: whether a detector that flags several addresses in one
/// IPv4 `/24` blocks the whole `/24` instead.
pub const SUBNET_ESCALATION: &str = "detect_subnet_escalation";
pub const SUBNET_ESCALATION_DEFAULT: bool = false;

/// How many addresses in one `/24` must be flagged in a single pass
/// before it escalates.
pub const SUBNET_ESCALATION_MIN: &str = "detect_subnet_escalation_min";
pub const SUBNET_ESCALATION_MIN_DEFAULT: i64 = 3;

/// The smallest threshold any detector will act on.
///
/// Every detector compares `count >= threshold`, so 0 and 1 both mean "no
/// evidence required": every address in the log matches, whatever it did.
/// That is the one failure this project cannot have — the tool exists to
/// not block people by mistake.
///
/// Two rather than one because one is still every client for the
/// behavioural detectors specifically: one distinct page, one user agent,
/// one path without a referer describes every visitor there has ever been.
pub const MIN_THRESHOLD: i64 = 2;

/// Reads a detector threshold, floored at [`MIN_THRESHOLD`].
///
/// The floor is at the read rather than at the writes because there are no
/// writes: none of these thresholds has a CLI verb, a TUI editor or a web
/// control. They are reachable the way every other verb-less setting in
/// this project is reachable, and the way TODO.md tells people to reach
/// them — by hand, with `sqlite3`. So the read is the only place that sees
/// every caller.
///
/// A negative value never gets this far: [`Db::get_int_setting`] screens
/// those and returns the detector's own default instead, which is what
/// stops `as usize` turning `-1` into `usize::MAX` and leaving a detector
/// that reports itself enabled while never firing again. This floor is
/// the layer above that one, and closes what it doesn't: zero, which is a
/// perfectly valid non-negative integer.
pub fn threshold(db: &Db, key: &str, default: i64) -> Result<usize> {
    Ok(db.get_int_setting(key, default)?.max(MIN_THRESHOLD) as usize)
}

/// Whether IPv4 `/24` escalation is on, and its threshold.
///
/// Deliberately separate from the unconditional IPv6 `/64` widening in
/// `scanblock::blockable_address`, which is a *correctness* equivalence —
/// a `/64` is one LAN, the same thing one IPv4 address represents. This is
/// a *policy* choice: blocking 256 addresses because three misbehaved is
/// collateral by design, so it gets a switch, a threshold, and an off
/// default.
pub fn subnet_escalation(db: &Db) -> Result<Option<usize>> {
    if !db.get_bool_setting(SUBNET_ESCALATION, SUBNET_ESCALATION_DEFAULT)? {
        return Ok(None);
    }
    Ok(Some(threshold(
        db,
        SUBNET_ESCALATION_MIN,
        SUBNET_ESCALATION_MIN_DEFAULT,
    )?))
}

/// Threshold for the asset-ratio detector: distinct successful page URLs
/// fetched with no accompanying asset. High, and *distinct* rather than a
/// request count, because the false positive to avoid is a legitimate API
/// client — which hammers a handful of endpoints rather than walking a
/// site.
pub const ASSET_RATIO_MIN_PAGES: &str = "detect_asset_ratio_min_pages";
pub const ASSET_RATIO_MIN_PAGES_DEFAULT: i64 = 15;

/// Threshold for the rotating-user-agent detector: distinct user agents
/// from one address.
pub const ROTATING_UA_MIN: &str = "detect_rotating_ua_min";
pub const ROTATING_UA_MIN_DEFAULT: i64 = 8;

/// Threshold for the referer-less detector: distinct deep (non-root) URLs
/// fetched with no `Referer`.
pub const REFERERLESS_MIN_PATHS: &str = "detect_refererless_min_paths";
pub const REFERERLESS_MIN_PATHS_DEFAULT: i64 = 25;

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this floor exists to prevent: every detector compares
    /// `count >= threshold`, so a hand-edited 0 turns "block scanners"
    /// into "block everyone who appears in the log at all".
    #[test]
    fn a_threshold_that_would_match_everything_is_raised_to_the_floor() {
        let db = Db::open_in_memory().unwrap();

        for value in [0, 1] {
            db.set_int_setting(ASSET_RATIO_MIN_PAGES, value).unwrap();
            assert_eq!(
                threshold(&db, ASSET_RATIO_MIN_PAGES, ASSET_RATIO_MIN_PAGES_DEFAULT).unwrap(),
                MIN_THRESHOLD as usize,
                "{value} was let through"
            );
        }
    }

    /// A negative one is screened a layer lower, by `get_int_setting`,
    /// which is what stops `as usize` turning it into `usize::MAX` and
    /// leaving a detector enabled but permanently silent. Asserted here
    /// rather than only in `db.rs` because this is the caller that would
    /// be hurt if that filter were ever dropped as redundant.
    #[test]
    fn a_negative_threshold_falls_back_to_the_default_rather_than_wrapping() {
        let db = Db::open_in_memory().unwrap();

        for value in [i64::MIN, -1] {
            db.set_int_setting(ROTATING_UA_MIN, value).unwrap();
            assert_eq!(
                threshold(&db, ROTATING_UA_MIN, ROTATING_UA_MIN_DEFAULT).unwrap(),
                ROTATING_UA_MIN_DEFAULT as usize,
                "{value} did not fall back to the default"
            );
        }
    }

    #[test]
    fn a_threshold_above_the_floor_is_left_alone() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(REFERERLESS_MIN_PATHS, 40).unwrap();

        assert_eq!(
            threshold(&db, REFERERLESS_MIN_PATHS, REFERERLESS_MIN_PATHS_DEFAULT).unwrap(),
            40
        );
    }

    /// Unset means the default, not the floor.
    #[test]
    fn an_unset_threshold_is_the_detector_s_own_default() {
        let db = Db::open_in_memory().unwrap();

        assert_eq!(
            threshold(&db, ASSET_RATIO_MIN_PAGES, ASSET_RATIO_MIN_PAGES_DEFAULT).unwrap(),
            ASSET_RATIO_MIN_PAGES_DEFAULT as usize
        );
    }

    #[test]
    fn every_detector_has_a_distinct_stable_id() {
        let mut ids: Vec<&str> = Detector::ALL.iter().map(|d| d.id()).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count, "detector ids must be unique");
        for d in Detector::ALL {
            assert_eq!(Detector::from_id(d.id()), Some(d));
        }
        assert_eq!(Detector::from_id("nope"), None);
    }

    /// These strings are live `settings` keys and cron-job ids in every
    /// installed database. Changing one silently orphans a stored toggle
    /// and resets that job's schedule, so they are pinned here rather than
    /// left to a careless rename.
    #[test]
    fn the_pre_existing_detector_ids_are_unchanged() {
        assert_eq!(Detector::SshScanners.id(), "block_scanners");
        assert_eq!(Detector::WebScanners.id(), "block_web_scanners");
        assert_eq!(Detector::SpoofedCrawlers.id(), "block_spoofed_crawlers");
        assert_eq!(Detector::ProbePaths.id(), "block_probe_paths");
        assert_eq!(Detector::Honeypot.id(), "block_honeypot");
    }

    #[test]
    fn defaults_apply_to_a_database_that_has_never_set_them() {
        let db = Db::open_in_memory().unwrap();
        for d in Detector::ALL {
            assert_eq!(d.is_enabled(&db).unwrap(), d.spec().enabled_default);
            assert_eq!(d.ttl_days(&db).unwrap(), d.spec().ttl_days_default);
        }
    }

    #[test]
    fn stored_values_override_the_defaults_per_detector() {
        let db = Db::open_in_memory().unwrap();
        Detector::Honeypot.set_enabled(&db, true).unwrap();
        Detector::Honeypot.set_ttl_days(&db, 9).unwrap();

        assert!(Detector::Honeypot.is_enabled(&db).unwrap());
        assert_eq!(Detector::Honeypot.ttl_days(&db).unwrap(), 9);
        // ...and only that detector.
        assert_eq!(
            Detector::ProbePaths.ttl_days(&db).unwrap(),
            Detector::ProbePaths.spec().ttl_days_default
        );
    }

    /// The three behavioural detectors each have a false positive they
    /// can't rule out (see their doc comments), so none may ship on.
    #[test]
    fn the_behavioural_detectors_are_off_by_default() {
        for d in [
            Detector::AssetRatio,
            Detector::RotatingUserAgent,
            Detector::RefererlessCrawl,
        ] {
            assert!(!d.spec().enabled_default, "{} must default off", d.id());
        }
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
    fn honeypot_path_falls_back_for_a_value_that_could_never_match() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(honeypot_path(&db).unwrap(), HONEYPOT_PATH_DEFAULT);

        db.set_text_setting(HONEYPOT_PATH, "no-leading-slash")
            .unwrap();
        assert_eq!(honeypot_path(&db).unwrap(), HONEYPOT_PATH_DEFAULT);

        db.set_text_setting(HONEYPOT_PATH, "  /my-trap/  ").unwrap();
        assert_eq!(honeypot_path(&db).unwrap(), "/my-trap/");
    }
}
