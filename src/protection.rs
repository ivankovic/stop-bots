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

//! The on/off switches (and their parameters) for every *automatic*
//! detector that adds firewall rules on its own — one place holding the
//! `settings` keys, their defaults, and the reasoning behind each default,
//! so the internal cron, the CLI and the Dashboard panel all read the same
//! values instead of three copies of the same literal.
//!
//! Everything here gates a detector that writes `firewall_rules` rows.
//! That's what makes it Dashboard-side rather than Site-settings-side (see
//! `tui/nginx.rs`'s module doc for the other half of that split):
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
//! detected" — the latter is the admin's call, via the Firewall
//! screen or `remove-firewall-rule`.

use crate::db::{keys, Db};
use anyhow::Result;

/// Spoofed-crawler detection defaults to **on**. Unlike the threshold-based
/// detectors this one has no false-positive tuning to get wrong: an IP is
/// only flagged when it puts a crawler's name in its user agent *and* sits
/// outside the CIDRs that crawler's own operator publishes, and the
/// published lists are complete by construction. It's also inert until
/// `update-crawler-ranges` has actually fetched something (see
/// `scanblock::crawler_claims`), so enabling it by default can't do
/// anything on a fresh install before there's data to check against.
pub const SPOOFED_CRAWLERS_ENABLED_DEFAULT: bool = true;

/// The longest a detector's block may last: ten years.
///
/// Not a policy anyone is expected to reach — the TUI offers a month at
/// most — but the TTL becomes `days * 86_400` seconds added to now, and
/// without a ceiling a large enough number wrapped in release builds
/// (a block born already expired, so a detector that silently blocks
/// nothing) and panicked in debug ones.
pub const MAX_TTL_DAYS: i64 = 3650;

/// How far back a detector looks, for every detector that is not one of
/// the three behavioural ones: a day.
///
/// For the two that count (twenty failed logins, seven distinct 404s) a
/// day is the span over which those numbers were chosen: a scanner that
/// works through a wordlist does it in minutes, and one that spreads the
/// same attempts over longer than a day is no longer an attack in
/// progress. For the ones a single line convicts, the window only says how
/// old that line may be, and a day is the longest a scan is worth
/// answering after the fact. It is also no longer than any of their block
/// lengths (see each `ttl_days_default`), so a block always outlives the
/// evidence that made it.
pub const EVIDENCE_WINDOW_HOURS: i64 = 24;

/// How far back the behavioural detectors look: an hour.
///
/// Each counts *distinct* things a browser also produces, just fewer of
/// them (pages, user agents, deep pages without a referer), so the window
/// is what separates a crawl from a visitor. Twenty pages in an hour with
/// no stylesheet is a scraper; twenty pages over a week of bookmarks is a
/// regular reader. The household that reached eight user agents in a day
/// (see `ROTATING_UA_MIN`) is the same argument for the rotating one.
pub const BEHAVIOURAL_WINDOW_HOURS: i64 = 1;

/// The longest window a detector may be given: thirty days. Longer brings
/// back what windows replaced, a count over everything ever seen.
pub const MAX_WINDOW_HOURS: i64 = 30 * 24;

/// One day, matching `run-detector web-scanners` rather than `run-detector ssh-scanners`'
/// five. The failure mode worth designing against is a crawler operator
/// adding a range faster than the daily `UpdateIpRanges` job picks it up:
/// a real Googlebot address could then be blocked for as long as the TTL.
/// A short TTL bounds that to a day, and a genuine impersonator gets
/// re-flagged on its very next request anyway.
pub const SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT: i64 = 1;

/// `settings` key: extra probe paths, one per line, appended to
/// [`crate::accesslog::DEFAULT_PROBE_PATHS`].
pub const PROBE_PATHS_EXTRA: &str = keys::DETECT_PROBE_PATHS_EXTRA;

/// Probe-path detection defaults to **on**. The built-in list is chosen
/// strictly enough that a single request to any of them is conclusive (see
/// `accesslog::DEFAULT_PROBE_PATHS` — deliberately *not* including
/// `/wp-login.php` and friends, which real administrators use), so unlike
/// a threshold there is nothing to tune wrong.
pub const PROBE_PATHS_ENABLED_DEFAULT: bool = true;

/// Five days, matching `run-detector ssh-scanners` rather than the one day
/// spoofed-crawler detection uses. The difference is who can be caught by
/// mistake: a mis-detected crawler is a real service you want back
/// quickly, whereas anything requesting `/.env` has no legitimate business
/// here at all, so there's no reason to hurry it back.
pub const PROBE_PATHS_TTL_DAYS_DEFAULT: i64 = 5;

/// Injection detection defaults to **on**, for the reason probe paths do:
/// one request is conclusive, so there is no threshold to tune wrong. A
/// signature that plain text could produce counts only where no person
/// types it — see `crate::injection` for the two strengths, and for the
/// five months of real traffic they were checked against.
pub const INJECTION_ENABLED_DEFAULT: bool = true;

/// Seven days: longer than a probe path's five, because a payload is an
/// attack in progress rather than reconnaissance, and shorter than the
/// honeypot's thirty, which is the one signal that cannot be an accident.
pub const INJECTION_TTL_DAYS_DEFAULT: i64 = 7;

/// Protocol probes default to **on**, for the reason injection does: one
/// request is conclusive, and what is counted is not HTTP at all, or HTTP
/// asking to be forwarded elsewhere. See `crate::protocol` for what is
/// never counted, and the two hosts' logs it was checked against.
pub const PROTOCOL_PROBES_ENABLED_DEFAULT: bool = true;

/// Five days, a probe path's: both are a scanner looking for something to
/// attack, not an attack.
pub const PROTOCOL_PROBES_TTL_DAYS_DEFAULT: i64 = 5;

/// The defaults generation the protocol-probe detector arrived in (see
/// `db::schema::DEFAULTS_GENERATION`): on a database an earlier release
/// created it is off, and marked new, until the operator chooses.
pub const PROTOCOL_PROBES_INTRODUCED_IN: u32 = 4;

/// robots.txt violators default to **off**, for the reason the honeypot
/// does: it judges by the robots.txt this project generates, and does
/// nothing until that is served, so on by default it would be an enabled
/// detector that cannot fire. And because a person can read robots.txt
/// too, and then open what it forbids, out of curiosity.
pub const ROBOTS_VIOLATORS_ENABLED_DEFAULT: bool = false;

/// Seven days: shorter than the honeypot's thirty, since what a page
/// forbids is read from a file here rather than being a path that exists
/// for no other reason, and as long as an injection's, since a crawler
/// that ignored the rules once will again.
pub const ROBOTS_VIOLATORS_TTL_DAYS_DEFAULT: i64 = 7;

/// The robots.txt the robots.txt-violator detector judges by: the one this
/// project generates, when it is served, and otherwise none.
///
/// **Only the generated one**, because it is the only one whose rules are
/// known to be what clients were sent. Every site gets it, from the same
/// `location = /robots.txt` (or Apache rewrite), so it does not matter
/// that the combined log format does not say which site a request was
/// for. A `robots.txt` in a site's document root can be shadowed by a
/// `location`, served by the application behind a proxy instead, or
/// differ from one site to the next; reading it would judge clients by
/// rules they may never have seen. Fetching each site's over localhost
/// would know what is served, but it is a network request from a detector
/// that runs every minute, through TLS and virtual hosts, and no test
/// here may touch the network.
pub fn robots_rules(db: &Db) -> Result<Option<crate::robots::Robots>> {
    if !db.get_serve_robots_txt()? {
        return Ok(None);
    }
    let body = crate::webserver::robots_txt_body(db)?;
    Ok(Some(crate::robots::Robots::parse(&body)))
}

/// Every extra probe path configured on top of the built-in list: the
/// `PROBE_PATHS_EXTRA` setting split on newlines, with blank lines and
/// `#` comments dropped so an admin can annotate the list.
///
/// [`crate::accesslog::probe_path_ips`] looks for each anywhere in the
/// request path, and the leading `/` is what keeps that to the start of a
/// path segment, so an entry without one is skipped: a bare `env` would
/// match every word ending in it. So is one that is nothing but slashes,
/// which every request contains: one `/` among the extra paths would have
/// blocked every visitor for five days.
pub fn extra_probe_paths(db: &Db) -> Result<Vec<String>> {
    let raw = db.get_text_setting(PROBE_PATHS_EXTRA)?.unwrap_or_default();
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| line.starts_with('/') && !line.trim_matches('/').is_empty())
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

/// `settings` key: whether the probe-paths detector also counts the paths
/// of applications this host does not run, such as `/wp-login.php` where
/// no site is WordPress (see [`crate::webapps`]).
pub const APP_PROBE_PATHS: &str = keys::DETECT_PROBE_PATHS_APP_AWARE;

/// The defaults generation app-aware probe paths arrived in (see
/// `db::schema::DEFAULTS_GENERATION`). On by default on a database created
/// at this generation or later; off, and marked new, on one created
/// before, until the operator chooses: it makes an existing detector block
/// more, and an upgrade never does that by itself.
pub const APP_PROBE_PATHS_INTRODUCED_IN: u32 = 3;

// A generation this binary creates, or it would be on nowhere; and a later
// one than repeat offenders', or every database from 0.3.0 would have it on.
const _: () = assert!(
    APP_PROBE_PATHS_INTRODUCED_IN > REPEAT_ESCALATION_INTRODUCED_IN
        && APP_PROBE_PATHS_INTRODUCED_IN <= crate::db::schema::DEFAULTS_GENERATION
);

/// Whether the probe-paths detector counts absent applications' paths:
/// the stored switch, or, where nobody has switched it, whether the
/// database is new enough to have it by default.
pub fn app_probe_paths(db: &Db) -> Result<bool> {
    Ok(match db.get_bool_setting_if_set(APP_PROBE_PATHS)? {
        Some(chosen) => chosen,
        None => APP_PROBE_PATHS_INTRODUCED_IN <= db.defaults_generation()?,
    })
}

/// Whether app-aware probe paths arrived after this database was created
/// and nobody has chosen either way: off, and marked "new" the way a new
/// detector is (see [`Detector::is_new_here`]).
pub fn app_probe_paths_is_new_here(db: &Db) -> Result<bool> {
    Ok(APP_PROBE_PATHS_INTRODUCED_IN > db.defaults_generation()?
        && db.get_bool_setting_if_set(APP_PROBE_PATHS)?.is_none())
}

pub fn set_app_probe_paths(db: &Db, enabled: bool) -> Result<()> {
    db.set_bool_setting(APP_PROBE_PATHS, enabled)
}

/// What app-aware probe paths do, in one sentence, for the CLI and the
/// Dashboard.
pub fn app_probe_paths_summary() -> String {
    format!(
        "{} also count as probes where no site runs the application they belong to",
        crate::webapps::conditional_paths()
            .iter()
            .map(|path| format!("/{path}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// `settings` key: the trap path itself.
pub const HONEYPOT_PATH: &str = keys::DETECT_HONEYPOT_PATH;

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

/// The configured trap path, falling back to [`HONEYPOT_PATH_DEFAULT`]
/// for a stored value [`validate_honeypot_path`] would refuse — one
/// written by hand or by an older version, which never checked more than
/// the leading `/`.
pub fn honeypot_path(db: &Db) -> Result<String> {
    Ok(db
        .get_text_setting(HONEYPOT_PATH)?
        .and_then(|p| validate_honeypot_path(&p).ok())
        .unwrap_or_else(|| HONEYPOT_PATH_DEFAULT.to_string()))
}

/// `path` trimmed, if it is usable as the trap path, or why not.
///
/// - **It must start with `/`.** Matching is anchored at the start of the
///   request path, so anything else could never fire and would leave the
///   detector looking switched on while doing nothing.
/// - **It must name something below `/`.** `/` is the start of every
///   request path: every visitor would be blocked for thirty days, and
///   robots.txt would disallow the whole site.
/// - **Only characters a URL path spells literally.** The path is
///   published as one `Disallow:` line of the generated robots.txt. Trim
///   only reached the ends, so a newline in the middle ended that line and
///   whatever followed became robots.txt of its own; `#` starts a comment
///   there, and `*` and `$` are wildcards to the crawlers that read it.
pub fn validate_honeypot_path(path: &str) -> Result<String> {
    let path = path.trim();
    if !path.starts_with('/') {
        anyhow::bail!("the honeypot path must start with '/' (got {path:?})");
    }
    if path.trim_matches('/').is_empty() {
        anyhow::bail!(
            "the honeypot path must name something below '/', which every request starts \
             with (got {path:?})"
        );
    }
    if let Some(c) = path.chars().find(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '.' | '_' | '~' | '%' | '+' | '@'))
    }) {
        anyhow::bail!("the honeypot path cannot contain {c:?} (got {path:?})");
    }
    Ok(path.to_string())
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
    Injection,
    Honeypot,
    AssetRatio,
    RotatingUserAgent,
    RefererlessCrawl,
    /// Only ever on under "humans only" — see [`Detector::is_enabled`].
    RobotsTxt,
    LoginAttempts,
    RequestRate,
    RobotsViolators,
    /// Another protocol spoken to the web server, or the web server asked
    /// to be a proxy: see [`crate::protocol`].
    ProtocolProbes,
    /// Reads the kernel log the firewall's trap ports write: see
    /// [`crate::portscan`].
    PortScanners,
}

/// The log a detector reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorLog {
    /// The web server's access log.
    Access,
    /// sshd's authentication lines.
    Ssh,
    /// The kernel log, for the lines the firewall's trap ports write.
    Kernel,
}

impl DetectorLog {
    /// What a report calls it.
    pub fn name(self) -> &'static str {
        match self {
            DetectorLog::Access => "access log",
            DetectorLog::Ssh => "SSH log",
            DetectorLog::Kernel => "kernel log",
        }
    }
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
    /// How far back evidence counts, in hours: a line older than this is
    /// no longer a reason to block. See [`Detector::window_hours`].
    pub window_hours_default: i64,
    /// Which log this detector's evidence comes from.
    pub log: DetectorLog,
    /// The defaults generation this detector arrived in (see
    /// `db::schema::DEFAULTS_GENERATION`). On a database created in an
    /// earlier one it is off until the operator turns it on, whatever
    /// `enabled_default` says: an upgrade never starts blocking by itself.
    /// Every detector that existed at 0.1 is generation 1.
    pub introduced_in: u32,
}

impl Detector {
    pub const ALL: [Detector; 15] = [
        Detector::SshScanners,
        Detector::WebScanners,
        Detector::SpoofedCrawlers,
        Detector::ProbePaths,
        Detector::Injection,
        Detector::ProtocolProbes,
        Detector::Honeypot,
        Detector::AssetRatio,
        Detector::RotatingUserAgent,
        Detector::RefererlessCrawl,
        Detector::RobotsTxt,
        Detector::LoginAttempts,
        Detector::RequestRate,
        Detector::RobotsViolators,
        Detector::PortScanners,
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
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Ssh,
                introduced_in: 1,
            },
            Detector::WebScanners => DetectorSpec {
                id: "block_web_scanners",
                label: "Web scanners",
                job_label: "Block web scanners",
                enabled_default: true,
                ttl_days_default: 1,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::SpoofedCrawlers => DetectorSpec {
                id: "block_spoofed_crawlers",
                label: "Forged crawler UAs",
                job_label: "Block forged crawler UAs",
                enabled_default: SPOOFED_CRAWLERS_ENABLED_DEFAULT,
                ttl_days_default: SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::ProbePaths => DetectorSpec {
                id: "block_probe_paths",
                label: "Probe paths",
                job_label: "Block probe paths",
                enabled_default: PROBE_PATHS_ENABLED_DEFAULT,
                ttl_days_default: PROBE_PATHS_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::Injection => DetectorSpec {
                id: "block_injection",
                label: "Injection attempts",
                job_label: "Block injection attempts",
                enabled_default: INJECTION_ENABLED_DEFAULT,
                ttl_days_default: INJECTION_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
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
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::Honeypot => DetectorSpec {
                id: "block_honeypot",
                label: "Honeypot path",
                job_label: "Block honeypot hits",
                enabled_default: HONEYPOT_ENABLED_DEFAULT,
                ttl_days_default: HONEYPOT_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
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
                window_hours_default: BEHAVIOURAL_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::RotatingUserAgent => DetectorSpec {
                id: "block_rotating_ua",
                label: "Rotating user agent",
                job_label: "Block rotating user agents",
                enabled_default: false,
                ttl_days_default: 5,
                window_hours_default: BEHAVIOURAL_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            Detector::RefererlessCrawl => DetectorSpec {
                id: "block_refererless",
                label: "Crawls with no referer",
                job_label: "Block referer-less crawling",
                enabled_default: false,
                ttl_days_default: 5,
                window_hours_default: BEHAVIOURAL_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: 1,
            },
            // Detectors from here on arrived after 0.3: off on a database
            // an earlier release created, whatever `enabled_default` says.
            Detector::LoginAttempts => DetectorSpec {
                id: "block_login_attempts",
                label: "Login brute force",
                job_label: "Block login brute force",
                enabled_default: LOGIN_ATTEMPTS_ENABLED_DEFAULT,
                ttl_days_default: LOGIN_ATTEMPTS_TTL_DAYS_DEFAULT,
                window_hours_default: LOGIN_ATTEMPTS_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: MORE_DETECTORS_INTRODUCED_IN,
            },
            Detector::RequestRate => DetectorSpec {
                id: "block_request_rate",
                label: "Request rate",
                job_label: "Block high request rates",
                enabled_default: REQUEST_RATE_ENABLED_DEFAULT,
                ttl_days_default: REQUEST_RATE_TTL_DAYS_DEFAULT,
                window_hours_default: REQUEST_RATE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: MORE_DETECTORS_INTRODUCED_IN,
            },
            Detector::RobotsViolators => DetectorSpec {
                id: "block_robots_violators",
                label: "robots.txt violators",
                job_label: "Block robots.txt violators",
                enabled_default: ROBOTS_VIOLATORS_ENABLED_DEFAULT,
                ttl_days_default: ROBOTS_VIOLATORS_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: MORE_DETECTORS_INTRODUCED_IN,
            },
            Detector::ProtocolProbes => DetectorSpec {
                id: "block_protocol_probes",
                label: "Protocol probes",
                job_label: "Block protocol probes",
                enabled_default: PROTOCOL_PROBES_ENABLED_DEFAULT,
                ttl_days_default: PROTOCOL_PROBES_TTL_DAYS_DEFAULT,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Access,
                introduced_in: PROTOCOL_PROBES_INTRODUCED_IN,
            },
            // Off by default, new database or old: it adds rules to the
            // firewall for ports beyond the web server and SSH, and a
            // service started on one of them after a render is dropped
            // until the next apply. See `crate::portscan`.
            Detector::PortScanners => DetectorSpec {
                id: "block_port_scanners",
                label: "Port scanners",
                job_label: "Block port scanners",
                enabled_default: false,
                ttl_days_default: 5,
                window_hours_default: EVIDENCE_WINDOW_HOURS,
                log: DetectorLog::Kernel,
                introduced_in: 3,
            },
        }
    }

    pub fn id(self) -> &'static str {
        self.spec().id
    }

    /// What this detector blocks, in a sentence or two, for someone who
    /// has not read the code: the TUI's `?` shows it.
    pub fn about(self) -> &'static str {
        match self {
            Detector::SshScanners => {
                "Blocks an address after many failed SSH logins: the password-guessing that \
                 every server on the internet gets. An address that ever logged in \
                 successfully is never blocked."
            }
            Detector::WebScanners => {
                "Blocks an address that asks for many different pages that do not exist \
                 (404s): a scanner walking a list of known-vulnerable paths."
            }
            Detector::SpoofedCrawlers => {
                "Blocks a client that calls itself Googlebot, Bingbot or GPTBot from an address \
                 that crawler does not use. The real crawlers publish their addresses, and \
                 the Crawler IP ranges panel downloads them."
            }
            Detector::ProbePaths => {
                "Blocks an address on a single request for a file no visitor asks for, such as \
                 /.env or /.git/config: someone looking for leaked passwords and keys. With \
                 \"Probes for absent apps\" on, also /wp-login.php, /phpmyadmin and the like, \
                 where no site here runs WordPress or phpMyAdmin."
            }
            Detector::Injection => {
                "Blocks an address on a single request carrying a known exploit, such as \
                 Shellshock or Log4Shell, in its path or headers."
            }
            Detector::ProtocolProbes => {
                "Blocks an address on a single request that is not for a web page: another \
                 protocol's handshake (TLS on the plain-HTTP port, SOCKS, SSH), or a request \
                 asking this server to forward it somewhere else, as a proxy would. Scanners \
                 looking for open proxies and other services send these; browsers never do. \
                 An address the site also answered normally is left alone."
            }
            Detector::Honeypot => {
                "Blocks a client that visits a trap path that only robots.txt mentions, as a \
                 path crawlers must not visit. People never see it; a bot that reads \
                 robots.txt for places to look does."
            }
            Detector::AssetRatio => {
                "Blocks an address that fetches many pages and never a stylesheet, script or \
                 image: a browser loads those, a scraper does not."
            }
            Detector::RotatingUserAgent => {
                "Blocks an address that sends many different user agents in a short time: a \
                 bot changing disguises to get past user-agent blocks."
            }
            Detector::RefererlessCrawl => {
                "Blocks an address that requests many deep pages and never sends a Referer, \
                 which a person clicking links does."
            }
            Detector::RobotsTxt => {
                "Under Humans only: blocks a client that fetches robots.txt. People do not ask \
                 for it; crawlers do."
            }
            Detector::LoginAttempts => {
                "Blocks an address that sends many login attempts in a short time: POST \
                 requests to a login page such as /wp-login.php, /xmlrpc.php or /user/login. \
                 That is password guessing, and a login that succeeds in the end does not \
                 excuse it."
            }
            Detector::RequestRate => {
                "Blocks an address that keeps up more requests a minute than its threshold \
                 for the whole window, or that NGINX's own rate limit has refused (429) a \
                 hundred times in it. Rate limiting in the web server slows a client down; \
                 this shuts it out. On Apache, which has no rate limiting here, it is the only \
                 defence against a flood."
            }
            Detector::RobotsViolators => {
                "Blocks a client that fetched robots.txt and then a page it forbids to that \
                 client: a crawler that read the rules and ignored them. The honeypot's trap \
                 path is one such page; a bot that robots.txt shuts out altogether asking for \
                 anything at all is another."
            }
            Detector::PortScanners => {
                "Protects the whole host, not only the web server and SSH. The firewall drops \
                 and logs new connections to trap ports: ports scanners try and a web host \
                 does not serve, such as telnet, SMB, RDP and the default database ports. An \
                 address that tries two of them is blocked from every port. Nothing that \
                 listens when the firewall is rendered is ever a trap port, and neither are \
                 22, 80, 443 or sshd's port."
            }
        }
    }

    /// Who this detector might block by mistake, when that is a real
    /// risk; `None` when what it looks for is an attack and nothing else.
    pub fn risk(self) -> Option<&'static str> {
        match self {
            Detector::AssetRatio => Some(
                "Can catch real people: a reader with images off, a text browser, or a feed \
                 reader. Off by default for that reason. It never blocks a verified search \
                 engine.",
            ),
            Detector::RotatingUserAgent => Some(
                "Can catch real people: an office or school behind one shared address, where \
                 many browsers look like one client. Off by default for that reason. It never \
                 blocks a verified search engine.",
            ),
            Detector::RefererlessCrawl => Some(
                "Can catch real people: privacy tools and some browsers send no Referer at \
                 all. Off by default for that reason. It never blocks a verified search \
                 engine.",
            ),
            Detector::Honeypot => Some(
                "Does nothing until the site serves the generated robots.txt (a setting on the \
                 web server's screen), which is where the trap path is published.",
            ),
            Detector::SpoofedCrawlers => Some(
                "Needs the crawler ranges downloaded; until they are, it cannot tell a real \
                 Googlebot from a forged one and blocks neither.",
            ),
            Detector::LoginAttempts => Some(
                "Can catch an office or school behind one shared address whose people all log \
                 in within the hour, and a program that posts to /xmlrpc.php often, such as \
                 the WordPress app or Jetpack. Twenty attempts an hour is far more than one \
                 person makes. It never blocks a trusted address, one that logged in over SSH, \
                 or a verified search engine.",
            ),
            Detector::RequestRate => Some(
                "Can catch many people behind one shared address, such as an office, a school \
                 or a mobile carrier, and a proxy or monitoring service that fetches a lot. \
                 Off by default for that reason, with a high threshold. What an application \
                 recognised behind a site fetches on its own data routes does not count, and \
                 it never blocks a trusted address or a verified search engine.",
            ),
            Detector::RobotsViolators => Some(
                "Does nothing until the site serves the generated robots.txt (a setting on the \
                 web server's screen), the only one it knows the rules of. A person who reads \
                 robots.txt and then opens a page it forbids by hand is blocked too. It never \
                 blocks a verified search engine.",
            ),
            Detector::ProtocolProbes => Some(
                "If a site's TLS is misconfigured, so that the port visitors reach for HTTPS \
                 answers plain HTTP, every visitor's browser sends a TLS handshake there, and \
                 one that arrives by a link, without first being redirected from http://, is \
                 blocked. Such a site serves nobody until it is fixed; the blocks last after it.",
            ),
            Detector::PortScanners => Some(
                "A service you start later on a trap port is dropped until the firewall is \
                 rendered and applied again, which leaves it out. Choose the ports with \
                 `set-detector port-scanners --ports`. Needs the kernel log readable \
                 (kern.log, or the journal) and `ss` to see what listens. What it counts is \
                 a first packet, which proves nothing about its sender: someone who can send \
                 packets with a forged source can have that address blocked. It never blocks \
                 a trusted address, one that logged in over SSH, or a verified search engine.",
            ),
            Detector::ProbePaths | Detector::Injection => Some(
                "One request is enough, and a web page can make a visitor's browser send one: \
                 an image whose address is /.env, on a page or in a mail someone else wrote, \
                 gets the person who opens it blocked from this server. Nothing in an access \
                 log tells that request from a scanner's. Trust the addresses that must never \
                 be blocked. It never blocks a trusted address, one that logged in over SSH, \
                 or a verified search engine.",
            ),
            _ => None,
        }
    }

    pub fn from_id(id: &str) -> Option<Detector> {
        Detector::ALL.into_iter().find(|d| d.id() == id)
    }

    /// `settings` key for this detector's on/off switch.
    pub fn enabled_key(self) -> String {
        keys::detector_enabled(self.id())
    }

    /// `settings` key for its block TTL, in days.
    pub fn ttl_key(self) -> String {
        keys::detector_ttl_days(self.id())
    }

    /// Whether this detector runs.
    ///
    /// [`Detector::RobotsTxt`] does not answer from its own setting: it is
    /// owned by the humans-only switch, on when that is on and off when it
    /// is not. A stored toggle would be a second place to say the same
    /// thing, and the two would disagree — which on this detector means
    /// either a day-long block per crawler on a host that never asked for
    /// one, or the mode's sharpest rule quietly not running.
    ///
    /// Every other detector answers from its switch, and a detector nobody
    /// has switched follows [`enabled_by_default`]: its spec's default,
    /// unless it arrived after this database was created.
    pub fn is_enabled(self, db: &Db) -> Result<bool> {
        if self == Detector::RobotsTxt {
            return db.get_humans_only();
        }
        Ok(match db.get_bool_setting_if_set(&self.enabled_key())? {
            Some(chosen) => chosen,
            None => enabled_by_default(&self.spec(), db.defaults_generation()?),
        })
    }

    /// Whether this detector arrived after the database was created and
    /// nobody has switched it on or off since: the UIs mark it "new", so an
    /// operator learns it exists. It is off, by [`enabled_by_default`].
    /// Choosing either way clears the mark.
    pub fn is_new_here(self, db: &Db) -> Result<bool> {
        Ok(self.is_operator_controlled()
            && self.spec().introduced_in > db.defaults_generation()?
            && db.get_bool_setting_if_set(&self.enabled_key())?.is_none())
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

    /// `settings` key for its evidence window, in hours.
    pub fn window_key(self) -> String {
        keys::detector_window_hours(self.id())
    }

    /// How far back this detector's evidence counts, in hours: the stored
    /// value, or the spec's default. A value outside one hour to
    /// [`MAX_WINDOW_HOURS`] (written by hand) reads as the default, since
    /// a zero window would switch the detector off without saying so and
    /// a huge one would bring back the whole-log counting this replaced.
    pub fn window_hours(self, db: &Db) -> Result<i64> {
        let default = self.spec().window_hours_default;
        let hours = db.get_int_setting(&self.window_key(), default)?;
        Ok(if (1..=MAX_WINDOW_HOURS).contains(&hours) {
            hours
        } else {
            default
        })
    }

    /// [`Self::window_hours`] in seconds.
    pub fn window_seconds(self, db: &Db) -> Result<i64> {
        Ok(self.window_hours(db)? * 3600)
    }

    /// Refuses anything outside one hour to [`MAX_WINDOW_HOURS`].
    pub fn set_window_hours(self, db: &Db, hours: i64) -> Result<()> {
        if !(1..=MAX_WINDOW_HOURS).contains(&hours) {
            anyhow::bail!("a detection window is from 1 to {MAX_WINDOW_HOURS} hours, not {hours}");
        }
        db.set_int_setting(&self.window_key(), hours)
    }

    pub fn set_enabled(self, db: &Db, enabled: bool) -> Result<()> {
        db.set_bool_setting(&self.enabled_key(), enabled)
    }

    /// Refuses anything outside one day to [`MAX_TTL_DAYS`], so no front-end
    /// can store a TTL the block arithmetic cannot carry.
    pub fn set_ttl_days(self, db: &Db, days: i64) -> Result<()> {
        if !(1..=MAX_TTL_DAYS).contains(&days) {
            anyhow::bail!("a block lasts from 1 to {MAX_TTL_DAYS} days, not {days}");
        }
        db.set_int_setting(&self.ttl_key(), days)
    }

    /// The `settings` key and default of this detector's threshold, for the
    /// ones that count something. `None` for the ones where a single
    /// request is conclusive, which have nothing to tune.
    ///
    /// The three behavioural keys predate this and keep their names; the
    /// two scanner keys are new and follow them.
    pub fn threshold_setting(self) -> Option<(&'static str, i64)> {
        match self {
            Detector::SshScanners => {
                Some((SSH_SCANNERS_MIN_ATTEMPTS, SSH_SCANNERS_MIN_ATTEMPTS_DEFAULT))
            }
            Detector::WebScanners => Some((WEB_SCANNERS_MIN_PATHS, WEB_SCANNERS_MIN_PATHS_DEFAULT)),
            Detector::AssetRatio => Some((ASSET_RATIO_MIN_PAGES, ASSET_RATIO_MIN_PAGES_DEFAULT)),
            Detector::RotatingUserAgent => Some((ROTATING_UA_MIN, ROTATING_UA_MIN_DEFAULT)),
            Detector::RefererlessCrawl => {
                Some((REFERERLESS_MIN_PATHS, REFERERLESS_MIN_PATHS_DEFAULT))
            }
            Detector::LoginAttempts => Some((LOGIN_ATTEMPTS_MIN, LOGIN_ATTEMPTS_MIN_DEFAULT)),
            Detector::RequestRate => {
                Some((REQUEST_RATE_PER_MINUTE, REQUEST_RATE_PER_MINUTE_DEFAULT))
            }
            Detector::PortScanners => {
                Some((PORT_SCANNERS_MIN_PORTS, PORT_SCANNERS_MIN_PORTS_DEFAULT))
            }
            Detector::SpoofedCrawlers
            | Detector::ProbePaths
            | Detector::Injection
            | Detector::ProtocolProbes
            | Detector::Honeypot
            | Detector::RobotsTxt
            | Detector::RobotsViolators => None,
        }
    }

    /// The threshold this detector runs with, floored at [`MIN_THRESHOLD`]
    /// (see [`threshold`]), or `None` if it has none.
    pub fn threshold(self, db: &Db) -> Result<Option<usize>> {
        self.threshold_setting()
            .map(|(key, default)| threshold(db, key, default))
            .transpose()
    }

    /// Stores a threshold, refusing one under [`MIN_THRESHOLD`] rather than
    /// storing a value the read would silently raise.
    pub fn set_threshold(self, db: &Db, value: i64) -> Result<()> {
        let Some((key, _)) = self.threshold_setting() else {
            anyhow::bail!(
                "{} has no threshold: one matching request is already conclusive",
                self.spec().label
            );
        };
        if value < MIN_THRESHOLD {
            anyhow::bail!(
                "a threshold under {MIN_THRESHOLD} matches every address in the log, whatever it \
                 did (got {value})"
            );
        }
        db.set_int_setting(key, value)
    }
}

/// Whether a detector nobody has switched on or off runs, on a database
/// created at defaults generation `created_at`.
///
/// This is the whole upgrade policy for detectors. Before 0.1 a detector
/// ran whenever its spec said so, which is how 0.0.15 turned its injection
/// detector on for every existing install. Now a detector newer than the
/// database is off until someone turns it on; the ones that were already
/// there keep the defaults they always had.
pub fn enabled_by_default(spec: &DetectorSpec, created_at: u32) -> bool {
    spec.enabled_default && spec.introduced_in <= created_at
}

/// Threshold for the SSH scanner detector: failed-authentication lines
/// from one address. Twenty, which a person mistyping a password never
/// reaches and a brute-forcer passes in seconds.
pub const SSH_SCANNERS_MIN_ATTEMPTS: &str = keys::DETECT_SSH_SCANNERS_MIN_ATTEMPTS;
pub const SSH_SCANNERS_MIN_ATTEMPTS_DEFAULT: i64 = 20;

/// Threshold for the web scanner detector: *distinct* paths answered 404
/// for one address. A visitor following a dead link produces one.
pub const WEB_SCANNERS_MIN_PATHS: &str = keys::DETECT_WEB_SCANNERS_MIN_PATHS;
pub const WEB_SCANNERS_MIN_PATHS_DEFAULT: i64 = 7;

/// How many times one missing page convicts an address, inside the
/// web-scanner window, however few distinct ones it asked for. Found by a
/// replay of a real host's logs: a camera-firmware probe asked for one
/// path about 140 times a day, and never reached seven distinct ones. A
/// person who follows a broken link, or reloads it, does not get near
/// fifty; assets, which a browser does ask for again on every page, are
/// not counted (see [`crate::evidence::Rule::DistinctOrRepeated`]).
pub const WEB_SCANNERS_REPEATS: u64 = 50;

/// `settings` key: whether a detector that flags several addresses in one
/// IPv4 `/24` blocks the whole `/24` instead.
pub const SUBNET_ESCALATION: &str = keys::DETECT_SUBNET_ESCALATION;
pub const SUBNET_ESCALATION_DEFAULT: bool = false;

/// How many addresses in one `/24` must be flagged in a single pass
/// before it escalates.
pub const SUBNET_ESCALATION_MIN: &str = keys::DETECT_SUBNET_ESCALATION_MIN;
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
/// The floor is at the read as well as at the one write,
/// [`Detector::set_threshold`] (`stop-bots set-detector --threshold`),
/// because a value can also arrive by hand, with `sqlite3`, or from a
/// database written before that check existed. The read is the only place
/// that sees every caller.
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
    Ok(Some(subnet_escalation_min(db)?))
}

/// The escalation threshold, whether or not escalation is on — for a
/// front-end showing what switching it on would do.
pub fn subnet_escalation_min(db: &Db) -> Result<usize> {
    threshold(db, SUBNET_ESCALATION_MIN, SUBNET_ESCALATION_MIN_DEFAULT)
}

/// Switches `/24` escalation and sets its threshold; `None` leaves either
/// as it is. The threshold is refused under [`MIN_THRESHOLD`] for the
/// reason [`Detector::set_threshold`] refuses one: at one, a single
/// flagged address would block its whole `/24`.
pub fn set_subnet_escalation(db: &Db, enabled: Option<bool>, min: Option<i64>) -> Result<()> {
    if let Some(min) = min {
        if min < MIN_THRESHOLD {
            anyhow::bail!(
                "escalating on fewer than {MIN_THRESHOLD} addresses would block a /24 for one \
                 address's behaviour (got {min})"
            );
        }
        db.set_int_setting(SUBNET_ESCALATION_MIN, min)?;
    }
    if let Some(enabled) = enabled {
        db.set_bool_setting(SUBNET_ESCALATION, enabled)?;
    }
    Ok(())
}

// ---- repeat offenders ----
//
// Every constant of the escalation is here, and so is the arithmetic: the
// detectors only ask [`escalated_ttl_days`] how long this offence earns.

/// `settings` key: whether a detector blocks an address it blocked before
/// for longer than the first time.
pub const REPEAT_ESCALATION: &str = keys::DETECT_REPEAT_OFFENDERS;

/// The defaults generation escalation arrived in (see
/// `db::schema::DEFAULTS_GENERATION`). On by default on a database created
/// at this generation or later; off, and marked new, on one created
/// before, until the operator chooses: an upgrade never makes a block
/// longer by itself.
pub const REPEAT_ESCALATION_INTRODUCED_IN: u32 = 2;

// A generation this binary creates, or escalation would be on nowhere; and
// a later one than 0.1's, or every upgraded database would have it on.
const _: () = assert!(
    REPEAT_ESCALATION_INTRODUCED_IN > 1
        && REPEAT_ESCALATION_INTRODUCED_IN <= crate::db::schema::DEFAULTS_GENERATION
);

/// The most a repeat offence multiplies a detector's TTL by: the fourth
/// offence and every one after it. Doubling, fail2ban's
/// `bantime.increment` shape, so the second block is twice the first and
/// a scanner that comes back as soon as each block ends spends
/// 1 + 2 + 4 + 8 = 15 times the TTL blocked over its first four.
pub const ESCALATION_MAX_MULTIPLIER: i64 = 8;

/// The longest an escalated block lasts: ninety days, whatever the
/// detector and the offence. The honeypot's thirty days would otherwise
/// reach eight months, and an address held that long has as likely
/// changed hands. A detector whose own TTL is longer keeps it: escalation
/// only ever lengthens a block.
pub const ESCALATION_MAX_DAYS: i64 = 90;

/// How long an address must stay out of trouble before its offences are
/// forgotten: thirty days after its last block *ended*, not after it
/// began, so a ninety-day block does not wipe the record it was made from.
pub const OFFENCE_MEMORY_DAYS: i64 = 30;

/// [`OFFENCE_MEMORY_DAYS`] in seconds.
pub const OFFENCE_MEMORY_SECONDS: i64 = OFFENCE_MEMORY_DAYS * 86_400;

/// How long the `offence`th block of an address lasts, for a detector
/// whose TTL is `ttl_days`: `ttl_days × 2^(offence − 1)`, the multiplier
/// capped at [`ESCALATION_MAX_MULTIPLIER`] and the result at
/// [`ESCALATION_MAX_DAYS`] (or at `ttl_days`, if that is longer). The
/// first offence, and an offence of 0, which no caller passes, are
/// `ttl_days` unchanged.
pub fn escalated_ttl_days(ttl_days: i64, offence: u32) -> i64 {
    let doublings = offence
        .saturating_sub(1)
        .min(ESCALATION_MAX_MULTIPLIER.ilog2());
    let multiplier = 1i64 << doublings;
    ttl_days
        .saturating_mul(multiplier)
        .min(ESCALATION_MAX_DAYS.max(ttl_days))
}

/// Whether repeat offenders are blocked for longer: the stored switch,
/// or, on a database nobody has switched it on, whether the database is
/// new enough to have it by default (see
/// [`REPEAT_ESCALATION_INTRODUCED_IN`]).
pub fn repeat_escalation(db: &Db) -> Result<bool> {
    Ok(match db.get_bool_setting_if_set(REPEAT_ESCALATION)? {
        Some(chosen) => chosen,
        None => REPEAT_ESCALATION_INTRODUCED_IN <= db.defaults_generation()?,
    })
}

/// Whether escalation arrived after this database was created and nobody
/// has chosen either way: off, and marked "new" the way a new detector is
/// (see [`Detector::is_new_here`]).
pub fn repeat_escalation_is_new_here(db: &Db) -> Result<bool> {
    Ok(REPEAT_ESCALATION_INTRODUCED_IN > db.defaults_generation()?
        && db.get_bool_setting_if_set(REPEAT_ESCALATION)?.is_none())
}

pub fn set_repeat_escalation(db: &Db, enabled: bool) -> Result<()> {
    db.set_bool_setting(REPEAT_ESCALATION, enabled)
}

/// What escalation does, in one sentence, for the CLI and the Dashboard.
pub fn repeat_escalation_summary() -> String {
    format!(
        "each new block of an address doubles its detector's TTL, up to \
         {ESCALATION_MAX_MULTIPLIER}x and {ESCALATION_MAX_DAYS} days; forgotten \
         {OFFENCE_MEMORY_DAYS} days after its last block ends"
    )
}

/// "2nd", "3rd", "11th": an offence count as people say it.
pub fn ordinal(n: u32) -> String {
    let suffix = match (n % 10, n % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

/// Threshold for the port-scan detector: *distinct* trap ports one
/// address tried. Two: one connection to one port can be a client with
/// the wrong address or a typo; trying a second port nobody serves is
/// looking for whatever answers.
pub const PORT_SCANNERS_MIN_PORTS: &str = keys::DETECT_PORT_SCANNERS_MIN_PORTS;
pub const PORT_SCANNERS_MIN_PORTS_DEFAULT: i64 = 2;

/// Threshold for the asset-ratio detector: distinct successful page URLs
/// fetched with no accompanying asset. High, and *distinct* rather than a
/// request count, because the false positive to avoid is a legitimate API
/// client — which hammers a handful of endpoints rather than walking a
/// site.
pub const ASSET_RATIO_MIN_PAGES: &str = keys::DETECT_ASSET_RATIO_MIN_PAGES;
pub const ASSET_RATIO_MIN_PAGES_DEFAULT: i64 = 15;

/// Threshold for the rotating-user-agent detector: distinct user agents
/// from one address.
///
/// 20, not the 8 it started at. One household behind one router reached 8
/// in a day without trying: a Fire TV, the Jellyfin TV and phone apps
/// (each with a second user agent for its media player), a Chromebook and
/// two phone browsers. The block landed on the TV. A scraper cycling
/// agents to evade per-agent rules goes far past 20; a home rarely does.
pub const ROTATING_UA_MIN: &str = keys::DETECT_ROTATING_UA_MIN;
pub const ROTATING_UA_MIN_DEFAULT: i64 = 20;

/// Threshold for the referer-less detector: distinct deep (non-root) URLs
/// fetched with no `Referer`.
pub const REFERERLESS_MIN_PATHS: &str = keys::DETECT_REFERERLESS_MIN_PATHS;
pub const REFERERLESS_MIN_PATHS_DEFAULT: i64 = 25;

/// The defaults generation the detectors added after 0.3 arrived in (see
/// `db::schema::DEFAULTS_GENERATION`): on a database an earlier release
/// created they are off, and marked new, until the operator chooses.
pub const MORE_DETECTORS_INTRODUCED_IN: u32 = 3;

/// Login brute force defaults to **on**: the evidence is twenty login
/// attempts from one address inside an hour, which no one person makes,
/// and every exemption a detector has applies (trusted addresses, recent
/// SSH logins, verified crawlers). Only on a database created at
/// [`MORE_DETECTORS_INTRODUCED_IN`] or later, by [`enabled_by_default`].
pub const LOGIN_ATTEMPTS_ENABLED_DEFAULT: bool = true;

/// One day, like the web scanner's: the false positive it can have is an
/// office behind one address, which should not wait long for its block to
/// end. A brute-forcer that comes back is blocked again, for longer each
/// time if repeat offenders are (see [`escalated_ttl_days`]).
pub const LOGIN_ATTEMPTS_TTL_DAYS_DEFAULT: i64 = 1;

/// An hour: the shortest window there is. A password-guesser makes its
/// attempts in minutes; twenty spread over a day could be a team, each
/// logging in once.
pub const LOGIN_ATTEMPTS_WINDOW_HOURS: i64 = 1;

/// Threshold for the login brute-force detector: POST requests to a login
/// page from one address inside the window. Twenty, as for SSH: a person
/// who mistypes a password a few times, or logs in and out and in again,
/// stays far below it, and a password-guesser passes it in a minute.
pub const LOGIN_ATTEMPTS_MIN: &str = keys::DETECT_LOGIN_ATTEMPTS_MIN;
pub const LOGIN_ATTEMPTS_MIN_DEFAULT: i64 = 20;

/// Request rate defaults to **off**. One address is not one person: an
/// office, a school or a carrier's NAT puts hundreds behind it, and their
/// requests add up to whatever a threshold says. Only the operator knows
/// how busy their own visitors are.
pub const REQUEST_RATE_ENABLED_DEFAULT: bool = false;

/// One day, like the other detectors that can catch a crowd behind one
/// address.
pub const REQUEST_RATE_TTL_DAYS_DEFAULT: i64 = 1;

/// An hour: long enough that a page with a hundred images, or a burst of
/// reloads, averages out, and short enough that a flood is answered while
/// it lasts.
pub const REQUEST_RATE_WINDOW_HOURS: i64 = 1;

/// Threshold for the request-rate detector: requests a minute from one
/// address, kept up for the window. 120 by default, two a second for an
/// hour: a person reading, even pages heavy with images, averages far less
/// over an hour, and what keeps it up is a scraper or a flood.
pub const REQUEST_RATE_PER_MINUTE: &str = keys::DETECT_REQUEST_RATE_PER_MINUTE;
pub const REQUEST_RATE_PER_MINUTE_DEFAULT: i64 = 120;

/// Requests NGINX's own rate limit refused (answered 429) inside the
/// window that block an address whatever its average. A hundred: a page
/// load that bursts past the limit is refused a handful of times; a client
/// that keeps coming back after a hundred refusals is not listening.
pub const REQUEST_RATE_REFUSED_MIN: usize = 100;

/// What the request-rate detector acts on, for `per_minute` requests a
/// minute over a window of `window_seconds`.
///
/// The rate is asked of the whole window, so a client under the threshold
/// is never caught. The requests counted are those in buckets that began
/// inside the window (see [`crate::evidence::decide`]), which can fall up
/// to a bucket short of it, so a client that keeps up exactly the
/// threshold may not be caught either: with an hour's window and
/// ten-minute buckets, one that keeps up a fifth more always is. Short of,
/// never over, as every count here errs.
pub fn request_rate_rule(per_minute: usize, window_seconds: i64) -> crate::evidence::Rule {
    let minutes = (window_seconds / 60).max(1) as usize;
    crate::evidence::Rule::Rate {
        lines: per_minute.saturating_mul(minutes),
        refused: REQUEST_RATE_REFUSED_MIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block that lapsed while its evidence was still inside the window
    /// would be judged on the lines that earned it the first time. Evidence
    /// is forgotten when a block is made (see `Db::forget_evidence_before`),
    /// so this is not what keeps it from coming back; but it keeps the
    /// defaults from depending on that alone.
    #[test]
    fn no_default_window_outlasts_its_detector_s_default_block() {
        for detector in Detector::ALL {
            let spec = detector.spec();
            assert!(
                spec.window_hours_default <= spec.ttl_days_default * 24,
                "{}: a {}h window against a {}-day block",
                spec.id,
                spec.window_hours_default,
                spec.ttl_days_default
            );
        }
    }

    #[test]
    fn a_window_is_stored_and_one_out_of_range_is_refused() {
        let db = Db::open_in_memory().unwrap();
        let detector = Detector::WebScanners;
        assert_eq!(detector.window_hours(&db).unwrap(), EVIDENCE_WINDOW_HOURS);

        detector.set_window_hours(&db, 6).unwrap();
        assert_eq!(detector.window_hours(&db).unwrap(), 6);
        assert_eq!(detector.window_seconds(&db).unwrap(), 6 * 3600);

        for hours in [0, -1, MAX_WINDOW_HOURS + 1] {
            assert!(detector.set_window_hours(&db, hours).is_err(), "{hours}");
        }
    }

    /// Written by hand with `sqlite3`: a zero window must not silently
    /// switch the detector off.
    #[test]
    fn a_stored_window_out_of_range_reads_as_the_default() {
        let db = Db::open_in_memory().unwrap();
        let detector = Detector::AssetRatio;
        db.set_int_setting(&detector.window_key(), 0).unwrap();
        assert_eq!(
            detector.window_hours(&db).unwrap(),
            BEHAVIOURAL_WINDOW_HOURS
        );
    }

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

    /// The two scanner thresholds used to be constants the cron could not
    /// be told about. Stored now, but an install that never sets them must
    /// keep today's behaviour exactly.
    #[test]
    fn the_scanner_thresholds_default_to_the_values_they_were_hard_coded_to() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(Detector::SshScanners.threshold(&db).unwrap(), Some(20));
        assert_eq!(Detector::WebScanners.threshold(&db).unwrap(), Some(7));
    }

    #[test]
    fn a_stored_threshold_is_read_back_for_that_detector_only() {
        let db = Db::open_in_memory().unwrap();
        Detector::SshScanners.set_threshold(&db, 40).unwrap();
        assert_eq!(Detector::SshScanners.threshold(&db).unwrap(), Some(40));
        assert_eq!(Detector::WebScanners.threshold(&db).unwrap(), Some(7));
    }

    #[test]
    fn a_threshold_under_the_floor_is_not_stored() {
        let db = Db::open_in_memory().unwrap();
        for value in [i64::MIN, -1, 0, 1] {
            assert!(
                Detector::WebScanners.set_threshold(&db, value).is_err(),
                "{value} was accepted"
            );
        }
        assert_eq!(Detector::WebScanners.threshold(&db).unwrap(), Some(7));
    }

    /// A detector where one request is conclusive has nothing to tune, and
    /// a stored value would be a setting nothing reads.
    #[test]
    fn a_detector_without_a_threshold_refuses_one() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(Detector::ProbePaths.threshold(&db).unwrap(), None);
        assert!(Detector::ProbePaths.set_threshold(&db, 5).is_err());
    }

    #[test]
    fn subnet_escalation_is_off_until_switched_on_and_keeps_its_threshold() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(subnet_escalation(&db).unwrap(), None);

        set_subnet_escalation(&db, None, Some(5)).unwrap();
        assert_eq!(
            subnet_escalation(&db).unwrap(),
            None,
            "a threshold alone switched it on"
        );
        set_subnet_escalation(&db, Some(true), None).unwrap();
        assert_eq!(subnet_escalation(&db).unwrap(), Some(5));

        assert!(set_subnet_escalation(&db, None, Some(1)).is_err());
        assert_eq!(subnet_escalation_min(&db).unwrap(), 5);
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

    // ---- repeat offenders ----

    #[test]
    fn each_offence_doubles_the_block_up_to_eight_times() {
        let cases = [
            ("first offence", 5, 1, 5),
            ("second", 5, 2, 10),
            ("third", 5, 3, 20),
            ("fourth: eight times", 5, 4, 40),
            ("fifth: still eight times", 5, 5, 40),
            ("a hundredth: still eight times", 5, 100, 40),
            ("a one-day detector's fourth", 1, 4, 8),
            ("no offence counts as the first", 5, 0, 5),
        ];
        for (what, ttl, offence, expected) in cases {
            assert_eq!(escalated_ttl_days(ttl, offence), expected, "{what}");
        }
    }

    #[test]
    fn an_escalated_block_lasts_ninety_days_at_most() {
        let cases = [
            ("honeypot, second offence", 30, 2, 60),
            ("honeypot, third offence", 30, 3, ESCALATION_MAX_DAYS),
            ("two weeks, fourth offence", 14, 4, ESCALATION_MAX_DAYS),
            ("a TTL already past the cap is kept", 365, 3, 365),
        ];
        for (what, ttl, offence, expected) in cases {
            assert_eq!(escalated_ttl_days(ttl, offence), expected, "{what}");
        }
    }

    /// The largest TTL anything stores must not overflow when escalated.
    #[test]
    fn escalating_the_longest_ttl_does_not_overflow() {
        assert_eq!(escalated_ttl_days(MAX_TTL_DAYS, 4), MAX_TTL_DAYS);
        assert_eq!(escalated_ttl_days(i64::MAX, 4), i64::MAX);
    }

    #[test]
    fn escalation_is_on_for_a_new_database() {
        let db = Db::open_in_memory().unwrap();
        assert!(repeat_escalation(&db).unwrap(), "off on a new database");
        assert!(
            !repeat_escalation_is_new_here(&db).unwrap(),
            "marked new on the database it shipped with"
        );
    }

    /// An upgrade never lengthens a block by itself: on a database from
    /// before escalation it is off, and new, until someone chooses.
    #[test]
    fn escalation_is_off_and_new_on_an_older_database_until_chosen() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 1)
            .unwrap();
        assert!(!repeat_escalation(&db).unwrap(), "on after an upgrade");
        assert!(
            repeat_escalation_is_new_here(&db).unwrap(),
            "not marked new"
        );

        set_repeat_escalation(&db, false).unwrap();
        assert!(
            !repeat_escalation_is_new_here(&db).unwrap(),
            "still new after choosing off"
        );
        set_repeat_escalation(&db, true).unwrap();
        assert!(repeat_escalation(&db).unwrap(), "switched on, reads off");
    }

    // ---- app-aware probe paths ----

    #[test]
    fn app_probe_paths_are_on_for_a_new_database() {
        let db = Db::open_in_memory().unwrap();
        assert!(app_probe_paths(&db).unwrap(), "off on a new database");
        assert!(
            !app_probe_paths_is_new_here(&db).unwrap(),
            "marked new on the database it shipped with"
        );
    }

    /// An upgrade never makes a detector block more by itself: on a
    /// database from 0.3.0 or before, it is off, and new, until chosen.
    #[test]
    fn app_probe_paths_are_off_and_new_on_an_older_database_until_chosen() {
        for generation in [1, 2] {
            let db = Db::open_in_memory().unwrap();
            db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, generation)
                .unwrap();
            assert!(!app_probe_paths(&db).unwrap(), "{generation}: on");
            assert!(
                app_probe_paths_is_new_here(&db).unwrap(),
                "{generation}: not marked new"
            );

            set_app_probe_paths(&db, true).unwrap();
            assert!(app_probe_paths(&db).unwrap(), "{generation}: switched on");
            assert!(
                !app_probe_paths_is_new_here(&db).unwrap(),
                "{generation}: still new after choosing"
            );
        }
    }

    #[test]
    fn offences_read_as_ordinals() {
        let cases = [
            (1, "1st"),
            (2, "2nd"),
            (3, "3rd"),
            (4, "4th"),
            (11, "11th"),
            (12, "12th"),
            (13, "13th"),
            (21, "21st"),
            (22, "22nd"),
            (111, "111th"),
        ];
        for (n, expected) in cases {
            assert_eq!(ordinal(n), expected, "{n}");
        }
    }

    // ---- the defaults policy across upgrades ----

    fn spec(enabled_default: bool, introduced_in: u32) -> DetectorSpec {
        DetectorSpec {
            enabled_default,
            introduced_in,
            ..Detector::ProbePaths.spec()
        }
    }

    /// The whole policy, pinned: only a detector at least as old as the
    /// database gets its spec's default; one that arrived later is off.
    #[test]
    fn a_detector_newer_than_the_database_is_off_until_chosen() {
        let cases = [
            (
                "on by default, as old as the database",
                spec(true, 1),
                1,
                true,
            ),
            (
                "on by default, older than the database",
                spec(true, 1),
                2,
                true,
            ),
            (
                "on by default, newer than the database",
                spec(true, 2),
                1,
                false,
            ),
            (
                "off by default, as old as the database",
                spec(false, 1),
                1,
                false,
            ),
            (
                "off by default, newer than the database",
                spec(false, 2),
                1,
                false,
            ),
        ];
        for (what, spec, created_at, expected) in cases {
            assert_eq!(enabled_by_default(&spec, created_at), expected, "{what}");
        }
    }

    /// A choice the operator made is theirs, whichever generation.
    #[test]
    fn a_switched_detector_follows_its_switch_on_any_database() {
        let db = Db::open_in_memory().unwrap();
        // Older than every detector there is: all of them are "new" here.
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 0)
            .unwrap();

        Detector::ProbePaths.set_enabled(&db, true).unwrap();
        Detector::Honeypot.set_enabled(&db, false).unwrap();

        assert!(Detector::ProbePaths.is_enabled(&db).unwrap());
        assert!(!Detector::Honeypot.is_enabled(&db).unwrap());
    }

    /// Through a real database: every detector that would be on by
    /// default reads off on a database older than it, and is marked new
    /// until someone chooses, either way.
    #[test]
    fn on_an_older_database_new_detectors_read_off_and_new_until_chosen() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 0)
            .unwrap();

        for d in Detector::ALL
            .into_iter()
            .filter(|d| d.is_operator_controlled())
        {
            assert!(!d.is_enabled(&db).unwrap(), "{} ran on its own", d.id());
            assert!(d.is_new_here(&db).unwrap(), "{} is not marked new", d.id());
        }

        Detector::Injection.set_enabled(&db, true).unwrap();
        Detector::ProbePaths.set_enabled(&db, false).unwrap();
        assert!(!Detector::Injection.is_new_here(&db).unwrap(), "turned on");
        assert!(
            !Detector::ProbePaths.is_new_here(&db).unwrap(),
            "turned off"
        );
    }

    /// An upgrade from 0.4 (generation 3) does not start blocking protocol
    /// probes by itself; a new install does.
    #[test]
    fn protocol_probes_are_new_and_off_after_an_upgrade_and_on_for_a_new_install() {
        let d = Detector::ProtocolProbes;
        let new = Db::open_in_memory().unwrap();
        assert!(d.is_enabled(&new).unwrap(), "off on a new install");
        assert!(!d.is_new_here(&new).unwrap(), "new on a new install");

        let upgraded = Db::open_in_memory().unwrap();
        upgraded
            .set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 3)
            .unwrap();
        assert!(!d.is_enabled(&upgraded).unwrap(), "on after an upgrade");
        assert!(d.is_new_here(&upgraded).unwrap(), "not marked new");
    }

    /// A database created by 0.2 or 0.3 (generation 2) is offered the
    /// port-scan detector as new, and it is off there until chosen.
    #[test]
    fn the_port_scan_detector_is_new_and_off_on_a_generation_2_database() {
        let db = Db::open_in_memory().unwrap();
        db.set_int_setting(crate::db::keys::DEFAULTS_GENERATION, 2)
            .unwrap();
        let d = Detector::PortScanners;
        assert!(!d.is_enabled(&db).unwrap(), "on after an upgrade");
        assert!(d.is_new_here(&db).unwrap(), "not marked new");

        d.set_enabled(&db, true).unwrap();
        assert!(d.is_enabled(&db).unwrap());
        assert!(!d.is_new_here(&db).unwrap(), "still new once chosen");
    }

    /// Off on a new database too: it changes what the host accepts on
    /// ports beyond the web server and SSH, which nobody asked for yet.
    #[test]
    fn the_port_scan_detector_is_off_on_a_new_database() {
        let db = Db::open_in_memory().unwrap();
        assert!(!Detector::PortScanners.is_enabled(&db).unwrap());
        assert!(!Detector::PortScanners.is_new_here(&db).unwrap());
    }

    /// Nothing is new on a database created by this very release.
    #[test]
    fn nothing_is_new_on_a_new_database() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            db.defaults_generation().unwrap(),
            crate::db::schema::DEFAULTS_GENERATION
        );
        for d in Detector::ALL {
            assert!(!d.is_new_here(&db).unwrap(), "{}", d.id());
        }
    }

    /// Every detector that existed before the policy did is generation 1,
    /// so no upgrade from 0.0.x changes what runs. A detector added from
    /// now on is not in this list, and must carry a later generation — and
    /// that generation must be one this binary knows, or it would never be
    /// on anywhere.
    #[test]
    fn only_the_detectors_from_before_0_1_are_generation_1() {
        let before_0_1 = [
            "block_scanners",
            "block_web_scanners",
            "block_spoofed_crawlers",
            "block_probe_paths",
            "block_injection",
            "block_honeypot",
            "block_asset_ratio",
            "block_rotating_ua",
            "block_refererless",
            "block_robots_txt",
        ];
        for d in Detector::ALL {
            let spec = d.spec();
            if before_0_1.contains(&spec.id) {
                assert_eq!(spec.introduced_in, 1, "{}", spec.id);
            } else {
                assert!(
                    spec.introduced_in > 1,
                    "{} is new since 0.1: give it `introduced_in` a new generation",
                    spec.id
                );
            }
            assert!(
                spec.introduced_in <= crate::db::schema::DEFAULTS_GENERATION,
                "{}: bump DEFAULTS_GENERATION to {}",
                spec.id,
                spec.introduced_in
            );
        }
    }

    #[test]
    fn a_ttl_outside_one_day_to_ten_years_is_not_stored() {
        let db = Db::open_in_memory().unwrap();
        for days in [0, -1, MAX_TTL_DAYS + 1, i64::MAX] {
            assert!(
                Detector::Honeypot.set_ttl_days(&db, days).is_err(),
                "{days} day(s) was accepted"
            );
        }
        Detector::Honeypot.set_ttl_days(&db, MAX_TTL_DAYS).unwrap();
        assert_eq!(Detector::Honeypot.ttl_days(&db).unwrap(), MAX_TTL_DAYS);
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

    /// The path is published in robots.txt, one line of it. A newline ends
    /// that line and starts whatever the rest says — `Allow: /` for every
    /// agent, say — and `#`, `*` and `$` change what the line means.
    #[test]
    fn a_honeypot_path_that_would_not_stay_one_robots_txt_line_is_refused() {
        let db = Db::open_in_memory().unwrap();
        for bad in [
            "/trap\nUser-agent: *\nAllow: /",
            "/tr\rap",
            "/tr ap/",
            "/tr\tap/",
            "/trap#x",
            "/trap/*",
            "/trap$",
        ] {
            assert!(
                validate_honeypot_path(bad).is_err(),
                "{bad:?} must be refused"
            );
            db.set_text_setting(HONEYPOT_PATH, bad).unwrap();
            assert_eq!(
                honeypot_path(&db).unwrap(),
                HONEYPOT_PATH_DEFAULT,
                "{bad:?} must not be used even if it was stored"
            );
        }
    }

    /// `/` begins every request path: as the trap it would block every
    /// visitor for thirty days and disallow the whole site in robots.txt.
    #[test]
    fn a_honeypot_path_that_names_nothing_below_the_root_is_refused() {
        let db = Db::open_in_memory().unwrap();
        for bad in ["/", "//", " / "] {
            assert!(
                validate_honeypot_path(bad).is_err(),
                "{bad:?} must be refused"
            );
            db.set_text_setting(HONEYPOT_PATH, bad).unwrap();
            assert_eq!(
                honeypot_path(&db).unwrap(),
                HONEYPOT_PATH_DEFAULT,
                "{bad:?}"
            );
        }
    }

    /// One `/` among the extra probe paths was in every request, and every
    /// visitor would have been blocked for five days.
    #[test]
    fn an_extra_probe_path_that_is_only_slashes_is_skipped() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(PROBE_PATHS_EXTRA, "/\n//\n/my-secret\n")
            .unwrap();
        assert_eq!(extra_probe_paths(&db).unwrap(), ["/my-secret"]);
    }

    #[test]
    fn an_ordinary_honeypot_path_is_accepted() {
        for good in ["/my-trap/", "/a/b.c_d~e/", "/%7Etrap"] {
            assert_eq!(validate_honeypot_path(good).unwrap(), good);
        }
    }
}
