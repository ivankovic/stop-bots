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

//! Is this host actually protected?
//!
//! Every other check in this project compares what it *would* generate
//! against what is *on disk*. None of them looks at the kernel. That gap
//! is not hypothetical: a real host ran for three weeks with 48,860
//! generated drop rules in `/etc/stop-bots/firewall.nft` and an empty
//! ruleset, because writing the script and loading it are two steps and
//! only the first had ever been checked.
//!
//! Split in two, the same way [`crate::refresh`] and [`crate::webaccess`]
//! are, and for the same reason:
//!
//! - [`probe`] shells out — `nft`, `iptables`, `systemctl`, the
//!   filesystem. It touches no database, so it can run anywhere.
//! - [`assess`] compares a [`Probe`] against the database and produces a
//!   [`Report`]. It runs no subprocesses, so its tests are a struct
//!   literal and nothing else.
//!
//! The split is also what keeps this affordable. `nft list table` on a
//! ruleset this size is megabytes of text — fine once an hour from the
//! internal cron, which is what runs it, and not something to do on every
//! render of a dashboard panel.
//!
//! ## Not looking is not the same as fine
//!
//! `nft list` needs root. Run without it, every probe field that could not
//! be collected is `None`, and the check that depends on it reports
//! [`Level::Unknown`] rather than [`Level::Ok`]. A health check that says
//! everything is fine because it could not look is worse than no health
//! check, because it is believed.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::db::Db;
use crate::firewall::{self, FirewallBackend};

/// How much a check wants the operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing to do.
    Ok,
    /// The check could not run — usually for want of root. Never
    /// collapsed into `Ok`; see the module docs.
    Unknown,
    /// Working, but not the way the operator probably intends.
    Warn,
    /// This host is not protected in the way it is configured to be.
    Critical,
}

impl Level {
    /// A short tag for a terminal or a pill.
    pub fn tag(self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Unknown => "UNKNOWN",
            Level::Warn => "WARN",
            Level::Critical => "CRITICAL",
        }
    }
}

/// One answered question about this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier, safe to grep for in a monitoring config. Never
    /// change one without meaning to.
    pub id: &'static str,
    /// What the operator is looking at.
    pub title: &'static str,
    pub level: Level,
    /// What is true, in one line. States the fact, not the advice.
    pub detail: String,
    /// What to do about it, when there is something to do.
    pub fix: Option<String>,
}

/// Every check, and when they were taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
    /// Unix seconds.
    pub checked_at: i64,
}

impl Report {
    /// The worst level in the report — what a single-line summary or an
    /// exit status should reflect.
    pub fn worst(&self) -> Level {
        self.checks
            .iter()
            .map(|check| check.level)
            .max()
            .unwrap_or(Level::Ok)
    }

    /// Checks at or above `level`, worst first, then in declaration order.
    pub fn at_least(&self, level: Level) -> Vec<&Check> {
        let mut found: Vec<&Check> = self.checks.iter().filter(|c| c.level >= level).collect();
        // `sort_by_key` with `Reverse` rather than a comparator, and a
        // stable sort either way: within one level the checks stay in the
        // order they are declared, which is the order they are worth
        // reading.
        found.sort_by_key(|check| std::cmp::Reverse(check.level));
        found
    }

    /// A one-line summary, for a status bar or the top of a panel.
    pub fn headline(&self) -> String {
        match self.worst() {
            Level::Ok => format!("{} check(s) passed", self.checks.len()),
            worst => {
                let n = self.checks.iter().filter(|c| c.level == worst).count();
                format!("{n} {} of {} check(s)", worst.tag(), self.checks.len())
            }
        }
    }
}

/// Everything [`assess`] needs that lives outside the database.
///
/// A plain struct of already-collected facts, so a test states the world
/// it wants in a literal rather than arranging for `nft` to exist. `None`
/// means "could not find out", which is a different answer from zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Probe {
    /// Rules currently loaded in this project's own table or chain.
    /// `None` when the tool could not be run at all.
    pub live_rules: Option<usize>,
    /// Which backend's live state `live_rules` came from, by its stored
    /// name — a string rather than the enum so that a probe written by one
    /// version still parses in the next.
    pub live_backend: Option<String>,
    /// Whether something will reload the ruleset after a reboot.
    /// `None` when it could not be determined.
    pub firewall_persists: Option<bool>,
    /// `systemctl is-active` for the console's unit, when there is one.
    pub unit_active: Option<bool>,
    /// The binary the unit's `ExecStart` names, if a unit exists.
    pub unit_binary: Option<PathBuf>,
    /// Bytes free on the filesystem holding the database.
    pub db_free_bytes: Option<u64>,
    /// Whether each log source could actually be read.
    pub ssh_log_readable: Option<bool>,
    pub access_log_readable: Option<bool>,
}

/// Below this, a database that is mostly appends starts failing writes
/// with `SQLITE_FULL` — which is what a real host reported for an hour,
/// naming neither the disk nor the tool.
const LOW_DISK_BYTES: u64 = 256 * 1024 * 1024;

/// Above this, the database is bigger than anything this schema explains
/// and something is growing that nobody is watching.
///
/// Deliberately far above a healthy size rather than close to it. Every
/// table here is bounded by something: the feeds' own length, the bot
/// lists', `firewall_rules`' TTLs, and — since `cron::maintenance` —
/// `user_agent_stats`' age window and row cap. Adding those up, a busy
/// host with every reputation feed enabled lands in the tens of
/// megabytes. A threshold set just above *that* would fire on a host that
/// is merely busy, and a check that cries wolf is one nobody reads on the
/// day it matters. This one exists to catch the thing the bounds above
/// have missed — which is exactly how the 4.7 MB rendered-signature value
/// went unnoticed for two months, in a database nothing ever reported the
/// size of.
const LARGE_DB_BYTES: u64 = 128 * 1024 * 1024;

/// Runs everything that needs a subprocess or the filesystem.
///
/// Never fails: a probe that cannot answer a question leaves that field
/// `None`, because "I could not check" is a result the report has to be
/// able to show. An error here would mean no report at all, which is the
/// least useful outcome available.
pub fn probe(backend: FirewallBackend, db_path: &Path, ssh_log: Option<&Path>) -> Probe {
    let (live_rules, live_backend) = match live_rule_count(backend) {
        Some(count) => (Some(count), Some(backend.stored().to_string())),
        None => (None, None),
    };
    Probe {
        live_rules,
        live_backend,
        firewall_persists: firewall_persists(backend),
        unit_active: unit_is_active(),
        unit_binary: unit_binary(),
        db_free_bytes: free_bytes(db_path),
        ssh_log_readable: Some(matches!(
            match ssh_log {
                Some(path) => crate::sshlog::read_log_file(path),
                None => crate::sshlog::find_default_source(),
            },
            crate::sshlog::LogSource::Found(_)
        )),
        access_log_readable: Some(matches!(
            crate::accesslog::find_default_source(),
            crate::accesslog::LogSource::Found(_)
        )),
    }
}

/// How many rules this project has loaded right now, or `None` if the
/// question could not be asked.
///
/// Counts only our own table or chain. The host's other firewall rules are
/// none of this tool's business, and a count of the whole ruleset would
/// answer a different question.
fn live_rule_count(backend: FirewallBackend) -> Option<usize> {
    // The distinction that matters, and the one a bare exit status
    // destroys: "the tool would not run" is unknown, while "the tool ran
    // and our table is not there" is *zero rules loaded* — which is the
    // critical case this whole module exists to catch. Both make
    // `nft list table` exit non-zero.
    let output = match backend {
        FirewallBackend::Nftables => {
            // Cheap — just the table names. Succeeding proves `nft` is
            // usable and we may read the ruleset; our table's absence from
            // the list then means zero, not unknown.
            let tables = run("nft", &["list", "tables"])?;
            if !tables
                .lines()
                .any(|line| line.trim() == "table inet stop_bots")
            {
                return Some(0);
            }
            run("nft", &["list", "table", "inet", "stop_bots"])?
        }
        FirewallBackend::Iptables => match run("iptables", &["-S", "STOP-BOTS"]) {
            Some(output) => output,
            // Listing a chain that certainly exists separates "no
            // permission" from "no STOP-BOTS chain yet".
            None => {
                run("iptables", &["-S", "INPUT"])?;
                return Some(0);
            }
        },
    };
    Some(match backend {
        FirewallBackend::Nftables => count_nft_rules(&output),
        FirewallBackend::Iptables => count_iptables_rules(&output),
    })
}

/// Rule lines inside an `nft list table` dump: the ones carrying a
/// verdict. The table, chain and brace lines are structure, not rules.
///
/// Split out from the subprocess so the parsing — the part that breaks
/// when a tool changes its output — is testable in microseconds. The
/// plumbing around it is covered by the container suite, against a real
/// `nft`.
fn count_nft_rules(output: &str) -> usize {
    output
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.ends_with("drop") || line.ends_with("accept") || line.ends_with("return")
        })
        .count()
}

/// `iptables -S` prints one `-A STOP-BOTS ...` per rule, plus an `-N` line
/// that creates the chain and is not one.
fn count_iptables_rules(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.trim_start().starts_with("-A"))
        .count()
}

/// Whether the ruleset will still be there after a reboot.
///
/// nftables rules live only in kernel memory. Debian's `nftables.service`
/// is what reloads them at boot; without it, a host that was protected
/// comes back up open and nothing says so.
fn firewall_persists(backend: FirewallBackend) -> Option<bool> {
    let unit = match backend {
        FirewallBackend::Nftables => "nftables.service",
        FirewallBackend::Iptables => "netfilter-persistent.service",
    };
    // `is-enabled` exits non-zero for a unit that is merely disabled, so
    // the status cannot tell that apart from "no such unit" — the printed
    // word can, and an empty answer is the one that means unknown.
    let state = run_allowing_failure("systemctl", &["is-enabled", unit])?;
    match state.trim() {
        "" => None,
        "enabled" | "enabled-runtime" => Some(true),
        _ => Some(false),
    }
}

fn unit_is_active() -> Option<bool> {
    // `LoadState` first, because `is-active` says "inactive" both for a
    // unit that is stopped and for one that does not exist — and calling
    // a host with no console installed "CRITICAL: installed but not
    // running" is exactly the false alarm that gets a health check muted.
    let load = run(
        "systemctl",
        &[
            "show",
            crate::install::WEB_UNIT,
            "-p",
            "LoadState",
            "--value",
        ],
    )?;
    match load.trim() {
        "" | "not-found" | "masked" => None,
        _ => {
            let state =
                run_allowing_failure("systemctl", &["is-active", crate::install::WEB_UNIT])?;
            Some(state.trim() == "active")
        }
    }
}

fn unit_binary() -> Option<PathBuf> {
    let shown = run(
        "systemctl",
        &["show", crate::install::WEB_UNIT, "-p", "ExecStart"],
    )?;
    parse_exec_start(&shown)
}

/// The binary out of `systemctl show -p ExecStart`, which prints
/// `ExecStart={ path=/usr/local/bin/stop-bots ; argv[]=... }`.
///
/// Reads `path=` rather than the first word of `argv[]`: they are normally
/// the same, but `path=` is what systemd will actually execute, and that
/// is the one whose absence produces `203/EXEC`.
fn parse_exec_start(shown: &str) -> Option<PathBuf> {
    let path = shown.split("path=").nth(1)?.split_whitespace().next()?;
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Free bytes on the filesystem holding `path`, via `df`.
///
/// `df` rather than `statvfs` to avoid a libc dependency for one number,
/// and `--output=avail` because the column layout of plain `df` is not
/// stable enough to index into.
fn free_bytes(path: &Path) -> Option<u64> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let out = run("df", &["--output=avail", "-B1", &dir.to_string_lossy()])?;
    out.lines().nth(1)?.trim().parse().ok()
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// The same, but a non-zero exit still yields whatever was printed —
/// `systemctl is-active` reports the state on stdout *and* exits non-zero
/// when that state is not "active".
fn run_allowing_failure(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Turns a [`Probe`] and the database into a [`Report`].
///
/// Runs no subprocesses, so every test below is a `Probe` literal and a
/// database. The order the checks come back in is the order they are worth
/// reading: the firewall first, because that is the one that was silently
/// wrong on a real host for three weeks.
pub fn assess(db: &Db, probe: &Probe) -> Result<Report> {
    let mut checks = Vec::new();
    let backend = firewall::stored_backend(db)?;
    let expected = firewall::all_rules(db)?.len();

    checks.push(firewall_enforced(probe, expected));
    checks.push(firewall_persistence(probe, backend));
    checks.push(script_freshness(db, expected)?);
    checks.push(nginx_applied(db)?);
    checks.push(service_health(probe));
    checks.push(disk_room(probe));
    checks.push(database_size(db)?);
    checks.push(log_sources(probe));

    Ok(Report {
        checks,
        checked_at: now_secs(),
    })
}

/// The check this module exists for.
fn firewall_enforced(probe: &Probe, expected: usize) -> Check {
    let (level, detail, fix) = match probe.live_rules {
        None => (
            Level::Unknown,
            "could not read the live ruleset — needs root".to_string(),
            None,
        ),
        Some(_) if expected == 0 => (Level::Ok, "no rules to enforce yet".to_string(), None),
        Some(0) => (
            Level::Critical,
            format!("{expected} rule(s) generated, none loaded into the kernel"),
            Some("run the generated script, or press \u{201c}Apply everything\u{201d}".to_string()),
        ),
        // Exact equality is the wrong test: the rendered script also
        // carries structural rules, and the ruleset can legitimately gain
        // a rule between a render and a look. What matters is whether the
        // kernel is carrying roughly what was generated, or a fraction of
        // it.
        Some(live) if live * 10 < expected * 9 => (
            Level::Warn,
            format!("{live} rule(s) loaded, {expected} generated — the ruleset is behind"),
            Some("re-run the generated script to catch the kernel up".to_string()),
        ),
        Some(live) => (Level::Ok, format!("{live} rule(s) loaded"), None),
    };
    Check {
        id: "firewall-enforced",
        title: "Firewall rules are in the kernel",
        level,
        detail,
        fix,
    }
}

fn firewall_persistence(probe: &Probe, backend: FirewallBackend) -> Check {
    let unit = match backend {
        FirewallBackend::Nftables => "nftables.service",
        FirewallBackend::Iptables => "netfilter-persistent.service",
    };
    let (level, detail, fix) = match probe.firewall_persists {
        None => (
            Level::Unknown,
            format!("could not tell whether {unit} is enabled"),
            None,
        ),
        Some(true) => (Level::Ok, format!("{unit} will reload them"), None),
        Some(false) => (
            Level::Warn,
            format!("{unit} is not enabled — a reboot comes back with no rules"),
            Some(format!("systemctl enable {unit}")),
        ),
    };
    Check {
        id: "firewall-persists",
        title: "Rules survive a reboot",
        level,
        detail,
        fix,
    }
}

/// Whether the script on disk still matches the rules in the database.
///
/// The one check here that already existed — the Dashboard's "needs
/// updating" row — folded in so that one panel answers the whole question
/// rather than half of it in two places.
fn script_freshness(db: &Db, expected: usize) -> Result<Check> {
    let current = firewall::rules_signature(&firewall::all_rules(db)?);
    let rendered = db.get_firewall_rendered_signature()?;
    let stale = rendered.as_deref() != Some(current.as_str());

    // Nothing to render and nothing rendered is not staleness, it is a
    // host that has not been configured yet. Saying otherwise puts a
    // warning on every fresh install, and a check that cries wolf on a
    // brand-new database is one nobody reads on the day it matters.
    let untouched = expected == 0 && rendered.is_none();

    Ok(Check {
        id: "script-fresh",
        title: "Generated script matches the rules",
        level: if stale && !untouched {
            Level::Warn
        } else {
            Level::Ok
        },
        detail: match (untouched, stale) {
            (true, _) => "no rules to render yet".to_string(),
            (_, true) => format!("the rules changed since the last render ({expected} now)"),
            (_, false) => "up to date".to_string(),
        },
        fix: (stale && !untouched).then(|| "render the firewall script again".to_string()),
    })
}

fn nginx_applied(db: &Db) -> Result<Check> {
    use crate::nginx::{self, SiteApplyStatus};

    let sites = db.list_sites()?;
    let total = sites.len();
    // Reads each site's config file, the same way the Site settings screen
    // does — this is the one check here that touches the filesystem from
    // `assess` rather than from `probe`, because it needs a per-site
    // `BlockConfig` that only the database can produce.
    let mut stale: Vec<String> = Vec::new();
    for site in sites {
        let config = nginx::block_config_for_site(db, site.id)?;
        let status =
            nginx::site_apply_status(Path::new(&site.config_path), &site.server_name, &config);
        if status != SiteApplyStatus::UpToDate {
            stale.push(site.server_name);
        }
    }

    let (level, detail, fix) = if total == 0 {
        (
            Level::Warn,
            "no sites scanned yet".to_string(),
            Some("run `stop-bots scan-sites`".to_string()),
        )
    } else if stale.is_empty() {
        (Level::Ok, format!("{total} site(s) applied"), None)
    } else {
        (
            Level::Warn,
            format!(
                "{} of {total} site(s) not applied: {}",
                stale.len(),
                stale.join(", ")
            ),
            Some("apply the blocking policy to every site".to_string()),
        )
    };
    Ok(Check {
        id: "nginx-applied",
        title: "NGINX blocks are applied",
        level,
        detail,
        fix,
    })
}

/// The console's own unit: running, and running the binary it names.
///
/// The second half is the one with history. A unit whose `ExecStart`
/// points somewhere the sandbox hides fails with `203/EXEC` and a message
/// naming neither; a deploy that replaces a binary without restarting
/// leaves the old code serving indefinitely.
fn service_health(probe: &Probe) -> Check {
    let (level, detail, fix) = match (probe.unit_active, &probe.unit_binary) {
        (None, _) => (
            Level::Unknown,
            "no systemd unit found for the console".to_string(),
            None,
        ),
        (Some(false), _) => (
            Level::Critical,
            "the console unit is installed but not running".to_string(),
            Some(format!("systemctl start {}", crate::install::WEB_UNIT)),
        ),
        (Some(true), Some(path)) if !path.exists() => (
            Level::Critical,
            format!("the unit runs {}, which does not exist", path.display()),
            Some("re-run `stop-bots install web --force`".to_string()),
        ),
        (Some(true), Some(path)) => (Level::Ok, format!("running {}", path.display()), None),
        (Some(true), None) => (Level::Ok, "running".to_string(), None),
    };
    Check {
        id: "service-health",
        title: "Console service",
        level,
        detail,
        fix,
    }
}

fn disk_room(probe: &Probe) -> Check {
    let (level, detail, fix) = match probe.db_free_bytes {
        None => (
            Level::Unknown,
            "could not read free space for the database".to_string(),
            None,
        ),
        Some(free) if free < LOW_DISK_BYTES => (
            Level::Critical,
            format!(
                "{} free where the database lives — writes will start failing",
                human_bytes(free)
            ),
            Some("free space on that filesystem".to_string()),
        ),
        Some(free) => (Level::Ok, format!("{} free", human_bytes(free)), None),
    };
    Check {
        id: "disk-room",
        title: "Room for the database",
        level,
        detail,
        fix,
    }
}

/// How big the database has become, and how much of that is slack the next
/// `CronJob::Maintenance` will hand back.
///
/// Reports the size unconditionally rather than only when it is a problem:
/// the size of this file was invisible everywhere until now — `disk_room`
/// above reports free space on the *filesystem*, which says nothing about
/// what this tool is responsible for — and a number an admin sees every
/// time is one they notice changing.
fn database_size(db: &Db) -> Result<Check> {
    let (level, detail, fix) = match db.size_on_disk()? {
        // In-memory, so there is no file and nothing that can grow.
        None => (Level::Ok, "in memory".to_string(), None),
        Some(size) => {
            let slack = if size.free_bytes > 0 {
                format!(" ({} reclaimable)", human_bytes(size.free_bytes))
            } else {
                String::new()
            };
            if size.bytes >= LARGE_DB_BYTES {
                (
                    Level::Warn,
                    format!(
                        "{}{slack} — larger than this schema accounts for",
                        human_bytes(size.bytes)
                    ),
                    Some("run `stop-bots maintain`, then check what is growing".to_string()),
                )
            } else {
                (
                    Level::Ok,
                    format!("{}{slack}", human_bytes(size.bytes)),
                    None,
                )
            }
        }
    };
    Ok(Check {
        id: "database-size",
        title: "Database size",
        level,
        detail,
        fix,
    })
}

/// The detectors are only as good as the logs they read, and a log they
/// cannot read looks exactly like a log with nothing in it.
fn log_sources(probe: &Probe) -> Check {
    let missing: Vec<&str> = [
        (probe.ssh_log_readable, "the SSH log"),
        (probe.access_log_readable, "the NGINX access log"),
    ]
    .into_iter()
    .filter_map(|(readable, name)| (readable == Some(false)).then_some(name))
    .collect();

    let unknown = probe.ssh_log_readable.is_none() || probe.access_log_readable.is_none();
    let (level, detail, fix) = if unknown {
        (
            Level::Unknown,
            "could not check the log sources".to_string(),
            None,
        )
    } else if missing.is_empty() {
        (Level::Ok, "both readable".to_string(), None)
    } else {
        (
            Level::Warn,
            format!(
                "{} unreadable — those detectors find nothing",
                missing.join(" and ")
            ),
            Some("point --ssh-log/--access-log at the real files".to_string()),
        )
    };
    Check {
        id: "log-sources",
        title: "Detector log sources",
        level,
        detail,
        fix,
    }
}

/// Where the last probe is kept, so both front-ends can render a report
/// without shelling out.
pub const PROBE_KEY: &str = "health:probe";
pub const PROBE_AT_KEY: &str = "health:probe_at";

/// Records a probe for the front-ends to read.
///
/// Only the [`Probe`] is stored, never the [`Report`]. The probe is the
/// expensive half and the half that goes stale slowly; the report is
/// derived from it and the database, so deriving it at render time keeps
/// it consistent with rules the operator changed a second ago. Storing the
/// report instead would show a panel confidently disagreeing with the
/// screen above it.
pub fn store_probe(db: &Db, probe: &Probe) -> Result<()> {
    db.set_text_setting(PROBE_KEY, &serde_json::to_string(probe)?)?;
    db.set_text_setting(PROBE_AT_KEY, &now_secs().to_string())?;
    Ok(())
}

/// The last stored probe and when it was taken, or `None` if the health
/// check has never run — or if what was stored no longer parses, which is
/// what an upgrade that changed the shape looks like. A stale probe is
/// worth showing; an unparsable one is worth forgetting.
pub fn cached_probe(db: &Db) -> Result<Option<(Probe, i64)>> {
    let Some(raw) = db.get_text_setting(PROBE_KEY)? else {
        return Ok(None);
    };
    let Ok(probe) = serde_json::from_str(&raw) else {
        return Ok(None);
    };
    let at = db
        .get_text_setting(PROBE_AT_KEY)?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(Some((probe, at)))
}

/// The report both front-ends show: the last probe the cron took,
/// re-assessed against the database as it is right now.
///
/// `None` when no probe has been taken yet, which a panel should say
/// rather than rendering seven `UNKNOWN` rows.
pub fn cached_report(db: &Db) -> Result<Option<(Report, i64)>> {
    let Some((probe, at)) = cached_probe(db)? else {
        return Ok(None);
    };
    Ok(Some((assess(db, &probe)?, at)))
}

pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1024 * 1024 * 1024, "GB"),
        (1024 * 1024, "MB"),
        (1024, "KB"),
        (1, "B"),
    ];
    for (scale, suffix) in UNITS {
        if bytes >= scale {
            return format!("{:.1}{suffix}", bytes as f64 / scale as f64);
        }
    }
    "0B".to_string()
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

    fn db() -> Db {
        Db::open_in_memory().unwrap()
    }

    /// A probe where everything that could be answered was, and every
    /// answer is the good one. Tests override the one field they are
    /// about, so a test reads as the difference from healthy.
    fn healthy() -> Probe {
        Probe {
            live_rules: Some(10),
            live_backend: Some(FirewallBackend::Nftables.stored().to_string()),
            firewall_persists: Some(true),
            unit_active: Some(true),
            unit_binary: None,
            db_free_bytes: Some(8 * 1024 * 1024 * 1024),
            ssh_log_readable: Some(true),
            access_log_readable: Some(true),
        }
    }

    fn check<'a>(report: &'a Report, id: &str) -> &'a Check {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check called {id}"))
    }

    fn with_rules(db: &Db, count: usize) {
        for i in 0..count {
            db.add_firewall_rule(&crate::db::NewFirewallRule {
                address: format!("198.51.100.{i}"),
                port: None,
                action: crate::db::FirewallAction::Block,
            })
            .unwrap();
        }
    }

    /// The check this module exists for, in the exact shape a real host
    /// was found in: a pile of generated rules and an empty ruleset.
    #[test]
    fn generated_rules_that_never_reached_the_kernel_are_critical() {
        let db = db();
        with_rules(&db, 12);

        let report = assess(
            &db,
            &Probe {
                live_rules: Some(0),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "firewall-enforced");
        assert_eq!(check.level, Level::Critical);
        assert!(check.detail.contains("12"), "was: {}", check.detail);
        assert!(
            check.detail.contains("none loaded"),
            "was: {}",
            check.detail
        );
        assert!(check.fix.is_some(), "a critical check must say what to do");
        assert_eq!(report.worst(), Level::Critical);
    }

    /// Not looking is not the same as fine. Without root the ruleset
    /// cannot be read, and reporting that as healthy is how a health check
    /// becomes worse than none.
    #[test]
    fn a_ruleset_that_could_not_be_read_is_unknown_rather_than_ok() {
        let db = db();
        with_rules(&db, 12);

        let report = assess(
            &db,
            &Probe {
                live_rules: None,
                ..healthy()
            },
        )
        .unwrap();

        assert_eq!(check(&report, "firewall-enforced").level, Level::Unknown);
        assert_ne!(report.worst(), Level::Ok);
    }

    /// A host with nothing to enforce is not a host in trouble.
    #[test]
    fn an_empty_ruleset_is_fine_when_there_are_no_rules_to_load() {
        let report = assess(
            &db(),
            &Probe {
                live_rules: Some(0),
                ..healthy()
            },
        )
        .unwrap();
        assert_eq!(check(&report, "firewall-enforced").level, Level::Ok);
    }

    /// A ruleset well short of what was generated is worth saying, but it
    /// is not the same as nothing being loaded at all.
    #[test]
    fn a_ruleset_far_behind_the_generated_one_warns() {
        let db = db();
        with_rules(&db, 100);

        let report = assess(
            &db,
            &Probe {
                live_rules: Some(3),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "firewall-enforced");
        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("behind"), "was: {}", check.detail);
    }

    /// A few rules either way is not drift — the rendered script carries
    /// structural rules the live count does not, and the two are read at
    /// different moments.
    #[test]
    fn a_ruleset_slightly_off_the_generated_count_is_not_reported() {
        let db = db();
        with_rules(&db, 100);

        let report = assess(
            &db,
            &Probe {
                live_rules: Some(97),
                ..healthy()
            },
        )
        .unwrap();

        assert_eq!(check(&report, "firewall-enforced").level, Level::Ok);
    }

    /// nftables rules live in kernel memory only. A host that is protected
    /// now and comes back open after a reboot is worth a word.
    #[test]
    fn rules_that_will_not_survive_a_reboot_warn_and_name_the_unit() {
        let report = assess(
            &db(),
            &Probe {
                firewall_persists: Some(false),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "firewall-persists");
        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains("nftables.service"),
            "was: {}",
            check.detail
        );
        assert!(check.fix.as_deref().unwrap().contains("systemctl enable"));
    }

    /// The backend decides which unit is the one that matters, the same
    /// way it decides the script's syntax and path.
    #[test]
    fn the_persistence_check_names_the_unit_for_the_stored_backend() {
        let db = db();
        firewall::store_backend(&db, FirewallBackend::Iptables).unwrap();

        let report = assess(
            &db,
            &Probe {
                firewall_persists: Some(false),
                ..healthy()
            },
        )
        .unwrap();

        assert!(
            check(&report, "firewall-persists")
                .detail
                .contains("netfilter-persistent"),
            "an iptables host was told to enable the nftables unit"
        );
    }

    #[test]
    fn a_console_unit_that_is_installed_but_down_is_critical() {
        let report = assess(
            &db(),
            &Probe {
                unit_active: Some(false),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "service-health");
        assert_eq!(check.level, Level::Critical);
        assert!(check.fix.as_deref().unwrap().contains("systemctl start"));
    }

    /// The `203/EXEC` shape: the unit is up but names a binary that is not
    /// there. Reported against the path, because that is the fact systemd
    /// itself will not tell you.
    #[test]
    fn a_unit_pointing_at_a_missing_binary_is_critical() {
        let probe = Probe {
            unit_active: Some(true),
            unit_binary: Some(PathBuf::from("/root/stop-bots")),
            ..healthy()
        };

        let report = assess(&db(), &probe).unwrap();

        let check = check(&report, "service-health");
        assert_eq!(check.level, Level::Critical);
        assert!(
            check.detail.contains("/root/stop-bots"),
            "was: {}",
            check.detail
        );
    }

    /// A host with no systemd at all is not a broken host.
    #[test]
    fn no_unit_at_all_is_unknown_not_broken() {
        let report = assess(
            &db(),
            &Probe {
                unit_active: None,
                ..healthy()
            },
        )
        .unwrap();
        assert_eq!(check(&report, "service-health").level, Level::Unknown);
    }

    /// The hour a real host spent reporting `SQLITE_FULL`, with the error
    /// naming neither the disk nor the tool.
    #[test]
    fn a_filesystem_with_no_room_for_the_database_is_critical() {
        let report = assess(
            &db(),
            &Probe {
                db_free_bytes: Some(4 * 1024 * 1024),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "disk-room");
        assert_eq!(check.level, Level::Critical);
        assert!(check.detail.contains("4.0MB"), "was: {}", check.detail);
    }

    /// A log the detectors cannot read looks exactly like a log with
    /// nothing in it, which is the quietest way for detection to stop.
    #[test]
    fn an_unreadable_log_source_is_named() {
        let probe = Probe {
            ssh_log_readable: Some(false),
            ..healthy()
        };

        let report = assess(&db(), &probe).unwrap();

        let check = check(&report, "log-sources");
        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("SSH log"), "was: {}", check.detail);
        assert!(
            !check.detail.contains("access log"),
            "was: {}",
            check.detail
        );
    }

    #[test]
    fn a_host_with_nothing_wrong_reports_nothing_wrong() {
        let report = assess(&db(), &healthy()).unwrap();

        // Scanning for sites is the one thing an untouched database has
        // genuinely not done, so that check is expected to complain.
        let unexpected: Vec<&str> = report
            .at_least(Level::Warn)
            .into_iter()
            .filter(|c| c.id != "nginx-applied")
            .map(|c| c.id)
            .collect();
        assert!(
            unexpected.is_empty(),
            "unexpected complaints: {unexpected:?}"
        );
    }

    /// A check that cries wolf on a brand-new database is one nobody reads
    /// on the day it matters. Nothing to render and nothing rendered is a
    /// host that has not been configured yet, not a stale script.
    #[test]
    fn a_fresh_database_is_not_told_its_script_is_stale() {
        let report = assess(&db(), &healthy()).unwrap();

        let check = check(&report, "script-fresh");
        assert_eq!(check.level, Level::Ok, "detail was: {}", check.detail);
        assert!(check.fix.is_none(), "nothing to do, so nothing to suggest");
    }

    /// But rules that exist and have never been rendered *are* stale.
    #[test]
    fn rules_that_were_never_rendered_are_stale() {
        let db = db();
        with_rules(&db, 3);

        let report = assess(&db, &healthy()).unwrap();

        assert_eq!(check(&report, "script-fresh").level, Level::Warn);
    }

    /// `systemctl is-active` says "inactive" both for a stopped unit and
    /// for one that was never installed. Calling a host with no console
    /// "CRITICAL: installed but not running" is the false alarm that gets
    /// a health check muted, so the two are kept apart.
    #[test]
    fn a_host_with_no_console_installed_is_not_reported_as_broken() {
        let report = assess(
            &db(),
            &Probe {
                unit_active: None,
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "service-health");
        assert_eq!(check.level, Level::Unknown);
        assert_ne!(report.worst(), Level::Critical);
    }

    /// A probe survives the round trip, so the dashboards read back what
    /// the cron recorded rather than a default.
    #[test]
    fn a_stored_probe_comes_back_as_it_went_in() {
        let db = db();
        let probe = Probe {
            live_rules: Some(41),
            ..healthy()
        };

        store_probe(&db, &probe).unwrap();

        let (read, at) = cached_probe(&db).unwrap().expect("nothing was stored");
        assert_eq!(read, probe);
        assert!(at > 0, "the timestamp was not recorded");
    }

    /// An upgrade that changes the probe's shape leaves unparsable JSON in
    /// the settings table. Forgetting it beats failing every dashboard
    /// render until someone clears it by hand.
    #[test]
    fn a_probe_that_no_longer_parses_is_forgotten_rather_than_fatal() {
        let db = db();
        db.set_text_setting(PROBE_KEY, r#"{"live_rules": "not a number"}"#)
            .unwrap();

        assert_eq!(cached_probe(&db).unwrap(), None);
        assert_eq!(cached_report(&db).unwrap(), None);
    }

    /// The headline is what a status bar shows, so it has to lead with the
    /// worst thing rather than a count of everything.
    #[test]
    fn the_headline_leads_with_the_worst_level() {
        let db = db();
        with_rules(&db, 5);

        let report = assess(
            &db,
            &Probe {
                live_rules: Some(0),
                ..healthy()
            },
        )
        .unwrap();

        assert!(
            report.headline().contains("CRITICAL"),
            "was: {}",
            report.headline()
        );
        assert_eq!(report.at_least(Level::Critical).len(), 1);
    }

    #[test]
    fn checks_are_ordered_worst_first_when_filtered() {
        let db = db();
        with_rules(&db, 5);
        let probe = Probe {
            live_rules: Some(0),
            firewall_persists: Some(false),
            ..healthy()
        };

        let report = assess(&db, &probe).unwrap();
        let ordered = report.at_least(Level::Warn);

        assert_eq!(ordered.first().unwrap().level, Level::Critical);
    }

    /// The shape `nft list table` really prints, braces and all.
    #[test]
    fn nft_rules_are_counted_and_structure_is_not() {
        let dump = "table inet stop_bots {\n\
                    \tchain input {\n\
                    \t\ttype filter hook input priority filter; policy accept;\n\
                    \t\tip saddr 198.51.100.7 drop\n\
                    \t\tip saddr 203.0.113.0/24 drop\n\
                    \t\tip6 saddr 2001:db8::/32 drop\n\
                    \t}\n\
                    }\n";

        assert_eq!(count_nft_rules(dump), 3);
    }

    /// An empty table is zero rules, not an unreadable ruleset — the
    /// difference between "nothing is enforced" and "I could not look".
    #[test]
    fn an_nft_table_with_no_rules_counts_zero() {
        let dump = "table inet stop_bots {\n\tchain input {\n\t}\n}\n";
        assert_eq!(count_nft_rules(dump), 0);
    }

    /// `-N` creates the chain and is not a rule.
    #[test]
    fn iptables_counts_rules_but_not_the_chain_that_holds_them() {
        let dump = "-N STOP-BOTS\n\
                    -A STOP-BOTS -s 198.51.100.7/32 -j DROP\n\
                    -A STOP-BOTS -s 203.0.113.0/24 -j DROP\n";

        assert_eq!(count_iptables_rules(dump), 2);
    }

    /// The path systemd will execute, which is the one whose absence is
    /// `203/EXEC`.
    #[test]
    fn the_unit_binary_is_read_from_the_path_systemd_will_execute() {
        let shown = "ExecStart={ path=/usr/local/bin/stop-bots ; \
                     argv[]=/usr/local/bin/stop-bots web --db /var/lib/stop-bots/db.sqlite3 ; \
                     ignore_errors=no }";

        assert_eq!(
            parse_exec_start(shown),
            Some(PathBuf::from("/usr/local/bin/stop-bots"))
        );
    }

    #[test]
    fn a_unit_with_no_exec_start_yields_no_binary() {
        assert_eq!(parse_exec_start("ExecStart="), None);
        assert_eq!(parse_exec_start(""), None);
    }

    /// The size check reports rather than judges on an ordinary database,
    /// and the number it reports is the one an admin would get from `du`.
    #[test]
    fn database_size_reports_an_ordinary_database_without_complaint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ordinary.sqlite3");
        let db = Db::open(&path).unwrap();

        let check = database_size(&db).unwrap();

        assert_eq!(check.level, Level::Ok);
        assert!(check.fix.is_none());
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            check.detail,
            human_bytes(on_disk),
            "the check should report the size the filesystem reports"
        );
    }

    /// Slack is named separately from the total, because the two prompt
    /// different actions: a large total is something to investigate, a
    /// large reclaimable share is something the next maintenance run
    /// simply fixes.
    #[test]
    fn database_size_names_reclaimable_space_when_there_is_any() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(dir.path().join("slack.sqlite3")).unwrap();
        // Long user agents, few inserts — see the note in
        // `db::tests::vacuum_returns_pruned_space_to_the_filesystem`.
        let mut counts = std::collections::HashMap::new();
        for n in 0..40 {
            counts.insert(format!("agent-{n}-{}", "x".repeat(4_000)), 1);
        }
        db.record_user_agent_hits(&counts, 1_000).unwrap();
        db.prune_user_agent_stats(2_000, usize::MAX).unwrap();

        let check = database_size(&db).unwrap();

        assert_eq!(check.level, Level::Ok);
        assert!(
            check.detail.contains("reclaimable"),
            "freed pages should be visible: {}",
            check.detail
        );
    }

    #[test]
    fn database_size_says_so_for_an_in_memory_database() {
        let check = database_size(&Db::open_in_memory().unwrap()).unwrap();

        assert_eq!(check.level, Level::Ok);
        assert_eq!(check.detail, "in memory");
    }

    #[test]
    fn human_bytes_reads_as_a_person_would_write_it() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(512), "512.0B");
        assert_eq!(human_bytes(1536), "1.5KB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0GB");
    }
}
