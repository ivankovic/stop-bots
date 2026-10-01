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
    /// Whether something will re-apply *this project's* rules after a
    /// reboot. `None` when it could not be determined. See
    /// [`firewall_persists`] for why the two backends are asked different
    /// questions.
    pub firewall_persists: Option<bool>,
    /// Whether `/etc/nftables.conf` opens with `flush ruleset`, which
    /// decides whether enabling `nftables.service` is safe to suggest on
    /// this host. `None` when the file could not be read.
    pub nftables_conf_flushes: Option<bool>,
    /// `systemctl is-active` for the console's unit, when there is one.
    pub unit_active: Option<bool>,
    /// The binary the unit's `ExecStart` names, if a unit exists.
    pub unit_binary: Option<PathBuf>,
    /// Bytes free on the filesystem holding the database.
    pub db_free_bytes: Option<u64>,
    /// Whether each log source could actually be read.
    pub ssh_log_readable: Option<bool>,
    pub access_log_readable: Option<bool>,
    /// The access log that was actually tried, so a failure can name it.
    /// "unreadable" without a path is the least actionable thing a check
    /// can say: the operator's next question is always which file.
    #[serde(default)]
    pub access_log_path: Option<String>,
    /// Which user agents the blocking policy turned away in the access
    /// log this probe read, with how much each still had served. Empty
    /// when the log could not be read.
    #[serde(default)]
    pub turned_away: Vec<crate::accesslog::TurnedAway>,
    /// The `conf.d` the generated `http`-context files go into, named so
    /// that a check can say which directory it means — for the reason
    /// [`Self::access_log_path`] is carried.
    #[serde(default)]
    pub conf_d_path: Option<String>,
    /// Whether that directory exists. `None` when it could not be asked.
    #[serde(default)]
    pub conf_d_exists: Option<bool>,
    /// Generated files found in the *stock* `conf.d` while the active one
    /// is somewhere else.
    ///
    /// Not tidiness. Before 0.0.9 these were written to a fixed
    /// `/etc/nginx/conf.d` whatever `nginx:root` said, so upgrading a host
    /// whose NGINX reads its config from elsewhere leaves a full set
    /// behind — and `unused_managed_files` will never collect them, since
    /// it now looks in the right place.
    #[serde(default)]
    pub stray_generated_files: Vec<String>,
    /// Where the NGINX that serves this host's config actually runs.
    pub nginx_home: NginxHome,
    /// Whether [`crate::nginx::managed_dir`] resolves, at the same path,
    /// *inside* the container. `None` when there is no container to ask.
    ///
    /// The generated config names that directory absolutely — the
    /// `robots.txt` alias and the blocked-agent map both do — and NGINX
    /// resolves it against whatever filesystem it is running on. A bind
    /// mount at a different path, or no bind mount at all, leaves those
    /// directives pointing at nothing.
    pub managed_dir_in_container: Option<bool>,
    /// Whether that container shares the host's network namespace, in
    /// which case `127.0.0.1` means the same thing on both sides and the
    /// generated `proxy_pass` needs no special address.
    pub container_shares_host_network: Option<bool>,
    /// Whether the *loaded* ruleset polices forwarded traffic as well as
    /// traffic addressed to the host. `None` when it could not be read.
    ///
    /// Not the same question as [`Self::live_rules`]. A ruleset rendered
    /// before this project covered the forward path loads cleanly and
    /// counts the right number of rules, while enforcing none of them for
    /// anything behind a published container port.
    pub firewall_covers_forward: Option<bool>,
    /// `(public, parsed)` client addresses in the access log's tail — see
    /// [`crate::accesslog::Survey::public`]. `None` when the log could not
    /// be read, which [`log_sources`] already reports.
    pub access_log_clients: Option<(usize, usize)>,
    /// `(lines, parsed)`: how many non-empty lines the access log's tail
    /// held, and how many of them are in a format the detectors read.
    /// `None` when the log could not be read. See [`access_log_format`].
    #[serde(default)]
    pub access_log_lines: Option<(usize, usize)>,
    /// The first line of that tail that did not parse, cut short and with
    /// its control characters replaced (it is the client's text).
    #[serde(default)]
    pub access_log_unparsed_sample: Option<String>,
    /// Of the public lines in [`Self::access_log_clients`], how many came
    /// from a CDN's edge addresses. `None` when the log could not be read.
    #[serde(default)]
    pub access_log_cdn: Option<usize>,
    /// Who the running console is, as the kernel has it: the effective
    /// uid and every group its process holds. `None` when no console unit
    /// is running, or it could not be read.
    #[serde(default)]
    pub console_identity: Option<crate::account::Identity>,
    /// Whether the running console was handed the root helper's socket
    /// (`--helper` in its `ExecStart`) and that socket is listening.
    /// `None` when no console unit is running.
    #[serde(default)]
    pub console_helper: Option<bool>,
    /// The logs this host is configured to read that the running
    /// console's process cannot — the access log, and the SSH log or the
    /// journal. Asked from root, for the console's uid and groups, since
    /// root itself can read everything.
    #[serde(default)]
    pub console_unreadable_logs: Vec<String>,
}

/// How much of the access log a probe reads: its last 32 MB. Every
/// question the probe asks of the log (which formats it holds, whose
/// addresses it records, whom it turns away) a recent sample answers as
/// well as the whole file, and the whole file was the one expensive thing
/// in a probe: on a 1 GB server, a 200 MB log read into memory twice over.
pub const ACCESS_LOG_SAMPLE_BYTES: u64 = 32 * 1024 * 1024;

/// Where the NGINX serving this host's config runs, as far as this host
/// can tell from outside it.
///
/// Deliberately has no "not sure, probably fine" variant that any check
/// reports on. Every ordinary install lands on `Host` or `Unclear`, and
/// both are silent: a check that fires on hosts with nothing wrong is one
/// nobody reads on the day it matters, which is the argument
/// [`LARGE_DB_BYTES`] makes at length a few lines below.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum NginxHome {
    /// A `systemctl is-active nginx` that answers "active". Named that way
    /// round on purpose: the default reload command *is* `systemctl reload
    /// nginx`, so this is not a guess about where NGINX lives, it is the
    /// direct question of whether the configured command reaches it.
    Host,
    /// No active host unit, and a running container whose image or command
    /// says NGINX.
    Container { name: String },
    /// Neither could be established — no host unit, and no container to
    /// find, or no Docker to ask. Reported on by nothing.
    ///
    /// The default, which is also what a probe cached by an older version
    /// deserialises to: `Probe` carries `#[serde(default)]` so a stored
    /// probe from before this field existed still parses, and lands on the
    /// variant that says nothing rather than one that accuses the host of
    /// something.
    #[default]
    Unclear,
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

/// The last [`ACCESS_LOG_SAMPLE_BYTES`] of the access log at `path`, read
/// through a [`crate::accesslog::Survey`], or `None` if it cannot be read.
fn access_log_sample(path: &Path, block_status: u16) -> Option<crate::accesslog::Survey> {
    let mut survey = crate::accesslog::Survey::new(block_status);
    crate::logread::read_tail(path, ACCESS_LOG_SAMPLE_BYTES, &mut |line| survey.line(line)).ok()?;
    Some(survey)
}

/// Runs everything that needs a subprocess or the filesystem.
///
/// Never fails: a probe that cannot answer a question leaves that field
/// `None`, because "I could not check" is a result the report has to be
/// able to show. An error here would mean no report at all, which is the
/// least useful outcome available.
pub fn probe(
    backend: FirewallBackend,
    db_path: &Path,
    ssh_log: Option<&Path>,
    paths: &crate::logpaths::LogPaths,
    conf_d: &Path,
    block_status: u16,
) -> Probe {
    let live = live_firewall(backend);
    let (live_rules, live_backend) = match &live {
        Some(state) => (Some(state.rules), Some(backend.stored().to_string())),
        None => (None, None),
    };
    // Read once, and only the tail, and every access-log question answered
    // from that one pass: two reads would be two different moments.
    let sample = access_log_sample(&paths.access_path(None), block_status);
    let access_readable = sample.is_some();
    let survey = sample.unwrap_or_default();
    let nginx_home = nginx_home();
    let unit_active = unit_is_active();
    let console = unit_active
        .filter(|active| *active)
        .and_then(|_| console_identity());
    let container = match &nginx_home {
        NginxHome::Container { name } => Some(name.clone()),
        _ => None,
    };
    Probe {
        live_rules,
        live_backend,
        // From the same read as every other access-log answer below.
        turned_away: survey.turned_away(),
        conf_d_path: Some(conf_d.display().to_string()),
        conf_d_exists: Some(conf_d.is_dir()),
        stray_generated_files: stray_generated_files(conf_d, Path::new(crate::nginx::CONF_D_DIR)),
        firewall_persists: firewall_persists(backend),
        nftables_conf_flushes: nftables_conf_flushes(),
        unit_active,
        unit_binary: unit_binary(),
        console_helper: console.as_ref().map(|_| console_has_helper()),
        console_unreadable_logs: console
            .as_ref()
            .map(|who| unreadable_logs(who, paths, ssh_log))
            .unwrap_or_default(),
        console_identity: console,
        db_free_bytes: free_bytes(db_path),
        // Asked, not read: this used to read the whole log, which on a
        // journald host was the whole sshd journal, once an hour.
        ssh_log_readable: Some(paths.ssh(ssh_log).is_readable()),
        access_log_readable: Some(access_readable),
        access_log_path: Some(paths.access_description(None)),
        access_log_clients: access_readable.then_some((survey.public, survey.counts.parsed)),
        access_log_lines: access_readable.then_some((survey.counts.lines, survey.counts.parsed)),
        access_log_unparsed_sample: survey.unparsed_sample.clone(),
        access_log_cdn: access_readable.then_some(survey.cdn),
        nginx_home,
        managed_dir_in_container: container.as_ref().map(|name| {
            // `test -d` inside the container, at the path the generated
            // config names. Anything other than a clean exit — no such
            // path, no shell, container gone between the two calls — is a
            // "no", because every one of those means the directive would
            // not resolve either.
            run_ok(
                "docker",
                &[
                    "exec",
                    name,
                    "test",
                    "-d",
                    &crate::nginx::managed_dir().to_string_lossy(),
                ],
            )
        }),
        firewall_covers_forward: live.as_ref().map(|state| state.covers_forward),
        container_shares_host_network: container.as_ref().map(|name| {
            run_allowing_failure(
                "docker",
                &["inspect", "-f", "{{.HostConfig.NetworkMode}}", name],
            )
            .is_some_and(|mode| mode.trim() == "host")
        }),
    }
}

/// Generated files sitting in the stock `conf.d` while the active one is
/// elsewhere — see [`Probe::stray_generated_files`].
///
/// Only the three this project generates, by name. A directory listing
/// would be the wrong instrument: on a host that really does run a second
/// NGINX from the stock tree, everything else in there belongs to someone
/// else.
fn stray_generated_files(conf_d: &Path, stock: &Path) -> Vec<String> {
    // Compared after resolving links, because the obvious workaround for
    // the bug this catches is to point the stock path at the real one --
    // and then the "stranded" file and the live one are the same file, and
    // reporting it would send an operator to delete their own config.
    // Falling back to a literal comparison keeps this answerable on a host
    // where neither path exists yet.
    let same = match (conf_d.canonicalize(), stock.canonicalize()) {
        (Ok(active), Ok(stock)) => active == stock,
        _ => conf_d == stock,
    };
    if same {
        return Vec::new();
    }
    [
        "stop-bots-trusted.conf",
        "stop-bots-limits.conf",
        "stop-bots-limits-untrusted.conf",
    ]
    .into_iter()
    .map(|name| stock.join(name))
    .filter(|path| path.exists())
    .map(|path| path.display().to_string())
    .collect()
}

/// Whether `program` ran and exited zero. A program that could not be
/// spawned at all is a `false`, not a panic: on a host with no Docker
/// this is the ordinary path.
fn run_ok(program: &str, args: &[&str]) -> bool {
    Command::new(crate::host::program(program))
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Where NGINX runs — see [`NginxHome`].
///
/// Asks the host question first and only reaches for Docker if the answer
/// is no, so a normal install never runs `docker ps` at all.
fn nginx_home() -> NginxHome {
    if run_allowing_failure("systemctl", &["is-active", "nginx"])
        .is_some_and(|state| state.trim() == "active")
    {
        return NginxHome::Host;
    }
    match nginx_container() {
        Some(name) => NginxHome::Container { name },
        None => NginxHome::Unclear,
    }
}

/// The name of a running container that appears to be NGINX.
///
/// Matches on the image or the entrypoint rather than the container's
/// name, which is whatever the operator called it. Takes the first match:
/// a host running two NGINX containers is past what one health check can
/// usefully say, and reporting on one of them is better than reporting on
/// neither.
fn nginx_container() -> Option<String> {
    let listed = run_allowing_failure(
        "docker",
        &["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Command}}"],
    )?;
    listed.lines().find_map(|line| {
        let mut fields = line.split('\t');
        let name = fields.next()?;
        let rest = fields.collect::<Vec<_>>().join(" ").to_lowercase();
        (rest.contains("nginx") && !name.is_empty()).then(|| name.to_string())
    })
}

/// What this project has loaded in the kernel right now, from one look.
///
/// Both fields come from the same read, deliberately. They used to be two
/// functions issuing the same two `nft` calls each, which is two moments
/// as well as twice the work — and a report that says "10 rules loaded"
/// about one moment and "the forward path is covered" about another is
/// describing a ruleset that may never have existed.
///
/// Counts only our own table or chain. The host's other firewall rules are
/// none of this tool's business, and a count of the whole ruleset would
/// answer a different question.
struct LiveFirewall {
    rules: usize,
    /// Whether the loaded ruleset polices forwarded traffic as well as
    /// traffic addressed to the host. The rule *count* cannot answer this:
    /// a ruleset generated before this project covered the forward hook
    /// loads cleanly and counts exactly right while enforcing nothing for
    /// a containerised service. See the module docs in [`crate::nftables`].
    covers_forward: bool,
}

/// Reads it, or `None` when the tool could not be run at all.
fn live_firewall(backend: FirewallBackend) -> Option<LiveFirewall> {
    // The distinction that matters, and the one a bare exit status
    // destroys: "the tool would not run" is unknown, while "the tool ran
    // and our table is not there" is *zero rules loaded* — which is the
    // critical case this whole module exists to catch. Both make
    // `nft list table` exit non-zero.
    match backend {
        FirewallBackend::Nftables => {
            // Cheap — just the table names. Succeeding proves `nft` is
            // usable and we may read the ruleset; our table's absence from
            // the list then means zero, not unknown.
            let tables = run("nft", &["list", "tables"])?;
            if !tables
                .lines()
                .any(|line| line.trim() == "table inet stop_bots")
            {
                return Some(LiveFirewall {
                    rules: 0,
                    covers_forward: false,
                });
            }
            let dump = run("nft", &["list", "table", "inet", "stop_bots"])?;
            Some(LiveFirewall {
                rules: count_nft_rules(&dump),
                covers_forward: dump.contains("hook forward"),
            })
        }
        FirewallBackend::Iptables => {
            let rules = match run("iptables", &["-S", "STOP-BOTS"]) {
                Some(output) => count_iptables_rules(&output),
                // Listing a chain that certainly exists separates "no
                // permission" from "no STOP-BOTS chain yet".
                None => {
                    run("iptables", &["-S", "INPUT"])?;
                    0
                }
            };
            // The script loads IPv6 rules into the same chain in
            // ip6tables. Absent (no chain yet, or no IPv6 on this kernel)
            // counts as none rather than as not knowing: the IPv4 read
            // above already proved we may look.
            let rules = rules
                + run("ip6tables", &["-S", "STOP-BOTS"])
                    .map(|output| count_iptables_rules(&output))
                    .unwrap_or(0);
            // Unlike nftables, the jump lives in a chain we do not own, so
            // this is a second read however it is arranged. Either jump
            // reaches our chain, and which one is present depends on
            // whether Docker was running when the script was applied.
            let forward = run("iptables", &["-S", "FORWARD"])?;
            let covers_forward = forward
                .lines()
                .any(|line| line.trim() == "-A FORWARD -j STOP-BOTS")
                || run_allowing_failure("iptables", &["-S", "DOCKER-USER"]).is_some_and(|dump| {
                    dump.lines()
                        .any(|line| line.trim() == "-A DOCKER-USER -j STOP-BOTS")
                });
            Some(LiveFirewall {
                rules,
                covers_forward,
            })
        }
    }
}

/// What an `nft list table` dump holds: the rule lines that carry a
/// verdict, plus the elements of every named set. The table, chain, brace
/// and set-header lines are structure, not rules.
///
/// A rule that matches a named set (`ip saddr @block_v4 drop`) is not
/// counted itself: its elements are, since each is what one rule used to
/// be, and the script puts one element in the kernel for each entry it
/// reports writing. A dump from before sets has no elements and counts
/// the way it always did.
///
/// Split out from the subprocess so the parsing — the part that breaks
/// when a tool changes its output — is testable in microseconds. The
/// plumbing around it is covered by the container suite, against a real
/// `nft`.
fn count_nft_rules(output: &str) -> usize {
    let mut count = 0;
    let mut in_elements = false;
    for line in output.lines() {
        let line = line.trim();
        let listed = if in_elements {
            Some(line)
        } else {
            line.strip_prefix("elements = {")
        };
        if let Some(listed) = listed {
            // `elements = { a, b,` then `c timeout 1d expires 23h, d }`:
            // one element per comma-separated item, over as many lines as
            // nft wraps them onto.
            in_elements = !listed.ends_with('}');
            count += listed
                .trim_end_matches('}')
                .split(',')
                .filter(|item| !item.trim().is_empty())
                .count();
            continue;
        }
        let verdict = line.ends_with("drop")
            || line.ends_with("accept")
            || line.ends_with("return")
            // `reject` is listed with what it answers:
            // `reject with icmpx port-unreachable`.
            || line.ends_with("reject")
            || line.contains(" reject with ");
        if verdict && !line.contains(" @") {
            count += 1;
        }
    }
    count
}

/// `iptables -S` prints one `-A STOP-BOTS ...` per rule, plus an `-N` line
/// that creates the chain and is not one.
fn count_iptables_rules(output: &str) -> usize {
    output
        .lines()
        .filter(|line| line.trim_start().starts_with("-A"))
        .count()
}

/// Whether a unit is enabled. `None` means the question could not be
/// answered: `is-enabled` exits non-zero for a unit that is merely
/// disabled, so the status cannot tell that apart from "no such unit" —
/// the printed word can, and an empty answer is the one that means unknown.
fn unit_enabled(unit: &str) -> Option<bool> {
    let state = run_allowing_failure("systemctl", &["is-enabled", unit])?;
    match state.trim() {
        "" => None,
        "enabled" | "enabled-runtime" => Some(true),
        _ => Some(false),
    }
}

/// Debian's stock `/etc/nftables.conf`, which `nftables.service` loads.
const NFTABLES_CONF: &str = "/etc/nftables.conf";

/// Whether `/etc/nftables.conf` re-applies *this project's* script, by
/// naming it in an `include`. `None` when the file could not be read.
fn nftables_conf_includes_script() -> Option<bool> {
    let script = crate::firewall::default_output_path(FirewallBackend::Nftables);
    let conf = std::fs::read_to_string(NFTABLES_CONF).ok()?;
    Some(
        conf.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .any(|l| l.starts_with("include") && l.contains(&script.display().to_string())),
    )
}

/// Whether `/etc/nftables.conf` begins by flushing the whole ruleset —
/// which Debian's stock file does. `None` when it could not be read.
///
/// This decides whether `systemctl enable nftables.service` is safe to
/// suggest. On a host where nothing else manages nftables it is harmless.
/// On one where ufw, Docker or a geo-blocker do, a boot-time `flush
/// ruleset` takes all of them out and replaces them with whatever that
/// file declares.
fn nftables_conf_flushes() -> Option<bool> {
    let conf = std::fs::read_to_string(NFTABLES_CONF).ok()?;
    Some(
        conf.lines()
            .map(str::trim)
            .any(|l| l.starts_with("flush ruleset")),
    )
}

/// Whether *this project's* rules will still be there after a reboot.
///
/// The two backends need different questions asked, and asking the
/// iptables one of nftables is how this check used to report OK on a host
/// that came back up with nothing.
///
/// `netfilter-persistent` saves and restores the **live** ruleset, so
/// whatever this project put in it is in what gets saved: the unit being
/// enabled really does answer the question.
///
/// `nftables.service` does not. It loads a **static file**,
/// `/etc/nftables.conf`, and this project writes
/// `/etc/stop-bots/firewall.nft`. Enabling it reloads somebody else's
/// ruleset and says nothing whatever about ours — so for nftables the
/// question is whether anything re-applies *our* script: the unit
/// `stop-bots install firewall` writes, or an `include` of it in
/// `/etc/nftables.conf`.
///
/// For iptables, the unit `install firewall` writes is an answer too now
/// that it follows the backend and re-runs the iptables script at boot.
fn firewall_persists(backend: FirewallBackend) -> Option<bool> {
    match backend {
        FirewallBackend::Iptables => {
            if unit_enabled(crate::install::FIREWALL_UNIT) == Some(true) {
                return Some(true);
            }
            unit_enabled("netfilter-persistent.service")
        }
        FirewallBackend::Nftables => {
            if unit_enabled(crate::install::FIREWALL_UNIT) == Some(true) {
                return Some(true);
            }
            // Falling back to the unit's answer when the file cannot be
            // read keeps "could not tell" distinct from "no".
            match nftables_conf_includes_script() {
                Some(true) => Some(true),
                Some(false) => Some(false),
                None => unit_enabled(crate::install::FIREWALL_UNIT),
            }
        }
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

/// The running console's uid and groups, from its process's
/// `/proc/<pid>/status` — what it actually holds, which is what decides
/// what it can read, whatever its unit says.
fn console_identity() -> Option<crate::account::Identity> {
    let pid = run(
        "systemctl",
        &["show", crate::install::WEB_UNIT, "-p", "MainPID", "--value"],
    )?;
    let pid: u32 = pid.trim().parse().ok().filter(|pid| *pid != 0)?;
    parse_proc_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// The effective uid and gid, and the supplementary groups, out of a
/// `/proc/<pid>/status`.
fn parse_proc_status(status: &str) -> Option<crate::account::Identity> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|rest| {
                rest.split_whitespace()
                    .filter_map(|word| word.parse::<u32>().ok())
                    .collect::<Vec<u32>>()
            })
    };
    // Real, effective, saved and filesystem: the second is the one the
    // kernel checks a read against (strictly the fourth, which follows it).
    let uid = *field("Uid:")?.get(1)?;
    let gid = *field("Gid:")?.get(1)?;
    let mut gids = vec![gid];
    for group in field("Groups:").unwrap_or_default() {
        if !gids.contains(&group) {
            gids.push(group);
        }
    }
    Some(crate::account::Identity { uid, gids })
}

/// Whether the console's unit hands it the helper's socket, and the
/// socket is listening. A console without one shows the host and applies
/// nothing.
fn console_has_helper() -> bool {
    let named = run(
        "systemctl",
        &["show", crate::install::WEB_UNIT, "-p", "ExecStart"],
    )
    .is_some_and(|shown| shown.contains(" --helper "));
    let listening = run_allowing_failure(
        "systemctl",
        &["is-active", crate::install::HELPER_SOCKET_UNIT],
    )
    .is_some_and(|state| state.trim() == "active");
    named && listening
}

/// The logs the host is set up to read that `who` cannot read.
fn unreadable_logs(
    who: &crate::account::Identity,
    paths: &crate::logpaths::LogPaths,
    ssh_log: Option<&Path>,
) -> Vec<String> {
    let mut logs = vec![paths.access_path(None)];
    match paths.ssh(ssh_log).locate() {
        crate::sshlog::Located::File(path) => logs.push(path),
        crate::sshlog::Located::Journal => logs.extend(system_journal()),
    }
    logs.into_iter()
        .filter(|log| crate::account::readable_by(log, who) == Some(false))
        .map(|log| log.display().to_string())
        .collect()
}

/// The system journal's active file, persistent or volatile, which is
/// what `journalctl` has to open to read sshd's lines.
fn system_journal() -> Option<PathBuf> {
    ["/var/log/journal", "/run/log/journal"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flat_map(|entries| entries.filter_map(|entry| entry.ok()))
        .map(|entry| entry.path().join("system.journal"))
        .find(|file| file.is_file())
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
    let out = run("df", &df_args(&dir.to_string_lossy()))?;
    out.lines().nth(1)?.trim().parse().ok()
}

/// `df`'s arguments for `dir`, with `--` before it so a path beginning
/// with `-` is a path and not an option.
fn df_args(dir: &str) -> [&str; 4] {
    ["--output=avail", "-B1", "--", dir]
}

/// Runs `program`, found by [`crate::host::program`] — the health check is
/// what cron runs hourly, and cron's `PATH` has no `/usr/sbin`, where `nft`
/// and `iptables` live. Asking a program that cannot be found reads as
/// "could not tell", which is how every firewall check on such a host
/// ended up.
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(crate::host::program(program))
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// The same, but a non-zero exit still yields whatever was printed —
/// `systemctl is-active` reports the state on stdout *and* exits non-zero
/// when that state is not "active".
fn run_allowing_failure(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(crate::host::program(program))
        .args(args)
        .output()
        .ok()?;
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
    let rules = firewall::all_rules(db)?;
    let expected = rules.len();

    // What the kernel should hold, which is not `expected`: a set leaves
    // out an address a range already covers, and nothing disabled or
    // expired is loaded. Compared against the rule count, a host with
    // overlapping feeds would read as a ruleset that is behind.
    let loadable = firewall::loaded_entries(&rules, backend, now_secs());
    let applied = db.get_firewall_applied_signature()?.as_deref()
        == Some(firewall::rules_signature(&rules).as_str());
    checks.push(firewall_enforced(probe, loadable, applied));
    checks.push(firewall_persistence(probe, backend));
    checks.push(script_freshness(db, expected, backend)?);
    checks.push(nginx_applied(db)?);
    checks.push(generated_files_reachable(probe));
    checks.push(service_health(probe));
    checks.extend(console_account(probe));
    checks.extend(console_helper(probe));
    checks.extend(console_log_access(probe));
    checks.push(disk_room(probe));
    checks.push(database_size(db)?);
    checks.push(log_sources(probe));
    checks.push(access_log_format(probe));
    checks.push(access_log_clients(probe));
    if let Some(check) = cdn_edges(probe) {
        checks.push(check);
    }
    checks.push(ssh_login_allowlist(db)?);
    if let Some(check) = trusted_by_hand(db)? {
        checks.push(check);
    }
    if let Some(check) = skipped_entries(db)? {
        checks.push(check);
    }
    if let Some(check) = turned_away_clients(db, probe)? {
        checks.push(check);
    }
    // Adds a line only on a host where NGINX really is in a container.
    if let Some(check) = firewall_reaches_containers(probe) {
        checks.push(check);
    }
    if let Some(check) = nginx_deployment(db, probe)? {
        checks.push(check);
    }
    if let Some(check) = console_proxy(db)? {
        checks.push(check);
    }

    Ok(Report {
        checks,
        checked_at: now_secs(),
    })
}

/// How few refusals are worth a line. Low on purpose: a first-party app
/// that cannot reach its server retries, so a real one clears this in
/// minutes, and the cost of a false positive is one line naming a client
/// the operator recognises.
const TURNED_AWAY_MIN_REFUSALS: u64 = 5;

/// Clients the blocking policy is turning away that this host has seen
/// working before.
///
/// The check exists because of how the three real cases were found: not
/// here, but by a person saying an app had stopped working. Nextcloud on
/// iOS, Nextcloud on Android and Jellyfin on a Fire TV, over one week on
/// one host, all three matching `okhttp` in a public bad-bot list. Every
/// one of them was visible in the access log from the first minute.
///
/// **Only agents with recorded successful hits**, from
/// [`Db::user_agent_stat`], rather than everything being refused. A
/// blocking policy turning away bots is the policy working; a client that
/// this host has previously served and is now refusing is a regression,
/// and that is the distinction worth waking someone for. The cost of
/// keying on the exact agent string is that a client which changed version
/// between the last recorded hit and the block will not match -- it reads
/// as a new agent, and goes unreported here while still appearing in
/// `list-turned-away`.
///
/// Absent rather than "nothing to report" when there is nothing, like its
/// neighbours: a line saying so on every healthy host is noise.
fn turned_away_clients(db: &Db, probe: &Probe) -> Result<Option<Check>> {
    let mut regressions: Vec<&crate::accesslog::TurnedAway> = Vec::new();
    for entry in &probe.turned_away {
        if entry.refused < TURNED_AWAY_MIN_REFUSALS {
            continue;
        }
        if db.user_agent_stat(&entry.user_agent)?.is_some() {
            regressions.push(entry);
        }
    }
    if regressions.is_empty() {
        return Ok(None);
    }
    let named: Vec<String> = regressions
        .iter()
        .take(3)
        // The agent is a client's text, and this line is drawn in the
        // console's header on every page: capped, and with anything
        // invisible written out.
        .map(|entry| {
            let (shown, _) = crate::uadetail::for_display(&entry.user_agent);
            format!("{shown} ({} refused)", entry.refused)
        })
        .collect();
    let more = regressions.len().saturating_sub(named.len());
    let suffix = if more > 0 {
        format!(", and {more} more")
    } else {
        String::new()
    };
    Ok(Some(Check {
        id: "turned-away-clients",
        title: "Clients this host used to serve",
        level: Level::Warn,
        detail: format!(
            "{} user agent(s) with successful requests on record are now being turned away: {}{}",
            regressions.len(),
            named.join(", "),
            suffix
        ),
        fix: Some(
            "see them all with `stop-bots list-turned-away`, and allow one with \
             `stop-bots trust --user-agent \"<part of the agent>\"`"
                .to_string(),
        ),
    }))
}

/// Whether the files NGINX has to read for the generated blocks to work
/// are somewhere NGINX actually reads.
///
/// The blocks reference `$stop_bots_trusted` and `limit_req zone=...`;
/// both are defined in `http`-context files in `conf.d`, and NGINX does
/// not degrade when one is missing — it refuses to load the config at
/// all, so a single wrong directory takes down every site on the host at
/// the next reload or restart. That is not a hypothetical: it is what
/// this check was written after.
fn generated_files_reachable(probe: &Probe) -> Check {
    let where_it_writes = probe
        .conf_d_path
        .as_deref()
        .unwrap_or(crate::nginx::CONF_D_DIR);
    let (level, detail, fix) = if !probe.stray_generated_files.is_empty() {
        (
            Level::Warn,
            format!(
                "writing to {where_it_writes}, but an older version left {} file(s) in {}: {}",
                probe.stray_generated_files.len(),
                crate::nginx::CONF_D_DIR,
                probe.stray_generated_files.join(", ")
            ),
            Some(format!(
                "delete them — nothing collects them now, and on a host that also runs an NGINX \
                 from {} they are live config nobody meant to write",
                crate::nginx::CONF_D_DIR
            )),
        )
    } else {
        match probe.conf_d_exists {
            None => (
                Level::Unknown,
                format!("could not tell whether {where_it_writes} exists"),
                None,
            ),
            Some(false) => (
                Level::Warn,
                format!("{where_it_writes} does not exist"),
                Some(
                    "check `nginx:root` — the generated files go in `conf.d` under it, and NGINX \
                     has to be the one reading that directory"
                        .to_string(),
                ),
            ),
            Some(true) => (Level::Ok, format!("writing to {where_it_writes}"), None),
        }
    };
    Check {
        id: "generated-files-reachable",
        title: "Generated files are where NGINX reads them",
        level,
        detail,
        fix,
    }
}

/// The check this module exists for.
///
/// `applied` is whether the configured rules are the ones last applied.
/// When they are not, a kernel short of `expected` is the rules waiting to
/// be applied — `script-fresh` says that, once — rather than a ruleset
/// something took rules out of, which is what this check is for.
fn firewall_enforced(probe: &Probe, expected: usize, applied: bool) -> Check {
    let apply =
        "press \u{201c}Apply everything\u{201d}, or run `stop-bots render-firewall --apply`";
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
            Some(apply.to_string()),
        ),
        // Exact equality is the wrong test: the rendered script also
        // carries structural rules, and the ruleset can legitimately gain
        // a rule between a render and a look. What matters is whether the
        // kernel is carrying roughly what was generated, or a fraction of
        // it.
        Some(live) if live * 10 < expected * 9 && !applied => (
            Level::Ok,
            format!("{live} rule(s) loaded; the rest are configured and not applied yet"),
            None,
        ),
        Some(live) if live * 10 < expected * 9 => (
            Level::Warn,
            format!(
                "{live} rule(s) loaded, {expected} applied — something removed rules from the \
                 kernel since"
            ),
            Some(format!("apply again to catch the kernel up: {apply}")),
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

/// Whether the loaded ruleset actually reaches the containerised service
/// this host is running.
///
/// The failure this exists for is the quietest one in the project. A
/// ruleset rendered before the forward hook was covered loads cleanly,
/// carries the right number of rules, and satisfies every other firewall
/// check on this panel — while a packet for a published container port is
/// DNAT'd straight past the only chain that was looking at it. "Firewall
/// rules are in the kernel" says Ok; nothing is enforced.
///
/// Reported only where NGINX is in a container, because that is where the
/// answer changes anything. On a host-NGINX box the forward hook carries
/// no traffic this project has an opinion about, and a warning there is a
/// warning nobody can act on.
///
/// Silent, too, when no rules are loaded at all: that is
/// [`firewall_enforced`]'s Critical, and saying it twice in one report
/// teaches the reader to skim.
fn firewall_reaches_containers(probe: &Probe) -> Option<Check> {
    let NginxHome::Container { name } = &probe.nginx_home else {
        return None;
    };
    // Nothing loaded is a different check's problem.
    if !matches!(probe.live_rules, Some(count) if count > 0) {
        return None;
    }

    Some(if probe.firewall_covers_forward? {
        Check {
            id: "firewall-reaches-containers",
            title: "Blocks reach the container",
            level: Level::Ok,
            detail: format!(
                "the ruleset polices forwarded traffic, so blocks apply to `{name}` as well as to this host"
            ),
            fix: None,
        }
    } else {
        Check {
            id: "firewall-reaches-containers",
            title: "Blocks reach the container",
            level: Level::Critical,
            detail: format!(
                "NGINX is in container `{name}`, and the loaded ruleset only polices traffic to this host \u{2014} traffic to a published port is forwarded past it, so no block applies to it"
            ),
            fix: Some(
                "re-render and re-run the generated script (the rendered one covers both paths)"
                    .to_string(),
            ),
        }
    })
}

fn firewall_persistence(probe: &Probe, backend: FirewallBackend) -> Check {
    let script = crate::firewall::default_output_path(backend);
    let script = script.display();
    let (level, detail, fix) = match (backend, probe.firewall_persists) {
        (_, None) => (
            Level::Unknown,
            "could not tell whether anything re-applies the rules at boot".to_string(),
            None,
        ),

        // `netfilter-persistent` saves the live ruleset, so it carries ours.
        (FirewallBackend::Iptables, Some(true)) => (
            Level::Ok,
            "netfilter-persistent.service will restore them".to_string(),
            None,
        ),
        (FirewallBackend::Iptables, Some(false)) => (
            Level::Warn,
            "netfilter-persistent.service is not enabled — a reboot comes back with no rules"
                .to_string(),
            Some("systemctl enable netfilter-persistent.service".to_string()),
        ),

        (FirewallBackend::Nftables, Some(true)) => {
            (Level::Ok, format!("{script} is re-applied at boot"), None)
        }
        (FirewallBackend::Nftables, Some(false)) => (
            Level::Warn,
            format!("nothing re-applies {script} at boot — a reboot comes back with no rules"),
            // Deliberately NOT `systemctl enable nftables.service`. That
            // unit loads /etc/nftables.conf, which is a different file
            // from the one this project writes, so enabling it would not
            // restore these rules — and on a host where Debian's stock
            // `flush ruleset` is still at the top of that file, it would
            // take out whatever else manages the ruleset (ufw, Docker, a
            // geo-blocker) on every boot.
            Some(match probe.nftables_conf_flushes {
                Some(true) => format!(
                    "stop-bots install firewall  (do NOT enable nftables.service: \
                     {NFTABLES_CONF} starts with `flush ruleset`, which would drop \
                     every other table on this host at boot)"
                ),
                _ => "stop-bots install firewall".to_string(),
            }),
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
///
/// **Against what was applied, not what was rendered.** The internal cron
/// renders on its own, to a script nothing loads (see
/// `firewall::rendered_path`), so "rendered" says nothing about what the
/// kernel holds or what a reboot restores. Comparing against the last
/// render is how this check came to say "up to date" about blocks nobody
/// had applied.
fn script_freshness(db: &Db, expected: usize, backend: FirewallBackend) -> Result<Check> {
    use firewall::ScriptState;
    let state = firewall::script_state(db)?;

    // Nothing to enforce and nothing ever applied is not staleness, it is
    // a host that has not been configured yet — even once the cron has
    // rendered its empty script. Saying otherwise puts a warning on every
    // fresh install, and a check that cries wolf on a brand-new database
    // is one nobody reads on the day it matters.
    let untouched = expected == 0 && db.get_firewall_applied_signature()?.is_none();
    let stale = state != ScriptState::Applied && !untouched;
    let rendered = firewall::rendered_path(&firewall::default_output_path(backend));

    Ok(Check {
        id: "script-fresh",
        title: "Applied rules match the configuration",
        level: if stale { Level::Warn } else { Level::Ok },
        detail: match (untouched, state) {
            (true, _) => "no rules to apply yet".to_string(),
            (_, ScriptState::Applied) => {
                "up to date: the rules applied are the ones configured".to_string()
            }
            (_, ScriptState::RenderedNotApplied) => format!(
                "rendered to {}, not applied: the kernel and a reboot still have the last \
                 rules applied",
                rendered.display()
            ),
            (_, ScriptState::Changed) => {
                let changed = format!("the rules changed since the last apply ({expected} now)");
                match scheduled_render(db)? {
                    Some(at) => format!(
                        "{changed}. Will auto-render{} at {}",
                        if db.get_auto_apply_firewall()? {
                            " and apply"
                        } else {
                            ""
                        },
                        format_utc(at)
                    ),
                    None => changed,
                }
            }
        },
        fix: stale.then(|| {
            "apply it: \u{201c}Apply everything\u{201d}, `stop-bots render-firewall --apply`, or \
             `stop-bots batch --apply`"
                .to_string()
        }),
    })
}

/// When the internal cron will next render the firewall by itself, or
/// `None` if this host cannot be promised that it will.
///
/// Two cases return `None`, and both are the difference between "will" and
/// "might". A `RenderFirewall` job that has never run means nothing has
/// ever driven the internal cron here — a host configured entirely from
/// the CLI, where the answer is never. A projected time already in the
/// *past* means the job is overdue, which is not a schedule either: it
/// runs within the minute if a front-end is ticking, and never if the one
/// that used to be has stopped. Naming a time that has been and gone is
/// the one thing worse than naming none.
///
/// The remaining false promise is a front-end stopped since its last run,
/// where a future time is still projected. That is deliberate rather than
/// missed: the console is only one of the things that drives this cron
/// (the TUI does, and so does `stop-bots batch` from a real crontab), so
/// there is no signal that distinguishes them, and the `service-health`
/// check immediately below already reports a console that is not running.
fn scheduled_render(db: &Db) -> Result<Option<i64>> {
    let at = crate::cron::next_run_at(db, crate::cron::CronJob::RenderFirewall)?;
    Ok(at.filter(|at| *at > now_secs()))
}

/// `secs` (Unix seconds) as `YYYY-MM-DD HH:MM UTC`.
///
/// The only absolute time this project formats — every other one it shows
/// is relative ("2h ago", and see `tui::dashboard::format_relative_time`),
/// which is why there is no date crate in the tree to ask. A relative
/// "in 6h" would have been the house style, but this string answers "has
/// it happened yet?" for someone reading a report rather than watching a
/// screen, and a fixed moment survives being read an hour later.
///
/// UTC rather than local time, and labelled as such: resolving a local
/// zone needs a database this does not carry, and an unlabelled time an
/// admin misreads by an hour is worse than one they have to convert.
///
/// The arithmetic is Howard Hinnant's `civil_from_days`, which shifts the
/// epoch to 0000-03-01 so that a leap day falls at the end of a cycle
/// rather than inside one — after that shift the month lengths repeat on
/// a fixed pattern and no case needs special-casing. `div_euclid`/
/// `rem_euclid` rather than `/` and `%` so that a pre-1970 (negative)
/// timestamp floors instead of truncating toward zero.
pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let seconds_into_day = secs.rem_euclid(86_400);
    let (hour, minute) = (seconds_into_day / 3_600, (seconds_into_day % 3_600) / 60);

    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_shifted + 2) / 5 + 1;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

fn nginx_applied(db: &Db) -> Result<Check> {
    use crate::nginx::{self, SiteApplyStatus};

    let sites = db.list_sites()?;
    let total = sites.len();
    // Reads each site's config file, the same way the NGINX screen
    // does — this is the one check here that touches the filesystem from
    // `assess` rather than from `probe`, because it needs a per-site
    // `BlockConfig` that only the database can produce.
    let mut stale: Vec<String> = Vec::new();
    let conf_d = nginx::conf_d_dir(&nginx::root(db, None)?);
    for site in sites {
        let config = nginx::block_config_for_site(db, site.id)?;
        let status = nginx::site_apply_status(
            Path::new(&site.config_path),
            &site.server_name,
            &config,
            &conf_d,
        );
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
        // The console is optional: a host run from the CLI and cron has no
        // unit, and that is a complete setup, not an unknown one. Reported
        // as UNKNOWN, it was the one thing `status` flagged after following
        // the README's quick start to the letter.
        (None, _) => (
            Level::Ok,
            "not installed (optional: `stop-bots install web` runs it as a service)".to_string(),
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

/// Whether the console runs as root, which since 0.1 it need not: a
/// console running as root is a compromise of the host away from anyone
/// who gets code running in it. Said only when a console is running.
fn console_account(probe: &Probe) -> Option<Check> {
    let who = probe.console_identity.as_ref()?;
    let (level, detail, fix) = if who.uid == 0 {
        (
            Level::Warn,
            "the console runs as root, so whoever compromises it has this host".to_string(),
            Some(
                "re-run `sudo stop-bots install web` to drop its privileges: it runs the \
                 console as the stop-bots user, with a root helper for what needs root"
                    .to_string(),
            ),
        )
    } else {
        (
            Level::Ok,
            format!("runs as {}, not root", crate::account::user_name(who.uid)),
            None,
        )
    };
    Some(Check {
        id: "console-account",
        title: "Console's account",
        level,
        detail,
        fix,
    })
}

/// Whether a console that is not root has the root helper to ask. Without
/// it the console can show everything and apply nothing. Not asked of a
/// console running as root, which does its own applying — and is
/// [`console_account`]'s warning.
fn console_helper(probe: &Probe) -> Option<Check> {
    let who = probe.console_identity.as_ref()?;
    if who.uid == 0 {
        return None;
    }
    let (level, detail, fix) = match probe.console_helper? {
        true => (
            Level::Ok,
            format!("asks {} for what needs root", crate::install::HELPER_UNIT),
            None,
        ),
        false => (
            Level::Warn,
            "the console has no root helper, so it can show this host but apply nothing"
                .to_string(),
            Some(format!(
                "sudo systemctl enable --now {}, or re-run `sudo stop-bots install web`",
                crate::install::HELPER_SOCKET_UNIT
            )),
        ),
    };
    Some(Check {
        id: "console-helper",
        title: "Console's root helper",
        level,
        detail,
        fix,
    })
}

/// Whether the console, not being root, can read the logs this host is
/// set up to read. [`log_sources`] asks the same as root, which reads
/// everything; this is the console's own answer, and the one its
/// detectors live by.
fn console_log_access(probe: &Probe) -> Option<Check> {
    let who = probe.console_identity.as_ref()?;
    if who.uid == 0 {
        return None;
    }
    let (level, detail, fix) = if probe.console_unreadable_logs.is_empty() {
        (
            Level::Ok,
            "the console can read every log it is set up to read".to_string(),
            None,
        )
    } else {
        (
            Level::Warn,
            format!(
                "the console's account ({}) cannot read {} — the detectors that read it find \
                 nothing",
                crate::account::user_name(who.uid),
                probe.console_unreadable_logs.join(" or ")
            ),
            Some(
                "re-run `sudo stop-bots install web`, which gives the console the adm and \
                 systemd-journal groups; for a log owned by another group, `sudo setfacl -m \
                 u:stop-bots:r <log>` (and `u:stop-bots:x` on each directory above it)"
                    .to_string(),
            ),
        )
    };
    Some(Check {
        id: "console-log-access",
        title: "Logs the console can read",
        level,
        detail,
        fix,
    })
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
/// Whether the access log is recording the *client's* address.
///
/// The quiet one. Every detector in `accesslog` skips private sources, so
/// a deployment that records a proxy's address instead of the visitor's
/// does not block the wrong people — it blocks nobody, from a log that
/// looks healthy and a report that says everything is clear. That is the
/// `--ssh-log` failure exactly: the detector most needed on an exposed
/// host, switched off by a path nobody chose, with nothing on screen.
///
/// Warn, not Critical: the host is still protected by everything already
/// in its ruleset. What has stopped is finding *new* offenders.
fn access_log_clients(probe: &Probe) -> Check {
    let (level, detail, fix) = match probe.access_log_clients {
        // `log_sources` already reports an unreadable log; saying it twice
        // in one report is noise, not emphasis.
        None => (Level::Unknown, "no access log to read".to_string(), None),
        // Nothing parsed from lines that are there is a format the
        // detectors cannot read, which `access_log_format` reports; "no
        // requests recorded yet" was the wrong thing to say about it.
        Some((_, 0)) if probe.access_log_lines.is_some_and(|(lines, _)| lines > 0) => (
            Level::Unknown,
            "none of the logged requests could be read".to_string(),
            None,
        ),
        // Not a misconfiguration. A host that has served nothing yet has
        // nothing to say about who it served.
        Some((_, 0)) => (Level::Ok, "no requests recorded yet".to_string(), None),
        Some((0, parsed)) => (
            Level::Warn,
            format!(
                "all {parsed} logged request(s) came from a private address \u{2014} every detector skips those, so none of them can see anything"
            ),
            Some(
                "NGINX is logging its proxy's address, not the client's. If it runs behind a container port mapping, a load balancer or a CDN, set `set_real_ip_from` and `real_ip_header` so $remote_addr is the visitor again."
                    .to_string(),
            ),
        ),
        // One private address among public ones is ordinary: a monitoring
        // cron on the host hits its own site. Only *all* of them is the
        // signal.
        Some((public, parsed)) => (
            Level::Ok,
            format!("{public} of {parsed} logged request(s) from public addresses"),
            None,
        ),
    };
    Check {
        id: "access-log-clients",
        title: "Access log records real clients",
        level,
        detail,
        fix,
    }
}

/// Fewer public lines than this say nothing about who is in front of NGINX:
/// a host that has served twelve requests may have had them all from one
/// monitoring service that happens to run on Cloudflare Workers.
const CDN_MIN_LINES: usize = 50;

/// The share of public lines from CDN edges that means NGINX is behind the
/// CDN. A site served through Cloudflare logs nothing *but* its edges; one
/// served directly sees a few from Workers and Cloudflare's own crawlers.
const CDN_MIN_SHARE: f64 = 0.5;

/// Whether NGINX is logging a CDN's edges instead of its visitors.
///
/// Behind Cloudflare without `set_real_ip_from`, every client address in
/// the log is an edge. The detectors skip edge addresses (blocking one
/// blocks everyone routed through it), so on such a host they see nobody
/// they are allowed to block, and every other check here still reads OK.
///
/// Absent when there is nothing to say, like its neighbours.
fn cdn_edges(probe: &Probe) -> Option<Check> {
    let (public, _) = probe.access_log_clients?;
    let cdn = probe.access_log_cdn?;
    if public < CDN_MIN_LINES || (cdn as f64) < public as f64 * CDN_MIN_SHARE {
        return None;
    }
    Some(Check {
        id: "cdn-edges",
        title: "Clients arrive through a CDN",
        level: Level::Warn,
        detail: format!(
            "{cdn} of {public} logged request(s) came from {}'s edge addresses \u{2014} the \
             detectors never block those, so behind it they cannot block anyone",
            crate::cdn::NAME
        ),
        fix: Some(format!(
            "Tell NGINX to log the visitor's address, from the header {} adds, in the \
             `http` block (ngx_http_realip_module): {}",
            crate::cdn::NAME,
            crate::cdn::real_ip_config()
        )),
    })
}

/// Below this share of lines parsed, the access log is mostly in a format
/// the detectors cannot read. Not zero: a log that parses to nothing is
/// the obvious case, but a custom `log_format` added beside the stock one
/// leaves a file that parses in part, and the detectors see only that
/// part.
const ACCESS_LOG_MIN_PARSED: f64 = 0.5;

/// Whether the access log is in a format the detectors read.
///
/// The failure this exists for is silent: a custom `log_format` parses to
/// nothing, every detector finds nothing, and the report used to say OK,
/// "no requests recorded yet", about a log with a million lines in it.
/// So the lines that did not parse are counted against those that did,
/// and one of them is quoted, because the next question is always "what
/// does my log look like, then".
fn access_log_format(probe: &Probe) -> Check {
    let (level, detail, fix) = match probe.access_log_lines {
        // `log_sources` reports an unreadable log.
        None => (Level::Unknown, "no access log to read".to_string(), None),
        Some((0, _)) => (Level::Ok, "no requests recorded yet".to_string(), None),
        Some((lines, parsed)) if (parsed as f64) < lines as f64 * ACCESS_LOG_MIN_PARSED => {
            let sample = probe
                .access_log_unparsed_sample
                .as_deref()
                .map(|line| format!("; one of them: {line}"))
                .unwrap_or_default();
            (
                Level::Warn,
                format!(
                    "only {parsed} of {lines} recent line(s) are in a format the detectors read{sample}"
                ),
                Some(
                    "log in NGINX's `combined` format, or a JSON `log_format ... escape=json` \
                     keyed by the variable names (remote_addr, status, request_uri or request, \
                     http_referer, http_user_agent, time_local or time_iso8601)"
                        .to_string(),
                ),
            )
        }
        Some((lines, parsed)) => (
            Level::Ok,
            format!("{parsed} of {lines} recent line(s) read"),
            None,
        ),
    };
    Check {
        id: "access-log-format",
        title: "Access log format is readable",
        level,
        detail,
        fix,
    }
}

/// Which addresses currently cannot be blocked, and why.
///
/// This exists because the anti-lockout allowlist is otherwise invisible:
/// it is computed at render time, stored in no rule table, and shown in no
/// screen — yet it overrides every block this tool can produce. An
/// allowlist nobody can see is how a host ends up with a hole in it that
/// nobody remembers opening.
///
/// Never a warning. The entries are, by construction, addresses whose
/// owner can already log into this machine over SSH; treating that as a
/// problem to fix would be reporting the operator to themselves.
fn ssh_login_allowlist(db: &Db) -> Result<Check> {
    let addresses = db.recent_ssh_login_ips()?;
    let days = crate::db::SSH_LOGIN_WINDOW_SECONDS / (24 * 60 * 60);
    let detail = match addresses.len() {
        // Not "no logins" — far more likely nothing has run yet, since the
        // window is fed by the cron and a host that has just started has an
        // empty table for a minute either way.
        0 => format!("no successful SSH login recorded in the last {days} days"),
        // Listed, not counted. The count answers "is it working"; the
        // addresses answer "should that one still be on here", which is
        // the question actually worth asking about an allowlist.
        _ => format!(
            "{} address(es) cannot be blocked, having logged in over SSH within {days} days: {}",
            addresses.len(),
            addresses.join(", ")
        ),
    };
    Ok(Check {
        id: "ssh-login-allowlist",
        title: "Addresses kept un-blockable",
        level: Level::Ok,
        detail,
        fix: None,
    })
}

/// What an operator has trusted by hand, listed — for the reason
/// [`ssh_login_allowlist`] lists its addresses, and more so: those expire
/// on their own after a week, and these never do.
///
/// Absent rather than "nothing trusted" when there is nothing: that is
/// the ordinary state, and a line saying so on every host is noise on the
/// one-line status strip the TUI shows these on.
///
/// Never a warning, for the same reason as the SSH list: trusting
/// something is a decision, not a fault.
fn trusted_by_hand(db: &Db) -> Result<Option<Check>> {
    let addresses = db.list_trusted_addresses()?;
    let user_agents = db.list_trusted_user_agents()?;
    if addresses.is_empty() && user_agents.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    if !addresses.is_empty() {
        parts.push(format!(
            "{} address(es), past the firewall and NGINX: {}",
            addresses.len(),
            addresses.join(", ")
        ));
    }
    if !user_agents.is_empty() {
        parts.push(format!(
            "{} user agent(s), past NGINX only: {}",
            user_agents.len(),
            user_agents.join(", ")
        ));
    }
    Ok(Some(Check {
        id: "trusted",
        title: "Trusted by hand",
        level: Level::Ok,
        detail: parts.join("; "),
        fix: None,
    }))
}

/// Stored blocks, exemptions and trusted agents that the NGINX config
/// leaves out, because they would not mean what they say there (see
/// `nginx::skipped_entries`).
///
/// A warning, not critical: what is written is correct, and leaving an
/// entry out is the safe failure. But each one is something the operator
/// believes is in force, and the render drops it without a word anywhere
/// else. The rows that end up here were stored by a release that did not
/// check them, and upgrading is exactly when nobody is looking.
///
/// Absent when there is nothing, like its neighbours.
fn skipped_entries(db: &Db) -> Result<Option<Check>> {
    let skipped = crate::nginx::skipped_entries(db)?;
    if skipped.is_empty() {
        return Ok(None);
    }
    let named: Vec<&str> = skipped.iter().take(3).map(String::as_str).collect();
    let more = skipped.len() - named.len();
    let suffix = if more > 0 {
        format!("; and {more} more")
    } else {
        String::new()
    };
    Ok(Some(Check {
        id: "skipped-entries",
        title: "Entries left out of the NGINX config",
        level: Level::Warn,
        detail: format!(
            "{} stored entr(ies) are not written: {}{}",
            skipped.len(),
            named.join("; "),
            suffix
        ),
        fix: Some(
            "`stop-bots apply-blocks --dry-run` lists them all; remove each and add it again \
             in a form that is accepted"
                .to_string(),
        ),
    }))
}

/// Where NGINX runs, and whether everything that has to agree with that
/// actually does.
///
/// Says the host case out loud — "on this host, reloaded with `systemctl
/// reload nginx`" — because an operator reading the report wants to know
/// which arrangement the tool believes it is in, and because that line is
/// the only evidence the detection ran at all.
///
/// Returns nothing only when *neither* arrangement could be established.
/// That is deliberate: this reports a positive identification, never a
/// guess. A host with no Docker and no active NGINX unit adds no check,
/// no `Unknown`, and no line to the report.
///
/// Three things have to line up for a containerised NGINX, and they fail
/// with very different loudness — so the levels differ:
///
/// - **The reload command.** `systemctl reload nginx` reloads nothing when
///   NGINX is in a container. Silent, and total: every block this project
///   writes is staged and never served. Critical.
/// - **The proxy target.** `webaccess` writes the console's own bind
///   address into `proxy_pass`, and `127.0.0.1` inside a container is the
///   container. Loud — a 502 the first time anyone opens the console — so
///   Warn.
/// - **The managed directory.** The generated config names it absolutely;
///   NGINX resolves it against its own filesystem. Caught at apply time by
///   `write_validated` running `nginx -t` inside the container, so Warn.
fn nginx_deployment(db: &Db, probe: &Probe) -> Result<Option<Check>> {
    let commands = crate::nginx::NginxCommands::from_db(db)?;
    let targets_a_container = |argv: &[String]| {
        argv.iter()
            .any(|word| word.contains("docker") || word.contains("podman"))
    };

    let name = match &probe.nginx_home {
        // Said out loud rather than left as the silent case. An operator
        // looking at this report wants to know which arrangement the tool
        // thinks it is in — "NGINX runs on this host" is the reassurance
        // that the commands below reach it, and it is the line that tells
        // them the detection is working at all.
        NginxHome::Host => {
            return Ok(Some(if targets_a_container(&commands.reload) {
                // The mirror image of the container case, and reachable:
                // an operator who set container commands and later moved
                // NGINX onto the host has a reload that reaches nothing,
                // just as silently.
                Check {
                    id: "nginx-deployment",
                    title: "Where NGINX runs",
                    level: Level::Critical,
                    detail: format!(
                        "NGINX runs on this host, but the reload command is `{}` \u{2014} which targets a container, so no block this tool writes is ever served",
                        commands.reload.join(" ")
                    ),
                    fix: Some("stop-bots set-nginx-commands --reset".to_string()),
                }
            } else {
                Check {
                    id: "nginx-deployment",
                    title: "Where NGINX runs",
                    level: Level::Ok,
                    detail: format!(
                        "on this host, reloaded with `{}`",
                        commands.reload.join(" ")
                    ),
                    fix: None,
                }
            }));
        }
        // Nothing could be established. Still the silent case: a guess
        // here would be a guess in the operator's report.
        NginxHome::Unclear => return Ok(None),
        NginxHome::Container { name } => name,
    };

    // The reload command first: it is the only one of the three that is
    // both silent and total.
    let reload_reaches_container =
        targets_a_container(&commands.reload) || commands.reload.iter().any(|w| w.contains(name));
    if !reload_reaches_container {
        return Ok(Some(Check {
            id: "nginx-deployment",
            title: "Where NGINX runs",
            level: Level::Critical,
            detail: format!(
                "NGINX is in container `{name}`, but the reload command is `{}` \u{2014} which reloads nothing, so no block this tool writes is ever served",
                commands.reload.join(" ")
            ),
            fix: Some(format!(
                "stop-bots set-nginx-commands --test \"docker exec {name} nginx -t\" --reload \"docker exec {name} nginx -s reload\""
            )),
        }));
    }

    let mut problems: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();

    let upstream = crate::web::resolve_bind(db, None)?;
    let host_networked = probe.container_shares_host_network == Some(true);
    if upstream.ip().is_loopback() && !host_networked {
        problems.push(format!(
            "the console binds {upstream}, which inside the container means the container itself, so the generated proxy_pass cannot reach it"
        ));
        fixes.push(
            "bind the console where the container can reach it (the bridge gateway, e.g. --bind 172.17.0.1:8787) and re-apply Web Access, or run the container with --network host"
                .to_string(),
        );
    }

    if probe.managed_dir_in_container == Some(false) {
        problems.push(format!(
            "{} does not exist inside the container, and the generated config names it absolutely",
            crate::nginx::managed_dir().display()
        ));
        fixes.push(format!(
            "bind-mount {} into the container at the same path",
            crate::nginx::managed_dir().display()
        ));
    }

    Ok(Some(if problems.is_empty() {
        Check {
            id: "nginx-deployment",
            title: "Where NGINX runs",
            level: Level::Ok,
            detail: format!("in container `{name}`, reached by the configured commands"),
            fix: None,
        }
    } else {
        Check {
            id: "nginx-deployment",
            title: "Where NGINX runs",
            level: Level::Warn,
            detail: format!(
                "NGINX is in container `{name}`, but {}",
                problems.join("; and ")
            ),
            fix: Some(fixes.join(". ")),
        }
    }))
}

/// Whether a console set up behind a proxy believes the proxy's word
/// about who is asking.
///
/// "Set up behind a proxy" is what the Web Access panel records: a path
/// prefix, or a host name to answer to other than loopback. Behind one,
/// every request arrives from the proxy's own address, and without
/// `web:trust_forwarded_for` the console takes that for the client. Then
/// the login throttle has one key for everyone, so an attacker's failures
/// are the operator's too, and the guard against blocking your own address
/// compares against 127.0.0.1.
///
/// A warning, not critical: nothing is unprotected, but the console's own
/// defences are working against the wrong address. Absent on a console
/// that is not proxied, which is the default.
fn console_proxy(db: &Db) -> Result<Option<Check>> {
    if !crate::web::is_proxied(db)? {
        return Ok(None);
    }
    let trusted = db.get_bool_setting(crate::web::TRUST_FORWARDED_KEY, false)?;
    Ok(Some(if trusted {
        Check {
            id: "web-proxy",
            title: "Console behind a proxy",
            level: Level::Ok,
            detail: "client addresses come from the proxy's X-Forwarded-For".to_string(),
            fix: None,
        }
    } else {
        Check {
            id: "web-proxy",
            title: "Console behind a proxy",
            level: Level::Warn,
            detail: "the console is set up behind a proxy but does not believe its \
                     X-Forwarded-For, so every client is the proxy's address: one login \
                     throttle for the operator and every attacker, and no way to stop you \
                     blocking your own address"
                .to_string(),
            fix: Some("stop-bots set-web --trust-forwarded-for true".to_string()),
        }
    }))
}

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
            match (&probe.access_log_path, probe.access_log_readable) {
                (Some(path), Some(false)) => format!(
                    "{} unreadable — those detectors find nothing (tried {path})",
                    missing.join(" and ")
                ),
                _ => format!(
                    "{} unreadable — those detectors find nothing",
                    missing.join(" and ")
                ),
            },
            // `set-log-paths` first, because it is the one that also fixes
            // the console and the internal cron: they take no arguments, so
            // a flag cannot reach them and only a stored path can.
            Some(
                "stop-bots set-log-paths --access-log <path> (or pass --ssh-log/--access-log \
                 for a one-off run)"
                    .to_string(),
            ),
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
pub const PROBE_KEY: &str = crate::db::keys::HEALTH_PROBE;
pub const PROBE_AT_KEY: &str = crate::db::keys::HEALTH_PROBE_AT;

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
            nftables_conf_flushes: None,
            unit_active: Some(true),
            unit_binary: None,
            turned_away: Vec::new(),
            conf_d_path: Some(crate::nginx::CONF_D_DIR.to_string()),
            conf_d_exists: Some(true),
            stray_generated_files: Vec::new(),
            db_free_bytes: Some(8 * 1024 * 1024 * 1024),
            ssh_log_readable: Some(true),
            access_log_readable: Some(true),
            access_log_path: None,
            access_log_clients: Some((40, 41)),
            access_log_lines: Some((41, 41)),
            access_log_unparsed_sample: None,
            access_log_cdn: Some(0),
            // The ordinary host: NGINX is a unit here, and the two
            // container fields have nothing to answer. Every
            // container-arrangement test below states its own.
            nginx_home: NginxHome::Host,
            managed_dir_in_container: None,
            container_shares_host_network: None,
            firewall_covers_forward: Some(true),
            // The console as `install web` leaves it since 0.1.
            console_identity: Some(console_user()),
            console_helper: Some(true),
            console_unreadable_logs: Vec::new(),
        }
    }

    /// The `stop-bots` user, with the two log groups its unit adds.
    fn console_user() -> crate::account::Identity {
        crate::account::Identity {
            uid: 998,
            gids: vec![998, 4, 101],
        }
    }

    /// The three things a console can be that the split was meant to
    /// prevent, each its own warning with its own fix — and a console as
    /// installed raises none of them.
    #[test]
    fn a_console_as_installed_raises_none_of_the_privilege_warnings() {
        let report = assess(&db(), &healthy()).unwrap();
        for id in ["console-account", "console-helper", "console-log-access"] {
            assert_eq!(check(&report, id).level, Level::Ok, "{id}");
        }
    }

    #[test]
    fn a_console_running_as_root_is_a_warning_that_says_how_to_drop_it() {
        let report = assess(
            &db(),
            &Probe {
                console_identity: Some(crate::account::Identity {
                    uid: 0,
                    gids: vec![0],
                }),
                ..healthy()
            },
        )
        .unwrap();

        let account = check(&report, "console-account");
        assert_eq!(account.level, Level::Warn);
        assert!(
            account
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("sudo stop-bots install web")),
            "{account:?}"
        );
        // A root console applies for itself; the other two are not its
        // problems, and one warning is enough.
        for id in ["console-helper", "console-log-access"] {
            assert!(
                report.checks.iter().all(|check| check.id != id),
                "{id} as well: {:#?}",
                report.checks
            );
        }
    }

    #[test]
    fn a_console_without_its_helper_is_a_warning() {
        let report = assess(
            &db(),
            &Probe {
                console_helper: Some(false),
                ..healthy()
            },
        )
        .unwrap();

        let helper = check(&report, "console-helper");
        assert_eq!(helper.level, Level::Warn);
        assert!(
            helper
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains(crate::install::HELPER_SOCKET_UNIT)),
            "{helper:?}"
        );
    }

    #[test]
    fn a_log_the_console_cannot_read_is_named() {
        let report = assess(
            &db(),
            &Probe {
                console_unreadable_logs: vec!["/srv/logs/access.log".to_string()],
                ..healthy()
            },
        )
        .unwrap();

        let logs = check(&report, "console-log-access");
        assert_eq!(logs.level, Level::Warn);
        assert!(logs.detail.contains("/srv/logs/access.log"), "{logs:?}");
    }

    /// No console running, nothing to say about it.
    #[test]
    fn no_running_console_means_no_privilege_checks() {
        let report = assess(
            &db(),
            &Probe {
                console_identity: None,
                console_helper: None,
                ..healthy()
            },
        )
        .unwrap();

        for id in ["console-account", "console-helper", "console-log-access"] {
            assert!(report.checks.iter().all(|check| check.id != id), "{id}");
        }
    }

    /// The effective ids, not the real ones, and every group the process
    /// holds.
    #[test]
    fn a_process_status_gives_its_effective_ids_and_groups() {
        let status = "Name:\tstop-bots\n\
                      Uid:\t998\t997\t998\t997\n\
                      Gid:\t996\t995\t996\t995\n\
                      Groups:\t4 101 \n";

        assert_eq!(
            parse_proc_status(status),
            Some(crate::account::Identity {
                uid: 997,
                gids: vec![995, 4, 101],
            })
        );
        assert_eq!(parse_proc_status("Name:\tx\n"), None);
    }

    /// A probe stored before these fields existed still parses, and says
    /// nothing about the console's account.
    #[test]
    fn a_probe_from_before_the_split_still_parses() {
        let probe: Probe = serde_json::from_str(r#"{"unit_active":true}"#).unwrap();
        assert_eq!(probe.console_identity, None);
        assert!(probe.console_unreadable_logs.is_empty());
    }

    /// Alias for [`check`], for tests that bind a local named `check`.
    fn check2<'a>(report: &'a Report, id: &str) -> &'a Check {
        check(report, id)
    }

    fn check<'a>(report: &'a Report, id: &str) -> &'a Check {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no check called {id}"))
    }

    /// Records the current rules as rendered and applied, as a successful
    /// apply does.
    fn applied_now(db: &Db) {
        let signature = crate::firewall::rules_signature(&crate::firewall::all_rules(db).unwrap());
        db.set_firewall_rendered_signature(&signature).unwrap();
        db.set_firewall_applied_signature(&signature).unwrap();
    }

    fn with_rules(db: &Db, count: usize) {
        for i in 0..count {
            db.add_firewall_rule(&crate::db::NewFirewallRule {
                address: format!("198.51.100.{i}"),
                port: None,
                action: crate::db::FirewallAction::Block,
                source: crate::db::RuleSource::Cli,
                evidence: None,
            })
            .unwrap();
        }
    }

    fn in_container() -> Probe {
        Probe {
            nginx_home: NginxHome::Container {
                name: "web".to_string(),
            },
            managed_dir_in_container: Some(true),
            container_shares_host_network: Some(false),
            ..healthy()
        }
    }

    fn configured_for_docker(db: &Db) {
        db.set_text_setting(
            crate::nginx::NginxCommands::RELOAD_KEY,
            "docker exec web nginx -s reload",
        )
        .unwrap();
        db.set_text_setting(
            crate::nginx::NginxCommands::TEST_KEY,
            "docker exec web nginx -t",
        )
        .unwrap();
    }

    /// The host arrangement is stated out loud, not left to silence: the
    /// operator wants to know which one the tool thinks it is in, and this
    /// is the only line that says the detection ran.
    #[test]
    fn an_ordinary_host_is_told_that_nginx_runs_on_it() {
        let report = assess(&db(), &healthy()).unwrap();

        let check = check2(&report, "nginx-deployment");
        assert_eq!(check.level, Level::Ok);
        assert!(
            check.detail.contains("on this host"),
            "was: {}",
            check.detail
        );
        assert!(
            check.detail.contains("systemctl reload nginx"),
            "it should name the command that reaches it: {}",
            check.detail
        );
    }

    fn refused(user_agent: &str, refused: u64, served: u64) -> crate::accesslog::TurnedAway {
        crate::accesslog::TurnedAway {
            user_agent: user_agent.to_string(),
            refused,
            served,
        }
    }

    /// Seeds the successful-hit history that separates "a client that used
    /// to work" from "a bot doing what bots do".
    fn seen_working(db: &Db, user_agent: &str) {
        let mut counts = std::collections::HashMap::new();
        counts.insert(user_agent.to_string(), 40);
        db.record_user_agent_hits(&counts, 1_790_000_000).unwrap();
    }

    /// The case this check was written for, in the shape it actually
    /// happened: a Jellyfin client that had been serving a household for
    /// months started matching `okhttp` in a bad-bot list.
    #[test]
    fn a_client_this_host_used_to_serve_being_refused_is_a_warning() {
        let db = db();
        let agent = "Jellyfin Android TV/0.19.10 via jellyfin-sdk-kotlin (OkHttp/4.12.0)";
        seen_working(&db, agent);
        let probe = Probe {
            turned_away: vec![refused(agent, 262, 0)],
            ..healthy()
        };

        let report = assess(&db, &probe).unwrap();
        let check = check2(&report, "turned-away-clients");

        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains("Jellyfin") && check.detail.contains("262"),
            "it should name the client and the damage: {}",
            check.detail
        );
        assert!(
            check.fix.as_deref().is_some_and(|f| f.contains("trust")),
            "and say how to allow it: {:?}",
            check.fix
        );
    }

    /// A blocking policy turning away bots is the policy working. Reporting
    /// every one of them would bury the one line that matters.
    #[test]
    fn an_agent_this_host_never_served_is_not_reported() {
        let probe = Probe {
            turned_away: vec![refused("AhrefsBot/7.0", 4_000, 0)],
            ..healthy()
        };

        assert!(
            assess(&db(), &probe)
                .unwrap()
                .checks
                .iter()
                .all(|check| check.id != "turned-away-clients"),
            "a bot with no history here is not a regression"
        );
    }

    /// One stray refusal is not a broken client, and a check that fires on
    /// it gets muted.
    #[test]
    fn a_couple_of_refusals_stays_below_the_threshold() {
        let db = db();
        seen_working(&db, "SomeApp/1.0");
        let probe = Probe {
            turned_away: vec![refused("SomeApp/1.0", 2, 900)],
            ..healthy()
        };

        assert!(assess(&db, &probe)
            .unwrap()
            .checks
            .iter()
            .all(|check| check.id != "turned-away-clients"));
    }

    /// Nothing refused, nothing said — like its neighbours, this adds no
    /// line to a healthy host.
    #[test]
    fn a_host_turning_nobody_away_gets_no_line() {
        assert!(assess(&db(), &healthy())
            .unwrap()
            .checks
            .iter()
            .all(|check| check.id != "turned-away-clients"));
    }

    /// The ordinary answer, and it names the directory. "Generated files
    /// are fine" is worth nothing to an operator who cannot tell which
    /// directory the tool means — the same reason the access-log check
    /// carries its path.
    #[test]
    fn the_generated_files_check_names_the_directory_it_writes_to() {
        let report = assess(&db(), &healthy()).unwrap();

        let check = check2(&report, "generated-files-reachable");
        assert_eq!(check.level, Level::Ok);
        assert!(
            check.detail.contains(crate::nginx::CONF_D_DIR),
            "it should name the directory: {}",
            check.detail
        );
    }

    /// Upgrading a containerised host leaves the old copies behind:
    /// before 0.0.9 they went to a fixed `/etc/nginx/conf.d` whatever
    /// `nginx:root` said, and nothing collects them now that the removal
    /// half looks in the right place.
    #[test]
    fn files_stranded_by_an_older_version_are_a_warning() {
        let probe = Probe {
            conf_d_path: Some("/srv/domaci/nginx/conf.d".to_string()),
            stray_generated_files: vec!["/etc/nginx/conf.d/stop-bots-trusted.conf".to_string()],
            ..healthy()
        };
        let report = assess(&db(), &probe).unwrap();

        let check = check2(&report, "generated-files-reachable");
        assert_eq!(check.level, Level::Warn);
        for expected in ["/srv/domaci/nginx/conf.d", "stop-bots-trusted.conf"] {
            assert!(
                check.detail.contains(expected),
                "the detail should name {expected}; it was: {}",
                check.detail
            );
        }
        assert!(check.fix.is_some(), "a stranded file is actionable");
    }

    /// A directory NGINX cannot read is the failure this check exists for.
    /// It is only a warning because the check cannot prove NGINX globs
    /// that path — but a directory that does not even exist is never the
    /// one NGINX is reading.
    #[test]
    fn a_conf_d_that_does_not_exist_is_a_warning() {
        let probe = Probe {
            conf_d_path: Some("/srv/domaci/nginx/conf.d".to_string()),
            conf_d_exists: Some(false),
            ..healthy()
        };
        let report = assess(&db(), &probe).unwrap();

        let check = check2(&report, "generated-files-reachable");
        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains("does not exist"),
            "was: {}",
            check.detail
        );
    }

    /// A generated file sitting in the stock directory while the active
    /// one is elsewhere is what an upgrade leaves behind.
    #[test]
    fn a_generated_file_left_in_the_stock_directory_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let stock = dir.path().join("etc/nginx/conf.d");
        let active = dir.path().join("srv/nginx/conf.d");
        std::fs::create_dir_all(&stock).unwrap();
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(stock.join("stop-bots-trusted.conf"), "geo {}\n").unwrap();
        std::fs::write(stock.join("unrelated.conf"), "server {}\n").unwrap();

        assert_eq!(
            stray_generated_files(&active, &stock),
            vec![stock.join("stop-bots-trusted.conf").display().to_string()],
            "only this project's own files, by name — the rest is someone else's"
        );
    }

    /// Nothing is stranded when the stock directory *is* the active one —
    /// on a normal host install the files there are the live ones.
    #[test]
    fn the_stock_directory_strands_nothing_when_it_is_the_active_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stop-bots-trusted.conf"), "geo {}\n").unwrap();

        assert!(stray_generated_files(dir.path(), dir.path()).is_empty());
    }

    /// Nor when the stock path has been *pointed at* the active one, which
    /// is what an operator who hit this bug before 0.0.9 most likely did
    /// to get their server back. Calling their live trust file stranded
    /// would send them to delete it.
    #[test]
    fn a_link_from_the_stock_path_to_the_active_one_strands_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("srv/nginx/conf.d");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("stop-bots-trusted.conf"), "geo {}\n").unwrap();
        let stock = dir.path().join("etc-nginx-conf.d");
        std::os::unix::fs::symlink(&active, &stock).unwrap();

        assert!(
            stray_generated_files(&active, &stock).is_empty(),
            "the two paths resolve to one directory, so nothing is stranded"
        );
    }

    /// The mirror of the container case, and reachable: an operator who
    /// pointed the commands at a container and later moved NGINX onto the
    /// host has a reload that reaches nothing, just as silently.
    #[test]
    fn container_commands_on_a_host_nginx_are_critical() {
        let db = db();
        configured_for_docker(&db);

        let check = assess(&db, &healthy()).unwrap();
        let check = check2(&check, "nginx-deployment");

        assert_eq!(check.level, Level::Critical);
        assert!(
            check.detail.contains("targets a container"),
            "was: {}",
            check.detail
        );
        assert!(check.fix.as_deref().unwrap_or_default().contains("--reset"));
    }

    /// And neither does a host where nothing could be established — which
    /// is what a probe cached by a version before this field existed
    /// deserialises to.
    #[test]
    fn an_unclear_deployment_accuses_the_host_of_nothing() {
        let report = assess(
            &db(),
            &Probe {
                nginx_home: NginxHome::Unclear,
                ..healthy()
            },
        )
        .unwrap();

        assert!(!report.checks.iter().any(|c| c.id == "nginx-deployment"));
        // Nothing in the report so much as mentions a container. Asserting
        // on `worst()` would not say that: an empty test database already
        // warns that no sites have been scanned, which is a different
        // subject entirely.
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.detail.contains("container") || c.title.contains("container")),
            "{:?}",
            report.checks
        );
    }

    /// The silent, total failure: NGINX is in a container and the reload
    /// command still talks to systemd, so every block is written and none
    /// is ever served.
    #[test]
    fn a_containerised_nginx_with_the_default_reload_is_critical() {
        let report = assess(&db(), &in_container()).unwrap();

        let check = check(&report, "nginx-deployment");
        assert_eq!(check.level, Level::Critical);
        assert!(
            check.detail.contains("reloads nothing"),
            "was: {}",
            check.detail
        );
        assert!(
            check
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("docker exec web"),
            "the fix should name the container: {:?}",
            check.fix
        );
    }

    /// The quiet failure: a ruleset that loads, counts right, and enforces
    /// nothing for the container it is supposed to be protecting.
    #[test]
    fn a_ruleset_that_misses_the_forward_path_is_critical_for_a_container() {
        let probe = Probe {
            firewall_covers_forward: Some(false),
            ..in_container()
        };
        let report = assess(&db(), &probe).unwrap();

        let check = check(&report, "firewall-reaches-containers");
        assert_eq!(check.level, Level::Critical);
        assert!(
            check.detail.contains("forwarded past it"),
            "the detail should say what happens to the packet: {}",
            check.detail
        );
        assert!(
            check.detail.contains("web"),
            "the detail should name the container: {}",
            check.detail
        );
        // The rule count is fine, which is the whole point: this check
        // must fire while its neighbour reports green.
        assert_eq!(check2(&report, "firewall-enforced").level, Level::Ok);
    }

    #[test]
    fn a_ruleset_covering_both_paths_says_so_for_a_container() {
        let report = assess(&db(), &in_container()).unwrap();
        let check = check(&report, "firewall-reaches-containers");
        assert_eq!(check.level, Level::Ok);
        assert!(
            check.detail.contains("forwarded traffic"),
            "was: {}",
            check.detail
        );
    }

    /// On a host NGINX the forward hook carries nothing this project has
    /// an opinion about, so there is nothing to report and no row.
    #[test]
    fn a_host_nginx_gets_no_container_reachability_row() {
        let probe = Probe {
            firewall_covers_forward: Some(false),
            ..healthy()
        };
        let report = assess(&db(), &probe).unwrap();
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.id == "firewall-reaches-containers"),
            "a host NGINX should not get this row"
        );
    }

    /// An empty kernel table is `firewall-enforced`'s Critical. Saying it
    /// twice, in two different wordings, is how a panel stops being read.
    #[test]
    fn nothing_loaded_at_all_is_left_to_the_other_check() {
        let probe = Probe {
            live_rules: Some(0),
            firewall_covers_forward: Some(false),
            ..in_container()
        };
        let report = assess(&db(), &probe).unwrap();
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.id == "firewall-reaches-containers"),
            "an empty ruleset is the other check's problem"
        );
    }

    /// A loopback bind is unreachable from inside the container, so the
    /// `proxy_pass` `webaccess` generates points at the container itself.
    #[test]
    fn a_loopback_console_bind_is_flagged_for_a_bridged_container() {
        let db = db();
        configured_for_docker(&db);

        let check = assess(&db, &in_container()).unwrap();
        let check = check2(&check, "nginx-deployment");

        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("proxy_pass"), "was: {}", check.detail);
    }

    /// The same bind is correct when the container shares the host's
    /// network namespace, where `127.0.0.1` means the same thing on both
    /// sides. Reporting it then would be advice to break a working host.
    #[test]
    fn a_host_networked_container_is_happy_with_a_loopback_bind() {
        let db = db();
        configured_for_docker(&db);

        let report = assess(
            &db,
            &Probe {
                container_shares_host_network: Some(true),
                ..in_container()
            },
        )
        .unwrap();

        assert_eq!(check2(&report, "nginx-deployment").level, Level::Ok);
    }

    /// The generated config names the managed directory absolutely, and
    /// NGINX resolves it inside the container.
    #[test]
    fn a_managed_directory_missing_from_the_container_is_flagged() {
        let db = db();
        configured_for_docker(&db);

        let report = assess(
            &db,
            &Probe {
                managed_dir_in_container: Some(false),
                container_shares_host_network: Some(true),
                ..in_container()
            },
        )
        .unwrap();

        let check = check2(&report, "nginx-deployment");
        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains("does not exist inside the container"),
            "was: {}",
            check.detail
        );
    }

    /// The quiet failure this pair exists for: a log full of requests,
    /// none of which carries a client address any detector will look at.
    #[test]
    fn an_access_log_of_only_private_clients_is_a_warning() {
        let report = assess(
            &db(),
            &Probe {
                access_log_clients: Some((0, 900)),
                ..healthy()
            },
        )
        .unwrap();

        let check = check2(&report, "access-log-clients");
        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("900"), "was: {}", check.detail);
        assert!(
            check
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("real_ip_header"),
            "the fix should name the directive: {:?}",
            check.fix
        );
    }

    /// The allowlist has to name its entries, not count them. A count
    /// tells an operator the mechanism works; only the addresses let them
    /// notice one that should no longer be there.
    #[test]
    fn the_ssh_allowlist_check_names_the_addresses_it_protects() {
        let db = db();
        db.record_ssh_login_ips(&["203.0.113.5".to_string(), "198.51.100.2".to_string()])
            .unwrap();

        let report = assess(&db, &healthy()).unwrap();

        let check = check2(&report, "ssh-login-allowlist");
        assert_eq!(check.level, Level::Ok);
        assert!(
            check.detail.contains("203.0.113.5"),
            "was: {}",
            check.detail
        );
        assert!(
            check.detail.contains("198.51.100.2"),
            "was: {}",
            check.detail
        );
        assert!(check.detail.contains('7'), "was: {}", check.detail);
    }

    /// Trusted entries never expire, so the one place they are all visible
    /// has to name every one of them — and say which plane each reaches.
    #[test]
    fn the_trusted_check_names_every_entry_and_how_far_it_reaches() {
        let db = db();
        db.trust_address("203.0.113.7").unwrap();
        db.trust_user_agent("UptimeRobot").unwrap();

        let report = assess(&db, &healthy()).unwrap();

        let check = check2(&report, "trusted");
        assert_eq!(check.level, Level::Ok);
        for needle in [
            "203.0.113.7",
            "firewall and NGINX",
            "UptimeRobot",
            "NGINX only",
        ] {
            assert!(
                check.detail.contains(needle),
                "missing {needle}: {}",
                check.detail
            );
        }
    }

    #[test]
    fn nothing_trusted_adds_no_check() {
        let report = assess(&db(), &healthy()).unwrap();
        assert!(report.checks.iter().all(|c| c.id != "trusted"));
    }

    /// A row an older release stored without today's checks is left out
    /// of the NGINX config; the report is where that is said.
    #[test]
    fn a_stored_entry_the_config_leaves_out_is_a_warning() {
        let db = db();
        assert!(assess(&db, &healthy())
            .unwrap()
            .checks
            .iter()
            .all(|c| c.id != "skipped-entries"));

        db.insert_unvalidated_row_for_tests(
            "blocked_user_agents",
            &[("user_agent", "ab"), ("blocked_at", "0")],
        );
        let report = assess(&db, &healthy()).unwrap();

        let check = check2(&report, "skipped-entries");
        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("\"ab\""), "was: {}", check.detail);
    }

    /// An empty allowlist is the ordinary state of a host that has just
    /// started, so it must never read as a fault.
    #[test]
    fn an_empty_ssh_allowlist_is_not_a_warning() {
        let report = assess(&db(), &healthy()).unwrap();

        let check = check2(&report, "ssh-login-allowlist");
        assert_eq!(check.level, Level::Ok);
        assert!(check.fix.is_none());
    }

    /// A host that has served nothing yet is not misconfigured, and must
    /// not be told it is.
    #[test]
    fn an_empty_access_log_is_not_a_warning() {
        let report = assess(
            &db(),
            &Probe {
                access_log_clients: Some((0, 0)),
                access_log_lines: Some((0, 0)),
                ..healthy()
            },
        )
        .unwrap();

        assert_eq!(check2(&report, "access-log-clients").level, Level::Ok);
        assert_eq!(check2(&report, "access-log-format").level, Level::Ok);
    }

    /// One private client among public ones is ordinary — a monitoring
    /// cron on the host hitting its own site. Only *all* of them is the
    /// signal, or this fires on every healthy server there is.
    #[test]
    fn a_few_private_clients_among_public_ones_are_fine() {
        let report = assess(
            &db(),
            &Probe {
                access_log_clients: Some((880, 900)),
                ..healthy()
            },
        )
        .unwrap();

        assert_eq!(check2(&report, "access-log-clients").level, Level::Ok);
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

    /// A ruleset well short of what was applied is worth saying, but it
    /// is not the same as nothing being loaded at all.
    #[test]
    fn a_ruleset_far_behind_the_applied_one_warns() {
        let db = db();
        with_rules(&db, 100);
        applied_now(&db);

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
        assert!(check.detail.contains("removed"), "was: {}", check.detail);
    }

    /// Rules waiting to be applied are one warning, not two: the kernel is
    /// holding what it was given, and `script-fresh` is the check that
    /// says the rest are waiting.
    #[test]
    fn a_kernel_short_by_the_unapplied_rules_is_said_once() {
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

        let enforced = check(&report, "firewall-enforced");
        assert_eq!(enforced.level, Level::Ok, "was: {}", enforced.detail);
        assert!(
            enforced.detail.contains("not applied"),
            "was: {}",
            enforced.detail
        );
        assert_eq!(check(&report, "script-fresh").level, Level::Warn);
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

    /// A set leaves out an address a range with the same verdict already
    /// covers, so the kernel holds fewer entries than there are rules. The
    /// expected count has to be what the script loads, or a host with
    /// overlapping feeds reads as a ruleset that is behind.
    #[test]
    fn addresses_a_range_already_covers_are_not_expected_in_the_kernel() {
        let db = db();
        with_rules(&db, 100);
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.0/24".to_string(),
            port: None,
            action: crate::db::FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        let report = assess(
            &db,
            &Probe {
                // The /24, and the five structural rules a real dump has.
                live_rules: Some(6),
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "firewall-enforced");
        assert_eq!(check.level, Level::Ok, "was: {}", check.detail);
    }

    /// nftables rules live in kernel memory only. A host that is protected
    /// now and comes back open after a reboot is worth a word.
    /// The advice this check used to give, and why it no longer does.
    ///
    /// `nftables.service` loads /etc/nftables.conf, which is not the file
    /// this project writes -- so recommending it was recommending
    /// something that would not have restored these rules. On a stock
    /// Debian or Ubuntu it is worse than useless: that file opens with
    /// `flush ruleset`, so enabling it drops ufw's tables, Docker's chains
    /// and any geo-blocker's rules once per boot.
    #[test]
    fn the_nftables_fix_never_recommends_enabling_nftables_service() {
        let report = assess(
            &db(),
            &Probe {
                firewall_persists: Some(false),
                nftables_conf_flushes: Some(true),
                ..healthy()
            },
        )
        .unwrap();
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "firewall-persists")
            .expect("the persistence check should be present");
        let fix = check.fix.clone().unwrap_or_default();
        assert!(
            fix.starts_with("stop-bots install firewall"),
            "the fix an operator reads first must be the one that applies *our* \
             script; fix was: {fix}"
        );
        // It may *mention* nftables.service -- warning about it is the point
        // -- but only to say not to. Any occurrence must be negated.
        for (offset, _) in fix.match_indices("enable nftables.service") {
            assert!(
                fix[..offset].contains("do NOT"),
                "every mention of enabling nftables.service must be a warning \
                 against it, not a recommendation; fix was: {fix}"
            );
        }
        assert!(
            fix.contains("flush ruleset"),
            "when /etc/nftables.conf flushes, the fix should say so; fix was: {fix}"
        );
    }

    /// And the detail names the file that is actually not being restored,
    /// rather than a service whose state says nothing about it.
    #[test]
    fn the_nftables_detail_names_the_script_that_is_not_re_applied() {
        let report = assess(
            &db(),
            &Probe {
                firewall_persists: Some(false),
                ..healthy()
            },
        )
        .unwrap();
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "firewall-persists")
            .expect("the persistence check should be present");
        assert!(
            check.detail.contains("firewall.nft"),
            "detail was: {}",
            check.detail
        );
    }

    #[test]
    fn rules_that_will_not_survive_a_reboot_warn_and_name_the_script() {
        let report = assess(
            &db(),
            &Probe {
                firewall_persists: Some(false),
                nftables_conf_flushes: None,
                ..healthy()
            },
        )
        .unwrap();

        let check = check(&report, "firewall-persists");
        assert_eq!(check.level, Level::Warn);
        // The script, not a service: naming `nftables.service` here was
        // what made this check answer a question about a different file.
        assert!(
            check.detail.contains("firewall.nft"),
            "was: {}",
            check.detail
        );
        assert!(
            check.fix.as_deref().unwrap().contains("install firewall"),
            "was: {:?}",
            check.fix
        );
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
                nftables_conf_flushes: None,
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

    /// A host with no console unit — run from the CLI and cron, or with no
    /// systemd at all — is a complete setup, not a broken or unknown one.
    #[test]
    fn no_console_unit_is_fine() {
        let report = assess(
            &db(),
            &Probe {
                unit_active: None,
                ..healthy()
            },
        )
        .unwrap();
        assert_eq!(check(&report, "service-health").level, Level::Ok);
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
    fn a_proxied_console_that_does_not_trust_the_proxy_is_warned_about() {
        let db = db();
        db.set_text_setting(crate::web::BASE_PATH_KEY, "/stop-bots")
            .unwrap();

        let report = assess(&db, &healthy()).unwrap();
        let check = check(&report, "web-proxy");

        assert_eq!(check.level, Level::Warn);
        assert_eq!(
            check.fix.as_deref(),
            Some("stop-bots set-web --trust-forwarded-for true")
        );
    }

    #[test]
    fn a_console_named_by_a_public_host_counts_as_proxied_too() {
        let db = db();
        db.set_text_setting(crate::web::ALLOWED_HOSTS_KEY, "console.example.com")
            .unwrap();

        let report = assess(&db, &healthy()).unwrap();
        assert_eq!(check(&report, "web-proxy").level, Level::Warn);

        db.set_bool_setting(crate::web::TRUST_FORWARDED_KEY, true)
            .unwrap();
        let report = assess(&db, &healthy()).unwrap();
        assert_eq!(check(&report, "web-proxy").level, Level::Ok);
    }

    /// The default install is loopback with no proxy, and has nothing to
    /// say about one.
    #[test]
    fn a_console_that_is_not_proxied_gets_no_proxy_line() {
        let db = db();
        db.set_text_setting(crate::web::ALLOWED_HOSTS_KEY, "localhost")
            .unwrap();

        let report = assess(&db, &healthy()).unwrap();
        assert!(
            report.checks.iter().all(|c| c.id != "web-proxy"),
            "{:?}",
            report.checks
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

    /// A stale script the internal cron is going to fix by itself should
    /// say when, so that the warning reads as "already in hand" rather
    /// than "go and do something". The time is the `RenderFirewall` job's
    /// last run plus its interval.
    #[test]
    fn a_stale_script_the_cron_will_fix_says_when_it_will_happen() {
        let db = db();
        with_rules(&db, 3);
        // Ran an hour ago, so the next daily render is 23 hours out.
        let last_run = now_secs() - 3_600;
        db.set_cron_last_run(
            crate::cron::CronJob::RenderFirewall.id(),
            last_run,
            "rendered",
        )
        .unwrap();

        let report = assess(&db, &healthy()).unwrap();

        let check = check(&report, "script-fresh");
        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains(&format!(
                "Will auto-render at {}",
                format_utc(last_run + 24 * 60 * 60)
            )),
            "no scheduled time in: {}",
            check.detail
        );
    }

    /// A host whose cron has never rendered gets no promise. Nothing has
    /// ever driven the internal cron there — configured from the CLI, say
    /// — and on that host the answer is "never", not "soon".
    #[test]
    fn a_stale_script_with_no_cron_history_promises_nothing() {
        let db = db();
        with_rules(&db, 3);

        let report = assess(&db, &healthy()).unwrap();

        let check = check(&report, "script-fresh");
        assert_eq!(check.level, Level::Warn);
        assert!(
            !check.detail.contains("auto-render"),
            "promised a render nothing is scheduled to do: {}",
            check.detail
        );
    }

    /// An overdue job is not a schedule. Its projected time has already
    /// been and gone, and naming it would tell a reader the render was due
    /// yesterday — which says nothing about whether one is coming.
    #[test]
    fn a_stale_script_whose_render_is_overdue_promises_nothing() {
        let db = db();
        with_rules(&db, 3);
        // Two days ago, against a daily interval: long overdue.
        db.set_cron_last_run(
            crate::cron::CronJob::RenderFirewall.id(),
            now_secs() - 2 * 24 * 60 * 60,
            "rendered",
        )
        .unwrap();

        let report = assess(&db, &healthy()).unwrap();

        let check = check(&report, "script-fresh");
        assert_eq!(check.level, Level::Warn);
        assert!(
            !check.detail.contains("auto-render"),
            "named a time in the past: {}",
            check.detail
        );
    }

    /// What the internal cron leaves behind on its own: the rules rendered
    /// to a script nothing loads. That is not up to date, and saying it was
    /// is how an operator came to believe blocks were enforced.
    #[test]
    fn a_script_rendered_and_not_applied_is_not_up_to_date() {
        let db = db();
        with_rules(&db, 3);
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(
            &crate::firewall::all_rules(&db).unwrap(),
        ))
        .unwrap();

        let report = assess(&db, &healthy()).unwrap();
        let check = check(&report, "script-fresh");

        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("not applied"), "{}", check.detail);
        assert!(
            check.detail.contains("firewall.next.nft"),
            "it should name the file waiting: {}",
            check.detail
        );
        assert!(
            check
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("--apply")),
            "{:?}",
            check.fix
        );
    }

    /// A database from before the applied signature existed has none. It
    /// reads as not applied until the first apply — nothing recorded what
    /// the kernel was given — but a fresh one with nothing to enforce is
    /// not warned about, even once the cron has rendered its empty script.
    #[test]
    fn a_fresh_database_the_cron_rendered_is_not_told_to_apply() {
        let db = db();
        db.set_firewall_rendered_signature(&crate::firewall::rules_signature(
            &crate::firewall::all_rules(&db).unwrap(),
        ))
        .unwrap();

        let report = assess(&db, &healthy()).unwrap();

        assert_eq!(check(&report, "script-fresh").level, Level::Ok);
    }

    /// The line belongs to the warning, not to the check: rules that are
    /// the ones applied have nothing to say about a future render.
    #[test]
    fn an_up_to_date_script_says_nothing_about_auto_rendering() {
        let db = db();
        with_rules(&db, 3);
        applied_now(&db);
        db.set_cron_last_run(
            crate::cron::CronJob::RenderFirewall.id(),
            now_secs() - 3_600,
            "rendered",
        )
        .unwrap();

        let report = assess(&db, &healthy()).unwrap();
        let check = check(&report, "script-fresh");

        assert_eq!(check.level, Level::Ok);
        assert!(!check.detail.contains("auto-render"), "{}", check.detail);
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
        assert_eq!(check.level, Level::Ok);
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
            nftables_conf_flushes: None,
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

    /// What `nft list table` prints for a rendered script with sets,
    /// verbatim from nftables 1.0.9: the elements are what the script
    /// loaded, one per address, and a rule that matches a set is not one
    /// more.
    #[test]
    fn nft_set_elements_are_counted_and_the_rules_that_match_them_are_not() {
        let dump = "table inet stop_bots {\n\
                    \tset allow_v4 {\n\
                    \t\ttype ipv4_addr\n\
                    \t\tflags interval\n\
                    \t\telements = { 203.0.113.7 }\n\
                    \t}\n\
                    \n\
                    \tset block_v4 {\n\
                    \t\ttype ipv4_addr\n\
                    \t\tflags interval,timeout\n\
                    \t\telements = { 192.0.2.77 timeout 1d1h expires 1d59m59s989ms, 198.51.100.0/24,\n\
                    \t\t\t     198.51.101.0/24, 198.51.102.0/24 }\n\
                    \t}\n\
                    \n\
                    \tchain bot_block {\n\
                    \t\ttype filter hook input priority filter - 1; policy accept;\n\
                    \t\tct state established,related accept\n\
                    \t\tiif \"lo\" accept\n\
                    \t\tjump bot_rules\n\
                    \t}\n\
                    \n\
                    \tchain bot_rules {\n\
                    \t\tip saddr @allow_v4 accept\n\
                    \t\tip saddr @block_v4 drop\n\
                    \t\tip saddr 192.0.2.9 tcp dport 22 reject with icmp port-unreachable\n\
                    \t}\n\
                    }\n";

        // Five elements, two structural accepts, and the reject.
        assert_eq!(count_nft_rules(dump), 8);
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

    /// A database directory whose name starts with `-` is still a path.
    #[test]
    fn df_is_told_where_the_options_end() {
        let args = df_args("-weird");

        assert_eq!(args[args.len() - 2..], ["--", "-weird"], "args: {args:?}");
    }

    /// The size check reports rather than judges on an ordinary database,
    /// and the number it reports is the one an admin would get from `du`
    /// once the write-ahead log is checkpointed: the `-wal` is bounded and
    /// comes and goes, and is not what a size check is watching grow.
    #[test]
    fn database_size_reports_an_ordinary_database_without_complaint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ordinary.sqlite3");
        let db = Db::open(&path).unwrap();
        db.checkpoint().unwrap();

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

    /// Cross-checked against `date -u -d @<epoch>` rather than against the
    /// same arithmetic written twice. The cases are the ones that break a
    /// hand-rolled civil-date conversion: both kinds of leap year (2000 is
    /// one, being divisible by 400; 2024 the ordinary kind), the epoch
    /// itself, a negative timestamp, and the far end of the range.
    #[test]
    fn format_utc_agrees_with_the_calendar() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_709_164_800), "2024-02-29 00:00 UTC");
        assert_eq!(format_utc(1_789_483_239), "2026-09-15 14:40 UTC");
        assert_eq!(format_utc(253_402_300_799), "9999-12-31 23:59 UTC");
    }

    /// A pre-epoch timestamp must floor, not truncate toward zero — `/`
    /// and `%` would put this on 1970-01-01 at a negative hour.
    #[test]
    fn format_utc_handles_a_time_before_the_epoch() {
        assert_eq!(format_utc(-86_400), "1969-12-31 00:00 UTC");
        assert_eq!(format_utc(-1), "1969-12-31 23:59 UTC");
    }

    #[test]
    fn human_bytes_reads_as_a_person_would_write_it() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(512), "512.0B");
        assert_eq!(human_bytes(1536), "1.5KB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0GB");
    }

    /// A custom `log_format`: a million lines, none of them read, and the
    /// report used to call it OK.
    #[test]
    fn a_log_mostly_in_an_unread_format_is_a_warning_that_quotes_it() {
        let db = db();
        let report = assess(
            &db,
            &Probe {
                access_log_lines: Some((1000, 10)),
                access_log_clients: Some((10, 10)),
                access_log_unparsed_sample: Some("203.0.113.5 my-format /x".to_string()),
                ..healthy()
            },
        )
        .unwrap();

        let check = check2(&report, "access-log-format");
        assert_eq!(check.level, Level::Warn, "{check:?}");
        assert!(
            check.detail.contains("10 of 1000") && check.detail.contains("my-format"),
            "{}",
            check.detail
        );
        let fix = check.fix.as_deref().unwrap_or_default();
        assert!(
            fix.contains("combined") && fix.contains("escape=json"),
            "{fix}"
        );
    }

    /// And the check beside it no longer calls an unread log empty.
    #[test]
    fn a_log_that_parses_to_nothing_is_not_reported_as_empty() {
        let db = db();
        let report = assess(
            &db,
            &Probe {
                access_log_lines: Some((500, 0)),
                access_log_clients: Some((0, 0)),
                ..healthy()
            },
        )
        .unwrap();

        assert_eq!(check2(&report, "access-log-format").level, Level::Warn);
        let clients = check2(&report, "access-log-clients");
        assert!(
            !clients.detail.contains("no requests recorded yet"),
            "{clients:?}"
        );
    }

    #[test]
    fn a_log_that_mostly_parses_is_fine() {
        let db = db();
        let report = assess(
            &db,
            &Probe {
                access_log_lines: Some((100, 60)),
                ..healthy()
            },
        )
        .unwrap();
        assert_eq!(check2(&report, "access-log-format").level, Level::Ok);
    }

    /// A probe stored by an older version has no line counts; it still
    /// parses, and the new check has nothing to say about it.
    #[test]
    fn a_probe_from_before_the_format_check_still_reads() {
        let mut stored = serde_json::to_value(healthy()).unwrap();
        let object = stored.as_object_mut().unwrap();
        object.remove("access_log_lines");
        object.remove("access_log_unparsed_sample");
        let probe: Probe = serde_json::from_value(stored).unwrap();
        assert_eq!(probe.access_log_lines, None);
    }

    /// A synthetic access log: `edge` lines from Cloudflare addresses and
    /// `direct` lines from a documentation range, surveyed the way a probe
    /// reads a real one.
    fn cdn_probe(edge: usize, direct: usize) -> Probe {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        let line = |ip: String| {
            format!("{ip} - - [28/Sep/2026:06:33:01 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"UA\"\n")
        };
        let text: String = (0..edge)
            .map(|i| line(format!("172.70.{}.{}", i / 200, i % 200 + 1)))
            .chain((0..direct).map(|i| line(format!("198.51.100.{}", i % 250 + 1))))
            .collect();
        std::fs::write(&log, text).unwrap();
        let survey = access_log_sample(&log, 403).expect("readable");
        Probe {
            access_log_clients: Some((survey.public, survey.counts.parsed)),
            access_log_cdn: Some(survey.cdn),
            ..Probe::default()
        }
    }

    /// Behind Cloudflare without `set_real_ip_from`, the log holds nothing
    /// but edges, the detectors can block none of them, and every other
    /// check reads OK. This is the one that says so, and says what to add.
    #[test]
    fn an_access_log_of_cdn_edges_is_reported_with_the_real_ip_fix() {
        let probe = cdn_probe(180, 20);
        assert_eq!(probe.access_log_cdn, Some(180));

        let check = cdn_edges(&probe).expect("a warning");

        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("180 of 200"), "{}", check.detail);
        let fix = check.fix.clone().unwrap_or_default();
        for needle in [
            "set_real_ip_from 173.245.48.0/20;",
            "real_ip_header CF-Connecting-IP;",
        ] {
            assert!(fix.contains(needle), "no {needle:?} in: {fix}");
        }
        assert_eq!(crate::present::check_label(&check), "cdn");
    }

    /// A host served directly sees an edge now and then — Workers, or a
    /// crawler hosted there — and a new host has too little to go on.
    #[test]
    fn a_few_edge_addresses_are_not_a_cdn_in_front() {
        for (edge, direct, why) in [(10, 190, "mostly direct"), (20, 0, "too few lines")] {
            assert!(cdn_edges(&cdn_probe(edge, direct)).is_none(), "{why}");
        }
    }

    /// The probe's sample of a real file: counts, quoted line and all.
    #[test]
    fn the_access_log_sample_counts_its_lines_and_quotes_one_safely() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        std::fs::write(
            &log,
            "203.0.113.5 - - [28/Sep/2026:06:33:01 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"UA\"\n\
             custom \x1b[2J format\n",
        )
        .unwrap();

        let survey = access_log_sample(&log, 403).expect("readable");

        assert_eq!(
            (survey.counts.lines, survey.counts.parsed, survey.public),
            (2, 1, 1)
        );
        assert_eq!(
            survey.unparsed_sample.as_deref(),
            Some("custom \u{fffd}[2J format")
        );
        assert!(access_log_sample(&dir.path().join("none.log"), 403).is_none());
    }
}
