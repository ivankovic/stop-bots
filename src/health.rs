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

//! Is this host actually protected?
//!
//! Every other check in this project compares what it *would* generate
//! against what is *on disk*. None of them looks at the kernel. That gap
//! is not hypothetical: a real host ran for three weeks with 48,860
//! generated drop rules in `/etc/stop-bots/firewall.nft` and an empty
//! ruleset, because writing the script and loading it are two steps and
//! only the first had ever been checked.
//!
//! Split in two, the same way [`crate::refresh`] is, and for the same
//! reason:
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

use std::path::Path;
use std::process::Command;

use anyhow::Result;

use crate::db::{Db, FirewallAction, FirewallRule, ACME_HTTP_PORT};
use crate::firewall::{self, FirewallBackend};
use crate::webserver;

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
    /// Every access log the detectors read, from the probe: what `status
    /// --json` lists beside the checks.
    pub access_logs: Vec<AccessLogState>,
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
    /// Whether `install cron`'s file is in `/etc/cron.d`. `None` in a probe
    /// taken before this was carried.
    #[serde(default)]
    pub cron_installed: Option<bool>,
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
    /// Every access log a pass reads, the stored or default one first,
    /// then those the web server's config names (see
    /// [`crate::logpaths::LogPaths::access_logs_to_read`]), each with
    /// whether it could be opened. Empty in a probe from before it was
    /// carried here.
    #[serde(default)]
    pub access_logs: Vec<AccessLogState>,
    /// Whether the kernel log, which the port-scan detector reads, could
    /// be read, and what was tried. `None` in a probe from before it was
    /// carried here.
    #[serde(default)]
    pub kernel_log_readable: Option<bool>,
    #[serde(default)]
    pub kernel_log_path: Option<String>,
    /// Whether `ss` could say what listens, which the port-scan
    /// detector's trap needs. `None` in a probe from before it was asked.
    #[serde(default)]
    pub listening_known: Option<bool>,
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
    /// Of the parsed lines in [`Self::access_log_lines`], how many name a
    /// user agent. `None` when the log could not be read, and in a probe
    /// from before this was counted.
    #[serde(default)]
    pub access_log_user_agents: Option<usize>,
    /// The NGINX test and reload commands the host settings name, for
    /// [`nginx_deployment`] to check against where NGINX runs. `None` from
    /// a probe taken before they were carried here, or when the setting
    /// does not parse; read as the defaults.
    #[serde(default)]
    pub nginx_commands: Option<crate::webserver::ServerCommands>,
    /// Which web server the host settings choose. NGINX in a probe taken
    /// before there was a choice, which is what that host ran.
    #[serde(default)]
    pub web_server: crate::webserver::WebServer,
    /// The web server's config root, as the host settings resolve it.
    /// `None` in a probe from before it was carried here.
    #[serde(default)]
    pub config_root: Option<String>,
    /// Apache only: whether `mod_rewrite`, which every block is written
    /// in, is enabled. `None` for NGINX, or where Debian's `mods-enabled`
    /// is not there to ask.
    #[serde(default)]
    pub apache_rewrite_enabled: Option<bool>,
    /// How many of certbot's certificates renew with an http-01 challenge,
    /// which Let's Encrypt fetches over port 80. `None` when certbot's
    /// renewal directory is there and could not be read; `Some(0)` on a
    /// host without one.
    #[serde(default)]
    pub http_renewals: Option<usize>,
    /// What this host's own sites served when asked for `/.env` and the
    /// like over loopback ([`crate::exposure`]). `None` when there were no
    /// sites to ask, or in a probe from before this was carried.
    #[serde(default)]
    pub exposed_files: Option<crate::exposure::Survey>,
}

/// One access log the detectors read, as a probe found it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessLogState {
    pub path: String,
    /// Where the path came from: [`crate::logpaths::LogOrigin::id`].
    pub origin: String,
    pub readable: bool,
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
fn access_log_sample(
    path: &Path,
    block_status: u16,
    claims: Vec<crate::accesslog::CrawlerClaim>,
) -> Option<crate::accesslog::Survey> {
    let mut survey = crate::accesslog::Survey::new(block_status).with_claims(claims);
    crate::logread::read_tail(path, ACCESS_LOG_SAMPLE_BYTES, &mut |line| survey.line(line)).ok()?;
    Some(survey)
}

/// Runs everything that needs a subprocess or the filesystem.
///
/// Never fails: a probe that cannot answer a question leaves that field
/// `None`, because "I could not check" is a result the report has to be
/// able to show. An error here would mean no report at all, which is the
/// least useful outcome available.
///
/// Where to look comes from `host` ([`crate::hostconf`]): the logs, the
/// NGINX root whose `conf.d` is checked, and the NGINX commands, which are
/// carried in the probe for [`assess`] to judge. `claims` are the
/// crawlers' published ranges ([`crate::scanblock::crawler_claims`]), so that
/// an impersonator refused is not counted as one of this host's clients.
pub fn probe(
    backend: FirewallBackend,
    db_path: &Path,
    ssh_log: Option<&Path>,
    host: &crate::hostconf::HostConf,
    block_status: u16,
    claims: Vec<crate::accesslog::CrawlerClaim>,
) -> Probe {
    let paths = &host.log_paths();
    let conf_d = &crate::nginx::conf_d_dir(&host.root(None));
    let live = live_firewall(backend);
    let (live_rules, live_backend) = match &live {
        Some(state) => (Some(state.rules), Some(backend.stored().to_string())),
        None => (None, None),
    };
    // Read once, and only the tail, and every access-log question answered
    // from that one pass: two reads would be two different moments.
    let sample = access_log_sample(&paths.access_path(None), block_status, claims);
    let access_readable = sample.is_some();
    let survey = sample.unwrap_or_default();
    let nginx_home = nginx_home();
    // Asked, not read: this used to read the whole log, which on a
    // journald host was the whole sshd journal, once an hour.
    let ssh_readable = paths.ssh(ssh_log).is_readable();
    let container = match &nginx_home {
        NginxHome::Container { name } => Some(name.clone()),
        _ => None,
    };
    let server = host.web_server();
    let config_root = host.root(None);
    let mods_enabled = config_root.join("mods-enabled");
    Probe {
        web_server: server,
        config_root: Some(config_root.display().to_string()),
        apache_rewrite_enabled: (server == crate::webserver::WebServer::Apache
            && mods_enabled.is_dir())
        .then(|| mods_enabled.join("rewrite.load").exists()),
        nginx_commands: host.commands().ok(),
        live_rules,
        live_backend,
        // From the same read as every other access-log answer below.
        turned_away: survey.turned_away(),
        conf_d_path: Some(conf_d.display().to_string()),
        conf_d_exists: Some(conf_d.is_dir()),
        stray_generated_files: stray_generated_files(conf_d, Path::new(crate::nginx::CONF_D_DIR)),
        firewall_persists: firewall_persists(backend),
        nftables_conf_flushes: nftables_conf_flushes(),
        cron_installed: Some(
            Path::new("/etc/cron.d")
                .join(crate::install::CRON_FILE)
                .is_file(),
        ),
        db_free_bytes: free_bytes(db_path),
        ssh_log_readable: Some(ssh_readable),
        access_log_readable: Some(access_readable),
        access_log_path: Some(paths.access_description(None)),
        access_logs: paths
            .access_logs_to_read(None)
            .into_iter()
            .map(|log| AccessLogState {
                readable: crate::logread::open_log(&log.path).is_ok(),
                path: log.path.display().to_string(),
                origin: log.origin.id().to_string(),
            })
            .collect(),
        kernel_log_readable: Some(crate::portscan::kernel_log_is_readable(&paths.kernel(None))),
        kernel_log_path: Some(paths.kernel_description(None)),
        listening_known: Some(crate::portscan::listening_ports().is_some()),
        access_log_clients: access_readable.then_some((survey.public, survey.counts.parsed)),
        access_log_lines: access_readable.then_some((survey.counts.lines, survey.counts.parsed)),
        access_log_unparsed_sample: survey.unparsed_sample.clone(),
        access_log_cdn: access_readable.then_some(survey.cdn),
        access_log_user_agents: access_readable.then_some(survey.with_user_agent),
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
        http_renewals: http_renewals(Path::new(CERTBOT_RENEWAL_DIR)),
        exposed_files: exposed_files_survey(server, &config_root, block_status),
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

/// Asks every site under `root` for the files [`crate::exposure`] lists.
/// `None`, and nothing asked, when there are no sites or no root.
fn exposed_files_survey(
    server: crate::webserver::WebServer,
    root: &Path,
    block_status: u16,
) -> Option<crate::exposure::Survey> {
    let sites = server.site_listens(root).ok()?;
    let targets = crate::exposure::targets(&sites);
    if targets.is_empty() {
        return None;
    }
    Some(crate::exposure::survey(
        &targets,
        block_status,
        crate::exposure::Limits::default(),
    ))
}

/// Where certbot keeps one `.conf` per certificate it renews.
const CERTBOT_RENEWAL_DIR: &str = "/etc/letsencrypt/renewal";

/// The certbot authenticators that answer an http-01 challenge, all of
/// them on port 80. The DNS plugins (`dns-cloudflare` and friends) do not
/// touch this host's firewall, and `manual` could be either.
const HTTP_AUTHENTICATORS: [&str; 4] = ["nginx", "apache", "webroot", "standalone"];

/// See [`Probe::http_renewals`].
fn http_renewals(dir: &Path) -> Option<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(0),
        Err(_) => return None,
    };
    let mut count = 0;
    for entry in entries {
        let path = entry.ok()?.path();
        if path.extension().is_none_or(|ext| ext != "conf") {
            continue;
        }
        let text = std::fs::read_to_string(&path).ok()?;
        let authenticator = text.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "authenticator").then(|| value.trim().to_string())
        });
        if authenticator.is_some_and(|a| HTTP_AUTHENTICATORS.contains(&a.as_str())) {
            count += 1;
        }
    }
    Some(count)
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
        == Some(firewall::current_signature(db)?.as_str());
    checks.push(firewall_enforced(probe, loadable, applied));
    checks.push(firewall_persistence(probe, backend));
    checks.push(script_freshness(db, expected, backend)?);
    checks.push(nginx_applied(db, probe)?);
    if probe.web_server == webserver::WebServer::Nginx {
        checks.push(generated_files_reachable(probe));
    }
    if let Some(check) = apache_rewrite(probe) {
        checks.push(check);
    }
    checks.push(schedule(db, probe)?);
    checks.push(disk_room(probe));
    checks.push(database_size(db)?);
    checks.push(log_sources(probe));
    if let Some(check) = port_scan_sources(db, probe)? {
        checks.push(check);
    }
    checks.push(access_log_format(probe));
    if let Some(check) = access_log_user_agents(probe) {
        checks.push(check);
    }
    checks.push(access_log_clients(probe));
    if let Some(check) = cdn_edges(probe) {
        checks.push(check);
    }
    checks.push(ssh_login_allowlist(db)?);
    if let Some(check) = ssh_lockout_check_off(db)? {
        checks.push(check);
    }
    if let Some(check) = lets_encrypt_reachable(&rules, probe) {
        checks.push(check);
    }
    if let Some(check) = exposed_files(probe) {
        checks.push(check);
    }
    if let Some(check) = trusted_by_hand(db, probe.web_server)? {
        checks.push(check);
    }
    if let Some(check) = hosting_asns_not_fetched(db)? {
        checks.push(check);
    }
    if let Some(check) = skipped_entries(db, probe.web_server)? {
        checks.push(check);
    }
    if let Some(check) = turned_away_clients(db, probe)? {
        checks.push(check);
    }
    // Adds a line only on a host where NGINX really is in a container.
    if let Some(check) = firewall_reaches_containers(probe) {
        checks.push(check);
    }
    if probe.web_server == webserver::WebServer::Nginx {
        if let Some(check) = nginx_deployment(db, probe)? {
            checks.push(check);
        }
    }

    Ok(Report {
        checks,
        checked_at: now_secs(),
        access_logs: probe.access_logs.clone(),
    })
}

/// Whether `user_agent` is refused by a choice somebody made about it: a
/// bot the lists class as a scanner or an AI crawler, or an agent blocked
/// by hand. Its refusal is the policy working, however much it was served
/// before it was listed — a scanner gets through until a list names it.
///
/// What is left is the case [`turned_away_clients`] exists for: a client
/// caught by an uncategorised pattern, as Nextcloud's and Jellyfin's apps
/// were by `okhttp`, or by a rule about the shape of a request. Matched as
/// the Firewall screen matches ([`crate::dynamic::matched_alternative`]),
/// and a hand-blocked agent as NGINX matches it: a substring, in any case.
fn refused_on_purpose(user_agent: &str, bots: &[crate::db::Bot], by_hand: &[String]) -> bool {
    let lower = user_agent.to_lowercase();
    by_hand
        .iter()
        .any(|blocked| lower.contains(&crate::db::stored_user_agent(blocked).to_lowercase()))
        || bots.iter().any(|bot| {
            (bot.is_scanner || bot.is_ai)
                && crate::dynamic::matched_alternative(user_agent, bot).is_some()
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
    let bots = db.list_bots()?;
    let by_hand = db.list_blocked_user_agents()?;
    let mut regressions: Vec<&crate::accesslog::TurnedAway> = Vec::new();
    for entry in &probe.turned_away {
        if entry.refused < TURNED_AWAY_MIN_REFUSALS {
            continue;
        }
        if refused_on_purpose(&entry.user_agent, &bots, &by_hand) {
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
        // The agent is a client's text, and this line is drawn on the
        // TUI's Dashboard: capped, and with anything invisible written out.
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
             `stop-bots add-trusted --user-agent \"<part of the agent>\"`"
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
/// missed: `tick` from cron is only one of the things that drives this
/// schedule (the TUI does, and so does `stop-bots batch` from a crontab of
/// the operator's own), so there is no signal that distinguishes them, and
/// the `schedule` check below already reports a schedule nothing has run
/// lately.
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

/// Apache's blocks are `mod_rewrite` rules, and Debian ships the module
/// switched off. Without it the config test fails, so an apply is refused
/// and nothing is protected — which this says before an apply does.
fn apache_rewrite(probe: &Probe) -> Option<Check> {
    let enabled = probe.apache_rewrite_enabled?;
    Some(Check {
        id: "apache-rewrite",
        title: "Apache can run the blocks",
        level: if enabled { Level::Ok } else { Level::Critical },
        detail: if enabled {
            "mod_rewrite is enabled".to_string()
        } else {
            "mod_rewrite is not enabled, so no block can be applied".to_string()
        },
        fix: (!enabled).then(|| "run `a2enmod rewrite`, then apply".to_string()),
    })
}

fn nginx_applied(db: &Db, probe: &Probe) -> Result<Check> {
    use crate::nginx;
    use crate::webserver::SiteApplyStatus;

    let sites = db.list_sites()?;
    let total = sites.len();
    // Reads each site's config file, the same way the NGINX screen
    // does — this is the one check here that touches the filesystem from
    // `assess` rather than from `probe`, because it needs a per-site
    // `BlockConfig` that only the database can produce.
    let mut stale: Vec<String> = Vec::new();
    // The `conf.d` the probe looked at, which is the host settings' root's.
    let conf_d = probe
        .conf_d_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| nginx::conf_d_dir(Path::new(nginx::DEFAULT_ROOT)));
    for site in sites {
        let config = webserver::block_config_for_site(db, site.id)?;
        let path = Path::new(&site.config_path);
        let status = match (probe.web_server, &probe.config_root) {
            (webserver::WebServer::Nginx, _) | (_, None) => {
                nginx::site_apply_status(path, &site.server_name, &config, &conf_d)
            }
            (server, Some(root)) => {
                server.site_apply_status(path, &site.server_name, &config, Path::new(root))
            }
        };
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
        // The id predates there being a choice, and is kept for whatever
        // reads it; the title names the server.
        id: "nginx-applied",
        title: match probe.web_server {
            webserver::WebServer::Nginx => "NGINX blocks are applied",
            webserver::WebServer::Apache => "Apache blocks are applied",
            webserver::WebServer::Traefik => "Traefik routers are applied",
            webserver::WebServer::Npmplus => "NPMplus blocks are applied",
        },
        level,
        detail,
        fix,
    })
}

/// How long the detectors can go unrun before the schedule reads as
/// stopped: ten of their one-minute intervals.
const SCHEDULE_STALE_SECS: i64 = 10 * 60;

/// Whether anything runs the schedule: `stop-bots tick` from
/// `/etc/cron.d`, or the TUI while it is open.
///
/// Read from when the detectors last ran rather than from whether the file
/// is there, because the file is a promise and the run is the fact: cron
/// not installed, not running, or failing every minute all look like an
/// installed file. Without the file, the TUI may still be running the
/// schedule, which the same runs show; once it closes, nothing does.
fn schedule(db: &Db, probe: &Probe) -> Result<Check> {
    let last_run = crate::cron::status(db)?
        .into_iter()
        .filter(|job| matches!(job.job, crate::cron::CronJob::Detect(_)))
        .filter_map(|job| job.last_run)
        .max();
    let recent = last_run.is_some_and(|at| now_secs() - at < SCHEDULE_STALE_SECS);
    let since = last_run
        .map(|at| format!("last ran {}", format_utc(at)))
        .unwrap_or_else(|| "has never run".to_string());
    let (level, detail, fix) = match (probe.cron_installed, recent) {
        (Some(true), true) => (
            Level::Ok,
            format!(
                "/etc/cron.d/{} runs it every minute",
                crate::install::CRON_FILE
            ),
            None,
        ),
        (Some(true), false) => (
            Level::Warn,
            format!(
                "/etc/cron.d/{} is installed, but the schedule {since}: is cron running?",
                crate::install::CRON_FILE
            ),
            Some("systemctl status cron".to_string()),
        ),
        (_, true) => (
            Level::Ok,
            "running while the TUI is open; nothing runs it once it closes".to_string(),
            Some("stop-bots install cron".to_string()),
        ),
        (_, false) => (
            Level::Warn,
            format!(
                "nothing runs the detectors and list updates unattended (the schedule {since})"
            ),
            Some("stop-bots install cron".to_string()),
        ),
    };
    Ok(Check {
        id: "schedule",
        title: "Schedule",
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
            Some(match probe.web_server {
                webserver::WebServer::Nginx => "NGINX is logging its proxy's address, not the client's. If it runs behind a container port mapping, a load balancer or a CDN, set `set_real_ip_from` and `real_ip_header` so $remote_addr is the visitor again.",
                webserver::WebServer::Apache => "Apache is logging its proxy's address, not the client's. If it runs behind a container port mapping, a load balancer or a CDN, enable mod_remoteip (`sudo a2enmod remoteip`), set `RemoteIPHeader` and `RemoteIPTrustedProxy`, and log `%a` in place of `%h` so the log names the visitor again.",
                webserver::WebServer::Traefik => "Traefik is logging its proxy's address, not the client's. Behind a load balancer or a CDN, list its addresses in each entrypoint's `forwardedHeaders.trustedIPs`, and Traefik logs the visitor from `X-Forwarded-For`. In rootless Docker or a Swarm, publish its ports in `host` mode so connections reach it from the visitor.",
                webserver::WebServer::Npmplus => "NPMplus is logging its proxy's address, not the client's. Behind a load balancer or a CDN, list its addresses in `TRUST_IP` in NPMplus's compose.yaml, and NPMplus logs the visitor from `X-Forwarded-For`. Run it with `network_mode: host`, as its compose file does, so connections reach it from the visitor.",
            }
            .to_string()),
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
        fix: Some(match probe.web_server {
            webserver::WebServer::Nginx => format!(
                "Tell NGINX to log the visitor's address, from the header {} adds, in the \
                 `http` block (ngx_http_realip_module): {}",
                crate::cdn::NAME,
                crate::cdn::real_ip_config()
            ),
            webserver::WebServer::Apache => format!(
                "Tell Apache to log the visitor's address, from the header {} adds, with \
                 mod_remoteip (`sudo a2enmod remoteip`): {}, and `%a` in place of `%h` in the \
                 log format",
                crate::cdn::NAME,
                crate::cdn::apache_real_ip_config()
            ),
            webserver::WebServer::Traefik => format!(
                "Tell Traefik to log the visitor's address, from the `X-Forwarded-For` {} \
                 sends, by trusting its edges on each entrypoint: {}",
                crate::cdn::NAME,
                crate::cdn::traefik_real_ip_config()
            ),
            webserver::WebServer::Npmplus => format!(
                "Tell NPMplus to log the visitor's address, from the header {} adds: set \
                 `TRUST_CLOUDFLARE=true` in its compose.yaml and recreate the container",
                crate::cdn::NAME
            ),
        }),
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
                    match probe.web_server {
                        webserver::WebServer::Nginx => {
                            "log in NGINX's `combined` format, or a JSON `log_format ... \
                             escape=json` keyed by the variable names (remote_addr, status, \
                             request_uri or request, http_referer, http_user_agent, time_local \
                             or time_iso8601); NPMplus's own access.log format also reads"
                        }
                        // The JSON form is NGINX's `log_format` variables;
                        // Apache's stock format is the one to point at.
                        webserver::WebServer::Apache => {
                            "log in Apache's `combined` format (`CustomLog <path> combined`), \
                             which is the format the detectors read"
                        }
                        // Either of Traefik's own formats reads; anything
                        // else in the file is someone else's.
                        webserver::WebServer::Traefik => {
                            "point stop-bots at the file Traefik's `accessLog.filePath` names, \
                             in either of its formats (`common` or `json`): `stop-bots \
                             set-log-paths --access-log <file>`"
                        }
                        // Both of the formats NPMplus has written read.
                        webserver::WebServer::Npmplus => {
                            "point stop-bots at the access.log NPMplus writes with \
                             `LOGROTATE=true`, in its data directory's nginx/logs: `stop-bots \
                             set-log-paths --access-log /opt/npmplus/nginx/logs/access.log`"
                        }
                    }
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

/// Fewer parsed lines than this say too little about a log to call its
/// format blind to user agents: a host that has served three health checks
/// with no user agent has not shown anything.
const ACCESS_LOG_MIN_FOR_USER_AGENTS: usize = 20;

/// Whether the access log records the user agent, when it plainly does
/// not: not one of many parsed lines names one. Every bot list's pattern,
/// the forged-crawler and rotating-agent detectors and the tally of who was
/// turned away all read it, and all of them see nothing — silently, from a
/// log that parses perfectly. Traefik's does exactly this until it is told
/// to keep the header.
fn access_log_user_agents(probe: &Probe) -> Option<Check> {
    let (_, parsed) = probe.access_log_lines?;
    let named = probe.access_log_user_agents?;
    if parsed < ACCESS_LOG_MIN_FOR_USER_AGENTS || named > 0 {
        return None;
    }
    Some(Check {
        id: "access-log-user-agents",
        title: "Access log records user agents",
        level: Level::Warn,
        detail: format!(
            "none of {parsed} recent request(s) in the log names a user agent, so no bot list \
             and no detector that reads one can see anything"
        ),
        fix: Some(
            match probe.web_server {
                webserver::WebServer::Traefik => {
                    "tell Traefik's access log to keep the headers the detectors read: \
                     `accessLog.fields.headers.names.User-Agent: keep` and `Referer: keep` \
                     (`--accesslog.fields.headers.names.User-Agent=keep` as a flag)"
                }
                webserver::WebServer::Nginx | webserver::WebServer::Apache => {
                    "log in the `combined` format, which records the user agent and the referer"
                }
                webserver::WebServer::Npmplus => {
                    "point stop-bots at the access.log NPMplus writes, which records the user \
                     agent and the referer"
                }
            }
            .to_string(),
        ),
    })
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

/// Whether the lock-out check is off on a host where someone does log in
/// over SSH. It is turned off by answering "I never log in over SSH", and
/// this is what notices when that stops being true. `None` while it is on.
fn ssh_lockout_check_off(db: &Db) -> Result<Option<Check>> {
    if db.get_ssh_lockout_check()? {
        return Ok(None);
    }
    let addresses = db.recent_ssh_login_ips()?;
    let days = crate::db::SSH_LOGIN_WINDOW_SECONDS / (24 * 60 * 60);
    let check = if addresses.is_empty() {
        Check {
            id: "ssh-lockout-check",
            title: "SSH lock-out check",
            level: Level::Ok,
            detail: format!(
                "off, and no one has logged in over SSH in the last {days} days: applies are \
                 not checked against SSH logins"
            ),
            fix: None,
        }
    } else {
        Check {
            id: "ssh-lockout-check",
            title: "SSH lock-out check",
            level: Level::Warn,
            detail: format!(
                "off, but {} logged in over SSH in the last {days} days: applies are not \
                 checked against those logins",
                addresses.join(", ")
            ),
            fix: Some(
                "turn it back on: `stop-bots set-ssh-lockout-check --enabled true`, or the \
                 SSH lock-out check row on the Dashboard"
                    .to_string(),
            ),
        }
    };
    Ok(Some(check))
}

/// Addresses Let's Encrypt fetched an http-01 challenge from, as a capture
/// on a real host caught them in October 2026: the first two families are
/// its own primary validators, the rest the secondary ones it runs in AWS
/// regions. It publishes no list and moves them when it likes, so this is a
/// sample, not the set; what it can show is a firewall that drops the
/// kind of address a renewal needs.
const LETS_ENCRYPT_VALIDATORS: [&str; 13] = [
    "23.178.112.103",
    "2600:3000:2710:200::83",
    "13.250.204.32",
    "13.51.169.225",
    "16.147.27.145",
    "18.216.118.75",
    "34.214.124.47",
    "51.20.251.217",
    "2406:da18:611:5702:7d40:9ed0:9c66:50a5",
    "2600:1f14:a8b:500:40f3:828d:f5cd:faa",
    "2600:1f16:13c:c402:11cd:b415:5ace:6e8a",
    "2a05:d016:dcc:9100:d24b:ecf0:d1ac:d0a1",
    "2a05:d016:dcc:9101:5fe4:af21:e3e4:80c8",
];

/// Whether Let's Encrypt can still reach port 80, on a host whose
/// certificates renew there.
///
/// Found by chance: with the AWS feed on, a host's every renewal failed,
/// the first validator getting its challenge and the AWS ones timing out,
/// and the only sign was certbot's own failed unit. The feeds
/// now leave port 80 open, but Allowlist geo mode, an abuse list or a rule
/// added by hand can still close it — and the price is every site on the
/// host going down the day its certificate expires.
///
/// Absent on a host with no such certificate, which is most of the reason
/// to ask the filesystem first.
fn lets_encrypt_reachable(rules: &[FirewallRule], probe: &Probe) -> Option<Check> {
    let renewals = probe.http_renewals.filter(|&n| n > 0)?;
    let now = now_secs();
    let dropped: Vec<String> = LETS_ENCRYPT_VALIDATORS
        .iter()
        .filter_map(|address| {
            let rule = firewall::first_match(rules, address.parse().ok()?, ACME_HTTP_PORT, now)?;
            (rule.action == FirewallAction::Block)
                .then(|| format!("{address} (by {})", rule.address.trim()))
        })
        .collect();
    let check = |level, detail, fix| Check {
        id: "lets-encrypt-reachable",
        title: "Let's Encrypt can renew",
        level,
        detail,
        fix,
    };
    Some(if dropped.is_empty() {
        check(
            Level::Ok,
            format!(
                "{renewals} certificate(s) renew over port 80, and the firewall lets {} known validator address(es) reach it",
                LETS_ENCRYPT_VALIDATORS.len()
            ),
            None,
        )
    } else {
        check(
            Level::Warn,
            format!(
                "{renewals} certificate(s) renew over port 80, and the firewall drops {} of {} known Let's Encrypt validator address(es) there: {}",
                dropped.len(),
                LETS_ENCRYPT_VALIDATORS.len(),
                dropped.join(", ")
            ),
            Some(
                "renewals will fail and the certificates expire: lift the rules named (for a cloud-provider feed, `stop-bots set-cloud-port-80 --enabled true`), or renew with a DNS challenge (a certbot dns-* plugin)"
                    .to_string(),
            ),
        )
    })
}

/// How many served files a line names before it says how many more.
const EXPOSED_FILES_SHOWN: usize = 5;

/// Whether this host's sites hand out the files scanners ask for.
///
/// The probe-paths detector blocks whoever asks for `/.env`; this says
/// whether the answer they got was the file. Critical when a credential,
/// a repository or a dump is served, a warning for what only describes
/// the server. Absent on a host with no sites to ask.
fn exposed_files(probe: &Probe) -> Option<Check> {
    let survey = probe.exposed_files.as_ref()?;
    let check = |level, detail, fix| Check {
        id: "exposed-files",
        title: "No secrets served",
        level,
        detail,
        fix,
    };
    let paths = crate::exposure::PATHS.len();
    if !survey.leaks.is_empty() {
        let secret = survey
            .leaks
            .iter()
            .any(|leak| crate::exposure::is_secret(&leak.path));
        let named: Vec<&str> = survey
            .leaks
            .iter()
            .take(EXPOSED_FILES_SHOWN)
            .map(|leak| leak.url.as_str())
            .collect();
        let more = survey.leaks.len().saturating_sub(EXPOSED_FILES_SHOWN);
        let more = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        let fix = match (secret, probe.web_server) {
            (true, webserver::WebServer::Nginx) => {
                "deny dotfiles in each `server` block, `location ~ /\\.(?!well-known) { deny all; }`, move dumps and backups out of the web root, and change every secret that was served"
            }
            (true, webserver::WebServer::Apache) => {
                "deny dotfiles, `<LocationMatch \"/\\.(?!well-known)\"> Require all denied </LocationMatch>`, move dumps and backups out of the document root, and change every secret that was served"
            }
            // Traefik serves no files, and NPMplus hands nearly every
            // request on: what answered is the application behind it.
            (true, webserver::WebServer::Traefik | webserver::WebServer::Npmplus) => {
                "the application behind the site served them: deny dotfiles there, move dumps and backups out of its web root, and change every secret that was served"
            }
            (false, _) => "delete them from the web root: they describe the server to whoever asks",
        };
        return Some(check(
            if secret { Level::Critical } else { Level::Warn },
            format!(
                "{} file(s) served that should not be: {}{more}",
                survey.leaks.len(),
                named.join(", ")
            ),
            Some(fix.to_string()),
        ));
    }
    let unanswered = if survey.unanswered.is_empty() {
        String::new()
    } else {
        format!(
            "; not checked: {}",
            survey
                .unanswered
                .iter()
                .take(EXPOSED_FILES_SHOWN)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Some(if survey.answered == 0 {
        check(
            Level::Unknown,
            format!(
                "none of {} site address(es) could be asked over loopback{unanswered}",
                survey.addresses
            ),
            None,
        )
    } else {
        check(
            Level::Ok,
            format!(
                "{} site address(es) asked over loopback for {paths} sensitive paths, and none served one{unanswered}",
                survey.answered
            ),
            None,
        )
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
fn trusted_by_hand(db: &Db, server: webserver::WebServer) -> Result<Option<Check>> {
    let server = server.label();
    let addresses = db.list_trusted_addresses()?;
    let user_agents = db.list_trusted_user_agents()?;
    if addresses.is_empty() && user_agents.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    if !addresses.is_empty() {
        parts.push(format!(
            "{} address(es), past the firewall and {server}: {}",
            addresses.len(),
            addresses.join(", ")
        ));
    }
    if !user_agents.is_empty() {
        parts.push(format!(
            "{} user agent(s), past {server} only: {}",
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

/// The hosting providers selected for blocking whose ranges were never
/// downloaded, and so block nothing yet. A warning: the operator chose to
/// block them and believes they are blocked. Absent when there is none.
fn hosting_asns_not_fetched(db: &Db) -> Result<Option<Check>> {
    let waiting: Vec<String> = db
        .list_hosting_asns()?
        .into_iter()
        .filter(|asn| asn.last_fetched_at.is_none())
        .map(|asn| {
            format!(
                "AS{} ({})",
                asn.asn,
                crate::ipranges::hosting::display_name(asn.asn, asn.description.as_deref())
            )
        })
        .collect();
    if waiting.is_empty() {
        return Ok(None);
    }
    Ok(Some(Check {
        id: "hosting-asns",
        title: "Hosting providers",
        level: Level::Warn,
        detail: format!(
            "{} selected but not fetched, so not blocked yet: {}",
            waiting.len(),
            waiting.join(", ")
        ),
        fix: Some(
            "`stop-bots update-hosting-asns`, or u on the Dashboard, downloads their ranges"
                .to_string(),
        ),
    }))
}

/// Stored blocks, exemptions and trusted agents that the web server's
/// config leaves out, because they would not mean what they say there (see
/// `nginx::skipped_entries`, whose checks Apache's render shares).
///
/// A warning, not critical: what is written is correct, and leaving an
/// entry out is the safe failure. But each one is something the operator
/// believes is in force, and the render drops it without a word anywhere
/// else. The rows that end up here were stored by a release that did not
/// check them, and upgrading is exactly when nobody is looking.
///
/// Absent when there is nothing, like its neighbours.
fn skipped_entries(db: &Db, server: webserver::WebServer) -> Result<Option<Check>> {
    let mut skipped = crate::nginx::skipped_entries(db)?;
    if server == webserver::WebServer::Traefik {
        skipped.extend(crate::traefik::skipped_entries(db)?);
    }
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
        title: match server {
            webserver::WebServer::Nginx => "Entries left out of the NGINX config",
            webserver::WebServer::Apache => "Entries left out of the Apache config",
            webserver::WebServer::Traefik => "Entries left out of the Traefik routers",
            webserver::WebServer::Npmplus => "Entries left out of the NPMplus config",
        },
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
/// Two things have to line up for a containerised NGINX, and they fail
/// with very different loudness — so the levels differ:
///
/// - **The reload command.** `systemctl reload nginx` reloads nothing when
///   NGINX is in a container. Silent, and total: every block this project
///   writes is staged and never served. Critical.
/// - **The managed directory.** The generated config names it absolutely;
///   NGINX resolves it against its own filesystem. Caught at apply time by
///   `write_validated` running `nginx -t` inside the container, so Warn.
///   Only while `robots.txt` is served: that `alias` is the one thing the
///   generated config reads from it.
fn nginx_deployment(db: &Db, probe: &Probe) -> Result<Option<Check>> {
    let commands = probe
        .nginx_commands
        .clone()
        .unwrap_or_else(|| webserver::WebServer::Nginx.default_commands());
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
                    fix: Some("stop-bots set-web-server nginx --reset".to_string()),
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

    // The reload command first: it is the only one of the two that is
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
                "stop-bots set-web-server nginx --test \"docker exec {name} nginx -t\" --reload \"docker exec {name} nginx -s reload\""
            )),
        }));
    }

    let mut problems: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();

    if probe.managed_dir_in_container == Some(false) && db.get_serve_robots_txt()? {
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

fn log_sources(probe: &Probe) -> Check {
    let missing: Vec<&str> = [
        (probe.ssh_log_readable, "the SSH log"),
        (
            probe.access_log_readable,
            match probe.web_server {
                webserver::WebServer::Nginx => "the NGINX access log",
                webserver::WebServer::Apache => "the Apache access log",
                webserver::WebServer::Traefik => "the Traefik access log",
                webserver::WebServer::Npmplus => "the NPMplus access log",
            },
        ),
    ]
    .into_iter()
    .filter_map(|(readable, name)| (readable == Some(false)).then_some(name))
    .collect();

    // The config's own logs, after the stored or default one: only those
    // that are there, so one that cannot be opened is a real problem
    // rather than a site that is not enabled.
    let config_logs = probe.access_logs.get(1..).unwrap_or_default();
    let unopened: Vec<&str> = config_logs
        .iter()
        .filter(|log| !log.readable)
        .map(|log| log.path.as_str())
        .collect();
    let unknown = probe.ssh_log_readable.is_none() || probe.access_log_readable.is_none();
    let (level, detail, fix) = if unknown {
        (
            Level::Unknown,
            "could not check the log sources".to_string(),
            None,
        )
    } else if missing.is_empty() && unopened.is_empty() {
        let also = match config_logs {
            [] => String::new(),
            logs => format!(
                ", and the {} other access log(s) the config names: {}",
                logs.len(),
                logs.iter()
                    .map(|log| log.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        (Level::Ok, format!("both readable{also}"), None)
    } else if missing.is_empty() {
        (
            Level::Warn,
            format!(
                "the access log(s) {} that the config names could not be opened — \
                 the detectors do not see those sites' requests",
                unopened.join(", ")
            ),
            Some("run stop-bots as root, or check what is at that path".to_string()),
        )
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
            // `tick` and the TUI's schedule: they take no arguments, so
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

/// What the port-scan detector needs and may not have, when it is on: a
/// kernel log it can read, and `ss` to see what listens. Absent when the
/// detector is off, or the probe is older than these questions.
///
/// Each failure is silent where it happens: an unreadable kernel log
/// leaves the trap dropping and logging with nothing reading the log, and
/// no `ss` leaves no trap at all. Both look like "no scanners found".
fn port_scan_sources(db: &Db, probe: &Probe) -> Result<Option<Check>> {
    if !crate::protection::Detector::PortScanners.is_enabled(db)? {
        return Ok(None);
    }
    if probe.kernel_log_readable.is_none() && probe.listening_known.is_none() {
        return Ok(None);
    }
    let mut problems = Vec::new();
    let mut fixes = Vec::new();
    if probe.kernel_log_readable == Some(false) {
        let tried = probe
            .kernel_log_path
            .as_deref()
            .map(|path| format!(" (tried {path})"))
            .unwrap_or_default();
        problems.push(format!(
            "the kernel log is unreadable{tried}, so trap hits are dropped and never read"
        ));
        fixes.push(
            "stop-bots set-log-paths --kernel-log <path> (/var/log/kern.log under rsyslog), \
             or run as root so the journal's kernel messages can be read"
                .to_string(),
        );
    }
    if probe.listening_known == Some(false) {
        problems.push(
            "`ss` could not be run, so the firewall traps no port: what listens is unknown"
                .to_string(),
        );
        fixes.push("install iproute2, which provides `ss`".to_string());
    }
    let (level, detail, fix) = if problems.is_empty() {
        (
            Level::Ok,
            "the kernel log is readable and what listens is known".to_string(),
            None,
        )
    } else {
        (Level::Warn, problems.join("; "), Some(fixes.join("; ")))
    };
    Ok(Some(Check {
        id: "port-scan-sources",
        title: "Port-scan detector",
        level,
        detail,
        fix,
    }))
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
            cron_installed: Some(true),
            turned_away: Vec::new(),
            conf_d_path: Some(crate::nginx::CONF_D_DIR.to_string()),
            conf_d_exists: Some(true),
            stray_generated_files: Vec::new(),
            db_free_bytes: Some(8 * 1024 * 1024 * 1024),
            ssh_log_readable: Some(true),
            access_log_readable: Some(true),
            access_log_path: None,
            access_logs: Vec::new(),
            kernel_log_readable: Some(true),
            kernel_log_path: None,
            listening_known: Some(true),
            access_log_clients: Some((40, 41)),
            access_log_lines: Some((41, 41)),
            access_log_unparsed_sample: None,
            access_log_cdn: Some(0),
            access_log_user_agents: Some(41),
            // The ordinary host: NGINX is a unit here, and the two
            // container fields have nothing to answer. Every
            // container-arrangement test below states its own.
            nginx_home: NginxHome::Host,
            managed_dir_in_container: None,
            container_shares_host_network: None,
            firewall_covers_forward: Some(true),
            nginx_commands: None,
            web_server: crate::webserver::WebServer::Nginx,
            config_root: None,
            apache_rewrite_enabled: None,
            http_renewals: Some(0),
            exposed_files: None,
        }
    }

    /// A host with an AWS feed switched on, holding the range one of Let's
    /// Encrypt's validators was caught in.
    fn with_aws_feed() -> Db {
        let db = db();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        db.replace_reputation_ranges("aws", &["18.216.0.0/15".to_string()])
            .unwrap();
        db.set_reputation_source_enabled("aws", true).unwrap();
        db
    }

    /// The port-scan detector's needs, said only when it is on: an
    /// unreadable kernel log and a missing `ss` each make it find nothing
    /// without failing anywhere.
    #[test]
    fn the_port_scan_detector_warns_when_it_cannot_read_or_cannot_see() {
        let db = db();
        let unreadable = Probe {
            kernel_log_readable: Some(false),
            kernel_log_path: Some("/var/log/kern.log".to_string()),
            ..healthy()
        };
        let no_ss = Probe {
            listening_known: Some(false),
            ..healthy()
        };
        assert!(
            port_scan_sources(&db, &unreadable).unwrap().is_none(),
            "said while the detector is off"
        );

        crate::protection::Detector::PortScanners
            .set_enabled(&db, true)
            .unwrap();
        let cases = [
            ("healthy", healthy(), Level::Ok, "readable"),
            ("unreadable", unreadable, Level::Warn, "/var/log/kern.log"),
            ("no ss", no_ss, Level::Warn, "`ss`"),
        ];
        for (what, probe, level, says) in cases {
            let check = port_scan_sources(&db, &probe).unwrap().unwrap();
            assert_eq!(check.level, level, "{what}: {check:?}");
            assert!(check.detail.contains(says), "{what}: {check:?}");
            assert_eq!(
                check.fix.is_some(),
                level == Level::Warn,
                "{what}: {check:?}"
            );
        }
    }

    fn renewing_over_http() -> Probe {
        Probe {
            http_renewals: Some(2),
            ..healthy()
        }
    }

    #[test]
    fn a_hosting_asn_that_was_never_fetched_is_named_until_it_is() {
        let db = db();
        db.add_hosting_asn(24940).unwrap();

        let report = assess(&db, &healthy()).unwrap();
        let line = check(&report, "hosting-asns");
        assert_eq!(line.level, Level::Warn, "{line:?}");
        assert!(line.detail.contains("AS24940 (Hetzner)"), "{line:?}");

        db.replace_hosting_asn_ranges(24940, "HETZNER-AS", &["5.9.0.0/16".to_string()])
            .unwrap();
        let report = assess(&db, &healthy()).unwrap();
        assert!(
            report.checks.iter().all(|c| c.id != "hosting-asns"),
            "still reported once fetched: {:?}",
            report.checks
        );
    }

    #[test]
    fn a_host_without_http_renewals_gets_no_lets_encrypt_line() {
        let report = assess(&with_aws_feed(), &healthy()).unwrap();
        assert!(
            report
                .checks
                .iter()
                .all(|c| c.id != "lets-encrypt-reachable"),
            "{:?}",
            report.checks
        );
    }

    /// The case that was found: the AWS feed no longer costs a host its
    /// certificates.
    #[test]
    fn a_cloud_feed_leaves_lets_encrypt_reaching_port_80() {
        let report = assess(&with_aws_feed(), &renewing_over_http()).unwrap();
        let check = check(&report, "lets-encrypt-reachable");
        assert_eq!(check.level, Level::Ok, "{check:?}");
    }

    /// Allowlist mode still closes port 80 to the validators, and the line
    /// names the rule that does it.
    #[test]
    fn an_allowlist_that_drops_the_validators_is_a_warning() {
        let db = db();
        db.set_geo_mode(crate::db::GeoMode::Allowlist).unwrap();
        let report = assess(&db, &renewing_over_http()).unwrap();
        let check = check(&report, "lets-encrypt-reachable");
        assert_eq!(check.level, Level::Warn, "{check:?}");
        assert!(
            check.detail.contains("18.216.118.75 (by 0.0.0.0/0)"),
            "{}",
            check.detail
        );
    }

    /// A probe whose survey of the sites found `leaks` (paths on
    /// `a.example`), with one site address answering.
    fn serving(leaks: &[&str]) -> Probe {
        Probe {
            exposed_files: Some(crate::exposure::Survey {
                addresses: 1,
                answered: 1,
                leaks: leaks
                    .iter()
                    .map(|path| crate::exposure::Leak {
                        site: "a.example".to_string(),
                        path: path.to_string(),
                        url: format!("https://a.example{path}"),
                    })
                    .collect(),
                unanswered: Vec::new(),
            }),
            ..healthy()
        }
    }

    #[test]
    fn a_served_env_file_is_critical_and_named() {
        let report = assess(&db(), &serving(&["/.env"])).unwrap();
        let check = check(&report, "exposed-files");
        assert_eq!(check.level, Level::Critical, "{check:?}");
        assert!(
            check.detail.contains("https://a.example/.env"),
            "{}",
            check.detail
        );
        let fix = check.fix.as_deref().unwrap_or_default();
        assert!(fix.contains("location ~ /\\.(?!well-known)"), "{fix}");
    }

    #[test]
    fn a_served_phpinfo_page_alone_is_a_warning() {
        let report = assess(&db(), &serving(&["/phpinfo.php"])).unwrap();
        assert_eq!(check(&report, "exposed-files").level, Level::Warn);
    }

    #[test]
    fn sites_that_serve_none_of_the_files_pass() {
        let report = assess(&db(), &serving(&[])).unwrap();
        assert_eq!(check(&report, "exposed-files").level, Level::Ok);
    }

    /// Not looking is not the same as fine.
    #[test]
    fn sites_that_could_not_be_asked_are_unknown_not_clean() {
        let probe = Probe {
            exposed_files: Some(crate::exposure::Survey {
                addresses: 1,
                unanswered: vec!["https://a.example (could not connect)".to_string()],
                ..Default::default()
            }),
            ..healthy()
        };
        let report = assess(&db(), &probe).unwrap();
        let check = check(&report, "exposed-files");
        assert_eq!(check.level, Level::Unknown, "{check:?}");
        assert!(
            check.detail.contains("could not connect"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn a_host_with_no_sites_gets_no_exposed_files_line() {
        let report = assess(&db(), &healthy()).unwrap();
        assert!(
            report.checks.iter().all(|c| c.id != "exposed-files"),
            "{:?}",
            report.checks
        );
    }

    #[test]
    fn only_http_challenges_count_as_renewing_over_port_80() {
        let dir = tempfile::tempdir().unwrap();
        for (name, authenticator) in [
            ("a.conf", "nginx"),
            ("b.conf", "webroot"),
            ("c.conf", "dns-cloudflare"),
            ("d.conf.bak", "nginx"),
        ] {
            let text =
                format!("version = 2.11.0\n\n[renewalparams]\nauthenticator = {authenticator}\n");
            std::fs::write(dir.path().join(name), text).unwrap();
        }
        assert_eq!(http_renewals(dir.path()), Some(2));
        assert_eq!(http_renewals(&dir.path().join("missing")), Some(0));
    }

    /// A probe a release with the web console stored still parses: its
    /// console fields are dropped, and nothing is known about the cron.
    #[test]
    fn a_probe_from_a_release_with_the_console_still_parses() {
        let probe: Probe = serde_json::from_str(
            r#"{"unit_active":true,"console_identity":{"uid":998,"gids":[998]},"live_rules":3}"#,
        )
        .unwrap();
        assert_eq!(probe.live_rules, Some(3));
        assert_eq!(probe.cron_installed, None);
    }

    /// The schedule reads as running from what ran, not from whether the
    /// cron file is there: a table of the four answers.
    #[test]
    fn the_schedule_check_reads_what_ran_against_what_is_installed() {
        let now = now_secs();
        for (installed, last_run, expected, says) in [
            (
                Some(true),
                Some(now - 60),
                Level::Ok,
                "runs it every minute",
            ),
            (Some(true), Some(now - 3600), Level::Warn, "is cron running"),
            (
                Some(false),
                Some(now - 60),
                Level::Ok,
                "while the TUI is open",
            ),
            (Some(false), None, Level::Warn, "has never run"),
        ] {
            let db = db();
            if let Some(at) = last_run {
                db.set_cron_last_run(
                    crate::cron::CronJob::Detect(crate::protection::Detector::WebScanners).id(),
                    at,
                    "ok",
                )
                .unwrap();
            }
            let probe = Probe {
                cron_installed: installed,
                ..healthy()
            };
            let check = schedule(&db, &probe).unwrap();
            assert_eq!(
                check.level, expected,
                "{installed:?}, {last_run:?}: {}",
                check.detail
            );
            assert!(
                check.detail.contains(says),
                "{installed:?}, {last_run:?}: {}",
                check.detail
            );
        }
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

    /// `probe`, taken on a host whose settings point the NGINX commands at
    /// the container `web`.
    fn configured_for_docker(probe: Probe) -> Probe {
        Probe {
            nginx_commands: Some(crate::webserver::ServerCommands {
                test: crate::webserver::split_command("docker exec web nginx -t").unwrap(),
                reload: crate::webserver::split_command("docker exec web nginx -s reload").unwrap(),
            }),
            ..probe
        }
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

    /// A scanner the lists name, or an agent blocked by hand, is refused on
    /// purpose, even one this host served before the list caught up with
    /// it. A client caught by an uncategorised pattern still is reported.
    #[test]
    fn an_agent_refused_on_purpose_is_not_reported() {
        let db = db();
        crate::botlist::register_all_sources(&db).unwrap();
        let source = db.list_sources().unwrap()[0].id.clone();
        for (slug, pattern, scanner) in [
            ("cyberconvoyscout", "CyberConvoyScout", true),
            ("okhttp", "okhttp", false),
        ] {
            db.upsert_bot(&crate::db::NewBot {
                slug: slug.into(),
                name: slug.into(),
                is_ai: false,
                is_search_engine: false,
                is_scanner: scanner,
                user_agent_pattern: pattern.into(),
                source_id: source.clone(),
            })
            .unwrap();
        }
        db.block_user_agent("curl/8.7.1").unwrap();
        let scanner = "Mozilla/5.0 (compatible; CyberConvoyScout/1.0)";
        let app = "Jellyfin Android TV/0.19.10 (OkHttp/4.12.0)";
        for agent in [scanner, "curl/8.7.1", app] {
            seen_working(&db, agent);
        }
        let probe = Probe {
            turned_away: vec![
                refused(scanner, 2_127, 0),
                refused("curl/8.7.1", 1_479, 0),
                refused(app, 262, 0),
            ],
            ..healthy()
        };

        let report = assess(&db, &probe).unwrap();
        let check = check2(&report, "turned-away-clients");

        assert!(
            check.detail.starts_with("1 user agent(s)") && check.detail.contains("Jellyfin"),
            "only the app caught by an uncategorised pattern belongs here: {}",
            check.detail
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

        let check = assess(&db, &configured_for_docker(healthy())).unwrap();
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

    /// The generated config names the managed directory absolutely, and
    /// NGINX resolves it inside the container.
    #[test]
    fn a_managed_directory_missing_from_the_container_is_flagged() {
        let db = db();
        db.set_serve_robots_txt(true).unwrap();

        let report = assess(
            &db,
            &configured_for_docker(Probe {
                managed_dir_in_container: Some(false),
                container_shares_host_network: Some(true),
                ..in_container()
            }),
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

    /// A console nobody proxies to — reached over an SSH tunnel — has no
    /// `proxy_pass` for a loopback bind to break, and a host that serves no
    /// generated `robots.txt` reads nothing from the managed directory. Both
    /// were reported anyway, on a real host using neither.
    #[test]
    fn a_container_host_using_neither_feature_is_not_warned_about_them() {
        let report = assess(
            &db(),
            &configured_for_docker(Probe {
                managed_dir_in_container: Some(false),
                ..in_container()
            }),
        )
        .unwrap();

        let check = check2(&report, "nginx-deployment");
        assert_eq!(check.level, Level::Ok, "was: {}", check.detail);
    }

    /// Serving `robots.txt` brings back the managed directory's warning,
    /// and nothing about a `proxy_pass`, which the web console's Web Access
    /// used to write.
    #[test]
    fn serving_robots_txt_brings_back_only_the_managed_directory_warning() {
        let db = db();
        db.set_serve_robots_txt(true).unwrap();

        let report = assess(
            &db,
            &configured_for_docker(Probe {
                managed_dir_in_container: Some(false),
                ..in_container()
            }),
        )
        .unwrap();

        let check = check2(&report, "nginx-deployment");
        assert_eq!(check.level, Level::Warn);
        assert!(
            check.detail.contains("does not exist inside the container")
                && !check.detail.contains("proxy_pass"),
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
    fn the_lockout_check_is_only_reported_when_it_is_off() {
        let db = db();
        let report = assess(&db, &healthy()).unwrap();
        assert!(
            !report.checks.iter().any(|c| c.id == "ssh-lockout-check"),
            "on is the default and needs no line"
        );

        db.set_ssh_lockout_check(false).unwrap();
        let report = assess(&db, &healthy()).unwrap();
        assert_eq!(check2(&report, "ssh-lockout-check").level, Level::Ok);
    }

    /// Off was the answer to "I never log in over SSH"; a login since says
    /// that answer no longer holds.
    #[test]
    fn a_login_while_the_lockout_check_is_off_is_a_warning() {
        let db = db();
        db.set_ssh_lockout_check(false).unwrap();
        db.record_ssh_login_ips(&["203.0.113.5".to_string()])
            .unwrap();

        let report = assess(&db, &healthy()).unwrap();

        let check = check2(&report, "ssh-lockout-check");
        assert_eq!(check.level, Level::Warn, "{}", check.detail);
        assert!(
            check.detail.contains("203.0.113.5"),
            "was: {}",
            check.detail
        );
        assert!(
            check
                .fix
                .as_deref()
                .is_some_and(|fix| fix.contains("--enabled true")),
            "{:?}",
            check.fix
        );
    }

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

    /// The access logs the config names are listed with the main one, and
    /// one of them that cannot be opened is a warning that names it.
    #[test]
    fn the_config_s_access_logs_are_listed_and_an_unopened_one_named() {
        let log = |path: &str, origin: &str, readable| AccessLogState {
            path: path.to_string(),
            origin: origin.to_string(),
            readable,
        };
        let cases = [
            (
                "all open",
                vec![
                    log("/var/log/nginx/access.log", "default", true),
                    log("/var/log/nginx/shop.log", "config", true),
                ],
                Level::Ok,
                "both readable, and the 1 other access log(s) the config names: \
                 /var/log/nginx/shop.log",
            ),
            (
                "one that cannot be opened",
                vec![
                    log("/var/log/nginx/access.log", "default", true),
                    log("/var/log/nginx/shop.log", "config", false),
                ],
                Level::Warn,
                "the access log(s) /var/log/nginx/shop.log that the config names could not \
                 be opened — the detectors do not see those sites' requests",
            ),
        ];
        for (case, access_logs, level, detail) in cases {
            let probe = Probe {
                access_logs,
                ..healthy()
            };

            let report = assess(&db(), &probe).unwrap();

            let check = check(&report, "log-sources");
            assert_eq!(
                (check.level, check.detail.as_str()),
                (level, detail),
                "{case}"
            );
        }
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
        let db = db();
        // The schedule ran a minute ago, as `install cron` keeps it.
        db.set_cron_last_run(
            crate::cron::CronJob::Detect(crate::protection::Detector::WebScanners).id(),
            now_secs() - 60,
            "ok",
        )
        .unwrap();
        let report = assess(&db, &healthy()).unwrap();

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
        let survey = access_log_sample(&log, 403, Vec::new()).expect("readable");
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

    /// Traefik's log, as it is until told to keep the header: every line
    /// parses, and not one names a user agent.
    #[test]
    fn a_log_that_names_no_user_agent_says_how_traefik_keeps_it() {
        let probe = |named: usize, parsed: usize| Probe {
            web_server: webserver::WebServer::Traefik,
            access_log_lines: Some((parsed, parsed)),
            access_log_user_agents: Some(named),
            ..Probe::default()
        };

        let check = access_log_user_agents(&probe(0, 100)).expect("a warning");

        assert_eq!(check.level, Level::Warn);
        let fix = check.fix.clone().unwrap_or_default();
        assert!(
            fix.contains("accessLog.fields.headers.names.User-Agent: keep"),
            "{fix}"
        );
        assert_eq!(crate::present::check_label(&check), "user agents");
        for (named, parsed, why) in [(1, 100, "one names one"), (0, 5, "too few lines")] {
            assert!(
                access_log_user_agents(&probe(named, parsed)).is_none(),
                "{why}"
            );
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

        let survey = access_log_sample(&log, 403, Vec::new()).expect("readable");

        assert_eq!(
            (survey.counts.lines, survey.counts.parsed, survey.public),
            (2, 1, 1)
        );
        assert_eq!(
            survey.unparsed_sample.as_deref(),
            Some("custom \u{fffd}[2J format")
        );
        assert!(access_log_sample(&dir.path().join("none.log"), 403, Vec::new()).is_none());
    }
}
