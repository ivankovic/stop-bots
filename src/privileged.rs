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

//! Everything the web console does that needs root, as a closed set of
//! operations.
//!
//! The console runs as its own unprivileged user. What it cannot do itself
//! — write the NGINX config and reload NGINX, write and load the firewall
//! script, read the logs root keeps to itself, probe the firewall — it asks
//! for as one [`Op`]: a name and a few typed, validated parameters. Never
//! config text, never a path, never a command. The root side derives
//! everything else itself, from the host settings ([`crate::hostconf`]),
//! from what it finds on disk, and from fixed code.
//!
//! [`execute`] is the one implementation of every operation. It runs in two
//! places:
//!
//! - in the console's own process ([`Privileged::Local`]), for a console
//!   running as root without a helper — `stop-bots web` started by hand,
//!   and the tests;
//! - in the root helper ([`crate::helper`]), which the console reaches over
//!   a Unix socket ([`Privileged::Helper`]).
//!
//! A console that is neither root nor given a helper is read-only
//! ([`Privileged::ReadOnly`]): its views work, and every action says what
//! it needs. The TUI and the CLI do not come through here; they run as
//! root and call the modules directly.
//!
//! ## The database is hostile
//!
//! After a compromise of the console, every row of its database may have
//! been written by an attacker. [`execute`] may only do what a logged-in
//! operator can already do — change policy, block and unblock, apply — and
//! no row decides what root executes, which path root writes or deletes,
//! or which file's contents come back:
//!
//! - the NGINX commands, the NGINX root and the log paths come from the
//!   host settings file, which only root can write;
//! - sites are rediscovered on disk under that root, and a row's id only
//!   picks one of them ([`crate::nginx::locate_site`]);
//! - a `managed_files` row is acted on only inside the managed directories
//!   ([`crate::nginx::unused_managed_files`]);
//! - the firewall script goes to the fixed path for its backend;
//! - every value rendered from a row is validated where it is rendered.
//!
//! The rows [`execute`] reads are named in each operation's comment.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::firewall::{self, FirewallRun, SshLog, WriteStep};
use crate::hostconf::HostConf;
use crate::nginx::{self, ApplyAllOutcome, SiteApplyStatus};

/// One privileged operation, as the console asks for it. The exact set the
/// console needs, and nothing more.
///
/// Serialised as JSON for the helper's socket. Unknown variants and unknown
/// fields are refused, so a request that does not say exactly one of these
/// does nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Op {
    /// Takes a health probe: the firewall's live state, the units, the logs.
    Probe,
    /// Finds the sites under the NGINX root and records them.
    ScanSites,
    /// Whether each scanned site's config carries the current policy.
    SiteStatuses,
    /// Applies the policy to one scanned site, by its id, or to all of
    /// them; tests and reloads NGINX when `reload`.
    ApplyNginx { site: Option<i64>, reload: bool },
    /// What "Apply everything" would change, with the diff when `diff`.
    Preview { diff: bool },
    /// Renders and writes the firewall script, and runs it when `apply`.
    /// `protect` is addresses the lockout guard must not block either: the
    /// browser driving the console, and the clients a log pass saw log in.
    /// It can only make the guard stricter.
    Firewall { apply: bool, protect: Vec<IpAddr> },
    /// Sets NGINX up to serve the console, and records the address it now
    /// answers to; reloads NGINX when `reload`.
    WebAccess {
        mode: WebAccessMode,
        /// The site to mount it on, in path mode.
        site_id: Option<i64>,
        /// The path prefix, in path mode.
        prefix: String,
        /// The host name, in subdomain mode.
        host: String,
        reload: bool,
    },
    /// Reads a piece of the access log or of sshd's authentication lines,
    /// from where an earlier read stopped: see [`crate::hostlog`]. Which
    /// file, or the journal, is the host settings' to say; the request
    /// names only the log.
    ReadLog(crate::hostlog::Request),
}

/// The two ways Web Access can serve the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebAccessMode {
    Path,
    Subdomain,
}

impl Op {
    /// The operation's name, which is all of it the helper logs.
    pub fn name(&self) -> &'static str {
        match self {
            Op::Probe => "Probe",
            Op::ScanSites => "ScanSites",
            Op::SiteStatuses => "SiteStatuses",
            Op::ApplyNginx { .. } => "ApplyNginx",
            Op::Preview { .. } => "Preview",
            Op::Firewall { .. } => "Firewall",
            Op::WebAccess { .. } => "WebAccess",
            Op::ReadLog(_) => "ReadLog",
        }
    }

    /// Whether it needs the database. A log read does not, and the helper
    /// does not open it for one.
    pub fn uses_db(&self) -> bool {
        !matches!(self, Op::ReadLog(_))
    }

    /// The site it is about, if it names one: the one parameter the helper
    /// logs besides the name.
    pub fn site(&self) -> Option<i64> {
        match self {
            Op::ApplyNginx { site, .. } => *site,
            Op::WebAccess { site_id, .. } => *site_id,
            _ => None,
        }
    }

    /// Whether it only looks: what a read-only console still does itself,
    /// with its own user's access.
    pub fn only_reads(&self) -> bool {
        matches!(self, Op::Probe | Op::SiteStatuses | Op::ReadLog(_))
    }
}

/// What an operation came to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    Probe(Box<crate::health::Probe>),
    Scanned {
        found: usize,
    },
    SiteStatuses(Vec<(i64, SiteApplyStatus)>),
    AppliedAll(ApplyAllOutcome),
    AppliedSite {
        name: String,
        changed: bool,
        reloaded: bool,
    },
    Preview(crate::preview::Summary),
    Firewall(FirewallReport),
    WebAccess(WebAccessReport),
    Log(crate::hostlog::Reply),
}

/// What a firewall run came to, in the words a front-end shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallReport {
    /// [`firewall::FirewallOutcome::summary`].
    pub summary: String,
    pub write: WriteStep,
    /// [`firewall::FirewallOutcome::succeeded`].
    pub succeeded: bool,
}

impl FirewallReport {
    pub fn of(outcome: &firewall::FirewallOutcome) -> Self {
        FirewallReport {
            summary: outcome.summary(),
            write: outcome.write.clone(),
            succeeded: outcome.succeeded(),
        }
    }
}

/// What setting up Web Access came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAccessReport {
    /// The file written.
    pub path: PathBuf,
    /// [`crate::webaccess::Plan::recorded_note`].
    pub note: String,
    /// `Ok(true)` reloaded, `Ok(false)` not asked to, `Err` why it failed.
    pub reloaded: Result<bool, String>,
}

/// What an executor is configured with: never from a request, never from
/// a row.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The host settings file, read at every operation so a
    /// `set-nginx-commands` takes effect without a restart.
    pub host_conf: PathBuf,
    /// Overrides the host settings' NGINX root: the console's own
    /// `--root`, in process. Never set in the helper.
    pub root: Option<PathBuf>,
    /// Overrides the SSH log for the lockout guard and the probe: the
    /// console's own `--ssh-log`, in process. Never set in the helper.
    pub ssh_log: Option<PathBuf>,
    /// Overrides where the applied firewall script is: the console's
    /// `--firewall-out`, in process, and the tests. `None` is the fixed
    /// path for the backend ([`firewall::default_output_path`]).
    pub firewall_out: Option<PathBuf>,
    /// Whether NGINX may really be reloaded and the firewall really
    /// loaded: `false` under `--no-apply` and in tests.
    pub for_real: bool,
}

impl Settings {
    /// The helper's: the host settings at [`crate::hostconf::path`], and
    /// nothing overridden.
    pub fn helper() -> Self {
        Settings {
            host_conf: crate::hostconf::path(),
            root: None,
            ssh_log: None,
            firewall_out: None,
            for_real: true,
        }
    }
}

/// A way to reach the database for the length of one closure: the
/// console's shared, locked handle in process, the helper's own connection
/// in the helper.
pub trait DbAccess {
    fn with<T>(&self, f: impl FnOnce(&Db) -> Result<T>) -> Result<T>;
}

impl DbAccess for Db {
    fn with<T>(&self, f: impl FnOnce(&Db) -> Result<T>) -> Result<T> {
        f(self)
    }
}

/// No database, for an operation that needs none ([`Op::uses_db`]): the
/// helper does not open it to read a log.
pub struct NoDb;

impl DbAccess for NoDb {
    fn with<T>(&self, _: impl FnOnce(&Db) -> Result<T>) -> Result<T> {
        bail!("this operation is not given the database")
    }
}

impl DbAccess for Mutex<Db> {
    fn with<T>(&self, f: impl FnOnce(&Db) -> Result<T>) -> Result<T> {
        let db = self
            .lock()
            .map_err(|_| anyhow!("the database lock was poisoned by an earlier panic"))?;
        f(&db)
    }
}

/// Does `op`. The one implementation, whichever side runs it.
///
/// The database rows each operation reads are named in its arm. None of
/// them chooses a command, a path to write or delete, or a file to return.
pub fn execute(settings: &Settings, db: &impl DbAccess, op: Op) -> Result<Reply> {
    let host = HostConf::load_from(&settings.host_conf)?;
    let root = host.root(settings.root.as_deref());
    let ssh = host.log_paths().ssh(settings.ssh_log.as_deref());
    match op {
        // Rows: `firewall:backend` (an enum, anything unknown is nftables)
        // and `block_response` (an enum, read as its status code). The
        // logs, the `conf.d` and the commands are the host settings'.
        Op::Probe => {
            let (backend, db_path, block_status) = db.with(|db| {
                Ok((
                    firewall::stored_backend(db)?,
                    db.path()
                        .unwrap_or_else(|| PathBuf::from("./stop-bots.sqlite3")),
                    db.get_block_response()?.status_code(),
                ))
            })?;
            let probe = crate::health::probe(
                backend,
                &db_path,
                settings.ssh_log.as_deref(),
                &host,
                block_status,
            );
            Ok(Reply::Probe(Box::new(probe)))
        }
        // Rows: none read. Writes a row per site found on disk.
        Op::ScanSites => {
            let sites = nginx::discover_sites(&root)?;
            db.with(|db| {
                for site in &sites {
                    db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
                }
                Ok(())
            })?;
            Ok(Reply::Scanned { found: sites.len() })
        }
        // Rows: `sites` (a name and a path, matched against what is on
        // disk; the file judged is the one found there) and the policy
        // rows a site's block is rendered from.
        Op::SiteStatuses => Ok(Reply::SiteStatuses(
            db.with(|db| nginx::site_statuses(db, &root))?,
        )),
        // Rows: the site's (to pick the file found on disk), the policy
        // rows every block is rendered from — validated where rendered —
        // and `managed_files`, acted on only inside the managed
        // directories.
        Op::ApplyNginx { site, reload } => {
            let commands = (reload && settings.for_real)
                .then(|| host.commands())
                .transpose()?;
            match site {
                None => db
                    .with(|db| nginx::apply_all_sites_and_reload(db, &root, commands.as_ref()))
                    .map(Reply::AppliedAll),
                Some(id) => db.with(|db| {
                    let site = db
                        .list_sites()?
                        .into_iter()
                        .find(|s| s.id == id)
                        .ok_or_else(|| anyhow!("no site with id {id}"))?;
                    let (changed, reloaded) =
                        nginx::apply_site_and_reload(db, &root, &site, commands.as_ref())?;
                    Ok(Reply::AppliedSite {
                        name: site.server_name,
                        changed,
                        reloaded,
                    })
                }),
            }
        }
        // Rows: as `ApplyNginx` and `Firewall`, and writes nothing. The
        // diff shows a site file's current content, which anyone who can
        // read the NGINX config can read anyway.
        Op::Preview { diff } => {
            let (nginx, prepared) = db.with(|db| {
                let nginx = nginx::preview_all_sites(db, &root).map_err(|err| format!("{err:#}"));
                let run = firewall_run(settings, db, true, &[])?.dry_run(true);
                Ok((
                    nginx,
                    firewall::prepare(db, run).map_err(|err| format!("{err:#}")),
                ))
            })?;
            let firewall = prepared.map(|prepared| firewall::execute(prepared, SshLog::Read(&ssh)));
            let preview = crate::preview::ApplyPreview { nginx, firewall };
            Ok(Reply::Preview(preview.summary(diff)))
        }
        // Rows: `firewall:backend`, the rules, trusted addresses, feeds
        // and countries a script is rendered from (each address validated
        // where it is rendered), and the recent SSH and console logins,
        // which only add to what the guard protects. The path is fixed by
        // the backend; the SSH log is the host settings'.
        Op::Firewall { apply, protect } => {
            let protect: Vec<String> = protect.iter().map(IpAddr::to_string).collect();
            let prepared =
                db.with(|db| firewall::prepare(db, firewall_run(settings, db, apply, &protect)?))?;
            let outcome = firewall::execute(prepared, SshLog::Read(&ssh));
            db.with(|db| firewall::record(db, &outcome))?;
            Ok(Reply::Firewall(FirewallReport::of(&outcome)))
        }
        // Rows: the site's name (to find its file on disk) and `web:bind`
        // (parsed as an address and port). The prefix and host name are
        // validated here and again where they are rendered.
        Op::WebAccess {
            mode,
            site_id,
            prefix,
            host: host_name,
            reload,
        } => {
            let request = match mode {
                WebAccessMode::Subdomain => {
                    crate::webaccess::Request::Subdomain { host: host_name }
                }
                WebAccessMode::Path => {
                    let id = site_id.context("Pick a site to mount the console under.")?;
                    let site = db.with(|db| {
                        db.list_sites()?
                            .into_iter()
                            .find(|s| s.id == id)
                            .map(|s| s.server_name)
                            .with_context(|| format!("no site with id {id}"))
                    })?;
                    crate::webaccess::Request::Path { site, prefix }
                }
            };
            let plan = db.with(|db| crate::webaccess::plan(db, &host, &root, &request))?;
            let path = crate::webaccess::apply(&plan, &root)?;
            db.with(|db| crate::webaccess::record(db, &plan))?;
            let reloaded = if reload && settings.for_real {
                nginx::reload_with(&plan.commands)
                    .map(|()| true)
                    .map_err(|err| format!("{err:#}"))
            } else {
                Ok(false)
            };
            Ok(Reply::WebAccess(WebAccessReport {
                path,
                note: plan.recorded_note().to_string(),
                reloaded,
            }))
        }
        // Rows: none, and no database is opened for it. The log is the
        // host settings', or what autodetection finds, as for the root
        // CLI; the request chooses only where in it to start.
        Op::ReadLog(request) => {
            let sources =
                crate::hostlog::Sources::new(&host.log_paths(), None, settings.ssh_log.as_deref());
            Ok(Reply::Log(crate::hostlog::read(&sources, &request)))
        }
    }
}

/// The firewall run every console operation makes: the stored backend, its
/// fixed path (unless the executor's settings override it), and a guard
/// that also protects `protect` and whoever logged in recently, over SSH
/// or to the console.
fn firewall_run(
    settings: &Settings,
    db: &Db,
    apply: bool,
    protect: &[String],
) -> Result<FirewallRun> {
    let backend = firewall::stored_backend(db)?;
    let mut recent = db.recent_ssh_login_ips()?;
    recent.extend(db.recent_console_logins(now() - crate::db::CONSOLE_LOGIN_WINDOW_SECONDS)?);
    Ok(FirewallRun::new(
        backend,
        firewall::output_path(settings.firewall_out.as_deref(), backend),
    )
    .apply(apply)
    .for_real(settings.for_real)
    .protect(protect.iter().cloned())
    .protect(recent))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// What a console that has neither root nor a helper says on every page.
pub const READ_ONLY_NOTICE: &str =
    "Read-only: this console has neither root nor its helper, so every change to the host \
     needs the helper — run `sudo stop-bots install web`.";

/// What a console that has neither root nor a helper says to every action.
pub const NEEDS_HELPER: &str =
    "This console runs without root and without its helper, so it cannot change the host: \
     this needs the helper — run `sudo stop-bots install web`.";

/// How the console does what needs root.
#[derive(Clone)]
pub enum Privileged {
    /// In its own process: it is root.
    Local(Arc<Local>),
    /// Through the root helper listening on this socket.
    Helper(PathBuf),
    /// Neither: only [`Op::only_reads`] operations, in process, with
    /// whatever this user may read.
    ReadOnly(Arc<Local>),
}

/// The in-process executor: the console's database and its settings.
pub struct Local {
    pub db: Arc<Mutex<Db>>,
    pub settings: Settings,
}

impl Privileged {
    /// Runs `op`, off the async runtime.
    pub async fn run(&self, op: Op) -> Result<Reply> {
        match self {
            Privileged::Local(local) => run_local(local, op).await,
            Privileged::ReadOnly(local) if op.only_reads() => run_local(local, op).await,
            Privileged::ReadOnly(_) => bail!("{NEEDS_HELPER}"),
            Privileged::Helper(socket) => {
                let socket = socket.clone();
                tokio::task::spawn_blocking(move || crate::helper::call(&socket, &op))
                    .await
                    .map_err(|err| anyhow!("the helper call panicked: {err}"))?
            }
        }
    }

    /// Whether every action is refused.
    pub fn is_read_only(&self) -> bool {
        matches!(self, Privileged::ReadOnly(_))
    }

    /// One line for the Help page: how this console does what needs root.
    pub fn describe(&self) -> String {
        match self {
            Privileged::Local(_) => "in this process, which runs as root".to_string(),
            Privileged::Helper(socket) => {
                format!("through the root helper at {}", socket.display())
            }
            Privileged::ReadOnly(_) => {
                "nowhere: this console is read-only (no root, and no helper)".to_string()
            }
        }
    }

    pub async fn probe(&self) -> Result<crate::health::Probe> {
        match self.run(Op::Probe).await? {
            Reply::Probe(probe) => Ok(*probe),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn scan_sites(&self) -> Result<usize> {
        match self.run(Op::ScanSites).await? {
            Reply::Scanned { found } => Ok(found),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn site_statuses(&self) -> Result<Vec<(i64, SiteApplyStatus)>> {
        match self.run(Op::SiteStatuses).await? {
            Reply::SiteStatuses(statuses) => Ok(statuses),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn apply_all(&self, reload: bool) -> Result<ApplyAllOutcome> {
        match self.run(Op::ApplyNginx { site: None, reload }).await? {
            Reply::AppliedAll(outcome) => Ok(outcome),
            other => Err(unexpected(&other)),
        }
    }

    /// One site: its name, whether anything changed, whether NGINX was
    /// reloaded.
    pub async fn apply_site(&self, id: i64, reload: bool) -> Result<(String, bool, bool)> {
        match self
            .run(Op::ApplyNginx {
                site: Some(id),
                reload,
            })
            .await?
        {
            Reply::AppliedSite {
                name,
                changed,
                reloaded,
            } => Ok((name, changed, reloaded)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn preview(&self, diff: bool) -> Result<crate::preview::Summary> {
        match self.run(Op::Preview { diff }).await? {
            Reply::Preview(summary) => Ok(summary),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn firewall(&self, apply: bool, protect: Vec<IpAddr>) -> Result<FirewallReport> {
        match self.run(Op::Firewall { apply, protect }).await? {
            Reply::Firewall(report) => Ok(report),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn web_access(&self, op: Op) -> Result<WebAccessReport> {
        match self.run(op).await? {
            Reply::WebAccess(report) => Ok(report),
            other => Err(unexpected(&other)),
        }
    }
}

/// The console's way to its logs: in process when it is root, or with its
/// own access when it is read-only, and otherwise through the helper,
/// which is the only one of the three that can read them under the
/// console's unit. Blocking: call it from a blocking thread.
impl crate::hostlog::LogReader for Privileged {
    fn read_log(&self, request: &crate::hostlog::Request) -> Result<crate::hostlog::Reply> {
        let op = Op::ReadLog(request.clone());
        let reply = match self {
            Privileged::Local(local) | Privileged::ReadOnly(local) => {
                execute(&local.settings, &*local.db, op)?
            }
            Privileged::Helper(socket) => crate::helper::call(socket, &op)?,
        };
        match reply {
            Reply::Log(reply) => Ok(reply),
            other => Err(unexpected(&other)),
        }
    }
}

async fn run_local(local: &Arc<Local>, op: Op) -> Result<Reply> {
    let local = Arc::clone(local);
    tokio::task::spawn_blocking(move || execute(&local.settings, &*local.db, op))
        .await
        .map_err(|err| anyhow!("the privileged task panicked: {err}"))?
}

fn unexpected(reply: &Reply) -> anyhow::Error {
    let kind = match reply {
        Reply::Probe(_) => "Probe",
        Reply::Scanned { .. } => "Scanned",
        Reply::SiteStatuses(_) => "SiteStatuses",
        Reply::AppliedAll(_) => "AppliedAll",
        Reply::AppliedSite { .. } => "AppliedSite",
        Reply::Preview(_) => "Preview",
        Reply::Firewall(_) => "Firewall",
        Reply::WebAccess(_) => "WebAccess",
        Reply::Log(_) => "Log",
    };
    anyhow!("the helper answered with a {kind} reply, which is not what was asked for")
}
