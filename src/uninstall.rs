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

//! `stop-bots uninstall`: the host back as it was before stop-bots.
//!
//! Everything stop-bots puts on a host, and how each is taken back:
//!
//! - **The units**: the console's (`stop-bots-web.service`), its root
//!   helper's (`stop-bots-helper.socket` and `.service`) and the firewall's
//!   boot unit (`stop-bots-firewall.service`): stopped, disabled, deleted,
//!   then `systemctl daemon-reload`.
//! - **The live firewall rules**: the nft table `inet stop_bots`, and the
//!   iptables `STOP-BOTS` chain with every jump into it, for IPv4 and IPv6 —
//!   whichever exist, all of them if several do.
//! - **NGINX**: the injected blocks in every site file (both kinds of
//!   marker), the generated `conf.d` files, the console's own site file,
//!   and `/etc/stop-bots/nginx`. One change, tested and put back if NGINX
//!   refuses it, then reloaded — `nginx::remove_everything`.
//! - **The firewall scripts** in `/etc/stop-bots`, and the directory once
//!   it is empty.
//! - **The database** and its `.bak-v*` copies only with `--purge`, and
//!   with them the `stop-bots` user and group that own them.
//!
//! ## The order, and why
//!
//! **The units go first**, the console before its helper, because the
//! web console is the one thing that would put the rest back: its
//! internal cron re-applies the NGINX blocks
//! and re-renders the firewall script every few minutes, so anything
//! removed while it runs can be back before this command ends. And the
//! firewall unit reloads the rules at boot; disabled first, a reboot in
//! the middle of an uninstall cannot bring them back.
//!
//! **Then the live firewall rules, before NGINX.** Removing them can only
//! ever let traffic through, never stop it — every rule in that table or
//! chain is a drop or an accept of its own, and without them packets go
//! on to whatever the host's own firewall says — so there is no order in
//! which taking them out locks the operator out. What makes them urgent is
//! that a leftover is the one piece nobody could see: a forgotten site
//! block is text in a file an operator reads, a forgotten table silently
//! drops packets on a host with no stop-bots left to explain why. So they
//! go before the step most likely to fail or stall, NGINX's test and
//! reload, which may be a `docker exec` into a container.
//!
//! **Files last**, once nothing running refers to them.
//!
//! Every step is reported, a failed one does not stop the ones after it,
//! and any failure makes the command exit non-zero.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::install::{FIREWALL_UNIT, HELPER_SOCKET_UNIT, HELPER_UNIT, WEB_UNIT};
use crate::nginx::{self, NginxCommands};

/// What to remove. `All` is everything, and the only one that touches
/// the database or `/etc/stop-bots` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The site blocks, the generated `conf.d` files and the console's
    /// site file, and `/etc/stop-bots/nginx`.
    Nginx,
    /// The live rules, the boot unit and the scripts.
    Firewall,
    /// The web console's unit and its helper's.
    Web,
    All,
}

impl Target {
    fn nginx(self) -> bool {
        matches!(self, Target::Nginx | Target::All)
    }
    fn firewall(self) -> bool {
        matches!(self, Target::Firewall | Target::All)
    }
    fn web(self) -> bool {
        matches!(self, Target::Web | Target::All)
    }
}

/// How this run behaves.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Work out and report every step, and change nothing.
    pub dry_run: bool,
    /// Also delete the database and every copy an upgrade kept.
    pub purge: bool,
}

/// The nft table every script this project writes creates.
pub const NFT_TABLE: [&str; 2] = ["inet", "stop_bots"];

/// The iptables chain every script this project writes creates.
pub const IPTABLES_CHAIN: &str = "STOP-BOTS";

/// Everything an uninstall acts on, resolved before it starts.
///
/// Every path and program is a field, as in `install::Layout`, so a test
/// can point the whole thing at a temporary tree and fake programs.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Nothing outside this directory is touched, when set. `None` is the
    /// host itself.
    pub prefix: Option<PathBuf>,
    /// Whether to drive the host's own programs: `systemctl`, `nft`,
    /// `iptables`, and NGINX's test and reload. Off under `--prefix`,
    /// whose tree no running program reads.
    pub host: bool,
    /// `/etc/systemd/system`.
    pub unit_dir: PathBuf,
    /// `/etc/stop-bots`: the firewall scripts, and the directory below.
    pub output_dir: PathBuf,
    /// `/etc/stop-bots/nginx`: the generated `robots.txt`.
    pub managed_dir: PathBuf,
    /// The NGINX config root whose site files carry the blocks.
    pub nginx_root: PathBuf,
    /// Every `conf.d` a generated file may be in: this root's, and the
    /// stock one, which 0.0.8 and earlier always wrote to.
    pub conf_d_dirs: Vec<PathBuf>,
    /// Generated files the database's record says were written.
    pub recorded: Vec<PathBuf>,
    /// How to test and reload NGINX, as `set-nginx-commands` stored them.
    pub nginx: NginxCommands,
    /// The database, kept unless `--purge`.
    pub db_path: PathBuf,
    /// The host settings file (see [`crate::hostconf`]), kept unless
    /// `--purge`, like the database whose settings it took over.
    pub host_conf: PathBuf,
    pub systemctl: PathBuf,
    /// `userdel` and `groupdel`, for `--purge`.
    pub userdel: PathBuf,
    pub groupdel: PathBuf,
    /// The console's user and group, removed with `--purge`.
    pub user: String,
    pub nft: PathBuf,
    /// `iptables` and `ip6tables`.
    pub iptables: Vec<PathBuf>,
}

impl Plan {
    /// The plan for the host, or for the tree under `prefix`, reading what
    /// the database at `db_path` stored — without changing it.
    ///
    /// The database is read through a read-only connection rather than
    /// `Db::open`, which would upgrade an older one (and copy it first):
    /// `--dry-run` must change nothing, and an uninstall has no business
    /// migrating a database it is about to leave behind. A database newer
    /// than this binary, which `Db::open` refuses, is read the same way:
    /// the settings and the record it needs are there in every version.
    pub fn resolve(
        prefix: Option<&Path>,
        db_path: Option<PathBuf>,
        root_flag: Option<&Path>,
    ) -> Result<Plan> {
        let base = prefix.unwrap_or(Path::new("/"));
        let db_path = db_path.unwrap_or_else(|| base.join("var/lib/stop-bots/db.sqlite3"));
        let stored = Stored::read(&db_path)?;
        let host_conf = match prefix {
            Some(_) => base.join(crate::hostconf::DEFAULT_PATH.trim_start_matches('/')),
            None => crate::hostconf::path(),
        };
        let host = stored.host_settings(&host_conf, &db_path)?;

        let nginx_root = match (root_flag, &host.nginx_root) {
            (Some(flag), _) => flag.to_path_buf(),
            // A stored root names the host's own path; under a prefix it
            // is taken to mean the same path inside the tree.
            (None, Some(root)) => base.join(root.strip_prefix("/").unwrap_or(root)),
            (None, None) => base.join("etc/nginx"),
        };
        let output_dir = base.join("etc/stop-bots");
        let managed_dir = match std::env::var_os(nginx::MANAGED_DIR_ENV) {
            Some(dir) => PathBuf::from(dir),
            None => output_dir.join("nginx"),
        };
        let mut conf_d_dirs = vec![
            nginx::conf_d_dir(&nginx_root),
            nginx_root.join("conf.d"),
            base.join(nginx::CONF_D_DIR.trim_start_matches('/')),
        ];
        conf_d_dirs.dedup();

        Ok(Plan {
            prefix: prefix.map(Path::to_path_buf),
            host: prefix.is_none(),
            unit_dir: base.join("etc/systemd/system"),
            output_dir,
            managed_dir,
            nginx_root,
            conf_d_dirs,
            recorded: stored.recorded,
            nginx: host.commands()?,
            db_path,
            host_conf,
            systemctl: crate::host::program("systemctl"),
            userdel: crate::host::program("userdel"),
            groupdel: crate::host::program("groupdel"),
            user: crate::account::USER.to_string(),
            nft: crate::host::program("nft"),
            iptables: vec![
                crate::host::program("iptables"),
                crate::host::program("ip6tables"),
            ],
        })
    }

    /// Whether `path` may be touched: always on the host, and only inside
    /// the prefix otherwise.
    fn allows(&self, path: &Path) -> bool {
        self.prefix
            .as_ref()
            .is_none_or(|prefix| path.starts_with(prefix))
    }
}

/// What an uninstall needs from the database.
///
/// The NGINX root and commands are read only for a database that was
/// never migrated to the host settings file ([`crate::hostconf`]), and
/// only from one this user owns, in a directory this user owns: an
/// uninstall runs the commands as root, and the console's database may
/// hold rows written by whoever compromised it.
#[derive(Debug, Default)]
struct Stored {
    root: Option<String>,
    test: Option<String>,
    reload: Option<String>,
    recorded: Vec<PathBuf>,
}

impl Stored {
    /// The host settings: the file at `host_conf` if there is one, else
    /// this database's rows if it is to be trusted, else the defaults.
    fn host_settings(&self, host_conf: &Path, db_path: &Path) -> Result<crate::hostconf::HostConf> {
        if std::fs::symlink_metadata(host_conf).is_ok() {
            return crate::hostconf::HostConf::load_from(host_conf);
        }
        if !crate::hostconf::is_trusted_database(db_path) {
            return Ok(crate::hostconf::HostConf::default());
        }
        let legacy = crate::hostconf::HostConf {
            nginx_test_command: self.test.clone(),
            nginx_reload_command: self.reload.clone(),
            nginx_root: self.root.as_ref().map(PathBuf::from),
            ..Default::default()
        };
        legacy.validate()?;
        Ok(legacy)
    }

    fn read(db_path: &Path) -> Result<Stored> {
        use rusqlite::{OpenFlags, OptionalExtension};

        if !db_path.is_file() {
            return Ok(Stored::default());
        }
        // Read-write but never created, and only ever read. Not
        // READ_ONLY: a read-only connection to a WAL database has to
        // create the `-wal` and `-shm` files and then cannot delete them,
        // so a dry run would leave two new files beside the database.
        // Nor `Db::open`, which would upgrade the schema.
        //
        // Guarded, too: uninstall is root, and the directory is the
        // console's (see `db::guard`).
        let conn = crate::db::guard::open_connection(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("failed to read {}", db_path.display()))?;
        // The console may be mid-write when this runs: it is stopped only
        // later, by the plan this is building.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let setting = |key: &str| -> Result<Option<String>> {
            Ok(conn
                .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                    row.get::<_, String>(0)
                })
                .optional()?
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()))
        };
        let has_record: bool = conn.query_row(
            "SELECT count(*) > 0 FROM sqlite_master WHERE type = 'table' AND name = 'managed_files'",
            [],
            |row| row.get(0),
        )?;
        let recorded = if has_record {
            let mut stmt = conn.prepare("SELECT path FROM managed_files ORDER BY path")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.map(|row| row.map(PathBuf::from))
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        // The root and the two commands are read for `host_settings`, which
        // uses them only for a database never migrated and owned by this
        // user: rows the console can write must not choose what this root
        // process runs or which tree it rewrites.
        Ok(Stored {
            root: setting(NginxCommands::ROOT_KEY)?,
            test: setting(NginxCommands::TEST_KEY)?,
            reload: setting(NginxCommands::RELOAD_KEY)?,
            recorded,
        })
    }
}

/// How one step went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// `--dry-run`: this is what would happen.
    Planned,
    /// Nothing to do, and why.
    Skipped(String),
    Failed(String),
}

/// One thing uninstall did, or would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub what: String,
    pub outcome: Outcome,
}

/// Every step, in order. Returned rather than printed, so a test asserts
/// on what the operator reads.
#[derive(Debug, Default)]
pub struct Report {
    pub steps: Vec<Step>,
    /// What was left in place on purpose, and where — the database, above
    /// all, so an operator knows what `--purge` would have removed.
    pub kept: Vec<String>,
}

impl Report {
    pub fn failures(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| matches!(step.outcome, Outcome::Failed(_)))
            .count()
    }

    fn skip(&mut self, what: impl Into<String>, why: impl Into<String>) {
        self.steps.push(Step {
            what: what.into(),
            outcome: Outcome::Skipped(why.into()),
        });
    }

    /// Records `what`, running `act` unless this is a dry run.
    fn step(
        &mut self,
        options: &Options,
        what: impl Into<String>,
        act: impl FnOnce() -> Result<()>,
    ) {
        let outcome = if options.dry_run {
            Outcome::Planned
        } else {
            match act() {
                Ok(()) => Outcome::Done,
                Err(err) => Outcome::Failed(format!("{err:#}")),
            }
        };
        self.steps.push(Step {
            what: what.into(),
            outcome,
        });
    }
}

/// Removes `target` as `plan` describes. Never stops at a failed step;
/// see [`Report::failures`].
pub fn run(plan: &Plan, target: Target, options: &Options) -> Report {
    let mut report = Report::default();

    // 1. The units, so nothing puts back what the steps below remove.
    let mut removed_a_unit = false;
    if target.web() {
        // The console first, so nothing asks the helper for anything; then
        // the socket, so nothing starts the helper again; then the helper,
        // which has no `[Install]` of its own to disable.
        removed_a_unit |= remove_unit(plan, options, &mut report, WEB_UNIT);
        removed_a_unit |= remove_unit(plan, options, &mut report, HELPER_SOCKET_UNIT);
        removed_a_unit |= remove_unit(plan, options, &mut report, HELPER_UNIT);
    } else if plan.unit_dir.join(WEB_UNIT).exists() {
        report.kept.push(format!(
            "{WEB_UNIT} is still installed, and its internal cron re-applies the NGINX \
             blocks and re-renders the firewall script. `stop-bots uninstall web` removes it."
        ));
    }
    if target.firewall() {
        removed_a_unit |= remove_unit(plan, options, &mut report, FIREWALL_UNIT);
    }
    if removed_a_unit && plan.host {
        report.step(options, "systemctl daemon-reload", || {
            systemctl(plan, &["daemon-reload"])
        });
    }

    // 2. The live rules. See the module docs for why before NGINX.
    if target.firewall() {
        if plan.host {
            remove_nft_table(plan, options, &mut report);
            for iptables in &plan.iptables {
                remove_iptables_chain(options, &mut report, iptables);
            }
        } else {
            report.skip(
                "remove the live firewall rules",
                "--prefix is not this host's firewall",
            );
        }
    }

    // 3. NGINX, as one tested change.
    if target.nginx() {
        remove_nginx(plan, options, &mut report);
    }

    // 4. Files nothing refers to any more.
    if target.firewall() {
        for script in firewall_scripts(&plan.output_dir) {
            remove_file_step(plan, options, &mut report, &script);
        }
    }
    if target == Target::All {
        host_settings(plan, options, &mut report);
        remove_dir_if_empty(plan, options, &mut report, &plan.output_dir);
        database(plan, options, &mut report);
        account(plan, options, &mut report);
    }
    report
}

/// The console's user and group: removed with `--purge`, which removes
/// what they own, and kept otherwise, with the database they own. Only on
/// the host; a `--prefix` tree has no user database of its own.
fn account(plan: &Plan, options: &Options, report: &mut Report) {
    let user = plan.user.as_str();
    if !plan.host {
        return;
    }
    let has_user = crate::account::user(user).is_some();
    let has_group = crate::account::group(user).is_some();
    if !has_user && !has_group {
        return;
    }
    if !options.purge {
        report.kept.push(format!(
            "the {user} user and group, which own the database. `--purge` removes them too."
        ));
        return;
    }
    if has_user {
        report.step(options, format!("userdel {user}"), || {
            run_program(&plan.userdel, &[user]).map(|_| ())
        });
    }
    // `userdel` removes the user's own group with it, where it was made
    // with the user; one that is still there afterwards is removed here.
    let group_left = if options.dry_run {
        has_group
    } else {
        crate::account::group(user).is_some()
    };
    if group_left {
        report.step(options, format!("groupdel {user}"), || {
            run_program(&plan.groupdel, &[user]).map(|_| ())
        });
    }
}

/// Stops, disables and deletes `unit`, if its file is there. Returns
/// whether it was.
fn remove_unit(plan: &Plan, options: &Options, report: &mut Report, unit: &str) -> bool {
    let path = plan.unit_dir.join(unit);
    if !path.exists() {
        report.skip(format!("remove {unit}"), "it is not installed");
        return false;
    }
    if plan.host {
        // Stopped before it is disabled, and each on its own: an operator
        // reading a failure needs to know which half happened. The helper
        // is started by its socket and never enabled, so there is nothing
        // to disable.
        report.step(options, format!("systemctl stop {unit}"), || {
            systemctl(plan, &["stop", unit])
        });
        if unit != HELPER_UNIT {
            report.step(options, format!("systemctl disable {unit}"), || {
                systemctl(plan, &["disable", unit])
            });
        }
    }
    remove_file_step(plan, options, report, &path);
    true
}

fn systemctl(plan: &Plan, args: &[&str]) -> Result<()> {
    run_program(&plan.systemctl, args).map(|_| ())
}

/// Runs `program` with `args`; its stdout on success, its stderr in the
/// error otherwise. Never through a shell.
fn run_program(program: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .env("PATH", crate::host::path_with_sbin())
        .output()
        .with_context(|| format!("failed to run `{} {}`", program.display(), args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{} {}` exited with {}: {}",
            program.display(),
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The name a program is known by, for a step's description.
fn name_of(program: &Path) -> String {
    program
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.display().to_string())
}

fn remove_nft_table(plan: &Plan, options: &Options, report: &mut Report) {
    let [family, table] = NFT_TABLE;
    let what = format!("nft delete table {family} {table}");
    // Asked, not assumed: `nft` missing, or no such table, is nothing to
    // do. Either way the listing fails, and neither is a failure here.
    if run_program(&plan.nft, &["list", "table", family, table]).is_err() {
        report.skip(what, format!("there is no {family} {table} table"));
        return;
    }
    report.step(options, what, || {
        run_program(&plan.nft, &["delete", "table", family, table]).map(|_| ())
    });
}

/// Every jump into the chain first — a chain something jumps to cannot be
/// deleted — then the chain's rules, then the chain.
fn remove_iptables_chain(options: &Options, report: &mut Report, iptables: &Path) {
    let name = name_of(iptables);
    if run_program(iptables, &["-w", "-S", IPTABLES_CHAIN]).is_err() {
        report.skip(
            format!("{name} -X {IPTABLES_CHAIN}"),
            format!("{name} has no {IPTABLES_CHAIN} chain"),
        );
        return;
    }
    let rules = run_program(iptables, &["-w", "-S"]).unwrap_or_default();
    for jump in jumps_into(&rules, IPTABLES_CHAIN) {
        let mut args = vec!["-w", "-D"];
        args.extend(jump.iter().map(String::as_str));
        report.step(options, format!("{name} -D {}", jump.join(" ")), || {
            run_program(iptables, &args).map(|_| ())
        });
    }
    report.step(options, format!("{name} -F {IPTABLES_CHAIN}"), || {
        run_program(iptables, &["-w", "-F", IPTABLES_CHAIN]).map(|_| ())
    });
    report.step(options, format!("{name} -X {IPTABLES_CHAIN}"), || {
        run_program(iptables, &["-w", "-X", IPTABLES_CHAIN]).map(|_| ())
    });
}

/// Each rule in `iptables -S` output that jumps to `chain`, as the words
/// after `-A` — which is exactly what `-D` takes to delete it.
fn jumps_into(listing: &str, chain: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .filter_map(|line| line.strip_prefix("-A "))
        .filter_map(|rule| nginx::split_command(rule).ok())
        .filter(|words| {
            words
                .windows(2)
                .any(|pair| pair[0] == "-j" && pair[1] == chain)
        })
        .collect()
}

/// The generated files NGINX may read, wherever they may be: the
/// record's, and each known name in each `conf.d` it may have gone to.
///
/// Each is held through its directory ([`nginx::DirFile`]), so that what
/// is removed — and put back, if NGINX refuses the result — is in the
/// directory that was checked.
fn generated_nginx_files(plan: &Plan) -> Vec<nginx::DirFile> {
    let console = nginx::console_site_path(&plan.nginx_root);
    let mut files: Vec<nginx::DirFile> = plan
        .recorded
        .iter()
        .filter_map(|path| recorded_file_ours(path, &plan.managed_dir))
        .collect();
    let mut known = Vec::new();
    for conf_d in &plan.conf_d_dirs {
        known.push(nginx::untrusted_rate_limit_conf_path(conf_d));
        known.push(nginx::rate_limit_conf_path(conf_d));
        known.push(nginx::trusted_conf_path(conf_d));
    }
    known.push(plan.managed_dir.join("robots.txt"));
    if nginx::is_console_site_file(&console) {
        known.push(console);
    }
    files.extend(
        known
            .iter()
            .filter(|path| plan.allows(path))
            .filter_map(|path| nginx::DirFile::locate(path).ok().flatten()),
    );
    let mut seen = std::collections::HashSet::new();
    files.retain(|file| plan.allows(file.path()) && seen.insert(file.path().to_path_buf()));
    // The order a removal must go in; see `nginx::ManagedKind`.
    files.sort_by_key(|file| nginx::ManagedKind::of(file.path()));
    files
}

/// A path the database's record names, if it is a file stop-bots
/// generated, held through its directory.
///
/// The record is a table the console writes, and the console is not
/// root: a row naming `/etc/passwd`, or a link in `conf.d` pointing at it,
/// must not have this root process delete it. So it has to be a plain
/// file, not a link, opening with this project's own header, and either a
/// `stop-bots*` file in a `conf.d` — any `conf.d`, because finding the
/// files an old NGINX root left behind is what the record is for — or a
/// file in `managed_dir`.
///
/// And the path must already be resolved, with no link and no `..` in
/// it ([`nginx::DirFile::exactly`]). A `conf.d` can be the console's own
/// (`/var/lib/stop-bots/conf.d`), and one reached through a link the
/// console made could lead elsewhere by the time it is used; what passes
/// is used only through the directory descriptor this checked.
fn recorded_file_ours(path: &Path, managed_dir: &Path) -> Option<nginx::DirFile> {
    let file = nginx::DirFile::exactly(path).ok()?;
    let named = path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("stop-bots"));
    let placed = (named && file.dir().file_name().is_some_and(|name| name == "conf.d"))
        || std::fs::canonicalize(managed_dir).is_ok_and(|managed| managed == file.dir());
    let headed = || {
        file.first_line()
            .is_some_and(|first| first.starts_with("# Generated by stop-bots"))
    };
    (placed && file.is_regular() && headed()).then_some(file)
}

fn remove_nginx(plan: &Plan, options: &Options, report: &mut Report) {
    let what = format!(
        "take stop-bots out of every site under {}, and its generated files",
        plan.nginx_root.display()
    );
    if !plan.nginx_root.is_dir() {
        report.skip(
            what,
            format!("{} does not exist", plan.nginx_root.display()),
        );
    } else if !plan.allows(&plan.nginx_root) {
        report.skip(what, "the NGINX root is outside --prefix");
    } else {
        let generated = generated_nginx_files(plan);
        let commands = plan.host.then_some(&plan.nginx);
        match nginx::remove_everything(&plan.nginx_root, &generated, commands, options.dry_run) {
            Ok(removal) if removal.site_files.is_empty() && removal.generated.is_empty() => {
                report.skip(what, "nothing of stop-bots' is in it")
            }
            Ok(removal) => {
                let outcome = if options.dry_run {
                    Outcome::Planned
                } else {
                    Outcome::Done
                };
                for path in &removal.site_files {
                    report.steps.push(Step {
                        what: format!("take the stop-bots blocks out of {}", path.display()),
                        outcome: outcome.clone(),
                    });
                }
                for path in &removal.generated {
                    report.steps.push(Step {
                        what: format!("remove {}", path.display()),
                        outcome: outcome.clone(),
                    });
                }
                if removal.reloaded {
                    report.steps.push(Step {
                        what: "test and reload NGINX".to_string(),
                        outcome: Outcome::Done,
                    });
                } else if options.dry_run && plan.host {
                    report.steps.push(Step {
                        what: format!("test and reload NGINX ({})", plan.nginx.test.join(" ")),
                        outcome: Outcome::Planned,
                    });
                } else if !plan.host {
                    report.skip(
                        "test and reload NGINX",
                        "--prefix is not the running NGINX's config",
                    );
                }
            }
            Err(err) => report.steps.push(Step {
                what,
                outcome: Outcome::Failed(format!("{err:#}")),
            }),
        }
    }

    // Only the robots.txt the blocks just stopped naming lives here.
    if plan.managed_dir.exists() && plan.allows(&plan.managed_dir) {
        let dir = plan.managed_dir.clone();
        report.step(options, format!("remove {}", dir.display()), || {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("failed to remove {}", dir.display()))
        });
    }
}

/// The firewall scripts in `dir`: every file named `firewall.*`, which
/// covers both backends' and anything written beside them.
fn firewall_scripts(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut scripts: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("firewall."))
        })
        .collect();
    scripts.sort();
    scripts
}

fn remove_file_step(plan: &Plan, options: &Options, report: &mut Report, path: &Path) {
    let what = format!("remove {}", path.display());
    if !plan.allows(path) {
        report.skip(what, "it is outside --prefix");
        return;
    }
    report.step(options, what, || {
        std::fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))
    });
}

/// Removes `dir` if nothing is left in it. Something that is, is not
/// ours to delete, and is named instead.
fn remove_dir_if_empty(plan: &Plan, options: &Options, report: &mut Report, dir: &Path) {
    if !dir.is_dir() || !plan.allows(dir) {
        return;
    }
    // Under a dry run the files the steps above would remove are all
    // still there, so whether it would be empty cannot be read off it.
    if options.dry_run {
        report.step(
            options,
            format!("remove {} if nothing else is left in it", dir.display()),
            || Ok(()),
        );
        return;
    }
    let mut left: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    left.sort();
    // The host settings file is stop-bots' own, kept on purpose without
    // `--purge` and already named among what is left in place; it is
    // neither something "stop-bots did not write" nor a reason to say so.
    let keeps_host_conf = left.iter().any(|name| dir.join(name) == plan.host_conf);
    left.retain(|name| dir.join(name) != plan.host_conf);
    if left.is_empty() && keeps_host_conf {
        // Nothing to report: the directory stays for the file kept in it.
    } else if left.is_empty() {
        report.step(options, format!("remove {}", dir.display()), || {
            std::fs::remove_dir(dir).with_context(|| format!("failed to remove {}", dir.display()))
        });
    } else {
        report.kept.push(format!(
            "{} still holds {}, which stop-bots did not write",
            dir.display(),
            left.join(", ")
        ));
    }
}

/// The database, its companions and the copies upgrades kept.
fn database_files(db: &Path) -> Vec<PathBuf> {
    let Some(name) = db
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return Vec::new();
    };
    let dir = db.parent().unwrap_or(Path::new("."));
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|file| {
                    file == &name
                        || ["-wal", "-shm", "-journal"]
                            .iter()
                            .any(|suffix| *file == format!("{name}{suffix}"))
                        || file.starts_with(&format!("{name}.bak-v"))
                })
                .map(|file| dir.join(file))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// The host settings file: kept, like the database, unless `--purge`.
fn host_settings(plan: &Plan, options: &Options, report: &mut Report) {
    if std::fs::symlink_metadata(&plan.host_conf).is_err() {
        return;
    }
    if options.purge {
        remove_file_step(plan, options, report, &plan.host_conf);
    } else {
        report.kept.push(format!(
            "the host settings (the NGINX commands and root, the log paths): {}. `--purge` \
             removes it too.",
            plan.host_conf.display()
        ));
    }
}

fn database(plan: &Plan, options: &Options, report: &mut Report) {
    let files = database_files(&plan.db_path);
    if files.is_empty() {
        return;
    }
    if !options.purge {
        let copies: Vec<String> = files
            .iter()
            .filter(|file| file.to_string_lossy().contains(".bak-v"))
            .map(|file| file.display().to_string())
            .collect();
        let mut kept = format!(
            "the database, with every setting and rule: {}",
            plan.db_path.display()
        );
        if !copies.is_empty() {
            kept.push_str(&format!(
                "; and the copies upgrades kept of it: {}",
                copies.join(", ")
            ));
        }
        kept.push_str(". `--purge` removes them too.");
        report.kept.push(kept);
        return;
    }
    for file in &files {
        remove_file_step(plan, options, report, file);
    }
    if let Some(dir) = plan.db_path.parent() {
        remove_dir_if_empty(plan, options, report, dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan for a tree under `dir`, driving fake programs that log
    /// their arguments to `dir/calls.log` — the host path, confined.
    struct Staged {
        dir: tempfile::TempDir,
        plan: Plan,
    }

    impl Staged {
        fn new() -> Staged {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path();
            let mut plan = Plan::resolve(Some(base), None, None).unwrap();
            // The host's path, programs and all, but kept inside the tree.
            plan.host = true;
            plan.managed_dir = base.join("etc/stop-bots/nginx");
            plan.conf_d_dirs = vec![base.join("etc/nginx/conf.d")];
            std::fs::create_dir_all(base.join("etc/nginx/conf.d")).unwrap();
            std::fs::create_dir_all(&plan.unit_dir).unwrap();
            let mut staged = Staged { dir, plan };
            staged.plan.systemctl = staged.fake("systemctl", "exit 0");
            // Never the host's own: a machine running these tests may well
            // have a `stop-bots` user.
            staged.plan.userdel = staged.fake("userdel", "exit 0");
            staged.plan.groupdel = staged.fake("groupdel", "exit 0");
            staged.plan.user = "stop-bots-test-no-such-user".to_string();
            // No table, and no chain, until a test says otherwise.
            staged.plan.nft = staged.fake("nft", "[ \"$1\" = list ] && exit 1\nexit 0");
            staged.plan.iptables = vec![staged.fake(
                "iptables",
                "[ \"$2\" = -S ] && [ -n \"$3\" ] && exit 1\nexit 0",
            )];
            staged.plan.nginx = NginxCommands {
                test: vec![
                    staged.fake("nginx", "exit 0").display().to_string(),
                    "-t".into(),
                ],
                reload: vec![staged.fake("reload", "exit 0").display().to_string()],
            };
            staged
        }

        fn path(&self, relative: &str) -> PathBuf {
            self.dir.path().join(relative)
        }

        fn write(&self, relative: &str, content: &str) -> PathBuf {
            let path = self.path(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }

        /// Every program call, in order, as `<name> <args>`.
        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.path("calls.log"))
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn fake(&self, name: &str, body: &str) -> PathBuf {
            let path = self.path(&format!("fake-{name}"));
            crate::testing::write_script(
                &path,
                &format!(
                    "echo \"{name} $*\" >> {}\n{body}",
                    self.path("calls.log").display()
                ),
            );
            path
        }
    }

    const SITE: &str = "server {\n    listen 80;\n    server_name example.com;\n}\n";

    fn with_block(site: &str) -> String {
        site.replacen(
            "server {\n",
            "server {\n    # BEGIN stop-bots (DO NOT EDIT)\n    if ($http_user_agent ~* \"BadBot\") {\n        return 403;\n    }\n    # END stop-bots\n\n",
            1,
        )
    }

    fn failures(report: &Report) -> Vec<&Step> {
        report
            .steps
            .iter()
            .filter(|s| matches!(s.outcome, Outcome::Failed(_)))
            .collect()
    }

    #[test]
    fn with_block_is_what_the_product_inserts() {
        // Pins the fixture above to the real insertion, so the tests
        // below are about the product's blocks, not a guess at them.
        assert_eq!(nginx::without_injected_blocks(&with_block(SITE)), SITE);
    }

    /// The order is the safety argument in the module docs: the units
    /// before anything they could put back, the rules before NGINX.
    #[test]
    fn everything_goes_in_the_safe_order() {
        let staged = Staged::new();
        staged.write("etc/systemd/system/stop-bots-web.service", "unit");
        staged.write("etc/systemd/system/stop-bots-helper.socket", "unit");
        staged.write("etc/systemd/system/stop-bots-helper.service", "unit");
        staged.write("etc/systemd/system/stop-bots-firewall.service", "unit");
        let mut plan = staged.plan.clone();
        plan.nft = staged.fake("nft", "exit 0");
        let site = staged.write("etc/nginx/sites-enabled/example", &with_block(SITE));

        let report = run(&plan, Target::All, &Options::default());

        assert!(failures(&report).is_empty(), "{report:#?}");
        let calls = staged.calls();
        let position = |needle: &str| {
            calls
                .iter()
                .position(|call| call.starts_with(needle))
                .unwrap_or_else(|| panic!("no `{needle}` in {calls:#?}"))
        };
        assert!(
            position("systemctl stop stop-bots-web.service")
                < position("systemctl stop stop-bots-helper.socket")
        );
        assert!(
            position("systemctl stop stop-bots-helper.socket")
                < position("systemctl stop stop-bots-helper.service")
        );
        assert!(
            position("systemctl stop stop-bots-helper.service")
                < position("nft delete table inet stop_bots")
        );
        assert!(
            position("systemctl disable stop-bots-firewall.service")
                < position("nft delete table inet stop_bots")
        );
        assert!(position("nft delete table") < position("nginx -t"));
        assert!(position("nginx -t") < position("reload"));
        assert_eq!(std::fs::read_to_string(site).unwrap(), SITE);
        assert!(!staged
            .path("etc/systemd/system/stop-bots-web.service")
            .exists());
        for unit in [
            "stop-bots-firewall.service",
            "stop-bots-helper.socket",
            "stop-bots-helper.service",
        ] {
            assert!(
                !staged.path(&format!("etc/systemd/system/{unit}")).exists(),
                "{unit} was left"
            );
        }
        // The helper is started by its socket and never enabled.
        assert!(
            !calls
                .iter()
                .any(|call| call == "systemctl disable stop-bots-helper.service"),
            "{calls:#?}"
        );
    }

    /// `--purge` removes what owns the database along with it: the
    /// console's user and its group. Without it both stay, and say so.
    #[test]
    fn the_consoles_user_goes_only_with_purge() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        // A user that exists, standing in for the console's; the fakes
        // remove nothing.
        // SAFETY: no preconditions; reads the process's own credentials.
        plan.user = crate::account::user_name(unsafe { libc::geteuid() });
        let has_group = crate::account::group(&plan.user).is_some();

        let kept = run(&plan, Target::All, &Options::default());
        assert!(
            !staged
                .calls()
                .iter()
                .any(|call| call.starts_with("userdel")),
            "{:#?}",
            staged.calls()
        );
        assert!(
            kept.kept.iter().any(|k| k.contains(&plan.user)),
            "{:#?}",
            kept.kept
        );

        let purged = run(
            &plan,
            Target::All,
            &Options {
                purge: true,
                ..Options::default()
            },
        );
        assert_eq!(purged.failures(), 0, "{purged:#?}");
        let calls = staged.calls();
        assert!(
            calls.contains(&format!("userdel {}", plan.user)),
            "{calls:#?}"
        );
        // The fake removed nothing, so the group is still there to remove.
        assert_eq!(
            calls.contains(&format!("groupdel {}", plan.user)),
            has_group,
            "{calls:#?}"
        );
    }

    /// The record is the console's to write, and the console is not
    /// root: a row naming a file that is not one of ours, or a link that
    /// is named like one, must not have uninstall delete it.
    #[test]
    fn a_recorded_path_that_is_not_ours_is_not_deleted() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        let passwd = staged.write("etc/passwd", "root:x:0:0::/root:/bin/sh\n");
        let headed_elsewhere = staged.write(
            "etc/cron.d/stop-bots-job",
            "# Generated by stop-bots.\n* * * * * root true\n",
        );
        let link = staged.path("etc/nginx/conf.d/stop-bots-evil.conf");
        std::os::unix::fs::symlink(&passwd, &link).unwrap();
        let unheaded = staged.write("etc/nginx/conf.d/stop-bots-site.conf", "server {}\n");
        plan.recorded = vec![
            passwd.clone(),
            headed_elsewhere.clone(),
            link.clone(),
            unheaded.clone(),
        ];

        let report = run(&plan, Target::Nginx, &Options::default());

        assert_eq!(report.failures(), 0, "{report:#?}");
        for file in [&passwd, &headed_elsewhere, &unheaded] {
            assert!(file.exists(), "{} was deleted", file.display());
        }
        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "the link was deleted"
        );
    }

    /// A recorded path that reaches a `conf.d` through a link the console
    /// made in its own directory is not followed: the file it leads to,
    /// headed and named like ours, stays.
    #[test]
    fn a_recorded_path_through_a_link_is_not_followed() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        let theirs = staged.write(
            "srv/old-root/conf.d/stop-bots-trusted.conf",
            "# Generated by stop-bots.\n",
        );
        let link = staged.path("var/lib/stop-bots/link");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(theirs.parent().unwrap(), &link).unwrap();
        plan.recorded = vec![link.join("stop-bots-trusted.conf")];

        let report = run(&plan, Target::Nginx, &Options::default());

        assert_eq!(report.failures(), 0, "{report:#?}");
        assert!(theirs.exists(), "removed through the console's link");
    }

    /// **Checked once, used through what was checked.** A `conf.d` of the
    /// console's own, swapped for a link to another directory after the
    /// files were resolved: the removal and the restore after NGINX
    /// refuses the result happen in the directory that was checked, and
    /// nothing is written where the link now points.
    #[test]
    fn a_conf_d_swapped_after_the_check_is_not_the_one_used() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        let body = "# Generated by stop-bots.\nmap $x $y {}\n";
        let recorded = staged.write("var/lib/stop-bots/conf.d/stop-bots-trusted.conf", body);
        plan.recorded = vec![recorded.clone()];
        let victim = staged.path("etc/fonts/conf.d");
        std::fs::create_dir_all(&victim).unwrap();

        let generated = generated_nginx_files(&plan);
        let checked = staged.path("var/lib/stop-bots/checked");
        std::fs::rename(recorded.parent().unwrap(), &checked).unwrap();
        std::os::unix::fs::symlink(&victim, recorded.parent().unwrap()).unwrap();
        let refusing = NginxCommands {
            test: vec!["false".into()],
            reload: vec!["true".into()],
        };
        let result = nginx::remove_everything(&plan.nginx_root, &generated, Some(&refusing), false);

        assert!(result.is_err(), "NGINX refused it, so it was put back");
        assert_eq!(
            std::fs::read_to_string(checked.join("stop-bots-trusted.conf")).unwrap(),
            body,
            "not put back where it was checked"
        );
        assert_eq!(
            std::fs::read_dir(&victim).unwrap().count(),
            0,
            "the restore wrote where the link now points"
        );
    }

    /// A FIFO or a directory a row names is not opened (a FIFO would hang
    /// the read) and not removed.
    #[test]
    fn a_recorded_fifo_or_directory_is_left_alone() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        let fifo = staged.path("etc/nginx/conf.d/stop-bots-fifo.conf");
        crate::testing::mkfifo(&fifo);
        let dir = staged.path("etc/nginx/conf.d/stop-bots-dir.conf");
        std::fs::create_dir(&dir).unwrap();
        plan.recorded = vec![fifo.clone(), dir.clone()];

        let report = run(&plan, Target::Nginx, &Options::default());

        assert_eq!(report.failures(), 0, "{report:#?}");
        assert!(std::fs::symlink_metadata(&fifo).is_ok(), "the FIFO went");
        assert!(dir.is_dir(), "the directory went");
    }

    #[test]
    fn the_iptables_chain_goes_after_every_jump_into_it() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        plan.iptables = vec![staged.fake(
            "iptables",
            "if [ \"$2\" = -S ] && [ -z \"$3\" ]; then\n\
             printf '%s\\n' '-P INPUT ACCEPT' '-N STOP-BOTS' '-A INPUT -j STOP-BOTS' \
             '-A FORWARD -j STOP-BOTS' '-A INPUT -p tcp --dport 22 -j ACCEPT' \
             '-A STOP-BOTS -s 192.0.2.1/32 -j DROP'\n\
             fi\nexit 0",
        )];

        let report = run(&plan, Target::Firewall, &Options::default());

        assert!(failures(&report).is_empty(), "{report:#?}");
        let changes: Vec<String> = staged
            .calls()
            .into_iter()
            .filter(|call| call.contains(" -D ") || call.contains(" -F ") || call.contains(" -X "))
            .collect();
        assert_eq!(
            changes,
            [
                "iptables -w -D INPUT -j STOP-BOTS",
                "iptables -w -D FORWARD -j STOP-BOTS",
                "iptables -w -F STOP-BOTS",
                "iptables -w -X STOP-BOTS",
            ]
        );
    }

    /// Nothing there is nothing to do, not a failure: an uninstall run
    /// twice, or on a host that never applied anything, succeeds.
    #[test]
    fn a_host_with_nothing_on_it_is_not_a_failure() {
        let staged = Staged::new();

        let report = run(&staged.plan, Target::All, &Options::default());

        assert_eq!(report.failures(), 0, "{report:#?}");
        assert!(
            !staged
                .calls()
                .iter()
                .any(|c| c.contains("delete") || c.contains(" -X ")),
            "it removed something that was not there: {:#?}",
            staged.calls()
        );
    }

    /// A failed step is reported, and the ones after it still run.
    #[test]
    fn a_failed_step_does_not_stop_the_rest() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        plan.nft = staged.fake(
            "nft",
            "[ \"$1\" = delete ] && { echo 'Operation not permitted' >&2; exit 1; }\nexit 0",
        );
        let site = staged.write("etc/nginx/sites-enabled/example", &with_block(SITE));

        let report = run(&plan, Target::All, &Options::default());

        let failed = failures(&report);
        assert_eq!(failed.len(), 1, "{report:#?}");
        assert!(
            matches!(&failed[0].outcome, Outcome::Failed(why) if why.contains("Operation not permitted"))
        );
        assert_eq!(
            std::fs::read_to_string(site).unwrap(),
            SITE,
            "NGINX was not reached"
        );
    }

    /// NGINX refusing the result puts every site back, and says so.
    #[test]
    fn nginx_refusing_the_result_puts_the_sites_back() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        plan.nginx.test = vec![staged.fake("nginx", "exit 1").display().to_string()];
        let site = staged.write("etc/nginx/sites-enabled/example", &with_block(SITE));

        let report = run(&plan, Target::Nginx, &Options::default());

        assert_eq!(report.failures(), 1, "{report:#?}");
        assert_eq!(std::fs::read_to_string(site).unwrap(), with_block(SITE));
        assert!(!staged.calls().iter().any(|c| c.starts_with("reload")));
    }

    #[test]
    fn a_dry_run_changes_nothing_and_says_what_it_would_do() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        plan.nft = staged.fake("nft", "exit 0");
        staged.write("etc/systemd/system/stop-bots-web.service", "unit");
        let site = staged.write("etc/nginx/sites-enabled/example", &with_block(SITE));
        let script = staged.write("etc/stop-bots/firewall.nft", "table");
        let limits = staged.write(
            "etc/nginx/conf.d/stop-bots-limits.conf",
            "# Generated by stop-bots.\n",
        );

        let report = run(
            &plan,
            Target::All,
            &Options {
                dry_run: true,
                purge: true,
            },
        );

        assert!(
            report.steps.iter().any(|s| s.outcome == Outcome::Planned),
            "{report:#?}"
        );
        let reads = ["nft list", "iptables -w -S"];
        assert!(
            staged
                .calls()
                .iter()
                .all(|call| reads.iter().any(|read| call.starts_with(read))),
            "only a read may run in a dry run: {:#?}",
            staged.calls()
        );
        assert_eq!(std::fs::read_to_string(site).unwrap(), with_block(SITE));
        for path in [
            &script,
            &limits,
            &staged.path("etc/systemd/system/stop-bots-web.service"),
        ] {
            assert!(path.exists(), "{} was removed", path.display());
        }
    }

    #[test]
    fn the_database_is_kept_unless_purged_and_says_where() {
        let staged = Staged::new();
        let db = staged.write("var/lib/stop-bots/db.sqlite3", "");
        let backup = staged.write("var/lib/stop-bots/db.sqlite3.bak-v0", "");
        // What WAL leaves beside it while the console has it open.
        let wal = staged.write("var/lib/stop-bots/db.sqlite3-wal", "");
        let shm = staged.write("var/lib/stop-bots/db.sqlite3-shm", "");

        let kept = run(&staged.plan, Target::All, &Options::default());
        assert!(db.exists() && backup.exists());
        assert!(
            kept.kept
                .iter()
                .any(|k| k.contains(&db.display().to_string()) && k.contains("bak-v0")),
            "{:#?}",
            kept.kept
        );

        let purged = run(
            &staged.plan,
            Target::All,
            &Options {
                purge: true,
                ..Options::default()
            },
        );
        assert_eq!(purged.failures(), 0, "{purged:#?}");
        for file in [&db, &backup, &wal, &shm] {
            assert!(!file.exists(), "{} survived --purge", file.display());
        }
        assert!(
            !staged.path("var/lib/stop-bots").exists(),
            "the emptied directory was left"
        );
    }

    /// `/etc/stop-bots` goes once it is empty, and not if an operator put
    /// something of their own in it.
    #[test]
    fn the_output_directory_goes_only_once_it_is_empty() {
        let staged = Staged::new();
        staged.write("etc/stop-bots/firewall.nft", "table");
        staged.write("etc/stop-bots/firewall.sh", "script");
        staged.write(
            "etc/stop-bots/nginx/robots.txt",
            "# Generated by stop-bots.\n",
        );

        run(&staged.plan, Target::All, &Options::default());
        assert!(!staged.path("etc/stop-bots").exists());

        let mine = staged.write("etc/stop-bots/notes.txt", "mine");
        let report = run(&staged.plan, Target::All, &Options::default());
        assert!(mine.exists());
        assert!(
            report.kept.iter().any(|k| k.contains("notes.txt")),
            "{:#?}",
            report.kept
        );
    }

    /// The host settings file stays without `--purge`, as the report's
    /// "left in place" says, and is not then called somebody else's file.
    #[test]
    fn a_kept_host_conf_is_not_called_somebody_elses() {
        let staged = Staged::new();
        let rel = crate::hostconf::DEFAULT_PATH.trim_start_matches('/');
        let host_conf = staged.write(rel, "# stop-bots host settings\n");
        assert_eq!(
            host_conf, staged.plan.host_conf,
            "the test stages the wrong file"
        );

        let report = run(&staged.plan, Target::All, &Options::default());
        assert!(host_conf.exists(), "host.conf went without --purge");
        assert!(
            !report.kept.iter().any(|k| k.contains("did not write")),
            "{:#?}",
            report.kept
        );
    }

    /// The generated files in every place they may have been written:
    /// the record's, and the stock `conf.d` that old releases always used.
    #[test]
    fn generated_files_are_found_by_the_record_and_by_name() {
        let staged = Staged::new();
        let mut plan = staged.plan.clone();
        let recorded = staged.write(
            "srv/old-root/conf.d/stop-bots-trusted.conf",
            "# Generated by stop-bots.\n",
        );
        plan.recorded = vec![recorded.clone()];
        let by_name = staged.write(
            "etc/nginx/conf.d/stop-bots-limits.conf",
            "# Generated by stop-bots.\n",
        );
        let theirs = staged.write("etc/nginx/conf.d/default.conf", "server {}\n");

        let report = run(&plan, Target::Nginx, &Options::default());

        assert_eq!(report.failures(), 0, "{report:#?}");
        assert!(!recorded.exists() && !by_name.exists());
        assert!(theirs.exists(), "an operator's own conf.d file was removed");
    }

    /// Under `--prefix` nothing outside the tree is touched, whatever the
    /// record says.
    #[test]
    fn nothing_outside_the_prefix_is_touched() {
        let staged = Staged::new();
        let outside = tempfile::tempdir().unwrap();
        let elsewhere = outside.path().join("stop-bots-trusted.conf");
        std::fs::write(&elsewhere, "# Generated by stop-bots.\n").unwrap();
        let mut plan = staged.plan.clone();
        plan.recorded = vec![elsewhere.clone()];

        run(&plan, Target::All, &Options::default());

        assert!(elsewhere.exists());
    }

    #[test]
    fn jumps_are_read_from_iptables_listing() {
        let listing = "-P INPUT ACCEPT\n-N STOP-BOTS\n-A INPUT -j STOP-BOTS\n\
                       -A DOCKER-USER -m comment --comment \"a b\" -j STOP-BOTS\n\
                       -A INPUT -j STOP-BOTS-OTHER\n-A STOP-BOTS -s 1.2.3.4/32 -j DROP\n";
        assert_eq!(
            jumps_into(listing, "STOP-BOTS"),
            [
                vec!["INPUT", "-j", "STOP-BOTS"],
                vec![
                    "DOCKER-USER",
                    "-m",
                    "comment",
                    "--comment",
                    "a b",
                    "-j",
                    "STOP-BOTS"
                ],
            ]
        );
    }

    /// The settings an uninstall needs are read without upgrading the
    /// database — a dry run must not leave a `.bak-v*` behind.
    #[test]
    fn reading_the_database_does_not_upgrade_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO settings VALUES (?1, '/srv/nginx')",
                [NginxCommands::ROOT_KEY],
            )
            .unwrap();
        }

        let plan = Plan::resolve(None, Some(path.clone()), None).unwrap();

        assert_eq!(plan.nginx_root, PathBuf::from("/srv/nginx"));
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("db.sqlite3")]);
    }

    /// A database this release wrote is in WAL mode, and a dry run must
    /// not leave a `-wal` and `-shm` behind by reading it.
    #[test]
    fn reading_a_wal_database_leaves_no_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        crate::db::Db::open(&path)
            .unwrap()
            .set_text_setting(NginxCommands::ROOT_KEY, "/srv/nginx")
            .unwrap();

        let plan = Plan::resolve(None, Some(path.clone()), None).unwrap();

        assert_eq!(plan.nginx_root, PathBuf::from("/srv/nginx"));
        let mut names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["db.sqlite3"]);
    }
}
