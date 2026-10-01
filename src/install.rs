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

//! Installing stop-bots as a system service — `stop-bots install web`.
//!
//! Everything else in this project writes a file and stops. This one
//! writes a unit, reloads systemd and starts a daemon, so it is the one
//! module whose mistakes are hard to undo by editing a file back. Three
//! rules follow from that, and they are why this is a module rather than
//! forty lines in `main.rs`:
//!
//! - **Every path it touches is a field on [`Layout`].** Nothing reads a
//!   constant at the point of use. That is what lets a test point the
//!   whole installer at a temp directory and assert the bytes, rather than
//!   asserting that the code would have written the right thing.
//! - **Nothing is written until every check has passed.** A half-install
//!   — directories made, unit missing — is worse than no install, because
//!   it looks done.
//! - **It refuses rather than overwrites.** A unit file someone has edited
//!   is a decision, not a stale artefact.
//!
//! ## Telling an edited unit from an old one
//!
//! "Differs from what this version would write" is not "edited": every
//! release that changes a template would read as an edit on every host,
//! and a re-install would refuse until `--force`, which then also
//! overwrites the units somebody really did edit. So each unit records the
//! hash of its own text on a [`TEMPLATE_MARKER`] line. A unit whose text
//! still hashes to it is exactly as stop-bots wrote it, whichever version
//! that was, and is replaced without asking; one that doesn't was edited.
//!
//! Units from 0.0.x carry no hash. They are compared against every text
//! those releases wrote instead — see [`legacy`].
//!
//! ## Three units, and who runs as whom
//!
//! The console is the part of stop-bots that listens on a network, so it
//! is the part that must not be root. `install web` writes three units:
//!
//! - [`WEB_UNIT`], the console, as the `stop-bots` system user this
//!   creates ([`crate::account`]). It can bind its port, read the logs
//!   through the groups its unit adds, and write its own database. It has
//!   no capability, cannot write `/etc`, cannot load firewall rules and
//!   cannot see systemd's sockets — see [`web_unit`].
//! - [`HELPER_SOCKET_UNIT`] and [`HELPER_UNIT`], the root helper, started
//!   by systemd when the console first connects to its socket. It does the
//!   handful of things that need root — write the NGINX config and the
//!   firewall script, run `nginx -t`, the reload and `nft` — as a closed
//!   set of operations with typed parameters. No path, command or config
//!   text ever crosses the socket.
//!
//! The helper keeps the sandbox the console had while it ran as root:
//! `ProtectSystem=strict` makes the whole tree read-only, and
//! `ReadWritePaths=` gives back exactly what the helper writes — see
//! [`writable_paths`]. The list has to be complete: a path missing from it
//! is not a failed start but an apply that fails an hour later with "Read-only
//! file system", so every entry is there because the container suite
//! watched something fail without it. For root that is defence in depth,
//! not a boundary: root can reach systemd, which `systemctl reload nginx`
//! needs. What makes the split a boundary is the console's side of it.
//!
//! The firewall boot unit is sandboxed harder, because it needs less: it
//! loads one script and has no business with systemd at all, so it gets no
//! `AF_UNIX` and no capability beyond the network. See [`firewall_unit`].

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub mod legacy;

/// The start of the line a generated unit records its template hash on:
/// the SHA-256, in hex, of the unit's whole text without this line.
///
/// **Frozen.** Every later release looks for exactly this to decide
/// whether a unit on disk is one it may replace. Renaming it would make
/// every unit written until then look edited, which is the failure this
/// line exists to prevent.
pub const TEMPLATE_MARKER: &str = "# stop-bots-template: ";

/// The unit this installs. Named for the thing it runs rather than the
/// project, because a later `install tui`-shaped target would want its own.
pub const WEB_UNIT: &str = "stop-bots-web.service";

/// The socket the console reaches the root helper on. systemd listens on
/// it and starts [`HELPER_UNIT`] at the first connection.
pub const HELPER_SOCKET_UNIT: &str = "stop-bots-helper.socket";

/// The root helper, socket-activated by [`HELPER_SOCKET_UNIT`].
pub const HELPER_UNIT: &str = "stop-bots-helper.service";

/// Where the helper's socket is, as the console's `--helper` names it.
pub const HELPER_SOCKET: &str = "/run/stop-bots/helper.sock";

/// The unit that re-applies the rendered firewall script at boot.
///
/// A unit of this project's own rather than Debian's `nftables.service`,
/// and the difference is the whole point. `nftables.service` loads
/// `/etc/nftables.conf`; this project writes `/etc/stop-bots/firewall.nft`.
/// Enabling the former restores a different file's rules and leaves these
/// ones gone — and on a stock Debian or Ubuntu, where that file still opens
/// with `flush ruleset`, enabling it also drops every table anything else
/// on the host has loaded (ufw, Docker, a geo-blocker) once per boot.
///
/// This unit applies one script, touches one table, and orders itself after
/// the services whose rules it must not race.
pub const FIREWALL_UNIT: &str = "stop-bots-firewall.service";

/// Where the installer writes, one field per path.
///
/// `system()` is the real one; `under()` puts the same tree inside a
/// prefix so a test can run the whole installer for real and read back
/// what it produced.
#[derive(Debug, Clone)]
pub struct Layout {
    /// `/etc/systemd/system`.
    pub unit_dir: PathBuf,
    /// `/var/lib/stop-bots` — holds the database, and so the password hash.
    pub state_dir: PathBuf,
    /// `/etc/stop-bots` — where the cron's `RenderFirewall` job writes.
    pub output_dir: PathBuf,
    /// The database the service will open.
    pub db_path: PathBuf,
    /// The `stop-bots` binary the unit's `ExecStart` will name.
    pub binary: PathBuf,
    /// `/etc/nginx`, the stock NGINX config root. Always writable by the
    /// service, whatever root it manages: with no `conf.d` beside the
    /// sites, the generated `conf.d` files go to `/etc/nginx/conf.d`.
    pub nginx_dir: PathBuf,
    /// Every other NGINX config root the service may manage: `--root`, the
    /// one a 0.0.x unit named, and — added by [`install_web`] — the one
    /// the database stores (`set-nginx-commands --root`). Only paths the
    /// unit has to let the service write; the service itself reads the
    /// stored root.
    pub nginx_roots: Vec<PathBuf>,
    /// `/var/log/nginx`. Written, not only read: `nginx -t` opens every
    /// log the config names for writing, and fails on one it cannot.
    pub nginx_log_dir: PathBuf,
    /// Every other directory NGINX writes a log in, which `nginx -t` opens
    /// files in for the same reason: the stored access log's
    /// (`set-log-paths`), and each one an `access_log` or `error_log` in the
    /// config names. Filled in by [`install_web`]; see [`nginx_log_dirs`].
    pub log_dirs: Vec<PathBuf>,
    /// `/run`. Writable for the service; see [`writable_paths`] for why
    /// the whole of it rather than the three files it uses there.
    pub run_dir: PathBuf,
    /// An explicit SSH log for the unit to name, or `None` to let the
    /// service find its own at runtime.
    ///
    /// `None` is the default, and the important one. This used to be a
    /// plain `PathBuf` defaulting to `/var/log/auth.log`, which baked a
    /// guess about the host into `ExecStart` at install time — and Debian
    /// 12 dropped rsyslog from default installs, so on a current Debian
    /// host that guess names a file which does not exist. The service then
    /// read nothing, found no SSH attempts, and said so as an empty panel
    /// rather than an error, because an unreadable log is "could not
    /// check", not "checked and clear".
    ///
    /// Passing no flag is not the same as passing this path. With no
    /// `--ssh-log`, `sshlog::SshSource::Search` tries `/var/log/auth.log`
    /// and `/var/log/secure`, *then* falls back to `journalctl`, which is
    /// where a journald-only host keeps its sshd lines. An explicit path
    /// deliberately skips that fallback — it means "read this, not whatever
    /// you can find" — so it belongs in the unit only when an operator
    /// asked for it.
    pub ssh_log: Option<PathBuf>,
    /// Exists only under systemd. The documented way to detect it — a
    /// `systemctl` binary on `PATH` proves only that the package is
    /// installed, which is true inside a Docker container that is not
    /// running systemd at all.
    pub systemd_marker: PathBuf,
    /// Exists only on Debian and its derivatives.
    pub debian_marker: PathBuf,
    /// The `systemctl` to run. A field rather than a bare `"systemctl"` at
    /// the point of use for the same reason every path here is one: it is
    /// what lets a test point [`activate`] at a script that records its
    /// arguments, instead of leaving the one function that starts a daemon
    /// untested. Injecting it beats putting a fake on `PATH`, which is
    /// process-global and races under a threaded test runner.
    pub systemctl: PathBuf,
    /// `useradd` and `groupadd`, injected for the same reason.
    pub useradd: PathBuf,
    pub groupadd: PathBuf,
    /// The user and group the console runs as.
    pub user: String,
    /// The groups the console's unit adds so it can read the logs. All of
    /// [`crate::account::LOG_GROUPS`] here; [`install_web`] keeps only the
    /// ones the host has, because a unit naming a missing group does not
    /// start.
    pub log_groups: Vec<String>,
    /// [`HELPER_SOCKET`], under the prefix.
    pub helper_socket: PathBuf,
    /// Whether this describes the running host rather than a staging tree,
    /// i.e. whether the prefix was `/`.
    ///
    /// `--prefix` writes a unit into a directory nothing will ever start,
    /// so the checks that are about what *this host's* systemd would do —
    /// see [`hidden_from_unit`] — have nothing to be true or false about
    /// there. Applying them anyway would refuse every `--prefix` run whose
    /// staging tree sits under `/tmp`, which is all of them. For the same
    /// reason [`install_firewall`] runs no `systemctl` unless this is set.
    real: bool,
}

impl Layout {
    pub fn system(binary: PathBuf) -> Self {
        Self::under(Path::new("/"), binary)
    }

    /// The same tree rooted at `prefix`. Every path is built by joining a
    /// *relative* path onto it, since `Path::join` with an absolute path
    /// discards the prefix entirely — the mistake that would make a test
    /// write to the developer's real `/etc`.
    pub fn under(prefix: &Path, binary: PathBuf) -> Self {
        Self {
            unit_dir: prefix.join("etc/systemd/system"),
            state_dir: prefix.join("var/lib/stop-bots"),
            output_dir: prefix.join("etc/stop-bots"),
            db_path: prefix.join("var/lib/stop-bots/db.sqlite3"),
            binary,
            nginx_dir: prefix.join("etc/nginx"),
            nginx_roots: Vec::new(),
            nginx_log_dir: prefix.join("var/log/nginx"),
            log_dirs: Vec::new(),
            run_dir: prefix.join("run"),
            ssh_log: None,
            systemd_marker: prefix.join("run/systemd/system"),
            debian_marker: prefix.join("etc/debian_version"),
            systemctl: PathBuf::from("systemctl"),
            useradd: crate::host::program("useradd"),
            groupadd: crate::host::program("groupadd"),
            user: crate::account::USER.to_string(),
            log_groups: crate::account::LOG_GROUPS.map(String::from).to_vec(),
            helper_socket: prefix.join(HELPER_SOCKET.trim_start_matches('/')),
            // Derived, not a parameter: `main.rs` builds every layout —
            // prefixed or not — with `under`, so a flag a caller had to
            // remember to set would have been `false` on the one path
            // that matters. That is not hypothetical; it is what the first
            // version of this did, and the check below was dead in
            // production while every test passed.
            real: prefix == Path::new("/"),
        }
    }

    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(WEB_UNIT)
    }

    /// This layout with what the host says added: the NGINX root the
    /// database stores, the stored access log's directory, and every log
    /// directory the NGINX config names.
    ///
    /// The database is read read-only, and only if it is there: `install
    /// web --dry-run` promises to touch nothing, and `Db::open` would
    /// create or migrate the file.
    fn with_host_settings(&self) -> Layout {
        let mut layout = self.clone();
        // On the host, only the groups it has: `SupplementaryGroups=`
        // naming a missing one fails the start with 216/GROUP.
        if self.real {
            layout
                .log_groups
                .retain(|name| crate::account::group(name).is_some());
        }
        let (stored_root, stored_access_log) = self.stored_host_settings();
        // A stored root inside /etc/nginx is given back already, and any
        // other one only if it is `grantable`: a database row may have been
        // written by the console.
        layout.nginx_roots.extend(
            stored_root
                .map(PathBuf::from)
                .filter(|root| root.starts_with(&self.nginx_dir) || grantable(root)),
        );
        layout.log_dirs.extend(
            stored_access_log
                .as_deref()
                .and_then(|log| Path::new(log).parent())
                .filter(|dir| grantable(dir))
                .map(Path::to_path_buf),
        );
        let roots: Vec<PathBuf> = std::iter::once(layout.nginx_dir.clone())
            .chain(layout.nginx_roots.iter().cloned())
            .collect();
        layout.log_dirs.extend(nginx_log_dirs(&roots));
        layout
    }
}

impl Layout {
    /// The NGINX root and the access log the host settings name
    /// ([`crate::hostconf`]); from the database's rows only while there is
    /// no host settings file yet, which is a database from before it.
    fn stored_host_settings(&self) -> (Option<String>, Option<String>) {
        let host_conf = if self.real {
            crate::hostconf::path()
        } else {
            self.output_dir.join("host.conf")
        };
        if std::fs::symlink_metadata(&host_conf).is_ok() {
            let host = crate::hostconf::HostConf::load_from(&host_conf).unwrap_or_default();
            let text = |path: Option<PathBuf>| path.map(|path| path.display().to_string());
            return (text(host.nginx_root), text(host.access_log));
        }
        (
            stored_setting_at(&self.db_path, crate::db::keys::NGINX_ROOT),
            stored_setting_at(&self.db_path, crate::db::keys::LOGS_ACCESS_PATH),
        )
    }
}

/// One setting from the database at `db_path`, without creating,
/// migrating or writing it. `None` for no database, no such row, an empty
/// value, or a database this cannot read — in every one of those cases
/// the service falls back to the stock paths, which the unit always
/// allows.
fn stored_setting_at(db_path: &Path, key: &str) -> Option<String> {
    use rusqlite::OpenFlags;
    if !db_path.is_file() {
        return None;
    }
    // Not READ_ONLY, for the reason `uninstall` gives: a read-only
    // connection to a WAL database creates `-wal` and `-shm` and then
    // cannot delete them. Nor `Db::open`, which would migrate. Guarded:
    // this is root, in what is by now the console's directory.
    let conn = crate::db::guard::open_connection(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    // A running console may be mid-write.
    conn.busy_timeout(std::time::Duration::from_secs(5)).ok()?;
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    })
    .ok()
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

/// Every path the root helper writes, in the order its unit lists them.
/// (Until 0.1 the console wrote them itself, as root; the list moved with
/// the writes.)
///
/// What each one is for:
///
/// - the state directory: the database, and SQLite's `-wal` and `-shm`
///   beside it, and the `.bak-v*` copy an upgrade makes there;
/// - `/etc/stop-bots`: the firewall scripts and `nginx/` (`robots.txt`);
/// - `/etc/nginx`, and the root the service manages if that is elsewhere:
///   the site files it injects blocks into and the `conf.d` files it
///   generates, including Web Access's;
/// - `/var/log/nginx`, and every other log directory ([`nginx_log_dirs`]):
///   `nginx -t` opens every log the config names for writing, and fails the
///   test on one it cannot open;
/// - `/run`, whole. `nginx -t` creates `/run/nginx.pid`, and granting just
///   that file does not work: a grant is a bind mount of that one inode,
///   NGINX deletes and recreates the file whenever it restarts, and the
///   next `nginx -t` fails on a read-only `/run` until the helper is
///   restarted too. `/run` is also where the apply lock is
///   ([`crate::applylock`]) and where legacy `iptables` takes
///   `xtables.lock`. It is a tmpfs, so nothing written there outlives a
///   boot, and what it could otherwise offer is systemd, which the helper
///   reaches over D-Bus regardless.
///
/// Every one is optional (`-`): a missing path is skipped instead of
/// failing the start with `226/NAMESPACE`, because the console is most
/// worth reaching when something on the host is not where it should be.
/// A path inside one already listed is left out, and so is a relative one,
/// which systemd would reject.
pub fn writable_paths(layout: &Layout) -> Vec<PathBuf> {
    let mut candidates = vec![
        layout.state_dir.clone(),
        layout.output_dir.clone(),
        layout.nginx_dir.clone(),
    ];
    candidates.extend(layout.nginx_roots.iter().cloned());
    candidates.push(layout.nginx_log_dir.clone());
    candidates.extend(layout.log_dirs.iter().cloned());
    candidates.push(layout.run_dir.clone());

    let mut paths: Vec<PathBuf> = Vec::new();
    for path in candidates {
        if path.is_absolute() && !paths.iter().any(|listed| path.starts_with(listed)) {
            paths.push(path);
        }
    }
    paths
}

/// The directories the `access_log` and `error_log` directives under
/// `roots` write in, other than ones this would never grant.
///
/// `nginx -t` opens every log the config names for writing, so a site
/// logging to `/srv/www/example.com/logs` fails the console's test — and
/// the apply is rolled back — unless the unit gives that directory back.
/// Read from the config as it is at install time; a site added later that
/// logs somewhere new needs `install web` run again, which replaces an
/// unedited unit silently.
///
/// Only an absolute path, only the part before any `$variable`, and only
/// a [`grantable`] one: whoever can edit the NGINX config must not be able
/// to use this to have the next `install web` open `/etc` or `/usr` to
/// the console.
pub fn nginx_log_dirs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for root in roots {
        for file in config_files(root) {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            for dir in log_dirs_in(&text) {
                if !dirs.contains(&dir) {
                    dirs.push(dir);
                }
            }
        }
    }
    dirs
}

/// Where a compromised console must never be given write access, and so
/// no log directory may be in or above.
const NEVER_WRITABLE: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/boot",
    "/opt",
    "/root",
    "/home",
    "/var/spool",
    "/var/lib",
    "/var/cache",
    "/var/backups",
    "/proc",
    "/sys",
    "/dev",
];

/// Whether a directory the console itself could have named — in its
/// database or in the NGINX config it writes — may be given back to it.
///
/// Those two are exactly what a compromised console controls, so without
/// this the next `install web` an operator runs would launder a stored
/// root of `/etc` into `ReadWritePaths=-/etc`. A path the operator typed
/// (`--root`) or a 0.0.x unit named is not checked: that is their call.
fn grantable(dir: &Path) -> bool {
    dir.is_absolute()
        && dir.parent().is_some()
        && !NEVER_WRITABLE.iter().any(|never| {
            let never = Path::new(never);
            dir.starts_with(never) || never.starts_with(dir)
        })
}

/// The directories the log directives in one config file name.
fn log_dirs_in(text: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word != "access_log" && word != "error_log" {
                continue;
            }
            let Some(target) = words.next() else { break };
            let target = target.trim_end_matches(';').trim_matches(['"', '\'']);
            // `/var/log/nginx/$host.log` writes somewhere in the part before
            // the first variable; `off`, `syslog:` and `stderr` nowhere.
            let dir = match target.find('$') {
                Some(at) => target[..at]
                    .rfind('/')
                    .map(|slash| Path::new(&target[..=slash])),
                None => Path::new(target).parent(),
            };
            let Some(dir) = dir else { continue };
            if grantable(dir) {
                dirs.push(dir.components().collect());
            }
        }
    }
    dirs
}

/// Every regular file under `root`, a few levels deep, without following
/// a link to a directory — NGINX's own tree links `sites-enabled` into
/// `sites-available`, whose files are listed anyway.
fn config_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() && depth < 4 {
                pending.push((path, depth + 1));
            } else if std::fs::metadata(&path)
                .is_ok_and(|meta| meta.is_file() && meta.len() < 1 << 20)
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// One optional `ReadWritePaths=` entry: `-` and the path, quoted and
/// escaped the way systemd parses that directive.
///
/// Not [`systemd_arg`]: this directive expands `%` specifiers but not `$`
/// variables, so `$` stays as it is. Quoted as one word, dash included, so
/// the dash is still the first character once systemd has unquoted it.
/// Checked against systemd 257, which read `"-/srv/a b"`, `"-/srv/c\"d"`,
/// `"-/srv/e\\f"`, `-/srv/p%%q` and `-/srv/d$x` back as the directories
/// they name.
fn read_write_path(path: &Path) -> String {
    systemd_word(&format!("-{}", path.to_string_lossy()), false)
}

/// What the caller asked for, beyond the paths.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Report every step and change nothing.
    pub dry_run: bool,
    /// Replace a unit file that exists and differs.
    pub force: bool,
    /// `systemctl enable --now` after installing. Off means the unit is
    /// written and enabled but not started.
    pub start: bool,
}

/// A `stop-bots` that lives in a build directory.
///
/// The most likely way to end up with a unit that works today and breaks
/// on the next `cargo clean`: `sudo cargo run -- install web` resolves
/// `current_exe()` to `target/debug/stop-bots`, writes that into
/// `ExecStart`, and nothing complains until the binary is gone.
pub fn is_build_artifact(binary: &Path) -> bool {
    let mut components = binary.components().peekable();
    while let Some(component) = components.next() {
        if component.as_os_str() != "target" {
            continue;
        }
        if let Some(next) = components.peek() {
            let next = next.as_os_str();
            if next == "debug" || next == "release" {
                return true;
            }
        }
    }
    false
}

/// Why the unit's own sandbox would not be able to see `binary`, if it
/// would not — named as the directive responsible.
///
/// [`preflight`] checking `binary.is_file()` is not the same question as
/// "can systemd execute this", because `ExecStart` is resolved inside the
/// mount namespace [`web_unit`] asks for, and that is a different
/// filesystem from the installer's:
///
/// - `ProtectHome=yes` replaces `/root`, `/home` and `/run/user` with
///   empty directories.
/// - `PrivateTmp=yes` gives the service a fresh `/tmp` and `/var/tmp`.
///
/// A binary in any of those exists for the installer and does not exist
/// for systemd. The failure is `status=203/EXEC` with `Unable to locate
/// executable: No such file or directory` — which sends whoever reads it
/// hunting for a missing file that is plainly, verifiably there. Reported
/// here in terms of what to do about it instead.
///
/// Found the hard way: `./stop-bots install web` run from `/root`, which
/// is exactly where someone who just downloaded a release binary is
/// standing.
pub fn hidden_from_unit(binary: &Path) -> Option<&'static str> {
    let path = binary.to_string_lossy();
    // Prefix matching on the path as written. `ExecStart` names this path
    // verbatim, so what matters is the literal string systemd will resolve
    // — not what it might canonicalise to.
    for prefix in ["/root/", "/home/", "/run/user/"] {
        if path.starts_with(prefix) {
            return Some("ProtectHome=yes");
        }
    }
    for prefix in ["/tmp/", "/var/tmp/"] {
        if path.starts_with(prefix) {
            return Some("PrivateTmp=yes");
        }
    }
    None
}

/// What to tell an operator whose binary the unit's sandbox would hide.
///
/// Pure and separately tested, because the *message* is the entire value
/// of this check: systemd's own report (`status=203/EXEC`, "No such file or
/// directory") is accurate and useless, and the thing that saves an
/// afternoon is naming the directive and giving a command to paste.
fn hidden_binary_error(binary: &Path, directive: &str) -> String {
    format!(
        "{} exists, but the unit sets {}, which hides that directory from the \
         service — systemd would fail with `status=203/EXEC` and \"No such file \
         or directory\" for a file that is plainly there.\n\n\
         Copy the binary somewhere the service can see, then re-run:\n\n    \
         install -m 755 {} /usr/local/bin/stop-bots\n    \
         /usr/local/bin/stop-bots install web\n\n\
         Or pass --binary with a path outside /root, /home and /tmp if the \
         binary already lives somewhere else.",
        binary.display(),
        directive,
        binary.display(),
    )
}

/// The header every unit `install web` writes opens with.
fn web_header(generated_by: &str) -> String {
    format!(
        "# {generated_by}, with `stop-bots install web`.\n\
         #\n\
         # Re-running that command replaces this file for as long as it is\n\
         # unedited: the stop-bots-template line is a hash of everything else\n\
         # here, and is how it tells. An edited copy is left alone, and the\n\
         # installer says so; `--force` replaces it anyway.\n"
    )
}

/// The resource limits both the console and the helper run under.
const YIELD_TO_THE_HOST: &str = "\
# stop-bots is here to protect the sites on this host, so it must never be\n\
# what starves them: a detector pass or a firewall render on a busy host\n\
# holds tens of megabytes, on a machine that may have 1 GB in all. Lower\n\
# CPU and I/O priority than NGINX, so that work waits for a quiet moment\n\
# rather than competing.\n\
Nice=10\n\
IOSchedulingClass=idle\n\
# MemoryHigh throttles and reclaims; it never kills. Past it the service\n\
# slows down, which background work can afford. MemoryMax is only the\n\
# backstop for a runaway: at that point the kernel stops this service\n\
# rather than choosing a victim host-wide. Percentages are of physical\n\
# RAM: 256 MB and 512 MB on a 1 GB VPS, and more on a machine that has it.\n\
MemoryHigh=25%\n\
MemoryMax=50%\n\
# A descriptor per connection: the default soft limit of 1024 ran out at\n\
# about 1,100 held connections. TasksMax bounds threads and child\n\
# processes together, well above the 512 blocking threads tokio may use.\n\
LimitNOFILE=16384\n\
TasksMax=1024\n";

/// The console's unit: the web console, as the `stop-bots` user, with
/// nothing of root's.
///
/// Pure, and takes every path it names — so the golden test locks the
/// bytes an operator will actually get rather than a rendering of them.
///
/// What it can do is what a logged-in operator can do: everything else
/// it asks of the helper over [`Layout::helper_socket`], and the helper
/// treats what it is asked, and the database, as hostile. What it cannot
/// do is the point of the unit, and the container suite checks each one
/// under real systemd:
///
/// - write anywhere but its database (`ProtectSystem=strict`, and one
///   `ReadWritePaths=`), and it could not anyway: it is not root;
/// - hold or gain a capability (`CapabilityBoundingSet=` empty,
///   `NoNewPrivileges=`);
/// - load firewall rules (no `AF_NETLINK`, no `CAP_NET_ADMIN`);
/// - ask systemd for anything: polkit refuses an unprivileged caller, and
///   `InaccessiblePaths=` hides the D-Bus and systemd sockets as well;
/// - map memory writable and executable, or make a system call outside
///   `@system-service`.
pub fn web_unit(layout: &Layout) -> String {
    let mut exec = format!(
        "{} web --db {}",
        systemd_arg(&layout.binary),
        systemd_arg(&layout.db_path),
    );
    // Only when the operator named one. Omitting the flag is what leaves
    // the service free to try the log files and then `journalctl`; naming
    // a path here would pin it to that path forever, including on the
    // hosts that do not have it. See `Layout::ssh_log`.
    if let Some(path) = &layout.ssh_log {
        exec.push_str(&format!(" --ssh-log {}", systemd_arg(path)));
    }
    exec.push_str(&format!(
        " --helper {}\n",
        systemd_arg(&layout.helper_socket)
    ));
    let groups = match layout.log_groups.as_slice() {
        [] => String::new(),
        groups => format!("SupplementaryGroups={}\n", groups.join(" ")),
    };

    seal(&format!(
        "{header}\
         #\n\
         # Settings deliberately absent from ExecStart: the bind address, the host\n\
         # allowlist, the path prefix and whether exposure is permitted live in the\n\
         # `settings` table, because the running server re-reads them. Adding a flag\n\
         # for one here gives it two sources of truth and the database wins on the\n\
         # next restart. Change them with `stop-bots set-web ...`.\n\
         [Unit]\n\
         Description=stop-bots web console\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         # Wants rather than Requires for NGINX: the console is most worth looking\n\
         # at when NGINX is down, so it must not be stopped along with it. Requires\n\
         # for the helper's socket: without it the console can show, not apply.\n\
         After=network-online.target nginx.service {HELPER_SOCKET_UNIT}\n\
         Wants=network-online.target\n\
         Requires={HELPER_SOCKET_UNIT}\n\
         \n\
         [Service]\n\
         Type=exec\n\
         ExecStart={exec}\
         Restart=on-failure\n\
         RestartSec=5s\n\
         \n\
         # Not root. Everything that needs root -- writing the NGINX config and\n\
         # the firewall script, `nginx -t`, the reload, nft -- the console asks of\n\
         # {HELPER_UNIT} over the socket above, which takes a fixed set of\n\
         # operations and no paths, commands or config text. Code running as this\n\
         # service runs as {user}, not as root.\n\
         User={user}\n\
         Group={user}\n\
         # The logs the detectors read: /var/log/nginx and auth.log belong to adm,\n\
         # the journal to systemd-journal. Here rather than in /etc/group, so the\n\
         # membership holds for this service and nothing else running as {user}.\n\
         {groups}\
         \n\
         # It writes its database and nothing else, holds no capability and can\n\
         # gain none, cannot reach netlink to change the firewall, and cannot see\n\
         # the sockets it would ask systemd anything over -- polkit refuses an\n\
         # unprivileged caller anyway; hiding them is defence in depth.\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         ReadWritePaths={state}\n\
         ProtectHome=yes\n\
         PrivateDevices=yes\n\
         ProtectClock=yes\n\
         ProtectHostname=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         SystemCallFilter=@system-service\n\
         SystemCallErrorNumber=EPERM\n\
         CapabilityBoundingSet=\n\
         # AF_UNIX for the helper's socket and journalctl, AF_INET/AF_INET6 for the\n\
         # console itself and the list downloads.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
         InaccessiblePaths=-/run/dbus/system_bus_socket -/run/systemd/private\n\
         # The database holds the console's password hash.\n\
         UMask=0077\n\
         \n\
         {yield_to_the_host}\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        header = web_header(&crate::generated::generated_by()),
        user = layout.user,
        state = read_write_path(&layout.state_dir),
        yield_to_the_host = YIELD_TO_THE_HOST,
    ))
}

/// The socket the console reaches the helper on.
///
/// Root's, in the console's group, `0660`: the console can connect and
/// nobody else on the host can. The helper checks each peer's uid as well
/// (`SO_PEERCRED`), so a mode loosened by hand still lets no one else in.
/// One listening socket handed to one long-running helper (`Accept=no`).
pub fn helper_socket_unit(layout: &Layout) -> String {
    seal(&format!(
        "{header}\
         [Unit]\n\
         Description=stop-bots root helper socket\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         \n\
         [Socket]\n\
         ListenStream={socket}\n\
         SocketUser=root\n\
         SocketGroup={user}\n\
         SocketMode=0660\n\
         DirectoryMode=0755\n\
         Accept=no\n\
         \n\
         [Install]\n\
         WantedBy=sockets.target\n",
        header = web_header(&crate::generated::generated_by()),
        // A socket path takes the rest of the line, unquoted; it does
        // expand specifiers.
        socket = layout
            .helper_socket
            .display()
            .to_string()
            .replace('%', "%%"),
        user = layout.user,
    ))
}

/// The root helper, started by [`helper_socket_unit`] when the console
/// first connects.
///
/// The sandbox the console had while it ran as root, because it now does
/// what the console did then: `ProtectSystem=strict` with the paths it
/// writes given back ([`writable_paths`]), and the capabilities applying
/// takes. It binds nothing, so not `CAP_NET_BIND_SERVICE`. Its address
/// families are the console's old ones, and none fewer: `AF_INET` and
/// `AF_INET6` look like a helper with no business on a network, but
/// `nginx -t`, which runs inside this unit, opens a socket for every
/// `listen` it checks and resolves host names in `proxy_pass`, and fails
/// with "Address family not supported by protocol" without them — the
/// container suite watched it. No `[Install]`: the socket is what is
/// enabled.
pub fn helper_unit(layout: &Layout) -> String {
    let writable: String = writable_paths(layout)
        .iter()
        .map(|path| format!("ReadWritePaths={}\n", read_write_path(path)))
        .collect();
    seal(&format!(
        "{header}\
         [Unit]\n\
         Description=stop-bots root helper\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         Requires={HELPER_SOCKET_UNIT}\n\
         After={HELPER_SOCKET_UNIT}\n\
         \n\
         [Service]\n\
         Type=exec\n\
         ExecStart={binary} helper --db {db}\n\
         \n\
         # Root, and has to be: it rewrites this host's NGINX config, writes the\n\
         # firewall script, and runs `nginx -t`, the reload and nft. It takes\n\
         # requests only from root and the console's user, and only a fixed set\n\
         # of operations, none of which carries a path, a command or config\n\
         # text. ProtectSystem=strict and ReadWritePaths= keep it to the files\n\
         # it writes: the database, /etc/stop-bots, the NGINX config, the NGINX\n\
         # logs (`nginx -t` opens them for writing), and /run (`nginx -t`\n\
         # creates /run/nginx.pid, which NGINX replaces whenever it restarts, so\n\
         # granting that one file stops working after the next restart). Cron,\n\
         # the systemd units and every binary stay out of reach. `-`: a missing\n\
         # path is skipped, rather than keeping the helper from starting.\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=strict\n\
         {writable}\
         ProtectHome=yes\n\
         PrivateDevices=yes\n\
         ProtectClock=yes\n\
         ProtectHostname=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         # CAP_NET_ADMIN and CAP_NET_RAW to load the firewall. CAP_DAC_OVERRIDE\n\
         # because the logs it reads and `nginx -t` opens belong to www-data and\n\
         # adm, and the database to the console's user. CAP_CHOWN and CAP_FOWNER\n\
         # because a site file keeps its owner and mode when it is rewritten, and\n\
         # because SQLite gives a -wal it creates to the database's owner. Nothing\n\
         # else, and above all not CAP_SYS_ADMIN, with which root can remount what\n\
         # ProtectSystem made read-only.\n\
         CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER\n\
         # AF_UNIX for the console's requests, the D-Bus socket `systemctl reload\n\
         # nginx` talks over and a Docker socket for `docker exec`; AF_NETLINK\n\
         # because both `nft` and Debian's nft-backed `iptables` reach the kernel\n\
         # over netlink. AF_INET and AF_INET6 not for downloads -- it makes none --\n\
         # but for `nginx -t`, which opens a socket for every `listen` and fails\n\
         # without them.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\
         UMask=0077\n\
         \n\
         {yield_to_the_host}\
         # Also absent on purpose: SystemCallFilter=, because the NGINX commands\n\
         # this runs are the operator's (`docker exec ...`) and untested under a\n\
         # filter.\n",
        header = web_header(&crate::generated::generated_by()),
        binary = systemd_arg(&layout.binary),
        db = systemd_arg(&layout.db_path),
        yield_to_the_host = YIELD_TO_THE_HOST,
    ))
}

/// `body` with its [`TEMPLATE_MARKER`] line added after the first line.
///
/// The hash covers everything else, the `Generated by` line and so the
/// version included, so it needs nothing but the file to check: see
/// [`is_sealed_and_unedited`].
fn seal(body: &str) -> String {
    let (first, rest) = body.split_once('\n').expect("a unit is more than one line");
    format!("{first}\n{TEMPLATE_MARKER}{}\n{rest}", sha256_hex(body))
}

/// Whether `text` carries a [`TEMPLATE_MARKER`] and still hashes to it —
/// that is, whether it is exactly as some version of stop-bots wrote it.
fn is_sealed_and_unedited(text: &str) -> bool {
    let mut recorded = None;
    let mut body = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match line.strip_prefix(TEMPLATE_MARKER) {
            Some(hash) if recorded.is_none() => recorded = Some(hash.trim_end()),
            _ => body.push_str(line),
        }
    }
    recorded.is_some_and(|hash| hash == sha256_hex(&body))
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// What is already at a unit's path, as far as replacing it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// Nothing there.
    Missing,
    /// Byte for byte what this would write.
    Current,
    /// Exactly as stop-bots wrote it — `by` says which version — so it may
    /// be replaced without asking.
    Unedited { by: String },
    /// Changed since stop-bots wrote it, or not written by stop-bots.
    Edited,
}

/// Classifies `existing` against `new`, the unit this run would write.
/// `legacy` recognises what 0.0.x wrote, which carries no hash, and
/// returns the releases that could have.
pub fn classify(
    existing: Option<&str>,
    new: &str,
    legacy: impl Fn(&str) -> Option<&'static str>,
) -> Existing {
    let Some(existing) = existing else {
        return Existing::Missing;
    };
    if existing == new {
        return Existing::Current;
    }
    if is_sealed_and_unedited(existing) {
        let by = match crate::generated::version_in(existing) {
            Some(version) => format!("stop-bots {version}"),
            None => "stop-bots".to_string(),
        };
        return Existing::Unedited { by };
    }
    match legacy(existing) {
        Some(releases) => Existing::Unedited {
            by: format!("stop-bots {releases}"),
        },
        None => Existing::Edited,
    }
}

/// Refuses an [`Existing::Edited`] unit unless `force`, and otherwise says
/// what will happen to it. Shared by both units, so they cannot drift.
fn plan_unit(state: &Existing, path: &Path, force: bool, retry: &str) -> Result<String> {
    Ok(match state {
        Existing::Missing => format!("write {}", path.display()),
        Existing::Current => format!("{} is already up to date", path.display()),
        Existing::Unedited { by } => {
            format!("replace {} (unedited since {by} wrote it)", path.display())
        }
        Existing::Edited if force => format!("replace {} (--force)", path.display()),
        Existing::Edited => anyhow::bail!(
            "{} has been edited since stop-bots wrote it, so this stopped rather than \
             replace your edit.\n\n\
             Pass --force to replace it anyway. `{retry} --dry-run` prints the plan \
             without changing anything.",
            path.display(),
        ),
    })
}

/// `path` as one argument of an `ExecStart=` line.
///
/// systemd does not hand `ExecStart` to a shell; it splits it itself, by
/// the rules in systemd.syntax(7) and systemd.service(5), and they differ
/// from a shell's in the two places that matter here:
///
/// - `%` starts a specifier (`%h`, `%n`, ...) and is expanded everywhere,
///   quoted or not, so a literal one is `%%`. `$` likewise starts a
///   variable, and a literal one is `$$`.
/// - An argument is split on whitespace unless double-quoted, and inside
///   the quotes `\` and `"` are C-style escapes.
///
/// So a path with a space used to become two arguments — the binary
/// named `/opt/stop` — and one with `%` had part of it replaced. An
/// ordinary path comes back unchanged, which keeps the golden unit the
/// bytes it always was.
fn systemd_arg(path: &Path) -> String {
    systemd_word(&path.to_string_lossy(), true)
}

/// `raw` as one word of a unit file line: quoted if it has to be, with
/// `%` as `%%`, and `$` as `$$` where the directive expands variables.
fn systemd_word(raw: &str, escape_dollar: bool) -> String {
    let needs_quotes = raw
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'));
    let mut out = String::with_capacity(raw.len() + 2);
    if needs_quotes {
        out.push('"');
    }
    for c in raw.chars() {
        match c {
            '%' => out.push_str("%%"),
            '$' if escape_dollar => out.push_str("$$"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let mut bytes = [0u8; 4];
                for byte in c.encode_utf8(&mut bytes).bytes() {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
            c => out.push(c),
        }
    }
    if needs_quotes {
        out.push('"');
    }
    out
}

/// One thing the installer did, or would do under `--dry-run`.
///
/// Returned rather than printed so that the test asserts on the same list
/// the operator reads, instead of on side effects that have to be
/// rediscovered from the filesystem.
pub type Steps = Vec<String>;

/// Everything that must hold before a single byte is written.
///
/// Separate from [`install_web`] and run first, in full: a check that
/// fails after the directories exist leaves a half-install, which is worse
/// than no install because it looks finished.
pub fn preflight(layout: &Layout, options: &Options) -> Result<()> {
    if !layout.systemd_marker.is_dir() {
        anyhow::bail!(
            "this host is not running systemd ({} does not exist), and the only \
             service manager `install web` knows how to write for is systemd.\n\n\
             Run the console under whatever this host does use, with:\n\n    \
             {} web",
            layout.systemd_marker.display(),
            layout.binary.display()
        );
    }

    if !layout.debian_marker.exists() {
        anyhow::bail!(
            "this does not look like Debian ({} does not exist).\n\n\
             The unit `install web` writes is almost certainly correct on any \
             systemd distribution — it names no distribution-specific path, and \
             the service finds its own logs at runtime — but nobody has run it \
             anywhere else. Write the unit by hand, or open an issue saying \
             which distribution this is.",
            layout.debian_marker.display(),
        );
    }

    // Before `is_file`, because a relative path can be a real file and
    // still produce a unit systemd refuses outright: it requires an
    // absolute `ExecStart`, and rejects the unit at load time rather than
    // at start time, which is a different and more confusing failure.
    // Reachable only via `--binary`; `current_exe` is always absolute.
    if !layout.binary.is_absolute() {
        anyhow::bail!(
            "--binary needs an absolute path, and {} is relative. systemd \
             requires an absolute ExecStart and would refuse to load the unit \
             at all.\n\n\
             Did you mean:\n\n    --binary {}",
            layout.binary.display(),
            std::env::current_dir()
                .map(|cwd| cwd.join(&layout.binary))
                .unwrap_or_else(|_| layout.binary.clone())
                .display()
        );
    }

    if !layout.binary.is_file() {
        anyhow::bail!(
            "{} is not a file, so the unit's ExecStart would point at nothing",
            layout.binary.display()
        );
    }

    // After the `is_file` check, and a different question: that one asks
    // the installer's filesystem, this one asks the unit's. See
    // `hidden_from_unit`.
    if let Some(directive) = hidden_from_unit(&layout.binary).filter(|_| layout.real) {
        anyhow::bail!("{}", hidden_binary_error(&layout.binary, directive));
    }

    // Checked by trying, not by comparing euid to 0: what matters is
    // whether this process can write there, and a root-in-a-container or
    // CAP_DAC_OVERRIDE case answers that differently from `id -u`.
    if !options.dry_run {
        writable(&layout.unit_dir).with_context(|| {
            format!(
                "cannot write to {} — `install web` needs root. Run it with sudo \
                 (`sudo stop-bots install web --dry-run` shows the plan first)",
                layout.unit_dir.display()
            )
        })?;
    }

    Ok(())
}

/// Whether this process can create a file in `dir`, answered by doing it.
fn writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let probe = dir.join(".stop-bots-install-probe");
    std::fs::write(&probe, b"").with_context(|| format!("writing {}", probe.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// The systemd unit that re-applies `script` at boot.
///
/// `After=` names the two services whose rules this must not race. Docker
/// rewrites its chains on every start, and ufw loads its own tables; a
/// script applied before either is still there afterwards, because it uses
/// its own table and never flushes the ruleset, but ordering after them
/// keeps the boot-time sequence the same as the one an operator sees by
/// hand. `Wants=network-online.target` rather than `Requires=`: a ruleset
/// is worth loading even on a host that came up without a network.
///
/// `backend` decides both the script and what runs it, for the reason
/// `firewall::output_path` gives: the backend is the one source of truth,
/// and a host rendering iptables has a `firewall.nft` that is stale or
/// absent. A boot unit that always loaded that file restored the wrong
/// rules, or none.
///
/// **Sandboxed harder than the console**, because whatever the script says
/// runs as root at every boot, the console writes it, and loading rules is
/// all it is for. No writes, no capability beyond the network, and no
/// `AF_UNIX` — the socket family root would use to ask systemd to run
/// something outside the sandbox. Under nftables that leaves a compromised
/// script able to change the firewall and nothing else; `nft -f` has no
/// way to run a command at all.
///
/// The iptables script is a shell script, and needs two concessions for
/// `iptables-legacy`, which a host may have selected: it fails outright
/// without `/run/xtables.lock`, which it cannot create once `/run` is
/// read-only, so the unit creates it first, outside the sandbox (only
/// creating it needs a writable `/run`; it opens an existing one read-only,
/// and `flock` needs no more); and it runs `modprobe` itself
/// when `ip_tables` is not loaded yet, early in a boot, so it keeps
/// `CAP_SYS_MODULE`. `iptables-nft`, Debian's default, needs neither, but
/// the unit cannot know which one `iptables` will be.
pub fn firewall_unit(backend: crate::firewall::FirewallBackend, script: &Path) -> String {
    let (exec, backend_sandbox) = match backend {
        crate::firewall::FirewallBackend::Nftables => (
            format!("/usr/sbin/nft -f {}", systemd_arg(script)),
            "ProtectKernelModules=yes\n\
             CapabilityBoundingSet=CAP_NET_ADMIN\n",
        ),
        crate::firewall::FirewallBackend::Iptables => (
            format!("/bin/sh {}", systemd_arg(script)),
            "# iptables-legacy refuses to run without its lock file and cannot\n\
             # create one in a read-only /run, but only reads one that is there;\n\
             # `+` creates it outside the sandbox. It also runs modprobe itself\n\
             # when ip_tables is not loaded yet.\n\
             ExecStartPre=+/usr/bin/touch /run/xtables.lock\n\
             CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE\n",
        ),
    };
    seal(&format!(
        "# {generated_by}, with `stop-bots install firewall`.\n\
         #\n\
         # Re-running that command replaces this file for as long as it is\n\
         # unedited: the stop-bots-template line is a hash of everything else\n\
         # here, and is how it tells. An edited copy is left alone, and the\n\
         # installer says so; `--force` replaces it anyway.\n\
         #\n\
         # Deliberately NOT nftables.service: that unit loads /etc/nftables.conf,\n\
         # which is not this file, so it would restore a different ruleset entirely\n\
         # -- and on a stock Debian or Ubuntu it would also `flush ruleset` at boot,\n\
         # dropping whatever else manages tables on this host.\n\
         [Unit]\n\
         Description=Apply the stop-bots firewall ruleset\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         After=docker.service ufw.service network-online.target\n\
         Wants=network-online.target\n\
         ConditionPathExists={script}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart={exec}\n\
         \n\
         # The script runs as root at every boot and the console writes it, so\n\
         # this may load rules and do nothing else: every path read-only, only\n\
         # the capabilities loading rules takes, and no AF_UNIX, which is how\n\
         # root would ask systemd to run something outside this sandbox.\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectClock=yes\n\
         ProtectHostname=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6\n\
         {backend_sandbox}\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        generated_by = crate::generated::generated_by(),
        // A condition takes the rest of the line as the path, so it is not
        // quoted; it does expand specifiers, so `%` still has to be `%%`.
        script = script.display().to_string().replace('%', "%%")
    ))
}

/// The backend the database at `db_path` renders for, without creating a
/// database that is not there: an install, and above all a `--dry-run`,
/// has no business leaving one behind. No database means nothing has
/// chosen a backend yet, which is the default's case in
/// `firewall::stored_backend` too.
fn stored_backend_at(db_path: &Path) -> Result<crate::firewall::FirewallBackend> {
    if !db_path.is_file() {
        return Ok(crate::firewall::FirewallBackend::Nftables);
    }
    let db = crate::db::Db::open(db_path)
        .with_context(|| format!("reading the firewall backend from {}", db_path.display()))?;
    crate::firewall::stored_backend(&db)
}

/// Writes [`firewall_unit`] and enables it. Mirrors [`install_web`],
/// including its refusal to overwrite a unit somebody has edited.
///
/// Under `--prefix` it writes the unit and stops, as `install web` does:
/// the unit is somewhere systemd never looks, and running the real
/// `systemctl daemon-reload`/`enable` would either claim a unit took
/// effect that did not, or enable a stale one of the same name.
pub fn install_firewall(layout: &Layout, options: &Options) -> Result<Steps> {
    let backend = stored_backend_at(&layout.db_path)?;
    let script = crate::firewall::default_output_path(backend);
    let unit = firewall_unit(backend, &script);
    let unit_path = layout.unit_dir.join(FIREWALL_UNIT);
    let existing = std::fs::read_to_string(&unit_path).ok();
    let state = classify(existing.as_deref(), &unit, legacy::firewall_unit);
    let retry = format!("{} install firewall", layout.binary.display());

    let mut steps = Steps::new();
    steps.push(plan_unit(&state, &unit_path, options.force, &retry)?);
    if !options.dry_run && state != Existing::Current {
        (|| -> Result<()> {
            if let Some(parent) = unit_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&unit_path, &unit)
                .with_context(|| format!("writing {}", unit_path.display()))
        })()
        .map_err(crate::hint::sudo_if_denied)?;
    }

    // Not started. The script may not exist yet, and starting a unit that
    // loads firewall rules is the one step an operator should take after
    // reading what it would load -- the same reason `render-firewall` only
    // applies what it writes when asked to.
    if layout.real {
        steps.push("systemctl daemon-reload".to_string());
        steps.push(format!("systemctl enable {FIREWALL_UNIT}"));
        if !options.dry_run {
            systemctl(layout, &["daemon-reload"])?;
            systemctl(layout, &["enable", FIREWALL_UNIT])?;
        }
    } else {
        steps.push(format!(
            "skipping systemctl: {} is not a path systemd reads",
            layout.unit_dir.display()
        ));
    }
    // `render-firewall --apply` rather than `nft -f <script>`: a script run
    // by hand is enforced now but never becomes what this unit loads, and
    // the one at `script` is only ever what was last applied.
    //
    // Which of the two things to say depends on whether an apply has
    // already happened. The README's quick start runs `batch --apply`
    // first, and telling that operator to go and apply what they just
    // applied read as if their rules had not taken.
    if layout.real && script.is_file() {
        steps.push(format!(
            "not started, and it need not be: {} holds the rules the last apply loaded, \
             and from the next boot on this unit loads it",
            script.display()
        ));
    } else {
        steps.push(format!(
            "not started: it loads {} at boot, which only an apply writes. Review the rules, \
             then run `stop-bots render-firewall --apply`: it checks for a lockout, runs the \
             script, and puts it there",
            script.display()
        ));
    }

    Ok(steps)
}

/// One unit `install web` writes: where, what, and what is there now.
struct PlannedUnit {
    path: PathBuf,
    text: String,
    state: Existing,
}

/// Writes the three units, the console's user, and the directories they
/// depend on.
///
/// Does not run `systemctl` — that is [`activate`], kept separate so the
/// filesystem half is testable without a service manager and so a
/// `--dry-run` can describe both without a special case in either.
///
/// The order is what keeps the console's directory the console's from the
/// first moment: the user exists before the state directory is given to
/// it, and the directory is given to it before the installer writes the
/// database there — so a database root creates is the console's from the
/// start (see [`crate::db::guard`]), and [`secure_database`] only has to
/// hand over what an earlier, root-run release left.
pub fn install_web(layout: &Layout, options: &Options) -> Result<Steps> {
    preflight(layout, options)?;

    // The helper's unit has to let it write wherever the database says the
    // NGINX config and its logs are, not only the stock paths.
    let host = layout.with_host_settings();
    let retry = format!("{} install web", layout.binary.display());

    // Refusing beats overwriting: a unit somebody has edited is a
    // decision. An unedited one, from this version or any earlier one, is
    // replaced; byte-identical is a no-op, which is what makes re-running
    // `install web` safe. Decided for all three before anything is written.
    let mut units = Vec::new();
    let mut unit_steps = Steps::new();
    for (name, text) in [
        (WEB_UNIT, web_unit(&host)),
        (HELPER_SOCKET_UNIT, helper_socket_unit(&host)),
        (HELPER_UNIT, helper_unit(&host)),
    ] {
        let path = layout.unit_dir.join(name);
        let existing = std::fs::read_to_string(&path).ok();
        let state = classify(existing.as_deref(), &text, |text| {
            // Only the console's unit predates the template hash.
            (name == WEB_UNIT)
                .then(|| legacy::web_unit(text).map(|unit| unit.releases))
                .flatten()
        });
        unit_steps.push(plan_unit(&state, &path, options.force, &retry)?);
        units.push(PlannedUnit { path, text, state });
    }

    let mut steps = Steps::new();
    let account = ensure_service_account(layout, options, &mut steps)?;

    for (dir, mode, owned) in [
        (&layout.state_dir, 0o700, true),
        (&layout.output_dir, 0o755, false),
    ] {
        if dir.is_dir() {
            steps.push(format!("{} already exists", dir.display()));
        } else {
            steps.push(format!("create {} ({mode:04o})", dir.display()));
            if !options.dry_run {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        if owned {
            steps.push(format!(
                "give {} to {user}:{user}, mode {mode:04o}",
                dir.display(),
                user = layout.user
            ));
        }
        // Set unconditionally, not only on create: 0700 on the state
        // directory is what keeps the password hash off a shared host, and
        // a directory that predates this (from a `stop-bots` run as root)
        // will be 0755.
        if !options.dry_run {
            match account.filter(|_| owned) {
                // Resolved first: the directory's own name is in /var/lib,
                // which is root's, so a link there is the operator's, and
                // only what is inside the directory is the console's.
                Some(account) => {
                    let dir = std::fs::canonicalize(dir)
                        .with_context(|| format!("resolving {}", dir.display()))?;
                    hand_over(&dir, account, mode)?
                }
                None => set_mode(dir, mode)?,
            }
        }
    }

    for (unit, step) in units.iter().zip(unit_steps) {
        steps.push(step);
        if !options.dry_run && unit.state != Existing::Current {
            std::fs::write(&unit.path, &unit.text)
                .with_context(|| format!("writing {}", unit.path.display()))?;
        }
    }

    Ok(steps)
}

/// The console's user and group, created if this host has neither, or
/// `None` where there is none to have: under `--prefix`, whose tree is not
/// this host's user database, and in a dry run that would have created
/// them.
///
/// `useradd --system`, from Debian's `passwd`, which every Debian and
/// Ubuntu has, rather than a `sysusers.d` file: that would be one more
/// file to own and remove, for a user `uninstall --purge` has to remove
/// with `userdel` either way. Its group comes with it; a group of that
/// name already there is used rather than refused.
///
/// An existing user is used as it is, unless it is root's uid or gid:
/// then the console would be root after all, and this refuses.
fn ensure_service_account(
    layout: &Layout,
    options: &Options,
    steps: &mut Steps,
) -> Result<Option<crate::account::Account>> {
    let name = layout.user.as_str();
    if !layout.real {
        steps.push(format!(
            "skipping the {name} user: {} is not this host's user database",
            layout.unit_dir.display()
        ));
        return Ok(None);
    }
    let lookup = || {
        crate::account::user(name)
            .zip(crate::account::group(name))
            .map(|(user, gid)| crate::account::Account { uid: user.uid, gid })
    };
    if lookup().is_none() {
        let mut commands: Vec<(&Path, Vec<String>)> = Vec::new();
        if crate::account::group(name).is_none() && crate::account::user(name).is_some() {
            commands.push((&layout.groupadd, vec!["--system".into(), name.into()]));
        }
        if crate::account::user(name).is_none() {
            let group = if crate::account::group(name).is_some() {
                vec!["--gid".to_string(), name.to_string()]
            } else {
                vec!["--user-group".to_string()]
            };
            let mut args = vec!["--system".to_string()];
            args.extend(group);
            args.extend([
                "--no-create-home".to_string(),
                "--home-dir".to_string(),
                layout.state_dir.display().to_string(),
                "--shell".to_string(),
                "/usr/sbin/nologin".to_string(),
                "--comment".to_string(),
                "stop-bots web console".to_string(),
                name.to_string(),
            ]);
            commands.push((&layout.useradd, args));
        }
        for (program, args) in commands {
            steps.push(format!("{} {}", name_of(program), args.join(" ")));
            if !options.dry_run {
                run_checked(program, &args)?;
            }
        }
        if options.dry_run {
            return Ok(None);
        }
    } else {
        steps.push(format!("the {name} user already exists"));
    }
    let account = lookup().with_context(|| {
        format!("created the {name} user and group, and the system still does not know them")
    })?;
    if account.uid == 0 || account.gid == 0 {
        anyhow::bail!(
            "the {name} user has uid {} and gid {}: the console would run as root after \
             all. Give it a system uid and group of its own, or remove it and run this \
             again to have one created.",
            account.uid,
            account.gid
        );
    }
    Ok(Some(account))
}

/// The console's user and group as the host knows them, or `None` under
/// `--prefix` or before [`install_web`] has created them.
pub fn service_account(layout: &Layout) -> Option<crate::account::Account> {
    if !layout.real {
        return None;
    }
    let user = crate::account::user(&layout.user)?;
    let gid = crate::account::group(&layout.user)?;
    Some(crate::account::Account { uid: user.uid, gid })
}

/// The name a program is known by, for a step.
fn name_of(program: &Path) -> String {
    program
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.display().to_string())
}

/// Runs `program` with `args`, never through a shell, and fails with its
/// stderr if it does.
fn run_checked(program: &Path, args: &[String]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{}`", program.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{} {}` exited with {}: {}",
            program.display(),
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Gives `path` to `account` with `mode`, through a descriptor opened
/// without following a link.
///
/// The console's directory is the console's to fill, so by the second
/// `install web` every name in it is one a compromised console could have
/// chosen: `chown` by path on a `db.sqlite3-wal` linked to `/etc/shadow`
/// hands `/etc/shadow` to the console. A link, a second name (a hard link
/// to someone else's file) or anything but a plain file or directory is
/// refused, and named.
fn hand_over(path: &Path, account: crate::account::Account, mode: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let file = crate::db::guard::open_nofollow(path)
        .with_context(|| {
            format!(
                "refusing to hand {} to the console's user: it could not be opened without \
                 following a link",
                path.display()
            )
        })?
        .with_context(|| format!("{} is not there", path.display()))?;
    let meta = file.metadata()?;
    if !(meta.is_dir() || (meta.is_file() && meta.nlink() == 1)) {
        anyhow::bail!(
            "refusing to hand {} to the console's user: it is not a plain file or directory",
            path.display()
        );
    }
    std::os::unix::fs::fchown(&file, Some(account.uid), Some(account.gid))
        .with_context(|| format!("giving {} to uid {}", path.display(), account.uid))?;
    crate::db::guard::fchmod(&file, mode)
        .with_context(|| format!("setting mode {mode:04o} on {}", path.display()))
}

/// Makes the database the console's, and private: its owner the console's
/// user under `account`, its mode 0600 either way. With it its `-wal`,
/// `-shm` and `-journal`, and every copy an upgrade kept (`.bak-v*`).
///
/// The state *directory* is already 0700, which is what actually keeps the
/// console's password hash off a shared host — but the file inside it is
/// created by whichever process got there first, under that process's
/// umask, and so is usually 0644. A mode travels with a file through a
/// backup or a `cp` in a way the directory it used to live in does not.
/// The `-wal` holds recently committed rows, the password hash included,
/// until they are checkpointed into the main file.
///
/// The owner is what an upgrade from 0.1.0-rc.2 needs: there everything
/// here was root's, and a console running as its own user could open none
/// of it. Every change goes through [`hand_over`], for the reason it
/// gives. Called after the installer's own writes, because the database
/// has to exist.
pub fn secure_database(path: &Path, account: Option<crate::account::Account>) -> Result<()> {
    for file in database_files(path) {
        match account {
            Some(account) => hand_over(&file, account, 0o600)?,
            None => {
                // Under `--prefix`, where there is no user to give it to,
                // still never through a link.
                if let Some(open) = crate::db::guard::open_nofollow(&file)
                    .with_context(|| format!("opening {}", file.display()))?
                {
                    crate::db::guard::fchmod(&open, 0o600)
                        .with_context(|| format!("setting mode 0600 on {}", file.display()))?;
                }
            }
        }
    }
    Ok(())
}

/// The database at `path`, its SQLite companions and the copies upgrades
/// kept beside it, as far as they exist.
fn database_files(path: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = crate::db::guard::with_companions(path)
        .into_iter()
        .filter(|file| std::fs::symlink_metadata(file).is_ok())
        .collect();
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return files;
    };
    let mut prefix = name.to_os_string();
    prefix.push(".bak-v");
    let prefix = prefix.to_string_lossy().into_owned();
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut copies: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect();
        copies.sort();
        files.extend(copies);
    }
    files
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode {mode:04o} on {}", path.display()))
}

/// Tells systemd about the units, and optionally starts them.
///
/// The helper's socket is enabled and started; the helper itself is not,
/// because systemd starts it at the console's first request. A helper
/// already running is restarted (`try-restart`), so it runs the binary
/// and unit just installed. The console is *restarted*, not merely
/// started: on an upgrade the old console is running, and `enable --now`
/// would leave it running — as root, if the old one was 0.1.0-rc.2's.
///
/// `systemctl` is run directly rather than through a shell, the same rule
/// [`crate::nginx`] follows for its configurable commands: nothing here is
/// operator-supplied, but the habit is what keeps it that way.
pub fn activate(layout: &Layout, options: &Options) -> Result<Steps> {
    let mut steps = Steps::new();
    let mut calls: Vec<&[&str]> = vec![&["daemon-reload"]];
    // `enable` without starting leaves the units set to start at the next
    // boot but not running, which is what --no-start is for.
    if options.start {
        calls.extend([
            &["enable", "--now", HELPER_SOCKET_UNIT][..],
            &["try-restart", HELPER_UNIT],
            &["enable", WEB_UNIT],
            &["restart", WEB_UNIT],
        ]);
    } else {
        calls.extend([&["enable", HELPER_SOCKET_UNIT][..], &["enable", WEB_UNIT]]);
    }
    for args in calls {
        steps.push(format!("systemctl {}", args.join(" ")));
        if !options.dry_run {
            systemctl(layout, args)?;
        }
    }
    Ok(steps)
}

fn systemctl(layout: &Layout, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(&layout.systemctl)
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "failed to run `{} {}`",
                layout.systemctl.display(),
                args.join(" ")
            )
        })?;
    if !output.status.success() {
        // `enable --now` is two operations, and the first one sticks even
        // when the second fails, as does an `enable` before a failed
        // `restart`: the unit ends up enabled, failing, and enabled again
        // at the next boot. Systemd's own start limit stops the restart
        // loop after a few tries, so this is untidy rather than dangerous —
        // but an operator reading this needs to be told the state they are
        // now in, and the one command that undoes it.
        let units: Vec<&str> = if args.contains(&"enable") || args.contains(&"restart") {
            match args.iter().find(|arg| arg.starts_with("stop-bots-")) {
                Some(&FIREWALL_UNIT) => vec![FIREWALL_UNIT],
                Some(_) => vec![WEB_UNIT, HELPER_SOCKET_UNIT],
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let cleanup = if units.is_empty() {
            String::new()
        } else {
            format!(
                "\n\nThe unit was written and enabled before this failed, so it will \
                 try again at the next boot. To undo that:\n\n    \
                 systemctl disable --now {}",
                units.join(" ")
            )
        };
        anyhow::bail!(
            "`systemctl {}` exited with {}: {}{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            cleanup
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout with no temp directory in it, so the golden file below is
    /// the bytes a real Debian host gets rather than a rendering of them.
    fn system_layout() -> Layout {
        Layout::system(PathBuf::from("/usr/local/bin/stop-bots"))
    }

    fn staged(dir: &Path) -> Layout {
        std::fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/debian_version"), "13.1\n").unwrap();
        let binary = dir.join("stop-bots");
        std::fs::write(&binary, b"#!/bin/true\n").unwrap();
        Layout::under(dir, binary)
    }

    /// A fake `systemctl` running `body`, wired into `layout`.
    ///
    /// Injected through `Layout` rather than placed on `PATH`: `PATH` is
    /// process-global and a threaded test runner would race on it.
    fn with_fake_systemctl(layout: &mut Layout, dir: &Path, body: &str) {
        let script = dir.join("fake-systemctl");
        crate::testing::write_script(&script, body);
        layout.systemctl = script;
    }

    /// The exact unit an operator gets. A golden rather than substring
    /// assertions because the failure that matters is a directive quietly
    /// changing meaning — a `ReadWritePaths=` line going missing leaves a
    /// directory read-only and breaks the first apply that writes there, an
    /// hour after the unit started cleanly.
    #[test]
    fn the_generated_unit_is_what_it_was() {
        crate::golden::assert_golden("stop-bots-web.service", &web_unit(&system_layout()));
    }

    #[test]
    fn the_generated_helper_units_are_what_they_were() {
        crate::golden::assert_golden(
            "stop-bots-helper.socket",
            &helper_socket_unit(&system_layout()),
        );
        crate::golden::assert_golden("stop-bots-helper.service", &helper_unit(&system_layout()));
    }

    /// Under WAL the `-wal` holds rows not yet checkpointed, the password
    /// hash among them, so it is tightened with the database — and so is
    /// a copy an upgrade kept, which holds everything the database did.
    #[test]
    fn securing_the_database_covers_its_wal_companions_and_copies() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite3");
        for suffix in ["", "-wal", "-shm", ".bak-v5"] {
            let file = dir.path().join(format!("db.sqlite3{suffix}"));
            std::fs::write(&file, "").unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        secure_database(&db, None).unwrap();

        for suffix in ["", "-wal", "-shm", ".bak-v5"] {
            let file = dir.path().join(format!("db.sqlite3{suffix}"));
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "db.sqlite3{suffix} was left {mode:04o}");
        }
    }

    /// The unit must not name an SSH log unless asked to.
    ///
    /// This is the regression that took a production host out quietly. The
    /// unit used to carry `--ssh-log /var/log/auth.log` always, and on a
    /// Debian 12 host — where rsyslog is no longer installed by default and
    /// sshd logs only to the journal — that file does not exist. An
    /// explicit path skips the `journalctl` fallback by design, so the
    /// service read nothing: the console's SSH panel sat empty and the
    /// brute-force detector, which runs inside that same service, found
    /// nothing to block. Neither said anything was wrong, because an
    /// unreadable log means "could not check".
    #[test]
    fn the_unit_names_no_ssh_log_by_default() {
        let unit = web_unit(&system_layout());

        assert!(
            !unit.contains("--ssh-log"),
            "the unit pinned an SSH log nobody asked for; the service has to be \
             free to fall back to journalctl. Unit was:\n{unit}"
        );
    }

    /// The flag is still there for the host where the log really is
    /// somewhere else — it just has to be asked for.
    #[test]
    fn an_explicit_ssh_log_still_reaches_the_unit() {
        let mut layout = system_layout();
        layout.ssh_log = Some(PathBuf::from("/srv/logs/auth.log"));

        assert!(
            web_unit(&layout).contains("--ssh-log /srv/logs/auth.log"),
            "an operator who named a log did not get it"
        );
    }

    /// `Path::join` with an absolute path throws the prefix away, which
    /// would point a `--prefix` install at the developer's real /etc.
    #[test]
    fn every_path_in_a_prefixed_layout_stays_inside_the_prefix() {
        let prefix = Path::new("/tmp/stop-bots-test-prefix");
        let layout = Layout::under(prefix, PathBuf::from("/usr/local/bin/stop-bots"));

        for path in [
            &layout.unit_dir,
            &layout.state_dir,
            &layout.output_dir,
            &layout.db_path,
            &layout.nginx_dir,
            &layout.nginx_log_dir,
            &layout.run_dir,
            &layout.helper_socket,
            &layout.systemd_marker,
            &layout.debian_marker,
        ] {
            assert!(
                path.starts_with(prefix),
                "{} escaped the prefix",
                path.display()
            );
        }
    }

    #[test]
    fn a_binary_under_a_build_directory_is_recognised() {
        for path in [
            "/home/me/src/stop-bots/target/debug/stop-bots",
            "/home/me/src/stop-bots/target/release/stop-bots",
            "target/debug/stop-bots",
        ] {
            assert!(is_build_artifact(Path::new(path)), "{path}");
        }
        for path in [
            "/usr/local/bin/stop-bots",
            "/usr/bin/stop-bots",
            // A directory that merely contains the word, and a `target`
            // that is not a cargo one.
            "/opt/target-practice/stop-bots",
            "/srv/target/bin/stop-bots",
        ] {
            assert!(!is_build_artifact(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn preflight_refuses_a_host_without_systemd() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_dir_all(&layout.systemd_marker).unwrap();

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(
            err.to_string().contains("not running systemd"),
            "was: {err}"
        );
    }

    #[test]
    fn preflight_refuses_a_host_that_is_not_debian() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_file(&layout.debian_marker).unwrap();

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(
            err.to_string().contains("not look like Debian"),
            "was: {err}"
        );
    }

    #[test]
    fn a_dry_run_writes_nothing_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let options = Options {
            dry_run: true,
            ..Options::default()
        };

        let steps = install_web(&layout, &options).unwrap();

        assert!(!steps.is_empty(), "a dry run still describes the plan");
        assert!(!layout.unit_path().exists(), "the dry run wrote the unit");
        assert!(
            !layout.state_dir.exists(),
            "the dry run made the state directory"
        );
        assert!(
            !layout.output_dir.exists(),
            "the dry run made the output directory"
        );
        for unit in [HELPER_SOCKET_UNIT, HELPER_UNIT] {
            assert!(
                !layout.unit_dir.join(unit).exists(),
                "the dry run wrote {unit}"
            );
        }
    }

    #[test]
    fn installing_writes_the_unit_and_locks_down_the_state_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());

        install_web(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
        assert_eq!(
            std::fs::read_to_string(layout.unit_dir.join(HELPER_SOCKET_UNIT)).unwrap(),
            helper_socket_unit(&layout)
        );
        assert_eq!(
            std::fs::read_to_string(layout.unit_dir.join(HELPER_UNIT)).unwrap(),
            helper_unit(&layout)
        );
        // 0700 because this directory holds the database, and the database
        // holds the console's password hash.
        let mode = std::fs::metadata(&layout.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "state dir was {mode:04o}");
        let mode = std::fs::metadata(&layout.output_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "output dir was {mode:04o}");
    }

    /// A state directory left at 0755 by an earlier root-run `stop-bots`
    /// has to be tightened, not left because it already exists.
    #[test]
    fn installing_tightens_a_state_directory_that_already_exists() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.state_dir).unwrap();
        std::fs::set_permissions(&layout.state_dir, std::fs::Permissions::from_mode(0o755))
            .unwrap();

        install_web(&layout, &Options::default()).unwrap();

        let mode = std::fs::metadata(&layout.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "state dir was left at {mode:04o}");
    }

    /// A `systemctl` that records its arguments and succeeds, so the one
    /// function here that starts a daemon is covered by something other
    /// than hope. Written into the layout rather than onto `PATH`: `PATH`
    /// is process-global and would race a threaded test runner.
    fn recording_systemctl(dir: &Path) -> (PathBuf, PathBuf) {
        let log = dir.join("systemctl.log");
        let script = dir.join("fake-systemctl");
        crate::testing::write_script(
            &script,
            &format!("echo \"$@\" >> {}\nexit 0", log.display()),
        );
        (script, log)
    }

    /// The exact calls, in order. An argument-order slip or a typo in the
    /// unit name is invisible to every other test here, because they all
    /// go through `--prefix`, which skips systemctl entirely.
    ///
    /// The console is restarted rather than started: on an upgrade the old
    /// one is running, as root if it was 0.1.0-rc.2's, and `enable --now`
    /// would leave it so.
    #[test]
    fn activating_reloads_systemd_then_starts_the_socket_and_restarts_the_console() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = activate(
            &layout,
            &Options {
                start: true,
                ..Options::default()
            },
        )
        .unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls,
            "daemon-reload\n\
             enable --now stop-bots-helper.socket\n\
             try-restart stop-bots-helper.service\n\
             enable stop-bots-web.service\n\
             restart stop-bots-web.service\n",
            "steps reported were: {steps:?}"
        );
    }

    /// `--no-start` enables the unit for the next boot without running it
    /// now — so no `--now`.
    #[test]
    fn activating_without_start_enables_but_does_not_run_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        activate(&layout, &Options::default()).unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls,
            "daemon-reload\nenable stop-bots-helper.socket\nenable stop-bots-web.service\n"
        );
    }

    /// A dry run must not reach systemd either — that is the whole promise
    /// of the flag on the one command that starts a daemon.
    #[test]
    fn a_dry_run_does_not_call_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = activate(
            &layout,
            &Options {
                dry_run: true,
                start: true,
                ..Options::default()
            },
        )
        .unwrap();

        assert!(!log.exists(), "systemctl ran during a dry run");
        assert!(
            steps
                .iter()
                .any(|s| s.contains("restart stop-bots-web.service")),
            "a dry run still describes what it would do: {steps:?}"
        );
    }

    /// A failing `systemctl` is an error, not a step that quietly reports
    /// success — the unit is written but the service is not running, and
    /// the operator has to know that.
    #[test]
    fn a_failing_systemctl_stops_the_install() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        with_fake_systemctl(&mut layout, dir.path(), "echo 'no such unit' >&2\nexit 1");

        let err = activate(&layout, &Options::default()).unwrap_err();

        assert!(err.to_string().contains("no such unit"), "was: {err}");
    }

    #[test]
    fn re_installing_over_an_identical_unit_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert!(
            steps.iter().any(|s| s.contains("already up to date")),
            "was: {steps:?}"
        );
    }

    /// The point of the refusal: an operator who edited `ExecStart` should
    /// not lose it to someone re-running the installer.
    #[test]
    fn an_edited_unit_is_refused_rather_than_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();
        let edited = format!("{}\n# a deliberate local edit\n", web_unit(&layout));
        std::fs::write(layout.unit_path(), &edited).unwrap();

        let err = install_web(&layout, &Options::default()).unwrap_err();

        assert!(err.to_string().contains("--force"), "was: {err}");
        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            edited,
            "the edit was overwritten anyway"
        );
    }

    #[test]
    fn force_replaces_an_edited_unit() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();
        std::fs::write(layout.unit_path(), "# entirely different\n").unwrap();

        install_web(
            &layout,
            &Options {
                force: true,
                ..Options::default()
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
    }
    /// The bug this check exists for, reported from a real Debian host:
    /// `./stop-bots install web` run from `/root` wrote
    /// `ExecStart=/root/stop-bots`, which systemd could not execute
    /// because the unit's own `ProtectHome=yes` makes `/root` empty for
    /// the service. `is_file()` said yes; systemd said
    /// `status=203/EXEC`, `No such file or directory`.
    #[test]
    fn the_hidden_binary_message_names_the_directive_and_the_fix() {
        let message = hidden_binary_error(Path::new("/root/stop-bots"), "ProtectHome=yes");

        assert!(
            message.contains("ProtectHome=yes"),
            "the message must name the directive responsible: {message}"
        );
        assert!(
            message.contains("install -m 755 /root/stop-bots /usr/local/bin/stop-bots"),
            "the message must be copy-pasteable: {message}"
        );
        assert!(
            message.contains("203/EXEC"),
            "it must connect to what systemd actually printed: {message}"
        );
    }

    /// End to end through `preflight`, using the tempdir's own binary —
    /// which is under the temporary directory `PrivateTmp=yes` replaces,
    /// so it is a file that exists and that the unit could not execute.
    /// Skipped, loudly, if this machine's temp directory is somewhere the
    /// unit does not hide.
    #[test]
    fn preflight_refuses_a_binary_the_units_own_sandbox_would_hide() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        assert!(layout.binary.is_file(), "the fixture binary must exist");
        let Some(directive) = hidden_from_unit(&layout.binary) else {
            crate::say_err!(
                "skipped: {} is not a directory the unit hides",
                layout.binary.display()
            );
            return;
        };

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains(directive), "was: {err:#}");
    }

    /// Every directory the unit replaces or privatises, checked against
    /// the unit text itself so adding a sandbox directive that hides
    /// somewhere new cannot silently outrun this list.
    #[test]
    fn every_directory_the_unit_hides_is_refused() {
        for (path, directive) in [
            ("/root/stop-bots", "ProtectHome=yes"),
            ("/home/marko/stop-bots", "ProtectHome=yes"),
            ("/run/user/1000/stop-bots", "ProtectHome=yes"),
            ("/tmp/stop-bots", "PrivateTmp=yes"),
            ("/var/tmp/stop-bots", "PrivateTmp=yes"),
        ] {
            assert_eq!(
                hidden_from_unit(Path::new(path)),
                Some(directive),
                "{path} should be refused because of {directive}"
            );
            let dir = tempfile::tempdir().unwrap();
            let layout = staged(dir.path());
            for unit in [web_unit(&layout), helper_unit(&layout)] {
                assert!(
                    unit.contains(directive),
                    "{directive} is no longer in the unit, so this refusal is stale"
                );
            }
        }
    }

    #[test]
    fn an_installed_binary_is_not_refused() {
        for path in [
            "/usr/local/bin/stop-bots",
            "/usr/bin/stop-bots",
            "/opt/stop-bots/stop-bots",
            // Not a prefix match on "/root": a sibling directory whose
            // name merely starts the same way is a different place.
            "/rootfs/stop-bots",
        ] {
            assert_eq!(hidden_from_unit(Path::new(path)), None, "{path}");
        }
    }

    /// `enable --now` half-succeeds: the enable sticks, the start does
    /// not. An operator who sees only "exited with 1" is not told they now
    /// have a unit that will try again at the next boot.
    #[test]
    fn a_failed_enable_says_how_to_undo_the_half_that_worked() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        // `daemon-reload` succeeds and `enable` fails — the real shape of
        // this failure, and the reason the message has something to say.
        with_fake_systemctl(
            &mut layout,
            dir.path(),
            "case \"$1\" in enable) echo 'Job failed' >&2; exit 1 ;; *) exit 0 ;; esac",
        );

        let err = activate(&layout, &Options::default()).unwrap_err();

        let message = format!("{err:#}");
        assert!(
            message.contains(&format!(
                "systemctl disable --now {WEB_UNIT} {HELPER_SOCKET_UNIT}"
            )),
            "message was: {message}"
        );
    }

    /// The same when it is the restart that fails, which is where a console
    /// that cannot start shows up.
    #[test]
    fn a_failed_restart_says_how_to_undo_the_enable() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        with_fake_systemctl(
            &mut layout,
            dir.path(),
            "case \"$1\" in restart) echo 'Job failed' >&2; exit 1 ;; *) exit 0 ;; esac",
        );

        let err = activate(
            &layout,
            &Options {
                start: true,
                ..Options::default()
            },
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("systemctl disable --now"),
            "message was: {err:#}"
        );
    }

    // ---- install firewall ----

    /// `--prefix` writes a unit systemd will never read, so telling the
    /// real systemd to reload and enable it is at best a lie about what
    /// happened and at worst enables a stale unit of the same name.
    #[test]
    fn install_firewall_under_a_prefix_does_not_run_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = install_firewall(&layout, &Options::default()).unwrap();

        assert!(!log.exists(), "systemctl ran for a prefixed install");
        assert!(
            layout.unit_dir.join(FIREWALL_UNIT).is_file(),
            "the unit should still be written"
        );
        assert!(
            steps.iter().any(|s| s.contains("skipping systemctl")),
            "steps: {steps:?}"
        );
    }

    /// The last step says how to get rules into the file the unit loads.
    /// Running the script by hand enforces it now but never puts it there,
    /// so the advice is the apply that does both.
    #[test]
    fn install_firewall_points_at_the_apply_not_at_running_the_script() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());

        let steps = install_firewall(&layout, &Options::default()).unwrap();

        let last = steps.iter().last().expect("at least one step");
        assert!(last.contains("render-firewall --apply"), "steps: {steps:?}");
        assert!(!last.contains("nft -f"), "steps: {steps:?}");
    }

    /// Not root: the error names the unit file and says to use sudo, where
    /// it used to be a bare "Permission denied (os error 13)".
    #[test]
    fn install_firewall_without_permission_names_the_file_and_sudo() {
        use std::os::unix::fs::PermissionsExt;
        if crate::hint::is_root() {
            return; // root is never denied, so there is nothing to see
        }
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        std::fs::set_permissions(&layout.unit_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = install_firewall(&layout, &Options::default());
        std::fs::set_permissions(&layout.unit_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = result.expect_err("wrote into a read-only directory");
        let text = format!("{err:#}");
        assert!(text.contains(FIREWALL_UNIT), "which file? {text}");
        assert!(text.contains("Run it with sudo"), "{text}");
    }

    /// And on the real host, it does.
    #[test]
    fn install_firewall_on_the_host_reloads_and_enables_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        install_firewall(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            format!("daemon-reload\nenable {FIREWALL_UNIT}\n")
        );
    }

    /// The boot unit loads the script the stored backend writes. On an
    /// iptables host `firewall.nft` is stale or absent, and loading it at
    /// boot restores the wrong rules or none.
    #[test]
    fn the_boot_unit_follows_the_stored_backend() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            crate::firewall::store_backend(&db, crate::firewall::FirewallBackend::Iptables)
                .unwrap();
        }

        install_firewall(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(FIREWALL_UNIT)).unwrap();
        for line in [
            "ExecStart=/bin/sh /etc/stop-bots/firewall.sh",
            "ConditionPathExists=/etc/stop-bots/firewall.sh",
        ] {
            assert!(unit.contains(line), "missing {line:?} in:\n{unit}");
        }
        assert!(!unit.contains("firewall.nft"), "unit was:\n{unit}");
    }

    /// With no database yet, the default backend is the answer — the same
    /// one `firewall::stored_backend` gives.
    #[test]
    fn the_boot_unit_defaults_to_nftables() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;

        install_firewall(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(FIREWALL_UNIT)).unwrap();
        assert!(
            unit.contains("ExecStart=/usr/sbin/nft -f /etc/stop-bots/firewall.nft"),
            "unit was:\n{unit}"
        );
        assert!(
            !layout.db_path.exists(),
            "reading the backend created a database"
        );
    }

    // ---- quoting in the unit ----

    /// systemd splits `ExecStart` on whitespace and expands `%` specifiers
    /// in it, so a path with either has to be quoted and escaped or the
    /// unit runs something else.
    #[test]
    fn exec_start_quotes_and_escapes_paths_systemd_would_misread() {
        let mut layout = system_layout();
        layout.binary = PathBuf::from("/opt/stop bots/stop-bots");
        layout.db_path = PathBuf::from("/var/lib/100%/db.sqlite3");
        layout.ssh_log = Some(PathBuf::from("/srv/a \"b\"\\c.log"));

        let unit = web_unit(&layout);

        let exec = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert_eq!(
            exec,
            r#"ExecStart="/opt/stop bots/stop-bots" web --db /var/lib/100%%/db.sqlite3 --ssh-log "/srv/a \"b\"\\c.log" --helper /run/stop-bots/helper.sock"#
        );
    }

    #[test]
    fn systemd_arg_leaves_an_ordinary_path_alone_and_quotes_the_rest() {
        for (raw, quoted) in [
            ("/usr/local/bin/stop-bots", "/usr/local/bin/stop-bots"),
            ("/a b", "\"/a b\""),
            ("/a\tb", "\"/a\\tb\""),
            ("/a$b", "/a$$b"),
            ("/100%", "/100%%"),
            ("/a\"b", "\"/a\\\"b\""),
            ("/a\\b", "\"/a\\\\b\""),
            ("/a'b", "\"/a'b\""),
        ] {
            assert_eq!(systemd_arg(Path::new(raw)), quoted, "{raw:?}");
        }
    }

    // ---- telling an edited unit from an old one ----

    fn forced() -> Options {
        Options {
            force: true,
            ..Options::default()
        }
    }

    /// The marker is how every later release decides whether it may
    /// replace a unit. Renamed, it would make every unit written until then
    /// look edited — so it is pinned here, literally, rather than through
    /// the constant.
    #[test]
    fn the_template_marker_is_frozen() {
        assert_eq!(TEMPLATE_MARKER, "# stop-bots-template: ");
        let unit = web_unit(&system_layout());
        let marker_line = unit.lines().nth(1).unwrap();
        assert!(
            marker_line.starts_with("# stop-bots-template: ") && marker_line.len() == 22 + 64,
            "the second line is not the marker: {marker_line:?}"
        );
    }

    #[test]
    fn a_generated_unit_hashes_to_its_own_marker() {
        let dir = tempfile::tempdir().unwrap();
        for unit in [
            web_unit(&system_layout()),
            web_unit(&staged(dir.path())),
            helper_socket_unit(&system_layout()),
            helper_unit(&staged(dir.path())),
            firewall_unit(
                crate::firewall::FirewallBackend::Iptables,
                Path::new("/etc/stop-bots/firewall.sh"),
            ),
        ] {
            assert!(is_sealed_and_unedited(&unit), "unit was:\n{unit}");
        }
    }

    #[test]
    fn any_edit_breaks_the_seal() {
        let unit = web_unit(&system_layout());
        for (what, edited) in [
            (
                "a directive",
                unit.replace("RestartSec=5s", "RestartSec=9s"),
            ),
            ("an added line", format!("{unit}Nice=5\n")),
            (
                "the version",
                unit.replace(crate::generated::VERSION, "9.9.9"),
            ),
            (
                "the hash",
                unit.replacen(TEMPLATE_MARKER, "# stop-bots-template: 0", 1),
            ),
            ("no marker", unit.replacen(TEMPLATE_MARKER, "# ", 1)),
        ] {
            assert!(!is_sealed_and_unedited(&edited), "{what} kept the seal");
        }
    }

    /// The failure this exists for: every release that changed the
    /// template made a re-install refuse, on every host, until `--force`.
    /// A sealed unit from another version stands in for "an older
    /// release's template".
    #[test]
    fn an_unedited_unit_from_another_version_is_replaced_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        let older = seal("# Generated by stop-bots 0.1.0, with `stop-bots install web`.\n[Unit]\n");
        std::fs::write(layout.unit_path(), &older).unwrap();

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
        assert!(
            steps
                .iter()
                .any(|s| s.contains("unedited since stop-bots 0.1.0")),
            "steps: {steps:?}"
        );
    }

    /// Units from 0.0.x carry no hash. Each one a release wrote, byte for
    /// byte, is recognised and upgraded without `--force`.
    #[test]
    fn every_0_0_x_web_unit_is_upgraded_without_force() {
        for fixture in [
            include_str!("../tests/fixtures/units/stop-bots-web-0.0.1.service"),
            include_str!("../tests/fixtures/units/stop-bots-web-0.0.6.service"),
            include_str!("../tests/fixtures/units/stop-bots-web-0.0.12.service"),
            include_str!("../tests/fixtures/units/stop-bots-web-0.0.15.service"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let layout = staged(dir.path());
            std::fs::create_dir_all(&layout.unit_dir).unwrap();
            std::fs::write(layout.unit_path(), fixture).unwrap();

            let steps = install_web(&layout, &Options::default())
                .unwrap_or_else(|err| panic!("refused {fixture}: {err:#}"));

            assert_eq!(
                std::fs::read_to_string(layout.unit_path()).unwrap(),
                web_unit(&layout)
            );
            assert!(
                steps
                    .iter()
                    .any(|s| s.contains("unedited since stop-bots 0.0.")),
                "steps: {steps:?}"
            );
        }
    }

    /// Installs the firewall unit over `fixture`, with `backend` stored,
    /// and asserts it was replaced without `--force`.
    fn assert_firewall_unit_upgrades(fixture: &str, backend: crate::firewall::FirewallBackend) {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        // No database is the nftables default; only iptables needs one.
        if backend != crate::firewall::FirewallBackend::Nftables {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            crate::firewall::store_backend(&db, backend).unwrap();
        }
        let path = layout.unit_dir.join(FIREWALL_UNIT);
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        std::fs::write(&path, fixture).unwrap();

        install_firewall(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            firewall_unit(backend, &crate::firewall::default_output_path(backend))
        );
    }

    #[test]
    fn a_0_0_x_nftables_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.0.15.service"),
            crate::firewall::FirewallBackend::Nftables,
        );
    }

    #[test]
    fn a_0_0_x_iptables_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.0.15.service"),
            crate::firewall::FirewallBackend::Iptables,
        );
    }

    /// An edit to a 0.0.x unit is still an edit: refused, and kept.
    #[test]
    fn an_edited_0_0_x_unit_is_refused_and_force_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        let edited = include_str!("../tests/fixtures/units/stop-bots-web-0.0.15.service")
            .replace("Restart=on-failure", "Restart=always");
        std::fs::write(layout.unit_path(), &edited).unwrap();

        let err = install_web(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            edited,
            "the edit was overwritten anyway"
        );

        install_web(&layout, &forced()).unwrap();
        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
    }

    #[test]
    fn an_edited_firewall_unit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        install_firewall(&layout, &Options::default()).unwrap();
        let path = layout.unit_dir.join(FIREWALL_UNIT);
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("After=docker.service ", "After=");
        std::fs::write(&path, &edited).unwrap();

        let err = install_firewall(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    }

    #[test]
    fn the_generated_firewall_unit_is_what_it_was() {
        crate::golden::assert_golden(
            "stop-bots-firewall.service",
            &firewall_unit(
                crate::firewall::FirewallBackend::Nftables,
                Path::new("/etc/stop-bots/firewall.nft"),
            ),
        );
    }

    /// The iptables variant differs in what it runs and in the two things
    /// iptables-legacy needs from its sandbox.
    #[test]
    fn the_generated_iptables_firewall_unit_is_what_it_was() {
        crate::golden::assert_golden(
            "stop-bots-firewall-iptables.service",
            &firewall_unit(
                crate::firewall::FirewallBackend::Iptables,
                Path::new("/etc/stop-bots/firewall.sh"),
            ),
        );
    }

    // ---- the sandbox ----

    /// The unit's directive lines, comments and blank lines left out: the
    /// comments name directives to explain them.
    fn directives(unit: &str) -> Vec<&str> {
        unit.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    }

    /// What `ReadWritePaths=` gives back, as paths.
    fn granted(unit: &str) -> Vec<PathBuf> {
        directives(unit)
            .iter()
            .filter_map(|line| line.strip_prefix("ReadWritePaths="))
            .map(|word| PathBuf::from(word.trim_start_matches('-')))
            .collect()
    }

    fn writable_in(unit: &str, path: &str) -> bool {
        granted(unit)
            .iter()
            .any(|dir| Path::new(path).starts_with(dir))
    }

    /// The point of `ProtectSystem=strict`: a write that lands in any of
    /// these is root at the next boot, or the next cron minute, outside the
    /// sandbox. The container suite checks the same against real systemd.
    #[test]
    fn neither_unit_gives_back_anything_that_would_outlive_the_service() {
        for unit in [web_unit(&system_layout()), helper_unit(&system_layout())] {
            assert!(directives(&unit).contains(&"ProtectSystem=strict"));
            for path in [
                "/etc/cron.d/x",
                "/etc/crontab",
                "/var/spool/cron/crontabs/root",
                "/etc/systemd/system/x.service",
                "/usr/lib/systemd/system/x.service",
                "/etc/sudoers.d/x",
                "/etc/ld.so.preload",
                "/usr/local/bin/stop-bots",
                "/root/.ssh/authorized_keys",
                "/var/lib/dpkg/info/x.postinst",
            ] {
                assert!(!writable_in(&unit, path), "{path} is writable:\n{unit}");
            }
        }
    }

    /// The console, which is not root, writes its database and nothing
    /// else, so that is all its unit gives back.
    #[test]
    fn the_console_gets_back_its_database_and_nothing_else() {
        let unit = web_unit(&system_layout());
        assert_eq!(granted(&unit), vec![PathBuf::from("/var/lib/stop-bots")]);
    }

    /// And everything the helper does write stays writable. Missing one is
    /// not a failed start but an apply failing with "Read-only file
    /// system" an hour later.
    #[test]
    fn the_helper_gets_back_everything_it_writes() {
        let unit = helper_unit(&system_layout());
        for (what, path) in [
            ("the database", "/var/lib/stop-bots/db.sqlite3"),
            ("its write-ahead log", "/var/lib/stop-bots/db.sqlite3-wal"),
            ("an upgrade's copy", "/var/lib/stop-bots/db.sqlite3.bak-v3"),
            ("the firewall script", "/etc/stop-bots/firewall.nft"),
            ("robots.txt", "/etc/stop-bots/nginx/robots.txt"),
            ("a site file", "/etc/nginx/sites-available/default"),
            ("a conf.d file", "/etc/nginx/conf.d/stop-bots-limits.conf"),
            ("a log nginx -t opens", "/var/log/nginx/error.log"),
            ("the pid file nginx -t creates", "/run/nginx.pid"),
            ("legacy iptables' lock", "/run/xtables.lock"),
            ("the apply lock", crate::applylock::ROOT_PATH),
        ] {
            assert!(
                writable_in(&unit, path),
                "{what} ({path}) is read-only:\n{unit}"
            );
        }
    }

    /// Without CAP_SYS_ADMIN in the bounding set, root in the sandbox
    /// cannot remount what `ProtectSystem` made read-only.
    #[test]
    fn no_unit_keeps_the_capability_that_undoes_the_sandbox() {
        let units = [
            web_unit(&system_layout()),
            helper_unit(&system_layout()),
            firewall_unit(
                crate::firewall::FirewallBackend::Nftables,
                Path::new("/etc/stop-bots/firewall.nft"),
            ),
            firewall_unit(
                crate::firewall::FirewallBackend::Iptables,
                Path::new("/etc/stop-bots/firewall.sh"),
            ),
        ];
        for unit in &units {
            let caps = directives(unit)
                .into_iter()
                .find_map(|line| line.strip_prefix("CapabilityBoundingSet="))
                .unwrap_or_else(|| panic!("no bounding set in:\n{unit}"));
            assert!(!caps.contains("CAP_SYS_ADMIN"), "{caps}");
            assert!(
                !caps.starts_with('~'),
                "a deny list keeps everything else: {caps}"
            );
        }
    }

    /// The boot unit runs a script the console writes, as root, at every
    /// boot. Without AF_UNIX it cannot ask systemd to run anything.
    #[test]
    fn the_boot_unit_cannot_reach_systemd() {
        for backend in [
            crate::firewall::FirewallBackend::Nftables,
            crate::firewall::FirewallBackend::Iptables,
        ] {
            let unit = firewall_unit(backend, &crate::firewall::default_output_path(backend));
            let families = directives(&unit)
                .into_iter()
                .find_map(|line| line.strip_prefix("RestrictAddressFamilies="))
                .unwrap_or_else(|| panic!("no address families in:\n{unit}"));
            assert!(!families.contains("AF_UNIX"), "{families}");
            assert!(
                directives(&unit).contains(&"ProtectSystem=strict"),
                "{unit}"
            );
        }
    }

    #[test]
    fn the_file_descriptor_and_task_limits_are_set() {
        for unit in [web_unit(&system_layout()), helper_unit(&system_layout())] {
            for line in ["LimitNOFILE=16384", "TasksMax=1024"] {
                assert!(directives(&unit).contains(&line), "no {line} in:\n{unit}");
            }
        }
    }

    /// The directives that make the console's compromise its user's and
    /// not root's, each one checked under real systemd by the container
    /// suite. A table rather than the golden alone, so that losing one is
    /// a failure that names it.
    #[test]
    fn the_console_runs_unprivileged_and_asks_the_helper() {
        let unit = web_unit(&system_layout());
        let lines = directives(&unit);
        for (what, line) in [
            ("its own user", "User=stop-bots"),
            ("its own group", "Group=stop-bots"),
            ("the log groups", "SupplementaryGroups=adm systemd-journal"),
            ("no capability at all", "CapabilityBoundingSet="),
            ("none gained either", "NoNewPrivileges=yes"),
            (
                "no netlink",
                "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            ),
            (
                "systemd's sockets hidden",
                "InaccessiblePaths=-/run/dbus/system_bus_socket -/run/systemd/private",
            ),
            ("W^X", "MemoryDenyWriteExecute=yes"),
            ("a syscall filter", "SystemCallFilter=@system-service"),
            ("the helper's socket", "Requires=stop-bots-helper.socket"),
        ] {
            assert!(lines.contains(&line), "{what}: no {line:?} in:\n{unit}");
        }
        let exec = lines
            .iter()
            .find(|line| line.starts_with("ExecStart="))
            .unwrap();
        assert!(
            exec.ends_with(" --helper /run/stop-bots/helper.sock"),
            "{exec}"
        );
    }

    /// The socket is root's and the console's group's, and nobody else's.
    #[test]
    fn only_the_console_can_reach_the_helpers_socket() {
        let unit = helper_socket_unit(&system_layout());
        let lines = directives(&unit);
        for line in [
            "ListenStream=/run/stop-bots/helper.sock",
            "SocketUser=root",
            "SocketGroup=stop-bots",
            "SocketMode=0660",
            "Accept=no",
        ] {
            assert!(lines.contains(&line), "no {line:?} in:\n{unit}");
        }
    }

    /// A unit naming a group the host lacks fails to start with
    /// 216/GROUP; with neither group there is no line at all.
    #[test]
    fn only_the_log_groups_the_host_has_are_named() {
        let mut layout = system_layout();
        layout.log_groups = vec!["adm".to_string()];
        assert!(directives(&web_unit(&layout)).contains(&"SupplementaryGroups=adm"));
        layout.log_groups.clear();
        assert!(!web_unit(&layout).contains("\nSupplementaryGroups="));
    }

    /// The helper is root and has no `User=`; it reaches the kernel's
    /// firewall over netlink, and keeps the internet families only because
    /// `nginx -t` will not run without them (see [`helper_unit`]).
    #[test]
    fn the_helper_is_root_with_the_families_nginx_t_needs() {
        let unit = helper_unit(&system_layout());
        assert!(
            directives(&unit)
                .contains(&"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK"),
            "{unit}"
        );
        assert!(!directives(&unit)
            .iter()
            .any(|line| line.starts_with("User=")));
    }

    /// A host whose NGINX lives elsewhere — in a container's bind mount —
    /// stores that root. The console rewrites files there, so the unit has
    /// to give it back, and the access log's directory with it.
    #[test]
    fn a_stored_nginx_root_and_access_log_are_writable_too() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            db.set_text_setting(crate::db::keys::NGINX_ROOT, "/srv/nginx/conf")
                .unwrap();
            db.set_text_setting(
                crate::db::keys::LOGS_ACCESS_PATH,
                "/srv/nginx/logs/access.log",
            )
            .unwrap();
        }

        install_web(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(HELPER_UNIT)).unwrap();
        for path in [
            "/srv/nginx/conf/sites-enabled/a",
            "/srv/nginx/logs/error.log",
        ] {
            assert!(writable_in(&unit, path), "{path} is read-only:\n{unit}");
        }
    }

    /// `nginx -t` opens every log the config names, so a site logging
    /// outside /var/log/nginx failed the console's apply until its
    /// directory was given back. Only where it can be given back safely.
    #[test]
    fn the_log_directories_the_config_names_are_given_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sites-available")).unwrap();
        std::fs::write(
            dir.path().join("sites-available/a.conf"),
            "server {\n\
             \x20   access_log /srv/www/a/logs/access.log combined;\n\
             \x20   error_log \"/srv/www/a/logs/error.log\" warn;\n\
             \x20   access_log /var/log/nginx/$host.log;\n\
             \x20   # access_log /srv/commented/out.log;\n\
             \x20   access_log off; error_log syslog:server=unix:/dev/log;\n\
             \x20   access_log /etc/cron.d/x; error_log /usr/lib/x.log;\n\
             \x20   access_log /var/lib/x/y.log; access_log /var/$x/a.log;\n\
             \x20   access_log relative/a.log;\n\
             }\n",
        )
        .unwrap();

        assert_eq!(
            nginx_log_dirs(&[dir.path().to_path_buf()]),
            vec![
                PathBuf::from("/srv/www/a/logs"),
                PathBuf::from("/var/log/nginx")
            ]
        );
    }

    /// The console writes its own database, so a root or a log path stored
    /// there is one a compromised console chose. The next `install web`
    /// must not turn it into a grant.
    #[test]
    fn a_stored_path_the_console_could_have_chosen_is_not_given_back() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            db.set_text_setting(crate::db::keys::NGINX_ROOT, "/etc")
                .unwrap();
            db.set_text_setting(
                crate::db::keys::LOGS_ACCESS_PATH,
                "/var/spool/cron/crontabs/root",
            )
            .unwrap();
        }

        install_web(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(HELPER_UNIT)).unwrap();
        for path in ["/etc/cron.d/x", "/var/spool/cron/crontabs/root"] {
            assert!(!writable_in(&unit, path), "{path} was given back:\n{unit}");
        }
    }

    /// `--root` and a 0.0.x unit's `--root` are given back as well, before
    /// the database has been told about either.
    #[test]
    fn a_root_named_on_the_command_line_is_writable() {
        let mut layout = system_layout();
        layout.nginx_roots = vec![PathBuf::from("/opt/nginx")];

        assert!(writable_in(&helper_unit(&layout), "/opt/nginx/nginx.conf"));
    }

    /// One line per place, not per spelling of it.
    #[test]
    fn a_path_inside_one_already_given_back_or_relative_is_left_out() {
        let mut layout = system_layout();
        layout.nginx_roots = vec![
            PathBuf::from("/etc/nginx/sites-enabled"),
            PathBuf::from("nginx"),
        ];
        layout.log_dirs = vec![PathBuf::from("/var/log/nginx/sites")];

        assert_eq!(writable_paths(&layout), writable_paths(&system_layout()));
    }

    /// `install web --dry-run` promises to change nothing, and reading the
    /// stored root must not migrate, create or leave anything beside the
    /// database.
    #[test]
    fn reading_the_stored_root_changes_nothing_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            db.set_text_setting(crate::db::keys::NGINX_ROOT, "/srv/nginx")
                .unwrap();
        }
        let listing = || {
            let mut names: Vec<_> = std::fs::read_dir(&layout.state_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let (before, bytes) = (listing(), std::fs::read(&layout.db_path).unwrap());

        let with = layout.with_host_settings();

        assert_eq!(with.nginx_roots, vec![PathBuf::from("/srv/nginx")]);
        assert_eq!(listing(), before);
        assert_eq!(std::fs::read(&layout.db_path).unwrap(), bytes);
    }

    #[test]
    fn read_write_paths_are_quoted_the_way_systemd_reads_them() {
        for (raw, word) in [
            ("/etc/nginx", "-/etc/nginx"),
            ("/srv/a b", "\"-/srv/a b\""),
            ("/srv/c\"d", "\"-/srv/c\\\"d\""),
            ("/srv/e\\f", "\"-/srv/e\\\\f\""),
            ("/srv/p%q", "-/srv/p%%q"),
            // Not expanded in this directive, unlike in ExecStart.
            ("/srv/d$x", "-/srv/d$x"),
        ] {
            assert_eq!(read_write_path(Path::new(raw)), word, "{raw:?}");
        }
    }

    // ---- upgrading from 0.1.0-rc.1 ----

    /// rc.1's units carry the template hash, so they are recognised by it
    /// rather than listed in `legacy`. These are the bytes rc.1 wrote, and
    /// the hash they carry is checked here, not assumed.
    #[test]
    fn every_0_1_0_rc_1_unit_is_sealed_and_unedited() {
        for fixture in [
            include_str!("../tests/fixtures/units/stop-bots-web-0.1.0-rc.1.service"),
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.1.0-rc.1.service"),
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.1.0-rc.1.service"),
        ] {
            assert!(
                is_sealed_and_unedited(fixture),
                "not recognised:\n{fixture}"
            );
        }
    }

    #[test]
    fn an_0_1_0_rc_1_web_unit_is_upgraded_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        std::fs::write(
            layout.unit_path(),
            include_str!("../tests/fixtures/units/stop-bots-web-0.1.0-rc.1.service"),
        )
        .unwrap();

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
        assert!(
            steps
                .iter()
                .any(|s| s.contains("unedited since stop-bots 0.1.0-rc.1")),
            "steps: {steps:?}"
        );
    }

    #[test]
    fn an_0_1_0_rc_1_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.1.0-rc.1.service"),
            crate::firewall::FirewallBackend::Nftables,
        );
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.1.0-rc.1.service"),
            crate::firewall::FirewallBackend::Iptables,
        );
    }

    /// An edit to an rc.1 unit is still refused: the hash is what tells.
    #[test]
    fn an_edited_0_1_0_rc_1_unit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        let edited = include_str!("../tests/fixtures/units/stop-bots-web-0.1.0-rc.1.service")
            .replace("ProtectSystem=yes", "ProtectSystem=full");
        std::fs::write(layout.unit_path(), &edited).unwrap();

        let err = install_web(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
    }

    /// The unit's own comment named `web --save`, which is deprecated.
    #[test]
    fn the_unit_points_at_set_web_not_the_deprecated_flag() {
        let unit = web_unit(&system_layout());
        assert!(
            unit.contains("`stop-bots set-web ...`"),
            "unit was:\n{unit}"
        );
        assert!(!unit.contains("--save"), "unit was:\n{unit}");
    }

    /// systemd rejects a relative `ExecStart` when it *loads* the unit,
    /// not when it starts it — so this failure does not even look like a
    /// failed service.
    #[test]
    fn preflight_refuses_a_relative_binary_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.binary = PathBuf::from("stop-bots");

        let err = preflight(&layout, &Options::default()).unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("absolute"), "was: {message}");
        assert!(
            message.contains("--binary /"),
            "it should suggest the absolute form: {message}"
        );
    }

    // ---- upgrading from 0.1.0-rc.2 ----

    /// rc.2's units, the bytes it wrote. Its console ran as root; the
    /// upgrade is what replaces that unit, so it has to be recognised as
    /// unedited, by its hash.
    #[test]
    fn every_0_1_0_rc_2_unit_is_sealed_and_unedited() {
        for fixture in [
            include_str!("../tests/fixtures/units/stop-bots-web-0.1.0-rc.2.service"),
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.1.0-rc.2.service"),
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.1.0-rc.2.service"),
        ] {
            assert!(
                is_sealed_and_unedited(fixture),
                "not recognised:\n{fixture}"
            );
        }
    }

    #[test]
    fn an_0_1_0_rc_2_web_unit_is_replaced_by_the_unprivileged_one_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        let rc2 = include_str!("../tests/fixtures/units/stop-bots-web-0.1.0-rc.2.service");
        assert!(
            !rc2.contains("\nUser="),
            "the fixture is not rc.2's root unit"
        );
        std::fs::write(layout.unit_path(), rc2).unwrap();

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
        assert!(
            steps
                .iter()
                .any(|s| s.contains("unedited since stop-bots 0.1.0-rc.2")),
            "steps: {steps:?}"
        );
    }

    #[test]
    fn an_0_1_0_rc_2_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.1.0-rc.2.service"),
            crate::firewall::FirewallBackend::Nftables,
        );
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.1.0-rc.2.service"),
            crate::firewall::FirewallBackend::Iptables,
        );
    }

    /// An edited helper unit is refused like an edited console unit, and
    /// before anything at all is written.
    #[test]
    fn an_edited_helper_unit_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        let edited = format!("{}# an operator's edit\n", helper_unit(&layout));
        std::fs::write(layout.unit_dir.join(HELPER_UNIT), &edited).unwrap();

        let err = install_web(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
        assert!(
            !layout.unit_path().exists(),
            "wrote the console's unit anyway"
        );
        assert!(
            !layout.state_dir.exists(),
            "made the state directory anyway"
        );
    }

    // ---- the console's user ----

    /// A recording stand-in for `useradd`.
    fn recording(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let log = dir.join(format!("{name}.log"));
        let script = dir.join(format!("fake-{name}"));
        crate::testing::write_script(
            &script,
            &format!("echo \"$@\" >> {}\nexit 0", log.display()),
        );
        (script, log)
    }

    /// Whoever runs the tests, standing in for the console's user: it
    /// exists, and handing a file to it needs no privilege.
    fn me() -> String {
        // SAFETY: no preconditions; reads the process's own credentials.
        crate::account::user_name(unsafe { libc::geteuid() })
    }

    /// The user is made the way the design says: a system account, with
    /// no home and no shell, and its own group.
    #[test]
    fn a_missing_user_is_created_as_a_system_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        layout.user = "stop-bots-test-no-such-user".to_string();
        let (useradd, log) = recording(dir.path(), "useradd");
        layout.useradd = useradd;
        let mut steps = Steps::new();

        let dry = ensure_service_account(
            &layout,
            &Options {
                dry_run: true,
                ..Options::default()
            },
            &mut steps,
        )
        .unwrap();
        assert_eq!(dry, None);
        assert!(!log.exists(), "a dry run ran useradd");
        assert!(
            steps
                .iter()
                .any(|step| step.starts_with("fake-useradd --system")),
            "the dry run did not say it would: {steps:?}"
        );

        let err = ensure_service_account(&layout, &Options::default(), &mut steps).unwrap_err();

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            format!(
                "--system --user-group --no-create-home --home-dir {} --shell \
                 /usr/sbin/nologin --comment stop-bots web console stop-bots-test-no-such-user\n",
                layout.state_dir.display()
            )
        );
        // The stand-in made nobody, and that is said rather than assumed.
        assert!(
            format!("{err:#}").contains("still does not know"),
            "{err:#}"
        );
    }

    #[test]
    fn an_existing_user_is_used_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        layout.user = me();
        let (useradd, log) = recording(dir.path(), "useradd");
        layout.useradd = useradd;
        if crate::account::group(&layout.user).is_none() {
            return; // a user without a group of its own name
        }
        let mut steps = Steps::new();

        let account = ensure_service_account(&layout, &Options::default(), &mut steps);

        assert!(!log.exists(), "ran useradd for a user that exists");
        if crate::hint::is_root() {
            let err = account.unwrap_err();
            assert!(format!("{err:#}").contains("root after all"), "{err:#}");
        } else {
            assert!(account.unwrap().is_some());
        }
    }

    /// Under `--prefix` there is no user database to add to.
    #[test]
    fn a_prefixed_install_makes_no_user() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (useradd, log) = recording(dir.path(), "useradd");
        layout.useradd = useradd;

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert!(!log.exists(), "ran useradd under --prefix");
        assert!(
            steps
                .iter()
                .any(|step| step.contains("not this host's user database")),
            "{steps:?}"
        );
    }

    /// The state directory is handed to the console's user when there is
    /// one — here, whoever runs the test.
    #[test]
    fn the_state_directory_is_handed_to_the_console() {
        use std::os::unix::fs::MetadataExt;
        if crate::hint::is_root() {
            return; // the test's user would be root, which is refused
        }
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        layout.user = me();
        if crate::account::group(&layout.user).is_none() {
            return;
        }
        // On the host, `real` also checks the binary against the unit's
        // sandbox, and the fixture's binary lives in a temp directory.
        layout.binary = PathBuf::from("/bin/sh");

        let steps = install_web(&layout, &Options::default()).unwrap();

        let meta = std::fs::metadata(&layout.state_dir).unwrap();
        assert_eq!(meta.uid(), crate::account::user(&layout.user).unwrap().uid);
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert!(
            steps
                .iter()
                .any(|step| step.contains("give ") && step.contains(&layout.user)),
            "{steps:?}"
        );
    }

    /// The attack this hands over by descriptor for: the console, owning
    /// its directory, links a companion to a root file, and the next
    /// `install web` would `chown` the link's target.
    #[test]
    fn handing_over_the_database_does_not_follow_a_link() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite3");
        std::fs::write(&db, "").unwrap();
        let shadow = dir.path().join("shadow");
        std::fs::write(&shadow, "root:*:\n").unwrap();
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::os::unix::fs::symlink(&shadow, dir.path().join("db.sqlite3-wal")).unwrap();
        let mine = std::fs::metadata(&shadow).unwrap();
        let account = crate::account::Account {
            uid: mine.uid(),
            gid: mine.gid(),
        };

        let handed = secure_database(&db, Some(account));
        let chmodded = secure_database(&db, None);

        assert!(handed.is_err() && chmodded.is_err(), "followed the link");
        assert_eq!(
            std::fs::metadata(&shadow).unwrap().mode() & 0o777,
            0o640,
            "the link's target was changed"
        );
    }

    /// A second name for someone else's file is refused the same way.
    #[test]
    fn handing_over_refuses_a_hard_link() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite3");
        std::fs::write(&db, "").unwrap();
        std::fs::hard_link(&db, dir.path().join("elsewhere")).unwrap();
        let mine = std::fs::metadata(&db).unwrap();

        let err = hand_over(
            &db,
            crate::account::Account {
                uid: mine.uid(),
                gid: mine.gid(),
            },
            0o600,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("not a plain file"), "{err:#}");
    }
}
