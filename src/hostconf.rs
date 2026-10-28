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

//! The host's own settings, in `/etc/stop-bots/host.conf`.
//!
//! Five settings say what root runs and where root writes and reads: the
//! NGINX test and reload commands, the NGINX config root, and the two
//! logs. They used to be rows in the database (`nginx:test_command`,
//! `nginx:reload_command`, `nginx:root`, `logs:access_path`,
//! `logs:ssh_path`), and the database is a file other software can write
//! — a release with the web console gave it to the console's own
//! unprivileged user. A row written there must not decide what a root
//! process executes, so these live in a file only root can write.
//!
//! The format is one `key = value` per line, `#` comments and blank lines
//! ignored. An unknown key or a line that is not `key = value` is an
//! error naming the line, because a typo in this file would otherwise
//! silently fall back to a default.
//!
//! ## Migration
//!
//! The first root process that opens the database while this file does
//! not exist moves the five rows into it and deletes them ([`migrate`]).
//! It creates the file even when there is nothing to move, so that from
//! then on the file's existence means "migrated": a row that appears in
//! the database later is never read again. A non-root process never
//! migrates. And a database that is not root's — the web console's, on a
//! host a release with one set up — is not trusted to migrate from at all:
//! its rows may have been written by whoever compromised the console.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::db::{keys, Db};
use crate::logpaths::LogPaths;
use crate::webserver::{ServerCommands, WebServer};

/// Where the file lives.
pub const DEFAULT_PATH: &str = "/etc/stop-bots/host.conf";

/// Environment override for [`DEFAULT_PATH`], for the end-to-end tests,
/// which drive the real binary and must not read or write `/etc`. The
/// same test-only rationale as `nginx::MANAGED_DIR_ENV`.
pub const PATH_ENV: &str = "STOP_BOTS_HOST_CONF";

/// The file this process reads and writes.
pub fn path() -> PathBuf {
    if let Some(path) = std::env::var_os(PATH_ENV).filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    if cfg!(test) {
        // A unit test runs inside the library, with no environment of its
        // own to point elsewhere, and must never read the host's settings:
        // once stop-bots was installed on the machine running the tests,
        // its /etc/stop-bots/host.conf decided whether `uninstall`'s tests
        // passed. A path that never exists is "nothing set", as on CI.
        return std::env::temp_dir()
            .join(format!("stop-bots-unit-tests-{}", std::process::id()))
            .join("host.conf");
    }
    PathBuf::from(DEFAULT_PATH)
}

const WEB_SERVER: &str = "web_server";
const NGINX_TEST: &str = "nginx_test_command";
const NGINX_RELOAD: &str = "nginx_reload_command";
const NGINX_ROOT: &str = "nginx_root";
const APACHE_TEST: &str = "apache_test_command";
const APACHE_RELOAD: &str = "apache_reload_command";
const APACHE_ROOT: &str = "apache_root";
const TRAEFIK_TEST: &str = "traefik_test_command";
const TRAEFIK_RELOAD: &str = "traefik_reload_command";
const TRAEFIK_ROOT: &str = "traefik_root";
const NPMPLUS_TEST: &str = "npmplus_test_command";
const NPMPLUS_RELOAD: &str = "npmplus_reload_command";
const NPMPLUS_ROOT: &str = "npmplus_root";
const ACCESS_LOG: &str = "access_log";
const SSH_LOG: &str = "ssh_log";
const KERNEL_LOG: &str = "kernel_log";

/// The host settings. `None` for any of them means "not set": the
/// built-in default, as it was when nothing was stored in the database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConf {
    /// Which web server serves this host's sites. `None` is NGINX, which
    /// is what every host was before there was a choice.
    pub web_server: Option<WebServer>,
    /// How to test the NGINX config, as one command line split by
    /// [`crate::webserver::split_command`]. Never through a shell.
    pub nginx_test_command: Option<String>,
    /// How to reload NGINX, the same way.
    pub nginx_reload_command: Option<String>,
    /// Where NGINX's config lives.
    pub nginx_root: Option<PathBuf>,
    /// How to test the Apache config, the same way as NGINX's.
    pub apache_test_command: Option<String>,
    /// How to reload Apache.
    pub apache_reload_command: Option<String>,
    /// Where Apache's config lives.
    pub apache_root: Option<PathBuf>,
    /// How to check Traefik's config, the same way as NGINX's. Traefik has
    /// no config test, so by default nothing is run.
    pub traefik_test_command: Option<String>,
    /// How to make Traefik read its config again. Its file provider does
    /// that by itself, so by default nothing is run.
    pub traefik_reload_command: Option<String>,
    /// The directory Traefik's file provider reads.
    pub traefik_root: Option<PathBuf>,
    /// How to test NPMplus's NGINX config, the same way as NGINX's.
    pub npmplus_test_command: Option<String>,
    /// How to reload NPMplus's NGINX.
    pub npmplus_reload_command: Option<String>,
    /// NPMplus's data directory, the one its container has at `/data`.
    pub npmplus_root: Option<PathBuf>,
    /// The NGINX access log.
    pub access_log: Option<PathBuf>,
    /// The SSH log, which the lockout guard reads.
    pub ssh_log: Option<PathBuf>,
    /// The kernel log, which the port-scan detector reads.
    pub kernel_log: Option<PathBuf>,
}

impl HostConf {
    /// Reads [`path`]. A file that does not exist is every default.
    pub fn load() -> Result<Self> {
        Self::load_from(&path())
    }

    /// Reads `path`. A file that does not exist is every default.
    pub fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                Self::parse(&text).with_context(|| format!("{} is not usable", path.display()))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    /// Parses the file's text.
    pub fn parse(text: &str) -> Result<Self> {
        let mut conf = Self::default();
        let mut seen: Vec<&str> = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let number = number + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("line {number} is not `key = value`");
            };
            let (key, value) = (key.trim(), value.trim());
            if seen.contains(&key) {
                bail!("line {number} sets `{key}` a second time");
            }
            let value = (!value.is_empty()).then(|| value.to_string());
            match key {
                WEB_SERVER => {
                    conf.web_server = match value.as_deref() {
                        None => None,
                        Some(id) => Some(WebServer::from_id(id).with_context(|| {
                            format!(
                                "line {number} sets `{key}` to `{id}`, which is not one of: {}",
                                WebServer::ALL.map(WebServer::id).join(", ")
                            )
                        })?),
                    }
                }
                NGINX_TEST => conf.nginx_test_command = value,
                NGINX_RELOAD => conf.nginx_reload_command = value,
                NGINX_ROOT => conf.nginx_root = value.map(PathBuf::from),
                APACHE_TEST => conf.apache_test_command = value,
                APACHE_RELOAD => conf.apache_reload_command = value,
                APACHE_ROOT => conf.apache_root = value.map(PathBuf::from),
                TRAEFIK_TEST => conf.traefik_test_command = value,
                TRAEFIK_RELOAD => conf.traefik_reload_command = value,
                TRAEFIK_ROOT => conf.traefik_root = value.map(PathBuf::from),
                NPMPLUS_TEST => conf.npmplus_test_command = value,
                NPMPLUS_RELOAD => conf.npmplus_reload_command = value,
                NPMPLUS_ROOT => conf.npmplus_root = value.map(PathBuf::from),
                ACCESS_LOG => conf.access_log = value.map(PathBuf::from),
                SSH_LOG => conf.ssh_log = value.map(PathBuf::from),
                KERNEL_LOG => conf.kernel_log = value.map(PathBuf::from),
                other => bail!("line {number} sets `{other}`, which is not a host setting"),
            }
            seen.push(key);
            conf.validate()
                .with_context(|| format!("line {number} sets `{key}`"))?;
        }
        Ok(conf)
    }

    /// Checks every value: commands that split into words, and absolute
    /// paths. Nothing may hold a line break, which is what keeps one value
    /// from becoming two lines of the file.
    pub fn validate(&self) -> Result<()> {
        for command in [
            &self.nginx_test_command,
            &self.nginx_reload_command,
            &self.apache_test_command,
            &self.apache_reload_command,
            &self.traefik_test_command,
            &self.traefik_reload_command,
            &self.npmplus_test_command,
            &self.npmplus_reload_command,
        ]
        .into_iter()
        .flatten()
        {
            no_control_characters(command)?;
            crate::webserver::split_command(command)?;
        }
        for path in [
            &self.nginx_root,
            &self.apache_root,
            &self.traefik_root,
            &self.npmplus_root,
            &self.access_log,
            &self.ssh_log,
            &self.kernel_log,
        ]
        .into_iter()
        .flatten()
        {
            let text = path
                .to_str()
                .with_context(|| format!("{} is not UTF-8", path.display()))?;
            no_control_characters(text)?;
            if !path.is_absolute() {
                bail!("{} is not an absolute path", path.display());
            }
        }
        Ok(())
    }

    /// The file's text: a header, then each setting that is set.
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# stop-bots host settings. Written by `stop-bots set-web-server`,\n\
             # `stop-bots set-web-server nginx` and `stop-bots set-log-paths`; read\n\
             # by every stop-bots process.\n\
             # Only root may change this file.\n",
        );
        let lines = [
            (
                WEB_SERVER,
                self.web_server.map(|server| server.id().to_string()),
            ),
            (NGINX_TEST, self.nginx_test_command.clone()),
            (NGINX_RELOAD, self.nginx_reload_command.clone()),
            (NGINX_ROOT, path_text(&self.nginx_root)),
            (APACHE_TEST, self.apache_test_command.clone()),
            (APACHE_RELOAD, self.apache_reload_command.clone()),
            (APACHE_ROOT, path_text(&self.apache_root)),
            (TRAEFIK_TEST, self.traefik_test_command.clone()),
            (TRAEFIK_RELOAD, self.traefik_reload_command.clone()),
            (TRAEFIK_ROOT, path_text(&self.traefik_root)),
            (NPMPLUS_TEST, self.npmplus_test_command.clone()),
            (NPMPLUS_RELOAD, self.npmplus_reload_command.clone()),
            (NPMPLUS_ROOT, path_text(&self.npmplus_root)),
            (ACCESS_LOG, path_text(&self.access_log)),
            (SSH_LOG, path_text(&self.ssh_log)),
            (KERNEL_LOG, path_text(&self.kernel_log)),
        ];
        for (key, value) in lines {
            if let Some(value) = value {
                out.push_str(&format!("{key} = {value}\n"));
            }
        }
        out
    }

    /// Writes [`Self::render`] to `path`, 0644, replacing it in one rename.
    /// Refuses a value [`Self::validate`] refuses.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        self.validate()?;
        write_file(path, &self.render())
    }

    /// Which web server serves this host's sites.
    pub fn web_server(&self) -> WebServer {
        self.web_server.unwrap_or_default()
    }

    /// The web server's commands, each falling back to its default. An
    /// empty default is no command, as Traefik's are.
    pub fn commands(&self) -> Result<ServerCommands> {
        let command = |raw: &Option<String>, key: &str, fallback: &str| -> Result<Vec<String>> {
            if raw.is_none() && fallback.is_empty() {
                return Ok(Vec::new());
            }
            crate::webserver::split_command(raw.as_deref().unwrap_or(fallback))
                .with_context(|| format!("the host setting `{key}` is not a valid command"))
        };
        let server = self.web_server();
        let (test, reload) = match server {
            WebServer::Nginx => (
                (&self.nginx_test_command, NGINX_TEST),
                (&self.nginx_reload_command, NGINX_RELOAD),
            ),
            WebServer::Apache => (
                (&self.apache_test_command, APACHE_TEST),
                (&self.apache_reload_command, APACHE_RELOAD),
            ),
            WebServer::Traefik => (
                (&self.traefik_test_command, TRAEFIK_TEST),
                (&self.traefik_reload_command, TRAEFIK_RELOAD),
            ),
            WebServer::Npmplus => (
                (&self.npmplus_test_command, NPMPLUS_TEST),
                (&self.npmplus_reload_command, NPMPLUS_RELOAD),
            ),
        };
        let root = self.root(None);
        Ok(ServerCommands {
            test: command(test.0, test.1, server.default_test_at(&root))?,
            reload: command(reload.0, reload.1, server.default_reload_at(&root))?,
        })
    }

    /// Where the web server's config is: `flag` if given, else the
    /// setting, else the stock path.
    pub fn root(&self, flag: Option<&Path>) -> PathBuf {
        let server = self.web_server();
        let stored = match server {
            WebServer::Nginx => &self.nginx_root,
            WebServer::Apache => &self.apache_root,
            WebServer::Traefik => &self.traefik_root,
            WebServer::Npmplus => &self.npmplus_root,
        };
        flag.map(Path::to_path_buf)
            .or_else(|| stored.clone())
            .unwrap_or_else(|| PathBuf::from(server.default_root()))
    }

    /// The stored config root of the web server this host runs — the
    /// setting [`Self::root`] reads — for a command that stores one.
    /// `nginx_root` on an NGINX host, `apache_root` on an Apache one,
    /// `traefik_root` on a Traefik one: a root written to another server's
    /// key is never read by anything.
    pub fn root_setting_mut(&mut self) -> &mut Option<PathBuf> {
        match self.web_server() {
            WebServer::Nginx => &mut self.nginx_root,
            WebServer::Apache => &mut self.apache_root,
            WebServer::Traefik => &mut self.traefik_root,
            WebServer::Npmplus => &mut self.npmplus_root,
        }
    }

    /// The two log paths, as [`LogPaths`] resolves them.
    pub fn log_paths(&self) -> LogPaths {
        LogPaths {
            access: self.access_log.clone(),
            ssh: self.ssh_log.clone(),
            kernel: self.kernel_log.clone(),
            server: self.web_server(),
            root: self.root(None),
            config_logs_here: self.config_paths_are_here(),
        }
    }

    /// Whether the paths the web server's config names are paths on this
    /// host. A test command of its own is how a server in a container is
    /// set up (see `set-web-server --test`): its config names the paths it
    /// has inside the container, and a file of the same name here says
    /// nothing about it.
    ///
    /// Never on Traefik, which has no test command to tell by and is in a
    /// container far more often than not; nor does its dynamic config name
    /// a document root or a log for this to matter to. Never on NPMplus,
    /// which is always in one: its config names the container's `/data`.
    pub fn config_paths_are_here(&self) -> bool {
        match self.web_server() {
            WebServer::Nginx => self.nginx_test_command.is_none(),
            WebServer::Apache => self.apache_test_command.is_none(),
            WebServer::Traefik | WebServer::Npmplus => false,
        }
    }
}

fn path_text(path: &Option<PathBuf>) -> Option<String> {
    path.as_ref().map(|path| path.display().to_string())
}

fn no_control_characters(value: &str) -> Result<()> {
    if value.chars().any(char::is_control) {
        bail!("{value:?} holds a control character");
    }
    Ok(())
}

/// Replaces `path` with `text`: a new file beside it, then a rename, so a
/// reader never sees half a file and a link planted at the name is
/// replaced rather than written through.
fn write_file(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let temp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err).with_context(|| {
            format!(
                "failed to write {}{}",
                path.display(),
                if crate::hint::is_root() {
                    ""
                } else {
                    " (host settings are root's: run this with sudo)"
                }
            )
        });
    }
    Ok(())
}

/// What [`migrate`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migrated {
    /// Not root: nothing was read or written.
    NotRoot,
    /// The file already exists, so there was nothing to do.
    AlreadyDone,
    /// The file was created, holding the settings in `moved`. The rows in
    /// `ignored` were deleted without being copied, each with why.
    Created {
        moved: Vec<&'static str>,
        ignored: Vec<String>,
    },
}

impl Migrated {
    /// What to tell the operator, if anything.
    pub fn note(&self, path: &Path) -> Option<String> {
        match self {
            Migrated::NotRoot | Migrated::AlreadyDone => None,
            Migrated::Created { moved, ignored } if moved.is_empty() && ignored.is_empty() => None,
            Migrated::Created { moved, ignored } => {
                let mut lines = Vec::new();
                if !moved.is_empty() {
                    lines.push(format!(
                        "Note: moved {} from the database into {}, which is where the host's \
                         settings live now.",
                        moved.join(", "),
                        path.display()
                    ));
                }
                for line in ignored {
                    lines.push(format!("Note: {line}"));
                }
                Some(lines.join("\n"))
            }
        }
    }
}

/// Writes [`path`] with every default if there is no file there yet, so
/// that from now on its existence means "migrated". Leaves one that exists
/// alone.
pub fn ensure_written() -> Result<()> {
    ensure_written_at(&path())
}

/// [`ensure_written`], for the file at `host_conf`.
pub fn ensure_written_at(host_conf: &Path) -> Result<()> {
    if std::fs::symlink_metadata(host_conf).is_ok() {
        return Ok(());
    }
    HostConf::default().save_to(host_conf)
}

/// The five database keys this file replaces, with the field each fills.
const MIGRATED_KEYS: [&str; 5] = [
    keys::NGINX_TEST_COMMAND,
    keys::NGINX_RELOAD_COMMAND,
    keys::NGINX_ROOT,
    keys::LOGS_ACCESS_PATH,
    keys::LOGS_SSH_PATH,
];

/// Moves the host settings out of `db` into `path`, once. See the module
/// docs. A no-op unless this process is root, and once `path` exists.
pub fn migrate(db: &Db, path: &Path) -> Result<Migrated> {
    if !crate::hint::is_root() {
        return Ok(Migrated::NotRoot);
    }
    move_settings(db, path, 0)
}

/// [`migrate`]'s work, with the owner a database must have to be trusted
/// given rather than assumed to be root, so a test can run it.
///
/// The database file and the directory it is in must both belong to
/// `trusted_owner`. A database another user owns, or sits in a directory
/// they own and could have swapped the file in, may hold rows that user
/// wrote: those are deleted, never copied.
pub fn move_settings(db: &Db, path: &Path, trusted_owner: u32) -> Result<Migrated> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Ok(Migrated::AlreadyDone);
    }
    let trusted = match db.path() {
        // In memory: nothing but this process could have written it.
        None => Ok(()),
        Some(file) => owned_by(&file, trusted_owner),
    };

    let mut conf = HostConf::default();
    let mut moved = Vec::new();
    let mut ignored = Vec::new();
    for key in MIGRATED_KEYS {
        let Some(raw) = db.get_text_setting(key)? else {
            continue;
        };
        let value = raw.trim().to_string();
        if value.is_empty() {
            continue;
        }
        if let Err(why) = &trusted {
            ignored.push(format!(
                "did not move `{key}` from the database into {}: {why}. Set it again with \
                 `stop-bots {}`.",
                path.display(),
                if key.starts_with("logs:") {
                    "set-log-paths"
                } else {
                    "set-web-server"
                }
            ));
            continue;
        }
        let mut candidate = conf.clone();
        match key {
            keys::NGINX_TEST_COMMAND => candidate.nginx_test_command = Some(value),
            keys::NGINX_RELOAD_COMMAND => candidate.nginx_reload_command = Some(value),
            keys::NGINX_ROOT => candidate.nginx_root = Some(PathBuf::from(value)),
            keys::LOGS_ACCESS_PATH => candidate.access_log = Some(PathBuf::from(value)),
            _ => candidate.ssh_log = Some(PathBuf::from(value)),
        }
        match candidate.validate() {
            Ok(()) => {
                conf = candidate;
                moved.push(key);
            }
            Err(why) => ignored.push(format!(
                "did not move `{key}` from the database: {why:#}, which never worked"
            )),
        }
    }

    // The file first, the rows second: a crash between the two leaves rows
    // nothing reads again, never settings that are nowhere.
    conf.save_to(path)?;
    for key in MIGRATED_KEYS {
        db.delete_setting(key)?;
    }
    Ok(Migrated::Created { moved, ignored })
}

/// Whether rows of the database at `file` may be taken as root's own:
/// the file and its directory belong to this process's user. What a
/// process that never migrated (`uninstall` reads without opening) may
/// still read the old settings from.
pub fn is_trusted_database(file: &Path) -> bool {
    // SAFETY: no preconditions; reads the process's own credentials.
    owned_by(file, unsafe { libc::geteuid() }).is_ok()
}

/// Whether `file` and the directory holding it both belong to `owner`,
/// and `file` is not a link.
fn owned_by(file: &Path, owner: u32) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(file)
        .map_err(|err| format!("{} could not be read ({err})", file.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    if meta.uid() != owner {
        return Err(format!(
            "{} belongs to uid {}, not {owner}, so its rows may have been written by \
             another user",
            file.display(),
            meta.uid()
        ));
    }
    let dir = file
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir_meta = std::fs::metadata(dir)
        .map_err(|err| format!("{} could not be read ({err})", dir.display()))?;
    if dir_meta.uid() != owner {
        return Err(format!(
            "its directory {} belongs to uid {}, not {owner}",
            dir.display(),
            dir_meta.uid()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid() -> u32 {
        // SAFETY: no preconditions; reads the process's own credentials.
        unsafe { libc::geteuid() }
    }

    fn container_settings(db: &Db) {
        db.set_text_setting(keys::NGINX_TEST_COMMAND, "docker exec web nginx -t")
            .unwrap();
        db.set_text_setting(
            keys::NGINX_RELOAD_COMMAND,
            "docker exec web nginx -s reload",
        )
        .unwrap();
        db.set_text_setting(keys::NGINX_ROOT, "/srv/web/nginx")
            .unwrap();
        db.set_text_setting(keys::LOGS_ACCESS_PATH, "/srv/web/logs/access.log")
            .unwrap();
        db.set_text_setting(keys::LOGS_SSH_PATH, "/var/log/secure")
            .unwrap();
    }

    fn file_db(dir: &Path) -> Db {
        Db::open(dir.join("db.sqlite3")).unwrap()
    }

    #[test]
    fn a_missing_file_is_every_default() {
        let dir = tempfile::tempdir().unwrap();
        let conf = HostConf::load_from(&dir.path().join("host.conf")).unwrap();
        assert_eq!(conf, HostConf::default());
        assert_eq!(
            conf.commands().unwrap(),
            WebServer::Nginx.default_commands()
        );
        assert_eq!(conf.root(None), PathBuf::from(crate::nginx::DEFAULT_ROOT));
    }

    #[test]
    fn an_unknown_web_server_is_refused() {
        let err = HostConf::parse("web_server = caddy\n").unwrap_err();
        assert!(
            format!("{err:#}").contains("nginx, apache"),
            "error was: {err:#}"
        );
    }

    #[test]
    fn an_apache_root_in_rhels_tree_gets_rhels_defaults() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("conf")).unwrap();
        std::fs::write(root.path().join("conf/httpd.conf"), "").unwrap();
        let conf = HostConf {
            web_server: Some(WebServer::Apache),
            apache_root: Some(root.path().to_path_buf()),
            ..HostConf::default()
        };
        let commands = conf.commands().unwrap();
        assert_eq!(commands.test, ["apachectl", "configtest"]);
        assert_eq!(commands.reload, ["systemctl", "reload", "httpd"]);
        assert_eq!(
            conf.log_paths().access_path(None),
            PathBuf::from("/var/log/httpd/access_log")
        );

        let stored = HostConf {
            apache_test_command: Some("httpd -t".into()),
            ..conf
        };
        assert_eq!(
            stored.commands().unwrap().test,
            ["httpd", "-t"],
            "a stored command no longer wins over the layout's default"
        );
    }

    #[test]
    fn what_is_saved_is_what_is_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/host.conf");
        let conf = HostConf {
            web_server: Some(WebServer::Apache),
            nginx_test_command: Some("docker exec \"my web\" nginx -t".into()),
            nginx_reload_command: Some("docker exec web nginx -s reload".into()),
            nginx_root: Some("/srv/web nginx".into()),
            apache_test_command: Some("apachectl -t".into()),
            apache_reload_command: None,
            // Not a tree on any host, so the default reload is Debian's
            // wherever this runs: one in RHEL's tree gets RHEL's (see
            // `an_apache_root_in_rhels_tree_gets_rhels_defaults`).
            apache_root: Some("/srv/web apache".into()),
            traefik_test_command: None,
            traefik_reload_command: Some("docker restart traefik".into()),
            traefik_root: Some("/srv/traefik/dynamic".into()),
            npmplus_test_command: Some("docker exec proxy nginx -t".into()),
            npmplus_reload_command: None,
            npmplus_root: Some("/srv/npmplus".into()),
            access_log: Some("/srv/logs/access.log".into()),
            ssh_log: None,
            kernel_log: Some("/srv/logs/kern.log".into()),
        };
        conf.save_to(&path).unwrap();
        assert_eq!(HostConf::load_from(&path).unwrap(), conf);
        // The server chosen decides whose commands and root are used.
        assert_eq!(conf.commands().unwrap().test, ["apachectl", "-t"]);
        assert_eq!(
            conf.commands().unwrap().reload,
            ["systemctl", "reload", "apache2"]
        );
        assert_eq!(conf.root(None), PathBuf::from("/srv/web apache"));
        let nginx = HostConf {
            web_server: None,
            ..conf
        };
        assert_eq!(
            nginx.commands().unwrap().test,
            ["docker", "exec", "my web", "nginx", "-t"]
        );
    }

    /// Its NGINX is in the container NPMplus's compose file names, with
    /// the data directory that file mounts.
    #[test]
    fn npmplus_defaults_to_its_compose_files_container() {
        let npmplus = HostConf {
            web_server: Some(WebServer::Npmplus),
            ..HostConf::default()
        };
        let commands = npmplus.commands().unwrap();
        assert_eq!(commands.test, ["docker", "exec", "npmplus", "nginx", "-t"]);
        assert_eq!(
            commands.reload,
            ["docker", "exec", "npmplus", "nginx", "-s", "reload"]
        );
        assert_eq!(npmplus.root(None), PathBuf::from("/opt/npmplus"));
        assert!(
            !npmplus.config_paths_are_here(),
            "its config names the container's paths"
        );
    }

    #[test]
    fn traefik_runs_no_command_unless_given_one() {
        let traefik = HostConf {
            web_server: Some(WebServer::Traefik),
            ..HostConf::default()
        };
        let commands = traefik.commands().unwrap();
        assert!(
            commands.test.is_empty() && commands.reload.is_empty(),
            "Traefik reloads its file provider itself, but got {commands:?}"
        );
        assert_eq!(traefik.root(None), PathBuf::from("/etc/traefik/dynamic"));
        let restarted = HostConf {
            traefik_reload_command: Some("docker restart traefik".into()),
            ..traefik
        };
        assert_eq!(
            restarted.commands().unwrap().reload,
            ["docker", "restart", "traefik"]
        );
    }

    /// Root writes it and everyone reads it.
    #[test]
    fn the_file_is_written_world_readable_and_owner_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.conf");
        HostConf::default().save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "mode was {mode:o}");
    }

    /// A rename replaces a link; a write would follow it.
    #[test]
    fn a_link_at_the_name_is_replaced_not_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious\n").unwrap();
        let path = dir.path().join("host.conf");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        HostConf::default().save_to(&path).unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious\n");
        assert!(!std::fs::symlink_metadata(&path).unwrap().is_symlink());
    }

    #[test]
    fn a_file_with_mistakes_names_the_line() {
        for (text, needle) in [
            ("nginx_root /etc/nginx\n", "line 1 is not `key = value`"),
            ("\n# c\nnginx_rot = /etc/nginx\n", "line 3 sets `nginx_rot`"),
            (
                "ssh_log = /a\nssh_log = /b\n",
                "line 2 sets `ssh_log` a second time",
            ),
            ("nginx_root = etc/nginx\n", "not an absolute path"),
            ("nginx_test_command = nginx \"-t\n", "unbalanced quote"),
        ] {
            let err = format!("{:#}", HostConf::parse(text).unwrap_err());
            assert!(err.contains(needle), "{text:?} gave: {err}");
        }
    }

    #[test]
    fn an_empty_value_is_unset() {
        let conf = HostConf::parse("nginx_root =   \nssh_log=\n").unwrap();
        assert_eq!(conf, HostConf::default());
    }

    /// A value is one line of the file, so a line break inside one would
    /// write a second setting of the caller's choosing.
    #[test]
    fn a_value_with_a_line_break_is_refused_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let conf = HostConf {
            nginx_test_command: Some("nginx -t\nnginx_reload_command = touch /tmp/x".into()),
            ..HostConf::default()
        };
        assert!(conf.save_to(&dir.path().join("host.conf")).is_err());
        assert!(!dir.path().join("host.conf").exists());
    }

    #[test]
    fn the_settings_move_out_of_a_trusted_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        container_settings(&db);
        let path = dir.path().join("host.conf");

        let migrated = move_settings(&db, &path, uid()).unwrap();

        assert!(
            matches!(&migrated, Migrated::Created { moved, ignored } if moved.len() == 5 && ignored.is_empty()),
            "{migrated:?}"
        );
        let conf = HostConf::load_from(&path).unwrap();
        assert_eq!(
            conf.commands().unwrap().reload,
            ["docker", "exec", "web", "nginx", "-s", "reload"]
        );
        assert_eq!(conf.root(None), PathBuf::from("/srv/web/nginx"));
        assert_eq!(
            conf.access_log.as_deref(),
            Some(Path::new("/srv/web/logs/access.log"))
        );
        assert_eq!(conf.ssh_log.as_deref(), Some(Path::new("/var/log/secure")));
        for key in MIGRATED_KEYS {
            assert_eq!(
                db.get_text_setting(key).unwrap(),
                None,
                "{key} is still a row"
            );
        }
    }

    /// Run twice, the second finds the file and leaves everything alone —
    /// including a row that appeared since, which is never read again.
    #[test]
    fn migrating_twice_changes_nothing_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        container_settings(&db);
        let path = dir.path().join("host.conf");
        move_settings(&db, &path, uid()).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();

        db.set_text_setting(keys::NGINX_RELOAD_COMMAND, "touch /tmp/pwned")
            .unwrap();
        assert_eq!(
            move_settings(&db, &path, uid()).unwrap(),
            Migrated::AlreadyDone
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first);
        assert_eq!(
            HostConf::load_from(&path)
                .unwrap()
                .commands()
                .unwrap()
                .reload,
            ["docker", "exec", "web", "nginx", "-s", "reload"]
        );
    }

    /// Nothing to move still creates the file: from then on its existence
    /// is what says the rows are not to be read.
    #[test]
    fn a_database_with_nothing_to_move_still_gets_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        let path = dir.path().join("host.conf");

        let migrated = move_settings(&db, &path, uid()).unwrap();

        assert_eq!(
            migrated,
            Migrated::Created {
                moved: vec![],
                ignored: vec![]
            }
        );
        assert_eq!(migrated.note(&path), None, "nothing worth saying");
        assert_eq!(HostConf::load_from(&path).unwrap(), HostConf::default());
    }

    /// A database another user owns — the web console's, on a host a release
    /// with one set up: whatever it holds may have been written by an
    /// attacker, so nothing is copied.
    #[test]
    fn a_database_someone_else_owns_is_not_migrated_from() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        db.set_text_setting(keys::NGINX_RELOAD_COMMAND, "touch /tmp/pwned")
            .unwrap();
        let path = dir.path().join("host.conf");

        let migrated = move_settings(&db, &path, uid().wrapping_add(1)).unwrap();

        let Migrated::Created { moved, ignored } = &migrated else {
            panic!("{migrated:?}");
        };
        assert!(moved.is_empty(), "{moved:?}");
        assert_eq!(ignored.len(), 1, "{ignored:?}");
        assert_eq!(HostConf::load_from(&path).unwrap(), HostConf::default());
        assert_eq!(
            db.get_text_setting(keys::NGINX_RELOAD_COMMAND).unwrap(),
            None,
            "the row is deleted, so it cannot be migrated from later either"
        );
        let note = migrated.note(&path).unwrap();
        assert!(note.contains("set-web-server"), "{note}");
    }

    #[test]
    fn a_value_that_never_worked_is_not_moved() {
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        db.set_text_setting(keys::NGINX_TEST_COMMAND, "nginx \"-t")
            .unwrap();
        db.set_text_setting(keys::NGINX_ROOT, "/srv/nginx").unwrap();
        let path = dir.path().join("host.conf");

        let migrated = move_settings(&db, &path, uid()).unwrap();

        let conf = HostConf::load_from(&path).unwrap();
        assert_eq!(conf.nginx_test_command, None);
        assert_eq!(conf.nginx_root, Some(PathBuf::from("/srv/nginx")));
        assert!(
            matches!(&migrated, Migrated::Created { ignored, .. } if ignored.len() == 1),
            "{migrated:?}"
        );
    }

    #[test]
    fn an_unprivileged_process_never_migrates() {
        if crate::hint::is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = file_db(dir.path());
        container_settings(&db);
        let path = dir.path().join("host.conf");

        assert_eq!(migrate(&db, &path).unwrap(), Migrated::NotRoot);
        assert!(!path.exists());
        assert!(db.get_text_setting(keys::NGINX_ROOT).unwrap().is_some());
    }
}
