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

//! The host's own settings, in `/etc/stop-bots/host.conf`.
//!
//! Five settings say what root runs and where root writes and reads: the
//! NGINX test and reload commands, the NGINX config root, and the two
//! logs. They used to be rows in the database (`nginx:test_command`,
//! `nginx:reload_command`, `nginx:root`, `logs:access_path`,
//! `logs:ssh_path`), and the web console can write every row of the
//! database. Once the console runs as its own unprivileged user, a row it
//! wrote must not decide what a root process executes, so these live in a
//! file only root can write. The console reads it to show the values and
//! to find the logs it reads itself; nothing it does can change it.
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
//! migrates. And a database that is not root's — the console's, once it
//! runs as its own user — is not trusted to migrate from at all: its rows
//! may have been written by whoever compromised the console.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::db::{keys, Db};
use crate::logpaths::LogPaths;
use crate::nginx::NginxCommands;

/// Where the file lives.
pub const DEFAULT_PATH: &str = "/etc/stop-bots/host.conf";

/// Environment override for [`DEFAULT_PATH`], for the end-to-end tests,
/// which drive the real binary and must not read or write `/etc`. The
/// same test-only rationale as `nginx::MANAGED_DIR_ENV`.
pub const PATH_ENV: &str = "STOP_BOTS_HOST_CONF";

/// The file this process reads and writes.
pub fn path() -> PathBuf {
    std::env::var_os(PATH_ENV)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

const NGINX_TEST: &str = "nginx_test_command";
const NGINX_RELOAD: &str = "nginx_reload_command";
const NGINX_ROOT: &str = "nginx_root";
const ACCESS_LOG: &str = "access_log";
const SSH_LOG: &str = "ssh_log";

/// The host settings. `None` for any of them means "not set": the
/// built-in default, as it was when nothing was stored in the database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostConf {
    /// How to test the NGINX config, as one command line split by
    /// [`crate::nginx::split_command`]. Never through a shell.
    pub nginx_test_command: Option<String>,
    /// How to reload NGINX, the same way.
    pub nginx_reload_command: Option<String>,
    /// Where NGINX's config lives.
    pub nginx_root: Option<PathBuf>,
    /// The NGINX access log.
    pub access_log: Option<PathBuf>,
    /// The SSH log, which the lockout guard reads.
    pub ssh_log: Option<PathBuf>,
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
                NGINX_TEST => conf.nginx_test_command = value,
                NGINX_RELOAD => conf.nginx_reload_command = value,
                NGINX_ROOT => conf.nginx_root = value.map(PathBuf::from),
                ACCESS_LOG => conf.access_log = value.map(PathBuf::from),
                SSH_LOG => conf.ssh_log = value.map(PathBuf::from),
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
        for command in [&self.nginx_test_command, &self.nginx_reload_command]
            .into_iter()
            .flatten()
        {
            no_control_characters(command)?;
            crate::nginx::split_command(command)?;
        }
        for path in [&self.nginx_root, &self.access_log, &self.ssh_log]
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
            "# stop-bots host settings. Written by `stop-bots set-nginx-commands`\n\
             # and `stop-bots set-log-paths`; read by every stop-bots process.\n\
             # Only root may change this file: the web console reads it and\n\
             # cannot write it.\n",
        );
        let lines = [
            (NGINX_TEST, self.nginx_test_command.clone()),
            (NGINX_RELOAD, self.nginx_reload_command.clone()),
            (NGINX_ROOT, path_text(&self.nginx_root)),
            (ACCESS_LOG, path_text(&self.access_log)),
            (SSH_LOG, path_text(&self.ssh_log)),
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

    /// The NGINX commands, each falling back to its default.
    pub fn commands(&self) -> Result<NginxCommands> {
        let command = |raw: &Option<String>, key: &str, fallback: &str| -> Result<Vec<String>> {
            crate::nginx::split_command(raw.as_deref().unwrap_or(fallback))
                .with_context(|| format!("the host setting `{key}` is not a valid command"))
        };
        Ok(NginxCommands {
            test: command(
                &self.nginx_test_command,
                NGINX_TEST,
                NginxCommands::DEFAULT_TEST,
            )?,
            reload: command(
                &self.nginx_reload_command,
                NGINX_RELOAD,
                NginxCommands::DEFAULT_RELOAD,
            )?,
        })
    }

    /// Where NGINX's config is: `flag` if given, else the setting, else
    /// the stock path.
    pub fn root(&self, flag: Option<&Path>) -> PathBuf {
        flag.map(Path::to_path_buf)
            .or_else(|| self.nginx_root.clone())
            .unwrap_or_else(|| PathBuf::from(crate::nginx::DEFAULT_ROOT))
    }

    /// The two log paths, as [`LogPaths`] resolves them.
    pub fn log_paths(&self) -> LogPaths {
        LogPaths {
            access: self.access_log.clone(),
            ssh: self.ssh_log.clone(),
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

/// [`migrate`] into [`path`], then the settings as they now are: what
/// `install web` calls before it hands the database to the console's user,
/// after which nothing may migrate from it.
pub fn migrate_from_db_if_absent(db: &Db) -> Result<HostConf> {
    migrate_from_db_if_absent_at(db, &path())
}

/// [`migrate_from_db_if_absent`], for the file at `host_conf` (a tree
/// under `install web --prefix`).
pub fn migrate_from_db_if_absent_at(db: &Db, host_conf: &Path) -> Result<HostConf> {
    let migrated = migrate(db, host_conf)?;
    if let Some(note) = migrated.note(host_conf) {
        crate::say_err!("{note}");
    }
    HostConf::load_from(host_conf)
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
/// `trusted_owner`. A database the console's user owns, or sits in a
/// directory it owns and could have swapped the file in, may hold rows the
/// console wrote: those are deleted, never copied.
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
                    "set-nginx-commands"
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
            "{} belongs to uid {}, not {owner}, so its rows may have been written by the web \
             console",
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
        assert_eq!(conf.commands().unwrap(), NginxCommands::default());
        assert_eq!(conf.root(None), PathBuf::from(crate::nginx::DEFAULT_ROOT));
    }

    #[test]
    fn what_is_saved_is_what_is_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc/host.conf");
        let conf = HostConf {
            nginx_test_command: Some("docker exec \"my web\" nginx -t".into()),
            nginx_reload_command: Some("docker exec web nginx -s reload".into()),
            nginx_root: Some("/srv/web nginx".into()),
            access_log: Some("/srv/logs/access.log".into()),
            ssh_log: None,
        };
        conf.save_to(&path).unwrap();
        assert_eq!(HostConf::load_from(&path).unwrap(), conf);
        assert_eq!(
            conf.commands().unwrap().test,
            ["docker", "exec", "my web", "nginx", "-t"]
        );
    }

    /// Root writes it and everyone, the console included, reads it.
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

    /// The console's database, once it runs as its own user: whatever it
    /// holds may have been written by an attacker, so nothing is copied.
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
        assert!(note.contains("set-nginx-commands"), "{note}");
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
