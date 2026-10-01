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

//! Root opening a database in a directory another user owns.
//!
//! Since the console runs as its own user, `/var/lib/stop-bots` and
//! everything in it belong to that user — and so, after a compromise of
//! the console, to whoever compromised it. Root still opens the database
//! there: the CLI, the TUI, `install web` and the privileged helper all
//! do. Every name in that directory is then the attacker's choice, and
//! a root process that follows one writes where they chose:
//!
//! - `db.sqlite3` as a link to `/etc/cron.d/x` that does not exist yet:
//!   SQLite resolves the link and creates a database there, as root, with
//!   rows the attacker wrote. That is a root shell at the next cron
//!   minute.
//! - `db.sqlite3-wal` as a link to a root file: the next write lands in
//!   it.
//! - `chmod`/`chown` by path on any of them: the link's target changes
//!   owner or mode instead.
//!
//! So a root process opening a database whose directory it does not own
//! is [`Guard`]ed:
//!
//! - the path is resolved up to the directory, which the attacker cannot
//!   replace because its parent is root's, and SQLite is opened with
//!   `SQLITE_OPEN_NOFOLLOW`, which refuses a link at the last component —
//!   and carries over to `VACUUM INTO`'s target, which is how the
//!   pre-upgrade copy is made. SQLite opens its `-wal`, `-shm` and
//!   `-journal` with `O_NOFOLLOW` whatever the flags;
//! - a database or companion that is a link, not a regular file, or has
//!   a second name is refused before SQLite sees it. A second name is how
//!   a hard link to a root file would look; `fs.protected_hardlinks`,
//!   which Debian and Ubuntu turn on, already stops anyone making one;
//! - a database root creates there is given to the directory's owner,
//!   and modes and owners are changed through a descriptor opened with
//!   `O_NOFOLLOW`, never by path.
//!
//! What it does not do is take anything back. Root opening the console's
//! database leaves it the console's: SQLite itself gives a `-wal` or
//! `-shm` it creates as root to the database file's owner, and the copy
//! an upgrade makes goes to that owner too (see `schema::backup`).

use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

/// SQLite's companions to a database file, by suffix.
pub const COMPANIONS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A root process opening a database in another user's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guard {
    /// The directory's owner, who gets a database root creates there.
    pub uid: u32,
    pub gid: u32,
}

impl Guard {
    /// The guard for opening `path` as `euid`, or `None` when nothing
    /// needs guarding: not root, or root's own directory.
    pub fn for_path(path: &Path, euid: u32) -> Option<Guard> {
        if euid != 0 {
            return None;
        }
        let dir = parent_of(path);
        // Followed, deliberately: the directory's own name is in a
        // directory root owns, so it is not the attacker's to replace.
        let meta = std::fs::metadata(dir).ok()?;
        (meta.uid() != 0).then_some(Guard {
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    /// The guard for this process.
    pub fn here(path: &Path) -> Option<Guard> {
        // SAFETY: no preconditions; reads the process's own credentials.
        Guard::for_path(path, unsafe { libc::geteuid() })
    }

    /// `path` with its directory resolved, so that `SQLITE_OPEN_NOFOLLOW`
    /// — which refuses a link anywhere in the path — refuses only one in
    /// the directory the attacker controls.
    pub fn resolve(&self, path: &Path) -> Result<PathBuf> {
        let dir = parent_of(path);
        let name = path
            .file_name()
            .with_context(|| format!("{} names no file", path.display()))?;
        Ok(std::fs::canonicalize(dir)
            .with_context(|| format!("failed to resolve {}", dir.display()))?
            .join(name))
    }

    /// Refuses `path` or a companion that is anything but a plain file
    /// with one name. A missing one is fine: SQLite creates it.
    pub fn check(&self, path: &Path) -> Result<()> {
        for file in with_companions(path) {
            let Ok(meta) = std::fs::symlink_metadata(&file) else {
                continue;
            };
            let problem = if meta.file_type().is_symlink() {
                "is a symbolic link"
            } else if !meta.is_file() {
                "is not a regular file"
            } else if meta.nlink() > 1 {
                "has another name (a hard link)"
            } else {
                continue;
            };
            anyhow::bail!(
                "refusing to open {} as root: {} {problem}, in a directory that belongs to \
                 uid {}. A link there could have root write wherever it points. If you made it, \
                 replace it with the file itself; if you did not, something that runs as that \
                 user put it there.",
                path.display(),
                file.display(),
                self.uid,
            );
        }
        Ok(())
    }
}

/// The directory `path` is in, `.` for a bare file name.
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// `path` and each of its [`COMPANIONS`].
pub fn with_companions(path: &Path) -> Vec<PathBuf> {
    let mut files = vec![path.to_path_buf()];
    for suffix in COMPANIONS {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        files.push(PathBuf::from(name));
    }
    files
}

/// A rusqlite connection to `path`, guarded as [`Guard::here`] says.
///
/// For the readers that must not go through `Db::open` because it would
/// migrate — `install web` reading a stored setting, `uninstall` reading
/// its plan — and that run as root on the console's directory all the
/// same.
pub fn open_connection(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let (path, flags) = match Guard::here(path) {
        Some(guard) => {
            guard.check(path)?;
            (
                guard.resolve(path)?,
                flags | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
        }
        None => (path.to_path_buf(), flags),
    };
    Connection::open_with_flags(&path, flags)
        .with_context(|| format!("failed to open {}", path.display()))
}

/// Opens `path` without following a link, for changing its owner or mode
/// through the descriptor. `None` if there is nothing there.
///
/// `O_NONBLOCK` so that a FIFO someone left in the name does not hang the
/// open; it is refused by the caller's file-type check either way.
pub fn open_nofollow(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Sets `mode` on the open `file`, through its descriptor.
pub fn fchmod(file: &std::fs::File, mode: u32) -> std::io::Result<()> {
    // SAFETY: a valid descriptor this function borrows for the call.
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Guard {
        let meta = std::fs::metadata(".").unwrap();
        Guard {
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }

    /// Only root needs the guard, and only in someone else's directory.
    #[test]
    fn only_root_in_another_users_directory_is_guarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        let owner = std::fs::metadata(dir.path()).unwrap().uid();

        assert_eq!(Guard::for_path(&path, 1234), None, "not root");
        let as_root = Guard::for_path(&path, 0);
        if owner == 0 {
            assert_eq!(as_root, None, "root's own directory");
        } else {
            assert_eq!(as_root.map(|guard| guard.uid), Some(owner));
        }
    }

    /// Every way a name in the console's directory could point root
    /// somewhere else is refused, for the database and each companion.
    #[test]
    fn a_link_or_a_second_name_is_refused() {
        for (what, make) in [
            (
                "a link to a file that is not there yet",
                &(|dir: &Path, name: &Path| {
                    std::os::unix::fs::symlink(dir.join("elsewhere"), name).unwrap()
                }) as &dyn Fn(&Path, &Path),
            ),
            ("a link to a file", &|dir: &Path, name: &Path| {
                std::fs::write(dir.join("target"), "x").unwrap();
                std::os::unix::fs::symlink(dir.join("target"), name).unwrap()
            }),
            ("a hard link", &|dir: &Path, name: &Path| {
                std::fs::write(dir.join("target"), "x").unwrap();
                std::fs::hard_link(dir.join("target"), name).unwrap()
            }),
            ("a directory", &|_: &Path, name: &Path| {
                std::fs::create_dir(name).unwrap()
            }),
        ] {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("db.sqlite3");
                make(dir.path(), &dir.path().join(format!("db.sqlite3{suffix}")));

                let err = me().check(&path).expect_err(what);

                assert!(
                    format!("{err:#}").contains(&format!("db.sqlite3{suffix}")),
                    "{what} at db.sqlite3{suffix}: {err:#}"
                );
            }
        }
    }

    #[test]
    fn plain_files_or_none_at_all_pass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        me().check(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::write(dir.path().join("db.sqlite3-wal"), "").unwrap();
        me().check(&path).unwrap();
    }

    /// The directory is resolved, so a link above it does not trip
    /// `SQLITE_OPEN_NOFOLLOW` — only one in the directory itself does.
    #[test]
    fn the_directory_is_resolved_and_the_file_name_kept() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("link")).unwrap();

        let resolved = me().resolve(&dir.path().join("link/db.sqlite3")).unwrap();

        assert_eq!(
            resolved,
            std::fs::canonicalize(dir.path().join("real"))
                .unwrap()
                .join("db.sqlite3")
        );
    }

    #[test]
    fn opening_without_following_refuses_a_link_and_finds_nothing_missing() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "x").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(open_nofollow(&link).is_err(), "followed a link");
        assert!(open_nofollow(&dir.path().join("missing"))
            .unwrap()
            .is_none());
        assert!(open_nofollow(&target).unwrap().is_some());
    }
}
