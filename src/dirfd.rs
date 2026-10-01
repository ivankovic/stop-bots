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

//! A file reached through a descriptor of its directory, never by its
//! path.
//!
//! Root removes, reads and puts back generated NGINX files whose paths
//! come from `managed_files`, a table the web console can write. A path
//! checked and then used by name can mean two different files: when one
//! of its directories belongs to the console, the console can make it a
//! link to somewhere else between the check and the use, and root then
//! deletes, or writes back, a file there.
//!
//! So a [`DirFile`] holds its directory open from the moment it is
//! checked. The directory is opened one component at a time with
//! `O_NOFOLLOW`, so the walk follows no link; and every later use is
//! `openat`, `unlinkat` or `renameat` relative to that descriptor, so a
//! name swapped afterwards changes nothing about which directory is used.
//! Files are opened with `O_NOFOLLOW | O_NONBLOCK` and checked to be
//! regular through the descriptor before a byte is read: a link is not
//! followed, and a FIFO does not hang the read.

use std::ffi::{CString, OsStr};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// A file `name` in a directory held open by descriptor.
///
/// Cloning shares the descriptor. [`DirFile::path`] is what it is called
/// in messages, and what the record knows it by; it is never opened.
#[derive(Debug, Clone)]
pub struct DirFile {
    path: PathBuf,
    dir: Arc<OwnedFd>,
    name: CString,
}

impl PartialEq for DirFile {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl DirFile {
    /// The file at `path`, with its directory resolved (links and all) and
    /// then held open. `Ok(None)` when the directory is not there, in
    /// which case neither is the file.
    ///
    /// For paths this program derives from its own settings, which may
    /// legitimately run through a link (`/etc/nginx` linked elsewhere).
    pub fn locate(path: &Path) -> io::Result<Option<DirFile>> {
        let (dir, name) = split(path)?;
        let resolved = match std::fs::canonicalize(dir) {
            Ok(resolved) => resolved,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        DirFile::in_dir(resolved, name).map(Some)
    }

    /// The file at `path` only if `path` is already resolved: absolute,
    /// with no `.`, `..` or link anywhere in its directory.
    ///
    /// For a path read from the database. A recorded path that runs
    /// through a link is refused rather than resolved, because the link is
    /// the attacker's: what it resolves to when checked and when used need
    /// not be the same.
    pub fn exactly(path: &Path) -> io::Result<DirFile> {
        let (dir, name) = split(path)?;
        let resolved = std::fs::canonicalize(dir)?;
        if resolved != dir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not a resolved path: its directory is {}",
                    path.display(),
                    resolved.display()
                ),
            ));
        }
        DirFile::in_dir(resolved, name)
    }

    fn in_dir(dir: PathBuf, name: &OsStr) -> io::Result<DirFile> {
        let fd = open_dir_nofollow(&dir)?;
        Ok(DirFile {
            path: dir.join(name),
            dir: Arc::new(fd),
            name: c_name(name)?,
        })
    }

    /// The path it was found at: its resolved directory and its name.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The resolved directory it is in.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or(Path::new("/"))
    }

    /// The file's own status, not following a link. `None` if there is
    /// nothing by that name.
    fn lstat(&self) -> io::Result<Option<libc::stat>> {
        // SAFETY: zeroed is a valid `stat`; the kernel fills it in.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor, a NUL-terminated name and a `stat`
        // this function owns, for the length of the call.
        let rc = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            return Ok(Some(stat));
        }
        match io::Error::last_os_error() {
            err if err.kind() == io::ErrorKind::NotFound => Ok(None),
            err => Err(err),
        }
    }

    /// Whether a plain file is there: not a link, a FIFO or a directory.
    pub fn is_regular(&self) -> bool {
        matches!(self.lstat(), Ok(Some(stat)) if stat.st_mode & libc::S_IFMT == libc::S_IFREG)
    }

    /// The file, opened for reading if it is a regular file. `None` for
    /// nothing there, a link, or anything but a regular file.
    fn open_regular(&self) -> io::Result<Option<std::fs::File>> {
        // SAFETY: a valid descriptor and a NUL-terminated name.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ENOENT) | Some(libc::ELOOP) | Some(libc::ENXIO) => Ok(None),
                _ => Err(err),
            };
        }
        // SAFETY: a descriptor `openat` just returned, owned from here.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(file.metadata()?.is_file().then_some(file))
    }

    /// The contents and permission bits of the regular file there, or
    /// `None` if there is none.
    pub fn read(&self) -> io::Result<Option<(Vec<u8>, u32)>> {
        let Some(mut file) = self.open_regular()? else {
            return Ok(None);
        };
        let mode = file.metadata()?.mode() & 0o7777;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some((bytes, mode)))
    }

    /// The regular file's contents as text, if there is one and it is.
    pub fn read_to_string(&self) -> Option<String> {
        let (bytes, _) = self.read().ok()??;
        String::from_utf8(bytes).ok()
    }

    /// The regular file's first line, read no further than 4 KiB.
    pub fn first_line(&self) -> Option<String> {
        use std::io::BufRead;
        let file = self.open_regular().ok()??;
        let mut line = String::new();
        std::io::BufReader::new(file.take(4096))
            .read_line(&mut line)
            .ok()?;
        Some(line)
    }

    /// Removes whatever is there by this name (a link itself, not what it
    /// points at). `false` if there was nothing.
    pub fn remove(&self) -> io::Result<bool> {
        // SAFETY: a valid descriptor and a NUL-terminated name.
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0) } == 0 {
            return Ok(true);
        }
        match io::Error::last_os_error() {
            err if err.kind() == io::ErrorKind::NotFound => Ok(false),
            err => Err(err),
        }
    }

    /// Replaces the file with `content` and `mode`: a new file beside it,
    /// created with `O_EXCL`, renamed over it. A link there is replaced,
    /// not written through.
    pub fn write_atomically(&self, content: &[u8], mode: u32) -> io::Result<()> {
        let dir = self.dir.as_raw_fd();
        let name = OsStr::from_bytes(self.name.as_bytes()).to_string_lossy();
        for _ in 0..8 {
            let temp = c_name(OsStr::new(&format!(
                ".{name}.stop-bots-{:016x}",
                crate::nginx::random_u64()
            )))?;
            // SAFETY: a valid descriptor and a NUL-terminated name.
            let fd = unsafe {
                libc::openat(
                    dir,
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                )
            };
            if fd < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(err);
            }
            // SAFETY: a descriptor `openat` just returned, owned from here.
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
            let written = (|| -> io::Result<()> {
                file.write_all(content)?;
                crate::db::guard::fchmod(&file, mode)?;
                file.sync_all()?;
                // SAFETY: valid descriptors and NUL-terminated names.
                if unsafe { libc::renameat(dir, temp.as_ptr(), dir, self.name.as_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            if written.is_err() {
                // SAFETY: as above.
                unsafe { libc::unlinkat(dir, temp.as_ptr(), 0) };
            }
            return written;
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a temporary file beside it",
        ))
    }
}

/// `path`'s directory and its file name. A path ending in `..`, or with
/// no directory, has neither.
fn split(path: &Path) -> io::Result<(&Path, &OsStr)> {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) if !dir.as_os_str().is_empty() => Ok((dir, name)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} does not name a file in a directory", path.display()),
        )),
    }
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a file name with a NUL byte in it",
        )
    })
}

/// Opens the directory at `path`, which must be absolute and resolved,
/// one component at a time with `O_NOFOLLOW`: a link anywhere in it fails
/// the open rather than being followed, whatever it was when `path` was
/// resolved. `O_PATH`, so a directory that may only be searched can still
/// be held.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let mut held: Option<OwnedFd> = None;
    for component in path.components() {
        let (base, name) = match (component, &held) {
            (Component::RootDir, None) => (libc::AT_FDCWD, c_name(OsStr::new("/"))?),
            (Component::Normal(name), Some(dir)) => (dir.as_raw_fd(), c_name(name)?),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not an absolute, resolved path", path.display()),
                ))
            }
        };
        // SAFETY: a valid descriptor (or AT_FDCWD) and a NUL-terminated name.
        let fd = unsafe { libc::openat(base, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor `openat` just returned, owned from here.
        held = Some(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    held.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "an empty path"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let real = fs::canonicalize(dir.path()).unwrap();
        (dir, real)
    }

    #[test]
    fn a_link_anywhere_in_the_directory_fails_the_walk() {
        let (_dir, base) = tree();
        fs::create_dir(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        fs::create_dir(base.join("real/inner")).unwrap();

        assert!(open_dir_nofollow(&base.join("real/inner")).is_ok());
        assert!(open_dir_nofollow(&base.join("link/inner")).is_err());
        assert!(open_dir_nofollow(&base.join("link")).is_err());
        assert!(open_dir_nofollow(&base.join("real/../real")).is_err());
        assert!(open_dir_nofollow(Path::new("relative")).is_err());
    }

    /// A recorded path is taken only as it stands: one through a link,
    /// or with `..` in it, is refused even though it leads somewhere real.
    #[test]
    fn exactly_refuses_a_path_that_is_not_already_resolved() {
        let (_dir, base) = tree();
        fs::create_dir(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();

        assert!(DirFile::exactly(&base.join("real/f")).is_ok());
        for path in [
            base.join("link/f"),
            base.join("real/../real/f"),
            PathBuf::from("f"),
        ] {
            assert!(
                DirFile::exactly(&path).is_err(),
                "{} was taken",
                path.display()
            );
        }
        let located = DirFile::locate(&base.join("link/f")).unwrap().unwrap();
        assert_eq!(located.path(), base.join("real/f"));
    }

    /// **Checked once, used through the descriptor.** The directory the
    /// file was found in is swapped for a link to another after the check:
    /// the read, the write and the removal all still happen in the first.
    #[test]
    fn swapping_the_directory_after_the_check_changes_nothing() {
        let (_dir, base) = tree();
        fs::create_dir(base.join("conf.d")).unwrap();
        fs::write(base.join("conf.d/f"), "ours\n").unwrap();
        fs::create_dir(base.join("victim")).unwrap();
        fs::write(base.join("victim/f"), "precious\n").unwrap();

        let file = DirFile::exactly(&base.join("conf.d/f")).unwrap();
        fs::rename(base.join("conf.d"), base.join("moved")).unwrap();
        std::os::unix::fs::symlink(base.join("victim"), base.join("conf.d")).unwrap();

        assert_eq!(file.read_to_string().as_deref(), Some("ours\n"));
        file.write_atomically(b"written\n", 0o644).unwrap();
        assert_eq!(
            fs::read_to_string(base.join("moved/f")).unwrap(),
            "written\n"
        );
        assert!(file.remove().unwrap());
        assert!(!base.join("moved/f").exists());
        assert_eq!(
            fs::read_to_string(base.join("victim/f")).unwrap(),
            "precious\n"
        );
    }

    /// A FIFO is not read (nor waited on), a link is not followed, and a
    /// directory is not a file.
    #[test]
    fn only_a_regular_file_is_read() {
        let (_dir, base) = tree();
        crate::testing::mkfifo(&base.join("fifo"));
        fs::write(base.join("target"), "secret\n").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("link")).unwrap();
        fs::create_dir(base.join("dir")).unwrap();

        for name in ["fifo", "link", "dir", "missing"] {
            let file = DirFile::exactly(&base.join(name)).unwrap();
            assert!(!file.is_regular(), "{name} is regular");
            assert_eq!(file.read().unwrap(), None, "{name} was read");
            assert_eq!(file.first_line(), None, "{name} was read");
        }
        let target = DirFile::exactly(&base.join("target")).unwrap();
        assert!(target.is_regular());
        assert_eq!(target.first_line().as_deref(), Some("secret\n"));
    }

    #[test]
    fn a_write_replaces_a_link_instead_of_following_it() {
        let (_dir, base) = tree();
        fs::write(base.join("target"), "precious\n").unwrap();
        std::os::unix::fs::symlink(base.join("target"), base.join("f")).unwrap();

        DirFile::exactly(&base.join("f"))
            .unwrap()
            .write_atomically(b"ours\n", 0o640)
            .unwrap();

        assert_eq!(
            fs::read_to_string(base.join("target")).unwrap(),
            "precious\n"
        );
        let meta = fs::symlink_metadata(base.join("f")).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o640);
    }
}
