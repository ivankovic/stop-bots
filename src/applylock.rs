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

//! One apply at a time, across every stop-bots process on the host.
//!
//! The TUI, the web console and a cron `batch --apply` can each rewrite
//! the NGINX config and run the firewall script, and nothing stopped two
//! of them doing it at once. Two NGINX applies interleaved can each take
//! the other's half-written file as the "before" it restores on a failed
//! `nginx -t`; two firewall scripts run together each flush and refill the
//! same table.
//!
//! [`hold`] takes an advisory `flock` on [`default_path`] and gives it
//! back when the guard drops, including when the process dies: the kernel
//! releases a `flock` with the last descriptor. A second process waits up
//! to [`WAIT`], then fails with [`Busy`], which says so in words.
//!
//! **Re-entrant within a thread.** A caller that holds the lock and then
//! calls something that takes it again gets a no-op guard rather than
//! waiting for itself: `flock` locks belong to the open file, so a second
//! `open` in the same process would conflict with the first. Other threads
//! in the same process do wait, which is what keeps two requests to the
//! console from applying at once.

use std::cell::Cell;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a second apply waits for the first before giving up.
///
/// Long enough for an ordinary apply — an `nginx -t` and a reload, or an
/// `nft -f` of a few thousand elements — to finish, so two that collide
/// by chance both succeed. Short enough that one stuck on a hung `docker
/// exec` is reported rather than waited on for ever.
pub const WAIT: Duration = Duration::from_secs(10);

/// How often a waiting apply tries again.
const POLL: Duration = Duration::from_millis(50);

thread_local! {
    /// How many guards this thread holds, so an inner [`hold`] is free.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// The lock, held until this is dropped.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct ApplyLock {
    // Kept only to keep the descriptor, and so the lock, open. `None` for
    // a nested guard, which holds nothing of its own.
    _file: Option<File>,
}

impl Drop for ApplyLock {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Another process held the lock for all of [`WAIT`].
#[derive(Debug)]
pub struct Busy {
    pub path: PathBuf,
    /// The holder's process id, as it wrote it into the file.
    pub holder: Option<u32>,
}

impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "another stop-bots is applying")?;
        if let Some(pid) = self.holder {
            write!(f, " (process {pid})")?;
        }
        write!(
            f,
            " and has not finished; nothing was applied. Try again once it has \
             (the lock is {})",
            self.path.display()
        )
    }
}

impl std::error::Error for Busy {}

/// Where the lock lives.
///
/// `/run/stop-bots.lock` for root, which is every process that can apply
/// anything for real: the unit, a root crontab and `sudo stop-bots` all
/// meet there. `/run` is a tmpfs, so a lock file never outlives a boot,
/// and the unit's `ProtectSystem=yes` leaves it writable.
///
/// Anyone else gets a path of their own — `$XDG_RUNTIME_DIR`, or the temp
/// directory — because they cannot create files in `/run`, and because a
/// file another user could create first is a file they could hold for
/// ever.
pub fn default_path() -> PathBuf {
    // SAFETY: no preconditions; reads the process's own credentials.
    let euid = unsafe { libc::geteuid() };
    path_for(
        euid,
        std::env::var_os("XDG_RUNTIME_DIR"),
        std::env::temp_dir(),
    )
}

fn path_for(euid: u32, runtime_dir: Option<std::ffi::OsString>, temp: PathBuf) -> PathBuf {
    if euid == 0 {
        return PathBuf::from("/run/stop-bots.lock");
    }
    match runtime_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir).join("stop-bots.lock"),
        None => temp.join(format!("stop-bots-{euid}.lock")),
    }
}

/// Takes the lock at [`default_path`], waiting up to [`WAIT`].
pub fn hold() -> anyhow::Result<ApplyLock> {
    hold_at(&default_path(), WAIT)
}

/// Takes the lock at `path`, waiting up to `wait` for another holder.
///
/// A lock file that cannot be opened at all — no `/run`, a read-only
/// filesystem — does not stop the apply: it proceeds unlocked, as every
/// release before this one did. Refusing to change the firewall because
/// a coordination file is missing would be the worse failure.
pub fn hold_at(path: &Path, wait: Duration) -> anyhow::Result<ApplyLock> {
    if DEPTH.with(Cell::get) > 0 {
        DEPTH.with(|depth| depth.set(depth.get() + 1));
        return Ok(ApplyLock { _file: None });
    }
    let file = match open(path) {
        Ok(file) => file,
        Err(_) => {
            DEPTH.with(|depth| depth.set(1));
            return Ok(ApplyLock { _file: None });
        }
    };
    let deadline = Instant::now() + wait;
    loop {
        if try_lock(&file) {
            break;
        }
        if Instant::now() >= deadline {
            return Err(Busy {
                path: path.to_path_buf(),
                holder: std::fs::read_to_string(path)
                    .ok()
                    .and_then(|text| text.trim().parse().ok()),
            }
            .into());
        }
        std::thread::sleep(POLL);
    }
    record_holder(&file);
    DEPTH.with(|depth| depth.set(1));
    Ok(ApplyLock { _file: Some(file) })
}

fn open(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

fn try_lock(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid descriptor, owned by `file` for the whole call.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Writes this process's id into the file, for the next one's [`Busy`].
/// Best effort: the lock is the `flock`, not the contents.
fn record_holder(file: &File) {
    use std::io::{Seek, Write};
    let mut file = file;
    let _ = file.set_len(0);
    let _ = file.seek(std::io::SeekFrom::Start(0));
    let _ = write!(file, "{}", std::process::id());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second holder in another thread is what another process looks
    /// like to `flock`: a different open file on the same path.
    fn held_elsewhere(path: &Path) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (taken, is_taken) = std::sync::mpsc::channel();
        let path = path.to_path_buf();
        let handle = std::thread::spawn(move || {
            let _lock = hold_at(&path, Duration::ZERO).unwrap();
            taken.send(()).unwrap();
            let _ = released.recv();
        });
        is_taken.recv().unwrap();
        (release, handle)
    }

    #[test]
    fn a_second_apply_is_refused_in_words_while_the_first_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stop-bots.lock");
        let (release, handle) = held_elsewhere(&path);

        let err = hold_at(&path, Duration::from_millis(60))
            .err()
            .expect("the lock was taken twice");

        let busy = err.downcast_ref::<Busy>().expect("not a Busy error");
        assert_eq!(busy.holder, Some(std::process::id()));
        let text = err.to_string();
        assert!(
            text.contains("another stop-bots is applying"),
            "the refusal does not say why: {text}"
        );
        release.send(()).unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn a_waiting_apply_proceeds_once_the_first_lets_go() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stop-bots.lock");
        let (release, handle) = held_elsewhere(&path);

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            release.send(()).unwrap();
        });
        let lock = hold_at(&path, Duration::from_millis(250));

        assert!(lock.is_ok(), "waited, and still did not get the lock");
        releaser.join().unwrap();
        handle.join().unwrap();
    }

    /// The unified apply may hold the lock and call `apply_script`, which
    /// takes it too. Without re-entrancy that waits on itself and fails.
    #[test]
    fn taking_the_lock_again_on_the_same_thread_does_not_wait_for_itself() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stop-bots.lock");

        let outer = hold_at(&path, Duration::ZERO).unwrap();
        let inner = hold_at(&path, Duration::ZERO);
        assert!(inner.is_ok(), "the thread waited for its own lock");
        drop(inner);
        drop(outer);

        // And both are gone: another thread gets it at once.
        let path_again = path.clone();
        let got = std::thread::spawn(move || hold_at(&path_again, Duration::ZERO).is_ok())
            .join()
            .unwrap();
        assert!(got, "the lock outlived its guards");
    }

    #[test]
    fn a_lock_file_that_cannot_be_created_does_not_stop_the_apply() {
        let lock = hold_at(Path::new("/nonexistent/dir/stop-bots.lock"), WAIT);
        assert!(lock.is_ok());
    }

    #[test]
    fn root_locks_in_run_and_everyone_else_somewhere_of_their_own() {
        let tmp = PathBuf::from("/tmp");
        for (what, euid, runtime, expected) in [
            ("root", 0, Some("/run/user/0"), "/run/stop-bots.lock"),
            (
                "a user session",
                1000,
                Some("/run/user/1000"),
                "/run/user/1000/stop-bots.lock",
            ),
            ("no session", 1000, None, "/tmp/stop-bots-1000.lock"),
            (
                "an empty runtime dir",
                1000,
                Some(""),
                "/tmp/stop-bots-1000.lock",
            ),
        ] {
            assert_eq!(
                path_for(euid, runtime.map(Into::into), tmp.clone()),
                PathBuf::from(expected),
                "{what}"
            );
        }
    }
}
