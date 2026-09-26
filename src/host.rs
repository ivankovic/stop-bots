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

//! This machine's host name, for the headers of both surfaces — and where
//! on it the system programs this project runs are (see [`program`]).
//!
//! Read once and cached: a host does not rename itself while a console is
//! open, the TUI's header redraws thirty times a second, and the web
//! console builds its chrome on every request. Both used to read
//! `/proc` themselves, the console twice per page.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static NAME: OnceLock<Option<String>> = OnceLock::new();

/// The host name as the kernel has it, or `None` when it cannot be read
/// — which is not an error anyone needs to hear about.
pub fn name() -> Option<&'static str> {
    NAME.get_or_init(|| {
        ["/proc/sys/kernel/hostname", "/etc/hostname"]
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
    })
    .as_deref()
}

/// Pins the name before it is first read. For the screenshot generator,
/// which must not put the maintainer's machine in the README; a no-op
/// once a header has been drawn.
pub fn override_name(name: &str) {
    let _ = NAME.set(Some(name.to_string()));
}

/// Where administrator tools live that a minimal `PATH` leaves out.
///
/// An `/etc/cron.d` entry runs with `PATH=/usr/bin:/bin`, and `nft` and
/// `iptables` are in `/usr/sbin`. Run by bare name from there, the apply
/// under `batch --apply` failed with "No such file or directory" — closed,
/// so nothing was applied, but also nothing was protected, every night.
const SBIN_DIRS: [&str; 3] = ["/usr/sbin", "/sbin", "/usr/local/sbin"];

/// The path to run for the system program `name`: the first executable
/// `name` on `PATH`, then in [`SBIN_DIRS`], else `name` itself so the
/// spawn fails with the error it always did.
///
/// `PATH` first, so a fake `nft` a test puts there, or an operator's own
/// wrapper, still wins — the fallback only ever adds places to look.
pub fn program(name: &str) -> PathBuf {
    find_program(name, std::env::var_os("PATH").as_deref(), &SBIN_DIRS)
}

/// `PATH` for a child that itself runs system programs by name — the
/// iptables script, whose every line is `iptables ...` — with whichever
/// of [`SBIN_DIRS`] it lacks appended.
pub fn path_with_sbin() -> OsString {
    extend_path(std::env::var_os("PATH").as_deref(), &SBIN_DIRS)
}

fn find_program(name: &str, path: Option<&OsStr>, fallbacks: &[&str]) -> PathBuf {
    if name.contains('/') {
        return PathBuf::from(name);
    }
    path.into_iter()
        .flat_map(std::env::split_paths)
        .chain(fallbacks.iter().map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn extend_path(path: Option<&OsStr>, extra: &[&str]) -> OsString {
    let mut dirs: Vec<PathBuf> = path
        .map(|p| std::env::split_paths(p).collect())
        .unwrap_or_default();
    for dir in extra {
        if !dirs.iter().any(|d| d == Path::new(dir)) {
            dirs.push(PathBuf::from(dir));
        }
    }
    // Only fails for a directory containing `:`, which none of these do
    // and which could not have come out of a `PATH` in the first place.
    std::env::join_paths(dirs).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The cron case: `PATH` has no sbin, and `nft` is only there.
    #[test]
    fn a_program_missing_from_path_is_found_in_sbin() {
        let path_dir = tempfile::tempdir().unwrap();
        let sbin = tempfile::tempdir().unwrap();
        let nft = executable(sbin.path(), "nft");
        let sbin_dir = sbin.path().to_str().unwrap();

        let found = find_program("nft", Some(path_dir.path().as_os_str()), &[sbin_dir]);

        assert_eq!(found, nft);
    }

    /// A fake on `PATH` — what the integration tests use — still wins.
    #[test]
    fn path_is_searched_before_the_fallbacks() {
        let path_dir = tempfile::tempdir().unwrap();
        let sbin = tempfile::tempdir().unwrap();
        let fake = executable(path_dir.path(), "nft");
        executable(sbin.path(), "nft");
        let sbin_dir = sbin.path().to_str().unwrap();

        let found = find_program("nft", Some(path_dir.path().as_os_str()), &[sbin_dir]);

        assert_eq!(found, fake);
    }

    #[test]
    fn a_file_that_is_not_executable_is_not_a_program() {
        let sbin = tempfile::tempdir().unwrap();
        std::fs::write(sbin.path().join("nft"), "").unwrap();
        let sbin_dir = sbin.path().to_str().unwrap();

        assert_eq!(find_program("nft", None, &[sbin_dir]), PathBuf::from("nft"));
    }

    /// Found nowhere: the bare name, so spawning it fails exactly as it
    /// always has, with the name in the error.
    #[test]
    fn a_program_found_nowhere_is_left_as_its_bare_name() {
        let empty = tempfile::tempdir().unwrap();
        let dir = empty.path().to_str().unwrap();

        assert_eq!(
            find_program("no-such-tool", Some(empty.path().as_os_str()), &[dir]),
            PathBuf::from("no-such-tool")
        );
    }

    #[test]
    fn the_extended_path_keeps_its_order_and_adds_only_what_is_missing() {
        let extended = extend_path(Some(OsStr::new("/usr/bin:/usr/sbin:/bin")), &SBIN_DIRS);

        assert_eq!(
            extended,
            OsString::from("/usr/bin:/usr/sbin:/bin:/sbin:/usr/local/sbin")
        );
    }
}
