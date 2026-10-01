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

//! The account the web console runs as, and what that account can read.
//!
//! Since 0.1 the console is not root: it runs as the `stop-bots` system
//! user, which `install web` creates, and reaches the logs through the
//! groups its unit adds (`SupplementaryGroups=`), not through membership
//! written into `/etc/group`. Two reasons for the unit rather than the
//! group file: the membership then holds for the console and nothing else
//! running as that user, and `uninstall` has nothing in `/etc/group` to
//! undo.
//!
//! Which groups, on the two distributions the README names:
//!
//! - `adm` owns `/var/log/nginx/*.log` (`www-data:adm 0640`) and
//!   `/var/log/auth.log` where rsyslog writes one (`root:adm` on Debian,
//!   `syslog:adm` on Ubuntu), and is granted the journal by systemd's own
//!   ACL on `/var/log/journal`.
//! - `systemd-journal` owns the journal files themselves (`0640`). Named as
//!   well because the ACL is something an operator can remove, and the
//!   group is what `journalctl`'s own documentation says to use. Only if
//!   the group exists: a unit naming a group that does not fails to start.
//!
//! [`readable_by`] answers "could the console read this?" from root, where
//! simply trying would always succeed — honouring POSIX ACLs, because the
//! journal's access for `adm` is one.

use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The console's user and group.
pub const USER: &str = "stop-bots";

/// The groups the console's unit adds for reading the logs, in the order
/// the unit names them. See the module docs.
pub const LOG_GROUPS: [&str; 2] = ["adm", "systemd-journal"];

/// A user, as the passwd database has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    /// The primary group.
    pub gid: u32,
}

/// `name` in the passwd database, or `None` if there is no such user.
pub fn user(name: &str) -> Option<Account> {
    let name = CString::new(name).ok()?;
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value for getpwnam_r to fill.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf` outlives it.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut found,
        )
    };
    (rc == 0 && !found.is_null()).then_some(Account {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
    })
}

/// The id of group `name`, or `None` if there is no such group.
pub fn group(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    // SAFETY: an all-zero group is a valid value for getgrnam_r to fill.
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf` outlives it.
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut entry,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut found,
        )
    };
    (rc == 0 && !found.is_null()).then_some(entry.gr_gid)
}

/// The name of user `uid`, or the number if it has none.
pub fn user_name(uid: u32) -> String {
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value for getpwuid_r to fill.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call and `buf` outlives it.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        return uid.to_string();
    }
    // SAFETY: getpwuid_r succeeded, so pw_name is a NUL-terminated string in `buf`.
    unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_string_lossy()
        .into_owned()
}

/// Who is asking, for [`readable_by`]: a uid, its primary group and its
/// supplementary groups.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub uid: u32,
    pub gids: Vec<u32>,
}

/// Whether `who` could read `path`: search permission on every directory
/// on the way, and read permission on the file. `None` when that cannot
/// be told, such as for a path that is not there.
///
/// Computed from modes and ACLs rather than tried, because the caller is
/// root, for whom trying always works.
pub fn readable_by(path: &Path, who: &Identity) -> Option<bool> {
    if who.uid == 0 {
        return Some(true);
    }
    let mut dir = std::path::PathBuf::new();
    let components: Vec<_> = path.components().collect();
    let (last, ancestors) = components.split_last()?;
    for component in ancestors {
        dir.push(component);
        if !allows(&dir, who, 0o1)? {
            return Some(false);
        }
    }
    dir.push(last);
    allows(&dir, who, 0o4)
}

/// Whether `who` has every bit of `want` (`r` 4, `w` 2, `x` 1) on `path`.
fn allows(path: &Path, who: &Identity, want: u32) -> Option<bool> {
    let meta = std::fs::metadata(path).ok()?;
    let acl = access_acl(path);
    Some(permits(
        meta.mode(),
        meta.uid(),
        meta.gid(),
        acl.as_deref(),
        who,
        want,
    ))
}

/// POSIX ACL tags, as the kernel stores them in `system.posix_acl_access`.
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;

/// One entry of an access ACL: (tag, permission bits, id).
type AclEntry = (u16, u32, u32);

/// The access ACL on `path`, if it has one beyond its mode.
fn access_acl(path: &Path) -> Option<Vec<AclEntry>> {
    use std::os::unix::ffi::OsStrExt;
    let name = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: both strings are NUL-terminated, and `buf` is valid for its length.
    let len = unsafe {
        libc::getxattr(
            name.as_ptr(),
            c"system.posix_acl_access".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if len < 0 {
        return None;
    }
    parse_acl(&buf[..len as usize])
}

/// The kernel's ACL format: a version (2), then 8-byte entries of tag,
/// permissions and id, little-endian.
fn parse_acl(bytes: &[u8]) -> Option<Vec<AclEntry>> {
    let (version, entries) = bytes.split_at_checked(4)?;
    if u32::from_le_bytes(version.try_into().ok()?) != 2 || entries.len() % 8 != 0 {
        return None;
    }
    Some(
        entries
            .chunks_exact(8)
            .map(|entry| {
                (
                    u16::from_le_bytes([entry[0], entry[1]]),
                    u32::from(u16::from_le_bytes([entry[2], entry[3]])),
                    u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
                )
            })
            .collect(),
    )
}

/// The kernel's access check, for one file, without root's override.
///
/// With an ACL, the mode's group bits are its mask, which limits every
/// named entry and the owning group alike; the owner and "other" are
/// always the mode's.
fn permits(
    mode: u32,
    owner: u32,
    group: u32,
    acl: Option<&[AclEntry]>,
    who: &Identity,
    want: u32,
) -> bool {
    let has = |bits: u32| bits & want == want;
    if who.uid == owner {
        return has((mode >> 6) & 7);
    }
    let group_bits = (mode >> 3) & 7;
    let Some(acl) = acl else {
        if who.gids.contains(&group) {
            return has(group_bits);
        }
        return has(mode & 7);
    };
    let mask = acl
        .iter()
        .find(|(tag, _, _)| *tag == ACL_MASK)
        .map_or(group_bits, |(_, perm, _)| *perm);
    if let Some((_, perm, _)) = acl
        .iter()
        .find(|(tag, _, id)| *tag == ACL_USER && *id == who.uid)
    {
        return has(perm & mask);
    }
    // The owning group's entry is the mode's group bits only when there
    // is no mask; with one, it is stored as its own entry.
    let owning_group = acl
        .iter()
        .find(|(tag, _, _)| *tag == ACL_GROUP_OBJ)
        .map_or(group_bits, |(_, perm, _)| *perm);
    let mut matched = false;
    if who.gids.contains(&group) {
        matched = true;
        if has(owning_group & mask) {
            return true;
        }
    }
    for (_, perm, _) in acl
        .iter()
        .filter(|(tag, _, id)| *tag == ACL_GROUP && who.gids.contains(id))
    {
        matched = true;
        if has(perm & mask) {
            return true;
        }
    }
    if matched {
        return false;
    }
    has(mode & 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn console(gids: &[u32]) -> Identity {
        Identity {
            uid: 999,
            gids: gids.to_vec(),
        }
    }

    /// The cases the console meets: NGINX's and rsyslog's logs, which
    /// `adm` reads, and anything else it must be told it cannot.
    #[test]
    fn the_mode_decides_for_owner_group_and_everyone_else() {
        const ADM: u32 = 4;
        for (what, mode, owner, group, who, readable) in [
            (
                "an nginx log, through adm",
                0o640,
                33,
                ADM,
                console(&[999, ADM]),
                true,
            ),
            (
                "an nginx log, without adm",
                0o640,
                33,
                ADM,
                console(&[999]),
                false,
            ),
            ("its own file", 0o600, 999, 999, console(&[999]), true),
            ("a world-readable file", 0o644, 0, 0, console(&[999]), true),
            // The owner's bits apply to the owner even when the group's
            // would have allowed more.
            (
                "owner without read",
                0o040,
                999,
                ADM,
                console(&[999, ADM]),
                false,
            ),
            // A matching group decides, even if "other" would allow.
            (
                "group without read",
                0o604,
                0,
                ADM,
                console(&[999, ADM]),
                false,
            ),
        ] {
            assert_eq!(
                permits(mode, owner, group, None, &who, 4),
                readable,
                "{what}"
            );
        }
    }

    /// systemd's own ACL on `/var/log/journal` is how `adm` reads the
    /// journal, and the mask limits every named entry.
    #[test]
    fn an_acl_grants_a_named_group_within_its_mask() {
        const ADM: u32 = 4;
        const JOURNAL: u32 = 101;
        let acl = |mask: u32| -> Vec<AclEntry> {
            vec![
                (0x01, 7, u32::MAX),
                (ACL_GROUP_OBJ, 5, u32::MAX),
                (ACL_GROUP, 5, ADM),
                (ACL_MASK, mask, u32::MAX),
                (0x20, 0, u32::MAX),
            ]
        };
        let journal_dir = |mask| permits(0o2750, 0, JOURNAL, Some(&acl(mask)), &console(&[ADM]), 5);
        assert!(journal_dir(5), "adm through the ACL");
        assert!(!journal_dir(0), "the mask takes it away");
        assert!(
            !permits(0o2750, 0, JOURNAL, Some(&acl(5)), &console(&[999]), 4),
            "neither group"
        );
    }

    #[test]
    fn the_kernels_acl_bytes_parse() {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [(0x01u16, 6u16, u32::MAX), (ACL_GROUP, 4, 4)] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(perm.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        assert_eq!(
            parse_acl(&bytes),
            Some(vec![(0x01, 6, u32::MAX), (ACL_GROUP, 4, 4)])
        );
        assert_eq!(parse_acl(&[1, 0, 0, 0]), None, "an unknown version");
        assert_eq!(parse_acl(&[2, 0, 0, 0, 1]), None, "a torn entry");
    }

    /// Each directory on the way needs search permission: a readable file
    /// in a directory the console cannot enter is not readable.
    #[test]
    fn a_closed_directory_on_the_way_makes_a_file_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("closed");
        std::fs::create_dir(&inner).unwrap();
        let file = inner.join("access.log");
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let stranger = Identity {
            uid: 4_000_000,
            gids: vec![4_000_000],
        };

        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let open = readable_by(&file, &stranger);
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        let closed = readable_by(&file, &stranger);
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(open, Some(true));
        assert_eq!(closed, Some(false));
        assert_eq!(readable_by(&inner.join("missing"), &stranger), None);
    }

    #[test]
    fn root_and_the_current_user_are_found_and_nonsense_is_not() {
        assert_eq!(user("root").map(|a| a.uid), Some(0));
        assert_eq!(group("root"), Some(0));
        assert_eq!(user_name(0), "root");
        assert_eq!(user("no such user, surely"), None);
        assert_eq!(user("nul\0in it"), None);
        assert_eq!(group("no-such-group-stop-bots-test"), None);
    }
}
