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

//! Errors that name the next step.
//!
//! "Permission denied (os error 13)" and "No such file or directory" are
//! accurate and leave the reader to work out what to do. The failures
//! someone new to this tool meets first — not root, `nginx` in a
//! container, no `nft` — each have one obvious next step, and the error
//! should say it.
//!
//! Each hint is appended after a blank line, below the error it explains,
//! so the error itself still reads first.

use std::io::ErrorKind;

/// What to do when this process lacks a permission root would have.
pub const SUDO: &str = "This needs root. Run it with sudo.";

/// Whether any cause in `err`'s chain is an I/O error of `kind`.
pub fn has_io_kind(err: &anyhow::Error, kind: ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == kind)
    })
}

/// Whether this process runs as root.
pub fn is_root() -> bool {
    // SAFETY: no preconditions; reads the process's own credentials.
    unsafe { libc::geteuid() == 0 }
}

/// `err` with `hint` below it.
pub fn with(err: anyhow::Error, hint: &str) -> anyhow::Error {
    anyhow::anyhow!("{err:#}\n\n{hint}")
}

/// `err`, told to run with sudo if it failed on a permission and this
/// process is not root. Root being denied is something else — a read-only
/// mount, a sandbox — and sudo would not help, so it is left alone.
pub fn sudo_if_denied(err: anyhow::Error) -> anyhow::Error {
    sudo_if_denied_as(err, is_root(), SUDO)
}

/// [`sudo_if_denied`] with the root check and the words given, for a
/// caller with a more specific next step and for tests.
pub fn sudo_if_denied_as(err: anyhow::Error, root: bool, hint: &str) -> anyhow::Error {
    if root || !has_io_kind(&err, ErrorKind::PermissionDenied) {
        return err;
    }
    with(err, hint)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied() -> anyhow::Error {
        anyhow::Error::new(std::io::Error::from(ErrorKind::PermissionDenied))
            .context("failed to write /etc/nginx/sites-enabled/default")
    }

    #[test]
    fn a_user_denied_a_permission_is_told_to_use_sudo_below_the_error() {
        let text = sudo_if_denied_as(denied(), false, SUDO).to_string();

        assert!(
            text.starts_with("failed to write /etc/nginx/sites-enabled/default: "),
            "the error itself should still come first: {text}"
        );
        assert!(
            text.ends_with("\n\nThis needs root. Run it with sudo."),
            "{text}"
        );
    }

    #[test]
    fn root_is_not_told_to_use_sudo() {
        let text = sudo_if_denied_as(denied(), true, SUDO).to_string();
        assert!(!text.contains("sudo"), "{text}");
    }

    #[test]
    fn a_failure_that_is_not_a_permission_gets_no_hint() {
        let err = anyhow::Error::new(std::io::Error::from(ErrorKind::NotFound));
        let text = format!("{:#}", sudo_if_denied_as(err, false, SUDO));
        assert!(!text.contains("sudo"), "{text}");
    }
}
