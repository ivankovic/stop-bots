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

//! Golden-file comparison for generated artifacts (only compiled for
//! tests — see `lib.rs`).
//!
//! Everything this project ultimately *does* is a piece of generated text:
//! an nftables/iptables script, an NGINX sentinel block, a robots.txt.
//! Substring assertions check that a directive is present; a golden file
//! locks the exact bytes, so an accidental change anywhere in the artifact
//! — reordering, a lost newline, a broken quote — fails a test instead of
//! reaching a server.
//!
//! The goldens serve a second purpose: they are the exact bytes to hand to
//! the real tools (`nft -c -f`, `nginx -t`) on a machine that has them.
//! Those tools aren't available in this environment or in CI, so
//! "validated against the real parser" is a once-per-change manual step —
//! but because the goldens pin the output, it genuinely is *once* per
//! change rather than a standing hope. See TODO.md.
//!
//! To update after an intended change: `UPDATE_GOLDENS=1 cargo test`,
//! then review the diff like any other code change.

use std::path::PathBuf;

pub(crate) fn assert_golden(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden file tests/golden/{name} — generate it with UPDATE_GOLDENS=1 cargo test, then review and commit it")
    });
    assert_eq!(
        actual, expected,
        "generated output no longer matches tests/golden/{name}. If the change is intended, \
         regenerate with UPDATE_GOLDENS=1 cargo test and review the golden's diff."
    );
}
