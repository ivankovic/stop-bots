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

//! Fixtures shared by the end-to-end binaries in this directory.
//!
//! A `common/mod.rs` rather than `common.rs`, so cargo treats it as a
//! module the test binaries include and not as a test binary of its own.
//! Only what two or more of them use lives here — a helper one binary
//! needs stays at the top of that file, where its doc comment is next to
//! the tests that read it. Unit tests in `src/` have `src/testing.rs`
//! for the same purpose.

#![allow(dead_code)]

use assert_cmd::Command;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Runs `stop-bots` with `args`, asserting it succeeded, and returns the
/// assertion so a caller can go on to check stdout.
pub fn stop_bots(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(args)
        .assert()
        .success()
}

/// Seeds the bot list from the checked-in sample, so tests never touch the
/// network.
pub fn seed_bots(db: &Path) {
    stop_bots(&[
        "update-bot-lists",
        "--db",
        db.to_str().unwrap(),
        "--source",
        "tests/fixtures/botlists/well-known-bots-sample.json",
    ]);
}

pub fn scan_sites(db: &Path, root: &Path) -> assert_cmd::assert::Assert {
    stop_bots(&[
        "scan-sites",
        "--root",
        root.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
    ])
}

/// PATH with `bin` in front, for handing to a spawned child.
pub fn path_with(bin: &Path) -> String {
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// A writable copy of the NGINX fixture tree under `dir`, for tests that
/// apply to it.
pub fn writable_nginx_fixture(dir: &Path) -> PathBuf {
    let root = dir.join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &root);
    root
}

pub fn copy_dir_all(src: &Path, dst: &Path) {
    for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
        let rel = entry.path().strip_prefix(src).unwrap();
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}
