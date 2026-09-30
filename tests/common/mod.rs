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

/// The two directories this project generates files into, pointed at a
/// temp tree for the whole test binary.
///
/// Without this a spawned `stop-bots` writes to — and deletes from — the
/// host's real `/etc/nginx/conf.d` and `/etc/stop-bots/nginx`. That is
/// invisible in CI, where both are empty, and goes red on a developer
/// machine that also *runs* stop-bots: a root-owned generated file there
/// makes an apply fail with a permission error no test expected.
///
/// One tree per binary rather than one per test: the tests that assert on
/// a generated file point these at their own fixture instead, which wins
/// because it is set after.
pub fn generated_dir(name: &str) -> PathBuf {
    static ROOT: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| tempfile::tempdir().expect("failed to create the generated-files dir"))
        .path()
        .join(name)
}

/// `stop-bots`, with those directories already pointed somewhere harmless,
/// and every download sent to the [`NetworkTripwire`] instead of the
/// internet.
pub fn stop_bots_bin() -> Command {
    let mut cmd = Command::cargo_bin("stop-bots").unwrap();
    // A developer's own `STOP_BOTS_DB` must never be what a test that
    // forgot `--db` writes to.
    cmd.env_remove("STOP_BOTS_DB")
        .env("STOP_BOTS_NGINX_CONF_D", generated_dir("conf.d"))
        .env("STOP_BOTS_NGINX_DIR", generated_dir("managed"));
    for name in NetworkTripwire::UNSET {
        cmd.env_remove(name);
    }
    cmd.envs(network_tripwire().env());
    cmd
}

/// Where a spawned `stop-bots` sends any download it starts: a proxy on
/// loopback that refuses every request and counts it.
///
/// No test may reach the network (see CONTRIBUTING.md), and nothing in a
/// test's output shows it when one does — the fetch runs in the
/// background, fails or succeeds quietly, and the test passes either way.
/// This makes it visible: the product's HTTP client honours the standard
/// proxy variables, so every request a child makes arrives here instead
/// of at the real host, and fails with a 403 rather than leaving the
/// machine. [`NetworkTripwire::hits`] is how a harness asserts that none
/// did.
///
/// Environment, not a product flag, on purpose: this is the ordinary way
/// to route any program's HTTP, and the product needs no code that knows
/// about tests.
pub struct NetworkTripwire {
    addr: std::net::SocketAddr,
    hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl NetworkTripwire {
    /// Proxy settings a developer's shell may carry that would route
    /// around the tripwire: an exemption list, or a proxy of their own.
    const UNSET: [&'static str; 8] = [
        "NO_PROXY",
        "no_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];

    /// The variables that point a child's HTTP client here.
    pub fn env(&self) -> Vec<(&'static str, String)> {
        let url = format!("http://{}", self.addr);
        [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ]
        .into_iter()
        .map(|name| (name, url.clone()))
        .collect()
    }

    /// Clears the variables in [`Self::UNSET`] on `cmd` and sets
    /// [`Self::env`], for a harness that builds a `std::process::Command`.
    pub fn route(&self, cmd: &mut std::process::Command) {
        for name in Self::UNSET {
            cmd.env_remove(name);
        }
        cmd.envs(self.env());
    }

    /// How many requests have arrived since this test binary started.
    pub fn hits(&self) -> usize {
        self.hits.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The tripwire for this test binary, started on first use.
pub fn network_tripwire() -> &'static NetworkTripwire {
    use std::io::{Read, Write};
    static TRIPWIRE: std::sync::OnceLock<NetworkTripwire> = std::sync::OnceLock::new();
    TRIPWIRE.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind the network tripwire");
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
                let _ = stream.read(&mut [0u8; 4096]);
                let _ = stream.write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        NetworkTripwire { addr, hits }
    })
}

/// Runs `stop-bots` with `args`, asserting it succeeded, and returns the
/// assertion so a caller can go on to check stdout.
pub fn stop_bots(args: &[&str]) -> assert_cmd::assert::Assert {
    stop_bots_bin().args(args).assert().success()
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
