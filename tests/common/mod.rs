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
        .env("STOP_BOTS_NGINX_DIR", generated_dir("managed"))
        // The host settings file is `/etc/stop-bots/host.conf` otherwise,
        // which a test must neither read nor write. A test that sets one
        // points this at a file of its own.
        .env("STOP_BOTS_HOST_CONF", generated_dir("host.conf"));
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

/// [`stop_bots`], with the host settings file at `host_conf`.
pub fn stop_bots_with_host(host_conf: &Path, args: &[&str]) -> assert_cmd::assert::Assert {
    stop_bots_bin()
        .env("STOP_BOTS_HOST_CONF", host_conf)
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

/// Writes an executable `#!/bin/sh` script at `path`.
///
/// Through a short-lived `sh` rather than `fs::write`: these test binaries
/// run many threads, and one that forks while another holds the script
/// open for writing hands that descriptor to its child, so running the
/// script fails with "Text file busy" one time in a few.
pub fn write_script(path: &Path, body: &str) {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(r#"printf '%s' "$2" > "$1" && chmod 755 "$1""#)
        .arg("sh")
        .arg(path)
        .arg(format!("#!/bin/sh\n{body}"))
        .status()
        .unwrap();
    assert!(status.success(), "could not write {}", path.display());
}

/// A host for the root helper to serve, all of it in a temp directory: a
/// database, an NGINX root with one site, an empty SSH log, and the host
/// settings file naming them, whose NGINX test and reload are `true`.
pub struct HelperHost {
    pub dir: tempfile::TempDir,
    pub db: PathBuf,
    pub root: PathBuf,
    pub site: PathBuf,
    pub host_conf: PathBuf,
    /// The applied firewall script: a test's own, never `/etc/stop-bots`.
    pub firewall: PathBuf,
}

/// The one site every [`HelperHost`] has.
pub const HELPER_SITE: &str = "server {\n    listen 80;\n    server_name example.com;\n}\n";

impl HelperHost {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nginx");
        fs::create_dir_all(root.join("conf.d")).unwrap();
        fs::create_dir_all(root.join("sites-enabled")).unwrap();
        let site = root.join("sites-enabled/example.com");
        fs::write(&site, HELPER_SITE).unwrap();
        let ssh_log = dir.path().join("auth.log");
        fs::write(&ssh_log, "").unwrap();
        let host_conf = dir.path().join("host.conf");
        stop_bots::hostconf::HostConf {
            nginx_test_command: Some("true".into()),
            nginx_reload_command: Some("true".into()),
            nginx_root: Some(root.clone()),
            access_log: Some(dir.path().join("access.log")),
            ssh_log: Some(ssh_log),
        }
        .save_to(&host_conf)
        .unwrap();
        let db = dir.path().join("db.sqlite3");
        fs::copy(helper_db_template(), &db).unwrap();
        let firewall = dir.path().join("firewall.nft");
        HelperHost {
            dir,
            db,
            root,
            site,
            host_conf,
            firewall,
        }
    }

    /// What an executor serving this host is configured with: the host
    /// settings file, and the firewall script redirected into the temp
    /// directory. Nothing for real: no `nft`, no reload.
    pub fn settings(&self) -> stop_bots::privileged::Settings {
        stop_bots::privileged::Settings {
            host_conf: self.host_conf.clone(),
            root: None,
            ssh_log: None,
            firewall_out: Some(self.firewall.clone()),
            for_real: false,
        }
    }

    /// The helper's configuration for this host, answering `allowed`.
    pub fn config(&self, allowed: Vec<u32>) -> stop_bots::helper::Config {
        stop_bots::helper::Config {
            db_path: self.db.clone(),
            settings: self.settings(),
            allowed_uids: allowed,
            request_deadline: std::time::Duration::from_millis(500),
            op_deadline: std::time::Duration::from_secs(10),
            max_connections: 8,
        }
    }

    /// Starts a real helper on a socket in the temp directory, answering
    /// this process's own user, and returns the socket.
    pub fn serve(&self) -> PathBuf {
        self.serve_with(self.config(vec![own_uid()]))
    }

    /// The same, with `config`.
    pub fn serve_with(&self, config: stop_bots::helper::Config) -> PathBuf {
        let socket = self.dir.path().join(format!(
            "helper-{}.sock",
            SOCKETS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let listener = stop_bots::helper::bind(&socket).unwrap();
        let server = stop_bots::helper::Server::new(config);
        std::thread::spawn(move || server.serve(listener));
        socket
    }

    /// An in-process executor over this host, the way a console running
    /// as root does it.
    pub fn local(&self) -> stop_bots::privileged::Privileged {
        stop_bots::privileged::Privileged::Local(std::sync::Arc::new(
            stop_bots::privileged::Local {
                db: std::sync::Arc::new(std::sync::Mutex::new(self.open_db())),
                settings: self.settings(),
            },
        ))
    }

    pub fn open_db(&self) -> stop_bots::db::Db {
        stop_bots::db::Db::open(&self.db).unwrap()
    }
}

static SOCKETS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A database for a [`HelperHost`], made once per test binary and copied:
/// creating one is a schema and a dozen fsyncs, most of a second on a busy
/// disk, and every host would otherwise pay it. The bot sources this binary
/// ships with, and one permanently blocked address so the firewall has a
/// rule to write.
fn helper_db_template() -> &'static Path {
    static TEMPLATE: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();
    &TEMPLATE
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("db.sqlite3");
            let db = stop_bots::db::Db::open(&path).unwrap();
            stop_bots::botlist::register_all_sources(&db).unwrap();
            db.block_address_permanently("192.0.2.10", stop_bots::db::RuleSource::Tui, None)
                .unwrap();
            // Checkpointed before it is copied, so the one file is the
            // whole database and no `-wal` holds part of it.
            db.vacuum().unwrap();
            drop(db);
            (dir, path)
        })
        .1
}

/// Blocks a bot whose user agent pattern is `pattern`, as it is stored:
/// what an apply then writes into every site.
pub fn block_a_bot(db: &stop_bots::db::Db, pattern: &str) {
    let source = db.list_sources().unwrap()[0].id.clone();
    let slug = format!("bot-{}", db.list_bots().unwrap().len());
    db.upsert_bot(&stop_bots::db::NewBot {
        slug: slug.clone(),
        name: slug.clone(),
        is_ai: false,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: pattern.to_string(),
        source_id: source,
    })
    .unwrap();
    db.set_bot_status(&slug, stop_bots::db::BotStatus::Blocked)
        .unwrap();
}

/// This process's effective uid.
pub fn own_uid() -> u32 {
    // SAFETY: no preconditions; reads the process's own credentials.
    unsafe { libc::geteuid() }
}
