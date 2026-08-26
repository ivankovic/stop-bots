//! End-to-end happy-path test for the db + nginx + bot-list CLI flow:
//! update-bot-lists -> scan-sites -> apply-blocks, run against a throwaway
//! copy of the NGINX fixtures. No network access is used.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// Every end-to-end test below drives the real binary against a throwaway
// database and NGINX root. The helpers here wrap the incantations that made
// up 20-40 lines of identical scaffolding in each of them.

/// A throwaway world for one end-to-end test: a database, an NGINX config
/// root, and the two directories the product writes its own generated
/// files into.
///
/// Every command run through this has the managed-directory overrides set,
/// which is a safety property and not just convenience: without them,
/// `apply-blocks` writes generated files under `/etc`. Today only
/// robots.txt and rate limiting do that and both default to off, so the
/// eight tests that never set the overrides happen to be harmless — one
/// setting away from not being. Making the fixture own them removes the
/// footgun rather than documenting it.
struct Fixture {
    // Held for its Drop: the directory is deleted when the fixture is.
    _tmp: tempfile::TempDir,
    db: std::path::PathBuf,
    nginx_root: std::path::PathBuf,
    /// `MANAGED_DIR` — where the generated robots.txt goes.
    managed: std::path::PathBuf,
    /// `conf.d` — where the generated rate-limit zone goes.
    conf_d: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_root = tmp.path().join("nginx");
        fs::create_dir_all(&nginx_root).unwrap();
        Fixture {
            db: tmp.path().join("db.sqlite3"),
            nginx_root,
            managed: tmp.path().join("managed"),
            conf_d: tmp.path().join("conf.d"),
            _tmp: tmp,
        }
    }

    /// Runs `stop-bots` with `args` plus `--db`, asserting success and
    /// returning the assertion so a caller can check stdout.
    fn run(&self, args: &[&str]) -> assert_cmd::assert::Assert {
        self.cmd(args).assert().success()
    }

    /// The same, without asserting success — for the tests that expect a
    /// failure and check stderr.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("stop-bots").unwrap();
        cmd.env("STOP_BOTS_NGINX_DIR", &self.managed)
            .env("STOP_BOTS_NGINX_CONF_D", &self.conf_d)
            .args(args)
            .args(["--db", self.db.to_str().unwrap()]);
        cmd
    }

    /// Seeds the bot list from the checked-in sample, so tests never touch
    /// the network.
    fn seed_bots(&self) {
        self.run(&[
            "update-bot-lists",
            "--source",
            "tests/fixtures/botlists/well-known-bots-sample.json",
        ]);
    }

    fn scan_sites(&self) -> assert_cmd::assert::Assert {
        self.run(&["scan-sites", "--root", self.nginx_root.to_str().unwrap()])
    }

    /// `--no-reload` throughout: these run on whatever machine hosts the
    /// test suite, and an apply without it shells out to the real
    /// `nginx -t` and `systemctl reload nginx`.
    fn apply_blocks(&self) -> assert_cmd::assert::Assert {
        self.run(&[
            "apply-blocks",
            "--root",
            self.nginx_root.to_str().unwrap(),
            "--no-reload",
        ])
    }

    /// One `server` block named `name`, in this fixture's config root.
    fn write_site(&self, name: &str) -> std::path::PathBuf {
        write_site(&self.nginx_root, name)
    }

    fn robots_txt(&self) -> std::path::PathBuf {
        self.managed.join("robots.txt")
    }

    fn rate_limit_conf(&self) -> std::path::PathBuf {
        self.conf_d.join("stop-bots-limits.conf")
    }
}

/// Runs `stop-bots` with `args`, asserting it succeeded, and returns the
/// assertion so a caller can go on to check stdout.
fn stop_bots(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(args)
        .assert()
        .success()
}

/// Seeds the bot list from the checked-in sample, so tests never touch the
/// network.
fn seed_bots(db: &Path) {
    stop_bots(&[
        "update-bot-lists",
        "--db",
        db.to_str().unwrap(),
        "--source",
        "tests/fixtures/botlists/well-known-bots-sample.json",
    ]);
}

fn scan_sites(db: &Path, root: &Path) -> assert_cmd::assert::Assert {
    stop_bots(&[
        "scan-sites",
        "--root",
        root.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
    ])
}

/// `--no-reload` throughout: these run on whatever machine hosts the test
/// suite, and an apply without it shells out to the real `nginx -t` and
/// `systemctl reload nginx`.
fn apply_blocks(db: &Path, root: &Path) -> assert_cmd::assert::Assert {
    stop_bots(&[
        "apply-blocks",
        "--root",
        root.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--no-reload",
    ])
}

/// One `server` block with `server_name`, written to `root/<name>.conf`.
fn write_site(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(format!("{name}.conf"));
    fs::write(
        &path,
        format!("server {{\n    listen 80;\n    server_name {name};\n}}\n"),
    )
    .unwrap();
    path
}

/// One NGINX combined-format access-log line.
fn access_line(ip: &str, path: &str, status: u16, ua: &str) -> String {
    format!(
        "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 0 \"-\" \"{ua}\"\n"
    )
}

/// Creates fake `nginx`, `systemctl` and `nft` executables in a directory
/// meant to be prepended to a child's PATH, so tests can exercise the real
/// reload and apply code paths — the process spawn, the argument building,
/// the exit-code handling, the ordering — on a machine where none of those
/// tools exist.
///
/// This is a fake, not a mock, in the sense that matters: nothing in the
/// product knows it's under test. The product resolves a command name
/// through PATH and interprets an exit code, exactly as in production; only
/// the binary found is ours. Each fake appends its name and arguments to
/// `calls.log` (returned) and exits 0 — unless a file named `fail-<tool>`
/// exists next to it, in which case it prints that file's contents to
/// stderr and exits 1, which is how a test stages e.g. a failing
/// `nginx -t`.
fn fake_tools(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let bin = dir.join("fakebin");
    fs::create_dir_all(&bin).unwrap();
    let log = dir.join("calls.log");
    for tool in ["nginx", "systemctl", "nft"] {
        let path = bin.join(tool);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\n\
                 echo \"{tool} $@\" >> \"{log}\"\n\
                 if [ -f \"{dir}/fail-{tool}\" ]; then cat \"{dir}/fail-{tool}\" >&2; exit 1; fi\n\
                 exit 0\n",
                log = log.display(),
                dir = dir.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    (bin, log)
}

/// PATH with `bin` in front, for handing to a spawned child.
fn path_with(bin: &Path) -> String {
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn copy_dir_all(src: &Path, dst: &Path) {
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

#[test]
fn update_scan_and_apply_blocks_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let nginx_root = tmp.path().join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &nginx_root);
    let db_path = tmp.path().join("db.sqlite3");

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "update-bot-lists",
            "--db",
            db_path.to_str().unwrap(),
            "--source",
            "tests/fixtures/botlists/well-known-bots-sample.json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Stored 4 bot(s)"));

    scan_sites(&db_path, &nginx_root).stdout(predicate::str::contains("Discovered 2 site(s)"));

    // `--no-reload`: this test's "nginx root" is a throwaway temp dir, not
    // the real system config, so there's nothing for a real `nginx -t` /
    // `systemctl reload nginx` to validate — and the CLI would otherwise
    // reload the machine's actual NGINX (if any) as a side effect of
    // running this test suite.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--no-reload",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("2 file(s) changed"));

    let example_com = fs::read_to_string(nginx_root.join("sites-enabled/example.com")).unwrap();
    assert!(
        example_com.contains("# BEGIN stop-bots"),
        "example_com was:\n{example_com}"
    );
    assert!(
        example_com.contains("AISearchBot"),
        "example_com was:\n{example_com}"
    );
    // The search-engine and unknown-category bots default to allowed, so
    // only the AI bot's pattern should show up in the generated rule.
    assert!(
        !example_com.contains("Googlebot"),
        "example_com was:\n{example_com}"
    );

    // Re-running apply-blocks should be a no-op.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--no-reload",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0 file(s) changed"));
}

/// Regression test for a real bug caught in design review: `sites` has
/// `UNIQUE(server_name, config_path)`, so the *same* `server_name` can
/// legitimately appear in two different files (e.g. a stale config left
/// behind after a rename). A per-site override must stay scoped to the
/// specific file its site row came from — building one flat
/// name-to-patterns map for the whole `apply-blocks` run and reusing it
/// across every file would let one site's override leak onto the other's
/// same-named block in a different file.
#[test]
fn apply_blocks_scopes_a_site_override_to_its_own_file_even_with_a_shared_server_name() {
    let tmp = tempfile::tempdir().unwrap();
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    // Two different files, both declaring the same server_name.
    let file_a = nginx_root.join("a.conf");
    let file_b = nginx_root.join("b.conf");
    fs::write(
        &file_a,
        "server {\n    listen 80;\n    server_name shared.example;\n    root /var/www/a;\n}\n",
    )
    .unwrap();
    fs::write(
        &file_b,
        "server {\n    listen 80;\n    server_name shared.example;\n    root /var/www/b;\n}\n",
    )
    .unwrap();

    seed_bots(&db_path);

    scan_sites(&db_path, &nginx_root).stdout(predicate::str::contains("Discovered 2 site(s)"));

    // Override the Search category to Blocked, but only for the site row
    // whose config_path is file_a.
    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        let site_a = db
            .list_sites()
            .unwrap()
            .into_iter()
            .find(|s| Path::new(&s.config_path) == file_a)
            .unwrap();
        db.set_site_category_override(
            site_a.id,
            stop_bots::db::Category::Search,
            Some(stop_bots::db::Policy::Blocked),
        )
        .unwrap();
    }

    apply_blocks(&db_path, &nginx_root);

    let a = fs::read_to_string(&file_a).unwrap();
    let b = fs::read_to_string(&file_b).unwrap();
    // file_a's site overrides Search to Blocked: the search-engine bot's
    // pattern should show up there.
    assert!(a.contains("Googlebot"), "a was:\n{a}");
    // file_b's same-named site has no override of its own and must not
    // pick up file_a's — it follows the global default (Search allowed).
    // It still gets a block, just for the AI bot (blocked by default),
    // not the search-engine one.
    assert!(!b.contains("Googlebot"), "b was:\n{b}");
    assert!(b.contains("AISearchBot"), "b was:\n{b}");
}

/// The block-response setting end to end: change it, apply, and confirm
/// the generated config carries the new code — the whole point being that
/// setting it alone changes nothing on disk until `apply-blocks` runs.
#[test]
fn set_block_response_changes_the_generated_status_code_on_the_next_apply() {
    let tmp = tempfile::tempdir().unwrap();
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    let site = write_site(&nginx_root, "a.example");

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    let apply = |db_path: &Path, root: &Path| {
        apply_blocks(db_path, root);
    };

    apply(&db_path, &nginx_root);
    assert!(fs::read_to_string(&site).unwrap().contains("return 403;"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-block-response",
            "--db",
            db_path.to_str().unwrap(),
            "--response",
            "close",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("apply-blocks"));

    // Still 403 on disk: setting it is not applying it.
    assert!(fs::read_to_string(&site).unwrap().contains("return 403;"));

    apply(&db_path, &nginx_root);
    let written = fs::read_to_string(&site).unwrap();
    assert!(written.contains("return 444;"), "written was:\n{written}");
    assert!(!written.contains("return 403;"), "written was:\n{written}");
}

/// Spoofed-crawler detection end to end, including the property that
/// matters most: it does nothing at all until crawler ranges are fetched.
#[test]
fn block_spoofed_crawlers_is_inert_without_ranges_then_blocks_a_forged_googlebot() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let access_log = tmp.path().join("access.log");

    let line = |ip: &str, ua: &str| access_line(ip, "/", 200, ua);
    fs::write(
        &access_log,
        line("203.0.113.9", "Mozilla/5.0 (compatible; Googlebot/2.1)")
            + &line("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1)"),
    )
    .unwrap();

    let run = |db_path: &Path, log: &Path| {
        Command::cargo_bin("stop-bots")
            .unwrap()
            .args([
                "block-spoofed-crawlers",
                "--db",
                db_path.to_str().unwrap(),
                "--access-log",
                log.to_str().unwrap(),
            ])
            .assert()
            .success()
    };

    // No ranges stored yet: says so explicitly rather than reporting a
    // clean log, and blocks nothing.
    run(&db_path, &access_log).stdout(predicate::str::contains("No crawler IP ranges fetched yet"));
    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    // Seed Googlebot's published ranges the way `update-ip-ranges` would.
    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        db.register_ip_range_source(&stop_bots::db::IpRangeSource {
            id: "googlebot".to_string(),
            name: "Googlebot IP ranges".to_string(),
            url: "https://example.invalid/googlebot.json".to_string(),
            category: stop_bots::db::Category::Search,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.replace_ip_ranges("googlebot", &["66.249.64.0/19".to_string()])
            .unwrap();
    }

    run(&db_path, &access_log).stdout(predicate::str::contains("203.0.113.9"));

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    let rules = db.list_firewall_rules().unwrap();
    assert_eq!(rules.len(), 1, "rules were: {rules:?}");
    // The forged claim is blocked; the address Google actually publishes
    // is not.
    assert_eq!(rules[0].address, "203.0.113.9");
    assert!(rules[0].expires_at.is_some());
}

/// Probe-path detection end to end, including the property the built-in
/// list is chosen for: a legitimate admin path must survive it.
#[test]
fn block_probe_paths_blocks_a_dotenv_probe_but_not_a_wordpress_login() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let access_log = tmp.path().join("access.log");

    let line = |ip: &str, path: &str| access_line(ip, path, 404, "curl/8");
    fs::write(
        &access_log,
        line("203.0.113.9", "/.env") + &line("198.51.100.2", "/wp-login.php"),
    )
    .unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-probe-paths",
            "--db",
            db_path.to_str().unwrap(),
            "--access-log",
            access_log.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("203.0.113.9"));

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    let rules = db.list_firewall_rules().unwrap();
    assert_eq!(rules.len(), 1, "rules were: {rules:?}");
    assert_eq!(rules[0].address, "203.0.113.9");

    // The site's own administrator signing in is not a probe.
    assert!(!rules.iter().any(|r| r.address == "198.51.100.2"));
}

/// Extra probe paths are configurable, and entries that could never match
/// are reported rather than silently dropped.
#[test]
fn set_probe_paths_adds_extras_and_reports_unanchored_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let access_log = tmp.path().join("access.log");
    fs::write(
        &access_log,
        access_line("203.0.113.9", "/internal/dump", 200, "curl/8"),
    )
    .unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-probe-paths",
            "--db",
            db_path.to_str().unwrap(),
            "--paths",
            "/internal\nnot-anchored",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 accepted"))
        .stdout(predicate::str::contains("Ignored 1"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-probe-paths", "--db", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("/.env"))
        .stdout(predicate::str::contains("/internal"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-probe-paths",
            "--db",
            db_path.to_str().unwrap(),
            "--access-log",
            access_log.to_str().unwrap(),
        ])
        .assert()
        .success();

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    assert_eq!(db.list_firewall_rules().unwrap()[0].address, "203.0.113.9");
}

/// The honeypot end to end, including its guard against a path that could
/// never match.
#[test]
fn honeypot_path_is_configurable_and_blocks_whatever_fetches_it() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let access_log = tmp.path().join("access.log");
    fs::write(
        &access_log,
        access_line("203.0.113.9", "/trap-me/", 404, "curl/8"),
    )
    .unwrap();

    // A path with no leading slash can never match, so it's rejected
    // rather than stored.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-honeypot-path",
            "--db",
            db_path.to_str().unwrap(),
            "--path",
            "trap-me",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must start with"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-honeypot-path",
            "--db",
            db_path.to_str().unwrap(),
            "--path",
            "/trap-me/",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("published"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-honeypot",
            "--db",
            db_path.to_str().unwrap(),
            "--access-log",
            access_log.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("203.0.113.9"));

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    let rules = db.list_firewall_rules().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].address, "203.0.113.9");
}

/// Reputation feeds end to end, without touching the network: seed ranges
/// directly, then confirm the on/off switch is what decides whether they
/// reach the rendered firewall script.
#[test]
fn a_reputation_feed_only_reaches_the_firewall_script_once_enabled() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let out = tmp.path().join("firewall.nft");

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-reputation-sources", "--db", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("firehol-level1"))
        .stdout(predicate::str::contains("[OFF]"));

    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        db.replace_reputation_ranges("tor-exits", &["198.51.100.7".to_string()])
            .unwrap();
    }

    let render = |db_path: &Path, out: &Path| {
        Command::cargo_bin("stop-bots")
            .unwrap()
            .args([
                "render-firewall",
                "--backend",
                "nftables",
                "--out",
                out.to_str().unwrap(),
                "--db",
                db_path.to_str().unwrap(),
                "--ssh-log",
                "/nonexistent/auth.log",
            ])
            .assert()
            .success();
    };

    // Fetched but off: the range must not be in the script.
    render(&db_path, &out);
    assert!(!fs::read_to_string(&out).unwrap().contains("198.51.100.7"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-reputation-source",
            "--db",
            db_path.to_str().unwrap(),
            "--source-id",
            "tor-exits",
            "--enabled",
            "true",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("render-firewall"));

    render(&db_path, &out);
    assert!(fs::read_to_string(&out).unwrap().contains("198.51.100.7"));

    // And switching it back off removes it again, without losing the data.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-reputation-source",
            "--db",
            db_path.to_str().unwrap(),
            "--source-id",
            "tor-exits",
            "--enabled",
            "false",
        ])
        .assert()
        .success();
    render(&db_path, &out);
    assert!(!fs::read_to_string(&out).unwrap().contains("198.51.100.7"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-reputation-sources", "--db", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 range(s)"));
}

/// Enabling a cloud-provider feed must say what it actually does.
#[test]
fn enabling_a_provider_feed_warns_and_flags_that_nothing_is_fetched_yet() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-reputation-source",
            "--db",
            db_path.to_str().unwrap(),
            "--source-id",
            "aws",
            "--enabled",
            "true",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("not just bots"))
        .stdout(predicate::str::contains("No ranges stored yet"));
}

#[test]
fn an_unknown_reputation_source_is_rejected_with_the_known_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "set-reputation-source",
            "--db",
            db_path.to_str().unwrap(),
            "--source-id",
            "not-a-feed",
            "--enabled",
            "true",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("firehol-level1"));
}

/// robots.txt generation end to end: the file is written, the site config
/// aliases it, and disabling removes both.
#[test]
fn robots_txt_is_generated_aliased_and_then_removed_again() {
    let fx = Fixture::new();
    let site = fx.write_site("a.example");
    fx.seed_bots();
    fx.scan_sites();

    // Off by default: no location block, no file.
    fx.apply_blocks();
    assert!(!fs::read_to_string(&site).unwrap().contains("/robots.txt"));
    assert!(!fx.robots_txt().exists());

    fx.run(&["set-robots-txt", "--enabled", "true"])
        .stdout(predicate::str::contains("replaces"));
    fx.run(&["show-robots-txt"])
        .stdout(predicate::str::contains("User-agent:"))
        // The honeypot trap path is always published.
        .stdout(predicate::str::contains("stop-bots-trap"));

    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.contains("location = /robots.txt"),
        "written was:\n{written}"
    );
    // The alias points at the file that was actually written.
    let robots = fx.robots_txt();
    assert!(robots.exists(), "robots.txt should have been written");
    assert!(
        written.contains(robots.to_str().unwrap()),
        "written was:\n{written}"
    );
    assert!(fs::read_to_string(&robots).unwrap().contains("User-agent:"));

    // Disabling removes the directive *and* the generated file — a stale
    // generated artifact left on disk invites being wired back up by hand.
    fx.run(&["set-robots-txt", "--enabled", "false"]);
    fx.apply_blocks();
    assert!(!fs::read_to_string(&site).unwrap().contains("/robots.txt"));
    assert!(!robots.exists(), "the generated file should be removed");
}

/// Rate limiting end to end, and specifically the ordering that keeps the
/// config valid: the http-context zone file must exist while any server
/// block references it, and must only be deleted once none does.
#[test]
fn rate_limit_writes_the_zone_file_and_removes_it_only_after_the_directive_goes() {
    let fx = Fixture::new();
    let site = fx.write_site("a.example");
    fx.scan_sites();

    fx.run(&[
        "set-rate-limit",
        "--enabled",
        "true",
        "--rps",
        "7",
        "--burst",
        "14",
    ])
    .stdout(predicate::str::contains("7 req/s"));

    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.contains("limit_req zone=stop_bots burst=14 nodelay;"),
        "written was:\n{written}"
    );
    assert!(
        written.contains("limit_req_status 429;"),
        "written was:\n{written}"
    );

    let zone = fs::read_to_string(fx.rate_limit_conf()).expect("zone file should exist");
    assert!(zone.contains("rate=7r/s"), "zone was:\n{zone}");
    // The zone the server block references is the zone that was defined.
    assert!(zone.contains("zone=stop_bots:"), "zone was:\n{zone}");

    fx.run(&["set-rate-limit", "--enabled", "false"]);

    // Still present until an apply actually rewrites the config — deleting
    // it while the directive is live would make nginx -t fail outright.
    assert!(fx.rate_limit_conf().exists());

    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(!written.contains("limit_req"), "written was:\n{written}");
    assert!(
        !fx.rate_limit_conf().exists(),
        "zone file should be removed after apply"
    );

    // Parameters persist across a disable, so re-enabling doesn't silently
    // revert to defaults.
    fx.run(&["set-rate-limit", "--enabled", "true"])
        .stdout(predicate::str::contains("7 req/s"));
}

/// Per-site path exemptions end to end: the generated block switches to
/// the flag form, and only the exempted path escapes the rule.
#[test]
fn a_site_path_exemption_switches_the_block_to_the_flag_form() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();

    let site_file = write_site(&nginx_root, "a.example");

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    let apply = || {
        apply_blocks(&db_path, &nginx_root);
    };

    // Without exemptions: the original direct-return shape.
    apply();
    let plain = fs::read_to_string(&site_file).unwrap();
    assert!(plain.contains("return 403;"), "plain was:\n{plain}");
    assert!(!plain.contains("$stop_bots_block"), "plain was:\n{plain}");

    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        let site = db.list_sites().unwrap().into_iter().next().unwrap();
        db.add_site_path_exemption(site.id, "/blog").unwrap();
    }

    apply();
    let exempted = fs::read_to_string(&site_file).unwrap();
    assert!(
        exempted.contains("set $stop_bots_block 0;"),
        "exempted was:\n{exempted}"
    );
    assert!(
        exempted.contains("set $stop_bots_block 1;"),
        "exempted was:\n{exempted}"
    );
    assert!(
        exempted.contains("if ($request_uri ~* \"^(/blog)\")"),
        "exempted was:\n{exempted}"
    );
    assert!(
        exempted.contains("if ($stop_bots_block) {"),
        "exempted was:\n{exempted}"
    );
    // Exactly one sentinel block still, not a second appended.
    assert_eq!(exempted.matches("# BEGIN stop-bots").count(), 1);
}

/// The reload path end to end, with no real NGINX anywhere: apply-blocks
/// without --no-reload must run `nginx -t` and then `systemctl reload
/// nginx`, in that order — validation before reload is the property, since
/// reloading an invalid config is how every site goes down at once.
#[test]
fn apply_blocks_reloads_nginx_after_validating_the_config() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    write_site(&nginx_root, "a.example");
    let (bin, calls) = fake_tools(tmp.path());

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    Command::cargo_bin("stop-bots")
        .unwrap()
        .env("PATH", path_with(&bin))
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Reloaded NGINX"));

    let log = fs::read_to_string(&calls).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines[0], "nginx -t", "validate first; log was: {log}");
    assert_eq!(lines[1], "systemctl reload nginx");
    assert_eq!(lines.len(), 2, "no extra tool invocations; log was: {log}");
}

/// A config that fails validation stops the reload cold: `systemctl` must
/// never run, and the error the admin sees is nginx's own message rather
/// than a pointer at systemctl status.
#[test]
fn a_failing_nginx_config_check_stops_the_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    write_site(&nginx_root, "a.example");
    let (bin, calls) = fake_tools(tmp.path());
    fs::write(
        tmp.path().join("fail-nginx"),
        "nginx: [emerg] unexpected end of file\n",
    )
    .unwrap();

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    Command::cargo_bin("stop-bots")
        .unwrap()
        .env("PATH", path_with(&bin))
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected end of file"));

    let log = fs::read_to_string(&calls).unwrap();
    assert!(
        !log.contains("systemctl"),
        "an invalid config must never be reloaded; log was: {log}"
    );
}

/// Per-site HTTP/1.x rejection end to end, including the guard that keeps
/// it from taking a site offline: a site's port-80 and port-443 blocks
/// share one `server_name`, so the setting reaches both, and only the TLS
/// one may carry the rule.
#[test]
fn rejecting_http_1x_applies_only_to_the_tls_server_block() {
    let fx = Fixture::new();
    let site = fx.nginx_root.join("a.example.conf");
    fs::write(
        &site,
        concat!(
            "server {\n    listen 80;\n    server_name a.example;\n}\n",
            "server {\n    listen 443 ssl;\n    server_name a.example;\n}\n"
        ),
    )
    .unwrap();
    fx.seed_bots();
    fx.scan_sites();

    // Off by default.
    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        !written.contains("$server_protocol"),
        "written was:\n{written}"
    );

    {
        let db = stop_bots::db::Db::open(&fx.db).unwrap();
        let s = db.list_sites().unwrap().into_iter().next().unwrap();
        db.set_site_request_rule(s.id, "http_1x", true).unwrap();
        // A header-shape rule alongside it: those are not TLS-dependent
        // and must reach *both* blocks.
        db.set_site_request_rule(s.id, "no_user_agent", true)
            .unwrap();
    }

    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert_eq!(
        written.matches("$server_protocol").count(),
        1,
        "only the TLS block may reject HTTP/1.x; written was:\n{written}"
    );
    assert_eq!(
        written.matches(r#"$http_user_agent = """#).count(),
        2,
        "a header-shape rule works over plain HTTP too, so both blocks \
         get it; written was:\n{written}"
    );
    // Certificate renewal has to keep working: ACME fetches
    // /.well-known/ over HTTP/1.1.
    assert!(
        written.contains(r"/\.well-known/"),
        "written was:\n{written}"
    );
}

/// Every block-response option end to end: each has to reach the config
/// as its own status code, and tarpit has to bring its throttle with it.
#[test]
fn each_block_response_reaches_the_generated_config() {
    let fx = Fixture::new();
    let site = fx.write_site("a.example");
    fx.seed_bots();
    fx.scan_sites();

    for (arg, expected) in [
        ("forbidden", "return 403;"),
        ("not-found", "return 404;"),
        ("gone", "return 410;"),
        ("too-many-requests", "return 429;"),
        ("teapot", "return 418;"),
        ("close", "return 444;"),
    ] {
        fx.run(&["set-block-response", "--response", arg]);
        fx.apply_blocks();
        let written = fs::read_to_string(&site).unwrap();
        assert!(
            written.contains(expected),
            "{arg} should render {expected}; written was:\n{written}"
        );
        assert!(
            !written.contains("set $limit_rate"),
            "{arg} must not throttle; written was:\n{written}"
        );
    }

    fx.run(&["set-block-response", "--response", "tarpit"]);
    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.contains("set $limit_rate 1;"),
        "written was:\n{written}"
    );
    assert!(written.contains("return 403;"), "written was:\n{written}");
}

#[test]
fn firewall_add_list_render_remove_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "1.2.3.4",
            "--action",
            "block",
        ])
        .assert()
        .success();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "66.249.64.0/19",
            "--action",
            "allow",
        ])
        .assert()
        .success();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("1.2.3.4"))
        .stdout(predicate::str::contains("66.249.64.0/19"));

    let script_path = tmp.path().join("stop-bots.sh");
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "iptables",
            "--out",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote 2 rule(s)"));

    let script = fs::read_to_string(&script_path).unwrap();
    assert!(
        script.contains("-A STOP-BOTS -s 1.2.3.4 -j DROP"),
        "script was:\n{script}"
    );
    assert!(
        script.contains("-A STOP-BOTS -s 66.249.64.0/19 -j ACCEPT"),
        "script was:\n{script}"
    );
    // This is the safety property that matters most: the script must never
    // touch chains/policies outside our own dedicated STOP-BOTS chain.
    assert!(!script.contains("*filter"), "script was:\n{script}");
    assert!(!script.contains("COMMIT"), "script was:\n{script}");

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["remove-firewall-rule", "--db", db_path, "--id", "1"])
        .assert()
        .success();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("1.2.3.4").not());
}

/// The lockout safety net: `render-firewall` must refuse to write a script
/// that would block an IP address with a recent successful SSH login,
/// unless `--force` is passed. Uses `--ssh-log` to point at a fixture
/// instead of the real system logs, so this is deterministic regardless of
/// what's actually in `/var/log/auth.log` on whatever machine runs the test.
#[test]
fn render_firewall_refuses_to_lock_out_a_connected_ssh_client() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "4.5.6.0/24",
            "--action",
            "block",
        ])
        .assert()
        .success();

    let log_path = tmp.path().join("auth.log");
    fs::write(
        &log_path,
        "Jun 12 01:02:03 host sshd[111]: Accepted publickey for admin from 4.5.6.7 port 54321 ssh2: ED25519 SHA256:abc\n",
    )
    .unwrap();

    let script_path = tmp.path().join("stop-bots.sh");

    // Without --force: refuses, warns once, writes nothing.
    let output = Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
            "--ssh-log",
            log_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("WARNING").count(), 1);
    assert!(stderr.contains("4.5.6.7"), "stderr was:\n{stderr}");
    assert!(
        stderr.contains("Refusing to write"),
        "stderr was:\n{stderr}"
    );
    assert!(!script_path.exists());

    // With --force: still warns (once), but writes the script.
    let output = Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("WARNING").count(), 1);
    assert!(stderr.contains("4.5.6.7"), "stderr was:\n{stderr}");
    assert!(fs::read_to_string(&script_path)
        .unwrap()
        .contains("4.5.6.0/24"));
}

/// The flip side: a log with logins from unrelated IPs must not trip the
/// safety net at all — `render-firewall` should behave exactly as if
/// `--ssh-log` were never passed.
#[test]
fn render_firewall_proceeds_normally_when_no_connected_ip_is_at_risk() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "4.5.6.0/24",
            "--action",
            "block",
        ])
        .assert()
        .success();

    let log_path = tmp.path().join("auth.log");
    fs::write(
        &log_path,
        "Accepted publickey for admin from 9.9.9.9 port 54321 ssh2\n",
    )
    .unwrap();

    let script_path = tmp.path().join("stop-bots.sh");
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
            "--ssh-log",
            log_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("WARNING").not());
    assert!(script_path.exists());
}

/// A crawler IP-range / country-block feeding into the *same* rendered
/// output must trip the same safety net as an admin-added rule — the check
/// runs against everything about to be written, not just `firewall_rules`.
#[test]
fn render_firewall_lockout_check_covers_derived_country_ranges_too() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        db.replace_country_ranges("xx", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("xx", true).unwrap();
    }

    let log_path = tmp.path().join("auth.log");
    fs::write(
        &log_path,
        "Accepted publickey for admin from 4.5.6.7 port 54321 ssh2\n",
    )
    .unwrap();

    let script_path = tmp.path().join("stop-bots.sh");
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path.to_str().unwrap(),
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
            "--ssh-log",
            log_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("4.5.6.7"));
    assert!(!script_path.exists());
}

#[test]
fn geo_mode_and_country_selection_cli_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    // Defaults to Blocklist with nothing selected.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Blocklist"))
        .stdout(predicate::str::contains("No countries selected"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["add-country", "--db", db_path, "--country", "nl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added country nl"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("nl"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Allowlist"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Allowlist"))
        .stdout(predicate::str::contains("nl"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["remove-country", "--db", db_path, "--country", "nl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed country nl"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("No countries selected"));
}

/// The nftables-only guard, end to end through the real CLI: Allowlist
/// mode's trailing default-deny catch-all is unsafe on iptables (no
/// loopback/established allowance, silently permits all IPv6), so
/// render-firewall must refuse before ever writing a script.
#[test]
fn render_firewall_rejects_allowlist_mode_on_iptables_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success();

    let script_path = tmp.path().join("stop-bots.sh");
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "iptables",
            "--out",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nftables"));
    assert!(!script_path.exists());
}

/// The scenario the whole first-match-wins lockout fix exists for: in
/// Allowlist mode, an admin whose connected IP is covered by an *earlier*
/// Allow rule (here, their own admin-added `firewall_rules` entry) must not
/// be flagged as at-risk just because the trailing catch-all's CIDR also
/// technically contains their IP — the catch-all never actually applies to
/// them, since the Allow rule matches first.
#[test]
fn render_firewall_allowlist_mode_does_not_warn_when_an_earlier_allow_rule_covers_the_admin() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success();
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "4.5.6.7",
            "--action",
            "allow",
        ])
        .assert()
        .success();

    let log_path = tmp.path().join("auth.log");
    fs::write(
        &log_path,
        "Accepted publickey for admin from 4.5.6.7 port 54321 ssh2\n",
    )
    .unwrap();

    let script_path = tmp.path().join("stop-bots.sh");
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
            "--ssh-log",
            log_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("WARNING").not());

    let script = fs::read_to_string(&script_path).unwrap();
    assert!(
        script.contains("ip saddr 4.5.6.7 accept"),
        "script was:\n{script}"
    );
    assert!(
        script.contains("ip saddr 0.0.0.0/0 drop"),
        "script was:\n{script}"
    );
    assert!(
        script.contains("ip6 saddr ::/0 drop"),
        "script was:\n{script}"
    );
}

fn repeat_failed_attempt(ip: &str, times: usize) -> String {
    format!("Failed password for root from {ip} port 4444 ssh2\n").repeat(times)
}

#[test]
fn block_scanners_adds_a_rule_for_an_ip_over_the_threshold_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 25)).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added 1 new block rule"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9"));

    // Re-running against the same log must not add a duplicate rule.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "all already covered by an existing firewall rule",
        ));
}

#[test]
fn block_scanners_ignores_an_ip_below_the_threshold() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 5)).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No scanning IPs found"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

/// The safety property that matters most: an IP that eventually logs in
/// successfully must never be auto-blocked, even with a mountain of failed
/// attempts before it.
#[test]
fn block_scanners_never_blocks_an_ip_that_eventually_logged_in() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    let mut log = repeat_failed_attempt("198.51.100.9", 25);
    log.push_str("Accepted publickey for admin from 198.51.100.9 port 5555 ssh2\n");
    fs::write(&log_path, log).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No scanning IPs found"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

#[test]
fn block_scanners_dry_run_reports_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 25)).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would add 1 new block rule"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

fn not_found_line(ip: &str, path: &str) -> String {
    format!(
        "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"\n"
    )
}

#[test]
fn block_web_scanners_adds_a_rule_for_distinct_not_found_paths_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("access.log");
    let log: String = (0..20)
        .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
        .collect();
    fs::write(&log_path, log).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-web-scanners",
            "--db",
            db_path,
            "--access-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "15",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added 1 new block rule"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9"));

    // Re-running against the same log must not add a duplicate rule.
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-web-scanners",
            "--db",
            db_path,
            "--access-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "15",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "all already covered by an existing firewall rule",
        ));
}

/// The core discriminator this feature exists to get right, verified again
/// at the CLI/DB-state level (already unit-tested in `accesslog.rs`):
/// hitting the *same* dead path repeatedly must never look like scanning.
#[test]
fn block_web_scanners_ignores_repeated_hits_on_a_single_dead_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("access.log");
    let log: String = (0..50)
        .map(|_| not_found_line("198.51.100.9", "/missing"))
        .collect();
    fs::write(&log_path, log).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-web-scanners",
            "--db",
            db_path,
            "--access-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "15",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No scanning IPs found"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

#[test]
fn block_web_scanners_dry_run_reports_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("access.log");
    let log: String = (0..20)
        .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
        .collect();
    fs::write(&log_path, log).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-web-scanners",
            "--db",
            db_path,
            "--access-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "15",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Would add 1 new block rule"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

/// End-to-end through the real binary: a rule added with an already-past
/// TTL (`--ttl-days=-1`, using `=` so clap doesn't mistake the negative
/// number for a flag) must be gone by the very next `list-firewall-rules`
/// call — proving the CLI wiring actually reaches `Db::list_firewall_rules`'s
/// pruning, not just the unit-tested `Db` layer in isolation.
#[test]
fn block_scanners_ttl_days_expires_the_rule_by_the_next_list() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 25)).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
            "--ttl-days=-1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("expiring in -1 day"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

/// The default (positive) TTL path — a freshly added rule must still show
/// up normally, with its expiry reflected in the confirmation message.
#[test]
fn block_web_scanners_ttl_days_defaults_to_one_day() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("access.log");
    let log: String = (0..20)
        .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
        .collect();
    fs::write(&log_path, log).unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-web-scanners",
            "--db",
            db_path,
            "--access-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "15",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("expiring after 1 day"));

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9"));
}

/// `list-firewall-rules` must show a temporary rule's expiry (so an admin
/// scanning the list can tell an auto-added block from a permanent
/// hand-added one), but never show one for a permanent rule.
#[test]
fn list_firewall_rules_shows_expiry_only_for_temporary_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "9.9.9.9",
            "--action",
            "block",
        ])
        .assert()
        .success();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 25)).unwrap();
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "20",
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("stop-bots")
        .unwrap()
        .args(["list-firewall-rules", "--db", db_path])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let permanent_line = stdout.lines().find(|l| l.contains("9.9.9.9")).unwrap();
    let temporary_line = stdout.lines().find(|l| l.contains("198.51.100.9")).unwrap();
    assert!(
        !permanent_line.contains("expires"),
        "permanent_line was:\n{permanent_line}"
    );
    assert!(
        temporary_line.contains("expires in"),
        "temporary_line was:\n{temporary_line}"
    );
}

// ---- batch mode ----

impl Fixture {
    /// One batch pass over this fixture, offline. `--no-fetch` throughout:
    /// every test in this suite must run without a network, and the
    /// download steps are the only part of batch that needs one.
    ///
    /// A fixture SSH log rather than auto-detection, for the usual reason
    /// — and because the lockout guard reads it, so leaving it to
    /// auto-detection would make these tests depend on whatever log the
    /// machine running them happens to have.
    fn batch(&self, extra: &[&str]) -> Command {
        let out = self.firewall_script();
        let mut args = vec![
            "batch",
            "--no-fetch",
            "--root",
            self.nginx_root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
            "--access-log",
            "/dev/null",
        ];
        args.extend_from_slice(extra);
        self.cmd(&args)
    }

    fn firewall_script(&self) -> std::path::PathBuf {
        self.managed.join("firewall.nft")
    }
}

/// The whole point of batch mode: one command does the lot. It has to
/// discover the site, write the NGINX block, and write the firewall
/// script, from a database that starts empty.
#[test]
fn batch_scans_applies_and_renders_in_one_pass() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");

    fixture.batch(&[]).assert().success();

    let config = fs::read_to_string(&site).unwrap();
    assert!(
        config.contains("stop-bots"),
        "the site config should carry the generated block:\n{config}"
    );
    assert!(
        fixture.firewall_script().exists(),
        "the firewall script should have been written"
    );
}

/// Quiet on success, because `cron` mails the owner anything a job
/// prints and a nightly run that says nothing is one nobody has to read.
#[test]
fn a_successful_batch_run_says_nothing() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");

    fixture
        .batch(&[])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
}

/// `--verbose` is what a first run by hand wants: every step, named.
#[test]
fn verbose_batch_reports_every_step() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");

    fixture
        .batch(&["--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scan sites"))
        .stdout(predicate::str::contains("nginx blocks"))
        .stdout(predicate::str::contains("firewall"));
}

/// **The safety property this whole feature turns on.** Under `--apply`,
/// a lockout guard that could not run at all counts as a refusal.
///
/// Interactive `render-firewall` prints a note and carries on here,
/// which is defensible when a human is watching the terminal. From
/// crontab nobody is — and this project has already taken a server off
/// the network once by letting exactly this case fall through.
#[test]
fn batch_apply_refuses_when_the_lockout_check_cannot_run() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");

    fixture
        .cmd(&[
            "batch",
            "--no-fetch",
            "--apply",
            "--root",
            fixture.nginx_root.to_str().unwrap(),
            "--out",
            fixture.firewall_script().to_str().unwrap(),
            "--ssh-log",
            "/nonexistent/auth.log",
            "--access-log",
            "/dev/null",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to apply"))
        .stderr(predicate::str::contains("--ssh-log"));

    assert!(
        !fixture.firewall_script().exists(),
        "refusing must mean nothing was written, not just nothing applied"
    );
}

/// The other half of the guard: rules that really would cut off the
/// admin who is connected right now. The fixture log's Accepted line is
/// for 192.0.2.10, which the rule below covers.
#[test]
fn batch_apply_refuses_to_block_the_connected_admin() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");
    fixture.run(&[
        "add-firewall-rule",
        "--address",
        "192.0.2.0/24",
        "--action",
        "block",
    ]);

    fixture
        .batch(&["--apply"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("192.0.2.10"));

    assert!(!fixture.firewall_script().exists());
}

/// Nothing is enforced without `--apply`, so the same rule set that is
/// refused above is written without complaint — the admin still gets to
/// read the script before running it, which is this project's default
/// everywhere else.
#[test]
fn batch_without_apply_writes_rules_the_guard_would_refuse_to_apply() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");
    fixture.run(&[
        "add-firewall-rule",
        "--address",
        "192.0.2.0/24",
        "--action",
        "block",
    ]);

    fixture.batch(&[]).assert().success();

    assert!(fixture.firewall_script().exists());
}

/// One step failing must not stop the others, and must still be visible:
/// `cron` only tells anyone about a job that exits non-zero.
#[test]
fn a_failed_step_is_reported_and_sets_a_failing_exit_status() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");

    // An unwritable output path fails the firewall step and nothing else.
    fixture
        .cmd(&[
            "batch",
            "--no-fetch",
            "--root",
            fixture.nginx_root.to_str().unwrap(),
            "--out",
            "/nonexistent/directory/firewall.nft",
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
            "--access-log",
            "/dev/null",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("FAIL"))
        .stderr(predicate::str::contains("firewall"));

    // The NGINX plane is independent and ran anyway.
    let config = fs::read_to_string(&site).unwrap();
    assert!(config.contains("stop-bots"), "config was:\n{config}");
}

/// Batch records each step under the same key the TUI's internal cron
/// uses, so the two schedulers agree about what has already run rather
/// than each doing the work again — and the Dashboard's "Scheduled
/// tasks" panel shows what the real cron did.
#[test]
fn batch_records_its_run_against_the_internal_crons_schedule() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");

    fixture.batch(&[]).assert().success();

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    for job in [
        stop_bots::cron::CronJob::RecordAccessStats,
        stop_bots::cron::CronJob::RenderFirewall,
        stop_bots::cron::CronJob::Detect(stop_bots::protection::Detector::SshScanners),
    ] {
        assert!(
            db.get_cron_last_run(job.id()).unwrap().is_some(),
            "{} should have been stamped",
            job.label()
        );
    }
}

/// Batch must share the access-log read offset with everything else that
/// reads the same log, not keep one of its own.
///
/// That offset is how `Db` remembers what has already been tallied. With a
/// key of its own, batch would re-count the whole log on its first run and
/// then double-count every line for as long as anything else read it too —
/// and the number it inflates is the hit count Dynamic Protection shows an
/// admin deciding whether to block a user agent.
#[test]
fn batch_shares_the_access_log_offset_with_record_access_stats() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");
    let log = fixture.nginx_root.join("access.log");
    fs::write(&log, access_line("203.0.113.5", "/", 200, "Mozilla/5.0")).unwrap();

    fixture.run(&["record-access-stats", "--access-log", log.to_str().unwrap()]);
    let after_cli = hit_count(&fixture, "Mozilla/5.0");
    assert_eq!(after_cli, 1, "one line, counted once");

    // Same log, nothing appended: batch has nothing new to count.
    let out = fixture.firewall_script();
    fixture
        .cmd(&[
            "batch",
            "--no-fetch",
            "--root",
            fixture.nginx_root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
            "--access-log",
            log.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert_eq!(
        hit_count(&fixture, "Mozilla/5.0"),
        after_cli,
        "batch re-counted a log line that had already been tallied"
    );
}

fn hit_count(fixture: &Fixture, user_agent: &str) -> i64 {
    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    db.list_user_agent_stats()
        .unwrap()
        .into_iter()
        .find(|s| s.user_agent == user_agent)
        .map(|s| s.hit_count)
        .unwrap_or(0)
}

// ---- `--source`: every download has a local-file path through it ----
//
// Every fetch in this project now takes a `--source <file>` override that
// parses the same format the server would have sent. It is a real feature
// for a host with no outbound access — and it is what lets these tests
// cover the parse-and-store half of a download without a network, which
// was the single largest gap in this suite's coverage.

/// Crawler ranges, from Google's published `prefixes` JSON. Both families
/// come out of one file, and both have to reach the database.
#[test]
fn update_ip_ranges_reads_a_local_file_instead_of_downloading() {
    let fixture = Fixture::new();

    fixture
        .run(&[
            "update-ip-ranges",
            "--source-id",
            "googlebot",
            "--source",
            "tests/fixtures/ipranges/googlebot-sample.json",
        ])
        .stdout(predicate::str::contains("Stored 3 CIDR range(s)"));

    // Visible where it matters: a rendered firewall script, not just a row.
    let out = fixture.managed.join("fw.nft");
    fixture.run(&[
        "render-firewall",
        "--backend",
        "nftables",
        "--out",
        out.to_str().unwrap(),
        "--force",
    ]);
    let script = fs::read_to_string(&out).unwrap();
    // Googlebot is a Search bot, allowed by default, so its ranges are
    // fetched but inert — which is the point of storing them: they are
    // what the spoofed-crawler detector checks *against*.
    assert!(!script.contains("192.178.4.0/27"), "script was:\n{script}");
}

/// A country's IPdeny zone file, which is bare CIDRs with blank lines.
#[test]
fn update_country_ranges_reads_a_local_file_instead_of_downloading() {
    let fixture = Fixture::new();

    fixture
        .run(&[
            "update-country-ranges",
            "--country",
            "nl",
            "--source",
            "tests/fixtures/ipranges/country-sample.zone",
        ])
        .stdout(predicate::str::contains("Stored 3 CIDR range(s)"));

    fixture.run(&["add-country", "--country", "nl"]);
    let out = fixture.managed.join("fw.nft");
    fixture.run(&[
        "render-firewall",
        "--backend",
        "nftables",
        "--out",
        out.to_str().unwrap(),
        "--force",
    ]);
    let script = fs::read_to_string(&out).unwrap();
    assert!(script.contains("86.48.240.0/20"), "script was:\n{script}");
}

/// The two shapes a reputation feed arrives in: a plain `.netset` list and
/// a provider's JSON. Both go through `--source`, so both parsers are
/// exercised offline.
#[test]
fn update_reputation_source_reads_a_local_file_in_either_format() {
    for (source_id, path, expected) in [
        (
            "firehol-level1",
            "tests/fixtures/ipranges/firehol-sample.netset",
            "198.51.100.0/24",
        ),
        (
            "aws",
            "tests/fixtures/ipranges/aws-sample.json",
            "13.34.37.64/27",
        ),
    ] {
        let fixture = Fixture::new();
        fixture
            .run(&[
                "update-reputation-source",
                "--source-id",
                source_id,
                "--source",
                path,
            ])
            .stdout(predicate::str::contains("Stored 2 range(s)"));
        // Fetching does not switch a feed on, so the output says so —
        // otherwise a fetch that changes nothing reads as a bug.
        fixture.run(&[
            "set-reputation-source",
            "--source-id",
            source_id,
            "--enabled",
            "true",
        ]);

        let out = fixture.managed.join("fw.nft");
        fixture.run(&[
            "render-firewall",
            "--backend",
            "nftables",
            "--out",
            out.to_str().unwrap(),
            "--force",
        ]);
        let script = fs::read_to_string(&out).unwrap();
        assert!(
            script.contains(expected),
            "{source_id}: script was:\n{script}"
        );
    }
}

/// The comments and blank lines a real `.netset` carries must not become
/// CIDRs. The fixture has one of each, and "Stored 2" above is only
/// meaningful because of it.
#[test]
fn a_feeds_comments_and_blank_lines_are_not_stored_as_ranges() {
    let fixture = Fixture::new();

    fixture.run(&[
        "update-reputation-source",
        "--source-id",
        "firehol-level1",
        "--source",
        "tests/fixtures/ipranges/firehol-sample.netset",
    ]);

    fixture
        .run(&["list-reputation-sources"])
        .stdout(predicate::str::contains("2 range"));
}

/// A `--source` that isn't there says which file, rather than leaving a
/// bare "No such file or directory" to be matched against the three paths
/// a command line can carry.
#[test]
fn a_missing_source_file_names_the_file() {
    let fixture = Fixture::new();

    fixture
        .cmd(&[
            "update-ip-ranges",
            "--source-id",
            "googlebot",
            "--source",
            "/nonexistent/ranges.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/nonexistent/ranges.json"));
}
