//! End-to-end happy-path test for the db + nginx + bot-list CLI flow:
//! update-bot-lists -> scan-sites -> apply-blocks, run against a throwaway
//! copy of the NGINX fixtures. No network access is used.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
mod common;
use common::{copy_dir_all, path_with, scan_sites, seed_bots, stop_bots, stop_bots_bin};

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
        let mut cmd = stop_bots_bin();
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
    for tool in ["nginx", "systemctl", "nft", "docker"] {
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

#[test]
fn update_scan_and_apply_blocks_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let nginx_root = tmp.path().join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &nginx_root);
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots_bin()
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
    stop_bots_bin()
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
    stop_bots_bin()
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

    stop_bots_bin()
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
        stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["list-probe-paths", "--db", db_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("/.env"))
        .stdout(predicate::str::contains("/internal"));

    stop_bots_bin()
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
    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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
        stop_bots_bin()
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

    stop_bots_bin()
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
    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

/// Trust end to end: an address reaches the firewall script as an accept
/// ahead of every drop and the NGINX trust file as a `geo` entry; a user
/// agent reaches the trust file only; the block clears for both; and
/// taking both away removes the file once nothing references it.
#[test]
fn trust_reaches_the_firewall_script_first_and_nginx_through_the_trust_file() {
    let fx = Fixture::new();
    fx.seed_bots();
    let site = fx.write_site("a.example");
    fx.scan_sites();
    let trust_conf = fx.conf_d.join("stop-bots-trusted.conf");

    // Typed with host bits set; stored, and echoed, as the network.
    fx.run(&["trust", "--address", "203.0.113.77/24"])
        .stdout(predicate::str::contains("Trusting 203.0.113.0/24"));
    fx.run(&["trust", "--user-agent", "UptimeRobot"])
        .stdout(predicate::str::contains("still judge it by its address"));
    fx.run(&["add-firewall-rule", "--address", "203.0.113.9"]);
    fx.run(&["list-trusted"])
        .stdout(predicate::str::contains("address     203.0.113.0/24"))
        .stdout(predicate::str::contains("user agent  UptimeRobot"));

    let script_path = fx._tmp.path().join("firewall.nft");
    let empty_log = fx._tmp.path().join("auth.log");
    fs::write(&empty_log, "").unwrap();
    fx.run(&[
        "render-firewall",
        "--backend",
        "nftables",
        "--out",
        script_path.to_str().unwrap(),
        "--ssh-log",
        empty_log.to_str().unwrap(),
    ]);
    let script = fs::read_to_string(&script_path).unwrap();
    let accept = script
        .find("ip saddr 203.0.113.0/24 accept")
        .unwrap_or_else(|| panic!("no accept for the trusted range:\n{script}"));
    let drop = script
        .find("ip saddr 203.0.113.9 drop")
        .unwrap_or_else(|| panic!("the block rule went missing:\n{script}"));
    assert!(accept < drop, "the accept must come first:\n{script}");

    fx.apply_blocks();
    let conf = fs::read_to_string(&trust_conf).expect("the trust file should exist");
    assert!(conf.contains("    203.0.113.0/24 1;"), "conf was:\n{conf}");
    assert!(conf.contains("\"~*UptimeRobot\" 1;"), "conf was:\n{conf}");
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.contains("if ($stop_bots_trusted) {"),
        "the site block does not clear for trusted clients:\n{written}"
    );

    fx.run(&["trust", "--remove", "--address", "203.0.113.0/24"]);
    fx.run(&["trust", "--remove", "--user-agent", "UptimeRobot"]);
    // Still there until the block that reads it is rewritten: deleting it
    // first would make `nginx -t` fail on an unknown variable.
    assert!(trust_conf.exists());
    fx.apply_blocks();
    assert!(
        !trust_conf.exists(),
        "the trust file outlived its last entry"
    );
    assert!(!fs::read_to_string(&site)
        .unwrap()
        .contains("stop_bots_trusted"));
}

/// Trusting a second user agent changes the trust file and no site's
/// block. An apply that counted only site files decided nothing changed
/// and never reloaded NGINX, so the new entry never took effect.
#[test]
fn a_change_to_the_trust_file_alone_still_reloads_nginx() {
    let fx = Fixture::new();
    fx.seed_bots();
    fx.write_site("a.example");
    fx.scan_sites();
    let (bin, calls) = fake_tools(fx._tmp.path());
    let apply = |fx: &Fixture| {
        fx.cmd(&["apply-blocks", "--root", fx.nginx_root.to_str().unwrap()])
            .env("PATH", path_with(&bin))
            .assert()
            .success()
    };

    fx.run(&["trust", "--user-agent", "UptimeRobot"]);
    apply(&fx);
    fx.run(&["trust", "--user-agent", "Pingdom"]);
    apply(&fx).stdout(predicate::str::contains("Reloaded NGINX"));

    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(
        log.lines()
            .filter(|l| l.starts_with("systemctl reload"))
            .count(),
        2,
        "the second apply did not reload; calls were:\n{log}"
    );
}

#[test]
fn trust_refuses_what_would_trust_more_than_it_says() {
    let fx = Fixture::new();
    for (args, why) in [
        (vec!["trust", "--address", "0.0.0.0/0"], "every address"),
        (vec!["trust", "--user-agent", " "], "every client"),
        (
            vec!["trust", "--remove", "--address", "203.0.113.7"],
            "is not trusted",
        ),
    ] {
        fx.cmd(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(why));
    }
    fx.run(&["list-trusted"])
        .stdout(predicate::str::contains("Nothing is trusted."));
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

/// An exemption scoped to one user agent, end to end through the CLI: it
/// reaches the site's block as a clear of its own, beside the bot rule it
/// narrows, and `--remove` takes it back out.
#[test]
fn exempt_path_with_a_user_agent_scopes_the_clear_to_that_client() {
    let fx = Fixture::new();
    let site_file = fx.write_site("a.example");
    fx.seed_bots();
    fx.scan_sites();
    let exempt = |extra: &[&str]| {
        let mut args = vec![
            "exempt-path",
            "--site",
            "a.example",
            "--path",
            "/remote.php/dav/",
            "--user-agent",
            "okhttp",
        ];
        args.extend_from_slice(extra);
        fx.run(&args)
    };

    exempt(&[]).stdout(predicate::str::contains("contains \"okhttp\""));
    fx.apply_blocks();
    let exempted = fs::read_to_string(&site_file).unwrap();
    for expected in [
        "if ($http_user_agent ~* \"okhttp\") {",
        "set $stop_bots_exempt $uri;",
        "if ($stop_bots_exempt ~* \"^(/remote\\.php/dav/)\") {",
    ] {
        assert!(
            exempted.contains(expected),
            "missing {expected}; the site was:\n{exempted}"
        );
    }

    exempt(&["--remove"]);
    fx.apply_blocks();
    let removed = fs::read_to_string(&site_file).unwrap();
    assert!(
        !removed.contains("stop_bots_exempt"),
        "the site was:\n{removed}"
    );
}

#[test]
fn exempt_path_refuses_a_user_agent_that_would_match_more_than_it_says() {
    let fx = Fixture::new();
    fx.write_site("a.example");
    fx.scan_sites();
    let base = ["exempt-path", "--site", "a.example", "--path", "/dav/"];
    for (extra, why) in [
        (vec!["--user-agent", " "], "every client"),
        (vec!["--user-agent", "ok\"http"], "cannot contain"),
        (
            vec!["--user-agent", "okhttp", "--remove"],
            "was not exempt for",
        ),
    ] {
        let args: Vec<&str> = base.iter().copied().chain(extra).collect();
        fx.cmd(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(why));
    }
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

    stop_bots_bin()
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

    stop_bots_bin()
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

/// The containerised case, end to end: with the test and reload commands
/// pointed at `docker exec`, an apply must drive *those* and must never
/// fall back to the host's `nginx` or `systemctl` — a host with NGINX in a
/// container generally has neither, and silently reloading the wrong one
/// is worse than failing.
#[test]
fn a_configured_reload_command_replaces_systemctl_entirely() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    write_site(&nginx_root, "a.example");
    let (bin, calls) = fake_tools(tmp.path());

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    stop_bots(&[
        "set-nginx-commands",
        "--db",
        db_path.to_str().unwrap(),
        "--test",
        "docker exec web nginx -t",
        "--reload",
        "docker exec web nginx -s reload",
    ]);

    stop_bots_bin()
        .env("PATH", path_with(&bin))
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let log = fs::read_to_string(&calls).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(
        lines,
        [
            "docker exec web nginx -t",
            "docker exec web nginx -s reload"
        ],
        "validate first, then reload, both through docker; log was: {log}"
    );
}

/// A configured test command that fails still stops the reload. The guard
/// is the property, not the binary it happens to run.
#[test]
fn a_configured_test_command_that_fails_stops_the_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    write_site(&nginx_root, "a.example");
    let (bin, calls) = fake_tools(tmp.path());
    fs::write(
        tmp.path().join("fail-docker"),
        "nginx: [emerg] unknown directive\n",
    )
    .unwrap();

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    stop_bots(&[
        "set-nginx-commands",
        "--db",
        db_path.to_str().unwrap(),
        "--test",
        "docker exec web nginx -t",
        "--reload",
        "docker exec web nginx -s reload",
    ]);

    stop_bots_bin()
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
        .stderr(predicate::str::contains("unknown directive"));

    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(
        log.lines().count(),
        1,
        "the reload must not run after a failed check; log was: {log}"
    );
}

/// Setting only one of the two leaves the other at its default, and the
/// command is echoed back so `set-nginx-commands` with no flags is a way
/// to ask what is in effect.
#[test]
fn set_nginx_commands_reports_both_and_defaults_the_unset_one() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots(&[
        "set-nginx-commands",
        "--db",
        db_path.to_str().unwrap(),
        "--reload",
        "docker exec web nginx -s reload",
    ])
    .stdout(predicate::str::contains("Test command:   nginx -t"))
    .stdout(predicate::str::contains(
        "Reload command: docker exec web nginx -s reload",
    ));

    stop_bots(&["set-nginx-commands", "--db", db_path.to_str().unwrap()]).stdout(
        predicate::str::contains("Reload command: docker exec web nginx -s reload"),
    );

    stop_bots(&[
        "set-nginx-commands",
        "--db",
        db_path.to_str().unwrap(),
        "--reset",
    ])
    .stdout(predicate::str::contains(
        "Reload command: systemctl reload nginx",
    ));
}

/// An unusable command is rejected when it is stored, not at the next
/// reload — which could be a cron run hours later with nobody watching.
#[test]
fn set_nginx_commands_rejects_an_unparsable_command() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots_bin()
        .args([
            "set-nginx-commands",
            "--db",
            db_path.to_str().unwrap(),
            "--reload",
            "docker exec \"web nginx -s reload",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unbalanced quote"));
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("1.2.3.4"))
        .stdout(predicate::str::contains("66.249.64.0/19"));

    let script_path = tmp.path().join("stop-bots.sh");
    stop_bots_bin()
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

    stop_bots_bin()
        .args(["remove-firewall-rule", "--db", db_path, "--id", "1"])
        .assert()
        .success();

    stop_bots_bin()
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

    stop_bots_bin()
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
    let output = stop_bots_bin()
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
    let output = stop_bots_bin()
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

    stop_bots_bin()
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
    stop_bots_bin()
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
    stop_bots_bin()
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
    stop_bots_bin()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Blocklist"))
        .stdout(predicate::str::contains("No countries selected"));

    stop_bots_bin()
        .args(["add-country", "--db", db_path, "--country", "nl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added country nl"));

    stop_bots_bin()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("nl"));

    stop_bots_bin()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Allowlist"));

    stop_bots_bin()
        .args(["list-selected-countries", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Allowlist"))
        .stdout(predicate::str::contains("nl"));

    stop_bots_bin()
        .args(["remove-country", "--db", db_path, "--country", "nl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Removed country nl"));

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success();

    let script_path = tmp.path().join("stop-bots.sh");
    stop_bots_bin()
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

    stop_bots_bin()
        .args(["set-geo-mode", "--db", db_path, "--mode", "allowlist"])
        .assert()
        .success();
    stop_bots_bin()
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
    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9"));

    // Re-running against the same log must not add a duplicate rule.
    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9").not());
}

/// `--threshold 0` used to be accepted, and every detector compares
/// `count >= threshold`, so it blocked every address in the log whatever
/// it had done — five single failed logins became five block rules. One
/// flag, or one shell variable that expanded to nothing, away from mass
/// blocking in a tool whose whole premise is not blocking people by
/// mistake.
///
/// Rejected at parse time, so nothing is written and no database is even
/// created; 1 is still allowed, because "one failed attempt is a scanner"
/// is an aggressive policy rather than a mistake.
#[test]
fn block_scanners_refuses_a_threshold_of_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("auth.log");
    fs::write(&log_path, repeat_failed_attempt("198.51.100.9", 1)).unwrap();

    for command in ["block-scanners", "block-web-scanners"] {
        stop_bots_bin()
            .args([command, "--db", db_path, "--threshold", "0"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("matches every address in the log"));
    }

    assert!(
        !std::path::Path::new(db_path).exists(),
        "a rejected threshold still created a database"
    );

    stop_bots_bin()
        .args([
            "block-scanners",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
            "--threshold",
            "1",
        ])
        .assert()
        .success();
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
        .args(["list-firewall-rules", "--db", db_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("198.51.100.9"));

    // Re-running against the same log must not add a duplicate rule.
    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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

    stop_bots_bin()
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
    stop_bots_bin()
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

    let output = stop_bots_bin()
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

/// The other half of the guard: rules that would cut off the admin who is
/// connected right now. The fixture log's Accepted line is for 192.0.2.10,
/// which the rule below covers.
///
/// Batch records that login before rendering, as the internal cron does,
/// so the admin gets an Allow rule ahead of the block rather than a
/// refusal. (This used to be the refusal case, because batch never fed the
/// login window.) No `--apply`: with the admin protected nothing would stop
/// it running the real `nft`.
#[test]
fn batch_protects_the_connected_admin_ahead_of_a_block_covering_them() {
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

    let script = fs::read_to_string(fixture.firewall_script()).unwrap();
    let allow = script.find("ip saddr 192.0.2.10 accept");
    let block = script.find("ip saddr 192.0.2.0/24 drop");
    assert!(
        matches!((allow, block), (Some(a), Some(b)) if a < b),
        "the admin's address should be allowed ahead of the block:\n{script}"
    );
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

/// The report exists because nothing else in this tool answered "what is
/// my own policy turning away" — which is how three first-party apps were
/// blocked on a real host for days. Reading the log is the whole feature,
/// so the end-to-end test reads a log.
#[test]
fn list_turned_away_names_the_refused_client_and_what_still_got_through() {
    let fixture = Fixture::new();
    let log = fixture.nginx_root.join("access.log");
    let client = "Jellyfin Android TV/0.19.10 via jellyfin-sdk-kotlin (OkHttp/4.12.0)";
    fs::write(
        &log,
        [
            access_line("203.0.113.5", "/", 444, client),
            access_line("203.0.113.5", "/", 444, client),
            access_line("203.0.113.6", "/", 200, "Mozilla/5.0"),
        ]
        .concat(),
    )
    .unwrap();
    fixture.run(&["set-block-response", "--response", "close"]);

    let out = fixture.run(&["list-turned-away", "--access-log", log.to_str().unwrap()]);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();

    assert!(
        stdout.contains("Jellyfin Android TV"),
        "the refused client must be named:\n{stdout}"
    );
    assert!(
        !stdout.contains("Mozilla/5.0"),
        "a client that was never refused has nothing to report:\n{stdout}"
    );
}

/// A host turning nobody away says so, rather than printing an empty
/// table and leaving the reader to wonder whether it ran.
#[test]
fn list_turned_away_says_so_when_nothing_was_refused() {
    let fixture = Fixture::new();
    let log = fixture.nginx_root.join("access.log");
    fs::write(&log, access_line("203.0.113.6", "/", 200, "Mozilla/5.0")).unwrap();

    fixture
        .run(&["list-turned-away", "--access-log", log.to_str().unwrap()])
        .stdout(predicate::str::contains(
            "Nothing in this log was turned away",
        ));
}

/// A user agent as `escape=json` writes one carrying an OSC 52 sequence,
/// which would set the operator's clipboard. serde decodes the `\u001b`
/// into a real ESC, so it reaches stdout unless the printing replaces it.
fn json_line_with_hostile_agent(status: u16) -> String {
    format!(
        r#"{{"remote_addr":"203.0.113.5","request_uri":"/","status":"{status}","http_user_agent":"evil\u001b]52;c;aGk=\u0007"}}"#
    ) + "\n"
}

/// Asserts `stdout` names the hostile agent from
/// [`json_line_with_hostile_agent`] with its control characters replaced.
fn assert_printed_defanged(stdout: &str) {
    assert!(
        !stdout.contains(['\u{1b}', '\u{7}']),
        "a control character reached the terminal: {stdout:?}"
    );
    assert!(
        stdout.contains("evil\u{fffd}]52;c;aGk=\u{fffd}"),
        "the agent should still be listed, defanged: {stdout:?}"
    );
}

#[test]
fn list_turned_away_replaces_control_characters_in_a_user_agent() {
    let fixture = Fixture::new();
    let log = fixture.nginx_root.join("access.log");
    fs::write(&log, json_line_with_hostile_agent(444)).unwrap();
    fixture.run(&["set-block-response", "--response", "close"]);

    let out = fixture.run(&["list-turned-away", "--access-log", log.to_str().unwrap()]);

    assert_printed_defanged(&String::from_utf8(out.get_output().stdout.clone()).unwrap());
}

#[test]
fn list_access_stats_replaces_control_characters_in_a_user_agent() {
    let fixture = Fixture::new();
    let log = fixture.nginx_root.join("access.log");
    fs::write(&log, json_line_with_hostile_agent(200)).unwrap();
    fixture.run(&["record-access-stats", "--access-log", log.to_str().unwrap()]);

    let out = fixture.run(&["list-access-stats"]);

    assert_printed_defanged(&String::from_utf8(out.get_output().stdout.clone()).unwrap());
}

/// Batch must share the access-log read offset with everything else that
/// reads the same log, not keep one of its own.
///
/// That offset is how `Db` remembers what has already been tallied. With a
/// key of its own, batch would re-count the whole log on its first run and
/// then double-count every line for as long as anything else read it too —
/// and the number it inflates is the hit count Firewall shows an
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

// ---- `stop-bots web` startup checks ----

/// Exposing the console is opt-in, and the refusal has to be a refusal:
/// nothing may be persisted, or a later plain `stop-bots web` comes up on
/// every interface having never passed this check.
#[test]
fn web_refuses_a_non_loopback_bind_without_expose_and_saves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots_bin()
        .args([
            "web",
            "--db",
            db_path.to_str().unwrap(),
            "--bind",
            "0.0.0.0:8787",
            "--save",
            "--set-password",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to bind"))
        .stderr(predicate::str::contains("ssh -L"));

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    assert_eq!(
        db.get_text_setting(stop_bots::web::BIND_KEY).unwrap(),
        None,
        "a refused bind must not be persisted"
    );
    assert!(
        !db.get_bool_setting(stop_bots::web::EXPOSE_KEY, false)
            .unwrap(),
        "nor may the exposure flag be"
    );
}

/// The deliberate path does persist, so a later plain run starts the same
/// way.
#[test]
fn web_with_expose_and_save_persists_the_bind() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots_cmd(&[
        "web",
        "--db",
        db_path.to_str().unwrap(),
        "--bind",
        "0.0.0.0:8788",
        "--expose",
        "--allowed-hosts",
        "admin.example.com",
        "--save",
        "--set-password",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("New password:"));

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    assert_eq!(
        db.get_text_setting(stop_bots::web::BIND_KEY)
            .unwrap()
            .as_deref(),
        Some("0.0.0.0:8788")
    );
    assert!(db
        .get_bool_setting(stop_bots::web::EXPOSE_KEY, false)
        .unwrap());
    assert_eq!(
        db.get_text_setting(stop_bots::web::ALLOWED_HOSTS_KEY)
            .unwrap()
            .as_deref(),
        Some("admin.example.com")
    );
}

/// The two proxy settings are read from the database on every request, so
/// like `--allowed-hosts` they are stored with or without `--save` — and
/// `false` has to switch them back off, not just leave them alone.
#[test]
fn web_stores_the_proxy_settings_and_can_turn_them_off() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let run = |value: &str| {
        stop_bots_cmd(&[
            "web",
            "--db",
            db_path.to_str().unwrap(),
            "--trust-forwarded-for",
            value,
            "--secure-cookie",
            value,
            "--set-password",
        ])
        .assert()
        .success();
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        (
            db.get_bool_setting(stop_bots::web::TRUST_FORWARDED_KEY, false)
                .unwrap(),
            db.get_bool_setting(stop_bots::web::SECURE_COOKIE_KEY, false)
                .unwrap(),
        )
    };

    assert_eq!(run("true"), (true, true));
    assert_eq!(run("false"), (false, false));
}

/// `--set-password` stores a hash and prints the password once. The
/// password itself must not survive anywhere this program can read it
/// back.
#[test]
fn web_set_password_stores_only_a_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    let output = stop_bots_cmd(&["web", "--db", db_path.to_str().unwrap(), "--set-password"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let password = stdout
        .lines()
        .next()
        .unwrap()
        .trim_start_matches("New password: ")
        .to_string();
    assert!(!password.is_empty(), "stdout was:\n{stdout}");

    let db = stop_bots::db::Db::open(&db_path).unwrap();
    let stored = db
        .get_text_setting(stop_bots::web::auth::PASSWORD_HASH_KEY)
        .unwrap()
        .unwrap();
    assert!(stored.starts_with("$argon2id$"), "was: {stored}");
    assert!(!stored.contains(&password));
    assert!(stop_bots::web::auth::verify_password(&db, &password).unwrap());
}

/// An unparsable bind address is rejected by name rather than defaulted.
#[test]
fn web_rejects_a_bind_that_is_not_an_address_and_port() {
    let tmp = tempfile::tempdir().unwrap();
    stop_bots_bin()
        .args([
            "web",
            "--db",
            tmp.path().join("db.sqlite3").to_str().unwrap(),
            "--bind",
            "8787",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("8787"));
}

/// Stages a fake Debian-with-systemd root that `install web` will accept,
/// and a binary for its ExecStart to point at.
fn fake_debian_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("run/systemd/system")).unwrap();
    fs::create_dir_all(tmp.path().join("etc")).unwrap();
    fs::write(tmp.path().join("etc/debian_version"), "13.1\n").unwrap();
    let binary = tmp.path().join("stop-bots");
    fs::write(&binary, b"#!/bin/true\n").unwrap();
    (tmp, binary)
}

/// The whole installer, end to end, into a prefix: a unit, the two
/// directories, a generated password, and no `systemctl` — a unit under a
/// prefix is not a path systemd reads, and saying so beats running
/// `daemon-reload` and implying the file took effect.
#[test]
fn install_web_writes_a_unit_and_a_password_under_a_prefix() {
    let (tmp, binary) = fake_debian_root();

    let output = stop_bots_bin()
        .args([
            "install",
            "web",
            "--prefix",
            tmp.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
        ])
        .assert()
        .success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains("Console password"), "was: {stdout}");
    assert!(stdout.contains("skipping systemctl"), "was: {stdout}");

    let unit = fs::read_to_string(tmp.path().join("etc/systemd/system/stop-bots-web.service"))
        .expect("no unit written");
    assert!(unit.contains(&format!("ExecStart={} web", binary.display())));
    // Directive lines only: the unit's own comments name
    // `ProtectSystem=full` to explain why it is not used, so a plain
    // substring search finds it in the prose.
    let directives: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert!(
        directives.contains(&"ProtectSystem=yes"),
        "was: {directives:?}"
    );
    assert!(
        !directives.contains(&"ProtectSystem=full"),
        "full would make /etc read-only and break the first NGINX apply"
    );
    assert!(tmp.path().join("var/lib/stop-bots/db.sqlite3").exists());
    assert!(tmp.path().join("etc/stop-bots").is_dir());
}

/// Re-running must not issue a second password: the first one was printed
/// once and written down, and silently replacing it locks the operator out
/// of their own console.
#[test]
fn install_web_run_twice_keeps_the_first_password() {
    let (tmp, binary) = fake_debian_root();
    let args = [
        "install",
        "web",
        "--prefix",
        tmp.path().to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
    ];

    let first = stop_bots_bin().args(args).assert().success();
    let first = String::from_utf8(first.get_output().stdout.clone()).unwrap();
    let second = stop_bots_bin().args(args).assert().success();
    let second = String::from_utf8(second.get_output().stdout.clone()).unwrap();

    assert!(first.contains("Console password"));
    assert!(
        !second.contains("Console password"),
        "a second password was issued: {second}"
    );
    assert!(second.contains("already set"), "was: {second}");
    assert!(second.contains("already up to date"), "was: {second}");
}

/// A service is where the proxy settings are needed, and a second
/// `stop-bots web` to set them would collide with the one systemd runs.
#[test]
fn install_web_stores_the_proxy_settings() {
    let (tmp, binary) = fake_debian_root();
    stop_bots_bin()
        .args([
            "install",
            "web",
            "--prefix",
            tmp.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--trust-forwarded-for",
            "true",
            "--secure-cookie",
            "true",
        ])
        .assert()
        .success();

    let db = stop_bots::db::Db::open(tmp.path().join("var/lib/stop-bots/db.sqlite3")).unwrap();
    assert!(db
        .get_bool_setting(stop_bots::web::TRUST_FORWARDED_KEY, false)
        .unwrap());
    assert!(db
        .get_bool_setting(stop_bots::web::SECURE_COOKIE_KEY, false)
        .unwrap());
}

/// `--dry-run` has to be trustworthy or nobody will use it on the one
/// command in this project that starts a daemon.
#[test]
fn install_web_dry_run_changes_nothing() {
    let (tmp, binary) = fake_debian_root();

    stop_bots_bin()
        .args([
            "install",
            "web",
            "--prefix",
            tmp.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("nothing was changed"));

    assert!(!tmp
        .path()
        .join("etc/systemd/system/stop-bots-web.service")
        .exists());
    assert!(!tmp.path().join("var/lib/stop-bots").exists());
    assert!(!tmp.path().join("etc/stop-bots").exists());
}

/// A host that is not Debian is told so rather than given a unit nobody
/// has checked.
#[test]
fn install_web_refuses_a_host_that_is_not_debian() {
    let (tmp, binary) = fake_debian_root();
    fs::remove_file(tmp.path().join("etc/debian_version")).unwrap();

    stop_bots_bin()
        .args([
            "install",
            "web",
            "--prefix",
            tmp.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not look like Debian"));
}

// ---- auto-apply ----

/// The switch itself: off by default, settable, and readable back.
///
/// Off by default is the part worth pinning. Every other default in this
/// project decides what gets *written*; this one decides whether a machine
/// reloads a live web server unattended, and an upgrade must not start
/// doing that on an existing install's behalf.
#[test]
fn auto_apply_is_off_until_it_is_turned_on() {
    let fixture = Fixture::new();

    fixture.run(&["set-auto-apply", "--enabled", "false"]);
    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(!db.get_auto_apply().unwrap(), "off is the default");
    drop(db);

    fixture
        .run(&["set-auto-apply", "--enabled", "true"])
        .stdout(predicate::str::contains("enabled"))
        // Says where the work happens, because it is not in this command:
        // setting this on a host with no console running turns on a switch
        // nothing will ever read.
        .stdout(predicate::str::contains("internal cron"));

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(db.get_auto_apply().unwrap());
}

/// Turning the switch on must not, by itself, apply anything: the CLI sets
/// a flag, and the internal cron inside the console or the TUI is what acts
/// on it. A `set-` command that quietly reloaded NGINX would be the worst
/// possible surprise from a subcommand whose name says "set".
#[test]
fn setting_auto_apply_does_not_itself_touch_any_config() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");
    let before = fs::read_to_string(&site).unwrap();

    fixture.run(&["set-auto-apply", "--enabled", "true"]);

    assert_eq!(
        fs::read_to_string(&site).unwrap(),
        before,
        "setting the switch rewrote a site config"
    );
}

/// The switched-on path, end to end: a config that has fallen behind the
/// database is rewritten, and a second pass finds nothing left to do.
///
/// Lives here rather than beside the code because `apply_all_sites`
/// resolves its managed directory from `STOP_BOTS_NGINX_DIR`, and with
/// robots.txt and rate limiting both off it *deletes* the files that
/// variable points at — `/etc/stop-bots/nginx/robots.txt` on a machine
/// that has one. So the variable has to be pointed somewhere safe, and it
/// is process-global: setting it in the library's own test binary breaks
/// `nginx::tests::kitchen_sink_block_matches_the_golden`, whose golden
/// holds the default path. Nothing in this binary reads that default —
/// every other test here passes the directory to a spawned command — so
/// this is the one place it can be set without breaking something else.
///
/// `reload` is false: a test that let the reload through would run
/// `systemctl reload nginx` on whatever machine hosts the suite.
#[test]
fn auto_apply_rewrites_a_stale_site_config_and_then_leaves_it_alone() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");
    // Both, for the same reason: this test drives `cron::apply_nginx`
    // in-process, so there is no child to pass them to.
    unsafe { std::env::set_var("STOP_BOTS_NGINX_DIR", &fixture.managed) };
    unsafe { std::env::set_var("STOP_BOTS_NGINX_CONF_D", &fixture.conf_d) };

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    db.set_auto_apply(true).unwrap();

    let summary = stop_bots::cron::apply_nginx(&db, &fixture.nginx_root, false);
    assert!(summary.contains("applied 1 site(s)"), "{summary}");
    assert!(summary.contains("1 file(s) changed"), "{summary}");
    // The reload is the step with a side effect outside this project's
    // files, so "did not reload" is said rather than assumed.
    assert!(summary.contains("not reloaded"), "{summary}");
    assert!(
        fs::read_to_string(&site).unwrap().contains("stop-bots"),
        "the generated block never reached the config"
    );

    // Nothing changed on disk the second time, so there is nothing to
    // reload — what makes an hourly job cheap on a quiet host.
    let again = stop_bots::cron::apply_nginx(&db, &fixture.nginx_root, false);
    assert_eq!(again, "1 site(s) already up to date");
}

/// The firewall switch is separate from the NGINX one, and separately off.
/// Two switches because the risks are not comparable — a bad NGINX config
/// costs a failed `nginx -t`, a bad firewall ruleset costs the host.
#[test]
fn the_firewall_auto_apply_switch_is_independent_of_the_nginx_one() {
    let fixture = Fixture::new();

    fixture.run(&["set-auto-apply", "--enabled", "true"]);

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(db.get_auto_apply().unwrap());
    assert!(
        !db.get_auto_apply_firewall().unwrap(),
        "the NGINX switch must not turn the firewall one on"
    );
    drop(db);

    fixture
        .run(&["set-auto-apply-firewall", "--enabled", "true"])
        .stdout(predicate::str::contains("enabled"))
        // The condition that most often stops it doing anything, said when
        // it is switched on rather than discovered in a summary a day on.
        .stdout(predicate::str::contains("anti-lockout"));

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(db.get_auto_apply_firewall().unwrap());
}

// ---- maintenance ----

/// The flow an admin reaches for after looking at `du`: prune what has
/// accumulated, hand the free pages back, and say what moved.
///
/// Seeds a user agent last seen well outside the 90-day window, which is
/// the row the scheduled job exists to remove.
#[test]
fn maintain_prunes_stale_user_agents_and_reports_the_size() {
    let fixture = Fixture::new();
    let stale = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        - (120 * 24 * 60 * 60);
    {
        let db = stop_bots::db::Db::open(&fixture.db).unwrap();
        let mut counts = std::collections::HashMap::new();
        counts.insert("long-gone-crawler".to_string(), 7);
        db.record_user_agent_hits(&counts, stale).unwrap();
    }

    fixture
        .run(&["maintain"])
        .stdout(predicate::str::contains("pruned 1 stale user agents"))
        .stdout(predicate::str::contains("Database is"));

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(
        db.list_user_agent_stats().unwrap().is_empty(),
        "the stale row should be gone"
    );
    assert!(
        db.get_cron_last_run(stop_bots::cron::CronJob::Maintenance.id())
            .unwrap()
            .is_some(),
        "running it by hand should satisfy the internal cron's schedule too"
    );
}

/// `--force-compact` rewrites the file whatever the thresholds say. The
/// claim under test is that the flag reaches `VACUUM` at all — a fixture
/// database has nothing worth reclaiming, so the scheduled job would
/// (correctly) leave it alone and the line would never appear.
#[test]
fn maintain_can_be_told_to_compact_regardless() {
    let fixture = Fixture::new();

    fixture
        .run(&["maintain", "--force-compact"])
        .stdout(predicate::str::contains("Compacted anyway"));
}

/// A `Command` carrying `args`, for the tests above that need one without
/// the `Fixture`'s own NGINX directories. Still not the host's: see
/// [`common::stop_bots_bin`].
fn stop_bots_cmd(args: &[&str]) -> Command {
    let mut cmd = stop_bots_bin();
    cmd.args(args);
    cmd
}
