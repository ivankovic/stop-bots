//! End-to-end happy-path test for the db + nginx + bot-list CLI flow:
//! update-bot-lists -> scan-sites -> apply-blocks, run against a throwaway
//! copy of the NGINX fixtures. No network access is used.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
mod common;
use common::{
    copy_dir_all, path_with, scan_sites, seed_bots, stop_bots, stop_bots_bin, stop_bots_with_host,
};

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
        // A root of its own from the start, which `set-web-server` replaces:
        // with none, every command reads the stock `/etc/nginx` for the
        // access logs its config names, the machine's own.
        fs::write(
            tmp.path().join("host.conf"),
            format!("nginx_root = {}\n", nginx_root.display()),
        )
        .unwrap();
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
            .env("STOP_BOTS_APACHE_DIR", &self.managed)
            .env("STOP_BOTS_NGINX_CONF_D", &self.conf_d)
            .env("STOP_BOTS_HOST_CONF", self.host_conf())
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

    /// One `server` block named `name` whose document root holds `files`
    /// (each empty), scanned.
    fn scan_site_serving(&self, name: &str, files: &[&str]) {
        let root = self._tmp.path().join("www").join(name);
        fs::create_dir_all(&root).unwrap();
        for file in files {
            fs::write(root.join(file), "").unwrap();
        }
        fs::write(
            self.nginx_root.join(format!("{name}.conf")),
            format!(
                "server {{\n    server_name {name};\n    root {};\n}}\n",
                root.display()
            ),
        )
        .unwrap();
        self.scan_sites();
    }

    fn robots_txt(&self) -> std::path::PathBuf {
        self.managed.join("robots.txt")
    }

    /// This fixture's host settings file.
    fn host_conf(&self) -> std::path::PathBuf {
        self._tmp.path().join("host.conf")
    }

    fn rate_limit_conf(&self) -> std::path::PathBuf {
        self.conf_d.join("stop-bots-limits.conf")
    }
}

/// The rule in an nftables script that decides `element`, and its line
/// number: the `add rule` matching the set whose `add element` block lists
/// it, e.g. `(31, "ip saddr @allow_v4 accept")`. Lower lines are matched
/// first. `None` if no set lists `element`.
fn nft_rule_for(script: &str, element: &str) -> Option<(usize, String)> {
    let mut set = None;
    for line in script.lines() {
        if let Some(rest) = line.strip_prefix("add element inet stop_bots ") {
            set = rest.split(' ').next();
        } else if line.starts_with('\t') && line.trim().trim_end_matches(',') == element {
            let matcher = format!("@{} ", set?);
            return script.lines().enumerate().find_map(|(at, l)| {
                l.strip_prefix("add rule inet stop_bots bot_rules ")
                    .filter(|rule| rule.contains(&matcher))
                    .map(|rule| (at, rule.to_string()))
            });
        }
    }
    None
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
    for tool in [
        "nginx",
        "apache2ctl",
        "systemctl",
        "nft",
        "docker",
        "systemd-run",
    ] {
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
        // Five of the sample's seven bots: one has no pattern, and the two
        // quoted patterns (one bot's only one) are left out, and said to be.
        .stdout(predicate::str::contains("Stored 5 bot(s)"))
        .stdout(predicate::str::contains("It left out 2 pattern(s)"));

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
                "run-detector",
                "spoofed-crawlers",
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
/// list is chosen for: a legitimate admin path must survive it. With no
/// site scanned, nothing says WordPress is absent, so its login is not a
/// probe either (see `run_detector_probe_paths_blocks_the_wordpress_login_
/// only_without_wordpress` for a host that has been scanned).
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
            "run-detector",
            "probe-paths",
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
            "run-detector",
            "probe-paths",
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
            "run-detector",
            "honeypot",
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

/// Let's Encrypt validates from AWS, so turning that feed on says what it
/// does to port 80, and the choice that closes it is the one that says
/// certificates will stop renewing.
#[test]
fn enabling_aws_with_port_80_closed_says_renewals_will_stop() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db.sqlite3");
    let db = db.to_str().unwrap();

    stop_bots_bin()
        .args(["set-cloud-port-80", "--db", db, "--enabled", "false"])
        .assert()
        .success()
        .stdout(predicate::str::contains("block port 80 too"));
    stop_bots_bin()
        .args([
            "set-reputation-source",
            "--db",
            db,
            "--source-id",
            "aws",
            "--enabled",
            "true",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("stop renewing"));
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

/// The checked-in ip2asn sample, gzipped as iptoasn.com serves it, in
/// `dir`.
fn gzipped_ip2asn_sample(dir: &Path) -> std::path::PathBuf {
    use std::io::Write as _;
    let sample = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ipranges/ip2asn-sample.tsv"),
    )
    .unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&sample).unwrap();
    let path = dir.join("ip2asn-combined.tsv.gz");
    fs::write(&path, gz.finish().unwrap()).unwrap();
    path
}

/// Blocking a hosting provider end to end, offline: select it, read its
/// ranges from a local copy of the table, and find them in the script,
/// with port 80 left open as for the cloud feeds.
#[test]
fn a_hosting_asn_reaches_the_firewall_script_with_port_80_open() {
    let fx = Fixture::new();
    let table = gzipped_ip2asn_sample(fx._tmp.path());
    let out = fx._tmp.path().join("firewall.nft");

    fx.run(&["add-hosting-asn", "--asn", "AS24940"])
        .stdout(predicate::str::contains("AS24940 (Hetzner) is now blocked"))
        .stdout(predicate::str::contains("not just bots"))
        .stdout(predicate::str::contains("No ranges stored yet"));
    fx.run(&["update-hosting-asns", "--source", table.to_str().unwrap()])
        .stdout(predicate::str::contains(
            "Stored 3 range(s) for AS24940 (Hetzner)",
        ));
    fx.run(&[
        "render-firewall",
        "--backend",
        "nftables",
        "--out",
        out.to_str().unwrap(),
        "--ssh-log",
        "/nonexistent/auth.log",
    ]);

    let script = fs::read_to_string(&out).unwrap();
    for range in ["5.9.0.0/16", "78.46.0.0/15", "2a01:4f8::/32"] {
        let listed = script
            .lines()
            .filter(|line| line.trim().trim_end_matches(',') == range)
            .count();
        assert_eq!(
            listed, 2,
            "{range} should be in the port-80 accept set and the block set:
{script}"
        );
        let (_, first) = nft_rule_for(&script, range).unwrap();
        assert!(
            first.contains("tcp dport 80 accept"),
            "{range} should meet the port-80 accept first, met {first:?}"
        );
    }
    assert!(
        !script.contains("51.68.0.0"),
        "OVH is in the table but not selected:\n{script}"
    );
}

/// Only selected ASNs' ranges are kept, so naming one that is not is an
/// error that says how to select it; one the table lacks is a failure
/// that names it.
#[test]
fn update_hosting_asns_refuses_an_unselected_asn_and_names_a_missing_one() {
    let fx = Fixture::new();
    let table = "tests/fixtures/ipranges/ip2asn-sample.tsv";

    fx.cmd(&["update-hosting-asns", "--asn", "16276", "--source", table])
        .assert()
        .failure()
        .stderr(predicate::str::contains("add-hosting-asn --asn 16276"));

    fx.run(&["add-hosting-asn", "--asn", "64999"]);
    fx.cmd(&["update-hosting-asns", "--source", table])
        .assert()
        .failure()
        .stderr(predicate::str::contains("AS64999: not in the table"));
}

#[test]
fn removing_a_hosting_asn_takes_its_ranges_out_of_the_list() {
    let fx = Fixture::new();
    let table = "tests/fixtures/ipranges/ip2asn-sample.tsv";
    fx.run(&["add-hosting-asn", "--asn", "16276"]);
    fx.run(&["update-hosting-asns", "--source", table]);

    fx.run(&["remove-hosting-asn", "--asn", "16276"])
        .stdout(predicate::str::contains("no longer blocked"));

    let ovh = fx.json(&["list-hosting-asns"])["asns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["asn"] == 16276)
        .cloned()
        .unwrap();
    assert_eq!(ovh["blocked"], false, "{ovh:#}");
    assert_eq!(ovh["range_count"], 0, "{ovh:#}");
}

/// `status` names a provider that is blocked in name only.
#[test]
fn status_names_a_hosting_asn_that_was_never_fetched() {
    let fx = Fixture::new();
    stop_bots::health::store_probe(&fx.db(), &stop_bots::health::Probe::default()).unwrap();
    fx.run(&["add-hosting-asn", "--asn", "24940"]);

    let status = fx.json(&["status", "--cached"]);

    let check = status["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "hosting-asns")
        .unwrap_or_else(|| panic!("no hosting-asns check:\n{status:#}"))
        .clone();
    assert_eq!(check["level"], "warn", "{check:#}");
    assert!(
        check["detail"]
            .as_str()
            .unwrap()
            .contains("AS24940 (Hetzner)"),
        "{check:#}"
    );
}

/// What a script reads: every built-in provider and every other one
/// selected, with what each holds.
#[test]
fn list_hosting_asns_json_matches_the_golden() {
    let fx = Fixture::new();
    let table = "tests/fixtures/ipranges/ip2asn-sample.tsv";
    fx.run(&["add-hosting-asn", "--asn", "24940"]);
    fx.run(&["add-hosting-asn", "--asn", "64999"]);
    // 64999 is not in the table, which fails the run after storing 24940.
    fx.cmd(&["update-hosting-asns", "--source", table])
        .assert()
        .failure();

    assert_json_golden(
        "list-hosting-asns.json",
        &json_text(&fx, &["list-hosting-asns"]),
    );
}

/// What the detectors will make allowances for is said when the site is
/// found, before it matters.
#[test]
fn scan_sites_says_which_application_runs_behind_a_site() {
    let fx = Fixture::new();
    fs::write(
        fx.nginx_root.join("cloud.example"),
        "server {\n    listen 443 ssl;\n    server_name cloud.example;\n    \
         location / {\n        proxy_pass http://nextcloud:80;\n    }\n}\n",
    )
    .unwrap();
    fx.write_site("blog.example");

    let out = String::from_utf8(fx.scan_sites().get_output().stdout.clone()).unwrap();

    assert!(
        out.contains("cloud.example runs Nextcloud"),
        "out was:\n{out}"
    );
    assert!(!out.contains("blog.example runs"), "out was:\n{out}");
}

/// A site whose file is gone is forgotten by the next scan, and says so,
/// rather than reading NOT FOUND for good.
#[test]
fn scan_sites_forgets_a_site_whose_file_is_gone() {
    let fx = Fixture::new();
    fx.write_site("blog.example");
    let shop = fx.write_site("shop.example");
    fx.scan_sites();
    fs::remove_file(&shop).unwrap();

    let out = String::from_utf8(fx.scan_sites().get_output().stdout.clone()).unwrap();

    assert!(out.contains("Discovered 1 site(s)"), "out was:\n{out}");
    assert!(out.contains("forgot shop.example"), "out was:\n{out}");
}

/// A copy of a site's config left beside it is not a second site.
#[test]
fn scan_sites_skips_a_backup_of_a_site() {
    let fx = Fixture::new();
    let blog = fx.write_site("blog.example");
    fs::copy(&blog, blog.with_extension("bak-2026-10-12")).unwrap();

    fx.scan_sites()
        .stdout(predicate::str::contains("Discovered 1 site(s)"));
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
    fx.run(&["add-trusted", "--address", "203.0.113.77/24"])
        .stdout(predicate::str::contains("Trusting 203.0.113.0/24"));
    fx.run(&["add-trusted", "--user-agent", "UptimeRobot"])
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
    let (accept, rule) = nft_rule_for(&script, "203.0.113.0/24")
        .unwrap_or_else(|| panic!("no accept for the trusted range:\n{script}"));
    assert!(
        rule.ends_with(" accept"),
        "the trusted range is in {rule:?}"
    );
    let (drop, rule) = nft_rule_for(&script, "203.0.113.9")
        .unwrap_or_else(|| panic!("the block rule went missing:\n{script}"));
    assert!(rule.ends_with(" drop"), "the block is in {rule:?}");
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

    fx.run(&["remove-trusted", "--address", "203.0.113.0/24"]);
    fx.run(&["remove-trusted", "--user-agent", "UptimeRobot"]);
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
/// A config the test rejects is put back exactly as it was, and a
/// generated file the apply created is removed again. Left in place, the
/// running NGINX would carry on serving the old config from memory and the
/// broken one would surface at the next restart — every site at once.
#[test]
fn a_config_that_fails_the_test_is_put_back_byte_for_byte() {
    let fx = Fixture::new();
    fx.seed_bots();
    let site = fx.write_site("a.example");
    fx.scan_sites();
    fx.run(&["set-robots-txt", "--enabled", "true"]);
    fx.run(&["set-rate-limit", "--enabled", "true"]);
    let before = fs::read(&site).unwrap();
    let (bin, calls) = fake_tools(fx._tmp.path());
    fs::write(
        fx._tmp.path().join("fail-nginx"),
        "nginx: [emerg] unknown directive\n",
    )
    .unwrap();

    fx.cmd(&["apply-blocks", "--root", fx.nginx_root.to_str().unwrap()])
        .env("PATH", path_with(&bin))
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown directive"))
        .stderr(predicate::str::contains("put back"));

    assert_eq!(fs::read(&site).unwrap(), before, "the site file changed");
    assert!(!fx.robots_txt().exists(), "the new robots.txt was left");
    assert!(!fx.rate_limit_conf().exists(), "the new zone was left");
    let log = fs::read_to_string(&calls).unwrap();
    assert!(!log.contains("systemctl"), "log was: {log}");
}

/// The first thing a host with NGINX in a container meets: no `nginx` on
/// PATH. The error names the verb that fixes it.
#[test]
fn nginx_missing_from_path_points_at_set_web_server() {
    let fx = Fixture::new();
    fx.seed_bots();
    fx.write_site("a.example");
    fx.scan_sites();
    let empty = fx._tmp.path().join("empty-bin");
    fs::create_dir_all(&empty).unwrap();

    fx.cmd(&["apply-blocks", "--root", fx.nginx_root.to_str().unwrap()])
        .env("PATH", &empty)
        .assert()
        .failure()
        .stderr(predicate::str::contains("`nginx` isn't on PATH"))
        .stderr(predicate::str::contains(
            "see `stop-bots set-web-server nginx --help`",
        ));
}

/// A config root that is not there names both ways to point at the
/// right one.
#[test]
fn a_missing_nginx_root_says_how_to_set_it() {
    let fx = Fixture::new();
    let missing = fx._tmp.path().join("no-such-nginx");

    fx.cmd(&["scan-sites", "--root", missing.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"))
        .stderr(predicate::str::contains(
            "stop-bots set-web-server nginx --root <dir>",
        ));
}

/// A user without write access to the site files is told to use sudo,
/// after the error that says which file it was.
#[test]
fn a_site_file_this_user_cannot_write_says_to_use_sudo() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return; // root is never denied, so there is nothing to see
    }
    let fx = Fixture::new();
    fx.seed_bots();
    let site = fx.write_site("a.example");
    fx.scan_sites();
    fs::set_permissions(&site, fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(&fx.nginx_root, fs::Permissions::from_mode(0o555)).unwrap();

    let assert = fx
        .cmd(&[
            "apply-blocks",
            "--root",
            fx.nginx_root.to_str().unwrap(),
            "--no-reload",
        ])
        .assert();
    fs::set_permissions(&fx.nginx_root, fs::Permissions::from_mode(0o755)).unwrap();

    assert
        .failure()
        .stderr(predicate::str::contains("a.example.conf"))
        .stderr(predicate::str::contains(
            "This needs root. Run it with sudo.",
        ));
}

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

    fx.run(&["add-trusted", "--user-agent", "UptimeRobot"]);
    apply(&fx);
    fx.run(&["add-trusted", "--user-agent", "Pingdom"]);
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
        (
            vec!["add-trusted", "--address", "0.0.0.0/0"],
            "every address",
        ),
        (vec!["add-trusted", "--user-agent", " "], "every client"),
        (
            vec!["remove-trusted", "--address", "203.0.113.7"],
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

/// The mirror of trust's `/0` refusal: blocking every address is the host
/// off the network, not a rule.
#[test]
fn add_firewall_rule_refuses_a_block_of_every_address() {
    let fx = Fixture::new();
    for address in ["0.0.0.0/0", "::/0", " 0.0.0.0/0"] {
        fx.cmd(&["add-firewall-rule", "--address", address])
            .assert()
            .failure()
            .stderr(predicate::str::contains("every address"));
    }
    fx.run(&["list-firewall-rules"])
        .stdout(predicate::str::contains("No firewall rules stored."));

    // Closing one port to everyone is an ordinary rule.
    fx.run(&[
        "add-firewall-rule",
        "--address",
        "0.0.0.0/0",
        "--port",
        "23",
    ]);
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
        exempted.contains("if ($stop_bots_path ~* \"^(/blog)\")"),
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
        "set $stop_bots_exempt $stop_bots_path;",
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
    let host = tmp.path().join("host.conf");
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    fs::create_dir_all(&nginx_root).unwrap();
    write_site(&nginx_root, "a.example");
    let (bin, calls) = fake_tools(tmp.path());

    seed_bots(&db_path);
    scan_sites(&db_path, &nginx_root);

    stop_bots_with_host(
        &host,
        &[
            "set-nginx-commands",
            "--db",
            db_path.to_str().unwrap(),
            "--test",
            "docker exec web nginx -t",
            "--reload",
            "docker exec web nginx -s reload",
        ],
    );

    stop_bots_bin()
        .env("STOP_BOTS_HOST_CONF", &host)
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
    let host = tmp.path().join("host.conf");
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

    stop_bots_with_host(
        &host,
        &[
            "set-nginx-commands",
            "--db",
            db_path.to_str().unwrap(),
            "--test",
            "docker exec web nginx -t",
            "--reload",
            "docker exec web nginx -s reload",
        ],
    );

    stop_bots_bin()
        .env("STOP_BOTS_HOST_CONF", &host)
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
    let host = tmp.path().join("host.conf");
    let db_path = tmp.path().join("db.sqlite3");

    stop_bots_with_host(
        &host,
        &[
            "set-nginx-commands",
            "--db",
            db_path.to_str().unwrap(),
            "--reload",
            "docker exec web nginx -s reload",
        ],
    )
    .stdout(predicate::str::contains("Test command:   nginx -t"))
    .stdout(predicate::str::contains(
        "Reload command: docker exec web nginx -s reload",
    ));

    stop_bots_with_host(
        &host,
        &["set-nginx-commands", "--db", db_path.to_str().unwrap()],
    )
    .stdout(predicate::str::contains(
        "Reload command: docker exec web nginx -s reload",
    ));

    stop_bots_with_host(
        &host,
        &[
            "set-nginx-commands",
            "--db",
            db_path.to_str().unwrap(),
            "--reset",
        ],
    )
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
    // touch chains/policies outside our own dedicated STOP-BOTS chain. The
    // restore it feeds declares that one chain and sets no policy.
    let declared: Vec<&str> = script.lines().filter(|l| l.starts_with(':')).collect();
    assert_eq!(
        declared,
        vec![":STOP-BOTS - [0:0]", ":STOP-BOTS - [0:0]"],
        "one declaration per family, of our chain only:\n{script}"
    );
    assert!(!script.contains(" -P "), "script was:\n{script}");

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

/// `set-log-paths --ssh-log` is where a host that keeps its SSH log
/// somewhere else says so, and the lockout guard used to ignore it: with no
/// flag it searched the defaults, found nothing, and could not run. Now the
/// stored path is what it reads.
#[test]
fn the_lockout_guard_reads_the_stored_ssh_log() {
    let tmp = tempfile::tempdir().unwrap();
    let host = tmp.path().join("host.conf");
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();
    let log_path = tmp.path().join("elsewhere-auth.log");
    fs::write(
        &log_path,
        "Jun 12 01:02:03 host sshd[111]: Accepted publickey for admin from 4.5.6.7 port 54321 ssh2\n",
    )
    .unwrap();
    for args in [
        vec![
            "add-firewall-rule",
            "--db",
            db_path,
            "--address",
            "4.5.6.0/24",
            "--action",
            "block",
        ],
        vec![
            "set-log-paths",
            "--db",
            db_path,
            "--ssh-log",
            log_path.to_str().unwrap(),
        ],
    ] {
        stop_bots_bin()
            .env("STOP_BOTS_HOST_CONF", &host)
            .args(args)
            .assert()
            .success();
    }

    let script_path = tmp.path().join("stop-bots.nft");
    let output = stop_bots_bin()
        .env("STOP_BOTS_HOST_CONF", &host)
        .args([
            "render-firewall",
            "--db",
            db_path,
            "--backend",
            "nftables",
            "--out",
            script_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr was:\n{stderr}");
    assert!(stderr.contains("4.5.6.7"), "stderr was:\n{stderr}");
    assert!(!script_path.exists());
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

/// `render-firewall --apply`, end to end against a fake `nft`: the
/// rendered script is what runs, and only once it has does it become the
/// script a boot unit loads.
#[test]
fn render_firewall_apply_runs_the_render_and_then_makes_it_the_boot_script() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, calls) = fake_tools(tmp.path());
    let db_path = tmp.path().join("db.sqlite3");
    let applied = tmp.path().join("firewall.nft");
    let rendered = tmp.path().join("firewall.next.nft");
    stop_bots_bin()
        .args(["add-firewall-rule", "--db", db_path.to_str().unwrap()])
        .args(["--address", "203.0.113.9"])
        .assert()
        .success();

    stop_bots_bin()
        .env("PATH", path_with(&bin))
        .args([
            "render-firewall",
            "--db",
            db_path.to_str().unwrap(),
            "--apply",
        ])
        .args(["--out", applied.to_str().unwrap()])
        .args(["--ssh-log", "tests/fixtures/logs/auth.log"])
        .assert()
        .success()
        .stdout(predicate::str::contains("loads at boot"));

    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(log.trim(), format!("nft -f {}", rendered.display()));
    let boot = fs::read_to_string(&applied).expect("the applied script should be in place");
    assert!(boot.contains("203.0.113.9"), "applied script was:\n{boot}");
    assert_eq!(fs::read_to_string(&rendered).unwrap(), boot);
}

/// With no SSH log to check against, the script is written for review and
/// not run, and the script a boot unit loads is left alone.
#[test]
fn render_firewall_apply_refuses_when_the_lockout_check_cannot_run() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, calls) = fake_tools(tmp.path());
    let db_path = tmp.path().join("db.sqlite3");
    let applied = tmp.path().join("firewall.nft");

    stop_bots_bin()
        .env("PATH", path_with(&bin))
        .args([
            "render-firewall",
            "--db",
            db_path.to_str().unwrap(),
            "--apply",
        ])
        .args(["--out", applied.to_str().unwrap()])
        .args(["--ssh-log", "/nonexistent/auth.log"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not applied"))
        .stderr(predicate::str::contains("--force overrides this"));

    assert!(!calls.exists(), "nft must not have run");
    assert!(!applied.exists());
    assert!(tmp.path().join("firewall.next.nft").exists());
}

/// A script `nft` rejects must not become what the host loads at boot:
/// the previous applied script stays exactly as it was.
#[test]
fn a_failed_apply_leaves_the_boot_script_as_it_was() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, _calls) = fake_tools(tmp.path());
    fs::write(tmp.path().join("fail-nft"), "Error: syntax error\n").unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let applied = tmp.path().join("firewall.nft");
    fs::write(&applied, "# what was applied last week\n").unwrap();

    stop_bots_bin()
        .env("PATH", path_with(&bin))
        .args([
            "render-firewall",
            "--db",
            db_path.to_str().unwrap(),
            "--apply",
        ])
        .args(["--out", applied.to_str().unwrap()])
        .args(["--ssh-log", "tests/fixtures/logs/auth.log"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("applying failed"));

    assert_eq!(
        fs::read_to_string(&applied).unwrap(),
        "# what was applied last week\n"
    );
}

/// `render-firewall --apply` against a fake `nft`, writing the applied
/// script to `applied`, with no terminal on stdin — as from cron.
fn apply_without_a_terminal(tmp: &Path, bin: &Path, applied: &Path) {
    stop_bots_bin()
        .env("PATH", path_with(bin))
        .args(["render-firewall", "--apply"])
        .args(["--db", tmp.join("db.sqlite3").to_str().unwrap()])
        .args(["--out", applied.to_str().unwrap()])
        .args(["--ssh-log", "tests/fixtures/logs/auth.log"])
        .assert()
        .success();
}

/// Confirm-or-revert needs someone to answer. Cron and scripts have no
/// terminal, so they apply as they always did: no timer, no record, and
/// the new script is the boot script at once.
#[test]
fn without_a_terminal_an_apply_arms_no_revert() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, calls) = fake_tools(tmp.path());
    let applied = tmp.path().join("firewall.nft");

    apply_without_a_terminal(tmp.path(), &bin, &applied);

    let log = fs::read_to_string(&calls).unwrap_or_default();
    assert!(!log.contains("systemd-run"), "calls were:\n{log}");
    assert!(
        !tmp.path().join("firewall.nft.pending").exists(),
        "no revert should be waiting"
    );
    assert!(applied.exists(), "the apply is the boot script at once");
}

/// Every apply keeps the applied script it replaces beside it, so the
/// rules from before the last apply are always one command away.
#[test]
fn an_apply_keeps_the_script_it_replaces_as_prev() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, _calls) = fake_tools(tmp.path());
    let applied = tmp.path().join("firewall.nft");
    fs::write(&applied, "# what was applied last week\n").unwrap();

    apply_without_a_terminal(tmp.path(), &bin, &applied);

    assert_eq!(
        fs::read_to_string(tmp.path().join("firewall.prev.nft"))
            .ok()
            .as_deref(),
        Some("# what was applied last week\n")
    );
}

/// `revert-firewall` by hand, with nothing waiting: loads the previous
/// script and swaps the two files, so a second run goes forward again.
#[test]
fn revert_firewall_goes_back_to_the_previous_script() {
    let tmp = tempfile::tempdir().unwrap();
    let (bin, calls) = fake_tools(tmp.path());
    let applied = tmp.path().join("firewall.nft");
    let previous = tmp.path().join("firewall.prev.nft");
    fs::write(&applied, "# new\n").unwrap();
    fs::write(&previous, "# old\n").unwrap();

    stop_bots_bin()
        .env("PATH", path_with(&bin))
        .args(["revert-firewall", "--backend", "nftables"])
        .args(["--db", tmp.path().join("db.sqlite3").to_str().unwrap()])
        .args(["--out", applied.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Reverted to the previous firewall rules",
        ));

    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(log.trim(), format!("nft -f {}", previous.display()));
    let files = [(&applied, "# old\n"), (&previous, "# new\n")];
    for (path, expected) in files {
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            expected,
            "{}",
            path.display()
        );
    }
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
    for (element, verdict) in [
        ("4.5.6.7", " accept"),
        ("0.0.0.0/0", " drop"),
        ("::/0", " drop"),
    ] {
        let (_, rule) = nft_rule_for(&script, element)
            .unwrap_or_else(|| panic!("{element} is in no set:\n{script}"));
        assert!(rule.ends_with(verdict), "{element} is decided by {rule:?}");
    }
    assert!(
        nft_rule_for(&script, "4.5.6.7").unwrap().0 < nft_rule_for(&script, "0.0.0.0/0").unwrap().0,
        "the admin's Allow must come before the catch-all:\n{script}"
    );
}

fn repeat_failed_attempt(ip: &str, times: usize) -> String {
    format!("Failed password for root from {ip} port 4444 ssh2\n").repeat(times)
}

/// Every detector subcommand's `--ttl-days` has the ceiling the TUI has; past it the arithmetic that dates the block wraps.
/// `=` so clap does not read the negative one as a flag.
#[test]
fn a_ttl_past_ten_years_is_refused_on_the_command_line() {
    let fx = Fixture::new();
    for detector in [
        "ssh-scanners",
        "web-scanners",
        "spoofed-crawlers",
        "probe-paths",
        "honeypot",
        "injection",
    ] {
        for days in ["3651", "106751991167301", "-106751991167301"] {
            let flag = format!("--ttl-days={days}");
            fx.cmd(&["run-detector", detector, "--dry-run", &flag])
                .assert()
                .failure()
                .stderr(predicate::str::contains("--ttl-days"));
        }
    }
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "ssh-scanners",
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

    for detector in ["ssh-scanners", "web-scanners"] {
        stop_bots_bin()
            .args([
                "run-detector",
                detector,
                "--db",
                db_path,
                "--threshold",
                "0",
            ])
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "web-scanners",
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
            "run-detector",
            "web-scanners",
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
/// hitting the *same* dead path repeatedly must not look like scanning,
/// short of the fifty times (`WEB_SCANNERS_REPEATS`) only a bot reaches.
#[test]
fn block_web_scanners_ignores_repeated_hits_on_a_single_dead_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let db_path = db_path.to_str().unwrap();

    let log_path = tmp.path().join("access.log");
    let log: String = (0..49)
        .map(|_| not_found_line("198.51.100.9", "/missing"))
        .collect();
    fs::write(&log_path, log).unwrap();

    stop_bots_bin()
        .args([
            "run-detector",
            "web-scanners",
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
            "run-detector",
            "web-scanners",
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
            "run-detector",
            "ssh-scanners",
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
            "run-detector",
            "web-scanners",
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
            "run-detector",
            "ssh-scanners",
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

    /// The applied script: what `--out` names, and what the boot unit
    /// loads. Only an apply writes it.
    fn firewall_script(&self) -> std::path::PathBuf {
        self.managed.join("firewall.nft")
    }

    /// The rendered script beside it, which every run writes.
    fn rendered_script(&self) -> std::path::PathBuf {
        self.managed.join("firewall.next.nft")
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
        fixture.rendered_script().exists(),
        "the firewall script should have been written"
    );
    assert!(
        !fixture.firewall_script().exists(),
        "without --apply, nothing reaches the script the boot unit loads"
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
        .stderr(predicate::str::contains("not applied"))
        .stderr(predicate::str::contains("lockout check could not run"))
        .stderr(predicate::str::contains("--ssh-log"));

    assert!(
        !fixture.firewall_script().exists(),
        "refusing must mean nothing reached the script the boot unit loads"
    );
    assert!(
        fixture.rendered_script().exists(),
        "the rendered script is inert, so it is written for review"
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

    let script = fs::read_to_string(fixture.rendered_script()).unwrap();
    let allow = nft_rule_for(&script, "192.0.2.10");
    let block = nft_rule_for(&script, "192.0.2.0/24");
    assert!(
        matches!((&allow, &block), (Some((a, allow)), Some((b, block)))
            if a < b && allow.ends_with(" accept") && block.ends_with(" drop")),
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

    assert!(fixture.rendered_script().exists());
}

/// `batch --dry-run` prints what the two planes would do and changes
/// nothing: no site file, no script, and not even the rendered signature
/// a Dashboard reads.
#[test]
fn a_batch_dry_run_says_what_would_change_and_changes_nothing() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");
    let before = fs::read_to_string(&site).unwrap();
    fixture.run(&["add-firewall-rule", "--address", "203.0.113.9"]);

    let output = fixture.batch(&["--apply", "--dry-run"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout:\n{stdout}");
    for (what, expected) in [
        ("that it is a dry run", "Dry run"),
        ("the site file", "example.com"),
        ("the rules against the applied script", "all of it is new"),
        ("the lockout check", "lockout check passed"),
        ("the verdict", "would be applied"),
    ] {
        assert!(stdout.contains(expected), "no {what} in:\n{stdout}");
    }
    assert_eq!(fs::read_to_string(&site).unwrap(), before);
    assert!(!fixture.rendered_script().exists());
    assert!(!fixture.firewall_script().exists());
    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert_eq!(db.get_firewall_rendered_signature().unwrap(), None);
}

/// Switching the mode keeps the country list, so what it now means is said
/// with it: the countries that were blocked are the only ones allowed, and
/// an Allowlist with none blocks everything not trusted.
#[test]
fn set_geo_mode_says_what_the_country_list_now_means() {
    let fixture = Fixture::new();

    let empty = fixture.run(&["set-geo-mode", "--mode", "allowlist"]);
    let empty = String::from_utf8_lossy(&empty.get_output().stdout).into_owned();
    assert!(
        empty.contains("WARNING: no country is selected"),
        "stdout:\n{empty}"
    );

    fixture.run(&["set-geo-mode", "--mode", "blocklist"]);
    fixture.run(&["add-country", "--country", "cn"]);
    let allow = fixture.run(&["set-geo-mode", "--mode", "allowlist"]);
    let allow = String::from_utf8_lossy(&allow.get_output().stdout).into_owned();
    assert!(allow.contains("Allowed: CN"), "stdout:\n{allow}");
}

/// With no SSH login on record, Only trusted IPs blocks whoever connects
/// next. The dry run says so, and that the apply would be refused, rather
/// than "lockout check passed".
#[test]
fn a_batch_dry_run_with_no_ssh_logins_refuses_a_rule_that_blocks_everyone() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");
    fixture.run(&["set-geo-mode", "--mode", "allowlist"]);
    let empty_log = fixture.managed.with_file_name("auth.log");
    fs::write(&empty_log, "").unwrap();
    let out = fixture.firewall_script();

    let output = fixture
        .cmd(&[
            "batch",
            "--no-fetch",
            "--apply",
            "--dry-run",
            "--root",
            fixture.nginx_root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--ssh-log",
            empty_log.to_str().unwrap(),
            "--access-log",
            "/dev/null",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    for (what, expected) in [
        ("why", "no one has logged in over SSH"),
        ("the rule", "0.0.0.0/0"),
        ("the verdict", "would not be applied"),
        ("the way past it", "set-ssh-lockout-check --enabled false"),
    ] {
        assert!(stdout.contains(expected), "no {what} in:\n{stdout}");
    }
    assert!(
        !stdout.contains("lockout check passed"),
        "nobody was checked:\n{stdout}"
    );
}

/// And `--diff` shows how: the site's new block and the script's rules.
#[test]
fn a_batch_dry_run_with_diff_prints_every_change() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    fixture.write_site("example.com");
    fixture.run(&["add-firewall-rule", "--address", "203.0.113.9"]);

    fixture
        .batch(&["--dry-run", "--diff"])
        .assert()
        .success()
        .stdout(predicate::str::contains("+++ "))
        .stdout(predicate::str::contains("+\t203.0.113.9"))
        .stdout(predicate::str::contains("+    # BEGIN stop-bots"));
}

/// **A fresh host run by `batch --no-fetch` alone blocks the scanners the
/// binary already knows.** The built-in list used to be stored only by
/// the TUI and the web console, or as one of the downloads, so on a host
/// without outbound access every step reported success and no user agent
/// was blocked. Found by the stranger test in the container suite.
#[test]
fn batch_without_fetching_still_blocks_the_built_in_list() {
    let fixture = Fixture::new();
    let site = fixture.write_site("example.com");

    fixture.batch(&[]).assert().success();

    let config = fs::read_to_string(&site).unwrap();
    assert!(
        config.contains("ModatScanner"),
        "a built-in scanner should be in the generated block:\n{config}"
    );
}

/// And the dry run a stranger reads before that first run shows the same
/// block, rather than "no file would change".
#[test]
fn a_batch_dry_run_on_a_fresh_host_shows_the_built_in_list() {
    let fixture = Fixture::new();
    let site = fixture.write_site("example.com");
    let before = fs::read_to_string(&site).unwrap();

    fixture
        .batch(&["--dry-run", "--diff"])
        .assert()
        .success()
        .stdout(predicate::str::contains("+    # BEGIN stop-bots"))
        .stdout(predicate::str::contains("ModatScanner"));

    assert_eq!(fs::read_to_string(&site).unwrap(), before);
}

/// `apply-blocks` is the other way a CLI-only host writes NGINX config.
#[test]
fn apply_blocks_on_a_fresh_database_writes_the_built_in_list() {
    let fixture = Fixture::new();
    let site = fixture.write_site("example.com");
    let root = fixture.nginx_root.to_str().unwrap();

    fixture.run(&["scan-sites", "--root", root]);
    fixture.run(&["apply-blocks", "--root", root, "--no-reload"]);

    let config = fs::read_to_string(&site).unwrap();
    assert!(config.contains("ModatScanner"), "config was:\n{config}");
}

#[test]
fn apply_blocks_dry_run_lists_and_diffs_without_writing() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");
    let before = fs::read_to_string(&site).unwrap();
    let root = fixture.nginx_root.to_str().unwrap();

    fixture
        .run(&["apply-blocks", "--root", root, "--dry-run", "--diff"])
        .stdout(predicate::str::contains("1 file(s) would change"))
        .stdout(predicate::str::contains(site.to_str().unwrap()))
        .stdout(predicate::str::contains("+    # BEGIN stop-bots"));

    assert_eq!(fs::read_to_string(&site).unwrap(), before);
}

/// One step failing must not stop the others, and must still be visible:
/// `cron` only tells anyone about a job that exits non-zero.
#[test]
fn a_failed_step_is_reported_and_sets_a_failing_exit_status() {
    let fixture = Fixture::new();
    fixture.seed_bots();
    let site = fixture.write_site("example.com");

    // An unwritable output path fails the firewall step and nothing else.
    // Under a regular file rather than under a missing directory: the
    // writer creates missing directories, so `/nonexistent/...` only fails
    // where `/` is read-only, and a sandbox with a writable root passed it.
    let not_a_directory = fixture.db.with_file_name("not-a-directory");
    fs::write(&not_a_directory, "").unwrap();
    let out = not_a_directory.join("firewall.nft");
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
            "update-crawler-ranges",
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
                "update-reputation-sources",
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
        "update-reputation-sources",
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
            "update-crawler-ranges",
            "--source-id",
            "googlebot",
            "--source",
            "/nonexistent/ranges.json",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/nonexistent/ranges.json"));
}

// ---- a staged host ----

/// Stages a fake Debian-with-systemd root to install into under
/// `--prefix`, and a binary for what is installed to point at.
fn fake_debian_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("run/systemd/system")).unwrap();
    fs::create_dir_all(tmp.path().join("etc")).unwrap();
    fs::write(tmp.path().join("etc/debian_version"), "13.1\n").unwrap();
    let binary = tmp.path().join("stop-bots");
    fs::write(&binary, b"#!/bin/true\n").unwrap();
    (tmp, binary)
}

// ---- uninstall ----

/// The host back as it was, end to end through the binary: an applied
/// site, a generated `conf.d` file, the cron file, the boot unit and a
/// firewall script go; the site file is byte for byte what it was before;
/// the database stays, and the output says where.
///
/// Under `--prefix`, which runs no system program; the unit tests in
/// `uninstall` cover the host's path with fakes, and the container suite
/// with the real ones.
#[test]
fn uninstall_takes_a_prefix_back_to_how_it_was() {
    let (tmp, _) = fake_debian_root();
    let prefix = tmp.path();
    let run = |args: &[&str]| {
        stop_bots_bin()
            .env("STOP_BOTS_NGINX_DIR", prefix.join("etc/stop-bots/nginx"))
            .env("STOP_BOTS_NGINX_CONF_D", prefix.join("etc/nginx/conf.d"))
            .args(args)
            .args([
                "--db",
                prefix
                    .join("var/lib/stop-bots/db.sqlite3")
                    .to_str()
                    .unwrap(),
            ])
            .assert()
            .success()
    };
    let root = prefix.join("etc/nginx");
    fs::create_dir_all(root.join("conf.d")).unwrap();
    fs::create_dir_all(root.join("sites-enabled")).unwrap();
    let site = write_site(&root.join("sites-enabled"), "example.com");
    let before = fs::read_to_string(&site).unwrap();
    // First, while there is no database for it to read the backend from.
    run(&["install", "firewall", "--prefix", prefix.to_str().unwrap()]);
    // Rate limiting alone is a block and a generated `conf.d` file.
    run(&["set-rate-limit", "--enabled", "true"]);
    run(&[
        "apply-blocks",
        "--root",
        root.to_str().unwrap(),
        "--no-reload",
    ]);
    fs::create_dir_all(prefix.join("etc/stop-bots")).unwrap();
    fs::create_dir_all(prefix.join("etc/cron.d")).unwrap();
    fs::create_dir_all(prefix.join("usr/sbin")).unwrap();
    fs::write(prefix.join("usr/sbin/cron"), "").unwrap();
    let binary = prefix.join("stop-bots");
    fs::write(&binary, "#!/bin/true\n").unwrap();
    run(&[
        "install",
        "cron",
        "--prefix",
        prefix.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
    ]);
    let units = prefix.join("etc/systemd/system");
    fs::write(prefix.join("etc/stop-bots/firewall.nft"), "table\n").unwrap();
    assert_ne!(
        fs::read_to_string(&site).unwrap(),
        before,
        "nothing was applied"
    );

    let out = run(&["uninstall", "--prefix", prefix.to_str().unwrap()]);

    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(fs::read_to_string(&site).unwrap(), before, "{stdout}");
    for gone in [
        root.join("conf.d/stop-bots-limits.conf"),
        prefix.join("etc/cron.d/stop-bots"),
        units.join("stop-bots-firewall.service"),
        prefix.join("etc/stop-bots"),
    ] {
        assert!(
            !gone.exists(),
            "{} is still there:\n{stdout}",
            gone.display()
        );
    }
    let db = prefix.join("var/lib/stop-bots/db.sqlite3");
    assert!(db.exists(), "the database went without --purge");
    assert!(
        stdout.contains(&db.display().to_string()),
        "the output must say where the database is:\n{stdout}"
    );
}

/// A cron file naming a binary in `target/` works until the next `cargo
/// clean`, so `install cron` refuses one and says what to run instead.
#[test]
fn install_cron_refuses_a_binary_in_a_build_directory() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("etc/cron.d")).unwrap();
    // Named outright: where the test's own binary was built depends on the
    // runner (`cargo llvm-cov` builds under `target/llvm-cov-target/`).
    let built = tmp.path().join("target/debug/stop-bots");
    fs::create_dir_all(built.parent().unwrap()).unwrap();
    fs::write(&built, "#!/bin/true\n").unwrap();
    stop_bots_bin()
        .args(["install", "cron", "--dry-run", "--prefix"])
        .arg(tmp.path())
        .arg("--binary")
        .arg(&built)
        .assert()
        .failure()
        .stderr(predicate::str::contains("build directory"));
}

/// A request for `/.env` from `ip`, logged now: what the probe-paths
/// detector, on by default, blocks on sight.
fn probe_logged_now(ip: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let stamp = std::process::Command::new("date")
        .args(["-u", "-d", &format!("@{now}"), "+%d/%b/%Y:%H:%M:%S +0000"])
        .output()
        .unwrap();
    let stamp = String::from_utf8(stamp.stdout).unwrap();
    format!(
        "{ip} - - [{}] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n",
        stamp.trim()
    )
}

impl Fixture {
    /// Readies this fixture for `tick`: the web server's config is this
    /// fixture's root, whose logs it names are the only ones read beside
    /// `access_log`; the jobs that download or probe the host are marked
    /// just run, so nothing leaves this machine; and the SSH log is an
    /// empty file of the fixture's, which `tick --ssh-log` is handed.
    fn ready_for_tick(&self, access_log: &Path) -> std::path::PathBuf {
        self.run(&[
            "set-web-server",
            "nginx",
            "--root",
            self.nginx_root.to_str().unwrap(),
        ]);
        self.run(&[
            "set-log-paths",
            "--access-log",
            access_log.to_str().unwrap(),
        ]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let db = stop_bots::db::Db::open(&self.db).unwrap();
        for job in [
            "update_ip_ranges",
            "update_everything",
            "health_check",
            "apply_nginx",
        ] {
            db.set_cron_last_run(job, now, "skipped for test").unwrap();
        }
        let ssh = self._tmp.path().join("auth.log");
        fs::write(&ssh, "").unwrap();
        ssh
    }

    /// `tick --verbose --ssh-log <ssh>`, and what it said. With a temporary
    /// directory of the fixture's own, which is where an unprivileged
    /// `tick` takes its lock: two tests ticking at once would otherwise
    /// each find "another tick still running" and do nothing.
    fn tick(&self, ssh: &Path) -> String {
        let ran = self
            .cmd(&["tick", "--verbose", "--ssh-log", ssh.to_str().unwrap()])
            .env("TMPDIR", self._tmp.path())
            .assert()
            .success();
        String::from_utf8_lossy(&ran.get_output().stdout).into_owned()
    }
}

/// One `tick` runs the due detectors against the stored access log and
/// blocks what they find; the next one, straight after, has nothing due.
#[test]
fn tick_runs_what_is_due_and_then_nothing() {
    let fx = Fixture::new();
    let access = fx._tmp.path().join("access.log");
    fs::write(&access, probe_logged_now("203.0.113.50")).unwrap();
    let ssh = fx.ready_for_tick(&access);

    let said = fx.tick(&ssh);
    assert!(said.contains("Block probe paths"), "tick said:\n{said}");
    fx.run(&["list-firewall-rules"])
        .stdout(predicate::str::contains("203.0.113.50"));

    let said = fx.tick(&ssh);
    assert!(said.contains("Nothing was due."), "tick said:\n{said}");
}

/// A site that logs to a file of its own is watched as the main log is:
/// `tick` reads every access log the config names, beside the stored one,
/// and `set-log-paths` says which they are.
#[test]
fn tick_reads_the_access_log_a_site_names() {
    let fx = Fixture::new();
    let access = fx._tmp.path().join("access.log");
    let shop = fx._tmp.path().join("shop.log");
    fs::write(&access, "").unwrap();
    fs::write(&shop, probe_logged_now("203.0.113.51")).unwrap();
    fs::write(
        fx.nginx_root.join("shop.conf"),
        format!(
            "server {{\n    server_name shop.example;\n    access_log {} combined;\n}}\n",
            shop.display()
        ),
    )
    .unwrap();
    let ssh = fx.ready_for_tick(&access);

    fx.run(&["set-log-paths"])
        .stdout(predicate::str::contains(shop.to_str().unwrap()));
    let said = fx.tick(&ssh);

    let rules = fx.run(&["list-firewall-rules"]);
    let rules = String::from_utf8_lossy(&rules.get_output().stdout).into_owned();
    assert!(
        rules.contains("203.0.113.51"),
        "rules:\n{rules}\ntick said:\n{said}"
    );
}

/// `batch --root` is the config this run scans and applies to, so the
/// access logs that config names are the ones it reads, not those of the
/// stored root.
#[test]
fn batch_reads_the_access_log_a_site_under_its_root_names() {
    let fx = Fixture::new();
    let other = fx._tmp.path().join("other-nginx");
    fs::create_dir_all(&other).unwrap();
    let access = fx._tmp.path().join("access.log");
    let shop = fx._tmp.path().join("shop.log");
    fs::write(&access, "").unwrap();
    fs::write(&shop, probe_logged_now("203.0.113.52")).unwrap();
    fs::write(
        other.join("shop.conf"),
        format!(
            "server {{\n    server_name shop.example;\n    access_log {} combined;\n}}\n",
            shop.display()
        ),
    )
    .unwrap();
    fx.run(&["set-log-paths", "--access-log", access.to_str().unwrap()]);

    let out = fx.firewall_script();
    let said = fx.run(&[
        "batch",
        "--no-fetch",
        "--root",
        other.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--ssh-log",
        "tests/fixtures/logs/auth.log",
    ]);
    let said = String::from_utf8_lossy(&said.get_output().stdout).into_owned();

    let rules = fx.run(&["list-firewall-rules"]);
    let rules = String::from_utf8_lossy(&rules.get_output().stdout).into_owned();
    assert!(
        rules.contains("203.0.113.52"),
        "rules:\n{rules}\nbatch said:\n{said}"
    );
}

/// `--purge` deletes the database, which every part still installed reads.
#[test]
fn uninstall_refuses_purge_on_a_part() {
    let tmp = tempfile::tempdir().unwrap();
    stop_bots_bin()
        .args([
            "uninstall",
            "nginx",
            "--purge",
            "--prefix",
            tmp.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("only with `all`"));
}

/// Half an uninstall is worse than none, and permissions are where one
/// would stop half way. Skipped when the suite runs as root, where this
/// would uninstall the machine running it.
#[test]
fn uninstall_needs_root_without_a_prefix() {
    if unsafe { libc::geteuid() } == 0 {
        stop_bots::say_err!(
            "skipped: running as root, where this would uninstall the test machine"
        );
        return;
    }
    stop_bots_bin()
        .args(["uninstall", "--dry-run"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("needs root"));
}

/// NGINX answers every visitor over HTTP/1.1 until something turns
/// HTTP/2 on, and then the HTTP/1.x rule would turn every one of them
/// away while `nginx -t` passes. So the apply refuses it, leaves the site
/// as it was, and writes it once HTTP/2 is on.
#[test]
fn the_http_1x_rule_is_refused_on_nginx_until_http2_is_on() {
    let fx = Fixture::new();
    fs::write(
        fx.nginx_root.join("nginx.conf"),
        "http {\n    include *.conf;\n}\n",
    )
    .unwrap();
    let site = fx.nginx_root.join("tls.conf");
    let before = "server {\n    listen 443 ssl;\n    server_name tls.example;\n    \
                  ssl_certificate /etc/ssl/x.pem;\n}\n";
    fs::write(&site, before).unwrap();
    fx.seed_bots();
    fx.scan_sites();
    fx.run(&[
        "set-site-rule",
        "--site",
        "tls.example",
        "--rule",
        "http-1x",
        "--enabled",
        "true",
    ]);

    fx.cmd(&[
        "apply-blocks",
        "--root",
        fx.nginx_root.to_str().unwrap(),
        "--no-reload",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "nothing in the NGINX config turns HTTP/2 on",
    ));
    assert_eq!(fs::read_to_string(&site).unwrap(), before);

    fs::write(&site, before.replace("ssl;", "ssl;\n    http2 on;")).unwrap();
    fx.apply_blocks();
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.contains(r#"if ($server_protocol ~ "^HTTP/1\.") {"#),
        "site was:\n{written}"
    );
}

// ---- Apache ----
//
// The same binary driving a fake Apache tree, with a fake `apache2ctl` and
// `systemctl` on PATH: what is written, what is run, in what order, and
// what is refused. The container suite runs the real Apache.

/// Debian's `apache2.conf`, as far as what it includes.
const DEBIAN_APACHE2_CONF: &str = "IncludeOptional mods-enabled/*.load\n\
     IncludeOptional mods-enabled/*.conf\n\
     IncludeOptional conf-enabled/*.conf\n\
     IncludeOptional sites-enabled/*.conf\n";

/// RHEL's `conf/httpd.conf`, as far as what it includes.
const RHEL_HTTPD_CONF: &str = "ServerRoot \"/etc/httpd\"\n\
     Include conf.modules.d/*.conf\n\
     IncludeOptional conf.d/*.conf\n";

/// A `<VirtualHost>` for `name`.
fn apache_site(name: &str) -> String {
    format!("<VirtualHost *:80>\n    ServerName {name}\n    DocumentRoot /var/www/{name}\n</VirtualHost>\n")
}

impl Fixture {
    /// Debian's Apache tree in this fixture, with one site, `example.com`,
    /// in `sites-available`, and Apache chosen in its host settings.
    /// Returns the root and the site file.
    fn debian_apache(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = self._tmp.path().join("apache2");
        for dir in ["conf-enabled", "sites-enabled", "sites-available"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("apache2.conf"), DEBIAN_APACHE2_CONF).unwrap();
        let site = root.join("sites-available/example.conf");
        fs::write(&site, apache_site("example.com")).unwrap();
        self.choose_apache(&root);
        (root, site)
    }

    /// RHEL's Apache tree, the same way: `conf/httpd.conf`, which reads its
    /// sites and everything else from `conf.d`.
    fn rhel_apache(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = self._tmp.path().join("httpd");
        fs::create_dir_all(root.join("conf")).unwrap();
        fs::create_dir_all(root.join("conf.d")).unwrap();
        fs::write(root.join("conf/httpd.conf"), RHEL_HTTPD_CONF).unwrap();
        let site = root.join("conf.d/example.conf");
        fs::write(&site, apache_site("example.com")).unwrap();
        self.choose_apache(&root);
        (root, site)
    }

    fn choose_apache(&self, root: &Path) {
        fs::write(
            self.host_conf(),
            format!("web_server = apache\napache_root = {}\n", root.display()),
        )
        .unwrap();
    }

    /// `apply-blocks` against the stored root, with `bin` first on PATH:
    /// tested and reloaded through the fakes there.
    fn apply_with(&self, bin: &Path) -> assert_cmd::assert::Assert {
        self.cmd(&["apply-blocks"])
            .env("PATH", path_with(bin))
            .assert()
    }
}

#[test]
fn apache_apply_tests_with_apache2ctl_then_reloads_apache() {
    let fx = Fixture::new();
    let (_, site) = fx.debian_apache();
    let (bin, calls) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    fx.apply_with(&bin).success();

    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(
        log.lines().collect::<Vec<_>>(),
        ["apache2ctl configtest", "systemctl reload apache2"],
        "log was: {log}"
    );
    let written = fs::read_to_string(&site).unwrap();
    assert!(
        written.starts_with("<VirtualHost *:80>\n    # BEGIN stop-bots (DO NOT EDIT)\n"),
        "site was:\n{written}"
    );
}

/// What an apply prints names the server it tested and reloaded: an
/// Apache host told "Reloaded NGINX" goes looking for an NGINX it does
/// not run.
#[test]
fn apache_apply_says_it_reloaded_apache() {
    let fx = Fixture::new();
    fx.debian_apache();
    let (bin, _) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    let preview = fx
        .cmd(&["apply-blocks", "--dry-run"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let preview = String::from_utf8(preview).unwrap();
    assert!(
        preview.contains("Apache: 1 file(s) would change") && !preview.contains("NGINX"),
        "preview was:\n{preview}"
    );

    let out = fx.apply_with(&bin).success().get_output().stdout.clone();
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.contains("Reloaded Apache") && !out.contains("NGINX"),
        "apply printed:\n{out}"
    );
}

/// The commands that say where a change ends up say Apache on an Apache
/// host, each where it used to say NGINX.
#[test]
fn apache_hosts_are_told_about_apache_not_nginx() {
    let fx = Fixture::new();
    fx.debian_apache();
    for (args, expected) in [
        (
            &["add-trusted", "--address", "192.0.2.1"][..],
            "never blocked by the firewall or Apache",
        ),
        (
            &["add-trusted", "--user-agent", "UptimeRobot"],
            "never blocked by Apache",
        ),
        (
            &["set-auto-apply", "--enabled", "true"],
            "Automatic Apache applying enabled",
        ),
        (
            &["set-rate-limit", "--enabled", "false"],
            "write it into the Apache config",
        ),
        (
            &["set-humans-only", "--enabled", "true"],
            "the Apache screen's",
        ),
    ] {
        let out = fx.run(args).get_output().stdout.clone();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains(expected) && !out.contains("NGINX"),
            "`{}` printed:\n{out}",
            args.join(" ")
        );
    }
}

#[test]
fn apache_hosts_are_told_it_was_apaches_access_log_that_could_not_be_read() {
    let fx = Fixture::new();
    fx.debian_apache();
    let missing = fx._tmp.path().join("no-such.log");
    fx.cmd(&[
        "list-turned-away",
        "--access-log",
        missing.to_str().unwrap(),
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "couldn't read the Apache access log",
    ));
}

#[test]
fn apache_refusing_the_config_puts_the_site_back_and_says_what_to_enable() {
    let fx = Fixture::new();
    let (_, site) = fx.debian_apache();
    let (bin, calls) = fake_tools(fx._tmp.path());
    fs::write(
        fx._tmp.path().join("fail-apache2ctl"),
        "AH00526: Syntax error: Invalid command 'RewriteEngine', perhaps misspelled",
    )
    .unwrap();
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    fx.apply_with(&bin)
        .failure()
        .stderr(predicate::str::contains("a2enmod rewrite"));

    assert_eq!(
        fs::read_to_string(&site).unwrap(),
        apache_site("example.com")
    );
    let log = fs::read_to_string(&calls).unwrap();
    assert!(!log.contains("systemctl"), "reloaded anyway: {log}");
}

/// The config test passes a block a later `RewriteEngine Off` switches
/// off; the apply must not.
#[test]
fn apache_apply_refuses_a_site_that_switches_rewriting_off() {
    let fx = Fixture::new();
    let (_, site) = fx.debian_apache();
    let switched_off = apache_site("example.com")
        .replace("</VirtualHost>", "    RewriteEngine Off\n</VirtualHost>");
    fs::write(&site, &switched_off).unwrap();
    let (bin, _) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    fx.apply_with(&bin)
        .failure()
        .stderr(predicate::str::contains("RewriteEngine Off"));
    assert_eq!(fs::read_to_string(&site).unwrap(), switched_off);
}

#[test]
fn apache_on_rhel_writes_the_trust_file_to_conf_d() {
    let fx = Fixture::new();
    let (root, site) = fx.rhel_apache();
    fx.seed_bots();
    fx.run(&["scan-sites"]);
    fx.run(&["add-trusted", "--user-agent", "UptimeRobot"]);

    fx.run(&["apply-blocks", "--no-reload"]);

    let trust = root.join("conf.d/stop-bots-trusted.conf");
    let written = fs::read_to_string(&trust).unwrap_or_default();
    assert!(
        written.contains("UptimeRobot"),
        "trust file was:\n{written}"
    );
    assert!(fs::read_to_string(&site)
        .unwrap()
        .contains("stop_bots_trusted"));
}

/// RHEL with a `conf-enabled` made by hand: `httpd.conf` never reads it,
/// and a trust file there would leave every trusted client blocked.
#[test]
fn apache_refuses_a_trust_file_where_apache_never_reads_it() {
    let fx = Fixture::new();
    let (root, site) = fx.rhel_apache();
    fs::create_dir_all(root.join("conf-enabled")).unwrap();
    fx.seed_bots();
    fx.run(&["scan-sites"]);
    fx.run(&["add-trusted", "--user-agent", "UptimeRobot"]);

    fx.cmd(&["apply-blocks", "--no-reload"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("never read"));
    assert!(!root.join("conf-enabled/stop-bots-trusted.conf").exists());
    assert_eq!(
        fs::read_to_string(&site).unwrap(),
        apache_site("example.com")
    );
}

#[test]
fn apache_refuses_to_turn_rate_limiting_on() {
    let fx = Fixture::new();
    fx.debian_apache();
    fx.cmd(&["set-rate-limit", "--enabled", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no rate limiting"));
    // Off is always fine: it is what Apache has.
    fx.run(&["set-rate-limit", "--enabled", "false"]);
}

/// Everything that would find NGINX's blocks again works on the server
/// chosen, so choosing Apache first would strand them.
#[test]
fn switching_web_server_is_refused_while_the_old_one_has_blocks() {
    let fx = Fixture::new();
    fx.run(&[
        "set-nginx-commands",
        "--root",
        fx.nginx_root.to_str().unwrap(),
    ]);
    let site = fx.write_site("a.example");
    let before = fs::read_to_string(&site).unwrap();
    fx.seed_bots();
    fx.scan_sites();
    fx.apply_blocks();

    fx.cmd(&["set-web-server", "apache"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("uninstall web-server"))
        .stderr(predicate::str::contains(site.to_str().unwrap()));
    let host = fs::read_to_string(fx.host_conf()).unwrap();
    assert!(!host.contains("web_server"), "switched anyway:\n{host}");

    // With the block gone, nothing stands in the way.
    fs::write(&site, before).unwrap();
    fx.run(&["set-web-server", "apache"]);
    let host = fs::read_to_string(fx.host_conf()).unwrap();
    assert!(host.contains("web_server = apache"), "host.conf:\n{host}");
}

/// NGINX is stored as no choice at all, so a host that never chose
/// Apache keeps a host.conf the releases before the choice can read.
#[test]
fn choosing_nginx_writes_no_web_server_line() {
    let fx = Fixture::new();
    fx.run(&["set-web-server", "nginx"]);
    let host = fs::read_to_string(fx.host_conf()).unwrap_or_default();
    assert!(!host.contains("web_server"), "host.conf:\n{host}");
}

/// `uninstall web-server` on an Apache host takes out what an Apache apply
/// wrote, byte for byte. Under `--prefix`, which runs no system program.
#[test]
fn apache_uninstall_takes_a_prefix_back_to_how_it_was() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tmp.path();
    let host_conf = prefix.join("etc/stop-bots/host.conf");
    let db = prefix.join("var/lib/stop-bots/db.sqlite3");
    let managed = prefix.join("etc/stop-bots/apache");
    let run = |args: &[&str]| {
        stop_bots_bin()
            .env("STOP_BOTS_APACHE_DIR", &managed)
            .env("STOP_BOTS_HOST_CONF", &host_conf)
            .args(args)
            .args(["--db", db.to_str().unwrap()])
            .assert()
            .success()
    };
    let root = prefix.join("etc/apache2");
    for dir in ["conf-enabled", "sites-available"] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    fs::write(root.join("apache2.conf"), DEBIAN_APACHE2_CONF).unwrap();
    let site = root.join("sites-available/example.conf");
    fs::write(&site, apache_site("example.com")).unwrap();
    // Stored as the host's own path, which `--prefix` reads inside the tree.
    fs::create_dir_all(host_conf.parent().unwrap()).unwrap();
    fs::write(
        &host_conf,
        "web_server = apache\napache_root = /etc/apache2\n",
    )
    .unwrap();
    run(&["add-trusted", "--user-agent", "UptimeRobot"]);
    run(&["set-robots-txt", "--enabled", "true"]);
    run(&[
        "apply-blocks",
        "--root",
        root.to_str().unwrap(),
        "--no-reload",
    ]);
    let trust = root.join("conf-enabled/stop-bots-trusted.conf");
    assert!(trust.exists(), "nothing was applied");

    let out = run(&[
        "uninstall",
        "web-server",
        "--prefix",
        prefix.to_str().unwrap(),
    ]);

    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert_eq!(
        fs::read_to_string(&site).unwrap(),
        apache_site("example.com"),
        "{stdout}"
    );
    for gone in [&trust, &managed] {
        assert!(
            !gone.exists(),
            "{} is still there:\n{stdout}",
            gone.display()
        );
    }
}

// ---- Traefik ----
//
// The same binary driving a fake Traefik file provider directory: what is
// written, that nothing is run, and what is refused. The container suite
// runs the real Traefik.

/// Two routers of a file provider's, one for `a.example` and one for
/// `b.example` and its `www`.
const TRAEFIK_SITES: &str = "http:\n  routers:\n    a:\n      rule: \"Host(`a.example`)\"\n      service: app\n    b:\n      rule: \"Host(`b.example`) || Host(`www.b.example`)\"\n      service: app\n";

impl Fixture {
    /// A Traefik file provider directory in this fixture, holding
    /// [`TRAEFIK_SITES`] as `sites.yml`, and Traefik chosen in its host
    /// settings. Returns the root and the sites file.
    fn traefik(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = self._tmp.path().join("traefik/dynamic");
        fs::create_dir_all(&root).unwrap();
        let sites = root.join("sites.yml");
        fs::write(&sites, TRAEFIK_SITES).unwrap();
        fs::write(
            self.host_conf(),
            format!("web_server = traefik\ntraefik_root = {}\n", root.display()),
        )
        .unwrap();
        (root, sites)
    }
}

/// Traefik reads its file provider's directory again by itself: an apply
/// writes the routers file beside the sites and runs nothing, and the
/// operator's own file is left as it was.
#[test]
fn traefik_apply_writes_its_routers_file_and_runs_nothing() {
    let fx = Fixture::new();
    let (root, sites) = fx.traefik();
    let (bin, calls) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"])
        .stdout(predicate::str::contains("Discovered 2 site(s)"));

    let out = fx.apply_with(&bin).success().get_output().stdout.clone();

    let routers = fs::read_to_string(root.join("stop-bots.yml")).unwrap_or_default();
    assert!(
        routers.contains("    stop-bots:\n      rule: '")
            && routers.contains("|zmap-proxy-probe)`"),
        "the host-wide router should carry the bot list; routers file was:\n{routers}"
    );
    assert_eq!(fs::read_to_string(&sites).unwrap(), TRAEFIK_SITES);
    let log = fs::read_to_string(&calls).unwrap_or_default();
    assert!(log.is_empty(), "ran: {log}");
    let out = String::from_utf8(out).unwrap();
    assert!(!out.contains("NGINX"), "apply printed:\n{out}");
}

#[test]
fn traefik_preview_names_traefik_and_its_routers_file() {
    let fx = Fixture::new();
    let (root, _) = fx.traefik();
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    let preview = fx
        .run(&["apply-blocks", "--dry-run"])
        .get_output()
        .stdout
        .clone();

    let preview = String::from_utf8(preview).unwrap();
    let routers = root.join("stop-bots.yml");
    assert!(
        preview.contains("Traefik: 1 file(s) would change")
            && preview.contains(routers.to_str().unwrap())
            && !preview.contains("NGINX"),
        "preview was:\n{preview}"
    );
    assert!(!routers.exists(), "a dry run wrote the routers file");
}

#[test]
fn traefik_refuses_what_it_cannot_do() {
    let fx = Fixture::new();
    fx.traefik();
    for (args, expected) in [
        (
            &["set-rate-limit", "--enabled", "true"][..],
            "Traefik limits rates only in a middleware",
        ),
        (
            &["set-robots-txt", "--enabled", "true"],
            "Traefik serves no files",
        ),
    ] {
        fx.cmd(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected));
    }
    fx.run(&["set-robots-txt", "--enabled", "false"]);
    fx.run(&["set-block-response", "--response", "teapot"])
        .stdout(predicate::str::contains(
            "Traefik cannot send that: a blocked request gets a plain 403 there",
        ));
}

/// No Traefik rule can tell HTTP versions apart, so a site with the
/// HTTP/1.x rule on would be told it is protected by a rule that does
/// nothing.
#[test]
fn traefik_refuses_a_site_with_a_rule_it_cannot_express() {
    let fx = Fixture::new();
    let (root, _) = fx.traefik();
    fx.seed_bots();
    fx.run(&["scan-sites"]);
    fx.run(&[
        "set-site-rule",
        "--site",
        "b.example",
        "--rule",
        "http-1x",
        "--enabled",
        "true",
    ]);

    fx.cmd(&["apply-blocks"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("b.example"))
        .stderr(predicate::str::contains("Switch it off for the site"));
    assert!(!root.join("stop-bots.yml").exists());
}

#[test]
fn set_web_server_traefik_shows_that_it_runs_no_command() {
    let fx = Fixture::new();
    let root = fx._tmp.path().join("dynamic");
    fs::create_dir_all(&root).unwrap();
    fx.run(&[
        "set-web-server",
        "traefik",
        "--root",
        root.to_str().unwrap(),
    ])
    .stdout(predicate::str::contains("Web server:     Traefik"))
    .stdout(predicate::str::contains("Test command:   (none)"))
    .stdout(predicate::str::contains("Reload command: (none)"));
    let host = fs::read_to_string(fx.host_conf()).unwrap();
    assert!(
        host.contains("web_server = traefik") && host.contains("traefik_root = "),
        "host.conf:\n{host}"
    );
}

/// `uninstall web-server` on a Traefik host deletes the routers file and
/// nothing else of the directory. Under `--prefix`, which runs no system
/// program.
#[test]
fn traefik_uninstall_takes_the_routers_file_away() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tmp.path();
    let host_conf = prefix.join("etc/stop-bots/host.conf");
    let db = prefix.join("var/lib/stop-bots/db.sqlite3");
    let run = |args: &[&str]| {
        stop_bots_bin()
            .env("STOP_BOTS_HOST_CONF", &host_conf)
            .args(args)
            .args(["--db", db.to_str().unwrap()])
            .assert()
            .success()
    };
    let root = prefix.join("etc/traefik/dynamic");
    fs::create_dir_all(&root).unwrap();
    let sites = root.join("sites.yml");
    fs::write(&sites, TRAEFIK_SITES).unwrap();
    fs::create_dir_all(host_conf.parent().unwrap()).unwrap();
    fs::write(
        &host_conf,
        "web_server = traefik\ntraefik_root = /etc/traefik/dynamic\n",
    )
    .unwrap();
    run(&[
        "update-bot-lists",
        "--source",
        "tests/fixtures/botlists/well-known-bots-sample.json",
    ]);
    run(&[
        "apply-blocks",
        "--root",
        root.to_str().unwrap(),
        "--no-reload",
    ]);
    let routers = root.join("stop-bots.yml");
    assert!(routers.exists(), "nothing was applied");

    let out = run(&[
        "uninstall",
        "web-server",
        "--prefix",
        prefix.to_str().unwrap(),
    ]);

    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(
        !routers.exists(),
        "the routers file is still there:\n{stdout}"
    );
    assert_eq!(
        fs::read_to_string(&sites).unwrap(),
        TRAEFIK_SITES,
        "{stdout}"
    );
}

// ---- NPMplus ----
//
// The same binary driving a fake NPMplus data directory: the one block
// every host includes, NPMplus's own files left alone, and the container's
// NGINX tested and reloaded through `docker exec`.

/// A proxy host as NPMplus renders it, trimmed to what is read.
const NPMPLUS_PROXY_HOST: &str = "server {\n  server_name a.example;\n  listen 0.0.0.0:80;\n  include /data/custom_nginx/server_http.conf;\n}\n";

/// A line of the operator's own in `server_http.conf`.
const NPMPLUS_OWN_LINE: &str = "add_header X-Mine 1;\n";

/// An NPMplus data directory at `root`: one proxy host, and the
/// `custom_nginx` files NPMplus creates, one with a line of the
/// operator's. Returns the proxy host's file and `server_http.conf`.
fn npmplus_data(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let proxy_host = root.join("nginx/proxy_host/1.conf");
    let server_http = root.join("custom_nginx/server_http.conf");
    fs::create_dir_all(proxy_host.parent().unwrap()).unwrap();
    fs::create_dir_all(server_http.parent().unwrap()).unwrap();
    fs::write(&proxy_host, NPMPLUS_PROXY_HOST).unwrap();
    fs::write(&server_http, NPMPLUS_OWN_LINE).unwrap();
    fs::write(root.join("custom_nginx/http_top.conf"), "").unwrap();
    (proxy_host, server_http)
}

impl Fixture {
    /// [`npmplus_data`] in this fixture, and NPMplus chosen in its host
    /// settings.
    fn npmplus(&self) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = self._tmp.path().join("npmplus");
        let files = npmplus_data(&root);
        fs::write(
            self.host_conf(),
            format!("web_server = npmplus\nnpmplus_root = {}\n", root.display()),
        )
        .unwrap();
        files
    }
}

#[test]
fn npmplus_apply_writes_the_block_every_host_includes() {
    let fx = Fixture::new();
    let (proxy_host, server_http) = fx.npmplus();
    let (bin, _) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"])
        .stdout(predicate::str::contains("Discovered 1 site(s)"));

    fx.apply_with(&bin).success();

    let written = fs::read_to_string(&server_http).unwrap();
    assert!(
        written.starts_with("    # BEGIN stop-bots") && written.ends_with(NPMPLUS_OWN_LINE),
        "server_http.conf was:\n{written}"
    );
    assert_eq!(
        fs::read_to_string(&proxy_host).unwrap(),
        NPMPLUS_PROXY_HOST,
        "NPMplus's own file was written"
    );
}

#[test]
fn npmplus_tests_and_reloads_nginx_in_its_container() {
    let fx = Fixture::new();
    fx.npmplus();
    let (bin, calls) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    fx.apply_with(&bin).success();

    assert_eq!(
        fs::read_to_string(&calls).unwrap_or_default(),
        "docker exec npmplus nginx -t\ndocker exec npmplus nginx -s reload\n"
    );
}

/// NPMplus's two files are the operator's: a config its NGINX refuses
/// puts both back as they were.
#[test]
fn npmplus_puts_its_files_back_when_nginx_refuses_the_config() {
    let fx = Fixture::new();
    let (_, server_http) = fx.npmplus();
    let (bin, _) = fake_tools(fx._tmp.path());
    fs::write(fx._tmp.path().join("fail-docker"), "nginx: [emerg] no\n").unwrap();
    fx.seed_bots();
    fx.run(&["scan-sites"]);

    fx.apply_with(&bin).failure();

    let http_top = server_http.with_file_name("http_top.conf");
    let cases = [
        ("server_http.conf", &server_http, NPMPLUS_OWN_LINE),
        ("http_top.conf", &http_top, ""),
    ];
    for (what, path, expected) in cases {
        assert_eq!(fs::read_to_string(path).unwrap(), expected, "{what}");
    }
}

/// Every host includes the one block, so a host's own settings have
/// nowhere to go, and an apply says so rather than leave them out.
#[test]
fn npmplus_refuses_a_site_with_settings_of_its_own() {
    let fx = Fixture::new();
    let (_, server_http) = fx.npmplus();
    let (bin, _) = fake_tools(fx._tmp.path());
    fx.seed_bots();
    fx.run(&["scan-sites"]);
    fx.run(&[
        "set-site-rule",
        "--site",
        "a.example",
        "--rule",
        "no-accept",
        "--enabled",
        "true",
    ]);

    fx.apply_with(&bin)
        .failure()
        .stderr(predicate::str::contains(
            "a.example has settings of its own",
        ));
    assert_eq!(fs::read_to_string(&server_http).unwrap(), NPMPLUS_OWN_LINE);
}

/// `uninstall web-server` takes the block out of both of NPMplus's files,
/// leaving each as it was, and removes the generated files. Under
/// `--prefix`, which runs no system program.
#[test]
fn npmplus_uninstall_puts_its_files_back() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tmp.path();
    let host_conf = prefix.join("etc/stop-bots/host.conf");
    let db = prefix.join("var/lib/stop-bots/db.sqlite3");
    let run = |args: &[&str]| {
        stop_bots_bin()
            .env("STOP_BOTS_HOST_CONF", &host_conf)
            .args(args)
            .args(["--db", db.to_str().unwrap()])
            .assert()
            .success()
    };
    let root = prefix.join("opt/npmplus");
    let (_, server_http) = npmplus_data(&root);
    fs::create_dir_all(host_conf.parent().unwrap()).unwrap();
    fs::write(&host_conf, "web_server = npmplus\n").unwrap();
    run(&[
        "update-bot-lists",
        "--source",
        "tests/fixtures/botlists/well-known-bots-sample.json",
    ]);
    run(&["set-robots-txt", "--enabled", "true"]);
    run(&[
        "apply-blocks",
        "--root",
        root.to_str().unwrap(),
        "--no-reload",
    ]);
    let robots = root.join("custom_nginx/stop-bots/robots.txt");
    assert!(robots.exists(), "nothing was applied");

    let out = run(&[
        "uninstall",
        "web-server",
        "--prefix",
        prefix.to_str().unwrap(),
    ]);

    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let cases = [
        (
            "server_http.conf",
            fs::read_to_string(&server_http).unwrap(),
            NPMPLUS_OWN_LINE,
        ),
        (
            "http_top.conf",
            fs::read_to_string(root.join("custom_nginx/http_top.conf")).unwrap(),
            "",
        ),
    ];
    for (what, got, expected) in cases {
        assert_eq!(got, expected, "{what} after uninstall:\n{stdout}");
    }
    assert!(!robots.exists(), "robots.txt is still there:\n{stdout}");
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
        // setting this on a host where nothing runs the schedule turns on a
        // switch nothing will ever read.
        .stdout(predicate::str::contains("install cron"));

    let db = stop_bots::db::Db::open(&fixture.db).unwrap();
    assert!(db.get_auto_apply().unwrap());
}

/// Turning the switch on must not, by itself, apply anything: the CLI sets
/// a flag, and the schedule (`tick`, or the TUI) is what acts on it. A `set-` command that quietly reloaded NGINX would be the worst
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

    let summary =
        stop_bots::cron::apply_nginx(&db, &Default::default(), &fixture.nginx_root, false);
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
    let again = stop_bots::cron::apply_nginx(&db, &Default::default(), &fixture.nginx_root, false);
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

// ---- command-line conventions ----

/// `--db` is global: it works before the subcommand as well as after it,
/// which is where every test above puts it.
#[test]
fn db_may_come_before_the_subcommand() {
    let fx = Fixture::new();
    stop_bots_bin()
        .args([
            "--db",
            fx.db.to_str().unwrap(),
            "add-trusted",
            "--address",
            "203.0.113.7",
        ])
        .assert()
        .success();
    fx.run(&["list-trusted"])
        .stdout(predicate::str::contains("203.0.113.7"));
}

/// `STOP_BOTS_DB` names the database when no `--db` does, and an explicit
/// `--db` still wins over it.
#[test]
fn stop_bots_db_names_the_database_and_db_overrides_it() {
    let fx = Fixture::new();
    let other = fx.db.with_file_name("other.sqlite3");

    stop_bots_bin()
        .env("STOP_BOTS_DB", &fx.db)
        .args(["add-trusted", "--address", "203.0.113.7"])
        .assert()
        .success();
    fx.run(&["list-trusted"])
        .stdout(predicate::str::contains("203.0.113.7"));

    stop_bots_bin()
        .env("STOP_BOTS_DB", &fx.db)
        .args(["list-trusted", "--db", other.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing is trusted."));
}

/// Renamed for 0.1; the old spelling works for one release.
/// With nothing to name, an `update-*` that updates every source of its
/// kind says there is nothing to do rather than downloading anything.
#[test]
fn an_update_of_everything_with_nothing_chosen_says_so() {
    let fx = Fixture::new();
    for (args, says) in [
        (&["update-country-ranges"][..], "No country is selected"),
        (&["update-reputation-sources"], "No feed is switched on"),
    ] {
        fx.run(args).stdout(predicate::str::contains(says));
    }
}

/// `trust --remove` and `exempt-path --remove` became verbs of their own,
/// and the old spelling still does what it did.
#[test]
fn trust_remove_still_removes_and_says_it_is_deprecated() {
    let fx = Fixture::new();
    fx.run(&["add-trusted", "--address", "203.0.113.7"]);
    fx.run(&["trust", "--remove", "--address", "203.0.113.7"])
        .stderr(predicate::str::contains("use `remove-trusted`"));
    let listed = fx.run(&["list-trusted"]);
    let listed = String::from_utf8_lossy(&listed.get_output().stdout).into_owned();
    assert!(!listed.contains("203.0.113.7"), "still trusted:\n{listed}");
}

/// The verbs `run-detector` replaced still run the same detector, and say
/// on stderr what to use instead, until 2.0.0.
#[test]
fn the_old_detector_verbs_still_work_and_say_they_are_deprecated() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("auth.log");
    fs::write(&log, repeat_failed_attempt("198.51.100.9", 25)).unwrap();

    for command in ["block-ssh-scanners", "block-scanners"] {
        fx.run(&[command, "--ssh-log", log.to_str().unwrap(), "--dry-run"])
            .stdout(predicate::str::contains("Would block 198.51.100.9"))
            .stderr(predicate::str::contains(
                "is deprecated, use `run-detector ssh-scanners`",
            ));
    }
}

/// The current spellings print no deprecation warning.
#[test]
fn run_detector_says_nothing_about_deprecation() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("auth.log");
    fs::write(&log, repeat_failed_attempt("198.51.100.9", 25)).unwrap();

    fx.run(&[
        "run-detector",
        "ssh-scanners",
        "--ssh-log",
        log.to_str().unwrap(),
        "--dry-run",
    ])
    .stderr(predicate::str::contains("deprecated").not());
}

/// Every detector runs by hand now, not only the five that had a verb.
#[test]
fn run_detector_runs_every_detector() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("access.log");
    fs::write(&log, "").unwrap();
    for detector in [
        "web-scanners",
        "spoofed-crawlers",
        "probe-paths",
        "injection",
        "honeypot",
        "asset-ratio",
        "rotating-ua",
        "refererless",
        "robots-txt",
    ] {
        fx.run(&[
            "run-detector",
            detector,
            "--access-log",
            log.to_str().unwrap(),
            "--dry-run",
        ]);
    }
}

/// A detector that convicts on one request has no threshold to give, and
/// each reads the log it reads.
#[test]
fn run_detector_refuses_a_flag_its_detector_has_no_use_for() {
    let fx = Fixture::new();
    for (args, says) in [
        (
            &["run-detector", "injection", "--threshold", "3"][..],
            "has no threshold",
        ),
        (
            &["run-detector", "ssh-scanners", "--access-log", "/dev/null"],
            "--ssh-log",
        ),
        (
            &["run-detector", "probe-paths", "--ssh-log", "/dev/null"],
            "--access-log",
        ),
    ] {
        fx.cmd(args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(says));
    }
}

// ---- detectors ----

/// The switch, TTL and threshold `set-detector` stores are the ones the
/// scheduled passes read, and `list-detectors` shows them.
#[test]
fn set_detector_stores_the_switch_ttl_and_threshold() {
    use stop_bots::protection::Detector;
    let fx = Fixture::new();

    fx.run(&[
        "set-detector",
        "injection",
        "--enabled",
        "false",
        "--ttl-days",
        "3",
    ]);
    fx.run(&[
        "set-detector",
        "ssh-scanners",
        "--threshold",
        "40",
        "--window-hours",
        "6",
    ]);

    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    assert_eq!(Detector::SshScanners.window_hours(&db).unwrap(), 6);
    assert!(!Detector::Injection.is_enabled(&db).unwrap());
    assert_eq!(Detector::Injection.ttl_days(&db).unwrap(), 3);
    assert_eq!(Detector::SshScanners.threshold(&db).unwrap(), Some(40));

    let listing = fx.run(&["list-detectors"]);
    let out = String::from_utf8(listing.get_output().stdout.clone()).unwrap();
    let line = |name: &str| {
        out.lines()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no {name} line in:\n{out}"))
            .split_whitespace()
            .take(5)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        line("injection"),
        ["injection", "off", "3d", "-", "24h"],
        "{out}"
    );
    assert_eq!(
        line("ssh-scanners"),
        ["ssh-scanners", "on", "5d", "40", "6h"],
        "{out}"
    );
}

/// Running a detector by hand uses the stored threshold unless told
/// otherwise, so it finds what the scheduled pass would.
#[test]
fn a_detector_run_by_hand_uses_the_stored_threshold() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("access.log");
    let lines: String = (0..4)
        .map(|i| access_line("203.0.113.9", &format!("/missing-{i}"), 404, "UA"))
        .collect();
    fs::write(&log, lines).unwrap();
    let log = log.to_str().unwrap();

    fx.run(&[
        "run-detector",
        "web-scanners",
        "--access-log",
        log,
        "--dry-run",
    ])
    .stdout(predicate::str::contains("No scanning IPs found"));

    fx.run(&["set-detector", "web-scanners", "--threshold", "4"]);
    fx.run(&[
        "run-detector",
        "web-scanners",
        "--access-log",
        log,
        "--dry-run",
    ])
    .stdout(predicate::str::contains("Would block 203.0.113.9"));
}

/// Each refusal names why, and a command with one bad flag changes
/// nothing — not even the flags beside it that were fine.
#[test]
fn set_detector_refuses_what_it_cannot_store_and_stores_nothing() {
    use stop_bots::protection::Detector;
    let fx = Fixture::new();

    for (args, why) in [
        (
            vec![
                "set-detector",
                "probe-paths",
                "--threshold",
                "5",
                "--ttl-days",
                "9",
            ],
            "no threshold",
        ),
        (
            vec![
                "set-detector",
                "web-scanners",
                "--threshold",
                "1",
                "--ttl-days",
                "9",
            ],
            "threshold under 2",
        ),
        (
            vec!["set-detector", "web-scanners", "--ttl-days", "0"],
            "from 1 to",
        ),
        (
            vec![
                "set-detector",
                "web-scanners",
                "--window-hours",
                "0",
                "--ttl-days",
                "9",
            ],
            "from 1 to 720 hours",
        ),
        (
            vec!["set-detector", "robots-txt", "--enabled", "true"],
            "set-humans-only",
        ),
    ] {
        fx.cmd(&args)
            .assert()
            .failure()
            .stderr(predicate::str::contains(why));
    }

    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    for d in [Detector::ProbePaths, Detector::WebScanners] {
        assert_eq!(d.ttl_days(&db).unwrap(), d.spec().ttl_days_default);
    }
    assert_eq!(Detector::WebScanners.threshold(&db).unwrap(), Some(7));
    assert!(!Detector::RobotsTxt.is_enabled(&db).unwrap());
}

#[test]
fn set_subnet_escalation_switches_it_on_with_a_threshold() {
    let fx = Fixture::new();
    fx.run(&["set-subnet-escalation", "--enabled", "true", "--min", "4"])
        .stdout(predicate::str::contains("escalation is on, at 4"));

    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    assert_eq!(
        stop_bots::protection::subnet_escalation(&db).unwrap(),
        Some(4)
    );
    fx.run(&["list-detectors"])
        .stdout(predicate::str::contains("escalation: on, at 4"));

    fx.run(&["set-subnet-escalation", "--enabled", "false"]);
    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    assert_eq!(stop_bots::protection::subnet_escalation(&db).unwrap(), None);
}

// ---- categories and bots ----

/// The old-browser list reaches the generated block once it is switched
/// on, and leaves it once it is off again.
#[test]
fn set_old_browsers_changes_what_apply_blocks_writes() {
    let fx = Fixture::new();
    let site = fx.write_site("example.com");
    fx.scan_sites();

    fx.run(&["set-old-browsers", "--enabled", "true"])
        .stdout(predicate::str::contains(
            "Old browsers are BLOCKED on every site",
        ));
    fx.apply_blocks();
    let config = fs::read_to_string(&site).unwrap();
    assert!(config.contains(r"Opera/9\."), "config was:\n{config}");
    fx.run(&["list-categories"])
        .stdout(predicate::str::contains(
            "Old browsers: blocked on every site",
        ));

    fx.run(&["set-old-browsers", "--enabled", "false"]);
    fx.apply_blocks();
    let config = fs::read_to_string(&site).unwrap();
    assert!(!config.contains("NetFront"), "config was:\n{config}");
}

/// The host-wide category policy reaches the generated NGINX block: an
/// allowed category's bots are no longer in it.
#[test]
fn set_category_changes_what_apply_blocks_writes() {
    let fx = Fixture::new();
    fx.seed_bots();
    let site = fx.write_site("example.com");
    fx.scan_sites();

    fx.run(&["set-category", "--category", "ai", "--policy", "blocked"]);
    fx.apply_blocks();
    let config = fs::read_to_string(&site).unwrap();
    assert!(config.contains("AISearchBot"), "config was:\n{config}");

    fx.run(&["set-category", "--category", "ai", "--policy", "allowed"])
        .stdout(predicate::str::contains(
            "Category ai is now allowed host-wide.",
        ));
    fx.apply_blocks();
    let config = fs::read_to_string(&site).unwrap();
    assert!(!config.contains("AISearchBot"), "config was:\n{config}");
}

/// A site override is stored per site, shown by `list-categories
/// --site`, and removed again by `default` — which on its own, host-wide,
/// is refused, since there is nothing above the host to follow.
#[test]
fn set_category_with_a_site_overrides_it_for_that_site_only() {
    use stop_bots::db::{Category, Policy};
    let fx = Fixture::new();
    fx.write_site("example.com");
    fx.scan_sites();

    fx.run(&[
        "set-category",
        "--category",
        "search",
        "--policy",
        "blocked",
        "--site",
        "example.com",
    ]);
    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    let site = db.list_sites().unwrap()[0].id;
    assert_eq!(
        db.get_site_category_override(site, Category::Search)
            .unwrap(),
        Some(Policy::Blocked)
    );
    fx.run(&["list-categories", "--site", "example.com"])
        .stdout(predicate::str::is_match(r"search\s+\w+\s+blocked").unwrap());

    fx.run(&[
        "set-category",
        "--category",
        "search",
        "--policy",
        "default",
        "--site",
        "example.com",
    ]);
    assert_eq!(
        db.get_site_category_override(site, Category::Search)
            .unwrap(),
        None
    );

    fx.cmd(&[
        "set-category",
        "--category",
        "search",
        "--policy",
        "default",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("nothing above it"));
}

#[test]
fn set_bot_overrides_one_bot_host_wide_and_per_site() {
    use stop_bots::db::{BotStatus, Policy};
    let fx = Fixture::new();
    fx.seed_bots();
    fx.write_site("example.com");
    fx.scan_sites();

    fx.run(&["list-bots", "--search", "search-bot"])
        .stdout(predicate::str::contains("ai-search-bot"))
        .stdout(predicate::str::contains("google-crawler").not());

    fx.run(&["set-bot", "--bot", "ai-search-bot", "--policy", "allowed"]);
    fx.run(&[
        "set-bot",
        "--bot",
        "google-crawler",
        "--policy",
        "blocked",
        "--site",
        "example.com",
    ]);

    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    let bots = db.list_bots().unwrap();
    let bot = |slug: &str| bots.iter().find(|b| b.slug == slug).unwrap().clone();
    assert_eq!(bot("ai-search-bot").status, BotStatus::Allowed);
    let site = db.list_sites().unwrap()[0].id;
    let overrides = db.site_bot_overrides(site).unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].bot_id, bot("google-crawler").id);
    assert_eq!(overrides[0].policy, Policy::Blocked);
    fx.run(&["list-categories", "--site", "example.com"])
        .stdout(predicate::str::is_match(r"google-crawler\s+blocked").unwrap());

    fx.run(&["set-bot", "--bot", "ai-search-bot", "--policy", "default"]);
    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    let back = db.list_bots().unwrap();
    assert_eq!(
        back.iter()
            .find(|b| b.slug == "ai-search-bot")
            .unwrap()
            .status,
        BotStatus::Default
    );

    fx.cmd(&["set-bot", "--bot", "no-such-bot", "--policy", "blocked"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("list-bots"));
}

// ---- firewall ----

/// A disabled rule stays listed and is left out of the script; enabling
/// it puts it back.
#[test]
fn set_firewall_rule_takes_a_rule_out_of_the_script_without_deleting_it() {
    let fx = Fixture::new();
    let script = fx.db.with_file_name("fw.nft");
    let render = || {
        fx.run(&[
            "render-firewall",
            "--out",
            script.to_str().unwrap(),
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
        ]);
        fs::read_to_string(&script).unwrap()
    };
    fx.run(&["add-firewall-rule", "--address", "198.51.100.7"]);

    fx.run(&["set-firewall-rule", "--id", "1", "--enabled", "false"]);
    fx.run(&["list-firewall-rules"])
        .stdout(predicate::str::contains("198.51.100.7 (disabled)"));
    let written = render();
    assert!(!written.contains("198.51.100.7"), "script was:\n{written}");

    fx.run(&["set-firewall-rule", "--id", "1", "--enabled", "true"]);
    let written = render();
    assert!(written.contains("198.51.100.7"), "script was:\n{written}");

    fx.cmd(&["set-firewall-rule", "--id", "99", "--enabled", "false"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no firewall rule with id: 99"));
}

/// Without `--backend`, `render-firewall` writes for the backend this
/// host is set to, rather than refusing to run.
#[test]
fn render_firewall_follows_the_stored_backend() {
    let fx = Fixture::new();
    let script = fx.db.with_file_name("fw.out");
    fx.run(&["add-firewall-rule", "--address", "198.51.100.7"]);

    fx.run(&["set-firewall-backend", "--backend", "iptables"])
        .stdout(predicate::str::contains("firewall.sh"));
    fx.run(&[
        "render-firewall",
        "--out",
        script.to_str().unwrap(),
        "--ssh-log",
        "tests/fixtures/logs/auth.log",
    ])
    .stdout(predicate::str::contains("firewall.sh"));
    let written = fs::read_to_string(&script).unwrap();
    assert!(
        written.contains("-A STOP-BOTS -s 198.51.100.7 -j DROP"),
        "script was:\n{written}"
    );
}

/// A script written with `--out` is not the one the boot unit loads, so
/// running it by hand would last until the next reboot. The hint names
/// the apply that does persist, not `nft -f` on the file.
#[test]
fn render_firewall_out_points_at_apply_not_a_hand_run() {
    let fx = Fixture::new();
    let script = fx.db.with_file_name("fw.out");
    fx.run(&["add-firewall-rule", "--address", "198.51.100.7"]);
    fx.run(&["set-firewall-backend", "--backend", "nftables"]);

    let output = fx.run(&[
        "render-firewall",
        "--out",
        script.to_str().unwrap(),
        "--ssh-log",
        "tests/fixtures/logs/auth.log",
    ]);
    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    assert!(
        stdout.contains("stop-bots render-firewall --apply"),
        "the hint does not name the apply:\n{stdout}"
    );
    assert!(
        !stdout.contains("nft -f"),
        "the hint still suggests running the file by hand:\n{stdout}"
    );
}

// ---- upgrading from 0.0.x ----

/// A database as 0.0.15 left it, restored from its SQL dump into `db`.
fn restore_0_0_15(db: &Path) {
    let sql = fs::read_to_string("tests/fixtures/db/db-0.0.15.sql").unwrap();
    // No fsyncs for the setup: it is not what is under test.
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch("PRAGMA synchronous = OFF").unwrap();
    conn.execute_batch(&sql).unwrap();
}

/// The upgrade an operator actually does: install the new package, run
/// any command. The rules are all still there, and the database as it
/// was sits next to it.
#[test]
fn the_first_command_after_an_upgrade_keeps_the_rules_and_leaves_a_copy() {
    let fixture = Fixture::new();
    restore_0_0_15(&fixture.db);

    fixture.run(&["list-firewall-rules"]).stdout(
        predicate::str::contains("203.0.113.7")
            .and(predicate::str::contains("198.51.100.0/24"))
            .and(predicate::str::contains("203.0.113.99")),
    );

    let mut backup = fixture.db.as_os_str().to_owned();
    backup.push(".bak-v0");
    assert!(
        Path::new(&backup).exists(),
        "no pre-upgrade copy at {backup:?}"
    );
}

/// Going back a version must not quietly misread what the newer one
/// wrote: it stops, and says which two versions disagree.
#[test]
fn a_database_from_a_newer_release_is_refused() {
    let fixture = Fixture::new();
    fixture.run(&["list-firewall-rules"]);
    rusqlite::Connection::open(&fixture.db)
        .unwrap()
        .pragma_update(None, "user_version", 999)
        .unwrap();

    fixture
        .cmd(&["list-firewall-rules"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("schema version 999").and(predicate::str::contains(format!(
                "versions up to {}",
                stop_bots::db::schema::CURRENT_VERSION
            ))),
        );
}

/// The CLI answer to "why is this blocked, and undo all of it": a
/// detector's block names the detector and the request, can be listed and
/// removed by source, and stays removed when the detector runs again over
/// the same log.
#[test]
fn a_detector_s_blocks_are_listed_and_removed_by_source_and_stay_removed() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("access.log");
    fs::write(
        &log,
        "203.0.113.5 - - [28/Sep/2026:10:00:00 +0000] \"GET /.env HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n\
         203.0.113.6 - - [28/Sep/2026:10:00:01 +0000] \"GET /.git/config HTTP/1.1\" 404 0 \"-\" \"curl/8\"\n",
    )
    .unwrap();
    let log = log.to_str().unwrap();
    fx.run(&["run-detector", "probe-paths", "--access-log", log]);
    fx.run(&["add-firewall-rule", "--address", "192.0.2.1"]);

    fx.run(&["list-firewall-rules", "--source", "probe-paths"])
        .stdout(predicate::str::contains(
            "[probe-paths, added 1m ago]: \"GET /.env HTTP/1.1\" 404",
        ))
        .stdout(predicate::str::contains("192.0.2.1").not());

    fx.run(&[
        "remove-firewall-rule",
        "--source",
        "probe-paths",
        "--dry-run",
    ])
    .stdout(predicate::str::contains("Would remove 2 firewall rule(s)"));
    fx.run(&["remove-firewall-rule", "--source", "probe-paths"])
        .stdout(predicate::str::contains(
            "Removed 2 firewall rule(s) from probe-paths.",
        ));

    fx.run(&["run-detector", "probe-paths", "--access-log", log])
        .stdout(predicate::str::contains("Left 2 alone: unblocked by hand"));
    fx.run(&["list-firewall-rules"])
        .stdout(predicate::str::contains("#3 Block 192.0.2.1 [cli"))
        .stdout(predicate::str::contains("203.0.113").not());
}

/// A 0.0.x rule has no source, and says so rather than guessing one.
#[test]
fn a_rule_from_before_0_1_is_listed_and_removed_as_before_0_1() {
    let fx = Fixture::new();
    let conn = rusqlite::Connection::open(&fx.db).unwrap();
    conn.execute_batch(include_str!("fixtures/db/db-0.0.15.sql"))
        .unwrap();
    drop(conn);

    fx.run(&["list-firewall-rules", "--source", "before-0.1"])
        .stdout(predicate::str::contains("#1 Block 203.0.113.7 [before-0.1"));
    fx.run(&["remove-firewall-rule", "--source", "before-0.1"])
        .stdout(predicate::str::contains("Removed 5 firewall rule(s)"));
}

#[test]
fn remove_firewall_rule_needs_an_id_or_a_source_and_names_the_sources() {
    let fx = Fixture::new();
    fx.cmd(&["remove-firewall-rule"]).assert().failure();
    fx.cmd(&["remove-firewall-rule", "--source", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ssh-scanners"));
}

/// `stop-bots list-bots | head -1` — a reader that stops early — used to
/// end in a panic ("failed printing to stdout: Broken pipe", exit 101).
/// A one-shot command now dies quietly of SIGPIPE, as every other
/// command-line tool does.
#[test]
fn output_piped_into_a_reader_that_stops_early_is_not_a_panic() {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::process::ExitStatusExt;

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db.sqlite3");
    let root = dir.path().join("nginx");
    fs::create_dir_all(&root).unwrap();
    // A dry run stores the built-in bot list — hundreds of rows, far more
    // than a pipe holds, so the command is still writing when the reader
    // goes away.
    stop_bots(&[
        "apply-blocks",
        "--dry-run",
        "--db",
        db.to_str().unwrap(),
        "--root",
        root.to_str().unwrap(),
    ]);
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("stop-bots"))
        .args(["list-bots", "--db", db.to_str().unwrap()])
        .env("PATH", common::quiet_path())
        .env_remove("STOP_BOTS_DB")
        .env("STOP_BOTS_HOST_CONF", dir.path().join("host.conf"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    // The reader is gone; everything the command writes from here on hits
    // a closed pipe.
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = child.wait().unwrap();

    assert!(first.contains("NAME"), "first line was: {first:?}");
    assert!(!stderr.contains("panicked"), "stderr was:\n{stderr}");
    assert_ne!(status.code(), Some(101), "stderr was:\n{stderr}");
    assert!(
        status.success() || status.signal() == Some(libc::SIGPIPE),
        "status was {status:?}, stderr:\n{stderr}"
    );
}

/// A `--root` outside the stock NGINX tree is a tree of its own: the
/// http-context files go into its own `conf.d`, never the host's
/// `/etc/nginx/conf.d`. `batch --root <scratch>` used to read the host's
/// trust file from there, and an apply would have rewritten it.
///
/// No `STOP_BOTS_NGINX_CONF_D` here, unlike everywhere else: the override
/// is what hid this.
#[test]
fn a_scratch_root_keeps_its_generated_files_inside_itself() {
    let fx = Fixture::new();
    fx.write_site("scratch.example");
    let root = fx.nginx_root.to_str().unwrap();
    let run = |args: &[&str]| {
        fx.cmd(args)
            .env_remove("STOP_BOTS_NGINX_CONF_D")
            .assert()
            .success()
    };

    run(&["scan-sites", "--root", root]);
    run(&["add-trusted", "--user-agent", "Pingdom.com_bot"]);
    run(&["apply-blocks", "--root", root, "--no-reload"]);

    let trust_file = fx.nginx_root.join("conf.d/stop-bots-trusted.conf");
    assert!(
        fs::read_to_string(&trust_file).is_ok_and(|body| body.contains("Pingdom")),
        "the trust file is not inside the root, at {}",
        trust_file.display()
    );
}

/// A blocked user agent or an exempt path stored by an older release
/// without today's checks is left out of the config, and `apply-blocks`
/// says which. Here, an exemption with a backslash in it: `/x\|` was a
/// match-all while exemptions were written verbatim.
#[test]
fn apply_blocks_names_what_it_leaves_out() {
    let fx = Fixture::new();
    fx.seed_bots();
    fx.write_site("old.example");
    fx.scan_sites();
    let db = rusqlite::Connection::open(&fx.db).unwrap();
    db.execute(
        "INSERT INTO site_path_exemptions (site_id, path) \
         SELECT id, '/x\\|' FROM sites WHERE server_name = 'old.example'",
        [],
    )
    .unwrap();
    drop(db);

    fx.apply_blocks().stderr(predicate::str::contains(
        r#"warning: left out of the NGINX config: old.example: exempt path "/x\\|""#,
    ));
    let site = fs::read_to_string(fx.nginx_root.join("old.example.conf")).unwrap();
    assert!(!site.contains("/x"), "the exemption was written:\n{site}");
}

// ---- nothing a database row or a log line holds drives the terminal ----

/// What a value would carry to take over the terminal of the root operator
/// who reads it, or to make what is printed read as something else. The
/// console runs unprivileged and writes the database these commands read,
/// and a client writes the logs, so each of these can arrive in a row.
const HOSTILE: &[(&str, &str)] = &[
    ("an OSC title change", "\u{1b}]0;PWNED\u{7}"),
    ("a CSI as the C1 U+009B", "\u{9b}31mred"),
    ("a bare ESC", "\u{1b}[2J"),
    ("a BEL", "bell\u{7}"),
    ("a DEL", "del\u{7f}"),
    ("a CR that prints over the start", "real\rfake"),
    ("a right-to-left override", "\u{202e}lmth.tob"),
    ("a zero-width space", "Google\u{200b}bot"),
];

/// Each of [`HOSTILE`], as one value inside some ordinary text, so that
/// every one of them reaches every field it is planted in.
fn hostile_values() -> impl Iterator<Item = String> {
    HOSTILE
        .iter()
        .enumerate()
        .map(|(n, (_, chars))| format!("h{n}{chars}x"))
}

/// Fails, naming the character and where, if `bytes` holds anything a
/// terminal acts on other than the program's own newlines and tabs: a C0
/// control, DEL, a C1 control (as its UTF-8 or as a lone byte, which is
/// not UTF-8 at all), or a bidirectional or zero-width character.
fn assert_terminal_safe(command: &str, stream: &str, bytes: &[u8]) {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|err| {
        panic!(
            "`{command}` wrote bytes that are not UTF-8 to {stream} ({err}):\n{}",
            String::from_utf8_lossy(bytes)
        )
    });
    for (at, c) in text.char_indices() {
        let drives_the_terminal = c.is_control() && !matches!(c, '\n' | '\t');
        let reorders_or_hides = stop_bots::present::is_invisible_format(c);
        assert!(
            !drives_the_terminal && !reorders_or_hides,
            "`{command}` wrote {c:?} to {stream} at byte {at}:\n{text}"
        );
    }
}

/// [`assert_terminal_safe`] on both streams of one run.
fn assert_output_terminal_safe(command: &str, output: &std::process::Output) {
    assert_terminal_safe(command, "stdout", &output.stdout);
    assert_terminal_safe(command, "stderr", &output.stderr);
}

impl Fixture {
    /// This fixture with every [`HOSTILE`] value planted where a `list-*`
    /// or `status` command prints it: in the rows themselves, written with
    /// plain SQL past every check, as anyone who can write the database
    /// could; in a site's
    /// server name; and in an access log that `host.conf` points at.
    fn hostile() -> Fixture {
        let fx = Fixture::new();
        let log = fx.nginx_root.join("access.log");
        let mut lines = String::new();
        for value in hostile_values() {
            lines += &serde_json::json!({
                "remote_addr": "203.0.113.5",
                "request_uri": format!("/{value}"),
                "status": "444",
                "http_user_agent": value,
            })
            .to_string();
            lines += "\n";
        }
        fs::write(&log, lines).unwrap();
        fs::write(
            fx.host_conf(),
            format!(
                "access_log = {}\nssh_log = {}/tests/fixtures/logs/auth.log\n",
                log.display(),
                env!("CARGO_MANIFEST_DIR")
            ),
        )
        .unwrap();
        // Through the library rather than the CLI: a run of the binary
        // costs a tenth of a second on a loaded machine, and this fixture
        // is set up five times.
        let db = stop_bots::db::Db::open(&fx.db).unwrap();
        db.set_block_response(stop_bots::db::BlockResponse::Close)
            .unwrap();
        let hits = hostile_values().map(|value| (value, 1)).collect();
        db.record_user_agent_hits(&hits, 0).unwrap();
        drop(db);

        let mut conn = rusqlite::Connection::open(&fx.db).unwrap();
        // One transaction: a commit per row is a sync per row, seconds.
        let db = conn.transaction().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO sources (id, name, url) VALUES ('evil', 'evil', 'x')",
            [],
        )
        .unwrap();
        for (n, value) in hostile_values().enumerate() {
            let site_id: i64 = db
                .query_row(
                    "INSERT INTO sites (server_name, config_path, discovered_at) \
                     VALUES (?1, ?2, 0) RETURNING id",
                    rusqlite::params![value, format!("/nowhere/{n}.conf")],
                    |row| row.get(0),
                )
                .unwrap();
            for sql in [
                "INSERT INTO firewall_rules (address, action, enabled, created_at, source, evidence) \
                 VALUES (?1, 'block', 1, 0, 'manual', ?1)",
                "INSERT INTO trusted_addresses (address, trusted_at) VALUES (?1, 0)",
                "INSERT INTO trusted_user_agents (user_agent, trusted_at) VALUES (?1, 0)",
                "INSERT INTO blocked_user_agents (user_agent, blocked_at) VALUES (?1, 0)",
                "INSERT INTO reputation_sources (id, name, url) VALUES (?1, ?1, ?1)",
                "INSERT INTO selected_countries (country_code, added_at) VALUES (?1, 0)",
                "INSERT INTO bots (slug, name, user_agent_pattern, status, source_id, updated_at) \
                 VALUES (?1, ?1, ?1, 'blocked', 'evil', 0)",
            ] {
                db.execute(sql, [&value]).unwrap();
            }
            // An exempt path NGINX cannot take, so that the site's name
            // is quoted in the warning that says it was left out.
            db.execute(
                "INSERT INTO site_path_exemptions (site_id, path) VALUES (?1, ?2)",
                rusqlite::params![site_id, format!("/x\\|{value}")],
            )
            .unwrap();
        }
        let paths: Vec<String> = hostile_values().map(|v| format!("/{v}")).collect();
        db.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('detect_probe_paths_extra', ?1)",
            [paths.join("\n")],
        )
        .unwrap();
        db.commit().unwrap();
        fx
    }
}

/// The confirmed attack: a title-set OSC and a C1 CSI in a firewall rule
/// the web console wrote reached root's terminal through
/// `list-firewall-rules`.
/// The rule is still listed, one line each, with the characters replaced.
#[test]
fn list_firewall_rules_prints_a_hostile_rule_defanged_on_one_line() {
    let fx = Fixture::hostile();

    let output = fx.cmd(&["list-firewall-rules"]).output().unwrap();

    assert_output_terminal_safe("list-firewall-rules", &output);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("h0\u{fffd}]0;PWNED\u{fffd}x") && stdout.contains("h6\\u{202E}lmth.tobx"),
        "the rule should still be listed, defanged:\n{stdout}"
    );
    assert_eq!(
        stdout.lines().count(),
        HOSTILE.len(),
        "one line per rule:\n{stdout}"
    );
}

/// Every `list-*` and `show-*` command `--help` lists, so that one added
/// later is walked too, against a database and a log holding every
/// [`HOSTILE`] value. And `status --cached`, which re-assesses the stored
/// probe against the same database.
#[test]
fn every_list_and_show_command_prints_hostile_rows_terminal_safe() {
    let fx = Fixture::hostile();
    let help = fx.cmd(&["--help"]).output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    let commands: Vec<&str> = help
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| word.starts_with("list-") || word.starts_with("show-"))
        .collect();
    assert!(
        commands.len() >= 10,
        "the walk found too few commands, so --help changed shape: {commands:?}"
    );

    // All at once: they only read, and one after another is seconds.
    let outputs: Vec<_> = std::thread::scope(|scope| {
        let runs: Vec<_> = commands
            .iter()
            .map(|&command| {
                let fx = &fx;
                scope.spawn(move || (command, fx.cmd(&[command]).output().unwrap()))
            })
            .collect();
        runs.into_iter().map(|run| run.join().unwrap()).collect()
    });
    for (command, output) in outputs {
        assert!(
            output.status.code() != Some(2),
            "`{command}` needs an argument this walk does not give it:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_output_terminal_safe(command, &output);
    }
}

/// `status --cached` prints the strings of a probe as it was stored,
/// as stored, and the checks it derives from the database: what is
/// trusted by hand, and what the NGINX config leaves out.
#[test]
fn status_cached_prints_a_hostile_probe_and_database_terminal_safe() {
    let fx = Fixture::hostile();
    let value = hostile_values().collect::<Vec<_>>().join(" ");
    let probe = stop_bots::health::Probe {
        access_log_readable: Some(false),
        access_log_path: Some(value.clone()),
        access_log_unparsed_sample: Some(value.clone()),
        stray_generated_files: vec![value.clone()],
        conf_d_path: Some(value),
        ..Default::default()
    };
    let db = stop_bots::db::Db::open(&fx.db).unwrap();
    stop_bots::health::store_probe(&db, &probe).unwrap();
    drop(db);

    let output = fx.cmd(&["status", "--cached"]).output().unwrap();

    assert_output_terminal_safe("status --cached", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("h0\u{fffd}]0;PWNED\u{fffd}x"),
        "the stored path should still be named, defanged:\n{stdout}"
    );
}

/// A site's server name, printed by `list-categories --site`, and quoted
/// by the error that lists the known sites when the name matches none,
/// which goes out through the top-level error printer.
#[test]
fn list_categories_and_its_unknown_site_error_print_server_names_terminal_safe() {
    let fx = Fixture::hostile();
    let site = hostile_values().next().unwrap();

    let found = fx
        .cmd(&["list-categories", "--site", &site])
        .output()
        .unwrap();
    assert!(found.status.success(), "{found:?}");
    assert_output_terminal_safe("list-categories --site", &found);

    let unknown = fx
        .cmd(&["list-categories", "--site", "nope.example"])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert_output_terminal_safe("list-categories --site nope.example", &unknown);
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(
        stderr.starts_with("Error: unknown site: nope.example (known: ")
            && stderr.contains("h5real\u{fffd}fakex"),
        "the error should still list the sites, defanged:\n{stderr}"
    );
}

/// `apply-blocks --dry-run` warns about every entry it would leave out of
/// the config, naming the site and quoting the value.
#[test]
fn apply_blocks_dry_run_names_hostile_skipped_entries_terminal_safe() {
    let fx = Fixture::hostile();

    let output = fx
        .cmd(&[
            "apply-blocks",
            "--root",
            fx.nginx_root.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert_output_terminal_safe("apply-blocks --dry-run", &output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: left out of the NGINX config: h0\u{fffd}]0;PWNED\u{fffd}x"),
        "the skipped entries should still be named, defanged:\n{stderr}"
    );
}

/// `batch` prints every step's error with its whole chain, and a step's
/// error quotes what it failed on: here, an NGINX root whose name is
/// [`HOSTILE`], which the site scan cannot find.
#[test]
fn batch_prints_hostile_step_errors_terminal_safe() {
    let fx = Fixture::hostile();
    let root = fx.nginx_root.join(hostile_values().collect::<String>());
    let out = fx.firewall_script();

    let output = fx
        .cmd(&[
            "batch",
            "--no-fetch",
            "--root",
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
            "--access-log",
            "/dev/null",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success(), "the site scan should fail");
    assert_output_terminal_safe("batch", &output);
    let printed = [output.stdout, output.stderr].concat();
    let printed = String::from_utf8_lossy(&printed);
    assert!(
        printed.contains("FAIL") && printed.contains("h0\u{fffd}]0;PWNED\u{fffd}x"),
        "the failing step should still name the root, defanged:\n{printed}"
    );
}

// ---- repeat offenders ----

/// `block-probe-paths` on `log`, against the database at `db`.
fn block_probe_paths(db: &Path, log: &Path) -> assert_cmd::assert::Assert {
    stop_bots_bin()
        .args(["run-detector", "probe-paths", "--db", db.to_str().unwrap()])
        .args(["--access-log", log.to_str().unwrap()])
        .assert()
        .success()
}

/// How long the live block of `address` was made for, in days.
fn days_blocked(db: &Path, address: &str) -> i64 {
    let rules = stop_bots::db::Db::open(db)
        .unwrap()
        .list_firewall_rules()
        .unwrap();
    let rule = rules
        .iter()
        .find(|r| r.address == address)
        .unwrap_or_else(|| panic!("{address} is not blocked; rules: {rules:?}"));
    (rule.expires_at.unwrap() - rule.created_at.unwrap() + 43_200) / 86_400
}

/// Ends every block now, the way its expiry would.
fn let_every_block_lapse(db: &Path) {
    rusqlite::Connection::open(db)
        .unwrap()
        .execute("UPDATE firewall_rules SET expires_at = 1", [])
        .unwrap();
}

#[test]
fn a_second_block_after_the_first_expired_is_longer() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db.sqlite3");
    let log = tmp.path().join("access.log");
    fs::write(&log, access_line("203.0.113.9", "/.env", 404, "curl/8")).unwrap();

    block_probe_paths(&db, &log);
    assert_eq!(days_blocked(&db, "203.0.113.9"), 5, "the first block");
    let_every_block_lapse(&db);

    block_probe_paths(&db, &log).stdout(predicate::str::contains(
        "Added block rule for 203.0.113.9, expiring in 10 day(s), its 2nd offence",
    ));
    assert_eq!(days_blocked(&db, "203.0.113.9"), 10, "the second block");

    stop_bots(&["list-firewall-rules", "--db", db.to_str().unwrap()])
        .stdout(predicate::str::contains("2nd offence"));
}

/// An upgrade never makes a block longer by itself: on a database an
/// earlier release created, the second block is as long as the first
/// until the operator turns repeat offenders on.
#[test]
fn on_an_upgraded_database_repeat_offenders_is_off_until_turned_on() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("db.sqlite3");
    restore_0_0_15(&db);
    let log = tmp.path().join("access.log");
    fs::write(&log, access_line("203.0.113.9", "/.env", 404, "curl/8")).unwrap();
    let db_arg = db.to_str().unwrap();

    stop_bots(&["list-detectors", "--db", db_arg])
        .stdout(predicate::str::contains("Repeat offenders: off (new"));
    block_probe_paths(&db, &log);
    let_every_block_lapse(&db);
    block_probe_paths(&db, &log);
    // The fixture set probe paths to nine days.
    assert_eq!(days_blocked(&db, "203.0.113.9"), 9, "escalated while off");

    stop_bots(&["set-repeat-offenders", "--enabled", "true", "--db", db_arg])
        .stdout(predicate::str::contains("Repeat offenders: on."));
    let_every_block_lapse(&db);
    block_probe_paths(&db, &log);
    assert_eq!(
        days_blocked(&db, "203.0.113.9"),
        36,
        "the third offence, counted while it was off"
    );
}

// ---- `--json` on `status` and every `list-*` ----
//
// The field names are part of the command-line contract, so the shape of
// the two a monitoring script is likeliest to read is pinned in a golden,
// and every other command is checked for the values it should carry.

impl Fixture {
    /// Runs `args --json`, asserting success, and parses what it printed.
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let args = [args, &["--json"]].concat();
        let output = self.cmd(&args).output().unwrap();
        let command = args.join(" ");
        assert!(
            output.status.success(),
            "`{command}` failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        parse_json(&command, &output.stdout)
    }

    /// The database, opened in-process, for setup the CLI would take a
    /// run per row to do.
    fn db(&self) -> stop_bots::db::Db {
        stop_bots::db::Db::open(&self.db).unwrap()
    }
}

/// `stdout` as the one JSON document it should be, failing with what was
/// printed when it is not.
fn parse_json(command: &str, stdout: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(stdout);
    serde_json::from_str(&text).unwrap_or_else(|err| {
        panic!("`{command}` did not print one JSON document ({err}):\n{text}")
    })
}

/// Runs `args --json` and returns what it printed, as printed: a golden
/// pins the order of the fields too, which a parsed value would sort.
fn json_text(fx: &Fixture, args: &[&str]) -> String {
    let args = [args, &["--json"]].concat();
    let output = fx.cmd(&args).output().unwrap();
    assert!(
        output.status.success(),
        "`{}` failed:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    parse_json(&args.join(" "), text.as_bytes());
    text
}

/// Compares the printed `json` with `tests/golden/<name>`, after replacing
/// the times, which change from run to run: every `*_at` field holding an
/// integer, as a Unix time should, becomes `"{UNIX_SECONDS}"`. Anything
/// else that varies the caller replaces first. `UPDATE_GOLDENS=1 cargo
/// test` rewrites the golden, as it does the library's.
fn assert_json_golden(name: &str, json: &str) {
    let actual: String = json
        .split_inclusive('\n')
        .map(|line| {
            let Some((key, value)) = line.split_once("_at\": ") else {
                return line.to_string();
            };
            let digits = value.trim_end_matches(['\n', ',']);
            if digits.parse::<i64>().is_ok() {
                format!("{key}_at\": \"{{UNIX_SECONDS}}\"{}", &value[digits.len()..])
            } else {
                line.to_string()
            }
        })
        .collect();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden file tests/golden/{name} — generate it with UPDATE_GOLDENS=1 cargo test, then review and commit it")
    });
    assert_eq!(
        actual, expected,
        "the JSON no longer matches tests/golden/{name}. A renamed or removed field breaks \
         scripts; an added one is fine — regenerate with UPDATE_GOLDENS=1 cargo test."
    );
}

/// One rule of each kind a script would meet: by hand with a port, an
/// allow, and a detector's, which expires and carries its evidence.
#[test]
fn list_firewall_rules_json_matches_the_golden() {
    use stop_bots::blocks::RuleSource;
    use stop_bots::db::{FirewallAction, NewFirewallRule};
    let fx = Fixture::new();
    let db = fx.db();
    let rule = |address: &str, port, action, source, evidence: Option<&str>| NewFirewallRule {
        address: address.to_string(),
        port,
        action,
        source,
        evidence: evidence.map(str::to_string),
    };
    db.add_firewall_rule(&rule(
        "10.0.0.1",
        Some(22),
        FirewallAction::Block,
        RuleSource::Cli,
        None,
    ))
    .unwrap();
    db.add_firewall_rule(&rule(
        "2001:db8::/64",
        None,
        FirewallAction::Allow,
        RuleSource::Tui,
        None,
    ))
    .unwrap();
    db.add_firewall_rule_with_ttl(
        &rule(
            "198.51.100.7",
            None,
            FirewallAction::Block,
            RuleSource::Detector(stop_bots::protection::Detector::ProbePaths),
            Some("GET /.env HTTP/1.1"),
        ),
        86_400,
    )
    .unwrap();
    drop(db);

    assert_json_golden(
        "list-firewall-rules.json",
        &json_text(&fx, &["list-firewall-rules"]),
    );
}

/// What a monitoring script reads: every check with its level, and the
/// counts. From a stored probe, so the host running the tests does not
/// decide what it says.
#[test]
fn status_json_matches_the_golden() {
    let fx = Fixture::new();
    stop_bots::health::store_probe(&fx.db(), &stop_bots::health::Probe::default()).unwrap();

    let json = json_text(&fx, &["status", "--cached"]);

    // The database's size moves with every schema change.
    let status = parse_json("status", json.as_bytes());
    let size = status["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "database-size")
        .unwrap_or_else(|| panic!("no database-size check:\n{json}"));
    let size = format!("\"detail\": {}", size["detail"]);
    assert_json_golden(
        "status.json",
        &json.replace(&size, "\"detail\": \"{SIZE}\""),
    );
}

/// `--json` changes what is printed, not what the exit status means: a
/// critical check still fails the run, with the reason on stderr, after a
/// whole document on stdout.
#[test]
fn status_json_still_exits_1_when_a_check_is_critical() {
    let fx = Fixture::new();
    fx.run(&["add-firewall-rule", "--address", "10.0.0.1"]);
    let probe = stop_bots::health::Probe {
        live_rules: Some(0),
        ..Default::default()
    };
    stop_bots::health::store_probe(&fx.db(), &probe).unwrap();

    let output = fx.cmd(&["status", "--cached", "--json"]).output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(
        stderr.contains("not protected"),
        "the reason should be on stderr:\n{stderr}"
    );
    let status = parse_json("status --cached --json", &output.stdout);
    assert_eq!(status["summary"]["worst"], "critical", "{status:#}");
    let enforced = status["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "firewall-enforced")
        .unwrap_or_else(|| panic!("no firewall-enforced check:\n{status:#}"));
    assert_eq!(enforced["level"], "critical", "{enforced:#}");
    assert!(enforced["fix"].is_string(), "{enforced:#}");
}

/// An empty list is an empty array, not the sentence the text prints.
#[test]
fn list_firewall_rules_json_with_no_rules_is_an_empty_list() {
    let fx = Fixture::new();

    assert_eq!(
        fx.json(&["list-firewall-rules"]),
        serde_json::json!({ "rules": [] })
    );
}

/// A failure is still an error on stderr with a non-zero exit, and puts
/// nothing on stdout for a script to half-parse.
#[test]
fn a_json_command_that_fails_prints_nothing_on_stdout() {
    let fx = Fixture::new();

    let output = fx
        .cmd(&["list-categories", "--site", "nope.example", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("Error: "), "stderr:\n{stderr}");
}

#[test]
fn list_probe_paths_json_separates_built_in_from_extra() {
    let fx = Fixture::new();
    fx.run(&["set-probe-paths", "--paths", "/secret-admin"]);

    let paths = fx.json(&["list-probe-paths"]);

    assert_eq!(
        paths["extra"],
        serde_json::json!(["/secret-admin"]),
        "{paths:#}"
    );
    assert_eq!(
        paths["built_in"].as_array().map(Vec::len),
        Some(stop_bots::accesslog::DEFAULT_PROBE_PATHS.len()),
        "{paths:#}"
    );
}

/// The conditional paths say, each, whether a request for it is a probe
/// on this host, and if not, which site serves it.
#[test]
fn list_probe_paths_json_says_which_app_paths_are_probes_here() {
    let fx = Fixture::new();
    fx.scan_site_serving("blog.example", &["wp-login.php"]);

    let listed = fx.json(&["list-probe-paths"]);

    let conditional = &listed["conditional"];
    assert_eq!(conditional["enabled"], true, "{conditional:#}");
    let path = |name: &str| {
        conditional["paths"]
            .as_array()
            .and_then(|paths| paths.iter().find(|p| p["path"] == name))
            .cloned()
            .unwrap_or_else(|| panic!("{name} not listed: {conditional:#}"))
    };
    let login = path("/wp-login.php");
    assert_eq!(login["active"], false, "{login:#}");
    assert!(
        login["reason"]
            .as_str()
            .is_some_and(|why| why.starts_with("blog.example: ")),
        "{login:#}"
    );
    assert_eq!(path("/phpmyadmin")["active"], true, "{conditional:#}");
}

#[test]
fn list_probe_paths_explains_each_app_path() {
    let fx = Fixture::new();
    fx.scan_site_serving("static.example", &["index.html"]);

    let out = fx.run(&["list-probe-paths"]).get_output().stdout.clone();

    let out = String::from_utf8_lossy(&out);
    assert!(
        out.contains("Probes for absent apps: on.")
            && out.contains("/wp-login.php   WordPress            probe on this host"),
        "stdout was:\n{out}"
    );
}

/// The one-off detector blocks a WordPress login on a host without
/// WordPress, and never on one with it.
#[test]
fn run_detector_probe_paths_blocks_the_wordpress_login_only_without_wordpress() {
    for (files, blocked) in [(&["index.html"][..], 1), (&["wp-login.php"][..], 0)] {
        let fx = Fixture::new();
        fx.scan_site_serving("example.com", files);
        let log = fx._tmp.path().join("access.log");
        fs::write(
            &log,
            access_line("203.0.113.9", "/wp-login.php", 200, "curl/8"),
        )
        .unwrap();

        fx.run(&[
            "run-detector",
            "probe-paths",
            "--access-log",
            log.to_str().unwrap(),
        ]);

        let rules = stop_bots::db::Db::open(&fx.db)
            .unwrap()
            .list_firewall_rules()
            .unwrap();
        assert_eq!(rules.len(), blocked, "{files:?}: {rules:?}");
    }
}

#[test]
fn set_detector_switches_probes_for_absent_apps() {
    let fx = Fixture::new();

    fx.run(&["set-detector", "probe-paths", "--app-aware", "false"]);

    let listed = fx.json(&["list-probe-paths"]);
    assert_eq!(listed["conditional"]["enabled"], false, "{listed:#}");
    fx.cmd(&["set-detector", "web-scanners", "--app-aware", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("probe-paths only"));
}

#[test]
fn list_detectors_json_carries_each_detector_s_settings() {
    let fx = Fixture::new();
    fx.run(&[
        "set-detector",
        "web-scanners",
        "--enabled",
        "false",
        "--threshold",
        "7",
    ]);

    let listed = fx.json(&["list-detectors"]);

    let detector = |name: &str| {
        listed["detectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("no {name}:\n{listed:#}"))
            .clone()
    };
    let web = detector("web-scanners");
    for (field, expected) in [
        ("enabled", serde_json::json!(false)),
        ("threshold", serde_json::json!(7)),
        ("follows_humans_only", serde_json::json!(false)),
    ] {
        assert_eq!(web[field], expected, "web-scanners {field}:\n{web:#}");
    }
    let robots = detector("robots-txt");
    assert_eq!(robots["follows_humans_only"], true, "{robots:#}");
    assert_eq!(robots["threshold"], serde_json::Value::Null, "{robots:#}");
    assert_eq!(listed["subnet_escalation"]["enabled"], false, "{listed:#}");
    // A database this release created starts with repeat offenders on.
    let repeat = &listed["repeat_offenders"];
    assert_eq!(repeat["enabled"], true, "{repeat:#}");
    assert_eq!(repeat["new_in_this_release"], false, "{repeat:#}");
    assert_eq!(repeat["max_days"], 90, "{repeat:#}");
}

/// `(enabled, new_in_this_release)` of each named detector, as
/// `list-detectors --json` reports them.
fn detector_states(fx: &Fixture, names: &[&str]) -> Vec<(String, bool, bool)> {
    let listed = fx.json(&["list-detectors"]);
    names
        .iter()
        .map(|name| {
            let row = listed["detectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["name"] == *name)
                .unwrap_or_else(|| panic!("no {name}:\n{listed:#}"));
            (
                name.to_string(),
                row["enabled"].as_bool().unwrap(),
                row["new_in_this_release"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// The detectors added after 0.3 follow their own default on a database
/// this release creates, and nothing else marks them new there.
#[test]
fn a_new_database_starts_the_detectors_added_since_0_3_at_their_defaults() {
    let fx = Fixture::new();
    assert_eq!(
        detector_states(&fx, &["login-attempts", "request-rate", "robots-violators"]),
        [
            ("login-attempts".to_string(), true, false),
            ("request-rate".to_string(), false, false),
            ("robots-violators".to_string(), false, false),
        ]
    );
}

/// On a database an earlier release created, an upgrade starts none of
/// them: each is off, and says it is new, until someone chooses.
#[test]
fn an_existing_database_leaves_the_detectors_added_since_0_3_off_and_new() {
    let fx = Fixture::new();
    fx.db()
        .set_int_setting(stop_bots::db::keys::DEFAULTS_GENERATION, 2)
        .unwrap();
    assert_eq!(
        detector_states(&fx, &["login-attempts", "request-rate", "robots-violators"]),
        [
            ("login-attempts".to_string(), false, true),
            ("request-rate".to_string(), false, true),
            ("robots-violators".to_string(), false, true),
        ]
    );
    let listing = fx.run(&["list-detectors"]);
    let out = String::from_utf8_lossy(&listing.get_output().stdout).into_owned();
    assert!(
        out.lines()
            .any(|l| l.starts_with("login-attempts") && l.contains("new in this release")),
        "list-detectors was:\n{out}"
    );
}

/// A password-guesser in a log given by hand, through the real binary.
#[test]
fn run_detector_login_attempts_dry_run_finds_the_password_guesser() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("access.log");
    let post = |ip: &str| {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"POST /wp-login.php HTTP/1.1\" 200 0 \"-\" \
             \"Mozilla/5.0\"\n"
        )
    };
    let lines = [
        post("203.0.113.9").repeat(25),
        post("198.51.100.4").repeat(3),
    ]
    .concat();
    fs::write(&log, lines).unwrap();

    fx.run(&[
        "run-detector",
        "login-attempts",
        "--access-log",
        log.to_str().unwrap(),
        "--dry-run",
    ])
    .stdout(predicate::str::contains("Would add 1 new block rule"))
    .stdout(predicate::str::contains("203.0.113.9"));
    assert!(
        fx.db().list_firewall_rules().unwrap().is_empty(),
        "a dry run wrote a rule"
    );
}

/// A client NGINX's rate limit kept refusing, in a log given by hand.
#[test]
fn run_detector_request_rate_dry_run_finds_the_client_refused_again_and_again() {
    let fx = Fixture::new();
    let log = fx.db.with_file_name("access.log");
    let lines = [
        access_line("203.0.113.9", "/", 429, "Mozilla/5.0").repeat(150),
        access_line("198.51.100.4", "/", 200, "Mozilla/5.0").repeat(20),
    ]
    .concat();
    fs::write(&log, lines).unwrap();

    fx.run(&[
        "run-detector",
        "request-rate",
        "--access-log",
        log.to_str().unwrap(),
        "--dry-run",
    ])
    .stdout(predicate::str::contains("Would add 1 new block rule"))
    .stdout(predicate::str::contains("203.0.113.9"));
}

/// A client that read the generated robots.txt and then went for the trap
/// it publishes, in a log given by hand.
#[test]
fn run_detector_robots_violators_dry_run_finds_the_client_that_ignored_robots_txt() {
    let fx = Fixture::new();
    fx.run(&["set-robots-txt", "--enabled", "true"]);
    let log = fx.db.with_file_name("access.log");
    let lines = [
        access_line("203.0.113.9", "/robots.txt", 200, "Bot"),
        access_line("203.0.113.9", "/stop-bots-trap/x", 404, "Bot"),
        access_line("198.51.100.4", "/stop-bots-trap/x", 404, "Bot"),
    ]
    .concat();
    fs::write(&log, lines).unwrap();

    fx.run(&[
        "run-detector",
        "robots-violators",
        "--access-log",
        log.to_str().unwrap(),
        "--dry-run",
    ])
    .stdout(predicate::str::contains("Would add 1 new block rule"))
    .stdout(predicate::str::contains("203.0.113.9"));
}

#[test]
fn list_access_stats_json_lists_each_user_agent_s_hits() {
    let fx = Fixture::new();
    let hits = [("Mozilla/5.0".to_string(), 3)].into_iter().collect();
    fx.db()
        .record_user_agent_hits(&hits, 1_700_000_000)
        .unwrap();

    let stats = fx.json(&["list-access-stats"]);

    assert_eq!(
        stats,
        serde_json::json!({ "user_agents": [
            { "user_agent": "Mozilla/5.0", "hit_count": 3, "last_seen_at": 1_700_000_000 }
        ] })
    );
}

#[test]
fn list_reputation_sources_json_says_which_are_on_and_what_they_cost() {
    let fx = Fixture::new();
    fx.run(&[
        "set-reputation-source",
        "--source-id",
        "aws",
        "--enabled",
        "true",
    ]);

    let listed = fx.json(&["list-reputation-sources"]);

    let source = |id: &str| {
        listed["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .unwrap_or_else(|| panic!("no {id}:\n{listed:#}"))
            .clone()
    };
    let aws = source("aws");
    assert_eq!(aws["enabled"], true, "{aws:#}");
    assert_eq!(aws["last_fetched_at"], serde_json::Value::Null, "{aws:#}");
    assert!(aws["warning"].is_string(), "a cloud feed warns:\n{aws:#}");
    let firehol = source("firehol-level1");
    assert_eq!(firehol["enabled"], false, "{firehol:#}");
    assert_eq!(firehol["warning"], serde_json::Value::Null, "{firehol:#}");
}

#[test]
fn list_selected_countries_json_names_the_mode_and_the_countries() {
    let fx = Fixture::new();
    fx.run(&[
        "update-country-ranges",
        "--country",
        "nl",
        "--source",
        "tests/fixtures/ipranges/country-sample.zone",
    ]);
    fx.run(&["add-country", "--country", "nl"]);

    assert_eq!(
        fx.json(&["list-selected-countries"]),
        serde_json::json!({ "geo_mode": "blocklist", "countries": ["nl"] })
    );
}

#[test]
fn list_categories_json_shows_a_site_s_overrides_next_to_the_host_wide_policy() {
    let fx = Fixture::new();
    fx.seed_bots();
    fx.write_site("example.com");
    fx.scan_sites();
    fx.run(&[
        "set-category",
        "--category",
        "search",
        "--policy",
        "blocked",
    ]);
    fx.run(&[
        "set-category",
        "--category",
        "ai",
        "--policy",
        "allowed",
        "--site",
        "example.com",
    ]);
    fx.run(&[
        "set-bot",
        "--bot",
        "google-crawler",
        "--policy",
        "allowed",
        "--site",
        "example.com",
    ]);

    let listed = fx.json(&["list-categories", "--site", "example.com"]);

    assert_eq!(
        listed["categories"][1],
        serde_json::json!({ "category": "search", "policy": "blocked" }),
        "{listed:#}"
    );
    assert_eq!(
        listed["site"],
        serde_json::json!({
            "server_name": "example.com",
            "categories": [
                { "category": "scanner", "policy": null },
                { "category": "search", "policy": null },
                { "category": "ai", "policy": "allowed" },
            ],
            "bot_overrides": [{ "bot": "google-crawler", "policy": "allowed" }],
        }),
        "{listed:#}"
    );
}

#[test]
fn list_bots_json_spells_status_as_set_bot_takes_it() {
    let fx = Fixture::new();
    fx.seed_bots();
    fx.run(&["set-bot", "--bot", "ai-search-bot", "--policy", "allowed"]);

    let listed = fx.json(&["list-bots", "--search", "search-bot"]);

    let bots = listed["bots"].as_array().unwrap();
    let bot = bots
        .iter()
        .find(|b| b["slug"] == "ai-search-bot")
        .unwrap_or_else(|| panic!("no ai-search-bot:\n{listed:#}"));
    assert_eq!(bot["status"], "allowed", "{bot:#}");
    assert!(
        bot["categories"].as_array().is_some_and(|c| !c.is_empty()),
        "{bot:#}"
    );
    assert!(
        bots.iter().all(|b| b["slug"] != "google-crawler"),
        "--search still filters:\n{listed:#}"
    );
}

#[test]
fn list_turned_away_json_counts_refused_and_served_per_user_agent() {
    let fx = Fixture::new();
    let log = fx.nginx_root.join("access.log");
    fs::write(
        &log,
        [
            access_line("203.0.113.5", "/", 444, "okhttp/4.9"),
            access_line("203.0.113.5", "/", 444, "okhttp/4.9"),
            access_line("203.0.113.5", "/", 200, "okhttp/4.9"),
        ]
        .concat(),
    )
    .unwrap();
    fx.db()
        .set_block_response(stop_bots::db::BlockResponse::Close)
        .unwrap();

    assert_eq!(
        fx.json(&["list-turned-away", "--access-log", log.to_str().unwrap()]),
        serde_json::json!({
            "block_status": 444,
            "user_agents": [{ "user_agent": "okhttp/4.9", "refused": 2, "served": 1 }],
        })
    );
}

#[test]
fn list_trusted_json_keeps_addresses_and_user_agents_apart() {
    let fx = Fixture::new();
    fx.run(&["add-trusted", "--address", "203.0.113.7"]);
    fx.run(&["add-trusted", "--user-agent", "UptimeRobot"]);

    assert_eq!(
        fx.json(&["list-trusted"]),
        serde_json::json!({ "addresses": ["203.0.113.7"], "user_agents": ["UptimeRobot"] })
    );
}

/// The `--json` twin of the walk above: the same database and log, every
/// command that takes `--json`. What a value carries reaches the terminal
/// as a JSON escape, and a parser reads back exactly what was stored.
#[test]
fn every_json_command_prints_hostile_rows_terminal_safe_and_intact() {
    let fx = Fixture::hostile();
    stop_bots::health::store_probe(&fx.db(), &stop_bots::health::Probe::default()).unwrap();
    let help = fx.cmd(&["--help"]).output().unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    let mut commands: Vec<Vec<&str>> = help
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| word.starts_with("list-"))
        .map(|word| vec![word, "--json"])
        .collect();
    assert!(
        commands.len() >= 10,
        "the walk found too few commands, so --help changed shape: {commands:?}"
    );
    commands.push(vec!["status", "--cached", "--json"]);

    // All at once, as in the walk above.
    let outputs: Vec<_> = std::thread::scope(|scope| {
        let runs: Vec<_> = commands
            .iter()
            .map(|args| {
                let fx = &fx;
                scope.spawn(move || (args.join(" "), fx.cmd(args).output().unwrap()))
            })
            .collect();
        runs.into_iter().map(|run| run.join().unwrap()).collect()
    });
    for (command, output) in &outputs {
        assert_output_terminal_safe(command, output);
        parse_json(command, &output.stdout);
    }

    let (_, rules) = outputs
        .iter()
        .find(|(command, _)| command.starts_with("list-firewall-rules"))
        .unwrap();
    let rules = parse_json("list-firewall-rules --json", &rules.stdout);
    let mut addresses: Vec<String> = rules["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["address"].as_str().unwrap().to_string())
        .collect();
    addresses.sort();
    let mut planted: Vec<String> = hostile_values().collect();
    planted.sort();
    assert_eq!(addresses, planted, "the addresses did not survive intact");
}

// ---- the port-scan detector ----

/// `list-firewall-rules --json`'s rules, by address.
fn rules_by_address(fx: &Fixture) -> std::collections::BTreeMap<String, serde_json::Value> {
    let output = fx.cmd(&["list-firewall-rules", "--json"]).output().unwrap();
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    rules["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| (rule["address"].as_str().unwrap().to_string(), rule.clone()))
        .collect()
}

/// The one-off pass over a kernel log: an address that tried two trap
/// ports or more is blocked, IPv6 by its /64, with the ports it tried as
/// the evidence; one port, a private address and another firewall's lines
/// are not.
#[test]
fn run_detector_port_scanners_blocks_what_tried_two_trap_ports() {
    let fx = Fixture::new();

    fx.run(&[
        "run-detector",
        "port-scanners",
        "--kernel-log",
        "tests/fixtures/logs/kern.log",
    ]);

    let rules = rules_by_address(&fx);
    let blocked: Vec<&String> = rules.keys().collect();
    assert_eq!(
        blocked,
        ["198.51.100.20", "2001:db8::/64"],
        "rules were: {rules:#?}"
    );
    let scanner = &rules["198.51.100.20"];
    assert_eq!(
        scanner["evidence"], "new connections to trap ports 23, 445, 3389",
        "{scanner:#}"
    );
    assert_eq!(scanner["source"], "port-scanners", "{scanner:#}");
}

#[test]
fn run_detector_port_scanners_reads_the_kernel_log_and_nothing_else() {
    let fx = Fixture::new();
    fx.cmd(&[
        "run-detector",
        "port-scanners",
        "--access-log",
        "tests/fixtures/logs/kern.log",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains(
        "port-scanners reads the kernel log: give --kernel-log, not --access-log",
    ));
}

/// A `ss` that reports MySQL on every address and Redis on loopback only.
fn fake_ss(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("ss-bin");
    fs::create_dir_all(&bin).unwrap();
    let ss = bin.join("ss");
    fs::write(
        &ss,
        "#!/bin/sh\n\
         echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'\n\
         echo 'LISTEN 0 151 0.0.0.0:3306 0.0.0.0:*'\n\
         echo 'LISTEN 0 4096 127.0.0.1:6379 0.0.0.0:*'\n",
    )
    .unwrap();
    fs::set_permissions(&ss, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

/// Switched on, the next render traps the configured ports, less what
/// listens beyond loopback; switched off, the script has no trap at all.
#[test]
fn the_rendered_firewall_traps_what_nothing_listens_on() {
    let fx = Fixture::new();
    let bin = fake_ss(fx._tmp.path());
    let out = fx._tmp.path().join("firewall.nft");
    let render = || {
        fx.cmd(&[
            "render-firewall",
            "--backend",
            "nftables",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("PATH", path_with(&bin))
        .assert()
        .success();
        fs::read_to_string(&out).unwrap()
    };

    let off = render();
    fx.run(&["set-detector", "port-scanners", "--enabled", "true"]);
    let on = render();

    assert!(!off.contains("dport"), "a trap while off:\n{off}");
    let drop = on
        .lines()
        .find(|line| line.ends_with(" counter drop"))
        .unwrap_or_else(|| panic!("no trap:\n{on}"));
    let checks = [
        ("traps telnet", drop.contains("{ 23, ")),
        (
            "traps Redis, which listens on loopback only",
            drop.contains(" 6379,"),
        ),
        ("not MySQL, which listens", !drop.contains("3306")),
        ("says why", on.contains("sshd does: 3306.")),
    ];
    for (what, holds) in checks {
        assert!(holds, "{what}:\n{on}");
    }
}

/// The trap ports are a setting: never SSH, HTTP or HTTPS, and `default`
/// goes back to the built-in list. `list-detectors --json` reports them.
#[test]
fn set_detector_sets_the_trap_ports_and_refuses_ssh() {
    let fx = Fixture::new();
    let trap_ports = || {
        let output = fx.cmd(&["list-detectors", "--json"]).output().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        json["trap_ports"].clone()
    };

    fx.cmd(&["set-detector", "port-scanners", "--ports", "23,22"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("22 cannot be a trap port"));
    fx.run(&["set-detector", "port-scanners", "--ports", "2323, 23"])
        .stdout(predicate::str::contains(
            "Trap ports (port-scanners): 23, 2323;",
        ));
    assert_eq!(trap_ports()["ports"], serde_json::json!([23, 2323]));
    assert_eq!(trap_ports()["default"], false);

    fx.run(&["set-detector", "port-scanners", "--ports", "default"]);
    assert_eq!(trap_ports()["default"], true);
    fx.cmd(&["set-detector", "ssh-scanners", "--ports", "23"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "only port-scanners has trap ports",
        ));
}
