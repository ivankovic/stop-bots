//! End-to-end happy-path test for the db + nginx + bot-list CLI flow:
//! update-bot-lists -> scan-sites -> apply-blocks, run against a throwaway
//! copy of the NGINX fixtures. No network access is used.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

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

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "scan-sites",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Discovered 2 site(s)"));

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
    assert!(example_com.contains("# BEGIN stop-bots"));
    assert!(example_com.contains("AISearchBot"));
    // The search-engine and unknown-category bots default to allowed, so
    // only the AI bot's pattern should show up in the generated rule.
    assert!(!example_com.contains("Googlebot"));

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
        .success();

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "scan-sites",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Discovered 2 site(s)"));

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
        .success();

    let a = fs::read_to_string(&file_a).unwrap();
    let b = fs::read_to_string(&file_b).unwrap();
    // file_a's site overrides Search to Blocked: the search-engine bot's
    // pattern should show up there.
    assert!(a.contains("Googlebot"));
    // file_b's same-named site has no override of its own and must not
    // pick up file_a's — it follows the global default (Search allowed).
    // It still gets a block, just for the AI bot (blocked by default),
    // not the search-engine one.
    assert!(!b.contains("Googlebot"));
    assert!(b.contains("AISearchBot"));
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

    let site = nginx_root.join("site.conf");
    fs::write(
        &site,
        "server {\n    listen 80;\n    server_name a.example;\n}\n",
    )
    .unwrap();

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
        .success();
    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "scan-sites",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let apply = |db_path: &Path, root: &Path| {
        Command::cargo_bin("stop-bots")
            .unwrap()
            .args([
                "apply-blocks",
                "--root",
                root.to_str().unwrap(),
                "--db",
                db_path.to_str().unwrap(),
                "--no-reload",
            ])
            .assert()
            .success();
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
    assert!(written.contains("return 444;"));
    assert!(!written.contains("return 403;"));
}

/// Spoofed-crawler detection end to end, including the property that
/// matters most: it does nothing at all until crawler ranges are fetched.
#[test]
fn block_spoofed_crawlers_is_inert_without_ranges_then_blocks_a_forged_googlebot() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let access_log = tmp.path().join("access.log");

    let line = |ip: &str, ua: &str| {
        format!("{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{ua}\"\n")
    };
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
    assert!(script.contains("-A STOP-BOTS -s 1.2.3.4 -j DROP"));
    assert!(script.contains("-A STOP-BOTS -s 66.249.64.0/19 -j ACCEPT"));
    // This is the safety property that matters most: the script must never
    // touch chains/policies outside our own dedicated STOP-BOTS chain.
    assert!(!script.contains("*filter"));
    assert!(!script.contains("COMMIT"));

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
    assert!(stderr.contains("4.5.6.7"));
    assert!(stderr.contains("Refusing to write"));
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
    assert!(stderr.contains("4.5.6.7"));
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
    assert!(script.contains("ip saddr 4.5.6.7 accept"));
    assert!(script.contains("ip saddr 0.0.0.0/0 drop"));
    assert!(script.contains("ip6 saddr ::/0 drop"));
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
    assert!(!permanent_line.contains("expires"));
    assert!(temporary_line.contains("expires in"));
}
