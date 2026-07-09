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

    Command::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "apply-blocks",
            "--root",
            nginx_root.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
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

    // Without --force: refuses, warns twice, writes nothing.
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
    assert_eq!(stderr.matches("WARNING").count(), 2);
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
        db.set_country_blocked("xx", true).unwrap();
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
