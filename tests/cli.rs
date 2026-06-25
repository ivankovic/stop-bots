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
