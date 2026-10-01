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

//! The root helper, driven over a real socket in this process: its
//! protocol, its equivalence with the in-process executor, and what a
//! hostile database can and cannot make it do.
//!
//! Each test starts a real `helper::Server` on a socket in a temp directory
//! (see `common::HelperHost`), answering this process's own user. Nothing
//! here needs root: the host settings point NGINX's test and reload at
//! `true` or at scripts of the test's own, and the firewall script at the
//! temp directory, with nothing loaded for real.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{block_a_bot, own_uid, write_script, HelperHost, HELPER_SITE};
use stop_bots::privileged::{Op, Privileged, Reply, WebAccessMode};

/// Sends `bytes` as they are and returns the helper's answer, raw.
fn raw(socket: &Path, bytes: &[u8]) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let _ = stream.write_all(bytes);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}

fn helper(socket: &Path) -> Privileged {
    Privileged::Helper(socket.to_path_buf())
}

async fn run(privileged: &Privileged, op: Op) -> Result<Reply, String> {
    privileged.run(op).await.map_err(|err| format!("{err:#}"))
}

// ---- the protocol ----

#[test]
fn an_operation_it_does_not_know_is_refused() {
    let host = HelperHost::new();
    let socket = host.serve();

    let answer = raw(&socket, b"\"Shell\"\n");

    assert!(answer.starts_with(r#"{"Err":"#), "answer was: {answer}");
    assert!(answer.contains("unknown variant"), "answer was: {answer}");
}

/// The fields are exactly the operation's: one more, however harmless it
/// looks, refuses the whole request rather than being ignored.
#[test]
fn a_field_it_does_not_know_is_refused() {
    let host = HelperHost::new();
    let socket = host.serve();

    let answer = raw(
        &socket,
        br#"{"ApplyNginx":{"site":null,"reload":false,"root":"/etc"}}"#,
    );

    assert!(answer.contains("unknown field"), "answer was: {answer}");
    assert_eq!(
        std::fs::read_to_string(&host.site).unwrap(),
        HELPER_SITE,
        "nothing was applied"
    );
}

#[test]
fn a_request_over_the_size_limit_is_refused_unread() {
    let host = HelperHost::new();
    let socket = host.serve();
    let mut huge = br#"{"Preview":{"diff":false}}"#.to_vec();
    huge.extend(std::iter::repeat_n(
        b' ',
        stop_bots::helper::MAX_REQUEST + 1,
    ));
    huge.push(b'\n');

    let answer = raw(&socket, &huge);

    assert!(answer.contains("larger than"), "answer was: {answer}");
}

/// Half a request, and then nothing: the connection is answered and closed
/// at the deadline, rather than held for as long as the client likes.
#[test]
fn a_request_that_never_finishes_arriving_is_given_up_on() {
    let host = HelperHost::new();
    let socket = host.serve_with(stop_bots::helper::Config {
        request_deadline: Duration::from_millis(150),
        ..host.config(vec![own_uid()])
    });
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(br#"{"Preview":"#).unwrap();

    let started = std::time::Instant::now();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();

    assert!(
        answer.contains("did not arrive in time"),
        "answer was: {answer}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

/// The socket's mode is what lets the console's group in; the peer check
/// is what keeps everyone else in that group out. A uid it does not
/// answer gets the connection closed without a word.
#[test]
fn a_peer_that_is_neither_root_nor_the_console_is_refused() {
    let host = HelperHost::new();
    let socket = host.serve_with(host.config(vec![0, own_uid().wrapping_add(1)]));

    let answer = raw(&socket, br#"{"ApplyNginx":{"site":null,"reload":false}}"#);
    assert_eq!(answer, "", "a stranger was answered");

    let err = stop_bots::helper::call(&socket, &Op::ScanSites).unwrap_err();
    assert!(
        format!("{err:#}").contains("closed the connection without answering"),
        "{err:#}"
    );
    assert_eq!(std::fs::read_to_string(&host.site).unwrap(), HELPER_SITE);
}

/// One operation at a time, however many clients ask at once. Each Web
/// Access request runs the configured `nginx -t`, which here notes when it
/// starts and ends and takes a moment in between: served one at a time,
/// no start ever comes before the previous end.
#[tokio::test]
async fn concurrent_clients_are_served_one_at_a_time() {
    let host = HelperHost::new();
    let log = host.dir.path().join("tests.log");
    let check = host.dir.path().join("check");
    write_script(
        &check,
        &format!(
            "echo start >> {log}\nsleep 0.05\necho end >> {log}\n",
            log = log.display()
        ),
    );
    stop_bots::hostconf::HostConf {
        nginx_test_command: Some(check.display().to_string()),
        ..stop_bots::hostconf::HostConf::load_from(&host.host_conf).unwrap()
    }
    .save_to(&host.host_conf)
    .unwrap();
    let socket = host.serve();

    let mut clients = Vec::new();
    for n in 0..4 {
        let client = helper(&socket);
        clients.push(tokio::spawn(async move {
            client
                .web_access(Op::WebAccess {
                    mode: WebAccessMode::Subdomain,
                    site_id: None,
                    prefix: String::new(),
                    host: format!("console{n}.example.com"),
                    reload: false,
                })
                .await
        }));
    }
    for client in clients {
        client.await.unwrap().unwrap();
    }

    let log = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 8, "log was:\n{log}");
    for pair in lines.chunks(2) {
        assert_eq!(pair, ["start", "end"], "two ran at once; log was:\n{log}");
    }
}

/// A request that waits past the deadline for its turn is told the helper
/// is busy, and is never run afterwards: whoever asked has been told no.
/// The first request here takes longer than the deadline; the second asks
/// while it runs.
#[tokio::test]
async fn a_request_that_waits_too_long_for_its_turn_is_refused_and_never_run() {
    let host = HelperHost::new();
    let log = host.dir.path().join("tests.log");
    let check = host.dir.path().join("check");
    write_script(
        &check,
        &format!(
            "echo start >> {log}\nsleep 0.4\necho end >> {log}\n",
            log = log.display()
        ),
    );
    stop_bots::hostconf::HostConf {
        nginx_test_command: Some(check.display().to_string()),
        ..stop_bots::hostconf::HostConf::load_from(&host.host_conf).unwrap()
    }
    .save_to(&host.host_conf)
    .unwrap();
    let socket = host.serve_with(stop_bots::helper::Config {
        op_deadline: Duration::from_millis(150),
        ..host.config(vec![own_uid()])
    });
    let console = |name: &str| Op::WebAccess {
        mode: WebAccessMode::Subdomain,
        site_id: None,
        prefix: String::new(),
        host: format!("{name}.example.com"),
        reload: false,
    };

    let first = tokio::spawn({
        let client = helper(&socket);
        let op = console("first");
        async move { client.web_access(op).await }
    });
    while !std::fs::read_to_string(&log).is_ok_and(|log| log.contains("start")) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = helper(&socket).web_access(console("second")).await;
    let first = first.await.unwrap();

    let second = format!("{:#}", second.unwrap_err());
    assert!(second.contains("nothing was done"), "{second}");
    assert!(
        format!("{:#}", first.unwrap_err()).contains("did not finish"),
        "the first outran its deadline"
    );
    // The first finishes in its own time; the second never starts.
    while !std::fs::read_to_string(&log).is_ok_and(|log| log.contains("end")) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "start\nend\n");
    let written = std::fs::read_to_string(stop_bots::nginx::console_site_path(&host.root)).unwrap();
    assert!(written.contains("first.example.com"), "{written}");
}

// ---- the same outcome in process and through the helper ----

/// Two identical hosts, one driven in process and one through the helper:
/// each operation must answer the same and leave the same files, once the
/// two hosts' own directories are taken out of the comparison.
struct Pair {
    local: HelperHost,
    remote: HelperHost,
    socket: PathBuf,
}

impl Pair {
    fn new(seed: impl Fn(&HelperHost)) -> Self {
        let (local, remote) = (HelperHost::new(), HelperHost::new());
        seed(&local);
        seed(&remote);
        let socket = remote.serve();
        Pair {
            local,
            remote,
            socket,
        }
    }

    /// `op` both ways, compared.
    async fn same(&self, op: Op) -> Result<Reply, String> {
        let here = run(&self.local.local(), op.clone()).await;
        let there = run(&helper(&self.socket), op.clone()).await;
        let (here_text, there_text) = (format!("{here:?}"), self.as_local(&format!("{there:?}")));
        assert_eq!(here_text, there_text, "{op:?} answered differently");
        assert_eq!(
            files(self.local.dir.path()),
            files(self.remote.dir.path())
                .into_iter()
                .map(|(path, text)| (path, self.as_local(&text)))
                .collect::<Vec<_>>(),
            "{op:?} left different files"
        );
        here
    }

    fn as_local(&self, text: &str) -> String {
        text.replace(
            &self.remote.dir.path().display().to_string(),
            &self.local.dir.path().display().to_string(),
        )
    }
}

/// Every file under `dir` but the database and the sockets, by its path
/// relative to `dir`, with its contents.
fn files(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut found: Vec<(PathBuf, String)> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy();
            !name.starts_with("db.sqlite3")
        })
        .map(|entry| {
            (
                entry.path().strip_prefix(dir).unwrap().to_path_buf(),
                std::fs::read_to_string(entry.path()).unwrap_or_default(),
            )
        })
        .collect();
    found.sort();
    found
}

/// A blocked bot, so an apply has something to write.
fn with_a_blocked_bot(host: &HelperHost) {
    block_a_bot(&host.open_db(), "BadBot");
}

fn scanned(host: &HelperHost) {
    with_a_blocked_bot(host);
    let db = host.open_db();
    db.upsert_site("example.com", host.site.to_str().unwrap())
        .unwrap();
}

#[tokio::test]
async fn scanning_is_the_same_both_ways() {
    let pair = Pair::new(with_a_blocked_bot);
    assert_eq!(
        pair.same(Op::ScanSites).await,
        Ok(Reply::Scanned { found: 1 })
    );
}

#[tokio::test]
async fn site_statuses_are_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let reply = pair.same(Op::SiteStatuses).await.unwrap();
    assert!(
        matches!(&reply, Reply::SiteStatuses(s) if s.len() == 1),
        "{reply:?}"
    );
}

#[tokio::test]
async fn applying_every_site_is_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let reply = pair
        .same(Op::ApplyNginx {
            site: None,
            reload: true,
        })
        .await
        .unwrap();
    assert!(
        matches!(&reply, Reply::AppliedAll(outcome) if outcome.changed > 0),
        "{reply:?}"
    );
    assert!(std::fs::read_to_string(&pair.remote.site)
        .unwrap()
        .contains("BadBot"));
}

#[tokio::test]
async fn applying_one_site_is_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let id = pair.local.open_db().list_sites().unwrap()[0].id;
    let reply = pair
        .same(Op::ApplyNginx {
            site: Some(id),
            reload: true,
        })
        .await
        .unwrap();
    assert!(
        matches!(&reply, Reply::AppliedSite { changed: true, .. }),
        "{reply:?}"
    );
}

#[tokio::test]
async fn the_preview_is_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let reply = pair.same(Op::Preview { diff: true }).await.unwrap();
    let Reply::Preview(summary) = reply else {
        panic!("{reply:?}");
    };
    assert!(
        summary
            .diff
            .as_deref()
            .unwrap_or_default()
            .contains("BadBot"),
        "{summary:?}"
    );
}

#[tokio::test]
async fn writing_the_firewall_is_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let reply = pair
        .same(Op::Firewall {
            apply: false,
            protect: vec![],
        })
        .await
        .unwrap();
    assert!(
        matches!(&reply, Reply::Firewall(report) if report.succeeded),
        "{reply:?}"
    );
    assert!(stop_bots::firewall::rendered_path(&pair.remote.firewall).exists());
}

/// And the refusal is the same: the address the console says is in use is
/// protected wherever the guard runs.
#[tokio::test]
async fn a_protected_address_refuses_the_firewall_both_ways() {
    let pair = Pair::new(scanned);
    let reply = pair
        .same(Op::Firewall {
            apply: true,
            protect: vec!["192.0.2.10".parse().unwrap()],
        })
        .await
        .unwrap();
    let Reply::Firewall(report) = reply else {
        panic!("{reply:?}");
    };
    assert!(!report.succeeded, "{report:?}");
    assert!(report.summary.contains("192.0.2.10"), "{report:?}");
}

#[tokio::test]
async fn web_access_is_the_same_both_ways() {
    let pair = Pair::new(scanned);
    let id = pair.local.open_db().list_sites().unwrap()[0].id;
    let reply = pair
        .same(Op::WebAccess {
            mode: WebAccessMode::Path,
            site_id: Some(id),
            prefix: "/stop-bots/".into(),
            host: String::new(),
            reload: true,
        })
        .await
        .unwrap();
    assert!(matches!(&reply, Reply::WebAccess(_)), "{reply:?}");
    assert!(std::fs::read_to_string(&pair.remote.site)
        .unwrap()
        .contains("location \"/stop-bots/\""));
}

// ---- a hostile database ----
//
// Rows written straight into the database, as a compromised console could
// write them, and then an operation asked for through the helper.

/// After migration the commands are the host settings' alone: a row
/// naming another command is never read, let alone run.
#[tokio::test]
async fn a_reload_command_row_runs_nothing_but_the_file_s_command() {
    let host = HelperHost::new();
    scanned(&host);
    let pwned = host.dir.path().join("pwned");
    let ran = host.dir.path().join("ran");
    let (check, reload) = (
        host.dir.path().join("check"),
        host.dir.path().join("reload"),
    );
    write_script(&check, &format!("echo test >> {}\n", ran.display()));
    write_script(&reload, &format!("echo reload >> {}\n", ran.display()));
    stop_bots::hostconf::HostConf {
        nginx_test_command: Some(check.display().to_string()),
        nginx_reload_command: Some(reload.display().to_string()),
        ..stop_bots::hostconf::HostConf::load_from(&host.host_conf).unwrap()
    }
    .save_to(&host.host_conf)
    .unwrap();
    {
        let db = host.open_db();
        let touch = format!("touch {}", pwned.display());
        for key in [
            stop_bots::db::keys::NGINX_TEST_COMMAND,
            stop_bots::db::keys::NGINX_RELOAD_COMMAND,
        ] {
            db.set_text_setting(key, &touch).unwrap();
        }
    }
    let socket = host.serve_with(stop_bots::helper::Config {
        settings: stop_bots::privileged::Settings {
            for_real: true,
            ..host.settings()
        },
        ..host.config(vec![own_uid()])
    });

    let applied = helper(&socket).apply_all(true).await.unwrap();

    assert!(applied.reloaded, "{applied:?}");
    assert!(!pwned.exists(), "a command from the database ran");
    assert_eq!(
        std::fs::read_to_string(&ran).unwrap(),
        "test\nreload\n",
        "the host settings' commands are what ran"
    );
}

/// A root row pointing somewhere else changes nothing: the root is the
/// host settings'.
#[tokio::test]
async fn a_root_row_is_ignored() {
    let host = HelperHost::new();
    scanned(&host);
    let elsewhere = tempfile::tempdir().unwrap();
    let decoy = elsewhere.path().join("decoy.conf");
    std::fs::write(&decoy, HELPER_SITE).unwrap();
    host.open_db()
        .set_text_setting(
            stop_bots::db::keys::NGINX_ROOT,
            elsewhere.path().to_str().unwrap(),
        )
        .unwrap();
    let socket = host.serve();

    helper(&socket).apply_all(true).await.unwrap();

    assert_eq!(std::fs::read_to_string(&decoy).unwrap(), HELPER_SITE);
    assert!(std::fs::read_to_string(&host.site)
        .unwrap()
        .contains("BadBot"));
}

/// A site row's path is never a path to write: the site applied is the
/// file found under the root for that name.
#[tokio::test]
async fn a_site_row_pointing_outside_the_root_is_not_written() {
    let host = HelperHost::new();
    with_a_blocked_bot(&host);
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.conf");
    std::fs::write(&victim, HELPER_SITE).unwrap();
    let id = {
        let db = host.open_db();
        db.upsert_site("example.com", victim.to_str().unwrap())
            .unwrap();
        db.list_sites().unwrap()[0].id
    };
    let socket = host.serve();

    let (_, changed, _) = helper(&socket).apply_site(id, true).await.unwrap();

    assert!(changed);
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        HELPER_SITE,
        "the file the row named was written"
    );
    assert!(std::fs::read_to_string(&host.site)
        .unwrap()
        .contains("BadBot"));

    // And Web Access, which writes a `location` into a site, the same.
    helper(&socket)
        .web_access(Op::WebAccess {
            mode: WebAccessMode::Path,
            site_id: Some(id),
            prefix: "/stop-bots/".into(),
            host: String::new(),
            reload: false,
        })
        .await
        .unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), HELPER_SITE);
}

/// A name with no file under the root is refused, wherever its row says it
/// is.
#[tokio::test]
async fn a_site_row_for_a_name_not_under_the_root_is_refused() {
    let host = HelperHost::new();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim.conf");
    let other = "server {\n    server_name victim.example;\n}\n";
    std::fs::write(&victim, other).unwrap();
    let id = {
        let db = host.open_db();
        db.upsert_site("victim.example", victim.to_str().unwrap())
            .unwrap();
        db.list_sites().unwrap()[0].id
    };
    let socket = host.serve();

    let err = helper(&socket).apply_site(id, true).await.unwrap_err();

    assert!(format!("{err:#}").contains("re-scan"), "{err:#}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), other);
}

/// `managed_files` rows naming files outside the managed directories —
/// directly, through a link, or by climbing out — delete nothing, even
/// with this project's header in the file.
#[tokio::test]
async fn managed_files_rows_outside_the_managed_directories_delete_nothing() {
    let host = HelperHost::new();
    scanned(&host);
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("stop-bots-limits.conf");
    let generated = stop_bots::nginx::rate_limit_conf_body(10, 10);
    std::fs::write(&victim, &generated).unwrap();
    let link = host.root.join("conf.d/stop-bots-trusted.conf");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let climbing = host
        .root
        .join("conf.d/../../..")
        .join(elsewhere.path().strip_prefix("/").unwrap())
        .join("stop-bots-limits.conf");
    {
        let db = host.open_db();
        for (path, kind) in [
            (victim.clone(), stop_bots::nginx::ManagedKind::Limits),
            (link.clone(), stop_bots::nginx::ManagedKind::Trusted),
            (climbing, stop_bots::nginx::ManagedKind::Limits),
            (
                PathBuf::from("/etc/passwd"),
                stop_bots::nginx::ManagedKind::Limits,
            ),
        ] {
            db.record_managed_file(&path, kind.id()).unwrap();
        }
    }
    let socket = host.serve();

    helper(&socket).apply_all(true).await.unwrap();

    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        generated,
        "a file outside the managed directories was deleted or written"
    );
    assert!(Path::new("/etc/passwd").exists());
}

/// What a row holds is rendered only once it passes the validation that
/// applies at render time: a bot pattern carrying NGINX syntax, written
/// straight into the table, writes no directive of its own.
#[tokio::test]
async fn a_hostile_pattern_row_writes_nothing_of_its_own() {
    let host = HelperHost::new();
    scanned(&host);
    {
        let db = host.open_db();
        block_a_bot(&db, "x\") { return 200; } error_log /tmp/pwned; if (\"");
        let id = db.list_sites().unwrap()[0].id;
        // Exemptions are validated where they are stored; this is the row
        // a compromised console writes past that.
        let conn = rusqlite::Connection::open(&host.db).unwrap();
        conn.execute(
            "INSERT INTO site_path_exemptions (site_id, path) VALUES (?1, ?2)",
            rusqlite::params![id, "/a\"; } location / { return 200; } #"],
        )
        .unwrap();
    }
    let socket = host.serve();

    helper(&socket).apply_all(true).await.unwrap();

    let written = std::fs::read_to_string(&host.site).unwrap();
    assert!(written.contains("BadBot"), "{written}");
    for smuggled in ["error_log", "return 200", "/tmp/pwned"] {
        assert!(!written.contains(smuggled), "{smuggled} landed:\n{written}");
    }
}
