//! End-to-end happy-path test for the TUI, driven through a real pty (via
//! `rexpect`) since `ratatui::init()` requires one — `assert_cmd` alone
//! can't exercise this, it has no pty. Covers: launch -> open/confirm a
//! category popup right on the Dashboard -> Bot settings shows the seeded
//! source and opens its update-confirmation popup -> quit.

use assert_cmd::Command as AssertCommand;
use rexpect::session::{spawn_command, PtySession};
use rexpect::ReadUntil;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::Command;

const TIMEOUT_MS: u64 = 5_000;

/// Spawns `stop-bots tui --db <db_path>` in a pty sized large enough for the
/// UI to actually draw into. `rexpect`/the kernel default a freshly opened
/// pty to a 0x0 window size, which makes every widget render into a
/// zero-area `Rect` (nothing visible, ever) — so the size must be set
/// explicitly via `TIOCSWINSZ` right after spawning, before the child's
/// first draw.
fn spawn_tui(db_path: &Path) -> PtySession {
    spawn_tui_with_args(db_path, &[])
}

/// Like [`spawn_tui`], but also passes `--root <root>` — needed for tests
/// that trigger a site scan from Site settings against a controlled fixture
/// directory rather than the real `/etc/nginx`.
fn spawn_tui_with_root(db_path: &Path, root: &Path) -> PtySession {
    spawn_tui_with_args(db_path, &["--root", root.to_str().unwrap()])
}

fn spawn_tui_with_args(db_path: &Path, extra_args: &[&str]) -> PtySession {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stop-bots"));
    cmd.args(["tui", "--db", db_path.to_str().unwrap()]);
    cmd.args(extra_args);
    cmd.env("TERM", "xterm-256color");

    let session = spawn_command(cmd, Some(TIMEOUT_MS)).expect("failed to spawn stop-bots tui");
    set_window_size(&session, 30, 100);
    session
}

fn set_window_size(session: &PtySession, rows: u16, cols: u16) {
    let file = session
        .process()
        .get_file_handle()
        .expect("failed to get pty file handle");
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
    assert_eq!(result, 0, "failed to set pty window size");
}

/// Sends a raw key sequence (no implicit newline) and flushes it, so the
/// child sees it immediately even when it doesn't itself end in `\n`.
fn send_key(session: &mut PtySession, keys: &str) {
    session.send(keys).unwrap();
    session.flush().unwrap();
}

/// Sends a bare Escape, separated from whatever comes next by a short
/// pause. crossterm's raw-mode parser briefly buffers a lone ESC byte to
/// see whether it's the start of an Alt-modified key (ESC immediately
/// followed by a character) or a standalone Escape press; sending the next
/// key right behind it risks exactly that misparse — e.g. Esc+`d` arriving
/// as one `Alt+d` event, which a popup's key handler then silently
/// swallows (any key other than the few it recognizes is just consumed),
/// leaving the popup open and the rest of the test waiting forever.
fn send_escape(session: &mut PtySession) {
    send_key(session, "\x1b");
    std::thread::sleep(std::time::Duration::from_millis(100));
}

/// Waits for `anchor` (e.g. a row label like "Scanners") and then for the
/// `[ ALLOWED ]`/`[ BLOCKED ]` tag that immediately follows it, returning
/// which one matched.
///
/// Use this right after switching to a screen (a fresh full redraw, so the
/// label genuinely retransmits), not after a same-screen update — terminal
/// output is diffed, so once a label has been drawn once, redrawing only
/// the cell that changed (e.g. just the tag) never retransmits it again,
/// and `exp_string(anchor)` would hang waiting for text that's already on
/// screen but isn't coming down the wire a second time. On a freshly
/// switched-to screen, plain `exp_string("ALLOWED")` isn't specific enough
/// either: "Search Bots" is allowed by default, so that text is on screen
/// regardless of whether the row actually being tested changed. Anchoring
/// to the label first is what makes the assertion specific to that row.
fn expect_status_after(session: &mut PtySession, anchor: &str) -> &'static str {
    session.exp_string(anchor).unwrap();
    let (_, matched) = session
        .exp_any(vec![
            ReadUntil::String("[ ALLOWED ]".to_string()),
            ReadUntil::String("[ BLOCKED ]".to_string()),
        ])
        .unwrap();
    if matched.contains("ALLOWED") {
        "ALLOWED"
    } else {
        "BLOCKED"
    }
}

#[test]
fn navigate_change_a_setting_and_quit() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    // Seed one bot-list source (no network access) so the Bot settings
    // screen below has a source row to show.
    AssertCommand::cargo_bin("stop-bots")
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

    let mut session = spawn_tui(&db_path);

    // Dashboard is the default screen. Scanners starts out Blocked, and is
    // the first row, already selected.
    session.exp_string("Dashboard").unwrap();
    assert_eq!(expect_status_after(&mut session, "Scanners"), "BLOCKED");

    // Open the popup for the selected row (Scanners) right on the
    // Dashboard — category defaults are edited here now, not on Bot
    // settings. (Checked as two separate substrings, not the literal
    // "Scanners default": the terminal output is diffed against the
    // previous frame, and the space between the two words happens to land
    // on a cell that was already blank, so the diff skips re-sending it —
    // splitting the space out of the match avoids depending on that.)
    send_key(&mut session, "\r");
    session.exp_string("Scanners").unwrap();
    session.exp_string("default").unwrap();
    session.exp_string("Allowed").unwrap();
    session.exp_string("Blocked").unwrap();

    // Move up to "Allowed" and confirm; the popup closes and the row
    // updates immediately, on the same screen.
    send_key(&mut session, "\x1b[A");
    send_key(&mut session, "\r");
    session.exp_string("[ ALLOWED ]").unwrap();
    session.exp_string("set").unwrap();
    session.exp_string("to").unwrap();
    session.exp_string("Allowed").unwrap();

    // Bot settings now shows bot-list sources (not categories): all three
    // known sources (App::new registers them all on startup, regardless of
    // which one was actually fetched), plus the known bots.
    send_key(&mut session, "b");
    session.exp_string("sources").unwrap();
    session.exp_string("ArcJet").unwrap();
    session.exp_string("bots").unwrap();
    session.exp_string("4").unwrap();

    // Enter on the selected source row opens an update-confirmation popup,
    // not an immediate fetch. "ai-robots-txt" sorts first alphabetically
    // among the three known source ids, so it's the one selected by
    // default here, not the seeded ArcJet one.
    send_key(&mut session, "\r");
    session.exp_string("Update").unwrap();
    session.exp_string("ai.robots.txt").unwrap();
    session.exp_string("Cancel").unwrap();
    session.exp_string("Update").unwrap();
    session.exp_string("now").unwrap();

    // Cancel rather than confirm: this test must not touch the network.
    send_escape(&mut session);

    // Back to the Dashboard: the category change made earlier must still
    // be visible here — this is exactly the cross-screen refresh that was
    // broken until the `Mutated` outcome was introduced.
    send_key(&mut session, "d");
    assert_eq!(expect_status_after(&mut session, "Scanners"), "ALLOWED");

    // Quit from the Dashboard.
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

#[test]
fn bot_settings_shows_the_known_sources_before_any_fetch_has_ever_run() {
    // No `update-bot-lists` seeding step here, unlike the test above: a
    // brand-new install's DB has no rows in `sources` at all. Without
    // `App::new` registering every known source on startup, the Bot
    // settings screen would render an empty list with nothing to select and
    // no way to trigger a first fetch from the TUI.
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "b");
    session.exp_string("sources").unwrap();
    // All three known sources show up, not just whichever was last used —
    // checked in the order they actually render (sorted by id:
    // "ai-robots-txt" < "nginx-bad-bots" < "well-known-bots"), since
    // `exp_string` only ever scans forward through the stream.
    session.exp_string("ai.robots.txt").unwrap();
    session
        .exp_string("Nginx Ultimate Bad Bot Blocker")
        .unwrap();
    session.exp_string("ArcJet").unwrap();
    session.exp_string("never updated").unwrap();

    // The selected row (ai.robots.txt, sorted first by id) is selectable
    // and its "Update now" option still works, even though the source has
    // never been fetched.
    send_key(&mut session, "\r");
    session.exp_string("Update").unwrap();
    session.exp_string("ai.robots.txt").unwrap();
    session.exp_string("Cancel").unwrap();

    send_escape(&mut session);

    // `q` on Bot settings backs out to the Dashboard; a second `q`, now on
    // the Dashboard, actually quits. Anchored on "wide" (System-wide
    // settings), not "Dashboard": the tab label reads "Dashboard" already
    // while on Bot settings (just unbolded), so the diffed terminal output
    // never re-sends that exact text — "wide" only appears once we're
    // actually back.
    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

#[test]
fn bot_details_search_filters_by_name_and_opens_a_bot_popup() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    // Seed four bots (no network access) so there's something to search.
    AssertCommand::cargo_bin("stop-bots")
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

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "b");
    session.exp_string("Bot details").unwrap();

    // Before typing anything, the panel just hints at the search box rather
    // than dumping every bot — that's the whole point of this screen.
    session.exp_string("Press").unwrap();
    session.exp_string("search").unwrap();

    // "jyxo" uniquely matches "Jyxo Crawler" among the seeded bots, and
    // isn't a substring of anything else already on screen (the source
    // name, "Bot list sources", etc.) — picked so the diffed terminal
    // output can't skip retransmitting it by coincidence (see SPECS.md's
    // note on that gotcha in this test file).
    send_key(&mut session, "/");
    send_key(&mut session, "jyxo");
    session.exp_string("Jyxo Crawler").unwrap();

    // The row itself always carries a "(system)" or "(override)" tag, not
    // just the popup — jyxo-crawler has no category (its source fixture
    // tags it "unknown"), so it's untouched, still following the system
    // default.
    session.exp_string("(system)").unwrap();

    // Enter on the (only) match opens its override popup.
    send_key(&mut session, "\r");
    session.exp_string("Override").unwrap();
    session.exp_string("jyxo-crawler").unwrap();
    session.exp_string("Use system settings").unwrap();
    session.exp_string("Allowed").unwrap();
    session.exp_string("Blocked").unwrap();

    // Cancel via Escape rather than confirm: this test isn't about the
    // override write path, which is already covered by unit tests.
    send_escape(&mut session);

    // Escape again leaves the search box (query preserved) without backing
    // all the way out to the Dashboard. There's no new text to anchor on for
    // that transition (only a border color changes) — proved indirectly
    // instead: if focus hadn't actually returned to the sources panel, the
    // `q` below would be swallowed as literal search-query text (Bot
    // details treats every printable key as query text while focused)
    // rather than backing out to the Dashboard, and the next `exp_string`
    // would time out.
    send_escape(&mut session);

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

#[test]
fn site_settings_scan_now_discovers_sites_from_the_tui() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    // No `scan-sites` seeding step: the db starts with zero sites, and the
    // scan is triggered entirely from the TUI below. `--root` points at the
    // static fixture directory `tests/cli.rs` also uses (2 discoverable
    // sites: "localhost" and "example.com") — read-only, so pointing
    // straight at it rather than copying is fine.
    let root = Path::new("tests/fixtures/nginx");
    let mut session = spawn_tui_with_root(&db_path, root);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    session.exp_string("Press").unwrap();
    session.exp_string("scan").unwrap();

    // `r` opens a Cancel/Scan-now confirmation popup, same as Bot
    // settings' source-update popup — even though there's nothing in the
    // sites list yet, this is exactly the bootstrap case it exists for.
    // (Not Enter: that now opens a site's detail view instead, once one
    // exists — see site_detail_search_and_override_a_site_from_the_tui.)
    send_key(&mut session, "r");
    session.exp_string("Scan").unwrap();
    session.exp_string("Cancel").unwrap();
    // Checked as "now" alone, not the literal "Scan now": the popup title
    // ("Scan <root>?") already sent "Scan" moments earlier, so re-anchoring
    // on that exact word risks the terminal-output-diffing coincidence
    // documented in SPECS.md/this file's other tests.
    session.exp_string("now").unwrap();

    send_key(&mut session, "\x1b[B"); // Cancel -> Scan now
    send_key(&mut session, "\r");

    // The scan ran synchronously (no async fetch involved, unlike bot-list
    // sources): the discovered site appears immediately.
    session.exp_string("example.com").unwrap();

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// Recursively copies `src` into `dst`, creating `dst` and any
/// intermediate directories as needed. Used to get a writable copy of the
/// (checked-in, read-only) NGINX fixtures for tests that actually write to
/// disk — mirrors `tests/cli.rs`'s own `copy_dir_all`, not shared with it
/// since these are two separate test binaries.
fn copy_dir_all(src: &Path, dst: &Path) {
    for entry in walkdir::WalkDir::new(src)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = entry.path().strip_prefix(src).unwrap();
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
        } else {
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
fn site_settings_apply_writes_the_selected_sites_rule_to_its_own_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &nginx_root);

    // Seed bots (AISearchBot is AI, blocked by the global default with no
    // overrides at all) and scan the writable fixture copy, entirely via
    // the CLI — the apply itself is what this test drives through the TUI.
    AssertCommand::cargo_bin("stop-bots")
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
    AssertCommand::cargo_bin("stop-bots")
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

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    // Nothing's been applied to disk yet, but a rule is expected (the
    // global AI default blocks AISearchBot with no overrides needed).
    session.exp_string("STALE").unwrap();

    // "example.com" sorts first and is selected by default. `a` opens a
    // Cancel/Apply-now popup, same shape as `r`'s scan popup.
    send_key(&mut session, "a");
    session
        .exp_string("Apply blocking rules to example.com")
        .unwrap();
    session.exp_string("Cancel").unwrap();
    session.exp_string("now").unwrap();

    send_key(&mut session, "\x1b[B"); // Cancel -> Apply now
    send_key(&mut session, "\r");
    session.exp_string("UP TO DATE").unwrap();

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Belt-and-suspenders: the file itself carries the rule, and only
    // example.com's block — localhost's file must be untouched since it
    // was never applied.
    let example_com_conf =
        std::fs::read_to_string(nginx_root.join("sites-enabled/example.com")).unwrap();
    assert!(example_com_conf.contains("AISearchBot"));

    let localhost_conf = std::fs::read_to_string(nginx_root.join("conf.d/server.conf")).unwrap();
    assert!(!localhost_conf.contains("AISearchBot"));
}

#[test]
fn site_settings_apply_all_writes_the_rule_to_every_sites_own_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &nginx_root);

    AssertCommand::cargo_bin("stop-bots")
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
    AssertCommand::cargo_bin("stop-bots")
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

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    session.exp_string("STALE").unwrap();

    // Shift+A opens a Cancel/Apply-now popup covering both discovered
    // sites at once, distinct from `a`'s single-site popup.
    send_key(&mut session, "A");
    session
        .exp_string("Apply blocking rules to all 2 site(s)")
        .unwrap();

    send_key(&mut session, "\x1b[B"); // Cancel -> Apply now
    send_key(&mut session, "\r");
    session.exp_string("UP TO DATE").unwrap();

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Both files, not just one, got the rule this time.
    let example_com_conf =
        std::fs::read_to_string(nginx_root.join("sites-enabled/example.com")).unwrap();
    assert!(example_com_conf.contains("AISearchBot"));
    let localhost_conf = std::fs::read_to_string(nginx_root.join("conf.d/server.conf")).unwrap();
    assert!(localhost_conf.contains("AISearchBot"));
}

#[test]
fn site_settings_apply_failure_shows_a_dismissible_alert_with_a_root_suggestion() {
    // Root bypasses file permission bits, so chmod-ing the file read-only
    // below wouldn't actually make the write fail there.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: running as root, permission bits are unenforced");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let nginx_root = tmp.path().join("nginx");
    copy_dir_all(Path::new("tests/fixtures/nginx"), &nginx_root);

    AssertCommand::cargo_bin("stop-bots")
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
    AssertCommand::cargo_bin("stop-bots")
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

    // Make example.com's config file read-only, simulating running the
    // TUI without the privileges nginx's own config directory normally
    // requires.
    let example_com_path = nginx_root.join("sites-enabled/example.com");
    let mut perms = std::fs::metadata(&example_com_path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o444);
    std::fs::set_permissions(&example_com_path, perms).unwrap();

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    session.exp_string("STALE").unwrap();

    send_key(&mut session, "a");
    session
        .exp_string("Apply blocking rules to example.com")
        .unwrap();
    send_key(&mut session, "\x1b[B"); // Cancel -> Apply now
    send_key(&mut session, "\r");

    session.exp_string("Apply failed").unwrap();
    session.exp_string("Try running as root").unwrap();

    // Dismiss the alert and quit. Not re-asserting "STALE" reappears here:
    // the alert's own text and the row's tag can share individual
    // characters at the same screen positions, which risks the same
    // terminal-output-diffing coincidence documented elsewhere in this
    // file (only a differing tail retransmits) — the file-content check
    // below is a more reliable way to confirm the write really didn't
    // happen.
    send_key(&mut session, "\r");

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Belt-and-suspenders: the file must be completely untouched by the
    // failed write attempt, not partially modified.
    let example_com_conf = std::fs::read_to_string(&example_com_path).unwrap();
    assert!(!example_com_conf.contains("AISearchBot"));
}

#[test]
fn site_detail_search_and_override_a_site_from_the_tui() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");

    // Seed 4 bots (jyxo-crawler among them, tagged "unknown" — no category
    // flags at all) and both fixture sites via the CLI; the detail view
    // itself is driven entirely through the TUI below.
    AssertCommand::cargo_bin("stop-bots")
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
    AssertCommand::cargo_bin("stop-bots")
        .unwrap()
        .args([
            "scan-sites",
            "--root",
            "tests/fixtures/nginx",
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    // "example.com" sorts before "localhost" and is selected by default.
    session.exp_string("example.com").unwrap();

    // Enter drills into the selected site's detail view rather than
    // opening the rescan popup (that's `r` now — see the test above).
    send_key(&mut session, "\r");
    session.exp_string("categories").unwrap();

    // Move to the Search Bots row (index 1) and override it to Blocked —
    // Search defaults to Allowed globally, so this is a visible flip, and
    // unrelated to the bot override exercised below.
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\r");
    session.exp_string("Use system default").unwrap();
    session.exp_string("Allowed").unwrap();
    session.exp_string("Blocked").unwrap();
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B"); // Use system default -> Allowed -> Blocked
    send_key(&mut session, "\r");
    // Checked as "override)" alone, not the literal "(site override)": the
    // row previously read "(system)", which shares its leading "(s" with
    // "(site override)" — the terminal-output-diffing gotcha documented
    // above means only the differing tail actually retransmits.
    session.exp_string("override)").unwrap();

    // Search for a bot with no category flags at all: overriding it
    // specifically (independent of the category override above) proves
    // the per-bot path works on its own.
    send_key(&mut session, "/");
    send_key(&mut session, "jyxo");
    session.exp_string("Jyxo Crawler").unwrap();

    send_key(&mut session, "\r");
    session.exp_string("Use site & system default").unwrap();
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B"); // -> Blocked
    send_key(&mut session, "\r");
    // Checked as "override)" alone, not the literal "(site override)": the
    // row previously read "(system)", which shares its leading "(s" with
    // "(site override)" — the terminal-output-diffing gotcha documented
    // above means only the differing tail actually retransmits.
    session.exp_string("override)").unwrap();

    // Leave the search box, then back all the way out of the detail view.
    send_escape(&mut session);
    send_escape(&mut session);

    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Belt-and-suspenders: confirm both writes actually landed in the db,
    // not just that the right text was rendered.
    let db = stop_bots::db::Db::open(&db_path).unwrap();
    let example_com = db
        .list_sites()
        .unwrap()
        .into_iter()
        .find(|s| s.server_name == "example.com")
        .unwrap();
    assert_eq!(
        db.get_site_category_override(example_com.id, stop_bots::db::Category::Search)
            .unwrap(),
        Some(stop_bots::db::Policy::Blocked)
    );
    let jyxo_bot = db
        .list_bots()
        .unwrap()
        .into_iter()
        .find(|b| b.slug == "jyxo-crawler")
        .unwrap();
    let jyxo_override = db
        .site_bot_overrides(example_com.id)
        .unwrap()
        .into_iter()
        .find(|o| o.bot_id == jyxo_bot.id)
        .map(|o| o.policy);
    assert_eq!(jyxo_override, Some(stop_bots::db::Policy::Blocked));
}

#[test]
fn help_screen_opens_and_returns_to_the_previous_screen() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();

    send_key(&mut session, "?");
    session.exp_string("Navigation").unwrap();
    session.exp_string("toggle this help screen").unwrap();

    // Esc on Help goes back to Site settings, not the Dashboard.
    send_key(&mut session, "\x1b");
    session.exp_string("Sites").unwrap();

    // `q` on a non-Dashboard screen backs out to the Dashboard rather than
    // quitting; only a second `q`, now on the Dashboard, actually quits.
    // (Anchored on "wide", not "System-wide": the leading "S" lands on the
    // same cell the previous screen's "Sites" title left a coincidentally
    // identical "S", so the diffed terminal output never re-sends it.)
    send_key(&mut session, "q");
    session.exp_string("wide").unwrap();
    session.exp_string("settings").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}
