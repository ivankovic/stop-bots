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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stop-bots"));
    cmd.args(["tui", "--db", db_path.to_str().unwrap()]);
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

    // Bot settings now shows bot-list sources (not categories): the seeded
    // source, with its signal count, plus the known bots.
    send_key(&mut session, "b");
    session.exp_string("sources").unwrap();
    session.exp_string("ArcJet").unwrap();
    session.exp_string("bots").unwrap();
    session.exp_string("4").unwrap();

    // Enter on the source row opens an update-confirmation popup, not an
    // immediate fetch.
    send_key(&mut session, "\r");
    session.exp_string("Update").unwrap();
    session.exp_string("ArcJet").unwrap();
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
fn bot_settings_shows_the_known_source_before_any_fetch_has_ever_run() {
    // No `update-bot-lists` seeding step here, unlike the test above: a
    // brand-new install's DB has no rows in `sources` at all. Without
    // `App::new` registering the well-known-bots source on startup, the Bot
    // settings screen would render an empty list with nothing to select and
    // no way to trigger a first fetch from the TUI.
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "b");
    session.exp_string("sources").unwrap();
    session.exp_string("ArcJet").unwrap();
    session.exp_string("never updated").unwrap();

    // The row is selectable and its "Update now" option still works, even
    // though the source has never been fetched.
    send_key(&mut session, "\r");
    session.exp_string("Update").unwrap();
    session.exp_string("ArcJet").unwrap();
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
