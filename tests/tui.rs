//! End-to-end happy-path test for the TUI, driven through a real pty (via
//! `rexpect`) since `ratatui::init()` requires one — `assert_cmd` alone
//! can't exercise this, it has no pty. Covers: launch -> Bot settings ->
//! open/confirm a category popup -> Dashboard reflects the change -> quit.

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
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));

    // Dashboard is the default screen. Scanners starts out Blocked.
    session.exp_string("Dashboard").unwrap();
    assert_eq!(expect_status_after(&mut session, "Scanners"), "BLOCKED");

    // Switch to Bot settings.
    send_key(&mut session, "b");
    session.exp_string("Categories & bots").unwrap();

    // Open the popup for the first row (Scanners, currently Blocked).
    send_key(&mut session, "\r");
    session.exp_string("Scanners default").unwrap();
    session.exp_string("Allowed").unwrap();
    session.exp_string("Blocked").unwrap();

    // Move up to "Allowed" and confirm; the popup closes and the row
    // updates immediately. (Plain `exp_string`, not anchored on "Scanners",
    // is correct here: terminal output is diffed, so on this same,
    // already-drawn screen only the cell that actually changed — this
    // row's tag — gets retransmitted. Search Bots' tag was already
    // consumed earlier and won't reappear since it didn't change.)
    send_key(&mut session, "\x1b[A");
    send_key(&mut session, "\r");
    session.exp_string("[ ALLOWED ]").unwrap();

    // Back to the Dashboard: the change (and a status message about it)
    // must be visible here too — this is exactly the cross-screen refresh
    // that was broken until the `Mutated` outcome was introduced. (Without
    // that fix this would still find "ALLOWED" on screen regardless, since
    // Search Bots is allowed by default — anchoring to the "Scanners" label
    // specifically is what makes this check meaningful.)
    send_key(&mut session, "d");
    assert_eq!(expect_status_after(&mut session, "Scanners"), "ALLOWED");
    session
        .exp_string("Scanners default set to Allowed")
        .unwrap();

    // Quit from the Dashboard.
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
    send_key(&mut session, "q");
    session.exp_string("Overview").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}
