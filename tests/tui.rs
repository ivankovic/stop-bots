//! End-to-end happy-path test for the TUI, driven through a real pty (via
//! `rexpect`) since `ratatui::init()` requires one — `assert_cmd` alone
//! can't exercise this, it has no pty. Covers: launch -> open/confirm a
//! category popup right on the Dashboard -> Bot settings shows the seeded
//! source and opens its update-confirmation popup -> quit.

use assert_cmd::Command as AssertCommand;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---- pty harness ----
//
// A deliberately small pty driver, in-repo, instead of a pty crate. The
// specific reason: rexpect (used previously) sleeps a fixed 100ms between
// polls inside `expect`, so every expectation that doesn't match on the
// very first read pays up to a 100ms quantum — and these tests make six to
// twenty expectations each, which put a hard floor of over a second under
// every test regardless of how fast the application actually was (first
// draw: ~150ms; a keystroke round-trip: single-digit ms). Owning the loop
// makes the poll interval 2ms and the harness fully inspectable.

struct PtySession {
    master: File,
    child: Child,
    /// Everything read from the pty and not yet consumed by a match. An
    /// expectation consumes the buffer up to and including its needle, so
    /// successive expectations scan strictly forward through the output —
    /// the same semantics the tests were written against.
    buf: String,
    timeout: Duration,
}

fn spawn_in_pty(mut cmd: Command, rows: u16, cols: u16, timeout: Duration) -> PtySession {
    let mut master_fd: libc::c_int = 0;
    let mut slave_fd: libc::c_int = 0;
    // The window size is set at open. A fresh pty defaults to 0x0, which
    // makes every ratatui widget render into a zero-area Rect — nothing
    // visible, ever — so this must happen before the child's first draw.
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null(),
            &winsize,
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    let master = unsafe { File::from_raw_fd(master_fd) };
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    unsafe {
        cmd.pre_exec(|| {
            // New session, and make the pty slave (already dup'ed onto
            // stdin by the time pre_exec closures run) the controlling
            // terminal, so the child's /dev/tty resolves to our pty.
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0);
            Ok(())
        });
    }
    let child = cmd.spawn().expect("failed to spawn in pty");
    PtySession {
        master,
        child,
        buf: String::new(),
        timeout,
    }
}

impl PtySession {
    /// Drains whatever the child has written so far into `buf`. Returns
    /// whether the stream has ended (EOF, or EIO — which is how Linux
    /// reports "the last slave handle closed" to the master side).
    fn read_available(&mut self) -> bool {
        let mut tmp = [0u8; 65536];
        loop {
            match self.master.read(&mut tmp) {
                Ok(0) => return true,
                Ok(n) => self.buf.push_str(&String::from_utf8_lossy(&tmp[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                Err(_) => return true,
            }
        }
    }

    fn consume_through(&mut self, pos: usize, len: usize) {
        self.buf.drain(..pos + len);
    }

    /// Waits until `needle` appears in the output, consuming through it.
    pub fn exp_string(&mut self, needle: &str) -> Result<(), String> {
        self.exp_any(&[needle]).map(|_| ())
    }

    /// Waits until the earliest of `needles` appears, consuming through it
    /// and returning the one that matched.
    pub fn exp_any(&mut self, needles: &[&str]) -> Result<String, String> {
        let start = Instant::now();
        loop {
            let eof = self.read_available();
            let earliest = needles
                .iter()
                .filter_map(|n| self.buf.find(n).map(|pos| (pos, *n)))
                .min_by_key(|(pos, _)| *pos);
            if let Some((pos, matched)) = earliest {
                self.consume_through(pos, matched.len());
                return Ok(matched.to_string());
            }
            if eof {
                return Err(format!(
                    "stream ended while waiting for {needles:?}; unconsumed output: {:?}",
                    tail(&self.buf)
                ));
            }
            if start.elapsed() > self.timeout {
                return Err(format!(
                    "timed out ({:?}) waiting for {needles:?}; unconsumed output: {:?}",
                    self.timeout,
                    tail(&self.buf)
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Waits for the child to close its side of the pty and exit.
    pub fn exp_eof(&mut self) -> Result<(), String> {
        let start = Instant::now();
        loop {
            if self.read_available() {
                let _ = self.child.wait();
                return Ok(());
            }
            if start.elapsed() > self.timeout {
                return Err(format!(
                    "timed out ({:?}) waiting for the process to exit",
                    self.timeout
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn send(&mut self, keys: &str) -> Result<(), String> {
        self.master
            .write_all(keys.as_bytes())
            .and_then(|()| self.master.flush())
            .map_err(|e| format!("failed to write to pty: {e}"))
    }
}

/// A child left running after a panicking test would outlive the test
/// binary and hold the pty open; kill it. Killing an already-exited child
/// is a harmless error.
impl Drop for PtySession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The last part of the unconsumed buffer, for failure messages — enough
/// to see what the screen actually said without dumping kilobytes of
/// escape sequences.
fn tail(buf: &str) -> &str {
    &buf[buf.len().saturating_sub(600)..]
}

/// How long an `exp_string` waits before declaring failure.
///
/// This is a *ceiling on waiting*, not a budget the tests spend: a passing
/// expectation returns the moment the text arrives, so raising it costs
/// nothing on the happy path and only slows down a genuine failure.
///
/// It used to be 5s, which was long enough on an idle machine and not long
/// enough on a busy one — several test binaries competing for CPU could push a
/// redraw past the deadline and fail on output that did arrive. That produced
/// roughly one spurious failure per two runs of this suite, with a different
/// test each time, which is the worst possible signal: a suite that cries wolf
/// is how a real regression gets waved through. 30s is far past any plausible
/// redraw latency while still bounding a hung child.
///
/// `STOP_BOTS_TEST_TIMEOUT_MS` overrides it, for bisecting a real hang without
/// waiting 30s a time.
fn timeout_ms() -> u64 {
    std::env::var("STOP_BOTS_TEST_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000)
}

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

/// Marks every internal-cron job as freshly run, so the TUI under test
/// never starts background work of its own. On a brand-new database every
/// job is due immediately, so without this each pty test silently kicked
/// off three real HTTP fetches (crawler IP ranges) and a `journalctl`
/// subprocess in the background — a network and system dependency nothing
/// here asserts on, and part of the fixed cost every test in this file
/// used to carry. Seeding goes through the real `Db` interface, not a
/// test-only knob in the product.
fn seed_cron_state(db_path: &Path) {
    let db = stop_bots::db::Db::open(db_path).expect("failed to open the test db");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for job in stop_bots::cron::CronJob::all() {
        db.set_cron_last_run(job.id(), now, "skipped for test")
            .expect("failed to seed cron state");
    }
}

fn spawn_tui_with_args(db_path: &Path, extra_args: &[&str]) -> PtySession {
    seed_cron_state(db_path);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stop-bots"));
    // `--no-reload`: some of these tests drive a real Site settings apply
    // through this real spawned process, and without this it would shell
    // out to the real `nginx -t`/`systemctl reload nginx` on whatever
    // machine runs the test suite (see `main.rs`'s `apply-blocks
    // --no-reload`, the same escape hatch for the CLI's own apply path).
    cmd.args(["tui", "--db", db_path.to_str().unwrap(), "--no-reload"]);
    // A fixture SSH log, for the same reason the CLI tests pass --ssh-log:
    // auto-detection reads whatever log the host machine has — or shells
    // out to `journalctl`, which costs upwards of half a second per
    // Dynamic Protection refresh on some hosts and made every test in this
    // file carry that as fixed overhead.
    cmd.args(["--ssh-log", "tests/fixtures/logs/auth.log"]);
    cmd.args(extra_args);
    cmd.env("TERM", "xterm-256color");

    spawn_in_pty(cmd, 32, 100, Duration::from_millis(timeout_ms()))
}

/// Like [`spawn_tui`], but *without* `--no-reload` and with `fakebin`
/// prepended to the child's PATH — for tests that exercise the code paths
/// which really execute external tools (`nft -f`, `nginx -t`,
/// `systemctl`), against fake executables rather than by skipping the
/// execution. `--no-reload` is the escape hatch that avoids running the
/// tools at all; this is the opposite: run them, and control what they
/// resolve to.
fn spawn_tui_with_fake_tools(db_path: &Path, fakebin: &Path) -> PtySession {
    spawn_tui_with_fake_tools_and_args(db_path, fakebin, &[])
}

/// [`spawn_tui_with_fake_tools`] plus extra arguments — for the one test
/// that needs both a fake `nginx`/`systemctl` on PATH *and* a `--root`
/// pointing at a writable fixture tree, so it can drive a real Site
/// settings apply all the way through to the reload it triggers.
fn spawn_tui_with_fake_tools_and_args(
    db_path: &Path,
    fakebin: &Path,
    extra_args: &[&str],
) -> PtySession {
    seed_cron_state(db_path);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stop-bots"));
    cmd.args(["tui", "--db", db_path.to_str().unwrap()]);
    cmd.args(extra_args);
    cmd.args(["--ssh-log", "tests/fixtures/logs/auth.log"]);
    cmd.env("TERM", "xterm-256color");
    cmd.env(
        "PATH",
        format!(
            "{}:{}",
            fakebin.display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );
    spawn_in_pty(cmd, 32, 100, Duration::from_millis(timeout_ms()))
}

/// Sends a raw key sequence (no implicit newline); the pty write is
/// unbuffered, so the child sees it immediately.
fn send_key(session: &mut PtySession, keys: &str) {
    session.send(keys).unwrap();
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
    let matched = session.exp_any(&["[ ALLOWED ]", "[ BLOCKED ]"]).unwrap();
    if matched.contains("ALLOWED") {
        "ALLOWED"
    } else {
        "BLOCKED"
    }
}

/// Asserts on raw escape bytes rather than on rendered text, because the
/// bug this covers is invisible in the rendered text: ratatui diffs each
/// frame against the previous one, and the very first frame is diffed
/// against a buffer that is already blank, so none of the frame's blank
/// cells are ever transmitted. On a terminal that honours the
/// alternate-screen request that is harmless. On one that ignores it, the
/// shell's scrollback stays put and shows through every gap in the first
/// frame — the report that prompted this test. `run_tui` clears explicitly
/// to force a full first repaint; these two sequences, in this order, are
/// what that looks like on the wire.
#[test]
fn startup_enters_the_alternate_screen_and_clears_it_before_drawing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));

    session
        .exp_string("\x1b[?1049h")
        .expect("the TUI should enter the alternate screen");
    // `exp_string` only scans forward, so finding this after the sequence
    // above is also an assertion that the clear comes second.
    session
        .exp_string("\x1b[2J")
        .expect("the TUI should clear the screen before its first frame");
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// The SSH panel is filled from a background read now, so it arrives a
/// moment after the screen does. Nothing else in the suite watches that
/// panel through a real terminal, which makes this the one place a broken
/// hand-off would show up: the screen would simply stay empty, and every
/// unit test would still pass.
#[test]
fn the_ssh_panel_fills_in_from_the_background_log_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "p");
    // Short needles on purpose. Switching screens redraws over the
    // Dashboard, and ratatui skips any cell that already holds the right
    // character — so a long literal arrives split around whatever the two
    // screens happen to have in common at the same column. "Failed SSH"
    // is exactly that: its "e" lands on the "e" of "System-wide" and the
    // run is cut in two.
    session.exp_string("logins").unwrap();
    // The fixture log that `spawn_tui` passes via --ssh-log has two failed
    // attempts from this address, and an accepted login from another that
    // must not appear: this panel ranks failures.
    session.exp_string("203.0.113.50").unwrap();

    send_key(&mut session, "q");
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
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
    session.exp_string("Automatic").unwrap();
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
    session.exp_string("details").unwrap();

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
    session.exp_string("Automatic").unwrap();
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
    session.exp_string("Automatic").unwrap();
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

/// Sets up a TUI over a writable copy of the NGINX fixture tree, with a
/// fake `nginx` and a fake `systemctl` on PATH — the two tools a Site
/// settings apply really executes.
///
/// The fake `systemctl` parks until the returned gate file is deleted,
/// which is what lets the two tests below assert on *ordering* instead of
/// on timing: they can hold a reload open for as long as they need and
/// still finish in milliseconds. `nginx -t` stays instant, since `reload`
/// runs it first and gives up if it fails.
///
/// Returns the temp dir (which must outlive the session), the session, the
/// log every fake appends its argv to, and the gate.
fn site_tui_with_a_holdable_reload() -> (tempfile::TempDir, PtySession, PathBuf, PathBuf) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

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

    let fakebin = tmp.path().join("bin");
    fs::create_dir_all(&fakebin).unwrap();
    let calls = tmp.path().join("calls.log");
    let gate = tmp.path().join("gate");
    fs::write(&gate, "").unwrap();
    let scripts = [
        ("nginx", String::new()),
        (
            "systemctl",
            format!("while [ -e \"{}\" ]; do sleep 0.02; done\n", gate.display()),
        ),
    ];
    for (tool, wait) in scripts {
        let path = fakebin.join(tool);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\n{wait}echo \"{tool} $@\" >> \"{}\"\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let session = spawn_tui_with_fake_tools_and_args(
        &db_path,
        &fakebin,
        &["--root", nginx_root.to_str().unwrap()],
    );
    (tmp, session, calls, gate)
}

/// Waits for `calls.log` to hold at least `want` lines mentioning
/// `systemctl`, and returns it. Polling rather than sleeping: the wait is
/// on a background task, on a machine whose load the test does not
/// control.
fn wait_for_systemctl_calls(calls: &Path, want: usize) -> String {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms());
    loop {
        let log = std::fs::read_to_string(calls).unwrap_or_default();
        if log.matches("systemctl reload nginx").count() >= want {
            return log;
        }
        assert!(
            Instant::now() < deadline,
            "expected {want} systemctl call(s); calls.log held: {log:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Selects the site named `name` in Site settings' list and applies it.
/// The list is sorted by server name, and the selection starts at the top.
fn apply_site(session: &mut PtySession, name: &str) {
    send_key(session, "a");
    session.exp_string("Cancel").unwrap();
    send_key(session, "\x1b[B"); // Cancel -> Apply now
    send_key(session, "\r");
    let _ = name;
}

/// The reload NGINX needs after an apply runs in the background now, so
/// the TUI stays live through it.
///
/// Asserted by *ordering*, not by timing: the fake `systemctl` parks on a
/// gate file, and the TUI has to switch screens and draw while it is still
/// parked. A synchronous reload cannot do that — the keypress would sit in
/// the queue until `systemctl` returned, so the Dashboard would arrive
/// after the call was logged, not before. No sleeps, and nothing that gets
/// slower on a loaded machine.
#[test]
fn applying_a_site_reloads_nginx_without_blocking_the_tui() {
    let (_tmp, mut session, calls, gate) = site_tui_with_a_holdable_reload();
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();
    apply_site(&mut session, "example.com");

    // The apply's own result lands immediately, with the reload still out.
    session.exp_string("UP").unwrap();
    // And the TUI keeps taking input while it is: jump to the Dashboard
    // and watch it draw, with `systemctl` still parked on the gate.
    send_key(&mut session, "d");
    session.exp_string("Automatic").unwrap();

    let so_far = std::fs::read_to_string(&calls).unwrap_or_default();
    assert!(
        !so_far.contains("systemctl"),
        "the reload should still be running -- the TUI answered a keypress \
         while it was, which is the point. calls.log held: {so_far:?}"
    );

    std::fs::remove_file(&gate).unwrap();
    let log = wait_for_systemctl_calls(&calls, 1);
    assert!(
        log.contains("nginx -t"),
        "the config must be validated before the reload; calls.log was: {log:?}"
    );

    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// Applying a second site while the first site's reload is still running
/// must not lose the second reload.
///
/// Only one reload runs at a time, and the obvious way to enforce that —
/// drop the request if one is already out — is wrong here: this is a
/// write-then-act pair, so the act has to happen at least once after the
/// last write. Dropping it leaves NGINX serving the old config for the
/// second site with nothing on screen saying so. The bug is silent, which
/// is what makes it worth its own test.
#[test]
fn a_second_apply_during_a_reload_still_gets_its_own_reload() {
    let (_tmp, mut session, calls, gate) = site_tui_with_a_holdable_reload();
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();

    // Both applies happen while the gate holds the first reload open, so
    // the second one is necessarily requested mid-flight.
    apply_site(&mut session, "example.com");
    session.exp_string("UP").unwrap();
    send_key(&mut session, "\x1b[B"); // next site in the list
    apply_site(&mut session, "localhost");
    session.exp_string("UP").unwrap();

    std::fs::remove_file(&gate).unwrap();
    wait_for_systemctl_calls(&calls, 2);

    send_key(&mut session, "q");
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
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
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Belt-and-suspenders: the file itself carries the rule, and only
    // example.com's block — localhost's file must be untouched since it
    // was never applied.
    let example_com_conf =
        std::fs::read_to_string(nginx_root.join("sites-enabled/example.com")).unwrap();
    assert!(
        example_com_conf.contains("AISearchBot"),
        "example_com_conf was:\n{example_com_conf}"
    );

    let localhost_conf = std::fs::read_to_string(nginx_root.join("conf.d/server.conf")).unwrap();
    assert!(
        !localhost_conf.contains("AISearchBot"),
        "localhost_conf was:\n{localhost_conf}"
    );
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
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Both files, not just one, got the rule this time.
    let example_com_conf =
        std::fs::read_to_string(nginx_root.join("sites-enabled/example.com")).unwrap();
    assert!(
        example_com_conf.contains("AISearchBot"),
        "example_com_conf was:\n{example_com_conf}"
    );
    let localhost_conf = std::fs::read_to_string(nginx_root.join("conf.d/server.conf")).unwrap();
    assert!(
        localhost_conf.contains("AISearchBot"),
        "localhost_conf was:\n{localhost_conf}"
    );
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
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");

    // Belt-and-suspenders: the file must be completely untouched by the
    // failed write attempt, not partially modified.
    let example_com_conf = std::fs::read_to_string(&example_com_path).unwrap();
    assert!(
        !example_com_conf.contains("AISearchBot"),
        "example_com_conf was:\n{example_com_conf}"
    );
}

/// Seeds four bots (jyxo-crawler among them, tagged "unknown" — no
/// category flags at all) and both fixture sites via the CLI, then opens
/// `example.com`'s detail view in the TUI. The two tests below start from
/// here; the view itself is driven entirely through the TUI.
fn open_site_detail(tmp: &tempfile::TempDir) -> PtySession {
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
    // opening the rescan popup (that's `r`).
    send_key(&mut session, "\r");
    session.exp_string("categories").unwrap();
    session
}

/// A site's *category* override, on its own. Search defaults to Allowed
/// globally, so flipping it to Blocked here is a visible change that could
/// only have come from the per-site override.
#[test]
fn site_detail_overrides_a_category_for_one_site() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = open_site_detail(&tmp);

    // Move to the Search Bots row (index 1) and open its popup.
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\r");
    session.exp_string("Use system default").unwrap();
    session.exp_string("Allowed").unwrap();
    session.exp_string("Blocked").unwrap();

    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B"); // Use system default -> Allowed -> Blocked
    send_key(&mut session, "\r");
    // Checked as "override)" alone, not the literal "(site override)": the
    // row previously read "(system)", which shares its leading "(s", and
    // the diffed terminal only retransmits the differing tail.
    session.exp_string("override)").unwrap();
}

/// A site's *per-bot* override, on its own — reached through the search
/// box, and deliberately on a bot with no category flags at all, so it
/// can't be confused with the category path above.
#[test]
fn site_detail_searches_for_a_bot_and_overrides_it_for_one_site() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = open_site_detail(&tmp);

    send_key(&mut session, "/");
    send_key(&mut session, "jyxo");
    session.exp_string("Jyxo Crawler").unwrap();

    send_key(&mut session, "\r");
    session.exp_string("Use site & system default").unwrap();
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B"); // -> Blocked
    send_key(&mut session, "\r");
    session.exp_string("override)").unwrap();

    // Leaving the search box and then the detail view returns to the site
    // list, rather than backing all the way out to the Dashboard. There's
    // no new text to anchor on for the first transition (only a border
    // colour changes), so it's proved indirectly: if focus hadn't returned
    // to the categories panel, the `q` below would be swallowed as literal
    // search-query text and the final expectation would time out.
    send_escape(&mut session);
    send_escape(&mut session);
    send_key(&mut session, "q");
    session.exp_string("Automatic").unwrap();
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
    session.exp_string("light/dark").unwrap();

    // Esc on Help goes back to Site settings, not the Dashboard.
    send_key(&mut session, "\x1b");
    session.exp_string("Sites").unwrap();

    // `q` on a non-Dashboard screen backs out to the Dashboard rather than
    // quitting; only a second `q`, now on the Dashboard, actually quits.
    // (Anchored on "wide", not "System-wide": the leading "S" lands on the
    // same cell the previous screen's "Sites" title left a coincidentally
    // identical "S", so the diffed terminal output never re-sends it.)
    send_key(&mut session, "q");
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// The Dashboard's geo-blocking panel, added below "System-wide settings".
/// Seeds an already-fetched-but-unblocked country directly (no network
/// access): the TUI only hits the network for a country that hasn't been
/// fetched yet (`App::start_country_block`), so blocking one that's already
/// The command palette end to end: `:` opens it over whatever screen is
/// up, typing narrows the list, Enter runs the selected command — here
/// "Re-read the SSH log", whose first effect is landing on Dynamic
/// Protection, a screen change the pty can see.
#[test]
fn the_command_palette_runs_a_typed_command() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();

    send_key(&mut session, "s");
    session.exp_string("Sites").unwrap();

    send_key(&mut session, ":");
    session.exp_string("Commands").unwrap();
    // A word from the unfiltered list that is not on Site settings.
    session.exp_string("Dynamic").unwrap();

    // Narrow to one row. Not checked on the query line: each keystroke
    // redraws one cell, so "re-read" never arrives contiguously. The
    // filtered row does — it moves to the top of the list, where "Go to
    // Dashboard" was, and differs from it in every cell.
    send_key(&mut session, "re-read");
    session.exp_string("Re-read").unwrap();

    send_key(&mut session, "\r");
    session.exp_string("Failed").unwrap();

    send_key(&mut session, "q");
    session.exp_string("Automatic").unwrap();
    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// fetched is the synchronous path this test can exercise without touching
/// the network.
#[test]
fn dashboard_geo_blocking_add_and_remove_a_country() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    {
        let db = stop_bots::db::Db::open(&db_path).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
    }

    let mut session = spawn_tui(&db_path);
    session.exp_string("Dashboard").unwrap();
    session.exp_string("Geo").unwrap();
    session.exp_string("Add a country").unwrap();

    // Down past the last category row (Scanners/Search Bots/AI Bots) flows
    // focus over into the Countries list, landing on its first row — the
    // fixed "Add a country" action.
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\r");
    session.exp_string("Add a country").unwrap();

    send_key(&mut session, "nl");
    send_key(&mut session, "\r");

    // Already fetched: adds it immediately, no "Fetching…" network step.
    // Default geo mode is Blocklist, so this blocks NL. Checked in actual
    // top-to-bottom render order (the geo box's row is above the message
    // box, so its text hits the wire first) — checking "Blocked NL" before
    // "range(s)" would consume past the row's text while scanning for the
    // message, then hang waiting for "range(s)" to retransmit, which a
    // diffed terminal never does once it's already on screen.
    session.exp_string("range(s)").unwrap();
    session.exp_string("Blocked NL").unwrap();

    // One more Down selects the new "nl" row; Enter removes it directly
    // (no confirmation popup, unlike a category default). Checked as
    // "Remov", not the full "Removed NL": "Blocked NL" (the previous
    // message) and "Removed NL" coincidentally share identical trailing
    // characters ("ed NL") at the same screen position, so the diffed
    // terminal only retransmits the part that actually changed.
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\r");
    session.exp_string("Remov").unwrap();

    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// `m` opens the geo mode popup from anywhere on the Dashboard (not just
/// while the Countries list has focus); confirming it switches the panel's
/// title and every subsequent "add a country" message from
/// Blocked/Blocklist wording to Allowed/Allowlist wording.
#[test]
fn dashboard_geo_mode_toggle_switches_to_allowlist() {
    let tmp = tempfile::tempdir().unwrap();
    let mut session = spawn_tui(&tmp.path().join("db.sqlite3"));
    session.exp_string("Dashboard").unwrap();
    session.exp_string("blocklist").unwrap();

    send_key(&mut session, "m");
    session.exp_string("Geo mode").unwrap();
    session
        .exp_string("Blocklist (block selected countries)")
        .unwrap();
    // Checked as split substrings, not verbatim, same reasoning as the
    // confirmation message below: the diffed terminal only retransmits
    // cells that changed from the *previous actual frame*, so whether a
    // given run of characters comes across as one contiguous write depends
    // on everything else the Dashboard drew before this popup opened, not
    // just the popup's own (unchanged) position.
    session.exp_string("Allowlist").unwrap();
    session.exp_string("(block").unwrap();
    session.exp_string("everything").unwrap();
    session.exp_string("except").unwrap();
    session.exp_string("selected)").unwrap();

    // Move to "Allowlist" and confirm. The confirmation lands in the Log
    // panel; checked as two split substrings, not verbatim, because the
    // spaces between "set", "to" and "Allowlist" coincidentally match
    // blank cells already on screen at that position, so the diffed
    // terminal never retransmits them. (The Geo panel's title flips to
    // "allowlist" in the same frame, but shares too many letters with
    // "blocklist" at the same cells to be a needle.)
    send_key(&mut session, "\x1b[B");
    send_key(&mut session, "\r");
    session.exp_string("Geo mode").unwrap();
    session.exp_string("Allowlist:").unwrap();

    send_key(&mut session, "q");
    session
        .exp_eof()
        .expect("process should exit after q on the Dashboard");
}

/// The one code path in the whole project that *executes* a generated
/// firewall script — the render popup's "apply after writing" toggle —
/// driven end to end against a fake `nft` on PATH. Everything real runs:
/// the popup, the path editing, the render, the write, the process spawn,
/// the exit-code handling; only the binary that PATH resolves is ours.
#[test]
fn dashboard_render_popup_applies_the_script_through_nft() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("db.sqlite3");
    let out_path = tmp.path().join("fw.nft");

    // A fake nft that records its argv and succeeds.
    let fakebin = tmp.path().join("fakebin");
    fs::create_dir_all(&fakebin).unwrap();
    let calls = tmp.path().join("calls.log");
    fs::write(
        fakebin.join("nft"),
        format!(
            "#!/bin/sh\necho \"nft $@\" >> \"{}\"\nexit 0\n",
            calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(fakebin.join("nft"), fs::Permissions::from_mode(0o755)).unwrap();

    let mut session = spawn_tui_with_fake_tools(&db_path, &fakebin);
    session.exp_string("Dashboard").unwrap();

    // Open the render popup; replace the default output path with ours.
    send_key(&mut session, "F");
    // Single-word needles throughout: the diffed terminal only transmits
    // cells that changed, and the spaces between words routinely land on
    // cells that were already blank — so a multi-word needle may never
    // arrive contiguously even though every word is on screen.
    session.exp_string("writing:").unwrap();
    for _ in 0.."/etc/stop-bots/firewall.nft".len() {
        send_key(&mut session, "\x7f");
    }
    for c in out_path.to_str().unwrap().chars() {
        send_key(&mut session, &c.to_string());
    }
    // Space toggles "apply after writing"; Enter confirms (backend defaults
    // to nftables).
    send_key(&mut session, " ");
    send_key(&mut session, "\r");
    session.exp_string("applied").unwrap();

    let script = fs::read_to_string(&out_path).expect("the script should have been written");
    assert!(script.contains("table"), "script was: {script}");
    let log = fs::read_to_string(&calls).expect("nft should have been invoked");
    assert_eq!(log.trim(), format!("nft -f {}", out_path.display()));

    send_key(&mut session, "q");
    session.exp_eof().unwrap();
}
