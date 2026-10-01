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

//! The root helper: `stop-bots helper`, which does for the unprivileged web
//! console what needs root.
//!
//! It listens on a Unix socket — `/run/stop-bots/helper.sock`, handed over
//! by systemd's `stop-bots-helper.socket` (`LISTEN_FDS`), or one it binds
//! itself with `--socket` — and answers [`crate::privileged::Op`]s, running
//! each through [`crate::privileged::execute`], the same code a console
//! running as root runs in process.
//!
//! ## The protocol
//!
//! One request per connection: a single line of JSON, at most
//! [`MAX_REQUEST`] bytes, which must arrive within [`REQUEST_DEADLINE`];
//! then a single line of JSON back, `{"Ok": <reply>}` or `{"Err":
//! "<why>"}`, and the connection is closed. An operation, an unknown field
//! or anything else that is not exactly an `Op` is refused.
//!
//! ## Who may ask
//!
//! The socket's mode lets the console's group in. On top of that, every
//! connection's peer is checked with `SO_PEERCRED`, and only root and the
//! `stop-bots` user are answered: anyone else in the group gets the
//! connection closed without a word read.
//!
//! ## One at a time
//!
//! Requests are served one at a time, and an apply also takes
//! [`crate::applylock`], which the CLI and the TUI share. A request waits
//! at most [`OP_DEADLINE`] for its turn, and is then refused rather than
//! run late; one that has started has as long again to finish, past which
//! the client is told so. At most [`MAX_CONNECTIONS`] are open at once.
//!
//! ## What is logged
//!
//! A line per request on stderr, which is the journal under systemd: the
//! peer's uid, the operation's name and site id, the outcome and how long
//! it took. Never the parameters, never the error text.

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

use crate::privileged::{Op, Reply, Settings};

/// The largest request: far more than any `Op` needs.
pub const MAX_REQUEST: usize = 64 * 1024;

/// How long a request may take to arrive, from the connection on.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// How long an operation may take before the client is told it timed out.
/// An apply is an `nginx -t`, a reload, and an `nft -f` of at most a few
/// tens of thousands of elements: seconds. A hung `docker exec` is the
/// case this exists for.
pub const OP_DEADLINE: Duration = Duration::from_secs(120);

/// Connections open at once. The console makes one at a time; the rest are
/// for a second operator, `status` and the cron.
pub const MAX_CONNECTIONS: usize = 8;

/// The largest reply a client reads. A preview's diff is cut long before.
const MAX_REPLY: u64 = 32 * 1024 * 1024;

/// How the helper is set up. Nothing here comes from a request.
#[derive(Debug, Clone)]
pub struct Config {
    /// The console's database.
    pub db_path: PathBuf,
    pub settings: Settings,
    /// The peers it answers. Root and the `stop-bots` user in the service;
    /// a test's own uid, or not, in the tests.
    pub allowed_uids: Vec<u32>,
    pub request_deadline: Duration,
    pub op_deadline: Duration,
    pub max_connections: usize,
}

impl Config {
    /// The service's: root and [`crate::account::USER`], the host settings at their path,
    /// the firewall script at its fixed one.
    pub fn for_host(db_path: PathBuf) -> Self {
        let mut allowed_uids = vec![0];
        match crate::account::user(crate::account::USER) {
            Some(account) => allowed_uids.push(account.uid),
            None => eprintln!(
                "stop-bots helper: there is no `{}` user, so only root is answered \
                 (`sudo stop-bots install web` creates it)",
                crate::account::USER
            ),
        }
        Config {
            db_path,
            settings: Settings::helper(),
            allowed_uids,
            request_deadline: REQUEST_DEADLINE,
            op_deadline: OP_DEADLINE,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

/// The uid of the process at the other end of `stream`, as the kernel
/// recorded it when that process connected.
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    // SAFETY: plain old data.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is open for the life of `stream`, and the
    // option buffer is a `ucred` whose size is passed with it.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

/// Whose turn it is to run an operation: one at a time.
///
/// A flag and a condition variable rather than a `Mutex<()>`, because the
/// turn is taken on the connection's thread — so a request that waits too
/// long is answered "busy" and never runs at all — and given back by the
/// worker that runs the operation, which may outlive the wait for it.
#[derive(Default)]
struct Turns {
    taken: Mutex<bool>,
    freed: Condvar,
}

/// A turn, given back when dropped.
struct Turn(Arc<Turns>);

impl Turns {
    /// Waits at most `wait` for the turn.
    fn take(self: &Arc<Self>, wait: Duration) -> Option<Turn> {
        let until = Instant::now() + wait;
        let mut taken = self.taken.lock().unwrap_or_else(|p| p.into_inner());
        while *taken {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            taken = self
                .freed
                .wait_timeout(taken, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        *taken = true;
        Some(Turn(Arc::clone(self)))
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        *self.0.taken.lock().unwrap_or_else(|p| p.into_inner()) = false;
        self.0.freed.notify_one();
    }
}

/// The server: [`Server::serve`] answers connections until the listener
/// fails.
#[derive(Clone)]
pub struct Server {
    config: Arc<Config>,
    /// One operation at a time.
    turns: Arc<Turns>,
    /// Connections being served now.
    open: Arc<AtomicUsize>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Server {
            config: Arc::new(config),
            turns: Arc::default(),
            open: Arc::default(),
        }
    }

    /// Answers every connection `listener` accepts, each on a thread of
    /// its own, at most [`Config::max_connections`] at once.
    pub fn serve(&self, listener: UnixListener) -> Result<()> {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err).context("the helper's socket failed"),
            };
            if self.open.fetch_add(1, Ordering::SeqCst) >= self.config.max_connections {
                self.open.fetch_sub(1, Ordering::SeqCst);
                let uid = peer_uid(&stream).ok();
                log(
                    uid,
                    "-",
                    None,
                    "refused: too many connections",
                    Duration::ZERO,
                );
                // Said only to a peer it would have answered.
                if uid.is_some_and(|uid| self.config.allowed_uids.contains(&uid)) {
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                    let _ = reply(&stream, &Err("the helper is busy; try again".to_string()));
                }
                continue;
            }
            let server = self.clone();
            std::thread::spawn(move || {
                server.connection(&stream);
                server.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    /// One connection: who, what, the answer, the log line.
    fn connection(&self, stream: &UnixStream) {
        let started = Instant::now();
        let uid = match peer_uid(stream) {
            Ok(uid) => uid,
            Err(_) => {
                log(
                    None,
                    "-",
                    None,
                    "refused: no peer credentials",
                    started.elapsed(),
                );
                return;
            }
        };
        if !self.config.allowed_uids.contains(&uid) {
            // Closed unanswered: nothing is read from a stranger.
            log(
                Some(uid),
                "-",
                None,
                "refused: not an allowed user",
                started.elapsed(),
            );
            return;
        }
        let op = match read_request(stream, self.config.request_deadline) {
            Ok(op) => op,
            Err(why) => {
                let _ = reply(stream, &Err(why.to_string()));
                log(Some(uid), "-", None, why.log(), started.elapsed());
                return;
            }
        };
        let (name, site) = (op.name(), op.site());
        let answer = self.run(op);
        let outcome = if answer.is_ok() { "ok" } else { "error" };
        let sent = reply(stream, &answer);
        let outcome = match sent {
            Ok(()) => outcome.to_string(),
            Err(_) => format!("{outcome}, but the reply could not be sent"),
        };
        log(Some(uid), name, site, &outcome, started.elapsed());
    }

    /// Runs `op` on a thread of its own once it is its turn (see [`Turns`]),
    /// waiting at most [`Config::op_deadline`] for the turn and as long
    /// again for the operation.
    ///
    /// A request still waiting for its turn at the deadline is answered
    /// "busy" and is not run later: whoever asked has been told no. One
    /// that has started finishes even if its client has stopped waiting —
    /// an apply abandoned half-way is worse than one that ends late — and
    /// the next waits for it.
    fn run(&self, op: Op) -> std::result::Result<Reply, String> {
        let Some(turn) = self.turns.take(self.config.op_deadline) else {
            return Err(format!(
                "the helper has been busy with another request for {} seconds; nothing was \
                 done, try again",
                self.config.op_deadline.as_secs()
            ));
        };
        let (done, result) = mpsc::channel();
        let server = self.clone();
        std::thread::spawn(move || {
            // Given back however this ends, a panic included: each
            // operation opens its own database, so nothing is left
            // half-done for the next to trip over.
            let _turn = turn;
            let answer = crate::db::Db::open_untrusted(&server.config.db_path)
                .and_then(|db| crate::privileged::execute(&server.config.settings, &db, op))
                .map_err(|err| format!("{err:#}"));
            let _ = done.send(answer);
        });
        match result.recv_timeout(self.config.op_deadline) {
            Ok(answer) => answer,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "the helper did not finish within {} seconds; it may still be running, and \
                 the next request waits for it",
                self.config.op_deadline.as_secs()
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("the helper failed while doing it; see its journal".to_string())
            }
        }
    }
}

/// Why a request was not read.
#[derive(Debug)]
enum BadRequest {
    TooLarge,
    TooSlow,
    Unreadable(std::io::Error),
    NotAnOp(String),
}

impl BadRequest {
    fn log(&self) -> &'static str {
        match self {
            BadRequest::TooLarge => "refused: request too large",
            BadRequest::TooSlow => "refused: request too slow",
            BadRequest::Unreadable(_) => "refused: request unreadable",
            BadRequest::NotAnOp(_) => "refused: not a request",
        }
    }
}

impl std::fmt::Display for BadRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadRequest::TooLarge => write!(f, "the request is larger than {MAX_REQUEST} bytes"),
            BadRequest::TooSlow => write!(f, "the request did not arrive in time"),
            BadRequest::Unreadable(err) => write!(f, "the request could not be read: {err}"),
            BadRequest::NotAnOp(err) => write!(f, "not a request the helper knows: {err}"),
        }
    }
}

/// Reads one line, within `deadline` of now and [`MAX_REQUEST`] bytes,
/// and parses it as an [`Op`].
fn read_request(
    mut stream: &UnixStream,
    deadline: Duration,
) -> std::result::Result<Op, BadRequest> {
    let until = Instant::now() + deadline;
    let mut line: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(BadRequest::TooSlow);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(BadRequest::Unreadable)?;
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(BadRequest::TooSlow)
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(BadRequest::Unreadable(err)),
        };
        let complete = read == 0 || chunk[..read].contains(&b'\n');
        line.extend_from_slice(&chunk[..read]);
        if let Some(end) = line.iter().position(|&b| b == b'\n') {
            line.truncate(end);
        }
        if line.len() > MAX_REQUEST {
            return Err(BadRequest::TooLarge);
        }
        if complete {
            break;
        }
    }
    serde_json::from_slice(&line).map_err(|err| BadRequest::NotAnOp(err.to_string()))
}

/// Writes `answer` as one line.
fn reply(mut stream: &UnixStream, answer: &std::result::Result<Reply, String>) -> Result<()> {
    let mut line = serde_json::to_vec(answer)?;
    line.push(b'\n');
    stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
    stream.write_all(&line)?;
    Ok(())
}

/// The one line a request leaves in the journal.
fn log(uid: Option<u32>, op: &str, site: Option<i64>, outcome: &str, took: Duration) {
    let uid = uid.map_or_else(|| "?".to_string(), |uid| uid.to_string());
    let site = site.map(|id| format!(" site={id}")).unwrap_or_default();
    eprintln!(
        "stop-bots helper: uid={uid} op={op}{site} {outcome} in {:.3}s",
        took.as_secs_f64()
    );
}

/// Asks the helper on `socket` to do `op`, and waits for the answer: as
/// long as the helper may take to give it a turn and then to run it.
pub fn call(socket: &Path, op: &Op) -> Result<Reply> {
    call_with(socket, op, 2 * OP_DEADLINE + REQUEST_DEADLINE)
}

/// [`call`], waiting at most `timeout` for the answer.
pub fn call_with(socket: &Path, op: &Op, timeout: Duration) -> Result<Reply> {
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "could not reach the stop-bots helper at {}: is stop-bots-helper.socket running? \
             `sudo stop-bots install web` sets it up",
            socket.display()
        )
    })?;
    stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
    stream.set_read_timeout(Some(timeout))?;
    let mut line = serde_json::to_vec(op)?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .context("could not send the request to the stop-bots helper")?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut answer = Vec::new();
    match (&stream).take(MAX_REPLY).read_to_end(&mut answer) {
        Ok(_) => {}
        // What a refused peer sees: the helper closed without reading what
        // was sent, so the kernel resets the connection.
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => answer.clear(),
        Err(err) => return Err(err).context("the stop-bots helper did not answer"),
    }
    if answer.iter().all(u8::is_ascii_whitespace) {
        bail!(
            "the stop-bots helper at {} closed the connection without answering: only root \
             and the `{}` user may use it",
            socket.display(),
            crate::account::USER
        );
    }
    let answer: std::result::Result<Reply, String> = serde_json::from_slice(answer.trim_ascii())
        .context("the stop-bots helper's answer could not be read")?;
    answer.map_err(|err| anyhow!(err))
}

/// The socket systemd passed this process, if it passed one: `LISTEN_PID`
/// names this process and `LISTEN_FDS` is 1, so the socket is fd 3.
///
/// The variables are removed, so nothing this process starts — `nginx`,
/// `nft` — thinks it was handed sockets too, and the descriptor is made
/// close-on-exec for the same reason.
pub fn systemd_listener() -> Result<Option<UnixListener>> {
    let count = listen_fds(
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    )?;
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(var);
    }
    let Some(count) = count else {
        return Ok(None);
    };
    if count != 1 {
        bail!("systemd passed {count} sockets; stop-bots-helper.socket listens on exactly one");
    }
    const FIRST: libc::c_int = 3;
    // SAFETY: fstat on a descriptor number into a local `stat`; an invalid
    // descriptor only makes it fail.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(FIRST, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
    {
        bail!("systemd's descriptor 3 is not a socket");
    }
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe { libc::fcntl(FIRST, libc::F_SETFD, libc::FD_CLOEXEC) };
    // SAFETY: systemd handed this process descriptor 3, a listening Unix
    // socket (checked above), and nothing else in it owns it.
    Ok(Some(unsafe { UnixListener::from_raw_fd(FIRST) }))
}

/// How many sockets `LISTEN_PID` and `LISTEN_FDS` say this process (`pid`)
/// was given, if they are about this process at all.
fn listen_fds(listen_pid: Option<&str>, listen_fds: Option<&str>, pid: u32) -> Result<Option<u32>> {
    let Some(listen_pid) = listen_pid else {
        return Ok(None);
    };
    let listen_pid: u32 = listen_pid
        .trim()
        .parse()
        .with_context(|| format!("LISTEN_PID is not a process id: {listen_pid:?}"))?;
    if listen_pid != pid {
        return Ok(None);
    }
    let count: u32 = listen_fds
        .unwrap_or("0")
        .trim()
        .parse()
        .with_context(|| format!("LISTEN_FDS is not a number: {listen_fds:?}"))?;
    Ok((count > 0).then_some(count))
}

/// Binds a socket of its own at `path`, for `stop-bots helper --socket`. A
/// socket left at that path by an earlier run is removed first; anything
/// else there is refused.
pub fn bind(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            bail!("{} exists and is not a socket", path.display());
        }
        std::fs::remove_file(path)
            .with_context(|| format!("failed to remove the old socket {}", path.display()))?;
    }
    UnixListener::bind(path).with_context(|| format!("failed to listen on {}", path.display()))
}

/// `stop-bots helper`: serves on systemd's socket, or on `socket`.
pub fn run(db_path: PathBuf, socket: Option<PathBuf>) -> Result<()> {
    let listener = match &socket {
        Some(path) => bind(path)?,
        None => systemd_listener()?.with_context(|| {
            format!(
                "no socket to serve on: run this under stop-bots-helper.socket \
                 (`sudo stop-bots install web`), or pass --socket <path>; it is {} \
                 under systemd",
                crate::install::HELPER_SOCKET
            )
        })?,
    };
    if !crate::hint::is_root() {
        eprintln!("stop-bots helper: not running as root, so nothing that needs root will work");
    }
    let config = Config::for_host(db_path);
    // It never migrates: the database is the console's, and nothing in it
    // is read for these. Without the file, every default applies.
    if std::fs::symlink_metadata(&config.settings.host_conf).is_err() {
        eprintln!(
            "stop-bots helper: there is no {}, so the built-in defaults apply and the \
             database's old host settings are ignored (`sudo stop-bots install web` writes it)",
            config.settings.host_conf.display()
        );
    }
    eprintln!(
        "stop-bots helper: serving {} for uids {:?}",
        config.db_path.display(),
        config.allowed_uids
    );
    Server::new(config).serve(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_s_variables_count_only_for_this_process() {
        assert_eq!(listen_fds(None, None, 42).unwrap(), None);
        assert_eq!(listen_fds(Some("41"), Some("1"), 42).unwrap(), None);
        assert_eq!(listen_fds(Some("42"), Some("1"), 42).unwrap(), Some(1));
        assert_eq!(listen_fds(Some("42"), Some("0"), 42).unwrap(), None);
        assert!(listen_fds(Some("x"), Some("1"), 42).is_err());
        assert!(listen_fds(Some("42"), Some("one"), 42).is_err());
    }

    #[test]
    fn the_peer_is_whoever_connected() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: no preconditions.
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }

    /// Something else at the path is somebody's file, not a stale socket.
    #[test]
    fn binding_over_a_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        std::fs::write(&path, "not a socket").unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a socket");
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helper.sock");
        drop(bind(&path).unwrap());
        bind(&path).unwrap();
    }
}
