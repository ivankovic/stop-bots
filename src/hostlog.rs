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

//! The two host logs the detectors read, a bounded piece at a time, from
//! where the last piece stopped: the NGINX access log, and sshd's
//! authentication lines.
//!
//! [`read`] is the one function that reads them, wherever it runs:
//!
//! - in the root helper, for the web console, which since 0.1 reads no
//!   host file but its database ([`crate::privileged::Op::ReadLog`]);
//! - in process, for everything that is root already — the CLI, the TUI,
//!   a console run by hand as root — and for a read-only console, with
//!   whatever its own user may read.
//!
//! Either way the caller holds a [`LogReader`] and asks it for [`Request`]s
//! until a reply says there is no more.
//!
//! ## What a request can choose, and what it cannot
//!
//! A request names one of the two logs, never a path: where each is comes
//! from [`Sources`], which the reader is configured with — the host
//! settings ([`crate::hostconf`]) and autodetection in the helper, as for
//! the root CLI. What a request does choose is where in that log to start:
//! a cursor, or a time for the journal. A cursor is a place, compared with
//! the log the reader finds and otherwise ignored; it cannot point the
//! read anywhere else.
//!
//! ## What comes back
//!
//! The access log's lines, every one, since every access-log detector and
//! the access statistics read them all. Of the SSH log, only the lines
//! sshd wrote about an authentication — `Accepted`, `Failed`, `Invalid
//! user`, as [`crate::sshlog`] reads them — and from the journal only the
//! entries of sshd's own units. Nothing else in `auth.log` (sudo, cron,
//! every user's sessions) and nothing else in the journal is returned.
//!
//! The lines come back unparsed, and are parsed where they are used, by
//! the same code whichever side read them. The alternative, parsing in the
//! helper and returning the detectors' evidence, would return less of the
//! access log, but it would run the detectors' parsers — on text an
//! attacker writes — as root, and it would need their whole configuration
//! in each request (probe paths, honeypot, the crawler ranges), or read it
//! from the database the helper treats as hostile. The console is meant to
//! see the access log: that is what its detectors are for.
//!
//! ## How much one request costs
//!
//! At most [`MAX_CHUNK`] bytes of log, stopping at a line or an entry:
//! a first read of a large log, or a journal with a month of brute-forcing
//! in it, is many requests, each quick, and never holds the helper long.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logread::{self, FileCursor};
use crate::sshlog::{self, Located, SshSource};

/// The most a request reads: 4 MB. A first read of a 100 MB log is 25
/// requests.
pub const MAX_CHUNK: u64 = 4 * 1024 * 1024;

/// How many cursors a request may offer; the SSH log may be in one of
/// [`sshlog::DEFAULT_LOG_PATHS`] or the journal, or one named file.
const MAX_CURSORS: usize = 4;

/// The stored form of a journal cursor, before journald's own.
pub const JOURNAL_CURSOR_PREFIX: &str = "journal ";

/// What an unreadable journal is reported as.
const JOURNAL_TRIED: &str = "journald (units sshd and ssh)";

/// Which log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Log {
    /// The NGINX access log.
    Access,
    /// sshd's authentication lines: from the auth log file, or the
    /// journal.
    Ssh,
}

/// Where an earlier read of one log stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    /// The log it is a place in, by the key its cursor is stored under:
    /// the path of a file, or [`sshlog::JOURNAL_SOURCE`]. Compared with the
    /// log the reader finds; never opened.
    pub source: String,
    /// The place, in its stored form: [`FileCursor::encode`], or
    /// [`JOURNAL_CURSOR_PREFIX`] and journald's cursor.
    pub at: String,
}

/// One read of one log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub log: Log,
    /// Where earlier reads stopped, one per place the log might be. The
    /// one for where it turns out to be is used; with none, the read starts
    /// at the beginning.
    pub cursors: Vec<Cursor>,
    /// With no cursor for the access log: the byte count 0.0.x's access
    /// statistics stopped at, to start there rather than at the beginning.
    pub legacy_offset: Option<u64>,
    /// With no cursor for the journal: the Unix time to read from. A file
    /// is read from its start; the journal is bounded by nothing else.
    pub since: Option<i64>,
    /// The most to read, in bytes; never more than [`MAX_CHUNK`].
    pub max_bytes: u64,
}

impl Request {
    /// The first read of `log`, or a later one from `cursors`, at the
    /// largest size.
    pub fn new(log: Log, cursors: Vec<Cursor>) -> Self {
        Request {
            log,
            cursors,
            legacy_offset: None,
            since: None,
            max_bytes: MAX_CHUNK,
        }
    }

    /// The stored cursor offered for `source`.
    fn cursor_for(&self, source: &str) -> Option<&str> {
        self.cursors
            .iter()
            .take(MAX_CURSORS)
            .find(|cursor| cursor.source == source)
            .map(|cursor| cursor.at.as_str())
    }
}

/// What a read came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Read(Chunk),
    /// Nothing could be read; what was tried, for a report.
    Unavailable(String),
}

/// A piece of a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    /// The key the log's cursor is stored under: see [`Cursor::source`].
    pub source: String,
    /// The cursor the read started from, as it was offered, or `None` if
    /// none applied.
    pub from: Option<String>,
    /// Where the next read starts. `None` only for a journal that has
    /// never had anything from sshd in it.
    pub to: Option<String>,
    /// Whether this read carried on from an earlier one (a cursor, or the
    /// legacy offset), rather than starting at the beginning: a line with
    /// no time of its own was then written since that read.
    pub resumed: bool,
    /// The lines, each ending in a newline.
    pub lines: String,
    /// Bytes read from a file, or entries from the journal, the ones not
    /// returned included.
    pub amount: u64,
    /// Whether the read stopped at its size rather than at the end: ask
    /// again, from [`Self::to`].
    pub more: bool,
}

impl Chunk {
    /// The cursor to offer for the next read of this log.
    pub fn next(&self) -> Option<Cursor> {
        self.to.as_ref().map(|at| Cursor {
            source: self.source.clone(),
            at: at.clone(),
        })
    }
}

/// Where this host's two logs are, as the reader resolves them. Never from
/// a request.
#[derive(Debug, Clone)]
pub struct Sources {
    pub access: PathBuf,
    pub ssh: SshSource,
    /// Where [`SshSource::Search`] looks before the journal.
    pub search: Vec<PathBuf>,
    /// `journalctl`, except in tests.
    pub journalctl: PathBuf,
}

impl Sources {
    /// The logs `paths` names, a flag winning over each: the access log,
    /// and the SSH log or the search for it.
    pub fn new(
        paths: &crate::logpaths::LogPaths,
        access_flag: Option<&Path>,
        ssh_flag: Option<&Path>,
    ) -> Self {
        Sources {
            access: paths.access_path(access_flag),
            ssh: paths.ssh(ssh_flag),
            search: sshlog::DEFAULT_LOG_PATHS
                .iter()
                .map(PathBuf::from)
                .collect(),
            journalctl: PathBuf::from("journalctl"),
        }
    }

    /// Only an SSH log, for its readers that read nothing else.
    pub fn ssh_only(ssh: SshSource) -> Self {
        Sources {
            access: PathBuf::new(),
            ..Sources::new(&Default::default(), None, None)
        }
        .with_ssh(ssh)
    }

    fn with_ssh(mut self, ssh: SshSource) -> Self {
        self.ssh = ssh;
        self
    }
}

/// The key a file's cursor is stored under: its path, as given.
pub fn source_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Something that answers [`Request`]s: [`Sources`] in process, or
/// [`crate::privileged::Privileged`], which may ask the helper. Blocking.
pub trait LogReader {
    fn read_log(&self, request: &Request) -> anyhow::Result<Reply>;
}

impl LogReader for Sources {
    fn read_log(&self, request: &Request) -> anyhow::Result<Reply> {
        Ok(read(self, request))
    }
}

/// Reads what `request` asks for from the log `sources` names. The one
/// implementation: see the module docs.
pub fn read(sources: &Sources, request: &Request) -> Reply {
    let budget = request.max_bytes.clamp(1, MAX_CHUNK);
    match request.log {
        Log::Access => read_access(&sources.access, request, budget),
        Log::Ssh => read_ssh(sources, request, budget),
    }
}

fn read_access(path: &Path, request: &Request, budget: u64) -> Reply {
    let source = source_key(path);
    let stored = request.cursor_for(&source);
    let start = match (stored, request.legacy_offset) {
        (Some(stored), _) => FileCursor::decode(stored),
        (None, Some(offset)) => logread::cursor_at(path, offset).ok(),
        (None, None) => None,
    };
    let mut lines = String::new();
    match logread::read_chunk(path, start, budget, &mut |line| push(&mut lines, line)) {
        Ok(done) => Reply::Read(Chunk {
            source,
            from: stored.map(String::from),
            to: Some(done.cursor.encode()),
            resumed: start.is_some(),
            lines,
            amount: done.bytes,
            more: done.more,
        }),
        Err(_) => Reply::Unavailable(path.display().to_string()),
    }
}

fn push(lines: &mut String, line: &str) {
    lines.push_str(line);
    lines.push('\n');
}

/// Appends `line` if it is one of sshd's authentication lines.
fn push_auth(lines: &mut String, line: &str) {
    if sshlog::is_auth_line(line) {
        push(lines, line);
    }
}

fn read_ssh(sources: &Sources, request: &Request, budget: u64) -> Reply {
    match sources.ssh.locate_among(&sources.search) {
        Located::File(path) => {
            let source = source_key(&path);
            let stored = request.cursor_for(&source);
            let start = stored.and_then(FileCursor::decode);
            let mut lines = String::new();
            match logread::read_chunk(&path, start, budget, &mut |line| {
                push_auth(&mut lines, line)
            }) {
                Ok(done) => Reply::Read(Chunk {
                    source,
                    from: stored.map(String::from),
                    to: Some(done.cursor.encode()),
                    resumed: start.is_some(),
                    lines,
                    amount: done.bytes,
                    more: done.more,
                }),
                Err(_) => Reply::Unavailable(path.display().to_string()),
            }
        }
        Located::Journal => read_journal(sources, request, budget),
    }
}

/// Whether `cursor` looks like one journald writes: `s=…;i=…;b=…`, of
/// letters, digits, `=` and `;`. It goes to `journalctl` as one argument
/// either way; this keeps anything else from going at all.
fn is_journal_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= 512
        && cursor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'=' || b == b';')
}

fn read_journal(sources: &Sources, request: &Request, budget: u64) -> Reply {
    let source = sshlog::JOURNAL_SOURCE.to_string();
    let stored = request.cursor_for(&source);
    let after = stored
        .and_then(|stored| stored.strip_prefix(JOURNAL_CURSOR_PREFIX))
        .filter(|cursor| is_journal_cursor(cursor));
    let query = logread::JournalQuery {
        program: &sources.journalctl,
        units: sshlog::journal_units(),
        after_cursor: after,
        since: request.since,
        last: None,
        max_bytes: Some(budget),
    };
    let mut lines = String::new();
    let done = match logread::read_journal(&query, &mut |line| push_auth(&mut lines, line)) {
        Ok(done) => done,
        Err(_) => return Reply::Unavailable(JOURNAL_TRIED.to_string()),
    };
    // A first read that found nothing since `since`: a quiet host, or a
    // journal this user cannot see. The newest entry, however old, tells
    // the two apart, and its cursor is where the next read starts.
    let cursor = match (&done.cursor, after) {
        (None, None) => newest_journal_cursor(&sources.journalctl),
        (cursor, _) => cursor.clone(),
    };
    // Readable is "it answered, and has at some point had something to
    // say": an unprivileged journalctl succeeds with nothing, and that must
    // not read as a log with no logins in it.
    if cursor.is_none() && after.is_none() {
        return Reply::Unavailable(JOURNAL_TRIED.to_string());
    }
    Reply::Read(Chunk {
        source,
        from: stored.map(String::from),
        to: cursor.map(|cursor| format!("{JOURNAL_CURSOR_PREFIX}{cursor}")),
        // Every entry `short-iso` prints is dated, so an undated line is
        // not one journald wrote.
        resumed: false,
        lines,
        amount: done.lines as u64,
        more: done.more,
    })
}

/// The cursor of the newest sshd entry in the journal, if there is one.
fn newest_journal_cursor(journalctl: &Path) -> Option<String> {
    let query = logread::JournalQuery {
        program: journalctl,
        units: sshlog::journal_units(),
        after_cursor: None,
        since: None,
        last: Some(1),
        max_bytes: None,
    };
    logread::read_journal(&query, &mut |_| {}).ok()?.cursor
}

/// sshd's authentication lines since `since`, from the start of the log:
/// for the readers that want them all at once rather than what is new —
/// the lockout guard, the Firewall screens, the one-off CLI commands.
/// `None` when the log could not be read.
///
/// A file is read whole, since logrotate bounds it; the journal from
/// `since`, since nothing bounds it. A request at a time, until the log
/// says there is no more.
pub fn ssh_since(reader: &dyn LogReader, since: i64) -> Option<String> {
    let mut text = String::new();
    let mut request = Request {
        since: Some(since),
        ..Request::new(Log::Ssh, Vec::new())
    };
    let mut source: Option<String> = None;
    loop {
        let chunk = match reader.read_log(&request).ok()? {
            Reply::Read(chunk) => chunk,
            Reply::Unavailable(_) => return source.is_some().then_some(text),
        };
        // The log moved under the read (rotated away, or the search found
        // another): what was read so far is what there is.
        if source
            .as_ref()
            .is_some_and(|source| *source != chunk.source)
        {
            return Some(text);
        }
        text.push_str(&chunk.lines);
        if !chunk.more {
            return Some(text);
        }
        request.cursors = chunk.next().into_iter().collect();
        source = Some(chunk.source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fake_journalctl, journal_entry, journalctl_calls};

    const SEP_28: i64 = 1_790_577_181;

    fn sources(dir: &Path) -> Sources {
        Sources {
            access: dir.join("access.log"),
            ssh: SshSource::File(dir.join("auth.log")),
            search: vec![dir.join("no-auth.log")],
            journalctl: dir.join("journalctl"),
        }
    }

    fn chunk(reply: Reply) -> Chunk {
        match reply {
            Reply::Read(chunk) => chunk,
            Reply::Unavailable(tried) => panic!("unavailable: {tried}"),
        }
    }

    /// Of `auth.log`, sshd's authentication lines and nothing else: not
    /// sudo, not cron, not another program that mentions SSH.
    #[test]
    fn of_the_auth_log_only_sshd_s_authentication_lines_come_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("auth.log"),
            "Sep 28 06:00:00 host sudo[9]: marko : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow\n\
             Sep 28 06:00:01 host CRON[9]: pam_unix(cron:session): session opened for root\n\
             Sep 28 06:00:02 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n\
             Sep 28 06:00:03 host sshd[1]: pam_unix(sshd:session): session opened for user m\n\
             Sep 28 06:00:04 host other[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n\
             Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 port 1 ssh2\n",
        )
        .unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request::new(Log::Ssh, Vec::new()),
        ));

        assert_eq!(
            read.lines,
            "Sep 28 06:00:02 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n\
             Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
        );
    }

    /// A request names a log, not a path: whatever it offers as a cursor's
    /// source, the file read is the one the reader was configured with,
    /// and a cursor offered for another file is not used.
    #[test]
    fn a_cursor_for_another_file_reads_the_configured_one_from_its_start() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("access.log"), "one\ntwo\n").unwrap();
        std::fs::write(dir.path().join("secret"), "secret\n").unwrap();
        let elsewhere = logread::cursor_at(&dir.path().join("secret"), 0).unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request::new(
                Log::Access,
                vec![Cursor {
                    source: source_key(&dir.path().join("secret")),
                    at: elsewhere.encode(),
                }],
            ),
        ));

        assert_eq!(read.lines, "one\ntwo\n");
        assert_eq!(read.from, None);
        assert_eq!(read.source, source_key(&dir.path().join("access.log")));
    }

    /// No request reads more than a chunk, whatever it asks for.
    #[test]
    fn a_request_reads_no_more_than_a_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let line = "x".repeat(1023) + "\n";
        std::fs::write(
            dir.path().join("access.log"),
            line.repeat((MAX_CHUNK / 1024) as usize + 10),
        )
        .unwrap();

        let read = chunk(read(
            &sources(dir.path()),
            &Request {
                max_bytes: u64::MAX,
                ..Request::new(Log::Access, Vec::new())
            },
        ));

        assert!(read.more);
        assert_eq!(read.amount, MAX_CHUNK);
        assert_eq!(read.lines.len() as u64, MAX_CHUNK);
    }

    /// From the journal: the units are sshd's, and of their entries only
    /// the authentication lines come back.
    #[test]
    fn of_the_journal_only_sshd_s_units_and_authentication_lines_are_read() {
        let dir = tempfile::tempdir().unwrap();
        fake_journalctl(
            dir.path(),
            &format!(
                "echo '{}'\necho '{}'\n",
                journal_entry("s=1", SEP_28, "Server listening on 0.0.0.0 port 22."),
                journal_entry(
                    "s=2",
                    SEP_28,
                    "Failed password for root from 203.0.113.5 port 1 ssh2"
                ),
            ),
        );
        let mut sources = sources(dir.path());
        sources.ssh = SshSource::Search;

        let read = chunk(read(
            &sources,
            &Request {
                since: Some(SEP_28 - 60),
                ..Request::new(Log::Ssh, Vec::new())
            },
        ));

        assert_eq!(read.lines.lines().count(), 1, "{}", read.lines);
        assert!(read.lines.contains("203.0.113.5"), "{}", read.lines);
        assert_eq!(read.to.as_deref(), Some("journal s=2"));
        let calls = journalctl_calls(dir.path());
        assert!(calls[0].starts_with("-u sshd -u ssh "), "{calls:?}");
        assert!(calls[0].contains("--since=@"), "{calls:?}");
    }

    /// A journal cursor that is not one journald would write is not passed
    /// on: the read starts from `since` instead.
    #[test]
    fn a_cursor_journald_did_not_write_is_not_passed_to_journalctl() {
        let dir = tempfile::tempdir().unwrap();
        fake_journalctl(dir.path(), "");
        let mut sources = sources(dir.path());
        sources.ssh = SshSource::Search;

        read(
            &sources,
            &Request {
                since: Some(SEP_28),
                ..Request::new(
                    Log::Ssh,
                    vec![Cursor {
                        source: sshlog::JOURNAL_SOURCE.to_string(),
                        at: "journal s=1 --file=/etc/shadow".to_string(),
                    }],
                )
            },
        );

        let calls = journalctl_calls(dir.path()).join("\n");
        assert!(!calls.contains("shadow"), "{calls}");
        assert!(calls.contains("--since=@"), "{calls}");
    }

    /// A reader that reads `max` bytes at a time, however much it is asked
    /// for: chunks small enough to have many in a test.
    struct Small(Sources, u64);

    impl LogReader for Small {
        fn read_log(&self, request: &Request) -> anyhow::Result<Reply> {
            let mut request = request.clone();
            request.max_bytes = self.1;
            Ok(read(&self.0, &request))
        }
    }

    /// The whole-log readers ask until there is no more, and get the same
    /// lines as one read would have given.
    #[test]
    fn reading_since_asks_until_the_log_runs_out() {
        let dir = tempfile::tempdir().unwrap();
        let line = "Sep 28 06:00:05 host sshd[2]: Failed password for root from 203.0.113.5 \
                    port 1 ssh2\n";
        std::fs::write(dir.path().join("auth.log"), line.repeat(50)).unwrap();

        let whole = ssh_since(&sources(dir.path()), 0).unwrap();
        let chunked = ssh_since(&Small(sources(dir.path()), 300), 0).unwrap();

        assert_eq!(whole.lines().count(), 50);
        assert_eq!(chunked, whole);
    }

    #[test]
    fn an_ssh_log_that_is_not_there_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ssh_since(&sources(dir.path()), 0), None);
    }
}
