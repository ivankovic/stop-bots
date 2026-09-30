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

//! Reading a log a line at a time, from where the last read stopped.
//!
//! Every log used to be read with `fs::read` and decoded into one string:
//! twice the file in memory, per reader, and on a 1 GB server with a
//! 200 MB access log, ten readers a minute. Everything here streams
//! instead. A line is decoded, handed to the caller and dropped, so memory
//! is one line plus whatever the caller keeps.
//!
//! ## Where a read resumes
//!
//! A file is remembered by a [`FileCursor`]: its device and inode, a digest
//! of its first bytes, and the byte offset reached. The inode is what tells
//! "the same file, grown" from "a new file under the same name", and the
//! digest catches the new file that was handed the old one's inode:
//!
//! - **Same inode and start, at least as long:** read from the offset.
//! - **Same inode, shorter, or starting differently:** it was truncated in
//!   place (logrotate's `copytruncate`), or it is another file. Read it
//!   from the start.
//! - **A different inode:** it was rotated, and a new file created. What
//!   the old file got between the last read and the rotation is in its
//!   rotated copy, which logrotate names `<path>.1` unless told otherwise;
//!   if that is the old inode, its remainder is read first. Then the new
//!   file, from the start.
//!
//! A last line with no newline yet is left for next time: NGINX writes a
//! line in one `write`, so an unterminated one is a line still arriving,
//! and reading half of it would count the half as a line of its own.
//!
//! journald has cursors of its own, which [`read_journal`] passes through.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How far into one file a read has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCursor {
    pub dev: u64,
    pub ino: u64,
    pub offset: u64,
    /// A digest of the file's first [`Self::head_len`] bytes, which is what
    /// tells a file from a new one that happens to get the same inode.
    /// A filesystem hands a freed inode straight back out, so "delete, then
    /// create" can produce a new log with the old one's identity.
    pub head: u64,
    pub head_len: u64,
}

/// How much of a file's start [`FileCursor::head`] covers. A log's first
/// line carries a time, so two files agree on it only by coincidence.
const HEAD_BYTES: u64 = 256;

impl FileCursor {
    /// The stored form: `file <dev> <ino> <offset> <head_len> <head>`.
    pub fn encode(&self) -> String {
        format!(
            "file {} {} {} {} {:016x}",
            self.dev, self.ino, self.offset, self.head_len, self.head
        )
    }

    pub fn decode(text: &str) -> Option<FileCursor> {
        let mut parts = text.strip_prefix("file ")?.split(' ');
        let cursor = FileCursor {
            dev: parts.next()?.parse().ok()?,
            ino: parts.next()?.parse().ok()?,
            offset: parts.next()?.parse().ok()?,
            head_len: parts.next()?.parse().ok()?,
            head: u64::from_str_radix(parts.next()?, 16).ok()?,
        };
        parts.next().is_none().then_some(cursor)
    }
}

/// FNV-1a over the first `len` bytes of `file`, or `None` if it is shorter.
fn head_digest(file: &mut File, len: u64) -> io::Result<Option<u64>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(len).read_to_end(&mut bytes)?;
    if (bytes.len() as u64) < len {
        return Ok(None);
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    Ok(Some(hash))
}

/// What one incremental read of a file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRead {
    /// Where the next read resumes.
    pub cursor: FileCursor,
    /// Whether there was no cursor to resume from, so the whole file was
    /// read.
    pub first: bool,
    /// Whether the file had been rotated or truncated since the cursor.
    pub rotated: bool,
    /// Bytes read, the rotated copy's remainder included.
    pub bytes: u64,
}

/// Reads every complete line of `path` that `from` has not seen, calling
/// `visit` with each. See the module docs for how a rotation is handled.
pub fn read_from(
    path: &Path,
    from: Option<FileCursor>,
    visit: &mut dyn FnMut(&str),
) -> io::Result<FileRead> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let (dev, ino, len) = (meta.dev(), meta.ino(), meta.len());

    let mut bytes = 0;
    let (start, rotated) = match from {
        Some(cursor) if cursor.dev == dev && cursor.ino == ino => {
            let same_head = head_digest(&mut file, cursor.head_len)? == Some(cursor.head);
            if cursor.offset <= len && same_head {
                (cursor.offset, false)
            } else {
                // Shorter than we left it, or starting differently: the
                // same inode holds a different log now.
                (0, true)
            }
        }
        Some(cursor) => {
            bytes += drain_rotated_copy(path, cursor, visit);
            (0, true)
        }
        None => (0, false),
    };

    let end = stream(&mut file, start, true, visit)?;
    bytes += end - start;
    let head_len = end.min(HEAD_BYTES);
    let head = head_digest(&mut file, head_len)?.unwrap_or_default();
    Ok(FileRead {
        cursor: FileCursor {
            dev,
            ino,
            offset: end,
            head,
            head_len,
        },
        first: from.is_none(),
        rotated,
        bytes,
    })
}

/// A cursor at `offset` into `path` as it is now, or at its start if it is
/// shorter than that. For picking up where something other than a cursor
/// left off: the byte count 0.0.x kept for the access-stats tally.
pub fn cursor_at(path: &Path, offset: u64) -> io::Result<FileCursor> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let offset = if offset <= meta.len() { offset } else { 0 };
    let head_len = offset.min(HEAD_BYTES);
    Ok(FileCursor {
        dev: meta.dev(),
        ino: meta.ino(),
        offset,
        head: head_digest(&mut file, head_len)?.unwrap_or_default(),
        head_len,
    })
}

/// The rest of a rotated file, if logrotate left it at `<path>.1` and it
/// is the one `cursor` was reading. Best effort: a copy that is not there,
/// or is not that file, means the lines are gone, which is what happened
/// to them before this existed too.
fn drain_rotated_copy(path: &Path, cursor: FileCursor, visit: &mut dyn FnMut(&str)) -> u64 {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    let rotated = PathBuf::from(name);
    let Ok(mut file) = File::open(&rotated) else {
        return 0;
    };
    let Ok(meta) = file.metadata() else {
        return 0;
    };
    if meta.dev() != cursor.dev
        || meta.ino() != cursor.ino
        || meta.len() < cursor.offset
        || head_digest(&mut file, cursor.head_len).ok().flatten() != Some(cursor.head)
    {
        return 0;
    }
    // Complete lines and the last one too: nothing will ever be appended
    // to a rotated file, so an unterminated line there is as whole as it
    // will get.
    stream(&mut file, cursor.offset, false, visit)
        .map(|end| end - cursor.offset)
        .unwrap_or(0)
}

/// Every line of `path`, the last one too whether or not it has a newline.
/// For the readers that want the whole file once rather than what is new.
pub fn read_whole(path: &Path, visit: &mut dyn FnMut(&str)) -> io::Result<()> {
    let mut file = File::open(path)?;
    stream(&mut file, 0, false, visit).map(|_| ())
}

/// Every line in the last `max_bytes` of `path`, starting at the first
/// line boundary inside them. For a report about what a log looks like,
/// which a recent sample answers as well as the whole file.
pub fn read_tail(path: &Path, max_bytes: u64, visit: &mut dyn FnMut(&str)) -> io::Result<()> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len <= max_bytes {
        return stream(&mut file, 0, false, visit).map(|_| ());
    }
    // Start one byte early, so a tail that begins exactly on a line
    // boundary keeps its first line, and drop everything up to the first
    // newline: the partial line it lands in.
    let start = len - max_bytes - 1;
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    let mut skipped = Vec::new();
    let partial = reader.read_until(b'\n', &mut skipped)? as u64;
    stream_reader(reader, start + partial, false, visit).map(|_| ())
}

/// Reads lines from `start`, returning the offset just past the last line
/// read. With `complete_only`, an unterminated last line is not read, and
/// the offset stays before it.
fn stream(
    file: &mut File,
    start: u64,
    complete_only: bool,
    visit: &mut dyn FnMut(&str),
) -> io::Result<u64> {
    file.seek(SeekFrom::Start(start))?;
    stream_reader(BufReader::new(file), start, complete_only, visit)
}

fn stream_reader<R: Read>(
    mut reader: BufReader<R>,
    start: u64,
    complete_only: bool,
    visit: &mut dyn FnMut(&str),
) -> io::Result<u64> {
    let mut offset = start;
    let mut line = Vec::with_capacity(512);
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(offset);
        }
        let terminated = line.last() == Some(&b'\n');
        if !terminated && complete_only {
            return Ok(offset);
        }
        offset += read as u64;
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        // Lossy, one line at a time: the bytes are the client's, and one
        // that is not UTF-8 must not make the rest of the file unreadable.
        visit(&String::from_utf8_lossy(body));
    }
}

/// What to ask journald for.
#[derive(Debug, Clone)]
pub struct JournalQuery<'a> {
    /// The binary to run. `journalctl`, except in tests.
    pub program: &'a Path,
    /// Units to match, any of them.
    pub units: &'a [&'a str],
    /// Only entries after this cursor, from an earlier read.
    pub after_cursor: Option<&'a str>,
    /// Only entries at or after this Unix time.
    pub since: Option<i64>,
    /// Only the newest this many entries.
    pub last: Option<usize>,
}

impl<'a> JournalQuery<'a> {
    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for unit in self.units {
            args.push("-u".to_string());
            args.push(unit.to_string());
        }
        // `short-iso`, not `cat`: `cat` drops the timestamp, and a window
        // needs it. The message is the same either way.
        args.extend(["-o", "short-iso", "--no-pager", "-q", "--show-cursor"].map(String::from));
        if let Some(cursor) = self.after_cursor {
            args.push(format!("--after-cursor={cursor}"));
        } else if let Some(since) = self.since {
            args.push(format!("--since=@{since}"));
        }
        if let Some(last) = self.last {
            args.push(format!("--lines={last}"));
        }
        args
    }
}

/// What one journal read did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRead {
    /// The cursor of the last entry read, if any was.
    pub cursor: Option<String>,
    /// How many entries were read.
    pub lines: usize,
}

/// Streams the entries `query` matches through `visit`. An error when
/// `journalctl` could not be run or said it failed.
pub fn read_journal(query: &JournalQuery, visit: &mut dyn FnMut(&str)) -> io::Result<JournalRead> {
    let mut child = Command::new(query.program)
        .args(query.args())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("journalctl gave no output pipe"))?;
    let mut cursor = None;
    let mut lines = 0;
    let streamed = stream_reader(BufReader::new(stdout), 0, false, &mut |line| {
        if let Some(found) = line.strip_prefix("-- cursor: ") {
            cursor = Some(found.trim().to_string());
        } else if !line.starts_with("-- ") {
            lines += 1;
            visit(line);
        }
    });
    let status = child.wait()?;
    streamed?;
    if !status.success() {
        return Err(io::Error::other(format!("journalctl exited with {status}")));
    }
    Ok(JournalRead { cursor, lines })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn lines_of(path: &Path, from: Option<FileCursor>) -> (Vec<String>, FileRead) {
        let mut lines = Vec::new();
        let read = read_from(path, from, &mut |line| lines.push(line.to_string())).unwrap();
        (lines, read)
    }

    fn append(path: &Path, text: &str) {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    #[test]
    fn a_cursor_round_trips_through_its_stored_form() {
        let cursor = FileCursor {
            dev: 2049,
            ino: 1_234_567,
            offset: 987,
            head: 0xdead_beef,
            head_len: 256,
        };
        assert_eq!(FileCursor::decode(&cursor.encode()), Some(cursor));
        assert_eq!(FileCursor::decode("file 1 2 3"), None);
        assert_eq!(FileCursor::decode("journal s=abc"), None);
    }

    /// The property the whole design rests on: a second read sees only
    /// what was appended since the first.
    #[test]
    fn a_second_read_sees_only_what_was_appended() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "one\ntwo\n");

        let (lines, first) = lines_of(&log, None);
        assert_eq!(lines, ["one", "two"]);
        assert!(first.first);

        append(&log, "three\n");
        let (lines, second) = lines_of(&log, Some(first.cursor));
        assert_eq!(lines, ["three"]);
        assert!(!second.first && !second.rotated);

        let (lines, _) = lines_of(&log, Some(second.cursor));
        assert!(lines.is_empty(), "nothing new is nothing: {lines:?}");
    }

    /// A line still being written is not half a line.
    #[test]
    fn an_unterminated_last_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "one\ntw");

        let (lines, read) = lines_of(&log, None);
        assert_eq!(lines, ["one"]);

        append(&log, "o\n");
        let (lines, _) = lines_of(&log, Some(read.cursor));
        assert_eq!(lines, ["two"]);
    }

    /// logrotate's `copytruncate`: same file, now shorter.
    #[test]
    fn a_truncated_file_is_read_again_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "old one\nold two\n");
        let (_, read) = lines_of(&log, None);

        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&log)
            .unwrap();
        append(&log, "new\n");

        let (lines, again) = lines_of(&log, Some(read.cursor));
        assert_eq!(lines, ["new"]);
        assert!(again.rotated);
    }

    /// The default rotation: renamed to `.1`, a new file created. The lines
    /// the old one got after the last read are read from `.1`, then the new
    /// file from its start.
    #[test]
    fn a_rotated_file_is_finished_from_its_copy_then_read_anew() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "seen\n");
        let (_, read) = lines_of(&log, None);
        append(&log, "late\n");

        std::fs::rename(&log, dir.path().join("access.log.1")).unwrap();
        append(&log, "fresh\n");

        let (lines, again) = lines_of(&log, Some(read.cursor));
        assert_eq!(lines, ["late", "fresh"]);
        assert!(again.rotated);
        assert_eq!(again.cursor.offset, 6, "the cursor is the new file's");
    }

    /// Without the copy (compressed at once, or deleted) the new file is
    /// still read, and nothing is read twice -- even when the filesystem
    /// gives the new file the old one's inode, which it readily does.
    #[test]
    fn a_rotated_file_with_no_copy_is_read_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "seen\n");
        let (_, read) = lines_of(&log, None);
        std::fs::remove_file(&log).unwrap();
        append(&log, "fresh\n");

        let (lines, _) = lines_of(&log, Some(read.cursor));
        assert_eq!(lines, ["fresh"]);
    }

    #[test]
    fn a_line_that_is_not_utf8_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("auth.log");
        std::fs::write(&log, b"bad \xff byte\nfine\n").unwrap();
        let (lines, _) = lines_of(&log, None);
        assert_eq!(lines, ["bad \u{fffd} byte", "fine"]);
    }

    #[test]
    fn a_tail_starts_at_a_line_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "aaaa\nbbbb\ncccc\n");
        let mut lines = Vec::new();
        read_tail(&log, 7, &mut |line| lines.push(line.to_string())).unwrap();
        assert_eq!(lines, ["cccc"], "the partial bbbb is dropped");

        let mut lines = Vec::new();
        read_tail(&log, 10, &mut |line| lines.push(line.to_string())).unwrap();
        assert_eq!(lines, ["bbbb", "cccc"], "exactly on a boundary");
    }

    /// A stand-in for `journalctl` that prints what it was asked, then two
    /// entries and a cursor, the way the real one does.
    fn fake_journalctl(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("journalctl");
        std::fs::write(
            &path,
            "#!/bin/sh\n\
             echo \"$@\" > \"$(dirname \"$0\")/args\"\n\
             echo '2026-09-28T06:33:01+0000 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2'\n\
             echo '2026-09-28T06:33:02+0000 host sshd[1]: Accepted publickey for m from 192.0.2.10 port 2 ssh2'\n\
             echo '-- cursor: s=abc;i=2'\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn a_journal_read_keeps_the_timestamps_and_returns_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_journalctl(dir.path());
        let mut lines = Vec::new();
        let read = read_journal(
            &JournalQuery {
                program: &program,
                units: &["ssh", "sshd"],
                after_cursor: Some("s=prev"),
                since: None,
                last: None,
            },
            &mut |line| lines.push(line.to_string()),
        )
        .unwrap();

        assert_eq!(read.cursor.as_deref(), Some("s=abc;i=2"));
        assert_eq!(read.lines, 2);
        assert!(lines[0].starts_with("2026-09-28T06:33:01"), "{lines:?}");
        let args = std::fs::read_to_string(dir.path().join("args")).unwrap();
        for needle in [
            "-o short-iso",
            "--show-cursor",
            "--after-cursor=s=prev",
            "-u ssh -u sshd",
        ] {
            assert!(args.contains(needle), "{needle:?} not in {args}");
        }
        assert!(!args.contains("-o cat"), "{args}");
    }

    #[test]
    fn a_first_journal_read_asks_only_for_its_window() {
        let query = JournalQuery {
            program: Path::new("journalctl"),
            units: &["ssh"],
            after_cursor: None,
            since: Some(1_790_577_181),
            last: None,
        };
        assert!(query.args().contains(&"--since=@1790577181".to_string()));
    }

    #[test]
    fn a_journal_that_cannot_be_run_is_an_error() {
        let result = read_journal(
            &JournalQuery {
                program: Path::new("/nonexistent/journalctl"),
                units: &["ssh"],
                after_cursor: None,
                since: None,
                last: None,
            },
            &mut |_| {},
        );
        assert!(result.is_err());
    }
}
