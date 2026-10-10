/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
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
//! ## How much one read takes
//!
//! [`read_chunk`] stops after a budget of bytes, at a line boundary, and
//! says whether there is more; the cursor it returns is where the next
//! read picks up, in the rotated copy if that is where it stopped. That is
//! what lets the root helper serve a large log a piece at a time, each
//! piece bounded in time and in memory (see [`crate::hostlog`]). A line
//! longer than [`MAX_LINE`] is read past rather than held: no log this
//! project reads writes one, and holding it would let one line take as
//! much memory as it likes.
//!
//! journald has cursors of its own, which [`read_journal`] passes through.
//! It is read as JSON, which carries each entry's cursor, so that a read
//! can stop after any entry and say where the next one starts.

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

/// The longest line a read hands on, in bytes. A longer one is read past
/// and not handed on: see the module docs.
pub const MAX_LINE: usize = 64 * 1024;

/// What one incremental read of a file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRead {
    /// Where the next read resumes.
    pub cursor: FileCursor,
    /// Whether there was no cursor to resume from, so the file was read
    /// from its start.
    pub first: bool,
    /// Whether the file had been rotated or truncated since the cursor.
    pub rotated: bool,
    /// Bytes read, the rotated copy's remainder included.
    pub bytes: u64,
    /// Whether the read stopped at its budget rather than at the end, so
    /// there may be more to read from [`Self::cursor`].
    pub more: bool,
}

/// Reads every complete line of `path` that `from` has not seen, calling
/// `visit` with each, and stops at the first line boundary at or after
/// `budget` bytes. The cursor it returns resumes the read exactly there,
/// in the rotated copy if that is where the budget ran out. See the module
/// docs for how a rotation is handled.
pub fn read_chunk(
    path: &Path,
    from: Option<FileCursor>,
    budget: u64,
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
        Some(cursor) => match drain_rotated_copy(path, cursor, budget, visit) {
            // The budget ran out in the copy: the next read carries on
            // there, with the copy's own cursor.
            Drained::Partly(cursor, read) => {
                return Ok(FileRead {
                    cursor,
                    first: false,
                    rotated: true,
                    bytes: read,
                    more: true,
                })
            }
            Drained::Finished(read) => {
                bytes += read;
                (0, true)
            }
        },
        None => (0, false),
    };

    let (end, more) = stream(&mut file, start, true, budget.saturating_sub(bytes), visit)?;
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
        more,
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

/// How far [`drain_rotated_copy`] got.
enum Drained {
    /// To the end of the copy, or there was no copy to read: this many
    /// bytes.
    Finished(u64),
    /// This many bytes, and then the budget ran out; the cursor is where
    /// in the copy the next read carries on.
    Partly(FileCursor, u64),
}

/// The rest of a rotated file, if logrotate left it at `<path>.1` and it
/// is the one `cursor` was reading, as far as `budget` goes. Best effort:
/// a copy that is not there, or is not that file, means the lines are
/// gone, which is what happened to them before this existed too.
fn drain_rotated_copy(
    path: &Path,
    cursor: FileCursor,
    budget: u64,
    visit: &mut dyn FnMut(&str),
) -> Drained {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    let rotated = PathBuf::from(name);
    let Ok(mut file) = File::open(&rotated) else {
        return Drained::Finished(0);
    };
    let Ok(meta) = file.metadata() else {
        return Drained::Finished(0);
    };
    if meta.dev() != cursor.dev
        || meta.ino() != cursor.ino
        || meta.len() < cursor.offset
        || head_digest(&mut file, cursor.head_len).ok().flatten() != Some(cursor.head)
    {
        return Drained::Finished(0);
    }
    // Complete lines and the last one too: nothing will ever be appended
    // to a rotated file, so an unterminated line there is as whole as it
    // will get.
    match stream(&mut file, cursor.offset, false, budget, visit) {
        Ok((end, true)) => Drained::Partly(
            FileCursor {
                offset: end,
                ..cursor
            },
            end - cursor.offset,
        ),
        Ok((end, false)) => Drained::Finished(end - cursor.offset),
        Err(_) => Drained::Finished(0),
    }
}

/// Every line in the last `max_bytes` of `path`, starting at the first
/// line boundary inside them. For a report about what a log looks like,
/// which a recent sample answers as well as the whole file.
pub fn read_tail(path: &Path, max_bytes: u64, visit: &mut dyn FnMut(&str)) -> io::Result<()> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len <= max_bytes {
        return stream(&mut file, 0, false, u64::MAX, visit).map(|_| ());
    }
    // Start one byte early, so a tail that begins exactly on a line
    // boundary keeps its first line, and drop everything up to the first
    // newline: the partial line it lands in.
    let start = len - max_bytes - 1;
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    let mut skipped = Vec::new();
    let (partial, _) = next_line(&mut reader, &mut skipped)?;
    stream_reader(reader, start + partial as u64, false, u64::MAX, visit).map(|_| ())
}

/// Reads lines from `start` until `budget` bytes have been read, and
/// returns the offset just past the last line read and whether the budget
/// stopped it. With `complete_only`, an unterminated last line is not
/// read, and the offset stays before it.
fn stream(
    file: &mut File,
    start: u64,
    complete_only: bool,
    budget: u64,
    visit: &mut dyn FnMut(&str),
) -> io::Result<(u64, bool)> {
    file.seek(SeekFrom::Start(start))?;
    stream_reader(BufReader::new(file), start, complete_only, budget, visit)
}

fn stream_reader<R: Read>(
    mut reader: BufReader<R>,
    start: u64,
    complete_only: bool,
    budget: u64,
    visit: &mut dyn FnMut(&str),
) -> io::Result<(u64, bool)> {
    let mut offset = start;
    let mut line = Vec::with_capacity(512);
    loop {
        if offset - start >= budget {
            return Ok((offset, true));
        }
        line.clear();
        let (read, terminated) = next_line(&mut reader, &mut line)?;
        if read == 0 || (!terminated && complete_only) {
            return Ok((offset, false));
        }
        offset += read as u64;
        let body = line.strip_suffix(b"\n").unwrap_or(&line);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        // Held only as far as `MAX_LINE` and a little, so this is a line
        // that was longer, and is passed over.
        if read > line.len() || body.len() > MAX_LINE {
            continue;
        }
        // Lossy, one line at a time: the bytes are the client's, and one
        // that is not UTF-8 must not make the rest of the file unreadable.
        visit(&String::from_utf8_lossy(body));
    }
}

/// Reads one line, its newline included, into `line`, but keeps no more
/// of it than [`MAX_LINE`] and its line ending: a longer line is consumed
/// whole and held only that far. Returns the bytes consumed and whether
/// the line ended in a newline.
fn next_line<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> io::Result<(usize, bool)> {
    let mut consumed = 0;
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if available.is_empty() {
            return Ok((consumed, false));
        }
        let (take, ends) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        let room = (MAX_LINE + 2).saturating_sub(line.len());
        line.extend_from_slice(&available[..take.min(room)]);
        reader.consume(take);
        consumed += take;
        if ends {
            return Ok((consumed, true));
        }
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
    /// Stop after the entry that takes the lines read to this many bytes.
    pub max_bytes: Option<u64>,
}

impl<'a> JournalQuery<'a> {
    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for unit in self.units {
            args.push("-u".to_string());
            args.push(unit.to_string());
        }
        // JSON, not `short-iso`: every entry carries its own cursor, so a
        // read can stop after any of them. Each is printed as `short-iso`
        // would print it (see `journal_line`); `cat` would drop the time,
        // and a window needs it.
        args.extend(["-o", "json", "--no-pager", "-q"].map(String::from));
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
    /// Whether [`JournalQuery::max_bytes`] stopped the read before the
    /// journal ran out.
    pub more: bool,
}

/// Streams the entries `query` matches through `visit`, each as one
/// `short-iso` line. An error when `journalctl` could not be run or said
/// it failed.
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
    let budget = query.max_bytes.unwrap_or(u64::MAX);
    let mut cursor = None;
    let mut lines = 0;
    let mut bytes = 0u64;
    let mut more = false;
    let mut reader = BufReader::new(stdout);
    let mut raw = Vec::with_capacity(1024);
    let streamed = loop {
        if bytes >= budget {
            more = true;
            break Ok(());
        }
        raw.clear();
        // Counted as JSON, which is longer than the line it becomes, so
        // the budget bounds both the work and what is handed on.
        match next_line(&mut reader, &mut raw) {
            Ok((0, _)) => break Ok(()),
            Ok((read, _)) => bytes += read as u64,
            Err(err) => break Err(err),
        }
        // An entry is one line of JSON; one longer than a line may be is
        // not one this reads, and one that does not parse is not one
        // journald wrote.
        let Some(entry) = (raw.len() <= MAX_LINE)
            .then(|| serde_json::from_slice::<JournalEntry>(&raw).ok())
            .flatten()
        else {
            // Still a place in the journal, if its cursor can be read: a
            // run of such entries longer than the budget must not keep the
            // next read starting before all of them.
            if let Some(skipped) = leading_cursor(&raw) {
                cursor = Some(skipped);
            }
            continue;
        };
        let line = entry.line();
        lines += 1;
        visit(&line);
        cursor = Some(entry.cursor);
    };
    if more {
        // Stopped early on purpose: what it had left to say is unwanted.
        let _ = child.kill();
        let _ = child.wait();
        streamed?;
        return Ok(JournalRead {
            cursor,
            lines,
            more,
        });
    }
    let status = child.wait()?;
    streamed?;
    if !status.success() {
        return Err(io::Error::other(format!("journalctl exited with {status}")));
    }
    Ok(JournalRead {
        cursor,
        lines,
        more,
    })
}

/// The cursor of an entry of `journalctl -o json` that is not read
/// whole: the first field `journalctl` prints, so it is there even in the
/// part of a long entry that is kept.
fn leading_cursor(raw: &[u8]) -> Option<String> {
    // `{"__CURSOR":"…"`, or with spaces around the colon, as older
    // versions print it.
    let text = String::from_utf8_lossy(&raw[..raw.len().min(1024)]);
    let rest = text.trim_start().strip_prefix('{')?.trim_start();
    let rest = rest.strip_prefix("\"__CURSOR\"")?.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start().strip_prefix('"')?;
    let cursor = &rest[..rest.find('"')?];
    cursor
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'=' || b == b';')
        .then(|| cursor.to_string())
}

/// One entry of `journalctl -o json`: the fields a `short-iso` line is
/// made of, and the entry's cursor.
#[derive(serde::Deserialize)]
struct JournalEntry {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime: Option<serde_json::Value>,
    #[serde(rename = "_HOSTNAME")]
    hostname: Option<serde_json::Value>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    identifier: Option<serde_json::Value>,
    #[serde(rename = "_COMM")]
    comm: Option<serde_json::Value>,
    #[serde(rename = "_PID")]
    pid: Option<serde_json::Value>,
    #[serde(rename = "SYSLOG_PID")]
    syslog_pid: Option<serde_json::Value>,
    #[serde(rename = "MESSAGE")]
    message: Option<serde_json::Value>,
}

impl JournalEntry {
    /// The entry as `journalctl -o short-iso` prints it, in UTC:
    /// `2026-09-28T06:33:01+0000 host sshd[123]: <message>`. The tag is
    /// the identifier, or the command, and the pid, as `short-iso` takes
    /// them.
    ///
    /// A line break in the message is a space here. The message is partly
    /// the client's (sshd logs the username it was sent), and a newline in
    /// it must not become a second line that reads as sshd's own.
    fn line(&self) -> String {
        let text = |field: &Option<serde_json::Value>| field.as_ref().and_then(journal_text);
        let at = text(&self.realtime)
            .and_then(|micros| micros.parse::<i64>().ok())
            .map(|micros| {
                let (y, mo, d, h, mi, s) = crate::logtime::civil(micros.div_euclid(1_000_000));
                format!("{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+0000")
            })
            .unwrap_or_default();
        let host = text(&self.hostname).unwrap_or_default();
        let tag = text(&self.identifier)
            .or_else(|| text(&self.comm))
            .unwrap_or_default();
        let pid = text(&self.pid)
            .or_else(|| text(&self.syslog_pid))
            .map(|pid| format!("[{pid}]"))
            .unwrap_or_default();
        let message = text(&self.message).unwrap_or_default();
        let line = format!("{at} {host} {tag}{pid}: {message}");
        line.replace(['\n', '\r'], " ")
    }
}

/// A journal field's text: a string as it is, bytes (which is how JSON
/// carries a value that is not UTF-8) decoded lossily, and the first of a
/// field that appears more than once.
fn journal_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Array(items) if items.iter().all(|item| item.is_u64()) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|item| item.as_u64())
                .map(|byte| byte as u8)
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        serde_json::Value::Array(items) => items.first().and_then(journal_text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn lines_of(path: &Path, from: Option<FileCursor>) -> (Vec<String>, FileRead) {
        let mut lines = Vec::new();
        let read = read_chunk(path, from, u64::MAX, &mut |line| {
            lines.push(line.to_string())
        })
        .unwrap();
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

    /// A file read a budget at a time is the same lines as read whole, and
    /// each read stops at the first line boundary past its budget.
    #[test]
    fn a_file_read_in_chunks_is_the_same_lines_as_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        let lines: Vec<String> = (0..50).map(|n| format!("line {n}")).collect();
        append(&log, &(lines.join("\n") + "\n"));

        let mut seen = Vec::new();
        let mut cursor = None;
        let mut reads = 0;
        loop {
            let read =
                read_chunk(&log, cursor, 20, &mut |line| seen.push(line.to_string())).unwrap();
            reads += 1;
            assert!(
                read.bytes < 20 + 8,
                "{} bytes past a 20-byte budget",
                read.bytes
            );
            cursor = Some(read.cursor);
            if !read.more {
                break;
            }
        }

        assert_eq!(seen, lines);
        assert!(reads > 10, "read in {reads} chunks");
    }

    /// A rotation found half-way through the old file's remainder: the
    /// copy is finished a chunk at a time, then the new file is read, and
    /// no line is lost or read twice.
    #[test]
    fn a_rotated_copy_is_finished_in_chunks_before_the_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(&log, "seen\n");
        let (_, read) = lines_of(&log, None);
        let late: Vec<String> = (0..20).map(|n| format!("late {n}")).collect();
        append(&log, &(late.join("\n") + "\n"));
        std::fs::rename(&log, dir.path().join("access.log.1")).unwrap();
        append(&log, "fresh\n");

        let mut seen = Vec::new();
        let mut cursor = Some(read.cursor);
        loop {
            let read =
                read_chunk(&log, cursor, 30, &mut |line| seen.push(line.to_string())).unwrap();
            cursor = Some(read.cursor);
            if !read.more {
                break;
            }
        }

        let mut expected = late.clone();
        expected.push("fresh".to_string());
        assert_eq!(seen, expected);
    }

    /// One line longer than any log writes is read past, not held, and
    /// the lines around it are read as ever.
    #[test]
    fn an_overlong_line_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        append(
            &log,
            &format!("before\n{}\nafter\n", "x".repeat(MAX_LINE + 10)),
        );

        let (lines, read) = lines_of(&log, None);

        assert_eq!(lines, ["before", "after"]);
        assert_eq!(read.cursor.offset, std::fs::metadata(&log).unwrap().len());
    }

    const SEP_28: i64 = 1_790_577_181;

    fn sshd_entries(dir: &Path) -> PathBuf {
        use crate::testing::journal_entry;
        crate::testing::fake_journalctl(
            dir,
            &format!(
                "echo '{}'\necho '{}'\n",
                journal_entry(
                    "s=abc;i=1",
                    SEP_28,
                    "Failed password for root from 203.0.113.5 port 1 ssh2"
                ),
                journal_entry(
                    "s=abc;i=2",
                    SEP_28 + 1,
                    "Accepted publickey for m from 192.0.2.10 port 2 ssh2"
                ),
            ),
        )
    }

    fn query(program: &Path) -> JournalQuery<'_> {
        JournalQuery {
            program,
            units: &["ssh", "sshd"],
            after_cursor: None,
            since: None,
            last: None,
            max_bytes: None,
        }
    }

    #[test]
    fn a_journal_read_prints_entries_as_short_iso_and_returns_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let program = sshd_entries(dir.path());
        let mut lines = Vec::new();
        let read = read_journal(
            &JournalQuery {
                after_cursor: Some("s=prev"),
                ..query(&program)
            },
            &mut |line| lines.push(line.to_string()),
        )
        .unwrap();

        assert_eq!(read.cursor.as_deref(), Some("s=abc;i=2"));
        assert_eq!((read.lines, read.more), (2, false));
        assert_eq!(
            lines[0],
            "2026-09-28T06:33:01+0000 host sshd[1]: Failed password for root from 203.0.113.5 \
             port 1 ssh2"
        );
        let args = crate::testing::journalctl_calls(dir.path()).join("\n");
        for needle in ["-o json", "--after-cursor=s=prev", "-u ssh -u sshd"] {
            assert!(args.contains(needle), "{needle:?} not in {args}");
        }
    }

    /// A budget stops the read after an entry, and the cursor is that
    /// entry's: where the next read starts.
    #[test]
    fn a_journal_read_stops_at_its_budget_with_that_entry_s_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let program = sshd_entries(dir.path());
        let mut lines = Vec::new();
        let read = read_journal(
            &JournalQuery {
                max_bytes: Some(1),
                ..query(&program)
            },
            &mut |line| lines.push(line.to_string()),
        )
        .unwrap();

        assert_eq!(read.cursor.as_deref(), Some("s=abc;i=1"));
        assert_eq!((read.lines, read.more), (1, true));
        assert_eq!(lines.len(), 1);
    }

    /// sshd logs the username a client sends. A newline in it must not
    /// make a second line, which could read as sshd's own.
    #[test]
    fn a_newline_in_a_journal_message_does_not_start_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let forged = "Invalid user x\n2026-09-28T06:33:01+0000 host sshd[1]: Accepted publickey \
                      for m from 192.0.2.66 port 2 ssh2 from 203.0.113.5 port 1";
        let program = crate::testing::fake_journalctl(
            dir.path(),
            &format!(
                "printf '%s\\n' '{}'",
                crate::testing::journal_entry("s=1", SEP_28, forged)
            ),
        );
        let mut lines = Vec::new();
        read_journal(&query(&program), &mut |line| lines.push(line.to_string())).unwrap();

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            crate::sshlog::parse_accepted_ips(&lines.join("\n")).is_empty(),
            "{lines:?}"
        );
    }

    /// An entry too long to read is passed over, but its cursor is still
    /// where the next read starts: a run of them must not hold every read
    /// before it.
    #[test]
    fn an_overlong_journal_entry_is_passed_over_but_moves_the_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let program = crate::testing::fake_journalctl(
            dir.path(),
            &format!(
                "echo '{}'\necho '{}'\n",
                crate::testing::journal_entry(
                    "s=1",
                    SEP_28,
                    "Failed password for root from 203.0.113.5 port 1 ssh2"
                ),
                crate::testing::journal_entry("s=2", SEP_28, &"x".repeat(MAX_LINE + 1)),
            ),
        );
        let mut lines = Vec::new();
        let read =
            read_journal(&query(&program), &mut |line| lines.push(line.to_string())).unwrap();

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(read.cursor.as_deref(), Some("s=2"));
        assert_eq!(
            leading_cursor(br#"{ "__CURSOR" : "s=3;i=4", "MESSAGE" : "x"#).as_deref(),
            Some("s=3;i=4"),
            "as older journalctl prints it"
        );
    }

    #[test]
    fn a_first_journal_read_asks_only_for_its_window() {
        let query = JournalQuery {
            since: Some(1_790_577_181),
            ..query(Path::new("journalctl"))
        };
        assert!(query.args().contains(&"--since=@1790577181".to_string()));
    }

    #[test]
    fn a_journal_that_cannot_be_run_is_an_error() {
        let result = read_journal(&query(Path::new("/nonexistent/journalctl")), &mut |_| {});
        assert!(result.is_err());
    }
}
