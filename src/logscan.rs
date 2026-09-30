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

//! Each log read once per pass, from where the last pass stopped, into
//! the evidence every detector decides on.
//!
//! ## What this replaced
//!
//! Every detector job read, decoded and parsed the whole access log for
//! itself, about ten full reads a minute at roughly twice the file's size
//! in memory each, and the TUI started them all at once. On a 200 MB log
//! that was 440 MB for one pass of the web console and 2.9 GB for the
//! TUI's first minute. And because each read counted over the whole file,
//! a block that expired was re-added from the same old lines.
//!
//! ## The three halves of a pass
//!
//! A pass is split the way every slow job in this project is, so that no
//! front-end holds its database, or its event loop, across the slow part:
//!
//! - [`plan`] reads the database: which logs are wanted, where each read
//!   resumes, what the detectors look for. Quick; under the web console's
//!   lock, or on the TUI's main thread.
//! - [`read`] reads and parses the logs, and touches no database: it
//!   cannot, it is given none. Slow; on a blocking thread, outside the
//!   lock. It streams a line at a time, so its memory is the evidence it
//!   collects, not the file.
//! - [`apply`] stores what the read found and where the next one resumes
//!   (see `db::evidence::Ingest`), and prunes what has fallen out of every
//!   window. Back under the lock; the web console takes it a chunk at a
//!   time ([`store`]), so a large read does not hold it for all of it.
//!
//! Then each due job decides from the stored evidence: see
//! `cron::run_log_jobs`.
//!
//! ## Which logs, and when
//!
//! A log is read when a due job wants it and not otherwise: the access log
//! for access-stats and any access-log detector that is on, the SSH log
//! for the SSH detector's job (on or off: the logins it records keep the
//! anti-lockout window fed) and the firewall render's guard.
//!
//! A read feeds *every* consumer of that log, due or not, because the
//! cursor moves past the lines for all of them at once.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::accesslog::{self, Clock, Counts, Watch};
use crate::cron::CronJob;
use crate::db::evidence::{Ingest, IngestStep, INGEST_CHUNK};
use crate::db::Db;
use crate::evidence::Evidence;
use crate::logread::{self, FileCursor};
use crate::protection::Detector;
use crate::sshlog::{self, Located, SshSource};

/// The logs a pass may read: flags from the command line, which win over
/// the stored paths (see [`crate::logpaths`]).
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub ssh_log: Option<PathBuf>,
    pub access_log: Option<PathBuf>,
}

/// What a pass will read, resolved from the database. Holds no handle to
/// it, so it can go to another thread.
#[derive(Debug, Clone)]
pub struct Plan {
    now: i64,
    access: Option<AccessPlan>,
    ssh: Option<SshPlan>,
    /// `journalctl`, except in tests.
    journalctl: PathBuf,
}

#[derive(Debug, Clone)]
struct AccessPlan {
    path: PathBuf,
    /// The cursor as stored, which the store compares against.
    stored: Option<String>,
    /// Where 0.0.x's access-stats tally stopped, for a log with no cursor
    /// yet: the first read starts there rather than counting the whole
    /// file into `user_agent_stats` a second time.
    legacy_offset: Option<u64>,
    watch: Watch,
}

#[derive(Debug, Clone)]
struct SshPlan {
    source: SshSource,
    /// The stored cursor of every place the SSH log might turn out to be.
    stored: HashMap<String, Option<String>>,
    /// The oldest a failed login may be and still count, when the SSH
    /// detector is on.
    cutoff: Option<i64>,
    /// How far back a first read of the journal looks. A file is read
    /// whole the first time (logrotate bounds it); the journal is bounded
    /// by nothing, and every login in the anti-lockout window is wanted.
    look_back: i64,
    /// Where [`SshSource::Search`] looks before the journal.
    search: Vec<PathBuf>,
}

impl Plan {
    /// Whether this pass reads anything at all.
    pub fn reads_anything(&self) -> bool {
        self.access.is_some() || self.ssh.is_some()
    }

    /// Reads the journal with `program` instead of `journalctl`.
    pub fn with_journalctl(mut self, program: &Path) -> Plan {
        self.journalctl = program.to_path_buf();
        self
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Whether `job` wants the access log.
fn wants_access_log(db: &Db, job: CronJob) -> Result<bool> {
    Ok(match job {
        CronJob::RecordAccessStats => true,
        CronJob::Detect(detector) => !detector.spec().uses_ssh_log && detector.is_enabled(db)?,
        _ => false,
    })
}

/// Whether `job` wants the SSH log.
fn wants_ssh_log(job: CronJob) -> bool {
    crate::cron::uses_ssh_log(job)
}

/// Works out what a pass over `jobs` reads.
pub fn plan(db: &Db, jobs: &[CronJob], flags: &Flags) -> Result<Plan> {
    let now = now();
    let paths = crate::logpaths::LogPaths::from_db(db).unwrap_or_default();

    let mut wants_access = false;
    for job in jobs {
        wants_access |= wants_access_log(db, *job)?;
    }
    let access = if wants_access {
        let path = paths.access_path(flags.access_log.as_deref());
        let source = source_key(&path);
        let stored = db.get_log_cursor(&source)?;
        let legacy_offset = match stored {
            Some(_) => None,
            None => legacy_offset(db, &path)?,
        };
        Some(AccessPlan {
            path,
            stored,
            legacy_offset,
            watch: watch(db, now)?,
        })
    } else {
        None
    };

    let ssh = if jobs.iter().any(|job| wants_ssh_log(*job)) {
        let source = paths.ssh(flags.ssh_log.as_deref());
        let search: Vec<PathBuf> = sshlog::DEFAULT_LOG_PATHS
            .iter()
            .map(PathBuf::from)
            .collect();
        let mut candidates: Vec<String> = match &source {
            SshSource::File(path) => vec![source_key(path)],
            SshSource::Search => search.iter().map(|p| source_key(p)).collect(),
        };
        candidates.push(sshlog::JOURNAL_SOURCE.to_string());
        let mut stored = HashMap::new();
        for key in candidates {
            let cursor = db.get_log_cursor(&key)?;
            stored.insert(key, cursor);
        }
        let detector = Detector::SshScanners;
        let window = detector.window_seconds(db)?;
        let cutoff = detector.is_enabled(db)?.then_some(now - window);
        Some(SshPlan {
            source,
            stored,
            cutoff,
            look_back: window.max(crate::db::SSH_LOGIN_WINDOW_SECONDS),
            search,
        })
    } else {
        None
    };

    Ok(Plan {
        now,
        access,
        ssh,
        journalctl: PathBuf::from("journalctl"),
    })
}

/// What every access-log detector that is on is looking for, and from
/// when.
fn watch(db: &Db, now: i64) -> Result<Watch> {
    let mut detectors = Vec::new();
    for detector in Detector::ALL {
        if !detector.spec().uses_ssh_log && detector.is_enabled(db)? {
            detectors.push((detector, Some(now - detector.window_seconds(db)?)));
        }
    }
    Ok(Watch {
        detectors,
        probe_paths: crate::protection::probe_paths(db)?,
        honeypot: crate::protection::honeypot_path(db)?,
        claims: crate::scanblock::crawler_claims(db)?,
        console: console(db)?,
    })
}

/// Where this host's web console is served, whose lines no detector reads
/// and the access stats do not count: see [`accesslog::Console`].
pub fn console(db: &Db) -> Result<accesslog::Console> {
    // A stored prefix the console itself would refuse to start with is
    // still the prefix NGINX was given, so it is read as it stands.
    let prefix = match crate::web::BasePath::from_db(db) {
        Ok(base) => base.as_str().to_string(),
        Err(_) => db
            .get_text_setting(crate::web::BASE_PATH_KEY)?
            .unwrap_or_default(),
    };
    Ok(accesslog::Console::new(
        &prefix,
        &crate::web::configured_hosts(db)?,
    ))
}

/// The access-stats offset 0.0.x kept for `path`.
///
/// Only under `path` itself. The internal cron used to key it by the
/// default path while reading a stored one, so on such a host the default
/// key may describe another file, and a start taken from another file's
/// offset would skip lines of this one. Counting a log's hits into
/// `user_agent_stats` a second time, once, is the smaller harm.
fn legacy_offset(db: &Db, path: &Path) -> Result<Option<u64>> {
    db.get_access_log_offset(&path.to_string_lossy())
}

/// The key a file's cursor is stored under: its path, as given.
fn source_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// What one read of one log came to.
#[derive(Debug, Clone)]
pub enum Outcome<T> {
    /// Nothing could be read. Carries what was tried, for a report.
    Unavailable(String),
    Read(LogRead<T>),
}

#[derive(Debug, Clone)]
pub struct LogRead<T> {
    /// The key its cursor is stored under.
    source: String,
    from: Option<String>,
    to: Option<String>,
    /// Bytes (a file) or entries (the journal) read.
    pub amount: u64,
    pub findings: T,
}

#[derive(Debug, Clone, Default)]
pub struct AccessFindings {
    pub evidence: Evidence,
    pub user_agents: HashMap<String, u64>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default)]
pub struct SshFindings {
    pub evidence: Evidence,
    /// Every address that logged in, in what was read.
    pub logins: Vec<String>,
}

/// Everything one pass read, not yet stored.
#[derive(Debug, Clone)]
pub struct Read {
    now: i64,
    pub access: Option<Outcome<AccessFindings>>,
    pub ssh: Option<Outcome<SshFindings>>,
}

/// Reads what `plan` asks for. Blocking, and deliberately without a `Db`:
/// see the module docs.
pub fn read(plan: &Plan) -> Read {
    Read {
        now: plan.now,
        access: plan
            .access
            .as_ref()
            .map(|access| read_access(access, plan.now)),
        ssh: plan
            .ssh
            .as_ref()
            .map(|ssh| read_ssh(ssh, plan.now, &plan.journalctl)),
    }
}

fn read_access(plan: &AccessPlan, now: i64) -> Outcome<AccessFindings> {
    let tried = plan.path.display().to_string();
    let start = match (&plan.stored, plan.legacy_offset) {
        (Some(stored), _) => FileCursor::decode(stored),
        (None, Some(offset)) => logread::cursor_at(&plan.path, offset).ok(),
        (None, None) => None,
    };
    // On a first read nothing dates an undated line, which may be months
    // old: it counts for nothing. After that, a line that was not there
    // last pass is from since then.
    let undated = start.is_some().then_some(now);
    let mut observer = accesslog::Observer::new(plan.watch.clone()).counting_user_agents();
    let clock = Clock::Logged { now, undated };
    let result = logread::read_from(&plan.path, start, &mut |line| observer.line(line, clock));
    match result {
        Ok(done) => {
            let (evidence, user_agents, counts) = observer.finish();
            Outcome::Read(LogRead {
                source: source_key(&plan.path),
                from: plan.stored.clone(),
                to: Some(done.cursor.encode()),
                amount: done.bytes,
                findings: AccessFindings {
                    evidence,
                    user_agents,
                    counts,
                },
            })
        }
        Err(_) => Outcome::Unavailable(tried),
    }
}

/// The stored form of a journal cursor.
const JOURNAL_CURSOR_PREFIX: &str = "journal ";

/// What an unreadable journal is reported as.
const JOURNAL_TRIED: &str = "journald (units sshd and ssh)";

/// The cursor of the newest sshd entry in the journal, if there is one.
fn newest_journal_cursor(journalctl: &Path) -> Option<String> {
    let query = logread::JournalQuery {
        program: journalctl,
        units: sshlog::journal_units(),
        after_cursor: None,
        since: None,
        last: Some(1),
    };
    logread::read_journal(&query, &mut |_| {}).ok()?.cursor
}

fn read_ssh(plan: &SshPlan, now: i64, journalctl: &Path) -> Outcome<SshFindings> {
    match plan.source.locate_among(&plan.search) {
        Located::File(path) => {
            let source = source_key(&path);
            let stored = plan.stored.get(&source).cloned().flatten();
            let start = stored.as_deref().and_then(FileCursor::decode);
            let mut observer =
                sshlog::Observer::new(plan.cutoff, now, start.is_some().then_some(now));
            match logread::read_from(&path, start, &mut |line| observer.line(line)) {
                Ok(done) => {
                    let (evidence, logins, _) = observer.finish();
                    Outcome::Read(LogRead {
                        source,
                        from: stored,
                        to: Some(done.cursor.encode()),
                        amount: done.bytes,
                        findings: SshFindings { evidence, logins },
                    })
                }
                Err(_) => Outcome::Unavailable(path.display().to_string()),
            }
        }
        Located::Journal => {
            let source = sshlog::JOURNAL_SOURCE.to_string();
            let stored = plan.stored.get(&source).cloned().flatten();
            let after = stored
                .as_deref()
                .and_then(|s| s.strip_prefix(JOURNAL_CURSOR_PREFIX));
            let query = logread::JournalQuery {
                program: journalctl,
                units: sshlog::journal_units(),
                after_cursor: after,
                since: Some(now - plan.look_back),
                last: None,
            };
            // Every entry `short-iso` prints is dated, so an undated line
            // is not one journald wrote.
            let mut observer = sshlog::Observer::new(plan.cutoff, now, None);
            let done = match logread::read_journal(&query, &mut |line| observer.line(line)) {
                Ok(done) => done,
                Err(_) => return Outcome::Unavailable(JOURNAL_TRIED.to_string()),
            };
            // A first read that found nothing in the look-back: a quiet
            // host, or a journal this user cannot see. The newest entry,
            // however old, tells the two apart, and its cursor is where the
            // next read starts.
            let cursor = match (&done.cursor, after) {
                (None, None) => newest_journal_cursor(journalctl),
                (cursor, _) => cursor.clone(),
            };
            // Readable is "it answered, and has at some point had something
            // to say": an unprivileged journalctl succeeds with nothing, and
            // that must not read as a log with no logins in it.
            if cursor.is_none() && after.is_none() {
                return Outcome::Unavailable(JOURNAL_TRIED.to_string());
            }
            let (evidence, logins, _) = observer.finish();
            Outcome::Read(LogRead {
                source,
                from: stored.clone(),
                to: cursor.map(|cursor| format!("{JOURNAL_CURSOR_PREFIX}{cursor}")),
                amount: done.lines as u64,
                findings: SshFindings { evidence, logins },
            })
        }
    }
}

/// Whether a log was there to read, after [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// No due job wanted it, so it was not read.
    NotRead,
    /// It could not be read; what was tried.
    Unavailable(String),
    /// It was read. `stored` is false when another process had already
    /// stored the same lines (see `Db::ingest`), in which case this pass
    /// added nothing, correctly.
    Read { stored: bool },
}

impl Availability {
    pub fn is_readable(&self) -> bool {
        matches!(self, Availability::Read { .. })
    }
}

/// What a pass stored, for the jobs that decide on it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub now: i64,
    pub access: Availability,
    pub ssh: Availability,
    /// Addresses that logged in over SSH, in what this pass read.
    pub logins: Vec<String>,
    /// The access-stats tally of what this pass read.
    pub stats: crate::accessstats::AccessStatsOutcome,
    /// Lines in the access log this pass read, and how many parsed.
    pub access_counts: Counts,
}

/// Stores what `read` found, all at once. See the module docs, and
/// [`store`] for the form that lets the database go between chunks.
pub fn apply(db: &Db, read: Read) -> Result<Applied> {
    let mut storing = store(read);
    loop {
        if let Some(applied) = storing.step(db)? {
            return Ok(applied);
        }
    }
}

/// Which log a [`Storing`] is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Log {
    Access,
    Ssh,
}

/// What a pass read, being stored one transaction at a time: each log's
/// findings a chunk at a time (see [`Ingest`]), then the pruning. Holds no
/// database, so the web console's cron can let the lock go between steps
/// and a large pass does not keep every request, `/login` included,
/// waiting for all of it.
pub struct Storing {
    applied: Applied,
    pending: Vec<(Log, Ingest)>,
    /// The access-stats tally, for when the access log's store is ours.
    stats: crate::accessstats::AccessStatsOutcome,
    /// The most rows a step writes.
    chunk: usize,
}

/// Starts storing what `read` found. Nothing is written until
/// [`Storing::step`].
pub fn store(read: Read) -> Storing {
    let mut applied = Applied {
        now: read.now,
        access: Availability::NotRead,
        ssh: Availability::NotRead,
        logins: Vec::new(),
        stats: crate::accessstats::AccessStatsOutcome::default(),
        access_counts: Counts::default(),
    };
    let mut pending = Vec::new();
    let mut stats = crate::accessstats::AccessStatsOutcome::default();

    match read.access {
        None => {}
        Some(Outcome::Unavailable(tried)) => applied.access = Availability::Unavailable(tried),
        Some(Outcome::Read(log)) => {
            let findings = log.findings;
            stats = crate::accessstats::AccessStatsOutcome::of(&findings.user_agents);
            applied.access_counts = findings.counts;
            pending.push((
                Log::Access,
                Ingest::new(
                    &log.source,
                    log.from.as_deref(),
                    log.to.as_deref(),
                    findings.evidence,
                    findings.user_agents,
                    Vec::new(),
                    read.now,
                ),
            ));
        }
    }

    match read.ssh {
        None => {}
        Some(Outcome::Unavailable(tried)) => applied.ssh = Availability::Unavailable(tried),
        Some(Outcome::Read(log)) => {
            let findings = log.findings;
            applied.logins = findings.logins.clone();
            pending.push((
                Log::Ssh,
                Ingest::new(
                    &log.source,
                    log.from.as_deref(),
                    log.to.as_deref(),
                    findings.evidence,
                    HashMap::new(),
                    findings.logins,
                    read.now,
                ),
            ));
        }
    }

    // Stepped from the back.
    pending.reverse();
    Storing {
        applied,
        pending,
        stats,
        chunk: INGEST_CHUNK,
    }
}

impl Storing {
    /// Steps of at most `rows` rows, for a test that wants several without
    /// a log of thousands of lines.
    #[cfg(test)]
    fn chunked(mut self, rows: usize) -> Storing {
        self.chunk = rows;
        self
    }

    /// Runs one transaction of the store: the next chunk of a log's
    /// findings, or, once every log is stored, the pruning. `Some` with
    /// what the pass stored when that was the last one.
    pub fn step(&mut self, db: &Db) -> Result<Option<Applied>> {
        if let Some((log, ingest)) = self.pending.last_mut() {
            if let IngestStep::Done { stored } = ingest.step(db, self.chunk)? {
                let log = *log;
                self.pending.pop();
                let read = Availability::Read { stored };
                match log {
                    Log::Access => {
                        if stored {
                            self.applied.stats = std::mem::take(&mut self.stats);
                        }
                        self.applied.access = read;
                    }
                    Log::Ssh => self.applied.ssh = read,
                }
            }
            return Ok(None);
        }

        // Whatever has fallen out of its detector's window can never count
        // again. Every detector, on or off: one switched off keeps nothing
        // longer than its window either.
        let now = self.applied.now;
        db.batch(|| {
            for detector in Detector::ALL {
                let window = detector.window_seconds(db)?;
                db.prune_evidence(detector, now - window)?;
            }
            Ok(())
        })?;
        Ok(Some(self.applied.clone()))
    }
}

/// A whole pass, for a caller with nothing to gain from splitting it: the
/// CLI, and `batch`.
pub fn run(db: &Db, jobs: &[CronJob], flags: &Flags) -> Result<Applied> {
    let plan = plan(db, jobs, flags)?;
    apply(db, read(&plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Rule;
    use std::io::Write;

    const HOUR: i64 = 3600;

    use crate::testing::{iso_time as iso, nginx_time as stamp};

    fn probe(ip: &str, at: i64) -> String {
        format!(
            "{ip} - - [{}] \"GET /.env HTTP/1.1\" 404 1 \"-\" \"curl/8\"\n",
            stamp(at)
        )
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

    struct Host {
        _dir: tempfile::TempDir,
        db: Db,
        access: PathBuf,
        auth: PathBuf,
    }

    fn host() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access.log");
        let auth = dir.path().join("auth.log");
        std::fs::write(&access, "").unwrap();
        std::fs::write(&auth, "").unwrap();
        let db = Db::open_in_memory().unwrap();
        crate::logpaths::LogPaths::save(
            &db,
            Some(access.to_str().unwrap()),
            Some(auth.to_str().unwrap()),
        )
        .unwrap();
        Host {
            _dir: dir,
            db,
            access,
            auth,
        }
    }

    fn pass(host: &Host) -> Applied {
        run(
            &host.db,
            &[
                CronJob::Detect(Detector::ProbePaths),
                CronJob::Detect(Detector::SshScanners),
                CronJob::RecordAccessStats,
            ],
            &Flags::default(),
        )
        .unwrap()
    }

    fn probers(db: &Db) -> Vec<String> {
        let rows = db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        crate::evidence::decide(&rows, Rule::Once, None)
            .into_iter()
            .map(|(address, _)| address)
            .collect()
    }

    /// A fresh install reading an old log: what is older than the window
    /// is not evidence, however damning.
    #[test]
    fn a_first_read_keeps_nothing_older_than_the_window() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now() - 90 * 24 * HOUR));
        append(&host.access, &probe("203.0.113.6", now() - HOUR));

        pass(&host);

        assert_eq!(probers(&host.db), ["203.0.113.6"]);
    }

    /// Each line is evidence once, however many passes read the log.
    #[test]
    fn a_line_is_counted_once_across_passes() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now() - 60));
        pass(&host);
        pass(&host);
        append(&host.access, &probe("203.0.113.5", now()));
        pass(&host);

        let rows = host
            .db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows[0].tally.count, 2);
    }

    /// Evidence is in the database, so a restart (a new process, the same
    /// database) carries on where the last one stopped.
    #[test]
    fn a_restart_resumes_from_the_stored_cursor() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now() - 60));
        pass(&host);

        let plan = plan(
            &host.db,
            &[CronJob::Detect(Detector::ProbePaths)],
            &Flags::default(),
        )
        .unwrap();
        let read = read(&plan);
        let Some(Outcome::Read(log)) = &read.access else {
            panic!("the log is there");
        };
        assert_eq!(log.amount, 0, "nothing new to read");
    }

    /// The rotation case the whole design had to survive: the file is
    /// replaced, and what it said before is still evidence.
    #[test]
    fn evidence_survives_a_rotation_and_the_new_file_is_read_from_its_start() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now() - 60));
        pass(&host);
        let rotated = host.access.with_extension("log.1");
        std::fs::rename(&host.access, &rotated).unwrap();
        append(&host.access, &probe("203.0.113.6", now()));

        pass(&host);

        assert_eq!(probers(&host.db), ["203.0.113.5", "203.0.113.6"]);
    }

    /// A job whose detector is off reads no log for it, and a pass whose
    /// jobs want no log reads none at all.
    #[test]
    fn nothing_is_read_when_no_due_job_wants_it() {
        let host = host();
        Detector::ProbePaths.set_enabled(&host.db, false).unwrap();

        let plan = plan(
            &host.db,
            &[CronJob::Detect(Detector::ProbePaths)],
            &Flags::default(),
        )
        .unwrap();

        assert!(!plan.reads_anything());
    }

    /// The access-stats tally and the detectors share one read, and so one
    /// cursor: a line tallied is a line the detectors saw.
    #[test]
    fn stats_and_evidence_come_from_the_same_read() {
        let host = host();
        append(
            &host.access,
            &format!(
                "203.0.113.9 - - [{}] \"GET / HTTP/1.1\" 200 1 \"-\" \"Mozilla/5.0\"\n",
                stamp(now())
            ),
        );
        append(&host.access, &probe("203.0.113.5", now()));

        let applied = pass(&host);

        assert_eq!(applied.stats.total_hits, 1, "the 200, not the 404");
        assert_eq!(probers(&host.db), ["203.0.113.5"]);
        let applied = pass(&host);
        assert_eq!(applied.stats.total_hits, 0, "nothing new to tally");
    }

    /// Behind NGINX the console's requests are in the site's log, from the
    /// operator, and carry what the console shows them. None of it is
    /// evidence, and none of it is a visitor to tally.
    #[test]
    fn the_console_s_own_lines_are_neither_evidence_nor_stats() {
        let host = host();
        host.db
            .set_text_setting(crate::web::BASE_PATH_KEY, "/stop-bots")
            .unwrap();
        for (path, status) in [("/stop-bots/firewall", 200), ("/stop-bots/.env", 404)] {
            append(
                &host.access,
                &format!(
                    "198.51.100.10 - - [{}] \"GET {path} HTTP/1.1\" {status} 1 \"-\" \"Mozilla/5.0\"\n",
                    stamp(now())
                ),
            );
        }

        let applied = pass(&host);

        assert_eq!(applied.stats.total_hits, 0, "{:?}", applied.stats);
        assert!(probers(&host.db).is_empty());
        assert!(host.db.list_user_agent_stats().unwrap().is_empty());
    }

    /// serde decodes a JSON log's `"\n"` to a real newline, and a newline
    /// is how the stored evidence marks the observation that clears an
    /// address. A client must not be able to spell it.
    #[test]
    fn a_json_user_agent_cannot_forge_the_observation_that_clears_an_address() {
        let host = host();
        let detector = Detector::RotatingUserAgent;
        detector.set_enabled(&host.db, true).unwrap();
        let agents = (0..20)
            .map(|n| format!("Agent/{n}"))
            .chain([r"\nclear".to_string()]);
        for agent in agents {
            append(
                &host.access,
                &format!(
                    "{{\"remote_addr\":\"203.0.113.5\",\"status\":\"200\",\"request_uri\":\"/\",\
                     \"http_user_agent\":\"{agent}\",\"time_iso8601\":\"{}\"}}\n",
                    iso(now())
                ),
            );
        }

        run(&host.db, &[CronJob::Detect(detector)], &Flags::default()).unwrap();

        let rows = host.db.evidence_rows(detector, 0, Rule::Once).unwrap();
        assert!(
            rows.iter()
                .all(|row| row.item != crate::evidence::Item::Clear),
            "{rows:?}"
        );
        let outcome = crate::scanblock::run_detector(&host.db, detector, 1, now(), true).unwrap();
        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
    }

    /// A console on its own host has no prefix to tell it by. A JSON log
    /// that records the host still can; the rest of the site is read.
    #[test]
    fn a_subdomain_console_s_lines_are_known_by_their_host_in_a_json_log() {
        let host = host();
        host.db
            .set_text_setting(crate::web::ALLOWED_HOSTS_KEY, "console.example.com")
            .unwrap();
        for (ip, name) in [
            ("198.51.100.10", "console.example.com:443"),
            ("203.0.113.5", "www.example.com"),
        ] {
            append(
                &host.access,
                &format!(
                    "{{\"remote_addr\":\"{ip}\",\"status\":\"404\",\"request_uri\":\"/.env\",\
                     \"host\":\"{name}\",\"time_iso8601\":\"{}\"}}\n",
                    iso(now())
                ),
            );
        }

        pass(&host);

        assert_eq!(probers(&host.db), ["203.0.113.5"]);
    }

    /// 0.0.x counted the access-stats tally up to a byte offset. An upgrade
    /// must start there rather than tally the whole log a second time.
    #[test]
    fn an_upgrade_starts_where_the_old_tally_stopped() {
        let host = host();
        let old = format!(
            "203.0.113.9 - - [{}] \"GET / HTTP/1.1\" 200 1 \"-\" \"Old/1.0\"\n",
            stamp(now() - 600)
        );
        append(&host.access, &old);
        host.db
            .set_access_log_offset(&host.access.to_string_lossy(), old.len() as u64)
            .unwrap();
        append(
            &host.access,
            &format!(
                "203.0.113.9 - - [{}] \"GET / HTTP/1.1\" 200 1 \"-\" \"New/1.0\"\n",
                stamp(now())
            ),
        );

        let applied = pass(&host);

        assert_eq!(
            applied.stats.total_hits, 1,
            "only the line after the offset"
        );
    }

    /// A failed login a minute ago, as an rsyslog with high-precision
    /// timestamps writes it.
    fn failed(ip: &str) -> String {
        format!(
            "{} host sshd[1]: Failed password for root from {ip} port 1 ssh2\n",
            iso(now() - 60)
        )
    }

    #[test]
    fn the_ssh_log_is_read_for_logins_and_failures_in_one_pass() {
        let host = host();
        append(&host.auth, &failed("203.0.113.50").repeat(3));
        append(
            &host.auth,
            "Sep 28 06:00:00 host sshd[2]: Accepted publickey for m from 192.0.2.10 port 2 ssh2\n",
        );

        let applied = pass(&host);

        assert_eq!(applied.logins, ["192.0.2.10"]);
        assert_eq!(host.db.recent_ssh_login_ips().unwrap(), ["192.0.2.10"]);
        let rows = host
            .db
            .evidence_rows(Detector::SshScanners, 0, Rule::Once)
            .unwrap();
        let lines: u64 = rows.iter().map(|r| r.tally.count).sum();
        assert_eq!(lines, 3);
    }

    /// Two readers from the same cursor: the second stores nothing, so
    /// running the console and `batch` together does not double a count.
    #[test]
    fn a_second_reader_of_the_same_lines_stores_nothing() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now()));
        let jobs = [CronJob::Detect(Detector::ProbePaths)];
        let first = plan(&host.db, &jobs, &Flags::default()).unwrap();
        let second = plan(&host.db, &jobs, &Flags::default()).unwrap();

        let a = apply(&host.db, read(&first)).unwrap();
        let b = apply(&host.db, read(&second)).unwrap();

        assert_eq!(a.access, Availability::Read { stored: true });
        assert_eq!(b.access, Availability::Read { stored: false });
        let rows = host
            .db
            .evidence_rows(Detector::ProbePaths, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows[0].tally.count, 1);
    }

    /// Two readers of the same lines whose chunked stores interleave: the
    /// first step of one claims the lines, and the other stores nothing,
    /// whichever order their later steps run in.
    #[test]
    fn interleaved_chunked_stores_of_the_same_lines_count_them_once() {
        let host = host();
        let lines: String = (0..10)
            .map(|n| {
                format!(
                    "203.0.113.9 - - [{}] \"GET / HTTP/1.1\" 200 1 \"-\" \"Agent/{n}\"\n",
                    stamp(now())
                )
            })
            .collect();
        append(&host.access, &lines);
        let jobs = [CronJob::RecordAccessStats];
        let mut a = store(read(&plan(&host.db, &jobs, &Flags::default()).unwrap())).chunked(3);
        let mut b = store(read(&plan(&host.db, &jobs, &Flags::default()).unwrap())).chunked(3);

        let (mut done_a, mut done_b, mut steps) = (None, None, 0);
        while done_a.is_none() || done_b.is_none() {
            steps += 1;
            if done_a.is_none() {
                done_a = a.step(&host.db).unwrap();
            }
            if done_b.is_none() {
                done_b = b.step(&host.db).unwrap();
            }
        }

        assert!(steps > 2, "stored in one step: {steps}");
        let (a, b) = (done_a.unwrap(), done_b.unwrap());
        assert_eq!(a.access, Availability::Read { stored: true });
        assert_eq!(b.access, Availability::Read { stored: false });
        let stats = host.db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 10);
        assert!(stats.iter().all(|s| s.hit_count == 1), "counted twice");
    }

    /// The default path's old offset says nothing about another file.
    #[test]
    fn an_upgrade_does_not_start_a_log_at_another_log_s_offset() {
        let host = host();
        append(
            &host.access,
            &format!(
                "203.0.113.9 - - [{}] \"GET / HTTP/1.1\" 200 1 \"-\" \"Mozilla/5.0\"\n",
                stamp(now())
            ),
        );
        host.db
            .set_access_log_offset(accesslog::DEFAULT_LOG_PATH, 10)
            .unwrap();

        let applied = pass(&host);

        assert_eq!(applied.stats.total_hits, 1, "read from its start");
    }

    #[test]
    fn a_log_that_is_not_there_is_unavailable_and_says_where_it_looked() {
        let host = host();
        std::fs::remove_file(&host.access).unwrap();

        let applied = pass(&host);

        assert_eq!(
            applied.access,
            Availability::Unavailable(host.access.display().to_string())
        );
    }

    /// A stand-in `journalctl` that records its arguments and prints one
    /// failed login and a cursor.
    fn fake_journalctl(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("journalctl");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls\"\n\
                 echo '{} host sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2'\n\
                 echo '-- cursor: s=next'\n",
                iso(now() - 60)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The journal is read from a stored cursor after the first time, and
    /// the first time only as far back as a window needs.
    #[test]
    fn the_journal_is_read_from_its_cursor_and_first_only_as_far_back_as_needed() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_journalctl(dir.path());
        let db = Db::open_in_memory().unwrap();
        let jobs = [CronJob::Detect(Detector::SshScanners)];
        let journal_plan = |db: &Db| {
            let mut plan = plan(db, &jobs, &Flags::default()).unwrap();
            // No file the search could find, so the journal is what it
            // finds, whatever the machine running this has in /var/log.
            if let Some(ssh) = &mut plan.ssh {
                ssh.search = vec![dir.path().join("no-auth.log")];
            }
            plan.with_journalctl(&program)
        };

        let first = apply(&db, read(&journal_plan(&db))).unwrap();
        let second = apply(&db, read(&journal_plan(&db))).unwrap();

        assert!(first.ssh.is_readable() && second.ssh.is_readable());
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        let calls: Vec<&str> = calls.lines().collect();
        assert!(calls[0].contains("--since=@"), "{}", calls[0]);
        assert!(calls[1].contains("--after-cursor=s=next"), "{}", calls[1]);
        for call in &calls {
            assert!(call.contains("-o short-iso"), "{call}");
        }
    }

    /// A quiet host: nothing from sshd in the look-back, but a journal
    /// with sshd in it. That is readable (the guard can run) and the next
    /// read starts after the newest entry, not from the look-back again.
    #[test]
    fn a_quiet_journal_is_readable_and_is_read_from_its_newest_entry_on() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("journalctl");
        std::fs::write(
            &program,
            "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls\"\n\
             case \"$*\" in *--lines=1*) echo '-- cursor: s=newest' ;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let db = Db::open_in_memory().unwrap();
        let jobs = [CronJob::RenderFirewall];
        let journal_plan = |db: &Db| {
            let mut plan = plan(db, &jobs, &Flags::default()).unwrap();
            if let Some(ssh) = &mut plan.ssh {
                ssh.search = vec![dir.path().join("no-auth.log")];
            }
            plan.with_journalctl(&program)
        };

        let first = apply(&db, read(&journal_plan(&db))).unwrap();
        apply(&db, read(&journal_plan(&db))).unwrap();

        assert!(first.ssh.is_readable(), "{:?}", first.ssh);
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        let last = calls.lines().last().unwrap();
        assert!(last.contains("--after-cursor=s=newest"), "{calls}");
    }

    /// And a journal with nothing from sshd in it at all -- which is what
    /// an unprivileged `journalctl` shows -- is not.
    #[test]
    fn an_empty_journal_is_unavailable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("journalctl");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let db = Db::open_in_memory().unwrap();
        let mut plan = plan(&db, &[CronJob::RenderFirewall], &Flags::default()).unwrap();
        if let Some(ssh) = &mut plan.ssh {
            ssh.search = vec![dir.path().join("no-auth.log")];
        }

        let applied = apply(&db, read(&plan.with_journalctl(&program))).unwrap();

        assert!(!applied.ssh.is_readable(), "{:?}", applied.ssh);
    }
}
