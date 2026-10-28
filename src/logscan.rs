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

//! Each log read once per pass, from where the last pass stopped, into
//! the evidence every detector decides on.
//!
//! ## What this replaced
//!
//! Every detector job read, decoded and parsed the whole access log for
//! itself, about ten full reads a minute at roughly twice the file's size
//! in memory each, and the TUI started them all at once. On a 200 MB log
//! that was 440 MB for one pass of the web console (since removed) and
//! 2.9 GB for the TUI's first minute. And because each read counted over the whole file,
//! a block that expired was re-added from the same old lines.
//!
//! ## The three halves of a pass
//!
//! A pass is split the way every slow job in this project is, so that no
//! front-end holds its database, or its event loop, across the slow part:
//!
//! - [`plan`] reads the database: which logs are wanted, where each read
//!   resumes, what the detectors look for. Quick; on the TUI's main
//!   thread, or inline in `tick` and the CLI.
//! - [`read`] reads and parses the logs, and touches no database: it
//!   cannot, it is given none. Slow; on a blocking thread, outside the
//!   lock. It streams a line at a time, so its memory is the evidence it
//!   collects, not the file.
//! - [`apply`] stores what the read found and where the next one resumes
//!   (see `db::evidence::Ingest`), and prunes what has fallen out of every
//!   window. A chunk at a time ([`store`]), each its own transaction, so a
//!   large read does not hold the database's write lock for all of it.
//!
//! Then each due job decides from the stored evidence: see
//! `cron::run_log_jobs`.
//!
//! ## Which logs, and when
//!
//! A log is read when a due job wants it and not otherwise: the access logs
//! for access-stats and any access-log detector that is on, the SSH log
//! for the SSH detector's job (on or off: the logins it records keep the
//! anti-lockout window fed) and the firewall render's guard, and the
//! kernel log for the port-scan detector when it is on.
//!
//! A read feeds *every* consumer of that log, due or not, because the
//! cursor moves past the lines for all of them at once.
//!
//! ## Several access logs
//!
//! The web server may write more than one: the stored or default log, and
//! each other file its config names (see [`crate::logpaths`] for which,
//! and why a flag reads only itself). Each is read on its own, with a
//! cursor of its own, so that one rotating, going missing or being read by
//! another process at the same moment changes nothing for the rest. One
//! that cannot be read is reported in [`Applied::access_logs`]; the access
//! detectors run as long as any of them was read.
//!
//! The first read of one, with no cursor yet, also reads what logrotate
//! kept of it (see [`crate::hostlog::read_rotated`]), as far back as the
//! longest window of a detector that is on: an install on the morning after
//! a rotation would otherwise know nothing of the day before. Those lines
//! are evidence only. The access-stats tally counts from the first read
//! on, as it always has.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::accesslog::{self, Clock, Counts, Watch};
use crate::cron::CronJob;
use crate::db::evidence::{Ingest, IngestStep, INGEST_CHUNK};
use crate::db::Db;
use crate::evidence::Evidence;
use crate::hostlog::{self, source_key, Chunk, Cursor, LogReader, Request, Sources};
use crate::protection::{Detector, DetectorLog};
use crate::sshlog::{self, SshSource};

/// The logs a pass may read: flags from the command line, which win over
/// the stored paths (see [`crate::logpaths`]).
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub ssh_log: Option<PathBuf>,
    pub access_log: Option<PathBuf>,
    pub kernel_log: Option<PathBuf>,
    /// The paths the host settings name ([`crate::hostconf`]), used where
    /// no flag is given.
    pub stored: crate::logpaths::LogPaths,
}

impl Flags {
    /// Where these say the logs are, for reading them in process.
    pub fn sources(&self) -> Sources {
        let mut sources = Sources::new(
            &self.stored,
            self.access_log.as_deref(),
            self.ssh_log.as_deref(),
        );
        sources.kernel = self.stored.kernel(self.kernel_log.as_deref());
        sources
    }
}

/// The most requests one pass makes of one log: a gigabyte of it. What a
/// log grows by faster than that is read by the next pass, from where this
/// one stopped.
const MAX_REQUESTS: usize = 256;

/// What a pass will read, resolved from the database. Holds no handle to
/// it, so it can go to another thread.
#[derive(Debug, Clone)]
pub struct Plan {
    now: i64,
    access: Option<AccessPlan>,
    ssh: Option<SshPlan>,
    kernel: Option<KernelPlan>,
    /// Where the flags say the logs are: what a pass that reads them in
    /// process reads (see [`Plan::sources`]).
    sources: Sources,
}

#[derive(Debug, Clone)]
struct AccessPlan {
    watch: Watch,
    /// One per access log in [`Sources::access`], in its order.
    logs: Vec<AccessLogPlan>,
}

#[derive(Debug, Clone)]
struct AccessLogPlan {
    /// Its place in [`Sources::access`].
    which: usize,
    /// The cursor as stored, which the store compares against.
    cursor: Option<Cursor>,
    /// Where 0.0.x's access-stats tally stopped, for a log with no cursor
    /// yet: the first read starts there rather than counting the whole
    /// file into `user_agent_stats` a second time.
    legacy_offset: Option<u64>,
    /// On a first read, how far back its rotated copies are read: the
    /// oldest time a detector that is on still counts. `None` on a later
    /// read, and when no detector looks back at all.
    rotated_since: Option<i64>,
}

#[derive(Debug, Clone)]
struct SshPlan {
    /// The stored cursor of every place the SSH log might turn out to be.
    cursors: Vec<Cursor>,
    /// The oldest a failed login may be and still count, when the SSH
    /// detector is on.
    cutoff: Option<i64>,
    /// How far back a first read of the journal looks. A file is read
    /// whole the first time (logrotate bounds it); the journal is bounded
    /// by nothing, and every login in the anti-lockout window is wanted.
    look_back: i64,
}

#[derive(Debug, Clone)]
struct KernelPlan {
    /// The stored cursor of every place the kernel log might be.
    cursors: Vec<Cursor>,
    /// The oldest a trap hit may be and still count, which is also how far
    /// back a first read of the journal looks.
    cutoff: i64,
}

impl Plan {
    /// Whether this pass reads anything at all.
    pub fn reads_anything(&self) -> bool {
        self.access.is_some() || self.ssh.is_some() || self.kernel.is_some()
    }

    /// The logs the flags it was planned with name, to [`read`] them in
    /// process: the CLI's and the TUI's reader, which run as root. The web
    /// console reads through [`crate::privileged::Privileged`] instead.
    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    /// Reads the journal with `program` instead of `journalctl`.
    pub fn with_journalctl(mut self, program: &Path) -> Plan {
        self.sources.journalctl = program.to_path_buf();
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
        CronJob::Detect(detector) => {
            detector.spec().log == DetectorLog::Access && detector.is_enabled(db)?
        }
        _ => false,
    })
}

/// Whether `job` wants the kernel log: the port-scan detector's, when it
/// is on.
fn wants_kernel_log(db: &Db, job: CronJob) -> Result<bool> {
    Ok(match job {
        CronJob::Detect(detector) => {
            detector.spec().log == DetectorLog::Kernel && detector.is_enabled(db)?
        }
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
    let sources = flags.sources();

    let mut wants_access = false;
    for job in jobs {
        wants_access |= wants_access_log(db, *job)?;
    }
    let access = if wants_access {
        let watch = watch(db, now)?;
        let longest = watch
            .detectors
            .iter()
            .filter_map(|(_, cutoff)| *cutoff)
            .min();
        let mut logs = Vec::new();
        for (which, path) in sources.access.iter().enumerate() {
            let source = source_key(path);
            let stored = db.get_log_cursor(&source)?;
            let legacy_offset = match stored {
                Some(_) => None,
                None => legacy_offset(db, path)?,
            };
            let first = stored.is_none() && legacy_offset.is_none();
            logs.push(AccessLogPlan {
                which,
                cursor: stored.map(|at| Cursor { source, at }),
                legacy_offset,
                rotated_since: longest.filter(|_| first),
            });
        }
        Some(AccessPlan { watch, logs })
    } else {
        None
    };

    let ssh = if jobs.iter().any(|job| wants_ssh_log(*job)) {
        let mut candidates: Vec<String> = match &sources.ssh {
            SshSource::File(path) => vec![source_key(path)],
            SshSource::Search => sources.search.iter().map(|p| source_key(p)).collect(),
        };
        candidates.push(sshlog::JOURNAL_SOURCE.to_string());
        let mut cursors = Vec::new();
        for source in candidates {
            if let Some(at) = db.get_log_cursor(&source)? {
                cursors.push(Cursor { source, at });
            }
        }
        let detector = Detector::SshScanners;
        let window = detector.window_seconds(db)?;
        let cutoff = detector.is_enabled(db)?.then_some(now - window);
        Some(SshPlan {
            cursors,
            cutoff,
            look_back: window.max(crate::db::SSH_LOGIN_WINDOW_SECONDS),
        })
    } else {
        None
    };

    let mut wants_kernel = false;
    for job in jobs {
        wants_kernel |= wants_kernel_log(db, *job)?;
    }
    let kernel = if wants_kernel {
        let mut candidates: Vec<String> = match &sources.kernel {
            SshSource::File(path) => vec![source_key(path)],
            SshSource::Search => sources
                .kernel_search
                .iter()
                .map(|p| source_key(p))
                .collect(),
        };
        candidates.push(crate::portscan::JOURNAL_SOURCE.to_string());
        let mut cursors = Vec::new();
        for source in candidates {
            if let Some(at) = db.get_log_cursor(&source)? {
                cursors.push(Cursor { source, at });
            }
        }
        Some(KernelPlan {
            cursors,
            cutoff: now - Detector::PortScanners.window_seconds(db)?,
        })
    } else {
        None
    };

    Ok(Plan {
        now,
        access,
        ssh,
        kernel,
        sources,
    })
}

/// What every access-log detector that is on is looking for, and from
/// when.
pub fn watch(db: &Db, now: i64) -> Result<Watch> {
    let mut detectors = Vec::new();
    for detector in Detector::ALL {
        if detector.spec().log == DetectorLog::Access && detector.is_enabled(db)? {
            detectors.push((detector, Some(now - detector.window_seconds(db)?)));
        }
    }
    let app_probes = if detectors.iter().any(|(d, _)| *d == Detector::ProbePaths) {
        app_probes_if_on(db)?
    } else {
        crate::webapps::AppProbes::default()
    };
    // Built from the whole bot list, so only when something reads it.
    let robots = if detectors
        .iter()
        .any(|(d, _)| *d == Detector::RobotsViolators)
    {
        crate::protection::robots_rules(db)?
    } else {
        None
    };
    Ok(Watch {
        detectors,
        probe_paths: crate::protection::probe_paths(db)?,
        honeypot: crate::protection::honeypot_path(db)?,
        robots,
        claims: crate::scanblock::crawler_claims(db)?,
        hosted: hosted(db)?,
        app_probes,
    })
}

/// Every name each scanned site answers to, with the application its
/// config says runs behind it: see [`crate::services`].
///
/// Read from the configs as they are now, on every pass, rather than
/// stored by `scan-sites`: what runs behind a site changes with its
/// config, and a stored answer would go on allowing an application's
/// requests after it moved. A handful of small files a minute.
pub fn hosted(db: &Db) -> Result<crate::services::Hosted> {
    let server = crate::webserver::WebServer::configured();
    let mut sites = Vec::new();
    for site in db.list_sites()? {
        let path = Path::new(&site.config_path);
        let service = server.site_service(path, &site.server_name);
        for name in server.server_names_for(path, &site.server_name) {
            sites.push((name, service));
        }
    }
    Ok(crate::services::Hosted::new(sites))
}

/// [`app_probes`] when app-aware probe paths are on (see
/// `protection::app_probe_paths`); nothing, so no path counts, when they
/// are off. What the probe-paths detector reads.
pub fn app_probes_if_on(db: &Db) -> Result<crate::webapps::AppProbes> {
    if !crate::protection::app_probe_paths(db)? {
        return Ok(crate::webapps::AppProbes::default());
    }
    app_probes(db)
}

/// Which of [`crate::webapps::APPS`]' paths are probes on which site.
///
/// Read from the configs and the document roots as they are now, on every
/// pass, for the reason [`hosted`] is: installing WordPress must stop its
/// login page counting as a probe within a minute, not at the next
/// `scan-sites`.
pub fn app_probes(db: &Db) -> Result<crate::webapps::AppProbes> {
    // A host settings file that cannot be read is no reason to fail a
    // pass, nor to guess: nothing is a probe.
    let Ok(host) = crate::hostconf::HostConf::load() else {
        return Ok(crate::webapps::AppProbes::default());
    };
    let server = host.web_server();
    // In a container, its document roots are paths in the container, and
    // a directory of the same name here says nothing.
    let files_here = host.config_paths_are_here();
    let mut sites = Vec::new();
    for site in db.list_sites()? {
        let path = Path::new(&site.config_path);
        let directives = server.site_directives(path, &site.server_name);
        let verdicts = crate::webapps::inspect_site(directives.as_deref(), files_here);
        sites.push((server.server_names_for(path, &site.server_name), verdicts));
    }
    // Unit tests never read the host's own config: there, the root is
    // the stock one, and nothing points it elsewhere.
    let global = if server == crate::webserver::WebServer::Traefik {
        // Traefik learns sites from Docker labels no file here names, so a
        // request for one of those is judged against the whole host, and
        // nothing says what any of its applications is.
        crate::webapps::Verdicts::unknown(
            "Traefik can serve sites no file under its root names, from Docker labels",
        )
    } else if cfg!(test) {
        crate::webapps::Verdicts::default()
    } else {
        global_config(server, &server.global_conf_dir(&host.root(None)))
    };
    Ok(crate::webapps::AppProbes::new(sites, &global))
}

/// What the server-wide config in `dir` serves, as
/// [`crate::webapps::inspect_global`] reads it: every file in it but this
/// project's own, with this project's blocks taken out.
fn global_config(server: crate::webserver::WebServer, dir: &Path) -> crate::webapps::Verdicts {
    /// Larger than any config file, smaller than a mistake.
    const MAX_BYTES: u64 = 1 << 20;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return crate::webapps::inspect_global(&[]);
    };
    let mut files = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if name.starts_with("stop-bots")
            || !path.is_file()
            || path.metadata().map_or(true, |m| m.len() > MAX_BYTES)
        {
            continue;
        }
        // A root someone else can write is read only where it holds a
        // regular file, without following a link or waiting on a FIFO;
        // a link in `conf.d` is the operator's to make anywhere else.
        let text = if server.root_is_hostile() {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_file())
                .then(|| crate::webserver::read_regular_file(&path))
                .flatten()
        } else {
            std::fs::read_to_string(&path).ok()
        };
        if let Some(text) = text {
            files.push((
                path.display().to_string(),
                server.without_injected_blocks(&text),
            ));
        }
    }
    crate::webapps::inspect_global(&files)
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
    /// Bytes (a file, with its rotated copies on a first read) or entries
    /// (the journal) read.
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
pub struct KernelFindings {
    pub evidence: Evidence,
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
    /// One per access log, in [`Sources::access`]' order: empty when no
    /// due job wanted them.
    pub access: Vec<Outcome<AccessFindings>>,
    pub ssh: Option<Outcome<SshFindings>>,
    pub kernel: Option<Outcome<KernelFindings>>,
}

/// Reads what `plan` asks for, through `reader` — [`Plan::sources`].
/// Blocking, and deliberately without a `Db`: see the module docs.
pub fn read(plan: &Plan, reader: &dyn LogReader) -> Read {
    Read {
        now: plan.now,
        access: plan.access.as_ref().map_or_else(Vec::new, |access| {
            access
                .logs
                .iter()
                .map(|log| read_access(log, &access.watch, plan.now, reader))
                .collect()
        }),
        ssh: plan.ssh.as_ref().map(|ssh| read_ssh(ssh, plan.now, reader)),
        kernel: plan
            .kernel
            .as_ref()
            .map(|kernel| read_kernel(kernel, plan.now, reader)),
    }
}

/// Where following one log to its end got.
struct Followed {
    source: String,
    from: Option<String>,
    to: Option<String>,
    amount: u64,
}

/// Asks `reader` for `request`, and again from where each reply stopped,
/// until the log has no more (or [`MAX_REQUESTS`]), handing each chunk to
/// `each`. `Err` with what was tried when nothing could be read.
///
/// A failure after the first chunk ends the read where it got to, which
/// the next pass carries on from; so does a log that turns out to be
/// another one part-way (rotated away, or the search found a different
/// file), which the next pass starts on.
fn follow(
    reader: &dyn LogReader,
    mut request: Request,
    each: &mut dyn FnMut(&Chunk),
) -> Result<Followed, String> {
    let mut followed: Option<Followed> = None;
    for _ in 0..MAX_REQUESTS {
        let chunk = match reader.read_log(&request) {
            Ok(hostlog::Reply::Read(chunk)) => chunk,
            Ok(hostlog::Reply::Unavailable(tried)) if followed.is_none() => return Err(tried),
            Err(err) if followed.is_none() => return Err(format!("{err:#}")),
            Ok(hostlog::Reply::Unavailable(_)) | Err(_) => break,
        };
        let so_far = followed.get_or_insert_with(|| Followed {
            source: chunk.source.clone(),
            from: chunk.from.clone(),
            to: None,
            amount: 0,
        });
        if so_far.source != chunk.source {
            break;
        }
        each(&chunk);
        so_far.to = chunk.to.clone();
        so_far.amount += chunk.amount;
        if !chunk.more {
            break;
        }
        request.cursors = chunk.next().into_iter().collect();
        request.legacy_offset = None;
    }
    followed.ok_or_else(|| "nothing was asked for".to_string())
}

fn read_access(
    plan: &AccessLogPlan,
    watch: &Watch,
    now: i64,
    reader: &dyn LogReader,
) -> Outcome<AccessFindings> {
    let request = Request {
        which: plan.which,
        legacy_offset: plan.legacy_offset,
        ..Request::new(hostlog::Log::Access, plan.cursor.iter().cloned().collect())
    };
    let mut reading: Option<(accesslog::Observer, Clock)> = None;
    let mut rotated = 0;
    let followed = follow(reader, request, &mut |chunk| {
        let (observer, clock) = reading.get_or_insert_with(|| {
            // On a first read nothing dates an undated line, which may be
            // months old: it counts for nothing. After that, a line that
            // was not there last pass is from since then.
            let undated = chunk.resumed.then_some(now);
            let mut observer = accesslog::Observer::new(watch.clone()).counting_user_agents();
            // Only once the log itself has answered, so a log that is not
            // there does not have its copies read again every pass; and
            // before its own lines, so the observer sees them in order.
            if let (Some(since), false) = (plan.rotated_since, chunk.resumed) {
                let clock = Clock::Logged { now, undated: None };
                rotated = reader.read_rotated(plan.which, since, &mut |line| {
                    observer.line_uncounted(line, clock)
                });
            }
            (observer, Clock::Logged { now, undated })
        });
        for line in chunk.lines.split_terminator('\n') {
            observer.line(line, *clock);
        }
    });
    match followed {
        Ok(done) => {
            let (evidence, user_agents, counts) = match reading {
                Some((observer, _)) => observer.finish(),
                None => Default::default(),
            };
            Outcome::Read(LogRead {
                source: done.source,
                from: done.from,
                to: done.to,
                amount: done.amount + rotated,
                findings: AccessFindings {
                    evidence,
                    user_agents,
                    counts,
                },
            })
        }
        Err(tried) => Outcome::Unavailable(tried),
    }
}

fn read_ssh(plan: &SshPlan, now: i64, reader: &dyn LogReader) -> Outcome<SshFindings> {
    let request = Request {
        since: Some(now - plan.look_back),
        ..Request::new(hostlog::Log::Ssh, plan.cursors.clone())
    };
    let mut observer: Option<sshlog::Observer> = None;
    let followed = follow(reader, request, &mut |chunk| {
        let observer = observer.get_or_insert_with(|| {
            sshlog::Observer::new(plan.cutoff, now, chunk.resumed.then_some(now))
        });
        for line in chunk.lines.split_terminator('\n') {
            observer.line(line);
        }
    });
    match followed {
        Ok(done) => {
            let (evidence, logins) = match observer {
                Some(observer) => {
                    let (evidence, logins, _) = observer.finish();
                    (evidence, logins)
                }
                None => Default::default(),
            };
            Outcome::Read(LogRead {
                source: done.source,
                from: done.from,
                to: done.to,
                amount: done.amount,
                findings: SshFindings { evidence, logins },
            })
        }
        Err(tried) => Outcome::Unavailable(tried),
    }
}

fn read_kernel(plan: &KernelPlan, now: i64, reader: &dyn LogReader) -> Outcome<KernelFindings> {
    let request = Request {
        since: Some(plan.cutoff),
        ..Request::new(hostlog::Log::Kernel, plan.cursors.clone())
    };
    let mut observer: Option<crate::portscan::Observer> = None;
    let followed = follow(reader, request, &mut |chunk| {
        let observer = observer.get_or_insert_with(|| {
            crate::portscan::Observer::new(plan.cutoff, now, chunk.resumed.then_some(now))
        });
        for line in chunk.lines.split_terminator('\n') {
            observer.line(line);
        }
    });
    match followed {
        Ok(done) => Outcome::Read(LogRead {
            source: done.source,
            from: done.from,
            to: done.to,
            amount: done.amount,
            findings: KernelFindings {
                evidence: observer.map(|o| o.finish()).unwrap_or_default(),
            },
        }),
        Err(tried) => Outcome::Unavailable(tried),
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
    /// The access logs as one: read when any of them was (stored when any
    /// read was ours to store), and otherwise unavailable, naming every
    /// one tried. What the access detectors and the tally go by.
    pub access: Availability,
    /// Each access log the pass meant to read, by its path, and how that
    /// went: for saying which one could not be read.
    pub access_logs: Vec<(String, Availability)>,
    pub ssh: Availability,
    pub kernel: Availability,
    /// Addresses that logged in over SSH, in what this pass read.
    pub logins: Vec<String>,
    /// The access-stats tally of what this pass read.
    pub stats: crate::accessstats::AccessStatsOutcome,
    /// Lines in the access logs this pass read, and how many parsed.
    pub access_counts: Counts,
}

impl Applied {
    /// The access logs this pass could not read, as each was tried.
    pub fn unreadable_access_logs(&self) -> Vec<&str> {
        self.access_logs
            .iter()
            .filter(|(_, availability)| matches!(availability, Availability::Unavailable(_)))
            .map(|(path, _)| path.as_str())
            .collect()
    }

    /// `"; could not read <path>, <path>"` when some access logs were read
    /// and others could not be, for the end of a summary; nothing otherwise.
    /// A log missing among several is not fatal, and not silent either.
    pub fn unreadable_note(&self) -> String {
        match self.unreadable_access_logs().as_slice() {
            [] => String::new(),
            _ if !self.access.is_readable() => String::new(),
            paths => format!("; could not read {}", paths.join(", ")),
        }
    }
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

/// Which log a [`Storing`] is on: an access log by its place in
/// [`Applied::access_logs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Log {
    Access(usize),
    Ssh,
    Kernel,
}

impl Applied {
    /// Whether the log `detector` reads was there to read in this pass.
    pub fn log_for(&self, detector: Detector) -> &Availability {
        match detector.spec().log {
            DetectorLog::Access => &self.access,
            DetectorLog::Ssh => &self.ssh,
            DetectorLog::Kernel => &self.kernel,
        }
    }
}

/// What a pass read, being stored one transaction at a time: each log's
/// findings a chunk at a time (see [`Ingest`]), then the pruning. Holds no
/// database, so the write lock goes between steps and a large pass does
/// not keep the TUI or a `batch` waiting for all of it.
pub struct Storing {
    applied: Applied,
    pending: Vec<(Log, Ingest)>,
    /// The access-stats tally of each access log, by its place, for when
    /// its store is ours; and of all of them at once, for when every one
    /// is (an agent in two logs is one agent).
    stats: Vec<crate::accessstats::AccessStatsOutcome>,
    all_stats: crate::accessstats::AccessStatsOutcome,
    /// The most rows a step writes.
    chunk: usize,
}

/// Starts storing what `read` found. Nothing is written until
/// [`Storing::step`].
pub fn store(read: Read) -> Storing {
    let mut applied = Applied {
        now: read.now,
        access: Availability::NotRead,
        access_logs: Vec::new(),
        ssh: Availability::NotRead,
        kernel: Availability::NotRead,
        logins: Vec::new(),
        stats: crate::accessstats::AccessStatsOutcome::default(),
        access_counts: Counts::default(),
    };
    let mut pending = Vec::new();
    let mut stats = Vec::new();
    let all_stats =
        crate::accessstats::AccessStatsOutcome::of_all(read.access.iter().filter_map(|outcome| {
            match outcome {
                Outcome::Read(log) => Some(&log.findings.user_agents),
                Outcome::Unavailable(_) => None,
            }
        }));

    for (place, outcome) in read.access.into_iter().enumerate() {
        let log = match outcome {
            Outcome::Unavailable(tried) => {
                applied
                    .access_logs
                    .push((tried.clone(), Availability::Unavailable(tried)));
                stats.push(Default::default());
                continue;
            }
            Outcome::Read(log) => log,
        };
        let findings = log.findings;
        stats.push(crate::accessstats::AccessStatsOutcome::of(
            &findings.user_agents,
        ));
        applied.access_counts.lines += findings.counts.lines;
        applied.access_counts.parsed += findings.counts.parsed;
        applied
            .access_logs
            .push((log.source.clone(), Availability::NotRead));
        pending.push((
            Log::Access(place),
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

    match read.kernel {
        None => {}
        Some(Outcome::Unavailable(tried)) => applied.kernel = Availability::Unavailable(tried),
        Some(Outcome::Read(log)) => {
            pending.push((
                Log::Kernel,
                Ingest::new(
                    &log.source,
                    log.from.as_deref(),
                    log.to.as_deref(),
                    log.findings.evidence,
                    HashMap::new(),
                    Vec::new(),
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
        all_stats,
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
                    Log::Access(place) => self.applied.access_logs[place].1 = read,
                    Log::Ssh => self.applied.ssh = read,
                    Log::Kernel => self.applied.kernel = read,
                }
            }
            return Ok(None);
        }

        self.applied.access = all_access(&self.applied.access_logs);
        self.applied.stats = self.stats_stored();

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

    /// The access-stats tally of the access logs whose store was ours.
    fn stats_stored(&self) -> crate::accessstats::AccessStatsOutcome {
        let logs = &self.applied.access_logs;
        let ours = |read: &Availability| *read == Availability::Read { stored: true };
        if logs
            .iter()
            .filter(|(_, read)| read.is_readable())
            .all(|(_, read)| ours(read))
        {
            return self.all_stats;
        }
        // Another process stored some of them, and their lines are its to
        // tally. An agent in two of ours is counted twice here, which is
        // the most this can say without the agents themselves.
        logs.iter()
            .zip(&self.stats)
            .filter(|((_, read), _)| ours(read))
            .fold(Default::default(), |sum, (_, stats)| sum.plus(*stats))
    }
}

/// The access logs as one, for [`Applied::access`].
fn all_access(logs: &[(String, Availability)]) -> Availability {
    if logs.is_empty() {
        return Availability::NotRead;
    }
    if logs
        .iter()
        .any(|(_, availability)| availability.is_readable())
    {
        return Availability::Read {
            stored: logs
                .iter()
                .any(|(_, availability)| *availability == Availability::Read { stored: true }),
        };
    }
    Availability::Unavailable(
        logs.iter()
            .map(|(tried, _)| tried.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// A whole pass, for a caller with nothing to gain from splitting it: the
/// CLI, and `batch`.
pub fn run(db: &Db, jobs: &[CronJob], flags: &Flags) -> Result<Applied> {
    let plan = plan(db, jobs, flags)?;
    let read = read(&plan, plan.sources());
    apply(db, read)
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
        kern: PathBuf,
        /// No flags, and both logs named by the host settings.
        flags: Flags,
    }

    fn host() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let access = dir.path().join("access.log");
        let auth = dir.path().join("auth.log");
        let kern = dir.path().join("kern.log");
        std::fs::write(&access, "").unwrap();
        std::fs::write(&auth, "").unwrap();
        std::fs::write(&kern, "").unwrap();
        let db = Db::open_in_memory().unwrap();
        let flags = Flags {
            stored: crate::logpaths::LogPaths {
                access: Some(access.clone()),
                ssh: Some(auth.clone()),
                kernel: Some(kern.clone()),
                ..Default::default()
            },
            ..Flags::default()
        };
        Host {
            _dir: dir,
            db,
            access,
            auth,
            kern,
            flags,
        }
    }

    /// Reads what `plan` asks for in process, from the logs its flags name.
    fn read_here(plan: &Plan) -> Read {
        read(plan, plan.sources())
    }

    fn pass(host: &Host) -> Applied {
        run(
            &host.db,
            &[
                CronJob::Detect(Detector::ProbePaths),
                CronJob::Detect(Detector::SshScanners),
                CronJob::RecordAccessStats,
            ],
            &host.flags,
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
            &host.flags,
        )
        .unwrap();
        let read = read_here(&plan);
        let [Outcome::Read(log)] = read.access.as_slice() else {
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
            &host.flags,
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

        run(&host.db, &[CronJob::Detect(detector)], &host.flags).unwrap();

        let rows = host.db.evidence_rows(detector, 0, Rule::Once).unwrap();
        assert!(
            rows.iter()
                .all(|row| row.item != crate::evidence::Item::Clear),
            "{rows:?}"
        );
        let outcome = crate::scanblock::run_detector(&host.db, detector, 1, now(), true).unwrap();
        assert_eq!(outcome.newly_blocked, ["203.0.113.5"], "{outcome:?}");
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

    /// A trap hit a minute ago, as rsyslog writes it to `kern.log`.
    fn trap_hit(ip: &str, port: u16) -> String {
        format!(
            "{} host kernel: [1.0] stop-bots-trap: IN=eth0 OUT= SRC={ip} DST=192.0.2.1 \
             PROTO=TCP SPT=40000 DPT={port} SYN URGP=0\n",
            iso(now() - 60)
        )
    }

    /// With the port-scan detector on, the kernel log is read like the
    /// others, from where the last pass stopped, into evidence the
    /// detector convicts on.
    #[test]
    fn the_kernel_log_feeds_the_port_scan_detector_once_per_line() {
        let host = host();
        Detector::PortScanners.set_enabled(&host.db, true).unwrap();
        append(&host.kern, "unrelated kernel line\n");
        append(&host.kern, &trap_hit("203.0.113.7", 23));
        let jobs = [CronJob::Detect(Detector::PortScanners)];

        let first = run(&host.db, &jobs, &host.flags).unwrap();
        append(&host.kern, &trap_hit("203.0.113.7", 445));
        run(&host.db, &jobs, &host.flags).unwrap();
        run(&host.db, &jobs, &host.flags).unwrap();

        assert!(first.kernel.is_readable(), "{:?}", first.kernel);
        let rows = host
            .db
            .evidence_rows(Detector::PortScanners, 0, Rule::Distinct(2))
            .unwrap();
        let counted: u64 = rows.iter().map(|row| row.tally.count).sum();
        assert_eq!((rows.len(), counted), (2, 2), "{rows:?}");
        let outcome =
            crate::scanblock::run_detector(&host.db, Detector::PortScanners, 1, now(), true)
                .unwrap();
        assert_eq!(outcome.newly_blocked, ["203.0.113.7"], "{outcome:?}");
    }

    /// Off, it reads nothing: the kernel log is not touched at all.
    #[test]
    fn the_kernel_log_is_not_read_while_the_port_scan_detector_is_off() {
        let host = host();
        let plan = plan(
            &host.db,
            &[CronJob::Detect(Detector::PortScanners)],
            &host.flags,
        )
        .unwrap();
        assert!(!plan.reads_anything());
    }

    /// An unreadable kernel log says so, and names what it tried.
    #[test]
    fn an_unreadable_kernel_log_is_unavailable_and_says_where_it_looked() {
        let host = host();
        Detector::PortScanners.set_enabled(&host.db, true).unwrap();
        std::fs::remove_file(&host.kern).unwrap();

        let applied = run(
            &host.db,
            &[CronJob::Detect(Detector::PortScanners)],
            &host.flags,
        )
        .unwrap();

        assert_eq!(
            applied.kernel,
            Availability::Unavailable(host.kern.display().to_string())
        );
    }

    /// From the journal, the kernel's own messages are asked for, from a
    /// cursor after the first read.
    #[test]
    fn the_kernel_journal_is_read_by_transport_and_from_its_cursor() {
        let dir = tempfile::tempdir().unwrap();
        crate::testing::fake_journalctl(
            dir.path(),
            &format!(
                "echo '{}'",
                crate::testing::kernel_journal_entry(
                    "s=k1",
                    now() - 60,
                    "stop-bots-trap: IN=eth0 OUT= SRC=203.0.113.8 DST=192.0.2.1 PROTO=TCP \
                     SPT=1 DPT=3389 SYN URGP=0"
                )
            ),
        );
        let db = Db::open_in_memory().unwrap();
        Detector::PortScanners.set_enabled(&db, true).unwrap();
        let jobs = [CronJob::Detect(Detector::PortScanners)];
        let journal = |db: &Db| {
            let mut plan = plan(db, &jobs, &Flags::default()).unwrap();
            plan.sources.kernel_search = vec![dir.path().join("no-kern.log")];
            plan.with_journalctl(&dir.path().join("journalctl"))
        };

        let first = apply(&db, read_here(&journal(&db))).unwrap();
        apply(&db, read_here(&journal(&db))).unwrap();

        assert!(first.kernel.is_readable(), "{:?}", first.kernel);
        let calls = crate::testing::journalctl_calls(dir.path());
        assert!(calls[0].starts_with("_TRANSPORT=kernel "), "{calls:?}");
        assert!(calls[0].contains("--since=@"), "{calls:?}");
        assert!(calls[1].contains("--after-cursor=s=k1"), "{calls:?}");
        let rows = db
            .evidence_rows(Detector::PortScanners, 0, Rule::Once)
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
    }

    /// Two readers from the same cursor: the second stores nothing, so
    /// running `tick` and `batch` together does not double a count.
    #[test]
    fn a_second_reader_of_the_same_lines_stores_nothing() {
        let host = host();
        append(&host.access, &probe("203.0.113.5", now()));
        let jobs = [CronJob::Detect(Detector::ProbePaths)];
        let first = plan(&host.db, &jobs, &host.flags).unwrap();
        let second = plan(&host.db, &jobs, &host.flags).unwrap();

        let a = apply(&host.db, read_here(&first)).unwrap();
        let b = apply(&host.db, read_here(&second)).unwrap();

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
        let mut a = store(read_here(&plan(&host.db, &jobs, &host.flags).unwrap())).chunked(3);
        let mut b = store(read_here(&plan(&host.db, &jobs, &host.flags).unwrap())).chunked(3);

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

    /// A plan for `jobs` that finds the SSH log in the journal, read with
    /// the `journalctl` in `dir`: no file the search could find, whatever
    /// the machine running this has in /var/log.
    fn journal_plan(db: &Db, jobs: &[CronJob], dir: &Path) -> Plan {
        let mut plan = plan(db, jobs, &Flags::default()).unwrap();
        plan.sources.search = vec![dir.join("no-auth.log")];
        plan.with_journalctl(&dir.join("journalctl"))
    }

    /// The journal is read from a stored cursor after the first time, and
    /// the first time only as far back as a window needs.
    #[test]
    fn the_journal_is_read_from_its_cursor_and_first_only_as_far_back_as_needed() {
        let dir = tempfile::tempdir().unwrap();
        crate::testing::fake_journalctl(
            dir.path(),
            &format!(
                "echo '{}'",
                crate::testing::journal_entry(
                    "s=next",
                    now() - 60,
                    "Failed password for root from 203.0.113.50 port 1 ssh2"
                )
            ),
        );
        let db = Db::open_in_memory().unwrap();
        let jobs = [CronJob::Detect(Detector::SshScanners)];

        let first = apply(&db, read_here(&journal_plan(&db, &jobs, dir.path()))).unwrap();
        let second = apply(&db, read_here(&journal_plan(&db, &jobs, dir.path()))).unwrap();

        assert!(first.ssh.is_readable() && second.ssh.is_readable());
        let calls = crate::testing::journalctl_calls(dir.path());
        assert!(calls[0].contains("--since=@"), "{}", calls[0]);
        assert!(calls[1].contains("--after-cursor=s=next"), "{}", calls[1]);
        for call in &calls {
            assert!(call.contains("-o json"), "{call}");
        }
    }

    /// A quiet host: nothing from sshd in the look-back, but a journal
    /// with sshd in it. That is readable (the guard can run) and the next
    /// read starts after the newest entry, not from the look-back again.
    #[test]
    fn a_quiet_journal_is_readable_and_is_read_from_its_newest_entry_on() {
        let dir = tempfile::tempdir().unwrap();
        crate::testing::fake_journalctl(
            dir.path(),
            &format!(
                "case \"$*\" in *--lines=1*) echo '{}' ;; esac",
                crate::testing::journal_entry("s=newest", 1_000_000_000, "Server listening")
            ),
        );
        let db = Db::open_in_memory().unwrap();
        let jobs = [CronJob::RenderFirewall];

        let first = apply(&db, read_here(&journal_plan(&db, &jobs, dir.path()))).unwrap();
        apply(&db, read_here(&journal_plan(&db, &jobs, dir.path()))).unwrap();

        assert!(first.ssh.is_readable(), "{:?}", first.ssh);
        let calls = crate::testing::journalctl_calls(dir.path());
        let last = calls.last().unwrap();
        assert!(last.contains("--after-cursor=s=newest"), "{calls:?}");
    }

    /// And a journal with nothing from sshd in it at all -- which is what
    /// an unprivileged `journalctl` shows -- is not.
    #[test]
    fn an_empty_journal_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        crate::testing::fake_journalctl(dir.path(), "exit 0");
        let db = Db::open_in_memory().unwrap();

        let plan = journal_plan(&db, &[CronJob::RenderFirewall], dir.path());
        let applied = apply(&db, read_here(&plan)).unwrap();

        assert!(!applied.ssh.is_readable(), "{:?}", applied.ssh);
    }

    /// A first read of a log larger than one request is many requests,
    /// and comes to the same evidence and statistics as one read of it
    /// all, stored once with one cursor.
    #[test]
    fn a_log_read_in_many_requests_is_the_same_as_one_read() {
        struct Small<'a>(&'a Sources);
        impl LogReader for Small<'_> {
            fn read_log(&self, request: &Request) -> anyhow::Result<hostlog::Reply> {
                let mut request = request.clone();
                request.max_bytes = 500;
                self.0.read_log(&request)
            }

            fn read_rotated(&self, which: usize, since: i64, visit: &mut dyn FnMut(&str)) -> u64 {
                self.0.read_rotated(which, since, visit)
            }
        }
        let (whole, chunked) = (host(), host());
        for host in [&whole, &chunked] {
            for n in 0..40 {
                append(&host.access, &probe(&format!("203.0.113.{n}"), now() - n));
            }
            append(&host.auth, &failed("203.0.113.50").repeat(30));
        }
        let jobs = [
            CronJob::Detect(Detector::ProbePaths),
            CronJob::Detect(Detector::SshScanners),
            CronJob::RecordAccessStats,
        ];

        let one = plan(&whole.db, &jobs, &whole.flags).unwrap();
        let one = apply(&whole.db, read(&one, one.sources())).unwrap();
        let many = plan(&chunked.db, &jobs, &chunked.flags).unwrap();
        let many = apply(&chunked.db, read(&many, &Small(many.sources()))).unwrap();

        assert_eq!(probers(&chunked.db), probers(&whole.db));
        assert_eq!(probers(&chunked.db).len(), 40);
        let ssh = |db: &Db| {
            db.evidence_rows(Detector::SshScanners, 0, Rule::Once)
                .unwrap()
        };
        assert_eq!(
            format!("{:?}", ssh(&chunked.db)),
            format!("{:?}", ssh(&whole.db))
        );
        assert_eq!(
            (many.access_counts.lines, many.stats.total_hits),
            (one.access_counts.lines, one.stats.total_hits)
        );
        // Both stopped at the end, so a second pass reads nothing more.
        let again = plan(&chunked.db, &jobs, &chunked.flags).unwrap();
        let again = read(&again, again.sources());
        let [Outcome::Read(log)] = again.access.as_slice() else {
            panic!("the log is there");
        };
        assert_eq!(log.amount, 0);
    }

    // ---- several access logs ----

    /// Gives `host` an NGINX config root beside its logs, served from this
    /// host, with a site that logs to a file of its own, `name`; and
    /// returns that file. Each call adds a site.
    fn site_logging_to(host: &mut Host, name: &str) -> PathBuf {
        let dir = host.access.parent().unwrap().to_path_buf();
        let root = dir.join("nginx");
        std::fs::create_dir_all(&root).unwrap();
        let log = dir.join(name);
        std::fs::write(&log, "").unwrap();
        std::fs::write(
            root.join(format!("{name}.conf")),
            format!(
                "server {{ server_name {name}; access_log {}; }}\n",
                log.display()
            ),
        )
        .unwrap();
        host.flags.stored.root = root;
        host.flags.stored.config_logs_here = true;
        log
    }

    /// How many times `detector` counted each address, in address order.
    fn counted(db: &Db, detector: Detector) -> Vec<(String, u64)> {
        let mut counts: Vec<(String, u64)> = Vec::new();
        for row in db.evidence_rows(detector, 0, Rule::Once).unwrap() {
            match counts
                .iter_mut()
                .find(|(address, _)| *address == row.address)
            {
                Some((_, count)) => *count += row.tally.count,
                None => counts.push((row.address, row.tally.count)),
            }
        }
        counts.sort();
        counts
    }

    /// A site that logs to its own file is seen as the main log is, and
    /// each file is read from its own cursor: one of them rotating changes
    /// nothing for the other, and no line is counted twice.
    #[test]
    fn every_access_log_the_config_names_is_read_from_its_own_cursor() {
        let mut host = host();
        let site = site_logging_to(&mut host, "shop.log");
        append(&host.access, &probe("203.0.113.1", now() - 60));
        append(&site, &probe("203.0.113.2", now() - 60));
        pass(&host);

        std::fs::rename(&site, host.access.with_file_name("shop.log.1")).unwrap();
        append(&site, &probe("203.0.113.3", now()));
        append(&host.access, &probe("203.0.113.4", now()));
        pass(&host);
        pass(&host);

        assert_eq!(
            counted(&host.db, Detector::ProbePaths),
            [
                ("203.0.113.1".to_string(), 1),
                ("203.0.113.2".to_string(), 1),
                ("203.0.113.3".to_string(), 1),
                ("203.0.113.4".to_string(), 1),
            ]
        );
        for log in [&host.access, &site] {
            assert!(
                host.db.get_log_cursor(&source_key(log)).unwrap().is_some(),
                "no cursor of its own for {}",
                log.display()
            );
        }
    }

    /// A fresh install the morning after a rotation: what logrotate kept,
    /// plain and compressed, is evidence as far back as the window, and no
    /// further. The tally of visits counts from the first read on.
    #[test]
    fn a_first_read_also_reads_what_logrotate_kept_within_the_window() {
        let host = host();
        let named = |suffix: &str| host.access.with_file_name(format!("access.log{suffix}"));
        let visit = format!(
            "{}\n",
            crate::testing::access_line_at(
                "203.0.113.9",
                "GET / HTTP/1.1",
                200,
                "Mozilla/5.0",
                now()
            )
        );
        std::fs::write(named(".1"), probe("203.0.113.1", now() - HOUR) + &visit).unwrap();
        crate::testing::write_gzip(
            &named(".2.gz"),
            &probe("203.0.113.2", now() - 6 * HOUR),
            now() - 6 * HOUR,
        );
        crate::testing::write_gzip(
            &named(".3.gz"),
            &probe("203.0.113.3", now() - 72 * HOUR),
            now() - 72 * HOUR,
        );
        append(&host.access, &probe("203.0.113.4", now()));

        let applied = pass(&host);

        assert_eq!(
            probers(&host.db),
            ["203.0.113.1", "203.0.113.2", "203.0.113.4"],
            "the three-day-old copy is outside the 24-hour window"
        );
        assert_eq!(
            applied.stats.total_hits, 0,
            "the rotated visit is not tallied"
        );
    }

    /// Only the first read: after it, the cursor says where the log is,
    /// and what was kept beside it is not read again.
    #[test]
    fn what_logrotate_kept_is_not_read_again_after_the_first_read() {
        let host = host();
        let copy = host.access.with_file_name("access.log.1");
        std::fs::write(&copy, probe("203.0.113.1", now() - HOUR)).unwrap();
        pass(&host);

        append(&copy, &probe("203.0.113.2", now()));
        append(&host.access, &probe("203.0.113.3", now()));
        pass(&host);

        assert_eq!(
            counted(&host.db, Detector::ProbePaths),
            [
                ("203.0.113.1".to_string(), 1),
                ("203.0.113.3".to_string(), 1)
            ]
        );
    }

    /// One log missing among several is reported, by its path, and the
    /// detectors still have the rest.
    #[test]
    fn a_log_missing_among_several_is_reported_and_the_rest_are_read() {
        let mut host = host();
        let site = site_logging_to(&mut host, "shop.log");
        append(&site, &probe("203.0.113.2", now()));
        std::fs::remove_file(&host.access).unwrap();

        let applied = pass(&host);

        assert!(applied.access.is_readable(), "{:?}", applied.access);
        assert_eq!(
            applied.unreadable_access_logs(),
            [host.access.display().to_string()]
        );
        assert_eq!(
            applied.unreadable_note(),
            format!("; could not read {}", host.access.display())
        );
        assert_eq!(probers(&host.db), ["203.0.113.2"]);
    }

    /// A web server in a container names the paths it has inside it: a
    /// file of the same name on this host is not its log, and is not read.
    #[test]
    fn the_config_s_logs_are_not_read_for_a_web_server_in_a_container() {
        let mut host = host();
        let site = site_logging_to(&mut host, "shop.log");
        append(&site, &probe("203.0.113.2", now()));
        append(&host.access, &probe("203.0.113.1", now()));
        host.flags.stored = crate::hostconf::HostConf {
            nginx_root: Some(host.flags.stored.root.clone()),
            nginx_test_command: Some("docker exec web nginx -t".to_string()),
            access_log: Some(host.access.clone()),
            ssh_log: Some(host.auth.clone()),
            ..Default::default()
        }
        .log_paths();

        let applied = pass(&host);

        assert_eq!(applied.access_logs.len(), 1, "{:?}", applied.access_logs);
        assert_eq!(probers(&host.db), ["203.0.113.1"]);
    }

    /// `--access-log` reads the file it names and nothing else: not the
    /// stored log, and not the config's.
    #[test]
    fn a_flag_reads_only_the_file_it_names() {
        let mut host = host();
        let site = site_logging_to(&mut host, "shop.log");
        let asked = host.access.with_file_name("copy.log");
        append(&site, &probe("203.0.113.2", now()));
        append(&host.access, &probe("203.0.113.1", now()));
        append(&asked, &probe("203.0.113.3", now()));
        host.flags.access_log = Some(asked);

        pass(&host);

        assert_eq!(probers(&host.db), ["203.0.113.3"]);
    }
}
