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

//! Batch mode: one unattended pass over everything the TUI would do by
//! hand, for a real `cron` entry.
//!
//! Refresh every list, scan the logs, write the blocks, and — only if
//! asked — put them into effect. This is the one place in the project that
//! will run `nft -f` and `systemctl reload nginx` with nobody watching, so
//! the rules around that are stricter here than anywhere else:
//!
//! - **Nothing is enforced without `--apply`.** Without it this writes
//!   NGINX config and a firewall script and stops there, which is inert:
//!   config does nothing until a reload, and a script does nothing until
//!   it is run. That keeps the project's "generated, never applied
//!   automatically" default intact for anyone who wants it.
//! - **The lockout guard can refuse, and refusing wins.** Under `--apply`,
//!   a guard that *cannot run* — no readable SSH log — is treated exactly
//!   like a guard that says no. In an interactive `render-firewall` a
//!   human sees the note and decides; from crontab there is no human, and
//!   this project has already taken a server off the network once by
//!   letting that case fall through.
//! - **A failure never silently becomes success.** Every step reports its
//!   own outcome, one step's failure doesn't stop the others, and the exit
//!   status is non-zero if any of them failed — which is what makes `cron`
//!   mail you.
//!
//! ## What "every list" means
//!
//! Bot lists and crawler IP ranges are refreshed in full: there are three
//! of each, they are small, and everything else depends on them.
//! Reputation feeds and country ranges are refreshed only where they are
//! **switched on or selected** — fetching AWS's published address space
//! for a feed nobody enabled is megabytes for nothing.
//!
//! `--no-fetch` skips all four. Bot lists change weekly and an access log
//! changes every second, so a nightly full run plus a frequent
//! `--no-fetch --apply` is the pair the README recommends.
//!
//! ## Two independent planes
//!
//! NGINX config and the firewall script are separate mechanisms, and one
//! failing must not stop the other: an NGINX reload that fails leaves the
//! firewall half perfectly applicable, and vice versa. They are the last
//! two steps, and neither is conditional on the other.
//!
//! ## Shared schedule state
//!
//! Each step that matches one of the TUI's internal cron jobs records
//! itself through the same `Db::set_cron_last_run` key. That is
//! deliberate: it is the same work against the same database, so an admin
//! running both gets one detection pass rather than two, and the
//! Dashboard's "Scheduled tasks" panel shows what the *real* cron did
//! rather than claiming everything is overdue.
//!
//! Where each log was last read up to is shared the same way (see
//! [`crate::logscan`]): keyed by the log's path, so a line the console
//! already read is not read again here, and the other way round. A key of
//! batch's own would re-read the whole log on the first run and count
//! every line twice thereafter.

use crate::cron::CronJob;
use crate::db::Db;
use crate::firewall::{self, FirewallBackend};
use crate::protection::Detector;
use crate::{nginx, refresh};
use anyhow::Result;
use std::path::{Path, PathBuf};

/// Everything a batch run needs to know, resolved from the CLI.
pub struct BatchOptions {
    /// The NGINX config root to scan and apply to.
    pub root: PathBuf,
    /// The applied firewall script: the one the boot unit loads. A render
    /// is written beside it and replaces it only when applied.
    pub out: PathBuf,
    pub backend: FirewallBackend,
    /// Whether to reload NGINX and run the firewall script, rather than
    /// only writing both.
    pub apply: bool,
    /// Overrides log auto-detection. `--ssh-log` matters more here than
    /// anywhere else in the project: `cron` runs as root, so a plain
    /// `/var/log/auth.log` is usually readable, but on a journald-only
    /// host `journalctl` under cron can come back empty — and that is the
    /// case where the lockout guard refuses.
    pub ssh_log: Option<PathBuf>,
    pub access_log: Option<PathBuf>,
    /// Applies even when the lockout guard objects, or couldn't run.
    pub force: bool,
    /// Skips every step that downloads something.
    ///
    /// Two audiences. A host without outbound access, where those steps
    /// would only ever fail — and a crontab that wants detection more
    /// often than refreshing: bot lists change weekly, an access log
    /// changes every second, so a nightly full run plus a ten-minute
    /// `--no-fetch --apply` is a reasonable pair. It also makes this whole
    /// module testable without a network.
    pub no_fetch: bool,
    /// The host settings: the NGINX commands, and the logs to read where
    /// no flag names them. See [`crate::hostconf`].
    pub host: crate::hostconf::HostConf,
}

/// One step's outcome. `Err` holds a message rather than an
/// `anyhow::Error` because by the time a report is printed, every failure
/// is just text — and keeping them uniform is what lets one step fail
/// without unwinding the run.
pub struct Step {
    pub name: String,
    pub outcome: Result<String, String>,
}

impl Step {
    fn new(name: impl Into<String>, outcome: Result<String>) -> Self {
        Step {
            name: name.into(),
            outcome: outcome.map_err(|err| format!("{err:#}")),
        }
    }
}

/// Every step of one run, in the order they happened.
pub struct BatchReport {
    pub steps: Vec<Step>,
}

impl BatchReport {
    pub fn failures(&self) -> usize {
        self.steps.iter().filter(|s| s.outcome.is_err()).count()
    }

    /// The whole run, one line per step — for `--verbose`, and for a first
    /// run by hand.
    pub fn full(&self) -> String {
        self.steps
            .iter()
            .map(|step| match &step.outcome {
                Ok(summary) => format!("ok    {}: {summary}", step.name),
                Err(err) => format!("FAIL  {}: {err}", step.name),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Only what went wrong. This is what an unattended run prints, so
    /// that a healthy nightly pass mails nobody anything.
    pub fn failures_only(&self) -> String {
        self.steps
            .iter()
            .filter_map(|step| step.outcome.as_ref().err().map(|err| (&step.name, err)))
            .map(|(name, err)| format!("FAIL  {name}: {err}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Runs one full pass. Never returns `Err` for a step failing — that is
/// what the report is for; the caller decides the exit status from
/// [`BatchReport::failures`].
pub async fn run(db: &Db, options: &BatchOptions) -> BatchReport {
    let mut steps = Vec::new();

    steps.push(Step::new("built-in bot list", store_built_in_list(db)));
    steps.push(Step::new("scan sites", scan_sites(db, &options.root)));
    if !options.no_fetch {
        steps.extend(update_lists(db).await);
    }
    steps.extend(scan_logs(db, options));

    // The two enforcement planes, in that order and independent of each
    // other: whichever fails, the other still gets its turn.
    steps.push(apply_nginx(db, options));
    steps.push(render_and_apply_firewall(db, options));

    BatchReport { steps }
}

/// Stores the bot list compiled into this binary, as the TUI and the web
/// console do when they start.
///
/// Its own step, not part of `update lists`, because it downloads nothing
/// and so has to happen under `--no-fetch` too. It used to happen only as
/// one of the downloads, so a host run by `batch --no-fetch` alone, which
/// is what a host without outbound access runs, never had it: a fresh
/// install then blocked no user agent at all, with every step reporting
/// success.
fn store_built_in_list(db: &Db) -> Result<String> {
    crate::botlist::register_all_sources(db)?;
    Ok(format!(
        "{} bot(s) in the list built into this binary",
        crate::botlist::stop_bots_extras::bots().len()
    ))
}

fn scan_sites(db: &Db, root: &Path) -> Result<String> {
    let sites = nginx::discover_sites(root)?;
    for site in &sites {
        db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
    }
    Ok(format!("{} site(s) under {}", sites.len(), root.display()))
}

/// Refreshes every list the blocking policy is built from. See the module
/// doc comment for why reputation feeds and countries are filtered and the
/// other two aren't.
/// Every downloadable list, through the shared plan in `refresh`.
///
/// This used to enumerate the four kinds of source itself, which is how
/// the web console ended up unable to offer the same button: the loop held
/// `&Db` across every `.await`, and `Db` is not `Sync`. `refresh::plan`
/// now decides *what* to update and both front-ends drive the fetching in
/// whatever order their runtime allows.
///
/// Holds the download lease (see [`refresh::Lease`]) while it runs. When a
/// front-end's download holds it, this fetches nothing and says so as a
/// step that did not fail: the lists are being updated, just not by this
/// process, and a nightly run should not mail anyone over it.
async fn update_lists(db: &Db) -> Vec<Step> {
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    };
    let lease = match refresh::claim(db, now()) {
        Ok(refresh::Claim::Granted(lease)) => lease,
        Ok(refresh::Claim::Busy { since }) => {
            return vec![Step::new(
                "update lists",
                Ok(format!("skipped: {}", refresh::Claim::busy_message(since))),
            )]
        }
        Err(err) => return vec![Step::new("update lists", Err(err))],
    };
    let plan = match refresh::plan(db) {
        Ok(plan) => plan,
        Err(err) => {
            let _ = refresh::release(db, &lease);
            return vec![Step::new("update lists", Err(err))];
        }
    };

    let mut outcomes = Vec::new();
    for source in plan {
        let outcome = match refresh::fetch(&source).await {
            Ok(raw) => refresh::store(db, &source, &raw),
            Err(err) => Err(err),
        };
        outcomes.push((source, outcome.map_err(|err| format!("{err:#}"))));
        let _ = refresh::renew(db, &lease, now());
    }

    refresh::record(db, &outcomes, "by batch run");
    let _ = refresh::release(db, &lease);

    outcomes
        .into_iter()
        .map(|(source, outcome)| Step {
            name: source.label(),
            outcome,
        })
        .collect()
}

/// Records recent SSH logins, tallies the access log and runs every
/// switched-on detector.
///
/// One pass over both logs, the same one the internal cron makes (see
/// [`crate::logscan`]): each is read once, from where the last reader of
/// it stopped, whoever that was. The logs are the flags if given and the
/// stored paths otherwise; `set-log-paths` used to be ignored here.
fn scan_logs(db: &Db, options: &BatchOptions) -> Vec<Step> {
    let mut jobs: Vec<CronJob> = Detector::ALL.into_iter().map(CronJob::Detect).collect();
    jobs.push(CronJob::RecordAccessStats);
    let flags = crate::logscan::Flags {
        ssh_log: options.ssh_log.clone(),
        access_log: options.access_log.clone(),
        stored: options.host.log_paths(),
    };
    let applied = match crate::logscan::run(db, &jobs, &flags) {
        Ok(applied) => applied,
        Err(err) => return vec![Step::new("read logs", Err(err))],
    };

    // Before the detectors, as the internal cron does it: on a host that
    // runs stop-bots only from crontab this is the only thing feeding the
    // anti-lockout window, and the firewall step below renders that window
    // as Allow rules ahead of everything else.
    let logins = if applied.ssh.is_readable() {
        Ok(format!(
            "{} address(es) logged in since the last read",
            applied.logins.len()
        ))
    } else {
        Ok("skipped: no SSH log".to_string())
    };
    let mut steps = vec![Step::new("ssh logins", logins)];

    let stats = if applied.access.is_readable() {
        crate::cron::record_run(db, CronJob::RecordAccessStats, "recorded by batch run");
        Ok(format!(
            "{} user agent(s)",
            applied.stats.distinct_user_agents
        ))
    } else {
        Ok("skipped: no NGINX access log".to_string())
    };
    steps.push(Step::new("access stats", stats));

    for detector in Detector::ALL {
        let outcome = run_one_detector(db, detector, &applied);
        if let Ok(summary) = &outcome {
            crate::cron::record_run(db, CronJob::Detect(detector), summary);
        }
        steps.push(Step::new(detector.spec().label, outcome));
    }
    steps
}

fn run_one_detector(
    db: &Db,
    detector: Detector,
    applied: &crate::logscan::Applied,
) -> Result<String> {
    if !detector.is_enabled(db)? {
        return Ok("off".to_string());
    }
    let log = if detector.spec().uses_ssh_log {
        &applied.ssh
    } else {
        &applied.access
    };
    if !log.is_readable() {
        return Ok("skipped: log unavailable".to_string());
    }
    let ttl = detector.ttl_days(db)?;
    Ok(crate::scanblock::run_detector(db, detector, ttl, applied.now, false)?.summary())
}

fn apply_nginx(db: &Db, options: &BatchOptions) -> Step {
    let outcome = (|| -> Result<String> {
        // Tested, and reloaded only when something changed on disk; a
        // config the test rejects is put back rather than left for the
        // next reload to find.
        let commands = options
            .apply
            .then(|| nginx::NginxCommands::from_host(&options.host))
            .transpose()?;
        let applied = nginx::apply_all_sites_and_reload(db, &options.root, commands.as_ref())?;
        let mut summary = format!(
            "{} site(s), {} file(s) changed",
            applied.sites, applied.changed
        );
        if applied.reloaded {
            summary.push_str(", reloaded");
        }
        // Counted rather than listed: the report is a line per step. The
        // status report and `apply-blocks` name them.
        let skipped = nginx::skipped_entries(db)?.len();
        if skipped > 0 {
            summary.push_str(&format!(
                ", {skipped} stored entr(ies) left out (see `stop-bots status`)"
            ));
        }
        Ok(summary)
    })();
    Step::new("nginx blocks", outcome)
}

/// Renders the firewall script, and runs it if `--apply` — through
/// [`firewall::render_and_apply`], whose policy is the one every front-end
/// shares. Here that means a guard that *could not run* refuses the apply:
/// on a host where no SSH log is readable, the check silently passing is
/// how this project once wrote and applied a script that took a server off
/// the network, and there is no human here to decide otherwise.
///
/// `--out` names the *applied* script, the one the boot unit loads; the
/// render goes beside it (see [`firewall::rendered_path`]) and replaces it
/// only when an apply succeeded.
fn render_and_apply_firewall(db: &Db, options: &BatchOptions) -> Step {
    let run = firewall::FirewallRun::new(options.backend, &options.out)
        .apply(options.apply)
        .force(options.force);
    // Wherever `LogPaths` says the SSH log is: `--ssh-log` first, then the
    // stored path, then a search.
    let source = options.host.log_paths().ssh(options.ssh_log.as_deref());
    let outcome =
        firewall::render_and_apply(db, run, firewall::SshLog::Read(&source)).and_then(|outcome| {
            let summary = outcome.summary();
            if outcome.succeeded() {
                Ok(summary)
            } else if outcome.refused() {
                Err(anyhow::anyhow!(
                    "{summary}. Point --ssh-log at the right file, or --force if you know"
                ))
            } else {
                Err(anyhow::anyhow!("{summary}"))
            }
        });
    let step = Step::new("firewall", outcome);
    if step.outcome.is_ok() {
        crate::cron::record_run(db, CronJob::RenderFirewall, "rendered by batch run");
    }
    step
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Options for a `scan_logs` pass over the given SSH log, with an
    /// access log that does not exist.
    fn reading_ssh_log(dir: &Path, ssh_log: &Path) -> BatchOptions {
        BatchOptions {
            root: dir.to_path_buf(),
            out: dir.join("fw.nft"),
            backend: FirewallBackend::Nftables,
            apply: false,
            ssh_log: Some(ssh_log.to_path_buf()),
            access_log: Some(dir.join("no-access.log")),
            force: false,
            no_fetch: true,
            host: crate::hostconf::HostConf::default(),
        }
    }

    /// A host that runs stop-bots only from crontab has nothing else
    /// feeding the anti-lockout window, so batch has to, or the guard is
    /// left with only the Accepted lines logrotate has not yet taken.
    #[test]
    fn a_batch_run_records_the_addresses_it_saw_ssh_logins_from() {
        let db = Db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ssh_log = dir.path().join("auth.log");
        std::fs::write(
            &ssh_log,
            "Accepted publickey for m from 203.0.113.5 port 55000 ssh2\n",
        )
        .unwrap();

        scan_logs(&db, &reading_ssh_log(dir.path(), &ssh_log));

        assert_eq!(db.recent_ssh_login_ips().unwrap(), vec!["203.0.113.5"]);
    }

    /// `set-log-paths` is where a host that keeps its logs elsewhere says
    /// so, and batch used to read the defaults regardless.
    #[test]
    fn a_batch_run_reads_the_stored_log_paths_when_no_flag_is_given() {
        let db = Db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ssh_log = dir.path().join("elsewhere-auth.log");
        std::fs::write(
            &ssh_log,
            "Accepted publickey for m from 203.0.113.9 port 55000 ssh2\n",
        )
        .unwrap();
        let options = BatchOptions {
            ssh_log: None,
            host: crate::hostconf::HostConf {
                ssh_log: Some(ssh_log.clone()),
                ..Default::default()
            },
            ..reading_ssh_log(dir.path(), &ssh_log)
        };

        scan_logs(&db, &options);

        assert_eq!(db.recent_ssh_login_ips().unwrap(), vec!["203.0.113.9"]);
    }
}
