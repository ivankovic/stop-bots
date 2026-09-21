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
//! The access-log read offset is shared the same way, and is the easier
//! half to get wrong: it is keyed by the log's path, so a key of batch's
//! own would re-tally the whole log on the first run and double-count
//! every line thereafter. See [`scan_logs`].

use crate::cron::CronJob;
use crate::db::Db;
use crate::firewall::{self, FirewallBackend, LockoutStatus};
use crate::protection::Detector;
use crate::{accessstats, nginx, refresh};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Everything a batch run needs to know, resolved from the CLI.
pub struct BatchOptions {
    /// The NGINX config root to scan and apply to.
    pub root: PathBuf,
    /// Where the firewall script is written.
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
async fn update_lists(db: &Db) -> Vec<Step> {
    let plan = match refresh::plan(db) {
        Ok(plan) => plan,
        Err(err) => return vec![Step::new("update lists", Err(err))],
    };

    let mut outcomes = Vec::new();
    for source in plan {
        let outcome = match refresh::fetch(&source).await {
            Ok(raw) => refresh::store(db, &source, &raw),
            Err(err) => Err(err),
        };
        outcomes.push((source, outcome.map_err(|err| format!("{err:#}"))));
    }

    if refresh::crawler_ranges_all_succeeded(&outcomes) {
        crate::cron::record_run(db, CronJob::UpdateIpRanges, "updated by batch run");
    }

    outcomes
        .into_iter()
        .map(|(source, outcome)| Step {
            name: source.label(),
            outcome,
        })
        .collect()
}

/// Tallies the access log and runs every switched-on detector.
///
/// Both logs are read once and shared across the detectors that want them,
/// rather than re-read per detector: on a busy server an access log is
/// tens of megabytes, and eight detectors re-reading it would be eight
/// times the I/O for identical bytes.
fn scan_logs(db: &Db, options: &BatchOptions) -> Vec<Step> {
    let mut steps = Vec::new();
    let access_log =
        read_log(
            options.access_log.as_deref(),
            || match crate::accesslog::find_default_source() {
                crate::accesslog::LogSource::Found(text) => Some(text),
                crate::accesslog::LogSource::Unavailable => None,
            },
        );
    let ssh_log = read_log(
        options.ssh_log.as_deref(),
        || match crate::sshlog::find_default_source() {
            crate::sshlog::LogSource::Found(text) => Some(text),
            crate::sshlog::LogSource::Unavailable => None,
        },
    );

    // Keyed by the log's real path, not by anything batch invents. That
    // key is where `Db` remembers how far into the log has already been
    // counted, so a key of its own would mean re-tallying the whole log on
    // the first run and then double-counting every line for as long as
    // anything else (the TUI, `record-access-stats`) also ran. The number
    // being inflated is the one Firewall shows an admin when
    // they decide whether to block a user agent.
    let log_path = options
        .access_log
        .clone()
        .unwrap_or_else(|| PathBuf::from(crate::accesslog::DEFAULT_LOG_PATH));
    let stats = match &access_log {
        Some(text) => accessstats::record_access_stats(db, &log_path.to_string_lossy(), text)
            .map(|outcome| format!("{} user agent(s)", outcome.distinct_user_agents)),
        None => Ok("skipped: no NGINX access log".to_string()),
    };
    if stats.is_ok() {
        crate::cron::record_run(db, CronJob::RecordAccessStats, "recorded by batch run");
    }
    steps.push(Step::new("access stats", stats));

    for detector in Detector::ALL {
        let outcome = run_one_detector(db, detector, &access_log, &ssh_log);
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
    access_log: &Option<String>,
    ssh_log: &Option<String>,
) -> Result<String> {
    if !detector.is_enabled(db)? {
        return Ok("off".to_string());
    }
    let log = if detector.spec().uses_ssh_log {
        ssh_log
    } else {
        access_log
    };
    let Some(text) = log else {
        return Ok("skipped: log unavailable".to_string());
    };
    let ttl = detector.ttl_days(db)?;
    Ok(crate::scanblock::run_detector(db, detector, ttl, text, false)?.summary())
}

/// Reads an override path, or falls back to the project's usual detection.
/// A missing override is `None` rather than an error: a detector that has
/// no log to read says so and the run carries on.
fn read_log(
    override_path: Option<&Path>,
    detect: impl FnOnce() -> Option<String>,
) -> Option<String> {
    match override_path {
        Some(path) => std::fs::read_to_string(path).ok(),
        None => detect(),
    }
}

fn apply_nginx(db: &Db, options: &BatchOptions) -> Step {
    let outcome = (|| -> Result<String> {
        let applied = nginx::apply_all_sites(db, &options.root)?;
        let mut summary = format!(
            "{} site(s), {} file(s) changed",
            applied.sites, applied.changed
        );
        // Writing the sentinel block does nothing until NGINX re-reads it,
        // so there is nothing to reload when nothing changed on disk.
        if applied.changed > 0 && options.apply {
            let commands = nginx::NginxCommands::from_db(db)?;
            nginx::reload_with(&commands).context("config was written, but the reload failed")?;
            summary.push_str(", reloaded");
        }
        Ok(summary)
    })();
    Step::new("nginx blocks", outcome)
}

/// Renders the firewall script, and runs it if `--apply`.
///
/// The lockout guard is the whole reason this function is not three lines.
/// See [`lockout_verdict`] for why "the guard could not run" is a refusal
/// here and only a note in `render-firewall`.
fn render_and_apply_firewall(db: &Db, options: &BatchOptions) -> Step {
    let outcome = (|| -> Result<String> {
        let built = firewall::build_script(db, options.backend)?;
        lockout_verdict(&built.rules, options)?;

        firewall::write_script(&options.out, &built.script)?;
        db.set_firewall_rendered_signature(&firewall::rules_signature(&built.rules))?;
        let mut summary = format!("{} rule(s) to {}", built.written, options.out.display());

        if options.apply {
            firewall::apply_script(options.backend, &options.out)
                .with_context(|| format!("script written to {}", options.out.display()))?;
            summary.push_str(", applied");
        }
        Ok(summary)
    })();
    let step = Step::new("firewall", outcome);
    if step.outcome.is_ok() {
        crate::cron::record_run(db, CronJob::RenderFirewall, "rendered by batch run");
    }
    step
}

/// Decides whether these rules may be written and applied.
///
/// Without `--apply` nothing is enforced, so a risky rule set is written
/// anyway and the admin still gets to look at the script before running
/// it — same as `render-firewall`.
///
/// With `--apply`, both a guard that objects and a guard that *could not
/// run* are refusals. The second is the one worth spelling out: on a host
/// where no SSH log is readable, the check silently passing is how this
/// project once wrote and applied a script that took a server off the
/// network. An interactive run can print a note and let a human decide;
/// there is no human here.
fn lockout_verdict(rules: &[crate::db::FirewallRule], options: &BatchOptions) -> Result<()> {
    if !options.apply || options.force {
        return Ok(());
    }
    match firewall::assess_lockout_risk(rules, options.ssh_log.as_deref()) {
        LockoutStatus::LogUnavailable => anyhow::bail!(
            "refusing to apply: no SSH log could be read, so the lockout safety check \
             could not run. Point --ssh-log at the right file, or drop --apply and run \
             the script by hand. --force overrides this."
        ),
        LockoutStatus::Risks(risks) if !risks.is_empty() => {
            let ips = risks
                .iter()
                .map(|(ip, cidr)| format!("{ip} (blocked by {cidr})"))
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "refusing to apply: would block {} currently-connected SSH client \
                 IP address(es): {ips}. --force overrides this.",
                risks.len()
            )
        }
        _ => Ok(()),
    }
}
