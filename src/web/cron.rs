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

//! The internal cron, driven by the web server.
//!
//! The TUI has run [`crate::cron`]'s jobs since they existed, which meant
//! "automatic" and "a terminal is open" were the same thing. They aren't
//! any more: a web server left running keeps the same schedule, using the
//! same `Db` keys, so whichever front-end happens to be up does the work
//! and neither repeats what the other already did.
//!
//! ## Why this is so much smaller than the TUI's version
//!
//! `App` splits every job in half — start it on a background thread, send
//! an event, finish it back on the main thread — because `Db` is not
//! `Sync` and the TUI's database handle lives on the thread that draws.
//! Here [`AppState::with_db`] already is that door, so a job is just an
//! `async fn` that awaits its halves in order.
//!
//! The one rule this file has to keep by hand is the one `with_db`'s
//! signature can't express: **read and parse the logs outside the lock.**
//! A read can be a large file or a `journalctl`, and doing it inside
//! `with_db` would hold the database against every in-flight request for
//! the duration. [`crate::logscan::read`] takes no `Db` precisely so that
//! this stays possible: the plan is made under the lock, the read happens
//! outside it, and only storing what it found goes back in.

use crate::cron::{self, CronJob};
use crate::web::state::AppState;

/// Starts the cron loop for a running server.
///
/// Spawned from [`crate::web::server::serve`] rather than from `router`,
/// so that driving the router directly — which the integration tests do
/// hundreds of times — never starts a background task. Tests of the cron
/// itself call [`tick`].
///
/// The handle is returned so `serve` can abort the loop on the one path
/// where it outlives the server: `axum::serve` returning an error rather
/// than the process being killed under it. Dropping the handle would
/// detach the task instead, which is harmless but leaves a tick running
/// against a database nothing is serving from.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Checked immediately, then once per interval — not the other way
        // round. A fresh install has every job due, and a server that sat
        // for a full minute doing nothing before its first tick looks
        // broken in exactly the way the Dashboard's "due now" tags
        // contradict. The TUI backdates its first check for the same
        // reason.
        loop {
            tick(&state).await;
            tokio::time::sleep(cron::CHECK_INTERVAL).await;
        }
    })
}

/// Runs every job that is currently due, in order, and returns how many
/// ran.
///
/// Sequential on purpose. The jobs share one database behind one mutex, so
/// running them concurrently would buy nothing but lock contention, and
/// two detectors writing blocks at once is not a race worth inviting.
///
/// A failure is reported and the run continues: a cron pass that gives up
/// on the first unreadable log is a cron pass that stops doing the other
/// three jobs forever.
pub async fn tick(state: &AppState) -> usize {
    let due = match state.with_db(cron::due_jobs).await {
        Ok(due) => due,
        Err(err) => {
            eprintln!("stop-bots: cron could not read its schedule: {err:#}");
            return 0;
        }
    };

    let mut ran = 0;
    // Every due job that reads a log, in one pass: each log is read once
    // for all of them, rather than once per job.
    let log_jobs: Vec<CronJob> = due
        .iter()
        .copied()
        .filter(|j| cron::is_log_job(*j))
        .collect();
    if !log_jobs.is_empty() {
        match run_log_jobs(state, log_jobs.clone()).await {
            Ok(()) => ran += log_jobs.len(),
            Err(err) => eprintln!("stop-bots: the log pass failed: {err:#}"),
        }
    }
    for job in due.into_iter().filter(|j| !cron::is_log_job(*j)) {
        let result = match job {
            CronJob::UpdateIpRanges => update_ip_ranges(state).await,
            CronJob::UpdateEverything => update_everything(state, "by the schedule")
                .await
                .map(|_| ()),
            CronJob::HealthCheck => health_check(state).await,
            CronJob::Maintenance => maintenance(state).await,
            CronJob::ApplyNginx => apply_nginx(state).await,
            CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::RenderFirewall => {
                unreachable!("run in the log pass above")
            }
        };
        match result {
            Ok(()) => ran += 1,
            Err(err) => eprintln!("stop-bots: cron job {} failed: {err:#}", job.id()),
        }
    }
    ran
}

/// Re-applies site configs and reloads NGINX, when the admin has switched
/// auto-apply on.
///
/// The switch is read here, before any work, as `cron::apply_nginx` does;
/// the apply itself is the console's privileged operation (see
/// [`crate::privileged`]), in this process or in the root helper. Under
/// `stop-bots web --no-apply` it writes configs without ever reloading,
/// exactly as it does for an apply an operator asks for by hand.
async fn apply_nginx(state: &AppState) -> anyhow::Result<()> {
    let summary = match state.with_db(|db| db.get_auto_apply()).await {
        Ok(false) => "auto-apply is off".to_string(),
        Err(err) => format!("error: {err}"),
        Ok(true) => match state.privileged().apply_all(true).await {
            Ok(applied) => cron::apply_nginx_summary(&applied),
            Err(err) => format!("error: {err:#}"),
        },
    };
    state
        .with_db(move |db| {
            cron::record_run(db, CronJob::ApplyNginx, &summary);
            Ok(())
        })
        .await
}

/// Prunes and compacts the database.
///
/// The whole job is database work, so unlike its neighbours there is no
/// half to hoist out of the lock — it is one `with_db` and nothing else.
/// Holding the lock across a compaction is the point rather than a cost:
/// `VACUUM` rewrites the file, and a request reading through it mid-rewrite
/// is exactly what the lock exists to prevent.
async fn maintenance(state: &AppState) -> anyhow::Result<()> {
    state
        .with_db(|db| {
            let summary = cron::maintenance(db);
            cron::record_run(db, CronJob::Maintenance, &summary);
            Ok(())
        })
        .await
}

/// One log pass for `jobs`: planned under the lock, read and parsed off
/// the async runtime and outside the lock, stored and decided under it
/// again.
async fn run_log_jobs(state: &AppState, jobs: Vec<CronJob>) -> anyhow::Result<()> {
    let flags = crate::logscan::Flags {
        ssh_log: state.ssh_log.clone(),
        access_log: None,
        stored: state.host().log_paths(),
    };
    let planned = jobs.clone();
    let plan = state
        .with_db(move |db| crate::logscan::plan(db, &planned, &flags))
        .await?;
    let read = tokio::task::spawn_blocking(move || crate::logscan::read(&plan))
        .await
        .map_err(|err| anyhow::anyhow!("the log-reading thread panicked: {err}"))?;

    // Stored one transaction at a time, letting the lock go between them:
    // a large read stored whole kept every request waiting, `/login`
    // included, for seconds. See `logscan::Storing`.
    let mut storing = crate::logscan::store(read);
    let applied = loop {
        let (returned, done) = state
            .with_db(move |db| {
                let done = storing.step(db)?;
                Ok((storing, done))
            })
            .await?;
        storing = returned;
        if let Some(applied) = done {
            break applied;
        }
    };

    // The firewall render writes `/etc/stop-bots`, so it is the console's
    // privileged operation rather than one of the jobs run here.
    let render = jobs.contains(&CronJob::RenderFirewall);
    let logins = applied.logins.clone();
    let jobs: Vec<CronJob> = jobs
        .into_iter()
        .filter(|job| *job != CronJob::RenderFirewall)
        .collect();
    let out = state.firewall_out.clone();
    let apply = state.apply_for_real;
    state
        .with_db(move |db| cron::run_log_jobs(db, &jobs, &applied, out.as_deref(), apply))
        .await?;
    if render {
        render_firewall(state, logins).await?;
    }
    Ok(())
}

/// The `RenderFirewall` job: renders and writes the script, and applies it
/// when `set-auto-apply-firewall` says so, through the console's
/// privileged operation. The guard also protects whoever this pass saw log
/// in, besides those the SSH log and the database name.
async fn render_firewall(state: &AppState, logins: Vec<String>) -> anyhow::Result<()> {
    let apply = state.with_db(|db| db.get_auto_apply_firewall()).await?;
    let protect = logins
        .iter()
        .filter_map(|address| address.parse::<std::net::IpAddr>().ok())
        .collect();
    let summary = match state.privileged().firewall(apply, protect).await {
        Ok(report) => cron::render_summary(&report.write, &report.summary),
        Err(err) => format!("error: {err:#}"),
    };
    state
        .with_db(move |db| {
            cron::record_run(db, CronJob::RenderFirewall, &summary);
            Ok(())
        })
        .await
}

/// Probes the host, then records what it found.
///
/// The probe shells out to `nft`, `systemctl` and `df`, and `nft list`
/// needs root: it is the console's privileged operation, in this process
/// or in the root helper, and off the database lock either way.
async fn health_check(state: &AppState) -> anyhow::Result<()> {
    let probe = state.privileged().probe().await?;

    state
        .with_db(move |db| {
            crate::health::store_probe(db, &probe)?;
            let summary = crate::health::assess(db, &probe)?.headline();
            cron::record_run(db, CronJob::HealthCheck, &summary);
            anyhow::Ok(())
        })
        .await?;
    Ok(())
}

/// Fetches the three crawler sources, then stores whatever arrived.
///
/// The fetch holds no database handle at all — it is three round-trips to
/// remote hosts, and the lock has no business being held across them.
///
/// Not while another download holds the lease (see
/// [`crate::refresh::Lease`]): the job stays due and the next tick asks
/// again, which costs one row read.
async fn update_ip_ranges(state: &AppState) -> anyhow::Result<()> {
    let claim = state.with_db(|db| crate::refresh::claim(db, now())).await?;
    let crate::refresh::Claim::Granted(lease) = claim else {
        return Ok(());
    };
    let results = cron::fetch_ip_ranges().await;
    state
        .with_db(move |db| {
            let stored = cron::store_ip_ranges(db, results);
            crate::refresh::release(db, &lease)?;
            stored
        })
        .await?;
    Ok(())
}

/// What one "update everything" came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRun {
    /// It ran: the line to show, and whether every source worked.
    Done { summary: String, all_ok: bool },
    /// Another download held the lease, last renewed at `since`.
    Busy { since: i64 },
}

/// Downloads every list this host uses, one source at a time, for the
/// console's button and for its weekly job: fetched off the database lock,
/// stored on it, holding the download lease throughout and renewing it
/// after each source. `by` goes into the crawler job's summary.
///
/// One source failing is reported and the rest still run: these are
/// eight third parties, and a transient failure at one of them is not a
/// reason to leave the other seven stale.
pub async fn update_everything(state: &AppState, by: &'static str) -> anyhow::Result<UpdateRun> {
    let claimed = state
        .with_db(|db| {
            Ok(match crate::refresh::claim(db, now())? {
                crate::refresh::Claim::Granted(lease) => Ok((lease, crate::refresh::plan(db))),
                crate::refresh::Claim::Busy { since } => Err(since),
            })
        })
        .await?;
    let (lease, plan) = match claimed {
        Ok(claimed) => claimed,
        Err(since) => return Ok(UpdateRun::Busy { since }),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(err) => {
            let lease = lease.clone();
            state
                .with_db(move |db| crate::refresh::release(db, &lease))
                .await?;
            return Err(err.context("could not work out what to update"));
        }
    };

    let mut outcomes = Vec::new();
    for source in plan {
        // Fetch off the database lock, store on it — `Db` is not `Sync`,
        // so nothing holding it can cross an `.await`.
        let fetched = crate::refresh::fetch(&source).await;
        let for_store = source.clone();
        let lease = lease.clone();
        let outcome = state
            .with_db(move |db| {
                let stored = fetched.and_then(|raw| crate::refresh::store(db, &for_store, &raw));
                crate::refresh::renew(db, &lease, now())?;
                Ok(stored.map_err(|err| format!("{err:#}")))
            })
            .await?;
        outcomes.push((source, outcome));
    }

    let all_ok = outcomes.iter().all(|(_, outcome)| outcome.is_ok());
    let summary = state
        .with_db(move |db| {
            let summary = crate::refresh::record(db, &outcomes, by);
            crate::refresh::release(db, &lease)?;
            Ok(summary)
        })
        .await?;
    Ok(UpdateRun::Done { summary, all_ok })
}

/// What downloading one list came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OneRun {
    /// It ran: what landed, or why nothing did.
    Done(Result<String, String>),
    /// Another download held the lease, last renewed at `since`.
    Busy { since: i64 },
}

/// Downloads one list and stores it, holding the download lease for the
/// duration: the console's per-source refresh. It records no cron job —
/// one source is not what either scheduled job means by "done".
pub async fn update_one(
    state: &AppState,
    source: crate::refresh::Source,
) -> anyhow::Result<OneRun> {
    let claim = state.with_db(|db| crate::refresh::claim(db, now())).await?;
    let lease = match claim {
        crate::refresh::Claim::Granted(lease) => lease,
        crate::refresh::Claim::Busy { since } => return Ok(OneRun::Busy { since }),
    };
    let fetched = crate::refresh::fetch(&source).await;
    let outcome = state
        .with_db(move |db| {
            let stored = fetched.and_then(|raw| crate::refresh::store(db, &source, &raw));
            crate::refresh::release(db, &lease)?;
            Ok(stored.map_err(|err| format!("{err:#}")))
        })
        .await?;
    Ok(OneRun::Done(outcome))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use std::path::PathBuf;

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// A state whose cron can't touch anything real: the firewall script
    /// goes to a temp directory rather than `/etc`, and the SSH log is a
    /// fixture rather than whatever `journalctl` on the machine running
    /// the tests would say.
    fn state_in(dir: &std::path::Path) -> AppState {
        let ssh_log = dir.join("auth.log");
        std::fs::write(&ssh_log, "").unwrap();
        let db = Db::open_in_memory().unwrap();
        // Marked just-run so no test ever makes the three outbound
        // crawler-range fetches, or runs the health probe — which asks the
        // *host* (`systemctl`, `nft`, `docker ps`) and so made every tick
        // test read this machine's services and Docker socket.
        for job in [
            CronJob::UpdateIpRanges,
            CronJob::UpdateEverything,
            CronJob::HealthCheck,
        ] {
            db.set_cron_last_run(job.id(), now_secs(), "skipped for test")
                .unwrap();
        }
        let mut state = AppState::new(db, PathBuf::from("/nonexistent"), Some(ssh_log), false);
        state.firewall_out = Some(dir.join("fw.nft"));
        state
    }

    /// The console's button, its weekly job, its crawler job and a single
    /// source's refresh all wait
    /// for a download someone else holds — another process, or this one —
    /// rather than fetching the same feeds beside it. Nothing is fetched
    /// and nothing is recorded, so the jobs stay due for the next tick.
    #[tokio::test]
    async fn every_download_waits_while_another_holds_the_lease() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());
        state
            .with_db(|db| crate::refresh::claim(db, now()))
            .await
            .unwrap();

        let run = update_everything(&state, "by the schedule").await.unwrap();
        assert!(matches!(run, UpdateRun::Busy { .. }), "{run:?}");

        update_ip_ranges(&state).await.unwrap();
        let one = crate::refresh::Source::CrawlerRanges(crate::ipranges::IpRangeSourceKind::GptBot);
        let run = update_one(&state, one).await.unwrap();
        assert!(matches!(run, OneRun::Busy { .. }), "{run:?}");
        for job in [CronJob::UpdateIpRanges, CronJob::UpdateEverything] {
            let summary = state
                .with_db(move |db| db.get_cron_last_summary(job.id()))
                .await
                .unwrap();
            assert_eq!(summary.as_deref(), Some("skipped for test"), "{}", job.id());
        }
    }

    #[tokio::test]
    async fn a_tick_runs_every_due_job_and_records_what_it_did() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());

        let ran = tick(&state).await;

        assert!(ran > 0, "a fresh database has every job due");
        for job in CronJob::all() {
            let last_run = state
                .with_db(move |db| db.get_cron_last_run(job.id()))
                .await
                .unwrap();
            assert!(last_run.is_some(), "{} never recorded a run", job.id());
        }
    }

    /// `VACUUM` cannot run inside a transaction, and `maintenance` runs
    /// inside `with_db` — so the question this pins is structural: does
    /// that wrapper leave the connection in autocommit? It does (a mutex
    /// and `spawn_blocking`, no `BEGIN`), and nothing else in the suite
    /// would notice if that changed, because every other web test uses an
    /// in-memory database whose freelist never reaches the threshold
    /// `cron::maintenance` compacts at. A failure here would otherwise
    /// only show up in production, as an `eprintln!` from `run_due_jobs`
    /// once a day.
    #[tokio::test]
    async fn the_database_can_be_compacted_from_inside_the_web_lock() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(
            Db::open(dir.path().join("web.sqlite3")).unwrap(),
            PathBuf::from("/nonexistent"),
            None,
            false,
        );

        let reclaimed = state.with_db(|db| db.vacuum()).await;

        assert!(
            reclaimed.is_ok(),
            "vacuum failed inside with_db: {:?}",
            reclaimed.unwrap_err()
        );
    }

    /// With the switch off — every install, until someone says otherwise
    /// — a tick leaves the config alone.
    ///
    /// Only the off path is tested here. The on path writes through
    /// `apply_all_sites`, which needs `STOP_BOTS_NGINX_DIR` pointed
    /// somewhere safe, and setting that anywhere in this binary breaks
    /// `nginx::tests::kitchen_sink_block_matches_the_golden` — see the note
    /// on `cron::tests::apply_nginx_is_a_scheduled_job`. It lives in
    /// `tests/cli.rs` instead.
    #[tokio::test]
    async fn a_tick_leaves_site_configs_alone_when_auto_apply_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nginx");
        std::fs::create_dir_all(&root).unwrap();
        let config = root.join("example.com.conf");
        let original = "server {\n    listen 80;\n    server_name example.com;\n}\n";
        std::fs::write(&config, original).unwrap();

        let mut state = state_in(dir.path());
        state.nginx_root = root;
        state
            .with_db(|db| {
                crate::testing::blocked_bot(db, "badbot", "BadBot");
                Ok(())
            })
            .await
            .unwrap();

        tick(&state).await;

        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            original,
            "a config was rewritten with the switch off"
        );
    }

    /// The point of sharing `Db::set_cron_last_run` with the TUI and with
    /// `stop-bots batch`: once a job has run, it stops being due, so a
    /// second front-end ticking a moment later does nothing rather than
    /// repeating the work.
    #[tokio::test]
    async fn a_second_tick_straight_afterwards_runs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());

        tick(&state).await;
        let ran_again = tick(&state).await;

        assert_eq!(ran_again, 0, "jobs ran twice in the same minute");
    }

    /// The `RenderFirewall` job must write where the state says, not to
    /// `firewall::DEFAULT_OUTPUT_PATH` — otherwise running the tests, or a
    /// server started by hand, writes to `/etc`.
    #[tokio::test]
    async fn the_firewall_job_writes_where_the_state_points_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());

        tick(&state).await;

        // Beside it, rather: the cron renders and does not apply, so it
        // writes the script nothing loads, not the one the boot unit does.
        let rendered = crate::firewall::rendered_path(state.firewall_out.as_ref().unwrap());
        assert!(rendered.exists(), "no script at {}", rendered.display());
        let summary = state
            .with_db(|db| db.get_cron_last_summary(CronJob::RenderFirewall.id()))
            .await
            .unwrap();
        assert!(
            summary.as_deref().unwrap_or_default().contains("wrote"),
            "summary was: {summary:?}"
        );
    }
}
