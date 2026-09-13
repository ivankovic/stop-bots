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
//! signature can't express: **read the log outside the lock.** Resolving
//! the SSH log can shell out to `journalctl`, which is slow, and doing it
//! inside `with_db` would hold the database against every in-flight
//! request for the duration. [`crate::cron::read_log_for`] takes no `Db`
//! precisely so that this stays possible.

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
    for job in due {
        let result = match job {
            CronJob::UpdateIpRanges => update_ip_ranges(state).await,
            CronJob::Detect(_) | CronJob::RecordAccessStats | CronJob::RenderFirewall => {
                run_log_job(state, job).await
            }
        };
        match result {
            Ok(()) => ran += 1,
            Err(err) => eprintln!("stop-bots: cron job {} failed: {err:#}", job.id()),
        }
    }
    ran
}

/// Reads the log this job needs off the async runtime and outside the
/// database lock, then runs the job.
async fn run_log_job(state: &AppState, job: CronJob) -> anyhow::Result<()> {
    let ssh_log = state.ssh_log.clone();
    let log_text = tokio::task::spawn_blocking(move || cron::read_log_for(job, ssh_log.as_deref()))
        .await
        .map_err(|err| anyhow::anyhow!("the log-reading thread panicked: {err}"))?;

    let out = state.firewall_out.clone();
    state
        .with_db(move |db| cron::run_log_job(db, job, log_text.as_deref(), out.as_deref()))
        .await?;
    Ok(())
}

/// Fetches the three crawler sources, then stores whatever arrived.
///
/// The fetch holds no database handle at all — it is three round-trips to
/// remote hosts, and the lock has no business being held across them.
async fn update_ip_ranges(state: &AppState) -> anyhow::Result<()> {
    let results = cron::fetch_ip_ranges().await;
    state
        .with_db(move |db| cron::store_ip_ranges(db, results))
        .await?;
    Ok(())
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
        // crawler-range fetches. Every other job is local.
        db.set_cron_last_run(CronJob::UpdateIpRanges.id(), now_secs(), "skipped for test")
            .unwrap();
        let mut state = AppState::new(db, PathBuf::from("/nonexistent"), Some(ssh_log), false);
        state.firewall_out = Some(dir.join("fw.nft"));
        state
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

        assert!(
            state.firewall_out.as_ref().unwrap().exists(),
            "no script at {}",
            state.firewall_out.as_ref().unwrap().display()
        );
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
