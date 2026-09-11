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

//! Everything a handler is allowed to reach, and the one door to the
//! database.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::db::Db;
use crate::web::auth::{LoginThrottle, Sessions};

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// The database, behind a `std::sync::Mutex` rather than a
    /// `tokio::sync::Mutex` on purpose. A tokio mutex exists to be held
    /// across `.await`, which is exactly what must never happen here —
    /// `rusqlite` blocks the thread it runs on, so a guard held across a
    /// suspension point would stall the runtime. Using the std mutex makes
    /// that a compile error at the point someone tries, because its guard
    /// is not `Send`.
    db: Arc<Mutex<Db>>,
    /// The NGINX config root to scan, as given on the command line.
    pub nginx_root: PathBuf,
    /// The SSH log to read, if one was specified.
    pub ssh_log: Option<PathBuf>,
    /// Live sessions.
    pub sessions: Arc<Sessions>,
    /// Failed-login throttling. Shared across requests, so it has to
    /// outlive any one of them.
    pub login_throttle: Arc<LoginThrottle>,
    /// The path prefix this console is served under. Read once at
    /// startup: it is part of how the server is deployed, not something a
    /// request can change.
    pub base: crate::web::BasePath,
    /// Whether writes may actually touch the system, or only the database.
    /// Mirrors the TUI's `--no-reload`, and the integration tests run with
    /// it off so that a test never reloads the developer's NGINX.
    pub apply_for_real: bool,
    /// Where the internal cron's `RenderFirewall` job writes its script.
    ///
    /// A field rather than [`crate::firewall::DEFAULT_OUTPUT_PATH`] read at
    /// the point of use, for the same reason the TUI passes it as a
    /// parameter: the default is a real path under `/etc`, and a test that
    /// drives a tick must be able to point it at a temp directory instead
    /// of writing to the developer's system.
    pub firewall_out: PathBuf,
}

impl AppState {
    pub fn new(
        db: Db,
        nginx_root: PathBuf,
        ssh_log: Option<PathBuf>,
        apply_for_real: bool,
    ) -> Self {
        Self::with_base(
            db,
            nginx_root,
            ssh_log,
            apply_for_real,
            crate::web::BasePath::default(),
        )
    }

    /// The same, served under a path prefix.
    pub fn with_base(
        db: Db,
        nginx_root: PathBuf,
        ssh_log: Option<PathBuf>,
        apply_for_real: bool,
        base: crate::web::BasePath,
    ) -> Self {
        Self {
            db: Arc::new(Mutex::new(db)),
            nginx_root,
            ssh_log,
            sessions: Arc::new(Sessions::default()),
            login_throttle: Arc::new(LoginThrottle::default()),
            base,
            apply_for_real,
            firewall_out: PathBuf::from(crate::firewall::DEFAULT_OUTPUT_PATH),
        }
    }

    /// Runs `f` against the database on a blocking thread.
    ///
    /// **The only way to reach a `Db` in this module**, and the reason the
    /// rule in the module docs is structural rather than a convention
    /// someone has to remember. `spawn_blocking` moves the work off the
    /// async runtime, so a slow query stalls one blocking thread instead of
    /// the executor; the guard is taken and dropped entirely inside the
    /// closure, so it cannot cross an `.await` even by accident.
    ///
    /// A panic inside `f` poisons the mutex, and this treats that as fatal
    /// for the request rather than papering over it: the database is in
    /// whatever state the panic left it, and the honest thing is an error.
    pub async fn with_db<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Db) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = Arc::clone(&self.db);
        tokio::task::spawn_blocking(move || {
            let guard = db.lock().map_err(|_| {
                anyhow::anyhow!("the database lock was poisoned by an earlier panic")
            })?;
            f(&guard)
        })
        .await
        .map_err(|e| anyhow::anyhow!("the database task failed to run: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::new(
            Db::open_in_memory().unwrap(),
            PathBuf::from("/nonexistent"),
            None,
            false,
        )
    }

    #[tokio::test]
    async fn with_db_reads_and_writes_the_same_database() {
        let state = state();

        state
            .with_db(|db| db.set_text_setting("a-key", "a-value"))
            .await
            .unwrap();
        let read = state
            .with_db(|db| db.get_text_setting("a-key"))
            .await
            .unwrap();

        assert_eq!(read.as_deref(), Some("a-value"));
    }

    #[tokio::test]
    async fn with_db_propagates_the_closure_s_error() {
        let state = state();
        let err = state
            .with_db(|_| -> Result<()> { anyhow::bail!("the closure said no") })
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("the closure said no"),
            "was: {err}"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_serialise_rather_than_race() {
        // Not a timing test: the claim is that N concurrent writers all
        // land, which is what the mutex is for. A lost update would show
        // up as a missing row.
        let state = state();
        let mut handles = Vec::new();
        for i in 0..16 {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                state
                    .with_db(move |db| db.set_text_setting(&format!("key-{i}"), "set"))
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        for i in 0..16 {
            let value = state
                .with_db(move |db| db.get_text_setting(&format!("key-{i}")))
                .await
                .unwrap();
            assert_eq!(value.as_deref(), Some("set"), "key-{i} was lost");
        }
    }

    #[tokio::test]
    async fn a_panicking_closure_does_not_take_the_server_down() {
        let state = state();

        let panicked = state
            .with_db(|_| -> Result<()> { panic!("a handler bug") })
            .await;
        assert!(panicked.is_err(), "a panic must surface as a request error");

        // The mutex is poisoned now, and later requests must say so
        // clearly rather than deadlock or pretend the write happened.
        let after = state.with_db(|db| db.get_text_setting("anything")).await;
        assert!(
            after.unwrap_err().to_string().contains("poisoned"),
            "a poisoned lock must be reported, not hidden"
        );
    }
}
