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

//! Terminal event plumbing, following the Ratatui event-driven-async
//! template (<https://github.com/ratatui/templates/tree/main/event-driven-async>).

use crate::db::NewBot;
use anyhow::{Context, Result};
use crossterm::event::Event as CrosstermEvent;
use futures::{FutureExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;

/// The frequency at which tick events are emitted.
const TICK_FPS: f64 = 30.0;

/// Representation of all possible events.
#[derive(Clone, Debug)]
pub enum Event {
    /// An event emitted on a regular schedule, for logic that isn't a direct
    /// response to user input.
    Tick,
    /// Raw terminal events (key presses, resizes, ...).
    Crossterm(CrosstermEvent),
    /// Application-specific events.
    App(AppEvent),
}

/// Application events, queued by [`App`](crate::app::App) and processed on
/// the next iteration of the event loop.
#[derive(Clone, Debug)]
pub enum AppEvent {
    /// Quit the application.
    Quit,
    /// A background bot-list source fetch (started from the Bot settings
    /// screen) has finished. Carries the source's stable id (so `App` can
    /// look up which `botlist::SourceKind` to store the result under, and
    /// derive its display name for the status message) and either the
    /// parsed bots or a stringified error — `anyhow::Error` isn't `Clone`,
    /// which `Event` needs to be.
    SourceUpdateFinished {
        source_id: String,
        result: Result<Vec<NewBot>, String>,
    },
    /// A background fetch of one country's IP ranges (started from the
    /// Dashboard's "add a country" popup, for a country not already
    /// fetched) has finished. Carries the parsed CIDR list — not stored
    /// yet, since `Db` isn't `Sync`: storing, and adding the country to the
    /// geo selection, happens back on the main thread in
    /// `App::finish_country_select`.
    CountrySelectFinished {
        country_code: String,
        result: Result<Vec<String>, String>,
    },
    /// The internal cron's background fetch for the `UpdateIpRanges` job
    /// (see `crate::cron`) has finished. Carries each of the three crawler
    /// sources' fetch outcome (parsed CIDRs, or a stringified error) so
    /// `App` can store whatever succeeded and summarize the rest — one
    /// source failing (e.g. a transient network error) shouldn't discard
    /// what the other two got.
    CronIpRangesFetched {
        results: Vec<(
            crate::ipranges::IpRangeSourceKind,
            Result<Vec<String>, String>,
        )>,
    },
    /// A cron job's log source has been resolved on a background thread
    /// (see `App::start_cron_log_job`). Only the *reading* of the SSH/access
    /// log (and, for the SSH log, the `journalctl` fallback subprocess) is
    /// blocking enough to move off the main thread — that's what this event
    /// carries back. The actual parsing/counting/Db writes for the job stay
    /// on the main thread in `App::finish_cron_log_job`, same as every other
    /// `Db` access in this app (`Db` isn't `Sync`). `None` means the log
    /// source was unavailable.
    CronLogFetched {
        job: crate::cron::CronJob,
        log_text: Option<String>,
    },
}

/// Terminal event handler: spawns a background task that emits tick events
/// on a fixed schedule and forwards crossterm events as they arrive.
#[derive(Debug)]
pub struct EventHandler {
    sender: mpsc::UnboundedSender<Event>,
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let actor = EventTask::new(sender.clone());
        tokio::spawn(async { actor.run().await });
        Self { sender, receiver }
    }

    /// Receives the next event. Blocks until one is available.
    pub async fn next(&mut self) -> Result<Event> {
        self.receiver
            .recv()
            .await
            .context("event channel closed unexpectedly")
    }

    /// Queues an app event to be processed on the next loop iteration.
    pub fn send(&self, app_event: AppEvent) {
        // Ignored: the receiver can't be dropped while this handle is alive.
        let _ = self.sender.send(Event::App(app_event));
    }

    /// Clones the sender half, for background tasks (e.g. a bot-list fetch)
    /// that need to report a result back into the event loop.
    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self.sender.clone()
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Background task that emits [`Event::Tick`] on a fixed schedule and
/// [`Event::Crossterm`] as terminal events arrive.
struct EventTask {
    sender: mpsc::UnboundedSender<Event>,
}

impl EventTask {
    fn new(sender: mpsc::UnboundedSender<Event>) -> Self {
        Self { sender }
    }

    async fn run(self) {
        let tick_rate = Duration::from_secs_f64(1.0 / TICK_FPS);
        let mut reader = crossterm::event::EventStream::new();
        let mut tick = tokio::time::interval(tick_rate);
        loop {
            let tick_delay = tick.tick();
            let crossterm_event = reader.next().fuse();
            tokio::select! {
                _ = self.sender.closed() => break,
                _ = tick_delay => self.send(Event::Tick),
                Some(Ok(evt)) = crossterm_event => self.send(Event::Crossterm(evt)),
            }
        }
    }

    fn send(&self, event: Event) {
        // Ignored: shutting down the app drops the receiver, which is
        // expected and not an error.
        let _ = self.sender.send(event);
    }
}
