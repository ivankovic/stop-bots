//! Event handling for the TUI application.
//!
//! This module provides an async event-driven architecture using tokio and mpsc channels,
//! following the ratatui event-driven-async template pattern.

use anyhow::Result;
use crossterm::event::Event as CrosstermEvent;
use futures::{FutureExt, StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::db::{Bot, DataSource};

/// The frequency at which tick events are emitted.
const TICK_FPS: f64 = 30.0;

/// Representation of all possible events.
#[derive(Clone, Debug)]
pub enum Event {
    /// An event that is emitted on a regular schedule.
    ///
    /// Use this event to run any code which has to run outside of being a direct response to a user
    /// event. e.g. polling external systems, updating animations, or rendering the UI based on a
    /// fixed frame rate.
    Tick,
    /// Crossterm events.
    ///
    /// These events are emitted by the terminal.
    Crossterm(CrosstermEvent),
    /// Application events.
    ///
    /// Use this event to emit custom events that are specific to your application.
    App(AppEvent),
}

/// Application events.
///
/// You can extend this enum with your own custom events.
#[derive(Clone, Debug)]
pub enum AppEvent {
    /// Quit the application.
    Quit,
    /// Toggle theme.
    ToggleTheme,
    /// Refresh current screen.
    Refresh,
    /// Navigate up.
    Up,
    /// Navigate down.
    Down,
    /// Navigate left.
    Left,
    /// Navigate right.
    Right,
    /// Select current item.
    Select,
    /// Go back.
    Back,
    /// Open settings/bot config screen.
    OpenSettings,
    /// Open bot list screen.
    OpenBotList,
    /// Open firewall screen.
    OpenFirewall,
    /// Open dashboard screen.
    OpenDashboard,
    /// Open help screen.
    Help,
    /// Confirm action (Yes).
    Confirm,
    /// Cancel action (No).
    Cancel,
    /// Toggle category status.
    ToggleCategory,
    /// Add firewall rule.
    AddFirewallRule,
    /// Remove firewall rule.
    RemoveFirewallRule,
    /// Sync firewall with database.
    SyncFirewall,
    /// Open sources screen.
    OpenSources,
    /// Refresh all data sources from network.
    RefreshAllSources,
    /// Discover NGINX sites.
    DiscoverSites,
    /// Sites discovery completed.
    SitesDiscovered { count: usize },
    /// Sources refresh completed with results.
    SourcesRefreshed {
        sources: Vec<DataSource>,
        messages: Vec<String>,
    },
    /// Bot data fetched from a source.
    BotDataFetched { source_id: String, bots: Vec<Bot> },
    /// Context menu.
    ContextMenu,
}

/// Terminal event handler.
#[derive(Debug)]
pub struct EventHandler {
    /// Event sender channel.
    pub sender: mpsc::UnboundedSender<Event>,
    /// Event receiver channel.
    receiver: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    /// Constructs a new instance of [`EventHandler`] and spawns a new thread to handle events.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let actor = EventTask::new(sender.clone());
        tokio::spawn(async { actor.run().await });
        Self { sender, receiver }
    }

    /// Receives an event from the sender.
    ///
    /// This function blocks until an event is received.
    ///
    /// # Errors
    ///
    /// This function returns an error if the sender channel is disconnected. This can happen if an
    /// error occurs in the event thread. In practice, this should not happen unless there is a
    /// problem with the underlying terminal.
    pub async fn next(&mut self) -> Result<Event> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Failed to receive event"))
    }

    /// Queue an app event to be sent to the event receiver.
    ///
    /// This is useful for sending events to the event handler which will be processed by the next
    /// iteration of the application's event loop.
    pub fn send(&mut self, app_event: AppEvent) {
        // Ignore the result as the receiver cannot be dropped while this struct still has a
        // reference to it
        let _ = self.sender.send(Event::App(app_event));
    }
}

/// A thread that handles reading crossterm events and emitting tick events on a regular schedule.
struct EventTask {
    /// Event sender channel.
    sender: mpsc::UnboundedSender<Event>,
}

impl EventTask {
    /// Constructs a new instance of [`EventTask`].
    fn new(sender: mpsc::UnboundedSender<Event>) -> Self {
        Self { sender }
    }

    /// Runs the event thread.
    ///
    /// This function emits tick events at a fixed rate and polls for crossterm events in between.
    async fn run(self) -> Result<()> {
        let tick_rate = Duration::from_secs_f64(1.0 / TICK_FPS);
        let mut reader = crossterm::event::EventStream::new();
        let mut tick = tokio::time::interval(tick_rate);
        loop {
            let tick_delay = tick.tick();
            let crossterm_event = reader.next().fuse();
            tokio::select! {
              _ = self.sender.closed() => {
                break;
              }
              _ = tick_delay => {
                self.send(Event::Tick);
              }
              Some(Ok(evt)) = crossterm_event => {
                self.send(Event::Crossterm(evt));
              }
            };
        }
        Ok(())
    }

    /// Sends an event to the receiver.
    fn send(&self, event: Event) {
        // Ignores the result because shutting down the app drops the receiver, which causes the send
        // operation to fail. This is expected behavior and should not panic.
        let _ = self.sender.send(event);
    }
}

/// Converts a crossterm key event to an AppEvent.
pub fn key_event_to_app_event(key_event: crossterm::event::KeyEvent) -> Option<AppEvent> {
    use crossterm::event::KeyCode;

    // Only handle key press events, not releases
    if key_event.kind != crossterm::event::KeyEventKind::Press {
        return None;
    }

    match key_event.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc
            if key_event.modifiers.is_empty() =>
        {
            Some(AppEvent::Quit)
        }
        // Theme toggle
        KeyCode::Char('c') | KeyCode::Char('C') => Some(AppEvent::ToggleTheme),
        // Refresh
        KeyCode::Char('r') | KeyCode::Char('R') => Some(AppEvent::RefreshAllSources),
        // Scan for NGINX sites
        KeyCode::Char('S') => Some(AppEvent::DiscoverSites),
        // Navigation
        KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => Some(AppEvent::Up),
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => Some(AppEvent::Down),
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => Some(AppEvent::Left),
        KeyCode::Right => Some(AppEvent::Right),
        // Select
        KeyCode::Enter | KeyCode::Char(' ') => Some(AppEvent::Select),
        // Back
        KeyCode::Backspace => Some(AppEvent::Back),
        // Open settings/bot config screen
        KeyCode::Char('b') | KeyCode::Char('B') => Some(AppEvent::OpenSettings),
        // Open bot list
        KeyCode::Char('l') | KeyCode::Char('L') => Some(AppEvent::OpenBotList),
        // Open firewall screen
        KeyCode::Char('f') | KeyCode::Char('F') => Some(AppEvent::OpenFirewall),
        // Open dashboard
        KeyCode::Char('d') | KeyCode::Char('D') => Some(AppEvent::OpenDashboard),
        // Open sources screen
        KeyCode::Char('s') => Some(AppEvent::OpenSources),
        // Confirm (Yes)
        KeyCode::Char('y') | KeyCode::Char('Y') => Some(AppEvent::Confirm),
        // Cancel (No)
        KeyCode::Char('n') | KeyCode::Char('N') => Some(AppEvent::Cancel),
        // Help
        KeyCode::Char('?') => Some(AppEvent::Help),
        // Toggle category
        KeyCode::Char('t') | KeyCode::Char('T') => Some(AppEvent::ToggleCategory),
        // Context menu
        KeyCode::Char('m') | KeyCode::Char('M') => Some(AppEvent::ContextMenu),
        // Firewall add rule
        KeyCode::Char('+') => Some(AppEvent::AddFirewallRule),
        // Firewall remove rule
        KeyCode::Char('-') => Some(AppEvent::RemoveFirewallRule),
        // Firewall sync
        KeyCode::Char('*') => Some(AppEvent::SyncFirewall),
        _ => None,
    }
}
