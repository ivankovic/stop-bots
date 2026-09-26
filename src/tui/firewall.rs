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

//! The Firewall screen: a live, actionable view of what's
//! currently hitting the server, split into two panels — "Failed SSH
//! logins" and "Top user agents" — each ranked by count with a bar, and
//! tagged `NOT BLOCKED` (dim), `BLOCKED` (red) or `BLOCKLIST` (yellow).
//! `Tab`/`Shift+Tab` switch which panel `Up`/`Down` (or `j`/`k`) move
//! through; `i` opens a detail popup for the selected row — see
//! [`crate::ipdetail`] and [`crate::uadetail`] for what each of the two
//! can honestly say; `y` copies the selected row; `R` re-reads the log; `f` cycles a
//! shared display filter (All / Not blocked only / Blocked only) applied to
//! both panels; `Enter` toggles the selected row's block state — blocks a
//! `NOT BLOCKED` row, unblocks a `BLOCKED` one. All of this is storage-only,
//! same as everywhere else in this codebase: (un)blocking an IP only adds
//! or removes a `firewall_rules` row (`render-firewall`, then applying the
//! script, is what actually enforces it — and its lockout-safety check
//! already guards against self-blocking a currently-connected SSH session,
//! so this screen doesn't duplicate that guard); (un)blocking a user agent
//! only adds or removes a row in `blocked_user_agents` (`apply-blocks`, or
//! the NGINX screen's `a`/`A`, is what injects/removes it in NGINX
//! config).
//!
//! Unlike the Dashboard's `cron_status`/`user_agent_stats` (both read
//! straight from `Db`), the SSH panel is populated by re-parsing the live
//! SSH log, which `App` reads in the background and hands to `refresh`
//! as text — there's no persisted "SSH attempt stats"
//! table, deliberately: this screen is a real-time view of the current
//! log, not a lifetime tally (that's what `sshlog::scanning_ips`/
//! `block-scanners` already handle, on their own cron cadence). The
//! User Agent panel *does* read from `Db::list_user_agent_stats` (the
//! same table `record-access-stats`/`RecordAccessStats` populate) since
//! that's already a cheap, pre-aggregated lifetime count — counting only
//! *successful* (non-4xx/5xx) requests, so a user agent already blocked by
//! an existing bot-category rule (and so 403'd before ever reaching this
//! tally) won't show up here; this panel is about traffic that's *getting
//! through*, not a complete traffic log.
//!
//! Both panels use the same `RowStatus`: `Pending` (no block on file yet,
//! rendered as "NOT BLOCKED") or `Blocked` (`until: Some(t)` for a temporary
//! `firewall_rules` block — e.g. one `block-scanners` already added — `None`
//! for permanent). Only the SSH panel can show a temporary `Blocked`; a
//! manually-blocked user agent is always permanent, since
//! [`crate::db::Db::block_user_agent`] has no TTL concept.
//!
//! `refresh` itself is deliberately thin: all the actual row-building logic lives
//! in [`build_ssh_rows`]/[`build_ua_rows`], pure functions tested directly
//! against synthetic counts below rather than through a real or faked log
//! file.

use crate::db::Db;
// The row model and the "is this already blocked?" decision live in
// `crate::dynamic`, shared with the web UI — see that module for why.
use crate::dynamic::{Filter, Live, RowStatus, SshRow, TrustedEntry, UaRow};
use crate::ipdetail::{AddressKind, IpDetail};
use crate::tui::{centered_rect, KeyOutcome, Theme};
use crate::uadetail::UaDetail;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::Line,
    widgets::{Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

/// Which of the three panels `Up`/`Down`/`Enter` currently apply to.
/// Switched with `Tab`/`Shift+Tab` (see the module doc comment for why
/// that claims the key on this screen instead of cycling top-level
/// screens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Ssh,
    UserAgents,
    /// Everything trusted by hand, with a row to add to it. Its own panel
    /// rather than only a `T` key on the other two, because what an
    /// operator most wants to trust — a monitoring service, an office
    /// range — is exactly what never shows up in a list of failed SSH
    /// logins, and may not have visited yet.
    Trusted,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Focus::Ssh => Focus::UserAgents,
            Focus::UserAgents => Focus::Trusted,
            Focus::Trusted => Focus::Ssh,
        }
    }

    fn previous(self) -> Self {
        match self {
            Focus::Ssh => Focus::Trusted,
            Focus::UserAgents => Focus::Ssh,
            Focus::Trusted => Focus::UserAgents,
        }
    }
}

/// The "trust an address or user agent" text field: what has been typed,
/// and why the last Enter was refused. The same shape as Site detail's
/// add-exempt-path popup.
#[derive(Debug, Default)]
struct TrustInput {
    input: String,
    error: Option<String>,
}

/// Which of the two detail popups is open.
///
/// Two variants rather than one generic detail because the two panels
/// answer different questions — see [`crate::uadetail`] for why an
/// address and a user agent are not the same kind of thing with different
/// text in it. Boxed: an `IpDetail` carrying a few hundred range hits
/// would otherwise set the size of every `Firewall`.
#[derive(Debug)]
enum Detail {
    Address(Box<IpDetail>),
    UserAgent(Box<UaDetail>),
}

#[derive(Debug, Default)]
pub struct Firewall {
    ssh_rows: Vec<SshRow>,
    ua_rows: Vec<UaRow>,
    ssh_state: ListState,
    ua_state: ListState,
    focus: Focus,
    filter: Filter,
    trusted: Vec<TrustedEntry>,
    /// Row 0 is "+ Trust an address or user agent"; row `n` is
    /// `trusted[n - 1]`.
    trusted_state: ListState,
    /// The open trust text field, if any. Owns the keyboard while open.
    trust_input: Option<TrustInput>,
    /// The open detail popup, if any. `Some` also means `Esc`
    /// closes the popup rather than leaving the screen, the same
    /// nested-back-out shape `site_detail` uses one level deeper.
    detail: Option<Detail>,
}

impl Firewall {
    /// Reloads both panels. See the module doc comment for why the actual
    /// row-building logic lives in [`build_ssh_rows`]/[`build_ua_rows`]
    /// instead of here.
    ///
    /// `ssh_log_text` is the log itself, already read — this screen used to
    /// resolve and read it here, which meant a `journalctl` subprocess on
    /// every reload on any host without a readable `auth.log`. `App` owns
    /// that read now and does it in the background (`App::read_ssh_log`);
    /// `None` means it hasn't arrived yet, and renders as an empty SSH
    /// panel rather than as a wait.
    pub fn refresh(&mut self, db: &Db, ssh_log_text: Option<&str>) -> Result<()> {
        let live = Live::load(db, ssh_log_text)?;
        self.ssh_rows = live.ssh;
        self.ua_rows = live.user_agents;
        self.trusted = crate::dynamic::trusted_entries(db)?;
        self.clamp_selections();
        Ok(())
    }

    /// Every SSH row currently passing [`Self::filter`], in display order —
    /// shared by rendering and by resolving which row `ssh_state`'s
    /// selected index actually points at, so the two can never disagree
    /// about what's on screen.
    fn visible_ssh_rows(&self) -> Vec<&SshRow> {
        self.ssh_rows
            .iter()
            .filter(|row| self.filter.matches(row.status))
            .collect()
    }

    /// The User Agent panel's equivalent of [`Self::visible_ssh_rows`].
    fn visible_ua_rows(&self) -> Vec<&UaRow> {
        self.ua_rows
            .iter()
            .filter(|row| self.filter.matches(row.status))
            .collect()
    }

    /// Re-clamps both panels' selections against their *filtered* (visible)
    /// lengths, not the full underlying row count — called after a reload
    /// and after the filter itself changes, since either can shrink or grow
    /// what's actually on screen out from under an existing selection.
    fn clamp_selections(&mut self) {
        let ssh_len = self.visible_ssh_rows().len();
        clamp_selection(&mut self.ssh_state, ssh_len);
        let ua_len = self.visible_ua_rows().len();
        clamp_selection(&mut self.ua_state, ua_len);
        // The add row is always there, so this list is never empty.
        clamp_selection(&mut self.trusted_state, self.trusted.len() + 1);
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        // The popup owns the keyboard while it is open. It is a read-only
        // view, so only "close" is meaningful — but it must claim `Esc`,
        // or the screen would back out to the Dashboard with a detail
        // still on screen.
        if self.detail.is_some() {
            return Ok(match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('i') | KeyCode::Enter => {
                    self.detail = None;
                    KeyOutcome::Consumed
                }
                _ => KeyOutcome::Consumed,
            });
        }
        // Text entry owns every printable key, so a `j` or an `f` typed
        // into a user agent reaches the field instead of the screen.
        if self.trust_input.is_some() {
            return self.handle_trust_input_key(key, db, message);
        }

        match key.code {
            KeyCode::Tab => {
                self.focus = self.focus.next();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::BackTab => {
                self.focus = self.focus.previous();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.clamp_selections();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.active_state().select_previous();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.active_state().select_next();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter if self.focus == Focus::Trusted => {
                self.activate_trusted_row(db, message)
            }
            KeyCode::Enter => self.toggle_block_selected(db, message),
            KeyCode::Char('T') => self.toggle_trust_selected(db, message),
            KeyCode::Char('i') => self.inspect_selected(db, message),
            KeyCode::Char('y') => Ok(self.copy_selected(message)),
            KeyCode::Char('R') => Ok(KeyOutcome::RereadLogs),
            _ => Ok(KeyOutcome::Ignored),
        }
    }

    /// `y`: the selected address or user agent to the clipboard, because
    /// the next thing anyone does with an address is paste it somewhere.
    /// Via OSC 52, which reaches the local clipboard through SSH and
    /// tmux; a terminal that does not honour it ignores the sequence.
    fn copy_selected(&self, message: &mut Option<String>) -> KeyOutcome {
        let value = match self.focus {
            Focus::Ssh => self.ssh_state.selected().and_then(|i| {
                self.visible_ssh_rows()
                    .get(i)
                    .map(|row| row.address.clone())
            }),
            Focus::UserAgents => self.ua_state.selected().and_then(|i| {
                self.visible_ua_rows()
                    .get(i)
                    .map(|row| row.user_agent.clone())
            }),
            Focus::Trusted => self
                .selected_trusted()
                .map(|entry| entry.value().to_string()),
        };
        let Some(value) = value else {
            return KeyOutcome::Consumed;
        };
        crate::tui::copy_to_clipboard(&value);
        *message = Some(format!("Copied \"{value}\" to the clipboard"));
        KeyOutcome::Consumed
    }

    /// The footer's key hints for the focused panel.
    pub fn hints(&self) -> crate::tui::Hints {
        if self.detail.is_some() {
            return ("Inspect", vec![("Esc", "close")]);
        }
        if self.trust_input.is_some() {
            return ("Trust", vec![("Enter", "trust"), ("Esc", "cancel")]);
        }
        let name = match self.focus {
            Focus::Ssh => "SSH",
            Focus::UserAgents => "User agents",
            Focus::Trusted => {
                return (
                    "Trusted",
                    vec![
                        ("\u{2191}\u{2193}", "move"),
                        ("Enter", "add/remove"),
                        ("y", "copy"),
                        ("Tab", "next panel"),
                    ],
                );
            }
        };
        // Both panels inspect now, so the hint is unconditional rather
        // than something the SSH panel alone advertises.
        let mut hints = vec![
            ("\u{2191}\u{2193}", "move"),
            ("Enter", "block/unblock"),
            ("T", "trust"),
            ("i", "inspect"),
        ];
        hints.extend([
            ("y", "copy"),
            ("f", "filter"),
            ("Tab", "next panel"),
            ("R", "re-read"),
        ]);
        (name, hints)
    }

    fn active_state(&mut self) -> &mut ListState {
        match self.focus {
            Focus::Ssh => &mut self.ssh_state,
            Focus::UserAgents => &mut self.ua_state,
            Focus::Trusted => &mut self.trusted_state,
        }
    }

    /// The trusted entry under the cursor, `None` on the add row.
    fn selected_trusted(&self) -> Option<&TrustedEntry> {
        self.trusted_state
            .selected()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| self.trusted.get(i))
    }

    /// Enter on the Trusted panel: the add row opens the text field, any
    /// other row stops trusting it. No confirmation, for the reason the
    /// Dashboard's country list has none — it is one reversible change,
    /// and the message says how to put it back.
    fn activate_trusted_row(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(entry) = self.selected_trusted().cloned() else {
            self.trust_input = Some(TrustInput::default());
            return Ok(KeyOutcome::Consumed);
        };
        crate::dynamic::untrust(db, &entry)?;
        *message = Some(format!(
            "No longer trusting {} {} — {}",
            entry.kind(),
            entry.value(),
            apply_hint(&entry)
        ));
        Ok(KeyOutcome::Mutated)
    }

    fn handle_trust_input_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(TrustInput { input, error }) = &mut self.trust_input else {
            unreachable!("dispatched on this popup")
        };
        match key.code {
            KeyCode::Esc => self.trust_input = None,
            KeyCode::Backspace => {
                input.pop();
                *error = None;
            }
            KeyCode::Char(c) => {
                input.push(c);
                *error = None;
            }
            KeyCode::Enter => match crate::dynamic::trust_typed(db, input) {
                Ok(entry) => {
                    self.trust_input = None;
                    *message = Some(format!(
                        "Trusting {} {} — {}",
                        entry.kind(),
                        entry.value(),
                        apply_hint(&entry)
                    ));
                    return Ok(KeyOutcome::Mutated);
                }
                // Left open with the reason, rather than closed with a
                // message: the operator is mid-typing, and the value is
                // what they need to fix.
                Err(err) => *error = Some(err.to_string()),
            },
            _ => {}
        }
        Ok(KeyOutcome::Consumed)
    }

    /// `T` on an SSH or user-agent row: trust it, or stop trusting it.
    ///
    /// Capital, because lower-case `t` is the global theme toggle, and a
    /// screen that claimed it would quietly take that away here.
    ///
    /// A user-agent row trusts its *whole* string. That is narrower than
    /// most operators want — a version bump makes it a different string —
    /// which is what typing a shorter substring into the Trusted panel is
    /// for.
    fn toggle_trust_selected(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let (entry, trusted) = match self.focus {
            Focus::Ssh => {
                let Some(row) = self
                    .ssh_state
                    .selected()
                    .and_then(|i| self.visible_ssh_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                (
                    TrustedEntry::Address(row.address.clone()),
                    row.status.is_trusted(),
                )
            }
            Focus::UserAgents => {
                let Some(row) = self
                    .ua_state
                    .selected()
                    .and_then(|i| self.visible_ua_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                (
                    TrustedEntry::UserAgent(row.user_agent.clone()),
                    row.status.is_trusted(),
                )
            }
            Focus::Trusted => return Ok(KeyOutcome::Ignored),
        };
        if trusted {
            // Only an exact entry can be removed from here. A row trusted
            // because a wider range or a shorter substring covers it is
            // left alone, and the message says where the entry lives.
            if !crate::dynamic::untrust(db, &entry)? {
                *message = Some(format!(
                    "{} is trusted by a wider entry — remove that one from the Trusted panel.",
                    entry.value()
                ));
                return Ok(KeyOutcome::Consumed);
            }
            *message = Some(format!(
                "No longer trusting {} {} — {}",
                entry.kind(),
                entry.value(),
                apply_hint(&entry)
            ));
        } else {
            let stored = match &entry {
                TrustedEntry::Address(address) => TrustedEntry::Address(db.trust_address(address)?),
                TrustedEntry::UserAgent(ua) => match db.trust_user_agent(ua) {
                    Ok(stored) => TrustedEntry::UserAgent(stored),
                    Err(err) => {
                        *message = Some(format!("Cannot trust that user agent: {err}"));
                        return Ok(KeyOutcome::Consumed);
                    }
                },
            };
            *message = Some(format!(
                "Trusting {} {} — {}",
                stored.kind(),
                stored.value(),
                apply_hint(&stored)
            ));
        }
        Ok(KeyOutcome::Mutated)
    }

    /// Opens the detail popup for whichever row is selected.
    ///
    /// The two panels take different routes on purpose. An address detail
    /// needs the SSH log text, which `App` read in the background and this
    /// screen does not keep a copy of, so it goes back through
    /// [`KeyOutcome::InspectAddress`] — the same shape `UpdateSource` and
    /// `SelectCountry` use when the work needs a resource `App` owns. A
    /// user-agent detail needs nothing but `db`, which is already in hand,
    /// so routing it through `App` would be ceremony for a resource
    /// nobody needs.
    ///
    /// Either way: reads the database, nothing over the network. See
    /// [`crate::ipdetail`] for why a detail view here is deliberately not
    /// reverse DNS, and [`crate::uadetail`] for why there is nothing to
    /// look up about a string the client made up.
    fn inspect_selected(&mut self, db: &Db, _message: &mut Option<String>) -> Result<KeyOutcome> {
        match self.focus {
            Focus::Ssh => {
                let Some(row) = self
                    .ssh_state
                    .selected()
                    .and_then(|i| self.visible_ssh_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                Ok(KeyOutcome::InspectAddress(row.address.clone()))
            }
            Focus::UserAgents => {
                let Some(row) = self
                    .ua_state
                    .selected()
                    .and_then(|i| self.visible_ua_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                let detail = UaDetail::load(db, &row.user_agent, row.status)?;
                self.detail = Some(Detail::UserAgent(Box::new(detail)));
                Ok(KeyOutcome::Consumed)
            }
            Focus::Trusted => Ok(KeyOutcome::Ignored),
        }
    }

    /// Shows a detail `App` assembled for [`KeyOutcome::InspectAddress`].
    pub fn show_detail(&mut self, detail: IpDetail) {
        self.detail = Some(Detail::Address(Box::new(detail)));
    }

    /// The status currently shown for `address`, so `App` can pass the
    /// row's own verdict into the detail rather than recomputing one that
    /// could disagree with what is on screen.
    pub fn status_of(&self, address: &str) -> RowStatus {
        self.ssh_rows
            .iter()
            .find(|row| row.address == address)
            .map(|row| row.status)
            .unwrap_or(RowStatus::Pending)
    }

    /// Toggles whichever row is selected in the currently focused panel
    /// (resolved against that panel's *filtered* rows — see
    /// [`Self::visible_ssh_rows`]/[`Self::visible_ua_rows`], since the
    /// selection index refers to a position on screen, not in the full
    /// underlying `ssh_rows`/`ua_rows`): a `NOT BLOCKED` row gets permanently
    /// blocked, a `Blocked` one gets unblocked. A no-op (still `Consumed`,
    /// not `Mutated`) if the panel is empty (or fully filtered out) —
    /// there's nothing to select. `Blocklist` rows are skipped (do nothing).
    fn toggle_block_selected(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        match self.focus {
            Focus::Ssh => {
                let Some(row) = self
                    .ssh_state
                    .selected()
                    .and_then(|i| self.visible_ssh_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                if row.status.is_blocklist() {
                    // Blocklist items cannot be toggled
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_trusted() {
                    *message = Some(trusted_refusal(&row.address));
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_blocked() {
                    db.unblock_address(&row.address)?;
                    *message = Some(format!(
                        "Unblocked {} — run render-firewall (then apply the script) to lift the enforced block.",
                        row.address
                    ));
                } else {
                    db.block_address_permanently(&row.address)?;
                    *message = Some(format!(
                        "Permanently blocked {} — run render-firewall (then apply the script) to enforce it.",
                        row.address
                    ));
                }
                Ok(KeyOutcome::Mutated)
            }
            Focus::UserAgents => {
                let Some(row) = self
                    .ua_state
                    .selected()
                    .and_then(|i| self.visible_ua_rows().get(i).copied())
                else {
                    return Ok(KeyOutcome::Consumed);
                };
                if row.status.is_blocklist() {
                    // Blocklist items cannot be toggled
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_trusted() {
                    *message = Some(trusted_refusal(&row.user_agent));
                    return Ok(KeyOutcome::Consumed);
                }
                if row.status.is_blocked() {
                    db.unblock_user_agent(&row.user_agent)?;
                    *message = Some(format!(
                        "Unblocked user agent \"{}\" — run apply-blocks to remove it from NGINX config.",
                        row.user_agent
                    ));
                } else {
                    if let Err(err) = db.block_user_agent(&row.user_agent) {
                        *message = Some(format!("Not blocked: {err}"));
                        return Ok(KeyOutcome::Consumed);
                    }
                    *message = Some(format!(
                        "Permanently blocked user agent \"{}\" — run apply-blocks to enforce it.",
                        row.user_agent
                    ));
                }
                Ok(KeyOutcome::Mutated)
            }
            Focus::Trusted => Ok(KeyOutcome::Ignored),
        }
    }

    /// `jobs` is `App`'s in-flight set, so the SSH panel can say when its
    /// contents are still on the way — the log read happens in the
    /// background now, and an empty panel with no explanation reads as
    /// "nothing to show" rather than "not here yet".
    pub fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        jobs: &std::collections::HashSet<crate::app::Job>,
    ) {
        // The trusted list is short by nature — a handful of hand-typed
        // entries — so it takes what it needs, up to a cap, and the two
        // traffic panels share the rest as before.
        let trusted_height = (self.trusted.len() as u16 + 1).clamp(1, 6) + 2;
        let [ssh_area, ua_area, trusted_area] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(trusted_height),
        ])
        .areas(area);

        let reading = jobs.contains(&crate::app::Job::ReadSshLog);
        let ssh_rows = self.visible_ssh_rows();
        let ua_rows_for_width = self.visible_ua_rows();
        // One width for both panels, not one each. They are stacked with
        // the same left edge and every column before this one already
        // lines up, so a tag column that agreed only within a panel would
        // put the two address columns a few cells apart — which reads as
        // a mistake rather than as two independent tables.
        let tag_width = tag_column_width(
            ssh_rows
                .iter()
                .map(|row| row.status)
                .chain(ua_rows_for_width.iter().map(|row| row.status)),
        );
        let ssh_max = ssh_rows.iter().map(|row| row.count).max().unwrap_or(0);
        let ssh_items: Vec<ListItem> = empty_or(
            ssh_rows
                .into_iter()
                .map(|row| ssh_row_line(row, ssh_max, tag_width, theme))
                .map(ListItem::new)
                .collect(),
            if reading {
                "Reading the SSH log…"
            } else if self.ssh_rows.is_empty() {
                "No failed SSH logins in the current log. Nothing to block — this is the good case."
            } else {
                "Nothing matches this filter. Press f to change it."
            },
        );
        let ssh_focused = self.focus == Focus::Ssh;
        let ssh_list = crate::tui::select_in(
            List::new(ssh_items).block(crate::tui::panel(
                panel_title(
                    "Failed SSH logins",
                    self.ssh_rows.len(),
                    self.filter.label(),
                ),
                ssh_focused,
                theme,
            )),
            ssh_focused,
            theme,
        );
        frame.render_stateful_widget(ssh_list, ssh_area, &mut self.ssh_state);

        let ua_rows = self.visible_ua_rows();
        let ua_max = ua_rows.iter().map(|row| row.count).max().unwrap_or(0);
        let ua_items: Vec<ListItem> = empty_or(
            ua_rows
                .into_iter()
                .map(|row| ua_row_line(row, ua_max, tag_width, theme))
                .map(ListItem::new)
                .collect(),
            if self.ua_rows.is_empty() {
                "No successful requests tallied yet. This fills in as traffic arrives, \
                 or run `stop-bots record-access-stats`."
            } else {
                "Nothing matches this filter. Press f to change it."
            },
        );
        let ua_focused = self.focus == Focus::UserAgents;
        let ua_list = crate::tui::select_in(
            List::new(ua_items).block(crate::tui::panel(
                panel_title("Top user agents", self.ua_rows.len(), self.filter.label()),
                ua_focused,
                theme,
            )),
            ua_focused,
            theme,
        );
        frame.render_stateful_widget(ua_list, ua_area, &mut self.ua_state);

        let trusted_items: Vec<ListItem> = std::iter::once(ListItem::new(
            Line::from("+ Trust an address or user agent").italic(),
        ))
        .chain(self.trusted.iter().map(|entry| {
            ListItem::new(Line::from(vec![
                format!("{:<11}", entry.kind()).fg(theme.dim()),
                entry.value().to_string().into(),
            ]))
        }))
        .collect();
        let trusted_focused = self.focus == Focus::Trusted;
        let trusted_list = crate::tui::select_in(
            List::new(trusted_items).block(crate::tui::panel(
                format!(
                    "Trusted \u{00b7} {} \u{00b7} never blocked",
                    self.trusted.len()
                ),
                trusted_focused,
                theme,
            )),
            trusted_focused,
            theme,
        );
        frame.render_stateful_widget(trusted_list, trusted_area, &mut self.trusted_state);

        if let Some(TrustInput { input, error }) = &self.trust_input {
            let title = "Trust an address or user agent";
            let hint =
                "An IP, a CIDR range, or part of a user agent — Enter to trust, Esc to cancel";
            let mut lines = vec![
                Line::from(format!("{input}\u{2588}")),
                Line::from(hint).dim(),
            ];
            if let Some(error) = error {
                lines.push(Line::from(error.clone()).red());
            }
            let popup = centered_rect(
                widest_line(&lines).max(title.len() as u16) + 4,
                lines.len() as u16 + 2,
                area,
            );
            let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
            frame.render_widget(Clear, popup);
            frame.render_widget(paragraph, popup);
        }

        // Last, and over the whole screen rather than one panel: it
        // answers a question about a row, and reading it against half the
        // table it came from is what a popup is for.
        if let Some(detail) = &self.detail {
            let (title, lines) = match detail {
                Detail::Address(detail) => (detail.address.clone(), detail_lines(detail)),
                // Built against the height actually available: the popup
                // cannot scroll, so a body longer than this loses its own
                // closing line rather than growing.
                Detail::UserAgent(detail) => (
                    "User agent".to_string(),
                    ua_detail_lines(detail, area.height.saturating_sub(2) as usize),
                ),
            };
            let popup = centered_rect(
                widest_line(&lines).max(24) + 4,
                lines.len() as u16 + 2,
                area,
            );
            let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
            frame.render_widget(Clear, popup);
            frame.render_widget(paragraph, popup);
        }
    }
}

/// The address-detail popup's body.
///
/// Every line is something already in the database — see
/// [`crate::ipdetail`] for why there is no reverse DNS here. The order is
/// deliberate: what the host already decided about this address, then what
/// the feeds say it *is*, then what it actually did. Someone deciding
/// whether to block reads top-down and can stop as soon as they have
/// enough.
fn detail_lines(detail: &IpDetail) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        "Status  ".into(),
        detail.status.label().bold(),
    ])];

    match detail.kind {
        AddressKind::LocalOrPrivate => {
            lines.push(Line::from(""));
            lines.push("A loopback or private address.".dim().into());
            // Said explicitly because the alternative — an empty list of
            // feed hits — reads as "nothing known about a public address",
            // which is a different and much more suspicious claim.
            lines.push(
                "No feed lists these, so there is nothing to look up."
                    .dim()
                    .into(),
            );
        }
        AddressKind::Malformed => {
            lines.push(Line::from(""));
            lines.push("Not a valid IP address or range.".dim().into());
        }
        AddressKind::Public => {
            lines.push(Line::from(""));
            for hit in &detail.crawlers {
                lines.push(Line::from(vec![
                    "Crawler ".into(),
                    hit.source.clone().green(),
                    format!("  ({})", hit.range).dim(),
                ]));
            }
            for hit in &detail.reputation {
                lines.push(Line::from(vec![
                    "Feed    ".into(),
                    hit.source.clone().yellow(),
                    format!("  ({})", hit.range).dim(),
                ]));
            }
            match (&detail.country, detail.country_data_available) {
                (Some(code), _) => {
                    lines.push(Line::from(vec!["Country ".into(), code.clone().into()]));
                }
                // Distinguished on purpose: with no zone file fetched,
                // "no country" is a statement about this host's data, not
                // about the address.
                (None, true) => lines.push("Country  not in any fetched country".dim().into()),
                (None, false) => lines.push("Country  no country data fetched".dim().into()),
            }
            if detail.is_unknown() {
                lines.push(Line::from(""));
                lines.push("In none of the crawler or reputation feeds.".dim().into());
            }
        }
    }

    if !detail.usernames.is_empty() {
        lines.push(Line::from(""));
        lines.push("Tried to log in as".bold().into());
        // Capped: an attacker picks these names, and a client that tried
        // four hundred of them would otherwise own the whole screen. The
        // count above already says how hard it tried.
        const MAX_SHOWN: usize = 8;
        for (user, count) in detail.usernames.iter().take(MAX_SHOWN) {
            lines.push(Line::from(vec![
                format!("  {user}").into(),
                format!("  ×{count}").dim(),
            ]));
        }
        if detail.usernames.len() > MAX_SHOWN {
            lines.push(
                format!("  … and {} more", detail.usernames.len() - MAX_SHOWN)
                    .dim()
                    .into(),
            );
        }
    }

    lines.push(Line::from(""));
    lines.push("Esc close".dim().into());
    lines
}

/// How wide the user agent itself is allowed to draw before it wraps.
///
/// The popup sizes itself to its widest line and `centered_rect` clamps
/// that to the terminal, so an unwrapped 300-character string would not
/// overflow — it would simply be cut off at the right edge, which is the
/// half of it nobody can read. Wrapping instead costs a few rows and
/// keeps all of it on screen. 64 leaves room for the border and the
/// two-space indent at the 80 columns this project treats as its floor.
const UA_WRAP_CHARS: usize = 64;

/// At most this many contributing lists are named per matched bot. Three
/// is the most any bot has on a real host; the count carries the rest.
const MAX_SOURCES_SHOWN: usize = 3;

/// At most this many wrapped rows for the user agent itself. `uadetail`
/// already caps the string at 300 characters, which is five rows at
/// [`UA_WRAP_CHARS`] — rows that on a short terminal would come out of
/// the verdict below, which is what the popup was opened for.
const MAX_UA_LINES: usize = 4;

/// The user-agent-detail popup's body, built to fit `budget` rows.
///
/// Reads top-down the way [`detail_lines`] does: what this host already
/// decided, then the string itself, then what the lists say about it. The
/// order matters more here, because the string is the one thing on the
/// popup the client chose — see [`crate::uadetail`].
///
/// Unlike `detail_lines` this is *unbounded* at the source — a string
/// containing several vendor tokens matches several entries, and there is
/// no ceiling on how many. The popup is clamped to the terminal and the
/// paragraph does not scroll, so every line past the bottom is silently
/// dropped, and the last line is the one saying how to get out. So the
/// match list is cut to what is left after the header and that closing
/// line, with the count of what was cut standing in for the rest.
fn ua_detail_lines(detail: &UaDetail, budget: usize) -> Vec<Line<'static>> {
    /// The blank line and the "Esc close" that always end the body.
    const TRAILER: usize = 2;
    /// Rows one matched bot takes.
    const PER_MATCH: usize = 2;

    let mut lines = vec![Line::from(vec![
        "Status  ".into(),
        detail.status.label().bold(),
    ])];
    lines.push(Line::from(vec![
        "Hits    ".into(),
        match detail.hits {
            Some(hits) => hits.to_string().into(),
            // Not "0": the tally is pruned on a schedule, and a row can
            // go between the table being drawn and this keypress.
            None => "no longer counted".dim(),
        },
    ]));
    if let Some(seen) = detail.last_seen_at {
        lines.push(Line::from(vec![
            "Seen    ".into(),
            crate::health::format_utc(seen).into(),
        ]));
    }
    if detail.blocked_by_hand {
        lines.push(Line::from(vec![
            "Blocked ".into(),
            "by hand, from this screen".into(),
        ]));
    }

    lines.push(Line::from(""));
    // Already capped and stripped of control characters by `uadetail` —
    // which matters here and not in the web UI, because an escape
    // sequence reaching the alternate screen repaints the terminal. The
    // second cap is on *rows*: 300 characters is four wrapped lines, and
    // on a short terminal those are four lines not spent on the verdict.
    let wrapped_ua = wrapped(&detail.user_agent, UA_WRAP_CHARS);
    let ua_truncated = detail.truncated || wrapped_ua.len() > MAX_UA_LINES;
    for chunk in wrapped_ua.into_iter().take(MAX_UA_LINES) {
        lines.push(chunk.into());
    }
    if ua_truncated {
        lines.push("(truncated — the client sent more)".dim().into());
    }

    lines.push(Line::from(""));
    if detail.matches.is_empty() {
        lines.push(
            "No bot list here has a pattern for this string."
                .dim()
                .into(),
        );
        if detail.self_declared_bot {
            lines.push("It calls itself a bot.".yellow().into());
        }
    } else {
        lines.push("Matched by".bold().into());
        // One row is always kept back for the "… and N more" that the cut
        // itself needs, so the cut can never be the thing that overflows.
        let room = budget
            .saturating_sub(lines.len() + TRAILER + 1)
            .saturating_div(PER_MATCH);
        let shown = detail.matches.len().min(room);
        for hit in detail.matches.iter().take(shown) {
            let verdict = if hit.verdict.is_blocked() {
                hit.verdict.label().red()
            } else {
                hit.verdict.label().dim()
            };
            lines.push(Line::from(vec![
                format!("  {}  ", hit.name).into(),
                verdict,
            ]));
            lines.push(Line::from(vec![
                format!("    {}  ", hit.pattern).dim(),
                source_summary(&hit.sources).dim(),
            ]));
        }
        if shown < detail.matches.len() {
            lines.push(
                format!("  … and {} more", detail.matches.len() - shown)
                    .dim()
                    .into(),
            );
        }
    }

    // The last word on the budget, whatever the sections above did with
    // theirs. On a terminal too short even for the header, something has
    // to give; what must not is the line saying how to get out.
    let room_for_body = budget.saturating_sub(TRAILER);
    if lines.len() > room_for_body {
        lines.truncate(room_for_body.saturating_sub(1));
        lines.push("\u{2026}".dim().into());
    }

    lines.push(Line::from(""));
    lines.push("Esc close".dim().into());
    lines
}

/// The lists contributing one bot, capped so a bot every source carries
/// cannot stretch the popup. The count is what the reader is after —
/// three lists agreeing is different evidence from one.
fn source_summary(sources: &[String]) -> String {
    if sources.len() <= MAX_SOURCES_SHOWN {
        return sources.join(", ");
    }
    format!(
        "{}, and {} more",
        sources[..MAX_SOURCES_SHOWN].join(", "),
        sources.len() - MAX_SOURCES_SHOWN
    )
}

/// `text` split into chunks of at most `width` characters, preferring to
/// break at a space.
///
/// Counts characters, not bytes: a user agent can carry multi-byte text,
/// and slicing one by byte offset either panics or produces mojibake.
/// Falls back to a hard break for a run with no space in it, which is
/// what a long base64-ish token is.
fn wrapped(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let remaining = chars.len() - start;
        if remaining <= width {
            out.push(chars[start..].iter().collect());
            break;
        }
        // The last space inside the window, so the break lands between
        // words when there is one to land between.
        let end = chars[start..start + width]
            .iter()
            .rposition(|c| *c == ' ')
            .map(|at| start + at + 1)
            .unwrap_or(start + width);
        out.push(chars[start..end].iter().collect());
        start = end;
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// What makes a trust change take effect. An address reaches both the
/// firewall and NGINX; a user agent only ever NGINX, which never sees a
/// packet's user agent to begin with.
fn apply_hint(entry: &TrustedEntry) -> &'static str {
    match entry {
        TrustedEntry::Address(_) => {
            "apply everything (a on the Dashboard) to put it in the firewall and NGINX."
        }
        TrustedEntry::UserAgent(_) => "apply everything (a on the Dashboard) to put it in NGINX.",
    }
}

/// Why Enter did nothing on a trusted row. Blocking something trusted
/// would store a rule the trust overrides — a block that does nothing,
/// and a row that would read `BLOCKED` while it is not.
fn trusted_refusal(value: &str) -> String {
    format!("{value} is trusted, so it cannot be blocked — press T to stop trusting it first.")
}

/// The widest line in `lines`, for sizing a popup to its content.
fn widest_line(lines: &[Line<'_>]) -> u16 {
    lines
        .iter()
        .map(|line| line.width() as u16)
        .max()
        .unwrap_or(0)
}

/// A panel title, with its key hints dropped when the terminal is too
/// narrow to hold them.
///
/// At 80 columns — the width this project documents as its minimum — the
/// old titles ran past the border and were cut mid-word, so the last
/// thing on screen was half a hint. What has to survive is the name of
/// the panel and which filter is on; the hints are in `?` too.
/// "Failed SSH logins · 5" and, when a filter is on, which one: the
/// count says how many rows there are, the filter says why fewer show.
fn panel_title(name: &str, total: usize, filter: &str) -> String {
    if filter == "all" {
        format!("{name} \u{00b7} {total}")
    } else {
        format!("{name} \u{00b7} {total} \u{00b7} {filter}")
    }
}

/// A list's items, or a single dimmed line saying why there are none.
///
/// An empty bordered box reads as "this is broken", not as "nothing to
/// show" — and on this screen the second is the *good* outcome, so it is
/// worth saying out loud. NGINX already does this for its own
/// empty list; this is the same idea.
fn empty_or(items: Vec<ListItem<'static>>, message: &str) -> Vec<ListItem<'static>> {
    if items.is_empty() {
        vec![ListItem::new(Line::from(message.to_string()).dim())]
    } else {
        items
    }
}

fn ssh_row_line(row: &SshRow, max: u64, tag_width: usize, theme: Theme) -> Line<'static> {
    row_line(
        row.count,
        max,
        row.status,
        row.address.clone(),
        tag_width,
        theme,
    )
}

fn ua_row_line(row: &UaRow, max: u64, tag_width: usize, theme: Theme) -> Line<'static> {
    row_line(
        row.count,
        max,
        row.status,
        row.user_agent.clone(),
        tag_width,
        theme,
    )
}

/// How many cells the count bar gets. Long enough to tell 4812 from
/// 3004 at a glance, short enough to leave the user agent its column.
const BAR_WIDTH: usize = 10;

/// The width the `[ ... ]` state tag is padded out to, over every tag
/// that will be on screen — see [`row_line`] for why the column has to be
/// one width rather than each row's own.
fn tag_column_width(statuses: impl Iterator<Item = RowStatus>) -> usize {
    statuses
        .map(|status| tag_text(status).chars().count())
        .max()
        .unwrap_or(0)
}

fn tag_text(status: RowStatus) -> String {
    format!("[ {} ]", status.label())
}

/// One row of either panel: the count, a bar scaled to the panel's
/// largest count, the state tag in a fixed column, then the value. The
/// tag carries the colour; the value stays default so a long user agent
/// reads as text rather than as a red stripe.
///
/// `tag_width` is what makes "a fixed column" true. The tags are four
/// different lengths — `[ BLOCKED ]`, `[ BLOCKLIST ]`, `[ NOT BLOCKED ]`
/// and `[ BLOCKED for 1d ]`, which is longest and varies with the time
/// left — so without padding every row started its address at a different
/// cell and the states ran into the addresses. The doc comment above had
/// claimed the fixed column since the panel was written; only the padding
/// was missing. It comes from the caller rather than from a constant
/// because the longest tag depends on the rows actually present: a panel
/// with no expiring blocks should not indent every address past a width
/// reserved for a tag that is not there.
fn row_line(
    count: u64,
    max: u64,
    status: RowStatus,
    value: String,
    tag_width: usize,
    theme: Theme,
) -> Line<'static> {
    let filled = if max == 0 {
        0
    } else {
        // Ceiling, so the smallest row still gets one cell.
        (count as usize * BAR_WIDTH).div_ceil(max as usize)
    };
    let bar = format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        " ".repeat(BAR_WIDTH - filled)
    );
    let text = tag_text(status);
    // Padded outside the brackets, not inside them: `[ BLOCKED        ]`
    // stretches the coloured box to the width of the widest state, which
    // draws the eye to the emptiest row on the screen.
    let padding = " ".repeat(tag_width.saturating_sub(text.chars().count()));
    let tag = match status {
        RowStatus::Blocklist => text.yellow(),
        RowStatus::Blocked { .. } => text.red(),
        RowStatus::Pending => text.fg(theme.dim()),
        // Not dim like `Pending`: the whole point of the tag is that this
        // row is worth a look, and dimming it would bury it among the
        // browsers it sits between.
        RowStatus::Unknown => text.yellow(),
        RowStatus::Trusted => text.green(),
    };
    Line::from(vec![
        format!("{count:>6} ").into(),
        bar.fg(theme.accent()),
        "  ".into(),
        tag,
        padding.into(),
        "  ".into(),
        value.into(),
    ])
}

/// `list_state`'s selection must always point at a valid row once `len`
/// rows exist (so the first arrow key press doesn't need to "discover" a
/// selection first), and never point at all once emptied — same convention
/// `Dashboard`'s two lists already use.
fn clamp_selection(list_state: &mut ListState, len: usize) {
    if len == 0 {
        list_state.select(None);
    } else if list_state.selected().is_none_or(|s| s >= len) {
        list_state.select(Some(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FirewallAction;
    use crate::db::NewBot;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;
    use ratatui::Terminal;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn refresh_populates_ua_rows_from_the_database() {
        let db = Db::open_in_memory().unwrap();
        // upsert_bot requires a source; not needed here, just documents
        // that this screen doesn't touch `bots` at all.
        let _ = NewBot {
            slug: "unused".to_string(),
            name: "unused".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "unused".to_string(),
            source_id: "unused".to_string(),
        };
        let mut counts = HashMap::new();
        counts.insert("Mozilla/5.0".to_string(), 5u64);
        db.record_user_agent_hits(&counts, 1000).unwrap();
        db.block_user_agent("Mozilla/5.0").unwrap();

        let mut screen = Firewall::default();
        screen.refresh(&db, None).unwrap();

        assert_eq!(screen.ua_rows.len(), 1);
        assert_eq!(screen.ua_rows[0].user_agent, "Mozilla/5.0");
        assert_eq!(screen.ua_rows[0].status, RowStatus::Blocked { until: None });
    }

    #[test]
    fn tab_cycles_through_the_three_panels_and_shift_tab_goes_back() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall::default();
        let mut message = None;
        assert_eq!(screen.focus, Focus::Ssh);

        for expected in [Focus::UserAgents, Focus::Trusted, Focus::Ssh] {
            screen
                .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
                .unwrap();
            assert_eq!(screen.focus, expected);
        }
        screen
            .handle_key(KeyEvent::from(KeyCode::BackTab), &db, &mut message)
            .unwrap();
        assert_eq!(screen.focus, Focus::Trusted);
    }

    fn press(screen: &mut Firewall, db: &Db, code: KeyCode) -> (KeyOutcome, Option<String>) {
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(code), db, &mut message)
            .unwrap();
        (outcome, message)
    }

    #[test]
    fn shift_t_trusts_the_selected_address_and_again_stops_trusting_it() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Pending);

        let (outcome, _) = press(&mut screen, &db, KeyCode::Char('T'));
        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.list_trusted_addresses().unwrap(), vec!["185.220.101.7"]);

        screen.ssh_rows[0].status = RowStatus::Trusted;
        press(&mut screen, &db, KeyCode::Char('T'));
        assert!(db.list_trusted_addresses().unwrap().is_empty());
    }

    #[test]
    fn shift_t_trusts_the_selected_user_agent() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ua_row("UptimeRobot/2.0", RowStatus::Blocklist);

        press(&mut screen, &db, KeyCode::Char('T'));

        assert_eq!(
            db.list_trusted_user_agents().unwrap(),
            vec!["UptimeRobot/2.0"]
        );
    }

    /// A block on a trusted row would be a rule the trust overrides: a
    /// block that does nothing, on a row that would then read BLOCKED.
    #[test]
    fn enter_refuses_to_block_a_trusted_row_and_says_why() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Trusted);

        let (outcome, message) = press(&mut screen, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(db.list_firewall_rules().unwrap().is_empty());
        assert!(message.unwrap().contains("press T"));
    }

    /// A row trusted by a wider range is not removed by `T` on it — there
    /// is no entry for that exact row — and saying it was would be a lie.
    #[test]
    fn shift_t_on_a_row_trusted_by_a_wider_range_says_where_the_entry_is() {
        let db = Db::open_in_memory().unwrap();
        db.trust_address("185.220.101.0/24").unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Trusted);

        let (outcome, message) = press(&mut screen, &db, KeyCode::Char('T'));

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert_eq!(
            db.list_trusted_addresses().unwrap(),
            vec!["185.220.101.0/24"]
        );
        assert!(message.unwrap().contains("wider entry"));
    }

    fn trusted_panel_screen(db: &Db) -> Firewall {
        let mut screen = Firewall {
            focus: Focus::Trusted,
            ..Default::default()
        };
        screen.refresh(db, None).unwrap();
        screen
    }

    fn type_into(screen: &mut Firewall, db: &Db, text: &str) {
        for c in text.chars() {
            press(screen, db, KeyCode::Char(c));
        }
    }

    /// The field owns every printable key: `j`, `t` and `f` are all
    /// letters a user agent can contain, and `t` would otherwise reach
    /// the global theme toggle.
    #[test]
    fn the_add_row_takes_typed_text_including_screen_keys() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = trusted_panel_screen(&db);

        press(&mut screen, &db, KeyCode::Enter);
        type_into(&mut screen, &db, "jtf-monitor");
        let (outcome, message) = press(&mut screen, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.list_trusted_user_agents().unwrap(), vec!["jtf-monitor"]);
        assert!(screen.trust_input.is_none());
        assert!(message.unwrap().contains("user agent"));
    }

    /// Left open with the reason, so the operator can fix what they typed.
    #[test]
    fn a_mistyped_address_keeps_the_field_open_with_the_reason() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = trusted_panel_screen(&db);

        press(&mut screen, &db, KeyCode::Enter);
        type_into(&mut screen, &db, "10.0.0.1/33");
        let (outcome, _) = press(&mut screen, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Consumed);
        let error = screen.trust_input.as_ref().and_then(|i| i.error.clone());
        assert!(error.is_some(), "no reason was shown");
        assert!(db.list_trusted_user_agents().unwrap().is_empty());
        assert!(drawn(&mut screen).contains("10.0.0.1/33"));
    }

    #[test]
    fn enter_on_a_trusted_entry_stops_trusting_it() {
        let db = Db::open_in_memory().unwrap();
        db.trust_address("203.0.113.7").unwrap();
        let mut screen = trusted_panel_screen(&db);
        screen.trusted_state.select(Some(1));

        let (outcome, _) = press(&mut screen, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_trusted_addresses().unwrap().is_empty());
    }

    #[test]
    fn the_trusted_panel_shows_each_entry_and_the_add_row() {
        let db = Db::open_in_memory().unwrap();
        db.trust_address("203.0.113.7").unwrap();
        db.trust_user_agent("UptimeRobot").unwrap();
        let mut screen = trusted_panel_screen(&db);

        let content = drawn(&mut screen);

        for needle in [
            "Trust an address or user agent",
            "203.0.113.7",
            "UptimeRobot",
        ] {
            assert!(content.contains(needle), "missing {needle}:\n{content}");
        }
    }

    #[test]
    fn enter_permanently_blocks_the_selected_ssh_row() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Pending,
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "198.51.100.9");
        assert_eq!(rules[0].expires_at, None);
        assert!(message.unwrap().contains("198.51.100.9"));
    }

    #[test]
    fn enter_permanently_blocks_the_selected_user_agent() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Pending,
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(
            db.list_blocked_user_agents().unwrap(),
            vec!["curl/8.0".to_string()]
        );
        assert!(message.unwrap().contains("curl/8.0"));
    }

    /// A user agent too short to mean one client (an access log records
    /// `-` for none) is refused with a reason on screen, not an error that
    /// ends the key handler.
    #[test]
    fn enter_on_a_user_agent_that_would_block_everyone_says_why_not() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ua_row("-", RowStatus::Pending);

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(db.list_blocked_user_agents().unwrap().is_empty());
        let message = message.unwrap_or_default();
        assert!(message.contains("Not blocked"), "message was: {message}");
    }

    /// Enter is a toggle, not just "ensure blocked": pressing it on a row
    /// already showing `BLOCKED` (temporary or permanent) unblocks it —
    /// this is `unblock_address`, the reverse of the previous test's
    /// `block_address_permanently`.
    #[test]
    fn enter_unblocks_an_already_blocked_ssh_row() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule_with_ttl(
            &crate::db::NewFirewallRule {
                address: "198.51.100.9".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            3600,
        )
        .unwrap();
        let mut screen = Firewall {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Blocked { until: Some(0) },
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_firewall_rules().unwrap().is_empty());
        assert!(message.unwrap().contains("Unblocked"));
    }

    #[test]
    fn enter_unblocks_an_already_blocked_user_agent() {
        let db = Db::open_in_memory().unwrap();
        db.block_user_agent("curl/8.0").unwrap();
        let mut screen = Firewall {
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Blocked { until: None },
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_blocked_user_agents().unwrap().is_empty());
        assert!(message.unwrap().contains("Unblocked"));
    }

    #[test]
    fn f_key_cycles_through_all_pending_and_blocked_filters() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall::default();
        assert_eq!(screen.filter, Filter::All);

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::PendingOnly);

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::BlockedOnly);

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::All);
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// The bug this column exists to stop: with four state tags of four
    /// different lengths, every row used to start its address at a
    /// different cell, so the states ran into the addresses instead of
    /// sitting in a column beside them. Asserts the thing the eye
    /// actually checks — that every address begins at the same x — rather
    /// than a golden screenful, so it still means something when a label
    /// or a bar width changes.
    ///
    /// Both panels, because the width is shared between them: they stack
    /// with one left edge, and two addresses a few cells apart read as a
    /// mistake rather than as two independent tables.
    #[test]
    fn every_row_starts_its_value_in_the_same_column() {
        let later = now_secs() + 86_400;
        let mut screen = Firewall {
            ssh_rows: vec![
                SshRow {
                    address: "203.0.113.5".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "198.51.100.9".to_string(),
                    count: 5,
                    status: RowStatus::Blocked { until: Some(later) },
                },
                SshRow {
                    address: "192.0.2.77".to_string(),
                    count: 12,
                    status: RowStatus::Blocked { until: None },
                },
                SshRow {
                    address: "2001:db8::abcd".to_string(),
                    count: 40,
                    status: RowStatus::Blocklist,
                },
            ],
            ua_rows: vec![UaRow {
                user_agent: "curl/8.5.0".to_string(),
                count: 9,
                status: RowStatus::Pending,
            }],
            ..Default::default()
        };

        let backend = TestBackend::new(100, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();
        let buffer = terminal.backend().buffer();

        // Counted in cells, not bytes. The bar is drawn with `\u{2588}`
        // and the border with `\u{2502}`, three bytes each, so a `find`
        // offset would make a row with more bar look further right than
        // one with less — which is the very thing under test.
        let column_of = |needle: &str| {
            (0..buffer.area.height)
                .find_map(|y| {
                    let row: String = (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect();
                    row.find(needle).map(|byte| row[..byte].chars().count())
                })
                .unwrap_or_else(|| panic!("{needle} should be on screen"))
        };

        let first = column_of("203.0.113.5");
        for value in ["198.51.100.9", "192.0.2.77", "2001:db8::abcd", "curl/8.5.0"] {
            assert_eq!(
                column_of(value),
                first,
                "{value} starts in a different column from the first address"
            );
        }
    }

    /// The column is sized from the rows on screen, not from a constant.
    /// `[ BLOCKED for 1d ]` is much the longest tag, so reserving room for
    /// it unconditionally would indent every address on a panel that has
    /// no expiring block to show.
    #[test]
    fn the_tag_column_reserves_no_room_for_a_state_that_is_not_shown() {
        let timed = tag_column_width(
            [
                RowStatus::Blocked { until: None },
                RowStatus::Blocked {
                    until: Some(now_secs() + 86_400),
                },
            ]
            .into_iter(),
        );
        let untimed =
            tag_column_width([RowStatus::Blocked { until: None }, RowStatus::Pending].into_iter());

        assert!(
            untimed < timed,
            "a panel with no expiring block should not pay for one: {untimed} vs {timed}"
        );
        assert_eq!(untimed, "[ NOT BLOCKED ]".chars().count());
    }

    /// The headline ask this change exists for: a `BLOCKED` row must
    /// actually render red, not just show the word "BLOCKED" in plain
    /// text. Uses digits that appear nowhere else on screen (neither
    /// address, count, nor status label repeats them) so each fetched cell
    /// is unambiguously from that one row.
    #[test]
    fn blocked_rows_render_red_and_pending_rows_do_not() {
        let mut screen = Firewall {
            ssh_rows: vec![
                SshRow {
                    address: "1.1.1.1".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "9.9.9.9".to_string(),
                    count: 5,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        // The tag carries the colour, not the address: a row reads as
        // text with a red `[ BLOCKED ]` beside it, not as a red stripe.
        let buffer = terminal.backend().buffer();
        let row_of = |needle: &str| {
            (0..buffer.area.height)
                .find(|&y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                        .contains(needle)
                })
                .expect("row should be on screen")
        };
        let tag_fg = |y: u16| {
            (0..buffer.area.width)
                .map(|x| &buffer[(x, y)])
                .find(|cell| cell.symbol() == "[")
                .map(|cell| cell.fg)
                .expect("row should have a tag")
        };
        assert_eq!(
            tag_fg(row_of("9.9.9.9")),
            Color::Red,
            "blocked row's tag must render red"
        );
        assert_ne!(
            tag_fg(row_of("1.1.1.1")),
            Color::Red,
            "pending row's tag must not render red"
        );
    }

    #[test]
    fn blocked_only_filter_hides_pending_rows_from_render() {
        let mut screen = Firewall {
            ssh_rows: vec![
                SshRow {
                    address: "198.51.100.9".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "203.0.113.5".to_string(),
                    count: 1,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            filter: Filter::BlockedOnly,
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("203.0.113.5"), "content was:\n{content}");
        assert!(!content.contains("198.51.100.9"), "content was:\n{content}");
        assert!(content.contains("blocked only"), "content was:\n{content}");
    }

    /// Changing the filter must re-clamp each panel's selection against the
    /// new *visible* length, not the full row count — otherwise switching
    /// to a filter with fewer visible rows than the current selection index
    /// would leave the selection pointing at nothing on screen.
    #[test]
    fn changing_the_filter_reclamps_the_selection_to_the_visible_rows() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            ssh_rows: vec![
                SshRow {
                    address: "198.51.100.9".to_string(),
                    count: 3,
                    status: RowStatus::Pending,
                },
                SshRow {
                    address: "203.0.113.5".to_string(),
                    count: 1,
                    status: RowStatus::Blocked { until: None },
                },
            ],
            ..Default::default()
        };
        screen.ssh_state.select(Some(1));

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();
        assert_eq!(screen.filter, Filter::PendingOnly);
        // Only one row is visible under this filter now, so the selection
        // must have been pulled back to index 0.
        assert_eq!(screen.ssh_state.selected(), Some(0));
    }

    #[test]
    fn enter_on_an_empty_panel_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall::default();

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn render_shows_both_panels() {
        let mut screen = Firewall {
            ssh_rows: vec![SshRow {
                address: "198.51.100.9".to_string(),
                count: 3,
                status: RowStatus::Pending,
            }],
            ua_rows: vec![UaRow {
                user_agent: "curl/8.0".to_string(),
                count: 2,
                status: RowStatus::Pending,
            }],
            ..Default::default()
        };

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Failed SSH logins"),
            "content was:\n{content}"
        );
        assert!(content.contains("198.51.100.9"), "content was:\n{content}");
        assert!(content.contains("NOT BLOCKED"), "content was:\n{content}");
        assert!(
            content.contains("Top user agents"),
            "content was:\n{content}"
        );
        assert!(content.contains("curl/8.0"), "content was:\n{content}");
    }

    #[test]
    fn enter_on_blocklist_row_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            ssh_rows: vec![SshRow {
                address: "192.168.1.5".to_string(),
                count: 3,
                status: RowStatus::Blocklist,
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.is_none());
        // Verify no firewall rules were added
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn enter_on_blocklist_ua_row_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            ua_rows: vec![UaRow {
                user_agent: "Googlebot".to_string(),
                count: 2,
                status: RowStatus::Blocklist,
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(message.is_none());
        // Verify no user agents were blocked
        assert!(db.list_blocked_user_agents().unwrap().is_empty());
    }

    #[test]
    fn blocklist_status_label_is_blocklist() {
        assert_eq!(RowStatus::Blocklist.label(), "BLOCKLIST");
    }

    #[test]
    fn blocklist_status_is_blocked() {
        assert!(RowStatus::Blocklist.is_blocked());
    }

    #[test]
    fn blocklist_status_is_blocklist() {
        assert!(RowStatus::Blocklist.is_blocklist());
        assert!(!RowStatus::Pending.is_blocklist());
        assert!(!RowStatus::Blocked { until: None }.is_blocklist());
    }
    fn screen_with_one_ssh_row(status: RowStatus) -> Firewall {
        let mut screen = Firewall {
            ssh_rows: vec![SshRow {
                address: "185.220.101.7".to_string(),
                count: 12,
                status,
            }],
            ..Default::default()
        };
        screen.ssh_state.select(Some(0));
        screen
    }

    fn drawn(screen: &mut Firewall) -> String {
        drawn_at(screen, 30)
    }

    fn drawn_at(screen: &mut Firewall, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, height)).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark, &HashSet::new()))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    /// Opening the popup is two steps on purpose: the screen asks, and
    /// `App` answers, because the usernames come from the SSH log text
    /// `App` holds. This stands in for that second step.
    fn open_detail(screen: &mut Firewall, db: &Db) {
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), db, &mut message)
            .unwrap();
        let KeyOutcome::InspectAddress(address) = outcome else {
            panic!("expected an InspectAddress outcome, got {outcome:?}");
        };
        let status = screen.status_of(&address);
        let detail = crate::ipdetail::IpDetail::load(
            db,
            &address,
            status,
            vec![("root".to_string(), 9), ("admin".to_string(), 3)],
        )
        .unwrap();
        screen.show_detail(detail);
    }

    #[test]
    fn i_asks_app_to_inspect_the_selected_address() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Pending);
        let mut message = None;

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        assert_eq!(
            outcome,
            KeyOutcome::InspectAddress("185.220.101.7".to_string())
        );
    }

    #[test]
    fn the_detail_popup_shows_the_address_and_the_accounts_tried() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Pending);

        open_detail(&mut screen, &db);

        let content = drawn(&mut screen);
        assert!(content.contains("185.220.101.7"), "content:\n{content}");
        assert!(content.contains("root"), "content:\n{content}");
        assert!(content.contains("admin"), "content:\n{content}");
    }

    /// `Esc` must close the popup rather than leave the screen — the same
    /// nested-back-out shape `site_detail` uses one level deeper.
    #[test]
    fn esc_closes_the_detail_popup_instead_of_leaving_the_screen() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Pending);
        let mut message = None;
        open_detail(&mut screen, &db);

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.detail.is_none());
        assert!(
            !drawn(&mut screen).contains("Tried to log in as"),
            "the popup was still drawn"
        );
    }

    /// The popup is read-only, so it must not let a keystroke meant for it
    /// fall through and block an address behind it.
    #[test]
    fn a_key_with_the_popup_open_never_reaches_the_screen_underneath() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ssh_row(RowStatus::Pending);
        let mut message = None;
        open_detail(&mut screen, &db);

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('f')), &db, &mut message)
            .unwrap();

        assert_eq!(screen.filter, Filter::All, "the filter changed behind it");
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    fn screen_with_one_ua_row(user_agent: &str, status: RowStatus) -> Firewall {
        let mut screen = Firewall {
            ua_rows: vec![UaRow {
                user_agent: user_agent.to_string(),
                count: 9,
                status,
            }],
            focus: Focus::UserAgents,
            ..Default::default()
        };
        screen.ua_state.select(Some(0));
        screen
    }

    /// `i` used to answer "switch panels with Tab" here. Both panels
    /// inspect now; the two popups differ in what they can honestly say,
    /// not in whether they exist — see [`crate::uadetail`].
    #[test]
    fn inspecting_from_the_user_agent_panel_opens_a_user_agent_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ua_row(
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            RowStatus::Pending,
        );
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        assert!(
            matches!(screen.detail, Some(Detail::UserAgent(_))),
            "detail was: {:?}",
            screen.detail
        );
        assert_eq!(message, None, "nothing to explain any more");
    }

    /// The row's own verdict goes into the popup rather than being
    /// recomputed, so the two can never disagree about the same string.
    #[test]
    fn the_user_agent_popup_shows_the_string_and_the_row_s_own_status() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ua_row("curl/8.0", RowStatus::Blocked { until: None });
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        let drawn = drawn(&mut screen);

        assert!(drawn.contains("curl/8.0"), "drawn:\n{drawn}");
        assert!(drawn.contains("BLOCKED"), "drawn:\n{drawn}");
    }

    /// Escape has to close this popup too, or the screen backs out to the
    /// Dashboard with a detail still on it.
    #[test]
    fn esc_closes_the_user_agent_popup_instead_of_leaving_the_screen() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen_with_one_ua_row("curl/8.0", RowStatus::Pending);
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.detail.is_none());
    }

    /// An empty panel has nothing to inspect. Silently doing nothing is
    /// right; opening a popup about a row that is not there is not.
    #[test]
    fn inspecting_an_empty_user_agent_panel_does_nothing() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = Firewall {
            focus: Focus::UserAgents,
            ..Default::default()
        };
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        assert!(screen.detail.is_none());
    }

    /// The popup sizes itself to its widest line, so an unwrapped string
    /// this long would be a popup as wide as the client cared to make it
    /// — clamped to the terminal, and therefore cut off exactly where the
    /// interesting part usually is.
    #[test]
    fn a_very_long_user_agent_wraps_instead_of_running_off_the_popup() {
        let long = format!("Mozilla/5.0 (compatible; {}bot/1.0)", "x".repeat(200));

        let lines = wrapped(&long, UA_WRAP_CHARS);

        assert!(lines.len() > 1, "did not wrap: {lines:?}");
        for line in &lines {
            assert!(
                line.chars().count() <= UA_WRAP_CHARS,
                "line of {} chars: {line:?}",
                line.chars().count()
            );
        }
        assert_eq!(lines.concat(), long, "wrapping lost or added characters");
    }

    /// Slicing a multi-byte string by byte offset either panics or leaves
    /// mojibake; a user agent is whatever the client sent.
    #[test]
    fn wrapping_counts_characters_rather_than_bytes() {
        let text = "\u{e9}".repeat(100);

        let lines = wrapped(&text, 10);

        assert_eq!(lines.len(), 10);
        assert!(lines.iter().all(|line| line.chars().count() == 10));
    }

    /// The popup is clamped to the terminal and the paragraph does not
    /// scroll, so every line past the bottom is silently dropped — and
    /// the last line is the one saying how to get out.
    #[test]
    fn a_user_agent_matching_many_bots_keeps_the_way_out_on_screen() {
        let db = Db::open_in_memory().unwrap();
        db.register_source(&crate::db::Source {
            id: "many".to_string(),
            name: "A list with opinions".to_string(),
            url: "https://example.invalid/list".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        // Every one of these matches the string below.
        for i in 0..15 {
            db.upsert_bot(&crate::db::NewBot {
                slug: format!("crawler-{i}"),
                name: format!("Crawler {i}"),
                is_ai: false,
                is_search_engine: false,
                is_scanner: true,
                user_agent_pattern: format!("Crawler{i}/"),
                source_id: "many".to_string(),
            })
            .unwrap();
        }
        let ua: String = (0..15).map(|i| format!("Crawler{i}/1.0 ")).collect();
        let mut screen = screen_with_one_ua_row(&ua, RowStatus::Pending);
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('i')), &db, &mut message)
            .unwrap();

        // Every height from a cramped terminal up to one with room to
        // spare: the body is built against the space available, so the
        // closing line is not a matter of the popup happening to fit.
        for height in [14, 20, 30, 50] {
            let drawn = drawn_at(&mut screen, height);
            assert!(
                drawn.contains("Esc close"),
                "no way out at height {height}:\n{drawn}"
            );
            // At 14 rows there is genuinely no room for a verdict: the
            // body degrades to the status, the string and the count, and
            // that is the honest outcome rather than a popup with no way
            // out. From 20 up, the thing the popup was opened for shows.
            if height >= 20 {
                assert!(
                    drawn.contains("Crawler 0"),
                    "the first match was cut at height {height}:\n{drawn}"
                );
            }
            if height < 50 {
                assert!(
                    drawn.contains("and") && drawn.contains("more"),
                    "matches were cut without saying so at height {height}:\n{drawn}"
                );
            }
        }
    }

    #[test]
    fn wrapping_breaks_at_a_space_when_there_is_one() {
        let lines = wrapped("alpha beta gamma delta", 12);

        assert_eq!(lines, vec!["alpha beta ", "gamma delta"]);
    }
}
