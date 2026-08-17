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

//! The Site settings screen: the NGINX sites `scan-sites` has discovered.
//! `r` triggers a Cancel/Scan-now confirmation popup (mirrors Bot settings'
//! source update popup, but runs inline rather than spawning a background
//! task: `nginx::discover_sites` is a local filesystem walk, not network
//! IO, so there's no need to keep it off the main thread). `Enter` on a
//! site row instead opens that site's [`site_detail::SiteDetail`] view —
//! category and per-bot overrides scoped to just that site. (`Enter` used
//! to trigger the scan popup too, before `SiteDetail` existed; it was moved
//! to `r` once Enter needed a per-row meaning, to avoid one key doing two
//! different things depending on whether the list happened to be empty.)
//!
//! `a` triggers a Cancel/Apply-now popup that applies just the selected
//! site's rule to its own config file (`nginx::apply_block_for_site`),
//! without touching any other site's block even if they share a file. `A`
//! does the same for every known site in one go (looping the same
//! per-site call, not a single bulk operation — see `apply_all`). Each row
//! also shows a status tag (`UP TO DATE`/`STALE`/`NOT FOUND`) computed by
//! re-reading that site's config file and comparing it against the
//! currently computed rule — this is a live disk check on every refresh,
//! not a cached flag, so it stays correct if the file is edited by hand.
//!
//! Above the site list sits a small "NGINX settings" panel holding the
//! host-wide knobs that shape *generated NGINX config text* (currently just
//! the block response, 403 vs 444). They live here rather than on the
//! Dashboard because that's where this project splits the two enforcement
//! planes: the Dashboard owns everything that ends up in the firewall
//! script, this screen owns everything that ends up in a site's config
//! file. `Tab` moves focus between the panel and the list. Changing any of
//! them re-renders the sentinel block differently, so every applied site
//! immediately flips to `STALE` — which is exactly the feedback wanted,
//! since nothing on disk changes until `a`/`A`.
//!
//! A failed apply opens a dismissible `alert` popup rather than relying on
//! `App`'s shared `message` field: that field is only ever rendered by
//! `Dashboard::render` (see `tui.rs`'s render dispatch), so a failure
//! surfaced through it while sitting on this screen would be completely
//! invisible — exactly why a real-world permission error here just looked
//! like "nothing happened, still STALE". The alert also special-cases a
//! permission-denied write (the single most likely real cause, since
//! `/etc/nginx` is normally root-owned) with a "Try running as root"
//! suggestion.

use crate::db::{BlockResponse, Db, Site};
use crate::nginx::{self, SiteApplyStatus};
use crate::tui::site_detail::SiteDetail;
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use std::path::{Path, PathBuf};

/// The popup title and its options, in the order [`SettingPopup::selected`]
/// indexes them. One function so the renderer and the key handler can never
/// disagree about how many options there are or what index means what.
fn setting_options(setting: NginxSetting) -> (&'static str, Vec<&'static str>) {
    match setting {
        NginxSetting::Response => (
            "Response for blocked requests",
            vec![
                BlockResponse::Forbidden.label(),
                BlockResponse::Close.label(),
            ],
        ),
    }
}

/// What confirming a popup actually does.
#[derive(Debug)]
enum PopupAction {
    Scan,
    /// Index into `SiteSettings::sites` of the site to apply.
    Apply(usize),
    /// Apply every known site's rule to its own config file.
    ApplyAll,
}

#[derive(Debug)]
struct Popup {
    action: PopupAction,
    options: Vec<&'static str>,
    selected: usize,
}

/// The host-wide NGINX-generation settings shown in this screen's top
/// panel, in display order. These live here rather than on the Dashboard
/// because they shape the text written into *site config files* — the
/// Dashboard owns everything that ends up in the firewall script instead.
///
/// Every row here changes the generated sentinel block, which means every
/// applied site goes `STALE` the moment one is changed (see
/// `nginx::site_apply_status`, which compares rendered block text). That's
/// intended and visible: the list below immediately shows what needs
/// re-applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NginxSetting {
    /// `BlockResponse` — 403 vs 444 for a matched request.
    Response,
}

impl NginxSetting {
    const ALL: [NginxSetting; 1] = [NginxSetting::Response];

    fn label(self) -> &'static str {
        match self {
            NginxSetting::Response => "Block response",
        }
    }
}

/// Which of this screen's two lists arrow keys currently move through.
/// Defaults to `Sites` so every pre-existing key (`Enter`/`a`/`A`/`r`)
/// keeps working exactly as before without first having to move focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    Settings,
    #[default]
    Sites,
}

/// The popup for editing one [`NginxSetting`]. A popup rather than a direct
/// Space-toggle because these are "choose one of N", the same reasoning the
/// Dashboard's category/geo-mode popups already use — and because changing
/// one invalidates every applied site, which deserves a deliberate
/// confirmation rather than a stray keypress.
#[derive(Debug, Clone)]
struct SettingPopup {
    setting: NginxSetting,
    selected: usize,
}

#[derive(Debug)]
pub struct SiteSettings {
    root: PathBuf,
    sites: Vec<Site>,
    /// Parallel to `sites`: whether each site's on-disk config currently
    /// matches its computed rule. Recomputed in full on every `refresh`.
    statuses: Vec<SiteApplyStatus>,
    list_state: ListState,
    popup: Option<Popup>,
    detail: Option<SiteDetail>,
    /// A dismissible error message from a failed apply, shown as its own
    /// popup (see the module doc comment for why this can't just go
    /// through `App`'s shared `message` field).
    alert: Option<String>,
    focus: Focus,
    settings_state: ListState,
    setting_popup: Option<SettingPopup>,
    block_response: BlockResponse,
}

impl SiteSettings {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            sites: Vec::new(),
            statuses: Vec::new(),
            list_state: ListState::default(),
            popup: None,
            detail: None,
            alert: None,
            focus: Focus::default(),
            settings_state: ListState::default().with_selected(Some(0)),
            setting_popup: None,
            block_response: BlockResponse::default(),
        }
    }

    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.block_response = db.get_block_response()?;
        self.sites = db.list_sites()?;
        self.statuses = self
            .sites
            .iter()
            .map(|site| {
                let config = nginx::block_config_for_site(db, site.id)?;
                Ok(nginx::site_apply_status(
                    Path::new(&site.config_path),
                    &site.server_name,
                    &config,
                ))
            })
            .collect::<Result<_>>()?;
        if !self.sites.is_empty() && self.list_state.selected().is_none() {
            self.list_state.select(Some(0));
        }
        if let Some(detail) = &mut self.detail {
            detail.refresh(db)?;
        }
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        if let Some(detail) = &mut self.detail {
            detail.render(frame, area, theme);
            return;
        }

        // The settings panel is fixed-height (one row per setting plus the
        // border) so the sites list — the screen's real content — keeps
        // every remaining line.
        let settings_height = NginxSetting::ALL.len() as u16 + 2;
        let [settings_area, sites_area] =
            Layout::vertical([Constraint::Length(settings_height), Constraint::Min(0)]).areas(area);
        self.render_settings(frame, settings_area, theme);
        let area = sites_area;

        if self.sites.is_empty() {
            let placeholder = Paragraph::new(format!(
                "No sites discovered yet. Press r to scan {} (or run `stop-bots scan-sites`).",
                self.root.display()
            ))
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title("Sites").fg(theme.accent()));
            frame.render_widget(placeholder, area);
        } else {
            let items: Vec<ListItem> = self
                .sites
                .iter()
                .zip(&self.statuses)
                .map(|(site, status)| {
                    ListItem::new(Line::from(vec![
                        site.server_name.clone().bold(),
                        format!("  ({})", site.config_path).dim(),
                        Span::from("  "),
                        status_tag(*status),
                    ]))
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::bordered()
                        .title("Sites — Enter for overrides, r to rescan, a to apply, A for all")
                        .fg(theme.accent()),
                )
                .highlight_style(ratatui::style::Style::new().reversed());
            frame.render_stateful_widget(list, area, &mut self.list_state);
        }

        if let Some(popup) = &self.popup {
            self.render_popup(frame, area, popup);
        }
        if let Some(popup) = &self.setting_popup {
            self.render_setting_popup(frame, area, popup);
        }
        if let Some(alert) = &self.alert {
            self.render_alert(frame, area, alert);
        }
    }

    /// The host-wide "how do we write NGINX config" panel above the site
    /// list. Only highlights its selection while it actually has focus, so
    /// there's never a second reversed row competing with the site list's.
    fn render_settings(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = NginxSetting::ALL
            .iter()
            .map(|setting| {
                let value = match setting {
                    NginxSetting::Response => self.block_response.label(),
                };
                ListItem::new(Line::from(vec![
                    format!("{:<18}", setting.label()).into(),
                    value.bold(),
                ]))
            })
            .collect();

        let mut list = List::new(items).block(
            Block::bordered()
                .title("NGINX settings — Tab to focus, Enter to change")
                .fg(theme.accent()),
        );
        if self.focus == Focus::Settings {
            list = list.highlight_style(ratatui::style::Style::new().reversed());
        }
        frame.render_stateful_widget(list, area, &mut self.settings_state);
    }

    fn render_setting_popup(&self, frame: &mut Frame, area: Rect, popup: &SettingPopup) {
        let (title, options) = setting_options(popup.setting);
        let content_width = options
            .iter()
            .map(|o| o.len())
            .max()
            .unwrap_or(0)
            .max(title.len());
        let popup_area = centered_rect(content_width as u16 + 4, options.len() as u16 + 2, area);
        let items: Vec<ListItem> = options
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let line = if i == popup.selected {
                    Line::from(*label).reversed()
                } else {
                    Line::from(*label)
                };
                ListItem::new(line)
            })
            .collect();
        let list = List::new(items).block(Block::bordered().title(title));
        frame.render_widget(Clear, popup_area);
        frame.render_widget(list, popup_area);
    }

    fn render_alert(&self, frame: &mut Frame, area: Rect, alert: &str) {
        const DISMISS_HINT: &str = "Press Enter or Esc to dismiss";
        let lines: Vec<&str> = alert.lines().collect();
        let content_width = lines
            .iter()
            .map(|l| l.len())
            .max()
            .unwrap_or(0)
            .max(DISMISS_HINT.len());
        let popup_area = centered_rect(content_width as u16 + 4, lines.len() as u16 + 4, area);

        let mut text: Vec<Line> = lines.into_iter().map(Line::from).collect();
        text.push(Line::from(""));
        text.push(Line::from(DISMISS_HINT).dim());

        let paragraph = Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("Apply failed").red());
        frame.render_widget(Clear, popup_area);
        frame.render_widget(paragraph, popup_area);
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: &Popup) {
        let title = match popup.action {
            PopupAction::Scan => format!("Scan {}?", self.root.display()),
            PopupAction::Apply(index) => {
                format!("Apply blocking rules to {}?", self.sites[index].server_name)
            }
            PopupAction::ApplyAll => {
                format!("Apply blocking rules to all {} site(s)?", self.sites.len())
            }
        };
        let content_width = popup
            .options
            .iter()
            .map(|o| o.len())
            .max()
            .unwrap_or(0)
            .max(title.len());
        let popup_area = centered_rect(
            content_width as u16 + 4,
            popup.options.len() as u16 + 2,
            area,
        );
        let items: Vec<ListItem> = popup
            .options
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let line = if i == popup.selected {
                    Line::from(*label).reversed()
                } else {
                    Line::from(*label)
                };
                ListItem::new(line)
            })
            .collect();
        let list = List::new(items).block(Block::bordered().title(title));
        frame.render_widget(Clear, popup_area);
        frame.render_widget(list, popup_area);
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if self.alert.is_some() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc | KeyCode::Char(' ')) {
                self.alert = None;
            }
            return Ok(KeyOutcome::Consumed);
        }

        if let Some(detail) = &mut self.detail {
            let outcome = detail.handle_key(key, db, message)?;
            return Ok(match outcome {
                // The detail view backs out to the site list, not all the
                // way to the Dashboard — same nested-back-out shape
                // bot_settings.rs's own `Focus::Search` already uses.
                KeyOutcome::Back => {
                    self.detail = None;
                    KeyOutcome::Consumed
                }
                other => other,
            });
        }

        if let Some(popup) = &mut self.popup {
            match key.code {
                KeyCode::Esc => {
                    self.popup = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    popup.selected = popup.selected.saturating_sub(1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    popup.selected = (popup.selected + 1).min(popup.options.len() - 1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let popup = self.popup.take().expect("checked above");
                    if popup.selected != 1 {
                        return Ok(KeyOutcome::Consumed);
                    }
                    let (result_message, wrote_nginx_config) = match popup.action {
                        PopupAction::Scan => (self.scan(db), false),
                        PopupAction::Apply(index) => self.apply_site(db, index),
                        PopupAction::ApplyAll => self.apply_all(db),
                    };
                    *message = Some(result_message);
                    // Neither of these necessarily writes to the db
                    // (applying only touches nginx files), but `Mutated` is
                    // also how every screen's state gets refreshed —
                    // needed here so the status tags reflect the files we
                    // just wrote. An apply that actually changed a file
                    // asks `App` to reload NGINX on top of that (see
                    // `KeyOutcome::ReloadNginx`'s doc comment for why that
                    // happens there and not inline here).
                    return Ok(if wrote_nginx_config {
                        KeyOutcome::ReloadNginx
                    } else {
                        KeyOutcome::Mutated
                    });
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }

        if let Some(popup) = &mut self.setting_popup {
            let option_count = setting_options(popup.setting).1.len();
            match key.code {
                KeyCode::Esc => {
                    self.setting_popup = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    popup.selected = popup.selected.saturating_sub(1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    popup.selected = (popup.selected + 1).min(option_count - 1);
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let popup = self.setting_popup.take().expect("checked above");
                    self.commit_setting(db, &popup, message)?;
                    // `Mutated`, never `ReloadNginx`: this only changes what
                    // *would* be written. Nothing on disk moves until the
                    // admin applies, which is exactly why every site's tag
                    // flipping to STALE right now is the useful feedback.
                    return Ok(KeyOutcome::Mutated);
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }

        // Tab moves focus between this screen's two lists rather than
        // cycling screens — the same narrower override Dynamic Protection
        // already makes for its own two panels (see `App::handle_key_event`,
        // which only sees Tab when the active screen returns `Ignored`).
        // Screen cycling stays available here via Right/`l`/BackTab's
        // aliases and the direct `d`/`b`/`s`/`p` jumps. BackTab is treated
        // as the same toggle rather than a reverse one: with exactly two
        // lists there's no distinct "previous".
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.focus = match self.focus {
                Focus::Sites => Focus::Settings,
                Focus::Settings => Focus::Sites,
            };
            return Ok(KeyOutcome::Consumed);
        }

        if self.focus == Focus::Settings {
            return Ok(match key.code {
                KeyCode::Esc => KeyOutcome::Back,
                KeyCode::Up | KeyCode::Char('k') => {
                    self.settings_state.select_previous();
                    KeyOutcome::Consumed
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.settings_state.selected().unwrap_or(0) + 1 < NginxSetting::ALL.len() {
                        self.settings_state.select_next();
                    }
                    KeyOutcome::Consumed
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.open_setting_popup();
                    KeyOutcome::Consumed
                }
                _ => KeyOutcome::Ignored,
            });
        }

        match key.code {
            KeyCode::Esc => Ok(KeyOutcome::Back),
            KeyCode::Up | KeyCode::Char('k') => {
                self.list_state.select_previous();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.list_state.select_next();
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char('r') => {
                self.popup = Some(Popup {
                    action: PopupAction::Scan,
                    options: vec!["Cancel", "Scan now"],
                    selected: 0,
                });
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char('a') => {
                if let Some(index) = self.list_state.selected() {
                    if index < self.sites.len() {
                        self.popup = Some(Popup {
                            action: PopupAction::Apply(index),
                            options: vec!["Cancel", "Apply now"],
                            selected: 0,
                        });
                    }
                }
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char('A') => {
                if !self.sites.is_empty() {
                    self.popup = Some(Popup {
                        action: PopupAction::ApplyAll,
                        options: vec!["Cancel", "Apply now"],
                        selected: 0,
                    });
                }
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.open_detail(db)?;
                Ok(KeyOutcome::Consumed)
            }
            _ => Ok(KeyOutcome::Ignored),
        }
    }

    /// Opens the edit popup for the focused NGINX setting, pre-selecting
    /// whatever that setting is currently set to — so confirming without
    /// moving is a no-op rather than a silent change to the first option.
    fn open_setting_popup(&mut self) {
        let Some(setting) = self
            .settings_state
            .selected()
            .and_then(|i| NginxSetting::ALL.get(i).copied())
        else {
            return;
        };
        let selected = match setting {
            NginxSetting::Response => match self.block_response {
                BlockResponse::Forbidden => 0,
                BlockResponse::Close => 1,
            },
        };
        self.setting_popup = Some(SettingPopup { setting, selected });
    }

    /// Persists a confirmed setting popup and reports what changed. The
    /// message spells out the consequence ("sites need re-applying")
    /// because nothing on disk changes here — without it, a user could
    /// reasonably read the new value in the panel as already in effect.
    fn commit_setting(
        &mut self,
        db: &Db,
        popup: &SettingPopup,
        message: &mut Option<String>,
    ) -> Result<()> {
        match popup.setting {
            NginxSetting::Response => {
                let response = if popup.selected == 1 {
                    BlockResponse::Close
                } else {
                    BlockResponse::Forbidden
                };
                if response == self.block_response {
                    return Ok(());
                }
                db.set_block_response(response)?;
                *message = Some(format!(
                    "Block response set to {} — apply (a/A) to update site configs",
                    response.label()
                ));
            }
        }
        Ok(())
    }

    /// Opens the selected site's detail view, loading its current overrides
    /// from `db`. A no-op if nothing's selected (e.g. the list is empty).
    fn open_detail(&mut self, db: &Db) -> Result<()> {
        let Some(selected) = self.list_state.selected() else {
            return Ok(());
        };
        let Some(site) = self.sites.get(selected) else {
            return Ok(());
        };
        let mut detail = SiteDetail::new(site.clone());
        detail.refresh(db)?;
        self.detail = Some(detail);
        Ok(())
    }

    /// Discovers sites under `self.root` and stores them in `db`, returning
    /// a status message either way. Errors (an unreadable/missing root, a
    /// malformed config) are caught here rather than propagated: this runs
    /// synchronously inside `handle_key`, whose `Result` bubbles all the way
    /// up through `App::run` — letting a bad scan through would tear down
    /// the whole TUI instead of just reporting the failure.
    fn scan(&self, db: &Db) -> String {
        match self.run_scan(db) {
            Ok(count) => format!("Discovered {count} site(s) under {}", self.root.display()),
            Err(err) => format!("Site scan failed: {err}"),
        }
    }

    fn run_scan(&self, db: &Db) -> Result<usize> {
        let sites = nginx::discover_sites(&self.root)?;
        for site in &sites {
            db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
        }
        Ok(sites.len())
    }

    /// Applies just `self.sites[index]`'s currently computed rule to its
    /// own config file, returning a status message either way (consumed by
    /// the caller for `App`'s shared `message` field — see the module doc
    /// comment for why that's not enough on its own) alongside whether the
    /// file actually changed, so the caller knows whether to ask `App` to
    /// reload NGINX. On failure, also sets `self.alert` so the error is
    /// actually visible on this screen; a permission-denied write gets an
    /// extra, actionable suggestion.
    fn apply_site(&mut self, db: &Db, index: usize) -> (String, bool) {
        let server_name = self.sites[index].server_name.clone();
        match self.run_apply_site(db, index) {
            Ok(true) => (format!("Applied blocking rules to {server_name}"), true),
            Ok(false) => (format!("{server_name} was already up to date"), false),
            Err(err) => {
                let mut alert = format!("Failed to apply rules to {server_name}:\n{err}");
                if is_permission_denied(&err) {
                    alert.push_str("\n\nTry running as root.");
                }
                self.alert = Some(alert);
                (format!("Apply failed for {server_name}"), false)
            }
        }
    }

    fn run_apply_site(&self, db: &Db, index: usize) -> Result<bool> {
        let site = &self.sites[index];
        let config = nginx::block_config_for_site(db, site.id)?;
        nginx::apply_block_for_site(Path::new(&site.config_path), &site.server_name, &config)
    }

    /// Applies every known site's own rule to its own config file — the
    /// same per-site `apply_block_for_site` call as `apply_site`, just
    /// looped over every site rather than a single bulk nginx-file
    /// rewrite. A site's failure doesn't stop the others from being tried;
    /// any failures are collected into one alert afterwards (with the same
    /// "Try running as root" suggestion if any of them was a permission
    /// error — the common case, since a single process either has root or
    /// doesn't, so one failure usually means they all will). The returned
    /// bool is whether *any* site's file actually changed, same meaning as
    /// `apply_site`'s.
    fn apply_all(&mut self, db: &Db) -> (String, bool) {
        let total = self.sites.len();
        let mut applied = 0;
        let mut unchanged = 0;
        let mut failures = Vec::new();
        let mut any_permission_denied = false;

        for index in 0..total {
            match self.run_apply_site(db, index) {
                Ok(true) => applied += 1,
                Ok(false) => unchanged += 1,
                Err(err) => {
                    any_permission_denied |= is_permission_denied(&err);
                    failures.push(format!("{}: {err}", self.sites[index].server_name));
                }
            }
        }

        if !failures.is_empty() {
            let mut alert = format!(
                "Failed to apply rules to {} of {total} site(s):\n{}",
                failures.len(),
                failures.join("\n")
            );
            if any_permission_denied {
                alert.push_str("\n\nTry running as root.");
            }
            self.alert = Some(alert);
        }

        (
            format!(
                "Applied blocking rules to {applied} site(s), {unchanged} already up to date, {} failed",
                failures.len()
            ),
            applied > 0,
        )
    }
}

fn status_tag(status: SiteApplyStatus) -> Span<'static> {
    match status {
        SiteApplyStatus::UpToDate => " [ UP TO DATE ] ".green(),
        SiteApplyStatus::Stale => " [ STALE ] ".yellow(),
        SiteApplyStatus::NotFound => " [ NOT FOUND ] ".dim(),
    }
}

/// Whether `err` (or anything in its causal chain — `fs::write`'s error is
/// wrapped in context by `nginx::apply_block_for_site`) is an OS
/// permission-denied error, e.g. writing to a root-owned `/etc/nginx` file
/// without being root.
fn is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn test_screen() -> SiteSettings {
        SiteSettings::new(PathBuf::from("tests/fixtures/nginx"))
    }

    #[test]
    fn refresh_loads_sites_and_selects_first() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        assert_eq!(screen.sites.len(), 1);
        assert_eq!(screen.list_state.selected(), Some(0));
    }

    #[test]
    fn escape_backs_out_to_dashboard() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Back);
    }

    #[test]
    fn render_with_no_sites_shows_a_hint_instead_of_an_empty_list() {
        let mut screen = test_screen();
        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("scan-sites"));
    }

    #[test]
    fn render_with_sites_shows_server_name_and_config_path() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("example.com"));
    }

    #[test]
    fn r_opens_a_scan_confirmation_popup_defaulting_to_cancel() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();

        let popup = screen.popup.as_ref().unwrap();
        assert_eq!(popup.selected, 0); // Cancel
    }

    #[test]
    fn r_opens_the_scan_popup_even_with_no_sites_yet() {
        // The empty-state placeholder must not swallow the popup: this is
        // exactly the bootstrap case the popup exists for.
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();

        assert!(screen.popup.is_some());
    }

    #[test]
    fn confirming_cancel_does_not_scan() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
        assert!(db.list_sites().unwrap().is_empty());
    }

    #[test]
    fn confirming_scan_now_discovers_and_stores_sites() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Cancel -> Scan now
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(screen.popup.is_none());
        assert!(!db.list_sites().unwrap().is_empty());
        assert!(message.unwrap().contains("Discovered"));
    }

    #[test]
    fn scanning_a_missing_root_finds_nothing_without_crashing() {
        // `nginx::discover_sites` silently skips walk errors (see its own
        // doc comment), so a missing root isn't actually an error path
        // today — but `handle_key`'s `Result` still must not propagate one
        // if that ever changes, hence `scan` catching errors at all. What's
        // observable today: this never panics or errors, and just reports
        // zero sites found.
        let db = Db::open_in_memory().unwrap();
        let mut screen = SiteSettings::new(PathBuf::from("/nonexistent/does-not-exist"));
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(message.unwrap().contains("Discovered 0 site(s)"));
        assert!(db.list_sites().unwrap().is_empty());
    }

    #[test]
    fn enter_on_a_site_opens_its_detail_view() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.detail.is_some());
    }

    #[test]
    fn enter_with_no_sites_is_a_noop_not_a_crash() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.detail.is_none());
    }

    #[test]
    fn escape_inside_a_site_detail_closes_it_without_backing_out_to_the_dashboard() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert!(screen.detail.is_some());

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.detail.is_none());
    }

    #[test]
    fn a_opens_an_apply_confirmation_popup_defaulting_to_cancel() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();

        let popup = screen.popup.as_ref().unwrap();
        assert!(matches!(popup.action, PopupAction::Apply(0)));
        assert_eq!(popup.selected, 0); // Cancel
    }

    #[test]
    fn a_with_no_sites_is_a_noop_not_a_crash() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
    }

    #[test]
    fn confirming_apply_now_writes_the_rule_and_the_status_tag_updates() {
        use crate::db::{BotStatus, NewBot, Source};
        use std::fs;

        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&NewBot {
            slug: "badbot".to_string(),
            name: "badbot".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "BadBot-UA".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();
        db.set_bot_status("badbot", BotStatus::Blocked).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(&path, "server {\n    server_name example.com;\n}\n").unwrap();
        db.upsert_site("example.com", path.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        assert_eq!(screen.statuses, vec![SiteApplyStatus::Stale]);

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Cancel -> Apply now
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::ReloadNginx);
        assert!(message.unwrap().contains("Applied"));
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("BadBot-UA"));

        screen.refresh(&db).unwrap();
        assert_eq!(screen.statuses, vec![SiteApplyStatus::UpToDate]);
    }

    #[test]
    fn render_shows_a_not_found_status_tag_for_an_unreachable_config_path() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("NOT FOUND"));
    }

    #[test]
    fn apply_failure_opens_a_dismissible_alert() {
        // The site's config file was removed on disk since it was scanned
        // (a plain "no such file" NotFound, no permission error involved):
        // `apply_block_for_site` fails, and that failure must be visible
        // right here, not silently swallowed into the Dashboard-only
        // `message` field.
        let db = Db::open_in_memory().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.conf");
        db.upsert_site("example.com", path.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let alert = screen.alert.as_ref().unwrap();
        assert!(alert.contains("Failed to apply rules to example.com"));
        assert!(!alert.contains("Try running as root"));
    }

    #[test]
    fn apply_failure_from_a_permission_error_suggests_running_as_root() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses file permission bits, so this check would never
        // actually fail to write and the test would be meaningless there.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits are unenforced");
            return;
        }

        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&crate::db::Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&crate::db::NewBot {
            slug: "badbot".to_string(),
            name: "badbot".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "BadBot-UA".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();
        db.set_bot_status("badbot", crate::db::BotStatus::Blocked)
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readonly.conf");
        // A non-empty rule is expected (the bot above is globally blocked),
        // so `apply_block_for_site` will actually attempt a write here —
        // if the file already had nothing to change, it would return
        // `Ok(false)` without ever touching the filesystem, and the
        // permission error this test exists to trigger would never fire.
        fs::write(&path, "server {\n    server_name example.com;\n}\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&path, perms).unwrap();
        db.upsert_site("example.com", path.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let alert = screen.alert.as_ref().unwrap();
        assert!(alert.contains("Try running as root"));
    }

    #[test]
    fn an_open_alert_swallows_other_keys_until_dismissed() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        screen.alert = Some("Failed to apply rules to example.com".to_string());
        let mut message = None;

        // An unrelated key neither dismisses the alert nor falls through
        // to normal list navigation.
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.alert.is_some());

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.alert.is_none());
    }

    #[test]
    fn shift_a_opens_an_apply_all_confirmation_popup_defaulting_to_cancel() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();
        db.upsert_site("localhost", "/etc/nginx/conf.d/server.conf")
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('A')), &db, &mut message)
            .unwrap();

        let popup = screen.popup.as_ref().unwrap();
        assert!(matches!(popup.action, PopupAction::ApplyAll));
        assert_eq!(popup.selected, 0); // Cancel
    }

    #[test]
    fn shift_a_with_no_sites_is_a_noop_not_a_crash() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Char('A')), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Consumed);
        assert!(screen.popup.is_none());
    }

    #[test]
    fn confirming_apply_all_applies_every_site_and_updates_their_status_tags() {
        use crate::db::{BotStatus, NewBot, Source};
        use std::fs;

        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&NewBot {
            slug: "badbot".to_string(),
            name: "badbot".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "BadBot-UA".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();
        db.set_bot_status("badbot", BotStatus::Blocked).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.example");
        let path_b = dir.path().join("b.example");
        fs::write(&path_a, "server {\n    server_name a.example;\n}\n").unwrap();
        fs::write(&path_b, "server {\n    server_name b.example;\n}\n").unwrap();
        db.upsert_site("a.example", path_a.to_str().unwrap())
            .unwrap();
        db.upsert_site("b.example", path_b.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        assert_eq!(
            screen.statuses,
            vec![SiteApplyStatus::Stale, SiteApplyStatus::Stale]
        );

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('A')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Cancel -> Apply now
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::ReloadNginx);
        assert!(message.unwrap().contains("Applied blocking rules to 2"));
        assert!(fs::read_to_string(&path_a).unwrap().contains("BadBot-UA"));
        assert!(fs::read_to_string(&path_b).unwrap().contains("BadBot-UA"));

        screen.refresh(&db).unwrap();
        assert_eq!(
            screen.statuses,
            vec![SiteApplyStatus::UpToDate, SiteApplyStatus::UpToDate]
        );
    }

    #[test]
    fn apply_all_reports_partial_failures_and_still_applies_the_rest() {
        use crate::db::{BotStatus, NewBot, Source};
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits are unenforced");
            return;
        }

        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&NewBot {
            slug: "badbot".to_string(),
            name: "badbot".to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "BadBot-UA".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();
        db.set_bot_status("badbot", BotStatus::Blocked).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.example");
        let path_b = dir.path().join("b.example");
        fs::write(&path_a, "server {\n    server_name a.example;\n}\n").unwrap();
        fs::write(&path_b, "server {\n    server_name b.example;\n}\n").unwrap();
        let mut perms = fs::metadata(&path_b).unwrap().permissions();
        perms.set_mode(0o444);
        fs::set_permissions(&path_b, perms).unwrap();
        db.upsert_site("a.example", path_a.to_str().unwrap())
            .unwrap();
        db.upsert_site("b.example", path_b.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('A')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        // a.example still got applied even though b.example failed.
        assert!(fs::read_to_string(&path_a).unwrap().contains("BadBot-UA"));
        assert!(message.unwrap().contains("1 failed"));
        let alert = screen.alert.as_ref().unwrap();
        assert!(alert.contains("b.example"));
        assert!(alert.contains("Try running as root"));
    }

    // ---- NGINX settings panel (Tab-focused, host-wide) ----

    #[test]
    fn tab_moves_focus_between_the_site_list_and_the_settings_panel() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        assert_eq!(screen.focus, Focus::Sites);
        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        assert_eq!(screen.focus, Focus::Settings);
        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        assert_eq!(screen.focus, Focus::Sites);
    }

    #[test]
    fn changing_the_block_response_persists_it_and_reports_the_apply_step() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.get_block_response().unwrap(), BlockResponse::Close);
        let message = message.unwrap();
        assert!(message.contains("444"), "message was: {message}");
        assert!(message.contains("apply"), "message was: {message}");
    }

    /// The popup opens on the *current* value, so confirming straight away
    /// never silently rewrites the setting to the first option.
    #[test]
    fn the_setting_popup_preselects_the_current_value() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::Close).unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(screen.setting_popup.as_ref().unwrap().selected, 1);

        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        assert_eq!(db.get_block_response().unwrap(), BlockResponse::Close);
        // Unchanged, so nothing worth telling the user about.
        assert!(message.is_none());
    }

    #[test]
    fn escape_closes_the_setting_popup_without_changing_anything() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();

        assert!(screen.setting_popup.is_none());
        assert_eq!(db.get_block_response().unwrap(), BlockResponse::Forbidden);
    }

    /// Changing a host-wide NGINX setting must make every already-applied
    /// site read as STALE — that tag is the only signal that the config on
    /// disk no longer matches what the tool would write.
    #[test]
    fn changing_the_response_marks_an_applied_site_stale() {
        use std::fs;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.example");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let db = Db::open_in_memory().unwrap();
        db.upsert_site("a.example", path.to_str().unwrap()).unwrap();
        db.block_user_agent("BadBot-UA").unwrap();

        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        // Apply with the default 403, then confirm it reads as up to date.
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        screen.refresh(&db).unwrap();
        assert_eq!(screen.statuses[0], SiteApplyStatus::UpToDate);

        db.set_block_response(BlockResponse::Close).unwrap();
        screen.refresh(&db).unwrap();
        assert_eq!(screen.statuses[0], SiteApplyStatus::Stale);
    }

    #[test]
    fn render_shows_the_nginx_settings_panel_with_the_current_value() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::Close).unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(content.contains("NGINX settings"));
        assert!(content.contains("Block response"));
        assert!(content.contains("444"));
    }
}
