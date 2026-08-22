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

/// The `(requests per second, burst)` pairs the Rate limit popup offers,
/// in the order it lists them after its "Off" row.
const RATE_LIMIT_PRESETS: [(i64, i64); 3] = [(5, 10), (10, 20), (30, 60)];

/// The popup title and its options, in the order [`SettingPopup::selected`]
/// indexes them. One function so the renderer and the key handler can never
/// disagree about how many options there are or what index means what.
fn setting_options(setting: NginxSetting) -> (&'static str, Vec<String>) {
    match setting {
        // Each option carries what it's *for*, not just its number: the
        // list would otherwise read as five interchangeable status codes,
        // and the difference matters most for clients caught by mistake.
        NginxSetting::Response => (
            "Response for blocked requests",
            BlockResponse::ALL
                .iter()
                .map(|r| format!("{:<24} {}", r.label(), r.rationale()))
                .collect(),
        ),
        NginxSetting::RobotsTxt => (
            "Serve a generated robots.txt",
            vec![
                "Off — leave /robots.txt alone".to_string(),
                "On — replace /robots.txt".to_string(),
            ],
        ),
        // Rates rather than a free-text number, for the same reason the
        // Dashboard's detector popup offers fixed TTLs: this screen has
        // one interaction pattern (pick one of N) and a numeric entry
        // field would be the only exception to it. The CLI takes any
        // value for anyone who needs one off this list.
        NginxSetting::RateLimit => (
            "Rate limit per client address",
            [
                "Off",
                "On — 5 req/s, burst 10",
                "On — 10 req/s, burst 20",
                "On — 30 req/s, burst 60",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
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
    /// Whether to generate and serve a `robots.txt`.
    RobotsTxt,
    /// Whether NGINX rate-limits requests per client address.
    RateLimit,
}

impl NginxSetting {
    const ALL: [NginxSetting; 3] = [
        NginxSetting::Response,
        NginxSetting::RobotsTxt,
        NginxSetting::RateLimit,
    ];

    fn label(self) -> &'static str {
        match self {
            NginxSetting::Response => "Block response",
            NginxSetting::RobotsTxt => "robots.txt",
            NginxSetting::RateLimit => "Rate limit",
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
    /// Whether [`Self::statuses`] still describes what is on disk.
    ///
    /// Cleared by every [`Self::refresh`] and set again only when a
    /// background check comes back. Without it, the tags would keep
    /// showing the previous answer through the moment that matters most —
    /// right after an apply, which is exactly when they change.
    statuses_current: bool,
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
    serve_robots_txt: bool,
    rate_limit_enabled: bool,
    rate_limit_rps: i64,
    rate_limit_burst: i64,
}

impl SiteSettings {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            sites: Vec::new(),
            statuses: Vec::new(),
            statuses_current: false,
            list_state: ListState::default(),
            popup: None,
            detail: None,
            alert: None,
            focus: Focus::default(),
            settings_state: ListState::default().with_selected(Some(0)),
            setting_popup: None,
            block_response: BlockResponse::default(),
            serve_robots_txt: false,
            rate_limit_enabled: false,
            rate_limit_rps: 0,
            rate_limit_burst: 0,
        }
    }

    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.block_response = db.get_block_response()?;
        self.serve_robots_txt = db.get_serve_robots_txt()?;
        self.rate_limit_enabled = db.get_rate_limit_enabled()?;
        self.rate_limit_rps = db.get_rate_limit_rps()?;
        self.rate_limit_burst = db.get_rate_limit_burst()?;
        self.sites = db.list_sites()?;
        // The status tags are *not* recomputed here: each one reads that
        // site's config file off disk and re-renders its block to compare,
        // which on a host with many sites is a visible pause every time
        // anything on this screen changes. `App` runs the check in the
        // background (`App::check_site_statuses`) and calls
        // `finish_status_check`; until then the tags say so.
        self.statuses_current = false;
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
                .enumerate()
                .map(|(index, site)| {
                    let status = self
                        .statuses_current
                        .then(|| self.statuses.get(index))
                        .flatten();
                    ListItem::new(Line::from(vec![
                        site.server_name.clone().bold(),
                        format!("  ({})", site.config_path).dim(),
                        Span::from("  "),
                        status_tag(status),
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
        let rate_limit_label = if self.rate_limit_enabled {
            format!(
                "{} req/s, burst {}",
                self.rate_limit_rps, self.rate_limit_burst
            )
        } else {
            "off".to_string()
        };
        let items: Vec<ListItem> = NginxSetting::ALL
            .iter()
            .map(|setting| {
                let value = match setting {
                    NginxSetting::Response => self.block_response.label(),
                    NginxSetting::RobotsTxt => {
                        if self.serve_robots_txt {
                            "generated"
                        } else {
                            "not managed"
                        }
                    }
                    NginxSetting::RateLimit => &rate_limit_label,
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
                    Line::from(label.clone()).reversed()
                } else {
                    Line::from(label.clone())
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

        if self.popup.is_some() {
            return self.handle_confirm_popup_key(key);
        }

        if self.setting_popup.is_some() {
            return self.handle_setting_popup_key(key, db, message);
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

        match self.focus {
            Focus::Settings => self.handle_settings_panel_key(key),
            Focus::Sites => self.handle_site_list_key(key, db),
        }
    }

    /// The Cancel/confirm popup shared by scan, apply-one and apply-all.
    /// Option 1 is always the affirmative one; anything else cancels.
    fn handle_confirm_popup_key(&mut self, key: KeyEvent) -> Result<KeyOutcome> {
        let Some(popup) = &mut self.popup else {
            unreachable!("dispatched on this popup")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                popup.selected = popup.selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                popup.selected = (popup.selected + 1).min(popup.options.len() - 1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let popup = self.popup.take().expect("checked above");
                if popup.selected != 1 {
                    return Ok(KeyOutcome::Consumed);
                }
                // Handed to `App` as a request rather than run here.
                // All three walk or rewrite files under /etc/nginx, and
                // doing that inline would block the event loop for as
                // long as it took — the same reason a reload was already
                // `App`'s job. `App` resolves what these need from `Db`,
                // performs the filesystem half on a background thread,
                // and hands the outcome back to `finish_site_action`.
                Ok(KeyOutcome::SiteAction(match popup.action {
                    PopupAction::Scan => SiteAction::Scan,
                    PopupAction::Apply(index) => SiteAction::Apply(index),
                    PopupAction::ApplyAll => SiteAction::ApplyAll,
                }))
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// The host-wide NGINX-setting popup. Its option count comes from
    /// `setting_options` rather than a literal, so the down-clamp stays
    /// right when a setting with a different number of choices is added.
    fn handle_setting_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(popup) = &mut self.setting_popup else {
            unreachable!("dispatched on this popup")
        };
        let option_count = setting_options(popup.setting).1.len();
        match key.code {
            KeyCode::Esc => {
                self.setting_popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                popup.selected = popup.selected.saturating_sub(1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                popup.selected = (popup.selected + 1).min(option_count - 1);
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                let popup = self.setting_popup.take().expect("checked above");
                self.commit_setting(db, &popup, message)?;
                // `Mutated`, never `ReloadNginx`: this only changes what
                // *would* be written. Nothing on disk moves until the
                // admin applies, which is exactly why every site's tag
                // flipping to STALE right now is the useful feedback.
                Ok(KeyOutcome::Mutated)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Keys for the NGINX settings panel, when it has focus.
    fn handle_settings_panel_key(&mut self, key: KeyEvent) -> Result<KeyOutcome> {
        Ok(match key.code {
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
        })
    }

    /// Keys for the site list, the screen's default focus. Every binding
    /// that existed before the settings panel was added lives here, which
    /// is why `Focus` defaults to `Sites`: none of them changed.
    fn handle_site_list_key(&mut self, key: KeyEvent, db: &Db) -> Result<KeyOutcome> {
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
            NginxSetting::Response => BlockResponse::ALL
                .iter()
                .position(|r| *r == self.block_response)
                .unwrap_or(0),
            NginxSetting::RobotsTxt => usize::from(self.serve_robots_txt),
            NginxSetting::RateLimit => {
                if !self.rate_limit_enabled {
                    0
                } else {
                    // Land on whichever preset matches the stored rate, or
                    // the nearest one — a rate set from the CLI that isn't
                    // on this list must still open as *on*, never as "Off".
                    RATE_LIMIT_PRESETS
                        .iter()
                        .position(|(rps, _)| *rps == self.rate_limit_rps)
                        .unwrap_or_else(|| {
                            RATE_LIMIT_PRESETS
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, (rps, _))| (rps - self.rate_limit_rps).abs())
                                .map(|(i, _)| i)
                                .unwrap_or(0)
                        })
                        + 1
                }
            }
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
                let response = BlockResponse::ALL
                    .get(popup.selected)
                    .copied()
                    .unwrap_or_default();
                if response == self.block_response {
                    return Ok(());
                }
                db.set_block_response(response)?;
                *message = Some(format!(
                    "Block response set to {} — apply (a/A) to update site configs",
                    response.label()
                ));
            }
            NginxSetting::RateLimit => {
                let chosen = popup
                    .selected
                    .checked_sub(1)
                    .and_then(|i| RATE_LIMIT_PRESETS.get(i).copied());
                match chosen {
                    None => {
                        if !self.rate_limit_enabled {
                            return Ok(());
                        }
                        db.set_rate_limit_enabled(false)?;
                        *message = Some(
                            "Rate limiting off — apply (a/A) to remove it from site configs"
                                .to_string(),
                        );
                    }
                    Some((rps, burst)) => {
                        db.set_rate_limit_rps(rps)?;
                        db.set_rate_limit_burst(burst)?;
                        db.set_rate_limit_enabled(true)?;
                        *message = Some(format!(
                            "Rate limit {rps} req/s, burst {burst} — apply (a/A) to write it"
                        ));
                    }
                }
            }
            NginxSetting::RobotsTxt => {
                let serve = popup.selected == 1;
                if serve == self.serve_robots_txt {
                    return Ok(());
                }
                db.set_serve_robots_txt(serve)?;
                *message = Some(if serve {
                    "robots.txt will be generated and served — apply (a/A) to write it. It \
                     replaces whatever each site serves at /robots.txt today."
                        .to_string()
                } else {
                    "robots.txt generation off — apply (a/A) to remove it from site configs"
                        .to_string()
                });
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

    /// The root this screen scans, for `App` to hand to a background
    /// `nginx::discover_sites`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves everything an apply needs out of `Db`, so the filesystem
    /// half can run where `Db` cannot go.
    ///
    /// `Apply(index)` plans one site, `ApplyAll` plans every one. Only
    /// `ApplyAll` plans removals: applying a *single* site must never
    /// delete a generated file, even when the feature that produced it is
    /// now off, because the other sites on this host still carry the
    /// directive that references it — and deleting a rate-limit zone out
    /// from under them makes NGINX refuse to load at all. Only a run that
    /// brings every site into line can safely clean up.
    pub fn plan_apply(&self, db: &Db, action: SiteAction) -> Result<ApplyPlan> {
        let indices: Vec<usize> = match action {
            SiteAction::Apply(index) => vec![index],
            SiteAction::ApplyAll => (0..self.sites.len()).collect(),
            SiteAction::Scan => Vec::new(),
        };
        let sites = indices
            .into_iter()
            .map(|index| {
                let site = &self.sites[index];
                Ok(PlannedSite {
                    server_name: site.server_name.clone(),
                    config_path: PathBuf::from(&site.config_path),
                    config: nginx::block_config_for_site(db, site.id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ApplyPlan {
            managed_writes: nginx::planned_managed_files(db)?,
            managed_removals: match action {
                SiteAction::ApplyAll => nginx::unused_managed_files(db)?,
                _ => Vec::new(),
            },
            sites,
            every_site: action == SiteAction::ApplyAll,
        })
    }

    /// Turns a finished background apply into the status message `App`
    /// shows and, when something went wrong, the alert this screen shows
    /// on top of it — a message on the Dashboard is no use to someone
    /// looking at Site settings.
    ///
    /// The returned bool is whether any file actually changed, which is
    /// what tells `App` whether NGINX needs reloading at all.
    pub fn finish_apply(&mut self, outcome: ApplyOutcome) -> (String, bool) {
        let ApplyOutcome {
            results,
            cleanup_error,
            every_site,
        } = outcome;
        let total = results.len();
        let mut applied = 0;
        let mut unchanged = 0;
        let mut failures = Vec::new();
        let mut any_permission_denied = false;
        for result in &results {
            match &result.changed {
                Ok(true) => applied += 1,
                Ok(false) => unchanged += 1,
                Err(err) => {
                    any_permission_denied |= result.permission_denied;
                    failures.push(format!("{}: {err}", result.server_name));
                }
            }
        }

        if !failures.is_empty() {
            let mut alert = if every_site {
                format!(
                    "Failed to apply rules to {} of {total} site(s):\n{}",
                    failures.len(),
                    failures.join("\n")
                )
            } else {
                format!("Failed to apply rules to {}", failures.join("\n"))
            };
            if any_permission_denied {
                alert.push_str("\n\nTry running as root.");
            }
            self.alert = Some(alert);
        } else if let Some(err) = cleanup_error {
            // Reported but not treated as undoing the apply: the config on
            // disk is valid either way, just with a stale file left behind.
            self.alert = Some(format!(
                "Applied, but cleaning up generated files failed:\n{err}"
            ));
        }

        let message = if every_site {
            format!(
                "Applied blocking rules to {applied} site(s), {unchanged} already up to date, {} failed",
                failures.len()
            )
        } else {
            let name = results
                .first()
                .map(|r| r.server_name.as_str())
                .unwrap_or("the site");
            match (applied, unchanged) {
                (1, _) => format!("Applied blocking rules to {name}"),
                (_, 1) => format!("{name} was already up to date"),
                _ => format!("Apply failed for {name}"),
            }
        };
        (message, applied > 0)
    }

    /// Stores freshly discovered sites and reports how many. Errors are
    /// returned as the message rather than propagated: a bad scan should
    /// report itself, not tear down the TUI on its way up through
    /// `App::run`.
    pub fn finish_scan(
        &self,
        db: &Db,
        sites: Result<Vec<nginx::DiscoveredSite>, String>,
    ) -> String {
        let root = self.root.display();
        let stored = sites.and_then(|sites| {
            for site in &sites {
                db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())
                    .map_err(|err| err.to_string())?;
            }
            Ok(sites.len())
        });
        match stored {
            Ok(count) => format!("Discovered {count} site(s) under {root}"),
            Err(err) => format!("Site scan failed: {err}"),
        }
    }
}

/// Resolves what a status check needs out of `Db`, so the per-site file
/// reads can happen off the main thread. Reuses [`PlannedSite`]: a status
/// check and an apply need exactly the same three things about a site.
impl SiteSettings {
    pub fn plan_status_check(&self, db: &Db) -> Result<Vec<PlannedSite>> {
        self.sites
            .iter()
            .map(|site| {
                Ok(PlannedSite {
                    server_name: site.server_name.clone(),
                    config_path: PathBuf::from(&site.config_path),
                    config: nginx::block_config_for_site(db, site.id)?,
                })
            })
            .collect()
    }

    /// Adopts a finished background status check.
    ///
    /// A check that no longer matches the site list is discarded: the list
    /// changed while it was out (a scan finished, say), and the check
    /// already running against the old one would put the wrong tag on the
    /// wrong row. Another check is always started with the new list.
    pub fn finish_status_check(&mut self, statuses: Vec<SiteApplyStatus>) {
        if statuses.len() != self.sites.len() {
            return;
        }
        self.statuses = statuses;
        self.statuses_current = true;
    }
}

/// Reads each planned site's config file and compares it against the block
/// that site's settings currently render to. Runs on a background thread
/// and touches no `Db`.
pub fn run_status_check(sites: &[PlannedSite]) -> Vec<SiteApplyStatus> {
    sites
        .iter()
        .map(|site| nginx::site_apply_status(&site.config_path, &site.server_name, &site.config))
        .collect()
}

/// Which filesystem action Site settings has asked `App` to carry out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteAction {
    /// Walk the NGINX config root and record what's there.
    Scan,
    /// Apply one site's rule to its own config file, by index into the
    /// screen's list.
    Apply(usize),
    /// Apply every site's.
    ApplyAll,
}

/// One site's share of an [`ApplyPlan`] — resolved from `Db`, so the write
/// itself needs nothing but this.
pub struct PlannedSite {
    pub server_name: String,
    pub config_path: PathBuf,
    pub config: nginx::BlockConfig,
}

/// Everything a background apply needs, with every `Db` read already done.
pub struct ApplyPlan {
    pub managed_writes: Vec<(PathBuf, String)>,
    /// Empty except for `ApplyAll`, and applied only if every site
    /// succeeded — see [`nginx::remove_unused_managed_files`] for why the
    /// ordering is load-bearing rather than tidy.
    pub managed_removals: Vec<PathBuf>,
    pub sites: Vec<PlannedSite>,
    pub every_site: bool,
}

/// What one site's write did.
#[derive(Clone, Debug)]
pub struct SiteResult {
    pub server_name: String,
    pub changed: Result<bool, String>,
    /// Kept separately because the error has been stringified by the time
    /// it crosses back, and "try running as root" is worth saying only for
    /// this one kind of failure.
    pub permission_denied: bool,
}

/// A finished background apply.
#[derive(Clone, Debug)]
pub struct ApplyOutcome {
    pub results: Vec<SiteResult>,
    pub cleanup_error: Option<String>,
    pub every_site: bool,
}

/// Performs a planned apply. Runs on a background thread and touches no
/// `Db`: everything it needs was resolved by
/// [`SiteSettings::plan_apply`].
///
/// A site's failure doesn't stop the others from being tried — a single
/// process either has root or doesn't, so one permission failure usually
/// means they all will, and reporting them together is more use than
/// stopping at the first.
pub fn run_apply(plan: ApplyPlan) -> ApplyOutcome {
    // Same ordering as the CLI's apply: a managed file has to exist before
    // a config that aliases it is reloaded.
    let managed = nginx::write_planned_managed_files(&plan.managed_writes);
    let results: Vec<SiteResult> = plan
        .sites
        .iter()
        .map(|site| {
            let outcome = managed.as_ref().map_err(clone_error).and_then(|()| {
                nginx::apply_block_for_site(&site.config_path, &site.server_name, &site.config)
                    .map_err(|err| (is_permission_denied(&err), err.to_string()))
            });
            SiteResult {
                server_name: site.server_name.clone(),
                changed: outcome
                    .as_ref()
                    .map(|changed| *changed)
                    .map_err(|(_, err)| err.clone()),
                permission_denied: outcome.err().is_some_and(|(denied, _)| denied),
            }
        })
        .collect();

    let all_ok = results.iter().all(|r| r.changed.is_ok());
    let cleanup_error = (all_ok && !plan.managed_removals.is_empty())
        .then(|| nginx::remove_planned_managed_files(&plan.managed_removals).err())
        .flatten()
        .map(|err| err.to_string());

    ApplyOutcome {
        results,
        cleanup_error,
        every_site: plan.every_site,
    }
}

/// `anyhow::Error` isn't `Clone`, and the managed-file write is shared by
/// every site in a plan, so its failure has to be reproducible per site.
fn clone_error(err: &anyhow::Error) -> (bool, String) {
    (is_permission_denied(err), err.to_string())
}

/// `None` means the check hasn't come back yet — the spinner rather than a
/// guess, since the previous answer is exactly what an apply just changed.
fn status_tag(status: Option<&SiteApplyStatus>) -> Span<'static> {
    match status {
        Some(SiteApplyStatus::UpToDate) => " [ UP TO DATE ] ".green(),
        Some(SiteApplyStatus::Stale) => " [ STALE ] ".yellow(),
        Some(SiteApplyStatus::NotFound) => " [ NOT FOUND ] ".dim(),
        None => format!(" [ {} CHECKING ] ", crate::tui::spinner_frame()).dim(),
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
    use crate::testing::blocked_bot;

    /// Carries out a [`SiteAction`] the way `App` does: plan against the
    /// database here, perform the filesystem half, then fold the outcome
    /// back into the screen. The popup used to do all of that inline, so
    /// tests below could press Enter and then look at the files; this
    /// keeps them able to, without pretending the split isn't there.
    fn perform(screen: &mut SiteSettings, db: &Db, action: SiteAction) -> (String, bool) {
        match action {
            SiteAction::Scan => {
                let sites = nginx::discover_sites(screen.root()).map_err(|err| err.to_string());
                (screen.finish_scan(db, sites), false)
            }
            _ => {
                let plan = screen
                    .plan_apply(db, action)
                    .expect("planning reads only Db");
                screen.finish_apply(run_apply(plan))
            }
        }
    }

    /// Reloads the screen *and* works out the status tags, the way `App`
    /// does across two turns of the event loop. `refresh` alone no longer
    /// reads the config files — see `SiteSettings::refresh`.
    fn refresh_with_statuses(screen: &mut SiteSettings, db: &Db) {
        screen.refresh(db).unwrap();
        let plan = screen.plan_status_check(db).unwrap();
        screen.finish_status_check(run_status_check(&plan));
    }

    /// Presses Enter on an open confirm popup and carries out whatever it
    /// asked for, returning the status message.
    fn confirm_popup(screen: &mut SiteSettings, db: &Db) -> String {
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), db, &mut None)
            .unwrap();
        let KeyOutcome::SiteAction(action) = outcome else {
            panic!("confirming should request a site action, got {outcome:?}");
        };
        perform(screen, db, action).0
    }

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Moves the open setting popup's selection to `response`, by
    /// searching rather than counting keypresses — the option list is
    /// `BlockResponse::ALL`, so adding an option would otherwise silently
    /// move these tests onto a different one and keep passing.
    fn select_response(screen: &mut SiteSettings, db: &Db, response: BlockResponse) {
        let target = BlockResponse::ALL
            .iter()
            .position(|r| *r == response)
            .expect("response should be offered");
        let mut message = None;
        while screen.setting_popup.as_ref().unwrap().selected != target {
            let current = screen.setting_popup.as_ref().unwrap().selected;
            let key = if current < target {
                KeyCode::Down
            } else {
                KeyCode::Up
            };
            screen
                .handle_key(KeyEvent::from(key), db, &mut message)
                .unwrap();
        }
    }

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
        assert!(content.contains("scan-sites"), "content was:\n{content}");
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
        assert!(content.contains("example.com"), "content was:\n{content}");
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
        let message = confirm_popup(&mut screen, &db);

        assert!(screen.popup.is_none());
        assert!(!db.list_sites().unwrap().is_empty());
        assert!(message.contains("Discovered"), "message was: {message}");
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
        let message = confirm_popup(&mut screen, &db);

        assert!(
            message.contains("Discovered 0 site(s)"),
            "message was: {message}"
        );
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
        use std::fs;

        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "badbot", "BadBot-UA");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(&path, "server {\n    server_name example.com;\n}\n").unwrap();
        db.upsert_site("example.com", path.to_str().unwrap())
            .unwrap();

        let mut screen = test_screen();
        refresh_with_statuses(&mut screen, &db);
        assert_eq!(screen.statuses, vec![SiteApplyStatus::Stale]);

        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Char('a')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Cancel -> Apply now
        let message = confirm_popup(&mut screen, &db);

        assert!(message.contains("Applied"), "message was: {message}");
        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("BadBot-UA"), "written was:\n{written}");

        refresh_with_statuses(&mut screen, &db);
        assert_eq!(screen.statuses, vec![SiteApplyStatus::UpToDate]);
    }

    #[test]
    fn render_shows_a_not_found_status_tag_for_an_unreachable_config_path() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let mut screen = test_screen();
        refresh_with_statuses(&mut screen, &db);

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
        assert!(content.contains("NOT FOUND"), "content was:\n{content}");
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
        confirm_popup(&mut screen, &db);

        let alert = screen.alert.as_ref().unwrap();
        assert!(
            alert.contains("Failed to apply rules to example.com"),
            "alert was:\n{alert}"
        );
        assert!(
            !alert.contains("Try running as root"),
            "alert was:\n{alert}"
        );
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
        blocked_bot(&db, "badbot", "BadBot-UA");
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
        confirm_popup(&mut screen, &db);

        let alert = screen.alert.as_ref().unwrap();
        assert!(alert.contains("Try running as root"), "alert was:\n{alert}");
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
        use std::fs;

        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "badbot", "BadBot-UA");
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
        refresh_with_statuses(&mut screen, &db);
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
        let message = confirm_popup(&mut screen, &db);

        assert!(
            message.contains("Applied blocking rules to 2"),
            "message was: {message}"
        );
        assert!(fs::read_to_string(&path_a).unwrap().contains("BadBot-UA"));
        assert!(fs::read_to_string(&path_b).unwrap().contains("BadBot-UA"));

        refresh_with_statuses(&mut screen, &db);
        assert_eq!(
            screen.statuses,
            vec![SiteApplyStatus::UpToDate, SiteApplyStatus::UpToDate]
        );
    }

    #[test]
    fn apply_all_reports_partial_failures_and_still_applies_the_rest() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, permission bits are unenforced");
            return;
        }

        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "badbot", "BadBot-UA");
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
        let message = confirm_popup(&mut screen, &db);

        // a.example still got applied even though b.example failed.
        assert!(fs::read_to_string(&path_a).unwrap().contains("BadBot-UA"));
        assert!(message.contains("1 failed"), "message was: {message}");
        let alert = screen.alert.as_ref().unwrap();
        assert!(alert.contains("b.example"), "alert was:\n{alert}");
        assert!(alert.contains("Try running as root"), "alert was:\n{alert}");
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
        select_response(&mut screen, &db, BlockResponse::Close);
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
        assert_eq!(
            screen.setting_popup.as_ref().unwrap().selected,
            BlockResponse::ALL
                .iter()
                .position(|r| *r == BlockResponse::Close)
                .unwrap()
        );

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
        confirm_popup(&mut screen, &db);
        refresh_with_statuses(&mut screen, &db);
        assert_eq!(screen.statuses[0], SiteApplyStatus::UpToDate);

        db.set_block_response(BlockResponse::Close).unwrap();
        refresh_with_statuses(&mut screen, &db);
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
        assert!(
            content.contains("NGINX settings"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("Block response"),
            "content was:\n{content}"
        );
        assert!(content.contains("444"), "content was:\n{content}");
    }

    // ---- popup key coverage ----
    //
    // These characterise the *existing* key handling rather than testing new
    // behaviour. Both popups on this screen accept Space as a synonym for
    // Enter and Up as navigation, and neither had a test for either — so a
    // refactor of `handle_key` could have silently dropped one and stayed
    // green. Written before that refactor, deliberately.

    #[test]
    fn up_navigates_within_the_scan_popup() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        assert_eq!(screen.popup.as_ref().unwrap().selected, 1);
        screen
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        assert_eq!(screen.popup.as_ref().unwrap().selected, 0);
    }

    #[test]
    fn space_confirms_the_scan_popup_like_enter() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Char('r')), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();

        assert!(
            screen.popup.is_none(),
            "Space should confirm, not be ignored"
        );
        let KeyOutcome::SiteAction(action) = outcome else {
            panic!("Space should request a scan, got {outcome:?}");
        };
        let message = perform(&mut screen, &db, action).0;
        assert!(message.contains("site(s)"), "message was: {message}");
    }

    #[test]
    fn up_navigates_within_the_nginx_setting_popup() {
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
        let opened_on = screen.setting_popup.as_ref().unwrap().selected;
        assert!(
            opened_on > 0,
            "should open on the stored value, not the first"
        );
        screen
            .handle_key(KeyEvent::from(KeyCode::Up), &db, &mut message)
            .unwrap();
        assert_eq!(
            screen.setting_popup.as_ref().unwrap().selected,
            opened_on - 1
        );
    }

    #[test]
    fn space_confirms_the_nginx_setting_popup_like_enter() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        let mut message = None;

        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), &db, &mut message)
            .unwrap();
        screen
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();
        assert!(screen.setting_popup.is_some(), "Space should open it");
        select_response(&mut screen, &db, BlockResponse::Close);
        screen
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();

        assert!(screen.setting_popup.is_none());
        assert_eq!(db.get_block_response().unwrap(), BlockResponse::Close);
    }
}
