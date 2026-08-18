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
        // Text settings are edited in their own popup and never reach
        // here; kept explicit rather than a `_` arm so a new setting is a
        // compile error.
        NginxSetting::PaymentPrice => ("Price for automated access", Vec::new()),
        NginxSetting::PaymentContact => ("Where to arrange access", Vec::new()),
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
    /// The price advertised in a 402 body. Only listed when the response
    /// is actually 402 — see [`NginxSetting::for_response`].
    PaymentPrice,
    /// Where to arrange access, advertised in the same 402 body.
    PaymentContact,
}

impl NginxSetting {
    /// The rows shown for `response`.
    ///
    /// The two payment rows appear only when the response is 402: they
    /// are meaningless otherwise, and a permanently-greyed pair of rows
    /// for a setting most installs never touch is worse than none.
    fn for_response(response: BlockResponse) -> Vec<NginxSetting> {
        let mut rows = vec![
            NginxSetting::Response,
            NginxSetting::RobotsTxt,
            NginxSetting::RateLimit,
        ];
        if response == BlockResponse::PaymentRequired {
            rows.push(NginxSetting::PaymentPrice);
            rows.push(NginxSetting::PaymentContact);
        }
        rows
    }

    /// Whether this setting is edited as free text rather than picked
    /// from a list.
    fn is_text(self) -> bool {
        matches!(
            self,
            NginxSetting::PaymentPrice | NginxSetting::PaymentContact
        )
    }

    fn label(self) -> &'static str {
        match self {
            NginxSetting::Response => "Block response",
            NginxSetting::RobotsTxt => "robots.txt",
            NginxSetting::RateLimit => "Rate limit",
            NginxSetting::PaymentPrice => "402 price",
            NginxSetting::PaymentContact => "402 contact",
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
    /// Index into `setting_options`, for the list-style settings.
    selected: usize,
    /// The value being typed, for the free-text ones. Carries the last
    /// validation error alongside it, same shape as Site detail's
    /// add-exempt-path popup.
    input: String,
    error: Option<String>,
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
    payment_price: String,
    payment_contact: String,
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
            list_state: ListState::default(),
            popup: None,
            detail: None,
            alert: None,
            focus: Focus::default(),
            settings_state: ListState::default().with_selected(Some(0)),
            setting_popup: None,
            block_response: BlockResponse::default(),
            payment_price: String::new(),
            payment_contact: String::new(),
            serve_robots_txt: false,
            rate_limit_enabled: false,
            rate_limit_rps: 0,
            rate_limit_burst: 0,
        }
    }

    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.block_response = db.get_block_response()?;
        self.payment_price = db.get_payment_price()?;
        self.payment_contact = db.get_payment_contact()?;
        self.serve_robots_txt = db.get_serve_robots_txt()?;
        self.rate_limit_enabled = db.get_rate_limit_enabled()?;
        self.rate_limit_rps = db.get_rate_limit_rps()?;
        self.rate_limit_burst = db.get_rate_limit_burst()?;
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
        let settings_height = self.settings_rows().len() as u16 + 2;
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
        let rate_limit_label = if self.rate_limit_enabled {
            format!(
                "{} req/s, burst {}",
                self.rate_limit_rps, self.rate_limit_burst
            )
        } else {
            "off".to_string()
        };
        let rows = self.settings_rows();
        let items: Vec<ListItem> = rows
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
                    NginxSetting::PaymentPrice => {
                        if self.payment_price.is_empty() {
                            "not set"
                        } else {
                            &self.payment_price
                        }
                    }
                    NginxSetting::PaymentContact => {
                        if self.payment_contact.is_empty() {
                            "not set"
                        } else {
                            &self.payment_contact
                        }
                    }
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

        if popup.setting.is_text() {
            let hint = "Enter to save, Esc to cancel — leave empty to clear";
            let mut lines = vec![
                Line::from(format!("{}\u{2588}", popup.input)),
                Line::from(hint).dim(),
            ];
            if let Some(error) = &popup.error {
                lines.push(Line::from(error.as_str()).red());
            }
            let width = hint.len().max(title.len()).max(popup.input.len()) as u16 + 4;
            let popup_area = centered_rect(width, lines.len() as u16 + 2, area);
            let paragraph = Paragraph::new(lines).block(Block::bordered().title(title));
            frame.render_widget(Clear, popup_area);
            frame.render_widget(paragraph, popup_area);
            return;
        }

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
            return self.handle_confirm_popup_key(key, db, message);
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
    fn handle_confirm_popup_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
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
                Ok(if wrote_nginx_config {
                    KeyOutcome::ReloadNginx
                } else {
                    KeyOutcome::Mutated
                })
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

        // Text entry owns every printable key, so it's handled before the
        // option-list branch — otherwise a `j` in a price would move a
        // selection instead of being typed.
        if popup.setting.is_text() {
            match key.code {
                KeyCode::Esc => {
                    self.setting_popup = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Backspace => {
                    popup.input.pop();
                    popup.error = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Char(c) => {
                    popup.input.push(c);
                    popup.error = None;
                    return Ok(KeyOutcome::Consumed);
                }
                KeyCode::Enter => {
                    let setting = popup.setting;
                    let value = popup.input.trim().to_string();
                    let (price, contact) = match setting {
                        NginxSetting::PaymentPrice => (value, self.payment_contact.clone()),
                        _ => (self.payment_price.clone(), value),
                    };
                    // Validation lives on `Db::set_payment_terms`, so the
                    // CLI and the TUI reject exactly the same values. The
                    // popup stays open with the reason shown.
                    if let Err(err) = db.set_payment_terms(&price, &contact) {
                        popup.error = Some(err.to_string());
                        return Ok(KeyOutcome::Consumed);
                    }
                    self.setting_popup = None;
                    *message = Some(format!(
                        "{} saved — apply (a/A) to write it into the site configs",
                        setting.label()
                    ));
                    return Ok(KeyOutcome::Mutated);
                }
                _ => return Ok(KeyOutcome::Consumed),
            }
        }
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
                if self.settings_state.selected().unwrap_or(0) + 1 < self.settings_rows().len() {
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
    /// The settings rows currently shown, which depend on the chosen
    /// response — see [`NginxSetting::for_response`].
    fn settings_rows(&self) -> Vec<NginxSetting> {
        NginxSetting::for_response(self.block_response)
    }

    fn open_setting_popup(&mut self) {
        let Some(setting) = self
            .settings_state
            .selected()
            .and_then(|i| self.settings_rows().get(i).copied())
        else {
            return;
        };
        if setting.is_text() {
            let input = match setting {
                NginxSetting::PaymentPrice => self.payment_price.clone(),
                _ => self.payment_contact.clone(),
            };
            self.setting_popup = Some(SettingPopup {
                setting,
                selected: 0,
                input,
                error: None,
            });
            return;
        }
        let selected = match setting {
            NginxSetting::Response => BlockResponse::ALL
                .iter()
                .position(|r| *r == self.block_response)
                .unwrap_or(0),
            NginxSetting::RobotsTxt => usize::from(self.serve_robots_txt),
            // Text settings returned above.
            NginxSetting::PaymentPrice | NginxSetting::PaymentContact => 0,
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
        self.setting_popup = Some(SettingPopup {
            setting,
            selected,
            input: String::new(),
            error: None,
        });
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
            NginxSetting::PaymentPrice | NginxSetting::PaymentContact => {
                unreachable!("text settings are committed in handle_setting_popup_key")
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
    /// Applying *one* site never removes a generated file, even when the
    /// feature that produced it is now off: the other sites on this host
    /// still carry the directive that references it, and deleting a
    /// rate-limit zone out from under them makes NGINX refuse to load at
    /// all. Only `apply_all`, which brings every site into line, can
    /// safely clean up.
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
        // Same ordering as the CLI's apply: the managed file has to exist
        // before a config that aliases it is reloaded.
        nginx::write_managed_files(db)?;
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
        // Deliberately not removing unused managed files here: `apply_all`
        // can partially fail, and deleting a rate-limit zone while some
        // site still references it makes NGINX refuse to load entirely.
        // The cleanup happens once every site succeeded, below.
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

        if failures.is_empty() {
            // Every site is now in line with the current settings, so a
            // file none of them references any more is safe to delete.
            // A failure here is reported but doesn't undo the apply: the
            // config on disk is valid either way, just with a stale file
            // left behind.
            if let Err(err) = nginx::remove_unused_managed_files(db) {
                self.alert = Some(format!(
                    "Applied, but cleaning up generated files failed:\n{err}"
                ));
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
    use crate::testing::blocked_bot;
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
        use std::fs;

        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "badbot", "BadBot-UA");
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
        assert!(written.contains("BadBot-UA"), "written was:\n{written}");

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
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

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
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

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
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        // a.example still got applied even though b.example failed.
        assert!(fs::read_to_string(&path_a).unwrap().contains("BadBot-UA"));
        assert!(message.unwrap().contains("1 failed"));
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
        screen
            .handle_key(KeyEvent::from(KeyCode::Char(' ')), &db, &mut message)
            .unwrap();

        assert!(
            screen.popup.is_none(),
            "Space should confirm, not be ignored"
        );
        assert!(message.unwrap().contains("site(s)"));
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

    // ---- 402 payment terms ----

    fn open_payment_row(screen: &mut SiteSettings, db: &Db, setting: NginxSetting) {
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Tab), db, &mut message)
            .unwrap();
        let target = screen
            .settings_rows()
            .iter()
            .position(|s| *s == setting)
            .expect("row should be shown");
        screen.settings_state.select(Some(target));
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), db, &mut message)
            .unwrap();
    }

    fn type_into(screen: &mut SiteSettings, db: &Db, text: &str) {
        let mut message = None;
        for c in text.chars() {
            screen
                .handle_key(KeyEvent::from(KeyCode::Char(c)), db, &mut message)
                .unwrap();
        }
    }

    /// The payment rows are meaningless for any other response, so they
    /// only appear once 402 is chosen.
    #[test]
    fn the_payment_rows_appear_only_for_the_402_response() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();
        assert!(!screen.settings_rows().contains(&NginxSetting::PaymentPrice));

        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        screen.refresh(&db).unwrap();
        assert!(screen.settings_rows().contains(&NginxSetting::PaymentPrice));
        assert!(screen
            .settings_rows()
            .contains(&NginxSetting::PaymentContact));
    }

    #[test]
    fn typing_a_price_stores_it() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        open_payment_row(&mut screen, &db, NginxSetting::PaymentPrice);
        type_into(&mut screen, &db, "USD 0.01 per request");
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.get_payment_price().unwrap(), "USD 0.01 per request");
        assert!(message.unwrap().contains("apply"));
    }

    /// The popup opens on the stored value, so editing doesn't mean
    /// retyping it.
    #[test]
    fn the_payment_popup_opens_on_the_current_value() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        db.set_payment_terms("EUR 500/month", "").unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        open_payment_row(&mut screen, &db, NginxSetting::PaymentPrice);
        assert_eq!(
            screen.setting_popup.as_ref().unwrap().input,
            "EUR 500/month"
        );
    }

    /// Same validation as the CLI, because both go through
    /// `Db::set_payment_terms` — and the popup stays open with the reason
    /// rather than silently discarding what was typed.
    #[test]
    fn a_price_that_would_corrupt_the_config_is_refused_in_place() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        open_payment_row(&mut screen, &db, NginxSetting::PaymentPrice);
        type_into(&mut screen, &db, "USD \"cheap\"");
        let mut message = None;
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert!(db.get_payment_price().unwrap().is_empty());
        let popup = screen
            .setting_popup
            .as_ref()
            .expect("popup should stay open");
        assert!(popup.error.as_ref().unwrap().contains("double quote"));
    }

    /// `j`/`k` are ordinary characters in a price.
    #[test]
    fn typing_j_into_a_price_does_not_navigate() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        open_payment_row(&mut screen, &db, NginxSetting::PaymentContact);
        type_into(&mut screen, &db, "jk@example.test");
        assert_eq!(
            screen.setting_popup.as_ref().unwrap().input,
            "jk@example.test"
        );
    }

    #[test]
    fn clearing_a_price_is_saving_an_empty_one() {
        let db = Db::open_in_memory().unwrap();
        db.set_block_response(BlockResponse::PaymentRequired)
            .unwrap();
        db.set_payment_terms("USD 1", "").unwrap();
        let mut screen = test_screen();
        screen.refresh(&db).unwrap();

        open_payment_row(&mut screen, &db, NginxSetting::PaymentPrice);
        let mut message = None;
        for _ in 0.."USD 1".len() {
            screen
                .handle_key(KeyEvent::from(KeyCode::Backspace), &db, &mut message)
                .unwrap();
        }
        screen
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert!(db.get_payment_price().unwrap().is_empty());
    }
}
