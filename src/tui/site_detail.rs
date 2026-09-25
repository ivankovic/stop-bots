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

//! The per-site detail view, opened from NGINX (`Enter` on a site
//! row) — a scoped-down mirror of Bot settings' shape (see that file), just
//! editing one site's overrides instead of the global defaults. Two panels:
//! "Category overrides" (top, 3 rows, mirrors the Dashboard's category
//! list) and "Bot overrides" (bottom, a search box exactly like Bot
//! settings' Bot details panel). Both popups have a third state Bot
//! settings' don't need at the global level: "no override at all", since
//! here that's a real, meaningfully different choice from "explicitly
//! Allowed"/"explicitly Blocked".
//!
//! `handle_key` returns the same [`crate::tui::KeyOutcome`] every screen
//! uses; `Nginx` (the parent) translates a `Back` from here into
//! closing this view rather than exiting to the Dashboard — the same
//! nested-back-out shape `bot_settings.rs`'s `Focus::Search` already uses
//! for its own Escape handling, one level deeper.

use crate::db::{Bot, BotStatus, Category, Db, Policy, Site, SiteBotOverride};
use crate::nginx::RequestRule;
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, ListState, Paragraph},
    Frame,
};

/// The rows of the "Category overrides" list, in display order.
const CATEGORIES: [Category; 3] = [Category::Scanner, Category::Search, Category::Ai];

fn category_index(category: Category) -> usize {
    CATEGORIES
        .iter()
        .position(|&c| c == category)
        .expect("CATEGORIES lists every Category variant")
}

/// Whether `path` is usable as an exemption prefix, or why not.
///
/// Rejected loudly at entry rather than stored and silently ignored: the
/// generated regex is anchored with `^`, so a value without a leading `/`
/// could never match, and an exemption that never fires is invisible —
/// the admin sees a configured exemption and blocked traffic, with
/// nothing to connect the two.
///
/// A literal `"` is rejected for the same reason `nginx::is_embeddable`
/// rejects it in a user-agent pattern: it would terminate the quoted
/// config string early and corrupt the whole file.
fn validate_exempt_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("Enter a path".to_string());
    }
    if !path.starts_with('/') {
        return Err("Must start with /".to_string());
    }
    if path.contains('"') {
        return Err("Cannot contain a double quote".to_string());
    }
    if path.contains(char::is_whitespace) {
        return Err("Cannot contain spaces".to_string());
    }
    Ok(())
}

/// One row of the exemptions panel: a path, and the user agent it is
/// limited to — `None` for a plain exemption, which covers every client.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Exemption {
    path: String,
    user_agent: Option<String>,
}

/// Reads the add-exemption field: `/blog`, or `/remote.php/dav/ okhttp` to
/// exempt only clients whose user agent contains `okhttp`.
///
/// The first space ends the path. A path can hold none (see
/// [`validate_exempt_path`]), so the split is unambiguous, and the user
/// agent after it may have spaces of its own (`Jellyfin Android`).
fn parse_exemption(input: &str) -> Result<Exemption, String> {
    let input = input.trim();
    let (path, user_agent) = match input.split_once(char::is_whitespace) {
        Some((path, rest)) => (path, Some(rest)),
        None => (input, None),
    };
    validate_exempt_path(path)?;
    let user_agent = user_agent
        .map(|ua| {
            crate::db::validate_exemption_user_agent(ua).map_err(|err| format!("User agent: {err}"))
        })
        .transpose()?;
    Ok(Exemption {
        path: path.to_string(),
        user_agent,
    })
}

/// Which panel keyboard input currently goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Categories,
    /// The per-site path-exemption list: one row per exempt path plus a
    /// fixed "+ Add a path" row at index 0, exactly like the Dashboard's
    /// country list. Reached by `Down` past the last category, left by
    /// `Up` above its first row — the same no-dedicated-focus-key flow.
    Exemptions,
    /// The per-site NGINX options list — currently one row, the HTTP/1.x
    /// rejection toggle. Its own panel rather than a row in the
    /// categories list above: a category is Allowed/Blocked for *bots*,
    /// and this is a protocol-level rule that applies to every client.
    Options,
    Search,
}

/// What's being changed in the open popup, and the options to cycle through.
#[derive(Debug, Clone)]
enum PopupTarget {
    Category(Category),
    Bot(i64, String),
    /// Text entry for a new exempt path. Carries the partially-typed
    /// value and the last validation error, same shape as the Dashboard's
    /// add-country popup.
    AddExemption {
        input: String,
        error: Option<String>,
    },
}

#[derive(Debug)]
struct Popup {
    target: PopupTarget,
    options: Vec<&'static str>,
    selected: usize,
}

#[derive(Debug)]
pub struct SiteDetail {
    site: Site,
    ai_default: Policy,
    search_default: Policy,
    scanner_default: Policy,
    /// This site's override for each of [`CATEGORIES`], indexed the same
    /// way (`category_index`). `None` means "inherit the global default".
    category_overrides: [Option<Policy>; 3],
    categories_state: ListState,
    bots: Vec<Bot>,
    bot_overrides: Vec<SiteBotOverride>,
    /// Which request-shape rules are on for this site.
    request_rules: Vec<RequestRule>,
    options_state: ListState,
    exemptions: Vec<Exemption>,
    exemptions_state: ListState,
    query: String,
    results_state: ListState,
    focus: Focus,
    popup: Option<Popup>,
}

impl SiteDetail {
    pub fn new(site: Site) -> Self {
        let mut categories_state = ListState::default();
        categories_state.select(Some(0));
        Self {
            site,
            ai_default: Policy::default(),
            search_default: Policy::default(),
            scanner_default: Policy::default(),
            category_overrides: [None; 3],
            categories_state,
            bots: Vec::new(),
            bot_overrides: Vec::new(),
            request_rules: Vec::new(),
            options_state: ListState::default().with_selected(Some(0)),
            exemptions: Vec::new(),
            exemptions_state: ListState::default().with_selected(Some(0)),
            query: String::new(),
            results_state: ListState::default(),
            focus: Focus::default(),
            popup: None,
        }
    }

    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.ai_default = db.get_category_default(Category::Ai)?;
        self.search_default = db.get_category_default(Category::Search)?;
        self.scanner_default = db.get_category_default(Category::Scanner)?;
        for &category in &CATEGORIES {
            self.category_overrides[category_index(category)] =
                db.get_site_category_override(self.site.id, category)?;
        }
        self.bots = db.list_bots()?;
        self.bot_overrides = db.site_bot_overrides(self.site.id)?;
        self.request_rules = crate::nginx::site_request_rules(db, self.site.id)?;
        let plain = db
            .site_path_exemptions(self.site.id)?
            .into_iter()
            .map(|path| Exemption {
                path,
                user_agent: None,
            });
        let scoped = db
            .site_agent_exemptions(self.site.id)?
            .into_iter()
            .map(|e| Exemption {
                path: e.path,
                user_agent: Some(e.user_agent),
            });
        self.exemptions = plain.chain(scoped).collect();
        // Removing a path shrinks the list; without this the selection
        // could be left pointing past the new last row until the next
        // arrow key re-clamped it.
        let max_row = self.exemptions.len(); // +1 for the Add row, -1 for 0-indexing
        if self
            .exemptions_state
            .selected()
            .is_some_and(|s| s > max_row)
        {
            self.exemptions_state.select(Some(max_row));
        }
        Ok(())
    }

    fn global_default(&self, category: Category) -> Policy {
        match category {
            Category::Scanner => self.scanner_default,
            Category::Search => self.search_default,
            Category::Ai => self.ai_default,
        }
    }

    fn effective_category(&self, category: Category) -> Policy {
        self.category_overrides[category_index(category)].unwrap_or(self.global_default(category))
    }

    fn site_bot_override(&self, bot_id: i64) -> Option<Policy> {
        self.bot_overrides
            .iter()
            .find(|o| o.bot_id == bot_id)
            .map(|o| o.policy)
    }

    /// Bots whose name or slug contains the current search query
    /// (case-insensitive). Empty until something is typed, same
    /// never-dump-the-whole-list rule as `bot_settings.rs`.
    fn filtered_bots(&self) -> Vec<&Bot> {
        if self.query.is_empty() {
            return Vec::new();
        }
        let query = self.query.to_lowercase();
        self.bots
            .iter()
            .filter(|bot| {
                bot.name.to_lowercase().contains(&query) || bot.slug.to_lowercase().contains(&query)
            })
            .collect()
    }

    fn reset_results_selection(&mut self) {
        if self.filtered_bots().is_empty() {
            self.results_state.select(None);
        } else {
            self.results_state.select(Some(0));
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let [categories_area, options_area, exemptions_area, details_area] = Layout::vertical([
            Constraint::Length(5),
            // Two border lines plus one row per request rule.
            Constraint::Length(RequestRule::ALL.len() as u16 + 2),
            // Two border lines plus the Add row, plus up to three paths
            // before it starts scrolling — enough to see a typical setup
            // at a glance without starving the bot search below it.
            Constraint::Length(6),
            Constraint::Min(3),
        ])
        .areas(area);

        self.render_categories(frame, categories_area, theme);
        self.render_options(frame, options_area, theme);
        self.render_exemptions(frame, exemptions_area, theme);
        self.render_details(frame, details_area, theme);

        if let Some(popup) = &self.popup {
            self.render_popup(frame, area, popup, theme);
        }
    }

    fn render_categories(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = CATEGORIES
            .iter()
            .map(|&category| ListItem::new(self.category_line(category)))
            .collect();

        let focused = self.focus == Focus::Categories;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel(
                format!("{} \u{2014} categories", self.site.server_name),
                focused,
                theme,
            )),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.categories_state);
    }

    fn render_options(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        // One row per rule, each with its own tag and its own caveat.
        // Deliberately not one "strict requests" switch: if these hid
        // behind a single toggle and someone's monitoring broke, they'd
        // have no way to tell which rule did it.
        let items: Vec<ListItem> = RequestRule::ALL
            .iter()
            .map(|rule| {
                let on = self.request_rules.contains(rule);
                ListItem::new(Line::from(vec![
                    Span::from(format!("{:<20}", rule.label())),
                    policy_tag(if on { Policy::Blocked } else { Policy::Allowed }),
                    Span::from(if on {
                        format!("  {}", rule.caveat())
                    } else {
                        String::new()
                    })
                    .dim(),
                ]))
            })
            .collect();

        let focused = self.focus == Focus::Options;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Request rules", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.options_state);
    }

    fn render_exemptions(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> =
            std::iter::once(ListItem::new(Line::from("+ Add an exempt path").italic()))
                .chain(self.exemptions.iter().map(|exemption| {
                    let scope = match &exemption.user_agent {
                        None => "bots allowed here".to_string(),
                        Some(user_agent) => format!("only for {user_agent}"),
                    };
                    ListItem::new(Line::from(vec![
                        Span::from(format!("{:<24}", exemption.path)),
                        Span::from(scope).dim(),
                    ]))
                }))
                .collect();

        let focused = self.focus == Focus::Exemptions;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Path exemptions", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.exemptions_state);
    }

    fn category_line(&self, category: Category) -> Line<'static> {
        let overridden = self.category_overrides[category_index(category)];
        let effective = overridden.unwrap_or(self.global_default(category));
        let mut line = vec![Span::from(format!("{:<14}", category_label(category)))];
        line.push(policy_tag(effective));
        let annotation = if overridden.is_some() {
            " (site override)"
        } else {
            " (system)"
        };
        line.push(Span::from(annotation).dim());
        Line::from(line)
    }

    fn render_details(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let focused = self.focus == Focus::Search;
        let block = crate::tui::panel("Bot overrides", focused, theme);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [search_area, results_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
        frame.render_widget(Paragraph::new(self.search_line()), search_area);

        let matches = self.filtered_bots();
        if matches.is_empty() {
            // No third "type something to search" hint here when the query
            // is empty and there are bots to search: `search_line()` above
            // already renders "Press / to search bots by name" in that
            // case, so a second hint would just repeat it.
            let hint = if !self.query.is_empty() {
                Some(format!("No bots match \"{}\".", self.query))
            } else if self.bots.is_empty() {
                Some("No bots yet — download some from Bot settings first.".to_string())
            } else {
                None
            };
            if let Some(hint) = hint {
                frame.render_widget(Paragraph::new(hint).dim(), results_area);
            }
            return;
        }

        let items: Vec<ListItem> = matches
            .iter()
            .map(|bot| ListItem::new(self.bot_line(bot)))
            .collect();
        let list = crate::tui::select_in(List::new(items), focused, theme);
        frame.render_stateful_widget(list, results_area, &mut self.results_state);
    }

    /// The footer's key hints for the focused panel.
    pub fn hints(&self) -> crate::tui::Hints {
        if self.popup.is_some() {
            return ("Popup", vec![("Enter", "confirm"), ("Esc", "cancel")]);
        }
        let common = [("Tab", "next panel"), ("Esc", "back to sites")];
        let (name, own): (&'static str, Vec<(&'static str, &'static str)>) = match self.focus {
            Focus::Categories => (
                "Categories",
                vec![("\u{2191}\u{2193}", "move"), ("Enter", "override")],
            ),
            Focus::Options => (
                "Request rules",
                vec![("\u{2191}\u{2193}", "move"), ("Enter", "change")],
            ),
            Focus::Exemptions => (
                "Exemptions",
                vec![("\u{2191}\u{2193}", "move"), ("Enter", "add/remove")],
            ),
            Focus::Search => (
                "Bot overrides",
                vec![
                    ("type", "filter"),
                    ("\u{2191}\u{2193}", "move"),
                    ("Enter", "override"),
                ],
            ),
        };
        (name, own.into_iter().chain(common).collect())
    }

    fn bot_line(&self, bot: &Bot) -> Line<'static> {
        let site_override = self.site_bot_override(bot.id);
        let effective = effective_bot_policy(
            bot,
            site_override,
            self.effective_category(Category::Ai),
            self.effective_category(Category::Search),
            self.effective_category(Category::Scanner),
        );
        let mut line = vec![Span::from(format!("  {:<22}", bot.name))];
        line.push(policy_tag(effective));
        // Three states here, one more than bot_settings.rs's global-only
        // version: which of the three cascade tiers is actually driving
        // this bot's effective policy on this site.
        let annotation = if site_override.is_some() {
            " (site override)"
        } else if bot.status != BotStatus::Default {
            " (global override)"
        } else {
            " (default)"
        };
        line.push(Span::from(annotation).dim());
        Line::from(line)
    }

    fn search_line(&self) -> Line<'static> {
        match self.focus {
            Focus::Search => format!("/{}\u{2588}", self.query).into(),
            // Categories and Exemptions render the search box identically:
            // it's inactive in both, and which of the two other panels
            // happens to have focus says nothing about the search state.
            _ if self.query.is_empty() => {
                Line::from(Span::from("Press / to search bots by name").dim())
            }
            _ => Line::from(Span::from(format!("/{}", self.query)).dim()),
        }
    }

    fn render_popup(&self, frame: &mut Frame, area: Rect, popup: &Popup, theme: Theme) {
        let title = match &popup.target {
            PopupTarget::Category(category) => {
                format!("{} on {}", category_label(*category), self.site.server_name)
            }
            PopupTarget::Bot(_, slug) => format!("{slug} on {}", self.site.server_name),
            PopupTarget::AddExemption { .. } => {
                format!("Exempt a path on {}", self.site.server_name)
            }
        };

        if let PopupTarget::AddExemption { input, error } = &popup.target {
            let hint = "Path prefix, e.g. /blog — Enter to add, Esc to cancel";
            let scope_hint = "Follow it with a user agent to exempt only that client";
            let mut lines = vec![
                Line::from(format!("{input}\u{2588}")),
                Line::from(Span::from(hint).dim()),
                Line::from(Span::from(scope_hint).dim()),
            ];
            if let Some(error) = error {
                lines.push(Line::from(Span::from(error.clone()).red()));
            }
            let width = hint.chars().count().max(scope_hint.len()).max(title.len()) as u16 + 4;
            let popup_area = centered_rect(width, lines.len() as u16 + 2, area);
            let paragraph = Paragraph::new(lines).block(crate::tui::popup(title, theme));
            frame.render_widget(Clear, popup_area);
            frame.render_widget(paragraph, popup_area);
            return;
        }

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
        let list = List::new(items).block(crate::tui::popup(title, theme));
        frame.render_widget(Clear, popup_area);
        frame.render_widget(list, popup_area);
    }

    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        // Text entry owns every printable key, so it has to be handled
        // before the option-list branch below — otherwise typing "j" in a
        // path would move the (nonexistent) selection instead.
        if matches!(
            self.popup,
            Some(Popup {
                target: PopupTarget::AddExemption { .. },
                ..
            })
        ) {
            return self.handle_add_exemption_key(key, db, message);
        }

        if self.popup.is_some() {
            return self.handle_option_popup_key(key, db, message);
        }

        // Tab walks the panels top to bottom (BackTab bottom to top);
        // Up/Down still flow across them for hands that never learned it.
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            const ORDER: [Focus; 4] = [
                Focus::Categories,
                Focus::Options,
                Focus::Exemptions,
                Focus::Search,
            ];
            let at = ORDER.iter().position(|f| *f == self.focus).unwrap_or(0);
            let next = if key.code == KeyCode::Tab {
                (at + 1) % ORDER.len()
            } else {
                (at + ORDER.len() - 1) % ORDER.len()
            };
            self.focus = ORDER[next];
            match self.focus {
                Focus::Categories if self.categories_state.selected().is_none() => {
                    self.categories_state.select(Some(0));
                }
                Focus::Options if self.options_state.selected().is_none() => {
                    self.options_state.select(Some(0));
                }
                Focus::Exemptions if self.exemptions_state.selected().is_none() => {
                    self.exemptions_state.select(Some(0));
                }
                _ => {}
            }
            return Ok(KeyOutcome::Consumed);
        }

        match self.focus {
            Focus::Categories => match key.code {
                // Backs out to the site list; `Nginx` intercepts
                // this `Back` rather than letting it exit to the Dashboard.
                KeyCode::Esc => return Ok(KeyOutcome::Back),
                KeyCode::Up | KeyCode::Char('k') => self.categories_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.categories_state.selected() == Some(CATEGORIES.len() - 1) {
                        self.focus = Focus::Options;
                        self.options_state.select(Some(0));
                    } else {
                        self.categories_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.open_category_popup(),
                KeyCode::Char('/') => self.focus = Focus::Search,
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Options => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Back),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.options_state.selected() == Some(0) {
                        self.focus = Focus::Categories;
                        self.categories_state.select(Some(CATEGORIES.len() - 1));
                    } else {
                        self.options_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.options_state.selected().unwrap_or(0) + 1 < RequestRule::ALL.len() {
                        self.options_state.select_next();
                    } else {
                        self.focus = Focus::Exemptions;
                        self.exemptions_state.select(Some(0));
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return self.toggle_request_rule(db, message);
                }
                KeyCode::Char('/') => self.focus = Focus::Search,
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Exemptions => match key.code {
                KeyCode::Esc => return Ok(KeyOutcome::Back),
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.exemptions_state.selected() == Some(0) {
                        self.focus = Focus::Options;
                        self.options_state.select(Some(0));
                    } else {
                        self.exemptions_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.exemptions_state.selected().unwrap_or(0) < self.exemptions.len() {
                        self.exemptions_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return self.activate_exemption_row(db, message)
                }
                KeyCode::Char('/') => self.focus = Focus::Search,
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Search => match key.code {
                // Leaves the search box rather than backing all the way
                // out — same nested-back-out shape bot_settings.rs uses.
                KeyCode::Esc => self.focus = Focus::Categories,
                KeyCode::Up => self.results_state.select_previous(),
                KeyCode::Down => self.results_state.select_next(),
                KeyCode::Enter => self.open_bot_popup(),
                KeyCode::Backspace => {
                    self.query.pop();
                    self.reset_results_selection();
                }
                KeyCode::Char(c) => {
                    self.query.push(c);
                    self.reset_results_selection();
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
        }
        Ok(KeyOutcome::Consumed)
    }

    /// The add-exempt-path text field.
    ///
    /// Matched before the option-list popup below and before any focus
    /// handling: it owns every printable key, so a `j` typed into a path
    /// must reach the field rather than move a selection. There is a
    /// regression test for exactly that.
    fn handle_add_exemption_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(Popup {
            target: PopupTarget::AddExemption { input, error },
            ..
        }) = &mut self.popup
        else {
            unreachable!("dispatched on this popup")
        };
        match key.code {
            KeyCode::Esc => {
                self.popup = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Backspace => {
                input.pop();
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Char(c) => {
                input.push(c);
                *error = None;
                Ok(KeyOutcome::Consumed)
            }
            KeyCode::Enter => {
                let exemption = match parse_exemption(input) {
                    Ok(exemption) => exemption,
                    Err(err) => {
                        *error = Some(err);
                        return Ok(KeyOutcome::Consumed);
                    }
                };
                self.popup = None;
                let path = &exemption.path;
                let site = &self.site.server_name;
                *message = Some(match &exemption.user_agent {
                    None => {
                        db.add_site_path_exemption(self.site.id, path)?;
                        format!("{path} exempted on {site} — apply (a/A) to write it")
                    }
                    Some(user_agent) => {
                        db.add_site_agent_exemption(self.site.id, path, user_agent)?;
                        format!(
                            "{path} exempted on {site} for {user_agent} — apply (a/A) to write it"
                        )
                    }
                });
                Ok(KeyOutcome::Mutated)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// The category and per-bot override popups: pick one of three.
    fn handle_option_popup_key(
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
                *message = Some(self.apply_popup(db, popup)?);
                Ok(KeyOutcome::Mutated)
            }
            _ => Ok(KeyOutcome::Consumed),
        }
    }

    /// Flips the selected request rule for this site.
    ///
    /// A direct toggle rather than a popup: it's a single reversible
    /// change, the same reasoning the Dashboard's country list uses. The
    /// message carries the rule's caveat because the consequences show up
    /// somewhere other than this screen — and, for the TLS-only rules,
    /// that they apply to HTTPS blocks only.
    fn toggle_request_rule(&mut self, db: &Db, message: &mut Option<String>) -> Result<KeyOutcome> {
        let Some(rule) = self
            .options_state
            .selected()
            .and_then(|i| RequestRule::ALL.get(i).copied())
        else {
            return Ok(KeyOutcome::Consumed);
        };
        let enable = !self.request_rules.contains(&rule);
        db.set_site_request_rule(self.site.id, rule.id(), enable)?;
        *message = Some(if enable {
            format!(
                "{}: blocking {} — {}. Apply (a/A) to write it",
                self.site.server_name,
                rule.label(),
                rule.caveat()
            )
        } else {
            format!(
                "{}: {} allowed again — apply (a/A) to write it",
                self.site.server_name,
                rule.label()
            )
        });
        Ok(KeyOutcome::Mutated)
    }

    /// Enter on the exemptions list: row 0 opens the add-path popup, any
    /// other row removes that path directly. Removal is a single
    /// reversible action, so it needs no confirmation — the same reasoning
    /// the Dashboard's country list already uses.
    fn activate_exemption_row(
        &mut self,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let Some(selected) = self.exemptions_state.selected() else {
            return Ok(KeyOutcome::Consumed);
        };
        if selected == 0 {
            self.popup = Some(Popup {
                target: PopupTarget::AddExemption {
                    input: String::new(),
                    error: None,
                },
                options: Vec::new(),
                selected: 0,
            });
            return Ok(KeyOutcome::Consumed);
        }
        let Some(Exemption { path, user_agent }) = self.exemptions.get(selected - 1).cloned()
        else {
            return Ok(KeyOutcome::Consumed);
        };
        let site = &self.site.server_name;
        *message = Some(match user_agent {
            None => {
                db.remove_site_path_exemption(self.site.id, &path)?;
                format!("{path} no longer exempt on {site} — apply (a/A) to write it")
            }
            Some(user_agent) => {
                db.remove_site_agent_exemption(self.site.id, &path, &user_agent)?;
                format!(
                    "{path} no longer exempt on {site} for {user_agent} — apply (a/A) to write it"
                )
            }
        });
        Ok(KeyOutcome::Mutated)
    }

    fn open_category_popup(&mut self) {
        let Some(selected) = self.categories_state.selected() else {
            return;
        };
        let Some(&category) = CATEGORIES.get(selected) else {
            return;
        };
        let selected_option = match self.category_overrides[category_index(category)] {
            None => 0,
            Some(Policy::Allowed) => 1,
            Some(Policy::Blocked) => 2,
        };
        self.popup = Some(Popup {
            target: PopupTarget::Category(category),
            options: vec!["Use system default", "Allowed", "Blocked"],
            selected: selected_option,
        });
    }

    fn open_bot_popup(&mut self) {
        let Some(selected) = self.results_state.selected() else {
            return;
        };
        let matches = self.filtered_bots();
        let Some(bot) = matches.get(selected) else {
            return;
        };
        let selected_option = match self.site_bot_override(bot.id) {
            None => 0,
            Some(Policy::Allowed) => 1,
            Some(Policy::Blocked) => 2,
        };
        self.popup = Some(Popup {
            target: PopupTarget::Bot(bot.id, bot.slug.clone()),
            options: vec!["Use site & system default", "Allowed", "Blocked"],
            selected: selected_option,
        });
    }

    fn apply_popup(&self, db: &Db, popup: Popup) -> Result<String> {
        let policy = match popup.selected {
            0 => None,
            1 => Some(Policy::Allowed),
            _ => Some(Policy::Blocked),
        };
        match popup.target {
            // Handled entirely in `handle_key`'s text-entry branch, which
            // never reaches here. Kept explicit rather than a `_` arm so a
            // new target variant is a compile error.
            PopupTarget::AddExemption { .. } => {
                unreachable!("add-exemption is committed in handle_key")
            }
            PopupTarget::Category(category) => {
                db.set_site_category_override(self.site.id, category, policy)?;
                let label = policy.map_or("use system default".to_string(), |p| format!("{p:?}"));
                Ok(format!(
                    "{} on {} set to {label}",
                    category_label(category),
                    self.site.server_name
                ))
            }
            PopupTarget::Bot(bot_id, slug) => {
                db.set_site_bot_override(self.site.id, bot_id, policy)?;
                let label = policy.map_or("use site & system default".to_string(), |p| {
                    format!("{p:?}")
                });
                Ok(format!(
                    "{slug} on {} set to {label}",
                    self.site.server_name
                ))
            }
        }
    }
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Scanner => "Scanners",
        Category::Search => "Search Bots",
        Category::Ai => "AI Bots",
    }
}

fn policy_tag(policy: Policy) -> Span<'static> {
    match policy {
        Policy::Allowed => " [ ALLOWED ] ".green(),
        Policy::Blocked => " [ BLOCKED ] ".red(),
    }
}

/// Mirrors `bot_settings.rs::effective_policy`, extended with a site
/// override at the top: `ai`/`search`/`scanner` here are already the
/// *effective* (site-override-or-global) values for this site, so this is
/// otherwise identical to the global cascade.
fn effective_bot_policy(
    bot: &Bot,
    site_override: Option<Policy>,
    ai: Policy,
    search: Policy,
    scanner: Policy,
) -> Policy {
    if let Some(policy) = site_override {
        return policy;
    }
    match bot.status {
        BotStatus::Allowed => Policy::Allowed,
        BotStatus::Blocked => Policy::Blocked,
        BotStatus::Default => {
            let blocked = (bot.is_ai && ai == Policy::Blocked)
                || (bot.is_search_engine && search == Policy::Blocked)
                || (bot.is_scanner && scanner == Policy::Blocked);
            if blocked {
                Policy::Blocked
            } else {
                Policy::Allowed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{NewBot, Source};

    fn test_db() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "test".to_string(),
            name: "Test".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db
    }

    fn test_site(db: &Db) -> Site {
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();
        db.list_sites().unwrap().into_iter().next().unwrap()
    }

    fn search_for(detail: &mut SiteDetail, db: &Db, query: &str) {
        let mut message = None;
        detail
            .handle_key(KeyEvent::from(KeyCode::Char('/')), db, &mut message)
            .unwrap();
        for c in query.chars() {
            detail
                .handle_key(KeyEvent::from(KeyCode::Char(c)), db, &mut message)
                .unwrap();
        }
    }

    #[test]
    fn refresh_loads_global_defaults_and_no_overrides_initially() {
        let db = test_db();
        let site = test_site(&db);
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        assert_eq!(detail.ai_default, Policy::Blocked);
        assert_eq!(detail.search_default, Policy::Allowed);
        assert_eq!(detail.scanner_default, Policy::Blocked);
        assert_eq!(detail.category_overrides, [None; 3]);
        assert!(detail.bot_overrides.is_empty());
    }

    #[test]
    fn enter_on_a_category_opens_a_three_way_popup_defaulting_to_system() {
        let db = test_db();
        let site = test_site(&db);
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        let mut message = None;
        detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let popup = detail.popup.as_ref().unwrap();
        assert!(matches!(
            popup.target,
            PopupTarget::Category(Category::Scanner)
        ));
        assert_eq!(popup.selected, 0); // Use system default
    }

    #[test]
    fn confirming_a_category_override_writes_through_and_is_reflected_in_the_tag() {
        let db = test_db();
        let site = test_site(&db);
        let mut detail = SiteDetail::new(site.clone());
        detail.refresh(&db).unwrap();

        let mut message = None;
        detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        detail
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // Use system default -> Allowed
        let outcome = detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(
            db.get_site_category_override(site.id, Category::Scanner)
                .unwrap(),
            Some(Policy::Allowed)
        );
        assert!(message.unwrap().contains("Scanners"));

        detail.refresh(&db).unwrap();
        let line = detail.category_line(Category::Scanner);
        assert!(line
            .spans
            .iter()
            .any(|s| s.content.contains("(site override)")));
    }

    #[test]
    fn slash_focuses_search_and_filters_bots_like_bot_settings_does() {
        let db = test_db();
        let site = test_site(&db);
        db.upsert_bot(&NewBot {
            slug: "gptbot".to_string(),
            name: "gptbot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "gptbot-ua".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();

        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        search_for(&mut detail, &db, "gpt");

        assert_eq!(detail.focus, Focus::Search);
        assert_eq!(detail.filtered_bots().len(), 1);
    }

    #[test]
    fn site_bot_override_wins_over_a_global_bot_override_in_the_tag() {
        let db = test_db();
        let site = test_site(&db);
        db.upsert_bot(&NewBot {
            slug: "gptbot".to_string(),
            name: "gptbot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "gptbot-ua".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();
        db.set_bot_status("gptbot", BotStatus::Allowed).unwrap();

        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        search_for(&mut detail, &db, "gpt");

        // Global override only: tag should read "(global override)".
        let bot = detail.filtered_bots()[0].clone();
        assert!(detail
            .bot_line(&bot)
            .spans
            .iter()
            .any(|s| s.content.contains("(global override)")));

        // Now confirm a site override for the same bot via the popup.
        let mut message = None;
        detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        detail
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap();
        detail
            .handle_key(KeyEvent::from(KeyCode::Down), &db, &mut message)
            .unwrap(); // -> Blocked
        detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();
        detail.refresh(&db).unwrap();

        let bot = detail.bots.iter().find(|b| b.slug == "gptbot").unwrap();
        assert!(detail
            .bot_line(bot)
            .spans
            .iter()
            .any(|s| s.content.contains("(site override)")));
    }

    #[test]
    fn escape_in_categories_backs_out_and_escape_in_search_does_not() {
        let db = test_db();
        let site = test_site(&db);
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        let mut message = None;
        let outcome = detail
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Back);

        detail.focus = Focus::Search;
        let outcome = detail
            .handle_key(KeyEvent::from(KeyCode::Esc), &db, &mut message)
            .unwrap();
        assert_eq!(outcome, KeyOutcome::Consumed);
        assert_eq!(detail.focus, Focus::Categories);
    }

    #[test]
    fn effective_bot_policy_prefers_site_override_over_everything() {
        let bot = Bot {
            id: 1,
            slug: "gptbot".to_string(),
            name: "gptbot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "gptbot-ua".to_string(),
            status: BotStatus::Allowed,
            source_id: "test".to_string(),
            updated_at: 0,
        };
        assert_eq!(
            effective_bot_policy(
                &bot,
                Some(Policy::Blocked),
                Policy::Allowed,
                Policy::Allowed,
                Policy::Allowed
            ),
            Policy::Blocked
        );
    }

    /// Regression test for a real bug: with an empty query and at least one
    /// bot loaded, the header search line and the (then-empty) results area
    /// both rendered a "press /" hint at once — the header's own "Press /
    /// to search bots by name" made the results area's "Press / then type a
    /// bot name to search." entirely redundant.
    #[test]
    fn press_slash_hint_renders_only_once_with_an_empty_query() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let db = test_db();
        let site = test_site(&db);
        db.upsert_bot(&NewBot {
            slug: "gptbot".to_string(),
            name: "gptbot".to_string(),
            is_ai: true,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: "gptbot-ua".to_string(),
            source_id: "test".to_string(),
        })
        .unwrap();

        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| detail.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert_eq!(content.matches("Press /").count(), 1);
    }

    // ---- path exemptions ----

    /// The existing `test_site` takes an already-built `Db`; these tests
    /// want both, so this wraps the pair.
    fn exemption_fixture() -> (Db, Site) {
        let db = test_db();
        let site = test_site(&db);
        (db, site)
    }

    fn press(detail: &mut SiteDetail, db: &Db, code: KeyCode) -> KeyOutcome {
        let mut message = None;
        detail
            .handle_key(KeyEvent::from(code), db, &mut message)
            .unwrap()
    }

    fn type_str(detail: &mut SiteDetail, db: &Db, text: &str) {
        for c in text.chars() {
            press(detail, db, KeyCode::Char(c));
        }
    }

    fn focus_exemptions(detail: &mut SiteDetail, db: &Db) {
        while detail.focus != Focus::Exemptions {
            press(detail, db, KeyCode::Down);
        }
    }

    #[test]
    fn focus_flows_down_through_every_panel_and_back_up() {
        let (db, site) = exemption_fixture();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        // Down walks Categories -> Options -> Exemptions...
        focus_exemptions(&mut detail, &db);
        assert_eq!(detail.exemptions_state.selected(), Some(0));

        // ...and Up walks back the same way, one panel at a time.
        press(&mut detail, &db, KeyCode::Up);
        assert_eq!(detail.focus, Focus::Options);
        press(&mut detail, &db, KeyCode::Up);
        assert_eq!(detail.focus, Focus::Categories);
    }

    #[test]
    fn adding_and_removing_an_exempt_path_round_trips() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_exemptions(&mut detail, &db);

        press(&mut detail, &db, KeyCode::Enter); // opens the add popup
        type_str(&mut detail, &db, "/blog");
        let outcome = press(&mut detail, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(db.site_path_exemptions(site_id).unwrap(), vec!["/blog"]);

        detail.refresh(&db).unwrap();
        press(&mut detail, &db, KeyCode::Down); // onto the /blog row
        let outcome = press(&mut detail, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.site_path_exemptions(site_id).unwrap().is_empty());
    }

    /// Adds whatever is typed into the add popup, from a freshly focused
    /// exemptions panel.
    fn add_exemption(detail: &mut SiteDetail, db: &Db, typed: &str) -> KeyOutcome {
        detail.refresh(db).unwrap();
        focus_exemptions(detail, db);
        press(detail, db, KeyCode::Enter);
        type_str(detail, db, typed);
        press(detail, db, KeyCode::Enter)
    }

    fn agent_exemption(path: &str, user_agent: &str) -> crate::db::AgentExemption {
        crate::db::AgentExemption {
            path: path.to_string(),
            user_agent: user_agent.to_string(),
        }
    }

    #[test]
    fn a_user_agent_after_the_path_adds_an_agent_exemption_instead() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);

        let outcome = add_exemption(&mut detail, &db, "/videos/ Jellyfin Android");

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(
            db.site_agent_exemptions(site_id).unwrap(),
            vec![agent_exemption("/videos/", "Jellyfin Android")],
            "the user agent keeps its own spaces"
        );
        assert!(db.site_path_exemptions(site_id).unwrap().is_empty());
    }

    #[test]
    fn removing_an_agent_exemption_row_leaves_the_plain_one_on_the_same_path() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        db.add_site_path_exemption(site_id, "/dav/").unwrap();
        db.add_site_agent_exemption(site_id, "/dav/", "okhttp")
            .unwrap();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_exemptions(&mut detail, &db);

        press(&mut detail, &db, KeyCode::Down); // the plain row
        press(&mut detail, &db, KeyCode::Down); // the okhttp row
        press(&mut detail, &db, KeyCode::Enter);

        assert!(db.site_agent_exemptions(site_id).unwrap().is_empty());
        assert_eq!(db.site_path_exemptions(site_id).unwrap(), vec!["/dav/"]);
    }

    #[test]
    fn a_user_agent_that_cannot_be_stored_is_refused_and_the_popup_stays_open() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);

        add_exemption(&mut detail, &db, "/dav/ ok\"http");

        assert!(db.site_agent_exemptions(site_id).unwrap().is_empty());
        match &detail.popup.as_ref().unwrap().target {
            PopupTarget::AddExemption { error, .. } => {
                let error = error.as_deref().unwrap_or_default();
                assert!(error.contains("cannot contain"), "error was: {error}");
            }
            other => panic!("expected the add-exemption popup, got {other:?}"),
        }
    }

    #[test]
    fn parse_exemption_splits_at_the_first_space_only() {
        let parsed = |input: &str| parse_exemption(input).map(|e| (e.path, e.user_agent));
        for (input, expected) in [
            ("/blog", Ok(("/blog".to_string(), None))),
            ("  /blog  ", Ok(("/blog".to_string(), None))),
            (
                "/dav/ okhttp",
                Ok(("/dav/".to_string(), Some("okhttp".to_string()))),
            ),
            (
                "/videos/   Jellyfin  Android ",
                Ok((
                    "/videos/".to_string(),
                    Some("Jellyfin  Android".to_string()),
                )),
            ),
        ] {
            assert_eq!(parsed(input), expected, "input was {input:?}");
        }
        assert!(
            parsed("dav okhttp").is_err(),
            "the path still has to start with /"
        );
    }

    /// A path that could never match is refused at entry, with the popup
    /// left open and the reason shown — storing it would leave a
    /// configured exemption that silently never fires.
    #[test]
    fn an_unanchored_path_is_refused_and_the_popup_stays_open() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_exemptions(&mut detail, &db);

        press(&mut detail, &db, KeyCode::Enter);
        type_str(&mut detail, &db, "blog");
        press(&mut detail, &db, KeyCode::Enter);

        assert!(db.site_path_exemptions(site_id).unwrap().is_empty());
        match &detail.popup.as_ref().unwrap().target {
            PopupTarget::AddExemption { input, error } => {
                assert_eq!(input, "blog");
                assert!(error.as_ref().unwrap().contains("start with /"));
            }
            other => panic!("expected the add-exemption popup, got {other:?}"),
        }
    }

    /// Typing must reach the text field rather than being read as list
    /// navigation — `j`/`k` are ordinary characters in a path.
    #[test]
    fn typing_j_and_k_into_a_path_does_not_navigate() {
        let (db, site) = exemption_fixture();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_exemptions(&mut detail, &db);

        press(&mut detail, &db, KeyCode::Enter);
        type_str(&mut detail, &db, "/jk");
        press(&mut detail, &db, KeyCode::Backspace);

        match &detail.popup.as_ref().unwrap().target {
            PopupTarget::AddExemption { input, .. } => assert_eq!(input, "/j"),
            other => panic!("expected the add-exemption popup, got {other:?}"),
        }
    }

    #[test]
    fn escape_closes_the_add_popup_without_adding_anything() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_exemptions(&mut detail, &db);

        press(&mut detail, &db, KeyCode::Enter);
        type_str(&mut detail, &db, "/blog");
        press(&mut detail, &db, KeyCode::Esc);

        assert!(detail.popup.is_none());
        assert!(db.site_path_exemptions(site_id).unwrap().is_empty());
    }

    #[test]
    fn validate_exempt_path_rejects_unusable_values() {
        assert!(validate_exempt_path("/blog").is_ok());
        assert!(validate_exempt_path("").is_err());
        assert!(validate_exempt_path("blog").is_err());
        assert!(validate_exempt_path("/a b").is_err());
        assert!(validate_exempt_path("/a\"b").is_err());
    }

    #[test]
    fn render_shows_the_exemptions_panel() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let (db, site) = exemption_fixture();
        db.add_site_path_exemption(site.id, "/blog").unwrap();
        db.add_site_agent_exemption(site.id, "/dav/", "okhttp")
            .unwrap();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| detail.render(frame, frame.area(), Theme::Dark))
            .unwrap();

        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(
            content.contains("Path exemptions"),
            "content was:\n{content}"
        );
        assert!(content.contains("/blog"), "content was:\n{content}");
        assert!(
            content.contains("Add an exempt path"),
            "content was:\n{content}"
        );
        assert!(
            content.contains("only for okhttp"),
            "content was:\n{content}"
        );
    }

    /// Characterises existing behaviour before `handle_key` is split: the
    /// category and bot popups accept Space as a synonym for Enter, and
    /// nothing tested that.
    #[test]
    fn space_confirms_a_category_popup_like_enter() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        press(&mut detail, &db, KeyCode::Char(' '));
        assert!(detail.popup.is_some(), "Space should open the popup");
        press(&mut detail, &db, KeyCode::Down);
        press(&mut detail, &db, KeyCode::Down);
        press(&mut detail, &db, KeyCode::Char(' '));

        assert!(detail.popup.is_none());
        assert_eq!(
            db.get_site_category_override(site_id, CATEGORIES[0])
                .unwrap(),
            Some(Policy::Blocked)
        );
    }

    // ---- HTTP/1.x rejection ----

    fn focus_options(detail: &mut SiteDetail, db: &Db) {
        while detail.focus != Focus::Options {
            press(detail, db, KeyCode::Down);
        }
    }

    /// Selects `rule`'s row rather than assuming its position, so adding
    /// a rule can't silently move these tests onto a different one.
    fn select_rule(detail: &mut SiteDetail, rule: RequestRule) {
        let index = RequestRule::ALL.iter().position(|r| *r == rule).unwrap();
        detail.options_state.select(Some(index));
    }

    #[test]
    fn enter_toggles_a_request_rule_for_this_site_only() {
        let (db, site) = exemption_fixture();
        let site_id = site.id;
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_options(&mut detail, &db);
        select_rule(&mut detail, RequestRule::NoUserAgent);

        assert!(db.site_request_rules(site_id).unwrap().is_empty());
        let outcome = press(&mut detail, &db, KeyCode::Enter);
        assert_eq!(outcome, KeyOutcome::Mutated);
        assert_eq!(
            db.site_request_rules(site_id).unwrap(),
            vec![RequestRule::NoUserAgent.id().to_string()],
            "only the selected rule may be switched on"
        );

        detail.refresh(&db).unwrap();
        select_rule(&mut detail, RequestRule::NoUserAgent);
        press(&mut detail, &db, KeyCode::Enter);
        assert!(
            db.site_request_rules(site_id).unwrap().is_empty(),
            "Enter is a toggle, not a one-way switch"
        );
    }

    /// The consequences land outside this screen — on HTTPS blocks only,
    /// and on clients that aren't browsers — so the confirmation has to
    /// say both.
    #[test]
    fn turning_a_request_rule_on_states_what_else_it_turns_away() {
        let (db, site) = exemption_fixture();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();
        focus_options(&mut detail, &db);
        select_rule(&mut detail, RequestRule::Http1x);

        let mut message = None;
        detail
            .handle_key(KeyEvent::from(KeyCode::Enter), &db, &mut message)
            .unwrap();

        let message = message.unwrap();
        assert!(
            message.contains(RequestRule::Http1x.caveat()),
            "message was: {message}"
        );
    }

    #[test]
    fn render_shows_every_request_rule_and_the_state_of_each() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let (db, site) = exemption_fixture();
        db.set_site_request_rule(site.id, RequestRule::Http1x.id(), true)
            .unwrap();
        let mut detail = SiteDetail::new(site);
        detail.refresh(&db).unwrap();

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| detail.render(frame, frame.area(), Theme::Dark))
            .unwrap();
        let content = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();

        assert!(content.contains("Request rules"), "content was:\n{content}");
        for rule in RequestRule::ALL {
            assert!(
                content.contains(rule.label()),
                "{} should be listed; content was:\n{content}",
                rule.label()
            );
        }
        // Only the one switched on reads as blocked.
        assert!(content.contains("BLOCKED"), "content was:\n{content}");
        assert!(content.contains("ALLOWED"), "content was:\n{content}");
    }
}
