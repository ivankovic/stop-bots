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

//! The Blocks screen: every stored firewall rule, and why it is there.
//!
//! A screen of its own rather than a panel on Firewall, because the two
//! answer different questions. Firewall is what is hitting the server now,
//! read from the SSH log; this is what the firewall holds, from every
//! source — including the four web-log detectors, whose blocks appeared
//! on neither screen before. It can hold tens of thousands of rows, so it
//! reads one page at a time (see `db::blocks`), and moving past the end
//! of a page loads the next.
//!
//! `f` cycles the source filter through the sources that have rules;
//! `/` searches by address, and an address finds the range it is in;
//! `Enter` removes the selected rule; `U` removes every rule from the
//! filtered source, after a popup that says how many. Removing a
//! detector's block keeps that detector off the address for a while (see
//! [`crate::blocks`]); the popup says so.

use crate::blocks::{self, SourceFilter};
use crate::db::{BlockQuery, Db, FirewallAction, FirewallRule};
use crate::tui::{centered_rect, KeyOutcome, Theme};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::Stylize,
    text::{Line, Span},
    widgets::{Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

/// Rows read at a time. More than any terminal shows, few enough that a
/// page costs nothing to read or draw.
pub const PAGE: usize = 100;

#[derive(Debug, Default)]
pub struct Blocks {
    query: BlockQuery,
    /// Every source with rules, and how many — what `f` cycles through.
    sources: Vec<(SourceFilter, usize)>,
    /// How many rules the query matches.
    total: usize,
    /// Where `page` starts in the query's results.
    offset: usize,
    page: Vec<FirewallRule>,
    state: ListState,
    /// Whether keys go to the search box.
    searching: bool,
    /// "Unblock all from this source" asked, and waiting for a yes.
    confirm: Option<(SourceFilter, usize)>,
    /// Addresses the detectors are leaving alone because they were
    /// unblocked by hand, for the header.
    unblocked: usize,
    /// Rules that are enforced but never stored, for the header: Allows
    /// for recent SSH logins and trusted addresses.
    not_listed: (usize, usize),
    /// The last thing this screen told the operator.
    notice: Option<String>,
}

impl Blocks {
    pub fn refresh(&mut self, db: &Db) -> Result<()> {
        self.sources = db.block_source_counts()?;
        // A filter whose last rule went is a filter showing nothing, with
        // no way to tell why; fall back to everything.
        if let Some(filter) = self.query.source {
            if !self.sources.iter().any(|(s, _)| *s == filter) {
                self.query.source = None;
            }
        }
        self.unblocked = db.unblocked_addresses()?.len();
        self.not_listed = (
            db.recent_ssh_login_ips()?.len(),
            db.list_trusted_addresses()?.len(),
        );
        let selected = self.selected_index();
        self.reload(db, selected)
    }

    /// Re-reads the count, and the page holding row `selected` (an index
    /// into the whole result), clamped to what exists.
    fn reload(&mut self, db: &Db, selected: usize) -> Result<()> {
        self.total = db.count_blocks(&self.query)?;
        let selected = selected.min(self.total.saturating_sub(1));
        self.offset = selected / PAGE * PAGE;
        self.page = db.blocks_page(&self.query, self.offset, PAGE)?;
        self.state
            .select((!self.page.is_empty()).then_some(selected - self.offset));
        Ok(())
    }

    fn selected_index(&self) -> usize {
        self.offset + self.state.selected().unwrap_or(0)
    }

    fn selected_rule(&self) -> Option<&FirewallRule> {
        self.page.get(self.state.selected()?)
    }

    /// Moves the selection by `delta` rows across pages.
    fn move_by(&mut self, db: &Db, delta: isize) -> Result<()> {
        if self.total == 0 {
            return Ok(());
        }
        let target = self
            .selected_index()
            .saturating_add_signed(delta)
            .min(self.total - 1);
        if (self.offset..self.offset + self.page.len()).contains(&target) {
            self.state.select(Some(target - self.offset));
            Ok(())
        } else {
            self.reload(db, target)
        }
    }

    pub fn hints(&self) -> crate::tui::Hints {
        if self.confirm.is_some() {
            return (
                "Unblock all",
                vec![("Enter", "unblock them"), ("Esc", "cancel")],
            );
        }
        if self.searching {
            return ("Search", vec![("Enter", "done"), ("Esc", "leave search")]);
        }
        let mut hints = vec![
            ("\u{2191}\u{2193}", "move"),
            ("Enter", "unblock"),
            ("f", "source"),
            ("/", "search"),
        ];
        if self.query.source.is_some() {
            hints.push(("U", "unblock all from the source"));
        }
        ("Blocks", hints)
    }

    /// Handles a key. What it tells the operator goes to `App`'s message
    /// (the Dashboard's log) and is also kept here, because this screen is
    /// where they are looking when they press it.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        let mut said = None;
        let outcome = self.handle(key, db, &mut said)?;
        if said.is_some() {
            self.notice.clone_from(&said);
            *message = said;
        }
        Ok(outcome)
    }

    fn handle(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        if let Some((filter, _)) = self.confirm {
            return match key.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    self.confirm = None;
                    let removed = db.remove_firewall_rules_from(filter, false)?;
                    *message = Some(format!(
                        "Removed {removed} rule(s) from {} — write and apply the firewall \
                         script (F, or a) to lift them.",
                        filter.label()
                    ));
                    Ok(KeyOutcome::Mutated)
                }
                KeyCode::Esc | KeyCode::Char('n' | 'q') => {
                    self.confirm = None;
                    Ok(KeyOutcome::Consumed)
                }
                _ => Ok(KeyOutcome::Consumed),
            };
        }
        if self.searching {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.searching = false,
                KeyCode::Backspace => {
                    self.query.search.pop();
                    self.reload(db, 0)?;
                }
                KeyCode::Char(c) => {
                    self.query.search.push(c);
                    self.reload(db, 0)?;
                }
                KeyCode::Up | KeyCode::Down => {
                    self.searching = false;
                    return self.handle(key, db, message);
                }
                _ => {}
            }
            return Ok(KeyOutcome::Consumed);
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.move_by(db, 1)?,
            KeyCode::Up | KeyCode::Char('k') => self.move_by(db, -1)?,
            KeyCode::PageDown => self.move_by(db, 20)?,
            KeyCode::PageUp => self.move_by(db, -20)?,
            KeyCode::Home => self.reload(db, 0)?,
            KeyCode::End => self.reload(db, self.total.saturating_sub(1))?,
            KeyCode::Char('/') => self.searching = true,
            KeyCode::Char('f') => {
                self.query.source = next_filter(self.query.source, &self.sources);
                self.reload(db, 0)?;
            }
            KeyCode::Enter | KeyCode::Delete => {
                let Some(rule) = self.selected_rule() else {
                    return Ok(KeyOutcome::Consumed);
                };
                let (id, address) = (rule.id, rule.address.clone());
                let by_detector = rule.source.and_then(|s| s.detector()).is_some();
                db.remove_firewall_rule(id)?;
                *message = Some(format!(
                    "Removed the rule for {address}{} — write and apply the firewall script \
                     (F, or a) to lift it.",
                    if by_detector {
                        "; its detector leaves it alone for now (T on Firewall trusts it for good)"
                    } else {
                        ""
                    }
                ));
                return Ok(KeyOutcome::Mutated);
            }
            KeyCode::Char('U') => {
                if let Some(filter) = self.query.source {
                    self.confirm = Some((filter, db.count_blocks(&self.query_for(filter))?));
                } else {
                    *message =
                        Some("Pick a source with f first: U unblocks all from one source.".into());
                }
            }
            KeyCode::Esc | KeyCode::Char('q') if !self.query.search.is_empty() => {
                self.query.search.clear();
                self.reload(db, 0)?;
            }
            KeyCode::Esc => return Ok(KeyOutcome::Back),
            _ => return Ok(KeyOutcome::Ignored),
        }
        Ok(KeyOutcome::Consumed)
    }

    /// Every rule from `filter`, whatever the search says: "unblock all
    /// from this source" means all of them, not the ones on screen.
    fn query_for(&self, filter: SourceFilter) -> BlockQuery {
        BlockQuery {
            source: Some(filter),
            search: String::new(),
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let [header_area, list_area, why_area] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(3),
            Constraint::Length(5),
        ])
        .areas(area);
        let now = blocks::now();

        let source = self
            .query
            .source
            .map_or("every source".to_string(), |f| f.label().to_string());
        let search: Line = if self.searching || !self.query.search.is_empty() {
            vec![
                "search: ".fg(theme.dim()),
                Span::from(self.query.search.clone()),
                if self.searching {
                    "\u{2588}".fg(theme.accent())
                } else {
                    "".into()
                },
            ]
            .into()
        } else {
            "/ searches by address; an address finds the range it is in"
                .fg(theme.dim())
                .into()
        };
        let (logins, trusted) = self.not_listed;
        let mut header = vec![
            Line::from(vec![
                format!("{} rule(s)", self.total).bold(),
                format!(" from {source}").into(),
                "   f cycles the source".fg(theme.dim()),
            ]),
            search,
            Line::from(
                format!(
                    "Not listed: {logins} SSH-login and {trusted} trusted allow(s), and the \
                     downloaded lists (Dashboard). {} address(es) unblocked by hand are left \
                     alone by the detectors.",
                    self.unblocked
                )
                .fg(theme.dim()),
            ),
        ];
        if let Some(notice) = &self.notice {
            header.push(Line::from(notice.clone().fg(theme.live())));
        }
        frame.render_widget(Paragraph::new(header), header_area);

        let items: Vec<ListItem> = if self.page.is_empty() {
            vec![ListItem::new(
                if self.total == 0 && self.query == BlockQuery::default() {
                    "No firewall rules stored."
                } else {
                    "No rules match."
                }
                .fg(theme.dim()),
            )]
        } else {
            self.page
                .iter()
                .map(|rule| ListItem::new(rule_line(rule, now, theme)))
                .collect()
        };
        let title = format!(
            "Blocks {}\u{2013}{} of {}",
            if self.total == 0 { 0 } else { self.offset + 1 },
            self.offset + self.page.len(),
            self.total
        );
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel(title, !self.searching, theme)),
            !self.searching,
            theme,
        );
        frame.render_stateful_widget(list, list_area, &mut self.state);

        let why = match self.selected_rule() {
            Some(rule) => vec![
                Line::from(vec![
                    rule.address.clone().bold(),
                    format!(
                        " — {}{}",
                        blocks::source_label(rule.source),
                        rule.created_at
                            .map(|t| format!(", added {} ago", blocks::format_age(t, now)))
                            .unwrap_or_default()
                    )
                    .into(),
                ]),
                Line::from(match &rule.evidence {
                    Some(evidence) => Span::from(evidence.clone()),
                    None if rule.source.is_none() => {
                        "Added before 0.1, which did not record why.".fg(theme.dim())
                    }
                    None => "No log line: added by hand.".fg(theme.dim()),
                }),
            ],
            None => vec![],
        };
        frame.render_widget(
            Paragraph::new(why)
                .wrap(Wrap { trim: false })
                .block(crate::tui::panel("Why", false, theme)),
            why_area,
        );

        if let Some((filter, count)) = self.confirm {
            self.render_confirm(frame, area, filter, count, theme);
        }
    }

    fn render_confirm(
        &self,
        frame: &mut Frame,
        area: Rect,
        filter: SourceFilter,
        count: usize,
        theme: Theme,
    ) {
        let mut lines = vec![
            Line::from(format!("Unblock all {count} rule(s) from {}?", filter.label()).bold()),
            Line::from(""),
        ];
        if matches!(filter, SourceFilter::Source(s) if s.detector().is_some())
            || filter == SourceFilter::Legacy
        {
            lines.push(Line::from(
                "The detector leaves each address alone for as long as its block was meant to \
                 last.",
            ));
        }
        lines.push(Line::from(
            "Nothing changes on the host until the firewall script is written and applied.",
        ));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            "Enter".fg(theme.accent()),
            " unblock them   ".into(),
            "Esc".fg(theme.accent()),
            " cancel".into(),
        ]));
        let popup = centered_rect(72, lines.len() as u16 + 4, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(crate::tui::popup("Unblock all", theme)),
            popup,
        );
    }
}

/// The filter after `current` in `f`'s cycle: every source, then each one
/// that has rules, then every source again.
fn next_filter(
    current: Option<SourceFilter>,
    sources: &[(SourceFilter, usize)],
) -> Option<SourceFilter> {
    let position = current.and_then(|c| sources.iter().position(|(s, _)| *s == c));
    match position {
        None => sources.first().map(|(s, _)| *s),
        Some(i) => sources.get(i + 1).map(|(s, _)| *s),
    }
}

/// One rule as a row: address, verdict and port, source, age, expiry, and
/// as much of the evidence as fits.
fn rule_line(rule: &FirewallRule, now: i64, theme: Theme) -> Line<'static> {
    let verdict = match rule.action {
        FirewallAction::Allow => format!("{:<7}", "allow").green(),
        FirewallAction::Block => format!("{:<7}", "block").red(),
        FirewallAction::Reject => format!("{:<7}", "reject").red(),
    };
    let port = rule.port.map(|p| format!(":{p}")).unwrap_or_default();
    let expires = match rule.expires_at {
        Some(t) => format!("for {}", crate::dynamic::format_until(t)),
        None => "permanent".to_string(),
    };
    let added = rule
        .created_at
        .map_or("?".to_string(), |t| blocks::format_age(t, now));
    let mut spans = vec![
        format!("{:<26}", format!("{}{port}", rule.address)).into(),
        verdict,
        format!("{:<22}", blocks::source_label(rule.source)).into(),
        format!("{added:>4} ago  ").fg(theme.dim()),
        format!("{expires:<10}").fg(theme.dim()),
        rule.evidence.clone().unwrap_or_default().into(),
    ];
    if !rule.enabled {
        spans.insert(2, "(off) ".fg(theme.dim()));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::RuleSource;
    use crate::db::NewFirewallRule;
    use crate::protection::Detector;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn add(db: &Db, address: &str, source: RuleSource, evidence: Option<&str>) {
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: address.to_string(),
                port: None,
                action: FirewallAction::Block,
                source,
                evidence: evidence.map(str::to_string),
            },
            86_400,
        )
        .unwrap();
    }

    const PROBES: RuleSource = RuleSource::Detector(Detector::ProbePaths);

    fn screen(db: &Db) -> Blocks {
        let mut screen = Blocks::default();
        screen.refresh(db).unwrap();
        screen
    }

    fn press(screen: &mut Blocks, db: &Db, code: KeyCode) -> (KeyOutcome, Option<String>) {
        let mut message = None;
        let outcome = screen
            .handle_key(KeyEvent::from(code), db, &mut message)
            .unwrap();
        (outcome, message)
    }

    fn drawn(screen: &mut Blocks) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 30)).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), Theme::Dark))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The four web-log detectors' blocks were on no screen before this.
    #[test]
    fn every_rule_is_listed_with_its_source_and_evidence() {
        let db = Db::open_in_memory().unwrap();
        add(
            &db,
            "203.0.113.5",
            PROBES,
            Some("\"GET /.env HTTP/1.1\" 404"),
        );
        add(&db, "192.0.2.1", RuleSource::Cli, None);

        let drawn = drawn(&mut screen(&db));

        for needle in [
            "203.0.113.5",
            "Probe paths",
            "\"GET /.env HTTP/1.1\" 404",
            "192.0.2.1",
            "by hand (CLI)",
            "2 rule(s)",
        ] {
            assert!(drawn.contains(needle), "{needle:?} missing from:\n{drawn}");
        }
    }

    #[test]
    fn f_cycles_through_the_sources_that_have_rules_and_back_to_all() {
        let db = Db::open_in_memory().unwrap();
        add(&db, "203.0.113.5", PROBES, None);
        add(&db, "203.0.113.6", PROBES, None);
        add(&db, "192.0.2.1", RuleSource::Cli, None);
        let mut screen = screen(&db);

        press(&mut screen, &db, KeyCode::Char('f'));
        assert_eq!(screen.query.source, Some(SourceFilter::Source(PROBES)));
        assert_eq!(screen.total, 2);
        press(&mut screen, &db, KeyCode::Char('f'));
        assert_eq!(
            screen.query.source,
            Some(SourceFilter::Source(RuleSource::Cli))
        );
        press(&mut screen, &db, KeyCode::Char('f'));
        assert_eq!(screen.query.source, None);
        assert_eq!(screen.total, 3);
    }

    #[test]
    fn searching_for_an_address_finds_the_range_that_blocks_it() {
        let db = Db::open_in_memory().unwrap();
        add(&db, "203.0.113.0/24", PROBES, None);
        add(&db, "192.0.2.1", RuleSource::Cli, None);
        let mut screen = screen(&db);

        press(&mut screen, &db, KeyCode::Char('/'));
        for c in "203.0.113.77".chars() {
            press(&mut screen, &db, KeyCode::Char(c));
        }

        assert_eq!(screen.total, 1);
        assert_eq!(screen.selected_rule().unwrap().address, "203.0.113.0/24");
    }

    #[test]
    fn enter_unblocks_the_selected_rule() {
        let db = Db::open_in_memory().unwrap();
        add(&db, "203.0.113.5", PROBES, None);
        let mut screen = screen(&db);

        let (outcome, message) = press(&mut screen, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.list_firewall_rules().unwrap().is_empty());
        assert!(
            message.unwrap_or_default().contains("leaves it alone"),
            "a detector's block says it will not come straight back"
        );
    }

    /// The count is in the question, and nothing happens before the yes.
    #[test]
    fn unblock_all_asks_with_the_count_and_removes_only_that_source() {
        let db = Db::open_in_memory().unwrap();
        add(&db, "203.0.113.5", PROBES, None);
        add(&db, "203.0.113.6", PROBES, None);
        add(&db, "192.0.2.1", RuleSource::Cli, None);
        let mut screen = screen(&db);
        press(&mut screen, &db, KeyCode::Char('f'));

        press(&mut screen, &db, KeyCode::Char('U'));
        let drawn = drawn(&mut screen);
        assert!(
            drawn.contains("Unblock all 2 rule(s) from Probe paths?"),
            "{drawn}"
        );
        assert_eq!(db.list_firewall_rules().unwrap().len(), 3, "not yet");

        let (outcome, _) = press(&mut screen, &db, KeyCode::Enter);
        assert_eq!(outcome, KeyOutcome::Mutated);
        let left: Vec<String> = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .map(|r| r.address)
            .collect();
        assert_eq!(left, ["192.0.2.1"]);
    }

    #[test]
    fn unblock_all_needs_a_source_and_esc_cancels_it() {
        let db = Db::open_in_memory().unwrap();
        add(&db, "203.0.113.5", PROBES, None);
        let mut screen = screen(&db);

        let (_, message) = press(&mut screen, &db, KeyCode::Char('U'));
        assert!(message.unwrap_or_default().contains("Pick a source"));

        press(&mut screen, &db, KeyCode::Char('f'));
        press(&mut screen, &db, KeyCode::Char('U'));
        press(&mut screen, &db, KeyCode::Esc);
        assert!(screen.confirm.is_none());
        assert_eq!(db.list_firewall_rules().unwrap().len(), 1);
    }

    /// Past the end of a page is the start of the next one, not a wall.
    #[test]
    fn moving_past_a_page_loads_the_next() {
        let db = Db::open_in_memory().unwrap();
        db.batch(|| {
            for i in 0..(PAGE + 5) {
                add(&db, &format!("10.0.{}.{}", i / 250, i % 250), PROBES, None);
            }
            Ok(())
        })
        .unwrap();
        let mut screen = screen(&db);

        press(&mut screen, &db, KeyCode::End);
        assert_eq!(screen.selected_index(), PAGE + 4);
        assert_eq!(screen.offset, PAGE);
        press(&mut screen, &db, KeyCode::PageUp);
        assert_eq!(screen.selected_index(), PAGE - 16);
        assert_eq!(screen.offset, 0);
        assert_eq!(screen.page.len(), PAGE);
    }

    #[test]
    fn a_rule_from_before_0_1_says_so() {
        let db = Db::open_in_memory().unwrap();
        db.insert_rule_from_before_0_1("198.51.100.1");
        let drawn = drawn(&mut screen(&db));
        assert!(drawn.contains("before 0.1"), "{drawn}");
    }

    #[test]
    fn esc_with_nothing_open_goes_back() {
        let db = Db::open_in_memory().unwrap();
        let mut screen = screen(&db);
        assert_eq!(press(&mut screen, &db, KeyCode::Esc).0, KeyOutcome::Back);
    }
}
