/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The Dashboard's simple mode: one screen for a self-hoster who is not a
//! sysadmin, and the screen a new database opens on (see `Db::get_ui_mode`).
//!
//! ## What is on it
//!
//! - **Status**: one state, worst first, and the one thing to do about it
//!   ([`verdict`]), where the advanced screens have a strip of every check.
//! - **Who can visit**: humans only and the three bot categories, the
//!   Policy panel's rows without old browsers.
//! - **Countries**: the Geo panel, as it is.
//! - **Running**: what the log detectors do, read-only, and "Keep running
//!   by itself", which stands for the cron file and both auto-applies.
//!
//! Everything else is on the advanced screens, behind `v`, and is left as
//! it was: nothing here is a preset that writes settings it cannot put
//! back. The detectors are shown and not switched for that reason. One
//! switch over all of them would be a second place to say what each
//! detector's own switch says.
//!
//! ## Why it is safer as well as shorter
//!
//! Switching humans only on asks first, since it takes the site out of
//! search engines ([`Confirm::HumansOnly`]). The detectors that can catch
//! real people are off by default and cannot be reached from here. Keeping
//! it running turns the SSH lock-out check on, and there is no row to turn
//! it off. A country allowlist cannot lock the operator out: every address
//! that logged in over SSH in the last week is allowed ahead of any geo
//! rule (`firewall::ssh_allow_rules`).
//!
//! The panels share the advanced screen's state (`list_state`,
//! `countries_state`, the popups), so moving between the two modes keeps
//! what is selected where both have it.

use super::*;
use crate::health::{Level, Report};

/// Rows in the simple screen's "Who can visit": humans only and the three
/// categories. Old browsers is the advanced Policy panel's fifth row.
const SIMPLE_POLICY_ROWS: usize = CATEGORIES.len() + 1;

/// Rows in the Running panel: the detectors, then keeping it running.
const ESSENTIAL_ROWS: usize = 2;

/// The simple screen's status: the worst thing about the host, and the one
/// thing to do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Verdict {
    pub level: Level,
    pub headline: String,
    /// What to do, or why; empty when nothing needs doing.
    pub advice: String,
}

/// What the status says, from the last health report, whether the cron
/// file was there, and whether it applies by itself
/// ([`Dashboard::keeps_running`]).
///
/// One state, checked worst first, so that a host with three problems
/// shows the one that matters: anything critical; then sites that were
/// never found, which leave nothing to protect; then changes not applied
/// yet, which `a` fixes; then a schedule that stops when the TUI does;
/// then any other warning. A check that could not run (`Unknown`, usually
/// for want of root) says nothing here: the advanced status strip shows it.
///
/// Changes waiting on a host that keeps running are not a warning. Every
/// new block is one, until the next scheduled render applies it within
/// minutes, and telling a busy host to press `a` after each would teach
/// its operator that the status is noise.
pub(super) fn verdict(
    report: Option<&Report>,
    cron_installed: Option<bool>,
    keeps_running: bool,
) -> Verdict {
    let Some(report) = report else {
        return Verdict {
            level: Level::Unknown,
            headline: "Not checked yet".to_string(),
            advice: "The first check runs within a minute of starting.".to_string(),
        };
    };
    let warned = |id: &str| {
        report
            .checks
            .iter()
            .find(|check| check.id == id && check.level >= Level::Warn)
    };
    if let Some(check) = report.checks.iter().find(|c| c.level == Level::Critical) {
        return Verdict {
            level: Level::Critical,
            headline: "Not protecting".to_string(),
            advice: format!(
                "{}: {}",
                check.title,
                check.fix.as_deref().unwrap_or(&check.detail)
            ),
        };
    }
    if warned("nginx-applied").is_some_and(|check| check.detail.starts_with("no sites")) {
        return Verdict {
            level: Level::Warn,
            headline: "No sites found yet".to_string(),
            // The command, because no screen sets this: the server and
            // where its config is are the host's settings, and the advice
            // used to send people to the advanced screens to look for one.
            advice: "Another server, or config somewhere else? Quit (q) and run: sudo \
                     stop-bots set-web-server nginx|apache|traefik|npmplus --root DIR"
                .to_string(),
        };
    }
    let waiting = warned("script-fresh").is_some() || warned("nginx-applied").is_some();
    if waiting && !keeps_running {
        return Verdict {
            level: Level::Warn,
            headline: "Changes not applied".to_string(),
            advice: "Press a to see what would change, and apply it.".to_string(),
        };
    }
    if cron_installed == Some(false) {
        return Verdict {
            level: Level::Warn,
            headline: "Only runs while this screen is open".to_string(),
            advice: "Turn on \u{201c}Keep running by itself\u{201d}, below.".to_string(),
        };
    }
    if let Some(check) = report
        .checks
        .iter()
        .find(|c| c.level == Level::Warn && !matches!(c.id, "script-fresh" | "nginx-applied"))
    {
        return Verdict {
            level: Level::Warn,
            headline: check.title.to_string(),
            advice: format!("{}. Press v for every check.", summary(&check.detail)),
        };
    }
    Verdict {
        level: Level::Ok,
        headline: "Protected".to_string(),
        advice: if waiting {
            "Some changes are waiting, and are applied by themselves within minutes. a applies \
             them now."
                .to_string()
        } else {
            String::new()
        },
    }
}

/// A check's detail up to its first colon: the checks put what happened
/// first and the list it is about after, and the list (every user agent,
/// every site) is for the advanced screen's report, not a one-line status.
fn summary(detail: &str) -> &str {
    detail.split_once(": ").map_or(detail, |(head, _)| head)
}

/// `text` cut to `width` columns, with an ellipsis where it was cut, so
/// that the status's lines stay one row each and the last of them, the
/// count of blocks, is never pushed out of its panel.
fn one_line(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('\u{2026}');
    cut
}

impl Dashboard {
    /// Switches between the simple screen and every panel. Focus goes back
    /// to the first row: the panel it was on may not exist in the other
    /// mode, and a selection past "AI bots" is old browsers, which the
    /// simple screen has no row for.
    pub fn set_simple(&mut self, simple: bool) {
        self.simple = simple;
        self.focus = Focus::Categories;
        self.list_state.select(Some(0));
        self.popup = None;
    }

    pub fn is_simple(&self) -> bool {
        self.simple
    }

    /// Puts the cursor on the first row of the advanced screen's
    /// Automatic blocking list.
    pub fn focus_detectors(&mut self) {
        self.focus = Focus::Protection;
        self.protection_state.select(Some(0));
    }

    /// Whether it applies on its own: both auto-applies, and a cron file
    /// to run them once the TUI closes. A probe that has not looked for
    /// the file yet does not count against it.
    fn keeps_running(&self) -> bool {
        self.auto_apply && self.auto_apply_firewall && self.cron_installed != Some(false)
    }

    pub(super) fn render_simple(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        theme: Theme,
        log: &[(i64, String)],
    ) {
        // The two lists side by side, as tall as the longer one: the
        // country list is the one that grows, a row per country and one
        // to add with. The Log takes what is left.
        let lists = SIMPLE_POLICY_ROWS.max(self.selected_countries.len() + 1) as u16 + 2;
        let [status_area, middle, essentials_area, log_area] = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(lists),
            Constraint::Length(ESSENTIAL_ROWS as u16 + 2),
            Constraint::Min(LOG_HEIGHT),
        ])
        .areas(area);
        let [who_area, countries_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(middle);

        self.render_status(frame, status_area, theme);
        self.render_who(frame, who_area, theme);
        self.render_geo(frame, countries_area, theme);
        self.render_essentials(frame, essentials_area, theme);
        self.render_log(frame, log_area, theme, log);
    }

    fn render_status(&self, frame: &mut Frame, area: Rect, theme: Theme) {
        let verdict = verdict(
            self.health.as_ref().map(|(r, _)| r),
            self.cron_installed,
            self.keeps_running(),
        );
        // Inside the borders.
        let width = usize::from(area.width.saturating_sub(2));
        let (mark, colour) = match verdict.level {
            Level::Ok => ("\u{25cf}", ratatui::style::Color::Green),
            Level::Warn => ("\u{25b2}", ratatui::style::Color::Yellow),
            Level::Critical => ("\u{2716}", ratatui::style::Color::Red),
            Level::Unknown => ("\u{25cb}", theme.dim()),
        };
        let mut lines = vec![Line::from(vec![
            format!(" {mark} ").fg(colour).bold(),
            verdict.headline.fg(colour).bold(),
        ])];
        if !verdict.advice.is_empty() {
            lines.push(Line::from(one_line(
                &format!("   {}", verdict.advice),
                width,
            )));
        }
        let mut facts = format!(
            "   {} address(es) blocked now, {} of them in the last day",
            self.blocked_now, self.blocked_today
        );
        if let Some((_, at)) = &self.health {
            facts.push_str(&format!(" \u{00b7} checked {}", crate::present::ago(*at)));
        }
        lines.push(Line::from(one_line(&facts, width)).fg(theme.dim()));
        frame.render_widget(
            Paragraph::new(lines).block(crate::tui::panel("Status", false, theme)),
            area,
        );
    }

    fn render_who(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let items: Vec<ListItem> = std::iter::once(ListItem::new(self.humans_only_line()))
            .chain(
                CATEGORIES
                    .iter()
                    .map(|&category| ListItem::new(self.row_line(category))),
            )
            .collect();
        let focused = self.focus == Focus::Categories;
        let list = crate::tui::select_in(
            List::new(items).block(crate::tui::panel("Who can visit", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_essentials(&mut self, frame: &mut Frame, area: Rect, theme: Theme) {
        let tag = |on: bool| {
            if on {
                Span::from("[ ON  ]").green().bold()
            } else {
                Span::from("[ off ]").dim()
            }
        };
        let (on, total) = self.detectors_on();
        let detectors = Line::from(vec![
            Span::from(format!("{:<24}", "Block attackers in logs")),
            tag(on > 0),
            format!("  {on} of {total} checks; v to change").fg(theme.dim()),
        ]);
        let keeps = self.keeps_running();
        let running = Line::from(vec![
            Span::from(format!("{:<24}", "Keep running by itself")),
            tag(keeps),
            match (keeps, self.cron_installed) {
                (true, _) => "  applies what it finds",
                (false, Some(true)) => "  finds attackers; you apply with a",
                (false, _) => "  only while this screen is open",
            }
            .fg(theme.dim()),
        ]);
        let focused = self.focus == Focus::Essentials;
        let list = crate::tui::select_in(
            List::new([ListItem::new(detectors), ListItem::new(running)])
                .block(crate::tui::panel("Running", focused, theme)),
            focused,
            theme,
        );
        frame.render_stateful_widget(list, area, &mut self.essentials_state);
    }

    /// How many of the detectors the operator controls are on, of how many.
    fn detectors_on(&self) -> (usize, usize) {
        let controlled: Vec<&(bool, i64)> = Detector::ALL
            .into_iter()
            .filter(|d| d.is_operator_controlled())
            .filter_map(|d| self.detectors.get(&d))
            .collect();
        let on = controlled.iter().filter(|(enabled, _)| *enabled).count();
        (on, controlled.len())
    }

    pub(super) fn simple_hints(&self) -> crate::tui::Hints {
        let host = [("Tab", "next panel"), ("a", "apply"), ("x", "blocks")];
        let (name, own): (&'static str, Vec<(&'static str, &'static str)>) = match self.focus {
            Focus::Countries => (
                "Countries",
                vec![("Enter", "add"), ("Del", "remove"), ("m", "mode")],
            ),
            Focus::Essentials => ("Running", vec![("Enter", "change")]),
            Focus::Categories | Focus::Crawlers | Focus::Protection => {
                ("Who can visit", vec![("Enter", "change")])
            }
        };
        (name, own.into_iter().chain(host).collect())
    }

    pub(super) fn explain_simple(&self) -> Explanation {
        match self.focus {
            Focus::Categories | Focus::Crawlers | Focus::Protection => {
                match self.list_state.selected().unwrap_or(0) {
                    0 => self.explain_humans_only(),
                    i => self.explain_category(CATEGORIES[(i - 1).min(CATEGORIES.len() - 1)]),
                }
            }
            Focus::Countries => match self.countries_state.selected().unwrap_or(0) {
                0 => self.explain_geo_mode(),
                i => match self.selected_countries.get(i - 1) {
                    Some(country) => self.explain_country(country),
                    None => self.explain_geo_mode(),
                },
            },
            Focus::Essentials if self.essentials_state.selected() == Some(0) => {
                let (on, total) = self.detectors_on();
                Explanation::new("Block attackers in logs")
                    .para(
                        "stop-bots reads the web server's and SSH's logs every minute, and \
                         blocks an address in the firewall when it does what only an attacker \
                         does: asks for /.env or /.git/config, sends an exploit, tries SSH \
                         passwords, or pretends to be Googlebot.",
                    )
                    .now(format!("{on} of {total} checks are on."))
                    .para(
                        "The ones that are off by default can catch real people, which is why \
                         they are not on this screen. Press v to see every check, and to switch \
                         one.",
                    )
                    .takes_effect(self.keeps_running())
            }
            Focus::Essentials => Explanation::new("Keep running by itself")
                .para(
                    "Runs stop-bots every minute from cron, whether this screen is open or \
                     not, and applies what it finds: the web server's config and the \
                     firewall. Turning it on writes /etc/cron.d/stop-bots, which needs root.",
                )
                .now(if self.keeps_running() {
                    "on."
                } else {
                    "off: nothing changes on the host until you press a."
                })
                .para(
                    "Every firewall apply is checked first, and refused if it would block an \
                     address that logged in over SSH. Turning it off stops the applying; the \
                     checks still run and record what they find.",
                ),
        }
    }

    pub(super) fn handle_simple_key(
        &mut self,
        key: KeyEvent,
        db: &Db,
        message: &mut Option<String>,
    ) -> Result<KeyOutcome> {
        // `m`, `u`, `a` and `F` are the advanced screen's, handled before
        // this is called.
        match key.code {
            KeyCode::Esc => return Ok(KeyOutcome::Ignored),
            KeyCode::Tab | KeyCode::BackTab => {
                let forward = key.code == KeyCode::Tab;
                self.focus = match (self.focus, forward) {
                    (Focus::Countries, true) | (Focus::Categories, false) => Focus::Essentials,
                    (Focus::Essentials, true) | (Focus::Countries, false) => Focus::Categories,
                    _ => Focus::Countries,
                };
                return Ok(KeyOutcome::Consumed);
            }
            _ => {}
        }
        match self.focus {
            Focus::Categories | Focus::Crawlers | Focus::Protection => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.list_state.select_previous(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.list_state.selected().unwrap_or(0) + 1 >= SIMPLE_POLICY_ROWS {
                        self.focus = Focus::Countries;
                        self.countries_state.select(Some(0));
                    } else {
                        self.list_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if self.list_state.selected() == Some(0) && !self.humans_only {
                        self.popup = Some(Popup::Confirm {
                            what: Confirm::HumansOnly,
                            selected: 1,
                        });
                        return Ok(KeyOutcome::Consumed);
                    }
                    return self.activate_policy_row(db, message);
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Countries => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.countries_state.selected() == Some(0) {
                        self.focus = Focus::Categories;
                        self.list_state.select(Some(SIMPLE_POLICY_ROWS - 1));
                    } else {
                        self.countries_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.countries_state.selected() == Some(self.selected_countries.len()) {
                        self.focus = Focus::Essentials;
                        self.essentials_state.select(Some(0));
                    } else {
                        self.countries_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    return Ok(self.activate_country_row(message));
                }
                KeyCode::Delete | KeyCode::Backspace => {
                    return self.remove_country_row(message, db);
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
            Focus::Essentials => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.essentials_state.selected() == Some(0) {
                        self.focus = Focus::Countries;
                        self.countries_state
                            .select(Some(self.selected_countries.len()));
                    } else {
                        self.essentials_state.select_previous();
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.essentials_state.selected().unwrap_or(0) + 1 < ESSENTIAL_ROWS {
                        self.essentials_state.select_next();
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if self.essentials_state.selected() == Some(0) {
                        // The row counts the checks, so opening it shows
                        // them. It used to say where they were instead.
                        return Ok(KeyOutcome::ShowDetectors);
                    } else if self.keeps_running() {
                        return Ok(KeyOutcome::KeepRunning(false));
                    } else {
                        self.popup = Some(Popup::Confirm {
                            what: Confirm::KeepRunning,
                            selected: 0,
                        });
                    }
                }
                _ => return Ok(KeyOutcome::Ignored),
            },
        }
        Ok(KeyOutcome::Consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Check;
    use ratatui::{backend::TestBackend, Terminal};

    fn simple(db: &Db) -> Dashboard {
        let mut dashboard = Dashboard::default();
        dashboard.set_simple(true);
        dashboard.refresh(db).unwrap();
        dashboard
    }

    fn press(dashboard: &mut Dashboard, db: &Db, code: KeyCode) -> (KeyOutcome, Option<String>) {
        let mut message = None;
        let outcome = dashboard
            .handle_key(KeyEvent::from(code), db, &mut message)
            .unwrap();
        (outcome, message)
    }

    fn drawn(dashboard: &mut Dashboard) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        terminal
            .draw(|frame| {
                dashboard.render(
                    frame,
                    frame.area(),
                    Theme::Dark,
                    &[],
                    &std::collections::HashSet::new(),
                )
            })
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

    fn check(id: &'static str, level: Level, detail: &str) -> Check {
        Check {
            id,
            title: "A check",
            level,
            detail: detail.to_string(),
            fix: Some("the fix".to_string()),
        }
    }

    fn report(checks: Vec<Check>) -> Report {
        Report {
            checks,
            checked_at: 0,
            access_logs: Vec::new(),
        }
    }

    /// One state, worst first: each row is a host with the problem it
    /// names and every lesser one, and the status names only the first.
    #[test]
    fn the_status_names_the_worst_thing_and_only_that() {
        let pending = check("script-fresh", Level::Warn, "rendered, not applied");
        let other = check("disk-room", Level::Warn, "1GB free");
        let critical = check("firewall-enforced", Level::Critical, "none loaded");
        let no_sites = check("nginx-applied", Level::Warn, "no sites scanned yet");
        let ok = check("schedule", Level::Ok, "runs");
        let cases = [
            ("nothing checked yet", None, Some(false), "Not checked yet"),
            (
                "a critical check",
                Some(vec![other.clone(), pending.clone(), critical]),
                Some(false),
                "Not protecting",
            ),
            (
                "no sites found",
                Some(vec![other.clone(), no_sites]),
                Some(true),
                "No sites found yet",
            ),
            (
                "changes waiting",
                Some(vec![other.clone(), pending.clone()]),
                Some(false),
                "Changes not applied",
            ),
            (
                "no cron file",
                Some(vec![other.clone(), ok.clone()]),
                Some(false),
                "Only runs while this screen is open",
            ),
            (
                "another warning",
                Some(vec![ok.clone(), pending.clone(), other]),
                Some(true),
                "A check",
            ),
            ("all well", Some(vec![ok]), Some(true), "Protected"),
        ];
        for (what, checks, cron, expected) in cases {
            let report = checks.map(report);
            let keeps_running = cron == Some(true);
            assert_eq!(
                verdict(report.as_ref(), cron, keeps_running).headline,
                expected,
                "{what}"
            );
        }
    }

    /// On a host that keeps running, every new block waits a few minutes
    /// for the next render: that is the schedule working, not something
    /// to press `a` about. It still says so, and that `a` does it now.
    #[test]
    fn changes_waiting_on_a_host_that_keeps_running_are_not_a_warning() {
        let report = report(vec![check(
            "script-fresh",
            Level::Warn,
            "the rules changed since the last apply",
        )]);

        let status = verdict(Some(&report), Some(true), true);

        assert_eq!(
            (status.level, status.headline.as_str()),
            (Level::Ok, "Protected"),
            "{status:?}"
        );
        assert!(status.advice.contains("a applies"), "{status:?}");
    }

    /// A warning whose detail lists every user agent it is about still
    /// leaves the status's last line, the count of blocks, in its panel.
    #[test]
    fn a_long_warning_leaves_the_count_of_blocks_on_screen() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);
        let agents = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) (231 refused), ".repeat(10);
        dashboard.health = Some((
            report(vec![check(
                "turned-away",
                Level::Warn,
                &format!("50 user agent(s) are now being turned away: {agents}"),
            )]),
            0,
        ));

        let content = drawn(&mut dashboard);

        assert!(content.contains("blocked now"), "{content}");
        assert!(
            !content.contains("Windows NT"),
            "the list is in the status:\n{content}"
        );
    }

    /// The four things it is for, and none of the advanced panels.
    #[test]
    fn the_simple_screen_shows_its_four_panels_and_leaves_the_rest_out() {
        let db = Db::open_in_memory().unwrap();
        let content = drawn(&mut simple(&db));

        for panel in ["Status", "Who can visit", "Countries", "Running"] {
            assert!(content.contains(panel), "no {panel}:\n{content}");
        }
        for hidden in [
            "Old browsers",
            "Crawler IP ranges",
            "Firewall script",
            "Scheduled",
        ] {
            assert!(!content.contains(hidden), "{hidden} is shown:\n{content}");
        }
    }

    /// Down from AI bots goes to the countries: old browsers has no row.
    #[test]
    fn down_from_the_last_category_moves_to_the_countries() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);
        dashboard.list_state.select(Some(SIMPLE_POLICY_ROWS - 1));

        press(&mut dashboard, &db, KeyCode::Down);

        assert_eq!(dashboard.focus, Focus::Countries);
    }

    /// Humans only takes the site out of search engines, so it asks, and
    /// the answer it starts on is the one that changes nothing.
    #[test]
    fn humans_only_asks_first_and_starts_on_no() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);

        press(&mut dashboard, &db, KeyCode::Enter);
        let (_, message) = press(&mut dashboard, &db, KeyCode::Enter);

        assert!(!db.get_humans_only().unwrap(), "message: {message:?}");
        assert!(dashboard.popup.is_none());

        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Up);
        let (outcome, message) = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(db.get_humans_only().unwrap(), "message: {message:?}");
    }

    /// Turning humans only off is going back to the categories as they
    /// were, which needs no second look.
    #[test]
    fn humans_only_switches_off_without_asking() {
        let db = Db::open_in_memory().unwrap();
        db.set_humans_only(true).unwrap();
        let mut dashboard = simple(&db);

        let (outcome, _) = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::Mutated);
        assert!(!db.get_humans_only().unwrap());
    }

    fn on_keep_running(db: &Db) -> Dashboard {
        let mut dashboard = simple(db);
        dashboard.focus = Focus::Essentials;
        dashboard.essentials_state.select(Some(ESSENTIAL_ROWS - 1));
        dashboard
    }

    /// On writes to /etc as root, so it asks, and `App` does the writing.
    #[test]
    fn keep_running_asks_and_hands_the_switch_to_app() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = on_keep_running(&db);

        let (asked, _) = press(&mut dashboard, &db, KeyCode::Enter);
        let (outcome, _) = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(asked, KeyOutcome::Consumed);
        assert_eq!(outcome, KeyOutcome::KeepRunning(true));
    }

    #[test]
    fn keep_running_switches_off_without_asking() {
        let db = Db::open_in_memory().unwrap();
        db.set_auto_apply(true).unwrap();
        db.set_auto_apply_firewall(true).unwrap();
        let mut dashboard = on_keep_running(&db);

        let (outcome, _) = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::KeepRunning(false));
    }

    /// The detectors are shown, not switched: each has its own switch on
    /// the advanced screen, and opening the row goes to them.
    #[test]
    fn the_detector_row_changes_nothing_and_opens_the_checks() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);
        dashboard.focus = Focus::Essentials;
        dashboard.essentials_state.select(Some(0));

        let (outcome, _) = press(&mut dashboard, &db, KeyCode::Enter);

        assert_eq!(outcome, KeyOutcome::ShowDetectors);
        for d in Detector::ALL {
            assert_eq!(
                d.is_enabled(&db).unwrap(),
                d.spec().enabled_default,
                "{}",
                d.id()
            );
        }
    }

    /// The status counts blocks in force: an allow, a block that was
    /// switched off and one that has expired are not blocking anyone.
    #[test]
    fn the_status_counts_only_the_blocks_in_force() {
        let db = Db::open_in_memory().unwrap();
        let rule = |address: &str, action| crate::db::NewFirewallRule {
            address: address.to_string(),
            port: None,
            action,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        };
        use crate::db::FirewallAction::{Allow, Block};
        db.add_firewall_rule(&rule("203.0.113.1", Block)).unwrap();
        db.add_firewall_rule_with_ttl(&rule("203.0.113.2", Block), 3_600)
            .unwrap();
        db.add_firewall_rule(&rule("203.0.113.3", Allow)).unwrap();
        let off = db.add_firewall_rule(&rule("203.0.113.4", Block)).unwrap();
        db.set_firewall_rule_enabled(off, false).unwrap();
        db.add_firewall_rule_with_ttl(&rule("203.0.113.5", Block), -1)
            .unwrap();

        let content = drawn(&mut simple(&db));

        assert!(
            content.contains("2 address(es) blocked now, 2 of them in the last day"),
            "{content}"
        );
    }

    /// Tab goes round the three panels, and Shift-Tab the other way.
    #[test]
    fn tab_goes_round_the_three_panels_both_ways() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);
        let mut forward = Vec::new();
        for _ in 0..3 {
            press(&mut dashboard, &db, KeyCode::Tab);
            forward.push(dashboard.focus);
        }
        let mut back = Vec::new();
        for _ in 0..3 {
            press(&mut dashboard, &db, KeyCode::BackTab);
            back.push(dashboard.focus);
        }

        assert_eq!(
            forward,
            [Focus::Countries, Focus::Essentials, Focus::Categories]
        );
        assert_eq!(
            back,
            [Focus::Essentials, Focus::Countries, Focus::Categories]
        );
    }

    /// Up and Down cross from one panel to the next at either end, and
    /// land on the row next to where they left.
    #[test]
    fn up_and_down_cross_between_panels_at_their_ends() {
        let db = Db::open_in_memory().unwrap();
        db.set_country_selected("CN", true).unwrap();
        let cases = [
            (
                "Up from the country list's first row",
                (Focus::Countries, 0),
                KeyCode::Up,
                (Focus::Categories, SIMPLE_POLICY_ROWS - 1),
            ),
            (
                "Down from the last country",
                (Focus::Countries, 1),
                KeyCode::Down,
                (Focus::Essentials, 0),
            ),
            (
                "Up from the Running panel's first row",
                (Focus::Essentials, 0),
                KeyCode::Up,
                (Focus::Countries, 1),
            ),
            (
                "Down from the Running panel's last row",
                (Focus::Essentials, ESSENTIAL_ROWS - 1),
                KeyCode::Down,
                (Focus::Essentials, ESSENTIAL_ROWS - 1),
            ),
        ];
        for (what, (focus, row), key, (expected_focus, expected_row)) in cases {
            let mut dashboard = simple(&db);
            dashboard.focus = focus;
            dashboard.countries_state.select(Some(row));
            dashboard.essentials_state.select(Some(row));

            press(&mut dashboard, &db, key);

            let selected = match dashboard.focus {
                Focus::Countries => dashboard.countries_state.selected(),
                Focus::Essentials => dashboard.essentials_state.selected(),
                _ => dashboard.list_state.selected(),
            };
            assert_eq!(
                (dashboard.focus, selected),
                (expected_focus, Some(expected_row)),
                "{what}"
            );
        }
    }

    /// The panel's title says what the countries listed do, in words, on
    /// the simple screen; the advanced one keeps its shorter names.
    #[test]
    fn the_countries_title_says_what_the_mode_does() {
        let db = Db::open_in_memory().unwrap();
        // An allowlist of none is "only trusted IPs", a third mode.
        db.set_country_selected("CN", true).unwrap();
        for (mode, expected) in [
            (crate::db::GeoMode::Blocklist, "these are blocked"),
            (crate::db::GeoMode::Allowlist, "only these are allowed"),
        ] {
            db.set_geo_mode(mode).unwrap();
            let content = drawn(&mut simple(&db));
            assert!(content.contains(expected), "{mode:?}:\n{content}");
        }
    }

    /// It keeps running only with both auto-applies on and a cron file to
    /// run them; a probe that has not looked for the file yet is no
    /// reason to say it does not.
    #[test]
    fn keep_running_is_on_only_with_both_auto_applies_and_a_cron_file() {
        let db = Db::open_in_memory().unwrap();
        let cases = [
            ("everything", (true, true, Some(true)), true),
            ("not looked for the cron file", (true, true, None), true),
            ("no cron file", (true, true, Some(false)), false),
            ("sites only", (true, false, Some(true)), false),
            ("firewall only", (false, true, Some(true)), false),
        ];
        for (what, (sites, firewall, cron), expected) in cases {
            let mut dashboard = simple(&db);
            dashboard.auto_apply = sites;
            dashboard.auto_apply_firewall = firewall;
            dashboard.cron_installed = cron;
            assert_eq!(dashboard.keeps_running(), expected, "{what}");
        }
    }

    /// The simple screen has no Sites screen to name, so humans only says
    /// to press `a`, the key that is on it.
    #[test]
    fn humans_only_on_the_simple_screen_says_to_press_a() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);

        press(&mut dashboard, &db, KeyCode::Enter);
        press(&mut dashboard, &db, KeyCode::Up);
        let (_, message) = press(&mut dashboard, &db, KeyCode::Enter);

        assert!(
            message.as_deref().is_some_and(|m| m.contains("Press a")),
            "message: {message:?}"
        );
    }

    /// Every row of the simple screen says what it is, as the advanced
    /// screen's do.
    #[test]
    fn every_simple_row_explains_itself() {
        let db = Db::open_in_memory().unwrap();
        let mut dashboard = simple(&db);
        let mut titles = Vec::new();
        for _ in 0..(SIMPLE_POLICY_ROWS + 1 + ESSENTIAL_ROWS) {
            titles.push(dashboard.explain().title);
            press(&mut dashboard, &db, KeyCode::Down);
        }
        for expected in [
            "Humans only",
            "Block attackers in logs",
            "Keep running by itself",
        ] {
            assert!(titles.iter().any(|t| t == expected), "{titles:?}");
        }
    }
}
