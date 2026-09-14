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

//! Regenerates the screenshots in `docs/screenshots/`.
//!
//! ```text
//! cargo run --example screenshots
//! ```
//!
//! **Why this exists rather than someone pressing a key and cropping a
//! terminal.** This tool reads real SSH and NGINX logs. A hand-taken
//! screenshot of the Dynamic Protection screen would publish the
//! attacker addresses hitting the maintainer's server and the hostnames
//! of every site on it. Everything below is seeded fiction: addresses
//! from the documentation ranges reserved by RFC 5737 (192.0.2.0/24,
//! 198.51.100.0/24, 203.0.113.0/24) and `example.com` hostnames, in a
//! throwaway database under a tempdir. No host state is read.
//!
//! The second reason is that it is reproducible. The screens render
//! through `TestBackend`, the same in-memory backend the unit tests use,
//! so the output is a pure function of the seed — a screenshot that goes
//! stale shows up as a diff rather than as a picture nobody re-took.
//!
//! Output is SVG rather than PNG: it stays sharp at any zoom, it is a
//! text diff in review, and it needs no rasteriser on the machine that
//! generates it. Both GitHub and crates.io render it, as long as the
//! README references it by absolute `raw.githubusercontent.com` URL —
//! relative image paths do not resolve on crates.io.

use std::path::PathBuf;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

use stop_bots::app::App;
use stop_bots::db::{
    BotStatus, Category, Db, FirewallAction, GeoMode, NewBot, NewFirewallRule, Policy, Source,
};
use stop_bots::nginx::SiteApplyStatus;
use stop_bots::tui::{self, Screen, Theme};

/// Wide enough that no panel elides, short enough to stay readable when
/// GitHub scales the image into a README column.
const COLS: u16 = 108;

// `App::new` builds an `EventHandler`, which spawns the terminal-event
// task — so this needs a runtime even though nothing here awaits an event.
#[tokio::main]
async fn main() -> Result<()> {
    silence_the_event_reader();
    // The Night Grid palette is 24-bit; without this the screens render
    // in the terminal's own cyan, and the screenshot would show whatever
    // the generating machine's terminal happened to be.
    std::env::set_var("COLORTERM", "truecolor");
    // The header names the host. This one is fiction, like the rest.
    tui::override_hostname("web-01");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/screenshots");
    std::fs::create_dir_all(&out)?;

    // A tempdir, not the host: `SiteSettings` is handed this as its NGINX
    // root, and pointing it at /etc/nginx would put the maintainer's real
    // sites in the picture. It stays empty — the sites below are written
    // straight into the database, which is the only thing this screen
    // reads. (Only the `r` rescan key walks the root, and nothing here
    // presses it.)
    let workspace = tempdir()?;
    let root = workspace.join("nginx");
    std::fs::create_dir_all(&root)?;

    let db = Db::open(workspace.join("stop-bots.db"))?;
    seed(&db)?;

    // `reload_nginx: false` — nothing here may touch systemctl or nginx.
    let mut app = App::new(db, root.clone(), false, None)?;
    app.theme = Theme::Dark;

    // After `App::new`, not before: it is what registers the bot-list and
    // feed sources, so anything that dresses those rows has to come second.
    seed_after_startup(&app.db)?;

    // `App::new` schedules a read of the SSH log, which the footer would
    // otherwise report as in flight in every screenshot.
    app.jobs_in_flight.clear();

    // A health probe, so the status strip reads as it does on a real host
    // rather than "not checked yet". The values are the ones a correctly
    // set-up host reports, bar the one warning worth showing.
    stop_bots::health::store_probe(
        &app.db,
        &stop_bots::health::Probe {
            live_rules: Some(6_506),
            live_backend: Some("nftables".into()),
            firewall_persists: Some(false),
            unit_active: Some(true),
            unit_binary: None,
            db_free_bytes: Some(140 * 1024 * 1024 * 1024),
            ssh_log_readable: Some(true),
            access_log_readable: Some(true),
        },
    )?;

    app.dashboard.refresh(&app.db)?;
    app.bot_settings.refresh(&app.db)?;
    app.site_settings.refresh(&app.db)?;
    app.dynamic_protection
        .refresh(&app.db, Some(SSH_LOG_FIXTURE))?;

    // The status tags are computed off the main thread and folded back
    // through an event; with no event loop running they would sit at
    // "CHECKING" forever. One of each, because the interesting thing about
    // this panel is that it tells them apart.
    app.site_settings
        .finish_status_check(vec![SiteApplyStatus::UpToDate, SiteApplyStatus::Stale]);

    // Bot settings shows results only for a typed query — that is the
    // point of its search box. Type one, so the screenshot shows the
    // screen doing its job rather than an empty prompt.
    // `/` opens the search box; the rest is the query. "bot" matches
    // across all three categories, which is the point.
    let mut press = |code: KeyCode| -> Result<()> {
        app.bot_settings
            .handle_key(KeyEvent::from(code), &app.db, &mut app.message)?;
        Ok(())
    };
    press(KeyCode::Char('/'))?;
    for c in "bot".chars() {
        press(KeyCode::Char(c))?;
    }

    // Height per screen rather than one size for all: the Dashboard
    // stacks five panels and needs every row, while Dynamic Protection at
    // the same height is two lists floating in eighteen blank lines. The
    // numbers are the shortest terminal on which nothing is cut off.
    for (screen, name, rows) in [
        (Screen::Dashboard, "dashboard", 38),
        (Screen::BotSettings, "bot-settings", 19),
        (Screen::SiteSettings, "site-settings", 16),
        (Screen::DynamicProtection, "dynamic-protection", 27),
    ] {
        app.screen = screen;
        let path = out.join(format!("{name}.svg"));
        std::fs::write(&path, render_svg(&mut app, rows)?)?;
        println!("wrote {}", path.display());
    }

    // The database holds seeded fiction and nothing else, but leaving a
    // directory per run in /tmp is still litter.
    std::fs::remove_dir_all(&workspace)?;

    Ok(())
}

/// `App::new` spawns a task that reads terminal events, and there is no
/// terminal here — crossterm's reader panics on that worker thread the
/// moment it runs. It is harmless (nothing in this example awaits an
/// event, and a panicking worker does not take the process down), but an
/// unexplained panic in the output of a generator makes it look broken.
/// Swallow exactly that one, and let every other panic through unchanged.
fn silence_the_event_reader() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_the_reader = info
            .location()
            .is_some_and(|l| l.file().contains("crossterm"));
        if !from_the_reader {
            default_hook(info);
        }
    }));
}

/// Draws the current screen through the same in-memory backend the unit
/// tests use, then converts the resulting cell grid to SVG.
fn render_svg(app: &mut App, rows: u16) -> Result<String> {
    let mut terminal = Terminal::new(TestBackend::new(COLS, rows))?;
    terminal.draw(|frame| tui::render(app, frame))?;
    Ok(svg(terminal.backend().buffer()))
}

// ---- seeding ----

fn seed(db: &Db) -> Result<()> {
    db.upsert_source(&Source {
        id: "well-known-bots".into(),
        name: "ArcJet Well-Known Bots".into(),
        url: "https://example.invalid/well-known-bots.json".into(),
        last_fetched_at: Some(1_757_000_000),
        bot_count: 0,
    })?;

    // A handful of real bot names — these are public identifiers from
    // published lists, not anybody's data.
    let bots: [(&str, &str, Cat); 8] = [
        ("gptbot", "GPTBot", Cat::Ai),
        ("claudebot", "ClaudeBot", Cat::Ai),
        ("ccbot", "CCBot", Cat::Ai),
        ("bytespider", "Bytespider", Cat::Ai),
        ("googlebot", "Googlebot", Cat::Search),
        ("bingbot", "Bingbot", Cat::Search),
        ("nikto", "Nikto", Cat::Scanner),
        ("sqlmap", "sqlmap", Cat::Scanner),
    ];
    for (slug, name, cat) in bots {
        db.upsert_bot(&NewBot {
            slug: slug.into(),
            name: name.into(),
            is_ai: matches!(cat, Cat::Ai),
            is_search_engine: matches!(cat, Cat::Search),
            is_scanner: matches!(cat, Cat::Scanner),
            user_agent_pattern: name.to_lowercase(),
            source_id: "well-known-bots".into(),
        })?;
    }
    // One explicit override, so the screenshot shows the feature rather
    // than eight rows all reading "category default".
    db.set_bot_status("bingbot", BotStatus::Allowed)?;

    db.set_category_default(Category::Scanner, Policy::Blocked)?;
    db.set_category_default(Category::Ai, Policy::Blocked)?;
    db.set_category_default(Category::Search, Policy::Allowed)?;

    db.set_geo_mode(GeoMode::Blocklist)?;
    for (code, cidrs) in [("CN", 4_312), ("RU", 2_190)] {
        db.replace_country_ranges(code, &synthetic_cidrs(cidrs))?;
        db.set_country_selected(code, true)?;
    }

    // Documentation-range addresses only (RFC 5737).
    for address in ["192.0.2.44", "198.51.100.17", "203.0.113.9", "192.0.2.201"] {
        db.add_firewall_rule(&NewFirewallRule {
            address: address.into(),
            port: None,
            action: FirewallAction::Block,
        })?;
    }

    // `seen_at` is fixed, not `now()`: a screenshot that changes every
    // time it is regenerated is a diff nobody can review.
    const SEEN_AT: i64 = 1_757_500_000;
    let hits: std::collections::HashMap<String, u64> = [
        (
            "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            4_812,
        ),
        ("Mozilla/5.0 (compatible; ClaudeBot/1.0)", 3_004),
        (
            "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)",
            2_671,
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36",
            1_988,
        ),
        (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            1_204,
        ),
        ("python-requests/2.31.0", 906),
        (
            "Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)",
            742,
        ),
        ("curl/8.5.0", 318),
    ]
    .into_iter()
    .map(|(ua, n)| (ua.to_string(), n))
    .collect();
    db.record_user_agent_hits(&hits, SEEN_AT)?;
    db.block_user_agent("Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)")?;

    Ok(())
}

/// The parts of the seed that need the rows `App::new` creates.
fn seed_after_startup(db: &Db) -> Result<()> {
    // The paths a real install would have found, rather than the tempdir's
    // — a screenshot with `/tmp/stop-bots-screenshots-1203097/` in it
    // teaches the reader nothing except that it was faked.
    for host in ["example.com", "shop.example.com"] {
        db.upsert_site(host, &format!("/etc/nginx/sites-enabled/{host}"))?;
    }

    // Mark the bot lists fetched, with the counts they really do return, so
    // the Summary panel reads "up to date" instead of "3 need updating" —
    // a screenshot of a tool that has never run is a screenshot of nothing.
    for (id, bot_count) in [
        ("well-known-bots", 1_384),
        ("ai-robots-txt", 62),
        ("nginx-bad-bots", 597),
    ] {
        db.touch_source(id, bot_count)?;
    }

    // A plausible run history, so the Scheduled tasks panel isn't nine
    // rows of "last ran never". Offsets from now rather than fixed
    // timestamps: the panel renders "N minutes ago", which stays the same
    // string across regenerations only if the offset is what's pinned.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    for (job_id, minutes_ago, summary) in [
        ("update_ip_ranges", 44, "4 sources, 21,904 ranges"),
        ("record_access_stats", 3, "8 user agents"),
        ("render_firewall", 44, "6,506 rules"),
        ("block_scanners", 3, "2 blocked"),
        ("block_web_scanners", 3, "1 blocked"),
        ("block_spoofed_crawlers", 3, "nothing new"),
        ("block_probe_paths", 3, "1 blocked"),
    ] {
        db.set_cron_last_run(job_id, now - minutes_ago * 60, summary)?;
    }

    Ok(())
}

enum Cat {
    Ai,
    Search,
    Scanner,
}

/// A plausible number of CIDRs for a country, so the Dashboard's counts
/// don't all read `1`. The addresses are never rendered — only counted.
fn synthetic_cidrs(n: usize) -> Vec<String> {
    // Distinct values, or the database collapses them and the panel
    // reports 256 ranges for every country.
    (0..n)
        .map(|i| format!("100.64.{}.{}/32", i / 256, i % 256))
        .collect()
}

/// Failed logins from documentation addresses, in the format `sshlog`
/// parses. Deliberately not a copy of any real auth.log.
const SSH_LOG_FIXTURE: &str = "\
Sep 10 04:11:02 host sshd[2201]: Failed password for invalid user admin from 192.0.2.44 port 51022 ssh2
Sep 10 04:11:04 host sshd[2202]: Failed password for invalid user root from 192.0.2.44 port 51024 ssh2
Sep 10 04:11:07 host sshd[2203]: Failed password for invalid user test from 192.0.2.44 port 51026 ssh2
Sep 10 04:12:31 host sshd[2210]: Failed password for invalid user ubuntu from 198.51.100.17 port 39114 ssh2
Sep 10 04:12:33 host sshd[2211]: Failed password for invalid user deploy from 198.51.100.17 port 39118 ssh2
Sep 10 04:19:55 host sshd[2288]: Failed password for invalid user git from 203.0.113.9 port 44002 ssh2
Sep 10 04:20:01 host sshd[2290]: Failed password for invalid user postgres from 203.0.113.9 port 44010 ssh2
Sep 10 04:20:08 host sshd[2291]: Failed password for invalid user oracle from 203.0.113.9 port 44018 ssh2
Sep 10 04:31:40 host sshd[2402]: Failed password for invalid user admin from 203.0.113.77 port 60112 ssh2
Sep 10 04:44:12 host sshd[2510]: Failed password for root from 192.0.2.201 port 33440 ssh2
";

/// A private scratch directory. Not `tempfile::TempDir`: that is a
/// dev-dependency, and an example is not a test — it links against the
/// normal dependency set.
fn tempdir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("stop-bots-screenshots-{}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ---- cell grid -> SVG ----
//
// Character cells are placed on an exact grid: every run of text carries a
// `textLength` of exactly `len * CELL_W`, so the columns line up whatever
// monospace font the viewer resolves. Without that, a reader whose default
// monospace has a different advance width sees a picture of a broken
// layout and blames the application.

const CELL_W: f32 = 8.4;
const CELL_H: f32 = 18.0;
const FONT_SIZE: f32 = 14.0;
/// The distance from the top of a cell down to the text baseline.
const BASELINE: f32 = 13.5;
const PAD: f32 = 12.0;

/// The palette the SVG resolves named ANSI colours through. Chosen to
/// match a common dark terminal theme rather than any one terminal's
/// exact values — the point is a legible picture, not a colour-accurate
/// reproduction of the maintainer's setup.
const FG_DEFAULT: &str = "#c8d0da";
const BG_DEFAULT: &str = "#12161c";

fn svg(buffer: &Buffer) -> String {
    let (cols, rows) = (buffer.area.width, buffer.area.height);
    let w = cols as f32 * CELL_W + PAD * 2.0;
    let h = rows as f32 * CELL_H + PAD * 2.0;

    let mut s = String::new();
    s.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w:.0} {h:.0}" width="{w:.0}" height="{h:.0}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,'DejaVu Sans Mono',monospace" font-size="{FONT_SIZE}">
<rect width="100%" height="100%" rx="8" fill="{BG_DEFAULT}"/>
"#
    ));

    // Backgrounds first, as their own pass: a run's rect must sit under
    // the text of its neighbours as well as its own, and interleaving
    // them would let a rect paint over the previous run's glyphs.
    for y in 0..rows {
        for run in runs(buffer, y) {
            if let Some(bg) = run.bg {
                s.push_str(&format!(
                    r#"<rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" fill="{}"/>{}"#,
                    PAD + run.col as f32 * CELL_W,
                    PAD + y as f32 * CELL_H,
                    run.text.chars().count() as f32 * CELL_W,
                    CELL_H,
                    bg,
                    "\n"
                ));
            }
        }
    }

    for y in 0..rows {
        for run in runs(buffer, y) {
            if run.text.trim().is_empty() {
                continue;
            }
            let len = run.text.chars().count() as f32 * CELL_W;
            let weight = if run.bold {
                r#" font-weight="bold""#
            } else {
                ""
            };
            let opacity = if run.dim { r#" opacity="0.55""# } else { "" };
            s.push_str(&format!(
                r#"<text x="{:.1}" y="{:.1}" fill="{}" textLength="{:.1}" lengthAdjust="spacingAndGlyphs" xml:space="preserve"{weight}{opacity}>{}</text>{}"#,
                PAD + run.col as f32 * CELL_W,
                PAD + y as f32 * CELL_H + BASELINE,
                run.fg,
                len,
                escape(&run.text),
                "\n"
            ));
        }
    }

    s.push_str("</svg>\n");
    s
}

struct Run {
    col: u16,
    text: String,
    fg: String,
    bg: Option<String>,
    bold: bool,
    dim: bool,
}

/// Groups row `y` into maximal spans sharing one style, so a full-width
/// row costs one `<text>` rather than 108 of them.
fn runs(buffer: &Buffer, y: u16) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    for x in 0..buffer.area.width {
        let Some(cell) = buffer.cell((x, y)) else {
            continue;
        };
        let reversed = cell.modifier.contains(Modifier::REVERSED);
        let (fg_color, bg_color) = if reversed {
            (cell.bg, cell.fg)
        } else {
            (cell.fg, cell.bg)
        };
        let fg = hex(fg_color).unwrap_or_else(|| FG_DEFAULT.to_string());
        // A reversed cell whose colours are both "default" still has to
        // paint a block, or the selected row in a list disappears.
        let bg = hex(bg_color).or_else(|| reversed.then(|| FG_DEFAULT.to_string()));
        let bold = cell.modifier.contains(Modifier::BOLD);
        let dim = cell.modifier.contains(Modifier::DIM);

        match out.last_mut() {
            Some(run) if run.fg == fg && run.bg == bg && run.bold == bold && run.dim == dim => {
                run.text.push_str(cell.symbol());
            }
            _ => out.push(Run {
                col: x,
                text: cell.symbol().to_string(),
                fg,
                bg,
                bold,
                dim,
            }),
        }
    }
    out
}

/// `None` for `Color::Reset`, which means "whatever the terminal's
/// default is" — the caller decides what that is, and for a background it
/// means painting nothing at all.
fn hex(color: Color) -> Option<String> {
    let named = match color {
        Color::Reset => return None,
        Color::Black => "#1c2028",
        Color::Red => "#e05561",
        Color::Green => "#8cc265",
        Color::Yellow => "#d18f52",
        Color::Blue => "#4aa5f0",
        Color::Magenta => "#c162de",
        Color::Cyan => "#42b3c2",
        Color::Gray => "#a1a8b3",
        Color::DarkGray => "#5c6370",
        Color::LightRed => "#ff616e",
        Color::LightGreen => "#a5e075",
        Color::LightYellow => "#f0a45d",
        Color::LightBlue => "#4dc4ff",
        Color::LightMagenta => "#de73ff",
        Color::LightCyan => "#4cd1e0",
        Color::White => "#e6e6e6",
        Color::Rgb(r, g, b) => return Some(format!("#{r:02x}{g:02x}{b:02x}")),
        Color::Indexed(i) => return Some(indexed(i)),
    };
    Some(named.to_string())
}

/// The xterm 256-colour cube, computed rather than tabulated.
fn indexed(i: u8) -> String {
    match i {
        // The first sixteen are the named colours above, which
        // `hex` has already covered by name wherever ratatui uses them;
        // an explicit `Indexed(0..16)` is rare and gets the same values.
        0..=15 => {
            const BASE: [&str; 16] = [
                "#1c2028", "#e05561", "#8cc265", "#d18f52", "#4aa5f0", "#c162de", "#42b3c2",
                "#a1a8b3", "#5c6370", "#ff616e", "#a5e075", "#f0a45d", "#4dc4ff", "#de73ff",
                "#4cd1e0", "#e6e6e6",
            ];
            BASE[i as usize].to_string()
        }
        16..=231 => {
            let i = i - 16;
            let level = |v: u8| if v == 0 { 0u8 } else { 55 + v * 40 };
            let (r, g, b) = (level(i / 36), level((i % 36) / 6), level(i % 6));
            format!("#{r:02x}{g:02x}{b:02x}")
        }
        232..=255 => {
            let v = 8 + (i - 232) * 10;
            format!("#{v:02x}{v:02x}{v:02x}")
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
