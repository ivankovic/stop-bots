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
//! screenshot of the Firewall screen would publish the
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
//! TUI output is SVG rather than PNG: it stays sharp at any zoom, it is a
//! text diff in review, and it needs no rasteriser on the machine that
//! generates it. Both GitHub and crates.io render it, as long as the
//! README references it by absolute `raw.githubusercontent.com` URL —
//! relative image paths do not resolve on crates.io.
//!
//! `tour.gif` is the one exception, and it buys something the stills
//! cannot show: that `1`-`4` are how you move between the screens. Its
//! frames are the same [`svg`] output rasterised, so it cannot drift from
//! the stills beside it. It gives up two of the three properties above —
//! it is a binary blob in review, and it needs fonts on the generating
//! machine — which is why it is one file rather than the format
//! everything uses. See [`tour_gif`].
//!
//! The web console's pages come from the same seed, rendered through the
//! real router in-process (the way `tests/web.rs` drives it) and written
//! as HTML under `target/web-screenshots/`. A browser has to rasterise
//! those: the generator runs whichever of Firefox or Chromium it finds
//! headless, in the light theme, and writes PNG. With neither on the
//! machine it says so and leaves the previous PNGs alone. The TUI is
//! shown dark and the console light on purpose — one of each, so the
//! README shows both palettes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::{header, Request};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use resvg::tiny_skia;
use resvg::usvg;
use tower::ServiceExt;

use stop_bots::app::App;
use stop_bots::db::{
    BotStatus, Category, Db, FirewallAction, GeoMode, NewBot, NewFirewallRule, Policy, Source,
};
use stop_bots::nginx::SiteApplyStatus;
use stop_bots::tui::{self, Screen, Theme};
use stop_bots::web::{auth, server, state::AppState};

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
    stop_bots::host::override_name("web-01");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/screenshots");
    std::fs::create_dir_all(&out)?;

    // A tempdir, not the host: `Nginx` is handed this as its NGINX
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
            nftables_conf_flushes: None,
            unit_active: Some(true),
            unit_binary: None,
            // The fiction is a host install, so the generated files are in
            // the stock place and nothing is stranded anywhere else.
            turned_away: Vec::new(),
            conf_d_path: Some(stop_bots::nginx::CONF_D_DIR.to_string()),
            conf_d_exists: Some(true),
            stray_generated_files: Vec::new(),
            db_free_bytes: Some(140 * 1024 * 1024 * 1024),
            ssh_log_readable: Some(true),
            access_log_readable: Some(true),
            access_log_path: None,
            access_log_clients: Some((11_284, 11_310)),
            // The fiction is a host install, so the container checks have
            // nothing to say and add no line to the strip.
            nginx_home: stop_bots::health::NginxHome::Host,
            managed_dir_in_container: None,
            container_shares_host_network: None,
            firewall_covers_forward: Some(true),
        },
    )?;

    app.dashboard.refresh(&app.db)?;
    app.bot_settings.refresh(&app.db)?;
    app.nginx.refresh(&app.db)?;
    app.firewall.refresh(&app.db, Some(SSH_LOG_FIXTURE))?;

    // The status tags are computed off the main thread and folded back
    // through an event; with no event loop running they would sit at
    // "CHECKING" forever. One of each, because the interesting thing about
    // this panel is that it tells them apart.
    app.nginx
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
    // stacks five panels and needs every row, while the Firewall screen at
    // the same height is two lists floating in eighteen blank lines. The
    // numbers are the shortest terminal on which nothing is cut off.
    for (screen, name, rows) in [
        (Screen::Dashboard, "dashboard", 38),
        (Screen::BotSettings, "bot-settings", 19),
        (Screen::Firewall, "firewall", 27),
        (Screen::Nginx, "nginx", 16),
    ] {
        app.screen = screen;
        let path = out.join(format!("{name}.svg"));
        std::fs::write(&path, render_svg(&mut app, rows)?)?;
        println!("wrote {}", path.display());
    }

    // The same four screens again, as one animation. The stills show what
    // each screen contains; only this shows that `1`-`4` are how you get
    // between them.
    tour_gif(&mut app, &out.join("tour.gif"))?;

    // The console, from the same database. `App` keeps its own
    // connection open; SQLite is happy to hand out a second one.
    web_screenshots(&workspace, &root, &out).await?;

    // The database holds seeded fiction and nothing else, but leaving a
    // directory per run in /tmp is still litter.
    std::fs::remove_dir_all(&workspace)?;

    Ok(())
}

/// The console pages the README shows, and the viewport each is shown in.
/// Wide enough for the Dashboard's two columns, tall enough for the top
/// of each page — the README is not the place for a 3,000px scroll.
const WEB_PAGES: [(&str, &str, u32, u32); 2] = [
    ("/", "web-dashboard", 1280, 1000),
    ("/firewall", "web-firewall", 1280, 640),
];

/// Renders each console page through the real router, stamps the light
/// theme on it, and rasterises it with a headless browser if there is one.
async fn web_screenshots(workspace: &Path, nginx_root: &Path, out: &Path) -> Result<()> {
    let db = Db::open(workspace.join("stop-bots.db"))?;
    let password = auth::generate_password()?;
    auth::set_password(&db, &password)?;
    let ssh_log = workspace.join("auth.log");
    std::fs::write(&ssh_log, SSH_LOG_FIXTURE)?;
    // `apply_for_real: false`: nothing here may touch NGINX or the
    // firewall, same as the TUI half.
    // `firewall_out` is left at its default, which the Firewall script
    // panel *shows* as `/etc/stop-bots/firewall.nft` — the path a real
    // install has, rather than this run's tempdir. Nothing here posts the
    // form that would write there; every request below is a GET.
    let state = AppState::new(db, nginx_root.to_path_buf(), Some(ssh_log), false);
    let app = server::router(state);

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("password={password}")))?,
        )
        .await?;
    let cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .context("the login should set a session cookie")?
        .to_str()?
        .split(';')
        .next()
        .unwrap_or_default()
        .to_string();
    // The pages reference the assets by absolute URL, which a file:// page
    // cannot resolve; they are written beside it and the links rewritten.
    let html_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/web-screenshots");
    std::fs::create_dir_all(&html_dir)?;
    std::fs::write(
        html_dir.join("style.css"),
        fetch(&app, &cookie, "/assets/style.css").await?,
    )?;
    std::fs::write(
        html_dir.join("htmx.min.js"),
        fetch(&app, &cookie, "/assets/htmx.min.js").await?,
    )?;

    let browser = find_browser();
    for (path, name, width, height) in WEB_PAGES {
        let html = fetch(&app, &cookie, path)
            .await?
            .replace(r#"href="/assets/style.css""#, r#"href="style.css""#)
            .replace(r#"src="/assets/htmx.min.js""#, r#"src="htmx.min.js""#)
            // Light, explicitly: the browser's own theme must not decide.
            .replace(
                r#"<html lang="en">"#,
                r#"<html lang="en" data-theme="light">"#,
            );
        let html_path = html_dir.join(format!("{name}.html"));
        std::fs::write(&html_path, html)?;

        let Some(browser) = &browser else {
            println!("no headless browser found — {name}.png left as it was");
            continue;
        };
        let png = out.join(format!("{name}.png"));
        browser.screenshot(&html_path, &png, width, height, &html_dir)?;
        println!("wrote {}", png.display());
    }
    Ok(())
}

/// One authenticated GET through the router, as the browser would make it.
async fn fetch(app: &axum::Router, cookie: &str, path: &str) -> Result<String> {
    let request = Request::builder()
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::COOKIE, cookie)
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    anyhow::ensure!(
        response.status().is_success(),
        "{path}: {}",
        response.status()
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A browser that can rasterise a page from the command line.
enum Browser {
    Firefox(PathBuf),
    Chromium(PathBuf),
}

/// Firefox first, because it is what the maintainer has; then the
/// Chromium names Debian, Fedora and Google ship under.
fn find_browser() -> Option<Browser> {
    let on_path = |name: &str| {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    };
    if let Some(path) = on_path("firefox") {
        return Some(Browser::Firefox(path));
    }
    [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ]
    .iter()
    .find_map(|name| on_path(name))
    .map(Browser::Chromium)
}

impl Browser {
    fn screenshot(
        &self,
        html: &Path,
        png: &Path,
        width: u32,
        height: u32,
        scratch: &Path,
    ) -> Result<()> {
        let url = format!("file://{}", html.display());
        let size = format!("{width},{height}");
        let output = match self {
            Browser::Firefox(bin) => {
                // A throwaway profile, so this never touches the user's
                // own and never waits on a running Firefox.
                let profile = scratch.join("firefox-profile");
                std::fs::create_dir_all(&profile)?;
                Command::new(bin)
                    .args(["--headless", "--no-remote", "--profile"])
                    .arg(&profile)
                    .arg(format!("--window-size={size}"))
                    .arg("--screenshot")
                    .arg(png)
                    .arg(&url)
                    .output()?
            }
            Browser::Chromium(bin) => Command::new(bin)
                .args(["--headless=new", "--hide-scrollbars"])
                .arg(format!("--window-size={size}"))
                .arg(format!("--screenshot={}", png.display()))
                .arg(&url)
                .output()?,
        };
        anyhow::ensure!(
            png.is_file(),
            "the browser wrote no screenshot for {}:\n{}",
            html.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
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

// ---- the animated tour ----

/// Rows every tour frame renders at.
///
/// One height for all of them, for two reasons. A GIF's frames are a
/// single size, and a real terminal does not resize itself when you press
/// `2`. It is the Dashboard's height because that screen needs all 38
/// rows: a frame with its bottom panel cut off is worse than one where a
/// shorter screen has room to spare, and the stills already show each
/// screen at its own best height.
const TOUR_ROWS: u16 = 38;

/// How long each screen holds, in hundredths of a second — the unit GIF
/// stores delays in. Long enough to read a panel, short enough that the
/// whole loop is under ten seconds.
const TOUR_DELAY_CS: u16 = 200;

/// The four screens, in the order the number keys put them in.
const TOUR: [Screen; 4] = [
    Screen::Dashboard,
    Screen::BotSettings,
    Screen::Firewall,
    Screen::Nginx,
];

/// Renders the tour and writes it as an animated GIF.
///
/// Every frame is the ordinary [`svg`] output for a screen, rasterised —
/// so the animation cannot drift from the stills beside it, and the whole
/// thing stays a pure function of the same seed.
fn tour_gif(app: &mut App, path: &Path) -> Result<()> {
    let fonts = font_database()?;

    let mut frames = Vec::with_capacity(TOUR.len());
    for screen in TOUR {
        app.screen = screen;
        let markup = render_svg(app, TOUR_ROWS)?;
        frames.push(rasterise(&markup, &fonts)?);
    }

    let (width, height, _) = frames[0];
    let file = std::fs::File::create(path)?;
    let mut encoder = gif::Encoder::new(
        std::io::BufWriter::new(file),
        u16::try_from(width)?,
        u16::try_from(height)?,
        &[],
    )?;
    encoder.set_repeat(gif::Repeat::Infinite)?;
    for (w, h, pixels) in &mut frames {
        // `from_rgba_speed` quantises to GIF's 256-entry palette and needs
        // the buffer mutable to do it. Speed 10 of 30 — these frames are
        // flat terminal colours, so there is little for a slower pass to
        // find, and speed 1 costs seconds per frame for no visible gain.
        let mut frame =
            gif::Frame::from_rgba_speed(u16::try_from(*w)?, u16::try_from(*h)?, pixels, 10);
        frame.delay = TOUR_DELAY_CS;
        encoder.write_frame(&frame)?;
    }
    drop(encoder);

    println!("wrote {}", path.display());
    Ok(())
}

/// The fonts the frames are rasterised with.
///
/// The stills never need this: an SVG names a font stack and leaves the
/// choice to whoever opens it. A GIF has to commit to actual glyphs, so
/// something has to resolve that stack here.
///
/// System fonts rather than a copy committed to the repository. That does
/// mean a machine with a different DejaVu build can produce slightly
/// different bytes, which is the same bargain the web screenshots already
/// make by rasterising through whichever browser is installed — and it is
/// better than carrying 660 KB of font binaries for one example. Missing
/// fonts are an error rather than a silent fallback: the grid only lines
/// up if the glyphs are monospace, and a proportional fallback would
/// produce a picture of a broken layout.
fn font_database() -> Result<Arc<usvg::fontdb::Database>> {
    let mut db = usvg::fontdb::Database::new();
    db.load_system_fonts();

    const WANTED: &str = "DejaVu Sans Mono";
    let have = db
        .faces()
        .any(|face| face.families.iter().any(|(name, _)| name == WANTED));
    anyhow::ensure!(
        have,
        "{WANTED} is not installed, and the tour GIF needs a monospace font to line its \
         columns up (Debian/Ubuntu: apt install fonts-dejavu-core). The SVG screenshots \
         do not need it and were still written."
    );
    db.set_monospace_family(WANTED);
    Ok(Arc::new(db))
}

/// One SVG frame to straight RGBA.
fn rasterise(markup: &str, fonts: &Arc<usvg::fontdb::Database>) -> Result<(u32, u32, Vec<u8>)> {
    let options = usvg::Options {
        fontdb: fonts.clone(),
        ..Default::default()
    };
    let tree = usvg::Tree::from_str(markup, &options).context("the generated SVG did not parse")?;
    let size = tree.size().to_int_size();
    let (width, height) = (size.width(), size.height());

    let mut pixmap =
        tiny_skia::Pixmap::new(width, height).context("frame dimensions are not a valid pixmap")?;
    // The SVG's background rect is rounded, so the pixels outside the
    // corners are transparent. GIF transparency is one palette index
    // rather than an alpha channel, and letting those corners through
    // would put a hard-edged notch on whatever the README is displayed
    // against. Filling first squares the corners off in the terminal's
    // own background, which is the quieter of the two.
    pixmap.fill(background());
    resvg::render(
        &tree,
        tiny_skia::Transform::identity(),
        &mut pixmap.as_mut(),
    );

    // tiny-skia stores premultiplied alpha; GIF wants it straight.
    let pixels = pixmap
        .pixels()
        .iter()
        .flat_map(|px| {
            let px = px.demultiply();
            [px.red(), px.green(), px.blue(), px.alpha()]
        })
        .collect();
    Ok((width, height, pixels))
}

/// [`BG_DEFAULT`] as a colour the rasteriser understands, so the two can
/// never disagree about what "the terminal background" is.
fn background() -> tiny_skia::Color {
    let hex = BG_DEFAULT.trim_start_matches('#');
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0);
    tiny_skia::Color::from_rgba8(byte(0), byte(2), byte(4), 255)
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

    // Offsets from now rather than fixed timestamps: the panels render
    // "N minutes ago", which stays the same string across regenerations
    // only if the offset is what's pinned.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

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

    // ...and then pin when they were fetched.
    //
    // `touch_source` stamps the moment it runs, and so does the
    // `register_all_sources` that `App::new` performs on the built-in
    // list. Bot settings renders that to the second, so it read "updated
    // 0s ago" on a fast machine and "updated 2s ago" on a slow one — the
    // one thing in these screenshots that changed by itself, and the
    // reason regenerating them produced a diff with nothing behind it.
    // Harmless while the output was SVG and somebody read the diff;
    // `tour.gif` is a binary blob, where an unexplained change is
    // unreviewable.
    //
    // 44 minutes because that is when "Update crawler IP ranges" below
    // last ran, and that is the job that fetches these.
    for mut source in db.list_sources()? {
        source.last_fetched_at = Some(now - 44 * 60);
        db.upsert_source(&source)?;
    }
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
