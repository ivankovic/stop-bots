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

//! Page chrome shared by every screen, and the small vocabulary of
//! components the screens are built from.
//!
//! The tabs mirror the TUI's, in the same order, because they are the same
//! product: someone who knows one should not have to learn the other.

use maud::{html, Markup, DOCTYPE};

/// Which tab is current. The same five the TUI has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Bots,
    Sites,
    Dynamic,
    Help,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Bots,
        Tab::Sites,
        Tab::Dynamic,
        Tab::Help,
    ];

    pub fn path(self) -> &'static str {
        match self {
            Tab::Dashboard => "/",
            Tab::Bots => "/bots",
            Tab::Sites => "/sites",
            Tab::Dynamic => "/dynamic",
            Tab::Help => "/help",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Bots => "Bot settings",
            Tab::Sites => "Site settings",
            Tab::Dynamic => "Dynamic Protection",
            Tab::Help => "Help",
        }
    }
}

/// A one-off notice above the page content.
pub struct Flash {
    pub text: String,
    pub ok: bool,
}

impl Flash {
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ok: true,
        }
    }

    pub fn err(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ok: false,
        }
    }
}

/// The full page: head, header, tabs, flash, content.
///
/// `csrf` is emitted as a meta tag as well as reaching the forms that need
/// it. That gives htmx somewhere to read it from for requests it issues
/// itself, and it means every authenticated page carries the token whether
/// or not it happens to render a form — which is also what lets a test
/// find it without seeding rows first.
pub fn page(tab: Tab, csrf: &str, flash: Option<Flash>, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                // No `referrer` leakage to anywhere: this console's URLs
                // name the sites and addresses being administered.
                meta name="referrer" content="no-referrer";
                title { (tab.label()) " — stop-bots" }
                meta name="csrf-token" content=(csrf);
                link rel="stylesheet" href="/assets/style.css";
                script src="/assets/htmx.min.js" defer {}
                // Applied before first paint, so a dark-theme user does
                // not get a white flash on every navigation.
                script {
                    (maud::PreEscaped(THEME_BOOTSTRAP))
                }
            }
            body hx-headers=(format!(r#"{{"x-csrf-token": "{csrf}"}}"#)) {
                header .top {
                    .brand {
                        strong { "stop-bots" }
                        span .version { (env!("CARGO_PKG_VERSION")) }
                        span .spacer {}
                        button type="button" onclick="stopBotsToggleTheme()" title="Switch between the light and dark theme" {
                            "Theme"
                        }
                        form .inline method="post" action="/logout" {
                            (csrf_field(csrf))
                            button type="submit" { "Log out" }
                        }
                    }
                    nav .tabs {
                        @for candidate in Tab::ALL {
                            @if candidate == tab {
                                a href=(candidate.path()) aria-current="page" { (candidate.label()) }
                            } @else {
                                a href=(candidate.path()) { (candidate.label()) }
                            }
                        }
                    }
                }
                main {
                    @if let Some(flash) = flash {
                        @let class = if flash.ok { "flash ok" } else { "flash err" };
                        div class=(class) { (flash.text) }
                    }
                    (content)
                }
            }
        }
    }
}

/// The login page, which has no chrome — no tabs to a UI you cannot reach
/// yet, and no logout button.
pub fn login_page(error: Option<&str>) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="referrer" content="no-referrer";
                title { "Log in — stop-bots" }
                link rel="stylesheet" href="/assets/style.css";
                script { (maud::PreEscaped(THEME_BOOTSTRAP)) }
            }
            body {
                .login-wrap {
                    section .panel {
                        h2 { "stop-bots" }
                        .panel-body {
                            @if let Some(error) = error {
                                .flash.err { (error) }
                            }
                            form method="post" action="/login" {
                                label .field {
                                    "Password"
                                    // `autofocus` so the only thing on the
                                    // page is ready to be typed into.
                                    input type="password" name="password" autocomplete="current-password" autofocus required;
                                }
                                button .primary type="submit" { "Log in" }
                            }
                            p .hint {
                                "The password was printed once, when the server first started. "
                                "Lost it? Run "
                                code { "stop-bots web --set-password" }
                                " on the host."
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A titled panel.
pub fn panel(title: &str, hint: Option<&str>, body: Markup) -> Markup {
    html! {
        section .panel {
            h2 {
                (title)
                @if let Some(hint) = hint {
                    span .hint { (hint) }
                }
            }
            (body)
        }
    }
}

/// A coloured state pill — the web equivalent of the TUI's `[ BLOCKED ]`.
pub fn pill(text: &str, kind: PillKind) -> Markup {
    let class = match kind {
        PillKind::Blocked => "pill blocked",
        PillKind::Allowed => "pill allowed",
        PillKind::Warn => "pill warn",
        PillKind::Neutral => "pill neutral",
    };
    html! { span class=(class) { (text) } }
}

#[derive(Debug, Clone, Copy)]
pub enum PillKind {
    Blocked,
    Allowed,
    Warn,
    Neutral,
}

/// The hidden CSRF field every mutating form must carry.
///
/// A function rather than a snippet to copy, so that adding a form and
/// forgetting the token is a thing you have to do on purpose. The server
/// rejects a post without it either way — this is what makes the correct
/// path the short one.
pub fn csrf_field(token: &str) -> Markup {
    html! { input type="hidden" name="csrf" value=(token); }
}

/// Placeholder row for an empty table.
pub fn empty(message: &str) -> Markup {
    html! { p .empty { (message) } }
}

/// Reads the stored theme before the body paints, and toggles it.
///
/// Inline rather than in `style.css`'s neighbour file because it must run
/// before first paint; a deferred external script would flash. It is the
/// only inline script in the UI, and the CSP names its hash rather than
/// allowing inline script generally.
const THEME_BOOTSTRAP: &str = r#"
(function () {
  try {
    var t = localStorage.getItem('stop-bots-theme');
    if (t) document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
function stopBotsToggleTheme() {
  var el = document.documentElement;
  var current = el.getAttribute('data-theme');
  if (!current) {
    current = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  var next = current === 'dark' ? 'light' : 'dark';
  el.setAttribute('data-theme', next);
  try { localStorage.setItem('stop-bots-theme', next); } catch (e) {}
}
"#;

/// SHA-256 of [`THEME_BOOTSTRAP`], for the Content-Security-Policy.
///
/// Computed at startup rather than pasted in: a hash written down by hand
/// goes stale the first time someone edits the script by one character,
/// and the symptom — the theme toggle silently doing nothing, only in
/// browsers that enforce CSP — is a genuinely nasty thing to debug.
pub fn theme_script_hash() -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(THEME_BOOTSTRAP.as_bytes());
    format!("'sha256-{}'", base64_standard(&digest))
}

/// Standard base64 (not URL-safe): what a CSP hash source is defined to
/// use.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tab_has_a_distinct_path_and_label() {
        let mut paths: Vec<&str> = Tab::ALL.iter().map(|t| t.path()).collect();
        paths.sort_unstable();
        let before = paths.len();
        paths.dedup();
        assert_eq!(before, paths.len(), "two tabs share a path: {paths:?}");
    }

    #[test]
    fn the_current_tab_is_the_only_one_marked_current() {
        let rendered = page(Tab::Bots, "t", None, html! {}).into_string();
        assert_eq!(
            rendered.matches("aria-current=\"page\"").count(),
            1,
            "exactly one tab is current"
        );
        assert!(rendered.contains(r#"<a href="/bots" aria-current="page">Bot settings</a>"#));
    }

    #[test]
    fn page_content_is_escaped() {
        // maud escapes by default; this is the test that says so out loud,
        // because every bot name and user agent on these screens is
        // attacker-controlled text.
        let content = html! { p { "<script>alert(1)</script>" } };
        let rendered = page(Tab::Dashboard, "t", None, content).into_string();

        assert!(
            !rendered.contains("<script>alert(1)</script>"),
            "a user agent must never reach the page as markup"
        );
        assert!(rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn a_flash_renders_with_the_class_that_colours_it() {
        let ok = page(Tab::Dashboard, "t", Some(Flash::ok("saved")), html! {}).into_string();
        assert!(ok.contains(r#"class="flash ok""#), "was: {ok}");

        let err = page(Tab::Dashboard, "t", Some(Flash::err("nope")), html! {}).into_string();
        assert!(err.contains(r#"class="flash err""#));
    }

    #[test]
    fn the_login_page_offers_no_way_into_the_app() {
        let rendered = login_page(None).into_string();
        for path in ["/bots", "/sites", "/dynamic", "/logout"] {
            assert!(
                !rendered.contains(path),
                "the login page must not link to {path}"
            );
        }
    }

    #[test]
    fn base64_standard_matches_known_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64_standard(input.as_bytes()),
                expected,
                "input was {input:?}"
            );
        }
    }

    #[test]
    fn the_csp_hash_tracks_the_script_it_covers() {
        let hash = theme_script_hash();
        assert!(
            hash.starts_with("'sha256-") && hash.ends_with('\''),
            "was: {hash}"
        );

        // The property that matters: it is derived, not written down. A
        // stale hash would silently disable the theme toggle under CSP.
        use sha2::{Digest, Sha256};
        let expected = format!(
            "'sha256-{}'",
            base64_standard(&Sha256::digest(THEME_BOOTSTRAP.as_bytes()))
        );
        assert_eq!(hash, expected);
    }
}
