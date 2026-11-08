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

//! User agents no browser sends: the shapes behind
//! [`crate::webserver::RequestRule::ImpossibleUserAgent`].
//!
//! ## Why shapes, not names
//!
//! A scanner that calls itself a browser names nothing a bot list can
//! carry. What gives it away is that the string is not one a browser
//! builds: every current one sends a platform comment, an engine and the
//! engine's own comment, in that order, `Mozilla/5.0 (Windows NT 10.0;
//! Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0
//! Safari/537.36`. Each of [`SHAPES`] is one way a hand-written string gets
//! that wrong.
//!
//! ## How they were chosen
//!
//! From one host's log, 2026-09-28 to 2026-11-08, judged by what each
//! client did rather than by what it said: not one address behind any of
//! these fetched a page's styles, scripts or images, and none sent a
//! referer. Most asked for `/.env` and the like; the rest were single
//! requests from cloud addresses, or one script running the same twenty
//! pages in a few seconds from one Tor exit after another. Ordinary
//! browser strings, for comparison,
//! fetched assets from 5% of their addresses and sent referers on 27% of
//! their requests.
//!
//! ## What is deliberately not here
//!
//! - **A bare `Mozilla/5.0`.** Most of what sends it is automated, but not
//!   all: on that host an AI assistant fetching for its user, a consumer
//!   VPN and two home connections each asked for the feed once with it.
//!   Not a browser is not the same as unwanted.
//! - **Chrome with no platform comment**
//!   (`Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/…`). It
//!   fetches assets: a headless renderer, link previews among them.
//! - **Runs of spaces.** One iPhone string with a gap in it was answered
//!   and may be an app's.
//!
//! [`NOT_IMPOSSIBLE`] holds those and the crawlers and in-app browsers the
//! shapes must leave alone, and the tests keep every shape off them.
//!
//! ## Matching
//!
//! [`pattern`] is what the web servers are given, matched ignoring case as
//! NGINX's `~*` and `mod_rewrite`'s `[NC]` do, and [`matching_shape`] reads
//! it with [`crate::uaregex`], so the preview is the same test.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// `(what is wrong with it, the regex for it)`.
pub const SHAPES: &[(&str, &str)] = &[
    (
        "an empty compatible comment",
        r"^Mozilla/5\.0 \(compatible\)$",
    ),
    (
        "a platform and no engine",
        r"^Mozilla/5\.0 \((Windows NT [0-9.]+(; Win64; x64)?|X11; Linux x86_64|Macintosh; Intel Mac OS X [0-9_]+)\)$",
    ),
    (
        "cut off after the engine",
        r"^Mozilla/5\.0 \([^)]*\) AppleWebKit/[0-9.]+( \(KHTML)?$",
    ),
    (
        "Chrome without its engine's comment",
        r"AppleWebKit/537\.36 Chrome/",
    ),
    ("a quote before the first word", r#"^""#),
    ("no space after Mozilla/5.0", r"^Mozilla/5\.0\("),
];

/// Every shape as one regex, for a web server's config.
pub fn pattern() -> String {
    SHAPES
        .iter()
        .map(|(_, regex)| *regex)
        .collect::<Vec<_>>()
        .join("|")
}

/// The shape `user_agent` has, if it is one of [`SHAPES`].
pub fn matching_shape(user_agent: &str) -> Option<&'static str> {
    SHAPES.iter().find_map(|(shape, regex)| {
        crate::uaregex::compiled(regex)
            .is_some_and(|compiled| compiled.is_match(user_agent))
            .then_some(*shape)
    })
}

/// What [`preview`] found in a log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preview {
    pub requests: usize,
    /// Requests the rule would have turned away.
    pub matched: usize,
    /// How many of those each shape caught, the commonest first.
    pub by_shape: Vec<(&'static str, usize)>,
    /// Distinct addresses among them.
    pub addresses: usize,
    /// Of the matched requests, the ones answered with a success.
    pub answered: usize,
    /// Matched addresses that also fetched a page's styles, scripts or
    /// images under the same user agent, as a browser does and these
    /// clients did not: the ones to look at before turning the rule on.
    ///
    /// The same user agent, not only the same address: a Tor exit or a VPN
    /// carries a script and a person at once, and on one host the only two
    /// matched addresses that fetched assets did it as other clients.
    pub browser_like: Vec<IpAddr>,
    /// A few of the requests, as logged, for a person to read.
    pub samples: Vec<String>,
}

/// Whether `path` is one of a page's own assets, which a browser fetches
/// and a script reading the page does not. Not the favicon, which plenty of
/// clients ask for on their own.
fn is_page_asset(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    !path.ends_with("favicon.ico")
        && [
            ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".woff", ".woff2",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Judges every request in `log_text` as the rule would, by its user agent,
/// and says which of the clients it would turn away behaved like a browser
/// anywhere in the log.
pub fn preview(log_text: &str) -> Preview {
    let mut preview = Preview::default();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut matched_addresses = BTreeSet::new();
    let mut matched_clients = BTreeSet::new();
    let mut fetched_assets = BTreeSet::new();
    for request in crate::accesslog::logged_requests(log_text) {
        preview.requests += 1;
        let path = request.request.split(' ').nth(1).unwrap_or_default();
        if matches!(request.status, 200 | 304) && is_page_asset(path) {
            fetched_assets.insert((request.ip, request.user_agent.clone()));
        }
        let Some(shape) = matching_shape(&request.user_agent) else {
            continue;
        };
        preview.matched += 1;
        *counts.entry(shape).or_default() += 1;
        matched_addresses.insert(request.ip);
        matched_clients.insert((request.ip, request.user_agent.clone()));
        if (200..400).contains(&request.status) {
            preview.answered += 1;
        }
        if preview.samples.len() < 5 {
            preview
                .samples
                .push(crate::accesslog::printable_sample(&format!(
                    "{} {} {} {}",
                    request.ip, request.status, request.request, request.user_agent
                )));
        }
    }
    let mut by_shape: Vec<(&'static str, usize)> = counts.into_iter().collect();
    by_shape.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    preview.by_shape = by_shape;
    preview.addresses = matched_addresses.len();
    let browser_like: BTreeSet<IpAddr> = matched_clients
        .intersection(&fetched_assets)
        .map(|(ip, _)| *ip)
        .collect();
    preview.browser_like = browser_like.into_iter().collect();
    preview
}

/// User agents no shape may match, each with the reason.
pub const NOT_IMPOSSIBLE: &[(&str, &str)] = &[
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36",
        "Chrome on Windows",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
        "Edge",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like \
         Gecko) Version/18.6 Safari/605.1.15",
        "Safari on a Mac",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Firefox on Linux",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Mobile Safari/537.36",
        "Chrome on Android",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A; wv) AppleWebKit/537.36 (KHTML, \
         like Gecko) Version/4.0 Chrome/140.0.0.0 Mobile Safari/537.36",
        "an Android app's WebView",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
         like Gecko) Mobile/15E148",
        "an iOS app's WebView, which names no browser",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
         like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/500.0.0.0]",
        "Facebook's in-app browser",
    ),
    (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot",
    ),
    (
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, \
         like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; \
         +http://www.google.com/bot.html)",
        "Googlebot's smartphone crawler",
    ),
    (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; \
         +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36",
        "Bingbot, which sends no platform",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like \
         Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
        "Applebot",
    ),
    (
        "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
        "certificate renewal",
    ),
    (
        "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
        "an uptime monitor, with a plus where the space goes",
    ),
    (
        "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
        "Discord's link previews",
    ),
    ("Mozilla/5.0", "a bare Mozilla/5.0, left out on purpose"),
    (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Safari/537.36",
        "Chrome with no platform, a headless renderer, left out on purpose",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The test that earns a place on someone's server: no shape matches a
    /// browser, an in-app browser, a crawler or a monitor.
    #[test]
    fn no_shape_matches_a_browser_or_a_crawler() {
        for (user_agent, why) in NOT_IMPOSSIBLE {
            assert_eq!(
                matching_shape(user_agent),
                None,
                "matches {why}: {user_agent:?}"
            );
        }
    }

    /// The strings the shapes were read off, from that host's log.
    #[test]
    fn the_strings_seen_are_all_caught() {
        const SEEN: &[(&str, &str)] = &[
            ("Mozilla/5.0 (compatible)", "an empty compatible comment"),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "a platform and no engine",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64)",
                "a platform and no engine",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "cut off after the engine",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML",
                "cut off after the engine",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "cut off after the engine",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 Chrome/120.0.0.0 Safari/537.36",
                "Chrome without its engine's comment",
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
                "Chrome without its engine's comment",
            ),
            (
                "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, \
                 like Gecko) Chrome/142.0.0.0 Safari/537.36",
                "a quote before the first word",
            ),
            (
                "Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)\
                 Chrome/86.0.4240.111Safari/537.36",
                "no space after Mozilla/5.0",
            ),
        ];
        for (user_agent, shape) in SEEN {
            assert_eq!(matching_shape(user_agent), Some(*shape), "{user_agent:?}");
        }
    }

    /// The web servers read [`pattern`] as PCRE (and Traefik as Go's
    /// RE2); `regex` reads it the same way. Whatever one says, the other
    /// does, so the preview is the rule.
    #[test]
    fn the_pattern_and_the_preview_agree() {
        let regex = regex::RegexBuilder::new(&pattern())
            .case_insensitive(true)
            .build()
            .unwrap();
        let every: Vec<&str> = NOT_IMPOSSIBLE
            .iter()
            .map(|(ua, _)| *ua)
            .chain([
                "Mozilla/5.0 (compatible)",
                "mozilla/5.0 (x11; linux x86_64)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "\"Mozilla/5.0",
                "Mozilla/5.0(X11)",
            ])
            .collect();
        for user_agent in every {
            assert_eq!(
                regex.is_match(user_agent),
                matching_shape(user_agent).is_some(),
                "{user_agent:?}"
            );
        }
    }

    /// Every shape compiles for the preview: one that did not would match
    /// nothing there and everything it should at the web server.
    #[test]
    fn every_shape_compiles_for_the_preview() {
        for (shape, regex) in SHAPES {
            assert!(
                crate::uaregex::compiled(regex).is_some(),
                "{shape}: {regex}"
            );
        }
    }

    fn line(ip: &str, path: &str, status: u16, user_agent: &str) -> String {
        format!(
            "{ip} - - [08/Nov/2026:10:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 1 \"-\" \
             \"{user_agent}\"\n"
        )
    }

    /// The preview counts what the rule would turn away and names the
    /// matched client that fetched a stylesheet under its own user agent,
    /// as only a browser would. Another client fetching one from the same
    /// address, as behind a Tor exit, is not that client.
    #[test]
    fn the_preview_names_a_matched_client_that_fetched_assets() {
        let cut_off = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let chrome = NOT_IMPOSSIBLE[0].0;
        let log = [
            line("203.0.113.1", "/.env", 404, cut_off),
            line("203.0.113.1", "/.git/config", 404, cut_off),
            line("203.0.113.2", "/", 200, cut_off),
            line("203.0.113.2", "/css/site.css", 200, cut_off),
            line("203.0.113.3", "/", 200, cut_off),
            line("203.0.113.3", "/css/site.css", 200, chrome),
            line("198.51.100.9", "/", 200, chrome),
        ]
        .concat();

        let preview = preview(&log);

        assert_eq!(preview.requests, 7, "{preview:?}");
        assert_eq!(preview.matched, 5, "{preview:?}");
        assert_eq!(preview.addresses, 3, "{preview:?}");
        assert_eq!(preview.answered, 3, "{preview:?}");
        assert_eq!(
            preview.by_shape,
            [("cut off after the engine", 5)],
            "{preview:?}"
        );
        assert_eq!(
            preview.browser_like,
            ["203.0.113.2".parse::<IpAddr>().unwrap()],
            "{preview:?}"
        );
    }
}
