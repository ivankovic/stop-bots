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

//! HTTP libraries and command-line clients: the user agents a program
//! sends when nobody gave it one of its own.
//!
//! ## Why a list of its own
//!
//! The upstream lists carry some of these, and the way they carry them is
//! the problem: ArcJet's entries are pinned to one version
//! (`python-requests/2.32.5`), so `2.28.0` and `2.34.2` asking a host for
//! `/.env` went through. And they carry them with no category, on
//! purpose, as [`crate::botlist::stop_bots_extras`] does not carry them at
//! all: health checks, webhooks and a site's own scripts use them too.
//! Blocking one by default would be wrong on a host with an API.
//!
//! A static site has no API. On one such host, in one week of October:
//! 167 requests from `python-requests` and 100 from `aiohttp`,
//! `Go-http-client` and the like, for `/`, `/.env` and config files, not
//! one of them fetching a page's images or styles. So they are one
//! switch, off by default
//! ([`crate::db::Db::get_block_http_libraries`]), for the host that has
//! nothing a library should be asking for, and a host with one client of
//! its own lets it through with `add-trusted --user-agent`.
//!
//! Unlike [`crate::botlist::old_browsers`], "humans only" turns this on:
//! that switch serves people, and none of these is one.
//!
//! ## What is deliberately not here
//!
//! - **Libraries a service sends under its own name.** Mastodon fetches
//!   link previews with `http.rb/5.1.1 (Mastodon/4.2.0; ...)`, and a feed
//!   reader or a webhook names itself. [`NOT_LIBRARIES`] holds those, and
//!   the tests keep every entry off them.
//! - **Names too short to be safe.** Node's own `fetch` sends `node`, and
//!   Ruby's `Net::HTTP` sends `Ruby`: substrings of too much else.
//! - **Scraping frameworks** (`Scrapy`): those are bots, and the bot
//!   lists carry them by name.
//!
//! ## Matching
//!
//! As [`crate::botlist::old_browsers`]: every entry a literal substring,
//! matched case-insensitively and written to the web server escaped, each
//! ending in the `/` before its version wherever it has one, so a word
//! that merely begins like a library's name does not match.

/// `(what it is, the substrings that name it)`.
const ENTRIES: &[(&str, &[&str])] = &[
    ("Python requests", &["python-requests/"]),
    ("Python urllib", &["Python-urllib/"]),
    ("Python httpx", &["python-httpx/"]),
    ("Python aiohttp", &["aiohttp/"]),
    ("Go net/http", &["Go-http-client/"]),
    // Java 8's `HttpURLConnection` sends `Java/1.8.0_292`, Java 11's
    // `HttpClient` `Java-http-client/11.0.2`.
    ("Java", &["Java/1.", "Java-http-client/"]),
    ("Apache HttpClient", &["Apache-HttpClient/"]),
    ("OkHttp", &["okhttp/"]),
    ("Node.js clients", &["axios/", "node-fetch/", "undici"]),
    ("Perl LWP", &["libwww-perl/", "lwp-trivial/"]),
    ("Ruby clients", &["Faraday v", "rest-client/"]),
    ("PHP Guzzle", &["GuzzleHttp/"]),
    ("Dart", &["(dart:io)"]),
    ("curl", &["curl/"]),
    ("Wget", &["Wget/"]),
    ("HTTPie", &["HTTPie/"]),
];

/// Every substring the list covers, as it is matched.
pub fn substrings() -> Vec<String> {
    ENTRIES
        .iter()
        .flat_map(|(_, strings)| strings.iter().map(|s| (*s).to_string()))
        .collect()
}

/// The list as web server patterns: each substring escaped, so it matches
/// itself and nothing else.
pub fn patterns() -> Vec<String> {
    substrings()
        .iter()
        .map(|s| crate::db::escape_regex_literal(s))
        .collect()
}

/// Whether `user_agent` is one of these clients, matched as the web
/// server matches it: a case-insensitive substring.
pub fn matches(user_agent: &str) -> bool {
    let lower = user_agent.to_lowercase();
    substrings()
        .iter()
        .any(|s| lower.contains(&s.to_lowercase()))
}

/// User agents no entry may match, each with the reason: browsers,
/// crawlers, and the services that fetch from a site through a library
/// but say who they are.
pub const NOT_LIBRARIES: &[(&str, &str)] = &[
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36",
        "Chrome on Windows",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Firefox on Linux",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
         like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
        "Safari on an iPhone",
    ),
    (
        "Lynx/2.8.9rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/3.0.13",
        "Lynx, whose own library is libwww-FM",
    ),
    (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot",
    ),
    (
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; \
         +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36",
        "Bingbot",
    ),
    (
        "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
        "certificate renewal",
    ),
    (
        "http.rb/5.1.1 (Mastodon/4.2.0; +https://mastodon.social/)",
        "Mastodon's link previews",
    ),
    ("facebookexternalhit/1.1", "link previews"),
    (
        "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        "Slack's link previews",
    ),
    ("GitHub-Hookshot/2b5a1d8", "GitHub's webhooks"),
    (
        "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
        "an uptime monitor",
    ),
    (
        "Mozilla/5.0 (compatible; Miniflux/2.2.1; +https://miniflux.app)",
        "a feed reader",
    ),
    (
        "FreshRSS/1.24.0 (Linux; https://freshrss.org)",
        "a feed reader",
    ),
    (
        "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 12 subscribers)",
        "a feed reader",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The test that earns a place on someone's server: no entry matches a
    /// browser, a crawler, or a service that says who it is.
    #[test]
    fn nothing_matches_a_browser_or_a_service_that_names_itself() {
        for (user_agent, why) in NOT_LIBRARIES {
            let lower = user_agent.to_lowercase();
            let hits: Vec<String> = substrings()
                .into_iter()
                .filter(|s| lower.contains(&s.to_lowercase()))
                .collect();
            assert!(hits.is_empty(), "{hits:?} match {why}: {user_agent:?}");
        }
    }

    /// The exposure check asks every site for its secrets as a browser
    /// would; switched on, this list must not turn it away.
    #[test]
    fn the_exposure_checks_own_requests_are_not_a_library() {
        assert!(!matches(crate::exposure::USER_AGENT));
    }

    /// The strings the list was read off: one host's log, September to
    /// November 2026, every one of them probing or scraping.
    #[test]
    fn the_clients_seen_probing_are_all_caught() {
        const SEEN: &[&str] = &[
            "python-requests/2.28.0",
            "python-requests/2.34.2",
            "Python/3.12 aiohttp/3.14.5",
            "Go-http-client/1.1",
            "curl/7.68.0",
            "curl/8.23.0",
        ];
        for user_agent in SEEN {
            assert!(matches(user_agent), "nothing catches {user_agent:?}");
        }
    }

    /// Escaped, every pattern passes the check the web server render
    /// applies, so none is dropped there in silence.
    #[test]
    fn every_pattern_can_be_written_to_the_web_server() {
        for pattern in patterns() {
            assert!(
                crate::nginx::pattern_problem(&pattern).is_none(),
                "{pattern:?} would be dropped: {:?}",
                crate::nginx::pattern_problem(&pattern)
            );
        }
    }

    /// Matched case-insensitively, as `~*` and `[NC]` match.
    #[test]
    fn matching_ignores_case() {
        assert!(matches("Python-Requests/2.31.0"));
        assert!(matches("CURL/8.5.0"));
    }
}
