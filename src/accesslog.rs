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

//! Best-effort, read-only integration with NGINX access logs — mirrors
//! `sshlog`'s role for SSH, but for HTTP: finds client IPs that look like
//! automated URL scanners (probing many nonexistent paths — `/wp-login.php`,
//! `/.env`, `/phpmyadmin`, ...) so `main.rs::block_web_scanners` can add
//! firewall Block rules for them. This module never writes to, rotates or
//! truncates any log — it only ever reads.
//!
//! ## Two log formats
//!
//! Both of NGINX's common layouts parse: the stock `combined` one, and a
//! JSON object written by a `log_format ... escape=json` directive. A JSON
//! format is not a niche choice — it is what anyone shipping logs to a
//! collector configures — and every detector in this module is driven by
//! [`parse_line`], so a format it could not read did not degrade them, it
//! switched them off. Silently, and with no failure anywhere: the file is
//! present and readable, every line simply parses to nothing, and the
//! honest report is "no scanners found".
//!
//! Deliberately doesn't share `sshlog`'s "never flag an IP that also
//! succeeded" exclusion: a scanner's own recon almost always includes at
//! least one 200 (`/`, `/robots.txt`, ...), so requiring "never succeeded"
//! would exclude nearly every real scanner, not just legitimate clients.
//! What *is* shared: [`crate::ipranges::is_local_or_private`], since a
//! monitoring probe or health check hammering a stale internal endpoint
//! isn't an internet scanner on either log.

use crate::evidence::{Evidence, Item, Rule};
use crate::ipranges::{cidr_contains, is_local_or_private};
use crate::protection::Detector;
use crate::services::Hosted;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

/// The conventional NGINX access-log location; unlike SSH logs there's no
/// second common layout to also try, and no journald fallback — NGINX logs
/// to a file whether or not the system boots under systemd. What
/// [`crate::logpaths::LogPaths::access_path`] falls back to when nothing
/// is stored or given.
pub const DEFAULT_LOG_PATH: &str = "/var/log/nginx/access.log";

/// The result of looking for access-log data: distinguishes "found and
/// read it, here's its text" from "nothing was even readable" (missing
/// file, permission denied — these are often only readable by
/// `root`/`adm`) — mirrors `sshlog::LogSource`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    Found(String),
    Unavailable,
}

/// Reads `path` directly, bypassing auto-detection — backs the CLI's
/// `--access-log` override, for non-default log locations and for
/// deterministic tests.
///
/// Read as bytes and decoded lossily, because the bytes are the client's:
/// a JSON `log_format` with `escape=json` writes a header's non-ASCII
/// bytes through untouched, so one request with a lone `0xFF` in its
/// user agent would otherwise make the whole file "unavailable" — every
/// access-log detector off — until it rotates.
pub fn read_log_file(path: &Path) -> LogSource {
    match std::fs::read(path) {
        Ok(bytes) => LogSource::Found(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => LogSource::Unavailable,
    }
}

/// Parses one access-log line in whichever of the two supported formats
/// it is written in. They are told apart by the first non-space character:
/// `{` can only begin the JSON one, since the combined layout opens with
/// the client address.
///
/// The choice is made per *line*, not per file, and that is the point
/// rather than an accident of implementation. Changing a running server's
/// `log_format` leaves one file holding both kinds until it rotates, and
/// an admin who adds a JSON format in order to switch these detectors on
/// should not have to wait out that rotation to see anything detected.
fn parse_line(line: &str) -> Option<ParsedLine> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        parse_json_line(trimmed)
    } else {
        parse_combined_line(line)
    }
}

/// Parses a single line of NGINX's default "combined" log format:
/// `<ip> - <remote_user> [<time_local>] "<method> <path> <proto>" <status>
/// <bytes> "<referer>" "<user_agent>"`. Returns `None` for anything that
/// doesn't parse cleanly (a custom log format, a line truncated at the
/// start/end of a rotated file, ...) rather than guessing — splitting on
/// `"` isolates the quoted request field from the unquoted ip/user/time
/// prefix and the status/bytes that follow it, which works regardless of
/// what the timestamp or remote_user contain, since neither can itself
/// contain a `"`. The trailing `"referer" "user_agent"` pair is extracted
/// the same way: `after_request` still has both quoted fields verbatim, so
/// splitting *it* on `"` isolates `user_agent` as the second quoted field.
/// A line with no trailing quoted pair at all (a stripped-down custom log
/// format) yields an empty `user_agent` rather than failing the whole
/// parse — status/path are still useful to `scanning_ips` either way.
fn parse_combined_line(line: &str) -> Option<ParsedLine> {
    let ip: IpAddr = line.split_whitespace().next()?.parse().ok()?;

    let mut fields = line.splitn(3, '"');
    // Unquoted prefix: ip, remote_user and `[time_local]`. The ip is
    // captured above; the time is whatever sits between the brackets, and
    // a line without a readable one still parses, undated.
    let prefix = fields.next()?;
    let time = prefix
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .and_then(|(stamp, _)| crate::logtime::nginx_time_local(stamp));
    let request = fields.next()?;
    let after_request = fields.next()?;

    let mut request_parts = request.split_whitespace();
    request_parts.next()?; // HTTP method
    let target = request_parts.next()?;
    // Strip any query string: `/foo?a=1` and `/foo?a=2` are the same path
    // as far as "is this a valid URL on this site" goes, and counting them
    // as distinct would let a real, repeatedly-hit-with-varying-params 404
    // endpoint masquerade as many different invalid URLs.
    let path = target.split('?').next().unwrap_or(target).to_string();

    // `after_request` is ` <status> <bytes> "<referer>" "<user_agent>"`;
    // splitting it on `"` yields [status/bytes, referer, the space between
    // the two quoted fields, user_agent, ""] — index 3 is the field we want.
    let quoted: Vec<&str> = after_request.split('"').collect();
    let status: u16 = quoted.first()?.split_whitespace().next()?.parse().ok()?;
    // `Some`, always: reaching here means the line had the trailing
    // quoted pair, so the format does record the header — `"-"` when the
    // request carried none. See [`ParsedLine::referer`] for why that is
    // not the same as `None`.
    let referer = Some(quoted.get(1).copied().unwrap_or("").to_string());
    let user_agent = quoted.get(3).copied().unwrap_or("").to_string();
    // Every quoted field after the user agent: [.., ua, " ", field, " ",
    // field, ..]. What they hold is the format's business; see
    // [`ParsedLine::trailing`].
    let trailing = quoted
        .iter()
        .skip(5)
        .step_by(2)
        .map(|field| field.to_string())
        .collect();

    Some(ParsedLine {
        ip,
        status,
        path,
        request: request.to_string(),
        referer,
        user_agent,
        time,
        // The combined format does not log the `Host`.
        host: None,
        trailing,
    })
}

/// Reads one field as text, whether the format quoted it or not.
///
/// `escape=json` writes every variable as a string, so `$status` arrives
/// as `"404"`. A format built with `escape=none`, or a log written by
/// something other than NGINX, can carry a bare `404` instead. Accepting
/// only one of the two would be the same silent no-detections failure
/// that JSON support exists to remove, so both are read.
fn json_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    match obj.get(key)? {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        // A bool, array, object or null in one of these positions is not a
        // value this knows how to read. `None` rather than a guess.
        _ => None,
    }
}

/// Parses a line written by a JSON `log_format`, keyed by the NGINX
/// variable names such a format is built from.
///
/// There is no configuration for the key names, and that is a judgement
/// rather than an omission: a JSON `log_format` is written by naming
/// variables, and the overwhelming convention is to keep each variable's
/// own name as its key — `$remote_addr` under `"remote_addr"`, `$status`
/// under `"status"`. Asking every admin to describe their format would
/// cost more configuration than it bought, and a wrong description fails
/// the same silent way an unparsed format does. A format that renames its
/// keys parses to `None` here, which is the same outcome it had before
/// this function existed.
fn parse_json_line(line: &str) -> Option<ParsedLine> {
    let LogObject(fields) = serde_json::from_str(line).ok()?;
    let obj = &fields;

    let ip: IpAddr = json_field(obj, "remote_addr")?.parse().ok()?;
    let status: u16 = json_field(obj, "status")?.parse().ok()?;

    // Three variables can carry the request target, in descending order of
    // faithfulness. `$request_uri` is the original target, query and all.
    // `$request` is the combined format's triple, `GET /a?b=1 HTTP/1.1`,
    // so the method and protocol come off it. `$uri` is the normalised
    // path NGINX settled on, which has already lost the query and may have
    // been rewritten — weaker evidence, but it still tells `/.env` apart
    // from `/index.html`, which is what every caller here asks of it.
    let target = json_field(obj, "request_uri")
        .or_else(|| {
            json_field(obj, "request")
                .and_then(|request| request.split_whitespace().nth(1).map(str::to_string))
        })
        .or_else(|| json_field(obj, "uri"))?;
    // Strip the query for the same reason as the combined parser: `/foo?a=1`
    // and `/foo?a=2` are one path as far as "is this a real URL here" goes.
    let path = target.split('?').next().unwrap_or(&target).to_string();
    // `$request` when the format has it; otherwise the target alone, which
    // is where nearly every payload is anyway.
    let request = json_field(obj, "request").unwrap_or_else(|| target.clone());

    Some(ParsedLine {
        ip,
        status,
        path,
        request,
        referer: json_field(obj, "http_referer"),
        // An absent user agent is an empty one for every caller here, so
        // unlike the referer this needs no third state: nothing draws a
        // conclusion from "the format doesn't log it" that differs from
        // what it does with "the client didn't send one".
        user_agent: json_field(obj, "http_user_agent").unwrap_or_default(),
        // `$time_iso8601` or `$time_local`, whichever the format logs.
        // Neither is required: a line without one parses, undated.
        time: json_field(obj, "time_iso8601")
            .and_then(|t| crate::logtime::iso8601(&t))
            .or_else(|| {
                json_field(obj, "time_local").and_then(|t| crate::logtime::nginx_time_local(&t))
            }),
        // `$host` or `$http_host`, when the format logs either: what tells
        // a subdomain console's lines apart (see [`Console`]).
        host: json_field(obj, "host").or_else(|| json_field(obj, "http_host")),
        trailing: Vec::new(),
    })
}

/// Every key [`parse_json_line`] reads.
const JSON_FIELDS: [&str; 11] = [
    "remote_addr",
    "status",
    "request_uri",
    "request",
    "uri",
    "http_referer",
    "http_user_agent",
    "time_iso8601",
    "time_local",
    "host",
    "http_host",
];

/// A JSON log line's top-level object, refused if it names any of
/// [`JSON_FIELDS`] twice.
///
/// A `log_format` built with `escape=none` writes a header verbatim, so a
/// user agent of `","remote_addr":"8.8.4.4` closes its own string and adds
/// a second `remote_addr`. serde's map keeps the last one, which pinned a
/// request on an address that never sent it — and the probe-path detector
/// blocks on a single request. Keeping the *first* instead is no fix: it
/// is just as wrong for a format that logs the user agent before the
/// address. Two values for one field means one of them was written by the
/// client, with no way to tell which, so the line is not read at all.
///
/// That costs nothing a client could not already do: under `escape=none`
/// it can make its own lines unparseable with a lone `"`. What this cannot
/// catch is a client adding a field the format does not log — `escape=none`
/// is not safe for a JSON format, and `escape=json` is what to use.
struct LogObject(serde_json::Map<String, serde_json::Value>);

impl<'de> serde::Deserialize<'de> for LogObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;

        impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
            type Value = LogObject;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<LogObject, A::Error> {
                let mut fields = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value()?;
                    if JSON_FIELDS.contains(&key.as_str()) && fields.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!("duplicate field {key}")));
                    }
                    fields.insert(key, value);
                }
                Ok(LogObject(fields))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

/// One parsed access-log line. A struct rather than a tuple since it grew
/// past three fields — `line.status` reads where `line.1` doesn't.
#[derive(Debug, PartialEq, Eq)]
struct ParsedLine {
    ip: IpAddr,
    status: u16,
    path: String,
    /// The request line as logged, method, query and protocol included —
    /// what [`injection_ips`] reads, since a payload is mostly in the
    /// query that [`ParsedLine::path`] drops, and sometimes in place of
    /// the method.
    request: String,
    /// Three states, not two, because the format gets a say.
    ///
    /// `Some("-")` (combined) and `Some("")` (`escape=json`) are how NGINX
    /// writes a request that carried no `Referer`, and are what
    /// [`refererless_crawl_ips`] counts. `None` is the weaker and quite
    /// different statement that this log format never records the header
    /// at all — a JSON format with no `http_referer` key, which is easy to
    /// write and common to find.
    ///
    /// Collapsing the two would turn every client on such a host into a
    /// referer-less crawler, and that detector's whole output is firewall
    /// blocks. So `None` means the question cannot be answered here, and
    /// the detector skips the line rather than answering it wrongly.
    referer: Option<String>,
    user_agent: String,
    /// When NGINX says the request happened, in Unix seconds: `$time_local`
    /// in the combined format, `time_iso8601` or `time_local` in a JSON
    /// one. `None` for a line that carries neither, which a JSON format is
    /// free to leave out.
    time: Option<i64>,
    /// The `Host` the request was for, when the format logs it: a JSON
    /// format's `host` or `http_host`. The combined format does not.
    host: Option<String>,
    /// The quoted fields a combined-style format appends after the user
    /// agent, such as `"$host"`. Nothing says which variable each one is,
    /// and `"$http_x_forwarded_for"`, which the client writes, is as
    /// common as `"$host"`. So they are only ever compared against the
    /// names of this server's sites, to tell which site a request was for
    /// (see [`crate::services::Hosted`]) — never taken for the host the
    /// console is recognised by, where a client naming the console would
    /// have its every line skipped.
    trailing: Vec<String>,
}

impl ParsedLine {
    /// Whether this is one of an application's own clients' requests on
    /// its data routes: see [`crate::services`].
    fn is_app_request(&self, hosted: &Hosted) -> bool {
        let hosts = self.host.iter().chain(&self.trailing).map(String::as_str);
        hosted.app_request(hosts, &self.path)
    }
}

/// Every IP with at least `threshold` *distinct* paths that returned 404
/// ("Not Found" — an invalid URL for this site) anywhere in `log_text`.
/// Distinct paths, not raw hit count: a real client repeatedly retrying
/// the same dead link must not look like a scanner, while a client probing
/// dozens of different well-known vulnerable paths is exactly the
/// signature this exists to catch. As with `sshlog::scanning_ips`, the
/// threshold is a count over *however much of the log `log_text` happens
/// to hold*, not a rate over a time window — this module doesn't parse
/// timestamps either. Loopback/private source IPs are excluded outright
/// (see the module docs for why there's no "had a 200" exclusion to go
/// with it). Deduplicated and sorted for deterministic output.
pub fn scanning_ips(log_text: &str, threshold: usize) -> Vec<String> {
    scanning_ips_hosted(log_text, threshold, Hosted::default())
}

/// [`scanning_ips`], not counting the 404s of the applications `hosted`
/// says run here on their own data routes (see [`crate::services`]).
pub fn scanning_ips_hosted(log_text: &str, threshold: usize, hosted: Hosted) -> Vec<String> {
    addresses(convicted_in_text(
        log_text,
        Watch {
            hosted,
            ..Watch::only(Detector::WebScanners)
        },
        Rule::Distinct(threshold),
    ))
}

/// One crawler that can be impersonated: a marker that identifies it in a
/// `User-Agent` string, plus the CIDRs its operator actually publishes.
/// Built by `crate::scanblock::crawler_claims` from the same
/// `ipranges::IpRangeSourceKind` data `update-ip-ranges` fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlerClaim {
    /// Lowercase substring that identifies a claim to be this crawler
    /// (`"googlebot"`, `"bingbot"`, `"gptbot"`). A substring rather than a
    /// full pattern because that's exactly what an impersonator copies —
    /// the recognisable token, embedded in whatever surrounding string
    /// they please.
    pub marker: &'static str,
    /// A human-readable name, for the "why was this blocked" message.
    pub name: &'static str,
    /// Every CIDR the operator publishes for this crawler. **Never empty**
    /// — see [`spoofed_crawler_ips`] for why an empty list must mean "skip
    /// this crawler entirely" rather than "nothing is legitimate".
    pub ranges: Vec<String>,
}

/// Every IP that claimed to be one of `claims`' crawlers from an address
/// that crawler's operator doesn't publish. This is the offline stand-in
/// for forward-confirmed reverse DNS: real rDNS needs a lookup per request,
/// which nothing in this codebase sits in a position to do, but the
/// published CIDR lists answer the same question — "is this actually
/// Google?" — against a log after the fact.
///
/// Unlike [`scanning_ips`] there is no threshold: a single request claiming
/// to be Googlebot from a non-Google address is already conclusive. Nothing
/// legitimate has a reason to put `googlebot` in its user agent from an
/// address Google doesn't own, and the published lists are complete by
/// construction (that's what publishing them is *for*).
///
/// **A crawler with no fetched ranges is skipped, not treated as
/// all-spoofed.** `CrawlerClaim::ranges` being empty means
/// `update-ip-ranges` has never successfully run for that source, in which
/// case every real crawler request would look like an impersonation — the
/// single worst failure this detector could have, since it would block the
/// actual Googlebot on a fresh install. The caller
/// (`crate::scanblock::crawler_claims`) filters those out, and this
/// function defends against it a second time rather than trusting that.
///
/// Loopback/private source IPs are excluded, same as [`scanning_ips`].
/// Deduplicated and sorted for deterministic output.
pub fn spoofed_crawler_ips(log_text: &str, claims: &[CrawlerClaim]) -> Vec<(String, String)> {
    convicted_in_text(
        log_text,
        Watch {
            claims: claims.to_vec(),
            ..Watch::only(Detector::SpoofedCrawlers)
        },
        Rule::Once,
    )
}

/// Request paths that no human, browser or legitimate crawler ever asks
/// for, matched case-insensitively as a prefix of the request path.
///
/// The selection rule is strict, because this detector blocks on a
/// **single** request with no threshold: a path only belongs here if it is
/// never legitimate *on any site*, not merely suspicious. That rules out
/// several of the most commonly probed paths on purpose —
/// `/wp-login.php` and `/wp-admin/` are how real WordPress admins sign in,
/// `/xmlrpc.php` is how Jetpack and pingbacks work, `/phpmyadmin` exists
/// on plenty of hosts that installed it deliberately. Blocking a site's
/// own administrator on their first login attempt would be a far worse
/// bug than missing one scanner, which the ≥7-distinct-404s detector
/// catches anyway.
///
/// What's left is credential and source-tree exposure — files that only
/// ever exist because of a deployment mistake, and that only ever get
/// requested by something looking for that mistake.
pub const DEFAULT_PROBE_PATHS: [&str; 13] = [
    "/.env",            // and /.env.local, /api/.env, ... (see the matching note)
    "/.git/",           // /.git/config, /.git/HEAD, ...
    "/.svn/",           //
    "/.hg/",            //
    "/.aws/",           // /.aws/credentials
    "/.ssh/",           // /.ssh/id_rsa
    "/wp-config.php",   // never served as content, only ever probed
    "/vendor/phpunit/", // the eval-stdin.php RCE probe and friends
    "/.DS_Store",       // leaks a directory listing
    "/.htpasswd",       //
    // A WordPress "plugin" that is a file-manager backdoor. Nobody
    // installs it on purpose, and it was the single most-requested path
    // from clients sending no user agent at all on the host this came
    // from — 1,001 requests, not one of them answered with content.
    "/wp-content/plugins/hellopress/",
    // Percent-encoded dots, in both the single- and double-encoded forms
    // actually seen. A `.` needs no encoding, so encoding one has exactly
    // one purpose: getting a `../` past something that is looking for
    // `../`. 22,762 requests on that host, in paths like
    // `/$(pwd)/%2eenv%2elocal` and
    // `/cgi-bin/.%2e/.%2e/.%2e/bin/sh` (CVE-2021-41773). The only five
    // that were answered at all were `/%2frobots%2etxt` and
    // `/%2f%2eds_store` — the same evasion, aimed at files that happen to
    // exist. `%252e` is listed separately because it does not contain
    // `%2e` as a substring: the characters are `%`,`2`,`5`,`2`,`e`.
    "%2e",
    "%252e",
];

/// Every IP that requested one of `probe_paths`, paired with the path it
/// asked for. No threshold and no status-code filter: one request is
/// conclusive (see [`DEFAULT_PROBE_PATHS`] for how strictly that list is
/// chosen), and the *response* is irrelevant — an attacker who gets a 200
/// for `/.env` is a bigger problem than one who gets a 404, so keying on
/// 404 like [`scanning_ips`] does would skip exactly the worst case.
///
/// Matching is a case-insensitive *substring* test against the request
/// path, which is already query-string-stripped by `parse_line`.
///
/// **It used to be anchored at the start, and that was wrong.** The anchor
/// was there so a legitimate path merely containing one of these strings
/// later on — `/blog/how-to-secure-your-env` — could not match. But that
/// path does not contain `/.env` at all; the leading slash in every needle
/// was already doing that work. What the anchor actually excluded was
/// `/api/.env`, `/backend/.env`, `/laravel/.env` and every path-traversal
/// attempt, which is 3,391 distinct paths and 39,675 requests on one
/// host's log — *none* of which were answered with content.
///
/// The widening is real and worth stating: a path segment that *begins*
/// with a needle now matches, so a URL whose last segment is `.env-file`
/// would be flagged where it was not before. That is accepted. Serving a
/// path segment that starts with a dot is not something sites do — most
/// web servers deny dotfiles outright — and the evidence is one-sided: of
/// every newly matched request in that log, zero returned 2xx.
///
/// Note that a traversal payload in the *query string*
/// (`/?file=%252e%252e/.aws/credentials`) is invisible here, because
/// `parse_line` strips the query before this sees it. Those requests are
/// answered 200 by the homepage and are somebody else's problem — this
/// detector is about the path.
///
/// Loopback/private source IPs are excluded, same as [`scanning_ips`] —
/// an internal backup job walking a checkout isn't an attacker.
/// Deduplicated (first matching path wins per IP) and sorted.
pub fn probe_path_ips(log_text: &str, probe_paths: &[String]) -> Vec<(String, String)> {
    convicted_in_text(
        log_text,
        Watch {
            probe_paths: probe_paths.to_vec(),
            ..Watch::only(Detector::ProbePaths)
        },
        Rule::Once,
    )
}

/// Every address that sent an exploit payload — in the request line, the
/// user agent or the referer — with the first signature seen from it.
///
/// One request is conclusive, like a probe path: see [`crate::injection`]
/// for what is matched, why a person searching for `/etc/passwd` is not,
/// and the evidence the signatures were checked against. The response is
/// irrelevant for the same reason it is for probe paths — a payload that
/// got a 200 is the worse case, not the excusable one.
///
/// Loopback and private addresses are excluded, as everywhere here.
///
/// Each distinct request line, user agent and referer is judged once per
/// call. A log repeats them endlessly — one host's 451,000 lines held
/// fewer than 8,000 distinct user agents — and judging every occurrence
/// took five seconds, on a job the internal cron runs every minute.
pub fn injection_ips(log_text: &str) -> Vec<(String, String)> {
    convicted_in_text(log_text, Watch::only(Detector::Injection), Rule::Once)
}

/// Filename extensions treated as "an asset a browser fetches alongside a
/// page". Deliberately generous — a miss here means a real browser looks
/// asset-less, which is the false positive that matters.
const ASSET_EXTENSIONS: [&str; 18] = [
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".avif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".map",
    ".webmanifest",
];

fn is_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    ASSET_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Every IP that fetched at least `min_pages` *distinct* pages and not one
/// asset. Browsers load the CSS, JS, fonts and images that go with a page;
/// scrapers pull the HTML and leave.
///
/// Three deliberate choices, each guarding a specific false positive:
///
/// - **Distinct pages, not request count.** The client this could wrongly
///   catch is a legitimate API consumer, which hammers a handful of
///   endpoints. A high distinct-URL count means something walked the site.
/// - **An asset counts at any status below 400, including 304.** A
///   returning browser with a warm cache gets `304 Not Modified` for every
///   asset. Counting only 200s would make well-cached real visitors look
///   exactly like scrapers.
/// - **Only successful page requests count**, so this doesn't re-flag the
///   404-sweeping already covered by [`scanning_ips`].
///
/// The false positive it *cannot* rule out: a site that serves no assets
/// at all — a pure JSON API — where every client looks like this. That is
/// why the detector is off by default.
pub fn asset_less_ips(log_text: &str, min_pages: usize) -> Vec<String> {
    addresses(convicted_in_text(
        log_text,
        Watch::only(Detector::AssetRatio),
        Rule::Distinct(min_pages),
    ))
}

/// Every IP that presented at least `min_agents` distinct user agents.
/// A single client has one; rotating them is a deliberate evasion.
///
/// **The false positive this cannot rule out is large: NAT.** A corporate
/// gateway, a university, or any mobile carrier doing CGNAT presents
/// hundreds of real users behind one address, each with their own browser.
/// The scheduled detector counts only inside its window, an hour by
/// default (`protection::BEHAVIOURAL_WINDOW_HOURS`), which is what tells
/// "twenty agents over a day from a campus" from "twenty agents in minutes
/// from one scraper"; this whole-text form, behind no CLI command, has
/// only the threshold. Off by default, and the threshold should be read as
/// "how many distinct browsers might legitimately share one address in an
/// hour".
pub fn rotating_user_agent_ips(log_text: &str, min_agents: usize) -> Vec<String> {
    addresses(convicted_in_text(
        log_text,
        Watch::only(Detector::RotatingUserAgent),
        Rule::Distinct(min_agents),
    ))
}

/// Every IP that fetched at least `min_paths` distinct *deep* pages (not
/// `/`) without ever sending a `Referer`. A person browsing arrives at
/// deep pages by following links, which sets one; a crawler working from
/// a sitemap or a URL list doesn't.
///
/// **Weaker than it looks, and off by default.** `Referrer-Policy:
/// no-referrer` is increasingly common, privacy tooling strips the header,
/// and typing a URL or opening a bookmark legitimately sends none — so
/// this is really "arrived at many distinct deep pages, every time with no
/// referer". The distinct-path threshold is doing all the work: one or two
/// referer-less deep hits are ordinary, twenty-five are a crawl.
pub fn refererless_crawl_ips(log_text: &str, min_paths: usize) -> Vec<String> {
    addresses(convicted_in_text(
        log_text,
        Watch::only(Detector::RefererlessCrawl),
        Rule::Distinct(min_paths),
    ))
}

/// The complement to [`scanning_ips`]: instead of flagging bad traffic,
/// tallies who's actually browsing the site successfully. Counts every
/// distinct user agent's hits across every *successful* (status < 400 —
/// 2xx/3xx) line in `log_text`, from a non-local/private source IP (the
/// same [`is_local_or_private`] exclusion `scanning_ips` uses: an internal
/// health check or monitoring probe isn't a real visitor). Lines with no
/// user agent at all, or the conventional `-` NGINX logs for a missing
/// `User-Agent` header, are excluded — neither identifies an actual client.
/// Every public address that fetched `/robots.txt`.
///
/// Only meaningful under "humans only", which is the one mode where this
/// is a signal rather than a fact. A browser never requests this file; a
/// crawler always does, first, and a well-behaved one does it precisely
/// *because* it intends to obey what it finds. Blocking on it is
/// therefore the least forgiving rule this project has — it catches the
/// polite bots and misses the rude ones, which is defensible only when
/// the host's answer to every bot is no.
///
/// Matched anywhere in the path, for the reason `probe_path_ips` is:
/// `/blog/robots.txt` is fetched by the same clients and by nobody else.
/// The query string is already stripped by `parse_line`, so a request for
/// `/?x=/robots.txt` cannot reach this.
pub fn robots_txt_ips(log_text: &str) -> Vec<String> {
    addresses(convicted_in_text(
        log_text,
        Watch::only(Detector::RobotsTxt),
        Rule::Once,
    ))
}

/// Successful requests by user agent, for `user_agent_stats`. The
/// scheduled pass tallies the same thing line by line (see
/// [`Observer::counting_user_agents`]); this is the whole-text form.
pub fn successful_user_agent_counts(log_text: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in log_text.lines().filter_map(parse_line) {
        if counts_as_a_visit(&line) {
            let user_agent = crate::db::stored_user_agent(&line.user_agent).to_string();
            *counts.entry(user_agent).or_insert(0) += 1;
        }
    }
    counts
}

/// One user agent's split between requests the blocking policy turned
/// away and requests that were served.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TurnedAway {
    pub user_agent: String,
    /// Requests answered with the configured block response.
    pub refused: u64,
    /// Requests that were served, in the same log.
    pub served: u64,
}

/// Which user agents this host's blocking policy is turning away, and how
/// much each of them still gets through.
///
/// The gap this fills: every other report here answers "what is this
/// project doing", and none answered "what is it doing *to my own
/// clients*". Three first-party apps were blocked on one host in a single
/// week -- two Nextcloud clients and a Jellyfin TV app, all three matching
/// `okhttp` in a public bad-bot list -- and each was found because someone
/// complained that something had stopped working. The information was in
/// the access log the whole time.
///
/// Inferred from the status code, because a block leaves no other trace in
/// a log whose format this project does not own. `block_status` is
/// [`crate::db::BlockResponse::status_code`], so on a host answering `444`
/// -- which NGINX invents and no application returns -- the count is
/// exact. On `403` or `404` it also catches the application's own
/// refusals, which is why `served` is carried next to it rather than left
/// for the reader to go and find: 262 refusals and nothing served is a
/// client being stopped at the door, while 300 served and three refused is
/// an application saying no to three requests, and the difference is the
/// whole question.
///
/// Private and loopback sources are skipped, as everywhere else in this
/// module, and so are requests with no user agent -- there is nothing to
/// report or trust for those.
///
/// Sorted by refusals, most first.
pub fn turned_away_user_agents(log_text: &str, block_status: u16) -> Vec<TurnedAway> {
    let mut survey = Survey::new(block_status);
    for line in log_text.lines() {
        survey.line(line);
    }
    survey.turned_away()
}

/// `(user agent, (refused, served))` as a report: only agents that were
/// refused at all, most refused first.
fn sorted_turned_away(counts: Vec<(String, (u64, u64))>) -> Vec<TurnedAway> {
    let mut turned_away: Vec<TurnedAway> = counts
        .into_iter()
        .filter(|(_, (refused, _))| *refused > 0)
        .map(|(user_agent, (refused, served))| TurnedAway {
            user_agent,
            refused,
            served,
        })
        .collect();
    // Refusals first, then the ones with least getting through, so the
    // clearest false positives sort to the top of a long list.
    turned_away.sort_by(|a, b| {
        b.refused
            .cmp(&a.refused)
            .then(a.served.cmp(&b.served))
            .then(a.user_agent.cmp(&b.user_agent))
    });
    turned_away
}

// ---- observing: one pass over the lines, for every detector at once ----

/// What the access-log detectors are looking for, resolved from the
/// database before any log is read.
///
/// A plain value with no database handle, because it goes with the read
/// to wherever the read happens: a blocking thread in the TUI, outside the
/// web console's lock. See [`crate::logscan`].
#[derive(Debug, Clone, Default)]
pub struct Watch {
    /// The access-log detectors that are on, each with the oldest time a
    /// line may carry and still count (`None`: any time). A line older
    /// than its detector's window is not even kept.
    pub detectors: Vec<(Detector, Option<i64>)>,
    /// [`crate::protection::probe_paths`].
    pub probe_paths: Vec<String>,
    /// [`crate::protection::honeypot_path`].
    pub honeypot: String,
    /// [`crate::scanblock::crawler_claims`].
    pub claims: Vec<CrawlerClaim>,
    /// Where this host's web console is served: its lines are the
    /// operator's, and are not read at all (see [`Console`]).
    pub console: Console,
    /// The applications behind this server's sites, whose own clients'
    /// requests the 404 and behavioural detectors do not count (see
    /// [`crate::services`]).
    pub hosted: Hosted,
}

impl Watch {
    /// One detector and nothing else, with no window and its built-in
    /// parameters: what the one-off functions above read a text with.
    pub fn only(detector: Detector) -> Watch {
        Watch {
            detectors: vec![(detector, None)],
            probe_paths: DEFAULT_PROBE_PATHS.iter().map(|p| p.to_string()).collect(),
            honeypot: crate::protection::HONEYPOT_PATH_DEFAULT.to_string(),
            claims: Vec::new(),
            console: Console::default(),
            hosted: Hosted::default(),
        }
    }

    pub fn watches(&self, detector: Detector) -> bool {
        self.detectors.iter().any(|(d, _)| *d == detector)
    }
}

/// Where this host's web console is served, so that its own traffic is
/// never read as evidence, nor tallied into the access stats.
///
/// Behind NGINX the console's requests go into the site's access log, from
/// the operator's address, and the console shows the operator what the
/// attackers sent: the Firewall page links a user agent's details as
/// `?inspect_ua=<the user agent>`, and a search is `?q=<what was typed>`.
/// Read as traffic, one look at a `${jndi:...}` user agent was a log4shell
/// payload from the operator, and the injection detector blocked them for
/// a week on that one line.
///
/// Two ways to recognise a console line, one per way the Web Access panel
/// puts it behind NGINX:
///
/// - **Under a path prefix** (`web:base_path`, e.g. `/stop-bots`): the
///   request path, normalised as NGINX normalises it before choosing a
///   `location` (`%XX` decoded once, `//` merged, `.` and `..` resolved), is
///   the prefix or under it. Normalised so that `/stop-bots/../.env`, which
///   NGINX serves from the site and not the console, is still read.
/// - **On its own host**, when there is no prefix: the line's `Host` is one
///   of the console's configured names. Only a JSON format can say, since
///   the combined one does not log the host, which is why the panel's
///   subdomain server block has `access_log off`.
///
/// The prefix wins when there is one: the configured names then include
/// the site's own, and matching on them would skip the whole site.
///
/// The cost is that nothing a client sends under the console's prefix is
/// judged. What answers there is the console, which does nothing without
/// a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Console {
    /// The prefix's segments: `["stop-bots"]`, or none for the root.
    prefix: Vec<String>,
    /// The console's own host names, compared without a port and ignoring
    /// case. Consulted only when there is no prefix.
    hosts: Vec<String>,
}

impl Console {
    /// A console under `prefix` (`""`, `/stop-bots`, `/stop-bots/`),
    /// answering to `hosts` besides the loopback names.
    pub fn new(prefix: &str, hosts: &[String]) -> Console {
        Console {
            prefix: prefix
                .split('/')
                .filter(|segment| !segment.is_empty())
                .map(str::to_string)
                .collect(),
            hosts: hosts.to_vec(),
        }
    }

    /// Whether no line can be the console's: one at the root with no
    /// configured name, which is a console on loopback.
    pub fn is_empty(&self) -> bool {
        self.prefix.is_empty() && self.hosts.is_empty()
    }

    /// Whether `line` was a request to the console.
    fn serves(&self, line: &ParsedLine) -> bool {
        if !self.prefix.is_empty() {
            return path_segments(&line.path).starts_with(&self.prefix);
        }
        let Some(host) = line.host.as_deref() else {
            return false;
        };
        let name = crate::services::host_name(host);
        self.hosts.iter().any(|h| h.eq_ignore_ascii_case(name))
    }
}

/// The segments of `path` as NGINX matches a `location` against it: `%XX`
/// decoded once, empty and `.` segments dropped, and `..` taking away the
/// one before it. Not the `%u` forms [`crate::injection`] also decodes:
/// NGINX does not, and a path read as the console's must be one NGINX
/// sent there.
pub(crate) fn path_segments(path: &str) -> Vec<String> {
    let bytes = path.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                decoded.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    let mut segments: Vec<String> = Vec::new();
    for segment in String::from_utf8_lossy(&decoded).split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment.to_string()),
        }
    }
    segments
}

/// `log_text` without the console's lines (see [`Console`]), for a
/// detector given a whole log to read, as the scheduled pass reads one.
pub fn without_console<'a>(log_text: &'a str, console: &Console) -> std::borrow::Cow<'a, str> {
    if console.is_empty() {
        return std::borrow::Cow::Borrowed(log_text);
    }
    let mut kept = String::with_capacity(log_text.len());
    for line in log_text.lines() {
        if parse_line(line).is_some_and(|parsed| console.serves(&parsed)) {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    std::borrow::Cow::Owned(kept)
}

/// When a line happened, for the observer.
#[derive(Debug, Clone, Copy)]
pub enum Clock {
    /// The time the line carries, capped at `now`. A line that carries
    /// none is dated `undated` instead, and not kept as evidence at all if
    /// that is `None` -- which is what a first read of a log uses, where an
    /// undated line could be months old.
    Logged { now: i64, undated: Option<i64> },
    /// The line's position, for a text read whole with no window: every
    /// line counts, and "earliest" means "first in the file".
    Ordinal(i64),
}

/// What [`Observer`] has counted besides the evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Lines with anything on them.
    pub lines: usize,
    /// Of those, lines in a format this module reads.
    pub parsed: usize,
}

/// Reads access-log lines one at a time into evidence for every watched
/// detector, and optionally into the successful-user-agent tally.
///
/// One observer, one pass: the point of the design. Each detector used to
/// parse the whole log on its own, so ten detectors were ten parses.
pub struct Observer {
    watch: Watch,
    needles: Vec<String>,
    honeypot: String,
    evidence: Evidence,
    user_agents: Option<HashMap<String, u64>>,
    counts: Counts,
    /// Verdicts already reached on a request line, user agent or referer.
    /// A log repeats them endlessly -- one host's 451,000 lines held fewer
    /// than 8,000 distinct user agents -- and judging every occurrence took
    /// five seconds. Cleared when it grows past [`JUDGED_MAX`], so a flood
    /// of unique requests cannot grow it without bound.
    judged: [HashMap<String, Option<&'static str>>; 3],
    /// Addresses a payload was already recorded for in this read. One is
    /// conclusive, so the rest of their lines need no judging.
    injecting: HashSet<IpAddr>,
}

/// See [`Observer::judged`].
const JUDGED_MAX: usize = 50_000;

impl Observer {
    pub fn new(watch: Watch) -> Observer {
        Observer {
            needles: watch.probe_paths.iter().map(|p| p.to_lowercase()).collect(),
            honeypot: watch.honeypot.to_lowercase(),
            watch,
            evidence: Evidence::default(),
            user_agents: None,
            counts: Counts::default(),
            judged: Default::default(),
            injecting: HashSet::new(),
        }
    }

    /// Also tally successful requests by user agent, as
    /// [`successful_user_agent_counts`] does.
    pub fn counting_user_agents(mut self) -> Observer {
        self.user_agents = Some(HashMap::new());
        self
    }

    /// Reads one line.
    pub fn line(&mut self, text: &str, clock: Clock) {
        if text.trim().is_empty() {
            return;
        }
        self.counts.lines += 1;
        let Some(line) = parse_line(text) else {
            return;
        };
        self.counts.parsed += 1;
        if self.watch.console.serves(&line) {
            return;
        }
        if let Some(tally) = &mut self.user_agents {
            if counts_as_a_visit(&line) {
                // Cut as it will be stored, so that two agents the table
                // cannot tell apart are one entry here too.
                let user_agent = crate::db::stored_user_agent(&line.user_agent);
                match tally.get_mut(user_agent) {
                    Some(count) => *count += 1,
                    None => {
                        tally.insert(user_agent.to_string(), 1);
                    }
                }
            }
        }
        if is_local_or_private(&line.ip) {
            return;
        }
        let at = match clock {
            Clock::Logged { now, undated } => match line.time.or(undated) {
                Some(at) => at.min(now),
                None => return,
            },
            Clock::Ordinal(n) => n,
        };
        // Worked out once, and only if a detector it matters to asks.
        let mut app_request = None;
        let detectors = std::mem::take(&mut self.watch.detectors);
        for (detector, cutoff) in &detectors {
            if cutoff.is_some_and(|cutoff| at < cutoff) {
                continue;
            }
            if allows_app_requests(*detector)
                && *app_request.get_or_insert_with(|| line.is_app_request(&self.watch.hosted))
            {
                continue;
            }
            if let Some(item) = self.observe(*detector, &line) {
                self.evidence.add(*detector, line.ip, item, at);
            }
        }
        self.watch.detectors = detectors;
    }

    /// What `line` says for `detector`, if anything. The one place each
    /// access-log detector's idea of a suspicious line is written down.
    fn observe(&mut self, detector: Detector, line: &ParsedLine) -> Option<Item> {
        match detector {
            // A distinct path that does not exist here.
            Detector::WebScanners => (line.status == 404).then(|| Item::seen(&line.path)),
            Detector::SpoofedCrawlers => {
                let active: Vec<&CrawlerClaim> = self
                    .watch
                    .claims
                    .iter()
                    .filter(|c| !c.ranges.is_empty())
                    .collect();
                if active.is_empty() {
                    return None;
                }
                let ua = line.user_agent.to_lowercase();
                let matched: Vec<&&CrawlerClaim> = active
                    .iter()
                    .filter(|claim| ua.contains(claim.marker))
                    .collect();
                // Verification is per *request*, not per claim: if any
                // crawler the user agent named vouches for the address,
                // the request is legitimate and the other names it
                // mentions prove nothing on their own. Checking per claim
                // would flag the real Googlebot the moment its user agent
                // contained another crawler's token.
                let vouched = matched
                    .iter()
                    .any(|claim| claim.ranges.iter().any(|cidr| cidr_contains(cidr, line.ip)));
                match matched.first() {
                    Some(first) if !vouched => Some(Item::seen(first.name)),
                    _ => None,
                }
            }
            Detector::ProbePaths => {
                let path = line.path.to_lowercase();
                self.needles
                    .iter()
                    .any(|needle| path.contains(needle.as_str()))
                    .then(|| Item::seen(&line.path))
            }
            Detector::Honeypot => (!self.honeypot.is_empty()
                && line.path.to_lowercase().contains(&self.honeypot))
            .then(|| Item::seen(&line.path)),
            Detector::RobotsTxt => line
                .path
                .to_lowercase()
                .contains("/robots.txt")
                .then(|| Item::seen(&line.path)),
            Detector::Injection => {
                if self.injecting.contains(&line.ip) {
                    return None;
                }
                let kind = self.injection(line)?;
                self.injecting.insert(line.ip);
                Some(Item::seen(kind))
            }
            // A page, or the asset that clears the whole address.
            Detector::AssetRatio => (line.status < 400).then(|| {
                if is_asset(&line.path) {
                    Item::Clear
                } else {
                    Item::seen(&line.path)
                }
            }),
            Detector::RotatingUserAgent => (!line.user_agent.is_empty() && line.user_agent != "-")
                .then(|| Item::seen(&line.user_agent)),
            Detector::RefererlessCrawl => {
                if line.status >= 400 {
                    return None;
                }
                // A format that never records the header cannot say
                // whether this request carried one, and "cannot tell" is
                // not "there was none" -- see [`ParsedLine::referer`].
                let referer = line.referer.as_deref()?;
                // NGINX logs a missing Referer as "-", and as "" under
                // escape=json.
                if !referer.is_empty() && referer != "-" {
                    Some(Item::Clear)
                } else {
                    (line.path != "/").then(|| Item::seen(&line.path))
                }
            }
            // Not an access-log detector.
            Detector::SshScanners => None,
        }
    }

    /// The payload `line` carries, if any: in the request, the user agent
    /// or the referer. See [`crate::injection`].
    fn injection(&mut self, line: &ParsedLine) -> Option<&'static str> {
        use crate::injection::{in_referer, in_request, in_user_agent};
        let [requests, user_agents, referers] = &mut self.judged;
        judged(requests, &line.request, in_request)
            .or_else(|| judged(user_agents, &line.user_agent, in_user_agent))
            .or_else(|| {
                line.referer
                    .as_deref()
                    .and_then(|referer| judged(referers, referer, in_referer))
            })
    }

    /// Everything collected: the evidence, the user-agent tally if one was
    /// asked for, and the line counts.
    pub fn finish(self) -> (Evidence, HashMap<String, u64>, Counts) {
        (
            self.evidence,
            self.user_agents.unwrap_or_default(),
            self.counts,
        )
    }
}

/// Whether `detector` leaves an application's own clients' requests on
/// its data routes alone (see [`crate::services`]): the four whose tell —
/// many distinct missing paths, no assets, no referer, several user
/// agents on one address — is also what a sync or media app looks like.
/// A probe, a payload, the honeypot or a forged crawler is judged on
/// those routes as anywhere else.
fn allows_app_requests(detector: Detector) -> bool {
    match detector {
        Detector::WebScanners
        | Detector::AssetRatio
        | Detector::RotatingUserAgent
        | Detector::RefererlessCrawl => true,
        Detector::SpoofedCrawlers
        | Detector::ProbePaths
        | Detector::Injection
        | Detector::Honeypot
        | Detector::RobotsTxt
        | Detector::SshScanners => false,
    }
}

fn judged(
    seen: &mut HashMap<String, Option<&'static str>>,
    value: &str,
    judge: fn(&str) -> Option<&'static str>,
) -> Option<&'static str> {
    if let Some(answer) = seen.get(value) {
        return *answer;
    }
    if seen.len() >= JUDGED_MAX {
        seen.clear();
    }
    let answer = judge(value);
    seen.insert(value.to_string(), answer);
    answer
}

/// Whether a line counts towards [`successful_user_agent_counts`].
fn counts_as_a_visit(line: &ParsedLine) -> bool {
    line.status < 400
        && !line.user_agent.is_empty()
        && line.user_agent != "-"
        && !is_local_or_private(&line.ip)
}

/// Every address `rule` convicts in `log_text` under `watch`, read whole
/// with no window: the one-off form every public detector function above
/// shares with the incremental one.
fn convicted_in_text(log_text: &str, watch: Watch, rule: Rule) -> Vec<(String, String)> {
    let detector = watch.detectors[0].0;
    let mut observer = Observer::new(watch);
    for (n, line) in log_text.lines().enumerate() {
        observer.line(line, Clock::Ordinal(n as i64));
    }
    let (evidence, _, _) = observer.finish();
    crate::evidence::decide(&evidence.rows_for(detector), rule, None)
}

fn addresses(convicted: Vec<(String, String)>) -> Vec<String> {
    convicted.into_iter().map(|(address, _)| address).collect()
}

/// What an access log looks like to this module, from one pass over some
/// of it: how much of it parses, who it records, and who it turns away.
/// What the health check reports on. See [`crate::health`].
#[derive(Debug, Default)]
pub struct Survey {
    pub counts: Counts,
    /// Parsed lines from a public address.
    ///
    /// Exists to catch a silent failure rather than a noisy one. Every
    /// detector skips private sources, so a deployment where NGINX records
    /// its proxy's address instead of the client's does not produce wrong
    /// blocks. It produces *no* blocks, from a log that looks perfectly
    /// healthy. The usual cause is NGINX behind something that terminates
    /// the connection itself -- a container's port mapping, a load
    /// balancer, a CDN -- without `set_real_ip_from`/`real_ip_header`.
    /// Lines, not distinct addresses: one proxy in front of everything is
    /// exactly the case worth catching, and it has one address.
    pub public: usize,
    /// Of `public`, lines from a CDN's edge addresses (see [`crate::cdn`]):
    /// most of them means NGINX is logging the CDN, not the visitor.
    pub cdn: usize,
    /// The first line that did not parse, as it is safe to show.
    pub unparsed_sample: Option<String>,
    turned_away: HashMap<String, (u64, u64)>,
    block_status: u16,
}

impl Survey {
    pub fn new(block_status: u16) -> Survey {
        Survey {
            block_status,
            ..Survey::default()
        }
    }

    pub fn line(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        self.counts.lines += 1;
        let Some(line) = parse_line(text) else {
            if self.unparsed_sample.is_none() {
                self.unparsed_sample = Some(printable_sample(text));
            }
            return;
        };
        self.counts.parsed += 1;
        if is_local_or_private(&line.ip) {
            return;
        }
        self.public += 1;
        if crate::cdn::is_edge_addr(line.ip) {
            self.cdn += 1;
        }
        if line.user_agent.is_empty() || line.user_agent == "-" {
            return;
        }
        let entry = self.turned_away.entry(line.user_agent).or_insert((0, 0));
        if line.status == self.block_status {
            entry.0 += 1;
        } else if line.status < 400 {
            entry.1 += 1;
        }
    }

    /// See [`turned_away_user_agents`].
    pub fn turned_away(&self) -> Vec<TurnedAway> {
        sorted_turned_away(
            self.turned_away
                .iter()
                .map(|(ua, counts)| (ua.clone(), *counts))
                .collect(),
        )
    }
}

/// The longest sample line a report quotes, in characters.
pub const SAMPLE_CHARS: usize = 160;

/// `text` as it is safe to quote in a report: control characters replaced
/// and invisible ones written out ([`crate::present::terminal_safe`]), and
/// cut at [`SAMPLE_CHARS`]. The line is whatever a client made NGINX
/// write, so it is treated as hostile.
pub fn printable_sample(text: &str) -> String {
    let text = text.trim_end_matches(['\r', '\n']);
    let mut sample = String::with_capacity(text.len().min(SAMPLE_CHARS * 4));
    for c in text.chars().take(SAMPLE_CHARS) {
        crate::present::push_terminal_safe(&mut sample, c);
    }
    if text.chars().count() > SAMPLE_CHARS {
        sample.push('\u{2026}');
    }
    sample
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"\n"
        )
    }

    /// The two columns are the whole point: refusals alone cannot tell a
    /// blocked client from an application saying no.
    #[test]
    fn turned_away_user_agents_counts_refusals_beside_what_still_got_through() {
        let log = [
            line_with("203.0.113.5", 444, "BlockedApp/1.0"),
            line_with("203.0.113.5", 444, "BlockedApp/1.0"),
            line_with("203.0.113.6", 444, "PartlyBlocked/1.0"),
            line_with("203.0.113.6", 200, "PartlyBlocked/1.0"),
            line_with("203.0.113.6", 200, "PartlyBlocked/1.0"),
        ]
        .concat();

        let turned_away = turned_away_user_agents(&log, 444);

        assert_eq!(
            turned_away,
            vec![
                TurnedAway {
                    user_agent: "BlockedApp/1.0".to_string(),
                    refused: 2,
                    served: 0,
                },
                TurnedAway {
                    user_agent: "PartlyBlocked/1.0".to_string(),
                    refused: 1,
                    served: 2,
                },
            ],
            "stopped at the door sorts above told-no-once"
        );
    }

    /// Only the configured response counts. A host answering 403 must not
    /// have its 404s read as blocks, or the report is every missing
    /// favicon on the server.
    #[test]
    fn turned_away_user_agents_counts_only_the_configured_response() {
        let log = [
            line_with("203.0.113.5", 404, "Wanderer/1.0"),
            line_with("203.0.113.5", 500, "Wanderer/1.0"),
            line_with("203.0.113.5", 403, "Wanderer/1.0"),
        ]
        .concat();

        let turned_away = turned_away_user_agents(&log, 403);

        assert_eq!(turned_away.len(), 1, "was: {turned_away:?}");
        assert_eq!(turned_away[0].refused, 1);
        assert_eq!(
            turned_away[0].served, 0,
            "a 404 and a 500 are neither refused by us nor served"
        );
    }

    /// An agent that was never refused has nothing to report, however much
    /// of the log it occupies.
    #[test]
    fn turned_away_user_agents_omits_an_agent_that_was_never_refused() {
        let log = [
            line_with("203.0.113.5", 200, "Browser/1.0"),
            line_with("203.0.113.5", 200, "Browser/1.0"),
        ]
        .concat();

        assert!(turned_away_user_agents(&log, 444).is_empty());
    }

    /// The same two exclusions every detector here applies: a private
    /// source is this host talking to itself, and there is nothing to
    /// trust for a request that sent no agent.
    #[test]
    fn turned_away_user_agents_skips_private_sources_and_missing_agents() {
        let log = [
            line_with("10.0.0.5", 444, "InternalProbe/1.0"),
            line_with("127.0.0.1", 444, "LocalProbe/1.0"),
            line_with("203.0.113.5", 444, "-"),
        ]
        .concat();

        assert!(
            turned_away_user_agents(&log, 444).is_empty(),
            "nothing here is a client this host should report on"
        );
    }

    fn ok_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n"
        )
    }

    #[test]
    fn parse_line_extracts_every_field_including_the_referer() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 162 \"https://ref.example/from\" \"Mozilla/5.0\"";
        let parsed = parse_line(line).expect("the standard combined format should parse");
        assert_eq!(parsed.ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.path, "/wp-login.php");
        assert_eq!(parsed.referer.as_deref(), Some("https://ref.example/from"));
        assert_eq!(parsed.user_agent, "Mozilla/5.0");
    }

    #[test]
    fn parse_line_reads_a_missing_referer_as_nginx_writes_it() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \"curl/8\"";
        assert_eq!(parse_line(line).unwrap().referer.as_deref(), Some("-"));
    }

    /// A JSON format with only `$request_uri` still gives the injection
    /// detector the query it reads.
    #[test]
    fn injection_ips_reads_a_json_line_without_a_request_field() {
        let log = r#"{"remote_addr":"203.0.113.9","status":"404","request_uri":"/?f=../../../../etc/passwd","http_user_agent":"curl/8"}"#;
        assert_eq!(
            injection_ips(log),
            vec![("203.0.113.9".to_string(), "path traversal".to_string())]
        );
    }

    #[test]
    fn parse_line_strips_the_query_string() {
        let line = "203.0.113.5 - - [10/Jul/2026:12:00:00 +0000] \"GET /foo?a=1&b=2 HTTP/1.1\" 404 162 \"-\" \"Mozilla/5.0\"";
        assert_eq!(parse_line(line).map(|l| l.path), Some("/foo".to_string()));
    }

    #[test]
    fn parse_line_handles_ipv6_addresses() {
        let line =
            "2001:db8::1 - - [10/Jul/2026:12:00:00 +0000] \"GET /x HTTP/1.1\" 404 1 \"-\" \"UA\"";
        assert_eq!(
            parse_line(line).map(|l| l.ip),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_line_rejects_malformed_lines() {
        assert_eq!(parse_line("not a log line at all"), None);
        assert_eq!(parse_line(""), None);
        // A remote_addr that isn't a real IP (e.g. a hostname from a
        // misconfigured log_format) must not be silently accepted.
        assert_eq!(
            parse_line("not-an-ip - - [t] \"GET /x HTTP/1.1\" 404 1 \"-\" \"UA\""),
            None
        );
    }

    /// Shaped after what `escape=json` actually emits: every value a
    /// string, and the keys named after the NGINX variables they came
    /// from.
    fn json_line(ip: &str, path: &str, status: u16) -> String {
        format!(
            r#"{{"time_local": "10/Jul/2026:12:00:00 +0000", "remote_addr": "{ip}", "request_uri": "{path}", "status": "{status}", "http_referer": "-", "http_user_agent": "Mozilla/5.0"}}"#
        ) + "\n"
    }

    #[test]
    fn parse_line_reads_every_field_from_a_json_log_format() {
        let line = r#"{"time_local": "10/Jul/2026:12:00:00 +0000", "remote_addr": "203.0.113.5", "request_uri": "/wp-login.php", "status": "404", "http_referer": "https://ref.example/from", "http_user_agent": "Mozilla/5.0"}"#;
        let parsed = parse_line(line).expect("an escape=json line should parse");
        let got = (
            parsed.ip,
            parsed.status,
            parsed.path.as_str(),
            parsed.referer.as_deref(),
            parsed.user_agent.as_str(),
        );
        assert_eq!(
            got,
            (
                "203.0.113.5".parse::<IpAddr>().unwrap(),
                404,
                "/wp-login.php",
                Some("https://ref.example/from"),
                "Mozilla/5.0",
            ),
            "parsed was: {parsed:?}"
        );
    }

    /// `escape=json` quotes every value, but `escape=none` and non-NGINX
    /// writers do not. Reading only the quoted form would leave those
    /// logs parsing to nothing, which is the failure JSON support exists
    /// to remove.
    #[test]
    fn parse_line_reads_a_json_status_written_as_a_bare_number() {
        let line = r#"{"remote_addr": "203.0.113.5", "request_uri": "/x", "status": 404}"#;
        assert_eq!(
            parse_line(line).map(|l| l.status),
            Some(404),
            "a numeric status should parse the same as a quoted one"
        );
    }

    #[test]
    fn parse_line_takes_the_target_from_the_request_triple_when_there_is_no_request_uri() {
        let line = r#"{"remote_addr": "203.0.113.5", "request": "GET /from-the-triple HTTP/1.1", "status": "404"}"#;
        assert_eq!(
            parse_line(line).map(|l| l.path),
            Some("/from-the-triple".to_string()),
            "the method and protocol should come off $request"
        );
    }

    #[test]
    fn parse_line_falls_back_to_uri_when_the_json_format_carries_no_other_target() {
        let line = r#"{"remote_addr": "203.0.113.5", "uri": "/only-uri", "status": "404"}"#;
        assert_eq!(
            parse_line(line).map(|l| l.path),
            Some("/only-uri".to_string()),
            "$uri is weaker evidence but still names the path"
        );
    }

    #[test]
    fn parse_line_strips_the_query_string_from_a_json_line() {
        let line =
            r#"{"remote_addr": "203.0.113.5", "request_uri": "/foo?a=1&b=2", "status": "404"}"#;
        assert_eq!(parse_line(line).map(|l| l.path), Some("/foo".to_string()));
    }

    #[test]
    fn parse_line_handles_ipv6_in_a_json_line() {
        let line = r#"{"remote_addr": "2001:db8::1", "request_uri": "/x", "status": "404"}"#;
        assert_eq!(
            parse_line(line).map(|l| l.ip),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn parse_line_rejects_json_that_is_not_a_log_line() {
        let cases = [
            ("truncated mid-object", r#"{"remote_addr": "203.0.113.5", "#),
            ("a JSON array", r#"["203.0.113.5", "/x", 404]"#),
            (
                "no remote_addr",
                r#"{"request_uri": "/x", "status": "404"}"#,
            ),
            (
                "a hostname where the address goes",
                r#"{"remote_addr": "host.example", "request_uri": "/x", "status": "404"}"#,
            ),
            (
                "no target of any kind",
                r#"{"remote_addr": "203.0.113.5", "status": "404"}"#,
            ),
        ];
        for (description, line) in cases {
            assert_eq!(parse_line(line), None, "should not parse: {description}");
        }
    }

    /// A `log_format` change leaves one file holding both until it
    /// rotates, which is exactly when someone has just switched a JSON
    /// format on to get these detectors working.
    #[test]
    fn scanning_ips_reads_a_file_holding_both_formats() {
        let mut log = String::new();
        for i in 0..6 {
            log.push_str(&not_found_line("198.51.100.9", &format!("/combined-{i}")));
            log.push_str(&json_line("198.51.100.9", &format!("/json-{i}"), 404));
        }
        assert_eq!(
            scanning_ips(&log, 10),
            vec!["198.51.100.9".to_string()],
            "twelve distinct 404s across the two formats is one scanner, log was:\n{log}"
        );
    }

    /// The trap three-state `referer` exists to avoid: this format does
    /// not log the header, so every request in it *looks* referer-less.
    /// Counting those would hand a firewall block to every ordinary
    /// visitor on such a host.
    #[test]
    fn refererless_crawl_ips_skips_a_json_format_that_does_not_log_the_referer() {
        let log: String = (0..40)
            .map(|i| {
                format!(
                    r#"{{"remote_addr": "203.0.113.9", "request_uri": "/page-{i}", "status": "200"}}"#
                ) + "\n"
            })
            .collect();
        assert!(
            refererless_crawl_ips(&log, 25).is_empty(),
            "a format with no http_referer key cannot answer this, log was:\n{log}"
        );
    }

    /// And the other half of that claim: once the format *does* record the
    /// header, the same crawl is detected exactly as it is in a combined log.
    #[test]
    fn refererless_crawl_ips_flags_a_deep_crawl_in_a_json_log_that_records_the_referer() {
        let log: String = (0..40)
            .map(|i| json_line("203.0.113.9", &format!("/page-{i}"), 200))
            .collect();
        assert_eq!(
            refererless_crawl_ips(&log, 25),
            vec!["203.0.113.9".to_string()],
            "log was:\n{log}"
        );
    }

    #[test]
    fn successful_user_agent_counts_reads_a_json_log() {
        let log = json_line("203.0.113.5", "/a", 200) + &json_line("203.0.113.5", "/b", 200);
        assert_eq!(
            successful_user_agent_counts(&log).get("Mozilla/5.0"),
            Some(&2),
            "log was:\n{log}"
        );
    }

    /// The core discriminator this module exists to get right: repeatedly
    /// hitting the *same* dead path must never look like scanning, no
    /// matter how many times, while hitting many *different* dead paths
    /// must, even at a lower total count.
    #[test]
    fn scanning_ips_distinguishes_repeated_from_distinct_not_found_paths() {
        let repeated: String = (0..50)
            .map(|_| not_found_line("198.51.100.9", "/missing"))
            .collect();
        assert!(scanning_ips(&repeated, 10).is_empty());

        let distinct: String = (0..10)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        assert_eq!(
            scanning_ips(&distinct, 10),
            vec!["198.51.100.9".to_string()]
        );
    }

    #[test]
    fn scanning_ips_ignores_an_ip_below_the_threshold() {
        let log: String = (0..9)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        assert!(scanning_ips(&log, 10).is_empty());
    }

    /// Unlike `sshlog::scanning_ips`, a 200 elsewhere in the log must NOT
    /// exempt an IP — a scanner's own recon traffic almost always includes
    /// at least one successful hit.
    #[test]
    fn scanning_ips_still_flags_an_ip_that_also_got_a_200() {
        let mut log: String = (0..10)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        log.push_str(&ok_line("198.51.100.9", "/"));
        assert_eq!(scanning_ips(&log, 10), vec!["198.51.100.9".to_string()]);
    }

    #[test]
    fn scanning_ips_excludes_loopback_and_private_addresses() {
        let mut log = String::new();
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.5", "fc00::1"] {
            for i in 0..10 {
                log.push_str(&not_found_line(ip, &format!("/missing-{i}")));
            }
        }
        assert!(scanning_ips(&log, 10).is_empty());
    }

    #[test]
    fn scanning_ips_is_sorted_and_deduplicated() {
        let mut log = String::new();
        for i in 0..10 {
            log.push_str(&not_found_line("198.51.100.9", &format!("/a-{i}")));
        }
        for i in 0..10 {
            log.push_str(&not_found_line("198.51.100.2", &format!("/b-{i}")));
        }
        assert_eq!(
            scanning_ips(&log, 10),
            vec!["198.51.100.2".to_string(), "198.51.100.9".to_string()]
        );
    }

    fn line_with(ip: &str, status: u16, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" {status} 512 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn successful_user_agent_counts_tallies_each_distinct_agent() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 200, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.6", 200, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.7", 304, "curl/8.0"));

        let counts = successful_user_agent_counts(&log);
        assert_eq!(counts.get("Mozilla/5.0"), Some(&2));
        assert_eq!(counts.get("curl/8.0"), Some(&1));
    }

    /// Tallied as the stats will store them: two agents that agree on
    /// their first 512 characters are one.
    #[test]
    fn the_scheduled_tally_cuts_a_long_user_agent_as_it_will_be_stored() {
        let prefix = "x".repeat(crate::db::MAX_STORED_USER_AGENT_CHARS);
        let mut observer = Observer::new(Watch::default()).counting_user_agents();
        for tail in ["a", "b"] {
            let line = line_with("203.0.113.5", 200, &format!("{prefix}{tail}"));
            observer.line(&line, Clock::Ordinal(0));
        }

        let (_, user_agents, _) = observer.finish();

        assert_eq!(user_agents, HashMap::from([(prefix, 2)]));
    }

    #[test]
    fn successful_user_agent_counts_excludes_client_and_server_errors() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 404, "Mozilla/5.0"));
        log.push_str(&line_with("203.0.113.5", 500, "Mozilla/5.0"));

        assert!(successful_user_agent_counts(&log).is_empty());
    }

    #[test]
    fn successful_user_agent_counts_excludes_missing_user_agent() {
        let mut log = String::new();
        log.push_str(&line_with("203.0.113.5", 200, "-"));
        log.push_str(&ok_line("203.0.113.6", "/")); // has a real UA, sanity check

        let counts = successful_user_agent_counts(&log);
        assert!(!counts.contains_key("-"));
        assert_eq!(counts.get("Mozilla/5.0"), Some(&1));
    }

    #[test]
    fn successful_user_agent_counts_excludes_loopback_and_private_addresses() {
        let mut log = String::new();
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.5", "fc00::1"] {
            log.push_str(&line_with(ip, 200, "curl/8.0"));
        }
        assert!(successful_user_agent_counts(&log).is_empty());
    }

    #[test]
    fn read_log_file_reports_unavailable_for_a_missing_path() {
        assert_eq!(
            read_log_file(Path::new("/nonexistent/does-not-exist.log")),
            LogSource::Unavailable
        );
    }

    #[test]
    fn read_log_file_reads_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        std::fs::write(&path, not_found_line("1.2.3.4", "/x")).unwrap();

        match read_log_file(&path) {
            LogSource::Found(content) => assert!(content.contains("1.2.3.4")),
            LogSource::Unavailable => panic!("expected the file to be readable"),
        }
    }

    /// A client puts whatever bytes it likes in a header, and one that is
    /// not UTF-8 must not make the log unreadable until it rotates —
    /// "unavailable" switches every access-log detector off.
    #[test]
    fn read_log_file_survives_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let mut bytes = b"198.51.100.1 - - [10/Jul/2026:12:00:00 +0000] \"GET /a HTTP/1.1\" 404 1 \"-\" \"\xff\"\n".to_vec();
        bytes.extend_from_slice(not_found_line("198.51.100.2", "/b").as_bytes());
        std::fs::write(&path, bytes).unwrap();

        let LogSource::Found(text) = read_log_file(&path) else {
            panic!("a log with one invalid byte was reported unavailable");
        };
        assert_eq!(
            scanning_ips(&text, 1),
            vec!["198.51.100.1".to_string(), "198.51.100.2".to_string()],
            "text was:\n{text}"
        );
    }

    // ---- JSON duplicate keys ----

    /// Under `escape=none` a client can close the string it is in and write
    /// keys of its own. serde keeps the *last* of a duplicated key, and
    /// taking the first instead only moves the problem to formats that log
    /// the header before `remote_addr`. Either way the line is someone
    /// else's claim about who sent it, so it is not read at all.
    #[test]
    fn a_json_line_with_a_duplicated_field_is_skipped() {
        let cases = [
            (
                "remote_addr injected after the real one",
                r#"{"remote_addr":"203.0.113.5","request_uri":"/.env","status":"404","http_user_agent":"","remote_addr":"8.8.4.4"}"#,
            ),
            (
                "remote_addr injected before the real one",
                r#"{"http_user_agent":"","remote_addr":"8.8.4.4","remote_addr":"203.0.113.5","request_uri":"/.env","status":"404"}"#,
            ),
            (
                "status injected",
                r#"{"remote_addr":"203.0.113.5","request_uri":"/.env","status":"200","http_referer":"","status":"404"}"#,
            ),
            (
                "the time injected, to backdate the line out of every window",
                r#"{"time_local":"28/Sep/2026:06:33:01 +0000","remote_addr":"203.0.113.5","request_uri":"/.env","status":"404","http_user_agent":"","time_local":"01/Jan/2000:00:00:00 +0000"}"#,
            ),
            (
                "the target injected",
                r#"{"remote_addr":"203.0.113.5","request_uri":"/","http_user_agent":"","request_uri":"/.env","status":"404"}"#,
            ),
        ];
        for (description, line) in cases {
            assert_eq!(parse_line(line), None, "should not parse: {description}");
        }
    }

    /// Only the fields this reads are held to it: a format that happens to
    /// log some other variable twice is not a forgery of anything read here.
    #[test]
    fn a_json_line_duplicating_a_field_nobody_reads_still_parses() {
        let line = r#"{"body_bytes_sent":"1","remote_addr":"203.0.113.5","request_uri":"/x","status":"404","body_bytes_sent":"2"}"#;
        assert_eq!(
            parse_line(line).map(|l| l.ip),
            Some("203.0.113.5".parse().unwrap())
        );
    }

    // ---- spoofed crawler detection ----

    fn claim(marker: &'static str, name: &'static str, ranges: &[&str]) -> CrawlerClaim {
        CrawlerClaim {
            marker,
            name,
            ranges: ranges.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn ua_line(ip: &str, ua: &str) -> String {
        format!("{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{ua}\"\n")
    }

    fn googlebot_claim() -> CrawlerClaim {
        claim("googlebot", "Googlebot IP ranges", &["66.249.64.0/19"])
    }

    #[test]
    fn spoofed_crawler_ips_flags_a_googlebot_claim_from_outside_googles_ranges() {
        let log = ua_line("203.0.113.9", "Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(
            spoofed_crawler_ips(&log, &[googlebot_claim()]),
            vec![("203.0.113.9".to_string(), "Googlebot IP ranges".to_string())]
        );
    }

    #[test]
    fn spoofed_crawler_ips_leaves_the_real_googlebot_alone() {
        let log = ua_line("66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_ignores_a_user_agent_that_claims_nothing() {
        let log = ua_line("203.0.113.9", "Mozilla/5.0 (X11; Linux x86_64)");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_matches_the_marker_case_insensitively() {
        let log = ua_line("203.0.113.9", "GOOGLEBOT");
        assert_eq!(spoofed_crawler_ips(&log, &[googlebot_claim()]).len(), 1);
    }

    /// The single most important property here: with no ranges fetched,
    /// every real crawler request looks forged. Skipping the crawler
    /// entirely is the only safe reading of "we have no data".
    #[test]
    fn spoofed_crawler_ips_skips_a_crawler_with_no_fetched_ranges() {
        let empty = claim("googlebot", "Googlebot IP ranges", &[]);
        let log = ua_line("203.0.113.9", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[empty]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_is_empty_with_no_claims_at_all() {
        let log = ua_line("203.0.113.9", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_excludes_local_and_private_sources() {
        let log = ua_line("10.0.0.5", "Googlebot/2.1") + &ua_line("127.0.0.1", "Googlebot/2.1");
        assert!(spoofed_crawler_ips(&log, &[googlebot_claim()]).is_empty());
    }

    #[test]
    fn spoofed_crawler_ips_deduplicates_and_sorts() {
        let log = ua_line("203.0.113.9", "Googlebot/2.1")
            + &ua_line("203.0.113.9", "Googlebot/2.1")
            + &ua_line("198.51.100.2", "bingbot/2.0");
        let found = spoofed_crawler_ips(
            &log,
            &[
                googlebot_claim(),
                claim("bingbot", "Bingbot IP ranges", &["40.77.167.0/24"]),
            ],
        );
        let ips: Vec<&str> = found.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(ips, vec!["198.51.100.2", "203.0.113.9"]);
    }

    /// An IP verified against one crawler's ranges must not be flagged by a
    /// *different* claim it also happens to mention.
    #[test]
    fn spoofed_crawler_ips_does_not_flag_a_verified_ip_for_another_claim() {
        let log = ua_line("66.249.66.1", "Googlebot/2.1 bingbot/2.0");
        let found = spoofed_crawler_ips(
            &log,
            &[
                googlebot_claim(),
                claim("bingbot", "Bingbot IP ranges", &["40.77.167.0/24"]),
            ],
        );
        // Verified as Googlebot, so the stray "bingbot" token isn't
        // treated as an impersonation of Bing on its own.
        assert!(found.is_empty(), "unexpectedly flagged: {found:?}");
    }

    // ---- probe-path detection ----

    fn probe_line(ip: &str, path: &str, status: u16) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 0 \"-\" \"curl/8\"\n"
        )
    }

    fn default_probes() -> Vec<String> {
        DEFAULT_PROBE_PATHS.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn robots_txt_ips_finds_the_fetchers_and_nobody_else() {
        let log = format!(
            "{}{}{}",
            line_with("203.0.113.5", 200, "Mozilla/5.0"),
            probe_line("198.51.100.7", "/robots.txt", 200),
            probe_line("198.51.100.8", "/blog/robots.txt", 200),
        );

        let found = robots_txt_ips(&log);

        assert_eq!(found, vec!["198.51.100.7", "198.51.100.8"]);
    }

    /// The operator's own monitoring hits the site from the host, and a
    /// day-long block on the loopback address would be a self-inflicted
    /// outage.
    #[test]
    fn robots_txt_ips_skips_local_and_private_sources() {
        let log = format!(
            "{}{}",
            probe_line("127.0.0.1", "/robots.txt", 200),
            probe_line("10.0.0.5", "/robots.txt", 200),
        );

        assert!(robots_txt_ips(&log).is_empty());
    }

    /// One address that asked twice is one address.
    #[test]
    fn robots_txt_ips_reports_each_address_once() {
        let log = format!(
            "{}{}",
            probe_line("198.51.100.7", "/robots.txt", 200),
            probe_line("198.51.100.7", "/robots.txt", 200),
        );

        assert_eq!(robots_txt_ips(&log).len(), 1);
    }

    #[test]
    fn probe_path_ips_flags_a_single_dotenv_request() {
        let log = probe_line("203.0.113.9", "/.env", 404);
        assert_eq!(
            probe_path_ips(&log, &default_probes()),
            vec![("203.0.113.9".to_string(), "/.env".to_string())]
        );
    }

    /// The response is irrelevant — a 200 for `/.env` is the *worse* case,
    /// so keying on 404 the way `scanning_ips` does would skip it.
    #[test]
    fn probe_path_ips_flags_a_successful_probe_too() {
        let log = probe_line("203.0.113.9", "/.env", 200);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    #[test]
    fn probe_path_ips_matches_by_prefix_and_case_insensitively() {
        let log = probe_line("203.0.113.9", "/.ENV.local", 404)
            + &probe_line("198.51.100.2", "/.git/config", 404);
        let found = probe_path_ips(&log, &default_probes());
        let ips: Vec<&str> = found.iter().map(|(ip, _)| ip.as_str()).collect();
        assert_eq!(ips, vec!["198.51.100.2", "203.0.113.9"]);
    }

    /// Anchored at the start, so an ordinary page whose URL merely contains
    /// one of these strings is not a probe.
    ///
    /// The example is the one the leading slash in every needle protects:
    /// `-env` is not `/.env`. It used to be
    /// `/blog/how-to-secure-your/.env-file`, which the anchoring also
    /// excluded — and so did the anchoring exclude `/api/.env`, which is
    /// why the anchoring is gone. A path segment beginning with a dot is
    /// not something sites serve; a word ending in "env" is.
    #[test]
    fn probe_path_ips_does_not_match_a_word_that_merely_ends_in_the_needle() {
        let log = probe_line("203.0.113.9", "/blog/how-to-secure-your-env", 200);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    /// The gap the anchoring left: every one of these was being missed,
    /// and between them they are most of what actually probes a server.
    #[test]
    fn probe_path_ips_flags_a_dotfile_below_the_root() {
        for path in [
            "/api/.env",
            "/backend/.env",
            "/laravel/.env",
            "/var/www/html/wp-config.php",
            "/%252e%252e/%252e%252e/home/ubuntu/.ssh/id_ed25519",
        ] {
            let log = probe_line("203.0.113.9", path, 404);
            assert_eq!(
                probe_path_ips(&log, &default_probes()).len(),
                1,
                "missed {path}"
            );
        }
    }

    /// The two entries added from that log, each with the request that
    /// earned it.
    #[test]
    fn probe_path_ips_flags_the_backdoor_plugin_and_encoded_dots() {
        for path in [
            "/wp-content/plugins/hellopress/wp_filemanager.php",
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
            "/$(pwd)/%2eenv%2elocal",
            "/%2frobots%2etxt",
        ] {
            let log = probe_line("203.0.113.9", path, 404);
            assert_eq!(
                probe_path_ips(&log, &default_probes()).len(),
                1,
                "missed {path}"
            );
        }
    }

    #[test]
    fn probe_path_ips_ignores_ordinary_requests() {
        let log = probe_line("203.0.113.9", "/", 200) + &probe_line("203.0.113.9", "/about", 200);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    #[test]
    fn probe_path_ips_excludes_local_and_private_sources() {
        let log = probe_line("127.0.0.1", "/.env", 404) + &probe_line("10.0.0.5", "/.git/", 404);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
    }

    #[test]
    fn probe_path_ips_is_empty_with_no_configured_paths() {
        let log = probe_line("203.0.113.9", "/.env", 404);
        assert!(probe_path_ips(&log, &[]).is_empty());
    }

    #[test]
    fn probe_path_ips_reports_one_row_per_ip() {
        let log = probe_line("203.0.113.9", "/.env", 404)
            + &probe_line("203.0.113.9", "/.git/config", 404);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    #[test]
    fn probe_path_ips_honours_an_extra_configured_path() {
        let log = probe_line("203.0.113.9", "/my-secret/key", 404);
        assert!(probe_path_ips(&log, &default_probes()).is_empty());
        assert_eq!(probe_path_ips(&log, &["/my-secret".to_string()]).len(), 1);
    }

    /// Query strings are already stripped by `parse_line`, so a probe that
    /// tacks one on is still caught.
    #[test]
    fn probe_path_ips_matches_despite_a_query_string() {
        let log = probe_line("203.0.113.9", "/.env?cachebust=1", 404);
        assert_eq!(probe_path_ips(&log, &default_probes()).len(), 1);
    }

    // ---- behavioural detectors ----

    fn line(ip: &str, path: &str, status: u16, referer: &str, ua: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" {status} 9 \"{referer}\" \"{ua}\"\n"
        )
    }

    fn pages(ip: &str, n: usize) -> String {
        (0..n)
            .map(|i| line(ip, &format!("/page{i}"), 200, "-", "UA"))
            .collect()
    }

    #[test]
    fn asset_less_ips_flags_a_client_that_fetched_pages_and_no_assets() {
        let log = pages("203.0.113.9", 20);
        assert_eq!(asset_less_ips(&log, 15), vec!["203.0.113.9".to_string()]);
    }

    #[test]
    fn asset_less_ips_ignores_a_client_below_the_page_threshold() {
        let log = pages("203.0.113.9", 5);
        assert!(asset_less_ips(&log, 15).is_empty());
    }

    /// A browser fetches the CSS that goes with the page. One asset is
    /// enough to clear the client.
    #[test]
    fn asset_less_ips_clears_a_client_that_fetched_any_asset() {
        let log = pages("203.0.113.9", 20) + &line("203.0.113.9", "/style.css", 200, "-", "UA");
        assert!(asset_less_ips(&log, 15).is_empty());
    }

    /// The false positive that would hit real, well-behaved visitors: a
    /// returning browser gets 304 Not Modified for every cached asset.
    /// Counting only 200s would make them indistinguishable from scrapers.
    #[test]
    fn asset_less_ips_counts_a_304_as_a_fetched_asset() {
        let log = pages("203.0.113.9", 20) + &line("203.0.113.9", "/app.js", 304, "-", "UA");
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "a cached asset still means the client fetches assets"
        );
    }

    /// Distinct paths, not request count — the client this must not catch
    /// is an API consumer hammering a handful of endpoints.
    #[test]
    fn asset_less_ips_counts_distinct_paths_not_requests() {
        let log: String = (0..50)
            .map(|_| line("203.0.113.9", "/api/status", 200, "-", "UA"))
            .collect();
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "50 hits on one endpoint is not a site crawl"
        );
    }

    #[test]
    fn asset_less_ips_ignores_failed_requests() {
        let log: String = (0..20)
            .map(|i| line("203.0.113.9", &format!("/missing{i}"), 404, "-", "UA"))
            .collect();
        assert!(
            asset_less_ips(&log, 15).is_empty(),
            "404 sweeping is scanning_ips' job, not this one"
        );
    }

    #[test]
    fn asset_less_ips_excludes_local_and_private_sources() {
        assert!(asset_less_ips(&pages("10.0.0.5", 20), 15).is_empty());
    }

    #[test]
    fn rotating_user_agent_ips_flags_many_agents_from_one_address() {
        let log: String = (0..10)
            .map(|i| line("203.0.113.9", "/", 200, "-", &format!("Agent{i}")))
            .collect();
        assert_eq!(
            rotating_user_agent_ips(&log, 8),
            vec!["203.0.113.9".to_string()]
        );
    }

    #[test]
    fn rotating_user_agent_ips_ignores_one_agent_used_many_times() {
        let log: String = (0..50)
            .map(|_| line("203.0.113.9", "/", 200, "-", "Mozilla/5.0"))
            .collect();
        assert!(rotating_user_agent_ips(&log, 8).is_empty());
    }

    #[test]
    fn rotating_user_agent_ips_ignores_a_missing_user_agent() {
        // "-" is how NGINX writes an absent header; it isn't an identity.
        let log: String = (0..10)
            .map(|_| line("203.0.113.9", "/", 200, "-", "-"))
            .collect();
        assert!(rotating_user_agent_ips(&log, 8).is_empty());
    }

    #[test]
    fn refererless_crawl_ips_flags_a_deep_crawl_with_no_referer() {
        let log = pages("203.0.113.9", 30);
        assert_eq!(
            refererless_crawl_ips(&log, 25),
            vec!["203.0.113.9".to_string()]
        );
    }

    /// Someone who follows a link has sent a referer at least once; that
    /// clears them entirely, which is what keeps ordinary direct
    /// navigation from accumulating into a false positive.
    #[test]
    fn refererless_crawl_ips_clears_a_client_that_ever_sent_a_referer() {
        let log = pages("203.0.113.9", 30)
            + &line("203.0.113.9", "/other", 200, "https://example.test/", "UA");
        assert!(refererless_crawl_ips(&log, 25).is_empty());
    }

    /// Hitting the front page with no referer is what every bookmark and
    /// typed URL looks like.
    #[test]
    fn refererless_crawl_ips_ignores_the_root_path() {
        let log: String = (0..40)
            .map(|_| line("203.0.113.9", "/", 200, "-", "UA"))
            .collect();
        assert!(refererless_crawl_ips(&log, 25).is_empty());
    }

    #[test]
    fn refererless_crawl_ips_ignores_a_client_below_the_threshold() {
        assert!(refererless_crawl_ips(&pages("203.0.113.9", 5), 25).is_empty());
    }

    // ---- timestamps ----

    /// 2026-09-28T06:33:01Z.
    const SEP_28: i64 = 1_790_577_181;

    #[test]
    fn a_combined_line_carries_its_time() {
        let line =
            "203.0.113.5 - - [28/Sep/2026:08:33:01 +0200] \"GET / HTTP/1.1\" 200 1 \"-\" \"UA\"";
        assert_eq!(parse_line(line).unwrap().time, Some(SEP_28));
    }

    /// A line whose time NGINX did not write, or wrote in a form this does
    /// not read, still parses: it is only undated.
    #[test]
    fn a_line_without_a_readable_time_still_parses_undated() {
        for line in [
            "203.0.113.5 - - [x] \"GET / HTTP/1.1\" 200 1 \"-\" \"UA\"",
            r#"{"remote_addr":"203.0.113.5","request_uri":"/","status":"200"}"#,
        ] {
            let parsed = parse_line(line).expect(line);
            assert_eq!(parsed.time, None, "{line}");
        }
    }

    #[test]
    fn a_json_line_carries_either_time_variable() {
        for line in [
            r#"{"time_iso8601":"2026-09-28T06:33:01+00:00","remote_addr":"203.0.113.5","request_uri":"/","status":"200"}"#,
            r#"{"time_local":"28/Sep/2026:06:33:01 +0000","remote_addr":"203.0.113.5","request_uri":"/","status":"200"}"#,
        ] {
            assert_eq!(parse_line(line).unwrap().time, Some(SEP_28), "{line}");
        }
    }

    fn observed(lines: &[String], watch: Watch, clock: Clock) -> Evidence {
        let mut observer = Observer::new(watch);
        for line in lines {
            observer.line(line, clock);
        }
        observer.finish().0
    }

    fn dated(ip: &str, path: &str, at: &str) -> String {
        format!("{ip} - - [{at}] \"GET {path} HTTP/1.1\" 404 1 \"-\" \"UA\"")
    }

    /// The whole point of the window: a line older than it is not kept,
    /// so it can never add to a count again.
    #[test]
    fn a_line_older_than_its_detector_s_window_is_not_kept() {
        let lines = [
            dated("203.0.113.5", "/.env", "27/Sep/2026:06:33:00 +0000"),
            dated("203.0.113.6", "/.env", "28/Sep/2026:06:00:00 +0000"),
        ];
        let watch = Watch {
            detectors: vec![(Detector::ProbePaths, Some(SEP_28 - 86_400))],
            ..Watch::only(Detector::ProbePaths)
        };
        let evidence = observed(
            &lines,
            watch,
            Clock::Logged {
                now: SEP_28,
                undated: Some(SEP_28),
            },
        );
        let rows = evidence.rows_for(Detector::ProbePaths);
        let addresses: Vec<&str> = rows.iter().map(|r| r.address.as_str()).collect();
        assert_eq!(addresses, ["203.0.113.6"]);
        assert_eq!(rows[0].tally.first, SEP_28 - 1981, "dated by the line");
    }

    /// On a first read nothing says when an undated line was written, and
    /// it may be months old: it counts for nothing.
    #[test]
    fn an_undated_line_is_only_kept_when_the_read_can_date_it() {
        let lines =
            [r#"{"remote_addr":"203.0.113.5","request_uri":"/.env","status":"404"}"#.to_string()];
        let first_read = observed(
            &lines,
            Watch::only(Detector::ProbePaths),
            Clock::Logged {
                now: SEP_28,
                undated: None,
            },
        );
        assert!(first_read.is_empty());

        let later_read = observed(
            &lines,
            Watch::only(Detector::ProbePaths),
            Clock::Logged {
                now: SEP_28,
                undated: Some(SEP_28 - 30),
            },
        );
        assert_eq!(
            later_read.rows_for(Detector::ProbePaths)[0].tally.last,
            SEP_28 - 30,
            "dated when it was read"
        );
    }

    /// A clock that ran ahead cannot put evidence in the future, where no
    /// window would ever let go of it.
    #[test]
    fn a_line_from_the_future_is_dated_now() {
        let lines = [dated("203.0.113.5", "/.env", "01/Jan/2030:00:00:00 +0000")];
        let evidence = observed(
            &lines,
            Watch::only(Detector::ProbePaths),
            Clock::Logged {
                now: SEP_28,
                undated: None,
            },
        );
        assert_eq!(
            evidence.rows_for(Detector::ProbePaths)[0].tally.last,
            SEP_28
        );
    }

    /// One pass serves every detector: the same line is evidence for each
    /// that it concerns.
    #[test]
    fn one_observer_collects_for_every_watched_detector() {
        let lines = [dated("203.0.113.5", "/.env", "28/Sep/2026:06:00:00 +0000")];
        let watch = Watch {
            detectors: vec![
                (Detector::WebScanners, None),
                (Detector::ProbePaths, None),
                (Detector::RobotsTxt, None),
            ],
            ..Watch::only(Detector::ProbePaths)
        };
        let evidence = observed(
            &lines,
            watch,
            Clock::Logged {
                now: SEP_28,
                undated: None,
            },
        );
        assert_eq!(evidence.rows_for(Detector::WebScanners).len(), 1);
        assert_eq!(evidence.rows_for(Detector::ProbePaths).len(), 1);
        assert!(evidence.rows_for(Detector::RobotsTxt).is_empty());
    }

    #[test]
    fn a_survey_counts_what_did_not_parse_and_keeps_a_safe_sample() {
        let mut survey = Survey::new(403);
        survey.line(&ok_line("203.0.113.5", "/"));
        survey.line("203.0.113.5 custom-format \u{1b}[31m hello");
        survey.line("another line nobody can read");
        survey.line("   ");

        assert_eq!(
            survey.counts,
            Counts {
                lines: 3,
                parsed: 1
            }
        );
        assert_eq!(
            survey.unparsed_sample.as_deref(),
            Some("203.0.113.5 custom-format \u{fffd}[31m hello"),
            "the first unparsed line, with its escape sequence defused"
        );
    }

    #[test]
    fn a_long_sample_is_cut_and_says_so() {
        let sample = printable_sample(&"x".repeat(1_000));
        assert_eq!(sample.chars().count(), SAMPLE_CHARS + 1);
        assert!(sample.ends_with('\u{2026}'));
    }

    /// A combined-style line with `"$host"` appended, as an authenticated
    /// sync client writes one.
    fn webdav_404(ip: &str, path: &str, host: &str) -> String {
        format!(
            "{ip} - alice [10/Jul/2026:12:00:00 +0000] \"PROPFIND {path} HTTP/2.0\" 404 223 \
             \"-\" \"Mozilla/5.0 (iOS) Nextcloud-iOS/35.0.0\" \"{host}\" 0.466"
        )
    }

    fn nextcloud_at(name: &str) -> Hosted {
        Hosted::new(vec![
            (name.to_string(), Some(crate::services::Service::Nextcloud)),
            ("blog.example.com".to_string(), None),
        ])
    }

    fn observed_with(lines: &[String], detector: Detector, hosted: Hosted) -> Vec<String> {
        let watch = Watch {
            hosted,
            ..Watch::only(detector)
        };
        observed(lines, watch, Clock::Ordinal(0))
            .rows_for(detector)
            .into_iter()
            .map(|row| row.address)
            .collect()
    }

    #[test]
    fn a_combined_line_keeps_the_fields_after_the_user_agent() {
        let line = webdav_404("203.0.113.5", "/remote.php/dav/a", "cloud.example.com");
        let parsed = parse_line(&line).unwrap();
        assert_eq!(parsed.trailing, ["cloud.example.com"]);
        assert_eq!(
            parsed.host, None,
            "a trailing field is never the console's host"
        );
    }

    /// What locked an owner out: their phone catching up on photos
    /// deleted elsewhere.
    #[test]
    fn a_sync_clients_404s_on_its_sites_data_routes_are_not_scanning() {
        let lines: Vec<String> = (0..100)
            .map(|i| {
                let path = format!("/remote.php/dav/files/alice/Photos/IMG_{i}.jpg");
                webdav_404("203.0.113.5", &path, "cloud.example.com")
            })
            .collect();
        let found = observed_with(
            &lines,
            Detector::WebScanners,
            nextcloud_at("cloud.example.com"),
        );
        assert!(found.is_empty(), "counted as scanning: {found:?}");
    }

    #[test]
    fn the_same_404s_for_a_site_without_the_application_still_count() {
        let lines = vec![webdav_404(
            "203.0.113.5",
            "/remote.php/dav/a",
            "blog.example.com",
        )];
        let found = observed_with(
            &lines,
            Detector::WebScanners,
            nextcloud_at("cloud.example.com"),
        );
        assert_eq!(found, ["203.0.113.5"]);
    }

    #[test]
    fn a_json_lines_host_names_its_site_too() {
        let lines = vec![
            r#"{"remote_addr":"203.0.113.5","request_uri":"/remote.php/dav/a","status":"404","host":"cloud.example.com"}"#.to_string(),
        ];
        let found = observed_with(
            &lines,
            Detector::WebScanners,
            nextcloud_at("cloud.example.com"),
        );
        assert!(found.is_empty(), "counted as scanning: {found:?}");
    }

    /// The routes only excuse what a client app looks like, not what an
    /// attacker sends.
    #[test]
    fn a_probe_on_an_app_route_is_still_a_probe() {
        let lines = vec![webdav_404(
            "203.0.113.5",
            "/remote.php/.env",
            "cloud.example.com",
        )];
        let found = observed_with(
            &lines,
            Detector::ProbePaths,
            nextcloud_at("cloud.example.com"),
        );
        assert_eq!(found, ["203.0.113.5"]);
    }
}
