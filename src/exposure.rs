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

//! Would this host have handed `/.env` to the scanner that asked for it?
//!
//! The probe-paths detector blocks whoever asks for `/.env`, but only
//! after the request has been answered, so whether the answer was a 404
//! or the database password is the question that decides how bad the
//! request was. This asks each of the host's own sites for a short list
//! of such files, over loopback, the way a scanner would, and reports the
//! ones that come back as the file.
//!
//! ## Only what is really the file
//!
//! A 200 is not enough. Plenty of sites answer every path with something:
//! a single-page app serves its `index.html` for any URL, and a CMS its
//! own "not found" page with a 200. So a path counts only if
//!
//! - it is answered 200,
//! - the answer does not look like the one for a path that cannot exist
//!   (same status, content type and length is the site's catch-all), and
//! - the body looks like the file: `[core]` in a `.git/config`, `KEY=`
//!   lines in a `.env`, a key's armour in `id_rsa`.
//!
//! ## Not turned away by our own block
//!
//! The generated config refuses agents by name and requests by shape, and
//! a check that was refused by it would report every site clean. So the
//! requests look like a current browser's ([`USER_AGENT`] and the headers
//! the request rules look for), and a site that answers even the path
//! that cannot exist with the block's status is reported as not checked
//! rather than as clean. The source is loopback, which no detector ever
//! blocks ([`crate::ipranges::is_local_or_private`]), so asking for
//! `/.env` here does not get this host blocked by itself.
//!
//! ## Bounded
//!
//! This runs in every health probe, from cron and the TUI as well as
//! `status`, so the whole survey has a deadline ([`Limits::budget`]), and
//! what has not answered by then is reported as not answering. It never
//! follows a redirect: a redirect is an answer, and not the file.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;

use crate::webserver::{Listen, SiteListens};

/// The agent every request is sent as: a current Firefox, so that no bot
/// list (and not the old-browsers list) refuses it. With the path that
/// cannot exist, `/stop-bots-exposure-check-…`, it is what tells these
/// requests apart in an access log ([`is_own_request`]).
pub const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";

/// A file a site should never serve, and how to recognise it.
pub struct Sensitive {
    pub path: &'static str,
    /// Credentials, source or data: critical when served. The rest give
    /// an attacker a map rather than a key.
    pub secret: bool,
    looks_like: fn(&[u8]) -> bool,
}

/// What is asked for. Short on purpose: every probe asks each site for
/// all of it. Most sit under [`crate::accesslog::DEFAULT_PROBE_PATHS`],
/// which are prefixes (`/.git/`) where these are files.
///
/// `/server-status` is not here although scanners ask for it: Debian's
/// Apache serves it to localhost only, and this asks from localhost, so
/// it would be reported on every such host while being served to nobody.
pub const PATHS: [Sensitive; 19] = [
    secret("/.env", env_file),
    secret("/.env.local", env_file),
    secret("/.git/config", git_config),
    secret("/.git/HEAD", git_head),
    secret("/.svn/entries", svn_entries),
    secret("/.aws/credentials", aws_credentials),
    secret("/.ssh/id_rsa", private_key),
    secret("/id_rsa", private_key),
    secret("/.htpasswd", htpasswd),
    secret("/backup.sql", sql_dump),
    secret("/dump.sql", sql_dump),
    secret("/db.sql", sql_dump),
    secret("/database.sql", sql_dump),
    secret("/wp-config.php.bak", wp_config),
    secret("/wp-config.php~", wp_config),
    secret("/config.php.bak", php_source),
    lesser("/.DS_Store", ds_store),
    lesser("/phpinfo.php", phpinfo),
    lesser("/info.php", phpinfo),
];

const fn secret(path: &'static str, looks_like: fn(&[u8]) -> bool) -> Sensitive {
    Sensitive {
        path,
        secret: true,
        looks_like,
    }
}

const fn lesser(path: &'static str, looks_like: fn(&[u8]) -> bool) -> Sensitive {
    Sensitive {
        path,
        secret: false,
        looks_like,
    }
}

/// What the path that cannot exist starts with.
const ABSENT_PREFIX: &str = "/stop-bots-exposure-check-";

/// Whether a logged request is one of this check's own: from a local or
/// private address, as [`USER_AGENT`], for one of [`PATHS`] or the path
/// that cannot exist.
///
/// The access log's readers leave these out. Every probe adds twenty
/// lines per site, and on a quiet host that is enough to make the log
/// read as mostly a proxy's, and to count a Firefox nobody runs among
/// the clients this host serves.
///
/// The check connects over loopback, but the log does not always say so:
/// to an NGINX in a container whose port Docker publishes, the request
/// comes from the bridge's gateway (`172.22.0.1`), handed on by Docker's
/// proxy. So any local or private source counts
/// ([`crate::ipranges::is_local_or_private`]), the same addresses no
/// detector ever blocks: leaving one of them out of a count hides nothing
/// that could have been blocked.
pub fn is_own_request(ip: &IpAddr, user_agent: &str, path: &str) -> bool {
    crate::ipranges::is_local_or_private(ip)
        && user_agent == USER_AGENT
        && (path.starts_with(ABSENT_PREFIX) || PATHS.iter().any(|p| p.path == path))
}

/// Whether `path` is one of the [`Sensitive::secret`] ones. A path this
/// build does not list (from a probe a newer one took) counts as secret.
pub fn is_secret(path: &str) -> bool {
    PATHS
        .iter()
        .find(|sensitive| sensitive.path == path)
        .is_none_or(|sensitive| sensitive.secret)
}

/// One site, at one address it is served on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub site: String,
    /// Always a loopback address. See [`targets`].
    pub ip: IpAddr,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    /// `https://site:8443`, with the port only when it is not the scheme's.
    fn origin(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            format!("{scheme}://{}", self.site)
        } else {
            format!("{scheme}://{}:{}", self.site, self.port)
        }
    }
}

/// What to ask: every site by name, at every port it listens on, over
/// loopback.
///
/// A site's port-80 and port-443 blocks are both asked, since either can
/// serve the file. Left out:
///
/// - names that are not a host name a request can carry: `_`, a regex
///   (`~^…`), a wildcard, a variable, an address;
/// - a listen on a specific address that is not loopback. The request
///   would come from that address, which is public, and the probe-paths
///   detector would block this host for asking.
///
/// `[::]` is asked at `::1`, unless the same port is also on IPv4.
pub fn targets(sites: &[SiteListens]) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    for site in sites {
        let name = site.server_name.trim_end_matches('.').to_ascii_lowercase();
        if !is_host_name(&name) {
            continue;
        }
        let default = [Listen {
            address: None,
            port: 80,
            tls: false,
        }];
        let listens = if site.listens.is_empty() {
            &default[..]
        } else {
            &site.listens[..]
        };
        for listen in listens {
            let Some(ip) = loopback_for(listen.address) else {
                continue;
            };
            let target = Target {
                site: name.clone(),
                ip,
                port: listen.port,
                tls: listen.tls,
            };
            let same_port = out.iter().position(|t| {
                t.site == target.site && t.port == target.port && t.tls == target.tls
            });
            match same_port {
                Some(i) if out[i].ip.is_ipv6() && target.ip.is_ipv4() => out[i] = target,
                Some(_) => {}
                None => out.push(target),
            }
        }
    }
    out
}

/// The loopback address that reaches a listen on `address`, if one does.
fn loopback_for(address: Option<IpAddr>) -> Option<IpAddr> {
    match address {
        None => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(IpAddr::V4(v4)) if v4.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Some(IpAddr::V6(v6)) if v6.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        Some(ip) if ip.is_loopback() => Some(ip),
        Some(_) => None,
    }
}

fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.parse::<IpAddr>().is_err()
        && name.bytes().any(|b| b.is_ascii_alphabetic())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// How long the survey may take.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The whole survey, every site.
    pub budget: Duration,
    /// One request, connect through the last byte read.
    pub request: Duration,
}

impl Default for Limits {
    /// Four seconds in all: loopback answers in milliseconds, so this is
    /// room for a slow application behind a proxy, not for a site that
    /// has stopped answering.
    fn default() -> Self {
        Limits {
            budget: Duration::from_secs(4),
            request: Duration::from_millis(1500),
        }
    }
}

/// What the survey found. Stored in the health probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Survey {
    /// How many site addresses were asked.
    pub addresses: usize,
    /// How many answered the path that cannot exist, and so were checked.
    pub answered: usize,
    /// Every file served, worst first.
    pub leaks: Vec<Leak>,
    /// The addresses that were not checked, each with why:
    /// `https://a.example (connection refused)`.
    pub unanswered: Vec<String>,
}

/// One file a site served.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Leak {
    pub site: String,
    pub path: String,
    /// Where it was served, as a visitor would ask for it.
    pub url: String,
}

/// Asks every target for every one of [`PATHS`], within `limits`.
///
/// Blocking, and safe to call from anywhere: the requests run on a
/// runtime of their own, on a thread of their own, since the callers are
/// a CLI already inside a runtime and a `spawn_blocking` task.
/// `block_status` is what the generated block answers a refused request
/// with.
pub fn survey(targets: &[Target], block_status: u16, limits: Limits) -> Survey {
    let targets = targets.to_vec();
    let asked = targets.len();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match runtime {
            Ok(runtime) => runtime.block_on(survey_async(&targets, block_status, limits)),
            Err(err) => Survey {
                addresses: targets.len(),
                unanswered: vec![format!("could not start: {err}")],
                ..Survey::default()
            },
        }
    })
    .join()
    .unwrap_or_else(|_| Survey {
        addresses: asked,
        unanswered: vec!["the survey failed".to_string()],
        ..Survey::default()
    })
}

/// How many site addresses are asked at once.
const CONCURRENCY: usize = 8;

/// The most of a body read. Every signature is near the start.
const MAX_BODY: usize = 64 * 1024;

enum Outcome {
    Answered(Vec<Leak>),
    Unanswered(String),
}

async fn survey_async(targets: &[Target], block_status: u16, limits: Limits) -> Survey {
    let deadline = tokio::time::Instant::now() + limits.budget;
    // One client per loopback address, each resolving every site's name
    // there, so the request carries the site's name in its `Host` and its
    // TLS handshake while connecting to this host.
    let mut names: HashMap<IpAddr, Vec<&str>> = HashMap::new();
    for target in targets {
        names.entry(target.ip).or_default().push(&target.site);
    }
    let clients: HashMap<IpAddr, Result<reqwest::Client, String>> = names
        .into_iter()
        .map(|(ip, names)| (ip, client(ip, &names, limits).map_err(|e| e.to_string())))
        .collect();

    let outcomes: Vec<(&Target, Outcome)> = futures::stream::iter(targets)
        .map(|target| {
            let client = clients[&target.ip].clone();
            async move {
                let outcome = match client {
                    Ok(client) => tokio::time::timeout_at(
                        deadline,
                        check_target(&client, target, block_status),
                    )
                    .await
                    .unwrap_or_else(|_| Outcome::Unanswered("no answer in time".to_string())),
                    Err(err) => Outcome::Unanswered(err),
                };
                (target, outcome)
            }
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;

    let mut survey = Survey {
        addresses: targets.len(),
        ..Survey::default()
    };
    for (target, outcome) in outcomes {
        match outcome {
            Outcome::Answered(leaks) => {
                survey.answered += 1;
                survey.leaks.extend(leaks);
            }
            Outcome::Unanswered(why) => survey
                .unanswered
                .push(format!("{} ({why})", target.origin())),
        }
    }
    survey
        .leaks
        .sort_by(|a, b| (!is_secret(&a.path), &a.url).cmp(&(!is_secret(&b.path), &b.url)));
    survey.unanswered.sort();
    survey
}

fn client(ip: IpAddr, names: &[&str], limits: Limits) -> reqwest::Result<reqwest::Client> {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE};
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    let mut builder = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        // Nothing between this host and itself, whatever the environment
        // says about proxies.
        .no_proxy()
        // The certificate is for the site's name and this is loopback;
        // what is checked is what is served, not who serves it. The name
        // is still sent (SNI), so the right site answers.
        .tls_danger_accept_invalid_certs(true)
        .connect_timeout(limits.request)
        .timeout(limits.request);
    for name in names {
        builder = builder.resolve(name, SocketAddr::new(ip, 0));
    }
    builder.build()
}

/// What a response looked like, for telling a site's catch-all apart from
/// a file.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    status: u16,
    content_type: Option<String>,
    length: u64,
}

async fn fetch(client: &reqwest::Client, url: &str) -> reqwest::Result<(Shape, Vec<u8>)> {
    let mut response = client.get(url).send().await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let declared = response.content_length();
    let mut body = Vec::new();
    if status == 200 {
        while let Some(chunk) = response.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() >= MAX_BODY {
                break;
            }
        }
    }
    let length = declared.unwrap_or(body.len() as u64);
    Ok((
        Shape {
            status,
            content_type,
            length,
        },
        body,
    ))
}

async fn check_target(client: &reqwest::Client, target: &Target, block_status: u16) -> Outcome {
    let origin = target.origin();
    let absent = format!(
        "{origin}{ABSENT_PREFIX}{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let baseline = match fetch(client, &absent).await {
        Ok((shape, _)) => shape,
        Err(err) => return Outcome::Unanswered(reason(&err)),
    };
    if baseline.status == block_status && !matches!(block_status, 200 | 404) {
        return Outcome::Unanswered(format!(
            "answered {block_status} even for a page that does not exist, as a block does"
        ));
    }
    let answers = futures::future::join_all(PATHS.iter().map(|sensitive| {
        let url = format!("{origin}{}", sensitive.path);
        async move { (sensitive, fetch(client, &url).await, url) }
    }))
    .await;
    let leaks = answers
        .into_iter()
        .filter_map(|(sensitive, answer, url)| {
            let (shape, body) = answer.ok()?;
            (shape.status == 200 && shape != baseline && (sensitive.looks_like)(&body)).then(|| {
                Leak {
                    site: target.site.clone(),
                    path: sensitive.path.to_string(),
                    url,
                }
            })
        })
        .collect();
    Outcome::Answered(leaks)
}

fn reason(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        "no answer in time".to_string()
    } else if err.is_connect() {
        "could not connect".to_string()
    } else {
        "no HTTP answer".to_string()
    }
}

// ---- what each file looks like ----

/// Whether the body starts like a page rather than a file: a catch-all's
/// HTML, served with a 200 for a path it never heard of.
fn markup(body: &[u8]) -> bool {
    body.iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'<')
}

fn contains(body: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(body).contains(needle)
}

fn contains_ignoring_case(body: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(body)
        .to_ascii_lowercase()
        .contains(needle)
}

/// `KEY=value` lines, optionally `export`ed.
fn env_file(body: &[u8]) -> bool {
    !markup(body)
        && String::from_utf8_lossy(body).lines().any(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            line.split_once('=').is_some_and(|(key, _)| {
                key.bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                    && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        })
}

fn git_config(body: &[u8]) -> bool {
    contains(body, "[core]")
}

/// `ref: refs/heads/main`, or a detached head's hash.
fn git_head(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    text.starts_with("ref: refs/")
        || (text.len() == 40 && text.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A format number on the first line (Subversion 1.4 on), or the XML
/// before it.
fn svn_entries(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    let first = text.lines().next().unwrap_or("").trim();
    (!first.is_empty() && first.bytes().all(|b| b.is_ascii_digit())) || text.contains("<wc-entries")
}

fn aws_credentials(body: &[u8]) -> bool {
    contains_ignoring_case(body, "aws_access_key_id")
}

fn private_key(body: &[u8]) -> bool {
    contains(body, "PRIVATE KEY-----")
}

/// `user:hash` lines.
fn htpasswd(body: &[u8]) -> bool {
    !markup(body)
        && String::from_utf8_lossy(body).lines().any(|line| {
            line.split_once(':').is_some_and(|(user, hash)| {
                !user.is_empty() && !hash.is_empty() && !line.contains(char::is_whitespace)
            })
        })
}

fn sql_dump(body: &[u8]) -> bool {
    !markup(body)
        && [
            "create table",
            "insert into",
            "-- mysql dump",
            "postgresql database dump",
        ]
        .iter()
        .any(|needle| contains_ignoring_case(body, needle))
}

fn wp_config(body: &[u8]) -> bool {
    contains(body, "DB_PASSWORD")
}

fn php_source(body: &[u8]) -> bool {
    contains(body, "<?php")
}

/// The Finder's own magic number.
fn ds_store(body: &[u8]) -> bool {
    body.starts_with(b"\0\0\0\x01Bud1")
}

fn phpinfo(body: &[u8]) -> bool {
    contains(body, "phpinfo()") || (contains(body, "PHP Version") && contains(body, "PHP License"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;

    const BLOCK_STATUS: u16 = 403;

    /// A plain-http site on a loopback port, answering each request with
    /// what `route` says for its path: `(status, content type, body)`.
    /// A real server rather than a fake client, for the reason
    /// `fetch.rs`'s tests give.
    fn site(route: fn(&str) -> (u16, &'static str, Vec<u8>)) -> Target {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let path = text.split(' ').nth(1).unwrap_or("/").to_string();
                    let (status, content_type, body) = route(&path);
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        Target {
            site: "a.example".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            tls: false,
        }
    }

    fn not_found() -> (u16, &'static str, Vec<u8>) {
        (404, "text/html", b"<h1>Not Found</h1>".to_vec())
    }

    fn ask(target: Target) -> Survey {
        survey(&[target], BLOCK_STATUS, Limits::default())
    }

    #[test]
    fn a_site_serving_its_env_file_leaks_it_by_name() {
        let survey = ask(site(|path| match path {
            "/.env" => (
                200,
                "application/octet-stream",
                b"DB_PASSWORD=hunter2\n".to_vec(),
            ),
            _ => not_found(),
        }));

        let leaked: Vec<&str> = survey.leaks.iter().map(|l| l.url.as_str()).collect();
        assert!(
            leaked.len() == 1
                && leaked[0].starts_with("http://a.example:")
                && leaked[0].ends_with("/.env"),
            "survey was: {survey:?}"
        );
        assert_eq!(survey.answered, 1, "survey was: {survey:?}");
    }

    /// The single-page app: `index.html` for every path, with a 200.
    #[test]
    fn a_catch_all_that_serves_its_index_for_everything_leaks_nothing() {
        let survey = ask(site(|_| {
            (
                200,
                "text/html",
                b"<!doctype html><div id=app></div>".to_vec(),
            )
        }));

        assert!(survey.leaks.is_empty(), "survey was: {survey:?}");
        assert_eq!(survey.answered, 1, "survey was: {survey:?}");
    }

    /// The same catch-all, serving text the shape of a `.env` — the one
    /// case the signatures alone would get wrong.
    #[test]
    fn a_catch_all_answer_is_not_a_leak_even_when_it_looks_like_the_file() {
        let survey = ask(site(|_| (200, "text/plain", b"STATUS=ok\n".to_vec())));

        assert!(survey.leaks.is_empty(), "survey was: {survey:?}");
    }

    #[test]
    fn a_site_that_refuses_the_paths_leaks_nothing() {
        let survey = ask(site(|path| {
            if path.starts_with("/.") {
                (403, "text/html", b"<h1>Forbidden</h1>".to_vec())
            } else {
                not_found()
            }
        }));

        assert!(survey.leaks.is_empty(), "survey was: {survey:?}");
        assert_eq!(survey.answered, 1, "survey was: {survey:?}");
    }

    /// What our own block looks like from here: the block's status for
    /// everything. Clean would be a lie; not checked is the truth.
    #[test]
    fn a_site_that_answers_everything_with_the_block_status_is_not_checked() {
        let survey = ask(site(|_| (403, "text/html", b"<h1>403</h1>".to_vec())));

        assert_eq!(survey.answered, 0, "survey was: {survey:?}");
        assert!(
            survey.unanswered.len() == 1 && survey.unanswered[0].contains("as a block does"),
            "survey was: {survey:?}"
        );
    }

    #[test]
    fn a_server_that_never_answers_is_given_up_on_within_the_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                held.push(stream);
            }
        });
        let target = Target {
            site: "a.example".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            tls: false,
        };
        let budget = Duration::from_millis(150);

        let started = Instant::now();
        let survey = survey(
            &[target],
            BLOCK_STATUS,
            Limits {
                budget,
                request: Duration::from_secs(10),
            },
        );

        let took = started.elapsed();
        assert!(took < budget + Duration::from_millis(100), "took {took:?}");
        assert!(
            survey.answered == 0 && survey.unanswered[0].contains("no answer in time"),
            "survey was: {survey:?}"
        );
    }

    /// `openssl s_server -WWW`, serving its working directory over TLS
    /// with a self-signed certificate for `a.example`, and refusing the
    /// handshake for any other name (`-servername_fatal`). Killed on drop.
    struct TlsSite {
        server: std::process::Child,
        port: u16,
        _dir: tempfile::TempDir,
    }

    impl Drop for TlsSite {
        fn drop(&mut self) {
            let _ = self.server.kill();
            let _ = self.server.wait();
        }
    }

    /// `None` where there is no `openssl` to run.
    fn tls_site_serving_env() -> Option<TlsSite> {
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "DB_PASSWORD=hunter2\n").unwrap();
        let made = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
            ])
            .args(["-nodes", "-subj", "/CN=a.example", "-days", "1"])
            .args(["-keyout", "key.pem", "-out", "cert.pem"])
            .current_dir(dir.path())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        assert!(made.success(), "openssl could not make a certificate");
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let server = Command::new("openssl")
            .args([
                "s_server",
                "-quiet",
                "-WWW",
                "-accept",
                &format!("127.0.0.1:{port}"),
            ])
            .args([
                "-cert",
                "cert.pem",
                "-key",
                "key.pem",
                "-servername",
                "a.example",
            ])
            .args([
                "-cert2",
                "cert.pem",
                "-key2",
                "key.pem",
                "-servername_fatal",
            ])
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let site = TlsSite {
            server,
            port,
            _dir: dir,
        };
        let started = Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "s_server never listened"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Some(site)
    }

    fn tls_target(site: &str, port: u16) -> Target {
        Target {
            site: site.to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            tls: true,
        }
    }

    /// Over TLS, with a certificate nothing trusts: loopback is checked
    /// for what it serves, not for who it is.
    #[test]
    fn a_tls_site_serving_its_env_file_leaks_it() {
        let Some(server) = tls_site_serving_env() else {
            return;
        };

        let survey = ask(tls_target("a.example", server.port));

        let leaked: Vec<&str> = survey.leaks.iter().map(|l| l.url.as_str()).collect();
        assert_eq!(
            leaked,
            [format!("https://a.example:{}/.env", server.port)],
            "survey was: {survey:?}"
        );
    }

    /// The handshake carries the site's name. The server refuses any name
    /// but `a.example`, so `b.example` getting no answer is the name being
    /// sent; without SNI the server would have answered it too.
    #[test]
    fn the_tls_handshake_names_the_site() {
        let Some(server) = tls_site_serving_env() else {
            return;
        };

        let survey = ask(tls_target("b.example", server.port));

        assert!(
            survey.answered == 0 && survey.leaks.is_empty(),
            "survey was: {survey:?}"
        );
    }

    /// If any list the web server is given refused [`USER_AGENT`], every
    /// site would read as refusing every path.
    #[test]
    fn no_built_in_list_refuses_the_agent_the_check_sends() {
        let db = crate::db::Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        let refusing: Vec<String> = db
            .list_bots()
            .unwrap()
            .iter()
            .filter_map(|bot| crate::dynamic::matched_alternative(USER_AGENT, bot))
            .collect();

        assert!(refusing.is_empty(), "matched by {refusing:?}");
        assert!(
            !crate::botlist::old_browsers::matches(USER_AGENT),
            "the old-browsers list refuses it"
        );
    }

    fn listens(name: &str, listens: &[(Option<&str>, u16, bool)]) -> SiteListens {
        SiteListens {
            server_name: name.to_string(),
            listens: listens
                .iter()
                .map(|&(address, port, tls)| Listen {
                    address: address.map(|a| a.parse().unwrap()),
                    port,
                    tls,
                })
                .collect(),
        }
    }

    #[test]
    fn each_listen_is_asked_at_the_loopback_address_that_reaches_it() {
        let cases = [
            (
                "no listen is port 80",
                listens("a.example", &[]),
                Some(("127.0.0.1", 80)),
            ),
            (
                "every address is IPv4 loopback",
                listens("a.example", &[(None, 443, true)]),
                Some(("127.0.0.1", 443)),
            ),
            (
                "IPv6 only is ::1",
                listens("a.example", &[(Some("::"), 8443, true)]),
                Some(("::1", 8443)),
            ),
            (
                "IPv4 wins over IPv6 on the same port",
                listens("a.example", &[(Some("::"), 80, false), (None, 80, false)]),
                Some(("127.0.0.1", 80)),
            ),
            (
                "a public address is not asked",
                listens("a.example", &[(Some("203.0.113.5"), 80, false)]),
                None,
            ),
            ("the catch-all name is not asked", listens("_", &[]), None),
            ("a regex name is not asked", listens("~^www\\.", &[]), None),
            (
                "an address name is not asked",
                listens("203.0.113.5", &[]),
                None,
            ),
        ];
        for (what, site, expected) in cases {
            let got: Vec<(String, u16)> = targets(&[site])
                .into_iter()
                .map(|t| (t.ip.to_string(), t.port))
                .collect();
            let expected: Vec<(String, u16)> = expected
                .map(|(ip, port)| (ip.to_string(), port))
                .into_iter()
                .collect();
            assert_eq!(got, expected, "{what}");
        }
    }

    #[test]
    fn each_signature_knows_its_file_from_a_page() {
        let page = b"<!doctype html><title>Home</title>".as_slice();
        let cases: [(&str, &[u8]); 9] = [
            ("/.env", b"APP_KEY=base64:abc\nexport DB_HOST=db\n"),
            ("/.git/config", b"[core]\n\trepositoryformatversion = 0\n"),
            ("/.git/HEAD", b"ref: refs/heads/main\n"),
            ("/.svn/entries", b"12\n"),
            (
                "/.aws/credentials",
                b"[default]\naws_access_key_id = AKIA\n",
            ),
            ("/id_rsa", b"-----BEGIN OPENSSH PRIVATE KEY-----\n"),
            ("/.htpasswd", b"admin:$apr1$x$y\n"),
            (
                "/dump.sql",
                b"-- MySQL dump 10.13\nCREATE TABLE `users` (\n",
            ),
            ("/.DS_Store", b"\0\0\0\x01Bud1\0\0"),
        ];
        for (path, file) in cases {
            let sensitive = PATHS.iter().find(|s| s.path == path).unwrap();
            assert!((sensitive.looks_like)(file), "{path} did not know its file");
            assert!(
                !(sensitive.looks_like)(page),
                "{path} took a page for its file"
            );
        }
    }
}
