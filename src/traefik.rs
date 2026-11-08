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

//! The Traefik backend: finds the sites a file provider's routers serve,
//! and writes one file of its own beside them that turns bots away.
//!
//! Everything around that — the policy, the transaction an apply runs in,
//! the generated files' lifecycle — is [`crate::webserver`]'s, shared with
//! [`crate::nginx`] and [`crate::apache`]. This module only speaks
//! Traefik, version 3.
//!
//! ## Nothing of the operator's is edited
//!
//! NGINX and Apache are told what to block inside each site's own config.
//! Traefik is told with routers of its own, in `stop-bots.yml` in the
//! directory its file provider reads (the config root here), and no file
//! of the operator's is ever written. Traefik reloads that directory by
//! itself, so there is no config test and no reload to run.
//!
//! ```yaml
//! http:
//!   routers:
//!     stop-bots:
//!       rule: 'HeaderRegexp(`User-Agent`, `(?i)(?:BadBot|EvilBot)`) && !PathRegexp(`(?i)^(/api/)`)'
//!       priority: 2147482647
//!       service: stop-bots-refused
//!       middlewares:
//!         - stop-bots-refuse
//!     stop-bots-tls:
//!       # the same, with `tls: {}`
//! ```
//!
//! **A router is how a request is decided.** Traefik has no middleware
//! that turns a request away by its user agent, so the rule does the
//! deciding: a router whose rule matches only what is to be blocked, at
//! the highest priority Traefik lets a router have, wins over every router
//! of the sites' own. Its middleware is an `ipAllowList` that allows an
//! address no client has, which answers `403`, and its service is never
//! reached. Each router has a twin with `tls: {}`, because a router
//! without one never sees a request that arrived over TLS. Traefik's own
//! routers sit above that priority, so an ACME challenge and an
//! entrypoint's redirect to HTTPS still come first.
//!
//! **Why not a middleware on every entrypoint.** Traefik can apply one to
//! every router on an entrypoint, which reads simpler. But every router of
//! every site would then name a middleware in this file, and a file
//! Traefik could not load would take every site down with it. A router
//! that is missing only stops blocking.
//!
//! **Which router a site gets.** One pair, `stop-bots` and
//! `stop-bots-tls`, for every host with the host-wide settings: the sites
//! found here, and the ones Traefik learns from Docker labels, which no
//! file under the root names. A site whose own settings block something
//! else gets a pair of its own, with its names in the rule, and the
//! host-wide pair leaves its names out.
//!
//! ## What Traefik cannot do that NGINX can
//!
//! - **Any response but `403`.** The allow list answers `403`, and only
//!   Traefik's internal services answer anything else — which Traefik does
//!   not log, and a refusal the detectors cannot read is worse than a
//!   different status code.
//! - **Serving the generated `robots.txt`.** Traefik serves no files. The
//!   front-ends do not offer it on a Traefik host.
//! - **Rate limiting.** Traefik's `rateLimit` is a middleware, which only
//!   the sites' own routers could carry.
//! - **The HTTP/1.x and old-TLS rules.** No rule can match on either
//!   version, so an apply refuses a site with one switched on. The
//!   bare-address rule needs no router: see [`condition`].
//!
//! ## Its log
//!
//! Traefik logs neither the user agent nor the referer until it is told to
//! keep them (`accessLog.fields.headers.names.User-Agent: keep`), in either
//! of its formats; `stop-bots status` says so when the log has none. Its
//! common format is NGINX's `combined` with three fields after the user
//! agent, and its JSON format has keys of its own, both of which
//! [`crate::accesslog`] reads.

use crate::webserver::*;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

/// Where Traefik's file provider reads from, as the Traefik docs set one
/// up (`providers.file.directory`). Traefik has no stock location: a host
/// whose directory is elsewhere stores it with `set-web-server traefik
/// --root`.
pub const DEFAULT_ROOT: &str = "/etc/traefik/dynamic";

/// Where its access log goes, once it is told to write one to a file. It
/// writes to standard output otherwise, which nothing here can read.
pub const DEFAULT_ACCESS_LOG: &str = "/var/log/traefik/access.log";

/// The file this module writes, in the config root.
pub const ROUTERS_FILE: &str = "stop-bots.yml";

/// The routers' priority: the highest a router may have on a 32-bit
/// Traefik, `MaxInt32 - 1000`. Above it are Traefik's own internal
/// routers, which is where an ACME challenge and an entrypoint redirect
/// are answered. A 64-bit Traefik allows more, and a site's router would
/// have to be given more on purpose to be asked first.
const PRIORITY: u32 = 2_147_482_647;

/// The host-wide pair of routers, and the prefix of every other name this
/// module gives Traefik.
const CATCH_ALL: &str = "stop-bots";

/// The middleware that answers `403`.
const REFUSE: &str = "stop-bots-refuse";

/// The service a refused request is routed to, which it never reaches.
/// One of the file's own rather than Traefik's `noop@internal`: Traefik
/// leaves a request routed to an internal service out of the access log.
const REFUSED: &str = "stop-bots-refused";

/// The routers file under `root`.
pub fn routers_path(root: &Path) -> PathBuf {
    root.join(ROUTERS_FILE)
}

/// What to do when the config root is not there.
fn missing_root_hint() -> &'static str {
    "Traefik's routers come from the directory its file provider reads \
     (`providers.file.directory`). Store where that is with \
     `stop-bots set-web-server traefik --root <dir>`, or pass `--root <dir>` for one run."
}

// ---- finding sites ----

/// Whether `path` is a file of dynamic config this module reads sites
/// from: YAML or TOML, which is all the file provider reads, and not its
/// own.
fn is_config_file(path: &Path) -> bool {
    let named = |ext: &str| {
        path.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(ext))
    };
    (named("yml") || named("yaml") || named("toml"))
        && path.file_name().is_none_or(|name| name != ROUTERS_FILE)
}

/// The host names every `Host(...)` in `line` names, in order, lowercased.
///
/// Read from the text rather than a parsed document, because the same rule
/// is written the same way in a YAML file, a TOML file and a Docker label:
/// `Host(`a.example`)`, or `Host("a.example")` inside a Go string, or
/// Traefik 2's `Host(`a`, `b`)`. `HostRegexp` and `HostSNI` name no host,
/// and a name that is not one (a typo, a template) is skipped.
pub(crate) fn host_names(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("Host(") {
        let preceded = rest[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        rest = &rest[at + "Host(".len()..];
        if preceded {
            continue;
        }
        let mut args = rest;
        loop {
            args = args.trim_start();
            let (open, close) = if args.starts_with('`') {
                ("`", "`")
            } else if args.starts_with("\\\"") {
                ("\\\"", "\\\"")
            } else if args.starts_with('"') {
                ("\"", "\"")
            } else {
                break;
            };
            let body = &args[open.len()..];
            let Some(end) = body.find(close) else {
                break;
            };
            let name = body[..end]
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if is_host_name(&name) && !names.contains(&name) {
                names.push(name);
            }
            args = body[end + close.len()..].trim_start();
            match args.strip_prefix(',') {
                Some(more) => args = more,
                None => break,
            }
        }
    }
    names
}

/// Whether `name` can be a site's name: letters, digits, `-` and `.`,
/// starting with neither punctuation mark.
fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The names of each router `content` declares, one entry per line that
/// names a host: a router's rule is one line in every format Traefik
/// reads. Comment lines name nothing.
fn routers_in(content: &str) -> Vec<Vec<String>> {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(host_names)
        .filter(|names| !names.is_empty())
        .collect()
}

/// Walks `root` for routers that name a host, returning one
/// [`DiscoveredSite`] per router, named after the first host it names. The
/// same walk, and the same refusal of a root that does not exist, as
/// `nginx::discover_sites`: [`crate::webserver::config_files`].
///
/// A site Traefik learns from a Docker label is found only if the file
/// with the label (a `compose.yml`) is under the root. One that is not is
/// still protected, by the host-wide routers; it has no settings of its
/// own.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    if !root.exists() {
        return Err(crate::hint::with(
            anyhow::anyhow!("{} does not exist", root.display()),
            missing_root_hint(),
        ));
    }
    let mut sites = Vec::new();
    for entry in crate::webserver::config_files(root) {
        let path = entry.path();
        if !is_config_file(path) {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for names in routers_in(&content) {
            sites.push(DiscoveredSite {
                server_name: names[0].clone(),
                config_path: path.to_path_buf(),
            });
        }
    }
    Ok(sites)
}

/// Every site under `root`, served on port 80 and on 443 over TLS: where
/// Traefik's entrypoints are is in its static config, which is not under
/// the root, and those two are where nearly every one is.
pub fn site_listens(root: &Path) -> Result<Vec<SiteListens>> {
    let listens = vec![
        Listen {
            address: None,
            port: 80,
            tls: false,
        },
        Listen {
            address: None,
            port: 443,
            tls: true,
        },
    ];
    Ok(discover_sites(root)?
        .into_iter()
        .map(|site| SiteListens {
            server_name: site.server_name,
            listens: listens.clone(),
        })
        .collect())
}

/// The access logs the config under `root` names: none. Traefik names its
/// one log in its static config, which is not under the root, so the
/// stored or the default log is read (see [`crate::logpaths`]).
pub fn access_logs(_root: &Path) -> Vec<PathBuf> {
    Vec::new()
}

/// Every name the routers in `config_path` that name `server_name` answer
/// to, `server_name` first; just `server_name` when the file says
/// otherwise.
pub fn server_names_for(config_path: &Path, server_name: &str) -> Vec<String> {
    let mut names = vec![server_name.to_string()];
    let Ok(content) = fs::read_to_string(config_path) else {
        return names;
    };
    for router in routers_in(&content) {
        if router.iter().any(|name| name == server_name) {
            for name in router {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// The directives [`crate::webapps`] reads a site from: none that name a
/// document root or an application. What a router hands requests on to is
/// a service, and nothing about a service says which application answers
/// there, so every site is in doubt — which is what keeps a WordPress
/// behind Traefik from having its login page counted as a probe.
pub fn site_directives(
    config_path: &Path,
    server_name: &str,
) -> Option<Vec<(String, Vec<String>)>> {
    let content = fs::read_to_string(config_path).ok()?;
    routers_in(&content)
        .iter()
        .any(|router| router.iter().any(|name| name == server_name))
        .then(Vec::new)
}

/// The application behind a site, which a Traefik config does not say.
pub fn site_service(_config_path: &Path, _server_name: &str) -> Option<crate::services::Service> {
    None
}

/// Where the web console's Web Access put its own site, in a release that
/// had one: never on Traefik, which no such release supported. A file
/// nobody writes, so `uninstall` never finds one.
pub fn console_site_path(root: &Path) -> PathBuf {
    root.join("zz-stop-bots-console.yml")
}

// ---- writing the routers ----

/// `pattern`, a PCRE pattern as the bot lists publish them, as a Go
/// regular expression that matches the same user agents — or `None` when
/// this cannot be sure it does.
///
/// Only patterns [`crate::uaregex`] reads are written: literals, classes,
/// groups, alternation and the plain quantifiers, which Go reads as PCRE
/// does with three exceptions this takes care of. Go refuses an escaped
/// character outside ASCII (`\é`), which is the character itself; it
/// refuses a repeat count over 1000; and a backtick would end the rule's
/// argument, so it is written `\x60`. A pattern Go refused would not lose
/// one entry: Traefik switches off the whole router that holds it.
fn go_regex(pattern: &str) -> Option<String> {
    crate::uaregex::UaPattern::compile(pattern)?;
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next()? {
                '`' => out.push_str(r"\x60"),
                c if !c.is_ascii() => out.push(c),
                c => {
                    out.push('\\');
                    out.push(c);
                }
            },
            '`' => out.push_str(r"\x60"),
            '{' => {
                out.push('{');
                let mut count = String::new();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    out.push(next);
                    if next == '}' {
                        break;
                    }
                    count.push(next);
                }
                let too_many = count
                    .split(',')
                    .any(|n| n.parse::<u32>().is_ok_and(|n| n > 1000));
                if too_many {
                    return None;
                }
            }
            c => out.push(c),
        }
    }
    Some(out)
}

/// `text`, a regex this module built from validated, escaped input, with
/// any backtick written so it cannot end the rule's argument.
fn regex_arg(text: &str) -> String {
    text.replace('`', r"\x60")
}

/// The patterns to write, as Go regexes: those `nginx` already finds
/// usable, less any [`go_regex`] cannot carry over.
fn usable_patterns(patterns: &[String]) -> Vec<String> {
    crate::nginx::usable_patterns(patterns)
        .into_iter()
        .filter_map(go_regex)
        .collect()
}

/// Every bot-list pattern the routers leave out that an NGINX block would
/// carry, for the status report: [`go_regex`]'s refusals, which
/// `nginx::skipped_entries` does not count.
pub fn skipped_entries(db: &crate::db::Db) -> Result<Vec<String>> {
    let left_out = db
        .list_bots()?
        .iter()
        .filter(|bot| crate::nginx::is_usable_pattern(&bot.user_agent_pattern))
        .filter(|bot| go_regex(&bot.user_agent_pattern).is_none())
        .count();
    Ok(if left_out > 0 {
        vec![format!(
            "{left_out} bot-list pattern(s) Traefik's regular expressions cannot be sure to \
             read the same way"
        )]
    } else {
        Vec::new()
    })
}

/// A match of `header` against `regex`.
fn header_matches(header: &str, regex: &str) -> String {
    format!("HeaderRegexp(`{header}`, `{}`)", regex_arg(regex))
}

/// A request rule's condition, or `None` for one with nothing to add: one
/// Traefik cannot express (see [`unsupported`]), or one already in force.
///
/// A header that is missing or empty fails `HeaderRegexp(.., `.`)`, which
/// is the "absent or empty" NGINX's `= ""` tests.
///
/// **A bare address as the host is turned away already.** A site's router
/// asks for the site's names, so a request for `203.0.113.5` never reaches
/// it, and Traefik answers it with a 404 of its own. NGINX needs the rule
/// because its default `server` block takes such a request in.
fn condition(rule: RequestRule) -> Option<String> {
    let absent = |header: &str| format!("!{}", header_matches(header, "."));
    match rule {
        RequestRule::Http1x | RequestRule::OldTls | RequestRule::IpLiteralHost => None,
        RequestRule::NoAccept => Some(absent("Accept")),
        RequestRule::NoAcceptLanguage => Some(absent("Accept-Language")),
        RequestRule::NoUserAgent => Some(absent("User-Agent")),
        // Go's `regexp` reads every shape as PCRE does; `(?i)` ignores
        // case, as NGINX's `~*` does.
        RequestRule::ImpossibleUserAgent => Some(header_matches(
            "User-Agent",
            &format!("(?i){}", crate::impossible_ua::pattern()),
        )),
    }
}

/// Whether `rule` is one Traefik cannot express: it has no rule that
/// matches on the HTTP version or the TLS version.
pub fn unsupported(rule: RequestRule) -> bool {
    matches!(rule, RequestRule::Http1x | RequestRule::OldTls)
}

/// Why `config` cannot be written for the site `name`, if it cannot.
fn refusal(name: &str, config: &BlockConfig) -> Option<String> {
    let rule = config.request_rules.iter().find(|r| unsupported(**r))?;
    Some(format!(
        "the {} rule is on for {name}, and Traefik has no rule that can tell what it asks \
         about, so it would block nothing. Switch it off for the site.",
        rule.label()
    ))
}

/// What applying `site_configs` to the routers in `content` makes of it:
/// the same text, because no file of the operator's is written (see the
/// module docs). Refuses a site with a rule Traefik cannot express, as the
/// routers file would.
pub fn blocks_for_file(content: &str, site_configs: &[(String, BlockConfig)]) -> Result<String> {
    for (name, config) in site_configs {
        if let Some(why) = refusal(name, config) {
            anyhow::bail!("refusing to apply {name}: {why}");
        }
    }
    Ok(content.to_string())
}

/// [`blocks_for_file`], for one site.
pub fn block_for_site(content: &str, server_name: &str, config: &BlockConfig) -> Result<String> {
    blocks_for_file(content, &[(server_name.to_string(), config.clone())])
}

/// `config` as Traefik can carry it: no `robots.txt` and no rate limit,
/// which it has no way to serve or apply (see the module docs).
fn for_traefik(config: &BlockConfig) -> BlockConfig {
    BlockConfig {
        serve_robots_txt: false,
        rate_limit_burst: None,
        ..config.clone()
    }
}

/// The part of a rule that decides a request is to be turned away under
/// `config`, or `None` when it turns nothing away: any reason to block,
/// and then every exemption and every trusted client as a condition the
/// request must not meet — the flag idiom of the NGINX and Apache blocks,
/// as one expression.
fn block_expression(config: &BlockConfig) -> Option<String> {
    let config = for_traefik(config);
    let patterns = usable_patterns(&config.patterns);
    let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let mut reasons: Vec<String> =
        crate::nginx::chunk_patterns(&patterns, crate::nginx::MAX_PATTERN_CHUNK_LEN)
            .iter()
            .map(|chunk| header_matches("User-Agent", &format!("(?i)(?:{chunk})")))
            .collect();
    reasons.extend(config.request_rules.iter().filter_map(|r| condition(*r)));
    let mut out = match reasons.as_slice() {
        [] => return None,
        [only] => only.clone(),
        all => format!("({})", all.join(" || ")),
    };
    let (prefixes, exact) = effective_exempt_paths(&config);
    for paths in crate::nginx::exemption_regexes(&prefixes, exact) {
        out.push_str(&format!(" && !PathRegexp(`(?i){}`)", regex_arg(&paths)));
    }
    for group in config
        .agent_exemptions
        .chunk_by(|a, b| a.user_agent == b.user_agent)
    {
        let user_agent = &group[0].user_agent;
        if !is_stored_as_valid(user_agent, crate::db::validate_exemption_user_agent) {
            continue;
        }
        let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
        for regex in crate::nginx::exemption_regexes(&paths, &[]) {
            out.push_str(&format!(
                " && !({} && PathRegexp(`(?i){}`))",
                header_matches(
                    "User-Agent",
                    &format!("(?i){}", crate::db::escape_regex_literal(user_agent))
                ),
                regex_arg(&regex)
            ));
        }
    }
    if let Some(trust) = &config.trust {
        for address in &trust.addresses {
            out.push_str(&format!(" && !ClientIP(`{address}`)"));
        }
        if !trust.user_agents.is_empty() {
            let escaped: Vec<String> = trust
                .user_agents
                .iter()
                .map(|ua| crate::db::escape_regex_literal(ua))
                .collect();
            out.push_str(&format!(
                " && !{}",
                header_matches("User-Agent", &format!("(?i)(?:{})", escaped.join("|")))
            ));
        }
    }
    Some(out)
}

/// A request for any of `names`.
fn hosts_expression(names: &[String]) -> String {
    let each: Vec<String> = names.iter().map(|n| format!("Host(`{n}`)")).collect();
    match each.as_slice() {
        [only] => only.clone(),
        all => format!("({})", all.join(" || ")),
    }
}

/// The name of a site's own pair of routers: readable, and unique however
/// alike two sites' names are.
fn router_name(site: &str) -> String {
    use sha2::{Digest, Sha256};
    let slug: String = site
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let hash = Sha256::digest(site.as_bytes());
    format!(
        "{CATCH_ALL}-{slug}-{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

/// `text` as a YAML single-quoted scalar, in which a quote is two.
fn yaml_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The pair of routers named `name` that refuse what `rule` matches: one
/// for plain HTTP, and its twin for TLS.
fn router_pair(name: &str, rule: &str) -> String {
    let router = |name: &str, tls: &str| {
        format!(
            "    {name}:\n      rule: {}\n      priority: {PRIORITY}\n      service: {REFUSED}\n      middlewares:\n        - {REFUSE}\n{tls}",
            yaml_quoted(rule)
        )
    };
    format!(
        "{}{}",
        router(name, ""),
        router(&format!("{name}-tls"), "      tls: {}\n")
    )
}

/// The rule of the router named `name` in `content`, as written there.
fn rule_of(content: &str, name: &str) -> Option<String> {
    let mut lines = content.lines();
    lines.find(|line| *line == format!("    {name}:"))?;
    let quoted = lines
        .next()?
        .strip_prefix("      rule: '")?
        .strip_suffix('\'')?;
    Some(quoted.replace("''", "'"))
}

/// The host-wide rule `rule`, as [`routers_body`] wrote it: the names it
/// leaves out, and the expression that blocks the rest.
fn host_wide_parts(rule: &str) -> (Vec<String>, &str) {
    let mut excluded = Vec::new();
    let mut rest = rule;
    while let Some((name, after)) = rest
        .strip_prefix("!Host(`")
        .and_then(|more| more.split_once("`) && "))
    {
        excluded.push(name.to_string());
        rest = after;
    }
    (excluded, rest)
}

/// One site, as the routers file is built from it: every name it answers
/// to, and its settings.
pub struct Site {
    pub names: Vec<String>,
    pub config: BlockConfig,
}

/// The routers file for `sites` and the host-wide `default`, or `None`
/// when nothing is to be blocked anywhere. Refuses a site, or the host-wide
/// settings, with a rule Traefik cannot express ([`refusal`]).
///
/// A site whose settings block exactly what the host-wide ones do is left
/// to the host-wide pair, which is most sites on most hosts: each pair
/// carries the whole list of bot patterns, and one pair per site would
/// multiply that by every site for nothing.
pub fn routers_body(sites: &[Site], default: &BlockConfig) -> Result<Option<String>> {
    for site in sites {
        if let Some(why) = refusal(&site.names[0], &site.config) {
            anyhow::bail!("refusing to write the Traefik routers: {why}");
        }
    }
    let host_wide = block_expression(default);
    let mut own: Vec<&Site> = sites
        .iter()
        .filter(|site| block_expression(&site.config) != host_wide)
        .collect();
    own.sort_by(|a, b| a.names[0].cmp(&b.names[0]));
    let mut routers = String::new();
    if let Some(expression) = &host_wide {
        let mut excluded: Vec<&String> = own.iter().flat_map(|site| &site.names).collect();
        excluded.sort();
        excluded.dedup();
        let rule: String = excluded
            .iter()
            .map(|name| format!("!Host(`{name}`) && "))
            .chain(std::iter::once(expression.clone()))
            .collect();
        routers.push_str(&router_pair(CATCH_ALL, &rule));
    }
    for site in own {
        if let Some(expression) = block_expression(&site.config) {
            let rule = format!("{} && {expression}", hosts_expression(&site.names));
            routers.push_str(&router_pair(&router_name(&site.names[0]), &rule));
        }
    }
    if routers.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!(
        "{}#\n\
         # Read by Traefik's file provider, which reloads it on its own. Each\n\
         # router turns away what its rule matches, with a 403, before any\n\
         # router of the sites' own is asked. To stop it: `stop-bots uninstall\n\
         # web-server`.\n\
         http:\n  routers:\n{routers}\
         \x20 middlewares:\n    {REFUSE}:\n      ipAllowList:\n        sourceRange:\n          - 255.255.255.255/32\n\
         \x20 services:\n    {REFUSED}:\n      loadBalancer:\n        servers:\n          - url: http://127.0.0.1:9\n",
        managed_header()
    )))
}

/// Every site scanned into `db` that is still found under `root`, with
/// its names and settings.
fn sites_of(db: &crate::db::Db, root: &Path) -> Result<Vec<Site>> {
    let discovered = discover_sites(root)?;
    let mut sites = Vec::new();
    for site in db.list_sites()? {
        let path = Path::new(&site.config_path);
        let found = discovered
            .iter()
            .any(|d| d.server_name == site.server_name && d.config_path == path);
        if found {
            sites.push(Site {
                names: server_names_for(path, &site.server_name),
                config: block_config_for_site(db, site.id)?,
            });
        }
    }
    Ok(sites)
}

/// The generated files the current settings call for: the routers file,
/// when anything is to be blocked.
pub fn planned_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let sites = sites_of(db, root)?;
    let body = routers_body(&sites, &default_block_config(db)?)?;
    Ok(body
        .map(|body| (routers_path(root), body))
        .into_iter()
        .collect())
}

/// Where each generated file the current settings do not call for would
/// be: the routers file, when nothing is to be blocked.
pub fn fallback_unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<PathBuf>> {
    let planned = planned_managed_files(db, root)?;
    Ok(if planned.is_empty() {
        vec![routers_path(root)]
    } else {
        Vec::new()
    })
}

/// The directories a recorded generated file may be removed from.
pub fn managed_directories(root: &Path) -> Vec<PathBuf> {
    fs::canonicalize(root).into_iter().collect()
}

/// Whether the routers file under `root` blocks for `server_name` (and the
/// rest of the names its routers in `config_path` answer to) what `config`
/// asks.
///
/// Either placement is up to date, because which one a site gets depends
/// on the host-wide settings, which this is not given: a pair of its own
/// with exactly the rule `config` renders to, or none of its own and the
/// host-wide pair blocking exactly what `config` does without leaving the
/// site out. A site with nothing to block is up to date when no router
/// blocks anything for it.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
    root: &Path,
) -> SiteApplyStatus {
    let Ok(site_file) = fs::read_to_string(config_path) else {
        return SiteApplyStatus::NotFound;
    };
    if !routers_in(&site_file)
        .iter()
        .any(|router| router.first().is_some_and(|name| name == server_name))
    {
        return SiteApplyStatus::NotFound;
    }
    if refusal(server_name, config).is_some() {
        return SiteApplyStatus::Stale;
    }
    let names = server_names_for(config_path, server_name);
    let content = fs::read_to_string(routers_path(root)).unwrap_or_default();
    let own_name = router_name(server_name);
    let expression = block_expression(config);
    let current = match rule_of(&content, &own_name) {
        Some(rule) => expression.is_some_and(|expression| {
            rule == format!("{} && {expression}", hosts_expression(&names))
                && content.contains(&router_pair(&own_name, &rule))
        }),
        None => match rule_of(&content, CATCH_ALL) {
            None => expression.is_none(),
            Some(rule) => {
                let (excluded, blocks) = host_wide_parts(&rule);
                content.contains(&router_pair(CATCH_ALL, &rule))
                    && match &expression {
                        None => names.iter().all(|name| excluded.contains(name)),
                        Some(expression) => {
                            blocks == expression
                                && !names.iter().any(|name| excluded.contains(name))
                        }
                    }
            }
        },
    };
    if current {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AgentExemption, BlockResponse};

    fn cfg(patterns: &[&str]) -> BlockConfig {
        BlockConfig::new(
            patterns.iter().map(|p| p.to_string()).collect(),
            BlockResponse::Forbidden,
        )
    }

    fn site(names: &[&str], config: BlockConfig) -> Site {
        Site {
            names: names.iter().map(|n| n.to_string()).collect(),
            config,
        }
    }

    /// A root holding one dynamic config file, `sites.yml`, with `text`.
    fn root_with(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sites.yml");
        fs::write(&path, text).unwrap();
        (dir, path)
    }

    const TWO_SITES: &str = "\
http:
  routers:
    a:
      rule: \"Host(`a.example`)\"
      service: app
    b:
      rule: \"Host(`b.example`) || Host(`www.b.example`)\"
      service: app
";

    #[test]
    fn host_names_are_read_however_the_rule_is_written() {
        let cases = [
            (
                "YAML",
                "      rule: \"Host(`a.example`)\"",
                vec!["a.example"],
            ),
            (
                "an alternative",
                "rule: Host(`a.example`) || Host(`www.a.example`)",
                vec!["a.example", "www.a.example"],
            ),
            ("TOML", "rule = \"Host(`a.example`)\"", vec!["a.example"]),
            (
                "a Docker label",
                "- \"traefik.http.routers.a.rule=Host(`A.Example`)\"",
                vec!["a.example"],
            ),
            (
                "a Go string in YAML",
                r#"rule: "Host(\"a.example\")""#,
                vec!["a.example"],
            ),
            (
                "Traefik 2's list",
                "rule: Host(`a.example`, `b.example`)",
                vec!["a.example", "b.example"],
            ),
            (
                "HostRegexp and HostSNI",
                "rule: HostRegexp(`.+`) || HostSNI(`a.example`)",
                vec![],
            ),
            ("a template", "rule: Host(`{{ .Name }}`)", vec![]),
            (
                "a fully qualified name",
                "rule: Host(`a.example.`)",
                vec!["a.example"],
            ),
        ];
        for (what, line, expected) in cases {
            assert_eq!(host_names(line), expected, "{what}: {line}");
        }
    }

    #[test]
    fn every_router_naming_a_host_is_a_site_named_after_its_first_host() {
        let (dir, path) = root_with(TWO_SITES);
        let sites = discover_sites(dir.path()).unwrap();
        let names: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
        assert_eq!(names, ["a.example", "b.example"], "sites were: {sites:?}");
        assert!(sites.iter().all(|s| s.config_path == path), "{sites:?}");
    }

    #[test]
    fn comments_backups_other_files_and_its_own_file_name_no_site() {
        let (dir, _) = root_with("# rule: Host(`commented.example`)\n");
        for name in ["sites.yml.bak", "notes.txt", ROUTERS_FILE] {
            fs::write(dir.path().join(name), "rule: Host(`x.example`)\n").unwrap();
        }
        let sites = discover_sites(dir.path()).unwrap();
        assert!(sites.is_empty(), "found: {sites:?}");
    }

    #[test]
    fn a_missing_root_is_an_error_that_says_where_to_set_it() {
        let err = discover_sites(Path::new("/nonexistent/traefik")).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("set-web-server traefik --root"), "{text}");
    }

    #[test]
    fn a_site_answers_to_every_name_its_routers_give_it() {
        let (_dir, path) = root_with(TWO_SITES);
        assert_eq!(
            server_names_for(&path, "b.example"),
            ["b.example", "www.b.example"]
        );
        assert_eq!(server_names_for(&path, "gone.example"), ["gone.example"]);
    }

    #[test]
    fn a_pattern_becomes_a_go_regex_that_matches_the_same_agents() {
        let cases = [
            ("plain", "BadBot", Some("BadBot")),
            ("escapes Go reads", r"Bad\ Bot\/\d", Some(r"Bad\ Bot\/\d")),
            ("an escaped letter outside ASCII", r"caf\é", Some("café")),
            ("a backtick", "x`y", Some(r"x\x60y")),
            ("an escaped backtick", r"x\`y", Some(r"x\x60y")),
            ("a repeat Go allows", "a{2,1000}", Some("a{2,1000}")),
            ("a repeat Go refuses", "a{1,1001}", None),
            ("a lookahead", "a(?=b)", None),
        ];
        for (what, pattern, expected) in cases {
            assert_eq!(go_regex(pattern).as_deref(), expected, "{what}: {pattern}");
        }
    }

    #[test]
    fn the_host_wide_routers_block_the_patterns_for_every_host() {
        let body = routers_body(&[], &cfg(&["BadBot", "EvilBot"]))
            .unwrap()
            .unwrap();
        crate::golden::assert_golden("traefik-host-wide.yml", &body);
    }

    #[test]
    fn nothing_to_block_anywhere_is_no_file() {
        let sites = [site(&["a.example"], cfg(&[]))];
        assert_eq!(routers_body(&sites, &cfg(&[])).unwrap(), None);
    }

    #[test]
    fn a_site_like_the_host_has_no_routers_of_its_own() {
        let sites = [site(&["a.example"], cfg(&["BadBot"]))];
        let body = routers_body(&sites, &cfg(&["BadBot"])).unwrap().unwrap();
        assert_eq!(body.matches("rule:").count(), 2, "body was:\n{body}");
        assert!(!body.contains("Host("), "body was:\n{body}");
    }

    #[test]
    fn a_site_with_settings_of_its_own_gets_routers_and_is_left_out_of_the_host_wide_ones() {
        let mut own = cfg(&["BadBot"]);
        own.exempt_paths = vec!["/api/".to_string()];
        let sites = [
            site(&["b.example", "www.b.example"], own),
            site(&["a.example"], cfg(&["BadBot"])),
        ];
        let body = routers_body(&sites, &cfg(&["BadBot"])).unwrap().unwrap();
        crate::golden::assert_golden("traefik-site-of-its-own.yml", &body);
    }

    #[test]
    fn a_site_that_blocks_nothing_is_only_left_out() {
        let sites = [site(&["a.example"], cfg(&[]))];
        let body = routers_body(&sites, &cfg(&["BadBot"])).unwrap().unwrap();
        let rule = rule_of(&body, CATCH_ALL).unwrap();
        assert!(
            rule.starts_with("!Host(`a.example`) && "),
            "rule was: {rule}"
        );
        assert_eq!(body.matches("rule:").count(), 2, "body was:\n{body}");
    }

    #[test]
    fn each_exemption_and_trusted_client_is_a_condition_the_request_must_not_meet() {
        let mut config = cfg(&["BadBot"]);
        config.exempt_paths = vec!["/feed".to_string()];
        config.agent_exemptions = vec![AgentExemption {
            path: "/remote.php/dav/".to_string(),
            user_agent: "okhttp".to_string(),
        }];
        config.trust = Trust::from_lists(&["192.0.2.0/24".to_string()], &["Uptime".to_string()]);
        let expression = block_expression(&config).unwrap();
        let cases = [
            ("the exempt path", r"!PathRegexp(`(?i)^(/feed)`)"),
            (
                "the agent's exemption",
                r"!(HeaderRegexp(`User-Agent`, `(?i)okhttp`) && PathRegexp(`(?i)^(/remote\.php/dav/)`))",
            ),
            ("the trusted address", "!ClientIP(`192.0.2.0/24`)"),
            (
                "the trusted user agent",
                "!HeaderRegexp(`User-Agent`, `(?i)(?:Uptime)`)",
            ),
        ];
        for (what, condition) in cases {
            assert!(
                expression.contains(condition),
                "{what} is missing from:\n{expression}"
            );
        }
    }

    #[test]
    fn request_rules_traefik_can_express_are_reasons_to_block() {
        let mut config = cfg(&[]);
        config.request_rules = vec![
            RequestRule::NoAccept,
            RequestRule::NoUserAgent,
            RequestRule::IpLiteralHost,
        ];
        let expression = block_expression(&config).unwrap();
        assert!(
            expression.starts_with(
                "(!HeaderRegexp(`Accept`, `.`) || !HeaderRegexp(`User-Agent`, `.`)) && "
            ),
            "{expression}"
        );
        assert!(
            expression.contains(r"!PathRegexp(`(?i)^(/\.well-known/)`)"),
            "ACME's path must stay open once a request rule is on: {expression}"
        );
    }

    /// Traefik answers a request for a bare address with a 404 before any
    /// site's router is asked, so the rule is in force with no router.
    #[test]
    fn the_bare_address_rule_alone_needs_no_router() {
        let mut config = cfg(&[]);
        config.request_rules = vec![RequestRule::IpLiteralHost];
        assert_eq!(block_expression(&config), None);
        assert!(!unsupported(RequestRule::IpLiteralHost));
    }

    #[test]
    fn a_rule_traefik_cannot_express_is_refused_with_the_site_named() {
        for rule in [RequestRule::Http1x, RequestRule::OldTls] {
            let mut config = cfg(&["BadBot"]);
            config.request_rules = vec![rule];
            let err = routers_body(&[site(&["a.example"], config)], &cfg(&["BadBot"])).unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("a.example") && text.contains(rule.label()),
                "{rule:?}: {text}"
            );
        }
    }

    #[test]
    fn robots_txt_rate_limits_and_responses_change_nothing_on_traefik() {
        let mut config = cfg(&["BadBot"]);
        config.serve_robots_txt = true;
        config.rate_limit_burst = Some(20);
        config.response = BlockResponse::Close;
        assert_eq!(
            block_expression(&config),
            block_expression(&cfg(&["BadBot"]))
        );
    }

    #[test]
    fn a_quote_in_a_pattern_survives_yaml() {
        let body = routers_body(&[], &cfg(&["it's"])).unwrap().unwrap();
        assert!(body.contains("`(?i)(?:it''s)`"), "body was:\n{body}");
        let rule = rule_of(&body, CATCH_ALL).unwrap();
        assert!(rule.contains("(?:it's)"), "rule was: {rule}");
    }

    /// A root with [`TWO_SITES`] and the routers file `sites` and
    /// `default` render to.
    fn applied(sites: &[Site], default: &BlockConfig) -> (tempfile::TempDir, PathBuf) {
        let (dir, path) = root_with(TWO_SITES);
        if let Some(body) = routers_body(sites, default).unwrap() {
            fs::write(routers_path(dir.path()), body).unwrap();
        }
        (dir, path)
    }

    #[test]
    fn a_site_the_host_wide_routers_cover_is_up_to_date() {
        let (dir, path) = applied(&[], &cfg(&["BadBot"]));
        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]), dir.path());
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    #[test]
    fn a_site_is_stale_until_the_routers_block_what_it_asks() {
        let cases = [
            ("a pattern added since", cfg(&["BadBot", "NewBot"])),
            ("nothing to block since", cfg(&[])),
        ];
        let (dir, path) = applied(&[], &cfg(&["BadBot"]));
        for (what, config) in cases {
            let status = site_apply_status(&path, "a.example", &config, dir.path());
            assert_eq!(status, SiteApplyStatus::Stale, "{what}");
        }
    }

    #[test]
    fn a_site_with_routers_of_its_own_is_up_to_date_against_them() {
        let mut own = cfg(&["BadBot"]);
        own.exempt_paths = vec!["/api/".to_string()];
        let sites = [site(&["b.example", "www.b.example"], own.clone())];
        let (dir, path) = applied(&sites, &cfg(&["BadBot"]));
        let cases = [
            ("its own settings", own, SiteApplyStatus::UpToDate),
            ("the host's", cfg(&["BadBot"]), SiteApplyStatus::Stale),
        ];
        for (what, config, expected) in cases {
            let status = site_apply_status(&path, "b.example", &config, dir.path());
            assert_eq!(status, expected, "{what}");
        }
    }

    #[test]
    fn a_site_that_blocks_nothing_is_up_to_date_once_left_out() {
        let sites = [site(&["a.example"], cfg(&[]))];
        let (dir, path) = applied(&sites, &cfg(&["BadBot"]));
        let status = site_apply_status(&path, "a.example", &cfg(&[]), dir.path());
        assert_eq!(status, SiteApplyStatus::UpToDate);
        let other = site_apply_status(&path, "b.example", &cfg(&["BadBot"]), dir.path());
        assert_eq!(
            other,
            SiteApplyStatus::UpToDate,
            "b.example is still covered"
        );
    }

    #[test]
    fn a_site_no_router_names_is_not_found() {
        let (dir, path) = applied(&[], &cfg(&["BadBot"]));
        let status = site_apply_status(&path, "gone.example", &cfg(&["BadBot"]), dir.path());
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn an_edited_twin_is_stale() {
        let (dir, path) = applied(&[], &cfg(&["BadBot"]));
        let file = routers_path(dir.path());
        let text = fs::read_to_string(&file)
            .unwrap()
            .replace("      tls: {}\n", "");
        fs::write(&file, text).unwrap();
        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]), dir.path());
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    #[test]
    fn router_names_differ_for_sites_that_slug_alike() {
        assert_ne!(router_name("a-b.example"), router_name("a.b-example"));
        assert!(
            router_name("a.example").starts_with("stop-bots-a-example-"),
            "{}",
            router_name("a.example")
        );
    }
}
