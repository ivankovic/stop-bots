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

//! Outbound traffic to command-and-control servers: the feeds that name
//! them, the firewall rules that watch for and stop connections to them
//! from this host and from its containers, and the kernel log lines those
//! rules write.
//!
//! Everything else in this project faces inward: who may reach the host.
//! This faces the other way. A web application running as `www-data`, a
//! container with a vulnerable dependency, a compromised user account:
//! each of them, once taken over, calls home. That call is the one thing
//! every piece of commodity malware does, and a firewall can see it.
//!
//! ## What it can and cannot do
//!
//! It stops an attacker who has *not* got root: a compromised service
//! account, a user, a container without `NET_ADMIN`. Each of those
//! connects out through this host's kernel, and the kernel drops it. An
//! attacker with root can delete the table (`nft delete table inet
//! stop_bots`); what is left then is that `status` notices the table is
//! gone. That is still worth having: most compromises start well short of
//! root, and the time between the foothold and root is exactly when
//! stopping the call home and containing its source matters
//! ([`crate::contain`]).
//!
//! It only knows the servers its feeds know. A new server, or one hidden
//! behind a service everyone uses, is not stopped.
//!
//! ## Three modes
//!
//! - **Off**, the default everywhere: nothing is rendered.
//! - **Watch**: a new outbound connection to a listed address is logged
//!   with [`LOG_PREFIX`] and let through. To see what would be stopped
//!   before stopping it.
//! - **Block**: logged, and dropped.
//!
//! ## Where the rules go
//!
//! Two paths leave the host. A process on the host sends through the
//! `output` hook, and the log line carries the uid of the socket's owner
//! (`log flags skuid`), which is what says which user made it. A
//! container's traffic is routed through `forward`, from the container's
//! own address. Both are checked by one chain of rules, as the inbound
//! rules are.
//!
//! Only connections this side started are logged: `ct direction
//! original`. A reply to a listed address that connected *in* (a scanner
//! that is also a C&C server) is dropped in Block mode but never reported
//! as a compromise, which it is not.
//!
//! ## What is never blocked
//!
//! A downloaded list deciding where this host may connect is a way to cut
//! it off from its own resolver, its package mirrors or the feeds
//! themselves. So [`guard`] leaves out of every feed, as it is stored:
//!
//! - anything that overlaps a private, loopback, link-local or reserved
//!   range: those are this host's own networks and containers;
//! - a range broader than a /8 (or an IPv6 /16), which no C&C list has a
//!   reason to carry;
//! - any range that holds an address this host depends on: the resolvers
//!   in `resolv.conf`, the apt mirrors, Let's Encrypt and the feeds'
//!   own servers, as they resolve at the time of the fetch.
//!
//! An address the operator trusts (`add-trusted`) is never blocked
//! either, here as everywhere, nor one that logged in over SSH lately
//! ([`Db::recent_ssh_login_ips`]), as inbound: listed, it would lose the
//! replies to its own session. Both are left out when the firewall is
//! rendered, not when a feed is fetched, so a login since counts.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use anyhow::{bail, Context, Result};

use crate::db::egress::{EgressFeed, NewEgressFeed, NewEgressHit};
use crate::db::{keys, Db};

/// What the firewall puts in front of every outbound attempt it logs.
pub const LOG_PREFIX: &str = "stop-bots-egress: ";

/// How many lines a second the egress rules may log, in total: a burst of
/// retries is one hit, and what matters is that one is logged.
pub const LOG_RATE: &str = "10/second";

/// How a host treats outbound connections to listed addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Mode {
    #[default]
    Off,
    Watch,
    Block,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Off, Mode::Watch, Mode::Block];

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Watch => "watch",
            Mode::Block => "block",
        }
    }

    pub fn parse(text: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|mode| mode.as_str() == text)
    }

    /// What the mode does, in a few words.
    pub fn describe(self) -> &'static str {
        match self {
            Mode::Off => "outbound connections are not checked",
            Mode::Watch => "outbound connections to listed addresses are logged, not stopped",
            Mode::Block => "outbound connections to listed addresses are logged and dropped",
        }
    }

    /// The stored mode. Unset, or a value this version does not know,
    /// reads as off: nothing outbound is ever blocked by a guess.
    pub fn get(db: &Db) -> Result<Mode> {
        Ok(db
            .get_text_setting(keys::EGRESS_MODE)?
            .as_deref()
            .and_then(Mode::parse)
            .unwrap_or(Mode::Off))
    }

    pub fn set(self, db: &Db) -> Result<()> {
        db.set_text_setting(keys::EGRESS_MODE, self.as_str())
    }
}

/// What a feed's entries are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Addresses and CIDR ranges, which the firewall matches.
    Ip,
    /// Domains, which only a resolver can stop: see [`crate::sinkhole`].
    Domain,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Ip => "ip",
            EntryKind::Domain => "domain",
        }
    }

    pub fn parse(text: &str) -> Option<EntryKind> {
        match text {
            "ip" => Some(EntryKind::Ip),
            "domain" => Some(EntryKind::Domain),
            _ => None,
        }
    }
}

/// One built-in feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedKind {
    /// abuse.ch's Feodo Tracker: botnet C&C servers (Emotet, QakBot,
    /// Pikabot and their kin), the "recommended" list of those active now.
    Feodo,
    /// C2IntelFeeds: C&C servers of attack frameworks (Cobalt Strike,
    /// Sliver, Mythic, ...) found by internet-wide scans, seen in the last
    /// 30 days.
    C2Intel,
    /// Spamhaus DROP: networks hijacked or leased by criminals, with no
    /// legitimate traffic to send or receive. IPv4 and IPv6.
    SpamhausDrop,
    /// C2IntelFeeds' C&C domains of the last 30 days, with the ones that
    /// are abused shared services left out.
    C2IntelDomains,
}

impl FeedKind {
    pub const ALL: [FeedKind; 4] = [
        FeedKind::Feodo,
        FeedKind::C2Intel,
        FeedKind::SpamhausDrop,
        FeedKind::C2IntelDomains,
    ];

    /// Stable across releases: it is an `egress_feeds` primary key.
    pub fn id(self) -> &'static str {
        match self {
            FeedKind::Feodo => "feodo",
            FeedKind::C2Intel => "c2intel",
            FeedKind::SpamhausDrop => "spamhaus-drop",
            FeedKind::C2IntelDomains => "c2intel-domains",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FeedKind::Feodo => "abuse.ch Feodo Tracker",
            FeedKind::C2Intel => "C2IntelFeeds C&C servers",
            FeedKind::SpamhausDrop => "Spamhaus DROP",
            FeedKind::C2IntelDomains => "C2IntelFeeds C&C domains",
        }
    }

    /// Where it is downloaded from: Spamhaus publishes each family in a
    /// file of its own.
    pub fn urls(self) -> &'static [&'static str] {
        match self {
            FeedKind::Feodo => {
                &["https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"]
            }
            FeedKind::C2Intel => &[
                "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
            ],
            FeedKind::SpamhausDrop => &[
                "https://www.spamhaus.org/drop/drop_v4.json",
                "https://www.spamhaus.org/drop/drop_v6.json",
            ],
            FeedKind::C2IntelDomains => &[
                "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
            ],
        }
    }

    pub fn kind(self) -> EntryKind {
        match self {
            FeedKind::C2IntelDomains => EntryKind::Domain,
            _ => EntryKind::Ip,
        }
    }

    /// Whether a hit on it may contain what made it, until the operator
    /// says otherwise. Only Feodo's: it lists servers that are botnet C&C
    /// now, and nothing else. The scan-derived list names servers that may
    /// have been rented to someone else since, and DROP whole networks.
    pub fn contains_by_default(self) -> bool {
        self == FeedKind::Feodo
    }

    /// What it holds, for `?` and `--help`.
    pub fn about(self) -> &'static str {
        match self {
            FeedKind::Feodo => {
                "Botnet command-and-control servers that are active now, tracked by abuse.ch. \
                 A connection to one is a machine that is already infected."
            }
            FeedKind::C2Intel => {
                "Command-and-control servers of attack frameworks such as Cobalt Strike, found \
                 by scanning the internet and seen in the last 30 days. Cloud addresses change \
                 hands, so an old entry can be someone else's server by now."
            }
            FeedKind::SpamhausDrop => {
                "Networks hijacked or leased by criminals, which no legitimate service uses. \
                 Spamhaus recommends dropping traffic to them as well as from them."
            }
            FeedKind::C2IntelDomains => {
                "Command-and-control domains of the last 30 days, without the shared services \
                 attackers also abuse. Stopped by the resolver, not the firewall: see \
                 `set-egress-dns`."
            }
        }
    }

    pub fn from_id(id: &str) -> Option<FeedKind> {
        FeedKind::ALL.into_iter().find(|kind| kind.id() == id)
    }

    fn as_new(self) -> NewEgressFeed {
        NewEgressFeed {
            id: self.id().to_string(),
            name: self.name().to_string(),
            url: self.urls().join(" "),
            kind: self.kind(),
            builtin: true,
            contain: self.contains_by_default(),
        }
    }
}

/// Registers every built-in feed that is not known yet, leaving the
/// switches of one that is.
pub fn register_builtin_feeds(db: &Db) -> Result<()> {
    db.batch(|| {
        for kind in FeedKind::ALL {
            db.register_egress_feed(&kind.as_new())?;
        }
        Ok(())
    })
}

/// The id a feed added by URL is stored under, from its name.
pub fn custom_feed_id(name: &str) -> Result<String> {
    let slug: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() || slug.len() > 40 {
        bail!("a feed's name needs between one and forty letters or digits");
    }
    Ok(format!("custom-{slug}"))
}

/// Adds a feed by URL: a list of addresses, or of domains, in any of the
/// forms [`parse_addresses`] and [`parse_domains`] read. Off until
/// switched on, like every feed.
pub fn add_custom_feed(
    db: &Db,
    name: &str,
    url: &str,
    kind: EntryKind,
    contain: bool,
) -> Result<String> {
    let id = custom_feed_id(name)?;
    let parsed =
        reqwest::Url::parse(url).with_context(|| format!("not a URL: {}", masked_url(url)))?;
    if parsed.scheme() != "https" {
        bail!(
            "{} is not https: anyone on the path could then choose what this host may connect to",
            masked_url(url)
        );
    }
    if db.get_egress_feed(&id)?.is_some() {
        bail!("there is already a feed called {id}");
    }
    db.register_egress_feed(&NewEgressFeed {
        id: id.clone(),
        name: name.trim().to_string(),
        url: url.to_string(),
        kind,
        builtin: false,
        contain,
    })?;
    Ok(id)
}

/// `url` with everything after its host replaced: abuse.ch's exports carry
/// the account's key in the path, and a URL is shown in lists, logs and
/// the job summaries the database keeps.
pub fn masked_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(parsed) => match parsed.host_str() {
            Some(host) if parsed.path() == "/" && parsed.query().is_none() => {
                format!("{}://{host}/", parsed.scheme())
            }
            Some(host) => format!("{}://{host}/\u{2026}", parsed.scheme()),
            None => "(a URL)".to_string(),
        },
        Err(_) => "(not a URL)".to_string(),
    }
}

/// The URLs a stored feed is fetched from.
pub fn feed_urls(feed: &EgressFeed) -> Vec<String> {
    match FeedKind::from_id(&feed.id).filter(|_| feed.builtin) {
        Some(kind) => kind.urls().iter().map(|u| u.to_string()).collect(),
        None => vec![feed.url.clone()],
    }
}

/// Downloads `feed`, every URL it has, as one text.
pub async fn fetch(feed: &EgressFeed) -> Result<String> {
    let mut text = String::new();
    for url in feed_urls(feed) {
        let body = crate::fetch::text(&url, &feed.name)
            .await
            // The error's chain names the URL, and a URL can carry a key.
            .map_err(|err| {
                anyhow::anyhow!("{}", format!("{err:#}").replace(&url, &masked_url(&url)))
            })?;
        text.push_str(&body);
        text.push('\n');
    }
    Ok(text)
}

// ---- parsing ----

/// Every address or range in `raw`, one per line at most, in whatever
/// shape the line has: a bare address (Feodo), the first column of a CSV
/// (C2IntelFeeds, ThreatFox's exports), `ip:port`, or a JSON object per
/// line (Spamhaus). The first field of a line that is an address is the
/// line's; a line with none is not one.
///
/// Comment lines (`#`, `;`, `//`) are skipped. Whatever is kept passed
/// [`crate::db::is_valid_address`]: it is going into a firewall script.
pub fn parse_addresses(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        let found = line
            .split(|c: char| {
                c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'' | '{' | '}' | '|')
            })
            .filter(|field| !field.is_empty())
            .find_map(address_of);
        if let Some(address) = found {
            if seen.insert(address.clone()) {
                out.push(address);
            }
        }
    }
    out
}

/// `field` as an address or range, with a port taken off: `1.2.3.4:443`
/// and `[2001:db8::1]:443` are their addresses.
fn address_of(field: &str) -> Option<String> {
    let candidate = if let Some(rest) = field.strip_prefix('[') {
        rest.split_once(']').map(|(ip, _)| ip)?
    } else if field.matches(':').count() == 1 && field.contains('.') {
        field.split_once(':')?.0
    } else {
        field
    };
    if !crate::db::is_valid_address(candidate) {
        return None;
    }
    // A bare number is never an address, whatever `parse` makes of it,
    // and an address with a prefix must have a dotted or coloned base.
    if !candidate.contains('.') && !candidate.contains(':') {
        return None;
    }
    Some(normalize(candidate))
}

/// The one spelling of an address or range: host bits cleared, a full
/// prefix dropped, IPv6 compressed.
fn normalize(address: &str) -> String {
    crate::db::normalize_trusted_address(address).unwrap_or_else(|_| address.to_string())
}

/// Every domain in `raw`: a hosts file (`0.0.0.0 example.com`), an RPZ
/// zone (`example.com CNAME .`), the first column of a CSV, or one per
/// line. Lowercased, without a trailing dot or a leading `*.`.
pub fn parse_domains(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
            || line.starts_with('$')
            || line.starts_with('@')
        {
            continue;
        }
        let found = line
            .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\''))
            .filter(|field| !field.is_empty())
            .filter(|field| field.parse::<IpAddr>().is_err())
            .map(|field| {
                field
                    .trim_end_matches('.')
                    .trim_start_matches("*.")
                    .to_ascii_lowercase()
            })
            .find(|field| is_domain(field));
        if let Some(domain) = found {
            if seen.insert(domain.clone()) {
                out.push(domain);
            }
        }
    }
    out
}

/// Whether `name` is a domain this may write into a resolver's config:
/// letters, digits and hyphens in labels of at most 63, at least two
/// labels, and a top-level one that is not a number.
pub fn is_domain(name: &str) -> bool {
    if name.len() > 253 || !name.contains('.') {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) && labels
        .last()
        .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

// ---- what is never blocked ----

/// An address this host depends on, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    pub address: IpAddr,
    pub why: String,
    /// The name `address` was resolved from, when it was: an apt mirror,
    /// the ACME server, a feed's host. What a domain feed is held to (see
    /// [`guard_domains`]); `None` for a resolver, which has no name.
    pub host: Option<String>,
}

/// Domains no feed may sinkhole, whatever this host's files name: where
/// certificates are renewed, where Debian and Ubuntu's packages and their
/// security updates come from, and where this project's lists and
/// releases are served. A name under one of these is kept off too.
///
/// A domain feed used to be stored as it arrived. One that listed
/// `raw.githubusercontent.com` would have sent the host's own feed
/// fetches to the sinkhole, the corrected list among them: a mistake
/// upstream that the next download could never undo.
pub const NEVER_SINKHOLED: [&str; 7] = [
    "letsencrypt.org",
    "debian.org",
    "ubuntu.com",
    "canonical.com",
    "github.com",
    "githubusercontent.com",
    "github.io",
];

/// The most domains one feed may carry. The lists this ships with hold a
/// few thousand; a resolver given millions of lines stops answering.
pub const MAX_FEED_DOMAINS: usize = 500_000;

/// `entries` of a domain feed, without any that would send to the
/// sinkhole a name this host needs: one of [`NEVER_SINKHOLED`] or below
/// it, or a host `protected` names, or a parent of one (a resolver given
/// `example.org` answers for `deb.example.org` too).
pub fn guard_domains(entries: Vec<String>, protected: &[Protected]) -> Guarded {
    let below = |name: &str, parent: &str| {
        name == parent
            || name
                .strip_suffix(parent)
                .is_some_and(|rest| rest.ends_with('.'))
    };
    let mut guarded = Guarded::default();
    for entry in entries {
        let why = NEVER_SINKHOLED
            .iter()
            .find(|base| below(&entry, base))
            .map(|base| format!("is {base} or below it, which this host needs"))
            .or_else(|| {
                protected
                    .iter()
                    .find(|p| p.host.as_deref().is_some_and(|host| below(host, &entry)))
                    .map(|p| format!("would sinkhole {}", p.why))
            });
        match why {
            Some(why) => guarded.kept_off.push((entry, why)),
            None => guarded.kept.push(entry),
        }
    }
    guarded
}

/// Ranges no feed may reach into: this host's own networks, and the ones
/// that are not the internet. Private, loopback and link-local as the
/// inbound rules spell them, then the shared address space carriers and
/// Tailscale use, `0.0.0.0/8`, multicast and the reserved block above it,
/// and IPv6 multicast.
pub const NEVER_BLOCKED: [&str; 13] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "0.0.0.0/8",
    "224.0.0.0/3",
    "::1",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// The broadest range a feed may carry: a /8, or an IPv6 /16.
const MIN_PREFIX_V4: u32 = 8;
const MIN_PREFIX_V6: u32 = 16;

/// What [`guard`] made of a feed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Guarded {
    pub kept: Vec<String>,
    /// Each entry left out, with why.
    pub kept_off: Vec<(String, String)>,
}

/// `entries`, without any that could cut this host off from what it needs:
/// see "What is never blocked" in the module docs.
pub fn guard(entries: Vec<String>, protected: &[Protected]) -> Guarded {
    let mut guarded = Guarded::default();
    for entry in entries {
        match kept_off_because(&entry, protected) {
            Some(why) => guarded.kept_off.push((entry, why)),
            None => guarded.kept.push(entry),
        }
    }
    guarded
}

fn kept_off_because(entry: &str, protected: &[Protected]) -> Option<String> {
    if let Some((_, len)) = entry.split_once('/') {
        let len: u32 = len.parse().unwrap_or(0);
        let min = if entry.contains(':') {
            MIN_PREFIX_V6
        } else {
            MIN_PREFIX_V4
        };
        if len < min {
            return Some(format!("broader than a /{min}"));
        }
    }
    if let Some(range) = NEVER_BLOCKED
        .iter()
        .find(|range| crate::ipranges::cidrs_overlap(entry, range))
    {
        return Some(format!("overlaps {range}, which is local or reserved"));
    }
    protected
        .iter()
        .find(|p| crate::ipranges::cidr_contains(entry, p.address))
        .map(|p| format!("holds {}, {}", p.address, p.why))
}

/// Where [`protected_destinations`] looks: the host's files under `root`,
/// `/` except in tests, and a resolver for the names it finds there.
pub struct Surroundings<'a> {
    pub root: &'a std::path::Path,
    pub resolve: &'a dyn Fn(&str) -> Vec<IpAddr>,
}

/// Resolves `host` with the system's resolver, as a connection to it would.
pub fn system_resolve(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (host, 443)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// The ACME server certbot and most other clients renew from.
const ACME_HOSTS: [&str; 1] = ["acme-v02.api.letsencrypt.org"];

/// Every address this host is known to depend on: its resolvers, what its
/// apt mirrors, Let's Encrypt and `feed_urls` resolve to now. Read at fetch
/// time, when the feeds are filtered by it.
pub fn protected_destinations(around: &Surroundings, feed_urls: &[String]) -> Vec<Protected> {
    let mut out: Vec<Protected> = Vec::new();
    // One row for each name an address answers to: a shared address (a
    // CDN's) is two hosts a domain feed must each leave alone.
    let mut add = |address: IpAddr, why: String, host: Option<String>| {
        if !out.iter().any(|p| p.address == address && p.host == host) {
            out.push(Protected { address, why, host });
        }
    };

    // The stub resolver's file names 127.0.0.53; the one beside it names
    // the upstreams systemd-resolved really asks.
    for file in ["etc/resolv.conf", "run/systemd/resolve/resolv.conf"] {
        let Ok(text) = std::fs::read_to_string(around.root.join(file)) else {
            continue;
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if words.next() != Some("nameserver") {
                continue;
            }
            if let Some(Ok(address)) = words
                .next()
                .map(|w| w.split('%').next().unwrap_or(w).parse::<IpAddr>())
            {
                if !address.is_loopback() {
                    add(address, "a resolver this host uses".to_string(), None);
                }
            }
        }
    }

    let mut hosts: Vec<(String, String)> = Vec::new();
    for host in apt_hosts(around.root) {
        hosts.push((host.clone(), format!("{host}, an apt mirror")));
    }
    for host in ACME_HOSTS {
        hosts.push((
            host.to_string(),
            format!("{host}, which renews certificates"),
        ));
    }
    for url in feed_urls {
        if let Some(host) = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
        {
            hosts.push((host.clone(), format!("{host}, which serves a feed")));
        }
    }
    let mut resolved = BTreeSet::new();
    for (host, why) in hosts {
        if !resolved.insert(host.clone()) {
            continue;
        }
        for address in (around.resolve)(&host) {
            add(address, why.clone(), Some(host.clone()));
        }
    }
    out
}

/// The hosts every apt source on this host names, from the one-line form
/// (`deb http://deb.debian.org/debian trixie main`) and the deb822 form
/// (`URIs: http://...`).
fn apt_hosts(root: &std::path::Path) -> Vec<String> {
    let mut files = vec![root.join("etc/apt/sources.list")];
    if let Ok(dir) = std::fs::read_dir(root.join("etc/apt/sources.list.d")) {
        let mut listed: Vec<_> = dir
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext == "list" || ext == "sources")
            })
            .collect();
        listed.sort();
        files.extend(listed);
    }
    let mut hosts = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let words: Vec<&str> = if let Some(uris) = line.strip_prefix("URIs:") {
                uris.split_whitespace().collect()
            } else if line.starts_with("deb ") || line.starts_with("deb-src ") {
                line.split_whitespace().collect()
            } else {
                continue;
            };
            for word in words {
                if let Some(host) = reqwest::Url::parse(word)
                    .ok()
                    .filter(|u| matches!(u.scheme(), "http" | "https"))
                    .and_then(|u| u.host_str().map(str::to_string))
                {
                    if !hosts.contains(&host) {
                        hosts.push(host);
                    }
                }
            }
        }
    }
    hosts
}

/// Parses `raw` as `feed`'s kind of list, keeps what [`guard`] lets
/// through, and stores it. Refuses a list that came to nothing, which is
/// an upstream that moved or an error page far more often than a list
/// that is really empty, and would quietly stop blocking everything the
/// feed held.
pub fn store(db: &Db, feed: &EgressFeed, raw: &str, protected: &[Protected]) -> Result<Stored> {
    let entries = match feed.kind {
        EntryKind::Ip => parse_addresses(raw),
        EntryKind::Domain => parse_domains(raw),
    };
    if entries.is_empty() {
        bail!(
            "{} returned nothing usable; keeping what it held before",
            feed.name
        );
    }
    let guarded = match feed.kind {
        EntryKind::Ip => guard(entries, protected),
        EntryKind::Domain => {
            if entries.len() > MAX_FEED_DOMAINS {
                bail!(
                    "{} returned {} domains, more than the {MAX_FEED_DOMAINS} a feed may \
                     hold; keeping what it held before",
                    feed.name,
                    entries.len()
                );
            }
            guard_domains(entries, protected)
        }
    };
    let count = db.replace_egress_entries(&feed.id, &guarded.kept, guarded.kept_off.len())?;
    Ok(Stored {
        count,
        kept_off: guarded.kept_off,
    })
}

/// What [`store`] stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub count: usize,
    pub kept_off: Vec<(String, String)>,
}

impl Stored {
    pub fn summary(&self, feed: &str) -> String {
        match self.kept_off.as_slice() {
            [] => format!("{feed}: {} entries", self.count),
            [(entry, why)] => format!("{feed}: {} entries, left out {entry} ({why})", self.count),
            [(entry, why), rest @ ..] => format!(
                "{feed}: {} entries, left out {entry} ({why}) and {} more",
                self.count,
                rest.len()
            ),
        }
    }
}

/// Every enabled feed, fetched and stored, each on its own: one that fails
/// keeps what it held, and the others are still updated. The summary, and
/// whether every one succeeded.
pub async fn update_enabled(db: &Db, around: &Surroundings<'_>) -> Result<(String, bool)> {
    let feeds: Vec<EgressFeed> = db
        .list_egress_feeds()?
        .into_iter()
        .filter(|f| f.enabled)
        .collect();
    if feeds.is_empty() {
        return Ok(("no C&C feed is switched on".to_string(), true));
    }
    let mut fetched = Vec::new();
    for feed in feeds {
        let raw = fetch(&feed).await.map_err(|err| format!("{err:#}"));
        fetched.push((feed, raw));
    }
    let urls: Vec<String> = fetched
        .iter()
        .flat_map(|(feed, _)| feed_urls(feed))
        .collect();
    let protected = protected_destinations(around, &urls);
    Ok(store_fetched(db, &protected, fetched))
}

/// The database half of [`update_enabled`], for a caller that fetched and
/// resolved on its own: the TUI and `tick`, which may not hold a `Db`
/// across the network.
pub fn store_fetched(
    db: &Db,
    protected: &[Protected],
    fetched: Vec<(EgressFeed, std::result::Result<String, String>)>,
) -> (String, bool) {
    let mut parts = Vec::new();
    let mut all_ok = true;
    for (feed, raw) in fetched {
        match raw
            .and_then(|raw| store(db, &feed, &raw, protected).map_err(|err| format!("{err:#}")))
        {
            Ok(stored) => parts.push(stored.summary(&feed.id)),
            Err(err) => {
                all_ok = false;
                parts.push(format!("{}: failed: {err}", feed.id));
            }
        }
    }
    (parts.join("; "), all_ok)
}

// ---- what the kernel logs ----

/// Which way an attempt left the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Path {
    /// From a process on this host, through `output`.
    Host,
    /// Routed through this host, through `forward`: from a container, or
    /// from another machine this host routes for.
    Forward,
}

impl Path {
    pub fn as_str(self) -> &'static str {
        match self {
            Path::Host => "host",
            Path::Forward => "forward",
        }
    }

    pub fn parse(text: &str) -> Option<Path> {
        match text {
            "host" => Some(Path::Host),
            "forward" => Some(Path::Forward),
            _ => None,
        }
    }
}

/// What one logged attempt says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub path: Path,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub port: Option<u16>,
    pub protocol: String,
    /// The owner of the socket that sent it, from `log flags skuid` (nft)
    /// or `--log-uid` (iptables). Never there for a forwarded packet,
    /// which no local socket sent.
    pub uid: Option<u32>,
}

/// Reads `line` as one the egress rules logged, or `None` for any other.
///
/// The kernel's one format, as in [`crate::portscan::parse_trap_line`]:
/// `IN= OUT=eth0 SRC=… DST=… … PROTO=TCP SPT=… DPT=443 … UID=33 GID=33`.
/// A packet from a local socket has an empty `IN=`; a forwarded one names
/// the interface it came in on.
pub fn parse_line(line: &str) -> Option<Logged> {
    let at = line.find(LOG_PREFIX)?;
    let before = line[..at].trim_end();
    let before = match before.strip_suffix(']') {
        Some(rest) => rest.rsplit_once('[')?.0.trim_end(),
        None => before,
    };
    if !before.ends_with("kernel:") {
        return None;
    }
    let mut incoming = None;
    let mut source = None;
    let mut destination = None;
    let mut port = None;
    let mut protocol = None;
    let mut uid = None;
    for field in line[at + LOG_PREFIX.len()..].split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "IN" if incoming.is_none() => incoming = Some(!value.is_empty()),
            "SRC" if source.is_none() => source = value.parse::<IpAddr>().ok(),
            "DST" if destination.is_none() => destination = value.parse::<IpAddr>().ok(),
            "DPT" if port.is_none() => port = value.parse::<u16>().ok(),
            "PROTO" if protocol.is_none() => protocol = Some(value.to_string()),
            "UID" if uid.is_none() => uid = value.parse::<u32>().ok(),
            _ => {}
        }
    }
    Some(Logged {
        path: if incoming? { Path::Forward } else { Path::Host },
        source: source?,
        destination: destination?,
        port,
        protocol: protocol.unwrap_or_else(|| "?".to_string()),
        uid,
    })
}

/// Whether `line` is one the egress rules logged.
pub fn is_egress_line(line: &str) -> bool {
    parse_line(line).is_some()
}

/// What makes two logged attempts one flow: the path, source,
/// destination, port and user.
type Flow = (Path, IpAddr, IpAddr, Option<u16>, Option<u32>);

/// Reads kernel log lines into hits, one per flow.
pub struct Observer {
    now: i64,
    undated: Option<i64>,
    offset: i64,
    flows: HashMap<Flow, NewEgressHit>,
    order: Vec<Flow>,
}

impl Observer {
    /// `undated`: the time to give a line that carries none, as
    /// [`crate::portscan::Observer::new`] has it.
    pub fn new(now: i64, undated: Option<i64>) -> Observer {
        Observer {
            now,
            undated,
            offset: crate::logtime::local_offset(now),
            flows: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn line(&mut self, text: &str) {
        let Some(logged) = parse_line(text) else {
            return;
        };
        let offset = self.offset;
        let Some(at) = crate::logtime::syslog_line(text, self.now, &|_| offset)
            .or(self.undated)
            .map(|at| at.min(self.now))
        else {
            return;
        };
        let key = (
            logged.path,
            logged.source,
            logged.destination,
            logged.port,
            logged.uid,
        );
        let evidence = crate::blocks::evidence_line(text).unwrap_or_default();
        match self.flows.get_mut(&key) {
            Some(hit) => {
                hit.count += 1;
                hit.first_seen = hit.first_seen.min(at);
                if at >= hit.last_seen {
                    hit.last_seen = at;
                    hit.evidence = evidence;
                }
            }
            None => {
                self.order.push(key);
                self.flows.insert(
                    key,
                    NewEgressHit {
                        path: logged.path,
                        source: logged.source.to_string(),
                        destination: logged.destination.to_string(),
                        port: logged.port,
                        protocol: logged.protocol,
                        uid: logged.uid,
                        count: 1,
                        first_seen: at,
                        last_seen: at,
                        evidence,
                    },
                );
            }
        }
    }

    /// The flows, in the order each was first seen.
    pub fn finish(mut self) -> Vec<NewEgressHit> {
        self.order
            .iter()
            .filter_map(|key| self.flows.remove(key))
            .collect()
    }
}

// ---- what the firewall is rendered with ----

/// The egress half of a firewall script: see "Where the rules go" in the
/// module docs, and the renderers for how each backend spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    pub mode: Mode,
    /// Every listed address and range, IPv4 and IPv6, in a stable order.
    pub destinations: Vec<String>,
    /// Addresses the operator trusts and ones that logged in over SSH
    /// lately, never stopped. Sorted, as it reaches the signature.
    pub trusted: Vec<String>,
    /// The sinkhole the resolver answers listed domains with, when that is
    /// on: a connection to it is a hit like any other.
    pub sinkhole: Option<String>,
    /// Addresses cut off by a containment, both ways.
    pub contained_addresses: Vec<String>,
    /// Users whose own outbound connections are cut off.
    pub contained_uids: Vec<u32>,
}

impl Egress {
    /// Whether the listed addresses are dropped, not only logged.
    pub fn blocks(&self) -> bool {
        self.mode == Mode::Block
    }

    /// Whether the listed addresses are checked at all. With the mode off,
    /// only what is contained is rendered.
    pub fn watches(&self) -> bool {
        self.mode != Mode::Off
    }

    /// Everything that is matched as a destination: the listed addresses
    /// and the sinkhole.
    pub fn listed(&self) -> Vec<String> {
        let mut all = self.destinations.clone();
        if let Some(sinkhole) = &self.sinkhole {
            if !all.contains(sinkhole) {
                all.push(sinkhole.clone());
            }
        }
        all
    }

    /// The line [`crate::firewall::signature`] hashes for it: a different
    /// egress section is a different script.
    pub fn signature_line(&self) -> String {
        format!(
            "egress {} {:?} {:?} {:?} {:?} {:?}",
            self.mode.as_str(),
            self.destinations,
            self.trusted,
            self.sinkhole,
            self.contained_addresses,
            self.contained_uids
        )
    }
}

/// What the firewall renders for outbound traffic now, or `None` when
/// there is nothing to render: the mode off and nothing contained.
pub fn for_render(db: &Db) -> Result<Option<Egress>> {
    let mode = Mode::get(db)?;
    let open = db.open_containments()?;
    if mode == Mode::Off && open.is_empty() {
        return Ok(None);
    }
    let mut destinations: Vec<String> = Vec::new();
    if mode != Mode::Off {
        let mut seen = BTreeSet::new();
        for (_, entry) in db.enabled_egress_entries(EntryKind::Ip)? {
            if crate::db::is_valid_address(&entry) && seen.insert(entry.clone()) {
                destinations.push(entry);
            }
        }
    }
    let mut contained_addresses = Vec::new();
    let mut contained_uids = Vec::new();
    for containment in open {
        match containment.kind {
            crate::db::egress::ContainmentKind::User => {
                if let Ok(uid) = containment.target.parse::<u32>() {
                    contained_uids.push(uid);
                }
            }
            _ => contained_addresses.extend(containment.addresses),
        }
    }
    contained_addresses.sort();
    contained_addresses.dedup();
    contained_uids.sort_unstable();
    contained_uids.dedup();
    let mut trusted = db.list_trusted_addresses()?;
    trusted.extend(db.recent_ssh_login_ips()?);
    trusted.sort();
    trusted.dedup();
    Ok(Some(Egress {
        mode,
        destinations,
        trusted,
        sinkhole: (mode != Mode::Off)
            .then(|| crate::sinkhole::active_address(db))
            .transpose()?
            .flatten(),
        contained_addresses,
        contained_uids,
    }))
}

/// The enabled feeds that list `address`, by id: what a hit is reported
/// against, and what decides whether it may contain.
pub fn feeds_listing(db: &Db, address: IpAddr) -> Result<Vec<String>> {
    let mut feeds: Vec<String> = Vec::new();
    for (feed, entry) in db.enabled_egress_entries(EntryKind::Ip)? {
        if !feeds.contains(&feed) && crate::ipranges::cidr_contains(&entry, address) {
            feeds.push(feed);
        }
    }
    if crate::sinkhole::active_address(db)?.as_deref() == Some(address.to_string().as_str()) {
        feeds.push(crate::sinkhole::FEED_LABEL.to_string());
    }
    Ok(feeds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_built_in_feed_has_a_distinct_id_that_round_trips() {
        let mut ids = BTreeSet::new();
        for kind in FeedKind::ALL {
            assert!(ids.insert(kind.id()), "{} twice", kind.id());
            assert_eq!(FeedKind::from_id(kind.id()), Some(kind));
            assert!(
                kind.urls().iter().all(|url| url.starts_with("https://")),
                "{} is fetched without TLS",
                kind.id()
            );
        }
    }

    #[test]
    fn a_new_database_is_off_and_watches_nothing() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(Mode::get(&db).unwrap(), Mode::Off);
        assert_eq!(for_render(&db).unwrap(), None);
    }

    #[test]
    fn a_stored_mode_this_version_does_not_know_reads_as_off() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(keys::EGRESS_MODE, "obliterate")
            .unwrap();
        assert_eq!(Mode::get(&db).unwrap(), Mode::Off);
    }

    /// One parser for every IP feed: the formats below are the first lines
    /// of each, as served.
    #[test]
    fn each_feed_s_format_parses_to_its_addresses() {
        let cases = [
            (
                "Feodo Tracker",
                "################################################################\n\
                 # abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #\n\
                 #\n\
                 # DstIP\n\
                 50.16.16.211\n\
                 # END 1 entries\n",
                vec!["50.16.16.211"],
            ),
            (
                "C2IntelFeeds",
                "#ip,ioc\n\
                 1.117.74.144,Possible Cobaltstrike C2 IP\n\
                 1.12.253.219,Possible Cobaltstrike C2 IP\n",
                vec!["1.117.74.144", "1.12.253.219"],
            ),
            (
                "Spamhaus DROP",
                "{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n\
                 {\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n\
                 {\"type\":\"metadata\",\"timestamp\":1792750442,\"size\":5759,\"records\":91}\n",
                vec!["1.10.16.0/20", "2001:678:254::/48"],
            ),
            (
                "ThreatFox's ip:port CSV",
                "# first_seen_utc,ioc_id,ioc_value,ioc_type\n\
                 \"2026-10-25 08:00:00\",\"1612345\",\"198.51.100.7:443\",\"ip:port\"\n\
                 \"2026-10-25 08:00:00\",\"1612346\",\"[2001:db8::7]:8443\",\"ip:port\"\n",
                vec!["198.51.100.7", "2001:db8::7"],
            ),
        ];
        for (feed, raw, want) in cases {
            assert_eq!(parse_addresses(raw), want, "{feed}");
        }
    }

    /// Whatever is kept goes into a firewall script, and for iptables
    /// into `sh`.
    #[test]
    fn a_line_that_smuggles_a_command_is_not_an_address() {
        let raw = "1.2.3.4/24;touch /tmp/pwned\n$(reboot)\n192.0.2.300\n12345\n";
        assert_eq!(parse_addresses(raw), vec!["1.2.3.0/24"]);
    }

    #[test]
    fn each_domain_list_s_format_parses_to_its_domains() {
        let cases = [
            (
                "C2IntelFeeds",
                "#domain,ioc\n178-128-196-79.sslip.io,Possible Cobalt Strike C2 Domain\n",
                vec!["178-128-196-79.sslip.io"],
            ),
            (
                "a hosts file",
                "# comment\n127.0.0.1 localhost\n0.0.0.0 Evil.Example.COM\n",
                vec!["evil.example.com"],
            ),
            (
                "an RPZ zone",
                "$TTL 30\n@ SOA rpz.example. hostmaster.example. 1 1h 15m 30d 2h\n\
                 bad.example.net CNAME .\n*.bad.example.net CNAME .\n",
                vec!["bad.example.net"],
            ),
            (
                "a plain list",
                "c2.example.org.\nnot a domain\n-bad-.example\n",
                vec!["c2.example.org"],
            ),
        ];
        for (list, raw, want) in cases {
            assert_eq!(parse_domains(raw), want, "{list}");
        }
    }

    fn protected(address: &str, why: &str) -> Protected {
        Protected {
            address: address.parse().unwrap(),
            why: why.to_string(),
            host: None,
        }
    }

    /// A feed that named where the feeds come from could never be
    /// corrected by the next download.
    #[test]
    fn a_domain_feed_cannot_sinkhole_what_the_host_needs() {
        let mirror = Protected {
            host: Some("mirror.example.net".to_string()),
            ..protected("192.0.2.80", "mirror.example.net, an apt mirror")
        };
        let entries = [
            "evil.example.com",
            "raw.githubusercontent.com",
            "letsencrypt.org",
            "example.net",
            "mirror.example.net",
            "notgithub.com",
        ]
        .map(String::from)
        .to_vec();

        let guarded = guard_domains(entries, &[mirror]);

        assert_eq!(guarded.kept, vec!["evil.example.com", "notgithub.com"]);
        let kept_off: Vec<&str> = guarded.kept_off.iter().map(|(e, _)| e.as_str()).collect();
        assert_eq!(
            kept_off,
            vec![
                "raw.githubusercontent.com",
                "letsencrypt.org",
                "example.net",
                "mirror.example.net"
            ],
            "with reasons: {:?}",
            guarded.kept_off
        );
    }

    #[test]
    fn the_guard_keeps_off_what_would_cut_the_host_off() {
        let entries = [
            "198.51.100.7",
            "10.0.0.0/8",
            "172.0.0.0/8",
            "100.64.0.0/10",
            "1.0.0.0/7",
            "192.0.2.0/24",
            "2001:db8::/32",
            "2000::/3",
        ]
        .map(String::from)
        .to_vec();
        let guarded = guard(
            entries,
            &[protected("192.0.2.53", "a resolver this host uses")],
        );
        assert_eq!(guarded.kept, vec!["198.51.100.7", "2001:db8::/32"]);
        let why: Vec<(&str, &str)> = guarded
            .kept_off
            .iter()
            .map(|(e, w)| (e.as_str(), w.as_str()))
            .collect();
        assert_eq!(
            why,
            vec![
                (
                    "10.0.0.0/8",
                    "overlaps 10.0.0.0/8, which is local or reserved"
                ),
                (
                    "172.0.0.0/8",
                    "overlaps 172.16.0.0/12, which is local or reserved"
                ),
                (
                    "100.64.0.0/10",
                    "overlaps 100.64.0.0/10, which is local or reserved"
                ),
                ("1.0.0.0/7", "broader than a /8"),
                (
                    "192.0.2.0/24",
                    "holds 192.0.2.53, a resolver this host uses"
                ),
                ("2000::/3", "broader than a /16"),
            ]
        );
    }

    fn surroundings_in(
        dir: &std::path::Path,
        then: impl FnOnce(&Surroundings) -> Vec<Protected>,
    ) -> Vec<Protected> {
        let resolve = |host: &str| -> Vec<IpAddr> {
            match host {
                "deb.debian.org" => vec!["192.0.2.80".parse().unwrap()],
                "security.debian.org" => vec!["192.0.2.81".parse().unwrap()],
                "acme-v02.api.letsencrypt.org" => vec!["192.0.2.82".parse().unwrap()],
                "feeds.example" => vec!["192.0.2.83".parse().unwrap()],
                _ => Vec::new(),
            }
        };
        then(&Surroundings {
            root: dir,
            resolve: &resolve,
        })
    }

    #[test]
    fn what_the_host_depends_on_is_found_in_its_own_files() {
        let dir = tempfile::tempdir().unwrap();
        let write = |path: &str, text: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0\n");
        write(
            "run/systemd/resolve/resolv.conf",
            "nameserver 192.0.2.53\nnameserver fe80::1%eth0\n",
        );
        write(
            "etc/apt/sources.list",
            "deb http://deb.debian.org/debian trixie main # main\n",
        );
        write(
            "etc/apt/sources.list.d/debian.sources",
            "Types: deb\nURIs: http://security.debian.org/debian-security\nSuites: trixie-security\n",
        );
        let found = surroundings_in(dir.path(), |around| {
            protected_destinations(around, &["https://feeds.example/list.txt".to_string()])
        });
        let found: Vec<(String, &str)> = found
            .iter()
            .map(|p| (p.address.to_string(), p.why.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("192.0.2.53".to_string(), "a resolver this host uses"),
                ("fe80::1".to_string(), "a resolver this host uses"),
                ("192.0.2.80".to_string(), "deb.debian.org, an apt mirror"),
                (
                    "192.0.2.81".to_string(),
                    "security.debian.org, an apt mirror"
                ),
                (
                    "192.0.2.82".to_string(),
                    "acme-v02.api.letsencrypt.org, which renews certificates"
                ),
                (
                    "192.0.2.83".to_string(),
                    "feeds.example, which serves a feed"
                ),
            ]
        );
    }

    #[test]
    fn a_key_in_a_feed_s_url_is_never_shown() {
        let url = "https://threatfox-api.abuse.ch/v2/files/exports/0123secret/full.csv";
        let masked = masked_url(url);
        assert_eq!(masked, "https://threatfox-api.abuse.ch/\u{2026}");
        assert!(!masked.contains("secret"));
    }

    #[test]
    fn a_feed_added_by_url_must_be_https_and_is_off() {
        let db = Db::open_in_memory().unwrap();
        let err = add_custom_feed(
            &db,
            "ThreatFox",
            "http://example.com/x",
            EntryKind::Ip,
            true,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not https"), "{err}");
        let id = add_custom_feed(
            &db,
            "ThreatFox IPs!",
            "https://example.com/x",
            EntryKind::Ip,
            true,
        )
        .unwrap();
        assert_eq!(id, "custom-threatfox-ips");
        let feed = db.get_egress_feed(&id).unwrap().unwrap();
        assert!(!feed.enabled && feed.contain && !feed.builtin, "{feed:?}");
    }

    #[test]
    fn an_empty_fetch_keeps_what_the_feed_held() {
        let db = Db::open_in_memory().unwrap();
        register_builtin_feeds(&db).unwrap();
        let feed = db.get_egress_feed("feodo").unwrap().unwrap();
        store(&db, &feed, "198.51.100.7\n", &[]).unwrap();
        let err = store(&db, &feed, "<html>maintenance</html>", &[]).unwrap_err();
        assert!(err.to_string().contains("nothing usable"), "{err}");
        assert_eq!(db.get_egress_feed("feodo").unwrap().unwrap().entry_count, 1);
    }

    const HOST_LINE: &str = "Oct 25 10:00:00 web kernel: [100.000000] stop-bots-egress: IN= \
        OUT=eth0 SRC=192.0.2.10 DST=198.51.100.7 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF \
        PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 UID=33 GID=33";

    const FORWARD_LINE: &str = "2026-10-25T10:00:01+00:00 web kernel: stop-bots-egress: \
        IN=docker0 OUT=eth0 MAC=02:42:ac:11:00:02 SRC=172.17.0.2 DST=198.51.100.7 LEN=60 \
        TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=4444 WINDOW=64240 RES=0x00 \
        SYN URGP=0";

    #[test]
    fn a_logged_attempt_says_its_path_flow_and_user() {
        let cases = [
            (
                HOST_LINE,
                Logged {
                    path: Path::Host,
                    source: "192.0.2.10".parse().unwrap(),
                    destination: "198.51.100.7".parse().unwrap(),
                    port: Some(443),
                    protocol: "TCP".to_string(),
                    uid: Some(33),
                },
            ),
            (
                FORWARD_LINE,
                Logged {
                    path: Path::Forward,
                    source: "172.17.0.2".parse().unwrap(),
                    destination: "198.51.100.7".parse().unwrap(),
                    port: Some(4444),
                    protocol: "TCP".to_string(),
                    uid: None,
                },
            ),
        ];
        for (line, want) in cases {
            assert_eq!(parse_line(line), Some(want), "{line}");
        }
    }

    #[test]
    fn a_line_that_only_quotes_the_prefix_is_not_one_of_ours() {
        let quoted = "Oct 25 10:00:00 web sshd[1]: user stop-bots-egress: IN= OUT=eth0 \
                      SRC=192.0.2.10 DST=198.51.100.7 PROTO=TCP DPT=443";
        assert_eq!(parse_line(quoted), None);
        assert_eq!(
            parse_line(&HOST_LINE.replace("stop-bots-egress", "stop-bots-trap")),
            None
        );
    }

    #[test]
    fn retries_of_one_flow_are_one_hit_counted() {
        let mut observer = Observer::new(1_800_000_000, None);
        observer.line(HOST_LINE);
        observer.line(HOST_LINE);
        observer.line(FORWARD_LINE);
        let hits = observer.finish();
        let flows: Vec<(Path, &str, u64)> = hits
            .iter()
            .map(|h| (h.path, h.source.as_str(), h.count))
            .collect();
        assert_eq!(
            flows,
            vec![
                (Path::Host, "192.0.2.10", 2),
                (Path::Forward, "172.17.0.2", 1)
            ]
        );
    }

    #[test]
    fn what_is_rendered_is_the_enabled_feeds_and_what_is_contained() {
        let db = Db::open_in_memory().unwrap();
        register_builtin_feeds(&db).unwrap();
        db.set_egress_feed_enabled("feodo", true).unwrap();
        let feodo = db.get_egress_feed("feodo").unwrap().unwrap();
        store(&db, &feodo, "198.51.100.7\n198.51.100.8\n", &[]).unwrap();
        let drop = db.get_egress_feed("spamhaus-drop").unwrap().unwrap();
        store(&db, &drop, "{\"cidr\":\"203.0.113.0/24\"}\n", &[]).unwrap();
        Mode::Watch.set(&db).unwrap();

        let egress = for_render(&db).unwrap().unwrap();
        assert_eq!(egress.destinations, vec!["198.51.100.7", "198.51.100.8"]);
        assert!(!egress.blocks());
        assert_eq!(
            feeds_listing(&db, "198.51.100.8".parse().unwrap()).unwrap(),
            vec!["feodo"]
        );
    }

    /// Switching the mode off stops checking destinations, and leaves
    /// whatever is contained cut off: releasing it is its own step.
    #[test]
    fn with_the_mode_off_a_containment_is_still_rendered() {
        let db = Db::open_in_memory().unwrap();
        db.open_containment(&crate::db::egress::NewContainment {
            kind: crate::db::egress::ContainmentKind::User,
            target: "1001".to_string(),
            name: Some("app".to_string()),
            addresses: Vec::new(),
            action: "isolate".to_string(),
            reason: "by hand".to_string(),
            automatic: false,
        })
        .unwrap();
        let egress = for_render(&db).unwrap().unwrap();
        assert!(!egress.watches());
        assert_eq!(egress.contained_uids, vec![1001]);
    }

    /// An address that logged in over SSH lately is never stopped going
    /// out, as it is never blocked coming in: listed, its session would
    /// lose every reply.
    #[test]
    fn an_address_that_logged_in_over_ssh_is_never_stopped() {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&["198.51.100.7".to_string()])
            .unwrap();
        Mode::Block.set(&db).unwrap();

        let egress = for_render(&db).unwrap().unwrap();
        assert_eq!(egress.trusted, vec!["198.51.100.7"], "{egress:?}");
    }
}
