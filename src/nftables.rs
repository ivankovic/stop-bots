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

//! Renders [`FirewallRule`]s into an `nft -f` script, scoped to our own
//! `inet stop_bots` table.
//!
//! Two things a typical hand-written nftables script (like the ones in
//! `tests/fixtures/nftables/`) gets away with, but that this generator
//! deliberately avoids:
//!
//! - `flush ruleset` wipes *every* table on the system, not just ours. We
//!   only ever reset our own table: `add table inet stop_bots` (a no-op if
//!   it already exists) followed by `delete table inet stop_bots` (now
//!   guaranteed to exist) then `add table inet stop_bots` again — leaving a
//!   guaranteed-fresh, empty table scoped to just us, with every other table
//!   on the system untouched. The chain and rules are then added fresh into
//!   it, so the whole script is safe to re-run without ever needing to know
//!   whether a previous run already created the base chain (re-declaring an
//!   existing hooked base chain via `add chain` is not reliably a no-op,
//!   unlike `add table`).
//! - `policy drop` on a chain hooked at `priority -1` makes that chain the
//!   de facto gatekeeper for *all* traffic through that hook: anything not
//!   explicitly accepted gets dropped, including ordinary traffic to the
//!   box — and, on the `forward` hook, every packet between containers.
//!   We use `policy accept` instead, so these chains only ever block the
//!   specific addresses they're told to.
//!
//! ## Two hooks, because `input` alone misses every container
//!
//! A packet arriving for a service that runs *on the host* is delivered
//! locally and traverses the `input` hook. A packet arriving for a
//! published container port does not: the DNAT in `nat/prerouting`
//! rewrites its destination to the container, routing then sees an address
//! that is not local, and it leaves through `forward` instead. An
//! `input`-only chain therefore never sees it, and every Block rule this
//! project writes is inert for anything containerised — silently, and
//! completely, which is the worst way for a firewall to fail.
//!
//! That is not a hypothetical arrangement. It is what NGINX in Docker with
//! `ports: 80:80` is, which is a common way to run the very thing this
//! project protects, and it is what makes `block_web_scanners` — whose
//! entire output is firewall rules — do nothing at all on such a host.
//!
//! So there are two base chains, `bot_block` on `input` and `bot_forward`
//! on `forward`, and the rules themselves live in a third, unhooked chain
//! that both of them `jump` to. One copy of the rules, reached from two
//! hooks: the alternative is rendering every rule twice and relying on
//! nobody ever editing one loop and not the other.
//!
//! Both sit at `priority -1`, ahead of Docker's own rules at the default
//! `filter` priority, and in our own table — so a `docker` restart, which
//! rewrites Docker's chains, cannot displace them.
//!
//! ## Sets, not one rule per address
//!
//! Every address used to be its own `add rule`. A real host carried 44,547
//! of them, and a chain is walked rule by rule, so every new connection
//! paid for every block before it was let through. The addresses now go
//! into named interval sets, one per family and verdict (`block_v4`,
//! `allow_v6`, ...), and each set is matched by a single rule. A set
//! lookup costs about the same with ten elements or a hundred thousand.
//!
//! The rules are still evaluated first-match-wins, in the order
//! [`crate::firewall::all_rules`] produces them, and the sets have to
//! keep that. So they are built in *stages*: consecutive rules with the
//! same verdict and port go into one stage. A rule may also join an
//! earlier stage with the same verdict and port when every stage between
//! the two has that verdict as well, because two rules with the same
//! verdict give the same answer in either order. Any other rule starts a
//! new stage. The SSH-login and trusted Allows therefore stay ahead of
//! every Block, the admin's own rules stay ahead of the private-range
//! Allows, and the allowlist catch-all stays last. A stage that is not the
//! first of its kind gets a numbered set (`allow_v4_2`).
//!
//! The rules come first in the script and the elements last, so the
//! policy can be read at the top of a file whose bulk is addresses.
//!
//! ### Why not `auto-merge`
//!
//! An interval set refuses two elements that overlap ("conflicting
//! intervals specified"), and `auto-merge` is nft's answer to that. It
//! merges without regard to timeouts: on nftables 1.0.9, a permanent
//! `1.2.3.4` added beside `1.2.3.0/24 timeout 60s` was absorbed into the
//! /24 and would have lapsed with it. So overlaps are resolved here
//! instead ([`layers`]):
//!
//! - an element inside another that lasts at least as long is left out,
//!   because the outer one already decides it;
//! - an element inside one that ends sooner is kept, in a second set with
//!   the same verdict (`block_v4_n1`), so each lasts as long as it
//!   should. Two CIDR ranges either nest or do not overlap at all, so
//!   the nesting depth is enough to keep every set free of overlaps.
//!
//! Without `auto-merge`, the kernel holds exactly the elements written,
//! which is also what lets `health` compare the two counts.
//!
//! ## Expiry in the kernel
//!
//! A rule with an `expires_at` becomes an element with a `timeout` of the
//! time it has left, and the kernel removes it when that runs out. Before
//! this, an expired block stayed in the kernel until someone applied the
//! script again. A rule already expired when the script is rendered is
//! left out. The timeout counts from when the script is loaded, not from
//! when it was rendered, so a script loaded long after it was written
//! (the boot unit loads the last one) keeps its blocks for up to that
//! much longer. It never keeps them for ever.
//!
//! This module never executes `nft` itself — applying the generated script
//! is a manual step for the admin. The container suite
//! (`tests/container.rs`) loads its output into a real `nft`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::db::{FirewallAction, FirewallRule};

const TABLE: &str = "inet stop_bots";

/// The base chain on `input`: traffic for services on the host itself.
const CHAIN: &str = "bot_block";

/// The base chain on `forward`: traffic DNAT'd onward to a container.
/// See the module docs for why `input` alone is not enough.
const FORWARD_CHAIN: &str = "bot_forward";

/// The unhooked chain holding the rules, jumped to from both base chains
/// so that the two hooks can never enforce different things.
const RULES_CHAIN: &str = "bot_rules";

/// The v4 ranges the forward chain lets through untouched: loopback,
/// RFC1918 and link-local. The set `ipranges::is_local_or_private` treats
/// as never-a-scanner, spelled as nftables literals.
const PRIVATE_V4: &str = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";

/// The v6 half of [`PRIVATE_V4`]: loopback and unique-local.
const PRIVATE_V6: &str = "::1, fc00::/7";

fn action_word(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "accept",
        FirewallAction::Block => "drop",
        FirewallAction::Reject => "reject",
    }
}

/// The verdict as it reads in a set name: `block_v4`, not `drop_v4`, so
/// the name says what the operator asked for.
fn set_word(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Block => "block",
        FirewallAction::Reject => "reject",
    }
}

/// An address or range the way the kernel stores it: host bits cleared,
/// so `1.2.3.4/24` and `1.2.3.0/24` are the same element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Prefix {
    v6: bool,
    /// The address, right-aligned: an IPv4 address is the low 32 bits.
    bits: u128,
    len: u8,
}

impl Prefix {
    fn parse(address: &str) -> Option<Prefix> {
        let (ip, len) = match address.split_once('/') {
            Some((ip, len)) => (ip, Some(len.parse::<u8>().ok()?)),
            None => (address, None),
        };
        let (v6, bits, width) = match ip.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => (false, u128::from(u32::from(ip)), 32),
            IpAddr::V6(ip) => (true, u128::from(ip), 128),
        };
        let len = len.unwrap_or(width);
        (len <= width).then(|| Prefix { v6, bits, len }.truncated(len))
    }

    fn width(self) -> u8 {
        if self.v6 {
            128
        } else {
            32
        }
    }

    /// The range of `len` bits that contains this one.
    fn truncated(self, len: u8) -> Prefix {
        let host = u32::from(self.width() - len);
        let bits = if host >= 128 {
            0
        } else {
            (self.bits >> host) << host
        };
        Prefix { bits, len, ..self }
    }

    #[cfg(test)]
    fn contains(self, ip: IpAddr) -> bool {
        let Some(ip) = Prefix::parse(&ip.to_string()) else {
            return false;
        };
        ip.v6 == self.v6 && ip.truncated(self.len) == self
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.v6 {
            write!(f, "{}", Ipv6Addr::from(self.bits))?;
        } else {
            write!(f, "{}", Ipv4Addr::from(self.bits as u32))?;
        }
        if self.len < self.width() {
            write!(f, "/{}", self.len)?;
        }
        Ok(())
    }
}

/// How long an element stays: `None` for ever, otherwise seconds from
/// when the script is loaded.
type Lifetime = Option<u64>;

/// Whether something that lasts `a` covers everything that lasts `b`.
fn lasts_as_long(a: Lifetime, b: Lifetime) -> bool {
    match (a, b) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(a), Some(b)) => a >= b,
    }
}

/// What is left of `rule`'s life at `now`, or `None` if it has already
/// ended and must not be rendered at all.
///
/// At least one second, never zero: `timeout 0s` means *no* timeout to
/// nft, which would turn a block about to lapse into a permanent one.
fn remaining(rule: &FirewallRule, now: i64) -> Option<Lifetime> {
    match rule.expires_at {
        None => Some(None),
        Some(at) if at <= now => None,
        Some(at) => Some(Some(u64::try_from(at - now).unwrap_or(1).max(1))),
    }
}

/// `1d2h3m4s`, the form nft prints. nftables 1.0.9 refused ten years
/// written as plain seconds ("value too large") and accepted the same
/// span written as `3650d`, which is the longest block a detector can ask
/// for.
fn nft_duration(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, secs) = (rest / 60, rest % 60);
    let mut out = String::new();
    for (value, unit) in [(days, 'd'), (hours, 'h'), (minutes, 'm'), (secs, 's')] {
        if value > 0 {
            out.push_str(&format!("{value}{unit}"));
        }
    }
    out
}

/// One element of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Element {
    prefix: Prefix,
    lifetime: Lifetime,
}

/// A run of rules that can be matched as one: same verdict, same port.
/// See "Sets, not one rule per address" in the module docs.
struct Stage {
    action: FirewallAction,
    port: Option<u16>,
    elements: Vec<Element>,
}

/// One named set and the rule that matches it.
struct NamedSet {
    name: String,
    v6: bool,
    action: FirewallAction,
    port: Option<u16>,
    elements: Vec<Element>,
}

impl NamedSet {
    fn has_timeouts(&self) -> bool {
        self.elements.iter().any(|e| e.lifetime.is_some())
    }
}

/// What a render puts in the kernel, before it is spelled as text.
struct Plan {
    /// In the order their rules are evaluated.
    sets: Vec<NamedSet>,
    /// Addresses that are not addresses, left out and named in a comment.
    skipped: Vec<String>,
}

impl Plan {
    fn new(rules: &[FirewallRule], now: i64) -> Plan {
        let mut stages: Vec<Stage> = Vec::new();
        let mut skipped = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            // Defence in depth. `Db` refuses to store an address this would
            // reject, so reaching here means a row predating that check (or
            // a database edited by hand). The script is executable input,
            // so an address that isn't one is dropped rather than
            // interpolated.
            let prefix = crate::db::is_valid_address(&rule.address)
                .then(|| Prefix::parse(rule.address.trim()))
                .flatten();
            let Some(prefix) = prefix else {
                skipped.push(rule.address.clone());
                continue;
            };
            let Some(lifetime) = remaining(rule, now) else {
                continue;
            };
            let element = Element { prefix, lifetime };

            // The latest stage this rule can join without changing any
            // verdict: walking back, every stage passed must share its
            // verdict, and the one it joins must share its port too.
            let joinable = stages
                .iter()
                .rev()
                .take_while(|stage| stage.action == rule.action)
                .position(|stage| stage.port == rule.port)
                .map(|from_end| stages.len() - 1 - from_end);
            match joinable {
                Some(index) => stages[index].elements.push(element),
                None => stages.push(Stage {
                    action: rule.action,
                    port: rule.port,
                    elements: vec![element],
                }),
            }
        }

        let mut seen: HashMap<(&str, Option<u16>), usize> = HashMap::new();
        let mut sets = Vec::new();
        for stage in stages {
            let ordinal = seen
                .entry((set_word(stage.action), stage.port))
                .or_insert(0);
            *ordinal += 1;
            for v6 in [false, true] {
                let family: Vec<Element> = stage
                    .elements
                    .iter()
                    .copied()
                    .filter(|e| e.prefix.v6 == v6)
                    .collect();
                for (depth, elements) in layers(&family).into_iter().enumerate() {
                    let mut name = set_word(stage.action).to_string();
                    if let Some(port) = stage.port {
                        name.push_str(&format!("_tcp{port}"));
                    }
                    name.push_str(if v6 { "_v6" } else { "_v4" });
                    if *ordinal > 1 {
                        name.push_str(&format!("_{ordinal}"));
                    }
                    if depth > 0 {
                        name.push_str(&format!("_n{depth}"));
                    }
                    sets.push(NamedSet {
                        name,
                        v6,
                        action: stage.action,
                        port: stage.port,
                        elements,
                    });
                }
            }
        }
        Plan { sets, skipped }
    }

    /// How many elements the kernel will hold.
    fn elements(&self) -> usize {
        self.sets.iter().map(|s| s.elements.len()).sum()
    }
}

/// The elements of one stage and family, as sets that each hold no two
/// overlapping elements — see "Why not `auto-merge`" in the module docs.
///
/// Layer 0 is every element that is not inside another; layer 1, those
/// inside exactly one; and so on. Order within a layer follows the input,
/// so the script reads in the order the rules were given.
fn layers(elements: &[Element]) -> Vec<Vec<Element>> {
    // The longest life asked of each distinct element.
    let mut longest: HashMap<Prefix, Lifetime> = HashMap::new();
    for e in elements {
        longest
            .entry(e.prefix)
            .and_modify(|l| {
                if lasts_as_long(e.lifetime, *l) {
                    *l = e.lifetime;
                }
            })
            .or_insert(e.lifetime);
    }
    let mut lengths: Vec<u8> = longest.keys().map(|p| p.len).collect();
    lengths.sort_unstable();
    lengths.dedup();

    // Every strictly larger range in the set that contains `p`.
    let (longest_ref, lengths_ref) = (&longest, &lengths);
    let containers = move |p: Prefix| {
        lengths_ref
            .iter()
            .take_while(move |&&len| len < p.len)
            .map(move |&len| p.truncated(len))
            .filter_map(move |outer| longest_ref.get(&outer).map(|&l| (outer, l)))
    };
    let kept: HashSet<Prefix> = longest
        .iter()
        .filter(|&(&p, &l)| !containers(p).any(|(_, outer)| lasts_as_long(outer, l)))
        .map(|(&p, _)| p)
        .collect();

    let mut out: Vec<Vec<Element>> = Vec::new();
    let mut written = HashSet::new();
    for e in elements {
        if !kept.contains(&e.prefix) || !written.insert(e.prefix) {
            continue;
        }
        let depth = containers(e.prefix)
            .filter(|(outer, _)| kept.contains(outer))
            .count();
        if out.len() <= depth {
            out.resize_with(depth + 1, Vec::new);
        }
        out[depth].push(Element {
            prefix: e.prefix,
            lifetime: longest[&e.prefix],
        });
    }
    out
}

/// How many entries a render of `rules` at `now` puts in the kernel: set
/// elements, once overlaps are resolved. What `health` expects to find
/// loaded, and what "wrote N rule(s)" reports.
pub fn loaded_entries(rules: &[FirewallRule], now: i64) -> usize {
    Plan::new(rules, now).elements()
}

/// Renders `rules` (skipping disabled and already-expired ones) into an
/// idempotent `nft` script, as of `now` (Unix seconds), which is what
/// each timed element's `timeout` counts from.
///
/// Ports are rendered as `tcp dport <port>`; there's no protocol field on
/// [`FirewallRule`] yet, so UDP-specific rules aren't representable (see
/// TODO.md).
pub fn render(rules: &[FirewallRule], now: i64) -> String {
    let plan = Plan::new(rules, now);

    let mut out = String::new();
    out.push_str("#!/usr/sbin/nft -f\n");
    out.push_str(&format!(
        "# {}. Not executed automatically — review, then run\n",
        crate::generated::generated_by()
    ));
    out.push_str("# with: nft -f <this file>\n");
    out.push_str("#\n");
    out.push_str("# Only touches our own \"inet stop_bots\" table (no `flush ruleset`) and\n");
    out.push_str("# uses \"policy accept\" so these chains can't become an implicit\n");
    out.push_str("# default-deny for traffic to the host or between containers.\n");
    out.push_str("#\n");
    out.push_str("# Two hooks: \"input\" for services on this host, \"forward\" for ones in\n");
    out.push_str("# containers, whose traffic is DNAT'd past \"input\" entirely.\n");
    out.push_str("#\n");
    out.push_str("# Addresses are in sets, matched first to last by the rules in bot_rules.\n");
    out.push_str("# An element with a timeout is removed by the kernel when it runs out.\n\n");

    // Reset just our own table to a fresh, empty state (see module docs for
    // why this is the idempotent idiom rather than `flush chain`).
    out.push_str(&format!("add table {TABLE}\n"));
    out.push_str(&format!("delete table {TABLE}\n"));
    out.push_str(&format!("add table {TABLE}\n"));
    out.push_str(&format!(
        "add chain {TABLE} {CHAIN} {{ type filter hook input priority -1; policy accept; }}\n"
    ));
    out.push_str(&format!(
        "add chain {TABLE} {FORWARD_CHAIN} {{ type filter hook forward priority -1; policy accept; }}\n"
    ));
    // No hook and no policy: reached only by the jumps below, so a packet
    // that falls off the end of it simply returns to whichever base chain
    // sent it.
    out.push_str(&format!("add chain {TABLE} {RULES_CHAIN}\n\n"));

    out.push_str(&format!(
        "add rule {TABLE} {CHAIN} ct state established,related accept\n"
    ));
    out.push_str(&format!("add rule {TABLE} {CHAIN} iif lo accept\n"));
    out.push_str(&format!("add rule {TABLE} {CHAIN} jump {RULES_CHAIN}\n"));

    // The same short-circuit on the forward path. `iif lo` has no meaning
    // here — a forwarded packet never arrives on the loopback interface —
    // so it is not repeated.
    out.push_str(&format!(
        "add rule {TABLE} {FORWARD_CHAIN} ct state established,related accept\n"
    ));

    // Everything from a private address passes, and this is load-bearing
    // rather than tidy.
    //
    // The forward hook carries traffic this project has no opinion about:
    // a container reaching the internet, one container reaching another,
    // the host reaching either. Their source addresses are RFC1918 or
    // unique-local — precisely what `ipranges::is_local_or_private` calls
    // "necessarily either this host talking to itself or a client on the
    // same private network, not an internet scanner", and what this tool
    // therefore never blocks on purpose.
    //
    // It can block them by accident, though, and the allowlist case shows
    // how: geo allowlist mode renders a trailing `0.0.0.0/0 drop`, and
    // reaching that from the forward hook would drop every packet a
    // container sent anywhere, the moment the script was applied. The same
    // goes for an operator who blocks a private range meaning "keep it off
    // this host". Inbound traffic is unaffected: a packet DNAT'd to a
    // published port still carries the remote client's address as its
    // source, so the rules below still see it.
    //
    // The input chain gets the same protection a different way:
    // `firewall::private_allow_rules` puts these ranges in the rules
    // themselves, after the admin's own and before the derived ones. A
    // container reaching a service on its own host arrives on *input*, and
    // an accept at the top of this chain would work too — but it would
    // also silence an operator who blocks a private range on purpose,
    // which the forward path has no reason to honour and this one does.
    out.push_str(&format!(
        "add rule {TABLE} {FORWARD_CHAIN} ip saddr {{ {PRIVATE_V4} }} accept\n"
    ));
    out.push_str(&format!(
        "add rule {TABLE} {FORWARD_CHAIN} ip6 saddr {{ {PRIVATE_V6} }} accept\n"
    ));

    out.push_str(&format!(
        "add rule {TABLE} {FORWARD_CHAIN} jump {RULES_CHAIN}\n"
    ));

    if !plan.skipped.is_empty() {
        out.push('\n');
    }
    for address in &plan.skipped {
        // `{:?}`, not `{}`: an unvalidated address can contain a newline,
        // which would end the comment and make the remainder of it a
        // statement.
        out.push_str(&format!(
            "# skipped (not an IP address or CIDR range): {address:?}\n"
        ));
    }
    if plan.sets.is_empty() {
        return out;
    }

    // Declared empty, then matched, then filled: all one transaction, so
    // the order is for the reader — the policy at the top of the file, the
    // bulk of it at the bottom.
    out.push('\n');
    for set in &plan.sets {
        let kind = if set.v6 { "ipv6_addr" } else { "ipv4_addr" };
        let flags = if set.has_timeouts() {
            "interval, timeout"
        } else {
            "interval"
        };
        out.push_str(&format!(
            "add set {TABLE} {} {{ type {kind}; flags {flags}; }}\n",
            set.name
        ));
    }
    out.push('\n');
    for set in &plan.sets {
        let family = if set.v6 { "ip6" } else { "ip" };
        out.push_str(&format!(
            "add rule {TABLE} {RULES_CHAIN} {family} saddr @{}",
            set.name
        ));
        if let Some(port) = set.port {
            out.push_str(&format!(" tcp dport {port}"));
        }
        out.push_str(&format!(" {}\n", action_word(set.action)));
    }
    for set in &plan.sets {
        out.push_str(&format!("\nadd element {TABLE} {} {{\n", set.name));
        let last = set.elements.len() - 1;
        for (i, element) in set.elements.iter().enumerate() {
            out.push('\t');
            out.push_str(&element.prefix.to_string());
            if let Some(seconds) = element.lifetime {
                out.push_str(&format!(" timeout {}", nft_duration(seconds)));
            }
            out.push_str(if i == last { "\n" } else { ",\n" });
        }
        out.push_str("}\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewFirewallRule;
    use crate::testing::{allow, block, block_port, block_until, disabled, rule};
    use serde::Deserialize;

    /// Any fixed moment will do: every timeout is relative to it.
    const NOW: i64 = 1_800_000_000;

    /// The forward chain's literal set and the input path's synthetic
    /// Allows (`firewall::PRIVATE_RANGES`) must protect the same sources,
    /// or the two hooks disagree about what "private" means.
    #[test]
    fn the_forward_chain_and_the_rules_agree_on_what_is_private() {
        let literal: Vec<&str> = PRIVATE_V4
            .split(", ")
            .chain(PRIVATE_V6.split(", "))
            .collect();
        assert_eq!(literal, crate::firewall::PRIVATE_RANGES);
    }

    #[derive(Deserialize)]
    struct JsonRule {
        address: String,
        port: Option<u16>,
        action: String,
        enabled: bool,
    }

    fn rules_from_fixture(json: &str) -> Vec<FirewallRule> {
        let raw: Vec<JsonRule> = serde_json::from_str(json).unwrap();
        raw.into_iter()
            .enumerate()
            .map(|(i, r)| FirewallRule {
                id: i as i64,
                address: r.address,
                port: r.port,
                action: FirewallAction::parse(&r.action).unwrap(),
                enabled: r.enabled,
                expires_at: None,
                source: None,
                created_at: None,
                evidence: None,
            })
            .collect()
    }

    const RULES_JSON: &str = include_str!("../tests/fixtures/nftables/rules.json");

    /// The rule in `bot_rules` that decides `element`, found through the
    /// set the element is in: `ip saddr @block_v4 drop`, without the
    /// `add rule inet stop_bots bot_rules` in front. `element` is written
    /// the way the script writes it, timeout and all if it has one.
    fn rule_for(script: &str, element: &str) -> Option<String> {
        let mut set = None;
        for line in script.lines() {
            if let Some(rest) = line.strip_prefix(&format!("add element {TABLE} ")) {
                set = rest.split(' ').next();
            } else if line.starts_with('\t') && line.trim().trim_end_matches(',') == element {
                let set = set?;
                let prefix = format!("add rule {TABLE} {RULES_CHAIN} ");
                return script
                    .lines()
                    .filter_map(|l| l.strip_prefix(&prefix))
                    .find(|l| l.contains(&format!("@{set} ")))
                    .map(str::to_string);
            }
        }
        None
    }

    /// Where the rule deciding `element` sits among the rules: lower is
    /// evaluated first.
    fn position_of(script: &str, element: &str) -> usize {
        let rule = rule_for(script, element)
            .unwrap_or_else(|| panic!("no rule decides {element}:\n{script}"));
        script
            .lines()
            .position(|l| l.ends_with(&rule) && l.starts_with("add rule"))
            .unwrap()
    }

    #[test]
    fn render_never_flushes_the_whole_ruleset_or_drops_by_default() {
        let rendered = render(&[], NOW);
        // Check actual statement lines, not the explanatory comment above
        // them (which mentions "flush ruleset" as the thing being avoided).
        let statements: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect();
        assert!(!statements.iter().any(|line| line.trim() == "flush ruleset"));
        assert!(!statements.iter().any(|line| line.contains("policy drop")));
        assert!(
            rendered.contains("policy accept"),
            "rendered was:\n{rendered}"
        );
    }

    #[test]
    fn render_empty_rules_still_sets_up_table_and_chain() {
        let rendered = render(&[], NOW);
        assert!(rendered.contains(&format!("add table {TABLE}")));
        assert!(rendered.contains(&format!("delete table {TABLE}")));
        assert!(rendered.contains(&format!("add chain {TABLE} {CHAIN}")));
        assert!(
            rendered.contains("ct state established,related accept"),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("iif lo accept"),
            "rendered was:\n{rendered}"
        );
        // Not `!contains("saddr")` any more: the forward chain's
        // private-source guard is structure, not a rule, and uses `saddr`
        // too. What must be absent is anything in the rules chain.
        assert!(
            !rendered.contains(&format!("add rule {TABLE} {RULES_CHAIN}")),
            "rendered was:\n{rendered}"
        );
        assert!(!rendered.contains("add set"), "rendered was:\n{rendered}");
    }

    #[test]
    fn render_resets_only_its_own_table_for_idempotency() {
        let rendered = render(&[], NOW);
        // `add table` (no-op if it exists) then `delete table` (now
        // guaranteed to exist) then `add table` again leaves a fresh, empty
        // table scoped to just "inet stop_bots" — safe to re-run, and never
        // a `flush ruleset` or a delete of a possibly-nonexistent table.
        let add_count = rendered.matches(&format!("add table {TABLE}")).count();
        assert_eq!(add_count, 2);
        assert_eq!(
            rendered.matches(&format!("delete table {TABLE}")).count(),
            1
        );
    }

    #[test]
    fn render_matches_fixture_rule_lines_from_json_input() {
        let rendered = render(&rules_from_fixture(RULES_JSON), NOW);

        // A table, so the cases read as a list of "this input shape
        // produces this rule" rather than as six near-identical asserts —
        // and so a failure names which shape broke and prints the script.
        let expected = [
            ("a bare IPv4 address", "1.2.3.4", "ip saddr @block_v4 drop"),
            ("an IPv4 CIDR", "5.6.7.0/24", "ip saddr @block_v4 drop"),
            (
                "IPv4 with a port",
                "8.9.10.11",
                "ip saddr @block_tcp80_v4 tcp dport 80 drop",
            ),
            (
                "the Reject action",
                "12.13.14.15",
                "ip saddr @reject_v4 reject",
            ),
            (
                "the Allow action",
                "66.249.64.0/19",
                "ip saddr @allow_v4 accept",
            ),
            (
                "IPv6 with a port",
                "2001:db8::1",
                "ip6 saddr @block_tcp443_v6 tcp dport 443 drop",
            ),
        ];
        for (shape, element, rule) in expected {
            assert_eq!(
                rule_for(&rendered, element).as_deref(),
                Some(rule),
                "{shape} should be decided by {rule:?}, but the script was:\n{rendered}"
            );
        }
    }

    /// The point of the change. A chain is walked rule by rule, so a
    /// thousand blocks used to be a thousand rules every new connection
    /// passed through; now they are one rule and one set lookup.
    #[test]
    fn a_thousand_blocks_are_one_rule_and_one_set() {
        let rules: Vec<FirewallRule> = (0..1_000)
            .map(|n| block(&format!("198.51.{}.{}", n / 250, n % 250)))
            .collect();

        let rendered = render(&rules, NOW);

        let in_chain: Vec<&str> = rendered
            .lines()
            .filter(|l| l.starts_with(&format!("add rule {TABLE} {RULES_CHAIN}")))
            .collect();
        assert_eq!(
            in_chain,
            vec![format!(
                "add rule {TABLE} {RULES_CHAIN} ip saddr @block_v4 drop"
            )],
            "rendered was:\n{rendered}"
        );
        assert_eq!(loaded_entries(&rules, NOW), 1_000);
    }

    /// The reason this backend has two base chains at all.
    ///
    /// A host that publishes a container port sees the traffic for it on
    /// `forward`, never on `input`, so an `input`-only ruleset enforces
    /// nothing for anything containerised. The failure is silent, which is
    /// why it is pinned by a test rather than left to the golden: a golden
    /// that someone regenerates without reading takes the property with it.
    #[test]
    fn both_hooks_are_covered_so_container_traffic_cannot_slip_past() {
        let rendered = render(&[block("1.2.3.4")], NOW);

        for (hook, chain) in [("input", CHAIN), ("forward", FORWARD_CHAIN)] {
            let decl = format!(
                "add chain {TABLE} {chain} {{ type filter hook {hook} priority -1; policy accept; }}"
            );
            assert!(
                rendered.contains(&decl),
                "the {hook} hook should be covered by {decl:?}, but the script was:\n{rendered}"
            );
            assert!(
                rendered.contains(&format!("add rule {TABLE} {chain} jump {RULES_CHAIN}")),
                "{chain} should reach the rules, but the script was:\n{rendered}"
            );
        }
    }

    /// One copy of the rules, not two.
    ///
    /// Rendering each rule into both base chains would enforce the same
    /// thing today and drift the first time someone edits one loop, so the
    /// set is matched from the jumped-to chain and nowhere else.
    #[test]
    fn a_rule_is_rendered_once_into_the_shared_chain() {
        let rendered = render(&[block("1.2.3.4")], NOW);
        assert_eq!(
            rendered.matches("1.2.3.4").count(),
            1,
            "the address should appear exactly once, but the script was:\n{rendered}"
        );
        assert_eq!(
            rendered.matches("@block_v4").count(),
            1,
            "the set should be matched exactly once, but the script was:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "add rule {TABLE} {RULES_CHAIN} ip saddr @block_v4 drop"
            )),
            "the rule belongs in {RULES_CHAIN}, but the script was:\n{rendered}"
        );
    }

    /// `policy accept` on `forward` is load-bearing in a way the `input`
    /// one is not: a `policy drop` there would cut every container on the
    /// host off from the network the moment the script ran.
    #[test]
    fn the_forward_chain_never_becomes_a_default_deny() {
        let rendered = render(&[], NOW);
        let forward_decl = rendered
            .lines()
            .find(|line| line.contains(FORWARD_CHAIN) && line.contains("hook forward"))
            .expect("the forward chain should be declared");
        assert!(
            forward_decl.contains("policy accept"),
            "the forward chain must not default-deny, but it was:\n{forward_decl}"
        );
    }

    #[test]
    fn render_skips_disabled_rules() {
        let mut rules = rules_from_fixture(RULES_JSON);
        rules[0].enabled = false;
        let rendered = render(&rules, NOW);
        assert!(!rendered.contains(&rules[0].address));
    }

    #[test]
    fn render_uses_ip6_saddr_for_ipv6_and_ip_saddr_for_ipv4() {
        let rules = vec![block("2001:db8:85a3::8a2e:370:7334/64"), block("10.0.0.1")];
        let rendered = render(&rules, NOW);
        // The host bits go: the kernel stores the /64 either way, and
        // spelling it as stored is what lets two spellings of one range
        // be recognised as the same element.
        assert_eq!(
            rule_for(&rendered, "2001:db8:85a3::/64").as_deref(),
            Some("ip6 saddr @block_v6 drop"),
            "rendered was:\n{rendered}"
        );
        assert_eq!(
            rule_for(&rendered, "10.0.0.1").as_deref(),
            Some("ip saddr @block_v4 drop"),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("add set inet stop_bots block_v6 { type ipv6_addr;"),
            "rendered was:\n{rendered}"
        );
    }

    #[test]
    fn add_firewall_rule_then_render_round_trips() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.add_firewall_rule(&NewFirewallRule {
            address: "203.0.113.7".to_string(),
            port: Some(443),
            action: FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        let rules = db.list_firewall_rules().unwrap();
        let rendered = render(&rules, NOW);
        assert_eq!(
            rule_for(&rendered, "203.0.113.7").as_deref(),
            Some("ip saddr @block_tcp443_v4 tcp dport 443 drop"),
            "rendered was:\n{rendered}"
        );
    }

    // ---- first match still wins ----

    /// The property the SSH guard and trusted addresses rest on: an Allow
    /// given first is evaluated first, even though a later Block covers
    /// the same address.
    #[test]
    fn an_allow_given_first_is_still_matched_first() {
        let rendered = render(&[allow("203.0.113.7"), block("203.0.113.0/24")], NOW);

        assert!(
            position_of(&rendered, "203.0.113.7") < position_of(&rendered, "203.0.113.0/24"),
            "the Allow must be matched before the Block:\n{rendered}"
        );
    }

    /// And the other way round, which is what keeps an operator's own
    /// block of a private range ahead of the private-range Allows.
    #[test]
    fn a_block_given_first_is_still_matched_first() {
        let rendered = render(&[block("10.0.5.0/24"), allow("10.0.0.0/8")], NOW);

        assert!(
            position_of(&rendered, "10.0.5.0/24") < position_of(&rendered, "10.0.0.0/8"),
            "the Block must be matched before the Allow:\n{rendered}"
        );
    }

    /// A Block after an Allow cannot join the Blocks before that Allow —
    /// it would jump the queue — so it gets a set of its own, after it.
    #[test]
    fn a_block_after_an_allow_gets_a_second_set_after_the_allow() {
        let rendered = render(
            &[
                block("198.51.100.1"),
                allow("203.0.113.0/24"),
                block("203.0.113.9"),
            ],
            NOW,
        );

        assert_eq!(
            rule_for(&rendered, "203.0.113.9").as_deref(),
            Some("ip saddr @block_v4_2 drop"),
            "rendered was:\n{rendered}"
        );
        assert!(
            position_of(&rendered, "203.0.113.0/24") < position_of(&rendered, "203.0.113.9"),
            "rendered was:\n{rendered}"
        );
    }

    /// Two Blocks agree whichever is asked first, so a Block may pass
    /// another Block to join an earlier set: a port-scoped rule between
    /// two of them does not split them into two sets.
    #[test]
    fn a_block_can_pass_another_block_to_join_the_first_set() {
        let rendered = render(
            &[
                block("198.51.100.1"),
                block_port("192.0.2.9", 22),
                block("198.51.100.2"),
            ],
            NOW,
        );

        assert_eq!(
            rule_for(&rendered, "198.51.100.2").as_deref(),
            Some("ip saddr @block_v4 drop"),
            "rendered was:\n{rendered}"
        );
        assert!(
            !rendered.contains("block_v4_2"),
            "rendered was:\n{rendered}"
        );
    }

    /// Allowlist geo mode's shape: explicit Allows followed by the v4 and
    /// v6 catch-alls, which must stay last.
    #[test]
    fn the_allowlist_catch_alls_are_matched_last() {
        let rendered = render(
            &[allow("203.0.113.0/24"), block("0.0.0.0/0"), block("::/0")],
            NOW,
        );

        let last = rendered
            .lines()
            .rfind(|l| l.starts_with("add rule"))
            .unwrap();
        assert!(last.ends_with("ip6 saddr @block_v6 drop"), "{rendered}");
        assert!(
            position_of(&rendered, "203.0.113.0/24") < position_of(&rendered, "0.0.0.0/0"),
            "{rendered}"
        );
    }

    /// The whole ordering argument, checked rather than reasoned: for a
    /// few thousand generated rule lists full of overlaps, ports, all
    /// three verdicts and timeouts, every address gets the verdict a plain
    /// first-match walk of the rule list gives it — now, and at each
    /// moment a timeout runs out.
    #[test]
    fn the_sets_decide_every_address_the_way_the_rule_list_does() {
        // A fixed LCG: the same cases every run, no dependency.
        let mut seed = 0x5eed_u64;
        let mut next = move |n: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        let probes: Vec<IpAddr> = (0..16)
            .map(|n| format!("203.0.113.{}", n * 16 + 3).parse().unwrap())
            .chain([
                "2001:db8::1".parse().unwrap(),
                "2001:db8:0:1::1".parse().unwrap(),
            ])
            .collect();

        for case in 0..300 {
            let rules: Vec<FirewallRule> = (0..1 + next(12))
                .map(|_| {
                    let address = match next(7) {
                        0 => "0.0.0.0/0".to_string(),
                        1 => "203.0.113.0/24".to_string(),
                        2 => format!("203.0.113.{}/28", next(16) * 16),
                        3 => "2001:db8::/32".to_string(),
                        4 => "2001:db8::/64".to_string(),
                        _ => format!("203.0.113.{}", next(16) * 16 + 3),
                    };
                    let action = [
                        FirewallAction::Allow,
                        FirewallAction::Block,
                        FirewallAction::Reject,
                    ][next(3) as usize];
                    FirewallRule {
                        port: [None, None, Some(22)][next(3) as usize],
                        expires_at: [None, Some(NOW + 60), Some(NOW + 120)][next(3) as usize],
                        ..rule(&address, action)
                    }
                })
                .collect();
            let plan = Plan::new(&rules, NOW);

            for set in &plan.sets {
                for (i, a) in set.elements.iter().enumerate() {
                    for b in &set.elements[i + 1..] {
                        let (outer, inner) = if a.prefix.len <= b.prefix.len {
                            (a.prefix, b.prefix)
                        } else {
                            (b.prefix, a.prefix)
                        };
                        assert_ne!(
                            inner.truncated(outer.len),
                            outer,
                            "case {case}: {outer} and {inner} overlap in {}; nft refuses that",
                            set.name
                        );
                    }
                }
            }

            for elapsed in [0, 60, 120] {
                for &ip in &probes {
                    for port in [22, 80] {
                        let alive = |l: Lifetime| l.is_none_or(|l| l > elapsed);
                        let expected = rules
                            .iter()
                            .find(|r| {
                                alive(remaining(r, NOW).unwrap())
                                    && r.port.is_none_or(|p| p == port)
                                    && Prefix::parse(&r.address).unwrap().contains(ip)
                            })
                            .map(|r| r.action);
                        let actual = plan
                            .sets
                            .iter()
                            .find(|set| {
                                set.port.is_none_or(|p| p == port)
                                    && set
                                        .elements
                                        .iter()
                                        .any(|e| alive(e.lifetime) && e.prefix.contains(ip))
                            })
                            .map(|set| set.action);
                        assert_eq!(
                            actual, expected,
                            "case {case}: {ip} port {port}, {elapsed}s in, rules:\n{rules:#?}"
                        );
                    }
                }
            }
        }
    }

    // ---- expiry in the kernel ----

    /// A timed rule becomes a timed element, lasting what it has left,
    /// in a set that allows timeouts.
    #[test]
    fn a_timed_rule_becomes_an_element_with_its_remaining_time() {
        let rendered = render(&[block_until("203.0.113.9", NOW + 90_061)], NOW);

        assert!(
            rendered.contains("\t203.0.113.9 timeout 1d1h1m1s\n"),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains(
                "add set inet stop_bots block_v4 { type ipv4_addr; flags interval, timeout; }"
            ),
            "rendered was:\n{rendered}"
        );
    }

    /// A set with nothing timed in it is declared the way it always was.
    #[test]
    fn a_set_without_timed_elements_does_not_ask_for_timeouts() {
        let rendered = render(&[block("203.0.113.9")], NOW);
        assert!(
            rendered
                .contains("add set inet stop_bots block_v4 { type ipv4_addr; flags interval; }"),
            "rendered was:\n{rendered}"
        );
    }

    /// Rendered from a snapshot taken before it lapsed, a block that has
    /// already expired is left out rather than given a timeout of zero —
    /// which nft reads as no timeout at all.
    #[test]
    fn an_expired_rule_is_left_out() {
        let rules = [
            block_until("203.0.113.9", NOW),
            block_until("203.0.113.10", NOW - 60),
        ];
        let rendered = render(&rules, NOW);

        assert!(
            !rendered.contains("203.0.113."),
            "rendered was:\n{rendered}"
        );
        assert_eq!(loaded_entries(&rules, NOW), 0);
    }

    #[test]
    fn durations_are_spelled_the_way_nft_prints_them() {
        for (seconds, spelled) in [
            (1, "1s"),
            (60, "1m"),
            (3_600, "1h"),
            (86_400, "1d"),
            (86_400 * 3_650, "3650d"),
            (90_061, "1d1h1m1s"),
        ] {
            assert_eq!(nft_duration(seconds), spelled);
        }
    }

    // ---- overlapping elements ----

    /// An interval set refuses overlapping elements. An address inside a
    /// range with the same verdict, which lasts at least as long, adds
    /// nothing and is left out.
    #[test]
    fn an_address_inside_a_range_that_outlasts_it_is_left_out() {
        let rules = [
            block("203.0.113.0/24"),
            block_until("203.0.113.9", NOW + 60),
        ];
        let rendered = render(&rules, NOW);

        assert!(
            !rendered.contains("203.0.113.9"),
            "rendered was:\n{rendered}"
        );
        assert_eq!(loaded_entries(&rules, NOW), 1);
    }

    /// The case `auto-merge` gets wrong: a permanent block inside a range
    /// that lapses in a minute. It is kept, in a second set, so it
    /// outlives the range.
    #[test]
    fn an_address_that_outlasts_the_range_around_it_gets_a_set_of_its_own() {
        let rules = [
            block_until("203.0.113.0/24", NOW + 60),
            block("203.0.113.9"),
        ];
        let rendered = render(&rules, NOW);

        assert_eq!(
            rule_for(&rendered, "203.0.113.0/24 timeout 1m").as_deref(),
            Some("ip saddr @block_v4 drop"),
            "rendered was:\n{rendered}"
        );
        assert_eq!(
            rule_for(&rendered, "203.0.113.9").as_deref(),
            Some("ip saddr @block_v4_n1 drop"),
            "rendered was:\n{rendered}"
        );
    }

    /// The same address given twice — a detector's block and a manual one
    /// — is one element, lasting as long as the longer of the two.
    #[test]
    fn a_repeated_address_is_one_element_with_the_longer_life() {
        let rules = [
            block_until("203.0.113.9", NOW + 60),
            block("203.0.113.9"),
            block("203.0.113.9/32"),
        ];
        let rendered = render(&rules, NOW);

        assert_eq!(
            rendered.matches("203.0.113.9").count(),
            1,
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("\t203.0.113.9\n"),
            "the permanent one should win:\n{rendered}"
        );
    }

    /// A representative rule set, locked byte-for-byte. The golden file is
    /// also the exact script to hand to `nft -c -f` on a machine that has
    /// it — see `crate::golden`.
    #[test]
    fn rendered_script_matches_the_golden() {
        let rules = vec![
            allow("203.0.113.7"),
            block("198.51.100.0/24"),
            block_port("192.0.2.9", 22),
            block("2001:db8::/32"),
            // A detector's block, with a day and an hour left.
            block_until("192.0.2.77", NOW + 90_000),
            // Disabled: must leave no trace in the script.
            disabled("10.0.0.1"),
        ];
        crate::golden::assert_golden("firewall.nft", &render(&rules, NOW));
    }

    /// Allowlist geo mode's shape: explicit Allows followed by the v4 and
    /// v6 catch-alls, strictly last.
    #[test]
    fn rendered_allowlist_script_matches_the_golden() {
        let rules = vec![allow("203.0.113.0/24"), block("0.0.0.0/0"), block("::/0")];
        crate::golden::assert_golden("firewall-allowlist.nft", &render(&rules, NOW));
    }

    /// The database now refuses such a row, so this can only come from a
    /// database written before that check existed — but the script is
    /// executable input, and the cost of checking again here is nothing.
    #[test]
    fn render_skips_an_address_that_is_not_one_rather_than_emitting_it() {
        let rendered = render(&[block("1.2.3.4/24; touch /tmp/pwned")], NOW);

        let statements: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
            .collect();
        assert!(
            !statements.iter().any(|line| line.contains("touch")),
            "the payload reached a statement line:\n{rendered}"
        );
        assert!(
            rendered.contains("skipped (not an IP address or CIDR range)"),
            "rendered was:\n{rendered}"
        );
    }

    /// Validation trims, so an address with whitespace around it is valid
    /// — and must be rendered as what was validated. Untrimmed, a trailing
    /// newline split the rule across two lines, leaving a bare `drop`.
    #[test]
    fn an_address_is_rendered_trimmed() {
        let rendered = render(&[block(" 1.2.3.4\n")], NOW);

        assert!(
            rendered.contains("\t1.2.3.4\n"),
            "rendered was:\n{rendered}"
        );
    }

    /// A newline in the address would end the `#` comment the skip note is
    /// written as, making the rest of it a statement — so the note escapes.
    #[test]
    fn the_skip_note_cannot_be_escaped_with_a_newline() {
        let rendered = render(&[block("1.2.3.4\nflush ruleset")], NOW);

        let statements: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
            .collect();
        assert!(
            !statements.iter().any(|line| line.contains("flush")),
            "the payload escaped the comment:\n{rendered}"
        );
    }
}
