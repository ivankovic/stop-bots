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
//! This module never executes `nft` itself — applying the generated script
//! is a manual step for the admin. Like the rest of this module, the
//! delete-then-recreate idempotency idiom hasn't been checked against a
//! real `nft` (not installed in this environment) — see TODO.md.

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

fn is_ipv6(address: &str) -> bool {
    address.contains(':')
}

/// Renders `rules` (skipping disabled ones) into an idempotent `nft` script.
///
/// Ports are rendered as `tcp dport <port>`; there's no protocol field on
/// [`FirewallRule`] yet, so UDP-specific rules aren't representable (see
/// TODO.md).
pub fn render(rules: &[FirewallRule]) -> String {
    let mut out = String::new();
    out.push_str("#!/usr/sbin/nft -f\n");
    out.push_str("# Generated by stop-bots. Not executed automatically — review, then run\n");
    out.push_str("# with: nft -f <this file>\n");
    out.push_str("#\n");
    out.push_str("# Only touches our own \"inet stop_bots\" table (no `flush ruleset`) and\n");
    out.push_str("# uses \"policy accept\" so these chains can't become an implicit\n");
    out.push_str("# default-deny for traffic to the host or between containers.\n");
    out.push_str("#\n");
    out.push_str("# Two hooks: \"input\" for services on this host, \"forward\" for ones in\n");
    out.push_str("# containers, whose traffic is DNAT'd past \"input\" entirely.\n\n");

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

    let enabled: Vec<&FirewallRule> = rules.iter().filter(|r| r.enabled).collect();
    if !enabled.is_empty() {
        out.push('\n');
    }
    for rule in enabled {
        // Defence in depth. `Db` refuses to store an address this would
        // reject, so reaching here means a row predating that check (or a
        // database edited by hand). The script is executable input — `sh`
        // for this backend — so an address that isn't one is dropped rather
        // than interpolated. `{:?}` in the note, not `{}`: an unvalidated
        // address can contain a newline, which would end the comment and
        // make the remainder of it a command.
        if !crate::db::is_valid_address(&rule.address) {
            out.push_str(&format!(
                "# skipped (not an IP address or CIDR range): {:?}\n",
                rule.address
            ));
            continue;
        }
        // What was validated is the trimmed form, so that is what goes in
        // the script: a trailing newline would split the rule in two.
        let address = rule.address.trim();
        let family = if is_ipv6(address) { "ip6" } else { "ip" };
        out.push_str(&format!(
            "add rule {TABLE} {RULES_CHAIN} {family} saddr {address}"
        ));
        if let Some(port) = rule.port {
            out.push_str(&format!(" tcp dport {port}"));
        }
        out.push_str(&format!(" {}\n", action_word(rule.action)));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
    use crate::db::NewFirewallRule;
    use crate::testing::{allow, block, block_port, disabled};
    use serde::Deserialize;

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
            })
            .collect()
    }

    const RULES_JSON: &str = include_str!("../tests/fixtures/nftables/rules.json");

    #[test]
    fn render_never_flushes_the_whole_ruleset_or_drops_by_default() {
        let rendered = render(&[]);
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
        let rendered = render(&[]);
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
    }

    #[test]
    fn render_resets_only_its_own_table_for_idempotency() {
        let rendered = render(&[]);
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
        let rendered = render(&rules_from_fixture(RULES_JSON));

        // A table, so the cases read as a list of "this input shape
        // produces this line" rather than as six near-identical asserts —
        // and so a failure names which shape broke and prints the script,
        // instead of pointing at a line number and a bare `false`.
        let expected = [
            ("a bare IPv4 address", "ip saddr 1.2.3.4 drop"),
            ("an IPv4 CIDR", "ip saddr 5.6.7.0/24 drop"),
            ("IPv4 with a port", "ip saddr 8.9.10.11 tcp dport 80 drop"),
            ("the Reject action", "ip saddr 12.13.14.15 reject"),
            ("the Allow action", "ip saddr 66.249.64.0/19 accept"),
            (
                "IPv6 with a port",
                "ip6 saddr 2001:db8::1 tcp dport 443 drop",
            ),
        ];
        for (shape, line) in expected {
            let full = format!("add rule inet stop_bots {RULES_CHAIN} {line}");
            assert!(
                rendered.contains(&full),
                "{shape} should render as {full:?}, but the script was:\n{rendered}"
            );
        }
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
        let rendered = render(&[block("1.2.3.4")]);

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
    /// rules live in the jumped-to chain and nowhere else.
    #[test]
    fn a_rule_is_rendered_once_into_the_shared_chain() {
        let rendered = render(&[block("1.2.3.4")]);
        assert_eq!(
            rendered.matches("saddr 1.2.3.4").count(),
            1,
            "the rule should appear exactly once, but the script was:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "add rule {TABLE} {RULES_CHAIN} ip saddr 1.2.3.4 drop"
            )),
            "the rule belongs in {RULES_CHAIN}, but the script was:\n{rendered}"
        );
    }

    /// `policy accept` on `forward` is load-bearing in a way the `input`
    /// one is not: a `policy drop` there would cut every container on the
    /// host off from the network the moment the script ran.
    #[test]
    fn the_forward_chain_never_becomes_a_default_deny() {
        let rendered = render(&[]);
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
        let rendered = render(&rules);
        assert!(!rendered.contains(&rules[0].address));
    }

    #[test]
    fn render_uses_ip6_saddr_for_ipv6_and_ip_saddr_for_ipv4() {
        let rules = vec![block("2001:db8:85a3::8a2e:370:7334/64"), block("10.0.0.1")];
        let rendered = render(&rules);
        assert!(
            rendered.contains("ip6 saddr 2001:db8:85a3::8a2e:370:7334/64 drop"),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("ip saddr 10.0.0.1 drop"),
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
        })
        .unwrap();

        let rules = db.list_firewall_rules().unwrap();
        let rendered = render(&rules);
        assert!(
            rendered.contains("ip saddr 203.0.113.7 tcp dport 443 drop"),
            "rendered was:\n{rendered}"
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
            // Disabled: must leave no trace in the script.
            disabled("10.0.0.1"),
        ];
        crate::golden::assert_golden("firewall.nft", &render(&rules));
    }

    /// Allowlist geo mode's shape: explicit Allows followed by the v4 and
    /// v6 catch-alls, strictly last.
    #[test]
    fn rendered_allowlist_script_matches_the_golden() {
        let rules = vec![allow("203.0.113.0/24"), block("0.0.0.0/0"), block("::/0")];
        crate::golden::assert_golden("firewall-allowlist.nft", &render(&rules));
    }
    /// The database now refuses such a row, so this can only come from a
    /// database written before that check existed — but the script is
    /// executable input, and the cost of checking again here is nothing.
    #[test]
    fn render_skips_an_address_that_is_not_one_rather_than_emitting_it() {
        let rendered = render(&[block("1.2.3.4/24; touch /tmp/pwned")]);

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
        let rendered = render(&[block(" 1.2.3.4\n")]);

        assert!(
            rendered.contains(&format!(
                "add rule {TABLE} {RULES_CHAIN} ip saddr 1.2.3.4 drop\n"
            )),
            "rendered was:\n{rendered}"
        );
    }

    /// A newline in the address would end the `#` comment the skip note is
    /// written as, making the rest of it a statement — so the note escapes.
    #[test]
    fn the_skip_note_cannot_be_escaped_with_a_newline() {
        let rendered = render(&[block("1.2.3.4\nflush ruleset")]);

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
