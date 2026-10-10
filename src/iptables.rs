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

//! Renders [`FirewallRule`]s into a shell script that loads them with
//! `iptables-restore --noflush` and `ip6tables-restore --noflush`.
//!
//! Not a full `iptables-save` dump: restoring a whole `*filter` table
//! replaces it, including chain policies and any unrelated rules an admin
//! already has (e.g. their SSH allow rule). The fragment this renders
//! declares one chain, `STOP-BOTS`, and appends only to it. With
//! `--noflush`, declaring a chain that exists empties it, so the fragment
//! replaces our chain and nothing else, and it does so in one commit.
//!
//! ## Why a restore and not one `iptables -A` per rule
//!
//! The script used to flush `STOP-BOTS` and then run one `iptables -A`
//! process per rule. With tens of thousands of rules, the chain was empty,
//! then partly filled, for as long as those processes took to run, and a
//! failure part way through (under `set -e`) left it partly filled until
//! the next apply. A restore is checked in full before it changes anything
//! and is committed at once, so a failed apply leaves the previous chain as
//! it was. `-w` waits for the xtables lock instead of failing when another
//! tool holds it.
//!
//! The jumps into `STOP-BOTS` from `INPUT`, `FORWARD` and `DOCKER-USER`
//! stay as guarded shell commands after the restore: `-C` before `-I` is
//! the only idempotent way to add a rule to a chain we do not own, and a
//! restore has no equivalent of `-C`.
//!
//! No `ipset`. It would do for this backend what named sets do for
//! nftables, but it is a separate package that most hosts do not have, and
//! `iptables-restore` is in the `iptables` package itself.
//!
//! ## IPv6
//!
//! `iptables` is IPv4-only, and IPv6 rules used to be skipped, including
//! every /64 a detector writes. They now go to `ip6tables-restore`, into a
//! `STOP-BOTS` chain of the same shape in the IPv6 tables, with the same
//! jumps. On a host where `ip6tables` cannot be used (IPv6 disabled in the
//! kernel), the script says so and exits non-zero if there were IPv6
//! rules to load. The IPv4 half has been applied by then.
//!
//! ## Expiry
//!
//! iptables has no timeouts without `ipset`, so a rule that expires stays
//! in the chain until the script is rendered and applied again. A rule
//! already expired at render time is left out.
//!
//! ## Default-deny (allowlist) mode
//!
//! For allowlist geo-blocking (block everything except selected countries),
//! [`crate::db::geo_firewall_rules`] generates trailing `0.0.0.0/0` and
//! `::/0` Block rules. This backend is not offered for it: see
//! [`crate::firewall::build_script`]. The established/related and loopback
//! accepts at the top of each chain are here all the same, so a catch-all
//! Block an admin adds by hand cannot cut existing connections or local
//! traffic.

use crate::db::{FirewallAction, FirewallRule};

const CHAIN: &str = "STOP-BOTS";

fn action_word(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "ACCEPT",
        FirewallAction::Block => "DROP",
        FirewallAction::Reject => "REJECT",
    }
}

fn is_ipv6(address: &str) -> bool {
    address.contains(':')
}

/// What the rules turn into: one `-A` line per rule, split by family.
struct Plan {
    v4: Vec<String>,
    v6: Vec<String>,
    /// Addresses that are not addresses, left out and named in a comment.
    skipped: Vec<String>,
}

impl Plan {
    fn new(rules: &[FirewallRule], now: i64) -> Plan {
        let mut plan = Plan {
            v4: Vec::new(),
            v6: Vec::new(),
            skipped: Vec::new(),
        };
        for rule in rules.iter().filter(|r| r.enabled) {
            // Defence in depth. `Db` refuses to store an address this would
            // reject, so reaching here means a row predating that check (or
            // a database edited by hand). The script is executable input —
            // `sh` for this backend — so an address that isn't one is
            // dropped rather than interpolated.
            if !crate::db::is_valid_address(&rule.address) {
                plan.skipped.push(rule.address.clone());
                continue;
            }
            if rule.expires_at.is_some_and(|at| at <= now) {
                continue;
            }
            // What was validated is the trimmed form, so that is what goes
            // in the script: a trailing newline would end the line early
            // and make `-j DROP` a line of its own.
            let address = rule.address.trim();
            let mut line = format!("-A {CHAIN} -s {address}");
            if let Some(port) = rule.port {
                line.push_str(&format!(" -p tcp --dport {port}"));
            }
            line.push_str(&format!(" -j {}", action_word(rule.action)));
            if is_ipv6(address) {
                plan.v6.push(line);
            } else {
                plan.v4.push(line);
            }
        }
        plan
    }
}

/// How many rules a render of `rules` at `now` puts in the two chains,
/// IPv4 and IPv6 together. What `health` expects to find loaded, and
/// what "wrote N rule(s)" reports.
pub fn loaded_entries(rules: &[FirewallRule], now: i64) -> usize {
    let plan = Plan::new(rules, now);
    plan.v4.len() + plan.v6.len()
}

/// The restore fragment for one family: our chain, emptied and refilled.
///
/// The established/related and loopback accepts come first, before any
/// user rule, so that a catch-all Block cannot cut existing connections or
/// local traffic.
fn fragment(out: &mut String, restore: &str, delimiter: &str, lines: &[String]) {
    out.push_str(&format!("{restore} -w --noflush <<'{delimiter}'\n"));
    out.push_str("*filter\n");
    out.push_str(&format!(":{CHAIN} - [0:0]\n"));
    out.push_str(&format!(
        "-A {CHAIN} -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
    ));
    out.push_str(&format!("-A {CHAIN} -i lo -j ACCEPT\n"));
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("COMMIT\n");
    out.push_str(&format!("{delimiter}\n"));
}

/// The guarded jumps into our chain from the chains that see traffic,
/// indented by `indent`.
fn jumps(out: &mut String, tool: &str, indent: &str) {
    for chain in ["INPUT", "FORWARD"] {
        out.push_str(&format!(
            "{indent}if ! {tool} -w -C {chain} -j {CHAIN} 2>/dev/null; then\n"
        ));
        out.push_str(&format!("{indent}    {tool} -w -I {chain} -j {CHAIN}\n"));
        out.push_str(&format!("{indent}fi\n"));
    }

    // And again from `DOCKER-USER`, which exists only when Docker does.
    //
    // The `FORWARD` jump above is inserted at the top, so on its own it
    // would already run first. What it does not survive is another chain
    // reaching a verdict before it: Docker puts its own `-j DOCKER-USER`
    // at the head of `FORWARD` on every restart, and an `ACCEPT` an admin
    // has put in there is terminal for the whole `FORWARD` traversal. That
    // packet would then never reach our jump. `DOCKER-USER` is the hook
    // Docker documents for exactly this, so we take both: the rules are
    // idempotent and `DROP` is terminal, so being traversed twice costs a
    // second pass over a short chain and changes no verdict.
    out.push_str(&format!(
        "{indent}if {tool} -w -L DOCKER-USER -n >/dev/null 2>&1; then\n"
    ));
    out.push_str(&format!(
        "{indent}    if ! {tool} -w -C DOCKER-USER -j {CHAIN} 2>/dev/null; then\n"
    ));
    out.push_str(&format!(
        "{indent}        {tool} -w -I DOCKER-USER -j {CHAIN}\n"
    ));
    out.push_str(&format!("{indent}    fi\n"));
    out.push_str(&format!("{indent}fi\n"));
}

/// Renders `rules` (skipping disabled and already-expired ones, as of
/// `now` in Unix seconds) into an idempotent shell script: safe to run
/// repeatedly, and safe to run alongside any other firewall rules already
/// on the system.
///
/// Ports are rendered as `-p tcp --dport <port>` — there's no protocol
/// field on [`FirewallRule`] yet, so UDP-specific rules aren't
/// representable (see TODO.md).
pub fn render(rules: &[FirewallRule], now: i64) -> String {
    let plan = Plan::new(rules, now);

    let mut out = String::new();
    out.push_str("#!/bin/sh\n");
    out.push_str(&format!(
        "# {}. Not executed automatically — review, then run\n",
        crate::generated::generated_by()
    ));
    out.push_str("# with: sh <this file>\n");
    out.push_str("#\n");
    out.push_str(&format!(
        "# Replaces the {CHAIN} chain in one step with iptables-restore --noflush,\n"
    ));
    out.push_str("# then adds the jumps into it from INPUT, FORWARD and DOCKER-USER.\n");
    out.push_str("# Existing rules in those chains, all other chains, and every chain\n");
    out.push_str("# policy are left alone. IPv6 rules get the same chain in ip6tables.\n");
    out.push_str(&format!(
        "# {} IPv4 rule(s), {} IPv6 rule(s).\n",
        plan.v4.len(),
        plan.v6.len()
    ));
    for address in &plan.skipped {
        // `{:?}`, not `{}`: an unvalidated address can contain a newline,
        // which would end the comment and make the remainder of it a
        // command.
        out.push_str(&format!(
            "# skipped (not an IP address or CIDR range): {address:?}\n"
        ));
    }
    out.push_str("set -e\n\n");

    fragment(&mut out, "iptables-restore", "STOP_BOTS_IPV4", &plan.v4);
    // `INPUT` alone only covers services running on the host. Traffic for
    // a published container port is DNAT'd and then *forwarded*, so it
    // never reaches `INPUT` and an `INPUT`-only jump enforces nothing for
    // it — see the module docs in `crate::nftables` for the same reasoning.
    jumps(&mut out, "iptables", "");

    // Listing `INPUT` is the cheapest proof that ip6tables works here at
    // all; it fails on a kernel booted with IPv6 disabled.
    out.push_str("\nif ip6tables -w -L INPUT -n >/dev/null 2>&1; then\n");
    fragment(&mut out, "ip6tables-restore", "STOP_BOTS_IPV6", &plan.v6);
    jumps(&mut out, "ip6tables", "    ");
    if !plan.v6.is_empty() {
        out.push_str("else\n");
        out.push_str(&format!(
            "    echo \"stop-bots: ip6tables cannot be used on this host, so {} IPv6 rule(s) \
             were not applied\" >&2\n",
            plan.v6.len()
        ));
        out.push_str("    exit 1\n");
    }
    out.push_str("fi\n");

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::NewFirewallRule;
    use crate::testing::{allow, block, block_port, block_until, disabled};
    use serde::Deserialize;

    /// Any fixed moment will do.
    const NOW: i64 = 1_800_000_000;

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

    const RULES_JSON: &str = include_str!("../tests/fixtures/iptables/rules.json");
    const BASIC_RULES: &str = include_str!("../tests/fixtures/iptables/basic_rules.txt");

    /// The lines between `<restore> ... <<'DELIM'` and `DELIM`: what one
    /// restore is handed.
    fn fragment_of<'a>(script: &'a str, delimiter: &str) -> Vec<&'a str> {
        script
            .lines()
            .skip_while(|l| !l.ends_with(&format!("<<'{delimiter}'")))
            .skip(1)
            .take_while(|l| *l != delimiter)
            .collect()
    }

    /// A restore fragment can say far more than "fill this chain": a
    /// policy line, another chain's declaration, a rule in `INPUT`. Every
    /// line in ours is the table header, our own chain's declaration, a
    /// rule appended to our own chain, or the commit.
    #[test]
    fn the_restore_touches_our_chain_and_nothing_else() {
        let rendered = render(&[block("1.2.3.4"), block("2001:db8::1")], NOW);

        for delimiter in ["STOP_BOTS_IPV4", "STOP_BOTS_IPV6"] {
            let fragment = fragment_of(&rendered, delimiter);
            assert!(
                fragment.len() > 3,
                "no {delimiter} fragment in:\n{rendered}"
            );
            for line in fragment {
                assert!(
                    line == "*filter"
                        || line == format!(":{CHAIN} - [0:0]")
                        || line.starts_with(&format!("-A {CHAIN} "))
                        || line == "COMMIT",
                    "{delimiter} carries a line that reaches past {CHAIN}: {line:?}"
                );
            }
        }
    }

    #[test]
    fn render_never_touches_other_chains_or_policies() {
        let rendered = render(&[], NOW);
        // `-P` is the only way to change a policy, and `-F`/`-X` the way to
        // empty or delete a chain. None appears: our chain is emptied by
        // being declared in the restore, which touches no other chain.
        for forbidden in [" -P ", " -F", " -X", "OUTPUT", "flush ruleset"] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden:?} in:\n{rendered}"
            );
        }
    }

    /// The change that made this backend reach containerised services, and
    /// the bound on how far it reaches into chains it does not own.
    ///
    /// A packet for a published container port is DNAT'd and forwarded, so
    /// an `INPUT`-only jump never sees it. Both other chains therefore get
    /// a jump — and a jump is *all* they get: every line naming one is a
    /// guarded `-C`/`-I` of our own chain, never a rule of its own. The
    /// same holds for ip6tables.
    #[test]
    fn every_hop_into_our_chain_is_covered_and_nothing_else_is_added() {
        let rendered = render(&[block("1.2.3.4")], NOW);

        for tool in ["iptables", "ip6tables"] {
            for chain in ["INPUT", "FORWARD", "DOCKER-USER"] {
                assert!(
                    rendered.contains(&format!("{tool} -w -I {chain} -j {CHAIN}")),
                    "{chain} should jump to {CHAIN} in {tool}, but rendered was:\n{rendered}"
                );
                assert!(
                    rendered.contains(&format!("{tool} -w -C {chain} -j {CHAIN}")),
                    "the {tool} {chain} jump should be guarded, but rendered was:\n{rendered}"
                );
            }
            // DOCKER-USER exists only where Docker does, so unlike the
            // other two its jump is additionally guarded on the chain.
            assert!(
                rendered.contains(&format!(
                    "if {tool} -w -L DOCKER-USER -n >/dev/null 2>&1; then"
                )),
                "the {tool} DOCKER-USER jump should be guarded on Docker being present, \
                 but rendered was:\n{rendered}"
            );
        }

        // Nothing but jumps. A rule added to a chain we don't own would
        // outlive our chain and could not be cleaned up by re-running.
        for line in rendered.lines() {
            let line = line.trim();
            if (line.contains("FORWARD") || line.contains("DOCKER-USER") || line.contains("INPUT"))
                && (line.starts_with("iptables") || line.starts_with("ip6tables"))
            {
                assert!(
                    line.ends_with(&format!("-j {CHAIN}")),
                    "a chain we do not own may only gain a jump to {CHAIN}, but got:\n{line}"
                );
            }
        }
    }

    /// The chain is filled before anything jumps to it, so on a first
    /// apply no packet is sent into a chain that is still empty.
    #[test]
    fn the_chain_is_filled_before_the_jumps_are_added() {
        let rendered = render(&[block("1.2.3.4")], NOW);
        let filled = rendered.find("iptables-restore").unwrap();
        let jumped = rendered.find("iptables -w -I INPUT").unwrap();
        assert!(filled < jumped, "rendered was:\n{rendered}");
    }

    #[test]
    fn render_empty_rules_still_sets_up_chain_and_jump() {
        let rendered = render(&[], NOW);
        let fragment = fragment_of(&rendered, "STOP_BOTS_IPV4");
        assert_eq!(
            fragment,
            vec![
                "*filter",
                ":STOP-BOTS - [0:0]",
                // Even with no user rules, the safety rules for
                // established/related and loopback are there.
                "-A STOP-BOTS -m state --state ESTABLISHED,RELATED -j ACCEPT",
                "-A STOP-BOTS -i lo -j ACCEPT",
                "COMMIT",
            ],
            "rendered was:\n{rendered}"
        );
        assert!(rendered.contains(&format!("iptables -w -I INPUT -j {CHAIN}")));
    }

    #[test]
    fn render_matches_fixture_rule_lines_from_json_input() {
        let rules = rules_from_fixture(RULES_JSON);
        let rendered = render(&rules, NOW);

        // These lines come straight from tests/fixtures/iptables/rules.json,
        // rendered the same way tests/fixtures/iptables/basic_rules.txt shows
        // hand-written stop-bots rules being expressed.
        for line in [
            "-A STOP-BOTS -s 1.2.3.4 -j DROP",
            "-A STOP-BOTS -s 5.6.7.0/24 -j DROP",
            "-A STOP-BOTS -s 8.9.10.11 -p tcp --dport 80 -j DROP",
        ] {
            assert!(
                rendered.contains(&format!("\n{line}\n")),
                "{line:?} missing, rendered was:\n{rendered}"
            );
            assert!(BASIC_RULES.contains(line));
        }
        for line in [
            "-A STOP-BOTS -s 12.13.14.15 -j REJECT",
            "-A STOP-BOTS -s 66.249.64.0/19 -j ACCEPT",
        ] {
            assert!(
                rendered.contains(&format!("\n{line}\n")),
                "{line:?} missing, rendered was:\n{rendered}"
            );
        }
    }

    #[test]
    fn render_skips_disabled_rules() {
        let rules = rules_from_fixture(RULES_JSON);
        let rendered = render(&rules, NOW);
        // rule-6 in the fixture (192.168.1.100) is disabled.
        assert!(
            !rendered.contains("192.168.1.100"),
            "rendered was:\n{rendered}"
        );
    }

    /// IPv6 used to be skipped here, including every /64 a detector
    /// writes. Now it goes to ip6tables, and never to iptables, which
    /// would refuse the whole restore over it.
    #[test]
    fn an_ipv6_rule_goes_to_ip6tables_and_not_to_iptables() {
        let rendered = render(&[block("2001:db8::/64"), block("1.2.3.4")], NOW);

        let v4 = fragment_of(&rendered, "STOP_BOTS_IPV4");
        let v6 = fragment_of(&rendered, "STOP_BOTS_IPV6");
        assert!(
            v6.contains(&"-A STOP-BOTS -s 2001:db8::/64 -j DROP"),
            "rendered was:\n{rendered}"
        );
        assert!(
            !v4.iter().any(|l| l.contains("2001:db8")),
            "rendered was:\n{rendered}"
        );
        assert!(
            !v6.iter().any(|l| l.contains("1.2.3.4")),
            "rendered was:\n{rendered}"
        );
        assert_eq!(
            loaded_entries(&[block("2001:db8::/64"), block("1.2.3.4")], NOW),
            2
        );
    }

    /// On a host without working ip6tables, IPv6 rules cannot be loaded.
    /// The script has to fail and say so rather than succeed quietly with
    /// part of the policy missing.
    #[test]
    fn ipv6_rules_on_a_host_without_ip6tables_fail_loudly() {
        let with_v6 = render(&[block("2001:db8::/64")], NOW);
        assert!(
            with_v6.contains("1 IPv6 rule(s) were not applied\" >&2\n    exit 1\n"),
            "rendered was:\n{with_v6}"
        );

        // With nothing to load there is nothing to report.
        let without = render(&[block("1.2.3.4")], NOW);
        assert!(!without.contains("exit 1"), "rendered was:\n{without}");
    }

    #[test]
    fn an_expired_rule_is_left_out() {
        let rules = [
            block_until("203.0.113.9", NOW - 1),
            block_until("203.0.113.10", NOW + 60),
        ];
        let rendered = render(&rules, NOW);

        assert!(
            !rendered.contains("203.0.113.9 "),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains("-A STOP-BOTS -s 203.0.113.10 -j DROP"),
            "rendered was:\n{rendered}"
        );
        assert_eq!(loaded_entries(&rules, NOW), 1);
    }

    /// First match wins in a chain, and the order is the order given.
    #[test]
    fn rules_keep_their_order() {
        let rendered = render(&[allow("203.0.113.7"), block("203.0.113.0/24")], NOW);
        let allow_at = rendered.find("-s 203.0.113.7 -j ACCEPT").unwrap();
        let block_at = rendered.find("-s 203.0.113.0/24 -j DROP").unwrap();
        assert!(allow_at < block_at, "rendered was:\n{rendered}");
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
        assert!(
            rendered.contains("-A STOP-BOTS -s 203.0.113.7 -p tcp --dport 443 -j DROP"),
            "rendered was:\n{rendered}"
        );
    }

    /// The same rule set as `nftables`' golden, rendered for iptables. The
    /// golden is the exact script to hand to `sh -n` / a real
    /// `iptables-restore` on a machine that has one.
    #[test]
    fn rendered_script_matches_the_golden() {
        let rules = vec![
            allow("203.0.113.7"),
            block("198.51.100.0/24"),
            block_port("192.0.2.9", 22),
            block("2001:db8::/32"),
            block_until("192.0.2.77", NOW + 90_000),
            disabled("10.0.0.1"),
        ];
        crate::golden::assert_golden("firewall.iptables.sh", &render(&rules, NOW));
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
    /// newline ended the line early and made `-j DROP` a line of its own,
    /// which the restore refuses.
    #[test]
    fn an_address_is_rendered_trimmed() {
        let rendered = render(&[block(" 1.2.3.4\n"), block(" 2001:db8::1 ")], NOW);

        assert!(
            rendered.contains(&format!("\n-A {CHAIN} -s 1.2.3.4 -j DROP\n")),
            "rendered was:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!("\n-A {CHAIN} -s 2001:db8::1 -j DROP\n")),
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
            // "ruleset", not "flush": the restore's own `--noflush` is a
            // statement that legitimately says "flush".
            !statements.iter().any(|line| line.contains("ruleset")),
            "the payload escaped the comment:\n{rendered}"
        );
    }
}
