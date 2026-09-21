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

//! Shared firewall-rendering logic used by both the CLI's `render-firewall`
//! subcommand and the TUI's Dashboard "render firewall" popup (`f` key) —
//! gathering rules, the allowlist/iptables guard, script rendering and the
//! lockout safety check all live here so the two callers can never drift
//! out of sync with each other. Presentation (what gets printed to stderr
//! for the CLI vs. what gets put in the TUI's status message) stays with
//! each caller.

use crate::db::{Db, FirewallAction, FirewallRule, GeoMode};
use crate::{ipranges, iptables, nftables, sshlog};
use anyhow::{Context, Result};
use std::path::Path;

/// The default output path for a rendered firewall script — shared by the
/// Dashboard's `f`-key render popup and the internal cron's
/// `RenderFirewall` job (see `crate::cron`), so a script one renders is
/// where the other expects to find it.
pub const DEFAULT_OUTPUT_PATH: &str = "/etc/stop-bots/firewall.nft";

/// Which backend to render a script for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Iptables,
    Nftables,
}

impl FirewallBackend {
    /// The command an admin should run to apply the generated script.
    pub fn apply_command(self) -> &'static str {
        match self {
            FirewallBackend::Iptables => "sh",
            FirewallBackend::Nftables => "nft -f",
        }
    }

    /// Stored form, named `stored`/`from_stored` for the reason
    /// `BlockResponse` is: this is a database representation, not a
    /// display one.
    pub fn stored(self) -> &'static str {
        match self {
            FirewallBackend::Iptables => "iptables",
            FirewallBackend::Nftables => "nftables",
        }
    }

    /// Falls back to nftables for anything unrecognised, the same
    /// never-fail-a-read-over-a-stored-enum convention `GeoMode` uses.
    /// Nftables rather than iptables because it is the only backend that
    /// can represent IPv6 and an allowlist catch-all — a host that gets
    /// the fallback should get the one that can express every rule.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "iptables" => FirewallBackend::Iptables,
            _ => FirewallBackend::Nftables,
        }
    }
}

/// Which backend this host renders for.
///
/// Stored rather than asked for every time, so a one-click "Apply
/// everything" has an answer without guessing, and so an operator who
/// picked iptables once is not silently handed an nftables script on the
/// next render. The CLI's `--backend` stays authoritative for the run it
/// is passed to; it is what writes this.
pub const BACKEND_KEY: &str = "firewall:backend";

/// The script path for `backend` when nobody has said otherwise.
///
/// The extension is part of the answer, not decoration: a `.nft` file
/// holding `#!/bin/sh` and 12,000 `iptables -A` lines is what a host ends
/// up with when the path is chosen once at startup and the backend is
/// chosen per render. That happened on a real host, and it is confusing
/// precisely when it matters — while deciding which of two scripts to run.
pub fn default_output_path(backend: FirewallBackend) -> std::path::PathBuf {
    let base = std::path::PathBuf::from(DEFAULT_OUTPUT_PATH);
    match backend {
        FirewallBackend::Nftables => base,
        FirewallBackend::Iptables => base.with_extension("sh"),
    }
}

/// Where to write: `override_path` if an operator named one, otherwise the
/// default for `backend`.
///
/// An explicit `--firewall-out` wins outright, extension and all. Someone
/// who names a path has said where they want it, and silently rewriting
/// their suffix would be the same class of surprise in the other
/// direction.
pub fn output_path(override_path: Option<&Path>, backend: FirewallBackend) -> std::path::PathBuf {
    match override_path {
        Some(path) => path.to_path_buf(),
        None => default_output_path(backend),
    }
}

pub fn stored_backend(db: &Db) -> Result<FirewallBackend> {
    Ok(db
        .get_text_setting(BACKEND_KEY)?
        .map(|value| FirewallBackend::from_stored(&value))
        .unwrap_or(FirewallBackend::Nftables))
}

pub fn store_backend(db: &Db, backend: FirewallBackend) -> Result<()> {
    db.set_text_setting(BACKEND_KEY, backend.stored())
}

/// Every synthetic (never persisted) `FirewallRule` derived from
/// currently-blocked-by-default crawler IP-range sources and the current
/// geo mode's selected countries — see [`Db::derived_firewall_entries`].
/// Uses `id: 0` since these don't correspond to a real `firewall_rules` row;
/// they're never looked up or removed by id, only rendered. Order is
/// preserved from `derived_firewall_entries` (crawler ranges, then geo rules
/// with any Allowlist catch-all strictly last) — callers must append this
/// after admin rules, never reorder it.
pub fn derived_firewall_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    Ok(db
        .derived_firewall_entries()?
        .into_iter()
        .map(|(address, action)| FirewallRule {
            id: 0,
            address,
            port: None,
            action,
            enabled: true,
            expires_at: None,
        })
        .collect())
}

/// Every `(connected_ip, matching_rule_address)` pair where a client with a
/// recent successful SSH login (from `connected_ips`) would actually end up
/// blocked by `rules` — simulating the same first-match-wins evaluation the
/// rendered script itself performs, walking `rules` in the exact order
/// they'll be written. This is deliberately *not* "does any Block rule's
/// CIDR contain this IP": once Allowlist geo mode can put an Allow rule
/// ahead of a catch-all Block, that cruder check would misfire on an IP an
/// earlier Allow rule already protects. Existing (established/related)
/// connections aren't modeled — this answers "can this client *reconnect*
/// after applying this", which is the stricter and more useful question:
/// an admin who disconnects after a bad allowlist can't rely on an
/// already-open session to get back in. An unparseable `connected_ips`
/// entry is simply skipped rather than erroring: this check exists to *add*
/// a warning on top of firewall rendering, never to block it over
/// something unrelated to that rendering.
pub fn lockout_risks(rules: &[FirewallRule], connected_ips: &[String]) -> Vec<(String, String)> {
    let mut risks = Vec::new();
    for ip_str in connected_ips {
        let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
            continue;
        };
        for rule in rules.iter().filter(|r| r.enabled) {
            if ipranges::cidr_contains(&rule.address, ip) {
                if rule.action != FirewallAction::Allow {
                    risks.push((ip_str.clone(), rule.address.clone()));
                }
                // First match wins, same as the real firewall: stop
                // checking further rules for this IP either way.
                break;
            }
        }
    }
    risks
}

/// What checking `rules` against currently-connected SSH clients found.
pub enum LockoutStatus {
    /// No SSH log could be found or read at all — nothing to check
    /// against, not itself a risk.
    LogUnavailable,
    /// Checked; these currently-connected `(ip, matching_rule_address)`
    /// pairs would actually end up blocked (empty if none would).
    Risks(Vec<(String, String)>),
}

/// Finds recent successful SSH logins (via `ssh_log`, or auto-detected) and
/// checks whether any of them would actually end up blocked by `rules` (see
/// [`lockout_risks`] for what "actually end up" means). Pure with respect to
/// presentation: callers decide how to report [`LockoutStatus::Risks`] and
/// whether to proceed anyway.
pub fn assess_lockout_risk(rules: &[FirewallRule], ssh_log: Option<&Path>) -> LockoutStatus {
    let source = match ssh_log {
        Some(path) => sshlog::read_log_file(path),
        None => sshlog::find_default_source(),
    };
    match source {
        sshlog::LogSource::Found(text) => {
            let connected_ips = sshlog::parse_accepted_ips(&text);
            LockoutStatus::Risks(lockout_risks(rules, &connected_ips))
        }
        sshlog::LogSource::Unavailable => LockoutStatus::LogUnavailable,
    }
}

/// A firewall script rendered for one backend, ready to write to disk.
#[derive(Debug)]
pub struct BuiltFirewall {
    /// Every rule that went into `script`: admin-managed rules followed by
    /// derived crawler/geo rules, in the exact order they were rendered —
    /// feed this to [`assess_lockout_risk`] so the safety check evaluates
    /// the same order the script itself will.
    pub rules: Vec<FirewallRule>,
    pub script: String,
    /// How many rules actually made it into `script`: excludes disabled
    /// rules, and on iptables, IPv6 rules that backend can't represent
    /// (see `iptables`'s module docs).
    pub written: usize,
}

/// Every rule currently in effect — admin-managed (from
/// [`Db::list_firewall_rules`]) followed by derived crawler/geo rules (from
/// [`derived_firewall_rules`]) — in the same order [`build_script`] renders
/// them. Factored out so [`build_script`] and the Dashboard's "needs
/// updating" staleness check ([`rules_signature`]) share one gathering
/// implementation and can never drift out of sync with each other.
pub fn all_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    let mut rules = ssh_allow_rules(db)?;
    rules.extend(db.list_firewall_rules()?);
    rules.extend(derived_firewall_rules(db)?);
    Ok(rules)
}

/// An Allow rule for every address a successful SSH login has been seen
/// from inside [`Db::recent_ssh_login_ips`]'s window. Synthetic, like
/// [`derived_firewall_rules`]: `id: 0`, never persisted, recomputed on
/// every render.
///
/// **These go strictly first, and that placement is the whole mechanism.**
/// Both backends evaluate first-match-wins, so an Allow ahead of
/// everything else means no later rule can block that address — not a
/// derived reputation CIDR that happens to contain it, not an allowlist
/// catch-all, not a Block rule an admin added by hand. Filtering blocks
/// out instead would have covered only the first of those three: a /24
/// from a reputation feed cannot be "removed" for one address inside it.
///
/// The consequence is worth stating plainly: whoever can authenticate over
/// SSH gets a week of immunity from every detector this tool has. That is
/// what "don't block that one under any circumstance" means, and it is the
/// right trade for a tool that can otherwise wall its own operator out of
/// the host, but it is a real hole and not an accident.
pub fn ssh_allow_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    Ok(db
        .recent_ssh_login_ips()?
        .into_iter()
        .map(|address| FirewallRule {
            id: 0,
            address,
            port: None,
            action: FirewallAction::Allow,
            enabled: true,
            expires_at: None,
        })
        .collect())
}

/// A stable, backend- and path-independent fingerprint of `rules` — used
/// only to detect whether the rule *set* has changed since the firewall
/// was last rendered (see `Db::get_firewall_rendered_signature`/
/// `set_firewall_rendered_signature`, and the Dashboard's Summary panel),
/// never to render anything itself. Deliberately not tied to a specific
/// backend's rendered text: a render with `--backend iptables` to a custom
/// path must still correctly mark a subsequent check as "up to date" — what
/// matters is whether the *rules* changed, not which backend/path last
/// wrote them. `FirewallRule`'s `Debug` output is a deterministic function
/// of its fields, so equal rule sets in the same order always produce
/// identical digests.
///
/// **This is a hash, and it has to stay one.** It used to be the rule
/// set's whole `Debug` dump, stored verbatim in `settings`. That is fine
/// with a handful of admin rules and ruinous with the derived ones:
/// `all_rules` appends every enabled reputation/cloud CIDR, and on a real
/// host that came to 44,075 rules — a single 4.7 MB `settings` value,
/// 31% of the database, rewritten in full on every render and every
/// hourly health check. The churn also built a 6.5 MB freelist, because
/// SQLite reuses freed pages but never shrinks the file on its own. Only
/// equality is ever asked of this value, so a 64-character digest answers
/// the same question at a constant, negligible size.
///
/// Hashed rule by rule rather than over one `format!("{rules:?}")` string
/// so that the 5 MB intermediate allocation goes away too, not just the
/// stored copy. The `\n` separator cannot be confused with rule content:
/// `Debug` for `String` escapes a literal newline as `\\n`, so no address
/// can forge a boundary.
///
/// Upgrading past the verbatim form makes the first staleness check see a
/// stored dump where it now expects a digest, report "the rules changed"
/// once, and settle after the next render. Deliberately not migrated: a
/// spurious "render again" is a smaller price than code that has to
/// recognise the old format forever.
pub fn rules_signature(rules: &[FirewallRule]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for rule in rules {
        hasher.update(format!("{rule:?}").as_bytes());
        hasher.update(b"\n");
    }
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Whether the rules have changed since the last successful render — the
/// one question three different callers were each answering with their own
/// copy of the same two lines (the Dashboard's Summary panel,
/// `health::script_freshness`, and now `cron::is_due`).
///
/// Comparing against the signature this app persisted on its last write
/// (`Db::get_firewall_rendered_signature`) rather than against the file on
/// disk keeps it hermetic — no dependency on a real system path — and
/// answers "did the desired rules change since our own last render", not
/// "do some file's bytes happen to match". It is also unaffected by which
/// backend or output path that render used; see [`rules_signature`].
///
/// Costs one pass over every rule, derived ones included — about 50ms on a
/// host with 44,000 of them. Cheap enough to ask once a minute, which is
/// what the internal cron does with it, and far cheaper than the render it
/// decides against.
pub fn needs_render(db: &Db) -> Result<bool> {
    let current = rules_signature(&all_rules(db)?);
    Ok(db.get_firewall_rendered_signature()?.as_deref() != Some(current.as_str()))
}

/// Gathers every firewall rule (see [`all_rules`]) and renders them for
/// `backend`. Fails immediately, before gathering or rendering anything, if
/// `backend` is iptables and geo mode is Allowlist — see `iptables`'s
/// module docs for why that combination can't be safely enforced.
pub fn build_script(db: &Db, backend: FirewallBackend) -> Result<BuiltFirewall> {
    if db.get_geo_mode()? == GeoMode::Allowlist && matches!(backend, FirewallBackend::Iptables) {
        anyhow::bail!(
            "Allowlist geo mode requires --backend nftables. iptables cannot safely enforce a \
             default-deny (catch-all) policy because: (1) it is IPv4-only, so the ::/0 \
             IPv6 catch-all would be silently skipped, leaving IPv6 traffic unblocked; \
             and (2) it would block established connections and loopback without \
             explicit allow rules. Use nftables which handles both address families."
        );
    }

    let rules = all_rules(db)?;

    let (script, written) = match backend {
        FirewallBackend::Iptables => {
            // iptables is IPv4-only; render() skips IPv6 rules (see SPECS.md).
            let written = rules
                .iter()
                .filter(|r| r.enabled && !r.address.contains(':'))
                .count();
            (iptables::render(&rules), written)
        }
        FirewallBackend::Nftables => {
            let written = rules.iter().filter(|r| r.enabled).count();
            (nftables::render(&rules), written)
        }
    };

    Ok(BuiltFirewall {
        rules,
        script,
        written,
    })
}

/// Writes a rendered script to `out`, creating any missing parent
/// directories first. Plain `std::fs::write` doesn't create parents, and
/// `DEFAULT_OUTPUT_PATH` (`/etc/stop-bots/`) has no other code path that
/// creates it — unlike the database's `/var/lib/stop-bots`, which
/// `open_or_fallback` creates — so without this, writing to the default
/// path fails with "No such file or directory" on any host where an admin
/// hasn't already `mkdir`ed it, including the internal cron's unattended
/// `RenderFirewall` job, which has no human present to react to the error.
pub fn write_script(out: &Path, script: &str) -> std::io::Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(out, script)
}

/// Actually enforces a just-written script by running `backend`'s apply
/// command (`sh <out>` for iptables, `nft -f <out>` for nftables — see
/// [`FirewallBackend::apply_command`]) against it. This is the one place in
/// the whole project that executes a generated firewall script rather than
/// only ever writing it — the Dashboard's render popup's "apply after
/// writing" toggle (`App::start_firewall_render`), gated by the same
/// `apply_firewall`/explicit-confirmation guard `nginx::reload` uses for
/// NGINX reloads.
///
/// There are exactly three callers, and one of them *is* unattended — this
/// comment once claimed there were none of those, which is the wrong answer
/// to the one question anyone reads it to ask:
///
/// - `App::start_firewall_render`, from the TUI Dashboard's render popup,
///   only when the TUI was started without `--no-apply`.
/// - `web::dashboard::write_and_apply_firewall`, from the console's "run it
///   after writing" box or its "Apply everything" button, only when the
///   console was started without `--no-apply`. The console refusing to do
///   this at all was a deliberate omission until it was reversed on
///   request; the guard below is what replaced the omission.
/// - `batch::render_and_apply_firewall`, under `batch --apply`, which is
///   the documented crontab entry point and has nobody watching.
///
/// All three run `assess_lockout_risk` over the same rules, in the same
/// order the script will evaluate them, before the script is written — and
/// under `batch --apply` a guard that merely *could not run* is a refusal
/// too.
/// So `README.md`'s "generated, never applied *automatically*" holds in the
/// sense that matters: nothing applies a script without an operator having
/// asked for it, whether by pressing a key or by putting `--apply` in a
/// crontab. It does not hold in the sense of "a human is looking".
pub fn apply_script(backend: FirewallBackend, out_path: &Path) -> Result<()> {
    let output = match backend {
        FirewallBackend::Iptables => std::process::Command::new("sh")
            .arg(out_path)
            .output()
            .context("failed to run `sh` on the generated iptables script")?,
        FirewallBackend::Nftables => std::process::Command::new("nft")
            .arg("-f")
            .arg(out_path)
            .output()
            .context("failed to run `nft -f` on the generated nftables script")?,
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "{} exited with {}: {}{}",
            backend.apply_command(),
            output.status,
            stderr.trim(),
            sandbox_hint(&stderr)
        );
    }
    Ok(())
}

/// An explanation to append when the apply failed for a reason the tool
/// itself cannot name.
///
/// `nft` and Debian's nft-backed `iptables` both reach the kernel over a
/// netlink socket, and the systemd unit `stop-bots install web` writes
/// restricts which address families the service may open. Get that wrong
/// and the failure is `Unable to initialize Netlink socket: Address family
/// not supported by protocol` — which is accurate, mentions neither
/// systemd nor this project, and sends whoever reads it looking for a
/// kernel module or a missing package.
///
/// Reported here rather than fixed here because the fix is in a file this
/// process does not own: an operator running an older unit needs to be
/// told which line to change, not have it changed under them.
fn sandbox_hint(stderr: &str) -> &'static str {
    let netlink_denied = stderr.contains("Netlink")
        && (stderr.contains("Address family not supported")
            || stderr.contains("Operation not permitted"));
    if !netlink_denied {
        return "";
    }
    "\n\nThat error means the kernel refused a netlink socket, which usually \
     means this process is sandboxed. If it is running from the unit \
     `stop-bots install web` writes, check that its RestrictAddressFamilies \
     line includes AF_NETLINK:\n\n    \
     systemctl show stop-bots-web.service -p RestrictAddressFamilies\n\n\
     Units written before the console could apply the firewall do not have \
     it. Re-run `stop-bots install web --force` to get the current unit, \
     then `systemctl restart stop-bots-web.service`."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(address: &str, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: 0,
            address: address.to_string(),
            port: None,
            action,
            enabled: true,
            expires_at: None,
        }
    }

    #[test]
    fn derived_firewall_rules_combines_blocked_ip_ranges_and_geo_rules() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&crate::db::IpRangeSource {
            id: "gptbot".to_string(),
            name: "GPTBot IP ranges".to_string(),
            url: "https://example.invalid/gptbot.json".to_string(),
            category: crate::db::Category::Ai,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.replace_ip_ranges("gptbot", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let mut rules = derived_firewall_rules(&db).unwrap();
        rules.sort_by(|a, b| a.address.cmp(&b.address));

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].address, "1.2.3.0/24");
        assert_eq!(rules[1].address, "4.5.6.0/24");
        assert!(rules.iter().all(|r| r.action == FirewallAction::Block));
        assert!(rules.iter().all(|r| r.enabled));
    }

    #[test]
    fn derived_firewall_rules_is_empty_with_no_ip_ranges_or_selected_countries() {
        let db = Db::open_in_memory().unwrap();
        assert!(derived_firewall_rules(&db).unwrap().is_empty());
    }

    #[test]
    fn derived_firewall_rules_in_allowlist_mode_ends_with_the_catchall() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        // Both families, so both catch-alls are rendered -- see
        // `Db::geo_firewall_rules` for why a family with no ranges gets none.
        db.replace_country_ranges(
            "nl",
            &["1.2.3.0/24".to_string(), "2001:db8::/32".to_string()],
        )
        .unwrap();
        db.set_country_selected("nl", true).unwrap();

        let rules = derived_firewall_rules(&db).unwrap();
        let tail: Vec<(&str, FirewallAction)> = rules
            .iter()
            .map(|r| (r.address.as_str(), r.action))
            .collect();
        assert_eq!(
            tail,
            vec![
                ("1.2.3.0/24", FirewallAction::Allow),
                ("2001:db8::/32", FirewallAction::Allow),
                ("0.0.0.0/0", FirewallAction::Block),
                ("::/0", FirewallAction::Block),
            ],
            "the catch-alls must come last, and one per family"
        );
    }

    /// The guarantee, against the case that motivated it: the operator's
    /// own address sits inside a reputation feed's /24. Nothing can remove
    /// one address from that CIDR, so the Allow has to come *first* — and
    /// first-match-wins is what makes that enough.
    #[test]
    fn all_rules_lets_a_recent_ssh_login_through_a_blocked_range_it_sits_inside() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&crate::db::IpRangeSource {
            id: "gptbot".to_string(),
            name: "GPTBot IP ranges".to_string(),
            url: "https://example.invalid/gptbot.json".to_string(),
            category: crate::db::Category::Ai,
            last_fetched_at: None,
            range_count: 0,
        })
        .unwrap();
        db.replace_ip_ranges("gptbot", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.record_ssh_login_ips(&["4.5.6.7".to_string()]).unwrap();

        let rules = all_rules(&db).unwrap();

        assert_eq!(rules[0].address, "4.5.6.7");
        assert_eq!(rules[0].action, FirewallAction::Allow);
        assert!(lockout_risks(&rules, &["4.5.6.7".to_string()]).is_empty());
    }

    /// "Under any circumstance" includes a rule an admin added by hand.
    /// The rule stays in the table — this does not delete anyone's work —
    /// it just never gets to match.
    #[test]
    fn all_rules_overrides_even_a_hand_added_block_for_a_recent_ssh_login() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "4.5.6.7".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();
        db.record_ssh_login_ips(&["4.5.6.7".to_string()]).unwrap();

        let rules = all_rules(&db).unwrap();

        assert!(lockout_risks(&rules, &["4.5.6.7".to_string()]).is_empty());
        // Still stored, still Block, still listed: neutralised, not removed.
        let stored = db.list_firewall_rules().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].action, FirewallAction::Block);
    }

    /// An allowlist catch-all blocks everything it does not explicitly
    /// permit, which is the other way an operator walls themselves out.
    #[test]
    fn all_rules_lets_a_recent_ssh_login_past_the_allowlist_catchall() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        db.record_ssh_login_ips(&["9.9.9.9".to_string()]).unwrap();

        let rules = all_rules(&db).unwrap();

        assert!(lockout_risks(&rules, &["9.9.9.9".to_string()]).is_empty());
    }

    /// The window is what stops this being a permanent allowlist. Nothing
    /// here reads a log, which is the point: a stored login still protects
    /// its address on a host where the SSH log has since become unreadable.
    #[test]
    fn all_rules_stops_protecting_an_address_once_its_window_lapses() {
        let db = Db::open_in_memory().unwrap();
        db.record_ssh_login_ips(&["4.5.6.7".to_string()]).unwrap();
        db.backdate_ssh_login_for_tests("4.5.6.7", crate::db::SSH_LOGIN_WINDOW_SECONDS + 60)
            .unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "4.5.6.7".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();

        let rules = all_rules(&db).unwrap();

        assert!(!rules.iter().any(|r| r.action == FirewallAction::Allow));
        assert_eq!(
            lockout_risks(&rules, &["4.5.6.7".to_string()]),
            vec![("4.5.6.7".to_string(), "4.5.6.7".to_string())]
        );
    }

    #[test]
    fn lockout_risks_finds_a_connected_ip_inside_a_block_rule() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        let connected = vec!["4.5.6.7".to_string()];
        assert_eq!(
            lockout_risks(&rules, &connected),
            vec![("4.5.6.7".to_string(), "4.5.6.0/24".to_string())]
        );
    }

    #[test]
    fn lockout_risks_is_empty_when_no_connected_ip_matches() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        let connected = vec!["9.9.9.9".to_string()];
        assert!(lockout_risks(&rules, &connected).is_empty());
    }

    #[test]
    fn lockout_risks_skips_unparseable_connected_ip_entries() {
        let rules = vec![rule("0.0.0.0/0", FirewallAction::Block)];
        let connected = vec!["not-an-ip".to_string()];
        assert!(lockout_risks(&rules, &connected).is_empty());
    }

    /// The critical correctness property for Allowlist geo mode: an IP
    /// covered by an earlier Allow rule must never be flagged, even though
    /// a later catch-all Block rule's CIDR also technically contains it —
    /// first match wins, exactly like the real firewall evaluates it.
    #[test]
    fn lockout_risks_is_safe_when_an_earlier_allow_rule_covers_the_catchall() {
        let rules = vec![
            rule("4.5.6.0/24", FirewallAction::Allow),
            rule("0.0.0.0/0", FirewallAction::Block),
        ];
        let connected = vec!["4.5.6.7".to_string()];
        assert!(lockout_risks(&rules, &connected).is_empty());
    }

    /// The flip side: an IP *not* covered by any earlier Allow rule must
    /// still be caught by the trailing catch-all.
    #[test]
    fn lockout_risks_catches_an_ip_only_covered_by_the_catchall() {
        let rules = vec![
            rule("4.5.6.0/24", FirewallAction::Allow),
            rule("0.0.0.0/0", FirewallAction::Block),
        ];
        let connected = vec!["9.9.9.9".to_string()];
        assert_eq!(
            lockout_risks(&rules, &connected),
            vec![("9.9.9.9".to_string(), "0.0.0.0/0".to_string())]
        );
    }

    #[test]
    fn assess_lockout_risk_reports_risks_from_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 4.5.6.7 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        match assess_lockout_risk(&rules, Some(&log_path)) {
            LockoutStatus::Risks(risks) => {
                assert_eq!(
                    risks,
                    vec![("4.5.6.7".to_string(), "4.5.6.0/24".to_string())]
                );
            }
            LockoutStatus::LogUnavailable => panic!("expected the log to be found"),
        }
    }

    #[test]
    fn assess_lockout_risk_is_unavailable_for_a_nonexistent_log() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(matches!(
            assess_lockout_risk(&rules, Some(Path::new("/nonexistent/x.log"))),
            LockoutStatus::LogUnavailable
        ));
    }

    #[test]
    fn write_script_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("nested/deeper/firewall.nft");

        write_script(&out, "table inet stop_bots {}\n").unwrap();

        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "table inet stop_bots {}\n"
        );
    }

    #[test]
    fn write_script_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("firewall.nft");
        std::fs::write(&out, "old content").unwrap();

        write_script(&out, "new content").unwrap();

        assert_eq!(std::fs::read_to_string(&out).unwrap(), "new content");
    }

    #[test]
    fn build_script_rejects_allowlist_mode_on_iptables() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();

        let result = build_script(&db, FirewallBackend::Iptables);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nftables"));
    }

    #[test]
    fn build_script_allows_allowlist_mode_on_nftables() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();

        let built = build_script(&db, FirewallBackend::Nftables).unwrap();
        assert!(built.script.contains("policy accept"));
    }

    #[test]
    fn all_rules_combines_admin_and_derived_rules_in_order() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "9.9.9.9".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let rules = all_rules(&db).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].address, "9.9.9.9");
        assert_eq!(rules[1].address, "4.5.6.0/24");
    }

    #[test]
    fn rules_signature_is_stable_for_equal_rule_sets() {
        let a = vec![rule("1.2.3.4", FirewallAction::Block)];
        let b = vec![rule("1.2.3.4", FirewallAction::Block)];
        assert_eq!(rules_signature(&a), rules_signature(&b));
    }

    #[test]
    fn rules_signature_differs_when_the_rule_set_changes() {
        let a = vec![rule("1.2.3.4", FirewallAction::Block)];
        let b = vec![
            rule("1.2.3.4", FirewallAction::Block),
            rule("5.6.7.8", FirewallAction::Block),
        ];
        assert_ne!(rules_signature(&a), rules_signature(&b));
    }

    /// The property the whole fix rests on: the stored value's size is a
    /// constant, not a function of how many rules there are. A rule set
    /// three orders of magnitude larger than the other must still produce
    /// the same 64 characters — that is what stops `settings` from
    /// carrying a multi-megabyte value again, and it is the invariant a
    /// future "just store the rules, it's easier to debug" change would
    /// break.
    #[test]
    fn rules_signature_is_a_fixed_size_however_many_rules_there_are() {
        let one = vec![rule("1.2.3.4", FirewallAction::Block)];
        // Three orders of magnitude apart is the point; more rules than
        // this only buys time off the 300ms budget this file's tests have.
        let many: Vec<FirewallRule> = (0..5_000)
            .map(|n| {
                rule(
                    &format!("10.{}.{}.1", n / 256, n % 256),
                    FirewallAction::Block,
                )
            })
            .collect();

        assert_eq!(rules_signature(&one).len(), 64);
        assert_eq!(rules_signature(&many).len(), 64);
    }

    /// A digest, not a transcript: no part of a rule may be readable in
    /// the value that gets stored. Pins the intent as well as the size —
    /// a signature that happened to be short but still embedded an
    /// address would pass the length test above.
    #[test]
    fn rules_signature_does_not_carry_the_rules_it_describes() {
        let signature = rules_signature(&[rule("203.0.113.9", FirewallAction::Block)]);

        assert!(
            !signature.contains("203.0.113.9") && !signature.contains("Block"),
            "the rule leaked into the signature: {signature}"
        );
        assert!(
            signature.chars().all(|c| c.is_ascii_hexdigit()),
            "not a hex digest: {signature}"
        );
    }

    /// Order is part of the identity: `all_rules` returns admin rules
    /// before derived ones, and `build_script` renders first-match-wins in
    /// exactly that order, so two sets holding the same rules in a
    /// different order are genuinely different rule sets and a render is
    /// genuinely needed.
    #[test]
    fn rules_signature_distinguishes_a_reordered_rule_set() {
        let a = vec![
            rule("1.2.3.4", FirewallAction::Allow),
            rule("1.2.3.0/24", FirewallAction::Block),
        ];
        let b = vec![a[1].clone(), a[0].clone()];

        assert_ne!(rules_signature(&a), rules_signature(&b));
    }

    /// Only the `Iptables` branch (`sh <script>`) is exercised here, with
    /// inert `true`/`false` scripts rather than real firewall commands —
    /// unlike `nft`, `sh` is universally available, and a trivial exit-code
    /// script never touches the actual system firewall, so this is safe to
    /// run in CI. The `Nftables` branch isn't unit tested for the same
    /// reason `nginx::reload`'s real `systemctl`/`nginx` calls aren't: it
    /// would require (and actually invoke) a real `nft` against whatever
    /// host runs the suite.
    #[test]
    fn apply_script_succeeds_when_the_command_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("ok.sh");
        std::fs::write(&script, "true\n").unwrap();

        apply_script(FirewallBackend::Iptables, &script).unwrap();
    }

    #[test]
    fn apply_script_reports_a_nonzero_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fail.sh");
        std::fs::write(&script, "false\n").unwrap();

        let err = apply_script(FirewallBackend::Iptables, &script).unwrap_err();
        assert!(err.to_string().contains("exited with"), "err was: {err}");
    }
    // ---- the path follows the backend ----

    /// The bug this prevents, from a real host: `/etc/stop-bots/firewall.nft`
    /// whose first line was `#!/bin/sh`, holding 12,000 `iptables -A` rules.
    /// The path was decided once at startup and the backend per render, so
    /// the two drifted apart — and they drift apart exactly when it matters,
    /// while someone is deciding which of two scripts to run.
    #[test]
    fn the_default_path_matches_the_backend_that_writes_it() {
        let nft = default_output_path(FirewallBackend::Nftables);
        let ipt = default_output_path(FirewallBackend::Iptables);

        assert_eq!(nft.extension().unwrap(), "nft", "was: {}", nft.display());
        assert_eq!(ipt.extension().unwrap(), "sh", "was: {}", ipt.display());
        assert_ne!(nft, ipt);
    }

    /// Whichever backend renders, the file it lands in must announce the
    /// same one — checked against the script's own first line rather than
    /// against a second copy of the mapping.
    #[test]
    fn the_extension_agrees_with_the_scripts_own_interpreter() {
        for (backend, shebang) in [
            (FirewallBackend::Nftables, "#!/usr/sbin/nft -f"),
            (FirewallBackend::Iptables, "#!/bin/sh"),
        ] {
            let db = Db::open_in_memory().unwrap();
            let built = build_script(&db, backend).unwrap();
            let path = default_output_path(backend);

            assert!(
                built.script.starts_with(shebang),
                "{:?} renders {shebang}?\n{}",
                backend,
                &built.script[..40]
            );
            let expected = if shebang.contains("nft") { "nft" } else { "sh" };
            assert_eq!(
                path.extension().unwrap(),
                expected,
                "{:?} writes {shebang} into {}",
                backend,
                path.display()
            );
        }
    }

    /// An operator who names a path has said where they want it. Rewriting
    /// their suffix would be the same surprise in the other direction.
    #[test]
    fn an_explicit_path_wins_over_the_backends_default() {
        let chosen = Path::new("/srv/rules.txt");

        for backend in [FirewallBackend::Nftables, FirewallBackend::Iptables] {
            assert_eq!(output_path(Some(chosen), backend), chosen);
        }
        assert_eq!(
            output_path(None, FirewallBackend::Iptables),
            default_output_path(FirewallBackend::Iptables)
        );
    }

    // ---- the sandbox hint ----

    /// The message an operator actually saw, from a console running under
    /// the unit `install web` wrote before the console could apply.
    #[test]
    fn a_netlink_refusal_explains_itself() {
        let hint = sandbox_hint(
            "src/mnl.c:64: Unable to initialize Netlink socket: \
             Address family not supported by protocol",
        );

        assert!(hint.contains("AF_NETLINK"), "was: {hint}");
        assert!(
            hint.contains("stop-bots install web --force"),
            "it has to say how to get a unit that works: {hint}"
        );
    }

    #[test]
    fn an_unrelated_failure_gets_no_hint() {
        assert_eq!(sandbox_hint("nft: command not found"), "");
        assert_eq!(sandbox_hint("Error: syntax error, unexpected newline"), "");
    }
}
