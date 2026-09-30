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

//! The firewall: gathering rules, the allowlist/iptables guard, script
//! rendering, the lockout guard, writing and applying.
//!
//! **One path, five front-ends.** `render-firewall`, `batch`, the internal
//! cron, the TUI and the web console all go render → guard → write → apply
//! through [`prepare`], [`execute`] and [`record`] (or [`render_and_apply`],
//! all three at once), with one policy — see [`FirewallRun`]. They differ
//! only in how they put the [`FirewallOutcome`] into words. It is the one
//! path in this project that can take a server off the network, and it
//! used to exist five times with four answers to "no SSH log".
//!
//! **Two scripts.** A render writes [`rendered_path`]; only an apply copies
//! it to the applied path, which is what `stop-bots-firewall.service`
//! loads at boot.

use crate::db::{Db, FirewallAction, FirewallRule, GeoMode, RuleSource};
use crate::{ipranges, iptables, nftables, sshlog};
use anyhow::Result;
use std::path::Path;

/// The applied firewall script: what the boot unit `install firewall`
/// writes loads, and what an apply replaces. Renders go beside it (see
/// [`rendered_path`]). Every front-end defaults to it, so a script one
/// applies is where the others expect to find it.
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
    /// can do allowlist geo mode and expire a block in the kernel — a host
    /// that gets the fallback should get the one that can express every
    /// rule.
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
pub const BACKEND_KEY: &str = crate::db::keys::FIREWALL_BACKEND;

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
            source: Some(RuleSource::List),
            created_at: None,
            evidence: None,
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
///
/// **Ports.** Both renderers turn a rule's port into `tcp dport <port>`
/// (`-p tcp --dport` for iptables), so a port-scoped rule only matches
/// traffic to that port — and nothing in this project knows which port
/// sshd listens on. The two directions are therefore resolved the way
/// that errs towards a warning: a port-scoped **Allow** is skipped, as if
/// absent, because it cannot be shown to cover SSH (not even on 22 — sshd
/// may be elsewhere); a port-scoped **Block** still counts, because it
/// may be on exactly the port sshd uses. Counting the Allow was how
/// `allow 203.0.113.0/24 port 443` ahead of a catch-all passed as safe
/// while the real script dropped every SSH packet from that range.
pub fn lockout_risks(rules: &[FirewallRule], connected_ips: &[String]) -> Vec<(String, String)> {
    let mut risks = Vec::new();
    for ip_str in connected_ips {
        let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
            continue;
        };
        let could_decide_ssh = |rule: &&FirewallRule| {
            rule.enabled && (rule.port.is_none() || rule.action != FirewallAction::Allow)
        };
        for rule in rules.iter().filter(could_decide_ssh) {
            if ipranges::cidr_contains(rule.address.trim(), ip) {
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

/// What the lockout guard found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guard {
    /// The SSH log was read. These currently-connected `(ip,
    /// matching_rule_address)` pairs would end up blocked; empty is a pass.
    Ran(Vec<(String, String)>),
    /// No SSH log could be found or read, so there was nothing to check
    /// against. Not a risk in itself, and not a pass either.
    LogUnreadable,
}

impl Guard {
    /// The connected clients the rules would block. Empty when the guard
    /// could not run, which is why this alone never means "safe".
    pub fn risks(&self) -> &[(String, String)] {
        match self {
            Guard::Ran(risks) => risks,
            Guard::LogUnreadable => &[],
        }
    }

    /// Whether the guard ran *and* found nothing.
    pub fn passed(&self) -> bool {
        matches!(self, Guard::Ran(risks) if risks.is_empty())
    }

    /// One line for any front-end: what the guard found.
    pub fn describe(&self) -> String {
        match self {
            Guard::Ran(risks) if risks.is_empty() => "lockout check passed: the SSH log was read, \
                                                      and no connected client would be blocked"
                .to_string(),
            Guard::Ran(risks) => format!(
                "lockout check FAILED: these rules would block {} connected SSH client(s): {}",
                risks.len(),
                risks
                    .iter()
                    .map(|(ip, rule)| format!("{ip} (blocked by {rule})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Guard::LogUnreadable => "lockout check could not run: no SSH log could be read \
                                     (pass --ssh-log, or run as root)"
                .to_string(),
        }
    }
}

/// Where the lockout guard gets its SSH log.
#[derive(Debug, Clone, Copy)]
pub enum SshLog<'a> {
    /// Read it from here, live: what [`crate::logpaths::LogPaths::ssh`]
    /// resolved — a flag, else the stored path, else a search.
    Read(&'a sshlog::SshSource),
    /// Already read by the caller; `None` means nothing could be read.
    Text(Option<&'a str>),
    /// Already read and parsed into the addresses with a recent login, as
    /// the internal cron's log pass does; `None` means nothing could be
    /// read.
    Connected(Option<&'a [String]>),
}

/// Checks `rules` against the SSH clients `log` says are connected — see
/// [`lockout_risks`] for what "would be blocked" means.
///
/// Reads the log **live**, every time, when asked to read, and from
/// wherever `LogPaths` says it is: a stored `set-log-paths --ssh-log` used
/// to be ignored here, so a host with its log elsewhere had a guard that
/// could never run. The journal is read back a week, not whole. It is the
/// one guard between a keypress and a server that can no longer be
/// reached, and a cached copy could be minutes old.
pub fn check_lockout(rules: &[FirewallRule], log: SshLog<'_>) -> Guard {
    let connected = match log {
        SshLog::Read(source) => match source.read(sshlog::recent_since()) {
            sshlog::LogSource::Found(text) => Some(sshlog::parse_accepted_ips(&text)),
            sshlog::LogSource::Unavailable => None,
        },
        SshLog::Text(text) => text.map(sshlog::parse_accepted_ips),
        SshLog::Connected(connected) => connected.map(<[String]>::to_vec),
    };
    match connected {
        Some(connected) => Guard::Ran(lockout_risks(rules, &connected)),
        None => Guard::LogUnreadable,
    }
}

/// A firewall script rendered for one backend, ready to write to disk.
#[derive(Debug)]
pub struct BuiltFirewall {
    /// Every rule that went into `script`: admin-managed rules followed by
    /// derived crawler/geo rules, in the exact order they were rendered —
    /// feed this to [`check_lockout`] so the safety check evaluates
    /// the same order the script itself will.
    pub rules: Vec<FirewallRule>,
    pub script: String,
    /// How many entries `script` puts in the kernel: set elements on
    /// nftables, chain rules (IPv4 and IPv6 together) on iptables. Excludes
    /// disabled and already-expired rules, and on nftables an address
    /// inside a range with the same verdict that lasts at least as long —
    /// see [`loaded_entries`].
    pub written: usize,
}

/// Every rule currently in effect — the Allows that nothing may override
/// ([`ssh_allow_rules`], then [`trusted_allow_rules`]), then admin-managed
/// rules (from [`Db::list_firewall_rules`]), then derived crawler/geo rules
/// (from [`derived_firewall_rules`]) — in the same order [`build_script`]
/// renders them. Factored out so [`build_script`] and the Dashboard's
/// "needs updating" staleness check ([`rules_signature`]) share one
/// gathering implementation and can never drift out of sync with each
/// other.
pub fn all_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    let mut rules = ssh_allow_rules(db)?;
    rules.extend(trusted_allow_rules(db)?);
    rules.extend(db.list_firewall_rules()?);
    let derived = derived_firewall_rules(db)?;
    if !derived.is_empty() {
        rules.extend(private_allow_rules());
    }
    rules.extend(derived);
    Ok(rules)
}

/// Loopback, RFC1918, link-local and unique-local: the source addresses
/// [`ipranges::is_local_or_private`] calls "this host or its own network,
/// never an internet scanner". Shared with `nftables`, whose forward chain
/// accepts the same set before any rule is consulted.
pub const PRIVATE_RANGES: [&str; 7] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1",
    "fc00::/7",
];

/// An Allow for every [`PRIVATE_RANGES`] entry, placed after the admin's
/// own rules and before the derived ones.
///
/// **Why.** A container talking to a service on its own host arrives on
/// the *input* hook from a Docker bridge address (172.17.0.0/16 and
/// friends), and so does every client on the LAN. Two kinds of derived
/// rule dropped all of them the moment the script was applied: a
/// reputation feed that lists private space as bogons (FireHOL level 1
/// carries 172.16.0.0/12), and the allow-list catch-all, `0.0.0.0/0 drop`.
/// Found on a real host whose NGINX container could no longer reach a
/// service on the host — the SYNs were dropped before ufw ever saw them,
/// because this table's input chain runs at `filter - 1`. The forward
/// chain never had the problem: it accepts private sources outright.
///
/// **Why here, and not at the top of the input chain like forward.** An
/// accept ahead of everything would also silence an operator who blocks a
/// private range on purpose ("keep 10.0.5.0/24 off this host"). Placed
/// after the admin rules, explicit intent still wins; only what a
/// downloaded list or a geo mode decided — neither of which can know
/// anything about a private address — is kept off them. Private addresses
/// have no country, and no public feed has an opinion about your LAN.
///
/// **Why only when there are derived rules.** Nothing else comes after
/// them to be shielded from, and a host with no rules at all must still
/// render none: `health` reads "0 generated" as "nothing to enforce yet",
/// and seven always-present rules would make every fresh host report
/// generated rules that never reached the kernel.
pub fn private_allow_rules() -> Vec<FirewallRule> {
    PRIVATE_RANGES
        .iter()
        .map(|address| FirewallRule {
            id: 0,
            address: address.to_string(),
            port: None,
            action: FirewallAction::Allow,
            enabled: true,
            expires_at: None,
            source: Some(RuleSource::Private),
            created_at: None,
            evidence: None,
        })
        .collect()
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
            source: Some(RuleSource::SshLogin),
            created_at: None,
            evidence: Some("a successful SSH login in the last week".to_string()),
        })
        .collect())
}

/// An Allow rule for every address an operator has trusted by hand (see
/// [`Db::trust_address`]). Synthetic and first-placed for exactly the
/// reasons [`ssh_allow_rules`] gives: a trusted address inside a
/// reputation /24, a country an allowlist excludes, or a Block row a
/// detector wrote before it was trusted is still let through, because the
/// Allow is evaluated before any of them.
pub fn trusted_allow_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    Ok(db
        .list_trusted_addresses()?
        .into_iter()
        .map(|address| FirewallRule {
            id: 0,
            address,
            port: None,
            action: FirewallAction::Allow,
            enabled: true,
            expires_at: None,
            source: Some(RuleSource::Trusted),
            created_at: None,
            evidence: None,
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
        hasher.update(rendered_fields(rule).as_bytes());
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

/// The part of `rule` a script is rendered from, spelled exactly as
/// `FirewallRule`'s `Debug` was before 0.1 added its source, creation time
/// and evidence.
///
/// Those three explain a rule; they change nothing in the script. Hashing
/// them would mark every host's script stale on upgrade, and again each
/// time a rule's evidence was filled in, for a render that writes the same
/// bytes. Keeping the old spelling means a signature stored by 0.0.x
/// still matches the same rules now.
fn rendered_fields(rule: &FirewallRule) -> String {
    format!(
        "FirewallRule {{ id: {:?}, address: {:?}, port: {:?}, action: {:?}, enabled: {:?}, \
         expires_at: {:?} }}",
        rule.id, rule.address, rule.port, rule.action, rule.enabled, rule.expires_at
    )
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
/// `backend`, as of now. Fails immediately, before gathering or rendering
/// anything, if `backend` is iptables and geo mode is Allowlist — see the
/// message below for why.
pub fn build_script(db: &Db, backend: FirewallBackend) -> Result<BuiltFirewall> {
    build_script_at(db, backend, now_secs())
}

/// [`build_script`] as of `now` (Unix seconds), which is what the timeouts
/// in an nftables script count from.
///
/// A rule that has already expired at `now` is dropped from
/// [`BuiltFirewall::rules`] as well as from the script, so the lockout
/// guard, which is fed those rules, judges exactly what will be loaded.
/// An expired Allow it still counted would pass a script that no longer
/// has it.
pub fn build_script_at(db: &Db, backend: FirewallBackend, now: i64) -> Result<BuiltFirewall> {
    if db.get_geo_mode()? == GeoMode::Allowlist && matches!(backend, FirewallBackend::Iptables) {
        anyhow::bail!(
            "Allowlist geo mode requires --backend nftables. Its catch-all makes the host \
             default-deny, and only the nftables script lets private sources through on the \
             forward path before any rule is consulted, so that containers keep their network. \
             The iptables script evaluates one chain for both paths."
        );
    }

    let mut rules = all_rules(db)?;
    rules.retain(|rule| rule.expires_at.is_none_or(|at| at > now));

    let script = match backend {
        FirewallBackend::Iptables => iptables::render(&rules, now),
        FirewallBackend::Nftables => nftables::render(&rules, now),
    };
    let written = loaded_entries(&rules, backend, now);

    Ok(BuiltFirewall {
        rules,
        script,
        written,
    })
}

/// How many entries a script rendered from `rules` at `now` puts in the
/// kernel: what `status` should find loaded once it has been applied.
///
/// Not `rules.len()`. On nftables an address inside a range with the same
/// verdict that lasts at least as long is left out of the set, because the
/// range already decides it — a host with overlapping feeds has many of
/// those — and disabled and expired rules are never loaded on either
/// backend.
pub fn loaded_entries(rules: &[FirewallRule], backend: FirewallBackend, now: i64) -> usize {
    match backend {
        FirewallBackend::Iptables => iptables::loaded_entries(rules, now),
        FirewallBackend::Nftables => nftables::loaded_entries(rules, now),
    }
}

/// The current time in Unix seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Writes a rendered script to `out`, creating any missing parent
/// directories first. Plain `std::fs::write` doesn't create parents, and
/// `DEFAULT_OUTPUT_PATH` (`/etc/stop-bots/`) has no other code path that
/// creates it — unlike the database's `/var/lib/stop-bots`, which
/// `open_or_fallback` creates — so without this, writing to the default
/// path fails with "No such file or directory" on any host where an admin
/// hasn't already `mkdir`ed it, including the internal cron's unattended
/// `RenderFirewall` job, which has no human present to react to the error.
///
/// **Written aside and renamed into place, never written in place.** The
/// file this produces is run as root by [`apply_script`], so the write is
/// the step an attacker with a foothold would aim at. `fs::write` followed
/// a symlink planted at `out` and truncated whatever it pointed to — a
/// root-owned file of the attacker's choosing. Now the script goes to a
/// freshly created (`O_EXCL`, random name) file in the same directory, is
/// flushed to disk, and is renamed over `out`, which replaces a link rather
/// than following it and means nothing ever sees half a script. The mode an
/// existing script had is kept; a new one gets the mode `fs::write` gave
/// it.
///
/// **And not at all into a directory someone else could write** — see
/// [`unsafe_script_directory`]. Whoever can write the directory can swap
/// the script between this write and root running it, and no care taken
/// over the write itself can prevent that.
pub fn write_script(out: &Path, script: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let dir = match out.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir)?;
    let meta = std::fs::metadata(dir)?;
    // SAFETY: neither call has preconditions; both only read the
    // process's own credentials.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if let Some(why) = unsafe_script_directory(meta.uid(), meta.gid(), meta.mode(), euid, egid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to write the firewall script into {}: it is {why}, who could \
                 replace the script before it is applied as root. Write it somewhere only \
                 root can change (the default is {}), or fix the directory's owner and mode",
                dir.display(),
                DEFAULT_OUTPUT_PATH
            ),
        ));
    }

    // The existing script's mode, not its link's target's: a planted
    // symlink should not get to choose the mode either.
    let mode = std::fs::symlink_metadata(out)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.permissions().mode() & 0o7777);
    let name = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (tmp_path, mut tmp) = create_exclusive(dir, &name)?;
    let written = (|| {
        if let Some(mode) = mode {
            tmp.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        tmp.write_all(script.as_bytes())?;
        tmp.sync_all()?;
        std::fs::rename(&tmp_path, out)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    written?;
    // The rename itself is only durable once the directory is flushed. A
    // failure here costs durability across a crash, not correctness, so it
    // is not worth failing a write that has already happened.
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());

    /// A new file beside the script, created with `O_EXCL` under a random
    /// name so nothing already there — a planted link included — can be
    /// opened in its place. 0666 before the umask, as `fs::write` would.
    fn create_exclusive(
        dir: &Path,
        name: &str,
    ) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
        use rand::TryRng;
        let mut last = None;
        for _ in 0..8 {
            let mut suffix = [0u8; 8];
            rand::rngs::SysRng
                .try_fill_bytes(&mut suffix)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
            let path = dir.join(format!(".{name}.{hex}.tmp"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o666)
                .open(&path)
            {
                Ok(file) => return Ok((path, file)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no free temporary name")))
    }
    Ok(())
}

/// Why a directory owned by `uid`:`gid` with `mode` is not a safe place for
/// a script root will run, or `None` if it is.
///
/// Anyone who can write the directory can rename a different file over
/// the script after it is written. So the owner must be root or this
/// process — nobody else — and nobody else may be able to write it either:
/// not other users, and not a group this process is not the primary group
/// of. The sticky bit (`/tmp`) is the exception, because it stops anyone
/// but a file's owner from renaming over it.
///
/// The group rule is what lets an ordinary user's own `0775` directory
/// through — the default under `umask 002`, where the group is the user's
/// own — while still refusing `root:adm 0775`.
fn unsafe_script_directory(uid: u32, gid: u32, mode: u32, euid: u32, egid: u32) -> Option<String> {
    const STICKY: u32 = 0o1000;
    if uid != 0 && uid != euid {
        return Some(format!("owned by uid {uid}"));
    }
    if mode & STICKY != 0 {
        return None;
    }
    if mode & 0o002 != 0 {
        return Some("writable by every user".to_string());
    }
    if mode & 0o020 != 0 && gid != egid {
        return Some(format!("writable by group {gid}"));
    }
    None
}

/// Actually enforces a just-written script by running `backend`'s apply
/// command (`sh <out>` for iptables, `nft -f <out>` for nftables — see
/// [`FirewallBackend::apply_command`]) against it. This is the one place in
/// the whole project that executes a generated firewall script rather than
/// only ever writing it, and it has exactly one caller: [`execute`], which
/// runs it only after the lockout guard has passed (or been forced past)
/// and only for a front-end that was asked to apply — see [`FirewallRun`]
/// for the policy and who asks.
///
/// So `README.md`'s "generated, never applied *automatically*" holds in the
/// sense that matters: nothing applies a script without an operator having
/// asked for it, whether by pressing a key or by putting `--apply` in a
/// crontab. It does not hold in the sense of "a human is looking".
///
/// Both programs are found through [`crate::host::program`], and the
/// child gets [`crate::host::path_with_sbin`]: under an `/etc/cron.d`
/// entry `PATH` is `/usr/bin:/bin`, which has neither `nft` nor the
/// `iptables` every line of the iptables script runs.
///
/// Holds [`crate::applylock`] while the script runs, so the TUI, the
/// console and a cron `batch` never run two scripts over the same table at
/// once; a second one waits briefly, then says another is applying.
pub fn apply_script(backend: FirewallBackend, out_path: &Path) -> Result<()> {
    let _lock = crate::applylock::hold()?;
    let (program, args, what): (_, &[&str], _) = match backend {
        FirewallBackend::Iptables => (
            "sh",
            &[],
            "failed to run `sh` on the generated iptables script",
        ),
        FirewallBackend::Nftables => (
            "nft",
            &["-f"],
            "failed to run `nft -f` on the generated nftables script",
        ),
    };
    let output = std::process::Command::new(crate::host::program(program))
        .args(args)
        .arg(out_path)
        .env("PATH", crate::host::path_with_sbin())
        .output()
        .map_err(|err| {
            let hint = missing_program_hint(backend, err.kind());
            let err = anyhow::Error::new(err).context(what);
            match hint {
                Some(hint) => crate::hint::with(err, hint),
                None => err,
            }
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "{} exited with {}: {}{}",
            backend.apply_command(),
            output.status,
            stderr.trim(),
            failure_hint(backend, &stderr, crate::hint::is_root())
        );
    }
    Ok(())
}

// ---- the one path: render, guard, write, apply ----

/// Where the script a render writes goes, beside the `applied` one.
///
/// **Two files, because a reboot must not enforce what nobody applied.**
/// `stop-bots-firewall.service` loads the applied script at boot. Every
/// front-end used to write straight to that file, the internal cron
/// included, whether or not anyone then applied it — so a detector's block,
/// written at 3am and never applied, went live at the next reboot. A render
/// now writes `firewall.next.nft` (or `.next.sh`); only an apply that
/// succeeded copies it over `firewall.nft`.
///
/// The applied path keeps the name every existing unit, `include` line and
/// habit already points at. Moving the *rendered* one is what changes
/// nothing for a host that upgrades.
pub fn rendered_path(applied: &Path) -> std::path::PathBuf {
    let stem = applied
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = match applied.extension() {
        Some(ext) => format!("{stem}.next.{}", ext.to_string_lossy()),
        None => format!("{stem}.next"),
    };
    applied.with_file_name(name)
}

/// One run of the firewall path, as a front-end asks for it.
///
/// ## The policy, which every front-end shares
///
/// - **Writing** the rendered script is allowed when no SSH log could be
///   read. The outcome carries the note, and a written script is inert:
///   nothing loads it, at boot or otherwise, until an apply.
/// - **Writing is refused** when the guard ran and found that a connected
///   SSH client would be blocked, unless `force`. A script that would lock
///   the operator out is not worth reviewing, and one that is on disk gets
///   run by hand.
/// - **Applying is refused** when the log could not be read, or when a
///   connected client would be blocked, unless `force`. "The check could
///   not run" is not "the check passed", whoever is watching.
/// - **An apply runs the rendered script and then promotes it** to
///   `applied_path`, the file the boot unit loads. A failed apply promotes
///   nothing.
/// - **The rendered signature is recorded on every write, the applied one
///   on every apply** (see [`record`]); a dry run records neither.
///
/// Five front-ends used to implement this themselves and handled "no SSH
/// log" four different ways: the TUI refused to write, the console wrote
/// but would not apply, the cron wrote without applying, `batch` bailed,
/// and `render-firewall` printed a note and recorded no signature.
#[derive(Debug, Clone)]
pub struct FirewallRun {
    pub backend: FirewallBackend,
    /// The applied script: what the boot unit loads, and what an apply
    /// replaces.
    pub applied_path: std::path::PathBuf,
    /// Where the rendered script is written. [`rendered_path`] of
    /// `applied_path` unless the operator named a file
    /// (`render-firewall --out`).
    pub rendered_path: std::path::PathBuf,
    /// Whether to run the script once it is written.
    pub apply: bool,
    /// Whether this process may really run `nft`/`sh`. `false` under
    /// `--no-apply`/`--no-reload` and in tests, where an apply that the
    /// guard allowed stops short and says so.
    pub for_real: bool,
    /// Past the guard's refusals, for someone who knows.
    pub force: bool,
    /// Decide and describe everything, and write, run and record nothing.
    pub dry_run: bool,
}

impl FirewallRun {
    /// A write-only run for `backend`, applied path `applied_path`.
    pub fn new(backend: FirewallBackend, applied_path: impl Into<std::path::PathBuf>) -> Self {
        let applied_path = applied_path.into();
        FirewallRun {
            backend,
            rendered_path: rendered_path(&applied_path),
            applied_path,
            apply: false,
            for_real: true,
            force: false,
            dry_run: false,
        }
    }

    pub fn apply(self, apply: bool) -> Self {
        FirewallRun { apply, ..self }
    }

    pub fn for_real(self, for_real: bool) -> Self {
        FirewallRun { for_real, ..self }
    }

    pub fn force(self, force: bool) -> Self {
        FirewallRun { force, ..self }
    }

    pub fn dry_run(self, dry_run: bool) -> Self {
        FirewallRun { dry_run, ..self }
    }

    /// Writes the rendered script to `path` rather than beside the applied
    /// one.
    pub fn rendered_at(self, path: impl Into<std::path::PathBuf>) -> Self {
        FirewallRun {
            rendered_path: path.into(),
            ..self
        }
    }
}

/// A run with every database read done, so the rest can happen where no
/// `Db` may go — the TUI's worker thread, or outside the console's lock.
#[derive(Debug)]
pub struct Prepared {
    pub run: FirewallRun,
    pub built: BuiltFirewall,
    /// [`rules_signature`] of `built.rules`, for [`record`].
    pub signature: String,
}

/// Reads and renders: the database half of a run. Fails before anything
/// is checked or written if the rules cannot be rendered for this backend
/// at all (see [`build_script`]).
pub fn prepare(db: &Db, run: FirewallRun) -> Result<Prepared> {
    let built = build_script(db, run.backend)?;
    let signature = rules_signature(&built.rules);
    Ok(Prepared {
        run,
        built,
        signature,
    })
}

/// What happened to the rendered script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStep {
    /// Written (or, in a dry run, would be).
    Written,
    /// The guard found a connected client the rules would block.
    Refused,
    Failed(String),
}

/// What happened to the apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyStep {
    /// Nobody asked for one.
    NotAsked,
    /// The guard could not run, or found a risk — [`FirewallOutcome::guard`]
    /// says which.
    Refused,
    /// The write before it did not happen.
    NotReached,
    /// Allowed, but this process may not change the host (`--no-apply`).
    NotForReal,
    /// Ran, and the script is now the one loaded at boot (or, in a dry run,
    /// would be).
    Applied,
    /// Ran, but copying it over the applied script failed, so a reboot
    /// loads the previous one.
    AppliedNotSaved(String),
    Failed(String),
}

/// Rules the rendered script adds and removes against the applied one.
///
/// Compared as rules, not as text: an element's `timeout` counts down from
/// the moment it is rendered, so every timed block's line differs between
/// two renders a minute apart even though nothing changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Whether there was an applied script to compare with at all.
    pub baseline: bool,
}

/// Everything one run did, for a front-end to put into words.
#[derive(Debug, Clone)]
pub struct FirewallOutcome {
    pub backend: FirewallBackend,
    pub rendered_path: std::path::PathBuf,
    pub applied_path: std::path::PathBuf,
    /// Rules in the script, the Allows ahead of everything included.
    pub rules: usize,
    /// What the script puts in the kernel — see [`loaded_entries`].
    pub entries: usize,
    pub signature: String,
    pub guard: Guard,
    /// Whether `force` was set: a refusal it overrode is still worth saying.
    pub forced: bool,
    pub dry_run: bool,
    pub change: RuleChange,
    pub write: WriteStep,
    pub apply: ApplyStep,
    /// The rendered script, and the applied one it would replace, for a
    /// diff on request.
    pub script: String,
    pub previous: Option<String>,
}

/// The half of a run that touches no database: the guard, the write, the
/// apply and the promotion, by the policy on [`FirewallRun`].
pub fn execute(prepared: Prepared, ssh_log: SshLog<'_>) -> FirewallOutcome {
    let Prepared {
        run,
        built,
        signature,
    } = prepared;
    let guard = check_lockout(&built.rules, ssh_log);
    let previous = std::fs::read_to_string(&run.applied_path).ok();
    let change = rule_change(previous.as_deref(), &built.script);

    let may_write = guard.risks().is_empty() || run.force;
    let may_apply = guard.passed() || run.force;

    // One apply at a time across processes, held from writing the script
    // to copying it over the applied one: otherwise another apply's write
    // can land between this one's write and its `nft -f`, and the kernel
    // and the boot script end up with different rules. Only when this run
    // will really apply; a render alone takes no lock. `apply_script`
    // takes it again below, which on the same thread is free.
    let will_apply = run.apply && may_apply && may_write && run.for_real && !run.dry_run;
    let mut busy = None;
    let _lock = if will_apply {
        match crate::applylock::hold() {
            Ok(lock) => Some(lock),
            Err(err) => {
                busy = Some(format!("{err:#}"));
                None
            }
        }
    } else {
        None
    };

    let write = if !may_write {
        WriteStep::Refused
    } else if run.dry_run {
        WriteStep::Written
    } else {
        match write_script(&run.rendered_path, &built.script) {
            Ok(()) => WriteStep::Written,
            Err(err) => WriteStep::Failed(format!(
                "could not write {}: {err}",
                run.rendered_path.display()
            )),
        }
    };

    let apply = if !run.apply {
        ApplyStep::NotAsked
    } else if !may_apply {
        ApplyStep::Refused
    } else if write != WriteStep::Written {
        ApplyStep::NotReached
    } else if !run.for_real {
        ApplyStep::NotForReal
    } else if run.dry_run {
        ApplyStep::Applied
    } else if let Some(busy) = busy {
        ApplyStep::Failed(busy)
    } else {
        match apply_script(run.backend, &run.rendered_path) {
            Err(err) => ApplyStep::Failed(format!("{err:#}")),
            Ok(()) if run.rendered_path == run.applied_path => ApplyStep::Applied,
            Ok(()) => match write_script(&run.applied_path, &built.script) {
                Ok(()) => ApplyStep::Applied,
                Err(err) => ApplyStep::AppliedNotSaved(format!(
                    "could not copy it to {}: {err}",
                    run.applied_path.display()
                )),
            },
        }
    };

    FirewallOutcome {
        backend: run.backend,
        rendered_path: run.rendered_path,
        applied_path: run.applied_path,
        rules: built.rules.len(),
        entries: built.written,
        signature,
        guard,
        forced: run.force,
        dry_run: run.dry_run,
        change,
        write,
        apply,
        script: built.script,
        previous,
    }
}

/// Records what `outcome` wrote and applied: the rendered signature on a
/// write, the applied one on an apply. A dry run records nothing.
pub fn record(db: &Db, outcome: &FirewallOutcome) -> Result<()> {
    if outcome.dry_run {
        return Ok(());
    }
    if outcome.write == WriteStep::Written {
        db.set_firewall_rendered_signature(&outcome.signature)?;
    }
    if outcome.applied() {
        db.set_firewall_applied_signature(&outcome.signature)?;
    }
    Ok(())
}

/// The whole path in one call, for a front-end that may hold the `Db`
/// throughout: `render-firewall`, `batch` and the internal cron.
pub fn render_and_apply(db: &Db, run: FirewallRun, ssh_log: SshLog<'_>) -> Result<FirewallOutcome> {
    let outcome = execute(prepare(db, run)?, ssh_log);
    record(db, &outcome)?;
    Ok(outcome)
}

impl FirewallOutcome {
    /// Whether the kernel now holds this script.
    pub fn applied(&self) -> bool {
        !self.dry_run
            && matches!(
                self.apply,
                ApplyStep::Applied | ApplyStep::AppliedNotSaved(_)
            )
    }

    /// Whether the guard refused something — the write or the apply — so a
    /// front-end can say what gets past it there.
    pub fn refused(&self) -> bool {
        self.write == WriteStep::Refused || self.apply == ApplyStep::Refused
    }

    /// Whether everything asked for happened. A refusal is not a success:
    /// `batch` exits non-zero on it, which is what makes cron mail someone.
    pub fn succeeded(&self) -> bool {
        self.write == WriteStep::Written
            && matches!(
                self.apply,
                ApplyStep::NotAsked | ApplyStep::NotForReal | ApplyStep::Applied
            )
    }

    /// Why the apply (or the write) was refused. What gets past it differs
    /// by front-end — a flag, a setting, nothing at all — so each adds its
    /// own; see [`FirewallOutcome::refused`].
    fn refusal(&self) -> String {
        match &self.guard {
            Guard::LogUnreadable => {
                "no SSH log could be read, so the lockout check could not run".to_string()
            }
            Guard::Ran(risks) => format!(
                "it would block {} connected SSH client(s): {}",
                risks.len(),
                risks
                    .iter()
                    .map(|(ip, rule)| format!("{ip} (blocked by {rule})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// `+3 / -1 rule(s) against the applied script`, or why there is no
    /// comparison.
    pub fn change_summary(&self) -> String {
        if !self.change.baseline {
            return format!(
                "no applied script at {} yet, so all of it is new",
                self.applied_path.display()
            );
        }
        if self.change.added.is_empty() && self.change.removed.is_empty() {
            return format!("same rules as the applied {}", self.applied_path.display());
        }
        format!(
            "+{} / -{} against the applied {}",
            self.change.added.len(),
            self.change.removed.len(),
            self.applied_path.display()
        )
    }

    /// One line, for a status message, a flash or a cron summary.
    pub fn summary(&self) -> String {
        let (wrote, refused) = if self.dry_run {
            ("would write", "would not write")
        } else {
            ("wrote", "did not write")
        };
        let rendered = self.rendered_path.display();
        let applied = self.applied_path.display();
        let mut out = match &self.write {
            WriteStep::Written => format!("{wrote} {} rule(s) to {rendered}", self.entries),
            WriteStep::Refused => format!("{refused} {rendered}: {}", self.refusal()),
            WriteStep::Failed(err) => err.clone(),
        };
        match &self.apply {
            ApplyStep::NotAsked => {
                if self.write == WriteStep::Written {
                    out.push_str(
                        "; not applied — review it, then apply it (\u{201c}Apply everything\u{201d} \
                         or `stop-bots render-firewall --apply`)",
                    );
                }
            }
            ApplyStep::Refused if self.write == WriteStep::Refused => {}
            ApplyStep::Refused => out.push_str(&format!(
                "; {}: {}",
                if self.dry_run {
                    "would not be applied"
                } else {
                    "not applied"
                },
                self.refusal()
            )),
            ApplyStep::NotReached => out.push_str("; not applied"),
            ApplyStep::NotForReal => out.push_str("; not applied: --no-apply"),
            ApplyStep::Applied => out.push_str(&format!(
                "; {}applied, and {applied} is what loads at boot",
                if self.dry_run { "would be " } else { "" }
            )),
            ApplyStep::AppliedNotSaved(err) => out.push_str(&format!(
                "; applied, but {err}, so a reboot loads the previous rules"
            )),
            ApplyStep::Failed(err) => out.push_str(&format!("; applying failed: {err}")),
        }
        if self.write == WriteStep::Written && self.guard == Guard::LogUnreadable {
            if self.forced && self.applied() {
                out.push_str(". Forced past a lockout check that could not run");
            } else if self.apply == ApplyStep::NotAsked {
                out.push_str(". Note: no SSH log could be read, so the lockout check did not run");
            }
        }
        out
    }

    /// The whole story, a line each, for a preview or `--verbose`.
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!(
                "Firewall ({}): {} rule(s), {} kernel entries; {}",
                self.backend.stored(),
                self.rules,
                self.entries,
                self.change_summary()
            ),
            format!(
                "{}{}",
                self.guard.describe(),
                if self.forced && !self.guard.passed() {
                    " — overridden by --force"
                } else {
                    ""
                }
            ),
            self.summary(),
        ]
    }

    /// The rendered script against the applied one, as a unified diff.
    pub fn diff(&self) -> String {
        crate::diff::unified(
            self.previous.as_deref(),
            Some(&self.script),
            &self.applied_path.display().to_string(),
            &self.rendered_path.display().to_string(),
        )
    }
}

/// The rules a script loads, one comparable string each: set elements
/// (`block_v4 192.0.2.7`) and rules (`add rule …`, `-A …`), with an
/// element's `timeout` left off. Structural lines are the same in every
/// render of one backend, so comparing them costs nothing and cancels out.
fn rule_lines(script: &str) -> std::collections::BTreeSet<String> {
    let mut lines = std::collections::BTreeSet::new();
    let mut set: Option<&str> = None;
    for line in script.lines().map(str::trim) {
        if let Some(name) = set {
            if line == "}" {
                set = None;
                continue;
            }
            let element = line.trim_end_matches(',');
            let element = element.split(" timeout ").next().unwrap_or(element);
            lines.insert(format!("{name} {element}"));
        } else if let Some(rest) = line.strip_prefix("add element ") {
            // `add element inet stop_bots block_v4 {`
            set = rest.split_whitespace().nth(2);
        } else if line.starts_with("add rule ") || line.starts_with("-A ") {
            lines.insert(line.to_string());
        }
    }
    lines
}

/// [`RuleChange`] between an applied script (if there is one) and `new`.
pub fn rule_change(applied: Option<&str>, new: &str) -> RuleChange {
    let Some(applied) = applied else {
        return RuleChange {
            added: rule_lines(new).into_iter().collect(),
            removed: Vec::new(),
            baseline: false,
        };
    };
    let (old, new) = (rule_lines(applied), rule_lines(new));
    RuleChange {
        added: new.difference(&old).cloned().collect(),
        removed: old.difference(&new).cloned().collect(),
        baseline: true,
    }
}

/// Where the rules stand against what was rendered and what was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScriptState {
    /// The rules are the ones last applied.
    Applied,
    /// Rendered to the `.next` script, and not applied since.
    RenderedNotApplied,
    /// Changed since the last render too — and what a screen shows before
    /// it has looked.
    #[default]
    Changed,
}

/// Where this host's rules stand — the Dashboard's "script" row in both
/// front-ends and `status`'s `script-fresh` check. Compares signatures the
/// app recorded, never file contents, so it works the same whatever path
/// or backend a run used.
///
/// A database from before the applied signature existed has none, and
/// reads as not applied until the first apply: nothing recorded what, if
/// anything, the kernel was given.
pub fn script_state(db: &Db) -> Result<ScriptState> {
    let current = rules_signature(&all_rules(db)?);
    Ok(
        if db.get_firewall_applied_signature()?.as_deref() == Some(current.as_str()) {
            ScriptState::Applied
        } else if db.get_firewall_rendered_signature()?.as_deref() == Some(current.as_str()) {
            ScriptState::RenderedNotApplied
        } else {
            ScriptState::Changed
        },
    )
}

/// What to do when the apply program itself is missing: for nftables,
/// `nft` is not installed; `sh` always is.
fn missing_program_hint(
    backend: FirewallBackend,
    kind: std::io::ErrorKind,
) -> Option<&'static str> {
    match (backend, kind) {
        (FirewallBackend::Nftables, std::io::ErrorKind::NotFound) => Some(
            "`nft` isn't installed. Install the `nftables` package, or switch to iptables \
             with `stop-bots set-firewall-backend iptables`.",
        ),
        _ => None,
    }
}

/// The next step for an apply that ran and failed, if the output names
/// one: not root, the iptables tools missing, or a sandboxed service
/// ([`sandbox_hint`]).
fn failure_hint(backend: FirewallBackend, stderr: &str, root: bool) -> &'static str {
    let denied = stderr.contains("Operation not permitted") || stderr.contains("Permission denied");
    if denied && !root {
        return "\n\nChanging the firewall needs root. Run it with sudo.";
    }
    let missing = stderr.contains(": not found") || stderr.contains("command not found");
    if backend == FirewallBackend::Iptables && missing && stderr.contains("iptables") {
        return "\n\nThe iptables tools aren't installed. Install the `iptables` package, \
                or switch to nftables with `stop-bots set-firewall-backend nftables`.";
    }
    sandbox_hint(stderr)
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
            source: None,
            created_at: None,
            evidence: None,
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
            source: crate::db::RuleSource::Cli,
            evidence: None,
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

    /// The bug that took a real host's containers off its own services: the
    /// allow-list catch-all and a feed listing private space both dropped a
    /// Docker bridge address arriving on the input hook.
    #[test]
    fn a_private_source_gets_past_every_derived_rule() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();

        let rules = all_rules(&db).unwrap();

        for source in ["172.22.0.5", "192.168.1.10", "10.1.2.3", "fd00::5"] {
            assert!(
                lockout_risks(&rules, &[source.to_string()]).is_empty(),
                "{source} was dropped by: {rules:?}"
            );
        }
        assert_eq!(
            lockout_risks(&rules, &["198.51.100.1".to_string()]).len(),
            1,
            "a public address outside the allow-list must still be dropped"
        );
    }

    /// Explicit intent still wins: the accepts go after the admin's rules.
    #[test]
    fn an_admin_block_of_a_private_range_still_applies() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "10.0.5.0/24".to_string(),
            port: None,
            action: FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();

        let rules = all_rules(&db).unwrap();

        assert_eq!(
            lockout_risks(&rules, &["10.0.5.9".to_string()]),
            vec![("10.0.5.9".to_string(), "10.0.5.0/24".to_string())]
        );
    }

    /// A host with nothing derived renders nothing extra, so `status` can
    /// still say "no rules to enforce yet" rather than reporting seven
    /// synthetic rules missing from the kernel.
    #[test]
    fn with_nothing_derived_no_private_accepts_are_written() {
        let db = Db::open_in_memory().unwrap();
        assert!(all_rules(&db).unwrap().is_empty());
    }

    /// The address-level half of "never block this": whatever else the
    /// rules say about a trusted address — a Block row, a derived range
    /// containing it, an allowlist catch-all — an Allow ahead of all of
    /// them wins.
    #[test]
    fn a_trusted_address_gets_past_every_kind_of_block() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();
        db.add_firewall_rule(&crate::db::NewFirewallRule {
            address: "198.51.100.0/24".to_string(),
            port: None,
            action: FirewallAction::Block,
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        db.trust_address("198.51.100.0/28").unwrap();

        let rules = all_rules(&db).unwrap();

        assert!(
            lockout_risks(&rules, &["198.51.100.9".to_string()]).is_empty(),
            "a trusted address was still blocked by: {rules:?}"
        );
        assert_eq!(
            lockout_risks(&rules, &["198.51.100.99".to_string()]).len(),
            1,
            "trust leaked past the range that was trusted"
        );
    }

    /// Trusting something is a change to the rules, so the Dashboard has
    /// to say the script needs rendering again.
    #[test]
    fn trusting_an_address_changes_the_rules_signature() {
        let db = Db::open_in_memory().unwrap();
        let before = rules_signature(&all_rules(&db).unwrap());
        db.trust_address("203.0.113.7").unwrap();
        assert_ne!(before, rules_signature(&all_rules(&db).unwrap()));
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
            source: crate::db::RuleSource::Cli,
            evidence: None,
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

    /// The reviewer's probe. The Allow renders as `tcp dport 443 accept`,
    /// which an SSH packet does not match, so it falls through to the
    /// catch-all and is dropped — and the guard has to say so.
    #[test]
    fn a_port_scoped_allow_does_not_protect_ssh() {
        let rules = vec![
            FirewallRule {
                port: Some(443),
                ..rule("203.0.113.0/24", FirewallAction::Allow)
            },
            rule("0.0.0.0/0", FirewallAction::Block),
        ];

        assert_eq!(
            lockout_risks(&rules, &["203.0.113.5".to_string()]),
            vec![("203.0.113.5".to_string(), "0.0.0.0/0".to_string())]
        );
    }

    /// Not even on 22: nothing here knows which port sshd listens on, and
    /// an Allow only counts if it provably covers SSH. Wrongly warning
    /// costs an operator a second look; wrongly passing costs them the
    /// host.
    #[test]
    fn an_allow_on_port_22_is_not_taken_as_protecting_ssh_either() {
        let rules = vec![
            FirewallRule {
                port: Some(22),
                ..rule("203.0.113.0/24", FirewallAction::Allow)
            },
            rule("0.0.0.0/0", FirewallAction::Block),
        ];

        assert_eq!(lockout_risks(&rules, &["203.0.113.5".to_string()]).len(), 1);
    }

    /// The conservative direction for a Block is the opposite one: a
    /// port-scoped Block may be on exactly the port sshd uses, so it
    /// still counts.
    #[test]
    fn a_port_scoped_block_still_counts_as_a_risk() {
        let rules = vec![crate::testing::block_port("203.0.113.0/24", 2222)];

        assert_eq!(
            lockout_risks(&rules, &["203.0.113.5".to_string()]),
            vec![("203.0.113.5".to_string(), "203.0.113.0/24".to_string())]
        );
    }

    #[test]
    fn the_guard_reports_risks_from_the_log_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 4.5.6.7 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert_eq!(
            check_lockout(&rules, SshLog::Read(&sshlog::SshSource::File(log_path))),
            Guard::Ran(vec![("4.5.6.7".to_string(), "4.5.6.0/24".to_string())])
        );
    }

    #[test]
    fn the_guard_cannot_run_on_a_nonexistent_log() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        let guard = check_lockout(
            &rules,
            SshLog::Read(&sshlog::SshSource::File("/nonexistent/x.log".into())),
        );
        assert_eq!(guard, Guard::LogUnreadable);
        assert!(!guard.passed(), "a guard that could not run has not passed");
    }

    #[test]
    fn the_guard_reads_text_it_is_handed() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(check_lockout(&rules, SshLog::Text(Some(""))).passed());
        assert_eq!(
            check_lockout(&rules, SshLog::Text(None)),
            Guard::LogUnreadable
        );
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

    /// The attack: a symlink planted where the script goes, pointing at
    /// something root would not otherwise write. `fs::write` followed it
    /// and truncated the target in place. The link is replaced instead,
    /// and what it pointed at is untouched.
    #[test]
    fn write_script_replaces_a_planted_symlink_rather_than_writing_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        let out = dir.path().join("firewall.nft");
        std::os::unix::fs::symlink(&victim, &out).unwrap();

        write_script(&out, "table inet stop_bots {}\n").unwrap();

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        let meta = std::fs::symlink_metadata(&out).unwrap();
        assert!(meta.is_file(), "{} is still a link", out.display());
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "table inet stop_bots {}\n"
        );
    }

    /// Written aside and renamed into place, so nothing ever sees half a
    /// script — and nothing is left beside it afterwards.
    #[test]
    fn write_script_leaves_nothing_but_the_script_behind() {
        let dir = tempfile::tempdir().unwrap();
        write_script(&dir.path().join("firewall.nft"), "x").unwrap();

        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["firewall.nft".to_string()]);
    }

    /// Replacing the file must not quietly change who may read it.
    #[test]
    fn write_script_keeps_an_existing_scripts_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("firewall.nft");
        std::fs::write(&out, "old").unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o640)).unwrap();

        write_script(&out, "new").unwrap();

        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "mode became {mode:04o}");
    }

    /// Anyone who can write the directory can swap the script between
    /// this write and root running it.
    #[test]
    fn write_script_refuses_a_directory_anyone_can_write_to() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = write_script(&open.join("firewall.nft"), "x").unwrap_err();

        assert!(
            err.to_string().contains("writable by"),
            "the refusal should say why, was: {err}"
        );
        assert!(!open.join("firewall.nft").exists());
    }

    /// Who could replace the script after it is written, decided from the
    /// directory's owner and mode. Pure, because a test cannot `chown` a
    /// directory to somebody else without being root.
    #[test]
    fn which_directories_are_safe_to_write_a_script_into() {
        const ROOT: u32 = 0;
        const ME: u32 = 1000;
        const ALICE: u32 = 1001;
        const ADM: u32 = 4;
        for (what, (uid, gid, mode), (euid, egid), safe) in [
            (
                "/etc/stop-bots as root",
                (ROOT, ROOT, 0o755),
                (ROOT, ROOT),
                true,
            ),
            ("/tmp: sticky", (ROOT, ROOT, 0o1777), (ROOT, ROOT), true),
            ("my own directory", (ME, ME, 0o755), (ME, ME), true),
            ("mine, umask 002", (ME, ME, 0o775), (ME, ME), true),
            (
                "root writing into alice's",
                (ALICE, ALICE, 0o755),
                (ROOT, ROOT),
                false,
            ),
            (
                "world-writable, no sticky",
                (ROOT, ROOT, 0o777),
                (ROOT, ROOT),
                false,
            ),
            (
                "group adm may write",
                (ROOT, ADM, 0o775),
                (ROOT, ROOT),
                false,
            ),
        ] {
            assert_eq!(
                unsafe_script_directory(uid, gid, mode, euid, egid).is_none(),
                safe,
                "{what}: {:?}",
                unsafe_script_directory(uid, gid, mode, euid, egid)
            );
        }
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
            source: crate::db::RuleSource::Cli,
            evidence: None,
        })
        .unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let rules = all_rules(&db).unwrap();
        let addresses: Vec<&str> = rules.iter().map(|r| r.address.as_str()).collect();
        // Admin first, then the private-source accepts, then derived.
        let mut expected = vec!["9.9.9.9"];
        expected.extend(PRIVATE_RANGES);
        expected.push("4.5.6.0/24");
        assert_eq!(addresses, expected);
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

    /// Why a rule exists is not part of the script, so it must not make
    /// the script look stale — and a signature 0.0.x stored must still
    /// match the same rules after the upgrade, which it does only if what
    /// is hashed is spelled as 0.0.x's `Debug` spelled it.
    #[test]
    fn the_signature_ignores_why_a_rule_exists_and_matches_what_0_0_x_stored() {
        let plain = rule("203.0.113.7", FirewallAction::Block);
        let explained = FirewallRule {
            source: Some(RuleSource::Cli),
            created_at: Some(1_790_000_000),
            evidence: Some("GET /.env HTTP/1.1".into()),
            ..plain.clone()
        };

        assert_eq!(
            rules_signature(std::slice::from_ref(&plain)),
            rules_signature(&[explained])
        );
        assert_eq!(
            rendered_fields(&plain),
            "FirewallRule { id: 0, address: \"203.0.113.7\", port: None, action: Block, \
             enabled: true, expires_at: None }"
        );
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
    fn a_missing_nft_says_to_install_it_or_switch_backend() {
        let hint =
            missing_program_hint(FirewallBackend::Nftables, std::io::ErrorKind::NotFound).unwrap();
        assert!(hint.contains("`nftables` package"), "{hint}");
        assert!(hint.contains("set-firewall-backend iptables"), "{hint}");
        assert_eq!(
            missing_program_hint(
                FirewallBackend::Nftables,
                std::io::ErrorKind::PermissionDenied
            ),
            None
        );
    }

    /// Through the real apply: the script is what `sh` runs, and it fails
    /// the way dash does when `iptables-restore` is not there.
    #[test]
    fn a_missing_iptables_restore_says_to_install_it_or_switch_backend() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("firewall.sh");
        std::fs::write(
            &script,
            "echo 'sh: 12: iptables-restore: not found' >&2\nexit 127\n",
        )
        .unwrap();

        let err = apply_script(FirewallBackend::Iptables, &script).unwrap_err();

        let text = err.to_string();
        assert!(text.contains("`iptables` package"), "{text}");
        assert!(text.contains("set-firewall-backend nftables"), "{text}");
    }

    #[test]
    fn a_user_refused_by_the_kernel_is_told_to_use_sudo_and_root_is_not() {
        let stderr = "Error: Could not process rule: Operation not permitted";
        for backend in [FirewallBackend::Nftables, FirewallBackend::Iptables] {
            assert!(failure_hint(backend, stderr, false).contains("sudo"));
            assert!(!failure_hint(backend, stderr, true).contains("sudo"));
        }
    }

    #[test]
    fn an_unrelated_failure_gets_no_hint() {
        assert_eq!(sandbox_hint("nft: command not found"), "");
        assert_eq!(sandbox_hint("Error: syntax error, unexpected newline"), "");
        let syntax = "Error: syntax error, unexpected newline";
        assert_eq!(failure_hint(FirewallBackend::Nftables, syntax, false), "");
    }

    // ---- the one path, and its policy ----

    /// An SSH log in which 4.5.6.7 is connected.
    const CONNECTED: &str = "Accepted publickey for admin from 4.5.6.7 port 12345 ssh2\n";

    /// A database blocking 4.5.6.0/24, and a run for it into `dir`. Never
    /// for real: nothing here may run `nft` on the machine running tests.
    fn blocking_the_admin(dir: &Path) -> (Db, FirewallRun) {
        let db = Db::open_in_memory().unwrap();
        db.block_address_permanently("4.5.6.0/24", crate::db::RuleSource::Tui, None)
            .unwrap();
        let run =
            FirewallRun::new(FirewallBackend::Nftables, dir.join("firewall.nft")).for_real(false);
        (db, run)
    }

    #[test]
    fn the_rendered_script_sits_beside_the_applied_one() {
        for (applied, rendered) in [
            (
                "/etc/stop-bots/firewall.nft",
                "/etc/stop-bots/firewall.next.nft",
            ),
            (
                "/etc/stop-bots/firewall.sh",
                "/etc/stop-bots/firewall.next.sh",
            ),
            ("/srv/rules", "/srv/rules.next"),
        ] {
            assert_eq!(rendered_path(Path::new(applied)), Path::new(rendered));
        }
    }

    /// The policy, as a table: what each guard verdict allows, for a write
    /// and for an apply, with and without `--force`. One place, because
    /// five front-ends used to decide this five ways.
    #[test]
    fn the_guard_decides_the_write_and_the_apply_the_same_way_for_everyone() {
        let unrelated = "Accepted publickey for admin from 9.9.9.9 port 1 ssh2\n";
        let cases = [
            // (what, log, force, write, apply)
            (
                "passed",
                Some(unrelated),
                false,
                WriteStep::Written,
                ApplyStep::NotForReal,
            ),
            (
                "log unreadable",
                None,
                false,
                WriteStep::Written,
                ApplyStep::Refused,
            ),
            (
                "log unreadable, forced",
                None,
                true,
                WriteStep::Written,
                ApplyStep::NotForReal,
            ),
            (
                "would lock out",
                Some(CONNECTED),
                false,
                WriteStep::Refused,
                ApplyStep::Refused,
            ),
            (
                "would lock out, forced",
                Some(CONNECTED),
                true,
                WriteStep::Written,
                ApplyStep::NotForReal,
            ),
        ];
        for (what, log, force, write, apply) in cases {
            let dir = tempfile::tempdir().unwrap();
            let (db, run) = blocking_the_admin(dir.path());
            let run = run.apply(true).force(force);

            let outcome = render_and_apply(&db, run, SshLog::Text(log)).unwrap();

            assert_eq!(outcome.write, write, "{what}: {}", outcome.summary());
            assert_eq!(outcome.apply, apply, "{what}: {}", outcome.summary());
            assert_eq!(
                dir.path().join("firewall.next.nft").exists(),
                write == WriteStep::Written,
                "{what}: the rendered script's existence should follow the write"
            );
            assert!(
                !dir.path().join("firewall.nft").exists(),
                "{what}: nothing was applied, so the boot script must not appear"
            );
        }
    }

    #[test]
    fn a_refusal_says_why_in_the_summary() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());

        let unreadable = render_and_apply(&db, run.clone().apply(true), SshLog::Text(None))
            .unwrap()
            .summary();
        assert!(unreadable.contains("not applied"), "{unreadable}");
        assert!(unreadable.contains("could not run"), "{unreadable}");

        let risky = render_and_apply(&db, run, SshLog::Text(Some(CONNECTED)))
            .unwrap()
            .summary();
        assert!(risky.contains("4.5.6.7 (blocked by 4.5.6.0/24)"), "{risky}");
    }

    /// A write with no apply notes that the check did not run: nothing is
    /// refused, but nothing was checked either.
    #[test]
    fn a_write_the_guard_could_not_check_carries_a_note() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());

        let outcome = render_and_apply(&db, run, SshLog::Text(None)).unwrap();

        assert!(outcome.succeeded(), "{}", outcome.summary());
        assert!(
            outcome.summary().contains("did not run"),
            "{}",
            outcome.summary()
        );
    }

    /// The rendered signature is recorded on every write — including one
    /// the guard could not check, which `render-firewall` used to skip —
    /// and the applied one only on an apply.
    #[test]
    fn a_write_records_the_rendered_signature_and_only_an_apply_the_applied_one() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());

        let outcome = render_and_apply(&db, run.apply(true), SshLog::Text(None)).unwrap();

        assert_eq!(
            db.get_firewall_rendered_signature().unwrap().as_deref(),
            Some(outcome.signature.as_str())
        );
        assert_eq!(db.get_firewall_applied_signature().unwrap(), None);
        assert_eq!(script_state(&db).unwrap(), ScriptState::RenderedNotApplied);

        // What a successful apply records, without running anything.
        let applied = FirewallOutcome {
            apply: ApplyStep::Applied,
            ..outcome
        };
        record(&db, &applied).unwrap();
        assert_eq!(script_state(&db).unwrap(), ScriptState::Applied);

        db.block_address_permanently("192.0.2.1", crate::db::RuleSource::Tui, None)
            .unwrap();
        assert_eq!(script_state(&db).unwrap(), ScriptState::Changed);
    }

    /// A dry run decides everything and does nothing: no file, no
    /// signature, and the verdict an apply would get.
    #[test]
    fn a_dry_run_writes_and_records_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());
        let run = run.apply(true).for_real(true).dry_run(true);

        let outcome = render_and_apply(&db, run, SshLog::Text(Some(""))).unwrap();

        assert_eq!(outcome.apply, ApplyStep::Applied, "{}", outcome.summary());
        assert!(
            outcome.summary().contains("would write"),
            "{}",
            outcome.summary()
        );
        assert!(!outcome.applied(), "a dry run applied nothing");
        assert!(!dir.path().join("firewall.next.nft").exists());
        assert_eq!(db.get_firewall_rendered_signature().unwrap(), None);
        assert_eq!(db.get_firewall_applied_signature().unwrap(), None);
    }

    /// `render-firewall --out` writes where it was told, not beside the
    /// applied script.
    #[test]
    fn a_named_rendered_path_is_used_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());
        let chosen = dir.path().join("review-me.nft");

        render_and_apply(&db, run.rendered_at(&chosen), SshLog::Text(None)).unwrap();

        assert!(chosen.exists());
        assert!(!dir.path().join("firewall.next.nft").exists());
    }

    /// Compared as rules: an element's timeout counts down from the render,
    /// so two renders a minute apart must not read as every timed block
    /// removed and added again.
    #[test]
    fn the_rule_change_ignores_timeouts_and_counts_real_changes() {
        let applied = "add element inet stop_bots block_v4 {\n\t192.0.2.1 timeout 1d,\n\
                       \t192.0.2.2\n}\n";
        let new = "add element inet stop_bots block_v4 {\n\t192.0.2.1 timeout 23h59m,\n\
                   \t192.0.2.3\n}\n";

        let change = rule_change(Some(applied), new);

        assert_eq!(change.added, vec!["block_v4 192.0.2.3"]);
        assert_eq!(change.removed, vec!["block_v4 192.0.2.2"]);
        assert!(change.baseline);
        assert!(!rule_change(None, new).baseline);
    }

    #[test]
    fn the_rule_change_reads_iptables_rules_too() {
        let change = rule_change(
            Some("-A STOP-BOTS -i lo -j ACCEPT\n-A STOP-BOTS -s 192.0.2.2 -j DROP\n"),
            "-A STOP-BOTS -i lo -j ACCEPT\n-A STOP-BOTS -s 192.0.2.3 -j DROP\n",
        );
        assert_eq!(change.added, vec!["-A STOP-BOTS -s 192.0.2.3 -j DROP"]);
        assert_eq!(change.removed, vec!["-A STOP-BOTS -s 192.0.2.2 -j DROP"]);
    }

    /// The diff on request is the rendered script against the applied one,
    /// labelled with both paths.
    #[test]
    fn the_diff_is_against_the_applied_script() {
        let dir = tempfile::tempdir().unwrap();
        let (db, run) = blocking_the_admin(dir.path());
        std::fs::write(dir.path().join("firewall.nft"), "# the old script\n").unwrap();

        let outcome = render_and_apply(&db, run.dry_run(true), SshLog::Text(None)).unwrap();
        let diff = outcome.diff();

        assert!(diff.contains("-# the old script"), "{diff}");
        assert!(diff.contains("+\t4.5.6.0/24"), "{diff}");
        assert!(diff.contains("firewall.next.nft"), "{diff}");
    }
}
