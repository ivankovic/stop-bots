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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use stop_bots::db::{Db, FirewallAction, FirewallRule, NewFirewallRule};
use stop_bots::{botlist, ipranges, iptables, nftables, nginx, sshlog};

const DEFAULT_DB_PATH: &str = "/var/lib/stop-bots/db.sqlite3";
const DEFAULT_NGINX_ROOT: &str = "/etc/nginx";

/// Help text shared by every subcommand's `--db` flag.
const DB_HELP: &str = "Database path (defaults to /var/lib/stop-bots/db.sqlite3, falling back to a per-user location if that's not writable)";

#[derive(Parser)]
#[command(name = "stop-bots", about = "Configure your server to stop bad bots")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Discover NGINX sites under a config root and store them in the database
    #[command(alias = "scan")]
    ScanSites {
        /// Root directory to scan for NGINX config files
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Download and store the latest known-bot list from one source
    #[command(alias = "update")]
    UpdateBotLists {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Which bot-list source to update: well-known-bots, ai-robots-txt
        /// or nginx-bad-bots
        #[arg(long, default_value = "well-known-bots")]
        source_id: String,
        /// Read the bot list from a local file instead of downloading it
        /// (parsed as --source-id's format)
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Apply the current blocking policy to every discovered NGINX site
    ApplyBlocks {
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Add a firewall rule blocking (or allowing) an IP address or CIDR range
    AddFirewallRule {
        /// IP address or CIDR range, e.g. 1.2.3.4 or 5.6.7.0/24
        #[arg(long)]
        address: String,
        /// Restrict the rule to a single TCP port
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "block")]
        action: String,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// List all stored firewall rules
    ListFirewallRules {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Remove a firewall rule by id
    RemoveFirewallRule {
        #[arg(long)]
        id: i64,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Render the stored firewall rules into an iptables or nftables script.
    /// The script is written to disk only — it is never executed by this
    /// tool. Review it, then apply it yourself. Also includes derived rules
    /// from any blocked-by-default crawler IP-range source and the current
    /// geo mode's selected countries (see UpdateIpRanges/AddCountry/
    /// SetGeoMode) — these are computed fresh each render, never stored as
    /// their own firewall_rules rows.
    ///
    /// Before writing anything, checks recent successful SSH logins (from
    /// /var/log/auth.log, /var/log/secure or journalctl) against every
    /// address about to be blocked, simulating the same first-match-wins
    /// order the script itself will evaluate. If any currently-connected
    /// client would be cut off, it refuses to write the script (pass
    /// --force to override).
    ///
    /// Allowlist geo mode (see SetGeoMode) requires --backend nftables:
    /// iptables has no loopback/established-connection allowance and
    /// silently permits all IPv6 (it skips IPv6 rules entirely), both fatal
    /// once a trailing "block everything else" rule is in play.
    RenderFirewall {
        #[arg(long)]
        backend: FirewallBackend,
        /// Path to write the generated script to
        #[arg(long)]
        out: PathBuf,
        /// Write the script even if it would block an IP with a recent
        /// successful SSH login
        #[arg(long)]
        force: bool,
        /// Check this SSH log file instead of auto-detecting one — for a
        /// non-standard log location, or a container where the real logs
        /// aren't at their usual path
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Download and store the current CIDR list for one published crawler
    /// IP-range source (Googlebot, Bingbot or GPTBot)
    UpdateIpRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Which source to update: googlebot, bingbot or gptbot
        #[arg(long)]
        source_id: String,
    },
    /// Download and store IPdeny's current aggregated CIDR list for one
    /// country (does not select it — see AddCountry)
    UpdateCountryRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// Sets the host-wide geo mode: "blocklist" (selected countries are
    /// blocked, everything else allowed — the default) or "allowlist"
    /// (selected countries are the only ones allowed, everything else
    /// blocked). Switching modes doesn't touch the selected-country list
    /// itself, only how render-firewall interprets it.
    SetGeoMode {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        mode: GeoModeArg,
    },
    /// Add a country to the host-wide geo selection (fetch its ranges first
    /// with UpdateCountryRanges). What this means depends on the current
    /// geo mode — see SetGeoMode.
    AddCountry {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        country: String,
    },
    /// Remove a country from the host-wide geo selection
    RemoveCountry {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        country: String,
    },
    /// List the current geo mode and every selected country
    ListSelectedCountries {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Start the TUI (also the default when run with no subcommand)
    Tui {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Root directory to scan for NGINX config files, when triggering a
        /// site scan from Site settings
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Clone, Copy, ValueEnum)]
enum GeoModeArg {
    Blocklist,
    Allowlist,
}

impl From<GeoModeArg> for stop_bots::db::GeoMode {
    fn from(arg: GeoModeArg) -> Self {
        match arg {
            GeoModeArg::Blocklist => stop_bots::db::GeoMode::Blocklist,
            GeoModeArg::Allowlist => stop_bots::db::GeoMode::Allowlist,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => run_tui(None, PathBuf::from(DEFAULT_NGINX_ROOT)).await,
        Some(Command::Tui { db, root }) => run_tui(db, root).await,
        Some(Command::ScanSites { root, db }) => scan_sites(&root, db),
        Some(Command::UpdateBotLists {
            db,
            source_id,
            source,
        }) => update_bot_lists(db, source_id, source).await,
        Some(Command::ApplyBlocks { root, db }) => apply_blocks(&root, db),
        Some(Command::AddFirewallRule {
            address,
            port,
            action,
            db,
        }) => add_firewall_rule(db, address, port, &action),
        Some(Command::ListFirewallRules { db }) => list_firewall_rules(db),
        Some(Command::RemoveFirewallRule { id, db }) => remove_firewall_rule(db, id),
        Some(Command::RenderFirewall {
            backend,
            out,
            force,
            ssh_log,
            db,
        }) => render_firewall(db, backend, &out, force, ssh_log),
        Some(Command::UpdateIpRanges { db, source_id }) => update_ip_ranges(db, source_id).await,
        Some(Command::UpdateCountryRanges { db, country }) => {
            update_country_ranges(db, country).await
        }
        Some(Command::SetGeoMode { db, mode }) => set_geo_mode(db, mode),
        Some(Command::AddCountry { db, country }) => set_country_selected(db, country, true),
        Some(Command::RemoveCountry { db, country }) => set_country_selected(db, country, false),
        Some(Command::ListSelectedCountries { db }) => list_selected_countries(db),
    }
}

/// Resolves and opens the database. An explicit `--db` is always honored
/// as-is, even if opening it fails — silently substituting a path the user
/// asked for would be worse than just erroring. Without one, tries the
/// system location first and falls back to a per-user location if that
/// isn't writable: `/var/lib` typically needs root, which actually applying
/// nginx/firewall changes needs anyway, but just exploring with `cargo run`
/// or the TUI shouldn't require it.
fn open_db(explicit: Option<PathBuf>) -> Result<Db> {
    let Some(path) = explicit else {
        return open_default_db();
    };
    Db::open(path)
}

fn open_default_db() -> Result<Db> {
    open_or_fallback(Path::new(DEFAULT_DB_PATH), user_db_path)
}

/// Tries to create `primary`'s parent directory and open it as the
/// database; only if that directory can't even be created does it fall
/// back to whatever `fallback` resolves to (printing a note about which
/// path was used). `fallback` is a closure, not an already-resolved path,
/// so resolving it (which can itself fail, e.g. if neither `XDG_DATA_HOME`
/// nor `HOME` is set) never gets in the way of the common case where
/// `primary` just works — important for e.g. a root-run container with a
/// minimal environment, where `/var/lib` is perfectly writable but `HOME`
/// might not be set at all.
///
/// Deliberately narrow: this does *not* fall back on every kind of
/// failure, e.g. the directory existing but its database file being
/// corrupt, or owned by someone else and unreadable. Falling back in those
/// cases would hand back a fresh, empty database that's easy to mistake for
/// "no data yet" instead of surfacing the real problem — the dev-ergonomics
/// win this exists for is specifically "the system directory doesn't exist
/// and I can't create it", not "something is wrong with the system db".
fn open_or_fallback(primary: &Path, fallback: impl FnOnce() -> Result<PathBuf>) -> Result<Db> {
    let parent = primary
        .parent()
        .with_context(|| format!("{} has no parent directory", primary.display()))?;
    if let Err(dir_err) = std::fs::create_dir_all(parent) {
        let fallback = fallback()?;
        eprintln!(
            "Note: couldn't create {} ({dir_err}); using {} instead.",
            parent.display(),
            fallback.display()
        );
        return Db::open(&fallback).with_context(|| {
            format!(
                "failed to create {} ({dir_err}) and failed to open the fallback database at {}",
                parent.display(),
                fallback.display()
            )
        });
    }
    Db::open(primary)
}

/// The per-user fallback database location, following the XDG Base
/// Directory spec (`$XDG_DATA_HOME`, or `~/.local/share` if that's unset).
fn user_db_path() -> Result<PathBuf> {
    resolve_user_db_path(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// Pure resolution logic for [`user_db_path`], taking the relevant env vars
/// as parameters so it's testable without mutating real process env vars
/// (which would race with other tests in this binary).
fn resolve_user_db_path(
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let data_home = xdg_data_home
        .map(PathBuf::from)
        .or_else(|| home.map(|home| PathBuf::from(home).join(".local/share")))
        .context(
            "could not determine a per-user data directory: neither XDG_DATA_HOME nor HOME is set",
        )?;
    Ok(data_home.join("stop-bots").join("db.sqlite3"))
}

async fn run_tui(db_path: Option<PathBuf>, root: PathBuf) -> Result<()> {
    let db = open_db(db_path)?;
    let app = stop_bots::app::App::new(db, root)?;
    let terminal = ratatui::init();
    let result = app.run(terminal).await;
    ratatui::restore();
    result
}

fn scan_sites(root: &Path, db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let sites = nginx::discover_sites(root)?;
    for site in &sites {
        db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
    }
    println!(
        "Discovered {} site(s) under {}",
        sites.len(),
        root.display()
    );
    Ok(())
}

async fn update_bot_lists(
    db_path: Option<PathBuf>,
    source_id: String,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let kind = botlist::SourceKind::from_id(&source_id)
        .with_context(|| format!("unknown bot-list source id: {source_id}"))?;
    let count = match source {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)?;
            let bots = kind.parse(&raw)?;
            botlist::store(&db, kind, &bots)?
        }
        None => botlist::update(&db, kind).await?,
    };
    println!("Stored {count} bot(s) from {}", kind.name());
    Ok(())
}

fn apply_blocks(root: &Path, db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let default_patterns = db.blocked_user_agent_patterns()?;
    // Sites already known to the db (i.e. previously scanned) — the only
    // ones that can carry a per-site override at all.
    let known_sites = db.list_sites()?;
    let sites = nginx::discover_sites(root)?;

    // A single config file commonly holds multiple `server` blocks for the
    // same site (e.g. an HTTP redirect block plus the HTTPS one), so dedupe
    // by file and apply once per file rather than once per discovered site.
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();

    let mut changed = 0;
    for path in &config_paths {
        // Built fresh per file, filtered to sites that actually live in
        // *this* file: `server_name` alone isn't unique across the whole
        // `sites` table (two different files can share one, e.g. a stale
        // config left behind after a rename), so a single map built once
        // for the whole run could leak one site's override onto another's
        // same-named block in a different file. Note this join is a
        // textual `config_path` match, only valid when `--root` here
        // matches whatever `--root` was used at scan time — a mismatch
        // just falls through to `default_patterns` below, not an error.
        let site_patterns: Vec<(String, Vec<String>)> = known_sites
            .iter()
            .filter(|s| Path::new(&s.config_path) == path.as_path())
            .map(|s| {
                Ok((
                    s.server_name.clone(),
                    db.blocked_user_agent_patterns_for_site(s.id)?,
                ))
            })
            .collect::<Result<_>>()?;
        if nginx::apply_blocks_to_file(path, &site_patterns, &default_patterns)? {
            changed += 1;
        }
    }
    println!(
        "Applied blocking rules to {} site(s) across {} file(s), {} file(s) changed",
        sites.len(),
        config_paths.len(),
        changed
    );
    Ok(())
}

fn add_firewall_rule(
    db_path: Option<PathBuf>,
    address: String,
    port: Option<u16>,
    action: &str,
) -> Result<()> {
    let db = open_db(db_path)?;
    let id = db.add_firewall_rule(&NewFirewallRule {
        address,
        port,
        action: FirewallAction::parse(action)?,
    })?;
    println!("Added firewall rule #{id}");
    Ok(())
}

fn list_firewall_rules(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let rules = db.list_firewall_rules()?;
    if rules.is_empty() {
        println!("No firewall rules stored.");
        return Ok(());
    }
    for rule in rules {
        let port = rule.port.map(|p| format!(":{p}")).unwrap_or_default();
        let status = if rule.enabled { "" } else { " (disabled)" };
        println!(
            "#{} {:?} {}{}{}",
            rule.id, rule.action, rule.address, port, status
        );
    }
    Ok(())
}

fn remove_firewall_rule(db_path: Option<PathBuf>, id: i64) -> Result<()> {
    let db = open_db(db_path)?;
    db.remove_firewall_rule(id)?;
    println!("Removed firewall rule #{id}");
    Ok(())
}

async fn update_ip_ranges(db_path: Option<PathBuf>, source_id: String) -> Result<()> {
    let db = open_db(db_path)?;
    let kind = ipranges::IpRangeSourceKind::from_id(&source_id)
        .with_context(|| format!("unknown ip-range source id: {source_id}"))?;
    let count = ipranges::update(&db, kind).await?;
    println!("Stored {count} CIDR range(s) from {}", kind.name());
    Ok(())
}

async fn update_country_ranges(db_path: Option<PathBuf>, country: String) -> Result<()> {
    let db = open_db(db_path)?;
    let count = ipranges::update_country(&db, &country).await?;
    println!("Stored {count} CIDR range(s) for country {country}");
    Ok(())
}

fn set_geo_mode(db_path: Option<PathBuf>, mode: GeoModeArg) -> Result<()> {
    let db = open_db(db_path)?;
    let mode: stop_bots::db::GeoMode = mode.into();
    db.set_geo_mode(mode)?;
    println!("Geo mode set to {mode:?}");
    Ok(())
}

fn set_country_selected(db_path: Option<PathBuf>, country: String, selected: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_country_selected(&country, selected)?;
    println!(
        "{} country {country}",
        if selected { "Added" } else { "Removed" }
    );
    Ok(())
}

fn list_selected_countries(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let mode = db.get_geo_mode()?;
    let countries = db.list_selected_countries()?;
    println!("Geo mode: {mode:?}");
    if countries.is_empty() {
        println!("No countries selected.");
        return Ok(());
    }
    for country in countries {
        println!("{country}");
    }
    Ok(())
}

/// Every synthetic (never persisted) `FirewallRule` derived from
/// currently-blocked-by-default crawler IP-range sources and the current
/// geo mode's selected countries — see `Db::derived_firewall_entries`.
/// Uses `id: 0` since these don't correspond to a real `firewall_rules`
/// row; they're never looked up or removed by id, only rendered. Order is
/// preserved from `derived_firewall_entries` (crawler ranges, then geo
/// rules with any Allowlist catch-all strictly last) — callers must append
/// this after admin rules, never reorder it.
fn derived_firewall_rules(db: &Db) -> Result<Vec<FirewallRule>> {
    Ok(db
        .derived_firewall_entries()?
        .into_iter()
        .map(|(address, action)| FirewallRule {
            id: 0,
            address,
            port: None,
            action,
            enabled: true,
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
fn lockout_risks(rules: &[FirewallRule], connected_ips: &[String]) -> Vec<(String, String)> {
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

fn print_lockout_warning(risks: &[(String, String)]) {
    eprintln!(
        "WARNING: these firewall rules would block {} currently-connected SSH client IP address(es):",
        risks.len()
    );
    for (ip, cidr) in risks {
        eprintln!("  {ip} (blocked by {cidr})");
    }
    eprintln!("Applying them could lock you out of remote access to this machine.");
}

/// The lockout safety check `render_firewall` runs before writing anything:
/// finds recent successful SSH logins (via `--ssh-log`, or auto-detected)
/// and warns if any of them would actually end up blocked by `rules` (see
/// `lockout_risks` for what "actually end up" means). Returns whether it's
/// safe to proceed — `false` means the caller should refuse to write the
/// script unless `--force` was passed. A log source that couldn't be found
/// or read at all is not a risk in itself (nothing to check against), just
/// a note that the check didn't run.
fn check_lockout_risk(rules: &[FirewallRule], ssh_log: Option<&Path>, force: bool) -> Result<bool> {
    let source = match ssh_log {
        Some(path) => sshlog::read_log_file(path),
        None => sshlog::find_default_source(),
    };
    let log_text = match source {
        sshlog::LogSource::Found(text) => text,
        sshlog::LogSource::Unavailable => {
            eprintln!(
                "Note: couldn't read any SSH log (tried /var/log/auth.log, /var/log/secure, journalctl) — skipping the lockout safety check. Run as root, or pass --ssh-log, for this check to work."
            );
            return Ok(true);
        }
    };
    let connected_ips = sshlog::parse_accepted_ips(&log_text);
    let risks = lockout_risks(rules, &connected_ips);
    if risks.is_empty() {
        return Ok(true);
    }
    print_lockout_warning(&risks);
    if force {
        return Ok(true);
    }
    print_lockout_warning(&risks);
    Ok(false)
}

fn render_firewall(
    db_path: Option<PathBuf>,
    backend: FirewallBackend,
    out: &Path,
    force: bool,
    ssh_log: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;

    // Allowlist mode's trailing "block everything else" catch-all is only
    // safe on nftables: iptables has no loopback/established-connection
    // allowance in this chain (so 0.0.0.0/0 would drop even local traffic)
    // and silently skips IPv6 rules entirely (so an IPv6 catch-all never
    // renders, quietly permitting all IPv6 while IPv4 is locked down). See
    // SPECS.md.
    if db.get_geo_mode()? == stop_bots::db::GeoMode::Allowlist
        && matches!(backend, FirewallBackend::Iptables)
    {
        anyhow::bail!(
            "Allowlist geo mode requires --backend nftables (iptables can't safely enforce a default-deny catch-all — see SPECS.md)"
        );
    }

    let mut rules = db.list_firewall_rules()?;
    rules.extend(derived_firewall_rules(&db)?);

    if !check_lockout_risk(&rules, ssh_log.as_deref(), force)? {
        anyhow::bail!(
            "Refusing to write firewall rules: would block a currently-connected SSH client. Re-run with --force if you're sure."
        );
    }

    let enabled = rules.iter().filter(|r| r.enabled);
    let (script, run_hint, written) = match backend {
        FirewallBackend::Iptables => {
            // iptables is IPv4-only; render() skips IPv6 rules (see SPECS.md).
            let written = enabled.filter(|r| !r.address.contains(':')).count();
            (
                iptables::render(&rules),
                format!("sh {}", out.display()),
                written,
            )
        }
        FirewallBackend::Nftables => (
            nftables::render(&rules),
            format!("nft -f {}", out.display()),
            enabled.count(),
        ),
    };
    std::fs::write(out, script)?;
    println!(
        "Wrote {written} rule(s) to {}. Not applied automatically — review it, then run: {run_hint}",
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_user_db_path_prefers_xdg_data_home() {
        let path = resolve_user_db_path(Some("/custom/data".into()), Some("/home/someone".into()))
            .unwrap();
        assert_eq!(path, PathBuf::from("/custom/data/stop-bots/db.sqlite3"));
    }

    #[test]
    fn resolve_user_db_path_falls_back_to_home_local_share() {
        let path = resolve_user_db_path(None, Some("/home/someone".into())).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/someone/.local/share/stop-bots/db.sqlite3")
        );
    }

    #[test]
    fn resolve_user_db_path_errors_without_any_signal() {
        assert!(resolve_user_db_path(None, None).is_err());
    }

    #[test]
    fn open_db_with_an_explicit_path_opens_it_directly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("explicit.sqlite3");
        assert!(open_db(Some(path.clone())).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn open_or_fallback_uses_fallback_when_primary_directory_cannot_be_created() {
        // A regular file masquerading as a directory component: `mkdir -p`
        // through it must fail for any user, including root, so this is a
        // root-safe way to force the "can't create the directory" path
        // without needing real permission denial.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let primary = blocker.join("db.sqlite3");

        let fallback_dir = tempfile::tempdir().unwrap();
        let fallback = fallback_dir.path().join("fallback.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(fallback.exists());
        assert!(!primary.exists());
    }

    #[test]
    fn open_or_fallback_uses_primary_when_it_works() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");
        let fallback = tmp.path().join("should-not-be-used.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(primary.exists());
        assert!(!fallback.exists());
    }

    #[test]
    fn open_or_fallback_never_resolves_fallback_when_primary_works() {
        // Regression guard: resolving the fallback path can itself fail
        // (e.g. neither XDG_DATA_HOME nor HOME is set, plausible in a
        // minimal-env root container). That must never get in the way of
        // the common case where the primary path just works.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");

        let result = open_or_fallback(&primary, || {
            anyhow::bail!("fallback should never be resolved here")
        });

        assert!(result.is_ok());
        assert!(primary.exists());
    }

    fn rule(address: &str, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: 0,
            address: address.to_string(),
            port: None,
            action,
            enabled: true,
        }
    }

    #[test]
    fn derived_firewall_rules_combines_blocked_ip_ranges_and_geo_rules() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&stop_bots::db::IpRangeSource {
            id: "gptbot".to_string(),
            name: "GPTBot IP ranges".to_string(),
            url: "https://example.invalid/gptbot.json".to_string(),
            category: stop_bots::db::Category::Ai,
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
        db.set_geo_mode(stop_bots::db::GeoMode::Allowlist).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();

        let rules = derived_firewall_rules(&db).unwrap();
        assert_eq!(rules[0].address, "1.2.3.0/24");
        assert_eq!(rules[0].action, FirewallAction::Allow);
        assert_eq!(rules[1].address, "0.0.0.0/0");
        assert_eq!(rules[1].action, FirewallAction::Block);
        assert_eq!(rules[2].address, "::/0");
        assert_eq!(rules[2].action, FirewallAction::Block);
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
    fn check_lockout_risk_blocks_without_force_and_passes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 4.5.6.7 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(!check_lockout_risk(&rules, Some(&log_path), false).unwrap());
        assert!(check_lockout_risk(&rules, Some(&log_path), true).unwrap());
    }

    #[test]
    fn check_lockout_risk_passes_when_the_log_has_no_matching_login() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 9.9.9.9 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(check_lockout_risk(&rules, Some(&log_path), false).unwrap());
    }

    #[test]
    fn check_lockout_risk_passes_when_the_log_source_is_unavailable() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(check_lockout_risk(&rules, Some(Path::new("/nonexistent/x.log")), false).unwrap());
    }

    #[test]
    fn render_firewall_rejects_allowlist_mode_on_iptables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            db.set_geo_mode(stop_bots::db::GeoMode::Allowlist).unwrap();
        }
        let out = tmp.path().join("fw.sh");

        let result = render_firewall(Some(db_path), FirewallBackend::Iptables, &out, false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nftables"));
        assert!(!out.exists());
    }
}
