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
use stop_bots::db::{Db, FirewallAction, NewFirewallRule};
use stop_bots::{botlist, iptables, nftables, nginx};

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
    /// tool. Review it, then apply it yourself.
    RenderFirewall {
        #[arg(long)]
        backend: FirewallBackend,
        /// Path to write the generated script to
        #[arg(long)]
        out: PathBuf,
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
        Some(Command::RenderFirewall { backend, out, db }) => render_firewall(db, backend, &out),
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

fn render_firewall(db_path: Option<PathBuf>, backend: FirewallBackend, out: &Path) -> Result<()> {
    let db = open_db(db_path)?;
    let rules = db.list_firewall_rules()?;
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
}
