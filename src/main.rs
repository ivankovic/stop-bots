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

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use stop_bots::db::{Db, FirewallAction, NewFirewallRule};
use stop_bots::{botlist, iptables, nftables, nginx};

const DEFAULT_DB_PATH: &str = "/var/lib/stop-bots/db.sqlite3";
const DEFAULT_NGINX_ROOT: &str = "/etc/nginx";

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
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
    },
    /// Download and store the latest known-bot list
    #[command(alias = "update")]
    UpdateBotLists {
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
        /// Read the bot list from a local file instead of downloading it
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Apply the current blocking policy to every discovered NGINX site
    ApplyBlocks {
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
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
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
    },
    /// List all stored firewall rules
    ListFirewallRules {
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
    },
    /// Remove a firewall rule by id
    RemoveFirewallRule {
        #[arg(long)]
        id: i64,
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
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
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
    },
    /// Start the TUI (also the default when run with no subcommand)
    Tui {
        #[arg(long, default_value = DEFAULT_DB_PATH)]
        db: PathBuf,
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
        None => run_tui(&PathBuf::from(DEFAULT_DB_PATH)).await,
        Some(Command::Tui { db }) => run_tui(&db).await,
        Some(Command::ScanSites { root, db }) => scan_sites(&root, &db),
        Some(Command::UpdateBotLists { db, source }) => update_bot_lists(&db, source).await,
        Some(Command::ApplyBlocks { root, db }) => apply_blocks(&root, &db),
        Some(Command::AddFirewallRule {
            address,
            port,
            action,
            db,
        }) => add_firewall_rule(&db, address, port, &action),
        Some(Command::ListFirewallRules { db }) => list_firewall_rules(&db),
        Some(Command::RemoveFirewallRule { id, db }) => remove_firewall_rule(&db, id),
        Some(Command::RenderFirewall { backend, out, db }) => render_firewall(&db, backend, &out),
    }
}

async fn run_tui(db_path: &Path) -> Result<()> {
    let db = Db::open(db_path)?;
    let app = stop_bots::app::App::new(db)?;
    let terminal = ratatui::init();
    let result = app.run(terminal).await;
    ratatui::restore();
    result
}

fn scan_sites(root: &Path, db_path: &Path) -> Result<()> {
    let db = Db::open(db_path)?;
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

async fn update_bot_lists(db_path: &Path, source: Option<PathBuf>) -> Result<()> {
    let db = Db::open(db_path)?;
    let count = match source {
        Some(path) => {
            let json = std::fs::read_to_string(&path)?;
            let bots = botlist::parse(&json)?;
            botlist::store(&db, &bots)?
        }
        None => botlist::update(&db).await?,
    };
    println!("Stored {count} bot(s) from {}", botlist::SOURCE_NAME);
    Ok(())
}

fn apply_blocks(root: &Path, db_path: &Path) -> Result<()> {
    let db = Db::open(db_path)?;
    let patterns = db.blocked_user_agent_patterns()?;
    let sites = nginx::discover_sites(root)?;

    // A single config file commonly holds multiple `server` blocks for the
    // same site (e.g. an HTTP redirect block plus the HTTPS one), so dedupe
    // by file and apply once per file rather than once per discovered site.
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();

    let mut changed = 0;
    for path in &config_paths {
        if nginx::apply_blocks_to_file(path, &patterns)? {
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
    db_path: &Path,
    address: String,
    port: Option<u16>,
    action: &str,
) -> Result<()> {
    let db = Db::open(db_path)?;
    let id = db.add_firewall_rule(&NewFirewallRule {
        address,
        port,
        action: FirewallAction::parse(action)?,
    })?;
    println!("Added firewall rule #{id}");
    Ok(())
}

fn list_firewall_rules(db_path: &Path) -> Result<()> {
    let db = Db::open(db_path)?;
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

fn remove_firewall_rule(db_path: &Path, id: i64) -> Result<()> {
    let db = Db::open(db_path)?;
    db.remove_firewall_rule(id)?;
    println!("Removed firewall rule #{id}");
    Ok(())
}

fn render_firewall(db_path: &Path, backend: FirewallBackend, out: &Path) -> Result<()> {
    let db = Db::open(db_path)?;
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
