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
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use stop_bots::{botlist, db::Db, nginx};

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            println!("stop-bots: no command given, run with --help to see available commands");
            Ok(())
        }
        Some(Command::ScanSites { root, db }) => scan_sites(&root, &db),
        Some(Command::UpdateBotLists { db, source }) => update_bot_lists(&db, source).await,
        Some(Command::ApplyBlocks { root, db }) => apply_blocks(&root, &db),
    }
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
