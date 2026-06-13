//! Command-line commands for stop-bots.
//!
//! This module provides functionality for command-line operations
//! that can be invoked without the TUI.

use crate::db::Database;
use crate::nginx::discover_nginx_sites;
use crate::source_fetch::SourceFetcher;
use anyhow::{Context, Result};

/// Discovers NGINX sites and stores them in the database.
pub fn scan_sites(db: &mut Database) -> Result<usize> {
    // Discover nginx sites
    let sites = match discover_nginx_sites() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error discovering nginx sites: {}", e);
            return Ok(0);
        }
    };

    let mut count = 0;
    for site in &sites {
        for server_name in &site.server_names {
            let config_path = site.config_path.to_string_lossy().into_owned();
            // Store each server name as a site
            db.upsert_site(server_name, &config_path, Some(site.line_number))?;
            count += 1;
        }
    }

    Ok(count)
}

/// Updates bot lists from all data sources.
pub async fn update_bot_lists(db: &mut Database) -> Result<usize> {
    let fetcher = SourceFetcher::new()
        .context("Failed to create source fetcher")?;
    
    // Fetch all bot data from all sources
    let bots = fetcher
        .fetch_all()
        .await
        .context("Failed to fetch bot lists")?;
    
    let mut count = 0;
    for bot in bots {
        // Store each bot in the database
        db.upsert_bot(&bot)?;
        count += 1;
    }
    
    Ok(count)
}
