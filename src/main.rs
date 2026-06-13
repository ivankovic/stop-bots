//! Stop Bots - A TUI that helps you configure your server to stop bad bots.
//!
//! This is the main entry point for the application.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use stop_bots::commands::{scan_sites, update_bot_lists};
use stop_bots::db::Database;
use stop_bots::tui::app::run_tui;

/// Stop Bots - Configure your server to stop bad bots and allow good bots
#[derive(Debug, Parser)]
#[command(name = "stop-bots")]
#[command(author = "Marko Ivankovic <marko@ivankovic.me>")]
#[command(version = "0.1.0")]
#[command(about = "A TUI that helps you configure your server to stop bad bots", long_about = None)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

/// Available commands for stop-bots
#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the TUI (default action if no command specified)
    Tui,

    /// Discover and store NGINX sites
    #[command(alias = "scan")]
    ScanSites,

    /// Update bot lists from all data sources
    #[command(alias = "update")]
    UpdateBotLists,

    /// Enable geoblock (stub - to be implemented)
    EnableGeoblock {
        /// Country code to enable geoblock for (optional, enables for all if not specified)
        country_code: Option<String>,
    },

    /// Disable geoblock (stub - to be implemented)
    DisableGeoblock {
        /// Country code to disable geoblock for (optional, disables for all if not specified)
        country_code: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    if cli.verbose > 0 {
        std::env::set_var("RUST_LOG", "debug");
        eprintln!("Debug mode enabled (level: {})", cli.verbose);
    }

    match cli.command {
        Commands::Tui => {
            // Try to run the TUI
            if let Err(e) = run_tui().await {
                eprintln!("Error running TUI: {}", e);
                std::process::exit(1);
            }
        }
        Commands::ScanSites => {
            let mut db = Database::open_default()
                .context("Failed to open database")?;
            db.initialize()
                .context("Failed to initialize database")?;

            let count = scan_sites(&mut db)
                .context("Failed to scan sites")?;
            println!("Discovered and stored {} nginx sites", count);
        }
        Commands::UpdateBotLists => {
            let mut db = Database::open_default()
                .context("Failed to open database")?;
            db.initialize()
                .context("Failed to initialize database")?;

            let count = update_bot_lists(&mut db)
                .await
                .context("Failed to update bot lists")?;
            println!("Updated {} bot entries", count);
        }
        Commands::EnableGeoblock { country_code } => {
            println!("Enable geoblock command: country_code = {:?}", country_code);
            println!("Note: Geoblock functionality is not yet fully implemented.");
        }
        Commands::DisableGeoblock { country_code } => {
            println!("Disable geoblock command: country_code = {:?}", country_code);
            println!("Note: Geoblock functionality is not yet fully implemented.");
        }
    }

    Ok(())
}
