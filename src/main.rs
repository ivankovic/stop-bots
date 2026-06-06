//! Stop Bots - A TUI that helps you configure your server to stop bad bots.
//!
//! This is the main entry point for the application.

use anyhow::{Context, Result};
use stop_bots::nginx::{common_config_paths, discover_nginx_configs, is_nginx_installed};
use std::io::{self, Write};

fn main() -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    // Check if nginx is installed
    writeln!(handle, "Checking for NGINX installation...")?;
    if !is_nginx_installed() {
        writeln!(handle, "NGINX does not appear to be installed on this system.")?;
        writeln!(handle)?;
        writeln!(handle, "Common NGINX configuration paths:")?;
        for path in common_config_paths() {
            writeln!(handle, "  - {}", path)?;
        }
        writeln!(handle)?;
        writeln!(
            handle,
            "If NGINX is installed in a custom location, please ensure the config files exist."
        )?;
        return Ok(());
    }

    writeln!(handle, "NGINX is installed on this system.")?;
    writeln!(handle)?;

    // Discover nginx configuration files
    writeln!(handle, "Discovering NGINX configuration files...")?;
    let configs = discover_nginx_configs()
        .context("Failed to discover NGINX configuration files")?;

    // Print results
    writeln!(handle)?;
    writeln!(handle, "=== NGINX Configuration Discovery Results ===")?;
    writeln!(handle)?;

    if let Some(ref main_config) = configs.main_config {
        writeln!(handle, "Main Configuration File:")?;
        writeln!(handle, "  Path: {}", main_config.path.display())?;
        writeln!(handle)?;
    } else {
        writeln!(handle, "No main configuration file found.")?;
        writeln!(handle)?;
    }

    if !configs.additional_configs.is_empty() {
        writeln!(handle, "Additional Configuration Files:")?;
        for config in &configs.additional_configs {
            writeln!(handle, "  - {}", config.path.display())?;
        }
        writeln!(handle)?;
    } else {
        writeln!(handle, "No additional configuration files found.")?;
        writeln!(handle)?;
    }

    // Summary
    let total_files = configs.all_configs().len();
    writeln!(handle, "Total configuration files found: {}", total_files)?;

    Ok(())
}
