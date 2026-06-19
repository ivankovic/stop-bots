# Completed

- ✅ In src/main.rs: Replaced native CLI parsing with clap library (the most popular Rust CLI arguments library)
- ✅ In src/main.rs: Removed CLI fallback mode and replaced with explicit subcommands:
  - `tui` - Start the TUI (default)
  - `scan-sites` / `scan` - Discover and store NGINX sites
  - `update-bot-lists` / `update` - Update bot lists from all data sources
  - `enable-geoblock` - Enable geoblock for specific country or all
  - `disable-geoblock` - Disable geoblock for specific country or all

# Completed

- ✅ TUI: "Bot settings" should be renamed to "Site settings"
- ✅ TUI: "Dashboard" should be renamed to "Bot settings"
- ✅ TUI: A new Dashboard should be created. It should be the default screen on app run. The new
  dashboard should contain: Overview of global settings, count of sites, count of bot lists that are
  up to date, count of bot lists that need updating, messages
- ✅ TUI: The bottom of the screen has two borders. It should only be one.

# Notes
- Geoblock commands are stubs and need to be fully implemented in a future update
- Test fixtures for iptables and nftables are already in place (12 files total)

