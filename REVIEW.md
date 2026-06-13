# Completed
- ✅ In src/main.rs: Replaced native CLI parsing with clap library (the most popular Rust CLI arguments library)
- ✅ In src/main.rs: Removed CLI fallback mode and replaced with explicit subcommands:
  - `tui` - Start the TUI (default)
  - `scan-sites` / `scan` - Discover and store NGINX sites
  - `update-bot-lists` / `update` - Update bot lists from all data sources
  - `enable-geoblock` - Enable geoblock for specific country or all
  - `disable-geoblock` - Disable geoblock for specific country or all

# Pending
- None

# Notes
- Geoblock commands are stubs and need to be fully implemented in a future update
- Test fixtures for iptables and nftables are already in place (12 files total)

