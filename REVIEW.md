# Completed

- ✅ Implemented SQLite storage (`src/db.rs`): sources, bots, sites, and
  global per-category default settings, with manual bot overrides surviving
  bot-list refreshes.
- ✅ Implemented NGINX site discovery and bot-blocking config injection
  (`src/nginx.rs`): walks a config root for `server {}` blocks and
  idempotently injects/removes a sentinel-marked `if ($http_user_agent ...)`
  rule per site.
- ✅ Implemented bot-list download/parsing/storage from ArcJet
  Well-Known Bots (`src/botlist.rs`).
- ✅ In `src/main.rs`: CLI with clap, subcommands `scan-sites`/`scan`,
  `update-bot-lists`/`update`, `apply-blocks`.

# Notes
- The previous TUI, geoblock and iptables/nftables integration were removed
  wholesale in an earlier commit (`human: remove this shit`) and have not
  been rebuilt; see TODO.md for what's still missing.
- Test fixtures for iptables and nftables are still in place (12 files total)
  but unused by the current code.
