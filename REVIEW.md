# Pending

# Completed

- ✅ Exploratory testing found: the Dashboard should allow changing the
  system-wide settings, with up/down cycling through them the same way Bot
  settings already did. The Dashboard's "Overview" panel (`src/tui/dashboard.rs`)
  is now a navigable list of the three category defaults; Enter opens the
  same Allowed/Blocked popup Bot settings used to own for them.
- ✅ Exploratory testing found: Bot settings shouldn't show the system-wide
  bot-blocking settings — moved to the Dashboard (see above); Bot settings
  no longer has category rows.
- ✅ Exploratory testing found: Bot settings should list all bot-list
  sources (last updated, signal count), with arrow keys to select one and
  Enter popping a confirmation dialog before updating it. Added to
  `src/tui/bot_settings.rs`, alongside (not replacing) the existing per-bot
  override list. Confirming "Update now" fetches and stores the source's
  bots without blocking the UI thread — see the `KeyOutcome::UpdateSource`
  / `AppEvent::SourceUpdateFinished` plumbing in SPECS.md.

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
- ✅ Implemented firewall rule storage and generation (`firewall_rules` table
  in `src/db.rs`, `src/iptables.rs`, `src/nftables.rs`): admin-managed
  IP/CIDR allow/block/reject rules, rendered into idempotent, narrowly-scoped
  iptables/nftables scripts. Generates only — never shells out to
  `iptables`/`nft` itself (a deliberate choice; see SPECS.md and TODO.md).
- ✅ Implemented the TUI (`src/app.rs`, `src/event.rs`, `src/tui.rs`,
  `src/tui/`), following the Ratatui event-driven-async template: Dashboard
  (default overview, with editable category defaults — see below), Bot
  settings (bot-list sources + per-bot overrides, each via a popup), Site
  settings (read-only site list), Help — matching the screen names/roles
  already decided in the entries below. Running the binary with no
  subcommand now launches it, per README.
- ✅ Added an automated e2e test for the TUI (`tests/tui.rs`), driving the
  real compiled binary through a pty via `rexpect` (`assert_cmd` can't do
  this — no pty). Turns the manual tmux-verification session below into a
  repeatable regression test covering the same flow.
- ✅ Fixed `cargo run`/`stop-bots` (no `--db`) failing with permission denied
  trying to create `/var/lib/stop-bots` as a non-root user: `--db` is now
  `Option<PathBuf>` everywhere, and `open_db` falls back to a per-user XDG
  path when the system path isn't writable, printing which path it picked.
  An explicit `--db` is still honored as-is and fails loudly if it's bad.
