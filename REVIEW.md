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
- ✅ Implemented firewall rule storage and generation (`firewall_rules` table
  in `src/db.rs`, `src/iptables.rs`, `src/nftables.rs`): admin-managed
  IP/CIDR allow/block/reject rules, rendered into idempotent, narrowly-scoped
  iptables/nftables scripts. Generates only — never shells out to
  `iptables`/`nft` itself (a deliberate choice; see SPECS.md and TODO.md).
- ✅ Implemented the TUI (`src/app.rs`, `src/event.rs`, `src/tui.rs`,
  `src/tui/`), following the Ratatui event-driven-async template: Dashboard
  (default, read-only overview), Bot settings (category defaults + per-bot
  overrides via a popup), Site settings (read-only site list), Help —
  matching the screen names/roles already decided in the entries below.
  Running the binary with no subcommand now launches it, per README.
- ✅ Added an automated e2e test for the TUI (`tests/tui.rs`), driving the
  real compiled binary through a pty via `rexpect` (`assert_cmd` can't do
  this — no pty). Turns the manual tmux-verification session below into a
  repeatable regression test covering the same flow.

# Notes
- The previous TUI and geoblock integration were removed wholesale in an
  earlier commit (`human: remove this shit`). Geoblock has not been rebuilt
  (see TODO.md); the TUI has been, deliberately much smaller than the
  ~4300-line original (no custom RGB theme palette, three screens instead of
  several, no firewall/geoblock screens yet).
- The iptables/nftables test fixtures (12 files) are now used by
  `src/iptables.rs`/`src/nftables.rs` tests — the line syntax and JSON shape
  drive the render tests, though the generated output deliberately deviates
  from the fixtures' own envelope/safety choices (see SPECS.md).
- `ratatui::init()` needs a real TTY, which the sandbox this was built in
  doesn't have by default — but `tmux` was available, so the TUI was driven
  and visually verified interactively through a real pty rather than only
  unit-tested. That caught two bugs unit tests missed: a popup that rendered
  off-screen (wrong centering math) and a Dashboard that didn't refresh
  after a change made on another screen.
