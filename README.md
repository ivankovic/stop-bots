# Stop Bots

A TUI (and CLI) that helps you configure your server to stop bad bots and still allow good bots.

It works alongside NGINX and your existing firewall (iptables or nftables): it classifies
known bots by category (scanners, search engines, AI crawlers), blocks or allows them by
injecting a rule into your NGINX site configs, watches your SSH and NGINX access logs to
automatically flag IPs that look like scanners, and generates (but never applies) firewall
scripts for everything else — geo-blocking, ad-hoc IP rules, and the auto-detected scanners.

# Installation

Build from source with cargo:

```
cargo install --path .
```

There is no published crate or binary package yet.

# Usage

Run the binary with no arguments to launch the TUI, or see `stop-bots --help` for the full
list of CLI subcommands (the TUI and CLI share the same SQLite database and drive the exact
same underlying logic — everything you can do interactively you can also automate).

You can exit the app, or back out of a popup/submenu, with 'q' or Escape.

## Theme

You can switch between the dark and light theme with 'c'. The app will try to auto-detect the theme,
but for some terminal and multiplexer combinations there isn't enough information available to make
the correct choice.

## Screens

Tab / Shift+Tab (or Left/Right, or their vim `h`/`l` aliases) cycle through the tabs below;
`d`/`b`/`s`/`p` jump straight to one; `?` toggles a full key-binding reference at any time.

- **Dashboard** (the default screen): system-wide category defaults (Scanners / Search Bots /
  AI Bots — Allowed or Blocked), host-wide geo-blocking (block or allow-list specific
  countries), a Summary panel (sites discovered, bot-list source freshness, and whether the
  firewall script on disk still matches the current rules), and a "Scheduled tasks" panel
  showing the internal cron's jobs and when they last ran (with a spinner next to any job
  currently running in the background). Press `f` here to render the current firewall rules
  to a script — the popup also has an "apply after writing" toggle (Space) for actually
  enforcing it immediately, instead of applying it by hand afterward.
- **Bot settings**: lists every known bot-list source (with an action to refresh it) and every
  individual bot, searchable by name, with a per-bot override (Allowed / Blocked / follow the
  category default).
- **Site settings**: every NGINX site discovered on disk, with a live "up to date / stale / not
  found" status and actions to apply the current policy to one site or all of them; opening a
  site lets you override its category/bot policy individually.
- **Dynamic Protection**: a live, actionable view of what's currently hitting the server — "Top
  IPs attempting SSH connection" and "Top User Agents", each ranked by count and tagged
  `PENDING`/`BLOCKED` (shown in red). `Tab`/`Shift+Tab` switch which of the two panels
  `Up`/`Down` apply to; `f` cycles a shared filter (all / pending only / blocked only);
  `Enter` blocks the selected `PENDING` row, or unblocks it if it's already `BLOCKED`.
- **Help**: the full key-binding reference.

## What it actually protects against

- **Known bots**, by category (scanner / search engine / AI crawler), sourced from
  [ArcJet's Well-Known Bots](https://github.com/arcjet/well-known-bots),
  [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) and the
  [NGINX Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)
  list. Blocking a category injects an `if ($http_user_agent ...)` rule into each site's NGINX
  config (`apply-blocks` / Site settings' `a`/`A`).
- **SSH and web scanners**, automatically: the internal cron re-reads your SSH log and NGINX
  access log every minute while the TUI is open, flags IPs with a pile of failed SSH logins or
  many distinct 404'd paths, and adds a temporary firewall block for each (expiring on its own
  after a few days, re-added if the behavior continues). Never blocks an IP with a recent
  successful SSH login, or one inside a known crawler's published IP range.
- **Whole countries**, via IPdeny's aggregated CIDR lists — block specific countries, or flip
  to allow-list mode and block everything else.
- **Anything else**, by hand — add an IP/CIDR allow or block rule directly, or use the Dynamic
  Protection screen to permanently block a specific IP or user agent you've spotted before it
  ever crosses an automatic threshold.

Every firewall decision above is *generated*, never applied automatically: `render-firewall`
(or the Dashboard's `f` key) writes an iptables or nftables script for you to review and apply
yourself, and refuses to write one that would lock out a currently-connected SSH session. The
Dashboard's render popup can also apply it for you immediately, but only when you explicitly
ask it to (the "apply after writing" toggle) — never as a side effect of anything automatic
like the internal cron.

There's also a plain access-log tally, independent of blocking: `record-access-stats` /
`list-access-stats` count how often each user agent shows up in successful (non-error)
requests, so you can see who's actually visiting on top of who's being blocked.

# Contact

You can contact me at [marko@ivankovic.me](marko@ivankovic.me).

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation.

See the [LICENSE](LICENSE) file for the full text of the License.

## Can't use AGPL software?

Alternative licensing is available, for individually negotiated compensation.

[Contact me](mailto:marko@ivankovic.me) for options.

# For Developers, human or otherwise

This part of the README is mostly used to tell the AI how to work in this code. Still, useful for humans too.

## Technology

The project is completely written in Rust.

SQLite is used to store user configuation and other runtime data.

The UI is a Terminal UI written using the excellent Ratatui and Crossterm libraries.

### UI design patterns

The TUI must follow the [Ratatui event driven async template](https://github.com/ratatui/templates/tree/main/event-driven-async).

Each component encapsulates its own state, event handlers, and rendering logic.

## Code quality

Code must always be formatted using the automated standard Rust formatter.

No Rust check errors are allowed. Rust check should be run frequently.

## Testing

Automated tests should be run frequently during coding.

Benchmarks should be used to measure quality. These should be run on demand.

### Automated tests

Each file in src/ should end with the test module for that file, as is typicall in Rust. These tests
should test both happy-path and corner cases.

**Tests in src/ must run in under 1 second**.

Each general user flow should have a test in test/. These should all
be happy-path tests, they should not test errors unless the error is a general user flow.

**Tests in tests/ must run in under 5 seconds.**

### How should tests handle dependencies?

*No mocks*. Mocks prevent testing through the interface and are brittle.

Ideally, the real implementation is used.

When necessary, e.g. for filesystem or database access, fake in-memory implementations should be used.

## Code structure

Rust's project structure must be followed.

Some directories don't exist yet but should be created if the need arises.

<root of the repository>
    |- /src               <- The implementation
        |- main.rs        <- CLI entry point (clap subcommands) and their handlers
        |- app.rs         <- The TUI app controller, responds to events and controls the UI
        |- event.rs       <- Terminal event plumbing (ticks, key events, app events)
        |- tui.rs         <- Outer TUI chrome (tab bar, footer) and screen dispatch
        |- tui/           <- One file per TUI screen (Dashboard, Bot settings, Site settings, ...)
        |- db.rs          <- SQLite storage: bots, sites, firewall rules, settings, ...
        |- botlist/       <- One file per bot-list source parser
        |- nginx.rs       <- NGINX site discovery and config injection
        |- sshlog.rs      <- SSH log parsing and scan detection
        |- accesslog.rs   <- NGINX access log parsing, scan detection and UA tallying
        |- accessstats.rs <- Shared CLI+cron logic for recording access-log UA stats
        |- scanblock.rs   <- Shared CLI+cron logic for SSH/web scan detection and blocking
        |- ipranges/      <- Crawler and country IP-range fetching/storage
        |- cron.rs        <- The internal cron: which background jobs run how often
        |- firewall.rs    <- Shared firewall-rendering logic (lockout safety, script writing)
        |- iptables.rs    <- iptables script generation
        |- nftables.rs    <- nftables script generation
    |- /tests           <- Integration and end-to-end automated tests
    |- README.md        <- This file. Only very high level information goes here
    |- AGENTS.md        <- AI-only instructions
    |- SPECS.md         <- Detailed specifications and all decisions that were taken
    |- REVIEW.md        <- Comments about the codebase that need to be improved uppon
    |- TODO.md          <- List of small to  mid size TODO items that need to be fixed in the future

The SPECS.md and README.md files can exist in any subdirectory, and they always serve the same
purpose:

*  README.md - High level summary. Must be readable to humans.
*  SPECS.md - Semi-structured collection of specifications and a decision log of every decision that
   was taken during implementation.

The TODO.md and REVIEW.md files are always only in the root of the repository.
