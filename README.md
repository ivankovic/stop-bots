# Stop Bots

A TUI (and CLI) that helps you configure your server to stop bad bots and still allow good bots.

It works alongside NGINX and your existing firewall (iptables or nftables), on two separate
planes:

- **NGINX config.** It classifies known bots by category (scanners, search engines, AI
  crawlers) and blocks or allows them by injecting a rule into your site configs. The same
  injected block can also rate-limit requests, serve a generated `robots.txt`, and exempt
  paths you don't want any of it applied to.
- **A firewall script.** It watches your SSH and NGINX access logs to flag IPs that are
  scanning, probing for exposed secrets, forging a crawler's identity, or walking into a
  honeypot — and turns those, plus geo-blocking, third-party blocklists and your own ad-hoc
  rules, into an iptables or nftables script.

Nothing is enforced behind your back. Every blocking decision is stored in a database first;
NGINX config is written only when you apply it, and the firewall script is *generated* for
you to review and run yourself.

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
On the two screens that have more than one list side by side — Site settings and Dynamic
Protection — Tab switches between *those* instead, and you cycle screens with Left/Right or
the direct jumps.

The Dashboard assumes a terminal of at least 80x30. Below that its panels start to truncate.

The Dashboard owns everything that ends up in the **firewall script**; Site settings owns
everything that ends up in **NGINX config**. That split decides where any given setting lives.

- **Dashboard** (the default screen): system-wide category defaults (Scanners / Search Bots /
  AI Bots — Allowed or Blocked); host-wide geo-blocking (block or allow-list specific
  countries); an "Automatic blocking" panel with an on/off switch for each detector and each
  third-party blocklist; a Summary panel (sites discovered, bot-list source freshness, and
  whether the firewall script on disk still matches the current rules); and a "Scheduled
  tasks" panel showing the internal cron's jobs and when they last ran (with a spinner next
  to any job currently running in the background). `Up`/`Down` flow between the three lists;
  `m` switches geo mode. Press `f` to render the current firewall rules to a script — the
  popup also has an "apply after writing" toggle (Space) for actually enforcing it
  immediately, instead of applying it by hand afterward.
- **Bot settings**: lists every known bot-list source (with an action to refresh it) and every
  individual bot, searchable by name, with a per-bot override (Allowed / Blocked / follow the
  category default).
- **Site settings**: an "NGINX settings" panel (`Tab` to focus it) holding the host-wide
  choices that shape generated config — the response for a blocked request (403 or 444),
  whether to serve a generated `robots.txt`, and rate limiting — above every NGINX site
  discovered on disk, each with a live "up to date / stale / not found" status and actions to
  apply the current policy to one site or all of them. Changing any of those settings flips
  every applied site to `STALE`, which is your cue to re-apply. Opening a site lets you
  override its category/bot policy and list paths exempt from blocking.
- **Dynamic Protection**: a live, actionable view of what's currently hitting the server — "Top
  IPs attempting SSH connection" and "Top User Agents", each ranked by count and tagged
  `NOT BLOCKED`/`BLOCKED` (shown in red). `Tab`/`Shift+Tab` switch which of the two panels
  `Up`/`Down` apply to; `f` cycles a shared filter (all / not blocked only / blocked only);
  `Enter` blocks the selected `NOT BLOCKED` row, or unblocks it if it's already `BLOCKED`.
- **Help**: the full key-binding reference.

## What it actually protects against

### In your NGINX config

- **Known bots**, by category (scanner / search engine / AI crawler), sourced from
  [ArcJet's Well-Known Bots](https://github.com/arcjet/well-known-bots),
  [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) and the
  [NGINX Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)
  list. Blocking a category injects an `if ($http_user_agent ...)` rule into each site's NGINX
  config (`apply-blocks` / Site settings' `a`/`A`). You choose whether a match gets a `403` or
  a `444` (close the connection without answering — cheaper, and gives a scanner no status
  code to adapt to).
- **Too many requests**, via NGINX's own rate limiting. Unlike everything else here this is
  enforced by NGINX at request time rather than by analysing a log afterwards. Off by default:
  a limit tuned for the wrong site turns away real visitors.
- **Politely, first** — an optional generated `robots.txt` listing every bot you're blocking,
  for the crawlers that honour it, plus the honeypot path below. Off by default, because it
  replaces whatever your site serves at `/robots.txt` today.
- **Except where you say otherwise** — per-site path exemptions, so you can block AI crawlers
  everywhere except `/blog`.

### From your logs, automatically

Each of these is an independent switch on the Dashboard's "Automatic blocking" panel, and
each adds a temporary firewall block that expires on its own and is re-added if the behaviour
continues.

They run on an internal timer that re-reads your SSH and NGINX access logs every minute —
**but only while the TUI is open.** Nothing is detected when the process isn't running. The
equivalent CLI subcommands (`block-scanners`, `block-web-scanners`,
`block-spoofed-crawlers`, `block-probe-paths`, `block-honeypot`) are safe to run unattended
from a real cron if you want that, since none of them applies anything by itself.

- **SSH and web scanners**: IPs with a pile of failed SSH logins, or many distinct 404'd
  paths. Never an IP with a recent successful SSH login, or one inside a known crawler's
  published IP range.
- **Forged crawlers**: anything claiming to be Googlebot, Bingbot or GPTBot from an address
  that crawler's own operator doesn't publish. The cheapest common disguise there is, and the
  published CIDR lists settle it. Inert until those lists have actually been fetched.
- **Probing for exposed secrets**: a single request for `/.env`, `/.git/config`,
  `/wp-config.php` and similar is conclusive on its own, so this needs no threshold. The
  built-in list deliberately leaves out paths that are legitimate somewhere — `/wp-login.php`,
  `/wp-admin/`, `/xmlrpc.php`, `/phpmyadmin` — since locking out your own administrator would
  be worse than missing a scanner the 404 detector catches anyway. Add your own with
  `set-probe-paths`.
- **Honeypot**: a path published only as `Disallow:` in the generated `robots.txt` and linked
  nowhere. Reaching it means ignoring robots.txt, which nothing legitimate does by accident —
  the strongest signal here, and the longest block. Needs robots.txt generation turned on to
  work at all.

### By address

- **Whole countries**, via IPdeny's aggregated CIDR lists — block specific countries, or flip
  to allow-list mode and block everything else.
- **Known-bad addresses**, via third-party lists: FireHOL level 1, Tor exit nodes and
  blocklist.de. All off by default.
- **Whole hosting providers**: AWS, Google Cloud and DigitalOcean publish their address space,
  and residential visitors don't browse from it. These are blunt instruments and labelled as
  such — they block *every* visitor hosted there, including VPN endpoints, corporate egress
  and API clients, not just bots. Off by default, with a warning when you switch one on.
- **Anything else**, by hand — add an IP/CIDR allow or block rule directly, or use the Dynamic
  Protection screen to permanently block a specific IP or user agent you've spotted before it
  ever crosses an automatic threshold.

### Nothing happens without you

Every firewall decision above is *generated*, never applied automatically: `render-firewall`
(or the Dashboard's `f` key) writes an iptables or nftables script for you to review and apply
yourself, and refuses to write one that would lock out a currently-connected SSH session. The
Dashboard's render popup can also apply it for you immediately, but only when you explicitly
ask it to (the "apply after writing" toggle) — never as a side effect of anything automatic
like the internal cron.

The same applies on the NGINX side: changing a setting only changes what *would* be written.
Site settings shows each site as `STALE` until you apply.

Switching a detector off never removes blocks it already added — those expire on their own.
"Stop detecting" and "undo what was detected" are deliberately separate; the second is the
Dynamic Protection screen or `remove-firewall-rule`.

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
        |- nginx.rs       <- NGINX site discovery, config injection and generated files
        |- sshlog.rs      <- SSH log parsing and scan detection
        |- accesslog.rs   <- NGINX access log parsing, all four detectors, UA tallying
        |- accessstats.rs <- Shared CLI+cron logic for recording access-log UA stats
        |- scanblock.rs   <- Shared CLI+cron logic for every detector's detect-and-block pass
        |- protection.rs  <- The detectors' on/off switches, their defaults, and why
        |- ipranges/      <- Crawler, country and third-party IP-range fetching/storage
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
