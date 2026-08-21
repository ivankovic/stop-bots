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

From crates.io:

```
cargo install stop-bots
```

Or build from a checkout:

```
cargo install --path .
```

A prebuilt `x86_64` Linux binary is attached to each
[release](https://github.com/ivankovic/stop-bots/releases).

Requires Rust 1.88 or newer to build. Linux only in practice: it shells out to
`systemctl`, `nginx -t` and `nft`/`iptables`, so while it compiles elsewhere it won't be
much use there.

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
  choices that shape generated config — what a blocked request gets back (see below),
  whether to serve a generated `robots.txt`, and rate limiting — above every NGINX site
  discovered on disk, each with a live "up to date / stale / not found" status and actions to
  apply the current policy to one site or all of them. Changing any of those settings flips
  every applied site to `STALE`, which is your cue to re-apply. Opening a site lets you
  override its category/bot policy, switch on any of the six request-shape rules, and list
  paths exempt from blocking.
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
  config (`apply-blocks` / Site settings' `a`/`A`).
- **Too many requests**, via NGINX's own rate limiting. Unlike everything else here this is
  enforced by NGINX at request time rather than by analysing a log afterwards. Off by default:
  a limit tuned for the wrong site turns away real visitors.
- **Politely, first** — an optional generated `robots.txt` listing every bot you're blocking,
  for the crawlers that honour it, plus the honeypot path below. Off by default, because it
  replaces whatever your site serves at `/robots.txt` today.
- **Except where you say otherwise** — per-site path exemptions, so you can block AI crawlers
  everywhere except `/blog`.
- **Requests that don't look like a browser**, per site. Six independent rules, each its own
  toggle and each off by default — one switch per rule so that if something of yours stops
  working, you can tell which rule did it:

  | Rule | Turns away, besides bots |
  |---|---|
  | HTTP/1.0 and HTTP/1.1 | crawlers and API clients that don't speak HTTP/2 |
  | No `Accept` header | some API clients send none |
  | No `Accept-Language` | privacy tooling strips it |
  | Empty/absent `User-Agent` | scripts and health checks often omit it |
  | `Host` is a bare IP | breaks reaching the site by IP |
  | TLS 1.0 / 1.1 | very old clients only |

  Two safeguards apply to all of them, and are enforced rather than left to you:
  - The two TLS-dependent rules are only written into **HTTPS** `server` blocks. Browsers
    don't do HTTP/2 without TLS, so on a plain `listen 80` block every request is HTTP/1.1 —
    including the redirect a browser makes on its way to HTTPS. Your port-80 and port-443
    blocks usually share a `server_name`, so the setting reaches both; only the TLS one gets
    those rules. The header-shape rules work over plain HTTP and are written to both.
  - `/.well-known/` is always exempt as soon as any rule is on. That's where Let's Encrypt
    fetches its HTTP-01 challenge, over HTTP/1.1 with no `Accept` and often no `User-Agent` —
    without the exemption your certificate stops renewing weeks later.

### What a blocked request actually gets

One host-wide choice, on Site settings. These aren't interchangeable status codes — each says
something different, and the difference matters most for the clients you *didn't* mean to
catch:

| Option | What it's for |
|---|---|
| `403 Forbidden` (default) | says the block was deliberate; the only one a wrongly-caught human can act on |
| `404 Not Found` | hides that anything was blocked at all |
| `410 Gone` | asks well-behaved crawlers to drop the URL **for good** — prefer this over 403 when you're turning away crawlers rather than attackers |
| `429 Too Many Requests` | tells a polite client to back off and retry |
| `418 I'm a teapot` | RFC 2324's joke. It works; it just isn't IANA-registered, and NGINX sends it with an empty body |
| `444 close connection` | no reply at all; cheapest, but indistinguishable from the server being down |
| `Tarpit` | answers 403 but trickles the body at one byte per second, so the client waits instead of moving on |

The tarpit is the gentlest option for a false positive — a wrongly caught client is slowed,
not refused — and the harshest on cost for a bot, whose connection sits idle. Two things to
know before choosing it: it holds one of *your* worker connections for the duration too, so
a flood of tarpitted clients competes with real visitors for `worker_connections`; and how
long it actually lasts depends on how NGINX chooses to write a small error body, which is
noted in TODO.md as needing a check against a real server.

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

Three more look at how a client *behaves* rather than what it asks for. All three are off by
default, because each has a false positive it cannot rule out on its own — and all three
exempt verified search-engine crawlers, which would otherwise match every one of them:

- **Fetches no assets**: many distinct pages and not one stylesheet, script or image. Browsers
  load what goes with a page. Won't catch an API client (it counts *distinct* paths, and an
  API client hits few) or a well-cached returning visitor (a `304` counts as a fetched asset).
  Can't help you on a site that serves no assets at all — a pure JSON API.
- **Rotating user agent**: several identities from one address. *Weakened considerably by
  NAT*: a carrier, campus or office gateway presents many real browsers on one IP, and without
  timestamp parsing there's no way to tell that apart from one scraper cycling agents.
- **Crawls with no referer**: many distinct deep pages, never a `Referer`. Weakened by
  `Referrer-Policy: no-referrer` and privacy tooling; the distinct-path threshold is what
  makes it usable at all.

### By address

- **Whole countries**, via IPdeny's aggregated CIDR lists — block specific countries, or flip
  to allow-list mode and block everything else.
- **Known-bad addresses**, via third-party lists: FireHOL level 1, Tor exit nodes and
  blocklist.de. All off by default.
- **Whole hosting providers**: AWS, Google Cloud and DigitalOcean publish their address space,
  and residential visitors don't browse from it. These are blunt instruments and labelled as
  such — they block *every* visitor hosted there, including VPN endpoints, corporate egress
  and API clients, not just bots. Off by default, with a warning when you switch one on.
- **Neighbouring addresses**, optionally: when several addresses in one IPv4 `/24` are flagged
  in the same pass, block the `/24`. Off by default — blocking 256 addresses because three
  misbehaved is collateral by design. (IPv6 is different and needs no switch: a detection
  always blocks the `/64`, because a `/64` is one LAN, the same thing a single IPv4 address
  represents. Blocking the single address an IPv6 attacker happened to use would stop nothing
  — they have 2^64 more.)
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

You can contact me at [marko@ivankovic.me](mailto:marko@ivankovic.me).

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

See the [LICENSE](https://github.com/ivankovic/stop-bots/blob/main/LICENSE) file for the
full text of the License.

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

Each file in src/ should end with the test module for that file, as is typical in Rust. These
tests should test both happy-path and corner cases.

**Each test in src/ must run in under 300ms** — in practice they are in-memory and finish in
microseconds.

Each general user flow should have a test in tests/. These should all be happy-path tests;
they should not test errors unless the error is a general user flow.

**Each test in tests/ must run in under 1 second.**

The budgets are enforced, not aspirational: `cargo nextest run` (what CI uses) flags any test
that exceeds them as SLOW, per `.config/nextest.toml`. Plain `cargo test` works identically,
it just doesn't report per-test time.

### How should tests handle dependencies?

*No mocks*. Mocks prevent testing through the interface and are brittle — they test the mock
of the interface, not the interface.

Ideally, the real implementation is used. Where it can't be, in order of preference:

- **In-memory fakes** for storage: SQLite's in-memory database (`Db::open_in_memory`) and
  tempdirs. These *are* the real implementation, just on throwaway backing.
- **Injected inputs** for everything the product reads from the system: `--ssh-log`,
  `--access-log`, `--root`, `STOP_BOTS_NGINX_DIR`/`STOP_BOTS_NGINX_CONF_D`. These are real
  product flags, not test back-doors — the same override an admin with a non-standard layout
  would use. A test must never read the host's real logs or config; auto-detection can shell
  out to `journalctl`, which is nondeterministic and slow.
- **Fake executables on PATH** for the external tools the product drives (`nginx`,
  `systemctl`, `nft`): tiny scripts that record their argv and exit 0 (or 1, to stage a
  failure). The product resolves and runs them exactly as it would the real tools — the
  process spawn, argument building, exit-code and ordering logic all execute for real; only
  the binary PATH finds is ours. See `fake_tools` in tests/cli.rs.
- **Golden files** (tests/golden/) for every generated artifact: firewall scripts, NGINX
  blocks, robots.txt. They lock exact bytes, and double as the samples to hand to the real
  `nft -c -f` / `nginx -t` once per change on a machine that has them. Regenerate with
  `UPDATE_GOLDENS=1 cargo test`, then review the diff.

The pty harness that drives the TUI end to end lives in tests/tui.rs itself (on raw `libc`);
see the comment there for why it isn't a crate.

### Container tests

`tests/container.rs` runs the generated output through a **real NGINX and a real nftables**,
in Docker, and checks the result by sending actual requests — including from a second
container with its own address, so a firewall rule is verified by packets that genuinely
don't arrive. It is the only place the two parsers this project writes for are exercised at
all; everything else asserts the text we hoped would satisfy them, which is exactly the check
that keeps passing when the text is wrong.

It needs Docker and `NET_ADMIN` and takes ~20s, so it is off by default:

```
make test-containers
```

CI runs it as its own job. Run it before a release, and before trusting any change to
generated config.

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
