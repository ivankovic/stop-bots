# Stop Bots

[![CI](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/stop-bots.svg)](https://crates.io/crates/stop-bots)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/ivankovic/stop-bots/blob/main/CONTRIBUTING.md#coverage)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue)](https://github.com/ivankovic/stop-bots/blob/main/Cargo.toml)
[![License: AGPL v3+](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](https://github.com/ivankovic/stop-bots/blob/main/LICENSE)

A TUI (and CLI) that helps you configure your server to stop bad bots without hiding behind a CDN.

It works alongside NGINX and your existing firewall (iptables or nftables), on two separate
planes:

- **NGINX config.** - It classifies known bots by category (scanners, search engines, AI
  crawlers) and blocks or allows them by injecting a rule into your site configs. It scans the NGINX
  log to detect bots dynamically and block them even if no ruleset tracks them yet.
- **A firewall script.** - Block entire countries, datacenter IP ranges, known bot IP ranges or any
  IP address that repeatedly tries to log into your server unsuccessfully.

![The stop-bots dashboard: system-wide bot categories, geo-blocking, automatic detectors and the internal cron](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/dashboard.svg)

The app tries its best to not lock you out of the server, but you use it on your own risk. And note
that it is licensed under AGPL, so if you are using it commercially, make sure you obey the letter
of the license.

# Installation

From crates.io:

```
cargo install stop-bots
```

Or build from a checkout:

```
cargo install --path .
```

A prebuilt `x86_64` Linux binary is available on GitHub [releases](https://github.com/ivankovic/stop-bots/releases).

## Dependencies

Requires Rust 1.88 or newer to build. Linux only in practice: it shells out to
`systemctl`, `nginx -t` and `nft`/`iptables`, so while it compiles elsewhere it won't be
much use there.

# Usage

Run the binary with no arguments to launch the TUI, or see `stop-bots --help` for the full
list of CLI subcommands. The TUI and CLI can be used together. Configure everything in the TUI and
then use the CLI in a crontab to keep the rules updated.

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

Bot settings, where every list source and every individual bot lives:

![Bot settings: the three bot-list sources with their counts, and a search matching five bots across categories](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/bot-settings.svg)

Site settings, where the host-wide NGINX choices sit above every site found on disk:

![Site settings: block response, robots.txt and rate limiting, above two sites tagged UP TO DATE and STALE](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/site-settings.svg)

Dynamic Protection, the live view of what is hitting the server right now:

![Dynamic Protection: failed SSH logins and top user agents, each row tagged BLOCKED, BLOCKLIST or NOT BLOCKED](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/dynamic-protection.svg)


## What it actually protects against

### Using the NGINX config

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
**but only while the TUI is open.** Nothing is detected when the process isn't running. For
a server you aren't sitting in front of, see [Unattended, from cron](#unattended-from-cron)
below.

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
like the internal cron. The one way to have it applied unattended is `batch --apply`, which
you have to put in a crontab yourself; see [Unattended, from cron](#unattended-from-cron).

The same applies on the NGINX side: changing a setting only changes what *would* be written.
Site settings shows each site as `STALE` until you apply.

Switching a detector off never removes blocks it already added — those expire on their own.
"Stop detecting" and "undo what was detected" are deliberately separate; the second is the
Dynamic Protection screen or `remove-firewall-rule`.

There's also a plain access-log tally, independent of blocking: `record-access-stats` /
`list-access-stats` count how often each user agent shows up in successful (non-error)
requests, so you can see who's actually visiting on top of who's being blocked.

## Unattended, from cron

`stop-bots batch` is one pass over everything the TUI does by hand: refresh every list,
scan the logs, write the NGINX blocking rules and the firewall script.

```
# One full pass a night. Refreshes the lists, scans the logs, applies both.
0 4 * * * root /usr/local/bin/stop-bots batch --apply --ssh-log /var/log/auth.log

# And detection every ten minutes, without re-downloading lists that change weekly.
*/10 * * * * root /usr/local/bin/stop-bots batch --apply --no-fetch --ssh-log /var/log/auth.log
```

It says nothing when everything worked, so a healthy nightly run doesn't mail you. A failed
step prints to stderr and sets a non-zero exit status, which is what makes cron tell you
about it. Run it once by hand with `--verbose` first — that prints a line per step, and is
the easiest way to see what it is actually doing.

**`--apply` is what makes it enforce anything.** Without it, `batch` writes the NGINX config
and the firewall script and stops: config does nothing until a reload, a script does nothing
until it is run. That is this project's default everywhere, and it stays the default here.

**With `--apply`, the SSH lockout guard can refuse — and refusing means nothing is applied.**
It refuses if the rules would block a client that is connected right now, *and* if no SSH log
could be read at all, because then the check could not run. The interactive
`render-firewall` only prints a note in that second case, on the reasoning that a human is
watching the terminal; from cron nobody is. **Pass `--ssh-log` explicitly**: cron runs as
root so `/var/log/auth.log` usually reads fine, but on a journald-only host `journalctl`
under cron can come back empty, which is exactly the case it refuses on. `--force` overrides
the guard if you mean it.

One step failing never stops the others, and the NGINX and firewall halves are independent —
a failed NGINX reload still leaves the firewall applied, and the other way round.

`batch` records each step against the same schedule the TUI's internal cron uses, so the two
agree about what has already run instead of both doing it, and the Dashboard's "Scheduled
tasks" panel shows what your real cron did.

# Contributing

How the code is laid out, how it is tested, and the rules it is written to are in
[CONTRIBUTING.md](https://github.com/ivankovic/stop-bots/blob/main/CONTRIBUTING.md). The release process is in
[RELEASING.md](https://github.com/ivankovic/stop-bots/blob/main/RELEASING.md).

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

Alternative licensing is **NOT** available.
