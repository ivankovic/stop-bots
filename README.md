# Stop Bots

[![CI](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/stop-bots.svg)](https://crates.io/crates/stop-bots)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/ivankovic/stop-bots/blob/main/CONTRIBUTING.md#coverage)
[![License: AGPL v3+](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](https://github.com/ivankovic/stop-bots/blob/main/LICENSE)

A TUI, a web console and a CLI that help you configure your server to stop bad bots without
hiding behind a CDN.

It works alongside NGINX and your existing firewall (nftables or iptables):

- **NGINX config.** - It classifies known bots by category (scanners, search engines, AI
  crawlers) and blocks or allows them by injecting a rule into your site configs. It scans the NGINX
  log to detect bots dynamically and block them even if no ruleset tracks them yet.
- **A firewall script.** - Block entire countries, datacenter IP ranges, known bot IP ranges or any
  IP address that repeatedly tries to log into your server unsuccessfully. Every block records
  why it exists.

![The five screens in sequence: Dashboard, Bot settings, Firewall, NGINX and Blocks](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/tour.gif)

The app tries its best to not lock you out of the server, but you use it on your own risk. And note
that it is licensed under AGPL, so if you are using it commercially, make sure you obey the
license.

# Quick start

## Install

On Debian or Ubuntu, from the APT repository:

```
curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg \
  | sudo tee /usr/share/keyrings/stop-bots.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/stop-bots.gpg] \
https://ivankovic.github.io/stop-bots stable main" \
  | sudo tee /etc/apt/sources.list.d/stop-bots.list
sudo apt update && sudo apt install stop-bots
```

The package brings `man stop-bots` (and a page per verb, such as `man stop-bots-batch`) and
bash, zsh and fish completions. It installs no service and starts nothing.

Or from crates.io, with Rust 1.88 or newer:

```
cargo install stop-bots
```

Or download a static binary for `x86_64` or `aarch64` Linux from the GitHub
[releases](https://github.com/ivankovic/stop-bots/releases).

## Supported platforms

- **Debian and Ubuntu, with systemd and NGINX.** That is what is tested. `install` refuses a
  host that is not Debian or a derivative.
- **Not Apache or Caddy.** Their access logs may parse, but everything that writes web server
  config is NGINX-only.
- **Runtime dependencies:** `nft`, or `iptables-restore` and `ip6tables-restore`, for the
  firewall; `nginx` for the rest. NGINX in a container works too — see
  [Running NGINX in a container](#running-nginx-in-a-container).

## In the TUI

1. `sudo stop-bots` starts the TUI. It needs root: it rewrites `/etc/nginx` and loads firewall
   rules.
2. `u` downloads every list: bot lists, crawler IP ranges, and any feed or country you
   switched on.
3. Review. The Dashboard (`1`) holds the host-wide policy: which bot categories are blocked,
   countries, and the detectors that read your logs. On the NGINX screen (`4`), `r` finds your
   sites. The Blocks screen (`5`) lists every rule the detectors or you added, and why.
4. `a` applies everything. It first shows what would change — the files, the rules added and
   removed, and the lockout check's verdict (`d` for the diff) — and asks.
5. `sudo stop-bots install firewall` makes the applied rules survive a reboot. Without it, a
   reboot comes back with no rules at all.
6. `sudo stop-bots status` checks the kernel, the units and the files, and says what is
   missing.

## The same from the CLI, for scripts

```
sudo stop-bots status
sudo stop-bots batch --dry-run --diff
sudo stop-bots batch --apply
sudo stop-bots install firewall
sudo stop-bots status
```

`batch --dry-run` downloads and scans nothing: on a brand-new install it shows the NGINX
blocks from the bot list built into the binary, and no firewall rules yet, because nothing
has been read from your logs. `sudo stop-bots batch` without `--apply` does the downloads
and scans and writes the files for review without enforcing them. See
[Unattended, from cron](#unattended-from-cron) for what `batch` does.

## Undo

```
sudo stop-bots uninstall all --dry-run
sudo stop-bots uninstall all
```

The first lists every step, the second takes them. See
[Upgrading and uninstalling](#upgrading-and-uninstalling).

# What it protects against

## Using the NGINX config

- **Known bots**, by category (scanner / search engine / AI crawler), sourced from
  [ArcJet's Well-Known Bots](https://github.com/arcjet/well-known-bots),
  [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) and the
  [NGINX Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)
  list. Blocking a category injects an `if ($http_user_agent ...)` rule into each site's NGINX
  config.
- **Too many requests**, via NGINX's own rate limiting.
- **Politely, first** — a generated `robots.txt` listing every bot you're blocking, for the
  crawlers that honour it, plus the honeypot path below.
- **Except where you say otherwise** — per-site path exemptions, and trusted addresses and
  user agents (`trust`), which no block, list or rate limit applies to.
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

## What a blocked request actually gets

There are seven choices:

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
not refused — and the harshest on cost for a bot, whose connection sits idle. One thing to
know before choosing it: it holds one of *your* worker connections for the duration too, so
a flood of tarpitted clients competes with real visitors for `worker_connections`.

## From your logs, automatically

Each of these is an independent switch on the Dashboard's "Automatic blocking" panel, or
`set-detector` on the CLI. Each adds a timed firewall block. With nftables the kernel lifts
it when it runs out; with iptables it stays until the script is next applied.

Detection is windowed: a detector counts only what the logs show inside its window (a day,
or an hour for the three behavioural ones below; `set-detector --window-hours` changes it),
and a block spends the evidence that made it. So an expired block comes back only for a new
offence, and a first scan never blocks for old log lines. `list-detectors` shows each one's
switch, block length, threshold and window.

They run on an internal timer that re-reads your SSH and NGINX access logs every minute —
**but only while the TUI or the web UI is running.** Either one keeps the same schedule, in
the same database, so leaving the web UI up is enough; nothing is detected when neither is
running. For a server with no stop-bots process on it at all, see
[Unattended, from cron](#unattended-from-cron) below.

The first five are on in a new database:

- **SSH and web scanners**: IPs with a pile of failed SSH logins, or many distinct 404'd
  paths. Never an IP with a recent successful SSH login or console login, or, for the web,
  one inside a known crawler's published IP range. Requests to the console itself are never
  counted by any detector, so inspecting an attack in the console cannot block you.
- **Forged crawlers**: anything claiming to be Googlebot, Bingbot or GPTBot from an address
  that crawler's own operator doesn't publish. The cheapest common disguise there is. Inert
  until those lists have actually been fetched.
- **Probing for exposed secrets**: a single request for `/.env`, `/.git/config`,
  `/wp-config.php` and similar is an immediate ban. The built-in list deliberately leaves out
  paths that are legitimate somewhere — `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`,
  `/phpmyadmin` — since locking out your own administrator would be worse than missing a
  scanner the 404 detector catches anyway. Add your own with `set-probe-paths`.
- **Injection attempts**: a request carrying an exploit payload — in the path, the query
  string, the user agent or the referer — such as Shellshock, a Log4Shell `${jndi:` lookup, the
  PHP-CGI `allow_url_include` exploit, `$(wget …)` or `../../`, however it is encoded. One request
  is enough, and the block lasts a week. Text a person might type, such as `/etc/passwd` or
  `union select`, only counts outside search boxes and referers, so searching a blog for it is
  safe.

Off by default:

- **Honeypot**: a path published only as `Disallow:` in the generated `robots.txt` and linked
  nowhere. Reaching it means ignoring robots.txt, which deserves a ban. Needs robots.txt
  generation turned on to work at all.

Three more look at how a client *behaves* rather than what it asks for. All three are off by
default, because each has false positives — and all three exempt verified search-engine
crawlers, which would otherwise match every one of them:

- **Fetches no assets**: many distinct pages and not one stylesheet, script or image. Browsers
  load what goes with a page. Won't catch an API client (it counts *distinct* paths, and an
  API client hits few) or a well-cached returning visitor (a `304` counts as a fetched asset).
  Can't help you on a site that serves no assets at all.
- **Rotating user agent**: several identities from one address. May block a carrier, campus or
  office gateway that presents many real browsers on one IP.
- **Crawls with no referer**: many distinct deep pages, never a `Referer`. Weakened by
  `Referrer-Policy: no-referrer` and privacy tooling; the distinct-path threshold makes it
  usable.

No detector ever blocks a Cloudflare edge address — blocking an edge blocks everyone routed
through it. If your site is behind Cloudflare
and NGINX logs the edge rather than the visitor, the detectors can block nobody. `status` then
warns (`cdn-edges`) and gives the `set_real_ip_from` and `real_ip_header` lines that make
NGINX log the visitor again.

## By address

- **Whole countries**, via IPdeny's aggregated CIDR lists — block specific countries, or flip
  to allow-list mode and block everything else. Allow-list mode needs nftables.
- **Known-bad addresses**, via third-party lists: FireHOL level 1, Tor exit nodes and
  blocklist.de. All off by default.
- **Whole hosting providers**: AWS, Google Cloud and DigitalOcean publish their address space,
  and residential visitors don't browse from it. They block *every* visitor hosted there,
  including VPN endpoints, corporate egress and API clients, not just bots. Off by default.
- **Neighbouring addresses**, optionally: when several addresses in one IPv4 `/24` are flagged
  in the same pass, block the `/24` (`set-subnet-escalation`). Off by default — blocking 256
  addresses because three misbehaved is collateral by design. (IPv6 is different and needs no
  switch: a detection always blocks the `/64`, because a `/64` is one LAN, the same thing a
  single IPv4 address represents. Blocking the single address an IPv6 attacker happened to use
  would stop nothing — they have 2^64 more.)
- **Anything else**, by hand. The Firewall screen blocks an address from its failed-SSH-login
  list, or a user agent from its list of what is getting through, permanently. Any other
  address or range is `add-firewall-rule` on the CLI.

## Nothing happens without you

Every decision is *generated*, never applied automatically.

A render writes `/etc/stop-bots/firewall.next.nft` (or `firewall.next.sh` for iptables), which
nothing loads. Only an apply that succeeded copies it to `firewall.nft`, the script the boot
unit loads. Three things apply, and all of them need you to ask:

- **In the TUI**, `a` ("apply everything"), or `F` with "apply after writing" ticked.
- **In the web console**, the "Apply everything…" button, or "run it after writing" in the
  firewall panel.
- **On the CLI**, `render-firewall --apply` and `batch --apply` — see
  [Unattended, from cron](#unattended-from-cron).

`a` and "Apply everything…" show what would change first — the files, the rules added and
removed, and the lockout check's verdict, with a diff on request — and ask. From the CLI,
`batch --dry-run` prints the same and changes nothing; `--diff` adds a unified diff of every
file.

Two switches let the internal timer apply for you: `set-auto-apply` (NGINX, hourly) and
`set-auto-apply-firewall`. Both are off unless you turn them on, and the second refuses to
apply unless the lockout check could actually run.

The same applies on the NGINX side: changing a setting only changes what *would* be written.
The NGINX screen shows each site as `STALE` until you apply.

Switching a detector off never removes blocks it already added — those expire on their own.
"Stop detecting" and "undo what was detected" are deliberately separate; the second is the
Blocks screen or `remove-firewall-rule`.

# Usage

Run the binary with no arguments to launch the TUI, `stop-bots web` for the same screens in
a browser (see [The web UI](#the-web-ui)), or see `stop-bots --help` for the full list of
CLI subcommands. All UIs can be used together. Configure everything in the TUI or web UI and
then use the CLI in a crontab to keep the rules updated.

Run it as root. The database is `/var/lib/stop-bots/db.sqlite3`; as a user who can't write
there, stop-bots falls back to one under `~/.local/share/stop-bots/`, and the TUI and the
console show a banner saying so. `--db <path>`, before or after any subcommand, or
`STOP_BOTS_DB` picks another.

## TUI

`1`–`5` (or `d`, `b`, `f`, `n`, `x`) jump to a screen, `?` opens a full key-binding reference
at any time, and `:` opens a command palette listing every action by name. You can exit the
app, or back out of a popup or submenu, with `q` or Escape. The digits, the letters and `?`
work in the web UI too; `:` is the TUI's own.

### Theme

You can switch between the dark and light theme with 't'. The app will try to auto-detect the theme,
but for some terminal and multiplexer combinations there isn't enough information available to make
the correct choice.

### Screens

The Dashboard, the Firewall screen and the Blocks screen own everything that ends up in the
**firewall script**; the NGINX screen owns everything that ends up in **NGINX config**.

- **Dashboard** (the default screen): system-wide category defaults (Scanners / Search bots /
  AI bots — Allowed or Blocked); host-wide geo-blocking (block or allow-list specific
  countries); a "Crawler IP ranges" panel (Googlebot, Bingbot and GPTBot's published
  addresses, with how many and how old, `Enter` to download one); an "Automatic blocking" panel with an on/off switch for each detector and each
  third-party blocklist (a detector added by an upgrade arrives off, marked "new"); a
  "Firewall script" panel (how many rules a render would write, and whether they are applied,
  rendered and not applied, or changed); a "Scheduled" panel showing the internal cron's jobs
  and when they last ran; and a Log of what the app last did. A status strip under the tabs
  shows the host's health checks on every screen. `Up`/`Down` flow between the lists; `m`
  switches geo mode. `F` renders the firewall script, with an "apply after writing" toggle
  (Space). Three more keys act on the whole host: `u` downloads every list, `a` applies both
  planes (NGINX, then the firewall) after showing what would change, and `w` puts this
  console behind NGINX — the same three the browser has as buttons and a panel.
- **Bot settings**: lists every known bot-list source (with an action to refresh it) and every
  individual bot, searchable by name, with a per-bot override (Allowed / Blocked / follow the
  category default).
- **Firewall**: a live, actionable view of what's currently hitting the server — "Failed SSH
  logins" and "Top user agents", each ranked by count and tagged `NOT BLOCKED`, `BLOCKLIST`,
  or `BLOCKED` (in red, naming the detector that blocked it) — and a "Trusted" panel.
  `Tab`/`Shift+Tab` switch panels; `f` cycles a shared filter (all / not blocked only /
  blocked only); `Enter` blocks the selected `NOT BLOCKED` row permanently, or unblocks it if
  it's already `BLOCKED`; `T` trusts it, so nothing ever blocks it. `i` inspects the selected
  address: which of the reputation feeds list it, whether it is inside a published crawler
  range (which is what separates a real Googlebot from a user agent that merely says so),
  which country it belongs to, and which accounts it tried to log in as. All of it from lists
  this host has already downloaded — there is no reverse DNS or whois lookup here, because a
  PTR record is written by whoever holds the address and would be attacker-supplied text that
  reads as authoritative.
- **NGINX**: an "NGINX settings" panel (`Tab` to focus it) holding the host-wide
  choices that shape generated config — what a blocked request gets back (see above),
  whether to serve a generated `robots.txt`, and rate limiting — above every NGINX site
  discovered on disk (`r` scans for them), each with a live "up to date / stale / not found"
  status and actions to apply the current policy to one site or all of them. Changing any of
  those settings flips every applied site to `STALE`, which is your cue to re-apply. Opening a
  site lets you override its category policy, allow or block one bot on that site only
  (searched by name, in the TUI and the console alike), switch on any of the six
  request-shape rules, and list paths exempt from blocking.
- **Blocks**: every firewall rule stored, and why it is there — its source (a detector, or
  added by hand in the TUI, the console or the CLI), when it was added, when it expires, and
  the log line that triggered it. `f` filters by source, `/` searches by address (an address
  finds the range that blocks it), `Enter` unblocks one rule and `U` every rule from the
  filtered source, after saying how many. An unblock sticks: the detector leaves that address
  alone for as long as the block was meant to last, even though the log still holds the lines
  that earned it. To exempt an address for good, trust it.
- **Help**: the full key-binding reference.

The Dashboard, where the host-wide policy and the firewall script live:

![The stop-bots dashboard: system-wide bot categories, geo-blocking, automatic detectors and the internal cron](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/dashboard.svg)

Bot settings, where every list source and every individual bot lives:

![Bot settings: the four bot-list sources with their counts, and a search matching six bots across categories](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/bot-settings.svg)

Firewall, the live view of what is hitting the server right now:

![Firewall: failed SSH logins and top user agents, each row tagged BLOCKED with its detector, BLOCKLIST or NOT BLOCKED, above the Trusted panel](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/firewall.svg)

NGINX, where the host-wide choices sit above every site found on disk:

![NGINX: block response, robots.txt and rate limiting, above two sites tagged UP TO DATE and STALE](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/nginx.svg)

Blocks, every rule and the log line behind it:

![Blocks: five rules with their source, age and expiry, and the injection attempt that caused the selected one](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/blocks.svg)

## The web UI

`stop-bots web` serves the same six screens in a browser: Dashboard, Bot settings, Firewall,
NGINX, Blocks (`/blocks`) and Help.

```
stop-bots web
```

It binds **127.0.0.1:8787** — reachable only from that machine — and prints a generated
password once, on first run. Reach it from your laptop over an SSH tunnel:

```
ssh -L 8787:127.0.0.1:8787 your-server
```

then open <http://127.0.0.1:8787/>.

![The web console's dashboard: health chips and the two host-wide buttons in the header, policy, geo-blocking and third-party feeds in one column, automatic blocking and scheduled tasks in the other](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/web-dashboard.png)

The console follows the operating system's light or dark setting, with a toggle in the
header; the TUI screenshots above are the dark theme, these the light one. The keys the
TUI uses work here too: `1`–`5` switch screens, `/` focuses the search box, `?` opens Help.

![The web console's Firewall page: failed SSH logins and top user agents, each with a count bar and a state tag, and a block, unblock or trust button per row](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/web-firewall.png)

Three host-wide actions live in the header, in the browser as buttons and in the TUI
as single keys:

- **Update everything** (`u`) downloads every bot list, every crawler IP range, every
  *enabled* reputation feed and every *selected* country — the same set `stop-bots batch`
  fetches, from the same plan. One source failing does not stop the rest, and nothing is
  enforced until something applies it.
- **Apply everything…** (`a`) shows what would change and asks, then writes and reloads the
  NGINX config, then writes and runs the firewall script. The two planes are independent:
  whichever fails, the other still gets its turn, because a half-applied host beats one where
  an NGINX syntax error also left the firewall stale.
- **Web Access** (`w`) sets NGINX up to serve the console itself — see
  [Behind NGINX](#behind-nginx-a-subdomain-or-a-path-prefix).

`stop-bots web --no-apply` starts a console that writes the config and the script but
reloads and runs neither. It runs everything in its own process, so it needs root, and it
cannot be combined with `--helper`, which the service uses (see below). A console that is
neither root nor given a helper is read-only: every page works, and every action says why
it can't.

### As a service (Debian)

```
sudo stop-bots install web
```

Creates the `stop-bots` system user, gives it `/var/lib/stop-bots` (0700 — it holds the
console's password hash) and the database in it (0600), creates `/etc/stop-bots`, writes three
systemd units, generates a password if there isn't one, and enables and starts them.

**`--dry-run` prints the whole plan and changes nothing.** `--prefix <dir>` writes the same tree
somewhere you can read it without root, and creates no user. Re-running it replaces the units
it wrote, from any version, as long as you have not edited them; if you have, the installer
stops and says so rather than replacing your edit, and `--force` replaces it anyway. It
restarts the console, so a new unit takes effect.

**Two processes, and only one of them is root:**

- **The console**, `stop-bots-web.service`, runs as the `stop-bots` user. It reads the NGINX
  and SSH logs through the `adm` and `systemd-journal` groups, which its unit adds (nothing is
  added to `/etc/group`), and writes its database and nothing else. It holds no Linux
  capability, has no access to netlink, so it cannot change the firewall, and cannot see
  systemd's sockets.
- **The helper**, `stop-bots-helper.service`, runs as root. systemd starts it when the console
  first connects to `/run/stop-bots/helper.sock` (`stop-bots-helper.socket`). Only root and the
  `stop-bots` group can open that socket, and the helper also checks the user of each caller.
  It writes the NGINX config and the firewall script, and runs `nginx -t`, the NGINX reload
  and `nft`. It accepts a fixed set of requests: apply NGINX, apply the firewall, set up Web
  Access, find the sites, check the host's health. No request contains a path, a command or
  config text. The NGINX commands, the NGINX config root and the log paths come from
  `/etc/stop-bots/host.conf`, which only root can write, not from the database.

**What someone who takes over the console can do, and what they cannot.** If an attacker gets
code running in the console, they have the `stop-bots` user and what it can reach:

- They can do what a logged-in operator can do: change the blocking policy, block or unblock
  any address, and apply. The detectors run in the console, so they can also make it block or
  unblock anything.
- They can read what the console reads: the logs, and the database with the password hash.
- They cannot get root through the console. They cannot write to `/etc`, cron, systemd units
  or binaries, cannot ask systemd to start anything, and cannot choose what the helper runs or
  which files it writes or deletes. The helper treats the database as hostile: it finds the
  sites to change on disk, checks again everything it writes from the database, and deletes
  only the files stop-bots generated.

The helper has the sandbox the console had before 0.1: `ProtectSystem=strict`, with write
access only to the database, `/etc/stop-bots`, the NGINX config root, the log directories that
config names (`nginx -t` opens them for writing) and `/run`. This stops a write to cron,
systemd units or binaries that the helper was tricked into. It does not stop code that runs as
the helper: that code is root, and root that can ask systemd to reload NGINX can ask it for
more. If you later add a site that logs somewhere new, re-run `install web` so the helper's
unit grants it.

Both processes yield to the host: they run at `Nice=10` with idle I/O priority, and systemd
throttles each at a quarter of RAM and stops it at half. `sudo stop-bots status` warns if the
console runs as root, if it has no helper, or if its user cannot read a log it must read.

Only Debian is checked for, because that is what has been tested; the units are very likely
correct on any systemd distribution, but the SSH log path the console assumes is Debian's.

### Exposing it

The flags `stop-bots web` takes are for that run only. What every later run and the service
read is set with `stop-bots set-web`; with no flags it prints what is stored.

Binding anything but loopback takes a second, deliberate setting, because this console can
rewrite the firewall and the NGINX config of the host it runs on:

```
stop-bots set-web --bind 0.0.0.0:8787 --expose true --allowed-hosts admin.example.com
```

`--allowed-hosts` is not optional in practice: a request carrying a host name that isn't
listed is refused.

Put it behind NGINX with TLS — the same NGINX this tool is protecting. If you do, and the
proxy sets `X-Forwarded-For`, tell the console it may believe that header, or it cannot
tell which address a request really came from:

```
stop-bots set-web --bind 127.0.0.1:8787 --trust-forwarded-for true --secure-cookie true
```

`--secure-cookie true` is for TLS. Without it a browser will send the session cookie to an
`http://` URL for the same host as well. `stop-bots install web` takes the same flags and
stores them the same way. Both stay set until you pass `false`.

`--trust-forwarded-for` matters more than it looks. Without it every request behind a
proxy arrives from `127.0.0.1`, so the console cannot tell one client from another: the
login throttle has one key for you and every attacker, and the guard that stops you
blocking your own address has nothing to compare against. With it, both work per-client.
The console believes only the last address in the header, the one the proxy itself added.
The Web Access panel below turns it on for the proxy it writes, and the health report
warns about a proxied console that has it off.

### Behind NGINX: a subdomain, or a path prefix

**The console can set this up for you**, and so can the TUI (`w` on the Dashboard). Both
write the NGINX config, record the path prefix and add the host name to the allowlist — the
three things that have to agree, because a missing prefix makes every link leave the
`location` block and a missing host name makes every request a 403. Both validate with
`nginx -t` before the config can take effect, roll it back if that fails, and record the
new address only once it validated. Recording it also turns on `--trust-forwarded-for`,
since the block it wrote sets that header, and `--secure-cookie` when path mode lands in a
site's TLS block. A subdomain starts on plain HTTP, so after `certbot` run
`stop-bots set-web --secure-cookie true` yourself.

Two modes, and *path* is the default for a reason: it adds a `location` block to a site you
already have, so the console inherits that site's certificate. A subdomain needs its own,
and until `certbot --nginx -d <host>` has run, this console's password form and session
cookie cross the network in the clear.

**Path mode shares an origin with everything else on that site.** A script running on any
other page of it can use your logged-in console. Use path mode only on a site that runs
nothing you don't fully trust; otherwise, use a subdomain.

The rest of this section is the same thing by hand, which is worth reading once even if you
use the panel — the trailing-slash trap below is the mistake it exists to prevent.

**A subdomain is the simpler deployment**, and the one to take if you can:

```nginx
server {
    server_name stopbots.example.com;
    # Keeps the console's own requests out of the log the detectors read.
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```
stop-bots set-web --allowed-hosts stopbots.example.com --trust-forwarded-for true
```

**A path prefix works too**, but the console has to be told about it — it needs to
generate every link, form action, redirect and cookie path with the prefix already in
them, and it cannot guess:

```
stop-bots set-web --base-path /stop-bots --allowed-hosts example.com --trust-forwarded-for true
```

```nginx
location /stop-bots/ {
    proxy_pass http://127.0.0.1:8787;   # NO trailing slash
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

**The trailing slash on `proxy_pass` matters, and its absence is the whole trick.**
Without it, NGINX passes the full path through and `stop-bots` sees
`/stop-bots/whatever`, which is what it now serves and generates. *With* a trailing
slash, NGINX strips the prefix — and then the browser resolves the links in the page
against the domain root, lands outside the `location` block, and everything 404s. No
amount of care on the server's side can fix that, so the prefix has to survive the
proxy.

Nothing enforces this from outside, but the failure is loud rather than subtle: with the
prefix configured, an unprefixed request is a plain 404 rather than a page that
half-works. A changed prefix takes effect when the console restarts.

### What it will not do

Two things are missing on purpose, and the Help screen says so with the reasons:

- **It will not unblock something a downloaded list blocked** — the next refresh of that
  list would silently undo it. Trust it instead: trust outranks every list.
- **It will not change its own password.** Use `stop-bots web --set-password` on the host.

It also refuses to block the address you are connected from, which would take away the
console you'd use to undo it.

Login attempts are throttled. Not because the password is guessable — it is generated,
144 bits — but because verifying one runs Argon2id, and letting an unauthenticated caller
drive that as fast as they can post is a denial of service against the host this tool is
supposed to be protecting. Ten wrong attempts are free; past that a client backs off
exponentially, to at most thirty seconds, and IPv6 clients are counted by their /64. A
global limit caps the work everyone together can cause.

A flood cannot keep you out of a browser you have logged in with before. A successful
login sets a 90-day cookie that remembers the browser; a login from it skips both limits
and has a small one of its own. It still needs the password. `stop-bots web
--set-password` forgets every remembered browser.

## The CLI

Everything the screens set has a verb, so a host can be configured from a script:

- detectors: `list-detectors`, `set-detector <name> --enabled --ttl-days --threshold
  --window-hours`, `set-subnet-escalation`;
- bots: `list-categories`, `set-category`, `list-bots`, `set-bot` (the last two setters take
  `--site` for a per-site override);
- the firewall: `set-firewall-backend`, `add-firewall-rule`, `list-firewall-rules`,
  `remove-firewall-rule --id` or `--source`, `set-firewall-rule --enabled`, `trust`;
- the console: `set-web`.

`stop-bots <verb> --help` says what each one does, and `man stop-bots-<verb>` has the same.

## Unattended, from cron

`stop-bots batch` is one pass over everything the TUI does by hand: refresh every list,
scan the logs, write the NGINX blocking rules and the firewall script.

```
# One full pass a night. Refreshes the lists, scans the logs, applies both.
0 4 * * * root /usr/bin/stop-bots batch --apply

# And detection every ten minutes, without re-downloading lists that change weekly.
*/10 * * * * root /usr/bin/stop-bots batch --apply --no-fetch
```

(`/usr/bin` is where the package puts it; `cargo install` puts it in `~/.cargo/bin`.)

The SSH log is found on its own: `/var/log/auth.log` where rsyslog writes one (Ubuntu), the
journal where it doesn't (Debian 12 and later). Name a file with `--ssh-log`, or store one
with `sudo stop-bots set-log-paths`, only if yours is somewhere else — a named file that does not exist
makes `--apply` refuse, because the lockout check cannot run.

It says nothing when everything worked, so a healthy nightly run doesn't mail you. A failed
step prints to stderr and sets a non-zero exit status, which is what makes cron tell you
about it. Run it once by hand with `--dry-run --diff` first to see what it would change, and
with `--verbose` to see a line per step.

**`--apply` is what makes it enforce anything.** Without it, `batch` writes the NGINX config
and `firewall.next.nft` and stops: config does nothing until a reload, and nothing loads that
script.

`batch` and a long-running front-end coexist safely. The TUI, the web UI and `batch` all
record what they did through the same keys in the same database, so whichever gets to a job
first does it and the others find it no longer due. Only one of them downloads at a time (a
second says so and fetches nothing), and only one applies at a time (a second waits up to ten
seconds, then says another stop-bots is applying).

The internal timer in the TUI and the console runs the detectors every minute, downloads the
crawler IP ranges daily and every list weekly ("Update every list", a week plus up to twelve
hours after the last run, so hosts drift apart instead of all asking at once), and renders
the firewall script daily.

**With `--apply`, the SSH lockout guard can refuse — and refusing means nothing is applied.**
It refuses if the rules would block a client that is connected right now; then nothing is
written either. It also refuses if no SSH log could be read at all, because then the check
could not run; the script is still written for you to review. `--force` overrides the guard
if you mean it.

One step failing never stops the others, and the NGINX and firewall halves are independent —
a failed NGINX reload still leaves the firewall applied, and the other way round.

# Upgrading and uninstalling

Upgrading needs the new binary and, if the web console runs as a service, `sudo stop-bots
install web` (below). The first root run of stop-bots after an upgrade from 0.1.0-rc.2 or
older moves the host settings — the NGINX commands and config root, and the log paths — out
of the database into `/etc/stop-bots/host.conf`, which only root can write. Before it changes
the database's layout, stop-bots
copies the database to `<db>.bak-v<N>` (mode 0600), where `N` is the old schema version. A
database written by a newer stop-bots is refused rather than misread; run the newer one.

An upgrade never switches a detector on. One added in a later release arrives off on an
existing install, marked "new" in the Automatic blocking panel until you switch it either way.

After an upgrade, re-run `sudo stop-bots install web` (and `install firewall`) to pick up the
new units; an unedited unit is replaced without `--force`.

`sudo stop-bots uninstall` puts the host back as it was: it stops and removes its units (the
console, its helper and socket, and the firewall's),
deletes the nft table or iptables chain, takes the blocks out of every NGINX site (tested with
`nginx -t`, and put back if that fails), and deletes the generated files. `nginx`, `firewall`
or `web` removes one part; `all` is the default. The database and `/etc/stop-bots/host.conf`
are kept unless you pass `--purge`, which also removes the `stop-bots` user and group. Run it
with `--dry-run` first.

# Reference

## Running NGINX in a container

If NGINX is in Docker and its config is on a bind mount, `systemctl reload nginx` reloads
nothing. Point the two commands at the container instead — this applies to the CLI, the TUI
and the console's helper alike. They are stored in `/etc/stop-bots/host.conf`, which only
root can write, because they are commands root runs:

```
sudo stop-bots set-nginx-commands \
  --test   "docker exec web nginx -t" \
  --reload "docker exec web nginx -s reload"
```

The command is split into words and run directly. It never goes through a shell, so `;`,
`|` and `$VAR` are ordinary characters rather than syntax.

## Building

Requires Rust 1.88 or newer to build: `cargo install --path .` from a checkout. Linux only in
practice: it shells out to `systemctl`, `nginx -t` and `nft`/`iptables`, so while it compiles
elsewhere it won't be much use there.

# Contributing

Contributions are not accepted at this time. [CONTRIBUTING.md](CONTRIBUTING.md) describes how
the maintainer works on the project.

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
