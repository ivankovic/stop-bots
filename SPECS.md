# Specifications & Decision Log

This file collects the decisions taken while implementing the database, NGINX
integration and bot-list pipeline. See README.md for the high-level product
description.

## Scope of this pass

Implemented: SQLite storage, NGINX site discovery + bot-blocking config
injection, downloading/storing a bot list, IP-based firewall rule generation
(iptables/nftables), and the TUI. Explicitly **not** implemented yet (left
for later, see TODO.md): geo-blocking and per-site bot overrides.

A previous, much larger implementation of this project (TUI, firewall
integration, 12-table schema, multiple bot-list fetchers) was deleted wholesale
(`human: remove this shit`). This pass deliberately stays small: one schema,
one bot-list source, one NGINX injection mechanism, CLI only.

## Database (`src/db.rs`)

Four tables, no per-site bot overrides (yet):

- `sources` — bot-list data sources (currently just `well-known-bots`).
- `bots` — normalized bots: `slug`, `name`, category flags (`is_ai`,
  `is_search_engine`, `is_scanner`), `user_agent_pattern` (a `|`-joined regex
  alternation), and a `status` (`default` / `allowed` / `blocked`).
- `sites` — NGINX sites discovered on disk (`server_name` + `config_path`).
- `settings` — global per-category default policy
  (`default_status_{scanner,search,ai}`), seeded to match the README mockup:
  scanners and AI bots blocked by default, search engines allowed.

A bot's effective blocked/allowed state is `status` if explicitly set,
otherwise the category default. Refreshing a bot list (`upsert_bot`) updates a
bot's metadata but never touches `status`, so a manual override survives
future `update-bot-lists` runs.

## NGINX integration (`src/nginx.rs`)

**Site discovery** walks a config root directory (`walkdir`) looking for
`server { ... }` blocks in any file, rather than following `include`
directives from `nginx.conf`. This matches how the `conf.d/` +
`sites-enabled/` layout is actually laid out on disk and avoids having to
resolve NGINX's include-glob semantics; the caller just points at the NGINX
config root (default `/etc/nginx`).

**Bot blocking mechanism** — two options were considered:

1. A single generated file dropped into `conf.d/`, relying on NGINX's default
   `include conf.d/*.conf` and a `map` block. Never touches existing site
   files, but blocking would be global-only and a `map` doesn't have an
   `if (...) { return 403; }` without an extra per-site reference anyway.
2. **(chosen)** A sentinel-marked block injected directly into each site's
   `server { ... }` block:
   ```
   # BEGIN stop-bots (DO NOT EDIT)
   if ($http_user_agent ~* "pattern1|pattern2") {
       return 403;
   }
   # END stop-bots
   ```
   Chosen because it supports true per-site blocking (matches the README's
   per-site override model) and is reversible/idempotent: the sentinel
   comments mean re-running only ever replaces those exact lines, never
   anything else in the file, and removing the rule is a clean line-range
   delete.

The block is generated from `Db::blocked_user_agent_patterns()`, which is
currently the same list for every site (no per-site overrides exist yet).

`apply_blocks_to_file` applies the rule to *every* `server` block in a file,
not just one looked up by name: the common redirect-plus-main-site layout
(an HTTP block that 301s to HTTPS, plus the real HTTPS block) has two
`server` blocks sharing the same `server_name`, and a name-based lookup would
only ever touch the first one found.

NGINX itself was not available in this environment to validate the generated
config with `nginx -t` at the time this was written; it has since become
available and was used to find and fix a real quoting bug — see "NGINX
reload, a real quoting bug, and a duplicate search hint" below.

Parsing avoids both a regex crate and a full NGINX grammar: a single
comment-aware tokenizer (`#` strips to end of line) feeds a brace-depth stack
that tags any `{` immediately preceded by the word `server`, so nested
`location {}` blocks and commented-out blocks (including ones containing
literal `{`/`}`, as in the test fixtures) are handled correctly.

## Bot list (`src/botlist/`)

Source: [ArcJet Well-Known Bots](https://github.com/arcjet/well-known-bots)
(`well-known-bots.json`), chosen because it's actively maintained, already
categorizes ~635 bots, and was already used (with an out-of-date JSON shape)
in the previous implementation. Each entry's `categories` array is mapped to
the local flags: `ai` -> `is_ai`, `search-engine` -> `is_search_engine`. There
is currently no upstream data source mapped to `is_scanner` (well-known-bots
covers crawlers, not malicious scanners) — see TODO.md.

Fetching (network IO, async via `reqwest`) and parsing (pure, sync) are
separate functions so tests can exercise parsing against a local fixture
(`tests/fixtures/botlists/well-known-bots-sample.json`) without any network
access.

## Firewall integration (`src/db.rs` firewall_rules, `src/iptables.rs`, `src/nftables.rs`)

Firewall rules (IP/CIDR + optional port + allow/block/reject) live in their
own `firewall_rules` table, independent of the `bots`/`sites` tables: no
current bot-list source provides IP ranges (see TODO.md), so this is plain
admin-managed allow/block list for now, not bot-driven.

**Generate-only, by design.** Asked directly, the choice was: render a script
to a file and let the admin apply it themselves, rather than have this tool
shell out to `iptables`/`nft` at all. `src/iptables.rs::render` and
`src/nftables.rs::render` are pure functions (`&[FirewallRule] -> String`);
neither module ever calls `Command::new("iptables")` / `Command::new("nft")`,
not even behind a flag. `nginx -t`-style validation of the generated syntax
against a real parser wasn't possible either (iptables/nft aren't installed
in this environment) — the guarantee is "matches the fixture shapes in
`tests/fixtures/{iptables,nftables}/`", not "validated by the real tool".

**Why the rendered output deliberately doesn't look like the fixtures.**
`tests/fixtures/iptables/basic_rules.txt` and `tests/fixtures/nftables/*.nft`
are realistic hand-written examples, but copying their structure verbatim as
*generated* output would be dangerous to hand an admin as "run this":

- The iptables fixture is in `iptables-restore` format (`*filter` /
  `:INPUT DROP [0:0]` / `COMMIT`). Restoring that replaces the *entire*
  filter table — chain policies and any unrelated rules (e.g. an existing SSH
  allow rule) get silently wiped. Instead, `iptables::render` emits a shell
  script of individually-additive `iptables` commands that only ever touch a
  dedicated `STOP-BOTS` chain: create-if-missing, flush *only that chain*,
  add an `INPUT -j STOP-BOTS` jump *only if not already present* (via
  `iptables -C`), then `-A` one line per rule. Safe to run alongside whatever
  else is already configured, and safe to re-run (no duplicate jump rules,
  no duplicate `-A` lines since the chain is flushed first).
- `tests/fixtures/nftables/basic_rules.nft` opens with `flush ruleset`, which
  wipes *every* nftables table on the system, and its chain has
  `policy drop` on a `hook input priority -1` chain — meaning *any* inbound
  packet not explicitly accepted by that chain gets dropped, making it the
  de facto gatekeeper for all traffic to the host regardless of any other
  rules. `nftables::render` never flushes the whole ruleset (only
  `flush chain inet stop_bots bot_block`, scoped to our own chain) and uses
  `policy accept`, so the chain only ever blocks the specific addresses it's
  told to. Idempotency for `nftables::render` works by resetting only our own
  table each run (`add table` (no-op if it exists) → `delete table` (now
  guaranteed to exist) → `add table` again, leaving a fresh empty table),
  rather than `flush chain`: re-declaring an already-existing hooked base
  chain via `add chain` is not reliably a no-op the way `add table` is.

**`iptables` is IPv4-only.** Feeding it an IPv6 address in a `-s` rule fails
at apply time (`host/network ... not found`), and with `set -e` that would
abort the script partway through, leaving some rules applied and others not.
`iptables::render` therefore skips IPv6 addresses, leaving a comment in their
place pointing at `nftables::render` (which handles both families in one
table via `ip`/`ip6 saddr`) instead of silently emitting a rule that breaks
on a real box.

`FirewallRule` has no protocol field — ports are rendered as TCP
(`-p tcp --dport <port>` / `tcp dport <port>`) even though the fixtures show
UDP examples too; a real protocol field is deferred until something needs it
(see TODO.md).

**`firewall_rules.expires_at` — this project's first schema migration.**
Added for the scanner-detection commands' temporary blocks (see "SSH scan
detection"/"Web scan detection" below): `NULL` for a permanent, hand-added
rule, a Unix timestamp for a temporary auto-added one. Every table so far
had been `CREATE TABLE IF NOT EXISTS` from day one — the `Bot::source_id`
doc comment even notes this project had never needed a real migration
before. A brand-new column needs one: `CREATE TABLE IF NOT EXISTS` only
adds it for a database created fresh by this version, so `init_schema`
also checks `pragma_table_info('firewall_rules')` for the column and runs
a guarded `ALTER TABLE ... ADD COLUMN` if an existing (pre-this-version)
database is missing it — guarded because an unconditional `ALTER` would
itself error ("duplicate column name") on a freshly created database that
already has the column via `CREATE TABLE`.

## TUI (`src/app.rs`, `src/event.rs`, `src/tui.rs`, `src/tui/`)

Follows the Ratatui event-driven-async template
(<https://github.com/ratatui/templates/tree/main/event-driven-async>), pulled
directly from the repo rather than recalled from memory: `event.rs` is an
almost verbatim copy (`Event`/`AppEvent`/`EventHandler`, a background task
emitting tick + crossterm events over an mpsc channel). `app.rs` deviates
from the template in one way: the template renders via `impl Widget for
&App` (an *immutable* borrow), which can't reach a mutable `ListState` for
list navigation. `App` instead has an inherent `render(&mut self, frame)`
called as `terminal.draw(|frame| tui::render(&mut self, frame))`, so screens
can use `frame.render_stateful_widget`.

Required bumping `ratatui` 0.27 → 0.30 (the template needs
`ratatui::init()`/`DefaultTerminal`, added in 0.28.1) and `crossterm` 0.28 →
0.29 (ratatui 0.30's actual transitive dependency, via the new
`ratatui-crossterm` backend crate — pinning our own crossterm to 0.28 like
the template's Cargo.toml resolved two different crossterm versions in the
tree, which risks `KeyEvent` type-mismatch errors between crates).

**Screens**, per the renames already decided in REVIEW.md before the
previous implementation was deleted: **Dashboard** (default screen — site
count, bot-source up-to-date/stale counts, last action message, *and* the
three category defaults, navigable and editable via a popup — see the
redesign note below), **Bot settings** (every bot-list source — name, last
fetched, signal/bot count — with Enter opening a Cancel/Update-now
confirmation popup, followed by every known bot and its effective status,
changeable via its own popup), **Site settings** (read-only list of
discovered sites — no per-site override storage exists yet, see TODO.md). A
**Help** screen (`?`) is reachable from any of the three and returns to
whichever one was active.

**Redesign (per REVIEW.md, after the initial cut above shipped):** the three
category defaults moved from Bot settings to the Dashboard — the Dashboard's
"Overview" panel is now a navigable `List` (up/down selects a category,
Enter opens the same Allowed/Blocked popup Bot settings used to own) instead
of a read-only `Paragraph`. Bot settings, in turn, gained the bot-list
source list (sources first, bots after, in one combined row list — mirrors
how it used to combine categories and bots) and lost the category rows.
Confirming a source's "Update now" popup doesn't write to the database
directly the way every other popup in this app does: `Db`'s connection isn't
`Sync`, so the fetch (network IO) has to happen off the screen's
synchronous `handle_key`. The screen returns a new `KeyOutcome::UpdateSource(name)`
instead; `App` (which owns the `EventHandler`) spawns a `tokio` task that
does *only* `botlist::fetch` + `botlist::parse` and reports the result back
as a new `AppEvent::SourceUpdateFinished`, and `App` does the actual
`botlist::store` on the main thread once that event arrives. `Event`/
`AppEvent` need to stay `Clone` for this (the channel is `Clone`-bounded),
so the fetch error is stringified at the task boundary rather than kept as
an `anyhow::Error` (not `Clone`).

`tests/tui.rs`'s pty-driven assertions turned up a real rexpect/crossterm
gotcha worth recording: sending a bare Escape immediately followed by
another key (no intervening `exp_string` wait) risks crossterm's raw-mode
parser coalescing them into a single `Alt+<key>` event — which a screen's
popup branch then silently swallows (anything it doesn't recognize is just
`Consumed`), leaving the popup open and the rest of the test hanging. Every
Esc that isn't immediately followed by a synchronizing wait now goes through
a small `send_escape` helper that sleeps briefly first. The terminal output
being diffed against the previous frame caused a second, unrelated kind of
test flakiness: a character that happens to coincide with whatever was at
that exact cell in the previous frame never gets retransmitted, so a popup
title like "Scanners default" can arrive over the wire as "canners" +
(cursor jump) + "default" — tests anchor on substrings that avoid straddling
or starting on such a coincidence rather than the literal label text.

Each screen is a self-contained component (state + `render` + `handle_key`),
per AGENTS.md. The key-handling contract is a `KeyOutcome`: `Consumed` (state
changed, nothing else to do), `Mutated` (wrote to the database — `App`
reloads *every* screen before the next render, not just the one that
changed, since e.g. a Bot-settings change makes the Dashboard's summary
stale), `Back` (no popup open, bubble out to the Dashboard), or `Ignored`
(fall through to `App`'s global keys: quit, theme toggle, screen
switching). Escape/`q` are context-dependent: they close a popup first, then
back out of a screen, and only quit from the Dashboard — matching the
README's stated behavior, not the template's unconditional `Esc => quit`.

Theme is a plain `Dark`/`Light` enum, not the deleted implementation's full
per-theme RGB color palette (which also predates, and conflicts with, the
AGENTS.md guidance to prefer the terminal's default foreground/background
and named Stylize colors). Detection reads `COLORFGBG` (a real heuristic
several terminals/multiplexers set); like the README admits, there isn't
always enough information to get this right, hence the manual `c` toggle.

**Verification.** `ratatui::init()` requires a real TTY, which this sandbox
doesn't have — `cargo run -- tui` fails with "No such device or address",
same class of limitation as `nginx -t`/`nft` not being installed for the
earlier features. Unlike those, an actual pty was available here via
`tmux`, so the full interactive flow (screen switching, theme toggle, Help,
opening/confirming/canceling popups, quitting) was driven and visually
verified by hand first, not just unit-tested. That caught two real bugs
before calling this done: `centered_rect`'s `percent_y` parameter was fed a
row count instead of a percentage (the popup rendered at near-zero height,
off-screen — replaced with a fixed-size `centered_rect(width, height,
area)` instead of a percentage-based one), and `BotSettings` confirming a
popup wasn't propagated to the Dashboard (no screen but the one that
changed got reloaded — fixed by the `Mutated` outcome triggering an
app-wide refresh). That manual session is now an automated regression test
(`tests/tui.rs`, see below) so the same flow — and the same two bug classes
— gets checked on every run, not just once by hand.

## CLI (`src/main.rs`)

Running the binary with no subcommand launches the TUI (per README: "Simply
run the binary to launch the TUI"); `tui` is also available explicitly.
Other subcommands, matching names already agreed in REVIEW.md before the
rewrite:

- `scan-sites` / `scan` — discover NGINX sites, store them in the db.
- `update-bot-lists` / `update` — fetch (or `--source <file>` for a local
  copy) and store the bot list.
- `apply-blocks` — recompute the blocked user-agent patterns from the db and
  write/update/remove the sentinel block in every discovered site.
- `add-firewall-rule` / `list-firewall-rules` / `remove-firewall-rule` —
  manage the `firewall_rules` table.
- `render-firewall --backend <iptables|nftables> --out <path>` — write the
  generated script to `<path>`. Never executes it.
- `block-scanners --threshold <n> [--ttl-days <n>] [--ssh-log <path>] [--dry-run]`
  — find IPs with `>= n` failed-authentication log lines
  (`stop_bots::sshlog::scanning_ips`; default threshold 20) and add each as
  a temporary `firewall_rules` Block row, expiring after `--ttl-days`
  (default 5). See "SSH scan detection" below.
- `block-web-scanners --threshold <n> [--ttl-days <n>] [--access-log <path>] [--dry-run]`
  — find IPs with `>= n` distinct 404-returning paths in the NGINX access
  log (`stop_bots::accesslog::scanning_ips`; default threshold 7) and add
  each as a temporary `firewall_rules` Block row, expiring after
  `--ttl-days` (default 1). See "Web scan detection" below. Deliberately
  named separately from `block-scanners` (not
  `block-ssh-scanners`/`block-web-scanners` symmetry) since renaming the
  just-shipped `block-scanners` would break anyone who already wired it
  into cron.

`apply-blocks` re-discovers sites from disk on every run rather than reading
back `sites` from the db, so it can never act on a stale config path.

**Default `--db` resolution falls back to a per-user path.** Every
subcommand's `--db` is `Option<PathBuf>` (no `clap` `default_value`), not a
plain `PathBuf` defaulting to `/var/lib/stop-bots/db.sqlite3` — a real
default baked in at parse time would make it impossible to tell "user
explicitly chose the system path" apart from "user didn't pass `--db` at
all", which is exactly the distinction that matters here. `open_db` (in
`main.rs`) keeps that distinction: an explicit `--db` is opened as-is, even
if that fails — silently substituting a path the user asked for would be
worse than erroring loudly. With no `--db`, `open_or_fallback` tries to
create `/var/lib/stop-bots` and, only if creating *that directory*
specifically fails, falls back to a per-user XDG location
(`$XDG_DATA_HOME/stop-bots/db.sqlite3`, or `~/.local/share/stop-bots/db.sqlite3`),
printing an explicit note about which path ended up being used. `/var/lib`
needs root in practice, which applying nginx/firewall changes needs
anyway — but just running `cargo run` or the TUI to look around shouldn't.

The fallback trigger is deliberately narrow: only "can't create the
directory", not "opening/reading the database failed" in general. If
`/var/lib/stop-bots` already exists (e.g. a root-run systemd service
created it) but isn't readable by the current user, that's a real
permissions problem with *existing data* — falling back there would hand
back a fresh, empty database that looks indistinguishable from "no data
yet" instead of surfacing the actual problem. Only the specific case this
exists for (the directory doesn't exist and can't be created) gets the
silent fallback; everything else still fails loudly.

`open_or_fallback`'s fallback parameter is a closure (`impl FnOnce() ->
Result<PathBuf>`), not an already-resolved `PathBuf`: resolving it
(`user_db_path`, which needs `XDG_DATA_HOME` or `HOME`) only happens inside
the create-failed branch, never on the success path. Resolving it eagerly
was tried first and is wrong — it would mean a root-run container with a
minimal environment (`/var/lib` writable, no `HOME` set, a realistic way to
run a server-side bot blocker) fails outright even though the primary path
it actually needed never had a problem.

## End-to-end tests (`tests/cli.rs`, `tests/tui.rs`)

`tests/cli.rs` covers the non-interactive subcommands via `assert_cmd`
(spawn, check stdout/exit code). That doesn't work for the TUI:
`ratatui::init()` needs a real TTY, and `assert_cmd` doesn't allocate one —
running `tui` under it fails immediately the same way it does in this
sandbox (see the TUI section above).

`tests/tui.rs` instead drives the actual compiled binary through a real pty
using `rexpect` (`spawn_command` takes a `std::process::Command`, so it's
the same `CARGO_BIN_EXE_stop-bots` binary `assert_cmd` uses, just attached to
a pty instead of pipes): launch, switch screens, open/confirm a popup, check
the change is visible on a different screen, quit. `exp_string` blocks until
the awaited text actually appears (or times out), so there's no sleep-based
guessing about whether the app has redrawn yet.

**The one non-obvious thing this needed**: a freshly opened pty has no
window size set (the kernel defaults it to 0×0 since nothing has called
`TIOCSWINSZ` on it), which makes every ratatui widget render into a
zero-area `Rect` — output that's all cursor-positioning/color escape codes
and no visible text. `tests/tui.rs::set_window_size` sets it explicitly via
a raw `libc::ioctl(fd, TIOCSWINSZ, ...)` on the pty master fd, immediately
after spawning, before the child gets far enough to call its first
`terminal.draw()`. (`rexpect` doesn't expose a way to do this itself; `libc`
is a small, otherwise-unused dev-dependency added just for this one ioctl
call — alternatives considered: pulling in `nix` directly duplicates what
`rexpect` already pulls in transitively but doesn't re-export.)

Test key sequences are sent as raw bytes via `send()` + an explicit
`flush()` (not `send_line()`, which appends a `\n` — wrong for keys like
arrows/Escape that aren't line input): `\r` for Enter, `\x1b` for Escape,
`\x1b[A`/`\x1b[B` for Up/Down. Plain letters (`b`, `d`, `s`, `q`, `?`) are
sent as themselves.

**Terminal output is diffed, which matters for what `exp_string` can
actually prove.** ratatui/crossterm only retransmit cells whose
content/style changed since the last frame; once a label has been drawn, a
later same-screen update that only changes an adjacent value (e.g. a tag
flipping from Blocked to Allowed) never resends the label text. Two
consequences, both load-bearing for whether an assertion actually checks
anything:

- Anchoring a wait on a label (`expect_status_after`) only works right
  after switching *to* a screen — a genuinely fresh full redraw, where the
  label text really does come down the wire again. Using it to re-check a
  value on a screen that's already been sitting on screen would just hang
  (confirmed empirically — see below), since the label byte simply never
  reappears.
- A bare `exp_string("ALLOWED")`/`exp_string("[ ALLOWED ]")` is meaningless
  read in isolation: with Search Bots allowed by default, that text is
  *always* somewhere in the stream. Whether a specific assertion is
  actually checking the row under test (Scanners) rather than coincidentally
  matching Search Bots' tag depends on exactly what's already been consumed
  by earlier `exp_*` calls in the same test — which is precisely why the two
  assertions in `navigate_change_a_setting_and_quit` use different
  strategies (a bare `exp_string` right after the same-screen confirm, since
  by that point Search Bots' tag has already been consumed by the earlier
  `exp_string("Scanners default")` jump; an anchored
  `expect_status_after` right after switching to the Dashboard, a fresh
  redraw where it isn't).

This was checked, not just reasoned through: temporarily reverting the
`Mutated`-triggers-`refresh()` fix in `app.rs` and rerunning made
`navigate_change_a_setting_and_quit` fail (at the same-screen check, before
even reaching the Dashboard one — confirming the fix is also load-bearing
for `BotSettings`'s own row, not just the Dashboard), then restoring the fix
made it pass again. Byte-identical to the pre-revert version afterward.

## Bootstrapping a bot-list source before it's ever been fetched

`sources` only ever gained a row inside `botlist::store`, which only runs
after a *successful* fetch. That's fine for the CLI (`update-bot-lists` can
always reach for the network or `--source <file>` regardless of what's in
the db yet), but it left the TUI with no way to trigger a first fetch at
all: Bot settings' "Update now" popup only opens for a row already in
`self.sources`, and on a brand-new install `sources` is empty — an
unpopulated database renders an empty screen with nothing to select.

Fixed with `Db::register_source` (`INSERT OR IGNORE`, unlike
`upsert_source`'s `ON CONFLICT DO UPDATE`) and `botlist::register_source`,
called once from `App::new` on every TUI startup. It's a deliberate no-op
once a source has actually been fetched — using `upsert_source` here
instead would reset `last_fetched_at`/`bot_count` back to "never
updated"/`0` on every launch, silently discarding real fetch state. A fresh
database now shows the well-known-bots source as "never updated" and
selectable, same as any other source, rather than nothing at all.

## Bot settings redesign: sources + a searchable "Bot details" panel

The original combined source-then-bots single list (see the redesign note
above) stopped scaling once a source's bot count grew past a handful — the
whole point of a bot list is to carry hundreds of entries, and rendering
all of them into one scrollable list buries the sources at the top and
makes finding one specific bot a matter of scrolling, not searching.

Split into two independent panels, each with its own `ListState`:
**Bot list sources** (top, unchanged behavior — Enter opens the
Cancel/Update-now popup) and **Bot details** (bottom — a one-line search
box plus whatever currently matches it). The bot list itself is never
rendered in full: `BotSettings::filtered_bots` returns nothing until the
query is non-empty, on the theory that a search box that also doubles as a
"browse everything" list defeats its own purpose.

A `Focus` enum (`Sources` / `Search`) tracks which panel owns keyboard
input, since this is the first screen in the app with more than one
interactive region. `/` moves focus into the search box from anywhere in
Sources; from there, every printable key (including Space — bot names can
contain one, e.g. "Google Crawler") is query text rather than a shortcut,
Backspace edits it, Up/Down (not `j`/`k` — those need to be typable) move
the match selection, and Enter opens the selected match's override popup.
Escape is overloaded the same nested way popups already use it: first
press returns focus to Sources without touching the query (so re-pressing
`/` resumes the same search); a second Escape, now with Sources focused and
no popup open, backs out to the Dashboard as usual.

The empty-results hint in Bot details distinguishes two states that look
identical if conflated: "haven't typed a query yet" vs. "typed one that
matched nothing" vs. "there are no bots in the database at all yet" (the
last one pointing back at the sources panel above rather than implying the
search itself is broken).

Focus is indicated the same minimal way selection already is elsewhere in
this app: the focused panel's border is `theme.accent()`; the other one is
left at the terminal's default foreground, per AGENTS.md's TUI color
guidance rather than a second bespoke "dim but not too dim" color.

Covered by a new pty test (`tests/tui.rs::bot_details_search_filters_by_name_and_opens_a_bot_popup`)
that types into the live search box and confirms a match's popup opens —
worth noting for future tests that touch this box: the search term needs to
be a substring that isn't already on screen anywhere else in Bot settings,
since the terminal-output-diffing gotcha documented above applies just as
much to freshly-typed text as to state transitions.

## Naming `BotStatus::Default` "Use system settings" in the UI

`BotStatus::Default` (the Rust/db name, unchanged — it's still the string
`"default"` on disk, and `Db::set_bot_status`/`effective_policy` don't care
what it's called) was surfaced to the user only as the word "Default" in
the override popup, and not surfaced at all on the bot row itself — a row
only got a `(override)` tag once you picked something else, so "no tag"
was silently doing double duty for "this bot follows the system default"
with no visual cue that a system-wide policy was even in play.

Two changes, both purely presentational — no data model or `BotStatus`
variant change: the popup option reads "Use system settings" instead of
"Default" (`status_label`, also used for the post-confirm message, so
"gptbot set to use system settings" reads the same way rather than falling
back to `{status:?}`'s "Default"), and every bot row now always carries an
explicit `(system)` or `(override)` tag — never blank — next to its
effective `[ ALLOWED ]`/`[ BLOCKED ]` state. The goal was specifically
"make it clear when the bot-specific setting overrides the system setting
and when not", which an absence-of-a-tag can't do as legibly as two
always-present, differently-worded ones.

## Triggering a site scan from Site settings

Site settings was read-only: `scan-sites` was CLI-only, with no TUI path to
populate `sites` at all short of shelling out separately. Added an Enter
opens a Cancel/Scan-now confirmation popup, same shape as Bot settings'
source-update popup — but **synchronous**, not spawned: the async path in
`app.rs` exists specifically because bot-list fetching is network IO and
`Db` isn't `Sync`, neither of which applies to `nginx::discover_sites` (a
local filesystem walk). Doing it inline inside `handle_key` and returning
`KeyOutcome::Mutated` is simpler and correct here — no `AppEvent` variant,
no background task.

The confirmation popup renders even when `sites` is empty — that's the
actual bootstrap case it exists for (a fresh install has zero sites and no
other way to get the first one short of the CLI), so `render` no longer
early-returns before the popup check the way it used to before this popup
existed. Missed on the first pass, caught by a stronger reviewer before
implementing: an early `return` after the empty-state placeholder would
have made the popup silently never draw on exactly the state it's meant to
fix.

`nginx::discover_sites` takes a `root: &Path`, which the TUI didn't
previously have any notion of — `App::new` gained a `root: PathBuf`
parameter (passed down to `SiteSettings::new`), and `stop-bots tui` gained
a `--root` flag (`default_value = DEFAULT_NGINX_ROOT`, matching
`scan-sites`/`apply-blocks`). The no-subcommand default path (`None =>
run_tui(...)`) bypasses clap's own `default_value` resolution, so it has to
pass `PathBuf::from(DEFAULT_NGINX_ROOT)` explicitly rather than relying on
some parsed default trickling through — an easy thing to silently get wrong
since it'd still compile fine while behaving differently from `stop-bots
tui` with no flags.

A scan failure (Errors are theoretically possible since `discover_sites`
returns a `Result`) is caught inside `SiteSettings::scan` and turned into a
status message rather than propagated: `handle_key`'s `Result` bubbles all
the way up through `App::run`, so letting an `Err` through would tear down
the whole TUI over what should be a recoverable, reportable failure — same
philosophy as the async bot-source-update error handling, just synchronous
here instead of arriving via an `AppEvent`. In practice `discover_sites`
today never actually returns `Err` for a bad root (it silently skips
`WalkDir` errors, per its own doc comment) — the catch-and-report path is
there for `Db::upsert_site` failures and to not depend on that
implementation detail holding forever.

Covered by a new pty test
(`tests/tui.rs::site_settings_scan_now_discovers_sites_from_the_tui`) that
points `--root` at the same static `tests/fixtures/nginx` fixture
`tests/cli.rs` uses, drives the whole popup from an empty sites list, and
confirms a discovered site's name appears — exercising the exact bootstrap
path the empty-state fix above was for.

## Per-site category and bot overrides

Every site used to follow the exact same global blocking policy —
`apply-blocks` computed one pattern list and wrote it into every `server{}`
block on disk (TODO.md: "Per-site bot overrides ... needs a
`site_bot_overrides` table plus CLI/TUI support"). Added per-site category
overrides (Scanners/Search/AI) and per-site individual-bot overrides, TUI
only — no new CLI verbs, matching the existing gap for global
category/bot-status changes. Geo-blocking (also shown in the README's
per-site mock) stays explicitly deferred: this codebase has zero
IP-to-country infrastructure, and building that is a separate decision.

**Precedence cascade**, most to least specific:

1. A site's own per-bot override, if set — decisive.
2. A *global* per-bot override (`bot.status` Allowed/Blocked) — decisive,
   bypasses category logic entirely.
3. Otherwise, per category the bot belongs to: the site's category
   override if it has one, else the global category default. Blocked if
   *any* matching category resolves to Blocked.

This is a direct generalization of the cascade `bot_settings.rs` already
shipped (an explicit per-bot pin bypasses category checks, globally); it's
now applied at both the site and global level rather than inventing a
second rule for the site layer. The one asymmetry worth remembering: **a
site's category override can never reach through a *global* per-bot pin**
— only that site's own per-bot override (tier 1) can override a globally
pinned bot. Zero overrides anywhere is byte-identical to the pre-existing
global-only behavior (checked with an equivalence test). A design-review
pass also flagged the multi-category case (a bot with both `is_ai` and
`is_search_engine` set) as untested territory before this change — now
covered explicitly.

**Schema** (`site_category_overrides`, `site_bot_overrides`): both use
row-presence to encode "overridden" — no stored "inherit" value, the same
reason `NewBot` deliberately excludes `status`. `Db::compute_blocked_patterns`
is a new private helper extracted from the pre-existing
`blocked_user_agent_patterns`, so the global and per-site public functions
(`blocked_user_agent_patterns` / `blocked_user_agent_patterns_for_site`)
share one cascade body rather than two copies. Per-bot overrides are a
`Vec<SiteBotOverride>` searched linearly, not a `HashMap` — this codebase
uses `Vec<T>` from `list_*` everywhere and bot/site counts are in the
hundreds, so introducing a new collection type here wasn't worth it.

**The `apply_blocks` per-file scoping fix** (caught in design review, not
obvious at first): `sites` has `UNIQUE(server_name, config_path)` — the
*same* `server_name` can legitimately appear in two different files (a
stale config left behind after a rename; nothing prunes this table). A
naive implementation would build one flat name→patterns map for the whole
`apply-blocks` run and reuse it across every file, letting one site's
override leak onto another same-named site's block in a different file.
Fixed by building `site_patterns` freshly *inside* the per-file loop,
filtered to `db.list_sites()` rows whose `config_path` matches that
specific file. Regression-tested in `tests/cli.rs` with two files sharing
one `server_name`, one overridden — the other must be untouched.
`nginx::apply_blocks_to_file` itself gained a `site_patterns: &[(String,
Vec<String>)]` parameter (linear-scanned by `block.names.first()`) plus a
`default_patterns` fallback for a block whose name isn't a known site yet;
two blocks sharing one `server_name` (the pre-existing redirect+HTTPS
regression test) still resolve to the same entry, so that invariant holds.
Note the disk↔db join is a textual `config_path` match, only valid when
`apply-blocks` runs with the same `--root` used at scan time — a mismatch
degrades safely to `default_patterns`, not an error.

**TUI**: a new `src/tui/site_detail.rs` (`SiteDetail`), opened from Site
settings via `Enter` on a site row. Deliberately mirrors `bot_settings.rs`'s
shape closely — a `Focus` enum, a search box that shows nothing until
something is typed, a 3-way popup — rather than sharing code with it: this
codebase already tolerates this level of duplication across screens (e.g.
`render_popup` is independently reimplemented near-identically in
`dashboard.rs`, `bot_settings.rs`, and `site_settings.rs`), and a shared
search/popup abstraction would be the kind of premature genericization
AGENTS.md/CLAUDE.md warn against. Two differences from Bot settings'
version: the popups are 3-way, not 2-way ("Use system default"/"Allowed"/
"Blocked" for categories, "Use site & system default"/.../... for bots),
since "no override" is a real third state here; and bot rows carry a
3-state tag (`(site override)` / `(global override)` / `(default)`)
instead of Bot settings' 2-state one, reflecting which cascade tier is
actually driving that bot's effective policy on this site.

`SiteSettings` owns `detail: Option<SiteDetail>` and delegates to it first
in both `render` and `handle_key`; a `Back` from the detail view is
intercepted and turned into `self.detail = None` + `Consumed` rather than
propagated (which would exit all the way to the Dashboard) — the same
nested-back-out shape `bot_settings.rs`'s own `Focus::Search` already uses
for its Escape handling, one level deeper here. `SiteSettings::refresh`
also refreshes an open `detail`, so a write inside it doesn't leave a stale
tag on screen until you back out and back in.

**An intentional key rebind**: Site settings used to trigger its scan
popup with Enter (previous session). Since Enter now needs a per-row
meaning (open that site's detail), the scan trigger moved to a dedicated
`r`, avoiding one key meaning two different things depending on whether the
list happened to be empty. The empty-state placeholder text changed
accordingly ("Press r to scan..." instead of "Press Enter to scan...").

Covered by a new pty test
(`tests/tui.rs::site_detail_search_and_override_a_site_from_the_tui`) that
overrides a category, searches for and overrides an individual bot, backs
all the way out, quits, then reopens the resulting db file directly
(`stop_bots::db::Db::open`) to confirm both writes actually landed — not
just that the right text was rendered. Hit the same terminal-output-diffing
gotcha documented above while writing it: a tag reading `(site override)`
right after previously reading `(system)` only retransmitted its differing
tail (`ite override)`), since both strings share a `(s` prefix at the same
screen position — anchored on `override)` instead to sidestep it.

## Per-site apply status and a per-site "Apply now" action

Previously the only way to get any computed rule (global or per-site) onto
disk was `stop-bots apply-blocks`, run out-of-band from the TUI, with no
feedback in Site settings about whether a given site's file was actually
up to date. Two additions close that gap, both in `src/nginx.rs`:

- `site_apply_status(config_path, server_name, patterns) -> SiteApplyStatus`
  (`UpToDate` / `Stale` / `NotFound`) — a read-only check, re-reads the file
  and compares what's actually written in the matching block(s)' sentinel
  rule against `patterns` (the currently-computed rule), rather than
  caching a flag anywhere. `NotFound` covers both an unreadable file and a
  file that no longer has a `server_name` matching what was recorded at
  scan time (renamed/removed on disk since). A bot list update, a category
  default change, or hand-editing the file are therefore all reflected
  immediately on the next `refresh`, with no separate invalidation to keep
  in sync. The readback (`current_block_pattern`) is anchored to the
  sentinel's own line range via the existing `locate_existing_block`, not
  just the first `~* "..."` found anywhere in the block — an admin's own
  hand-written `if ($http_user_agent ~* "...")` condition elsewhere in the
  same `server { ... }`, ahead of the sentinel, would otherwise be
  misread as our applied pattern and make an already-correct site read
  permanently `Stale`. Regression-tested with exactly that fixture shape.
- `apply_block_for_site(config_path, server_name, patterns) -> Result<bool>`
  — deliberately *not* built on top of `apply_blocks_to_file`. That
  function resets every block it has no explicit `site_patterns` entry for
  back to `default_patterns`, which is correct for a whole-tree
  `apply-blocks` run but wrong for "apply just this one site": two sites
  can share a config file, and touching the file must not silently rewrite
  the other site's block. `apply_block_for_site` walks every block in the
  file (same re-parse-before-each-edit approach as `apply_blocks_to_file`,
  for the same reason — edits shift byte offsets of blocks after them) but
  only edits ones whose `server_name` matches; every other block is left
  byte-for-byte untouched.

**TUI**: `SiteSettings` gained a `statuses: Vec<SiteApplyStatus>` parallel
to `sites`, recomputed in full on every `refresh` (one `site_apply_status`
call per site — a local file re-read, not network IO, so no need to keep
it off the main thread, same reasoning as the site scan itself). Each row
renders its tag via a `status_tag` helper mirroring `site_detail.rs`'s
`policy_tag`. A new `a` key opens a Cancel/Apply-now popup (same shape as
`r`'s scan popup) that calls `apply_block_for_site` for just the selected
site, using that site's own `db`-recorded `config_path` and
`blocked_user_agent_patterns_for_site` — notably, this path never depends
on `--root` at all, so it isn't subject to the `apply-blocks`
CLI's textual `config_path`-vs-`--root` mismatch caveat noted above.
`Popup` gained an `action: PopupAction` field (`Scan` or `Apply(usize)`,
the site's index) so the two confirmation flows can share one popup type
and `render_popup` picks the right title from it. Confirming either action
returns `KeyOutcome::Mutated` — technically a stretch of its doc comment
("a screen wrote to the database"), since applying only touches the nginx
file, but it's the existing, simplest way to get `App::refresh` to re-run
`SiteSettings::refresh` and pick up the file's new on-disk state in the
status tag.

**A failed apply needs its own popup, not `App`'s shared `message`**: a
real-world test of this (applying against `/etc/nginx` without root)
surfaced a pre-existing gap — `tui.rs`'s render dispatch only ever passes
`app.message` into `Dashboard::render`; `BotSettings`/`SiteSettings` never
render it at all. A failure reported through `*message` from Site settings
was therefore completely invisible unless the user happened to switch to
the Dashboard tab, which looked indistinguishable from "nothing happened,
still STALE". `SiteSettings` now has its own `alert: Option<String>`,
rendered as a dismissible bordered popup (Enter/Esc/Space to close, and
while it's open it swallows every other key — same "block input until
dismissed" shape as the existing confirm popups, just with no options to
select) set directly by `apply_site` on failure, independent of
`*message`. It also special-cases a permission-denied write — by far the
most likely real cause, since `/etc/nginx` is normally root-owned — with
an extra "Try running as root" line, detected via `err.chain().any(...)`
downcasting each cause to `std::io::Error` and checking
`ErrorKind::PermissionDenied` (`anyhow`'s `.with_context()` wraps the
original `io::Error` as the new error's `source()`, reachable through
`.chain()`, not just the outer message). Covered by both a unit test that
chmods a file read-only (skipped under `geteuid() == 0`, since root
ignores permission bits) and a pty test doing the same against a real
`stop-bots tui` process. This is scoped to the apply flow only — the
identical invisibility gap in `scan`'s own error path, and in
`BotSettings`'/`Dashboard`'s messages generally when not on the Dashboard
tab, is a wider pre-existing issue this pass doesn't attempt to fix.

**`A` applies every known site in one go**: `apply_all` just loops
`run_apply_site` over every index in `self.sites` — the same per-site
`nginx::apply_block_for_site` call `a` already used, not a new bulk-write
code path. A site's failure doesn't stop the rest from being tried; all
failures collected during the loop are joined into one alert afterwards
(one line per failed site), with the same "Try running as root" suggestion
if *any* failure in the batch was permission-denied — reasonable since a
single process either has root or doesn't, so one such failure usually
means the rest will fail the same way. The success message reports
counts (`"Applied blocking rules to N site(s), M already up to date, K
failed"`) rather than one message per site, since a batch could cover many
sites at once. `PopupAction` gained a third variant, `ApplyAll` (no
site index — it always covers every currently-known site), sharing the
existing `Popup`/`render_popup` machinery.

**Bot settings' sources list spells out its own key binding**: the panel
title changed from "Bot list sources" to "Bot list sources — Enter to
update", mirroring the hint style Site settings' own title already uses
("Sites — Enter for overrides, r to rescan, a to apply, A for all").
Previously this relied entirely on the generic "Enter, Space open a
setting" line in the Help screen, which doesn't make it obvious from the
sources list itself that Enter is the way to trigger an update.

**Known limitations, not addressed by this pass**: `SiteDetail` (the
per-site override editor) has no apply/status of its own — after editing
a site's overrides there, back out to the list (`Esc`) and press `a` there
to apply. And `block_text`'s pattern interpolation was already unescaped
before this change (a literal `"` inside a bot's user-agent pattern, e.g.
the `Evil"Bot` fixture, breaks the written nginx string) — a pre-existing
issue, not something this feature's status check can paper over, since a
malformed on-disk rule can't be read back as "matching" anything sensible.

## Bot-list sources: `SourceKind` and three sources

`src/botlist.rs` was a single flat file hardcoded to one source
(well-known-bots): its own `SOURCE_ID`/`SOURCE_NAME`/`SOURCE_URL`
constants, and `fetch`/`parse`/`store`/`update`/`register_source`
functions that only ever knew how to talk to that one JSON schema. Adding
two more real-world sources — [ai.robots.txt] and
[nginx-ultimate-bad-bot-blocker] — meant genericizing the whole pipeline,
since their upstream formats are both completely different from
well-known-bots' and from each other:

| Source | Format | Pattern comes from | Categories set |
|---|---|---|---|
| `well_known_bots` | JSON array, each entry has `pattern.accepted: [String]` | An explicit field, possibly multiple patterns joined with `\|` | `is_ai`/`is_search_engine` from `categories` |
| `ai_robots_txt` | JSON object keyed by bot name, e.g. `{"GPTBot": {...}}` | The object *key itself* — there's no separate pattern field at all; upstream's own generated `nginx-block-ai-bots.conf` matches bot names directly | Always `is_ai` — that's this source's entire scope |
| `nginx_bad_bots` | Plain text, one already-regex-escaped token per line (e.g. `1h4x\.com`, `ALittle\ Client`) | The line itself, verbatim | Always `is_scanner` — the first source that actually populates it (see TODO.md) |

[ai.robots.txt]: https://github.com/ai-robots-txt/ai.robots.txt
[nginx-ultimate-bad-bot-blocker]: https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker

**Module layout**: `src/botlist.rs` became `src/botlist/mod.rs` plus three
sibling modules (`well_known_bots.rs`, `ai_robots_txt.rs`,
`nginx_bad_bots.rs`), each owning its own `SOURCE_ID`/`SOURCE_NAME`/
`SOURCE_URL`/`parse`/`fetch` — `well_known_bots.rs` is the original file's
content moved as-is. `botlist::SourceKind` (`WellKnownBots`/`AiRobotsTxt`/
`NginxBadBots`) is the single place that knows all three exist, dispatching
`id()`/`name()`/`url()`/`parse()`/`fetch()` to the right module; adding a
fourth source means adding one variant here plus one new sibling module,
nothing else. `register_all_sources`/`store`/`update` are now generic over
`SourceKind`, replacing the old hardcoded versions of the same names.

**Two normalization problems specific to the new sources**, both solved by
a shared `botlist::slugify(name: &str) -> String` (lowercases, collapses
runs of non-alphanumeric characters to one hyphen): well-known-bots has a
ready-made kebab-case `id` field to use as `slug` directly, but neither new
source does — ai.robots.txt's keys are things like `"ChatGPT Agent"` and
`"Claude-Code"`, and nginx_bad_bots' lines are backslash-escaped for regex
use (`"1h4x\.com"`). `nginx_bad_bots::parse` therefore keeps two different
strings per entry: `user_agent_pattern` stays exactly as-written (still
escaped — it's fed straight into NGINX's own regex, same shape
`Db::blocked_user_agent_patterns` already produces by joining with `\|`),
while `name`/`slug` run through a small `unescape` helper first, so the
Bot settings search box shows `"1h4x.com"`, not `"1h4x\.com"`.

**Cross-source overlap is real, measured against live data**: fetching all
three real sources and comparing slug sets directly (not just observing
the db after the fact, which can't distinguish "no collision" from
"collided and already resolved") found genuine overlap — well-known-bots
vs ai-robots-txt: 3 names (e.g. `Perplexity-User`/`perplexity-user`);
well-known-bots vs nginx-bad-bots: 10 (e.g. `HTTrack`/`httrack`); ai-robots-txt
vs nginx-bad-bots: 21, including well-known names like `GPTBot`,
`anthropic-ai`, `CCBot`, `ChatGPT-User` — names ai.robots.txt tags `is_ai`
and nginx-bad-bots simultaneously tags `is_scanner`. There's also small
**internal** collision within a single source's own list (well-known-bots:
0; ai-robots-txt: ~159 keys -> ~156 unique slugs, genuine upstream
near-duplicates like `Meta-ExternalAgent`/`meta-externalagent`;
nginx-bad-bots: ~696 lines -> ~689 unique).

## Bot-list sources: merging overlapping bots

Originally, `bots.slug` was globally `UNIQUE` and `upsert_bot` keyed only
on it — a straight `ON CONFLICT(slug) DO UPDATE` that overwrote
`is_ai`/`is_search_engine`/`is_scanner`/`user_agent_pattern`/`source_id`
wholesale on every upsert (never `status`, so a manual override always
survived). That's fine with one source, but with the ~34 real overlapping
names above, it meant whichever source was fetched *last* won outright —
e.g. fetching ai-robots-txt then nginx-bad-bots left `GPTBot` tagged
`is_scanner` only, having silently lost `is_ai`; fetching in the other
order lost `is_scanner` instead. Both are wrong: the point of having
multiple sources is that a bot flagged by two of them should end up
carrying *both* flags.

**Fix**: a new table, `bot_source_entries`, keyed by `(slug, source_id)`
rather than `bots.id` (a slug's `bots` row may not exist yet the first
time a source contributes it) records each source's own raw, un-merged
contribution — its own `name`/`is_ai`/`is_search_engine`/`is_scanner`/
`user_agent_pattern` for that slug. A `bots` row is now a *derived* view:
`Db::recompute_merged_bot(slug)` reads every `bot_source_entries` row for
that slug and computes `is_ai`/`is_search_engine`/`is_scanner` as the
logical OR across all of them, `user_agent_pattern` as every *distinct*
contributed pattern joined with `|` (the same "multiple accepted
patterns" shape a single source's own list can already produce, e.g.
well-known-bots' `pattern.accepted`), and `name` as the longest
contributed name (ties broken by whichever sorts later alphabetically) —
picked for usually being the most descriptive/properly-cased variant, and
deterministic regardless of fetch order. `source_id` on the merged row is
now purely informational (see `Bot`'s own doc comment) — nothing reads it
for logic anymore, it's kept only because dropping the column would need
a schema migration this project has never had before.

`Db::upsert_bot` now writes to `bot_source_entries` first (`ON
CONFLICT(slug, source_id) DO UPDATE`, so a source re-contributing the same
bot just refreshes its own entry) and then calls
`recompute_merged_bot(&bot.slug)`. `botlist::store` calls a new
`Db::clear_source_bot_entries(source_id)` *before* re-upserting a source's
current list — deleting all of that source's previous entries and
returning which slugs they were — so a bot the source no longer reports
stops being attributed to it, rather than its old contribution lingering
forever. Any of those previously-contributed slugs *not* present in the
new batch (i.e. `upsert_bot` won't touch them this round) get an explicit
`recompute_merged_bot` call too, so they either fall back correctly to
another source's still-current contribution, or (documented, deliberate
simplification) are left exactly as they last were if this was their only
contributing source — `recompute_merged_bot` is a no-op when a slug has
zero remaining entries, rather than zeroing out or deleting the `bots`
row, so a manual `status` override or a site override pointing at that
bot's id doesn't silently go stale. `store` also now sets
`sources.bot_count` from `Db::count_bot_source_entries(source_id)` (the
accurate, post-merge count) instead of the raw pre-dedup `bots.len()`,
fixing the count-drift this same overlap caused.

**Verified against live data, both fetch orders**: storing ai-robots-txt
then nginx-bad-bots, and the reverse, on a fresh db each time — `GPTBot`,
`anthropic-ai`, `CCBot`, `ChatGPT-User` end up with **both** `is_ai=1` and
`is_scanner=1` regardless of which order they were fetched in. Also
checked: re-fetching a source a second time doesn't double-count or
duplicate anything (`bot_source_entries`' composite primary key makes
that an update, not an insert). Covered by a new regression test in
`botlist/mod.rs`, `storing_two_overlapping_sources_merges_rather_than_clobbers`,
using real fixture data with a deliberately shared name (`GPTBot`, added
to the `nginx-bad-bots` sample fixture specifically to exercise this),
plus a set of lower-level `db.rs` tests exercising the merge/fallback/
no-op-on-zero-entries cases directly against `bot_source_entries`.

**Not done**: no CLI/TUI surface for seeing *which* sources contribute to
a given bot's merged flags (e.g. "is_ai because ai-robots-txt, is_scanner
because nginx-bad-bots") — `bot_source_entries` has that data, nothing
displays it yet.

**CLI**: `update-bot-lists` gained a `--source-id` flag (`well-known-bots`,
`ai-robots-txt`, or `nginx-bad-bots`; defaults to `well-known-bots` for
backward compatibility), resolved via `SourceKind::from_id`. `--source
<path>` (read a local file instead of downloading) is now parsed using
whichever format `--source-id` selects, rather than always assuming
well-known-bots' JSON shape.

**TUI**: `App::new` now calls `botlist::register_all_sources`, so Bot
settings shows all three rows (sorted by id — `"ai-robots-txt"` sorts
first, alphabetically ahead of the seeded well-known-bots row, which
matters for pty tests asserting on default row selection) even before any
of them has ever been fetched. The bigger change is what
`KeyOutcome::UpdateSource` and `AppEvent::SourceUpdateFinished` carry: both
used to carry the source's *display name* (`"ArcJet Well-Known Bots"`),
which was fine when there was only one possible fetcher to call regardless
of which row was confirmed. With three different fetch/parse
implementations to choose between, `App::start_source_update` needs to
resolve a `SourceKind` from whatever gets confirmed — so both now carry
the stable **id** (`"well-known-bots"`) instead, resolved via
`SourceKind::from_id` on the receiving end; `bot_settings.rs`'s
`PopupTarget::Source` changed the same way, looking the display name back
up from `self.sources` only when rendering the popup's title.

## Crawler and country IP ranges (`src/ipranges/`, `Db::derived_firewall_entries`)

Extends the firewall layer (see "Firewall integration" above, which
predates this and describes it as plain admin-managed with "no bot-list
source provides IP ranges yet") with two real IP-data sources, both feeding
`firewall_rules`/iptables/nftables rather than NGINX:

**Published crawler CIDR lists.** Google, Bing and OpenAI (GPTBot) each
publish a stable JSON URL with the *identical* shape —
`{"creationTime": ..., "prefixes": [{"ipv4Prefix": "x.x.x.x/y"} |
{"ipv6Prefix": "..."}]}` — verified live against all three
(`developers.google.com/search/apis/ipranges/googlebot.json`,
`bing.com/toolbox/bingbot.json`, `openai.com/gptbot.json`). Because the
shape is identical, `IpRangeSourceKind` (in `src/ipranges/mod.rs`) shares one
parser across all three, unlike `botlist::SourceKind`'s three different
per-source modules. Anthropic doesn't publish a range file (recommends
reverse-DNS instead), so there's no fourth source here.

**Why these don't map onto `bots`/`bot_source_entries` at all.** A
publisher's IP list covers *all* of its crawling activity, not one UA
variant — Google alone splits into a dozen distinct well-known-bots slugs
(`google-crawler`, `google-crawler-mobile`, `google-adsbot`, ...) with no
single row an IP list could attach to. Rather than inventing a fake
mapping, `IpRangeSource` (a new, separate `ip_range_sources`/`ip_ranges`
table pair in `db.rs`) is keyed to a `Category` instead:
`Db::blocked_ip_ranges` includes a source's CIDRs only if that category's
*global* default currently resolves to Blocked. Google and Bing are tagged
`Category::Search` (Allowed by default — these two sources are genuinely
inert until Search is blocked, which is correct, not a bug: their real
value would be *allow-listing* real crawler IPs while blocking spoofed
UAs, a feature this pass doesn't build). GPTBot is tagged `Category::Ai`
(Blocked by default), so it's live immediately. This is deliberately
coarser than `blocked_user_agent_patterns`'s cascade — no per-bot or
per-site override layer — because there's no per-bot row to layer one on
top of for a multi-slug publisher, and adding one just for GPTBot (the one
source that *does* have a matching bot row) would be an asymmetric special
case for a single source, not a real generalization.

**IPdeny country CIDRs, fetched on demand.** `ipranges::fetch_country`
pulls the *aggregated* variant of IPdeny's per-country zone file
(`ipdeny.com/ipblocks/data/aggregated/<cc>-aggregated.zone`) — plain
CIDR-per-line, no header, no API key. One country at a time, never all
~250 at once: verified live that even the aggregated form is large
(`nl-aggregated.zone` ≈ 5,700 lines, `us-aggregated.zone` ≈ 29,000 —
several times more in the unaggregated form, which is why aggregated is
used unconditionally). Fetched ranges land in `country_ip_ranges`; a
separate `blocked_countries` table (row presence = blocked, same
convention as `site_category_overrides`) marks which fetched countries are
actually enforced. Blocking a country before ever fetching its ranges is a
deliberate, harmless no-op (see `Db::blocked_country_ranges`'s doc
comment) rather than an error — the two steps are independent by design
(`update-country-ranges` vs. `block-country`), same "fetching updates data,
a separate step decides what's enforced" split `botlist`/`apply-blocks`
already has for UA patterns.

**Host-wide, not per-site — a scope change from the original plan.**
TODO.md previously said geo-blocking's deferred design would be a per-site
country allow/block list once a data source was chosen. That plan assumed
storing just country *codes*, cheap enough to duplicate per site. Once real
CIDR data was in scope, the per-country scale above (tens of thousands of
entries for large countries) made per-site enforcement impractical: NGINX
has no problem with a large `deny` list per se, but duplicating one across
every site's config, or building a shared-include-file mechanism just to
avoid that duplication, is real added complexity for a distinction (does
this specific site need a different blocked-country set than every other
site on the box) that's a much rarer real-world need than per-site
bot/category overrides already are. Host-wide reuses the exact same
firewall pipeline crawler IP ranges use, with zero NGINX changes:
`Db::derived_block_addresses` unions `blocked_ip_ranges()` and
`blocked_country_ranges()`, and `main.rs::render_firewall` builds synthetic
`FirewallRule { id: 0, action: Block, enabled: true, .. }` values from it,
appended to (never persisted alongside) `db.list_firewall_rules()` before
handing everything to `iptables::render`/`nftables::render`.

*If per-site geo is revisited later*, two sharp edges this design sidesteps
are worth knowing about going in: (1) NGINX's `allow`/`deny` directives
accept CIDRs directly with no GeoIP module needed, so the mechanism itself
is cheap — the expensive part is exactly the duplication/include-file
problem above; and (2) a per-site status tag analogous to
`SiteApplyStatus` would need real thought once large shared CIDR lists are
involved — re-fetching a country would rewrite a shared include file's
contents without touching any site's own config text, so a naive
in-block-text diff (which is exactly how `site_apply_status` works for UA
patterns today) would report "up to date" while the enforced ranges
silently changed underneath it.

**Not done, deliberately, for this pass:** no TUI surface at all (CLI-only:
`update-ip-ranges --source-id <id>`, `update-country-ranges --country
<cc>`, `block-country`/`unblock-country --country <cc>`,
`list-blocked-countries`) — matches the pre-existing gap that firewall
rules in general have no TUI screen yet. No per-bot or per-site cascade for
crawler IP ranges (see above). No allow-listing use of the verified
crawler IPs (only ever used to add Block rules when a category is
blocked). No validation of country codes beyond a 2-letter-alpha shape
check — an unknown code just 404s at fetch time with IPdeny's own error
surfaced via `.error_for_status()`, there's no embedded list of valid ISO
codes to validate against up front.

## SSH lockout safety net (`src/sshlog.rs`, `main.rs::render_firewall`)

Host-wide country blocking (see above) raised an obvious risk the crawler
IP-range work didn't: a country block emits an unconditional DROP for every
inbound packet from that country's ranges, including SSH — block the
country you (or the box's only remote admin) actually connect through, and
`render-firewall`'s generated script locks you out the moment it's applied.
The generate-only design (nothing here ever shells out to `iptables`/`nft`
itself) is the existing safety margin, but it only helps if the admin
actually re-reads the script before running it — which a decent-sized
country's CIDR list makes easy to skim past.

**The check.** Before writing anything, `render_firewall` reads whichever
common Linux SSH log source is actually available —
`sshlog::find_default_source` tries `/var/log/auth.log`, then
`/var/log/secure`, then falls back to `journalctl -u sshd`/`-u ssh` (RHEL
vs. Debian systemd unit naming) for a systemd-only host with no log file
at all — and extracts every IP with a recent *successful* login
(`sshlog::parse_accepted_ips`, matching sshd's own `Accepted <method> for
<user> from <ip> port <port>` message, identical whether it arrives via
classic syslog or `journalctl -o cat`). Each of those IPs is checked
against every address about to be blocked — admin `firewall_rules` *and*
the derived crawler/country ranges, via a small dependency-free
`ipranges::cidr_contains` (handles IPv4 and IPv6, treats a malformed CIDR
or a family mismatch as simply "no match", since this check only ever adds
a warning, never a hard failure over unrelated data). Read-only throughout:
this module never writes to, rotates, or truncates any log.

**Why parsing is keyed on the literal `"Accepted "` prefix, not just
`" from "`.** sshd logs failed attempts and disconnects with their own
`from <ip>` text too (`Failed password for ... from ...`, `Received
disconnect from ...`) — those must never count as a currently-reachable
session. Requiring `"Accepted "` to appear first excludes both.

**Warn twice, refuse; `--force` warns once, proceeds.** If any connected
IP would be blocked, the warning (which IP, which CIDR) prints twice and
`render_firewall` returns an error without writing the script — a
literal reading of the ask ("warn the user 2 times before applying"), and
a deliberately loud one given the stakes. `--force` still prints the
warning once (so the risk is never *silently* bypassed) but proceeds.  A
log source that couldn't be found or read at all (missing file,
permission denied — these logs are typically root/`adm`-group-only, or no
`journalctl` binary) is not treated as a risk in itself; it just means the
check didn't run, noted on stderr, and rendering proceeds normally — a
missing safety net isn't a reason to block firewall generation the user
explicitly asked for.

**`--ssh-log <path>`** bypasses auto-detection entirely, reading that file
instead. Built for two real needs at once: non-standard log locations
(containers, unusual distros) and deterministic testing —
`tests/cli.rs`'s lockout tests write a fixture log and point `--ssh-log` at
it, rather than depending on whatever happens to be in the real system
logs on whichever machine runs the suite (which, during development,
turned out to have real, readable `Accepted` entries — harmless here since
none of those IPs happen to fall inside the fixture-only test data, but a
reminder that this check is live against real data by default, not just a
test fixture concept).

**Not done, deliberately:** no check at the actual apply step — this tool
never runs `sh`/`nft -f` itself (see "Firewall integration" above), so
there's no second checkpoint to warn at even if one were wanted; the
`render-firewall` check is the one point this codebase actually controls
before a script reaches disk. No log-rotation handling (`auth.log.1`,
`.gz`, ...) — only the live log/journal is read, on the theory that a
session active within the current rotation window is what "would this
lock me out right now" actually needs.

## SSH scan detection (`src/sshlog.rs::scanning_ips`, `main.rs::block_scanners`)

`block-scanners` is the offensive counterpart to the lockout safety net
above: instead of protecting a currently-connected admin from a bad
firewall render, it turns the same SSH log into new Block rules for IPs
that look like automated scanners/brute-force bots.

**Detection is a threshold over log *lines*, not a rate over time.**
`sshlog::scanning_ips(log_text, threshold)` counts every failed-auth line
per IP (`parse_failed_attempt_ips`: sshd's `Failed
password/publickey/keyboard-interactive/none for [invalid user] <user> from
<ip> port <port>` and the standalone `Invalid user <user> from <ip> port
<port>` logged before any auth method is tried) and flags any IP at or
above `threshold`. There is deliberately no timestamp parsing — log formats
vary too much across syslog/journalctl to parse reliably — so the count is
over however much of the log the caller happened to read (a day, a month,
a whole boot's worth of `journalctl`), not a real rate. The default
threshold (20) is set high specifically because of this: a real scanner
produces dozens to thousands of failed attempts, while a human who
mistyped a password a couple of times should never come close.

**Two hard exclusions, independent of the threshold.** An IP with a
successful login anywhere in the same log (`parse_accepted_ips`) is never
flagged, no matter how many failures preceded it — this is the same
"proven itself a legitimate, currently-reachable client" reasoning the
lockout check uses, and both sides of the comparison go through
`IpAddr::to_string()` so an IPv6 formatting mismatch can't quietly defeat
it. Loopback and private addresses (RFC1918, IPv6 `fc00::/7`, `is_loopback`
on both families) are excluded outright — a monitoring box or jump host on
the same LAN hammering SSH is not an internet scanner.

**Only ever inserts into `firewall_rules`; never renders or applies
anything.** `block_scanners` calls `Db::add_firewall_rule` for each newly
found IP (`FirewallAction::Block`, no port), skipping any address that
already has a rule (exact-address match only — not CIDR-aware, so a
scanner already covered by a broader admin-added range still gets its own
row; harmless, just redundant). Like every other `firewall_rules` row, an
added rule has no effect on the actual host until `render-firewall` renders
it and the admin applies the script themselves — this is what makes it
reasonable to suggest running `block-scanners` unattended (e.g. from cron)
without the immediate-lockout risk a live `iptables`/`nft` write would
carry. `--dry-run` prints what would be added without touching the
database, for a preview before wiring up automation.

**Expiry (`--ttl-days`, default 5).** Auto-added rules aren't permanent:
`Db::add_firewall_rule_with_ttl` stamps `firewall_rules.expires_at` (Unix
seconds) instead of leaving it `NULL` the way a hand-added
`add-firewall-rule` row does, and `Db::list_firewall_rules` — read by
*every* consumer (rendering, `list-firewall-rules`, the scanner commands'
own dedup check) — deletes any row whose `expires_at` has passed before
returning anything. This is what makes an auto-block temporary rather than
a growing, never-reviewed pile: a scanner that's moved on stops being
blocked after `--ttl-days`, and one that's still scanning simply gets
re-flagged and re-added on the next run. Pruning-on-list, not a separate
sweep job, is also what keeps re-blocking clean: without it, an
already-expired-but-undeleted row would make the dedup check think a
still-scanning IP was "already covered" forever (never re-added) instead
of correctly treating a lapsed block as gone. **The expiry only takes
effect in the database** — same as everything else in this table, the
actual host-level block only lifts once `render-firewall` runs again
(picking up the now-shorter rule list) and the admin applies the new
script; if you automate `block-scanners`, automate `render-firewall`
alongside it, or blocks will outlive their TTL in practice even though
they've already expired in the data. `list-firewall-rules` shows
`(expires in Nd)`/`(expires in Nh)` next to a temporary rule so it reads
differently from a permanent one at a glance. The TTL of an existing,
not-yet-expired block is never extended by a later detection run that
still finds the IP scanning — it just expires on its original schedule and
gets a fresh one if it's re-flagged after that.

**Known limitations, left deliberately unaddressed:** no CIDR-range
grouping (each scanning IP gets its own `/32` rule, even if several came
from the same subnet). Some older sshd log shapes (`Connection closed by
invalid user ... [preauth]`, disconnect notices without a `port` token)
aren't counted — undercounts rather than overcounts, and the companion
`Failed password`/`Invalid user` line for the same connection attempt is
normally already counted, so this rarely loses an IP entirely. No
interactive TUI affordance (no popup to run this on demand or tweak its
threshold/TTL from the Dashboard) — but it does now run automatically on a
timer while the TUI or web UI is open, and its state is shown in both;
see "Internal cron" below.

## Web scan detection (`src/accesslog.rs::scanning_ips`, `main.rs::block_web_scanners`)

The HTTP-layer counterpart to SSH scan detection above: `block-web-scanners`
reads the NGINX access log and adds Block rules for IPs that look like
automated URL/vulnerability scanners — clients probing for paths like
`/wp-login.php`, `/.env`, `/phpmyadmin` that don't exist on this site.
Structurally it's the same shape as `block-scanners` (find scanning IPs,
add Block rules, skip addresses already covered, storage-only), but two
of its detection decisions deliberately diverge from the SSH version, and
both are load-bearing enough to call out explicitly.

**Counts *distinct* 404 paths per IP, not raw hit count.** A real client
that keeps retrying the same dead link (a stale bookmark, a broken image
reference elsewhere on the site) must never look like a scanner no matter
how many times it retries — so `accesslog::scanning_ips` puts each IP's
404'd request paths into a `HashSet` and thresholds on its size, not on
the number of 404 lines. A scanner probing dozens of different
well-known vulnerable paths is the actual signature being caught, and
that's inherently about path *diversity*, unlike SSH's brute-force case
where every failed attempt (even against the same username) is itself
already suspicious. The query string is stripped before counting
(`/foo?a=1` and `/foo?a=2` collapse to `/foo`) — otherwise a single
real 404 endpoint hit with varying parameters would inflate into "many
distinct invalid URLs" and false-positive a legitimate client.

**No "had a success" exclusion, unlike `sshlog::scanning_ips`.** The SSH
version never flags an IP that has a successful login anywhere in the
log — a strong signal of a legitimate, credentialed client. There's no
HTTP equivalent: a scanner's own recon traffic almost always includes at
least one 200 (`/`, `/robots.txt`, a common file it happens to guess
right), so requiring "never got a 200" would exclude nearly every real
scanner rather than protecting legitimate ones. What *is* still shared
with the SSH version: loopback/private source IPs
(`ipranges::is_local_or_private`, moved there from `sshlog` specifically
so both modules could use it) are excluded outright, since an internal
monitoring probe hammering a stale endpoint isn't an internet scanner
either.

**Known-crawler exclusion (`main.rs::known_crawler_ranges`/
`known_crawler_match`) — the one exclusion that actually matters here.**
Dropping the "had a success" filter (above) means a *real* Googlebot,
Bingbot or GPTBot crawling a site with a stale sitemap or a run of removed
pages will routinely clear the distinct-404 threshold purely by doing its
job — chasing old links is normal crawler behavior, not scanning. Since
this app's entire premise is "stop bad bots, still allow good bots"
(README/Cargo.toml), shipping this feature without an exclusion for the
three *verified* crawler sources it already tracks would auto-blocklist
exactly the bots the rest of the codebase goes out of its way to protect.
Before adding any Block rules, `block_web_scanners` fetches every CIDR
already stored for `ipranges::IpRangeSourceKind::ALL` (Googlebot, Bingbot,
GPTBot — the same three `update-ip-ranges` populates) via
`Db::ip_ranges_for_source`, and drops any candidate IP that
`ipranges::cidr_contains` places inside one of them, regardless of the
site's current category-blocking defaults — this is about never
misidentifying a *verified* crawler via a behavioral heuristic, a
different concern from whether the admin has separately chosen to block
that crawler's category through the normal, range-complete derived-
firewall-rule path (which still works independently of this exclusion).
If none of the three sources has ever been fetched (`update-ip-ranges`
never run), the exclusion list is simply empty and a warning is printed —
silently providing no protection would be worse than saying so. That
warning only covers *never fetched*, though — it's silent about *fetched
long ago*: Google/Bing periodically rotate their published ranges, so an
admin who fetches once at setup and only automates `block-web-scanners`
(not `update-ip-ranges`) will find the exclusion quietly going stale over
time. If you're automating this, automate both together.

**Threshold is a count, not a rate — same caveat as `block-scanners`.**
No timestamp parsing, so `--threshold` (default 7, lowered from an
original default of 15 to detect scans sooner) counts over however much
of the log got read, not attempts-per-minute. Lower than SSH's
default-20 specifically because it's counting *distinct paths*, already a
much stronger signal than raw line count — a benign visitor essentially
never racks up 7 different dead links, while scanner tooling (nikto,
dirb-style path enumeration, ...) routinely tries far more than that in
one pass.

**Log source:** unlike `sshlog::find_default_source`, there's no second
default path to try and no `journalctl` fallback — NGINX writes to a
configured file path regardless of init system, and the vast majority of
installs use the stock `/var/log/nginx/access.log`. `--access-log <path>`
overrides it, same rationale as `--ssh-log` (custom install layouts,
deterministic tests).

**Expiry (`--ttl-days`, default 1) — same mechanism as `block-scanners`,
shorter default.** A day, not five: an HTTP scan is typically a single
short automated pass (crawling every path on a list in minutes), not an
ongoing brute-force campaign, so there's less value in holding the block
open for days and more value in re-evaluating sooner whether the IP is
still worth blocking. Otherwise identical semantics — pruned on read via
`Db::list_firewall_rules`, expiry only takes effect once `render-firewall`
re-renders and is re-applied, no TTL refresh on re-detection, shown in
`list-firewall-rules` as `(expires in Nd)`/`(expires in Nh)` — see the SSH
section above for the full reasoning, which isn't repeated per-flag here.

**Known limitations, left deliberately unaddressed, same spirit as
`block-scanners`'s:** no CIDR-range grouping; only the stock "combined" log format is parsed (a
custom `log_format` directive that reorders or omits fields won't parse,
and is silently skipped line-by-line rather than erroring); only ever
reads whichever single file `--access-log`/the default path names — a
multi-vhost setup logging each site to its own file needs one run per
log file, there's no vhost-discovery integration with `discover_sites`
yet; no interactive TUI affordance, same caveat as `block-scanners` above
— it does run on a timer via "Internal cron" below, just without a popup
to trigger or configure it on demand. Behind a reverse proxy/CDN,
`$remote_addr` is the proxy's own IP, not the real client's (that's
`X-Forwarded-For`, not parsed here) — on a proxied site this would
blocklist the proxy, i.e. every visitor. No `X-Forwarded-For` handling is
built, deliberately: trusting a client-controlled header without also
knowing which upstream proxies are legitimate is its own can of worms, and
better solved (if ever) as its own deliberate feature rather than bolted
onto this one.

## Internal cron (`src/cron.rs`, `App`'s tick handler in `src/app.rs`, `src/web/cron.rs`, the Dashboard's "Scheduled tasks" panel)

Replaces relying on an external `cron`/systemd-timer entry to keep the
scanner-detection and crawler-range commands running unattended, by having
the TUI itself periodically check which of four background jobs are due
and run them: `UpdateIpRanges`, `BlockScanners`, `BlockWebScanners`,
`RenderFirewall` (see `CronJob` for exactly what each does — it's the same
logic each equivalent CLI subcommand runs, via `scanblock`/`ipranges`/
`firewall`, not a reimplementation). The Dashboard grew a fifth panel,
"Scheduled tasks", listing all four with when they last ran and their last
outcome.

**Only automates while a stop-bots front-end is running — this is the one
limitation to know before treating it as a full cron replacement.** The
TUI (`App::check_cron`) and the web server (`crate::web::cron`, a plain
background task, since `AppState::with_db` already solves the
`Db`-isn't-`Sync` problem that makes the TUI's version a start/finish
pair) both drive it; closing both pauses every job, and there is no
separate headless daemon mode. Running both at once is safe and does not
double the work: they record through the same `cron_last_run:{id}` keys,
so whichever ticks first marks the job done and the other finds it no
longer due — which is also why the per-job logic lives in `cron.rs`
(`read_log_for`, `run_log_job`, `fetch_ip_ranges`, `store_ip_ranges`)
rather than in either front-end. A job overdue when a front-end (re)starts
just runs the next time it's checked (the same never-fetched-yet
convention `ipranges` staleness already used), not a "catch up on however
many intervals were missed" scheme.

**State is persisted in the existing `settings` table, not kept
in-memory.** Two keys per job (`cron_last_run:{id}`, `cron_last_summary:{id}`,
new `Db` methods) rather than a second schema migration (see "Firewall
integration" above for the first one, `firewall_rules.expires_at`) — this
buys two things: "last ran 3h ago" survives restarts instead of resetting
(and, worse, making everything look overdue and firing a thundering herd
of work every time the TUI opens), and a future headless daemon could read
and write the exact same state the TUI does, making it a thin follow-on
rather than a different architecture chosen now.

**Per-job interval, not one blanket tick rate** (see `CronJob::interval`'s
doc comment for the full reasoning): `UpdateIpRanges` and `RenderFirewall`
stay daily — neither is time-sensitive. The three detection/log jobs
(`BlockScanners`, `BlockWebScanners`, `RecordAccessStats` — see below)
originally ran every 4 hours/hourly/hourly respectively, on the reasoning
that SSH brute-forcing is a longer campaign than a URL-enumeration scan.
Changed to every 60 seconds, all three: the point of automated detection
is catching an attack while it's still in progress, and once-a-minute is
the practical floor anyway, since `App::check_cron` itself only checks
which jobs are due once a minute (throttled against `Event::Tick`'s 30fps
rate — cheap either way, a handful of `settings` reads, but no reason to
ask 30 times a second). A job's own interval can never be shorter than
that check cadence and have it matter; tightening detection further would
mean shortening `cron::CHECK_INTERVAL` itself, not just the job's
`interval()`.

**All five jobs now start background work rather than running any part of
themselves inline — this replaced an earlier design where only
`UpdateIpRanges` did.** The other four (`BlockScanners`/`BlockWebScanners`/
`RecordAccessStats`/`RenderFirewall`) used to run their log read straight
from `App::check_cron`, on the reasoning that log-parsing/`Db`/
file-writing is "pure local work". That reasoning missed that
`sshlog::find_default_source`/`accesslog::find_default_source` do blocking
file I/O, and — for the SSH log, when no log file exists — shell out to
`journalctl` via a fully synchronous `Command::output()`, which can take
long enough to freeze the whole TUI (no redraw, no input) for the
duration. Fixed by moving only that log-resolution step to
`tokio::task::spawn_blocking` (not a plain `tokio::spawn` task, since it's
blocking I/O/a subprocess call, not async I/O — a plain async task would
stall a runtime worker the event loop needs) in
`App::start_cron_log_job`, which reports the resolved text (or `None` if
unavailable) back via a new `AppEvent::CronLogFetched`. The parsing/
counting/`Db` writes that follow stay on the main thread in
`App::finish_cron_log_job`, unchanged from before — they're fast in-memory
work, and moving them too would mean a second `Db` connection fighting the
existing `Db`-isn't-`Sync` pattern for no benefit. `UpdateIpRanges` keeps
its original shape (`start_source_update`/`start_country_select`-style: a
plain `tokio::spawn` task, since it's real async network I/O, reporting
via `AppEvent::CronIpRangesFetched`). A single `cron_jobs_in_flight:
HashSet<CronJob>` (one guard covering all five jobs, replacing the old
`UpdateIpRanges`-only bool) stops a slow job from starting a second,
overlapping run if `check_cron` finds it still "due" on a later tick —
`last_run` doesn't update until a job actually completes, so without the
guard every check while one was still in flight would start another.

**The Dashboard's "Scheduled tasks" panel shows a braille spinner next to
whichever job(s) are currently running**, reading `App::cron_jobs_in_flight`
(threaded into `Dashboard::render` as `running_jobs`) instead of the usual
"due now"/last-summary text for that job's line. The spinner frame is
picked from wall-clock time (`SystemTime::now()`, ten-frame braille
cycle) rather than a counter `Dashboard` would have to own and advance
itself — since `render` runs on every draw of the TUI's own redraw loop,
that alone is enough to animate it smoothly. Tests assert the fixed
"Running now" text only, never a specific frame glyph, since the glyph is
time-dependent and would flake.

**The manual `f`-key firewall render (`App::render_firewall`) is
deliberately still fully synchronous, unfixed by this change.** It calls
the same `assess_lockout_risk` → `sshlog::find_default_source` chain
internally, so it can hang the TUI too — left alone because the request
that prompted this fix was specifically about *cron* jobs; the manual path
is a separate, smaller-blast-radius follow-on if it turns out to matter in
practice (it's a single explicit keypress, not something firing every
minute unattended).

**`RenderFirewall` never applies anything — same generate-only design as
everywhere else `firewall_rules` is touched.** It writes to
`firewall::DEFAULT_OUTPUT_PATH` (`/etc/stop-bots/firewall.nft`, the same
path the Dashboard's `f`-key popup defaults to) using the nftables backend
(handles allowlist geo mode, unlike iptables), and skips the write
entirely — recording why as the job's summary, not an error — if the
lockout check finds it would risk cutting off a currently-connected SSH
client. Actually applying the script (`nft -f ...`) remains a manual step
for the admin; an internal cron that silently executed firewall changes
would be a categorically different, much riskier feature than this one.

**The three-things-must-be-automated-together caveat from the scan
detection sections above is exactly what this feature closes** — `update-ip-ranges`,
`block-scanners`/`block-web-scanners`, and `render-firewall` no longer
need separate cron entries kept in sync by hand, since all three now run
on their own schedules from the same process. What it *doesn't* close:
applying the rendered script is still manual (see above), and none of it
runs when the TUI isn't open.

## Dashboard geo-blocking panel (`src/tui/dashboard.rs`)

Adds a TUI surface for the host-wide country blocking described above —
previously CLI-only (`update-country-ranges`/`block-country`/
`unblock-country`). Lives on the Dashboard, not a new screen: a second
list, "Geo-blocking (host-wide)", rendered below the existing "System-wide
settings" category list.

**Two lists, one arrow-key flow, no dedicated focus key.** Bot settings'
`Focus` enum switches panels via `/` because it's pairing a list with a
search box — genuinely different input modes. Here both panels are plain
lists, so `Focus::Categories`/`Focus::Countries` switches simply by
flowing `Down` past the last category row into the countries list (landing
on row 0), and `Up` above the countries list's row 0 back into the last
category row. Feels like scrolling one continuous list without the
bookkeeping of actually unifying two differently-shaped data sources
(fixed 3 categories vs. a dynamic "+ Add a country" action row plus N
blocked countries) into one.

**The countries list's row 0 is always the fixed "+ Add a country to
block" action**, never a real country — `Db::list_blocked_countries()`'s
results start at row 1. Enter on row 0 opens a small text-input popup
(`Popup::AddCountry { input, error }`); Enter on any other row unblocks
that country directly, no confirmation popup. This asymmetry is
deliberate: a category default is genuinely "choose one of two options"
(warrants a popup with both shown), but unblocking a country has exactly
one meaningful action — direct execution matches how Site settings'
apply/apply-all already work (immediate, reversible, no "are you sure").

**The add-country popup validates before ever dispatching anything.**
`ipranges::validate_country_code` (made `pub` for this) rejects anything
that isn't 2 alphabetic characters inline, in the popup itself (`error:
Option<String>` shown under the input), before any database write or
network call. Confirming a *valid* code then branches on whether it's
already known:
- Already blocked → no-op, just a "already blocked" message.
- Already fetched (has rows in `country_ip_ranges`, e.g. blocked before via
  the CLI, or blocked-then-unblocked previously in this same session) →
  `Db::set_country_blocked` directly, `KeyOutcome::Mutated`. No network
  round-trip needed — reuses whatever was cached.
- Never fetched → `KeyOutcome::BlockCountry(code)`, handled by `App`.

**Why fetching can't happen inside `Dashboard::handle_key` itself.** Same
constraint `start_source_update` already works around: `Db`'s connection
isn't `Sync`, so a `tokio::spawn`ed background task can't hold a reference
to it. `App::start_country_block` spawns a task that only fetches and
parses (`ipranges::fetch_country` + `parse_zone_file`); the actual
`Db::replace_country_ranges` + `Db::set_country_blocked` — completing the
original "block this country" intent, not just "fetch its data" — happens
back on the main thread in `App::finish_country_block`, once
`AppEvent::CountryBlockFinished` arrives. Exactly the
fetch-off-thread/store-on-thread split `start_source_update`/
`finish_source_update` already established for bot-list source updates;
`KeyOutcome::SelectCountry`/`AppEvent::CountrySelectFinished` are the
country-selection analogues of `KeyOutcome::UpdateSource`/
`AppEvent::SourceUpdateFinished`. (Originally named `BlockCountry`/
`CountryBlockFinished` — renamed along with everything else described in
"Geo-blocking: Blocklist and Allowlist modes" below, once "block" stopped
being universally true.)

**Testing the fetch-needed path without hitting the network.** Every pty
test in this codebase that involves a real fetch cancels rather than
confirms (see "End-to-end tests" above) — this one is no different in
spirit, just cheaper to arrange: the unit test
(`add_country_popup_confirming_an_unfetched_code_returns_select_country`)
asserts the `KeyOutcome` directly without ever spawning anything, and the
one pty test (`dashboard_geo_blocking_add_and_remove_a_country`) seeds an
*already-fetched* country directly via `Db::replace_country_ranges` before
launching the TUI, so the add-country flow it exercises takes the
synchronous "already fetched" branch — no network access, same as every
other pty test in this suite.

## Geo-blocking: Blocklist and Allowlist modes (`Db::GeoMode`, `Db::geo_firewall_rules`)

The original geo design (previous two sections) only ever blocked selected
countries, everything else allowed. Extended to a second mode: **Allowlist**
— selected countries are the *only* ones allowed, everything else blocked
host-wide. `Db::GeoMode` (`Blocklist` | `Allowlist`, stored in `settings`
under `geo_mode`, defaulting to `Blocklist`) governs how
`Db::geo_firewall_rules` interprets `selected_countries` (renamed from
`blocked_countries` — see below):

- **Blocklist**: every selected country's CIDRs, as Block.
- **Allowlist**: every selected country's CIDRs, as Allow, **followed by**
  a trailing `0.0.0.0/0`/`::/0` Block — the "everything else" catch-all.
  Order is load-bearing: the catch-all must render last so it never shadows
  an allowed country's rule, or an admin's own `firewall_rules` Allow
  entry, that came before it in the combined rule list `main.rs::render_firewall`
  builds (admin rules, then crawler IP-range Blocks, then geo rules).

**Renamed, not just extended — "blocked" stopped being universally true.**
`blocked_countries` → `selected_countries`; `Db::set_country_blocked`/
`list_blocked_countries` → `set_country_selected`/`list_selected_countries`;
CLI `block-country`/`unblock-country`/`list-blocked-countries` →
`add-country`/`remove-country`/`list-selected-countries`, plus a new
`set-geo-mode --mode blocklist|allowlist`. `Db::blocked_country_ranges`
(a join across all blocked countries) was replaced by a plain per-country
`Db::country_ranges` lookup, since `geo_firewall_rules` needed to iterate
selected countries and look up each one's CIDRs regardless of what action
they'd get. The Dashboard's messages ("Blocked NL" vs "Allowed NL",
"Removed NL" regardless of mode) and the geo panel's title
(`Geo-blocking (host-wide) — Blocklist — ...` / `— Allowlist — ...`) read
`geo_mode` directly rather than hardcoding "block" language — see
"Dashboard geo-blocking panel" above for the panel itself, extended here
with `Popup::GeoMode { selected }` (`m` key, from anywhere on the
Dashboard) and its own confirmation message spelling out exactly what
Allowlist means, since it's the one action on this screen that isn't
easily reversible in spirit (Blocklist→Allowlist doesn't destroy data, but
the *next* `render-firewall` run behaves completely differently).

This mode split surfaced two real bugs, both fixed as part of landing it
rather than filed for later — Allowlist's trailing catch-all is exactly
the kind of change that turns a latent gap into an active one:

**1. `render-firewall` now refuses Allowlist mode on `--backend iptables`.**
A trailing `0.0.0.0/0`/`::/0` Block only makes the resulting chain a safe
default-deny gate if two things are also true: loopback and
established/related connections are allowed ahead of it, and IPv6 is
actually enforced. `nftables::render` already emits both (`iif lo accept`,
`ct state established,related accept`, and real `ip6 saddr` rules) — see
"Firewall integration" above. `iptables::render` has neither: its
`STOP-BOTS` chain has no loopback/established carve-out at all (fine
today, since it only ever holds specific DROPs that fall through to
INPUT's own ACCEPT policy when nothing matches — but a `0.0.0.0/0` DROP as
the last rule means *nothing* ever falls through again, dropping
`127.0.0.1` along with everything else), and it skips IPv6 rules entirely
by design (see its module doc comment) — meaning an Allowlist catch-all's
`::/0` entry never renders at all, silently permitting *all* IPv6 traffic
while IPv4 is locked down to just the allowed countries. `render_firewall`
now checks `db.get_geo_mode()` before doing anything else and bails with a
clear message if the backend is iptables — a one-line guard that avoids
either failure mode entirely, rather than trying to patch iptables into
supporting a use case its module doc comment already explains it wasn't
designed for.

**2. The SSH lockout check was rewritten to simulate first-match-wins
evaluation, not "does any Block rule's CIDR contain this IP".** The
pre-Allowlist version (`lockout_risks(addresses: &[String], ...)`, see
"SSH lockout safety net" above) only ever had Block-rule addresses to
check against, so "any Block CIDR contains this IP" and "the first
matching rule is a Block" were the same question. Allowlist breaks that
equivalence on purpose: an admin's connected IP might be *covered by an
earlier Allow rule* (their own `firewall_rules` entry, or an allowed
country) before the catch-all is ever reached — real firewalls stop at
the first match, so that admin is safe, but the old heuristic would still
flag them, because the catch-all's `0.0.0.0/0` CIDR *does* technically
contain their IP too. Rewritten to `lockout_risks(rules: &[FirewallRule],
...)`: for each connected IP, walk `rules` in the exact order they'll be
rendered and stop at the first CIDR match; only a Block/Reject first-match
counts as a risk. Deliberately doesn't model established/related
connections — the question this answers is "can this client *reconnect*
after applying this", which is the stricter and more useful one (an admin
who disconnects can't rely on an already-open session to get back in).
Verified end to end in `tests/cli.rs`
(`render_firewall_allowlist_mode_does_not_warn_when_an_earlier_allow_rule_covers_the_admin`):
an admin-added Allow rule for the connected IP renders successfully with
no warning, while the same IP with no such rule (`render_firewall_rejects_allowlist_mode_on_iptables_cli`'s
sibling scenarios) still gets caught by the catch-all.

**A side effect of fixing #2, not something Allowlist mode itself needed:**
tracing through real rule lists surfaced that `ipranges::cidr_contains`
never matched a bare IP address with no `/len` at all — exactly the shape
of `firewall_rules.address` for a plain `add-firewall-rule --address
1.2.3.4` (no CIDR suffix). Its `split_once('/')` returning `None` fell
through to "no match", silently treating every plain-IP admin rule as
invisible to the lockout check. Fixed by treating a bare address as an
exact-match `/32`/`/128` rather than "not a CIDR, so never matches" — this
was already wrong before Allowlist existed (a plain-IP Block rule's
address was never checked against connected IPs either), just never
exercised by a test until this rewrite needed real rule lists containing
plain IPs to verify the first-match-wins logic against.

## NGINX reload, a real quoting bug, and a duplicate search hint

Three issues found by exploratory testing on a real machine (NGINX now
available in this environment, unlike when "NGINX integration" above was
written).

**1. A bot pattern ending in a backslash corrupted the generated config.**
Reproduced against a real `nginx -t`: NGINX's config parser treats a `\"`
immediately before what would be a string's closing quote as an *escaped*
quote, not a terminator, so a trailing backslash on whichever pattern
happened to land last in the `|`-joined regex left the quoted state open.
NGINX then scans for a real closing quote through the rest of the file and
fails at EOF with `too long parameter, probably missing terminating """
character` — exactly the error seen in the field. (A trailing backslash
*pair* avoids that specific failure by collapsing to one backslash before
the closing quote, but that leftover backslash then fails regex compilation
instead: `pcre2_compile() failed: \ at end of pattern`. So any trailing
backslash at all is unsafe, not just an odd run — confirmed with both cases
against the real binary.) Each botlist parser already filtered patterns
containing a literal `"` (they'd break out of the string the same way), but
none filtered a trailing backslash, and `nginx-bad-bots` in particular is a
~700-entry scraped list where a malformed trailing-backslash entry is
entirely plausible upstream.

Fixed at the point patterns get joined into NGINX syntax (`nginx::
is_embeddable`/`join_patterns` in `src/nginx.rs`), not only at the botlist
parsers: this is the single place all three current sources' output (and
any row already sitting in the db from before this fix) funnels through, so
it's the actual last line of defense regardless of where a bad pattern came
from. The three parsers also got the same filter extended (`!p.contains('"')
&& !p.ends_with('\\')`) for defense in depth and to keep obviously-unusable
patterns out of the db entirely, matching their existing quote-filtering.
Regression test in `nginx.rs` writes the exact scenario and asserts the
sentinel's closing quote lands where expected; verified end to end against
a real `nginx -t` during development (not committed as an automated test,
since it needs the `nginx` binary).

**1b. This was not the actual production failure.** After landing the fix
above, the same `too long parameter, probably missing terminating """
character` error recurred on the real machine. Re-tested against a real
`nginx -t` with a properly *terminated* quoted string of increasing length
and found a second, unrelated cause: NGINX's config parser has a hard
ceiling on a single quoted parameter's length, somewhere around 4100 bytes
(matching `NGX_CONF_BUFFER`) — confirmed by binary search (4090 bytes: ok;
4095: fails) and confirmed the boundary isn't about file position either (a
2000-byte parameter still parses fine after ~10KB of unrelated preceding
content). A single `if ($http_user_agent ~* "pattern1|pattern2|...")`
holding every blocked bot's pattern joined with `|` trivially exceeds that
once there are enough bots — `nginx-bad-bots` alone is ~700 entries, and a
synthetic 700-entry list reproduced the exact production error end to end
(`nginx -t` on the generated config: fails before the fix, "syntax is ok"
after).

Fixed by splitting: `chunk_pattern` (in `src/nginx.rs`) breaks the `|`-joined
pattern back into pieces of at most `MAX_PATTERN_CHUNK_LEN` (2000, well
under the observed ~4100-byte failure point) bytes each, splitting only on
`|` boundaries so no individual bot pattern is ever cut in half.
`block_text` renders one `if ($http_user_agent ~* "chunk") { return 403; }`
per chunk instead of a single one — sequential `if` statements are
equivalent to one big alternation (whichever fires first returns 403), so
this changes nothing about *what* gets blocked, only how it's written. A
pattern short enough for one chunk (every existing test fixture) still
renders as exactly one `if`, so this was a no-op for all prior test
coverage. The one place that had to change to match: `current_block_pattern`
(backing `site_apply_status`) previously read only the *first* `~* "..."`
occurrence in a sentinel block; a chunked block now has several, so it
collects every occurrence and rejoins them with `|` to reconstruct the full
pattern — otherwise any site with a long enough pattern list would read
permanently `Stale` immediately after a successful apply, since the
comparison would only ever see the first chunk. Verified end to end with a
synthetic 700-entry list, both via a unit test (asserts every generated
line stays under the safe chunk length and `site_apply_status` reads
`UpToDate` right after applying) and against a real `nginx -t`.

**2. Applying blocking rules never reloaded NGINX**, so a freshly-applied
rule had no effect until an admin manually reloaded — the actual bug the
first exploratory-testing note flagged. Added `nginx::reload()` (`nginx -t`
then `systemctl reload nginx`; the explicit `-t` first gets a caller-facing
error message instead of digging through `systemctl status`). Wiring it in
had a test-suite hazard: both `tests/cli.rs`'s `apply-blocks` invocations
and `site_settings.rs`'s apply tests exercise the real success path
(`Ok(true)`, a file actually changed) as part of normal test coverage, and
naively calling `nginx::reload()` inline there would mean `cargo test`
shells out to the *real* `systemctl reload nginx` against whatever NGINX
happens to be installed on the machine running the tests — nondeterministic
in CI, and actually reloads a real service as a side effect of running the
test suite.

Two different fixes for the two callers:
- **CLI** (`apply-blocks`): new `--no-reload` flag (tests pass it; real
  usage leaves it off, since applying is a no-op without a reload).
- **TUI** (`site_settings.rs`'s "Apply now"/"Apply all"): reload is a real
  side effect the same way `RenderFirewall`/`UpdateSource` already are, so
  it doesn't run inline inside the screen's own (unit-tested, no real
  process execution) `handle_key`. `apply_site`/`apply_all` now return
  `(String, bool)` — status message plus whether a file actually changed —
  and `handle_key` turns that into a new `KeyOutcome::ReloadNginx` instead
  of `Mutated` when something did. `App` (`src/app.rs`) is the only place
  that actually calls `nginx::reload()`, exactly mirroring how it already
  owns `render_firewall`. A reload failure appends to the already-set
  status message rather than replacing it, so a successful apply doesn't
  get reported as a total failure just because the reload step afterward
  didn't work.

  This still wasn't the whole story: `site_settings.rs`'s own unit tests
  only reach `handle_key`, which *returns* `KeyOutcome::ReloadNginx` but
  never executes it, so they were always safe. `tests/tui.rs`, though,
  drives a real spawned `stop-bots tui` process through a pty and *does*
  reach `App::handle_key_event` for real in its Site settings apply tests
  — missed on the first pass and only caught by asking for a second look
  before calling this done. Fixed the same way as the CLI: `App::new`
  gained a `reload_nginx: bool` (stored, checked in the `ReloadNginx` arm
  before calling `nginx::reload()`), threaded from a new `tui --no-reload`
  CLI flag, which `tests/tui.rs`'s single `spawn_tui_with_args` choke point
  now always passes — every pty-driven test is covered, not just the ones
  that currently apply, so a future test reaching the same path stays safe
  by default. `App`'s own unit tests (`test_app()`) also pass
  `reload_nginx: false`, on the same "don't rely on today's coverage
  staying true" reasoning.

**3. The Bot settings and Site detail search boxes showed two "press /"
hints at once.** `filtered_bots()` returns nothing until the query is
non-empty (deliberate — searching starts empty, not "show everything").
With an empty query and at least one bot loaded, that meant *both* the
header's `search_line()` ("Press / to search bots by name") *and* the
results area's empty-state hint ("Press / then type a bot name to search.")
rendered simultaneously — not two different screens each saying it once,
but the same screen saying it twice. Fixed by dropping the results-area
hint for that specific case (empty query, non-empty `bots`) in both
`bot_settings.rs` and `site_detail.rs`, since the header's hint already
covers it; the "no bots yet" and "no bots match "query"" hints are
unaffected. Verified with a `TestBackend` render test in each file
asserting `"Press /"` appears exactly once, not just by reading the code —
this was originally a report from looking at the rendered screen, so the
regression test renders the screen too rather than only exercising
`filtered_bots()`/`search_line()` in isolation.

## Successful-access user-agent tracking (`src/accesslog.rs::successful_user_agent_counts`, `src/accessstats.rs`, `Db::user_agent_stats`)

The complement to web scan detection above: instead of flagging bad
traffic, tallies who's actually browsing the site successfully. New
`accesslog::successful_user_agent_counts(log_text)` extends `parse_line`
(now also returning the request's user agent, the second field of the
trailing `"referer" "user_agent"` quoted pair) and counts each distinct
user agent's hits across every line with `status < 400` from a
non-local/private source IP (same `is_local_or_private` exclusion
`scanning_ips` uses — an internal health check isn't a real visitor
either). Lines with no user agent, or NGINX's `-` placeholder for a
missing `User-Agent` header, are excluded — neither identifies a real
client.

**Storage is additive, not a snapshot.** New `user_agent_stats` table
(`user_agent` primary key, `hit_count`, `last_seen_at`) and
`Db::record_user_agent_hits`/`Db::list_user_agent_stats`. Repeated calls
onto the same user agent add to `hit_count` rather than replacing it, so
running this repeatedly over overlapping log windows (or a log that gets
rotated between runs) accumulates a running lifetime total instead of
losing whatever an earlier run already saw — deliberately different from
`firewall_rules`, which is about current state, not a running count.

**Fixed: every pass now only tallies bytes appended since the last one,
not the whole file again.** `RecordAccessStats` runs every 60 seconds (see
below) and, like every other log-based cron job, re-reads the *entire*
current log from disk each time (no job here keeps a file handle open
between ticks). Because storage is additive (previous paragraph), that
combination silently re-tallied the same still-present requests on every
single tick for as long as the log went un-rotated — `hit_count` numbers
grew far past reality, sometimes dramatically, the longer NGINX's
`access.log` sat between logrotate runs. Fixed by persisting a byte-offset
watermark per log path: new `settings` keys `access_log_offset:{path}`
(`Db::get_access_log_offset`/`set_access_log_offset`, same reused-table
convention as `cron_last_run:{id}`) and a private `accessstats::
new_content(full, last_offset)` that slices off only the suffix appended
since the watermark. `record_access_stats` now takes the log's path (not
just its text) purely as this cache key — nothing is re-read from disk
with it, so the CLI's `--access-log` override and the cron's fixed
`accesslog::DEFAULT_LOG_PATH` (now `pub`, for exactly this) each track
their own progress independently rather than sharing one offset. A file
shorter than the watermark (a rotate, or `copytruncate`) is treated as
entirely new rather than partially skipped or panicking on an
out-of-range slice.

**Shared CLI+cron logic lives in `src/accessstats.rs`, not `scanblock.rs`.**
Mirrors `scanblock`'s "one implementation, both callers" shape, but kept
separate since this isn't a blocking decision — no threshold, TTL,
dry-run or known-crawler exclusion to share with `block_web_scanners`.
`accessstats::record_access_stats(db, log_text)` parses, tallies and
persists in one call, returning an `AccessStatsOutcome` (distinct user
agents, total hits) with the same `summary()`-for-a-status-line shape
`ScanBlockOutcome` uses.

**CLI:** `record-access-stats` (reads the access log, same
`--access-log`/auto-detect resolution as `block-web-scanners`) and
`list-access-stats` (prints every recorded user agent's hit count,
most-seen first). Both storage-only/idempotent-safe-to-rerun, same spirit
as every other command touching this database.

**Internal cron:** new `CronJob::RecordAccessStats`, every 60 seconds — same
cadence as `BlockWebScanners` (both since tightened from hourly, see
"Internal cron" above) since it reads the identical log, no reason
to check it on a different schedule. `CronJob::ALL` is now 5 jobs, not 4.

**Dashboard (superseded — see "Dynamic Protection screen" below):** this
originally folded the top 2 user agents into the "Stats" panel (renamed
"Summary"), rebalancing Geo-blocking (8→6 lines) and Stats (4→6) to make
room within this project's 30-row minimum terminal size without growing
the total past what the Messages panel could give up. That fold-in has
since been superseded: the Dashboard's own panel heights are back to
their original 5/8/4/(2+job count) — Geo-blocking back to 8, the renamed
"Summary" panel back to 4 (just site/source counts, no user agents) —
and the top-user-agents view moved to its own screen (which also lets an
admin act on an entry, not just look at it). `list-access-stats` remains
the CLI's full, unbounded view of the underlying table either way.

**A rendering gotcha surfaced by this change, not a data bug:** the
Dashboard's popups (`Popup::Category`, `Popup::GeoMode`, ...) center
themselves on the *whole* body `Rect` passed into `Dashboard::render`, not
on any of its internal sub-areas — so resizing internal panels alone
never moves a popup's on-screen position. It can still perturb
`tests/tui.rs`'s pty-based assertions, though: those diff the terminal's
*actual previous frame*, and changing what the Dashboard draws underneath
a popup's fixed footprint changes which characters happen to already
match between frames, which changes which runs of text arrive as one
contiguous write versus several (interspersed with cursor-repositioning
escapes). `dashboard_geo_mode_toggle_switches_to_allowlist` needed its
`"Allowlist (block everything except selected)"` assertion split into
three substrings for exactly this reason — same coping pattern the test
already used elsewhere, not a new kind of fragility.

## Dynamic Protection screen (`src/tui/dynamic_protection.rs`, new `blocked_user_agents` table, `Db::block_address_permanently`)

A new fifth tab, `d`/`b`/`s`/`p` jump keys (was `d`/`b`/`s`), inserted
between Site settings and Help in the tab cycle. Two panels — "Top IPs
attempting SSH connection" and "Top User Agents" — each a ranked,
navigable list tagged `NOT BLOCKED` or `BLOCKED` (`BLOCKED until <Nd/Nh>` for
a temporary `firewall_rules` row, bare `BLOCKED` for a permanent one).
`Tab`/`Shift+Tab` switch which panel `Up`/`Down`/`j`/`k` apply to; `Enter`
permanently blocks the selected row. This superseded the Dashboard's
brief "fold top user agents into Stats" detour (see above) — the
Dashboard's own panels are back to their original sizes, renamed to
"Summary".

**Why `Tab` is claimed on this screen, and how that's kept from being a
dead end.** Every other screen leaves `Tab`/`Shift+Tab` to `App`'s global
handler (cycle screens); this one intercepts them (`KeyOutcome::Consumed`)
to switch between its own two panels instead, per how the feature was
asked for. That means Tab-cycling through screens stops advancing once
you land here — `d`/`b`/`s`/`p` and `Esc`/`q` (back to Dashboard) remain
the way out, same as any screen already reachable that way.

**The SSH panel has no persisted table — deliberately, unlike the User
Agent panel.** `Db::list_user_agent_stats` already existed (cheap,
pre-aggregated, populated on its own cron cadence — see "Successful-access
user-agent tracking" above), so the User Agent panel just reads it
directly. Nothing equivalent existed for SSH attempt counts, and this
screen doesn't add one: it re-parses the live SSH log
(`sshlog::find_default_source`, no path override, same lookup
`cron::read_log_for` already uses) on every `refresh`. The
discriminating question that ruled out a new `ssh_attempt_stats`
table/cron job/CLI command mirroring `accessstats.rs`: does this panel
need data that outlives the current log? No — it's explicitly a
real-time "who's hitting me right now" view (the screen's own name), so
the live log is the right source of truth, not a lifetime tally (that's
what `sshlog::scanning_ips`/`block-scanners` already are, on their own
60s cron cadence). New `sshlog::failed_attempt_counts(log_text)` supplies
the raw counts: refactored out of `scanning_ips` (extracted into a shared
`candidate_failed_attempt_counts` helper) so both share the same safety
exclusions — loopback/private addresses and any IP with a successful
login anywhere in the log are never included, even here, so this screen
can never surface something unsafe to block, only unthresholded (every
candidate, not just ones that already cleared `scanning_ips`'s bar).

**"Permanently block" stores intent; it doesn't enforce, same
generate-only discipline as everywhere else.** Blocking an IP
(`Db::block_address_permanently`) only ensures a permanent (`expires_at =
NULL`) `firewall_rules` Block row exists — pruning expired rows first,
then updating any surviving row for that address in place (upgrading an
existing temporary `block-scanners` block to permanent, the natural
reading of pressing Enter on an already-`BLOCKED until` row) or inserting
a fresh one if none exists. `render-firewall` (then applying the script)
is what actually enforces it — and its lockout-safety check (see "SSH
lockout safety net" above) already guards against self-blocking a
currently-connected SSH session, so this screen doesn't duplicate that
guard. Blocking a user agent (`Db::block_user_agent`) only inserts a row
into the new `blocked_user_agents` table (`user_agent TEXT PRIMARY KEY,
blocked_at INTEGER`); `apply-blocks` (or Site settings' `a`/`A`) is what
injects it into NGINX config.

**Why `blocked_user_agents` is its own table, not a synthetic `bots` row.**
`bots`/`bot_source_entries` describe *known, publicly-catalogued* bots —
category flags, a merge cascade across multiple sources contributing the
same slug, a foreign key onto `sources`. None of that fits a one-off
literal string an admin flagged by hand from observed traffic. A
dedicated table (same shape as `selected_countries`/`firewall_rules`) is
simpler and avoids inventing a fake `sources` row just to satisfy a
foreign key. It's folded into `Db::compute_blocked_patterns`'s output
(both `blocked_user_agent_patterns` and `_for_site` funnel through this),
regex-escaped (`escape_for_nginx_regex` — hand-rolled, no `regex`
dependency, since the only requirement is "produce a literal-matching
fragment safe to embed in a `|`-joined NGINX regex," not full parsing) so
special characters in a captured real UA string (parentheses, dots, ...)
don't get interpreted as regex syntax. Appended unconditionally, after
the bot/category cascade: a manual UA block is the same kind of "global
pin, always wins" a global per-bot pin already is, just for a string with
no `bots` row at all, so a site's category override can't limit or lift
it either.

**A caveat worth knowing, not a bug:** the User Agent panel counts only
*successful* (non-4xx/5xx) requests (see `accesslog::
successful_user_agent_counts`), so a user agent already 403'd by an
existing bot-category block never reaches `user_agent_stats` and so never
shows up here. This panel is about traffic that's *getting through*, not
a complete traffic log — by design, not oversight.

## Firewall "needs updating" status and apply-after-write (`src/firewall.rs`, `src/tui/dashboard.rs`, `src/app.rs`)

The `RenderFirewall` cron job only renders daily, while `BlockScanners`/
`BlockWebScanners` add new `firewall_rules` rows every minute — so the
on-disk script can silently lag behind the actual rule set for up to a
day unless an admin happens to press `f`. Added a Summary panel row
("Firewall rules: up to date" / "needs updating (press f to update)")
and an "apply after writing" shortcut in the render popup itself.

**Staleness is a persisted signature comparison, never a disk read.**
`firewall::rules_signature(rules)` is just `format!("{rules:?}")` over the
same rule set `build_script` renders (`firewall::all_rules`, factored out
of `build_script` for exactly this reuse — admin-managed rules from
`Db::list_firewall_rules` followed by derived crawler/geo rules). Every
successful write (`App::render_firewall`, `cron::render_firewall`)
persists this string via new `Db::set_firewall_rendered_signature`
(reuses the `settings` table, one fixed key — there's only ever one
"current" render to track). `Dashboard::refresh` recomputes the current
signature and compares. Deliberately *not* "does `/etc/stop-bots/
firewall.nft`'s bytes match a freshly-rendered nftables script": that
would (a) make `Dashboard::refresh` — called from plain unit tests
constructing an in-memory `Db` — read a real system path, an
unnecessary hermeticity violation, and (b) misreport a real render done
with `--backend iptables` to a custom path as permanently "stale",
since it'd always be compared against a fresh nftables build. The
signature is backend/path-independent by construction: what matters is
whether the *rules* changed since the last render, not which
backend/path last wrote them.

**Panel height was already at its floor, so this didn't grow the
Dashboard.** The Summary panel's new third line needed a row, but at
this project's documented 30-row minimum terminal size, `Constraint::
Min(1)` on the Messages panel was already down to its bare 3-row floor
(1 content row + 2 borders — see "Successful-access user-agent
tracking" above, which hit and rebalanced around this same ceiling
once already). Geo-blocking (`Constraint::Length(8)` -> `Length(7)`)
gave up the row instead of Messages or Summary: it's a scrollable
`List`, which degrades by scrolling to the selected row when its
viewport shrinks, where `Paragraph`'s fixed lines (Messages, Summary)
would just silently lose whichever line no longer fits. Total fixed
height is unchanged (5+7+5+7 = 5+8+4+7 = 24), so the 30-row floor still
gets the same 3-row Messages panel it always did.

**Apply-after-write uses Space, not a modifier combo, for the popup
toggle.** Ctrl+Enter was the first idea, but many terminals (plain
Linux console, tmux without extended keyboard protocols) don't reliably
distinguish Ctrl+Enter from plain Enter, which would make the shortcut
silently not fire in exactly the SSH/tmux environments this admin tool
actually runs in. Space was free to repurpose: the output-path text
field only ever accepted `is_ascii_punctuation() || is_ascii_alphanumeric()`
characters, and space is neither, so it was already a no-op keystroke in
this popup, not text a path could contain. `Popup::RenderFirewall` grew
an `apply_after_write: bool` field toggled by Space and shown as a
`[ ]`/`[x]` checkbox line, carried through unchanged by Enter into
`KeyOutcome::RenderFirewall`'s new `apply` field.

**Applying is still never automatic — only this one explicit, interactive
path can do it.** New `firewall::apply_script(backend, out_path)` runs
`sh <out>` (iptables) or `nft -f <out>` (nftables) — the only place in
the whole project that executes a generated script rather than only
writing it. No cron job calls it; `App::render_firewall` only reaches it
when the popup's toggle was on *and* the write itself already succeeded
(so the same lockout-risk check that gates writing gates applying too,
transitively). Gated by a new `App::apply_firewall: bool` field, sharing
`main.rs`'s existing `--no-reload` flag rather than getting its own CLI
flag — same "don't actually run system-changing commands under test"
reason `reload_nginx` exists for, and re-running the real `nft -f`/`sh`
against a freshly generated script from an automated test would mutate
whatever host runs the suite. `apply_script`'s own unit tests only
exercise the `Iptables` (`sh <script>`) branch, with inert `true`/`false`
scripts rather than real firewall commands: unlike `nft`, `sh` is
universally available and a trivial exit-code script never touches the
real system firewall, so it's safe in CI the same way `nftables::render`'s
tests are safe (they only ever produce text, never execute it) — the
`Nftables` branch has no direct test, for the same reason
`nginx::reload`'s real `systemctl`/`nginx` calls don't either.

## Left/Right and vim h/l as screen-cycling aliases (`src/app.rs`, `src/tui.rs`, `src/tui/help.rs`)

Tab/Shift+Tab already cycled screens; added Left/Right as equivalents, plus
`h` (= Left)/`l` (= Right) as their vim aliases, in the same global
fallback `match` in `App::handle_key_event` that already had Tab/BackTab —
so all four only ever fire once the active screen's own `handle_key` has
returned `Ignored` for the key, exactly the same gating Tab/BackTab
already relied on (a popup's catch-all `_ => Consumed`, or a search box's
unguarded `Char(c)` catch-all, both already stop them from leaking through
today for `d`/`b`/`s`/`p`, so they stop Left/Right/`h`/`l` the same way).

**`h`/`l` deliberately do *not* appear everywhere `j`/`k` do.** `j`/`k`
already alias Up/Down almost everywhere a list is navigated. Left/Right
had no prior meaning anywhere in the app, so `h`/`l` only needed adding at
the one place Left/Right themselves now mean something: this global
screen-cycle fallback. Three places were deliberately *not* given `h`/`l`
(and don't have `j`/`k` either, on inspection — not an oversight,
confirmed while auditing every existing Up/Down site for this change):
Bot settings' and Site detail's `Focus::Search` (a live-filter query box
where every character, including 'h'/'j'/'k'/'l', must be literal search
text — `bot.rs`/`site_detail.rs`'s Up/Down there stay arrow-only), and the
Dashboard's `Popup::RenderFirewall` backend selector (a free-text output
path field with the exact same problem — see the "Firewall 'needs
updating'" entry above, which hit this exact bug with 'j'/'k' and fixed it
the same way: arrows only, no vim aliases, wherever free text entry sits
right next to a selector).

## Dynamic Protection: red for blocked, a display filter, and unblock (`src/tui/dynamic_protection.rs`, `src/db.rs`)

Three additions to the existing SSH/User Agent panels: `BLOCKED` rows
render in red (`style_by_status`, mirroring `dashboard.rs::policy_tag`'s
fixed, theme-independent red/green — not varied per light/dark theme); a
shared `f`-cycled `Filter` (`All` -> `NotBlockedOnly` -> `BlockedOnly` ->
`All`) applied to both panels at once; and `Enter` now unblocks an
already-`Blocked` row instead of only ever (re-)blocking.

**One filter for both panels, not two.** Both panels already share one
mental model ("what am I looking for right now"), and a per-panel filter
would need its own title-hint slot in both — one `Filter` field keeps the
UI and the state simple. `Filter::matches(status)` is the single place
that decides visibility; `Filter::All` always passes.

**Filtering never mutates `ssh_rows`/`ua_rows` — it's a view.** New
`visible_ssh_rows`/`visible_ua_rows` filter the full rows fresh on every
call (render *and* selection resolution both go through them), so there's
only one source of truth for "what does the current filter show" and it
can never drift from what's actually on screen. `ListState`'s selected
index refers to a position in this *filtered* list, not the full
underlying vector — `toggle_block_selected` resolves through
`visible_ssh_rows().get(i)`/`visible_ua_rows().get(i)` accordingly, not
`ssh_rows.get(i)`/`ua_rows.get(i)` directly, and both the filter-change
handler and `refresh` re-clamp the selection against the *filtered*
length (`clamp_selections`, replacing the old direct `clamp_selection`
calls against the raw row counts) — otherwise switching to a filter with
fewer visible rows than the current selection index would leave the
selection pointing at a row that's no longer on screen.

**Enter is now a toggle, which is a real, deliberate behavior change from
before.** Previously Enter always called `block_address_permanently`
regardless of a row's current status — including upgrading an
already-temporarily-blocked row (e.g. one `block-scanners` added) to
permanent, a dedicated convenience with its own test
(`enter_upgrades_an_already_temporarily_blocked_ssh_row_to_permanent`).
That convenience is gone: Enter on *any* `Blocked` row (temporary or
permanent) now unblocks it instead, matching how this app already treats
Enter as a context-sensitive toggle elsewhere (the Dashboard's Countries
list: Enter on an existing country removes it directly, no separate key —
see `tui/dashboard.rs`'s module doc). New `Db::unblock_address`/
`unblock_user_agent` are the direct reverse of `block_address_permanently`/
`block_user_agent`: the former only ever deletes a `firewall_rules` row
matching the exact address *and* `action = 'block'` — never a CIDR range
(those are derived, never stored as rows) and never an `Allow` rule that
happens to share the address, which an unblock action has no business
touching.

## Configurable block response, and `BlockConfig` (`src/nginx.rs`, `Db::BlockResponse`)

**What changed.** The generated sentinel block's `return 403;` is now a
setting: `Db::BlockResponse` (`settings` key `block_response`) is either
`Forbidden` (403 — the default) or `Close` (444). Surfaced three ways: a
new "NGINX settings" panel on the Site settings screen, the CLI's
`set-block-response --response forbidden|close`, and `nginx::BlockConfig`
which is what actually renders it.

**Why 444 at all.** `return 444;` is NGINX's non-standard "close the
connection without any response". It's cheaper (nothing is generated or
sent) and it gives a scanner no status code to adapt its probing to —
both real reasons operators prefer it. It stays *opt-in* because it is
indistinguishable from the server being down: a legitimate client caught
by an over-broad pattern gets no way to tell it was blocked deliberately.
403 remains the default so an existing install's generated blocks don't
change shape on upgrade.

**Why the setting is host-wide, not per-site.** Every existing per-site
knob (`site_category_overrides`, `site_bot_overrides`) answers "*which*
bots are blocked here". This answers "*how* do we turn bots away", which
is a house style rather than a per-site policy decision. It's still
carried *through* `BlockConfig` per site, because that's what the
rendering and staleness paths need.

**The `BlockConfig` refactor, and why it wasn't optional.** Before this,
`site_apply_status` compared *the user-agent pattern extracted back out of
the on-disk block* against the pattern that would be computed now
(`current_block_pattern`, which scraped `~* "` occurrences and rejoined
them). That works only as long as the pattern is the *sole* thing that can
differ between two valid blocks. The moment the response code became
configurable it stopped being true: flipping 403 → 444 leaves the patterns
identical, so every already-applied site would have kept reading `UP TO
DATE` while its config still returned 403 — a silent lie in the one
indicator that exists for "does disk match policy". Both callers of that
status (Site settings' row tags) and the apply paths now share one struct:

    pub struct BlockConfig { patterns: Vec<String>, response: BlockResponse }

`block_text(&BlockConfig) -> Option<String>` renders it (`None` = nothing
to block, which *removes* an existing block), and `site_apply_status`
compares that rendered text against `current_block_text` — the whole
sentinel region verbatim, still anchored to the sentinel markers so an
unrelated hand-written `if ($http_user_agent ...)` elsewhere in the same
`server { }` is never mistaken for ours. Rendered-text-vs-rendered-text
has no blind spot and stays correct for free as `BlockConfig` grows, which
matters because the remaining planned NGINX features (path exemptions,
rate limiting, robots.txt) all add fields to it.

**The invariant this establishes**, documented on the module and on
`BlockConfig` itself: anything that changes the generated block goes *on
`BlockConfig`*. A knob smuggled into `block_text` as a separate argument
would render correctly and still break staleness detection.

`nginx::block_config_for_site(db, site_id)` / `default_block_config(db)`
assemble the struct, so a future host-wide field reaches all three call
sites (`apply-blocks`, Site settings' refresh, Site settings' apply) at
once instead of being wired up three times.

**TUI placement.** Host-wide settings that shape *NGINX config text* live
on Site settings; host-wide settings that shape the *firewall script* live
on the Dashboard. That split is the organising rule for where any future
toggle goes. `Tab` switches focus between the new panel and the site list
— a narrower override of the global screen-cycling Tab, exactly like
Dynamic Protection already does for its two panels (screen cycling stays
reachable via Right/`l` and the direct `d`/`b`/`s`/`p` jumps). The setting
opens a popup pre-selected on its current value, so confirming without
moving is a no-op rather than a silent change to the first option.

**Nothing is applied implicitly.** Changing the response only changes what
*would* be written; the CLI prints an explicit "run apply-blocks" line and
the TUI's status message says the same, because every applied site
flipping to STALE is otherwise easy to misread as "already live". This is
the same generate-then-apply discipline the firewall side already follows.

## Spoofed-crawler detection (`accesslog::spoofed_crawler_ips`, `scanblock::block_spoofed_crawlers`, `src/protection.rs`)

**What it does.** Flags any IP whose request claimed — via its
`User-Agent` — to be Googlebot, Bingbot or GPTBot while connecting from an
address that crawler's own operator doesn't publish, and adds a temporary
Block rule for it. Available as `block-spoofed-crawlers` on the CLI, as the
`BlockSpoofedCrawlers` internal-cron job, and as an "Automatic blocking"
row on the Dashboard.

**Why this and not reverse DNS.** Forward-confirmed rDNS is the canonical
crawler check, but it needs a DNS lookup *per request*, at request time —
nothing in this codebase sits in the request path, and a generated NGINX
`if` block cannot do a lookup. The published CIDR lists answer the same
"is this actually Google?" question offline, against a log after the fact.
The data was already here: `ipranges::IpRangeSourceKind` fetches all three
lists, and until now they were only used for *exclusion* (never
auto-blocking a verified crawler in `block_web_scanners`). This inverts
the same data into a detector.

**No threshold, unlike the other two detectors.** `block-scanners` needs
≥20 failed logins and `block-web-scanners` ≥7 distinct 404s because
behaviour is a matter of degree. A forged crawler UA isn't: one request is
already conclusive, because nothing legitimate has a reason to put
`googlebot` in its user agent from an address Google doesn't own, and the
published lists are complete by construction — that's what publishing them
is for. So there is no count to tune and no `--threshold` flag.

**The one dangerous failure mode, and the two guards against it.** With no
ranges stored, *every* real crawler request looks forged — a fresh install
would block the actual Googlebot, which is SEO damage rather than a
nuisance. Guard one: `scanblock::crawler_claims` drops any source with an
empty range list rather than including it empty, so the detector is inert
until `update-ip-ranges` has actually succeeded. Guard two:
`spoofed_crawler_ips` re-checks the same condition instead of trusting its
caller. `ScanBlockOutcome::crawler_exclusion_active` carries the
distinction outward, so the CLI can say "nothing was checked" rather than
the much worse "nothing was found".

**Verification is per request, not per claim.** A user agent naming two
crawlers is verified if *any* of the named crawlers vouches for the
address. Checking each claim separately would flag the real Googlebot the
moment its UA string happened to contain another crawler's token — the
detector's own `googlebot`-verified line would still be reported as a
Bing impersonation. There is a regression test for exactly this.

**Defaults: on, with a 1-day TTL.** On, because unlike the threshold
detectors there's no tuning to get wrong and it's inert without data. One
day rather than `block-scanners`' five because the realistic false
positive is a crawler operator publishing a new range faster than the
daily `UpdateIpRanges` job picks it up; a short TTL bounds how long a real
crawler address stays blocked, and a genuine impersonator is re-flagged on
its very next request anyway.

**`ScanKind`.** `ScanBlockOutcome` gained a `kind` so `summary()` says "no
forged crawler IPs found" instead of "no scanning IPs found" — on the
Dashboard's Scheduled-tasks panel the old noun would have described the
wrong thing entirely.

## Automatic-blocking settings (`src/protection.rs`) and the Dashboard panel

**Where the toggles live, and the rule behind it.** Host-wide settings
that shape the *firewall script* go on the Dashboard; host-wide settings
that shape *NGINX config text* go on Site settings. Detectors write
`firewall_rules` rows, so they're Dashboard-side. This is the organising
rule for any future toggle, and it's why the block-response setting went
to the other screen.

`protection.rs` holds every detector's `settings` key, its default, and
the reasoning for that default in one place, so the cron job, the CLI and
the TUI panel can't disagree. `Db` grew generic
`get_bool_setting`/`get_int_setting`/`get_text_setting` accessors (plus
setters) over the existing key/value `settings` table rather than a column
per knob — these are all scalar, host-wide and independently defaulted.
Every read falls back to a caller-supplied default, so a database written
before a setting existed keeps behaving exactly as it did, and a corrupt
or hand-edited value falls back rather than failing a detection pass.
`ProtectionSettings::default()` is hand-written (not derived) so it agrees
with `load()` on an untouched database — a derived `false`/`0` would make
the panel show one thing before its first refresh and another after.

**A disabled detector is skipped, not run-and-discarded**, but it still
records a `"disabled"` last-run summary so the Scheduled-tasks panel
explains itself rather than showing a job that looks permanently overdue.
Turning a detector off never removes rules it already added: those expire
on their own TTL. "Stop detecting" and "undo what was detected" are
deliberately separate, the latter being the admin's call via Dynamic
Protection or `remove-firewall-rule`.

**Panel layout.** Geo-blocking and Automatic blocking now sit *side by
side* in the Dashboard's middle row. Stacking a fourth full-width panel
would have pushed past the documented 30-row minimum terminal height —
and the Scheduled-tasks panel grows by a row for every detector added, so
that ceiling gets closer with each one. Both are scrollable `List`s of the
same shape, so splitting the width costs neither anything it can't absorb.
The consequence is a **width** floor of ~80 columns (the universal
terminal minimum), since a title longer than its half-width border is
silently truncated; the Geo-blocking title was shortened accordingly, with
the *mode* kept first because Allowlist turning the host default-deny is
the one thing that must never be what gets cut. Focus still flows
linearly, Up/Down, System-wide settings → Geo-blocking → Automatic
blocking, and only the focused panel draws a highlight.

**One popup, not a toggle plus a number entry.** Enter on a detector row
opens a one-of-N popup: "Off", then one "On — block for N days" row per
`PROTECTION_TTL_CHOICES` entry. That folds the TTL into the interaction
this screen already uses everywhere else, instead of adding a second key
and free-text numeric entry for one field. Choosing "Off" leaves the
stored TTL alone, so re-enabling restores what was configured. A TTL set
outside the offered choices (the CLI takes any number of days) opens on
the *closest* choice rather than falling back to "Off", which would
misrepresent an enabled detector as switched off.

The ON/OFF tag is deliberately not `policy_tag`: that one means "traffic
is allowed/blocked", so an enabled detector rendered as `[ BLOCKED ]`
would read as the opposite of what it says.

## Instant-block probe paths (`accesslog::probe_path_ips`, `scanblock::block_probe_paths`)

**What it does.** Blocks any IP that requests a path nothing legitimate
ever asks for — `/.env`, `/.git/config`, `/wp-config.php`,
`/vendor/phpunit/...` — on the *first* request, with no threshold.
Complements `block-web-scanners`' ≥7-distinct-404s heuristic, which is
deliberately slow by comparison.

**The selection rule for `DEFAULT_PROBE_PATHS`, which is the whole design.**
A path belongs on the list only if it is never legitimate *on any site*,
not merely if it's commonly probed. That excludes several of the most
frequently attacked paths on purpose: `/wp-login.php` and `/wp-admin/` are
how real WordPress administrators sign in, `/xmlrpc.php` is how Jetpack
and pingbacks work, `/phpmyadmin` exists deliberately on plenty of hosts.
Instant-blocking a site's own admin on their first login attempt would be
a far worse bug than missing a scanner — and the 404-counting detector
catches that scanner anyway. What's left is credential and source-tree
exposure: files that only exist because of a deployment mistake and are
only ever requested by something hunting for that mistake. There's a unit
test asserting the legitimate paths stay off the list, so a future "helpful"
addition fails loudly.

**No status-code filter, unlike `scanning_ips`.** Keying on 404 would skip
the worst case: an attacker who gets a **200** for `/.env` has already won.
The response is irrelevant; the request is the signal.

**Prefix matching, anchored at the start.** One entry covers `/.env`,
`/.env.local` and `/.env.backup`; anchoring means an ordinary URL that
merely contains the string later on (`/blog/how-to-secure-your/.env-file`)
doesn't match. Query strings are already stripped by `parse_line`, so a
cache-busted probe is still caught.

**Extra paths, but no removals.** `set-probe-paths` stores a newline-
separated list in `settings` (`detect_probe_paths_extra`), appended to the
built-ins; `list-probe-paths` shows both. Entries not starting with `/`
are rejected *and reported*, because matching is anchored and a bare
`wp-config.php` would silently never fire — a detector that quietly does
nothing is the worst failure mode available. The built-ins can't be
removed individually: an admin who doesn't want them turns the whole
detector off, which is a clearer thing to reason about than a partially
disabled list.

**TTL 5 days**, matching `block-scanners` rather than spoofed-crawler
detection's 1. The difference is who gets caught by mistake: a
mis-detected crawler is a real service you want back quickly, whereas
anything requesting `/.env` has no legitimate business here at all.

## Dashboard layout: which panel absorbs a short terminal

Adding detectors grows the Scheduled-tasks panel by one row each, and with
every panel on a fixed `Constraint::Length` that pushed the *last* one —
Messages, which reports what just happened — off a 28-row screen. Fixed
heights made the least important thing the most protected.

Scheduled tasks is now `Constraint::Min(3)`: it takes the leftover space
and is the panel that clips when there isn't enough. That's the right
thing to lose (it's a status list whose content is also available from the
CLI), and everything above it, Messages included, always renders. Adding
another detector no longer risks silently hiding a panel.

## Honeypot trap path (`scanblock::block_honeypot`)

**What it does.** Blocks anything that fetches a path published only as
`Disallow:` in robots.txt and referenced nowhere else. A client can reach
it in exactly two ways: by reading robots.txt and ignoring it, or by
guessing a path that exists for no other purpose. Neither is something a
human following a link or a crawler obeying robots.txt can do by accident.

**Reuses the probe-path matcher on purpose.** Mechanically this is the
same "one request to path X is conclusive" match as
`block_probe_paths`, and it calls `accesslog::probe_path_ips` directly
rather than growing a second matcher. What makes it a *honeypot* is
external to the matching — the path being published as forbidden. It's
still its own detector, with its own toggle, cron job and `ScanKind`,
because that signal is much stronger than a generic probe and earns a much
longer TTL; folding the trap path into the probe list instead would give
it the wrong TTL and the wrong label. There's a test asserting the probe
detector doesn't also catch it.

**Off by default**, unlike the other two path detectors — not because it's
risky (it's the most precise signal here) but because it cannot fire until
the trap path is actually served. An enabled detector that can never fire
is worse than an honest off.

**TTL 30 days**, the longest of any detector. Every other one infers
intent from behaviour or from a claim that might be mistaken; this one
catches a client doing something with no innocent explanation.

**The default path is deliberately boring** (`/stop-bots-trap/`). A trap
that *sounds* valuable — `/admin`, `/backup` — would also be guessed by
scanners that never read robots.txt, converting a precise "ignored
robots.txt" signal into just another probe path. The point is that the
only way to learn this path is to read the robots.txt forbidding it.

**A path that can't match is rejected, not stored.** Matching is anchored
at the start of the request path, so a value without a leading `/` would
never fire. The CLI fails loudly and `protection::honeypot_path` falls
back to the default, rather than leaving a detector that looks switched on
and does nothing — the same reasoning as `set-probe-paths`' rejection of
unanchored entries.

## Reputation and cloud-provider CIDR feeds (`src/ipranges/reputation.rs`)

**What they are.** Six built-in third-party CIDR lists: three abuse
lists (FireHOL level 1, Tor exit nodes, blocklist.de) and three cloud
providers' published address space (AWS, Google Cloud, DigitalOcean).
Each is independently switchable; while on, every CIDR it holds becomes a
derived Block rule at render time, exactly like crawler and country
ranges — nothing is written to `firewall_rules`.

**Why a separate table and enum, not `ip_range_sources`.** Two silent
bugs were available here, neither of which would have failed to compile:

1. `Db::blocked_ip_ranges` decides whether an `ip_range_sources` row
   applies by looking up its **bot category**'s default. A reputation feed
   has no bot category, and borrowing one would tie "block Spamhaus-listed
   addresses" to "block AI crawlers".
2. `scanblock::known_crawler_ranges` iterates `IpRangeSourceKind::ALL` to
   build the *exemption* list for web-scanner detection. A feed added
   there would start **exempting** known-abusive addresses from being
   flagged — the exact opposite of the point.

So: `reputation_sources` / `reputation_ranges` tables (new `CREATE TABLE
IF NOT EXISTS`, so no migration), and a `ReputationSourceKind` that
`known_crawler_ranges` never sees.

**Why no Spamhaus DROP entry.** Spamhaus has moved its published format
more than once — the classic `drop.txt` is deprecated in favour of a JSON
endpoint — and FireHOL level 1 already *includes* DROP alongside several
other lists in one stable plain-text format. One well-maintained aggregate
beats three parsers chasing three upstreams.

**The two halves of this list are not the same kind of thing**, and the
code says so via `blocks_infrastructure()`/`warning()`. An abuse list
names addresses that *did something*. A provider list names every address
a company owns — every VPN endpoint, corporate egress, CI runner and API
integration hosted there. Real people browse from AWS addresses. That
warning is surfaced on enable in both the CLI and the TUI, not left in a
doc comment, because unlike every detector here there is no behavioural
evidence involved and a wrongly-blocked visitor has no way to tell you.
All six default to off.

**Fetching and enabling are separate steps**, so refreshing a feed you
deliberately switched off never silently re-enables it, and switching one
off keeps its downloaded ranges so turning it back on is instant.
Enabling a never-fetched feed *from the TUI* does trigger a download
(`KeyOutcome::FetchReputationSource` → `App::start_reputation_fetch`,
the same off-thread-fetch/on-thread-store split as country selection),
because enabling something with no data would otherwise look like it
worked while doing nothing. If that download fails, the feed stays
enabled-and-empty — inert, and reported — rather than having an explicit
choice silently undone by a transient network error.

**An empty parse is an error, not an empty list.** Both `update()` and the
TUI's completion handler refuse to store a zero-length result: it almost
always means the upstream format moved or an error page was served, and
storing it would silently un-block everything the feed covered. The
per-line parsers also drop anything that doesn't look like an address at
all, because one bad line in a generated firewall script makes the *whole*
script fail to apply, taking every other rule down with it.

**Panel placement.** Feeds are rows in the existing "Automatic blocking"
list rather than a fifth Dashboard panel there is no room for — they
answer the same question ("what adds firewall blocks without me doing
anything?"). `ProtectionRow::Feed(usize)` indexes into the loaded source
list, and `protection_rows()` is recomputed rather than cached so the row
count can never disagree with the data behind it. A feed's popup offers
only Off/On, with no TTL rows: its blocks are derived fresh at every
render, so there is nothing that expires.

## robots.txt generation (`nginx::robots_txt_body`, `nginx::write_managed_files`)

**What it does.** When on, `apply-blocks` writes a `robots.txt` and adds a
`location = /robots.txt` block to each site that serves it: one
`User-agent:` line per currently-blocked bot under a single shared
`Disallow: /`, plus a `Disallow:` for the honeypot trap path. The polite
layer under the 403, for the crawlers that honour it — and what makes the
honeypot work at all.

**Off by default**, because it *replaces* whatever each site already
serves at `/robots.txt`, which may be hand-written and carry rules this
project knows nothing about. That's the one genuinely destructive thing in
this feature, so it's opt-in and the message says so on both surfaces.

**Aliased from a file, not inlined with `return 200`.** The obvious
implementation — `return 200 "<body>"` — cannot work: with every AI bot
listed the body runs to several kilobytes, and NGINX's config parser
rejects a single quoted parameter past roughly 4KB. That's the same
ceiling `MAX_PATTERN_CHUNK_LEN` already exists for, and unlike the
user-agent pattern a robots.txt body can't be split across several
directives. So `BlockConfig` carries a `serve_robots_txt: bool` flag and
the block emits an `alias`; the body never appears in config text, which
also means changing the body alone doesn't churn every site's staleness.

**Grouped under one `Disallow`, not a stanza per bot.** Both are valid
robots.txt. Grouping roughly halves a file that can list well over a
thousand agents, and makes the intent readable instead of buried in
repetition.

**A robots token, not a regex.** `bot.user_agent_pattern` is an NGINX
regex fragment, often an alternation; robots.txt has no regex. The bot's
*name* is used, and only when `is_robots_token` accepts it as a plain
token — anything with whitespace or regex metacharacters is skipped rather
than emitted as a rule no crawler will ever match, since a `User-agent:`
line that matches nothing looks like coverage that isn't there.

**The trap path is published whether or not the honeypot detector is on.**
Publishing is what *creates* the trap; the detector only decides whether
hits are acted on. Publishing it only when the detector is enabled would
mean switching the detector on and then waiting for crawlers to re-read
robots.txt before it could ever fire.

**With nothing blocked the file is still valid** (`User-agent: * /
Disallow:` plus the trap), not empty — an enabled feature serving an empty
file reads as broken.

### Managed files: a new artifact class, and its lifecycle

This is the first thing this project writes that is neither a sentinel
edit inside an admin's file nor a standalone firewall script. Two rules
came out of that:

- **They live in their own directory** (`/etc/stop-bots/nginx`), not
  `/etc/nginx/`. Nothing NGINX globs lives there, so a leftover file can't
  take effect on its own — it's only ever reached through an explicit
  directive inside a sentinel block.
- **Disabling deletes the file**, it doesn't merely stop referencing it.
  A stale generated artifact left on disk invites someone to wire it back
  up by hand and serve a months-old policy. Removal treats a missing file
  as success.

`write_managed_files` runs at the start of every apply path (CLI and both
TUI apply actions), so the file an `alias` points at always exists before
NGINX reloads. `MANAGED_DIR_ENV` (`STOP_BOTS_NGINX_DIR`) overrides the
location for the end-to-end tests, which drive the real binary and would
otherwise only pass as root; it's read in exactly one place so the written
path and the aliased path can never disagree, and it's deliberately not a
persisted setting.

## NGINX rate limiting (`limit_req_zone` + `limit_req`)

**What it does.** When on, `apply-blocks` writes a `limit_req_zone` to
`/etc/nginx/conf.d/stop-bots-limits.conf` and adds
`limit_req zone=stop_bots burst=N nodelay; limit_req_status 429;` to each
site's sentinel block. NGINX enforces it at request time — the only
feature here that doesn't go through log analysis.

**The zone cannot live in the sentinel block.** `limit_req_zone` is an
`http`-context directive; the sentinel block is inside `server { }`. Hence
the separate file, in a directory the stock `nginx.conf` already globs
(`include /etc/nginx/conf.d/*.conf;`). That's the important difference
from `MANAGED_DIR`: a leftover file *there* is inert, a leftover file in
`conf.d` is **live** and keeps allocating its shared memory zone forever.

**The ordering is load-bearing, not tidiness.** A `server` block
containing `limit_req zone=stop_bots;` whose zone has been deleted is not
a degraded config — NGINX refuses to load with "unknown limit_req_zone",
so `nginx -t` fails and the *entire* reload is rejected, every unrelated
site included. So the managed-file lifecycle is split in two:

- `write_managed_files` runs **before** any config is rewritten, so a file
  the new config references always exists first.
- `remove_unused_managed_files` runs **after** every config is rewritten,
  so a file is only deleted once nothing references it.

Between the two the config on disk is valid at every point, which means an
apply that dies half way (a permission error on one file) leaves a working
NGINX rather than one that won't reload at all. In the TUI this is why
single-site apply (`a`) *never* cleans up — the other sites on the host
still carry the directive — and only apply-all (`A`), and only when every
site succeeded, does.

**`nodelay` and 429.** `nodelay` serves a visitor who briefly exceeds the
rate immediately from the burst allowance instead of queueing them;
queueing makes an ordinary page load feel broken while doing nothing extra
to a bot, which just waits. 429 rather than NGINX's default 503 because a
rate-limited client is not being told the server is unavailable, and a
well-behaved one backs off correctly when told the truth.

**Defaults: off, 10 req/s, burst 20, 10MB zone.** Off because a limit
tuned for the wrong site turns away real visitors, and unlike a
bot-pattern block there's no user agent to inspect afterwards to work out
who was caught. 10/s is deliberately generous — one page load can fire a
dozen asset requests — and burst 20 absorbs that without letting a
sustained flood through. The zone is keyed on `$binary_remote_addr`
(4 bytes v4, 16 v6) rather than the string form, fitting roughly four
times as many clients into the same memory.

**One zone-name constant** shared by the block and the file. A mismatch
between them is not subtle: NGINX refuses to start. There's a test
asserting the two agree.

The TUI offers three presets rather than a numeric entry field, for the
same reason the Dashboard's detector popup offers fixed TTLs: these
screens have exactly one interaction pattern (pick one of N), and a
free-text number would be the sole exception. The CLI takes any value. A
rate set from the CLI that isn't on the preset list still opens the popup
as *on*, at the nearest preset, never as "Off".

## Per-site path exemptions (`site_path_exemptions`, `nginx::exemption_regex`)

**What it does.** A per-site list of request-path prefixes the bot block
doesn't apply to — "block AI bots everywhere except `/blog`". Per site,
not host-wide, because a site's URL space is its own. Managed from Site
detail: a "Path exemptions" panel with a `+ Add an exempt path` row and
direct removal on Enter, the same shape (and the same
no-confirmation-for-a-reversible-action reasoning) as the Dashboard's
country list.

**Why the generated block changes shape.** NGINX cannot express "matches
this user agent *and* the path is not one of these" in one condition:
`if` takes a single condition and they don't compose. The standard idiom
is a flag variable:

    set $stop_bots_block 0;
    if ($http_user_agent ~* "…") { set $stop_bots_block 1; }
    if ($request_uri ~* "^(/blog)") { set $stop_bots_block 0; }
    if ($stop_bots_block) { return 403; }

Order *is* the mechanism — the clear has to come after every set, and the
act after the clear. There's a test asserting that ordering explicitly,
including with a chunked pattern list where every chunk sets the flag but
only one statement clears it and one acts.

**A site with no exemptions keeps the original direct-`return` form.**
Emitting the flag form unconditionally would have been simpler, but it
would rewrite the sentinel block of every already-applied site on upgrade
for no behavioural change. This is the second block shape referred to in
the `BlockConfig` entry above, and it's exactly why staleness compares
*rendered text* rather than an extracted pattern: with two possible
shapes, reconstructing one field and comparing it can't tell them apart.

**Exemptions only ever narrow an existing rule.** A config with exemptions
and nothing to block writes no block at all, rather than an empty flag
dance.

**Escaping matters more here than elsewhere.** The paths are literal URL
prefixes typed by an admin, embedded into a `^(a|b)` regex. An unescaped
`.` or `?` would quietly *widen* the exemption — and unlike a too-narrow
pattern, a too-wide exemption fails **open**, letting through exactly the
traffic the rule exists to stop. Every path goes through
`db::escape_for_nginx_regex` (now `pub(crate)`, previously used only for
manually-blocked user agents), and the regex is anchored with `^` so
`/blog` covers `/blog/post` but not `/notablog`.

**Unusable values are rejected at entry, not stored.** A path without a
leading `/` can never match an anchored regex, and one containing `"`
would terminate the quoted config string. Both are refused in the TUI with
the reason shown and the popup left open — the alternative is a
configured exemption that silently never fires, where the admin sees the
rule and sees the blocked traffic with nothing connecting the two.
`exemption_regex` filters both again rather than trusting its caller.

Ordering of paths comes from SQL (`ORDER BY path`) for a reason: an
unstable order would make the rendered block differ run to run, and every
site would read as `STALE` forever.

## robots.txt and the block are in the same phase — the implicit exemption

A bug caught only by reasoning through NGINX's request phases, because
every test here asserts generated text rather than served behaviour.

Server-level `if`/`return` (the `ngx_http_rewrite_module` directives the
sentinel block is built from) execute in the **server rewrite phase**,
which runs *before* location selection. So a user agent matched by the
block is finalised with 403/444 before NGINX ever considers the
`location = /robots.txt` sitting a few lines below it in the same block.

The consequence was that the generated robots.txt listed exactly the user
agents that could never fetch it. The polite layer would have been pure
decoration, and the honeypot's `Disallow:` line would only ever have been
readable by clients that weren't being blocked anyway.

`effective_exempt_paths` therefore adds `/robots.txt` to the exemption
list whenever the block serves it, which forces the flag form (the direct
`return` form has nowhere to put an exemption). Serving robots.txt to a
blocked crawler is also the behaviour worth wanting independently: a bot
that can read the file can learn to stop asking, whereas one that gets a
bare 403 on everything learns nothing and keeps coming back — for the cost
of one small static file.

## Testing without nginx, iptables or the network (the whole strategy)

The question this answers: how does a project whose entire job is driving
NGINX, a firewall and system logs get tested end to end on a machine that
has none of them? The policy (README "For Developers"): no mocks — a mock
tests the mock of the interface — with per-test budgets of 300ms in `src/`
and 1s in `tests/`. The mechanisms, in order of preference:

**1. The real implementation on throwaway backing.** SQLite in-memory for
every unit test, a tempdir file database for every e2e test, tempdir NGINX
roots. Nothing is faked; only the location is.

**2. Injected inputs, as real product flags.** `--ssh-log`, `--access-log`,
`--root`, `STOP_BOTS_NGINX_DIR`, `STOP_BOTS_NGINX_CONF_D` — every place the
product reads the *system* has an override, and each override is the same
one an admin with a non-standard layout would use, not a test back-door.
This pass added the last missing one: `tui --ssh-log`. Without it the
Dynamic Protection screen auto-detected the SSH log on every refresh, which
on a host without a readable `auth.log` means shelling out to `journalctl`
— measured at 0.5–7s per call. Every pty test paid it, and so did every
real refresh on such hosts; the flag fixed a product latency problem and a
test problem with one change, which is the recurring pattern here.

**3. Fake executables on PATH**, for the three tools the product actually
runs (`nginx`, `systemctl`, `nft`). Shell scripts that append their argv to
a log and exit 0 — or print a staged error and exit 1. The product's real
code executes: PATH resolution, argument building, exit-code handling,
ordering. What this bought that was previously untestable anywhere:
- `apply-blocks` *with* reload: asserts `nginx -t` runs before
  `systemctl reload nginx`, and that a failing `-t` stops the reload cold
  with nginx's own error surfaced (`tests/cli.rs`).
- The render popup's apply-after-write toggle — the one code path in the
  project that executes a generated firewall script — end to end through
  the real TUI against a fake `nft` (`tests/tui.rs`).
These are fakes, not mocks, in the sense the policy cares about: nothing in
the product knows it is under test.

**4. Golden files** (`tests/golden/`), for every generated artifact: both
firewall backends (including the Allowlist catch-all shape), the NGINX
block in plain and kitchen-sink form, robots.txt, the rate-limit zone file.
Substring assertions say a directive is present; a golden pins the exact
bytes, so reordering, a lost newline or a broken quote fails a test instead
of reaching a server. They double as the exact samples to hand to
`nft -c -f` / `nginx -t` once per change on a machine that has them —
which converts TODO's "generated syntax never validated" from a standing
hope into a bounded manual step. `UPDATE_GOLDENS=1 cargo test` regenerates;
the diff is then reviewed like code.

**The pty harness is now in-repo** (`tests/tui.rs`, on raw `libc`),
replacing rexpect. Not invented for fun: rexpect sleeps a fixed 100ms per
unmatched poll inside `expect`, and these tests make 6–20 expectations
each, which put a >1s floor under every test regardless of how fast the
app was. Measured app reality: ~150ms to first draw, single-digit ms per
keystroke round-trip, 1ms from `q` to exit. The replacement polls at 2ms,
preserves rexpect's consume-through-the-match semantics the tests were
written against, and kills the child on drop so a panicking test can't
leak a TUI holding the pty.

**Two product-level performance bugs the budgets flushed out** (the
budgets' real value — neither was visible before measuring):
- Fresh-database open took ~450ms: `init_schema`'s ~16 CREATE TABLEs each
  autocommitted, one fsync apiece. Now one transaction, one fsync (~80ms
  total open). Every CLI test paid this per spawned process; so does every
  real first run.
- `botlist::store` paid one fsync *per bot* — 700+ for a real fetch, i.e.
  seconds of pure disk waits. Now wrapped in a single transaction via the
  new `Db::batch` (BEGIN IMMEDIATE/COMMIT with rollback-on-error;
  deliberately not re-entrant, documented on the method).
  `set_cron_last_run` similarly collapsed two statements into one, which
  also made its documented "timestamp and summary are set together"
  promise actually atomic.

**Background work is seeded away, through the front door.** On a fresh
database every internal-cron job is due the moment the TUI opens, so each
pty test used to fire three real HTTP fetches (crawler ranges) and a
`journalctl` in the background. Tests now mark every job as freshly run
via the public `Db::set_cron_last_run` before spawning — real interface,
no test-only knob in the product.

**Budgets are enforced, not aspirational**: `.config/nextest.toml` flags
any unit test over 300ms or e2e test over 1s as SLOW (CI runs
`cargo nextest run`), and kills at a generous multiple so a hang fails
the build rather than stalling it. Measured after the work: unit tests
are microseconds; the slowest cli test is ~240ms; the slowest pty test
~700ms warm. The known residual is cold-binary page-in on a test suite's
first pty test (up to a few seconds on a cold cache), which is why the
kill threshold is a multiple of the budget rather than the budget.

**A false alarm worth recording**: while writing the `nft`-apply pty test,
the render popup appeared genuinely broken in the live TUI — key traced to
the handler, popup set, nothing on screen. The actual cause: the diffed
terminal only transmits changed cells, and the spaces inside a multi-word
needle land on cells that were already blank, so `"Apply after writing"`
never arrives as contiguous bytes even though every word is on screen.
The file's own older tests document this gotcha; the rule is single-word
needles, always. One real gap did fall out of the chase: no unit test had
ever *rendered* the RenderFirewall popup arm — there is one now.

## Test readability pass

Measured before changing anything: 551 tests, 13,044 lines of test code,
average 23 lines per test, 16 tests over 60 lines, and 234 assertions that
printed nothing useful when they failed.

**Shared fixtures (`src/testing.rs`).** Two setups were being hand-written
across the tree: `FirewallRule` literals (54 sites, 8 files — two of which
had already independently grown a private `rule()` helper) and the
`upsert_source` + `upsert_bot` + `set_bot_status` incantation (~20 lines,
11 sites). Now `block("10.0.0.1")`, `allow(...)`, `block_port(...)`,
`disabled(...)`, `blocked_bot(&db, slug, pattern)`. The clearest case:
nftables' IPv4-vs-IPv6 test went from 20 lines of struct literal to one
line that says what it means.

The bar recorded on the module is *the call site reads better*, not *it is
shorter* — and two categories are deliberately left duplicated: the
`NewBot` literals in `botlist/*`'s parser tests (there the literal is the
expected parse result, so a builder would hide the thing under test) and
the Dashboard's source-freshness rows (same reason). `tests/cli.rs` and
`tests/tui.rs` can't see a `#[cfg(test)]` module at all; their own local
helpers stay.

Builders take `&Db` and mutate rather than returning one — a helper that
hands back a database hides which database the test is using.

**Diagnostic assertions.** 170 assertions of the shape
`assert!(x.contains("..."))` now carry `, "x was:\n{x}"`. Verified by
breaking `block_text` on purpose: the failure prints the generated NGINX
config with `~=` visible where `~*` belonged, instead of a line number.
The first attempt at this expanded each assert to five lines — a net
readability *loss* — and was redone in the two-line form: the needle is
already on the assert line, so only the actual value needs printing.
The 61 remaining bare ones are on expressions too complex to rewrite
mechanically.

**A table instead of a run of asserts.** nftables' fixture test was six
near-identical `contains` checks; it is now a `(shape, expected line)`
table, which both reads as a list of supported input shapes and names
which shape broke.

**One test split.** `site_detail_search_and_override_a_site_from_the_tui`
(116 lines) walked through a category override *and* a bot search *and* a
bot override, so a failure localised to nothing. Split into two tests
sharing an `open_site_detail` helper. This was only affordable because pty
spawn is now ~150ms; at the old 1.5s it would have been a bad trade. The
other long tests are sequential narratives where the ordering *is* the
assertion (`rate_limit_writes_the_zone_file_and_removes_it_only_after_the_directive_goes`
is precisely about what exists at each step) and are left whole.

**A `Fixture` for the CLI tests, which closed a real hole.** It owns the
tempdir, database, NGINX root and both managed-output directories, and
sets `STOP_BOTS_NGINX_DIR`/`STOP_BOTS_NGINX_CONF_D` on *every* command it
runs. That is a safety property, not a convenience: of the ten CLI tests
that run `apply-blocks`, only two set those overrides — the other eight
were one settings change away from writing generated files under `/etc`
on a developer's machine. Both features that write there default to off,
so nothing had actually escaped; the fixture removes the footgun instead
of documenting it.

Result: 552 tests, longest 84 lines (was 116), 11 over 60 lines (was 16),
64 opaque assertions (was 234). Conventions written into AGENTS.md so the
next contributor follows them rather than inventing an eleventh helper
name — the pass found ten different names for near-identical helpers
(`test_db`, `test_db_with_bot`, `sample_bot`, `seed_bot`, `rule`,
`test_screen`, `test_site`, `test_app`, …). Renaming them all was judged
low-value churn; converge opportunistically.

## Per-site HTTP/1.x rejection

**What it does.** An optional per-site rule rejecting HTTP/1.0 and
HTTP/1.1 requests: `if ($server_protocol ~ "^HTTP/1\.")`, folded into the
same flag form as the other blockers so exemptions still apply. Stored as
row presence in `site_request_rules` (the `selected_countries` shape), a
per-site table rather than a column on `sites` because `sites` rows are
rewritten by every scan and a setting must not be lost to re-running
discovery. It shipped with a table of its own, `site_reject_http_1x`,
which the `RequestRule` generalisation below superseded and which nothing
has read since.

**The premise, and its limit.** Current browsers negotiate HTTP/2, and a
lot of scraping tooling doesn't, so this is a cheap filter. It is also the
bluntest instrument in the project, and two of its failure modes are bad
enough to be *enforced* rather than documented.

**Guard 1: only emitted in TLS-terminating blocks.** Browsers do not speak
HTTP/2 without TLS — h2c is effectively unused on the public web — so on a
`listen 80` block every single request is HTTP/1.1, including the redirect
a browser makes on its way to HTTPS. And a site's port-80 and port-443
blocks routinely share one `server_name`, which is exactly what a per-site
setting keys on. Without the guard, switching this on would take the site
off the internet.

`ServerBlock` therefore gained `is_tls`, detected while parsing from
either `listen ... ssl` or an `ssl_certificate` directive (configs express
it both ways, and neither is required to come first). `for_block()`
narrows a site's config per server block, and — importantly — both the
apply path and `site_apply_status` go through it, so a plain-HTTP block
that *correctly* lacks the rule reads as `UP TO DATE` rather than
permanently `STALE`.

Silently narrowing beats the alternatives: refusing to apply would make a
legitimate setting unusable on an ordinary two-block site, and emitting it
anyway would be an outage.

**Guard 2: `/.well-known/` is always exempt**, with no way to switch it
off. ACME HTTP-01 validation is fetched over HTTP/1.1 by a non-browser
client. Blocking it doesn't fail now — it fails at certificate renewal
weeks later, which is close to the least traceable failure this project
could ship. The same prefix carries security.txt and other
machine-fetched documents that don't negotiate HTTP/2 either.

**What no guard can fix, and why it's off by default.** Googlebot and
Bingbot crawl plenty of sites over HTTP/1.1, as do RSS readers, webhooks,
uptime monitors and most API clients. For a tool whose stated purpose is
"stop bad bots and still allow good bots" that is a real tension, so the
feature is per site, off by default, and the TUI's confirmation message
says both things that surprise people (HTTPS-only, and that it turns away
non-browser clients) rather than only the reassuring one.

**`block_text` restructured.** There are now two things that can decide a
request is unwanted — user agent and protocol version — and NGINX's `if`
takes one condition with no composition. The function now computes whether
the flag idiom is needed (`uses_flag`) and emits each reason as a
`set $stop_bots_block 1`, or keeps the older direct-`return` form for the
single-reason-no-exemptions case so a plain bot-blocking site's config
doesn't churn.

## Detectors become table-driven, and three more arrive

TODO.md recorded that adding a detector touched seven files and said to do
the descriptor refactor "before a fifth". Three were about to be added, so
it went first — and was then validated by being used three times
immediately.

`protection::Detector` is now an enum with a `DetectorSpec` (id, labels,
defaults, which log it reads). `CronJob::Detect(Detector)` and
`ProtectionRow::Detect(Detector)` replace a variant per detector, which
took `cron.rs` from 41 per-detector references to 12 and deleted four
parallel match arms from the Dashboard. Settings moved from a named struct
field per detector to keys derived from the id.

**The ids are pinned by a test.** They are live `settings` keys
(`cron_last_run:block_scanners`) and cron job ids in every installed
database; renaming one silently orphans a stored toggle *and* resets that
job's schedule so everything re-runs at once.

A visible side effect worth knowing: SSH and web scanner detection are now
Dashboard rows like everything else. They previously ran unconditionally,
with thresholds hardcoded in `app.rs` and no way to switch them off.

### The three behavioural detectors

All off by default, all sharing `scanblock::behavioural()` — and the
shared helper exists for one reason: it applies the known-crawler
exclusion. Googlebot fetches no CSS, presents several user agents and
sends no referer, so it matches all three *by design*. Without the
exclusion these would block search engines, which is the opposite of the
project's purpose.

- **Asset ratio.** Many distinct pages, not one asset. Two guards make it
  viable: *distinct* paths rather than request count (the false positive
  to avoid is an API client, which hammers few endpoints), and a `304`
  counts as a fetched asset (a returning browser with a warm cache would
  otherwise be indistinguishable from a scraper). Cannot help on a site
  that serves no assets at all.
- **Rotating user agent.** Honestly the weakest of the three: CGNAT means
  a carrier or campus presents hundreds of real browsers on one address,
  and with no timestamp parsing there is no window in which to distinguish
  that from one scraper cycling agents. A threshold is the only control
  available and pretending otherwise would add false confidence.
- **Referer-less crawling.** Weakened by `Referrer-Policy: no-referrer`
  and privacy tooling. The distinct-deep-path threshold does the work; one
  or two referer-less hits are ordinary, twenty-five are a crawl.

`parse_line` grew a `referer` field it had been parsing and discarding,
and became a named struct — `line.status` reads where `line.1` didn't.

## Request-shape rules, and why `reject_http_1x` generalised

The HTTP/1.x work had already restructured `block_text` around "a request
can be unwanted for more than one reason". `RequestRule` makes that a
list: six rules, each its own toggle, each with a `caveat()` shown next to
it in the UI (a test asserts none is empty — a bare switch with no stated
downside is the thing to avoid).

One toggle per rule rather than a "strict requests" bundle, deliberately:
if four rules hid behind one switch and an admin's monitoring broke, they
would have no way to tell which one did it.

`for_block` now filters on `RequestRule::needs_tls()` rather than a single
flag. Verified rather than assumed: only HTTP/1.x and old-TLS are dropped
in a plain block — the header-shape rules work identically over HTTP, and
dropping them there would silently disable them on a redirect block. There
is a test for each direction, and the e2e test asserts a two-block site
gets `$server_protocol` once and `$http_user_agent = ""` twice.

An unrecognised stored rule id is skipped rather than fatal, so a database
written by a newer build doesn't stop an older one applying anything.

## IPv6 `/64` and IPv4 `/24` are different things

Split deliberately, because shipping them together would mean the safe
half couldn't be enabled without the risky half:

- **IPv6 `/64` is a correctness equivalence**, unconditional and with no
  threshold. A `/64` is one LAN, one household, one mobile subscriber —
  the same thing a single IPv4 address represents. Blocking the `/128` we
  observed was the equivalent of blocking one TCP source port.
- **IPv4 `/24` escalation is a policy choice** — deliberately blocking 256
  addresses because three misbehaved — so it has a toggle, a threshold and
  an off default. Scoped to a single pass: three neighbours misbehaving
  *now* is evidence about the subnet; three over six months is a busy ISP.

Writing the `/64` test surfaced a latent bug: `add_block_rules` read the
existing-rules set once before its loop, so two addresses collapsing onto
one `/64` both got inserted. It now tracks what the pass itself adds. That
couldn't happen before — two distinct addresses were never equal — so the
widening created it.

## Choosing what a blocked request gets back

`BlockResponse` went from two options to six: 403, 404, 410, 429, 444 and
a tarpit. The stored values for the original two are unchanged (`"403"`,
`"444"`) so an installed database keeps its setting, and there's a test
pinning that — an upgrade silently changing what a live site returns would
be a bad way to find out.

**They are not five interchangeable numbers, and the UI says so.** Each
carries a `rationale()` shown beside it in the chooser, and a test asserts
none is empty. The distinctions that actually matter:

- **403** is the only option that tells a wrongly-caught human what
  happened. That is why it stays the default.
- **410** is the only one that asks a well-behaved crawler to stop coming
  back — it's a signal to drop the URL from an index permanently. For a
  tool whose main quarry is crawlers, that makes it arguably the better
  choice than 403 in many setups, which is worth saying out loud rather
  than leaving buried in a status-code table.
- **404** denies a scanner the signal that it was noticed.
- **444** is cheapest and most opaque, at the cost of being
  indistinguishable from an outage.
- **402** looks like a novelty and isn't one. It was reserved and unused
  for most of HTTP's life, and has since become the de facto "this content
  is not free" signal that pay-per-crawl schemes build on — which makes it
  the most pointed answer available to an AI crawler, and worth listing
  above the joke rather than beside it.
- **418** is the joke, included because it is a good one. Two caveats it
  carries in its own doc comment: it is not IANA-registered, so an
  intermediary that only understands registered codes may not pass it
  through cleanly, and NGINX has no canned error page for it — the client
  gets a status line and an empty body.

Adding the teapot broke one test, correctly:
`an_unrecognised_stored_response_falls_back_to_403` had used `"418"` as
its example of a value this build has no variant for. It now uses codes
that stay unrecognised, and the failure is worth recording as the check
doing its job rather than an inconvenience.

**402 was added and then removed.** It briefly carried a configurable
price and contact, sent as the response body, on the reasoning that
pay-per-crawl schemes have settled on 402 and that a bare one tells a
crawler's operator nothing actionable. That reasoning still holds; the
cost didn't. One niche status code had grown two host-wide settings, two
CLI verbs, a pair of conditionally-shown TUI rows and this project's
second free-text popup — more machinery than every other response option
put together, for the option fewest installs would choose. Removed on
those grounds, not because the feature was wrong.

`from_stored("402")` is covered by a test: a database written during that
window has to keep opening, falling back to 403 like any other
unrecognised value. That fallback is the only trace left.

### The tarpit, and why it's `$limit_rate` rather than `limit_req`

Tarpit renders as a normal `return 403` preceded by
`set $limit_rate 1;` inside the same `if`. `$limit_rate` is a writable
NGINX variable, so a few hundred bytes of default error page becomes
minutes of held connection. Cost asymmetry is the point: their connection
slot is occupied, ours costs almost nothing.

The obvious alternative was the standard nginx tarpit idiom —
`limit_req` *without* `nodelay`, which queues rather than rejects. It was
rejected for a specific reason: it needs an `http`-context `map` over
`$stop_bots_block` to scope the limiter to matched requests only, and if
that variable is ever undefined (any config where no `server` block emits
our flag form) **NGINX refuses to start**. This project generates config
onto machines it cannot test against, so between two approaches the one
that fails harmless wins: if `$limit_rate` turns out not to throttle a
body that small, the client simply gets an ordinary 403 and nothing
breaks.

That uncertainty is real and recorded in TODO.md rather than glossed: the
dwell time has not been measured against a real server, and NGINX may
write a small body in one go before the throttle engages.

Two honest costs are stated in the UI and README rather than only here: a
tarpitted client holds one of *our* worker connections too, so a flood of
them competes with real visitors for `worker_connections`; and unlike
every other option it is the *gentlest* outcome for a false positive,
which cuts both ways.

**Placement matters.** The throttle is emitted inside the same `if` as the
`return`, in both block shapes, with a test asserting exactly that and
that it appears once. `set $limit_rate` at server level would throttle
every visitor on the site.

## Container tests, and the two bugs they were built to find

A real server reported that applying a firewall script from the TUI left
SSH unreachable. Two defects came out of it, plus a third the new harness
found on its own.

### 1. The lockout guard was inert exactly where it mattered most

`App::render_firewall` matched only `LockoutStatus::Risks`:

```rust
if let LockoutStatus::Risks(risks) = assess_lockout_risk(&built.rules, None) { ... }
```

`LogUnavailable` fell straight through. On any host where the SSH log
isn't readable — not running as root, or a journald-only system where
`journalctl` returns nothing — the guard did nothing, silently, and the
script was written *and applied* (the render popup's "apply after
writing" toggle) with no warning at all.

The CLI has always printed a note and continued. That is defensible
there: a human is reading the terminal. It is not defensible on a
keypress that applies immediately, so the TUI now refuses unless
`--force`. This is the one code path in the project that can take a
machine off the network, and it was the one with no check on it.

The same call passed `None`, so the `tui --ssh-log` override added
earlier never reached the check either.

### 2. The generated robots.txt named nobody

`robots_txt_body` filtered bots on `is_robots_token(&bot.name)`. For the
well-known-bots source, `name` is humanised from the slug —
`ai-search-bot` becomes `Ai Search Bot` — and a name with spaces is not a
usable robots token, so **every bot from that source was silently
dropped**. The file was still generated and served: it forbade nobody
while looking like a working feature.

The token now comes from `user_agent_pattern`, which is the substring the
bot actually sends, correctly cased. Backslash escapes are undone
(patterns are NGINX regex fragments) and a trailing `/` trimmed.

This was found by asserting on a real HTTP response rather than on
generated text, which is the entire argument for the harness.

### What the harness is

`tests/container.rs` plus `tests/container/Dockerfile`: Ubuntu 24.04 with
NGINX, nftables and curl, and the host-built binary copied in (matching
glibc, so a container run is seconds rather than a rebuild). Ten tests
covering:

- every generated directive form through a real `nginx -t`;
- a blocked user agent actually receiving 403 while an ordinary one gets
  200;
- every block-response option as the status code a client observes,
  including `444` arriving as "connection closed, no status";
- exempt paths and `/.well-known/` staying reachable for a client the
  rules otherwise catch;
- the generated robots.txt being served, and being readable by a crawler
  it blocks;
- generated firewall scripts through `nft -c -f` and then loaded for
  real, including that re-applying doesn't duplicate rules — the
  idempotency idiom TODO.md had flagged as reasoned-through but
  unverified;
- the lockout guard refusing, and naming the admin it would cut off;
- **packets from a second container**, on a user-defined Docker network
  with its own address, failing to arrive once blocked — and arriving
  again after `nft delete table inet stop_bots`, which is the recovery
  path an admin needs.

Off by default (`STOP_BOTS_CONTAINER_TESTS=1`, or `make integration-test`),
since it needs Docker and `NET_ADMIN`. Its own CI job.

**Three things the harness taught us that no unit test could:**

- Blocking `127.0.0.1` does *not* stop loopback traffic, because the
  generated chain accepts `iif lo` before any drop rule. That is a
  deliberate safety property and now has a test asserting it, rather than
  being an assumption.
- `curl` exits non-zero against a `444`, so the harness's own status
  helper had to stop treating a failed curl as a failed test — the `000`
  is the observation.
- Tests calling `docker build` in parallel raced on the staged binary,
  producing four unrelated-looking failures that each passed in
  isolation. Guarded with a `Once`.

## Two ways the TUI corrupted its own screen (`main.rs::clear_screen`, `nginx::reload`)

Reported from a real server: the TUI came up unreadable, the shell's
scrollback still visible through it.

**`ratatui::init` does enter the alternate screen** — `try_init` runs
`execute!(stdout(), EnterAlternateScreen)`, so the first suspicion was
wrong. The bug is what happens when a terminal *ignores* that request (a
`TERM` without `smcup`, tmux with `alternate-screen off`, some SSH
clients): the old content stays on screen, and ratatui never paints over
it. Each frame is diffed against the previous one, and the very first is
diffed against a buffer whose cells are already blank — so every blank
cell of the first frame is skipped, and the scrollback shows through the
gaps. Nothing about this is visible in the *rendered* text; the widgets
are all correct.

So `run_tui` now emits an unconditional `Clear(All)` after `init`, which
is right whether or not `?1049h` was honoured.

**Not `Terminal::clear`**, which was the obvious call and is wrong here:
`ratatui-core` snapshots the cursor with `get_cursor_position()` first,
a blocking `\x1b[6n` DSR query. There is no cursor position worth
preserving before a full repaint, and on a terminal that doesn't answer
the query it fails outright — as it did immediately, in the pty test
written to cover this, with *"The cursor position could not be read
within a normal duration"*. Straight `crossterm::terminal::Clear` asks
nothing of the terminal.

**The second leak, found while looking:** `nginx::reload` ran `systemctl
reload nginx` with `.status()`, which inherits stdout and stderr. Every
other subprocess in the codebase already used `.output()`. Anything
systemctl printed went straight onto the alternate screen; worse,
non-root, polkit can spawn a `pkttyagent` that takes the terminal over
completely to ask for a password. Now captured, with stderr folded into
the error message — where it is actually readable.

**Testing it:** the assertion is on raw escape bytes in the pty stream
(`\x1b[?1049h`, then `\x1b[2J`, then the first rendered text), because
`exp_string` only scans forward — finding them in sequence is the
ordering assertion. This is one of the few places where asserting on
bytes rather than on rendered text is the point: the rendered text was
never wrong.

## Taking every blocking action off the TUI's event loop

Reported from the same server as the garbled screen: on a small machine
many actions froze the interface outright.

The loop is `draw` → `await event` → `handle_event`, so anything slow in
a handler is a frozen screen for exactly as long as it takes. Nothing was
async except four network fetches that already had the pattern.

**The rule that shaped all of it.** `Db` holds a `rusqlite::Connection`,
which is `Send` but not `Sync`, and the codebase had already settled on
"all database access on the main thread" — `AppEvent::CronLogFetched`
even documents it: *only the reading of the log is blocking enough to
move off the main thread; the parsing and the `Db` writes stay*.
Extending that beat the alternative (`Arc<Mutex<Db>>`), which would have
let a background job hold the lock across a subprocess — a freeze by
another route, and an easy invariant to violate. Every split below is the
same: resolve from `Db` on the main thread, do the slow half on the
blocking pool, fold the result back on the main thread.

**What was actually slow, in the order it was fixed:**

- `sshlog::find_default_source()` inside `DynamicProtection::refresh` —
  a `journalctl` subprocess on any host without a readable `auth.log`,
  half a second or more, and it ran on *every* reload of the screen.
  The worst of them by a wide margin.
- `nginx -t` + `systemctl reload nginx`, after an apply.
- The firewall render: a live SSH-log read for the lockout check, the
  script write, then `nft -f`.
- `nginx::discover_sites` (a walk of the whole config root) and the
  per-site config rewrites — both inside `SiteSettings::handle_key`.
- `nginx::site_apply_status` in `SiteSettings::refresh`: one config file
  read and one block re-render per site, per change to that screen.

**Cheaper than async, and done first:** `refresh()` reloaded all four
screens on every mutation and threw three of them away unlooked at.
Toggling a category default on the Dashboard re-read the SSH log and
re-listed ~700 bots. The other three are marked stale and reload when
each next comes into view, driven from the draw loop so every route into
a screen is covered. Deferring is safe by construction rather than by
judgement: a screen's cached state cannot be observed before it is drawn.

**Widening the `KeyOutcome` boundary.** Everything above except the last
two was work `App` already owned. The scan and the applies were not:
`SiteSettings::handle_key` performed them itself and returned
`ReloadNginx` afterwards. So the screen now returns
`KeyOutcome::SiteAction` as *data*, and `App` plans it against `Db`,
performs it on the blocking pool, and hands the outcome back through
`finish_apply`/`finish_scan`. `nginx::write_managed_files` and
`remove_unused_managed_files` grew resolve/perform pairs for the same
reason; both still exist unchanged for the CLI, which wants them in one
go.

**Dedupe versus coalesce, which is not a style choice.** One in-flight
set (`App::jobs_in_flight`) both animates the spinners and stops the same
work starting twice. Dropping a duplicate is right for a *read* — a
skipped SSH-log re-read only means slightly stale display, and the 30s
timer catches it. It is wrong for anything shaped write-then-act, where
the act has to happen at least once after the last write:

> Apply site A. Its reload starts. Apply site B while it is still out —
> the file is written, the reload is dropped, and NGINX never picks B up.

That is a silent wrong answer, and worse than the pause being fixed. The
reload holds a pending flag instead, which the finishing reload consumes.
The site status check needed the same treatment for the same reason:
nothing else would ever catch up, so the tags would keep describing the
settings from before the change. The firewall render is the exception —
it is only reachable by confirming a popup, so a second request is
*reported* rather than coalesced (and coalescing would mean deciding
which of two output paths wins).

**The safety property that must not be optimised.** `render_firewall`'s
lockout check reads the SSH log live, every time. `App::ssh_log_text` —
the cached copy Dynamic Protection draws from — must never reach it. The
free function that runs on the worker only ever receives the *path*, so
there is no way to pass it the cache by accident.

**Saying so on screen.** The footer is the only line drawn on every
screen, and `App::message` only ever appeared on the Dashboard — so an
admin applying from Site settings had nothing telling them the TUI was
waiting rather than idle. It now names the running job with a braille
spinner, sorted so which of several gets named doesn't flicker.
`spinner_frame()` reads wall-clock rather than a per-widget counter,
which both costs no plumbing and keeps every spinner on screen turning in
step. The site status tags show `CHECKING` rather than the previous
answer, because the moment they are most read is right after an apply —
exactly when the old answer is wrong.

**Testing non-blocking, without timing.** The pty harness gets a fake
`systemctl` that parks until the test deletes a gate file. The TUI then
has to switch screens and draw *while it is parked*; a synchronous reload
cannot, because the keypress would sit in the queue until `systemctl`
returned. Ordering, not timing — no sleeps, nothing that degrades on a
loaded machine. The same harness proves the coalescing: two applies with
the gate held across both must produce two `systemctl` calls. Both tests
were checked by reverting their fix and watching them fail.

One thing this exercise re-taught: a long literal needle is a bad pty
assertion across a screen switch. Ratatui skips any cell that already
holds the right character, so `"Top IPs attempting SSH"` arrives split
around whatever the two screens have in common at the same column, while
`"Top IPs"` does not.

## Batch mode (`src/batch.rs`, `stop-bots batch`)

"A batch mode that can run from crontab that simply updates all lists,
scans the logs, creates the updated blocks and applies them."

The last four words are the whole design problem. Everything else in
this project is *generate-only* on purpose — `src/iptables.rs` and
`src/nftables.rs` both say so in their module docs, `cron.rs` says an
internal cron that silently executed firewall changes "would be a very
different, much riskier feature", and the README promises "generated,
never applied automatically". This is the one thing that breaks that,
so it breaks it on purpose and only when asked.

**`--apply` is a flag, and the default is unchanged.** Without it,
`batch` writes NGINX config and a firewall script and stops. Both are
inert: config does nothing until a reload, a script does nothing until
it is run. Anyone who wants the old guarantee just doesn't pass the
flag, and the tests assert that shape rather than assuming it.

**The lockout guard refuses on "could not run", not only on "no".**
`render-firewall` prints a note and continues when no SSH log is
readable, which is defensible with a human at the terminal — and is the
exact hole that, in the TUI, wrote *and applied* a script that took a
server off the network. From crontab there is no human, so
`LockoutStatus::LogUnavailable` under `--apply` is a refusal: non-zero
exit, and **nothing written**, not merely nothing applied. This is why
batch does not reuse `main.rs`'s `check_lockout_risk`, which encodes the
interactive policy.

`--ssh-log` matters more here than anywhere else and the CLI help says
so: cron runs as root, so `/var/log/auth.log` usually reads fine, but on
a journald-only host `journalctl` under cron can come back empty — which
is precisely the refuse case, so the run would fail nightly for a reason
that looks like nothing.

**Two independent planes.** NGINX config and the firewall script are
separate mechanisms. A failed NGINX reload must not stop the firewall
half and vice versa, so they are the last two steps and neither is
conditional on the other. Same rule one level down: one step's failure
never aborts the run, every step reports its own outcome, and the exit
status is non-zero if any failed — which is the only thing that makes
`cron` mail anyone.

**Quiet on success.** `cron` mails the owner whatever a job prints, so a
nightly run that says nothing is a nightly run nobody has to read.
`--verbose` prints a line per step, which is what a first run by hand
wants; the README says to start there.

**Scope of "all lists".** Bot lists and crawler IP ranges refresh in
full — three of each, all small, and everything depends on them.
Reputation feeds and country ranges refresh only where switched on or
selected: fetching AWS's published address space for a feed nobody
enabled is megabytes for nothing.

**`--no-fetch` is not just test scaffolding.** Bot lists change weekly;
an access log changes every second. A nightly full run plus a
ten-minute `--no-fetch --apply` is the pattern the README shows, and it
happens to be what makes the module testable offline.

**Shared schedule state.** Each step stamps `Db::set_cron_last_run`
under the same key the TUI's internal cron uses. Deliberate, and it
could have gone either way: it means an admin running both gets one
detection pass rather than two, and the Dashboard's "Scheduled tasks"
panel reports what the *real* cron did instead of claiming everything is
overdue.

**Two lifts, so nothing forked.** `scanblock::run_detector` is now the
one place a `Detector` maps to its implementation, so a detector added
to `Detector::ALL` and forgotten fails to compile rather than silently
never running from one of the two schedulers. `nginx::apply_all_sites`
moved out of `main.rs`, which had real logic in it — the dedupe by
config file, and the write-generated-files-before / delete-unreferenced-
after ordering that is load-bearing because deleting a rate-limit zone
another site still references makes NGINX refuse to load at all.

**One defect found in review, worth recording.** The access-log tally
was keyed by the literal string `"batch"` rather than by the log's path.
That key is where `Db` remembers how far into the log has already been
counted, so batch would have re-tallied the whole log on its first run
and then double-counted every line for as long as anything else read the
same log — and the number it inflates is the hit count Dynamic
Protection shows an admin deciding whether to block a user agent. It now
uses the same `access_log.unwrap_or(DEFAULT_LOG_PATH)` key every other
caller does, with a test that fails on the old behaviour.

**Testing.** The refusals are asserted in `tests/cli.rs`, offline via
`--no-fetch`, including that nothing was *written* — and the
log-unavailable one was checked by disabling the guard and watching it
fail. `--apply` itself can only be proven in `tests/container.rs`: real
`nft`, and a real HTTP request to an NGINX that has genuinely been
reloaded. That needed a `systemctl` shim in the image, since a container
has no init system — the same substitution the harness already made by
calling `nginx -s reload` by hand, now available to the code under test
so `--apply` can be exercised as the single command an admin runs.

## Usability pass before launch

Done by *looking*: every screen rendered to a `TestBackend` at 100x32 and
80x30 and read as a first-time user would, plus the CLI's help and error
paths run by hand. Reading the source would not have found most of what
follows — several items are only visible as pixels.

**What a fresh install actually looked like.** Four panels of zeros and,
in the Summary, "Firewall rules: needs updating (press f to update)".
Pressing `f` on a database with no rules renders an empty script, which
looks like the tool doing nothing — so the one piece of guidance a new
user got pointed the wrong way. That row now has three states, and at
zero it points at the Automatic blocking panel instead. Dynamic
Protection was two empty bordered boxes with no text at all; an empty box
reads as "broken", and on that screen empty is usually the *good* case.
Site settings already had the right pattern — *"No sites discovered yet.
Press r to scan /etc/nginx"* — so the fix was to copy it, not to build an
onboarding wizard.

**Two clipping bugs, both from hardcoded widths.** The firewall render
popup was `width = 56` against a 57-character key hint, so it printed
"Esc ca" and stopped; a longer output path would have gone the same way.
Dynamic Protection's panel titles ran past the border at 80 columns, the
width the README documents as the minimum. Both now size to their
content, and the titles drop their key hints rather than truncate — the
panel's name and the active filter are what has to survive, and the hints
are in `?` anyway.

**`--help` was the front door and it was a wall.** Clap uses the first
paragraph of a doc comment as the short help, and twenty subcommands had
no paragraph break — `block-scanners` presented **931 characters** as its
one-line summary. Adding a blank line was not enough, because several
first *sentences* were already 200+ characters; each needed a real
one-line opener written above the existing text. The long form is
unchanged under `<subcommand> --help`.

**A mistyped `--root` reported success.** `discover_sites` deliberately
swallows walk errors, which is right for an unreadable file inside a real
tree and wrong for a root that does not exist: the second reported
"Discovered 0 site(s)", indistinguishable from a correct run against a
server with no sites. Now separated. This is also the rare case where the
existing test asserted the *bug* — `scanning_a_missing_root_finds_nothing_
without_crashing` pinned the old message — so it was rewritten rather
than deleted, keeping its real point (the failure must arrive as a
message, never propagate and tear down the TUI).

**`--version` did not exist**, on a project that ships tagged release
binaries. It is also in the TUI header now: the TUI is where someone is
standing when they decide to report something, and "which build is this?"
is the first question back.

**One duplication found by looking rather than grepping.** Choice popups
had two implementations, one in `dashboard.rs` and one in
`site_settings.rs`, and only the first grew an `Esc cancel` hint. Now one
shared `render_option_list`.

**Deliberately not done.** No wizard, no first-run tour: the empty states
plus the existing per-screen hints are the onboarding, and a tour is a
thing to maintain. The Geo-blocking panel's blank rows are cosmetic and
left alone.

**Test fallout is expected here, not a regression.** Changing what a
screen says breaks tests that assert on what it said — and two of those
had pinned wording this pass exists to change.

## Code health pass before launch

Measured first, because "readability" invites rewriting whatever the reader
last touched. What the numbers said: no dead code, `-D warnings` clean, and
the longest real functions are 100–140 lines of inherently-dispatchy `match`.
So the debt was not function length, and the pass did not chase it.

**The `db.rs` split was considered and rejected — again, and this time
written down properly.** It is the obvious lever (2,400 lines of code across
fourteen concerns) and the wrong one. `Db` is one struct wrapping one
connection, so the mechanical version spreads `impl Db` blocks across files:
2,400 lines moved, none of them easier to read, and the `// ---- section ----`
banners already give exactly the navigation a split would. The version that
would genuinely help — per-concern types — is a design exercise, not a
tidy-up. A no-behaviour-change diff of that size is an expensive way to make a
launch riskier.

**The biggest actual finding was `TODO.md`.** It carried open items, a
history of everything shipped, and design reasoning all at once, and the
history had outgrown the todos — so real open work was buried inside the
"Done" section as parenthetical asides: `App::message` only ever rendering on
the Dashboard, no CLI verb for category defaults, `set_firewall_rule_enabled`
tested but unwired. For a repo about to be public, a todo list you can't find
the todos in is worse than a long source file. Now open work only; the history
is in the changelog and the git log, the reasoning in this file. Every
remaining claim was re-checked against the code — one had been fixed this
session and was removed.

**Then the code written this session, which was the only code that hadn't had
a readability pass.** Two things came out of it:

- **The `start_`/`finish_` family had drifted.** The `finish_` half had
  converged on one name shape; the `start_` half was `start_`, `check_`,
  `read_`, `reload_` and `render_` for the identical pattern — so the app's
  central mechanism, and the reason the TUI never blocks, was invisible to
  anyone reading down the file. All eleven are pairs now, named for the work
  rather than the verb: `start_nginx_reload`, not `reload_nginx`, because it
  does not reload anything, it starts a reload and returns. The tense was the
  actual bug in those names — each promised to do the thing.
- **`site_settings.rs` had grown a second `impl SiteSettings`**, an artifact
  of how the plan/run/finish methods were added rather than a distinction
  worth keeping. Folded back in.

**Three pedantic lints are wrong here and are now recorded as rejected** in
`AGENTS.md`, so the next reader doesn't "fix" them: `unnecessary_wraps` and
`unused_self` both fire on members of deliberately uniform families
(`handle_*_key`, `render_*`, `start_*`), where breaking three out of a family
of eight costs more than the `?` it saves; and `missing_errors_doc`/`must_use`
earn their keep on a published library API, which `src/lib.rs` explicitly is
not.

One caution worth keeping: `clippy -W clippy::pedantic` prints a *summary*
rather than one warning per site, so grepping its output for `clippy::` finds
nothing and looks like a clean run. It isn't; check before trusting silence.

## Test coverage, measured

93% of lines (`cargo llvm-cov --summary-only --workspace`), and an
understatement: the container suite runs a binary inside Docker, so its
coverage never comes back.

Worth recording *how* the gap was found, because the percentage alone
would have sent the work to the wrong place. Pulling the uncovered line
ranges rather than the per-file percentages showed the misses were not
spread thinly — they clustered almost entirely into one cause: **every
code path that makes an HTTP request**, because no test here touches the
network. `app.rs` sat at 74% not because it was under-tested but because
six of its methods were downloaders.

Two things closed most of it.

**The `finish_` half of every fetch is testable as-is.** Each takes the
same `Result<T, String>` its background task would have sent, so a
synthetic payload exercises it exactly as the real event does — and it is
the half where the decisions live: what gets stored, what the admin is
told, what happens on failure. Nine tests took `app.rs` from 74% to 85%.
The `start_` halves are a spawn and a message; there is not much there to
get wrong.

**`--source <file>` on the three downloaders that lacked it.** The
pattern already existed on `update-bot-lists`, where it is a real feature
(a host with no outbound access) that happens to make the parser
testable. Extending it to crawler ranges, country ranges and reputation
feeds needed one genuine split — `ipranges::store_country`, separating
parse-and-store from fetch, exactly as `store` was already separated from
`update` — and covered both feed formats (a plain `.netset` and a
provider's JSON) offline.

**Where the line is drawn, deliberately.** What remains uncovered is the
spawn itself: four `App::start_*` methods, `parse_off_thread`, and
`batch`'s `update_lists`. Covering those means an injectable base URL and
a local HTTP server, which tests `reqwest` rather than this project. The
`--source` overrides are the better answer to the same question, and they
ship as a feature rather than as scaffolding.

## Configurable NGINX test and reload commands (`nginx::NginxCommands`, `set-nginx-commands`)

`test_config` ran `nginx -t` and `reload` ran `systemctl reload nginx`, both
hardcoded. That is right for a host install and wrong for the deployment that
prompted this: NGINX in a container, with its config on a bind mount this tool
writes to. The files are ours to edit, but there is no unit to reload, and the
host's `nginx -t` — if it exists at all — validates a different config than the
one the container will read.

Two settings, `nginx:test_command` and `nginx:reload_command`, defaulting to
exactly what every caller got before. `NginxCommands::from_db` resolves them on
the main thread; the blocking half receives the resolved argv, because by the
rule in `app.rs` that half cannot reach a `Db`.

**The command is never handed to a shell**, and that is the security-relevant
decision rather than a stylistic one. `split_command` handles whitespace and
quoted arguments and nothing else; `;`, `|`, `&&`, globs and `$VAR` stay
ordinary characters inside a word, with a test asserting it. This program runs
as root, and the settings table became reachable from a web UI in the same
release — `sh -c` here would have turned a settings row into arbitrary code
execution.

**A stored command that no longer parses is an error, not a fallback.** Quietly
reloading the host's NGINX because the container command had an unbalanced
quote is the precise surprise worth failing over. `set-nginx-commands` parses
before it stores, so the rejection lands while a human is watching rather than
at the next cron run.

Tested through the existing fake-executables harness, with `docker` added to
it. The assertion is on the whole call log, so a fallback to the host's `nginx`
or `systemctl` fails the test rather than passing unnoticed.

## Installing as a service (`src/install.rs`, `stop-bots install web`)

Everything else in this project writes a file and stops. This writes a unit,
reloads systemd and starts a daemon, so it is the one module whose mistakes
are not undone by editing a file back. Three rules follow, and they are why
it is a module rather than forty lines in `main.rs`.

**Every path is a field on `Layout`.** Nothing reads a constant at the point
of use, which is what lets a test point the whole installer at a temp
directory and assert the bytes it produced. `Layout::under` builds each path
by joining a *relative* path onto the prefix, because `Path::join` with an
absolute path discards the prefix — the mistake that would send a `--prefix`
install to the developer's real `/etc`, and the reason there is a test
asserting every field stays inside.

**Nothing is written until every check has passed.** `preflight` runs in full
first: systemd (`/run/systemd/system` exists — a `systemctl` binary on `PATH`
proves only that the package is installed, which is true inside a container
that is not running systemd), Debian, the binary is a file, and the unit
directory is writable. Writability is checked by writing, not by comparing
euid to 0: what matters is whether this process can write there, and
root-in-a-container answers that differently from `id -u`. A check that fails
after the directories exist leaves a half-install, which is worse than no
install because it looks finished.

**It refuses rather than overwrites.** A unit that exists and differs stops
the run unless `--force`; byte-identical is a no-op, which is what makes
re-running safe. An operator who edited `ExecStart` made a decision.

`is_build_artifact` refuses a binary under `target/debug` or `target/release`.
`sudo cargo run -- install web` would otherwise resolve `current_exe()` to a
path that works until the next `cargo clean`, with nothing warning when it
stops.

### Why the service runs as root

Because the console rewrites `/etc/nginx`, writes `/etc/stop-bots/firewall.nft`
and runs `nginx -t` and `systemctl reload nginx`. There is no unprivileged
split that leaves the feature set intact; dropping privilege would mean the
web UI silently losing the ability to apply anything.

The hardening in the generated unit is what survives that. `ProtectSystem=full`
would make `/etc` read-only and break the first NGINX apply — an hour after
the unit started cleanly — so it is `ProtectSystem=yes`, covering `/usr` and
`/boot`. `CapabilityBoundingSet=` is deliberately not set: root's ability to
write a file it does not own *is* `CAP_DAC_OVERRIDE`, so trimming the set is
how you get a service that starts and then cannot write NGINX config.
`MemoryDenyWriteExecute=` is safe in principle for a Rust binary with no JIT
and is left off because nobody has run the unit with it on — an untested
sandbox directive is not hardening. `systemd-analyze security` scores the
result 5.8 (MEDIUM), up from 7.8 (EXPOSED) before the additions.

### Settings do not go in the unit

`ExecStart` carries `--db` and `--root`, which are paths. The bind address,
host allowlist, path prefix and exposure flag go to the `settings` table,
because the running server re-reads them on every request — a flag in
`ExecStart` would be a second source of truth that loses to the database on
the next restart. The unit says so in a comment, so the next person to add a
flag reads the reason first.

`--ssh-log` used to be in that list, defaulted to `/var/log/auth.log`, and it
is the one that went wrong in production. Debian 12 dropped rsyslog from
default installs, so on a current Debian host sshd logs only to the journal
and that file does not exist. An explicit `--ssh-log` deliberately skips the
`journalctl` fallback in `sshlog::find_default_source` — it means "read this,
not whatever you can find" — so the service read nothing at all. The visible
half was a permanently empty SSH panel in the console. The expensive half was
silent: the brute-force detector runs inside that same service and inherits
the same path, so on the host most exposed to this traffic nothing was ever
detected or blocked. Neither surfaced as an error, because an unreadable log
is "could not check" rather than "checked and clear" — the right call
everywhere except when the path was a guess the installer made.

So the installer now names no SSH log unless the operator passes one.
`Layout::ssh_log` is an `Option`, `None` by default, and the flag reaches
`ExecStart` only when set. Two tests hold the line: one asserts a default unit
contains no `--ssh-log`, the other that an explicit path still arrives. The
general rule this is an instance of: a default that encodes a guess about the
host belongs at the point of use, where it can be retried and fall back, not
frozen into a unit file at install time.

### How it is verified

The unit is a golden file (`tests/golden/stop-bots-web.service`), built from a
`Layout` with no temp directory in it so the golden is the bytes a real Debian
host gets. Golden rather than substring assertions because the failure that
matters is a directive quietly changing meaning.

`activate` — the half that actually starts a daemon — is covered by pointing
`Layout::systemctl` at a script that records its arguments, asserting the exact
calls and their order. Injected into the layout rather than put on `PATH`,
because `PATH` is process-global and would race a threaded test runner; it is
also the same shape `NginxCommands` already uses for the configurable NGINX
commands. Without it that function had no coverage at all, since every other
test goes through `--prefix`, which skips systemctl entirely.

`systemd-analyze verify` parses the generated unit — that is what catches a
misspelled directive name, which a golden file cannot. Running it under a real
system manager needs root and has not been done here; the sandbox directives
were smoke-tested with `systemd-run --user`, where every one a user manager can
apply ran the binary fine, and the three it cannot (`ProtectClock`,
`ProtectKernelModules`, `ProtectKernelLogs`) fail identically for `/bin/true`,
which is a user-session limitation rather than anything about this unit.

## Web UI (`src/web/`, `stop-bots web`)

A third front-end over the same core as the CLI and the TUI. Nothing under
`src/web/` knows how to block a bot: `nginx`, `firewall`, `dynamic`,
`protection` and `cron` already carry every decision this project makes,
because the CLI and the TUI both needed them.

### Why a password on a loopback-only server

The bind default is `127.0.0.1:8787`, and "bound to loopback" is not the same
as "only reachable by the admin". Two ways in that need no network access:

- **Every local user on the box** can open it — a shared host, a CI runner,
  anything else running there.
- **The admin's own browser.** A page on any origin can POST to loopback; a
  form post needs no readable response, so same-origin policy does not stop it.
  DNS rebinding removes even that limit, by making a hostile name resolve to
  127.0.0.1 — at which point the attacker's page *is* same-origin.

So four guards, in this order: a `Host` allowlist, security headers, the
session, then CSRF. The allowlist is specifically the rebinding defence — an
attacker's page cannot change the `Host` header the browser sends, so a request
arriving as `evil.example` is one that got here by having that name point at
us, and is refused before any handler runs. Loopback names are allowed without
configuration; anything else has to be listed, which is the price of putting
the console on a hostname.

Argon2id for the password, generated on first run and shown once. Generated
rather than prompted: nobody picks a good password for a service they are about
to leave running. Sessions live in memory, so a restart logs everyone out —
for a process that rewrites firewall rules, that is the safer default and the
cost is one login.

The stored hash is a PHC string, and it has to outlive the library that wrote
it. Upgrading `argon2` 0.5 → 0.6 moved the whole hashing API — `SaltString` and
the b64 encoding step gone, `hash_password` no longer taking a salt,
`PasswordHash` moved under `phc` — and every test in `web::auth` kept passing
throughout, because each of them hashes and verifies inside one process with
one version. None of them could have caught a release that stopped reading what
is already on operators' disks; the symptom would have been an operator locked
out of the console governing their own firewall, found after deploying.

So `a_hash_written_by_the_previous_argon2_still_verifies` freezes a string
generated by the *old* version and asserts the current code accepts it, and
rejects a wrong password against it. Regenerate that fixture only from the
version that wrote it. A fixture produced by the code under test asserts that
the code agrees with itself, which is the one thing never in doubt. The default
cost parameters were identical across the upgrade (m=19456, t=2, p=1), so the
OWASP figures quoted elsewhere in this document still hold.

### Exposure is opt-in twice

A non-loopback bind needs `--expose` (or the `web:expose` setting) on top of
`--bind`. The refusal names the SSH tunnel as the alternative, because that is
the recommendation: `ssh -L 8787:127.0.0.1:8787 host` gets a remote admin to
the console without putting it on the network at all.

### Threading

`Db` wraps a `rusqlite::Connection`, which is `Send` but not `Sync`.
`AppState::with_db` is the only door to it, and enforces the same rule `app.rs`
follows for the TUI's event loop: the work happens inside `spawn_blocking`, and
the mutex guard never crosses an `.await`.

A `std::sync::Mutex` rather than a `tokio::sync::Mutex`, deliberately. A tokio
mutex exists to be held across `.await`, which is exactly what must never
happen here — `rusqlite` blocks its thread, so a guard held across a suspension
point would stall the runtime. The std guard is not `Send`, so the mistake is a
compile error at the point someone tries to make it.

A connection pool was the other answer and is the wrong one: SQLite serialises
writes anyway, and a second connection buys contention handling for a workload
that is one operator clicking buttons.

Each screen reads its whole view in **one** `with_db` call. Every call is a
`spawn_blocking` hop and a lock acquisition, and a page assembled from a dozen
of them can show two halves of two different states. The exception is a bot-list
update, which fetches *outside* the lock and takes it only to store — a network
request under the single lock would stall every other request in the console for
as long as the publisher takes to answer.

### The internal cron (`src/web/cron.rs`)

The web server ticks the internal cron for as long as it runs, the same as the
TUI. See "Internal cron" above for the shared-schedule design; what is
web-specific is here.

`cron::spawn` is called from `server::serve`, **not** from `router`. The
integration tests drive `router` directly hundreds of times, and a spawn there
would start that many background tasks ticking against tempdir databases. Tests
of the cron call `web::cron::tick` instead.

The TUI splits every job into a start/finish pair routed through its event loop,
because `Db` is not `Sync` and its handle lives on the drawing thread.
`with_db` already is that door, so here a job is an `async fn` that awaits its
halves in order — which is why this file is a fifth the size of the equivalent
in `app.rs`.

The one rule `with_db`'s signature cannot enforce, and this file keeps by hand:
**the log read happens outside the lock.** Resolving the SSH log can shell out
to `journalctl`; doing that inside `with_db` would hold the database against
every in-flight request for its duration. `cron::read_log_for` takes no `Db`
precisely so that stays possible. `UpdateIpRanges` follows the same shape for
the same reason, with three remote round-trips in place of the log read.

Jobs run sequentially. They share one database behind one mutex, so concurrency
would buy lock contention and two detectors writing blocks at once. A failing
job is reported to stderr and the pass continues — a cron pass that gives up on
the first unreadable log is one that stops doing its other jobs forever.

`AppState::firewall_out` exists because `firewall::DEFAULT_OUTPUT_PATH` is a
real path under `/etc`: a test driving a tick, or a server started by hand, must
be able to point the `RenderFirewall` job somewhere else. Same reasoning as the
`out_path` parameter the TUI's equivalent has always taken.

The first tick runs immediately rather than after a minute's sleep, matching the
TUI's backdated `last_cron_check`. On a fresh install that means `stop-bots web`
fetches the three crawler-range sources and writes a firewall script within a
second of starting — deliberate, and the same thing opening the TUI has always
done, but worth knowing before running it on a host with no outbound access.

### The anti-lockout guard

`firewall::assess_lockout_risk` protects SSH. The web UI needs the same guard
for a sharper reason: blocking the address your own browser is connected from
takes away the console you would use to undo it, and unlike SSH there is no
second way in that this tool is not also managing.

The address compared against is the socket peer, or the leftmost
`X-Forwarded-For` entry when the peer is loopback **and** the operator has set
`web:trust_forwarded_for`. Both conditions, not either: a forwarded header is
client-supplied text, and believing it unconditionally would let anyone switch
the guard off from outside by claiming to be the address they are about to
block. A `None` client address means the block goes ahead — refusing every
block because the address is unknown would make the tool useless in exactly the
deployment where it is most wanted.

### What the UI will not do, and why

- **Apply the firewall script.** It writes it; running it stays manual. A
  written script is inert, and putting the one operation that can take the host
  off the network a single click away in a browser is not a trade worth making.
  The lockout guard still runs at write time, because the script is written to
  be run later, by which point nobody is watching.
- **Unblock a row a downloaded list blocked.** The next refresh of that list
  would silently undo it, so the button is not offered — the honest place to
  change it is the bot's own setting.
- **Change the password.** A console whose password can be changed by whoever
  is already looking at it gains nothing from the change.

### Choice of stack

axum, maud, and vendored htmx; no build step and no JavaScript toolchain.
`reqwest` already brings `hyper`, `http` and `tower`, so axum costs about four
net crates. maud checks the HTML at compile time and escapes by default, which
matters on screens where every bot name and user agent is attacker-supplied
text.

htmx is checked in with its digest recorded rather than linked from a CDN. An
administration console for a server under attack should not let a third-party
origin execute code in the page that rewrites the firewall, and it has to keep
working on a host with no outbound access — the same constraint `--source`
answers everywhere else.

### Layout: two columns, and tables that scroll

Every screen wraps its panels in `.cols`, a grid that is one column by
default and two above 1040px. One column is the default rather than the
exception, so a narrow window and a phone need no special case, and adding
a panel needs no decision about where it goes. `align-items: start` is what
stops a two-row panel being stretched to the height of the table beside it.

`main` is 1440px wide rather than 1180px, which is what makes two columns
worth having on a laptop without turning a single panel into a 2000px line
of text on a desktop monitor.

The two Dynamic Protection tables are as long as the logs make them —
hundreds of rows on a server that is actually being scanned — so they are
capped at twenty rows (`--table-rows-visible`) and scroll inside their
panel, with the header stuck to the top. Twenty is the cap for a row
carrying an action button, which is the tall case; a table of rows that
offer no button — everything a downloaded blocklist blocked — is shorter
per row and shows a few more before it scrolls. It is a `max-height`, so
either way it degrades into "about twenty" rather than cutting a row in
half. Without the cap the two tables
could not usefully sit side by side: one would start a screen below the
other.

The cap is a `max-height` computed from `--table-row-h`/`--table-head-h`,
which are derived from the `td`/`th`/`button` padding above them in the
same file and have to be changed with it. Measuring the real row height
would mean a second inline script and a second CSP hash, which is not worth
it for a cap that is a design choice rather than a correctness property.

It does mean rows have to be a predictable height, which is why a user
agent in a scrollable table is truncated with an ellipsis rather than
wrapped — a wrapped one is three rows tall, and twenty of them is not
twenty rows. The whole string stays in the document as the cell's `title`,
and there is a test for that, because truncation that loses information is
a different feature from truncation that doesn't.

### CSP and inline handlers

The Content-Security-Policy is `default-src 'none'` with `frame-ancestors
'none'`, and allows the one inline script by SHA-256 hash, computed at startup
from the script itself rather than pasted in — a hash written down by hand goes
stale the first time someone edits the script, and the symptom is the theme
toggle silently doing nothing in browsers that enforce CSP.

That hash does **not** cover inline event handlers: `onclick` and `onchange`
need `unsafe-hashes`, which is the hole hashing was meant to avoid. The first
draft used both and would have shipped a theme toggle and a set of dropdowns
that did nothing in any enforcing browser. Handlers are now attached from the
hashed script, the selects use one delegated `change` listener, and their
submit buttons are always rendered rather than hidden inside `<noscript>` — the
auto-submit is an enhancement, and a control that silently does nothing without
script is worse than one extra button. `tests/web.rs` asserts that no page
carries an inline handler.

### `crate::dynamic`

Lifted out of `tui/dynamic_protection.rs` when the web UI needed the same
answers, for the reason `scanblock` and `accessstats` were lifted out before
it: whether an address counts as blocked is product behaviour, not
presentation, and two front-ends computing it separately is two front-ends that
will eventually disagree. What stayed behind is lists, selection and key
handling. Its tests moved with it.

### Testing

`tests/web.rs` drives the assembled router with `tower::ServiceExt::oneshot` —
the whole middleware stack runs, without binding a port. There are no mocks:
the database is real SQLite on a tempdir and the password is really hashed and
verified.

Argon2 at OWASP-default cost takes ~2s in a debug build, which blew every web
test's budget and starved the rest of the suite of CPU badly enough that
unrelated tests were killed. Fixed with `[profile.dev.package.argon2]
opt-level = 3` (and blake2), not by weakening the parameters — the cost
parameters are what the tests should be exercising, and a test that hashes with
settings the product never uses is a test of nothing. 4.8s to 1.1s, and no
nextest overrides needed.

### Serving under a path prefix (`web::BasePath`, `--base-path`)

The first version generated root-absolute URLs everywhere — about seventy of
them across `href`, `src`, `action`, every `Location` header and the session
cookie's `Path`. That works for a subdomain and cannot work for
`https://example.com/stop-bots/`, in either proxy configuration:

- `proxy_pass http://127.0.0.1:8787;` (prefix preserved) — every request 404s,
  because the router had no `/stop-bots/*` routes.
- `proxy_pass http://127.0.0.1:8787/;` (prefix stripped) — the first request
  works and nothing after it does. The page comes back referring to
  `/assets/style.css`, `/bots`, `/category`; the browser resolves those against
  the domain root, outside the `location` block, and they 404. The
  post-login redirect to `/` walks the browser out of the console entirely.

**The prefix must survive the proxy.** That is the decision everything else
follows from: this server matches the full path *including* the prefix and
generates links that do too, so `proxy_pass` must have no trailing slash. The
other arrangement — proxy strips, server serves from the root — is not
implementable from the server side at all, because what breaks it is the
browser's resolution of paths in the returned HTML.

`BasePath` normalises `stop-bots`, `/stop-bots` and `/stop-bots/` to
`/stop-bots`, and rejects `..` and URL punctuation. That validation is not
theatre: the value is concatenated into every URL and every `Location` header
the site emits, and a prefix able to climb out of itself is not a thing to
discover later.

**`Ctx` rather than a second parameter.** Screens already threaded
`csrf: &str` through every render function. Widening that one parameter into
`Ctx { csrf, base }` was less churn than adding a second, and it is better
grouped: the two always travel together, and a screen with one but not the
other cannot render a working form. `ctx.url("/bots")` is now the only way to
write a link, and a literal `"/bots"` in an `href` is the mistake the test
below catches.

**Explicit route paths, not `Router::nest`.** `nest` was the obvious tool and
has a sharp edge: it maps `/stop-bots` onto the inner `/` but leaves
`/stop-bots/` — the canonical URL, the one `BasePath::url("/")` produces and the
one an NGINX `location /stop-bots/` block sends — falling through to the
fallback as a 404. Registering each route at its full path costs one closure
and puts the trailing slash under the router's own control. `/stop-bots` with
no slash gets a 308 to `/stop-bots/`, so the console has one canonical URL and
the cookie's `Path` is unambiguous.

The cookie is scoped to the prefix rather than to `/`, which is a bonus of
having a prefix at all: on a shared domain the session stops being sent to
every other application on it.

**The test is exhaustive rather than a spot check.** A single absolute URL left
in a template is a broken link that only appears in a proxied deployment.
`no_url_on_any_page_escapes_the_prefix` seeds every table so no panel renders
its empty state, walks all seven pages, extracts every `href`/`src`/`action`,
and asserts each root-relative one starts with the prefix. There is also a test
that unprefixed paths are *not* served, which is what makes "the proxy must not
strip it" a loud failure rather than a page that half-works.

A subdomain needs none of this and stays the recommended deployment. The prefix
support exists because an NGINX `location` block is what many people already
have.

### Login throttling (`web::auth::LoginThrottle`)

**What this defends is not what it looks like.** `--set-password` only ever
generates, and a generated password is 24 base64url characters — 144 bits.
Online guessing was never a threat. The exposure was that verifying a password
runs Argon2id at OWASP defaults, ~50ms of CPU and 19MB of working memory, and
anyone who could reach `/login` could make the server do that as fast as they
could post. That is an amplification denial of service against the host this
tool exists to protect.

So the ordering is the whole design: **a refusal happens before any hashing**,
and costs a map lookup.

Two limits, answering different attacks:

- **A global token bucket** (burst 20, refill 2/s) caps the CPU an
  unauthenticated caller can provoke — about 10% of one core spent on Argon2,
  whatever they do. Global on purpose: a per-client limit is bypassed by
  rotating source addresses, and behind a proxy this server frequently cannot
  tell clients apart at all.
- **Per-client exponential backoff** (10 free attempts, then 1s doubling to a
  30s ceiling) slows a guesser that *can* be identified, and produces the
  message the operator sees.

The client map is bounded and swept: an attacker cycling source addresses would
otherwise turn it into a memory leak with a network interface in front of it.
Both refusals carry the same wording, because which limit tripped would tell a
guesser how close they are to it.

**The shared-bucket problem, found by testing against a real server rather than
only in the suite.** The unit tests all passed while the live behaviour was
worse than intended: after a flood, the *correct* password also got a 429.
Behind NGINX every request's peer is `127.0.0.1`, so the attacker and the
operator share one bucket.

Some of that is inherent — any limiter on an unauthenticated endpoint lets a
flood deny the legitimate user — and three things bound it. The ceiling is
thirty seconds rather than hours. The free allowance is ten, so ordinary use
never meets it. The TUI and the CLI on the host are untouched, so the operator
is never actually shut out of their own server.

The part that is *not* inherent is the one worth acting on:
`web:trust_forwarded_for` is what lets the console tell clients apart behind a
proxy. Verified end to end — with it on, an attacker at one address is
throttled while the operator at another logs in normally, and there is a test
asserting exactly that. It already mattered for the anti-lockout guard; this
gives it a second reason to be set, and the README now says so.

## Security pass: untrusted feeds, an unbounded write, and unbounded fetches (`src/db.rs`, `src/fetch.rs`, `src/web/dashboard.rs`)

Three findings from a pass scoped to the four categories `SECURITY.md` says
are in scope. Each was confirmed by running the code, not by reading it.

### A feed line reaching a root shell

The generated firewall script is not data. iptables' is run with `sh`, and
nftables' with `nft -f`; both are parsers that take statement separators.
`iptables::render` and `nftables::render` interpolate `FirewallRule.address`
verbatim, so an address is code by the time it lands.

`Db::insert_firewall_rule` had validated admin-entered addresses since an
earlier review, which explicitly exempted the fetched ranges — "those come
from trusted upstream sources, not admin input". Reputable is not
uncompromised, and `SECURITY.md` puts a hostile upstream list in scope.
`replace_ip_ranges`, `replace_country_ranges` and `replace_reputation_ranges`
validated nothing at all, and `ipranges::parse_zone_file` /
`parse_prefixes_json` pass through whatever an upstream sends. Feeding
`1.2.3.4/24; touch /tmp/pwned` through `replace_country_ranges` and rendering
produced:

```
iptables -A STOP-BOTS -s 1.2.3.4/24; touch /tmp/pwned -j DROP
```

`ipranges::reputation::looks_like_address` was meant to be the guard for the
six reputation feeds and was not one: it only inspected the part before the
first `/`, so `1.2.3.4/$(reboot)` passed it. (The `;` and `#` forms happened
to be caught there already — both are comment markers in those feeds and are
stripped before the filter runs — which is why the hole survived review.)

The fix is one validator at three depths:

- `db::is_valid_address` is now `pub`, and `db::usable_addresses` filters and
  trims through it. All four address tables use it. `looks_like_address`
  delegates to it.
- Feed entries are **dropped, not rejected as a batch**. These are fetched
  unattended, in four formats from eight upstreams; one bad line in a
  29,000-line zone file should cost that line. Failing the whole fetch is
  also the more dangerous outcome — it leaves the *previous* ranges in place
  while reporting an error nobody is awake to read. `replace_country_ranges`
  now returns the stored count rather than `cidrs.len()`, so the number an
  admin sees is the number that landed.
- Both renderers check again and emit `# skipped (not an IP address or CIDR
  range): {addr:?}` instead of a rule. Defence in depth for a database
  written by an older version — and `{:?}` rather than `{}` because an
  unvalidated address can contain a newline, which would end the comment and
  make the remainder of it a statement.

Addresses are also now stored **trimmed**, because they were validated
trimmed: `is_valid_address` parses `address.trim()`, so `"1.2.3.4\n"` passed
and was written into the middle of a rule line. Not injection — trim only
reaches the ends — but under iptables' `set -e` the script aborts there and
leaves the host with a partial rule set.

### The console's arbitrary root write

`web::dashboard::render_firewall` took its destination from a free-text form
field and handed it to `firewall::write_script`, which `create_dir_all`s the
parent. The console runs as root and the file it writes is an executable
script, so `/etc/profile.d/`, `/etc/cron.d/` and a unit directory were all
reachable — a way around every restriction this console is built around (it
may not apply the firewall script, unblock a blocklist entry, or change its
own password).

The destination is now `AppState.firewall_out`, set by the new
`stop-bots web --firewall-out` and shown in the panel rather than asked for.
Where the script goes is an install-time decision made from a root shell, not
a per-request one. A posted `out=` is ignored rather than rejected — axum's
`Form` extractor drops a key the struct has no field for — and there is a
test that posts one and asserts the file did not appear at that path.

`install web` does **not** write `--firewall-out` into the generated unit,
and shouldn't: `ExecStart` already omits every flag with a working default,
and the installer creates `/etc/stop-bots/` for exactly this file. An
operator who wants it elsewhere uses a drop-in (`systemctl edit
stop-bots-web.service`, `ExecStart=` then the replacement line), which
`install::preflight`'s edited-unit refusal does not touch — it compares the
unit file itself, not the `.d/` directory beside it. Editing the unit in
place would need `--force` on every later install; the drop-in is the
systemd-native route and survives them.

### Unbounded fetches

All six downloads were bare `reqwest::get(url).text()`: no connect timeout,
no total timeout, no bound on what is read into memory. Under the internal
cron — which is where they now mostly run — an upstream that accepts the
connection and then says nothing holds the job forever.

New `src/fetch.rs` is the one place this project makes an outbound request:
one shared `Client` (60s total, 10s connect, 5 redirects, a `stop-bots/x.y.z`
user agent) and `fetch::text(url, what)`. The 32MB cap is checked against
`Content-Length` first, so an oversized body is refused before a byte is
read, and then against the bytes actually arriving, because nothing obliges
a peer to declare a true length. An oversized body is refused rather than
truncated: a truncated blocklist is one with entries silently missing.

`what` names the source rather than the URL — "the ai.robots.txt list" is
what an admin recognises in a cron log.

Tested against a real loopback server rather than a mocked client (the thing
under test is behaviour against bytes on a socket), with the limit as a
parameter on a private `capped_text` so the refusal paths cost eight bytes
instead of 32MB. One of those tests exists only because the client is now
shared: bailing on an over-cap response drops the `Response` mid-body, so it
checks that a refused fetch leaves the connection pool able to serve the
next one.

### What the new refusal did to its callers

`reject_a_wholly_unusable_fetch` turns an outcome that used to be `Ok(0)`
into an `Err`, and three callers reached it with a `?`:

- `cron::store_ip_ranges` would have abandoned its loop *and* skipped
  `set_cron_last_run`, leaving `UpdateIpRanges` permanently due — so a
  single broken feed would have had the console re-fetching all three
  sources every tick. A store failure is now counted alongside a fetch
  failure, which is what the summary already reported.
- `App::finish_reputation_fetch` and `App::finish_country_select` would have
  propagated it out of the event handler. A feed serving an error page must
  not be able to take the TUI down; both now set `self.message`, matching
  how every other failure in those handlers is already reported, and the
  country is not marked selected on the strength of ranges that were never
  stored.

### One doc comment that was simply wrong

`firewall::apply_script` said "Never called from anywhere unattended (no cron
job calls this)". `batch::render_and_apply_firewall` calls it under
`--apply`, and `batch` is the documented crontab entry point. The comment now
names both callers and says what the guarantee actually is: nothing applies a
script without an operator having asked for it, by pressing a key or by
putting `--apply` in a crontab — which is not the same as a human looking.

## Per-address detail on Dynamic Protection (`src/ipdetail.rs`, `i` in the TUI, `?inspect=` in the web UI)

The reflex answer to "what is this address" is reverse DNS and whois. Neither
is here, and the reasoning is the feature's main design decision.

Both are outbound requests, one per row, to infrastructure an attacker
frequently controls — so a detail view that did them on render would hand
every visible row's latency to whoever is attacking, which is the shape of
the unbounded-fetch problem the security pass had just fixed arriving through
a different door. Worse, a PTR record is written by whoever holds the
address. It is attacker-supplied text that *reads* as authoritative, and a
row showing `crawl-66-249-66-1.googlebot.com` beside an attack count invites
exactly the wrong conclusion.

What this host already downloads answers most of the same question, offline
and instantly: six reputation feeds (`reputation_ranges`), three crawler
sources (`ip_ranges`), and whichever countries have been fetched
(`country_ip_ranges`). "Is this a hosting provider, a Tor exit, a known-bad
address, or a crawler that is who it claims to be" is most of what anyone
opens a whois for, and the crawler answer is *better* than whois gives —
being inside Google's published ranges is the thing a user agent string
cannot fake.

### What the model holds

`IpDetail` carries the feed hits (with the matching range: "in Google's
ranges" and "in `66.249.64.0/19`" are different amounts of evidence, and the
second is free), the country, the block status, and the usernames. Three
details that are each there because the obvious version is wrong:

- **`AddressKind`** short-circuits private and malformed addresses. Every
  detector in `accesslog` already skips loopback and RFC1918, and a panel
  solemnly reporting "in none of six reputation feeds" for `10.0.0.5` is
  true and actively misleading — no feed lists those because none can.
- **`country_data_available`** exists so `country: None` can be told from
  "no zone file has ever been fetched". Without it the view reports a fact
  about this host's data as a fact about the address.
- **One hit per source.** A feed listing both a /16 and a /24 covering one
  address has said one thing, not two.

`status` is passed in from the row rather than recomputed, so the verdict
shown in two places at once has one source of truth.

### Usernames

`sshlog` parsed straight past the username to get at the address. It is now
kept — "root, admin, oracle, test" is the single most informative thing an
SSH log holds about an attacker — bounded by the *same* `" from "`
[`ip_after`] uses, so a line the address parse rejects is rejected here too
and the pair can never come from two readings of one line.

It is attacker-controlled text: capped at 48 characters and stripped of
control characters at the parser, not in each front-end, because the TUI
draws into fixed-width cells and an escape sequence reaching the alternate
screen is a corrupted display. A username containing the literal `" from "`
defeats `ip_after` and so drops the line from every count in that module —
pre-existing, a detection weakness rather than a display one, pinned by a
test and recorded in TODO.md rather than worked around here.

### Cost

The lookup scans the range lists rather than indexing them. That is the cost
model already shipping: `dynamic::Live::load` pulls `blocked_ip_ranges` and
scans it per row on *every* render of the screen this opens from, so one
scan on an explicit keypress is strictly cheaper than the surrounding
screen. Measured at 16ms over 20,000 ranges — the test goes at `hits`
directly rather than through `IpDetail::load`, because inserting 20,000 rows
to re-measure the database read put the test's own setup, not the scan, up
against the 300ms budget.

The username breakdown is computed **for one address, when a detail view is
actually opened** — not for every address on every refresh. The first
version did the latter, and it was measured rather than assumed: building
the whole map took `dynamic::Live::load` from 78ms to 293ms on a
120,000-line auth.log, paid by both front-ends on every render whether or
not anyone ever pressed `i`. (The log *read* is 6ms of that — parsing
dominates entirely, so the "it's behind a slow read anyway" intuition was
simply wrong.) Scoped to one address it is 45ms, once, on the keypress.
`dynamic::Live` is unchanged as a result.

Getting there needed the TUI screen to reach the log text, which it does not
keep — and giving one screen's `handle_key` an extra parameter would break
the uniform dispatch signature all four screens share. `KeyOutcome` already
exists for exactly this: `i` returns `KeyOutcome::InspectAddress`, and `App`
— which holds `ssh_log_text` from its background read — assembles the detail
and hands it back via `show_detail`, the same shape `UpdateSource` and
`SelectCountry` already use. It is synchronous, unlike its `start_`/`finish_`
neighbours, because nothing it touches is slow: the log is already in memory
and the rest is a scan the surrounding screen does per render anyway. The web
handler already knows `inspect` inside the closure that reads the log, so it
needs none of this.

### Two front-ends, two shapes

The TUI gets a popup on `i`, which claims `Esc` while open (the nested
back-out `site_detail` already uses) and swallows every other key, so a
keystroke meant for the popup can never block an address behind it. The
User Agent panel says why it has nothing to inspect rather than opening an
empty popup: its rows are keyed by user agent, not address.

The web UI uses `?inspect=<address>` on the same page rather than an htmx
fragment — the page is already parameterised by `?filter=`, so this is the
same shape, and it survives a reload and can be linked to. The address is
percent-encoded into that URL by a hand-rolled encoder: one query parameter
does not justify a dependency, and the only way to get it wrong is to be too
permissive.

### The help screen has no slack, and now says so in code

Adding one line to `tui/help.rs` pushed the last line — the one that says how
to close the help screen — off the bottom. The file's comment already warned
that "adding an entry here means merging or dropping another"; a comment was
not enough, and the only thing that noticed was an end-to-end pty test
failing fifteen seconds later with a timeout. There is now a `MAX_LINES`
constant, a `debug_assert`, and a unit test that renders at the pty harness's
body size and asserts the last line survives. The Dynamic Protection entries
were merged onto one line to stay inside the budget.

## `install web`: the binary has to exist inside the unit's own sandbox

Reported from a real Debian host. `./stop-bots install web`, run from
`/root`, wrote `ExecStart=/root/stop-bots` and then:

```
Process: ExecStart=/root/stop-bots web ... (code=exited, status=203/EXEC)
(top-bots)[191414]: Unable to locate executable '/root/stop-bots': No such file or directory
```

The file was there. The unit sets `ProtectHome=yes`, which replaces `/root`,
`/home` and `/run/user` with empty directories for the service — so
`ExecStart` is resolved in a filesystem where the binary genuinely does not
exist. `PrivateTmp=yes` does the same to `/tmp` and `/var/tmp`.

`preflight` checked `binary.is_file()`, which asks the *installer's*
filesystem. That is a different question from "can systemd execute this",
and the hardening the installer writes is what makes the two disagree. The
check that was missing is `hidden_from_unit`, and its test asserts the
directive it names is still in `web_unit`'s text — so adding a sandbox
directive that hides somewhere new cannot silently outrun the list.

The message is the whole value here: systemd's own report is accurate and
useless, so `hidden_binary_error` is a pure function, separately tested, that
names the directive and gives two commands to paste. A relative `--binary`
is refused in the same place, before `is_file`, because systemd requires an
absolute `ExecStart` and rejects such a unit at *load* time — a failure that
does not even present as a failed service.

### The flag that was dead in production

The check only makes sense for a real install: `--prefix` writes a unit
nothing will ever start, and every `--prefix` staging tree is under `/tmp`,
so applying it there would refuse all of them. The first version put a
`real: bool` on `Layout`, set by `Layout::system`.

`main.rs` never calls `Layout::system`. It builds every layout with
`Layout::under(&prefix, binary)`, prefix defaulting to `/` — so `real` was
`false` on the one path that mattered and the new check was dead in
production while all 21 install tests passed. It was caught by reproducing
the reported failure against the built binary rather than trusting the
tests, and the fix is to derive the flag inside `under` from `prefix == "/"`
so there is nothing for a caller to forget.

### What a failed activation leaves behind

`systemctl enable --now` is two operations and the first one sticks: a
failed start leaves the unit enabled, failed, and enabled again at the next
boot. Systemd's own start limit ends the restart loop after a few attempts,
so this is untidy rather than dangerous — but the error said only "exited
with 1". It now names `systemctl disable --now stop-bots-web.service`.

## Web Access, "Update everything", "Apply everything", and applying the firewall from the console

Four requests, two changes. The first three run machinery that already
existed from a button; the Web Access panel is new NGINX codegen with its
own failure mode, so it landed separately.

### `src/refresh.rs`: one answer to "what does 'everything' mean"

`batch::update_lists` enumerated the four kinds of downloadable source
itself, and could not be reused: it was an `async fn` holding `&Db` across
every fetch. `Db` is not `Sync`, and the console reaches its database
through `spawn_blocking`, which needs `Send + 'static`. So that function
works exactly once — in `batch`, on a current-thread runtime — and nowhere
else.

`refresh::plan` now decides *what* to update; `fetch` touches no database
and `store` touches no network, so either front-end drives them in whatever
order its runtime allows. `batch::update_lists` is a loop over the same
plan. That matters beyond tidiness: a button labelled "Update everything"
that skipped reputation feeds or selected countries would be lying, and the
test for it is that after pressing it, nothing in the UI still tells you to
go and run a CLI command.

Only *enabled* feeds and *selected* countries are planned. A feed nobody
turned on and a country nobody chose are not lists this host uses, and
fetching them would be pointless requests and a table of ranges no rule
references.

### Selecting a country does not download, deliberately

The TUI fetches a country's zone file when you select it, and the console
does not. The asymmetry is on purpose, and it is worth recording because
the obvious fix is to match the TUI:

- An aggregated zone file is hundreds of kilobytes from a third party.
  Blocking a request handler on that makes the button feel broken on a slow
  link, where the TUI does it on a background thread with a spinner.
- This project keeps its test suite free of network access (see "Testing
  without nginx, iptables or the network"). Fetching on POST made
  `the_geo_mode_and_country_selection_round_trip` reach ipdeny.com — it
  went from 0.35s to 0.93s of real HTTP, which is how it was noticed.

What the handler no longer does is tell the operator to run
`stop-bots update-country-ranges` themselves. It names the button.

### Applying the firewall from the console

One of the console's three deliberate omissions, reversed on request. It
happens in exactly one place, `write_and_apply_firewall`, and three things
make it defensible:

- `assess_lockout_risk` runs against the rules in the order the script will
  evaluate them, *before* anything is written. A risk is a refusal, not a
  warning — the same guard `batch --apply` uses.
- `apply_for_real` gates the run, so `stop-bots web --no-apply` keeps the
  old write-only behaviour.
- What executes is the script just written to `firewall_out`, not a freshly
  derived one, so it is what the guard approved and what the operator can
  read afterwards.

The apply itself goes through `spawn_blocking`: it runs `nft -f` or `sh`,
and a subprocess on the async runtime blocks whatever else that thread was
about to serve.

`FirewallBackend` is now stored (`firewall:backend`), because a one-click
"Apply everything" needs an answer without guessing, and an operator who
picked iptables once should not be handed an nftables script next time. It
falls back to nftables, that being the only backend that can express IPv6
and an allowlist catch-all.

### The Web Access panel

Path mode is the default because the console has a password form and a
session cookie: a path attaches to a site that already has a certificate,
where a subdomain needs its own. Within the chosen site it takes the **TLS**
`server` block, not the port-80 redirect — a site normally has both, and
putting the login form in the first would serve it in the clear on a host
with a certificate sitting right there.

Three things are written and all three must agree:

- the `location` block (own sentinels, `CONSOLE_BEGIN`/`CONSOLE_END` — the
  bot-blocking markers live in the same `server` block and are rewritten by
  a different action, so one pair would have the two deleting each other's
  work);
- `web:base_path`, because this server matches the full path *including* the
  prefix and generates links that do too;
- `web:allowed_hosts`, because a proxied request arrives carrying the site's
  host name and the host guard refuses one it was not told about.

Miss the second and every link leaves the location block. Miss the third and
every request is a 403. Both failures look like a broken console rather than
a missing setting, which is why the panel writes all three or none.

`proxy_pass` deliberately has no trailing slash, and there is a test for it:
a trailing slash makes NGINX strip the prefix, which breaks the first thing
in that list.

### `write_validated`: the one that can hurt an operator

`apply_all_sites` writes then tests. That is survivable for an edit to a
file NGINX already loads. A *new* `server` block that fails `nginx -t` leaves
the entire config unloadable — and nothing looks wrong, because the running
NGINX keeps serving from memory. The bill arrives at the next reload, most
likely certbot's renewal hook in the middle of the night.

So the console's NGINX writes go through `write_validated`: keep the
previous content, write, `nginx -t`, and on failure put the previous state
back (or delete the file if there wasn't one) before reporting. The error
says the rollback happened, and says so much louder if the rollback itself
failed. Validation is not gated by `--no-apply`: it is read-only and it is
the safety mechanism. `--no-apply` gates the reload.

## The firewall backend is the single source of truth

Two bugs from one host, both from the same shape: the backend was decided in
one place and something that depends on it was decided in another.

### An iptables script in a file called `firewall.nft`

`AppState.firewall_out` was a `PathBuf` fixed at startup, defaulting to
`/etc/stop-bots/firewall.nft`, while the backend came from a form on every
render. On a host set to iptables, the console wrote `#!/bin/sh` and 12,000
`iptables -A` lines into a file named for the other backend. Confusing
exactly when it matters — while deciding which of two scripts to run.

Worse, and found while fixing it: `cron::render_firewall` hardcoded
`FirewallBackend::Nftables`. With iptables stored, every tick quietly
replaced the operator's iptables script with an nftables one *at the same
path*, and the next "Apply everything" ran `sh` over nftables syntax.

The backend now decides both. `firewall::default_output_path(backend)` is
the one mapping (`main.rs` delegates to it), `firewall::output_path` layers
an explicit `--firewall-out` over it, and `AppState.firewall_out` is an
`Option` meaning "override" rather than "the path". The cron reads
`stored_backend`. The console derives the path inside the same closure that
reads the backend, so the two cannot be computed apart.

The test worth having is not a second copy of the mapping: it renders each
backend, reads the script's own shebang, and asserts the extension agrees
with it.

An explicit path wins outright, extension and all. Someone who passes
`--firewall-out /srv/rules.txt` has said where they want it, and rewriting
their suffix would be the same surprise in the other direction.

### The unit's sandbox forbade the thing the console had just learned to do

`stop-bots install web` writes `RestrictAddressFamilies=AF_UNIX AF_INET
AF_INET6`, under a comment that read:

> Nothing here uses a raw or netlink socket: this service writes the
> firewall script, it never applies it.

That was true when it was written. Adding "apply the firewall from the
console" made it false without touching the file, and the symptom was:

```
nft -f exited with exit status: 3: src/mnl.c:64:
Unable to initialize Netlink socket: Address family not supported by protocol
```

Both `nft` and Debian's nft-backed `iptables` talk to the kernel over
netlink. Reproduced in one line —
`systemd-run --user -p RestrictAddressFamilies='AF_UNIX AF_INET AF_INET6' ip link show`
prints the same "Address family not supported by protocol" — which is what
turned a plausible guess into a diagnosis before anything was changed.

`AF_NETLINK` is now in the list. It is a real widening of the sandbox, and
it is the price of the feature: there is no way to load a ruleset without
talking to the kernel.

The second half is `firewall::sandbox_hint`. nft's message is accurate,
mentions neither systemd nor this project, and sends whoever reads it
hunting for a missing kernel module. A netlink refusal now appends the
directive to check, the command to check it with, and the fact that units
written before applying existed do not have it — `install web --force` and a
restart. It is a *hint*, not a fix: the file belongs to the host, and an
operator running an older unit needs to be told which line to change rather
than have it changed under them.

**Both of these are the same lesson as `apply_script`'s doc comment in the
security pass, and as the `ProtectHome` install bug**: a comment or a
constant that asserts what the code does not need is a claim with no test
behind it, and it goes stale the moment the code starts needing it. The
golden unit file is what tests this one now — the `AF_NETLINK` line cannot
change without the golden diff showing it.

## The same three actions in the TUI

"Make sure the TUI also has this functionality" is the request that decides
whether a feature was built in the right place. Two of the three had been:
`u` reuses `refresh::plan`/`fetch`/`store`, and `a` chains the two
background pairs the TUI already had (`start_site_action(ApplyAll)` and
`start_firewall_render`) rather than reimplementing either. Reimplementing
the second would have meant a second copy of the anti-lockout guard, which
is exactly the duplication the console's version had just collapsed.

The third had not. `set_web_access` was 120 lines of validation, NGINX
codegen and settings writes living inside an axum handler, and none of it
was reachable from the TUI. It is now `src/webaccess.rs`, split the same
three ways `refresh` is and for the same reason — the middle step runs a
subprocess and must be able to run where `Db` cannot:

- `plan(db, request)` reads the scanned sites, the bind address and the
  NGINX commands, and validates what was typed.
- `apply(plan, root)` writes the config and runs `nginx -t`. No `Db`.
- `record(db, plan)` stores the host name and path prefix, **only after**
  the config validated. A host allowlist naming somewhere NGINX never got
  is a setting that only makes the console harder to reach, and there is a
  test that a refused `nginx -t` leaves both settings untouched.

The console does all three inside one `with_db` closure, because all three
are synchronous and its `Db` is already on a blocking thread; splitting
there would buy nothing. The TUI splits them across the thread boundary,
because its `Db` lives on the main thread. Same three functions either way.

### One event per source, not one payload bundle

`u` fetches one source and stores it before starting the next. The plan on
a real host is three bot lists, three crawler ranges, whatever feeds are
enabled and whatever countries are selected — eight or more downloads of
several megabytes each. Fetch-all-then-store-all would hold every payload
in memory at once and leave the message line empty until the last one
landed. `AppEvent::EverythingSourceFetched` carries one body, and
`finish_update_everything_source` stores it and starts the next.

### Where the keys are hinted, and why not where they belong

`u`, `a` and `w` act on the whole host, so by meaning they belong to the
"System-wide settings" panel — which is where the console's two buttons
moved. The hint is in the *Summary* panel's title instead, and the reason
is measured rather than assumed: that panel is half-width, which is 37
title columns at an 80-column terminal, and ratatui truncates a longer
`Block` title silently. "System-wide settings — u update everything, a
apply everything" loses everything past "a app" there. A title short enough
to fit — "System-wide settings — u/a/w" — names the keys without saying
what they do. Summary is full-width, and already the panel that says
"press f".

The Help screen's `MAX_LINES = 27` had zero slack, so adding three keys
meant merging three lines first: `m`/`f` onto one line, and the Dashboard's
`(focus)` line folded into Navigation's `Up/Down`. Budgeting before wiring
is cheaper than discovering it from a pty test timing out.

### The panel padding bug the move surfaced

`.panel-body { padding: 4px 16px 14px; }` is the only thing giving a
panel's loose content side padding. A `table` is full-bleed by design and
brings its own cell padding; anything after it has to be wrapped. The Web
Access panel emitted its form and hints bare, so its dropdowns sat flush
against the panel edge — and moving the two buttons into "System-wide
settings" would have reproduced it exactly, since that panel's content is
also a bare table.

The test is a rule rather than two assertions: for each panel, whatever
follows the last `</table>` must start with a `.panel-body`.

## Asking the kernel, not the file

`stop-bots status` exists because of a gap nobody had named. Every check in
this project was of the form "does what we would generate match what is on
disk" — `firewall_needs_update` compares a signature, `SiteApplyStatus`
compares a config file, the cron panel compares timestamps. All correct,
and all of them were green on a host that was not protected at all: 48,860
drop rules in `/etc/stop-bots/firewall.nft`, and an `ip filter` table with
`policy accept`. The script was right, the database was right, and the
kernel had never been told.

That is not a bug in any one place. It is a whole category of question —
"is the thing in effect" — that the codebase could not ask, because
`src/` contained no code that read live system state. `health` is that
code.

### The split, and why the probe is what gets stored

`probe` shells out and touches no database; `assess` reads the database and
runs no subprocesses. The same division as `refresh` and `webaccess`, for
the same `Db`-is-not-`Sync` reason, plus one specific to this module: `nft
list` on a real ruleset is megabytes of text, so it must not happen on a
dashboard render.

What is cached is the **probe**, not the report. The probe is the expensive
half and the slow-moving half — a ruleset does not change between page
loads — while the report is derived from it *and the database*, which the
operator may have changed a second ago. Caching the report instead would
produce a panel confidently disagreeing with the screen above it.

### Not looking is not the same as fine

Every field on `Probe` is an `Option`, and `None` means "could not find
out". The checks that depend on a `None` report `Unknown`, never `Ok`. This
is the whole reason the module is trustworthy: `nft list` needs root, and a
status panel that says a host is protected because it could not check is
worse than no panel, because it is believed.

### Exit status conflated with the answer, twice

Both bugs found by the container tests, and both the same mistake:

- `nft list table inet stop_bots` exits non-zero when the table does not
  exist. That is not "could not check" — it is *zero rules loaded*, the
  exact critical case. Fixed by listing table *names* first, which is cheap
  and proves `nft` is usable; our table's absence from that list then means
  zero rather than unknown.
- `systemctl is-enabled` exits non-zero for a unit that is merely disabled,
  which is indistinguishable by status from a unit that does not exist. The
  printed word tells them apart; an empty answer is the one that means
  unknown.

Both would have made the check silently useless in precisely the state it
exists to detect, and neither was visible from a unit test — the failures
only appear against a real `nft` and a real systemd.

### Where the report is shown

The console gets a panel with a row per check and the fix on the row that
needs one. The TUI gets a single line in the Summary panel, coloured by the
worst check, because a host that has quietly stopped being protected should
be visible from the screen the admin already has open rather than behind a
key they would have to know to press.

## Look and feel: Night Grid and Greenhouse (`src/tui.rs`, `src/tui/*`, `src/web/assets/style.css`, `src/web/layout.rs`)

A visual pass over both surfaces, done from screenshots rather than from
the code: the four seeded SVGs in `docs/screenshots/` and headless-browser
captures of every console page. What it found was not missing features
but missing *hierarchy* — the TUI painted borders, titles, labels and body
text all in the one accent, so a focused panel looked like an unfocused
one; the console was a competent generic admin panel with no typographic
voice. The redesign is mostly chrome, and it is the same on both surfaces
on purpose: someone who knows one should recognise the other.

**Two palettes, one set of roles.** "Night Grid" (dark): blue-black
ground, phosphor cyan `#2ee6d6` for structure and focus, magenta `#ff5fd2`
reserved for what is *live* right now (spinner, running job, the newest
log line). "Greenhouse" (light): warm paper, deep teal-green `#0f7a6a`,
copper `#b8551c` where the dark theme uses magenta. Ok/warn/danger never
double as the accent. `Theme` in `src/tui.rs` exposes the roles —
`accent`, `live`, `dim`, `selection_bg`, `surface` — and `style.css`
defines the same roles as custom properties, so a component is written
once against the token and looks right in both.

**The TUI keeps the terminal's default foreground for body text** (the
AGENTS.md rule stands). The role colours are 24-bit when `COLORTERM`
says `truecolor`/`24bit` and named ANSI colours otherwise, so a curated
terminal scheme still supplies its own hues. Read once through a
`OnceLock`, because every list on every frame asks.

**Focus is the border, not the row.** `tui::panel(title, focused, theme)`
draws the focused panel with an accent border and bold accent title and
every other panel dim-bordered with a plain title. `tui::select_in` gives
the focused list a `▎` stripe and a tinted background instead of reverse
video, so a red `[ BLOCKED ]` on the selected row stays red — focus and
state no longer fight for the same cells. Unfocused lists reserve the
stripe column and draw nothing in it, so rows do not shift sideways when
focus moves. Popups get `tui::popup`: the focused treatment on the
`surface` ground, one step off the terminal background, so they read as
lifted rather than drawn on.

**A side effect of the popup surface worth knowing about.** The pty tests
match on the raw diffed byte stream, and ratatui only transmits cells
that changed. The old `Block::fg(accent)` set a style on every cell of a
panel, blanks included, so a popup's spaces over them were "changes" and
came down the wire; a popup over default-styled blanks sends only its
letters, and `exp_string("Apply blocking rules to example.com")` never
sees the spaces. The surface tint restores that property (every popup
cell differs from what was under it) — but it is there because a lifted
popup is the right design, and the tests were re-anchored on single
words wherever the new layout moved them regardless. `tests/tui.rs` has
the convention written at its top; it now bites more often, so it is
worth reading before adding an expectation.

**Chrome.** Three header rows and one footer, on every screen. Row one:
brand, version, host name (from `/proc/sys/kernel/hostname`, then
`/etc/hostname`), and on the right whatever job is in flight, in the
live colour — moved up from the footer. Row two: the tab bar, hand-built
rather than `Tabs` so each screen's jump digit can sit in the accent in
front of its name. Row three: the status strip — the seven health checks
from `health::cached_report`, one symbol and one word each (`● kernel`,
`▲ reboot`, `○ console`), so "is this host protected" is answered on
whatever screen the operator has open. The footer is context-sensitive:
each screen's `hints()` returns the focused panel's name and its
`(key, action)` pairs, then `? help`, `t theme`, `q quit`. This is what
let the panel titles go back to being titles — "Summary — u update
everything, a apply everything" was a title doing a footer's job.

**Dashboard layout.** Two columns over a log. Left is *policy* — what
the host blocks by category ("Policy", was "System-wide settings"), by
country ("Geo · blocklist"), and the script those become ("Firewall
script": rule count, `[ STALE ]`/`[ UP TO DATE ]`, sites found and
bot-list freshness — the old Summary panel's content). Right is what the
host does on its own — "Automatic blocking" dealt into as many columns as
its own width allows, and "Scheduled". The Log panel spans both: every
message `App` has shown, newest first with a relative time, the newest
in the live colour. `App` watches `message` once per frame
(`note_message`) rather than every setter learning about a log, capped
at a hundred entries. The System status line the Summary used to carry
is now the strip in the header.

**Dynamic Protection rows.** Count, a ten-cell bar scaled to the panel's
largest count, the state tag in a fixed column, then the value. The tag
carries the colour (red blocked, yellow blocklist, dim not-blocked); the
address or user agent stays default so a long one reads as text rather
than as a red stripe. Panel titles carry the row count and, when a filter
is on, which one.

**Keys.** One map, consistent enough to print on a line:

- `1`–`4` jump to screens, shown in the tab bar; `d`/`b`/`s`/`p` stay as
  aliases.
- `Tab`/`Shift+Tab` always mean next/previous *panel* on the current
  screen — including on the Dashboard (three panels) and Bot settings
  (two), where they used to cycle screens. Screens cycle with
  `←`/`→`/`h`/`l` and the digits. One meaning per key.
- `F` writes the firewall script (was `f`). Capitals for actions that
  touch the host, as `A` already was; lower-case `f` is "filter"
  wherever a list has one.
- `Space` toggles an Automatic-blocking row in place, keeping a
  detector's TTL; `Enter` still opens the chooser.
- `y` copies the selected address or user agent via OSC 52 (a
  twenty-line base64 in `src/tui.rs` rather than a dependency), which
  reaches the local clipboard through SSH and tmux.
- `R` re-reads the SSH log now (`KeyOutcome::RereadLogs`), rather than
  when the 30-second cache says so.
- `t` toggles the theme; `c` still works as the alias it was.

**The console.** Same tokens, three-state theme structure unchanged.
Mono for what the tool is about — panel titles (uppercase, tracked),
tags, counts, addresses, paths, key caps — and sans for the sentences
that explain them. No web fonts: the CSP is `default-src 'none'` and the
console may be reached over an SSH tunnel from a machine with no route
to a font CDN, so the identity comes from *where* the monospace is used,
not which one. Corners 3px, no shadows, tags squared with a 2px left
stripe (the web's `[ BLOCKED ]`). The header carries the host, the
health checks as chips, and a command bar with Update everything and
Apply everything — the TUI's `u` and `a`, which were buried mid-panel
under a paragraph. Dashboard columns stack independently (two `.col`
flex columns inside the grid) so a short panel no longer leaves a hole
beside a tall one. The keyboard map is the same as the TUI's, added to
the one hashed inline script (digits and letters for tabs, `/` focuses
search, `?` help, `t` theme, `Esc` blurs) — the CSP hash is computed
from the constant at runtime, so it tracks.

**Screenshots.** `examples/screenshots.rs` now pins `COLORTERM` so the
SVGs carry the Night Grid palette rather than the generating terminal's
cyan, seeds a health probe so the strip shows something, and pins the
header's host name to `web-01` through `tui::override_hostname` — the
first regeneration put the maintainer's real machine name in the README.

**The command palette (`src/tui/palette.rs`).** `:` on any screen opens
a popup near the top with a query line and every action by name, fuzzy
matched as you type (each query character in order; a hit at a word
start or in a run scores higher, so "apply all" lists "Apply everything"
first and "Apply blocking to every site" second). It is the
discoverability layer the Help screen tries to be, and the reason rare
host actions do not each need a letter. The palette owns its state,
matching and drawing; `App::commands` says what the rows are and
`App::run_command` what running one does, because every one touches a
screen or the database. Most rows are `Action::Key(screen, key)`: switch
to that screen and press the key through `handle_key_event`, so a
command can never do something its key cannot — same popups, same
anti-lockout guards, same background jobs. Site settings' `r`/`A` first
go through `SiteSettings::show_sites`, because those are keys of the
site list and the palette may have been opened from an open site's
detail. The detector rows are snapshotted when the palette opens, so
each says "Turn on" or "Turn off" for the state at that moment; running
one is a direct `Detector::set_enabled` and a refresh. The hint column
on the right shows the key that does the same thing, which is how the
palette teaches the map.

**Not done here.** README still documents `c` for the theme and `Tab`
for cycling screens (README edits are by request only).

## Code health pass: readability and performance

Measured first, again. `cargo clippy` with `pedantic`, `nursery` and
`perf` on top of the clean `-D warnings` baseline; the tally was
dominated by lints this codebase has already considered and rejected
(`struct_excessive_bools`, `doc_markdown`, `cast_possible_truncation` on
terminal-cell arithmetic) plus a long tail of `format!` appended to a
`String`. The findings worth a change:

**The bulk range inserts compiled their SQL once per row.** Every
`replace_*_ranges` ran inside `Db::batch` (one transaction, one fsync —
that part was already right) but called `Connection::execute` in the
loop, which prepares the statement afresh each time. A `prepare_cached`
outside the loop takes 20,000 CIDRs from ~116ms to ~79ms in a release
build, and the same change went into `record_user_agent_hits`. This is
the only genuinely hot path that changed: it runs on every crawler-range
and country fetch, and the country lists are the biggest tables in the
database.

**The host name was read from `/proc` twice per console page.** Now one
cached read in `src/host.rs`, shared with the TUI header, which had its
own copy (and its own `OnceLock`). The screenshot generator pins it
through the same module.

**The Dashboard measured its detector labels twice per frame** — once
to size the panel, once to draw it, each formatting every row's label.
Measured once, passed to both. Thirty frames a second makes small things
worth a line.

**Comments that described the previous chrome.** `Screen`'s doc said
Tab cycled screens; the Dashboard module doc described a Summary panel
and a "press f"; field docs pointed at the Summary panel; the web
dashboard's stale-list constant said it matched it. All now describe
what is on screen.

**Integration tests share fixtures.** `tests/common/mod.rs` holds what
`tests/cli.rs` and `tests/tui.rs` both had copies of — `stop_bots`,
`seed_bots`, `scan_sites`, `path_with`, `copy_dir_all` — plus a
`writable_nginx_fixture`. Eight pty tests opened with a fourteen-line
`update-bot-lists` invocation and five with a `scan-sites` one; each is
now one line, which is the AGENTS.md bar ("setup longer than the
assertion is a sign a fixture is missing"). The two pty spawners that
differed only in `--no-reload` versus a fake-tool PATH are one
`spawn_tui_cmd`. `apply_site` took a site name it ignored; it is
`apply_selected_site` now and says what it does. The palette test had
been dropped into the middle of another test's doc comment.

**The container harness had three copies of `docker exec` and four of
`docker rm -f`.** One `exec_in`/`sh_in`/`remove_container` each, called
by the one-line methods the tests read. A no-op shell line in one test
(output discarded, failure suppressed, `--db` in the wrong position) is
gone. The nextest config gained an override for the container binary:
it is gated by an environment variable, not excluded, so with the
variable set every test used to fall under the 300ms unit budget and
would have been killed at three seconds.

**Considered and rejected.** The thirty-odd `push_str(&format!(..))`
in the firewall renderers would be `write!` — one avoided allocation per
rule line, a millisecond at 20,000 rules, not worth thirty-odd noisier
lines. `sshlog` and `accesslog` read the whole log into memory; the text
is held for thirty seconds and parsed by every detector, streaming would
change every detector's signature, and logrotate keeps the files small.
`main.rs`'s twenty `PathBuf` parameters that could be `&Path` are churn
in a dispatch layer. The container suite's fixed 300ms sleep after an
NGINX reload is real time (up to 2.4s in the table-driven tests) but
replacing it with a poll needs a signal that the new worker is serving,
and `nginx -s reload` offers none that is cheaper than the sleep.
The container suite's `Host` tests all opened with the same three lines;
`Host::start` now boots *with* NGINX running, `Host::installed` adds the
console service, and `Host::stop_bots` supplies the installed console's
database path (`HOST_DB`), so a test starts at its first interesting
line.

## The database stopped growing (`firewall::rules_signature`, `cron::maintenance`, `Db::prune_user_agent_stats`, `stop-bots maintain`)

A live host's database had reached 16 MB. Per-object page accounting
(`dbstat`) put 4.85 MB of that in `settings` — a table of 45 rows. One
row held 4,948,608 bytes.

**`firewall_rendered_signature` was not a signature, it was a
transcript.** `rules_signature` was `format!("{rules:?}")`: the `Debug`
dump of every rule, stored verbatim. That is unremarkable with a handful
of admin rules, and ruinous with the derived ones — `all_rules` appends
every enabled reputation and cloud-provider CIDR, which on that host was
44,075 rules at roughly 110 bytes each. Only equality is ever asked of
the value (`script_freshness`, the Dashboard's "needs updating" row), so
it is now a SHA-256 digest: 64 bytes, constant, whatever the rule count.
Hashed rule by rule rather than over one joined string, so the 5 MB
intermediate allocation goes too — it was being built on every render
*and* every hourly health check, not just when something changed.

**The churn was the second half of the problem.** `auto_vacuum` is off
and `journal_mode` is `delete`, so rewriting a multi-megabyte overflow
chain daily built a freelist: 1,592 pages, 6.5 MB, 40% of the file that
SQLite would reuse but never return. Shrinking the value does not shrink
the file; only `VACUUM` does.

**`user_agent_stats` was the one genuinely unbounded table.** Its own
schema comment says it accumulates lifetime totals, and nothing had ever
deleted a row — a third of that host's 3,161 rows had not been seen in
30 days, and 1,150 were seen exactly once. Everything else in the schema
is bounded by something outside itself: `firewall_rules` by its TTLs
(2,358 of 2,359 rows carried one, and none were overdue, so
`prune_expired_firewall_rules` was working), `ip_ranges` and
`reputation_ranges` by the length of the feeds they mirror, `bots` by the
published lists.

**So: a daily `CronJob::Maintenance`.** It prunes `user_agent_stats` rows
unseen for 90 days, then evicts least-recently-seen rows above a 20,000
cap, then compacts the file if the freelist is both ≥ 4 MB and ≥ 20% of
it. Both vacuum thresholds have to be met — the absolute one stops a
small database being rewritten over a trivial amount, the proportional
one stops a large one being rewritten daily over slack it is about to
reuse. The age window is the honest limit and the row cap is the
backstop: a window alone still admits any number of *recent* one-off
agents, which is exactly what a rotating-user-agent flood is, and this
tool exists to be pointed at those. Eviction is by `last_seen_at`, not
`hit_count`: the count is a lifetime total, so evicting by it would
preferentially discard the newest arrivals.

**A one-line migration, because the old value would otherwise outlive the
fix.** `Db::open` deletes `firewall_rendered_signature` when its length
is not 64. The CLI's `render-firewall` never recorded a signature at all,
so on a command-line-driven host nothing would ever have overwritten the
old dump. Losing the value costs one spurious "the rules changed" until
the next render — the same one-off the format change causes anyway.

**`stop-bots maintain`** runs the job now rather than waiting for the
cron, and `--force-compact` vacuums past the thresholds. It exists
because the host that prompted this has no `sqlite3` installed, and
because after an upgrade that frees several megabytes at once, waiting a
day for the file to shrink is not what someone who just ran `du` wants.
On a copy of that host's database it went 16.0 MB → 4.1 MB in one
invocation, `PRAGMA integrity_check` clean.

**The size is now visible.** `health::database_size` reports the file and
its reclaimable share on every probe, and warns past 128 MB. `disk_room`
already reported free space on the *filesystem*, which says nothing about
what this tool is responsible for — the 4.7 MB row sat there for two
months in a database nothing ever reported the size of. The threshold is
deliberately far above a healthy size rather than just above it: it is
there to catch the next unbounded thing, not to nag a busy host.

**Considered and rejected.** Pruning `reputation_ranges` (43,093 rows,
3.1 MB — the largest legitimate consumer): it is the feed payload, it is
refetched daily, and deleting it only buys a refetch. Migrating the old
signature value to its digest rather than dropping it: that means code
that recognises the old format forever, to save one "render again".
`WITHOUT ROWID` for `reputation_ranges` and `user_agent_stats`, whose
composite/TEXT primary-key autoindexes are each *larger* than the table
they index (1.65 MB against 1.45 MB) — it would roughly halve both, but
it is a table rebuild, and this project still has no migration runner.
A hard byte cap on the file: SQLite offers no way to enforce one that
does not end in a failed write, and bounded retention plus a visible size
is the version that actually holds.

## "Will auto-render at ..." on the stale-script warning (`health::script_freshness`, `cron::next_run_at`)

The firewall-staleness warning told an admin the rules had changed since
the last render and suggested they render again. On a host running the
console that is misleading advice: the internal cron renders daily by
itself, so the warning is a notice, not a task. It now names the time —
`the rules changed since the last render (44077 now). Will auto-render at
2026-09-15 14:40 UTC`.

**The time comes from `cron::next_run_at`, not from arithmetic in
`health`.** It sits beside `is_due` and is built from the same last-run
row and the same `CronJob::interval`, so the projected time and the
due-check cannot disagree about what "daily" means.

**Two cases deliberately say nothing, and both are the difference between
"will" and "might".** A `RenderFirewall` job that has never run means
nothing has ever driven the internal cron on this host — one configured
entirely from the CLI, where the honest answer is never. A projected time
already in the past means the job is *overdue*, which is not a schedule
either: it renders within the minute if a front-end is ticking and never
if the one that used to be has stopped. Naming a time that has been and
gone is worse than naming none.

The remaining false promise — a front-end stopped since its last run,
where a future time is still projected — is accepted rather than missed.
The console is only one of the things that drives this cron (the TUI does,
and so does `stop-bots batch` from a real crontab), so no available signal
distinguishes "will render" from "would have rendered"; and the
`service-health` check immediately below already reports a console that
is not running.

**`format_utc` is the only absolute time this project formats.** Every
other one it shows is relative ("2h ago"), which is why there is no date
crate in the tree to ask, and a relative "in 6h" would have been the house
style. Absolute won because this string answers "has it happened yet?" for
someone reading a report rather than watching a screen, and a fixed moment
survives being read an hour later. UTC and labelled: resolving a local
zone needs a database the binary does not carry, and an unlabelled time an
admin misreads by an hour is worse than one they have to convert. The
arithmetic is Howard Hinnant's `civil_from_days`, tested against
`date -u` rather than against itself — both kinds of leap year, the epoch,
a negative timestamp, and 9999-12-31.

**A gap the change surfaced.** The TUI's one-line status strip maps each
check id to a one-word label and falls back to the id itself, so the
`database-size` check added in the previous pass had been rendering as
"database-size" among "disk", "logs" and "script". The fallback keeps that
readable rather than correct, so nothing noticed. There is now a test that
walks every check `assess` produces and fails on any that falls through —
verified by removing the label and watching it fail.

**Considered and rejected.** Gating the line on `Probe::unit_active`: it
would be wrong on a host driven by `stop-bots batch` from a crontab, which
has no console unit and does auto-render. Changing the `fix` line when a
render is scheduled: rendering by hand is still a real thing an admin can
do to fix it sooner, so the suggestion stands. Adding `chrono` or `jiff`
for one format string, in a tree that has neither.

## Dynamic Protection: "for" not "until", and a tag column that is actually a column

Two things an admin looking at the SSH panel reported, both in one row of
one list.

**"BLOCKED until 1d" was describing a duration with the preposition for a
moment.** `format_until` returns how much time is *left* ("1d", "23h"),
so the sentence read as though the block lifted at something called 1d.
It is `BLOCKED for 1d` now. Only the timed label changed; `BLOCKED`,
`NOT BLOCKED` and `BLOCKLIST` keep the all-caps tag style they share, so
the four still read as one set of states rather than one of them having
been restyled.

**The state tag was never in a column, though the code had said so since
the panel was written.** The four tags are four different lengths —
`[ BLOCKED ]`, `[ BLOCKLIST ]`, `[ NOT BLOCKED ]` and the longest,
`[ BLOCKED for 1d ]`, which varies with the time left — and nothing
padded them, so every row began its address at a different cell and the
states ran into the addresses. `row_line`'s own doc comment had promised
"the state tag in a fixed column" the whole time; only the padding was
missing.

The width comes from the caller rather than from a constant, because the
longest tag depends on the rows actually present: a panel with no
expiring block should not indent every address past room reserved for a
tag that is not there. It is one width across *both* panels rather than
one each — they stack with a single left edge and every column before
this one already lines up, so a tag column that agreed only within a
panel would leave the two address columns a few cells apart, which reads
as a mistake rather than as two independent tables. The padding goes
outside the brackets: `[ BLOCKED        ]` would stretch the coloured box
to the width of the widest state and draw the eye to the emptiest row on
the screen.

The test asserts the thing the eye actually checks — that every value
starts at the same x, across both panels — rather than a golden
screenful, so it still means something when a label or the bar width
changes. It counts **cells, not bytes**: the bar is `\u{2588}` and the
border `\u{2502}`, three bytes each, so a `str::find` offset makes a row
with more bar look further right than one with less. The first version of
this test did exactly that and "failed" against correct output.

**Two things found while looking.** The user-agent panel's empty-state
message had a run of spaces in the middle of it — a string literal broken
across two source lines with no `\` continuation, so the source
indentation was part of the text, invisible at 80 columns because it was
clipped there. And the TUI's one-line status strip maps check ids to
one-word labels with a fallback to the id itself, so the `database-size`
check had been rendering as "database-size" among "disk", "logs" and
"script"; it has a label, and a test now walks every check `assess`
produces so the next one cannot slip through.

## Auto-apply (`Db::get_auto_apply`, `CronJob::ApplyNginx`, `cron::apply_nginx`)

Every user agent a detector blocks changes the generated sentinel block,
which puts every applied site back to `STALE` within the minute. Nothing
in the internal cron applied that, so a host left to itself drifted
further from its own configuration every day; the health report's "NGINX
blocks are applied" warning was the only sign, and it is the one that
turned up on a real host two hours after a deploy, from a single detector
blocking a single scanner.

**One setting, off by default.** Every other default here decides what
gets *written*. This one decides whether a machine reloads a live web
server with nobody watching, so defaulting it on would change that on
every existing install the moment it upgraded — which is not a decision
an upgrade gets to make on an admin's behalf.

**NGINX only, deliberately.** The firewall script is already rendered on
a schedule and still is never applied on one. Its anti-lockout guard
treats `LockoutStatus::LogUnavailable` as a pass, and the cron's SSH-log
read falls back to `journalctl` and can come back empty — a guard that
silently no-ops when it cannot read a log is survivable when a human is
reading the result and is how a server is lost at 3am when none is. NGINX
has a real pre-check in `nginx -t` and a bounded failure mode; the
firewall has neither, unattended. `batch --apply`, with `--ssh-log`
pointed at a real file, remains the supported way to automate that half.

**The toggle is read before any work.** `apply_all_sites` walks every
config file under the root; on a host with the switch off that must not
happen hourly. Same convention the detectors follow. The test for it
points the job at a root that does not exist: `discover_sites` bails on a
missing root, so getting the plain "auto-apply is off" summary back —
rather than an error — is proof nothing walked.

**Hourly, and not faster.** The detectors run every minute and each new
block changes the config, so a minute-interval job would reload a live
NGINX every time one bot arrived. The reload is further gated on
`changed > 0`, the same condition `apply-blocks` and `batch` use, so an
hourly pass on a quiet host costs one directory walk rather than one
`systemctl reload`.

**A failure has to become the summary, not an error.** `run_due_jobs`
reports a failed job to `eprintln!` and carries on, and `record_run`
swallows write failures — so a config NGINX rejects would fail silently
every hour on the one host where it matters. `apply_nginx` never returns
an error: a rejected reload lands in the recorded summary, which is what
puts it on the Scheduled tasks panel.

**Two front-ends, two shapes, one reason.** The console runs the whole
job inside one `with_db` closure: `with_db` is already a `spawn_blocking`
task, and the config write and the reload that publishes it should not be
separated by a window in which another request rewrites the same files.
The TUI cannot do that — `Db` is not `Sync`, and `apply_all_sites` plus
`nginx -t` plus `systemctl reload` is seconds with nothing redrawing — so
it starts the *same* work the operator's own "Apply everything" starts,
through `start_site_action`, whose plan/run split already puts the `Db`
reads on the main thread and the file writes on the blocking pool, and
whose `finish_site_apply` already chains the reload behind the same
flag. A `cron_apply_nginx` flag marks that the run was the cron's, so the
outcome is recorded against the job; it comes back down immediately if
the apply refused to start, or the *operator's* next apply would be
recorded as this job's.

**Where the switch lives.** `NginxSetting`, on the Site settings screen,
beside Block response, robots.txt and Rate limit — not on the Dashboard,
whose panel is explicitly "what adds firewall blocks without me doing
anything?", and not in `protection.rs`, whose module doc says everything
there gates a detector writing `firewall_rules` rows and never NGINX
config. It is the one row on that screen that does not change the *text*
of the generated block; it decides who writes it, which is why it belongs
directly above the list showing which sites are stale.

**Considered and rejected.** A single switch covering the firewall too —
see above; if that is ever wanted it is a second switch with its own
defaults argument. Defaulting on for new installs only: "new" is
indistinguishable from "existing" by the time `Db::open` runs, and a
default that depends on install date is a default nobody can reason
about. Making the CLI's `set-auto-apply` apply immediately: a `set-`
subcommand that reloaded NGINX would be the worst surprise available from
a command whose name says it sets a value — there is a test that it
rewrites no config.

## The firewall's own auto-apply switch (`Db::get_auto_apply_firewall`)

Auto-apply shipped covering NGINX only, and the reasoning for that split
was written down above. Asked for the other half, the answer was a
*second* switch rather than widening the first.

**Two switches, because the risks are not comparable.** A bad NGINX
config is caught by `nginx -t` and costs a failed reload; a bad firewall
ruleset locks you out of the host, and nothing done here can undo that
remotely. One toggle that turned on both would make the cheap decision
carry the expensive one.

**Unattended, it is stricter than the button it automates.** The
interactive paths — the console's "run it after writing", the TUI's
render popup — treat `LockoutStatus::LogUnavailable` as a pass. That is
defensible with a person reading the result, who can get back in. The
cron reads the SSH log through `read_log_for`, which falls back to
`journalctl` and can legitimately come back with nothing, so the same
rule unattended means applying a ruleset whose lockout check never ran.
`render_firewall` therefore tracks whether the guard *ran*, which is a
different fact from whether it objected, and refuses to apply when it did
not. The script is still written; only the running is withheld, and the
summary says which condition stopped it so the fix (point `--ssh-log` at
a readable log) is in front of the admin rather than inferred.

**It lives in `RenderFirewall`, not a job of its own.** The script that
runs is the one just written, so what executes is what the guard
approved — the same reasoning the console's `write_and_apply_firewall`
gives for applying the file rather than a freshly derived ruleset. A
separate job would have to re-derive or re-read, and could apply a script
a later render had already replaced.

`run_log_job` gained an `apply_for_real` parameter to carry each
front-end's "may touch the system" flag (`--no-apply`, the TUI's
`reload_nginx`) down to it, rather than the job reaching for a global.

**Where the switch lives.** The Dashboard's "Automatic blocking" list, as
a third `ProtectionRow` — the one row there that adds no blocks of its
own. It earns the place: every other row decides what ends up in the
firewall script, and this answers what happens to that script afterwards,
which is the question an admin has immediately after switching one of the
others on. The NGINX half stays on Site settings next to the config it
applies, which is the same split `tui/site_settings.rs`'s module doc
already draws. `is_detector` changed from "not a feed" to "is a detector"
so the option-count, popup-index and toggle paths all treat the new row
as the plain Off/On it is, with no further arms.

**A stale claim, removed.** `cron`'s module doc said "nothing here
applies a firewall script" and called applying "a manual step for the
admin". That is no longer true for an admin who sets the switch, and a
module doc that promises a safety property the code no longer has is
worse than no doc.

**Considered and rejected.** Reusing `Db::get_auto_apply` — see above.
Treating `LogUnavailable` as a pass for consistency with the interactive
paths: consistency is the wrong thing to optimise when the difference is
whether anyone will read the outcome. Making the refusal an error rather
than a summary: `run_due_jobs` prints errors to stderr and carries on, so
the one host where this matters would never see it.

## A built-in bot list (`src/botlist/stop_bots_extras.rs`)

The three upstream sources are all downloaded. This one is compiled in,
and that is the whole point: a fresh install is covered before it has
network access, before `update-bot-lists` has run, and on a host that
cannot reach GitHub. `fetch` returns an empty string and `parse` ignores
its argument, so the source still goes through the same fetch-then-parse
pair as the other three and needs no special case in `refresh` or
`SourceKind::update`.

**How the entries were chosen.** Two months of one server's NGINX access
log: 6,493 distinct user agents over 435,782 requests, each matched
against all 1,606 patterns the three upstream sources contribute. 5,283
user agents matched none — almost all of them ordinary browsers. What
survived the filtering is 46 entries covering 22,573 requests the
existing lists let through, every one of which was checked by eye against
the full list of user agents its pattern matches.

**Generalised from instances to names.** `ModatScanner/1.2` became
`ModatScanner`. The upstream lists' own worst entry is `Googlebot\/`,
which stops matching the moment a client drops the version — that is a
32-request gap on this one host, and over-specific patterns are exactly
the failure this list exists to correct.

**Categories, not a deny list.** Entries carry the same `is_ai`/
`is_scanner` flags every other source's bots do, so the host's policy
decides and a per-bot override still wins over both. That matters most
for the AI crawlers: xAI's `xAI-SearchBot` is a documented, declared
crawler, and a host that wants AI traffic keeps it with the switch it
already has rather than by editing a list.

**What was deliberately left out**, because a list that ships to other
people's servers is judged by its false positives:

- *Already covered upstream.* Six of the 31 user agents blocked by hand
  on that server — `curl/7.74.0`, `WordPress/6.9.4` and friends — are
  matched by `^curl` and `WordPress\/` already.
- *Site-specific strings.* A URL that arrived in the user-agent field is
  an attack artifact, not a user agent; one server's own hostname is
  nobody else's problem.
- *Real software pinned to a build.* `eMClient/10.4.4867.0` is a mail
  client.
- *Names too generic for a substring match.* `Scanner/1.0` and a bare
  `scanner` were both seen and either would match a third of the list
  itself.
- *A bare `Googlebot`.* Almost certainly an impersonator, but that is
  what `scanblock`'s spoofed-crawler detector is for, and blocking the
  name would also block the real one wherever the search category is
  allowed.
- *`Let's Encrypt validation server`*, seen 68 times. Blocking it breaks
  ACME HTTP-01 renewal and surfaces as an expired certificate two months
  later. `no_pattern_matches_something_that_must_not_be_blocked` pins
  that, along with the four commonest browser strings and the real
  Googlebot and bingbot.

**Seeded at registration, not only on fetch.** `register_all_sources`
stores it as well as registering it, because a source that is already in
the binary has nothing to wait for, and leaving it registered-but-empty
would mean shipping a list an install never used until an unrelated
button was pressed. `upsert_bot` writes to `bot_source_entries` and
recomputes the merged row, so re-seeding on every startup cannot clobber
an admin's own per-bot status.

**Three tests broke, and all three were asserting too much.** Two checked
"the whole `bots` table is empty / has one row" when what they meant was
"this source contributed nothing / one row"; they use
`count_bot_source_entries` now. The Bot-settings web fixture called
`register_all_sources` only to satisfy a foreign key and now registers
the single source it attributes its three rows to. A fourth, the pty test
for bot search, lost one assertion: the built-in list contains
`jscrawler`, so the first keystroke of "jyxo" already renders a row whose
`(system)` tag sits at the same cells, and unchanged cells are never
retransmitted — the diffing gotcha this file's own notes describe. The
tag is covered by a unit test that reads the rendered line instead.

**Considered and rejected.** Shipping the admin's 31 hand-blocked strings
as they stand — six are redundant, three are site-specific, and two pin a
real mail client to a build number. Marking the AI crawlers `is_search_engine`
as well: the flags are OR-ed, so it changes nothing while the AI category
is blocked and misleads whenever it is not. A separate "block everything
on this list" switch: the category defaults already answer that, and a
second answer would eventually disagree with the first.
