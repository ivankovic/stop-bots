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

## Bot list (`src/botlist.rs`)

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

## Crawler and country IP ranges (`src/ipranges.rs`, `Db::derived_firewall_entries`)

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
shape is identical, `IpRangeSourceKind` (in `src/ipranges.rs`) shares one
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
timer while the TUI is open, and its state is shown there; see "Internal
cron" below.

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

## Internal cron (`src/cron.rs`, `App`'s tick handler in `src/app.rs`, the Dashboard's "Scheduled tasks" panel)

Replaces relying on an external `cron`/systemd-timer entry to keep the
scanner-detection and crawler-range commands running unattended, by having
the TUI itself periodically check which of four background jobs are due
and run them: `UpdateIpRanges`, `BlockScanners`, `BlockWebScanners`,
`RenderFirewall` (see `CronJob` for exactly what each does — it's the same
logic each equivalent CLI subcommand runs, via `scanblock`/`ipranges`/
`firewall`, not a reimplementation). The Dashboard grew a fifth panel,
"Scheduled tasks", listing all four with when they last ran and their last
outcome.

**Only automates while the TUI is open — this is the one limitation to
know before treating it as a full cron replacement.** Closing the TUI
pauses every job; there is no separate headless daemon mode. A job overdue
when the TUI (re)starts just runs the next time it's checked (the same
never-fetched-yet convention `ipranges` staleness already used), not a
"catch up on however many intervals were missed" scheme.

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
mean shortening `CRON_CHECK_INTERVAL` itself, not just the job's
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
`run_cron_block_scanners` already uses) on every `refresh`. The
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
successful write (`App::render_firewall`, `render_firewall_for_cron`)
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
