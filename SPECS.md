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
config with `nginx -t`; the generator was only checked against the existing
fixtures and hand-built multi-block cases, not a real NGINX parse.

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
