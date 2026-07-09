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

## Crawler and country IP ranges (`src/ipranges.rs`, `Db::derived_block_addresses`)

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
