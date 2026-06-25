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
previous implementation was deleted: **Dashboard** (new, default screen —
read-only overview: category defaults, site count, bot-source
up-to-date/stale counts, last action message), **Bot settings** (the three
category defaults plus every known bot and its effective status, each
changeable via a popup), **Site settings** (read-only list of discovered
sites — no per-site override storage exists yet, see TODO.md). A **Help**
screen (`?`) is reachable from any of the three and returns to whichever one
was active.

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
