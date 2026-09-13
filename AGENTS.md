# Developement Workflow

- Always read the README.md file in the root of the repository. Always.
- Always read README.md in any directory in this repository before you read or write any files in
that directory.

## Markdown files

- Do NOT update the README.md files unless explicitly asked to do so.
- Update SPECS.md files every time you do a big change.
- Always clean up TODO.md and REVIEW.md files when you complete a task from those files.

# Rust

## TUI

- Prefer Stylize helpers: use "text".dim(), .bold(), .cyan(), .italic(), .underlined() instead of manual Style where possible.
- Prefer simple conversions: use "text".into() for spans and vec![…].into() for lines; when inference is ambiguous (e.g., Paragraph::new/Cell::from), use Line::from(spans) or Span::from(text).
- Computed styles: if the Style is computed at runtime, using `Span::styled` is OK (`Span::from(text).set_style(style)` is also acceptable).
- Avoid hardcoded white: do not use `.white()`; prefer the default foreground (no color).
- Chaining: combine helpers by chaining for readability (e.g., url.cyan().underlined()).
- Single items: prefer "text".into(); use Line::from(text) or Span::from(text) only when the target type isn’t obvious from context, or when using .into() would require extra type annotations.
- Building lines: use vec![…].into() to construct a Line when the target type is obvious and no extra type annotations are needed; otherwise use Line::from(vec![…]).
- Avoid churn: don’t refactor between equivalent forms (Span::styled ↔ set_style, Line::from ↔ .into()) without a clear readability or functional gain; follow file‑local conventions and do not introduce type annotations solely to satisfy .into().
- Compactness: prefer the form that stays on one line after rustfmt; if only one of Line::from(vec![…]) or vec![…].into() avoids wrapping, choose that. If both wrap, pick the one with fewer wrapped lines.

## Clippy beyond `-D warnings`

`cargo clippy --all-targets -- -D warnings` is the bar and it is clean. If you
run `-W clippy::pedantic` as well, three of its lints are **wrong for this
codebase** and have been considered and rejected — don't "fix" them:

- `unnecessary_wraps` on the `handle_*_key` methods and on `App`'s
  `start_*` family. They return `Result` to match their siblings, and a
  uniform signature across a family of dispatch methods is worth more than
  removing a `?` from three of them.
- `unused_self` on `render_message`, `apply_popup` and friends, for the same
  reason: they sit among sibling methods that do use `self`, and breaking a
  `render_*` family into methods and free functions helps nobody reading it.
- `missing_errors_doc` / `must_use` (169 and 83 hits). Those earn their keep
  on a published library API. `src/lib.rs` exists so the integration tests can
  reach the binary's internals; it is not a designed API surface, and
  `Cargo.toml` says so.

## Background work in `App`

Every long-running action is a `start_x` / `finish_x` pair, thirteen times
over: `start_` does the `Db` reads on the main thread, spawns the slow half,
and returns immediately; `finish_` applies the result back on the main thread,
where `Db` can be touched again. Adding a fourteenth follows the same shape,
and the pair is named for the work, not the verb — `start_nginx_reload`, not
`reload_nginx`, because it doesn't reload anything, it starts a reload.

An action that is two existing pairs in sequence is *not* a new pair.
`start_apply_everything` starts the site apply and sets a flag that
`finish_site_apply` reads to start the firewall render; it adds no event and
no `finish_` of its own. Reimplementing either half would have meant a second
copy of the anti-lockout guard.

## Tests

Beyond the policy in README.md (no mocks; in-memory fakes, injected inputs,
fake executables on PATH, golden files; 300ms per test in `src/`, 1s in
`tests/`), the conventions that keep them readable:

- **A test should read as a claim, not a script.** The name states the
  property; the body should get to the interesting part within a few lines.
  Setup longer than the assertion is a sign a fixture is missing.
- **Shared fixtures live in `src/testing.rs`** (unit tests) and in the
  helpers at the top of each file in `tests/` (integration tests, which
  cannot see a `#[cfg(test)]` module). Prefer them over hand-rolled struct
  literals: `block("10.0.0.1")` says what an eight-field `FirewallRule`
  literal makes you decode.
- **The bar for a new fixture is that the call site reads better**, not
  that it is shorter. A helper whose name doesn't carry its meaning makes a
  test worse — now you have to go and look it up.
- **Don't hide the thing under test.** Where a literal *is* the expected
  value (the `NewBot`s in `botlist/*`'s parser tests, the source rows in
  the Dashboard's freshness tests), leave it inline.
- **Every assertion should say what happened when it fails.**
  `assert!(x.contains(y))` prints nothing useful; add `, "x was:\n{x}"`.
  For several related checks, prefer a table of `(description, expected)`
  over a run of near-identical asserts.
- **Pin generated output with a golden** (`tests/golden/`) rather than a
  wall of substring checks. Keep a substring assert only where it names a
  property a golden can't — "skips disabled rules", "uses `ip6 saddr` for
  v6".
- **`tests/tui.rs` expectations must be single words.** The terminal output
  is diffed, so the spaces inside a multi-word needle routinely land on
  cells that were already blank and never transmit, even though every word
  is on screen.
- **One property per test where splitting is cheap.** A test that walks
  through four unrelated features doesn't localise a failure.

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->
