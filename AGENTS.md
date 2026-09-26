# Developement Workflow

- Always read the README.md file in the root of the repository. Always.
- Always read README.md in any directory in this repository before you read or write any files in
that directory.

## Markdown files

- Do NOT update the README.md files unless explicitly asked to do so.
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

Every long-running action is a `start_x` / `finish_x` pair, fourteen times
over: `start_` does the `Db` reads on the main thread, spawns the slow half,
and returns immediately; `finish_` applies the result back on the main thread,
where `Db` can be touched again. Adding a fifteenth follows the same shape,
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
- **Shared fixtures live in `src/testing.rs`** (unit tests), in
  `tests/common/mod.rs` (what two or more integration binaries use —
  they cannot see a `#[cfg(test)]` module), and otherwise in the helpers
  at the top of each file in `tests/`. Prefer them over hand-rolled struct
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
