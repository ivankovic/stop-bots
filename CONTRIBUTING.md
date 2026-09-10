# Contributing

Everything a contributor — human or otherwise — needs to know about how this code is
built, tested and laid out. It used to live at the bottom of `README.md`; it was moved
here so the README stays a description of the *tool* rather than of the workshop.

The AI-only instructions are in [`AGENTS.md`](AGENTS.md); the decision log behind every
shipped behaviour is in `SPECS.md`; open work is in `TODO.md`. Releasing is its own
document, [`RELEASING.md`](RELEASING.md).

## Technology

The project is completely written in Rust.

SQLite is used to store user configuation and other runtime data.

The UI is a Terminal UI written using the excellent Ratatui and Crossterm libraries.

### UI design patterns

The TUI must follow the [Ratatui event driven async template](https://github.com/ratatui/templates/tree/main/event-driven-async).

Each component encapsulates its own state, event handlers, and rendering logic.

**Nothing blocks the event loop.** The loop is `draw` → `await event` →
`handle_event`, so anything slow in a handler freezes the interface for exactly as long
as it takes. Every action that touches the filesystem, a subprocess or the network is
split the same way:

- resolve what it needs from `Db` on the main thread — `rusqlite::Connection` is `Send`
  but not `Sync`, and all database access lives here;
- do the slow half on `tokio::task::spawn_blocking`, where no `Db` can reach;
- fold the result back on the main thread, through an `AppEvent`.

A screen whose key handler wants to do such work returns it to `App` as data (see
`KeyOutcome`) rather than doing it inline. `App::jobs_in_flight` both animates the
spinners and stops the same work starting twice — but dropping a duplicate is only safe
for a *read*. Anything shaped write-then-act must coalesce instead, because the act has
to happen at least once after the last write.

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

### Coverage

93% of lines, measured with `cargo llvm-cov --summary-only --workspace`. That figure
*understates* it: the container suite (`make test-containers`) runs a binary inside Docker,
so its coverage never comes back.

It is a check, not a boast — but the check and the achieved figure are deliberately two
different numbers. CI runs the same command with `--fail-under-lines 90`, and the badge
at the top of the README claims that **floor**, not this snapshot.

A floor set at today's figure would be a trap rather than a check. 93.29% of 16,012 lines
leaves 47 uncovered lines of headroom — one ordinary function landing slightly
under-tested turns CI red on an unrelated pull request, and the quickest fix at that point
is to edit the floor down, which is exactly the rot the floor exists to prevent. 90% is
low enough to survive normal development and high enough that a real collapse is a red
build.

Raising the floor as the achieved figure rises is welcome. It just has to move together
with the badge in `README.md` and this paragraph.

**No test touches the network**, which is where the remaining gap is and why it is there.
Every downloader takes a `--source <file>` override that parses the same format the server
would have sent — a real feature for a host with no outbound access, and what makes the
parse-and-store half of a download testable. What is left uncovered is the spawn itself:
four `App::start_*` methods and `batch`'s `update_lists`, whose entire job is to start an
HTTP request. Covering those would mean an injectable base URL and a local HTTP server, and
would test reqwest rather than this project.

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

### Screenshots

`docs/screenshots/` is generated, not captured:

```
make screenshots
```

`examples/screenshots.rs` seeds a throwaway database with fiction — addresses from
the documentation ranges reserved by RFC 5737, `example.com` hostnames — draws each
screen through `TestBackend`, the same in-memory backend the unit tests use, and
writes SVG.

Two reasons it works this way rather than someone pressing a key and cropping a
terminal. The first is that this tool reads real SSH and NGINX logs: a hand-taken
screenshot of Dynamic Protection publishes the addresses currently attacking the
maintainer's server and the hostname of every site on it. The second is that the
output is a pure function of the seed, so a screenshot that has gone stale shows up
as a diff in review rather than as a picture nobody thought to re-take.

Re-run it after any change to a screen's layout, and commit the result. The README
references the files by absolute `raw.githubusercontent.com` URL, because relative
image paths do not resolve on crates.io (which is also why `Cargo.toml` excludes
`docs/` from the package).

The generator reaches into things that move — `Dashboard::refresh`,
`SiteSettings::finish_status_check`, the `Screen` enum, and the string ids of five
cron jobs and three bot-list sources. It does not silently rot when one of those is
renamed: CI's `cargo clippy --all-targets -- -D warnings` compiles examples, so the
break is a red build rather than a surprise the next time somebody runs
`make screenshots`.

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

```
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
        |- batch.rs       <- Batch mode: one unattended pass, for a real crontab
        |- cron.rs        <- The internal cron: which background jobs run how often
        |- firewall.rs    <- Shared firewall-rendering logic (lockout safety, script writing)
        |- iptables.rs    <- iptables script generation
        |- nftables.rs    <- nftables script generation
    |- /tests           <- Integration and end-to-end automated tests
    |- README.md        <- What the tool is and how to use it. High level only
    |- CONTRIBUTING.md  <- This file. How the code is built, tested and laid out
    |- RELEASING.md     <- The release process, and why it is split the way it is
    |- CHANGELOG.md     <- What changed, per release
    |- AGENTS.md        <- AI-only instructions
    |- SPECS.md         <- Detailed specifications and all decisions that were taken
    |- REVIEW.md        <- Comments about the codebase that need to be improved uppon
    |- TODO.md          <- List of small to  mid size TODO items that need to be fixed in the future
```

The SPECS.md and README.md files can exist in any subdirectory, and they always serve the same
purpose:

*  README.md - High level summary. Must be readable to humans.
*  SPECS.md - Semi-structured collection of specifications and a decision log of every decision that
   was taken during implementation.

The TODO.md and REVIEW.md files are always only in the root of the repository.
