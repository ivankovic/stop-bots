# Contributing

Contributions are welcome, and bug reports most of all.

## Reporting a bug

[Open an issue](https://github.com/ivankovic/stop-bots/issues). The most useful reports say:

- which version (`stop-bots --version`) and which distribution you run it on;
- what you did, what you expected, and what happened instead;
- for a wrongly blocked or wrongly allowed client, the relevant lines from the SSH or web server log,
  with anything private (your hostnames, your own IP addresses) redacted.

A security problem is the exception: don't open a public issue, follow
[`SECURITY.md`](SECURITY.md) instead.

## Sending a change

1. For anything bigger than a small fix, open an issue first so we can agree on the approach
   before you spend time on it.
2. Follow the rest of this file. In practice: `make hooks` once, so formatting and clippy run on
   every commit, and `make unit-test` before you push. CI also runs the container suite.
3. Agree to the [Contributor License Agreement](CLA.md) by posting the comment it asks for on
   your pull request. You keep the copyright in your work; the CLA lets the project offer
   alternative licenses alongside the AGPL (see "License" in the README). It is needed once,
   and only for changes, not for bug reports.

## How the project works

The rest of this file is everything a contributor, the maintainer or a coding agent needs to
know about how this code is built, tested and laid out. It used to live at the bottom of
`README.md`; it was moved here so the README stays a description of the *tool* rather than of
the workshop.

The AI-only instructions are in [`AGENTS.md`](AGENTS.md); open work is in `TODO.md`. Releasing is its own
document, [`RELEASING.md`](RELEASING.md).

## Technology

The project is completely written in Rust, and needs Rust 1.88 or newer to build: `cargo install
--path .` from a checkout. It is Linux only in practice: it shells out to `systemctl`, `nginx -t`
or `apache2ctl`, and `nft`/`iptables`, so while it compiles elsewhere it won't be much use there.

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

Print with `say!`, `say_inline!` and `say_err!`, never `println!` and its siblings,
which `clippy.toml` forbids. They pass the line through `present::terminal_safe_text`,
because much of what this program prints was chosen by a client — a user agent, a request
path — and it is read by root in a terminal.

### The pre-commit hook

Opt-in, one command:

```
make hooks
```

It formats what you staged and runs `cargo clippy --all-targets -- -D warnings`, the same
invocation CI uses, so a commit that passes here passes there. A commit with no Rust in it
skips both and costs nothing; a clean Rust commit costs about four seconds warm.

It deliberately does not run the tests. The unit suite is twenty seconds, and a hook that
costs that much gets bypassed once and then by habit.

**It will refuse a commit rather than guess.** If a file is staged unformatted *and* has
unstaged changes, formatting is judged against the staged bytes (`git show :file`) but
`cargo fmt` rewrites your working tree — so re-staging would sweep in edits you left out on
purpose. It formats your working tree, says which files, and stops so you can `git add -p`
the part you meant.

`git commit --no-verify` skips it once; `git config --unset core.hooksPath` turns it off.

## Testing

```
make unit-test         # everything that needs only a compiler
make integration-test  # the container suite: Docker and NET_ADMIN
make test              # both, unit first
```

`make unit-test` prefers `cargo nextest run` when it is installed and falls back to
`cargo test`; they run the same tests, but only nextest enforces the per-test budgets below.

Automated tests should be run frequently during coding.

Benchmarks should be used to measure quality. These should be run on demand.

### Resource benchmark

```
make bench
```

`tests/bench.rs` runs the real release binary over what a large host has: a 1 GB NGINX
access log through every detector (`batch --no-fetch`), 10 MB appended and scanned again,
and 100,000 country and reputation ranges stored and rendered into an nftables script
(`render-firewall`). Each step's wall time and peak RSS are checked against a budget, and the
results printed as a table. It is off unless `STOP_BOTS_BENCH=1`, takes about two minutes
with the build, and writes 1.3 GB under `target/tmp`. `STOP_BOTS_BENCH_LOG_MB=100` makes
the log smaller; `STOP_BOTS_BENCH_KEEP=1` keeps the host it built, to profile a step by hand.

CI runs it as the `bench` job. The budgets, and the numbers they were set from, are in
`BUDGETS` at the top of the file: a few times the measured time and 1.5 times the measured
memory, so it catches an order-of-magnitude regression (the whole log re-read every pass,
a render gone quadratic, memory that grows with the log) rather than runner noise. A change
that genuinely needs more moves the budget in the same commit, and says why.

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

92.5% of lines (33,814 lines, 2,522 not covered), measured on 2026-09-28 at `0.0.15`
with `cargo llvm-cov --summary-only --workspace`. This is the one place that figure is
quoted; the comment on the `coverage` job in `ci.yml` points here. It *understates*
coverage: the container suite (`make integration-test`) runs a binary inside Docker, so
its coverage never comes back.

It is a check, not a boast — but the check and the achieved figure are deliberately two
different numbers. CI runs the same command with `--fail-under-lines 90`: that **floor**
is the promise, not this snapshot. The README carries no coverage badge, because CI
publishes no coverage figure for one to read, and a hand-written number is a claim
nothing keeps true.

A floor set at today's figure would be a trap rather than a check: with no headroom, one
ordinary function landing slightly under-tested turns CI red on an unrelated pull
request, and the quickest fix at that point is to edit the floor down, which is exactly
the rot the floor exists to prevent. 90% is low enough to survive normal development
(about 850 lines of headroom today) and high enough that a real collapse is a red build.

Raising the floor as the achieved figure rises is welcome. It just has to move together
with this paragraph.

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
  `--access-log`, `--root`, `STOP_BOTS_NGINX_DIR`/`STOP_BOTS_NGINX_CONF_D` and their
  `STOP_BOTS_APACHE_*` twins. These are real
  product flags, not test back-doors — the same override an admin with a non-standard layout
  would use. A test must never read the host's real logs or config; auto-detection can shell
  out to `journalctl`, which is nondeterministic and slow.
- **Fake executables on PATH** for the external tools the product drives (`nginx`,
  `systemctl`, `nft`): tiny scripts that record their argv and exit 0 (or 1, to stage a
  failure). The product resolves and runs them exactly as it would the real tools — the
  process spawn, argument building, exit-code and ordering logic all execute for real; only
  the binary PATH finds is ours. See `fake_tools` in tests/cli.rs.
- **Golden files** (tests/golden/) for every generated artifact: firewall scripts, NGINX
  and Apache blocks, robots.txt. They lock exact bytes, and double as the samples to hand
  to the real `nft -c -f` / `nginx -t` / `apache2ctl configtest` once per change on a machine that has them. Regenerate with
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
TUI screen through `TestBackend`, the same in-memory backend the unit tests use, and
writes SVG.

Two reasons it works this way rather than someone pressing a key and cropping a
terminal. The first is that this tool reads real SSH and web server logs: a hand-taken
screenshot of the Firewall screen publishes the addresses currently attacking the
maintainer's server and the hostname of every site on it. The second is that the
output is a pure function of the seed, so a screenshot that has gone stale shows up
as a diff in review rather than as a picture nobody thought to re-take.

Re-run it after any change to a screen's layout, and commit the result. The SVGs are
a pure function of the seed; the PNGs also depend on the fonts installed on the
machine that rendered them, so expect a byte-level diff from another machine even
when nothing changed. The animated `tour.gif` is drawn in Iosevka Extended, whose
advance is exactly the SVGs' cell width, and the generator stops with an error rather
than fall back to another font if it is not installed. The README
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

`tests/container.rs` runs the generated output through a **real NGINX, a real Apache and a
real nftables**, in Docker, and checks the result by sending actual requests — including from
a second container with its own address, so a firewall rule is verified by packets that
genuinely don't arrive. It is the only place the parsers this project writes for are exercised
at all; everything else asserts the text we hoped would satisfy them, which is exactly the check
that keeps passing when the text is wrong.

It needs Docker and `NET_ADMIN` and takes ~20s, so it is off by default:

```
make integration-test
```

CI runs it as its own job. Run it before a release, and before trusting any change to
generated config.

Besides Debian's and Ubuntu's layouts, two images stand in for hosts nobody here runs.
`Dockerfile.rhel` is AlmaLinux 10's `httpd`, for RHEL's `/etc/httpd` tree. And
`Dockerfile.upgrade` adds the released 0.1.1 binary to the systemd host, for the tests
that upgrade what 0.1.1 actually left on a host rather than a fixture of it. It
downloads that binary when the image is built, pinned by its published checksum, the
way every image fetches its packages; no test touches the network.

NPMplus is tested in its own released image, pinned by digest in `tests/container.rs`, and
not in one of ours: it is Alpine, on musl, and the point is to run stop-bots where an
operator does, on the host, against NPMplus's data directory as a bind mount, testing and
reloading with `<runtime> exec`. The hosts are created through NPMplus's API, so the
config read is the config NPMplus renders. The container has no network, and a stand-in
ACME account in its data directory keeps NPMplus from registering one on every run.

Under rootless Podman, a test that starts a second container on a network of its own
fails if Podman's network backend cannot load `ip_tables`, which some kernels refuse to
an unprivileged user. Those containers only talk to each other on one bridge, which
needs no host firewall rules, so for this suite they can be switched off without
touching your own Podman configuration:

```
printf '[network]\nfirewall_driver = "none"\n' > /tmp/containers.conf
CONTAINERS_CONF_OVERRIDE=/tmp/containers.conf STOP_BOTS_CONTAINER_RUNTIME=podman make integration-test
```

**Flakes are retried, and counted.** The suite races a real systemd, NGINX and SQLite,
so `.config/nextest.toml` gives this binary, and only this one, two retries. CI runs it
with `cargo nextest run --test container`: a test that passes on a retry is reported
`FLAKY` in the log and the summary, and becomes a warning annotation on the run, so a
test that keeps needing its retries shows up there rather than as a red job nobody can
reproduce. Three failures in a row still fail. `make integration-test` uses plain
`cargo test` for its streamed output and does not retry; `STOP_BOTS_CONTAINER_TESTS=1
cargo nextest run --test container` locally behaves as CI does.

### The stranger test

Three tests in the same file follow the README's quick start on a fresh Debian 12 and a
fresh Ubuntu 24.04 (`tests/container/Dockerfile.stranger`: systemd, an SSH server,
and NGINX and nftables as `apt install` leaves them), and on a fresh Ubuntu 24.04 with
Apache in NGINX's place, where they also take the quick start's two Apache steps. They install the `.deb`, run
every quick-start command as written, check blocking with packets from a second
container, and end with `uninstall all` and a host identical to the one they started
from. They install a package rather than the test binary because the package is part
of what a stranger meets, and because a glibc build from a newer host does not start
on Debian 12.

```
make stranger-test
```

builds the static package the way CI's `deb` job does (it needs `musl-gcc` and
`cargo-deb`) and runs them. Two environment variables drive them:

- `STOP_BOTS_STRANGER_DEB` names the `.deb` to install. Without it the three tests
  skip, and say so.
- `STOP_BOTS_STRANGER_FETCH=1` runs `batch --apply` with real downloads, exactly as
  written. Without it, `batch` gets `--no-fetch` and blocks from the list compiled
  into the binary, so a feed that is down cannot turn the suite red.

CI runs them as the `stranger` job, on pushes to main and weekly; the weekly run sets
`STOP_BOTS_STRANGER_FETCH`.

### Real traffic

The container suite's requests are written by hand, so they show that a detector
convicts what it was written for, not what it does to real traffic. Two things cover that.

A visitor test in `tests/container.rs` reads a 30-page site the way a browser does
(assets once, every page through a link) and runs every access-log detector over it:
none may convict it. Its control reads the same pages with no assets and no `Referer`,
and must be convicted, which shows the visit was long enough to judge.

`scripts/replay-logs.py` runs every detector in dry-run over a real host's logs, against
a database of its own, and reports who would be blocked, which of those look like
visitors or logged in over SSH, and the busiest addresses nothing convicts. Run it on
the host itself, with `--config-root`, so the probe check can look into the sites'
document roots:

```
sudo journalctl -u ssh -o short > ssh.log      # or /var/log/auth.log, where rsyslog runs
sudo journalctl -k -o short > kern.log         # or /var/log/kern.log
sudo scripts/replay-logs.py --access-log /var/log/nginx/access.log \
  --ssh-log ssh.log --kernel-log kern.log --config-root /etc/nginx > report.md
```

It reads and stores nothing of the host's own. The report names real visitors'
addresses, so it stays out of this repository and out of issues.

## CLI conventions

The command line is part of the contract from 0.1 on, so these are decided once. The
tests at the bottom of `src/main.rs` walk the whole command tree and check the parts a
machine can check.

- **A stored setting is changed by a `set-*` verb.** Every setting a person is meant to
  change has one: `set-detector`, `set-category`, `set-old-browsers`, `set-firewall-backend` and
  so on. Give a `set-*` verb no flags and it prints what is stored.
- **Flags on a verb that runs something apply to that run only.** `batch --backend`,
  `render-firewall --out`, `tick --ssh-log` and `run-detector --threshold`
  change nothing stored; without them the run uses what is stored.
- **A list of things has `add-*`, `remove-*` and `list-*` verbs**: `add-country`,
  `remove-country`, `list-selected-countries`; `add-trusted`, `remove-trusted`,
  `list-trusted`; `add-exempt-path`, `remove-exempt-path`; `add-firewall-rule`,
  `remove-firewall-rule`, `list-firewall-rules`. Never a `--remove` flag on the verb that
  adds.
- **`update-*` downloads, and is plural: every source of its kind, or one.**
  `update-bot-lists`, `update-crawler-ranges`, `update-reputation-sources` (every feed
  switched on) and `update-country-ranges` (every selected country) update all of them,
  and `--source-id` (`--country` for countries) narrows it to one. `--source <file>`
  reads one source from a file instead of downloading it.
- **One verb per action, with the thing it acts on as an argument**: `run-detector
  <detector>` and `set-detector <detector>`, not a verb per detector.
- **A stored on/off value takes an explicit value**: `--enabled true|false`. Both directions have to be sayable, and a bare flag can
  only say one. Declare it with `action = clap::ArgAction::Set` and
  `value_name = "true|false"`, as `bool` when the verb exists to set it and
  `Option<bool>` when it is one of several optional settings.
- **A presence flag is for how this run behaves**: `--force`, `--dry-run`, `--no-fetch`.
  Never for a stored value.
- **`status` and every `list-*` take `--json`**, which prints one JSON object built from
  the output structs in `src/output.rs`, never from a database type. A new `list-*` takes
  it too; a test at the bottom of `src/main.rs` checks.
- **`--db` is global** and falls back to `STOP_BOTS_DB`. Don't add a `db` field to a
  subcommand; clap refuses a subcommand argument that shadows a global one.
- **Help text is for someone typing commands.** Name other verbs as they are typed
  (`apply-blocks`), never as the Rust variant (`ApplyBlocks`), a table, or a module path.
  The first line of a doc comment is the summary in `stop-bots --help`: a whole sentence,
  starting with a capital, different from every other command's. Every flag says what it
  does.
- **Renaming.** The old spelling keeps working until the next major release, and says
  so on stderr. A renamed verb, or a verb and flag that became a verb, is a row in
  `DEPRECATED` in `src/main.rs`, which rewrites it to the new spelling before parsing and
  prints the warning; a test walks every row. A verb that still has its own behaviour
  stays as a hidden command (`#[command(hide = true)]`) that calls `deprecated(...)`.
  List it under **Deprecated** in the changelog, and remove it in the next major, under
  **Removed** (see "Versioning" in `RELEASING.md`).

## Code structure

Rust's project structure must be followed.

Some directories don't exist yet but should be created if the need arises.

```
<root of the repository>
    |- /src               <- The implementation
        |- main.rs        <- CLI entry point: what each subcommand does
        |- cli.rs         <- The command line itself: every verb, flag and help text (clap)
        |- lib.rs         <- Every module below, for main.rs and tests/; not a supported API
        |- app.rs         <- The TUI app controller, responds to events and controls the UI
        |- applylock.rs   <- One web server or firewall apply at a time, across processes (flock)
        |- event.rs       <- Terminal event plumbing (ticks, key events, app events)
        |- tui.rs         <- Outer TUI chrome (tab bar, footer) and screen dispatch
        |- tui/           <- One file per TUI screen (Dashboard, Bot settings, Firewall, ...)
        |- db.rs          <- SQLite storage: bots, sites, firewall rules, settings, ...
        |- db/schema.rs   <- The schema version and the migrations up to it
        |- db/keys.rs     <- Every `settings` key, spelled once
        |- db/managed.rs  <- The record of every generated file written, for cleaning up
        |- db/evidence.rs <- What the detectors have seen, and each log's read cursor
        |- db/blocks.rs   <- The Blocks views' pages, removal by source, and unblocks by hand
        |- botlist/       <- One file per bot-list source parser, and old_browsers.rs, the
        |                    compiled-in list of old browser agents behind its own switch
        |- fetch.rs       <- The one place an outbound HTTP request is made
        |- refresh.rs     <- "Update everything": every downloadable list as fetch-then-store, one at a time
        |- webserver.rs   <- What the web servers share: the policy, the apply (test, put back, reload), uninstall
        |- nginx.rs       <- NGINX: finding server blocks, rendering and placing its blocks and generated files
        |- apache.rs      <- Apache: finding <VirtualHost>s, its mod_rewrite blocks, trust file and robots.txt
        |- traefik.rs     <- Traefik: finding routers' hosts, and the routers file it writes beside them
        |- npmplus.rs     <- NPMplus: reading the hosts it renders, and its custom_nginx files every host includes
        |- hostconf.rs    <- /etc/stop-bots/host.conf: the web server, its commands and root, the logs
        |- logpaths.rs    <- Where this host's SSH and access logs are, remembered
        |- logscan.rs     <- One pass over the logs: plan, read (no Db), store
        |- logread.rs     <- Reading a log a line at a time, from where the last read stopped
        |- hostlog.rs     <- The logs the detectors read, a bounded piece per request
        |- logtime.rs     <- When a log line says it happened
        |- evidence.rs    <- What each detector counts, and the one decision over it
        |- sshlog.rs      <- SSH log parsing and scan detection
        |- portscan.rs    <- The port-scan detector: trap ports, what listens, the kernel log's lines
        |- accesslog.rs   <- Access log parsing (NGINX's, Apache's, Traefik's and NPMplus's), the web-log detectors, UA tallying
        |- injection.rs   <- Recognising an exploit payload in a logged request
        |- protocol.rs    <- Recognising a request that is not for a page: another protocol, or a proxy
        |- accessstats.rs <- What one pass tallied into the access-log UA stats
        |- cdn.rs         <- A CDN's edge addresses, which no detector blocks
        |- scanblock.rs   <- Shared CLI+cron logic for every detector's detect-and-block pass
        |- blocks.rs      <- Why a rule exists: its source, its evidence line, and unblocks
        |- trigger.rs     <- The log line behind a new block, when a whole log was read
        |- protection.rs  <- The detectors' on/off switches, their defaults, and why
        |- robots.rs      <- Reading a robots.txt: which paths it forbids to which client
        |- ipranges/      <- Crawler, country and third-party IP-range fetching/storage
        |- ipdetail.rs    <- Everything already known about one address (Firewall detail view)
        |- uadetail.rs    <- The same for one user agent string
        |- uaregex.rs     <- Matching a user agent against a list's pattern as the web server does
        |- health.rs      <- Is this host actually protected? The checks behind `status`
        |- hint.rs        <- Errors that name the next step (run with sudo, set-web-server)
        |- host.rs        <- The host name, and where the system programs this runs are
        |- install.rs     <- `stop-bots install`: the cron file and the firewall's boot unit
        |- install/       <- The firewall units 0.0.x wrote, to tell an old unit from an edited one
        |- uninstall.rs   <- `stop-bots uninstall`: the host back as it was
        |- batch.rs       <- Batch mode: one unattended pass, for a real crontab
        |- cron.rs        <- The schedule: which background jobs run how often, and `tick`
        |- docs.rs        <- Man pages and shell completions for the `.deb` (hidden `generate-docs`)
        |- dynamic.rs     <- What is hitting the server now, for the Firewall screen
        |- firewall.rs    <- The one render -> lockout guard -> write -> apply path, and its policy
        |- iptables.rs    <- iptables script generation
        |- nftables.rs    <- nftables script generation
        |- generated.rs   <- The `Generated by stop-bots <version>` header, and comparing past it
        |- present.rs     <- Relative times, category names and health labels, spelled once
        |- preview.rs     <- What "Apply everything" would change, for the confirmations and --dry-run
        |- diff.rs        <- Unified diffs, for those previews
        |- golden.rs      <- Golden-file comparison for generated output (tests only)
        |- testing.rs     <- Shared unit-test fixtures (tests only)
    |- /tests           <- Integration and end-to-end automated tests
    |- /examples        <- screenshots.rs, which generates docs/screenshots/
    |- /packaging       <- APT landing page, AUR PKGBUILDs, Gentoo ebuild, bump.py
    |- /scripts         <- build-apt-repo.sh (the APT repository), deploy-remote.sh and
                           replay-logs.py (every detector over a real host's logs)
    |- README.md        <- What the tool is and how to use it. High level only
    |- CONTRIBUTING.md  <- This file. How the code is built, tested and laid out
    |- RELEASING.md     <- The release process, versioning, and what counts as breaking
    |- SECURITY.md      <- Supported versions and how to report a vulnerability
    |- CLA.md           <- The Contributor License Agreement for code contributions
    |- ROADMAP.md       <- What 0.1 and 1.0 mean, and what stands between here and there
    |- CHANGELOG.md     <- What changed, per release
    |- AGENTS.md        <- AI-only instructions
    |- REVIEW.md        <- Comments about the codebase that need to be improved uppon
    |- TODO.md          <- List of small to  mid size TODO items that need to be fixed in the future
```

A README.md can exist in any subdirectory, and it always serves the same purpose: a high level
summary, readable by humans.

The TODO.md and REVIEW.md files are always only in the root of the repository.
