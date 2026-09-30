# Road to 0.1 and 1.0

Written 2026-09-28 against v0.0.15 (216 commits, 15 releases in 14 days, ~72k lines
including ~1,470 tests). Based on four read-only reviews of the codebase — stability
surfaces, robustness at scale, user experience, code health — with the load-bearing
claims re-checked by hand. `(verified)` marks those that were reproduced rather than
read.

## What the project is for

A single operator with one or a few NGINX servers who wants bad bots gone **without
putting a CDN in front**. It classifies known bots, reads the host's own logs to catch the
ones no list knows yet, and turns both into NGINX config and a firewall script. Three
principles run through everything and should survive every release:

1. **Nothing happens without you.** Everything is generated; applying is a separate,
   visible act.
2. **Don't lock out the operator.** The SSH guard, the "never block the address you're
   connected from" rule, `nginx -t` with rollback.
3. **No component in the request path.** Offline log analysis plus generated config. That
   is what makes JS challenges and TLS fingerprinting out of scope, and it should stay a
   stated boundary rather than a backlog item.

## What the version numbers mean

In cargo's semver, `0.0.x` promises nothing: every release may break you. **`0.1.0` is the
first release after which `0.1.1` is a promise** — a patch release fixes things and
breaks nothing. So "reaching 0.1" is less about features than about knowing what the
contract is, so that "breaking" can be told apart from "not breaking".

### 0.1 — safe for a stranger

Someone who is not the author installs it on an ordinary Debian or Ubuntu VPS (1 GB RAM,
one NGINX, logs as the distro ships them), follows only the README, and:

- is blocking bots within fifteen minutes;
- can see **why** any address is blocked, and undo one block or all of them;
- can remove stop-bots entirely and get the host back as it was;
- can upgrade to `0.1.x` or `0.2` without losing settings, and without the upgrade
  applying anything they didn't ask for;
- never gets the box starved of memory by the tool meant to protect it.

The contract from 0.1 on is **the CLI, the database, the files it writes and the paths it
uses**. The Rust library is explicitly *not* part of it.

What 0.1 is **not**: feature-complete. No new detectors or feeds are needed for it.

### 1.0 — trustworthy unattended, with a written compatibility promise

- A documented compatibility policy: CLI verbs and flags, settings, generated-file
  markers and paths change only with a deprecation period of one minor release, with
  warnings.
- Upgrades from **any** 0.1+ database tested in CI.
- Detection is time-windowed everywhere; repeat offenders escalate.
- Bounded, measured resource use on a large host (a 1 GB log, 100k blocked ranges) with a
  benchmark that fails CI on regression.
- Default behaviour never changes silently on upgrade — a new detector arrives *off* on an
  existing install and is announced, however safe it looks.
- Machine-readable output (`--json`) for anything a script would want to read.
- Packaging (APT, AUR, Gentoo) updated by the release pipeline, not by hand.
- Used on hosts the author doesn't run, with issues coming from them.

**A suggested change to `RELEASING.md`:** it says designing the library API deliberately is
a prerequisite for 1.0. I'd drop that. The product is the binary; a designed Rust API is a
second product with its own users, and nobody has asked for it. Hiding the library for good
is the cheaper and more honest 1.0.

---

## Checklist for 0.1

Sizes are rough: **S** an afternoon, **M** a day or two, **L** most of a week.

### A. Don't hurt the operator

- [x] **One firewall path.** Render → lockout guard → write → apply exists five times
  (`app.rs:308`, `web/dashboard.rs:1466`, `cron.rs:710`, `batch.rs:405`,
  `main.rs:2909`). They handle "no SSH log readable" four different ways. That is the one
  path that can take a server off the network. Make it one function with a typed outcome,
  and leave each front-end only the message. **M**
- [x] **The boot unit loads only what was explicitly applied.** The internal cron rewrites
  `/etc/stop-bots/firewall.nft` even when the guard could not run (`cron.rs:741`), and
  `stop-bots-firewall.service` loads that file at boot. A reboot can therefore enforce
  rules nobody applied. The cron should write a staging file; only an apply promotes it. **S**
- [x] **Confirm and preview before "Apply everything".** `a` in the TUI and the web button
  inject into every site and run the firewall script as root, on one keypress. Show a
  summary (sites changed, rules added and removed, the guard's result) with a diff on
  request, and add `--dry-run` to `apply-blocks` and `batch`. **M**
- [x] **`stop-bots uninstall`** with `--dry-run`. It removes the injected site blocks, the
  managed `conf.d` files, the nft table or iptables chain, and both units. Today nothing
  removes any of them. **M**
- [x] **Memory and CPU bounded on a 1 GB VPS.** Each detector job re-reads and re-parses
  the whole access log itself: about ten full reads a minute, at roughly twice the file
  size in memory each. The TUI starts them concurrently. The fixes:
  - read once per tick and share the text, as `batch` already does;
  - skip the read when every consumer is disabled;
  - stream from a byte offset (keyed by inode) instead of `read_to_string`;
  - parse outside the web console's DB lock.

  www has a 72 MB log and 962 MB of RAM *(verified)*. **L**
- [x] **The journald fallback reads the whole sshd journal** each minute, on every Firewall
  page view and in every lockout check (`sshlog.rs:84`, *verified*). This is the default
  path on Debian 12+ and Fedora. Use `--since` plus a stored cursor. **S**
- [x] **nftables sets instead of one rule per address.** www's table is 44,547 lines with
  no sets *(verified)*, so every new connection walks a linear chain. Use named interval
  sets per family and verdict. As a bonus, per-element `timeout` makes expiry happen in the
  kernel, which fixes the next item on the nft side. **M**
- [x] **Expiry that actually expires.**
  - An expired block is only deleted from the database; the kernel keeps it until someone
    applies again.
  - Detectors count over the whole log since the last rotation and ignore timestamps, so
    once a block expires the same old lines re-add it at the next tick. A "1-day" block
    lasts until logrotate; with journald it is effectively permanent.
  - The minimum is to parse the timestamp both log formats already carry and give each
    detector a window. The README's "expires on its own and is re-added if the behaviour
    continues" is not true today. **M–L**
- [x] **iptables: be honest about scale.** One `iptables -A` process per rule after a
  flush, with no `-w`, so the chain sits empty while tens of thousands of processes run.
  IPv6 is silently skipped, including every `/64` a detector writes. For 0.1, either
  switch to `iptables-restore --noflush` for the one chain, or refuse feeds and geo
  blocking on iptables and label it IPv4-only in the UI. **S** (label) / **M** (restore)

### B. Upgrades don't break you

- [x] **Schema versioning.**
  - Use `PRAGMA user_version` with an ordered list of migrations. Today's schema, plus the
    two ad-hoc fixes in `init_schema`, is version 1.
  - Copy the database before migrating.
  - Refuse to open a database newer than the binary.
  - Add fixture databases from 0.0.1 and 0.0.15, and a test that opens each.

  Today there is no version at all (`db.rs:1066–1413`), and an older binary silently
  reinterprets values it doesn't know. **M**
- [x] **Unit templates vs. user edits.** `install` treats "differs from what *this*
  version would write" as "the user edited it". Every template change in a release
  therefore reads as an edit, and a re-install refuses without `--force`. Embed a template
  hash or version and compare against that. **S**
- [x] **Generated files carry the generator version** in their header, never in the
  markers. **Freeze the marker strings.** Record what was written (in the database or a
  manifest) and clean up from that record, not from a hard-coded list of names. **S**
- [x] **A defaults policy for upgrades.** v0.0.15 turned a new detector on for every
  existing install. From 0.1, something new that blocks arrives off on an existing
  database, or at least lands in a "new since your last version" notice. **S**
- [x] **One registry of settings keys.** About forty keys in three naming styles across
  nine modules. A rename silently orphans the old value. **S**

### C. Surfaces that tell the truth

- [x] **Fix `--help`** *(verified)*. Doc comments are attached to the wrong variants:
  - `web --help` says "Set what NGINX sends a blocked request";
  - `set-log-paths` shows the `set-nginx-commands` text;
  - `set-nginx-commands` has no description at all;
  - `status` shows `batch`'s text;
  - `batch` starts mid-sentence.

  Add a test that every subcommand's description is non-empty and unique. **S**
- [x] **Declare the contract.**
  - Put the library behind `#[doc(hidden)]` or a `pub mod internal`.
  - Say in the README and the crate docs that there is no supported Rust API.
  - Update `RELEASING.md` and `SECURITY.md` (the supported-versions table becomes "latest
    0.1.x"). **S**
- [x] **CLI conventions, decided once.**
  - Booleans come in three forms today (`--enabled true`, `Option<bool>`, presence flags).
  - Settings persist two ways (`set-*` verbs vs `web --save`).
  - `--db` is repeated on every subcommand instead of being global, and there is no
    `STOP_BOTS_DB`.
  - `render-firewall` requires `--backend` even though one is stored, and defaults `--out`
    to `.nft` even for iptables (`main.rs:237`, *verified*).

  Rename freely now, with hidden aliases for one release. **M**
- [x] **CLI verbs for what only the UIs can do.**
  - detector on/off, TTL and thresholds;
  - category defaults and per-bot status;
  - enabling and disabling a firewall rule;
  - `web:secure_cookie` and `web:trust_forwarded_for`.

  A host run only by `batch` can't switch off the injection detector today.
  Thresholds are hard-coded for the cron (`scanblock.rs:179`), and subnet escalation,
  which the README advertises, can't be set anywhere. **M**
- [x] **Say when a log doesn't parse.** A custom `log_format` parses to zero lines, and
  health then reports OK "no requests recorded yet". Compare non-empty lines with parsed
  lines, warn below about half, and show one sample line. **S**
- [x] **Use the stored log paths everywhere.** `set-log-paths` is ignored by:
  - `batch`;
  - the lockout guard;
  - the web Firewall page and the TUI SSH panel;
  - the access-stats offset, which is keyed by the default path while the stored one is
    read. **S–M**
- [x] **Docs fit for a newcomer.**
  - A quick start near the top: APT install, `sudo stop-bots`, `u`, review, `a`,
    `install firewall` for persistence (not in the README today), then `status`.
  - Supported platforms, stated: Debian/Ubuntu, systemd, NGINX. Not Apache or Caddy.
  - Correct the wrong claims:
    - `SECURITY.md` says every detector is off by default; five are on.
    - The README says "four screens" in one place and "five" in another.
    - The README says blocks "expire on its own".
    - The README describes a Firewall-screen capability that is CLI-only.
  - Reconcile "Contributions are not accepted" with `CONTRIBUTING.md`: one line saying it
    describes how the maintainer works. **M**

### D. Explain every block

- [x] **Why is this address blocked?**
  - `firewall_rules` has no source, reason or evidence.
  - Blocks from the four web-log detectors appear in neither UI: the Firewall screens list
    only SSH-log addresses, and rules themselves are CLI-only, by id.
  - Add a detector column, `created_at` and one evidence line (the request that triggered
    it). Add a Blocks view in both front-ends, filterable by detector, with "unblock all
    from this detector".

  With five detectors on by default, this is the difference between "nothing happens
  without you" and "things happened and you can't see them". **L**

### E. Release engineering

- [x] Gate `release.yml` on the test job, and run the tests on `ubuntu-24.04-arm`: the
  aarch64 binary is shipped but only `--version` is ever run. **S**
- [x] Merge dependabot #8 and #9. **S**
- [x] AUR and Gentoo are seven releases behind (0.0.8). Script the version bump, or mark
  them unmaintained in `packaging/README.md`. **S**
- [x] Housekeeping:
  - `REVIEW.md` has an empty Pending section, 29 finished items and nine references to the
    deleted SPECS.md.
  - `TODO.md` quotes old line counts.
  - `CONTRIBUTING.md`'s module list is missing eight modules.
  - Two different coverage figures are quoted. **S**
- [x] **A stranger test.** A fresh Debian 12 and Ubuntu 24.04 VM (or a Podman container
  with systemd), README only, start to "blocking" to `uninstall`. Automate as much as the
  container suite can hold. **M**
- [ ] **A release candidate that soaks.** `0.1.0-rc.1` runs on www and the home server
  for two weeks with the web console up, and nothing ships in between that isn't a fix
  for it. **—**

### Should fix for 0.1, but wouldn't hold it

- SQLite WAL mode; a UNIQUE index on `firewall_rules` with `INSERT OR IGNORE` (TUI, web and
  `batch` can race into duplicates); an `flock` around apply.
- `Nice=`, `IOSchedulingClass=idle` and `MemoryHigh=` in the web unit.
- A visible banner when the database fell back to `~/.local/share` because you aren't root.
  Today the only warning goes to stderr, just before the TUI's alternate screen hides it.
- Errors that name the next step (ENOENT on `nginx` → `set-nginx-commands`, EACCES → "run
  with sudo").
- A weekly "update everything" job in the internal cron. Today lists go stale unless
  `batch` or `u` runs.
- Stop "Update everything" and the cron from fetching the same feeds at once.
- Offer only the firewall backend that is installed.
- Warn when detections look like CDN edge addresses.
- `App::message` outside the Dashboard; the "(f)" in messages that means `F`.
- One `present` module for relative times, category labels (casing differs between the TUI
  and the web) and health-check labels.
- nextest retries for the container suite, with retries counted.
- Man page and shell completions in the `.deb`.
- Per-site bot overrides in the web console; crawler-range sources in either UI.

## After 0.1, towards 1.0

Roughly in the order they would matter to a user:

1. **Time windows everywhere, then escalating TTLs**, with an offence count per address.
2. **Several access logs**, taken from the `access_log` directives already parsed, plus
   rotated `.1`/`.gz` files on the first scan.
3. **`--json`** on `status` and every `list-*`.
4. **A resource benchmark in CI**: a 1 GB log and 100k ranges, with budgets.
5. **Upgrade tests from every released 0.x** database and generated file.
6. **IPv6 for iptables**, or an explicit IPv4-only backend with nftables as the
   recommendation.
7. **SSH detection on key-only hosts**: `Connection closed by authenticating user …
   [preauth]` and `maximum authentication attempts exceeded`.
8. **One job layer for both front-ends.** The TUI's in-flight interlock, the cron dispatch
   and each screen's data loading exist twice today (`app.rs` vs `web/cron.rs`,
   `tui/dashboard.rs` vs `web/dashboard.rs`).
9. **Structural debt**, when it earns its keep: `Commands` out of `main.rs`, `db.rs` by
   concern.
10. **Release pace and the changelog.** After 0.1, patch releases for fixes only, with
    features batched into minors. Changelog bullets of one to three lines, with the
    reasoning in commits. It is 1,484 lines after two weeks and ships in the `.deb`.

Out of scope for 1.0, stated rather than deferred: JS or proof-of-work challenges, TLS
fingerprinting, and anything else that needs a component in the request path.

## Suggested order

1. **Contract first** (B, and C's "declare the contract" and "CLI conventions"). Every
   later change is then made on versioned ground and with the final names.
2. **Safety** (A's first four items and D), because they change what the UIs show and do.
3. **Scale** (log reading, journald, nft sets, expiry and windows). One piece of work
   around "read the log once, incrementally, with timestamps".
4. **Docs and the stranger test**, last, against the finished behaviour.
5. **RC and soak.**
