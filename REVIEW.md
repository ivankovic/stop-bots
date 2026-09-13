# Pending

# Completed

- ✅ Two bugs from one deployed host, both "the backend was decided in one place
  and something depending on it in another". See "The firewall backend is the
  single source of truth" in SPECS.md.
  - The console could not apply the firewall **at all** under the unit
    `install web` writes: `RestrictAddressFamilies` omitted `AF_NETLINK`, under
    a comment claiming the service never applies anything — true when written,
    false the moment applying was added. Diagnosed before changing anything by
    reproducing it with `systemd-run --user -p RestrictAddressFamilies=...
    ip link show`, which prints the same message. Allowed now, plus a
    `sandbox_hint` that names the directive, since nft's own error mentions
    neither systemd nor this project. Existing installs need
    `install web --force`.
  - The path no longer drifts from the backend, and — found while fixing it —
    `cron::render_firewall` hardcoded nftables, so on an iptables host every
    tick overwrote the operator's script with the wrong syntax at the same
    path and the next apply ran `sh` over it. That was the more dangerous half.
  - `make deploy` fixed separately in the same session: it copied to the login
    directory and restarted nothing, so on this host every command succeeded
    and the console kept serving the previous build.

- ✅ `make deploy` did not deploy. It was `scp ./target/release/stop-bots www:`,
  which lands the binary in the login directory and restarts nothing. That
  happened to be the path the unit ran until `install web` was re-run with the
  binary in `/usr/local/bin`; after that, deploying wrote a file nothing
  executes while the console carried on serving the previous build. The failure
  mode is that every command succeeds and the change simply is not there.
  Now stages next to the target and renames into place (writing over a running
  executable is ETXTBSY), `try-restart`s the unit when one exists, and prints
  the unit's ExecStart and the deployed file's timestamp — because
  `--version` reports `0.0.1` for every build of a `0.0.x` and so cannot tell
  two builds apart, which is exactly the confirmation that was missing.

- ✅ Fixed the documentation the previous change made wrong. The console's Help
  screen listed "apply the firewall script" and "download country or crawler IP
  ranges" as deliberate omissions with reasons — both had just become
  capabilities, and a help screen that is confidently wrong is worse than one
  that is silent. Replaced with a panel explaining the two buttons that change
  the host and the anti-lockout refusal that makes a one-click apply
  defensible, plus a new panel for the Web Access modes including the cleartext
  caveat on subdomain mode. Two regression tests: one asserting the retired
  omission's wording is gone *and* the replacement is present, one asserting
  both Web Access modes and the `certbot` fix are on the page.
  - README: "three things are missing on purpose" is now two, with the third
    recorded as having changed and why; "Nothing happens without you" now names
    all three ways to apply rather than two; added the Web Access panel, the two
    Dashboard buttons and the Dynamic Protection `i` key.
  - `firewall::apply_script`'s doc comment said "exactly two callers". There are
    three now. That comment was rewritten during the security pass precisely
    because it had been wrong, so letting it go stale again would have been the
    same mistake twice.
  - The unreleased CHANGELOG contradicted itself: the web-UI entry said it
    "writes the firewall script but never runs it" while a later entry in the
    same release said it does. Fixed, with the reversal noted rather than
    quietly edited out.
  - `src/tui/help.rs` needed no change — it documents keys, and every key it
    lists still does what it says.

- ✅ Four requests, shipped as two changes. See "Web Access, \"Update
  everything\", \"Apply everything\", and applying the firewall from the
  console" in SPECS.md.
  - New `src/refresh.rs` so "everything" means one thing. `batch::update_lists`
    could not be reused from the console — an `async fn` holding `&Db` across
    every fetch, and `Db` is not `Sync` — so it was rewritten on the shared
    plan rather than duplicated. A button that skipped reputation feeds or
    selected countries would have left the UI still telling you to run a CLI
    command.
  - Selecting a country deliberately does **not** download, against the
    obvious fix of matching the TUI. Fetching on POST blocks a request
    handler on hundreds of kilobytes from a third party, and it made
    `the_geo_mode_and_country_selection_round_trip` reach ipdeny.com —
    0.35s to 0.93s of real HTTP, which is how it was caught. The message now
    names the "Update everything" button instead of a CLI command.
  - The console can apply the firewall script now, reversing one of its three
    deliberate omissions on request. Same anti-lockout refusal as
    `batch --apply`, gated by `apply_for_real` so `--no-apply` keeps the old
    behaviour, and it runs the script that was just written rather than a
    freshly derived one.
  - The Web Access panel's NGINX writes go through `write_validated`: write,
    `nginx -t`, roll back on failure. `apply_all_sites` writes-then-tests,
    which is fine for an edit — but a new `server` block that does not parse
    leaves the whole config unloadable while the running NGINX keeps serving
    from memory, so the failure surfaces at somebody else's reload.
  - Path mode writes three things that must agree: the `location` block,
    `web:base_path` and `web:allowed_hosts`. Missing the second makes every
    link leave the location block; missing the third makes every request a
    403. Both look like a broken console rather than a missing setting.

- ✅ Fixed a real `install web` failure reported from a Debian host:
  `./stop-bots install web` from `/root` wrote `ExecStart=/root/stop-bots`,
  which systemd could not execute because the unit's own `ProtectHome=yes`
  makes `/root` empty for the service — `status=203/EXEC`, "No such file or
  directory", for a file that was plainly there. `preflight` checked that the
  binary existed on the *installer's* filesystem, never that it existed
  inside the sandbox the unit itself asks for. See "`install web`: the binary
  has to exist inside the unit's own sandbox" in SPECS.md.
  - The first fix was dead in production. It gated the new check on a
    `real: bool` that only `Layout::system` set — and `main.rs` never calls
    `Layout::system`, it calls `Layout::under` with a prefix defaulting to
    `/`. All 21 install tests passed while the check never ran on the one
    path that matters. Caught by reproducing the reported failure against the
    built binary; the flag is now derived inside `under` from the prefix, so
    no caller can forget it.
  - Fixed alongside: a relative `--binary` (systemd rejects such a unit at
    load time, which does not present as a failed service), and a failed
    `systemctl enable --now` not saying that the enable half stuck and the
    unit would try again at the next boot.

- ✅ Per-address detail on Dynamic Protection (`i` in the TUI, clicking the
  address in the web console), built after weighing reverse DNS and whois and
  deciding against both: each is an outbound request per row to infrastructure
  the attacker often controls, and a PTR record is authored by whoever holds
  the address. What the host already downloads — six reputation feeds, three
  crawler range sources, the fetched country zones — answers most of the same
  question offline and instantly, and the crawler answer is better than whois
  gives, since being inside Google's published ranges is what a user agent
  string cannot fake. New `src/ipdetail.rs`; `sshlog` now keeps the
  failed-login usernames it used to parse past, capped and stripped of control
  characters at the parser because they are whatever the client sent. See
  "Per-address detail on Dynamic Protection" in SPECS.md.
  - Caught while building it: adding one line to the TUI help pushed the last
    line — how to close the help screen — off the bottom. The file's comment
    already warned that adding an entry means merging another; a comment was
    not enough, and the only thing that noticed was a pty test timing out
    fifteen seconds later. Now a `MAX_LINES` constant with a `debug_assert`
    and a unit test that renders at the harness's size, verified to fail when
    a line is added.
  - Caught by measuring rather than assuming: the first version built the
    username breakdown for every address on every refresh, which took
    `Live::load` from 78ms to 293ms on a 120,000-line auth.log — paid by
    both front-ends whether or not anyone opened a detail. Now scoped to
    the one address asked about (45ms, on the keypress), routed through
    `KeyOutcome::InspectAddress` so `App` supplies the log text it already
    holds. `src/dynamic.rs` ends up unchanged.
  - Reported, not fixed: a username containing the literal `" from "` defeats
    `sshlog::ip_after` and so drops the line from every count in that module,
    `scanning_ips` included. Pinned by a test, recorded in TODO.md — narrowing
    it changes which lines scan detection counts, which is its own change.

- ✅ Security and robustness pass over the whole repository, scoped to the
  four categories `SECURITY.md` says are in scope. Three findings, each
  confirmed by running the code rather than by reading it, all fixed — see
  "Security pass: untrusted feeds, an unbounded write, and unbounded
  fetches" in SPECS.md for the full account.
  - **A line from a downloaded IP-range feed became a root shell command.**
    `replace_ip_ranges`, `replace_country_ranges` and
    `replace_reputation_ranges` validated nothing, and the addresses they
    store are interpolated verbatim into a generated firewall script that
    `batch --apply` runs under `sh`. Confirmed:
    `1.2.3.4/24; touch /tmp/pwned` rendered as
    `iptables -A STOP-BOTS -s 1.2.3.4/24; touch /tmp/pwned -j DROP`. On
    nftables the same shape reaches `nft -f`, where `; flush ruleset` drops
    the host's whole firewall. `looks_like_address`, meant to be the guard
    for the six reputation feeds, only inspected the part before the first
    `/`. Fixed by routing all four address tables, both renderers and that
    filter through one validator; feed entries are dropped rather than
    failing the batch. **This reverses the decision recorded below** that
    "crawler/country-derived CIDRs still bypass this check ... since those
    come from trusted upstream sources" — reputable is not uncompromised,
    and `SECURITY.md` says so explicitly.
  - **The web console could write a root-owned executable file anywhere on
    the host**, because "Write script" took its destination from a free-text
    form field. That is a way around every restriction the console is built
    around. Fixed: it writes to the path the server was started with, via
    the new `stop-bots web --firewall-out`, and takes no destination from
    the request.
  - **No upstream fetch had a timeout or a size limit.** Six bare
    `reqwest::get(...).text()` calls, now one shared client in the new
    `src/fetch.rs` (60s total, 10s connect, 5 redirects) with a 32MB cap
    checked against both the declared length and the arriving bytes.
  - Two smaller ones fixed alongside: an address was validated trimmed and
    stored untrimmed, so `"1.2.3.4\n"` was written into the middle of a rule
    line (under iptables' `set -e`, that aborts the script partway through);
    and `firewall::apply_script`'s doc comment claimed no unattended caller
    exists when `batch --apply` is exactly that, which is the wrong answer
    to the one question anyone reads it to ask.


Each entry describes a change as it was made, and is not kept up to date
afterwards — several below have since been superseded (the internal cron
runs from the web UI as well as the TUI now; `src/botlist.rs` is a
directory). For what the code does today, read SPECS.md; for what changed
and when, CHANGELOG.md and the git log.

- ✅ Reported: the Dashboard's "Scheduled tasks" panel showed "last ran never, due now" for a job that never actually ran. Root cause: `App::new` initialized `last_cron_check` to `Instant::now()`, so the very first `check_cron` call (on the first `Event::Tick`, a fraction of a second after startup) was throttled away for a full `CRON_CHECK_INTERVAL` (60s) — a job due the instant the TUI opens would sit displaying "due now" without actually running for up to a minute. This was always true but negligible back when the detection jobs ran hourly/every-4-hours; it became user-visible once `BlockScanners`/`BlockWebScanners`/`RecordAccessStats` were sped up to run every 60 seconds (see below), the same as the check throttle itself, making that fixed startup delay comparable to the entire interval. Fixed in `src/app.rs` by backdating `last_cron_check` by a full `CRON_CHECK_INTERVAL` at construction (`checked_sub`, falling back to `Instant::now()` if the process started within that long of system boot), so the first tick's check already passes the throttle. New regression test `a_freshly_constructed_app_runs_due_jobs_on_its_first_check` calls `check_cron` right after `App::new()` with no manual backdating (unlike the existing cron tests, which simulate a later tick) — confirmed it fails without the fix.
- ✅ Sped up attack detection per user request ("detect attacks as they happen"): `CronJob::BlockScanners`/`BlockWebScanners`/`RecordAccessStats` intervals cut from 4 hours/hourly/hourly down to 60 seconds each (`src/cron.rs`), the practical floor since `App::check_cron` itself only re-checks which jobs are due once a minute (`CRON_CHECK_INTERVAL` in `src/app.rs`) — going faster would need shortening that constant too, not just the jobs' own `interval()`. `UpdateIpRanges`/`RenderFirewall` stay daily, since neither is time-sensitive.

- ✅ In /home/m/src/stop-bots/src/main.rs on line 628: Added documentation explaining why we DON'T use 0.0.0.0/0 catch-all rules with iptables. The issue is twofold: (1) iptables is IPv4-only, so the ::/0 IPv6 catch-all would be silently skipped, leaving IPv6 traffic unblocked; and (2) without explicit allow rules for established connections and loopback, a 0.0.0.0/0 rule would block existing connections and local traffic. Added safety rules (established/related and loopback ACCEPT) to iptables::render to address issue #2, but issue #1 remains fatal — hence allowlist mode requires nftables. See updated documentation in iptables.rs and improved error message in main.rs.
- ✅ How are iptables rules applied from the TUI? Added a new 'f' key binding in the Dashboard that opens a popup for firewall rule rendering. Users can select backend (nftables or iptables) and edit the output path, then confirm to generate the firewall script. Rendering logic (rule gathering, the allowlist/iptables guard, and the lockout safety check) was pulled out of `main.rs` into a shared `src/firewall.rs` library module; the TUI calls it directly (`App::render_firewall`) instead of shelling out to a `stop-bots` subprocess — the old subprocess approach relied on `stop-bots` being on `$PATH` under that exact name, which silently broke the feature under `cargo run` or any non-PATH install. The CLI's `render-firewall` subcommand is now a thin wrapper around the same module.
- ✅ Code review of firewall IP-manipulation correctness found `db::is_valid_address` didn't bound-check a CIDR's prefix length (e.g. `1.2.3.4/999` or `1.2.3.4/40` passed validation) — on iptables, whose generated script runs individual commands under `set -e`, a rule like that would fail at apply time and abort the script partway through, having applied only some rules. Fixed to reject any prefix outside 0-32 (IPv4) / 0-128 (IPv6). Crawler/country-derived CIDRs still bypass this check, same as before — left as-is since those come from trusted upstream sources, not admin input.
- ✅ Parse the SSH log and identify scans, adding them to the blocklist. New `stop_bots::sshlog::scanning_ips(log_text, threshold)`: flags IPs with `>= threshold` failed-authentication log lines, excluding any IP that also has a successful login anywhere in the same log (never auto-block a client that's proven itself legitimate) and any loopback/private address. New `block-scanners` CLI subcommand adds a `firewall_rules` Block row per flagged IP (idempotent, `--dry-run` available); storage-only, same as every other row in that table — has no effect until `render-firewall` renders and the admin applies it, which is what makes it reasonable to run unattended. See "SSH scan detection" in SPECS.md.
- ✅ Also add NGINX access-log scanning: look for crawlers hitting many invalid URLs. New `stop_bots::accesslog::scanning_ips(log_text, threshold)` (new `src/accesslog.rs` module) flags IPs with `>= threshold` *distinct* 404-returning paths — deliberately distinct-path count, not raw hit count, so a client repeatedly hitting one dead link never looks like a scanner. Deliberately has no "had a 200" exclusion (unlike the SSH version): a scanner's own recon traffic almost always includes a successful hit, so that exclusion would neuter detection rather than protect anyone. New `block-web-scanners` CLI subcommand, same storage-only/idempotent/`--dry-run` shape as `block-scanners`. `is_local_or_private` moved from `sshlog.rs` to `ipranges.rs` so both modules share it. See "Web scan detection" in SPECS.md.
- ✅ Caught before shipping: dropping the "had a success" exclusion for web scan detection meant a real Googlebot/Bingbot/GPTBot chasing stale links would routinely clear the distinct-404 threshold and get auto-blocklisted — directly against this project's "stop bad bots, still allow good bots" premise. Asked the user how to handle it; chose "exclude known crawler IPs". Added `main.rs::known_crawler_ranges`/`known_crawler_match`: before adding any Block rules, `block_web_scanners` fetches every CIDR already stored for the three `ipranges::IpRangeSourceKind::ALL` sources (Googlebot/Bingbot/GPTBot) and drops any candidate IP inside one of them, printing how many were skipped. If none of those sources has ever been fetched, prints a warning that the exclusion is inactive rather than silently providing no protection.
- ✅ Add timeouts to auto-detected scanner IPs: 5 days for `block-scanners` (SSH), 1 day for `block-web-scanners` (NGINX) — resolves the "no expiry" known limitation noted above. New `firewall_rules.expires_at` column (this project's first schema migration — `NULL` for a permanent hand-added rule, a Unix timestamp for a temporary auto-added one; guarded `ALTER TABLE ADD COLUMN` for existing databases alongside the `CREATE TABLE` for fresh ones, see "Firewall integration" in SPECS.md). New `Db::add_firewall_rule_with_ttl` (used by both `block-scanners`/`block-web-scanners`, each with a new `--ttl-days` flag defaulting to 5/1 respectively) and `Db::prune_expired_firewall_rules`, called from inside `Db::list_firewall_rules` so every consumer — rendering, `list-firewall-rules`, the scanner commands' own dedup check — automatically sees an already-pruned table. That last part is load-bearing, not just tidy: pruning on the same read the dedup check uses is what stops a lapsed block from ever producing a duplicate row when the same IP gets re-flagged later. The expiry only takes effect in the database; the actual host-level block still only lifts once `render-firewall` re-renders and is re-applied — same "generate-only" caveat as everything else in that table. `list-firewall-rules` now shows `(expires in Nd)`/`(expires in Nh)` next to temporary rules.
- ✅ Add an internal cron: timers running each automatable action (`update-ip-ranges`, `block-scanners`, `block-web-scanners`, `render-firewall`) at its own best-fit frequency, with state shown in the Dashboard, instead of relying on an external cron. New `src/cron.rs` (`CronJob` enum: id/label/interval — daily/4h/hourly/daily respectively — plus `due_jobs`/`status`), new `Db` methods `get_cron_last_run`/`set_cron_last_run`/`get_cron_last_summary` reusing the existing `settings` table (no second migration). Detection logic that used to live directly in `main.rs`'s `block_scanners`/`block_web_scanners` was pulled out into a new `src/scanblock.rs` library module (`ScanBlockOutcome`, `block_ssh_scanners`, `block_web_scanners`) so the CLI and the cron job call the exact same code — the CLI wrappers now just resolve the log source and reconstruct their existing wording from the returned outcome. `App::check_cron`, throttled to once a minute against `Event::Tick`'s 30fps rate, runs the three purely-local jobs (`BlockScanners`/`BlockWebScanners`/`RenderFirewall`) inline and spawns a background fetch (same `Db`-isn't-`Sync` pattern as `start_source_update`/`start_country_select`, guarded against overlap) for the one job needing network I/O (`UpdateIpRanges`). New Dashboard "Scheduled tasks" panel shows each job's last-run (relative time) and last outcome. **Biggest caveat, called out explicitly in SPECS.md and here:** this only automates while the TUI is open — there's no headless daemon mode, and closing the TUI pauses every job; also, if every job is overdue when the TUI opens (e.g. a fresh install), all four fire together on the first tick past the 60s throttle, including `UpdateIpRanges`'s outbound fetch — opening the dashboard can make network calls without an explicit user action. `RenderFirewall`'s cron job still only writes the script (to `firewall::DEFAULT_OUTPUT_PATH`, moved there from a `dashboard.rs`-local const so both share it); applying it remains a manual step, preserving the generate-only design intact.
- ✅ Caught before shipping (writing the cron's own tests surfaced it, since the CLI's earlier tests all happened to use paths that already existed): `render-firewall` — CLI, TUI popup, and the new cron job alike — wrote its script with plain `std::fs::write`, which doesn't create missing parent directories. `DEFAULT_OUTPUT_PATH` is `/etc/stop-bots/firewall.nft`, and nothing in the codebase creates `/etc/stop-bots/` (unlike the database's `/var/lib/stop-bots`, which `open_or_fallback` creates on demand) — so on any host where an admin hasn't already `mkdir`ed it, every one of those three call sites would fail with "No such file or directory". The CLI and TUI popup at least surface the error to a human who can `mkdir` and retry; the cron job has nobody watching, so it would fail silently on every single tick forever. Fixed with one shared `firewall::write_script(out, script)` (`create_dir_all` on the parent, then write) used by all three call sites instead of raw `std::fs::write`.

- ✅ Exploratory testing found: the Dashboard should allow changing the
  system-wide settings, with up/down cycling through them the same way Bot
  settings already did. The Dashboard's "Overview" panel (`src/tui/dashboard.rs`)
  is now a navigable list of the three category defaults; Enter opens the
  same Allowed/Blocked popup Bot settings used to own for them.
- ✅ Exploratory testing found: Bot settings shouldn't show the system-wide
  bot-blocking settings — moved to the Dashboard (see above); Bot settings
  no longer has category rows.
- ✅ Exploratory testing found: Bot settings should list all bot-list
  sources (last updated, signal count), with arrow keys to select one and
  Enter popping a confirmation dialog before updating it. Added to
  `src/tui/bot_settings.rs`, alongside (not replacing) the existing per-bot
  override list. Confirming "Update now" fetches and stores the source's
  bots without blocking the UI thread — see the `KeyOutcome::UpdateSource`
  / `AppEvent::SourceUpdateFinished` plumbing in SPECS.md.

- ✅ Implemented SQLite storage (`src/db.rs`): sources, bots, sites, and
  global per-category default settings, with manual bot overrides surviving
  bot-list refreshes.
- ✅ Implemented NGINX site discovery and bot-blocking config injection
  (`src/nginx.rs`): walks a config root for `server {}` blocks and
  idempotently injects/removes a sentinel-marked `if ($http_user_agent ...)`
  rule per site.
- ✅ Implemented bot-list download/parsing/storage from ArcJet
  Well-Known Bots (`src/botlist.rs`).
- ✅ In `src/main.rs`: CLI with clap, subcommands `scan-sites`/`scan`,
  `update-bot-lists`/`update`, `apply-blocks`.
- ✅ Implemented firewall rule storage and generation (`firewall_rules` table
  in `src/db.rs`, `src/iptables.rs`, `src/nftables.rs`): admin-managed
  IP/CIDR allow/block/reject rules, rendered into idempotent, narrowly-scoped
  iptables/nftables scripts. Generates only — never shells out to
  `iptables`/`nft` itself (a deliberate choice; see SPECS.md and TODO.md).
- ✅ Implemented the TUI (`src/app.rs`, `src/event.rs`, `src/tui.rs`,
  `src/tui/`), following the Ratatui event-driven-async template: Dashboard
  (default overview, with editable category defaults — see below), Bot
  settings (bot-list sources + per-bot overrides, each via a popup), Site
  settings (read-only site list), Help — matching the screen names/roles
  already decided in the entries below. Running the binary with no
  subcommand now launches it, per README.
- ✅ Added an automated e2e test for the TUI (`tests/tui.rs`), driving the
  real compiled binary through a pty via `rexpect` (`assert_cmd` can't do
  this — no pty). Turns the manual tmux-verification session below into a
  repeatable regression test covering the same flow.
- ✅ Fixed `cargo run`/`stop-bots` (no `--db`) failing with permission denied
  trying to create `/var/lib/stop-bots` as a non-root user: `--db` is now
  `Option<PathBuf>` everywhere, and `open_db` falls back to a per-user XDG
  path when the system path isn't writable, printing which path it picked.
  An explicit `--db` is still honored as-is and fails loudly if it's bad.

