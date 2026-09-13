# Changelog

Notable changes per release. Versions follow [semver](https://semver.org), with the
caveat that `0.0.x` means cargo treats *every* release as potentially breaking — which is
the intent while the library API in `src/lib.rs` is still whatever the binary happened to
need.

## [Unreleased]

### Added

- **The container suite went from 12 tests to 36, and grew a second image
  that has a real init.** Three of the four bugs that reached a live server
  were systemd *sandbox* failures, and the old container had no systemd at
  all — so none of them was findable there. `Dockerfile.host` (debian:13,
  the actual deployment target) runs systemd as PID 1, and the sandbox tests
  each carry a negative control that strips the directive under test and
  asserts the failure comes back. Without that control a container where the
  sandbox silently did not apply would pass every one of them.

  Probes are derived from the unit `install web` actually wrote rather than
  hand-written, so a test cannot keep passing after the generator stops
  emitting a directive.

  Newly covered: `install web` under a real service manager, the netlink
  sandbox for both firewall backends, `ProtectSystem` still permitting a
  later apply, replacing the binary and restarting, the iptables backend
  executed for real, allowlist mode as genuine default-deny, IPv6 drops,
  the console as a listening server (login, "Apply everything", the host
  allowlist, Web Access through the NGINX it just configured), rate
  limiting, the tarpit, each request-shape rule against a request actually
  shaped that way, a per-site rule proving it stops at that site, and the
  whole detection loop — honeypot and probe paths — from a real client's
  request through the log NGINX wrote to a rule that really blocks it.

- **The tarpit is timed**, closing a TODO.md item: a tarpitted client is
  still waiting after five seconds while an unblocked one is served in
  under two.

- **The TUI has the three host-wide Dashboard actions too.** `u` downloads every
  list, `a` applies both planes (NGINX, then the firewall), and `w` opens the Web
  Access form. Each goes through the same shared module the console's button or
  panel does — `refresh`, the existing apply pairs, and a new `webaccess` — rather
  than a second implementation that could drift from the first.

  `u` fetches one source at a time and stores each before starting the next. The
  plan is eight or more downloads of several megabytes; fetching them together
  would hold every payload at once and show nothing until the last one landed.

- **A "Web Access" panel on the Dashboard.** Sets NGINX up to serve this console
  from outside, in one of two modes.

  *Path on an existing site* is the default: it adds a sentinel-marked
  `location /stop-bots/` block to a site you pick, so the console inherits that
  site's certificate. It picks the site's TLS `server` block rather than its
  port-80 redirect. *Its own subdomain* writes a new `server` block on port 80 —
  the generated file says, in a comment where you will find it, that the password
  form and session cookie are in the clear until `certbot --nginx -d <host>` has
  run.

  The panel writes three things that have to agree: the config, `web:base_path`
  and `web:allowed_hosts`. Any one missing gives you a console that looks broken
  rather than misconfigured — a 404 for the prefix, a 403 for the host.

  The config is validated with `nginx -t` **before it can take effect**, and rolled
  back if it fails. `apply_all_sites` writes-then-tests, which is survivable for an
  edit; a new `server` block that does not parse leaves the whole config unloadable
  while the running NGINX keeps serving from memory, so nothing looks wrong until
  certbot's renewal reload fails at 3am.

- **"Update everything" and "Apply everything" buttons in "System-wide settings".**
  Update downloads every bot list, crawler range, enabled feed and selected
  country; apply writes and reloads the NGINX config, then writes and runs the
  firewall script. Both planes are independent, same as `batch --apply`: whichever
  fails, the other still gets its turn.

  Selecting a country used to say "its ranges still need downloading with
  `stop-bots update-country-ranges --country RU`" — a console that knew what needed
  doing and asked you to do it. It now names the button.

- **The console can apply the firewall script.** Previously one of its three
  deliberate omissions, reversed on request. Tick "run it after writing" in the
  firewall panel, or use "Apply everything". The same anti-lockout guard
  `batch --apply` runs still applies — rules that would block a currently-connected
  SSH client are refused, not warned about — and `stop-bots web --no-apply` keeps
  the old write-only behaviour. The chosen backend is now remembered, so a
  one-click apply has an answer without guessing.

### Fixed

- **`make deploy` could land a new binary and leave the console down.** The
  remote half used `systemctl try-restart`, which does nothing at all to a
  unit that is enabled but not running — which is exactly where a service
  that crash-looped and was given up on ends up. It now restarts an
  *enabled* unit and try-restarts one that merely exists, so a host where
  the console is deliberately run by hand does not get a second copy
  competing for the port. It also prints the state it left the unit in.

  The remote half moved to `scripts/deploy-remote.sh`, piped over ssh, so
  that a container test can run that exact file against a real systemd.

- **`batch` ignored the firewall backend this host is set to.** `--backend`
  carried an `nftables` default and nothing consulted
  `firewall::stored_backend`, so an operator who chose iptables in the
  console and ran `stop-bots batch --apply` from crontab — as the README
  recommends — got an nftables script at `firewall.nft` while the console
  maintained an iptables one at `firewall.sh`. Both were applied, by
  different things, and either could be stale. The same drift once had the
  internal cron overwriting an operator's iptables script with nftables
  syntax; that was fixed by reading the stored backend and this path was
  missed. An explicit `--backend` still wins; without one, the host's
  setting decides, and the output path follows from it.

- **`stop-bots install web` could leave the service crash-looping.** It ran
  `systemctl enable --now` *before* opening the database to record the bind
  address and generate the password, so the installer and the service it had
  just started raced for the same SQLite file. `Db::open` set no busy timeout,
  so the loser failed instantly with "database is locked": either the service
  exited 1 and crash-looped on `Restart=on-failure`, or the install failed
  having already enabled the unit, or the service won and generated the
  password itself — leaving the installer to report "a console password is
  already set, keeping it" and the operator with no password at all. The
  database work now finishes first, and `Db::open` waits five seconds for a
  lock rather than giving up, which also covers the console running alongside
  the TUI or a `batch` from crontab. Found by the new container tests, which
  only showed it under parallel load.

- **The database file was world-readable.** `install web` set the state
  directory to 0700 but left `db.sqlite3` at the umask default, usually 0644.
  Nothing was exposed — the directory is what protects it — but the mode
  travels with the file through a backup or a `cp`, and the unit's
  `UMask=0077` applies only to files the service creates, not the installer.

- **The Web Access panel's form sat flush against the panel edge.** Every other
  panel wraps its loose content in a `.panel-body`, which is the only thing
  carrying the side padding; this one emitted the form bare. A test now asserts
  that whatever follows a panel's table is inside one.

- **The console could not apply the firewall at all under its own systemd unit.**
  `nft` and Debian's nft-backed `iptables` reach the kernel over a netlink socket, and
  the unit `install web` writes set `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
  — with a comment asserting "nothing here uses a raw or netlink socket: this service
  writes the firewall script, it never applies it", which stopped being true the moment
  applying was added. The failure was `Unable to initialize Netlink socket: Address
  family not supported by protocol`, which names neither systemd nor this project.
  `AF_NETLINK` is now allowed, and a netlink refusal appends an explanation naming the
  directive and how to get a current unit. **Existing installs need
  `stop-bots install web --force` and a restart.**

- **An iptables script could land in a file called `firewall.nft`.** The destination
  was fixed at startup and the backend chosen per render, so on a host set to iptables
  the console wrote `#!/bin/sh` and 12,000 `iptables -A` lines into the nftables path.
  Worse, the internal cron hardcoded nftables regardless — so each tick replaced an
  operator's iptables script with an nftables one at the same path, and the next apply
  ran `sh` over nftables syntax. The backend is now the single source of truth: the
  cron renders for the stored backend, and the path follows it (`.nft` or `.sh`) unless
  `--firewall-out` names one explicitly, in which case that wins.

- **`make deploy` did not deploy.** It copied the binary to the login directory and
  restarted nothing, so on a host where the service runs from `/usr/local/bin` every
  step succeeded and the console kept serving the previous build. It now installs to
  the path the unit actually names, restarts the service if there is one, and prints
  the unit's `ExecStart` alongside the deployed file's timestamp — `--version` is
  `0.0.1` for every build, so it could never have shown the difference.

- **`install web` wrote a unit systemd could not execute** when run from `/root` —
  which is exactly where someone who just downloaded a release binary is standing.
  The unit sets `ProtectHome=yes`, so `/root` is an empty directory for the
  service, and `ExecStart=/root/stop-bots` failed with `status=203/EXEC`,
  "No such file or directory", for a file that was plainly there. Preflight checked
  that the binary existed; it did not check that it existed *inside the sandbox the
  unit itself asks for*. It now refuses up front, names the directive responsible,
  and gives the two commands that fix it. Same for `/home`, `/run/user`, `/tmp` and
  `/var/tmp` (the last two via `PrivateTmp=yes`), and for a relative `--binary`,
  which systemd rejects when it loads the unit rather than when it starts it.

  A failed `systemctl enable --now` also now says what state it left behind: the
  enable sticks even when the start fails, so the unit was enabled and would have
  tried again at the next boot with nothing saying so.

### Added

- **Inspect an address on the Dynamic Protection screen.** `i` in the TUI, or click
  the address in the web console. It answers "what *is* this thing" from lists this
  host already downloads: which of the six reputation feeds list it (Tor exit,
  FireHOL, blocklist.de, AWS, Google Cloud, DigitalOcean), whether it is inside a
  published crawler range — which is what separates a real Googlebot from a user
  agent that merely says so — which fetched country it belongs to, and which
  accounts it tried to log in as.

  Deliberately **not** reverse DNS or whois. Both are outbound requests, per row, to
  infrastructure an attacker often controls, and a PTR record is written by whoever
  holds the address — so it is attacker-supplied text that reads as authoritative.
  Everything here is local, instant, works offline, and tells the attacker nothing.

  The SSH log's failed-login usernames were being parsed past and discarded; they
  are now kept, capped and stripped of control characters, since they are whatever
  the client chose to send. Extracted for one address when you ask, not for every
  address on every refresh — the latter cost 215ms per refresh on a large
  auth.log, for an answer almost nobody had asked for.

### Security

- **A line from a downloaded feed could become a root shell command.** The IP-range
  and reputation feeds are fetched unattended from eight third parties, and nothing
  validated what they sent before it was interpolated into a generated firewall
  script. A feed line of `1.2.3.4/24; touch /tmp/pwned` rendered as
  `iptables -A STOP-BOTS -s 1.2.3.4/24; touch /tmp/pwned -j DROP`, and
  `stop-bots batch --apply` runs that script under `sh` as root. On nftables the
  same shape gets `nft -f` to accept arbitrary statements — `; flush ruleset` would
  drop the host's entire firewall.

  Admin-entered rules had been validated since an earlier review; the fetched
  ranges were exempted on the grounds that their upstreams are reputable, which is
  not the same as uncompromised. All four tables that hold an address now go
  through one validator, invalid entries are dropped rather than failing the whole
  fetch, and both renderers check again before emitting a line — the script is
  executable input, and a database written by an older version is still out there.

- **The web console could write a root-owned file anywhere on the host.** The
  destination for "Write script" came from a free-text form field, and the file it
  writes is an executable script — `/etc/profile.d/`, `/etc/cron.d/` and unit
  directories were all reachable. That is a way around every restriction the console
  is built around. It now writes to the path the server was started with, set by the
  new `stop-bots web --firewall-out`, and takes no destination from the request.

- **Fetches now have timeouts and a size limit.** Every bot list and IP-range
  download was a bare `reqwest::get`: no connect timeout, no total timeout, and the
  whole body read into memory. Under the internal cron that means an upstream which
  accepts the connection and then says nothing stalls the job indefinitely. There is
  now one shared client (60s total, 10s connect, 5 redirects) and a 32MB cap
  enforced against both the declared length and the bytes actually arriving.

### Added


- **A web UI — `stop-bots web`.** The same five screens as the TUI, in a browser.

  It binds `127.0.0.1:8787` and generates a password on first run, printed once.
  Reach it over an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 host`); binding anything
  else needs `--expose` as well, because the console can rewrite the firewall and the
  NGINX config of the host it runs on.

  There is a password, a CSRF token and a `Host` allowlist even on loopback, because
  loopback is reachable by every local user on the box and by any page in the admin's
  own browser — a form post needs no readable response, and DNS rebinding defeats
  same-origin. The `Host` allowlist is what makes rebinding fail.

  It refuses to block the address you are connected from, will not unblock something a
  downloaded list blocked, and will not change its own password. The Help screen lists
  each omission with its reason, alongside how this console is actually exposed. (It also
  would not *apply* the firewall script; see "The console can apply the firewall script"
  below, which is the same release changing its mind.)

  Serve it under a path prefix with `--base-path /stop-bots` when NGINX puts it in a
  `location` block rather than on its own subdomain. The proxy must not strip the
  prefix — `proxy_pass http://127.0.0.1:8787;` with no trailing slash — because this
  server matches the full path and generates links that include it. A subdomain needs
  none of this and is the simpler deployment.

  Login attempts are throttled — before the password is hashed, not after. The point is
  not that a generated 144-bit password is guessable; it is that verifying one runs
  Argon2id (~50ms of CPU, 19MB), and an unauthenticated caller could otherwise drive that
  as fast as they could post.

  Behind TLS, set `web:secure_cookie` — without it a browser will also send the
  session to an `http://` URL for the same host. It is off by default because the
  default deployment is plain HTTP on loopback, where a `Secure` cookie is never
  stored at all.

- **The internal cron now ticks while the web UI runs, not only the TUI.** The two share
  one schedule in one database, so running both does the work once: whichever ticks first
  records the job and the other finds it no longer due. The same is true of a crontab
  entry running `stop-bots batch`, which already recorded through those keys.

  This closes the gap that made the web UI look like a viewer: a server left running now
  keeps detection, access-log stats and the daily crawler-range refresh current on its
  own. `RenderFirewall` still only writes the script — nothing here applies
  one — and if the server can't write it (an unprivileged `stop-bots web`, and a
  default path under `/etc`) the recorded outcome names the file rather than
  reporting a bare "Permission denied".

  The per-job logic moved out of `App` into `cron.rs` (`read_log_for`, `run_log_job`,
  `fetch_ip_ranges`, `store_ip_ranges`) so the two front-ends run the same code rather
  than two copies that drift. Behaviour in the TUI is unchanged.

- **`stop-bots install web`** sets the console up as a systemd service on Debian:
  a unit at `/etc/systemd/system/stop-bots-web.service`, `/var/lib/stop-bots` at
  0700 because it holds the password hash, `/etc/stop-bots` for the firewall
  script, a generated password if there isn't one, and `systemctl enable --now`.

  `--dry-run` prints the plan and changes nothing; `--prefix` writes the tree
  somewhere readable without root; a unit you have edited is refused rather than
  replaced unless you pass `--force`; and a binary under `target/debug` is
  refused, because a unit naming one works until the next `cargo clean`.

  The service runs as root, which it has to — the console rewrites `/etc/nginx`
  and runs `systemctl reload nginx`. The unit carries the hardening compatible
  with that and names the hardening that isn't, with reasons.

- **`make unit-test` / `make integration-test` / `make test`**, replacing the old
  `test` / `test-containers` pair. `unit-test` is everything that needs only a
  compiler; `integration-test` is the container suite; `test` is both, unit first,
  since there is no sense building containers to find out the code doesn't compile.
  Every target is `.PHONY` now — a directory named `build` or `test` would
  previously have made `make` say "up to date" and run nothing.

- **An opt-in pre-commit hook**, `make hooks`. Formats what you staged and runs
  CI's exact clippy invocation. A commit with no Rust in it skips both; a clean
  Rust commit costs about four seconds. It judges formatting against the staged
  bytes rather than the working tree, and refuses rather than re-stage a file that
  is staged unformatted *and* has unstaged changes — formatting rewrites the
  working tree, so `git add` there would commit edits that were left out on
  purpose.

- **`--threshold 0` is refused.** Every detector compares `count >= threshold`, so
  zero meant "no evidence required": `block-scanners --threshold 0` added a block
  rule for every address in the log, whatever it had done. One is still allowed —
  that is an aggressive policy, not a mistake. The same floor is applied to the
  three behavioural thresholds that have no CLI verb and are set by hand in the
  settings table, where it is 2, since one distinct page or one user agent
  describes every visitor there has ever been.

- Dependency advisories are now a CI job (`cargo audit`), weekly as well as on
  push, because an advisory is published against code that hasn't changed. It
  fails on vulnerabilities, unsound crates and yanked ones, but not on
  unmaintained ones — nobody here can act on those. This found
  `RUSTSEC-2026-0258` in `h2` — reachable from the web server through hyper —
  along with unsoundness in `anyhow` and `lru`; all three had patched versions
  already published and are updated in `Cargo.lock`.

- **The web UI puts panels side by side on a wide window**, rather than stacking
  everything down one 1180px column. Every screen is a grid that collapses back to
  one column below 1040px, so a narrow window and a phone are unchanged.

  The Dynamic Protection tables — failed SSH logins and top user agents — are
  capped at twenty rows and scroll inside their panel, with the column headers
  stuck to the top. On a server that is actually being scanned those tables ran to
  hundreds of rows and buried everything after them. A user agent too long for its
  column is now truncated rather than wrapped, so that rows are a uniform height;
  the whole string is still there as the cell's `title`.

- **Configurable NGINX test and reload commands** — `stop-bots set-nginx-commands`.
  For NGINX in a container, where the config is on a bind mount this tool can write but
  `systemctl reload nginx` reloads nothing:

  ```
  stop-bots set-nginx-commands --test "docker exec web nginx -t" \
                               --reload "docker exec web nginx -s reload"
  ```

  The command is split into words and run directly, never through a shell.

- `update-ip-ranges`, `update-country-ranges` and `update-reputation-source` take a
  `--source <file>` override, parsing the same format the server would have sent —
  matching what `update-bot-lists` already had. For a host with no outbound access, and
  what makes the parse-and-store half of every download testable offline.


- **`stop-bots batch` — one unattended pass, for a real crontab.** Refreshes every list,
  scans the logs, writes the NGINX blocking rules and the firewall script, and with
  `--apply` puts both into effect. Quiet when everything worked (so a healthy nightly run
  doesn't mail you), non-zero exit and a report on stderr when something didn't; `--verbose`
  prints a line per step. `--no-fetch` skips the downloads, for a host with no outbound
  access or a second, more frequent entry that only wants the log scan and the apply.

  Under `--apply` the SSH lockout guard refuses — and refusing means nothing is written or
  applied — both when the rules would block a currently-connected client and when no SSH log
  could be read at all, because then the check could not run. The interactive
  `render-firewall` only warns in that second case, which is defensible with a human at the
  terminal and is not from cron. Pass `--ssh-log` explicitly; `--force` overrides.


- Seven choices for what a blocked request gets back, rather than two: `403`, `404`, `410`
  (asks crawlers to drop the URL permanently), `429`, `418` (RFC 2324's teapot), `444`
  (close without replying), or a tarpit that answers 403 with the body throttled to a byte
  per second. Each option states what it is for in the chooser. Existing `403`/`444`
  settings are unchanged.

- Six per-site request-shape rules (Site settings → open a site → Request rules), each its
  own toggle and each off by default: reject HTTP/1.0-1.1, a missing `Accept`, a missing
  `Accept-Language`, an empty `User-Agent`, a bare-IP `Host`, or TLS 1.0/1.1. The two
  TLS-dependent rules are only written into HTTPS `server` blocks, since browsers don't
  negotiate HTTP/2 without TLS and a plain port-80 block sees nothing but 1.1;
  `/.well-known/` is always exempt so ACME certificate renewal keeps working. Each rule
  states in the UI what it turns away besides bots.
- Three behavioural detectors, all off by default and all exempting verified crawlers:
  fetches-no-assets, rotating user agent, and referer-less deep crawling. Each has a false
  positive it can't rule out — see the README.
- Optional IPv4 `/24` escalation when several addresses in one subnet are flagged together.
- `tui --ssh-log` — the same SSH-log override every SSH-reading subcommand
  already took, now for the TUI too. Without it, hosts without a readable
  `/var/log/auth.log` paid a `journalctl` invocation (0.5s or more) on every
  refresh of the Dynamic Protection screen.

### Changed

- `App`'s background work is a `start_x` / `finish_x` pair throughout. Several of the
  `start` halves were named `reload_nginx`, `read_ssh_log`, `check_site_statuses` — right
  about the subject and wrong about the tense, since none of them does the thing, they all
  only start it. Internal naming only; no behaviour change.


- The Dashboard's "Automatic blocking" panel is a full-width panel of its own, and shows
  all fourteen options at once instead of five at a time behind a scroll. It deals its
  rows into as many columns as the terminal is wide enough for (two from about 100
  columns), and "System-wide settings" and "Geo-blocking" now share the row above it —
  between them they were using a quarter of the width.


- **The TUI no longer blocks on anything it does.** Every action that touches the
  filesystem, a subprocess or the network now runs on a background thread while the
  interface stays live: reloading NGINX, rendering and applying the firewall script,
  scanning the NGINX config root, applying site configs, working out each site's
  UP TO DATE / STALE tag, and reading the SSH log that Dynamic Protection's SSH panel is
  built from. On a small server several of these were multi-second pauses with a frozen
  screen. Database access still happens on the main thread, where it is fast and where
  SQLite's connection can go.

  The footer names whatever is running, with a braille spinner, on every screen; the SSH
  panel and the site status tags carry their own. Two safety properties are unchanged and
  covered by tests: the firewall's lockout guard still reads the SSH log *live* rather
  than from the display cache, and a reload requested while one is running is held rather
  than dropped, so applying a second site can't leave NGINX serving its old config.

- A keypress reloads only the screen being looked at. All four used to reload on every
  mutation, so toggling one category default on the Dashboard also made Dynamic
  Protection re-read the SSH log and Bot settings re-list every bot. The other three
  reload when each next comes into view.

### Fixed

- `--version` now exists. It also shows in the TUI's header, which is where someone is
  standing when they decide to report something.
- `stop-bots --help` is scannable: twenty subcommands printed their entire description —
  one ran to 931 characters — as their one-line summary. Each now has a real one-liner,
  with the full text still under `<subcommand> --help`.
- A mistyped `--root` is an error rather than "Discovered 0 site(s)", which read exactly
  like a correct run against a server with no sites. Something unreadable *inside* a real
  root is still skipped, as before.
- The Dashboard's Summary no longer tells a fresh install to press `f`, which would have
  rendered an empty script. With no rules it says so, and points at the panel above.
- Dynamic Protection's two panels say what an empty one means. A blank bordered box reads
  as "broken", and here it is usually the good case: nothing is attacking you.
- Bot list source names no longer overflow their column and knock the counts out of line.
- Popups are sized to their contents. The firewall render popup was two columns short of
  its own key hint and cut "Esc cancel" in half; a longer output path would have gone the
  same way.
- Dynamic Protection's panel titles fit at 80 columns, the documented minimum, instead of
  being cut mid-word.
- Choice popups say `Enter choose  Esc cancel`. The one popup shape with no text besides
  its options was also the only one that never mentioned the way out.
- The "Automatic blocking" panel says what its `5d` column means.


- **Switching on a large blocklist feed no longer freezes the TUI for a minute or more.**
  Storing the fetched ranges inserted one row per autocommit — one `fsync` each — so AWS's
  ~7,000 ranges took **98 seconds** on the main thread. One transaction makes the same work
  about a tenth of a second. The same per-row pattern was in the crawler IP ranges, the
  per-country geo ranges and the user-agent hit counts, and is fixed in all four; it was
  fixed for bot lists in an earlier change and these were missed.
- Registering the known bot-list and reputation sources is one transaction rather than nine,
  which is startup cost on every launch.
- The parse of a downloaded feed runs on a worker thread rather than on the async runtime.
  The download always yielded properly, but the parse that follows it is plain CPU work —
  and on a one-core server there is a single runtime thread, shared with the draw loop.

- The TUI now clears the screen before its first frame. On a terminal that ignores the
  alternate-screen request the shell's scrollback stayed put, and because ratatui never
  transmits the blank cells of a first frame, the old text showed through every gap — the
  UI was unreadable.
- `systemctl reload nginx` no longer writes onto the TUI's screen: its output was
  inherited rather than captured, so anything it said corrupted the display, and non-root
  a polkit agent could take over the terminal outright. Its stderr now appears in the
  error message instead.
- **The TUI's firewall render no longer applies a script when the lockout safety check
  couldn't run.** If no SSH log was readable — not running as root, or a journald-only host —
  the check was silently skipped and the script written and applied anyway. This could take a
  server off the network, and did. It now refuses unless forced; the CLI's behaviour (warn and
  continue) is unchanged, since a human is watching there.
- The TUI's lockout check now honours `tui --ssh-log` instead of always auto-detecting.
- The generated `robots.txt` listed no bots at all when they came from the well-known-bots
  source: their names are humanised from slugs (`ai-search-bot` → `Ai Search Bot`) and a name
  with spaces is unusable as a robots token, so every one was silently dropped. The token now
  comes from the user-agent pattern, which is both correctly cased and a real token.

- IPv6 detections now block the `/64` rather than the single `/128`. A `/64` is the smallest
  allocation anyone gets — one LAN, the same thing a single IPv4 address represents — so
  blocking one address stopped nothing while costing a firewall rule per request.

- Opening a fresh database no longer takes ~450ms: schema creation ran one
  fsync per table; it is now a single transaction.
- Storing a bot list no longer fsyncs once per bot — with the ~700-entry
  real lists that was seconds of disk waits per fetch.

## [0.0.1] — 2026-08-18

First published release. Everything below already existed in the repository; this is the
point it became installable.

### Blocking, in NGINX config

- Known-bot blocking by category (scanner / search engine / AI crawler), from ArcJet's
  Well-Known Bots, ai.robots.txt and the NGINX Ultimate Bad Bot Blocker list, injected as a
  sentinel-marked block into each discovered site.
- Per-site category and per-bot overrides, and per-site path exemptions.
- Configurable response for a blocked request: `403`, or `444` to close the connection
  without answering.
- Optional generated `robots.txt`, listing every blocked bot plus the honeypot path.
- Optional per-client rate limiting (`limit_req`).

### Blocking, in a generated firewall script

- Automatic detection, each independently switchable, each adding a block that expires on
  its own: SSH brute-force scanners, web scanners (many distinct 404s), forged crawler user
  agents, requests for exposed-secret paths, and honeypot hits.
- Host-wide geo-blocking via IPdeny, in blocklist or allowlist mode.
- Third-party CIDR feeds: FireHOL level 1, Tor exit nodes, blocklist.de, and the published
  address space of AWS, Google Cloud and DigitalOcean. All off by default.
- Ad-hoc IP/CIDR allow and block rules.
- iptables and nftables output, generated and never applied without an explicit request,
  with a check that refuses to write a script that would lock out a connected SSH session.

### Interface

- A TUI (Dashboard, Bot settings, Site settings, Dynamic Protection, Help) and a CLI over
  the same SQLite database and the same underlying logic.
- An internal scheduler that runs the detectors while the TUI is open; the equivalent CLI
  subcommands are safe to run unattended from a real cron.

[Unreleased]: https://github.com/ivankovic/stop-bots/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/ivankovic/stop-bots/releases/tag/v0.0.1
