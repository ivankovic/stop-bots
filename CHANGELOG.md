# Changelog

Notable changes per release. Versions follow [semver](https://semver.org), with the
caveat that `0.0.x` means cargo treats *every* release as potentially breaking — which is
the intent while the library API in `src/lib.rs` is still whatever the binary happened to
need.

## [0.0.7] — 2026-09-22

### Added

- **`set-nginx-commands --root`**, so the NGINX config root is remembered
  like the commands and the log paths already are. It is the third thing a
  containerised NGINX moves away from its default, and the only one still
  passed by hand on every invocation.

  `--root` defaulted to `/etc/nginx` on six subcommands, so the code could
  not tell "not passed" from "passed the default". Forgetting it did not
  error — it scanned an empty `/etc/nginx`, found no sites, and reported
  success over nothing. Two cases could not be fixed by remembering: the
  bare `stop-bots` invocation hardcoded the default and accepted no flags,
  and the web unit baked the path into `ExecStart` at install time.

  An explicit `--root` still wins, so a one-off run against a checkout needs
  no change to the stored value.

### Changed

- **The web unit no longer names `--root` in `ExecStart`.** The service
  reads the stored root itself, which is what the unit's own comment already
  says about the bind address, host allowlist, path prefix and exposure
  flag: a setting that lives in the database must not also live in a flag,
  or they disagree on the next restart.

- **`render-firewall --out` defaults to `/etc/stop-bots/firewall.nft`.**
  That path already existed as `DEFAULT_OUTPUT_PATH`, the health check looks
  for it, and `install firewall` hardcodes it — while the command that
  writes the file made you type it, and any other path produced a script
  nothing reads.

## [0.0.6] — 2026-09-21

### Added

- **`stop-bots set-log-paths`**, the companion to `set-nginx-commands` for
  the other half of a containerised NGINX. A container that bind-mounts its
  log directory writes the access log somewhere that is not
  `/var/log/nginx/access.log`, and until now the only way to say so was
  `--access-log` on each invocation.

  That covered the CLI and a crontab, and missed the two things that
  actually run the detectors: the console and the TUI drive an internal
  cron that takes no arguments, and the unit `install web` writes has an
  `--ssh-log` flag and nothing for the access log. On such a host the
  console ran every minute against a path that did not exist, found
  nothing, and reported "the NGINX access log unreadable" without saying
  which file it meant. The documented workaround was a symlink — making the
  filesystem lie so a default became true.

  A stored path is used whenever no flag overrides it. The flag still wins,
  so a one-off run against a rotated copy needs no change to the setting and
  no change back. Pass an empty string to clear one.

### Changed

- **The log-sources health check names the path it tried.** "unreadable" on
  its own could not answer the operator's next question, which was always
  which file. The fix it suggests now leads with `set-log-paths`, because
  the flags it used to name cannot reach the console.

## [0.0.5] — 2026-09-21

### Fixed

- **"Rules survive a reboot" reported OK on nftables hosts where they did
  not.** The check asked whether `nftables.service` was enabled. That unit
  loads `/etc/nftables.conf`; this project writes
  `/etc/stop-bots/firewall.nft`. The two are unrelated, so the check passed
  on hosts that came back from a reboot with none of these rules loaded —
  the same failure it exists to catch, arriving through the check itself.
  The iptables half was always right: `netfilter-persistent` saves the live
  ruleset, so it really does carry them.

- **The suggested fix could take out the host's whole firewall.** It said
  `systemctl enable nftables.service`. Debian's stock `/etc/nftables.conf`
  opens with `flush ruleset`, so on a host where ufw, Docker or a
  geo-blocker also manage tables, enabling that unit drops all of them once
  per boot. The fix now names `stop-bots install firewall`, and when
  `/etc/nftables.conf` is seen to flush it says explicitly not to enable
  that service.

### Added

- **`stop-bots install firewall`**, a second install target beside `web`.
  Writes a `Type=oneshot` unit that applies the rendered script at boot —
  `ExecStart=/usr/sbin/nft -f /etc/stop-bots/firewall.nft`, ordered
  `After=docker.service ufw.service`, with `ConditionPathExists` so a host
  that has never rendered one stays quiet. Enabled but not started, for the
  same reason `render-firewall` does not apply what it writes. Same
  `--dry-run`, `--force` and refuse-to-replace-an-edited-unit behaviour as
  `install web`.

## [0.0.4] — 2026-09-21

### Changed

- **Two screens were renamed and the tab order changed**: the third tab
  is now **Firewall** (was "Dynamic Protection") and the fourth is
  **NGINX** (was "Site settings"). `1`–`4` still jump to a screen, but
  the mnemonic letters moved with the names — `f` and `n` where `s` and
  `p` used to be. In the web console the paths moved too: `/dynamic` is
  now `/firewall` and `/sites` is now `/nginx`.

  The old names described the screens' provenance rather than what they
  do. Everything on tab three ends up in the **firewall script** and
  everything on tab four ends up in **NGINX config** — which is the split
  the project has documented from the start, and the one question a new
  reader has to answer to find a setting. Naming the tabs after the two
  outputs answers it from the tab bar. The new order puts them in the
  order the Dashboard's "Apply everything" runs them.

### Fixed

- **Allow-list geo blocking dropped every IPv6 client.** The country fetch
  read only IPdeny's IPv4 list, while allow-list mode rendered a `::/0`
  block regardless — so on a dual-stack host it allowed the selected
  countries over IPv4 and black-holed IPv6 entirely: web, SSH, everything.
  No IPv6 address can be inside a range that was never fetched.

  The SSH lockout guard did not catch it. It checks the addresses of
  connected SSH sessions, so an operator connected over IPv4 is checked
  against the v4 rules, sits inside an allowed country, and passes — while
  the ruleset about to be applied removes an address family. A safety net
  that is silent about a failure it does not model is worse than none,
  because the render reads as verified.

  `fetch_country` now fetches both of IPdeny's paths and stores both
  families; `country_ip_ranges` is keyed `(country_code, cidr)`, so this
  needed no schema change. Both must succeed — a half-fetched country is
  the failure being fixed, and the two paths agree about which countries
  exist, so nothing loses coverage.

  And a catch-all is now rendered **per family, only for a family the
  selection has ranges for**. A blanket `::/0` does not filter IPv6 without
  IPv6 data, it removes IPv6, and that is a verdict the data cannot
  support. An allow-list with no countries selected at all still blocks
  both, deliberately: that is a misconfiguration rather than missing data,
  and the deny-all is what makes the lockout guard refuse and say so.

  Measured against the live feed: `update-country-ranges ch` now stores
  3,550 ranges (2,680 v4 + 870 v6) where it stored 2,680.

## [0.0.3] — 2026-09-20

### Added

- **The access-log detectors now read JSON logs.** Everything driven by
  the NGINX access log — the 404 scanner, probe paths, the honeypot,
  forged-crawler detection, the three behavioural detectors and
  `record-access-stats` — parsed only the stock `combined` format. A
  `log_format ... escape=json` directive is not a niche choice; it is what
  anyone shipping logs to a collector configures. On such a host every
  line parsed to nothing, so none of those detectors ever found anything.

  There was no error, and that is the part worth fixing rather than the
  parser: the log was present, readable and being written to, `batch`
  reported success, and the honest report from a detector that read 14
  million lines and understood none of them is "no scanners found".
  Measured on a real server's log, 2,946 JSON lines yielded 0 scanners and
  0 recorded user agents before, and 1 scanner and 2,736 hits across 13
  user agents after.

  Both formats parse, chosen per line rather than per file, because
  changing a running server's `log_format` leaves one file holding both
  until it rotates — which is exactly when someone has just switched JSON
  on to get these detectors working. Keys are the NGINX variable names a
  JSON format is built from (`remote_addr`, `status`, `request_uri` or
  `request` or `uri`, `http_user_agent`, `http_referer`), which is what
  makes it work with no configuration to get wrong. Values may be quoted
  or bare, since `escape=json` writes `"404"` and `escape=none` writes
  `404`.

  One detector gained a third answer rather than a second format. A JSON
  format that never names `$http_referer` cannot say whether a request
  carried one, and counting "not recorded" as "there wasn't one" would
  make every ordinary visitor on such a host look like a referer-less
  crawler — a detector whose entire output is firewall blocks. So the
  parsed referer is now absent, empty, or present, and
  `refererless_crawl_ips` skips the lines it cannot answer for instead of
  answering wrongly.

- **Debian and Ubuntu packages, and an APT repository to install them
  from.** `cargo deb` builds the package from `[package.metadata.deb]`,
  and the release workflow publishes `amd64` and `arm64` `.deb`s to a
  signed repository on GitHub Pages:

  ```
  curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg \
    | sudo tee /usr/share/keyrings/stop-bots.gpg > /dev/null
  echo "deb [signed-by=/usr/share/keyrings/stop-bots.gpg] \
  https://ivankovic.github.io/stop-bots stable main" \
    | sudo tee /etc/apt/sources.list.d/stop-bots.list
  sudo apt update && sudo apt install stop-bots
  ```

  The package installs a binary and its documentation, and starts
  nothing. `stop-bots install web` still writes the systemd unit, behind
  the `--dry-run` that prints the plan first; a package that shipped an
  enabled unit would start a root-run web console on `apt install`, which
  is the opposite of the rule the rest of the project keeps.


- **A "Humans only" switch**, off by default. With it on, every
  catalogued bot is blocked whatever its category, the three category
  policies are forced to Blocked and cannot be edited, and any address
  that fetches `/robots.txt` is blocked for a day. Let's Encrypt is the
  single exception, because blocking it breaks certificate renewal in a
  way that only surfaces two months later as an expired certificate.

  It does not work by setting the three category defaults, and it cannot:
  measured on a real 793-bot list with all three categories already set
  to Blocked, that blocks **140 of 793**. The rest are catalogued bots
  carrying no category at all — `ahrefs-site-audit`, `adscanner-crawler`,
  `amazon-adbot`. With the switch on, all 793 are blocked.

  The stored category policies are left untouched, so turning the switch
  off gives them back rather than leaving three blocked categories and no
  record of what was chosen. The robots.txt rule is worth understanding
  before turning it on: a browser never fetches that file, and a crawler
  fetches it precisely because it intends to obey what it finds — so the
  rule catches the polite bots and misses the rude ones, which only makes
  sense when the answer to every bot is no anyway.

- **stop-bots now notices when NGINX is in a container, and says what is
  wrong.** `set-nginx-commands` has been documented since it shipped,
  which never helped the operator who did not know they needed it: with
  NGINX in Docker and the default `systemctl reload nginx`, every block is
  written, `apply-blocks` reports success, the config on disk is correct,
  and nothing serves it. A new `nginx-in-container` check reports that as
  CRITICAL with the exact `set-nginx-commands` line to paste, and once the
  commands are right it goes on to check the two remaining seams — a
  console bound to loopback that the container cannot reach, and a managed
  directory that does not exist inside it.

  The host arrangement is stated too, rather than left to silence: "on
  this host, reloaded with `systemctl reload nginx`" says which
  arrangement the tool believes it is in, and is the only line that shows
  the detection ran. The mirror-image mistake — container commands
  configured against an NGINX that runs on the host — is CRITICAL for the
  same reason as the reverse.

  Only a machine where *neither* could be established stays silent: no
  extra line at all, not a warning, not an "unknown".

- **A check that the access log records real client addresses.** Every
  detector skips private sources, so a deployment logging a proxy's
  address instead of the visitor's does not block the wrong people — it
  blocks nobody, from a log that looks healthy. Warns only when *every*
  logged request is from a private address; an empty log and a handful of
  local requests among public ones are both normal and stay quiet.

- **An animated tour of the four screens**, at
  `docs/screenshots/tour.gif`, in the README's Screens section. Four
  stills show what each screen holds; only this shows that `1`-`4` are
  how you get between them. Its frames are the existing seeded SVGs
  rasterised, so it cannot drift from the stills next to it, and it is
  generated by the same `make screenshots` as everything else. The
  rasteriser is a dev-dependency: `cargo install stop-bots` does not
  build it.

### Changed

- **The released binaries are statically linked against musl**, and the
  release tarballs are named for that target
  (`stop-bots-<version>-x86_64-unknown-linux-musl.tar.gz`, previously
  `...-gnu.tar.gz`). A glibc-linked build inherits a version floor from
  whatever machine built it, and the failure it produces is a package
  that installs cleanly and then will not start:

  ```
  stop-bots: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39'
  not found (required by stop-bots)
  ```

  One static build installs on every Debian and Ubuntu still receiving
  updates instead. It is possible here only because the dependency tree
  has no C TLS in it — `reqwest` resolves to `rustls` — so the only C
  left to compile is the SQLite that `rusqlite`'s `bundled` feature
  carries. An `aarch64` tarball is published alongside the `x86_64` one
  for the first time, built on a native runner.

  `packaging/aur/stop-bots-bin` follows the rename and no longer depends
  on `gcc-libs`.

### Fixed

- **The screenshots changed every time they were regenerated.** Bot
  settings renders a source's fetch time to the second, and both
  `touch_source` and the `register_all_sources` in `App::new` stamp the
  moment they run — so the committed images read "updated 0s ago" or
  "updated 2s ago" depending on how fast the machine was, and every
  regeneration produced a diff that looked like a change and was not.
  Pinned to a whole-minute offset, the way the cron history already was.
  The generator is now byte-for-byte reproducible, which `tour.gif`
  needs: an unexplained change to a binary blob cannot be reviewed.

- **Firewall blocks did nothing for an NGINX in a container.** The
  generated ruleset hooked `input` only. A packet for a published
  container port is DNAT'd and then *forwarded*, so it never traverses
  `input` — every Block rule was inert for anything containerised, which
  includes the common case of running the NGINX this tool protects in
  Docker with `ports: 80:80`. `block_web_scanners`, whose entire output is
  firewall rules, therefore did nothing at all on such a host. Nothing
  said so: the script applied cleanly, `nft list` showed the rules, and
  the "Firewall rules are in the kernel" check went green.

  `nftables::render` now emits a second base chain on `forward` beside the
  one on `input`, with the rules in a shared, unhooked chain both jump to;
  the iptables backend adds the matching guarded jumps from `FORWARD` and
  from `DOCKER-USER` where Docker provides it. Both are validated against
  a real kernel by the container suite.

  The forward chain passes traffic from private source addresses before
  reaching the rules, which matters most in geo **allowlist** mode: its
  trailing `0.0.0.0/0 drop`, reached from `forward`, would otherwise have
  cut every container on the host off from the network. Inbound traffic is
  unaffected, since a DNAT'd packet still carries the client's own address.

  A new `firewall-reaches-containers` check reports the case this fix
  leaves behind — a ruleset rendered by an older version, still loaded,
  still counting right, still enforcing nothing. It is Critical when NGINX
  is containerised and the loaded ruleset has no forward coverage, and
  silent where the answer would change nothing.

- **The built-in bot list never reached a console-only host.**
  `register_all_sources` both registers the four sources and stores the
  one compiled into the binary, and it was called from the TUI's startup
  and nowhere else — so every host set up by `install web`, which is what
  a production host is, had no `stop-bots-extras` source row, no entries,
  and none of its 49 patterns in the rendered config. Nothing failed,
  because nothing was asked to: the source was simply absent, on a host
  whose own access log the list had been written from. Found on that host
  with 0 rows, and now pinned by a container test that fails without the
  call.


## [0.0.2] — 2026-09-15

### Added

- **Tap a user agent for a detail popup, the way an address already
  does.** `i` in the TUI and a link on the cell in the web UI, showing
  which lists carry a matching pattern, which alternative matched, the
  categories, and — the reason it exists — *why* it is blocked or allowed:
  a per-bot override, a category default, or nothing. "Blocked" on its own
  never said whether un-blocking meant clearing one override or changing a
  default that governs hundreds of other bots.

  Deliberately a different model from the address detail rather than the
  same one with different text. An address can be checked against a
  published range; a user agent is a string the client typed and can say
  anything, so everything here is phrased as what the lists on this host
  say, never as what the client is. Nothing is looked up over the network,
  for that reason and because there is nothing to ask. The string is capped
  and stripped of control characters at the model — nothing sanitises a
  user agent on the way in, and an escape sequence reaching the TUI's
  alternate screen repaints the terminal.

- **Two more built-in probe paths**, both meeting the list's rule that a
  path only belongs there if it is never legitimate on *any* site:
  `/wp-content/plugins/hellopress/`, a WordPress file-manager backdoor
  that nobody installs on purpose, and percent-encoded dots (`%2e`,
  `%252e`). A `.` needs no encoding, so encoding one has exactly one
  purpose — getting a `../` past something looking for `../`. That is
  22,762 requests on one host, including the CVE-2021-41773
  `/cgi-bin/.%2e/.%2e/bin/sh` shell RCE.

- **Dynamic Protection marks user agents no bot list has heard of.** A new
  `UNKNOWN` tag, for rows that announce themselves as a bot — a `bot`,
  `crawler`, `scanner`… token, or the `+http` convention of citing a page
  about yourself — and that match no pattern in any list. That is the
  signal that turned up 46 missing entries, and it needed a script to
  find. Ordinary browsers are not tagged: checked against 6,493 real user
  agents, the test flags none of the 4,644 carrying a browser's product
  tokens.

- **A built-in bot list of this project's own** — the first source that is
  compiled into the binary rather than downloaded, so a fresh install is
  covered before it has network access and on a host that cannot reach
  GitHub at all.

  46 entries: 6 AI crawlers `ai.robots.txt` does not carry yet (xAI's
  three names, Moonshot/Kimi, Tencent's Hunyuan, 01.AI's YiBot) and 40
  scanners and commercial crawlers. They were read off two months of one
  server's NGINX log — 6,493 distinct user agents over 435,782 requests —
  by matching every one against all 1,606 patterns the three upstream
  lists contribute and keeping what matched none. On that log the list
  covers 22,573 requests the existing sources let through.

  It also carries two search engines the upstream lists miss — Qwant's
  crawler, and the *unversioned* `Googlebot` that `Googlebot\/` cannot
  match — plus Let's Encrypt's validation server, which is in no list at
  all and must never be blocked.

  Entries carry the same category flags every other source's do, so the
  host's own AI/scanner/search policy decides and a per-bot override still
  wins. A search engine is filed as one, so it stays allowed by default
  and is blocked only where an admin has actually asked to block search
  engines.
  Patterns are bare names, never versions: the upstream `Googlebot\/`
  already fails to match a bare `Googlebot`, and repeating that mistake
  would be perverse. Nothing in the list matches `Let's Encrypt validation
  server`, and there is a test that says so.

- **An "Auto-apply" switch.** With it on, the internal cron re-writes every
  site's generated block and reloads NGINX once an hour, whenever they have
  fallen behind the database — which happens constantly on a busy host,
  because every user agent a detector blocks changes the generated block
  and puts every site back to STALE within the minute. Until now nothing
  applied that on a schedule, so a host left alone drifted further from its
  own configuration every day and the health report's "NGINX blocks are
  applied" warning was the only sign.

  On the Site settings screen in the TUI, under Sites in the web UI, or
  `stop-bots set-auto-apply --enabled true`. **Off by default**, and it
  stays off on upgrade: it reloads a live web server with nobody watching,
  which is not a decision an upgrade gets to make.

- **A second, separate switch for the firewall script.** With it on, the
  daily render also runs what it wrote. Separate from the NGINX switch and
  separately off, because the risks are not comparable: a bad NGINX config
  is caught by `nginx -t` and costs a failed reload, while a bad firewall
  ruleset locks you out of the host.

  Unattended it is **stricter than the button**. The interactive paths
  treat "the anti-lockout check could not read an SSH log" as a pass,
  which is reasonable while a person is reading the result; here it is a
  refusal, because "the check could not run" is not "the check passed"
  when nobody is watching. On the Dashboard in both front-ends, or
  `stop-bots set-auto-apply-firewall --enabled true`.

- **A daily maintenance job, and `stop-bots maintain` to run it now.** It
  prunes `user_agent_stats` rows for agents not seen in 90 days (and any
  excess over 20,000, least recently seen first), clears lapsed firewall
  rules, and compacts the database when enough free space has built up to
  be worth the rewrite. `--force-compact` compacts regardless, which is
  what a host that has already grown wants right after upgrading.

- **The health report now includes the database's size**, and its
  reclaimable share, warning past 128MB. "Room for the database" reports
  free space on the *filesystem*, which says nothing about how big this
  tool's own database has become.

- **"Generated script matches the rules" now says when the script will
  render itself.** A stale script the internal cron is about to fix is a
  different situation from one waiting on somebody, and the warning read
  the same either way. It now adds "Will auto-render at
  2026-09-15 14:40 UTC" when there is a scheduled render to name — and
  deliberately says nothing on a host whose cron has never rendered, or
  whose render is already overdue, because neither is a schedule.

### Changed

- **CI actions updated**, and `actions/checkout` off deprecated Node 20:
  `actions/checkout` v4 → v7 (v7.0.0 is the ESM/Node 24 move, which is
  what the runner's deprecation warning was asking for) and
  `softprops/action-gh-release` v2 → v3 (the same move). v7's breaking
  change narrows fork checkouts under `pull_request_target` and
  `workflow_run`; this project uses neither. `Swatinem/rust-cache` and
  `taiki-e/install-action` are already on their current major.

- **Dependencies refreshed** across the tree (`cargo update`), including
  `cc`, `clap`, `futures`, `http`, `hyper` and `tokio`. No API change
  reached this code, the MSRV is unmoved at 1.88, and `cargo audit`
  reports nothing.

- **`rusqlite` 0.31 → 0.40**, which carries the bundled SQLite from
  3.45.0 to 3.53.2. No code changed: nothing this project uses moved,
  including the `dbstat`/`PRAGMA page_count` reads and the `VACUUM` the
  maintenance job runs. The MSRV is unmoved at 1.88.

- **A failing `container` job now says what failed.** Its step echoes the
  failing test names and the first panic back as workflow annotations.
  Job logs need admin on this repository; annotations do not, so a red
  `container` used to read as "exit code 101" to everyone but the owner
  — and this suite races a real systemd, a real nginx and a real SQLite,
  so it is the job most likely to need reading.

- **`reqwest` 0.12 → 0.13.** No code changed, and the TLS stack is
  unmoved — still `rustls` 0.23.45, so the RUSTSEC-2026-0285 fix stays
  where it was. Checked by actually downloading all three bot lists over
  HTTPS, which is the part no unit test covers. MSRV 1.88, against
  reqwest's own floor of 1.85.

### Fixed

- **Both Dynamic Protection detail panels had no gutter.** Their prose,
  button row and sub-heading sat flush against the panel border: a table
  pads its own cells to the panel's 14px, and nothing else in a panel
  does without a `.panel-body`. The `h3` between a panel's two halves had
  no rule at all and rendered at the browser's default. The user agent
  itself now gets a tinted block that wraps anywhere, because it is as
  often one unbroken token as not and a value that cannot wrap sets the
  panel's width from the worst string in the log.

- **Probe-path detection was anchored to the start of the path, and
  attackers are not.** It saw `/.env` but not `/api/.env`,
  `/backend/.env` or `/laravel/.env`; not
  `/%252e%252e/%252e%252e/home/ubuntu/.ssh/id_ed25519`; and not
  `GET http://example.com/.git/HEAD`, whose absolute request URI does not
  begin with a slash-dot at all. The anchor was there to stop
  `/blog/how-to-secure-your-env` matching — but that path does not contain
  `/.env`, so the leading slash in every needle was already doing that
  work. Matching anywhere in the path takes one host's log from 28,213
  probe requests to 67,888, and from 1,640 probing IPs to 1,811. Of the
  39,675 newly matched requests, none was answered with content.

- **A detected block no longer waits a day to be rendered.** The firewall
  render was on a fixed 24-hour clock while the detectors add blocks every
  minute — on a real host fifteen detections sat in the database for
  twenty-one hours, found and unenforced. A changed rule set now makes the
  render due as well, reusing the signature the health check already
  computes, with a five-minute floor so a render that keeps failing backs
  off instead of retrying every tick. The 24 hours stays as the maximum,
  because a rule that merely *expired* changes no signature.

- **Dynamic Protection could not see 217 of its own bot patterns.** It
  compares user agents to patterns by substring, but 13% of them arrive
  regex-escaped from `nginx-bad-bots` — `Googlebot\/`, `Mediapartners
  \(Googlebot\)` — and no user agent contains a backslash, so those
  patterns never matched anything. The screen believed the commonest
  crawler on the web was in no list at all. Escapes are stripped before
  comparing now.

- **"BLOCKED until 1d" now reads "BLOCKED for 1d".** The time beside it is
  how long is left, not a moment, so "until" described something the
  number never was.

- **The state tags on Dynamic Protection no longer run into the addresses
  beside them.** The four tags are four different lengths, and nothing
  padded them, so every row started its address at a different column —
  a column the code had claimed was fixed since the panel was written.
  Both panels now share one tag column, sized to the longest tag actually
  on screen.

- **The "no user agents tallied yet" message no longer has a gap in the
  middle of it.** A string literal was broken across two source lines
  without a continuation, so the indentation was part of the text.

- **The database-size check now has a short name in the TUI status
  strip**, where it had been showing as "database-size" among "disk",
  "logs" and "script".

- **The database no longer grows without bound.** On a live host it had
  reached 16MB, of which a single `settings` row held 4.7MB: the
  "rendered signature" the Dashboard uses to tell whether the firewall
  script is stale was storing the entire rule set's debug dump rather
  than a hash of it. With reputation feeds enabled that is every CIDR in
  every feed — 44,075 rules — rewritten in full on every render and
  rebuilt on every hourly health check. It is now a SHA-256 digest: 64
  bytes, whatever the rule count.

  Rewriting that value daily had also left 6.5MB of free pages SQLite
  reuses but never returns to the filesystem, and nothing had ever
  deleted a `user_agent_stats` row. Both are handled by the new
  maintenance job above. Upgrading drops the old oversized value on the
  first open; the Dashboard reports the script as needing a render once
  afterwards, and settles after it. On the host that prompted this,
  `stop-bots maintain` took the database from 16.0MB to 4.1MB.

- **`install web` no longer pins the service to `/var/log/auth.log`.** It wrote
  that path into the unit's `ExecStart` at install time, and Debian 12 dropped
  rsyslog from default installs — so on a current Debian host the file does not
  exist and sshd logs only to the journal. An explicit `--ssh-log` skips the
  `journalctl` fallback by design, so the service read nothing: the console's
  SSH panel stayed empty and the brute-force detector, which runs inside that
  same service, never saw an attempt to act on. Neither reported an error,
  because an unreadable log means "could not check".

  The unit now names no SSH log unless `install web --ssh-log` asked for one,
  which leaves the service to search `/var/log/auth.log`, `/var/log/secure` and
  then `journalctl` on every read. Existing installs keep the old unit until
  `install web --force` rewrites it.

- **The "couldn't read the log" errors no longer describe a search that did not
  happen.** Passing `--ssh-log` reads that path and nothing else, but the
  failure still listed all three sources as tried, which sends the reader
  looking for a bug in the fallback chain instead of at the path they passed.
  Both the SSH and access-log messages now name the path actually read.

### Security

- `rustls` 0.23.40 → 0.23.45, for RUSTSEC-2026-0285: TLS 1.3 handshake messages
  were accepted across encryption level boundaries. Reached only through
  `reqwest`, which this uses to fetch bot lists and IP-range feeds over HTTPS.

### Changed

- `argon2` 0.5 → 0.6 and `rand` 0.9 → 0.10. Both moved the API this code
  touches: `rand`'s `OsRng` became `rngs::SysRng` and `TryRngCore` became
  `TryRng`, while `argon2` dropped the salt argument from `hash_password`,
  moved `PasswordHash` under `phc`, and now takes raw salt bytes instead of an
  encoded `SaltString` — which deletes the base64 step this file used to do by
  hand. Default cost parameters are unchanged (m=19456, t=2, p=1), so the stored
  hashes and the OWASP figures in the docs both still stand.

### Added

- A test that a password hash written by the *previous* `argon2` still
  verifies. Every other test in `web::auth` hashes and verifies in one process
  with one version, so none of them could fail on the upgrade that stopped
  reading what is already in operators' databases. That failure would surface as
  an operator locked out of the console that manages their firewall, after they
  deployed.

## [0.0.1] — 2026-09-14

First published release. The sections below describe the whole of what became
installable, starting with the blocking the crate was built for.

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

### Added

- **`stop-bots status`, and a System status panel on both Dashboards.** Every
  other check in this project compares what it *would* generate against what
  is *on disk*. None of them looked at the kernel — which is how a real host
  ran for three weeks with 48,860 generated drop rules and an empty ruleset.

  Seven checks: rules actually loaded, rules surviving a reboot, script
  matching the rules, NGINX blocks applied, the console service running the
  binary it names, room for the database, and readable detector logs. Each one
  is something that went wrong on a real server.

  `status` exits non-zero on anything CRITICAL, so it works from a monitoring
  check or a crontab; `--quiet` prints only what needs attention. A check that
  could not run reports UNKNOWN rather than OK: `nft list` needs root, and a
  health check that says everything is fine because it could not look is worse
  than no health check.

  Split as `health::probe` (shells out, no database) and `health::assess`
  (database, no subprocesses), the same shape as `refresh` and `webaccess`.
  Only the probe is stored — an hourly `HealthCheck` cron job takes it — and
  the report is re-derived at render time, so the panel agrees with rules the
  operator changed a second ago. `nft list` on a large ruleset is megabytes of
  text, which is why it is not done per render.

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

- **The console returned 421 on a site's second `server_name`.** A block
  reading `server_name www.example.com example.com;` is routine and NGINX
  answers for both, but `scan-sites` stores a site under the first name only
  — one row, one name — so Web Access allowlisted just that one. The console
  then worked on `www.example.com` and refused `example.com`, the
  DNS-rebinding guard correctly rejecting a host nobody had told it about.
  `nginx::server_names_for` now reads every name off the block the console's
  `location` is going into, and `Plan.host` became `Plan.hosts`. A config
  that cannot be read still yields the stored name, so it degrades to the
  old behaviour rather than to an empty allowlist.

- **The Web Access panel showed a path prefix with a doubled slash.** It
  rendered `"/" + base_path` where the stored value already carried its
  leading slash, so `/stop-bots` displayed as `//stop-bots`. Only the display
  was wrong. The panel now reads the prefix through `BasePath`, so a setting
  written by hand without a leading slash also displays as a path.

- **Recording a path prefix looked like it had done nothing.** The prefix is
  read once, when the router is built, so a newly recorded one left the
  console still answering on the old one: the panel showed the new prefix,
  every link 404'd, and nothing on the page explained it. The Web Access
  panel now carries a "Restart needed" row naming what this process is
  actually serving and the command to pick up the change.

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

[Unreleased]: https://github.com/ivankovic/stop-bots/compare/v0.0.7...HEAD
[0.0.7]: https://github.com/ivankovic/stop-bots/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/ivankovic/stop-bots/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/ivankovic/stop-bots/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/ivankovic/stop-bots/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/ivankovic/stop-bots/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/ivankovic/stop-bots/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/ivankovic/stop-bots/releases/tag/v0.0.1
