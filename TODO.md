# TODO

Open work only. Why each shipped thing was built the way it was lives in
`SPECS.md`; what changed and when lives in `CHANGELOG.md` and the git log. This
file used to carry all three, and its history section grew longer than its todo
list — which meant the open items below were unfindable inside it.

## Worth doing next

* **Show `App::message` somewhere other than the Dashboard.** It is only passed
  to `Dashboard::render`, so a status line set by a Site settings apply or a Bot
  settings fetch is invisible unless you happen to be on the Dashboard tab. Site
  settings' *apply failure* path works around this with its own alert popup, one
  screen at a time. The footer already renders global state (the in-flight job
  spinner), which makes it the obvious home for the message too — one fix rather
  than an alert popup per screen.
* **`ua_matches_blocked_bot_patterns`** (`dynamic.rs`) does case-insensitive
  *substring* matching over `|`-split alternatives, while NGINX enforces a real
  `~*` regex. The `BLOCKLIST` tag can therefore disagree with what actually gets
  blocked — and since the web UI arrived it says so on two screens rather than
  one, because both front-ends now read this from `crate::dynamic`.
* **A username containing `" from "` hides the whole line** (`sshlog.rs`).
  `ip_after` takes the *first* `" from "` after its marker, but sshd writes the
  address last — so `Failed password for invalid user x from y from 1.2.3.4 port
  22 ssh2` parses the username fragment as the address, fails, and the line is
  dropped from every count in that module, `scanning_ips` included. A client that
  names itself that way is invisible to SSH scan detection. Taking the *last*
  `" from "` before `" port "` would close it, but it changes which lines
  `scanning_ips` counts, so it wants its own change with its own test.
  **This is attacker-selectable, not just a parse quirk**: the username is chosen
  by whoever is connecting, so a scanner that offers `x from y` as its username
  hides itself from detection for the cost of one string. Pinned as
  current behaviour by `a_username_containing_from_defeats_the_whole_line`.
* **The container suite fails intermittently under parallel load.** Roughly
  one run in five at `--test-threads 3` or higher reports a failure that does
  not reproduce, and the three runs either side of it are clean. The failure
  detail has not been captured yet, so the cause is unknown; the suspicion is
  Docker resource contention during container start rather than any
  assertion. Worth catching once with the output saved before deciding
  whether it needs a retry, a lower default parallelism, or a fix.
* **Recommend only the backend that is installed.** Nothing checks whether
  `nft` or `iptables` exists before offering both. `health` now reports which
  backend's live state it read, so the information is to hand.
* **"Update everything" and the internal cron can fetch the same feeds at
  once.** `Job::UpdateEverything` and `Job::Cron(UpdateIpRanges)` are separate
  entries in `jobs_in_flight`, and `check_cron` keeps ticking while `u` runs —
  the `record_run` that would mark the job done only lands at the end. Nothing
  corrupts (every store replaces), but it is duplicate traffic to three third
  parties and two background jobs competing for one message line. Same in the
  console, whose `/update-all` has no interlock with its own cron either.
* **A changed path prefix needs a restart.** `BasePath` is read once when the
  router is built, so after Web Access mounts the console under `/stop-bots/`
  — from either front-end — the running console keeps generating links without
  it until it is restarted. The Web Access panel now says so explicitly, with
  a "Restart needed" row naming what this process is serving; the underlying
  fix is rebuilding the router in place, which nothing does yet.
* **No CLI verb for the web UI's own settings.** `web:secure_cookie` and
  `web:trust_forwarded_for` have to be set by hand, unlike `web:bind` and
  `web:allowed_hosts`, which `stop-bots web --save` writes. A
  `set-web-option`-shaped verb, or flags on `web`, would close it.

## Known gaps

Deliberate omissions rather than oversights — each is a thing someone will
eventually ask for, with the reason it isn't there.

* **CLI verbs that don't exist**, though the `Db` methods behind them do and are
  tested: category defaults (`set_category_default`), per-bot status
  (`set_bot_status`), per-site category and bot overrides, and toggling a
  firewall rule's `enabled` flag (`set_firewall_rule_enabled` — only add and
  remove are wired up). All are reachable from the TUI.
* **TUI screens that don't exist**: firewall rules (CLI-only), and crawler
  IP-range sources (Googlebot/Bingbot/GPTBot — also CLI-only, unlike country
  ranges, which do have a Dashboard panel).
* **No `--firewall-out` for the TUI.** `App::firewall_out` exists so a test can
  point the `a` key's write somewhere harmless, but nothing on the command line
  sets it; the render popup takes a path from the operator instead, and `a`
  uses whatever the stored backend implies. `stop-bots web` does have the flag,
  because its console has no field to type one into.
* **No way to refresh an already-fetched country from the TUI.** Re-adding a
  code that is already fetched reuses the cached ranges. The CLI's
  `update-country-ranges` does force a re-fetch.
* **No per-bot provenance display.** `bot_source_entries` records which source
  contributed which flag to a merged bot; nothing shows it.
* **No override indicator on a site row.** Whether a site carries a category or
  bot override is only visible once you open its detail view.
* **`FirewallRule` has no protocol field.** Ports always render as TCP, in both
  backends, though bot traffic can be UDP.
* **`iptables::render` skips IPv6 rules entirely.** Fine while `nftables` covers
  both families; IPv6 on iptables would mean generating a second `ip6tables`
  script, not extending this one.
* **`Theme::detect` only reads `COLORFGBG`.** Everything else gets the dark
  default and the manual `c` toggle.
* **No quit confirmation.** `q` on the Dashboard exits immediately, which is
  what the README promises.

## Blocked on machinery this codebase doesn't have

The organising constraint: **there is no runtime component in the request
path.** Everything is either offline log analysis that writes a database row, or
text generated into a config file. That is what decides which of these are cheap
and which are not.

* **Timestamp parsing in `sshlog`/`accesslog`.** The highest-leverage item here,
  because it gates a whole category: both detectors are count-based and never
  parse timestamps, so nothing rate-, burst- or sliding-window-based is possible
  until this exists. (NGINX-side rate limiting did ship — `limit_req` needs no
  timestamps, because NGINX counts at request time. This is about rate-based
  *detection* from logs, which is a different thing.)
* **Escalating TTL for repeat offenders**, fail2ban style. The formula is
  trivial; `firewall_rules` persists only `expires_at`, with no offence count or
  block history. A schema addition, not arithmetic. Worth more now that four
  detectors write rules with four different TTLs.
* **ASN / datacenter ranges.** Partly addressed — AWS, Google Cloud and
  DigitalOcean ship as named provider feeds. A generic "datacenter ranges" list
  is deferred because there is no single feed: Azure sits behind a download-page
  indirection, and Hetzner/OVH need ASN→CIDR resolution with no source for it. A
  list under that name covering a third of them is worse than no list, because
  this is the one category that blocks *legitimate* traffic when it fires.
* **JS / proof-of-work challenge** (Anubis style) and **TLS/HTTP2
  fingerprinting** (JA3/JA4, header-order anomalies). Both need a component in
  the request path. The honest answer is "not without a new architecture", not
  "another option on the list".

## Structural debt, measured

Recorded so the decision is made on evidence rather than on how the code felt
that day.

* **`db.rs` is ~2,400 lines of code across fourteen concerns**, already marked
  out by `// ---- section ----` banners — which is also exactly where a `db/`
  split would fall, one file per banner. Not done, and the reason is worth
  keeping: `Db` is one struct wrapping one connection, so the mechanical version
  spreads `impl Db` blocks across files and moves 2,400 lines without making any
  one of them easier to read. The banners already provide the navigation a split
  would. The version that would genuinely help — decomposing into per-concern
  types — is a design exercise, not a tidy-up.
* **`main.rs` is ~1,800 lines**, most of it the `Commands` enum and its help
  text. Lifting the enum into its own module is self-contained and would halve
  the file. Smaller and safer than the `db.rs` split, if file size is what
  bothers you.
