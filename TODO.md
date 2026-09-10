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
* **Time the tarpit.** `set $limit_rate 1;` throttles the response body and a
  default error page is a few hundred bytes, so a tarpitted client should wait
  minutes — but how much NGINX writes before the throttle engages on a body that
  small has never been measured. Cheap now: one test in `tests/container.rs`
  timing `curl` against a tarpitted request.
* **`ua_matches_blocked_bot_patterns`** (`dynamic.rs`) does case-insensitive
  *substring* matching over `|`-split alternatives, while NGINX enforces a real
  `~*` regex. The `BLOCKLIST` tag can therefore disagree with what actually gets
  blocked — and since the web UI arrived it says so on two screens rather than
  one, because both front-ends now read this from `crate::dynamic`.
* **Recommend only the backend that is installed.** Nothing checks whether
  `nft` or `iptables` exists before offering both.
* **The web UI has no rate limit on failed logins.** Argon2 makes a guess
  expensive, which is most of the defence, but nothing sleeps or locks out after
  a run of failures. Worth having before anyone runs it exposed for real.
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
