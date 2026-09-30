# TODO

Open work only. What changed and when lives in `CHANGELOG.md` and the git log.
This file used to carry both, and its history section grew longer than its todo
list — which meant the open items below were unfindable inside it.

## Worth doing next

* **`ua_matches_blocked_bot_patterns`** (`dynamic.rs`) does case-insensitive
  *substring* matching over `|`-split alternatives, while NGINX enforces a real
  `~*` regex. The `BLOCKLIST` tag can therefore disagree with what actually gets
  blocked — and since the web UI arrived it says so on two screens rather than
  one, because both front-ends now read this from `crate::dynamic`.
* **A changed path prefix needs a restart.** `BasePath` is read once when the
  router is built, so after Web Access mounts the console under `/stop-bots/`
  — from either front-end — the running console keeps generating links without
  it until it is restarted. The Web Access panel now says so explicitly, with
  a "Restart needed" row naming what this process is serving; the underlying
  fix is rebuilding the router in place, which nothing does yet.

## Known gaps

Deliberate omissions rather than oversights — each is a thing someone will
eventually ask for, with the reason it isn't there.

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

* **`db.rs` is ~3,500 lines before its tests (~5,900 with them), across
  seventeen concerns**, already marked
  out by `// ---- section ----` banners — which is also exactly where a `db/`
  split would fall, one file per banner. Not done, and the reason is worth
  keeping: `Db` is one struct wrapping one connection, so the mechanical version
  spreads `impl Db` blocks across files and moves 3,500 lines without making any
  one of them easier to read. The banners already provide the navigation a split
  would. The version that would genuinely help — decomposing into per-concern
  types — is a design exercise, not a tidy-up.
* **`main.rs` is ~3,400 lines before its tests**, about 1,100 of them the
  `Command` enum and its help text. Lifting the enum into its own module is
  self-contained and would take a third off the file. Smaller and safer than the `db.rs` split, if file size is what
  bothers you.
