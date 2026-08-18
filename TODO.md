# TODO

* Check if nftables / iptables are installed and recommend only the installed backend.

## Blocking techniques worth adding

Surveyed against what this codebase can actually do. The organising constraint:
**there is no runtime component in the request path** — everything is either
offline log analysis that writes a DB row, or text generated into a config file.
That decides which of these are cheap and which need a new architecture.

Eight of the items originally listed here are now built; see the Done section
below. What's left:

### Deferred, with a reason

* **ASN / datacenter ranges.** Blocking whole hosting providers (Hetzner, OVH,
  Alibaba, Tencent) is widely used and effective — residential visitors do not
  originate from datacenter ASNs. Partly addressed: AWS, Google Cloud and
  DigitalOcean now ship as *named provider feeds* under
  `ipranges::reputation`. A generic "datacenter ranges" list is still deferred,
  and not for effort reasons: there is no single feed. Azure sits behind a
  download-page indirection, and Hetzner/OVH need real ASN→CIDR resolution
  there's no source for. A list under that name that silently covers a third of
  them is worse than no list, because this is the one category here that blocks
  *legitimate* traffic when it fires — which is exactly why the feeds that did
  ship are labelled by provider and carry an explicit warning.

### Needs new machinery (not doable in the current architecture)

* **Timestamp parsing in `sshlog`/`accesslog`.** The highest-leverage item on
  this list, because it gates an entire category. Both detectors are
  explicitly count-based today and never parse timestamps, so *nothing*
  rate-, burst- or sliding-window-based is possible until this exists.
  (Note NGINX-side rate limiting *did* ship — `limit_req` needs no timestamps
  because NGINX does the counting itself, at request time. This item is about
  rate-based *detection* from logs, which is a different thing.)
* **Escalating TTL for repeat offenders** (fail2ban-style: second offence gets
  a longer ban). The formula is trivial; the blocker is that `firewall_rules`
  persists only `expires_at`, with no offence count or block history. Needs a
  schema addition, not just arithmetic. Now that four detectors write rules
  with four different TTLs, this is more valuable than when it was first noted.
* **JS / proof-of-work challenge** (Anubis-style, currently the common OSS
  answer to AI crawlers) and **TLS/HTTP2 fingerprinting** (JA3/JA4, header-
  order anomalies). Both require a component sitting in the request path.
  The honest answer for these is "not without a new architecture", not
  "another option on the list".

### Structural debt, measured

Both of these are real and neither is urgent. Recording the size so the
decision to do them is made on evidence rather than on how the code felt that
day.

* **Adding a detector touches seven files.** Counting references to the
  spoofed-crawler detector alone: `protection.rs` 29, `dashboard.rs` 21,
  `scanblock.rs` 18, `cron.rs` 8, `main.rs` 6, `app.rs` 5. Each is a parallel
  switch — a settings-key pair, a `ProtectionSettings` field, a `Default` arm,
  a `load` arm, a `CronJob` variant with three match arms, a `ProtectionRow`
  variant with four match arms, and a CLI subcommand. Nothing is *wrong*, and
  the compiler catches a missed match arm, but it does mean the fifth detector
  costs about what the fourth did. A table-driven `Detector` descriptor
  (id, label, settings keys, default TTL, the detect fn) would collapse most of
  it. Worth doing before adding a fifth, not before then.
* **`db.rs` is ~2500 lines of code across fourteen concerns**, already marked
  out by `// ---- section ----` comments: sources, bots, settings, per-site
  overrides, firewall rules, crawler ranges, country ranges, reputation feeds,
  cron state, user-agent stats, and more. Those comment banners are precisely
  where a `db/` module split would fall, one file per banner. The reason not to
  do it yet is that `Db` is one struct with one connection, so a split means
  either `impl Db` blocks spread across files (legal, and arguably clearer) or
  a genuine decomposition into per-concern types. The first is a mechanical
  hour; the second is a design exercise.

### Loose ends from the work that shipped

* **The generated NGINX and nftables syntax still needs one pass against the
  real parsers** — nginx and nft aren't installed in the development
  environment. What changed: `tests/golden/` now pins the exact bytes of every
  generated artifact (both firewall backends, the NGINX block in plain and
  kitchen-sink form, robots.txt, the rate-limit zone file), so this is a
  *bounded* step, not a standing hope: on a box with the tools, feed
  `tests/golden/firewall*.nft` to `nft -c -f`, paste the `nginx-block-*.conf`
  goldens into a server block and run `nginx -t`, once — and thereafter any
  change to generated output fails a golden test and tells you to re-check.

* `ua_matches_blocked_bot_patterns` in `tui/dynamic_protection.rs` does
  case-insensitive *substring* matching over `|`-split alternatives, while
  NGINX enforces a real `~*` regex. The `BLOCKLIST` tag can therefore disagree
  with what actually gets blocked. Pre-existing, and now sitting next to a lot
  more machinery that gets this right.
* The Dashboard's "Automatic blocking" panel now holds nine rows in a
  five-row viewport, so it scrolls. Fine, but if more detectors or feeds are
  added it's worth revisiting whether detectors and feeds should be separate
  panels — the Dashboard is out of vertical room, so that would mean a layout
  rethink rather than one more panel.

## Done

- Fixed: `tests/tui.rs` was flaky under load, at roughly one spurious failure
  per two runs of the suite with a different test each time. Cause was a fixed
  5s `rexpect` expectation timeout, long enough on an idle machine and not on a
  contended one, so a redraw that *did* arrive was reported as a failure. Now
  30s, overridable with `STOP_BOTS_TEST_TIMEOUT_MS`. Because the timeout is a
  ceiling on waiting rather than a budget the tests spend, raising it cost
  nothing: eight consecutive clean runs afterwards at unchanged wall time.
  Worth remembering that this predated the blocking-technique work — it was
  verified against commit d476c27 before being blamed on anything recent.

- **Eight blocking techniques added in one pass** (each its own commit; see
  SPECS.md for the design notes on every one):
  1. **Configurable block response** — 403 vs 444, host-wide. Brought with it
     the `nginx::BlockConfig` refactor: everything shaping the generated block
     now lives on one struct, and `site_apply_status` compares *rendered text*
     against the on-disk block instead of reconstructing the user-agent
     pattern. Without that, flipping 403→444 would have left every applied
     site reading `UP TO DATE` while still returning the old code.
  2. **Spoofed-crawler detection** — a UA claiming Googlebot/Bingbot/GPTBot
     from outside that crawler's published CIDRs. Inverts range data that was
     already fetched but only used for *exclusion*. Guarded twice against the
     no-ranges-stored case, which would otherwise block the real Googlebot on
     a fresh install.
  3. **Instant-block probe paths** — `/.env`, `/.git/`, `/wp-config.php` and
     friends, no threshold. The built-in list deliberately excludes
     `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` and `/phpmyadmin`, which are
     legitimate somewhere; a test enforces that.
  4. **Honeypot trap path** — published as `Disallow:` and blocked on any hit.
     Reuses the probe-path matcher; separate detector for its much longer TTL.
  5. **Reputation and cloud-provider CIDR feeds** — FireHOL level 1, Tor
     exits, blocklist.de, AWS, Google Cloud, DigitalOcean. Separate tables and
     enum from `ip_range_sources`, because reusing that one would have gated
     feeds on a bot category *and* started exempting abusive addresses from
     scanner detection.
  6. **robots.txt generation** — aliased from a generated file rather than
     inlined, since the body exceeds NGINX's ~4KB quoted-parameter limit.
     Introduced managed files as an artifact class, deleted rather than merely
     unreferenced when switched off.
  7. **NGINX rate limiting** — `limit_req_zone` in `conf.d` plus per-site
     `limit_req`. The create-before / delete-after ordering is load-bearing: a
     `limit_req` whose zone is gone makes `nginx -t` fail and rejects the
     *whole* reload, every unrelated site included.
  8. **Per-site path exemptions** — switches the block to the
     `set $stop_bots_block` flag form. Paths are regex-escaped because a
     too-wide exemption fails *open*.

  TUI placement follows one rule throughout: anything host-wide that ends up in
  the **firewall script** is on the Dashboard ("Automatic blocking" panel);
  anything that ends up in **NGINX config** is on Site settings ("NGINX
  settings" panel), with per-site knobs in Site detail.


- Per-site category and bot overrides are done (TUI only — `site_category_overrides`/
  `site_bot_overrides` tables, `SiteDetail`, `apply-blocks` applies them
  per-file). No CLI verb to set them, matching the existing gap for global
  category defaults/bot status noted below. Geo-blocking (also shown in the
  README's UI mock) is still explicitly deferred — see the item further
  down; it needs an IP-to-country data source this codebase doesn't have.
- Site settings' list now shows a live per-site status tag (`UP TO DATE`/
  `STALE`/`NOT FOUND`, from `nginx::site_apply_status`) and an `a` key to
  apply just that one site's rule to its own config file
  (`nginx::apply_block_for_site`), plus `A` to apply every known site in
  one go (`apply_all`, a loop over the same per-site call, not a bulk
  operation — a failure on one site doesn't stop the rest). So
  `apply-blocks` isn't the only way to get overrides onto disk anymore.
  Still no override indicator (e.g. a small marker distinct from the
  apply-status tag) on the row itself for "this site has a category/bot
  override set" — that's still only visible once you open the site's
  detail view. A deliberate simplification for this pass, not an
  oversight.
- A failed `a`/`A` apply now shows its own dismissible alert popup (with a
  "Try running as root" suggestion when it's a permission error), since
  `App`'s shared `message` field is only ever rendered on the Dashboard —
  see SPECS.md. That same invisibility gap still applies to `SiteSettings`'
  own scan failures and to `BotSettings`'/background source-update messages
  in general whenever the user isn't on the Dashboard tab; only the apply
  path got its own popup this pass. Worth a proper fix (e.g. rendering
  `message` in the global footer instead of per-screen) rather than adding
  a bespoke alert to every screen one at a time.
- Bot settings' sources list title now spells out "Enter to update"
  (mirroring Site settings' hint style) instead of relying solely on the
  global "Enter, Space open a setting" help line.
- `is_scanner` is now populated: `nginx-bad-bots` (Nginx Ultimate Bad Bot
  Blocker's `bad-user-agents.list`) tags every entry it imports as a
  scanner. `ai-robots-txt` (ai.robots.txt's `robots.json`) adds a second,
  denser source of `is_ai` bots alongside well-known-bots. See SPECS.md's
  "Bot-list sources: SourceKind and three sources" section for the schema
  differences between all three and how `botlist::SourceKind` dispatches
  to each. `is_search_engine` still only comes from well-known-bots — none
  of the three sources here are search-engine-specific.
- Fixed: bots contributed by more than one source now merge instead of
  last-write-wins. `bot_source_entries` records each source's own raw
  contribution per slug; a `bots` row's `is_ai`/`is_search_engine`/
  `is_scanner`/`user_agent_pattern` are recomputed from *all* of a slug's
  current entries (OR the flags, join distinct patterns with `|`)
  whenever any of them changes. Verified against live data in both fetch
  orders: `GPTBot`/`anthropic-ai`/`CCBot`/`ChatGPT-User` now correctly
  carry both `is_ai` (from ai-robots-txt) and `is_scanner` (from
  nginx-bad-bots) at once, regardless of which source was fetched last.
  See SPECS.md's "Bot-list sources: merging overlapping bots" section.
  `sources.bot_count` is also now the accurate post-merge count
  (`Db::count_bot_source_entries`), fixing the drift noted previously.
  Deliberately not handled: a bot whose *only* contributing source drops
  it keeps its last-known merged state rather than being zeroed out or
  deleted — same "never silently destroy state" bias the rest of this
  schema follows (see `Db::recompute_merged_bot`'s doc comment). No CLI/
  TUI surface yet for *seeing* which sources contribute to a given bot
  (e.g. "is_ai because ai-robots-txt, is_scanner because nginx-bad-bots")
  — `bot_source_entries` has the data, nothing displays it. Worth adding
  if per-bot provenance ever matters enough to look at.
- Applying now bakes every bot from every fetched source into one `~*`
  alternation per site (potentially ~1400+ patterns with all three
  sources populated, up from ~635). NGINX handles this fine, but it's a
  large regex evaluated per request and a much bigger generated
  `# BEGIN stop-bots` block — worth knowing before being surprised by it,
  not a bug.
- No CLI verb to change category defaults or per-bot status (the TUI covers
  this now — category defaults on the Dashboard, per-bot overrides on Bot
  settings; `Db::set_category_default` / `Db::set_bot_status` just aren't
  wired up as `stop-bots` subcommands too).
- Fixed (with a scope change from the original plan): geo-blocking now uses
  real IPdeny CIDR data, not just stored country codes — but it's host-wide
  via `firewall_rules`/iptables/nftables, not per-site as originally
  planned. That plan predated knowing the actual data scale: a country's
  *aggregated* CIDR list alone can run into the tens of thousands of
  entries (`us-aggregated.zone` is ~29,000 lines) — duplicating that into
  every site's NGINX config, or building shared-include-file plumbing just
  for NGINX, was judged not worth it for a per-site distinction real
  deployments are unlikely to need. Host-wide reuses the exact same
  render-time-derivation path as crawler IP ranges (see the firewall bullet
  above) with no NGINX changes at all. If per-site geo is ever actually
  needed, the write-up on why it's harder than per-site UA/bot overrides
  (shared include files, `site_apply_status` no longer being a simple
  in-block text diff) is in SPECS.md — worth reading before attempting it.
- Added: geo-blocking now has two modes (`Db::GeoMode`, `settings` key
  `geo_mode`, defaults to Blocklist): **Blocklist** (selected countries are
  blocked, everything else allowed — the original design) and
  **Allowlist** (selected countries are the *only* ones allowed, every
  other CIDR blocked via a trailing `0.0.0.0/0`/`::/0` catch-all —
  `Db::geo_firewall_rules`). The table backing the selection was renamed
  `blocked_countries` → `selected_countries` (and its CLI verbs
  `block-country`/`unblock-country`/`list-blocked-countries` →
  `add-country`/`remove-country`/`list-selected-countries`,
  `set-geo-mode` added) since "blocked" stopped being universally true
  once Allowlist existed. See SPECS.md's "Geo-blocking: Blocklist and
  Allowlist modes" section for the full design, including two real bugs
  this surfaced and fixed along the way:
  1. **`render-firewall` now refuses Allowlist mode on `--backend
     iptables`.** The trailing catch-all is only safe on nftables: this
     project's `iptables::render` has no loopback/established-connection
     allowance in its chain (so `0.0.0.0/0` would drop local traffic too)
     and silently skips IPv6 rules entirely (so an IPv6 catch-all never
     renders, quietly permitting *all* IPv6 while IPv4 is locked down).
  2. **The SSH lockout check (`main.rs::lockout_risks`) was rewritten to
     simulate first-match-wins evaluation**, not "does any Block rule's
     CIDR contain this IP". The old heuristic would have misfired
     constantly under Allowlist: an admin correctly covered by an earlier
     Allow rule (their own `firewall_rules` entry, or an allowed country)
     would still get flagged just because the trailing catch-all's CIDR
     also technically contains their IP. It now walks the exact rendered
     rule order and stops at the first match, same as the real firewall.
     A side effect worth knowing: this uncovered that `ipranges::cidr_contains`
     didn't handle a bare IP address with no `/len` at all (e.g. an
     admin's plain `add-firewall-rule --address 1.2.3.4`) — it now treats
     that as an exact-match `/32`/`/128` rather than "never matches".
- Added: the Dashboard now has a "Geo-blocking (host-wide)" panel below
  "System-wide settings" — a second, independently-focused list (`Down`
  past the last category row flows focus into it, `Up` above its first row
  flows back, no dedicated focus key) showing the mode in its title plus
  every selected country and a fixed "+ Add a country" row. `m` opens a
  popup to switch Blocklist/Allowlist (a popup, not a direct toggle like
  removing a country, since flipping to Allowlist is materially
  higher-stakes). Confirming a 2-letter code whose ranges are already
  fetched adds it immediately; a not-yet-fetched code spawns a background
  fetch first (`App::start_country_select`/`AppEvent::CountrySelectFinished`,
  same fetch-off-the-main-thread-then-store-on-it shape as bot-list source
  updates) and adds it once that finishes. Enter on an existing selected
  country removes it directly, no confirmation popup — unlike a category
  default (which is genuinely "choose one of two options"), removing a
  country is a single reversible action, same reasoning Site settings'
  apply/apply-all actions already use. See SPECS.md's "Dashboard
  geo-blocking panel" section.
  Deliberately not done: no way to see/manage crawler IP-range sources
  (Googlebot/Bingbot/GPTBot) from the TUI, still CLI-only (see the firewall
  bullet above); no way to refresh an already-fetched country's ranges from
  the TUI — re-adding a code that's already fetched just reuses the cached
  ranges and adds it immediately, it never re-fetches. A genuine "refresh
  this country" action is a separate, not yet built, feature (the CLI's
  `update-country-ranges` does force a re-fetch, for now).
- The TUI has no screen for firewall rules (`add-firewall-rule` etc. are
  CLI-only).
- No quit confirmation in the TUI: `q`/Esc on the Dashboard exits
  immediately. Matches what the README currently says ("exit the app at any
  time by hitting 'q'"), so this is a deliberate read of the spec, not an
  oversight — revisit only if that wording changes.
- `Theme::detect` only reads `COLORFGBG`; terminals that signal their theme
  through other means (e.g. `TERM_PROGRAM`, OSC queries) will just get the
  `Dark` default and rely on the manual `c` toggle. Matches the README's own
  caveat that detection can't always be right; extend the heuristic only if
  a real terminal/multiplexer combination turns out to need it.
- Firewall rules have no `enabled`-toggle CLI verb yet (`Db::set_firewall_rule_enabled`
  exists and is tested, just not wired up) — only add/remove.
- `FirewallRule` has no protocol field; ports always render as TCP in both
  `iptables::render` and `nftables::render`, even though real bot/scanner
  traffic can be UDP. Add a protocol field once a real use case needs it.
- Fixed: firewall rules are no longer *only* admin-managed. `ipranges::` adds
  two independent sources of IP data: published crawler CIDR lists
  (Googlebot, Bingbot, GPTBot — `IpRangeSourceKind`, `stop-bots
  update-ip-ranges --source-id <id>`) and IPdeny's per-country aggregated
  CIDR lists (`stop-bots update-country-ranges --country <cc>`, fetched on
  demand, not all ~250 up front). `Db::derived_block_addresses` combines
  whichever crawler sources currently resolve to Blocked (via their
  `category`'s global default — Google/Bing are Search, so inert by default;
  GPTBot is AI, blocked by default) with every CIDR from a host-wide
  `stop-bots block-country --country <cc>` country, and `render-firewall`
  layers this on top of `firewall_rules` as synthetic, non-persisted Block
  rules — never written to the table, so there's no derived-vs-admin
  bookkeeping and no risk of a refresh deleting an admin's own rule. See
  SPECS.md's "Crawler and country IP ranges" section.
  Deliberately not done: no per-bot cascade for crawler IP ranges (Google
  alone splits into a dozen well-known-bots UA slugs with no single bot row
  an IP-range publisher maps onto — see `IpRangeSource`'s doc comment, and
  the category-only design is coarser than the UA path on purpose); country
  blocking is host-wide, not per-site — see the geo bullet below for why
  that changed from the original plan. Crawler IP-range sources
  (Googlebot/Bingbot/GPTBot) still have no TUI (CLI-only, same gap as
  firewall rules generally, just below) — but country blocking itself now
  does, see the Dashboard bullet further down.
- Added: a lockout safety net on `render-firewall`. Before writing anything,
  it cross-references recent successful SSH logins (`src/sshlog.rs`: reads
  `/var/log/auth.log`, falls back to `/var/log/secure`, then `journalctl -u
  sshd`/`-u ssh` for systemd-only hosts with no log file at all) against
  every address about to be blocked — admin `firewall_rules` *and* the
  derived crawler/country ranges above. If any currently-connected client
  would be cut off, it prints the warning twice and refuses to write the
  script; `--force` overrides (still warns once, so the risk is never
  silently swallowed). `--ssh-log <path>` points at a specific log file
  instead of auto-detecting one, for non-standard locations/containers —
  and is what makes this deterministically testable
  (`tests/cli.rs`) without depending on whatever's actually in the real
  system logs on whatever machine runs the tests. Read-only throughout:
  never writes to, rotates or truncates any log.
  Deliberately not done: this only ever warns/refuses at
  `render-firewall` time, the one point this codebase already controls
  before a script reaches disk — it has no way to warn again at the actual
  `sh`/`nft -f` apply step, since this tool deliberately never runs those
  itself (see "Firewall integration" in SPECS.md). No IPv4/IPv6 log-rotation
  handling (`auth.log.1`, `.gz`, etc.) — only the live/current log/journal
  is checked, on the theory that a session active in the last rotation
  window is the one that matters for "would this lock me out right now".
- `render-firewall` only ever writes a file; nothing in this codebase shells
  out to `iptables`/`nft`, by deliberate choice (see SPECS.md). Revisit only
  if explicitly asked for — the blast radius of getting that wrong (locking
  out remote access) is high.
- Neither `iptables::render` nor `nftables::render` output has been checked
  against the real tools — they aren't installed in this environment. In
  particular, `nftables::render`'s idempotency idiom (`add table` / `delete
  table` / `add table` to reset just our own table) is reasoned through but
  unverified; worth a one-time manual two-run check (`nft -f` twice in a
  row) on a real box before relying on it.
- `iptables::render` skips IPv6 rules entirely rather than emitting them (see
  SPECS.md) — fine since `nftables::render` covers both families, but if
  iptables-only IPv6 support is ever needed it'd mean generating a second
  `ip6tables` script, not extending this one.
