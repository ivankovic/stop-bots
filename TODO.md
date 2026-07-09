# TODO

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
  the category-only design is coarser than the UA path on purpose); no TUI
  for any of this yet (CLI-only, same gap as firewall rules generally, just
  below); country blocking is host-wide, not per-site — see the geo bullet
  below for why that changed from the original plan.
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
