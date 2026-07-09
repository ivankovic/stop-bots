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
- Real overlap exists between the three sources' bot names (measured, see
  SPECS.md: ~34 names shared across pairs, e.g. `GPTBot`/`anthropic-ai`/
  `CCBot` appear in both ai-robots-txt as `is_ai` and nginx-bad-bots as
  `is_scanner`). Since `bots.slug` is the only identity and `upsert_bot`
  is last-write-wins, updating one of an overlapping pair after the other
  silently discards the first source's categorization rather than merging
  them. No fix planned — it's the existing single-source-of-truth-per-slug
  design, just newly observable with more than one real source.
- Each source's `sources.bot_count` is the pre-dedup parsed count
  (`bots.len()` at fetch time), not the number of rows actually still
  attributed to that `source_id` after any cross-source slug reclaiming
  above — so per-source counts shown in Bot settings can overstate
  reality once sources overlap. Pre-existing counting behavior, just more
  visible now.
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
- Geo-blocking is out of scope for this pass — deferred pending a decision
  on an IP-to-country data source (this codebase has no GeoIP/MaxMind
  infrastructure at all today). If/when it lands, the user's stated
  preference is a static per-site country allow/block list stored in the
  db first, without real IP lookup — i.e. get the data model and UI in
  place before wiring up actual enforcement.
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
- Firewall rules are entirely admin-managed (no bot-list source provides IP
  ranges yet). Once one does, decide how it feeds `firewall_rules` —
  probably mirrors how `bots`/`blocked_user_agent_patterns` works today.
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
