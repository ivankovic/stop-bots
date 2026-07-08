# TODO

- Per-site bot overrides: `apply-blocks` currently applies the same global
  blocked-pattern list to every site. The README's UI mock shows per-site
  overrides; this needs a `site_bot_overrides` (or similar) table plus CLI/TUI
  support.
- No data source populates `is_scanner` yet (well-known-bots only covers
  crawlers, not malicious scanners/pentest tools). Need a source or static
  seed list for the "Scanners" category to actually do anything.
- `update-bot-lists` only knows about one source (well-known-bots). Add more
  sources (e.g. official per-vendor IP-range feeds) once the single-source
  pipeline has proven out.
- No CLI verb to change category defaults or per-bot status (the TUI covers
  this now — category defaults on the Dashboard, per-bot overrides on Bot
  settings; `Db::set_category_default` / `Db::set_bot_status` just aren't
  wired up as `stop-bots` subcommands too).
- `update-bot-lists`/Bot settings' "Update now" popup both still only know
  about the one `well-known-bots` source (see the item above about adding
  more sources) — the TUI's per-source update is wired generically (any row
  in the sources list can trigger it), but the actual fetch always reaches
  for `botlist::fetch`, so a second source wouldn't update for real yet.
- Geo-blocking is out of scope for this pass.
- The TUI has no screen for firewall rules (`add-firewall-rule` etc. are
  CLI-only) or for adjusting NGINX/firewall settings per site (Site settings
  is read-only — see the per-site-overrides item above, which blocks this).
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
