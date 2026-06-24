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
- No commands yet to change category defaults or per-bot status from the CLI
  (`Db::set_category_default` / `Db::set_bot_status` exist and are tested, just
  not wired up). Needed once the TUI (or a CLI verb) lands.
- Geo-blocking and iptables/nftables integration are out of scope for this
  pass (test fixtures for iptables/nftables already exist from a prior
  attempt, unused for now).
- TUI not implemented yet; everything above is CLI-only.
