# Changelog

Notable changes per release. Versions follow [semver](https://semver.org), with the
caveat that `0.0.x` means cargo treats *every* release as potentially breaking — which is
the intent while the library API in `src/lib.rs` is still whatever the binary happened to
need.

## [Unreleased]

### Added

- Per-site rejection of HTTP/1.0 and HTTP/1.1 requests (Site settings → open a site → Site
  options). Off by default. Only written into HTTPS `server` blocks, since browsers don't
  negotiate HTTP/2 without TLS and a plain port-80 block sees nothing but 1.1; `/.well-known/`
  is always exempt so ACME certificate renewal keeps working. Note it also turns away
  search-engine crawlers and API clients that still speak 1.1.
- `tui --ssh-log` — the same SSH-log override every SSH-reading subcommand
  already took, now for the TUI too. Without it, hosts without a readable
  `/var/log/auth.log` paid a `journalctl` invocation (0.5s or more) on every
  refresh of the Dynamic Protection screen.

### Fixed

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
