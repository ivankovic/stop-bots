# Changelog

Notable changes per release. Versions follow [semver](https://semver.org), with the
caveat that `0.0.x` means cargo treats *every* release as potentially breaking — which is
the intent while the library API in `src/lib.rs` is still whatever the binary happened to
need.

## [Unreleased]

### Added

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

### Fixed

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
