# Pending

From the 2026-11-10 review (security, detection, UX). What it found and fixed is in
`CHANGELOG.md` under Unreleased; these are what it found and left, each with why.

## Security

* **A page can make a visitor's browser ask for `/.env`.** One request convicts, and an
  access log cannot tell an embedded image from a scanner. Verified crawlers are exempt
  now and the detectors' risk text says it. A real fix needs either history of an address
  kept across reads (clearing rows are dropped unless beside suspicion, for speed) or a
  header the combined format does not log (`Sec-Fetch-Site`).
* **The APT `Release` file has no `Valid-Until`.** Adding one without a scheduled job that
  re-signs the index makes every user's `apt update` fail once it lapses; it needs that
  job, with the signing key, first.
* **Automatic containment acts on one outbound attempt**, which a server-side fetch
  (pingback, link preview, webhook) can be made to produce. Opt-in. Wants a count over an
  interval, or Isolate rather than Pause as what happens automatically.
* **The port-scan detector counts a bare SYN**, whose source can be forged. Opt-in;
  crawlers are exempt now and its risk text says it. Logging only what completed a
  handshake would close it.
* **`journal` is not the default SSH source** on a host that has both. Switching existing
  hosts would re-read a window of lines already counted from the file.

## Detection

* **A dedicated access log** (`Sec-Fetch-*`, `Sec-CH-UA`, `Accept-Language`, TLS, content
  type), and on top of it a browser header-consistency rule. NGINX inherits `access_log`
  only where a level sets none, so writing one into a `server` that had none silently
  stops its inherited log: needs the level chosen per site and the container suite.
* **A hidden-link honeypot through `sub_filter`**, for crawlers that never read
  robots.txt. Does nothing to a compressed upstream body without changing
  `Accept-Encoding`, which must not be imposed silently.
* **Hosting origin as a scope** for the four behavioural detectors, and **a UA-fleet
  report** (one user agent from many addresses, no assets, no referers).
* **More verified crawlers** (Applebot, DuckDuckBot, OpenAI's other two, Perplexity).
  Each URL and shape has to be checked against the live file first, and a new source
  makes the default-on forged-crawler detector act on a new name.
* **SSH clients that never try a password** (`Connection closed … [preauth]`,
  `Unable to negotiate`, banner probes) need their own, higher threshold, since a
  monitoring service's port check writes the same lines.
* **"Chrome 110+ on Windows 7" is not impossible**: Supermium and other forks send it.
  Considered and rejected.
* **One asset or one referer still clears** the behavioural detectors; ratios would need
  the counts kept that clearing rows deliberately are not.

## TUI and CLI

* **The advanced Dashboard on a small terminal**: at 80x24 the Firewall script panel is
  an empty frame. Wants a one-column layout under about 34 rows.
* **The Help screen does not scroll**, and is cut below 32 rows.
* **Key collisions**: `f` is the Firewall screen on three screens and a filter on two;
  `a` applies everything on the Dashboard and one site on the sites screen. Changing
  either moves keys people have learned.
* **The Scheduled panel** cannot be focused, scrolled or used to run a job now.
* **`--help` lists nearly ninety commands ungrouped**; clap has no headings for subcommands.
* **One vocabulary for detectors**: the README, the TUI rows and the CLI ids name some
  differently ("Probing for secrets", `Probe paths`, `probe-paths`).
* **`uninstall all --purge` asks nothing** before deleting the database.
