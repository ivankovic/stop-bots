# TODO

Open work only. What changed and when lives in `CHANGELOG.md` and the git log.
This file used to carry both, and its history section grew longer than its todo
list — which meant the open items below were unfindable inside it.

## Worth doing next

Nothing at the moment.

## Known gaps

Deliberate omissions rather than oversights — each is a thing someone will
eventually ask for, with the reason it isn't there.

* **TUI screens that don't exist**: firewall rules (CLI-only), and crawler
  IP-range sources (Googlebot/Bingbot/GPTBot — also CLI-only, unlike country
  ranges, which do have a Dashboard panel).
* **No `--firewall-out` for the TUI.** `App::firewall_out` exists so a test can
  point the `a` key's write somewhere harmless, but nothing on the command line
  sets it; the render popup takes a path from the operator instead, and `a`
  uses whatever the stored backend implies.
* **No way to refresh an already-fetched country from the TUI.** Re-adding a
  code that is already fetched reuses the cached ranges. The CLI's
  `update-country-ranges` does force a re-fetch.
* **No per-bot provenance display.** `bot_source_entries` records which source
  contributed which flag to a merged bot; nothing shows it.
* **No override indicator on a site row.** Whether a site carries a category or
  bot override is only visible once you open its detail view.
* **The HTTP-libraries switch is for every site, not one.** A host with an API
  on one site and a static blog on another cannot block libraries on the blog
  alone; it trusts the API's clients by user agent instead. Old browsers are
  the same, and a per-site override for both would be one design, not two.
* **`FirewallRule` has no protocol field.** Ports always render as TCP, in both
  backends, though bot traffic can be UDP.
* **`Theme::detect` only reads `COLORFGBG`.** Everything else gets the dark
  default and the manual `c` toggle.
* **No quit confirmation.** `q` on the Dashboard exits immediately, which is
  what the README promises.
* **Nothing checks that Traefik reads the root.** `status` says the routers are
  applied once `stop-bots.yml` is current, whether or not the file provider's
  `directory` is that root: Traefik's static config is rarely on this host's
  path (it is in a container), and its API, which would say, is often off.
* **A Traefik site from a Docker label has no settings of its own** unless the
  file with the label is under the root. The host-wide routers protect it.
* **An NPMplus host has no settings of its own.** Every host includes the one
  `custom_nginx/server_http.conf`, so the block there is the host-wide one, and an
  apply refuses a site with settings of its own. Per-site blocks would mean keying
  each one on `$host` inside that file. The request-shape rules are per-site only,
  so none of them is available on NPMplus.
* **NPMplus's default site and admin UI are not covered.** A request for a host
  NPMplus has no proxy host for is answered by its default server, and port 81 by
  its admin UI; neither includes `server_http.conf`.
* **Nothing checks that the root is the data directory NPMplus mounts.** `status`
  says the block is applied once `custom_nginx/server_http.conf` carries it, as for
  Traefik's root: whether the container mounts that directory at `/data` is in the
  compose file, which is not on this host's path in general.

* **Outbound hits and containments have no TUI screen.** The Dashboard's
  Outbound C&C checks rows set the mode, the feeds and automatic
  containment, and its
  Firewall script panel and the status strip show hits; listing them,
  containing by hand and releasing are CLI-only (`list-egress-hits`,
  `contain`, `release`), as are users, the never-contain list and the
  breaker (`set-containment`).
* **"Update everything" (`u`, `batch`) does not fetch the C&C feeds.** Their
  own daily job does, and `update-egress-feeds`: they need the
  never-blocked guard's resolution step, which `refresh` has no place for.
* **A rootless Podman container's traffic is its user's.** pasta sends it
  from a host process, so it is attributed to, and contained as, the user
  running Podman, not as a container.
* **A container on Docker's default DNS bypasses the sinkhole.** Docker
  hands containers the host's upstream servers; only one started with
  `--dns` pointing at the host's dnsmasq or unbound asks it.
* **Hit attribution is a snapshot.** A container is found by its address
  when the hit is answered, up to a minute later; one that stopped and gave
  its address to another in between is reported as the other.

* **The exploit rules and ModSecurity are NGINX-only.** Apache's `RewriteCond`
  and `mod_security2` (the same Core Rule Set), and Traefik through Coraza,
  are the next backends; on either, the settings say they write nothing.
* **ModSecurity on Debian and Ubuntu's layout only**: the module in
  `modules-enabled`, CRS in `/etc/modsecurity/crs` and
  `/usr/share/modsecurity-crs`. An NGINX in a container needs the module in its
  image, and is reported as not installed.
* **Own ModSecurity exclusions for Immich's uploads only.** Jellyfin and
  Navidrome get the Core Rule Set as it is: what they trip, if anything, is for
  detect mode and the audit log to show.

## Blocked on machinery this codebase doesn't have

The organising constraint: **there is no runtime component in the request
path.** Everything is either offline log analysis that writes a database row, or
text generated into a config file. That is what decides which of these are cheap
and which are not.

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
