# Changelog

Notable changes per release. Versions follow [semver](https://semver.org) for the
program: its command line, its database, the files it writes and the paths it uses.
While the version is `0.0.x` any release may break those; from `0.1.0` a patch release
breaks none of them. The Rust library in `src/lib.rs` is not a supported API and is not
covered: it can change in any release. `RELEASING.md` says what counts as breaking.

## [Unreleased]

**Before upgrading:** nothing to do. The database schema is unchanged, and an NGINX, Apache
or Traefik host is configured as before.

**After upgrading:** nothing changes on an NGINX, Apache or Traefik host.

**Going back to 0.7.0.** An NGINX, Apache or Traefik host can. An NPMplus host cannot by
installing the older release: 0.7.0 refuses a `/etc/stop-bots/host.conf` that names NPMplus.
First run `sudo stop-bots uninstall web-server` with this release, which takes the blocks out
of `custom_nginx/server_http.conf` and `custom_nginx/http_top.conf` and deletes what it
generated in `custom_nginx/stop-bots/`, then delete the `web_server` and `npmplus_*` lines
from `host.conf`, then install 0.7.0.

### Added

- **NPMplus, beside NGINX, Apache and Traefik.** `sudo stop-bots set-web-server npmplus`
  reads the hosts NPMplus renders under its data directory (`/opt/npmplus`, or `--root`) and
  never writes them, since NPMplus rewrites a host's file whenever it is saved. It writes
  one marked block into `custom_nginx/server_http.conf`, which every proxy, redirection and
  404 host includes, and one include line into `custom_nginx/http_top.conf`; the rest of
  each file is left as it was, and `uninstall web-server` takes both out again. The trusted
  clients, the rate-limit zones and `robots.txt` go in `custom_nginx/stop-bots/`. It tests
  and reloads with `docker exec npmplus nginx -t` and `docker exec npmplus nginx -s reload`.
  Tested against NPMplus 2.15.1.
  - Every host gets the host-wide settings. An apply refuses a site with settings of its
    own, which includes the request-shape rules, since those are per-site only.
  - Everything else NGINX does, NPMplus does: every block response, the generated
    `robots.txt`, rate limiting and trusted clients.
  - stop-bots runs as root, and NPMplus's data directory is its container's to write, so
    nothing below it is reached through a link. Every file there is read, written and,
    after a failed config test, put back through its own directory; a link in the way
    refuses the apply. A file put back keeps its owner and loses any setuid, setgid or
    sticky bit. `uninstall web-server` removes only what it generated in
    `custom_nginx/stop-bots/`, and the directory only if that leaves it empty.
  - `stop-bots status` gives NPMplus's own fixes: `TRUST_CLOUDFLARE=true` behind
    Cloudflare, `TRUST_IP` behind another proxy, and `LOGROTATE=true` for its access log.
- **NPMplus's access log is read**, in both the format its releases write (the referer and
  the user agent unquoted) and the one its development branch writes (both quoted).
  NPMplus writes it only with `LOGROTATE=true`, to `/opt/npmplus/nginx/logs/access.log`.

### Fixed

- **A config root holding logs no longer takes the host's memory.** Finding sites read
  every file under the web server's config root whole. A root that also holds logs, such as
  a container's bind-mounted directory with its config and its access logs side by side, had
  them read whole on every `tick`, `status` and apply, and before `set-web-server` would
  switch away: a 1 GB log took 82 seconds of CPU and 7.7 GB of memory. A file over 4 MiB is
  now skipped by its size, unread; no file that declares a site comes near that.

## [0.7.0] — 2026-10-25

**Before upgrading:** nothing to do. The database schema is unchanged.

**After upgrading:** a database created by an earlier release opens on the screens it
always did; `v` shows the simple one. Only a new database opens on the simple screen.

**Going back to 0.6.0** works: it ignores the one setting this release adds, which
remembers the screen.

### Added

- **A simple screen, for a self-hoster who is not a sysadmin.** One screen with what most
  hosts need:
  - a one-line **Status** that names the worst problem and the one thing to do about it;
  - **Who can visit**: humans only, scanners, search bots, AI bots;
  - **Countries**;
  - **Keep running by itself**.

  Turning on "Keep running by itself" writes `/etc/cron.d/stop-bots` and switches both
  auto-applies on, with the SSH lock-out check. It says so and changes nothing when the TUI
  is not running as root.

  Switching humans only on asks first, since it takes the site out of search engines. The
  log detectors are shown, not switched. On a new database with no sites known, the simple
  screen looks for them when it starts. `x` is still the Blocks screen, to undo a block.

  "Press 'v' to enable advanced mode", beside its tabs, says how to reach every other
  screen. `v` switches between the two, and the choice is remembered; so does
  `stop-bots set-ui-mode --mode simple|advanced`.

## [0.6.0] — 2026-10-21

Traefik, beside NGINX and Apache.

**Before upgrading:** nothing to do. The database schema is unchanged, and an NGINX or Apache
host is configured as before.

**After upgrading:** `stop-bots status` has one new check, which warns when the access log
names no user agent. Nothing else changes on an NGINX or Apache host.

**Going back to 0.5.0.** An NGINX or an Apache host can. A Traefik host cannot by installing
the older release: 0.5.0 refuses a `/etc/stop-bots/host.conf` that names Traefik. First run
`sudo stop-bots uninstall web-server` with this release, which deletes the routers file, then
delete the `web_server` and `traefik_*` lines from `host.conf`, then install 0.5.0.

### Added

- **Traefik 3, beside NGINX and Apache.** `sudo stop-bots set-web-server traefik` reads the
  routers in the directory Traefik's file provider reads (`/etc/traefik/dynamic`, or
  `--root`) and writes `stop-bots.yml` there. That file holds routers of its own, at the
  highest priority a router may have, which answer a blocked request with a 403 before any
  site's router is asked. No file of yours is written, and no command is run: Traefik reads
  the file by itself. Tested against Traefik 3.5, with the full downloaded bot lists.
  - Sites Traefik learns from Docker labels are protected by the host-wide routers. A site
    has settings of its own when its router is in a file under the root.
  - Traefik cannot send any response but 403, serve the generated `robots.txt`, or rate
    limit, and `set-robots-txt` and `set-rate-limit` refuse to turn those on. An apply
    refuses a site with the HTTP/1.x or the old-TLS rule on, which no Traefik rule can
    express. The bare-address rule needs nothing: Traefik answers a request for an address
    with a 404 of its own.
  - Both of Traefik's access log formats are read. Traefik drops the user agent and the
    referer from them until told to keep them
    (`accessLog.fields.headers.names.User-Agent: keep`).
- **`status` warns when the access log names no user agent.** Not one of many recent
  requests naming one means no bot list and no detector that reads one can see anything,
  from a log that otherwise reads fine. It says how to fix it on each server.

### Changed

- **On Traefik, a request for an absent application's path is never a probe.** No file
  says which application answers behind a router, and sites from Docker labels are in no
  file at all, so `/wp-login.php` is never taken for a scan there.

### Security

- `rustls-webpki` is 0.103.16 and `webpki-root-certs` 1.0.10, for RUSTSEC-2026-0382 and
  -0383: certificates under distrusted intermediates could be accepted. stop-bots uses them
  only as a client, to download the bot lists and address feeds.

## [0.5.0] — 2026-10-20

Checked against what attacks look like elsewhere: a month of public honeypot traffic and two
hosts' real logs. A detector for requests that are not for a web page, every access log the
web server writes read instead of one, single-request detectors that recognise much more of
what honeypots see, and downloaded lists that no longer block the real search engines.

**Before upgrading:** nothing to do. The database schema is unchanged, and 0.4.0 still opens a
database 0.5.0 has used; a block `protocol-probes` made shows there with an unknown source and
stays in force.

**After upgrading:** the protocol-probe detector arrives off and marked new;
`stop-bots set-detector protocol-probes --enabled true` turns it on. Two things change on their
own, because they widen detectors that are already on rather than add one. Every access log
the web server's config names is now read, the first time with what logrotate kept back to the
longest detector window, so a site's own log can produce blocks on the first pass. And probe
paths, injection attempts and probes for absent apps recognise more. `stop-bots status` lists
the logs read.

### Added

- **A protocol-probe detector, `protocol-probes`: one request that is not for a web page.**
  Scanners looking for open proxies, SSH, SOCKS, WebLogic or mining pools send port 80
  the bytes they send everywhere. NGINX answers 400 and logs them as the request line.
  The detector counts a TLS handshake on the plain-HTTP port, a SOCKS or SSH handshake,
  `CONNECT`, a full URL naming a host that is none of this server's sites, and anything
  else that is not an HTTP request line. These lines used to be skipped as unreadable, so
  nothing judged them. On a month of one host's log, it blocked 248 addresses, 235 of
  which no other detector caught. It is never counted:
  - an empty request, which an unused browser connection also leaves;
  - a TLS alert, which one host's owner's own client was found sending;
  - anything from an address the site also answered normally in the same read.

  On for a new install. After an upgrade it is off and marked new until you choose:
  `stop-bots set-detector protocol-probes --enabled true`.

- **Every access log the web server's config names is read**, each from a cursor of its own: a
  site with its own `access_log` (NGINX) or `CustomLog` (Apache) was invisible to the detectors.
  `status` names them, and `status --json` lists every log read under `access_logs`.

- **A stored `set-log-paths --access-log` is read beside those logs; `--access-log` still reads
  only its file.** One says where the main log is, the other is one run against one file. A web
  server in a container (`set-web-server --test`) has only the stored log read: its paths are its own.

- **A log's first read also reads what logrotate kept**, `<log>.1` and `<log>.N.gz`, back to the
  longest window of a detector that is on. After an upgrade, a site's log read for the first time
  can therefore block at once, as the main log could on a new install.

### Changed

- **Probe paths, injection attempts and probes for absent apps know what honeypots see.**
  Replaying a month of SANS ISC DShield's web honeypot URLs showed what these single-request
  detectors missed. New probe paths: `/eval-stdin.php` anywhere, and `/.vscode/`. New
  payloads: ThinkPHP's `invokefunction`, and a backslash `\..\` traversal. Apps they
  probe for where no site runs them: Exchange, FortiGate SSL VPN, Tomcat manager, Solr,
  Spring Boot actuator, the Docker API, router admin pages and GeoServer. Together they
  cover 36% of the honeypots' requests, from 21%. On one host's month they block 87 more
  addresses, none a visitor's. `/autodiscover/` stays out, since Outlook asks for it.

- **An operator checking their own site is not taken for a prober.** A successful SSH
  login is now remembered for 90 days. For the first 7, nothing blocks the address, as
  before; for the rest, the two detectors that convict on a single request (probe paths
  and injection attempts) still leave it alone. A replay of a real host's logs found the
  owner convicted for asking for their own `/.DS_Store`, weeks after their last login.
  Detectors that count, such as web scanners, still block the address after the first week.

- **Web scanners also convicts one missing page asked for over and over**: 50 times
  inside its window, however few distinct paths that makes. A camera-firmware probe that
  asked for one path about 140 times a day never reached the seven distinct ones the
  detector counts. Assets, `robots.txt`, sitemaps and `/.well-known/` never count this way,
  since a browser asks again for a missing favicon on every page.

### Fixed

- **The BLOCKLIST tag agrees with the web server.** It compared each bot pattern as plain
  text, while NGINX and Apache read it as a case-insensitive regex. So `bingbot\/`,
  `^curl` and `[wW]get` never matched, though the web server blocked those clients. Of one
  host's 1,305 user agents, 24 were tagged wrong. Patterns are now read as a regex.

- **A backup of a site's config is no longer a second site.** A copy kept under the config
  root, such as `conf.d.bak-2026-10-12/` or `site.conf.orig`, was stored as a site of its
  own, and every apply wrote blocks into it. Files and directories whose names end the way a
  backup's or a package manager's leftovers do (`.bak`, `.orig`, `.old`, `.dpkg-dist`, `~`
  and the like) are now skipped.

- **A rescan forgets a site whose file is gone.** Before, its row stayed for good and read
  NOT FOUND, however often the sites were scanned again. `scan-sites`, `batch` and `r` in the
  TUI now say which sites they forgot, and drop their per-site settings with them. A site
  found in a new file keeps its row and settings. A scan that finds no sites at all forgets
  nothing, since that is more often an empty or unmounted root than a host with no sites.

- **A downloaded list no longer blocks Googlebot, Bingbot or GPTBot.** blocklist.de listed
  13 of their verified addresses on the day this was checked, so switching that feed on
  blocked them at the firewall. Each crawler's published ranges are now taken out of every
  abuse feed, cloud feed and hosting provider before the firewall is written. Blocking the
  crawler's category still blocks it, and so does blocking a country it crawls from.

- **A detector that convicts many addresses at once no longer slows to a crawl.** Each
  block checked every other convicted address to find the ones it covers, so the time grew
  with the square of their number: 40,000 addresses took 76 seconds, and a first run over
  a month of honeypot traffic took two and a half minutes. Both now take about a second.

- **The TUI's health check records a failure instead of closing.** A database error while
  the TUI stored its hourly probe ended the TUI. Now the error is the job's summary on the
  Scheduled tasks panel, as it always was under `tick`.

## [0.4.0] — 2026-10-16

More ways to catch bots, and one that checks your own sites: a `status` check for secrets
your sites serve, whole hosting providers blocked by network, three new detectors from the
access log, a port-scan detector that covers the whole host, and probe paths for
applications a host does not run.

**Before upgrading:** the database gains a schema version (the hosting-provider tables), and
0.3.0 refuses the upgraded database rather than misreading it. To go back, put back the copy
the upgrade kept, `/var/lib/stop-bots/db.sqlite3.bak-v7`, then install the older release.

**After upgrading:** everything here that blocks more arrives off on an existing install, and
the Dashboard marks it new. Login brute force, probes for absent apps and repeat offenders
(from 0.3.0) are low-risk to turn on: `stop-bots set-detector login-attempts --enabled true`,
`stop-bots set-detector probe-paths --app-aware true` and
`stop-bots set-repeat-offenders --enabled true`. Run `stop-bots status` once to see whether
any of your sites serves a file it should not.

### Added

- **Block whole hosting providers by AS number.** Hetzner, OVHcloud, Contabo,
  Akamai Linode, Vultr, Oracle Cloud, Alibaba Cloud, Tencent Cloud,
  Scaleway, Leaseweb, M247 and Hostinger are on a built-in list, and
  `add-hosting-asn --asn <n>` takes any other. Their ranges come from iptoasn.com's
  public-domain table, downloaded once for all of them (about 9 MB) by
  `update-hosting-asns` (`--source <file>` reads a local copy, gzipped or plain), and
  again every week with the other lists; only the chosen networks' ranges are kept.
  They are blocked like the AWS, Google Cloud and DigitalOcean feeds, with the same
  warning and the same port 80 left open for Let's Encrypt (`set-cloud-port-80`).
  `remove-hosting-asn` and `list-hosting-asns [--json]` complete the set. On the
  Dashboard, one "Hosting providers" row under Automatic blocking opens the list to
  tick, `status` warns about a provider that is chosen but not downloaded yet, and
  the Firewall screen's detail view names the provider an address belongs to. Off
  by default. Microsoft is not on the list: its network is also Bingbot's and
  Microsoft 365's (`add-hosting-asn --asn 8075` adds it anyway).

- **`status` says whether your sites serve their secrets.** The probe-paths detector
  blocks whoever asks for `/.env`; the new `exposed-files` check says whether they got
  it. Each site the web server's config names is asked, over loopback at the port it
  listens on and with its own name (TLS included, certificate unchecked), for 19 files
  scanners look for: `.env`, `.git/config`, `.git/HEAD`, `.svn/entries`,
  `.aws/credentials`, private keys, `.htpasswd`, SQL dumps, config backups,
  `.DS_Store` and phpinfo pages. A file counts only when it is answered 200, unlike
  the answer for a page that cannot exist, and looks like the file (`[core]` in a git
  config, `KEY=` lines in a `.env`), so a single-page app answering every path with
  its `index.html` reports nothing. Critical for credentials, repositories and dumps,
  a warning for the rest, with the NGINX or Apache lines that deny them. Asked as a
  current browser, so the site's own blocks do not turn it away; a site that answers
  everything with the block's status is reported as not checked rather than clean.
  Read-only, four seconds at most, and absent on a host with no sites. It runs with
  the rest of the health probe, so `stop-bots status`, the TUI and the schedule all
  ask. The access log shows requests for these paths from `127.0.0.1`; no detector
  blocks them, and `status` leaves them out of what it says about the log.

- **Probes for absent apps.** The probe-paths detector also blocks a request for
  `/wp-login.php`, `/wp-admin`, `/wp-includes` or `/xmlrpc.php` where no site runs
  WordPress (or, for `/xmlrpc.php`, Drupal), and for `/phpmyadmin` or `/pma` where none
  runs phpMyAdmin. An application is recognised from each site's config (its name in a
  `root`, an upstream, an `include` or a `location`; the path itself named anywhere) and
  from its document root (`wp-config.php`, `wp-login.php`, `config.inc.php`, Drupal's
  core files, or the path existing, at the root or one directory below). Where a log line
  names its site (`$host` in the log format), that site decides; where it does not, as in
  NGINX's default combined format, the path counts only when no site on the host runs the
  application. A site this cannot see into (one that passes requests to an unrecognised
  upstream, a document root that is not on this host, a web server in a container) counts
  as running every application, so never blocks its login page. `stop-bots
  list-probe-paths` (and `--json`) lists each path and why it is or is not a probe here;
  the Dashboard has a "Probes for absent apps" row. On for a new database; off, and
  marked new, on one an earlier release created:
  `stop-bots set-detector probe-paths --app-aware true` turns it on.

- **Login brute force** (`login-attempts`): blocks an address that sends 20 or more
  login attempts within an hour, for a day. A login attempt is a `POST` to a sign-in
  page: `/wp-login.php`, `/xmlrpc.php`, `/user/login`, `/login`, `/users/sign_in`,
  Joomla's `/administrator/index.php` and the like, plus the sign-in page of an
  application recognised behind a site (Nextcloud's `/index.php/login`, Jellyfin's
  `/Users/AuthenticateByName`). A login that succeeds in the end does not excuse the
  attempts before it. On for a database this release creates; off, and marked new, on an
  existing one (`stop-bots set-detector login-attempts --enabled true`). Trusted
  addresses, addresses that logged in over SSH and verified crawlers are never blocked.
- **Request rate** (`request-rate`): blocks an address that keeps up more than 120
  requests a minute for an hour, or that NGINX's own rate limit refused (429) a hundred
  times in the hour, for a day. The threshold is requests a minute
  (`stop-bots set-detector request-rate --threshold 300`). It is the only defence against
  a flood an Apache host has, which has no rate limiting here. Off by default, since
  many people can share one address; what an application recognised behind a site
  fetches on its own data routes does not count, and trusted addresses and verified
  crawlers are never blocked.
- **robots.txt violators** (`robots-violators`): blocks a client that fetched
  `robots.txt` and then a page it forbids to that client, for a week: a bot named in
  a `User-agent:` group with `Disallow: /` asking for anything, or anyone asking for the
  honeypot's trap path. It judges by the robots.txt stop-bots generates, the only one
  whose rules it knows were served, so it does nothing until that is on
  (`stop-bots set-robots-txt --enabled true`). Off by default; verified crawlers are
  never blocked.
- `list-detectors` marks a detector added since the database was created, and
  `list-detectors --json` carries it as `new_in_this_release`.

- **A port-scan detector, `port-scanners`, that protects the whole host**, not only the
  web server and SSH. With it on, the firewall script drops new connections to *trap
  ports*, ports scanners try and a web host does not serve (23, 135, 139, 445, 1433,
  1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211 and 27017), and logs them to the
  kernel log as `stop-bots-trap:`, at most ten lines a second. An address that tries two
  different trap ports within a day is blocked from every port for five days, and the
  block records the ports it tried. Never trapped: 22, 80 and 443, sshd's configured
  port, and anything listening on a non-loopback address when the firewall is rendered
  (`ss -ltnH`). The trap is on the input path after every address rule, so a trusted
  address or an SSH login is let through first, and a container's published port is never
  trapped. nftables and iptables, IPv4 and IPv6.
  - Off by default, on new databases as on existing ones, where it is marked new: it
    changes what the host accepts on ports beyond the web server and SSH, and a service
    started later on a trap port is dropped until the firewall is rendered and applied
    again.
  - `stop-bots set-detector port-scanners --enabled true` turns it on; `--ports` sets
    the trap ports (`default` for the built-in list), `--threshold` the number of
    different ports. `run-detector port-scanners --kernel-log <file>` judges a kernel
    log once.
  - The kernel log is read like the SSH log: `/var/log/kern.log`, then
    `/var/log/messages`, then the journal's kernel messages, from a stored cursor;
    `set-log-paths --kernel-log` names it. `status` warns when the detector is on and the
    kernel log cannot be read, or `ss` cannot be run.

### Changed

- **The Dashboard's Automatic blocking panel has the right-hand column to itself.** With a row
  per detector, feed and setting it no longer fitted beside Scheduled tasks on a 100×32
  terminal, so Scheduled tasks moved to the left column under Firewall script, and the two
  columns are now equal.

## [0.3.0] — 2026-10-16

The release that gets stop-bots ready to stand behind a 1.0: an undo for firewall
applies, a `?` that explains every screen, `--json` for scripts, repeat offenders blocked
for longer, and a command line tidied into the shape 1.0 will keep. Every old command
spelling still works and says what replaces it.

**Before upgrading:** the database gains a schema version (offences, for repeat
offenders), and a release before this one refuses the upgraded database rather than
misreading it. To go back, put back the copy the upgrade kept,
`/var/lib/stop-bots/db.sqlite3.bak-v6`, then install the older release; settings changed
since the upgrade are lost. Repeat offenders arrives off on an existing database
(`stop-bots set-repeat-offenders --enabled true`), as new blocking behaviour always does.

**After upgrading:** an apply from the TUI, or `render-firewall --apply` and
`batch --apply` run from a terminal, now asks you to keep the new rules within 60 seconds
and puts the previous ones back if nobody answers. Cron and scripts are unaffected.

### Added

- **`?` explains what is under the cursor.** On every screen, `?` opens what the
  selected row is, what it is set to now, what it can block by mistake and when a change
  reaches the host, with the keys for that panel beside it. This covers every detector,
  feed, country, category, crawler range, bot, request rule, site, trusted entry and
  block. `?` again opens the full key reference, which is what `?` alone used to do.
- **`--json` on `status` and every `list-*` command**: `list-firewall-rules`,
  `list-probe-paths`, `list-detectors`, `list-access-stats`, `list-reputation-sources`,
  `list-selected-countries`, `list-categories`, `list-bots`, `list-turned-away` and
  `list-trusted`. Each prints one JSON object (`{"rules": [...]}`,
  `{"checks": [...], "summary": {...}}`, ...) with times as Unix seconds and values in
  lowercase, as the command line spells them. `status --json` exits 1 on a critical
  check, as `status` does. Without the flag the output is unchanged. The field names
  become part of the stable contract at 1.0: fields may be added, never renamed or
  removed in a minor (`RELEASING.md`).
- **Confirm-or-revert for firewall applies someone is watching.** The TUI's "Apply
  everything" and render popup, and `render-firewall --apply` and `batch --apply` run from
  a terminal, now arm a revert before running the new script and then ask "Keep these
  firewall rules?" with a countdown (60 s; `--confirm-timeout` changes it). Enter or `y`
  keeps them; `n`, Esc or no answer puts the previous rules back — or, if there were
  none, removes the stop-bots table or chains. The revert runs from a transient
  `systemd-run` timer, or a detached process where there is no systemd, so it still
  happens if the TUI, the CLI or the SSH session dies. Until kept, the applied script
  the boot unit loads is left as it was. `--no-confirm` skips the question; without a
  terminal on stdin (cron, scripts) and for auto-apply nothing is asked or armed, as
  before. `status` mentions an apply waiting to be kept and a recent revert.
- **The applied script an apply replaces is kept** as `firewall.prev.nft` (or
  `.prev.sh`), and the new `stop-bots revert-firewall` goes back to it (running it again
  goes forward). While an apply waits to be kept, it reverts that apply now.

- **A question when no one has logged in over SSH.** The TUI's "Apply everything" asks
  "Do you log into this server over SSH?" before its preview when the SSH log holds no
  login from the last week. Answering no turns the lock-out check off, which is also a
  new row on the Dashboard (SSH lock-out check) and a new command,
  `set-ssh-lockout-check --enabled true|false`. Addresses that log in over SSH are still
  let through with the check off, and `status` warns if anyone logs in while it is off.
- **Repeat offenders are blocked for longer.** When a detector blocks an address again
  after its earlier block ended, the block doubles: twice the detector's TTL for the
  second offence, four times for the third, eight times from the fourth on, and never
  more than 90 days (a detector whose own TTL is longer keeps it). An address is
  forgotten 30 days after its last block ends, or as soon as you unblock it by hand.
  Finding an address that is still blocked is not a new offence, and trusted addresses
  and addresses that log in over SSH are never blocked, so never counted. It is a new
  row on the Dashboard (Repeat offenders), a new command,
  `set-repeat-offenders --enabled true|false`, and a line in `list-detectors`. The Blocks
  screen and `list-firewall-rules` say "2nd offence", "3rd offence" and so on. On for a
  new database; **off on an existing one** until you turn it on, and marked "new" there.
  Offences are counted either way, so turning it on later has a history to go by.
- The lock-out check counts the SSH session the TUI or CLI runs in as connected, read
  from its environment (it still works under `sudo`), so a log that rotated or a journal
  that keeps nothing no longer hides it.
- **Upgrade tests from every release since 0.1.0.** The database, NGINX site and firewall
  script that the released 0.1.0, 0.1.1, 0.2.0 and 0.2.1 binaries wrote are now test
  fixtures. The tests check that this build reads back every setting in them and
  re-applies over those files in place. `scripts/upgrade-fixture.sh` records each new
  release the same way.

### Changed

- **The command line has one shape for each kind of verb**, before 1.0 freezes it:
  - **`run-detector <detector>`** runs any detector over a log by hand, all ten of them,
    in place of the five `block-*` verbs.
  - **Lists have `add-*`/`remove-*` verbs**: `add-trusted`/`remove-trusted` in place of
    `trust` and `trust --remove`, and `add-exempt-path`/`remove-exempt-path` in place of
    `exempt-path` and `exempt-path --remove`.
  - **`update-*` updates every source of its kind** unless one is named:
    `update-bot-lists` (every bot list; it updated well-known-bots alone before),
    `update-crawler-ranges` (was `update-ip-ranges`, one crawler at a time),
    `update-reputation-sources` (every feed switched on; was `update-reputation-source`,
    one at a time) and `update-country-ranges` (every selected country).
  - **`set-web-server nginx`** takes NGINX's commands and root, in place of
    `set-nginx-commands`.

  `CONTRIBUTING.md` writes the conventions down.

### Deprecated

Each still works as before, prints a one-line warning on stderr naming its replacement,
and goes in 2.0.0:

- `block-ssh-scanners` (and `block-scanners`), `block-web-scanners`,
  `block-spoofed-crawlers`, `block-probe-paths`, `block-honeypot`: use
  `run-detector <detector>`.
- `trust`: use `add-trusted`; `trust --remove`: use `remove-trusted`.
- `exempt-path`: use `add-exempt-path`; `exempt-path --remove`: use
  `remove-exempt-path`.
- `update-ip-ranges`: use `update-crawler-ranges`.
- `update-reputation-source`: use `update-reputation-sources`.
- `set-nginx-commands`: use `set-web-server nginx`.

### Fixed

- **SSH scanners on a host that takes keys only** are counted when they reach sshd's
  `MaxAuthTries`: `maximum authentication attempts exceeded for …` is now read as a failed
  login. Such a scanner leaves no `Failed` line, so before this only its disconnect counted.

- **An SSH log with no login in it passed the lock-out check.** It said "lockout check
  passed: … no connected client would be blocked" when no one had been checked at all.
  It now says no one was checked, and refuses an apply whose rules block every address
  not listed (Allowlist, Only trusted IPs), since that blocks whoever connects next.
  This also applies to `batch --apply` and auto-apply.
- **Switching the geo mode asks first when it changes what the country list means.** The
  list is kept across modes, so Blocklist to Allowlist turned the countries you meant to
  block into the only ones allowed, with nothing said until afterwards. The TUI now names
  the countries and what they become before switching, as it does for an Allowlist with
  no country yet, and for Only trusted IPs, which takes every country off the list.
  `set-geo-mode` prints the same.
- **Turning on auto-apply of the firewall script asks first**, and says what it does: the
  scheduled render runs within five minutes of any change to the rules, not daily as the
  message said, and with auto-apply on it runs the script with no preview.
- Messages that named a key that does nothing where they appear. Blocks said `F, or a`,
  and a site's detail view said `apply (a/A)`. `a` and `A` now work in the detail view,
  and Blocks and Firewall name "a on the Dashboard" in place of `F` and CLI commands.
- Enter on a Firewall row blocked by a downloaded list did nothing, silently. It now says
  where the block comes from.
- The Firewall screen said "No failed SSH logins… this is the good case" when it could not
  read the SSH log at all. It now says the log could not be read, and how to fix that.

## [0.2.1] — 2026-10-15

A fix worth taking if a host renews a Let's Encrypt certificate over HTTP and has the
AWS feed on: its renewals have been failing, and its certificates will expire. After
upgrading, re-render the firewall (`sudo stop-bots render-firewall --apply`, or wait
for the cron) and run `sudo certbot renew`. `sudo stop-bots status` now says whether
Let's Encrypt can reach port 80.

### Added

- **Only trusted IPs, a geo mode in the TUI.** The Dashboard's geo mode popup (`m`) has
  a third option beside Blocklist and Allowlist: block everything host-wide except the
  addresses trusted on the Firewall screen, SSH logins from the last week and private
  networks. It is Allowlist with no country selected, which is what it was before it had
  a name, so choosing it deselects every country, and adding one makes it Allowlist
  again. The Geo panel's title says `only trusted IPs` with how many are trusted, and
  choosing it with nothing trusted says so first. On the command line it is still
  `set-geo-mode --mode allowlist` with no country selected.
- `status` says whether Let's Encrypt can renew, on a host where certbot renews a
  certificate over HTTP (its `nginx`, `apache`, `webroot` or `standalone` plugin). It
  runs the firewall's rules against addresses Let's Encrypt has validated from and warns
  when they would be dropped on port 80, naming the rule. Allowlist geo mode drops
  most of them.
- **Switching the AWS feed on asks about port 80 first.** In the Dashboard, the AWS
  ranges row opens a popup, "Let's Encrypt validates from AWS", with two choices: block
  AWS but keep port 80 open for renewals, or block port 80 too and let renewals over
  HTTP fail. Esc leaves the feed off. On the command line the choice is
  `set-cloud-port-80 --enabled true|false`, on by default, and `set-reputation-source`
  says which it is when it turns AWS on.
- The Geo panel's first row says how to change its mode: `Enter to add a country, m to
  change mode`, in place of `+ Add a country`.

### Changed

- **Delete or Backspace removes a country from the Geo panel; Enter no longer does.**
  Enter adds a country on the row above, so the same key deleting on the next row down
  made a removal one keypress away from an add. Enter on a country now says which key
  removes it.

### Removed

- The help screen's `w` line, for putting the web console behind NGINX: the key did nothing
  since the console was removed in 0.2.0.

### Fixed

- **The AWS, Google Cloud and DigitalOcean feeds no longer stop Let's Encrypt
  renewing a certificate.** Let's Encrypt fetches an http-01 challenge from several
  places, and every one but the first is in AWS, so with the AWS feed on every renewal
  timed out, and nothing but certbot's own failed unit said so. In Blocklist geo mode
  the cloud-provider feeds now leave port 80 open unless `set-cloud-port-80` says
  otherwise: it serves the challenge and the redirect to HTTPS, and the web server still
  turns bots away there by user agent. An address an abuse list, a country or a
  detector blocks stays blocked on every port.
- The SSH-scanner detector now sees failed logins on a host that takes keys only. There,
  at sshd's default log level, a wrong key for an existing user such as `root` leaves no
  `Failed` line, only `Connection closed by authenticating user root <ip> … [preauth]`
  (or `Disconnected from authenticating user …`), and those lines now count as failed
  attempts. A connection dropped before naming any user is a port scan and still does not.

## [0.2.0] — 2026-10-15

Apache, beside NGINX, and no web console. What changed since 0.1.1 is in this section
and under the two release candidates below. In short:

- **Apache, beside NGINX:** `sudo stop-bots set-web-server apache` makes this an Apache
  host, with Debian's paths and commands by default and RHEL's when `--root /etc/httpd`
  names RHEL's tree. NGINX is still the default, and an NGINX host has nothing to do.
- **No web console:** stop-bots is a TUI and a CLI, and nothing of it listens on a
  network. `sudo stop-bots install cron` runs the detectors on a schedule instead.
- **More of what scanners send is refused:** 88 more bots in the stop-bots enhanced
  list, and a list of old browsers' user agents, off by default, for the scanners that
  wear them.
- **Fewer false alarms from `status`:** its "Clients this host used to serve" check no
  longer counts forged crawlers, bots refused on purpose, or scanners wearing a
  browser's user agent.

**Upgrading from 0.1.x.** Install the new binary or package. If you had the console
installed, remove it as described below, before anything else. Then run
`sudo stop-bots install cron`, and apply: every site reads as not applied until the next
apply writes the new bot names in.

**Going back to 0.1.x.** An NGINX host can. An Apache host cannot by installing the older
package: 0.1.1 refuses a `/etc/stop-bots/host.conf` that names a web server, and where it
falls back to its defaults it takes the host for NGINX and never finds, updates or
removes the blocks this release wrote into Apache's sites. To go back, first run
`sudo stop-bots uninstall web-server` with this release, then delete the `web_server` and
`apache_*` lines from `host.conf`, then install 0.1.1. An NGINX host that was set to
Apache at some point may still carry `apache_*` lines, which 0.1.1 refuses; delete them
first. The same holds if 0.2.0 is ever withdrawn: removing it from the APT repository
does not take an Apache host back.

**The web console is gone.** stop-bots is a TUI and a CLI now, and nothing of it listens
on a network. The console was a control panel for the host's firewall and web server
config, reachable over HTTP; however carefully it was split and sandboxed, it was the one
piece of attack surface this tool added, on hosts it exists to protect. Everything it did,
the TUI does over SSH, and its unattended schedule is now cron's (`install cron`, below).
`web`, `set-web`, `install web`, `uninstall web` and Web Access are removed with it.

**If you had the console installed** (`install web`), remove it after upgrading, as root,
before anything else. This release no longer knows the console's units or user, so
`uninstall` will not take them out:

```
systemctl disable --now stop-bots-web.service stop-bots-helper.socket
systemctl stop stop-bots-helper.service
rm -f /etc/systemd/system/stop-bots-web.service \
  /etc/systemd/system/stop-bots-helper.socket \
  /etc/systemd/system/stop-bots-helper.service
systemctl daemon-reload
chown -R root:root /var/lib/stop-bots
userdel stop-bots
```

Then `sudo stop-bots install cron` to keep the detectors running. **If you set up Web
Access**, also delete the console's `location` between the `# BEGIN stop-bots console`
markers in that site, or its own site (`conf.d/stop-bots-console.conf` for NGINX,
`zz-stop-bots-console.conf` for Apache), and reload the web server; `uninstall` still
recognises both and takes them out with everything else. The console's settings stay in
the database unread, so an NGINX host can still go back to 0.1.1.

### Fixed

- `status` no longer reports a crawler's impersonators as one of this host's clients
  being turned away. A request claiming to be Googlebot, Bingbot or GPTBot from outside
  that crawler's published ranges is the forged-crawler detector's to judge, and is now
  left out of the "Clients this host used to serve" check: on one host, 16,210 refusals
  of forged Googlebots probing for `/.env` read as Googlebot being blocked.
- The same check no longer lists agents refused on purpose: a bot the lists class as a
  scanner or an AI crawler, or an agent blocked by hand, even one served before a list
  named it. What it reports is what it was written for, a client caught by an
  uncategorised pattern, as the Nextcloud and Jellyfin apps were by `okhttp`.
- Nor does it count refusals from an address that probed for a path like `/.env` or sent
  an exploit payload, whatever user agent it wore. Scanners dress as browsers: one
  Chrome string, worn by 33 addresses asking for `/.env`, read as a lost visitor.

### Removed

- The web console (`stop-bots web`), its settings (`set-web`), its service and root
  helper (`install web`, `uninstall web`), and Web Access, which put it behind NGINX or
  Apache. The detectors no longer skip the console's own requests or its operator's
  address, since there are none.

### Added

- **`sudo stop-bots install cron`** writes `/etc/cron.d/stop-bots`, which runs the new
  **`stop-bots tick`** every minute: the jobs the TUI runs while it is open, each when
  it is due, applying only as far as `set-auto-apply` and `set-auto-apply-firewall`
  allow. `tick` prints nothing unless something could not be recorded, so cron mails
  only trouble, and a run that finds the last one still going leaves. `uninstall cron`
  and `uninstall all` remove the file, before anything else. `status` has a Schedule
  check in place of the console's: whether the detectors have run lately, and what runs
  them.

- **Old browsers, a list with a switch of its own.** `sudo stop-bots set-old-browsers
  --enabled true` blocks, on every site, the user agents of browsers too old for anyone
  to still run: Opera 5 to 12, Firefox 1 to 9, Chrome 1 to 39, Internet Explorer 2 to 9,
  Android 1 to 3, early Lynx and ELinks, and feature phones (NetFront, UP.Browser,
  J2ME, Symbian, BlackBerry OS). Scanners rotate through these to pass for people; on
  one host a single scanner asked for `/.env`, `.git` and credentials files 1,150 times
  from 637 addresses, never twice with the same one, and no bot list can carry them
  because none is a bot's name. It is a row of the Policy panel in the TUI, and
  `list-categories` shows it. **Off by default**, on new hosts as well as upgraded ones,
  because a few of these strings are still a person somewhere (Opera Mini sends
  `Opera/9.80`); and humans only does not turn it on. Old iOS, Windows XP and
  Android 4 are left out on purpose: Bing's and Yandex's mobile crawlers send old iOS,
  and Gmail's image proxy sends XP. It is a setting rather than a schema change, so a
  host can still go back to 0.1.1.
- **88 more bots in the stop-bots enhanced list**, from a third pass over a real host's
  log (April to October, 474,041 requests): scanners and exploit kits that name
  themselves (`Go Web Pentest Tool`, `EnvScanner`, `Hello, World`, `r00ts3c`), probes for
  VPN and appliance logins (`PAN GlobalProtect`, `ncsrv`, `WinRM Client`, Cisco's),
  "research" scanners, SEO, lead and ads.txt crawlers, and two scanners calling
  themselves `MistralBot` and `CohereBot`, which asked only for framework manifests. All
  are scanners for policy, so they are blocked by default. YaCy's crawler, which now
  sends `yacycrawler` where the upstream list has `yacybot`, is added as a search engine. The list is
  compiled in and loaded when the upgraded binary first opens the database, so every
  site reads as not applied until the next apply writes the new names in.

## [0.2.0-rc.2] — 2026-10-14

Also corrected since rc.1's release notes, in its section below: with the console
installed, run `sudo stop-bots install web` after upgrading, or the old console and its
root helper go on running; and every NGINX site whose block exempts a path reads as not
applied until the next apply, which includes any site with a request-shape rule, not
only those with an exemption.

### Changed

- **An Apache root in RHEL's tree gets RHEL's defaults.** `sudo stop-bots set-web-server
  apache --root /etc/httpd` is now all RHEL needs: where the root's main config is
  `conf/httpd.conf`, the config test defaults to `apachectl configtest`, the reload to
  `systemctl reload httpd` and the access log to `/var/log/httpd/access_log`, in place of
  Debian's `apache2ctl`, `apache2` and `/var/log/apache2/access.log`, none of which exist
  there. Under rc.1 every apply on such a host failed its config test until `--test` and
  `--reload` were given, and the detectors read nothing until `set-log-paths` was. Stored
  commands and a stored log path still win, so a host set up that way is unchanged.

## [0.2.0-rc.1] — 2026-10-14

**Going back to 0.1.x.** This release is 0.2.0 rather than 0.1.2 because an Apache host
cannot be downgraded: every 0.1.x release promises that going back one patch release is
safe (see "Versioning" in `RELEASING.md`), and on an Apache host that is not true. 0.1.1
knows nothing of the web server setting. It refuses a `/etc/stop-bots/host.conf` that
names one, so most of its commands fail, and where it falls back to its defaults instead
(the web console, the detectors' log paths) it takes the host for NGINX: it looks for
sites in `/etc/nginx` and reads NGINX's log, and it never finds, updates or removes the
blocks this release wrote into Apache's sites. To go back, first run
`sudo stop-bots uninstall web-server` with this release, then delete the `web_server` and
`apache_*` lines from `host.conf`. An NGINX host can go back to 0.1.1 as before:
choosing NGINX writes no `web_server` line, and `set-web-server nginx` stores the same
keys `set-nginx-commands` does. Only an NGINX host that was set to Apache at some point
may still carry `apache_*` lines, which 0.1.1 refuses; delete them first. The database
and the files this release writes for NGINX are otherwise unchanged; a site whose block
exempts a path reads as stale until it is applied again (see Fixed).

**Upgrading, with the console installed.** Run `sudo stop-bots install web` after the
package upgrade, as for 0.1.0. The package has no maintainer scripts, so the console and
its root helper go on running the old binary until something restarts them, and the old
helper goes on writing the old blocks. `install web` restarts both, and keeps the
password and any unit you edited.

### Added

- **Apache, beside NGINX.** `sudo stop-bots set-web-server apache` makes this an Apache
  host. It is stored in `/etc/stop-bots/host.conf` with Apache's own config root
  (`/etc/apache2`), config test (`apache2ctl configtest`) and reload (`systemctl reload
  apache2`), each of which `--root`, `--test` and `--reload` change for a server that is
  not where Debian puts it. Every command, the TUI and the web console follow it, and
  say Apache where they used to say NGINX: the sites tab, what an apply reports, the
  health report's advice (`mod_remoteip` rather than NGINX's `real_ip` directives). NGINX
  is still the default, and an NGINX host has nothing to do: choosing NGINX writes no
  `web_server` line at all.
  - Sites are the `<VirtualHost>` sections under the root. Each gets a block of
    `mod_rewrite` rules at its top, between the same `# BEGIN stop-bots (DO NOT EDIT)`
    markers NGINX's blocks carry. Trusted addresses and user agents go in a generated
    `SetEnvIf` file, and the generated `robots.txt`, in `/etc/stop-bots/apache`, is
    served by a rewrite to the file, which answers before a site's own `ProxyPass /`.
  - Debian's layout (`/etc/apache2`, generated files in `conf-enabled`) and RHEL's
    (`/etc/httpd`, which reads everything from `conf.d`, where the generated files go).
    The defaults are Debian's, so on RHEL say all three of its paths and commands:

    ```
    sudo stop-bots set-web-server apache --root /etc/httpd \
      --test 'apachectl configtest' --reload 'systemctl reload httpd'
    sudo stop-bots set-log-paths --access-log /var/log/httpd/access_log
    ```

    For the console's root helper, relative log paths resolve against the root's own
    `ServerRoot`, through RHEL's `logs` link, and the helper is granted that tree and
    its logs; `install web --root` stores the root of the server the host runs.
  - The block decides once, on the request the client sent. Its last rule skips
    internal redirects and subrequests, so an exempt path that a front controller's
    `.htaccess` sends on to `/index.php`, or a trusted client there, stays let through,
    and a blocked request is served the site's own `ErrorDocument`.
  - `apache2ctl configtest` passes configs that do nothing, so the rest of Apache's
    config is read and an apply refuses, with what to change, a generated file in a
    directory Apache never includes, a `RewriteEngine Off` later in the same
    `<VirtualHost>`, and the HTTP/1.x rule on a host that does not speak HTTP/2
    (`mod_http2` off, no `Protocols h2`, or the prefork MPM). `status` never reads
    such a site as up to date.
  - `set-web-server` refuses to switch while the server chosen now still has stop-bots
    in its config, listing each file and naming `uninstall web-server` as the way to
    take it out. Switching first left the blocks where nothing would find them again.
  - Debian ships `mod_rewrite` switched off. An apply that needs it is refused with the
    `sudo a2enmod rewrite` that fixes it, and `status` says so too. Web Access needs
    `mod_proxy_http` (`sudo a2enmod proxy_http`) and puts the console behind Apache as a
    `<Location>` in a site, or as a site of its own in `sites-enabled` (`conf.d` on
    RHEL), named to sort last so it is never Apache's default site.
  - The detectors read `/var/log/apache2/access.log` unless `set-log-paths` names another;
    both servers write the same combined format. The application behind a site is
    recognised from its `ProxyPass`, `DocumentRoot` and `Alias`.
  - What Apache cannot do: it has no rate limiting of its own, so `set-rate-limit
    --enabled true` and the console's form refuse it and the TUI and console say why
    instead of offering it; and `mod_rewrite` cannot close the connection, tarpit or
    answer 418, so those three responses are a 403.
  - `uninstall web-server` is another name for `uninstall nginx`. Both remove the blocks
    and generated files of whichever web server the host is set to.
  - Database ids, `host.conf` keys and the root helper's requests keep their names, so
    an existing install migrates nothing.
- **Every release asset has a checksum and a build provenance attestation.** A `.sha256`
  beside each tarball and `.deb`, one `SHA256SUMS` over all of them, and an attestation,
  signed through Sigstore, that this repository's release workflow built each file.
  `RELEASING.md` ("Verifying a download") says how to check both. The tarballs now carry
  the man pages and the bash, zsh and fish completions the `.deb` already shipped.
- **`make demo`**, from a clone of the repository, drops you into a shell in a throwaway
  Ubuntu container running NGINX, with a few bad requests already in its log and a list
  of things to try. The firewall rules it applies stay inside the container.

### Changed

- **The licence is now AGPL-3.0-only**, rather than AGPL-3.0-or-later: no later version
  of the AGPL applies. Code contributions need a one-time Contributor License Agreement
  (`CLA.md`), which lets the project also be offered under a commercial licence.
  Running stop-bots on a server does not change the licence of anything it protects.

### Fixed

- An exempt path on NGINX now stays exempt behind a front controller. An internal
  redirect runs the block again with the new path: WordPress's `try_files $uri $uri/
  /index.php?$args` sent `/wp-json/wp/v2/posts` on to `/index.php`, so an exemption for
  `/wp-json/` (or an agent exemption) let a blocked client in and then blocked it on the
  second pass. Exemptions now match the path of the request the client sent wherever it
  has nothing NGINX would resolve (no `%`, `//` or dot segment), and `$uri` otherwise, so
  `/wp-json/../wp-login.php` still matches as `/wp-login.php`. Trust was not affected. A
  site whose block exempts any path reads as stale until it is applied again: one with
  an exempt path or an agent exemption, one serving the generated `robots.txt`, one
  with any request-shape rule (each exempts `/.well-known/`), and one the console is
  served under by path.
- The HTTP/1.x rule is refused on an NGINX host where nothing turns HTTP/2 on (no
  `http2 on;` and no `listen ... http2` anywhere under `nginx.conf`). There NGINX answers
  every visitor over HTTP/1.1, and the rule passed `nginx -t` and turned every one of
  them away.
- The web scanner detector no longer blocks the owner of a Nextcloud, Jellyfin, Immich
  or Navidrome server for what that application's own apps do. Nextcloud's iOS app,
  catching up on a hundred photos deleted elsewhere, asks after each one and gets a
  hundred 404s, which was enough to be blocked. The application behind each site is
  now recognised from its NGINX config (what it passes requests to, or Nextcloud's
  `/remote.php/dav` redirects), and its clients' requests on its own data routes, such
  as `/remote.php/` or Jellyfin's `/Items/`, are not counted by the 404 detector or by
  the three behavioural ones. The probe-path, injection, honeypot and forged-crawler
  detectors still judge those routes as they judge any other. A request counts for the
  site its `Host` names: a JSON format's `host`, or a quoted field appended after the
  user agent in a combined-style format. A request whose host can't be tied to a site
  gets the allowances of every application on the server. `scan-sites` says which
  application it found behind each site.
- A downloaded bot list can no longer make NGINX answer 500 to every visitor. A pattern
  that repeats in more than one place, such as `Mozilla.*.*.*.*[!#]`, or repeats a
  choice, such as `(a|aa)+`, passed the check, passed `nginx -t`, and then ran PCRE into
  its match limit on ordinary browsers' user agents, which NGINX answers with a 500.
  Such patterns are now dropped and counted like the other unusable ones. No entry in
  the current upstream lists repeats more than once.
- Geo allow-list mode no longer takes down the host's IPv6. Its `::/0` block also dropped
  IPv6 neighbour discovery, which conntrack does not track, so once the neighbour cache
  expired the host stopped answering over IPv6, SSH included, while the lockout check
  passed. Both firewall backends now accept router and neighbour advertisements and
  neighbour solicitations ahead of every rule, and link-local `fe80::/10` joins loopback
  and unique-local as an address no rule or detector treats as an internet client.
- A country, crawler range list or reputation feed that comes back empty no longer
  wipes what was stored for it. Under allow-list mode an empty zone file from IPdeny
  removed that country's ranges, and the next apply blocked the whole country. The
  stored ranges are now kept and the update reports a failure, as it already did for a
  list with no usable entries.
- One client can no longer shut everyone else out of the web console. A client that
  sent requests and never read the responses kept each connection open indefinitely,
  and 128 of them filled every slot. A response that makes no progress for ten seconds
  now ends its connection, and one client (an IPv6 client by its /64) may hold at most
  32 connections at once.
- The root helper no longer follows a log that is a link in a directory someone else
  can write, and refuses a FIFO or socket in place of a log. A site user who owned
  the directory a site logs to could otherwise have pointed the helper at another
  file root can read, and had its lines handed to the console, or hung the helper on
  a FIFO. A log linked from a directory only root controls is still followed.
- `set-honeypot-path /` is refused, and a `/` among `set-probe-paths` is skipped. Either
  matched every request and would have blocked every visitor, and the first also
  published `Disallow: /` for the whole site. The honeypot now matches only paths that
  start with it, as robots.txt does, rather than paths that contain it anywhere.
- A trusted user agent, an agent exemption or an exempt path longer than 1,024 bytes
  (once escaped) is refused, and a longer one already stored is left out of the
  generated config. One that long made `nginx -t` fail, and every apply after it was
  rolled back. A site with many exempt paths no longer hits the same limit: they are
  split between several `if`s, as the bot patterns are.
- The copy of the database taken before an upgrade is synced through the file it was
  written to, and the upgrade stops if that name no longer holds it. It used to be
  reopened by name, and with the console installed that name is in a directory the
  console can write, so a compromised console could have swapped in a FIFO and hung the
  root migration for good.
- The access log's time is read from the last brackets on the line, the ones NGINX's
  `$time_local` writes, rather than the first, which a client-controlled field can come
  before in a custom log format; a backdated stamp there would have aged the line out
  of every detector's window. A time zone with a non-ASCII character in it is refused
  rather than stopping the log read at that line. Neither is reachable with NGINX's
  stock formats.

### Security

- `rustls` is 0.23.46, for RUSTSEC-2026-0346, -0347, -0348 and -0349. stop-bots uses it
  only as a client, to download the bot lists and address feeds.

## [0.1.1] — 2026-10-01

### Fixed

- `status` no longer warns, on a host whose NGINX runs in a container, about two
  things only some setups use: the console's loopback bind (now only when NGINX
  proxies to the console, i.e. Web Access is set up) and `/etc/stop-bots/nginx` missing
  inside the container (now only while a generated `robots.txt` is served, the one
  thing the generated config reads from it).

## [0.1.0] — 2026-10-01

The first release whose command line, database, generated files and paths are a
contract: from here, a `0.1.x` patch release breaks none of them (see "Versioning" in
`RELEASING.md`). It is 0.1.0-rc.3 with no further changes to what it does; what changed
since 0.0.15 is under the three release candidates below. In short:

- **Safe for a stranger to run:** a quick start, tested end to end on fresh Debian 12
  and Ubuntu 24.04; `uninstall`; every apply previewed and confirmed; a firewall that
  only changes when something applies it; every block saying why it exists.
- **Bounded on a small server:** the log read once a minute, incrementally, with time
  windows; nftables sets with expiry in the kernel; iptables loaded atomically.
- **Upgrades that don't hurt:** a versioned database copied before each upgrade; a
  detector added later arrives off; an unedited unit replaced without `--force`.
- **A web console that is not root:** it runs as its own user and asks a small root
  helper, which treats its database as hostile, for each privileged action. Every
  finding of two security reviews is fixed.

Upgrading from 0.0.x or an earlier 0.1.0 candidate: install the new binary or package,
then run `sudo stop-bots install web` and `sudo stop-bots install firewall`.

## [0.1.0-rc.3] — 2026-10-01

**The web console no longer runs as root.** Under rc.2, code running in the console
was root on the host however it was sandboxed: it could ask systemd for anything over
D-Bus, and it wrote the NGINX config that NGINX's root master loads. Now the console
runs as its own `stop-bots` user, reads no host file and can write only its database.
A small root helper, reached over a socket only root and that user can open, does each
privileged action from a fixed list and treats the database as hostile. The split was
reviewed by trying to get from code running as the console to root; what that found is
fixed below.

Upgrading from rc.2: run `sudo stop-bots install web`. It creates the `stop-bots` user,
moves the NGINX commands, the NGINX root and the log paths out of the database into
`/etc/stop-bots/host.conf` (which only root can write), hands the database to the new
user, writes the console's, the helper's and the socket's units, and restarts the
console. `set-nginx-commands` and `set-log-paths` now need `sudo`.

### Security

- **The web console no longer runs as root.** `install web` creates a `stop-bots`
  system user and runs the console as it, with no capability, no write access outside
  its database, and systemd's sockets hidden. What needs root it asks of a new root
  helper, `stop-bots-helper.service`, started by `stop-bots-helper.socket`.
- **The console reads no host log.** Its unit has no log groups and hides `/var/log`
  and `/run/log`. The helper reads the access log and sshd's lines of the SSH log for
  it, 4 MB a request, and returns nothing else: no other line of `auth.log`, no other
  unit's journal. The journal is read as `journalctl -o json`.
- Root opening the console's database (the CLI, the TUI, the helper, `install web`,
  `uninstall`) follows no link in its directory, refuses a database or `-wal`/`-shm`
  that is a link or has a second name, and changes owners and modes only by descriptor.
- `uninstall` deletes a file the database's record names only if it is a plain file
  in a `conf.d` or `/etc/stop-bots/nginx` that starts with the stop-bots header.
- The root helper answers only root and the `stop-bots` user (`SO_PEERCRED`), and only
  eight typed operations — never a command, a path or config text. It reads the NGINX
  commands, root and log paths from `/etc/stop-bots/host.conf`, finds sites on disk
  rather than where a database row says they are, removes a recorded generated file only
  inside this root's `conf.d` or `/etc/stop-bots/nginx`, and re-validates what it
  renders.
- The console's firewall render and apply also refuse to block the browser's own address
  and anyone who logged in over SSH or to the console in the last 7 days.
- A console that is not root and has no `--helper` is read-only: it shows everything,
  and every action says it needs the helper.
- **Nothing the CLI prints can drive the terminal.** Every line, error and warning
  replaces control characters (C0, DEL, C1) with `�` and writes bidi and zero-width
  characters out as `\u{…}`. A row the console wrote, or a log line, could set the title
  or the clipboard of root's terminal through `list-*`, `status`, `apply-blocks` and `batch`.
- The TUI's `y` refuses to copy a value with such characters, and says why.
- A generated file the database's record names is used only by a path with no link in
  it, and only through its directory, held open from the check on: removed, read and
  put back after a refused test by `openat`/`unlinkat`/`renameat`, never by path.
  This covers applies, previews, the TUI and `uninstall`. A FIFO there is not read.
- The trust file gets each trusted address trimmed, as it was validated.
- Root opening the console's database (every CLI verb, the TUI, `install`, `uninstall`)
  runs no trigger or view in it: defensive mode on, triggers, views and
  `trusted_schema` off, as the helper already had.
- The root helper never upgrades the database: one at another schema version is
  refused until `sudo stop-bots install web` (or any root command) upgrades it. It also
  refuses a database with a second name (a hard link).
- `install web` moves the host settings into `host.conf` before it hands the database's
  directory to the console. The other order deleted an rc.2 host's NGINX commands, root
  and log paths instead of moving them.
- `install web` skips, with a warning, a `.bak-v*` beside the database that is a link,
  not a regular file, or a hard link, without following it, instead of failing the
  upgrade half way.
- The console's unit makes `/run` read-only outright (`ReadOnlyPaths=/run`), which
  `ProtectSystem=strict` alone did not under `ProtectKernelTunables=`. It hides
  `/run/dbus` rather than the socket, made first by a root `ExecStartPre=` if D-Bus has
  not made it, so D-Bus started after the console is out of its reach too.

### Changed

- **The NGINX test and reload commands, the NGINX root and the log paths move from the
  database to `/etc/stop-bots/host.conf`** (`key = value`, root's, 0644).
  `set-nginx-commands`, `set-log-paths` and `install web --root` write it. The first
  `sudo stop-bots` command after the upgrade (or `install web`) moves the stored values
  into it and deletes them from the database, once, and only from a database root owns.
- `stop-bots web --helper <socket>` does everything that needs root through the helper;
  it cannot be combined with `--root`, `--ssh-log`, `--firewall-out` or `--no-apply`.
  `install web --ssh-log` stores the path in `host.conf`, not in the unit.
- `uninstall` keeps `/etc/stop-bots/host.conf` unless `--purge`, like the database.

- Upgrading from rc.2: re-run `sudo stop-bots install web`. It replaces the unedited
  rc.2 unit without `--force`, gives `/var/lib/stop-bots` and the database to
  `stop-bots` (0700/0600), and restarts the console as that user.
- `install web` restarts a running console instead of leaving it as it was, so a new
  unit takes effect.
- `uninstall` removes the helper's socket and service with the console's unit;
  `uninstall --purge` also removes the `stop-bots` user and group.
- A copy taken before a schema upgrade (`.bak-v*`), and a database root creates in the
  console's directory, belong to the database's owner, not root.
- `status` warns when the console runs as root, when it has no root helper, and when
  the helper (or a console without one) cannot read a log it is set up to read
  (`console-account`, `console-helper`, `console-log-access`).

## [0.1.0-rc.2] — 2026-09-30

The findings of a security review of the web console, all fixed. The threat model: an
attacker who can reach the console over HTTP, and can send anything to the sites
stop-bots protects, but has no password and no local access. SQL and HTML output came
out clean; what did not was the path from what an attacker writes into the access log
to what the operator clicks, and the login throttle behind a proxy.

Upgrading from rc.1: the database goes to schema version 6 (a copy is kept as
`<db>.bak-v4`), and `sudo stop-bots install web` and `sudo stop-bots install firewall`
replace their units without `--force`, to pick up the new sandboxes.

### Security

- **The web console no longer gets its operator blocked.** Viewing an attacker's
  user agent or searching for a payload put it in the access log from the operator's
  address, and the injection detector blocked them for a week. No detector, and no
  access stat, reads a request under the console's path prefix (`web:base_path`), or,
  in a JSON log that records the host, one for a subdomain console's host.
- Addresses that logged in to the web console in the last 7 days are never blocked by
  a detector, as with SSH logins, and are on the scheduled apply's lockout check
  (schema version 5: `console_logins`).
- The Web Access panel's subdomain server block has `access_log off;`. Re-apply it
  from the panel to update an existing one.
- A JSON log line can no longer forge the evidence that clears an address: a user
  agent of `"\nclear"` was stored as that observation. Control characters in what a
  line says are replaced before it is stored.
- The access stats keep the first 512 characters of a user agent, not up to 8 KB, and
  hold to 20,000 rows as they are written, dropping the least-hit first, rather than
  only at the daily prune.
- The web console stores a log pass 5,000 rows at a time and lets its database go
  between them: a 200,000-line pass held every request, `/login` included, for 7 s.
- **A blocked user agent with a backslash in it blocked every visitor.** NGINX
  undoes `\\`, `\"` and `\t` in a quoted string before PCRE sees it; every regex
  is now written so that PCRE gets exactly the text that was checked.
- **A stored path exemption such as `/x\|` exempted every path**, and `/x\(`
  failed `nginx -t`. Exemptions are literal prefixes: `"`, `\`, whitespace and
  control characters are refused, and stored rows that break the rule are left out.
- Blocked user agents with a backslash or control character are refused. Rows
  stored earlier are still written, now exactly as they read.
- Bot-list patterns PCRE would refuse (`[z-a]`, `{2,1}`, `{99999}`, unknown POSIX
  classes) are left out and counted in the fetch summary, instead of failing
  every apply.
- The server block that serves the console (Web Access path mode) exempts the
  console's prefix, so a site rule cannot lock the operator out. `limit_req`
  still applies there.
- `--root` outside `/etc/nginx` keeps generated files in `<root>/conf.d`, and
  never reads or writes the host's `/etc/nginx/conf.d`.
- **The operator's own browser gets past a login flood.** A successful login sets a
  90-day `stop_bots_remember` cookie (schema version 6); a login presenting it skips the
  shared throttles. `web --set-password` forgets them all.
- A throttle key shared by everyone behind an untrusted proxy has no backoff, only the
  global limit; IPv6 clients are throttled by /64.
- Web Access turns on `trust_forwarded_for`, and `secure_cookie` on a TLS site; a new
  `web-proxy` health check warns about a proxied console that does not trust its proxy.
- Argon2 runs outside the database lock.
- Request heads and bodies have 10 s to arrive, and at most 128 connections are open.
- The Firewall page shows 200 user agents a page, and links and acts on one by
  reference: no client's text goes into a console URL.
- A flash message is named in the URL by an id; `?flash=<text>` shows nothing.
- htmx is removed, and the CSP allows no script file.
- Direction overrides and zero-width characters in a user agent are shown as `\u{202E}`.
- The login page no longer names the host, and errors before login say nothing of
  their cause; `/nginx/<unknown id>` is a 404.
- **The web console's unit is `ProtectSystem=strict`**: it can write its database,
  `/etc/stop-bots`, the NGINX config, the log directories that config names, and
  `/run`, and nothing else — not `/etc/cron.d`, systemd units or binaries.
  Capabilities are cut to the six it uses, and it gets `LimitNOFILE=16384` and
  `TasksMax=1024`. A site added later that logs elsewhere: re-run `install web`.
- **The firewall boot unit is sandboxed too**: read-only, no `AF_UNIX` (so the
  script it loads cannot ask systemd for anything), network capabilities only.
- Re-run `sudo stop-bots install web` and `install firewall` to get both; an
  unedited unit from 0.1.0-rc.1 or 0.0.x is replaced without `--force`.

### Changed

- The internal cron's daily crawler-range download waits for the first download, as
  the weekly one does: a database that has never downloaded anything leaves it to the
  operator (`u`, "Update everything", or `batch`) instead of fetching on the first tick.
- Stored entries left out of the NGINX config are named: by `status` and the
  Dashboards (`skipped-entries`), on stderr by `apply-blocks`, and counted by `batch`.

### Fixed

- `install web --root` is stored, as `set-nginx-commands --root` would; it was
  accepted and ignored.

## [0.1.0-rc.1] — 2026-09-30

The first release whose command line, database, generated files and paths are a
contract: see "Versioning" in `RELEASING.md`. Upgrading from 0.0.x:

- The first open copies the database to `<db>.bak-v0`, then upgrades it in place.
  An older stop-bots will refuse the upgraded database; restore the copy to go back.
- The first log pass reads the whole access log once, and keeps only what falls
  inside each detector's window.
- Renders now go to `firewall.next.*`; the script loaded at boot changes only when
  something applies. Apply once after upgrading: the Dashboard says "not applied"
  until you do.
- `sudo stop-bots install web` (and `install firewall`) replaces an unedited unit
  from any 0.0.x without `--force`, and the web unit gains resource limits.

### Added

- **A stranger test**: the README's quick start, from `apt install` of the
  `.deb` to `uninstall all`, on fresh Debian 12 and Ubuntu 24.04 containers
  under systemd (`make stranger-test`; CI on pushes to main and weekly).
- **Per-site bot overrides in the web console**: a site's page searches the
  bots and allows or blocks one on that site only, as the TUI's site detail does.
- **Crawler IP ranges on both Dashboards**: Googlebot, Bingbot and GPTBot, each
  with its range count, when it was fetched, and a refresh (Enter in the TUI)
  that waits for any other download, like "Update everything".
- **A weekly "Update every list" job in the internal cron**, the same plan as
  "Update everything", at a week plus up to 12 hours' jitter.
- `set-detector <name>` and `list-detectors`: switch, TTL and threshold for
  every detector, as the internal cron and `batch` use them.
- `set-subnet-escalation`: IPv4 /24 escalation, previously unreachable.
- `set-category`, `set-bot` (both with `--site`), `list-categories`, `list-bots`.
- `set-firewall-rule --enabled`, `set-firewall-backend`.
- `set-web`: bind, exposure, path prefix, allowed hosts, `X-Forwarded-For`
  trust and the `Secure` cookie, in one place.
- `--db` works before or after any subcommand, and falls back to `STOP_BOTS_DB`.
- **`stop-bots uninstall`** (`nginx`, `firewall`, `web` or `all`), with
  `--dry-run`: both units, the nft table and iptables chain, every NGINX
  block (tested, put back on failure) and the generated files. The database
  stays unless `--purge`. Needs root, or `--prefix`.
- Every generated whole file (units, `conf.d` files, `robots.txt`, firewall
  scripts) starts `Generated by stop-bots <version>`. The site blocks and
  their markers do not, and the markers are frozen.
- A `managed_files` table (schema version 2) records every generated NGINX
  file written; cleaning up works from it, so a `conf.d` left behind by an
  old NGINX root is removed too.
- `render-firewall --apply`: runs the script if the lockout check allows, and
  makes it the one loaded at boot.
- `apply-blocks --dry-run` and `batch --dry-run` print what would change and change
  nothing; `--diff` adds a unified diff of every file.
- **Every firewall rule says why it exists** (schema version 4): its source
  (the detector, or `cli`/`tui`/`web`) and the log line that triggered it,
  cleaned of control characters and capped at 300 bytes. Older rules read
  "before 0.1".
- **A Blocks screen** in the TUI (`5`, or `x`) and the web console (`/blocks`):
  every stored rule with its source, age, expiry and evidence, filtered by
  source, searched by address (an address finds the range that blocks it),
  paged, with unblock per row and "unblock all from this source" behind a
  confirmation that shows the count. The Firewall screens' `BLOCKED` tag
  names the detector.
- `list-firewall-rules` shows each rule's source, age, expiry and evidence,
  newest first, and takes `--source`. `remove-firewall-rule --source <name>`
  removes every rule from one source and prints the count; `--dry-run` only counts.
- **Unblocking a detector's block sticks.** The detectors leave that address
  alone for as long as the block was meant to last, however long the log keeps
  the lines that earned it.
- The TUI header and every web console page name the database when it is
  not `/var/lib/stop-bots/db.sqlite3`; the non-root fallback says "Not
  root: settings go to your user database, not the system one".
- **Man pages and shell completions in the `.deb`**: `man stop-bots` and a
  page per verb (`man stop-bots-batch`), plus bash, zsh and fish completions,
  generated from `--help` by the hidden `stop-bots generate-docs --out <dir>`.

### Changed

- **The README starts with a quick start** (install, the TUI path, the same from the
  CLI, undo) and states the supported platforms: Debian and Ubuntu, systemd, NGINX.
  Its screenshots show the Blocks screen.
- The crates.io and `.deb` descriptions say "a TUI, web console and CLI".

- **Re-installing over an unedited unit replaces it without `--force`**,
  including one any 0.0.x wrote. Units carry a `stop-bots-template` hash
  line; an edited one is still refused. A 0.0.1–0.0.6 unit's `--root` is
  kept as the stored NGINX root.
- The unit and the Web Access file point at `set-web`, not `web --save`.
- **Detection has windows, so a block that expires stays expired.** Each
  detector counts only log lines newer than its window (a day; an hour for
  the three behavioural ones), stored per detector as `detect:<id>:window_hours`.
  A block spends the evidence that made it, so only a new offence brings it back,
  and a first scan never blocks for old lines.
- **Each log is read once a minute, incrementally.** One pass from a stored
  cursor (device, inode, offset) serves every detector and the access stats,
  survives rotation and truncation, and parses outside the web console's lock.
  On a 200 MB log a tick went from 24 s and 440 MB to 2–3 s and 10 MB, and the
  TUI's start-up from 2.9 GB to 37 MB.
- **journald is read with `--since` and a stored cursor**, in `short-iso` so its
  lines keep their times, instead of the whole sshd journal on every read.
- **`set-log-paths` is honoured everywhere**: `batch`, the lockout guard, the
  Firewall screens and `record-access-stats`. A flag still wins.
- A `log_evidence` table (schema version 3).
- **The database has a schema version** (`PRAGMA user_version`). Upgrading
  from any 0.0.x first copies the database to `<db>.bak-v0` (mode 0600),
  and a database written by a newer stop-bots is refused rather than misread.
- **An upgrade never switches a detector on.** A detector added after your
  database was created starts off there, and the Dashboard's Automatic
  blocking panel marks it "new" until you switch it either way.
- **The Rust library is not a supported API.** Its modules are hidden from the
  documentation, and the version now describes the program alone: its command
  line, database, generated files and paths. `RELEASING.md` says what breaks them.
- **A release is built only after the tests pass**, on both `x86_64` and
  `aarch64`. The `aarch64` tests also run on every push to `main`; before,
  that binary was shipped having only ever run `--version`.
- `rand` 0.10.3, and the release workflow on `upload-artifact` v7 and
  `download-artifact` v8.
- **AUR and Gentoo packages at 0.0.15**, seven releases on from 0.0.8.
  `stop-bots-bin` now also installs on `aarch64`. `packaging/bump.py <version>`
  does this after each release from the published checksums.
- Housekeeping: `REVIEW.md` holds open items only, and `CONTRIBUTING.md` lists
  every module and quotes one coverage figure, measured.


- The SSH and web scanner thresholds are stored settings (defaults 20 and 7,
  as before), so the cron and `batch` honour them.
- `render-firewall` no longer needs `--backend`: it uses the stored one, and
  `--out` defaults to that backend's file (`firewall.sh` for iptables).
- The `block-*` detectors default `--threshold` and `--ttl-days` to the stored
  values instead of fixed numbers.
- `block-scanners` is now `block-ssh-scanners`; the old name works for one release.
- `web --allowed-hosts`, `--trust-forwarded-for`, `--secure-cookie` and `--save`
  are deprecated in favour of `set-web`. They still work, with a note, for one release.


- **nftables: addresses go in sets.** One set per verdict and family, matched by one rule
  each, instead of one rule per address. First-match order is kept.
- **nftables: timed blocks expire in the kernel.** A detector's block is a set element with a
  `timeout`, so it lifts without re-applying the script.
- **iptables: loaded with `iptables-restore --noflush`.** The chain is replaced in one step, and
  a failed apply leaves the previous chain as it was.
- **iptables: IPv6 rules are applied** through `ip6tables-restore`, not skipped.
- `status` counts set elements and ip6tables rules as loaded rules.
- The web unit runs at `Nice=10` and `IOSchedulingClass=idle`, with
  `MemoryHigh=25%` (throttles) and `MemoryMax=50%` (backstop) of RAM.
- **The database runs in WAL mode**: readers no longer wait for a writer.
  Its `-wal`/`-shm` are 0600, `install web` tightens them and
  `uninstall --purge` removes them.
- **One apply at a time**: NGINX applies and firewall scripts take a lock
  (`/run/stop-bots.lock` as root). A second waits up to 10s, then says
  another stop-bots is applying.
- **Errors name the next step**: `nginx` not on PATH points at
  `set-nginx-commands`, a missing NGINX root at `--root`, a permission a
  non-root user lacks at sudo (or `--db` for the database), a missing
  `nft` or `iptables-restore` at the package or `set-firewall-backend`.


- **A render no longer changes what loads at boot.** It writes
  `/etc/stop-bots/firewall.next.nft` (or `.next.sh`); only an apply that succeeded
  copies it to `firewall.nft`, the file `stop-bots-firewall.service` loads.
  `install firewall` now ends by pointing at `render-firewall --apply`.
- **One lockout policy for every front-end.** No readable SSH log: the script is
  written, with a note, and not applied. A connected SSH client the rules would
  block: nothing is written or applied. `--force` overrides both.
- The Dashboards and `status` say whether the rules are applied, rendered and not
  applied, or changed. `batch --out` names the applied script.
- **"Apply everything" asks first.** `a` in the TUI and the console's button show the
  files that would change, the rules added and removed, and the lockout check's
  verdict, with a diff on request (`d`, or "Show the diff").
- The TUI's render popup opens on the stored backend and its path, and remembers
  the backend it renders for, as the console does.


- **The TUI's status message shows on every screen**, in the footer, until the
  next key press. It used to reach only the Dashboard.
- One spelling for relative times ("5m ago"), category names ("Search bots",
  "AI bots") and the health strip's labels, in the CLI, the TUI and the console.
- **Only an installed firewall backend is applied.** The TUI's render popup and
  the console's backend list mark one whose `nft` or `iptables-restore` is
  missing "not installed", and applying with it is refused, naming the package.
- A new database renders for the backend this host has, preferring nftables. One
  that has chosen, or has written a script, keeps its backend.
- **One download at a time, across every stop-bots.** "Update everything", the
  cron's download jobs and `batch` share a lease in the database; a second one
  says so and fetches nothing.
- **No detector blocks a Cloudflare edge address**, from a compiled-in copy of
  Cloudflare's published ranges. `status` warns when most of the access log
  comes from them, and gives the `set_real_ip_from` lines that fix it.

### Fixed

- A pre-release's `.deb` is versioned `0.1.0~rc.1-1`, not `0.1.0.rc.1-1`, which
  Debian sorted after `0.1.0-1`: a host that installed a release candidate would
  never have upgraded to the release.
- `status` on a host run from the CLI and cron reported "UNKNOWN: Console service";
  the console is optional, and not having one is now OK.
- Piping a command's output into something that stops reading early (`| head`)
  ended in a panic; it now ends quietly, like any other command-line tool.
- The README's cron lines named `--ssh-log /var/log/auth.log`, which Debian 12
  does not have, so `batch --apply` refused. The SSH log is found on its own.

- `render-firewall --out` no longer suggests running the file by hand, which would
  not survive a reboot; it points at `render-firewall --apply`.
- The web Firewall page: a `BLOCKED` tag naming its detector no longer spills over
  the address beside it. The tag says `BLOCKED`, with the time left and the detector
  on a line under it.
- Time left on a block is rounded to the nearest day or hour. A five-day block read
  "4d" a minute after it was made.

- Messages that named the wrong key: "render the firewall (f)" (the key is `F`,
  and `a` applies) and "press s, then r" (NGINX is `n`).

- **A log in a format the detectors cannot read is reported.** `status` warns
  when under half the access log parses, quoting a line, instead of "no requests
  recorded yet".
- **One row per firewall rule.** The TUI, the console and `batch` could race
  into duplicate rules; upgrading merges them into the oldest (keeping the
  longest expiry), and adding a rule that exists now extends it instead.
- `SECURITY.md` said every detector is off by default; five are on. It now
  says which, and that blocking traffic you wanted is a matter of tuning.


- `--help`: `web`, `status`, `batch`, `set-log-paths`, `set-nginx-commands` and
  `set-block-response` showed another command's text or none. Every flag has help now.
- **`batch` and `apply-blocks` store the bot list built into the binary.** On a
  host run by the CLI alone, `batch --no-fetch` blocked no user agent at all, and
  `batch --dry-run` showed a fresh host no NGINX change.
- `install firewall` after an apply no longer tells you to go and apply.

## [0.0.15] — 2026-09-27

### Added

- **An injection-attempt detector.** A request carrying an exploit payload
  gets its address a seven-day firewall block from a single request, like a
  probe path. It reads the whole request line — query string included,
  which every other detector drops — plus the user agent and the referer,
  after undoing percent-, double- and `%u`-encoding, full-width characters
  and NGINX's own log escapes. It recognises Shellshock, Log4Shell lookups,
  OGNL and other expression injection, the PHP-CGI `allow_url_include`
  exploit, command injection, path traversal, NUL and CRLF bytes, and
  exploits a client names by CVE in its user agent. Signatures a person
  might type (`/etc/passwd`, `union select`, `<script`) only count outside
  search-box parameters and referers. On five months of one host's log it
  matched 715 addresses, none of which had done anything but scan, 157 of
  them caught by no other detector. On by default, like probe paths; the
  Dashboard's "Automatic blocking" panel switches it off.

## [0.0.14] — 2026-09-27

### Added

- **51 more scanners in the built-in list**, read off five months of a
  real host's access log against what that host was actually blocking.
  Among them LeakIX's `l9explore` — 6,042 requests there, the largest
  single scanner in the log — `feroxbuster`, and a run of self-declared
  security and research scanners. Three (`l9explore`, ipip.net's
  `HTTP Banner Detection`, `BitSightBot`) were already in ArcJet's list
  with no category, so no policy could ever block them; the built-in
  entries merge with those and give them the scanner flag. Every new
  pattern was checked against every user agent in that log: each matches
  only the bot it names.

## [0.0.13] — 2026-09-26

### Security

A security review of the whole codebase. Every item below has a regression
test. Upgrade: several of these can be triggered remotely without a
password.

- **SSH log lines are read the way sshd writes them.** A client chooses its
  own SSH username, and sshd logs it verbatim. The parser searched each line
  for `Accepted`/`Failed` and took the first `from <address>`, so a crafted
  username could make a failed login count as a successful one — a week of
  immunity from every block — or credit failures to someone else's address.
  One username crashed the TUI and stopped the web console until a restart.
  The message must now begin where sshd's does (after an `sshd[pid]:` or
  `sshd-session[pid]:` tag in a syslog file), and the address is the last
  `from <ip> port <n>`, which sshd writes after everything the client sent.
- **Bot-list patterns can no longer escape NGINX's quoting.** Long pattern
  lists are split across several `if` lines, and the split could fall inside
  an escaped `\|`, leaving a quote escaped and the rest of the pattern read as
  config. Chunks now hold whole patterns only and are re-checked.
- **Re-applying a site no longer corrupts it** when a pattern or user agent
  contains `#`, `{` or `}`. The tool re-reads its own blocks with a parser
  that now follows NGINX's quoting rules.
- **Patterns that match every visitor are refused**: empty ones, empty
  alternatives (`|`, `||`), ones with too few literal characters (`.*`), and
  ones shaped for catastrophic backtracking. That covers the bot lists, the
  console's "block this user agent" and the TUI. A list over 10,000 entries,
  or with a pattern over 1 KiB, is refused whole.
- **A console session can no longer write arbitrary NGINX config.** The
  Web Access path prefix is limited to letters, digits and `._~-` per
  segment, and is quoted in the generated `location`. A prefix stored by an
  earlier version that no longer passes is refused at startup with the fix
  to run.
- **A failed `nginx -t` puts every file back.** Applying used to write site
  files, test, and leave a config that failed the test on disk, where the
  next NGINX restart would load it. Every apply path — CLI, `batch`, cron,
  TUI, console — now restores what it changed and only reloads after the
  test passes.
- **Files are replaced, not written through symlinks.** Generated NGINX
  files, the console's own config and the firewall script are written to a
  temporary file and renamed into place. A site file that is a link is only
  followed to a target inside the NGINX root. The firewall script is refused
  in a directory other users can write to.
- **A downloaded feed cannot block (or, in allowlist mode, admit) the
  whole internet.** Fetched ranges broader than `/3` (IPv4) or `/12` (IPv6)
  are dropped and named in the summary. A fetch whose ranges together cover
  more than half of IPv4 (country zones) or a tenth (every other feed), or
  5% of IPv6, is refused whole and the previous ranges kept, as is one with
  more than 250,000 entries.
- **The lockout guards compare addresses, not text.** The console refused
  to block your own address only when the text matched exactly; a range
  containing it, `/32`, a leading space, another IPv6 spelling or an
  IPv4-mapped address got past. It now tests containment, and a manual
  block of `0.0.0.0/0` or `::/0` is refused. The SSH guard no longer counts
  an Allow limited to one port as protecting SSH.
- **The console's "Apply everything" refuses when the SSH log cannot be
  read**, as `batch --apply`, cron and the TUI already did. Writing the
  script without applying it still works.
- **`batch` now records SSH logins** for the lockout guard. A cron-only host
  had an empty record, and relied on whatever the log still held after
  rotation.
- **Plain path exemptions match NGINX's resolved `$uri`**, so a blocked
  client can no longer reach any path by prefixing it with an exempt one and
  `..`. The `robots.txt` exemption is exact. Sites with exemptions read
  `STALE` once after upgrading.
- **Sessions end when the password changes**, and last at most 12 hours
  however actively they are used.
- **The database is created private**: its directory `0700` and the file
  `0600`. An existing database readable by others is tightened when opened
  by its owner.
- **Downloads refuse plain HTTP**, including through a redirect.

### Fixed

- One invalid UTF-8 byte in a log no longer makes the whole log unreadable
  until it rotates.
- A JSON access-log line with a duplicated field is skipped rather than
  attributed to whichever copy came last.
- User agents printed by `list-turned-away` and `list-access-stats` have
  control characters replaced, so a logged user agent cannot send escape
  sequences to your terminal.
- The detector block duration is limited to 3,650 days; larger values
  overflowed and produced blocks that had already expired.
- A correct console login clears that client's earlier failed attempts.
- Logging out of a console under a path prefix lands on its own login page.
- `install firewall --prefix` no longer runs the real `systemctl`.
- Paths in generated systemd units are quoted and escaped.
- The boot unit from `install firewall` follows the stored backend, so an
  iptables host loads `firewall.sh`.
- `nft`, `iptables` and friends are found in `/usr/sbin` and `/sbin` even
  under cron's minimal `PATH`.
- The honeypot path is limited to characters that keep it one `robots.txt`
  line.
- Every console response, including the refusal of an unknown host name and
  error pages, carries the security headers.

### Changed

- **The rotating-user-agent detector's default threshold is 20 agents, not
  8.** One household behind one router reached 8 in a day. Hosts that set
  the threshold keep their value.
- The Web Access panel, its TUI popup and the Help page say that path mode
  shares an origin with everything else on that site.

## [0.0.12] — 2026-09-25

### Added

- **Path exemptions scoped to one user agent.** `stop-bots exempt-path
  --site <site> --path /remote.php/dav/ --user-agent okhttp` lets clients
  whose user agent contains `okhttp` through on that site's path, and
  nowhere else — for an app of your own that a bot list catches by its HTTP
  library. The Boox reader's WebDAV client and the Jellyfin Android TV
  player's stream requests both say only `okhttp/4.x`, which the NGINX
  Ultimate Bad Bot Blocker list blocks. Trusting the user agent would let
  every scraper built on the same library through on every site; this is
  one site, some paths, one client. In Site detail, type the user agent
  after the path (TUI) or in its own field (web). The generated clear
  matches NGINX's resolved `$uri`, so `..` and `%2e%2e` cannot walk out of
  the exempt prefix. Existing exemptions render exactly as before, so no
  applied site reads `STALE` after upgrading.

## [0.0.11] — 2026-09-25

### Added

- **`--trust-forwarded-for` and `--secure-cookie` on `stop-bots web` and
  `stop-bots install web`.** The README, the console's Help page and the
  NGINX file the Web Access panel writes all told you to set
  `web:trust_forwarded_for` and `web:secure_cookie`, and nothing could.
  Both take `true` or `false`, are stored whether or not `--save` is given
  (like `--allowed-hosts`), and stay as set until changed.

### Fixed

- **With `web:trust_forwarded_for` on, a client could name its own
  address.** The console believed the *first* entry in `X-Forwarded-For`,
  but the proxy block the Web Access panel generates uses NGINX's
  `$proxy_add_x_forwarded_for`, which appends the address NGINX saw to
  whatever the client sent. A client that sent its own header could claim
  any address, and so get its own login-throttle bucket per request and
  get past the guard that stops you blocking the address you are
  connected from. The console now believes the *last* entry, the one the
  proxy wrote. Hosts with the setting off, the default, were not affected.

### Changed

- **README trimmed** after a review pass. The "Is it actually working?"
  section is gone; `stop-bots status --help` covers the same ground. "Contributing" now says contributions are not accepted at this time.

## [0.0.10] — 2026-09-24

### Added

- **`stop-bots list-turned-away`, and a `status` check to go with it.**
  Reads the access log and reports, per user agent, how many requests came
  back with your configured block response and how many were served.

  Nothing in this tool previously answered *"what is my own policy turning
  away?"*. On one host in a single week that cost three first-party
  applications — Nextcloud's iOS client, Nextcloud's Android client, and
  Jellyfin on a Fire TV — each matching `okhttp` in a public bad-bot list,
  and each discovered only when somebody said an app had stopped working.
  All three were visible in the access log from the first minute.

  The two columns are the point. A client with 262 refusals and nothing
  served is being stopped at the door; one with 300 served and three
  refused is being told no by the application behind NGINX. On a host
  answering `444` the count is exact, since NGINX invents that code and no
  application returns it; on `403` or `404` the command says so before
  printing the table.

  The `status` check is deliberately quieter than the command: it reports
  only agents that this host has **recorded successful requests for** and
  is now refusing. A blocking policy turning away bots is the policy
  working — a client it used to serve and no longer does is a regression,
  and that is the one worth a warning.

## [0.0.9] — 2026-09-23

### Fixed

- **Generated `http`-context files went to `/etc/nginx/conf.d` whatever
  `nginx:root` said, which could stop NGINX loading at all.** On a host
  whose NGINX runs in a container with its config on a bind mount,
  `apply-blocks` rewrote every site file under the stored root and then
  failed its reload with `unknown "stop_bots_trusted" variable`: the trust
  file and the two `limit_req_zone` files had been written to a directory
  that NGINX never reads, and on such a host frequently does not exist until
  this code creates it.

  This was not a cosmetic misplacement. NGINX refuses to load a
  configuration that references an undefined variable, so the site blocks on
  disk were unloadable — the running NGINX kept serving only because the
  reload had failed, leaving every site on the host, including ones this
  tool had never touched, one restart away from not coming back.

  They now go in the root's **own** `conf.d` when it has one, and a
  `--root` flag governs them too, so `apply-blocks --root /tmp/x` no longer
  discovers sites under one root while writing their `http`-context files
  under another. A `conf.d` that is not already there is never created: the
  root can be a sites directory rather than the NGINX prefix, and a new
  directory inside one that `include sites-enabled/*` globs is something
  NGINX tries to read as a config file and refuses to start over. Such a
  root keeps the stock path, and `status` names whichever directory is in
  use.

  A host that never set a root is unaffected — the fallback is
  `/etc/nginx`, whose `conf.d` exists, so the path is unchanged. Anyone
  whose NGINX config lives elsewhere should set it (`stop-bots
  set-nginx-commands --root /srv/app/nginx`) and delete the stale copies
  the previous versions left in `/etc/nginx/conf.d`; `status` points at
  them by name.

- **Sites could report `Stale` for ever on such a host.** The per-site apply
  status compares the trust file on disk against what the settings render
  to, and it was reading it from the same wrong directory. Finding nothing
  is indistinguishable from finding an out-of-date file, so applying again
  changed nothing and said so.

### Added

- **`status` gains "Generated files are where NGINX reads them".** It names
  the directory even when the answer is fine, warns when that directory does
  not exist, and warns when files this project generated are stranded in
  `/etc/nginx/conf.d` while the active directory is somewhere else — which
  is what upgrading a containerised host leaves behind, and what nothing
  collects now that the removal half looks in the right place.

## [0.0.8] — 2026-09-23

### Added

- **Trusted addresses and user agents: never blocked, whatever else matches.**
  `stop-bots trust --address 198.51.100.0/24` or `--user-agent UptimeRobot`
  (with `--remove`, and `list-trusted`), a Trusted panel on the Firewall
  screen in both the TUI and the console, and `T` / a Trust button on the
  traffic rows.

  A trusted address becomes a firewall allow rule ahead of every other rule.
  It overrides a detector's block, a reputation feed, a country and the
  allow-list catch-all. It also clears every NGINX block and rate limit, and
  the detectors leave it alone. A trusted user agent clears NGINX only, and
  matches as a substring, ignoring case. It deliberately does not exempt a
  client from the log detectors: anyone can send any user agent, so that
  would be a bypass for the price of copying a string. `status` lists
  everything trusted.

### Fixed

- **Containers could not reach services on their own host.** A container
  talking to the host arrives on the firewall's *input* hook from a private
  bridge address. The allow-list catch-all, or a reputation feed that lists
  private space (FireHOL level 1 carries `172.16.0.0/12`), dropped it there,
  before ufw ever saw it. Only the forward hook accepted private sources.
  Private sources now get past every derived rule on both hooks. A block
  you add by hand for a private range still applies, because it comes first.

- **An apply that changed only a generated file did not reload NGINX.**
  Changing only the rate-limit rate rewrote `stop-bots-limits.conf`, counted
  as "0 files changed", and was never reloaded. Generated files now count.

## [0.0.7] — 2026-09-22

### Added

- **`set-nginx-commands --root`**, so the NGINX config root is remembered
  like the commands and the log paths already are. It is the third thing a
  containerised NGINX moves away from its default, and the only one still
  passed by hand on every invocation.

  `--root` defaulted to `/etc/nginx` on six subcommands, so the code could
  not tell "not passed" from "passed the default". Forgetting it did not
  error — it scanned an empty `/etc/nginx`, found no sites, and reported
  success over nothing. Two cases could not be fixed by remembering: the
  bare `stop-bots` invocation hardcoded the default and accepted no flags,
  and the web unit baked the path into `ExecStart` at install time.

  An explicit `--root` still wins, so a one-off run against a checkout needs
  no change to the stored value.

### Changed

- **The web unit no longer names `--root` in `ExecStart`.** The service
  reads the stored root itself, which is what the unit's own comment already
  says about the bind address, host allowlist, path prefix and exposure
  flag: a setting that lives in the database must not also live in a flag,
  or they disagree on the next restart.

- **`render-firewall --out` defaults to `/etc/stop-bots/firewall.nft`.**
  That path already existed as `DEFAULT_OUTPUT_PATH`, the health check looks
  for it, and `install firewall` hardcodes it — while the command that
  writes the file made you type it, and any other path produced a script
  nothing reads.

## [0.0.6] — 2026-09-21

### Added

- **`stop-bots set-log-paths`**, the companion to `set-nginx-commands` for
  the other half of a containerised NGINX. A container that bind-mounts its
  log directory writes the access log somewhere that is not
  `/var/log/nginx/access.log`, and until now the only way to say so was
  `--access-log` on each invocation.

  That covered the CLI and a crontab, and missed the two things that
  actually run the detectors: the console and the TUI drive an internal
  cron that takes no arguments, and the unit `install web` writes has an
  `--ssh-log` flag and nothing for the access log. On such a host the
  console ran every minute against a path that did not exist, found
  nothing, and reported "the NGINX access log unreadable" without saying
  which file it meant. The documented workaround was a symlink — making the
  filesystem lie so a default became true.

  A stored path is used whenever no flag overrides it. The flag still wins,
  so a one-off run against a rotated copy needs no change to the setting and
  no change back. Pass an empty string to clear one.

### Changed

- **The log-sources health check names the path it tried.** "unreadable" on
  its own could not answer the operator's next question, which was always
  which file. The fix it suggests now leads with `set-log-paths`, because
  the flags it used to name cannot reach the console.

## [0.0.5] — 2026-09-21

### Fixed

- **"Rules survive a reboot" reported OK on nftables hosts where they did
  not.** The check asked whether `nftables.service` was enabled. That unit
  loads `/etc/nftables.conf`; this project writes
  `/etc/stop-bots/firewall.nft`. The two are unrelated, so the check passed
  on hosts that came back from a reboot with none of these rules loaded —
  the same failure it exists to catch, arriving through the check itself.
  The iptables half was always right: `netfilter-persistent` saves the live
  ruleset, so it really does carry them.

- **The suggested fix could take out the host's whole firewall.** It said
  `systemctl enable nftables.service`. Debian's stock `/etc/nftables.conf`
  opens with `flush ruleset`, so on a host where ufw, Docker or a
  geo-blocker also manage tables, enabling that unit drops all of them once
  per boot. The fix now names `stop-bots install firewall`, and when
  `/etc/nftables.conf` is seen to flush it says explicitly not to enable
  that service.

### Added

- **`stop-bots install firewall`**, a second install target beside `web`.
  Writes a `Type=oneshot` unit that applies the rendered script at boot —
  `ExecStart=/usr/sbin/nft -f /etc/stop-bots/firewall.nft`, ordered
  `After=docker.service ufw.service`, with `ConditionPathExists` so a host
  that has never rendered one stays quiet. Enabled but not started, for the
  same reason `render-firewall` does not apply what it writes. Same
  `--dry-run`, `--force` and refuse-to-replace-an-edited-unit behaviour as
  `install web`.

## [0.0.4] — 2026-09-21

### Changed

- **Two screens were renamed and the tab order changed**: the third tab
  is now **Firewall** (was "Dynamic Protection") and the fourth is
  **NGINX** (was "Site settings"). `1`–`4` still jump to a screen, but
  the mnemonic letters moved with the names — `f` and `n` where `s` and
  `p` used to be. In the web console the paths moved too: `/dynamic` is
  now `/firewall` and `/sites` is now `/nginx`.

  The old names described the screens' provenance rather than what they
  do. Everything on tab three ends up in the **firewall script** and
  everything on tab four ends up in **NGINX config** — which is the split
  the project has documented from the start, and the one question a new
  reader has to answer to find a setting. Naming the tabs after the two
  outputs answers it from the tab bar. The new order puts them in the
  order the Dashboard's "Apply everything" runs them.

### Fixed

- **Allow-list geo blocking dropped every IPv6 client.** The country fetch
  read only IPdeny's IPv4 list, while allow-list mode rendered a `::/0`
  block regardless — so on a dual-stack host it allowed the selected
  countries over IPv4 and black-holed IPv6 entirely: web, SSH, everything.
  No IPv6 address can be inside a range that was never fetched.

  The SSH lockout guard did not catch it. It checks the addresses of
  connected SSH sessions, so an operator connected over IPv4 is checked
  against the v4 rules, sits inside an allowed country, and passes — while
  the ruleset about to be applied removes an address family. A safety net
  that is silent about a failure it does not model is worse than none,
  because the render reads as verified.

  `fetch_country` now fetches both of IPdeny's paths and stores both
  families; `country_ip_ranges` is keyed `(country_code, cidr)`, so this
  needed no schema change. Both must succeed — a half-fetched country is
  the failure being fixed, and the two paths agree about which countries
  exist, so nothing loses coverage.

  And a catch-all is now rendered **per family, only for a family the
  selection has ranges for**. A blanket `::/0` does not filter IPv6 without
  IPv6 data, it removes IPv6, and that is a verdict the data cannot
  support. An allow-list with no countries selected at all still blocks
  both, deliberately: that is a misconfiguration rather than missing data,
  and the deny-all is what makes the lockout guard refuse and say so.

  Measured against the live feed: `update-country-ranges ch` now stores
  3,550 ranges (2,680 v4 + 870 v6) where it stored 2,680.

## [0.0.3] — 2026-09-20

### Added

- **The access-log detectors now read JSON logs.** Everything driven by
  the NGINX access log — the 404 scanner, probe paths, the honeypot,
  forged-crawler detection, the three behavioural detectors and
  `record-access-stats` — parsed only the stock `combined` format. A
  `log_format ... escape=json` directive is not a niche choice; it is what
  anyone shipping logs to a collector configures. On such a host every
  line parsed to nothing, so none of those detectors ever found anything.

  There was no error, and that is the part worth fixing rather than the
  parser: the log was present, readable and being written to, `batch`
  reported success, and the honest report from a detector that read 14
  million lines and understood none of them is "no scanners found".
  Measured on a real server's log, 2,946 JSON lines yielded 0 scanners and
  0 recorded user agents before, and 1 scanner and 2,736 hits across 13
  user agents after.

  Both formats parse, chosen per line rather than per file, because
  changing a running server's `log_format` leaves one file holding both
  until it rotates — which is exactly when someone has just switched JSON
  on to get these detectors working. Keys are the NGINX variable names a
  JSON format is built from (`remote_addr`, `status`, `request_uri` or
  `request` or `uri`, `http_user_agent`, `http_referer`), which is what
  makes it work with no configuration to get wrong. Values may be quoted
  or bare, since `escape=json` writes `"404"` and `escape=none` writes
  `404`.

  One detector gained a third answer rather than a second format. A JSON
  format that never names `$http_referer` cannot say whether a request
  carried one, and counting "not recorded" as "there wasn't one" would
  make every ordinary visitor on such a host look like a referer-less
  crawler — a detector whose entire output is firewall blocks. So the
  parsed referer is now absent, empty, or present, and
  `refererless_crawl_ips` skips the lines it cannot answer for instead of
  answering wrongly.

- **Debian and Ubuntu packages, and an APT repository to install them
  from.** `cargo deb` builds the package from `[package.metadata.deb]`,
  and the release workflow publishes `amd64` and `arm64` `.deb`s to a
  signed repository on GitHub Pages:

  ```
  curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg \
    | sudo tee /usr/share/keyrings/stop-bots.gpg > /dev/null
  echo "deb [signed-by=/usr/share/keyrings/stop-bots.gpg] \
  https://ivankovic.github.io/stop-bots stable main" \
    | sudo tee /etc/apt/sources.list.d/stop-bots.list
  sudo apt update && sudo apt install stop-bots
  ```

  The package installs a binary and its documentation, and starts
  nothing. `stop-bots install web` still writes the systemd unit, behind
  the `--dry-run` that prints the plan first; a package that shipped an
  enabled unit would start a root-run web console on `apt install`, which
  is the opposite of the rule the rest of the project keeps.


- **A "Humans only" switch**, off by default. With it on, every
  catalogued bot is blocked whatever its category, the three category
  policies are forced to Blocked and cannot be edited, and any address
  that fetches `/robots.txt` is blocked for a day. Let's Encrypt is the
  single exception, because blocking it breaks certificate renewal in a
  way that only surfaces two months later as an expired certificate.

  It does not work by setting the three category defaults, and it cannot:
  measured on a real 793-bot list with all three categories already set
  to Blocked, that blocks **140 of 793**. The rest are catalogued bots
  carrying no category at all — `ahrefs-site-audit`, `adscanner-crawler`,
  `amazon-adbot`. With the switch on, all 793 are blocked.

  The stored category policies are left untouched, so turning the switch
  off gives them back rather than leaving three blocked categories and no
  record of what was chosen. The robots.txt rule is worth understanding
  before turning it on: a browser never fetches that file, and a crawler
  fetches it precisely because it intends to obey what it finds — so the
  rule catches the polite bots and misses the rude ones, which only makes
  sense when the answer to every bot is no anyway.

- **stop-bots now notices when NGINX is in a container, and says what is
  wrong.** `set-nginx-commands` has been documented since it shipped,
  which never helped the operator who did not know they needed it: with
  NGINX in Docker and the default `systemctl reload nginx`, every block is
  written, `apply-blocks` reports success, the config on disk is correct,
  and nothing serves it. A new `nginx-in-container` check reports that as
  CRITICAL with the exact `set-nginx-commands` line to paste, and once the
  commands are right it goes on to check the two remaining seams — a
  console bound to loopback that the container cannot reach, and a managed
  directory that does not exist inside it.

  The host arrangement is stated too, rather than left to silence: "on
  this host, reloaded with `systemctl reload nginx`" says which
  arrangement the tool believes it is in, and is the only line that shows
  the detection ran. The mirror-image mistake — container commands
  configured against an NGINX that runs on the host — is CRITICAL for the
  same reason as the reverse.

  Only a machine where *neither* could be established stays silent: no
  extra line at all, not a warning, not an "unknown".

- **A check that the access log records real client addresses.** Every
  detector skips private sources, so a deployment logging a proxy's
  address instead of the visitor's does not block the wrong people — it
  blocks nobody, from a log that looks healthy. Warns only when *every*
  logged request is from a private address; an empty log and a handful of
  local requests among public ones are both normal and stay quiet.

- **An animated tour of the four screens**, at
  `docs/screenshots/tour.gif`, in the README's Screens section. Four
  stills show what each screen holds; only this shows that `1`-`4` are
  how you get between them. Its frames are the existing seeded SVGs
  rasterised, so it cannot drift from the stills next to it, and it is
  generated by the same `make screenshots` as everything else. The
  rasteriser is a dev-dependency: `cargo install stop-bots` does not
  build it.

### Changed

- **The released binaries are statically linked against musl**, and the
  release tarballs are named for that target
  (`stop-bots-<version>-x86_64-unknown-linux-musl.tar.gz`, previously
  `...-gnu.tar.gz`). A glibc-linked build inherits a version floor from
  whatever machine built it, and the failure it produces is a package
  that installs cleanly and then will not start:

  ```
  stop-bots: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39'
  not found (required by stop-bots)
  ```

  One static build installs on every Debian and Ubuntu still receiving
  updates instead. It is possible here only because the dependency tree
  has no C TLS in it — `reqwest` resolves to `rustls` — so the only C
  left to compile is the SQLite that `rusqlite`'s `bundled` feature
  carries. An `aarch64` tarball is published alongside the `x86_64` one
  for the first time, built on a native runner.

  `packaging/aur/stop-bots-bin` follows the rename and no longer depends
  on `gcc-libs`.

### Fixed

- **The screenshots changed every time they were regenerated.** Bot
  settings renders a source's fetch time to the second, and both
  `touch_source` and the `register_all_sources` in `App::new` stamp the
  moment they run — so the committed images read "updated 0s ago" or
  "updated 2s ago" depending on how fast the machine was, and every
  regeneration produced a diff that looked like a change and was not.
  Pinned to a whole-minute offset, the way the cron history already was.
  The generator is now byte-for-byte reproducible, which `tour.gif`
  needs: an unexplained change to a binary blob cannot be reviewed.

- **Firewall blocks did nothing for an NGINX in a container.** The
  generated ruleset hooked `input` only. A packet for a published
  container port is DNAT'd and then *forwarded*, so it never traverses
  `input` — every Block rule was inert for anything containerised, which
  includes the common case of running the NGINX this tool protects in
  Docker with `ports: 80:80`. `block_web_scanners`, whose entire output is
  firewall rules, therefore did nothing at all on such a host. Nothing
  said so: the script applied cleanly, `nft list` showed the rules, and
  the "Firewall rules are in the kernel" check went green.

  `nftables::render` now emits a second base chain on `forward` beside the
  one on `input`, with the rules in a shared, unhooked chain both jump to;
  the iptables backend adds the matching guarded jumps from `FORWARD` and
  from `DOCKER-USER` where Docker provides it. Both are validated against
  a real kernel by the container suite.

  The forward chain passes traffic from private source addresses before
  reaching the rules, which matters most in geo **allowlist** mode: its
  trailing `0.0.0.0/0 drop`, reached from `forward`, would otherwise have
  cut every container on the host off from the network. Inbound traffic is
  unaffected, since a DNAT'd packet still carries the client's own address.

  A new `firewall-reaches-containers` check reports the case this fix
  leaves behind — a ruleset rendered by an older version, still loaded,
  still counting right, still enforcing nothing. It is Critical when NGINX
  is containerised and the loaded ruleset has no forward coverage, and
  silent where the answer would change nothing.

- **The built-in bot list never reached a console-only host.**
  `register_all_sources` both registers the four sources and stores the
  one compiled into the binary, and it was called from the TUI's startup
  and nowhere else — so every host set up by `install web`, which is what
  a production host is, had no `stop-bots-extras` source row, no entries,
  and none of its 49 patterns in the rendered config. Nothing failed,
  because nothing was asked to: the source was simply absent, on a host
  whose own access log the list had been written from. Found on that host
  with 0 rows, and now pinned by a container test that fails without the
  call.


## [0.0.2] — 2026-09-15

### Added

- **Tap a user agent for a detail popup, the way an address already
  does.** `i` in the TUI and a link on the cell in the web UI, showing
  which lists carry a matching pattern, which alternative matched, the
  categories, and — the reason it exists — *why* it is blocked or allowed:
  a per-bot override, a category default, or nothing. "Blocked" on its own
  never said whether un-blocking meant clearing one override or changing a
  default that governs hundreds of other bots.

  Deliberately a different model from the address detail rather than the
  same one with different text. An address can be checked against a
  published range; a user agent is a string the client typed and can say
  anything, so everything here is phrased as what the lists on this host
  say, never as what the client is. Nothing is looked up over the network,
  for that reason and because there is nothing to ask. The string is capped
  and stripped of control characters at the model — nothing sanitises a
  user agent on the way in, and an escape sequence reaching the TUI's
  alternate screen repaints the terminal.

- **Two more built-in probe paths**, both meeting the list's rule that a
  path only belongs there if it is never legitimate on *any* site:
  `/wp-content/plugins/hellopress/`, a WordPress file-manager backdoor
  that nobody installs on purpose, and percent-encoded dots (`%2e`,
  `%252e`). A `.` needs no encoding, so encoding one has exactly one
  purpose — getting a `../` past something looking for `../`. That is
  22,762 requests on one host, including the CVE-2021-41773
  `/cgi-bin/.%2e/.%2e/bin/sh` shell RCE.

- **Dynamic Protection marks user agents no bot list has heard of.** A new
  `UNKNOWN` tag, for rows that announce themselves as a bot — a `bot`,
  `crawler`, `scanner`… token, or the `+http` convention of citing a page
  about yourself — and that match no pattern in any list. That is the
  signal that turned up 46 missing entries, and it needed a script to
  find. Ordinary browsers are not tagged: checked against 6,493 real user
  agents, the test flags none of the 4,644 carrying a browser's product
  tokens.

- **A built-in bot list of this project's own** — the first source that is
  compiled into the binary rather than downloaded, so a fresh install is
  covered before it has network access and on a host that cannot reach
  GitHub at all.

  46 entries: 6 AI crawlers `ai.robots.txt` does not carry yet (xAI's
  three names, Moonshot/Kimi, Tencent's Hunyuan, 01.AI's YiBot) and 40
  scanners and commercial crawlers. They were read off two months of one
  server's NGINX log — 6,493 distinct user agents over 435,782 requests —
  by matching every one against all 1,606 patterns the three upstream
  lists contribute and keeping what matched none. On that log the list
  covers 22,573 requests the existing sources let through.

  It also carries two search engines the upstream lists miss — Qwant's
  crawler, and the *unversioned* `Googlebot` that `Googlebot\/` cannot
  match — plus Let's Encrypt's validation server, which is in no list at
  all and must never be blocked.

  Entries carry the same category flags every other source's do, so the
  host's own AI/scanner/search policy decides and a per-bot override still
  wins. A search engine is filed as one, so it stays allowed by default
  and is blocked only where an admin has actually asked to block search
  engines.
  Patterns are bare names, never versions: the upstream `Googlebot\/`
  already fails to match a bare `Googlebot`, and repeating that mistake
  would be perverse. Nothing in the list matches `Let's Encrypt validation
  server`, and there is a test that says so.

- **An "Auto-apply" switch.** With it on, the internal cron re-writes every
  site's generated block and reloads NGINX once an hour, whenever they have
  fallen behind the database — which happens constantly on a busy host,
  because every user agent a detector blocks changes the generated block
  and puts every site back to STALE within the minute. Until now nothing
  applied that on a schedule, so a host left alone drifted further from its
  own configuration every day and the health report's "NGINX blocks are
  applied" warning was the only sign.

  On the Site settings screen in the TUI, under Sites in the web UI, or
  `stop-bots set-auto-apply --enabled true`. **Off by default**, and it
  stays off on upgrade: it reloads a live web server with nobody watching,
  which is not a decision an upgrade gets to make.

- **A second, separate switch for the firewall script.** With it on, the
  daily render also runs what it wrote. Separate from the NGINX switch and
  separately off, because the risks are not comparable: a bad NGINX config
  is caught by `nginx -t` and costs a failed reload, while a bad firewall
  ruleset locks you out of the host.

  Unattended it is **stricter than the button**. The interactive paths
  treat "the anti-lockout check could not read an SSH log" as a pass,
  which is reasonable while a person is reading the result; here it is a
  refusal, because "the check could not run" is not "the check passed"
  when nobody is watching. On the Dashboard in both front-ends, or
  `stop-bots set-auto-apply-firewall --enabled true`.

- **A daily maintenance job, and `stop-bots maintain` to run it now.** It
  prunes `user_agent_stats` rows for agents not seen in 90 days (and any
  excess over 20,000, least recently seen first), clears lapsed firewall
  rules, and compacts the database when enough free space has built up to
  be worth the rewrite. `--force-compact` compacts regardless, which is
  what a host that has already grown wants right after upgrading.

- **The health report now includes the database's size**, and its
  reclaimable share, warning past 128MB. "Room for the database" reports
  free space on the *filesystem*, which says nothing about how big this
  tool's own database has become.

- **"Generated script matches the rules" now says when the script will
  render itself.** A stale script the internal cron is about to fix is a
  different situation from one waiting on somebody, and the warning read
  the same either way. It now adds "Will auto-render at
  2026-09-15 14:40 UTC" when there is a scheduled render to name — and
  deliberately says nothing on a host whose cron has never rendered, or
  whose render is already overdue, because neither is a schedule.

### Changed

- **CI actions updated**, and `actions/checkout` off deprecated Node 20:
  `actions/checkout` v4 → v7 (v7.0.0 is the ESM/Node 24 move, which is
  what the runner's deprecation warning was asking for) and
  `softprops/action-gh-release` v2 → v3 (the same move). v7's breaking
  change narrows fork checkouts under `pull_request_target` and
  `workflow_run`; this project uses neither. `Swatinem/rust-cache` and
  `taiki-e/install-action` are already on their current major.

- **Dependencies refreshed** across the tree (`cargo update`), including
  `cc`, `clap`, `futures`, `http`, `hyper` and `tokio`. No API change
  reached this code, the MSRV is unmoved at 1.88, and `cargo audit`
  reports nothing.

- **`rusqlite` 0.31 → 0.40**, which carries the bundled SQLite from
  3.45.0 to 3.53.2. No code changed: nothing this project uses moved,
  including the `dbstat`/`PRAGMA page_count` reads and the `VACUUM` the
  maintenance job runs. The MSRV is unmoved at 1.88.

- **A failing `container` job now says what failed.** Its step echoes the
  failing test names and the first panic back as workflow annotations.
  Job logs need admin on this repository; annotations do not, so a red
  `container` used to read as "exit code 101" to everyone but the owner
  — and this suite races a real systemd, a real nginx and a real SQLite,
  so it is the job most likely to need reading.

- **`reqwest` 0.12 → 0.13.** No code changed, and the TLS stack is
  unmoved — still `rustls` 0.23.45, so the RUSTSEC-2026-0285 fix stays
  where it was. Checked by actually downloading all three bot lists over
  HTTPS, which is the part no unit test covers. MSRV 1.88, against
  reqwest's own floor of 1.85.

### Fixed

- **Both Dynamic Protection detail panels had no gutter.** Their prose,
  button row and sub-heading sat flush against the panel border: a table
  pads its own cells to the panel's 14px, and nothing else in a panel
  does without a `.panel-body`. The `h3` between a panel's two halves had
  no rule at all and rendered at the browser's default. The user agent
  itself now gets a tinted block that wraps anywhere, because it is as
  often one unbroken token as not and a value that cannot wrap sets the
  panel's width from the worst string in the log.

- **Probe-path detection was anchored to the start of the path, and
  attackers are not.** It saw `/.env` but not `/api/.env`,
  `/backend/.env` or `/laravel/.env`; not
  `/%252e%252e/%252e%252e/home/ubuntu/.ssh/id_ed25519`; and not
  `GET http://example.com/.git/HEAD`, whose absolute request URI does not
  begin with a slash-dot at all. The anchor was there to stop
  `/blog/how-to-secure-your-env` matching — but that path does not contain
  `/.env`, so the leading slash in every needle was already doing that
  work. Matching anywhere in the path takes one host's log from 28,213
  probe requests to 67,888, and from 1,640 probing IPs to 1,811. Of the
  39,675 newly matched requests, none was answered with content.

- **A detected block no longer waits a day to be rendered.** The firewall
  render was on a fixed 24-hour clock while the detectors add blocks every
  minute — on a real host fifteen detections sat in the database for
  twenty-one hours, found and unenforced. A changed rule set now makes the
  render due as well, reusing the signature the health check already
  computes, with a five-minute floor so a render that keeps failing backs
  off instead of retrying every tick. The 24 hours stays as the maximum,
  because a rule that merely *expired* changes no signature.

- **Dynamic Protection could not see 217 of its own bot patterns.** It
  compares user agents to patterns by substring, but 13% of them arrive
  regex-escaped from `nginx-bad-bots` — `Googlebot\/`, `Mediapartners
  \(Googlebot\)` — and no user agent contains a backslash, so those
  patterns never matched anything. The screen believed the commonest
  crawler on the web was in no list at all. Escapes are stripped before
  comparing now.

- **"BLOCKED until 1d" now reads "BLOCKED for 1d".** The time beside it is
  how long is left, not a moment, so "until" described something the
  number never was.

- **The state tags on Dynamic Protection no longer run into the addresses
  beside them.** The four tags are four different lengths, and nothing
  padded them, so every row started its address at a different column —
  a column the code had claimed was fixed since the panel was written.
  Both panels now share one tag column, sized to the longest tag actually
  on screen.

- **The "no user agents tallied yet" message no longer has a gap in the
  middle of it.** A string literal was broken across two source lines
  without a continuation, so the indentation was part of the text.

- **The database-size check now has a short name in the TUI status
  strip**, where it had been showing as "database-size" among "disk",
  "logs" and "script".

- **The database no longer grows without bound.** On a live host it had
  reached 16MB, of which a single `settings` row held 4.7MB: the
  "rendered signature" the Dashboard uses to tell whether the firewall
  script is stale was storing the entire rule set's debug dump rather
  than a hash of it. With reputation feeds enabled that is every CIDR in
  every feed — 44,075 rules — rewritten in full on every render and
  rebuilt on every hourly health check. It is now a SHA-256 digest: 64
  bytes, whatever the rule count.

  Rewriting that value daily had also left 6.5MB of free pages SQLite
  reuses but never returns to the filesystem, and nothing had ever
  deleted a `user_agent_stats` row. Both are handled by the new
  maintenance job above. Upgrading drops the old oversized value on the
  first open; the Dashboard reports the script as needing a render once
  afterwards, and settles after it. On the host that prompted this,
  `stop-bots maintain` took the database from 16.0MB to 4.1MB.

- **`install web` no longer pins the service to `/var/log/auth.log`.** It wrote
  that path into the unit's `ExecStart` at install time, and Debian 12 dropped
  rsyslog from default installs — so on a current Debian host the file does not
  exist and sshd logs only to the journal. An explicit `--ssh-log` skips the
  `journalctl` fallback by design, so the service read nothing: the console's
  SSH panel stayed empty and the brute-force detector, which runs inside that
  same service, never saw an attempt to act on. Neither reported an error,
  because an unreadable log means "could not check".

  The unit now names no SSH log unless `install web --ssh-log` asked for one,
  which leaves the service to search `/var/log/auth.log`, `/var/log/secure` and
  then `journalctl` on every read. Existing installs keep the old unit until
  `install web --force` rewrites it.

- **The "couldn't read the log" errors no longer describe a search that did not
  happen.** Passing `--ssh-log` reads that path and nothing else, but the
  failure still listed all three sources as tried, which sends the reader
  looking for a bug in the fallback chain instead of at the path they passed.
  Both the SSH and access-log messages now name the path actually read.

### Security

- `rustls` 0.23.40 → 0.23.45, for RUSTSEC-2026-0285: TLS 1.3 handshake messages
  were accepted across encryption level boundaries. Reached only through
  `reqwest`, which this uses to fetch bot lists and IP-range feeds over HTTPS.

### Changed

- `argon2` 0.5 → 0.6 and `rand` 0.9 → 0.10. Both moved the API this code
  touches: `rand`'s `OsRng` became `rngs::SysRng` and `TryRngCore` became
  `TryRng`, while `argon2` dropped the salt argument from `hash_password`,
  moved `PasswordHash` under `phc`, and now takes raw salt bytes instead of an
  encoded `SaltString` — which deletes the base64 step this file used to do by
  hand. Default cost parameters are unchanged (m=19456, t=2, p=1), so the stored
  hashes and the OWASP figures in the docs both still stand.

### Added

- A test that a password hash written by the *previous* `argon2` still
  verifies. Every other test in `web::auth` hashes and verifies in one process
  with one version, so none of them could fail on the upgrade that stopped
  reading what is already in operators' databases. That failure would surface as
  an operator locked out of the console that manages their firewall, after they
  deployed.

## [0.0.1] — 2026-09-14

First published release. The sections below describe the whole of what became
installable, starting with the blocking the crate was built for.

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

### Added

- **`stop-bots status`, and a System status panel on both Dashboards.** Every
  other check in this project compares what it *would* generate against what
  is *on disk*. None of them looked at the kernel — which is how a real host
  ran for three weeks with 48,860 generated drop rules and an empty ruleset.

  Seven checks: rules actually loaded, rules surviving a reboot, script
  matching the rules, NGINX blocks applied, the console service running the
  binary it names, room for the database, and readable detector logs. Each one
  is something that went wrong on a real server.

  `status` exits non-zero on anything CRITICAL, so it works from a monitoring
  check or a crontab; `--quiet` prints only what needs attention. A check that
  could not run reports UNKNOWN rather than OK: `nft list` needs root, and a
  health check that says everything is fine because it could not look is worse
  than no health check.

  Split as `health::probe` (shells out, no database) and `health::assess`
  (database, no subprocesses), the same shape as `refresh` and `webaccess`.
  Only the probe is stored — an hourly `HealthCheck` cron job takes it — and
  the report is re-derived at render time, so the panel agrees with rules the
  operator changed a second ago. `nft list` on a large ruleset is megabytes of
  text, which is why it is not done per render.

- **The container suite went from 12 tests to 36, and grew a second image
  that has a real init.** Three of the four bugs that reached a live server
  were systemd *sandbox* failures, and the old container had no systemd at
  all — so none of them was findable there. `Dockerfile.host` (debian:13,
  the actual deployment target) runs systemd as PID 1, and the sandbox tests
  each carry a negative control that strips the directive under test and
  asserts the failure comes back. Without that control a container where the
  sandbox silently did not apply would pass every one of them.

  Probes are derived from the unit `install web` actually wrote rather than
  hand-written, so a test cannot keep passing after the generator stops
  emitting a directive.

  Newly covered: `install web` under a real service manager, the netlink
  sandbox for both firewall backends, `ProtectSystem` still permitting a
  later apply, replacing the binary and restarting, the iptables backend
  executed for real, allowlist mode as genuine default-deny, IPv6 drops,
  the console as a listening server (login, "Apply everything", the host
  allowlist, Web Access through the NGINX it just configured), rate
  limiting, the tarpit, each request-shape rule against a request actually
  shaped that way, a per-site rule proving it stops at that site, and the
  whole detection loop — honeypot and probe paths — from a real client's
  request through the log NGINX wrote to a rule that really blocks it.

- **The tarpit is timed**, closing a TODO.md item: a tarpitted client is
  still waiting after five seconds while an unblocked one is served in
  under two.

- **The TUI has the three host-wide Dashboard actions too.** `u` downloads every
  list, `a` applies both planes (NGINX, then the firewall), and `w` opens the Web
  Access form. Each goes through the same shared module the console's button or
  panel does — `refresh`, the existing apply pairs, and a new `webaccess` — rather
  than a second implementation that could drift from the first.

  `u` fetches one source at a time and stores each before starting the next. The
  plan is eight or more downloads of several megabytes; fetching them together
  would hold every payload at once and show nothing until the last one landed.

- **A "Web Access" panel on the Dashboard.** Sets NGINX up to serve this console
  from outside, in one of two modes.

  *Path on an existing site* is the default: it adds a sentinel-marked
  `location /stop-bots/` block to a site you pick, so the console inherits that
  site's certificate. It picks the site's TLS `server` block rather than its
  port-80 redirect. *Its own subdomain* writes a new `server` block on port 80 —
  the generated file says, in a comment where you will find it, that the password
  form and session cookie are in the clear until `certbot --nginx -d <host>` has
  run.

  The panel writes three things that have to agree: the config, `web:base_path`
  and `web:allowed_hosts`. Any one missing gives you a console that looks broken
  rather than misconfigured — a 404 for the prefix, a 403 for the host.

  The config is validated with `nginx -t` **before it can take effect**, and rolled
  back if it fails. `apply_all_sites` writes-then-tests, which is survivable for an
  edit; a new `server` block that does not parse leaves the whole config unloadable
  while the running NGINX keeps serving from memory, so nothing looks wrong until
  certbot's renewal reload fails at 3am.

- **"Update everything" and "Apply everything" buttons in "System-wide settings".**
  Update downloads every bot list, crawler range, enabled feed and selected
  country; apply writes and reloads the NGINX config, then writes and runs the
  firewall script. Both planes are independent, same as `batch --apply`: whichever
  fails, the other still gets its turn.

  Selecting a country used to say "its ranges still need downloading with
  `stop-bots update-country-ranges --country RU`" — a console that knew what needed
  doing and asked you to do it. It now names the button.

- **The console can apply the firewall script.** Previously one of its three
  deliberate omissions, reversed on request. Tick "run it after writing" in the
  firewall panel, or use "Apply everything". The same anti-lockout guard
  `batch --apply` runs still applies — rules that would block a currently-connected
  SSH client are refused, not warned about — and `stop-bots web --no-apply` keeps
  the old write-only behaviour. The chosen backend is now remembered, so a
  one-click apply has an answer without guessing.

- **Inspect an address on the Dynamic Protection screen.** `i` in the TUI, or click
  the address in the web console. It answers "what *is* this thing" from lists this
  host already downloads: which of the six reputation feeds list it (Tor exit,
  FireHOL, blocklist.de, AWS, Google Cloud, DigitalOcean), whether it is inside a
  published crawler range — which is what separates a real Googlebot from a user
  agent that merely says so — which fetched country it belongs to, and which
  accounts it tried to log in as.

  Deliberately **not** reverse DNS or whois. Both are outbound requests, per row, to
  infrastructure an attacker often controls, and a PTR record is written by whoever
  holds the address — so it is attacker-supplied text that reads as authoritative.
  Everything here is local, instant, works offline, and tells the attacker nothing.

  The SSH log's failed-login usernames were being parsed past and discarded; they
  are now kept, capped and stripped of control characters, since they are whatever
  the client chose to send. Extracted for one address when you ask, not for every
  address on every refresh — the latter cost 215ms per refresh on a large
  auth.log, for an answer almost nobody had asked for.

- **A web UI — `stop-bots web`.** The same five screens as the TUI, in a browser.

  It binds `127.0.0.1:8787` and generates a password on first run, printed once.
  Reach it over an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 host`); binding anything
  else needs `--expose` as well, because the console can rewrite the firewall and the
  NGINX config of the host it runs on.

  There is a password, a CSRF token and a `Host` allowlist even on loopback, because
  loopback is reachable by every local user on the box and by any page in the admin's
  own browser — a form post needs no readable response, and DNS rebinding defeats
  same-origin. The `Host` allowlist is what makes rebinding fail.

  It refuses to block the address you are connected from, will not unblock something a
  downloaded list blocked, and will not change its own password. The Help screen lists
  each omission with its reason, alongside how this console is actually exposed. (It also
  would not *apply* the firewall script; see "The console can apply the firewall script"
  below, which is the same release changing its mind.)

  Serve it under a path prefix with `--base-path /stop-bots` when NGINX puts it in a
  `location` block rather than on its own subdomain. The proxy must not strip the
  prefix — `proxy_pass http://127.0.0.1:8787;` with no trailing slash — because this
  server matches the full path and generates links that include it. A subdomain needs
  none of this and is the simpler deployment.

  Login attempts are throttled — before the password is hashed, not after. The point is
  not that a generated 144-bit password is guessable; it is that verifying one runs
  Argon2id (~50ms of CPU, 19MB), and an unauthenticated caller could otherwise drive that
  as fast as they could post.

  Behind TLS, set `web:secure_cookie` — without it a browser will also send the
  session to an `http://` URL for the same host. It is off by default because the
  default deployment is plain HTTP on loopback, where a `Secure` cookie is never
  stored at all.

- **The internal cron now ticks while the web UI runs, not only the TUI.** The two share
  one schedule in one database, so running both does the work once: whichever ticks first
  records the job and the other finds it no longer due. The same is true of a crontab
  entry running `stop-bots batch`, which already recorded through those keys.

  This closes the gap that made the web UI look like a viewer: a server left running now
  keeps detection, access-log stats and the daily crawler-range refresh current on its
  own. `RenderFirewall` still only writes the script — nothing here applies
  one — and if the server can't write it (an unprivileged `stop-bots web`, and a
  default path under `/etc`) the recorded outcome names the file rather than
  reporting a bare "Permission denied".

  The per-job logic moved out of `App` into `cron.rs` (`read_log_for`, `run_log_job`,
  `fetch_ip_ranges`, `store_ip_ranges`) so the two front-ends run the same code rather
  than two copies that drift. Behaviour in the TUI is unchanged.

- **`stop-bots install web`** sets the console up as a systemd service on Debian:
  a unit at `/etc/systemd/system/stop-bots-web.service`, `/var/lib/stop-bots` at
  0700 because it holds the password hash, `/etc/stop-bots` for the firewall
  script, a generated password if there isn't one, and `systemctl enable --now`.

  `--dry-run` prints the plan and changes nothing; `--prefix` writes the tree
  somewhere readable without root; a unit you have edited is refused rather than
  replaced unless you pass `--force`; and a binary under `target/debug` is
  refused, because a unit naming one works until the next `cargo clean`.

  The service runs as root, which it has to — the console rewrites `/etc/nginx`
  and runs `systemctl reload nginx`. The unit carries the hardening compatible
  with that and names the hardening that isn't, with reasons.

- **`make unit-test` / `make integration-test` / `make test`**, replacing the old
  `test` / `test-containers` pair. `unit-test` is everything that needs only a
  compiler; `integration-test` is the container suite; `test` is both, unit first,
  since there is no sense building containers to find out the code doesn't compile.
  Every target is `.PHONY` now — a directory named `build` or `test` would
  previously have made `make` say "up to date" and run nothing.

- **An opt-in pre-commit hook**, `make hooks`. Formats what you staged and runs
  CI's exact clippy invocation. A commit with no Rust in it skips both; a clean
  Rust commit costs about four seconds. It judges formatting against the staged
  bytes rather than the working tree, and refuses rather than re-stage a file that
  is staged unformatted *and* has unstaged changes — formatting rewrites the
  working tree, so `git add` there would commit edits that were left out on
  purpose.

- **`--threshold 0` is refused.** Every detector compares `count >= threshold`, so
  zero meant "no evidence required": `block-scanners --threshold 0` added a block
  rule for every address in the log, whatever it had done. One is still allowed —
  that is an aggressive policy, not a mistake. The same floor is applied to the
  three behavioural thresholds that have no CLI verb and are set by hand in the
  settings table, where it is 2, since one distinct page or one user agent
  describes every visitor there has ever been.

- Dependency advisories are now a CI job (`cargo audit`), weekly as well as on
  push, because an advisory is published against code that hasn't changed. It
  fails on vulnerabilities, unsound crates and yanked ones, but not on
  unmaintained ones — nobody here can act on those. This found
  `RUSTSEC-2026-0258` in `h2` — reachable from the web server through hyper —
  along with unsoundness in `anyhow` and `lru`; all three had patched versions
  already published and are updated in `Cargo.lock`.

- **The web UI puts panels side by side on a wide window**, rather than stacking
  everything down one 1180px column. Every screen is a grid that collapses back to
  one column below 1040px, so a narrow window and a phone are unchanged.

  The Dynamic Protection tables — failed SSH logins and top user agents — are
  capped at twenty rows and scroll inside their panel, with the column headers
  stuck to the top. On a server that is actually being scanned those tables ran to
  hundreds of rows and buried everything after them. A user agent too long for its
  column is now truncated rather than wrapped, so that rows are a uniform height;
  the whole string is still there as the cell's `title`.

- **Configurable NGINX test and reload commands** — `stop-bots set-nginx-commands`.
  For NGINX in a container, where the config is on a bind mount this tool can write but
  `systemctl reload nginx` reloads nothing:

  ```
  stop-bots set-nginx-commands --test "docker exec web nginx -t" \
                               --reload "docker exec web nginx -s reload"
  ```

  The command is split into words and run directly, never through a shell.

- `update-ip-ranges`, `update-country-ranges` and `update-reputation-source` take a
  `--source <file>` override, parsing the same format the server would have sent —
  matching what `update-bot-lists` already had. For a host with no outbound access, and
  what makes the parse-and-store half of every download testable offline.

- **`stop-bots batch` — one unattended pass, for a real crontab.** Refreshes every list,
  scans the logs, writes the NGINX blocking rules and the firewall script, and with
  `--apply` puts both into effect. Quiet when everything worked (so a healthy nightly run
  doesn't mail you), non-zero exit and a report on stderr when something didn't; `--verbose`
  prints a line per step. `--no-fetch` skips the downloads, for a host with no outbound
  access or a second, more frequent entry that only wants the log scan and the apply.

  Under `--apply` the SSH lockout guard refuses — and refusing means nothing is written or
  applied — both when the rules would block a currently-connected client and when no SSH log
  could be read at all, because then the check could not run. The interactive
  `render-firewall` only warns in that second case, which is defensible with a human at the
  terminal and is not from cron. Pass `--ssh-log` explicitly; `--force` overrides.

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

### Changed

- `App`'s background work is a `start_x` / `finish_x` pair throughout. Several of the
  `start` halves were named `reload_nginx`, `read_ssh_log`, `check_site_statuses` — right
  about the subject and wrong about the tense, since none of them does the thing, they all
  only start it. Internal naming only; no behaviour change.

- The Dashboard's "Automatic blocking" panel is a full-width panel of its own, and shows
  all fourteen options at once instead of five at a time behind a scroll. It deals its
  rows into as many columns as the terminal is wide enough for (two from about 100
  columns), and "System-wide settings" and "Geo-blocking" now share the row above it —
  between them they were using a quarter of the width.

- **The TUI no longer blocks on anything it does.** Every action that touches the
  filesystem, a subprocess or the network now runs on a background thread while the
  interface stays live: reloading NGINX, rendering and applying the firewall script,
  scanning the NGINX config root, applying site configs, working out each site's
  UP TO DATE / STALE tag, and reading the SSH log that Dynamic Protection's SSH panel is
  built from. On a small server several of these were multi-second pauses with a frozen
  screen. Database access still happens on the main thread, where it is fast and where
  SQLite's connection can go.

  The footer names whatever is running, with a braille spinner, on every screen; the SSH
  panel and the site status tags carry their own. Two safety properties are unchanged and
  covered by tests: the firewall's lockout guard still reads the SSH log *live* rather
  than from the display cache, and a reload requested while one is running is held rather
  than dropped, so applying a second site can't leave NGINX serving its old config.

- A keypress reloads only the screen being looked at. All four used to reload on every
  mutation, so toggling one category default on the Dashboard also made Dynamic
  Protection re-read the SSH log and Bot settings re-list every bot. The other three
  reload when each next comes into view.

### Fixed

- **The console returned 421 on a site's second `server_name`.** A block
  reading `server_name www.example.com example.com;` is routine and NGINX
  answers for both, but `scan-sites` stores a site under the first name only
  — one row, one name — so Web Access allowlisted just that one. The console
  then worked on `www.example.com` and refused `example.com`, the
  DNS-rebinding guard correctly rejecting a host nobody had told it about.
  `nginx::server_names_for` now reads every name off the block the console's
  `location` is going into, and `Plan.host` became `Plan.hosts`. A config
  that cannot be read still yields the stored name, so it degrades to the
  old behaviour rather than to an empty allowlist.

- **The Web Access panel showed a path prefix with a doubled slash.** It
  rendered `"/" + base_path` where the stored value already carried its
  leading slash, so `/stop-bots` displayed as `//stop-bots`. Only the display
  was wrong. The panel now reads the prefix through `BasePath`, so a setting
  written by hand without a leading slash also displays as a path.

- **Recording a path prefix looked like it had done nothing.** The prefix is
  read once, when the router is built, so a newly recorded one left the
  console still answering on the old one: the panel showed the new prefix,
  every link 404'd, and nothing on the page explained it. The Web Access
  panel now carries a "Restart needed" row naming what this process is
  actually serving and the command to pick up the change.

- **`make deploy` could land a new binary and leave the console down.** The
  remote half used `systemctl try-restart`, which does nothing at all to a
  unit that is enabled but not running — which is exactly where a service
  that crash-looped and was given up on ends up. It now restarts an
  *enabled* unit and try-restarts one that merely exists, so a host where
  the console is deliberately run by hand does not get a second copy
  competing for the port. It also prints the state it left the unit in.

  The remote half moved to `scripts/deploy-remote.sh`, piped over ssh, so
  that a container test can run that exact file against a real systemd.

- **`batch` ignored the firewall backend this host is set to.** `--backend`
  carried an `nftables` default and nothing consulted
  `firewall::stored_backend`, so an operator who chose iptables in the
  console and ran `stop-bots batch --apply` from crontab — as the README
  recommends — got an nftables script at `firewall.nft` while the console
  maintained an iptables one at `firewall.sh`. Both were applied, by
  different things, and either could be stale. The same drift once had the
  internal cron overwriting an operator's iptables script with nftables
  syntax; that was fixed by reading the stored backend and this path was
  missed. An explicit `--backend` still wins; without one, the host's
  setting decides, and the output path follows from it.

- **`stop-bots install web` could leave the service crash-looping.** It ran
  `systemctl enable --now` *before* opening the database to record the bind
  address and generate the password, so the installer and the service it had
  just started raced for the same SQLite file. `Db::open` set no busy timeout,
  so the loser failed instantly with "database is locked": either the service
  exited 1 and crash-looped on `Restart=on-failure`, or the install failed
  having already enabled the unit, or the service won and generated the
  password itself — leaving the installer to report "a console password is
  already set, keeping it" and the operator with no password at all. The
  database work now finishes first, and `Db::open` waits five seconds for a
  lock rather than giving up, which also covers the console running alongside
  the TUI or a `batch` from crontab. Found by the new container tests, which
  only showed it under parallel load.

- **The database file was world-readable.** `install web` set the state
  directory to 0700 but left `db.sqlite3` at the umask default, usually 0644.
  Nothing was exposed — the directory is what protects it — but the mode
  travels with the file through a backup or a `cp`, and the unit's
  `UMask=0077` applies only to files the service creates, not the installer.

- **The Web Access panel's form sat flush against the panel edge.** Every other
  panel wraps its loose content in a `.panel-body`, which is the only thing
  carrying the side padding; this one emitted the form bare. A test now asserts
  that whatever follows a panel's table is inside one.

- **The console could not apply the firewall at all under its own systemd unit.**
  `nft` and Debian's nft-backed `iptables` reach the kernel over a netlink socket, and
  the unit `install web` writes set `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
  — with a comment asserting "nothing here uses a raw or netlink socket: this service
  writes the firewall script, it never applies it", which stopped being true the moment
  applying was added. The failure was `Unable to initialize Netlink socket: Address
  family not supported by protocol`, which names neither systemd nor this project.
  `AF_NETLINK` is now allowed, and a netlink refusal appends an explanation naming the
  directive and how to get a current unit. **Existing installs need
  `stop-bots install web --force` and a restart.**

- **An iptables script could land in a file called `firewall.nft`.** The destination
  was fixed at startup and the backend chosen per render, so on a host set to iptables
  the console wrote `#!/bin/sh` and 12,000 `iptables -A` lines into the nftables path.
  Worse, the internal cron hardcoded nftables regardless — so each tick replaced an
  operator's iptables script with an nftables one at the same path, and the next apply
  ran `sh` over nftables syntax. The backend is now the single source of truth: the
  cron renders for the stored backend, and the path follows it (`.nft` or `.sh`) unless
  `--firewall-out` names one explicitly, in which case that wins.

- **`make deploy` did not deploy.** It copied the binary to the login directory and
  restarted nothing, so on a host where the service runs from `/usr/local/bin` every
  step succeeded and the console kept serving the previous build. It now installs to
  the path the unit actually names, restarts the service if there is one, and prints
  the unit's `ExecStart` alongside the deployed file's timestamp — `--version` is
  `0.0.1` for every build, so it could never have shown the difference.

- **`install web` wrote a unit systemd could not execute** when run from `/root` —
  which is exactly where someone who just downloaded a release binary is standing.
  The unit sets `ProtectHome=yes`, so `/root` is an empty directory for the
  service, and `ExecStart=/root/stop-bots` failed with `status=203/EXEC`,
  "No such file or directory", for a file that was plainly there. Preflight checked
  that the binary existed; it did not check that it existed *inside the sandbox the
  unit itself asks for*. It now refuses up front, names the directive responsible,
  and gives the two commands that fix it. Same for `/home`, `/run/user`, `/tmp` and
  `/var/tmp` (the last two via `PrivateTmp=yes`), and for a relative `--binary`,
  which systemd rejects when it loads the unit rather than when it starts it.

  A failed `systemctl enable --now` also now says what state it left behind: the
  enable sticks even when the start fails, so the unit was enabled and would have
  tried again at the next boot with nothing saying so.

- `--version` now exists. It also shows in the TUI's header, which is where someone is
  standing when they decide to report something.
- `stop-bots --help` is scannable: twenty subcommands printed their entire description —
  one ran to 931 characters — as their one-line summary. Each now has a real one-liner,
  with the full text still under `<subcommand> --help`.
- A mistyped `--root` is an error rather than "Discovered 0 site(s)", which read exactly
  like a correct run against a server with no sites. Something unreadable *inside* a real
  root is still skipped, as before.
- The Dashboard's Summary no longer tells a fresh install to press `f`, which would have
  rendered an empty script. With no rules it says so, and points at the panel above.
- Dynamic Protection's two panels say what an empty one means. A blank bordered box reads
  as "broken", and here it is usually the good case: nothing is attacking you.
- Bot list source names no longer overflow their column and knock the counts out of line.
- Popups are sized to their contents. The firewall render popup was two columns short of
  its own key hint and cut "Esc cancel" in half; a longer output path would have gone the
  same way.
- Dynamic Protection's panel titles fit at 80 columns, the documented minimum, instead of
  being cut mid-word.
- Choice popups say `Enter choose  Esc cancel`. The one popup shape with no text besides
  its options was also the only one that never mentioned the way out.
- The "Automatic blocking" panel says what its `5d` column means.

- **Switching on a large blocklist feed no longer freezes the TUI for a minute or more.**
  Storing the fetched ranges inserted one row per autocommit — one `fsync` each — so AWS's
  ~7,000 ranges took **98 seconds** on the main thread. One transaction makes the same work
  about a tenth of a second. The same per-row pattern was in the crawler IP ranges, the
  per-country geo ranges and the user-agent hit counts, and is fixed in all four; it was
  fixed for bot lists in an earlier change and these were missed.
- Registering the known bot-list and reputation sources is one transaction rather than nine,
  which is startup cost on every launch.
- The parse of a downloaded feed runs on a worker thread rather than on the async runtime.
  The download always yielded properly, but the parse that follows it is plain CPU work —
  and on a one-core server there is a single runtime thread, shared with the draw loop.

- The TUI now clears the screen before its first frame. On a terminal that ignores the
  alternate-screen request the shell's scrollback stayed put, and because ratatui never
  transmits the blank cells of a first frame, the old text showed through every gap — the
  UI was unreadable.
- `systemctl reload nginx` no longer writes onto the TUI's screen: its output was
  inherited rather than captured, so anything it said corrupted the display, and non-root
  a polkit agent could take over the terminal outright. Its stderr now appears in the
  error message instead.
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

### Security

- **A line from a downloaded feed could become a root shell command.** The IP-range
  and reputation feeds are fetched unattended from eight third parties, and nothing
  validated what they sent before it was interpolated into a generated firewall
  script. A feed line of `1.2.3.4/24; touch /tmp/pwned` rendered as
  `iptables -A STOP-BOTS -s 1.2.3.4/24; touch /tmp/pwned -j DROP`, and
  `stop-bots batch --apply` runs that script under `sh` as root. On nftables the
  same shape gets `nft -f` to accept arbitrary statements — `; flush ruleset` would
  drop the host's entire firewall.

  Admin-entered rules had been validated since an earlier review; the fetched
  ranges were exempted on the grounds that their upstreams are reputable, which is
  not the same as uncompromised. All four tables that hold an address now go
  through one validator, invalid entries are dropped rather than failing the whole
  fetch, and both renderers check again before emitting a line — the script is
  executable input, and a database written by an older version is still out there.

- **The web console could write a root-owned file anywhere on the host.** The
  destination for "Write script" came from a free-text form field, and the file it
  writes is an executable script — `/etc/profile.d/`, `/etc/cron.d/` and unit
  directories were all reachable. That is a way around every restriction the console
  is built around. It now writes to the path the server was started with, set by the
  new `stop-bots web --firewall-out`, and takes no destination from the request.

- **Fetches now have timeouts and a size limit.** Every bot list and IP-range
  download was a bare `reqwest::get`: no connect timeout, no total timeout, and the
  whole body read into memory. Under the internal cron that means an upstream which
  accepts the connection and then says nothing stalls the job indefinitely. There is
  now one shared client (60s total, 10s connect, 5 redirects) and a 32MB cap
  enforced against both the declared length and the bytes actually arriving.

[Unreleased]: https://github.com/ivankovic/stop-bots/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/ivankovic/stop-bots/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ivankovic/stop-bots/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ivankovic/stop-bots/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ivankovic/stop-bots/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ivankovic/stop-bots/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/ivankovic/stop-bots/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ivankovic/stop-bots/compare/v0.1.1...v0.2.0
[0.2.0-rc.2]: https://github.com/ivankovic/stop-bots/compare/v0.2.0-rc.1...v0.2.0-rc.2
[0.2.0-rc.1]: https://github.com/ivankovic/stop-bots/compare/v0.1.1...v0.2.0-rc.1
[0.1.1]: https://github.com/ivankovic/stop-bots/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ivankovic/stop-bots/compare/v0.0.15...v0.1.0
[0.1.0-rc.3]: https://github.com/ivankovic/stop-bots/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/ivankovic/stop-bots/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/ivankovic/stop-bots/compare/v0.0.15...v0.1.0-rc.1
[0.0.15]: https://github.com/ivankovic/stop-bots/compare/v0.0.14...v0.0.15
[0.0.14]: https://github.com/ivankovic/stop-bots/compare/v0.0.13...v0.0.14
[0.0.13]: https://github.com/ivankovic/stop-bots/compare/v0.0.12...v0.0.13
[0.0.12]: https://github.com/ivankovic/stop-bots/compare/v0.0.11...v0.0.12
[0.0.11]: https://github.com/ivankovic/stop-bots/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/ivankovic/stop-bots/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/ivankovic/stop-bots/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/ivankovic/stop-bots/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/ivankovic/stop-bots/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/ivankovic/stop-bots/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/ivankovic/stop-bots/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/ivankovic/stop-bots/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/ivankovic/stop-bots/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/ivankovic/stop-bots/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/ivankovic/stop-bots/releases/tag/v0.0.1
