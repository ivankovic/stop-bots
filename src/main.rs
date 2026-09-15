/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use stop_bots::db::{Db, FirewallAction, FirewallRule, NewFirewallRule};
use stop_bots::{accesslog, botlist, ipranges, nginx, sshlog};

const DEFAULT_DB_PATH: &str = "/var/lib/stop-bots/db.sqlite3";
const DEFAULT_NGINX_ROOT: &str = "/etc/nginx";

/// Rejects `--threshold 0` at the command line.
///
/// Every detector compares `count >= threshold`, so zero matches every
/// address in the log regardless of what it did — one flag away from
/// "block every visitor", in a tool whose whole safety story is never
/// blocking someone by mistake. One is a defensible policy (fail2ban's
/// `maxretry` goes that low); zero is not a policy, it is a mistake, and
/// an error beats silently treating it as one.
fn min_threshold(raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a whole number"))?;
    if value == 0 {
        return Err(
            "a threshold of 0 matches every address in the log, whatever it did".to_string(),
        );
    }
    Ok(value)
}

/// Help text shared by every subcommand's `--db` flag.
const DB_HELP: &str = "Database path (defaults to /var/lib/stop-bots/db.sqlite3, falling back to a per-user location if that's not writable)";

#[derive(Parser)]
// `version` is not decoration: this ships as a tagged GitHub release
// binary, so "is the thing on the server the thing I built?" is a
// question someone will actually have to answer.
#[command(
    name = "stop-bots",
    version,
    about = "Configure your server to stop bad bots"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Discover NGINX sites under a config root and store them in the database
    #[command(alias = "scan")]
    ScanSites {
        /// Root directory to scan for NGINX config files
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Download and store the latest known-bot list from one source
    #[command(alias = "update")]
    UpdateBotLists {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Which bot-list source to update: well-known-bots, ai-robots-txt
        /// or nginx-bad-bots
        #[arg(long, default_value = "well-known-bots")]
        source_id: String,
        /// Read the bot list from a local file instead of downloading it
        /// (parsed as --source-id's format)
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Apply the current blocking policy to every discovered NGINX site
    ApplyBlocks {
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Skip reloading NGINX after writing config changes (e.g. for
        /// tests, or to review the written config before it goes live).
        /// Applying is a no-op without a reload, so real usage wants this
        /// left on.
        #[arg(long)]
        no_reload: bool,
    },
    /// Add a firewall rule blocking (or allowing) an IP address or CIDR range
    AddFirewallRule {
        /// IP address or CIDR range, e.g. 1.2.3.4 or 5.6.7.0/24
        #[arg(long)]
        address: String,
        /// Restrict the rule to a single TCP port
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value = "block")]
        action: String,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// List all stored firewall rules
    ListFirewallRules {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Remove a firewall rule by id
    RemoveFirewallRule {
        #[arg(long)]
        id: i64,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Write the firewall rules to a script for you to review and apply.
    ///
    /// Render the stored firewall rules into an iptables or nftables script.
    /// The script is written to disk only — it is never executed by this
    /// tool. Review it, then apply it yourself. Also includes derived rules
    /// from any blocked-by-default crawler IP-range source and the current
    /// geo mode's selected countries (see UpdateIpRanges/AddCountry/
    /// SetGeoMode) — these are computed fresh each render, never stored as
    /// their own firewall_rules rows.
    ///
    /// Before writing anything, checks recent successful SSH logins (from
    /// /var/log/auth.log, /var/log/secure or journalctl) against every
    /// address about to be blocked, simulating the same first-match-wins
    /// order the script itself will evaluate. If any currently-connected
    /// client would be cut off, it refuses to write the script (pass
    /// --force to override).
    ///
    /// Allowlist geo mode (see SetGeoMode) requires --backend nftables:
    /// iptables has no loopback/established-connection allowance and
    /// silently permits all IPv6 (it skips IPv6 rules entirely), both fatal
    /// once a trailing "block everything else" rule is in play.
    RenderFirewall {
        #[arg(long)]
        backend: FirewallBackend,
        /// Path to write the generated script to
        #[arg(long)]
        out: PathBuf,
        /// Write the script even if it would block an IP with a recent
        /// successful SSH login
        #[arg(long)]
        force: bool,
        /// Check this SSH log file instead of auto-detecting one — for a
        /// non-standard log location, or a container where the real logs
        /// aren't at their usual path
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Block IPs with a pile of failed SSH logins.
    ///
    /// Scans the SSH log for IP addresses with a pile of failed
    /// authentication attempts — the signature of an automated
    /// scanner/brute-force bot, not a human — and adds a temporary Block
    /// rule (expiring after --ttl-days) for each to the firewall_rules
    /// table. Never blocks an IP that also has a successful login anywhere
    /// in the same log, or a loopback/private address (see
    /// stop_bots::sshlog::scanning_ips). Adding a rule here only stores it:
    /// as with every other firewall_rules row, it has no effect until
    /// RenderFirewall renders it into a script and you apply that script
    /// yourself — so this is safe to run unattended (e.g. from cron)
    /// without risking an immediate, unreviewed lockout. The expiry is
    /// enforced by RenderFirewall/ListFirewallRules pruning lapsed rows
    /// on read, not by anything running on a timer — so a block only
    /// actually lifts on the host the next time you render and re-apply
    /// after it expires.
    BlockScanners {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Minimum number of failed-authentication log lines (not a rate —
        /// this module doesn't parse timestamps) before an IP is
        /// considered a scanner rather than someone who mistyped a
        /// password a couple of times
        ///
        /// Must be at least 1. Zero would mean "no evidence required" and
        /// block every address that appears in the log at all.
        #[arg(long, default_value_t = 20, value_parser = min_threshold)]
        threshold: usize,
        /// How many days an added block rule lasts before it's
        /// automatically dropped (re-added on a later run if the IP is
        /// still scanning by then)
        #[arg(long, default_value_t = 5)]
        ttl_days: i64,
        /// Check this SSH log file instead of auto-detecting one
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Show what would be added without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Block IPs that probed a pile of nonexistent URLs.
    ///
    /// Scans the NGINX access log for IP addresses that requested a pile of
    /// distinct nonexistent URLs (404s) — the signature of an automated
    /// vulnerability/URL scanner, not a human clicking a dead link — and
    /// adds a temporary Block rule (expiring after --ttl-days) for each to
    /// the firewall_rules table. Unlike BlockScanners, an IP is not
    /// exempted just because it also got a successful (200) response
    /// somewhere in the log: a scanner's own recon traffic almost always
    /// includes one (see stop_bots::accesslog::scanning_ips for the full
    /// reasoning). Also excludes IPs inside known crawler ranges (Googlebot/
    /// Bingbot/GPTBot). Adding a rule here only stores it: same as every
    /// other firewall_rules row, it has no effect until RenderFirewall
    /// renders it into a script and you apply that script yourself — same
    /// expiry-is-enforced-on-read caveat as BlockScanners.
    BlockWebScanners {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Minimum number of *distinct* 404-returning paths (not total
        /// hits, and not a rate — this module doesn't parse timestamps)
        /// before an IP is considered a scanner rather than a client that
        /// hit one dead link
        ///
        /// Must be at least 1. Zero would mean "no evidence required" and
        /// block every address that appears in the log at all.
        #[arg(long, default_value_t = 7, value_parser = min_threshold)]
        threshold: usize,
        /// How many days an added block rule lasts before it's
        /// automatically dropped (re-added on a later run if the IP is
        /// still scanning by then)
        #[arg(long, default_value_t = 1)]
        ttl_days: i64,
        /// Check this NGINX access log file instead of the default
        /// /var/log/nginx/access.log
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Show what would be added without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Block IPs faking a Googlebot/Bingbot/GPTBot user agent.
    ///
    /// Scans the NGINX access log for IP addresses that claimed, via their
    /// User-Agent, to be Googlebot, Bingbot or GPTBot while connecting from
    /// an address that crawler's own operator does not publish — the
    /// cheapest and most common bot disguise there is — and adds a
    /// temporary Block rule (expiring after --ttl-days) for each.
    ///
    /// This is the offline stand-in for forward-confirmed reverse DNS:
    /// real rDNS needs a lookup per request, which nothing here is in a
    /// position to do, but the operators' published CIDR lists answer the
    /// same "is this actually Google?" question against a log after the
    /// fact. There is deliberately no --threshold: one forged request is
    /// already conclusive, unlike the behavioural counting BlockScanners
    /// and BlockWebScanners do.
    ///
    /// Inert until UpdateIpRanges has fetched at least one crawler's
    /// ranges — with no ranges stored, every real crawler request would
    /// look forged, so those sources are skipped rather than treated as
    /// "nothing is legitimate". Same storage-only, expiry-enforced-on-read
    /// caveats as BlockScanners.
    BlockSpoofedCrawlers {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// How many days an added block rule lasts. Short by default: if a
        /// crawler operator publishes a new range faster than the daily
        /// range refresh picks it up, this bounds how long a real crawler
        /// address stays blocked. A genuine impersonator is re-flagged on
        /// its next request anyway.
        #[arg(long, default_value_t = stop_bots::protection::SPOOFED_CRAWLERS_TTL_DAYS_DEFAULT)]
        ttl_days: i64,
        /// Check this NGINX access log file instead of the default
        /// /var/log/nginx/access.log
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Show what would be added without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Block IPs that asked for /.env, /.git/config and friends.
    ///
    /// Block IPs that asked for /.env, /.git/config and friends.
    ///
    /// Scans the NGINX access log for IP addresses that requested a path
    /// nothing legitimate ever asks for — `/.env`, `/.git/config`,
    /// `/wp-config.php`, `/vendor/phpunit/...` and friends — and adds a
    /// temporary Block rule (expiring after --ttl-days) for each.
    ///
    /// No --threshold, unlike BlockWebScanners: one request to any of
    /// these is already conclusive. The built-in list is chosen strictly
    /// for that reason and deliberately excludes commonly-probed paths
    /// that are *also* legitimate somewhere — `/wp-login.php`,
    /// `/wp-admin/`, `/xmlrpc.php`, `/phpmyadmin` — since instant-blocking
    /// a site's own administrator would be far worse than missing a
    /// scanner that BlockWebScanners catches anyway. Add site-specific
    /// paths with SetProbePaths.
    ///
    /// Same storage-only, expiry-enforced-on-read caveats as BlockScanners.
    BlockProbePaths {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = stop_bots::protection::PROBE_PATHS_TTL_DAYS_DEFAULT)]
        ttl_days: i64,
        /// Check this NGINX access log file instead of the default
        /// /var/log/nginx/access.log
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Show what would be added without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Set the extra probe paths, on top of the built-in list.
    ///
    /// Replaces the extra probe paths checked by BlockProbePaths, on top of
    /// the built-in list (which is never removable — turn the detector off
    /// instead). One path per line; blank lines and `#` comments are
    /// ignored, and every entry must start with `/` since matching is
    /// anchored at the start of the request path.
    SetProbePaths {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Newline-separated paths. Pass an empty string to clear.
        #[arg(long)]
        paths: String,
    },
    /// Lists every probe path currently checked, built-in and extra
    ListProbePaths {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Block anything that fetched the honeypot trap path.
    ///
    /// Scans the NGINX access log for anything that fetched the honeypot
    /// trap path and adds a temporary Block rule (expiring after
    /// --ttl-days) for each.
    ///
    /// The trap path is published as `Disallow:` in the robots.txt this
    /// tool generates and is otherwise unreferenced, so fetching it means
    /// the client either read robots.txt and ignored it, or guessed a path
    /// that exists for no other reason. That makes this the strongest
    /// signal here — hence the longest default TTL — and, unlike a
    /// behavioural threshold, one with essentially no way to trip by
    /// accident.
    ///
    /// Does nothing until the path is actually published: turn on
    /// robots.txt generation (Site settings, or the robots.txt setting on
    /// the CLI) and apply, or add the Disallow line yourself.
    BlockHoneypot {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = stop_bots::protection::HONEYPOT_TTL_DAYS_DEFAULT)]
        ttl_days: i64,
        /// Check this NGINX access log file instead of the default
        /// /var/log/nginx/access.log
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Show what would be added without writing to the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Set the honeypot trap path.
    ///
    /// Must start with `/`. Pick something
    /// that does *not* sound valuable: a path like `/admin` or `/backup`
    /// would also be guessed by scanners that never read robots.txt, which
    /// turns a precise "ignored robots.txt" signal into just another probe
    /// path.
    SetHoneypotPath {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        path: String,
    },
    /// Tally which user agents are getting through successfully.
    ///
    /// Reads the NGINX access log and tallies which user agents made a
    /// successful (non-4xx/5xx) request, adding the counts onto the
    /// `user_agent_stats` table (see stop_bots::accessstats::
    /// record_access_stats) — a read of who's actually visiting
    /// successfully, complementing BlockWebScanners' bad-traffic detection
    /// rather than replacing it. Additive across runs: re-running over an
    /// overlapping or rotated log window accumulates onto each user
    /// agent's existing count instead of resetting it.
    RecordAccessStats {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Check this NGINX access log file instead of the default
        /// /var/log/nginx/access.log
        #[arg(long)]
        access_log: Option<PathBuf>,
    },
    /// Lists recorded user-agent hit counts, most-seen first
    ListAccessStats {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Prune stale rows and compact the database.
    ///
    /// Drops `user_agent_stats` rows for agents not seen in 90 days (and
    /// any excess over 20,000 rows, least recently seen first), clears
    /// lapsed firewall rules, and rewrites the file to hand free pages
    /// back to the filesystem if enough has accumulated to be worth it.
    /// The internal cron does this daily on its own — this runs it now,
    /// which is what a host that has already grown wants, and what a host
    /// with no `sqlite3` installed has no other way to do
    Maintain {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Compact the file even when there is little to reclaim. The
        /// scheduled job weighs that up for itself; this overrides it
        #[arg(long)]
        force_compact: bool,
    },
    /// Download one crawler's published IP ranges.
    ///
    /// Download and store the current CIDR list for one published crawler
    /// IP-range source (Googlebot, Bingbot or GPTBot)
    UpdateIpRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Which source to update: googlebot, bingbot or gptbot
        #[arg(long)]
        source_id: String,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Download one third-party CIDR feed (does not switch it on).
    ///
    /// Download and store one third-party CIDR feed: an abuse/reputation
    /// list (firehol-level1, tor-exits, blocklist-de) or a cloud
    /// provider's published address space (aws, google-cloud,
    /// digitalocean). Fetching does *not* switch the feed on — see
    /// SetReputationSource — so refreshing a feed you deliberately
    /// disabled never silently re-enables it.
    UpdateReputationSource {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        source_id: String,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Switch a third-party CIDR feed on or off.
    ///
    /// While on, every CIDR it
    /// holds becomes a derived Block rule at render-firewall time (nothing
    /// is written to firewall_rules, same as crawler and country ranges).
    ///
    /// All feeds are off by default. Note what the cloud-provider ones
    /// actually do: they block *every* visitor hosted at that provider,
    /// including VPN endpoints, corporate egress and API clients — not
    /// just bots. Unlike the behavioural detectors there's no evidence
    /// involved, and a wrongly-blocked visitor has no way to tell you.
    SetReputationSource {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        source_id: String,
        /// `true` or `false`. Spelled out as a value rather than a bare
        /// `--enabled` flag so the *off* direction is expressible at all
        /// — a flag would only ever be able to turn feeds on.
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// List the third-party CIDR feeds.
    ///
    /// Lists every third-party CIDR feed with its on/off state and how many
    /// ranges it currently holds
    ListReputationSources {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Download one country's IP ranges (does not select it).
    ///
    /// Download and store IPdeny's current aggregated CIDR list for one
    /// country (does not select it — see AddCountry)
    UpdateCountryRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Set the geo mode: blocklist or allowlist.
    ///
    /// "blocklist" (selected countries are
    /// blocked, everything else allowed — the default) or "allowlist"
    /// (selected countries are the only ones allowed, everything else
    /// blocked). Switching modes doesn't touch the selected-country list
    /// itself, only how render-firewall interprets it.
    SetGeoMode {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        mode: GeoModeArg,
    },
    /// Add a country to the geo selection.
    ///
    /// Add a country to the host-wide geo selection (fetch its ranges first
    /// with UpdateCountryRanges). What this means depends on the current
    /// geo mode — see SetGeoMode.
    AddCountry {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        country: String,
    },
    /// Remove a country from the host-wide geo selection
    RemoveCountry {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        country: String,
    },
    /// List the current geo mode and every selected country
    ListSelectedCountries {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Turns NGINX rate limiting on or off, and sets its parameters.
    ///
    /// When on, ApplyBlocks writes a `limit_req_zone` to
    /// /etc/nginx/conf.d/stop-bots-limits.conf (it has to live in `http`
    /// context, so it can't go in the per-site block) and adds a
    /// `limit_req ... burst=N nodelay; limit_req_status 429;` to each
    /// site. NGINX then does the enforcement itself, at request time —
    /// unlike everything else here, no log analysis is involved.
    ///
    /// Off by default: a limit tuned for the wrong site turns away real
    /// visitors, and unlike a bot-pattern block there's no user agent to
    /// inspect afterwards to work out who was caught.
    SetRateLimit {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
        /// Sustained requests per second per client address. Generous by
        /// default (10): one page load can easily fire a dozen requests
        /// for assets.
        #[arg(long)]
        rps: Option<i64>,
        /// How many requests may exceed the rate before any are refused.
        #[arg(long)]
        burst: Option<i64>,
    },
    /// Switch one request-shape rule on or off for a site.
    ///
    /// See the rule list below (see
    /// SetBlockResponse's siblings in Site settings). Rules:
    /// http-1x, no-accept, no-accept-language, no-user-agent,
    /// ip-literal-host, old-tls.
    SetSiteRule {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        #[arg(long)]
        rule: String,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Exempt a path prefix from a site's blocking rules.
    ///
    /// Adds a request-path prefix that a site's blocking rules don't apply
    /// to. Must start with `/`.
    ExemptPath {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        site: String,
        #[arg(long)]
        path: String,
        /// Remove the exemption instead of adding it
        #[arg(long)]
        remove: bool,
    },
    /// Turn generation of a robots.txt on or off.
    ///
    /// When on, ApplyBlocks
    /// writes one to /etc/stop-bots/nginx/robots.txt and adds a
    /// `location = /robots.txt` block to each site that serves it: one
    /// `User-agent:` line per currently-blocked bot under a shared
    /// `Disallow: /`, plus a `Disallow:` for the honeypot trap path.
    ///
    /// Off by default, because it *replaces* whatever the site already
    /// serves at /robots.txt — which may be hand-written and carry rules
    /// this tool knows nothing about.
    ///
    /// This is the polite layer under the 403, for the crawlers that
    /// honour it, and it is also what makes the honeypot work at all.
    SetRobotsTxt {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Prints the robots.txt that would currently be generated, without
    /// writing anything
    ShowRobotsTxt {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Set what NGINX sends a blocked request.
    ///
    ///
    /// These are not interchangeable status codes; each says something
    /// different, and the difference matters most for clients caught by
    /// mistake. "forbidden" (403, the default) is the only one that tells
    /// a wrongly-caught human what happened. "not-found" (404) hides that
    /// anything was blocked. "gone" (410) is the one that asks a
    /// well-behaved crawler to drop the URL permanently — prefer it over
    /// 403 when you're turning away crawlers rather than attackers.
    /// "too-many-requests" (429) tells a polite client to retry later.
    /// "teapot" (418) is RFC 2324's joke — it works, but it is
    /// not IANA-registered and NGINX sends it with an empty body.
    /// "close" (444) sends nothing at all, which is cheapest but
    /// indistinguishable from the server being down. "tarpit" answers 403
    /// but throttles the body to a byte per second, holding the client's
    /// connection open — and one of yours.
    ///
    /// Host-wide, and only changes what *would* be written: run ApplyBlocks
    /// afterwards to get the new response code into the site configs. Until
    /// then Site settings shows every applied site as STALE.
    /// Start the web UI.
    ///
    /// Binds 127.0.0.1:8787 by default, which is reachable only from this
    /// machine. That default is the safe one and staying on it is the
    /// recommendation: the console can rewrite your firewall and your
    /// NGINX config, so it is worth reaching over an SSH tunnel
    /// (`ssh -L 8787:127.0.0.1:8787 you@host`) rather than exposing.
    ///
    /// Binding anywhere else needs --expose as well, on purpose. The
    /// intended deployment for that is behind the same NGINX this tool is
    /// protecting, with TLS and the Host allowlist set:
    ///
    ///   stop-bots web --bind 0.0.0.0:8787 --expose \
    ///     --allowed-hosts admin.example.com --save
    ///
    /// A password is generated and printed the first time this runs.
    /// It is shown once and stored only as an Argon2 hash, so keep it;
    /// --set-password issues a new one.
    Web {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// NGINX config root to scan for sites.
        #[arg(long, default_value = "/etc/nginx")]
        root: PathBuf,
        /// SSH log to read for the Dynamic Protection screen.
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Where the console's "Write script" button and its internal cron
        /// write the firewall script.
        ///
        /// Set here rather than in the console because the console runs as
        /// root and the script is executable: a destination taken from a
        /// form field would let anyone who reaches the login page create a
        /// root-owned file anywhere on the host.
        #[arg(long)]
        firewall_out: Option<PathBuf>,
        /// Address to bind, as `address:port`.
        #[arg(long)]
        bind: Option<String>,
        /// Serve under a path prefix, for an NGINX location block like
        /// `https://example.com/stop-bots/`.
        ///
        /// The proxy must NOT strip the prefix — this server matches the
        /// full path including it, and generates links that do too:
        ///
        ///   location /stop-bots/ {
        ///       proxy_pass http://127.0.0.1:8787;   # no trailing slash
        ///       proxy_set_header Host $host;
        ///   }
        ///
        /// A `proxy_pass` *with* a trailing slash strips the prefix, and
        /// then every link this server generates points outside the
        /// location block. A subdomain needs none of this and is the
        /// simpler deployment if you can take it.
        #[arg(long)]
        base_path: Option<String>,
        /// Permit a bind that is not loopback. Without this, a
        /// non-loopback address is refused rather than silently exposing
        /// the console to the network.
        #[arg(long)]
        expose: bool,
        /// Comma-separated host names this server will answer to, beyond
        /// localhost and 127.0.0.1. Required when reaching it by name:
        /// a request carrying an unlisted Host is refused, which is what
        /// makes DNS rebinding against the console fail.
        ///
        /// Always persisted, with or without --save: the running server
        /// reads it from the database on every request, so there is
        /// nowhere else for it to live.
        #[arg(long)]
        allowed_hosts: Option<String>,
        /// Persist --bind and --expose, so a later plain `stop-bots web`
        /// starts the same way. Nothing is saved unless the address passes
        /// the exposure check first.
        #[arg(long)]
        save: bool,
        /// Generate a new password, print it, and exit without serving.
        #[arg(long)]
        set_password: bool,
        /// Never touch the system: applying writes the database and the
        /// config files but does not reload NGINX or run the firewall
        /// script. The same escape hatch the TUI's --no-reload is.
        #[arg(long)]
        no_apply: bool,
    },
    /// Set the commands used to test and reload NGINX.
    ///
    /// Defaults are `nginx -t` and `systemctl reload nginx`, which is what
    /// a normal host install needs. Change them when NGINX is not a
    /// service on this host — the case that motivated this is NGINX in a
    /// container with its config on a bind mount, where the files are ours
    /// to edit but there is no unit to reload:
    ///
    ///   --test "docker exec web nginx -t"
    ///   --reload "docker exec web nginx -s reload"
    ///
    /// The command is split into words and run directly. It is never
    /// handed to a shell, so `;`, `|`, `&&`, globs and `$VAR` are ordinary
    /// characters in an argument rather than syntax. Quote an argument
    /// that genuinely contains a space.
    ///
    /// Pass neither flag to print the commands currently in effect.
    SetNginxCommands {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// The config check. Must exit non-zero on a bad config.
        #[arg(long)]
        test: Option<String>,
        /// The reload.
        #[arg(long)]
        reload: Option<String>,
        /// Restore both to their defaults.
        #[arg(long, conflicts_with_all = ["test", "reload"])]
        reset: bool,
    },
    SetBlockResponse {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        response: BlockResponseArg,
    },
    /// One unattended pass over everything, for a real cron entry.
    ///
    /// Refreshes every list, scans the logs, writes the NGINX blocking
    /// rules and the firewall script — and, with --apply, puts both into
    /// effect.
    ///
    /// Without --apply nothing is enforced: the config and the script are
    /// written and left alone, which is inert (config does nothing until a
    /// reload, a script does nothing until it is run). That is this
    /// project's default everywhere else and stays the default here.
    ///
    /// With --apply, the SSH lockout guard refuses — and refusing means
    /// nothing is applied — if the rules would block a currently-connected
    /// client, *or* if no SSH log could be read at all so the check could
    /// not run. Interactive RenderFirewall only prints a note in that
    /// second case, because a human is watching; from crontab nobody is.
    /// Pass --ssh-log if the log isn't where this expects, or --force if
    /// you know what you're doing.
    ///
    /// Refreshes bot lists and crawler IP ranges in full, and reputation
    /// feeds and country ranges only where they are switched on or
    /// Report whether this host is actually protected.
    ///
    /// Every other check in this tool compares what it would generate
    /// against what is on disk. This one looks at the kernel, the units
    /// and the filesystem — the gap that let a host run for three weeks
    /// with 48,860 generated rules and an empty ruleset.
    ///
    /// Exits 1 if anything is CRITICAL and 0 otherwise, so it is usable
    /// from a monitoring check. `--quiet` prints only what needs
    /// attention, which is the form to put in cron.
    Status {
        /// Database path (defaults to /var/lib/stop-bots/db.sqlite3,
        /// falling back to a per-user location if that's not writable)
        #[arg(long)]
        db: Option<PathBuf>,
        /// Read this SSH log instead of auto-detecting one
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Print only checks that need attention
        #[arg(long)]
        quiet: bool,
        /// Use the last probe the internal cron took instead of looking at
        /// the host now. Cheap, and what the dashboards show.
        #[arg(long)]
        cached: bool,
    },
    /// selected. One step's failure never stops the others; the exit
    /// status is non-zero if any of them failed, which is what makes cron
    /// mail you.
    Batch {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Root directory to scan for NGINX config files
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        /// Reload NGINX and run the generated firewall script, rather than
        /// only writing both
        #[arg(long)]
        apply: bool,
        /// Path to write the generated firewall script to. Defaults to
        /// /etc/stop-bots/firewall.nft, or firewall.sh with --backend
        /// iptables — which generates a shell script, not an nftables one
        #[arg(long)]
        out: Option<PathBuf>,
        /// Which firewall to generate for. Defaults to whichever backend
        /// this host is set to — the console records that, and a crontab
        /// that silently disagreed with it used to leave two scripts on
        /// disk, in two syntaxes, at two paths, one of them stale.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// Read this SSH log file instead of auto-detecting one. Worth
        /// setting explicitly under cron: on a journald-only host,
        /// `journalctl` can come back empty, which is the case --apply
        /// refuses on
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Read this NGINX access log instead of auto-detecting one
        #[arg(long)]
        access_log: Option<PathBuf>,
        /// Apply even if the lockout guard objects, or could not run
        #[arg(long)]
        force: bool,
        /// Skip every step that downloads something — for a host with no
        /// outbound access, or a second, more frequent cron entry that
        /// only wants the log scan and the apply (bot lists change weekly;
        /// an access log changes every second)
        #[arg(long)]
        no_fetch: bool,
        /// Print a line per step, not just the failures
        #[arg(long, short)]
        verbose: bool,
    },
    /// Set stop-bots up as a system service.
    ///
    /// Currently Debian with systemd, which is what has been tested. The
    /// unit it writes is very likely correct on any systemd distribution;
    /// the SSH log path it assumes is Debian's.
    ///
    /// Nothing is written until every check has passed, an existing unit
    /// file that you have edited is left alone rather than replaced, and
    /// --dry-run prints the whole plan without touching anything. Start
    /// there.
    Install {
        /// What to install. `web` writes a systemd unit for the web
        /// console and enables it.
        #[arg(value_enum)]
        target: InstallTarget,
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Print every step and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Replace a unit file that exists and differs from what this
        /// would write.
        #[arg(long)]
        force: bool,
        /// Enable the unit but do not start it now.
        #[arg(long)]
        no_start: bool,
        /// The stop-bots binary to name in ExecStart. Defaults to the one
        /// running this command, which is refused if it sits in a build
        /// directory — a unit pointing into target/debug works until the
        /// next `cargo clean`.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// NGINX config root the service will scan.
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        /// Pin the service to this SSH log instead of letting it find one.
        ///
        /// Leave it off unless the log is somewhere this would not look.
        /// Without it the service tries /var/log/auth.log, /var/log/secure
        /// and then journalctl, every time it reads — which is what works
        /// on a host that keeps sshd's output only in the journal. Naming
        /// a path here disables that search for the life of the unit.
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Install into this prefix instead of `/`. For inspecting the
        /// result without root; a unit written under a prefix is not a
        /// unit systemd will ever see, so this skips systemctl entirely.
        #[arg(long)]
        prefix: Option<PathBuf>,
        /// Address the service will bind. Persisted to the database, not
        /// written into the unit — the server re-reads it.
        #[arg(long)]
        bind: Option<String>,
        /// Serve under a path prefix, for an NGINX `location` block.
        #[arg(long)]
        base_path: Option<String>,
        /// Permit a bind that is not loopback.
        #[arg(long)]
        expose: bool,
        /// Comma-separated host names the console will answer to.
        #[arg(long)]
        allowed_hosts: Option<String>,
    },
    /// Start the TUI (also the default when run with no subcommand)
    Tui {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Root directory to scan for NGINX config files, when triggering a
        /// site scan from Site settings
        #[arg(long, default_value = DEFAULT_NGINX_ROOT)]
        root: PathBuf,
        /// Skip reloading NGINX after Site settings applies blocking rules
        /// (e.g. for tests driving the TUI end to end against a throwaway
        /// fixture root, where there's no real NGINX install to reload)
        #[arg(long)]
        no_reload: bool,
        /// Read this SSH log file instead of auto-detecting one — the same
        /// override every SSH-reading CLI subcommand already takes, and for
        /// the same two audiences: a host with a non-standard log location,
        /// and tests, where auto-detection would otherwise shell out to
        /// `journalctl` on every refresh of the Dynamic Protection screen
        #[arg(long)]
        ssh_log: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum InstallTarget {
    /// The web console, as a systemd service.
    Web,
}

#[derive(Clone, Copy, ValueEnum)]
enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Clone, Copy, ValueEnum)]
enum GeoModeArg {
    Blocklist,
    Allowlist,
}

impl From<GeoModeArg> for stop_bots::db::GeoMode {
    fn from(arg: GeoModeArg) -> Self {
        match arg {
            GeoModeArg::Blocklist => stop_bots::db::GeoMode::Blocklist,
            GeoModeArg::Allowlist => stop_bots::db::GeoMode::Allowlist,
        }
    }
}

/// Named rather than numeric (`--response forbidden`, not `--response
/// 403`): "444" means nothing without knowing NGINX's non-standard codes,
/// and a bare number invites passing an arbitrary one this tool doesn't
/// support.
#[derive(Clone, Copy, ValueEnum)]
enum BlockResponseArg {
    /// 403 — says the block was deliberate
    Forbidden,
    /// 404 — hides that anything was blocked
    NotFound,
    /// 410 — asks well-behaved crawlers to drop the URL for good
    Gone,
    /// 429 — tells a polite client to back off and retry
    TooManyRequests,
    /// 418 — a joke (RFC 2324); unregistered, and sends an empty body
    Teapot,
    /// 444 — close without replying at all
    Close,
    /// A 403 whose body is throttled to one byte per second
    Tarpit,
}

impl From<BlockResponseArg> for stop_bots::db::BlockResponse {
    fn from(arg: BlockResponseArg) -> Self {
        use stop_bots::db::BlockResponse as R;
        match arg {
            BlockResponseArg::Forbidden => R::Forbidden,
            BlockResponseArg::NotFound => R::NotFound,
            BlockResponseArg::Gone => R::Gone,
            BlockResponseArg::TooManyRequests => R::TooManyRequests,
            BlockResponseArg::Teapot => R::Teapot,
            BlockResponseArg::Close => R::Close,
            BlockResponseArg::Tarpit => R::Tarpit,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => run_tui(None, PathBuf::from(DEFAULT_NGINX_ROOT), false, None).await,
        Some(Command::Tui {
            db,
            root,
            no_reload,
            ssh_log,
        }) => run_tui(db, root, no_reload, ssh_log).await,
        Some(Command::Install {
            target,
            db,
            dry_run,
            force,
            no_start,
            binary,
            root,
            ssh_log,
            prefix,
            bind,
            base_path,
            expose,
            allowed_hosts,
        }) => match target {
            InstallTarget::Web => run_install_web(InstallWeb {
                db,
                dry_run,
                force,
                start: !no_start,
                binary,
                root,
                ssh_log,
                prefix,
                bind,
                base_path,
                expose,
                allowed_hosts,
            }),
        },
        Some(Command::Status {
            db,
            ssh_log,
            quiet,
            cached,
        }) => run_status(db, ssh_log, quiet, cached),
        Some(Command::Batch {
            db,
            root,
            apply,
            out,
            backend,
            ssh_log,
            access_log,
            force,
            no_fetch,
            verbose,
        }) => {
            run_batch(
                db,
                BatchRequest {
                    root,
                    out,
                    backend,
                    apply,
                    ssh_log,
                    access_log,
                    force,
                    no_fetch,
                },
                verbose,
            )
            .await
        }
        Some(Command::ScanSites { root, db }) => scan_sites(&root, db),
        Some(Command::UpdateBotLists {
            db,
            source_id,
            source,
        }) => update_bot_lists(db, source_id, source).await,
        Some(Command::ApplyBlocks {
            root,
            db,
            no_reload,
        }) => apply_blocks(&root, db, no_reload),
        Some(Command::AddFirewallRule {
            address,
            port,
            action,
            db,
        }) => add_firewall_rule(db, address, port, &action),
        Some(Command::ListFirewallRules { db }) => list_firewall_rules(db),
        Some(Command::RemoveFirewallRule { id, db }) => remove_firewall_rule(db, id),
        Some(Command::RenderFirewall {
            backend,
            out,
            force,
            ssh_log,
            db,
        }) => render_firewall(db, backend, &out, force, ssh_log),
        Some(Command::BlockScanners {
            db,
            threshold,
            ttl_days,
            ssh_log,
            dry_run,
        }) => block_scanners(db, threshold, ttl_days, ssh_log, dry_run),
        Some(Command::BlockWebScanners {
            db,
            threshold,
            ttl_days,
            access_log,
            dry_run,
        }) => block_web_scanners(db, threshold, ttl_days, access_log, dry_run),
        Some(Command::BlockSpoofedCrawlers {
            db,
            ttl_days,
            access_log,
            dry_run,
        }) => block_spoofed_crawlers(db, ttl_days, access_log, dry_run),
        Some(Command::BlockProbePaths {
            db,
            ttl_days,
            access_log,
            dry_run,
        }) => block_probe_paths(db, ttl_days, access_log, dry_run),
        Some(Command::SetProbePaths { db, paths }) => set_probe_paths(db, paths),
        Some(Command::ListProbePaths { db }) => list_probe_paths(db),
        Some(Command::BlockHoneypot {
            db,
            ttl_days,
            access_log,
            dry_run,
        }) => block_honeypot(db, ttl_days, access_log, dry_run),
        Some(Command::SetHoneypotPath { db, path }) => set_honeypot_path(db, path),
        Some(Command::RecordAccessStats { db, access_log }) => record_access_stats(db, access_log),
        Some(Command::ListAccessStats { db }) => list_access_stats(db),
        Some(Command::Maintain { db, force_compact }) => maintain(db, force_compact),
        Some(Command::UpdateIpRanges {
            db,
            source_id,
            source,
        }) => update_ip_ranges(db, source_id, source).await,
        Some(Command::UpdateReputationSource {
            db,
            source_id,
            source,
        }) => update_reputation_source(db, source_id, source).await,
        Some(Command::SetReputationSource {
            db,
            source_id,
            enabled,
        }) => set_reputation_source(db, source_id, enabled),
        Some(Command::ListReputationSources { db }) => list_reputation_sources(db),
        Some(Command::UpdateCountryRanges {
            db,
            country,
            source,
        }) => update_country_ranges(db, country, source).await,
        Some(Command::SetGeoMode { db, mode }) => set_geo_mode(db, mode),
        Some(Command::AddCountry { db, country }) => set_country_selected(db, country, true),
        Some(Command::RemoveCountry { db, country }) => set_country_selected(db, country, false),
        Some(Command::ListSelectedCountries { db }) => list_selected_countries(db),
        Some(Command::Web {
            db,
            root,
            ssh_log,
            firewall_out,
            bind,
            base_path,
            expose,
            allowed_hosts,
            save,
            set_password,
            no_apply,
        }) => {
            run_web(
                db,
                root,
                ssh_log,
                firewall_out,
                bind,
                base_path,
                expose,
                allowed_hosts,
                save,
                set_password,
                no_apply,
            )
            .await
        }
        Some(Command::SetNginxCommands {
            db,
            test,
            reload,
            reset,
        }) => set_nginx_commands(db, test, reload, reset),
        Some(Command::SetBlockResponse { db, response }) => set_block_response(db, response),
        Some(Command::SetRateLimit {
            db,
            enabled,
            rps,
            burst,
        }) => set_rate_limit(db, enabled, rps, burst),
        Some(Command::SetSiteRule {
            db,
            site,
            rule,
            enabled,
        }) => set_site_rule(db, site, rule, enabled),
        Some(Command::ExemptPath {
            db,
            site,
            path,
            remove,
        }) => exempt_path(db, site, path, remove),
        Some(Command::SetRobotsTxt { db, enabled }) => set_robots_txt(db, enabled),
        Some(Command::ShowRobotsTxt { db }) => show_robots_txt(db),
    }
}

/// Resolves and opens the database. An explicit `--db` is always honored
/// as-is, even if opening it fails — silently substituting a path the user
/// asked for would be worse than just erroring. Without one, tries the
/// system location first and falls back to a per-user location if that
/// isn't writable: `/var/lib` typically needs root, which actually applying
/// nginx/firewall changes needs anyway, but just exploring with `cargo run`
/// or the TUI shouldn't require it.
fn open_db(explicit: Option<PathBuf>) -> Result<Db> {
    let Some(path) = explicit else {
        return open_default_db();
    };
    Db::open(path)
}

fn open_default_db() -> Result<Db> {
    open_or_fallback(Path::new(DEFAULT_DB_PATH), user_db_path)
}

/// Tries to create `primary`'s parent directory and open it as the
/// database; only if that directory can't even be created does it fall
/// back to whatever `fallback` resolves to (printing a note about which
/// path was used). `fallback` is a closure, not an already-resolved path,
/// so resolving it (which can itself fail, e.g. if neither `XDG_DATA_HOME`
/// nor `HOME` is set) never gets in the way of the common case where
/// `primary` just works — important for e.g. a root-run container with a
/// minimal environment, where `/var/lib` is perfectly writable but `HOME`
/// might not be set at all.
///
/// Deliberately narrow: this does *not* fall back on every kind of
/// failure, e.g. the directory existing but its database file being
/// corrupt, or owned by someone else and unreadable. Falling back in those
/// cases would hand back a fresh, empty database that's easy to mistake for
/// "no data yet" instead of surfacing the real problem — the dev-ergonomics
/// win this exists for is specifically "the system directory doesn't exist
/// and I can't create it", not "something is wrong with the system db".
fn open_or_fallback(primary: &Path, fallback: impl FnOnce() -> Result<PathBuf>) -> Result<Db> {
    let parent = primary
        .parent()
        .with_context(|| format!("{} has no parent directory", primary.display()))?;
    if let Err(dir_err) = std::fs::create_dir_all(parent) {
        let fallback = fallback()?;
        eprintln!(
            "Note: couldn't create {} ({dir_err}); using {} instead.",
            parent.display(),
            fallback.display()
        );
        return Db::open(&fallback).with_context(|| {
            format!(
                "failed to create {} ({dir_err}) and failed to open the fallback database at {}",
                parent.display(),
                fallback.display()
            )
        });
    }
    Db::open(primary)
}

/// The per-user fallback database location, following the XDG Base
/// Directory spec (`$XDG_DATA_HOME`, or `~/.local/share` if that's unset).
fn user_db_path() -> Result<PathBuf> {
    resolve_user_db_path(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// Pure resolution logic for [`user_db_path`], taking the relevant env vars
/// as parameters so it's testable without mutating real process env vars
/// (which would race with other tests in this binary).
fn resolve_user_db_path(
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let data_home = xdg_data_home
        .map(PathBuf::from)
        .or_else(|| home.map(|home| PathBuf::from(home).join(".local/share")))
        .context(
            "could not determine a per-user data directory: neither XDG_DATA_HOME nor HOME is set",
        )?;
    Ok(data_home.join("stop-bots").join("db.sqlite3"))
}

/// Blanks the screen before the TUI's first frame.
///
/// `ratatui::init` enters the alternate screen, which normally comes up
/// blank — but a terminal that ignores the request (a `TERM` without
/// `smcup`, tmux with `alternate-screen off`) leaves the shell's scrollback
/// where it is. That would be cosmetic if the first frame painted over it,
/// and it doesn't: ratatui diffs each frame against the previous one, and
/// the first is diffed against a buffer that is already blank, so none of
/// the frame's blank cells are transmitted and the old text shows through
/// every gap.
///
/// Deliberately not `Terminal::clear`, which snapshots the cursor position
/// first — a `\x1b[6n` query that blocks until the terminal answers, and
/// errors out after a timeout on any terminal that doesn't. There is no
/// cursor position worth preserving here.
fn clear_screen() -> Result<()> {
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )
    .context("failed to clear the terminal")
}

async fn run_tui(
    db_path: Option<PathBuf>,
    root: PathBuf,
    no_reload: bool,
    ssh_log: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let app = stop_bots::app::App::new(db, root, !no_reload, ssh_log)?;
    let terminal = ratatui::init();
    // Not `?`: bailing here would skip the `restore` below and leave the
    // terminal in raw mode.
    let result = match clear_screen() {
        Ok(()) => app.run(terminal).await,
        Err(err) => Err(err),
    };
    ratatui::restore();
    result
}

/// Runs one batch pass and turns its report into output and an exit
/// status.
///
/// Quiet on success on purpose: this is built to sit in a crontab, and
/// `cron` mails the owner anything a job prints. A nightly run that says
/// nothing is a nightly run nobody has to read. `--verbose` prints every
/// step, which is what a first run by hand wants.
///
/// Failures go to stderr and set a non-zero exit status, so they are
/// visible whichever way the job is wired up.
/// Where `batch` writes its firewall script when not told otherwise.
///
/// Prints the health report, and exits non-zero if anything is critical.
///
/// The exit status is the point: this is meant to go in a monitoring check
/// or a crontab, where nobody reads the output until something is wrong.
fn run_status(
    db_path: Option<PathBuf>,
    ssh_log: Option<PathBuf>,
    quiet: bool,
    cached: bool,
) -> Result<()> {
    use stop_bots::health::{self, Level};

    let db = open_db(db_path)?;
    let (report, taken_at) = if cached {
        match health::cached_report(&db)? {
            Some((report, at)) => (report, Some(at)),
            None => anyhow::bail!(
                "no health probe has been recorded yet — run `stop-bots status` without \
                 --cached, or leave the console running so its internal cron takes one"
            ),
        }
    } else {
        let backend = stop_bots::firewall::stored_backend(&db)?;
        let path = db
            .path()
            .unwrap_or_else(|| PathBuf::from("./stop-bots.sqlite3"));
        let probe = health::probe(backend, &path, ssh_log.as_deref());
        health::store_probe(&db, &probe)?;
        (health::assess(&db, &probe)?, None)
    };

    let shown: Vec<_> = if quiet {
        report.at_least(Level::Warn)
    } else {
        report.checks.iter().collect()
    };

    if quiet && shown.is_empty() {
        return Ok(());
    }

    println!("{}", report.headline());
    if let Some(at) = taken_at {
        println!("(from a probe taken {})", format_age(at));
    }
    println!();

    for check in shown {
        println!("  [{}] {}", check.level.tag(), check.title);
        println!("      {}", check.detail);
        if let Some(fix) = &check.fix {
            println!("      -> {fix}");
        }
    }
    println!();

    if report.worst() == Level::Critical {
        // `bail!` rather than `exit(1)`: it prints the reason, and the
        // reason is the whole value of a non-zero status here.
        anyhow::bail!("this host is not protected the way it is configured to be");
    }
    Ok(())
}

/// "3 minutes ago", for a probe's timestamp.
fn format_age(taken_at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let seconds = (now - taken_at).max(0);
    match seconds {
        0..=90 => "just now".to_string(),
        91..=5400 => format!("{} minute(s) ago", seconds / 60),
        _ => format!("{} hour(s) ago", seconds / 3600),
    }
}

/// `batch`'s arguments as the command line gives them, before the two
/// that depend on the database have been resolved.
///
/// Separate from [`stop_bots::batch::BatchOptions`] because resolving them
/// needs an open database and parsing does not: the backend falls back to
/// whatever this host is set to, and the output path falls out of
/// whichever backend that turns out to be.
struct BatchRequest {
    root: PathBuf,
    out: Option<PathBuf>,
    backend: Option<FirewallBackend>,
    apply: bool,
    ssh_log: Option<PathBuf>,
    access_log: Option<PathBuf>,
    force: bool,
    no_fetch: bool,
}

async fn run_batch(db_path: Option<PathBuf>, request: BatchRequest, verbose: bool) -> Result<()> {
    let db = open_db(db_path)?;

    // An explicit `--backend` wins; without one, the host's own setting
    // does. It used to be neither: the flag carried a `nftables` default,
    // so a host switched to iptables in the console got an nftables script
    // from every cron run — at the *other* path, so both files existed and
    // one of them was always stale. The same drift once had the internal
    // cron overwriting an operator's iptables script with nftables syntax.
    let backend = match request.backend {
        Some(backend) => backend.into(),
        None => stop_bots::firewall::stored_backend(&db)?,
    };
    let options = stop_bots::batch::BatchOptions {
        root: request.root,
        out: request
            .out
            .unwrap_or_else(|| stop_bots::firewall::default_output_path(backend)),
        backend,
        apply: request.apply,
        ssh_log: request.ssh_log,
        access_log: request.access_log,
        force: request.force,
        no_fetch: request.no_fetch,
    };

    let report = stop_bots::batch::run(&db, &options).await;

    if verbose {
        println!("{}", report.full());
    } else if report.failures() > 0 {
        eprintln!("{}", report.failures_only());
    }

    let failures = report.failures();
    if failures > 0 {
        anyhow::bail!("{failures} of {} step(s) failed", report.steps.len());
    }
    Ok(())
}

fn scan_sites(root: &Path, db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let sites = nginx::discover_sites(root)?;
    for site in &sites {
        db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
    }
    println!(
        "Discovered {} site(s) under {}",
        sites.len(),
        root.display()
    );
    Ok(())
}

async fn update_bot_lists(
    db_path: Option<PathBuf>,
    source_id: String,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let kind = botlist::SourceKind::from_id(&source_id)
        .with_context(|| format!("unknown bot-list source id: {source_id}"))?;
    let count = match source {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)?;
            let bots = kind.parse(&raw)?;
            botlist::store(&db, kind, &bots)?
        }
        None => botlist::update(&db, kind).await?,
    };
    println!("Stored {count} bot(s) from {}", kind.name());
    Ok(())
}

fn apply_blocks(root: &Path, db_path: Option<PathBuf>, no_reload: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let outcome = nginx::apply_all_sites(&db, root)?;
    println!(
        "Applied blocking rules to {} site(s) across {} file(s), {} file(s) changed",
        outcome.sites, outcome.files, outcome.changed
    );

    // Writing the sentinel block does nothing until NGINX re-reads it — no
    // point reloading when nothing actually changed on disk.
    if outcome.changed > 0 && !no_reload {
        let commands = nginx::NginxCommands::from_db(&db)?;
        nginx::reload_with(&commands).context("nginx config was applied, but reload failed")?;
        println!("Reloaded NGINX");
    }
    Ok(())
}

fn add_firewall_rule(
    db_path: Option<PathBuf>,
    address: String,
    port: Option<u16>,
    action: &str,
) -> Result<()> {
    let db = open_db(db_path)?;
    let id = db.add_firewall_rule(&NewFirewallRule {
        address,
        port,
        action: FirewallAction::parse(action)?,
    })?;
    println!("Added firewall rule #{id}");
    Ok(())
}

fn list_firewall_rules(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let rules = db.list_firewall_rules()?;
    if rules.is_empty() {
        println!("No firewall rules stored.");
        return Ok(());
    }
    for rule in rules {
        let port = rule.port.map(|p| format!(":{p}")).unwrap_or_default();
        let status = if rule.enabled { "" } else { " (disabled)" };
        let expiry = rule
            .expires_at
            .map(|t| format!(" ({})", format_expiry(t)))
            .unwrap_or_default();
        println!(
            "#{} {:?} {}{}{}{}",
            rule.id, rule.action, rule.address, port, status, expiry
        );
    }
    Ok(())
}

/// Renders a firewall rule's `expires_at` (Unix seconds, already known to
/// be in the future — anything at or past `now` would have been pruned
/// before `list_firewall_rules` returned it) as a short "expires in ..."
/// string for `list-firewall-rules`. Rounds down to whole days once at
/// least one has passed, otherwise whole hours — precision the admin
/// scanning a rule list actually needs, not a countdown clock.
fn format_expiry(expires_at: i64) -> String {
    let seconds_left = (expires_at - now_secs()).max(0);
    let days = seconds_left / 86_400;
    if days > 0 {
        format!("expires in {days}d")
    } else {
        let hours = (seconds_left / 3_600).max(1);
        format!("expires in {hours}h")
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn remove_firewall_rule(db_path: Option<PathBuf>, id: i64) -> Result<()> {
    let db = open_db(db_path)?;
    db.remove_firewall_rule(id)?;
    println!("Removed firewall rule #{id}");
    Ok(())
}

async fn update_ip_ranges(
    db_path: Option<PathBuf>,
    source_id: String,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let kind = ipranges::IpRangeSourceKind::from_id(&source_id)
        .with_context(|| format!("unknown ip-range source id: {source_id}"))?;
    let count = match source {
        Some(path) => ipranges::store(&db, kind, &kind.parse(&read_source_file(&path)?)?)?,
        None => ipranges::update(&db, kind).await?,
    };
    println!("Stored {count} CIDR range(s) from {}", kind.name());
    Ok(())
}

async fn update_country_ranges(
    db_path: Option<PathBuf>,
    country: String,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let count = match source {
        Some(path) => ipranges::store_country(&db, &country, &read_source_file(&path)?)?,
        None => ipranges::update_country(&db, &country).await?,
    };
    println!("Stored {count} CIDR range(s) for country {country}");
    Ok(())
}

/// Reads a `--source` override, saying which file failed rather than
/// leaving a bare "No such file or directory" to be matched against three
/// possible paths on the command line.
fn read_source_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn set_geo_mode(db_path: Option<PathBuf>, mode: GeoModeArg) -> Result<()> {
    let db = open_db(db_path)?;
    let mode: stop_bots::db::GeoMode = mode.into();
    db.set_geo_mode(mode)?;
    println!("Geo mode set to {mode:?}");
    Ok(())
}

async fn update_reputation_source(
    db_path: Option<PathBuf>,
    source_id: String,
    source: Option<PathBuf>,
) -> Result<()> {
    use stop_bots::ipranges::reputation::{self, ReputationSourceKind};

    let db = open_db(db_path)?;
    let Some(kind) = ReputationSourceKind::from_id(&source_id) else {
        let known: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
        anyhow::bail!("unknown source: {source_id} (known: {})", known.join(", "));
    };
    let count = match source {
        Some(path) => reputation::store(&db, kind, &kind.parse(&read_source_file(&path)?)?)?,
        None => reputation::update(&db, kind).await?,
    };
    println!("Stored {count} range(s) for {}", kind.name());
    // Fetching and enabling are separate on purpose; say so, or a fetch
    // that appears to succeed but changes nothing reads as a bug.
    let enabled = db
        .list_reputation_sources()?
        .into_iter()
        .any(|s| s.id == kind.id() && s.enabled);
    if !enabled {
        println!(
            "This feed is currently OFF — run `stop-bots set-reputation-source --source-id {} \
             --enabled true` to apply it.",
            kind.id()
        );
    }
    Ok(())
}

fn set_reputation_source(db_path: Option<PathBuf>, source_id: String, enabled: bool) -> Result<()> {
    use stop_bots::ipranges::reputation::ReputationSourceKind;

    let db = open_db(db_path)?;
    let Some(kind) = ReputationSourceKind::from_id(&source_id) else {
        let known: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
        anyhow::bail!("unknown source: {source_id} (known: {})", known.join(", "));
    };
    db.register_reputation_source(&kind.as_source())?;
    db.set_reputation_source_enabled(kind.id(), enabled)?;
    println!(
        "{} is now {}",
        kind.name(),
        if enabled { "ON" } else { "OFF" }
    );
    if enabled {
        if let Some(warning) = kind.warning() {
            println!("Warning: {warning}.");
        }
        let count = db
            .list_reputation_sources()?
            .into_iter()
            .find(|s| s.id == kind.id())
            .map(|s| s.range_count)
            .unwrap_or(0);
        if count == 0 {
            println!(
                "No ranges stored yet — run `stop-bots update-reputation-source --source-id {}` \
                 first, or this does nothing.",
                kind.id()
            );
        }
        println!("Run render-firewall, then apply the script, to enforce it.");
    }
    Ok(())
}

fn list_reputation_sources(db_path: Option<PathBuf>) -> Result<()> {
    use stop_bots::ipranges::reputation::{self, ReputationSourceKind};

    let db = open_db(db_path)?;
    reputation::register_all_reputation_sources(&db)?;
    for source in db.list_reputation_sources()? {
        let state = if source.enabled { "ON " } else { "OFF" };
        let fetched = match source.last_fetched_at {
            Some(_) => format!("{} range(s)", source.range_count),
            None => "never fetched".to_string(),
        };
        let note = ReputationSourceKind::from_id(&source.id)
            .and_then(|k| k.warning())
            .map(|w| format!("  [{w}]"))
            .unwrap_or_default();
        println!("[{state}] {:<22} {fetched}{note}", source.id);
    }
    Ok(())
}

fn set_rate_limit(
    db_path: Option<PathBuf>,
    enabled: bool,
    rps: Option<i64>,
    burst: Option<i64>,
) -> Result<()> {
    let db = open_db(db_path)?;
    // Parameters are stored even when disabling, so `--enabled false
    // --rps 5` then `--enabled true` uses 5 rather than silently
    // reverting to the default.
    if let Some(rps) = rps {
        db.set_rate_limit_rps(rps)?;
    }
    if let Some(burst) = burst {
        db.set_rate_limit_burst(burst)?;
    }
    db.set_rate_limit_enabled(enabled)?;
    if enabled {
        println!(
            "Rate limiting on: {} req/s per client, burst {}, then 429.",
            db.get_rate_limit_rps()?,
            db.get_rate_limit_burst()?
        );
    } else {
        println!("Rate limiting off.");
    }
    println!("Run `stop-bots apply-blocks` to write it into the NGINX config.");
    Ok(())
}

/// Resolves a `server_name` to its `sites` row, failing with the known
/// names rather than a bare "not found" — a typo here is the likeliest
/// mistake, and the fix is usually visible in the list.
fn find_site(db: &stop_bots::db::Db, server_name: &str) -> Result<stop_bots::db::Site> {
    let sites = db.list_sites()?;
    sites
        .iter()
        .find(|s| s.server_name == server_name)
        .cloned()
        .ok_or_else(|| {
            let known: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
            if known.is_empty() {
                anyhow::anyhow!("no sites discovered yet — run `stop-bots scan-sites` first")
            } else {
                anyhow::anyhow!("unknown site: {server_name} (known: {})", known.join(", "))
            }
        })
}

fn set_site_rule(
    db_path: Option<PathBuf>,
    site: String,
    rule: String,
    enabled: bool,
) -> Result<()> {
    use stop_bots::nginx::RequestRule;

    let db = open_db(db_path)?;
    let site = find_site(&db, &site)?;
    // Accept the dashed form the CLI advertises as well as the stored
    // underscore form, so `--rule no-user-agent` works.
    let id = rule.replace('-', "_");
    let Some(rule) = RequestRule::from_id(&id) else {
        let known: Vec<String> = RequestRule::ALL
            .iter()
            .map(|r| r.id().replace('_', "-"))
            .collect();
        anyhow::bail!("unknown rule: {rule} (known: {})", known.join(", "));
    };
    db.set_site_request_rule(site.id, rule.id(), enabled)?;
    println!(
        "{}: {} is now {}",
        site.server_name,
        rule.label(),
        if enabled { "blocked" } else { "allowed" }
    );
    if enabled {
        println!("Note: {}.", rule.caveat());
    }
    println!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

fn exempt_path(db_path: Option<PathBuf>, site: String, path: String, remove: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let site = find_site(&db, &site)?;
    let trimmed = path.trim();
    // Matching is anchored at the start of the request path, so a value
    // without a leading slash could never fire — refused rather than
    // stored and silently ignored, same as the TUI does.
    if !remove && !trimmed.starts_with('/') {
        anyhow::bail!("an exempt path must start with '/' (got {trimmed:?})");
    }
    if remove {
        db.remove_site_path_exemption(site.id, trimmed)?;
        println!("{}: {trimmed} is no longer exempt", site.server_name);
    } else {
        db.add_site_path_exemption(site.id, trimmed)?;
        println!("{}: {trimmed} is exempt from blocking", site.server_name);
    }
    println!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

fn set_robots_txt(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_serve_robots_txt(enabled)?;
    println!(
        "robots.txt generation {}",
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled {
        println!(
            "It replaces whatever each site currently serves at /robots.txt. Preview it with \
             `stop-bots show-robots-txt`."
        );
    }
    println!("Run `stop-bots apply-blocks` to write it into the site configs.");
    Ok(())
}

fn show_robots_txt(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    print!("{}", nginx::robots_txt_body(&db)?);
    Ok(())
}

/// Everything `install web` was given. A struct because it is a dozen
/// fields and `run_install_web(db, true, false, true, None, ...)` is not
/// a call anyone can read.
struct InstallWeb {
    db: Option<PathBuf>,
    dry_run: bool,
    force: bool,
    start: bool,
    binary: Option<PathBuf>,
    root: PathBuf,
    ssh_log: Option<PathBuf>,
    prefix: Option<PathBuf>,
    bind: Option<String>,
    base_path: Option<String>,
    expose: bool,
    allowed_hosts: Option<String>,
}

fn run_install_web(options: InstallWeb) -> Result<()> {
    use stop_bots::install::{self, Layout, Options};
    use stop_bots::web;

    let binary = match options.binary {
        Some(path) => path,
        None => {
            let current = std::env::current_exe()
                .context("could not work out which stop-bots binary is running")?;
            // A unit naming target/debug/stop-bots works right up until the
            // next `cargo clean`, and nothing warns when it stops.
            if install::is_build_artifact(&current) {
                anyhow::bail!(
                    "{} is a build artifact, so a unit naming it would break on the \
                     next `cargo clean`. Install the binary first, then:\n\n    \
                     stop-bots install web --binary /usr/local/bin/stop-bots\n\n\
                     Or pass --binary explicitly if you really do mean this path.",
                    current.display()
                );
            }
            current
        }
    };

    let prefix = options.prefix.clone().unwrap_or_else(|| PathBuf::from("/"));
    let mut layout = Layout::under(&prefix, binary);
    // `--root` has its own default and is absolute, so it replaces what the
    // prefix produced rather than being joined onto it. Under a prefix that
    // means the unit names the real path, which is right: a prefixed install
    // is for reading the output, not running it.
    layout.nginx_root = options.root;
    // Stays `None` unless the operator passed `--ssh-log`, which is what
    // keeps the flag out of `ExecStart` and leaves the service free to find
    // the log itself. See `install::Layout::ssh_log`.
    layout.ssh_log = options.ssh_log;

    let opts = Options {
        dry_run: options.dry_run,
        force: options.force,
        start: options.start,
    };

    let mut steps = install::install_web(&layout, &opts)?;

    let prefixed = prefix != Path::new("/");

    // Settings, not unit contents. The running server re-reads these on
    // every request, so a flag in ExecStart would be a second source of
    // truth that loses to the database on the next restart.
    //
    // **Before `activate`, not after.** `activate` is `systemctl enable
    // --now`, so everything below would otherwise be racing a service that
    // is already starting and opening this same database. Three things
    // went wrong when it did: the service lost the race and crash-looped
    // on `Restart=on-failure` with "database is locked"; or this lost it
    // and the install failed having already enabled the unit; or the
    // service won, generated the password first, and the operator was
    // shown "a console password is already set" instead of the password.
    // The bind-address refusal below is the same argument in one line — it
    // declines to install a service that, in the old order, was already
    // running.
    let mut password = None;
    if !options.dry_run {
        let db = open_db(options.db.or(Some(layout.db_path.clone())))?;

        let addr = web::resolve_bind(&db, options.bind.as_deref())?;
        let exposed = options.expose || db.get_bool_setting(web::EXPOSE_KEY, false)?;
        if !web::is_loopback(&addr) && !exposed {
            anyhow::bail!(
                "refusing to install a service bound to {addr}, which is reachable \
                 from the network, without --expose. The console can rewrite this \
                 host's firewall and NGINX config."
            );
        }
        db.set_text_setting(web::BIND_KEY, &addr.to_string())?;
        if options.expose {
            db.set_bool_setting(web::EXPOSE_KEY, true)?;
        }
        if let Some(raw) = &options.base_path {
            db.set_text_setting(web::BASE_PATH_KEY, web::BasePath::parse(raw)?.as_str())?;
        }
        if let Some(hosts) = &options.allowed_hosts {
            db.set_text_setting(web::ALLOWED_HOSTS_KEY, hosts)?;
        }
        steps.push(format!(
            "bind {addr} recorded in {}",
            layout.db_path.display()
        ));

        if !web::auth::password_is_set(&db)? {
            let generated = web::auth::generate_password()?;
            web::auth::set_password(&db, &generated)?;
            password = Some(generated);
            steps.push("generated a console password".to_string());
        } else {
            steps.push("a console password is already set, keeping it".to_string());
        }

        // After the writes, and while the path is still to hand.
        install::secure_database(&layout.db_path)?;
    }

    // Only now, with the database written and closed, is it safe to start
    // the service. Under a prefix there is no systemd to tell: the unit is
    // somewhere systemd will never look, and saying so beats running
    // `daemon-reload` and implying the file took effect.
    if prefixed {
        steps.push(format!(
            "skipping systemctl: {} is not a path systemd reads",
            layout.unit_dir.display()
        ));
    } else {
        steps.extend(install::activate(&layout, &opts)?);
    }

    if options.dry_run {
        println!("Dry run — nothing was changed. Would:");
    } else {
        println!("Installed:");
    }
    for step in &steps {
        println!("  {step}");
    }
    println!();

    if let Some(password) = password {
        println!("Console password:\n");
        println!("    {password}\n");
        println!("Shown once. Only an Argon2 hash of it is stored — write it down now.");
        println!("`stop-bots web --set-password` issues a new one.\n");
    }

    if options.dry_run {
        println!("Re-run without --dry-run to do it.");
        return Ok(());
    }

    if prefixed {
        println!(
            "Written under {}. Review it, then install for real.",
            prefix.display()
        );
        return Ok(());
    }

    if options.start {
        println!("The console is on loopback. Reach it over an SSH tunnel:\n");
        println!("    ssh -L 8787:127.0.0.1:8787 <this-host>\n");
        println!("then open http://127.0.0.1:8787/.\n");
        println!(
            "To put it behind the NGINX it is protecting, see \"Behind NGINX\" in the README."
        );
    } else {
        // Telling someone to open a URL for a service that is not running
        // is how a working install gets reported as broken.
        println!("Enabled for the next boot but not started, as asked. Start it with:\n");
        println!("    systemctl start {}\n", stop_bots::install::WEB_UNIT);
        println!("then reach it over an SSH tunnel:\n");
        println!("    ssh -L 8787:127.0.0.1:8787 <this-host>");
    }
    println!();
    println!("One thing that changes now that this runs as root: the internal cron's");
    println!(
        "daily RenderFirewall job can write {}/firewall.nft,",
        layout.output_dir.display()
    );
    println!("which it could not before. Nothing applies that script — running it is");
    println!("still yours to do, or `stop-bots batch --apply` from a crontab.");

    Ok(())
}

/// Starts the web UI, after the checks that decide whether it may bind
/// where it was asked to.
#[allow(clippy::too_many_arguments)]
async fn run_web(
    db_path: Option<PathBuf>,
    root: PathBuf,
    ssh_log: Option<PathBuf>,
    firewall_out: Option<PathBuf>,
    bind: Option<String>,
    base_path: Option<String>,
    expose: bool,
    allowed_hosts: Option<String>,
    save: bool,
    set_password: bool,
    no_apply: bool,
) -> Result<()> {
    use stop_bots::web::{self, auth, server, state::AppState};

    let db = open_db(db_path)?;

    // Resolve and *check* before anything is written. `--save` used to run
    // first, which meant `--bind 0.0.0.0:8787 --expose --save
    // --set-password` persisted an exposed bind and exited before the
    // guard below ever ran — and the next plain `stop-bots web` came up on
    // every interface having never passed it.
    let addr = web::resolve_bind(&db, bind.as_deref())?;
    let exposed = expose || db.get_bool_setting(web::EXPOSE_KEY, false)?;
    let base = match &base_path {
        Some(raw) => web::BasePath::parse(raw)?,
        None => web::BasePath::from_db(&db)?,
    };

    if !web::is_loopback(&addr) && !exposed {
        anyhow::bail!(
            "refusing to bind {addr}, which is reachable from the network.\n\n\
             The web UI can rewrite this host's firewall and NGINX config, so exposing it \n\
             is a deliberate act rather than a default. If that is what you want:\n\n    \
             stop-bots web --bind {addr} --expose --allowed-hosts <your-hostname>\n\n\
             Otherwise reach it over an SSH tunnel and leave it on loopback:\n\n    \
             ssh -L 8787:127.0.0.1:8787 <this-host>"
        );
    }

    // The host allowlist is read from the database on every request, so it
    // is stored whether or not --save was given — there is nowhere else for
    // it to live. The flag's help says so.
    if let Some(hosts) = &allowed_hosts {
        db.set_text_setting(web::ALLOWED_HOSTS_KEY, hosts)?;
    }

    if save {
        db.set_text_setting(web::BIND_KEY, &addr.to_string())?;
        db.set_text_setting(web::BASE_PATH_KEY, base.as_str())?;
        if expose {
            db.set_bool_setting(web::EXPOSE_KEY, true)?;
        }
    }

    if set_password {
        let password = auth::generate_password()?;
        auth::set_password(&db, &password)?;
        println!("New password: {password}");
        println!();
        println!("Shown once. Only an Argon2 hash of it is stored.");
        return Ok(());
    }

    // Only once the server is actually going to start. Printing a
    // password and then refusing to bind reads as though the password is
    // the problem, and burns one for nothing.
    if !auth::password_is_set(&db)? {
        let password = auth::generate_password()?;
        auth::set_password(&db, &password)?;
        println!("A password has been generated for the web UI:");
        println!();
        println!("    {password}");
        println!();
        println!("Shown once. Only an Argon2 hash of it is stored — write it down now.");
        println!("`stop-bots web --set-password` issues a new one.");
        println!();
    }

    let hosts = web::configured_hosts(&db)?;
    if !web::is_loopback(&addr) && hosts.is_empty() {
        // Not fatal: an exposed console reached by bare IP is a real, if
        // unusual, deployment. Loud, because the usual reason to get here
        // is putting it behind NGINX on a hostname and then finding every
        // request refused.
        eprintln!(
            "Warning: bound to {addr} with no --allowed-hosts set. Requests carrying a \n\
             host name rather than an address will be refused. This is the DNS-rebinding \n\
             guard doing its job; list the name you will use."
        );
    }

    println!("stop-bots web UI on http://{addr}{}", base.url("/"));
    if !base.is_root() {
        println!(
            "Served under {}. The proxy in front must not strip it:",
            base.as_str()
        );
        println!("    proxy_pass http://{addr};   # no trailing slash");
    }
    if web::is_loopback(&addr) {
        println!("Loopback only — reachable from this machine.");
    } else {
        println!("Exposed on {addr}. Put TLS and this tool's own protection in front of it.");
        if !db.get_bool_setting(web::SECURE_COOKIE_KEY, false)? {
            // Not fatal: this process cannot tell whether there is TLS in
            // front of it, and refusing would break the plaintext-behind-a-
            // proxy case that is otherwise fine.
            eprintln!(
                "Note: the session cookie is not marked Secure, so a browser will also send \n\
                 it to an http:// URL for this host. Behind TLS, set `{}` to true.",
                web::SECURE_COOKIE_KEY
            );
        }
    }

    let mut state = AppState::with_base(db, root, ssh_log, !no_apply, base);
    // `None` unless the operator named a path: without one the destination
    // follows the backend, so an iptables render lands in `.sh`.
    state.firewall_out = firewall_out;
    server::serve(state, addr).await
}

fn set_nginx_commands(
    db_path: Option<PathBuf>,
    test: Option<String>,
    reload: Option<String>,
    reset: bool,
) -> Result<()> {
    use stop_bots::nginx::NginxCommands;

    let db = open_db(db_path)?;

    if reset {
        db.set_text_setting(NginxCommands::TEST_KEY, NginxCommands::DEFAULT_TEST)?;
        db.set_text_setting(NginxCommands::RELOAD_KEY, NginxCommands::DEFAULT_RELOAD)?;
    }
    for (key, value) in [
        (NginxCommands::TEST_KEY, &test),
        (NginxCommands::RELOAD_KEY, &reload),
    ] {
        let Some(value) = value else { continue };
        // Parsed before it is stored, so an unbalanced quote is rejected
        // here rather than at the next reload — which could be a cron run
        // hours later with nobody watching.
        stop_bots::nginx::split_command(value)
            .with_context(|| format!("refusing to store an unusable command for `{key}`"))?;
        db.set_text_setting(key, value)?;
    }

    let commands = NginxCommands::from_db(&db)?;
    println!("Test command:   {}", commands.test.join(" "));
    println!("Reload command: {}", commands.reload.join(" "));
    Ok(())
}

fn set_block_response(db_path: Option<PathBuf>, response: BlockResponseArg) -> Result<()> {
    let db = open_db(db_path)?;
    let response: stop_bots::db::BlockResponse = response.into();
    db.set_block_response(response)?;
    println!("Block response set to {}", response.label());
    // Nothing on disk has changed yet, and silently leaving that implicit
    // is exactly how an admin ends up believing 444 is live while every
    // site still returns 403.
    println!("Run `stop-bots apply-blocks` to write it into the site configs.");
    Ok(())
}

fn set_country_selected(db_path: Option<PathBuf>, country: String, selected: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_country_selected(&country, selected)?;
    println!(
        "{} country {country}",
        if selected { "Added" } else { "Removed" }
    );
    Ok(())
}

fn list_selected_countries(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let mode = db.get_geo_mode()?;
    let countries = db.list_selected_countries()?;
    println!("Geo mode: {mode:?}");
    if countries.is_empty() {
        println!("No countries selected.");
        return Ok(());
    }
    for country in countries {
        println!("{country}");
    }
    Ok(())
}

/// The lockout safety check `render_firewall` runs before writing anything:
/// finds recent successful SSH logins (via `--ssh-log`, or auto-detected)
/// and warns if any of them would actually end up blocked by `rules` (see
/// [`stop_bots::firewall::lockout_risks`] for what "actually end up" means).
/// Returns whether it's safe to proceed — `false` means the caller should
/// refuse to write the script unless `--force` was passed. A log source
/// that couldn't be found or read at all is not a risk in itself (nothing
/// to check against), just a note that the check didn't run.
fn check_lockout_risk(rules: &[FirewallRule], ssh_log: Option<&Path>, force: bool) -> Result<bool> {
    match stop_bots::firewall::assess_lockout_risk(rules, ssh_log) {
        stop_bots::firewall::LockoutStatus::LogUnavailable => {
            eprintln!(
                "Note: couldn't read any SSH log (tried /var/log/auth.log, /var/log/secure, journalctl) — skipping the lockout safety check. Run as root, or pass --ssh-log, for this check to work."
            );
            Ok(true)
        }
        stop_bots::firewall::LockoutStatus::Risks(risks) => {
            if risks.is_empty() {
                return Ok(true);
            }
            print_lockout_warning(&risks);
            Ok(force)
        }
    }
}

fn print_lockout_warning(risks: &[(String, String)]) {
    eprintln!(
        "WARNING: these firewall rules would block {} currently-connected SSH client IP address(es):",
        risks.len()
    );
    for (ip, cidr) in risks {
        eprintln!("  {ip} (blocked by {cidr})");
    }
    eprintln!("Applying them could lock you out of remote access to this machine.");
}

impl From<FirewallBackend> for stop_bots::firewall::FirewallBackend {
    fn from(backend: FirewallBackend) -> Self {
        match backend {
            FirewallBackend::Iptables => stop_bots::firewall::FirewallBackend::Iptables,
            FirewallBackend::Nftables => stop_bots::firewall::FirewallBackend::Nftables,
        }
    }
}

fn render_firewall(
    db_path: Option<PathBuf>,
    backend: FirewallBackend,
    out: &Path,
    force: bool,
    ssh_log: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let backend: stop_bots::firewall::FirewallBackend = backend.into();
    let built = stop_bots::firewall::build_script(&db, backend)?;

    if !check_lockout_risk(&built.rules, ssh_log.as_deref(), force)? {
        anyhow::bail!(
            "Refusing to write firewall rules: would block a currently-connected SSH client. Re-run with --force if you're sure."
        );
    }

    stop_bots::firewall::write_script(out, &built.script)?;
    println!(
        "Wrote {} rule(s) to {}. Not applied automatically — review it, then run: {} {}",
        built.written,
        out.display(),
        backend.apply_command(),
        out.display()
    );
    Ok(())
}

/// Finds scanning IPs in the SSH log and adds a temporary Block rule for
/// each — see [`stop_bots::scanblock::block_ssh_scanners`] for the shared
/// detection/insertion logic (also used by the internal cron's
/// `BlockScanners` job). This CLI wrapper only resolves the log source and
/// reconstructs the on-screen messages from the returned outcome.
fn block_scanners(
    db_path: Option<PathBuf>,
    threshold: usize,
    ttl_days: i64,
    ssh_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;

    let log_text = read_ssh_log(ssh_log.as_deref())?;

    let outcome =
        stop_bots::scanblock::block_ssh_scanners(&db, threshold, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        println!("No scanning IPs found (threshold: {threshold} failed attempt(s)).");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

/// Finds IPs whose NGINX access-log traffic looks like an automated URL
/// scanner and adds a temporary Block rule for each — see
/// [`stop_bots::scanblock::block_web_scanners`] for the shared
/// detection/exclusion/insertion logic (also used by the internal cron's
/// `BlockWebScanners` job). This CLI wrapper only resolves the log source
/// and reconstructs the on-screen messages from the returned outcome.
fn block_web_scanners(
    db_path: Option<PathBuf>,
    threshold: usize,
    ttl_days: i64,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;

    let log_text = read_access_log(access_log.as_deref())?;

    let outcome =
        stop_bots::scanblock::block_web_scanners(&db, threshold, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        println!("No scanning IPs found (threshold: {threshold} distinct 404'd path(s)).");
        return Ok(());
    }
    if !outcome.crawler_exclusion_active {
        println!(
            "Warning: no crawler IP ranges fetched yet (run update-ip-ranges --source-id \
             googlebot/bingbot/gptbot first) — known-crawler exclusion is inactive, so a \
             legitimate search crawler chasing stale links could be flagged below."
        );
    }
    if outcome.skipped_known_crawlers > 0 {
        println!(
            "Skipped {} IP(s) matching known crawler ranges (Googlebot/Bingbot/GPTBot) — never \
             auto-blocked here, even when their 404 behavior looks scan-like.",
            outcome.skipped_known_crawlers
        );
    }
    if outcome.newly_blocked.is_empty() && outcome.already_covered == 0 {
        println!("No scanning IPs left to block after excluding known crawlers.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn block_spoofed_crawlers(
    db_path: Option<PathBuf>,
    ttl_days: i64,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;

    let log_text = read_access_log(access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_spoofed_crawlers(&db, ttl_days, &log_text, dry_run)?;

    // Distinct from "found nothing": with no ranges stored there was
    // nothing to check against, so a clean result here means the detector
    // never ran, not that the log is clean.
    if !outcome.crawler_exclusion_active {
        println!(
            "No crawler IP ranges fetched yet — run `stop-bots update-ip-ranges --source-id \
             googlebot` (and bingbot/gptbot) first. Nothing was checked."
        );
        return Ok(());
    }
    if outcome.candidates == 0 {
        println!("No forged crawler user agents found.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn block_probe_paths(
    db_path: Option<PathBuf>,
    ttl_days: i64,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;

    let log_text = read_access_log(access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_probe_paths(&db, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        println!("No probe-path requests found.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn set_probe_paths(db_path: Option<PathBuf>, paths: String) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_text_setting(stop_bots::protection::PROBE_PATHS_EXTRA, &paths)?;
    let accepted = stop_bots::protection::extra_probe_paths(&db)?;
    println!("Extra probe paths set ({} accepted).", accepted.len());
    // Report what was dropped rather than silently ignoring it: an entry
    // that doesn't start with `/` can never match, and finding that out
    // from a detector that quietly never fires is much worse.
    let offered = paths
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    if offered > accepted.len() {
        println!(
            "Ignored {} entr(y/ies) that don't start with '/' — matching is anchored at the \
             start of the request path.",
            offered - accepted.len()
        );
    }
    Ok(())
}

fn list_probe_paths(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let extra = stop_bots::protection::extra_probe_paths(&db)?;
    println!("Built-in (always checked):");
    for path in stop_bots::accesslog::DEFAULT_PROBE_PATHS {
        println!("  {path}");
    }
    if extra.is_empty() {
        println!("Extra: none (set with set-probe-paths)");
    } else {
        println!("Extra:");
        for path in &extra {
            println!("  {path}");
        }
    }
    Ok(())
}

fn block_honeypot(
    db_path: Option<PathBuf>,
    ttl_days: i64,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;

    let log_text = read_access_log(access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_honeypot(&db, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        println!(
            "Nothing fetched the honeypot path ({}).",
            stop_bots::protection::honeypot_path(&db)?
        );
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn set_honeypot_path(db_path: Option<PathBuf>, path: String) -> Result<()> {
    let db = open_db(db_path)?;
    let trimmed = path.trim();
    // Rejected loudly rather than stored and silently ignored: matching is
    // anchored at the start of the request path, so a path without a
    // leading slash could never fire, leaving an apparently-enabled
    // detector that does nothing.
    if !trimmed.starts_with('/') {
        anyhow::bail!("the honeypot path must start with '/' (got {trimmed:?})");
    }
    db.set_text_setting(stop_bots::protection::HONEYPOT_PATH, trimmed)?;
    println!("Honeypot path set to {trimmed}");
    println!(
        "It only catches anything once it's published — enable robots.txt generation, or add a \
         Disallow line for it yourself."
    );
    Ok(())
}

/// Reads the NGINX access log for a detector subcommand: `--access-log` if
/// given, the conventional path otherwise.
///
/// Every access-log detector needs exactly this, including the same failure
/// message — the two likely causes are a non-standard path and not being
/// root, and naming both is what turns "couldn't read the log" from a dead
/// end into something actionable. Shared so a sixth detector can't quietly
/// ship a seventh wording of it.
fn read_access_log(access_log: Option<&Path>) -> Result<String> {
    let source = match access_log {
        Some(path) => accesslog::read_log_file(path),
        None => accesslog::find_default_source(),
    };
    match source {
        accesslog::LogSource::Found(text) => Ok(text),
        // Same distinction as `read_ssh_log`: name the path that was
        // actually tried, not the one the reader might assume.
        accesslog::LogSource::Unavailable => match access_log {
            Some(path) => anyhow::bail!(
                "couldn't read the NGINX access log at {} — pass a different --access-log, \
                 or run as root, for this to work",
                path.display()
            ),
            None => anyhow::bail!(
                "couldn't read the NGINX access log (tried /var/log/nginx/access.log) — pass \
                 --access-log, or run as root, for this to work"
            ),
        },
    }
}

/// The SSH-log counterpart of [`read_access_log`]. Separate rather than
/// generic over the two `LogSource` types: they are distinct enums with
/// distinct fallback chains, and the error text has to name the right
/// paths and the right flag to be worth printing at all.
fn read_ssh_log(ssh_log: Option<&Path>) -> Result<String> {
    let source = match ssh_log {
        Some(path) => sshlog::read_log_file(path),
        None => sshlog::find_default_source(),
    };
    match source {
        sshlog::LogSource::Found(text) => Ok(text),
        // Two different failures, and saying the wrong one costs real time.
        // An explicit path is read and nothing else is tried, so claiming a
        // search happened sends the reader looking for a bug in the
        // fallback chain instead of at the path they passed — which is
        // exactly how a service pinned to a missing auth.log stayed
        // invisible on a journald-only host.
        sshlog::LogSource::Unavailable => match ssh_log {
            Some(path) => anyhow::bail!(
                "couldn't read the SSH log at {} — that path was given explicitly, so \
                 /var/log/secure and journalctl were not tried. Drop --ssh-log to search \
                 all three, point it somewhere readable, or run as root.",
                path.display()
            ),
            None => anyhow::bail!(
                "couldn't read any SSH log (tried /var/log/auth.log, /var/log/secure, \
                 journalctl) — pass --ssh-log, or run as root, for this to work"
            ),
        },
    }
}

/// Prints the per-IP and summary lines shared by [`block_scanners`] and
/// [`block_web_scanners`], reconstructing the wording each used to print
/// directly (back when the detection/insertion logic itself lived here)
/// from the [`stop_bots::scanblock::ScanBlockOutcome`] it now gets handed.
fn print_scan_block_outcome(outcome: &stop_bots::scanblock::ScanBlockOutcome) {
    for ip in &outcome.newly_blocked {
        if outcome.dry_run {
            println!("Would block {ip} for {} day(s) (dry run)", outcome.ttl_days);
        } else {
            println!(
                "Added block rule for {ip}, expiring in {} day(s)",
                outcome.ttl_days
            );
        }
    }
    if outcome.newly_blocked.is_empty() {
        println!(
            "Found {} {}(s), all already covered by an existing firewall rule.",
            outcome.already_covered,
            outcome.kind.noun()
        );
    } else if outcome.dry_run {
        println!(
            "Would add {} new block rule(s), each expiring after {} day(s). Re-run without \
             --dry-run to apply.",
            outcome.newly_blocked.len(),
            outcome.ttl_days
        );
    } else {
        println!(
            "Added {} new block rule(s), each expiring after {} day(s). Not applied \
             automatically — run render-firewall, then apply the generated script, to actually \
             enforce them (and again after they expire, to actually lift the block).",
            outcome.newly_blocked.len(),
            outcome.ttl_days
        );
    }
}

/// Reads the NGINX access log and records successful-request user-agent
/// counts — see [`stop_bots::accessstats::record_access_stats`] for the
/// shared detection/persistence logic (also used by the internal cron's
/// `RecordAccessStats` job). This CLI wrapper only resolves the log source
/// and prints the returned outcome's summary.
fn record_access_stats(db_path: Option<PathBuf>, access_log: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;

    let log_path = access_log
        .clone()
        .unwrap_or_else(|| PathBuf::from(accesslog::DEFAULT_LOG_PATH));
    let log_text = read_access_log(access_log.as_deref())?;

    let outcome =
        stop_bots::accessstats::record_access_stats(&db, &log_path.to_string_lossy(), &log_text)?;
    println!("{}", outcome.summary());
    Ok(())
}

/// Lists every recorded user agent's accumulated hit count, most-seen
/// first (see [`stop_bots::db::Db::list_user_agent_stats`]).
fn list_access_stats(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let stats = db.list_user_agent_stats()?;
    if stats.is_empty() {
        println!("No user-agent stats recorded yet — run record-access-stats first.");
        return Ok(());
    }
    for stat in stats {
        println!("{:>8}  {}", stat.hit_count, stat.user_agent);
    }
    Ok(())
}

/// Runs the maintenance the internal cron runs daily, right now, and
/// prints what it did.
///
/// Prints the before/after sizes rather than only the summary line the
/// Dashboard shows: someone reaching for this has just looked at `du` and
/// wants the same number to have moved.
fn maintain(db_path: Option<PathBuf>, force_compact: bool) -> Result<()> {
    let db = open_db(db_path)?;

    let before = db.size_on_disk()?;
    if let Some(size) = before {
        println!(
            "Database is {} ({} reclaimable).",
            stop_bots::health::human_bytes(size.bytes),
            stop_bots::health::human_bytes(size.free_bytes)
        );
    }

    let summary = stop_bots::cron::maintenance(&db);
    println!("{summary}");

    // `cron::maintenance` compacts only when the slack is worth the
    // rewrite. `--force-compact` is for the case its thresholds are wrong
    // for this host — most usefully right after an upgrade that freed a
    // lot at once, where waiting for the next scheduled run would leave
    // the file at its old size for a day.
    if force_compact {
        let reclaimed = db.vacuum()?;
        println!(
            "Compacted anyway: reclaimed {}.",
            stop_bots::health::human_bytes(reclaimed)
        );
    }

    if let (Some(before), Ok(Some(after))) = (before, db.size_on_disk()) {
        if after.bytes < before.bytes {
            println!(
                "Now {} — down from {}.",
                stop_bots::health::human_bytes(after.bytes),
                stop_bots::health::human_bytes(before.bytes)
            );
        }
    }
    // Recording the run last means an interrupted maintenance leaves the
    // job due rather than looking done.
    stop_bots::cron::record_run(&db, stop_bots::cron::CronJob::Maintenance, &summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_user_db_path_prefers_xdg_data_home() {
        let path = resolve_user_db_path(Some("/custom/data".into()), Some("/home/someone".into()))
            .unwrap();
        assert_eq!(path, PathBuf::from("/custom/data/stop-bots/db.sqlite3"));
    }

    #[test]
    fn resolve_user_db_path_falls_back_to_home_local_share() {
        let path = resolve_user_db_path(None, Some("/home/someone".into())).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/someone/.local/share/stop-bots/db.sqlite3")
        );
    }

    #[test]
    fn resolve_user_db_path_errors_without_any_signal() {
        assert!(resolve_user_db_path(None, None).is_err());
    }

    #[test]
    fn open_db_with_an_explicit_path_opens_it_directly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("explicit.sqlite3");
        assert!(open_db(Some(path.clone())).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn open_or_fallback_uses_fallback_when_primary_directory_cannot_be_created() {
        // A regular file masquerading as a directory component: `mkdir -p`
        // through it must fail for any user, including root, so this is a
        // root-safe way to force the "can't create the directory" path
        // without needing real permission denial.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let primary = blocker.join("db.sqlite3");

        let fallback_dir = tempfile::tempdir().unwrap();
        let fallback = fallback_dir.path().join("fallback.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(fallback.exists());
        assert!(!primary.exists());
    }

    #[test]
    fn open_or_fallback_uses_primary_when_it_works() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");
        let fallback = tmp.path().join("should-not-be-used.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(primary.exists());
        assert!(!fallback.exists());
    }

    #[test]
    fn open_or_fallback_never_resolves_fallback_when_primary_works() {
        // Regression guard: resolving the fallback path can itself fail
        // (e.g. neither XDG_DATA_HOME nor HOME is set, plausible in a
        // minimal-env root container). That must never get in the way of
        // the common case where the primary path just works.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");

        let result = open_or_fallback(&primary, || {
            anyhow::bail!("fallback should never be resolved here")
        });

        assert!(result.is_ok());
        assert!(primary.exists());
    }

    #[test]
    fn format_expiry_rounds_to_whole_days_once_at_least_one_has_passed() {
        let expires_at = now_secs() + 3 * 86_400 + 100;
        assert_eq!(format_expiry(expires_at), "expires in 3d");
    }

    #[test]
    fn format_expiry_rounds_to_whole_hours_under_a_day() {
        let expires_at = now_secs() + 5 * 3_600;
        assert_eq!(format_expiry(expires_at), "expires in 5h");
    }

    #[test]
    fn format_expiry_floors_at_one_hour_for_an_imminent_expiry() {
        let expires_at = now_secs() + 30;
        assert_eq!(format_expiry(expires_at), "expires in 1h");
    }

    fn rule(address: &str, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: 0,
            address: address.to_string(),
            port: None,
            action,
            enabled: true,
            expires_at: None,
        }
    }

    #[test]
    fn check_lockout_risk_blocks_without_force_and_passes_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 4.5.6.7 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(!check_lockout_risk(&rules, Some(&log_path), false).unwrap());
        assert!(check_lockout_risk(&rules, Some(&log_path), true).unwrap());
    }

    #[test]
    fn check_lockout_risk_passes_when_the_log_has_no_matching_login() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("auth.log");
        std::fs::write(
            &log_path,
            "Accepted publickey for admin from 9.9.9.9 port 12345 ssh2\n",
        )
        .unwrap();

        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(check_lockout_risk(&rules, Some(&log_path), false).unwrap());
    }

    #[test]
    fn check_lockout_risk_passes_when_the_log_source_is_unavailable() {
        let rules = vec![rule("4.5.6.0/24", FirewallAction::Block)];
        assert!(check_lockout_risk(&rules, Some(Path::new("/nonexistent/x.log")), false).unwrap());
    }

    #[test]
    fn render_firewall_rejects_allowlist_mode_on_iptables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            db.set_geo_mode(stop_bots::db::GeoMode::Allowlist).unwrap();
        }
        let out = tmp.path().join("fw.sh");

        let result = render_firewall(Some(db_path), FirewallBackend::Iptables, &out, false, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nftables"));
        assert!(!out.exists());
    }

    fn not_found_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 1 \"-\" \"Googlebot\"\n"
        )
    }

    /// The property the crawler exclusion exists for: an IP inside a known
    /// crawler's published ranges must never be auto-blocked by
    /// `block_web_scanners`, even when its 404 behavior clears the
    /// scanning threshold — a real Googlebot routinely chases enough stale
    /// links to do exactly that.
    #[test]
    fn block_web_scanners_never_blocks_an_ip_inside_a_known_crawler_range() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            ipranges::store(
                &db,
                ipranges::IpRangeSourceKind::GoogleBot,
                &["198.51.100.0/24".to_string()],
            )
            .unwrap();
        }

        let log_path = tmp.path().join("access.log");
        let log: String = (0..20)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        std::fs::write(&log_path, log).unwrap();

        block_web_scanners(Some(db_path.clone()), 15, 1, Some(log_path), false).unwrap();

        let db = Db::open(&db_path).unwrap();
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// The flip side: an IP that scans just as aggressively but *isn't*
    /// inside any known crawler range must still get blocked.
    #[test]
    fn block_web_scanners_still_blocks_a_scanner_outside_known_crawler_ranges() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            ipranges::store(
                &db,
                ipranges::IpRangeSourceKind::GoogleBot,
                &["198.51.100.0/24".to_string()],
            )
            .unwrap();
        }

        let log_path = tmp.path().join("access.log");
        let log: String = (0..20)
            .map(|i| not_found_line("203.0.113.9", &format!("/missing-{i}")))
            .collect();
        std::fs::write(&log_path, log).unwrap();

        block_web_scanners(Some(db_path.clone()), 15, 1, Some(log_path), false).unwrap();

        let db = Db::open(&db_path).unwrap();
        assert_eq!(
            db.list_firewall_rules().unwrap()[0].address,
            "203.0.113.9".to_string()
        );
    }

    /// The dup-row hazard a naive "list then filter expired" design would
    /// hit: re-running `block_scanners` against an IP whose earlier block
    /// already expired must produce exactly one row for that address, not
    /// two (one stale-but-undeleted, one freshly inserted). Proven here by
    /// calling `block_scanners` twice against the same still-scanning IP —
    /// first with a negative TTL (an instantly-expired "earlier" block),
    /// then with a normal positive one.
    #[test]
    fn block_scanners_re_blocks_cleanly_after_a_rule_expires() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");

        let log_path = tmp.path().join("auth.log");
        let log: String = "Failed password for root from 198.51.100.9 port 4444 ssh2\n".repeat(25);
        std::fs::write(&log_path, &log).unwrap();

        block_scanners(Some(db_path.clone()), 20, -1, Some(log_path.clone()), false).unwrap();
        {
            // The rule from the first (instantly-expired) call must
            // already be gone before the second call ever runs, exactly
            // as `list_firewall_rules`'s pruning intends.
            let db = Db::open(&db_path).unwrap();
            assert!(db.list_firewall_rules().unwrap().is_empty());
        }

        block_scanners(Some(db_path.clone()), 20, 5, Some(log_path), false).unwrap();

        let db = Db::open(&db_path).unwrap();
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "198.51.100.9");
        assert!(rules[0].expires_at.is_some());

        // Guards against a regression to "filter expired rows on read"
        // instead of actually deleting them: under a filter-only
        // implementation every assertion above would still pass (the
        // dead first-call row would just be hidden, not gone), but the
        // raw table would hold two physical rows for this address instead
        // of one.
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let raw_count: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM firewall_rules WHERE address = '198.51.100.9'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 1);
    }

    fn ok_line(ip: &str, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn record_access_stats_persists_counts_from_the_default_log_path_override() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        let log_path = tmp.path().join("access.log");
        let mut log = String::new();
        log.push_str(&ok_line("203.0.113.5", "Mozilla/5.0"));
        log.push_str(&ok_line("203.0.113.6", "Mozilla/5.0"));
        std::fs::write(&log_path, log).unwrap();

        record_access_stats(Some(db_path.clone()), Some(log_path)).unwrap();

        let db = Db::open(&db_path).unwrap();
        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].user_agent, "Mozilla/5.0");
        assert_eq!(stats[0].hit_count, 2);
    }

    #[test]
    fn list_access_stats_succeeds_on_an_empty_database() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        Db::open(&db_path).unwrap();

        list_access_stats(Some(db_path)).unwrap();
    }
}
