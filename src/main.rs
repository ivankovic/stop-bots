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

/// Help text shared by every subcommand's `--db` flag.
const DB_HELP: &str = "Database path (defaults to /var/lib/stop-bots/db.sqlite3, falling back to a per-user location if that's not writable)";

#[derive(Parser)]
#[command(name = "stop-bots", about = "Configure your server to stop bad bots")]
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
        #[arg(long, default_value_t = 20)]
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
        #[arg(long, default_value_t = 7)]
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
    /// Sets the honeypot trap path. Must start with `/`. Pick something
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
    /// Download and store the current CIDR list for one published crawler
    /// IP-range source (Googlebot, Bingbot or GPTBot)
    UpdateIpRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Which source to update: googlebot, bingbot or gptbot
        #[arg(long)]
        source_id: String,
    },
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
    },
    /// Switches a third-party CIDR feed on or off. While on, every CIDR it
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
    /// Lists every third-party CIDR feed with its on/off state and how many
    /// ranges it currently holds
    ListReputationSources {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Download and store IPdeny's current aggregated CIDR list for one
    /// country (does not select it — see AddCountry)
    UpdateCountryRanges {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// Sets the host-wide geo mode: "blocklist" (selected countries are
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
    /// Sets the price and contact advertised in a `402 Payment Required`
    /// response. Only used when the block response is `payment-required`.
    ///
    /// Both are free text — a line a human operating a crawler can read
    /// and act on. There is no interoperable machine-readable format a
    /// generated NGINX config could emit here: the emerging ones (x402's
    /// JSON challenge, pay-per-crawl's signed headers) need a payment
    /// endpoint and a settlement path, which this tool does not own.
    /// Neither value may contain a double quote or end in a backslash —
    /// both would corrupt the generated config.
    ///
    /// Pass empty strings to clear.
    SetPaymentTerms {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        /// e.g. "USD 0.01 per request" or "EUR 500/month"
        #[arg(long, default_value = "")]
        price: String,
        /// A URL or email address where access can be arranged
        #[arg(long, default_value = "")]
        contact: String,
    },
    /// Prints the 402 body that would currently be sent, without writing
    /// anything
    ShowPaymentTerms {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
    },
    /// Turns generation of a `robots.txt` on or off. When on, ApplyBlocks
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
    /// Sets what NGINX does with a request the blocking rules caught.
    ///
    /// These are not interchangeable status codes; each says something
    /// different, and the difference matters most for clients caught by
    /// mistake. "forbidden" (403, the default) is the only one that tells
    /// a wrongly-caught human what happened. "not-found" (404) hides that
    /// anything was blocked. "gone" (410) is the one that asks a
    /// well-behaved crawler to drop the URL permanently — prefer it over
    /// 403 when you're turning away crawlers rather than attackers.
    /// "too-many-requests" (429) tells a polite client to retry later.
    /// "payment-required" (402) is what pay-per-crawl schemes have settled
    /// on, which makes it the most pointed answer available to an AI
    /// crawler. "teapot" (418) is RFC 2324's joke — it works, but it is
    /// not IANA-registered and NGINX sends it with an empty body.
    /// "close" (444) sends nothing at all, which is cheapest but
    /// indistinguishable from the server being down. "tarpit" answers 403
    /// but throttles the body to a byte per second, holding the client's
    /// connection open — and one of yours.
    ///
    /// Host-wide, and only changes what *would* be written: run ApplyBlocks
    /// afterwards to get the new response code into the site configs. Until
    /// then Site settings shows every applied site as STALE.
    SetBlockResponse {
        #[arg(long, help = DB_HELP)]
        db: Option<PathBuf>,
        #[arg(long)]
        response: BlockResponseArg,
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
    /// 402 — what pay-per-crawl schemes use; pointed at AI crawlers
    PaymentRequired,
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
            BlockResponseArg::PaymentRequired => R::PaymentRequired,
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
        Some(Command::UpdateIpRanges { db, source_id }) => update_ip_ranges(db, source_id).await,
        Some(Command::UpdateReputationSource { db, source_id }) => {
            update_reputation_source(db, source_id).await
        }
        Some(Command::SetReputationSource {
            db,
            source_id,
            enabled,
        }) => set_reputation_source(db, source_id, enabled),
        Some(Command::ListReputationSources { db }) => list_reputation_sources(db),
        Some(Command::UpdateCountryRanges { db, country }) => {
            update_country_ranges(db, country).await
        }
        Some(Command::SetGeoMode { db, mode }) => set_geo_mode(db, mode),
        Some(Command::AddCountry { db, country }) => set_country_selected(db, country, true),
        Some(Command::RemoveCountry { db, country }) => set_country_selected(db, country, false),
        Some(Command::ListSelectedCountries { db }) => list_selected_countries(db),
        Some(Command::SetBlockResponse { db, response }) => set_block_response(db, response),
        Some(Command::SetRateLimit {
            db,
            enabled,
            rps,
            burst,
        }) => set_rate_limit(db, enabled, rps, burst),
        Some(Command::SetPaymentTerms { db, price, contact }) => {
            set_payment_terms(db, price, contact)
        }
        Some(Command::ShowPaymentTerms { db }) => show_payment_terms(db),
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

async fn run_tui(
    db_path: Option<PathBuf>,
    root: PathBuf,
    no_reload: bool,
    ssh_log: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let app = stop_bots::app::App::new(db, root, !no_reload, ssh_log)?;
    let terminal = ratatui::init();
    let result = app.run(terminal).await;
    ratatui::restore();
    result
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
    // Written before any config is touched, so the file the generated
    // `alias` points at already exists by the time NGINX reloads.
    nginx::write_managed_files(&db)?;
    let default_config = nginx::default_block_config(&db)?;
    // Sites already known to the db (i.e. previously scanned) — the only
    // ones that can carry a per-site override at all.
    let known_sites = db.list_sites()?;
    let sites = nginx::discover_sites(root)?;

    // A single config file commonly holds multiple `server` blocks for the
    // same site (e.g. an HTTP redirect block plus the HTTPS one), so dedupe
    // by file and apply once per file rather than once per discovered site.
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();

    let mut changed = 0;
    for path in &config_paths {
        // Built fresh per file, filtered to sites that actually live in
        // *this* file: `server_name` alone isn't unique across the whole
        // `sites` table (two different files can share one, e.g. a stale
        // config left behind after a rename), so a single map built once
        // for the whole run could leak one site's override onto another's
        // same-named block in a different file. Note this join is a
        // textual `config_path` match, only valid when `--root` here
        // matches whatever `--root` was used at scan time — a mismatch
        // just falls through to `default_config` below, not an error.
        let site_configs: Vec<(String, nginx::BlockConfig)> = known_sites
            .iter()
            .filter(|s| Path::new(&s.config_path) == path.as_path())
            .map(|s| {
                Ok((
                    s.server_name.clone(),
                    nginx::block_config_for_site(&db, s.id)?,
                ))
            })
            .collect::<Result<_>>()?;
        if nginx::apply_blocks_to_file(path, &site_configs, &default_config)? {
            changed += 1;
        }
    }
    println!(
        "Applied blocking rules to {} site(s) across {} file(s), {} file(s) changed",
        sites.len(),
        config_paths.len(),
        changed
    );

    // Only now that every config has been rewritten is it safe to delete a
    // generated file the new config no longer references — see
    // `nginx::remove_unused_managed_files` for why the order is
    // load-bearing rather than tidy.
    nginx::remove_unused_managed_files(&db)?;

    // Writing the sentinel block does nothing until NGINX re-reads it — no
    // point reloading when nothing actually changed on disk.
    if changed > 0 && !no_reload {
        nginx::reload().context("nginx config was applied, but reload failed")?;
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

async fn update_ip_ranges(db_path: Option<PathBuf>, source_id: String) -> Result<()> {
    let db = open_db(db_path)?;
    let kind = ipranges::IpRangeSourceKind::from_id(&source_id)
        .with_context(|| format!("unknown ip-range source id: {source_id}"))?;
    let count = ipranges::update(&db, kind).await?;
    println!("Stored {count} CIDR range(s) from {}", kind.name());
    Ok(())
}

async fn update_country_ranges(db_path: Option<PathBuf>, country: String) -> Result<()> {
    let db = open_db(db_path)?;
    let count = ipranges::update_country(&db, &country).await?;
    println!("Stored {count} CIDR range(s) for country {country}");
    Ok(())
}

fn set_geo_mode(db_path: Option<PathBuf>, mode: GeoModeArg) -> Result<()> {
    let db = open_db(db_path)?;
    let mode: stop_bots::db::GeoMode = mode.into();
    db.set_geo_mode(mode)?;
    println!("Geo mode set to {mode:?}");
    Ok(())
}

async fn update_reputation_source(db_path: Option<PathBuf>, source_id: String) -> Result<()> {
    use stop_bots::ipranges::reputation::{self, ReputationSourceKind};

    let db = open_db(db_path)?;
    let Some(kind) = ReputationSourceKind::from_id(&source_id) else {
        let known: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
        anyhow::bail!("unknown source: {source_id} (known: {})", known.join(", "));
    };
    let count = reputation::update(&db, kind).await?;
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

fn set_payment_terms(db_path: Option<PathBuf>, price: String, contact: String) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_payment_terms(&price, &contact)?;
    if price.trim().is_empty() && contact.trim().is_empty() {
        println!("Payment terms cleared.");
        return Ok(());
    }
    println!("Payment terms set.");
    // Said explicitly, because the terms are stored regardless and it
    // would otherwise look as though nothing happened.
    if db.get_block_response()? != stop_bots::db::BlockResponse::PaymentRequired {
        println!(
            "Note: the block response is currently {}, so these terms aren't sent. Run \
             `stop-bots set-block-response --response payment-required` to use them.",
            db.get_block_response()?.label()
        );
    }
    println!("Run `stop-bots apply-blocks` to write it into the site configs.");
    Ok(())
}

fn show_payment_terms(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let body = nginx::payment_body(&db)?;
    if body.is_empty() {
        println!(
            "No 402 body would be sent (needs the payment-required response and at least one \
             of --price / --contact)."
        );
        return Ok(());
    }
    // Stored with literal `\n` escapes, because that is what goes into the
    // NGINX config; unescape them so this prints as the client sees it.
    print!("{}", body.replace("\\n", "\n"));
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
        accesslog::LogSource::Unavailable => anyhow::bail!(
            "couldn't read the NGINX access log (tried /var/log/nginx/access.log) — pass \
             --access-log, or run as root, for this to work"
        ),
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
        sshlog::LogSource::Unavailable => anyhow::bail!(
            "couldn't read any SSH log (tried /var/log/auth.log, /var/log/secure, journalctl) — \
             pass --ssh-log, or run as root, for this to work"
        ),
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
