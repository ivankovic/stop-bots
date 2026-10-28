/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The command line: every verb, its flags and their help text, as clap
//! parses them. What each verb does is in `main.rs`; this is only what it
//! is called and what it takes, which is a third of that file and the
//! part a reader looking for a flag wants on its own.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use stop_bots::blocks::SourceFilter;
use stop_bots::db::RuleSource;
use stop_bots::webserver;

/// Rejects `--threshold 0` at the command line.
///
/// Every detector compares `count >= threshold`, so zero matches every
/// address in the log regardless of what it did — one flag away from
/// "block every visitor", in a tool whose whole safety story is never
/// blocking someone by mistake. One is a defensible policy (fail2ban's
/// `maxretry` goes that low); zero is not a policy, it is a mistake, and
/// an error beats silently treating it as one.
pub(crate) fn min_threshold(raw: &str) -> Result<usize, String> {
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

/// Parses a detector subcommand's `--ttl-days`, refusing anything past
/// `MAX_TTL_DAYS` either way. Past the ceiling, the arithmetic that dates
/// the block wraps.
///
/// Only the magnitude is bounded, unlike the TUI, which refuses anything
/// under a day: a zero or negative TTL here writes a block
/// that is born expired, which the CLI tests use to prove expiry end to
/// end, and an operator typing one has asked for exactly that.
pub(crate) fn ttl_days_arg(raw: &str) -> Result<i64, String> {
    let max = stop_bots::protection::MAX_TTL_DAYS;
    match raw.parse::<i64>() {
        Ok(days) if (-max..=max).contains(&days) => Ok(days),
        _ => Err(format!(
            "a block lasts a whole number of days, at most {max}"
        )),
    }
}

/// Help text for the global `--db` flag.
pub(crate) const DB_HELP: &str =
    "Database path. Defaults to $STOP_BOTS_DB, then /var/lib/stop-bots/db.sqlite3, \
falling back to a per-user location if that is not writable";

/// Help text shared by every `--root` flag.
pub(crate) const ROOT_HELP: &str = "The web server's config root. Defaults to the one stored by \
`set-web-server --root`, else /etc/nginx, /etc/apache2 for Apache, /etc/traefik/dynamic for \
Traefik's file provider, or /opt/npmplus for NPMplus's data directory";

/// Help text shared by every detector subcommand's `--access-log`.
pub(crate) const ACCESS_LOG_HELP: &str = "Read only this access log. Without it, the stored one \
(`set-log-paths`) is read, else /var/log/nginx/access.log, for Apache \
/var/log/apache2/access.log (/var/log/httpd/access_log in RHEL's /etc/httpd), for Traefik \
/var/log/traefik/access.log, or for NPMplus /opt/npmplus/nginx/logs/access.log, and with it \
every other access log the web server's config names";

/// Help text shared by `status --json` and every `list-* --json`.
pub(crate) const JSON_HELP: &str =
    "Print one JSON object instead of text. Its field names are part of \
the stable contract from 1.0: fields may be added, never renamed or removed";

/// Help text shared by every detector subcommand's `--dry-run`.
pub(crate) const DRY_RUN_HELP: &str = "Show what would be blocked without storing anything";

/// Help text shared by every apply's `--no-confirm`.
pub(crate) const NO_CONFIRM_HELP: &str =
    "Apply without asking to keep the new firewall rules. On a \
terminal, an apply otherwise arms a revert first and asks \"Keep these firewall rules?\"; \
no answer within --confirm-timeout puts the previous rules back. Without a terminal on stdin \
(cron, scripts) nothing is asked and nothing is armed, flag or not";

/// Help text shared by every `--confirm-timeout`.
pub(crate) const CONFIRM_TIMEOUT_HELP: &str =
    "Seconds to answer \"Keep these firewall rules?\" before the previous rules are put back";

/// Help text shared by every detector subcommand's `--ttl-days`.
pub(crate) const TTL_HELP: &str =
    "How many days a block lasts. Defaults to this detector's stored TTL \
(`set-detector`)";

/// Printed under the list of commands by `-h` and `--help`. The list is
/// long and flat — clap 4 has one heading for every subcommand — so this
/// is the order to read it in, for someone who has just installed it.
pub(crate) const GETTING_STARTED: &str = "\
Getting started:
  sudo stop-bots set-web-server apache    Only on an Apache (or a Traefik) host; NGINX is the default
  sudo stop-bots batch --dry-run --diff   Show what a full pass would change, change nothing
  sudo stop-bots batch --apply            Fetch the lists, scan the logs, apply both
  sudo stop-bots install firewall         Load the applied firewall script at boot
  sudo stop-bots install cron             Run the detectors and list updates every minute
  sudo stop-bots uninstall all --dry-run  Show every step that puts the host back

`sudo stop-bots` with no command starts the TUI. `stop-bots <command> --help` says
more about one command.";

#[derive(Parser)]
// `version` is not decoration: this ships as a tagged GitHub release
// binary, so "is the thing on the server the thing I built?" is a
// question someone will actually have to answer.
#[command(
    name = "stop-bots",
    version,
    about = "Configure your server to stop bad bots, in NGINX, Apache, Traefik or NPMplus and the firewall",
    after_help = GETTING_STARTED
)]
pub(crate) struct Cli {
    // Global, so it works before or after the subcommand, and read from
    // `STOP_BOTS_DB` when not given. Every subcommand used to declare its
    // own copy; `stop-bots scan-sites --db x` still parses the same way,
    // because a global flag is accepted after the subcommand too. A `//`
    // comment rather than `///`, which clap would print as long help.
    #[arg(long, global = true, env = "STOP_BOTS_DB", value_name = "PATH", help = DB_HELP)]
    pub(crate) db: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

// Conventions for everything below — written down in CONTRIBUTING.md
// under "CLI conventions", and checked by the tests at the bottom of
// `main.rs`:
//
// - A stored on/off setting takes an explicit value, `--enabled
//   true|false`, so both directions can be said. A presence flag is only
//   for how *this run* behaves (`--force`, `--dry-run`, `--no-fetch`).
// - A stored setting is changed by a `set-*` verb. Flags on a verb that
//   runs something (`batch`, `render-firewall`, `run-detector`) apply to
//   that run and are never written back.
// - A list of things has `add-*`, `remove-*` and `list-*` verbs, and an
//   `update-*` verb downloads every source of its kind unless one is named.
// - Help text names commands the way a user types them (`apply-blocks`),
//   never the Rust variant (`ApplyBlocks`) or a table or module name.
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Discover the web server's sites under a config root and store them in the database
    #[command(alias = "scan")]
    ScanSites {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
    },
    /// Download and store the known-bot lists: every source, or one.
    #[command(alias = "update")]
    UpdateBotLists {
        /// Only this source: well-known-bots, ai-robots-txt, nginx-bad-bots
        /// or stop-bots-extras. Every one without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the bot list from a local file instead of downloading it,
        /// parsed as --source-id's format (well-known-bots' when none is
        /// given, as before every source was updated by default)
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Apply the current blocking policy to every discovered site
    ApplyBlocks {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Skip reloading the web server after writing config changes (e.g. for
        /// tests, or to review the written config before it goes live).
        /// Applying is a no-op without a reload, so real usage wants this
        /// left on.
        #[arg(long)]
        no_reload: bool,
        /// Print which files would change, and change nothing but storing
        /// the bot list built into this binary
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run, also print a unified diff of every file that
        /// would change
        #[arg(long, requires = "dry_run")]
        diff: bool,
    },
    /// Add a firewall rule blocking (or allowing) an IP address or CIDR range
    AddFirewallRule {
        /// IP address or CIDR range, e.g. 1.2.3.4 or 5.6.7.0/24
        #[arg(long)]
        address: String,
        /// Restrict the rule to a single TCP port
        #[arg(long)]
        port: Option<u16>,
        /// `block` or `allow`
        #[arg(long, default_value = "block")]
        action: String,
    },
    /// Never block an address or a user agent, whatever else matches it.
    ///
    /// A trusted address (an IP or a CIDR range) becomes an allow rule
    /// ahead of every other firewall rule — a detector's block, a
    /// reputation feed, a country, the allow-list catch-all — clears every
    /// web server block and rate limit, and is skipped by the detectors.
    ///
    /// A trusted user agent clears every web server block and rate limit
    /// for any client whose user agent contains it, ignoring case. Only the
    /// web server's: a client chooses its own user agent, so letting one past the log
    /// detectors too would let any scanner past them by copying it. Trust
    /// the address for that.
    ///
    /// Takes effect after `render-firewall` (addresses) and `apply-blocks`
    /// (both), like every other change here. `remove-trusted` takes it
    /// back; `list-trusted` lists them.
    AddTrusted {
        /// An IP address or CIDR range, e.g. 203.0.113.7 or 198.51.100.0/24
        #[arg(
            long,
            required_unless_present = "user_agent",
            conflicts_with = "user_agent"
        )]
        address: Option<String>,
        /// Part of a user agent, e.g. UptimeRobot
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Stop trusting an address or a user agent added with `add-trusted`
    RemoveTrusted {
        /// The address or CIDR range, as `list-trusted` shows it
        #[arg(
            long,
            required_unless_present = "user_agent",
            conflicts_with = "user_agent"
        )]
        address: Option<String>,
        /// The user agent, as `list-trusted` shows it
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// List the user agents this host's blocking policy is turning away.
    ///
    /// Reads the web server's access log and counts, per user agent, how many
    /// requests came back with the configured block response and how many
    /// were served. A client with refusals and nothing served is being
    /// stopped at the door; one with plenty served and a few refused is
    /// being told no by the application behind the web server.
    ///
    /// Bots appearing here is the policy working. What this is for is the
    /// other kind: a first-party app matching a pattern in a public bad-bot
    /// list, which is how Nextcloud's and Jellyfin's mobile clients -- all
    /// carrying `okhttp` -- were blocked on a real host for days before
    /// anyone noticed.
    ///
    /// Allow one with `stop-bots add-trusted --user-agent`.
    ListTurnedAway {
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// List every trusted address and user agent
    ListTrusted {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// List every stored firewall rule: its id, where it came from and why.
    ///
    /// Each rule shows its source — the detector that added it, or `cli`,
    /// `tui` or `web` for one added by hand — when it was added, when it
    /// expires, and the log line that triggered it. Rules from before 0.1
    /// have no source and show `before-0.1`. Newest first.
    ListFirewallRules {
        /// Only rules from this source: a detector's name (as `set-detector`
        /// takes it), `cli`, `tui`, `web` or `before-0.1`
        #[arg(long, value_parser = source_arg)]
        source: Option<SourceFilter>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Remove a firewall rule by id, or every rule from one source.
    ///
    /// Removing a detector's block also keeps that detector from adding
    /// it straight back from the same log lines: it leaves the address
    /// alone for as long as the block was meant to last. Trust the
    /// address (`add-trusted --address`) to exempt it for good.
    #[command(group(clap::ArgGroup::new("which").required(true).args(["id", "source"])))]
    RemoveFirewallRule {
        /// The rule's id, as `list-firewall-rules` shows it
        #[arg(long)]
        id: Option<i64>,
        /// Every rule from this source instead: a detector's name, `cli`,
        /// `tui`, `web` or `before-0.1`
        #[arg(long, value_parser = source_arg)]
        source: Option<SourceFilter>,
        /// Say how many rules --source would remove, and remove nothing
        #[arg(long, requires = "source")]
        dry_run: bool,
    },
    /// Switch a stored firewall rule off or back on, without deleting it.
    ///
    /// A disabled rule stays in the list, marked "(disabled)", and is left
    /// out of the next script `render-firewall` writes. Like every rule
    /// change, it takes effect once that script is applied.
    SetFirewallRule {
        /// The rule's id, as `list-firewall-rules` shows it
        #[arg(long)]
        id: i64,
        /// Whether the rule is rendered into the firewall script
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Write the firewall rules to a script for you to review and apply.
    ///
    /// Renders every stored rule into an nftables or iptables script, plus
    /// the rules derived from blocked crawler IP ranges, switched-on
    /// reputation feeds and the geo selection (see `set-geo-mode` and
    /// `add-country`). Derived rules are computed fresh on each render and
    /// never stored.
    ///
    /// Without --apply this only writes the script, to
    /// /etc/stop-bots/firewall.next.nft (or firewall.next.sh), which
    /// nothing loads. Review it, then run `render-firewall --apply`: that
    /// runs it and copies it to /etc/stop-bots/firewall.nft (or
    /// firewall.sh), the script `install firewall` loads at boot. `batch
    /// --apply` and "Apply everything" in the TUI do the same.
    ///
    /// Before writing anything, checks recent successful SSH logins (from
    /// /var/log/auth.log, /var/log/secure or journalctl) against every
    /// address about to be blocked, simulating the same first-match-wins
    /// order the script itself will evaluate. If any currently-connected
    /// client would be cut off, it refuses to write the script. If no SSH
    /// log could be read, it writes the script but refuses to apply it.
    /// --force overrides both.
    ///
    /// Allowlist geo mode needs the nftables backend: iptables has no
    /// loopback/established-connection allowance and silently permits all
    /// IPv6 (it skips IPv6 rules entirely), both fatal once a trailing
    /// "block everything else" rule is in play.
    RenderFirewall {
        /// Which firewall to write for. Defaults to the backend this host
        /// is set to (`set-firewall-backend`), which is nftables unless
        /// changed.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// Write the script to this file instead, for you to review or run
        /// yourself; nothing loads it at boot. With --apply it names the
        /// applied script instead, as `batch --out` does, and the script is
        /// written beside it as <name>.next.<ext>
        #[arg(long)]
        out: Option<PathBuf>,
        /// Run the script once it is written, if the lockout check allows,
        /// and make it the script loaded at boot
        #[arg(long)]
        apply: bool,
        /// Write, and with --apply run, the script even if it would block
        /// an IP with a recent successful SSH login, or no SSH log could be
        /// read to check
        #[arg(long)]
        force: bool,
        /// Check this SSH log file instead of auto-detecting one — for a
        /// non-standard log location, or a container where the real logs
        /// aren't at their usual path
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = NO_CONFIRM_HELP)]
        no_confirm: bool,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
    /// Put back the firewall rules from before the last apply.
    ///
    /// While an apply is waiting to be kept ("Keep these firewall rules?"),
    /// this reverts it now: the applied script, which an unconfirmed apply
    /// leaves alone, is loaded again — or, if there was none, the
    /// stop-bots nft table or iptables chains are deleted. The timer an
    /// interactive apply arms runs exactly this when nobody answers.
    ///
    /// With nothing waiting, it goes back to /etc/stop-bots/firewall.prev.nft
    /// (or .prev.sh), the applied script the last apply replaced, and swaps
    /// the two, so running it again goes forward again.
    RevertFirewall {
        /// The backend, for going back to the previous script. Defaults to
        /// the stored one; a waiting apply knows its own.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// The applied script. Defaults to /etc/stop-bots/firewall.nft, or
        /// firewall.sh for iptables
        #[arg(long)]
        out: Option<PathBuf>,
        /// Only revert the apply armed with this token (what the timer
        /// passes), and do nothing if it was kept
        #[arg(long, hide = true)]
        token: Option<String>,
        /// Wait this many seconds first: the timer, where there is no
        /// systemd to run it
        #[arg(long, hide = true, requires = "token")]
        after: Option<u64>,
    },
    /// Choose which firewall this host generates scripts for.
    ///
    /// Read by `render-firewall`, `batch`, the internal cron, `status` and
    /// `install firewall` whenever they are not told otherwise. The TUI's
    /// render popup sets the same value.
    SetFirewallBackend {
        /// nftables (the default) or iptables
        #[arg(long)]
        backend: FirewallBackend,
    },
    /// Run one detector over a log now, and block what it finds.
    ///
    /// Reads the whole log given (or the one stored with `set-log-paths`,
    /// or the usual place), runs the detector over it with its stored
    /// settings unless overridden here, and stores a block for each address
    /// it convicts. The schedule (`tick`, the TUI) runs the same detectors
    /// on its own, over each detector's window; this is for a log you want
    /// judged once, by hand.
    ///
    /// A stored block has no effect until the firewall script is applied
    /// (`render-firewall --apply`, `batch --apply`, or "Apply everything"),
    /// so this is safe to run unattended. Addresses that logged in over SSH,
    /// trusted ones, private ones, and those inside a verified crawler's
    /// published ranges are never blocked.
    ///
    /// ssh-scanners reads the SSH log, port-scanners the kernel log its
    /// trap ports write to, and every other detector the web server's
    /// access log. spoofed-crawlers needs the crawler ranges
    /// (`update-crawler-ranges`), and honeypot and robots-violators need the
    /// generated robots.txt served (`set-robots-txt --enabled true`).
    RunDetector {
        /// Which detector, as `list-detectors` names it
        detector: DetectorArg,
        /// How much evidence from one address before it is blocked, for the
        /// detectors that count (ssh-scanners, web-scanners, asset-ratio,
        /// rotating-ua, refererless, login-attempts, request-rate,
        /// port-scanners). A count over the whole log given, except for
        /// request-rate, which takes requests a minute over its window, ending
        /// where the log ends. Defaults to the stored threshold
        /// (`set-detector`). Must be at least 1.
        #[arg(long, value_parser = min_threshold)]
        threshold: Option<usize>,
        #[arg(long, value_parser = ttl_days_arg, help = TTL_HELP)]
        ttl_days: Option<i64>,
        /// Read this SSH log file instead of auto-detecting one
        /// (ssh-scanners only)
        #[arg(long, conflicts_with = "access_log")]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
        /// Read this kernel log file instead of the stored one or the
        /// usual places (kern.log, messages, then the journal)
        /// (port-scanners only)
        #[arg(long, conflicts_with_all = ["access_log", "ssh_log"])]
        kernel_log: Option<PathBuf>,
        #[arg(long, help = DRY_RUN_HELP)]
        dry_run: bool,
    },
    /// Set the extra probe paths, on top of the built-in list.
    ///
    /// Replaces the extra paths the probe-paths detector checks. The built-in
    /// list is never removable — switch the detector off instead. One path
    /// per line; blank lines and `#` comments are ignored. Each is looked
    /// for anywhere in the request path, so every entry must start with
    /// `/`, which keeps it to the start of a path segment, and must name
    /// something after it.
    SetProbePaths {
        /// Newline-separated paths. Pass an empty string to clear.
        #[arg(long)]
        paths: String,
    },
    /// List every probe path currently checked, built-in and extra
    ListProbePaths {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Set the honeypot trap path.
    ///
    /// Pick something that does *not* sound valuable: a path like `/admin`
    /// or `/backup` would also be guessed by scanners that never read
    /// robots.txt, which turns a precise "ignored robots.txt" signal into
    /// just another probe path.
    SetHoneypotPath {
        /// The trap path. Must start with `/`, and contain only characters
        /// a URL path spells literally.
        #[arg(long)]
        path: String,
    },
    /// List every detector with its switch, TTL and threshold.
    ///
    /// These are the settings the internal cron and `batch` run the
    /// detectors with. Change them with `set-detector`, and IPv4 /24
    /// escalation with `set-subnet-escalation`.
    ListDetectors {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Switch a detector on or off, and set its TTL, threshold and window.
    ///
    /// These are what the schedule (`stop-bots tick`, or the TUI while it
    /// is open) and `batch` use. Switching a detector off stops it adding
    /// blocks; it never removes the ones it already added, which expire on
    /// their own. Give no flags to print the detector's current settings.
    ///
    /// Only the detectors that count something take a threshold:
    /// ssh-scanners, web-scanners, asset-ratio, rotating-ua, refererless,
    /// login-attempts, request-rate and port-scanners. For the others one
    /// matching request is conclusive.
    ///
    /// port-scanners also takes --ports, the trap ports the firewall drops
    /// and logs.
    ///
    /// robots-txt cannot be switched here: it runs exactly when "humans
    /// only" is on (`set-humans-only`).
    SetDetector {
        /// Which detector
        detector: DetectorArg,
        /// Whether it runs
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: Option<bool>,
        /// How many days each block it adds lasts, from 1 to 3650
        #[arg(long)]
        ttl_days: Option<i64>,
        /// How much evidence from one address before it is blocked: failed
        /// logins, 404'd paths, pages without assets, user agents,
        /// referer-less pages, login attempts, trap ports or, for
        /// request-rate, requests a minute, depending on the detector. At
        /// least 2.
        #[arg(long)]
        threshold: Option<i64>,
        /// port-scanners only: the trap ports, comma-separated, or
        /// `default` for the built-in list. Never 22, 80 or 443; whatever
        /// listens, and sshd's port, are left out when the firewall is
        /// rendered.
        #[arg(long)]
        ports: Option<String>,
        /// How far back evidence counts, in hours, from 1 to 720: a log
        /// line older than this is no reason to block. 24 unless changed,
        /// and 1 for asset-ratio, rotating-ua, refererless, login-attempts
        /// and request-rate.
        #[arg(long)]
        window_hours: Option<i64>,
        /// probe-paths only: also count /wp-login.php, /phpmyadmin and the
        /// other paths of an application where no site runs it
        /// (`list-probe-paths` shows each, and why). On for a database
        /// created by a release that has it; off on one an earlier release
        /// created, until you turn it on.
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        app_aware: Option<bool>,
    },
    /// Block a whole IPv4 /24 when several of its addresses are flagged.
    ///
    /// When on, a detector that flags at least --min addresses in one IPv4
    /// /24 in the same pass blocks the /24 instead. Off by default:
    /// blocking 256 addresses because three misbehaved is collateral by
    /// design. IPv6 needs no switch: a detection always blocks the /64,
    /// which is one network, the same as one IPv4 address.
    SetSubnetEscalation {
        /// Whether to escalate
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: Option<bool>,
        /// Flagged addresses in one /24 before it escalates. At least 2,
        /// and 3 unless changed.
        #[arg(long)]
        min: Option<i64>,
    },
    /// Block repeat offenders for longer.
    ///
    /// When on, a detector that blocks an address again after its earlier
    /// block ended doubles the block: twice the detector's TTL for the
    /// second offence, four times for the third, and eight times from the
    /// fourth on, but never more than 90 days (or the detector's own TTL,
    /// if that is longer). An address is forgotten 30 days after its last
    /// block ends, or when you unblock it by hand. Trusted addresses and
    /// addresses that log in over SSH are never blocked, so never counted.
    ///
    /// On for a database created by a release that has it; off on one an
    /// earlier release created, until you turn it on.
    SetRepeatOffenders {
        /// Whether repeat offenders are blocked for longer
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Tally which user agents are getting through successfully.
    ///
    /// Reads the web server's access log and adds up, per user agent, the requests
    /// that were answered successfully (anything but 4xx and 5xx) — a view
    /// of who is actually visiting, next to the detectors' view of who is
    /// misbehaving. Additive across runs: re-reading an overlapping or
    /// rotated log adds onto each user agent's count rather than resetting
    /// it.
    RecordAccessStats {
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
    },
    /// List recorded user-agent hit counts, most-seen first
    ListAccessStats {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Prune stale rows and compact the database.
    ///
    /// Drops user-agent statistics not seen in 90 days (and any excess over
    /// 20,000 rows, least recently seen first), clears lapsed firewall
    /// rules, and rewrites the file to hand free pages back to the
    /// filesystem if enough has accumulated to be worth it. The internal
    /// cron does this daily on its own. This runs it now, which is what a
    /// host that has already grown wants, and what a host with no `sqlite3`
    /// installed has no other way to do.
    Maintain {
        /// Compact the file even when there is little to reclaim. The
        /// scheduled job weighs that up for itself; this overrides it
        #[arg(long)]
        force_compact: bool,
    },
    /// Download the crawlers' published IP ranges: every crawler, or one.
    ///
    /// Downloads and stores the current CIDR lists Googlebot, Bingbot and
    /// GPTBot publish. A blocked category blocks its crawler's ranges in
    /// the firewall, and the spoofed-crawlers detector checks claims
    /// against them.
    UpdateCrawlerRanges {
        /// Only this crawler: googlebot, bingbot or gptbot. Every one
        /// without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "source_id")]
        source: Option<PathBuf>,
    },
    /// Download third-party CIDR feeds: every one switched on, or one.
    ///
    /// Downloads and stores a reputation list (firehol-level1, tor-exits,
    /// blocklist-de) or a cloud provider's published address space (aws,
    /// google-cloud, digitalocean). Without --source-id, every feed that is
    /// switched on. Fetching does *not* switch a feed on — see
    /// `set-reputation-source` — so refreshing a feed you deliberately
    /// disabled never silently re-enables it.
    UpdateReputationSources {
        /// Only this feed: firehol-level1, tor-exits, blocklist-de, aws,
        /// google-cloud or digitalocean. Every feed switched on without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "source_id")]
        source: Option<PathBuf>,
    },
    /// Switch a third-party CIDR feed on or off.
    ///
    /// While on, every range it holds is blocked in the next script
    /// `render-firewall` writes. Nothing is added to the stored rule list,
    /// the same as crawler and country ranges.
    ///
    /// All feeds are off by default. Note what the cloud-provider ones
    /// actually do: they block *every* visitor hosted at that provider,
    /// including VPN endpoints, corporate egress and API clients — not
    /// just bots. Unlike the behavioural detectors there's no evidence
    /// involved, and a wrongly-blocked visitor has no way to tell you.
    ///
    /// In Blocklist geo mode a cloud-provider feed leaves TCP port 80 open,
    /// because Let's Encrypt validates from AWS: with it closed, no
    /// certificate on this host renews over HTTP.
    SetReputationSource {
        /// Which feed, as `list-reputation-sources` names it
        #[arg(long)]
        source_id: String,
        /// Whether its ranges are blocked
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// List the third-party CIDR feeds.
    ///
    /// Lists every third-party CIDR feed with its on/off state and how many
    /// ranges it currently holds.
    ListReputationSources {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Download country IP ranges: every selected country, or one.
    ///
    /// Downloads and stores IPdeny's current aggregated CIDR lists. One
    /// named with --country is not selected by this — see `add-country`.
    UpdateCountryRanges {
        /// Only this country, by its two-letter code, e.g. "us" or "nl".
        /// Every selected country without it
        #[arg(long)]
        country: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "country")]
        source: Option<PathBuf>,
    },
    /// Set the geo mode: blocklist or allowlist.
    ///
    /// "blocklist" (the default) blocks the selected countries and allows
    /// everything else; "allowlist" allows only the selected countries and
    /// blocks everything else. Switching modes doesn't touch the
    /// selected-country list itself, only how `render-firewall` reads it.
    SetGeoMode {
        /// blocklist or allowlist
        #[arg(long)]
        mode: GeoModeArg,
    },
    /// Add a country to the geo selection.
    ///
    /// Adds a country to the host-wide geo selection (fetch its ranges
    /// first with `update-country-ranges`). What this means depends on the
    /// geo mode — see `set-geo-mode`.
    AddCountry {
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// Remove a country from the host-wide geo selection
    RemoveCountry {
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// List the current geo mode and every selected country
    ListSelectedCountries {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Block a hosting provider's whole network, by its AS number.
    ///
    /// Every range the network announces is blocked in the next script
    /// `render-firewall` writes, like a cloud-provider feed: every visitor
    /// hosted there is turned away, not just bots — VPN endpoints, company
    /// networks and API clients included — and port 80 stays open for
    /// Let's Encrypt unless `set-cloud-port-80` closes it.
    ///
    /// `list-hosting-asns` names the providers on the built-in list, but any
    /// AS number is accepted. Nothing is downloaded by this: run
    /// `update-hosting-asns` for the ranges.
    AddHostingAsn {
        /// The AS number, e.g. 24940 or AS24940 (Hetzner)
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: u32,
    },
    /// Stop blocking a hosting provider's network, and forget its ranges
    RemoveHostingAsn {
        /// The AS number, as `list-hosting-asns` shows it
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: u32,
    },
    /// List the hosting providers that can be blocked by AS number.
    ///
    /// Every provider on the built-in list and every other AS number
    /// selected, with whether it is blocked and how many ranges it holds.
    ListHostingAsns {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Download the blocked hosting providers' ranges: every one, or one.
    ///
    /// Downloads iptoasn.com's public table of which network announces which
    /// range (about 9 MB) once, and keeps the ranges of every AS number
    /// selected with `add-hosting-asn`. The rest of the table is not kept.
    UpdateHostingAsns {
        /// Only this AS number, which must be selected. Every selected one
        /// without it
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: Option<u32>,
        /// Read the table from a local file instead of downloading it: an
        /// ip2asn TSV, gzipped or plain. For a host with no outbound access
        /// — and what makes this path testable offline
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Set whether a category of bots is allowed or blocked.
    ///
    /// Without --site this is the host-wide default for the category:
    /// every bot in it follows it unless `set-bot` overrides that bot.
    /// With --site it overrides the default for that one site; `--policy
    /// default` removes the override again.
    ///
    /// Only changes what would be written: run `apply-blocks` to put it
    /// into the web server's config. While "humans only" is on, every category is
    /// blocked whatever is stored here.
    SetCategory {
        /// scanner, search or ai
        #[arg(long)]
        category: CategoryArg,
        /// allowed, blocked, or (with --site) default
        #[arg(long)]
        policy: PolicyArg,
        /// Override the policy for this site only, by its server_name
        #[arg(long)]
        site: Option<String>,
    },
    /// List the category policies, host-wide or for one site
    ListCategories {
        /// Show this site's overrides too, by its server_name
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Allow or block one bot, whatever its category says.
    ///
    /// Without --site this is the host-wide status of the bot; `--policy
    /// default` makes it follow its category again. With --site it
    /// overrides the bot for that one site only.
    ///
    /// Find a bot's slug with `list-bots`. Run `apply-blocks` afterwards to
    /// write the change into the web server's config.
    SetBot {
        /// The bot's slug, as `list-bots` shows it
        #[arg(long)]
        bot: String,
        /// allowed, blocked, or default
        #[arg(long)]
        policy: PolicyArg,
        /// Override the bot for this site only, by its server_name
        #[arg(long)]
        site: Option<String>,
    },
    /// List every known bot with its categories and status
    ListBots {
        /// Only bots whose slug or name contains this, ignoring case
        #[arg(long)]
        search: Option<String>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Turn NGINX rate limiting on or off, and set its parameters.
    ///
    /// When on, `apply-blocks` writes a `limit_req_zone` to
    /// /etc/nginx/conf.d/stop-bots-limits.conf (it has to live in `http`
    /// context, so it can't go in the per-site block) and adds a
    /// `limit_req ... burst=N nodelay; limit_req_status 429;` to each
    /// site. NGINX then does the enforcement itself, at request time —
    /// unlike everything else here, no log analysis is involved.
    ///
    /// Off by default: a limit tuned for the wrong site turns away real
    /// visitors, and unlike a bot-pattern block there's no user agent to
    /// inspect afterwards to work out who was caught.
    ///
    /// NGINX only: Apache has no request-rate limit of its own, and
    /// Traefik's is a middleware only each site's own router can carry, so
    /// on either it is refused.
    SetRateLimit {
        /// Whether rate limiting is written into the site configs
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
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
    /// Each rule turns away requests that don't look like a browser's, and
    /// each is off by default, one switch per rule so that if something of
    /// yours stops working you can tell which rule did it. Run
    /// `apply-blocks` afterwards to write it into the site config.
    SetSiteRule {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// One of http-1x, no-accept, no-accept-language, no-user-agent,
        /// ip-literal-host, old-tls
        #[arg(long)]
        rule: String,
        /// Whether requests the rule matches are turned away
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Exempt a path prefix from a site's blocking rules.
    ///
    /// Adds a request-path prefix that a site's blocking rules don't apply
    /// to. Run `apply-blocks` afterwards to write it into the site config.
    /// `remove-exempt-path` takes it back.
    AddExemptPath {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// The path prefix. Must start with `/`.
        #[arg(long)]
        path: String,
        /// Exempt only clients whose user agent contains this, ignoring
        /// case — e.g. `okhttp` for an app whose HTTP library a bot list
        /// blocks. Matched against the resolved path, so `..` cannot walk
        /// out of the exempt prefix.
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Remove a path exemption added with `add-exempt-path`.
    ///
    /// Give the same --site, --path and --user-agent it was added with. Run
    /// `apply-blocks` afterwards to write the change into the site config.
    RemoveExemptPath {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// The path prefix. Must start with `/`.
        #[arg(long)]
        path: String,
        /// The user agent it was limited to, if it was
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Turn generation of a robots.txt on or off.
    ///
    /// When on, `apply-blocks` writes one to /etc/stop-bots/nginx/robots.txt
    /// (/etc/stop-bots/apache/robots.txt on Apache) and has each site serve
    /// it, with a `location = /robots.txt` block on NGINX or an `Alias` on
    /// Apache: one `User-agent:` line per currently-blocked bot under a shared
    /// `Disallow: /`, plus a `Disallow:` for the honeypot trap path.
    ///
    /// Off by default, because it *replaces* whatever the site already
    /// serves at /robots.txt — which may be hand-written and carry rules
    /// this tool knows nothing about. Refused on Traefik, which serves no
    /// files.
    ///
    /// This is the polite layer under the 403, for the crawlers that
    /// honour it, and it is also what makes the honeypot work at all.
    SetRobotsTxt {
        /// Whether the robots.txt is generated and served
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Turn automatic applying of the web server's config on or off.
    ///
    /// When on, the schedule (`stop-bots tick` from `install cron`, or the
    /// TUI while it is open — not this command) re-writes every site's generated block and
    /// reloads the web server once an hour, whenever they have fallen behind the
    /// database. That happens constantly on a busy host: every user agent
    /// a detector blocks changes the generated block, which puts every
    /// site back to STALE within the minute.
    ///
    /// Off by default. It reloads a live web server with nobody watching,
    /// which is not something an upgrade should start doing on its own.
    ///
    /// The web server's config only. The firewall script has its own
    /// switch, `set-auto-apply-firewall`.
    SetAutoApply {
        /// Whether the internal cron applies the web server's config
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Turn automatic applying of the firewall script on or off.
    ///
    /// Separate from `set-auto-apply`, and separately off by default,
    /// because the risks are not comparable: a bad web server config is
    /// caught by its config test (`nginx -t`, `apache2ctl configtest`) and
    /// costs a failed reload (Traefik switches off only the router it
    /// cannot read), while a bad firewall
    /// ruleset locks you out of the host and no care taken here can undo
    /// that remotely.
    ///
    /// When on, the internal cron runs the script it renders instead of
    /// only writing it — but it refuses to apply unless the anti-lockout
    /// check actually ran. The interactive paths treat "the SSH log could
    /// not be read" as a pass, which is reasonable while a person is
    /// reading the result; unattended it is not, so this refuses. If the
    /// cron reports that, point `--ssh-log` at a readable log.
    ///
    /// An automatic apply is not asked about afterwards, as one from the
    /// TUI or a terminal is ("Keep these firewall rules?"): there is
    /// nobody to answer, so nothing is armed to revert it.
    SetAutoApplyFirewall {
        /// Whether the internal cron runs the firewall script
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Keep port 80 open in the cloud-provider feeds, for Let's Encrypt.
    ///
    /// Let's Encrypt fetches an http-01 challenge from several places, and
    /// all but one are in AWS. With this on, which it is by default, the
    /// AWS, Google Cloud and DigitalOcean feeds and the hosting providers
    /// blocked by AS number (`add-hosting-asn`) block every port but TCP 80,
    /// so certbot's `nginx`, `apache`, `webroot` and `standalone` plugins
    /// keep renewing. Turn it off on a host that renews over DNS, or has no
    /// certificate, to block those ranges on port 80 as well. Allowlist geo
    /// mode never opens the port.
    #[command(name = "set-cloud-port-80")]
    SetCloudPort80 {
        /// Whether the cloud-provider feeds and hosting providers leave port
        /// 80 open
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Check every firewall apply against the addresses that log in over SSH.
    ///
    /// On by default. Every apply, by hand or by cron, is refused when its
    /// rules would block an address that logged in over SSH in the last
    /// week, or the session it runs in. When no one has logged in for a
    /// week, an apply whose rules block every address not listed
    /// (Allowlist, Only trusted IPs) is refused too, as it would block
    /// whoever connects next.
    ///
    /// Turn it off on a server you never log into over SSH, such as one you
    /// reach through your provider's console. Addresses that do log in are
    /// still let through ahead of every block; only the check is skipped.
    #[command(name = "set-ssh-lockout-check")]
    SetSshLockoutCheck {
        /// Whether applies are checked against SSH logins
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Serve humans and nothing else.
    ///
    /// Blocks every catalogued bot whatever its category, and gives any
    /// address that fetches /robots.txt a one-day block.
    ///
    /// The three category policies are forced to Blocked while this is on
    /// and cannot be edited, but their stored values are untouched — turn
    /// this off and they come back. Let's Encrypt is the one bot still
    /// allowed, because blocking it breaks certificate renewal in a way
    /// that only surfaces two months later.
    SetHumansOnly {
        /// Whether humans-only mode is on
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Choose which TUI `stop-bots` opens: simple or advanced.
    ///
    /// "simple" is one screen: who can visit, which countries, whether it
    /// keeps running by itself, and a one-line status. "advanced" is every
    /// screen and setting. `v` in the TUI switches between them too. A new
    /// database opens in simple; one from before 0.7.0 in advanced.
    SetUiMode {
        /// simple or advanced
        #[arg(long)]
        mode: UiModeArg,
    },
    /// Block the user agents of browsers too old for anyone to still run.
    ///
    /// Opera 5 to 12, Firefox 1 to 9, Chrome 1 to 39, Internet Explorer 2
    /// to 9, feature phones (NetFront, UP.Browser, J2ME, Symbian,
    /// BlackBerry OS) and the like: the strings scanners rotate through to
    /// look like people, which no bot list can carry because none of them
    /// is a bot's name. One switch for every site, off by default, because
    /// a few are still a person somewhere (Opera Mini sends `Opera/9.80`).
    /// Humans only does not turn it on.
    SetOldBrowsers {
        /// Whether old browser agents are blocked
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Print the robots.txt that would be generated now, without writing it
    ShowRobotsTxt,
    /// Set what the web server sends a blocked request.
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
    /// "teapot", "close" and "tarpit" are NGINX's: on Apache each is a
    /// 403. Traefik sends nothing but a 403.
    ///
    /// Host-wide, and only changes what *would* be written: run
    /// `apply-blocks` afterwards to get the new response into the site
    /// configs. Until then every applied site shows as STALE.
    SetBlockResponse {
        /// What a blocked request gets back
        #[arg(long)]
        response: BlockResponseArg,
    },
    /// Remember where this host's logs actually are.
    ///
    /// The companion to `set-web-server`, for the other half of a
    /// containerised web server. A container that
    /// bind-mounts its log directory writes the access log somewhere that
    /// is not /var/log/nginx/access.log (or /var/log/apache2/access.log) on
    /// the host, and Traefik's goes wherever its `accessLog.filePath` says
    /// — and `--access-log` on a
    /// single command cannot reach the two things that actually run the
    /// detectors: `stop-bots tick` and the TUI take no arguments for it, so
    /// the schedule reads the default and finds nothing.
    ///
    /// A path given here is used whenever no flag overrides it. Pass an
    /// empty string to clear one. Give neither flag to print what is
    /// stored.
    ///
    /// The access logs the web server's config names (`access_log`,
    /// `CustomLog`) are read as well as the one stored here, unless the
    /// server runs in a container (`set-web-server --test`), whose paths
    /// are its own. Traefik's dynamic config names none, so on Traefik the
    /// one stored here is the one read. A command's `--access-log` reads
    /// only the file it names.
    SetLogPaths {
        /// The web server's main access log, which every web-side detector
        /// reads, beside the ones its config names.
        #[arg(long)]
        access_log: Option<String>,
        /// The SSH authentication log, feeding the SSH scanner detector
        /// and the anti-lockout window.
        #[arg(long)]
        ssh_log: Option<String>,
        /// The kernel log, feeding the port-scan detector.
        #[arg(long)]
        kernel_log: Option<String>,
    },
    /// Set the commands used to test and reload NGINX, and its config root.
    ///
    /// NGINX only. `set-web-server` takes the same flags for either
    /// server, Apache and Traefik included.
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
    /// Pass no flag to print the commands currently in effect.
    #[command(hide = true)]
    SetNginxCommands {
        /// The config check. Must exit non-zero on a bad config.
        #[arg(long)]
        test: Option<String>,
        /// The reload.
        #[arg(long)]
        reload: Option<String>,
        /// Where this host's site configs live, when that is not
        /// /etc/nginx — an NGINX in a container with its config on a bind
        /// mount being the case this exists for. Stored, so it no longer
        /// has to be repeated on scan-sites, apply-blocks, batch and tui,
        /// where forgetting it scanned an empty /etc/nginx and reported
        /// success.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Restore all three to their defaults.
        #[arg(long, conflicts_with_all = ["test", "reload", "root"])]
        reset: bool,
    },
    /// Choose the web server whose sites this host protects.
    ///
    /// `nginx` is the default, and what every host was before there was a
    /// choice. `apache` reads `<VirtualHost>` sections under /etc/apache2,
    /// blocks with mod_rewrite (`a2enmod rewrite` if it is off), and tests
    /// and reloads with `apache2ctl configtest` and `systemctl reload
    /// apache2`. Stored in the host settings, so every command and the TUI
    /// follow it.
    ///
    /// `traefik` (version 3) reads the routers in the directory Traefik's
    /// file provider reads, /etc/traefik/dynamic unless `--root` says
    /// otherwise, and writes `stop-bots.yml` there: routers of its own that
    /// turn bots away with a 403 before any site's router is asked. No
    /// file of yours is edited. Traefik reloads the directory itself, so no
    /// command is run unless you give one. Sites from Docker labels are
    /// protected too, with the host-wide settings. Tell Traefik's access log
    /// to keep the `User-Agent` and `Referer` headers, which it drops by
    /// default, and store where it writes the log:
    ///
    ///   set-web-server traefik --root /srv/traefik/dynamic
    ///
    ///   set-log-paths --access-log /srv/traefik/logs/access.log
    ///
    /// `npmplus` reads the hosts NPMplus renders in its data directory,
    /// /opt/npmplus unless `--root` says otherwise, and never writes them:
    /// NPMplus rewrites a host's file whenever it is saved. It writes one
    /// block into custom_nginx/server_http.conf, which every host includes,
    /// and one line into custom_nginx/http_top.conf, keeping the rest of
    /// each; every host gets the host-wide settings, and a site with
    /// settings of its own is refused. It tests and reloads with `docker
    /// exec npmplus nginx -t` and `docker exec npmplus nginx -s reload`.
    /// NPMplus writes its access log only with `LOGROTATE=true`:
    ///
    ///   set-web-server npmplus --root /opt/npmplus
    ///
    ///   set-log-paths --access-log /opt/npmplus/nginx/logs/access.log
    ///
    /// Also takes the server's own commands and config root, for a server
    /// that is not where a stock install puts it. On RHEL and its relatives, whose Apache
    /// reads conf.d and logs to /var/log/httpd:
    ///
    ///   set-web-server apache --root /etc/httpd --test "apachectl configtest" --reload "systemctl reload httpd"
    ///
    ///   set-log-paths --access-log /var/log/httpd/access_log
    ///
    /// Refused while the web server chosen now still has stop-bots in its
    /// config: take that out first with `uninstall web-server`.
    ///
    /// Pass no server to print what is in effect.
    SetWebServer {
        /// `nginx`, `apache`, `traefik` or `npmplus`.
        #[arg(value_parser = parse_web_server)]
        server: Option<webserver::WebServer>,
        /// The config check. Must exit non-zero on a bad config.
        #[arg(long, requires = "server")]
        test: Option<String>,
        /// The reload.
        #[arg(long, requires = "server")]
        reload: Option<String>,
        /// Where this host's site configs live, when that is not where a
        /// stock install puts them.
        #[arg(long, requires = "server")]
        root: Option<PathBuf>,
        /// Restore the server's commands and root to their defaults.
        #[arg(long, requires = "server", conflicts_with_all = ["test", "reload", "root"])]
        reset: bool,
    },
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
        /// Print every check as one JSON object instead of text; the exit
        /// status is the same. Its field names are part of the stable
        /// contract from 1.0: fields may be added, never renamed or removed
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    /// One unattended pass over everything, for a real cron entry.
    ///
    /// Refreshes every list, scans the logs, writes the web server's
    /// blocking rules and the firewall script — and, with --apply, puts both into
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
    /// not run. That is the same line every other apply draws. Pass
    /// --ssh-log if the log isn't where this expects, or --force if you
    /// know what you're doing.
    ///
    /// The script is written to /etc/stop-bots/firewall.next.nft (or
    /// .next.sh) and copied to firewall.nft, the file the boot unit loads,
    /// only once it has been applied. --dry-run prints what would change
    /// and changes nothing.
    ///
    /// Refreshes bot lists and crawler IP ranges in full, and reputation
    /// feeds and country ranges only where they are switched on or
    /// selected. Runs every detector that is switched on, with its stored
    /// TTL and threshold (`list-detectors`). One step's failure never stops
    /// the others; the exit status is non-zero if any of them failed, which
    /// is what makes cron mail you.
    Batch {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Reload the web server and run the generated firewall script, rather than
        /// only writing both
        #[arg(long)]
        apply: bool,
        /// The applied firewall script: what an apply replaces, and what the
        /// boot unit loads. The script is written beside it as
        /// <name>.next.<ext>. Defaults to /etc/stop-bots/firewall.nft, or
        /// firewall.sh for iptables — which generates a shell script, not an
        /// nftables one
        #[arg(long)]
        out: Option<PathBuf>,
        /// Which firewall to generate for. Defaults to whichever backend
        /// this host is set to (`set-firewall-backend`) — a crontab that
        /// silently disagreed with it used to leave two scripts on disk, in
        /// two syntaxes, at two paths, one of them stale.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// Read this SSH log file instead of auto-detecting one. Worth
        /// setting explicitly under cron: on a journald-only host,
        /// `journalctl` can come back empty, which is the case --apply
        /// refuses on
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = ACCESS_LOG_HELP)]
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
        /// Print a line per step, not just the failures. With --dry-run,
        /// also print the diffs --diff prints
        #[arg(long, short)]
        verbose: bool,
        /// Print what the web server and firewall steps would change — the
        /// files, the rules added and removed against the applied script,
        /// the lockout check's verdict — and change nothing: nothing is
        /// downloaded, scanned, written, applied or recorded. The one
        /// exception is the bot list built into this binary, which is
        /// stored first, as every other command that renders web server
        /// config does
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run, also print a unified diff of every file that
        /// would change, the firewall script included
        #[arg(long, requires = "dry_run")]
        diff: bool,
        #[arg(long, help = NO_CONFIRM_HELP)]
        no_confirm: bool,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
    /// Keep this host protected with nobody at a terminal.
    ///
    /// `install cron` writes /etc/cron.d/stop-bots, which runs `stop-bots
    /// tick` once a minute: the detectors each minute and the lists weekly,
    /// the same schedule the TUI runs while it is open. It writes what the
    /// detectors find, and applies it only as far as `set-auto-apply` and
    /// `set-auto-apply-firewall` allow; both are off until you turn them on.
    ///
    /// `install firewall` writes a systemd unit that loads the applied
    /// firewall script at boot.
    ///
    /// Nothing is written until every check has passed, a file you have
    /// edited is left alone rather than replaced, and --dry-run prints the
    /// whole plan without touching anything. Start there.
    Install {
        /// What to install: `cron`, the schedule, or `firewall`, the unit
        /// that loads the applied firewall script at boot.
        #[arg(value_enum)]
        target: InstallTarget,
        /// Print every step and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Replace a file even if it has been edited since stop-bots wrote
        /// it. An unedited one, from any version, is replaced without this.
        #[arg(long)]
        force: bool,
        /// The stop-bots binary the cron file runs. Defaults to the one
        /// running this command, which is refused if it sits in a build
        /// directory — a cron file pointing into target/debug works until
        /// the next `cargo clean`.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Install into this prefix instead of `/`. For inspecting the
        /// result without root; a file written under a prefix is one that
        /// cron and systemd never see, so this runs no `systemctl`.
        #[arg(long)]
        prefix: Option<PathBuf>,
    },
    /// Remove stop-bots from this host and put it back as it was.
    ///
    /// Stops and removes every unit it installed, deletes the live nft table or
    /// iptables chain, takes the injected blocks out of every site of the
    /// web server the host settings choose (tested with `nginx -t` or
    /// `apache2ctl configtest`, put back if that fails, then reloaded; on
    /// Traefik, its routers file is deleted), and
    /// deletes the generated web server files and firewall scripts. Every
    /// step is reported, a failed one does not stop the rest, and any
    /// failure makes the exit status non-zero.
    ///
    /// The database is kept, with every setting and rule, and so is the
    /// `stop-bots` user that owns it, unless --purge is given; the output
    /// says where it is. Needs root, except with
    /// --prefix. Run it with --dry-run first.
    Uninstall {
        /// What to remove: `nginx` (also spelled `web-server`, and on an
        /// Apache or a Traefik host it is that server's it removes), `firewall`, `cron`,
        /// or `all` (the default), which is all three plus /etc/stop-bots
        /// itself.
        #[arg(value_enum, default_value = "all")]
        target: UninstallTarget,
        /// Print every step and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also delete the database and the copies upgrades kept of it.
        /// Only with `all`.
        #[arg(long)]
        purge: bool,
        /// Remove from this prefix instead of `/`, as `install --prefix`
        /// wrote it. Nothing outside it is touched, and no systemctl, nft,
        /// iptables or web server test or reload is run.
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
    },
    /// Write the man pages and shell completions for packaging
    ///
    /// Hidden: the release pipeline runs it, and the `.deb` ships what it
    /// writes. Not part of the command line people use.
    #[command(hide = true)]
    GenerateDocs {
        /// The directory to write `man/` and `completions/` into
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Run whatever is due on the schedule, once, and exit.
    ///
    /// What `install cron` runs every minute: the jobs the TUI's Dashboard
    /// lists under Scheduled tasks, each only when it is due, so a minute
    /// with nothing due costs one database read. It applies to the web
    /// server and the firewall only what `set-auto-apply` and
    /// `set-auto-apply-firewall` allow. Prints nothing unless a job could
    /// not be recorded or --verbose is given, so cron mails only trouble.
    /// A run while another is still going leaves at once.
    Tick {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Read this SSH log file instead of the stored one or the search
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Print what each job that ran did
        #[arg(long, short)]
        verbose: bool,
    },
    /// Start the TUI (also the default when run with no subcommand)
    Tui {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Skip reloading the web server after its screen applies blocking
        /// rules (e.g. for tests driving the TUI end to end against a
        /// throwaway fixture root, where there's no real server to reload)
        #[arg(long)]
        no_reload: bool,
        /// Read this SSH log file instead of auto-detecting one — the same
        /// override every SSH-reading CLI subcommand already takes, and for
        /// the same two audiences: a host with a non-standard log location,
        /// and tests, where auto-detection would otherwise shell out to
        /// `journalctl` on every refresh of the Firewall screen
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum InstallTarget {
    /// /etc/cron.d/stop-bots, which runs `stop-bots tick` every minute.
    Cron,
    /// A systemd unit that re-applies the rendered firewall script at
    /// boot. Not `nftables.service`: that loads /etc/nftables.conf, which
    /// is a different file, and on a stock Debian or Ubuntu it flushes
    /// every other table on the host first.
    Firewall,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum UninstallTarget {
    /// The blocks in every site, the generated conf.d (or Apache's
    /// conf-enabled) files and /etc/stop-bots/nginx (or apache), or
    /// Traefik's routers file, for the web server the host settings choose.
    #[value(alias = "web-server")]
    Nginx,
    /// The live nft table or iptables chain, the boot unit and the
    /// firewall scripts.
    Firewall,
    /// /etc/cron.d/stop-bots.
    Cron,
    /// All of the above, and /etc/stop-bots once it is empty.
    All,
}

impl From<UninstallTarget> for stop_bots::uninstall::Target {
    fn from(target: UninstallTarget) -> Self {
        match target {
            UninstallTarget::Nginx => Self::Nginx,
            UninstallTarget::Firewall => Self::Firewall,
            UninstallTarget::Cron => Self::Cron,
            UninstallTarget::All => Self::All,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum UiModeArg {
    Simple,
    Advanced,
}

impl From<UiModeArg> for stop_bots::db::UiMode {
    fn from(arg: UiModeArg) -> Self {
        match arg {
            UiModeArg::Simple => stop_bots::db::UiMode::Simple,
            UiModeArg::Advanced => stop_bots::db::UiMode::Advanced,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum GeoModeArg {
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

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum CategoryArg {
    /// Vulnerability and SEO scanners
    Scanner,
    /// Search-engine crawlers
    Search,
    /// AI crawlers and assistants
    Ai,
}

impl From<CategoryArg> for stop_bots::db::Category {
    fn from(arg: CategoryArg) -> Self {
        use stop_bots::db::Category as C;
        match arg {
            CategoryArg::Scanner => C::Scanner,
            CategoryArg::Search => C::Search,
            CategoryArg::Ai => C::Ai,
        }
    }
}

/// `allowed`, `blocked`, or `default` — "follow whatever is above me",
/// which is the category for a bot and the host-wide policy for a site
/// override.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PolicyArg {
    Allowed,
    Blocked,
    /// Follow the category (for a bot) or the host-wide policy (for a
    /// site override)
    Default,
}

impl PolicyArg {
    /// `None` for `default`, which every override API spells as "no
    /// override".
    pub(crate) fn policy(self) -> Option<stop_bots::db::Policy> {
        match self {
            PolicyArg::Allowed => Some(stop_bots::db::Policy::Allowed),
            PolicyArg::Blocked => Some(stop_bots::db::Policy::Blocked),
            PolicyArg::Default => None,
        }
    }
}

/// A detector as the command line names it.
///
/// The stored ids (`block_scanners`, ...) are settings keys and cron-job
/// ids that can never change; these are the names a person types, and
/// the stored id is accepted too, as a hidden alias.
#[derive(Clone, Copy)]
pub(crate) struct DetectorArg(pub(crate) stop_bots::protection::Detector);

impl DetectorArg {
    pub(crate) const ALL: [DetectorArg; stop_bots::protection::Detector::ALL.len()] = {
        let all = stop_bots::protection::Detector::ALL;
        let mut out = [DetectorArg(all[0]); stop_bots::protection::Detector::ALL.len()];
        let mut i = 0;
        while i < all.len() {
            out[i] = DetectorArg(all[i]);
            i += 1;
        }
        out
    };

    /// The name `set-detector` and `--source` both take — one list, in
    /// `blocks::detector_name`, so the two can never disagree.
    pub(crate) fn name(self) -> &'static str {
        stop_bots::blocks::detector_name(self.0)
    }
}

impl ValueEnum for DetectorArg {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(
            clap::builder::PossibleValue::new(self.name())
                .help(self.0.spec().label)
                .alias(self.0.id()),
        )
    }
}

/// Named rather than numeric (`--response forbidden`, not `--response
/// 403`): "444" means nothing without knowing NGINX's non-standard codes,
/// and a bare number invites passing an arbitrary one this tool doesn't
/// support.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum BlockResponseArg {
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

/// A `--source` value: a source's name, its stored id, or `before-0.1`.
pub(crate) fn source_arg(value: &str) -> Result<SourceFilter, String> {
    SourceFilter::parse(value).ok_or_else(|| {
        let names: Vec<&str> = RuleSource::stored_sources()
            .into_iter()
            .map(RuleSource::name)
            .chain([stop_bots::blocks::LEGACY_NAME])
            .collect();
        format!("unknown source {value:?}; one of: {}", names.join(", "))
    })
}

pub(crate) fn parse_web_server(id: &str) -> std::result::Result<webserver::WebServer, String> {
    webserver::WebServer::from_id(id).ok_or_else(|| {
        format!(
            "not a web server stop-bots knows: choose one of {}",
            webserver::WebServer::ALL
                .map(webserver::WebServer::id)
                .join(", ")
        )
    })
}
