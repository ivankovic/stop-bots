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

//! Installing stop-bots as a system service — `stop-bots install web`.
//!
//! Everything else in this project writes a file and stops. This one
//! writes a unit, reloads systemd and starts a daemon, so it is the one
//! module whose mistakes are hard to undo by editing a file back. Three
//! rules follow from that, and they are why this is a module rather than
//! forty lines in `main.rs`:
//!
//! - **Every path it touches is a field on [`Layout`].** Nothing reads a
//!   constant at the point of use. That is what lets a test point the
//!   whole installer at a temp directory and assert the bytes, rather than
//!   asserting that the code would have written the right thing.
//! - **Nothing is written until every check has passed.** A half-install
//!   — directories made, unit missing — is worse than no install, because
//!   it looks done.
//! - **It refuses rather than overwrites.** A unit file someone has edited
//!   is a decision, not a stale artefact.
//!
//! ## Why the service runs as root
//!
//! Because the console rewrites `/etc/nginx`, writes the firewall script
//! to `/etc/stop-bots`, and runs `nginx -t` and `systemctl reload nginx`.
//! There is no unprivileged split that leaves the feature set intact —
//! dropping privilege would mean the web UI silently losing the ability to
//! apply anything, which is worse than saying plainly what it needs.
//!
//! The hardening directives in the generated unit are the ones that
//! survive that requirement. `ProtectSystem=full` would make `/etc`
//! read-only and break writing NGINX config on the first apply, an hour
//! after the unit started cleanly — so it is `ProtectSystem=yes`, which
//! only covers `/usr` and `/boot`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The unit this installs. Named for the thing it runs rather than the
/// project, because a later `install tui`-shaped target would want its own.
pub const WEB_UNIT: &str = "stop-bots-web.service";

/// The unit that re-applies the rendered firewall script at boot.
///
/// A unit of this project's own rather than Debian's `nftables.service`,
/// and the difference is the whole point. `nftables.service` loads
/// `/etc/nftables.conf`; this project writes `/etc/stop-bots/firewall.nft`.
/// Enabling the former restores a different file's rules and leaves these
/// ones gone — and on a stock Debian or Ubuntu, where that file still opens
/// with `flush ruleset`, enabling it also drops every table anything else
/// on the host has loaded (ufw, Docker, a geo-blocker) once per boot.
///
/// This unit applies one script, touches one table, and orders itself after
/// the services whose rules it must not race.
pub const FIREWALL_UNIT: &str = "stop-bots-firewall.service";

/// Where the installer writes, one field per path.
///
/// `system()` is the real one; `under()` puts the same tree inside a
/// prefix so a test can run the whole installer for real and read back
/// what it produced.
#[derive(Debug, Clone)]
pub struct Layout {
    /// `/etc/systemd/system`.
    pub unit_dir: PathBuf,
    /// `/var/lib/stop-bots` — holds the database, and so the password hash.
    pub state_dir: PathBuf,
    /// `/etc/stop-bots` — where the cron's `RenderFirewall` job writes.
    pub output_dir: PathBuf,
    /// The database the service will open.
    pub db_path: PathBuf,
    /// The `stop-bots` binary the unit's `ExecStart` will name.
    pub binary: PathBuf,
    /// The NGINX config root to scan.
    pub nginx_root: PathBuf,
    /// An explicit SSH log for the unit to name, or `None` to let the
    /// service find its own at runtime.
    ///
    /// `None` is the default, and the important one. This used to be a
    /// plain `PathBuf` defaulting to `/var/log/auth.log`, which baked a
    /// guess about the host into `ExecStart` at install time — and Debian
    /// 12 dropped rsyslog from default installs, so on a current Debian
    /// host that guess names a file which does not exist. The service then
    /// read nothing, found no SSH attempts, and said so as an empty panel
    /// rather than an error, because an unreadable log is "could not
    /// check", not "checked and clear".
    ///
    /// Passing no flag is not the same as passing this path. With no
    /// `--ssh-log`, `sshlog::find_default_source` tries `/var/log/auth.log`
    /// and `/var/log/secure`, *then* falls back to `journalctl`, which is
    /// where a journald-only host keeps its sshd lines. An explicit path
    /// deliberately skips that fallback — it means "read this, not whatever
    /// you can find" — so it belongs in the unit only when an operator
    /// asked for it.
    pub ssh_log: Option<PathBuf>,
    /// Exists only under systemd. The documented way to detect it — a
    /// `systemctl` binary on `PATH` proves only that the package is
    /// installed, which is true inside a Docker container that is not
    /// running systemd at all.
    pub systemd_marker: PathBuf,
    /// Exists only on Debian and its derivatives.
    pub debian_marker: PathBuf,
    /// The `systemctl` to run. A field rather than a bare `"systemctl"` at
    /// the point of use for the same reason every path here is one: it is
    /// what lets a test point [`activate`] at a script that records its
    /// arguments, instead of leaving the one function that starts a daemon
    /// untested. Injecting it beats putting a fake on `PATH`, which is
    /// process-global and races under a threaded test runner.
    pub systemctl: PathBuf,
    /// Whether this describes the running host rather than a staging tree,
    /// i.e. whether the prefix was `/`.
    ///
    /// `--prefix` writes a unit into a directory nothing will ever start,
    /// so the checks that are about what *this host's* systemd would do —
    /// see [`hidden_from_unit`] — have nothing to be true or false about
    /// there. Applying them anyway would refuse every `--prefix` run whose
    /// staging tree sits under `/tmp`, which is all of them. For the same
    /// reason [`install_firewall`] runs no `systemctl` unless this is set.
    real: bool,
}

impl Layout {
    pub fn system(binary: PathBuf) -> Self {
        Self::under(Path::new("/"), binary)
    }

    /// The same tree rooted at `prefix`. Every path is built by joining a
    /// *relative* path onto it, since `Path::join` with an absolute path
    /// discards the prefix entirely — the mistake that would make a test
    /// write to the developer's real `/etc`.
    pub fn under(prefix: &Path, binary: PathBuf) -> Self {
        Self {
            unit_dir: prefix.join("etc/systemd/system"),
            state_dir: prefix.join("var/lib/stop-bots"),
            output_dir: prefix.join("etc/stop-bots"),
            db_path: prefix.join("var/lib/stop-bots/db.sqlite3"),
            binary,
            nginx_root: prefix.join("etc/nginx"),
            ssh_log: None,
            systemd_marker: prefix.join("run/systemd/system"),
            debian_marker: prefix.join("etc/debian_version"),
            systemctl: PathBuf::from("systemctl"),
            // Derived, not a parameter: `main.rs` builds every layout —
            // prefixed or not — with `under`, so a flag a caller had to
            // remember to set would have been `false` on the one path
            // that matters. That is not hypothetical; it is what the first
            // version of this did, and the check below was dead in
            // production while every test passed.
            real: prefix == Path::new("/"),
        }
    }

    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(WEB_UNIT)
    }
}

/// What the caller asked for, beyond the paths.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Report every step and change nothing.
    pub dry_run: bool,
    /// Replace a unit file that exists and differs.
    pub force: bool,
    /// `systemctl enable --now` after installing. Off means the unit is
    /// written and enabled but not started.
    pub start: bool,
}

/// A `stop-bots` that lives in a build directory.
///
/// The most likely way to end up with a unit that works today and breaks
/// on the next `cargo clean`: `sudo cargo run -- install web` resolves
/// `current_exe()` to `target/debug/stop-bots`, writes that into
/// `ExecStart`, and nothing complains until the binary is gone.
pub fn is_build_artifact(binary: &Path) -> bool {
    let mut components = binary.components().peekable();
    while let Some(component) = components.next() {
        if component.as_os_str() != "target" {
            continue;
        }
        if let Some(next) = components.peek() {
            let next = next.as_os_str();
            if next == "debug" || next == "release" {
                return true;
            }
        }
    }
    false
}

/// Why the unit's own sandbox would not be able to see `binary`, if it
/// would not — named as the directive responsible.
///
/// [`preflight`] checking `binary.is_file()` is not the same question as
/// "can systemd execute this", because `ExecStart` is resolved inside the
/// mount namespace [`web_unit`] asks for, and that is a different
/// filesystem from the installer's:
///
/// - `ProtectHome=yes` replaces `/root`, `/home` and `/run/user` with
///   empty directories.
/// - `PrivateTmp=yes` gives the service a fresh `/tmp` and `/var/tmp`.
///
/// A binary in any of those exists for the installer and does not exist
/// for systemd. The failure is `status=203/EXEC` with `Unable to locate
/// executable: No such file or directory` — which sends whoever reads it
/// hunting for a missing file that is plainly, verifiably there. Reported
/// here in terms of what to do about it instead.
///
/// Found the hard way: `./stop-bots install web` run from `/root`, which
/// is exactly where someone who just downloaded a release binary is
/// standing.
pub fn hidden_from_unit(binary: &Path) -> Option<&'static str> {
    let path = binary.to_string_lossy();
    // Prefix matching on the path as written. `ExecStart` names this path
    // verbatim, so what matters is the literal string systemd will resolve
    // — not what it might canonicalise to.
    for prefix in ["/root/", "/home/", "/run/user/"] {
        if path.starts_with(prefix) {
            return Some("ProtectHome=yes");
        }
    }
    for prefix in ["/tmp/", "/var/tmp/"] {
        if path.starts_with(prefix) {
            return Some("PrivateTmp=yes");
        }
    }
    None
}

/// What to tell an operator whose binary the unit's sandbox would hide.
///
/// Pure and separately tested, because the *message* is the entire value
/// of this check: systemd's own report (`status=203/EXEC`, "No such file or
/// directory") is accurate and useless, and the thing that saves an
/// afternoon is naming the directive and giving a command to paste.
fn hidden_binary_error(binary: &Path, directive: &str) -> String {
    format!(
        "{} exists, but the unit sets {}, which hides that directory from the \
         service — systemd would fail with `status=203/EXEC` and \"No such file \
         or directory\" for a file that is plainly there.\n\n\
         Copy the binary somewhere the service can see, then re-run:\n\n    \
         install -m 755 {} /usr/local/bin/stop-bots\n    \
         /usr/local/bin/stop-bots install web\n\n\
         Or pass --binary with a path outside /root, /home and /tmp if the \
         binary already lives somewhere else.",
        binary.display(),
        directive,
        binary.display(),
    )
}

/// The unit file's exact contents.
///
/// Pure, and takes every path it names — so the golden test locks the
/// bytes an operator will actually get rather than a rendering of them.
pub fn web_unit(layout: &Layout) -> String {
    let mut exec = format!(
        "{} web --db {}",
        systemd_arg(&layout.binary),
        systemd_arg(&layout.db_path),
    );
    // Only when the operator named one. Omitting the flag is what leaves
    // the service free to try the log files and then `journalctl`; naming
    // a path here would pin it to that path forever, including on the
    // hosts that do not have it. See `Layout::ssh_log`.
    if let Some(path) = &layout.ssh_log {
        exec.push_str(&format!(" --ssh-log {}", systemd_arg(path)));
    }
    exec.push('\n');

    format!(
        "# Written by `stop-bots install web`. Re-running that command leaves an\n\
         # edited copy of this file alone and tells you so; `--force` replaces it.\n\
         #\n\
         # Settings deliberately absent from ExecStart: the bind address, the host\n\
         # allowlist, the path prefix, whether exposure is permitted, and the NGINX\n\
         # config root all live in the `settings` table, because the running server\n\
         # re-reads them. Adding a flag for one here gives it two sources of truth\n\
         # and the database wins on the next restart. Change them with\n\
         # `stop-bots web --save ...` and `stop-bots set-nginx-commands --root ...`.\n\
         [Unit]\n\
         Description=stop-bots web console\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         # Wants rather than Requires: the console is most worth looking at when\n\
         # NGINX is down, so it must not be stopped along with it.\n\
         After=network-online.target nginx.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=exec\n\
         ExecStart={exec}\
         Restart=on-failure\n\
         RestartSec=5s\n\
         \n\
         # Runs as root, and has to: it rewrites this host's NGINX config, writes\n\
         # the firewall script, and runs `nginx -t` and `systemctl reload nginx`.\n\
         # The directives below are the hardening that survives that. Notably\n\
         # absent is ProtectSystem=full, which would make /etc read-only and break\n\
         # the first apply — an hour after the unit started cleanly.\n\
         NoNewPrivileges=yes\n\
         PrivateTmp=yes\n\
         ProtectSystem=yes\n\
         ProtectHome=yes\n\
         ProtectClock=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         SystemCallArchitectures=native\n\
         # AF_UNIX for the dbus socket `systemctl reload nginx` talks over,\n\
         # AF_INET/AF_INET6 for the console itself and the list downloads,\n\
         # and AF_NETLINK because the console applies the firewall script:\n\
         # both `nft` and Debian's nft-backed `iptables` talk to the kernel\n\
         # over netlink. Without it the apply fails with\n\
         # \"Unable to initialize Netlink socket: Address family not\n\
         # supported by protocol\", which names neither this file nor the\n\
         # reason. This line said the opposite until applying arrived; a\n\
         # comment asserting what a service does not need is a comment that\n\
         # goes stale the moment it starts needing it.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n\
         # The database holds the console's password hash.\n\
         UMask=0077\n\
         \n\
         # Three that `systemd-analyze security` will still flag, each on\n\
         # purpose. User= — see above. CapabilityBoundingSet= — root's ability\n\
         # to write a file it does not own *is* CAP_DAC_OVERRIDE, so trimming\n\
         # the set is how you get a service that starts cleanly and cannot\n\
         # write /etc/nginx an hour later. MemoryDenyWriteExecute= — safe for a\n\
         # Rust binary with no JIT, but nobody has run this unit with it on,\n\
         # and an untested sandbox directive is not hardening.\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// `path` as one argument of an `ExecStart=` line.
///
/// systemd does not hand `ExecStart` to a shell; it splits it itself, by
/// the rules in systemd.syntax(7) and systemd.service(5), and they differ
/// from a shell's in the two places that matter here:
///
/// - `%` starts a specifier (`%h`, `%n`, ...) and is expanded everywhere,
///   quoted or not, so a literal one is `%%`. `$` likewise starts a
///   variable, and a literal one is `$$`.
/// - An argument is split on whitespace unless double-quoted, and inside
///   the quotes `\` and `"` are C-style escapes.
///
/// So a path with a space used to become two arguments — the binary
/// named `/opt/stop` — and one with `%` had part of it replaced. An
/// ordinary path comes back unchanged, which keeps the golden unit the
/// bytes it always was.
fn systemd_arg(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let needs_quotes = raw
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\'));
    let mut out = String::with_capacity(raw.len() + 2);
    if needs_quotes {
        out.push('"');
    }
    for c in raw.chars() {
        match c {
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let mut bytes = [0u8; 4];
                for byte in c.encode_utf8(&mut bytes).bytes() {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
            c => out.push(c),
        }
    }
    if needs_quotes {
        out.push('"');
    }
    out
}

/// One thing the installer did, or would do under `--dry-run`.
///
/// Returned rather than printed so that the test asserts on the same list
/// the operator reads, instead of on side effects that have to be
/// rediscovered from the filesystem.
pub type Steps = Vec<String>;

/// Everything that must hold before a single byte is written.
///
/// Separate from [`install_web`] and run first, in full: a check that
/// fails after the directories exist leaves a half-install, which is worse
/// than no install because it looks finished.
pub fn preflight(layout: &Layout, options: &Options) -> Result<()> {
    if !layout.systemd_marker.is_dir() {
        anyhow::bail!(
            "this host is not running systemd ({} does not exist), and the only \
             service manager `install web` knows how to write for is systemd.\n\n\
             Run the console under whatever this host does use, with:\n\n    \
             {} web",
            layout.systemd_marker.display(),
            layout.binary.display()
        );
    }

    if !layout.debian_marker.exists() {
        anyhow::bail!(
            "this does not look like Debian ({} does not exist).\n\n\
             The unit `install web` writes is almost certainly correct on any \
             systemd distribution — it names no distribution-specific path, and \
             the service finds its own logs at runtime — but nobody has run it \
             anywhere else. Write the unit by hand, or open an issue saying \
             which distribution this is.",
            layout.debian_marker.display(),
        );
    }

    // Before `is_file`, because a relative path can be a real file and
    // still produce a unit systemd refuses outright: it requires an
    // absolute `ExecStart`, and rejects the unit at load time rather than
    // at start time, which is a different and more confusing failure.
    // Reachable only via `--binary`; `current_exe` is always absolute.
    if !layout.binary.is_absolute() {
        anyhow::bail!(
            "--binary needs an absolute path, and {} is relative. systemd \
             requires an absolute ExecStart and would refuse to load the unit \
             at all.\n\n\
             Did you mean:\n\n    --binary {}",
            layout.binary.display(),
            std::env::current_dir()
                .map(|cwd| cwd.join(&layout.binary))
                .unwrap_or_else(|_| layout.binary.clone())
                .display()
        );
    }

    if !layout.binary.is_file() {
        anyhow::bail!(
            "{} is not a file, so the unit's ExecStart would point at nothing",
            layout.binary.display()
        );
    }

    // After the `is_file` check, and a different question: that one asks
    // the installer's filesystem, this one asks the unit's. See
    // `hidden_from_unit`.
    if let Some(directive) = hidden_from_unit(&layout.binary).filter(|_| layout.real) {
        anyhow::bail!("{}", hidden_binary_error(&layout.binary, directive));
    }

    // Checked by trying, not by comparing euid to 0: what matters is
    // whether this process can write there, and a root-in-a-container or
    // CAP_DAC_OVERRIDE case answers that differently from `id -u`.
    if !options.dry_run {
        writable(&layout.unit_dir).with_context(|| {
            format!(
                "cannot write to {} — `install web` needs root",
                layout.unit_dir.display()
            )
        })?;
    }

    Ok(())
}

/// Whether this process can create a file in `dir`, answered by doing it.
fn writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let probe = dir.join(".stop-bots-install-probe");
    std::fs::write(&probe, b"").with_context(|| format!("writing {}", probe.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Writes the unit and the directories it depends on.
///
/// Does not run `systemctl` — that is [`activate`], kept separate so the
/// filesystem half is testable without a service manager and so a
/// `--dry-run` can describe both without a special case in either.
/// The systemd unit that re-applies `script` at boot.
///
/// `After=` names the two services whose rules this must not race. Docker
/// rewrites its chains on every start, and ufw loads its own tables; a
/// script applied before either is still there afterwards, because it uses
/// its own table and never flushes the ruleset, but ordering after them
/// keeps the boot-time sequence the same as the one an operator sees by
/// hand. `Wants=network-online.target` rather than `Requires=`: a ruleset
/// is worth loading even on a host that came up without a network.
///
/// `backend` decides both the script and what runs it, for the reason
/// `firewall::output_path` gives: the backend is the one source of truth,
/// and a host rendering iptables has a `firewall.nft` that is stale or
/// absent. A boot unit that always loaded that file restored the wrong
/// rules, or none.
pub fn firewall_unit(backend: crate::firewall::FirewallBackend, script: &Path) -> String {
    let exec = match backend {
        crate::firewall::FirewallBackend::Nftables => {
            format!("/usr/sbin/nft -f {}", systemd_arg(script))
        }
        crate::firewall::FirewallBackend::Iptables => format!("/bin/sh {}", systemd_arg(script)),
    };
    format!(
        "# Written by `stop-bots install firewall`. Re-running that command leaves\n\
         # an edited copy of this file alone and tells you so; `--force` replaces it.\n\
         #\n\
         # Deliberately NOT nftables.service: that unit loads /etc/nftables.conf,\n\
         # which is not this file, so it would restore a different ruleset entirely\n\
         # -- and on a stock Debian or Ubuntu it would also `flush ruleset` at boot,\n\
         # dropping whatever else manages tables on this host.\n\
         [Unit]\n\
         Description=Apply the stop-bots firewall ruleset\n\
         Documentation=https://github.com/ivankovic/stop-bots\n\
         After=docker.service ufw.service network-online.target\n\
         Wants=network-online.target\n\
         ConditionPathExists={script}\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         ExecStart={exec}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        // A condition takes the rest of the line as the path, so it is not
        // quoted; it does expand specifiers, so `%` still has to be `%%`.
        script = script.display().to_string().replace('%', "%%")
    )
}

/// The backend the database at `db_path` renders for, without creating a
/// database that is not there: an install, and above all a `--dry-run`,
/// has no business leaving one behind. No database means nothing has
/// chosen a backend yet, which is the default's case in
/// `firewall::stored_backend` too.
fn stored_backend_at(db_path: &Path) -> Result<crate::firewall::FirewallBackend> {
    if !db_path.is_file() {
        return Ok(crate::firewall::FirewallBackend::Nftables);
    }
    let db = crate::db::Db::open(db_path)
        .with_context(|| format!("reading the firewall backend from {}", db_path.display()))?;
    crate::firewall::stored_backend(&db)
}

/// Writes [`firewall_unit`] and enables it. Mirrors [`install_web`],
/// including its refusal to overwrite a unit somebody has edited.
///
/// Under `--prefix` it writes the unit and stops, as `install web` does:
/// the unit is somewhere systemd never looks, and running the real
/// `systemctl daemon-reload`/`enable` would either claim a unit took
/// effect that did not, or enable a stale one of the same name.
pub fn install_firewall(layout: &Layout, options: &Options) -> Result<Steps> {
    let backend = stored_backend_at(&layout.db_path)?;
    let script = crate::firewall::default_output_path(backend);
    let unit = firewall_unit(backend, &script);
    let unit_path = layout.unit_dir.join(FIREWALL_UNIT);
    let existing = std::fs::read_to_string(&unit_path).ok();

    if let Some(existing) = &existing {
        if existing != &unit && !options.force {
            anyhow::bail!(
                "{} already exists and differs from what this would write.\n\n\
                 If you edited it, that edit is why this stopped. Pass --force to \
                 replace it, or diff it against:\n\n    \
                 {} install firewall --dry-run",
                unit_path.display(),
                layout.binary.display()
            );
        }
    }

    let mut steps = Steps::new();
    steps.push(format!("write {}", unit_path.display()));
    if !options.dry_run {
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&unit_path, &unit)?;
    }

    // Not started. The script may not exist yet, and starting a unit that
    // loads firewall rules is the one step an operator should take after
    // reading what it would load -- the same reason `render-firewall` does
    // not apply what it writes.
    if layout.real {
        steps.push("systemctl daemon-reload".to_string());
        steps.push(format!("systemctl enable {FIREWALL_UNIT}"));
        if !options.dry_run {
            systemctl(layout, &["daemon-reload"])?;
            systemctl(layout, &["enable", FIREWALL_UNIT])?;
        }
    } else {
        steps.push(format!(
            "skipping systemctl: {} is not a path systemd reads",
            layout.unit_dir.display()
        ));
    }
    steps.push(format!(
        "not started: run `{} {}` yourself once you have read it",
        backend.apply_command(),
        script.display()
    ));

    Ok(steps)
}

pub fn install_web(layout: &Layout, options: &Options) -> Result<Steps> {
    preflight(layout, options)?;

    let unit = web_unit(layout);
    let unit_path = layout.unit_path();
    let existing = std::fs::read_to_string(&unit_path).ok();

    // Refusing beats overwriting: a unit somebody has edited is a
    // decision. Byte-identical is a no-op, which is what makes re-running
    // `install web` safe.
    if let Some(existing) = &existing {
        if existing != &unit && !options.force {
            anyhow::bail!(
                "{} already exists and differs from what this would write.\n\n\
                 If you edited it, that edit is why this stopped. Pass --force to \
                 replace it, or diff it against:\n\n    \
                 {} install web --dry-run",
                unit_path.display(),
                layout.binary.display()
            );
        }
    }

    let mut steps = Steps::new();

    for (dir, mode) in [(&layout.state_dir, 0o700), (&layout.output_dir, 0o755)] {
        if dir.is_dir() {
            steps.push(format!("{} already exists", dir.display()));
        } else {
            steps.push(format!("create {} ({mode:04o})", dir.display()));
            if !options.dry_run {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        // Set unconditionally, not only on create: 0700 on the state
        // directory is what keeps the password hash off a shared host, and
        // a directory that predates this (from a `stop-bots` run as root)
        // will be 0755.
        if !options.dry_run {
            set_mode(dir, mode)?;
        }
    }

    match &existing {
        Some(existing) if existing == &unit => {
            steps.push(format!("{} is already up to date", unit_path.display()));
        }
        Some(_) => steps.push(format!("replace {} (--force)", unit_path.display())),
        None => steps.push(format!("write {}", unit_path.display())),
    }
    if !options.dry_run && existing.as_deref() != Some(unit.as_str()) {
        std::fs::write(&unit_path, &unit)
            .with_context(|| format!("writing {}", unit_path.display()))?;
    }

    Ok(steps)
}

/// Tightens the database file itself to 0600.
///
/// The state *directory* is already 0700, which is what actually keeps the
/// console's password hash off a shared host — but the file inside it is
/// created by whichever process got there first, under that process's
/// umask, and so is usually 0644. The unit's `UMask=0077` does not help:
/// it applies to files the *service* creates, and this one is created by
/// the installer. A mode travels with a file through a backup or a `cp`
/// in a way the directory it used to live in does not.
///
/// Called after the database has been written, because it has to exist.
pub fn secure_database(path: &Path) -> Result<()> {
    if path.exists() {
        set_mode(path, 0o600)?;
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode {mode:04o} on {}", path.display()))
}

/// Tells systemd about the unit, and optionally starts it.
///
/// `systemctl` is run directly rather than through a shell, the same rule
/// [`crate::nginx`] follows for its configurable commands: nothing here is
/// operator-supplied, but the habit is what keeps it that way.
pub fn activate(layout: &Layout, options: &Options) -> Result<Steps> {
    let mut steps = Steps::new();

    steps.push("systemctl daemon-reload".to_string());
    if !options.dry_run {
        systemctl(layout, &["daemon-reload"])?;
    }

    // `enable` without `--now` leaves the unit set to start at the next
    // boot but not running, which is what --no-start is for.
    let action: &[&str] = if options.start {
        &["enable", "--now", WEB_UNIT]
    } else {
        &["enable", WEB_UNIT]
    };
    steps.push(format!("systemctl {}", action.join(" ")));
    if !options.dry_run {
        systemctl(layout, action)?;
    }

    Ok(steps)
}

fn systemctl(layout: &Layout, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(&layout.systemctl)
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "failed to run `{} {}`",
                layout.systemctl.display(),
                args.join(" ")
            )
        })?;
    if !output.status.success() {
        // `enable --now` is two operations, and the first one sticks even
        // when the second fails: the unit ends up enabled, failing, and
        // enabled again at the next boot. Systemd's own start limit stops
        // the restart loop after a few tries, so this is untidy rather
        // than dangerous — but an operator reading this needs to be told
        // the state they are now in, and the one command that undoes it.
        let cleanup = if args.contains(&"enable") {
            format!(
                "\n\nThe unit was written and enabled before this failed, so it will \
                 try again at the next boot. To undo that:\n\n    \
                 systemctl disable --now {WEB_UNIT}"
            )
        } else {
            String::new()
        };
        anyhow::bail!(
            "`systemctl {}` exited with {}: {}{}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
            cleanup
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout with no temp directory in it, so the golden file below is
    /// the bytes a real Debian host gets rather than a rendering of them.
    fn system_layout() -> Layout {
        Layout::system(PathBuf::from("/usr/local/bin/stop-bots"))
    }

    fn staged(dir: &Path) -> Layout {
        std::fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("etc/debian_version"), "13.1\n").unwrap();
        let binary = dir.join("stop-bots");
        std::fs::write(&binary, b"#!/bin/true\n").unwrap();
        Layout::under(dir, binary)
    }

    /// A fake `systemctl` running `body`, wired into `layout`.
    ///
    /// Injected through `Layout` rather than placed on `PATH`: `PATH` is
    /// process-global and a threaded test runner would race on it.
    fn with_fake_systemctl(layout: &mut Layout, dir: &Path, body: &str) {
        let script = dir.join("fake-systemctl");
        crate::testing::write_script(&script, body);
        layout.systemctl = script;
    }

    /// The exact unit an operator gets. A golden rather than substring
    /// assertions because the failure that matters is a directive quietly
    /// changing meaning — `ProtectSystem=yes` becoming `full` makes /etc
    /// read-only and breaks the first NGINX apply, an hour after the unit
    /// started cleanly.
    #[test]
    fn the_generated_unit_is_what_it_was() {
        crate::golden::assert_golden("stop-bots-web.service", &web_unit(&system_layout()));
    }

    /// The unit must not name an SSH log unless asked to.
    ///
    /// This is the regression that took a production host out quietly. The
    /// unit used to carry `--ssh-log /var/log/auth.log` always, and on a
    /// Debian 12 host — where rsyslog is no longer installed by default and
    /// sshd logs only to the journal — that file does not exist. An
    /// explicit path skips the `journalctl` fallback by design, so the
    /// service read nothing: the console's SSH panel sat empty and the
    /// brute-force detector, which runs inside that same service, found
    /// nothing to block. Neither said anything was wrong, because an
    /// unreadable log means "could not check".
    #[test]
    fn the_unit_names_no_ssh_log_by_default() {
        let unit = web_unit(&system_layout());

        assert!(
            !unit.contains("--ssh-log"),
            "the unit pinned an SSH log nobody asked for; the service has to be \
             free to fall back to journalctl. Unit was:\n{unit}"
        );
    }

    /// The flag is still there for the host where the log really is
    /// somewhere else — it just has to be asked for.
    #[test]
    fn an_explicit_ssh_log_still_reaches_the_unit() {
        let mut layout = system_layout();
        layout.ssh_log = Some(PathBuf::from("/srv/logs/auth.log"));

        assert!(
            web_unit(&layout).contains("--ssh-log /srv/logs/auth.log"),
            "an operator who named a log did not get it"
        );
    }

    /// `Path::join` with an absolute path throws the prefix away, which
    /// would point a `--prefix` install at the developer's real /etc.
    #[test]
    fn every_path_in_a_prefixed_layout_stays_inside_the_prefix() {
        let prefix = Path::new("/tmp/stop-bots-test-prefix");
        let layout = Layout::under(prefix, PathBuf::from("/usr/local/bin/stop-bots"));

        for path in [
            &layout.unit_dir,
            &layout.state_dir,
            &layout.output_dir,
            &layout.db_path,
            &layout.nginx_root,
            &layout.systemd_marker,
            &layout.debian_marker,
        ] {
            assert!(
                path.starts_with(prefix),
                "{} escaped the prefix",
                path.display()
            );
        }
    }

    #[test]
    fn a_binary_under_a_build_directory_is_recognised() {
        for path in [
            "/home/me/src/stop-bots/target/debug/stop-bots",
            "/home/me/src/stop-bots/target/release/stop-bots",
            "target/debug/stop-bots",
        ] {
            assert!(is_build_artifact(Path::new(path)), "{path}");
        }
        for path in [
            "/usr/local/bin/stop-bots",
            "/usr/bin/stop-bots",
            // A directory that merely contains the word, and a `target`
            // that is not a cargo one.
            "/opt/target-practice/stop-bots",
            "/srv/target/bin/stop-bots",
        ] {
            assert!(!is_build_artifact(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn preflight_refuses_a_host_without_systemd() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_dir_all(&layout.systemd_marker).unwrap();

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(
            err.to_string().contains("not running systemd"),
            "was: {err}"
        );
    }

    #[test]
    fn preflight_refuses_a_host_that_is_not_debian() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_file(&layout.debian_marker).unwrap();

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(
            err.to_string().contains("not look like Debian"),
            "was: {err}"
        );
    }

    #[test]
    fn a_dry_run_writes_nothing_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let options = Options {
            dry_run: true,
            ..Options::default()
        };

        let steps = install_web(&layout, &options).unwrap();

        assert!(!steps.is_empty(), "a dry run still describes the plan");
        assert!(!layout.unit_path().exists(), "the dry run wrote the unit");
        assert!(
            !layout.state_dir.exists(),
            "the dry run made the state directory"
        );
        assert!(
            !layout.output_dir.exists(),
            "the dry run made the output directory"
        );
    }

    #[test]
    fn installing_writes_the_unit_and_locks_down_the_state_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());

        install_web(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
        // 0700 because this directory holds the database, and the database
        // holds the console's password hash.
        let mode = std::fs::metadata(&layout.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "state dir was {mode:04o}");
        let mode = std::fs::metadata(&layout.output_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "output dir was {mode:04o}");
    }

    /// A state directory left at 0755 by an earlier root-run `stop-bots`
    /// has to be tightened, not left because it already exists.
    #[test]
    fn installing_tightens_a_state_directory_that_already_exists() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.state_dir).unwrap();
        std::fs::set_permissions(&layout.state_dir, std::fs::Permissions::from_mode(0o755))
            .unwrap();

        install_web(&layout, &Options::default()).unwrap();

        let mode = std::fs::metadata(&layout.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "state dir was left at {mode:04o}");
    }

    /// A `systemctl` that records its arguments and succeeds, so the one
    /// function here that starts a daemon is covered by something other
    /// than hope. Written into the layout rather than onto `PATH`: `PATH`
    /// is process-global and would race a threaded test runner.
    fn recording_systemctl(dir: &Path) -> (PathBuf, PathBuf) {
        let log = dir.join("systemctl.log");
        let script = dir.join("fake-systemctl");
        crate::testing::write_script(
            &script,
            &format!("echo \"$@\" >> {}\nexit 0", log.display()),
        );
        (script, log)
    }

    /// The exact calls, in order. An argument-order slip or a typo in the
    /// unit name is invisible to every other test here, because they all
    /// go through `--prefix`, which skips systemctl entirely.
    #[test]
    fn activating_reloads_systemd_then_enables_and_starts_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = activate(
            &layout,
            &Options {
                start: true,
                ..Options::default()
            },
        )
        .unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            calls, "daemon-reload\nenable --now stop-bots-web.service\n",
            "steps reported were: {steps:?}"
        );
    }

    /// `--no-start` enables the unit for the next boot without running it
    /// now — so no `--now`.
    #[test]
    fn activating_without_start_enables_but_does_not_run_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        activate(&layout, &Options::default()).unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(calls, "daemon-reload\nenable stop-bots-web.service\n");
    }

    /// A dry run must not reach systemd either — that is the whole promise
    /// of the flag on the one command that starts a daemon.
    #[test]
    fn a_dry_run_does_not_call_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = activate(
            &layout,
            &Options {
                dry_run: true,
                start: true,
                ..Options::default()
            },
        )
        .unwrap();

        assert!(!log.exists(), "systemctl ran during a dry run");
        assert!(
            steps.iter().any(|s| s.contains("enable --now")),
            "a dry run still describes what it would do: {steps:?}"
        );
    }

    /// A failing `systemctl` is an error, not a step that quietly reports
    /// success — the unit is written but the service is not running, and
    /// the operator has to know that.
    #[test]
    fn a_failing_systemctl_stops_the_install() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        with_fake_systemctl(&mut layout, dir.path(), "echo 'no such unit' >&2\nexit 1");

        let err = activate(&layout, &Options::default()).unwrap_err();

        assert!(err.to_string().contains("no such unit"), "was: {err}");
    }

    #[test]
    fn re_installing_over_an_identical_unit_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();

        let steps = install_web(&layout, &Options::default()).unwrap();

        assert!(
            steps.iter().any(|s| s.contains("already up to date")),
            "was: {steps:?}"
        );
    }

    /// The point of the refusal: an operator who edited `ExecStart` should
    /// not lose it to someone re-running the installer.
    #[test]
    fn an_edited_unit_is_refused_rather_than_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();
        let edited = format!("{}\n# a deliberate local edit\n", web_unit(&layout));
        std::fs::write(layout.unit_path(), &edited).unwrap();

        let err = install_web(&layout, &Options::default()).unwrap_err();

        assert!(err.to_string().contains("--force"), "was: {err}");
        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            edited,
            "the edit was overwritten anyway"
        );
    }

    #[test]
    fn force_replaces_an_edited_unit() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_web(&layout, &Options::default()).unwrap();
        std::fs::write(layout.unit_path(), "# entirely different\n").unwrap();

        install_web(
            &layout,
            &Options {
                force: true,
                ..Options::default()
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.unit_path()).unwrap(),
            web_unit(&layout)
        );
    }
    /// The bug this check exists for, reported from a real Debian host:
    /// `./stop-bots install web` run from `/root` wrote
    /// `ExecStart=/root/stop-bots`, which systemd could not execute
    /// because the unit's own `ProtectHome=yes` makes `/root` empty for
    /// the service. `is_file()` said yes; systemd said
    /// `status=203/EXEC`, `No such file or directory`.
    #[test]
    fn the_hidden_binary_message_names_the_directive_and_the_fix() {
        let message = hidden_binary_error(Path::new("/root/stop-bots"), "ProtectHome=yes");

        assert!(
            message.contains("ProtectHome=yes"),
            "the message must name the directive responsible: {message}"
        );
        assert!(
            message.contains("install -m 755 /root/stop-bots /usr/local/bin/stop-bots"),
            "the message must be copy-pasteable: {message}"
        );
        assert!(
            message.contains("203/EXEC"),
            "it must connect to what systemd actually printed: {message}"
        );
    }

    /// End to end through `preflight`, using the tempdir's own binary —
    /// which is under the temporary directory `PrivateTmp=yes` replaces,
    /// so it is a file that exists and that the unit could not execute.
    /// Skipped, loudly, if this machine's temp directory is somewhere the
    /// unit does not hide.
    #[test]
    fn preflight_refuses_a_binary_the_units_own_sandbox_would_hide() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        assert!(layout.binary.is_file(), "the fixture binary must exist");
        let Some(directive) = hidden_from_unit(&layout.binary) else {
            eprintln!(
                "skipped: {} is not a directory the unit hides",
                layout.binary.display()
            );
            return;
        };

        let err = preflight(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains(directive), "was: {err:#}");
    }

    /// Every directory the unit replaces or privatises, checked against
    /// the unit text itself so adding a sandbox directive that hides
    /// somewhere new cannot silently outrun this list.
    #[test]
    fn every_directory_the_unit_hides_is_refused() {
        for (path, directive) in [
            ("/root/stop-bots", "ProtectHome=yes"),
            ("/home/marko/stop-bots", "ProtectHome=yes"),
            ("/run/user/1000/stop-bots", "ProtectHome=yes"),
            ("/tmp/stop-bots", "PrivateTmp=yes"),
            ("/var/tmp/stop-bots", "PrivateTmp=yes"),
        ] {
            assert_eq!(
                hidden_from_unit(Path::new(path)),
                Some(directive),
                "{path} should be refused because of {directive}"
            );
            let dir = tempfile::tempdir().unwrap();
            let layout = staged(dir.path());
            assert!(
                web_unit(&layout).contains(directive),
                "{directive} is no longer in the unit, so this refusal is stale"
            );
        }
    }

    #[test]
    fn an_installed_binary_is_not_refused() {
        for path in [
            "/usr/local/bin/stop-bots",
            "/usr/bin/stop-bots",
            "/opt/stop-bots/stop-bots",
            // Not a prefix match on "/root": a sibling directory whose
            // name merely starts the same way is a different place.
            "/rootfs/stop-bots",
        ] {
            assert_eq!(hidden_from_unit(Path::new(path)), None, "{path}");
        }
    }

    /// `enable --now` half-succeeds: the enable sticks, the start does
    /// not. An operator who sees only "exited with 1" is not told they now
    /// have a unit that will try again at the next boot.
    #[test]
    fn a_failed_enable_says_how_to_undo_the_half_that_worked() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        // `daemon-reload` succeeds and `enable` fails — the real shape of
        // this failure, and the reason the message has something to say.
        with_fake_systemctl(
            &mut layout,
            dir.path(),
            "case \"$1\" in enable) echo 'Job failed' >&2; exit 1 ;; *) exit 0 ;; esac",
        );

        let err = activate(&layout, &Options::default()).unwrap_err();

        let message = format!("{err:#}");
        assert!(
            message.contains(&format!("systemctl disable --now {WEB_UNIT}")),
            "message was: {message}"
        );
    }

    // ---- install firewall ----

    /// `--prefix` writes a unit systemd will never read, so telling the
    /// real systemd to reload and enable it is at best a lie about what
    /// happened and at worst enables a stale unit of the same name.
    #[test]
    fn install_firewall_under_a_prefix_does_not_run_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        let steps = install_firewall(&layout, &Options::default()).unwrap();

        assert!(!log.exists(), "systemctl ran for a prefixed install");
        assert!(
            layout.unit_dir.join(FIREWALL_UNIT).is_file(),
            "the unit should still be written"
        );
        assert!(
            steps.iter().any(|s| s.contains("skipping systemctl")),
            "steps: {steps:?}"
        );
    }

    /// And on the real host, it does.
    #[test]
    fn install_firewall_on_the_host_reloads_and_enables_the_unit() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.real = true;
        let (script, log) = recording_systemctl(dir.path());
        layout.systemctl = script;

        install_firewall(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            format!("daemon-reload\nenable {FIREWALL_UNIT}\n")
        );
    }

    /// The boot unit loads the script the stored backend writes. On an
    /// iptables host `firewall.nft` is stale or absent, and loading it at
    /// boot restores the wrong rules or none.
    #[test]
    fn the_boot_unit_follows_the_stored_backend() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            crate::firewall::store_backend(&db, crate::firewall::FirewallBackend::Iptables)
                .unwrap();
        }

        install_firewall(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(FIREWALL_UNIT)).unwrap();
        for line in [
            "ExecStart=/bin/sh /etc/stop-bots/firewall.sh",
            "ConditionPathExists=/etc/stop-bots/firewall.sh",
        ] {
            assert!(unit.contains(line), "missing {line:?} in:\n{unit}");
        }
        assert!(!unit.contains("firewall.nft"), "unit was:\n{unit}");
    }

    /// With no database yet, the default backend is the answer — the same
    /// one `firewall::stored_backend` gives.
    #[test]
    fn the_boot_unit_defaults_to_nftables() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;

        install_firewall(&layout, &Options::default()).unwrap();

        let unit = std::fs::read_to_string(layout.unit_dir.join(FIREWALL_UNIT)).unwrap();
        assert!(
            unit.contains("ExecStart=/usr/sbin/nft -f /etc/stop-bots/firewall.nft"),
            "unit was:\n{unit}"
        );
        assert!(
            !layout.db_path.exists(),
            "reading the backend created a database"
        );
    }

    // ---- quoting in the unit ----

    /// systemd splits `ExecStart` on whitespace and expands `%` specifiers
    /// in it, so a path with either has to be quoted and escaped or the
    /// unit runs something else.
    #[test]
    fn exec_start_quotes_and_escapes_paths_systemd_would_misread() {
        let mut layout = system_layout();
        layout.binary = PathBuf::from("/opt/stop bots/stop-bots");
        layout.db_path = PathBuf::from("/var/lib/100%/db.sqlite3");
        layout.ssh_log = Some(PathBuf::from("/srv/a \"b\"\\c.log"));

        let unit = web_unit(&layout);

        let exec = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert_eq!(
            exec,
            r#"ExecStart="/opt/stop bots/stop-bots" web --db /var/lib/100%%/db.sqlite3 --ssh-log "/srv/a \"b\"\\c.log""#
        );
    }

    #[test]
    fn systemd_arg_leaves_an_ordinary_path_alone_and_quotes_the_rest() {
        for (raw, quoted) in [
            ("/usr/local/bin/stop-bots", "/usr/local/bin/stop-bots"),
            ("/a b", "\"/a b\""),
            ("/a\tb", "\"/a\\tb\""),
            ("/a$b", "/a$$b"),
            ("/100%", "/100%%"),
            ("/a\"b", "\"/a\\\"b\""),
            ("/a\\b", "\"/a\\\\b\""),
            ("/a'b", "\"/a'b\""),
        ] {
            assert_eq!(systemd_arg(Path::new(raw)), quoted, "{raw:?}");
        }
    }

    /// systemd rejects a relative `ExecStart` when it *loads* the unit,
    /// not when it starts it — so this failure does not even look like a
    /// failed service.
    #[test]
    fn preflight_refuses_a_relative_binary_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.binary = PathBuf::from("stop-bots");

        let err = preflight(&layout, &Options::default()).unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("absolute"), "was: {message}");
        assert!(
            message.contains("--binary /"),
            "it should suggest the absolute form: {message}"
        );
    }
}
