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

//! Installing what keeps stop-bots running without anyone at a terminal:
//! `stop-bots install cron` and `stop-bots install firewall`.
//!
//! - [`install_cron`] writes [`CRON_FILE`], which runs `stop-bots tick`
//!   once a minute: every job on the schedule the TUI keeps while it is
//!   open, the detectors each minute and the lists weekly, applying only
//!   what the two auto-apply switches allow.
//! - [`install_firewall`] writes [`FIREWALL_UNIT`], which loads the applied
//!   firewall script at boot.
//!
//! Nothing here listens on a network or starts a daemon. Three rules still
//! hold, because these files run as root on a timer and at boot:
//!
//! - **Every path it touches is a field on [`Layout`],** so a test can point
//!   the whole installer at a temp directory and assert the bytes.
//! - **Nothing is written until every check has passed.**
//! - **It refuses rather than overwrites.** A file someone has edited is a
//!   decision, not a stale artefact.
//!
//! ## Telling an edited file from an old one
//!
//! "Differs from what this version would write" is not "edited": every
//! release that changes a template would read as an edit on every host. So
//! each file records the hash of its own text on a [`TEMPLATE_MARKER`]
//! line. One whose text still hashes to it is exactly as stop-bots wrote
//! it, whichever version that was, and is replaced without asking; one
//! that doesn't was edited. Firewall units from 0.0.x carry no hash and are
//! compared against every text those releases wrote — see [`legacy`].

pub mod legacy;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The start of the line a generated file records its template hash on:
/// the SHA-256, in hex, of the file's whole text without this line.
///
/// **Frozen.** Every later release looks for exactly this to decide
/// whether a file on disk is one it may replace. Renaming it would make
/// every file written until then look edited, which is the failure this
/// line exists to prevent.
pub const TEMPLATE_MARKER: &str = "# stop-bots-template: ";

/// The unit that re-applies the rendered firewall script at boot.
///
/// A unit of this project's own rather than Debian's `nftables.service`,
/// and the difference is the whole point. `nftables.service` loads
/// `/etc/nftables.conf`; this project writes `/etc/stop-bots/firewall.nft`.
/// Enabling the former restores a different file's rules and leaves these
/// ones gone — and on a stock Debian or Ubuntu, where that file still opens
/// with `flush ruleset`, enabling it also drops every table anything else
/// on the host has loaded (ufw, Docker, a geo-blocker) once per boot.
pub const FIREWALL_UNIT: &str = "stop-bots-firewall.service";

/// The cron file's name in `/etc/cron.d`. cron ignores a name with a dot
/// in it, so it has none.
pub const CRON_FILE: &str = "stop-bots";

/// Where the installer writes, one field per path.
///
/// `system()` is the real one; `under()` puts the same tree inside a
/// prefix so a test can run the whole installer for real and read back
/// what it produced.
#[derive(Debug, Clone)]
pub struct Layout {
    /// `/etc/systemd/system`.
    pub unit_dir: PathBuf,
    /// `/etc/cron.d`.
    pub cron_dir: PathBuf,
    /// Where a cron daemon's binary would be, any one of which will do:
    /// Debian's `cron`, and cronie's `crond`. The directory alone proves
    /// nothing — other packages ship files into it on hosts with no cron
    /// at all, as Debian 13's cloud images are.
    pub cron_daemons: Vec<PathBuf>,
    /// The database, read for the firewall backend and named in the cron
    /// file.
    pub db_path: PathBuf,
    /// The `stop-bots` binary the cron file runs.
    pub binary: PathBuf,
    /// Exists only under systemd. The documented way to detect it — a
    /// `systemctl` binary on `PATH` proves only that the package is
    /// installed, which is true inside a container not running systemd.
    pub systemd_marker: PathBuf,
    /// The `systemctl` to run. A field for the same reason every path here
    /// is one: a test points it at a script that records its arguments.
    pub systemctl: PathBuf,
    /// Whether this describes the running host rather than a staging tree,
    /// i.e. whether the prefix was `/`. `--prefix` writes into a directory
    /// nothing will ever read, so no `systemctl` runs unless this is set.
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
            cron_dir: prefix.join("etc/cron.d"),
            cron_daemons: ["usr/sbin/cron", "usr/sbin/crond", "usr/bin/crond"]
                .iter()
                .map(|path| prefix.join(path))
                .collect(),
            db_path: prefix.join("var/lib/stop-bots/db.sqlite3"),
            binary,
            systemd_marker: prefix.join("run/systemd/system"),
            systemctl: PathBuf::from("systemctl"),
            // Derived, not a parameter: `main.rs` builds every layout with
            // `under`, so a flag a caller had to remember to set would have
            // been `false` on the one path that matters.
            real: prefix == Path::new("/"),
        }
    }

    pub fn cron_path(&self) -> PathBuf {
        self.cron_dir.join(CRON_FILE)
    }
}

/// What the caller asked for, beyond the paths.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Report every step and change nothing.
    pub dry_run: bool,
    /// Replace a file that exists and has been edited.
    pub force: bool,
}

/// A `stop-bots` that lives in a build directory.
///
/// The most likely way to end up with a cron file that works today and breaks
/// on the next `cargo clean`: `sudo cargo run -- install cron` resolves
/// `current_exe()` to `target/debug/stop-bots`, writes that into the cron
/// file, and nothing complains until the binary is gone.
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

/// `body` with its [`TEMPLATE_MARKER`] line added after the first line.
///
/// The hash covers everything else, the `Generated by` line and so the
/// version included, so it needs nothing but the file to check: see
/// [`is_sealed_and_unedited`].
fn seal(body: &str) -> String {
    let (first, rest) = body.split_once('\n').expect("a unit is more than one line");
    format!("{first}\n{TEMPLATE_MARKER}{}\n{rest}", sha256_hex(body))
}

/// Whether `text` carries a [`TEMPLATE_MARKER`] and still hashes to it —
/// that is, whether it is exactly as some version of stop-bots wrote it.
fn is_sealed_and_unedited(text: &str) -> bool {
    let mut recorded = None;
    let mut body = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match line.strip_prefix(TEMPLATE_MARKER) {
            Some(hash) if recorded.is_none() => recorded = Some(hash.trim_end()),
            _ => body.push_str(line),
        }
    }
    recorded.is_some_and(|hash| hash == sha256_hex(&body))
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// What is already at a unit's path, as far as replacing it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    /// Nothing there.
    Missing,
    /// Byte for byte what this would write.
    Current,
    /// Exactly as stop-bots wrote it — `by` says which version — so it may
    /// be replaced without asking.
    Unedited { by: String },
    /// Changed since stop-bots wrote it, or not written by stop-bots.
    Edited,
}

/// Classifies `existing` against `new`, the unit this run would write.
/// `legacy` recognises what 0.0.x wrote, which carries no hash, and
/// returns the releases that could have.
pub fn classify(
    existing: Option<&str>,
    new: &str,
    legacy: impl Fn(&str) -> Option<&'static str>,
) -> Existing {
    let Some(existing) = existing else {
        return Existing::Missing;
    };
    if existing == new {
        return Existing::Current;
    }
    if is_sealed_and_unedited(existing) {
        let by = match crate::generated::version_in(existing) {
            Some(version) => format!("stop-bots {version}"),
            None => "stop-bots".to_string(),
        };
        return Existing::Unedited { by };
    }
    match legacy(existing) {
        Some(releases) => Existing::Unedited {
            by: format!("stop-bots {releases}"),
        },
        None => Existing::Edited,
    }
}

/// Refuses an [`Existing::Edited`] unit unless `force`, and otherwise says
/// what will happen to it. Shared by the unit and the cron file, so they cannot drift.
fn plan_unit(state: &Existing, path: &Path, force: bool, retry: &str) -> Result<String> {
    Ok(match state {
        Existing::Missing => format!("write {}", path.display()),
        Existing::Current => format!("{} is already up to date", path.display()),
        Existing::Unedited { by } => {
            format!("replace {} (unedited since {by} wrote it)", path.display())
        }
        Existing::Edited if force => format!("replace {} (--force)", path.display()),
        Existing::Edited => anyhow::bail!(
            "{} has been edited since stop-bots wrote it, so this stopped rather than \
             replace your edit.\n\n\
             Pass --force to replace it anyway. `{retry} --dry-run` prints the plan \
             without changing anything.",
            path.display(),
        ),
    })
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
    systemd_word(&path.to_string_lossy(), true)
}

/// `raw` as one word of a unit file line: quoted if it has to be, with
/// `%` as `%%`, and `$` as `$$` where the directive expands variables.
fn systemd_word(raw: &str, escape_dollar: bool) -> String {
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
            '$' if escape_dollar => out.push_str("$$"),
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

/// `raw` as one word of a `/bin/sh` command line: single-quoted unless it
/// is plain, with a single quote inside closed, escaped and reopened.
fn shell_word(raw: &str) -> String {
    let plain = !raw.is_empty()
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ':'));
    if plain {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

/// The cron file: one line, every minute, running `stop-bots tick` as root
/// against the system database.
///
/// Every minute because that is the schedule's own granularity — the
/// detectors are due each minute, and `tick` runs only what is due, so a
/// minute with nothing due costs one database read. Overlapping runs are
/// `tick`'s own business: it takes a lock and leaves when another holds it.
///
/// cron runs the line through `/bin/sh`, so the paths are quoted for a
/// shell, and `%` is cron's own newline, so it is escaped too. A `tick`
/// that succeeds prints nothing, which is how cron's mail stays for when
/// something failed.
pub fn cron_file(layout: &Layout) -> String {
    let word = |path: &Path| shell_word(&path.to_string_lossy()).replace('%', "\\%");
    seal(&format!(
        "# {generated_by}, with `stop-bots install cron`.\n\
         #\n\
         # Re-running that command replaces this file for as long as it is\n\
         # unedited: the stop-bots-template line is a hash of everything else\n\
         # here, and is how it tells. An edited copy is left alone, and the\n\
         # installer says so; `--force` replaces it anyway.\n\
         #\n\
         # Once a minute, run whatever is due on stop-bots' schedule: the same\n\
         # jobs the TUI runs while it is open, which `stop-bots status` and the\n\
         # TUI's Dashboard show. It writes what the detectors find, and applies\n\
         # it to the web server and the firewall only as far as\n\
         # `set-auto-apply` and `set-auto-apply-firewall` allow -- both are off\n\
         # until you turn them on.\n\
         SHELL=/bin/sh\n\
         PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
         * * * * * root {binary} tick --db {db}\n",
        generated_by = crate::generated::generated_by(),
        binary = word(&layout.binary),
        db = word(&layout.db_path),
    ))
}

/// Everything that must hold before the cron file is written.
/// The first part of `binary`'s path that someone other than root or this
/// process could replace, and why, or `None` if nobody could.
///
/// The cron file runs the binary as root every minute, so whoever can
/// write the binary, or rename something over any directory on the way to
/// it, is root. `cargo install` leaves it in `~/.cargo/bin`, the user's
/// own, and `sudo ~/.cargo/bin/stop-bots install cron` then gave every
/// program that user runs a root shell with no password asked. Both the
/// path as given and the path its links resolve to are walked: a link in
/// a directory someone else can write is theirs to point elsewhere.
///
/// The rule for each directory is [`crate::firewall::unsafe_directory`],
/// the one the firewall script's directory is held to.
fn replaceable_by_someone_else(binary: &Path) -> Option<(PathBuf, String)> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: neither call has preconditions; both only read the
    // process's own credentials.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let resolved = std::fs::canonicalize(binary).ok();
    for path in [Some(binary.to_path_buf()), resolved].into_iter().flatten() {
        let meta = std::fs::metadata(&path).ok()?;
        if meta.uid() != 0 && meta.uid() != euid {
            return Some((path, format!("owned by uid {}", meta.uid())));
        }
        if meta.mode() & 0o002 != 0 {
            return Some((path, "writable by every user".to_string()));
        }
        if meta.mode() & 0o020 != 0 && meta.gid() != egid {
            return Some((path, format!("writable by group {}", meta.gid())));
        }
        for dir in path.ancestors().skip(1) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let Ok(meta) = std::fs::metadata(dir) else {
                continue;
            };
            if let Some(why) =
                crate::firewall::unsafe_directory(meta.uid(), meta.gid(), meta.mode(), euid, egid)
            {
                return Some((dir.to_path_buf(), why));
            }
        }
    }
    None
}

fn preflight_cron(layout: &Layout, options: &Options) -> Result<()> {
    if !layout.cron_dir.is_dir() || !layout.cron_daemons.iter().any(|path| path.is_file()) {
        anyhow::bail!(
            "this host has no cron to run the schedule: no cron daemon ({}), and {} \
             proves nothing by itself.\n\n\
             On Debian and Ubuntu: `sudo apt install cron`, then run this again.",
            layout
                .cron_daemons
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            layout.cron_dir.display()
        );
    }
    // Before `is_file`, because a relative path can be a real file and
    // still be the wrong one when cron runs it from `/`.
    if !layout.binary.is_absolute() {
        anyhow::bail!(
            "--binary needs an absolute path, and {} is relative: cron runs it from /, \
             not from here",
            layout.binary.display()
        );
    }
    if !layout.binary.is_file() {
        anyhow::bail!(
            "{} is not a file, so cron would run nothing",
            layout.binary.display()
        );
    }
    if let Some((path, why)) = replaceable_by_someone_else(&layout.binary) {
        anyhow::bail!(
            "refusing to have cron run {} as root: {} is {why}, who could put another \
             program in its place and have it run as root within the minute.\n\n\
             Install the binary where only root can change it, and run that one:\n  \
             sudo install -m 755 {} /usr/local/bin/stop-bots\n  \
             sudo /usr/local/bin/stop-bots install cron",
            layout.binary.display(),
            path.display(),
            layout.binary.display(),
        );
    }
    // Checked by trying, not by comparing euid to 0: what matters is
    // whether this process can write there.
    if !options.dry_run {
        writable(&layout.cron_dir).with_context(|| {
            format!(
                "cannot write to {} — `install cron` needs root. Run it with sudo \
                 (`sudo stop-bots install cron --dry-run` shows the plan first)",
                layout.cron_dir.display()
            )
        })?;
    }
    Ok(())
}

/// Writes [`cron_file`], refusing to overwrite one somebody has edited.
///
/// Mode 0644 and owned by whoever runs this, which is root: cron skips a
/// file in `/etc/cron.d` that anyone else could write. Nothing to start —
/// cron rereads the directory each minute.
pub fn install_cron(layout: &Layout, options: &Options) -> Result<Steps> {
    preflight_cron(layout, options)?;
    let text = cron_file(layout);
    let path = layout.cron_path();
    let existing = std::fs::read_to_string(&path).ok();
    let state = classify(existing.as_deref(), &text, |_| None);
    let retry = format!("{} install cron", layout.binary.display());

    let mut steps = Steps::new();
    steps.push(plan_unit(&state, &path, options.force, &retry)?);
    if !options.dry_run && state != Existing::Current {
        (|| -> Result<()> {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .with_context(|| format!("setting the mode of {}", path.display()))
        })()
        .map_err(crate::hint::sudo_if_denied)?;
    }
    steps.push(
        "cron reads it within the minute; `stop-bots status` shows each job's last run".to_string(),
    );
    Ok(steps)
}

/// The simple TUI's "Keep running by itself", switched on: [`install_cron`],
/// then both auto-apply switches on, with the SSH lock-out check on too.
///
/// One switch for what is three on the advanced screens, because together
/// they are the answer to "does this protect me when I am not looking?" and
/// none of them is on its own. The lock-out check is switched on rather than
/// left as found: with nobody previewing an apply, it is what stands between
/// a bad rule and the operator's own SSH session.
///
/// Refused, with what to do, when not root: the cron file is root's to
/// write, and a half-done switch (auto-apply on, nothing to run it) would
/// read as on. The cron file comes first for the same reason: if it cannot
/// be written, no setting has changed.
pub fn keep_running(db: &crate::db::Db, layout: &Layout, root: bool) -> Result<String> {
    if !root {
        anyhow::bail!(
            "Keeping it running writes {} and needs root. Quit, and start stop-bots again \
             with sudo.",
            layout.cron_path().display()
        );
    }
    if is_build_artifact(&layout.binary) {
        anyhow::bail!(
            "{} is in a build directory, and cron would stop finding it at the next \
             `cargo clean`. Install the binary first, then switch this on.",
            layout.binary.display()
        );
    }
    install_cron(layout, &Options::default())?;
    db.set_auto_apply(true)?;
    db.set_auto_apply_firewall(true)?;
    db.set_ssh_lockout_check(true)?;
    Ok(format!(
        "Keeps running by itself: {} runs it every minute, and what it finds is applied, \
         after the SSH lock-out check.",
        layout.cron_path().display()
    ))
}

/// "Keep running by itself", switched off: both auto-apply switches off.
/// The cron file stays, so the detectors still run and record what they
/// find, and nothing reaches the web server or the firewall until `a`.
pub fn stop_keep_running(db: &crate::db::Db) -> Result<String> {
    db.set_auto_apply(false)?;
    db.set_auto_apply_firewall(false)?;
    Ok("No longer applies by itself: it still finds attackers, and you apply with a.".to_string())
}

/// Whether this process can create a file in `dir`, answered by doing it.
fn writable(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let probe = dir.join(".stop-bots-install-probe");
    std::fs::write(&probe, b"").with_context(|| format!("writing {}", probe.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

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
///
/// **Sandboxed hard**, because whatever the script says runs as root at
/// every boot, and loading rules is all it is for. No writes, no capability beyond the network, and no
/// `AF_UNIX` — the socket family root would use to ask systemd to run
/// something outside the sandbox. Under nftables that leaves a compromised
/// script able to change the firewall and nothing else; `nft -f` has no
/// way to run a command at all.
///
/// The iptables script is a shell script, and needs two concessions for
/// `iptables-legacy`, which a host may have selected: it fails outright
/// without `/run/xtables.lock`, which it cannot create once `/run` is
/// read-only, so the unit creates it first, outside the sandbox (only
/// creating it needs a writable `/run`; it opens an existing one read-only,
/// and `flock` needs no more); and it runs `modprobe` itself
/// when `ip_tables` is not loaded yet, early in a boot, so it keeps
/// `CAP_SYS_MODULE`. `iptables-nft`, Debian's default, needs neither, but
/// the unit cannot know which one `iptables` will be.
pub fn firewall_unit(backend: crate::firewall::FirewallBackend, script: &Path) -> String {
    let (exec, backend_sandbox) = match backend {
        crate::firewall::FirewallBackend::Nftables => (
            format!("/usr/sbin/nft -f {}", systemd_arg(script)),
            "ProtectKernelModules=yes\n\
             CapabilityBoundingSet=CAP_NET_ADMIN\n",
        ),
        crate::firewall::FirewallBackend::Iptables => (
            format!("/bin/sh {}", systemd_arg(script)),
            "# iptables-legacy refuses to run without its lock file and cannot\n\
             # create one in a read-only /run, but only reads one that is there;\n\
             # `+` creates it outside the sandbox. It also runs modprobe itself\n\
             # when ip_tables is not loaded yet.\n\
             ExecStartPre=+/usr/bin/touch /run/xtables.lock\n\
             CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE\n",
        ),
    };
    seal(&format!(
        "# {generated_by}, with `stop-bots install firewall`.\n\
         #\n\
         # Re-running that command replaces this file for as long as it is\n\
         # unedited: the stop-bots-template line is a hash of everything else\n\
         # here, and is how it tells. An edited copy is left alone, and the\n\
         # installer says so; `--force` replaces it anyway.\n\
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
         # The script runs as root at every boot, so\n\
         # this may load rules and do nothing else: every path read-only, only\n\
         # the capabilities loading rules takes, and no AF_UNIX, which is how\n\
         # root would ask systemd to run something outside this sandbox.\n\
         NoNewPrivileges=yes\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         PrivateDevices=yes\n\
         ProtectClock=yes\n\
         ProtectHostname=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelLogs=yes\n\
         ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n\
         RestrictRealtime=yes\n\
         RestrictNamespaces=yes\n\
         LockPersonality=yes\n\
         MemoryDenyWriteExecute=yes\n\
         SystemCallArchitectures=native\n\
         RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6\n\
         {backend_sandbox}\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        generated_by = crate::generated::generated_by(),
        // A condition takes the rest of the line as the path, so it is not
        // quoted; it does expand specifiers, so `%` still has to be `%%`.
        script = script.display().to_string().replace('%', "%%")
    ))
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

/// Writes [`firewall_unit`] and enables it. Refuses to overwrite
/// a unit somebody has edited, as [`install_cron`] does.
///
/// Under `--prefix` it writes the unit and stops, as `install cron` does:
/// the unit is somewhere systemd never looks, and running the real
/// `systemctl daemon-reload`/`enable` would either claim a unit took
/// effect that did not, or enable a stale one of the same name.
pub fn install_firewall(layout: &Layout, options: &Options) -> Result<Steps> {
    let backend = stored_backend_at(&layout.db_path)?;
    let script = crate::firewall::default_output_path(backend);
    let unit = firewall_unit(backend, &script);
    let unit_path = layout.unit_dir.join(FIREWALL_UNIT);
    let existing = std::fs::read_to_string(&unit_path).ok();
    let state = classify(existing.as_deref(), &unit, legacy::firewall_unit);
    let retry = format!("{} install firewall", layout.binary.display());

    let mut steps = Steps::new();
    steps.push(plan_unit(&state, &unit_path, options.force, &retry)?);
    if !options.dry_run && state != Existing::Current {
        (|| -> Result<()> {
            if let Some(parent) = unit_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&unit_path, &unit)
                .with_context(|| format!("writing {}", unit_path.display()))
        })()
        .map_err(crate::hint::sudo_if_denied)?;
    }

    // Not started. The script may not exist yet, and starting a unit that
    // loads firewall rules is the one step an operator should take after
    // reading what it would load -- the same reason `render-firewall` only
    // applies what it writes when asked to.
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
    // `render-firewall --apply` rather than `nft -f <script>`: a script run
    // by hand is enforced now but never becomes what this unit loads, and
    // the one at `script` is only ever what was last applied.
    //
    // Which of the two things to say depends on whether an apply has
    // already happened. The README's quick start runs `batch --apply`
    // first, and telling that operator to go and apply what they just
    // applied read as if their rules had not taken.
    if layout.real && script.is_file() {
        steps.push(format!(
            "not started, and it need not be: {} holds the rules the last apply loaded, \
             and from the next boot on this unit loads it",
            script.display()
        ));
    } else {
        steps.push(format!(
            "not started: it loads {} at boot, which only an apply writes. Review the rules, \
             then run `stop-bots render-firewall --apply`: it checks for a lockout, runs the \
             script, and puts it there",
            script.display()
        ));
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
        anyhow::bail!(
            "`systemctl {}` exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(dir: &Path) -> Layout {
        std::fs::create_dir_all(dir.join("run/systemd/system")).unwrap();
        std::fs::create_dir_all(dir.join("etc/cron.d")).unwrap();
        std::fs::create_dir_all(dir.join("usr/sbin")).unwrap();
        std::fs::write(dir.join("usr/sbin/cron"), "").unwrap();
        let binary = dir.join("stop-bots");
        std::fs::write(&binary, b"#!/bin/true\n").unwrap();
        Layout::under(dir, binary)
    }

    fn recording_systemctl(dir: &Path) -> (PathBuf, PathBuf) {
        let log = dir.join("systemctl.log");
        let script = dir.join("fake-systemctl");
        crate::testing::write_script(
            &script,
            &format!("echo \"$@\" >> {}\nexit 0", log.display()),
        );
        (script, log)
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

    /// The last step says how to get rules into the file the unit loads.
    /// Running the script by hand enforces it now but never puts it there,
    /// so the advice is the apply that does both.
    #[test]
    fn install_firewall_points_at_the_apply_not_at_running_the_script() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());

        let steps = install_firewall(&layout, &Options::default()).unwrap();

        let last = steps.iter().last().expect("at least one step");
        assert!(last.contains("render-firewall --apply"), "steps: {steps:?}");
        assert!(!last.contains("nft -f"), "steps: {steps:?}");
    }

    /// Not root: the error names the unit file and says to use sudo, where
    /// it used to be a bare "Permission denied (os error 13)".
    #[test]
    fn install_firewall_without_permission_names_the_file_and_sudo() {
        use std::os::unix::fs::PermissionsExt;
        if crate::hint::is_root() {
            return; // root is never denied, so there is nothing to see
        }
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        std::fs::set_permissions(&layout.unit_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = install_firewall(&layout, &Options::default());
        std::fs::set_permissions(&layout.unit_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = result.expect_err("wrote into a read-only directory");
        let text = format!("{err:#}");
        assert!(text.contains(FIREWALL_UNIT), "which file? {text}");
        assert!(text.contains("Run it with sudo"), "{text}");
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

    // ---- telling an edited file from an old one ----

    fn forced() -> Options {
        Options {
            force: true,
            ..Options::default()
        }
    }

    /// The marker is how every later release decides whether it may
    /// replace a file. Renamed, it would make every file written until then
    /// look edited — so it is pinned here, literally, rather than through
    /// the constant.
    #[test]
    fn the_template_marker_is_frozen() {
        assert_eq!(TEMPLATE_MARKER, "# stop-bots-template: ");
        let unit = firewall_unit(
            crate::firewall::FirewallBackend::Nftables,
            Path::new("/etc/stop-bots/firewall.nft"),
        );
        let marker_line = unit.lines().nth(1).unwrap();
        assert!(
            marker_line.starts_with("# stop-bots-template: ") && marker_line.len() == 22 + 64,
            "the second line is not the marker: {marker_line:?}"
        );
    }

    #[test]
    fn a_generated_file_hashes_to_its_own_marker() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            cron_file(&Layout::system(PathBuf::from("/usr/bin/stop-bots"))),
            cron_file(&staged(dir.path())),
            firewall_unit(
                crate::firewall::FirewallBackend::Iptables,
                Path::new("/etc/stop-bots/firewall.sh"),
            ),
        ] {
            assert!(is_sealed_and_unedited(&text), "file was:\n{text}");
        }
    }

    #[test]
    fn any_edit_breaks_the_seal() {
        let text = cron_file(&Layout::system(PathBuf::from("/usr/bin/stop-bots")));
        for (what, edited) in [
            ("the schedule", text.replace("* * * * *", "*/5 * * * *")),
            ("an added line", format!("{text}MAILTO=\"\"\n")),
            (
                "the version",
                text.replace(crate::generated::VERSION, "9.9.9"),
            ),
            (
                "the hash",
                text.replacen(TEMPLATE_MARKER, "# stop-bots-template: 0", 1),
            ),
            ("no marker", text.replacen(TEMPLATE_MARKER, "# ", 1)),
        ] {
            assert!(!is_sealed_and_unedited(&edited), "{what} kept the seal");
        }
    }

    /// Installs the firewall unit over `fixture`, with `backend` stored,
    /// and asserts it was replaced without `--force`.
    fn assert_firewall_unit_upgrades(fixture: &str, backend: crate::firewall::FirewallBackend) {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        // No database is the nftables default; only iptables needs one.
        if backend != crate::firewall::FirewallBackend::Nftables {
            let db = crate::db::Db::open(&layout.db_path).unwrap();
            crate::firewall::store_backend(&db, backend).unwrap();
        }
        let path = layout.unit_dir.join(FIREWALL_UNIT);
        std::fs::create_dir_all(&layout.unit_dir).unwrap();
        std::fs::write(&path, fixture).unwrap();

        install_firewall(&layout, &Options::default()).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            firewall_unit(backend, &crate::firewall::default_output_path(backend))
        );
    }

    #[test]
    fn a_0_0_x_nftables_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-nftables-0.0.15.service"),
            crate::firewall::FirewallBackend::Nftables,
        );
    }

    #[test]
    fn a_0_0_x_iptables_firewall_unit_is_upgraded_without_force() {
        assert_firewall_unit_upgrades(
            include_str!("../tests/fixtures/units/stop-bots-firewall-iptables-0.0.15.service"),
            crate::firewall::FirewallBackend::Iptables,
        );
    }

    #[test]
    fn an_edited_firewall_unit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut layout = staged(dir.path());
        layout.systemctl = recording_systemctl(dir.path()).0;
        install_firewall(&layout, &Options::default()).unwrap();
        let path = layout.unit_dir.join(FIREWALL_UNIT);
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("After=docker.service ", "After=");
        std::fs::write(&path, &edited).unwrap();

        let err = install_firewall(&layout, &Options::default()).unwrap_err();

        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited);
    }

    #[test]
    fn the_generated_firewall_unit_is_what_it_was() {
        crate::golden::assert_golden(
            "stop-bots-firewall.service",
            &firewall_unit(
                crate::firewall::FirewallBackend::Nftables,
                Path::new("/etc/stop-bots/firewall.nft"),
            ),
        );
    }

    /// The iptables variant differs in what it runs and in the two things
    /// iptables-legacy needs from its sandbox.
    #[test]
    fn the_generated_iptables_firewall_unit_is_what_it_was() {
        crate::golden::assert_golden(
            "stop-bots-firewall-iptables.service",
            &firewall_unit(
                crate::firewall::FirewallBackend::Iptables,
                Path::new("/etc/stop-bots/firewall.sh"),
            ),
        );
    }

    // ---- install cron ----

    /// The exact file a real host gets.
    #[test]
    fn the_generated_cron_file_is_what_it_was() {
        crate::golden::assert_golden(
            "stop-bots.cron",
            &cron_file(&Layout::system(PathBuf::from("/usr/bin/stop-bots"))),
        );
    }

    #[test]
    fn install_cron_writes_the_file_world_readable_and_root_writable_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());

        install_cron(&layout, &Options::default()).unwrap();

        let path = layout.cron_path();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), cron_file(&layout));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "cron skips a file others can write");
    }

    #[test]
    fn a_dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let options = Options {
            dry_run: true,
            ..Options::default()
        };

        let steps = install_cron(&layout, &options).unwrap();

        assert!(!layout.cron_path().exists(), "steps: {steps:?}");
    }

    // ---- keep running ----

    /// The three switches it stands for, and the file that runs them.
    #[test]
    fn keeping_it_running_installs_cron_and_turns_on_both_auto_applies_and_the_lockout_check() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_ssh_lockout_check(false).unwrap();

        keep_running(&db, &layout, true).unwrap();

        assert_eq!(
            std::fs::read_to_string(layout.cron_path()).unwrap(),
            cron_file(&layout)
        );
        for (what, on) in [
            ("auto-apply", db.get_auto_apply().unwrap()),
            ("auto-apply firewall", db.get_auto_apply_firewall().unwrap()),
            ("lock-out check", db.get_ssh_lockout_check().unwrap()),
        ] {
            assert!(on, "{what} is off");
        }
    }

    /// Not root: nothing written, nothing switched, and the way out named.
    #[test]
    fn keeping_it_running_without_root_says_so_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let db = crate::db::Db::open_in_memory().unwrap();

        let err = keep_running(&db, &layout, false).unwrap_err();

        assert!(format!("{err:#}").contains("sudo"), "was: {err:#}");
        assert!(!layout.cron_path().exists());
        assert!(!db.get_auto_apply().unwrap());
        assert!(!db.get_auto_apply_firewall().unwrap());
    }

    /// A cron file that cannot be written leaves the switches as they were,
    /// so the screen does not say "on" about a host nothing runs.
    #[test]
    fn keeping_it_running_on_a_host_without_cron_switches_nothing_on() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_dir(&layout.cron_dir).unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();

        let err = keep_running(&db, &layout, true).unwrap_err();

        assert!(
            format!("{err:#}").contains("apt install cron"),
            "was: {err:#}"
        );
        assert!(!db.get_auto_apply().unwrap());
        assert!(!db.get_auto_apply_firewall().unwrap());
    }

    /// Off keeps the schedule finding things, and stops it applying them.
    #[test]
    fn stopping_keeps_the_cron_file_and_turns_both_auto_applies_off() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        let db = crate::db::Db::open_in_memory().unwrap();
        keep_running(&db, &layout, true).unwrap();

        stop_keep_running(&db).unwrap();

        assert!(layout.cron_path().exists());
        assert!(!db.get_auto_apply().unwrap());
        assert!(!db.get_auto_apply_firewall().unwrap());
    }

    #[test]
    fn a_host_without_cron_is_told_how_to_get_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_dir(&layout.cron_dir).unwrap();

        let err = install_cron(&layout, &Options::default()).unwrap_err();

        assert!(
            format!("{err:#}").contains("apt install cron"),
            "was: {err:#}"
        );
    }

    /// `/etc/cron.d` exists on a host with no cron daemon — other packages
    /// put files there — which is how a cron file came to be installed on
    /// a server where nothing would ever run it.
    #[test]
    fn a_cron_directory_without_a_daemon_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        std::fs::remove_file(dir.path().join("usr/sbin/cron")).unwrap();

        let err = install_cron(&layout, &Options::default()).unwrap_err();

        assert!(
            format!("{err:#}").contains("no cron daemon"),
            "was: {err:#}"
        );
        assert!(!layout.cron_path().exists(), "wrote it anyway");
    }

    /// `cargo install` leaves the binary in the user's own directory, and
    /// a cron line naming it there is a root shell for that user.
    #[test]
    fn a_binary_someone_else_could_replace_is_not_given_to_cron() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for (what, loosen) in [
            ("the binary itself", "bin/stop-bots"),
            ("the directory it is in", "bin"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut layout = staged(dir.path());
            std::fs::create_dir(dir.path().join("bin")).unwrap();
            layout.binary = dir.path().join("bin/stop-bots");
            std::fs::write(&layout.binary, b"#!/bin/true\n").unwrap();
            mode(&dir.path().join(loosen), 0o777);

            let err = install_cron(&layout, &Options::default()).unwrap_err();

            assert!(
                format!("{err:#}").contains("writable by every user"),
                "{what}: {err:#}"
            );
            assert!(!layout.cron_path().exists(), "{what}: wrote it anyway");
        }
    }

    #[test]
    fn an_edited_cron_file_is_refused_and_force_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = staged(dir.path());
        install_cron(&layout, &Options::default()).unwrap();
        let edited = std::fs::read_to_string(layout.cron_path())
            .unwrap()
            .replace("* * * * *", "*/5 * * * *");
        std::fs::write(layout.cron_path(), &edited).unwrap();

        let err = install_cron(&layout, &Options::default()).unwrap_err();
        assert!(format!("{err:#}").contains("--force"), "was: {err:#}");
        assert_eq!(
            std::fs::read_to_string(layout.cron_path()).unwrap(),
            edited,
            "the edit was overwritten anyway"
        );

        install_cron(&layout, &forced()).unwrap();
        assert_eq!(
            std::fs::read_to_string(layout.cron_path()).unwrap(),
            cron_file(&layout)
        );
    }

    /// cron hands the line to `/bin/sh`, and reads `%` as a newline, so a
    /// path with a space, a quote or a percent sign still names one file.
    #[test]
    fn the_cron_line_quotes_what_sh_and_cron_would_misread() {
        let mut layout = Layout::system(PathBuf::from("/opt/stop bots/stop-bots"));
        layout.db_path = PathBuf::from("/var/lib/it's 100%/db.sqlite3");

        let text = cron_file(&layout);

        let line = text.lines().last().unwrap();
        assert_eq!(
            line,
            r"* * * * * root '/opt/stop bots/stop-bots' tick --db '/var/lib/it'\''s 100\%/db.sqlite3'"
        );
    }
}
