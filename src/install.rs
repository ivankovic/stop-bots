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
    /// The SSH log to read. Debian's is `/var/log/auth.log`.
    pub ssh_log: PathBuf,
    /// Exists only under systemd. The documented way to detect it — a
    /// `systemctl` binary on `PATH` proves only that the package is
    /// installed, which is true inside a Docker container that is not
    /// running systemd at all.
    pub systemd_marker: PathBuf,
    /// Exists only on Debian and its derivatives.
    pub debian_marker: PathBuf,
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
            ssh_log: prefix.join("var/log/auth.log"),
            systemd_marker: prefix.join("run/systemd/system"),
            debian_marker: prefix.join("etc/debian_version"),
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

/// The unit file's exact contents.
///
/// Pure, and takes every path it names — so the golden test locks the
/// bytes an operator will actually get rather than a rendering of them.
pub fn web_unit(layout: &Layout) -> String {
    let mut exec = format!(
        "{} web --db {} --root {} --ssh-log {}",
        layout.binary.display(),
        layout.db_path.display(),
        layout.nginx_root.display(),
        layout.ssh_log.display()
    );
    exec.push('\n');

    format!(
        "# Written by `stop-bots install web`. Re-running that command leaves an\n\
         # edited copy of this file alone and tells you so; `--force` replaces it.\n\
         #\n\
         # Settings deliberately absent from ExecStart: the bind address, the host\n\
         # allowlist, the path prefix and whether exposure is permitted all live in\n\
         # the `settings` table, because the running server re-reads them. Adding a\n\
         # flag for one here gives it two sources of truth and the database wins on\n\
         # the next restart. Change them with `stop-bots web --save ...` instead.\n\
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
         # AF_INET/AF_INET6 for the console itself and the crawler-range\n\
         # downloads. Nothing here uses a raw or netlink socket: this service\n\
         # writes the firewall script, it never applies it.\n\
         RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\
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
             systemd distribution, but the SSH log path it assumes \
             ({}) is Debian's, and nobody has checked the rest. \
             Write the unit by hand, or open an issue saying which distribution \
             this is.",
            layout.debian_marker.display(),
            layout.ssh_log.display()
        );
    }

    if !layout.binary.is_file() {
        anyhow::bail!(
            "{} is not a file, so the unit's ExecStart would point at nothing",
            layout.binary.display()
        );
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
        systemctl(&["daemon-reload"])?;
    }

    let action: &[&str] = if options.start {
        &["enable", "--now", WEB_UNIT]
    } else {
        &["enable", WEB_UNIT]
    };
    steps.push(format!("systemctl {}", action.join(" ")));
    if !options.dry_run {
        systemctl(action)?;
    }

    let _ = layout;
    Ok(steps)
}

fn systemctl(args: &[&str]) -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to run `systemctl {}`", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "`systemctl {}` exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
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

    /// The exact unit an operator gets. A golden rather than substring
    /// assertions because the failure that matters is a directive quietly
    /// changing meaning — `ProtectSystem=yes` becoming `full` makes /etc
    /// read-only and breaks the first NGINX apply, an hour after the unit
    /// started cleanly.
    #[test]
    fn the_generated_unit_is_what_it_was() {
        crate::golden::assert_golden("stop-bots-web.service", &web_unit(&system_layout()));
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
            &layout.ssh_log,
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
}
