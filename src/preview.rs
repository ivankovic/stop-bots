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

//! What "Apply everything" would do, before it does it.
//!
//! "Apply everything" — `a` in the TUI, the button in the console, `batch
//! --apply` — rewrites every site's NGINX config and runs the firewall
//! script as root. Each front-end now shows this first: the files that
//! would change, the rules added and removed against the applied script,
//! and the lockout guard's verdict, with a unified diff of all of it on
//! request. `apply-blocks --dry-run` and `batch --dry-run` print the same
//! and stop there.
//!
//! Nothing here writes anything, or records anything in the database: the
//! NGINX half reads files through the functions the apply uses, and the
//! firewall half is a [`crate::firewall::FirewallRun`] with `dry_run` set.

use crate::firewall::{FirewallOutcome, FirewallRun, SshLog};
use crate::nginx::FileChange;
use std::path::Path;

/// Both halves of a preview. Each is its own `Result`, as the apply's two
/// planes are independent: one failing to preview says nothing about the
/// other.
#[derive(Debug, Clone)]
pub struct ApplyPreview {
    pub nginx: Result<Vec<FileChange>, String>,
    pub firewall: Result<FirewallOutcome, String>,
}

impl ApplyPreview {
    /// The summary, a line each: the NGINX half, then the firewall's.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = nginx_lines(&self.nginx);
        match &self.firewall {
            Ok(outcome) => lines.extend(outcome.lines()),
            Err(err) => lines.push(format!("Firewall: could not be previewed: {err}")),
        }
        lines
    }

    /// Every change as a unified diff: each site and generated file, then
    /// the firewall script against the applied one. Empty when nothing
    /// would change.
    pub fn diff(&self) -> String {
        let mut out = match &self.nginx {
            Ok(changes) => nginx_diff(changes),
            Err(_) => String::new(),
        };
        if let Ok(outcome) = &self.firewall {
            out.push_str(&outcome.diff());
        }
        out
    }
}

/// Lines of diff a [`Summary`] carries before it stops and says where the
/// rest is. A first apply on a host with reputation feeds is a 44,000-line
/// script; a page that size helps nobody review anything, and the web
/// console's helper should not have to send it.
pub const DIFF_LINES_SHOWN: usize = 4_000;

/// What the web console's confirm page shows: the summary lines, and the
/// diff when asked for, cut at [`DIFF_LINES_SHOWN`]. All a front-end that
/// does not hold the files gets — the root helper returns this and no
/// file's contents beyond the diff.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub lines: Vec<String>,
    pub diff: Option<String>,
}

impl ApplyPreview {
    /// The [`Summary`] of this preview, with the diff if `diff`.
    pub fn summary(&self, diff: bool) -> Summary {
        Summary {
            lines: self.lines(),
            diff: diff.then(|| truncated(&self.diff(), DIFF_LINES_SHOWN)),
        }
    }
}

/// `full`'s first `max` lines, and a line saying how many more there were.
pub fn truncated(full: &str, max: usize) -> String {
    let total = full.lines().count();
    let mut shown: String = full
        .lines()
        .take(max)
        .flat_map(|line| [line, "\n"])
        .collect();
    if total > max {
        shown.push_str(&format!(
            "\u{2026} {} more line(s). `stop-bots batch --dry-run --diff` prints all of it.\n",
            total - max
        ));
    }
    shown
}

/// The NGINX half of a summary: how many files would change, and which.
pub fn nginx_lines(changes: &Result<Vec<FileChange>, String>) -> Vec<String> {
    match changes {
        Err(err) => vec![format!("NGINX: could not be previewed: {err}")],
        Ok(changes) if changes.is_empty() => vec!["NGINX: no file would change".to_string()],
        Ok(changes) => std::iter::once(format!("NGINX: {} file(s) would change:", changes.len()))
            .chain(
                changes
                    .iter()
                    .map(|change| format!("  {}{}", change.path.display(), change.kind())),
            )
            .collect(),
    }
}

/// Every file's unified diff, one after the other.
pub fn nginx_diff(changes: &[FileChange]) -> String {
    changes.iter().map(FileChange::diff).collect()
}

/// A preview for a front-end that may hold the `Db` throughout: the CLI,
/// and the console inside one `with_db`. `run` is the firewall run the
/// apply would make; it is turned into a dry run here.
pub fn apply_everything(
    db: &crate::db::Db,
    root: &Path,
    run: FirewallRun,
    ssh_log: SshLog<'_>,
) -> ApplyPreview {
    ApplyPreview {
        nginx: crate::nginx::preview_all_sites(db, root).map_err(|err| format!("{err:#}")),
        firewall: crate::firewall::render_and_apply(db, run.dry_run(true), ssh_log)
            .map_err(|err| format!("{err:#}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::firewall::FirewallBackend;

    /// A root with one site whose config has never been applied, and a
    /// run whose applied script lives in `dir`.
    fn fixture(dir: &Path) -> (Db, std::path::PathBuf, FirewallRun) {
        let root = dir.join("nginx");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("site.conf"),
            "server {\n    listen 80;\n    server_name example.com;\n}\n",
        )
        .unwrap();
        let db = Db::open_in_memory().unwrap();
        db.block_address_permanently("192.0.2.9", crate::db::RuleSource::Tui, None)
            .unwrap();
        crate::testing::blocked_bot(&db, "badbot", "BadBot");
        let run = FirewallRun::new(FirewallBackend::Nftables, dir.join("firewall.nft"))
            .apply(true)
            .for_real(false);
        (db, root, run)
    }

    /// The claim a preview makes: nothing it looked at has changed, and
    /// nothing is recorded — not even the rendered signature, which is
    /// what a Dashboard reads as "rendered".
    #[test]
    fn a_preview_changes_nothing_on_disk_or_in_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let (db, root, run) = fixture(dir.path());
        let site = std::fs::read_to_string(root.join("site.conf")).unwrap();

        let preview = apply_everything(&db, &root, run, SshLog::Text(Some("")));

        assert_eq!(
            std::fs::read_to_string(root.join("site.conf")).unwrap(),
            site
        );
        assert!(!dir.path().join("firewall.next.nft").exists());
        assert!(!dir.path().join("firewall.nft").exists());
        assert_eq!(db.get_firewall_rendered_signature().unwrap(), None);
        assert!(
            preview.nginx.is_ok() && preview.firewall.is_ok(),
            "{preview:?}"
        );
    }

    #[test]
    fn the_summary_names_the_files_the_rules_and_the_guard_s_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let (db, root, run) = fixture(dir.path());

        let lines = apply_everything(&db, &root, run, SshLog::Text(None)).lines();
        let text = lines.join("\n");

        for (what, expected) in [
            ("the site file", "site.conf"),
            ("the rules against the applied script", "all of it is new"),
            (
                "whether the SSH log was readable",
                "no SSH log could be read",
            ),
            ("the verdict", "would not be applied"),
        ] {
            assert!(text.contains(expected), "no {what} in:\n{text}");
        }
    }

    /// What the apply would write, as a diff that says where.
    #[test]
    fn the_diff_shows_each_site_and_the_firewall_script() {
        let dir = tempfile::tempdir().unwrap();
        let (db, root, run) = fixture(dir.path());

        let diff = apply_everything(&db, &root, run, SshLog::Text(Some(""))).diff();

        assert!(
            diff.contains(&format!("+++ {}", root.join("site.conf").display())),
            "{diff}"
        );
        assert!(diff.contains("BadBot"), "{diff}");
        assert!(diff.contains("+\t192.0.2.9"), "{diff}");
    }

    /// The preview must describe the apply that then happens: what the
    /// apply writes to a site file is byte for byte what the preview said.
    #[test]
    fn the_apply_writes_exactly_what_the_preview_showed() {
        let dir = tempfile::tempdir().unwrap();
        let (db, root, run) = fixture(dir.path());
        let before = apply_everything(&db, &root, run.clone(), SshLog::Text(Some("")));
        let sites: Vec<_> = before
            .nginx
            .as_ref()
            .unwrap()
            .iter()
            .filter(|change| change.path.starts_with(&root))
            .cloned()
            .collect();
        assert_eq!(sites.len(), 1, "{before:?}");

        // The site file alone, through the apply's own function: the
        // generated files live under `/etc`, which a test must not touch.
        let site_path = root.join("site.conf");
        let configs: Vec<(String, crate::nginx::BlockConfig)> = Vec::new();
        crate::nginx::apply_blocks_to_file(
            &site_path,
            &root,
            &configs,
            &crate::nginx::default_block_config(&db).unwrap(),
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(&site_path).unwrap(),
            sites[0].after.clone().unwrap(),
            "the apply wrote something other than what the preview showed"
        );
    }
}
