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

//! Man pages and shell completions, generated from the command line's own
//! definition by the hidden `stop-bots generate-docs --out <dir>`.
//!
//! Generated rather than written, so they cannot drift from `--help`: the
//! same clap definition produces all three. A subcommand rather than a
//! `build.rs`, because a build script cannot see the `Cli` in `main.rs`
//! without splitting it out, and rather than an example, for the same
//! reason. The release and CI `deb` jobs run it on the binary they just
//! built, and `[package.metadata.deb]` ships what it writes.
//!
//! Layout under `out`, which is what `Cargo.toml`'s assets name:
//!
//! - `man/stop-bots.1`, and `man/stop-bots-<verb>.1` per visible verb;
//! - `completions/stop-bots.bash`, `completions/_stop-bots` (zsh) and
//!   `completions/stop-bots.fish`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Writes every man page and completion script for `cmd` under `out`, and
/// returns the paths written.
pub fn generate(cmd: clap::Command, out: &Path) -> Result<Vec<PathBuf>> {
    use clap_complete::Shell;

    let man = out.join("man");
    let completions = out.join("completions");
    for dir in [&man, &completions] {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    clap_mangen::generate_to(cmd.clone(), &man)
        .with_context(|| format!("writing the man pages to {}", man.display()))?;
    let mut written: Vec<PathBuf> = std::fs::read_dir(&man)
        .with_context(|| format!("reading {}", man.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();

    let mut cmd = cmd;
    let name = cmd.get_name().to_string();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        let path = clap_complete::generate_to(shell, &mut cmd, &name, &completions)
            .with_context(|| format!("writing the {shell} completions"))?;
        written.push(path);
    }
    written.sort();
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli() -> clap::Command {
        clap::Command::new("stop-bots")
            .about("Configure your server to stop bad bots")
            .subcommand(clap::Command::new("batch").about("One unattended pass"))
            .subcommand(
                clap::Command::new("generate-docs")
                    .about("Write the man pages")
                    .hide(true),
            )
    }

    fn names(paths: &[PathBuf]) -> Vec<String> {
        let mut names: Vec<String> = paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// One page per visible verb, none for a hidden one, and a completion
    /// script under the name each shell looks for.
    #[test]
    fn writes_a_page_per_visible_verb_and_three_completion_scripts() {
        let dir = tempfile::tempdir().unwrap();

        let written = generate(cli(), dir.path()).unwrap();

        assert_eq!(
            names(&written),
            [
                "_stop-bots",
                "stop-bots-batch.1",
                "stop-bots.1",
                "stop-bots.bash",
                "stop-bots.fish",
            ]
        );
        let page = std::fs::read_to_string(dir.path().join("man/stop-bots.1")).unwrap();
        assert!(page.starts_with(".ie"), "not roff: {page}");
        assert!(page.contains("stop\\-bots\\-batch(1)"), "{page}");
    }
}
