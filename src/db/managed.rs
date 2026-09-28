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

//! The record of every generated file stop-bots has written outside its
//! own directories, in the `managed_files` table.
//!
//! Cleaning up by a list of names only finds files where that list says
//! they are *now*. The `conf.d` files follow the NGINX root, so a host
//! whose root changed kept a full set in the old `conf.d`, still live if
//! NGINX reads it, and nothing would ever remove them; the same goes for
//! any file a later release stops writing. A row here is written *before*
//! the file is (see `nginx::record_managed_files`), so every file that can
//! exist has one, even if the process died between the two.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::params;

use super::{now, Db};

/// One row of the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFile {
    pub path: PathBuf,
    /// What the file is, as `nginx::ManagedKind::id` spells it. Stored as
    /// text so a kind a later release adds is still a row this one can
    /// list and remove.
    pub kind: String,
    /// Unix seconds of the last time it was recorded as written.
    pub written_at: i64,
    /// The stop-bots version that last recorded it.
    pub version: String,
}

impl Db {
    /// Records that `path`, a file of `kind`, is about to be written by
    /// this version. Replaces an earlier row for the same path.
    pub fn record_managed_file(&self, path: &Path, kind: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO managed_files (path, kind, written_at, version) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    path.to_string_lossy(),
                    kind,
                    now(),
                    crate::generated::VERSION
                ],
            )
            .with_context(|| format!("failed to record {}", path.display()))?;
        Ok(())
    }

    /// Every recorded file, by path.
    pub fn managed_files(&self) -> Result<Vec<ManagedFile>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, kind, written_at, version FROM managed_files ORDER BY path")?;
        let rows = stmt.query_map([], |row| {
            Ok(ManagedFile {
                path: PathBuf::from(row.get::<_, String>(0)?),
                kind: row.get(1)?,
                written_at: row.get(2)?,
                version: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list the generated files stop-bots has written")
    }

    /// Drops the row for `path`, once the file is gone.
    pub fn forget_managed_file(&self, path: &Path) -> Result<()> {
        self.conn.execute(
            "DELETE FROM managed_files WHERE path = ?1",
            params![path.to_string_lossy()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_file_is_listed_with_this_version_until_forgotten() {
        let db = Db::open_in_memory().unwrap();
        let path = Path::new("/etc/nginx/conf.d/stop-bots-limits.conf");

        db.record_managed_file(path, "nginx-limits").unwrap();
        db.record_managed_file(path, "nginx-limits").unwrap();

        let files = db.managed_files().unwrap();
        assert_eq!(files.len(), 1, "recording twice made two rows: {files:?}");
        assert_eq!(files[0].path, path);
        assert_eq!(files[0].kind, "nginx-limits");
        assert_eq!(files[0].version, crate::generated::VERSION);
        assert!(files[0].written_at > 0);

        db.forget_managed_file(path).unwrap();
        assert!(db.managed_files().unwrap().is_empty());
    }
}
