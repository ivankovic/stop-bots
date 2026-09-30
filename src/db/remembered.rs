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

//! The browsers the web console remembers — `remembered_browsers`, schema
//! version 6. What a remembered browser is for, and why only a digest of
//! its token is kept, is in `web::auth`; this is the storage.

use anyhow::{Context, Result};
use rusqlite::params;

use super::Db;

impl Db {
    /// Remembers the browser whose token digests to `token_hash`, or
    /// refreshes it if it is already remembered, as of `now`. Keeps only
    /// the `keep` most recently used, so the table stays a handful of
    /// rows however many browsers have ever logged in.
    pub fn remember_browser(&self, token_hash: &str, now: i64, keep: usize) -> Result<()> {
        self.batch(|| {
            self.conn.execute(
                "INSERT INTO remembered_browsers (token_hash, created_at, last_used_at)
                 VALUES (?1, ?2, ?2)
                 ON CONFLICT(token_hash) DO UPDATE SET last_used_at = excluded.last_used_at",
                params![token_hash, now],
            )?;
            self.conn.execute(
                "DELETE FROM remembered_browsers WHERE token_hash NOT IN (
                     SELECT token_hash FROM remembered_browsers
                     ORDER BY last_used_at DESC, created_at DESC LIMIT ?1)",
                params![keep as i64],
            )?;
            Ok(())
        })
        .context("failed to remember this browser")
    }

    /// Whether `token_hash` is a browser remembered and used since
    /// `used_since`. The ones that are not are deleted on the way, so an
    /// expired row does not wait for anything else to clear it.
    pub fn is_remembered_browser(&self, token_hash: &str, used_since: i64) -> Result<bool> {
        self.conn
            .execute(
                "DELETE FROM remembered_browsers WHERE last_used_at < ?1",
                params![used_since],
            )
            .context("failed to expire remembered browsers")?;
        let found: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM remembered_browsers WHERE token_hash = ?1",
                params![token_hash],
                |row| row.get(0),
            )
            .context("failed to look up a remembered browser")?;
        Ok(found > 0)
    }

    /// Forgets every remembered browser. Returns how many there were.
    pub fn forget_remembered_browsers(&self) -> Result<usize> {
        self.conn
            .execute("DELETE FROM remembered_browsers", [])
            .context("failed to forget the remembered browsers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remembered_browser_is_known_until_it_goes_unused_too_long() {
        let db = Db::open_in_memory().unwrap();
        db.remember_browser("hash-a", 1_000, 32).unwrap();

        assert!(db.is_remembered_browser("hash-a", 500).unwrap());
        assert!(!db.is_remembered_browser("hash-b", 500).unwrap());
        assert!(
            !db.is_remembered_browser("hash-a", 1_001).unwrap(),
            "unused since before the cutoff"
        );
        assert!(
            !db.is_remembered_browser("hash-a", 0).unwrap(),
            "an expired row is deleted, not merely skipped"
        );
    }

    #[test]
    fn using_a_remembered_browser_again_keeps_it_alive() {
        let db = Db::open_in_memory().unwrap();
        db.remember_browser("hash-a", 1_000, 32).unwrap();
        db.remember_browser("hash-a", 5_000, 32).unwrap();

        assert!(db.is_remembered_browser("hash-a", 4_000).unwrap());
    }

    #[test]
    fn only_the_most_recently_used_browsers_are_kept() {
        let db = Db::open_in_memory().unwrap();
        for i in 0..5 {
            db.remember_browser(&format!("hash-{i}"), 1_000 + i, 3)
                .unwrap();
        }

        let kept: Vec<bool> = (0..5)
            .map(|i| db.is_remembered_browser(&format!("hash-{i}"), 0).unwrap())
            .collect();
        assert_eq!(kept, [false, false, true, true, true]);
    }

    #[test]
    fn forgetting_clears_every_browser() {
        let db = Db::open_in_memory().unwrap();
        db.remember_browser("hash-a", 1_000, 32).unwrap();
        db.remember_browser("hash-b", 1_000, 32).unwrap();

        assert_eq!(db.forget_remembered_browsers().unwrap(), 2);
        assert!(!db.is_remembered_browser("hash-a", 0).unwrap());
    }
}
