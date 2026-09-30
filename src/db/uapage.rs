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

//! `user_agent_stats` a page at a time, for the Firewall screens.
//!
//! [`Db::list_user_agent_stats`] reads every row, which is right for the
//! CLI's `list-access-stats` and wrong for a screen: the table's rows are
//! strings any client can choose, and twenty thousand distinct 4–8 KB user
//! agents made the console's Firewall page load them all, classify each
//! against every bot pattern inside the database lock, and render 418 MB of
//! HTML. A screen shows the most-seen [`crate::dynamic::UA_PAGE_ROWS`] and
//! pages through the rest.

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use super::{Db, UserAgentStat};

impl Db {
    /// Up to `limit` user agents, most-seen first, skipping the first
    /// `offset`, each with its row id — the handle a console URL names it
    /// by, so that the string itself never goes into one.
    ///
    /// The same order as [`Db::list_user_agent_stats`], with the ties
    /// broken the same way, so page two starts where page one stopped.
    pub fn user_agent_stats_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<(i64, UserAgentStat)>> {
        let mut stmt = self.conn.prepare(
            "SELECT rowid, user_agent, hit_count, last_seen_at FROM user_agent_stats
             ORDER BY hit_count DESC, user_agent ASC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok((
                row.get(0)?,
                UserAgentStat {
                    user_agent: row.get(1)?,
                    hit_count: row.get(2)?,
                    last_seen_at: row.get(3)?,
                },
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list a page of user agent stats")
    }

    /// How many user agents are tallied, for "showing 200 of 20,413".
    pub fn count_user_agent_stats(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM user_agent_stats", [], |row| {
                row.get(0)
            })
            .context("failed to count user agent stats")?;
        Ok(count.max(0) as usize)
    }

    /// The row [`Self::user_agent_stats_page`] returned under `id`, if it
    /// is still there.
    ///
    /// A `rowid` is not forever: `VACUUM` may renumber a table whose key is
    /// not an `INTEGER PRIMARY KEY`, and pruning deletes rows. A caller that
    /// took the id from a URL must check the string it gets back is the
    /// one it meant; `web::firewall`'s reference carries a digest for that.
    pub fn user_agent_stat_by_id(&self, id: i64) -> Result<Option<UserAgentStat>> {
        self.conn
            .query_row(
                "SELECT user_agent, hit_count, last_seen_at FROM user_agent_stats
                 WHERE rowid = ?1",
                params![id],
                |row| {
                    Ok(UserAgentStat {
                        user_agent: row.get(0)?,
                        hit_count: row.get(1)?,
                        last_seen_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .context("failed to read a user agent's statistics")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn db_with(counts: &[(&str, u64)]) -> Db {
        let db = Db::open_in_memory().unwrap();
        let counts: HashMap<String, u64> =
            counts.iter().map(|(ua, n)| (ua.to_string(), *n)).collect();
        db.record_user_agent_hits(&counts, 1_000).unwrap();
        db
    }

    fn names(page: &[(i64, UserAgentStat)]) -> Vec<&str> {
        page.iter().map(|(_, s)| s.user_agent.as_str()).collect()
    }

    #[test]
    fn pages_follow_the_full_list_s_order_without_gaps_or_repeats() {
        let db = db_with(&[("a", 5), ("b", 9), ("c", 5), ("d", 1), ("e", 7)]);
        let everything: Vec<String> = db
            .list_user_agent_stats()
            .unwrap()
            .into_iter()
            .map(|s| s.user_agent)
            .collect();

        let mut paged = Vec::new();
        for offset in [0, 2, 4] {
            let page = db.user_agent_stats_page(2, offset).unwrap();
            paged.extend(names(&page).into_iter().map(str::to_string));
        }

        assert_eq!(paged, everything);
        assert_eq!(names(&db.user_agent_stats_page(2, 0).unwrap()), ["b", "e"]);
    }

    #[test]
    fn a_page_holds_at_most_its_limit_whatever_the_table_holds() {
        let many: Vec<(String, u64)> = (0..500).map(|i| (format!("ua-{i}"), i)).collect();
        let refs: Vec<(&str, u64)> = many.iter().map(|(s, n)| (s.as_str(), *n)).collect();
        let db = db_with(&refs);

        assert_eq!(db.user_agent_stats_page(200, 0).unwrap().len(), 200);
        assert_eq!(db.user_agent_stats_page(200, 400).unwrap().len(), 100);
        assert_eq!(db.count_user_agent_stats().unwrap(), 500);
    }

    #[test]
    fn a_row_is_found_again_by_the_id_its_page_gave_it() {
        let db = db_with(&[("curl/8.0", 3), ("Googlebot/2.1", 12)]);

        for (id, stat) in db.user_agent_stats_page(10, 0).unwrap() {
            assert_eq!(db.user_agent_stat_by_id(id).unwrap(), Some(stat));
        }
        assert_eq!(db.user_agent_stat_by_id(9_999).unwrap(), None);
    }
}
