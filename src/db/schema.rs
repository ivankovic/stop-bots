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

//! The database's schema version, and the numbered steps that bring an
//! older database up to it.
//!
//! The version lives in SQLite's own `PRAGMA user_version`, a number in
//! the file header that SQLite reserves for the application and never
//! touches itself. Every 0.0.x release left it at 0, so 0 means "written
//! before 0.1", whichever 0.0.x that was.
//!
//! Opening a database ([`migrate`]) does one of three things:
//!
//! - **It is at [`CURRENT_VERSION`]:** nothing.
//! - **It is older:** copy the file to `<db>.bak-v<old>` (see
//!   [`backup_path`]), then run every step after its version, in order,
//!   in one transaction, and record the new version in that same
//!   transaction. A step that fails leaves the database exactly as it was.
//! - **It is newer:** refuse to open it. An older binary cannot know what
//!   a newer one's tables and settings mean, and before 0.1 it silently
//!   reinterpreted them.
//!
//! A brand-new, empty database takes the same path as an old one, from 0,
//! minus the backup: there is nothing in it to lose.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

use super::{Category, GeoMode, Policy};

/// The schema version this binary writes, and the newest it will open.
///
/// Always equal to `MIGRATIONS.len()`; a test holds the two together, so
/// adding a migration without bumping this (or the reverse) fails the
/// build's tests rather than a user's upgrade.
pub const CURRENT_VERSION: u32 = 1;

/// One step from version `n - 1` to version `n`, where `n` is its position
/// in [`MIGRATIONS`] counting from one.
pub struct Migration {
    /// What the step does, in a few words. Quoted in the error if it fails,
    /// so an operator's bug report says which step broke.
    pub summary: &'static str,
    /// The step itself. It runs inside the transaction [`migrate`] opens,
    /// so it must not `BEGIN` or `COMMIT` on its own.
    pub apply: fn(&Connection) -> rusqlite::Result<()>,
}

/// Every schema change since 0.1, oldest first. **Append only.**
///
/// Entry `i` takes a database from version `i` to version `i + 1`. A
/// database at version `v` runs entries `v..` in order, so an entry that
/// has shipped must never be edited, reordered or removed: some host has
/// already run it, and will not run it again.
///
/// **Adding a migration** is one line here and one number:
///
/// ```text
/// Migration { summary: "firewall_rules.source", apply: |db| db.execute_batch(
///     "ALTER TABLE firewall_rules ADD COLUMN source TEXT") },
/// ```
///
/// then bump [`CURRENT_VERSION`] to the new length, and add a test that a
/// database from the previous version (a fixture in `tests/fixtures/`, or
/// the one [`Db::open_in_memory`](super::Db::open_in_memory) makes today)
/// comes through it with its data. Rules for the step itself:
///
/// - **Only this step's change.** Don't rewrite the baseline's `CREATE
///   TABLE`s: a fresh database runs the baseline and then every step, so a
///   new column belongs in the step that adds it, not in version 1.
/// - **Anything that can fail on real data goes before the change that
///   needs it.** A `UNIQUE` index on a table that already holds duplicates
///   fails, so delete them first, in the same step.
/// - **Keep stored values' meaning.** A step that renames a settings key
///   or changes how a value is spelled must rewrite the existing rows,
///   because the old binary is gone and nothing else will.
pub const MIGRATIONS: &[Migration] = &[Migration {
    summary: "the 0.0.x schema, with the column and cleanup every 0.0.x open applied",
    apply: v1_baseline,
}];

/// Where the copy of a database at `version` is kept before it is
/// migrated: next to it, named for the version it holds, so a failed or
/// unwanted upgrade can be undone by moving the file back.
pub fn backup_path(db: &Path, version: u32) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(format!(".bak-v{version}"));
    PathBuf::from(name)
}

/// Brings the database on `conn` to [`CURRENT_VERSION`], or refuses it.
/// `path` is the file behind `conn`, or `None` for an in-memory one, which
/// has nothing on disk to back up.
pub(super) fn migrate(conn: &Connection, path: Option<&Path>) -> Result<()> {
    let found = user_version(conn)?;
    refuse_if_newer(found, path)?;
    if found == CURRENT_VERSION {
        return Ok(());
    }
    // An empty file is a new database, not an old one: nothing to keep.
    let fresh = !has_tables(conn)?;
    if let (Some(path), false) = (path, fresh) {
        backup(conn, path, found)?;
    }

    // One transaction for every step and the version bump. Not only for
    // atomicity: in autocommit mode every `CREATE TABLE` is its own
    // transaction with its own fsync, and that made a *fresh database open
    // take ~450ms* on an ordinary disk. One transaction is one fsync.
    //
    // `IMMEDIATE` takes the write lock up front, so two processes opening
    // the same old database at once (the console and a `batch` from cron)
    // take turns rather than both migrating it.
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<()> {
        // Read again under the lock: whoever held it before us may have
        // migrated already, and a step must never run twice.
        let from = user_version(conn)?;
        refuse_if_newer(from, path)?;
        for (index, step) in MIGRATIONS.iter().enumerate().skip(from as usize) {
            (step.apply)(conn).with_context(|| {
                format!(
                    "failed to upgrade the database to schema version {} ({})",
                    index + 1,
                    step.summary
                )
            })?;
        }
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            // The step's error is the one worth reporting.
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

fn user_version(conn: &Connection) -> Result<u32> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("failed to read the database's schema version")?;
    // SQLite stores a signed 32-bit number; nothing here ever writes a
    // negative one, so a negative one was not written by stop-bots and is
    // as unknown as a version from the future.
    u32::try_from(version).map_err(|_| {
        anyhow::anyhow!("the database's schema version is {version}, which stop-bots never writes")
    })
}

fn refuse_if_newer(found: u32, path: Option<&Path>) -> Result<()> {
    if found <= CURRENT_VERSION {
        return Ok(());
    }
    let what = path.map_or_else(
        || "the database".to_string(),
        |p| format!("the database {}", p.display()),
    );
    bail!(
        "{what} is at schema version {found}, but this stop-bots ({}) only knows versions up \
         to {CURRENT_VERSION}. A newer stop-bots has upgraded it, and this one cannot tell \
         what the newer tables and settings mean. Run the newer stop-bots again; or, to go \
         back to this one, restore {}, the copy that upgrade took, if there is one",
        env!("CARGO_PKG_VERSION"),
        path.map_or_else(
            || format!("<db>.bak-v{CURRENT_VERSION}"),
            |p| backup_path(p, CURRENT_VERSION).display().to_string()
        ),
    )
}

fn has_tables(conn: &Connection) -> Result<bool> {
    Ok(conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table'")?
        .exists([])?)
}

/// Copies the database to [`backup_path`] before it is migrated.
///
/// `VACUUM INTO` rather than a file copy: it is a consistent snapshot
/// even with another process writing, and it includes anything still in a
/// `-wal` file, which copying the main file alone would miss. The copy is
/// created 0600 before SQLite writes into it (`VACUUM INTO` accepts an
/// empty file), because it holds everything the database does, the
/// console's password hash included.
///
/// An existing copy is never overwritten. It is older than this one and
/// may be the only copy of that state; the new one gets `.1`, `.2`, ...
fn backup(conn: &Connection, path: &Path, version: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let base = backup_path(path, version);
    let mut target = base.clone();
    let mut n = 0;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)
        {
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                n += 1;
                let mut name = base.as_os_str().to_owned();
                name.push(format!(".{n}"));
                target = PathBuf::from(name);
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create the pre-upgrade copy {}", target.display())
                })
            }
        }
    }
    let target_str = target
        .to_str()
        .with_context(|| format!("the backup path {} is not UTF-8", target.display()))?;
    conn.execute("VACUUM INTO ?1", params![target_str])
        .with_context(|| {
            format!(
                "failed to copy the database to {} before upgrading it; nothing was changed",
                target.display()
            )
        })?;
    Ok(())
}

/// Version 1: the schema every 0.0.x release converged on, as one step
/// that is safe to run on a database any of them wrote.
///
/// Before 0.1 there was no version: every open ran `CREATE TABLE IF NOT
/// EXISTS` for every table, plus two one-off repairs, and a release that
/// added a table simply added it there. So a 0.0.x database is always
/// *some prefix* of this schema, possibly missing tables added later, and
/// every statement here either creates what is missing or leaves what is
/// there alone. The two repairs are folded in with their guards, so they
/// too are no-ops on a database that doesn't need them.
///
/// Frozen from 0.1 on. A later change is a new step in [`MIGRATIONS`].
fn v1_baseline(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
            CREATE TABLE IF NOT EXISTS sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                last_fetched_at INTEGER,
                bot_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                is_ai INTEGER NOT NULL DEFAULT 0,
                is_search_engine INTEGER NOT NULL DEFAULT 0,
                is_scanner INTEGER NOT NULL DEFAULT 0,
                user_agent_pattern TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'default',
                source_id TEXT NOT NULL REFERENCES sources(id),
                updated_at INTEGER NOT NULL
            );

            -- One source's raw contribution for a bot, keyed by (slug,
            -- source_id) rather than bots.id: the first time a source
            -- contributes a slug, there may be no `bots` row for it yet.
            -- A `bots` row's own is_ai/is_search_engine/is_scanner/
            -- user_agent_pattern/name is the *merged* view recomputed from
            -- every row here for that slug (see Db::recompute_merged_bot)
            -- whenever any of them changes — this is what lets two
            -- different sources both describing the same bot (e.g. one
            -- tagging it is_ai, another tagging the same name is_scanner)
            -- combine instead of whichever fetched last silently
            -- overwriting the other's categorization.
            CREATE TABLE IF NOT EXISTS bot_source_entries (
                slug TEXT NOT NULL,
                source_id TEXT NOT NULL REFERENCES sources(id),
                name TEXT NOT NULL,
                is_ai INTEGER NOT NULL DEFAULT 0,
                is_search_engine INTEGER NOT NULL DEFAULT 0,
                is_scanner INTEGER NOT NULL DEFAULT 0,
                user_agent_pattern TEXT NOT NULL,
                PRIMARY KEY (slug, source_id)
            );

            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY,
                server_name TEXT NOT NULL,
                config_path TEXT NOT NULL,
                discovered_at INTEGER NOT NULL,
                UNIQUE(server_name, config_path)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER,
                action TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                expires_at INTEGER
            );

            -- Row presence encodes an override; absence means \"inherit the
            -- global category default\" (see get_site_category_override).
            CREATE TABLE IF NOT EXISTS site_category_overrides (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                category TEXT NOT NULL,
                policy TEXT NOT NULL,
                PRIMARY KEY (site_id, category)
            );

            -- Same presence-encodes-override convention as above, but for a
            -- single bot on a single site (see get_site_bot_override).
            CREATE TABLE IF NOT EXISTS site_bot_overrides (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                bot_id INTEGER NOT NULL REFERENCES bots(id),
                policy TEXT NOT NULL,
                PRIMARY KEY (site_id, bot_id)
            );

            -- Published crawler IP-range sources (Google, Bing, GPTBot, ...)
            -- and their current CIDRs. Kept separate from `sources`/`bots`:
            -- these publish one list per *publisher*, not per UA-slug, so
            -- there is no bot row to merge into (see `IpRangeSource`'s doc
            -- comment). `ip_ranges` is a plain child table, not a
            -- source-entries/merge setup like `bot_source_entries` — two
            -- sources publishing the exact same CIDR is not a real scenario
            -- worth designing for.
            -- Request-path prefixes where this site's bot block does not
            -- apply. Per site rather than host-wide because a rule like
            -- 'block AI bots everywhere except /blog' is inherently a
            -- property of that site's own URL space.
            CREATE TABLE IF NOT EXISTS site_path_exemptions (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                path TEXT NOT NULL,
                PRIMARY KEY (site_id, path)
            );
            -- The same, but only for clients whose user agent contains
            -- `user_agent`, ignoring case: 'let okhttp reach /remote.php/dav/
            -- on this site', for an app whose HTTP library a bot list names.
            -- A table of its own rather than a column on the one above,
            -- whose primary key would have to grow, which SQLite can only do
            -- by rebuilding the table.
            CREATE TABLE IF NOT EXISTS site_agent_exemptions (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                path TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                PRIMARY KEY (site_id, path, user_agent)
            );
            -- One row per (site, enabled request-shape rule). Row presence
            -- is the flag, the shape `selected_countries` uses; a per-site
            -- table rather than columns on `sites` because `sites` rows are
            -- rewritten wholesale by every scan and a setting must not be
            -- lost because someone re-ran discovery, and a table rather than
            -- one boolean column per rule so a new rule is a new
            -- `RequestRule` variant and no schema change.
            --
            -- This replaced a single-purpose `site_reject_http_1x` table,
            -- whose `http_1x` rule became one variant among six. That table
            -- is not created any more: nothing has read it since, and no
            -- released version ever wrote it.
            CREATE TABLE IF NOT EXISTS site_request_rules (
                site_id INTEGER NOT NULL REFERENCES sites(id),
                rule TEXT NOT NULL,
                PRIMARY KEY (site_id, rule)
            );
            CREATE TABLE IF NOT EXISTS ip_range_sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                category TEXT NOT NULL,
                last_fetched_at INTEGER,
                range_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS ip_ranges (
                source_id TEXT NOT NULL REFERENCES ip_range_sources(id),
                cidr TEXT NOT NULL,
                PRIMARY KEY (source_id, cidr)
            );

            -- One country's currently-known CIDR blocks (from IPdeny),
            -- fetched on demand per country rather than all ~250 at once —
            -- see `Db::replace_country_ranges`.
            CREATE TABLE IF NOT EXISTS country_ip_ranges (
                country_code TEXT NOT NULL,
                cidr TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (country_code, cidr)
            );

            -- Row presence means \"this country is in the active geo
            -- list\", host-wide (not per-site: per-site geo was dropped
            -- once real CIDR data, not just
            -- country codes, was in scope: some countries carry tens of
            -- thousands of CIDR blocks, which is impractical to enforce per
            -- NGINX vhost). What being \"in the list\" actually *means* —
            -- blocked, or the only ones allowed — depends on the
            -- `geo_mode` setting (see GeoMode), which is why this table is
            -- named for what it stores (a selection) rather than for one
            -- mode's interpretation of it.
            CREATE TABLE IF NOT EXISTS selected_countries (
                country_code TEXT PRIMARY KEY,
                added_at INTEGER NOT NULL
            );

            -- Successful-access user-agent frequency — the complement to
            -- `firewall_rules`' bad-traffic focus: `accesslog::
            -- successful_user_agent_counts` tallies who's actually browsing
            -- the site (status < 400, non-local/private IP) each time
            -- `Db::record_user_agent_hits` runs, and this table accumulates
            -- those counts across runs rather than replacing them, so it
            -- reflects lifetime traffic seen, not just the current log
            -- window (which may itself be rotated/truncated at any time).
            CREATE TABLE IF NOT EXISTS user_agent_stats (
                user_agent TEXT PRIMARY KEY,
                hit_count INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NOT NULL
            );

            -- Literal user agents an admin chose to permanently block from
            -- the Dashboard's \"Firewall\" screen — distinct from
            -- `bots`/`bot_source_entries`: those describe *known,
            -- publicly-catalogued* bots with category flags and a merge
            -- cascade across sources, which doesn't fit a one-off exact
            -- string an admin flagged by hand. Kept as its own small table,
            -- same shape as `selected_countries`/`firewall_rules`, and
            -- folded into `Db::compute_blocked_patterns`'s output (see
            -- there) so it enforces the same way any other blocked pattern
            -- does, globally and un-overridable per site — matching how a
            -- global per-bot pin already can't be overridden by a site's
            -- category override.
            -- Third-party reputation and cloud-provider CIDR feeds.
            -- Deliberately NOT stored in `ip_range_sources`: that table's
            -- `category` column is a *bot* category, and
            -- `blocked_ip_ranges` decides whether to apply a source's
            -- ranges by looking up that category's default. A reputation
            -- feed has no bot category, and worse, `IpRangeSourceKind::ALL`
            -- is what `scanblock::known_crawler_ranges` iterates to build
            -- the *exemption* list for scanner detection — adding feeds
            -- there would start exempting Spamhaus-listed addresses from
            -- being flagged as scanners, which is exactly backwards. A
            -- separate table keeps both concerns from ever meeting.
            CREATE TABLE IF NOT EXISTS reputation_sources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                last_fetched_at INTEGER,
                range_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS reputation_ranges (
                source_id TEXT NOT NULL REFERENCES reputation_sources(id),
                cidr TEXT NOT NULL,
                PRIMARY KEY (source_id, cidr)
            );
            CREATE TABLE IF NOT EXISTS blocked_user_agents (
                user_agent TEXT PRIMARY KEY,
                blocked_at INTEGER NOT NULL
            );
            -- Addresses a successful SSH login has been observed from, and
            -- when we observed it. The anti-lockout guarantee is built on
            -- this table: `firewall::all_rules` turns every row inside the
            -- window into an Allow rule ahead of everything else, so an
            -- address the operator actually logs in from cannot be blocked
            -- by any rule, derived or hand-written.
            --
            -- `seen_at` is *observation* time, not login time, and that is
            -- deliberate rather than a shortcut. sshd\'s own timestamps are
            -- not usable for a window this long: the syslog file format
            -- carries no year, and the `journalctl -o cat` fallback strips
            -- timestamps entirely. Observation time needs neither. It is
            -- also what survives log rotation — once a login is recorded
            -- here it stays for the full window even after the line that
            -- proved it is gone, which is the case that matters, since an
            -- operator who has not logged in for six days is exactly the
            -- one at risk of locking themselves out.
            --
            -- The trade is that a first run against an old log dates every
            -- login in it to now, over-protecting for up to a week. That
            -- errs in the safe direction for a table whose whole job is
            -- keeping the operator\'s way back in open.
            CREATE TABLE IF NOT EXISTS ssh_login_ips (
                address TEXT PRIMARY KEY,
                seen_at INTEGER NOT NULL
            );
            -- Clients an operator has said must never be blocked. The
            -- hand-written counterpart of `ssh_login_ips`: an address here
            -- becomes an Allow rule ahead of every other firewall rule and
            -- clears the NGINX block, and a user agent here clears the
            -- NGINX block (it cannot reach the firewall, which never sees
            -- one). Stored normalised — see `normalize_trusted_address` —
            -- so the primary key is what deduplicates `10.0.0.5/24` and
            -- `10.0.0.0/24`.
            CREATE TABLE IF NOT EXISTS trusted_addresses (
                address TEXT PRIMARY KEY,
                trusted_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trusted_user_agents (
                user_agent TEXT PRIMARY KEY,
                trusted_at INTEGER NOT NULL
            );
        ",
    )?;

    // `firewall_rules.expires_at` was added before 0.0.1 shipped, by a
    // guarded `ALTER TABLE` that every 0.0.x ran on open, so a database
    // made before the column existed got it on its next open. Kept, with
    // its guard: `ADD COLUMN` fails on a table that already has the
    // column, which is every table the `CREATE` above just made.
    let has_expires_at = conn
        .prepare("SELECT 1 FROM pragma_table_info('firewall_rules') WHERE name = 'expires_at'")?
        .exists([])?;
    if !has_expires_at {
        conn.execute(
            "ALTER TABLE firewall_rules ADD COLUMN expires_at INTEGER",
            [],
        )?;
    }

    // `firewall_rendered_signature` used to hold the rule set's entire
    // `Debug` dump rather than a digest of it (see
    // `firewall::rules_signature`). On a host with reputation feeds
    // enabled that is megabytes in one `settings` row — 4.7 MB, 31% of
    // the whole database, on the host that prompted this — and nothing
    // shrinks it until something happens to re-render. The CLI's
    // `render-firewall` doesn't record a signature at all, so on a host
    // driven from the command line that is *never*.
    //
    // Dropping it is the whole repair. The value is a cache of "what did
    // we last render", so losing it costs one spurious "the rules changed"
    // until the next render writes a digest. Guarded by length: a digest
    // is exactly 64 hex characters, and a `Debug` dump of even a single
    // rule is over a hundred, so the two can't be confused.
    conn.execute(
        "DELETE FROM settings
         WHERE key = 'firewall_rendered_signature' AND length(value) <> 64",
        [],
    )?;

    // Seed default category policies, matching the product defaults shown
    // in the README: scanners and AI bots blocked by default, search
    // engines allowed. `OR IGNORE`, so an operator's choice on an existing
    // database stands.
    for (key, default) in [
        (Category::Scanner.settings_key(), Policy::Blocked),
        (Category::Search.settings_key(), Policy::Allowed),
        (Category::Ai.settings_key(), Policy::Blocked),
    ] {
        conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, default.as_str()],
        )?;
    }

    // Seed the default geo mode: Blocklist (block specific countries,
    // allow everything else) — the least surprising default, and the
    // only one that's safe to render on either firewall backend.
    conn.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES ('geo_mode', ?1)",
        params![GeoMode::Blocklist.as_str()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn version_of(db: &Db) -> u32 {
        user_version(&db.conn).unwrap()
    }

    /// The one-line recipe for a new migration depends on these two
    /// moving together: a step without a bump would never run, and a bump
    /// without a step would mark databases as having a schema they don't.
    #[test]
    fn the_current_version_is_the_number_of_migrations() {
        assert_eq!(MIGRATIONS.len(), CURRENT_VERSION as usize);
    }

    #[test]
    fn a_new_database_is_created_at_the_current_version() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(version_of(&db), CURRENT_VERSION);
    }

    /// Nothing to lose in an empty file, so no copy of it either.
    #[test]
    fn a_new_database_on_disk_leaves_no_backup_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");

        Db::open(&path).unwrap();

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(files, ["db.sqlite3"], "files next to a new database");
    }

    /// A database written by any 0.0.x: tables, no version.
    fn pre_0_1_database(path: &Path, sql: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    #[test]
    fn a_pre_0_1_database_is_copied_before_it_is_upgraded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        pre_0_1_database(
            &path,
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO settings VALUES ('web:bind', '127.0.0.1:9000');",
        );

        let db = Db::open(&path).unwrap();

        assert_eq!(version_of(&db), CURRENT_VERSION);
        let backup = backup_path(&path, 0);
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the copy holds what the database does");
        let copy = Connection::open(&backup).unwrap();
        let (version, bind): (u32, String) = copy
            .query_row(
                "SELECT (SELECT user_version FROM pragma_user_version), value
                 FROM settings WHERE key = 'web:bind'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (version, bind.as_str()),
            (0, "127.0.0.1:9000"),
            "the copy is the database as it was, version included"
        );
    }

    /// The copy of an earlier upgrade may be the only one of that state.
    #[test]
    fn an_earlier_backup_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        std::fs::write(backup_path(&path, 0), "an earlier copy").unwrap();
        pre_0_1_database(
            &path,
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);",
        );

        Db::open(&path).unwrap();

        assert_eq!(
            std::fs::read_to_string(backup_path(&path, 0)).unwrap(),
            "an earlier copy"
        );
        let second = dir.path().join("db.sqlite3.bak-v0.1");
        assert!(second.exists(), "the new copy should sit beside it");
    }

    /// Opening a database that is already current must not copy it:
    /// that would be a full copy of the database on every CLI run.
    #[test]
    fn a_current_database_is_opened_without_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        drop(Db::open(&path).unwrap());

        Db::open(&path).unwrap();

        assert!(!backup_path(&path, CURRENT_VERSION).exists());
        assert!(!backup_path(&path, 0).exists());
    }

    #[test]
    fn a_database_from_a_newer_stop_bots_is_refused_naming_both_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        {
            let db = Db::open(&path).unwrap();
            db.conn
                .pragma_update(None, "user_version", CURRENT_VERSION + 1)
                .unwrap();
        }

        let err = Db::open(&path)
            .err()
            .expect("a newer database must be refused");

        let message = format!("{err:#}");
        for needle in [
            format!("schema version {}", CURRENT_VERSION + 1),
            format!("versions up to {CURRENT_VERSION}"),
            path.display().to_string(),
        ] {
            assert!(
                message.contains(&needle),
                "{needle:?} missing from: {message}"
            );
        }
    }

    /// Refusing must also leave it alone: no copy, no partial upgrade.
    #[test]
    fn a_refused_database_is_not_touched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        drop(Db::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();

        assert!(Db::open(&path).is_err());

        let version: u32 = Connection::open(&path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 99);
        assert!(!backup_path(&path, 99).exists());
    }

    /// Every 0.0.x re-ran the baseline on every open, so it has to be
    /// harmless on a database that already has all of it.
    #[test]
    fn the_baseline_can_run_on_a_database_that_already_has_it() {
        let db = Db::open_in_memory().unwrap();
        db.set_category_default(Category::Ai, Policy::Allowed)
            .unwrap();

        v1_baseline(&db.conn).unwrap();

        assert_eq!(
            db.get_stored_category_default(Category::Ai).unwrap(),
            Policy::Allowed,
            "re-seeding must not overwrite an operator's choice"
        );
    }

    /// The oldest shape `firewall_rules` had, before `expires_at`, gets
    /// the column and keeps its rows as permanent blocks.
    #[test]
    fn a_firewall_table_from_before_expiry_gets_the_column_and_keeps_its_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        pre_0_1_database(
            &path,
            "CREATE TABLE firewall_rules (
                 id INTEGER PRIMARY KEY, address TEXT NOT NULL, port INTEGER,
                 action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                 created_at INTEGER NOT NULL);
             INSERT INTO firewall_rules (address, action, created_at)
             VALUES ('203.0.113.7', 'block', 1700000000);",
        );

        let db = Db::open(&path).unwrap();

        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert_eq!(rules[0].address, "203.0.113.7");
        assert_eq!(rules[0].expires_at, None);
    }

    /// The upgrade path off the verbatim-dump format: a database carrying
    /// one must come back with it gone, not merely ignored, because the
    /// entire point is the megabytes it was occupying.
    #[test]
    fn upgrading_drops_a_pre_digest_firewall_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite3");
        pre_0_1_database(
            &path,
            // What the old `format!("{rules:?}")` would have stored.
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO settings VALUES ('firewall_rendered_signature',
               '[FirewallRule { id: 1, address: \"1.2.3.4\", port: None, action: Block, \
                enabled: true, expires_at: None }]');",
        );

        let db = Db::open(&path).unwrap();

        let rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM settings WHERE key = 'firewall_rendered_signature'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            rows, 0,
            "the row itself should be gone, not just unreadable"
        );
    }

    // ---- databases real 0.0.x releases wrote ----

    const DB_0_0_1: &str = include_str!("../../tests/fixtures/db/db-0.0.1.sql");
    const DB_0_0_15: &str = include_str!("../../tests/fixtures/db/db-0.0.15.sql");

    /// Opens `fixture`, restored into a file, the way an upgraded binary
    /// would find it on a host.
    fn upgraded(fixture: &str) -> (tempfile::TempDir, std::path::PathBuf, Db) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite3");
        pre_0_1_database(&path, fixture);
        let db = Db::open(&path).unwrap();
        (dir, path, db)
    }

    /// Every table and its columns (name, type, not-null, default,
    /// primary-key position), sorted. What a query can tell apart,
    /// without the comments and whitespace `sqlite_master` keeps.
    fn shape(db: &Db) -> Vec<String> {
        let mut tables = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap();
        let names: Vec<String> = tables
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut shape = Vec::new();
        for table in names {
            let mut columns = db
                .conn
                .prepare(
                    "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info(?1)",
                )
                .unwrap();
            let rows = columns
                .query_map([&table], |row| {
                    Ok(format!(
                        "{table}.{} {} notnull={} default={:?} pk={}",
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .unwrap();
            shape.extend(rows.map(Result::unwrap));
        }
        shape
    }

    #[test]
    fn a_0_0_1_database_upgrades_to_exactly_the_schema_of_a_new_one() {
        let (_dir, _path, old) = upgraded(DB_0_0_1);
        assert_eq!(shape(&old), shape(&Db::open_in_memory().unwrap()));
        assert_eq!(version_of(&old), CURRENT_VERSION);
    }

    #[test]
    fn a_0_0_15_database_upgrades_to_exactly_the_schema_of_a_new_one() {
        let (_dir, _path, old) = upgraded(DB_0_0_15);
        assert_eq!(shape(&old), shape(&Db::open_in_memory().unwrap()));
        assert_eq!(version_of(&old), CURRENT_VERSION);
    }

    #[test]
    fn upgrading_a_0_0_x_database_leaves_a_copy_of_it() {
        for (release, fixture) in [("0.0.1", DB_0_0_1), ("0.0.15", DB_0_0_15)] {
            let (_dir, path, _db) = upgraded(fixture);
            let copy = Connection::open(backup_path(&path, 0)).unwrap();
            let rules: i64 = copy
                .query_row("SELECT COUNT(*) FROM firewall_rules", [], |row| row.get(0))
                .unwrap();
            assert_eq!(rules, 5, "{release}: the copy should hold the old rules");
        }
    }

    /// Both fixtures hold three hand-added rules, which never expire, and
    /// two a detector added with a TTL.
    #[test]
    fn upgrading_keeps_every_firewall_rule_with_and_without_an_expiry() {
        for (release, fixture) in [("0.0.1", DB_0_0_1), ("0.0.15", DB_0_0_15)] {
            let (_dir, _path, db) = upgraded(fixture);
            let rules: Vec<_> = db
                .list_firewall_rules()
                .unwrap()
                .into_iter()
                .map(|r| (r.address, r.port, r.action, r.enabled, r.expires_at))
                .collect();
            use crate::db::FirewallAction::{Allow, Block};
            assert_eq!(
                rules,
                [
                    ("203.0.113.7".to_string(), None, Block, true, None),
                    ("198.51.100.0/24".to_string(), Some(22), Block, true, None),
                    ("192.0.2.1".to_string(), None, Allow, true, None),
                    (
                        "198.51.100.23".to_string(),
                        None,
                        Block,
                        true,
                        Some(4102444800)
                    ),
                    (
                        "203.0.113.99".to_string(),
                        None,
                        Block,
                        true,
                        Some(4102444800)
                    ),
                ],
                "{release}"
            );
        }
    }

    #[test]
    fn upgrading_keeps_sites_their_rules_and_the_bot_lists() {
        for (release, fixture) in [("0.0.1", DB_0_0_1), ("0.0.15", DB_0_0_15)] {
            let (_dir, _path, db) = upgraded(fixture);
            let sites = db.list_sites().unwrap();
            let names: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
            assert_eq!(names, ["example.com", "localhost"], "{release}");
            let example = sites[0].id;
            assert_eq!(
                db.site_request_rules(example).unwrap(),
                ["http_1x"],
                "{release}"
            );
            assert_eq!(
                db.site_path_exemptions(example).unwrap(),
                ["/blog/"],
                "{release}"
            );
            assert_eq!(db.list_bots().unwrap().len(), 6, "{release}");
            assert_eq!(db.list_sources().unwrap().len(), 2, "{release}");
            assert_eq!(db.list_selected_countries().unwrap(), ["hr"], "{release}");
        }
    }

    /// Every setting the fixtures changed from its default reads back
    /// changed. A key renamed or a value re-spelled by an upgrade would
    /// read as the default here instead.
    #[test]
    fn upgrading_keeps_every_setting() {
        use crate::protection::{self, Detector};
        for (release, fixture) in [("0.0.1", DB_0_0_1), ("0.0.15", DB_0_0_15)] {
            let (_dir, _path, db) = upgraded(fixture);
            let checks: [(&str, String, String); 12] = [
                (
                    "geo mode",
                    format!("{:?}", db.get_geo_mode().unwrap()),
                    "Allowlist".into(),
                ),
                (
                    "rate limiting",
                    db.get_rate_limit_enabled().unwrap().to_string(),
                    "true".into(),
                ),
                (
                    "rate",
                    db.get_rate_limit_rps().unwrap().to_string(),
                    "7".into(),
                ),
                (
                    "burst",
                    db.get_rate_limit_burst().unwrap().to_string(),
                    "11".into(),
                ),
                (
                    "robots.txt",
                    db.get_serve_robots_txt().unwrap().to_string(),
                    "true".into(),
                ),
                (
                    "block response",
                    format!("{:?}", db.get_block_response().unwrap()),
                    "Gone".into(),
                ),
                (
                    "honeypot",
                    protection::honeypot_path(&db).unwrap(),
                    "/my-trap/".into(),
                ),
                (
                    "probe paths",
                    protection::extra_probe_paths(&db).unwrap().join(","),
                    "/secret-admin/".into(),
                ),
                (
                    "nginx test",
                    crate::nginx::NginxCommands::from_db(&db)
                        .unwrap()
                        .test
                        .join(" "),
                    "/bin/true".into(),
                ),
                (
                    "web scanners",
                    Detector::WebScanners.is_enabled(&db).unwrap().to_string(),
                    "false".into(),
                ),
                (
                    "asset ratio",
                    Detector::AssetRatio.is_enabled(&db).unwrap().to_string(),
                    "true".into(),
                ),
                (
                    "probe TTL",
                    Detector::ProbePaths.ttl_days(&db).unwrap().to_string(),
                    "9".into(),
                ),
            ];
            for (what, got, want) in checks {
                assert_eq!(got, want, "{release}: {what}");
            }
            assert_eq!(
                db.get_stored_category_default(Category::Search).unwrap(),
                Policy::Allowed,
                "{release}"
            );
        }
    }

    #[test]
    fn upgrading_0_0_15_keeps_what_only_it_could_store() {
        let (_dir, _path, db) = upgraded(DB_0_0_15);
        assert_eq!(db.list_trusted_addresses().unwrap(), ["192.0.2.77"]);
        assert_eq!(db.list_trusted_user_agents().unwrap(), ["MyUptimeChecker"]);
        assert!(db.get_auto_apply().unwrap());
        assert_eq!(
            crate::logpaths::LogPaths::from_db(&db).unwrap().access,
            Some("/srv/log/access.log".into())
        );
    }

    /// 0.0.1 had no trust lists and no SSH login table; the upgrade adds
    /// them, empty, and they work.
    #[test]
    fn upgrading_0_0_1_adds_the_tables_later_releases_introduced() {
        let (_dir, _path, db) = upgraded(DB_0_0_1);
        assert!(db.list_trusted_addresses().unwrap().is_empty());
        db.trust_address("192.0.2.77").unwrap();
        db.record_ssh_login_ips(&["192.0.2.8".to_string()]).unwrap();
        assert_eq!(db.recent_ssh_login_ips().unwrap(), ["192.0.2.8"]);
    }
}
