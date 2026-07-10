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

//! SQLite-backed storage for known bots, bot-list sources, discovered NGINX
//! sites and global per-category blocking defaults.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether a category or bot should be allowed through or blocked at the NGINX layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    Allowed,
    #[default]
    Blocked,
}

impl Policy {
    fn as_str(self) -> &'static str {
        match self {
            Policy::Allowed => "allowed",
            Policy::Blocked => "blocked",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "allowed" => Ok(Policy::Allowed),
            "blocked" => Ok(Policy::Blocked),
            other => anyhow::bail!("invalid policy value: {other}"),
        }
    }
}

/// Per-bot status: either following the category default, or explicitly
/// overridden by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotStatus {
    Default,
    Allowed,
    Blocked,
}

impl BotStatus {
    fn as_str(self) -> &'static str {
        match self {
            BotStatus::Default => "default",
            BotStatus::Allowed => "allowed",
            BotStatus::Blocked => "blocked",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "allowed" => BotStatus::Allowed,
            "blocked" => BotStatus::Blocked,
            _ => BotStatus::Default,
        }
    }
}

/// The bot categories the system understands today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Scanner,
    Search,
    Ai,
}

impl Category {
    fn settings_key(self) -> &'static str {
        match self {
            Category::Scanner => "default_status_scanner",
            Category::Search => "default_status_search",
            Category::Ai => "default_status_ai",
        }
    }

    /// A plain identifier for this category, used as the `category` column
    /// value in `site_category_overrides` — distinct from [`Self::settings_key`],
    /// which is a compound key specific to the flat `settings` table.
    fn as_str(self) -> &'static str {
        match self {
            Category::Scanner => "scanner",
            Category::Search => "search",
            Category::Ai => "ai",
        }
    }

    /// Falls back to `Ai` for any unrecognized value, same
    /// never-fail-a-read-over-a-stored-enum convention as
    /// [`BotStatus::from_str`] and how `list_firewall_rules` reads back
    /// [`FirewallAction`] — the column is only ever written by
    /// [`Self::as_str`], so a mismatch here would mean a bug elsewhere, not
    /// bad user input to reject.
    fn from_str(s: &str) -> Self {
        match s {
            "scanner" => Category::Scanner,
            "search" => Category::Search,
            _ => Category::Ai,
        }
    }
}

/// How the countries in `selected_countries` should be enforced host-wide.
/// See [`Db::geo_firewall_rules`] for exactly what each mode produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeoMode {
    /// Selected countries are blocked; everything else is allowed (the
    /// default — matches the original, simpler design before allowlisting
    /// existed, and is the only mode safe to render on either firewall
    /// backend).
    #[default]
    Blocklist,
    /// Selected countries are the *only* ones allowed; everything else is
    /// blocked host-wide via a trailing catch-all. Meaningfully more
    /// dangerous than Blocklist — see `main.rs::render_firewall`'s
    /// nftables-only guard and SPECS.md.
    Allowlist,
}

impl GeoMode {
    fn as_str(self) -> &'static str {
        match self {
            GeoMode::Blocklist => "blocklist",
            GeoMode::Allowlist => "allowlist",
        }
    }

    /// Falls back to `Blocklist` for any unrecognized value, same
    /// never-fail-a-read-over-a-stored-enum convention as
    /// [`Category::from_str`] — the column is only ever written by
    /// [`Self::as_str`].
    fn from_str(s: &str) -> Self {
        match s {
            "allowlist" => GeoMode::Allowlist,
            _ => GeoMode::Blocklist,
        }
    }
}

/// A bot-list data source that bots can be fetched from.
#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub id: String,
    pub name: String,
    pub url: String,
    pub last_fetched_at: Option<i64>,
    pub bot_count: i64,
}

/// A single known bot, *merged* from every source that currently reports
/// it (see `bot_source_entries` and [`Db::upsert_bot`]): `is_ai`/
/// `is_search_engine`/`is_scanner` are true if *any* contributing source
/// says so, and `user_agent_pattern` is every distinct contributed pattern
/// joined with `|`. `source_id` is now purely informational — one of the
/// contributing sources, deterministically but arbitrarily chosen —
/// nothing in this codebase's blocking logic reads it; it stays on this
/// struct/table only because dropping it would need a schema migration
/// this project has never needed before, not because it means anything.
#[derive(Debug, Clone, PartialEq)]
pub struct Bot {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub is_ai: bool,
    pub is_search_engine: bool,
    pub is_scanner: bool,
    pub user_agent_pattern: String,
    pub status: BotStatus,
    pub source_id: String,
    pub updated_at: i64,
}

/// One source's raw contribution for a bot — what a bot-list parser
/// produces. The user's manual `status` override is intentionally not
/// part of this struct so that refreshing a bot list never clobbers it;
/// see [`Db::upsert_bot`]. Multiple `NewBot`s with the same `slug` but
/// different `source_id`s are expected and merged, not treated as
/// conflicting versions of one record — see `bot_source_entries`.
#[derive(Debug, Clone, PartialEq)]
pub struct NewBot {
    pub slug: String,
    pub name: String,
    pub is_ai: bool,
    pub is_search_engine: bool,
    pub is_scanner: bool,
    pub user_agent_pattern: String,
    pub source_id: String,
}

/// An NGINX site (server block) discovered on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct Site {
    pub id: i64,
    pub server_name: String,
    pub config_path: String,
    pub discovered_at: i64,
}

/// A single bot's blocking override for one site, from `site_bot_overrides`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteBotOverride {
    pub bot_id: i64,
    pub policy: Policy,
}

/// What a firewall rule should do with matching traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Block,
    Reject,
}

impl FirewallAction {
    fn as_str(self) -> &'static str {
        match self {
            FirewallAction::Allow => "allow",
            FirewallAction::Block => "block",
            FirewallAction::Reject => "reject",
        }
    }

    /// Parses an action, accepting both our canonical names and the
    /// upstream iptables/nftables spellings (`ACCEPT`/`accept`, `DROP`/
    /// `drop`, `REJECT`/`reject`), case-insensitively.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" | "accept" => Ok(FirewallAction::Allow),
            "block" | "drop" => Ok(FirewallAction::Block),
            "reject" => Ok(FirewallAction::Reject),
            other => anyhow::bail!("invalid firewall action: {other}"),
        }
    }
}

/// A firewall rule: allow, block or reject traffic from `address` (an IP
/// address or CIDR range), optionally restricted to `port`. `expires_at`
/// (Unix seconds) is `None` for a permanent, hand-added rule (via
/// [`Db::add_firewall_rule`]); `Some` for a temporary one (via
/// [`Db::add_firewall_rule_with_ttl`], e.g. `block-scanners`/
/// `block-web-scanners`'s auto-detected rows) — see
/// [`Db::list_firewall_rules`] for how expiry is actually enforced.
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallRule {
    pub id: i64,
    pub address: String,
    pub port: Option<u16>,
    pub action: FirewallAction,
    pub enabled: bool,
    pub expires_at: Option<i64>,
}

/// Fields needed to add a new firewall rule.
#[derive(Debug, Clone, PartialEq)]
pub struct NewFirewallRule {
    pub address: String,
    pub port: Option<u16>,
    pub action: FirewallAction,
}

/// A published IP-range source for a known crawler (Google, Bing, OpenAI's
/// GPTBot, ...), distinct from the UA-pattern `bots`/`sources` tables: these
/// publishers ship one CIDR list covering *all* of their crawling activity,
/// which doesn't line up with this app's much more granular per-variant bot
/// slugs (Google alone splits into a dozen `google-crawler-*` well-known-bots
/// entries). Blocking decisions for a source are made at the coarser
/// `category` level instead — see [`Db::blocked_ip_ranges`].
#[derive(Debug, Clone, PartialEq)]
pub struct IpRangeSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub category: Category,
    pub last_fetched_at: Option<i64>,
    pub range_count: i64,
}

/// Returns whether `address` is a plain IP address or CIDR range. A CIDR's
/// prefix length must be within the address family's actual bit width (0-32
/// for IPv4, 0-128 for IPv6) — otherwise it's a mask no renderer can turn
/// into a real `iptables`/`nft` rule, e.g. `1.2.3.4/40` or `1.2.3.4/999`
/// would slip past this check and fail at *apply* time instead, and on
/// iptables (whose generated script runs under `set -e`) that means the
/// script aborts partway through, having applied only some of its rules.
fn is_valid_address(address: &str) -> bool {
    use std::net::IpAddr;

    let address = address.trim();
    let Some((prefix, suffix)) = address.split_once('/') else {
        return address.parse::<IpAddr>().is_ok();
    };
    // `"+5".parse::<u32>()` succeeds, so the digit check must stay even
    // though we now also parse the value — otherwise a mask like `/+5`
    // would slip back through as "valid".
    if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(prefix_len) = suffix.parse::<u32>() else {
        return false;
    };
    match prefix.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix_len <= 32,
        Ok(IpAddr::V6(_)) => prefix_len <= 128,
        Err(_) => false,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// The database handle. Wraps a single SQLite connection.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Opens (creating if necessary) the database at `path`, creating parent
    /// directories as needed, and ensures the schema is up to date.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory: {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open database: {}", path.display()))?;
        let db = Db { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Opens an in-memory database. Intended for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory database")?;
        let db = Db { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
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
            -- list\", host-wide (not per-site — see SPECS.md for why
            -- per-site geo was dropped once real CIDR data, not just
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
            ",
        )?;

        // `firewall_rules.expires_at` is on the `CREATE TABLE` above, which
        // only takes effect for a database created fresh by this version —
        // an existing database from before this column existed needs it
        // added explicitly. This project has never needed a schema
        // migration before now (see the doc comment on `Bot::source_id`),
        // so there's no migration runner to hook into; this one column is
        // simple enough to guard by hand instead: `ALTER TABLE ADD COLUMN`
        // errors ("duplicate column name") if the column is already there
        // (which it always is on a fresh database, since `CREATE TABLE`
        // just added it above), so check via `PRAGMA table_info` first and
        // only run the `ALTER` on a database that actually predates it.
        let has_expires_at = self
            .conn
            .prepare("SELECT 1 FROM pragma_table_info('firewall_rules') WHERE name = 'expires_at'")?
            .exists([])?;
        if !has_expires_at {
            self.conn
                .execute("ALTER TABLE firewall_rules ADD COLUMN expires_at INTEGER", [])?;
        }

        // Seed default category policies, matching the product defaults shown
        // in the README: scanners and AI bots blocked by default, search engines allowed.
        for (key, default) in [
            (Category::Scanner.settings_key(), Policy::Blocked),
            (Category::Search.settings_key(), Policy::Allowed),
            (Category::Ai.settings_key(), Policy::Blocked),
        ] {
            self.conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
                params![key, default.as_str()],
            )?;
        }

        // Seed the default geo mode: Blocklist (block specific countries,
        // allow everything else) — the least surprising default, and the
        // only one that's safe to render on either firewall backend.
        self.conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('geo_mode', ?1)",
            params![GeoMode::Blocklist.as_str()],
        )?;

        Ok(())
    }

    // ---- sources ----

    /// Inserts a source, or updates it in place if its `id` already exists.
    pub fn upsert_source(&self, source: &Source) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sources (id, name, url, last_fetched_at, bot_count)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                url = excluded.url,
                last_fetched_at = excluded.last_fetched_at,
                bot_count = excluded.bot_count",
            params![
                source.id,
                source.name,
                source.url,
                source.last_fetched_at,
                source.bot_count
            ],
        )?;
        Ok(())
    }

    /// Registers `source` if no source with that `id` exists yet; a no-op
    /// otherwise. Unlike [`Self::upsert_source`], this never overwrites an
    /// already-fetched source's `last_fetched_at`/`bot_count` — it's meant to
    /// make a known source selectable (and thus fetchable) in the TUI before
    /// it has ever been fetched, not to refresh one that has.
    pub fn register_source(&self, source: &Source) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO sources (id, name, url, last_fetched_at, bot_count)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                source.id,
                source.name,
                source.url,
                source.last_fetched_at,
                source.bot_count
            ],
        )?;
        Ok(())
    }

    /// Records that `id` was just fetched, with `bot_count` bots found.
    pub fn touch_source(&self, id: &str, bot_count: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE sources SET last_fetched_at = ?1, bot_count = ?2 WHERE id = ?3",
            params![now(), bot_count, id],
        )?;
        Ok(())
    }

    pub fn list_sources(&self) -> Result<Vec<Source>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, url, last_fetched_at, bot_count FROM sources ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok(Source {
                id: row.get(0)?,
                name: row.get(1)?,
                url: row.get(2)?,
                last_fetched_at: row.get(3)?,
                bot_count: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list sources")
    }

    // ---- bots ----

    /// Records one source's contribution for a bot (`bot.slug`,
    /// `bot.source_id`), then recomputes that slug's merged row in `bots`
    /// from every source's current contribution to it — see
    /// [`Self::recompute_merged_bot`]. The user's manual `status` override
    /// is untouched either way, same guarantee this always had.
    pub fn upsert_bot(&self, bot: &NewBot) -> Result<()> {
        self.conn.execute(
            "INSERT INTO bot_source_entries (slug, source_id, name, is_ai, is_search_engine, is_scanner, user_agent_pattern)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(slug, source_id) DO UPDATE SET
                name = excluded.name,
                is_ai = excluded.is_ai,
                is_search_engine = excluded.is_search_engine,
                is_scanner = excluded.is_scanner,
                user_agent_pattern = excluded.user_agent_pattern",
            params![
                bot.slug,
                bot.source_id,
                bot.name,
                bot.is_ai,
                bot.is_search_engine,
                bot.is_scanner,
                bot.user_agent_pattern,
            ],
        )?;
        self.recompute_merged_bot(&bot.slug)
    }

    /// Deletes every `bot_source_entries` row for `source_id` (called
    /// before a re-fetch re-inserts its current list, so a bot this fetch
    /// no longer includes stops being attributed to it too, rather than
    /// accumulating stale contributions forever), returning the distinct
    /// slugs that were affected. The caller is responsible for calling
    /// [`Self::recompute_merged_bot`] on any of these not present in the
    /// new batch — a slug this source just dropped might still have other
    /// sources' entries to fall back to.
    pub fn clear_source_bot_entries(&self, source_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT slug FROM bot_source_entries WHERE source_id = ?1")?;
        let slugs = stmt
            .query_map(params![source_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list a source's contributed slugs")?;
        self.conn.execute(
            "DELETE FROM bot_source_entries WHERE source_id = ?1",
            params![source_id],
        )?;
        Ok(slugs)
    }

    /// How many distinct bots `source_id` currently contributes to the
    /// merged list — the accurate, post-collapse count, unlike a source's
    /// own raw pre-dedup parsed length (which is what `sources.bot_count`
    /// used to be set from, and could overstate reality once a source had
    /// internal duplicates or another source reclaimed an overlapping
    /// slug).
    pub fn count_bot_source_entries(&self, source_id: &str) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM bot_source_entries WHERE source_id = ?1",
                params![source_id],
                |row| row.get(0),
            )
            .context("failed to count a source's contributed bots")
    }

    /// Recomputes `slug`'s merged row in `bots` from every remaining
    /// `bot_source_entries` row for it: `is_ai`/`is_search_engine`/
    /// `is_scanner` are true if *any* contributing source says so;
    /// `user_agent_pattern` is every distinct contributed pattern joined
    /// with `|` (the same "multiple accepted patterns" shape a single
    /// source's own list can already produce); `name` is the longest
    /// contributed name (ties broken by whichever sorts later
    /// alphabetically) — usually the most descriptive/properly-cased
    /// variant, and deterministic regardless of fetch order. A no-op if
    /// `slug` has zero entries: if it never had any, there's nothing to
    /// create; if it just dropped to zero (its last contributing source
    /// stopped reporting it), the existing `bots` row — and any manual
    /// `status` override or site override pointing at its id — is
    /// deliberately left exactly as it was rather than zeroed out or
    /// deleted, the same "never silently destroy state" bias the rest of
    /// this schema already follows.
    pub fn recompute_merged_bot(&self, slug: &str) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT source_id, name, is_ai, is_search_engine, is_scanner, user_agent_pattern
             FROM bot_source_entries WHERE slug = ?1 ORDER BY source_id",
        )?;
        let entries: Vec<(String, String, bool, bool, bool, String)> = stmt
            .query_map(params![slug], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to load a bot's source entries")?;

        let Some(first) = entries.first() else {
            return Ok(());
        };

        let is_ai = entries.iter().any(|e| e.2);
        let is_search_engine = entries.iter().any(|e| e.3);
        let is_scanner = entries.iter().any(|e| e.4);

        let mut patterns: Vec<&str> = Vec::new();
        for entry in &entries {
            if !patterns.contains(&entry.5.as_str()) {
                patterns.push(&entry.5);
            }
        }
        let user_agent_pattern = patterns.join("|");

        let mut name = first.1.clone();
        for entry in &entries[1..] {
            if entry.1.len() > name.len() || (entry.1.len() == name.len() && entry.1 > name) {
                name = entry.1.clone();
            }
        }

        // Purely informational (see `Bot`'s doc comment) — the
        // alphabetically last contributing source id, an arbitrary but
        // deterministic pick.
        let source_id = &entries.last().expect("checked non-empty above").0;

        self.conn.execute(
            "INSERT INTO bots (slug, name, is_ai, is_search_engine, is_scanner, user_agent_pattern, status, source_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'default', ?7, ?8)
             ON CONFLICT(slug) DO UPDATE SET
                name = excluded.name,
                is_ai = excluded.is_ai,
                is_search_engine = excluded.is_search_engine,
                is_scanner = excluded.is_scanner,
                user_agent_pattern = excluded.user_agent_pattern,
                source_id = excluded.source_id,
                updated_at = excluded.updated_at",
            params![
                slug,
                name,
                is_ai,
                is_search_engine,
                is_scanner,
                user_agent_pattern,
                source_id,
                now()
            ],
        )?;
        Ok(())
    }

    /// Sets a manual status override for the bot identified by `slug`.
    pub fn set_bot_status(&self, slug: &str, status: BotStatus) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE bots SET status = ?1 WHERE slug = ?2",
            params![status.as_str(), slug],
        )?;
        if changed == 0 {
            anyhow::bail!("no bot with slug: {slug}");
        }
        Ok(())
    }

    pub fn list_bots(&self) -> Result<Vec<Bot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, slug, name, is_ai, is_search_engine, is_scanner, user_agent_pattern, status, source_id, updated_at
             FROM bots ORDER BY slug",
        )?;
        let rows = stmt.query_map([], Self::row_to_bot)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list bots")
    }

    fn row_to_bot(row: &rusqlite::Row) -> rusqlite::Result<Bot> {
        let status: String = row.get(7)?;
        Ok(Bot {
            id: row.get(0)?,
            slug: row.get(1)?,
            name: row.get(2)?,
            is_ai: row.get(3)?,
            is_search_engine: row.get(4)?,
            is_scanner: row.get(5)?,
            user_agent_pattern: row.get(6)?,
            status: BotStatus::from_str(&status),
            source_id: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }

    // ---- settings ----

    pub fn get_category_default(&self, category: Category) -> Result<Policy> {
        let value: String = self.conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![category.settings_key()],
            |row| row.get(0),
        )?;
        Policy::from_str(&value)
    }

    pub fn set_category_default(&self, category: Category, policy: Policy) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![category.settings_key(), policy.as_str()],
        )?;
        Ok(())
    }

    pub fn get_geo_mode(&self) -> Result<GeoMode> {
        let value: String = self.conn.query_row(
            "SELECT value FROM settings WHERE key = 'geo_mode'",
            [],
            |row| row.get(0),
        )?;
        Ok(GeoMode::from_str(&value))
    }

    pub fn set_geo_mode(&self, mode: GeoMode) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES ('geo_mode', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![mode.as_str()],
        )?;
        Ok(())
    }

    // ---- internal cron (`crate::cron`) ----
    //
    // Reuses the existing `settings` key/value table rather than a new one:
    // this project's first (and, so far, only) schema migration was adding
    // `firewall_rules.expires_at` for scanner-detection TTLs — a second
    // migration isn't worth it just to persist "when did each background
    // job last run". Two keys per job, `cron_last_run:{id}` (a Unix
    // timestamp, as text) and `cron_last_summary:{id}` (a short
    // human-readable outcome), so both the Dashboard's "Scheduled tasks"
    // panel and `crate::cron::due_jobs` can read a job's state without
    // needing its own row shape.

    /// When `job_id` last ran, or `None` if it never has (on a fresh
    /// database, or a database from before this feature existed) — treated
    /// by [`crate::cron::due_jobs`] as "due immediately", the same
    /// never-fetched-yet-so-do-it-now convention `ipranges` sources already
    /// use for staleness.
    pub fn get_cron_last_run(&self, job_id: &str) -> Result<Option<i64>> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![format!("cron_last_run:{job_id}")],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|v| v.parse::<i64>().context("corrupt cron_last_run value"))
            .transpose()
    }

    /// Records that `job_id` just ran at `ran_at` (Unix seconds) with a
    /// short `summary` of what happened — both are always set together so
    /// a caller reading the Dashboard's job list never sees a fresh
    /// timestamp next to a stale summary from a previous run, or vice versa.
    pub fn set_cron_last_run(&self, job_id: &str, ran_at: i64, summary: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![format!("cron_last_run:{job_id}"), ran_at.to_string()],
        )?;
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![format!("cron_last_summary:{job_id}"), summary],
        )?;
        Ok(())
    }

    /// `job_id`'s last recorded outcome, or `None` if it's never run.
    pub fn get_cron_last_summary(&self, job_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![format!("cron_last_summary:{job_id}")],
                |row| row.get(0),
            )
            .optional()?)
    }

    // ---- sites ----

    /// Records that a site with the given `server_name` was discovered in
    /// `config_path`. Idempotent: re-scanning the same site just bumps
    /// `discovered_at`.
    pub fn upsert_site(&self, server_name: &str, config_path: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sites (server_name, config_path, discovered_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(server_name, config_path) DO UPDATE SET discovered_at = excluded.discovered_at",
            params![server_name, config_path, now()],
        )?;
        Ok(())
    }

    pub fn list_sites(&self) -> Result<Vec<Site>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, server_name, config_path, discovered_at FROM sites ORDER BY server_name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Site {
                id: row.get(0)?,
                server_name: row.get(1)?,
                config_path: row.get(2)?,
                discovered_at: row.get(3)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list sites")
    }

    // ---- per-site overrides ----

    /// The site's override for `category`, if one has been set. `None`
    /// means "inherit the global category default" — no row is stored for
    /// that case, so absence is exactly how "not overridden" is represented.
    pub fn get_site_category_override(
        &self,
        site_id: i64,
        category: Category,
    ) -> Result<Option<Policy>> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT policy FROM site_category_overrides WHERE site_id = ?1 AND category = ?2",
                params![site_id, category.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        value.map(|v| Policy::from_str(&v)).transpose()
    }

    /// Sets, or clears (`policy = None`), `site_id`'s override for `category`.
    pub fn set_site_category_override(
        &self,
        site_id: i64,
        category: Category,
        policy: Option<Policy>,
    ) -> Result<()> {
        match policy {
            Some(policy) => {
                self.conn.execute(
                    "INSERT INTO site_category_overrides (site_id, category, policy)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(site_id, category) DO UPDATE SET policy = excluded.policy",
                    params![site_id, category.as_str(), policy.as_str()],
                )?;
            }
            None => {
                self.conn.execute(
                    "DELETE FROM site_category_overrides WHERE site_id = ?1 AND category = ?2",
                    params![site_id, category.as_str()],
                )?;
            }
        }
        Ok(())
    }

    /// Every per-bot override set for `site_id`. Sparse by design — most
    /// sites override nothing, so this is typically empty rather than
    /// listing every known bot with a "no override" placeholder.
    pub fn site_bot_overrides(&self, site_id: i64) -> Result<Vec<SiteBotOverride>> {
        let mut stmt = self
            .conn
            .prepare("SELECT bot_id, policy FROM site_bot_overrides WHERE site_id = ?1")?;
        let rows = stmt.query_map(params![site_id], |row| {
            let policy: String = row.get(1)?;
            Ok((row.get::<_, i64>(0)?, policy))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list site bot overrides")?
            .into_iter()
            .map(|(bot_id, policy)| {
                Ok(SiteBotOverride {
                    bot_id,
                    policy: Policy::from_str(&policy)?,
                })
            })
            .collect()
    }

    /// Sets, or clears (`policy = None`), `site_id`'s override for `bot_id`.
    pub fn set_site_bot_override(
        &self,
        site_id: i64,
        bot_id: i64,
        policy: Option<Policy>,
    ) -> Result<()> {
        match policy {
            Some(policy) => {
                self.conn.execute(
                    "INSERT INTO site_bot_overrides (site_id, bot_id, policy)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(site_id, bot_id) DO UPDATE SET policy = excluded.policy",
                    params![site_id, bot_id, policy.as_str()],
                )?;
            }
            None => {
                self.conn.execute(
                    "DELETE FROM site_bot_overrides WHERE site_id = ?1 AND bot_id = ?2",
                    params![site_id, bot_id],
                )?;
            }
        }
        Ok(())
    }

    /// Like [`Self::blocked_user_agent_patterns`], but layering `site_id`'s
    /// category and per-bot overrides on top of the global cascade. See the
    /// precedence order documented on [`Self::compute_blocked_patterns`].
    pub fn blocked_user_agent_patterns_for_site(&self, site_id: i64) -> Result<Vec<String>> {
        let ai = self
            .get_site_category_override(site_id, Category::Ai)?
            .unwrap_or(self.get_category_default(Category::Ai)?);
        let search = self
            .get_site_category_override(site_id, Category::Search)?
            .unwrap_or(self.get_category_default(Category::Search)?);
        let scanner = self
            .get_site_category_override(site_id, Category::Scanner)?
            .unwrap_or(self.get_category_default(Category::Scanner)?);
        let overrides = self.site_bot_overrides(site_id)?;
        self.compute_blocked_patterns(ai, search, scanner, &overrides)
    }

    // ---- firewall rules ----

    /// Adds a new firewall rule, enabled by default, that never expires.
    /// Returns its id. Every hand-added rule (`add-firewall-rule`) goes
    /// through here — permanent unless an admin removes it themselves.
    pub fn add_firewall_rule(&self, rule: &NewFirewallRule) -> Result<i64> {
        self.insert_firewall_rule(rule, None)
    }

    /// Adds a new firewall rule, enabled by default, that expires
    /// `ttl_seconds` from now — [`Self::list_firewall_rules`] (and so every
    /// renderer/lister that reads through it) stops returning the row once
    /// its `expires_at` has passed, and actually deletes it at that point
    /// rather than just hiding it. Used for auto-detected scanner rules
    /// (`block-scanners`/`block-web-scanners`), where a temporary block is
    /// the point — a bot that stops scanning shouldn't stay blocked
    /// forever, and one that doesn't will simply get re-flagged and
    /// re-added on the next detection run after this one lapses.
    /// `ttl_seconds` isn't validated as positive: a zero or negative value
    /// legitimately produces an already-expired row (used by tests to
    /// exercise pruning deterministically without waiting or mocking time).
    pub fn add_firewall_rule_with_ttl(&self, rule: &NewFirewallRule, ttl_seconds: i64) -> Result<i64> {
        self.insert_firewall_rule(rule, Some(now() + ttl_seconds))
    }

    fn insert_firewall_rule(&self, rule: &NewFirewallRule, expires_at: Option<i64>) -> Result<i64> {
        if !is_valid_address(&rule.address) {
            anyhow::bail!("invalid firewall rule address: {}", rule.address);
        }
        self.conn.execute(
            "INSERT INTO firewall_rules (address, port, action, enabled, created_at, expires_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            params![rule.address, rule.port, rule.action.as_str(), now(), expires_at],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Deletes every firewall rule whose `expires_at` has passed. Returns
    /// how many were removed. Called at the top of
    /// [`Self::list_firewall_rules`] so every consumer (rendering, the CLI
    /// listing, the scanner commands' own dedup check) sees a
    /// already-pruned table without needing to remember to call this
    /// separately — critical for the scanner commands specifically: their
    /// "is this address already covered by an existing rule" dedup check
    /// reads through `list_firewall_rules`, so an expired-but-not-yet-
    /// deleted row would otherwise make a still-scanning IP whose block
    /// just lapsed look "already covered" forever instead of getting
    /// re-flagged.
    pub fn prune_expired_firewall_rules(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM firewall_rules WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now()],
        )?)
    }

    /// Deletes the firewall rule with the given id. Errors if no such rule exists.
    pub fn remove_firewall_rule(&self, id: i64) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])?;
        if changed == 0 {
            anyhow::bail!("no firewall rule with id: {id}");
        }
        Ok(())
    }

    /// Enables or disables the firewall rule with the given id, without
    /// deleting it. Errors if no such rule exists.
    pub fn set_firewall_rule_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE firewall_rules SET enabled = ?1 WHERE id = ?2",
            params![enabled, id],
        )?;
        if changed == 0 {
            anyhow::bail!("no firewall rule with id: {id}");
        }
        Ok(())
    }

    /// Lists every firewall rule, including disabled ones. Renderers
    /// (`iptables::render`, `nftables::render`) skip disabled rules
    /// themselves. Prunes expired rules first (see
    /// [`Self::prune_expired_firewall_rules`]) so every caller — rendering,
    /// the CLI listing, the scanner commands' dedup check — automatically
    /// sees a table with no stale, already-lapsed rows in it.
    pub fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        self.prune_expired_firewall_rules()?;
        let mut stmt = self.conn.prepare(
            "SELECT id, address, port, action, enabled, expires_at FROM firewall_rules ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let action: String = row.get(3)?;
            Ok(FirewallRule {
                id: row.get(0)?,
                address: row.get(1)?,
                port: row.get(2)?,
                action: FirewallAction::parse(&action).unwrap_or(FirewallAction::Block),
                enabled: row.get(4)?,
                expires_at: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list firewall rules")
    }

    // ---- crawler IP-range sources ----

    /// Registers `source` if no source with that `id` exists yet, same
    /// never-clobber-an-already-fetched-source convention as
    /// [`Self::register_source`].
    pub fn register_ip_range_source(&self, source: &IpRangeSource) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO ip_range_sources (id, name, url, category, last_fetched_at, range_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                source.id,
                source.name,
                source.url,
                source.category.as_str(),
                source.last_fetched_at,
                source.range_count
            ],
        )?;
        Ok(())
    }

    pub fn list_ip_range_sources(&self) -> Result<Vec<IpRangeSource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, url, category, last_fetched_at, range_count
             FROM ip_range_sources ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let category: String = row.get(3)?;
            Ok(IpRangeSource {
                id: row.get(0)?,
                name: row.get(1)?,
                url: row.get(2)?,
                category: Category::from_str(&category),
                last_fetched_at: row.get(4)?,
                range_count: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list ip range sources")
    }

    /// Replaces every CIDR `source_id` currently contributes with `cidrs`,
    /// updates its `last_fetched_at`/`range_count`, and returns the new
    /// count — same clear-then-reinsert idiom as
    /// [`Self::clear_source_bot_entries`], so a CIDR dropped from the
    /// upstream list on a later fetch doesn't linger here forever.
    pub fn replace_ip_ranges(&self, source_id: &str, cidrs: &[String]) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM ip_ranges WHERE source_id = ?1",
            params![source_id],
        )?;
        for cidr in cidrs {
            self.conn.execute(
                "INSERT OR IGNORE INTO ip_ranges (source_id, cidr) VALUES (?1, ?2)",
                params![source_id, cidr],
            )?;
        }
        // The real distinct count, not `cidrs.len()`: `INSERT OR IGNORE`
        // above means a source whose fetched list has internal duplicate
        // CIDRs would otherwise overstate its own count here — the same
        // drift `count_bot_source_entries` exists to avoid for bot-list
        // sources.
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ip_ranges WHERE source_id = ?1",
            params![source_id],
            |row| row.get(0),
        )?;
        self.conn.execute(
            "UPDATE ip_range_sources SET last_fetched_at = ?1, range_count = ?2 WHERE id = ?3",
            params![now(), count, source_id],
        )?;
        Ok(count as usize)
    }

    pub fn ip_ranges_for_source(&self, source_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT cidr FROM ip_ranges WHERE source_id = ?1 ORDER BY cidr")?;
        let rows = stmt.query_map(params![source_id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list a source's ip ranges")
    }

    /// Every CIDR from every registered IP-range source whose `category`
    /// currently defaults to Blocked. Coarser than
    /// [`Self::blocked_user_agent_patterns`]: it only ever consults the
    /// *global category default*, not per-bot overrides or site overrides —
    /// there is no single bot row a multi-variant publisher like Google maps
    /// onto (see `IpRangeSource`'s doc comment), so there is nothing finer
    /// to check. A source whose category defaults to Allowed (e.g. Google
    /// and Bing, since Search is Allowed by default) contributes nothing —
    /// not a bug, just this mechanism's natural, documented inertness until
    /// that category is actually blocked.
    pub fn blocked_ip_ranges(&self) -> Result<Vec<String>> {
        let mut addrs = Vec::new();
        for source in self.list_ip_range_sources()? {
            if self.get_category_default(source.category)? == Policy::Blocked {
                addrs.extend(self.ip_ranges_for_source(&source.id)?);
            }
        }
        Ok(addrs)
    }

    // ---- country IP ranges and host-wide geo blocking ----

    /// Replaces every CIDR known for `country_code` with `cidrs`, stamping
    /// them with the current time. Same clear-then-reinsert idiom as
    /// [`Self::replace_ip_ranges`] — a CIDR IPdeny drops from a country's
    /// zone file on a later fetch stops being attributed to it.
    pub fn replace_country_ranges(&self, country_code: &str, cidrs: &[String]) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM country_ip_ranges WHERE country_code = ?1",
            params![country_code],
        )?;
        let fetched_at = now();
        for cidr in cidrs {
            self.conn.execute(
                "INSERT OR IGNORE INTO country_ip_ranges (country_code, cidr, fetched_at)
                 VALUES (?1, ?2, ?3)",
                params![country_code, cidr, fetched_at],
            )?;
        }
        Ok(cidrs.len())
    }

    /// Every country code with at least one fetched CIDR, alongside how many
    /// and when they were last fetched — backs a CLI listing of "which
    /// countries have data available to block".
    pub fn list_fetched_countries(&self) -> Result<Vec<(String, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT country_code, COUNT(*), MAX(fetched_at) FROM country_ip_ranges
             GROUP BY country_code ORDER BY country_code",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list fetched countries")
    }

    /// Adds or removes `country_code` from the active geo selection. Row
    /// presence in `selected_countries` encodes membership, same convention
    /// as the site override tables — what membership actually *means*
    /// (blocked, or the only one allowed) depends on [`Self::get_geo_mode`].
    pub fn set_country_selected(&self, country_code: &str, selected: bool) -> Result<()> {
        if selected {
            self.conn.execute(
                "INSERT OR IGNORE INTO selected_countries (country_code, added_at) VALUES (?1, ?2)",
                params![country_code, now()],
            )?;
        } else {
            self.conn.execute(
                "DELETE FROM selected_countries WHERE country_code = ?1",
                params![country_code],
            )?;
        }
        Ok(())
    }

    pub fn list_selected_countries(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT country_code FROM selected_countries ORDER BY country_code")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list selected countries")
    }

    /// Every CIDR currently known for `country_code` — a plain lookup, not
    /// filtered by selection state, unlike the old (removed)
    /// `blocked_country_ranges`'s all-blocked-countries join. A country
    /// with no fetched ranges yet simply returns empty, not an error.
    fn country_ranges(&self, country_code: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT cidr FROM country_ip_ranges WHERE country_code = ?1 ORDER BY cidr")?;
        let rows = stmt.query_map(params![country_code], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list a country's ip ranges")
    }

    /// The host-wide geo portion of the firewall, as `(address, action)`
    /// pairs in the exact order they must be rendered — see
    /// [`Self::derived_firewall_entries`] and `main.rs::render_firewall`,
    /// which appends this after admin rules and crawler IP ranges, never
    /// reorders it, and feeds the same ordered list to both the rendered
    /// script and the pre-render lockout safety check.
    ///
    /// - [`GeoMode::Blocklist`]: every selected country's CIDRs, as Block.
    ///   A country selected before its ranges were ever fetched (or after
    ///   its only fetch was cleared) simply contributes nothing yet, not an
    ///   error — same "fetching and selecting are independent steps"
    ///   reasoning `ipranges`'s doc comments already describe.
    /// - [`GeoMode::Allowlist`]: every selected country's CIDRs, as Allow,
    ///   **followed by** a trailing `0.0.0.0/0`/`::/0` Block — the
    ///   "everything else" catch-all. Order is load-bearing here: the
    ///   catch-all must be last so it never shadows an allowed country's
    ///   rule (or, upstream of this function, an admin's own explicit
    ///   Allow rule) that came before it. This mode is meaningfully more
    ///   dangerous than Blocklist — see `main.rs::render_firewall`'s
    ///   nftables-only guard.
    pub fn geo_firewall_rules(&self) -> Result<Vec<(String, FirewallAction)>> {
        let mode = self.get_geo_mode()?;
        let selected = self.list_selected_countries()?;
        let mut rules = Vec::new();
        let action = match mode {
            GeoMode::Blocklist => FirewallAction::Block,
            GeoMode::Allowlist => FirewallAction::Allow,
        };
        for country_code in &selected {
            for cidr in self.country_ranges(country_code)? {
                rules.push((cidr, action));
            }
        }
        if mode == GeoMode::Allowlist {
            rules.push(("0.0.0.0/0".to_string(), FirewallAction::Block));
            rules.push(("::/0".to_string(), FirewallAction::Block));
        }
        Ok(rules)
    }

    /// Every `(address, action)` pair [`Self::blocked_ip_ranges`] (always
    /// Block) and [`Self::geo_firewall_rules`] (Block or Allow, depending on
    /// mode) currently contribute, combined — what `render-firewall` layers
    /// on top of the admin-managed `firewall_rules` table as synthetic,
    /// non-persisted rules (see `main.rs::render_firewall`). Not persisted
    /// into `firewall_rules` itself: recomputing this fresh on every render
    /// means there is never a stale derived row to reconcile, and an
    /// admin's own rules are never at risk of being deleted by a refresh.
    pub fn derived_firewall_entries(&self) -> Result<Vec<(String, FirewallAction)>> {
        let mut entries: Vec<(String, FirewallAction)> = self
            .blocked_ip_ranges()?
            .into_iter()
            .map(|address| (address, FirewallAction::Block))
            .collect();
        entries.extend(self.geo_firewall_rules()?);
        Ok(entries)
    }

    /// Computes the user-agent regex alternatives for every bot that should
    /// currently be blocked, taking category defaults and per-bot overrides
    /// into account. Returns an empty vec if nothing should be blocked.
    pub fn blocked_user_agent_patterns(&self) -> Result<Vec<String>> {
        let ai_default = self.get_category_default(Category::Ai)?;
        let search_default = self.get_category_default(Category::Search)?;
        let scanner_default = self.get_category_default(Category::Scanner)?;
        self.compute_blocked_patterns(ai_default, search_default, scanner_default, &[])
    }

    /// Shared cascade behind [`Self::blocked_user_agent_patterns`] and
    /// [`Self::blocked_user_agent_patterns_for_site`]. Precedence, most to
    /// least specific:
    ///
    /// 1. `bot_overrides` (a site's per-bot override, when called for a
    ///    site — empty for the global case) — decisive.
    /// 2. `bot.status` (a *global* per-bot override) — decisive, bypasses
    ///    category checks entirely.
    /// 3. Otherwise, per category the bot belongs to: `ai`/`search`/
    ///    `scanner` here are already the *effective* values for the call
    ///    site (a site's category override if it has one, else the global
    ///    default) — blocked if any matching category is `Blocked`.
    ///
    /// Note the asymmetry: a site's category override can never override a
    /// *global* per-bot pin — only a site's own per-bot override can. That
    /// bypass-categories-entirely behavior for an explicit bot pin already
    /// existed before per-site overrides did; this just applies it at both
    /// levels rather than inventing a second rule for the site layer.
    fn compute_blocked_patterns(
        &self,
        ai: Policy,
        search: Policy,
        scanner: Policy,
        bot_overrides: &[SiteBotOverride],
    ) -> Result<Vec<String>> {
        let mut patterns = Vec::new();
        for bot in self.list_bots()? {
            let overridden = bot_overrides
                .iter()
                .find(|o| o.bot_id == bot.id)
                .map(|o| o.policy);
            let blocked = if let Some(policy) = overridden {
                policy == Policy::Blocked
            } else {
                match bot.status {
                    BotStatus::Blocked => true,
                    BotStatus::Allowed => false,
                    BotStatus::Default => {
                        (bot.is_ai && ai == Policy::Blocked)
                            || (bot.is_search_engine && search == Policy::Blocked)
                            || (bot.is_scanner && scanner == Policy::Blocked)
                    }
                }
            };
            if blocked {
                patterns.push(bot.user_agent_pattern);
            }
        }
        Ok(patterns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bot(slug: &str) -> NewBot {
        NewBot {
            slug: slug.to_string(),
            name: slug.to_string(),
            is_ai: false,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: format!("{slug}-ua"),
            source_id: "test-source".to_string(),
        }
    }

    /// Opens an in-memory database with the `test-source` source already
    /// registered, since `bots.source_id` has a foreign key onto `sources`.
    fn test_db() -> Db {
        let db = Db::open_in_memory().unwrap();
        db.upsert_source(&Source {
            id: "test-source".to_string(),
            name: "Test Source".to_string(),
            url: "https://example.invalid".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db
    }

    #[test]
    fn open_in_memory_creates_schema_with_defaults() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            db.get_category_default(Category::Ai).unwrap(),
            Policy::Blocked
        );
        assert_eq!(
            db.get_category_default(Category::Search).unwrap(),
            Policy::Allowed
        );
        assert_eq!(
            db.get_category_default(Category::Scanner).unwrap(),
            Policy::Blocked
        );
        assert!(db.list_bots().unwrap().is_empty());
        assert!(db.list_sites().unwrap().is_empty());
    }

    #[test]
    fn upsert_bot_inserts_then_updates_metadata() {
        let db = test_db();
        db.upsert_bot(&sample_bot("gptbot")).unwrap();

        let mut updated = sample_bot("gptbot");
        updated.name = "GPTBot".to_string();
        updated.is_ai = true;
        db.upsert_bot(&updated).unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots.len(), 1);
        assert_eq!(bots[0].name, "GPTBot");
        assert!(bots[0].is_ai);
    }

    #[test]
    fn refreshing_a_bot_preserves_manual_status_override() {
        let db = test_db();
        db.upsert_bot(&sample_bot("gptbot")).unwrap();
        db.set_bot_status("gptbot", BotStatus::Allowed).unwrap();

        // Simulate a bot-list refresh re-inserting the same bot.
        db.upsert_bot(&sample_bot("gptbot")).unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots[0].status, BotStatus::Allowed);
    }

    /// Registers a second source ("test-source-2") in `db`, for tests that
    /// exercise merging contributions from more than one source.
    fn add_second_source(db: &Db) {
        db.upsert_source(&Source {
            id: "test-source-2".to_string(),
            name: "Test Source 2".to_string(),
            url: "https://example.invalid/2".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
    }

    #[test]
    fn two_sources_contributing_the_same_slug_merge_their_category_flags() {
        let db = test_db();
        add_second_source(&db);

        let mut ai_entry = sample_bot("gptbot");
        ai_entry.is_ai = true;
        db.upsert_bot(&ai_entry).unwrap();

        let mut scanner_entry = sample_bot("gptbot");
        scanner_entry.is_scanner = true;
        scanner_entry.source_id = "test-source-2".to_string();
        db.upsert_bot(&scanner_entry).unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots.len(), 1);
        assert!(bots[0].is_ai);
        assert!(bots[0].is_scanner);
        assert!(!bots[0].is_search_engine);
    }

    #[test]
    fn merging_two_sources_is_order_independent() {
        // Same two contributions as above, but upserted in the opposite
        // order — the whole point of merging instead of last-write-wins
        // is that fetch order must not change the final result.
        let db = test_db();
        add_second_source(&db);

        let mut scanner_entry = sample_bot("gptbot");
        scanner_entry.is_scanner = true;
        scanner_entry.source_id = "test-source-2".to_string();
        db.upsert_bot(&scanner_entry).unwrap();

        let mut ai_entry = sample_bot("gptbot");
        ai_entry.is_ai = true;
        db.upsert_bot(&ai_entry).unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots.len(), 1);
        assert!(bots[0].is_ai);
        assert!(bots[0].is_scanner);
    }

    #[test]
    fn merge_joins_distinct_patterns_but_dedupes_identical_ones() {
        let db = test_db();
        add_second_source(&db);

        let mut a = sample_bot("gptbot");
        a.user_agent_pattern = "GPTBot".to_string();
        db.upsert_bot(&a).unwrap();

        let mut b = sample_bot("gptbot");
        b.user_agent_pattern = "GPTBot-2".to_string();
        b.source_id = "test-source-2".to_string();
        db.upsert_bot(&b).unwrap();

        assert_eq!(
            db.list_bots().unwrap()[0].user_agent_pattern,
            "GPTBot|GPTBot-2"
        );

        // Re-upserting source 2 with the exact same pattern must not
        // duplicate it in the merged string.
        db.upsert_bot(&b).unwrap();
        assert_eq!(
            db.list_bots().unwrap()[0].user_agent_pattern,
            "GPTBot|GPTBot-2"
        );
    }

    #[test]
    fn dropping_a_bot_from_one_source_falls_back_to_the_others_contribution() {
        let db = test_db();
        add_second_source(&db);

        let mut ai_entry = sample_bot("gptbot");
        ai_entry.is_ai = true;
        db.upsert_bot(&ai_entry).unwrap();

        let mut scanner_entry = sample_bot("gptbot");
        scanner_entry.is_scanner = true;
        scanner_entry.source_id = "test-source-2".to_string();
        db.upsert_bot(&scanner_entry).unwrap();

        // test-source no longer reports this bot at all — simulates its
        // next fetch just not including it anymore.
        let dropped = db.clear_source_bot_entries("test-source").unwrap();
        assert_eq!(dropped, vec!["gptbot".to_string()]);
        db.recompute_merged_bot("gptbot").unwrap();

        let bots = db.list_bots().unwrap();
        assert_eq!(bots.len(), 1);
        assert!(!bots[0].is_ai);
        assert!(bots[0].is_scanner);
    }

    #[test]
    fn a_bot_with_no_remaining_contributions_is_left_as_is_not_deleted() {
        let db = test_db();
        let mut ai_entry = sample_bot("gptbot");
        ai_entry.is_ai = true;
        db.upsert_bot(&ai_entry).unwrap();
        db.set_bot_status("gptbot", BotStatus::Allowed).unwrap();

        db.clear_source_bot_entries("test-source").unwrap();
        db.recompute_merged_bot("gptbot").unwrap();

        // The row, its flags and its manual override all survive even
        // though no source contributes it anymore — see
        // recompute_merged_bot's doc comment for why that's deliberate.
        let bots = db.list_bots().unwrap();
        assert_eq!(bots.len(), 1);
        assert!(bots[0].is_ai);
        assert_eq!(bots[0].status, BotStatus::Allowed);
    }

    #[test]
    fn count_bot_source_entries_reflects_distinct_contributed_slugs() {
        let db = test_db();
        db.upsert_bot(&sample_bot("gptbot")).unwrap();
        db.upsert_bot(&sample_bot("claudebot")).unwrap();
        // Re-upserting the same slug from the same source must not
        // double-count.
        db.upsert_bot(&sample_bot("gptbot")).unwrap();

        assert_eq!(db.count_bot_source_entries("test-source").unwrap(), 2);
    }

    #[test]
    fn set_bot_status_errors_for_unknown_slug() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.set_bot_status("nope", BotStatus::Blocked).is_err());
    }

    #[test]
    fn blocked_patterns_follow_category_defaults_by_default() {
        let db = test_db();
        let mut ai_bot = sample_bot("ai-bot");
        ai_bot.is_ai = true;
        let mut search_bot = sample_bot("search-bot");
        search_bot.is_search_engine = true;
        db.upsert_bot(&ai_bot).unwrap();
        db.upsert_bot(&search_bot).unwrap();

        // Defaults: AI blocked, search allowed.
        let blocked = db.blocked_user_agent_patterns().unwrap();
        assert_eq!(blocked, vec!["ai-bot-ua".to_string()]);
    }

    #[test]
    fn explicit_override_wins_over_category_default() {
        let db = test_db();
        let mut ai_bot = sample_bot("ai-bot");
        ai_bot.is_ai = true;
        db.upsert_bot(&ai_bot).unwrap();
        db.set_bot_status("ai-bot", BotStatus::Allowed).unwrap();

        assert!(db.blocked_user_agent_patterns().unwrap().is_empty());

        let mut search_bot = sample_bot("search-bot");
        search_bot.is_search_engine = true;
        db.upsert_bot(&search_bot).unwrap();
        db.set_bot_status("search-bot", BotStatus::Blocked).unwrap();

        assert_eq!(
            db.blocked_user_agent_patterns().unwrap(),
            vec!["search-bot-ua".to_string()]
        );
    }

    #[test]
    fn set_category_default_changes_future_blocking_decisions() {
        let db = test_db();
        let mut search_bot = sample_bot("search-bot");
        search_bot.is_search_engine = true;
        db.upsert_bot(&search_bot).unwrap();

        assert!(db.blocked_user_agent_patterns().unwrap().is_empty());

        db.set_category_default(Category::Search, Policy::Blocked)
            .unwrap();
        assert_eq!(
            db.blocked_user_agent_patterns().unwrap(),
            vec!["search-bot-ua".to_string()]
        );
    }

    #[test]
    fn upsert_site_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example.com")
            .unwrap();

        let sites = db.list_sites().unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].server_name, "example.com");
    }

    fn site_id(db: &Db, server_name: &str) -> i64 {
        db.upsert_site(server_name, "/etc/nginx/sites-enabled/x")
            .unwrap();
        db.list_sites()
            .unwrap()
            .into_iter()
            .find(|s| s.server_name == server_name)
            .unwrap()
            .id
    }

    #[test]
    fn site_category_override_defaults_to_none_and_round_trips() {
        let db = Db::open_in_memory().unwrap();
        let site = site_id(&db, "example.com");

        assert_eq!(
            db.get_site_category_override(site, Category::Ai).unwrap(),
            None
        );

        db.set_site_category_override(site, Category::Ai, Some(Policy::Allowed))
            .unwrap();
        assert_eq!(
            db.get_site_category_override(site, Category::Ai).unwrap(),
            Some(Policy::Allowed)
        );

        db.set_site_category_override(site, Category::Ai, None)
            .unwrap();
        assert_eq!(
            db.get_site_category_override(site, Category::Ai).unwrap(),
            None
        );
    }

    #[test]
    fn site_bot_override_defaults_to_empty_and_round_trips() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        db.upsert_bot(&sample_bot("gptbot")).unwrap();
        let bot_id = db.list_bots().unwrap()[0].id;

        assert!(db.site_bot_overrides(site).unwrap().is_empty());

        db.set_site_bot_override(site, bot_id, Some(Policy::Blocked))
            .unwrap();
        let overrides = db.site_bot_overrides(site).unwrap();
        assert_eq!(
            overrides,
            vec![SiteBotOverride {
                bot_id,
                policy: Policy::Blocked
            }]
        );

        db.set_site_bot_override(site, bot_id, None).unwrap();
        assert!(db.site_bot_overrides(site).unwrap().is_empty());
    }

    #[test]
    fn blocked_patterns_for_site_matches_global_when_no_overrides_are_set() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        let mut ai_bot = sample_bot("ai-bot");
        ai_bot.is_ai = true;
        db.upsert_bot(&ai_bot).unwrap();

        assert_eq!(
            db.blocked_user_agent_patterns_for_site(site).unwrap(),
            db.blocked_user_agent_patterns().unwrap()
        );
    }

    #[test]
    fn site_bot_override_wins_over_everything_else() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        let mut ai_bot = sample_bot("ai-bot");
        ai_bot.is_ai = true;
        db.upsert_bot(&ai_bot).unwrap();
        let bot_id = db.list_bots().unwrap()[0].id;

        // Global default blocks AI bots; a global per-bot override allows
        // it; the site override should still win over both.
        db.set_bot_status("ai-bot", BotStatus::Allowed).unwrap();
        db.set_site_bot_override(site, bot_id, Some(Policy::Blocked))
            .unwrap();

        assert_eq!(
            db.blocked_user_agent_patterns_for_site(site).unwrap(),
            vec!["ai-bot-ua".to_string()]
        );
    }

    #[test]
    fn global_bot_override_wins_over_a_site_category_override() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        let mut ai_bot = sample_bot("ai-bot");
        ai_bot.is_ai = true;
        db.upsert_bot(&ai_bot).unwrap();

        // The bot is globally pinned Allowed; the site blocks the whole AI
        // category but sets no override for this specific bot. The global
        // pin should still win: a site category override can't reach
        // through an explicit global per-bot pin (see
        // Db::compute_blocked_patterns's doc comment).
        db.set_bot_status("ai-bot", BotStatus::Allowed).unwrap();
        db.set_site_category_override(site, Category::Ai, Some(Policy::Blocked))
            .unwrap();

        assert!(db
            .blocked_user_agent_patterns_for_site(site)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn site_category_override_wins_over_global_default_when_bot_has_no_pin() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        let mut search_bot = sample_bot("search-bot");
        search_bot.is_search_engine = true;
        db.upsert_bot(&search_bot).unwrap();

        // Global default allows search engines; site overrides to Blocked.
        db.set_site_category_override(site, Category::Search, Some(Policy::Blocked))
            .unwrap();

        assert_eq!(
            db.blocked_user_agent_patterns_for_site(site).unwrap(),
            vec!["search-bot-ua".to_string()]
        );
    }

    #[test]
    fn multi_category_bot_is_blocked_if_any_matching_category_is_blocked() {
        let db = test_db();
        let site = site_id(&db, "example.com");
        let mut bot = sample_bot("both-bot");
        bot.is_ai = true;
        bot.is_search_engine = true;
        db.upsert_bot(&bot).unwrap();

        // Search is allowed globally, AI is blocked globally: the bot
        // matches both, so it should be blocked.
        assert_eq!(
            db.blocked_user_agent_patterns_for_site(site).unwrap(),
            vec!["both-bot-ua".to_string()]
        );

        // Allowing AI at the site level isn't enough on its own: the bot is
        // also a search engine, and search defaults to Allowed globally
        // anyway, so it should now be fully unblocked (confirms the
        // multi-category check is an OR, not just "any override clears it").
        db.set_site_category_override(site, Category::Ai, Some(Policy::Allowed))
            .unwrap();
        assert!(db
            .blocked_user_agent_patterns_for_site(site)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn upsert_source_inserts_then_updates() {
        let db = Db::open_in_memory().unwrap();
        let source = Source {
            id: "well-known-bots".to_string(),
            name: "ArcJet Well-Known Bots".to_string(),
            url: "https://example.invalid/bots.json".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        };
        db.upsert_source(&source).unwrap();
        db.touch_source("well-known-bots", 42).unwrap();

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].bot_count, 42);
        assert!(sources[0].last_fetched_at.is_some());
    }

    #[test]
    fn register_source_does_not_clobber_an_already_fetched_source() {
        let db = Db::open_in_memory().unwrap();
        let source = Source {
            id: "well-known-bots".to_string(),
            name: "ArcJet Well-Known Bots".to_string(),
            url: "https://example.invalid/bots.json".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        };
        db.upsert_source(&source).unwrap();
        db.touch_source("well-known-bots", 42).unwrap();

        // Re-registering the same id (e.g. on every TUI startup) must not
        // reset a source that's already been fetched back to "never
        // updated / 0 bots".
        db.register_source(&source).unwrap();

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].bot_count, 42);
        assert!(sources[0].last_fetched_at.is_some());
    }

    #[test]
    fn register_source_makes_an_unfetched_source_appear() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.list_sources().unwrap().is_empty());

        db.register_source(&Source {
            id: "well-known-bots".to_string(),
            name: "ArcJet Well-Known Bots".to_string(),
            url: "https://example.invalid/bots.json".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();

        let sources = db.list_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].last_fetched_at.is_none());
        assert_eq!(sources[0].bot_count, 0);
    }

    #[test]
    fn firewall_action_parses_canonical_and_upstream_spellings() {
        assert_eq!(
            FirewallAction::parse("allow").unwrap(),
            FirewallAction::Allow
        );
        assert_eq!(
            FirewallAction::parse("ACCEPT").unwrap(),
            FirewallAction::Allow
        );
        assert_eq!(
            FirewallAction::parse("block").unwrap(),
            FirewallAction::Block
        );
        assert_eq!(
            FirewallAction::parse("DROP").unwrap(),
            FirewallAction::Block
        );
        assert_eq!(
            FirewallAction::parse("REJECT").unwrap(),
            FirewallAction::Reject
        );
        assert!(FirewallAction::parse("nope").is_err());
    }

    #[test]
    fn add_firewall_rule_rejects_invalid_addresses() {
        let db = Db::open_in_memory().unwrap();
        let result = db.add_firewall_rule(&NewFirewallRule {
            address: "not-an-ip".to_string(),
            port: None,
            action: FirewallAction::Block,
        });
        assert!(result.is_err());
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// A prefix length past the address family's actual bit width (32 for
    /// IPv4, 128 for IPv6) must be rejected here rather than slipping
    /// through to render an `iptables`/`nft` rule that fails at apply time —
    /// see `is_valid_address`'s doc comment.
    #[test]
    fn add_firewall_rule_rejects_out_of_range_cidr_prefixes() {
        let db = Db::open_in_memory().unwrap();
        for address in ["1.2.3.4/40", "1.2.3.4/999", "2001:db8::/129", "1.2.3.4/+5"] {
            let result = db.add_firewall_rule(&NewFirewallRule {
                address: address.to_string(),
                port: None,
                action: FirewallAction::Block,
            });
            assert!(result.is_err(), "{address} should have been rejected");
        }
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn add_firewall_rule_accepts_plain_ips_and_cidr_ranges() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&NewFirewallRule {
            address: "1.2.3.4".to_string(),
            port: Some(80),
            action: FirewallAction::Block,
        })
        .unwrap();
        db.add_firewall_rule(&NewFirewallRule {
            address: "2001:db8::/32".to_string(),
            port: None,
            action: FirewallAction::Allow,
        })
        .unwrap();

        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].address, "1.2.3.4");
        assert_eq!(rules[0].port, Some(80));
        assert!(rules[0].enabled);
        assert_eq!(rules[1].action, FirewallAction::Allow);
    }

    #[test]
    fn add_firewall_rule_never_expires() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&NewFirewallRule {
            address: "1.2.3.4".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();
        assert_eq!(db.list_firewall_rules().unwrap()[0].expires_at, None);
    }

    #[test]
    fn add_firewall_rule_with_ttl_sets_a_future_expiry() {
        let db = Db::open_in_memory().unwrap();
        let before = now();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "1.2.3.4".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            60,
        )
        .unwrap();
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        let expires_at = rules[0].expires_at.expect("should have an expiry");
        assert!(expires_at >= before + 60);
    }

    /// The core property this feature exists for: a rule added with a
    /// negative (or otherwise already-past) TTL is functionally identical
    /// to a rule that expired naturally — real time doesn't need to pass,
    /// and no time-mocking is needed, to exercise pruning deterministically.
    #[test]
    fn list_firewall_rules_prunes_an_already_expired_rule() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "1.2.3.4".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            -1,
        )
        .unwrap();
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn list_firewall_rules_keeps_a_rule_that_has_not_expired_yet() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "1.2.3.4".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            60,
        )
        .unwrap();
        assert_eq!(db.list_firewall_rules().unwrap().len(), 1);
    }

    #[test]
    fn prune_expired_firewall_rules_deletes_only_lapsed_rows_and_reports_the_count() {
        let db = Db::open_in_memory().unwrap();
        db.add_firewall_rule(&NewFirewallRule {
            address: "1.2.3.4".to_string(),
            port: None,
            action: FirewallAction::Block,
        })
        .unwrap();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "5.6.7.8".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            -1,
        )
        .unwrap();
        db.add_firewall_rule_with_ttl(
            &NewFirewallRule {
                address: "9.10.11.12".to_string(),
                port: None,
                action: FirewallAction::Block,
            },
            60,
        )
        .unwrap();

        let pruned = db.prune_expired_firewall_rules().unwrap();
        assert_eq!(pruned, 1);

        let mut remaining: Vec<String> = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .map(|r| r.address)
            .collect();
        remaining.sort();
        assert_eq!(
            remaining,
            vec!["1.2.3.4".to_string(), "9.10.11.12".to_string()]
        );
    }

    #[test]
    fn firewall_rule_enabled_toggle_and_removal() {
        let db = Db::open_in_memory().unwrap();
        let id = db
            .add_firewall_rule(&NewFirewallRule {
                address: "1.2.3.4".to_string(),
                port: None,
                action: FirewallAction::Block,
            })
            .unwrap();

        db.set_firewall_rule_enabled(id, false).unwrap();
        assert!(!db.list_firewall_rules().unwrap()[0].enabled);

        db.remove_firewall_rule(id).unwrap();
        assert!(db.list_firewall_rules().unwrap().is_empty());

        assert!(db.remove_firewall_rule(id).is_err());
        assert!(db.set_firewall_rule_enabled(id, true).is_err());
    }

    fn sample_ip_range_source(id: &str, category: Category) -> IpRangeSource {
        IpRangeSource {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.invalid/{id}.json"),
            category,
            last_fetched_at: None,
            range_count: 0,
        }
    }

    #[test]
    fn register_ip_range_source_is_idempotent_and_preserves_a_later_fetch() {
        let db = Db::open_in_memory().unwrap();
        let source = sample_ip_range_source("googlebot", Category::Search);
        db.register_ip_range_source(&source).unwrap();
        db.replace_ip_ranges("googlebot", &["1.2.3.0/24".to_string()])
            .unwrap();

        // Re-registering (e.g. on every TUI/CLI startup) must not reset a
        // source that's already been fetched.
        db.register_ip_range_source(&source).unwrap();

        let sources = db.list_ip_range_sources().unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].range_count, 1);
        assert!(sources[0].last_fetched_at.is_some());
        assert_eq!(sources[0].category, Category::Search);
    }

    #[test]
    fn replace_ip_ranges_drops_cidrs_no_longer_present() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&sample_ip_range_source("gptbot", Category::Ai))
            .unwrap();

        db.replace_ip_ranges(
            "gptbot",
            &["1.2.3.0/24".to_string(), "4.5.6.0/24".to_string()],
        )
        .unwrap();
        assert_eq!(db.ip_ranges_for_source("gptbot").unwrap().len(), 2);

        db.replace_ip_ranges("gptbot", &["4.5.6.0/24".to_string()])
            .unwrap();
        assert_eq!(
            db.ip_ranges_for_source("gptbot").unwrap(),
            vec!["4.5.6.0/24".to_string()]
        );
    }

    #[test]
    fn replace_ip_ranges_reports_the_distinct_count_not_the_raw_input_length() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&sample_ip_range_source("gptbot", Category::Ai))
            .unwrap();

        // A source's fetched list has an internal duplicate — the reported
        // and stored count must reflect the distinct CIDR, not the raw
        // input length (same drift bug already fixed for bot_count).
        let count = db
            .replace_ip_ranges(
                "gptbot",
                &[
                    "1.2.3.0/24".to_string(),
                    "1.2.3.0/24".to_string(),
                    "4.5.6.0/24".to_string(),
                ],
            )
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(db.list_ip_range_sources().unwrap()[0].range_count, 2);
    }

    #[test]
    fn blocked_ip_ranges_only_includes_sources_whose_category_defaults_to_blocked() {
        let db = Db::open_in_memory().unwrap();
        // Search defaults to Allowed, AI defaults to Blocked (see
        // open_in_memory_creates_schema_with_defaults).
        db.register_ip_range_source(&sample_ip_range_source("googlebot", Category::Search))
            .unwrap();
        db.replace_ip_ranges("googlebot", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.register_ip_range_source(&sample_ip_range_source("gptbot", Category::Ai))
            .unwrap();
        db.replace_ip_ranges("gptbot", &["4.5.6.0/24".to_string()])
            .unwrap();

        assert_eq!(
            db.blocked_ip_ranges().unwrap(),
            vec!["4.5.6.0/24".to_string()]
        );

        // Flipping Search to Blocked makes googlebot's ranges contribute too.
        db.set_category_default(Category::Search, Policy::Blocked)
            .unwrap();
        let mut blocked = db.blocked_ip_ranges().unwrap();
        blocked.sort();
        assert_eq!(
            blocked,
            vec!["1.2.3.0/24".to_string(), "4.5.6.0/24".to_string()]
        );
    }

    #[test]
    fn replace_country_ranges_is_idempotent_and_reports_status() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.list_fetched_countries().unwrap().is_empty());

        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string(), "5.6.7.0/24".to_string()])
            .unwrap();
        let fetched = db.list_fetched_countries().unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].0, "nl");
        assert_eq!(fetched[0].1, 2);

        // A later fetch with fewer CIDRs must drop the stale one, not just
        // add to it.
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        let fetched = db.list_fetched_countries().unwrap();
        assert_eq!(fetched[0].1, 1);
    }

    #[test]
    fn geo_mode_defaults_to_blocklist_and_round_trips() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Blocklist);

        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Allowlist);

        db.set_geo_mode(GeoMode::Blocklist).unwrap();
        assert_eq!(db.get_geo_mode().unwrap(), GeoMode::Blocklist);
    }

    #[test]
    fn cron_last_run_is_none_for_a_job_that_has_never_run() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_cron_last_run("block_scanners").unwrap(), None);
        assert_eq!(db.get_cron_last_summary("block_scanners").unwrap(), None);
    }

    #[test]
    fn set_cron_last_run_round_trips_timestamp_and_summary() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run("block_scanners", 1_700_000_000, "blocked 2 IP(s)")
            .unwrap();

        assert_eq!(
            db.get_cron_last_run("block_scanners").unwrap(),
            Some(1_700_000_000)
        );
        assert_eq!(
            db.get_cron_last_summary("block_scanners").unwrap(),
            Some("blocked 2 IP(s)".to_string())
        );
    }

    #[test]
    fn cron_last_run_updating_overwrites_rather_than_duplicates() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run("block_scanners", 1_700_000_000, "first run")
            .unwrap();
        db.set_cron_last_run("block_scanners", 1_800_000_000, "second run")
            .unwrap();

        assert_eq!(
            db.get_cron_last_run("block_scanners").unwrap(),
            Some(1_800_000_000)
        );
        assert_eq!(
            db.get_cron_last_summary("block_scanners").unwrap(),
            Some("second run".to_string())
        );
    }

    #[test]
    fn cron_last_run_is_tracked_independently_per_job() {
        let db = Db::open_in_memory().unwrap();
        db.set_cron_last_run("block_scanners", 1_700_000_000, "ssh")
            .unwrap();

        assert_eq!(
            db.get_cron_last_run("block_scanners").unwrap(),
            Some(1_700_000_000)
        );
        assert_eq!(db.get_cron_last_run("block_web_scanners").unwrap(), None);
    }

    #[test]
    fn blocklist_mode_only_blocks_explicitly_selected_countries() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();

        assert!(db.geo_firewall_rules().unwrap().is_empty());

        db.set_country_selected("us", true).unwrap();
        assert_eq!(
            db.geo_firewall_rules().unwrap(),
            vec![("4.5.6.0/24".to_string(), FirewallAction::Block)]
        );
        assert_eq!(
            db.list_selected_countries().unwrap(),
            vec!["us".to_string()]
        );

        db.set_country_selected("us", false).unwrap();
        assert!(db.geo_firewall_rules().unwrap().is_empty());
    }

    #[test]
    fn allowlist_mode_allows_selected_countries_then_blocks_everything_else() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();
        db.set_country_selected("nl", true).unwrap();

        // Order matters: the allowed country's rule must come before the
        // trailing catch-all, never after.
        assert_eq!(
            db.geo_firewall_rules().unwrap(),
            vec![
                ("1.2.3.0/24".to_string(), FirewallAction::Allow),
                ("0.0.0.0/0".to_string(), FirewallAction::Block),
                ("::/0".to_string(), FirewallAction::Block),
            ]
        );
    }

    #[test]
    fn allowlist_mode_with_no_selected_countries_still_blocks_everything() {
        let db = Db::open_in_memory().unwrap();
        db.set_geo_mode(GeoMode::Allowlist).unwrap();

        assert_eq!(
            db.geo_firewall_rules().unwrap(),
            vec![
                ("0.0.0.0/0".to_string(), FirewallAction::Block),
                ("::/0".to_string(), FirewallAction::Block),
            ]
        );
    }

    #[test]
    fn selecting_a_country_before_its_ranges_are_fetched_is_a_harmless_noop() {
        let db = Db::open_in_memory().unwrap();
        db.set_country_selected("us", true).unwrap();
        assert!(db.geo_firewall_rules().unwrap().is_empty());

        // Fetching afterwards makes the block take effect retroactively.
        db.replace_country_ranges("us", &["4.5.6.0/24".to_string()])
            .unwrap();
        assert_eq!(
            db.geo_firewall_rules().unwrap(),
            vec![("4.5.6.0/24".to_string(), FirewallAction::Block)]
        );
    }

    #[test]
    fn derived_firewall_entries_combines_ip_ranges_and_geo_rules() {
        let db = Db::open_in_memory().unwrap();
        db.register_ip_range_source(&sample_ip_range_source("gptbot", Category::Ai))
            .unwrap();
        db.replace_ip_ranges("gptbot", &["4.5.6.0/24".to_string()])
            .unwrap();
        db.replace_country_ranges("us", &["7.8.9.0/24".to_string()])
            .unwrap();
        db.set_country_selected("us", true).unwrap();

        let mut derived = db.derived_firewall_entries().unwrap();
        derived.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            derived,
            vec![
                ("4.5.6.0/24".to_string(), FirewallAction::Block),
                ("7.8.9.0/24".to_string(), FirewallAction::Block),
            ]
        );
    }
}
