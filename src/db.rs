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
use rusqlite::{params, Connection};
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

/// A single known bot, normalized from one of the bot-list sources.
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

/// Fields needed to insert or refresh a bot from a source. The user's manual
/// `status` override is intentionally not part of this struct so that
/// refreshing a bot list never clobbers it; see [`Db::upsert_bot`].
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
/// address or CIDR range), optionally restricted to `port`.
#[derive(Debug, Clone, PartialEq)]
pub struct FirewallRule {
    pub id: i64,
    pub address: String,
    pub port: Option<u16>,
    pub action: FirewallAction,
    pub enabled: bool,
}

/// Fields needed to add a new firewall rule.
#[derive(Debug, Clone, PartialEq)]
pub struct NewFirewallRule {
    pub address: String,
    pub port: Option<u16>,
    pub action: FirewallAction,
}

/// Returns whether `address` is a plain IP address or CIDR range.
fn is_valid_address(address: &str) -> bool {
    let address = address.trim();
    if let Some((prefix, suffix)) = address.split_once('/') {
        return prefix.parse::<std::net::IpAddr>().is_ok()
            && !suffix.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit());
    }
    address.parse::<std::net::IpAddr>().is_ok()
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
                created_at INTEGER NOT NULL
            );
            ",
        )?;

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

    /// Inserts a bot, or refreshes its metadata if a bot with the same `slug`
    /// already exists. The `status` column is left untouched on update so a
    /// bot-list refresh never clobbers a manual override.
    pub fn upsert_bot(&self, bot: &NewBot) -> Result<()> {
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
                bot.slug,
                bot.name,
                bot.is_ai,
                bot.is_search_engine,
                bot.is_scanner,
                bot.user_agent_pattern,
                bot.source_id,
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

    // ---- firewall rules ----

    /// Adds a new firewall rule, enabled by default. Returns its id.
    pub fn add_firewall_rule(&self, rule: &NewFirewallRule) -> Result<i64> {
        if !is_valid_address(&rule.address) {
            anyhow::bail!("invalid firewall rule address: {}", rule.address);
        }
        self.conn.execute(
            "INSERT INTO firewall_rules (address, port, action, enabled, created_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            params![rule.address, rule.port, rule.action.as_str(), now()],
        )?;
        Ok(self.conn.last_insert_rowid())
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
    /// themselves.
    pub fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, address, port, action, enabled FROM firewall_rules ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            let action: String = row.get(3)?;
            Ok(FirewallRule {
                id: row.get(0)?,
                address: row.get(1)?,
                port: row.get(2)?,
                action: FirewallAction::parse(&action).unwrap_or(FirewallAction::Block),
                enabled: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list firewall rules")
    }

    /// Computes the user-agent regex alternatives for every bot that should
    /// currently be blocked, taking category defaults and per-bot overrides
    /// into account. Returns an empty vec if nothing should be blocked.
    pub fn blocked_user_agent_patterns(&self) -> Result<Vec<String>> {
        let ai_default = self.get_category_default(Category::Ai)?;
        let search_default = self.get_category_default(Category::Search)?;
        let scanner_default = self.get_category_default(Category::Scanner)?;

        let mut patterns = Vec::new();
        for bot in self.list_bots()? {
            let blocked = match bot.status {
                BotStatus::Blocked => true,
                BotStatus::Allowed => false,
                BotStatus::Default => {
                    (bot.is_ai && ai_default == Policy::Blocked)
                        || (bot.is_search_engine && search_default == Policy::Blocked)
                        || (bot.is_scanner && scanner_default == Policy::Blocked)
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
}
