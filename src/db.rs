//! Database module for Stop Bots.
//!
//! This module provides SQLite database functionality for storing and managing
//! bot definitions, configurations, and blocking rules.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

// ============================================================================
// Database Path Configuration
// ============================================================================

/// Default database file name.
const DEFAULT_DB_NAME: &str = "stop-bots.db";

/// Returns the default database path.
///
/// On Unix-like systems: ~/.local/share/stop-bots/stop-bots.db
/// On Windows: %APPDATA%\stop-bots\stop-bots.db
/// Can be overridden with STOP_BOTS_DB_PATH environment variable (for testing)
pub fn default_db_path() -> PathBuf {
    // Check for environment variable override (for testing)
    if let Ok(db_path) = std::env::var("STOP_BOTS_DB_PATH") {
        return PathBuf::from(db_path);
    }

    if cfg!(windows) {
        // Windows: %APPDATA%\stop-bots\stop-bots.db
        if let Ok(app_data) = std::env::var("APPDATA") {
            return PathBuf::from(app_data)
                .join("stop-bots")
                .join(DEFAULT_DB_NAME);
        }
    }

    // Unix-like: ~/.local/share/stop-bots/stop-bots.db
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("stop-bots")
            .join(DEFAULT_DB_NAME);
    }

    // Fallback to current directory
    PathBuf::from(DEFAULT_DB_NAME)
}

// ============================================================================
// Bot Status
// ============================================================================

/// Whether a bot is allowed or blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum BotStatus {
    /// Bot is allowed to access the site
    Allowed,
    /// Bot is blocked from accessing the site
    #[default]
    Blocked,
}

impl fmt::Display for BotStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BotStatus::Allowed => write!(f, "Allowed"),
            BotStatus::Blocked => write!(f, "Blocked"),
        }
    }
}

impl BotStatus {
    /// Returns true if the bot is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, BotStatus::Allowed)
    }

    /// Returns true if the bot is blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, BotStatus::Blocked)
    }

    /// Toggles the status.
    pub fn toggle(&self) -> Self {
        match self {
            BotStatus::Allowed => BotStatus::Blocked,
            BotStatus::Blocked => BotStatus::Allowed,
        }
    }
}

impl From<bool> for BotStatus {
    fn from(allowed: bool) -> Self {
        if allowed {
            BotStatus::Allowed
        } else {
            BotStatus::Blocked
        }
    }
}

impl From<BotStatus> for bool {
    fn from(status: BotStatus) -> bool {
        status.is_allowed()
    }
}

// ============================================================================
// Bot Category
// ============================================================================

/// Category of a bot for organization and filtering purposes.
/// A bot can belong to multiple categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BotCategory {
    /// Scanners that probe for vulnerabilities
    Scanner,
    /// Search engine crawlers (Googlebot, Bingbot, etc.)
    SearchEngine,
    /// AI bots and scrapers (GPTBot, CCBot, etc.)
    AiScraper,
    /// Content scrapers and data harvesters
    Scraper,
    /// Security scanners and vulnerability testers
    SecurityScanner,
    /// Ad bots and click fraud
    AdBot,
    /// Social media bots
    SocialBot,
    /// Monitoring and uptime bots
    MonitoringBot,
    /// Unknown or uncategorized bots
    Unknown,
}

impl fmt::Display for BotCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BotCategory::Scanner => write!(f, "Scanner"),
            BotCategory::SearchEngine => write!(f, "Search Engine"),
            BotCategory::AiScraper => write!(f, "AI Scraper"),
            BotCategory::Scraper => write!(f, "Scraper"),
            BotCategory::SecurityScanner => write!(f, "Security Scanner"),
            BotCategory::AdBot => write!(f, "Ad Bot"),
            BotCategory::SocialBot => write!(f, "Social Bot"),
            BotCategory::MonitoringBot => write!(f, "Monitoring Bot"),
            BotCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

impl BotCategory {
    /// Returns all bot categories.
    pub fn all() -> &'static [BotCategory] {
        &[
            BotCategory::Scanner,
            BotCategory::SearchEngine,
            BotCategory::AiScraper,
            BotCategory::Scraper,
            BotCategory::SecurityScanner,
            BotCategory::AdBot,
            BotCategory::SocialBot,
            BotCategory::MonitoringBot,
            BotCategory::Unknown,
        ]
    }

    /// Converts a string to a BotCategory (case-insensitive).
    pub fn from_str_case_insensitive(s: &str) -> Option<BotCategory> {
        match s.to_lowercase().as_str() {
            "scanner" => Some(BotCategory::Scanner),
            "searchengine" | "search engine" | "search_engine" => Some(BotCategory::SearchEngine),
            "aiscraper" | "ai scraper" | "ai_scraper" => Some(BotCategory::AiScraper),
            "scraper" => Some(BotCategory::Scraper),
            "securityscanner" | "security scanner" | "security_scanner" => {
                Some(BotCategory::SecurityScanner)
            }
            "adbot" | "ad bot" | "ad_bot" => Some(BotCategory::AdBot),
            "socialbot" | "social bot" | "social_bot" => Some(BotCategory::SocialBot),
            "monitoringbot" | "monitoring bot" | "monitoring_bot" => {
                Some(BotCategory::MonitoringBot)
            }
            _ => None,
        }
    }

    /// Returns the category as a string suitable for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            BotCategory::Scanner => "scanner",
            BotCategory::SearchEngine => "search_engine",
            BotCategory::AiScraper => "ai_scraper",
            BotCategory::Scraper => "scraper",
            BotCategory::SecurityScanner => "security_scanner",
            BotCategory::AdBot => "ad_bot",
            BotCategory::SocialBot => "social_bot",
            BotCategory::MonitoringBot => "monitoring_bot",
            BotCategory::Unknown => "unknown",
        }
    }

    /// Parses a category from a database string.
    pub fn from_db_str(s: &str) -> Option<BotCategory> {
        match s {
            "scanner" => Some(BotCategory::Scanner),
            "search_engine" => Some(BotCategory::SearchEngine),
            "ai_scraper" => Some(BotCategory::AiScraper),
            "scraper" => Some(BotCategory::Scraper),
            "security_scanner" => Some(BotCategory::SecurityScanner),
            "ad_bot" => Some(BotCategory::AdBot),
            "social_bot" => Some(BotCategory::SocialBot),
            "monitoring_bot" => Some(BotCategory::MonitoringBot),
            "unknown" => Some(BotCategory::Unknown),
            _ => None,
        }
    }
}

// ============================================================================
// Signal Type
// ============================================================================

/// Type of signal that identified a bot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalType {
    /// Bot identified by IP address
    IpAddress,
    /// Bot identified by User-Agent string
    UserAgent,
    /// Bot identified by country/geo location
    GeoLocation,
    /// Bot identified by request rate (rate limiting)
    RateLimit,
    /// Bot identified by request pattern
    RequestPattern,
    /// Bot identified by behavior analysis (local-only)
    Behavioral,
    /// Bot manually reported by user
    ManualReport,
    /// Bot identified from official source
    OfficialSource,
    /// Bot identified from crowdsourced/community source
    Crowdsourced,
}

impl fmt::Display for SignalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignalType::IpAddress => write!(f, "IP Address"),
            SignalType::UserAgent => write!(f, "User-Agent"),
            SignalType::GeoLocation => write!(f, "Geo Location"),
            SignalType::RateLimit => write!(f, "Rate Limit"),
            SignalType::RequestPattern => write!(f, "Request Pattern"),
            SignalType::Behavioral => write!(f, "Behavioral"),
            SignalType::ManualReport => write!(f, "Manual Report"),
            SignalType::OfficialSource => write!(f, "Official Source"),
            SignalType::Crowdsourced => write!(f, "Crowdsourced"),
        }
    }
}

impl SignalType {
    /// Returns the signal type as a string suitable for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            SignalType::IpAddress => "ip_address",
            SignalType::UserAgent => "user_agent",
            SignalType::GeoLocation => "geo_location",
            SignalType::RateLimit => "rate_limit",
            SignalType::RequestPattern => "request_pattern",
            SignalType::Behavioral => "behavioral",
            SignalType::ManualReport => "manual_report",
            SignalType::OfficialSource => "official_source",
            SignalType::Crowdsourced => "crowdsourced",
        }
    }

    /// Parses a signal type from a database string.
    pub fn from_db_str(s: &str) -> Option<SignalType> {
        match s {
            "ip_address" => Some(SignalType::IpAddress),
            "user_agent" => Some(SignalType::UserAgent),
            "geo_location" => Some(SignalType::GeoLocation),
            "rate_limit" => Some(SignalType::RateLimit),
            "request_pattern" => Some(SignalType::RequestPattern),
            "behavioral" => Some(SignalType::Behavioral),
            "manual_report" => Some(SignalType::ManualReport),
            "official_source" => Some(SignalType::OfficialSource),
            "crowdsourced" => Some(SignalType::Crowdsourced),
            _ => None,
        }
    }
}

// ============================================================================
// Data Source
// ============================================================================

/// A source of bot data that can be auto-updated.
#[derive(Debug, Clone)]
pub struct DataSource {
    /// Unique identifier for the source
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of the source
    pub description: String,
    /// URL where the data can be fetched from
    pub url: Option<String>,
    /// Frequency of auto-updates
    pub update_frequency: UpdateFrequency,
    /// Whether auto-update is enabled
    pub auto_update_enabled: bool,
    /// Last update timestamp
    pub last_updated: Option<SystemTime>,
    /// Whether the source is official/verified
    pub is_official: bool,
    /// Type of data provided by this source
    pub data_type: DataSourceType,
}

/// Type of data provided by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSourceType {
    /// Bot definitions (name, UA patterns, etc.)
    BotDefinitions,
    /// IP ranges/block lists
    IpRanges,
    /// User agent patterns
    UserAgents,
    /// Combined data
    Combined,
}

/// Frequency of auto-updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpdateFrequency {
    /// Never auto-update
    Never,
    /// Update daily
    Daily,
    /// Update weekly
    #[default]
    Weekly,
    /// Update monthly
    Monthly,
    /// Custom duration
    Custom(Duration),
}

impl UpdateFrequency {
    /// Returns the duration between updates.
    pub fn duration(&self) -> Option<Duration> {
        match self {
            UpdateFrequency::Never => None,
            UpdateFrequency::Daily => Some(Duration::from_secs(86400)),
            UpdateFrequency::Weekly => Some(Duration::from_secs(604800)),
            UpdateFrequency::Monthly => Some(Duration::from_secs(2592000)),
            UpdateFrequency::Custom(d) => Some(*d),
        }
    }

    /// Returns the frequency as a string for display.
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateFrequency::Never => "Never",
            UpdateFrequency::Daily => "Daily",
            UpdateFrequency::Weekly => "Weekly",
            UpdateFrequency::Monthly => "Monthly",
            UpdateFrequency::Custom(_) => "Custom",
        }
    }
}

// ============================================================================
// IP Range Verification
// ============================================================================

/// Status of IP range verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// IP range has been verified and is valid
    Verified,
    /// IP range failed verification
    Failed,
    /// IP range has not been verified yet
    Unverified,
    /// Verification is in progress
    Verifying,
}

/// Information about IP range verification.
#[derive(Debug, Clone)]
pub struct VerificationInfo {
    /// Current verification status
    pub status: VerificationStatus,
    /// When the verification was last performed
    pub verified_at: Option<SystemTime>,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Source of the IP range (official, crowdsourced, manual)
    pub source: VerificationSource,
}

/// Source of IP range data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationSource {
    /// From official bot owner documentation
    Official,
    /// From crowdsourced/third-party lists
    Crowdsourced,
    /// Manually entered by user
    Manual,
    /// Detected automatically by the system
    AutoDetected,
}

// ============================================================================
// Bot Definition
// ============================================================================

/// A bot definition with all its identifiers.
#[derive(Debug, Clone)]
pub struct Bot {
    /// Unique identifier
    pub id: Option<i64>,
    /// Bot name
    pub name: String,
    /// Default status (allowed or blocked)
    pub status: BotStatus,
    /// Categories this bot belongs to
    pub categories: Vec<BotCategory>,
    /// User agent patterns
    pub user_agent_patterns: Vec<BotUserAgentPattern>,
    /// IP ranges associated with this bot
    pub ip_ranges: Vec<BotIpRange>,
    /// Signals that identified this bot
    pub signals: Vec<SignalType>,
    /// Owner information
    pub owner: Option<BotOwner>,
    /// Owner ID for database reference (separate from owner object)
    pub owner_id: Option<i64>,
    /// Notes/description
    pub notes: Option<String>,
    /// Whether this is an AI bot/scraper
    pub is_ai_bot: bool,
    /// Whether this is a scanner
    pub is_scanner: bool,
    /// Source data source ID
    pub source_id: Option<String>,
    /// Created timestamp
    pub created_at: Option<SystemTime>,
    /// Updated timestamp
    pub updated_at: Option<SystemTime>,
}

/// User-Agent pattern for a bot.
#[derive(Debug, Clone)]
pub struct BotUserAgentPattern {
    /// Unique identifier
    pub id: Option<i64>,
    /// Bot ID this pattern belongs to
    pub bot_id: Option<i64>,
    /// The pattern to match
    pub pattern: String,
    /// Whether the pattern is a regex
    pub is_regex: bool,
    /// Whether matching is case-sensitive
    pub case_sensitive: bool,
    /// Whether this is the primary pattern for the bot
    pub is_primary: bool,
}

/// IP range for a bot.
#[derive(Debug, Clone)]
pub struct BotIpRange {
    /// Unique identifier
    pub id: Option<i64>,
    /// Bot ID this range belongs to
    pub bot_id: Option<i64>,
    /// The IP address or CIDR range
    pub address: String,
    /// Description of this range
    pub description: Option<String>,
    /// Verification information
    pub verification: VerificationInfo,
}

/// Owner of a bot.
#[derive(Debug, Clone)]
pub struct BotOwner {
    /// Unique identifier
    pub id: Option<i64>,
    /// Owner name
    pub name: String,
    /// Website URL
    pub website: Option<String>,
    /// Contact email
    pub contact: Option<String>,
}

// ============================================================================
// Site Definition
// ============================================================================

/// Represents a discovered NGINX site for database storage.
#[derive(Debug, Clone)]
pub struct Site {
    /// Unique identifier
    pub id: Option<i64>,
    /// Site name (server_name from nginx config)
    pub name: String,
    /// Path to the nginx configuration file
    pub config_path: String,
    /// Line number where the server block starts
    pub config_line: Option<i32>,
    /// When the site was discovered
    pub discovered_at: Option<SystemTime>,
}

// ============================================================================
// Database Connection
// ============================================================================

/// Manages the SQLite database connection.
#[derive(Debug)]
pub struct Database {
    /// The SQLite connection
    conn: Connection,
    /// Path to the database file
    path: PathBuf,
}

impl Clone for Database {
    fn clone(&self) -> Self {
        // Open a new connection to the same database file
        // This allows sharing the database across threads via Arc<Mutex<Database>>
        // or by cloning and using in spawn_blocking
        let conn = Connection::open(&self.path).expect("Failed to clone database connection");

        // Enable WAL mode and foreign keys on the cloned connection
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .expect("Failed to enable WAL mode");
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .expect("Failed to enable foreign keys");

        Self {
            conn,
            path: self.path.clone(),
        }
    }
}

impl Database {
    /// Opens a database at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open database: {}", path.display()))?;

        // Enable WAL mode for better performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        Ok(Database {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Opens the default database.
    pub fn open_default() -> Result<Self> {
        Self::open(default_db_path())
    }

    /// Returns the path to the database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Initializes the database schema.
    pub fn initialize(&mut self) -> Result<()> {
        // Create schema SQL first (before starting transaction)
        let schema_sql = self.create_schema_sql();
        let indexes_sql = self.create_indexes_sql();

        let tx = self.conn.transaction()?;

        // Create tables
        tx.execute_batch(&schema_sql)?;

        // Create indexes
        tx.execute_batch(&indexes_sql)?;

        tx.commit()?;

        Ok(())
    }

    /// Returns the SQL for creating the database schema.
    fn create_schema_sql(&self) -> String {
        let mut sql = String::new();

        // Categories table
        sql.push_str("CREATE TABLE IF NOT EXISTS categories (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL UNIQUE,");
        sql.push_str("    description TEXT");
        sql.push_str(");\n\n");

        // Owners table
        sql.push_str("CREATE TABLE IF NOT EXISTS owners (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL,");
        sql.push_str("    website TEXT,");
        sql.push_str("    contact TEXT");
        sql.push_str(");\n\n");

        // Signals table
        sql.push_str("CREATE TABLE IF NOT EXISTS signals (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL UNIQUE,");
        sql.push_str("    description TEXT");
        sql.push_str(");\n\n");

        // Data sources table
        sql.push_str("CREATE TABLE IF NOT EXISTS data_sources (");
        sql.push_str("    id TEXT PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL,");
        sql.push_str("    description TEXT,");
        sql.push_str("    url TEXT,");
        sql.push_str("    update_frequency TEXT NOT NULL,");
        sql.push_str("    auto_update_enabled INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    last_updated INTEGER,");
        sql.push_str("    is_official INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    data_type TEXT NOT NULL");
        sql.push_str(");\n\n");

        // Bots table
        sql.push_str("CREATE TABLE IF NOT EXISTS bots (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL,");
        sql.push_str("    status TEXT NOT NULL,");
        sql.push_str("    is_ai_bot INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    is_scanner INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    owner_id INTEGER REFERENCES owners(id),");
        sql.push_str("    source_id TEXT REFERENCES data_sources(id),");
        sql.push_str("    notes TEXT,");
        sql.push_str("    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),");
        sql.push_str("    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))");
        sql.push_str(");\n\n");

        // Bot categories (many-to-many)
        sql.push_str("CREATE TABLE IF NOT EXISTS bot_categories (");
        sql.push_str("    bot_id INTEGER NOT NULL REFERENCES bots(id) ON DELETE CASCADE,");
        sql.push_str(
            "    category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,",
        );
        sql.push_str("    PRIMARY KEY (bot_id, category_id)");
        sql.push_str(");\n\n");

        // Bot signals (many-to-many)
        sql.push_str("CREATE TABLE IF NOT EXISTS bot_signals (");
        sql.push_str("    bot_id INTEGER NOT NULL REFERENCES bots(id) ON DELETE CASCADE,");
        sql.push_str("    signal_id INTEGER NOT NULL REFERENCES signals(id) ON DELETE CASCADE,");
        sql.push_str("    PRIMARY KEY (bot_id, signal_id)");
        sql.push_str(");\n\n");

        // User agent patterns
        sql.push_str("CREATE TABLE IF NOT EXISTS user_agent_patterns (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    bot_id INTEGER REFERENCES bots(id) ON DELETE CASCADE,");
        sql.push_str("    pattern TEXT NOT NULL,");
        sql.push_str("    is_regex INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    case_sensitive INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    is_primary INTEGER NOT NULL DEFAULT 0");
        sql.push_str(");\n\n");

        // IP ranges
        sql.push_str("CREATE TABLE IF NOT EXISTS ip_ranges (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    bot_id INTEGER REFERENCES bots(id) ON DELETE CASCADE,");
        sql.push_str("    address TEXT NOT NULL,");
        sql.push_str("    description TEXT,");
        sql.push_str("    verification_status TEXT NOT NULL DEFAULT 'unverified',");
        sql.push_str("    verified_at INTEGER,");
        sql.push_str("    verification_error TEXT,");
        sql.push_str("    verification_source TEXT NOT NULL");
        sql.push_str(");\n\n");

        // Rate limits
        sql.push_str("CREATE TABLE IF NOT EXISTS rate_limits (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL UNIQUE,");
        sql.push_str("    zone_name TEXT NOT NULL UNIQUE,");
        sql.push_str("    zone_size TEXT NOT NULL,");
        sql.push_str("    rate TEXT NOT NULL,");
        sql.push_str("    burst INTEGER,");
        sql.push_str("    nodelay INTEGER NOT NULL DEFAULT 0,");
        sql.push_str("    description TEXT");
        sql.push_str(");\n\n");

        // Geo blocks
        sql.push_str("CREATE TABLE IF NOT EXISTS geo_blocks (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    country_code TEXT NOT NULL,");
        sql.push_str("    is_blocked INTEGER NOT NULL DEFAULT 1,");
        sql.push_str("    description TEXT");
        sql.push_str(");\n\n");

        // User settings
        sql.push_str("CREATE TABLE IF NOT EXISTS settings (");
        sql.push_str("    key TEXT PRIMARY KEY,");
        sql.push_str("    value TEXT");
        sql.push_str(");\n\n");

        // Sites table - for storing discovered NGINX sites
        sql.push_str("CREATE TABLE IF NOT EXISTS sites (");
        sql.push_str("    id INTEGER PRIMARY KEY,");
        sql.push_str("    name TEXT NOT NULL,");
        sql.push_str("    config_path TEXT NOT NULL,");
        sql.push_str("    config_line INTEGER,");
        sql.push_str("    discovered_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),");
        sql.push_str("    UNIQUE(name, config_path)");
        sql.push_str(");\n\n");

        sql
    }

    /// Returns the SQL for creating indexes.
    fn create_indexes_sql(&self) -> String {
        let mut sql = String::new();

        // Indexes for faster lookups
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_bots_name ON bots(name);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_bots_status ON bots(status);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_bots_is_ai_bot ON bots(is_ai_bot);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_bots_is_scanner ON bots(is_scanner);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_user_agent_patterns_pattern ON user_agent_patterns(pattern);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_user_agent_patterns_bot_id ON user_agent_patterns(bot_id);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_ip_ranges_address ON ip_ranges(address);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_ip_ranges_bot_id ON ip_ranges(bot_id);\n");
        sql.push_str(
            "CREATE INDEX IF NOT EXISTS idx_bot_categories_bot_id ON bot_categories(bot_id);\n",
        );
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_bot_categories_category_id ON bot_categories(category_id);\n");
        sql.push_str(
            "CREATE INDEX IF NOT EXISTS idx_geo_blocks_country_code ON geo_blocks(country_code);\n",
        );
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_data_sources_id ON data_sources(id);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_sites_name ON sites(name);\n");
        sql.push_str("CREATE INDEX IF NOT EXISTS idx_sites_config_path ON sites(config_path);\n");

        sql
    }

    /// Returns the connection to the database.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

// ============================================================================
// Database Operations
// ============================================================================

impl Database {
    // Category operations

    /// Ensures all default categories exist in the database.
    pub fn ensure_categories(&self) -> Result<()> {
        for category in BotCategory::all() {
            self.conn.execute(
                "INSERT OR IGNORE INTO categories (name, description) VALUES (?1, ?2)",
                params![category.as_db_str(), format!("{}", category)],
            )?;
        }
        Ok(())
    }

    // Signal operations

    /// Ensures all default signals exist in the database.
    pub fn ensure_signals(&self) -> Result<()> {
        use SignalType::*;
        let signals = [
            (IpAddress, "Identified by IP address"),
            (UserAgent, "Identified by User-Agent string"),
            (GeoLocation, "Identified by geo location"),
            (RateLimit, "Identified by rate limiting"),
            (RequestPattern, "Identified by request pattern"),
            (Behavioral, "Identified by behavioral analysis"),
            (ManualReport, "Manually reported by user"),
            (OfficialSource, "From official source"),
            (Crowdsourced, "From crowdsourced/community source"),
        ];

        for (signal, desc) in signals {
            self.conn.execute(
                "INSERT OR IGNORE INTO signals (name, description) VALUES (?1, ?2)",
                params![signal.as_db_str(), desc],
            )?;
        }
        Ok(())
    }

    // Bot operations

    /// Inserts or updates a bot.
    pub fn upsert_bot(&mut self, bot: &Bot) -> Result<i64> {
        let tx = self.conn.transaction()?;

        // First, handle the owner if present
        let owner_id = if let Some(ref owner) = bot.owner {
            if let Some(id) = owner.id {
                // Owner already has an ID, update it
                tx.execute(
                    "UPDATE owners SET name = ?1, website = ?2, contact = ?3 WHERE id = ?4",
                    params![
                        &owner.name,
                        owner.website.as_deref(),
                        owner.contact.as_deref(),
                        id
                    ],
                )?;
                Some(id)
            } else {
                // Insert new owner
                tx.execute(
                    "INSERT INTO owners (name, website, contact) VALUES (?1, ?2, ?3)",
                    params![
                        &owner.name,
                        owner.website.as_deref(),
                        owner.contact.as_deref()
                    ],
                )?;
                Some(tx.last_insert_rowid())
            }
        } else {
            bot.owner_id
        };

        // Insert or update the bot
        let bot_id: i64;

        if let Some(id) = bot.id {
            tx.execute(
                "UPDATE bots SET name = ?1, status = ?2, is_ai_bot = ?3, is_scanner = ?4, 
                 owner_id = ?5, source_id = ?6, notes = ?7, updated_at = strftime('%s', 'now') 
                 WHERE id = ?8",
                params![
                    &bot.name,
                    bot.status.as_db_str(),
                    bot.is_ai_bot as i32,
                    bot.is_scanner as i32,
                    owner_id,
                    bot.source_id.as_deref(),
                    bot.notes.as_deref(),
                    id
                ],
            )?;
            bot_id = id;
        } else {
            tx.execute(
                "INSERT INTO bots (name, status, is_ai_bot, is_scanner, owner_id, source_id, notes) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &bot.name,
                    bot.status.as_db_str(),
                    bot.is_ai_bot as i32,
                    bot.is_scanner as i32,
                    owner_id,
                    bot.source_id.as_deref(),
                    bot.notes.as_deref(),
                ],
            )?;
            bot_id = tx.last_insert_rowid();
        }

        // Clear existing categories and insert new ones
        tx.execute("DELETE FROM bot_categories WHERE bot_id = ?1", [bot_id])?;
        for category in &bot.categories {
            // Try to get existing category ID first
            let category_id: i64 = tx
                .query_row(
                    "SELECT id FROM categories WHERE name = ?1",
                    [category.as_db_str()],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            let category_id = if category_id == 0 {
                // Insert new category
                tx.execute(
                    "INSERT INTO categories (name, description) VALUES (?1, ?2)",
                    params![category.as_db_str(), &format!("{}", category)],
                )?;
                tx.last_insert_rowid()
            } else {
                category_id
            };

            tx.execute(
                "INSERT INTO bot_categories (bot_id, category_id) VALUES (?1, ?2)",
                params![bot_id, category_id],
            )?;
        }

        // Clear existing signals and insert new ones
        tx.execute("DELETE FROM bot_signals WHERE bot_id = ?1", [bot_id])?;
        for signal in &bot.signals {
            // Try to get existing signal ID first
            let signal_id: i64 = tx
                .query_row(
                    "SELECT id FROM signals WHERE name = ?1",
                    [signal.as_db_str()],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            let signal_id = if signal_id == 0 {
                // Insert new signal
                tx.execute(
                    "INSERT INTO signals (name, description) VALUES (?1, ?2)",
                    params![signal.as_db_str(), &format!("{}", signal)],
                )?;
                tx.last_insert_rowid()
            } else {
                signal_id
            };

            tx.execute(
                "INSERT INTO bot_signals (bot_id, signal_id) VALUES (?1, ?2)",
                params![bot_id, signal_id],
            )?;
        }

        // Upsert user agent patterns
        for pattern in &bot.user_agent_patterns {
            if let Some(pattern_id) = pattern.id {
                tx.execute(
                    "UPDATE user_agent_patterns SET pattern = ?1, is_regex = ?2, 
                     case_sensitive = ?3, is_primary = ?4, bot_id = ?5 
                     WHERE id = ?6",
                    params![
                        &pattern.pattern,
                        pattern.is_regex as i32,
                        pattern.case_sensitive as i32,
                        pattern.is_primary as i32,
                        bot_id,
                        pattern_id
                    ],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO user_agent_patterns (bot_id, pattern, is_regex, case_sensitive, is_primary) 
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        bot_id,
                        &pattern.pattern,
                        pattern.is_regex as i32,
                        pattern.case_sensitive as i32,
                        pattern.is_primary as i32
                    ],
                )?;
            }
        }

        // Upsert IP ranges
        for ip_range in &bot.ip_ranges {
            if let Some(range_id) = ip_range.id {
                tx.execute(
                    "UPDATE ip_ranges SET address = ?1, description = ?2, 
                     verification_status = ?3, verified_at = ?4, verification_error = ?5, 
                     verification_source = ?6, bot_id = ?7 
                     WHERE id = ?8",
                    params![
                        &ip_range.address,
                        ip_range.description.as_deref(),
                        ip_range.verification.status.as_db_str(),
                        ip_range.verification.verified_at.map(|t| t
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or(Duration::ZERO)
                            .as_secs()
                            as i64),
                        ip_range.verification.error.as_deref(),
                        ip_range.verification.source.as_db_str(),
                        bot_id,
                        range_id
                    ],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO ip_ranges (bot_id, address, description, verification_status, verified_at, verification_error, verification_source) 
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        bot_id,
                        &ip_range.address,
                        ip_range.description.as_deref(),
                        ip_range.verification.status.as_db_str(),
                        ip_range.verification.verified_at.map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() as i64),
                        ip_range.verification.error.as_deref(),
                        ip_range.verification.source.as_db_str()
                    ],
                )?;
            }
        }

        tx.commit()?;
        Ok(bot_id)
    }

    /// Fetches a bot by ID.
    pub fn get_bot(&self, id: i64) -> Result<Option<Bot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, status, is_ai_bot, is_scanner, owner_id, source_id, notes, created_at, updated_at 
             FROM bots WHERE id = ?1",
        )?;

        let bot_row = stmt.query_row([id], |row| {
            Ok(Bot {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                status: BotStatus::from_db_str(&row.get::<_, String>(2)?)
                    .unwrap_or(BotStatus::Blocked),
                categories: Vec::new(),
                user_agent_patterns: Vec::new(),
                ip_ranges: Vec::new(),
                signals: Vec::new(),
                owner: None,
                owner_id: row.get(5)?,
                notes: row.get(7)?,
                is_ai_bot: row.get::<_, i32>(3)? != 0,
                is_scanner: row.get::<_, i32>(4)? != 0,
                source_id: row.get(6)?,
                created_at: Self::timestamp_from_unix(row.get::<_, i64>(8)?),
                updated_at: Self::timestamp_from_unix(row.get::<_, i64>(9)?),
            })
        });

        let bot = match bot_row {
            Ok(bot) => bot,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // Fetch categories
        let mut stmt = self.conn.prepare(
            "SELECT c.name FROM bot_categories bc 
             JOIN categories c ON bc.category_id = c.id 
             WHERE bc.bot_id = ?1",
        )?;
        let categories: Vec<BotCategory> = stmt
            .query_map([id], |row| {
                let name: String = row.get(0)?;
                Ok(BotCategory::from_db_str(&name).unwrap_or(BotCategory::Unknown))
            })?
            .collect::<Result<_, _>>()?;

        // Fetch signals
        let mut stmt = self.conn.prepare(
            "SELECT s.name FROM bot_signals bs 
             JOIN signals s ON bs.signal_id = s.id 
             WHERE bs.bot_id = ?1",
        )?;
        let signals: Vec<SignalType> = stmt
            .query_map([id], |row| {
                let name: String = row.get(0)?;
                Ok(SignalType::from_db_str(&name).unwrap_or(SignalType::UserAgent))
            })?
            .collect::<Result<_, _>>()?;

        // Fetch user agent patterns
        let mut stmt = self.conn.prepare(
            "SELECT id, pattern, is_regex, case_sensitive, is_primary 
             FROM user_agent_patterns WHERE bot_id = ?1",
        )?;
        let user_agent_patterns: Vec<BotUserAgentPattern> = stmt
            .query_map([id], |row| {
                Ok(BotUserAgentPattern {
                    id: row.get(0)?,
                    bot_id: Some(id),
                    pattern: row.get(1)?,
                    is_regex: row.get::<_, i32>(2)? != 0,
                    case_sensitive: row.get::<_, i32>(3)? != 0,
                    is_primary: row.get::<_, i32>(4)? != 0,
                })
            })?
            .collect::<Result<_, _>>()?;

        // Fetch IP ranges
        let mut stmt = self.conn.prepare(
            "SELECT id, address, description, verification_status, verified_at, verification_error, verification_source 
             FROM ip_ranges WHERE bot_id = ?1",
        )?;
        let ip_ranges: Vec<BotIpRange> = stmt
            .query_map([id], |row| {
                let verification = VerificationInfo {
                    status: VerificationStatus::from_db_str(&row.get::<_, String>(3)?)
                        .unwrap_or(VerificationStatus::Unverified),
                    verified_at: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(4)?),
                    error: row.get(5)?,
                    source: VerificationSource::from_db_str(&row.get::<_, String>(6)?)
                        .unwrap_or(VerificationSource::Manual),
                };

                Ok(BotIpRange {
                    id: row.get(0)?,
                    bot_id: Some(id),
                    address: row.get(1)?,
                    description: row.get(2)?,
                    verification,
                })
            })?
            .collect::<Result<_, _>>()?;

        // Fetch owner if present
        let owner = if bot.owner_id.is_some() {
            let owner_id: i64 = bot.owner_id.unwrap();
            let mut stmt = self
                .conn
                .prepare("SELECT id, name, website, contact FROM owners WHERE id = ?1")?;
            stmt.query_row([owner_id], |row| {
                Ok(BotOwner {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    website: row.get(2)?,
                    contact: row.get(3)?,
                })
            })
            .ok()
        } else {
            None
        };

        Ok(Some(Bot {
            owner,
            categories,
            signals,
            user_agent_patterns,
            ip_ranges,
            ..bot
        }))
    }

    /// Fetches all bots.
    pub fn get_all_bots(&self) -> Result<Vec<Bot>> {
        let mut stmt = self.conn.prepare("SELECT id FROM bots")?;
        let bot_ids: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;

        let mut bots = Vec::new();
        for id in bot_ids {
            if let Some(bot) = self.get_bot(id)? {
                bots.push(bot);
            }
        }
        Ok(bots)
    }

    /// Deletes a bot by ID.
    pub fn delete_bot(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM bots WHERE id = ?1", [id])?;
        Ok(())
    }

    // Data source operations

    /// Initializes the data sources table with known sources.
    pub fn initialize_data_sources(&mut self) -> Result<()> {
        // Insert all known sources (use INSERT OR IGNORE to avoid conflicts)
        // We don't delete existing sources to avoid breaking foreign key references from bots
        for source in crate::source_fetch::KnownSources::all() {
            self.upsert_data_source(&source)?;
        }

        Ok(())
    }

    /// Upserts a data source.
    pub fn upsert_data_source(&self, source: &DataSource) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO data_sources 
             (id, name, description, url, update_frequency, auto_update_enabled, last_updated, is_official, data_type) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &source.id,
                &source.name,
                &source.description,
                source.url.as_deref(),
                source.update_frequency.as_db_str(),
                source.auto_update_enabled as i32,
                source.last_updated.map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() as i64),
                source.is_official as i32,
                source.data_type.as_db_str(),
            ],
        )?;
        Ok(())
    }

    /// Gets a data source by ID.
    pub fn get_data_source(&self, id: &str) -> Result<Option<DataSource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, url, update_frequency, auto_update_enabled, last_updated, is_official, data_type 
             FROM data_sources WHERE id = ?1",
        )?;

        let source_row = stmt.query_row([id], |row| {
            Ok(DataSource {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                url: row.get(3)?,
                update_frequency: UpdateFrequency::from_db_str(&row.get::<_, String>(4)?)
                    .unwrap_or(UpdateFrequency::Weekly),
                auto_update_enabled: row.get::<_, i32>(5)? != 0,
                last_updated: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(6)?),
                is_official: row.get::<_, i32>(7)? != 0,
                data_type: DataSourceType::from_db_str(&row.get::<_, String>(8)?)
                    .unwrap_or(DataSourceType::Combined),
            })
        });

        match source_row {
            Ok(source) => Ok(Some(source)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Gets all data sources.
    pub fn get_all_data_sources(&self) -> Result<Vec<DataSource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, url, update_frequency, auto_update_enabled, last_updated, is_official, data_type 
             FROM data_sources ORDER BY is_official DESC, name",
        )?;

        let sources: Vec<DataSource> = stmt
            .query_map([], |row| {
                Ok(DataSource {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    url: row.get(3)?,
                    update_frequency: UpdateFrequency::from_db_str(&row.get::<_, String>(4)?)
                        .unwrap_or(UpdateFrequency::Weekly),
                    auto_update_enabled: row.get::<_, i32>(5)? != 0,
                    last_updated: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(6)?),
                    is_official: row.get::<_, i32>(7)? != 0,
                    data_type: DataSourceType::from_db_str(&row.get::<_, String>(8)?)
                        .unwrap_or(DataSourceType::Combined),
                })
            })?
            .collect::<Result<_, _>>()?;

        Ok(sources)
    }

    /// Updates the last_updated timestamp for a data source.
    pub fn update_data_source_last_updated(&self, id: &str, timestamp: SystemTime) -> Result<()> {
        let timestamp_secs = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        self.conn.execute(
            "UPDATE data_sources SET last_updated = ?1 WHERE id = ?2",
            params![timestamp_secs, id],
        )?;
        Ok(())
    }

    /// Checks if a data source needs to be updated based on its frequency.
    pub fn data_source_needs_update(&self, source: &DataSource) -> Result<bool> {
        // If auto-update is disabled, never update
        if !source.auto_update_enabled {
            return Ok(false);
        }

        // If never update, return false
        if let UpdateFrequency::Never = source.update_frequency {
            return Ok(false);
        }

        // If never updated before, needs update
        let last_updated = match source.last_updated {
            Some(ts) => ts,
            None => return Ok(true),
        };

        // Get the duration since last update
        let duration_since_update = SystemTime::now()
            .duration_since(last_updated)
            .unwrap_or(Duration::ZERO);

        // Get the update frequency duration
        let update_duration = source
            .update_frequency
            .duration()
            .ok_or_else(|| anyhow::anyhow!("Invalid update frequency"))?;

        // Needs update if duration since last update >= update frequency
        Ok(duration_since_update >= update_duration)
    }

    /// Upserts multiple bots from a source, updating the source's last_updated timestamp.
    pub fn upsert_bots_from_source(&mut self, source_id: &str, bots: Vec<Bot>) -> Result<Vec<i64>> {
        // First, ensure the data source exists
        // If it doesn't exist, create a default one
        let source_exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM data_sources WHERE id = ?1",
                [source_id],
                |_| Ok(()),
            )
            .is_ok();

        if !source_exists {
            // Create a minimal data source entry
            let default_source = DataSource {
                id: source_id.to_string(),
                name: source_id.to_string(),
                description: format!("Auto-created source: {}", source_id),
                url: None,
                update_frequency: UpdateFrequency::Weekly,
                auto_update_enabled: true,
                last_updated: None,
                is_official: false,
                data_type: DataSourceType::Combined,
            };
            self.upsert_data_source(&default_source)?;
        }

        let mut bot_ids = Vec::new();

        for mut bot in bots {
            // Set the source_id for all bots
            if bot.source_id.is_none() {
                bot.source_id = Some(source_id.to_string());
            }

            // Upsert the bot and get its ID
            let bot_id = self.upsert_bot(&bot)?;
            bot_ids.push(bot_id);
        }

        // Update the source's last_updated timestamp
        self.update_data_source_last_updated(source_id, SystemTime::now())?;

        Ok(bot_ids)
    }

    /// Deletes all bots from a specific source.
    pub fn delete_bots_from_source(&self, source_id: &str) -> Result<usize> {
        let changes = self
            .conn
            .execute("DELETE FROM bots WHERE source_id = ?1", [source_id])?;
        Ok(changes)
    }

    /// Refreshes bots from a specific source by deleting and re-inserting.
    /// This is useful for full refreshes of a source's data.
    pub fn refresh_bots_from_source(
        &mut self,
        source_id: &str,
        bots: Vec<Bot>,
    ) -> Result<Vec<i64>> {
        // Delete existing bots from this source
        self.delete_bots_from_source(source_id)?;

        // Insert new bots (this will ensure the source exists and update last_updated)
        self.upsert_bots_from_source(source_id, bots)
    }

    /// Fetches all bots from a specific source.
    pub fn get_bots_by_source(&self, source_id: &str) -> Result<Vec<Bot>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM bots WHERE source_id = ?1")?;
        let bot_ids: Vec<i64> = stmt
            .query_map([source_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;

        let mut bots = Vec::new();
        for id in bot_ids {
            if let Some(bot) = self.get_bot(id)? {
                bots.push(bot);
            }
        }
        Ok(bots)
    }

    /// Fetches and stores bots from a specific source using the SourceFetcher.
    pub async fn fetch_and_store_from_source(&mut self, source_id: &str) -> Result<Vec<i64>> {
        use crate::source_fetch::SourceFetcher;

        let fetcher = SourceFetcher::new()?;
        let bots = fetcher.fetch_from_source(source_id).await?;
        self.upsert_bots_from_source(source_id, bots)
    }

    /// Fetches and stores bots from all official sources.
    pub async fn fetch_and_store_official(&mut self) -> Result<Vec<i64>> {
        use crate::source_fetch::SourceFetcher;

        let fetcher = SourceFetcher::new()?;
        let bots = fetcher.fetch_official().await?;

        let mut all_ids = Vec::new();

        // Group bots by source_id
        let mut bots_by_source: std::collections::HashMap<String, Vec<Bot>> =
            std::collections::HashMap::new();

        for bot in bots {
            let source_id = bot
                .source_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            bots_by_source.entry(source_id).or_default().push(bot);
        }

        // Upsert bots for each source
        for (source_id, source_bots) in bots_by_source {
            let ids = self.upsert_bots_from_source(&source_id, source_bots)?;
            all_ids.extend(ids);
        }

        Ok(all_ids)
    }

    // Helper methods

    /// Converts a Unix timestamp to SystemTime.
    fn timestamp_from_unix(timestamp: i64) -> Option<SystemTime> {
        if timestamp > 0 {
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        } else {
            None
        }
    }

    /// Converts an optional Unix timestamp to SystemTime.
    fn timestamp_from_unix_opt(timestamp: Option<i64>) -> Option<SystemTime> {
        timestamp.and_then(Self::timestamp_from_unix)
    }

    // Site operations

    /// Inserts or updates a site.
    pub fn upsert_site(
        &mut self,
        name: &str,
        config_path: &str,
        config_line: Option<usize>,
    ) -> Result<i64> {
        let line_num: Option<i32> = config_line.map(|l| l as i32);

        let tx = self.conn.transaction()?;

        // Try to update existing site
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM sites WHERE name = ?1 AND config_path = ?2",
                params![name, config_path],
                |row| row.get(0),
            )
            .ok();

        if let Some(id) = existing {
            tx.execute(
                "UPDATE sites SET config_line = ?1, discovered_at = strftime('%s', 'now') WHERE id = ?2",
                params![line_num, id],
            )?;
            return Ok(id);
        }

        // Insert new site
        tx.execute(
            "INSERT INTO sites (name, config_path, config_line) VALUES (?1, ?2, ?3)",
            params![name, config_path, line_num],
        )?;

        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Gets all sites from the database.
    pub fn get_all_sites(&self) -> Result<Vec<Site>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, config_path, config_line, discovered_at FROM sites ORDER BY name",
        )?;

        let sites = stmt
            .query_map([], |row| {
                Ok(Site {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config_path: row.get(2)?,
                    config_line: row.get(3)?,
                    discovered_at: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(4)?),
                })
            })?
            .collect::<Result<_, _>>()?;

        Ok(sites)
    }

    /// Gets a site by name.
    pub fn get_site_by_name(&self, name: &str) -> Result<Option<Site>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, config_path, config_line, discovered_at FROM sites WHERE name = ?1",
        )?;

        let site = stmt
            .query_row([name], |row| {
                Ok(Site {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config_path: row.get(2)?,
                    config_line: row.get(3)?,
                    discovered_at: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(4)?),
                })
            })
            .ok();

        Ok(site)
    }

    /// Gets sites by config path.
    pub fn get_sites_by_config_path(&self, config_path: &str) -> Result<Vec<Site>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, config_path, config_line, discovered_at FROM sites WHERE config_path = ?1 ORDER BY name",
        )?;

        let sites = stmt
            .query_map([config_path], |row| {
                Ok(Site {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    config_path: row.get(2)?,
                    config_line: row.get(3)?,
                    discovered_at: Self::timestamp_from_unix_opt(row.get::<_, Option<i64>>(4)?),
                })
            })?
            .collect::<Result<_, _>>()?;

        Ok(sites)
    }

    /// Deletes a site by ID.
    pub fn delete_site(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM sites WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Deletes all sites.
    pub fn delete_all_sites(&self) -> Result<()> {
        self.conn.execute("DELETE FROM sites", [])?;
        Ok(())
    }
}

// ============================================================================
// Trait Implementations for Database Storage
// ============================================================================

impl BotStatus {
    /// Converts to a string for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            BotStatus::Allowed => "allowed",
            BotStatus::Blocked => "blocked",
        }
    }

    /// Parses from a database string.
    pub fn from_db_str(s: &str) -> Option<BotStatus> {
        match s {
            "allowed" => Some(BotStatus::Allowed),
            "blocked" => Some(BotStatus::Blocked),
            _ => None,
        }
    }
}

impl VerificationStatus {
    /// Converts to a string for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            VerificationStatus::Verified => "verified",
            VerificationStatus::Failed => "failed",
            VerificationStatus::Unverified => "unverified",
            VerificationStatus::Verifying => "verifying",
        }
    }

    /// Parses from a database string.
    pub fn from_db_str(s: &str) -> Option<VerificationStatus> {
        match s {
            "verified" => Some(VerificationStatus::Verified),
            "failed" => Some(VerificationStatus::Failed),
            "unverified" => Some(VerificationStatus::Unverified),
            "verifying" => Some(VerificationStatus::Verifying),
            _ => None,
        }
    }
}

impl VerificationSource {
    /// Converts to a string for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            VerificationSource::Official => "official",
            VerificationSource::Crowdsourced => "crowdsourced",
            VerificationSource::Manual => "manual",
            VerificationSource::AutoDetected => "auto_detected",
        }
    }

    /// Parses from a database string.
    pub fn from_db_str(s: &str) -> Option<VerificationSource> {
        match s {
            "official" => Some(VerificationSource::Official),
            "crowdsourced" => Some(VerificationSource::Crowdsourced),
            "manual" => Some(VerificationSource::Manual),
            "auto_detected" => Some(VerificationSource::AutoDetected),
            _ => None,
        }
    }
}

impl UpdateFrequency {
    /// Converts to a string for database storage.
    pub fn as_db_str(&self) -> String {
        match self {
            UpdateFrequency::Never => "never".to_string(),
            UpdateFrequency::Daily => "daily".to_string(),
            UpdateFrequency::Weekly => "weekly".to_string(),
            UpdateFrequency::Monthly => "monthly".to_string(),
            UpdateFrequency::Custom(_) => "custom".to_string(),
        }
    }

    /// Parses from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "never" => Some(UpdateFrequency::Never),
            "daily" => Some(UpdateFrequency::Daily),
            "weekly" => Some(UpdateFrequency::Weekly),
            "monthly" => Some(UpdateFrequency::Monthly),
            _ => None, // Custom frequencies would need additional handling
        }
    }
}

impl DataSourceType {
    /// Converts to a string for database storage.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            DataSourceType::BotDefinitions => "bot_definitions",
            DataSourceType::IpRanges => "ip_ranges",
            DataSourceType::UserAgents => "user_agents",
            DataSourceType::Combined => "combined",
        }
    }

    /// Parses from a database string.
    pub fn from_db_str(s: &str) -> Option<DataSourceType> {
        match s {
            "bot_definitions" => Some(DataSourceType::BotDefinitions),
            "ip_ranges" => Some(DataSourceType::IpRanges),
            "user_agents" => Some(DataSourceType::UserAgents),
            "combined" => Some(DataSourceType::Combined),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_database_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();

        db.initialize().unwrap();

        assert!(db.path().exists());
    }

    #[test]
    fn test_ensure_categories() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();

        db.ensure_categories().unwrap();

        // Verify all categories were inserted
        for category in BotCategory::all() {
            let count: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM categories WHERE name = ?1",
                    [category.as_db_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn test_ensure_signals() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();

        db.ensure_signals().unwrap();

        // Verify all signals were inserted
        let signals = [
            SignalType::IpAddress,
            SignalType::UserAgent,
            SignalType::GeoLocation,
            SignalType::RateLimit,
            SignalType::RequestPattern,
            SignalType::Behavioral,
            SignalType::ManualReport,
            SignalType::OfficialSource,
            SignalType::Crowdsourced,
        ];

        for signal in signals {
            let count: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM signals WHERE name = ?1",
                    [signal.as_db_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn test_upsert_and_get_bot() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();
        db.ensure_categories().unwrap();
        db.ensure_signals().unwrap();

        let bot = Bot {
            id: None,
            name: "TestBot".to_string(),
            status: BotStatus::Blocked,
            categories: vec![BotCategory::Scraper, BotCategory::AiScraper],
            user_agent_patterns: vec![BotUserAgentPattern {
                id: None,
                bot_id: None,
                pattern: "TestBot/1.0".to_string(),
                is_regex: false,
                case_sensitive: false,
                is_primary: true,
            }],
            ip_ranges: vec![BotIpRange {
                id: None,
                bot_id: None,
                address: "1.2.3.4/24".to_string(),
                description: Some("Test range".to_string()),
                verification: VerificationInfo {
                    status: VerificationStatus::Unverified,
                    verified_at: None,
                    error: None,
                    source: VerificationSource::Manual,
                },
            }],
            signals: vec![SignalType::UserAgent, SignalType::ManualReport],
            owner: None,
            owner_id: None,
            notes: Some("A test bot".to_string()),
            is_ai_bot: true,
            is_scanner: false,
            source_id: None,
            created_at: None,
            updated_at: None,
        };

        let bot_id = db.upsert_bot(&bot).unwrap();
        assert!(bot_id > 0);

        let fetched_bot = db.get_bot(bot_id).unwrap();
        assert!(fetched_bot.is_some());

        let fetched_bot = fetched_bot.unwrap();
        assert_eq!(fetched_bot.name, "TestBot");
        assert_eq!(fetched_bot.status, BotStatus::Blocked);
        assert!(fetched_bot.is_ai_bot);
        assert!(!fetched_bot.is_scanner);
        assert_eq!(fetched_bot.categories.len(), 2);
        assert_eq!(fetched_bot.signals.len(), 2);
        assert_eq!(fetched_bot.user_agent_patterns.len(), 1);
        assert_eq!(fetched_bot.ip_ranges.len(), 1);
    }

    #[test]
    fn test_bot_status_conversion() {
        assert_eq!(BotStatus::Allowed.as_db_str(), "allowed");
        assert_eq!(BotStatus::Blocked.as_db_str(), "blocked");

        assert_eq!(BotStatus::from_db_str("allowed"), Some(BotStatus::Allowed));
        assert_eq!(BotStatus::from_db_str("blocked"), Some(BotStatus::Blocked));
        assert_eq!(BotStatus::from_db_str("invalid"), None);
    }

    #[test]
    fn test_bot_category_conversion() {
        assert_eq!(BotCategory::Scraper.as_db_str(), "scraper");
        assert_eq!(BotCategory::SearchEngine.as_db_str(), "search_engine");

        assert_eq!(
            BotCategory::from_db_str("scraper"),
            Some(BotCategory::Scraper)
        );
        assert_eq!(
            BotCategory::from_db_str("search_engine"),
            Some(BotCategory::SearchEngine)
        );
    }

    #[test]
    fn test_signal_type_conversion() {
        assert_eq!(SignalType::UserAgent.as_db_str(), "user_agent");
        assert_eq!(SignalType::IpAddress.as_db_str(), "ip_address");
        assert_eq!(SignalType::Crowdsourced.as_db_str(), "crowdsourced");

        assert_eq!(
            SignalType::from_db_str("user_agent"),
            Some(SignalType::UserAgent)
        );
        assert_eq!(
            SignalType::from_db_str("ip_address"),
            Some(SignalType::IpAddress)
        );
        assert_eq!(
            SignalType::from_db_str("crowdsourced"),
            Some(SignalType::Crowdsourced)
        );
        assert_eq!(SignalType::from_db_str("invalid"), None);
    }

    #[test]
    fn test_update_frequency_conversion() {
        assert_eq!(UpdateFrequency::Daily.as_db_str(), "daily");
        assert_eq!(UpdateFrequency::Weekly.as_db_str(), "weekly");
        assert_eq!(UpdateFrequency::Never.as_db_str(), "never");

        assert_eq!(
            UpdateFrequency::from_db_str("daily"),
            Some(UpdateFrequency::Daily)
        );
        assert_eq!(
            UpdateFrequency::from_db_str("weekly"),
            Some(UpdateFrequency::Weekly)
        );
        assert_eq!(
            UpdateFrequency::from_db_str("monthly"),
            Some(UpdateFrequency::Monthly)
        );
        assert_eq!(UpdateFrequency::from_db_str("invalid"), None);
    }

    #[test]
    fn test_default_db_path() {
        let path = default_db_path();
        assert!(path.to_string_lossy().contains("stop-bots"));
        assert!(path.to_string_lossy().contains(DEFAULT_DB_NAME));
    }

    #[test]
    fn test_bot_status_toggle() {
        assert_eq!(BotStatus::Allowed.toggle(), BotStatus::Blocked);
        assert_eq!(BotStatus::Blocked.toggle(), BotStatus::Allowed);
    }

    #[test]
    fn test_bot_status_from_bool() {
        assert_eq!(BotStatus::from(true), BotStatus::Allowed);
        assert_eq!(BotStatus::from(false), BotStatus::Blocked);
    }

    #[test]
    fn test_bool_from_bot_status() {
        assert_eq!(bool::from(BotStatus::Allowed), true);
        assert_eq!(bool::from(BotStatus::Blocked), false);
    }

    #[test]
    fn test_data_source_operations() {
        use crate::source_fetch::KnownSources;

        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();

        // Initialize data sources
        db.initialize_data_sources().unwrap();

        // Get all data sources
        let sources = db.get_all_data_sources().unwrap();
        assert!(!sources.is_empty());

        // Verify we have the expected number of sources
        let known_sources = KnownSources::all();
        assert_eq!(sources.len(), known_sources.len());

        // Verify official sources are marked as official
        let official_sources: Vec<_> = sources.iter().filter(|s| s.is_official).collect();
        assert!(!official_sources.is_empty());

        // Get a specific source
        let googlebot = db.get_data_source("googlebot-official").unwrap();
        assert!(googlebot.is_some());
        assert!(googlebot.unwrap().is_official);

        // Verify non-existent source returns None
        let nonexistent = db.get_data_source("nonexistent").unwrap();
        assert!(nonexistent.is_none());
    }

    #[test]
    fn test_data_source_needs_update() {
        use std::time::{Duration, SystemTime};

        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();

        // Create a data source that was last updated 2 days ago with daily frequency
        let mut source = DataSource {
            id: "test-daily".to_string(),
            name: "Test Daily".to_string(),
            description: "Test source with daily updates".to_string(),
            url: None,
            update_frequency: UpdateFrequency::Daily,
            auto_update_enabled: true,
            last_updated: Some(SystemTime::now() - Duration::from_secs(86400 * 2)), // 2 days ago
            is_official: true,
            data_type: DataSourceType::Combined,
        };

        db.upsert_data_source(&source).unwrap();

        // Should need update (2 days > 1 day)
        assert!(db.data_source_needs_update(&source).unwrap());

        // Update to now - should not need update
        source.last_updated = Some(SystemTime::now());
        db.upsert_data_source(&source).unwrap();
        assert!(!db.data_source_needs_update(&source).unwrap());

        // Test with auto-update disabled
        source.auto_update_enabled = false;
        db.upsert_data_source(&source).unwrap();
        assert!(!db.data_source_needs_update(&source).unwrap());

        // Test with Never frequency
        source.auto_update_enabled = true;
        source.update_frequency = UpdateFrequency::Never;
        db.upsert_data_source(&source).unwrap();
        assert!(!db.data_source_needs_update(&source).unwrap());
    }

    #[test]
    fn test_upsert_bots_from_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();
        db.ensure_categories().unwrap();
        db.ensure_signals().unwrap();
        db.initialize_data_sources().unwrap();

        // Create test bots from a source
        let bots = vec![
            Bot {
                id: None,
                name: "TestBot1".to_string(),
                status: BotStatus::Blocked,
                categories: vec![BotCategory::Scraper],
                user_agent_patterns: vec![],
                ip_ranges: vec![],
                signals: vec![SignalType::UserAgent],
                owner: None,
                owner_id: None,
                notes: Some("Test bot 1".to_string()),
                is_ai_bot: false,
                is_scanner: false,
                source_id: None,
                created_at: None,
                updated_at: None,
            },
            Bot {
                id: None,
                name: "TestBot2".to_string(),
                status: BotStatus::Allowed,
                categories: vec![BotCategory::SearchEngine],
                user_agent_patterns: vec![],
                ip_ranges: vec![],
                signals: vec![SignalType::OfficialSource],
                owner: None,
                owner_id: None,
                notes: Some("Test bot 2".to_string()),
                is_ai_bot: false,
                is_scanner: false,
                source_id: None,
                created_at: None,
                updated_at: None,
            },
        ];

        // Upsert bots from source
        let bot_ids = db.upsert_bots_from_source("test-source", bots).unwrap();
        assert_eq!(bot_ids.len(), 2);

        // Verify bots were inserted
        let all_bots = db.get_all_bots().unwrap();
        assert_eq!(all_bots.len(), 2);

        // Verify source_id was set
        for bot in all_bots {
            assert_eq!(bot.source_id, Some("test-source".to_string()));
        }

        // Verify last_updated was set on source
        let source = db.get_data_source("test-source").unwrap();
        assert!(source.is_some());
        assert!(source.unwrap().last_updated.is_some());
    }

    #[test]
    fn test_delete_bots_from_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();
        db.ensure_categories().unwrap();
        db.ensure_signals().unwrap();
        db.initialize_data_sources().unwrap();

        // Create a bot with a source (use a known source or create it first)
        let bot = Bot {
            id: None,
            name: "TestBot".to_string(),
            status: BotStatus::Blocked,
            categories: vec![BotCategory::Scraper],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: None,
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("googlebot-official".to_string()), // Use a known source
            created_at: None,
            updated_at: None,
        };

        db.upsert_bot(&bot).unwrap();

        // Verify bot exists
        let all_bots = db.get_all_bots().unwrap();
        assert_eq!(all_bots.len(), 1);

        // Delete bots from source
        let deleted = db.delete_bots_from_source("googlebot-official").unwrap();
        assert_eq!(deleted, 1);

        // Verify bot was deleted
        let all_bots = db.get_all_bots().unwrap();
        assert_eq!(all_bots.len(), 0);
    }

    #[test]
    fn test_refresh_bots_from_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();
        db.ensure_categories().unwrap();
        db.ensure_signals().unwrap();

        // Insert initial bots
        let initial_bots = vec![Bot {
            id: None,
            name: "OldBot".to_string(),
            status: BotStatus::Blocked,
            categories: vec![BotCategory::Scraper],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: Some("Old bot".to_string()),
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("refresh-test".to_string()),
            created_at: None,
            updated_at: None,
        }];

        db.upsert_bots_from_source("refresh-test", initial_bots)
            .unwrap();

        // Verify old bot exists
        let all_bots = db.get_all_bots().unwrap();
        assert_eq!(all_bots.len(), 1);
        assert_eq!(all_bots[0].name, "OldBot");

        // Refresh with new bots
        let new_bots = vec![Bot {
            id: None,
            name: "NewBot".to_string(),
            status: BotStatus::Allowed,
            categories: vec![BotCategory::SearchEngine],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: Some("New bot".to_string()),
            is_ai_bot: false,
            is_scanner: false,
            source_id: None,
            created_at: None,
            updated_at: None,
        }];

        db.refresh_bots_from_source("refresh-test", new_bots)
            .unwrap();

        // Verify old bot was replaced
        let all_bots = db.get_all_bots().unwrap();
        assert_eq!(all_bots.len(), 1);
        assert_eq!(all_bots[0].name, "NewBot");
        assert_eq!(all_bots[0].status, BotStatus::Allowed);
    }

    #[test]
    fn test_get_bots_by_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut db = Database::open(temp_file.path()).unwrap();
        db.initialize().unwrap();
        db.ensure_categories().unwrap();
        db.ensure_signals().unwrap();
        db.initialize_data_sources().unwrap();

        // Create the test sources first
        let source1 = DataSource {
            id: "source-1".to_string(),
            name: "Source 1".to_string(),
            description: "Test source 1".to_string(),
            url: None,
            update_frequency: UpdateFrequency::Weekly,
            auto_update_enabled: true,
            last_updated: None,
            is_official: false,
            data_type: DataSourceType::Combined,
        };

        let source2 = DataSource {
            id: "source-2".to_string(),
            name: "Source 2".to_string(),
            description: "Test source 2".to_string(),
            url: None,
            update_frequency: UpdateFrequency::Weekly,
            auto_update_enabled: true,
            last_updated: None,
            is_official: false,
            data_type: DataSourceType::Combined,
        };

        db.upsert_data_source(&source1).unwrap();
        db.upsert_data_source(&source2).unwrap();

        // Insert bots from different sources
        let bot1 = Bot {
            id: None,
            name: "Source1Bot".to_string(),
            status: BotStatus::Blocked,
            categories: vec![BotCategory::Scraper],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: None,
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("source-1".to_string()),
            created_at: None,
            updated_at: None,
        };

        let bot2 = Bot {
            id: None,
            name: "Source2Bot".to_string(),
            status: BotStatus::Allowed,
            categories: vec![BotCategory::SearchEngine],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: None,
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("source-2".to_string()),
            created_at: None,
            updated_at: None,
        };

        let bot3 = Bot {
            id: None,
            name: "Source1Bot2".to_string(),
            status: BotStatus::Blocked,
            categories: vec![BotCategory::AiScraper],
            user_agent_patterns: vec![],
            ip_ranges: vec![],
            signals: vec![],
            owner: None,
            owner_id: None,
            notes: None,
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("source-1".to_string()),
            created_at: None,
            updated_at: None,
        };

        db.upsert_bot(&bot1).unwrap();
        db.upsert_bot(&bot2).unwrap();
        db.upsert_bot(&bot3).unwrap();

        // Get bots from source-1
        let source1_bots = db.get_bots_by_source("source-1").unwrap();
        assert_eq!(source1_bots.len(), 2);
        assert!(source1_bots.iter().any(|b| b.name == "Source1Bot"));
        assert!(source1_bots.iter().any(|b| b.name == "Source1Bot2"));

        // Get bots from source-2
        let source2_bots = db.get_bots_by_source("source-2").unwrap();
        assert_eq!(source2_bots.len(), 1);
        assert_eq!(source2_bots[0].name, "Source2Bot");

        // Get bots from non-existent source
        let nonexistent_bots = db.get_bots_by_source("nonexistent").unwrap();
        assert_eq!(nonexistent_bots.len(), 0);
    }
}
