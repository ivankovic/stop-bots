//! Bot definitions and configuration for the stop-bots application.
//!
//! This module contains all data structures related to bots, their categorization,
//! blocking rules, and configuration. It is separate from the nginx-specific code
//! to allow for potential future support of other web servers.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

// ============================================================================
// Bot Categories and Signals
// ============================================================================

/// Category of a bot for organization and filtering purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BotCategory {
    /// Scanners that probe for vulnerabilities
    Scanner,
    /// Search engine crawlers (Googlebot, Bingbot, etc.)
    #[default]
    SearchEngine,
    /// AI bots and scrapers (GPTBot, CCBot, etc.)
    AiScraper,
    /// Content scrapers and data harvesters
    Scraper,
    /// Security scanners and vulnerability testers
    SecurityScanner,
    /// Ad bots and click fraud
    AdBot,
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
            BotCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Signal that triggered a bot to be blocked or flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotSignal {
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
    /// Bot identified by behavior analysis
    Behavioral,
    /// Bot manually reported by user
    ManualReport,
}

/// Owner or organization associated with a bot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotOwner {
    /// Name of the owner/organization
    pub name: String,
    /// Website URL of the owner
    pub website: Option<String>,
    /// Contact email for the owner
    pub contact: Option<String>,
}

impl BotOwner {
    /// Creates a new bot owner with just a name.
    pub fn new<N: Into<String>>(name: N) -> Self {
        BotOwner {
            name: name.into(),
            website: None,
            contact: None,
        }
    }

    /// Sets the website URL.
    pub fn with_website<N: Into<String>>(mut self, website: N) -> Self {
        self.website = Some(website.into());
        self
    }

    /// Sets the contact email.
    pub fn with_contact<N: Into<String>>(mut self, contact: N) -> Self {
        self.contact = Some(contact.into());
        self
    }
}

// ============================================================================
// Bot Blocking Configuration
// ============================================================================

/// Represents a single IP address or CIDR range to block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBlock {
    /// The IP address or CIDR notation (e.g., "1.2.3.4" or "1.2.3.0/24")
    pub address: String,
    /// Optional description of what this IP block is for
    pub description: Option<String>,
    /// Category of bots this IP block targets
    pub category: Option<BotCategory>,
}

impl IpBlock {
    /// Creates a new IP block.
    pub fn new<S: Into<String>>(address: S) -> Self {
        IpBlock {
            address: address.into(),
            description: None,
            category: None,
        }
    }

    /// Creates a new IP block with a description.
    pub fn with_description<S: Into<String>>(address: S, description: S) -> Self {
        IpBlock {
            address: address.into(),
            description: Some(description.into()),
            category: None,
        }
    }

    /// Sets the description.
    pub fn description<S: Into<String>>(mut self, description: S) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the category.
    pub fn category(mut self, category: BotCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Validates that the address is a valid IP or CIDR.
    /// Note: CIDR validation is simplified and may not catch all invalid formats.
    pub fn is_valid(&self) -> bool {
        // Try as single IP first
        if IpAddr::from_str(&self.address).is_ok() {
            return true;
        }

        // For CIDR, do basic validation (contains / and has valid parts)
        if self.address.contains('/') {
            let parts: Vec<&str> = self.address.split('/').collect();
            if parts.len() == 2 {
                // Validate the IP part
                if IpAddr::from_str(parts[0]).is_ok() {
                    // Validate the prefix part (0-32 for IPv4, 0-128 for IPv6)
                    if let Ok(prefix) = parts[1].parse::<u32>() {
                        return prefix <= 128; // Max prefix for IPv6
                    }
                }
            }
        }
        false
    }

    /// Generates the nginx deny directive for this IP block.
    pub fn to_nginx_directive(&self) -> String {
        format!("deny {};", self.address)
    }
}

/// Represents a user agent pattern to block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentBlock {
    /// Regex pattern to match against the User-Agent header
    pub pattern: String,
    /// Whether the pattern is case-insensitive (uses ~* vs ~ in nginx)
    pub case_insensitive: bool,
    /// Optional description of what this pattern matches
    pub description: Option<String>,
    /// Category of bots this pattern targets
    pub category: Option<BotCategory>,
}

impl UserAgentBlock {
    /// Creates a new user agent block with case-insensitive matching.
    pub fn new<S: Into<String>>(pattern: S) -> Self {
        UserAgentBlock {
            pattern: pattern.into(),
            case_insensitive: true,
            description: None,
            category: None,
        }
    }

    /// Creates a new user agent block with the specified case sensitivity.
    pub fn with_case_sensitivity<S: Into<String>>(pattern: S, case_insensitive: bool) -> Self {
        UserAgentBlock {
            pattern: pattern.into(),
            case_insensitive,
            description: None,
            category: None,
        }
    }

    /// Sets the description.
    pub fn description<S: Into<String>>(mut self, description: S) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the category.
    pub fn category(mut self, category: BotCategory) -> Self {
        self.category = Some(category);
        self
    }
}

/// Represents a country to block using geo-based blocking.
/// Uses ISO 3166-1 alpha-2 country codes (e.g., "CN", "RU", "US").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoBlock {
    /// ISO 3166-1 alpha-2 country code
    pub country_code: String,
    /// Optional description/reason for blocking
    pub description: Option<String>,
}

impl GeoBlock {
    /// Creates a new geo block for the specified country.
    pub fn new<S: Into<String>>(country_code: S) -> Self {
        GeoBlock {
            country_code: country_code.into().to_uppercase(),
            description: None,
        }
    }

    /// Sets the description.
    pub fn description<S: Into<String>>(mut self, description: S) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Validates that the country code is a valid 2-letter ISO code.
    pub fn is_valid(&self) -> bool {
        self.country_code.len() == 2
            && self
                .country_code
                .chars()
                .all(|c| c.is_ascii_uppercase())
    }
}

/// Represents a rate limit configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimit {
    /// Name of the rate limit zone
    pub zone_name: String,
    /// Memory size for the zone (e.g., "10m" for 10 megabytes)
    pub zone_size: String,
    /// Rate limit (e.g., "10r/s" for 10 requests per second)
    pub rate: String,
    /// Burst size (number of requests that can exceed the rate)
    pub burst: Option<u32>,
    /// Whether to delay excess requests or reject them immediately
    pub nodelay: bool,
    /// Optional description of what this rate limit is for
    pub description: Option<String>,
}

impl RateLimit {
    /// Creates a new rate limit with default settings.
    pub fn new<S: Into<String>>(zone_name: S, zone_size: S, rate: S) -> Self {
        RateLimit {
            zone_name: zone_name.into(),
            zone_size: zone_size.into(),
            rate: rate.into(),
            burst: None,
            nodelay: false,
            description: None,
        }
    }

    /// Sets the burst size.
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = Some(burst);
        self
    }

    /// Sets whether to use nodelay.
    pub fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Sets the description.
    pub fn description<S: Into<String>>(mut self, description: S) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Generates the nginx limit_req_zone directive.
    pub fn to_zone_directive(&self) -> String {
        format!(
            "limit_req_zone $binary_remote_addr zone={}:{} rate={};",
            self.zone_name, self.zone_size, self.rate
        )
    }

    /// Generates the nginx limit_req directive.
    pub fn to_request_directive(&self) -> String {
        let mut directive = format!("limit_req zone={}", self.zone_name);

        if let Some(burst) = self.burst {
            directive.push_str(&format!(" burst={}", burst));
        }

        if self.nodelay {
            directive.push_str(" nodelay");
        }

        directive.push(';');
        directive
    }
}

/// Represents a bot scanner to block (IPs that scan for vulnerabilities).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerBlock {
    /// Description of the scanner
    pub description: String,
    /// IP addresses associated with this scanner
    pub ips: Vec<IpBlock>,
    /// Signals that identified this scanner
    pub signals: Vec<BotSignal>,
    /// Owner information if known
    pub owner: Option<BotOwner>,
}

impl ScannerBlock {
    /// Creates a new scanner block.
    pub fn new<S: Into<String>>(description: S) -> Self {
        ScannerBlock {
            description: description.into(),
            ips: Vec::new(),
            signals: Vec::new(),
            owner: None,
        }
    }

    /// Adds an IP block to this scanner.
    pub fn add_ip(mut self, ip: IpBlock) -> Self {
        self.ips.push(ip);
        self
    }

    /// Adds a signal to this scanner.
    pub fn add_signal(mut self, signal: BotSignal) -> Self {
        self.signals.push(signal);
        self
    }

    /// Sets the owner.
    pub fn with_owner(mut self, owner: BotOwner) -> Self {
        self.owner = Some(owner);
        self
    }
}

/// Represents a search engine bot that may be allowed or blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchBot {
    /// Name of the search bot (e.g., "Googlebot", "Bingbot")
    pub name: String,
    /// User agent string pattern
    pub user_agent: String,
    /// Whether this bot is currently allowed
    pub allowed: bool,
    /// Known IP ranges for this bot
    pub ip_ranges: Vec<IpBlock>,
    /// Owner information
    pub owner: Option<BotOwner>,
}

impl SearchBot {
    /// Creates a new search bot.
    pub fn new<S: Into<String>>(name: S, user_agent: S) -> Self {
        SearchBot {
            name: name.into(),
            user_agent: user_agent.into(),
            allowed: true,
            ip_ranges: Vec::new(),
            owner: None,
        }
    }

    /// Sets whether this bot is allowed.
    pub fn with_allowed(mut self, allowed: bool) -> Self {
        self.allowed = allowed;
        self
    }

    /// Adds an IP range to this bot.
    pub fn add_ip_range(mut self, ip_range: IpBlock) -> Self {
        self.ip_ranges.push(ip_range);
        self
    }

    /// Sets the owner.
    pub fn with_owner(mut self, owner: BotOwner) -> Self {
        self.owner = Some(owner);
        self
    }
}

/// Represents an AI bot/scraper that should be blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiBot {
    /// Name of the AI bot (e.g., "GPTBot", "CCBot")
    pub name: String,
    /// User agent string pattern
    pub user_agent: String,
    /// IP ranges associated with this bot
    pub ip_ranges: Vec<IpBlock>,
    /// Owner information
    pub owner: Option<BotOwner>,
    /// Category of this AI bot
    pub category: BotCategory,
    /// Signals that identified this bot
    pub signals: Vec<BotSignal>,
}

impl AiBot {
    /// Creates a new AI bot.
    pub fn new<S: Into<String>>(name: S, user_agent: S) -> Self {
        AiBot {
            name: name.into(),
            user_agent: user_agent.into(),
            ip_ranges: Vec::new(),
            owner: None,
            category: BotCategory::AiScraper,
            signals: Vec::new(),
        }
    }

    /// Adds an IP range to this AI bot.
    pub fn add_ip_range(mut self, ip_range: IpBlock) -> Self {
        self.ip_ranges.push(ip_range);
        self
    }

    /// Sets the owner.
    pub fn with_owner(mut self, owner: BotOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the category.
    pub fn with_category(mut self, category: BotCategory) -> Self {
        self.category = category;
        self
    }

    /// Adds a signal.
    pub fn add_signal(mut self, signal: BotSignal) -> Self {
        self.signals.push(signal);
        self
    }
}

/// Global settings for bot protection.
#[derive(Debug, Clone, PartialEq)]
pub struct BotProtectionSettings {
    /// Whether bot protection is enabled
    pub enabled: bool,
    /// Default action for blocked requests: 403, 404, or 444
    pub default_block_response: BlockResponse,
}

impl Default for BotProtectionSettings {
    fn default() -> Self {
        BotProtectionSettings {
            enabled: true,
            default_block_response: BlockResponse::Return444,
        }
    }
}

/// The HTTP response to return when blocking a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockResponse {
    /// Return 403 Forbidden
    Return403,
    /// Return 404 Not Found (cloak the fact that we're blocking)
    Return404,
    /// Return 444 No Response (nginx-specific, closes connection immediately)
    /// This is the most performant option as it sends no response at all.
    Return444,
}

impl fmt::Display for BlockResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockResponse::Return403 => write!(f, "403"),
            BlockResponse::Return404 => write!(f, "404"),
            BlockResponse::Return444 => write!(f, "444"),
        }
    }
}

impl BlockResponse {
    /// Returns the nginx directive for this block response.
    pub fn to_nginx_return(self) -> String {
        match self {
            BlockResponse::Return403 => "return 403;".to_string(),
            BlockResponse::Return404 => "return 404;".to_string(),
            BlockResponse::Return444 => "return 444;".to_string(),
        }
    }
}

/// Represents the complete bot protection configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BotProtectionConfig {
    /// Global settings
    pub settings: BotProtectionSettings,
    /// IP addresses and ranges to block
    pub ip_blocks: Vec<IpBlock>,
    /// User agent patterns to block
    pub user_agent_blocks: Vec<UserAgentBlock>,
    /// Countries to block (by ISO 3166-1 alpha-2 code)
    pub geo_blocks: Vec<GeoBlock>,
    /// Scanner IPs to block
    pub scanner_blocks: Vec<ScannerBlock>,
    /// Search bots and their status
    pub search_bots: Vec<SearchBot>,
    /// AI bots to block
    pub ai_bots: Vec<AiBot>,
    /// Rate limit configurations
    pub rate_limits: Vec<RateLimit>,
}

impl BotProtectionConfig {
    /// Creates a new empty bot protection configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an IP block.
    pub fn add_ip_block(mut self, ip_block: IpBlock) -> Self {
        self.ip_blocks.push(ip_block);
        self
    }

    /// Adds a user agent block.
    pub fn add_user_agent_block(mut self, ua_block: UserAgentBlock) -> Self {
        self.user_agent_blocks.push(ua_block);
        self
    }

    /// Adds a geo block.
    pub fn add_geo_block(mut self, geo_block: GeoBlock) -> Self {
        self.geo_blocks.push(geo_block);
        self
    }

    /// Adds a scanner block.
    pub fn add_scanner_block(mut self, scanner: ScannerBlock) -> Self {
        self.scanner_blocks.push(scanner);
        self
    }

    /// Adds a search bot.
    pub fn add_search_bot(mut self, bot: SearchBot) -> Self {
        self.search_bots.push(bot);
        self
    }

    /// Adds an AI bot.
    pub fn add_ai_bot(mut self, bot: AiBot) -> Self {
        self.ai_bots.push(bot);
        self
    }

    /// Adds a rate limit.
    pub fn add_rate_limit(mut self, rate_limit: RateLimit) -> Self {
        self.rate_limits.push(rate_limit);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_block_creation() {
        let ip_block = IpBlock::new("1.2.3.4");
        assert_eq!(ip_block.address, "1.2.3.4");
        assert!(ip_block.is_valid());
        assert_eq!(ip_block.to_nginx_directive(), "deny 1.2.3.4;");
    }

    #[test]
    fn test_ip_block_cidr() {
        let ip_block = IpBlock::new("192.168.1.0/24");
        assert!(ip_block.is_valid());
        assert_eq!(ip_block.to_nginx_directive(), "deny 192.168.1.0/24;");
    }

    #[test]
    fn test_ip_block_invalid() {
        let ip_block = IpBlock::new("invalid");
        assert!(!ip_block.is_valid());
    }

    #[test]
    fn test_user_agent_block() {
        let ua_block = UserAgentBlock::new("BadBot");
        assert_eq!(ua_block.pattern, "BadBot");
        assert!(ua_block.case_insensitive);

        let ua_block_case = UserAgentBlock::with_case_sensitivity("BadBot", false);
        assert!(!ua_block_case.case_insensitive);
    }

    #[test]
    fn test_geo_block() {
        let geo_block = GeoBlock::new("cn");
        assert_eq!(geo_block.country_code, "CN");
        assert!(geo_block.is_valid());

        let geo_block_invalid = GeoBlock::new("XXX");
        assert!(!geo_block_invalid.is_valid());
    }

    #[test]
    fn test_rate_limit() {
        let rate_limit = RateLimit::new("scanner", "10m", "10r/s");
        assert_eq!(rate_limit.zone_name, "scanner");
        assert_eq!(rate_limit.zone_size, "10m");
        assert_eq!(rate_limit.rate, "10r/s");
        assert!(!rate_limit.nodelay);

        let zone_directive = rate_limit.to_zone_directive();
        assert!(zone_directive.contains("limit_req_zone"));
        assert!(zone_directive.contains("zone=scanner:10m"));
        assert!(zone_directive.contains("rate=10r/s"));

        let request_directive = rate_limit.to_request_directive();
        assert!(request_directive.contains("limit_req zone=scanner"));
    }

    #[test]
    fn test_rate_limit_with_burst() {
        let rate_limit = RateLimit::new("api", "10m", "100r/m")
            .with_burst(50)
            .with_nodelay(true);

        let request_directive = rate_limit.to_request_directive();
        assert!(request_directive.contains("burst=50"));
        assert!(request_directive.contains("nodelay"));
    }

    #[test]
    fn test_scanner_block() {
        let scanner = ScannerBlock::new("Test Scanner")
            .add_ip(IpBlock::new("1.2.3.4"))
            .add_ip(IpBlock::new("5.6.7.8"));

        assert_eq!(scanner.description, "Test Scanner");
        assert_eq!(scanner.ips.len(), 2);
    }

    #[test]
    fn test_search_bot() {
        let bot = SearchBot::new("Googlebot", "Googlebot")
            .with_allowed(true);

        assert_eq!(bot.name, "Googlebot");
        assert!(bot.allowed);
    }

    #[test]
    fn test_ai_bot() {
        let bot = AiBot::new("GPTBot", "GPTBot")
            .add_ip_range(IpBlock::new("1.2.3.0/24"));

        assert_eq!(bot.name, "GPTBot");
        assert_eq!(bot.ip_ranges.len(), 1);
    }

    #[test]
    fn test_block_response() {
        assert_eq!(
            BlockResponse::Return403.to_nginx_return(),
            "return 403;"
        );
        assert_eq!(
            BlockResponse::Return404.to_nginx_return(),
            "return 404;"
        );
        assert_eq!(
            BlockResponse::Return444.to_nginx_return(),
            "return 444;"
        );
    }

    #[test]
    fn test_bot_protection_config_empty() {
        let config = BotProtectionConfig::new();
        assert!(config.ip_blocks.is_empty());
        assert!(config.user_agent_blocks.is_empty());
        assert!(config.geo_blocks.is_empty());
        assert!(config.scanner_blocks.is_empty());
        assert!(config.search_bots.is_empty());
        assert!(config.ai_bots.is_empty());
        assert!(config.rate_limits.is_empty());
    }

    #[test]
    fn test_bot_protection_config_builder() {
        let config = BotProtectionConfig::new()
            .add_ip_block(IpBlock::new("1.2.3.4"))
            .add_user_agent_block(UserAgentBlock::new("BadBot"))
            .add_geo_block(GeoBlock::new("CN"))
            .add_scanner_block(ScannerBlock::new("Scanner").add_ip(IpBlock::new("5.6.7.8")))
            .add_search_bot(SearchBot::new("Googlebot", "Googlebot"))
            .add_ai_bot(AiBot::new("GPTBot", "GPTBot"))
            .add_rate_limit(RateLimit::new("scanner", "10m", "10r/s"));

        assert_eq!(config.ip_blocks.len(), 1);
        assert_eq!(config.user_agent_blocks.len(), 1);
        assert_eq!(config.geo_blocks.len(), 1);
        assert_eq!(config.scanner_blocks.len(), 1);
        assert_eq!(config.search_bots.len(), 1);
        assert_eq!(config.ai_bots.len(), 1);
        assert_eq!(config.rate_limits.len(), 1);
    }

    #[test]
    fn test_bot_category_display() {
        assert_eq!(format!("{}", BotCategory::Scanner), "Scanner");
        assert_eq!(format!("{}", BotCategory::SearchEngine), "Search Engine");
        assert_eq!(format!("{}", BotCategory::AiScraper), "AI Scraper");
    }

    #[test]
    fn test_bot_owner() {
        let owner = BotOwner::new("Google")
            .with_website("https://google.com")
            .with_contact("abuse@google.com");

        assert_eq!(owner.name, "Google");
        assert_eq!(owner.website, Some("https://google.com".to_string()));
        assert_eq!(owner.contact, Some("abuse@google.com".to_string()));
    }
}
