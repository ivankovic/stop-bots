//! Module for reading and writing NGINX configuration files.
//!
//! This module provides functionality to discover and read NGINX configuration
//! from common system locations, as well as generate bot-blocking configurations.

use anyhow::{Context, Result};
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

/// Common locations where NGINX configuration files might be stored.
/// Ordered by priority (most common first).
const NGINX_CONFIG_PATHS: &[&str] = &[
    // Main configuration file
    "/etc/nginx/nginx.conf",
    "/usr/local/nginx/conf/nginx.conf",
    "/usr/local/etc/nginx/nginx.conf",
    // Additional config directories
    "/etc/nginx/conf.d",
    "/etc/nginx/sites-enabled",
    "/etc/nginx/sites-available",
    "/usr/local/nginx/conf/conf.d",
    // Nginx installed via Homebrew on macOS
    "/opt/homebrew/etc/nginx/nginx.conf",
    "/opt/homebrew/etc/nginx/servers",
];

/// Represents an NGINX configuration file.
#[derive(Debug, Clone)]
pub struct NginxConfig {
    /// Path to the configuration file
    pub path: PathBuf,
    /// Raw content of the configuration file
    #[allow(dead_code)]
    pub content: String,
}

/// Represents a discovered NGINX configuration structure.
#[derive(Debug, Clone)]
pub struct NginxConfigSet {
    /// Main configuration file
    pub main_config: Option<NginxConfig>,
    /// Additional configuration files (from conf.d, sites-enabled, etc.)
    pub additional_configs: Vec<NginxConfig>,
}

impl NginxConfigSet {
    /// Returns all configuration files as a single vector.
    pub fn all_configs(&self) -> Vec<&NginxConfig> {
        let mut all = Vec::new();
        if let Some(ref main) = self.main_config {
            all.push(main);
        }
        all.extend(&self.additional_configs);
        all
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
}

impl IpBlock {
    /// Creates a new IP block.
    pub fn new<S: Into<String>>(address: S) -> Self {
        IpBlock {
            address: address.into(),
        }
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
}

impl UserAgentBlock {
    /// Creates a new user agent block with case-insensitive matching.
    pub fn new<S: Into<String>>(pattern: S) -> Self {
        UserAgentBlock {
            pattern: pattern.into(),
            case_insensitive: true,
        }
    }

    /// Creates a new user agent block with the specified case sensitivity.
    pub fn with_case_sensitivity<S: Into<String>>(pattern: S, case_insensitive: bool) -> Self {
        UserAgentBlock {
            pattern: pattern.into(),
            case_insensitive,
        }
    }
}

/// Represents a country to block using geo-based blocking.
/// Uses ISO 3166-1 alpha-2 country codes (e.g., "CN", "RU", "US").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoBlock {
    /// ISO 3166-1 alpha-2 country code
    pub country_code: String,
}

impl GeoBlock {
    /// Creates a new geo block for the specified country.
    pub fn new<S: Into<String>>(country_code: S) -> Self {
        GeoBlock {
            country_code: country_code.into().to_uppercase(),
        }
    }

    /// Validates that the country code is a valid 2-letter ISO code.
    pub fn is_valid(&self) -> bool {
        self.country_code.len() == 2 && self.country_code.chars().all(|c| c.is_ascii_uppercase())
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
}

impl ScannerBlock {
    /// Creates a new scanner block.
    pub fn new<S: Into<String>>(description: S) -> Self {
        ScannerBlock {
            description: description.into(),
            ips: Vec::new(),
        }
    }

    /// Adds an IP block to this scanner.
    pub fn add_ip(mut self, ip: IpBlock) -> Self {
        self.ips.push(ip);
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
}

impl SearchBot {
    /// Creates a new search bot.
    pub fn new<S: Into<String>>(name: S, user_agent: S) -> Self {
        SearchBot {
            name: name.into(),
            user_agent: user_agent.into(),
            allowed: true,
        }
    }

    /// Sets whether this bot is allowed.
    pub fn with_allowed(mut self, allowed: bool) -> Self {
        self.allowed = allowed;
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
}

impl AiBot {
    /// Creates a new AI bot.
    pub fn new<S: Into<String>>(name: S, user_agent: S) -> Self {
        AiBot {
            name: name.into(),
            user_agent: user_agent.into(),
            ip_ranges: Vec::new(),
        }
    }

    /// Adds an IP range to this AI bot.
    pub fn add_ip_range(mut self, ip_range: IpBlock) -> Self {
        self.ip_ranges.push(ip_range);
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

    /// Generates the complete NGINX configuration for bot protection.
    ///
    /// This generates:
    /// 1. IP deny directives
    /// 2. User agent map and blocking
    /// 3. Geo blocking map and rules
    /// 4. Rate limit zones
    /// 5. Combined blocking logic
    pub fn generate_nginx_config(&self) -> String {
        let mut config = String::new();

        // Add header comment
        config.push_str("# Bot Protection Configuration\n# Generated by stop-bots\n\n");

        // Generate IP blocks
        if !self.ip_blocks.is_empty() {
            config.push_str(&self.generate_ip_blocks());
            config.push('\n');
        }

        // Generate scanner blocks (these are also IP-based)
        if !self.scanner_blocks.is_empty() {
            config.push_str(&self.generate_scanner_blocks());
            config.push('\n');
        }

        // Generate AI bot IP ranges
        if !self.ai_bots.is_empty() {
            config.push_str(&self.generate_ai_bot_ip_blocks());
            config.push('\n');
        }

        // Generate user agent blocks
        if !self.user_agent_blocks.is_empty() {
            config.push_str(&self.generate_user_agent_blocks());
            config.push('\n');
        }

        // Generate AI bot user agent blocks
        if !self.ai_bots.is_empty() {
            config.push_str(&self.generate_ai_bot_ua_blocks());
            config.push('\n');
        }

        // Generate geo blocks
        if !self.geo_blocks.is_empty() {
            config.push_str(&self.generate_geo_blocks());
            config.push('\n');
        }

        // Generate rate limits
        if !self.rate_limits.is_empty() {
            config.push_str(&self.generate_rate_limits());
            config.push('\n');
        }

        // Generate combined blocking logic
        config.push_str(&self.generate_blocking_logic());

        config
    }

    /// Generates nginx config for IP blocks.
    fn generate_ip_blocks(&self) -> String {
        let mut config = String::from("# IP Block List\n");
        for ip_block in &self.ip_blocks {
            config.push_str(&format!("{}\n", ip_block.to_nginx_directive()));
        }
        config
    }

    /// Generates nginx config for scanner blocks.
    fn generate_scanner_blocks(&self) -> String {
        let mut config = String::from("# Scanner IP Blocks\n");
        for scanner in &self.scanner_blocks {
            config.push_str(&format!("# {}\n", scanner.description));
            for ip_block in &scanner.ips {
                config.push_str(&format!("{}\n", ip_block.to_nginx_directive()));
            }
        }
        config
    }

    /// Generates nginx config for AI bot IP ranges.
    fn generate_ai_bot_ip_blocks(&self) -> String {
        let mut config = String::from("# AI Bot IP Ranges\n");
        for bot in &self.ai_bots {
            config.push_str(&format!("# {}\n", bot.name));
            for ip_range in &bot.ip_ranges {
                config.push_str(&format!("{}\n", ip_range.to_nginx_directive()));
            }
        }
        config
    }

    /// Generates nginx config for user agent blocks using map module.
    fn generate_user_agent_blocks(&self) -> String {
        let mut config = String::from("# User Agent Blocking\n");

        // Create a map for user agent blocking
        config.push_str("map $http_user_agent $block_bad_ua {\n");
        config.push_str("    default 0;\n");

        for ua_block in &self.user_agent_blocks {
            let operator = if ua_block.case_insensitive { "~*" } else { "~" };
            config.push_str(&format!("    {} {} 1;\n", operator, ua_block.pattern));
        }

        config.push_str("}\n");
        config
    }

    /// Generates nginx config for AI bot user agent blocks.
    fn generate_ai_bot_ua_blocks(&self) -> String {
        let mut config = String::from("# AI Bot User Agent Blocking\n");

        // Add to the existing user agent map or create a new one
        config.push_str("map $http_user_agent $block_ai_bot {\n");
        config.push_str("    default 0;\n");

        for bot in &self.ai_bots {
            config.push_str(&format!("    ~*{} 1;\n", bot.user_agent));
        }

        config.push_str("}\n");
        config
    }

    /// Generates nginx config for geo blocks.
    fn generate_geo_blocks(&self) -> String {
        let mut config = String::from("# Geo Blocking\n");

        // For geo blocking, we need to use the geo module
        // First, we create a map based on the country codes
        config.push_str("geo $blocked_geo {\n");
        config.push_str("    default 0;\n");

        for geo_block in &self.geo_blocks {
            // In real implementation, you'd map IP ranges to country codes
            // For simplicity, we'll use a variable that would be set by geoip
            config.push_str(&format!("    # {} blocked\n", geo_block.country_code));
        }

        config.push_str("}\n");

        // Add the blocking logic
        config.push_str("map $geoip_country_code $is_blocked_country {\n");
        config.push_str("    default 0;\n");

        for geo_block in &self.geo_blocks {
            config.push_str(&format!("    {} 1;\n", geo_block.country_code));
        }

        config.push_str("}\n");
        config
    }

    /// Generates nginx config for rate limits.
    fn generate_rate_limits(&self) -> String {
        let mut config = String::from("# Rate Limiting\n");

        for rate_limit in &self.rate_limits {
            config.push_str(&format!("{}\n", rate_limit.to_zone_directive()));
        }

        config
    }

    /// Generates the combined blocking logic.
    fn generate_blocking_logic(&self) -> String {
        let mut config = String::from("# Combined Blocking Logic\n");

        config.push_str("# This should be placed in server or location blocks\n");
        config.push_str("# Example usage:\n");
        config.push_str("# server {\n");
        config.push_str("#     # Check all block conditions\n");

        // IP blocks are already handled by deny directives at http/server level

        // User agent blocks
        if !self.user_agent_blocks.is_empty() {
            config.push_str(&format!(
                "#     if ($block_bad_ua) {{ return {}; }}\n",
                self.settings.default_block_response
            ));
        }

        // AI bot user agent blocks
        if !self.ai_bots.is_empty() {
            config.push_str(&format!(
                "#     if ($block_ai_bot) {{ return {}; }}\n",
                self.settings.default_block_response
            ));
        }

        // Geo blocks
        if !self.geo_blocks.is_empty() {
            config.push_str(&format!(
                "#     if ($is_blocked_country) {{ return {}; }}\n",
                self.settings.default_block_response
            ));
        }

        // Rate limits
        if !self.rate_limits.is_empty() {
            for rate_limit in &self.rate_limits {
                config.push_str(&format!(
                    "#     limit_req {};\n",
                    rate_limit.to_request_directive()
                ));
            }
        }

        config.push_str("# }\n");
        config
    }
}

/// Discovers NGINX configuration files from common system locations.
///
/// Returns a [`NginxConfigSet`] containing the main configuration file
/// and any additional configuration files found.
pub fn discover_nginx_configs() -> Result<NginxConfigSet> {
    let mut main_config: Option<NginxConfig> = None;
    let mut additional_configs: Vec<NginxConfig> = Vec::new();

    for path_str in NGINX_CONFIG_PATHS {
        let path = Path::new(path_str);

        if path.exists() {
            if path.is_file() {
                // This is likely a main config or a single config file
                if main_config.is_none() {
                    // Use the first file found as the main config
                    if let Ok(config) = read_config_file(path) {
                        main_config = Some(config);
                    }
                }
            } else if path.is_dir() {
                // This is a directory containing config files
                for entry in WalkDir::new(path)
                    .follow_links(true)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                {
                    // Skip hidden files and common non-config files
                    let file_name = entry.file_name().to_string_lossy();
                    if file_name.starts_with('.') || file_name.ends_with('~') {
                        continue;
                    }

                    if let Ok(config) = read_config_file(entry.path()) {
                        // If we haven't found a main config yet and this looks like one,
                        // use it as main config
                        if main_config.is_none()
                            && (file_name == "nginx.conf" || file_name.ends_with(".conf"))
                        {
                            main_config = Some(config.clone());
                        } else {
                            additional_configs.push(config);
                        }
                    }
                }
            }
        }
    }

    Ok(NginxConfigSet {
        main_config,
        additional_configs,
    })
}

/// Reads a single NGINX configuration file from the given path.
///
/// # Arguments
///
/// * `path` - Path to the NGINX configuration file
///
/// # Returns
///
/// A [`NginxConfig`] struct containing the path and content of the file.
pub fn read_config_file<P: AsRef<Path>>(path: P) -> Result<NginxConfig> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read NGINX config file: {}", path.display()))?;

    Ok(NginxConfig {
        path: path.to_path_buf(),
        content,
    })
}

/// Checks if NGINX is installed on the system.
///
/// This is a simple check that looks for the nginx binary in common locations
/// or checks if any of the common config paths exist.
pub fn is_nginx_installed() -> bool {
    // Check for nginx binary
    let binary_exists = std::process::Command::new("which")
        .arg("nginx")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if binary_exists {
        return true;
    }

    // Check if any config paths exist
    NGINX_CONFIG_PATHS
        .iter()
        .any(|path| Path::new(path).exists())
}

/// Returns the default NGINX configuration file path.
///
/// This returns the most common path for NGINX configuration.
/// Use [`discover_nginx_configs`] for automatic discovery.
#[allow(dead_code)]
pub fn default_config_path() -> &'static str {
    "/etc/nginx/nginx.conf"
}

/// Returns all common NGINX configuration paths.
pub fn common_config_paths() -> &'static [&'static str] {
    NGINX_CONFIG_PATHS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_config_file() {
        // Create a temporary file with some content
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "server {{").unwrap();
        writeln!(file, "    listen 80;").unwrap();
        writeln!(file, "}}").unwrap();

        let path = file.path();
        let config = read_config_file(path).unwrap();

        assert_eq!(config.path, path);
        assert!(config.content.contains("server {"));
        assert!(config.content.contains("listen 80"));
    }

    #[test]
    fn test_read_nonexistent_file() {
        let result = read_config_file("/nonexistent/path/nginx.conf");
        assert!(result.is_err());
    }

    #[test]
    fn test_common_config_paths() {
        let paths = common_config_paths();
        assert!(!paths.is_empty());
        assert!(paths.contains(&"/etc/nginx/nginx.conf"));
    }

    #[test]
    fn test_default_config_path() {
        assert_eq!(default_config_path(), "/etc/nginx/nginx.conf");
    }

    #[test]
    fn test_config_set_all_configs() {
        let main_config = NginxConfig {
            path: PathBuf::from("/etc/nginx/nginx.conf"),
            content: String::from("main config"),
        };

        let additional = vec![
            NginxConfig {
                path: PathBuf::from("/etc/nginx/conf.d/server.conf"),
                content: String::from("server config"),
            },
            NginxConfig {
                path: PathBuf::from("/etc/nginx/sites-enabled/site.conf"),
                content: String::from("site config"),
            },
        ];

        let config_set = NginxConfigSet {
            main_config: Some(main_config),
            additional_configs: additional,
        };

        let all = config_set.all_configs();
        assert_eq!(all.len(), 3);
        assert!(all[0].path.to_string_lossy().contains("nginx.conf"));
    }

    // ========================================================================
    // Bot Blocking Tests
    // ========================================================================

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
        let bot = SearchBot::new("Googlebot", "Googlebot").with_allowed(true);

        assert_eq!(bot.name, "Googlebot");
        assert!(bot.allowed);
    }

    #[test]
    fn test_ai_bot() {
        let bot = AiBot::new("GPTBot", "GPTBot").add_ip_range(IpBlock::new("1.2.3.0/24"));

        assert_eq!(bot.name, "GPTBot");
        assert_eq!(bot.ip_ranges.len(), 1);
    }

    #[test]
    fn test_block_response() {
        assert_eq!(BlockResponse::Return403.to_nginx_return(), "return 403;");
        assert_eq!(BlockResponse::Return404.to_nginx_return(), "return 404;");
        assert_eq!(BlockResponse::Return444.to_nginx_return(), "return 444;");
    }

    #[test]
    fn test_bot_protection_config_empty() {
        let config = BotProtectionConfig::new();
        let generated = config.generate_nginx_config();

        assert!(generated.contains("Bot Protection Configuration"));
        assert!(generated.contains("Generated by stop-bots"));
    }

    #[test]
    fn test_bot_protection_config_with_ip_blocks() {
        let config = BotProtectionConfig::new()
            .add_ip_block(IpBlock::new("1.2.3.4"))
            .add_ip_block(IpBlock::new("5.6.7.8/24"));

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# IP Block List"));
        assert!(generated.contains("deny 1.2.3.4;"));
        assert!(generated.contains("deny 5.6.7.8/24;"));
    }

    #[test]
    fn test_bot_protection_config_with_user_agent_blocks() {
        let config = BotProtectionConfig::new()
            .add_user_agent_block(UserAgentBlock::new("BadBot"))
            .add_user_agent_block(UserAgentBlock::new("Scraper"));

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# User Agent Blocking"));
        assert!(generated.contains("map $http_user_agent $block_bad_ua"));
        // Check that the patterns appear in the config
        assert!(generated.contains("BadBot"));
        assert!(generated.contains("Scraper"));
        // Check that the map structure is correct
        assert!(generated.contains("default 0;"));
        assert!(generated.contains("~*"));
    }

    #[test]
    fn test_bot_protection_config_with_geo_blocks() {
        let config = BotProtectionConfig::new()
            .add_geo_block(GeoBlock::new("CN"))
            .add_geo_block(GeoBlock::new("RU"));

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# Geo Blocking"));
        assert!(generated.contains("CN"));
        assert!(generated.contains("RU"));
    }

    #[test]
    fn test_bot_protection_config_with_rate_limits() {
        let config =
            BotProtectionConfig::new().add_rate_limit(RateLimit::new("scanner", "10m", "10r/s"));

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# Rate Limiting"));
        assert!(generated.contains("limit_req_zone"));
    }

    #[test]
    fn test_bot_protection_config_with_scanner_blocks() {
        let scanner = ScannerBlock::new("Test Scanner").add_ip(IpBlock::new("1.2.3.4"));

        let config = BotProtectionConfig::new().add_scanner_block(scanner);

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# Scanner IP Blocks"));
        assert!(generated.contains("Test Scanner"));
        assert!(generated.contains("deny 1.2.3.4;"));
    }

    #[test]
    fn test_bot_protection_config_with_ai_bots() {
        let bot = AiBot::new("GPTBot", "GPTBot").add_ip_range(IpBlock::new("1.2.3.0/24"));

        let config = BotProtectionConfig::new().add_ai_bot(bot);

        let generated = config.generate_nginx_config();

        assert!(generated.contains("# AI Bot IP Ranges"));
        assert!(generated.contains("# AI Bot User Agent Blocking"));
        assert!(generated.contains("GPTBot"));
    }

    #[test]
    fn test_bot_protection_settings() {
        let settings = BotProtectionSettings {
            enabled: true,
            default_block_response: BlockResponse::Return403,
        };

        let config = BotProtectionConfig {
            settings,
            ..BotProtectionConfig::default()
        }
        .add_user_agent_block(UserAgentBlock::new("BadBot"));

        let generated = config.generate_nginx_config();

        assert!(generated.contains("return 403;"));
    }

    #[test]
    fn test_bot_protection_config_full() {
        let config = BotProtectionConfig::new()
            .add_ip_block(IpBlock::new("1.2.3.4"))
            .add_user_agent_block(UserAgentBlock::new("BadBot"))
            .add_geo_block(GeoBlock::new("CN"))
            .add_rate_limit(RateLimit::new("scanner", "10m", "10r/s"))
            .add_scanner_block(ScannerBlock::new("Scanner").add_ip(IpBlock::new("5.6.7.8")))
            .add_ai_bot(AiBot::new("GPTBot", "GPTBot"));

        let generated = config.generate_nginx_config();

        // Check that all sections are present
        assert!(generated.contains("# IP Block List"));
        assert!(generated.contains("# User Agent Blocking"));
        assert!(generated.contains("# Geo Blocking"));
        assert!(generated.contains("# Rate Limiting"));
        assert!(generated.contains("# Scanner IP Blocks"));
        assert!(generated.contains("# AI Bot"));
        assert!(generated.contains("# Combined Blocking Logic"));
    }
}
