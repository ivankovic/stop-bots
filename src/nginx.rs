//! Module for reading and writing NGINX configuration files.
//!
//! This module provides functionality to discover and read NGINX configuration
//! from common system locations, as well as generate NGINX configurations for
//! bot protection using bot definitions from the `bots` module.

// Import bot types from the bots module
// These are used for generating nginx configuration from bot protection config
use crate::bots::{AiBot, BotProtectionConfig, GeoBlock, IpBlock, RateLimit, ScannerBlock, UserAgentBlock};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ============================================================================
// NGINX Configuration Reading
// ============================================================================

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

// ============================================================================
// NGINX Configuration Generation for Bot Protection
// ============================================================================

/// Generates NGINX configuration for bot protection from a BotProtectionConfig.
///
/// This generates a complete NGINX configuration snippet that can be included
/// in nginx.conf or a separate file in conf.d/.
pub fn generate_bot_protection_config(config: &BotProtectionConfig) -> String {
    let mut nginx_config = String::new();

    // Add header comment
    nginx_config.push_str("# Bot Protection Configuration\n# Generated by stop-bots\n\n");

    // Generate IP blocks
    if !config.ip_blocks.is_empty() {
        nginx_config.push_str(&generate_ip_blocks(&config.ip_blocks));
        nginx_config.push('\n');
    }

    // Generate scanner blocks (these are also IP-based)
    if !config.scanner_blocks.is_empty() {
        nginx_config.push_str(&generate_scanner_blocks(&config.scanner_blocks));
        nginx_config.push('\n');
    }

    // Generate AI bot IP ranges
    if !config.ai_bots.is_empty() {
        nginx_config.push_str(&generate_ai_bot_ip_blocks(&config.ai_bots));
        nginx_config.push('\n');
    }

    // Generate user agent blocks
    if !config.user_agent_blocks.is_empty() {
        nginx_config.push_str(&generate_user_agent_blocks(&config.user_agent_blocks));
        nginx_config.push('\n');
    }

    // Generate AI bot user agent blocks
    if !config.ai_bots.is_empty() {
        nginx_config.push_str(&generate_ai_bot_ua_blocks(&config.ai_bots));
        nginx_config.push('\n');
    }

    // Generate geo blocks
    if !config.geo_blocks.is_empty() {
        nginx_config.push_str(&generate_geo_blocks(&config.geo_blocks));
        nginx_config.push('\n');
    }

    // Generate rate limits
    if !config.rate_limits.is_empty() {
        nginx_config.push_str(&generate_rate_limits(&config.rate_limits));
        nginx_config.push('\n');
    }

    // Generate combined blocking logic
    nginx_config.push_str(&generate_blocking_logic(config));

    nginx_config
}

/// Generates nginx config for IP blocks.
fn generate_ip_blocks(ip_blocks: &[IpBlock]) -> String {
    let mut config = String::from("# IP Block List\n");
    for ip_block in ip_blocks {
        if let Some(ref desc) = ip_block.description {
            config.push_str(&format!("# {}\n", desc));
        }
        config.push_str(&format!("{}\n", ip_block.to_nginx_directive()));
    }
    config
}

/// Generates nginx config for scanner blocks.
fn generate_scanner_blocks(scanner_blocks: &[ScannerBlock]) -> String {
    let mut config = String::from("# Scanner IP Blocks\n");
    for scanner in scanner_blocks {
        config.push_str(&format!("# {}\n", scanner.description));
        for ip_block in &scanner.ips {
            if let Some(ref desc) = ip_block.description {
                config.push_str(&format!("#   {}\n", desc));
            }
            config.push_str(&format!("{}\n", ip_block.to_nginx_directive()));
        }
    }
    config
}

/// Generates nginx config for AI bot IP ranges.
fn generate_ai_bot_ip_blocks(ai_bots: &[AiBot]) -> String {
    let mut config = String::from("# AI Bot IP Ranges\n");
    for bot in ai_bots {
        config.push_str(&format!("# {}\n", bot.name));
        for ip_range in &bot.ip_ranges {
            if let Some(ref desc) = ip_range.description {
                config.push_str(&format!("#   {}\n", desc));
            }
            config.push_str(&format!("{}\n", ip_range.to_nginx_directive()));
        }
    }
    config
}

/// Generates nginx config for user agent blocks using map module.
fn generate_user_agent_blocks(user_agent_blocks: &[UserAgentBlock]) -> String {
    let mut config = String::from("# User Agent Blocking\n");

    // Create a map for user agent blocking
    config.push_str("map $http_user_agent $block_bad_ua {\n");
    config.push_str("    default 0;\n");

    for ua_block in user_agent_blocks {
        let operator = if ua_block.case_insensitive {
            "~*"
        } else {
            "~"
        };
        if let Some(ref desc) = ua_block.description {
            config.push_str(&format!("    # {}\n", desc));
        }
        config.push_str(&format!(
            "    {} {} 1;\n",
            operator, ua_block.pattern
        ));
    }

    config.push_str("}\n");
    config
}

/// Generates nginx config for AI bot user agent blocks.
fn generate_ai_bot_ua_blocks(ai_bots: &[AiBot]) -> String {
    let mut config = String::from("# AI Bot User Agent Blocking\n");

    // Add to the existing user agent map or create a new one
    config.push_str("map $http_user_agent $block_ai_bot {\n");
    config.push_str("    default 0;\n");

    for bot in ai_bots {
        config.push_str(&format!("    # {}\n", bot.name));
        config.push_str(&format!("    ~*{} 1;\n", bot.user_agent));
    }

    config.push_str("}\n");
    config
}

/// Generates nginx config for geo blocks.
fn generate_geo_blocks(geo_blocks: &[GeoBlock]) -> String {
    let mut config = String::from("# Geo Blocking\n");

        // For geo blocking, we need to use the geo module
        // First, we create a map based on the country codes
        config.push_str("geo $blocked_geo {\n");
        config.push_str("    default 0;\n");

        for geo_block in geo_blocks {
            if let Some(ref desc) = geo_block.description {
                config.push_str(&format!("    # {}\n", desc));
            }
            // In real implementation, you'd map IP ranges to country codes
            // For simplicity, we'll use a variable that would be set by geoip
            config.push_str(&format!("    # {} blocked\n", geo_block.country_code));
        }

        config.push_str("}\n");

        // Add the blocking logic
        config.push_str("map $geoip_country_code $is_blocked_country {\n");
        config.push_str("    default 0;\n");

        for geo_block in geo_blocks {
            if let Some(ref desc) = geo_block.description {
                config.push_str(&format!("    # {}\n", desc));
            }
            config.push_str(&format!("    {} 1;\n", geo_block.country_code));
        }

        config.push_str("}\n");
        config
    }

/// Generates nginx config for rate limits.
fn generate_rate_limits(rate_limits: &[RateLimit]) -> String {
    let mut config = String::from("# Rate Limiting\n");

    for rate_limit in rate_limits {
        if let Some(ref desc) = rate_limit.description {
            config.push_str(&format!("# {}\n", desc));
        }
        config.push_str(&format!("{}\n", rate_limit.to_zone_directive()));
    }

    config
}

/// Generates the combined blocking logic.
fn generate_blocking_logic(config: &BotProtectionConfig) -> String {
    let mut nginx_config = String::from("# Combined Blocking Logic\n");

    nginx_config.push_str("# This should be placed in server or location blocks\n");
    nginx_config.push_str("# Example usage:\n");
    nginx_config.push_str("# server {\n");
    nginx_config.push_str("#     # Check all block conditions\n");

    // IP blocks are already handled by deny directives at http/server level

    // User agent blocks
    if !config.user_agent_blocks.is_empty() {
        nginx_config.push_str(&format!(
            "#     if ($block_bad_ua) {{ return {}; }}\n",
            config.settings.default_block_response
        ));
    }

    // AI bot user agent blocks
    if !config.ai_bots.is_empty() {
        nginx_config.push_str(&format!(
            "#     if ($block_ai_bot) {{ return {}; }}\n",
            config.settings.default_block_response
        ));
    }

    // Geo blocks
    if !config.geo_blocks.is_empty() {
        nginx_config.push_str(&format!(
            "#     if ($is_blocked_country) {{ return {}; }}\n",
            config.settings.default_block_response
        ));
    }

    // Rate limits
    if !config.rate_limits.is_empty() {
        for rate_limit in &config.rate_limits {
            nginx_config.push_str(&format!(
                "#     limit_req {};\n",
                rate_limit.to_request_directive()
            ));
        }
    }

    nginx_config.push_str("# }\n");
    nginx_config
}

// ============================================================================
// NGINX Configuration Writing
// ============================================================================

/// Writes the bot protection configuration to a file.
///
/// # Arguments
///
/// * `config` - The bot protection configuration to write
/// * `path` - Path where the configuration file should be written
///
/// # Returns
///
/// The path where the configuration was written
pub fn write_bot_protection_config<P: AsRef<Path>>(
    config: &BotProtectionConfig,
    path: P,
) -> Result<PathBuf> {
    let path = path.as_ref();
    let nginx_config = generate_bot_protection_config(config);

    fs::write(path, nginx_config)
        .with_context(|| format!("Failed to write bot protection config to: {}", path.display()))?;

    Ok(path.to_path_buf())
}

/// Writes the bot protection configuration to the default location.
///
/// The default location is `/etc/nginx/conf.d/bot-protection.conf`.
pub fn write_bot_protection_config_default(config: &BotProtectionConfig) -> Result<PathBuf> {
    write_bot_protection_config(config, "/etc/nginx/conf.d/bot-protection.conf")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Tests for config reading

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

    // Tests for config generation

    #[test]
    fn test_generate_bot_protection_config_empty() {
        let config = BotProtectionConfig::new();
        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("Bot Protection Configuration"));
        assert!(generated.contains("Generated by stop-bots"));
    }

    #[test]
    fn test_generate_bot_protection_config_with_ip_blocks() {
        let config = BotProtectionConfig::new()
            .add_ip_block(IpBlock::new("1.2.3.4"))
            .add_ip_block(IpBlock::new("5.6.7.8/24"));

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("# IP Block List"));
        assert!(generated.contains("deny 1.2.3.4;"));
        assert!(generated.contains("deny 5.6.7.8/24;"));
    }

    #[test]
    fn test_generate_bot_protection_config_with_user_agent_blocks() {
        let config = BotProtectionConfig::new()
            .add_user_agent_block(UserAgentBlock::new("BadBot"))
            .add_user_agent_block(UserAgentBlock::new("Scraper"));

        let generated = generate_bot_protection_config(&config);

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
    fn test_generate_bot_protection_config_with_geo_blocks() {
        let config = BotProtectionConfig::new()
            .add_geo_block(GeoBlock::new("CN"))
            .add_geo_block(GeoBlock::new("RU"));

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("# Geo Blocking"));
        assert!(generated.contains("CN"));
        assert!(generated.contains("RU"));
    }

    #[test]
    fn test_generate_bot_protection_config_with_rate_limits() {
        let config = BotProtectionConfig::new()
            .add_rate_limit(RateLimit::new("scanner", "10m", "10r/s"));

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("# Rate Limiting"));
        assert!(generated.contains("limit_req_zone"));
    }

    #[test]
    fn test_generate_bot_protection_config_with_scanner_blocks() {
        let scanner = ScannerBlock::new("Test Scanner")
            .add_ip(IpBlock::new("1.2.3.4"));

        let config = BotProtectionConfig::new()
            .add_scanner_block(scanner);

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("# Scanner IP Blocks"));
        assert!(generated.contains("Test Scanner"));
        assert!(generated.contains("deny 1.2.3.4;"));
    }

    #[test]
    fn test_generate_bot_protection_config_with_ai_bots() {
        let bot = AiBot::new("GPTBot", "GPTBot")
            .add_ip_range(IpBlock::new("1.2.3.0/24"));

        let config = BotProtectionConfig::new()
            .add_ai_bot(bot);

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("# AI Bot IP Ranges"));
        assert!(generated.contains("# AI Bot User Agent Blocking"));
        assert!(generated.contains("GPTBot"));
    }

    #[test]
    fn test_generate_bot_protection_settings() {
        use crate::bots::{BlockResponse, BotProtectionSettings};

        let settings = BotProtectionSettings {
            enabled: true,
            default_block_response: BlockResponse::Return403,
        };

        let config = BotProtectionConfig {
            settings,
            ..BotProtectionConfig::default()
        }
        .add_user_agent_block(UserAgentBlock::new("BadBot"));

        let generated = generate_bot_protection_config(&config);

        assert!(generated.contains("return 403;"));
    }

    #[test]
    fn test_generate_bot_protection_config_full() {
        use crate::bots::{SearchBot};

        let config = BotProtectionConfig::new()
            .add_ip_block(IpBlock::new("1.2.3.4"))
            .add_user_agent_block(UserAgentBlock::new("BadBot"))
            .add_geo_block(GeoBlock::new("CN"))
            .add_rate_limit(RateLimit::new("scanner", "10m", "10r/s"))
            .add_scanner_block(ScannerBlock::new("Scanner").add_ip(IpBlock::new("5.6.7.8")))
            .add_ai_bot(AiBot::new("GPTBot", "GPTBot"))
            .add_search_bot(SearchBot::new("Googlebot", "Googlebot"));

        let generated = generate_bot_protection_config(&config);

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
