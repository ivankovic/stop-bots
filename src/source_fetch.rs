//! Module for fetching bot metadata from online sources.
//!
//! This module implements the recommended strategy for fetching bot data from
//! official company sources and community-maintained repositories.

use crate::db::{
    Bot, BotCategory, BotIpRange, BotOwner, BotStatus, BotUserAgentPattern, DataSource,
    DataSourceType, SignalType, UpdateFrequency, VerificationInfo, VerificationSource,
    VerificationStatus,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

// ============================================================================
// JSON Structures for Official Feeds
// ============================================================================

/// Structure for Google's official bot IP ranges JSON.
/// See: https://developers.google.com/static/crawling/ipranges/common-crawlers.json
#[derive(Debug, Clone, Deserialize)]
struct GoogleBotJson {
    #[serde(rename = "prefixes")]
    prefixes: Vec<GooglePrefix>,
}

#[derive(Debug, Clone, Deserialize)]
struct GooglePrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6: Option<String>,
}

/// Structure for Bingbot's official JSON.
/// See: https://www.bing.com/toolbox/bingbot.json
#[derive(Debug, Clone, Deserialize)]
struct BingBotJson {
    #[serde(rename = "prefixes")]
    prefixes: Vec<BingPrefix>,
}

#[derive(Debug, Clone, Deserialize)]
struct BingPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
}

/// Structure for OpenAI's official bot JSON.
/// See: https://openai.com/gptbot.json
#[derive(Debug, Clone, Deserialize)]
struct OpenAIBotJson {
    #[serde(rename = "prefixes")]
    prefixes: Vec<OpenAIPrefix>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    #[serde(rename = "description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "name")]
    name: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "product_url")]
    product_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAIPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6: Option<String>,
}

/// Structure for community well-known-bots JSON.
/// See: https://github.com/arcjet/well-known-bots
#[derive(Debug, Clone, Deserialize)]
struct WellKnownBot {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "userAgents")]
    user_agents: Option<Vec<String>>,
    #[serde(rename = "ipRanges")]
    ip_ranges: Option<Vec<String>>,
    #[serde(rename = "category")]
    category: Option<String>,
    #[serde(rename = "description")]
    description: Option<String>,
    #[serde(rename = "website")]
    website: Option<String>,
    #[serde(rename = "isAI")]
    is_ai: Option<bool>,
    #[allow(dead_code)]
    #[serde(rename = "respectsRobotsTxt")]
    respects_robots_txt: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct WellKnownBotsJson {
    #[serde(rename = "bots")]
    bots: Vec<WellKnownBot>,
}

// ============================================================================
// Source Definitions
// ============================================================================

/// Known data sources with their configurations.
pub struct KnownSources;

impl KnownSources {
    /// Returns all known data sources with their default configurations.
    pub fn all() -> Vec<DataSource> {
        vec![
            // Official company sources (Priority 1)
            DataSource {
                id: "googlebot-official".to_string(),
                name: "Googlebot Official".to_string(),
                description: "Official Googlebot IP ranges and user agents".to_string(),
                url: Some("https://developers.google.com/static/crawling/ipranges/common-crawlers.json".to_string()),
                update_frequency: UpdateFrequency::Daily,
                auto_update_enabled: true,
                last_updated: None,
                is_official: true,
                data_type: DataSourceType::Combined,
            },
            DataSource {
                id: "bingbot-official".to_string(),
                name: "Bingbot Official".to_string(),
                description: "Official Bingbot IP ranges and user agents".to_string(),
                url: Some("https://www.bing.com/toolbox/bingbot.json".to_string()),
                update_frequency: UpdateFrequency::Daily,
                auto_update_enabled: true,
                last_updated: None,
                is_official: true,
                data_type: DataSourceType::Combined,
            },
            DataSource {
                id: "openai-gptbot".to_string(),
                name: "OpenAI GPTBot".to_string(),
                description: "Official OpenAI GPTBot IP ranges".to_string(),
                url: Some("https://openai.com/gptbot.json".to_string()),
                update_frequency: UpdateFrequency::Daily,
                auto_update_enabled: true,
                last_updated: None,
                is_official: true,
                data_type: DataSourceType::IpRanges,
            },
            DataSource {
                id: "openai-searchbot".to_string(),
                name: "OpenAI SearchBot".to_string(),
                description: "Official OpenAI SearchBot IP ranges".to_string(),
                url: Some("https://openai.com/searchbot.json".to_string()),
                update_frequency: UpdateFrequency::Daily,
                auto_update_enabled: true,
                last_updated: None,
                is_official: true,
                data_type: DataSourceType::IpRanges,
            },
            DataSource {
                id: "openai-chatgpt-user".to_string(),
                name: "OpenAI ChatGPT-User".to_string(),
                description: "Official OpenAI ChatGPT-User IP ranges".to_string(),
                url: Some("https://openai.com/chatgpt-user.json".to_string()),
                update_frequency: UpdateFrequency::Daily,
                auto_update_enabled: true,
                last_updated: None,
                is_official: true,
                data_type: DataSourceType::IpRanges,
            },
            // Community sources (Priority 2-3)
            DataSource {
                id: "arcjet-well-known-bots".to_string(),
                name: "ArcJet Well-Known Bots".to_string(),
                description: "Community-maintained list of well-known bots and user agents".to_string(),
                url: Some("https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json".to_string()),
                update_frequency: UpdateFrequency::Weekly,
                auto_update_enabled: true,
                last_updated: None,
                is_official: false,
                data_type: DataSourceType::BotDefinitions,
            },
            DataSource {
                id: "counter-robots".to_string(),
                name: "COUNTER Robots".to_string(),
                description: "Official COUNTER list of user agents regarded as robots".to_string(),
                url: Some("https://raw.githubusercontent.com/atmire/COUNTER-Robots/master/COUNTER_Robots_list.json".to_string()),
                update_frequency: UpdateFrequency::Monthly,
                auto_update_enabled: true,
                last_updated: None,
                is_official: false,
                data_type: DataSourceType::UserAgents,
            },
            DataSource {
                id: "monperrus-crawlers".to_string(),
                name: "Monperrus Crawlers".to_string(),
                description: "Community-maintained syntactic patterns of crawler user agents".to_string(),
                url: Some("https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json".to_string()),
                update_frequency: UpdateFrequency::Monthly,
                auto_update_enabled: true,
                last_updated: None,
                is_official: false,
                data_type: DataSourceType::UserAgents,
            },
            DataSource {
                id: "abuseipdb".to_string(),
                name: "AbuseIPDB".to_string(),
                description: "Crowdsourced IP reputation database for malicious bots".to_string(),
                url: Some("https://api.abuseipdb.com/api/v2/blacklist".to_string()),
                update_frequency: UpdateFrequency::Weekly,
                auto_update_enabled: false, // Requires API key
                last_updated: None,
                is_official: false,
                data_type: DataSourceType::IpRanges,
            },
        ]
    }

    /// Returns only official company sources.
    pub fn official_only() -> Vec<DataSource> {
        Self::all()
            .into_iter()
            .filter(|s| s.is_official)
            .collect()
    }

    /// Returns only community/crowdsourced sources.
    pub fn community_only() -> Vec<DataSource> {
        Self::all()
            .into_iter()
            .filter(|s| !s.is_official)
            .collect()
    }

    /// Returns sources by priority (official first, then community).
    pub fn by_priority() -> Vec<DataSource> {
        let mut sources = Self::all();
        // Sort: official first, then by name
        sources.sort_by(|a, b| {
            if a.is_official != b.is_official {
                b.is_official.cmp(&a.is_official) // true comes first
            } else {
                a.name.cmp(&b.name)
            }
        });
        sources
    }
}

// ============================================================================
// HTTP Client
// ============================================================================

/// HTTP client for fetching data from online sources.
#[derive(Debug, Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    #[allow(dead_code)]
    timeout: Duration,
}

impl HttpClient {
    /// Creates a new HTTP client with default settings.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("stop-bots/0.1.0")
            .build()?;

        Ok(Self {
            client,
            timeout: Duration::from_secs(30),
        })
    }

    /// Creates a new HTTP client with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("stop-bots/0.1.0")
            .build()?;

        Ok(Self { client, timeout })
    }

    /// Fetches JSON data from a URL.
    pub async fn fetch_json<T: for<'de> serde::Deserialize<'de>>(
        &self,
        url: &str,
    ) -> Result<T> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch from: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP {}: {}",
                response.status(),
                url
            ));
        }

        response
            .json::<T>()
            .await
            .with_context(|| format!("Failed to parse JSON from: {}", url))
    }

    /// Fetches raw text from a URL.
    pub async fn fetch_text(&self, url: &str) -> Result<String> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch from: {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP {}: {}",
                response.status(),
                url
            ));
        }

        response
            .text()
            .await
            .with_context(|| format!("Failed to read text from: {}", url))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create HTTP client")
    }
}

// ============================================================================
// Fetcher Trait and Implementations
// ============================================================================

/// Trait for fetching bot data from a source.
#[async_trait::async_trait]
pub trait BotDataFetcher: Send + Sync {
    /// Fetches bot data from the source.
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>>;

    /// Returns the source ID.
    fn source_id(&self) -> &str;

    /// Returns the source name.
    fn source_name(&self) -> &str;
}

// ============================================================================
// Official Source Fetchers
// ============================================================================

/// Fetcher for Googlebot official JSON.
pub struct GoogleBotFetcher;

#[async_trait::async_trait]
impl BotDataFetcher for GoogleBotFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json";
        let json: GoogleBotJson = client.fetch_json(url).await?;

        let mut bots = Vec::new();
        let owner = BotOwner {
            id: None,
            name: "Google".to_string(),
            website: Some("https://www.google.com/bot.html".to_string()),
            contact: Some("googlebot@google.com".to_string()),
        };

        // With the new format, we don't have crawler information anymore
        // Create a single bot for all Google prefixes
        // Note: This is a simplification due to Google's API change
        let mut bot = Bot {
            id: None,
            name: "Googlebot Common".to_string(),
            status: BotStatus::Allowed,
            categories: vec![BotCategory::SearchEngine],
            user_agent_patterns: vec![
                BotUserAgentPattern {
                    id: None,
                    bot_id: None,
                    pattern: "Googlebot".to_string(),
                    is_regex: false,
                    case_sensitive: false,
                    is_primary: true,
                },
                BotUserAgentPattern {
                    id: None,
                    bot_id: None,
                    pattern: "Googlebot-Image".to_string(),
                    is_regex: false,
                    case_sensitive: false,
                    is_primary: false,
                },
            ],
            ip_ranges: Vec::new(),
            signals: vec![SignalType::IpAddress, SignalType::UserAgent, SignalType::OfficialSource],
            owner: Some(owner.clone()),
            owner_id: None,
            notes: Some("Official Google crawler IP ranges".to_string()),
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("googlebot-official".to_string()),
            created_at: Some(SystemTime::now()),
            updated_at: Some(SystemTime::now()),
        };

        // Add IP ranges
        let verification = VerificationInfo {
            status: VerificationStatus::Verified,
            verified_at: Some(SystemTime::now()),
            error: None,
            source: VerificationSource::Official,
        };

        for prefix in json.prefixes {
            if let Some(ip) = prefix.ipv4 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some("Googlebot IPv4 range".to_string()),
                    verification: verification.clone(),
                });
            }
            if let Some(ip) = prefix.ipv6 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some("Googlebot IPv6 range".to_string()),
                    verification: verification.clone(),
                });
            }
        }

        if !bot.ip_ranges.is_empty() || !bot.user_agent_patterns.is_empty() {
            bots.push(bot);
        }

        Ok(bots)
    }

    fn source_id(&self) -> &str {
        "googlebot-official"
    }

    fn source_name(&self) -> &str {
        "Googlebot Official"
    }
}

/// Fetcher for Bingbot official JSON.
pub struct BingBotFetcher;

#[async_trait::async_trait]
impl BotDataFetcher for BingBotFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = "https://www.bing.com/toolbox/bingbot.json";
        let json: BingBotJson = client.fetch_json(url).await?;

        let mut bots = Vec::new();
        let owner = BotOwner {
            id: None,
            name: "Microsoft".to_string(),
            website: Some("https://www.bing.com/bingbot.htm".to_string()),
            contact: None,
        };

        // Collect user agents from prefixes (they might not all be the same)
        let user_agents: Vec<String> = json.prefixes
            .iter()
            .filter_map(|p| p.user_agent.as_ref().map(|ua| ua.clone()))
            .collect();

        let mut bot = Bot {
            id: None,
            name: "Bingbot".to_string(),
            status: BotStatus::Allowed,
            categories: vec![BotCategory::SearchEngine],
            user_agent_patterns: Vec::new(),
            ip_ranges: Vec::new(),
            signals: vec![SignalType::IpAddress, SignalType::UserAgent, SignalType::OfficialSource],
            owner: Some(owner.clone()),
            owner_id: None,
            notes: Some("Official Microsoft Bing crawler".to_string()),
            is_ai_bot: false,
            is_scanner: false,
            source_id: Some("bingbot-official".to_string()),
            created_at: Some(SystemTime::now()),
            updated_at: Some(SystemTime::now()),
        };

        let verification = VerificationInfo {
            status: VerificationStatus::Verified,
            verified_at: Some(SystemTime::now()),
            error: None,
            source: VerificationSource::Official,
        };

        // Add user agents if any exist
        if !user_agents.is_empty() {
            for (idx, ua) in user_agents.into_iter().enumerate() {
                bot.user_agent_patterns.push(BotUserAgentPattern {
                    id: None,
                    bot_id: None,
                    pattern: ua,
                    is_regex: false,
                    case_sensitive: false,
                    is_primary: idx == 0,
                });
            }
        } else {
            // Default user agent if none in prefixes
            bot.user_agent_patterns.push(BotUserAgentPattern {
                id: None,
                bot_id: None,
                pattern: "Bingbot".to_string(),
                is_regex: false,
                case_sensitive: false,
                is_primary: true,
            });
        }

        // Add IP ranges
        for prefix in json.prefixes {
            if let Some(ip) = prefix.ipv4 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some("Bingbot IPv4 range".to_string()),
                    verification: verification.clone(),
                });
            }
            if let Some(ip) = prefix.ipv6 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some("Bingbot IPv6 range".to_string()),
                    verification: verification.clone(),
                });
            }
        }

        if !bot.ip_ranges.is_empty() || !bot.user_agent_patterns.is_empty() {
            bots.push(bot);
        }

        Ok(bots)
    }

    fn source_id(&self) -> &str {
        "bingbot-official"
    }

    fn source_name(&self) -> &str {
        "Bingbot Official"
    }
}

/// Fetcher for OpenAI bot JSON files.
pub struct OpenAIBotFetcher {
    bot_type: OpenAIBotType,
}

#[derive(Debug, Clone)]
pub enum OpenAIBotType {
    GptBot,
    SearchBot,
    ChatGptUser,
}

impl OpenAIBotType {
    fn json_url(&self) -> &'static str {
        match self {
            OpenAIBotType::GptBot => "https://openai.com/gptbot.json",
            OpenAIBotType::SearchBot => "https://openai.com/searchbot.json",
            OpenAIBotType::ChatGptUser => "https://openai.com/chatgpt-user.json",
        }
    }

    fn bot_name(&self) -> &'static str {
        match self {
            OpenAIBotType::GptBot => "GPTBot",
            OpenAIBotType::SearchBot => "OAI-SearchBot",
            OpenAIBotType::ChatGptUser => "ChatGPT-User",
        }
    }

    fn category(&self) -> BotCategory {
        match self {
            OpenAIBotType::GptBot | OpenAIBotType::ChatGptUser => BotCategory::AiScraper,
            OpenAIBotType::SearchBot => BotCategory::AiScraper,
        }
    }

    fn source_id(&self) -> &'static str {
        match self {
            OpenAIBotType::GptBot => "openai-gptbot",
            OpenAIBotType::SearchBot => "openai-searchbot",
            OpenAIBotType::ChatGptUser => "openai-chatgpt-user",
        }
    }
}

#[async_trait::async_trait]
impl BotDataFetcher for OpenAIBotFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = self.bot_type.json_url();
        let json: OpenAIBotJson = client.fetch_json(url).await?;

        let owner = BotOwner {
            id: None,
            name: "OpenAI".to_string(),
            website: Some("https://openai.com".to_string()),
            contact: Some("abuse@openai.com".to_string()),
        };

        let verification = VerificationInfo {
            status: VerificationStatus::Verified,
            verified_at: Some(SystemTime::now()),
            error: None,
            source: VerificationSource::Official,
        };

        let mut bot = Bot {
            id: None,
            name: self.bot_type.bot_name().to_string(),
            status: BotStatus::Blocked, // AI bots typically blocked by default
            categories: vec![self.bot_type.category()],
            user_agent_patterns: Vec::new(),
            ip_ranges: Vec::new(),
            signals: vec![SignalType::IpAddress, SignalType::OfficialSource],
            owner: Some(owner),
            owner_id: None,
            notes: json.description.clone(),
            is_ai_bot: true,
            is_scanner: false,
            source_id: Some(self.bot_type.source_id().to_string()),
            created_at: Some(SystemTime::now()),
            updated_at: Some(SystemTime::now()),
        };

        // Add user agent if present
        if let Some(ua) = json.user_agent {
            bot.user_agent_patterns.push(BotUserAgentPattern {
                id: None,
                bot_id: None,
                pattern: ua,
                is_regex: false,
                case_sensitive: false,
                is_primary: true,
            });
        }

        // Add IP ranges from prefixes
        for prefix in json.prefixes {
            if let Some(ip) = prefix.ipv4 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some(format!("{} IP range", self.bot_type.bot_name())),
                    verification: verification.clone(),
                });
            }
            if let Some(ip) = prefix.ipv6 {
                bot.ip_ranges.push(BotIpRange {
                    id: None,
                    bot_id: None,
                    address: ip,
                    description: Some(format!("{} IPv6 range", self.bot_type.bot_name())),
                    verification: verification.clone(),
                });
            }
        }

        Ok(vec![bot])
    }

    fn source_id(&self) -> &str {
        self.bot_type.source_id()
    }

    fn source_name(&self) -> &str {
        match &self.bot_type {
            OpenAIBotType::GptBot => "OpenAI GPTBot",
            OpenAIBotType::SearchBot => "OpenAI SearchBot",
            OpenAIBotType::ChatGptUser => "OpenAI ChatGPT-User",
        }
    }
}

// ============================================================================
// Community Source Fetchers
// ============================================================================

/// Fetcher for ArcJet Well-Known Bots.
pub struct WellKnownBotsFetcher;

#[async_trait::async_trait]
impl BotDataFetcher for WellKnownBotsFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = "https://raw.githubusercontent.com/arcjet/well-known-bots/main/well-known-bots.json";
        let json: WellKnownBotsJson = client.fetch_json(url).await?;

        let mut bots = Vec::new();

        for well_known_bot in json.bots {
            let category = match well_known_bot.category.as_deref() {
                Some("AI") | Some("ai") | Some("AI Bot") => vec![BotCategory::AiScraper],
                Some("Search Engine") | Some("search engine") => vec![BotCategory::SearchEngine],
                Some("Scanner") | Some("scanner") => vec![BotCategory::Scanner, BotCategory::SecurityScanner],
                Some("Scraper") | Some("scraper") => vec![BotCategory::Scraper],
                Some("Ad") | Some("ad") => vec![BotCategory::AdBot],
                Some("Social") | Some("social") => vec![BotCategory::SocialBot],
                Some("Monitoring") | Some("monitoring") => vec![BotCategory::MonitoringBot],
                _ => vec![BotCategory::Unknown],
            };

            let is_ai = well_known_bot.is_ai.unwrap_or(false);
            let is_scanner = category.iter().any(|c| matches!(c, BotCategory::Scanner | BotCategory::SecurityScanner));

            let mut bot = Bot {
                id: None,
                name: well_known_bot.name.clone(),
                // Default to blocked for AI bots, allowed for search engines
                status: if is_ai {
                    BotStatus::Blocked
                } else {
                    BotStatus::Allowed
                },
                categories: category.clone(),
                user_agent_patterns: Vec::new(),
                ip_ranges: Vec::new(),
                signals: vec![SignalType::UserAgent, SignalType::OfficialSource],
                owner: well_known_bot.website.clone().map(|w| BotOwner {
                    id: None,
                    name: well_known_bot.name.clone(),
                    website: Some(w),
                    contact: None,
                }),
                owner_id: None,
                notes: well_known_bot.description.clone(),
                is_ai_bot: is_ai,
                is_scanner,
                source_id: Some("arcjet-well-known-bots".to_string()),
                created_at: Some(SystemTime::now()),
                updated_at: Some(SystemTime::now()),
            };

            // Add user agents
            if let Some(uas) = well_known_bot.user_agents {
                for (idx, ua) in uas.into_iter().enumerate() {
                    bot.user_agent_patterns.push(BotUserAgentPattern {
                        id: None,
                        bot_id: None,
                        pattern: ua,
                        is_regex: true, // These are typically regex patterns
                        case_sensitive: false,
                        is_primary: idx == 0,
                    });
                }
            }

            // Add IP ranges
            let verification = VerificationInfo {
                status: VerificationStatus::Unverified,
                verified_at: None,
                error: None,
                source: VerificationSource::Crowdsourced,
            };

            if let Some(ip_ranges) = well_known_bot.ip_ranges {
                for ip_range in ip_ranges {
                    bot.ip_ranges.push(BotIpRange {
                        id: None,
                        bot_id: None,
                        address: ip_range,
                        description: Some("IP range from well-known-bots".to_string()),
                        verification: verification.clone(),
                    });
                }
            }

            if !bot.user_agent_patterns.is_empty() || !bot.ip_ranges.is_empty() {
                bots.push(bot);
            }
        }

        Ok(bots)
    }

    fn source_id(&self) -> &str {
        "arcjet-well-known-bots"
    }

    fn source_name(&self) -> &str {
        "ArcJet Well-Known Bots"
    }
}

/// Structure for COUNTER Robots JSON.
#[derive(Debug, Clone, Deserialize)]
struct CounterRobotsJson {
    #[serde(rename = "robots")]
    robots: Vec<CounterRobot>,
}

#[derive(Debug, Clone, Deserialize)]
struct CounterRobot {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "userAgent")]
    user_agent: String,
}

/// Fetcher for COUNTER Robots list.
pub struct CounterRobotsFetcher;

#[async_trait::async_trait]
impl BotDataFetcher for CounterRobotsFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = "https://raw.githubusercontent.com/atmire/COUNTER-Robots/master/COUNTER_Robots_list.json";
        let json: CounterRobotsJson = client.fetch_json(url).await?;

        let mut bots = Vec::new();

        for robot in json.robots {
            let bot = Bot {
                id: None,
                name: robot.name.clone(),
                status: BotStatus::Allowed, // COUNTER robots are typically legitimate
                categories: vec![BotCategory::Unknown],
                user_agent_patterns: vec![BotUserAgentPattern {
                    id: None,
                    bot_id: None,
                    pattern: robot.user_agent,
                    is_regex: false,
                    case_sensitive: false,
                    is_primary: true,
                }],
                ip_ranges: Vec::new(),
                signals: vec![SignalType::UserAgent, SignalType::OfficialSource],
                owner: None,
                owner_id: None,
                notes: Some("COUNTER-standard robot".to_string()),
                is_ai_bot: false,
                is_scanner: false,
                source_id: Some("counter-robots".to_string()),
                created_at: Some(SystemTime::now()),
                updated_at: Some(SystemTime::now()),
            };

            bots.push(bot);
        }

        Ok(bots)
    }

    fn source_id(&self) -> &str {
        "counter-robots"
    }

    fn source_name(&self) -> &str {
        "COUNTER Robots"
    }
}

/// Structure for Monperrus crawler user agents JSON.
#[derive(Debug, Clone, Deserialize)]
struct MonperrusEntry {
    #[serde(rename = "pattern")]
    pattern: String,
    #[allow(dead_code)]
    #[serde(rename = "url")]
    url: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "instances")]
    instances: Option<Vec<String>>,
    #[serde(rename = "description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "tags")]
    tags: Option<Vec<String>>,
}

/// Fetcher for Monperrus Crawler User Agents.
pub struct MonperrusCrawlersFetcher;

#[async_trait::async_trait]
impl BotDataFetcher for MonperrusCrawlersFetcher {
    async fn fetch(&self, client: &HttpClient) -> Result<Vec<Bot>> {
        let url = "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json";
        let text = client.fetch_text(url).await?;

        let mut bots = Vec::new();

        // Parse JSON file (array of user agents)
        // Format is now JSON: [{"pattern": "...", "name": "..."}, ...]
        // But if that fails, fall back to text format
        let user_agents: Vec<MonperrusEntry> = match serde_json::from_str(&text) {
            Ok(agents) => agents,
            Err(_) => {
                // Fall back to text format
                let mut entries = Vec::new();
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    // Try to parse "pattern -> name" format
                    let (pattern, _name) = if line.contains(" -> ") {
                        let parts: Vec<&str> = line.splitn(2, " -> ").collect();
                        (parts[0].to_string(), parts[1].to_string())
                    } else {
                        (line.to_string(), line.to_string())
                    };
                    entries.push(MonperrusEntry {
                        pattern,
                        url: None,
                        instances: None,
                        description: None,
                        tags: None
                    });
                }
                entries
            }
        };

        for entry in user_agents {
            // Use description as name if available, otherwise use pattern
            let name = entry.description.clone().unwrap_or_else(|| entry.pattern.clone());
            let bot = Bot {
                id: None,
                name,
                status: BotStatus::Blocked, // Unknown crawlers blocked by default
                categories: vec![BotCategory::Unknown],
                user_agent_patterns: vec![BotUserAgentPattern {
                    id: None,
                    bot_id: None,
                    pattern: entry.pattern,
                    is_regex: true,
                    case_sensitive: false,
                    is_primary: true,
                }],
                ip_ranges: Vec::new(),
                signals: vec![SignalType::UserAgent, SignalType::Crowdsourced],
                owner: None,
                owner_id: None,
                notes: Some("From Monperrus crawler user agents".to_string()),
                is_ai_bot: false,
                is_scanner: false,
                source_id: Some("monperrus-crawlers".to_string()),
                created_at: Some(SystemTime::now()),
                updated_at: Some(SystemTime::now()),
            };

            bots.push(bot);
        }

        Ok(bots)
    }

    fn source_id(&self) -> &str {
        "monperrus-crawlers"
    }

    fn source_name(&self) -> &str {
        "Monperrus Crawlers"
    }
}

// ============================================================================
// Fetcher Registry
// ============================================================================

/// Registry of all available bot data fetchers.
pub struct FetcherRegistry {
    fetchers: HashMap<String, Box<dyn BotDataFetcher>>,
}

impl FetcherRegistry {
    /// Creates a new registry with all default fetchers.
    pub fn new() -> Self {
        let mut fetchers = HashMap::new();

        // Official sources
        fetchers.insert(
            "googlebot-official".to_string(),
            Box::new(GoogleBotFetcher) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "bingbot-official".to_string(),
            Box::new(BingBotFetcher) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "openai-gptbot".to_string(),
            Box::new(OpenAIBotFetcher {
                bot_type: OpenAIBotType::GptBot,
            }) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "openai-searchbot".to_string(),
            Box::new(OpenAIBotFetcher {
                bot_type: OpenAIBotType::SearchBot,
            }) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "openai-chatgpt-user".to_string(),
            Box::new(OpenAIBotFetcher {
                bot_type: OpenAIBotType::ChatGptUser,
            }) as Box<dyn BotDataFetcher>,
        );

        // Community sources
        fetchers.insert(
            "arcjet-well-known-bots".to_string(),
            Box::new(WellKnownBotsFetcher) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "counter-robots".to_string(),
            Box::new(CounterRobotsFetcher) as Box<dyn BotDataFetcher>,
        );
        fetchers.insert(
            "monperrus-crawlers".to_string(),
            Box::new(MonperrusCrawlersFetcher) as Box<dyn BotDataFetcher>,
        );

        Self { fetchers }
    }

    /// Gets a fetcher by source ID.
    pub fn get(&self, source_id: &str) -> Option<&dyn BotDataFetcher> {
        self.fetchers.get(source_id).map(|f| f.as_ref())
    }

    /// Returns all registered source IDs.
    pub fn source_ids(&self) -> Vec<&str> {
        self.fetchers.keys().map(|k| k.as_str()).collect()
    }

    /// Returns all official source fetchers.
    pub fn official_fetchers(&self) -> Vec<&dyn BotDataFetcher> {
        KnownSources::official_only()
            .into_iter()
            .filter_map(|s| self.get(&s.id))
            .collect()
    }

    /// Returns all community source fetchers.
    pub fn community_fetchers(&self) -> Vec<&dyn BotDataFetcher> {
        KnownSources::community_only()
            .into_iter()
            .filter_map(|s| self.get(&s.id))
            .collect()
    }
}

impl Default for FetcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Source Fetcher (Main API)
// ============================================================================

/// Main source fetcher that coordinates fetching from multiple sources.
pub struct SourceFetcher {
    client: HttpClient,
    registry: FetcherRegistry,
}

impl SourceFetcher {
    /// Creates a new source fetcher.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: HttpClient::default(),
            registry: FetcherRegistry::new(),
        })
    }

    /// Creates a new source fetcher with a custom HTTP client.
    pub fn with_client(client: HttpClient) -> Self {
        Self {
            client,
            registry: FetcherRegistry::new(),
        }
    }

    /// Fetches bot data from a specific source by ID.
    pub async fn fetch_from_source(&self, source_id: &str) -> Result<Vec<Bot>> {
        let fetcher = self
            .registry
            .get(source_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown source: {}", source_id))?;

        fetcher.fetch(&self.client).await
    }

    /// Fetches bot data from multiple sources.
    pub async fn fetch_from_sources(&self, source_ids: &[&str]) -> Result<Vec<Bot>> {
        let mut all_bots = Vec::new();

        for source_id in source_ids {
            match self.fetch_from_source(source_id).await {
                Ok(bots) => {
                    all_bots.extend(bots);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to fetch from {}: {}", source_id, e);
                }
            }
        }

        Ok(all_bots)
    }

    /// Fetches bot data from all official sources.
    pub async fn fetch_official(&self) -> Result<Vec<Bot>> {
        let official_sources = KnownSources::official_only();
        let source_ids: Vec<&str> = official_sources
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        self.fetch_from_sources(&source_ids).await
    }

    /// Fetches bot data from all community sources.
    pub async fn fetch_community(&self) -> Result<Vec<Bot>> {
        let community_sources = KnownSources::community_only();
        let source_ids: Vec<&str> = community_sources
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        self.fetch_from_sources(&source_ids).await
    }

    /// Fetches bot data from all sources (official first, then community).
    pub async fn fetch_all(&self) -> Result<Vec<Bot>> {
        let all_sources = KnownSources::by_priority();
        let source_ids: Vec<&str> = all_sources
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        self.fetch_from_sources(&source_ids).await
    }

    /// Gets the list of all known sources.
    pub fn known_sources(&self) -> Vec<DataSource> {
        KnownSources::all()
    }

    /// Gets the registry of fetchers.
    pub fn registry(&self) -> &FetcherRegistry {
        &self.registry
    }
}

impl Default for SourceFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create SourceFetcher")
    }
}

// ============================================================================
// IP Range Utilities
// ============================================================================

/// IP range utilities for validation and parsing.
pub struct IpRangeUtils;

impl IpRangeUtils {
    /// Checks if an IP address is in a CIDR range.
    pub fn ip_in_cidr(_ip: &str, _cidr: &str) -> Result<bool> {
        // Implementation would use ipnetwork or similar crate
        // For now, we'll use a simple approach
        // This is a placeholder - in production, use the `ipnetwork` crate
        Ok(false)
    }

    /// Validates a CIDR range.
    pub fn validate_cidr(cidr: &str) -> bool {
        // Check if it's a valid CIDR notation
        if !cidr.contains('/') {
            // Single IP
            return IpAddr::from_str(cidr).is_ok();
        }

        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let ip_str = parts[0];
        let prefix_str = parts[1];

        // Validate IP part
        if IpAddr::from_str(ip_str).is_err() {
            return false;
        }

        // Validate prefix
        match prefix_str.parse::<u32>() {
            Ok(prefix) => {
                // IPv4: 0-32, IPv6: 0-128
                if ip_str.contains(':') {
                    // IPv6
                    prefix <= 128
                } else {
                    // IPv4
                    prefix <= 32
                }
            }
            Err(_) => false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_sources_all() {
        let sources = KnownSources::all();
        assert!(!sources.is_empty());
        assert!(sources.len() >= 7); // At least our defined sources
    }

    #[test]
    fn test_known_sources_official_only() {
        let official = KnownSources::official_only();
        assert!(!official.is_empty());
        assert!(official.iter().all(|s| s.is_official));
    }

    #[test]
    fn test_known_sources_community_only() {
        let community = KnownSources::community_only();
        assert!(!community.is_empty());
        assert!(community.iter().all(|s| !s.is_official));
    }

    #[test]
    fn test_known_sources_by_priority() {
        let by_priority = KnownSources::by_priority();
        assert!(!by_priority.is_empty());

        // First should be official, then community
        let mut found_community = false;
        for (idx, source) in by_priority.iter().enumerate() {
            if !source.is_official {
                found_community = true;
                // All after this should also be community
                for s in &by_priority[idx..] {
                    assert!(!s.is_official);
                }
                break;
            }
        }
        assert!(found_community);
    }

    #[test]
    fn test_fetcher_registry() {
        let registry = FetcherRegistry::new();
        assert!(!registry.source_ids().is_empty());
        assert!(registry.get("googlebot-official").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_openai_bot_type() {
        assert_eq!(OpenAIBotType::GptBot.json_url(), "https://openai.com/gptbot.json");
        assert_eq!(OpenAIBotType::GptBot.bot_name(), "GPTBot");
        assert_eq!(OpenAIBotType::GptBot.source_id(), "openai-gptbot");
        assert_eq!(OpenAIBotType::GptBot.category(), BotCategory::AiScraper);
    }

    #[test]
    fn test_ip_range_utils_validate_cidr() {
        // Valid IPv4 CIDR
        assert!(IpRangeUtils::validate_cidr("192.168.1.0/24"));
        assert!(IpRangeUtils::validate_cidr("10.0.0.0/8"));
        assert!(IpRangeUtils::validate_cidr("0.0.0.0/0"));

        // Valid IPv6 CIDR
        assert!(IpRangeUtils::validate_cidr("2001:db8::/32"));
        assert!(IpRangeUtils::validate_cidr("::/0"));

        // Single IPs
        assert!(IpRangeUtils::validate_cidr("192.168.1.1"));
        assert!(IpRangeUtils::validate_cidr("::1"));

        // Invalid
        assert!(!IpRangeUtils::validate_cidr("invalid"));
        assert!(!IpRangeUtils::validate_cidr("192.168.1.0/99"));
        assert!(!IpRangeUtils::validate_cidr("2001:db8::/200"));
    }
}
