//! Module for integrating with nftables firewall.
//!
//! This module provides functionality to manage nftables rules for blocking
//! bot IP addresses at the network level. nftables is the modern replacement
//! for iptables and provides better performance and more consistent syntax.

use anyhow::{bail, Context, Result};
use std::fmt;
use std::process::Command;

// ============================================================================
// Table and Chain Configuration
// ============================================================================

/// Default nftables table name for stop-bots
const STOP_BOTS_TABLE: &str = "stop_bots";

/// Default chain name for bot blocking
const BOT_BLOCK_CHAIN: &str = "bot_block";

/// Priority for the chain (runs before other chains)
const CHAIN_PRIORITY: i32 = -1;

/// Hook point for the chain
const CHAIN_HOOK: &str = "input";

/// Type of chain
const CHAIN_TYPE: &str = "filter";

// ============================================================================
// Address Types
// ============================================================================

/// Represents an IP address or CIDR range for firewall rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallAddress {
    /// IP address or CIDR notation (e.g., "1.2.3.4" or "1.2.3.0/24")
    pub address: String,
}

impl FirewallAddress {
    /// Creates a new firewall address.
    pub fn new<A: Into<String>>(address: A) -> Self {
        Self {
            address: address.into(),
        }
    }

    /// Validates that the address is valid IP or CIDR notation.
    pub fn is_valid(&self) -> bool {
        let addr = self.address.trim();
        if addr.is_empty() {
            return false;
        }

        if addr.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }

        if let Some(slash_pos) = addr.rfind('/') {
            let prefix = &addr[..slash_pos];
            let suffix = &addr[slash_pos + 1..];
            if prefix.parse::<std::net::IpAddr>().is_ok()
                && suffix.chars().all(|c| c.is_ascii_digit())
            {
                return true;
            }
        }

        false
    }

    /// Escapes special characters for nftables.
    pub fn escape_for_nftables(&self) -> String {
        let addr = self.address.trim();
        if addr.contains('"') || addr.contains('\\') || addr.contains('$') {
            format!("'{}'", addr)
        } else {
            addr.to_string()
        }
    }
}

impl fmt::Display for FirewallAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

// ============================================================================
// Firewall Action
// ============================================================================

/// Action to take when a packet matches a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Drop,
    Reject,
    Accept,
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallAction::Drop => write!(f, "drop"),
            FirewallAction::Reject => write!(f, "reject"),
            FirewallAction::Accept => write!(f, "accept"),
        }
    }
}

impl FirewallAction {
    pub fn to_nftables_action(&self) -> &'static str {
        match self {
            FirewallAction::Drop => "drop",
            FirewallAction::Reject => "reject",
            FirewallAction::Accept => "accept",
        }
    }
}

// ============================================================================
// Firewall Rule
// ============================================================================

/// Represents a firewall rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub id: Option<String>,
    pub address: FirewallAddress,
    pub port: Option<u16>,
    pub action: FirewallAction,
    pub enabled: bool,
}

impl FirewallRule {
    pub fn new_block(address: FirewallAddress) -> Self {
        Self {
            id: None,
            address,
            port: None,
            action: FirewallAction::Drop,
            enabled: true,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_action(mut self, action: FirewallAction) -> Self {
        self.action = action;
        self
    }
}

impl fmt::Display for FirewallRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = format!("{} {}", self.action, self.address);
        if let Some(port) = self.port {
            s.push_str(&format!(" port {}", port));
        }
        write!(f, "{}", s)
    }
}

// ============================================================================
// Nftables Manager
// ============================================================================

/// Manages nftables rules for blocking bots.
#[derive(Debug)]
pub struct Nftables {
    use_sudo: bool,
    nft_path: String,
}

impl Default for Nftables {
    fn default() -> Self {
        Self {
            use_sudo: true,
            nft_path: "nft".to_string(),
        }
    }
}

impl Nftables {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path<P: Into<String>>(path: P) -> Self {
        Self {
            use_sudo: false,
            nft_path: path.into(),
        }
    }

    pub fn is_available(&self) -> bool {
        let output = if self.use_sudo {
            Command::new("sudo")
                .arg(&self.nft_path)
                .arg("--version")
                .output()
        } else {
            Command::new(&self.nft_path)
                .arg("--version")
                .output()
        };

        output.is_ok() && output.as_ref().map_or(false, |o| o.status.success())
    }

    pub fn ensure_table_exists(&self) -> Result<()> {
        let table_exists = self.table_exists()?;
        if !table_exists {
            self.create_table()?;
            self.create_chain()?;
        }
        Ok(())
    }

    pub fn table_exists(&self) -> Result<bool> {
        let output = self.run_nft(&["list", "tables"])?;
        Ok(output.contains(STOP_BOTS_TABLE))
    }

    pub fn create_table(&self) -> Result<()> {
        let rule = format!("add table {} inet", STOP_BOTS_TABLE);
        self.run_nft(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        Ok(())
    }

    pub fn create_chain(&self) -> Result<()> {
        let rule = format!(
            "add chain {} {} type {} hook {} priority {}",
            STOP_BOTS_TABLE, BOT_BLOCK_CHAIN, CHAIN_TYPE, CHAIN_HOOK, CHAIN_PRIORITY
        );
        self.run_nft(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        Ok(())
    }

    pub fn add_block_rule(&self, address: &FirewallAddress) -> Result<()> {
        self.ensure_table_exists()?;
        let escaped_addr = address.escape_for_nftables();
        let rule = format!("add rule {} {} ip saddr {} drop", STOP_BOTS_TABLE, BOT_BLOCK_CHAIN, escaped_addr);
        self.run_nft(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        Ok(())
    }

    pub fn add_rule(&self, address: &FirewallAddress, action: FirewallAction) -> Result<()> {
        self.ensure_table_exists()?;
        let escaped_addr = address.escape_for_nftables();
        let rule = format!(
            "add rule {} {} ip saddr {} {}",
            STOP_BOTS_TABLE, BOT_BLOCK_CHAIN, escaped_addr, action.to_nftables_action()
        );
        self.run_nft(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        Ok(())
    }

    pub fn add_rule_with_port(&self, address: &FirewallAddress, port: u16, action: FirewallAction) -> Result<()> {
        self.ensure_table_exists()?;
        let escaped_addr = address.escape_for_nftables();
        let rule = format!(
            "add rule {} {} ip saddr {} tcp dport {} {}",
            STOP_BOTS_TABLE, BOT_BLOCK_CHAIN, escaped_addr, port, action.to_nftables_action()
        );
        self.run_nft(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        Ok(())
    }

    pub fn remove_rules_for_address(&self, address: &FirewallAddress) -> Result<()> {
        self.ensure_table_exists()?;
        let rules = self.list_rules()?;
        for rule in rules {
            if rule.address.address == address.address {
                if let Some(ref handle) = rule.id {
                    let _ = self.run_nft(&["delete", "rule", STOP_BOTS_TABLE, BOT_BLOCK_CHAIN, "handle", handle]);
                }
            }
        }
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        self.ensure_table_exists()?;
        let output = self.run_nft(&["list", "ruleset"])?;
        let mut rules = Vec::new();
        let mut in_table = false;
        let mut in_chain = false;
        let mut current_handle: Option<String> = None;
        let mut current_address: Option<String> = None;
        
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(&format!("table {} {{", STOP_BOTS_TABLE)) {
                in_table = true;
                continue;
            }
            if in_table && trimmed == "}" {
                in_table = false;
                continue;
            }
            if in_table && trimmed.starts_with(&format!("chain {} {{", BOT_BLOCK_CHAIN)) {
                in_chain = true;
                continue;
            }
            if in_chain && trimmed == "}" {
                in_chain = false;
                continue;
            }
            if in_chain {
                if trimmed.starts_with("handle") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        current_handle = Some(parts[1].to_string());
                    }
                } else if trimmed.starts_with("ip saddr") || trimmed.starts_with("ip6 saddr") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        current_address = Some(parts[1].to_string());
                    }
                } else if let Some(action) = self.parse_action(trimmed) {
                    if let (Some(handle), Some(addr)) = (current_handle.clone(), current_address.clone()) {
                        rules.push(FirewallRule {
                            id: Some(handle),
                            address: FirewallAddress::new(addr),
                            port: None,
                            action,
                            enabled: true,
                        });
                        current_handle = None;
                        current_address = None;
                    }
                }
            }
        }
        Ok(rules)
    }

    fn parse_action(&self, line: &str) -> Option<FirewallAction> {
        match line.trim() {
            "drop" => Some(FirewallAction::Drop),
            "reject" => Some(FirewallAction::Reject),
            "accept" => Some(FirewallAction::Accept),
            _ => None,
        }
    }

    pub fn clear_rules(&self) -> Result<()> {
        let _ = self.run_nft(&["delete", "chain", STOP_BOTS_TABLE, BOT_BLOCK_CHAIN]);
        self.create_chain()?;
        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        let _ = self.run_nft(&["delete", "chain", STOP_BOTS_TABLE, BOT_BLOCK_CHAIN]);
        let _ = self.run_nft(&["delete", "table", STOP_BOTS_TABLE]);
        Ok(())
    }

    pub fn sync_block_rules(&self, addresses: &[FirewallAddress]) -> Result<()> {
        self.ensure_table_exists()?;
        self.clear_rules()?;
        for address in addresses {
            self.add_block_rule(address)?;
        }
        Ok(())
    }

    fn run_nft(&self, args: &[&str]) -> Result<String> {
        let output = if self.use_sudo {
            Command::new("sudo")
                .arg(&self.nft_path)
                .args(args)
                .output()
                .with_context(|| format!("Failed to run: sudo nft {}", args.join(" ")))?
        } else {
            Command::new(&self.nft_path)
                .args(args)
                .output()
                .with_context(|| format!("Failed to run: nft {}", args.join(" ")))?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!("nft command failed: {}\\nstderr: {}", stdout, stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_address_validation() {
        assert!(FirewallAddress::new("192.168.1.1").is_valid());
        assert!(FirewallAddress::new("10.0.0.1").is_valid());
        assert!(FirewallAddress::new("8.8.8.8").is_valid());
        assert!(FirewallAddress::new("192.168.1.0/24").is_valid());
        assert!(FirewallAddress::new("10.0.0.0/8").is_valid());
        assert!(!FirewallAddress::new("").is_valid());
        assert!(!FirewallAddress::new("not-an-ip").is_valid());
    }

    #[test]
    fn test_nftables_action_display() {
        assert_eq!(format!("{}", FirewallAction::Drop), "drop");
        assert_eq!(format!("{}", FirewallAction::Reject), "reject");
        assert_eq!(format!("{}", FirewallAction::Accept), "accept");
    }
}
