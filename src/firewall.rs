//! Unified firewall module for bot blocking.
//!
//! This module provides a unified interface for both iptables and nftables,
//! with automatic backend detection and IP set support for better performance
//! with large numbers of blocked IP addresses.

use anyhow::{Context, Result};
use std::collections::HashSet;

// ============================================================================
// Firewall Types (Unified)
// ============================================================================

/// Represents an IP address or CIDR range for firewall rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallAddress {
    pub address: String,
}

impl FirewallAddress {
    pub fn new<A: Into<String>>(address: A) -> Self {
        Self {
            address: address.into(),
        }
    }
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
}

impl std::fmt::Display for FirewallAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// Action to take when a packet matches a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Drop,
    Reject,
    Accept,
}

impl std::fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallAction::Drop => write!(f, "DROP"),
            FirewallAction::Reject => write!(f, "REJECT"),
            FirewallAction::Accept => write!(f, "ACCEPT"),
        }
    }
}

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

impl std::fmt::Display for FirewallRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = format!("{} {}", self.action, self.address);
        if let Some(port) = self.port {
            s.push_str(&format!(" port {}", port));
        }
        write!(f, "{}", s)
    }
}

// ============================================================================
// Firewall Backend
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirewallBackend {
    #[default]
    Iptables,
    Nftables,
    Auto,
}

// ============================================================================
// Firewall Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub backend: FirewallBackend,
    pub use_ipsets: bool,
    pub ipset_name: String,
    pub ipset_max_entries: usize,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::Auto,
            use_ipsets: true,
            ipset_name: "stop_bots_blocked".to_string(),
            ipset_max_entries: 0,
        }
    }
}

impl FirewallConfig {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_backend(mut self, backend: FirewallBackend) -> Self {
        self.backend = backend;
        self
    }
    pub fn with_ipsets(mut self, enabled: bool) -> Self {
        self.use_ipsets = enabled;
        self
    }
    pub fn with_ipset_name<N: Into<String>>(mut self, name: N) -> Self {
        self.ipset_name = name.into();
        self
    }
}

// ============================================================================
// Firewall Manager
// ============================================================================

/// Unified firewall manager that works with either iptables or nftables.
#[derive(Debug)]
pub struct FirewallManager {
    config: FirewallConfig,
    iptables: crate::iptables::Iptables,
    nftables: crate::nftables::Nftables,
    detected_backend: Option<FirewallBackend>,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            config: FirewallConfig::default(),
            iptables: crate::iptables::Iptables::new(),
            nftables: crate::nftables::Nftables::new(),
            detected_backend: None,
        }
    }

    pub fn with_config(config: FirewallConfig) -> Self {
        Self {
            config,
            iptables: crate::iptables::Iptables::new(),
            nftables: crate::nftables::Nftables::new(),
            detected_backend: None,
        }
    }

    pub fn detect_backend(&mut self) -> FirewallBackend {
        if let Some(b) = self.detected_backend {
            return b;
        }
        let b = if self.nftables.is_available() {
            FirewallBackend::Nftables
        } else if self.iptables.is_available() {
            FirewallBackend::Iptables
        } else {
            FirewallBackend::Iptables
        };
        self.detected_backend = Some(b);
        b
    }

    pub fn active_backend(&mut self) -> FirewallBackend {
        match self.config.backend {
            FirewallBackend::Auto => self.detect_backend(),
            other => other,
        }
    }

    pub fn is_available(&mut self) -> bool {
        match self.config.backend {
            FirewallBackend::Auto => self.nftables.is_available() || self.iptables.is_available(),
            FirewallBackend::Iptables => self.iptables.is_available(),
            FirewallBackend::Nftables => self.nftables.is_available(),
        }
    }

    fn to_iptables(&self, addr: &FirewallAddress) -> crate::iptables::FirewallAddress {
        crate::iptables::FirewallAddress::new(addr.address.clone())
    }
    fn to_nftables(&self, addr: &FirewallAddress) -> crate::nftables::FirewallAddress {
        crate::nftables::FirewallAddress::new(addr.address.clone())
    }
    fn from_iptables(&self, rule: crate::iptables::FirewallRule) -> FirewallRule {
        FirewallRule {
            id: rule.id,
            address: FirewallAddress::new(rule.address.address),
            port: rule.port,
            action: match rule.action {
                crate::iptables::FirewallAction::Drop => FirewallAction::Drop,
                crate::iptables::FirewallAction::Reject => FirewallAction::Reject,
                crate::iptables::FirewallAction::Accept => FirewallAction::Accept,
            },
            enabled: rule.enabled,
        }
    }
    fn from_nftables(&self, rule: crate::nftables::FirewallRule) -> FirewallRule {
        FirewallRule {
            id: rule.id,
            address: FirewallAddress::new(rule.address.address),
            port: rule.port,
            action: match rule.action {
                crate::nftables::FirewallAction::Drop => FirewallAction::Drop,
                crate::nftables::FirewallAction::Reject => FirewallAction::Reject,
                crate::nftables::FirewallAction::Accept => FirewallAction::Accept,
            },
            enabled: rule.enabled,
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => {
                self.nftables.ensure_table_exists()?;
            }
            _ => {
                self.iptables.ensure_chain_exists()?;
                if self.config.use_ipsets {
                    self.create_ipset()?;
                    self.setup_ipset_chain()?;
                }
            }
        }
        Ok(())
    }

    pub fn add_block_rule(&mut self, address: &FirewallAddress) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => {
                let a = self.to_nftables(address);
                self.nftables.add_block_rule(&a)
            }
            _ => {
                if self.config.use_ipsets && self.ipset_exists()? {
                    self.add_to_ipset(address)
                } else {
                    let a = self.to_iptables(address);
                    self.iptables.add_block_rule(&a)
                }
            }
        }
    }

    pub fn remove_block_rule(&mut self, address: &FirewallAddress) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => {
                let a = self.to_nftables(address);
                self.nftables.remove_rules_for_address(&a)
            }
            _ => {
                if self.config.use_ipsets && self.ipset_exists()? {
                    self.remove_from_ipset(address)
                } else {
                    let a = self.to_iptables(address);
                    self.iptables.remove_block_rule(&a)
                }
            }
        }
    }

    pub fn list_rules(&mut self) -> Result<Vec<FirewallRule>> {
        match self.active_backend() {
            FirewallBackend::Nftables => {
                let r = self.nftables.list_rules()?;
                Ok(r.into_iter().map(|r| self.from_nftables(r)).collect())
            }
            _ => {
                if self.config.use_ipsets && self.ipset_exists()? {
                    self.list_ipset_entries()
                } else {
                    let r = self.iptables.list_rules()?;
                    Ok(r.into_iter().map(|r| self.from_iptables(r)).collect())
                }
            }
        }
    }

    pub fn clear_rules(&mut self) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => self.nftables.clear_rules(),
            _ => {
                if self.config.use_ipsets && self.ipset_exists()? {
                    self.clear_ipset()
                } else {
                    self.iptables.clear_rules()
                }
            }
        }
    }

    pub fn sync_block_rules(&mut self, addresses: &[FirewallAddress]) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => {
                let a: Vec<_> = addresses.iter().map(|a| self.to_nftables(a)).collect();
                self.nftables.sync_block_rules(&a)
            }
            _ => {
                if self.config.use_ipsets {
                    self.sync_ipset(addresses)
                } else {
                    let a: Vec<_> = addresses.iter().map(|a| self.to_iptables(a)).collect();
                    self.iptables.sync_block_rules(&a)
                }
            }
        }
    }

    pub fn cleanup(&mut self) -> Result<()> {
        match self.active_backend() {
            FirewallBackend::Nftables => self.nftables.cleanup(),
            _ => {
                if self.config.use_ipsets && self.ipset_exists()? {
                    let _ = self.destroy_ipset();
                }
                self.iptables.cleanup()
            }
        }
    }

    // IP Set Support
    fn run_ipset(&self, args: &[&str]) -> Result<()> {
        use std::process::Command;
        let output = Command::new("sudo")
            .arg("ipset")
            .args(args)
            .output()
            .with_context(|| format!("sudo ipset {}", args.join(" ")))?;
        if !output.status.success() {
            let s = String::from_utf8_lossy(&output.stderr);
            if !s.contains("already exists") && !s.contains("not found") {
                anyhow::bail!("ipset failed: {}", s);
            }
        }
        Ok(())
    }

    fn create_ipset(&self) -> Result<()> {
        let max = if self.config.ipset_max_entries > 0 {
            format!("maxelem {}", self.config.ipset_max_entries)
        } else {
            String::new()
        };
        self.run_ipset(&["create", &self.config.ipset_name, "hash:ip", &max])
    }
    fn ipset_exists(&self) -> Result<bool> {
        use std::process::Command;
        Ok(Command::new("sudo")
            .arg("ipset")
            .args(&["list", &self.config.ipset_name])
            .output()
            .is_ok())
    }
    fn add_to_ipset(&self, addr: &FirewallAddress) -> Result<()> {
        self.run_ipset(&["add", &self.config.ipset_name, &addr.address])
    }
    fn remove_from_ipset(&self, addr: &FirewallAddress) -> Result<()> {
        self.run_ipset(&["del", &self.config.ipset_name, &addr.address])
    }
    fn list_ipset_entries(&self) -> Result<Vec<FirewallRule>> {
        use std::process::Command;
        let out = Command::new("sudo")
            .arg("ipset")
            .args(&["list", &self.config.ipset_name])
            .output()?;
        if !out.status.success() {
            anyhow::bail!("ipset list failed");
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let mut rules = Vec::new();
        for line in s.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with(&self.config.ipset_name) {
                rules.push(FirewallRule::new_block(FirewallAddress::new(t.to_string())));
            }
        }
        Ok(rules)
    }
    fn clear_ipset(&self) -> Result<()> {
        self.run_ipset(&["flush", &self.config.ipset_name])
    }
    fn destroy_ipset(&self) -> Result<()> {
        self.run_ipset(&["destroy", &self.config.ipset_name])
    }
    fn sync_ipset(&self, addresses: &[FirewallAddress]) -> Result<()> {
        self.create_ipset()?;
        self.clear_ipset()?;
        for a in addresses {
            self.add_to_ipset(a)?;
        }
        Ok(())
    }
    fn setup_ipset_chain(&self) -> Result<()> {
        use std::process::Command;
        Command::new("sudo")
            .arg("iptables")
            .args(&[
                "-I",
                "STOP-BOTS",
                "-m",
                "set",
                "--match-set",
                &self.config.ipset_name,
                "src",
                "-j",
                "DROP",
            ])
            .output()?;
        Ok(())
    }

    pub fn get_status(&mut self) -> Result<FirewallStatus> {
        let backend = self.active_backend();
        let available = self.is_available();
        let rules = self.list_rules()?;
        let using_ipsets = self.config.use_ipsets
            && backend == FirewallBackend::Iptables
            && self.ipset_exists().unwrap_or(false);
        let unique_ips: HashSet<_> = rules.iter().map(|r| r.address.address.clone()).collect();
        Ok(FirewallStatus {
            backend,
            available,
            using_ipsets,
            rule_count: rules.len(),
            unique_ip_count: unique_ips.len(),
        })
    }
}

// ============================================================================
// Firewall Status
// ============================================================================

#[derive(Debug, Clone)]
pub struct FirewallStatus {
    pub backend: FirewallBackend,
    pub available: bool,
    pub using_ipsets: bool,
    pub rule_count: usize,
    pub unique_ip_count: usize,
}

impl std::fmt::Display for FirewallStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Backend: {}, Available: {}, Using IP Sets: {}, Rules: {}, Unique IPs: {}",
            match self.backend {
                FirewallBackend::Iptables => "iptables",
                FirewallBackend::Nftables => "nftables",
                _ => "auto",
            },
            self.available,
            self.using_ipsets,
            self.rule_count,
            self.unique_ip_count
        )
    }
}

// ============================================================================
// TUI Helper Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct BlockedIp {
    pub address: String,
    pub is_cidr: bool,
    pub description: Option<String>,
}

impl BlockedIp {
    pub fn new<A: Into<String>>(address: A) -> Self {
        let a = address.into();
        let is_cidr = a.contains('/');
        Self {
            address: a,
            is_cidr,
            description: None,
        }
    }
    pub fn with_description<D: Into<String>>(mut self, description: D) -> Self {
        self.description = Some(description.into());
        self
    }
}

impl From<FirewallAddress> for BlockedIp {
    fn from(addr: FirewallAddress) -> Self {
        Self::new(addr.address)
    }
}
impl From<FirewallRule> for BlockedIp {
    fn from(rule: FirewallRule) -> Self {
        Self::new(rule.address.address)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_config() {
        let c = FirewallConfig::new();
        assert_eq!(c.backend, FirewallBackend::Auto);
    }
    #[test]
    fn test_address() {
        assert!(FirewallAddress::new("1.2.3.4").is_valid());
        assert!(FirewallAddress::new("1.2.3.0/24").is_valid());
    }
    #[test]
    fn test_blocked_ip() {
        assert!(!BlockedIp::new("1.2.3.4").is_cidr);
        assert!(BlockedIp::new("1.2.3.0/24").is_cidr);
    }
}
