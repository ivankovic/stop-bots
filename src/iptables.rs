//! Module for integrating with iptables firewall.
//!
//! This module provides functionality to manage iptables rules for blocking
//! bot IP addresses at the network level.

use anyhow::{bail, Context, Result};
use std::fmt;
use std::process::Command;

// ============================================================================
// Chain Configuration
// ============================================================================

/// Default iptables chain name for stop-bots
const STOP_BOTS_CHAIN: &str = "STOP-BOTS";

/// Protocol for blocking
const PROTOCOL: &str = "tcp";

// ============================================================================
// IP Tables Backend
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
        // Basic validation - could be enhanced with ipnetwork crate
        let addr = self.address.trim();
        if addr.is_empty() {
            return false;
        }

        // Check if it's a valid IP address
        if addr.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }

        // Check if it's a valid CIDR (basic check for / followed by digits)
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

impl fmt::Display for FirewallAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

// ============================================================================
// Firewall Rule
// ============================================================================

/// Represents a firewall rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    /// Rule identifier
    pub id: Option<String>,
    /// Address to block
    pub address: FirewallAddress,
    /// Port to block (optional, None means all ports)
    pub port: Option<u16>,
    /// Action (DROP, REJECT, ACCEPT)
    pub action: FirewallAction,
    /// Rule is enabled
    pub enabled: bool,
}

impl FirewallRule {
    /// Creates a new firewall rule to drop traffic from an address.
    pub fn new_block(address: FirewallAddress) -> Self {
        Self {
            id: None,
            address,
            port: None,
            action: FirewallAction::Drop,
            enabled: true,
        }
    }

    /// Creates a rule for a specific port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Creates a rule with a specific action.
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
// Firewall Action
// ============================================================================

/// Action to take when a packet matches a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// Drop the packet silently
    Drop,
    /// Reject the packet with a response
    Reject,
    /// Accept the packet
    Accept,
}

impl fmt::Display for FirewallAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FirewallAction::Drop => write!(f, "DROP"),
            FirewallAction::Reject => write!(f, "REJECT"),
            FirewallAction::Accept => write!(f, "ACCEPT"),
        }
    }
}

impl FirewallAction {
    /// Returns the iptables action string.
    pub fn to_iptables_action(&self) -> &'static str {
        match self {
            FirewallAction::Drop => "DROP",
            FirewallAction::Reject => "REJECT",
            FirewallAction::Accept => "ACCEPT",
        }
    }
}

// ============================================================================
// Iptables Manager
// ============================================================================

/// Manages iptables rules for blocking bots.
#[derive(Debug)]
pub struct Iptables {
    /// Whether to use sudo for privileged commands
    use_sudo: bool,
    /// Path to iptables binary (for testing)
    iptables_path: String,
}

impl Default for Iptables {
    fn default() -> Self {
        Self {
            use_sudo: true,
            iptables_path: "iptables".to_string(),
        }
    }
}

impl Iptables {
    /// Creates a new iptables manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates with custom iptables path (for testing).
    pub fn with_path<P: Into<String>>(path: P) -> Self {
        Self {
            use_sudo: false,
            iptables_path: path.into(),
        }
    }

    /// Checks if iptables is available on the system.
    pub fn is_available(&self) -> bool {
        let output = if self.use_sudo {
            Command::new("sudo")
                .arg(&self.iptables_path)
                .arg("--version")
                .output()
        } else {
            Command::new(&self.iptables_path).arg("--version").output()
        };

        output.is_ok()
    }

    /// Initializes the stop-bots chain if it doesn't exist.
    pub fn ensure_chain_exists(&self) -> Result<()> {
        // Check if chain exists
        let chain_exists = self.chain_exists(STOP_BOTS_CHAIN)?;
        if !chain_exists {
            // Create the chain
            self.create_chain(STOP_BOTS_CHAIN)?;

            // Insert jump rule at the beginning of INPUT chain
            let rule = format!("-I INPUT -j {}", STOP_BOTS_CHAIN);
            self.run_iptables(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;
        }
        Ok(())
    }

    /// Checks if a chain exists.
    pub fn chain_exists(&self, chain: &str) -> Result<bool> {
        let output = self.run_iptables(&["-L", chain])?;
        Ok(output.contains(chain) || output.contains("No chain") == false)
    }

    /// Creates a new chain.
    pub fn create_chain(&self, chain: &str) -> Result<()> {
        self.run_iptables(&["-N", chain])?;
        Ok(())
    }

    /// Adds a rule to block an IP address or CIDR range.
    ///
    /// This adds the rule to the STOP-BOTS chain.
    pub fn add_block_rule(&self, address: &FirewallAddress) -> Result<()> {
        self.ensure_chain_exists()?;

        let rule = format!(
            "-A {} -p {} -s {} -j DROP",
            STOP_BOTS_CHAIN, PROTOCOL, address.address
        );
        self.run_iptables(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;

        Ok(())
    }

    /// Adds a rule with a custom action.
    pub fn add_rule(&self, address: &FirewallAddress, action: FirewallAction) -> Result<()> {
        self.ensure_chain_exists()?;

        let rule = format!(
            "-A {} -p {} -s {} -j {}",
            STOP_BOTS_CHAIN,
            PROTOCOL,
            address.address,
            action.to_iptables_action()
        );
        self.run_iptables(rule.split_whitespace().collect::<Vec<_>>().as_slice())?;

        Ok(())
    }

    /// Removes a block rule for an IP address or CIDR range.
    pub fn remove_block_rule(&self, address: &FirewallAddress) -> Result<()> {
        let rule = format!(
            "-D {} -p {} -s {} -j DROP",
            STOP_BOTS_CHAIN, PROTOCOL, address.address
        );
        // Try to delete the rule - it might not exist
        let _ = self.run_iptables(rule.split_whitespace().collect::<Vec<_>>().as_slice());
        Ok(())
    }

    /// Removes a rule with a specific action.
    pub fn remove_rule(&self, address: &FirewallAddress, action: FirewallAction) -> Result<()> {
        let rule = format!(
            "-D {} -p {} -s {} -j {}",
            STOP_BOTS_CHAIN,
            PROTOCOL,
            address.address,
            action.to_iptables_action()
        );
        let _ = self.run_iptables(rule.split_whitespace().collect::<Vec<_>>().as_slice());
        Ok(())
    }

    /// Lists all rules in the stop-bots chain.
    pub fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        self.ensure_chain_exists()?;

        let output = self.run_iptables(&["-L", STOP_BOTS_CHAIN, "--line-numbers"])?;
        let mut rules = Vec::new();

        for line in output.lines() {
            // Parse line like: "num   target     prot opt source               destination"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[1] != "target" {
                let action = match parts[1] {
                    "DROP" => FirewallAction::Drop,
                    "REJECT" => FirewallAction::Reject,
                    "ACCEPT" => FirewallAction::Accept,
                    _ => continue,
                };

                let address_str = parts[3]; // source column
                rules.push(FirewallRule {
                    id: None,
                    address: FirewallAddress::new(address_str.to_string()),
                    port: None,
                    action,
                    enabled: true,
                });
            }
        }

        Ok(rules)
    }

    /// Clears all rules from the stop-bots chain.
    pub fn clear_rules(&self) -> Result<()> {
        // Flush the chain (remove all rules)
        let _ = self.run_iptables(&["-F", STOP_BOTS_CHAIN]);
        Ok(())
    }

    /// Cleans up the stop-bots chain.
    pub fn cleanup(&self) -> Result<()> {
        // Flush the chain
        let _ = self.run_iptables(&["-F", STOP_BOTS_CHAIN]);
        // Delete the chain
        let _ = self.run_iptables(&["-X", STOP_BOTS_CHAIN]);
        // Remove jump rule from INPUT chain
        let _ = self.run_iptables(&["-D", "INPUT", "-j", STOP_BOTS_CHAIN]);
        Ok(())
    }

    /// Syncs firewall rules with a list of addresses to block.
    ///
    /// This clears existing rules and adds new ones for all addresses.
    pub fn sync_block_rules(&self, addresses: &[FirewallAddress]) -> Result<()> {
        self.ensure_chain_exists()?;
        self.clear_rules()?;

        for address in addresses {
            self.add_block_rule(address)?;
        }

        Ok(())
    }

    /// Runs an iptables command and returns the output.
    fn run_iptables(&self, args: &[&str]) -> Result<String> {
        let output = if self.use_sudo {
            Command::new("sudo")
                .arg(&self.iptables_path)
                .args(args)
                .output()
                .with_context(|| format!("Failed to run: sudo iptables {}", args.join(" ")))?
        } else {
            Command::new(&self.iptables_path)
                .args(args)
                .output()
                .with_context(|| format!("Failed to run: iptables {}", args.join(" ")))?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!("iptables command failed: {}\\nstderr: {}", stdout, stderr);
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
        // Valid IP addresses
        assert!(FirewallAddress::new("192.168.1.1").is_valid());
        assert!(FirewallAddress::new("10.0.0.1").is_valid());
        assert!(FirewallAddress::new("8.8.8.8").is_valid());

        // Valid IPv6
        assert!(FirewallAddress::new("::1").is_valid());
        assert!(FirewallAddress::new("2001:db8::1").is_valid());

        // Valid CIDR
        assert!(FirewallAddress::new("192.168.1.0/24").is_valid());
        assert!(FirewallAddress::new("10.0.0.0/8").is_valid());
        assert!(FirewallAddress::new("8.8.8.0/24").is_valid());

        // Invalid
        assert!(!FirewallAddress::new("").is_valid());
        assert!(!FirewallAddress::new("not-an-ip").is_valid());
        assert!(!FirewallAddress::new("192.168.1.1/abc").is_valid());
    }

    #[test]
    fn test_firewall_action_display() {
        assert_eq!(format!("{}", FirewallAction::Drop), "DROP");
        assert_eq!(format!("{}", FirewallAction::Reject), "REJECT");
        assert_eq!(format!("{}", FirewallAction::Accept), "ACCEPT");
    }

    #[test]
    fn test_firewall_rule_display() {
        let rule = FirewallRule::new_block(FirewallAddress::new("1.2.3.4"));
        assert!(format!("{}", rule).contains("1.2.3.4"));

        let rule_with_port = FirewallRule::new_block(FirewallAddress::new("1.2.3.4")).with_port(80);
        assert!(format!("{}", rule_with_port).contains("port 80"));
    }
}
