//! Stop Bots - Library crate
//!
//! This crate provides functionality for managing NGINX configurations
//! to stop bad bots while allowing good bots.

pub mod bots;
pub mod db;
pub mod iptables;
pub mod nginx;
pub mod nftables;
pub mod source_fetch;
pub mod tui;
