//! Module for reading and writing NGINX configuration files.
//!
//! This module provides functionality to discover and read NGINX configuration
//! from common system locations.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
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
}
