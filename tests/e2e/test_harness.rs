//! Test harness for end-to-end tests.
//!
//! This module provides utilities for setting up a fake filesystem
//! and running the application in a controlled environment.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Represents a fake filesystem for testing.
/// This creates a temporary directory that acts as our /fake mount point.
pub struct FakeFilesystem {
    /// The temp directory (kept alive to prevent deletion)
    _temp_dir: TempDir,
    /// The root directory of the fake filesystem
    root: PathBuf,
    /// Path to the nginx config directory
    nginx_dir: PathBuf,
    /// Path to sites-enabled directory
    sites_enabled_dir: PathBuf,
    /// Path to conf.d directory
    conf_d_dir: PathBuf,
}

impl FakeFilesystem {
    /// Creates a new fake filesystem.
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let root = temp_dir.path().to_path_buf();

        // Create nginx directory structure
        let nginx_dir = root.join("nginx");
        let sites_enabled_dir = nginx_dir.join("sites-enabled");
        let conf_d_dir = nginx_dir.join("conf.d");

        fs::create_dir_all(&sites_enabled_dir)?;
        fs::create_dir_all(&conf_d_dir)?;

        Ok(Self {
            _temp_dir: temp_dir,
            root,
            nginx_dir,
            sites_enabled_dir,
            conf_d_dir,
        })
    }

    /// Returns the root path of the fake filesystem.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the path to the nginx directory.
    pub fn nginx_dir(&self) -> &Path {
        &self.nginx_dir
    }

    /// Returns the path to the sites-enabled directory.
    pub fn sites_enabled_dir(&self) -> &Path {
        &self.sites_enabled_dir
    }

    /// Returns the path to the conf.d directory.
    pub fn conf_d_dir(&self) -> &Path {
        &self.conf_d_dir
    }

    /// Adds an nginx main configuration file.
    pub fn add_nginx_main_config(&self, content: &str) -> Result<PathBuf> {
        let path = self.nginx_dir.join("nginx.conf");
        fs::write(&path, content).context("Failed to write nginx.conf")?;
        Ok(path)
    }

    /// Adds a site configuration to sites-enabled.
    pub fn add_site_config(&self, filename: &str, content: &str) -> Result<PathBuf> {
        let path = self.sites_enabled_dir.join(filename);
        fs::write(&path, content).context("Failed to write site config")?;
        Ok(path)
    }

    /// Returns the path for the STOP_BOTS_NGINX_CONFIG_PATHS environment variable.
    /// This should be a colon-separated list of paths.
    pub fn nginx_config_paths_env(&self) -> String {
        let mut paths = Vec::new();

        // Add main config path
        paths.push(
            self.nginx_dir
                .join("nginx.conf")
                .to_string_lossy()
                .into_owned(),
        );

        // Add sites-enabled directory
        paths.push(self.sites_enabled_dir.to_string_lossy().into_owned());

        // Add conf.d directory
        paths.push(self.conf_d_dir.to_string_lossy().into_owned());

        paths.join(":")
    }
}

/// Represents a running application process for testing.
pub struct RunningApp {
    /// The child process
    child: Child,
    /// The database path
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl RunningApp {
    /// Starts the application with the specified environment variables.
    #[allow(dead_code)]
    pub fn start(db_path: &Path, nginx_config_paths: &str) -> Result<Self> {
        Self::start_with_args(db_path, nginx_config_paths, &[])
    }

    /// Starts the application with scan-sites command.
    pub fn start_with_scan(db_path: &Path, nginx_config_paths: &str) -> Result<Self> {
        Self::start_with_args(db_path, nginx_config_paths, &["scan-sites"])
    }

    /// Starts the application with additional command-line arguments.
    fn start_with_args(
        db_path: &Path,
        nginx_config_paths: &str,
        extra_args: &[&str],
    ) -> Result<Self> {
        let mut args = vec!["run", "--"];
        args.extend(extra_args);

        let child = Command::new("cargo")
            .args(&args)
            .env("STOP_BOTS_DB_PATH", db_path.to_string_lossy().as_ref())
            .env("STOP_BOTS_NGINX_CONFIG_PATHS", nginx_config_paths)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Give the app a moment to start and complete the scan
        std::thread::sleep(Duration::from_millis(500));

        Ok(Self {
            child,
            db_path: db_path.to_path_buf(),
        })
    }

    /// Sends a key press to the application.
    #[allow(dead_code)]
    pub fn send_key(&mut self, key: char) -> Result<()> {
        if let Some(stdin) = self.child.stdin.as_mut() {
            use std::io::Write;
            stdin.write_all(&[key as u8])?;
            stdin.flush()?;
        }
        Ok(())
    }

    /// Sends multiple keys to the application.
    #[allow(dead_code)]
    pub fn send_keys(&mut self, keys: &str) -> Result<()> {
        for key in keys.chars() {
            self.send_key(key)?;
        }
        Ok(())
    }

    /// Waits for the app to process events and updates.
    pub fn wait_for_processing(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    /// Stops the application.
    pub fn stop(mut self) -> Result<()> {
        // Kill the process (sending 'q' doesn't work reliably with crossterm TUI)
        let _ = self.child.kill();

        // Wait for the process to finish
        let _ = self.child.wait();

        Ok(())
    }

    /// Returns the path to the database.
    #[allow(dead_code)]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

/// Generated random site name for each test run
pub fn generate_random_site_name() -> String {
    let uuid = Uuid::new_v4();
    format!("test-site-{}.example.com", uuid.simple())
}

/// Creates a basic nginx site configuration with the given site name
pub fn create_nginx_site_config(site_name: &str) -> String {
    format!(
        "# Site configuration for {}\n\nserver {{\n    listen       80;\n    listen       [::]:80;\n    server_name  {} www.{};\n\n    access_log  /var/log/nginx/{}.access.log;\n    error_log   /var/log/nginx/{}.error.log;\n\n    root        /var/www/{}/html;\n    index       index.html;\n\n    location / {{\n        try_files $uri $uri/ =404;\n    }}\n\n    location = /robots.txt {{\n        allow all;\n        log_not_found off;\n        access_log off;\n    }}\n\n}}\n",
        site_name, site_name, site_name, site_name, site_name, site_name
    )
}

/// Creates a basic nginx main configuration
pub fn create_nginx_main_config() -> String {
    String::from(
        "# Main NGINX configuration file\n\nuser  nginx;\nworker_processes  auto;\n\nerror_log  /var/log/nginx/error.log warn;\npid        /var/run/nginx.pid;\n\nevents {{\n    worker_connections  1024;\n}}\n\nhttp {{\n    include       /etc/nginx/mime.types;\n    default_type  application/octet-stream;\n\n    log_format  main  '$remote_addr - $remote_user [$time_local] \"$request\" '\
                      '$status $body_bytes_sent \"$http_referer\" '\
                      '\"$http_user_agent\" \"$http_x_forwarded_for\"';\n\n    access_log  /var/log/nginx/access.log  main;\n\n    sendfile        on;\n    keepalive_timeout  65;\n\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}}\n",
    )
}

/// Test context for end-to-end tests.
pub struct TestContext {
    /// The fake filesystem
    pub filesystem: FakeFilesystem,
    /// The database path
    pub db_path: PathBuf,
}

impl TestContext {
    /// Creates a new test context with a fake filesystem and database.
    pub fn new() -> Result<Self> {
        let filesystem = FakeFilesystem::new()?;

        // Create a temporary database file
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("stop-bots.db");

        Ok(Self {
            filesystem,
            db_path,
        })
    }

    /// Sets up the nginx config paths and creates configs.
    pub fn setup_nginx_with_site(&mut self, site_name: &str) -> Result<()> {
        // Add nginx main config
        self.filesystem
            .add_nginx_main_config(&create_nginx_main_config())?;

        // Add site config
        let config_content = create_nginx_site_config(site_name);
        self.filesystem
            .add_site_config(&format!("{}.conf", site_name), &config_content)?;

        Ok(())
    }

    /// Returns the nginx config paths environment variable value.
    pub fn nginx_config_paths_env(&self) -> String {
        self.filesystem.nginx_config_paths_env()
    }

    /// Starts the application.
    #[allow(dead_code)]
    pub fn start_app(&self) -> Result<RunningApp> {
        RunningApp::start(&self.db_path, &self.nginx_config_paths_env())
    }

    /// Starts the application with --scan-sites flag.
    pub fn start_app_with_scan(&self) -> Result<RunningApp> {
        RunningApp::start_with_scan(&self.db_path, &self.nginx_config_paths_env())
    }
}

/// Helper function to create a complete test environment with one site.
pub fn setup_test_with_site(site_name: &str) -> Result<TestContext> {
    let mut ctx = TestContext::new()?;
    ctx.setup_nginx_with_site(site_name)?;
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_filesystem_creation() -> Result<()> {
        let fs = FakeFilesystem::new()?;

        assert!(fs.root().exists());
        assert!(fs.nginx_dir().exists());
        assert!(fs.sites_enabled_dir().exists());
        assert!(fs.conf_d_dir().exists());

        Ok(())
    }

    #[test]
    fn test_fake_filesystem_add_configs() -> Result<()> {
        let fs = FakeFilesystem::new()?;

        // Add main config
        let main_path = fs.add_nginx_main_config("user nginx; events {}")?;
        assert!(main_path.exists());

        // Add site config
        let site_path = fs.add_site_config("test.com", "server { listen 80; }")?;
        assert!(site_path.exists());

        Ok(())
    }

    #[test]
    fn test_nginx_config_paths_env() -> Result<()> {
        let fs = FakeFilesystem::new()?;
        fs.add_nginx_main_config("user nginx;")?;

        let env_value = fs.nginx_config_paths_env();
        assert!(!env_value.is_empty());
        assert!(env_value.contains("nginx"));

        Ok(())
    }
}
