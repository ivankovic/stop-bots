/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! What applying a blocking policy to a web server's config means,
//! whichever web server it is.
//!
//! The split mirrors the firewall's ([`crate::firewall`] over
//! `nftables`/`iptables`): this module owns the policy ([`BlockConfig`]),
//! the transaction every apply runs in (lock, [`Snapshot`], write, test,
//! put back on a failure, reload), the generated files' lifecycle, and
//! taking everything out again. A backend module — [`crate::nginx`],
//! [`crate::apache`], [`crate::traefik`], [`crate::npmplus`] — owns only
//! what is spelled in its own config language: finding sites,
//! rendering and placing the sentinel block, and the generated files'
//! bodies. [`WebServer`] is the one place that dispatches between them.
//!
//! Every backend keeps the invariant `nginx` started with: the staleness
//! check compares the *rendered block* against what is on disk, so a knob
//! that shapes the generated text belongs on [`BlockConfig`] and nowhere
//! else.

use crate::db::BlockResponse;
pub use crate::dirfd::DirFile;
use crate::{apache, nginx, npmplus, traefik};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Which web server this host's sites are served by. A host setting
/// ([`crate::hostconf`]), never a database row: it decides which files root
/// rewrites and which commands root runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum WebServer {
    #[default]
    Nginx,
    Apache,
    Traefik,
    /// NPMplus, the Nginx Proxy Manager fork: NGINX in a container that
    /// writes its sites' config itself (see [`crate::npmplus`]).
    Npmplus,
}

impl WebServer {
    pub const ALL: [WebServer; 4] = [
        WebServer::Nginx,
        WebServer::Apache,
        WebServer::Traefik,
        WebServer::Npmplus,
    ];

    /// The value in `host.conf`'s `web_server`. Stored, so never renamed.
    pub fn id(self) -> &'static str {
        match self {
            WebServer::Nginx => "nginx",
            WebServer::Apache => "apache",
            WebServer::Traefik => "traefik",
            WebServer::Npmplus => "npmplus",
        }
    }

    pub fn from_id(id: &str) -> Option<WebServer> {
        WebServer::ALL.into_iter().find(|server| server.id() == id)
    }

    /// The web server the host settings choose, for a reader with no
    /// [`crate::hostconf::HostConf`] at hand. The file is world-readable;
    /// one that cannot be read is NGINX, as every host was before there
    /// was a choice.
    pub fn configured() -> WebServer {
        crate::hostconf::HostConf::load()
            .map(|host| host.web_server())
            .unwrap_or_default()
    }

    /// How the server is named to an operator.
    pub fn label(self) -> &'static str {
        match self {
            WebServer::Nginx => "NGINX",
            WebServer::Apache => "Apache",
            WebServer::Traefik => "Traefik",
            WebServer::Npmplus => "NPMplus",
        }
    }

    /// Where its config lives on a stock install.
    pub fn default_root(self) -> &'static str {
        match self {
            WebServer::Nginx => nginx::DEFAULT_ROOT,
            WebServer::Apache => apache::DEFAULT_ROOT,
            WebServer::Traefik => traefik::DEFAULT_ROOT,
            WebServer::Npmplus => npmplus::DEFAULT_ROOT,
        }
    }

    /// How to test its config on a stock install. Empty for Traefik,
    /// which has no config test: it checks what it reads as it reads it.
    /// NPMplus's is in the container its compose file names `npmplus`.
    pub fn default_test(self) -> &'static str {
        match self {
            WebServer::Nginx => "nginx -t",
            WebServer::Apache => "apache2ctl configtest",
            WebServer::Traefik => "",
            WebServer::Npmplus => "docker exec npmplus nginx -t",
        }
    }

    /// How to reload it on a stock install. Empty for Traefik, whose file
    /// provider reloads its directory by itself.
    pub fn default_reload(self) -> &'static str {
        match self {
            WebServer::Nginx => "systemctl reload nginx",
            WebServer::Apache => "systemctl reload apache2",
            WebServer::Traefik => "",
            WebServer::Npmplus => "docker exec npmplus nginx -s reload",
        }
    }

    /// Where its access log is on a stock install. NGINX and Apache write
    /// the `combined` format by default, and Traefik its `common` one,
    /// which reads the same way: what the detectors read.
    pub fn default_access_log(self) -> &'static str {
        match self {
            WebServer::Nginx => crate::accesslog::DEFAULT_LOG_PATH,
            WebServer::Apache => "/var/log/apache2/access.log",
            WebServer::Traefik => traefik::DEFAULT_ACCESS_LOG,
            WebServer::Npmplus => npmplus::DEFAULT_ACCESS_LOG,
        }
    }

    /// [`Self::default_test`] and [`Self::default_reload`], split. An
    /// empty one is no command at all.
    pub fn default_commands(self) -> ServerCommands {
        let split = |command: &str| {
            if command.is_empty() {
                Vec::new()
            } else {
                split_command(command).expect("the default commands parse")
            }
        };
        ServerCommands {
            test: split(self.default_test()),
            reload: split(self.default_reload()),
        }
    }

    /// [`Self::default_test`] for the config under `root`. Apache's
    /// differs between Debian's tree and RHEL's ([`apache::layout`]), and
    /// a default that names `apache2ctl` on RHEL fails every apply.
    pub fn default_test_at(self, root: &Path) -> &'static str {
        match self {
            WebServer::Nginx | WebServer::Traefik | WebServer::Npmplus => self.default_test(),
            WebServer::Apache => apache::layout(root).test(),
        }
    }

    /// [`Self::default_reload`] for the config under `root`, likewise.
    pub fn default_reload_at(self, root: &Path) -> &'static str {
        match self {
            WebServer::Nginx | WebServer::Traefik | WebServer::Npmplus => self.default_reload(),
            WebServer::Apache => apache::layout(root).reload(),
        }
    }

    /// [`Self::default_access_log`] for the config under `root`, likewise.
    pub fn default_access_log_at(self, root: &Path) -> &'static str {
        match self {
            WebServer::Nginx | WebServer::Traefik | WebServer::Npmplus => self.default_access_log(),
            WebServer::Apache => apache::layout(root).access_log(),
        }
    }

    /// Every site declared under `root`, one per named block. A `root`
    /// that does not exist is an error; see `nginx::discover_sites`.
    pub fn discover_sites(self, root: &Path) -> Result<Vec<DiscoveredSite>> {
        match self {
            WebServer::Nginx => nginx::discover_sites(root),
            WebServer::Apache => apache::discover_sites(root),
            WebServer::Traefik => traefik::discover_sites(root),
            WebServer::Npmplus => npmplus::discover_sites(root),
        }
    }

    /// Every file the config under `root` names as an access log, that is
    /// a file on this host to read: see `nginx::access_logs` and
    /// `apache::access_logs`. Paths as the config names them, which are
    /// this host's only when the server runs here (see
    /// [`crate::logpaths`]).
    pub fn access_logs(self, root: &Path) -> Vec<PathBuf> {
        match self {
            WebServer::Nginx => nginx::access_logs(root),
            WebServer::Apache => apache::access_logs(root),
            WebServer::Traefik => traefik::access_logs(root),
            WebServer::Npmplus => npmplus::access_logs(root),
        }
    }

    /// Every named block under `root` and the addresses it listens on, one
    /// entry per block: a site's port-80 and port-443 blocks are two.
    pub fn site_listens(self, root: &Path) -> Result<Vec<SiteListens>> {
        match self {
            WebServer::Nginx => nginx::site_listens(root),
            WebServer::Apache => apache::site_listens(root),
            WebServer::Traefik => traefik::site_listens(root),
            WebServer::Npmplus => npmplus::site_listens(root),
        }
    }

    /// What applying `site_configs` (and `default_config` for every block
    /// they do not name) to every block in `content` makes of it.
    ///
    /// `root` is the config root the file is under. Apache reads the rest
    /// of its config there, to refuse a block that would pass the config
    /// test and not do what it says (see `apache::refusal`).
    pub fn blocks_for_file(
        self,
        content: &str,
        config_path: &Path,
        root: &Path,
        site_configs: &[(String, BlockConfig)],
        default_config: &BlockConfig,
    ) -> Result<String> {
        match self {
            WebServer::Nginx => {
                let config_for = |block: &nginx::ServerBlock| {
                    Some(
                        block
                            .names
                            .first()
                            .and_then(|name| site_configs.iter().find(|(n, _)| n == name))
                            .map_or(default_config, |(_, config)| config),
                    )
                };
                if let Some(why) = nginx::refusal(content, config_path, root, config_for) {
                    anyhow::bail!("{why}");
                }
                nginx::blocks_for_file(content, config_path, site_configs, default_config)
            }
            WebServer::Apache => {
                apache::blocks_for_file(content, config_path, root, site_configs, default_config)
            }
            WebServer::Traefik => traefik::blocks_for_file(content, site_configs),
            WebServer::Npmplus => npmplus::blocks_for_file(content, site_configs, default_config),
        }
    }

    /// What applying `config` to only `server_name`'s blocks in `content`
    /// makes of it. `root` as for [`Self::blocks_for_file`].
    pub fn block_for_site(
        self,
        content: &str,
        config_path: &Path,
        root: &Path,
        server_name: &str,
        config: &BlockConfig,
    ) -> Result<String> {
        match self {
            WebServer::Nginx => {
                let config_for = |block: &nginx::ServerBlock| {
                    (block.names.first().map(String::as_str) == Some(server_name)).then_some(config)
                };
                if let Some(why) = nginx::refusal(content, config_path, root, config_for) {
                    anyhow::bail!("{why}");
                }
                nginx::block_for_site(content, config_path, server_name, config)
            }
            WebServer::Apache => {
                apache::block_for_site(content, config_path, root, server_name, config)
            }
            WebServer::Traefik => traefik::block_for_site(content, server_name, config),
            WebServer::Npmplus => npmplus::block_for_site(content, root, server_name, config),
        }
    }

    /// Whether what is written for `server_name` in `config_path` is what
    /// `config` renders to, without changing anything.
    pub fn site_apply_status(
        self,
        config_path: &Path,
        server_name: &str,
        config: &BlockConfig,
        root: &Path,
    ) -> SiteApplyStatus {
        match self {
            WebServer::Nginx => {
                // What an apply would refuse is not up to date, however the
                // file reads: the apply that would bring it up to date fails.
                let refused = fs::read_to_string(config_path).is_ok_and(|content| {
                    let config_for = |block: &nginx::ServerBlock| {
                        (block.names.first().map(String::as_str) == Some(server_name))
                            .then_some(config)
                    };
                    nginx::refusal(&content, config_path, root, config_for).is_some()
                });
                match nginx::site_apply_status(
                    config_path,
                    server_name,
                    config,
                    &nginx::conf_d_dir(root),
                ) {
                    SiteApplyStatus::UpToDate if refused => SiteApplyStatus::Stale,
                    status => status,
                }
            }
            WebServer::Apache => apache::site_apply_status(config_path, server_name, config, root),
            WebServer::Traefik => {
                traefik::site_apply_status(config_path, server_name, config, root)
            }
            WebServer::Npmplus => {
                npmplus::site_apply_status(config_path, server_name, config, root)
            }
        }
    }

    /// `content` with everything stop-bots injected into it taken out.
    pub fn without_injected_blocks(self, content: &str) -> String {
        match self {
            WebServer::Nginx => nginx::without_injected_blocks(content),
            WebServer::Apache => apache::without_injected_blocks(content),
            // Nothing is injected into an operator's file on Traefik.
            WebServer::Traefik => content.to_string(),
            WebServer::Npmplus => npmplus::without_injected_blocks(content),
        }
    }

    /// Every file under `root` stop-bots may have put a block into, which
    /// [`Self::without_injected_blocks`] takes it out of: each site's own
    /// file, and on NPMplus the two of its files every site includes.
    pub fn injected_files(self, root: &Path) -> Result<Vec<PathBuf>> {
        if self == WebServer::Npmplus {
            let mut paths = Vec::new();
            for path in npmplus::injected_files(root) {
                if under_hostile_root(root, &path)?.is_some_and(|file| file.is_regular()) {
                    paths.push(path);
                }
            }
            return Ok(paths);
        }
        let mut paths: Vec<PathBuf> = self
            .discover_sites(root)?
            .into_iter()
            .map(|site| site.config_path)
            .collect();
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// The generated files the current settings call for, as `(path,
    /// body)` pairs, in the order they may be written.
    pub fn planned_managed_files(
        self,
        db: &crate::db::Db,
        root: &Path,
    ) -> Result<Vec<(PathBuf, String)>> {
        match self {
            WebServer::Nginx => nginx::planned_managed_files(db, root),
            WebServer::Apache => apache::planned_managed_files(db, root),
            WebServer::Traefik => traefik::planned_managed_files(db, root),
            WebServer::Npmplus => npmplus::planned_managed_files(db, root),
        }
    }

    /// Where each generated file the current settings do *not* call for
    /// would be, were it written today.
    fn fallback_unused_managed_files(
        self,
        db: &crate::db::Db,
        root: &Path,
    ) -> Result<Vec<PathBuf>> {
        match self {
            WebServer::Nginx => nginx::fallback_unused_managed_files(db, root),
            WebServer::Apache => apache::fallback_unused_managed_files(db, root),
            WebServer::Traefik => traefik::fallback_unused_managed_files(db, root),
            WebServer::Npmplus => npmplus::fallback_unused_managed_files(db, root),
        }
    }

    /// The directories a recorded generated file may be removed from,
    /// each with its links resolved.
    fn managed_directories(self, root: &Path) -> Vec<PathBuf> {
        match self {
            WebServer::Nginx => nginx::managed_directories(root),
            WebServer::Apache => apache::managed_directories(root),
            WebServer::Traefik => traefik::managed_directories(root),
            WebServer::Npmplus => npmplus::managed_directories(root),
        }
    }

    /// Every name on the block that declares `server_name`, that one
    /// included; just `server_name` when the file says otherwise.
    pub fn server_names_for(self, config_path: &Path, server_name: &str) -> Vec<String> {
        match self {
            WebServer::Nginx => nginx::server_names_for(config_path, server_name),
            WebServer::Npmplus => npmplus::server_names_for(config_path, server_name),
            WebServer::Apache => apache::server_names_for(config_path, server_name),
            WebServer::Traefik => traefik::server_names_for(config_path, server_name),
        }
    }

    /// The application behind `server_name` in `config_path`, as
    /// [`crate::services::recognise`] reads it.
    pub fn site_service(
        self,
        config_path: &Path,
        server_name: &str,
    ) -> Option<crate::services::Service> {
        match self {
            WebServer::Nginx => nginx::site_service(config_path, server_name),
            WebServer::Npmplus => npmplus::site_service(config_path, server_name),
            WebServer::Apache => apache::site_service(config_path, server_name),
            WebServer::Traefik => traefik::site_service(config_path, server_name),
        }
    }

    /// Every directive of the blocks that serve `server_name` in
    /// `config_path`, under NGINX's directive names: what
    /// [`crate::webapps`] recognises an application from.
    pub fn site_directives(
        self,
        config_path: &Path,
        server_name: &str,
    ) -> Option<Vec<(String, Vec<String>)>> {
        match self {
            WebServer::Nginx => nginx::site_directives(config_path, server_name),
            WebServer::Npmplus => npmplus::site_directives(config_path, server_name),
            WebServer::Apache => apache::site_directives(config_path, server_name),
            WebServer::Traefik => traefik::site_directives(config_path, server_name),
        }
    }

    /// The directory of server-wide config every site inherits: NGINX's
    /// `conf.d`, Apache's `conf-enabled`. An `Alias /phpmyadmin` there,
    /// which Debian's phpMyAdmin package puts in Apache's, serves the path
    /// on every site. Traefik's root, whose files every router is read
    /// from alike. NPMplus's `custom_nginx`, whose files every host
    /// includes.
    pub fn global_conf_dir(self, root: &Path) -> PathBuf {
        match self {
            WebServer::Nginx => nginx::conf_d_dir(root),
            WebServer::Apache => apache::conf_enabled_dir(root),
            WebServer::Traefik => root.to_path_buf(),
            WebServer::Npmplus => root.join("custom_nginx"),
        }
    }

    /// Where the web console's Web Access put its own site, in subdomain
    /// mode, in a release that had one: `uninstall` takes it out.
    pub fn console_site_path(self, root: &Path) -> PathBuf {
        match self {
            WebServer::Nginx => nginx::console_site_path(root),
            WebServer::Apache => apache::console_site_path(root),
            WebServer::Traefik => traefik::console_site_path(root),
            WebServer::Npmplus => npmplus::console_site_path(root),
        }
    }

    /// What one site's block is called in this server's config, for a
    /// message.
    pub fn block_noun(self) -> &'static str {
        match self {
            WebServer::Nginx => "`server` block",
            WebServer::Apache => "<VirtualHost>",
            WebServer::Traefik => "router",
            WebServer::Npmplus => "proxy host",
        }
    }

    /// Why rate limiting does nothing on this server, if it does nothing:
    /// Apache has no request-rate limit of its own (only third-party
    /// modules), so no block written for it carries one. Every front-end
    /// asks before it offers the setting, rather than store one that reads
    /// as on and limits nothing.
    pub fn without_rate_limiting(self) -> Option<&'static str> {
        match self {
            WebServer::Nginx | WebServer::Npmplus => None,
            WebServer::Apache => Some(
                "Apache has no rate limiting of its own, so stop-bots writes none there: \
                 turning it on would limit nothing.",
            ),
            WebServer::Traefik => Some(
                "Traefik limits rates only in a middleware on each site's own router, which \
                 stop-bots does not write, so turning it on would limit nothing.",
            ),
        }
    }

    /// Why the generated `robots.txt` is served by nothing on this server,
    /// if it is not: Traefik serves no files. Asked before the setting is
    /// offered, as [`Self::without_rate_limiting`] is.
    pub fn without_robots_txt(self) -> Option<&'static str> {
        match self {
            WebServer::Nginx | WebServer::Apache | WebServer::Npmplus => None,
            WebServer::Traefik => Some(
                "Traefik serves no files, so nothing would serve the generated robots.txt: \
                 turning it on would publish nothing.",
            ),
        }
    }

    /// What a blocked request gets instead, when this server cannot send
    /// `response`: Apache sends no `444`, no `418` and no tarpit, and
    /// Traefik nothing but a plain `403` (see each one's module docs).
    /// `None` when it sends `response` itself.
    pub fn instead_of(self, response: BlockResponse) -> Option<u16> {
        let exact = match self {
            WebServer::Nginx | WebServer::Npmplus => true,
            WebServer::Apache => !matches!(
                response,
                BlockResponse::Close | BlockResponse::Teapot | BlockResponse::Tarpit
            ),
            WebServer::Traefik => response == BlockResponse::Forbidden,
        };
        (!exact).then_some(403)
    }

    /// Whether someone other than root can write under the config root:
    /// NPMplus's data directory is its container's.
    ///
    /// On such a root nothing below it is reached by path. It is resolved
    /// once, being the operator's own choice, and every file under it is
    /// read, written, put back and removed through its directory, opened
    /// without following a link ([`DirFile`]): a link planted there would
    /// otherwise take root's write, or the bytes root reads and writes
    /// back, anywhere on the host. See [`under_hostile_root`].
    pub fn root_is_hostile(self) -> bool {
        self == WebServer::Npmplus
    }

    /// The verb that stores this server's commands and config root.
    pub fn commands_verb(self) -> &'static str {
        match self {
            WebServer::Nginx => "set-web-server nginx",
            WebServer::Apache => "set-web-server apache",
            WebServer::Traefik => "set-web-server traefik",
            WebServer::Npmplus => "set-web-server npmplus",
        }
    }
}

/// A site discovered while scanning a config directory.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredSite {
    pub server_name: String,
    pub config_path: PathBuf,
}

/// What a backup or an editor leaves behind ends in, after its last `.`:
/// `site.conf.bak`, `conf.d.bak-2026-10-12`, `default.dpkg-dist`.
const BACKUP_SUFFIXES: &[&str] = &[
    "bak",
    "backup",
    "backups",
    "orig",
    "old",
    "save",
    "swp",
    "rpmsave",
    "rpmnew",
    "dpkg-old",
    "dpkg-dist",
    "dpkg-new",
    "dpkg-bak",
    "ucf-old",
    "ucf-dist",
    "ucf-new",
];

/// Whether a file or directory named `name` is a copy kept beside the
/// config rather than config: a backup, a package manager's leftover or an
/// editor's. Judged by what follows the last `.`, after any purely numeric
/// parts (`site.conf.bak.1`), so `backup.example.com.conf` is a site and
/// `site.bak.conf` — which `include conf.d/*.conf` loads — is too.
pub(crate) fn is_backup_name(name: &str) -> bool {
    if name.ends_with('~') || (name.starts_with('#') && name.ends_with('#')) {
        return true;
    }
    let last = name
        .rsplit('.')
        .find(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(name)
        .to_ascii_lowercase();
    BACKUP_SUFFIXES.iter().any(|suffix| {
        last.strip_prefix(suffix).is_some_and(|rest| {
            rest.is_empty()
                || rest.starts_with(['-', '_'])
                || rest.starts_with(|c: char| c.is_ascii_digit())
        })
    })
}

/// The regular files under `root` that may hold sites. Links are not
/// followed, so Debian's `sites-enabled` links lead nowhere and each site
/// is found once, in `sites-available`; and nothing at or under a backup's
/// name ([`is_backup_name`]) is, because a copy of a site is not a site.
/// Counting one made a second row for every site it copied, wrote blocks
/// into it on every apply, and left that row naming a missing file once
/// the copy was cleaned up. Anything unreadable is skipped.
///
/// So is anything over [`MAX_CONFIG_BYTES`], by its size, before a byte of
/// it is read. Every caller reads each file whole, and a root is not
/// always a tree of config: one set to a container's data directory holds
/// its access logs too. Reading those whole, gigabytes at a time, on every
/// `tick` and before `set-web-server` would switch away, took a host's
/// memory and its CPU with it.
pub(crate) fn config_files(root: &Path) -> impl Iterator<Item = walkdir::DirEntry> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0 || !is_backup_name(&entry.file_name().to_string_lossy())
        })
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|meta| meta.len() <= MAX_CONFIG_BYTES)
        })
}

/// The largest file [`config_files`] reads: larger than any file that
/// declares a site, with every bot list's block in it, and far smaller
/// than a log.
pub(crate) const MAX_CONFIG_BYTES: u64 = 4 << 20;

/// The text of the regular file at `path`, read without following a link
/// at it or waiting on a FIFO: `None` for anything else, or nothing.
///
/// For a file [`config_files`] found, which it found as a regular file
/// and not a link: read this way, one swapped for a link or a FIFO since
/// is not followed, and cannot hang the apply that holds the lock. Nor is
/// one over [`MAX_CONFIG_BYTES`], as [`config_files`] skips: on a root
/// another user can write, one could grow between the two.
pub(crate) fn read_regular_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let file = crate::db::guard::open_nofollow(path).ok()??;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_CONFIG_BYTES).then_some(text)
}

/// One address a site is served on, as its config declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Listen {
    /// `None` for every address (`listen 80`, `*:80`, `_default_:443`)
    /// and for one given by host name.
    pub address: Option<std::net::IpAddr>,
    pub port: u16,
    pub tls: bool,
}

impl Listen {
    /// The address and port in `text`, the way both servers write one:
    /// `80`, `*:80`, `127.0.0.1:8080`, `[::]:443`, `example.com:80`, or
    /// an address with no port, which is 80. `None` for a Unix socket or
    /// a port that is not a number.
    pub fn parse_address(text: &str) -> Option<(Option<std::net::IpAddr>, u16)> {
        if text.starts_with("unix:") {
            return None;
        }
        if let Some(v6) = text.strip_prefix('[') {
            let (address, rest) = v6.split_once(']')?;
            let port = match rest.strip_prefix(':') {
                Some(port) => port.parse().ok()?,
                None => 80,
            };
            return Some((address.parse().ok(), port));
        }
        if text.bytes().all(|b| b.is_ascii_digit()) {
            return Some((None, text.parse().ok()?));
        }
        match text.rsplit_once(':') {
            Some((host, port)) => Some((host.parse().ok(), port.parse().ok()?)),
            None => Some((text.parse().ok(), 80)),
        }
    }
}

/// A site by its name, with every address one of its blocks listens on.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteListens {
    pub server_name: String,
    /// Empty for a block with no `listen` (or an Apache host with no
    /// address), which is served on port 80.
    pub listens: Vec<Listen>,
}

/// An optional per-site rule that decides a request is unwanted from its
/// *shape* rather than from a user-agent pattern.
///
/// Each is a separate toggle rather than one "strict requests" switch, and
/// deliberately so: if four rules hid behind one setting and an admin's
/// monitoring stopped working, they'd have no way to tell which one did
/// it. Every variant is off by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestRule {
    /// HTTP/1.0 and HTTP/1.1. Only emitted in TLS blocks — see
    /// [`for_block`].
    Http1x,
    /// No `Accept` header. Every browser sends one; a fair amount of
    /// tooling sends nothing.
    NoAccept,
    /// No `Accept-Language`. Browsers send it; most scripts don't. Weaker
    /// than `NoAccept` — some privacy configurations strip it.
    NoAcceptLanguage,
    /// Empty or absent `User-Agent`. Distinct from bot-pattern matching,
    /// which can only catch agents that identify themselves.
    NoUserAgent,
    /// A `Host` that is a bare IP address rather than a name. Scanners
    /// sweep address ranges; real visitors arrive by hostname.
    IpLiteralHost,
    /// TLS 1.0 and 1.1. The same "only modern clients" argument as
    /// [`Self::Http1x`] but on firmer ground — both are formally
    /// deprecated and no current browser offers them. Inert outside a TLS
    /// block, where `$ssl_protocol` is empty.
    OldTls,
}

impl RequestRule {
    pub const ALL: [RequestRule; 6] = [
        RequestRule::Http1x,
        RequestRule::NoAccept,
        RequestRule::NoAcceptLanguage,
        RequestRule::NoUserAgent,
        RequestRule::IpLiteralHost,
        RequestRule::OldTls,
    ];

    /// Stable id — a `site_request_rules.rule` value in every installed
    /// database, so never rename one without a migration.
    pub fn id(self) -> &'static str {
        match self {
            RequestRule::Http1x => "http_1x",
            RequestRule::NoAccept => "no_accept",
            RequestRule::NoAcceptLanguage => "no_accept_language",
            RequestRule::NoUserAgent => "no_user_agent",
            RequestRule::IpLiteralHost => "ip_literal_host",
            RequestRule::OldTls => "old_tls",
        }
    }

    pub fn from_id(id: &str) -> Option<RequestRule> {
        RequestRule::ALL.into_iter().find(|r| r.id() == id)
    }

    pub fn label(self) -> &'static str {
        match self {
            RequestRule::Http1x => "HTTP/1.x requests",
            RequestRule::NoAccept => "No Accept header",
            RequestRule::NoAcceptLanguage => "No Accept-Language",
            RequestRule::NoUserAgent => "No User-Agent",
            RequestRule::IpLiteralHost => "Host is an IP",
            RequestRule::OldTls => "TLS 1.0 / 1.1",
        }
    }

    /// What the rule turns away and why that catches bots, for the TUI's
    /// `?`.
    pub fn about(self) -> &'static str {
        match self {
            RequestRule::Http1x => {
                "Turns away requests over HTTP/1.0 and 1.1 on HTTPS. Every current browser \
                 speaks HTTP/2 there; much bot tooling still does not."
            }
            RequestRule::NoAccept => {
                "Turns away requests with no Accept header. Every browser sends one; a fair \
                 amount of tooling sends nothing."
            }
            RequestRule::NoAcceptLanguage => {
                "Turns away requests with no Accept-Language header. Browsers send it; most \
                 scripts do not. Weaker than No Accept header, as some privacy setups strip it."
            }
            RequestRule::NoUserAgent => {
                "Turns away requests with an empty or missing user agent, which the bot lists \
                 cannot catch: they match only agents that name themselves."
            }
            RequestRule::IpLiteralHost => {
                "Turns away requests addressed to the server's IP address rather than the \
                 site's name. Scanners sweep address ranges; visitors arrive by name."
            }
            RequestRule::OldTls => {
                "Turns away connections over TLS 1.0 and 1.1, which are formally deprecated \
                 and offered by no current browser."
            }
        }
    }

    /// A one-line note on what this turns away besides bots, shown next to
    /// the toggle. Every one of these has collateral; saying so at the
    /// point of the decision is the whole point.
    pub fn caveat(self) -> &'static str {
        match self {
            RequestRule::Http1x => "also turns away crawlers and API clients",
            RequestRule::NoAccept => "some API clients send none",
            RequestRule::NoAcceptLanguage => "privacy tooling strips it",
            RequestRule::NoUserAgent => "scripts and health checks often omit it",
            RequestRule::IpLiteralHost => "breaks reaching the site by IP",
            RequestRule::OldTls => "very old clients only",
        }
    }

    /// Whether the rule can only work in a TLS-terminating block.
    pub(crate) fn needs_tls(self) -> bool {
        matches!(self, RequestRule::Http1x | RequestRule::OldTls)
    }
}

/// Everything that shapes one site's generated sentinel block. Grouped into
/// a struct rather than passed as loose arguments because the block's
/// *content* is what [`site_apply_status`] compares against disk: every
/// field here is something that, when changed, must make an
/// already-applied site read as `Stale`. Adding a knob that affects the
/// generated text without adding it here would silently break that check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockConfig {
    /// The per-site blocked user-agent patterns, as computed by
    /// `Db::blocked_user_agent_patterns_for_site`. Empty means "block
    /// nothing", which removes any existing sentinel block.
    pub patterns: Vec<String>,
    /// How a matched request is turned away — host-wide, but carried here
    /// per site since it's part of the rendered text.
    pub response: BlockResponse,
    /// Whether to serve the generated `robots.txt` (see
    /// [`robots_txt_path`]) from this site. Host-wide, like `response`.
    ///
    /// Only a flag, not the body: the body can run to several kilobytes
    /// with every AI bot listed, and NGINX's config parser rejects a
    /// single quoted parameter past roughly 4KB (the same ceiling
    /// [`MAX_PATTERN_CHUNK_LEN`] exists for), so `return 200 "<body>"` is
    /// not an option. The block `alias`es a file instead, so the body
    /// never appears in the config text at all — which also keeps the
    /// staleness comparison stable when only the body changes.
    pub serve_robots_txt: bool,
    /// Per-server rate limiting: `Some(burst)` emits a `limit_req`
    /// referencing the shared zone, `None` emits nothing.
    ///
    /// Only the burst, not the rate: the rate belongs to `limit_req_zone`,
    /// which is an `http`-context directive living in a separate file (see
    /// [`rate_limit_conf_path`]). Carrying the rate here too would invite
    /// writing it into a `server` block where NGINX rejects it.
    pub rate_limit_burst: Option<u32>,
    /// Request-path prefixes this site's bot block does not apply to.
    ///
    /// Non-empty switches the block to its second shape (see
    /// [`block_text`]): a `set $stop_bots_block` flag rather than a direct
    /// `return`, because NGINX has no way to say "match this user agent
    /// unless the path is one of these" in a single condition.
    pub exempt_paths: Vec<String>,
    /// Request-path prefixes exempt only for clients whose user agent
    /// contains the given string, sorted by user agent (see
    /// [`crate::db::AgentExemption`]). Rendered by
    /// [`agent_exemption_clears`], after every set like the other clears.
    pub agent_exemptions: Vec<crate::db::AgentExemption>,
    /// Per-site [`RequestRule`]s switched on for this site.
    ///
    /// These decide a request is unwanted from its shape rather than from
    /// a user-agent pattern, and they are the bluntest instruments in the
    /// project. Two things make them survivable, and both are enforced
    /// rather than documented:
    ///
    /// 1. **TLS-only rules are dropped in non-TLS blocks** (see
    ///    [`for_block`]). Browsers don't negotiate HTTP/2 without TLS, so
    ///    on a `listen 80` block every request is HTTP/1.1 — and a site's
    ///    port-80 and port-443 blocks routinely share one `server_name`,
    ///    which is what a per-site setting keys on.
    /// 2. **`/.well-known/` is always exempt** whenever any of these is on
    ///    (see `effective_exempt_paths`). ACME HTTP-01 validation is
    ///    fetched over HTTP/1.1 by a non-browser client with no `Accept`
    ///    and often no `User-Agent`; blocking it doesn't fail now, it
    ///    fails at certificate renewal weeks later.
    ///
    /// What no guard fixes: each rule turns away some legitimate
    /// non-browser client. See [`RequestRule::caveat`].
    pub request_rules: Vec<RequestRule>,
    /// What this host trusts (see [`Trust`]), or `None` when it trusts
    /// nothing.
    ///
    /// Only whether it is `Some` reaches the block text — one check that
    /// clears the flag. The lists are carried anyway because they are part
    /// of what this site's protection *is*: trusting a second user agent
    /// changes no site's block, only the generated trust file, and a site
    /// whose file is out of date must still read as `Stale` or nobody will
    /// apply it. See `nginx::trust_file_is_current`.
    pub trust: Option<Trust>,
}

/// The addresses and user agents no block, list or rate limit applies to,
/// each one checked again here rather than trusted as stored: a backend
/// writes these into a file its web server loads as root, where a bad
/// entry would not break one site but stop the server loading at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Trust {
    /// Addresses and CIDR ranges, trimmed, each a valid one.
    pub addresses: Vec<String>,
    /// User agents, each matched as a case-insensitive substring.
    pub user_agents: Vec<String>,
}

impl Trust {
    /// What `db` trusts, or `None` when nothing usable is trusted — in
    /// which case no generated file exists, and no block mentions one.
    pub fn of(db: &crate::db::Db) -> Result<Option<Trust>> {
        Ok(Trust::from_lists(
            &db.list_trusted_addresses()?,
            &db.list_trusted_user_agents()?,
        ))
    }

    /// The usable entries of `addresses` and `user_agents`, or `None` when
    /// there are none.
    pub fn from_lists(addresses: &[String], user_agents: &[String]) -> Option<Trust> {
        let user_agents: Vec<String> = user_agents
            .iter()
            .filter(|ua| is_stored_as_valid(ua, crate::db::validate_trusted_user_agent))
            .cloned()
            .collect();
        // Trimmed before it is checked and written alike: the check trims,
        // so what it passed is the trimmed text, and that is all that is
        // written.
        let addresses: Vec<String> = addresses
            .iter()
            .map(|a| a.trim())
            .filter(|a| crate::db::is_valid_address(a))
            .map(str::to_string)
            .collect();
        (!addresses.is_empty() || !user_agents.is_empty()).then_some(Trust {
            addresses,
            user_agents,
        })
    }
}

impl BlockConfig {
    /// The common case: patterns plus the host-wide response setting.
    pub fn new(patterns: Vec<String>, response: BlockResponse) -> Self {
        BlockConfig {
            patterns,
            response,
            ..BlockConfig::default()
        }
    }
}

/// Builds the `robots.txt` body from the current blocking policy: one
/// `User-agent:` line per blocked bot, a single shared `Disallow: /`, and
/// a `Disallow:` for the honeypot trap path.
///
/// **Grouped under one `Disallow`, not one stanza per bot.** Both are
/// valid, and grouping roughly halves a file that can otherwise list well
/// over a thousand agents. It also makes the intent obvious at a glance
/// rather than burying it in repetition.
///
/// **A robots token, not a regex.** `bot.user_agent_pattern` is an NGINX
/// regex fragment (and often an alternation); robots.txt has no regex, so
/// the *name* is used, and only when it's a single word that could
/// plausibly be a real token. Anything with whitespace or regex
/// metacharacters is skipped rather than emitted as a broken rule — a
/// `User-agent:` line no crawler matches is worse than no line, because it
/// looks like coverage that isn't there.
///
/// **The honeypot line is emitted whether or not the honeypot detector is
/// on.** Publishing the trap path is what *creates* the trap; a detector
/// that's off simply doesn't act on hits yet. Publishing it only when the
/// detector is enabled would mean turning the detector on and then waiting
/// for crawlers to re-read robots.txt before it could ever fire.
pub fn robots_txt_body(db: &crate::db::Db) -> Result<String> {
    let blocked: Vec<String> = db
        .list_bots()?
        .into_iter()
        .filter(|bot| db.bot_is_blocked(bot).unwrap_or(false))
        .filter_map(|bot| robots_token(&bot))
        .collect();

    let mut out = managed_header();
    out.push('\n');
    if blocked.is_empty() {
        // Still a valid, meaningful robots.txt: "everyone may crawl
        // everything except the trap". Emitting nothing here would make an
        // enabled feature serve an empty file, which reads as broken.
        out.push_str("User-agent: *\nDisallow:\n\n");
    } else {
        for name in &blocked {
            out.push_str(&format!("User-agent: {name}\n"));
        }
        out.push_str("Disallow: /\n\n");
    }

    let trap = crate::protection::honeypot_path(db)?;
    out.push_str("User-agent: *\n");
    out.push_str(&format!("Disallow: {trap}\n"));
    Ok(out)
}

/// The `User-agent:` token to publish for `bot`, or `None` if nothing
/// usable can be derived.
///
/// **Prefers the user-agent pattern over the display name**, which is not
/// a cosmetic choice. A bot's `name` is humanised from its slug by the
/// well-known-bots parser — `ai-search-bot` becomes `Ai Search Bot` — so
/// it is both mis-cased *and* contains spaces, and a name with spaces is
/// no use as a robots token. Filtering on the name alone meant the
/// generated robots.txt listed **none** of that source's bots while still
/// being served: a file that forbade nobody, which is worse than no file,
/// because it looks like the feature is working.
///
/// The pattern is the substring the bot actually sends, which is exactly
/// what a robots token is. Backslash escapes are undone (patterns are
/// NGINX regex fragments: `Googlebot\/`), a trailing `/` is trimmed
/// (`Googlebot/` is a UA prefix, not a token), and only the first
/// alternative of a merged pattern is used — one `User-agent:` line has
/// room for one token.
fn robots_token(bot: &crate::db::Bot) -> Option<String> {
    let first = bot.user_agent_pattern.split('|').next().unwrap_or_default();
    let unescaped = first.replace('\\', "");
    let candidate = unescaped.trim_end_matches('/');
    if is_robots_token(candidate) {
        return Some(candidate.to_string());
    }
    // A name that happens to be a clean token (ai.robots.txt keys entries
    // by the real token, so this is the common path for that source).
    is_robots_token(&bot.name).then(|| bot.name.clone())
}

/// Whether `name` can be used verbatim as a robots.txt `User-agent:`
/// value. Deliberately strict: robots.txt matching is a simple
/// case-insensitive substring test with no escaping, so anything with
/// whitespace or punctuation beyond the few characters real tokens use
/// is rejected rather than guessed at.
pub(crate) fn is_robots_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// The burst to emit for this host, or `None` when rate limiting is off.
pub(crate) fn rate_limit_burst(db: &crate::db::Db) -> Result<Option<u32>> {
    if !db.get_rate_limit_enabled()? {
        return Ok(None);
    }
    Ok(Some(db.get_rate_limit_burst()? as u32))
}

/// The first line of every file this module writes whole: which version
/// generated it, and that it is not for editing.
///
/// Only in whole files. The sentinel block inside an operator's site file
/// carries no version, for the reasons `crate::generated` gives.
pub(crate) fn managed_header() -> String {
    format!(
        "# {}. Edits will be overwritten.\n",
        crate::generated::generated_by()
    )
}

/// Creates or updates every file the config about to be written will
/// reference. **Runs before any site config is touched**, so an `alias` or
/// a `limit_req` never points at something that isn't there yet.
///
/// Deliberately does not delete anything — see
/// [`remove_unused_managed_files`] for why the two halves are separate.
pub fn write_managed_files(server: WebServer, db: &crate::db::Db, root: &Path) -> Result<usize> {
    let files = server.planned_managed_files(db, root)?;
    record_managed_files(db, &files)?;
    write_planned_managed_files(server, root, &files)
}

/// What a generated file is, as the `managed_files` record spells
/// it.
///
/// Declared in the order these files can be removed in: a file that reads
/// a variable or a zone another one defines goes before it (see
/// [`unused_managed_files`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedKind {
    /// `stop-bots-limits-untrusted.conf`, which reads the trust file's
    /// variable.
    UntrustedLimits,
    /// `stop-bots-limits.conf`.
    Limits,
    /// The generated `robots.txt`.
    RobotsTxt,
    /// `stop-bots-trusted.conf`, which the untrusted zone reads.
    Trusted,
    /// Traefik's `stop-bots.yml`, which nothing of anyone else's reads.
    TraefikRouters,
}

impl ManagedKind {
    const ALL: [ManagedKind; 5] = [
        ManagedKind::UntrustedLimits,
        ManagedKind::Limits,
        ManagedKind::RobotsTxt,
        ManagedKind::Trusted,
        ManagedKind::TraefikRouters,
    ];

    /// The id in `managed_files.kind`. Stored, so never renamed.
    pub fn id(self) -> &'static str {
        match self {
            ManagedKind::UntrustedLimits => "nginx-untrusted-limits",
            ManagedKind::Limits => "nginx-limits",
            ManagedKind::RobotsTxt => "nginx-robots-txt",
            ManagedKind::Trusted => "nginx-trusted",
            ManagedKind::TraefikRouters => "traefik-routers",
        }
    }

    pub fn from_id(id: &str) -> Option<ManagedKind> {
        ManagedKind::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// The kind of a file this module writes, by its name — which is
    /// fixed for each kind wherever the file lives.
    pub fn of(path: &Path) -> Option<ManagedKind> {
        let name = path.file_name()?.to_str()?;
        let conf_d = Path::new("");
        ManagedKind::ALL.into_iter().find(|kind| {
            let own = match kind {
                ManagedKind::UntrustedLimits => nginx::untrusted_rate_limit_conf_path(conf_d),
                ManagedKind::Limits => nginx::rate_limit_conf_path(conf_d),
                ManagedKind::RobotsTxt => PathBuf::from("robots.txt"),
                ManagedKind::Trusted => nginx::trusted_conf_path(conf_d),
                ManagedKind::TraefikRouters => traefik::routers_path(conf_d),
            };
            own.as_os_str() == name
        })
    }
}

/// Records every file in `files` as about to be written, and forgets
/// recorded ones that are gone and not about to come back.
///
/// **Before the write, not after.** The record is what cleaning up works
/// from, so it must never be missing a file that exists: a process that
/// dies between the two leaves a row for a file that may not exist, which
/// costs one no-op removal, rather than a file no row names, which would
/// never be removed at all.
///
/// Called wherever a `Db` is at hand ahead of [`write_planned_managed_files`]:
/// here, by [`write_managed_files`] and [`apply_site_and_reload`], and by
/// the TUI when it plans an apply on the main thread.
pub fn record_managed_files(db: &crate::db::Db, files: &[(PathBuf, String)]) -> Result<()> {
    let recorded: Vec<PathBuf> = files.iter().map(|(path, _)| recorded_form(path)).collect();
    for path in &recorded {
        if let Some(kind) = ManagedKind::of(path) {
            db.record_managed_file(path, kind.id())?;
        }
    }
    for row in db.managed_files()? {
        let known = ManagedKind::from_id(&row.kind).is_some();
        let planned = recorded.contains(&row.path);
        if known && !planned && fs::symlink_metadata(&row.path).is_err() {
            db.forget_managed_file(&row.path)?;
        }
    }
    Ok(())
}

/// `path` as the record keeps it: its directory resolved, so that the
/// record names it the way [`unused_managed_files`] will accept it back
/// (see [`DirFile::exactly`]). As it is if its directory is not there yet.
fn recorded_form(path: &Path) -> PathBuf {
    match (path.parent().map(fs::canonicalize), path.file_name()) {
        (Some(Ok(dir)), Some(name)) => dir.join(name),
        _ => path.to_path_buf(),
    }
}

/// Whether the regular file `file` is one this project generated, by its
/// header. Read through its directory's descriptor, without following a
/// link or waiting on a FIFO.
///
/// Asked before removing a file the record names in a place the current
/// settings would not write to: the record says stop-bots wrote a file
/// there once, and this says it is still that file rather than one an
/// operator has since put in its place.
pub fn is_generated(file: &DirFile) -> bool {
    file.first_line()
        .is_some_and(|first| first.starts_with('#') && first.contains("Generated by stop-bots"))
}

/// `path`, under `root`, as it is with `root` resolved: the one place a
/// link is followed on a root that is hostile
/// ([`WebServer::root_is_hostile`]).
fn resolved_under(root: &Path, path: &Path) -> Result<PathBuf> {
    let resolved = fs::canonicalize(root)
        .with_context(|| format!("failed to read the config root {}", root.display()))?;
    let below = path
        .strip_prefix(root)
        .or_else(|_| path.strip_prefix(&resolved))
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    Ok(resolved.join(below))
}

/// `path`, under a `root` someone else can write, held through its
/// directory: `root` resolved, and everything below it opened without
/// following a link ([`DirFile::exactly`]). `None` when its directory is
/// not there, in which case neither is the file; an error when a link is
/// on the way.
pub(crate) fn under_hostile_root(root: &Path, path: &Path) -> Result<Option<DirFile>> {
    let resolved = resolved_under(root, path)?;
    match DirFile::exactly(&resolved) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| {
            format!(
                "refusing to use {}: a link, or something else that is not a directory, is on \
                 the way to it, under a root another user can write",
                path.display()
            )
        }),
    }
}

/// [`under_hostile_root`], creating its directory first if it is not
/// there, through the directory above it ([`create_dir_nofollow`]).
fn under_hostile_root_created(root: &Path, path: &Path) -> Result<DirFile> {
    let resolved = resolved_under(root, path)?;
    if let Some(dir) = resolved.parent() {
        crate::dirfd::create_dir_nofollow(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    under_hostile_root(root, path)?
        .with_context(|| format!("{} disappeared as it was made", resolved.display()))
}

/// The text of `path`, a file under `root`, read as `server` must read it,
/// or `None` when there is none: on a hostile root through its directory,
/// following no link and never waiting on a FIFO, so that only a regular
/// file is read at all.
pub(crate) fn read_under(server: WebServer, root: &Path, path: &Path) -> Result<Option<String>> {
    if !server.root_is_hostile() {
        return match fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
        };
    }
    let Some(file) = under_hostile_root(root, path)? else {
        return Ok(None);
    };
    let Some((bytes, _)) = file
        .read()
        .with_context(|| format!("failed to read {}", path.display()))?
    else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Some)
        .with_context(|| format!("{} is not text", path.display()))
}

/// Writes `content` at `path`, a file under `root`, as `server` must: on a
/// hostile root through its directory, following no link, keeping the
/// owner of the file it replaces and none of its setuid, setgid or sticky
/// bits; otherwise as a site file ([`write_site_file`]).
fn write_under(server: WebServer, root: &Path, path: &Path, content: &str) -> Result<()> {
    if !server.root_is_hostile() {
        return write_site_file(path, root, content);
    }
    let file = under_hostile_root_created(root, path)?;
    let (mode, owner) = match file.mode_and_owner()? {
        Some((mode, owner)) => (mode & 0o777, Some(owner)),
        None => (0o644, None),
    };
    file.write_atomically_owned(content.as_bytes(), mode, owner)
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Writes what [`planned_managed_files`] resolved. Touches no `Db`.
///
/// Returns how many files it actually changed, because that can be the
/// whole of an apply: trusting a second user agent rewrites the trust
/// file and no site's block, and an apply that counted only site files
/// would decide NGINX had nothing new to read and never reload it.
///
/// On a root another user can write ([`WebServer::root_is_hostile`]) each
/// file is compared and written through its directory, following no link
/// ([`write_under`]): the generated files, and the operator's own that
/// carry a block, NPMplus's `server_http.conf` and `http_top.conf`, which
/// keep their owner.
pub fn write_planned_managed_files(
    server: WebServer,
    root: &Path,
    files: &[(PathBuf, String)],
) -> Result<usize> {
    let mut changed = 0;
    for (path, body) in files {
        let current = if server.root_is_hostile() {
            read_under(server, root, path)?
        } else {
            fs::read_to_string(path).ok()
        };
        if current.as_deref() == Some(body.as_str()) {
            continue;
        }
        if server.root_is_hostile() {
            write_under(server, root, path, body)?;
        } else {
            write_managed(path, body)?;
        }
        changed += 1;
    }
    Ok(changed)
}

/// Deletes every file this project owns that the current settings no
/// longer reference. **Runs after site configs have been rewritten**, and
/// that ordering is load-bearing rather than tidy:
///
/// A `server` block containing `limit_req zone=stop_bots;` whose
/// `limit_req_zone` has been deleted is not a degraded config, it's an
/// invalid one — NGINX refuses to load with "unknown limit_req_zone", so
/// `nginx -t` fails and the *whole* reload is rejected, including every
/// unrelated site. Removing the zone only once no block references it any
/// more means the config on disk is valid at every point in between, so
/// an apply that dies half way (a permission error on one file, say)
/// leaves a working NGINX rather than one that won't reload at all.
///
/// A missing file is success, not an error.
pub fn remove_unused_managed_files(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
) -> Result<usize> {
    let unused = unused_managed_files(server, db, root)?;
    remove_and_forget(db, &unused)
}

/// Removes `unused`, as [`unused_managed_files`] resolved it, and forgets
/// each one's row.
fn remove_and_forget(db: &crate::db::Db, unused: &[DirFile]) -> Result<usize> {
    let removed = remove_planned_managed_files(unused)?;
    for file in unused {
        db.forget_managed_file(file.path())?;
    }
    Ok(removed)
}

/// The managed files the current settings no longer reference. Split from
/// the removal for the same reason [`planned_managed_files`] is split from
/// the write.
///
/// Two sources, in the order they may be removed ([`ManagedKind`]'s):
///
/// - **The record** of what was written (`managed_files`): every file
///   stop-bots wrote that the current settings would not write where it
///   is. This is what finds a set left in a `conf.d` the root no longer
///   points at, and a file an earlier release wrote that this one does not
///   know by name. Each is checked to still be a generated file first.
/// - **The fixed list** of where each file would be now, for files written
///   before the record existed. Removing one that is not there is a no-op.
///
/// Each comes back with its directory held open ([`DirFile`]): what is
/// removed, read or put back later is in the directory checked here, even
/// if a name on the way to it has changed since.
pub fn unused_managed_files(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
) -> Result<Vec<DirFile>> {
    let planned: Vec<PathBuf> = server
        .planned_managed_files(db, root)?
        .iter()
        .map(|(path, _)| recorded_form(path))
        .collect();
    let mut files = Vec::new();
    for path in server.fallback_unused_managed_files(db, root)? {
        // On a hostile root the fixed list is no more trusted than the
        // record: reached following no link, and removed only if it is
        // still a file this project generated.
        if server.root_is_hostile() {
            if let Some(file) = under_hostile_root(root, &path)? {
                if file.is_regular() && is_generated(&file) {
                    files.push(file);
                }
            }
            continue;
        }
        if let Some(file) = DirFile::locate(&path)
            .with_context(|| format!("failed to open the directory of {}", path.display()))?
        {
            files.push(file);
        }
    }
    let within = server.managed_directories(root);
    for row in db.managed_files()? {
        let Some(kind) = ManagedKind::from_id(&row.kind) else {
            continue;
        };
        if planned.contains(&row.path)
            || files.iter().any(|file| file.path() == row.path)
            || ManagedKind::of(&row.path) != Some(kind)
        {
            continue;
        }
        if let Some(file) = removable_record(&row.path, &within) {
            files.push(file);
        }
    }
    // Stable, so the fixed list's own order survives within a kind.
    files.sort_by_key(|file| ManagedKind::of(file.path()));
    Ok(files)
}

/// The `managed_files` row naming `path`, if it may be acted on: a
/// regular file, not a link, directly inside one of `within`, with this
/// project's header — and `path` already resolved, with no link and no
/// `..` anywhere in it.
///
/// **The record is not trusted.** The database is not always root's (see
/// [`crate::hostconf`]), and this runs as root: a row naming `/etc/passwd`,
/// a link to it, or `<conf.d>/../../passwd` must delete nothing. Nor may a
/// row that reaches `conf.d` through a directory another user owns
/// (`/var/lib/stop-bots/link/...`): they could point that link somewhere
/// else between this check and the removal. So such a row is
/// refused, and the one that passes comes back with its directory held
/// open, which is what every later use goes through.
fn removable_record(path: &Path, within: &[PathBuf]) -> Option<DirFile> {
    let file = DirFile::exactly(path).ok()?;
    (within.iter().any(|dir| dir == file.dir()) && file.is_regular() && is_generated(&file))
        .then_some(file)
}

/// Deletes what [`unused_managed_files`] resolved, through each one's
/// directory descriptor. Touches no `Db`. Returns how many were actually
/// there to delete — see [`write_planned_managed_files`] for why an apply
/// needs the count.
pub fn remove_planned_managed_files(files: &[DirFile]) -> Result<usize> {
    let mut removed = 0;
    for file in files {
        if remove_managed(file)? {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Writes a file this project owns outright. Replaced, never written
/// through — see [`write_atomically`].
pub(crate) fn write_managed(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_atomically(path, body.as_bytes(), 0o644, None)
}

/// Replaces `path` with `content`: a new file beside it, then a rename
/// over it.
///
/// **A rename replaces a symlink; a write follows it.** Everything here
/// runs as root, and on a host whose NGINX tree is a bind mount an
/// unprivileged user may be able to create files in it. `fs::write` on a
/// `conf.d/stop-bots-trusted.conf` they had made a link to `/etc/shadow`
/// would have written our text there. The temporary file is created with
/// `O_EXCL` under a random name, so a link planted at a guessed name makes
/// the create fail rather than be followed. It is also what makes the
/// write atomic: NGINX, or a reload that races us, sees the old file or
/// the new one, never half of one.
///
/// A leading dot keeps the temporary file out of NGINX's own globs
/// (`include sites-enabled/*`), which, like the shell's, skip dot files.
pub(crate) fn write_atomically(
    path: &Path,
    content: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    for _ in 0..8 {
        let temp = path.with_file_name(format!(".{name}.stop-bots-{:016x}", random_u64()));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to write {}", path.display()))
            }
        };
        let written = (|| -> std::io::Result<()> {
            file.write_all(content)?;
            if let Some((uid, gid)) = owner {
                // Best effort: only root can give a file away, and a
                // non-root run that got this far owns what it replaces.
                let _ = std::os::unix::fs::fchown(&file, Some(uid), Some(gid));
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            fs::rename(&temp, path)
        })();
        if let Err(err) = written {
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("failed to write {}", path.display()));
        }
        return Ok(());
    }
    anyhow::bail!(
        "failed to write {}: could not create a temporary file beside it",
        path.display()
    )
}

/// Unpredictable enough for a temporary file name, without a dependency:
/// std seeds every `RandomState` from the OS.
pub(crate) fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    hasher.finish()
}

/// Where an operator's site file really is: `path` itself, or, when a
/// symlink is involved, its target — which must be inside `root`.
///
/// Site files are legitimately links (`sites-enabled/x` to
/// `../sites-available/x`), so a link is followed rather than replaced.
/// But the same writable-tree case [`write_atomically`] is about applies:
/// a link to a file outside the NGINX config is not one this tool was
/// pointed at, and root rewriting whatever `server {` block it finds there
/// is exactly what the link was planted for.
pub(crate) fn resolve_site_file(path: &Path, root: &Path) -> Result<PathBuf> {
    let resolved =
        fs::canonicalize(path).with_context(|| format!("failed to read {}", path.display()))?;
    let as_given = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if resolved == as_given {
        return Ok(resolved);
    }
    let root = fs::canonicalize(root)
        .with_context(|| format!("failed to read the config root {}", root.display()))?;
    if !resolved.starts_with(&root) {
        anyhow::bail!(
            "refusing to write {}: it links to {}, outside the config root {}",
            path.display(),
            resolved.display(),
            root.display()
        );
    }
    Ok(resolved)
}

/// Writes an operator's site file in place of `path`, following a link to
/// it (see [`resolve_site_file`]) and keeping its mode and owner.
///
/// A file the operator made read-only stays unwritten: a rename would
/// replace it regardless of its permission bits, which is not what
/// `chmod 444` was asking for — and running without root is reported as
/// the permission error it is.
pub(crate) fn write_site_file(path: &Path, root: &Path, content: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let resolved = resolve_site_file(path, root)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&resolved)
        .with_context(|| format!("failed to write {}", path.display()))?;
    let meta = fs::metadata(&resolved)
        .with_context(|| format!("failed to read {}", resolved.display()))?;
    write_atomically(
        &resolved,
        content.as_bytes(),
        meta.mode() & 0o7777,
        Some((meta.uid(), meta.gid())),
    )
}

/// Removes a generated file, treating "already gone" as success.
///
/// Deleting rather than merely leaving it unreferenced matters most for
/// the rate-limit zone: [`CONF_D_DIR`] is globbed by the stock
/// `nginx.conf`, so a leftover file there stays *live* — it would keep
/// allocating its shared memory zone forever after the feature was
/// switched off. The `robots.txt` case is only inert-but-misleading, and
/// is removed for consistency: a stale generated artifact on disk invites
/// being wired back up by hand.
pub(crate) fn remove_managed(file: &DirFile) -> Result<bool> {
    file.remove()
        .with_context(|| format!("failed to remove {}", file.path().display()))
}

/// The exemptions actually applied, as `(prefixes, exact paths)`: the
/// site's configured prefixes, plus `/robots.txt` itself — exactly that
/// file, not everything under it — whenever this block serves it.
///
/// That addition is not a convenience, it's what makes robots.txt work at
/// all. Server-level `if`/`return` run in NGINX's **server rewrite
/// phase**, which happens *before* location selection — so a user agent
/// caught by the block never reaches the `location = /robots.txt` block
/// underneath it. Without this, the generated robots.txt would list
/// exactly the agents that can never read it, and the polite layer would
/// be pure decoration.
///
/// Letting a blocked crawler read robots.txt is also the behaviour worth
/// wanting on its own: a bot that can fetch the file can learn to stop
/// asking, whereas one that gets a bare 403 on everything learns nothing
/// and keeps coming back. Serving it costs a single small static file.
pub(crate) fn effective_exempt_paths(
    config: &BlockConfig,
) -> (Vec<String>, &'static [&'static str]) {
    let mut paths = config.exempt_paths.clone();
    let exact: &[&str] = if config.serve_robots_txt {
        &["/robots.txt"]
    } else {
        &[]
    };
    if !config.request_rules.is_empty() {
        // Never optional, and never surfaced as a setting to switch off.
        // `/.well-known/` is where ACME HTTP-01 validation is fetched
        // from, by a non-browser client speaking HTTP/1.1. Rejecting it
        // doesn't break anything today — it breaks certificate renewal
        // weeks later, which is about the least traceable failure this
        // project could ship. The same path prefix carries security.txt
        // and a pile of other machine-fetched documents, none of which
        // negotiate HTTP/2 either.
        paths.push("/.well-known/".to_string());
    }
    (paths, exact)
}

/// The [`BlockConfig`] currently in effect for one site — its own resolved
/// patterns (per-site overrides layered over the global cascade) plus every
/// host-wide setting that shapes the generated text. Every caller that
/// applies or status-checks a *specific* site goes through here rather than
/// assembling the struct itself, so a newly added host-wide knob reaches
/// all of them at once.
pub fn block_config_for_site(db: &crate::db::Db, site_id: i64) -> Result<BlockConfig> {
    Ok(BlockConfig {
        patterns: db.blocked_user_agent_patterns_for_site(site_id)?,
        response: db.get_block_response()?,
        serve_robots_txt: db.get_serve_robots_txt()?,
        rate_limit_burst: rate_limit_burst(db)?,
        exempt_paths: db.site_path_exemptions(site_id)?,
        agent_exemptions: db.site_agent_exemptions(site_id)?,
        request_rules: site_request_rules(db, site_id)?,
        trust: Trust::of(db)?,
    })
}

/// The request-shape rules switched on for one site, in a stable order.
/// An unrecognised stored id is skipped rather than erroring: a database
/// written by a newer build must not stop an older one from applying
/// anything at all.
pub fn site_request_rules(db: &crate::db::Db, site_id: i64) -> Result<Vec<RequestRule>> {
    let mut rules: Vec<RequestRule> = db
        .site_request_rules(site_id)?
        .iter()
        .filter_map(|id| RequestRule::from_id(id))
        .collect();
    rules.sort();
    Ok(rules)
}

/// The [`BlockConfig`] for a `server` block with no site-specific overrides
/// — the global cascade only. Used as `apply_blocks_to_file`'s
/// `default_config` for blocks discovered on disk that were never scanned
/// into the database.
pub fn default_block_config(db: &crate::db::Db) -> Result<BlockConfig> {
    Ok(BlockConfig {
        patterns: db.blocked_user_agent_patterns()?,
        response: db.get_block_response()?,
        serve_robots_txt: db.get_serve_robots_txt()?,
        rate_limit_burst: rate_limit_burst(db)?,
        // A block with no site row has no per-site settings by
        // definition — both are keyed on `sites.id`.
        exempt_paths: Vec::new(),
        agent_exemptions: Vec::new(),
        request_rules: Vec::new(),
        trust: Trust::of(db)?,
    })
}

/// Whether `value`, as stored, is exactly what `validate` would store:
/// how a row is checked again at render time rather than trusted, whatever
/// wrote it.
pub(crate) fn is_stored_as_valid(value: &str, validate: fn(&str) -> Result<String>) -> bool {
    validate(value).is_ok_and(|valid| valid == value)
}

/// Stores what a scan found as the sites there are, the one way every
/// scan does: see [`crate::db::Db::store_scanned_sites`]. Returns the sites
/// it forgot.
pub fn store_scan(db: &crate::db::Db, sites: &[DiscoveredSite]) -> Result<Vec<crate::db::Site>> {
    let paths: Vec<String> = sites
        .iter()
        .map(|site| site.config_path.to_string_lossy().into_owned())
        .collect();
    let found: Vec<(&str, &str)> = sites
        .iter()
        .zip(&paths)
        .map(|(site, path)| (site.server_name.as_str(), path.as_str()))
        .collect();
    db.store_scanned_sites(&found)
}

/// The sites a scan forgot, for the end of its one-line summary: empty if
/// none, else `; forgot 2 no longer there: a.example (/etc/…), …`.
pub fn forgotten_note(gone: &[crate::db::Site]) -> String {
    if gone.is_empty() {
        return String::new();
    }
    let named: Vec<String> = gone
        .iter()
        .map(|site| format!("{} ({})", site.server_name, site.config_path))
        .collect();
    format!(
        "; forgot {} no longer there: {}",
        gone.len(),
        named.join(", ")
    )
}

/// The file under `root` that declares `server_name`, found on disk.
///
/// The database records where a site was when it was scanned, and root
/// does not always own the database. Whatever writes a site's file as
/// root therefore asks the disk, and uses `recorded` only to tell apart
/// two files that both declare the name: the one at the recorded path if
/// it is among them, the only one if there is one, and otherwise none.
pub fn locate_site(
    server: WebServer,
    root: &Path,
    server_name: &str,
    recorded: Option<&Path>,
) -> Result<PathBuf> {
    let discovered = server.discover_sites(root)?;
    if let Some(found) = pick_site(&discovered, server_name, recorded) {
        return Ok(found.to_path_buf());
    }
    let candidates = discovered
        .iter()
        .filter(|site| site.server_name == server_name)
        .count();
    match candidates {
        0 => anyhow::bail!(
            "no {} under {} is named {server_name} — re-scan sites and try again",
            server.block_noun(),
            root.display()
        ),
        _ => anyhow::bail!(
            "{candidates} files under {} declare {server_name}, and none is the one scanned — \
             re-scan sites and try again",
            root.display()
        ),
    }
}

/// [`locate_site`]'s choice among sites already discovered: the one named
/// `server_name` at `recorded`, else the only one named `server_name`.
fn pick_site<'a>(
    discovered: &'a [DiscoveredSite],
    server_name: &str,
    recorded: Option<&Path>,
) -> Option<&'a Path> {
    let mut named = discovered
        .iter()
        .filter(|site| site.server_name == server_name)
        .map(|site| site.config_path.as_path());
    let all: Vec<&Path> = named.by_ref().collect();
    if let Some(found) = recorded.and_then(|recorded| all.iter().find(|p| **p == recorded)) {
        return Some(found);
    }
    match all.as_slice() {
        [only] => Some(only),
        _ => None,
    }
}

/// The status of every scanned site, each judged against the file found
/// for it on disk under `root` (see [`locate_site`]) rather than the one
/// its row names. A site with no file there is [`SiteApplyStatus::NotFound`].
pub fn site_statuses(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
) -> Result<Vec<(i64, SiteApplyStatus)>> {
    let discovered = server.discover_sites(root).unwrap_or_default();
    let mut statuses = Vec::new();
    for site in db.list_sites()? {
        let status = match pick_site(
            &discovered,
            &site.server_name,
            Some(Path::new(&site.config_path)),
        ) {
            Some(path) => server.site_apply_status(
                path,
                &site.server_name,
                &block_config_for_site(db, site.id)?,
                root,
            ),
            None => SiteApplyStatus::NotFound,
        };
        statuses.push((site.id, status));
    }
    Ok(statuses)
}

/// Applies the bot-blocking rule to every `server { ... }` block found in
/// `config_path`. Each block gets the [`BlockConfig`] from `site_configs`
/// belonging to its own `server_name` (its `names.first()`), or
/// `default_config` if that name isn't in `site_configs` at all (e.g. a
/// block discovered on disk that was never scanned into the db yet). A
/// config that renders to nothing removes any existing block there.
/// Returns whether the file was actually changed on disk.
///
/// Two blocks sharing the same `server_name` (e.g. a port-80-redirect block
/// plus the real port-443 block for the same site) resolve to the same
/// `site_configs` entry and so still get the same rule; two blocks with
/// *different* names in the same file now correctly get independent rules.
///
/// `root` is the NGINX config root: a `config_path` that is a symlink is
/// written through only to a target inside it (see [`write_site_file`]).
pub fn apply_blocks_to_file(
    server: WebServer,
    config_path: &Path,
    root: &Path,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
) -> Result<bool> {
    let before = read_under(server, root, config_path)?
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let after = server.blocks_for_file(&before, config_path, root, site_configs, default_config)?;
    if after == before {
        return Ok(false);
    }
    write_under(server, root, config_path, &after)?;
    Ok(true)
}

/// Whether a site's on-disk config currently matches the blocking rule
/// that would be computed for it right now — backs the TUI's per-site
/// status tag in NGINX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SiteApplyStatus {
    /// Every `server` block for this name already carries the expected
    /// rule (or none is expected and none is present).
    UpToDate,
    /// At least one block for this name is missing the expected rule, or
    /// carries a different one.
    Stale,
    /// The config file couldn't be read, or no `server` block in it
    /// declares this `server_name` anymore (e.g. renamed or removed on
    /// disk since the last scan).
    NotFound,
}

/// Applies `config` only to the `server { ... }` block(s) in `config_path`
/// whose first `server_name` is `server_name`, leaving every other block in
/// the file completely untouched — unlike [`apply_blocks_to_file`], which
/// resets every block it has no explicit entry for back to
/// `default_config`. This backs the TUI's per-site "Apply now" action:
/// applying one site's overrides must never silently rewrite an unrelated
/// site sharing the same file. Returns whether the file was actually
/// changed on disk. `root` is as for [`apply_blocks_to_file`].
pub fn apply_block_for_site(
    server: WebServer,
    config_path: &Path,
    root: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<bool> {
    let before = read_under(server, root, config_path)?
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let after = server.block_for_site(&before, config_path, root, server_name, config)?;
    if after == before {
        return Ok(false);
    }
    write_under(server, root, config_path, &after)?;
    Ok(true)
}

/// One file an apply would change: its content before and after, `None`
/// for a file that does not exist (before) or would be removed (after).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: PathBuf,
    pub before: Option<String>,
    pub after: Option<String>,
}

impl FileChange {
    /// A unified diff of the change, labelled with the path.
    pub fn diff(&self) -> String {
        let label = self.path.display().to_string();
        crate::diff::unified(
            self.before.as_deref(),
            self.after.as_deref(),
            &label,
            &label,
        )
    }

    /// `(new)`, `(removed)` or nothing, for a summary line.
    pub fn kind(&self) -> &'static str {
        match (&self.before, &self.after) {
            (None, Some(_)) => " (new)",
            (Some(_), None) => " (removed)",
            _ => "",
        }
    }
}

/// Every file [`apply_all_sites_and_reload`] would change under `root`,
/// and how, without changing any of them: the generated files it would
/// write or remove, and each site file it would rewrite. Through the same
/// functions the apply uses, so a preview cannot promise something the
/// apply then does differently.
pub fn preview_all_sites(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
) -> Result<Vec<FileChange>> {
    let sites = server.discover_sites(root)?;
    let mut changes: Vec<FileChange> = Vec::new();
    for (path, body) in server.planned_managed_files(db, root)? {
        let before = read_under(server, root, &path)?;
        if before.as_deref() != Some(body.as_str()) {
            changes.push(FileChange {
                path,
                before,
                after: Some(body),
            });
        }
    }

    let default_config = default_block_config(db)?;
    let known_sites = db.list_sites()?;
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();
    for path in config_paths {
        // The same per-file join `apply_all_sites` makes, for its reason.
        let site_configs: Vec<(String, BlockConfig)> = known_sites
            .iter()
            .filter(|s| Path::new(&s.config_path) == path.as_path())
            .map(|s| Ok((s.server_name.clone(), block_config_for_site(db, s.id)?)))
            .collect::<Result<_>>()?;
        let before = read_under(server, root, &path)?
            .with_context(|| format!("failed to read {}", path.display()))?;
        let after = server.blocks_for_file(&before, &path, root, &site_configs, &default_config)?;
        if after != before {
            changes.push(FileChange {
                path,
                before: Some(before),
                after: Some(after),
            });
        }
    }

    for file in unused_managed_files(server, db, root)? {
        if let Some(before) = file.read_to_string() {
            changes.push(FileChange {
                path: file.path().to_path_buf(),
                before: Some(before),
                after: None,
            });
        }
    }
    Ok(changes)
}

/// What [`apply_all_sites_and_reload`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApplyAllOutcome {
    pub sites: usize,
    pub files: usize,
    /// How many files were actually rewritten, generated ones (the trust
    /// file, the rate-limit zone) included. Zero means NGINX has nothing
    /// new to read, so there is no point reloading it.
    pub changed: usize,
    /// Whether the new config passed the test and NGINX was reloaded.
    pub reloaded: bool,
}

/// Applies the current blocking policy to every site discovered under
/// `root`, and — given `commands` — tests the result and reloads NGINX.
/// The one way every front-end applies everything.
///
/// **A config that fails the test is put back.** Every file the apply may
/// touch is read first ([`Snapshot`]); if the test then fails, each is
/// restored byte for byte and each generated file this apply created is
/// removed, before the error is returned. Writing and leaving it was
/// survivable only in appearance: the running NGINX keeps serving the old
/// config from memory, and the broken one is loaded by whatever reloads
/// next — certbot's renewal hook at 3am, or a reboot — taking every site
/// down together. A write that fails half way is put back the same way.
///
/// `None` writes without testing or reloading: `--no-reload` and
/// `--no-apply`, for a host whose NGINX this process must not touch.
///
/// **One at a time**, across processes: it holds [`crate::applylock`]
/// from before the snapshot to after the reload, and a second apply waits
/// briefly and then reports that another stop-bots is applying.
pub fn apply_all_sites_and_reload(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
    commands: Option<&ServerCommands>,
) -> Result<ApplyAllOutcome> {
    // Before the snapshot, not after: what a failed test restores has to
    // be the state no other apply was halfway through changing.
    let _lock = crate::applylock::hold()?;
    let sites = server.discover_sites(root)?;
    // Resolved once, for the snapshot and the apply alike: what is put
    // back on a failure is exactly what the apply may have changed.
    let planned = server.planned_managed_files(db, root)?;
    let unused = unused_managed_files(server, db, root)?;
    let snapshot = Snapshot::of_apply(
        server,
        root,
        planned.iter().map(|(path, _)| path.clone()),
        &unused,
        sites.iter().map(|site| site.config_path.as_path()),
    )?;

    let outcome = match apply_all_sites(server, db, root, &sites, &planned, &unused) {
        Ok(outcome) => outcome,
        Err(err) => return Err(crate::hint::sudo_if_denied(snapshot.restore_after(err))),
    };
    let Some(commands) = commands.filter(|_| outcome.changed > 0) else {
        return Ok(outcome);
    };
    test_or_restore(server, &snapshot, commands)?;
    reload(server, commands).context("the new config passed the test, but the reload failed")?;
    Ok(ApplyAllOutcome {
        reloaded: commands.reloads(),
        ..outcome
    })
}

/// The writing half of [`apply_all_sites_and_reload`].
///
/// The ordering below is load-bearing: generated files are written
/// *before* any config that aliases them, and unreferenced ones are
/// deleted only *after* every config has been rewritten (see
/// [`remove_unused_managed_files`]).
fn apply_all_sites(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
    sites: &[DiscoveredSite],
    planned: &[(PathBuf, String)],
    unused: &[DirFile],
) -> Result<ApplyAllOutcome> {
    record_managed_files(db, planned)?;
    let mut changed = write_planned_managed_files(server, root, planned)?;
    let default_config = default_block_config(db)?;
    // Sites already known to the db (i.e. previously scanned) — the only
    // ones that can carry a per-site override at all.
    let known_sites = db.list_sites()?;

    // A single config file commonly holds multiple `server` blocks for the
    // same site (e.g. an HTTP redirect block plus the HTTPS one), so dedupe
    // by file and apply once per file rather than once per discovered site.
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();

    for path in &config_paths {
        // Built fresh per file, filtered to sites that actually live in
        // *this* file: `server_name` alone isn't unique across the whole
        // `sites` table (two different files can share one, e.g. a stale
        // config left behind after a rename), so a single map built once
        // for the whole run could leak one site's override onto another's
        // same-named block in a different file. Note this join is a
        // textual `config_path` match, only valid when `root` here matches
        // whatever root was used at scan time — a mismatch just falls
        // through to `default_config`, not an error.
        let site_configs: Vec<(String, BlockConfig)> = known_sites
            .iter()
            .filter(|s| Path::new(&s.config_path) == path.as_path())
            .map(|s| Ok((s.server_name.clone(), block_config_for_site(db, s.id)?)))
            .collect::<Result<_>>()?;
        if apply_blocks_to_file(server, path, root, &site_configs, &default_config)? {
            changed += 1;
        }
    }

    // Only now that every config has been rewritten is it safe to delete a
    // generated file the new config no longer references.
    changed += remove_and_forget(db, unused)?;

    Ok(ApplyAllOutcome {
        sites: sites.len(),
        files: config_paths.len(),
        changed,
        reloaded: false,
    })
}

/// Applies one site's policy — its file and the generated files it reads —
/// and, given `commands`, tests and reloads the way
/// [`apply_all_sites_and_reload`] does. Returns the site's name and
/// whether anything changed.
pub fn apply_site_and_reload(
    server: WebServer,
    db: &crate::db::Db,
    root: &Path,
    site: &crate::db::Site,
    commands: Option<&ServerCommands>,
) -> Result<(bool, bool)> {
    let _lock = crate::applylock::hold()?;
    // The file found on disk for this site, not the one its row names:
    // see `locate_site`.
    let config_path = &locate_site(
        server,
        root,
        &site.server_name,
        Some(Path::new(&site.config_path)),
    )?;
    let managed = server.planned_managed_files(db, root)?;
    record_managed_files(db, &managed)?;
    let snapshot = Snapshot::of_apply(
        server,
        root,
        managed.iter().map(|(path, _)| path.clone()),
        &[],
        [config_path.as_path()],
    )?;

    let written = (|| -> Result<bool> {
        let managed_changed = write_planned_managed_files(server, root, &managed)?;
        let config = block_config_for_site(db, site.id)?;
        let site_changed =
            apply_block_for_site(server, config_path, root, &site.server_name, &config)?;
        Ok(managed_changed > 0 || site_changed)
    })();
    let changed = match written {
        Ok(changed) => changed,
        Err(err) => return Err(crate::hint::sudo_if_denied(snapshot.restore_after(err))),
    };
    let Some(commands) = commands.filter(|_| changed) else {
        return Ok((changed, false));
    };
    test_or_restore(server, &snapshot, commands)?;
    reload(server, commands).context("the new config passed the test, but the reload failed")?;
    Ok((changed, commands.reloads()))
}

/// Whether `path` is the web console's own site file, as the `Web Access`
/// panel of an earlier release wrote it (see
/// [`WebServer::console_site_path`]) — by its first line, which every
/// version wrote, so that a file an operator put at the same path is left
/// alone.
pub fn is_console_site_file(path: &Path) -> bool {
    use std::io::BufRead;
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut first = String::new();
    std::io::BufReader::new(file)
        .read_line(&mut first)
        .is_ok_and(|_| {
            first.starts_with('#')
                && first.contains("by stop-bots")
                && first.contains("(`Web Access` panel)")
        })
}

/// Where `server` loads each file this project generates for it under
/// `root`, whether or not one is there: the trust file and the rate-limit
/// zones beside the sites. Not the `robots.txt`, which lives in a
/// directory of this project's own and is read only through a block.
fn generated_file_places(server: WebServer, root: &Path) -> Vec<PathBuf> {
    match server {
        WebServer::Nginx => {
            let conf_d = nginx::conf_d_dir(root);
            vec![
                nginx::untrusted_rate_limit_conf_path(&conf_d),
                nginx::rate_limit_conf_path(&conf_d),
                nginx::trusted_conf_path(&conf_d),
            ]
        }
        WebServer::Apache => vec![apache::trusted_conf_path(&apache::conf_enabled_dir(root))],
        WebServer::Traefik => vec![traefik::routers_path(root)],
        WebServer::Npmplus => {
            let own = npmplus::own_dir(root);
            vec![
                nginx::untrusted_rate_limit_conf_path(&own),
                nginx::rate_limit_conf_path(&own),
                nginx::trusted_conf_path(&own),
            ]
        }
    }
}

/// What stop-bots has left in `server`'s config under `root`: each site
/// file with a block or a console section in it, each generated file where
/// it would be, and the console's own site an earlier release wrote. Empty
/// for a root that is not there.
///
/// Asked before the host's web server is switched. Everything that finds
/// these again — an apply, `uninstall web-server` — works on the server the
/// host settings choose, so once they choose the other one, what is left
/// here would stay in a config that is still loaded, with nothing in
/// stop-bots that would ever take it out.
pub fn leftovers(server: WebServer, root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for path in server.injected_files(root).unwrap_or_default() {
        if read_under(server, root, &path)
            .ok()
            .flatten()
            .is_some_and(|content| server.without_injected_blocks(&content) != content)
        {
            found.push(path);
        }
    }
    for path in generated_file_places(server, root) {
        let file = if server.root_is_hostile() {
            under_hostile_root(root, &path).ok().flatten()
        } else {
            DirFile::locate(&path).ok().flatten()
        };
        if file.is_some_and(|file| file.is_regular() && is_generated(&file)) {
            found.push(path);
        }
    }
    // No release wrote a console site on a hostile root, and opening that
    // name there by path would follow a link or wait on a FIFO.
    let console = server.console_site_path(root);
    if !server.root_is_hostile() && is_console_site_file(&console) && !found.contains(&console) {
        found.push(console);
    }
    found
}

/// What [`remove_everything`] did, or would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removal {
    /// Site files that had a block taken out.
    pub site_files: Vec<PathBuf>,
    /// Generated files that were there and were deleted.
    pub generated: Vec<PathBuf>,
    /// Whether the result passed the test and NGINX was reloaded.
    pub reloaded: bool,
}

/// Takes every injected block out of every site file under `root` and
/// deletes `generated`, as one change: tested with `commands`, **put back
/// byte for byte if the test fails**, and reloaded only once it passes.
///
/// The same machinery an apply uses ([`Snapshot`], [`test_or_restore`]),
/// for the same reason: a config NGINX rejects is not loaded by this
/// reload, it is loaded by the next one — certbot's at 3am.
///
/// The site files are rewritten before the generated files go, the
/// reverse of an apply's order and for the same reason: nothing may be
/// left referring to a zone or variable that is gone.
///
/// `commands` is `None` for a tree that is not the running NGINX's
/// (`uninstall --prefix`); `dry_run` works out the same answer and writes
/// nothing.
///
/// `generated` is held by directory descriptor ([`DirFile`]): some of it
/// comes from the database's record, and is removed, and put back if the
/// test fails, in the directory it was checked in.
pub fn remove_everything(
    server: WebServer,
    root: &Path,
    generated: &[DirFile],
    commands: Option<&ServerCommands>,
    dry_run: bool,
) -> Result<Removal> {
    // The same lock every apply holds, from the first read of a site file
    // to the reload: a console or a cron `batch` applying while this runs
    // would otherwise write a block back into a file this has just read.
    // A dry run writes nothing and takes nothing.
    let _lock = if dry_run {
        None
    } else {
        Some(crate::applylock::hold()?)
    };
    let mut edits = Vec::new();
    for path in server.injected_files(root)? {
        let content = read_under(server, root, &path)?
            .with_context(|| format!("failed to read {}", path.display()))?;
        let stripped = server.without_injected_blocks(&content);
        if stripped != content {
            edits.push((path, stripped));
        }
    }
    let present: Vec<DirFile> = generated
        .iter()
        .filter(|file| file.is_regular())
        .cloned()
        .collect();
    let mut removal = Removal {
        site_files: edits.iter().map(|(path, _)| path.clone()).collect(),
        generated: present
            .iter()
            .map(|file| file.path().to_path_buf())
            .collect(),
        reloaded: false,
    };
    if dry_run || (edits.is_empty() && present.is_empty()) {
        return Ok(removal);
    }

    let snapshot = Snapshot::of_apply(
        server,
        root,
        [],
        &present,
        edits.iter().map(|(path, _)| path.as_path()),
    )?;
    let written = (|| -> Result<()> {
        for (path, content) in &edits {
            write_under(server, root, path, content)?;
        }
        remove_planned_managed_files(&present)?;
        Ok(())
    })();
    if let Err(err) = written {
        return Err(snapshot.restore_after(err));
    }
    let Some(commands) = commands else {
        return Ok(removal);
    };
    test_or_restore(server, &snapshot, commands)?;
    reload(server, commands)
        .context("the config without stop-bots passed the test, but the reload failed")?;
    removal.reloaded = commands.reloads();
    Ok(removal)
}

/// Every file an apply may touch, as it was before the apply began, so
/// that a config NGINX rejects can be taken back.
///
/// Holds the bytes and the mode of each regular file, and "absent" for
/// anything else — so restoring removes a file the apply created. A
/// symlink counts as absent: the writes here replace a link rather than
/// following it (see [`write_atomically`]), and putting a planted one back
/// would put back the thing that was planted.
///
/// A file named by the database's record is held by its directory's
/// descriptor ([`DirFile`]) and put back through it, never through its
/// path: a path in a directory another user owns can lead somewhere
/// else by the time a failed test puts it back, and root would write the
/// held bytes there. So is every file under a root someone else can
/// write ([`WebServer::root_is_hostile`]), where that someone also decides
/// whether the test fails.
pub struct Snapshot {
    files: Vec<(Place, Option<Held>)>,
}

/// Where a [`Snapshot`]ed file is: a path this program derived itself (a
/// site file, a generated file the settings call for), or a file held
/// through its directory.
enum Place {
    Path(PathBuf),
    Held(DirFile),
}

impl Place {
    fn path(&self) -> &Path {
        match self {
            Place::Path(path) => path,
            Place::Held(file) => file.path(),
        }
    }

    /// The regular file there, or `None` for nothing, a link or anything
    /// else. Opened without following a link or waiting on a FIFO.
    fn read(&self) -> std::io::Result<Option<Held>> {
        match self {
            Place::Held(file) => {
                let owner = file.mode_and_owner()?.map(|(_, owner)| owner);
                Ok(file
                    .read()?
                    .map(|(bytes, mode)| Held { bytes, mode, owner }))
            }
            Place::Path(path) => {
                use std::io::Read;
                use std::os::unix::fs::MetadataExt;
                let mut file = match crate::db::guard::open_nofollow(path) {
                    Ok(Some(file)) => file,
                    Ok(None) => return Ok(None),
                    Err(err) if err.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
                    Err(err) => return Err(err),
                };
                let meta = file.metadata()?;
                if !meta.is_file() {
                    return Ok(None);
                }
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Ok(Some(Held {
                    bytes,
                    mode: meta.mode() & 0o7777,
                    owner: None,
                }))
            }
        }
    }

    /// Puts `held` back. A held file goes back through its directory with
    /// its owner and without its setuid, setgid or sticky bit: what is
    /// held is, on a hostile root, a file another user made, and root
    /// writes it.
    fn write(&self, held: &Held) -> Result<()> {
        match self {
            Place::Path(path) => write_atomically(path, &held.bytes, held.mode, None),
            Place::Held(file) => file
                .write_atomically_owned(&held.bytes, held.mode & 0o777, held.owner)
                .with_context(|| format!("failed to write {}", file.path().display())),
        }
    }

    /// Removes the regular file there, if there is one.
    fn remove_file(&self) -> Result<()> {
        let removed = match self {
            Place::Path(path) => match fs::symlink_metadata(path) {
                Ok(meta) if meta.is_file() => fs::remove_file(path),
                _ => Ok(()),
            },
            Place::Held(file) if file.is_regular() => file.remove().map(|_| ()),
            Place::Held(_) => Ok(()),
        };
        removed.with_context(|| format!("failed to remove {}", self.path().display()))
    }
}

/// A regular file as [`Snapshot`] found it: its contents, its permission
/// bits, and its owner where it is held through its directory.
struct Held {
    bytes: Vec<u8>,
    mode: u32,
    owner: Option<(u32, u32)>,
}

impl Snapshot {
    /// Reads every file in `paths`. Fails if one exists and cannot be
    /// read, because an apply that could not be undone should not start.
    pub fn take(paths: impl IntoIterator<Item = PathBuf>) -> Result<Snapshot> {
        Snapshot::take_places(paths.into_iter().map(Place::Path))
    }

    fn take_places(places: impl IntoIterator<Item = Place>) -> Result<Snapshot> {
        let mut files: Vec<(Place, Option<Held>)> = Vec::new();
        for place in places {
            if files.iter().any(|(seen, _)| seen.path() == place.path()) {
                continue;
            }
            let before = place
                .read()
                .with_context(|| format!("failed to read {}", place.path().display()))?;
            files.push((place, before));
        }
        Ok(Snapshot { files })
    }

    /// A snapshot of what an apply under `root` may touch: the `planned`
    /// generated files at their own paths, the `held` ones (those the
    /// record names) through their directories, and each of `site_files`
    /// where it really is, which is where [`write_site_file`] will write
    /// it. A site file that cannot be resolved is left out; its write will
    /// fail with the same error, and that failure is what undoes the
    /// apply.
    ///
    /// On a root someone else can write ([`WebServer::root_is_hostile`])
    /// every one of them is held through its directory instead, from the
    /// resolved root ([`under_hostile_root`]), its directory made first if
    /// the apply is about to make it: putting back, like writing, then
    /// goes where the file was, whatever has been linked in since. A link
    /// already on the way refuses the snapshot, and with it the apply.
    pub fn of_apply<'a>(
        server: WebServer,
        root: &Path,
        planned: impl IntoIterator<Item = PathBuf>,
        held: &[DirFile],
        site_files: impl IntoIterator<Item = &'a Path>,
    ) -> Result<Snapshot> {
        if server.root_is_hostile() {
            let mut places = Vec::new();
            for path in planned
                .into_iter()
                .chain(site_files.into_iter().map(Path::to_path_buf))
            {
                places.push(Place::Held(under_hostile_root_created(root, &path)?));
            }
            places.extend(held.iter().cloned().map(Place::Held));
            return Snapshot::take_places(places);
        }
        Snapshot::take_places(
            planned
                .into_iter()
                .map(Place::Path)
                .chain(held.iter().cloned().map(Place::Held))
                .chain(
                    site_files
                        .into_iter()
                        .filter_map(|path| resolve_site_file(path, root).ok())
                        .map(Place::Path),
                ),
        )
    }

    /// Puts every file back as it was. Carries on past a failure, so one
    /// stuck file does not leave the rest half restored, and names each
    /// one that could not be.
    pub fn restore(&self) -> Result<()> {
        let mut failed = Vec::new();
        for (place, before) in &self.files {
            let restored = match before {
                Some(held)
                    if place.read().ok().flatten().map(|now| now.bytes).as_ref()
                        == Some(&held.bytes) =>
                {
                    Ok(())
                }
                Some(held) => place.write(held),
                None => place.remove_file(),
            };
            if let Err(err) = restored {
                failed.push(format!("{err:#}"));
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("{}", failed.join("; "));
        }
        Ok(())
    }

    /// `err`, with whether the restore that follows it worked.
    pub(crate) fn restore_after(&self, err: anyhow::Error) -> anyhow::Error {
        match self.restore() {
            Ok(()) => err.context("nothing was applied: every file it changed was put back"),
            Err(restore) => err.context(format!(
                "AND PUTTING THE PREVIOUS FILES BACK FAILED, fix these by hand: {restore:#}"
            )),
        }
    }
}

/// Runs the configured test against what was just written, and on a
/// failure puts back everything `snapshot` holds before reporting.
pub fn test_or_restore(
    server: WebServer,
    snapshot: &Snapshot,
    commands: &ServerCommands,
) -> Result<()> {
    test_config(server, commands).map_err(|err| snapshot.restore_after(err))
}

/// How to test and reload the web server.
///
/// Two commands rather than two hardcoded invocations, because the web
/// server is not always a service on this host. The case that forced it:
/// NGINX in a container, with its config on a bind mount this tool writes
/// to. The files are ours to edit, but `systemctl reload nginx` reloads
/// nothing — there is no such unit — and `nginx -t` either isn't installed
/// or tests a different config than the one the container will read. Both
/// become `docker exec <name> nginx ...` there.
///
/// Read from the host's settings ([`crate::hostconf`]), never from the
/// database: these run as root, and root does not always own the database.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerCommands {
    /// Argv for the config check. Must exit non-zero on a bad config.
    /// Empty for none, which is Traefik's default.
    pub test: Vec<String>,
    /// Argv for the reload, or empty for none, likewise.
    pub reload: Vec<String>,
}

impl ServerCommands {
    /// The `settings` keys NGINX's were stored under before they became
    /// host settings. Read only by [`crate::hostconf::migrate`], once.
    pub const TEST_KEY: &'static str = crate::db::keys::NGINX_TEST_COMMAND;
    pub const RELOAD_KEY: &'static str = crate::db::keys::NGINX_RELOAD_COMMAND;
    /// Where this host's site configs actually live.
    pub const ROOT_KEY: &'static str = crate::db::keys::NGINX_ROOT;

    /// The same, from the host's settings — see [`crate::hostconf`].
    pub fn from_host(host: &crate::hostconf::HostConf) -> Result<Self> {
        host.commands()
    }

    /// Whether running these reloads anything: not when the reload is no
    /// command, as on a Traefik host, which reads what changed by itself.
    pub fn reloads(&self) -> bool {
        !self.reload.is_empty()
    }
}

/// Where to look for site configs: the flag if one was given, else the
/// host setting, else the stock path. See [`crate::hostconf::HostConf::root`].
///
/// A web server in a container moves three things away from their
/// defaults — the commands that drive it, the logs it writes, and the
/// directory its config lives in — and all three are host settings now.
/// Flag beats setting: a one-off run against a checkout or a staging tree
/// must not require the stored value to be changed and put back.
pub fn root(host: &crate::hostconf::HostConf, flag: Option<&Path>) -> PathBuf {
    host.root(flag)
}

/// Splits a configured command into argv.
///
/// Deliberately *not* a shell: the string is never handed to `sh -c`, so
/// there is no expansion, no globbing, no `;` and no pipelines. What a
/// reload command needs is words, and words with spaces in them — a path
/// under `/Applications/...`, a container named with a space — which is
/// exactly single and double quotes and nothing else.
///
/// Keeping the shell out of it is the security-relevant half. This command
/// runs as root; `sh -c` would turn a settings row into arbitrary code, and
/// the settings table is reachable from the web UI.
pub fn split_command(input: &str) -> Result<Vec<String>> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut has_word = false;
    let mut quote: Option<char> = None;

    for c in input.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => {
                // An empty quoted string is still an argument, so the
                // word has to be marked as started here and not only by
                // pushing a character.
                quote = Some(c);
                has_word = true;
            }
            None if c.is_whitespace() => {
                if has_word {
                    argv.push(std::mem::take(&mut current));
                    has_word = false;
                }
            }
            None => {
                current.push(c);
                has_word = true;
            }
        }
    }

    if quote.is_some() {
        anyhow::bail!("unbalanced quote in `{input}`");
    }
    if has_word {
        argv.push(current);
    }
    if argv.is_empty() {
        anyhow::bail!("`{input}` is empty");
    }
    Ok(argv)
}

/// Runs `argv`, returning its stderr on a non-zero exit. An empty `argv`
/// is no command, and runs nothing: Traefik's default test and reload.
///
/// `output`, not `status`: `status` inherits stdout and stderr, so anything
/// the command says lands directly on the TUI's alternate screen and
/// corrupts it. Run non-root, `systemctl` additionally pulls in a polkit
/// agent, which takes over the terminal outright to ask for a password.
fn run(server: WebServer, argv: &[String], what: &str) -> Result<()> {
    let Some((program, args)) = argv.split_first() else {
        return Ok(());
    };
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|err| spawn_failure(server, argv, err))?;
    if !output.status.success() {
        anyhow::bail!(
            "{what} (`{}`) exited with {}: {}",
            argv.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Why `argv` could not be started, and — when its program is not there
/// at all, the usual state of a host whose web server is in a container —
/// where the commands are set.
fn spawn_failure(server: WebServer, argv: &[String], err: std::io::Error) -> anyhow::Error {
    let not_found = err.kind() == std::io::ErrorKind::NotFound;
    let err = anyhow::Error::new(err).context(format!("failed to run `{}`", argv.join(" ")));
    if !not_found {
        return err;
    }
    crate::hint::with(
        err,
        &format!(
            "`{}` isn't on PATH. If {} runs in a container, point stop-bots at it: \
             see `stop-bots {} --help`.",
            argv[0],
            server.label(),
            server.commands_verb(),
        ),
    )
}

/// Validates the currently-installed config. Run before every reload so a
/// malformed config — ours or an unrelated hand edit elsewhere in the same
/// install — is reported as a clear error here rather than left for the
/// admin to dig out of `systemctl status`.
fn test_config(server: WebServer, commands: &ServerCommands) -> Result<()> {
    let tested = run(
        server,
        &commands.test,
        &format!("the {} config test", server.label()),
    );
    match tested {
        Err(err) if server == WebServer::Apache => match apache::missing_module_hint(&err) {
            Some(hint) => Err(crate::hint::with(err, hint)),
            None => Err(err),
        },
        tested => tested,
    }
}

/// Runs the reload command alone, for a config that has just passed
/// [`test_config`].
fn reload(server: WebServer, commands: &ServerCommands) -> Result<()> {
    run(
        server,
        &commands.reload,
        &format!("the {} reload", server.label()),
    )
}

/// Reloads the web server so a just-written blocking rule actually takes
/// effect — writing the sentinel block to a site's config file alone does
/// nothing until the server re-reads it. Always preceded by
/// [`test_config`]: `systemctl reload` refuses a config that fails
/// validation on its own too, but checking explicitly here gets a message
/// callers can show directly rather than send the admin to `systemctl
/// status`/`journalctl`.
pub fn reload_with(server: WebServer, commands: &ServerCommands) -> Result<()> {
    test_config(server, commands)?;
    reload(server, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log under the root is skipped by its size, never read: sparse,
    /// so the test writes nothing, and named like config, so only its size
    /// can tell it apart.
    #[test]
    fn a_file_too_large_to_be_config_is_never_read() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("site.conf"),
            "server { server_name a.example; }\n",
        )
        .unwrap();
        fs::File::create(dir.path().join("huge.conf"))
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        let names: Vec<String> = config_files(dir.path())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["site.conf"]);
    }

    /// Nor is one read through [`read_regular_file`], which reads files
    /// under a root another user can write, outside [`config_files`] too.
    #[test]
    fn a_file_too_large_to_be_config_is_not_read_as_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("huge.conf");
        fs::File::create(&huge)
            .unwrap()
            .set_len(MAX_CONFIG_BYTES + 1)
            .unwrap();
        assert_eq!(
            read_regular_file(&huge),
            None,
            "a sparse file over the cap was read"
        );
    }

    #[test]
    fn a_backup_is_told_from_a_site_by_its_name() {
        let cases = [
            ("site.conf.bak", true),
            ("site.conf.BAK", true),
            ("nextcloud.conf.bak-2026-10-12", true),
            ("conf.d.bak-2026-10-13-1127", true),
            ("site.conf.bak.1", true),
            ("site.conf.20261012.bak", true),
            ("site.conf.orig", true),
            ("site.conf.old", true),
            ("default.dpkg-dist", true),
            ("site.conf.rpmnew", true),
            ("site.conf~", true),
            ("#site.conf#", true),
            ("backups", true),
            ("site.conf", false),
            ("default", false),
            ("conf.d", false),
            // A domain may be named anything, but only a backup ends in one.
            ("backup.example.com.conf", false),
            ("old.example.com", false),
            ("bakery.example", false),
            // `include conf.d/*.conf` loads it, so it is config.
            ("site.bak.conf", false),
        ];
        let wrong: Vec<String> = cases
            .iter()
            .filter(|(name, backup)| is_backup_name(name) != *backup)
            .map(|(name, backup)| format!("{name}: expected backup = {backup}"))
            .collect();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn a_listen_address_is_read_the_way_both_servers_write_it() {
        let cases = [
            ("80", Some((None, 80))),
            ("*:8080", Some((None, 8080))),
            ("_default_:443", Some((None, 443))),
            ("127.0.0.1", Some((Some("127.0.0.1"), 80))),
            ("127.0.0.1:8080", Some((Some("127.0.0.1"), 8080))),
            ("[::]:443", Some((Some("::"), 443))),
            ("[::1]", Some((Some("::1"), 80))),
            ("localhost:8080", Some((None, 8080))),
            ("unix:/run/site.sock", None),
            ("*:http", None),
        ];
        for (text, expected) in cases {
            let expected = expected
                .map(|(ip, port): (Option<&str>, u16)| (ip.map(|ip| ip.parse().unwrap()), port));
            assert_eq!(Listen::parse_address(text), expected, "{text}");
        }
    }

    // ---- split_command ----

    #[test]
    fn a_command_splits_into_words_and_quotes_keep_theirs_together() {
        for (written, argv) in [
            ("nginx -t", vec!["nginx", "-t"]),
            (
                "  apachectl   configtest  ",
                vec!["apachectl", "configtest"],
            ),
            (
                "docker exec 'my web' nginx -t",
                vec!["docker", "exec", "my web", "nginx", "-t"],
            ),
            (r#"say "it's""#, vec!["say", "it's"]),
            ("a\"b c\"d", vec!["ab cd"]),
            ("run ''", vec!["run", ""]),
        ] {
            assert_eq!(split_command(written).unwrap(), argv, "{written:?}");
        }
    }

    /// No shell: what a shell would act on is just part of a word.
    #[test]
    fn a_command_is_never_a_shell_line() {
        assert_eq!(
            split_command("nginx -t; rm -rf / $(id) `x` | y").unwrap(),
            ["nginx", "-t;", "rm", "-rf", "/", "$(id)", "`x`", "|", "y"]
        );
    }

    #[test]
    fn an_unbalanced_quote_or_nothing_at_all_is_refused() {
        for written in ["nginx '-t", "\"", "", "   "] {
            assert!(split_command(written).is_err(), "{written:?} was accepted");
        }
    }

    // ---- Snapshot ----

    #[test]
    fn a_snapshot_puts_back_a_changed_file_with_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "before\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let snapshot = Snapshot::take([path.clone()]).unwrap();

        write_managed(&path, "after\n").unwrap();
        snapshot.restore().unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "before\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn a_snapshot_removes_a_file_that_was_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stop-bots-trusted.conf");
        let snapshot = Snapshot::take([path.clone()]).unwrap();

        write_managed(&path, "new\n").unwrap();
        snapshot.restore().unwrap();

        assert!(!path.exists());
    }

    /// A link counts as absent: putting a planted one back would put back
    /// the thing that was planted.
    #[test]
    fn a_snapshot_does_not_put_a_link_back() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, "not ours\n").unwrap();
        let path = dir.path().join("stop-bots-trusted.conf");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let snapshot = Snapshot::take([path.clone()]).unwrap();

        write_managed(&path, "ours\n").unwrap();
        snapshot.restore().unwrap();

        assert!(fs::symlink_metadata(&path).is_err(), "the link came back");
        assert_eq!(fs::read_to_string(&target).unwrap(), "not ours\n");
    }

    #[test]
    fn a_failed_restore_names_the_file_and_the_rest_are_still_put_back() {
        let dir = tempfile::tempdir().unwrap();
        let stuck = dir.path().join("gone/site.conf");
        fs::create_dir_all(stuck.parent().unwrap()).unwrap();
        fs::write(&stuck, "before\n").unwrap();
        let fine = dir.path().join("other.conf");
        fs::write(&fine, "before\n").unwrap();
        let snapshot = Snapshot::take([stuck.clone(), fine.clone()]).unwrap();

        fs::remove_dir_all(stuck.parent().unwrap()).unwrap();
        fs::write(&fine, "after\n").unwrap();
        let err = snapshot.restore().unwrap_err();

        assert!(
            format!("{err:#}").contains(&stuck.display().to_string()),
            "said: {err:#}"
        );
        assert_eq!(fs::read_to_string(&fine).unwrap(), "before\n");
    }

    // ---- switching servers ----

    #[test]
    fn leftovers_name_each_site_file_with_a_block_and_each_generated_file() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("apache2.conf"),
            "IncludeOptional conf-enabled/*.conf\n",
        )
        .unwrap();
        fs::create_dir_all(root.path().join("conf-enabled")).unwrap();
        let blocked = root.path().join("blocked.conf");
        let untouched = root.path().join("untouched.conf");
        let site =
            |name: &str| format!("<VirtualHost *:80>\n    ServerName {name}\n</VirtualHost>\n");
        fs::write(&untouched, site("b.example")).unwrap();
        let config = BlockConfig::new(vec!["BadBot".to_string()], BlockResponse::Forbidden);
        let applied = WebServer::Apache
            .blocks_for_file(&site("a.example"), &blocked, root.path(), &[], &config)
            .unwrap();
        fs::write(&blocked, applied).unwrap();
        assert_eq!(
            leftovers(WebServer::Apache, root.path()),
            vec![blocked.clone()]
        );

        let trust = apache::trusted_conf_path(&apache::conf_enabled_dir(root.path()));
        fs::write(&trust, format!("{}SetEnvIf x y\n", managed_header())).unwrap();
        assert_eq!(
            leftovers(WebServer::Apache, root.path()),
            vec![blocked, trust]
        );
    }

    /// A file of the same name an operator wrote is theirs, not a leftover.
    #[test]
    fn a_file_without_this_projects_header_is_no_leftover() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("conf-enabled")).unwrap();
        let trust = apache::trusted_conf_path(&apache::conf_enabled_dir(root.path()));
        fs::write(&trust, "SetEnvIf x y\n").unwrap();
        assert_eq!(
            leftovers(WebServer::Apache, root.path()),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn a_root_that_is_not_there_has_no_leftovers() {
        let gone = Path::new("/nonexistent/stop-bots/nginx-root");
        assert_eq!(leftovers(WebServer::Nginx, gone), Vec::<PathBuf>::new());
    }

    #[test]
    fn only_nginx_rate_limits() {
        assert_eq!(WebServer::Nginx.without_rate_limiting(), None);
        assert!(WebServer::Apache.without_rate_limiting().is_some());
    }
}
