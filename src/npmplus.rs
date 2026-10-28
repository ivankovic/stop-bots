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

//! The NPMplus backend: an NGINX that writes its own sites' config, in a
//! container, with its data directory on the host.
//!
//! Everything around that — the policy, the transaction an apply runs in,
//! the generated files' lifecycle — is [`crate::webserver`]'s. What is
//! written is [`crate::nginx`]'s, word for word: NPMplus *is* NGINX. This
//! module only knows where NPMplus lets anyone else's config in.
//!
//! ## Nothing NPMplus writes is edited
//!
//! NPMplus renders each proxy host from its database into
//! `nginx/proxy_host/<id>.conf` (and redirection and 404 hosts beside it),
//! and renders it again whenever the host is saved. A block written into
//! one of those files would be there until the next save, and then gone
//! with nothing to say so. They are read here, for the sites' names and
//! what runs behind them, and never written.
//!
//! What NPMplus offers instead is `custom_nginx/`, files it includes and
//! never writes: `server_http.conf` inside every HTTP host's `server`
//! block, and `http_top.conf` in the `http` block above them. stop-bots
//! puts one marked block in each, as it would in a site file:
//!
//! - in `server_http.conf`, the same block [`crate::nginx`] puts in a
//!   `server` block, which is therefore every host's;
//! - in `http_top.conf`, one line that includes the generated files in
//!   `custom_nginx/stop-bots/`: the trusted clients and the rate-limit
//!   zones, which only the `http` block can hold. A wildcard, so a file
//!   coming or going changes nothing here.
//!
//! The rest of each file is the operator's, and stays as it was.
//!
//! ## One rule for every host
//!
//! The block is in a file every host includes, so every host gets the
//! same one: the host-wide settings. A site with settings of its own is
//! refused at apply time, saying so, rather than written as if it had
//! none. The request-shape rules are per-site only, so none of them is
//! available here.
//!
//! ## Two paths for every file
//!
//! stop-bots runs on the host, and NPMplus in its container: the host's
//! `/opt/npmplus` is the container's `/data`. Files are written at the
//! first and named in config at the second ([`CONTAINER_OWN_DIR`]).
//!
//! ## Root, writing where a container can
//!
//! The data directory is the container's to write, and stop-bots writes
//! there as root. A link the container made would take that write, or the
//! read of `server_http.conf` whose bytes are written back, somewhere else
//! on the host: a link to `/etc/shadow` there would have been copied into
//! a file the container reads. The container also decides whether the
//! config test fails, so whatever puts files back after one is in its
//! hands too.
//!
//! So nothing below the root is followed, by anything that touches it
//! ([`WebServer::root_is_hostile`]). The root is resolved once, being the
//! operator's own choice; under it, a link or anything but a directory or
//! a regular file where these files go refuses the apply
//! ([`checked_place`]), and every file — the operator's two, the generated
//! ones, NPMplus's own host files — is read, written, held for putting
//! back, put back and removed through its directory, opened without
//! following a link ([`DirFile`], [`crate::webserver::under_hostile_root`]).
//! A file put back keeps its owner and loses any setuid, setgid or sticky
//! bit.

use crate::webserver::*;
use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Where NPMplus's compose file mounts its data directory on the host.
pub const DEFAULT_ROOT: &str = "/opt/npmplus";

/// Where it writes its access log, once `LOGROTATE=true` tells it to write
/// one at all, in [`crate::accesslog`]'s NPMplus format.
pub const DEFAULT_ACCESS_LOG: &str = "/opt/npmplus/nginx/logs/access.log";

/// The directories under the root NPMplus renders its HTTP hosts into:
/// proxy hosts, redirection hosts and 404 hosts. Each includes
/// `server_http.conf`.
const SITE_DIRS: [&str; 3] = [
    "nginx/proxy_host",
    "nginx/redirection_host",
    "nginx/dead_host",
];

/// The directory of files NPMplus includes and never writes.
const CUSTOM_DIR: &str = "custom_nginx";

/// The file included in every HTTP host's `server` block.
const SERVER_FILE: &str = "server_http.conf";

/// The file included at the top of the `http` block.
const HTTP_FILE: &str = "http_top.conf";

/// This module's own directory, in [`CUSTOM_DIR`].
const OWN_DIR: &str = "stop-bots";

/// [`OWN_DIR`] as NGINX in the container sees it: what the config names.
const CONTAINER_OWN_DIR: &str = "/data/custom_nginx/stop-bots";

/// `custom_nginx/server_http.conf` under `root`.
pub fn server_file(root: &Path) -> PathBuf {
    root.join(CUSTOM_DIR).join(SERVER_FILE)
}

/// `custom_nginx/http_top.conf` under `root`.
pub fn http_file(root: &Path) -> PathBuf {
    root.join(CUSTOM_DIR).join(HTTP_FILE)
}

/// Where the generated files go on the host.
pub fn own_dir(root: &Path) -> PathBuf {
    root.join(CUSTOM_DIR).join(OWN_DIR)
}

/// The two files a block is written into, which are all an uninstall has
/// to take one out of.
pub fn injected_files(root: &Path) -> Vec<PathBuf> {
    vec![server_file(root), http_file(root)]
}

/// What to do when the root is not NPMplus's data directory.
fn missing_root_hint() -> &'static str {
    "NPMplus's data directory is the host directory its compose file mounts at /data, \
     /opt/npmplus unless you changed it. Store where it is with \
     `stop-bots set-web-server npmplus --root <dir>`, or pass `--root <dir>` for one run."
}

/// `root`, if it is NPMplus's data directory as far as can be told: one
/// with the `custom_nginx` NPMplus creates when it starts.
fn checked_root(root: &Path) -> Result<&Path> {
    if root.join(CUSTOM_DIR).is_dir() {
        return Ok(root);
    }
    let what = if root.exists() {
        format!("{} has no {CUSTOM_DIR} directory", root.display())
    } else {
        format!("{} does not exist", root.display())
    };
    Err(crate::hint::with(
        anyhow::anyhow!("{what}"),
        missing_root_hint(),
    ))
}

// ---- finding sites ----

/// The directories of [`SITE_DIRS`] that exist under `root`.
fn site_dirs(root: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    SITE_DIRS
        .iter()
        .map(|dir| root.join(dir))
        .filter(|dir| dir.is_dir())
}

/// Every HTTP host NPMplus has rendered, one per `server` block, as
/// [`crate::nginx::discover_sites`] finds them in its files.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    let root = checked_root(root)?;
    let mut sites = Vec::new();
    for dir in site_dirs(root) {
        sites.extend(crate::nginx::discover_sites(&dir)?);
    }
    Ok(sites)
}

/// Every host and the addresses it listens on, as NPMplus rendered them.
pub fn site_listens(root: &Path) -> Result<Vec<SiteListens>> {
    let root = checked_root(root)?;
    let mut sites = Vec::new();
    for dir in site_dirs(root) {
        sites.extend(crate::nginx::site_listens(&dir)?);
    }
    Ok(sites)
}

/// The access logs the config names, as files on this host: none. The one
/// NPMplus writes is named inside the container, so the stored or the
/// default log is read (see [`crate::logpaths`]).
pub fn access_logs(_root: &Path) -> Vec<PathBuf> {
    Vec::new()
}

/// Where the web console's Web Access put its own site, in a release that
/// had one: never on NPMplus, which no such release supported. A file
/// nobody writes, so `uninstall` never finds one.
pub fn console_site_path(root: &Path) -> PathBuf {
    root.join(CUSTOM_DIR).join("stop-bots-console.conf")
}

/// Every name on the host that declares `server_name` in `config_path`,
/// one of NPMplus's own host files, as [`crate::nginx::server_names_for`]
/// reads them: but read without following a link at it or waiting on a
/// FIFO, the file being the container's ([`read_regular_file`]).
pub fn server_names_for(config_path: &Path, server_name: &str) -> Vec<String> {
    match read_regular_file(config_path) {
        Some(content) => crate::nginx::server_names_in(&content, server_name),
        None => vec![server_name.to_string()],
    }
}

/// [`crate::nginx::site_directives`], read as [`server_names_for`] reads.
pub fn site_directives(
    config_path: &Path,
    server_name: &str,
) -> Option<Vec<(String, Vec<String>)>> {
    crate::nginx::site_directives_in(&read_regular_file(config_path)?, server_name)
}

/// [`crate::nginx::site_service`], read as [`server_names_for`] reads.
pub fn site_service(config_path: &Path, server_name: &str) -> Option<crate::services::Service> {
    crate::services::recognise(&site_directives(config_path, server_name)?)
}

// ---- writing the block ----

/// The block for `config`, as NGINX in the container is to read it, or
/// `None` when it blocks nothing.
fn block(config: &BlockConfig) -> Option<String> {
    crate::nginx::block_text_serving(config, &Path::new(CONTAINER_OWN_DIR).join("robots.txt"))
}

/// The marked block in `content`, if there is one.
fn region(content: &str) -> Option<&str> {
    crate::nginx::locate_marked_in_file(content).map(|(start, end)| &content[start..end])
}

/// `content` with its marked block replaced by `block`: put first in the
/// file when there was none, so that taking it out again leaves the file
/// byte for byte as it was, and taken out when `block` is `None`.
fn with_region(content: &str, block: Option<&str>) -> String {
    let block = block.unwrap_or("");
    match crate::nginx::locate_marked_in_file(content) {
        Some((start, end)) => format!("{}{block}{}", &content[..start], &content[end..]),
        None => format!("{block}{content}"),
    }
}

/// `content` with the marked block taken out.
pub fn without_injected_blocks(content: &str) -> String {
    with_region(content, None)
}

/// The line in `http_top.conf` that reads the generated `http` files.
fn http_block() -> String {
    crate::nginx::marked(&format!("include {CONTAINER_OWN_DIR}/*.conf;\n"))
}

/// Why `server_name`'s `config` cannot be written, if it cannot: it is not
/// the host-wide one, `written`, and NPMplus has no file of its own for
/// one host that stop-bots may write.
fn refusal(server_name: &str, config: &BlockConfig, written: Option<&str>) -> Option<String> {
    (block(config).as_deref() != written).then(|| {
        format!(
            "{server_name} has settings of its own, and NPMplus rewrites each host's own file \
             whenever it is saved, so stop-bots writes one rule for every host, in \
             {CUSTOM_DIR}/{SERVER_FILE}. Clear {server_name}'s own settings, or make them \
             host-wide."
        )
    })
}

/// What applying `site_configs` makes of a site file: nothing, since the
/// rule is not written there. Refused when one of them is not
/// `default_config`.
pub fn blocks_for_file(
    content: &str,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
) -> Result<String> {
    let written = block(default_config);
    for (name, config) in site_configs {
        if let Some(why) = refusal(name, config, written.as_deref()) {
            anyhow::bail!("refusing to apply {name}: {why}");
        }
    }
    Ok(content.to_string())
}

/// What applying `config` to `server_name` makes of its file: nothing, as
/// for [`blocks_for_file`]. Refused when it is not the rule already in
/// `server_http.conf`, which the apply writes from the host-wide settings
/// before it asks this.
pub fn block_for_site(
    content: &str,
    root: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<String> {
    let on_disk = read_under(WebServer::Npmplus, root, &server_file(root))?.unwrap_or_default();
    if let Some(why) = refusal(server_name, config, region(&on_disk)) {
        anyhow::bail!("refusing to apply {server_name}: {why}");
    }
    Ok(content.to_string())
}

/// The generated files the current settings call for: the `http` files in
/// [`own_dir`], `robots.txt` beside them, and the two files of NPMplus's
/// with the marked block in each.
///
/// In the order they may be written: what is read before what reads it,
/// and the `server` block last.
pub fn planned_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let root = &fs::canonicalize(checked_root(root)?)
        .with_context(|| format!("failed to read {}", root.display()))?;
    checked_place(&root.join(CUSTOM_DIR), true)?;
    let own = own_dir(root);
    checked_place(&own, true)?;
    let mut files = Vec::new();
    if db.get_serve_robots_txt()? {
        files.push((own.join("robots.txt"), robots_txt_body(db)?));
    }
    let trust = crate::nginx::trusted_conf(db)?;
    if let Some(body) = &trust {
        files.push((crate::nginx::trusted_conf_path(&own), body.clone()));
    }
    if db.get_rate_limit_enabled()? {
        let (rps, megabytes) = (db.get_rate_limit_rps()?, db.get_rate_limit_zone_mb()?);
        files.push((
            crate::nginx::rate_limit_conf_path(&own),
            crate::nginx::rate_limit_conf_body(rps, megabytes),
        ));
        if trust.is_some() {
            files.push((
                crate::nginx::untrusted_rate_limit_conf_path(&own),
                crate::nginx::untrusted_rate_limit_conf_body(rps, megabytes),
            ));
        }
    }

    let server_block = block(&default_block_config(db)?);
    // The include goes wherever there is a block: its wildcard matches
    // nothing until there is a file, which NGINX allows.
    let http = server_block.as_ref().map(|_| http_block());
    for (path, wanted) in [
        (http_file(root), http.as_deref()),
        (server_file(root), server_block.as_deref()),
    ] {
        let before = read_operators_file(&path)?;
        let after = with_region(&before, wanted);
        if after != before || wanted.is_some() {
            files.push((path, after));
        }
    }
    Ok(files)
}

/// `path`, a place under the root stop-bots writes in, refused if it is
/// a link, or anything but a directory (`dir`) or a regular file. Nothing
/// there is fine: it is created.
fn checked_place(path: &Path, dir: bool) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", path.display())),
    };
    let (fits, what) = if dir {
        (meta.is_dir(), "a directory")
    } else {
        (meta.is_file(), "a regular file")
    };
    if !fits {
        anyhow::bail!(
            "refusing to write {}: it is a link or something else that is not {what}, in a \
             directory NPMplus's container can write, and stop-bots runs as root",
            path.display()
        );
    }
    Ok(())
}

/// One of the operator's two files, read through its directory without
/// following a link ([`checked_place`] says why); empty when it is not
/// there yet.
fn read_operators_file(path: &Path) -> Result<String> {
    checked_place(path, false)?;
    let file =
        DirFile::exactly(path).with_context(|| format!("refusing to read {}", path.display()))?;
    let bytes = file
        .read()
        .with_context(|| format!("failed to read {}", path.display()))?
        .map(|(bytes, _)| bytes)
        .unwrap_or_default();
    String::from_utf8(bytes).with_context(|| format!("{} is not text", path.display()))
}

/// Where each generated file the current settings do not call for would
/// be.
pub fn fallback_unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<PathBuf>> {
    let own = own_dir(root);
    let rate_limited = db.get_rate_limit_enabled()?;
    let trusted = crate::nginx::trusted_conf(db)?.is_some();
    let mut paths = Vec::new();
    if !db.get_serve_robots_txt()? {
        paths.push(own.join("robots.txt"));
    }
    if !rate_limited {
        paths.push(crate::nginx::rate_limit_conf_path(&own));
    }
    // Before the trust file, whose variable it reads; see
    // `nginx::fallback_unused_managed_files`.
    if !(rate_limited && trusted) {
        paths.push(crate::nginx::untrusted_rate_limit_conf_path(&own));
    }
    if !trusted {
        paths.push(crate::nginx::trusted_conf_path(&own));
    }
    Ok(paths)
}

/// The directory a recorded file may be removed from: [`own_dir`] under
/// the resolved root, with nothing below the root resolved. A record is
/// reached following no link ([`DirFile::exactly`]), so one there now, or
/// planted later, is never taken for this directory.
pub fn managed_directories(root: &Path) -> Vec<PathBuf> {
    fs::canonicalize(root)
        .map(|root| own_dir(&root))
        .into_iter()
        .collect()
}

/// Whether what is written for every host is what `config` renders to,
/// and whether `server_name` is still one of NPMplus's hosts.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
    root: &Path,
) -> SiteApplyStatus {
    if site_directives(config_path, server_name).is_none() {
        return SiteApplyStatus::NotFound;
    }
    let read = |path: PathBuf| read_under(WebServer::Npmplus, root, &path).ok().flatten();
    let server = read(server_file(root)).unwrap_or_default();
    let http = read(http_file(root)).unwrap_or_default();
    let expected = block(config);
    let trust_on_disk = config
        .trust
        .as_ref()
        .and_then(|_| read(crate::nginx::trusted_conf_path(&own_dir(root))));
    let current = region(&server) == expected.as_deref()
        && region(&http) == expected.as_ref().map(|_| http_block()).as_deref()
        && crate::nginx::trust_file_is_current(config, trust_on_disk.as_deref());
    if current {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::testing::blocked_bot;
    use std::os::unix::fs::PermissionsExt;

    /// One host of each kind NPMplus renders that a test reads: a proxy
    /// host and a 404 host, in their own directories.
    const PROXY_HOST: &str = "\
# a.example
server {
  server_name a.example www.a.example;
  listen 0.0.0.0:80;
  location / { proxy_pass http://127.0.0.1:8080; }
  include /data/custom_nginx/server_http.conf;
  include /data/custom_nginx/server_proxy.conf;
}
";
    const DEAD_HOST: &str = "\
server {
  server_name gone.example;
  listen 0.0.0.0:80;
  include /data/custom_nginx/server_http.conf;
  include /data/custom_nginx/server_dead.conf;
}
";

    /// An NPMplus data directory as NPMplus leaves it, with `server_http`
    /// in `server_http.conf`.
    fn data_dir(server_http: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (path, text) in [
            ("nginx/proxy_host/1.conf", PROXY_HOST),
            ("nginx/dead_host/2.conf", DEAD_HOST),
            ("custom_nginx/server_http.conf", server_http),
            ("custom_nginx/http_top.conf", ""),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        dir
    }

    /// A database that blocks `BadBot` and nothing else.
    fn blocking_db() -> Db {
        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "badbot", "BadBot");
        db
    }

    /// What `planned_managed_files` would write at `path`.
    fn planned(db: &Db, root: &Path, path: &Path) -> Option<String> {
        planned_managed_files(db, root)
            .unwrap()
            .into_iter()
            .find_map(|(planned, body)| (planned == path).then_some(body))
    }

    #[test]
    fn every_kind_of_host_is_a_site() {
        let dir = data_dir("");
        let names: Vec<String> = discover_sites(dir.path())
            .unwrap()
            .into_iter()
            .map(|site| site.server_name)
            .collect();
        assert_eq!(names, ["a.example", "gone.example"]);
    }

    #[test]
    fn a_root_that_is_not_npmplus_data_says_where_to_point_it() {
        let dir = tempfile::tempdir().unwrap();
        let err = format!("{:#}", discover_sites(dir.path()).unwrap_err());
        assert!(
            err.contains("set-web-server npmplus --root"),
            "error was: {err}"
        );
    }

    /// Trust, rate limiting and robots.txt all on: every part the block
    /// can have, each named at the path the container reads it at.
    #[test]
    fn the_block_and_its_include_match_the_goldens() {
        let dir = data_dir("");
        let db = blocking_db();
        db.trust_address("192.0.2.10").unwrap();
        db.set_rate_limit_enabled(true).unwrap();
        db.set_serve_robots_txt(true).unwrap();
        let root = dir.path();
        crate::golden::assert_golden(
            "npmplus-server_http.conf",
            &planned(&db, root, &server_file(root)).unwrap(),
        );
        crate::golden::assert_golden(
            "npmplus-http_top.conf",
            &planned(&db, root, &http_file(root)).unwrap(),
        );
    }

    #[test]
    fn the_generated_files_go_where_the_include_reads_them() {
        let dir = data_dir("");
        let db = blocking_db();
        db.trust_address("192.0.2.10").unwrap();
        db.set_rate_limit_enabled(true).unwrap();
        db.set_serve_robots_txt(true).unwrap();
        let own = own_dir(dir.path());
        let paths: Vec<PathBuf> = planned_managed_files(&db, dir.path())
            .unwrap()
            .into_iter()
            .map(|(path, _)| path)
            .filter(|path| path.starts_with(&own))
            .collect();
        assert_eq!(
            paths,
            [
                "robots.txt",
                "stop-bots-trusted.conf",
                "stop-bots-limits.conf",
                "stop-bots-limits-untrusted.conf"
            ]
            .map(|name| own.join(name))
        );
    }

    #[test]
    fn the_operators_own_lines_stay_after_the_block() {
        let mine = "if ($http_x_mine) { return 418; }\n";
        let dir = data_dir(mine);
        let written = planned(&blocking_db(), dir.path(), &server_file(dir.path())).unwrap();
        assert!(
            written.starts_with("    # BEGIN stop-bots") && written.ends_with(mine),
            "server_http.conf would be:\n{written}"
        );
    }

    #[test]
    fn taking_the_block_out_leaves_the_file_as_it_was() {
        for before in ["", "if ($http_x_mine) { return 418; }\n"] {
            let with = with_region(
                before,
                block(&default_block_config(&blocking_db()).unwrap()).as_deref(),
            );
            assert_ne!(with, before);
            assert_eq!(
                without_injected_blocks(&with),
                before,
                "with the block:\n{with}"
            );
        }
    }

    #[test]
    fn nothing_to_block_takes_both_blocks_out() {
        let dir = data_dir("return 418;\n");
        let db = blocking_db();
        let root = dir.path();
        crate::webserver::write_planned_managed_files(
            WebServer::Npmplus,
            root,
            &planned_managed_files(&db, root).unwrap(),
        )
        .unwrap();
        db.set_bot_status("badbot", crate::db::BotStatus::Allowed)
            .unwrap();
        assert_eq!(
            (
                planned(&db, root, &server_file(root)).as_deref(),
                planned(&db, root, &http_file(root)).as_deref()
            ),
            (Some("return 418;\n"), Some(""))
        );
    }

    /// A pattern that quotes the end marker does not end the block: the
    /// markers are found as comments only, so a second apply replaces the
    /// first block rather than leaving half of it behind.
    #[test]
    fn a_pattern_quoting_the_marker_does_not_end_the_block() {
        let db = Db::open_in_memory().unwrap();
        blocked_bot(&db, "hostile", "Evil# END stop-bots");
        let text = block(&default_block_config(&db).unwrap());
        let once = with_region("", text.as_deref());
        assert_eq!(with_region(&once, text.as_deref()), once);
        assert_eq!(without_injected_blocks(&once), "");
    }

    #[test]
    fn a_site_with_settings_of_its_own_is_refused() {
        let db = blocking_db();
        let default = default_block_config(&db).unwrap();
        let mut own = default.clone();
        own.patterns.push("OtherBot".to_string());
        let site_file = "server { server_name a.example; }\n";
        assert_eq!(
            blocks_for_file(
                site_file,
                &[("a.example".into(), default.clone())],
                &default
            )
            .unwrap(),
            site_file,
            "the host-wide settings write nothing into NPMplus's own file"
        );
        let err = blocks_for_file(site_file, &[("a.example".into(), own)], &default)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("a.example has settings of its own"),
            "error was: {err}"
        );
    }

    #[test]
    fn every_host_reads_the_one_block_as_its_status() {
        let dir = data_dir("");
        let db = blocking_db();
        let root = dir.path();
        let proxy = root.join("nginx/proxy_host/1.conf");
        let default = default_block_config(&db).unwrap();
        let status =
            |name: &str, config: &BlockConfig| site_apply_status(&proxy, name, config, root);
        assert_eq!(status("a.example", &default), SiteApplyStatus::Stale);
        crate::webserver::write_planned_managed_files(
            WebServer::Npmplus,
            root,
            &planned_managed_files(&db, root).unwrap(),
        )
        .unwrap();
        let mut own = default.clone();
        own.patterns.push("OtherBot".to_string());
        let cases = [
            (
                "applied",
                status("a.example", &default),
                SiteApplyStatus::UpToDate,
            ),
            (
                "its own settings",
                status("a.example", &own),
                SiteApplyStatus::Stale,
            ),
            (
                "not a host",
                status("b.example", &default),
                SiteApplyStatus::NotFound,
            ),
        ];
        for (what, got, expected) in cases {
            assert_eq!(got, expected, "{what}");
        }
    }

    /// The data directory is the container's to write, and stop-bots is
    /// root: a link planted there is refused rather than followed, and
    /// what it points at is neither read into the plan nor written.
    #[test]
    fn a_link_in_the_data_directory_is_refused_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("shadow");
        fs::write(&secret, "root:secret\n").unwrap();
        let cases = [
            ("server_http.conf", secret.clone()),
            ("stop-bots", outside.path().to_path_buf()),
        ];
        for (name, target) in cases {
            let dir = data_dir("");
            let db = blocking_db();
            db.set_serve_robots_txt(true).unwrap();
            let link = dir.path().join(CUSTOM_DIR).join(name);
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let planned = planned_managed_files(&db, dir.path());

            let err = format!("{:#}", planned.expect_err(name));
            assert!(err.contains("refusing to write"), "{name}: {err}");
            assert_eq!(
                fs::read_to_string(&secret).unwrap(),
                "root:secret\n",
                "{name}"
            );
            assert!(!outside.path().join("robots.txt").exists(), "{name}");
        }
    }

    /// What a failed test puts back is a file the container made, and root
    /// writes it: it goes back with its bytes, but without the setuid bit
    /// the container gave it.
    #[test]
    fn a_file_put_back_loses_its_setuid_bit() {
        let dir = data_dir("mine\n");
        let path = server_file(dir.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
        let snapshot =
            Snapshot::of_apply(WebServer::Npmplus, dir.path(), [path.clone()], &[], []).unwrap();
        fs::write(&path, "changed\n").unwrap();

        snapshot.restore().unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            (fs::read_to_string(&path).unwrap(), mode),
            ("mine\n".into(), 0o755)
        );
    }

    /// A FIFO where `server_http.conf` goes refuses the apply rather than
    /// hanging it with the apply lock held, and a status read finds nothing
    /// there rather than waiting.
    #[test]
    fn a_fifo_in_the_data_directory_hangs_nothing() {
        let dir = data_dir("");
        let path = server_file(dir.path());
        fs::remove_file(&path).unwrap();
        crate::testing::mkfifo(&path);
        let db = blocking_db();

        let planned = planned_managed_files(&db, dir.path());
        let status = site_apply_status(
            &dir.path().join("nginx/proxy_host/1.conf"),
            "a.example",
            &default_block_config(&db).unwrap(),
            dir.path(),
        );

        let err = format!("{:#}", planned.expect_err("a FIFO is not a regular file"));
        assert!(err.contains("refusing to write"), "{err}");
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    /// Switching away from NPMplus first asks what stop-bots left in its
    /// data directory: a FIFO at a name it asks about is not waited on.
    #[test]
    fn asking_what_was_left_waits_on_no_fifo() {
        let dir = data_dir("");
        fs::remove_file(server_file(dir.path())).unwrap();
        crate::testing::mkfifo(&server_file(dir.path()));
        crate::testing::mkfifo(&console_site_path(dir.path()));

        let left = crate::webserver::leftovers(WebServer::Npmplus, dir.path());

        assert_eq!(left, Vec::<PathBuf>::new());
    }

    /// Cleaning up removes only what stop-bots generated, from its own
    /// directory, and refuses to look through a link put there.
    #[test]
    fn only_generated_files_are_cleaned_up_and_never_through_a_link() {
        let db = blocking_db();
        let dir = data_dir("");
        let own = own_dir(dir.path());
        fs::create_dir(&own).unwrap();
        fs::write(own.join("robots.txt"), "User-agent: *\n").unwrap();
        let unused = crate::webserver::unused_managed_files(WebServer::Npmplus, &db, dir.path());
        assert_eq!(
            unused.unwrap().len(),
            0,
            "a robots.txt with no header is not ours"
        );

        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("robots.txt"),
            "# Generated by stop-bots\n",
        )
        .unwrap();
        fs::remove_dir_all(&own).unwrap();
        std::os::unix::fs::symlink(outside.path(), &own).unwrap();
        let err = crate::webserver::unused_managed_files(WebServer::Npmplus, &db, dir.path())
            .expect_err("a link to another directory is not followed");
        assert!(format!("{err:#}").contains("refusing"), "{err:#}");
        assert!(outside.path().join("robots.txt").exists());
    }

    /// `server_http.conf` is the operator's, and is replaced keeping its
    /// owner and mode; stop-bots' own files are written as its own.
    #[test]
    fn the_operators_file_keeps_its_mode() {
        let dir = data_dir("");
        let root = dir.path();
        let db = blocking_db();
        db.set_serve_robots_txt(true).unwrap();
        fs::set_permissions(server_file(root), fs::Permissions::from_mode(0o600)).unwrap();
        crate::webserver::write_planned_managed_files(
            WebServer::Npmplus,
            root,
            &planned_managed_files(&db, root).unwrap(),
        )
        .unwrap();
        let mode = |path: PathBuf| fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            (
                mode(server_file(root)),
                mode(own_dir(root).join("robots.txt"))
            ),
            (0o600, 0o644)
        );
    }
}
