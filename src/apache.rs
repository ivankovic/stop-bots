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

//! The Apache httpd backend: finds `<VirtualHost>` sections, and injects
//! and removes a sentinel-marked block of `mod_rewrite` rules at the top of
//! each one.
//!
//! Everything around that — the policy, the transaction an apply runs in,
//! the generated files' lifecycle — is [`crate::webserver`]'s, shared with
//! [`crate::nginx`]. This module only speaks Apache.
//!
//! ## How a block decides
//!
//! `mod_rewrite` is the one module every Apache has that can look at the
//! user agent, the path and the client's trust all at once, and it runs in
//! the translate-name phase, before `Alias`, `ProxyPass`, `<Location>` or
//! `.htaccess` can route the request anywhere. The block uses the same flag
//! idiom the NGINX block does, with an environment variable as the flag:
//! each reason to block sets it, each exemption clears it, and one last
//! rule acts on it. Order is the whole mechanism, and every rule but the
//! last carries no `[L]`, so the site's own rewrite rules after the block
//! still run.
//!
//! ```apache
//! # BEGIN stop-bots (DO NOT EDIT)
//! RewriteEngine On
//! RewriteCond %{HTTP_USER_AGENT} "(?:BadBot|EvilBot)" [NC]
//! RewriteRule ^ - [E=stop_bots_block:1]
//! RewriteCond %{REQUEST_URI} "(?:^(/api/))" [NC]
//! RewriteRule ^ - [E=stop_bots_block:0]
//! RewriteCond %{ENV:REDIRECT_STATUS} ^$
//! RewriteCond %{ENV:stop_bots_block} =1
//! RewriteRule ^ - [R=403,L,NS]
//! # END stop-bots
//! ```
//!
//! **The decision is made once, on the request the client sent.** Rules in
//! a `<VirtualHost>` run again on every internal redirect — a front
//! controller's `.htaccess` sending `/wp-json/x` on to `/index.php`, an
//! `ErrorDocument` — and on every subrequest (`DirectoryIndex` looking for
//! `index.php`), each time with the *new* path. An exemption for `/wp-json/`
//! would pass the first round and lose the second, and a blocked request's
//! own error page would be blocked in turn. So the last rule acts only on
//! the original request: not when `REDIRECT_STATUS` is set, which Apache
//! does on every internal redirect, and not in a subrequest (`NS`). That
//! lets nothing through that was turned away: a redirect or a subrequest
//! only ever happens on behalf of a request the first round let through, or
//! to send a blocked one its error page.
//!
//! ## What Apache cannot do that NGINX can
//!
//! - **Rate limiting.** Apache has no request-rate limit of its own (only
//!   third-party modules), so the setting is not rendered here, and the
//!   front-ends do not offer it on an Apache host.
//! - **Closing the connection (444), the tarpit and the teapot (418).**
//!   Each answers `403` instead: a block still blocks, only less cheaply.
//!   `mod_rewrite` refuses `[R=418]` outright, which the config test
//!   reports and the apply then undoes.
//!
//! ## What the config test does not catch, and an apply refuses
//!
//! A block can pass `apache2ctl configtest` and still do nothing, or do far
//! more than asked. Each case below is read from the config on disk
//! ([`Tree`]) and refused, by the apply, with what to change, and never
//! reported as up to date by status:
//!
//! - a generated file in a directory Apache does not `Include` — RHEL's
//!   `httpd.conf` reads `conf.d`, never a `conf-enabled` (see
//!   [`conf_enabled_dir`]);
//! - a `RewriteEngine Off` later in the same `<VirtualHost>`, which
//!   switches the whole block off;
//! - the HTTP/1.x rule on a host that does not speak HTTP/2, where it
//!   would turn away every visitor.
//!
//! ## Requirements
//!
//! `mod_rewrite`, which Debian ships but does not enable (`a2enmod
//! rewrite`), and `mod_setenvif` and `mod_alias`, which it enables. A
//! missing `mod_rewrite` fails the config test, and the apply puts every
//! file back and says so — a block that silently did nothing would be
//! worse.
//!
//! ## Layouts
//!
//! Debian's (`/etc/apache2`, with `conf-enabled` and `sites-enabled`), and
//! RHEL's (`/etc/httpd`, which reads everything of its own from `conf.d`).

use crate::webserver::*;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// The same markers NGINX's blocks carry, so an operator reading either
/// finds the same words. Apache only has whole-line comments, which is
/// what these are.
const BLOCK_BEGIN: &str = "# BEGIN stop-bots (DO NOT EDIT)";
const BLOCK_END: &str = "# END stop-bots";

/// The markers around the section the web console's Web Access wrote into
/// a site, in a release that had one: NGINX's too. Nothing writes them now;
/// `uninstall` takes the section out with the blocks. **Frozen**, like
/// [`BLOCK_BEGIN`].
const CONSOLE_BEGIN: &str = "# BEGIN stop-bots console (DO NOT EDIT)";
const CONSOLE_END: &str = "# END stop-bots console";

/// The stock location on Debian and Ubuntu.
pub const DEFAULT_ROOT: &str = "/etc/apache2";

/// The environment variable a block's rules set to block a request.
const BLOCK_VAR: &str = "stop_bots_block";

/// The environment variable the trust file sets for a trusted client.
const TRUSTED_VAR: &str = "stop_bots_trusted";

/// Where this project writes its own Apache files: the generated
/// `robots.txt`. A directory of its own, beside NGINX's, so that
/// switching a host from one server to the other leaves neither's files
/// in the other's way.
pub const MANAGED_DIR: &str = "/etc/stop-bots/apache";

/// Environment override for [`MANAGED_DIR`], for the end-to-end tests,
/// which drive the real binary and must not write to `/etc`. The same
/// test-only rationale as `nginx::MANAGED_DIR_ENV`.
pub const MANAGED_DIR_ENV: &str = "STOP_BOTS_APACHE_DIR";

/// The directory this project writes its own Apache files into.
pub fn managed_dir() -> PathBuf {
    std::env::var_os(MANAGED_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(MANAGED_DIR))
}

/// The generated `robots.txt`, aliased by the block when robots.txt
/// generation is on.
pub fn robots_txt_path() -> PathBuf {
    managed_dir().join("robots.txt")
}

/// The stock directory Debian's `apache2.conf` includes `*.conf` from.
pub const CONF_ENABLED_DIR: &str = "/etc/apache2/conf-enabled";

/// Environment override for [`conf_enabled_dir`], for the end-to-end
/// tests, as [`MANAGED_DIR_ENV`].
pub const CONF_ENABLED_DIR_ENV: &str = "STOP_BOTS_APACHE_CONF_D";

/// Where the server-wide trust file goes: `conf-enabled` beside the sites,
/// for a root that has one or is a tree of its own, and the stock one for a
/// root inside the stock tree (`/etc/apache2/sites-available`) — the same
/// rule, and for the same reasons, as `nginx::conf_d_dir`.
///
/// **And `conf.d` for a root that has that and no `conf-enabled`**: RHEL's
/// layout, whose `httpd.conf` ends in `IncludeOptional conf.d/*.conf` and
/// reads no `conf-enabled` at all. A trust file written to one there passed
/// the config test, read as up to date, and was never loaded, so every
/// trusted monitor was blocked. Whatever this picks, an apply then checks
/// that Apache loads it ([`unloaded_file`]).
///
/// A plain file in `conf-enabled` rather than one in `conf-available` and
/// a link: `a2enconf` is how an operator enables their own files, and one
/// file is one thing to remove.
pub fn conf_enabled_dir(root: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os(CONF_ENABLED_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let beside_the_sites = root.join("conf-enabled");
    let rhel = root.join("conf.d");
    if !beside_the_sites.is_dir() && rhel.is_dir() {
        return rhel;
    }
    let in_stock_tree = root.starts_with(DEFAULT_ROOT)
        && !root
            .components()
            .any(|part| part == std::path::Component::ParentDir);
    if beside_the_sites.is_dir() || !in_stock_tree {
        return beside_the_sites;
    }
    PathBuf::from(CONF_ENABLED_DIR)
}

/// The trust file: one `SetEnvIf` per trusted address or user agent.
/// The same name as NGINX's, so `ManagedKind` knows it either way.
pub fn trusted_conf_path(conf_enabled: &Path) -> PathBuf {
    conf_enabled.join("stop-bots-trusted.conf")
}

/// What to do when the config root is not there.
fn missing_root_hint() -> &'static str {
    "If Apache's config lives somewhere else, store where with \
     `stop-bots set-web-server apache --root <dir>`, or pass `--root <dir>` for one run."
}

// ---- reading a config ----

/// One logical line of a config file: physical lines joined where one
/// ends in a backslash, as Apache's own reader joins them.
struct Line {
    /// Byte offset of its first character.
    start: usize,
    /// Byte offset just past it, its line break included.
    end: usize,
    /// Its text, continuations joined, without the line break.
    text: String,
}

fn lines(content: &str) -> Vec<Line> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut text = String::new();
    let mut at = 0;
    for physical in content.split_inclusive('\n') {
        let bare = physical.trim_end_matches('\n').trim_end_matches('\r');
        at += physical.len();
        if let Some(joined) = bare.strip_suffix('\\') {
            text.push_str(joined);
            continue;
        }
        text.push_str(bare);
        out.push(Line {
            start,
            end: at,
            text: std::mem::take(&mut text),
        });
        start = at;
    }
    if !text.is_empty() {
        out.push(Line {
            start,
            end: at,
            text,
        });
    }
    out
}

/// A `<VirtualHost>` section found while scanning a config file.
#[derive(Debug, Clone)]
struct VirtualHost {
    /// `ServerName` first (or `_` when there is none, the catch-all name
    /// NGINX configs use for the same thing), then every `ServerAlias`.
    names: Vec<String>,
    /// Whether it terminates TLS: `SSLEngine on`, or an address on 443.
    /// The same thing NGINX's `is_tls` is load-bearing for — see
    /// `nginx::ServerBlock::is_tls`.
    is_tls: bool,
    /// The addresses on the `<VirtualHost ...>` line, as written.
    addresses: Vec<String>,
    /// Byte offset of the line after `<VirtualHost ...>`, where a block
    /// is inserted.
    open: usize,
    /// Byte offset of the `</VirtualHost>` line.
    close: usize,
    /// Every directive inside, nested sections' included, as its name
    /// (lowercased) and its arguments.
    directives: Vec<(String, Vec<String>)>,
    /// The directives that set something for the host as a whole, in
    /// order: those outside every `<Directory>`, `<Location>`, `<Files>`,
    /// `<If>` or `<Proxy>`, though maybe inside an `<IfModule>` or another
    /// section that only decides whether its lines are read. A
    /// `RewriteEngine Off` here switches the block off; one inside a
    /// `<Directory>` is about that directory's `.htaccess`-style rules and
    /// does not.
    server_scope: Vec<(String, Vec<String>)>,
}

/// Whether a section named `name` (lowercased) only decides whether the
/// lines inside it are read, leaving them in the scope around it.
fn is_conditional(name: &str) -> bool {
    matches!(
        name,
        "ifmodule" | "ifdefine" | "ifversion" | "iffile" | "ifdirective" | "ifsection"
    )
}

/// Splits a directive's arguments the way Apache's `ap_getword_conf`
/// does: whitespace separates words, and a word that starts with a quote
/// runs to the matching quote, inside which a backslash escapes that quote
/// or another backslash.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            return out;
        };
        let mut word = String::new();
        if first == '"' || first == '\'' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' if chars.peek().is_some_and(|&n| n == first || n == '\\') => {
                        word.push(chars.next().unwrap_or('\\'));
                    }
                    c if c == first => break,
                    c => word.push(c),
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                word.push(c);
            }
        }
        out.push(word);
    }
}

/// A section's opening or closing tag on `line`: its name, lowercased,
/// whether it closes, and its arguments.
fn section(line: &str) -> Option<(String, bool, Vec<String>)> {
    let tag = line.trim().strip_prefix('<')?;
    let tag = tag.strip_suffix('>')?;
    let (closing, tag) = match tag.strip_prefix('/') {
        Some(rest) => (true, rest),
        None => (false, tag),
    };
    let mut parts = words(tag);
    if parts.is_empty() {
        return None;
    }
    let name = parts.remove(0).to_ascii_lowercase();
    Some((name, closing, parts))
}

/// A host name as `ServerName` may write it — `https://example.com:443`
/// — reduced to the name, which is what a site is stored under.
fn bare_name(name: &str) -> String {
    let name = name.split_once("://").map_or(name, |(_, rest)| rest);
    let name = match name.strip_prefix('[') {
        // `[2001:db8::1]:443`: the brackets hold the colons.
        Some(v6) => return v6.split(']').next().unwrap_or(v6).to_string(),
        None => name,
    };
    name.split(':').next().unwrap_or(name).to_string()
}

/// Every `<VirtualHost>` in `content`, in order.
///
/// Only whole-line comments are comments in Apache, and only a line
/// starting with `<` can open or close a section, so a line this tool
/// writes — every one of which starts with a directive name or `#` — can
/// never be read as structure, whatever a quoted pattern in it holds.
fn virtual_hosts(content: &str) -> Vec<VirtualHost> {
    let mut hosts = Vec::new();
    // The open `<VirtualHost>`, and the sections open inside it.
    let mut current: Option<(VirtualHost, Vec<String>)> = None;
    for line in lines(content) {
        let text = line.text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if let Some((name, closing, args)) = section(text) {
            match (&mut current, name.as_str(), closing) {
                (None, "virtualhost", false) => {
                    let is_tls = args.iter().any(|addr| addr.ends_with(":443"));
                    current = Some((
                        VirtualHost {
                            names: Vec::new(),
                            is_tls,
                            addresses: args.clone(),
                            open: line.end,
                            close: line.end,
                            directives: Vec::new(),
                            server_scope: Vec::new(),
                        },
                        Vec::new(),
                    ));
                }
                (Some((host, open)), "virtualhost", true) if open.is_empty() => {
                    host.close = line.start;
                    let (mut host, _) = current.take().expect("a host is open");
                    finish(&mut host);
                    hosts.push(host);
                }
                (Some((_, open)), _, false) => open.push(name),
                (Some((_, open)), _, true) => {
                    open.pop();
                }
                (None, _, _) => {}
            }
            continue;
        }
        if let Some((host, open)) = &mut current {
            let mut parts = words(text);
            if parts.is_empty() {
                continue;
            }
            let name = parts.remove(0).to_ascii_lowercase();
            if open.iter().all(|section| is_conditional(section)) {
                host.server_scope.push((name.clone(), parts.clone()));
            }
            host.directives.push((name, parts));
        }
    }
    hosts
}

/// Fills in a closed host's names and TLS from its directives.
fn finish(host: &mut VirtualHost) {
    let mut server_name = None;
    let mut aliases = Vec::new();
    for (name, args) in &host.directives {
        match name.as_str() {
            "servername" => server_name = server_name.or(args.first().map(|n| bare_name(n))),
            "serveralias" => aliases.extend(args.iter().map(|n| bare_name(n))),
            "sslengine" => {
                host.is_tls |= args.first().is_some_and(|v| v.eq_ignore_ascii_case("on"))
            }
            _ => {}
        }
    }
    host.names = std::iter::once(server_name.unwrap_or_else(|| "_".to_string()))
        .chain(aliases)
        .collect();
}

/// Walks `root` for config files holding `<VirtualHost>` sections,
/// returning one [`DiscoveredSite`] per section, named after its
/// `ServerName`. The same walk, and the same refusal of a root that does
/// not exist, as `nginx::discover_sites`: [`crate::webserver::config_files`].
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    if !root.exists() {
        return Err(crate::hint::with(
            anyhow::anyhow!("{} does not exist", root.display()),
            missing_root_hint(),
        ));
    }
    let mut sites = Vec::new();
    for entry in crate::webserver::config_files(root) {
        let path = entry.path();
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for host in virtual_hosts(&content) {
            sites.push(DiscoveredSite {
                server_name: host.names[0].clone(),
                config_path: path.to_path_buf(),
            });
        }
    }
    Ok(sites)
}

/// Every `<VirtualHost>` under `root`, with the addresses it is served
/// on: [`discover_sites`]' walk, keeping what the health check needs to
/// ask the site something over loopback. A host with `SSLEngine on` is
/// TLS on every address it names.
pub fn site_listens(root: &Path) -> Result<Vec<SiteListens>> {
    if !root.exists() {
        anyhow::bail!("{} does not exist", root.display());
    }
    let mut sites = Vec::new();
    for entry in crate::webserver::config_files(root) {
        let Ok(content) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for host in virtual_hosts(&content) {
            let listens = host
                .addresses
                .iter()
                .filter_map(|address| Listen::parse_address(address))
                .map(|(address, port)| Listen {
                    address,
                    port,
                    tls: host.is_tls,
                })
                .collect();
            sites.push(SiteListens {
                server_name: host.names[0].clone(),
                listens,
            });
        }
    }
    Ok(sites)
}

// ---- what the rest of the config says ----

/// Where Apache's main config file is, relative to the directory relative
/// paths in it are relative to: Debian's, a source build's, and RHEL's,
/// which keeps it under `conf/` with the server root above that.
const MAIN_CONFIGS: [&str; 3] = ["apache2.conf", "httpd.conf", "conf/httpd.conf"];

/// How many directories above a root the main config is looked for: a root
/// of `/etc/apache2/sites-available`, or RHEL's `/etc/httpd/conf.d`, is
/// still that tree.
const MAIN_CONFIG_LEVELS_UP: usize = 2;

/// The directory Apache's main config is in, at or up to
/// [`MAIN_CONFIG_LEVELS_UP`] above `root`, and the file: `/etc/httpd` and
/// `/etc/httpd/conf/httpd.conf` for any root in RHEL's tree. `None` when
/// there is none — a root that is not Apache's, as far as this can tell.
fn main_config(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let root = std::path::absolute(root).ok()?;
    root.ancestors()
        .take(MAIN_CONFIG_LEVELS_UP + 1)
        .find_map(|dir| {
            MAIN_CONFIGS
                .iter()
                .map(|name| dir.join(name))
                .find(|main| main.is_file())
                .map(|main| (dir.to_path_buf(), main))
        })
}

/// Apache's configuration as Apache reads it under one root: its main
/// file, then everything that `Include`s, transitively.
///
/// Read because the config test passes configs that do nothing: a file in
/// a directory nothing includes, a block a later `RewriteEngine Off`
/// switches off, a rule for HTTP/2 that the server never speaks. Each of
/// those is checked against this, and refused.
///
/// What it does not know, it says it does not know, and nothing is refused
/// on it: a root with no main file at or just above it ([`Tree::find`]), or
/// an include it cannot resolve. Everything else is approximate on purpose
/// in the one direction that is safe: a conditional section's lines all
/// count as read, so a file this says is included may not be — but a file
/// this says is *not* included is not, whatever the conditions say.
struct Tree {
    /// The main file.
    main: PathBuf,
    /// What relative paths are relative to: the server root.
    base: PathBuf,
    /// The `ServerRoot` the main file declares, when it is not `base`: a
    /// config on a bind mount names the paths it has inside its container,
    /// and those are read as the same paths under `base`.
    declared_root: Option<PathBuf>,
    /// Every `Include` and `IncludeOptional` pattern, made absolute.
    includes: Vec<PathBuf>,
    /// Whether an include could not be resolved (it holds a `${VAR}`), in
    /// which case no file can be said to be left out.
    unresolved: bool,
    /// Every file read, in the order Apache reads them, with its text.
    files: Vec<(PathBuf, String)>,
}

impl Tree {
    /// The tree whose main file is at `root`, or a level or two above it,
    /// read; `None` when there is none.
    fn find(root: &Path) -> Option<Tree> {
        let (dir, main) = main_config(root)?;
        let text = fs::read_to_string(&main).ok()?;
        let declared = lines(&text).into_iter().find_map(|line| {
            let parts = words(line.text.trim());
            (parts.len() == 2 && parts[0].eq_ignore_ascii_case("serverroot"))
                .then(|| PathBuf::from(&parts[1]))
        });
        // The declared root is the base when the main file is inside it, as
        // on RHEL; otherwise it names the container's paths, and the base is
        // the directory the main file was found from.
        let (base, declared_root) = match declared {
            Some(declared) if main.starts_with(&declared) => (declared, None),
            declared => (dir, declared.filter(|d| d.is_absolute())),
        };
        let mut tree = Tree {
            main: main.clone(),
            base,
            declared_root,
            includes: Vec::new(),
            unresolved: false,
            files: Vec::new(),
        };
        tree.load(&main, 0);
        Some(tree)
    }

    /// Reads `file` and, depth first, what it includes, as Apache does.
    fn load(&mut self, file: &Path, depth: usize) {
        const MAX_DEPTH: usize = 16;
        const MAX_FILES: usize = 4096;
        if depth > MAX_DEPTH
            || self.files.len() >= MAX_FILES
            || self.files.iter().any(|(read, _)| read == file)
        {
            return;
        }
        let Ok(text) = fs::read_to_string(file) else {
            return;
        };
        self.files.push((file.to_path_buf(), text.clone()));
        for line in lines(&text) {
            let parts = words(line.text.trim());
            let [name, argument] = parts.as_slice() else {
                continue;
            };
            if !name.eq_ignore_ascii_case("include")
                && !name.eq_ignore_ascii_case("includeoptional")
            {
                continue;
            }
            let Some(pattern) = self.resolve(argument) else {
                self.unresolved = true;
                continue;
            };
            self.includes.push(pattern.clone());
            for included in expand(&pattern) {
                self.load(&included, depth + 1);
            }
        }
    }

    /// A path as the config writes it, as a path on this host; `None` for
    /// one holding a variable, whose value only Apache's environment knows.
    fn resolve(&self, written: &str) -> Option<PathBuf> {
        if written.contains("${") {
            return None;
        }
        let path = Path::new(written);
        if !path.is_absolute() {
            return Some(self.base.join(path));
        }
        Some(
            match self
                .declared_root
                .as_ref()
                .and_then(|declared| path.strip_prefix(declared).ok())
            {
                Some(inside) => self.base.join(inside),
                None => path.to_path_buf(),
            },
        )
    }

    /// Whether Apache reads `file`, which need not exist yet: `None` when
    /// that cannot be told.
    fn includes(&self, file: &Path) -> Option<bool> {
        let file = std::path::absolute(file).ok()?;
        if file == self.main || self.includes.iter().any(|pattern| matches(pattern, &file)) {
            return Some(true);
        }
        (!self.unresolved).then_some(false)
    }

    /// Whether some file Apache reads loads the module `name`
    /// (`http2_module`).
    fn loads_module(&self, name: &str) -> bool {
        self.directives_outside_hosts().any(|(directive, args)| {
            directive == "loadmodule" && args.first().is_some_and(|m| m == name)
        })
    }

    /// The last `Protocols` the main server sets, which every
    /// `<VirtualHost>` without one of its own inherits.
    fn main_protocols(&self) -> Option<Vec<String>> {
        self.directives_outside_hosts()
            .filter(|(directive, _)| directive == "protocols")
            .last()
            .map(|(_, args)| args)
    }

    /// Every directive outside a `<VirtualHost>`, in the order Apache reads
    /// them, as its name (lowercased) and arguments.
    fn directives_outside_hosts(&self) -> impl Iterator<Item = (String, Vec<String>)> + '_ {
        self.files.iter().flat_map(|(_, text)| {
            let mut in_host = false;
            lines(text).into_iter().filter_map(move |line| {
                let text = line.text.trim();
                if text.starts_with('#') {
                    return None;
                }
                if let Some((name, closing, _)) = section(text) {
                    if name == "virtualhost" {
                        in_host = !closing;
                    }
                    return None;
                }
                if in_host {
                    return None;
                }
                let mut parts = words(text);
                (!parts.is_empty()).then(|| {
                    let name = parts.remove(0).to_ascii_lowercase();
                    (name, parts)
                })
            })
        })
    }
}

// ---- the access logs the config names ----

/// Every file a `CustomLog`, `TransferLog` or `GlobalLog` names in the
/// config Apache reads under `root` ([`Tree`]), in the order Apache reads
/// them, each once; under a root with no main file, in every file the site
/// scan reads.
///
/// Left out, because they are not a file on this host to read: a piped
/// log (`"|/usr/bin/rotatelogs ..."`), a `syslog:` target, and a path
/// with a variable in it, whose value only Apache's environment knows.
/// The one exception is Debian's `${APACHE_LOG_DIR}`, which every site
/// Debian ships logs under: it is read from the `envvars` file beside
/// `apache2.conf`, as `apache2ctl` reads it. A relative path is the server
/// root's, as Apache resolves it: RHEL's `logs/access_log` is
/// `/etc/httpd/logs/access_log`.
pub fn access_logs(root: &Path) -> Vec<PathBuf> {
    let (files, base) = match Tree::find(root) {
        Some(tree) => (tree.files, tree.base),
        None => {
            let Ok(base) = std::path::absolute(root) else {
                return Vec::new();
            };
            let files = crate::webserver::config_files(root)
                .filter_map(|entry| {
                    let text = fs::read_to_string(entry.path()).ok()?;
                    Some((entry.into_path(), text))
                })
                .collect();
            (files, base)
        }
    };
    let log_dir = apache_log_dir(&base);
    let mut logs: Vec<PathBuf> = Vec::new();
    for (_, text) in &files {
        for line in lines(text) {
            let parts = words(line.text.trim());
            let [directive, written, ..] = parts.as_slice() else {
                continue;
            };
            if !["customlog", "transferlog", "globallog"]
                .iter()
                .any(|name| directive.eq_ignore_ascii_case(name))
            {
                continue;
            }
            if let Some(path) = access_log_path(written, &base, log_dir.as_deref()) {
                if !logs.contains(&path) {
                    logs.push(path);
                }
            }
        }
    }
    logs
}

/// The file a log directive's first argument names; `None` for one that
/// names no file here. See [`access_logs`].
fn access_log_path(written: &str, base: &Path, log_dir: Option<&Path>) -> Option<PathBuf> {
    if written.starts_with('|') || written.starts_with("syslog:") {
        return None;
    }
    let written = match (written.strip_prefix("${APACHE_LOG_DIR}"), log_dir) {
        (Some(rest), Some(dir)) => format!("{}{rest}", dir.display()),
        _ => written.to_string(),
    };
    if written.contains('$') {
        return None;
    }
    Some(base.join(written))
}

/// The value Debian's `envvars` beside the main config gives
/// `APACHE_LOG_DIR`, for the default instance: `/var/log/apache2`. Its
/// `$SUFFIX` names another instance (`apache2@name`) and is empty for
/// this one. `None` when there is no such file, or it says something else.
fn apache_log_dir(base: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(base.join("envvars")).ok()?;
    let value = text.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        line.strip_prefix("APACHE_LOG_DIR=")
    })?;
    let value = value
        .trim()
        .trim_matches(['"', '\''])
        .replace("$SUFFIX", "");
    let dir = PathBuf::from(value);
    (dir.is_absolute() && !dir.as_os_str().to_string_lossy().contains('$')).then_some(dir)
}

/// Whether a path holds a wildcard Apache expands.
fn has_wildcard(text: &str) -> bool {
    text.contains(['*', '?', '['])
}

/// The files an `Include` of `pattern` reads, in the order it reads them:
/// a wildcard in any part of the path is matched against what is there,
/// and a directory is every file under it. A wildcard does not match a
/// leading dot, as Apache's does not — which is what keeps the temporary
/// files [`write_atomically`] makes out of the config.
fn expand(pattern: &Path) -> Vec<PathBuf> {
    let mut found = vec![PathBuf::from("/")];
    for part in pattern.components() {
        let std::path::Component::Normal(part) = part else {
            if part == std::path::Component::ParentDir {
                found.iter_mut().for_each(|dir| dir.push(".."));
            }
            continue;
        };
        let part = part.to_string_lossy();
        if !has_wildcard(&part) {
            found.iter_mut().for_each(|dir| dir.push(part.as_ref()));
            continue;
        }
        found = found
            .iter()
            .flat_map(|dir| sorted_entries(dir))
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name_matches(&part, &name.to_string_lossy()))
            })
            .collect();
    }
    found
        .into_iter()
        .flat_map(|path| {
            if path.is_dir() {
                WalkDir::new(&path)
                    .sort_by_file_name()
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| !e.file_type().is_dir())
                    .map(|e| e.into_path())
                    .collect()
            } else if path.exists() {
                vec![path]
            } else {
                Vec::new()
            }
        })
        .collect()
}

/// What is in `dir`, by name.
fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    entries
}

/// Whether `file`, which need not exist, is one an `Include` of `pattern`
/// reads: `pattern` itself, a file under it if it is a directory, or one
/// its wildcards match part for part.
fn matches(pattern: &Path, file: &Path) -> bool {
    if !has_wildcard(&pattern.to_string_lossy()) {
        return file == pattern || (pattern.is_dir() && file.starts_with(pattern));
    }
    let wanted: Vec<_> = pattern.components().collect();
    let parts: Vec<_> = file.components().collect();
    wanted.len() == parts.len()
        && wanted
            .iter()
            .zip(&parts)
            .all(|(want, part)| match (want, part) {
                (std::path::Component::Normal(want), std::path::Component::Normal(part)) => {
                    name_matches(&want.to_string_lossy(), &part.to_string_lossy())
                }
                (want, part) => want == part,
            })
}

/// `fnmatch` for one path component, as Apache's include does it: `*`,
/// `?` and `[...]` (with `!` or `^` to negate, and ranges), and no
/// wildcard matching a leading dot.
fn name_matches(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    glob(&pattern, &name)
}

fn glob(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| glob(rest, &name[skip..])),
        Some(('?', rest)) => !name.is_empty() && glob(rest, &name[1..]),
        Some(('[', rest)) => {
            let Some(close) = rest.iter().skip(1).position(|&c| c == ']').map(|at| at + 1) else {
                // No closing bracket: a literal `[`.
                return name.first() == Some(&'[') && glob(rest, &name[1..]);
            };
            let Some(&c) = name.first() else {
                return false;
            };
            let (negated, set) = match rest[..close].split_first() {
                Some(('!' | '^', set)) => (true, set),
                _ => (false, &rest[..close]),
            };
            let mut hit = false;
            let mut i = 0;
            while i < set.len() {
                if i + 2 < set.len() && set[i + 1] == '-' {
                    hit |= set[i] <= c && c <= set[i + 2];
                    i += 3;
                } else {
                    hit |= set[i] == c;
                    i += 1;
                }
            }
            hit != negated && glob(&rest[close + 1..], &name[1..])
        }
        Some((&literal, rest)) => name.first() == Some(&literal) && glob(rest, &name[1..]),
    }
}

/// Why Apache would not read `file`, a file this project writes under
/// `root` for it to load: `None` when it would, or when that cannot be
/// told. Every write of one is refused on this, and no status reads one as
/// up to date: the config test passes a file it never opens.
pub fn unloaded_file(root: &Path, file: &Path) -> Option<String> {
    let tree = Tree::find(root)?;
    if tree.includes(file)? {
        return None;
    }
    let dir = file.parent().unwrap_or(Path::new("/"));
    Some(format!(
        "Apache would never read {}: nothing {} includes names {}. Add \
         `IncludeOptional {}/*.conf` to {}, or point stop-bots at the directory \
         holding Apache's own config with `stop-bots set-web-server apache --root <dir>`.",
        file.display(),
        tree.main.display(),
        dir.display(),
        dir.display(),
        tree.main.display(),
    ))
}

/// Why `host` would not be answered over HTTP/2, if it would not: the
/// HTTP/1.x rule turns away every visitor of a host that only speaks
/// HTTP/1.1. Debian enables neither `mod_http2` nor `Protocols h2` by
/// default, and `mod_http2` serves nothing under the prefork MPM.
fn without_h2(tree: Option<&Tree>, host: &VirtualHost) -> Option<&'static str> {
    let Some(tree) = tree else {
        return Some(
            "stop-bots cannot find Apache's main config (apache2.conf, or conf/httpd.conf) \
             to check that it speaks HTTP/2",
        );
    };
    if !tree.loads_module("http2_module") {
        return Some("mod_http2 is not enabled (`a2enmod http2`)");
    }
    if tree.loads_module("mpm_prefork_module") {
        return Some("mod_http2 serves nothing under the prefork MPM");
    }
    let protocols = host
        .server_scope
        .iter()
        .rev()
        .find(|(name, _)| name == "protocols")
        .map(|(_, args)| args.clone())
        .or_else(|| tree.main_protocols());
    if !protocols.is_some_and(|p| p.iter().any(|p| p.eq_ignore_ascii_case("h2"))) {
        return Some("its `Protocols` do not include `h2` (`Protocols h2 http/1.1`)");
    }
    None
}

/// Whether a later `RewriteEngine Off` in `host` switches its rewrite
/// rules — the block among them — off. The last one in the host's own
/// scope decides, and the block's own `RewriteEngine On` is the first.
fn rewrite_switched_off(host: &VirtualHost) -> bool {
    host.server_scope
        .iter()
        .rev()
        .find(|(name, _)| name == "rewriteengine")
        .is_some_and(|(_, args)| args.first().is_some_and(|v| v.eq_ignore_ascii_case("off")))
}

/// Why `config` (as [`for_host`] narrowed it) cannot be written into `host`
/// as it asks, if it cannot. Both cases pass the config test.
fn refusal(config: &BlockConfig, host: &VirtualHost, tree: Option<&Tree>) -> Option<String> {
    let name = &host.names[0];
    if config.request_rules.contains(&RequestRule::Http1x) {
        if let Some(why) = without_h2(tree, host) {
            return Some(format!(
                "the HTTP/1.x rule is on for {name}, but {why}: Apache answers every \
                 visitor of it over HTTP/1.1, and the rule would turn every one of them \
                 away. Turn HTTP/2 on for it, or switch the rule off for the site."
            ));
        }
    }
    if block_text(config).is_some() && rewrite_switched_off(host) {
        return Some(format!(
            "the <VirtualHost> for {name} says `RewriteEngine Off`, which switches the \
             stop-bots block off while the config test still passes. Take that line out \
             (the site's own rewrite rules can stay), then apply again."
        ));
    }
    None
}

// ---- writing a block ----

/// `regex` as one double-quoted `RewriteCond` pattern.
///
/// `mod_rewrite` reads its own arguments: a quoted one runs to the next
/// quote of its kind, and nothing escapes it. So a `"` is written as PCRE's
/// `\x22`, which matches the same character without being one — an escaped
/// `\"` included, whose backslash goes with it. Every other character,
/// backslashes too, reaches PCRE as written.
///
/// Wrapped in `(?:...)` as well. A pattern `mod_rewrite` sees starting with
/// `!` is negated, and one that is `-f` or `>x` is a file test or a string
/// comparison, not a regex; a group in front is a regex whatever follows,
/// and matches the same strings.
fn rewrite_quoted(regex: &str) -> String {
    let mut out = String::from("\"(?:");
    let mut chars = regex.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                chars.next();
                out.push_str(r"\x22");
            }
            '\\' => {
                out.push('\\');
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '"' => out.push_str(r"\x22"),
            c => out.push(c),
        }
    }
    out.push_str(")\"");
    out
}

/// `text` as one double-quoted argument Apache's core reads
/// (`ap_getword_conf`): a backslash or a quote inside is escaped with a
/// backslash.
fn conf_quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', r"\\").replace('"', r#"\""#))
}

/// Whether `regex` can be written into an Apache config at all.
///
/// Apache substitutes `${NAME}` in every config line it reads, before any
/// module sees the line, so a pattern holding `${` would reach PCRE as
/// something else. And a control character would end the line. Neither is
/// a pattern worth guessing about.
fn survives_apache(regex: &str) -> bool {
    !regex.contains("${") && !regex.chars().any(char::is_control)
}

/// The patterns to write, of those `nginx` already finds usable as PCRE
/// (Apache's regex engine too), less any [`survives_apache`] refuses.
fn usable_patterns(patterns: &[String]) -> Vec<&str> {
    crate::nginx::usable_patterns(patterns)
        .into_iter()
        .filter(|p| survives_apache(p))
        .collect()
}

/// A request rule's `RewriteCond`, without the `RewriteCond` itself.
fn condition(rule: RequestRule) -> String {
    let matches = |variable: &str, regex: &str| format!("{variable} {}", rewrite_quoted(regex));
    match rule {
        // `HTTP/2.0` under mod_http2, and only ever 1.x without it.
        RequestRule::Http1x => matches("%{SERVER_PROTOCOL}", r"^HTTP/1\."),
        RequestRule::NoAccept => matches("%{HTTP:Accept}", "^$"),
        RequestRule::NoAcceptLanguage => matches("%{HTTP:Accept-Language}", "^$"),
        RequestRule::NoUserAgent => matches("%{HTTP_USER_AGENT}", "^$"),
        // `HTTP_HOST` keeps a port, which an anchored match ignores.
        RequestRule::IpLiteralHost => matches("%{HTTP_HOST}", r"^(\d+\.\d+\.\d+\.\d+|\[)"),
        RequestRule::OldTls => matches("%{SSL:SSL_PROTOCOL}", r"^TLSv1(\.[01])?$"),
        // Ignoring case, as the bot lists are matched here.
        RequestRule::ImpossibleUserAgent => format!(
            "{} [NC]",
            matches("%{HTTP_USER_AGENT}", &crate::impossible_ua::pattern())
        ),
    }
}

/// The status a blocked request is answered with. `444` and the tarpit
/// are NGINX's; here both are the `403` they stand in for. So is `418`:
/// `mod_rewrite` refuses to send a status Apache has no reason phrase for,
/// and a config the test rejects is no block at all.
fn status_code(response: crate::db::BlockResponse) -> u16 {
    match response.status_code() {
        444 | 418 => 403,
        code => code,
    }
}

/// Renders the sentinel block for `config`, or `None` when there is
/// nothing to block and nothing to serve — which is what makes
/// [`apply_block`] remove an existing block. Rate limiting is not
/// rendered: see the module docs.
fn block_text(config: &BlockConfig) -> Option<String> {
    let chunks = crate::nginx::chunk_patterns(
        &usable_patterns(&config.patterns),
        crate::nginx::MAX_PATTERN_CHUNK_LEN,
    );
    let blocks_something = !chunks.is_empty() || !config.request_rules.is_empty();
    if !blocks_something && !config.serve_robots_txt {
        return None;
    }
    let mut out = format!("    {BLOCK_BEGIN}\n    RewriteEngine On\n");
    if let Some(robots) = config.serve_robots_txt.then(robots_txt_path) {
        // A rewrite to the file, not an `Alias`: `mod_rewrite` answers the
        // translate-name phase before `mod_proxy` and `mod_alias` are asked,
        // so this serves the file on a site that hands everything else to
        // `ProxyPass /` — where an `Alias` lost, and the generated file was
        // never seen. `[L]`, so no rule after this one, the site's included,
        // routes it anywhere else.
        //
        // Written bare, because `mod_rewrite` reads its own arguments and
        // has no escape for a quote in one: a path with anything but the
        // characters below (which the stock one never has; only a test's
        // override could) serves nothing rather than something misread.
        let plain = |path: &Path| {
            path.to_str().is_some_and(|text| {
                text.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
            })
        };
        let dir = robots.parent().unwrap_or(Path::new("/"));
        if plain(&robots) {
            out.push_str(&format!(
                "    RewriteRule ^/robots\\.txt$ {} [L]\n    <Directory {}>\n        Require all granted\n    </Directory>\n",
                robots.display(),
                conf_quoted(&dir.display().to_string()),
            ));
        }
    }
    if blocks_something {
        let set = |value: u8| format!("    RewriteRule ^ - [E={BLOCK_VAR}:{value}]\n");
        for chunk in &chunks {
            out.push_str(&format!(
                "    RewriteCond %{{HTTP_USER_AGENT}} {} [NC]\n{}",
                rewrite_quoted(chunk),
                set(1)
            ));
        }
        for rule in &config.request_rules {
            out.push_str(&format!("    RewriteCond {}\n{}", condition(*rule), set(1)));
        }
        let (prefixes, exact) = effective_exempt_paths(config);
        for paths in crate::nginx::exemption_regexes(&prefixes, exact) {
            out.push_str(&format!(
                "    RewriteCond %{{REQUEST_URI}} {} [NC]\n{}",
                rewrite_quoted(&paths),
                set(0)
            ));
        }
        out.push_str(&agent_exemption_clears(&config.agent_exemptions));
        if config.trust.is_some() {
            out.push_str(&format!(
                "    RewriteCond %{{ENV:{TRUSTED_VAR}}} =1\n{}",
                set(0)
            ));
        }
        // Only on the request the client sent: see "The decision is made
        // once" in the module docs.
        out.push_str(&format!(
            "    RewriteCond %{{ENV:REDIRECT_STATUS}} ^$\n    RewriteCond %{{ENV:{BLOCK_VAR}}} =1\n    RewriteRule ^ - [R={},L,NS]\n",
            status_code(config.response)
        ));
    }
    out.push_str(&format!("    {BLOCK_END}\n"));
    Some(out)
}

/// The rules that clear the flag for agent exemptions: per user agent,
/// one rule whose conditions are the user agent and then its paths, the
/// paths joined by `[OR]` — which `mod_rewrite` reads as "the user agent,
/// and any of these paths", the conjunction NGINX needs a variable for.
fn agent_exemption_clears(exemptions: &[crate::db::AgentExemption]) -> String {
    let mut out = String::new();
    for group in exemptions.chunk_by(|a, b| a.user_agent == b.user_agent) {
        let user_agent = &group[0].user_agent;
        if !is_stored_as_valid(user_agent, crate::db::validate_exemption_user_agent) {
            continue;
        }
        let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
        let paths = crate::nginx::exemption_regexes(&paths, &[]);
        if paths.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "    RewriteCond %{{HTTP_USER_AGENT}} {} [NC]\n",
            rewrite_quoted(&crate::db::escape_regex_literal(user_agent))
        ));
        for (i, regex) in paths.iter().enumerate() {
            let flags = if i + 1 < paths.len() { "NC,OR" } else { "NC" };
            out.push_str(&format!(
                "    RewriteCond %{{REQUEST_URI}} {} [{flags}]\n",
                rewrite_quoted(regex)
            ));
        }
        out.push_str(&format!("    RewriteRule ^ - [E={BLOCK_VAR}:0]\n"));
    }
    out
}

/// Narrows a site's config to what is safe in *this* virtual host: the
/// TLS-only request rules are dropped in one that does not terminate TLS,
/// for the reason `nginx::for_block` gives.
fn for_host(config: &BlockConfig, host: &VirtualHost) -> BlockConfig {
    let mut config = config.clone();
    if !host.is_tls {
        config.request_rules.retain(|rule| !rule.needs_tls());
    }
    config
}

/// The byte range of the whole lines from the begin marker to the end
/// marker inside `host`, if a block is there. Only a line that is exactly
/// the marker counts.
fn locate_existing_block(content: &str, host: &VirtualHost) -> Option<(usize, usize)> {
    locate_marked(content, host, BLOCK_BEGIN, BLOCK_END)
}

/// The whole lines from a `begin` marker to the next `end` marker inside
/// `host`.
fn locate_marked(
    content: &str,
    host: &VirtualHost,
    begin: &str,
    end: &str,
) -> Option<(usize, usize)> {
    let inside: Vec<Line> = lines(content)
        .into_iter()
        .filter(|line| line.start >= host.open && line.start < host.close)
        .collect();
    let first = inside.iter().position(|l| l.text.trim() == begin)?;
    let last = inside[first..].iter().position(|l| l.text.trim() == end)?;
    Some((inside[first].start, inside[first + last].end))
}

/// Inserts, replaces or removes the block inside `host`. Idempotent.
/// Refuses a block that would pass the config test and not do what it
/// says ([`refusal`]).
fn apply_block(
    content: &str,
    host: &VirtualHost,
    config: &BlockConfig,
    tree: Option<&Tree>,
    config_path: &Path,
) -> Result<String> {
    let config = for_host(config, host);
    if let Some(why) = refusal(&config, host, tree) {
        anyhow::bail!("refusing to write {}: {why}", config_path.display());
    }
    let new_block = block_text(&config);
    let (start, end) = locate_existing_block(content, host).unwrap_or((host.open, host.open));
    let mut out = String::with_capacity(content.len() + new_block.as_ref().map_or(0, String::len));
    out.push_str(&content[..start]);
    if let Some(block) = &new_block {
        out.push_str(block);
    }
    out.push_str(&content[end..]);
    Ok(out)
}

/// Host `i` of `hosts`, which must still number `expected` — the guard
/// `nginx::nth_block` is, for the same reason.
fn nth_host<'a>(
    hosts: &'a [VirtualHost],
    i: usize,
    expected: usize,
    config_path: &Path,
) -> Result<&'a VirtualHost> {
    if hosts.len() != expected {
        anyhow::bail!(
            "refusing to write {}: editing it changed how many <VirtualHost> sections it has",
            config_path.display()
        );
    }
    Ok(&hosts[i])
}

/// What applying `site_configs` (and `default_config` for every host
/// they do not name) to every `<VirtualHost>` in `content` makes of it.
/// `root` is Apache's config root, which says what the file alone cannot
/// (see [`Tree`]).
pub fn blocks_for_file(
    content: &str,
    config_path: &Path,
    root: &Path,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
) -> Result<String> {
    let tree = Tree::find(root);
    let mut content = content.to_string();
    let count = virtual_hosts(&content).len();
    for i in 0..count {
        let hosts = virtual_hosts(&content);
        let host = nth_host(&hosts, i, count, config_path)?;
        let config = site_configs
            .iter()
            .find(|(name, _)| *name == host.names[0])
            .map_or(default_config, |(_, config)| config);
        content = apply_block(&content, host, config, tree.as_ref(), config_path)?;
    }
    Ok(content)
}

/// What applying `config` to only `server_name`'s hosts in `content`
/// makes of it.
pub fn block_for_site(
    content: &str,
    config_path: &Path,
    root: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<String> {
    let tree = Tree::find(root);
    let mut content = content.to_string();
    let count = virtual_hosts(&content).len();
    for i in 0..count {
        let hosts = virtual_hosts(&content);
        let host = nth_host(&hosts, i, count, config_path)?;
        if host.names[0] == server_name {
            content = apply_block(&content, host, config, tree.as_ref(), config_path)?;
        }
    }
    Ok(content)
}

/// The trust file's body for `trust`: one `SetEnvIf` per entry, read in
/// every virtual host because the main server's are merged into each.
///
/// `SetEnvIfExpr` with `-R` for addresses, because it is the one CIDR-aware
/// match `mod_setenvif` has. User agents match as an escaped,
/// case-insensitive substring, as they do everywhere else.
///
/// Server-wide, which is also what makes trust survive an internal
/// redirect: Apache runs the server's `SetEnvIf`s again for the request it
/// redirects to, where a variable set on the first round has been renamed
/// `REDIRECT_stop_bots_trusted`.
pub fn trusted_conf_body(trust: &Trust) -> String {
    let mut out = managed_header();
    for address in &trust.addresses {
        out.push_str(&format!(
            "SetEnvIfExpr \"-R '{address}'\" {TRUSTED_VAR}=1\n"
        ));
    }
    for user_agent in &trust.user_agents {
        out.push_str(&format!(
            "SetEnvIfNoCase User-Agent {} {TRUSTED_VAR}=1\n",
            conf_quoted(&crate::db::escape_regex_literal(user_agent))
        ));
    }
    out
}

/// Whether the trust file on disk is the one `config` expects, where
/// Apache reads it; see `nginx::trust_file_is_current`, which this is for
/// Apache.
fn trust_file_is_current(config: &BlockConfig, root: &Path) -> bool {
    match (&config.trust, block_text(config)) {
        (Some(trust), Some(_)) => {
            let path = trusted_conf_path(&conf_enabled_dir(root));
            unloaded_file(root, &path).is_none()
                && fs::read_to_string(&path).is_ok_and(|text| {
                    crate::generated::same_but_for_the_version(&text, &trusted_conf_body(trust))
                })
        }
        _ => true,
    }
}

/// Whether what is written for `server_name` in `config_path` is what
/// `config` renders to — and does what it says: a block an apply would
/// refuse to write ([`refusal`]) is never up to date, nor one that leans on
/// a trust file Apache does not read.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
    root: &Path,
) -> SiteApplyStatus {
    let Ok(content) = fs::read_to_string(config_path) else {
        return SiteApplyStatus::NotFound;
    };
    let hosts = virtual_hosts(&content);
    let matching: Vec<&VirtualHost> = hosts.iter().filter(|h| h.names[0] == server_name).collect();
    if matching.is_empty() {
        return SiteApplyStatus::NotFound;
    }
    let tree = Tree::find(root);
    let current = matching.iter().all(|host| {
        let config = for_host(config, host);
        refusal(&config, host, tree.as_ref()).is_none()
            && locate_existing_block(&content, host)
                .map(|(start, end)| content[start..end].to_string())
                == block_text(&config)
    });
    if current && trust_file_is_current(config, root) {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

/// `content` with every block this project injected taken out: the exact
/// inverse of an insertion, which puts the block's lines right after the
/// `<VirtualHost>` line, or the console section an earlier release wrote
/// right before `</VirtualHost>`, and adds nothing else.
pub fn without_injected_blocks(content: &str) -> String {
    let mut content = content.to_string();
    loop {
        // One whole section at a time, the first in the file first: taking
        // it out moves only what is after it, and the rest are found again
        // on the next round.
        let found = virtual_hosts(&content).iter().find_map(|host| {
            [
                locate_existing_block(&content, host),
                locate_marked(&content, host, CONSOLE_BEGIN, CONSOLE_END),
            ]
            .into_iter()
            .flatten()
            .min()
        });
        let Some((start, end)) = found else {
            return content;
        };
        content.replace_range(start..end, "");
    }
}

/// The generated files the current settings call for: the trust file and
/// `robots.txt`.
///
/// Refuses a trust file in a directory Apache does not read
/// ([`unloaded_file`]): every apply and every preview starts here, so
/// nothing is written that leaves each trusted client blocked while the
/// config test passes.
pub fn planned_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();
    if db.get_serve_robots_txt()? {
        files.push((robots_txt_path(), robots_txt_body(db)?));
    }
    if let Some(trust) = Trust::of(db)? {
        let path = trusted_conf_path(&conf_enabled_dir(root));
        if let Some(why) = unloaded_file(root, &path) {
            anyhow::bail!("refusing to write the trusted clients' file: {why}");
        }
        files.push((path, trusted_conf_body(&trust)));
    }
    Ok(files)
}

/// Where each generated file the current settings do not call for would
/// be.
pub fn fallback_unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if !db.get_serve_robots_txt()? {
        paths.push(robots_txt_path());
    }
    if Trust::of(db)?.is_none() {
        paths.push(trusted_conf_path(&conf_enabled_dir(root)));
    }
    Ok(paths)
}

/// The directories a recorded generated file may be removed from.
pub fn managed_directories(root: &Path) -> Vec<PathBuf> {
    [conf_enabled_dir(root), managed_dir()]
        .iter()
        .filter_map(|dir| fs::canonicalize(dir).ok())
        .collect()
}

/// Every name on the host that declares `server_name`, or just that name.
pub fn server_names_for(config_path: &Path, server_name: &str) -> Vec<String> {
    fs::read_to_string(config_path)
        .ok()
        .and_then(|content| {
            virtual_hosts(&content)
                .into_iter()
                .find(|host| host.names.iter().any(|name| name == server_name))
        })
        .map_or_else(|| vec![server_name.to_string()], |host| host.names)
}

/// The application that answers for `server_name` in `config_path`, as
/// [`crate::services::recognise`] reads it, from every `<VirtualHost>`
/// there that declares one of the site's names — as `nginx::site_service`
/// does from `server` blocks, and for the same reasons.
///
/// `recognise` speaks NGINX's directive names, so Apache's are given the
/// name of the NGINX directive that does the same: `ProxyPass` hands
/// requests on as `proxy_pass` does, `DocumentRoot` is `root`, and `Alias`
/// is `alias`. Anything else keeps its own name, which still counts for
/// the one thing `recognise` reads from any directive: Nextcloud's
/// `/remote.php/dav` in a `Redirect` or a `RewriteRule`.
///
/// This project's own block is taken out first: it quotes upstream
/// user-agent patterns, which could name anything.
pub fn site_service(config_path: &Path, server_name: &str) -> Option<crate::services::Service> {
    crate::services::recognise(&site_directives(config_path, server_name)?)
}

/// Every directive of every `<VirtualHost>` in `config_path` that
/// declares one of `server_name`'s names, under the name of the NGINX
/// directive that does the same (see [`site_service`]): what
/// [`crate::webapps`] reads a site from, as `nginx::site_directives`.
pub fn site_directives(
    config_path: &Path,
    server_name: &str,
) -> Option<Vec<(String, Vec<String>)>> {
    let content = without_injected_blocks(&fs::read_to_string(config_path).ok()?);
    let hosts = virtual_hosts(&content);
    let names = hosts
        .iter()
        .find(|host| host.names.iter().any(|name| name == server_name))?
        .names
        .clone();
    Some(
        hosts
            .iter()
            .filter(|host| host.names.iter().any(|name| names.contains(name)))
            .flat_map(|host| host.directives.iter())
            .map(|(name, arguments)| (nginx_equivalent(name).to_string(), arguments.clone()))
            .collect(),
    )
}

/// The NGINX directive that does what Apache's `name` (lowercased) does,
/// as far as [`site_service`] needs: or `name` itself.
fn nginx_equivalent(name: &str) -> &str {
    match name {
        "proxypass" | "proxypassmatch" => "proxy_pass",
        "documentroot" => "root",
        "alias" | "aliasmatch" => "alias",
        name => name,
    }
}

/// The stock layout an Apache root belongs to, which decides the defaults
/// an operator would otherwise have to type: the config test, the reload
/// and the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `/etc/apache2`, with `apache2ctl`, the `apache2` unit and
    /// `/var/log/apache2`. Also the answer for a root with no main config
    /// to read, as it has always been.
    Debian,
    /// `/etc/httpd`, with its main config in `conf/httpd.conf`,
    /// `apachectl`, the `httpd` unit and `/var/log/httpd`.
    Rhel,
}

/// Which stock layout `root` is part of, from where its main config is
/// ([`main_config`]): RHEL keeps it in `conf/httpd.conf`, and nothing else
/// does. A source build's or the upstream image's top-level `httpd.conf`
/// is neither layout, and keeps Debian's defaults as before; those hosts
/// name their own commands anyway.
pub fn layout(root: &Path) -> Layout {
    match main_config(root) {
        Some((_, main)) if main.ends_with("conf/httpd.conf") => Layout::Rhel,
        _ => Layout::Debian,
    }
}

impl Layout {
    /// The config test this layout ships.
    pub fn test(self) -> &'static str {
        match self {
            Layout::Debian => "apache2ctl configtest",
            Layout::Rhel => "apachectl configtest",
        }
    }

    /// The reload, through this layout's unit.
    pub fn reload(self) -> &'static str {
        match self {
            Layout::Debian => "systemctl reload apache2",
            Layout::Rhel => "systemctl reload httpd",
        }
    }

    /// Where this layout's stock config writes the access log.
    pub fn access_log(self) -> &'static str {
        match self {
            Layout::Debian => "/var/log/apache2/access.log",
            Layout::Rhel => "/var/log/httpd/access_log",
        }
    }
}

/// What fixes a config test that failed because a module this project
/// writes for is not loaded: `mod_rewrite`, which the blocks are written
/// in. Debian ships it switched off.
pub fn missing_module_hint(err: &anyhow::Error) -> Option<&'static str> {
    let text = format!("{err:#}");
    let invalid = |command: &str| text.contains(&format!("Invalid command '{command}'"));
    if invalid("RewriteEngine") || invalid("RewriteCond") {
        return Some(
            "stop-bots blocks requests with mod_rewrite, which is not enabled: \
             run `a2enmod rewrite`, then apply again.",
        );
    }
    None
}

// ---- what earlier releases wrote for the web console ----

/// Where the web console's Web Access put its own site, in subdomain mode,
/// in a release that had one. Nothing writes it now; `uninstall` takes it
/// out.
///
/// **Named to sort last.** For a name no site declares — every request
/// that asks for a bare address — Apache answers with the first
/// `<VirtualHost>` it read for that address and port, and Debian reads
/// `sites-enabled` in name order. The console was never to be that site.
///
/// In `conf.d` on a root that has that and no `sites-enabled` — RHEL's,
/// whose `httpd.conf` reads its sites from there, also in name order — for
/// the reason [`conf_enabled_dir`] gives.
pub fn console_site_path(root: &Path) -> PathBuf {
    let sites = root.join("sites-enabled");
    let rhel = root.join("conf.d");
    let dir = if !sites.is_dir() && rhel.is_dir() {
        rhel
    } else {
        sites
    };
    dir.join("zz-stop-bots-console.conf")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BlockResponse;
    use crate::services::Service;

    /// A root that is no Apache tree and has none above it: what a test
    /// about one file alone renders against.
    const NO_TREE: &str = "/nonexistent/stop-bots/apache";

    const SITE: &str = "\
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example
</VirtualHost>
";

    const TWO_HOSTS: &str = "\
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    <Directory /var/www/example>
        AllowOverride All
    </Directory>
</VirtualHost>
</IfModule>

<VirtualHost *:80>
    ServerName other.example
</VirtualHost>
";

    fn cfg(patterns: &[&str]) -> BlockConfig {
        BlockConfig::new(
            patterns.iter().map(|p| p.to_string()).collect(),
            BlockResponse::Forbidden,
        )
    }

    // ---- what releases with the web console wrote ----
    //
    // Frozen copies of the writers that put the console's section into a
    // site, so the tests can make the bytes those hosts have and check that
    // `uninstall` takes them back out.

    fn console_location(prefix: &str, upstream: &std::net::SocketAddr) -> String {
        format!(
            "    {CONSOLE_BEGIN}\n    <Location {}>\n        ProxyPass {}\n        \
             ProxyPreserveHost On\n    </Location>\n    {CONSOLE_END}\n",
            conf_quoted(prefix),
            conf_quoted(&format!("http://{upstream}{prefix}")),
        )
    }

    fn with_console_location(
        content: &str,
        server_name: &str,
        prefix: &str,
        upstream: &std::net::SocketAddr,
    ) -> Option<String> {
        let pick = |content: &str| {
            virtual_hosts(content)
                .into_iter()
                .filter(|h| h.names.iter().any(|n| n == server_name))
                .max_by_key(|h| h.is_tls)
        };
        let host = pick(content)?;
        let mut content = content.to_string();
        if let Some((start, end)) = locate_marked(&content, &host, CONSOLE_BEGIN, CONSOLE_END) {
            content.replace_range(start..end, "");
        }
        let host = pick(&content)?;
        content.insert_str(host.close, &console_location(prefix, upstream));
        Some(content)
    }

    #[test]
    fn finds_every_virtual_host_with_its_names_and_tls() {
        let hosts = virtual_hosts(TWO_HOSTS);
        let seen: Vec<(Vec<String>, bool)> =
            hosts.iter().map(|h| (h.names.clone(), h.is_tls)).collect();
        assert_eq!(
            seen,
            vec![
                (vec!["example.com".to_string()], false),
                (vec!["example.com".to_string()], true),
                (vec!["other.example".to_string()], false),
            ]
        );
        assert_eq!(
            virtual_hosts(SITE)[0].names,
            vec!["example.com", "www.example.com"]
        );
    }

    #[test]
    fn each_host_listens_where_its_section_says_with_its_tls() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sites.conf"), TWO_HOSTS).unwrap();

        let seen: Vec<(String, Vec<(u16, bool)>)> = site_listens(dir.path())
            .unwrap()
            .into_iter()
            .map(|site| {
                let ports = site.listens.iter().map(|l| (l.port, l.tls)).collect();
                (site.server_name, ports)
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("example.com".to_string(), vec![(80, false)]),
                ("example.com".to_string(), vec![(443, true)]),
                ("other.example".to_string(), vec![(80, false)]),
            ]
        );
    }

    #[test]
    fn a_host_without_a_server_name_is_the_catch_all() {
        let hosts =
            virtual_hosts("<VirtualHost *:80>\n    DocumentRoot /var/www/html\n</VirtualHost>\n");
        assert_eq!(hosts[0].names, vec!["_"]);
    }

    #[test]
    fn a_server_name_loses_its_scheme_and_port() {
        for (written, stored) in [
            ("example.com", "example.com"),
            ("example.com:443", "example.com"),
            ("https://example.com:8443", "example.com"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            assert_eq!(bare_name(written), stored, "from {written:?}");
        }
    }

    #[test]
    fn commented_sections_are_not_structure() {
        let content =
            "# <VirtualHost *:80>\n#   ServerName ghost\n# </VirtualHost>\n".to_string() + SITE;
        let hosts = virtual_hosts(&content);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].names[0], "example.com");
    }

    #[test]
    fn a_continued_line_is_one_directive() {
        let content =
            "<VirtualHost *:80>\n    ServerName \\\n        joined.example\n</VirtualHost>\n";
        assert_eq!(virtual_hosts(content)[0].names[0], "joined.example");
    }

    #[test]
    fn a_block_matches_the_golden() {
        let config = BlockConfig {
            exempt_paths: vec!["/api/".to_string()],
            ..cfg(&["BadBot", "Evil\"Quote"])
        };
        crate::golden::assert_golden("apache-block-simple.conf", &block_text(&config).unwrap());
    }

    #[test]
    fn a_full_block_matches_the_golden() {
        let config = BlockConfig {
            serve_robots_txt: true,
            request_rules: vec![RequestRule::NoAccept, RequestRule::IpLiteralHost],
            agent_exemptions: vec![crate::db::AgentExemption {
                path: "/remote.php/dav/".to_string(),
                user_agent: "okhttp".to_string(),
            }],
            trust: Trust::from_lists(&["203.0.113.7".to_string()], &[]),
            response: BlockResponse::Gone,
            ..cfg(&["BadBot"])
        };
        // The robots.txt alias names the managed directory, which a test
        // environment may move; pin the stock one.
        let text = block_text(&config)
            .unwrap()
            .replace(&managed_dir().display().to_string(), MANAGED_DIR);
        crate::golden::assert_golden("apache-block-full.conf", &text);
    }

    #[test]
    fn the_trust_file_matches_the_golden() {
        let trust = Trust::from_lists(
            &["203.0.113.7".to_string(), "2001:db8::/48".to_string()],
            &["UptimeRobot".to_string(), "Pingdom.com_bot".to_string()],
        )
        .unwrap();
        let body = trusted_conf_body(&trust);
        let ours = format!("# {}.", crate::generated::generated_by());
        crate::golden::assert_golden(
            "apache-trusted.conf",
            &body.replacen(&ours, "# Generated by stop-bots.", 1),
        );
    }

    #[test]
    fn applying_inserts_after_the_opening_line_and_is_idempotent() {
        let once = blocks_for_file(
            SITE,
            Path::new("site.conf"),
            Path::new(NO_TREE),
            &[],
            &cfg(&["BadBot"]),
        )
        .unwrap();
        let twice = blocks_for_file(
            &once,
            Path::new("site.conf"),
            Path::new(NO_TREE),
            &[],
            &cfg(&["BadBot"]),
        )
        .unwrap();
        assert_eq!(once, twice);
        assert!(
            once.starts_with(&format!("<VirtualHost *:80>\n    {BLOCK_BEGIN}\n")),
            "applied:\n{once}"
        );
    }

    #[test]
    fn nothing_to_block_takes_the_block_out_byte_for_byte() {
        let applied = blocks_for_file(
            SITE,
            Path::new("s"),
            Path::new(NO_TREE),
            &[],
            &cfg(&["BadBot"]),
        )
        .unwrap();
        let removed =
            blocks_for_file(&applied, Path::new("s"), Path::new(NO_TREE), &[], &cfg(&[])).unwrap();
        assert_eq!(removed, SITE);
        assert_eq!(without_injected_blocks(&applied), SITE);
    }

    #[test]
    fn each_site_gets_its_own_config_and_tls_rules_only_where_tls_is() {
        let strict = BlockConfig {
            request_rules: vec![RequestRule::OldTls],
            ..cfg(&["BadBot"])
        };
        let applied = blocks_for_file(
            TWO_HOSTS,
            Path::new("s"),
            Path::new(NO_TREE),
            &[("example.com".to_string(), strict)],
            &cfg(&[]),
        )
        .unwrap();
        let hosts = virtual_hosts(&applied);
        let block = |i: usize| {
            locate_existing_block(&applied, &hosts[i]).map(|(s, e)| applied[s..e].to_string())
        };
        assert!(!block(0).unwrap().contains("SSL_PROTOCOL"), "{applied}");
        assert!(block(1).unwrap().contains("SSL_PROTOCOL"), "{applied}");
        assert_eq!(block(2), None, "{applied}");
    }

    #[test]
    fn applying_to_one_site_leaves_the_others_alone() {
        let applied = block_for_site(
            TWO_HOSTS,
            Path::new("s"),
            Path::new(NO_TREE),
            "other.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();
        let hosts = virtual_hosts(&applied);
        assert!(locate_existing_block(&applied, &hosts[0]).is_none());
        assert!(locate_existing_block(&applied, &hosts[2]).is_some());
    }

    #[test]
    fn a_quote_in_a_pattern_cannot_end_the_argument() {
        for (regex, written) in [
            (r#"a"b"#, r#""(?:a\x22b)""#),
            (r#"a\"b"#, r#""(?:a\x22b)""#),
            (r"a\\b", r#""(?:a\\b)""#),
            (r"-f", r#""(?:-f)""#),
            (r"!x", r#""(?:!x)""#),
        ] {
            assert_eq!(rewrite_quoted(regex), written, "for {regex:?}");
        }
    }

    #[test]
    fn a_pattern_apache_would_substitute_into_is_never_written() {
        let text = block_text(&cfg(&["Good", "x${jndi}"])).unwrap();
        assert!(!text.contains("${"), "block was:\n{text}");
        assert!(text.contains("Good"), "block was:\n{text}");
    }

    #[test]
    fn what_apache_cannot_send_answers_403() {
        for response in [
            BlockResponse::Close,
            BlockResponse::Tarpit,
            BlockResponse::Teapot,
        ] {
            let text = block_text(&BlockConfig {
                response,
                ..cfg(&["BadBot"])
            })
            .unwrap();
            assert!(text.contains("[R=403,L,NS]"), "{response:?} gave:\n{text}");
        }
    }

    #[test]
    fn rate_limiting_alone_writes_no_block() {
        let config = BlockConfig {
            rate_limit_burst: Some(20),
            ..cfg(&[])
        };
        assert_eq!(block_text(&config), None);
    }

    #[test]
    fn a_site_reads_up_to_date_only_once_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, SITE).unwrap();
        let config = cfg(&["BadBot"]);
        assert_eq!(
            site_apply_status(&path, "example.com", &config, dir.path()),
            SiteApplyStatus::Stale
        );
        fs::write(
            &path,
            blocks_for_file(SITE, &path, Path::new(NO_TREE), &[], &config).unwrap(),
        )
        .unwrap();
        assert_eq!(
            site_apply_status(&path, "example.com", &config, dir.path()),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "nobody.example", &config, dir.path()),
            SiteApplyStatus::NotFound
        );
    }

    #[test]
    fn discovery_skips_links_and_finds_each_host() {
        let dir = tempfile::tempdir().unwrap();
        let available = dir.path().join("sites-available");
        let enabled = dir.path().join("sites-enabled");
        fs::create_dir_all(&available).unwrap();
        fs::create_dir_all(&enabled).unwrap();
        fs::write(available.join("two.conf"), TWO_HOSTS).unwrap();
        std::os::unix::fs::symlink(available.join("two.conf"), enabled.join("two.conf")).unwrap();
        let sites = discover_sites(dir.path()).unwrap();
        let names: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
        assert_eq!(names, vec!["example.com", "example.com", "other.example"]);
        assert!(sites.iter().all(|s| s.config_path.starts_with(&available)));
        assert!(discover_sites(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn recognises_the_application_behind_a_site() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let cases = [
            (
                "ProxyPass / http://127.0.0.1:8096/",
                Some(Service::Jellyfin),
            ),
            (
                "ProxyPassMatch ^/(.*)$ http://immich_server:2283/$1",
                Some(Service::Immich),
            ),
            ("DocumentRoot /var/www/nextcloud", Some(Service::Nextcloud)),
            (
                "Alias /cloud \"/var/www/nextcloud/\"",
                Some(Service::Nextcloud),
            ),
            (
                "Redirect 301 /.well-known/carddav /remote.php/dav",
                Some(Service::Nextcloud),
            ),
            ("DocumentRoot /var/www/blog", None),
            // A name outside anything that hands requests on.
            ("ServerAdmin jellyfin@example.com", None),
        ];
        for (directive, expected) in cases {
            fs::write(
                &path,
                format!("<VirtualHost *:443>\n    ServerName cloud.example\n    {directive}\n</VirtualHost>\n"),
            )
            .unwrap();
            assert_eq!(
                site_service(&path, "cloud.example"),
                expected,
                "{directive}"
            );
        }
    }

    /// The HTTPS host passes requests on; the port-80 one only redirects.
    /// Both are the site.
    #[test]
    fn every_host_of_a_site_counts_and_our_own_block_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let content = "<VirtualHost *:80>\n    ServerName cloud.example\n    Redirect / https://cloud.example/\n</VirtualHost>\n<VirtualHost *:443>\n    ServerName cloud.example\n    ProxyPass / http://navidrome:4533/\n</VirtualHost>\n";
        fs::write(&path, content).unwrap();
        assert_eq!(
            site_service(&path, "cloud.example"),
            Some(Service::Navidrome)
        );

        // A blocked bot whose pattern names an application says nothing.
        let plain = "<VirtualHost *:80>\n    ServerName blog.example\n</VirtualHost>\n";
        let blocked = blocks_for_file(
            plain,
            &path,
            Path::new(NO_TREE),
            &[],
            &cfg(&["nextcloud-crawler"]),
        )
        .unwrap();
        assert!(blocked.contains("nextcloud-crawler"), "applied:\n{blocked}");
        fs::write(&path, blocked).unwrap();
        assert_eq!(site_service(&path, "blog.example"), None);
    }

    // ---- what uninstall takes out of a host that had Web Access ----

    fn upstream() -> std::net::SocketAddr {
        "127.0.0.1:8787".parse().unwrap()
    }

    #[test]
    fn uninstalling_takes_the_console_out_too() {
        let mounted =
            with_console_location(SITE, "example.com", "/stop-bots/", &upstream()).unwrap();
        let applied = blocks_for_file(
            &mounted,
            Path::new("s"),
            Path::new(NO_TREE),
            &[],
            &cfg(&["BadBot"]),
        )
        .unwrap();
        assert_eq!(without_injected_blocks(&applied), SITE);
    }

    #[test]
    fn a_missing_module_names_the_command_that_enables_it() {
        let said = "Invalid command 'RewriteEngine', perhaps misspelled";
        let hint = missing_module_hint(&anyhow::anyhow!("{said}")).unwrap();
        assert!(hint.contains("a2enmod rewrite"), "{said} gave: {hint}");
        assert_eq!(missing_module_hint(&anyhow::anyhow!("Syntax error")), None);
    }

    // ---- what the rest of the config says ----

    /// One file of a test's config tree: its path under the root, and its
    /// text.
    type ConfigFile = (&'static str, &'static str);

    /// An Apache config tree in a temporary directory: `files`, each at its
    /// path under the root, the main file among them.
    fn tree(files: &[ConfigFile]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, text) in files {
            let path = dir.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        dir
    }

    /// Debian's `apache2.conf`, as far as what it includes.
    const DEBIAN_MAIN: (&str, &str) = (
        "apache2.conf",
        "IncludeOptional mods-enabled/*.load\n\
         IncludeOptional mods-enabled/*.conf\n\
         Include ports.conf\n\
         IncludeOptional conf-enabled/*.conf\n\
         IncludeOptional sites-enabled/*.conf\n",
    );

    /// RHEL's `conf/httpd.conf`, as far as what it includes and where it
    /// logs. Its `ServerRoot` is the host's, not the test's, which is what
    /// a config on a bind mount looks like too.
    const RHEL_MAIN: (&str, &str) = (
        "conf/httpd.conf",
        "ServerRoot \"/etc/httpd\"\n\
         Include conf.modules.d/*.conf\n\
         ErrorLog \"logs/error_log\"\n\
         CustomLog \"logs/access_log\" combined\n\
         IncludeOptional conf.d/*.conf\n",
    );

    /// `LoadModule http2_module`, as Debian's `a2enmod http2` links it.
    const HTTP2_LOAD: (&str, &str) = (
        "mods-enabled/http2.load",
        "LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so\n",
    );

    /// The `Protocols` Debian's `http2.conf` sets for the whole server.
    const HTTP2_CONF: (&str, &str) = (
        "mods-enabled/http2.conf",
        "<IfModule !mpm_prefork>\n    Protocols h2 h2c http/1.1\n</IfModule>\n",
    );

    const PREFORK_LOAD: (&str, &str) = (
        "mods-enabled/mpm_prefork.load",
        "LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so\n",
    );

    const TLS_SITE: &str = "\
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
</VirtualHost>
";

    #[test]
    fn a_rhel_root_keeps_its_files_in_conf_d_which_it_reads() {
        let root = tree(&[RHEL_MAIN, ("conf.d/welcome.conf", "")]);
        let conf_d = root.path().join("conf.d");
        assert_eq!(conf_enabled_dir(root.path()), conf_d);
        assert_eq!(
            console_site_path(root.path()),
            conf_d.join("zz-stop-bots-console.conf")
        );
        for file in [
            trusted_conf_path(&conf_enabled_dir(root.path())),
            console_site_path(root.path()),
        ] {
            assert_eq!(
                unloaded_file(root.path(), &file),
                None,
                "{}",
                file.display()
            );
        }
    }

    #[test]
    fn debian_reads_conf_enabled_and_sites_enabled() {
        let root = tree(&[
            DEBIAN_MAIN,
            ("conf-enabled/x.conf", ""),
            ("sites-enabled/x.conf", ""),
        ]);
        for file in [
            trusted_conf_path(&conf_enabled_dir(root.path())),
            console_site_path(root.path()),
        ] {
            assert_eq!(
                unloaded_file(root.path(), &file),
                None,
                "{}",
                file.display()
            );
        }
    }

    /// RHEL with a `conf-enabled` someone made by hand: its `httpd.conf`
    /// reads none, and the config test would pass a trust file there.
    #[test]
    fn a_file_where_apache_never_reads_says_what_to_include() {
        let root = tree(&[RHEL_MAIN, ("conf-enabled/.keep", "")]);
        let file = trusted_conf_path(&conf_enabled_dir(root.path()));
        let why = unloaded_file(root.path(), &file).expect("conf-enabled is not read");
        assert!(
            why.contains("IncludeOptional") && why.contains("conf-enabled"),
            "said: {why}"
        );
    }

    #[test]
    fn planning_a_trust_file_apache_never_reads_is_refused() {
        let root = tree(&[RHEL_MAIN, ("conf-enabled/.keep", "")]);
        let db = crate::db::Db::open_in_memory().unwrap();
        db.trust_user_agent("UptimeRobot").unwrap();
        let err = planned_managed_files(&db, root.path()).unwrap_err();
        assert!(format!("{err:#}").contains("never read"), "said: {err:#}");
    }

    #[test]
    fn a_site_whose_trust_file_apache_never_reads_is_never_up_to_date() {
        let root = tree(&[RHEL_MAIN, ("conf-enabled/.keep", "")]);
        let path = root.path().join("conf.d/site.conf");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let config = BlockConfig {
            trust: Trust::from_lists(&[], &["UptimeRobot".to_string()]),
            ..cfg(&["BadBot"])
        };
        let applied = blocks_for_file(SITE, &path, root.path(), &[], &config).unwrap();
        fs::write(&path, applied).unwrap();
        fs::write(
            trusted_conf_path(&conf_enabled_dir(root.path())),
            trusted_conf_body(config.trust.as_ref().unwrap()),
        )
        .unwrap();
        assert_eq!(
            site_apply_status(&path, "example.com", &config, root.path()),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn a_root_inside_the_tree_still_finds_its_main_file() {
        let root = tree(&[DEBIAN_MAIN, ("sites-available/x.conf", "")]);
        let found = Tree::find(&root.path().join("sites-available")).expect("found from below");
        assert_eq!(found.main, root.path().join("apache2.conf"));
    }

    #[test]
    fn includes_follow_wildcards_and_nested_files_but_not_dot_files() {
        let root = tree(&[
            ("httpd.conf", "Include extra/*.conf\n"),
            ("extra/vhosts.conf", "IncludeOptional sites/[a-m]*.conf\n"),
        ]);
        let found = Tree::find(root.path()).unwrap();
        for (file, read) in [
            ("sites/blog.conf", Some(true)),
            ("sites/zz.conf", Some(false)),
            ("sites/.blog.conf", Some(false)),
            ("elsewhere/blog.conf", Some(false)),
        ] {
            assert_eq!(found.includes(&root.path().join(file)), read, "{file}");
        }
    }

    #[test]
    fn an_include_through_a_variable_leaves_inclusion_unknown() {
        let root = tree(&[("apache2.conf", "IncludeOptional ${CONF}/*.conf\n")]);
        let file = root.path().join("conf-enabled/stop-bots-trusted.conf");
        assert_eq!(unloaded_file(root.path(), &file), None);
    }

    #[test]
    fn a_root_with_no_main_file_refuses_nothing_on_what_it_includes() {
        let file = Path::new(NO_TREE).join("conf-enabled/stop-bots-trusted.conf");
        assert_eq!(unloaded_file(Path::new(NO_TREE), &file), None);
    }

    #[test]
    fn names_match_as_apache_include_matches_them() {
        for (pattern, name, matched) in [
            ("*.conf", "site.conf", true),
            ("*.conf", "site.load", false),
            ("*.conf", ".site.conf", false),
            (".*.conf", ".site.conf", true),
            ("site?.conf", "site1.conf", true),
            ("[a-c]*", "blog", true),
            ("[!a-c]*", "blog", false),
            ("[^a-c]*", "zone", true),
            ("[x", "[x", true),
        ] {
            assert_eq!(
                name_matches(pattern, name),
                matched,
                "{pattern} against {name}"
            );
        }
    }

    #[test]
    fn only_rhels_own_tree_gets_rhels_defaults() {
        for (what, files, expected) in [
            ("RHEL's conf/httpd.conf", &[RHEL_MAIN][..], Layout::Rhel),
            ("Debian's apache2.conf", &[DEBIAN_MAIN], Layout::Debian),
            (
                "a source build's httpd.conf",
                &[("httpd.conf", "")],
                Layout::Debian,
            ),
            (
                "no main config at all",
                &[("sites/x.conf", "")],
                Layout::Debian,
            ),
        ] {
            let root = tree(files);
            assert_eq!(layout(root.path()), expected, "{what}");
        }
        let root = tree(&[RHEL_MAIN, ("conf.d/site.conf", "")]);
        assert_eq!(
            layout(&root.path().join("conf.d")),
            Layout::Rhel,
            "a root inside RHEL's tree, where its sites are"
        );
    }

    #[test]
    fn the_block_acts_only_on_the_request_the_client_sent() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[lines.len() - 4..lines.len() - 1],
            [
                "    RewriteCond %{ENV:REDIRECT_STATUS} ^$",
                "    RewriteCond %{ENV:stop_bots_block} =1",
                "    RewriteRule ^ - [R=403,L,NS]",
            ],
            "block was:\n{text}"
        );
    }

    /// An `Alias` loses to a site's `ProxyPass /`; a rewrite answers first.
    #[test]
    fn robots_txt_is_rewritten_to_the_file_ahead_of_every_other_rule() {
        let text = block_text(&BlockConfig {
            serve_robots_txt: true,
            ..cfg(&["BadBot"])
        })
        .unwrap();
        let first_rule = text
            .lines()
            .find(|line| line.trim_start().starts_with("RewriteRule"))
            .unwrap();
        assert_eq!(
            first_rule,
            format!(
                "    RewriteRule ^/robots\\.txt$ {} [L]",
                robots_txt_path().display()
            ),
            "block was:\n{text}"
        );
        assert!(!text.contains("Alias"), "block was:\n{text}");
    }

    /// `site` with every block `config` asks for, against no tree.
    fn applied(site: &str, config: &BlockConfig) -> Result<String> {
        blocks_for_file(site, Path::new("s"), Path::new(NO_TREE), &[], config)
    }

    #[test]
    fn a_later_rewrite_engine_off_is_refused() {
        let site = SITE.replace("</VirtualHost>", "    RewriteEngine Off\n</VirtualHost>");
        let err = applied(&site, &cfg(&["BadBot"])).unwrap_err();
        assert!(
            format!("{err:#}").contains("RewriteEngine Off"),
            "said: {err:#}"
        );
        // Nothing to write is nothing to switch off.
        assert!(applied(&site, &cfg(&[])).is_ok());
    }

    #[test]
    fn a_block_a_later_rewrite_engine_off_switches_off_is_never_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let config = cfg(&["BadBot"]);
        fs::write(
            &path,
            applied(SITE, &config)
                .unwrap()
                .replace("</VirtualHost>", "    RewriteEngine off\n</VirtualHost>"),
        )
        .unwrap();
        assert_eq!(
            site_apply_status(&path, "example.com", &config, Path::new(NO_TREE)),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn rewrite_engine_off_for_one_directory_leaves_the_block_alone() {
        let site = SITE.replace(
            "</VirtualHost>",
            "    <Directory /var/www/example/static>\n        RewriteEngine Off\n    </Directory>\n</VirtualHost>",
        );
        assert!(applied(&site, &cfg(&["BadBot"])).is_ok());
    }

    #[test]
    fn the_http_1x_rule_is_written_only_where_http2_is_spoken() {
        let host_h2 = TLS_SITE.replace("SSLEngine on", "SSLEngine on\n    Protocols h2 http/1.1");
        let cases: [(&str, &[ConfigFile], &str, bool); 6] = [
            ("no main config to check", &[], TLS_SITE, false),
            ("mod_http2 off", &[DEBIAN_MAIN, HTTP2_CONF], TLS_SITE, false),
            (
                "no Protocols h2",
                &[DEBIAN_MAIN, HTTP2_LOAD],
                TLS_SITE,
                false,
            ),
            (
                "the prefork MPM",
                &[DEBIAN_MAIN, HTTP2_LOAD, HTTP2_CONF, PREFORK_LOAD],
                TLS_SITE,
                false,
            ),
            (
                "h2 for the whole server",
                &[DEBIAN_MAIN, HTTP2_LOAD, HTTP2_CONF],
                TLS_SITE,
                true,
            ),
            (
                "h2 for the host",
                &[DEBIAN_MAIN, HTTP2_LOAD],
                &host_h2,
                true,
            ),
        ];
        let strict = BlockConfig {
            request_rules: vec![RequestRule::Http1x],
            ..cfg(&[])
        };
        for (what, files, site, written) in cases {
            let root = tree(files);
            let path = root.path().join("sites-available/site.conf");
            let result = blocks_for_file(
                site,
                &path,
                root.path(),
                &[("example.com".to_string(), strict.clone())],
                &cfg(&[]),
            );
            assert_eq!(result.is_ok(), written, "{what}: {result:?}");
            if let Err(err) = result {
                assert!(format!("{err:#}").contains("HTTP/1.x"), "{what}: {err:#}");
            }
        }
    }

    // ---- the access logs the config names ----

    /// Debian's tree: every log a file Apache reads names, once, with
    /// `${APACHE_LOG_DIR}` from `envvars`; nothing from a file it does not
    /// read, a pipe, or another variable.
    #[test]
    fn the_logs_debian_s_config_names_are_found_once_each() {
        let root = tree(&[
            DEBIAN_MAIN,
            (
                "envvars",
                "export APACHE_RUN_USER=www-data\nexport APACHE_LOG_DIR=/var/log/apache2$SUFFIX\n",
            ),
            (
                "conf-enabled/other-vhosts-access-log.conf",
                "CustomLog ${APACHE_LOG_DIR}/other_vhosts_access.log vhost_combined\n",
            ),
            (
                "sites-enabled/000-default.conf",
                "<VirtualHost *:80>\n    CustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n",
            ),
            (
                "sites-enabled/shop.conf",
                "<VirtualHost *:443>\n    ServerName shop.example\n    \
                 CustomLog \"/srv/shop/logs/access.log\" combined env=!dontlog\n    \
                 TransferLog \"|/usr/bin/rotatelogs /srv/shop/logs/x 86400\"\n    \
                 CustomLog ${SHOP_LOGS}/access.log combined\n    \
                 # CustomLog /srv/shop/logs/commented.log combined\n    \
                 CustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n",
            ),
            (
                "sites-available/disabled.conf",
                "<VirtualHost *:80>\n    CustomLog /srv/disabled/access.log combined\n</VirtualHost>\n",
            ),
        ]);

        assert_eq!(
            access_logs(root.path()),
            [
                PathBuf::from("/var/log/apache2/other_vhosts_access.log"),
                PathBuf::from("/var/log/apache2/access.log"),
                PathBuf::from("/srv/shop/logs/access.log"),
            ]
        );
    }

    /// A relative path is the server root's, as Apache resolves it: RHEL's
    /// `logs/access_log`.
    #[test]
    fn a_relative_log_is_under_the_server_root() {
        let root = tree(&[RHEL_MAIN]);

        assert_eq!(
            access_logs(root.path()),
            [root.path().join("logs/access_log")]
        );
    }
}
