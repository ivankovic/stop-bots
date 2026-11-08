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

//! Probe paths that are only probes where their application is absent.
//!
//! ## Why
//!
//! `/wp-login.php` is how a WordPress administrator signs in, so the
//! built-in probe list leaves it out (see
//! `accesslog::DEFAULT_PROBE_PATHS`). On a server with no WordPress the
//! same request is a scanner and nothing else, and it is one of the most
//! requested paths in any access log. [`APPS`] lists the paths of that kind,
//! each with the application that makes it legitimate and how that
//! application is recognised; the probe-paths detector counts a path as a
//! probe where its applications are known to be absent, and nowhere else.
//!
//! ## Which site a request was for
//!
//! As [`crate::services`] tells it: the `Host` a JSON format logs, or a
//! quoted field a combined-style format appends after the user agent,
//! when it names a scanned site. NGINX's default combined format logs
//! neither, so on most hosts no line names its site. Such a request is
//! judged against the whole host: a path is a probe only when **no** site
//! on it runs the application, and when no site is in doubt. A request
//! that does name a site is judged against that site (and the server-wide
//! config every site inherits).
//!
//! ## In doubt is not absent
//!
//! A wrong "absent" blocks an administrator on their own login page, so
//! everything this cannot see into counts as possibly running the
//! application: a site that passes requests to an upstream no
//! [`crate::services::Service`] names (a WordPress container behind
//! `proxy_pass http://127.0.0.1:8080` looks like that), a document root
//! that is not a directory on this host or is decided per request, a site
//! whose config names no document root at all, and every document root
//! when the web server runs with a test command of its own, which is how
//! one in a container is set up: its paths are the container's, not this
//! host's. Anything that names the application or the path in the config,
//! even a `location` that denies it, counts as present.

use std::path::Path;

/// A directive of a site's config: its name, under NGINX's spelling, and
/// its arguments.
pub type Directive = (String, Vec<String>);

/// One application whose own users request paths a scanner also probes.
#[derive(Debug)]
pub struct WebApp {
    pub name: &'static str,
    /// Words that, in any argument of any directive of a site (an
    /// `include`, a `root`, an upstream, a `location`), say the
    /// application answers there. Compared ignoring case.
    pub config_names: &'static [&'static str],
    /// Files whose presence in a document root, or in a directory one
    /// level below it, says the application is installed there.
    pub files: &'static [&'static str],
    /// The path segments its users request, matched against each segment
    /// of a request path ignoring case: `/blog/wp-login.php` is a request
    /// for `wp-login.php`. One with a `/` is several segments in a row,
    /// for an application whose own names are ordinary words:
    /// `remote/logincheck` is FortiGate's, `remote` alone anyone's.
    pub paths: &'static [&'static str],
}

/// The whole table: application, markers, conditional probe paths.
///
/// A path listed under two applications (`xmlrpc.php`) is a probe only
/// where both are absent. Any path here that exists in a document root is
/// served there, whatever application put it there.
pub const APPS: [WebApp; 16] = [
    WebApp {
        name: "WordPress",
        config_names: &["wordpress"],
        files: &["wp-config.php", "wp-login.php"],
        paths: &["wp-login.php", "wp-admin", "wp-includes", "xmlrpc.php"],
    },
    WebApp {
        name: "phpMyAdmin",
        config_names: &["phpmyadmin"],
        files: &["phpmyadmin", "config.inc.php"],
        paths: &["phpmyadmin", "pma"],
    },
    // Drupal 7 serves `xmlrpc.php` for its pingbacks, as WordPress does.
    WebApp {
        name: "Drupal",
        config_names: &["drupal"],
        files: &["core/lib/Drupal.php", "includes/bootstrap.inc"],
        paths: &["xmlrpc.php"],
    },
    // The rest are what DShield's web honeypots were asked for most, in
    // the month to 2026-10-19, that no other probe path covered: appliances
    // and servers a web host does not run, but that some host behind a
    // reverse proxy might. Each path is one only that product uses.
    // Exchange's `/autodiscover/` is left out, whatever the product: a
    // person's Outlook asks for it on the domain of their email address.
    WebApp {
        name: "Microsoft Exchange",
        config_names: &["exchange", "owa"],
        files: &[],
        paths: &[
            "auth.owa",
            // Outlook on the web's sign-in page, `/owa/auth/logon.aspx`.
            "owa/auth",
            "rpcproxy.dll",
            "emsmdb",
            "microsoft-server-activesync",
            "reportingwebservice",
        ],
    },
    WebApp {
        name: "FortiGate SSL VPN",
        config_names: &["fortigate", "fortinet"],
        files: &[],
        paths: &[
            "remote/logincheck",
            "remote/fgt_lang",
            "remote/login",
            "remote/info",
        ],
    },
    WebApp {
        name: "Tomcat manager",
        config_names: &["tomcat"],
        files: &[],
        paths: &["manager/html", "host-manager"],
    },
    WebApp {
        name: "Solr",
        config_names: &["solr"],
        files: &[],
        paths: &["solr/admin"],
    },
    WebApp {
        name: "Spring Boot",
        config_names: &["actuator", "spring"],
        files: &[],
        paths: &["actuator"],
    },
    WebApp {
        name: "Docker API or registry",
        config_names: &["docker", "registry"],
        files: &[],
        paths: &["containers/json", "v2/_catalog"],
    },
    WebApp {
        name: "a router's admin pages",
        config_names: &["luci", "goform", "boaform"],
        files: &[],
        paths: &[
            "hnap1",
            "boaform",
            "goform",
            "gponform",
            "cgi-bin/luci",
            "authlogin.cgi",
        ],
    },
    WebApp {
        name: "GeoServer",
        config_names: &["geoserver"],
        files: &[],
        paths: &["geoserver"],
    },
    // What one host's log was asked for, 2026-09-28 to 2026-11-07, that
    // nothing above covered: VPN logins, monitoring, and camera streams.
    WebApp {
        name: "Palo Alto GlobalProtect",
        config_names: &["globalprotect", "global-protect"],
        files: &[],
        paths: &["global-protect"],
    },
    WebApp {
        name: "Zabbix",
        config_names: &["zabbix"],
        files: &[],
        paths: &["zabbix"],
    },
    // `/remote_agent.php`, the unauthenticated command injection
    // (CVE-2022-46169).
    WebApp {
        name: "Cacti",
        config_names: &["cacti"],
        files: &["remote_agent.php"],
        paths: &["remote_agent.php"],
    },
    WebApp {
        name: "an IP camera's video stream",
        config_names: &["axis-cgi", "mjpg", "zoneminder"],
        files: &[],
        paths: &["axis-cgi", "mjpg"],
    },
    // Apache's mod_status, which a host that runs it names in its config.
    WebApp {
        name: "Apache's server-status",
        config_names: &["server-status"],
        files: &[],
        paths: &["server-status"],
    },
];

/// Every conditional path, once each, in the order of [`APPS`]: the
/// index [`Verdicts`] is kept by.
pub fn conditional_paths() -> &'static [&'static str] {
    static PATHS: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
        let mut paths: Vec<&'static str> = Vec::new();
        for path in APPS.iter().flat_map(|app| app.paths) {
            if !paths.contains(path) {
                paths.push(path);
            }
        }
        paths
    });
    &PATHS
}

/// The applications that make `path` legitimate.
pub fn apps_serving(path: &str) -> Vec<&'static str> {
    APPS.iter()
        .filter(|app| app.paths.contains(&path))
        .map(|app| app.name)
        .collect()
}

/// What one conditional path is on a site, or on the whole host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing serves it: a request for it is a probe.
    Probe,
    /// Something serves it, and why this thinks so.
    Served(String),
    /// Something might, and why this cannot tell.
    Unknown(String),
}

impl Verdict {
    /// Which of two verdicts on the same path wins: served over unknown
    /// over probe, so a path is a probe only where every part agrees.
    fn rank(&self) -> u8 {
        match self {
            Verdict::Probe => 0,
            Verdict::Unknown(_) => 1,
            Verdict::Served(_) => 2,
        }
    }

    /// Why it is not a probe, if it is not.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verdict::Probe => None,
            Verdict::Served(why) | Verdict::Unknown(why) => Some(why),
        }
    }
}

/// A verdict for each of [`conditional_paths`], in that order. Empty is
/// "nothing known", in which nothing is a probe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdicts(Vec<Verdict>);

impl Verdicts {
    /// Every path a probe: where a site's inspection starts.
    fn all_probes() -> Verdicts {
        Verdicts(vec![Verdict::Probe; conditional_paths().len()])
    }

    /// Every path in doubt, for `why`.
    pub fn unknown(why: &str) -> Verdicts {
        let mut verdicts = Verdicts::all_probes();
        verdicts.doubt_all(why);
        verdicts
    }

    pub fn get(&self, path: &str) -> Option<&Verdict> {
        let index = conditional_paths().iter().position(|p| *p == path)?;
        self.0.get(index)
    }

    /// Records `verdict` for `path`, unless what is there already wins.
    fn set(&mut self, path: &str, verdict: Verdict) {
        let Some(index) = conditional_paths().iter().position(|p| *p == path) else {
            return;
        };
        if let Some(slot) = self.0.get_mut(index) {
            if verdict.rank() > slot.rank() {
                *slot = verdict;
            }
        }
    }

    fn serve_app(&mut self, app: &WebApp, why: &str) {
        for path in app.paths {
            self.set(path, Verdict::Served(why.to_string()));
        }
    }

    fn doubt_all(&mut self, why: &str) {
        for path in conditional_paths() {
            self.set(path, Verdict::Unknown(why.to_string()));
        }
    }

    /// Each path's verdict combined with `other`'s, its reasons prefixed
    /// with `whose` (a site's name) when given. Combining with an empty
    /// set changes nothing.
    fn combine(&mut self, other: &Verdicts, whose: Option<&str>) {
        if self.0.is_empty() {
            *self = Verdicts::all_probes();
        }
        for (path, verdict) in conditional_paths().iter().copied().zip(&other.0) {
            let verdict = match (verdict, whose) {
                (Verdict::Served(why), Some(site)) => Verdict::Served(format!("{site}: {why}")),
                (Verdict::Unknown(why), Some(site)) => Verdict::Unknown(format!("{site}: {why}")),
                (verdict, _) => verdict.clone(),
            };
            self.set(path, verdict);
        }
    }

    /// Each conditional path with its verdict.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Verdict)> {
        conditional_paths().iter().copied().zip(&self.0)
    }
}

/// Upstreams this cannot see into: whatever answers behind them could be
/// any application. `fastcgi_pass` is not one, because PHP-FPM runs the
/// files under the site's own `root`, which is looked at instead.
const OPAQUE_PASSES: [&str; 5] = [
    "proxy_pass",
    "uwsgi_pass",
    "scgi_pass",
    "grpc_pass",
    "memcached_pass",
];

/// Directives that send a request elsewhere rather than serve it: a site
/// made only of these serves no application.
const REDIRECTS: [&str; 6] = [
    "return",
    "rewrite",
    "redirect",
    "redirectmatch",
    "redirectpermanent",
    "rewriterule",
];

/// The most entries a document root is listed for: past this, looking at
/// each subdirectory every minute costs more than it is worth, and the
/// root counts as in doubt.
const MAX_ROOT_ENTRIES: usize = 200;

/// The applications `verdicts` say are served, by name: those whose own
/// paths are all served. In doubt is not served here: what this is for
/// (ModSecurity's exclusions, `crate::modsecurity`) loosens checks, and
/// loosening them for an application that is not there is a hole.
pub fn apps_present(verdicts: &Verdicts) -> Vec<&'static str> {
    APPS.iter()
        .filter(|app| {
            !app.paths.is_empty()
                && app
                    .paths
                    .iter()
                    .all(|path| matches!(verdicts.get(path), Some(Verdict::Served(_))))
        })
        .map(|app| app.name)
        .collect()
}

/// What one site serves, from its directives (`None`: its config could
/// not be read) and, when `files_here`, its document roots on disk.
pub fn inspect_site(directives: Option<&[Directive]>, files_here: bool) -> Verdicts {
    let Some(directives) = directives else {
        return Verdicts::unknown("its config could not be read");
    };
    let mut verdicts = Verdicts::all_probes();
    named_in(
        directives.iter().flat_map(|(_, arguments)| arguments),
        "its config",
        &mut verdicts,
    );
    let mut roots = Vec::new();
    let mut passes = false;
    for directive in directives {
        let (name, arguments) = directive;
        if OPAQUE_PASSES.contains(&name.as_str()) {
            passes = true;
            if crate::services::recognise(std::slice::from_ref(directive)).is_none() {
                let upstream = arguments.first().map(String::as_str).unwrap_or_default();
                verdicts.doubt_all(&format!("it passes requests to {upstream}"));
            }
        } else if matches!(name.as_str(), "root" | "alias") {
            roots.extend(arguments.last());
        }
    }
    // A site with neither serves only what it redirects, unless a file it
    // includes says otherwise, which this does not read.
    if roots.is_empty() && !passes {
        let redirects = directives
            .iter()
            .any(|(name, _)| REDIRECTS.contains(&name.as_str()));
        let includes = directives
            .iter()
            .any(|(name, _)| name.starts_with("include"));
        if !redirects || includes {
            verdicts.doubt_all("its config names no document root");
        }
    }
    for root in roots {
        inspect_root(root.trim_matches(['"', '\'']), files_here, &mut verdicts);
    }
    verdicts
}

/// What the server-wide config every site inherits serves: each of
/// `files` as its name and its text. Only what it names counts; a
/// `server` block in it with a name of its own is a site, inspected as
/// one.
pub fn inspect_global(files: &[(String, String)]) -> Verdicts {
    let mut verdicts = Verdicts::all_probes();
    for (name, text) in files {
        let words: Vec<String> = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().to_string())
            .collect();
        named_in(words.iter(), name, &mut verdicts);
    }
    verdicts
}

/// Marks served whatever `texts` name: an application by one of its
/// [`WebApp::config_names`], or a conditional path by `/` and itself.
fn named_in<'a>(texts: impl Iterator<Item = &'a String>, place: &str, verdicts: &mut Verdicts) {
    for text in texts {
        let text = text.to_ascii_lowercase();
        for app in &APPS {
            if app.config_names.iter().any(|name| text.contains(name)) {
                verdicts.serve_app(app, &format!("{} is named in {place}", app.name));
            }
        }
        for path in conditional_paths() {
            if text.contains(&format!("/{path}")) {
                verdicts.set(
                    path,
                    Verdict::Served(format!("/{path} is named in {place}")),
                );
            }
        }
    }
}

/// Looks for each application, and each conditional path, in the
/// document root `root` and the directories directly in it.
fn inspect_root(root: &str, files_here: bool, verdicts: &mut Verdicts) {
    if root.contains('$') {
        verdicts.doubt_all(&format!("its document root {root} is decided per request"));
        return;
    }
    let dir = Path::new(root);
    if !dir.is_absolute() {
        verdicts.doubt_all(&format!("its document root {root} is a relative path"));
        return;
    }
    if !files_here {
        verdicts.doubt_all(&format!(
            "the web server has a test command of its own, so {root} may be inside a container"
        ));
        return;
    }
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .take(MAX_ROOT_ENTRIES + 1)
            .collect(),
        Err(_) => {
            verdicts.doubt_all(&format!("{root} is not a directory this host can read"));
            return;
        }
    };
    if entries.len() > MAX_ROOT_ENTRIES {
        verdicts.doubt_all(&format!("{root} has too many entries to look through"));
        return;
    }
    // Names in the root itself are compared ignoring case: `phpMyAdmin/`
    // answers `/phpmyadmin` on a case-insensitive request match.
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if conditional_paths().contains(&name.as_str()) {
            let why = format!("{} exists", entry.path().display());
            verdicts.set(&name, Verdict::Served(why));
        }
    }
    let places = std::iter::once(dir.to_path_buf()).chain(
        entries
            .iter()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(std::fs::DirEntry::path),
    );
    for place in places {
        for app in &APPS {
            if app.files.iter().any(|file| place.join(file).exists()) {
                let why = format!("{} is installed in {}", app.name, place.display());
                verdicts.serve_app(app, &why);
            }
        }
        for path in conditional_paths() {
            if place.join(path).exists() {
                let why = format!("{} exists", place.join(path).display());
                verdicts.set(path, Verdict::Served(why));
            }
        }
    }
}

/// Whether `path`'s segments (one, or several joined by `/`) appear one
/// after another among `segments`.
fn in_a_row(segments: &[String], path: &str) -> bool {
    let wanted: Vec<&str> = path.split('/').collect();
    segments
        .windows(wanted.len())
        .any(|window| window.iter().zip(&wanted).all(|(have, want)| have == want))
}

/// Which conditional paths are probes where, for every request: the
/// probe-paths detector's half of this module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppProbes {
    /// Each name a site answers to, with that site's verdicts (the
    /// server-wide config's folded in).
    sites: Vec<(String, Verdicts)>,
    /// For a request that names no site: every site's, and the
    /// server-wide config's, folded together.
    host: Verdicts,
}

impl AppProbes {
    /// From each site's names and verdicts, and the server-wide config's.
    /// With no site at all, nothing is a probe: an unscanned host is one
    /// this knows nothing about.
    pub fn new(sites: Vec<(Vec<String>, Verdicts)>, global: &Verdicts) -> AppProbes {
        let mut host = if sites.is_empty() {
            Verdicts::unknown("no site has been scanned (`stop-bots scan-sites`)")
        } else {
            Verdicts::all_probes()
        };
        host.combine(global, None);
        let mut named = Vec::new();
        for (names, verdicts) in sites {
            let label = names.first().cloned().unwrap_or_default();
            host.combine(&verdicts, Some(&label));
            let mut own = verdicts;
            own.combine(global, None);
            for name in names {
                named.push((name, own.clone()));
            }
        }
        AppProbes { sites: named, host }
    }

    /// The conditional path a request for `path` is a probe for, given
    /// every host name the line carries; `None` if it is not one.
    pub fn probe<'a>(
        &self,
        hosts: impl IntoIterator<Item = &'a str>,
        path: &str,
    ) -> Option<&'static str> {
        if self.host.0.is_empty() && self.sites.is_empty() {
            return None;
        }
        // Every line of the log comes through here: a substring test
        // first, so only the few that might be asking pay for decoding.
        let lower = path.to_ascii_lowercase();
        if !conditional_paths().iter().any(|p| lower.contains(p)) && !lower.contains('%') {
            return None;
        }
        let segments: Vec<String> = crate::accesslog::path_segments(path)
            .into_iter()
            .map(|segment| segment.to_ascii_lowercase())
            .collect();
        let asked: Vec<&'static str> = conditional_paths()
            .iter()
            .copied()
            .filter(|path| in_a_row(&segments, path))
            .collect();
        if asked.is_empty() {
            return None;
        }
        let verdicts = hosts
            .into_iter()
            .find_map(|host| {
                let name = crate::services::host_name(host);
                self.sites
                    .iter()
                    .find(|(site, _)| site.eq_ignore_ascii_case(name))
            })
            .map_or(&self.host, |(_, verdicts)| verdicts);
        asked
            .into_iter()
            .find(|path| verdicts.get(path) == Some(&Verdict::Probe))
    }

    /// The verdicts for a request that names no site.
    pub fn host(&self) -> &Verdicts {
        &self.host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(name: &str, arguments: &[&str]) -> Directive {
        (
            name.to_string(),
            arguments.iter().map(|a| a.to_string()).collect(),
        )
    }

    /// A site whose only directive is `root <dir>`.
    fn rooted_at(dir: &Path) -> Verdicts {
        let directives = [directive("root", &[dir.to_str().unwrap()])];
        inspect_site(Some(&directives), true)
    }

    fn is_probe(verdicts: &Verdicts, path: &str) -> bool {
        verdicts.get(path) == Some(&Verdict::Probe)
    }

    fn touch(dir: &Path, file: &str) {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "").unwrap();
    }

    /// One fixture document root per application, recognised by its
    /// marker file, at the root or one directory below it.
    #[test]
    fn recognises_each_application_by_its_files() {
        let cases = [
            ("wp-login.php", "wp-includes", "WordPress"),
            ("blog/wp-config.php", "wp-admin", "WordPress"),
            ("tools/config.inc.php", "pma", "phpMyAdmin"),
            ("core/lib/Drupal.php", "xmlrpc.php", "Drupal"),
            ("includes/bootstrap.inc", "xmlrpc.php", "Drupal"),
        ];
        for (marker, path, app) in cases {
            let dir = tempfile::tempdir().unwrap();
            touch(dir.path(), marker);
            let verdicts = rooted_at(dir.path());
            let reason = verdicts.get(path).and_then(Verdict::reason).unwrap_or("");
            assert!(
                matches!(verdicts.get(path), Some(Verdict::Served(_))) && reason.contains(app),
                "{marker}: {path} was {:?}",
                verdicts.get(path)
            );
        }
    }

    #[test]
    fn a_static_site_serves_none_of_the_paths() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "index.html");
        touch(dir.path(), "css/site.css");
        let verdicts = rooted_at(dir.path());
        for (path, verdict) in verdicts.iter() {
            assert_eq!(verdict, &Verdict::Probe, "{path}");
        }
    }

    /// Drupal's `xmlrpc.php` is not WordPress's login page: each path
    /// belongs to its own applications.
    #[test]
    fn drupal_serves_xmlrpc_and_not_the_wordpress_login() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "includes/bootstrap.inc");
        let verdicts = rooted_at(dir.path());
        assert!(!is_probe(&verdicts, "xmlrpc.php"), "{verdicts:?}");
        assert!(is_probe(&verdicts, "wp-login.php"), "{verdicts:?}");
    }

    /// Whatever put it there, a file a path names is served.
    #[test]
    fn a_path_that_exists_in_the_root_is_served() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "phpMyAdmin/index.php");
        touch(dir.path(), "xmlrpc.php");
        let verdicts = rooted_at(dir.path());
        assert!(!is_probe(&verdicts, "phpmyadmin"), "{verdicts:?}");
        assert!(!is_probe(&verdicts, "xmlrpc.php"), "{verdicts:?}");
        assert!(is_probe(&verdicts, "wp-login.php"), "{verdicts:?}");
    }

    /// The config names an application wherever it does: an upstream, an
    /// include, an alias.
    #[test]
    fn recognises_each_application_named_in_the_config() {
        let cases = [
            (
                directive("fastcgi_pass", &["wordpress:9000"]),
                "wp-login.php",
            ),
            (directive("include", &["snippets/phpmyadmin.conf"]), "pma"),
            (directive("fastcgi_pass", &["drupal:9000"]), "xmlrpc.php"),
            (directive("location", &["=", "/xmlrpc.php"]), "xmlrpc.php"),
        ];
        for (named, path) in cases {
            let directives = [named.clone(), directive("return", &["404"])];
            let verdicts = inspect_site(Some(&directives), true);
            assert!(
                matches!(verdicts.get(path), Some(Verdict::Served(_))),
                "{named:?}: {path} was {:?}",
                verdicts.get(path)
            );
        }
    }

    /// Each thing this cannot see into leaves every path in doubt.
    #[test]
    fn what_cannot_be_seen_into_is_never_a_probe() {
        let missing = "/nonexistent/stop-bots/docroot";
        let cases: [(&str, Option<Vec<Directive>>, bool); 7] = [
            (
                "no root, but an include",
                Some(vec![
                    directive("include", &["snippets/site.conf"]),
                    directive("return", &["404"]),
                ]),
                true,
            ),
            ("unreadable config", None, true),
            (
                "unknown upstream",
                Some(vec![directive("proxy_pass", &["http://127.0.0.1:8080"])]),
                true,
            ),
            (
                "missing root",
                Some(vec![directive("root", &[missing])]),
                true,
            ),
            (
                "per-request root",
                Some(vec![directive("root", &["/var/www/$host"])]),
                true,
            ),
            (
                "no root",
                Some(vec![directive("index", &["index.php"])]),
                true,
            ),
            (
                "container",
                Some(vec![directive(
                    "root",
                    &[std::env::temp_dir().to_str().unwrap()],
                )]),
                false,
            ),
        ];
        for (what, directives, files_here) in cases {
            let verdicts = inspect_site(directives.as_deref(), files_here);
            for (path, verdict) in verdicts.iter() {
                assert!(
                    matches!(verdict, Verdict::Unknown(_)),
                    "{what}: {path} was {verdict:?}"
                );
            }
        }
    }

    /// An upstream a known application answers on is not a mystery, and
    /// a site that only redirects serves nothing.
    #[test]
    fn a_known_upstream_and_a_redirect_leave_the_paths_probes() {
        let cases = [
            directive("proxy_pass", &["http://127.0.0.1:8096"]),
            directive("return", &["301", "https://example.com$request_uri"]),
        ];
        for only in cases {
            let verdicts = inspect_site(Some(std::slice::from_ref(&only)), true);
            assert!(
                is_probe(&verdicts, "wp-login.php"),
                "{only:?}: {verdicts:?}"
            );
        }
    }

    #[test]
    fn the_server_wide_config_serves_what_it_aliases() {
        let debian = "Alias /phpmyadmin /usr/share/phpmyadmin\n# WordPress lives elsewhere\n";
        let verdicts = inspect_global(&[("phpmyadmin.conf".to_string(), debian.to_string())]);
        assert!(!is_probe(&verdicts, "pma"), "{verdicts:?}");
        assert!(
            is_probe(&verdicts, "wp-login.php"),
            "a comment is not config: {verdicts:?}"
        );
    }

    /// A site that answers everything with a 404: it serves nothing.
    fn static_site() -> Verdicts {
        inspect_site(Some(&[directive("return", &["404"])]), true)
    }

    /// The same, with WordPress's snippet included.
    fn wordpress_site() -> Verdicts {
        let directives = [
            directive("include", &["snippets/wordpress.conf"]),
            directive("return", &["404"]),
        ];
        inspect_site(Some(&directives), true)
    }

    fn site(name: &str, verdicts: Verdicts) -> (Vec<String>, Verdicts) {
        (vec![name.to_string()], verdicts)
    }

    #[test]
    fn a_host_with_no_wordpress_treats_its_login_as_a_probe() {
        let probes = AppProbes::new(
            vec![
                site("a.example", static_site()),
                site("b.example", static_site()),
            ],
            &Verdicts::default(),
        );
        assert_eq!(probes.probe([], "/wp-login.php"), Some("wp-login.php"));
        assert_eq!(
            probes.probe([], "/blog/WP-Admin/install.php"),
            Some("wp-admin")
        );
        assert_eq!(probes.probe([], "/blog/wp-login.php.html"), None);
        assert_eq!(probes.probe([], "/about"), None);
    }

    /// One WordPress anywhere, and a request that names no site might be
    /// for it.
    #[test]
    fn one_wordpress_site_makes_an_unattributed_login_no_probe() {
        let probes = AppProbes::new(
            vec![
                site("static.example", static_site()),
                site("blog.example", wordpress_site()),
            ],
            &Verdicts::default(),
        );
        assert_eq!(probes.probe([], "/wp-login.php"), None);
        let reason = probes.host().get("wp-login.php").and_then(Verdict::reason);
        assert_eq!(
            reason,
            Some("blog.example: WordPress is named in its config")
        );
    }

    /// Where the line names its site, that site decides: the static one
    /// is probed, the WordPress one is not.
    #[test]
    fn a_request_that_names_its_site_is_judged_by_that_site() {
        let probes = AppProbes::new(
            vec![
                site("static.example", static_site()),
                site("blog.example", wordpress_site()),
            ],
            &Verdicts::default(),
        );
        assert_eq!(
            probes.probe(["static.example:443"], "/wp-login.php"),
            Some("wp-login.php")
        );
        assert_eq!(probes.probe(["BLOG.example"], "/wp-login.php"), None);
        assert_eq!(probes.probe(["unknown.example"], "/wp-login.php"), None);
    }

    #[test]
    fn the_server_wide_config_applies_to_every_site() {
        let global = inspect_global(&[(
            "phpmyadmin.conf".to_string(),
            "Alias /phpmyadmin /usr/share/phpmyadmin".to_string(),
        )]);
        let probes = AppProbes::new(vec![site("static.example", static_site())], &global);
        assert_eq!(probes.probe(["static.example"], "/phpmyadmin/"), None);
        assert_eq!(probes.probe([], "/phpmyadmin/"), None);
    }

    #[test]
    fn nothing_is_a_probe_before_any_site_is_scanned() {
        let probes = AppProbes::new(Vec::new(), &Verdicts::default());
        assert_eq!(probes.probe([], "/wp-login.php"), None);
        assert_eq!(AppProbes::default().probe([], "/wp-login.php"), None);
    }

    /// Every path has an application, and every application paths and a
    /// way to be recognised. Files are optional: an appliance or a server
    /// with its own port is never in a document root, and is recognised
    /// by its name in the config or doubted for the proxy in front of it.
    #[test]
    fn the_table_is_complete() {
        for app in &APPS {
            assert!(
                !app.paths.is_empty() && !app.config_names.is_empty(),
                "{}",
                app.name
            );
        }
        assert_eq!(apps_serving("xmlrpc.php"), ["WordPress", "Drupal"]);
        for path in conditional_paths() {
            assert!(
                path.split('/').all(|segment| !segment.is_empty()) && *path == path.to_lowercase(),
                "{path} must be lowercase segments joined by single slashes"
            );
        }
    }

    /// A path of several segments is a probe only with all of them, in
    /// order: `remote` alone is anyone's.
    #[test]
    fn a_path_of_several_segments_matches_only_all_of_them_in_a_row() {
        let probes = AppProbes::new(
            vec![site("static.example", static_site())],
            &Verdicts::default(),
        );
        let cases = [
            ("/remote/logincheck", true),
            ("/REMOTE/LoginCheck", true),
            ("/vpn/remote/logincheck", true),
            ("/remote/login", true),
            ("/remote/log", false),
            ("/remote/", false),
            ("/logincheck/remote", false),
            ("/owa/auth.owa", true),
            ("/owa/auth/logon.aspx", true),
            ("/owa/", false),
            ("/cgi-bin/luci/;stok=/locale", true),
            ("/global-protect/login.esp", true),
            ("/axis-cgi/mjpg/video.cgi", true),
            ("/cgi-bin/mjpg/video.cgi", true),
        ];
        for (path, probe) in cases {
            assert_eq!(probes.probe([], path).is_some(), probe, "{path}");
        }
    }
}
