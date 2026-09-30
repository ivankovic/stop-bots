/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Putting the console behind NGINX — the half both front-ends share.
//!
//! Split into three the same way [`crate::refresh`] is, and for the same
//! reason: the middle step is the slow, system-touching one, and it must
//! be able to run somewhere the database cannot go.
//!
//! - [`plan`] reads the scanned sites, the bind address and the NGINX
//!   commands out of `Db`, and validates what the operator typed.
//! - [`apply`] writes the config and runs `nginx -t`, touching no `Db`.
//! - [`record`] stores the host name and path prefix the console must now
//!   answer to — *after* the config validated, so a failed apply never
//!   leaves the console expecting an address nothing serves — and turns on
//!   what a console behind that proxy needs: believing its
//!   `X-Forwarded-For`, and a `Secure` cookie where the site serves TLS.
//!
//! Reloading is not in here. It is the one step that is already a shared
//! `start_`/`finish_` pair in the TUI and a helper in the console, and
//! both call it themselves once this has returned a path.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::db::Db;
use crate::nginx::{self, ConsoleAccess, NginxCommands};
use crate::web::BasePath;

/// The prefix both front-ends offer first. Path mode is the default
/// because it inherits the site's certificate, and this is the prefix the
/// console's own form prefills.
pub const DEFAULT_PREFIX: &str = "/stop-bots/";

/// What a front-end collected from its operator, before any of it has been
/// checked against the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Give the console its own `server` block on a host name of its own.
    Subdomain { host: String },
    /// Mount it as a `location` on a site that already exists, so it
    /// inherits that site's certificate.
    Path { site: String, prefix: String },
}

/// A validated request, with everything [`apply`] and [`record`] need
/// already read out of the database.
///
/// Deliberately free of anything borrowing `Db`: this is what crosses onto
/// a worker thread, and `Db` is not `Sync`.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The config change to make.
    pub access: ConsoleAccess,
    /// Every host name the console must start accepting, added to the
    /// allowlist by [`record`].
    ///
    /// Plural, and that is the whole point. A `server` block routinely
    /// carries several names — `server_name www.example.com example.com;`
    /// — and NGINX answers for all of them, but `scan-sites` records only
    /// the first as the site's name. Allowlisting just that one produces a
    /// console that works on `www.example.com` and returns 421 on
    /// `example.com`, with the host check correctly refusing a name it was
    /// never told about.
    pub hosts: Vec<String>,
    /// The prefix to serve under, in path mode. `None` in subdomain mode,
    /// where the console keeps the root.
    pub base_path: Option<BasePath>,
    /// Where NGINX will proxy to — this server's own bind address.
    pub upstream: SocketAddr,
    /// Whether the console will be served over TLS once this is applied:
    /// path mode on a site with an `ssl` server block. Never true in
    /// subdomain mode, whose block is plain HTTP until certbot has run —
    /// and it is only certbot that knows when that is.
    pub tls: bool,
    /// How to test and reload NGINX on this host.
    pub commands: NginxCommands,
}

/// Checks `request` against the host and gathers what applying it needs.
///
/// Every failure here is written for the operator reading it in a status
/// line, because that is the only place any of them appears.
pub fn plan(db: &Db, request: &Request) -> Result<Plan> {
    let upstream = crate::web::resolve_bind(db, None)?;
    let commands = NginxCommands::from_db(db)?;

    match request {
        Request::Subdomain { host } => {
            let host = host.trim().to_string();
            if !is_plausible_host(&host) {
                anyhow::bail!("A subdomain needs a host name, like console.example.com.");
            }
            Ok(Plan {
                access: ConsoleAccess::Subdomain { host: host.clone() },
                hosts: vec![host],
                base_path: None,
                upstream,
                commands,
                tls: false,
            })
        }
        Request::Path { site, prefix } => {
            let server_name = site.trim().to_string();
            if server_name.is_empty() {
                anyhow::bail!("Pick a site to mount the console under, or scan for sites first.");
            }
            let prefix = BasePath::parse(prefix.trim())?;
            if prefix.is_root() {
                anyhow::bail!(
                    "Path mode needs a prefix, like /stop-bots/ — mounting the console at \
                     the site root would take over the whole site."
                );
            }
            let config_path = db
                .list_sites()
                .context("could not read the scanned sites")?
                .into_iter()
                .find(|s| s.server_name == server_name)
                .map(|s| PathBuf::from(s.config_path))
                .with_context(|| {
                    format!("No scanned site called {server_name}. Re-scan sites first.")
                })?;
            // Every name on the block this location is going into, not
            // just the one the database happens to store.
            let hosts = nginx::server_names_for(&config_path, &server_name);
            let tls = nginx::serves_tls(&config_path, &server_name);
            Ok(Plan {
                tls,
                access: ConsoleAccess::Path {
                    prefix: prefix.url("/"),
                    config_path,
                    server_name,
                },
                hosts,
                base_path: Some(prefix),
                upstream,
                commands,
            })
        }
    }
}

/// Writes the config change and validates it, rolling the file back if
/// `nginx -t` refuses. Returns the file that changed.
///
/// Touches no `Db`, on purpose: this is the step that runs a subprocess,
/// and it is the one a front-end moves off its main thread.
pub fn apply(plan: &Plan, root: &Path) -> Result<PathBuf> {
    nginx::apply_console_access(root, &plan.access, &plan.upstream, &plan.commands)
}

/// Records the address the console now answers to, and what a console
/// behind this proxy needs.
///
/// Only ever called after [`apply`] returned `Ok`: a host allowlist naming
/// somewhere nothing serves, or a prefix NGINX never got, is a setting
/// that only makes the console harder to reach.
///
/// **`web:trust_forwarded_for`, always.** The `location` this wrote sets
/// `X-Forwarded-For $proxy_add_x_forwarded_for`, and it used to leave the
/// console not believing it: every proxied client was 127.0.0.1, so the
/// login throttle had one key for everyone and an attacker's failures
/// kept the operator out. The header is still only believed from a
/// loopback peer, which is where this proxy connects from.
///
/// **`web:secure_cookie`, when the site serves TLS** ([`Plan::tls`]).
/// Only turned on, never off: an operator who set it by hand keeps it.
/// Not in subdomain mode, whose block is plain HTTP when written; its
/// comment says to set it after running certbot.
pub fn record(db: &Db, plan: &Plan) -> Result<()> {
    let mut hosts = crate::web::configured_hosts(db)?;
    let before = hosts.len();
    for host in &plan.hosts {
        if !hosts.iter().any(|known| known == host) {
            hosts.push(host.clone());
        }
    }
    if hosts.len() != before {
        db.set_text_setting(crate::web::ALLOWED_HOSTS_KEY, &hosts.join(","))?;
    }
    if let Some(prefix) = &plan.base_path {
        // `BasePath::from_db` reads this back through `parse`, which
        // accepts the `/stop-bots` form `as_str` produces.
        db.set_text_setting(crate::web::BASE_PATH_KEY, prefix.as_str())?;
    }
    db.set_bool_setting(crate::web::TRUST_FORWARDED_KEY, true)?;
    if plan.tls {
        db.set_bool_setting(crate::web::SECURE_COOKIE_KEY, true)?;
    }
    Ok(())
}

impl Plan {
    /// What [`record`] turns on besides the address, for the message a
    /// front-end shows once it has.
    pub fn recorded_note(&self) -> &'static str {
        if self.tls {
            "The console now believes the proxy's X-Forwarded-For, and its session cookie is \
             HTTPS-only."
        } else {
            "The console now believes the proxy's X-Forwarded-For."
        }
    }
}

/// A cheap plausibility check on a host name, not a validator: it only has
/// to keep a blank field and an obvious typo out of a generated
/// `server_name` directive. NGINX itself is the real parser, and
/// `nginx::write_validated` is what makes running it safe.
pub fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with('.')
        && !host.starts_with('-')
        && !host.ends_with('.')
        && !host.ends_with('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open_in_memory().unwrap()
    }

    #[test]
    fn a_blank_subdomain_is_refused_before_anything_is_written() {
        let err = plan(
            &db(),
            &Request::Subdomain {
                host: "  ".to_string(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("console.example.com"), "was: {err}");
    }

    #[test]
    fn a_subdomain_plans_its_own_server_block() {
        let plan = plan(
            &db(),
            &Request::Subdomain {
                host: " console.example.com ".to_string(),
            },
        )
        .unwrap();

        assert_eq!(plan.hosts, vec!["console.example.com".to_string()]);
        assert!(plan.base_path.is_none(), "a subdomain keeps the root");
        assert!(matches!(plan.access, ConsoleAccess::Subdomain { .. }));
    }

    #[test]
    fn path_mode_needs_a_site_that_was_actually_scanned() {
        let err = plan(
            &db(),
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Re-scan sites"), "was: {err}");
    }

    #[test]
    fn path_mode_refuses_the_site_root() {
        let db = db();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example")
            .unwrap();

        let err = plan(
            &db,
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/".to_string(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("take over the whole site"), "was: {err}");
    }

    #[test]
    fn path_mode_plans_a_location_on_the_scanned_site_s_own_file() {
        let db = db();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example")
            .unwrap();

        let plan = plan(
            &db,
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap();

        match &plan.access {
            ConsoleAccess::Path {
                prefix,
                config_path,
                server_name,
            } => {
                assert_eq!(prefix, "/stop-bots/");
                assert_eq!(
                    config_path,
                    std::path::Path::new("/etc/nginx/sites-enabled/example")
                );
                assert_eq!(server_name, "example.com");
            }
            other => panic!("expected path mode, got {other:?}"),
        }
        assert_eq!(plan.base_path.as_ref().unwrap().as_str(), "/stop-bots");
    }

    /// **The bug this found on a real host.** `server_name www.example.com
    /// example.com;` is routine, NGINX answers for both, and `scan-sites`
    /// records the site under the first. Allowlisting only that one gives
    /// a console that works on `www.example.com` and returns 421 on
    /// `example.com` — the host check correctly refusing a name nobody
    /// told it about.
    #[test]
    fn every_name_on_the_block_is_allowlisted_not_just_the_stored_one() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("example.conf");
        std::fs::write(
            &config,
            "server {\n    server_name www.example.com example.com;\n    listen 443 ssl;\n}\n",
        )
        .unwrap();

        let db = db();
        db.upsert_site("www.example.com", config.to_str().unwrap())
            .unwrap();

        let plan = plan(
            &db,
            &Request::Path {
                site: "www.example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            plan.hosts,
            vec!["www.example.com".to_string(), "example.com".to_string()],
            "the second name on the block was dropped"
        );

        record(&db, &plan).unwrap();
        let allowed = crate::web::configured_hosts(&db).unwrap();
        assert!(
            allowed.contains(&"example.com".to_string()),
            "was: {allowed:?}"
        );
        assert!(
            allowed.contains(&"www.example.com".to_string()),
            "was: {allowed:?}"
        );
    }

    /// A config that cannot be read still yields the name the database
    /// has, so a missing file degrades to the old behaviour rather than to
    /// an empty allowlist.
    #[test]
    fn an_unreadable_config_still_allowlists_the_stored_name() {
        let db = db();
        db.upsert_site("example.com", "/nonexistent/example.conf")
            .unwrap();

        let plan = plan(
            &db,
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap();

        assert_eq!(plan.hosts, vec!["example.com".to_string()]);
    }

    /// The console has to start answering to the name NGINX will now send
    /// it, and under the prefix NGINX will now keep — or the operator
    /// applies the change and locks themselves out of the page they were
    /// looking at.
    #[test]
    fn recording_teaches_the_console_its_new_address() {
        let db = db();
        db.upsert_site("example.com", "/etc/nginx/sites-enabled/example")
            .unwrap();
        let plan = plan(
            &db,
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap();

        record(&db, &plan).unwrap();

        assert!(crate::web::configured_hosts(&db)
            .unwrap()
            .contains(&"example.com".to_string()));
        assert_eq!(
            db.get_text_setting(crate::web::BASE_PATH_KEY).unwrap(),
            Some("/stop-bots".to_string())
        );
    }

    /// The proxy this writes sets `X-Forwarded-For`, and a console that
    /// does not believe it sees every client as 127.0.0.1: one throttle
    /// key for the operator and every attacker.
    #[test]
    fn recording_either_mode_trusts_the_proxy_s_forwarded_header() {
        for request in [
            Request::Subdomain {
                host: "console.example.com".to_string(),
            },
            Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        ] {
            let db = db();
            db.upsert_site("example.com", "/nonexistent/example.conf")
                .unwrap();
            let plan = plan(&db, &request).unwrap();

            record(&db, &plan).unwrap();

            assert!(
                db.get_bool_setting(crate::web::TRUST_FORWARDED_KEY, false)
                    .unwrap(),
                "{request:?}"
            );
        }
    }

    fn site_config(content: &str) -> (tempfile::TempDir, Db, Plan) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("example.conf");
        std::fs::write(&config, content).unwrap();
        let db = db();
        db.upsert_site("example.com", config.to_str().unwrap())
            .unwrap();
        let plan = plan(
            &db,
            &Request::Path {
                site: "example.com".to_string(),
                prefix: "/stop-bots/".to_string(),
            },
        )
        .unwrap();
        (dir, db, plan)
    }

    /// Path mode on a site with a certificate puts the console behind
    /// TLS, and a cookie without `Secure` would still go to `http://`.
    #[test]
    fn a_path_on_a_tls_site_makes_the_cookie_secure() {
        let (_dir, db, plan) = site_config(
            "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}\n\
             server {\n    listen 443 ssl;\n    server_name example.com;\n}\n",
        );
        assert!(plan.tls);

        record(&db, &plan).unwrap();

        assert!(db
            .get_bool_setting(crate::web::SECURE_COOKIE_KEY, false)
            .unwrap());
        assert!(plan.recorded_note().contains("HTTPS-only"));
    }

    /// Conservative: on a plain-HTTP site, or a subdomain before certbot,
    /// a `Secure` cookie is never stored and the console could not keep
    /// anyone logged in. And one set by hand is never turned off.
    #[test]
    fn a_plain_http_site_leaves_the_cookie_setting_as_it_was() {
        let (_dir, db, plan) =
            site_config("server {\n    listen 80;\n    server_name example.com;\n}\n");
        assert!(!plan.tls);

        record(&db, &plan).unwrap();
        assert!(!db
            .get_bool_setting(crate::web::SECURE_COOKIE_KEY, false)
            .unwrap());

        db.set_bool_setting(crate::web::SECURE_COOKIE_KEY, true)
            .unwrap();
        record(&db, &plan).unwrap();
        assert!(db
            .get_bool_setting(crate::web::SECURE_COOKIE_KEY, false)
            .unwrap());

        let subdomain = super::plan(
            &db,
            &Request::Subdomain {
                host: "console.example.com".to_string(),
            },
        )
        .unwrap();
        assert!(!subdomain.tls, "plain HTTP until certbot has run");
    }

    /// Applying twice must not list the host twice, which is what a plain
    /// push would do.
    #[test]
    fn recording_the_same_host_twice_lists_it_once() {
        let db = db();
        let plan = plan(
            &db,
            &Request::Subdomain {
                host: "console.example.com".to_string(),
            },
        )
        .unwrap();

        record(&db, &plan).unwrap();
        record(&db, &plan).unwrap();

        assert_eq!(
            crate::web::configured_hosts(&db).unwrap(),
            vec!["console.example.com".to_string()]
        );
    }

    #[test]
    fn a_host_name_check_that_only_keeps_the_obvious_mistakes_out() {
        assert!(is_plausible_host("console.example.com"));
        assert!(!is_plausible_host(""));
        assert!(!is_plausible_host("localhost"));
        assert!(!is_plausible_host(".example.com"));
        assert!(!is_plausible_host("example.com."));
        assert!(!is_plausible_host("-example.com"));
        assert!(!is_plausible_host("example.com-"));
        assert!(!is_plausible_host("exa mple.com"));
        assert!(!is_plausible_host("exam;ple.com"));
    }
}
