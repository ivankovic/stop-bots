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
//!   leaves the console expecting an address nothing serves.
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
    /// The host name the console must start accepting, added to the
    /// allowlist by [`record`].
    pub host: String,
    /// The prefix to serve under, in path mode. `None` in subdomain mode,
    /// where the console keeps the root.
    pub base_path: Option<BasePath>,
    /// Where NGINX will proxy to — this server's own bind address.
    pub upstream: SocketAddr,
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
                host,
                base_path: None,
                upstream,
                commands,
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
            Ok(Plan {
                access: ConsoleAccess::Path {
                    prefix: prefix.url("/"),
                    config_path,
                    server_name: server_name.clone(),
                },
                host: server_name,
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

/// Records the address the console now answers to.
///
/// Only ever called after [`apply`] returned `Ok`: a host allowlist naming
/// somewhere nothing serves, or a prefix NGINX never got, is a setting
/// that only makes the console harder to reach.
pub fn record(db: &Db, plan: &Plan) -> Result<()> {
    let mut hosts = crate::web::configured_hosts(db)?;
    if !hosts.iter().any(|h| h == &plan.host) {
        hosts.push(plan.host.clone());
        db.set_text_setting(crate::web::ALLOWED_HOSTS_KEY, &hosts.join(","))?;
    }
    if let Some(prefix) = &plan.base_path {
        // `BasePath::from_db` reads this back through `parse`, which
        // accepts the `/stop-bots` form `as_str` produces.
        db.set_text_setting(crate::web::BASE_PATH_KEY, prefix.as_str())?;
    }
    Ok(())
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

        assert_eq!(plan.host, "console.example.com");
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
