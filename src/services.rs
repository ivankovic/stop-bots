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

//! Which self-hosted application answers behind each site, and which of
//! its own clients' requests look like a bot's without being one.
//!
//! ## Why
//!
//! A sync or media app is the one client that asks for many distinct
//! paths that are not there. The Nextcloud iOS app, catching up after a
//! hundred photos were deleted elsewhere, sends a `PROPFIND` and a
//! preview request for each of them and gets a hundred 404s: on one host
//! that was 14,469 404s in two weeks, all from its owner's phone, and the
//! web scanner detector blocked the owner. Jellyfin's apps 404 on every
//! item without artwork; Immich's on every thumbnail of a deleted photo.
//! The same apps fetch no stylesheets, send no `Referer` and walk deep
//! paths, which is what the three behavioural detectors look for.
//!
//! ## What changes
//!
//! A request on one of the application's own data routes
//! ([`Service::app_routes`]) is not evidence for the 404 detector or the
//! three behavioural ones. Nothing else changes: a probe for `/.env`, an
//! injection payload, the honeypot and a forged crawler are judged as
//! everywhere else, on these routes too. The routes are specific —
//! `/remote.php/`, not `/` — so a scanner gains nothing by them: it can
//! only go unnoticed while asking for things a scanner does not want.
//!
//! ## Which site a request was for
//!
//! The `Host` a JSON format logs, or any quoted field a combined-style
//! format appends after the user agent (`... "$http_user_agent" "$host"`),
//! when it names a site. A request whose host names no site — the
//! combined format logs none, and a bare-IP request names none — gets the
//! routes of every application on the server, since it could have reached
//! any of them. A request for a site with no recognised application gets
//! none.
//!
//! ## How an application is recognised
//!
//! From the site's own `server` blocks, by what they pass requests to
//! ([`recognise`]): an upstream or a document root named after the
//! application (`proxy_pass http://nextcloud:80`, `root
//! /var/www/nextcloud`), its default port (`127.0.0.1:8096`), or, for
//! Nextcloud, the `/remote.php/dav` its CalDAV and CardDAV redirects point
//! to. Read from the config each pass, so it follows the config without a
//! rescan; a file that cannot be read recognises nothing, which leaves the
//! detectors as they were.

/// An application whose own clients' requests [`Hosted`] allows for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Also ownCloud, which shares its routes.
    Nextcloud,
    /// Also Emby, which shares its routes and its default port.
    Jellyfin,
    Immich,
    Navidrome,
}

impl Service {
    /// In the order [`recognise`] tries them.
    pub const ALL: [Service; 4] = [
        Service::Nextcloud,
        Service::Jellyfin,
        Service::Immich,
        Service::Navidrome,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Service::Nextcloud => "Nextcloud",
            Service::Jellyfin => "Jellyfin",
            Service::Immich => "Immich",
            Service::Navidrome => "Navidrome",
        }
    }

    /// The path prefixes the application's own clients fetch its data
    /// from, where a 404 means an item went away rather than that someone
    /// is guessing. Compared ignoring case: Jellyfin's routes are
    /// case-insensitive, and its web client asks for `/videos/` where its
    /// apps ask for `/Videos/`.
    pub fn app_routes(self) -> &'static [&'static str] {
        match self {
            // WebDAV (files, versions, trash, calendars, contacts), public
            // shares' WebDAV, the OCS API the apps poll, and previews and
            // avatars, with and without `index.php`.
            Service::Nextcloud => &[
                "/remote.php/",
                "/public.php/",
                "/ocs/",
                "/index.php/core/preview",
                "/core/preview",
                "/index.php/avatar/",
                "/avatar/",
            ],
            // Items and their images, streams and HLS segments, people.
            Service::Jellyfin => &[
                "/Items/",
                "/Videos/",
                "/Audio/",
                "/Shows/",
                "/Users/",
                "/UserItems/",
                "/Persons/",
                "/Artists/",
            ],
            // Thumbnails and originals, faces, profile pictures.
            Service::Immich => &["/api/assets/", "/api/people/", "/api/users/"],
            // The Subsonic API, which is what every Navidrome app speaks.
            Service::Navidrome => &["/rest/"],
        }
    }

    /// Whether `path`, already normalised as NGINX normalises it, is on
    /// one of [`Self::app_routes`].
    fn routes(self, path: &str) -> bool {
        self.app_routes().iter().any(|route| {
            path.len() >= route.len()
                && path.as_bytes()[..route.len()].eq_ignore_ascii_case(route.as_bytes())
        })
    }

    /// Whether one directive's argument says this application answers.
    /// `passes` is whether the directive hands requests on — a `*_pass`,
    /// `root`, `alias` or `set` — rather than, say, a `location` or a
    /// `return`.
    fn named_by(self, passes: bool, argument: &str) -> bool {
        let argument = argument.to_ascii_lowercase();
        let (names, port): (&[&str], &str) = match self {
            Service::Nextcloud => {
                // The CalDAV and CardDAV discovery redirects every
                // Nextcloud config carries, wherever they appear.
                if argument.contains("/remote.php/dav") {
                    return true;
                }
                (&["nextcloud", "owncloud"], "")
            }
            Service::Jellyfin => (&["jellyfin", "emby"], ":8096"),
            Service::Immich => (&["immich"], ":2283"),
            Service::Navidrome => (&["navidrome"], ":4533"),
        };
        passes
            && (names.iter().any(|name| argument.contains(name))
                || (!port.is_empty() && has_port(&argument, port)))
    }
}

/// Whether `argument` has `port` (`:8096`) not followed by another digit.
fn has_port(argument: &str, port: &str) -> bool {
    argument.match_indices(port).any(|(at, _)| {
        !argument[at + port.len()..]
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_digit())
    })
}

/// The application a site's directives say answers it, if any. Each item
/// is a directive's name and its arguments, from every `server` block
/// that declares one of the site's names.
pub fn recognise(directives: &[(String, Vec<String>)]) -> Option<Service> {
    Service::ALL.into_iter().find(|service| {
        directives.iter().any(|(name, arguments)| {
            let passes =
                name.ends_with("_pass") || matches!(name.as_str(), "root" | "alias" | "set");
            arguments
                .iter()
                .any(|argument| service.named_by(passes, argument))
        })
    })
}

/// Every site on this server with the application behind it, if one was
/// recognised: what tells a client app's request from a scanner's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hosted {
    /// Each name a site answers to, compared ignoring case.
    sites: Vec<(String, Option<Service>)>,
}

impl Hosted {
    pub fn new(sites: Vec<(String, Option<Service>)>) -> Hosted {
        Hosted { sites }
    }

    /// Whether a request for `path` is one of an application's own
    /// clients' requests, given every host name the line carries.
    ///
    /// `path` is as logged; it is normalised here as NGINX normalises it
    /// before routing, so that `/remote.php/../.env`, which NGINX answers
    /// as `/.env`, is not taken for a WebDAV request.
    pub fn app_request<'a>(&self, hosts: impl IntoIterator<Item = &'a str>, path: &str) -> bool {
        if self.sites.iter().all(|(_, service)| service.is_none()) {
            return false;
        }
        let path = format!("/{}", crate::accesslog::path_segments(path).join("/"));
        let site = hosts.into_iter().find_map(|host| {
            let name = host_name(host);
            self.sites
                .iter()
                .find(|(site, _)| site.eq_ignore_ascii_case(name))
        });
        match site {
            Some((_, service)) => service.is_some_and(|service| service.routes(&path)),
            None => self
                .sites
                .iter()
                .filter_map(|(_, service)| *service)
                .any(|service| service.routes(&path)),
        }
    }
}

/// A `Host` value without its port or IPv6 brackets.
pub fn host_name(host: &str) -> &str {
    let name = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    name.trim_start_matches('[').trim_end_matches(']')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(name: &str, arguments: &[&str]) -> (String, Vec<String>) {
        (
            name.to_string(),
            arguments.iter().map(|a| a.to_string()).collect(),
        )
    }

    #[test]
    fn recognises_each_application_by_what_its_site_passes_requests_to() {
        let cases = [
            (
                directive("proxy_pass", &["http://nextcloud:80"]),
                Some(Service::Nextcloud),
            ),
            (
                directive("root", &["/var/www/nextcloud"]),
                Some(Service::Nextcloud),
            ),
            (
                directive("set", &["$upstream_app", "jellyfin"]),
                Some(Service::Jellyfin),
            ),
            (
                directive("proxy_pass", &["http://127.0.0.1:8096/"]),
                Some(Service::Jellyfin),
            ),
            (
                directive("proxy_pass", &["http://immich_server:2283"]),
                Some(Service::Immich),
            ),
            (
                directive("proxy_pass", &["http://navidrome:4533"]),
                Some(Service::Navidrome),
            ),
            (directive("proxy_pass", &["http://127.0.0.1:80960"]), None),
            (directive("proxy_pass", &["http://calibre-web:8083"]), None),
            (directive("proxy_pass", &["$ffca_enrollment"]), None),
        ];
        for (directive, expected) in cases {
            assert_eq!(
                recognise(std::slice::from_ref(&directive)),
                expected,
                "{directive:?}"
            );
        }
    }

    /// The redirects are `return`s and `rewrite`s, not passes, and still
    /// say Nextcloud wherever they are.
    #[test]
    fn recognises_nextcloud_by_its_dav_discovery_redirect() {
        let redirect = directive("return", &["301", "$scheme://$host/remote.php/dav"]);
        assert_eq!(recognise(&[redirect]), Some(Service::Nextcloud));
    }

    /// A `location` or a `return` that mentions a name is not what the
    /// site runs: a static site can link to Jellyfin.
    #[test]
    fn a_name_outside_a_pass_recognises_nothing() {
        let directives = [
            directive("location", &["/jellyfin/"]),
            directive("return", &["302", "https://immich.example.com"]),
        ];
        assert_eq!(recognise(&directives), None);
    }

    fn hosted() -> Hosted {
        Hosted::new(vec![
            ("cloud.example.com".to_string(), Some(Service::Nextcloud)),
            ("media.example.com".to_string(), Some(Service::Jellyfin)),
            ("blog.example.com".to_string(), None),
        ])
    }

    #[test]
    fn a_request_for_a_site_gets_only_that_sites_routes() {
        let cases = [
            ("cloud.example.com", "/remote.php/dav/files/a/b.jpg", true),
            ("CLOUD.example.com:443", "/index.php/core/preview", true),
            ("cloud.example.com", "/Items/abc/Images/Primary", false),
            ("media.example.com", "/videos/abc/hls1/main/0.ts", true),
            ("blog.example.com", "/remote.php/dav/files/a/b.jpg", false),
            ("cloud.example.com", "/wp-login.php", false),
        ];
        for (host, path, expected) in cases {
            assert_eq!(
                hosted().app_request([host], path),
                expected,
                "{host} {path}"
            );
        }
    }

    /// The combined format logs no host, and a bare-IP request names no
    /// site; either could have reached any application here.
    #[test]
    fn a_request_naming_no_site_gets_every_applications_routes() {
        for hosts in [vec![], vec!["203.0.113.1"]] {
            assert!(
                hosted().app_request(hosts.clone(), "/remote.php/dav/x"),
                "{hosts:?}"
            );
            assert!(
                hosted().app_request(hosts.clone(), "/Items/x/Images/Primary"),
                "{hosts:?}"
            );
            assert!(
                !hosted().app_request(hosts.clone(), "/rest/ping.view"),
                "{hosts:?}"
            );
        }
    }

    #[test]
    fn a_server_with_no_recognised_application_allows_nothing() {
        let hosted = Hosted::new(vec![("blog.example.com".to_string(), None)]);
        assert!(!hosted.app_request([], "/remote.php/dav/x"));
    }

    /// NGINX routes `/remote.php/../.env` as `/.env`.
    #[test]
    fn a_route_climbed_out_of_is_not_the_route() {
        let cases = [
            "/remote.php/../.env",
            "/remote.php/%2e%2e/wp-login.php",
            "/remote.php/dav/../../xmlrpc.php",
        ];
        for path in cases {
            assert!(
                !hosted().app_request(["cloud.example.com"], path),
                "{path} was taken for a WebDAV request"
            );
        }
    }
}
