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

//! The web UI: a third front-end over the same core as the TUI and the CLI.
//!
//! Nothing in here knows how to block a bot. `nginx`, `firewall`,
//! `scanblock`, `protection` and `cron` already carry every decision this
//! project makes, because the CLI and the TUI both needed them; this module
//! renders them and routes form posts back into them.
//!
//! # Threading
//!
//! `Db` wraps a `rusqlite::Connection`, which is `Send` but not `Sync`, so
//! it cannot be shared across concurrent handlers as it stands. The rule
//! here is the same one `app.rs` follows for the TUI's event loop, for the
//! same reason: **all database work happens inside `spawn_blocking`, and
//! the mutex guard never crosses an `.await`.** [`state::AppState::with_db`]
//! is the only way to reach a `Db` and enforces both.
//!
//! A pool would be the other answer, and is the wrong one here: SQLite
//! serialises writes anyway, and a second connection buys contention
//! handling for a workload that is one operator clicking buttons.
//!
//! # Exposure
//!
//! Loopback by default. Binding anywhere else is opt-in and refuses to
//! start until a password is set, because the intended deployment for that
//! case — behind the very NGINX this tool is protecting — puts the console
//! on the public internet.
//!
//! See [`auth`] for why the loopback default still gets a password, a CSRF
//! token and a `Host` allowlist rather than none of the three.

pub mod auth;
pub mod bots;
pub mod dashboard;
pub mod dynamic;
pub mod help;
pub mod layout;
pub mod server;
pub mod sites;
pub mod state;

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};

/// `settings` key for the address the server binds.
pub const BIND_KEY: &str = "web:bind";

/// Loopback, on a port unlikely to collide with anything an admin already
/// runs. Not 8080.
pub const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// `settings` key for whether the session cookie carries `Secure`.
///
/// Off by default because the default deployment is plain HTTP on
/// loopback, where a `Secure` cookie is simply never stored and the
/// console would appear to reject a correct password. Turn it on for the
/// deployment the README describes — behind NGINX with TLS — where without
/// it a browser will happily send the session to an `http://` URL for the
/// same host.
pub const SECURE_COOKIE_KEY: &str = "web:secure_cookie";

/// `settings` key for whether `X-Forwarded-For` may be believed.
///
/// Off by default, and that default matters. A forwarded header is
/// client-supplied text; believing it unconditionally would let anyone
/// claim to be any address, which in this program's case means claiming to
/// be the address they are about to block and so switching off the
/// anti-lockout guard from outside. Turn it on only when this server is
/// genuinely behind a proxy that overwrites the header.
pub const TRUST_FORWARDED_KEY: &str = "web:trust_forwarded_for";

/// `settings` key for the persisted form of `--expose`.
pub const EXPOSE_KEY: &str = "web:expose";

/// `settings` key for the extra `Host` values this server will answer to,
/// comma-separated. See [`allowed_host`].
pub const ALLOWED_HOSTS_KEY: &str = "web:allowed_hosts";

/// Whether `addr` is a loopback address.
///
/// The distinction the whole exposure policy turns on: a loopback bind is
/// reachable only from this machine, anything else is reachable from the
/// network the moment a firewall lets it through.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Resolves the bind address: the `--bind` flag, else the stored setting,
/// else [`DEFAULT_BIND`].
pub fn resolve_bind(db: &crate::db::Db, flag: Option<&str>) -> Result<SocketAddr> {
    let stored = db.get_text_setting(BIND_KEY)?;
    let raw = flag.or(stored.as_deref()).unwrap_or(DEFAULT_BIND);
    raw.parse()
        .with_context(|| format!("`{raw}` is not a valid `address:port`"))
}

/// Whether this server should answer a request carrying `host`.
///
/// The DNS-rebinding defence. An attacker's page cannot change the `Host`
/// header the browser sends, so a request that arrives claiming to be for
/// `evil.example` is one that reached us by having that name resolve to
/// our address — exactly the rebinding attack — and gets refused before
/// any handler runs.
///
/// Loopback names are always allowed, because that is the default
/// deployment and requiring configuration for it would mean everyone's
/// first experience is a rejection. Anything else has to be listed, which
/// is the price of putting this on a hostname.
pub fn allowed_host(host: &str, configured: &[String]) -> bool {
    // A `Host` carries an optional port, and the port is not part of the
    // identity being checked — `localhost:8787` and `localhost` are the
    // same name. IPv6 literals are bracketed, so split from the right and
    // only when the tail is numeric.
    let name = match host.rsplit_once(':') {
        Some((head, port)) if !head.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => head,
        _ => host,
    };
    let name = name.trim_start_matches('[').trim_end_matches(']');

    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = name.parse::<IpAddr>() {
        if ip.is_loopback() {
            return true;
        }
    }
    configured.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// The `Host` values configured beyond the loopback ones.
pub fn configured_hosts(db: &crate::db::Db) -> Result<Vec<String>> {
    Ok(db
        .get_text_setting(ALLOWED_HOSTS_KEY)?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_recognised_in_both_families() {
        for addr in ["127.0.0.1:8787", "127.0.0.53:80", "[::1]:8787"] {
            assert!(is_loopback(&addr.parse().unwrap()), "{addr} is loopback");
        }
        for addr in ["0.0.0.0:8787", "192.168.1.10:8787", "[::]:8787"] {
            assert!(
                !is_loopback(&addr.parse().unwrap()),
                "{addr} is not loopback"
            );
        }
    }

    #[test]
    fn the_bind_address_falls_back_from_flag_to_setting_to_default() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            resolve_bind(&db, None).unwrap().to_string(),
            DEFAULT_BIND,
            "a fresh install binds loopback without being told to"
        );

        db.set_text_setting(BIND_KEY, "0.0.0.0:9000").unwrap();
        assert_eq!(resolve_bind(&db, None).unwrap().to_string(), "0.0.0.0:9000");

        assert_eq!(
            resolve_bind(&db, Some("127.0.0.1:1234"))
                .unwrap()
                .to_string(),
            "127.0.0.1:1234",
            "the flag wins over the stored setting for one run"
        );
    }

    #[test]
    fn an_unparsable_bind_address_names_itself_in_the_error() {
        let db = Db::open_in_memory().unwrap();
        let err = resolve_bind(&db, Some("8787")).unwrap_err();
        assert!(err.to_string().contains("8787"), "error was: {err}");
    }

    #[test]
    fn loopback_hosts_are_allowed_without_configuration() {
        for host in [
            "localhost",
            "localhost:8787",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.1:8787",
            "[::1]:8787",
        ] {
            assert!(allowed_host(host, &[]), "{host} must be allowed by default");
        }
    }

    #[test]
    fn an_unlisted_host_is_refused() {
        // The rebinding case: the request really did arrive here, but it
        // arrived under a name we were never told to answer to.
        for host in ["evil.example", "evil.example:8787", "192.168.1.10"] {
            assert!(!allowed_host(host, &[]), "{host} must be refused");
        }
    }

    #[test]
    fn a_configured_host_is_allowed_with_or_without_a_port() {
        let configured = vec!["admin.example.com".to_string()];
        assert!(allowed_host("admin.example.com", &configured));
        assert!(allowed_host("admin.example.com:443", &configured));
        assert!(
            allowed_host("ADMIN.EXAMPLE.COM", &configured),
            "host names are case-insensitive"
        );
        assert!(!allowed_host("other.example.com", &configured));
    }

    #[test]
    fn a_port_is_only_stripped_when_it_is_actually_a_port() {
        // `evil.example:not-a-port` must not be read as the host
        // `evil.example`; nor may a bare name containing a colon be
        // truncated into one that happens to be allowed.
        let configured = vec!["admin.example.com".to_string()];
        assert!(!allowed_host("admin.example.com:evil", &configured));
    }

    #[test]
    fn configured_hosts_are_split_and_trimmed() {
        let db = Db::open_in_memory().unwrap();
        assert!(configured_hosts(&db).unwrap().is_empty());

        db.set_text_setting(
            ALLOWED_HOSTS_KEY,
            " admin.example.com , stop-bots.internal ,, ",
        )
        .unwrap();
        assert_eq!(
            configured_hosts(&db).unwrap(),
            ["admin.example.com", "stop-bots.internal"],
            "blank entries from a trailing comma must not become an allowed empty host"
        );
    }

    use crate::db::Db;
}
