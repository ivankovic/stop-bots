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

//! Password, sessions and CSRF for the web UI.
//!
//! **Why any of this exists on a loopback-only server.** "Bound to
//! 127.0.0.1" is not the same as "only reachable by the admin". Two ways
//! in that need no network access at all:
//!
//! - **Every local user.** A shared host, a CI runner, anything else on
//!   the box can open `http://127.0.0.1:8787/` the same as you can.
//! - **The admin's own browser.** A page on any origin can make requests
//!   to loopback. Same-origin policy stops it *reading* the response, but
//!   a plain form POST needs no response — and DNS rebinding removes even
//!   that limit by making a hostile name resolve to 127.0.0.1, at which
//!   point the attacker's page *is* same-origin with this server.
//!
//! So: a password, a session cookie the browser will only send back to
//! this origin, a CSRF token on every mutating request, and a `Host`
//! header allowlist. The last one is specifically the rebinding defence —
//! a rebound request arrives carrying the attacker's hostname, and this
//! server only answers to names it was told about.
//!
//! What this deliberately is *not*: a user system. There is one operator,
//! one password, no registration, no reset flow, no roles. Anyone who can
//! reach this UI can already rewrite the firewall, so a permission model
//! would be decoration.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::TryRngCore;
use subtle::ConstantTimeEq;

use crate::db::Db;

/// `settings` key holding the Argon2 PHC string. Only ever the hash — the
/// password itself is shown once, at the moment it is generated, and then
/// exists nowhere this program can reach.
pub const PASSWORD_HASH_KEY: &str = "web:password_hash";

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "stop_bots_session";

/// How long a session lasts without being used.
///
/// Eight hours rather than a token minute: this is an admin console, and
/// the realistic failure of a short expiry is someone leaving the page
/// open on a wall display and finding it logged out, not an attacker
/// waiting one out. Idle time, not absolute age — `Sessions::validate`
/// pushes it forward on every request.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// Bytes of randomness in a session id and in a CSRF token. 32 bytes is
/// well past what is guessable and costs nothing.
const TOKEN_BYTES: usize = 32;

/// One logged-in browser.
struct Session {
    /// This session's CSRF token. Per-session rather than per-form: a
    /// token is only useful to an attacker who can read it, and one who
    /// can read one form's token can read them all.
    csrf: String,
    /// When it was last used, for the idle timeout.
    last_seen: Instant,
}

/// Every live session, keyed by session id.
///
/// In memory, not in the database, and that is deliberate: restarting the
/// server logs everyone out. For a process that rewrites firewall rules,
/// "a restart invalidates access" is the safer default, and the cost is
/// one login.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, Session>>,
}

/// What a request proved about itself. Handlers take this rather than
/// checking a cookie themselves, so a new handler cannot forget to.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// The session's CSRF token, to embed in every form this response
    /// renders.
    pub csrf: String,
}

impl Sessions {
    /// Creates a session and returns `(session_id, csrf_token)`.
    pub fn create(&self) -> Result<(String, String)> {
        let id = random_token()?;
        let csrf = random_token()?;
        self.inner
            .lock()
            .expect("the session map is never held across a panic")
            .insert(
                id.clone(),
                Session {
                    csrf: csrf.clone(),
                    last_seen: Instant::now(),
                },
            );
        Ok((id, csrf))
    }

    /// Looks `id` up, refreshing its idle timer. `None` if it does not
    /// exist or has gone idle for too long.
    pub fn validate(&self, id: &str) -> Option<Authenticated> {
        let mut sessions = self
            .inner
            .lock()
            .expect("the session map is never held across a panic");

        // Sweep here rather than on a timer: sessions are few, this runs
        // on every request anyway, and a background task to expire a
        // handful of map entries is machinery for its own sake.
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.last_seen) < SESSION_IDLE_TIMEOUT);

        let session = sessions.get_mut(id)?;
        session.last_seen = now;
        Some(Authenticated {
            csrf: session.csrf.clone(),
        })
    }

    /// Drops a session, for logout.
    pub fn remove(&self, id: &str) {
        self.inner
            .lock()
            .expect("the session map is never held across a panic")
            .remove(id);
    }

    /// How many sessions are live. For tests and the UI's own status.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("the session map is never held across a panic")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Compares a submitted CSRF token against the session's, in constant
/// time.
///
/// `ct_eq` on equal-length slices only, so the length check comes first
/// and short-circuits — a length mismatch is not a secret, the bytes are.
pub fn csrf_matches(expected: &str, submitted: &str) -> bool {
    expected.len() == submitted.len() && expected.as_bytes().ct_eq(submitted.as_bytes()).into()
}

/// Hashes `password` with Argon2id and stores the PHC string in `db`.
pub fn set_password(db: &Db, password: &str) -> Result<()> {
    // The salt bytes come from `rand`'s OsRng and are encoded here, rather
    // than from `SaltString::generate`. argon2 0.5 is built on rand_core
    // 0.6, whose `OsRng` sits behind a feature this crate would otherwise
    // have to turn on just to reach a second path to the same system
    // entropy — and having one source of randomness in this file is worth
    // more than the two lines it saves.
    let mut salt_bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt_bytes)
        .context("the operating system refused to provide randomness")?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("failed to encode the salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash the password: {e}"))?
        .to_string();
    db.set_text_setting(PASSWORD_HASH_KEY, &hash)
        .context("failed to store the password hash")
}

/// Whether a password has been set at all. The web server refuses to bind
/// anything but loopback until it has.
pub fn password_is_set(db: &Db) -> Result<bool> {
    Ok(db.get_text_setting(PASSWORD_HASH_KEY)?.is_some())
}

/// Verifies `password` against the stored hash.
///
/// A missing hash verifies nothing — it returns `false` rather than
/// letting anyone in. The "no password set yet" case is handled at
/// startup, by generating one, not by leaving the door open.
pub fn verify_password(db: &Db, password: &str) -> Result<bool> {
    let Some(stored) = db.get_text_setting(PASSWORD_HASH_KEY)? else {
        return Ok(false);
    };
    let parsed = PasswordHash::new(&stored)
        .map_err(|e| anyhow::anyhow!("the stored password hash is unreadable: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// A fresh password to show the operator once, on first run.
///
/// Base64url of 18 random bytes: 144 bits, no characters that need
/// escaping in a shell, a URL or a copy-paste, and no ambiguity about
/// whether a character is a letter or a digit in the font someone reads it
/// in.
pub fn generate_password() -> Result<String> {
    let mut bytes = [0u8; 18];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system refused to provide randomness")?;
    Ok(base64url(&bytes))
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system refused to provide randomness")?;
    Ok(base64url(&bytes))
}

/// Base64url without padding, written out rather than pulled in.
///
/// `base64` is in the dependency tree already, but only as something
/// `reqwest` happens to use; depending on it directly for sixteen lines
/// would make a transitive dependency load-bearing for the security of
/// session tokens.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = |i: usize| *chunk.get(i).unwrap_or(&0) as u32;
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        // 3 bytes make 4 characters; a 1- or 2-byte tail makes 2 or 3.
        for i in 0..chunk.len() + 1 {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_hash() {
        let db = Db::open_in_memory().unwrap();
        set_password(&db, "correct horse battery staple").unwrap();

        assert!(verify_password(&db, "correct horse battery staple").unwrap());
        assert!(!verify_password(&db, "Correct horse battery staple").unwrap());
        assert!(!verify_password(&db, "").unwrap());
    }

    #[test]
    fn the_stored_hash_is_not_the_password() {
        let db = Db::open_in_memory().unwrap();
        set_password(&db, "hunter2").unwrap();

        let stored = db.get_text_setting(PASSWORD_HASH_KEY).unwrap().unwrap();
        assert!(
            !stored.contains("hunter2"),
            "the password must not survive anywhere in the stored value; it was: {stored}"
        );
        assert!(
            stored.starts_with("$argon2id$"),
            "expected an Argon2id PHC string, got: {stored}"
        );
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let db = Db::open_in_memory().unwrap();
        set_password(&db, "hunter2").unwrap();
        let first = db.get_text_setting(PASSWORD_HASH_KEY).unwrap().unwrap();
        set_password(&db, "hunter2").unwrap();
        let second = db.get_text_setting(PASSWORD_HASH_KEY).unwrap().unwrap();

        assert_ne!(
            first, second,
            "a per-hash salt is what stops two installs with the same password sharing a hash"
        );
    }

    #[test]
    fn verification_fails_closed_when_no_password_was_ever_set() {
        let db = Db::open_in_memory().unwrap();

        assert!(!password_is_set(&db).unwrap());
        assert!(
            !verify_password(&db, "").unwrap(),
            "an unset password must let nobody in, not everybody"
        );
        assert!(!verify_password(&db, "anything").unwrap());
    }

    #[test]
    fn a_created_session_validates_once_and_not_under_another_id() {
        let sessions = Sessions::default();
        let (id, csrf) = sessions.create().unwrap();

        let authenticated = sessions.validate(&id).expect("the session just created");
        assert_eq!(authenticated.csrf, csrf);
        assert!(sessions.validate("not-a-session-id").is_none());
    }

    #[test]
    fn a_removed_session_stops_validating() {
        let sessions = Sessions::default();
        let (id, _) = sessions.create().unwrap();
        sessions.remove(&id);

        assert!(
            sessions.validate(&id).is_none(),
            "logout has to actually end the session, not just clear the cookie"
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn two_sessions_get_distinct_ids_and_tokens() {
        let sessions = Sessions::default();
        let (first_id, first_csrf) = sessions.create().unwrap();
        let (second_id, second_csrf) = sessions.create().unwrap();

        assert_ne!(first_id, second_id);
        assert_ne!(first_csrf, second_csrf);
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn csrf_comparison_accepts_only_the_exact_token() {
        let token = "a-csrf-token";
        assert!(csrf_matches(token, token));
        assert!(
            !csrf_matches(token, "a-csrf-toke"),
            "a prefix is not a match"
        );
        assert!(!csrf_matches(token, "a-csrf-tokenn"));
        assert!(!csrf_matches(token, ""));
        assert!(!csrf_matches(token, "b-csrf-token"));
    }

    #[test]
    fn generated_passwords_are_long_and_never_repeat() {
        let first = generate_password().unwrap();
        let second = generate_password().unwrap();

        assert_ne!(first, second);
        assert_eq!(first.len(), 24, "18 bytes of base64url is 24 characters");
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "must survive a copy-paste through a shell and a URL: {first}"
        );
    }

    #[test]
    fn base64url_matches_known_vectors() {
        // RFC 4648 test vectors, in the URL-safe alphabet and unpadded.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), expected, "input was {input:?}");
        }
    }

    #[test]
    fn base64url_uses_the_url_safe_alphabet() {
        // 0xfb 0xff encodes to "+/" in standard base64 and must not here:
        // a session id lands in a Set-Cookie header and a CSRF token in an
        // HTML attribute.
        let encoded = base64url(&[0xfb, 0xff, 0xbf]);
        assert!(
            !encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='),
            "got: {encoded}"
        );
    }
}
