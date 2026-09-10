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

/// How long a client is made to wait, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Throttled {
    pub retry_after: Duration,
    /// What to tell the operator. Deliberately the same wording whether
    /// the global cap or this client's own backoff is what refused: which
    /// one it was tells a guesser how close they are to the limit.
    pub message: &'static str,
}

/// Tunables, so tests can exercise the backoff without sleeping for real
/// seconds. Production uses [`ThrottleConfig::default`].
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Failures allowed before any delay is imposed. A fat-fingered
    /// paste should not cost the operator a wait.
    pub free_attempts: u32,
    /// The delay after the first attempt past `free_attempts`; it doubles
    /// with each further failure.
    pub base_delay: Duration,
    /// Ceiling on that doubling. Without one, an attacker could push the
    /// legitimate operator's next attempt hours out.
    pub max_delay: Duration,
    /// Verifications the server will do in a burst.
    pub burst: f64,
    /// Sustained verifications per second once the burst is spent.
    pub refill_per_second: f64,
    /// A client with no failures for this long is forgotten.
    pub client_ttl: Duration,
    /// Cap on tracked clients, so cycling source addresses cannot grow
    /// this map without bound.
    pub max_clients: usize,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            // Generous, because the cost of being wrong here lands on the
            // operator and the benefit is small: the password is always
            // generated and 144 bits wide, so nothing in this range makes
            // guessing more or less hopeless than it already is.
            free_attempts: 10,
            base_delay: Duration::from_secs(1),
            // Thirty seconds, not minutes. The ceiling exists for the
            // operator's sake, not the attacker's — see the note on
            // `LoginThrottle` about sharing a bucket behind a proxy.
            max_delay: Duration::from_secs(30),
            // ~2 verifications a second sustained is ~10% of one core
            // spent on Argon2, which is the number that actually matters:
            // it is the cap on what an unauthenticated caller can make
            // this host do.
            burst: 20.0,
            refill_per_second: 2.0,
            client_ttl: Duration::from_secs(60 * 60),
            max_clients: 1024,
        }
    }
}

#[derive(Debug)]
struct Failures {
    consecutive: u32,
    next_allowed: Instant,
    last_seen: Instant,
}

/// Throttling for the login endpoint.
///
/// **What this is actually defending.** The password is always generated
/// — `--set-password` offers no way to choose a weak one — so 144 bits of
/// entropy makes online guessing hopeless on its own. The exposure worth
/// closing is different: verifying a password runs Argon2id at OWASP
/// defaults, ~50ms of CPU and 19MB of memory, and until now anyone who
/// could reach `/login` could make the server do that as fast as they
/// could post. That is an amplification DoS against the host this tool is
/// supposed to be protecting.
///
/// So the order matters: **a refusal here happens before any hashing**,
/// and costs a map lookup.
///
/// Two limits, because they answer different attacks:
///
/// - **A global token bucket** caps the CPU an unauthenticated caller can
///   provoke. It is global on purpose — a per-client limit is bypassed by
///   rotating source addresses, and this server frequently cannot tell
///   clients apart anyway (behind a proxy every request arrives from
///   127.0.0.1 unless `X-Forwarded-For` is trusted).
/// - **Per-client exponential backoff** punishes a persistent guesser
///   that *can* be identified, and is what produces the "too many
///   attempts" the operator sees.
///
/// **The honest cost, and what to do about it.** Any limiter on an
/// unauthenticated endpoint lets a flood deny the legitimate user; that is
/// inherent, not a flaw in this one. Where clients cannot be told apart
/// they share a bucket, so a sustained attack delays the operator's own
/// login by up to `max_delay` too.
///
/// Three things bound that. The ceiling is thirty seconds rather than
/// hours. The TUI and the CLI on the host are untouched by any of this,
/// so the operator is never actually shut out of their own server. And —
/// the one worth acting on — **behind a proxy, `web:trust_forwarded_for`
/// is what lets this tell clients apart at all**: without it every request
/// arrives from 127.0.0.1 and the attacker shares the operator's bucket;
/// with it the attacker gets their own and the operator is unaffected.
pub struct LoginThrottle {
    config: ThrottleConfig,
    state: Mutex<ThrottleState>,
}

#[derive(Debug)]
struct ThrottleState {
    clients: HashMap<String, Failures>,
    tokens: f64,
    last_refill: Instant,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new(ThrottleConfig::default())
    }
}

impl LoginThrottle {
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            state: Mutex::new(ThrottleState {
                clients: HashMap::new(),
                tokens: config.burst,
                last_refill: Instant::now(),
            }),
            config,
        }
    }

    /// Whether to attempt a verification for `key` at all.
    ///
    /// `Ok(())` consumes a token — an accepted attempt costs one whether
    /// or not the password turns out to be right, because the cost being
    /// rationed is the hash, not the failure.
    pub fn check(&self, key: &str) -> Result<(), Throttled> {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("the throttle map is never held across a panic");

        let elapsed = now.saturating_duration_since(state.last_refill);
        state.tokens = (state.tokens + elapsed.as_secs_f64() * self.config.refill_per_second)
            .min(self.config.burst);
        state.last_refill = now;

        state
            .clients
            .retain(|_, f| now.saturating_duration_since(f.last_seen) < self.config.client_ttl);

        if let Some(failures) = state.clients.get(key) {
            if failures.next_allowed > now {
                return Err(Throttled {
                    retry_after: failures.next_allowed.saturating_duration_since(now),
                    message: TOO_MANY,
                });
            }
        }

        if state.tokens < 1.0 {
            // How long until one token is back.
            let deficit = 1.0 - state.tokens;
            return Err(Throttled {
                retry_after: Duration::from_secs_f64(
                    (deficit / self.config.refill_per_second).max(0.001),
                ),
                message: TOO_MANY,
            });
        }

        state.tokens -= 1.0;
        Ok(())
    }

    /// Records that `key` got the password wrong, and pushes its next
    /// permitted attempt out.
    pub fn record_failure(&self, key: &str) {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("the throttle map is never held across a panic");

        // Evict the least recently seen rather than let an address-cycling
        // attacker grow this map without bound. Cheap because the cap is
        // small and this only runs when it is reached.
        if state.clients.len() >= self.config.max_clients && !state.clients.contains_key(key) {
            if let Some(oldest) = state
                .clients
                .iter()
                .min_by_key(|(_, f)| f.last_seen)
                .map(|(k, _)| k.clone())
            {
                state.clients.remove(&oldest);
            }
        }

        let free = self.config.free_attempts;
        let base = self.config.base_delay;
        let max = self.config.max_delay;
        let entry = state.clients.entry(key.to_string()).or_insert(Failures {
            consecutive: 0,
            next_allowed: now,
            last_seen: now,
        });
        entry.consecutive = entry.consecutive.saturating_add(1);
        entry.last_seen = now;
        entry.next_allowed = now + backoff(entry.consecutive, free, base, max);
    }

    /// Clears `key`'s history. The right password ends the punishment.
    pub fn record_success(&self, key: &str) {
        self.state
            .lock()
            .expect("the throttle map is never held across a panic")
            .clients
            .remove(key);
    }

    /// How many clients are being tracked. For tests.
    pub fn tracked(&self) -> usize {
        self.state
            .lock()
            .expect("the throttle map is never held across a panic")
            .clients
            .len()
    }
}

/// One message for every refusal: which limit tripped would tell a guesser
/// how close they are to it.
const TOO_MANY: &str = "Too many login attempts. Wait a moment and try again.";

/// The delay after `consecutive` failures.
///
/// Doubling from `base` once the free attempts are spent, capped at `max`.
/// Saturating rather than shifting: at 40 consecutive failures a naive
/// `1 << n` overflows, and the answer there is "the cap", not a panic.
fn backoff(consecutive: u32, free: u32, base: Duration, max: Duration) -> Duration {
    if consecutive <= free {
        return Duration::ZERO;
    }
    let steps = consecutive - free - 1;
    let multiplier = 1u64.checked_shl(steps.min(32)).unwrap_or(u64::MAX);
    base.checked_mul(multiplier.min(u32::MAX as u64) as u32)
        .unwrap_or(max)
        .min(max)
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

    /// Short delays so the backoff can be exercised for real rather than
    /// simulated. These are the production semantics on a compressed
    /// clock — the same trick the project uses elsewhere (an in-memory
    /// SQLite is still SQLite).
    fn fast_throttle() -> LoginThrottle {
        LoginThrottle::new(ThrottleConfig {
            free_attempts: 2,
            base_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(80),
            burst: 4.0,
            refill_per_second: 1000.0,
            client_ttl: Duration::from_millis(50),
            max_clients: 4,
        })
    }

    #[test]
    fn the_first_few_attempts_are_not_delayed() {
        let throttle = fast_throttle();
        for attempt in 0..2 {
            assert!(
                throttle.check("a").is_ok(),
                "attempt {attempt} should not be throttled: a typo must not cost a wait"
            );
            throttle.record_failure("a");
        }
    }

    #[test]
    fn failures_past_the_free_ones_impose_a_growing_delay() {
        let throttle = fast_throttle();
        for _ in 0..3 {
            let _ = throttle.check("a");
            throttle.record_failure("a");
        }

        let first = throttle.check("a").unwrap_err();
        std::thread::sleep(first.retry_after + Duration::from_millis(5));

        assert!(throttle.check("a").is_ok(), "the wait should have expired");
        throttle.record_failure("a");
        let second = throttle.check("a").unwrap_err();

        assert!(
            second.retry_after > first.retry_after,
            "the delay should grow: {:?} then {:?}",
            first.retry_after,
            second.retry_after
        );
    }

    #[test]
    fn the_delay_is_capped() {
        let config = ThrottleConfig {
            free_attempts: 1,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            ..ThrottleConfig::default()
        };
        // Far past the point where a naive `1 << n` would overflow.
        for consecutive in [10, 40, 1_000, u32::MAX] {
            let delay = backoff(
                consecutive,
                config.free_attempts,
                config.base_delay,
                config.max_delay,
            );
            assert_eq!(
                delay, config.max_delay,
                "{consecutive} failures must give the ceiling, not an overflow"
            );
        }
    }

    #[test]
    fn the_right_password_clears_the_backoff() {
        let throttle = fast_throttle();
        for _ in 0..4 {
            let _ = throttle.check("a");
            throttle.record_failure("a");
        }
        assert!(throttle.check("a").is_err());

        throttle.record_success("a");
        assert!(
            throttle.check("a").is_ok(),
            "a burst of typos must not keep costing the operator once they get it right"
        );
    }

    #[test]
    fn one_clients_failures_do_not_delay_another() {
        let throttle = fast_throttle();
        for _ in 0..4 {
            let _ = throttle.check("noisy");
            throttle.record_failure("noisy");
        }
        assert!(throttle.check("noisy").is_err());
        assert!(
            throttle.check("quiet").is_ok(),
            "an identifiable attacker must not lock out everyone else"
        );
    }

    #[test]
    fn the_global_bucket_caps_work_no_client_key_can_dodge() {
        // The property a per-client limit cannot give: rotating the source
        // address does not buy more hashing.
        let throttle = LoginThrottle::new(ThrottleConfig {
            burst: 3.0,
            refill_per_second: 0.0001,
            ..fast_config()
        });

        for i in 0..3 {
            assert!(throttle.check(&format!("client-{i}")).is_ok(), "burst {i}");
        }
        assert!(
            throttle.check("client-99").is_err(),
            "a fresh address must not refill the global bucket"
        );
    }

    #[test]
    fn a_throttled_caller_is_told_how_long_to_wait() {
        let throttle = LoginThrottle::new(ThrottleConfig {
            burst: 1.0,
            refill_per_second: 1.0,
            ..fast_config()
        });
        assert!(throttle.check("a").is_ok());

        let throttled = throttle.check("a").unwrap_err();
        assert!(
            throttled.retry_after > Duration::ZERO,
            "a Retry-After of zero tells the caller nothing"
        );
    }

    #[test]
    fn every_refusal_reads_the_same() {
        // Which limit tripped would tell a guesser how close they are to
        // it, so both say the same thing.
        let throttle = LoginThrottle::new(ThrottleConfig {
            burst: 1.0,
            refill_per_second: 0.0001,
            ..fast_config()
        });
        let _ = throttle.check("a");
        let global = throttle.check("b").unwrap_err();

        let backoff_throttle = fast_throttle();
        for _ in 0..4 {
            let _ = backoff_throttle.check("a");
            backoff_throttle.record_failure("a");
        }
        let per_client = backoff_throttle.check("a").unwrap_err();

        assert_eq!(global.message, per_client.message);
    }

    #[test]
    fn stale_clients_are_forgotten() {
        let throttle = fast_throttle();
        throttle.record_failure("a");
        assert_eq!(throttle.tracked(), 1);

        std::thread::sleep(Duration::from_millis(60));
        // `check` is what sweeps; it does not itself record anything, so
        // afterwards the map should hold nothing at all.
        let _ = throttle.check("b");

        assert_eq!(
            throttle.tracked(),
            0,
            "an entry idle past the TTL should have been swept"
        );
    }

    #[test]
    fn the_client_map_cannot_be_grown_without_bound() {
        // An attacker cycling source addresses would otherwise turn this
        // into a memory leak with a network interface in front of it.
        let throttle = fast_throttle();
        for i in 0..50 {
            throttle.record_failure(&format!("client-{i}"));
        }
        assert!(
            throttle.tracked() <= 4,
            "tracked {} clients, cap is 4",
            throttle.tracked()
        );
    }

    fn fast_config() -> ThrottleConfig {
        ThrottleConfig {
            free_attempts: 2,
            base_delay: Duration::from_millis(20),
            max_delay: Duration::from_millis(80),
            burst: 4.0,
            refill_per_second: 1000.0,
            client_ttl: Duration::from_millis(50),
            max_clients: 4,
        }
    }

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
