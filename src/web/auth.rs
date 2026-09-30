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
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use rand::TryRng;
use subtle::ConstantTimeEq;

use crate::db::Db;

/// `settings` key holding the Argon2 PHC string. Only ever the hash — the
/// password itself is shown once, at the moment it is generated, and then
/// exists nowhere this program can reach.
pub const PASSWORD_HASH_KEY: &str = crate::db::keys::WEB_PASSWORD_HASH;

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "stop_bots_session";

/// Name of the cookie that marks a browser this console has seen log in.
/// See [`LoginKey::Remembered`].
pub const REMEMBER_COOKIE: &str = "stop_bots_remember";

/// How long a remembered browser stays remembered without logging in
/// again: ninety days, refreshed by every login.
pub const REMEMBER_MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// How many remembered browsers are kept, most recently used first. A
/// handful of the operator's own browsers; an eviction only means that
/// browser waits its turn with everyone else until it logs in again.
const REMEMBERED_BROWSERS_KEPT: usize = 32;

/// How long a session lasts without being used.
///
/// Eight hours rather than a token minute: this is an admin console, and
/// the realistic failure of a short expiry is someone leaving the page
/// open on a wall display and finding it logged out, not an attacker
/// waiting one out. Idle time — `Sessions::validate` pushes it forward on
/// every request, which is why [`SESSION_MAX_AGE`] exists as well.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 60 * 60);

/// How long a session lasts however busy it is.
///
/// The idle timeout alone slides forever: a session used once every few
/// hours — or a stolen cookie replayed on a timer — never ends. Twelve
/// hours is a working day with room to spare, so the operator logs in
/// about once a day and a leaked cookie is worth half of one.
const SESSION_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

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
    /// When it was created, for [`SESSION_MAX_AGE`].
    created: Instant,
    /// The stored password hash this session logged in under.
    ///
    /// Sessions live in this process's memory, but the password is changed
    /// by another one — `stop-bots web --set-password` only rewrites the
    /// hash in the database. Binding each session to the hash it was
    /// created under is what lets that rotation end them: a new password
    /// is a new salt and so a new hash, and every older session stops
    /// matching. The hash rather than a separate generation counter
    /// because it is already the thing that changes, and there is no
    /// second setting to forget to bump.
    credential: String,
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
    /// Creates a session bound to `credential` — the stored password hash
    /// the login was just verified against — and returns
    /// `(session_id, csrf_token)`.
    pub fn create(&self, credential: &str) -> Result<(String, String)> {
        let id = random_token()?;
        let csrf = random_token()?;
        let now = Instant::now();
        self.inner
            .lock()
            .expect("the session map is never held across a panic")
            .insert(
                id.clone(),
                Session {
                    csrf: csrf.clone(),
                    last_seen: now,
                    created: now,
                    credential: credential.to_string(),
                },
            );
        Ok((id, csrf))
    }

    /// Looks `id` up, refreshing its idle timer. `None` if it does not
    /// exist, has gone idle for too long, has outlived
    /// [`SESSION_MAX_AGE`], or was created under a password hash other
    /// than `credential` — the one stored now, read by the caller. `None`
    /// for `credential` means no password is stored, and nothing
    /// validates.
    pub fn validate(&self, id: &str, credential: Option<&str>) -> Option<Authenticated> {
        self.validate_at(id, credential, Instant::now())
    }

    /// [`Self::validate`] at a given moment, so the timeouts can be tested
    /// without sleeping through them.
    fn validate_at(
        &self,
        id: &str,
        credential: Option<&str>,
        now: Instant,
    ) -> Option<Authenticated> {
        let mut sessions = self
            .inner
            .lock()
            .expect("the session map is never held across a panic");

        // Sweep here rather than on a timer: sessions are few, this runs
        // on every request anyway, and a background task to expire a
        // handful of map entries is machinery for its own sake.
        sessions.retain(|_, s| {
            now.saturating_duration_since(s.last_seen) < SESSION_IDLE_TIMEOUT
                && now.saturating_duration_since(s.created) < SESSION_MAX_AGE
        });

        let session = sessions.get_mut(id)?;
        // Not a secret comparison: both sides are the stored hash, which
        // the requester never sees. Dropped rather than just refused, so
        // a session from before a rotation cannot come back.
        if credential != Some(session.credential.as_str()) {
            sessions.remove(id);
            return None;
        }
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
    /// The same, for a remembered browser's own limit: smaller, because a
    /// browser that has the password saved rarely needs more than one try.
    pub remembered_free_attempts: u32,
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
            remembered_free_attempts: 5,
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

/// Who a login attempt is counted against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginKey {
    /// A browser that presented a valid remembered-browser token: one this
    /// console has seen log in, within [`REMEMBER_MAX_AGE`]. Keyed by the
    /// token's digest.
    ///
    /// **Exempt from the per-address backoff and from the global bucket**,
    /// with a small limit of its own instead. This is what keeps the
    /// operator's own browser in, whatever an attacker does to the shared
    /// limits: without it, one attacker posting a wrong password each time
    /// `Retry-After` lapsed — about two requests a minute — held a shared
    /// key at the thirty-second ceiling, and the operator got 0 of 40
    /// logins through with the right password. The exemption costs little:
    /// a token is only minted by a correct password, at most
    /// [`REMEMBERED_BROWSERS_KEPT`] are valid at once, and each is limited.
    Remembered(String),
    /// A client this server can tell apart: its address, with IPv6 taken
    /// as its /64 (see [`client_key`]). Per-client backoff and the global
    /// bucket.
    Client(String),
    /// Everyone this server cannot tell apart: no address at all, or the
    /// local proxy's address when the console is proxied and
    /// `web:trust_forwarded_for` is off. The global bucket only.
    ///
    /// **No per-key backoff, on purpose.** A key everyone shares is a
    /// global limit in disguise, and a far harsher one than the bucket:
    /// the backoff let one wrong password every thirty seconds refuse
    /// every login on the key, the operator's included. The bucket already
    /// caps the Argon2 work anyone can cause, and to keep the operator out
    /// through it an attacker has to spend its whole refill, two
    /// verifications a second, sustained. The operator's own browser is
    /// past both once remembered.
    Shared,
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
///   attempts" the operator sees. IPv6 clients are keyed by /64.
///
/// **The honest cost, and what bounds it.** Any limiter on an
/// unauthenticated endpoint lets a flood deny the legitimate user; that is
/// inherent, not a flaw in this one. It used to be worse than it had to
/// be: clients that could not be told apart shared one backoff key, and
/// one wrong password every thirty seconds held that key at the ceiling —
/// measured, the operator got 0 of 40 logins through with the right
/// password against about two attacker requests a minute.
///
/// Four things bound it now (see [`LoginKey`]):
///
/// - **A remembered browser skips both limits.** A successful login sets a
///   90-day cookie; a login presenting it has only a small limit of its
///   own, so the operator's own browser always gets to try its password.
/// - **A shared key has no backoff**, only the global bucket, which an
///   attacker must drain at two verifications a second, sustained, to
///   keep a new browser out.
/// - **Behind a proxy, `web:trust_forwarded_for`** lets this tell clients
///   apart at all. The Web Access panel turns it on for the proxy it
///   writes, and the health report warns when a proxied console has it
///   off.
/// - The TUI and the CLI on the host are untouched by any of this, so the
///   operator is never actually shut out of their own server.
pub struct LoginThrottle {
    config: ThrottleConfig,
    state: Mutex<ThrottleState>,
}

#[derive(Debug)]
struct ThrottleState {
    clients: HashMap<String, Failures>,
    /// Remembered browsers' own failures, apart from `clients` so that
    /// neither can evict or collide with the other.
    remembered: HashMap<String, Failures>,
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
                remembered: HashMap::new(),
                tokens: config.burst,
                last_refill: Instant::now(),
            }),
            config,
        }
    }

    /// Whether to attempt a verification for `key` at all. See
    /// [`LoginKey`] for which limits each kind of key is held to.
    pub fn check_login(&self, key: &LoginKey) -> Result<(), Throttled> {
        match key {
            LoginKey::Remembered(token) => self.check_remembered(token),
            LoginKey::Client(client) => self.check(client),
            LoginKey::Shared => self.check_global(),
        }
    }

    /// Records a wrong password against `key`.
    pub fn record_login_failure(&self, key: &LoginKey) {
        match key {
            LoginKey::Remembered(token) => self.record_remembered(token, false),
            LoginKey::Client(client) => self.record_failure(client),
            // Nothing to push out: see `LoginKey::Shared`.
            LoginKey::Shared => {}
        }
    }

    /// Records the right password for `key`, ending its backoff.
    pub fn record_login_success(&self, key: &LoginKey) {
        match key {
            LoginKey::Remembered(token) => self.record_remembered(token, true),
            LoginKey::Client(client) => self.record_success(client),
            LoginKey::Shared => {}
        }
    }

    /// Whether to attempt a verification for the client `key`: its own
    /// backoff, then the global bucket.
    ///
    /// `Ok(())` consumes a token — an accepted attempt costs one whether
    /// or not the password turns out to be right, because the cost being
    /// rationed is the hash, not the failure.
    pub fn check(&self, key: &str) -> Result<(), Throttled> {
        let now = Instant::now();
        let mut state = self.lock();
        self.sweep(&mut state, now);

        if let Some(throttled) = still_waiting(state.clients.get(key), now) {
            return Err(throttled);
        }
        self.take_token(&mut state)
    }

    /// The global bucket alone, for [`LoginKey::Shared`].
    fn check_global(&self) -> Result<(), Throttled> {
        let now = Instant::now();
        let mut state = self.lock();
        self.sweep(&mut state, now);
        self.take_token(&mut state)
    }

    /// A remembered browser's own backoff alone, for
    /// [`LoginKey::Remembered`]: no global token is taken or needed.
    fn check_remembered(&self, token: &str) -> Result<(), Throttled> {
        let now = Instant::now();
        let mut state = self.lock();
        self.sweep(&mut state, now);
        match still_waiting(state.remembered.get(token), now) {
            Some(throttled) => Err(throttled),
            None => Ok(()),
        }
    }

    fn record_remembered(&self, token: &str, succeeded: bool) {
        let now = Instant::now();
        let mut state = self.lock();
        if succeeded {
            state.remembered.remove(token);
            return;
        }
        // Bounded by the tokens that can be valid at once, but capped
        // anyway rather than trusting that from here.
        if state.remembered.len() >= self.config.max_clients
            && !state.remembered.contains_key(token)
        {
            evict_oldest(&mut state.remembered);
        }
        let entry = state
            .remembered
            .entry(token.to_string())
            .or_insert(Failures {
                consecutive: 0,
                next_allowed: now,
                last_seen: now,
            });
        entry.consecutive = entry.consecutive.saturating_add(1);
        entry.last_seen = now;
        entry.next_allowed = now
            + backoff(
                entry.consecutive,
                self.config.remembered_free_attempts,
                self.config.base_delay,
                self.config.max_delay,
            );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ThrottleState> {
        self.state
            .lock()
            .expect("the throttle map is never held across a panic")
    }

    /// Refills the bucket for the time since the last call, and forgets
    /// clients idle past the TTL.
    fn sweep(&self, state: &mut ThrottleState, now: Instant) {
        let elapsed = now.saturating_duration_since(state.last_refill);
        state.tokens = (state.tokens + elapsed.as_secs_f64() * self.config.refill_per_second)
            .min(self.config.burst);
        state.last_refill = now;

        let ttl = self.config.client_ttl;
        state
            .clients
            .retain(|_, f| now.saturating_duration_since(f.last_seen) < ttl);
        state
            .remembered
            .retain(|_, f| now.saturating_duration_since(f.last_seen) < ttl);
    }

    fn take_token(&self, state: &mut ThrottleState) -> Result<(), Throttled> {
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
            evict_oldest(&mut state.clients);
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

/// The refusal a key's own backoff makes, if it is still running.
fn still_waiting(failures: Option<&Failures>, now: Instant) -> Option<Throttled> {
    let failures = failures?;
    (failures.next_allowed > now).then(|| Throttled {
        retry_after: failures.next_allowed.saturating_duration_since(now),
        message: TOO_MANY,
    })
}

fn evict_oldest(map: &mut HashMap<String, Failures>) {
    if let Some(oldest) = map
        .iter()
        .min_by_key(|(_, f)| f.last_seen)
        .map(|(k, _)| k.clone())
    {
        map.remove(&oldest);
    }
}

/// The throttle key for a client at `ip`.
///
/// An IPv4 address is its own key. An IPv6 address is keyed by its /64:
/// a single host is routinely handed a whole /64, and SLAAC and privacy
/// extensions let it pick a fresh address in it for every request, so a
/// per-address key would give one attacker 2^64 fresh backoffs.
pub fn client_key(ip: std::net::IpAddr) -> String {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            let network = u128::from(v6) & !((1u128 << 64) - 1);
            format!("{}/64", std::net::Ipv6Addr::from(network))
        }
    }
}

/// The digest a remembered-browser token is stored and throttled under.
/// The token itself lives only in the browser's cookie, the way the
/// password lives only in the operator's head: a copy of the database is
/// not a way past the throttle.
pub fn remember_token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `token` is a browser this console remembers, as of `now`
/// (Unix seconds).
pub fn is_remembered(db: &Db, token: &str, now: i64) -> Result<bool> {
    if token.is_empty() || token.len() > 128 {
        return Ok(false);
    }
    db.is_remembered_browser(
        &remember_token_hash(token),
        now - REMEMBER_MAX_AGE.as_secs() as i64,
    )
}

/// Remembers the browser that just logged in, returning the token its
/// cookie should carry: `existing` if it presented a valid one, which is
/// refreshed, or a new one.
pub fn remember_browser(db: &Db, existing: Option<&str>, now: i64) -> Result<String> {
    let token = match existing {
        Some(token) => token.to_string(),
        None => random_token()?,
    };
    db.remember_browser(&remember_token_hash(&token), now, REMEMBERED_BROWSERS_KEPT)?;
    Ok(token)
}

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
    // The salt bytes come from this file's own `SysRng` rather than from
    // `hash_password`, which would generate its own. Both end at the same
    // system entropy, but every other secret here — session ids, CSRF
    // tokens, the generated password — is drawn the same way, and one
    // source of randomness in this file is worth more than the two lines
    // it saves.
    //
    // 16 raw bytes: the length `password_hash` recommends, and comfortably
    // inside the 8..=48 a PHC salt may occupy. Base64 encoding happens
    // inside the hasher now; it used to be done here, against a
    // `SaltString`.
    let mut salt_bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut salt_bytes)
        .context("the operating system refused to provide randomness")?;
    let hash = Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &salt_bytes)
        .map_err(|e| anyhow::anyhow!("failed to hash the password: {e}"))?
        .to_string();
    db.set_text_setting(PASSWORD_HASH_KEY, &hash)
        .context("failed to store the password hash")?;
    // A new password is a fresh start: no browser from before it keeps
    // its way past the throttle, including one whose owner the password
    // was rotated to shut out.
    db.forget_remembered_browsers()?;
    Ok(())
}

/// The stored password hash, which is what a session is bound to (see
/// [`Sessions::validate`]). `None` if no password has been set.
pub fn current_credential(db: &Db) -> Result<Option<String>> {
    db.get_text_setting(PASSWORD_HASH_KEY)
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
    verify_against(&stored, password)
}

/// Verifies `password` against `stored`, a PHC string already read.
///
/// No `Db`, so that the ~50 ms of Argon2 can run where the database is not
/// locked: the console reads the hash, lets go, and verifies on the
/// blocking pool. Verifying inside the lock stalled every other request
/// for the length of each attempt.
pub fn verify_against(stored: &str, password: &str) -> Result<bool> {
    let parsed = PasswordHash::new(stored)
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
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system refused to provide randomness")?;
    Ok(base64url(&bytes))
}

/// 256 random bits, base64url: a session id, a CSRF token, a flash id.
pub(crate) fn random_token() -> Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::SysRng
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
            remembered_free_attempts: 1,
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

    /// The attack this exists for: the shared key held at its ceiling, and
    /// the global bucket drained. A remembered browser gets to try anyway.
    #[test]
    fn a_remembered_browser_is_let_through_whatever_the_shared_limits_say() {
        let throttle = LoginThrottle::new(ThrottleConfig {
            burst: 2.0,
            refill_per_second: 0.0001,
            ..fast_config()
        });
        for _ in 0..10 {
            let _ = throttle.check_login(&LoginKey::Client("attacker".into()));
            throttle.record_login_failure(&LoginKey::Client("attacker".into()));
        }
        assert!(throttle.check_login(&LoginKey::Shared).is_err(), "drained");

        assert!(
            throttle
                .check_login(&LoginKey::Remembered("operator".into()))
                .is_ok(),
            "the operator's own browser must not wait on an attacker"
        );
    }

    /// Exempt from the shared limits is not unlimited: a remembered token
    /// someone got hold of still backs off on its own.
    #[test]
    fn a_remembered_browser_has_a_small_limit_of_its_own() {
        let throttle = fast_throttle();
        let key = LoginKey::Remembered("token-digest".into());
        for _ in 0..3 {
            let _ = throttle.check_login(&key);
            throttle.record_login_failure(&key);
        }
        assert!(throttle.check_login(&key).is_err());
        assert!(
            throttle
                .check_login(&LoginKey::Remembered("another".into()))
                .is_ok(),
            "one browser's typos are its own"
        );

        throttle.record_login_success(&key);
        assert!(throttle.check_login(&key).is_ok());
    }

    /// A key everyone shares had the backoff too, and one wrong password
    /// every thirty seconds kept every login on it refused. It has only
    /// the global bucket now.
    #[test]
    fn failures_on_the_shared_key_impose_no_backoff() {
        let throttle = fast_throttle();
        for attempt in 0..3 {
            assert!(
                throttle.check_login(&LoginKey::Shared).is_ok(),
                "attempt {attempt}"
            );
            throttle.record_login_failure(&LoginKey::Shared);
        }
        assert_eq!(throttle.tracked(), 0, "nothing is tracked for it");
    }

    /// A host is routinely handed a whole /64, and may use a fresh address
    /// in it for every request.
    #[test]
    fn an_ipv6_client_is_keyed_by_its_64() {
        let key = |text: &str| client_key(text.parse().unwrap());

        assert_eq!(key("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(key("2001:db8:1:2:ffff:1:2:3"), "2001:db8:1:2::/64");
        assert_ne!(key("2001:db8:1:3::1"), key("2001:db8:1:2::1"));
        assert_eq!(key("203.0.113.5"), "203.0.113.5");
        assert_eq!(key("::ffff:203.0.113.5"), "203.0.113.5");
    }

    #[test]
    fn a_browser_is_remembered_by_a_token_whose_digest_alone_is_stored() {
        let db = Db::open_in_memory().unwrap();
        let token = remember_browser(&db, None, 1_000).unwrap();

        assert!(is_remembered(&db, &token, 1_000).unwrap());
        assert!(!is_remembered(&db, "a-made-up-token", 1_000).unwrap());
        assert!(!is_remembered(&db, "", 1_000).unwrap());
        let later = 1_000 + REMEMBER_MAX_AGE.as_secs() as i64 + 1;
        assert!(
            !is_remembered(&db, &token, later).unwrap(),
            "unused for longer than the cookie lives"
        );

        let fresh = remember_browser(&db, None, 2_000).unwrap();
        assert!(db
            .is_remembered_browser(&remember_token_hash(&fresh), 0)
            .unwrap());
        assert!(
            !db.is_remembered_browser(&fresh, 0).unwrap(),
            "the token itself was stored"
        );
    }

    #[test]
    fn logging_in_again_keeps_the_same_token_and_its_life() {
        let db = Db::open_in_memory().unwrap();
        let token = remember_browser(&db, None, 1_000).unwrap();
        let later = 1_000 + REMEMBER_MAX_AGE.as_secs() as i64 - 10;

        assert_eq!(remember_browser(&db, Some(&token), later).unwrap(), token);
        assert!(is_remembered(&db, &token, later + 100).unwrap());
    }

    /// A new password is a fresh start: no browser from before it keeps
    /// its way past the throttle.
    #[test]
    fn setting_a_password_forgets_every_remembered_browser() {
        let db = Db::open_in_memory().unwrap();
        let token = remember_browser(&db, None, 1_000).unwrap();

        set_password(&db, "a new one").unwrap();

        assert!(!is_remembered(&db, &token, 1_000).unwrap());
    }

    fn fast_config() -> ThrottleConfig {
        ThrottleConfig {
            free_attempts: 2,
            remembered_free_attempts: 1,
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

    /// A hash written by an older build must still let its owner in.
    ///
    /// The string below was produced by `argon2` 0.5 — the version 0.0.1
    /// shipped with — and is frozen here deliberately. Every other test in
    /// this file hashes and verifies with the same code in the same
    /// process, so all of them would keep passing on the day an upgrade
    /// quietly stopped reading what is already in operators' databases.
    /// The failure that would cause is not a red test; it is an operator
    /// locked out of the console that manages their firewall, discovered
    /// after they deployed.
    ///
    /// Regenerate it only against the version that wrote it, never by
    /// pasting what the current code emits — a fixture the current code
    /// produced tests nothing.
    #[test]
    fn a_hash_written_by_the_previous_argon2_still_verifies() {
        const ARGON2_0_5_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
             P7iCYXZZ42l48eJFg3PGMQ$IzzZ5yaG88g7mVKFAqzMqWxkjYVHHb34BYwSp4IsZuo";
        const PASSWORD: &str = "correct horse battery staple";

        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(PASSWORD_HASH_KEY, ARGON2_0_5_HASH)
            .unwrap();

        assert!(
            verify_password(&db, PASSWORD).unwrap(),
            "a password hashed by argon2 0.5 no longer verifies; upgrading would \
             lock every existing operator out of their own console"
        );
        assert!(
            !verify_password(&db, "not the password").unwrap(),
            "the wrong password was accepted against the frozen hash"
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

    /// What a session is bound to: the stored password hash it was
    /// created under. Any string will do for tests of the map itself.
    const CREDENTIAL: Option<&str> = Some("hash-at-login");

    fn session_under(sessions: &Sessions) -> (String, String) {
        sessions.create(CREDENTIAL.unwrap()).unwrap()
    }

    #[test]
    fn a_created_session_validates_once_and_not_under_another_id() {
        let sessions = Sessions::default();
        let (id, csrf) = session_under(&sessions);

        let authenticated = sessions
            .validate(&id, CREDENTIAL)
            .expect("the session just created");
        assert_eq!(authenticated.csrf, csrf);
        assert!(sessions.validate("not-a-session-id", CREDENTIAL).is_none());
    }

    #[test]
    fn a_removed_session_stops_validating() {
        let sessions = Sessions::default();
        let (id, _) = session_under(&sessions);
        sessions.remove(&id);

        assert!(
            sessions.validate(&id, CREDENTIAL).is_none(),
            "logout has to actually end the session, not just clear the cookie"
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn two_sessions_get_distinct_ids_and_tokens() {
        let sessions = Sessions::default();
        let (first_id, first_csrf) = session_under(&sessions);
        let (second_id, second_csrf) = session_under(&sessions);

        assert_ne!(first_id, second_id);
        assert_ne!(first_csrf, second_csrf);
        assert_eq!(sessions.len(), 2);
    }

    /// `stop-bots web --set-password` is another process: all it can
    /// change is the stored hash. A session from before it — including
    /// one somebody stole, which is the usual reason to rotate — has to
    /// stop working on its next request.
    #[test]
    fn a_new_password_ends_every_session_from_before_it() {
        let sessions = Sessions::default();
        let (id, _) = session_under(&sessions);

        assert!(sessions
            .validate(&id, Some("hash-after-rotation"))
            .is_none());
        assert!(
            sessions.validate(&id, CREDENTIAL).is_none(),
            "a rejected session is dropped, not merely refused this once"
        );
    }

    #[test]
    fn with_no_password_stored_no_session_validates() {
        let sessions = Sessions::default();
        let (id, _) = session_under(&sessions);

        assert!(sessions.validate(&id, None).is_none());
    }

    #[test]
    fn a_session_in_steady_use_still_ends_at_its_absolute_lifetime() {
        let sessions = Sessions::default();
        let (id, _) = session_under(&sessions);
        let start = Instant::now();

        // Used every hour, so the idle timeout never fires.
        for hour in 1..SESSION_MAX_AGE.as_secs() / 3600 {
            let at = start + Duration::from_secs(hour * 3600);
            assert!(
                sessions.validate_at(&id, CREDENTIAL, at).is_some(),
                "a session in use for {hour}h should still be valid"
            );
        }
        let past = start + SESSION_MAX_AGE + Duration::from_secs(60);
        assert!(
            sessions.validate_at(&id, CREDENTIAL, past).is_none(),
            "the idle timer slides; the absolute lifetime must not"
        );
    }

    #[test]
    fn an_idle_session_still_expires_on_the_idle_timeout() {
        let sessions = Sessions::default();
        let (id, _) = session_under(&sessions);
        let later = Instant::now() + SESSION_IDLE_TIMEOUT + Duration::from_secs(1);

        assert!(sessions.validate_at(&id, CREDENTIAL, later).is_none());
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
