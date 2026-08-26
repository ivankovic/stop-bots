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

//! Shared fixtures for unit tests (only compiled for tests — see
//! `lib.rs`), for the two setups that were being hand-written in eight and
//! eleven files respectively.
//!
//! **The bar for adding something here is that the call site reads better,
//! not that it is shorter.** `block("10.0.0.1")` beats an eight-line struct
//! literal because it *says* "a rule blocking this address" — the reader
//! learns the intent without decoding five fields that were `None`,
//! `true`, `None` in every single case. A helper whose name doesn't carry
//! its meaning makes a test worse, because now you have to look it up.
//!
//! By the same rule, some duplication deliberately stays put:
//!
//! - The `NewBot` literals in `botlist/*`'s parser tests are the *expected
//!   parse result* being asserted. A builder there would hide the thing
//!   under test.
//! - `tests/cli.rs` and `tests/tui.rs` are integration tests and cannot see
//!   a `#[cfg(test)]` module at all. Their own local helpers are the right
//!   answer, and they already have them.
//!
//! Builders take `&Db` and mutate rather than returning one: a helper that
//! hands back a database hides which database the test is actually using.

use crate::db::{BotStatus, Db, FirewallAction, FirewallRule, NewBot, Source};

/// A `FirewallRule` blocking `address`, with every other field at the
/// value it has in almost every test: no port, enabled, no expiry.
pub(crate) fn block(address: &str) -> FirewallRule {
    rule(address, FirewallAction::Block)
}

/// A `FirewallRule` allowing `address`. The counterpart to [`block`] —
/// spelled out separately rather than as `rule(addr, Allow)` because
/// allow-vs-block is the single most important fact about a rule, and a
/// reader shouldn't have to parse an argument to find it.
pub(crate) fn allow(address: &str) -> FirewallRule {
    rule(address, FirewallAction::Allow)
}

/// For the few tests that genuinely vary the action, e.g. by looping over
/// both.
pub(crate) fn rule(address: &str, action: FirewallAction) -> FirewallRule {
    FirewallRule {
        // Zero rather than a running counter: no code path looks a rule up
        // by id, and a meaningless-but-distinct number in a test invites
        // the reader to hunt for significance it doesn't have.
        id: 0,
        address: address.to_string(),
        port: None,
        action,
        enabled: true,
        expires_at: None,
    }
}

/// A rule restricted to a single TCP port.
pub(crate) fn block_port(address: &str, port: u16) -> FirewallRule {
    FirewallRule {
        port: Some(port),
        ..block(address)
    }
}

/// A rule that exists but is switched off — renderers must skip it.
pub(crate) fn disabled(address: &str) -> FirewallRule {
    FirewallRule {
        enabled: false,
        ..block(address)
    }
}

/// Registers a bot list source in `db`. Bots are foreign-keyed to one, so
/// anything that stores a bot needs this first; the source itself is
/// almost never what a test is about.
pub(crate) fn seed_source(db: &Db, id: &str) {
    db.upsert_source(&Source {
        id: id.to_string(),
        name: id.to_string(),
        url: format!("https://example.invalid/{id}.json"),
        last_fetched_at: None,
        bot_count: 0,
    })
    .expect("failed to seed a bot-list source");
}

/// A minimal [`NewBot`], for tests that only need *a* bot to exist.
///
/// Separate from [`blocked_bot`]: that one seeds a source and pins the
/// bot's status, which is what a test about applying NGINX config wants.
/// This is the plain value, for callers that hand it to something which
/// does the storing itself.
pub(crate) fn new_bot(slug: &str, source_id: &str) -> NewBot {
    NewBot {
        slug: slug.to_string(),
        name: slug.to_string(),
        is_ai: false,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: format!("{slug}-ua"),
        source_id: source_id.to_string(),
    }
}

/// A bot pinned to Blocked, matching `pattern` — the "there is something
/// to block" setup, previously ~20 lines of `upsert_source` +
/// `upsert_bot` + `set_bot_status` in eleven places.
///
/// Pinned per-bot rather than via a category default on purpose: it makes
/// the bot blocked regardless of what the test does to category settings,
/// so a test about applying NGINX config can't be quietly changed into a
/// test about the category cascade.
pub(crate) fn blocked_bot(db: &Db, slug: &str, pattern: &str) {
    seed_source(db, "test-source");
    db.upsert_bot(&NewBot {
        slug: slug.to_string(),
        name: slug.to_string(),
        is_ai: false,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: pattern.to_string(),
        source_id: "test-source".to_string(),
    })
    .expect("failed to seed a bot");
    db.set_bot_status(slug, BotStatus::Blocked)
        .expect("failed to pin the seeded bot to Blocked");
}
