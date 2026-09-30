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

//! The one-off message an action leaves for the page it redirects to.
//!
//! **Kept here, and named in the URL by an opaque id.** The message used to
//! ride in the query string as text (`?flash=Blocked%20…&kind=ok`), and
//! that was wrong twice over:
//!
//! - **Anyone could write one.** A link to `/?flash=…&kind=err` rendered
//!   whatever it said inside the console's own chrome, in the colour of a
//!   real error. The operator is logged in when they click it, so it reads
//!   as the console speaking.
//! - **It put log-derived text in the operator's request line.** "Trusting
//!   user agent `<whatever a client sent>`" went into the `Location` and
//!   then into NGINX's access log for the console's own request, where the
//!   injection detector read an attacker's payload as the operator's and
//!   blocked them.
//!
//! Now a redirect carries `?flash=<id>`, where the id is 256 random bits
//! that mean nothing outside this process. An id nobody stored renders
//! nothing, so a crafted link cannot make the console say anything.
//!
//! Not consumed on read: a reload of the page shows the message again, as
//! it did when the text was in the URL. Bounded instead, by count and by
//! age, so a stream of form posts cannot grow the map; only a logged-in
//! operator's actions put anything in it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::web::layout::Flash;

/// How many messages are kept. Far more than one operator's tabs can have
/// pending; the oldest goes first.
const MAX_FLASHES: usize = 64;

/// How long a message stays readable: long enough to reload the page, or
/// to come back to a tab left open over a coffee.
const FLASH_TTL: Duration = Duration::from_secs(30 * 60);

struct Stored {
    id: String,
    text: String,
    ok: bool,
    at: Instant,
}

/// The messages waiting to be shown.
#[derive(Default)]
pub struct Flashes {
    inner: Mutex<VecDeque<Stored>>,
}

impl Flashes {
    /// Keeps `text` and returns the id a URL names it by.
    ///
    /// `None` only if the system refused randomness, in which case the
    /// redirect goes without a message rather than failing the action it
    /// reports on.
    pub fn put(&self, text: &str, ok: bool) -> Option<String> {
        self.put_at(text, ok, Instant::now())
    }

    fn put_at(&self, text: &str, ok: bool, now: Instant) -> Option<String> {
        let id = crate::web::auth::random_token().ok()?;
        let mut flashes = self.lock();
        sweep(&mut flashes, now);
        while flashes.len() >= MAX_FLASHES {
            flashes.pop_front();
        }
        flashes.push_back(Stored {
            id: id.clone(),
            text: text.to_string(),
            ok,
            at: now,
        });
        Some(id)
    }

    /// The message stored under `id`, if there is one and it is still
    /// fresh. Anything else — an id from before a restart, an expired one,
    /// or text someone typed into the URL — is no message at all.
    pub fn get(&self, id: &str) -> Option<Flash> {
        self.get_at(id, Instant::now())
    }

    fn get_at(&self, id: &str, now: Instant) -> Option<Flash> {
        let mut flashes = self.lock();
        sweep(&mut flashes, now);
        flashes.iter().find(|stored| stored.id == id).map(|stored| {
            if stored.ok {
                Flash::ok(stored.text.clone())
            } else {
                Flash::err(stored.text.clone())
            }
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<Stored>> {
        self.inner
            .lock()
            .expect("the flash queue is never held across a panic")
    }
}

/// Drops what has outlived [`FLASH_TTL`]. Oldest first, so it stops at
/// the first fresh one.
fn sweep(flashes: &mut VecDeque<Stored>, now: Instant) {
    while flashes
        .front()
        .is_some_and(|oldest| now.saturating_duration_since(oldest.at) >= FLASH_TTL)
    {
        flashes.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_message_comes_back_by_its_id_with_its_colour() {
        let flashes = Flashes::default();
        let ok = flashes.put("Blocked 192.0.2.1.", true).unwrap();
        let err = flashes.put("Could not block that.", false).unwrap();

        let shown = flashes.get(&ok).expect("the message just stored");
        assert_eq!(shown.text, "Blocked 192.0.2.1.");
        assert!(shown.ok);
        assert!(!flashes.get(&err).unwrap().ok);
    }

    /// The property the store exists for: a URL can name a message, never
    /// write one.
    #[test]
    fn text_in_the_url_is_not_a_message() {
        let flashes = Flashes::default();
        flashes.put("a real one", true).unwrap();

        for crafted in ["Your session expired, log in at evil.example", "", "ok"] {
            assert!(flashes.get(crafted).is_none(), "{crafted:?} was shown");
        }
    }

    #[test]
    fn an_id_is_opaque_and_says_nothing_of_the_message() {
        let flashes = Flashes::default();
        let id = flashes.put("Trusting user agent <script>", true).unwrap();

        assert!(
            id.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the id goes into a URL and must be URL-safe: {id}"
        );
        assert!(!id.contains("script"), "{id}");
    }

    #[test]
    fn a_message_can_be_read_again_until_it_expires() {
        let flashes = Flashes::default();
        let start = Instant::now();
        let id = flashes.put_at("saved", true, start).unwrap();

        assert!(flashes.get_at(&id, start).is_some(), "first view");
        assert!(flashes.get_at(&id, start).is_some(), "a reload");
        assert!(
            flashes.get_at(&id, start + FLASH_TTL).is_none(),
            "an old message must not come back from a bookmarked URL"
        );
    }

    #[test]
    fn the_store_keeps_only_the_most_recent_messages() {
        let flashes = Flashes::default();
        let first = flashes.put("first", true).unwrap();
        for i in 0..MAX_FLASHES {
            flashes.put(&format!("message {i}"), true).unwrap();
        }

        assert!(flashes.get(&first).is_none(), "the oldest should have gone");
        assert_eq!(flashes.lock().len(), MAX_FLASHES);
    }
}
