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

//! This machine's host name, for the headers of both surfaces.
//!
//! Read once and cached: a host does not rename itself while a console is
//! open, the TUI's header redraws thirty times a second, and the web
//! console builds its chrome on every request. Both used to read
//! `/proc` themselves, the console twice per page.

use std::sync::OnceLock;

static NAME: OnceLock<Option<String>> = OnceLock::new();

/// The host name as the kernel has it, or `None` when it cannot be read
/// — which is not an error anyone needs to hear about.
pub fn name() -> Option<&'static str> {
    NAME.get_or_init(|| {
        ["/proc/sys/kernel/hostname", "/etc/hostname"]
            .iter()
            .find_map(|path| std::fs::read_to_string(path).ok())
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
    })
    .as_deref()
}

/// Pins the name before it is first read. For the screenshot generator,
/// which must not put the maintainer's machine in the README; a no-op
/// once a header has been drawn.
pub fn override_name(name: &str) {
    let _ = NAME.set(Some(name.to_string()));
}
