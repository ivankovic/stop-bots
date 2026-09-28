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

//! stop-bots is a program, not a library. **There is no supported Rust API.**
//!
//! This library target exists so that `main.rs`, the integration tests in
//! `tests/` and `examples/screenshots.rs` can reach the program's internals.
//! Every module below is `pub` for them, and hidden from the documentation
//! because nothing in it is a promise: any of it can be renamed, changed or
//! removed in any release, patch releases included.
//!
//! What the project does keep stable, from 0.1 on, is the command line, the
//! database, the files it writes and the paths it uses. `RELEASING.md` says
//! what counts as breaking those. Use the `stop-bots` binary; depending on
//! this crate from other Rust code is not supported.

#[doc(hidden)]
pub mod accesslog;
#[doc(hidden)]
pub mod accessstats;
#[doc(hidden)]
pub mod app;
#[doc(hidden)]
pub mod batch;
#[doc(hidden)]
pub mod botlist;
#[doc(hidden)]
pub mod cron;
#[doc(hidden)]
pub mod db;
#[doc(hidden)]
pub mod dynamic;
#[doc(hidden)]
pub mod event;
#[doc(hidden)]
pub mod fetch;
#[doc(hidden)]
pub mod firewall;
#[cfg(test)]
mod golden;
#[doc(hidden)]
pub mod health;
#[doc(hidden)]
pub mod host;
#[doc(hidden)]
pub mod injection;
#[doc(hidden)]
pub mod install;
#[doc(hidden)]
pub mod ipdetail;
#[doc(hidden)]
pub mod ipranges;
#[doc(hidden)]
pub mod iptables;
#[doc(hidden)]
pub mod logpaths;
#[doc(hidden)]
pub mod nftables;
#[doc(hidden)]
pub mod nginx;
#[doc(hidden)]
pub mod protection;
#[doc(hidden)]
pub mod refresh;
#[doc(hidden)]
pub mod scanblock;
#[doc(hidden)]
pub mod sshlog;
#[cfg(test)]
mod testing;
#[doc(hidden)]
pub mod tui;
#[doc(hidden)]
pub mod uadetail;
#[doc(hidden)]
pub mod web;
#[doc(hidden)]
pub mod webaccess;
