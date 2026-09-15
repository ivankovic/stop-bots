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

pub mod accesslog;
pub mod accessstats;
pub mod app;
pub mod batch;
pub mod botlist;
pub mod cron;
pub mod db;
pub mod dynamic;
pub mod event;
pub mod fetch;
pub mod firewall;
#[cfg(test)]
mod golden;
pub mod health;
pub mod host;
pub mod install;
pub mod ipdetail;
pub mod ipranges;
pub mod iptables;
pub mod nftables;
pub mod nginx;
pub mod protection;
pub mod refresh;
pub mod scanblock;
pub mod sshlog;
#[cfg(test)]
mod testing;
pub mod tui;
pub mod uadetail;
pub mod web;
pub mod webaccess;
