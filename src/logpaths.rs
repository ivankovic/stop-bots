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

//! Where this host's logs actually are, remembered.
//!
//! The same problem [`crate::nginx::NginxCommands`] solves, for the other
//! half of a containerised NGINX. That type exists because `nginx -t` and
//! `systemctl reload nginx` are wrong when NGINX is in a container, so the
//! right commands are stored and every caller reads them from there.
//!
//! The logs move for exactly the same reason and were not stored. A
//! container that bind-mounts its log directory writes the access log
//! somewhere that is not `/var/log/nginx/access.log` on the host, and the
//! only way to say so was `--access-log` on each invocation. That works for
//! the CLI and for a crontab. It does not work for the two things that
//! actually run the detectors — the web console and the TUI — because their
//! internal cron takes no arguments. Their unit has an `--ssh-log` flag and
//! nothing for the access log at all.
//!
//! The visible result on such a host was a console running every minute,
//! finding nothing, and a health check that could only say "unreadable"
//! without being able to say which path it had tried. The documented
//! workaround was a symlink from `/var/log/nginx` into wherever the logs
//! really were — making the filesystem lie so that a default became true.
//!
//! ## Precedence
//!
//! Flag, then setting, then the built-in search. An explicit `--access-log`
//! still wins, because a one-off run against a copied or rotated file is a
//! real thing to want and must not need the stored value changed and put
//! back. The stored value is what the console and the internal cron get,
//! since they have no way to be passed a flag.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::db::Db;

/// The stored location of each log this project reads.
///
/// `None` for either field means "nothing stored" — fall back to the
/// module's own search, which is what a host with logs in the usual places
/// wants and what every host got before these were configurable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogPaths {
    /// The NGINX access log, feeding every web-side detector.
    pub access: Option<PathBuf>,
    /// The SSH authentication log, feeding the SSH scanner detector and —
    /// more importantly — the anti-lockout window.
    pub ssh: Option<PathBuf>,
}

impl LogPaths {
    /// `settings` keys. A `logs:` family, alongside `nginx:`.
    pub const ACCESS_KEY: &'static str = "logs:access_path";
    pub const SSH_KEY: &'static str = "logs:ssh_path";

    /// Reads both from `db`. A row that is present but empty reads as
    /// unset, so clearing one is `set-log-paths --access-log ""` rather
    /// than a second verb.
    pub fn from_db(db: &Db) -> Result<Self> {
        let stored = |key: &str| -> Result<Option<PathBuf>> {
            Ok(db
                .get_text_setting(key)?
                .map(|raw| raw.trim().to_string())
                .filter(|raw| !raw.is_empty())
                .map(PathBuf::from))
        };
        Ok(Self {
            access: stored(Self::ACCESS_KEY)?,
            ssh: stored(Self::SSH_KEY)?,
        })
    }

    /// Stores `access` and `ssh`, each `None` leaving that key untouched
    /// and each `Some("")` clearing it.
    pub fn save(db: &Db, access: Option<&str>, ssh: Option<&str>) -> Result<()> {
        for (key, value) in [(Self::ACCESS_KEY, access), (Self::SSH_KEY, ssh)] {
            if let Some(value) = value {
                db.set_text_setting(key, value.trim())?;
            }
        }
        Ok(())
    }

    /// The access log this run should read: the flag if given, else the
    /// stored path, else the module default.
    pub fn access_source(&self, flag: Option<&Path>) -> crate::accesslog::LogSource {
        match flag.or(self.access.as_deref()) {
            Some(path) => crate::accesslog::read_log_file(path),
            None => crate::accesslog::find_default_source(),
        }
    }

    /// The SSH log this run should read, by the same precedence.
    ///
    /// Note the fallback differs from the access log's: with nothing stored
    /// and no flag, `sshlog` tries two paths and then `journalctl`, so
    /// "nothing configured" is a real strategy here rather than one guess.
    pub fn ssh_source(&self, flag: Option<&Path>) -> crate::sshlog::LogSource {
        match flag.or(self.ssh.as_deref()) {
            Some(path) => crate::sshlog::read_log_file(path),
            None => crate::sshlog::find_default_source(),
        }
    }

    /// What to name in a report when the access log could not be read.
    ///
    /// "unreadable" on its own is the least useful thing a health check can
    /// say, because the operator's next question is always "which file did
    /// you try". Answering it is the difference between a warning that
    /// leads somewhere and one that gets muted.
    pub fn access_description(&self, flag: Option<&Path>) -> String {
        match flag.or(self.access.as_deref()) {
            Some(path) => path.display().to_string(),
            None => crate::accesslog::DEFAULT_LOG_PATH.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open_in_memory().unwrap()
    }

    #[test]
    fn nothing_stored_reads_as_nothing_configured() {
        assert_eq!(LogPaths::from_db(&db()).unwrap(), LogPaths::default());
    }

    #[test]
    fn a_stored_path_round_trips() {
        let db = db();
        LogPaths::save(&db, Some("/srv/domaci/nginx/logs/access.log"), None).unwrap();
        let paths = LogPaths::from_db(&db).unwrap();
        assert_eq!(
            paths.access.as_deref(),
            Some(Path::new("/srv/domaci/nginx/logs/access.log"))
        );
        assert_eq!(
            paths.ssh, None,
            "the ssh key was not named, so it is untouched"
        );
    }

    /// The containerised-NGINX case this exists for: the console has no way
    /// to be passed a flag, so the stored path has to be what it reads.
    #[test]
    fn a_stored_path_is_used_when_no_flag_is_given() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("access.log");
        std::fs::write(
            &log,
            "203.0.113.5 - - [x] \"GET / HTTP/1.1\" 200 1 \"-\" \"UA\"\n",
        )
        .unwrap();

        let db = db();
        LogPaths::save(&db, Some(log.to_str().unwrap()), None).unwrap();
        let paths = LogPaths::from_db(&db).unwrap();

        assert!(
            matches!(
                paths.access_source(None),
                crate::accesslog::LogSource::Found(_)
            ),
            "a stored path must be read when nothing was passed"
        );
    }

    /// And the flag still wins, so a one-off run against a rotated copy
    /// needs no change to the stored value and no change back.
    #[test]
    fn an_explicit_flag_beats_the_stored_path() {
        let dir = tempfile::tempdir().unwrap();
        let stored = dir.path().join("stored.log");
        let asked = dir.path().join("asked.log");
        std::fs::write(
            &stored,
            "1.1.1.1 - - [x] \"GET /s HTTP/1.1\" 200 1 \"-\" \"UA\"\n",
        )
        .unwrap();
        std::fs::write(
            &asked,
            "2.2.2.2 - - [x] \"GET /a HTTP/1.1\" 200 1 \"-\" \"UA\"\n",
        )
        .unwrap();

        let db = db();
        LogPaths::save(&db, Some(stored.to_str().unwrap()), None).unwrap();
        let paths = LogPaths::from_db(&db).unwrap();

        match paths.access_source(Some(&asked)) {
            crate::accesslog::LogSource::Found(text) => assert!(
                text.contains("/a"),
                "the flag should have won; text was: {text}"
            ),
            crate::accesslog::LogSource::Unavailable => panic!("the named file exists"),
        }
    }

    #[test]
    fn an_empty_value_clears_a_stored_path() {
        let db = db();
        LogPaths::save(&db, Some("/somewhere/access.log"), None).unwrap();
        LogPaths::save(&db, Some(""), None).unwrap();
        assert_eq!(LogPaths::from_db(&db).unwrap().access, None);
    }

    /// The health check's whole improvement: naming the file it tried.
    #[test]
    fn the_description_names_the_path_that_would_be_read() {
        let db = db();
        LogPaths::save(&db, Some("/srv/domaci/nginx/logs/access.log"), None).unwrap();
        let paths = LogPaths::from_db(&db).unwrap();

        assert_eq!(
            paths.access_description(None),
            "/srv/domaci/nginx/logs/access.log"
        );
        assert_eq!(
            LogPaths::default().access_description(None),
            crate::accesslog::DEFAULT_LOG_PATH,
            "with nothing stored it names the built-in default, not an empty string"
        );
    }
}
