/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
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
//!
//! "Stored" means the host settings file ([`crate::hostconf`]), not the
//! database: the lockout guard runs as root on the SSH log named here, and
//! the web console can write every row of the database.

use std::path::{Path, PathBuf};

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
    /// The access log this run should read: the flag if given, else the
    /// stored path, else the module default.
    pub fn access_path(&self, flag: Option<&Path>) -> PathBuf {
        flag.or(self.access.as_deref())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(crate::accesslog::DEFAULT_LOG_PATH))
    }

    /// [`Self::access_path`], read whole. For the one-off CLI commands;
    /// everything that runs on a schedule reads incrementally instead (see
    /// [`crate::logscan`]).
    pub fn access_source(&self, flag: Option<&Path>) -> crate::accesslog::LogSource {
        crate::accesslog::read_log_file(&self.access_path(flag))
    }

    /// The SSH log this run should read, by the same precedence.
    ///
    /// Note the fallback differs from the access log's: with nothing stored
    /// and no flag, `sshlog` tries two paths and then journald, so
    /// "nothing configured" is a real strategy here rather than one guess.
    pub fn ssh(&self, flag: Option<&Path>) -> crate::sshlog::SshSource {
        match flag.or(self.ssh.as_deref()) {
            Some(path) => crate::sshlog::SshSource::File(path.to_path_buf()),
            None => crate::sshlog::SshSource::Search,
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

    /// The paths the host settings name, as every reader gets them.
    fn stored(access: Option<&str>, ssh: Option<&str>) -> LogPaths {
        crate::hostconf::HostConf {
            access_log: access.map(PathBuf::from),
            ssh_log: ssh.map(PathBuf::from),
            ..Default::default()
        }
        .log_paths()
    }

    #[test]
    fn nothing_stored_reads_as_nothing_configured() {
        assert_eq!(
            crate::hostconf::HostConf::default().log_paths(),
            LogPaths::default()
        );
    }

    /// Every reader of the SSH log goes through here, so a stored path
    /// reaches the lockout guard, the Firewall screens and the detectors
    /// alike, and a flag still beats it.
    #[test]
    fn the_ssh_log_is_the_flag_then_the_stored_path_then_a_search() {
        assert_eq!(
            stored(None, None).ssh(None),
            crate::sshlog::SshSource::Search
        );
        let paths = stored(None, Some("/srv/log/auth.log"));
        assert_eq!(
            paths.ssh(None),
            crate::sshlog::SshSource::File("/srv/log/auth.log".into())
        );
        assert_eq!(
            paths.ssh(Some(Path::new("/tmp/other.log"))),
            crate::sshlog::SshSource::File("/tmp/other.log".into())
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

        let paths = stored(log.to_str(), None);

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

        let paths = super::tests::stored(stored.to_str(), None);

        match paths.access_source(Some(&asked)) {
            crate::accesslog::LogSource::Found(text) => assert!(
                text.contains("/a"),
                "the flag should have won; text was: {text}"
            ),
            crate::accesslog::LogSource::Unavailable => panic!("the named file exists"),
        }
    }

    /// The health check's whole improvement: naming the file it tried.
    #[test]
    fn the_description_names_the_path_that_would_be_read() {
        let paths = stored(Some("/srv/domaci/nginx/logs/access.log"), None);

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
