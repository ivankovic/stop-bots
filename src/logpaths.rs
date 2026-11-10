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
//! The same problem [`crate::webserver::ServerCommands`] solves, for the other
//! half of a containerised NGINX. That type exists because `nginx -t` and
//! `systemctl reload nginx` are wrong when NGINX is in a container, so the
//! right commands are stored and every caller reads them from there.
//!
//! The logs move for exactly the same reason and were not stored. A
//! container that bind-mounts its log directory writes the access log
//! somewhere that is not `/var/log/nginx/access.log` on the host, and the
//! only way to say so was `--access-log` on each invocation. That works for
//! the CLI and for a crontab. It does not work for the things that run the
//! detectors on a schedule — the TUI, and `tick` from the cron file
//! `install cron` writes — because the schedule takes no arguments.
//!
//! The visible result on such a host was a schedule running every minute,
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
//! back. The stored value is what the TUI and `tick` get, since they have
//! no way to be passed a flag.
//!
//! "Stored" means the host settings file ([`crate::hostconf`]), not the
//! database: the lockout guard runs as root on the SSH log named here, and
//! the database is a file root does not always own (see
//! [`crate::hostconf`]).
//!
//! ## Several access logs
//!
//! A web server writes as many access logs as its config names: a site
//! with an `access_log` (NGINX) or `CustomLog` (Apache) of its own logs
//! there and nowhere else, so a detector reading only the main log never
//! saw its traffic. Every pass therefore reads the stored or default log
//! *and* each other file the config names ([`LogPaths::access_logs`]).
//!
//! The two ways of naming a log by hand do different things, on purpose:
//!
//! - **A stored path adds to them.** It replaces the default, as it always
//!   did, and the config's own logs are read beside it. Someone who stored
//!   where their main log is did not mean "and ignore every site that logs
//!   elsewhere", and a stored path is the only way the schedule is told
//!   anything, so it cannot also mean "only this".
//! - **A flag replaces them.** `--access-log` is for one run against one
//!   file — a copy, a rotated log, a test — and reading the live logs
//!   beside it, moving their cursors, would be the surprise. So a run with
//!   the flag reads exactly that file, as it did before there were several.
//!
//! The config's paths are only read when the web server runs on this host.
//! One in a container (a test command of its own, see `set-web-server
//! --test`) names paths inside the container, and a file of the same name
//! here is somebody else's; there, the stored path is what is read, as
//! [`crate::logscan::app_probes`] reads no document root for the same
//! reason.

use std::path::{Path, PathBuf};

/// Where one of the access logs a pass reads came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOrigin {
    /// `--access-log`, for this run only.
    Flag,
    /// `set-log-paths --access-log`.
    Stored,
    /// The web server's stock path, with nothing stored.
    Default,
    /// An `access_log` or `CustomLog` in the web server's config.
    Config,
}

impl LogOrigin {
    /// How `status --json` names it. Part of the contract, so never
    /// renamed.
    pub fn id(self) -> &'static str {
        match self {
            LogOrigin::Flag => "flag",
            LogOrigin::Stored => "stored",
            LogOrigin::Default => "default",
            LogOrigin::Config => "config",
        }
    }
}

/// One access log a pass reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLog {
    pub path: PathBuf,
    pub origin: LogOrigin,
}

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
    /// The kernel log, feeding the port-scan detector (see
    /// [`crate::portscan`]).
    pub kernel: Option<PathBuf>,
    /// The web server whose access log is read when none is stored.
    pub server: crate::webserver::WebServer,
    /// Its config root, which decides where that default is: Apache logs
    /// to `/var/log/httpd` in RHEL's tree, not Debian's `/var/log/apache2`.
    pub root: PathBuf,
    /// Whether the paths in the config under [`Self::root`] are paths on
    /// this host: false for a web server in a container. See the module
    /// docs. False unless the host settings say so, so that paths built
    /// by hand read only what they name.
    pub config_logs_here: bool,
}

impl LogPaths {
    /// The access log this run should read: the flag if given, else the
    /// stored path, else the module default.
    pub fn access_path(&self, flag: Option<&Path>) -> PathBuf {
        flag.or(self.access.as_deref())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(self.default_access_log()))
    }

    /// Where the access log is when nothing names it: the web server's
    /// stock path, for the layout its root is in.
    pub fn default_access_log(&self) -> &'static str {
        self.server.default_access_log_at(&self.root)
    }

    /// Every access log this run should read: the flag alone if given;
    /// else [`Self::access_path`] first, then each other file the web
    /// server's config names, when that config is this host's. See the
    /// module docs for why the two differ.
    ///
    /// A file is named once however many directives name it, and however
    /// it is spelled: a second name for the same file would read its lines
    /// twice, under two cursors.
    pub fn access_logs(&self, flag: Option<&Path>) -> Vec<AccessLog> {
        if let Some(flag) = flag {
            return vec![AccessLog {
                path: flag.to_path_buf(),
                origin: LogOrigin::Flag,
            }];
        }
        let mut logs = vec![AccessLog {
            path: self.access_path(None),
            origin: match self.access {
                Some(_) => LogOrigin::Stored,
                None => LogOrigin::Default,
            },
        }];
        for path in self.config_logs() {
            if !logs.iter().any(|log| same_file(&log.path, &path)) {
                logs.push(AccessLog {
                    path,
                    origin: LogOrigin::Config,
                });
            }
        }
        logs
    }

    /// [`Self::access_logs`] without those the config names that are not
    /// there: what a pass reads, and what `status` lists.
    ///
    /// The web server opens every log it is configured with when it
    /// starts, so one that does not exist belongs to a site it is not
    /// serving: a file in `sites-available` that is not enabled, say. It is
    /// read from its start once it appears. The stored or default log is
    /// kept whether or not it is there, and reported when it is not.
    pub fn access_logs_to_read(&self, flag: Option<&Path>) -> Vec<AccessLog> {
        self.access_logs(flag)
            .into_iter()
            .filter(|log| {
                log.origin != LogOrigin::Config
                    || !std::fs::symlink_metadata(&log.path)
                        .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
            })
            .collect()
    }

    /// The access logs the web server's config names, when it is this
    /// host's.
    fn config_logs(&self) -> Vec<PathBuf> {
        // Unit tests never read the host's own config: there, the root is
        // the stock one, and nothing points it elsewhere.
        let stock = cfg!(test) && self.root == Path::new(self.server.default_root());
        if !self.config_logs_here || stock {
            return Vec::new();
        }
        self.server.access_logs(&self.root)
    }

    /// [`Self::access_logs_to_read`], read whole, one after another. For
    /// the one-off CLI commands; everything that runs on a schedule reads
    /// incrementally instead (see [`crate::logscan`]). Unavailable only
    /// when none of them could be read.
    pub fn access_source(&self, flag: Option<&Path>) -> crate::accesslog::LogSource {
        let mut text: Option<String> = None;
        for log in self.access_logs_to_read(flag) {
            if let crate::accesslog::LogSource::Found(found) =
                crate::accesslog::read_log_file(&log.path)
            {
                let text = text.get_or_insert_with(String::new);
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&found);
            }
        }
        match text {
            Some(text) => crate::accesslog::LogSource::Found(text),
            None => crate::accesslog::LogSource::Unavailable,
        }
    }

    /// The SSH log this run should read, by the same precedence.
    ///
    /// Note the fallback differs from the access log's: with nothing stored
    /// and no flag, `sshlog` tries two paths and then journald, so
    /// "nothing configured" is a real strategy here rather than one guess.
    pub fn ssh(&self, flag: Option<&Path>) -> crate::sshlog::SshSource {
        match flag.or(self.ssh.as_deref()) {
            Some(path) if path == Path::new(crate::sshlog::JOURNAL_KEYWORD) => {
                crate::sshlog::SshSource::Journal
            }
            Some(path) => crate::sshlog::SshSource::File(path.to_path_buf()),
            None => crate::sshlog::SshSource::Search,
        }
    }

    /// The kernel log this run should read, by the same precedence, and
    /// with the same kind of search as the SSH log's: `kern.log`,
    /// `messages`, then the journal.
    pub fn kernel(&self, flag: Option<&Path>) -> crate::portscan::KernelSource {
        match flag.or(self.kernel.as_deref()) {
            Some(path) if path == Path::new(crate::sshlog::JOURNAL_KEYWORD) => {
                crate::sshlog::SshSource::Journal
            }
            Some(path) => crate::sshlog::SshSource::File(path.to_path_buf()),
            None => crate::sshlog::SshSource::Search,
        }
    }

    /// What to name in a report when the kernel log could not be read:
    /// the path given or stored, or what the search tries.
    pub fn kernel_description(&self, flag: Option<&Path>) -> String {
        match flag.or(self.kernel.as_deref()) {
            Some(path) => path.display().to_string(),
            None => format!(
                "{}, then the journal",
                crate::portscan::DEFAULT_KERNEL_LOG_PATHS.join(", ")
            ),
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
            None => self.default_access_log().to_string(),
        }
    }
}

/// Whether `a` and `b` name the same file: the same path, or, for two
/// that exist, the same inode. RHEL's Apache logs to `logs/access_log`
/// under its server root, a link to `/var/log/httpd`.
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if a == b {
        return true;
    }
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => (a.dev(), a.ino()) == (b.dev(), b.ino()),
        _ => false,
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
        let paths = crate::hostconf::HostConf::default().log_paths();
        assert_eq!((&paths.access, &paths.ssh), (&None, &None));
        assert_eq!(
            paths.access_path(None),
            PathBuf::from(crate::accesslog::DEFAULT_LOG_PATH),
            "the default is not NGINX's log"
        );
    }

    /// Every reader of the SSH log goes through here, so a stored path
    /// reaches the lockout guard, the Firewall screens and the detectors
    /// alike, and a flag still beats it.
    #[test]
    fn the_word_journal_in_place_of_a_path_is_the_journal_alone() {
        assert_eq!(
            stored(None, Some("journal")).ssh(None),
            crate::sshlog::SshSource::Journal
        );
        assert_eq!(
            stored(None, Some("/var/log/auth.log")).ssh(Some(Path::new("journal"))),
            crate::sshlog::SshSource::Journal
        );
    }

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

    /// The containerised-NGINX case this exists for: the schedule has no way
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

    /// An NGINX config root under `dir` with one site logging to
    /// `dir/site.log`, which exists, and host settings with `main.log`
    /// stored and that root.
    fn host_with_a_site_log(dir: &Path) -> crate::hostconf::HostConf {
        let root = dir.join("nginx");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("site.conf"),
            format!(
                "server {{ server_name a.example; access_log {}; }}\n",
                dir.join("site.log").display()
            ),
        )
        .unwrap();
        std::fs::write(dir.join("site.log"), "").unwrap();
        crate::hostconf::HostConf {
            nginx_root: Some(root),
            access_log: Some(dir.join("main.log")),
            ..Default::default()
        }
    }

    /// A stored path is read beside the logs the config names; a flag is
    /// read alone; and a server in a container has its config's paths
    /// left alone, since they are the container's.
    #[test]
    fn a_flag_reads_only_itself_and_a_stored_path_adds_the_config_s_logs() {
        let dir = tempfile::tempdir().unwrap();
        let (main, site, asked) = (
            dir.path().join("main.log"),
            dir.path().join("site.log"),
            dir.path().join("asked.log"),
        );
        let here = host_with_a_site_log(dir.path());
        let in_a_container = crate::hostconf::HostConf {
            nginx_test_command: Some("docker exec web nginx -t".to_string()),
            ..here.clone()
        };
        let cases = [
            (
                "stored, server here",
                &here,
                None,
                vec![(&main, LogOrigin::Stored), (&site, LogOrigin::Config)],
            ),
            (
                "a flag",
                &here,
                Some(asked.as_path()),
                vec![(&asked, LogOrigin::Flag)],
            ),
            (
                "stored, server in a container",
                &in_a_container,
                None,
                vec![(&main, LogOrigin::Stored)],
            ),
        ];
        for (case, host, flag, expected) in cases {
            let logs = host.log_paths().access_logs(flag);
            let logs: Vec<(&PathBuf, LogOrigin)> =
                logs.iter().map(|log| (&log.path, log.origin)).collect();
            assert_eq!(logs, expected, "{case}");
        }
    }

    /// The config naming the stored log again, by another name for the
    /// same file, does not make it two logs: its lines would be read
    /// twice, under two cursors.
    #[test]
    fn a_file_named_twice_is_one_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = host_with_a_site_log(dir.path());
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(dir.path().join("site.log"), &link).unwrap();
        host.access_log = Some(link.clone());

        let logs = host.log_paths().access_logs(None);

        assert_eq!(
            logs,
            [AccessLog {
                path: link,
                origin: LogOrigin::Stored
            }]
        );
    }

    /// A log the config names that is not there is a site the server is
    /// not serving, and is not read; the stored one is kept, to be
    /// reported, whether or not it is there.
    #[test]
    fn only_the_config_s_logs_that_are_there_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let host = host_with_a_site_log(dir.path());
        std::fs::remove_file(dir.path().join("site.log")).unwrap();

        let logs = host.log_paths().access_logs_to_read(None);

        assert_eq!(
            logs,
            [AccessLog {
                path: dir.path().join("main.log"),
                origin: LogOrigin::Stored
            }],
            "main.log is not there either, and is still read"
        );
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
