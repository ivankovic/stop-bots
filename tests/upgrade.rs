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

//! Upgrading from every release since 0.1.0: this build opens the
//! database each one wrote with its settings intact, and re-applies over
//! the files each one wrote.
//!
//! The fixtures are what the released binaries themselves wrote, recorded
//! by `scripts/upgrade-fixture.sh`: a dump of the database in
//! `tests/fixtures/db/db-<version>.sql`, and the NGINX site and firewall
//! script in `tests/fixtures/upgrade/<version>/`. The script lists every
//! command it ran; the settings checked below are exactly the ones those
//! commands changed. A new release adds its version to [`RELEASES`] (see
//! RELEASING.md).
//!
//! The 0.0.x databases, from before the compatibility promise, are tested
//! in `src/db/schema.rs` and `tests/cli.rs`.

use std::fs;
use std::path::{Path, PathBuf};
use stop_bots::db::{Category, Db, FirewallAction, Policy};
use stop_bots::protection::Detector;
mod common;
use common::stop_bots_bin;

const RELEASES: [&str; 13] = [
    "0.1.0", "0.1.1", "0.2.0", "0.2.1", "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.8.0",
    "0.9.0", "0.10.0", "0.11.0",
];

const BEGIN: &str = "# BEGIN stop-bots";
const END: &str = "# END stop-bots";

/// A host as `release` left it, moved into a temp directory: its database,
/// its NGINX root holding the one site it applied to, and the directories
/// the generated files go to.
///
/// The fixtures name the paths a real host has (`/etc/nginx`,
/// `/etc/stop-bots/nginx`); they are rewritten to this host's, in the
/// database and the site alike, since a site's per-site settings are found
/// by the path its config was scanned at.
struct UpgradedHost {
    release: &'static str,
    /// Deleted, with everything in it, when the host is dropped.
    tmp: tempfile::TempDir,
    db: PathBuf,
    nginx_root: PathBuf,
    managed: PathBuf,
}

impl UpgradedHost {
    fn of(release: &'static str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_root = tmp.path().join("nginx");
        let managed = tmp.path().join("stop-bots-nginx");
        fs::create_dir_all(nginx_root.join("sites-enabled")).unwrap();
        let host = UpgradedHost {
            release,
            db: tmp.path().join("db.sqlite3"),
            nginx_root,
            managed,
            tmp,
        };

        let sql = host.here(&read(format!("tests/fixtures/db/db-{release}.sql")));
        let conn = rusqlite::Connection::open(&host.db).unwrap();
        // No fsyncs for the setup: it is not what is under test.
        conn.execute_batch("PRAGMA synchronous = OFF").unwrap();
        conn.execute_batch(&sql).unwrap();
        drop(conn);
        fs::write(host.site(), host.written_site()).unwrap();
        host
    }

    /// `text` with a real host's paths replaced by this one's.
    fn here(&self, text: &str) -> String {
        text.replace("/etc/stop-bots/nginx", self.managed.to_str().unwrap())
            .replace("/etc/nginx", self.nginx_root.to_str().unwrap())
    }

    /// The site's config file in this host's NGINX root.
    fn site(&self) -> PathBuf {
        self.nginx_root.join("sites-enabled/example.com")
    }

    /// The site as the release wrote it, at this host's paths.
    fn written_site(&self) -> String {
        self.here(&read(self.fixture("example.com")))
    }

    fn fixture(&self, name: &str) -> String {
        format!("tests/fixtures/upgrade/{}/{name}", self.release)
    }

    /// This build, on this host, asserting success; its stdout.
    fn run(&self, args: &[&str]) -> String {
        let output = stop_bots_bin()
            .env("STOP_BOTS_NGINX_DIR", &self.managed)
            .env("STOP_BOTS_NGINX_CONF_D", self.nginx_root.join("conf.d"))
            .env("STOP_BOTS_HOST_CONF", self.tmp.path().join("host.conf"))
            .args(args)
            .args(["--db", self.db.to_str().unwrap()])
            .assert()
            .success();
        String::from_utf8_lossy(&output.get_output().stdout).into_owned()
    }

    /// `apply-blocks` over this host's root, and the site it leaves.
    fn apply_blocks(&self) -> String {
        self.run(&[
            "apply-blocks",
            "--root",
            self.nginx_root.to_str().unwrap(),
            "--no-reload",
        ]);
        read(self.site())
    }
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// `site` split around its one stop-bots block: what is before the BEGIN
/// marker's line, the block, and what is after the END marker's line.
fn around_block(site: &str) -> (&str, &str, &str) {
    let begin = site.find(BEGIN).expect("no BEGIN marker");
    let begin = site[..begin].rfind('\n').map_or(0, |at| at + 1);
    let end = site.find(END).expect("no END marker");
    let end = site[end..].find('\n').map_or(site.len(), |at| end + at + 1);
    (&site[..begin], &site[begin..end], &site[end..])
}

/// The part of a firewall script that decides anything: its sets, the
/// rules matching them and their addresses. Everything above it is the
/// fixed table and chain setup, which a newer release may well improve.
fn rules(script: &str) -> &str {
    let at = script
        .find("\nadd set ")
        .expect("no `add set` in the script");
    &script[at..]
}

#[test]
fn every_release_s_database_opens_at_the_current_schema_version() {
    for release in RELEASES {
        let host = UpgradedHost::of(release);
        Db::open(&host.db).unwrap_or_else(|err| panic!("{release}: {err:#}"));
        let version: u32 = rusqlite::Connection::open(&host.db)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, stop_bots::db::schema::CURRENT_VERSION, "{release}");
    }
}

/// The simple screen is for a new install: a host upgraded from a release
/// before it opens on every screen, the ones its operator already knows,
/// and one created since keeps opening on the simple screen.
#[test]
fn a_database_from_before_the_simple_screen_opens_on_every_screen() {
    use stop_bots::db::UiMode;
    for release in RELEASES {
        let db = Db::open(UpgradedHost::of(release).db).unwrap();
        let expected = if older_than(release, "0.7.0") {
            UiMode::Advanced
        } else {
            UiMode::Simple
        };
        assert_eq!(db.get_ui_mode().unwrap(), expected, "{release}");
    }
}

/// An upgrade starts no detector by itself: one added since a release is
/// off on that release's database, and marked new, whatever it defaults
/// to on a new one.
#[test]
fn every_release_s_database_has_the_detectors_added_since_off_and_new() {
    for release in RELEASES {
        let db = Db::open(UpgradedHost::of(release).db).unwrap();
        let created_at = db.defaults_generation().unwrap();
        for detector in Detector::ALL
            .into_iter()
            .filter(|d| d.spec().introduced_in > created_at)
        {
            let id = detector.id();
            assert!(!detector.is_enabled(&db).unwrap(), "{release}: {id} is on");
            assert!(
                detector.is_new_here(&db).unwrap(),
                "{release}: {id} not new"
            );
        }
    }
}

/// Every setting `scripts/upgrade-fixture.sh` changed from its default
/// reads back changed. A key renamed or a value re-spelled since would
/// read as the default here instead.
#[test]
fn every_setting_a_release_changed_reads_back_the_same() {
    for release in RELEASES {
        let db = Db::open(UpgradedHost::of(release).db).unwrap();
        let sites = db.list_sites().unwrap();
        assert_eq!(sites.len(), 1, "{release}: sites were {sites:?}");
        let site = sites[0].id;
        let checks: Vec<(&str, String, &str)> = vec![
            (
                "search engines, host-wide",
                format!(
                    "{:?}",
                    db.get_stored_category_default(Category::Search).unwrap()
                ),
                "Blocked",
            ),
            (
                "AI crawlers on example.com",
                format!(
                    "{:?}",
                    db.get_site_category_override(site, Category::Ai).unwrap()
                ),
                "Some(Allowed)",
            ),
            (
                "web scanners",
                Detector::WebScanners.is_enabled(&db).unwrap().to_string(),
                "false",
            ),
            (
                "fetches no assets",
                Detector::AssetRatio.is_enabled(&db).unwrap().to_string(),
                "true",
            ),
            (
                "probe paths TTL",
                Detector::ProbePaths.ttl_days(&db).unwrap().to_string(),
                "9",
            ),
            (
                "SSH scanners threshold",
                format!("{:?}", Detector::SshScanners.threshold(&db).unwrap()),
                "Some(7)",
            ),
            (
                "SSH scanners window",
                Detector::SshScanners.window_hours(&db).unwrap().to_string(),
                "48",
            ),
            (
                "geo mode",
                format!("{:?}", db.get_geo_mode().unwrap()),
                "Allowlist",
            ),
            (
                "countries",
                db.list_selected_countries().unwrap().join(","),
                "hr",
            ),
            (
                "trusted addresses",
                db.list_trusted_addresses().unwrap().join(","),
                "192.0.2.10",
            ),
            (
                "trusted user agents",
                db.list_trusted_user_agents().unwrap().join(","),
                "UptimeRobot",
            ),
            (
                "block response",
                format!("{:?}", db.get_block_response().unwrap()),
                "Gone",
            ),
            (
                "robots.txt",
                db.get_serve_robots_txt().unwrap().to_string(),
                "true",
            ),
            (
                "rate limiting",
                db.get_rate_limit_enabled().unwrap().to_string(),
                "true",
            ),
            ("rate", db.get_rate_limit_rps().unwrap().to_string(), "7"),
            (
                "burst",
                db.get_rate_limit_burst().unwrap().to_string(),
                "11",
            ),
            (
                "example.com's request rules",
                db.site_request_rules(site).unwrap().join(","),
                "http_1x",
            ),
            (
                "example.com's exempt paths",
                db.site_path_exemptions(site).unwrap().join(","),
                "/blog/",
            ),
        ];
        for (what, got, want) in checks {
            assert_eq!(got, want, "{release}: {what}");
        }
        // Not a setting that was changed, but one an upgrade could flip:
        // the category nobody touched keeps its stored default.
        assert_eq!(
            db.get_stored_category_default(Category::Scanner).unwrap(),
            Policy::Blocked,
            "{release}: scanners"
        );
    }
}

/// Probes for absent apps make the probe-paths detector block more, so no
/// upgrade switches them on: off on the database of every release before
/// the one that brought them (0.4.0), and marked new until the operator
/// chooses. A database 0.4.0 or later created has them as it started.
#[test]
fn no_earlier_release_s_database_gains_probes_for_absent_apps() {
    for release in RELEASES.into_iter().filter(|r| older_than(r, "0.4.0")) {
        let host = UpgradedHost::of(release);
        let listed: serde_json::Value =
            serde_json::from_str(&host.run(&["list-probe-paths", "--json"])).unwrap();
        let conditional = &listed["conditional"];
        assert_eq!(conditional["enabled"], false, "{release}: {conditional:#}");
        assert_eq!(
            conditional["new_in_this_release"], true,
            "{release}: {conditional:#}"
        );
    }
}

/// Whether `release` comes before `other`, comparing `major.minor.patch`.
fn older_than(release: &str, other: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|n| n.parse().unwrap()).collect() };
    parse(release) < parse(other)
}

#[test]
fn older_than_compares_versions_numerically() {
    for (a, b, older) in [
        ("0.3.0", "0.4.0", true),
        ("0.4.0", "0.4.0", false),
        ("0.10.0", "0.4.0", false),
        ("0.2.1", "0.10.0", true),
    ] {
        assert_eq!(older_than(a, b), older, "{a} < {b}");
    }
}

#[test]
fn every_release_s_firewall_rules_read_back_the_same() {
    use FirewallAction::{Allow, Block};
    for release in RELEASES {
        let db = Db::open(UpgradedHost::of(release).db).unwrap();
        let rules: Vec<_> = db
            .list_firewall_rules()
            .unwrap()
            .into_iter()
            .map(|r| (r.address, r.port, r.action, r.enabled, r.expires_at))
            .collect();
        assert_eq!(
            rules,
            [
                ("203.0.113.7".to_string(), None, Block, true, None),
                ("198.51.100.0/24".to_string(), Some(22), Block, true, None),
                ("192.0.2.1".to_string(), None, Allow, true, None),
            ],
            "{release}"
        );
    }
}

/// The block is replaced where it stands, not added a second time, and
/// not a byte outside it changes.
#[test]
fn apply_blocks_replaces_the_block_a_release_wrote_in_place() {
    for release in RELEASES {
        let host = UpgradedHost::of(release);
        let before = host.written_site();

        let after = host.apply_blocks();

        for marker in [BEGIN, END] {
            assert_eq!(
                after.matches(marker).count(),
                1,
                "{release}: {marker:?} should appear once; the site was:\n{after}"
            );
        }
        let (old_head, _, old_tail) = around_block(&before);
        let (new_head, _, new_tail) = around_block(&after);
        assert_eq!(new_head, old_head, "{release}: before the block");
        assert_eq!(new_tail, old_tail, "{release}: after the block");
    }
}

/// What the release wrote for the site, this build writes too: the same
/// response, the same exempt path, the same rate limit, the same
/// robots.txt.
#[test]
fn the_block_re_applied_over_a_release_s_keeps_its_site_s_settings() {
    for release in RELEASES {
        let host = UpgradedHost::of(release);
        let after = host.apply_blocks();
        let (_, block, _) = around_block(&after);
        let robots = format!("alias {}/robots.txt;", host.managed.display());
        for (what, needle) in [
            ("block response", "return 410;"),
            ("exempt path", "/blog/"),
            ("rate limit", "burst=11"),
            ("robots.txt", robots.as_str()),
        ] {
            assert!(
                block.contains(needle),
                "{release}: {what}: no {needle:?} in the block:\n{block}"
            );
        }
    }
}

#[test]
fn the_firewall_rendered_from_a_release_s_database_has_the_rules_that_release_wrote() {
    for release in RELEASES {
        let host = UpgradedHost::of(release);
        let out = host.db.with_file_name("firewall.nft");
        host.run(&[
            "render-firewall",
            "--out",
            out.to_str().unwrap(),
            "--ssh-log",
            "tests/fixtures/logs/auth.log",
        ]);

        let written = read(host.fixture("firewall.nft"));
        assert_eq!(rules(&read(&out)), rules(&written), "{release}");
    }
}
