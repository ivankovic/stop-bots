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

//! ModSecurity with the OWASP Core Rule Set, set up for each site from
//! what runs behind it.
//!
//! The exploit rules ([`crate::exploits`]) see the request line and the
//! headers. ModSecurity sees the rest: the body of a form post, a JSON API
//! call, an upload. It is not this project's: it is a module of the web
//! server, installed from the distribution (`libnginx-mod-http-modsecurity`
//! and `modsecurity-crs` on Debian and Ubuntu). What this does is what it
//! does for NGINX itself: write its config, per site, and read back what
//! it did.
//!
//! ## Three modes, per site
//!
//! - **Off**: the site's block says nothing, and ModSecurity never runs
//!   for it.
//! - **Detect**: every request is checked and what CRS would block is
//!   written to the audit log, and nothing is blocked. Where every site
//!   starts: CRS on an application it was not tuned for blocks real
//!   requests, and the audit log is how to find out which.
//! - **Block**: what CRS scores as an attack is answered with a 403.
//!
//! ## What is behind the site
//!
//! CRS ships exclusions for the applications whose ordinary requests look
//! like attacks to it (a WordPress post is HTML, a Nextcloud sync is
//! WebDAV). Each is switched on by a flag, and this switches on the one
//! for the application recognised behind the site ([`crate::webapps`],
//! [`crate::services`]): WordPress, Drupal, Nextcloud. For applications CRS
//! has none for, this carries its own, few and narrow, said in
//! [`own_exclusions`]. And every exclusion the operator made from the audit
//! log, a rule switched off under one path.
//!
//! ## How a request is tied to its site
//!
//! Not by its `Host` header, which the client writes and HTTP/2 does not
//! send as one. Each site's block names its transaction ids
//! (`modsecurity_transaction_id "sb<site>-$request_id"`), and every
//! per-site rule here matches that prefix. A request reaching a server
//! block no site row names gets the host's defaults and no exclusion.
//!
//! ## One rules file
//!
//! `/etc/stop-bots/nginx/modsecurity.conf`, loaded once at `http` level
//! from `conf.d/stop-bots-modsecurity.conf`: the engine's settings, then
//! every site's rules, then CRS. The per-site rules come before CRS
//! because its exclusion flags and the paranoia level are read in its
//! first phase, and a rule loaded after it would set them too late. One
//! load of CRS for the whole server, however many sites: a rules file
//! per site would hold a copy of CRS each.
//!
//! Nothing is written unless the module is loaded and CRS is installed:
//! `modsecurity on;` without the module fails `nginx -t`, which would
//! refuse every other change of the same apply.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::db::waf::ModsecExclusion;
use crate::db::{keys, Db};

/// What ModSecurity does for a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Mode {
    #[default]
    Off,
    Detect,
    Block,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Off, Mode::Detect, Mode::Block];

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Detect => "detect",
            Mode::Block => "block",
        }
    }

    pub fn parse(text: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|m| m.as_str() == text)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Mode::Off => "not run",
            Mode::Detect => "checks every request and logs what it would block",
            Mode::Block => "blocks what the Core Rule Set scores as an attack",
        }
    }
}

/// The paranoia levels CRS has: 1 blocks the least that is not an attack,
/// 4 the most that might be.
pub const PARANOIA: std::ops::RangeInclusive<u8> = 1..=4;

pub fn host_mode(db: &Db) -> Result<Mode> {
    Ok(db
        .get_text_setting(keys::WAF_MODSECURITY)?
        .as_deref()
        .and_then(Mode::parse)
        .unwrap_or_default())
}

pub fn set_host_mode(db: &Db, mode: Mode) -> Result<()> {
    db.set_text_setting(keys::WAF_MODSECURITY, mode.as_str())
}

pub fn host_paranoia(db: &Db) -> Result<u8> {
    let level = db.get_int_setting(keys::WAF_PARANOIA, 1)?;
    Ok(u8::try_from(level)
        .ok()
        .filter(|l| PARANOIA.contains(l))
        .unwrap_or(1))
}

pub fn set_host_paranoia(db: &Db, level: u8) -> Result<()> {
    check_paranoia(level)?;
    db.set_int_setting(keys::WAF_PARANOIA, i64::from(level))
}

pub fn check_paranoia(level: u8) -> Result<()> {
    if !PARANOIA.contains(&level) {
        bail!("the Core Rule Set's paranoia levels are 1 to 4");
    }
    Ok(())
}

/// A site's mode: its own choice, else the host's.
pub fn site_mode(db: &Db, site_id: i64) -> Result<Mode> {
    match db
        .site_waf(site_id)?
        .modsecurity
        .as_deref()
        .and_then(Mode::parse)
    {
        Some(mode) => Ok(mode),
        None => host_mode(db),
    }
}

pub fn site_paranoia(db: &Db, site_id: i64) -> Result<u8> {
    match db
        .site_waf(site_id)?
        .paranoia
        .filter(|l| PARANOIA.contains(l))
    {
        Some(level) => Ok(level),
        None => host_paranoia(db),
    }
}

// ---- what is installed ----

/// Where the Core Rule Set is, as Debian and Ubuntu install it, unless the
/// environment says otherwise: for the tests, which must not depend on
/// what the machine running them has installed.
pub const CRS_SETUP: &str = "/etc/modsecurity/crs/crs-setup.conf";
pub const CRS_RULES: &str = "/usr/share/modsecurity-crs/rules";
pub const CRS_ENV: &str = "STOP_BOTS_MODSECURITY_CRS";

/// The audit log, in NGINX's own log directory: the rules file is loaded
/// by NGINX's master process, which opens it before the workers drop to
/// their user.
pub const AUDIT_LOG: &str = "/var/log/nginx/stop-bots-modsecurity.log";

/// Overrides [`AUDIT_LOG`] for reading, for the tests.
pub const AUDIT_LOG_ENV: &str = "STOP_BOTS_MODSECURITY_AUDIT_LOG";

/// Where the audit log is read from.
pub fn audit_log_path() -> PathBuf {
    crate::host::path_override(AUDIT_LOG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(AUDIT_LOG))
}

/// The most of the audit log read at once: its end, where the latest is.
const MAX_AUDIT_READ: u64 = 8 * 1024 * 1024;

/// The end of the audit log, as text; why not, when it cannot be read. A
/// log that is not there yet is nothing found, not an error.
pub fn read_audit_log(path: &Path) -> std::result::Result<String, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(err) => {
            return Err(format!(
                "could not read {}: {err} (run as root)",
                path.display()
            ))
        }
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len > MAX_AUDIT_READ {
        let _ = file.seek(SeekFrom::Start(len - MAX_AUDIT_READ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    // A read that started part-way drops the line it started in.
    Ok(if len > MAX_AUDIT_READ {
        text.split_once('\n')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    } else {
        text
    })
}

/// What there is to run ModSecurity with, or why there is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installation {
    Ready {
        crs_setup: PathBuf,
        crs_rules: PathBuf,
    },
    /// What is missing, said so it can be installed.
    Missing(String),
}

impl Installation {
    pub fn is_ready(&self) -> bool {
        matches!(self, Installation::Ready { .. })
    }
}

/// Whether NGINX under `root` loads the module, and CRS is installed.
pub fn installation(root: &Path) -> Installation {
    if !module_loaded(root) {
        return Installation::Missing(
            "NGINX does not load the ModSecurity module: install \
             libnginx-mod-http-modsecurity"
                .to_string(),
        );
    }
    let (crs_setup, crs_rules) = match crate::host::path_override(CRS_ENV) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            (dir.join("crs-setup.conf"), dir.join("rules"))
        }
        None => (PathBuf::from(CRS_SETUP), PathBuf::from(CRS_RULES)),
    };
    if !crs_setup.is_file() || !crs_rules.is_dir() {
        return Installation::Missing(format!(
            "the OWASP Core Rule Set is not installed ({} and {}): install modsecurity-crs",
            crs_setup.display(),
            crs_rules.display()
        ));
    }
    Installation::Ready {
        crs_setup,
        crs_rules,
    }
}

/// Whether a `load_module` of ModSecurity's NGINX module is in the main
/// config or a file of `modules-enabled` beside it.
fn module_loaded(root: &Path) -> bool {
    let Some(dir) = crate::nginx::main_config_dir(root) else {
        return false;
    };
    let names_module = |path: &Path| {
        std::fs::read_to_string(path).is_ok_and(|text| {
            text.lines().any(|line| {
                let line = line.split('#').next().unwrap_or("");
                line.contains("load_module") && line.contains("ngx_http_modsecurity_module")
            })
        })
    };
    if names_module(&dir.join("nginx.conf")) {
        return true;
    }
    std::fs::read_dir(dir.join("modules-enabled")).is_ok_and(|entries| {
        entries
            .filter_map(|e| e.ok())
            .any(|e| names_module(&e.path()))
    })
}

// ---- what each site gets ----

/// A CRS exclusion flag, by the application it is for.
const CRS_EXCLUSIONS: [(&str, &str); 3] = [
    ("WordPress", "wordpress"),
    ("Drupal", "drupal"),
    ("Nextcloud", "nextcloud"),
];

/// An exclusion this project writes for an application CRS has none for:
/// the request-body inspection switched off under one path, where the
/// application's own clients send what is not a form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnExclusion {
    pub app: &'static str,
    pub path: &'static str,
    pub why: &'static str,
}

/// Every one this carries. Only where a body is something CRS has no
/// business parsing: a photo or a video an app uploads in full. Anything
/// else is left to detect mode and the audit log to show.
pub fn own_exclusions() -> &'static [OwnExclusion] {
    &[OwnExclusion {
        app: "Immich",
        path: "/api/assets",
        why: "photo and video uploads",
    }]
}

/// What one site's ModSecurity is set to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SitePlan {
    pub site_id: i64,
    pub mode: Mode,
    pub paranoia: u8,
    /// The CRS exclusion flags, by their CRS names (`wordpress`).
    pub crs_exclusions: Vec<&'static str>,
    pub own: Vec<OwnExclusion>,
    /// Exclusions the operator made, as `(rule, path)`.
    pub learned: Vec<(u32, String)>,
    /// What runs behind the site, by name, as it was recognised.
    pub apps: Vec<&'static str>,
}

impl SitePlan {
    /// The prefix of this site's transaction ids.
    pub fn token(&self) -> String {
        format!("sb{}-", self.site_id)
    }

    /// The comment its block carries, which is also what makes a change of
    /// mode put the site back to STALE.
    pub fn summary(&self) -> String {
        let mut out = format!(
            "ModSecurity: {}, paranoia {}",
            self.mode.as_str(),
            self.paranoia
        );
        if !self.crs_exclusions.is_empty() {
            out.push_str(&format!(
                ", CRS exclusions for {}",
                self.crs_exclusions.join(", ")
            ));
        }
        let own = self.own.len() + self.learned.len();
        if own > 0 {
            out.push_str(&format!(", {own} exclusion(s) of its own"));
        }
        out
    }
}

/// What runs behind a site, from its config and its document root.
pub fn apps_behind(config_path: &Path, server_name: &str) -> Vec<&'static str> {
    let directives = crate::nginx::site_directives(config_path, server_name);
    let mut apps =
        crate::webapps::apps_present(&crate::webapps::inspect_site(directives.as_deref(), true));
    if let Some(service) = directives.as_deref().and_then(crate::services::recognise) {
        apps.push(service.name());
    }
    apps
}

/// The plan for a site whose mode is `mode`, given what runs behind it and
/// the exclusions stored for it.
pub fn plan_for(
    site_id: i64,
    mode: Mode,
    paranoia: u8,
    apps: Vec<&'static str>,
    exclusions: &[ModsecExclusion],
) -> SitePlan {
    let crs_exclusions = CRS_EXCLUSIONS
        .iter()
        .filter(|(app, _)| apps.contains(app))
        .map(|(_, flag)| *flag)
        .collect();
    let own = own_exclusions()
        .iter()
        .filter(|own| apps.contains(&own.app))
        .copied()
        .collect();
    let learned = exclusions
        .iter()
        .filter(|e| e.site_id == site_id)
        .map(|e| (e.rule_id, e.path.clone()))
        .collect();
    SitePlan {
        site_id,
        mode,
        paranoia,
        crs_exclusions,
        own,
        learned,
        apps,
    }
}

/// Every site's plan, for the rules file. `None` when ModSecurity cannot
/// run on this host (see [`installation`]), or runs for no site.
pub fn plans(db: &Db, root: &Path) -> Result<Option<(Installation, Vec<SitePlan>)>> {
    let installed = installation(root);
    if !installed.is_ready() {
        return Ok(None);
    }
    let exclusions = db.modsec_exclusions()?;
    let mut plans = Vec::new();
    for site in db.list_sites()? {
        let mode = site_mode(db, site.id)?;
        if mode == Mode::Off {
            continue;
        }
        plans.push(plan_for(
            site.id,
            mode,
            site_paranoia(db, site.id)?,
            apps_behind(Path::new(&site.config_path), &site.server_name),
            &exclusions,
        ));
    }
    if plans.is_empty() {
        return Ok(None);
    }
    Ok(Some((installed, plans)))
}

/// The plan for one site, or `None` when its ModSecurity is off or cannot
/// run: what its block is rendered with.
pub fn site_plan(db: &Db, site_id: i64, root: &Path) -> Result<Option<SitePlan>> {
    let mode = site_mode(db, site_id)?;
    if mode == Mode::Off || !installation(root).is_ready() {
        return Ok(None);
    }
    let Some(site) = db.list_sites()?.into_iter().find(|s| s.id == site_id) else {
        return Ok(None);
    };
    Ok(Some(plan_for(
        site_id,
        mode,
        site_paranoia(db, site_id)?,
        apps_behind(Path::new(&site.config_path), &site.server_name),
        &db.modsec_exclusions()?,
    )))
}

/// Where the rules file is: beside the other files NGINX reads of ours.
pub fn rules_path() -> PathBuf {
    crate::nginx::managed_dir().join("modsecurity.conf")
}

/// The `conf.d` file that loads it.
pub fn loader_path(conf_d: &Path) -> PathBuf {
    conf_d.join("stop-bots-modsecurity.conf")
}

/// The loader's body.
pub fn loader_body() -> String {
    let mut out = crate::webserver::managed_header();
    out.push_str("# ModSecurity's rules, for every site whose block switches it on.\n");
    out.push_str(&format!(
        "modsecurity_rules_file {};\n",
        rules_path().display()
    ));
    out
}

/// The first rule id this writes. CRS keeps 900,000 to 999,999 for itself;
/// below 100,000 is for local rules.
const FIRST_RULE_ID: u32 = 10_000;

/// The rules file's body: see "One rules file" in the module docs.
pub fn rules_body(installation: &Installation, plans: &[SitePlan]) -> String {
    let Installation::Ready {
        crs_setup,
        crs_rules,
    } = installation
    else {
        return String::new();
    };
    let mut out = crate::webserver::managed_header();
    out.push_str(&format!(
        "# ModSecurity for the sites stop-bots manages: the engine, each site's\n\
         # rules, then the OWASP Core Rule Set. See `stop-bots set-modsecurity`.\n\n\
         SecRuleEngine DetectionOnly\n\
         SecRequestBodyAccess On\n\
         SecRequestBodyLimit 13107200\n\
         SecRequestBodyNoFilesLimit 131072\n\
         SecRequestBodyLimitAction ProcessPartial\n\
         SecResponseBodyAccess Off\n\
         SecPcreMatchLimit 100000\n\
         SecPcreMatchLimitRecursion 100000\n\
         SecTmpDir /tmp/\n\
         SecDataDir /tmp/\n\
         SecArgumentSeparator &\n\
         SecCookieFormat 0\n\
         SecStatusEngine Off\n\
         SecAuditEngine RelevantOnly\n\
         SecAuditLogRelevantStatus \"^(?:5|4(?!04))\"\n\
         SecAuditLogParts ABHZ\n\
         SecAuditLogType Serial\n\
         SecAuditLogFormat JSON\n\
         SecAuditLog {AUDIT_LOG}\n\n"
    ));
    let mut id = FIRST_RULE_ID;
    let mut next = || {
        id += 1;
        id
    };
    for plan in plans {
        let token = plan.token();
        out.push_str(&format!("# site {}: {}\n", plan.site_id, plan.summary()));
        let mut actions = vec![format!("setvar:tx.paranoia_level={}", plan.paranoia)];
        if plan.mode == Mode::Block {
            actions.push("ctl:ruleEngine=On".to_string());
        }
        for flag in &plan.crs_exclusions {
            actions.push(format!("setvar:tx.crs_exclusions_{flag}=1"));
        }
        out.push_str(&format!(
            "SecRule UNIQUE_ID \"@beginsWith {token}\" \"id:{},phase:1,pass,nolog,t:none,{}\"\n",
            next(),
            actions.join(",")
        ));
        for own in &plan.own {
            out.push_str(&format!(
                "SecRule UNIQUE_ID \"@beginsWith {token}\" \"id:{},phase:1,pass,nolog,t:none,chain\"\n    \
                 SecRule REQUEST_FILENAME \"@beginsWith {}\" \"t:none,ctl:requestBodyAccess=Off\"\n",
                next(),
                own.path
            ));
        }
        for (rule, path) in &plan.learned {
            if !crate::db::waf::is_exclusion_path(path) {
                continue;
            }
            out.push_str(&format!(
                "SecRule UNIQUE_ID \"@beginsWith {token}\" \"id:{},phase:1,pass,nolog,t:none,chain\"\n    \
                 SecRule REQUEST_FILENAME \"@beginsWith {path}\" \"t:none,ctl:ruleRemoveById={rule}\"\n",
                next()
            ));
        }
        out.push('\n');
    }
    out.push_str(&format!(
        "Include {}\nInclude {}/*.conf\n",
        crs_setup.display(),
        crs_rules.display()
    ));
    out
}

/// What a site's block carries for it: switched on, with its transaction
/// ids named for it, under the comment that says how it is set.
pub fn block_lines(plan: &SitePlan) -> String {
    format!(
        "    # {}\n    modsecurity on;\n    modsecurity_transaction_id \"{}$request_id\";\n",
        plan.summary(),
        plan.token()
    )
}

// ---- what it did ----

/// One rule's findings on one site and path, from the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `None` for a request no site's transaction id names.
    pub site_id: Option<i64>,
    pub rule_id: u32,
    pub path: String,
    pub message: String,
    pub count: usize,
    /// How many of those requests CRS scored over its threshold: blocked
    /// in Block mode, and what would have been in Detect.
    pub over_threshold: usize,
    pub last_seen: String,
}

/// The rules that only add up a score or report one, which say nothing
/// about what in a request matched.
fn is_scoring_rule(id: u32) -> bool {
    matches!(id, 949110 | 959100 | 980130 | 980140 | 949111 | 980170)
}

/// Whether `transaction` is one of the exposure check's own requests
/// ([`crate::exposure::is_own_request`]). It asks every site for `/.env`
/// and friends about once an hour, and CRS flags each one, so without
/// this the top of the findings is the health check, on every host.
fn is_own_request(transaction: &serde_json::Value, path: &str) -> bool {
    let Some(ip) = transaction
        .get("client_ip")
        .and_then(|v| v.as_str())
        .and_then(|ip| ip.parse().ok())
    else {
        return false;
    };
    // As the client sent it: reqwest's is lowercase, but nothing says so.
    let user_agent = transaction
        .pointer("/request/headers")
        .and_then(|v| v.as_object())
        .and_then(|headers| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        })
        .and_then(|(_, v)| v.as_str())
        .unwrap_or("");
    crate::exposure::is_own_request(&ip, user_agent, path)
}

/// Reads ModSecurity's JSON audit log, one transaction a line, into one
/// finding per site, rule and path, the commonest first. The exposure
/// check's own requests are left out ([`is_own_request`]).
pub fn findings(audit_log: &str) -> Vec<Finding> {
    let mut found: Vec<Finding> = Vec::new();
    for line in audit_log.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(transaction) = entry.get("transaction") else {
            continue;
        };
        let unique_id = transaction
            .get("unique_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let site_id = unique_id
            .strip_prefix("sb")
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(id, _)| id.parse::<i64>().ok());
        let uri = transaction
            .pointer("/request/uri")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = uri.split('?').next().unwrap_or("").to_string();
        if is_own_request(transaction, &path) {
            continue;
        }
        let time = transaction
            .get("time_stamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let Some(messages) = transaction.get("messages").and_then(|v| v.as_array()) else {
            continue;
        };
        let rule = |m: &serde_json::Value| {
            m.pointer("/details/ruleId")
                .and_then(|v| v.as_str())
                .and_then(|id| id.parse::<u32>().ok())
        };
        let over = messages
            .iter()
            .any(|m| matches!(rule(m), Some(949110 | 959100)));
        for message in messages {
            let Some(rule_id) = rule(message) else {
                continue;
            };
            if is_scoring_rule(rule_id) {
                continue;
            }
            let text = message
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            match found
                .iter_mut()
                .find(|f| f.site_id == site_id && f.rule_id == rule_id && f.path == path)
            {
                Some(finding) => {
                    finding.count += 1;
                    finding.over_threshold += usize::from(over);
                    finding.last_seen = time.clone();
                }
                None => found.push(Finding {
                    site_id,
                    rule_id,
                    path: path.clone(),
                    message: text,
                    count: 1,
                    over_threshold: usize::from(over),
                    last_seen: time.clone(),
                }),
            }
        }
    }
    found.sort_by(|a, b| {
        b.over_threshold
            .cmp(&a.over_threshold)
            .then(b.count.cmp(&a.count))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Installation {
        Installation::Ready {
            crs_setup: PathBuf::from("/etc/modsecurity/crs/crs-setup.conf"),
            crs_rules: PathBuf::from("/usr/share/modsecurity-crs/rules"),
        }
    }

    fn wordpress_in_block() -> SitePlan {
        plan_for(
            3,
            Mode::Block,
            2,
            vec!["WordPress"],
            &[ModsecExclusion {
                site_id: 3,
                rule_id: 942100,
                path: "/wp-admin/admin-ajax.php".to_string(),
            }],
        )
    }

    #[test]
    fn the_rules_file_matches_the_golden() {
        let plans = [
            wordpress_in_block(),
            plan_for(7, Mode::Detect, 1, vec!["Immich"], &[]),
        ];
        crate::golden::assert_golden("modsecurity.conf", &rules_body(&ready(), &plans));
    }

    /// CRS reads its exclusion flags and the paranoia level in its first
    /// phase: set after it, they would come too late.
    #[test]
    fn every_site_rule_comes_before_the_core_rule_set() {
        let body = rules_body(&ready(), &[wordpress_in_block()]);
        let crs = body.find("Include ").unwrap();
        let last_rule = body.rfind("SecRule").unwrap();
        assert!(last_rule < crs, "{body}");
    }

    #[test]
    fn what_runs_behind_a_site_chooses_its_exclusions() {
        let cases = [
            (vec!["WordPress"], vec!["wordpress"], 0),
            (vec!["Nextcloud"], vec!["nextcloud"], 0),
            (vec!["Immich"], vec![], 1),
            (vec![], vec![], 0),
        ];
        for (apps, crs, own) in cases {
            let plan = plan_for(1, Mode::Detect, 1, apps.clone(), &[]);
            assert_eq!(
                (plan.crs_exclusions.clone(), plan.own.len()),
                (crs, own),
                "{apps:?}"
            );
        }
    }

    #[test]
    fn a_site_follows_the_host_until_it_chooses() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_site("a.example", "/etc/nginx/sites-enabled/a")
            .unwrap();
        let site = db.list_sites().unwrap()[0].id;
        assert_eq!(site_mode(&db, site).unwrap(), Mode::Off);
        set_host_mode(&db, Mode::Detect).unwrap();
        assert_eq!(site_mode(&db, site).unwrap(), Mode::Detect);
        db.set_site_modsecurity(site, Some("block")).unwrap();
        assert_eq!(site_mode(&db, site).unwrap(), Mode::Block);
        assert!(set_host_paranoia(&db, 5).is_err());
    }

    /// Without the module, `modsecurity on;` fails `nginx -t` and takes the
    /// rest of the apply with it.
    #[test]
    fn nothing_is_planned_where_the_module_is_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nginx.conf"), "events {}\nhttp {}\n").unwrap();
        assert!(!installation(dir.path()).is_ready());
        std::fs::create_dir(dir.path().join("modules-enabled")).unwrap();
        std::fs::write(
            dir.path()
                .join("modules-enabled/50-mod-http-modsecurity.conf"),
            "load_module modules/ngx_http_modsecurity_module.so;\n",
        )
        .unwrap();
        assert!(
            matches!(installation(dir.path()), Installation::Missing(why) if why.contains("Core Rule Set")),
            "the module alone should still want CRS"
        );
    }

    #[test]
    fn the_audit_log_is_read_into_findings_by_site_rule_and_path() {
        let entry = |id: &str, uri: &str, rules: &[&str]| {
            let messages: Vec<String> = rules
                .iter()
                .map(|r| {
                    format!(
                        r#"{{"message":"rule {r}","details":{{"ruleId":"{r}","severity":"2"}}}}"#
                    )
                })
                .collect();
            format!(
                r#"{{"transaction":{{"unique_id":"{id}","time_stamp":"Sun Oct 25 10:00:00 2026","request":{{"method":"POST","uri":"{uri}"}},"messages":[{}]}}}}"#,
                messages.join(",")
            )
        };
        let log = [
            entry(
                "sb3-abc",
                "/wp-admin/admin-ajax.php?action=x",
                &["942100", "949110"],
            ),
            entry("sb3-def", "/wp-admin/admin-ajax.php", &["942100"]),
            entry("other", "/", &["920350"]),
        ]
        .join("\n");
        let found = findings(&log);
        let summary: Vec<(Option<i64>, u32, &str, usize, usize)> = found
            .iter()
            .map(|f| {
                (
                    f.site_id,
                    f.rule_id,
                    f.path.as_str(),
                    f.count,
                    f.over_threshold,
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (Some(3), 942100, "/wp-admin/admin-ajax.php", 2, 1),
                (None, 920350, "/", 1, 0),
            ]
        );
    }

    /// The exposure check asks every site for `/.env` over loopback; CRS
    /// flags it each time, and that is not a finding. A scanner asking for
    /// the same, or anything else from loopback, still is.
    #[test]
    fn the_exposure_checks_own_requests_are_not_findings() {
        let firefox = crate::exposure::USER_AGENT;
        let entry = |ip: &str, user_agent: &str, uri: &str| {
            format!(
                r#"{{"transaction":{{"client_ip":"{ip}","unique_id":"sb1-x","time_stamp":"Mon Oct 26 12:36:44 2026","request":{{"method":"GET","uri":"{uri}","headers":{{"user-agent":"{user_agent}"}}}},"messages":[{{"message":"Restricted File Access Attempt","details":{{"ruleId":"930130"}}}}]}}}}"#
            )
        };
        let cases = [
            (
                "the check's own request",
                entry("127.0.0.1", firefox, "/.env"),
                false,
            ),
            (
                "the check over IPv6",
                entry("::1", firefox, "/.git/config"),
                false,
            ),
            (
                "a scanner asking the same",
                entry("203.0.113.9", firefox, "/.env"),
                true,
            ),
            (
                "another agent on loopback",
                entry("127.0.0.1", "curl/8.0", "/.env"),
                true,
            ),
            (
                "a path the check never asks",
                entry("127.0.0.1", firefox, "/.env.bak"),
                true,
            ),
        ];
        for (what, log, reported) in cases {
            assert_eq!(!findings(&log).is_empty(), reported, "{what}:\n{log}");
        }
    }
}
