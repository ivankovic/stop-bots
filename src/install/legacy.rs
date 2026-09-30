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

//! The units 0.0.x releases wrote, so that one of them can be recognised
//! as unedited.
//!
//! Units from 0.1 on carry the hash of their own text (see
//! [`super::TEMPLATE_MARKER`]), and that answers "has anybody edited
//! this?" for good. A unit written before then has no hash. The only way
//! to tell one that is exactly as a release wrote it from one somebody
//! changed is to know every text a release could have written — which is
//! what this module holds, recovered from the release tags:
//!
//! - `web-0.0.1-to-0.0.6.service` and `web-0.0.7-to-0.0.15.service`: the
//!   web unit, with its one variable line, `ExecStart=`, left as
//!   `@EXEC@`. 0.0.7 reworded the header comment when the NGINX root moved
//!   into the database. `ExecStart` changed shape four times, which
//!   [`web_exec_matches`] checks line by line.
//! - The firewall unit has no variable part: 0.0.5 to 0.0.12 wrote the
//!   nftables one, and 0.0.13 added the iptables one beside it.
//!
//! **Frozen.** These are the bytes on real hosts; they never change.
//!
//! Nothing from 0.1.0-rc.1 on belongs here. Its units carry the hash, so
//! they are recognised by it whatever their text — the rc.1 units are kept
//! as fixtures in `tests/fixtures/units/` instead, and `install`'s tests
//! check that each one still hashes to its marker and upgrades without
//! `--force`. Listing them here as well would be a second way to recognise
//! the same bytes, and the first place to look when the two disagreed.

use std::path::PathBuf;

const WEB_0_0_1_TO_0_0_6: &str = include_str!("legacy/web-0.0.1-to-0.0.6.service");
const WEB_0_0_7_TO_0_0_15: &str = include_str!("legacy/web-0.0.7-to-0.0.15.service");
const FIREWALL_NFT: &str = include_str!("legacy/firewall-nftables-0.0.5-to-0.0.15.service");
const FIREWALL_IPTABLES: &str = include_str!("legacy/firewall-iptables-0.0.13-to-0.0.15.service");

/// A web unit recognised as one a 0.0.x release wrote and nobody edited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyWebUnit {
    /// Which releases could have written it, for the installer to say.
    pub releases: &'static str,
    /// The `--root` its `ExecStart` named, if it named one. 0.0.1 to 0.0.6
    /// always did; from 0.0.7 on the service reads the root from the
    /// database instead, so a replacement unit would silently drop this
    /// one unless the installer stores it.
    pub root: Option<PathBuf>,
}

/// The release range that wrote `text`, if it is a web unit exactly as a
/// 0.0.x release wrote it.
pub fn web_unit(text: &str) -> Option<LegacyWebUnit> {
    let exec_line = text.lines().find(|line| line.starts_with("ExecStart="))?;
    let exec = &exec_line["ExecStart=".len()..];
    let rest = text.replacen(exec_line, "ExecStart=@EXEC@", 1);
    let (releases, shape) = if rest == WEB_0_0_1_TO_0_0_6 {
        ("0.0.1 to 0.0.6", Shape::WithRoot)
    } else if rest == WEB_0_0_7_TO_0_0_15 {
        ("0.0.7 to 0.0.15", Shape::WithoutRoot)
    } else {
        return None;
    };
    let args = web_exec_matches(exec, shape)?;
    Some(LegacyWebUnit {
        releases,
        root: args.root.map(PathBuf::from),
    })
}

/// The release range that wrote `text`, if it is a firewall unit exactly
/// as a 0.0.x release wrote it.
pub fn firewall_unit(text: &str) -> Option<&'static str> {
    if text == FIREWALL_NFT {
        Some("0.0.5 to 0.0.15")
    } else if text == FIREWALL_IPTABLES {
        Some("0.0.13 to 0.0.15")
    } else {
        None
    }
}

/// Whether an `ExecStart` has the shape its release wrote.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// 0.0.1 to 0.0.6: `<bin> web --db <db> --root <root>`, then
    /// `--ssh-log <log>` (always in 0.0.1, only when asked from 0.0.2).
    WithRoot,
    /// 0.0.7 on: `<bin> web --db <db>`, then `--ssh-log <log>` if asked.
    WithoutRoot,
}

struct ExecArgs {
    root: Option<String>,
}

/// The arguments of `exec` if it is exactly what a release of `shape`
/// would have written for *some* binary, database and log paths.
///
/// The paths are free, because the installer chose them from flags and
/// its own location. Nothing else is: an added flag, a reordered one or a
/// changed spacing is an edit. The test is to split the line the way
/// systemd does, check the words, and then write it back the way the
/// release did — as plain text before 0.0.13, and through
/// [`super::systemd_arg`] from then on — and get the same bytes.
fn web_exec_matches(exec: &str, shape: Shape) -> Option<ExecArgs> {
    let words = split_exec(exec)?;
    let mut words = words.iter().map(String::as_str);
    let binary = words.next()?;
    if words.next()? != "web" || words.next()? != "--db" {
        return None;
    }
    let db = words.next()?;
    let mut rest: Vec<&str> = words.collect();
    let root = match shape {
        Shape::WithRoot => {
            if rest.len() < 2 || rest[0] != "--root" {
                return None;
            }
            let root = rest[1];
            rest.drain(..2);
            Some(root)
        }
        Shape::WithoutRoot => None,
    };
    let ssh_log = match rest.as_slice() {
        [] => None,
        ["--ssh-log", log] => Some(*log),
        _ => return None,
    };

    let mut paths = vec![("", binary), (" web --db ", db)];
    if let Some(root) = root {
        paths.push((" --root ", root));
    }
    if let Some(log) = ssh_log {
        paths.push((" --ssh-log ", log));
    }
    let written = |quote: &dyn Fn(&str) -> String| -> String {
        paths
            .iter()
            .map(|(before, path)| format!("{before}{}", quote(path)))
            .collect()
    };
    let plain = written(&|path| path.to_string());
    let quoted = written(&|path| super::systemd_arg(std::path::Path::new(path)));
    (exec == plain || exec == quoted).then(|| ExecArgs {
        root: root.map(str::to_string),
    })
}

/// `exec` split into words the way systemd splits `ExecStart=`, for the
/// subset [`super::systemd_arg`] writes: whitespace between words, a word
/// in double quotes with `\"`, `\\`, `\n`, `\t` and `\xNN` escapes, and
/// `%%` and `$$` for a literal `%` and `$`. `None` for anything else, which
/// no release wrote.
fn split_exec(exec: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut chars = exec.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| *c == ' ') {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            return Some(words);
        };
        let mut word = String::new();
        let quoted = first == '"';
        if quoted {
            chars.next();
        }
        loop {
            match chars.next() {
                None if quoted => return None,
                None => break,
                Some('"') if quoted => break,
                Some(' ') if !quoted => break,
                Some('\\') if quoted => match chars.next()? {
                    '"' => word.push('"'),
                    '\\' => word.push('\\'),
                    'n' => word.push('\n'),
                    't' => word.push('\t'),
                    'x' => {
                        let hex: String = [chars.next()?, chars.next()?].iter().collect();
                        word.push(char::from(u8::from_str_radix(&hex, 16).ok()?));
                    }
                    _ => return None,
                },
                Some(c @ ('%' | '$')) => {
                    if chars.next()? != c {
                        return None;
                    }
                    word.push(c);
                }
                Some(c) => word.push(c),
            }
        }
        words.push(word);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB_0_0_1: &str = include_str!("../../tests/fixtures/units/stop-bots-web-0.0.1.service");
    const WEB_0_0_6: &str = include_str!("../../tests/fixtures/units/stop-bots-web-0.0.6.service");
    const WEB_0_0_12: &str =
        include_str!("../../tests/fixtures/units/stop-bots-web-0.0.12.service");
    const WEB_0_0_15: &str =
        include_str!("../../tests/fixtures/units/stop-bots-web-0.0.15.service");

    /// Each release's own golden unit, as it shipped, is recognised.
    #[test]
    fn every_released_web_unit_is_recognised() {
        for (text, releases, root) in [
            (WEB_0_0_1, "0.0.1 to 0.0.6", Some("/etc/nginx")),
            (WEB_0_0_6, "0.0.1 to 0.0.6", Some("/etc/nginx")),
            (WEB_0_0_12, "0.0.7 to 0.0.15", None),
            (WEB_0_0_15, "0.0.7 to 0.0.15", None),
        ] {
            assert_eq!(
                web_unit(text),
                Some(LegacyWebUnit {
                    releases,
                    root: root.map(PathBuf::from)
                }),
                "{releases}:\n{text}"
            );
        }
    }

    /// The paths are whatever the installer was given; only they may vary.
    #[test]
    fn a_legacy_unit_with_other_paths_is_still_recognised() {
        for exec in [
            "/opt/sb/stop-bots web --db /srv/sb.db",
            "/opt/sb/stop-bots web --db /srv/sb.db --ssh-log /srv/log/auth.log",
            // 0.0.13 on quoted a path systemd would misread.
            r#""/opt/stop bots/stop-bots" web --db /var/lib/100%%/db.sqlite3"#,
        ] {
            let text = WEB_0_0_15.replace(
                "ExecStart=/usr/local/bin/stop-bots web --db /var/lib/stop-bots/db.sqlite3",
                &format!("ExecStart={exec}"),
            );
            assert!(web_unit(&text).is_some(), "not recognised: {exec}");
        }
    }

    /// Anything a release would not have written is an edit.
    #[test]
    fn an_edited_legacy_unit_is_not_recognised() {
        let edits = [
            (
                "an added flag",
                WEB_0_0_15.replace("db.sqlite3\n", "db.sqlite3 --no-apply\n"),
            ),
            (
                "a changed directive",
                WEB_0_0_15.replace("RestartSec=5s", "RestartSec=30s"),
            ),
            (
                "an added line",
                WEB_0_0_15.replace("[Install]", "Nice=10\n\n[Install]"),
            ),
            (
                "--root from 0.0.7 on",
                WEB_0_0_15.replace("db.sqlite3\n", "db.sqlite3 --root /srv/nginx\n"),
            ),
            (
                "no --root before 0.0.7",
                WEB_0_0_6.replace(" --root /etc/nginx", ""),
            ),
            (
                "doubled spacing",
                WEB_0_0_15.replace(" web --db", "  web --db"),
            ),
            (
                "a trailing newline removed",
                WEB_0_0_15.trim_end().to_string(),
            ),
        ];
        for (what, text) in edits {
            assert_eq!(web_unit(&text), None, "{what} was taken for unedited");
        }
    }

    #[test]
    fn both_released_firewall_units_are_recognised_and_an_edit_is_not() {
        let nft =
            include_str!("../../tests/fixtures/units/stop-bots-firewall-nftables-0.0.15.service");
        let ipt =
            include_str!("../../tests/fixtures/units/stop-bots-firewall-iptables-0.0.15.service");
        assert_eq!(firewall_unit(nft), Some("0.0.5 to 0.0.15"));
        assert_eq!(firewall_unit(ipt), Some("0.0.13 to 0.0.15"));
        assert_eq!(
            firewall_unit(&nft.replace("After=docker.service ", "After=")),
            None
        );
    }

    #[test]
    fn exec_lines_split_the_way_systemd_splits_them() {
        for (exec, words) in [
            ("/a web", vec!["/a", "web"]),
            (r#""/a b" web"#, vec!["/a b", "web"]),
            (r#""/a \"b\"\\c" x"#, vec![r#"/a "b"\c"#, "x"]),
            ("/100%% /a$$b", vec!["/100%", "/a$b"]),
            (r#""/a\tb""#, vec!["/a\tb"]),
        ] {
            assert_eq!(
                split_exec(exec),
                Some(words.iter().map(|w| w.to_string()).collect()),
                "{exec}"
            );
        }
        for broken in [r#""/a"#, "/100%", r#""/a\q""#] {
            assert_eq!(split_exec(broken), None, "{broken}");
        }
    }
}
