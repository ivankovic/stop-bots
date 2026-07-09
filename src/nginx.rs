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

//! Discovers NGINX sites by walking a config directory, and injects/removes a
//! sentinel-marked `if ($http_user_agent ...) { return 403; }` block inside
//! each site's `server { ... }` block to block unwanted bots.
//!
//! The sentinel comments make the edit idempotent and easy to spot/undo by
//! hand: re-running only ever replaces the marked lines, never anything else
//! in the file.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const BLOCK_BEGIN: &str = "# BEGIN stop-bots (DO NOT EDIT)";
const BLOCK_END: &str = "# END stop-bots";

/// A `server { ... }` block found while scanning a config file.
#[derive(Debug, Clone)]
pub struct ServerBlock {
    pub names: Vec<String>,
    open: usize,
    close: usize,
}

/// A site discovered while scanning a config directory.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredSite {
    pub server_name: String,
    pub config_path: PathBuf,
}

/// Marks which bytes of `content` are outside of a `#`-comment, so that
/// brace/token scanning can ignore commented-out directives (NGINX configs
/// commonly comment out whole blocks line by line).
fn comment_mask(content: &str) -> Vec<bool> {
    let bytes = content.as_bytes();
    let mut mask = vec![true; bytes.len()];
    let mut in_comment = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            in_comment = false;
            continue;
        }
        if in_comment {
            mask[i] = false;
            continue;
        }
        if b == b'#' {
            in_comment = true;
            mask[i] = false;
        }
    }
    mask
}

/// Splits `content` into tokens (`{`, `}`, `;` and bare words), skipping
/// commented-out bytes, alongside the byte offset each token starts at.
fn tokenize(content: &str, mask: &[bool]) -> Vec<(String, usize)> {
    let bytes = content.as_bytes();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut word_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if !mask[i] {
            if !word.is_empty() {
                tokens.push((std::mem::take(&mut word), word_start));
            }
            continue;
        }
        let c = b as char;
        if c == '{' || c == '}' || c == ';' {
            if !word.is_empty() {
                tokens.push((std::mem::take(&mut word), word_start));
            }
            tokens.push((c.to_string(), i));
            continue;
        }
        if c.is_whitespace() {
            if !word.is_empty() {
                tokens.push((std::mem::take(&mut word), word_start));
            }
            continue;
        }
        if word.is_empty() {
            word_start = i;
        }
        word.push(c);
    }
    if !word.is_empty() {
        tokens.push((word, word_start));
    }
    tokens
}

/// Finds every top-level `server { ... }` block in `content`, along with the
/// `server_name` values declared directly inside it.
fn parse_server_blocks(content: &str) -> Vec<ServerBlock> {
    let mask = comment_mask(content);
    let tokens = tokenize(content, &mask);

    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut names_stack: Vec<Vec<String>> = Vec::new();
    let mut blocks = Vec::new();
    let mut prev_word: Option<&str> = None;

    let mut idx = 0;
    while idx < tokens.len() {
        let (tok, off) = &tokens[idx];
        match tok.as_str() {
            "{" => {
                let is_server = prev_word == Some("server");
                stack.push((*off, is_server));
                if is_server {
                    names_stack.push(Vec::new());
                }
                prev_word = None;
            }
            "}" => {
                if let Some((open, is_server)) = stack.pop() {
                    if is_server {
                        let names = names_stack.pop().unwrap_or_default();
                        blocks.push(ServerBlock {
                            names,
                            open,
                            close: *off,
                        });
                    }
                }
                prev_word = None;
            }
            ";" => prev_word = None,
            word => {
                let directly_in_server =
                    stack.last().map(|(_, is_server)| *is_server) == Some(true);
                if word == "server_name" && directly_in_server {
                    let mut j = idx + 1;
                    let mut names = Vec::new();
                    while j < tokens.len()
                        && tokens[j].0 != ";"
                        && tokens[j].0 != "{"
                        && tokens[j].0 != "}"
                    {
                        let name = tokens[j].0.trim_matches(['"', '\'']).to_string();
                        if !name.is_empty() {
                            names.push(name);
                        }
                        j += 1;
                    }
                    if let Some(top) = names_stack.last_mut() {
                        top.extend(names);
                    }
                    idx = j;
                    prev_word = Some(word);
                    continue;
                }
                prev_word = Some(word);
            }
        }
        idx += 1;
    }

    blocks
}

/// Renders the sentinel block content (without surrounding blank lines) for
/// the given combined user-agent regex `pattern`.
fn block_text(pattern: &str) -> String {
    format!(
        "    {BLOCK_BEGIN}\n    if ($http_user_agent ~* \"{pattern}\") {{\n        return 403;\n    }}\n    {BLOCK_END}\n"
    )
}

/// Finds the byte range of an existing sentinel block's lines within
/// `block`, if one is already present.
fn locate_existing_block(content: &str, block: &ServerBlock) -> Option<(usize, usize)> {
    let region = &content[block.open..block.close];
    let begin_rel = region.find(BLOCK_BEGIN)?;
    let begin_abs = block.open + begin_rel;
    let line_start = content[..begin_abs].rfind('\n').map(|i| i + 1).unwrap_or(0);

    let end_rel = region[begin_rel..].find(BLOCK_END)?;
    let end_marker_abs = begin_abs + end_rel + BLOCK_END.len();
    let line_end = content[end_marker_abs..]
        .find('\n')
        .map(|i| end_marker_abs + i + 1)
        .unwrap_or(content.len());

    Some((line_start, line_end))
}

/// Inserts, replaces or removes the sentinel bot-blocking block inside
/// `block`. Pass `None` (or an empty pattern) to remove any existing block.
/// Idempotent: applying the same pattern twice yields identical output.
fn apply_block(content: &str, block: &ServerBlock, pattern: Option<&str>) -> String {
    let new_block = pattern.filter(|p| !p.is_empty()).map(block_text);

    match locate_existing_block(content, block) {
        Some((start, end)) => {
            let mut out = String::with_capacity(content.len());
            out.push_str(&content[..start]);
            if let Some(b) = &new_block {
                out.push_str(b);
            }
            out.push_str(&content[end..]);
            out
        }
        None => match new_block {
            Some(b) => {
                let mut out = String::with_capacity(content.len() + b.len() + 1);
                out.push_str(&content[..block.open + 1]);
                out.push('\n');
                out.push_str(&b);
                out.push_str(&content[block.open + 1..]);
                out
            }
            None => content.to_string(),
        },
    }
}

/// Recursively walks `root` looking for NGINX config files containing
/// `server { ... }` blocks, returning one [`DiscoveredSite`] per block (named
/// after its first `server_name`). Files with no server block, or that
/// aren't valid UTF-8 text, are silently skipped.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    let mut sites = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for block in parse_server_blocks(&content) {
            if let Some(name) = block.names.first() {
                sites.push(DiscoveredSite {
                    server_name: name.clone(),
                    config_path: path.to_path_buf(),
                });
            }
        }
    }
    Ok(sites)
}

/// Applies the bot-blocking rule to every `server { ... }` block found in
/// `config_path`. Each block gets the pattern list from `site_patterns`
/// belonging to its own `server_name` (its `names.first()`), or
/// `default_patterns` if that name isn't in `site_patterns` at all (e.g. a
/// block discovered on disk that was never scanned into the db yet). An
/// empty pattern list for a block removes any existing block there. Returns
/// whether the file was actually changed on disk.
///
/// Two blocks sharing the same `server_name` (e.g. a port-80-redirect block
/// plus the real port-443 block for the same site) resolve to the same
/// `site_patterns` entry and so still get the same rule; two blocks with
/// *different* names in the same file now correctly get independent rules.
pub fn apply_blocks_to_file(
    config_path: &Path,
    site_patterns: &[(String, Vec<String>)],
    default_patterns: &[String],
) -> Result<bool> {
    let mut content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    let block_count = parse_server_blocks(&content).len();
    if block_count == 0 {
        return Ok(false);
    }

    // Editing a block shifts the byte offsets of every block after it, so
    // re-parse before each edit rather than reusing stale spans. Block order
    // is stable across re-parses since edits only rewrite sentinel lines
    // inside existing braces, never add or remove server blocks.
    let mut changed = false;
    for i in 0..block_count {
        let blocks = parse_server_blocks(&content);
        let block = &blocks[i];
        let patterns = block
            .names
            .first()
            .and_then(|name| site_patterns.iter().find(|(n, _)| n == name))
            .map(|(_, patterns)| patterns.as_slice())
            .unwrap_or(default_patterns);
        let pattern = (!patterns.is_empty()).then(|| patterns.join("|"));
        let updated = apply_block(&content, block, pattern.as_deref());
        if updated != content {
            changed = true;
            content = updated;
        }
    }

    if !changed {
        return Ok(false);
    }
    fs::write(config_path, &content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(true)
}

/// Whether a site's on-disk config currently matches the blocking rule
/// that would be computed for it right now — backs the TUI's per-site
/// status tag in Site settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteApplyStatus {
    /// Every `server` block for this name already carries the expected
    /// rule (or none is expected and none is present).
    UpToDate,
    /// At least one block for this name is missing the expected rule, or
    /// carries a different one.
    Stale,
    /// The config file couldn't be read, or no `server` block in it
    /// declares this `server_name` anymore (e.g. renamed or removed on
    /// disk since the last scan).
    NotFound,
}

/// Extracts the user-agent pattern currently applied inside `block`'s
/// sentinel rule, if any. Anchored to the sentinel's own line range (via
/// `locate_existing_block`), not just searched for anywhere in the whole
/// block — a hand-written `if ($http_user_agent ~* "...")` or similar
/// regex condition elsewhere in the same `server { ... }` would otherwise
/// be picked up as "the" applied pattern and make an up-to-date site
/// permanently read as stale.
fn current_block_pattern(content: &str, block: &ServerBlock) -> Option<String> {
    let (start, end) = locate_existing_block(content, block)?;
    let region = &content[start..end];
    let pattern_start = region.find("~* \"")? + 4;
    let rest = &region[pattern_start..];
    let pattern_end = rest.find('"')?;
    Some(rest[..pattern_end].to_string())
}

/// Compares what's actually written in `config_path` for `server_name`
/// against `patterns` (the currently computed blocking rule for that
/// site) without changing anything on disk.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    patterns: &[String],
) -> SiteApplyStatus {
    let Ok(content) = fs::read_to_string(config_path) else {
        return SiteApplyStatus::NotFound;
    };
    let blocks = parse_server_blocks(&content);
    let matching: Vec<&ServerBlock> = blocks
        .iter()
        .filter(|b| b.names.first().map(String::as_str) == Some(server_name))
        .collect();
    if matching.is_empty() {
        return SiteApplyStatus::NotFound;
    }
    let expected = (!patterns.is_empty()).then(|| patterns.join("|"));
    if matching
        .iter()
        .all(|block| current_block_pattern(&content, block) == expected)
    {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

/// Applies `patterns` only to the `server { ... }` block(s) in
/// `config_path` whose first `server_name` is `server_name`, leaving
/// every other block in the file completely untouched — unlike
/// [`apply_blocks_to_file`], which resets every block it has no explicit
/// entry for back to `default_patterns`. This backs the TUI's per-site
/// "Apply now" action: applying one site's overrides must never silently
/// rewrite an unrelated site sharing the same file. Returns whether the
/// file was actually changed on disk.
pub fn apply_block_for_site(
    config_path: &Path,
    server_name: &str,
    patterns: &[String],
) -> Result<bool> {
    let mut content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    let block_count = parse_server_blocks(&content).len();
    let pattern = (!patterns.is_empty()).then(|| patterns.join("|"));

    // Same re-parse-before-each-edit approach as apply_blocks_to_file:
    // editing a block shifts the byte offsets of every block after it.
    let mut changed = false;
    for i in 0..block_count {
        let blocks = parse_server_blocks(&content);
        let block = &blocks[i];
        if block.names.first().map(String::as_str) != Some(server_name) {
            continue;
        }
        let updated = apply_block(&content, block, pattern.as_deref());
        if updated != content {
            changed = true;
            content = updated;
        }
    }

    if !changed {
        return Ok(false);
    }
    fs::write(config_path, &content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const FIXTURES_ROOT: &str = "tests/fixtures/nginx";

    #[test]
    fn discover_sites_finds_both_fixture_sites() {
        let mut sites = discover_sites(Path::new(FIXTURES_ROOT)).unwrap();
        sites.sort_by(|a, b| a.server_name.cmp(&b.server_name));

        let names: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
        assert_eq!(names, vec!["example.com", "localhost"]);
    }

    #[test]
    fn parse_server_blocks_ignores_commented_braces() {
        let content = fs::read_to_string(format!("{FIXTURES_ROOT}/conf.d/server.conf")).unwrap();
        let blocks = parse_server_blocks(&content);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].names, vec!["localhost"]);
    }

    #[test]
    fn parse_server_blocks_reads_multiple_server_names() {
        let content =
            fs::read_to_string(format!("{FIXTURES_ROOT}/sites-enabled/example.com")).unwrap();
        let blocks = parse_server_blocks(&content);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].names, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn apply_block_inserts_and_is_idempotent() {
        let content = "server {\n    listen 80;\n}\n".to_string();
        let block = parse_server_blocks(&content).remove(0);

        let once = apply_block(&content, &block, Some("BadBot|EvilCrawler"));
        assert!(once.contains(BLOCK_BEGIN));
        assert!(once.contains("BadBot|EvilCrawler"));
        assert!(once.contains("return 403;"));

        let block_again = parse_server_blocks(&once).remove(0);
        let twice = apply_block(&once, &block_again, Some("BadBot|EvilCrawler"));
        assert_eq!(once, twice);
    }

    #[test]
    fn apply_block_replaces_pattern_on_update() {
        let content = "server {\n    listen 80;\n}\n".to_string();
        let block = parse_server_blocks(&content).remove(0);
        let first = apply_block(&content, &block, Some("OldBot"));

        let block_again = parse_server_blocks(&first).remove(0);
        let second = apply_block(&first, &block_again, Some("NewBot"));

        assert!(!second.contains("OldBot"));
        assert!(second.contains("NewBot"));
        assert_eq!(second.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn apply_block_with_no_patterns_removes_existing_block() {
        let content = "server {\n    listen 80;\n}\n".to_string();
        let block = parse_server_blocks(&content).remove(0);
        let with_block = apply_block(&content, &block, Some("BadBot"));

        let block_again = parse_server_blocks(&with_block).remove(0);
        let removed = apply_block(&with_block, &block_again, None);

        assert!(!removed.contains(BLOCK_BEGIN));
        assert!(removed.contains("listen 80;"));
    }

    #[test]
    fn apply_block_only_touches_the_targeted_server_block() {
        let content =
            "server {\n    server_name a.example;\n}\nserver {\n    server_name b.example;\n}\n";
        let blocks = parse_server_blocks(content);
        assert_eq!(blocks.len(), 2);

        let target = blocks
            .iter()
            .find(|b| b.names == vec!["b.example"])
            .unwrap();
        let updated = apply_block(content, target, Some("BadBot"));

        let updated_blocks = parse_server_blocks(&updated);
        let a_region = &updated[updated_blocks[0].open..updated_blocks[0].close];
        let b_region = &updated[updated_blocks[1].open..updated_blocks[1].close];
        assert!(!a_region.contains(BLOCK_BEGIN));
        assert!(b_region.contains(BLOCK_BEGIN));
    }

    #[test]
    fn apply_blocks_to_file_writes_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(
            &path,
            fs::read_to_string(format!("{FIXTURES_ROOT}/sites-enabled/example.com")).unwrap(),
        )
        .unwrap();

        let patterns = vec!["BadBot".to_string(), "EvilCrawler".to_string()];
        let changed = apply_blocks_to_file(&path, &[], &patterns).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains(BLOCK_BEGIN));
        assert!(written.contains("BadBot|EvilCrawler"));

        let changed_again = apply_blocks_to_file(&path, &[], &patterns).unwrap();
        assert!(!changed_again);
    }

    #[test]
    fn apply_blocks_to_file_with_no_server_blocks_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx.conf");
        fs::write(&path, "events {}\nhttp {\n    include conf.d/*.conf;\n}\n").unwrap();

        let changed = apply_blocks_to_file(&path, &[], &["BadBot".to_string()]).unwrap();
        assert!(!changed);
        assert!(!fs::read_to_string(&path).unwrap().contains(BLOCK_BEGIN));
    }

    /// Regression test: a redirect-plus-main-site file has two `server`
    /// blocks sharing the same `server_name`. Both must get the rule, not
    /// just whichever one a name lookup happens to find first.
    #[test]
    fn apply_blocks_to_file_covers_every_block_with_the_same_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(
            &path,
            "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}\n\
             server {\n    listen 443 ssl;\n    server_name example.com;\n    root /var/www;\n}\n",
        )
        .unwrap();

        let changed = apply_blocks_to_file(&path, &[], &["BadBot".to_string()]).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written.matches(BLOCK_BEGIN).count(), 2);

        let blocks = parse_server_blocks(&written);
        assert_eq!(blocks.len(), 2);
        for block in &blocks {
            let region = &written[block.open..block.close];
            assert!(region.contains(BLOCK_BEGIN));
        }
    }

    #[test]
    fn apply_blocks_to_file_applies_different_patterns_per_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-site.conf");
        fs::write(
            &path,
            "server {\n    listen 80;\n    server_name a.example;\n}\n\
             server {\n    listen 80;\n    server_name b.example;\n}\n",
        )
        .unwrap();

        let site_patterns = vec![
            ("a.example".to_string(), vec!["OnlyOnA".to_string()]),
            ("b.example".to_string(), vec!["OnlyOnB".to_string()]),
        ];
        let changed = apply_blocks_to_file(&path, &site_patterns, &[]).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        let blocks = parse_server_blocks(&written);
        let a_region = &written[blocks[0].open..blocks[0].close];
        let b_region = &written[blocks[1].open..blocks[1].close];
        assert!(a_region.contains("OnlyOnA"));
        assert!(!a_region.contains("OnlyOnB"));
        assert!(b_region.contains("OnlyOnB"));
        assert!(!b_region.contains("OnlyOnA"));
    }

    #[test]
    fn apply_blocks_to_file_falls_back_to_default_patterns_for_an_unknown_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unscanned.conf");
        fs::write(
            &path,
            "server {\n    listen 80;\n    server_name unscanned.example;\n}\n",
        )
        .unwrap();

        // No entry for "unscanned.example" in site_patterns at all (as if
        // it was just discovered on disk but never scanned into the db).
        let changed = apply_blocks_to_file(&path, &[], &["GlobalDefaultBot".to_string()]).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("GlobalDefaultBot"));
    }

    #[test]
    fn site_apply_status_reports_not_found_for_a_missing_file() {
        let status = site_apply_status(
            Path::new("/nonexistent/does-not-exist.conf"),
            "example.com",
            &["BadBot".to_string()],
        );
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_reports_not_found_when_the_server_name_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "b.example", &["BadBot".to_string()]);
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_is_up_to_date_when_nothing_is_expected_and_nothing_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "a.example", &[]);
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    #[test]
    fn site_apply_status_is_stale_when_a_rule_is_expected_but_not_yet_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "a.example", &["BadBot".to_string()]);
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    #[test]
    fn site_apply_status_is_up_to_date_once_the_matching_rule_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(
            &path,
            "a.example",
            &["BadBot".to_string(), "EvilBot".to_string()],
        )
        .unwrap();

        let status = site_apply_status(
            &path,
            "a.example",
            &["BadBot".to_string(), "EvilBot".to_string()],
        );
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    /// Regression test: a hand-written user-agent regex condition elsewhere
    /// in the same server block, ahead of our sentinel, must not be
    /// mistaken for our own applied pattern.
    #[test]
    fn site_apply_status_ignores_a_hand_written_user_agent_check_ahead_of_the_sentinel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(
            &path,
            "server {\n    server_name a.example;\n    if ($http_user_agent ~* \"AdminBot\") { return 403; }\n}\n",
        )
        .unwrap();
        apply_block_for_site(&path, "a.example", &["BadBot".to_string()]).unwrap();

        let status = site_apply_status(&path, "a.example", &["BadBot".to_string()]);
        assert_eq!(status, SiteApplyStatus::UpToDate);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("AdminBot"));
        assert!(written.contains("BadBot"));
    }

    #[test]
    fn site_apply_status_is_stale_when_the_applied_pattern_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &["OldBot".to_string()]).unwrap();

        let status = site_apply_status(&path, "a.example", &["NewBot".to_string()]);
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    #[test]
    fn apply_block_for_site_only_touches_the_named_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-site.conf");
        fs::write(
            &path,
            "server {\n    listen 80;\n    server_name a.example;\n}\n\
             server {\n    listen 80;\n    server_name b.example;\n}\n",
        )
        .unwrap();

        let changed = apply_block_for_site(&path, "a.example", &["OnlyOnA".to_string()]).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        let blocks = parse_server_blocks(&written);
        let a_region = &written[blocks[0].open..blocks[0].close];
        let b_region = &written[blocks[1].open..blocks[1].close];
        assert!(a_region.contains("OnlyOnA"));
        assert!(!b_region.contains(BLOCK_BEGIN));
    }

    #[test]
    fn apply_block_for_site_is_a_noop_once_already_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        assert!(apply_block_for_site(&path, "a.example", &["BadBot".to_string()]).unwrap());
        assert!(!apply_block_for_site(&path, "a.example", &["BadBot".to_string()]).unwrap());
    }

    #[test]
    fn apply_block_for_site_is_a_noop_for_an_unknown_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let original = "server {\n    server_name a.example;\n}\n";
        fs::write(&path, original).unwrap();

        let changed =
            apply_block_for_site(&path, "unknown.example", &["BadBot".to_string()]).unwrap();
        assert!(!changed);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}
