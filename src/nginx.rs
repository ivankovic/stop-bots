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

/// Whether `pattern` can be embedded verbatim inside the double-quoted
/// NGINX string [`block_text`] builds, without corrupting the surrounding
/// config. Two conditions:
///
/// - No literal `"` — would end the string early (each botlist parser
///   already filters this at the source, but this is the last line of
///   defense for any pattern that reaches here some other way, including a
///   row already stored in the db from before a parser had this filter).
/// - Doesn't end in a backslash — NGINX's config parser treats `\"`
///   immediately before what would be our closing quote as an *escaped*
///   quote, not a terminator, so a trailing backslash on the last pattern
///   joined into the string leaves the quoted state open. NGINX then keeps
///   scanning for a real closing quote through the rest of the file and
///   reports `too long parameter, probably missing terminating """
///   character` once it hits EOF still "inside" the string — confirmed
///   against a real `nginx -t`. (A trailing backslash *pair* avoids that
///   specific failure by collapsing to one backslash before the closing
///   quote, but that one leftover backslash then fails regex compilation
///   instead — `pcre2_compile() failed: \ at end of pattern` — so any
///   trailing backslash at all is treated as unsafe, not just an odd run.)
fn is_embeddable(pattern: &str) -> bool {
    !pattern.contains('"') && !pattern.ends_with('\\')
}

/// Joins the patterns in `patterns` that are safe to embed (see
/// [`is_embeddable`]) into a single `|`-separated NGINX regex, or `None` if
/// none remain — the same "nothing to block" case as an empty pattern list,
/// which removes any existing sentinel block instead of writing an empty
/// one.
fn join_patterns(patterns: &[String]) -> Option<String> {
    let safe: Vec<&str> = patterns
        .iter()
        .map(String::as_str)
        .filter(|p| is_embeddable(p))
        .collect();
    (!safe.is_empty()).then(|| safe.join("|"))
}

/// Maximum byte length of a single chunk [`chunk_pattern`] produces.
///
/// NGINX's config-file parser has a hard ceiling on the length of a single
/// quoted parameter — confirmed empirically against a real `nginx -t`:
/// even a *properly terminated* quoted string fails with `too long
/// parameter, probably missing terminating """ character` once it crosses
/// roughly 4100 bytes (matching `NGX_CONF_BUFFER`), regardless of what
/// precedes it in the file. This is unrelated to the quote-escaping issue
/// [`is_embeddable`] guards against — even a config free of embedding bugs
/// can still hit this purely from having enough blocked bots: the
/// `nginx-bad-bots` source alone is ~700 entries, easily exceeding 4096
/// bytes once joined with `|`. Set well below the observed failure point to
/// stay safe regardless of how much unrelated content precedes the
/// sentinel block in a real config file (confirmed empirically too: a
/// 2000-byte quoted parameter still parses fine even after ~10KB of
/// preceding file content).
const MAX_PATTERN_CHUNK_LEN: usize = 2000;

/// Splits `full` (a `|`-joined NGINX regex, as produced by [`join_patterns`])
/// into pieces of at most `max_len` bytes each, splitting only on `|`
/// boundaries so no individual alternative is ever cut in half. A single
/// alternative longer than `max_len` on its own still becomes its own
/// (oversized) chunk rather than being dropped or truncated — better to
/// risk that rare case than silently stop blocking a legitimate pattern.
fn chunk_pattern(full: &str, max_len: usize) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    for part in full.split('|') {
        match chunks.last_mut() {
            Some(last) if last.len() + 1 + part.len() <= max_len => {
                last.push('|');
                last.push_str(part);
            }
            _ => chunks.push(part.to_string()),
        }
    }
    chunks
}

/// Renders the sentinel block content (without surrounding blank lines) for
/// the given combined user-agent regex `pattern`, split (via
/// [`chunk_pattern`]) into one `if` statement per chunk if it's long enough
/// to need it. Multiple sequential `if ($http_user_agent ~* "...") { return
/// 403; }` statements are equivalent to one big alternation — whichever
/// fires first returns 403 — so splitting changes nothing about what gets
/// blocked, only how it's written, and a pattern short enough for one chunk
/// renders exactly as before (a single `if`).
fn block_text(pattern: &str) -> String {
    let mut out = format!("    {BLOCK_BEGIN}\n");
    for chunk in chunk_pattern(pattern, MAX_PATTERN_CHUNK_LEN) {
        out.push_str(&format!(
            "    if ($http_user_agent ~* \"{chunk}\") {{\n        return 403;\n    }}\n"
        ));
    }
    out.push_str(&format!("    {BLOCK_END}\n"));
    out
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
        let pattern = join_patterns(patterns);
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

    // A pattern long enough to need [`chunk_pattern`]'s splitting renders as
    // more than one `if` statement (see `block_text`), so every occurrence
    // has to be collected and rejoined with `|` to reconstruct the full
    // pattern — not just the first one. Safe to search for a bare `"` as
    // each chunk's end even though patterns can contain arbitrary text: no
    // pattern ever contains a literal `"` itself (`is_embeddable` rejects
    // those before they're ever written), so the first `"` after each
    // `~* "` marker is always that chunk's real closing quote.
    let mut patterns = Vec::new();
    let mut rest = region;
    while let Some(marker) = rest.find("~* \"") {
        let after = &rest[marker + 4..];
        let Some(end) = after.find('"') else { break };
        patterns.push(&after[..end]);
        rest = &after[end + 1..];
    }
    (!patterns.is_empty()).then(|| patterns.join("|"))
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
    let expected = join_patterns(patterns);
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
    let pattern = join_patterns(patterns);

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

/// Validates the currently-installed NGINX config with `nginx -t`. Run
/// before every [`reload`] so a malformed config — ours or an unrelated
/// hand edit elsewhere in the same install — is reported as a clear error
/// here rather than left for the admin to dig out of `systemctl status`.
fn test_config() -> Result<()> {
    let output = std::process::Command::new("nginx")
        .arg("-t")
        .output()
        .context("failed to run `nginx -t`")?;
    if !output.status.success() {
        anyhow::bail!(
            "nginx -t failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Reloads NGINX via `systemctl reload nginx` so a just-written blocking
/// rule (from [`apply_blocks_to_file`] or [`apply_block_for_site`]) actually
/// takes effect — writing the sentinel block to a site's config file alone
/// does nothing until NGINX re-reads it. Always preceded by [`test_config`]:
/// `systemctl reload` refuses a config that fails validation on its own too,
/// but checking explicitly here gets a message callers can show directly
/// rather than send the admin to `systemctl status`/`journalctl`.
pub fn reload() -> Result<()> {
    test_config()?;
    let status = std::process::Command::new("systemctl")
        .args(["reload", "nginx"])
        .status()
        .context("failed to run `systemctl reload nginx`")?;
    if !status.success() {
        anyhow::bail!("systemctl reload nginx exited with {status}");
    }
    Ok(())
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

    #[test]
    fn is_embeddable_rejects_a_literal_quote() {
        assert!(!is_embeddable("Evil\"Bot"));
    }

    #[test]
    fn is_embeddable_rejects_any_trailing_backslash_run() {
        assert!(!is_embeddable("EvilBot\\"));
        assert!(!is_embeddable("EvilBot\\\\"));
        assert!(!is_embeddable("EvilBot\\\\\\"));
    }

    #[test]
    fn is_embeddable_accepts_an_interior_backslash() {
        assert!(is_embeddable("1h4x\\.com"));
    }

    #[test]
    fn join_patterns_drops_only_the_unsafe_entries() {
        let patterns = vec![
            "GoodBot".to_string(),
            "Trailing\\".to_string(),
            "1h4x\\.com".to_string(),
        ];
        assert_eq!(
            join_patterns(&patterns).as_deref(),
            Some("GoodBot|1h4x\\.com")
        );
    }

    #[test]
    fn join_patterns_is_none_when_every_pattern_is_unsafe() {
        let patterns = vec!["Trailing\\".to_string(), "Quoted\"Bot".to_string()];
        assert_eq!(join_patterns(&patterns), None);
    }

    /// Regression test for a real bug: a bot pattern ending in a backslash,
    /// if it happened to land last in the joined `|`-separated regex, wrote
    /// an NGINX config that failed `nginx -t` with "too long parameter,
    /// probably missing terminating \" character" — confirmed against a
    /// real `nginx -t` binary. `apply_blocks_to_file` must silently drop
    /// such a pattern rather than write it.
    #[test]
    fn apply_blocks_to_file_drops_a_pattern_with_a_trailing_backslash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(
            &path,
            fs::read_to_string(format!("{FIXTURES_ROOT}/sites-enabled/example.com")).unwrap(),
        )
        .unwrap();

        let patterns = vec!["GoodBot".to_string(), "TrailingBackslash\\".to_string()];
        apply_blocks_to_file(&path, &[], &patterns).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("GoodBot"));
        assert!(!written.contains("TrailingBackslash"));
        // The sentinel's own closing quote must be the last character
        // before the closing paren, i.e. immediately followed by `) {` —
        // not swallowed into an unterminated string.
        assert!(written.contains("~* \"GoodBot\") {"));
    }

    #[test]
    fn chunk_pattern_keeps_everything_in_one_chunk_when_it_fits() {
        let chunks = chunk_pattern("A|B|C", 2000);
        assert_eq!(chunks, vec!["A|B|C".to_string()]);
    }

    #[test]
    fn chunk_pattern_splits_only_on_pipe_boundaries_once_the_limit_is_hit() {
        // Each part is 5 bytes ("AAAAA" etc, 4 chars + digit); a limit of 11
        // fits exactly two parts plus their separator (5 + 1 + 5 = 11) but
        // not three.
        let full = "AAAA0|AAAA1|AAAA2|AAAA3";
        let chunks = chunk_pattern(full, 11);
        assert_eq!(
            chunks,
            vec!["AAAA0|AAAA1".to_string(), "AAAA2|AAAA3".to_string()]
        );
        // Rejoining every chunk with `|` must reconstruct the original,
        // order preserved — this is the property `current_block_pattern`
        // relies on to read a chunked block back correctly.
        assert_eq!(chunks.join("|"), full);
    }

    #[test]
    fn chunk_pattern_gives_an_oversized_single_part_its_own_chunk_rather_than_dropping_it() {
        let huge = "x".repeat(50);
        let chunks = chunk_pattern(&huge, 10);
        assert_eq!(chunks, vec![huge]);
    }

    /// Regression test for the real bug: NGINX's config parser rejects any
    /// single quoted parameter beyond roughly 4100 bytes with `too long
    /// parameter, probably missing terminating """ character` — confirmed
    /// against a real `nginx -t`, and easily reached by a realistic
    /// default bot list (`nginx-bad-bots` alone is ~700 entries). A single
    /// giant `if` block must not be written; `block_text` should split into
    /// several instead, each safely under the limit.
    #[test]
    fn apply_blocks_to_file_splits_a_long_pattern_list_into_multiple_if_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(
            &path,
            fs::read_to_string(format!("{FIXTURES_ROOT}/sites-enabled/example.com")).unwrap(),
        )
        .unwrap();

        // Comfortably more than MAX_PATTERN_CHUNK_LEN once joined with `|`.
        let patterns: Vec<String> = (0..500).map(|i| format!("BadBot{i}Agent")).collect();
        apply_blocks_to_file(&path, &[], &patterns).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        let if_count = written.matches("if ($http_user_agent").count();
        assert!(if_count > 1, "expected multiple if blocks, got {if_count}");
        for line in written.lines() {
            assert!(
                line.len() < MAX_PATTERN_CHUNK_LEN + 100,
                "line exceeds the safe chunk length: {} bytes",
                line.len()
            );
        }
        assert!(written.contains("BadBot0Agent"));
        assert!(written.contains("BadBot499Agent"));
    }

    /// A chunked block (multiple `if` statements) must still be read back
    /// correctly by `site_apply_status` — otherwise every site with a long
    /// enough pattern list would permanently read `Stale` even right after
    /// applying, since `current_block_pattern` would only ever see the
    /// first chunk.
    #[test]
    fn site_apply_status_is_up_to_date_after_applying_a_chunked_pattern_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let patterns: Vec<String> = (0..500).map(|i| format!("BadBot{i}Agent")).collect();
        apply_block_for_site(&path, "a.example", &patterns).unwrap();

        let status = site_apply_status(&path, "a.example", &patterns);
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }
}
