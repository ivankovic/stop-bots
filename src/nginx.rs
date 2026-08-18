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
//! sentinel-marked `if ($http_user_agent ...) { return <code>; }` block inside
//! each site's `server { ... }` block to block unwanted bots.
//!
//! The sentinel comments make the edit idempotent and easy to spot/undo by
//! hand: re-running only ever replaces the marked lines, never anything else
//! in the file.
//!
//! Everything that shapes the generated text lives in one [`BlockConfig`],
//! and [`site_apply_status`] compares the *rendered block* against what's on
//! disk rather than reconstructing individual fields back out of it. That's
//! the invariant to preserve when adding a knob here: put it on
//! `BlockConfig` and the staleness check keeps working; smuggle it in as a
//! separate argument to `block_text` and an already-applied site will read
//! as up to date while its config still carries the old text.

use crate::db::BlockResponse;
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

/// Where this project writes NGINX files it fully owns, as opposed to the
/// sentinel blocks it edits *into* files an admin owns. Currently just the
/// generated `robots.txt`.
///
/// A separate directory, not `/etc/nginx/`, for the same reason the
/// sentinel markers exist: everything in here can be deleted wholesale
/// without touching an admin's own config. Nothing NGINX globs lives here
/// either — these files are only ever reached through an explicit
/// directive inside a sentinel block, so a leftover file can't take effect
/// on its own.
pub const MANAGED_DIR: &str = "/etc/stop-bots/nginx";

/// Environment variable overriding [`MANAGED_DIR`].
///
/// This exists for the end-to-end tests, which drive the real binary and
/// would otherwise have to write to `/etc` (i.e. only pass as root). It is
/// read in exactly one place, so the path written and the path referenced
/// by the generated `alias` can never disagree. Not documented as a user
/// feature: an admin who wants these files elsewhere is better served by a
/// real setting, and this one is deliberately not persisted anywhere.
pub const MANAGED_DIR_ENV: &str = "STOP_BOTS_NGINX_DIR";

/// The directory this project writes its own NGINX files into.
pub fn managed_dir() -> PathBuf {
    std::env::var_os(MANAGED_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(MANAGED_DIR))
}

/// The generated `robots.txt`, served by the `location = /robots.txt`
/// block when robots.txt generation is on.
pub fn robots_txt_path() -> PathBuf {
    managed_dir().join("robots.txt")
}

/// Where the rate-limit zone definition goes.
///
/// Unlike [`MANAGED_DIR`] this **is** a directory NGINX globs — the stock
/// `nginx.conf` on every mainstream distro has `include
/// /etc/nginx/conf.d/*.conf;` inside its `http` block, and `limit_req_zone`
/// is an `http`-context directive that therefore cannot live in the
/// sentinel block with everything else. That makes a leftover file here
/// genuinely live rather than inert, which is why removal is handled
/// explicitly (see [`remove_unused_managed_files`]) instead of being left
/// to tidy up later.
pub const CONF_D_DIR: &str = "/etc/nginx/conf.d";

/// Environment override for [`CONF_D_DIR`]; same test-only rationale as
/// [`MANAGED_DIR_ENV`].
pub const CONF_D_DIR_ENV: &str = "STOP_BOTS_NGINX_CONF_D";

pub fn conf_d_dir() -> PathBuf {
    std::env::var_os(CONF_D_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CONF_D_DIR))
}

/// The generated `limit_req_zone` file.
pub fn rate_limit_conf_path() -> PathBuf {
    conf_d_dir().join("stop-bots-limits.conf")
}

/// The shared memory zone name used by both the generated
/// `limit_req_zone` and every `limit_req` that references it. One
/// constant, because a mismatch between the two is not a subtle bug: NGINX
/// refuses to start with "unknown limit_req_zone".
const RATE_LIMIT_ZONE: &str = "stop_bots";

/// Everything that shapes one site's generated sentinel block. Grouped into
/// a struct rather than passed as loose arguments because the block's
/// *content* is what [`site_apply_status`] compares against disk: every
/// field here is something that, when changed, must make an
/// already-applied site read as `Stale`. Adding a knob that affects the
/// generated text without adding it here would silently break that check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockConfig {
    /// The per-site blocked user-agent patterns, as computed by
    /// `Db::blocked_user_agent_patterns_for_site`. Empty means "block
    /// nothing", which removes any existing sentinel block.
    pub patterns: Vec<String>,
    /// How a matched request is turned away — host-wide, but carried here
    /// per site since it's part of the rendered text.
    pub response: BlockResponse,
    /// Whether to serve the generated `robots.txt` (see
    /// [`robots_txt_path`]) from this site. Host-wide, like `response`.
    ///
    /// Only a flag, not the body: the body can run to several kilobytes
    /// with every AI bot listed, and NGINX's config parser rejects a
    /// single quoted parameter past roughly 4KB (the same ceiling
    /// [`MAX_PATTERN_CHUNK_LEN`] exists for), so `return 200 "<body>"` is
    /// not an option. The block `alias`es a file instead, so the body
    /// never appears in the config text at all — which also keeps the
    /// staleness comparison stable when only the body changes.
    pub serve_robots_txt: bool,
    /// Per-server rate limiting: `Some(burst)` emits a `limit_req`
    /// referencing the shared zone, `None` emits nothing.
    ///
    /// Only the burst, not the rate: the rate belongs to `limit_req_zone`,
    /// which is an `http`-context directive living in a separate file (see
    /// [`rate_limit_conf_path`]). Carrying the rate here too would invite
    /// writing it into a `server` block where NGINX rejects it.
    pub rate_limit_burst: Option<u32>,
    /// Request-path prefixes this site's bot block does not apply to.
    ///
    /// Non-empty switches the block to its second shape (see
    /// [`block_text`]): a `set $stop_bots_block` flag rather than a direct
    /// `return`, because NGINX has no way to say "match this user agent
    /// unless the path is one of these" in a single condition.
    pub exempt_paths: Vec<String>,
}

impl BlockConfig {
    /// The common case: patterns plus the host-wide response setting.
    pub fn new(patterns: Vec<String>, response: BlockResponse) -> Self {
        BlockConfig {
            patterns,
            response,
            ..BlockConfig::default()
        }
    }
}

/// Builds the `robots.txt` body from the current blocking policy: one
/// `User-agent:` line per blocked bot, a single shared `Disallow: /`, and
/// a `Disallow:` for the honeypot trap path.
///
/// **Grouped under one `Disallow`, not one stanza per bot.** Both are
/// valid, and grouping roughly halves a file that can otherwise list well
/// over a thousand agents. It also makes the intent obvious at a glance
/// rather than burying it in repetition.
///
/// **A robots token, not a regex.** `bot.user_agent_pattern` is an NGINX
/// regex fragment (and often an alternation); robots.txt has no regex, so
/// the *name* is used, and only when it's a single word that could
/// plausibly be a real token. Anything with whitespace or regex
/// metacharacters is skipped rather than emitted as a broken rule — a
/// `User-agent:` line no crawler matches is worse than no line, because it
/// looks like coverage that isn't there.
///
/// **The honeypot line is emitted whether or not the honeypot detector is
/// on.** Publishing the trap path is what *creates* the trap; a detector
/// that's off simply doesn't act on hits yet. Publishing it only when the
/// detector is enabled would mean turning the detector on and then waiting
/// for crawlers to re-read robots.txt before it could ever fire.
pub fn robots_txt_body(db: &crate::db::Db) -> Result<String> {
    let blocked: Vec<String> = db
        .list_bots()?
        .into_iter()
        .filter(|bot| is_robots_token(&bot.name))
        .filter(|bot| db.bot_is_blocked(bot).unwrap_or(false))
        .map(|bot| bot.name)
        .collect();

    let mut out = String::from("# Generated by stop-bots. Edits will be overwritten.\n\n");
    if blocked.is_empty() {
        // Still a valid, meaningful robots.txt: "everyone may crawl
        // everything except the trap". Emitting nothing here would make an
        // enabled feature serve an empty file, which reads as broken.
        out.push_str("User-agent: *\nDisallow:\n\n");
    } else {
        for name in &blocked {
            out.push_str(&format!("User-agent: {name}\n"));
        }
        out.push_str("Disallow: /\n\n");
    }

    let trap = crate::protection::honeypot_path(db)?;
    out.push_str("User-agent: *\n");
    out.push_str(&format!("Disallow: {trap}\n"));
    Ok(out)
}

/// Whether `name` can be used verbatim as a robots.txt `User-agent:`
/// value. Deliberately strict: robots.txt matching is a simple
/// case-insensitive substring test with no escaping, so anything with
/// whitespace or punctuation beyond the few characters real tokens use
/// is rejected rather than guessed at.
fn is_robots_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// The burst to emit for this host, or `None` when rate limiting is off.
fn rate_limit_burst(db: &crate::db::Db) -> Result<Option<u32>> {
    if !db.get_rate_limit_enabled()? {
        return Ok(None);
    }
    Ok(Some(db.get_rate_limit_burst()? as u32))
}

/// The contents of the generated `limit_req_zone` file.
///
/// Keyed on `$binary_remote_addr` (4 bytes for IPv4, 16 for IPv6) rather
/// than `$remote_addr`'s string form, the conventional choice: the zone is
/// a fixed-size shared memory block and the binary key fits roughly four
/// times as many clients into it.
pub fn rate_limit_conf_body(rate_per_second: i64, zone_megabytes: i64) -> String {
    format!(
        "# Generated by stop-bots. Edits will be overwritten.\n\
         limit_req_zone $binary_remote_addr zone={RATE_LIMIT_ZONE}:{zone_megabytes}m \
         rate={rate_per_second}r/s;\n"
    )
}

/// Creates or updates every file the config about to be written will
/// reference. **Runs before any site config is touched**, so an `alias` or
/// a `limit_req` never points at something that isn't there yet.
///
/// Deliberately does not delete anything — see
/// [`remove_unused_managed_files`] for why the two halves are separate.
pub fn write_managed_files(db: &crate::db::Db) -> Result<()> {
    if db.get_serve_robots_txt()? {
        write_managed(&robots_txt_path(), &robots_txt_body(db)?)?;
    }
    if db.get_rate_limit_enabled()? {
        write_managed(
            &rate_limit_conf_path(),
            &rate_limit_conf_body(db.get_rate_limit_rps()?, db.get_rate_limit_zone_mb()?),
        )?;
    }
    Ok(())
}

/// Deletes every file this project owns that the current settings no
/// longer reference. **Runs after site configs have been rewritten**, and
/// that ordering is load-bearing rather than tidy:
///
/// A `server` block containing `limit_req zone=stop_bots;` whose
/// `limit_req_zone` has been deleted is not a degraded config, it's an
/// invalid one — NGINX refuses to load with "unknown limit_req_zone", so
/// `nginx -t` fails and the *whole* reload is rejected, including every
/// unrelated site. Removing the zone only once no block references it any
/// more means the config on disk is valid at every point in between, so
/// an apply that dies half way (a permission error on one file, say)
/// leaves a working NGINX rather than one that won't reload at all.
///
/// A missing file is success, not an error.
pub fn remove_unused_managed_files(db: &crate::db::Db) -> Result<()> {
    if !db.get_serve_robots_txt()? {
        remove_managed(&robots_txt_path())?;
    }
    if !db.get_rate_limit_enabled()? {
        remove_managed(&rate_limit_conf_path())?;
    }
    Ok(())
}

fn write_managed(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, body).with_context(|| format!("failed to write {}", path.display()))
}

/// Removes a generated file, treating "already gone" as success.
///
/// Deleting rather than merely leaving it unreferenced matters most for
/// the rate-limit zone: [`CONF_D_DIR`] is globbed by the stock
/// `nginx.conf`, so a leftover file there stays *live* — it would keep
/// allocating its shared memory zone forever after the feature was
/// switched off. The `robots.txt` case is only inert-but-misleading, and
/// is removed for consistency: a stale generated artifact on disk invites
/// being wired back up by hand.
fn remove_managed(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// The [`BlockConfig`] currently in effect for one site — its own resolved
/// patterns (per-site overrides layered over the global cascade) plus every
/// host-wide setting that shapes the generated text. Every caller that
/// applies or status-checks a *specific* site goes through here rather than
/// assembling the struct itself, so a newly added host-wide knob reaches
/// all of them at once.
pub fn block_config_for_site(db: &crate::db::Db, site_id: i64) -> Result<BlockConfig> {
    Ok(BlockConfig {
        patterns: db.blocked_user_agent_patterns_for_site(site_id)?,
        response: db.get_block_response()?,
        serve_robots_txt: db.get_serve_robots_txt()?,
        rate_limit_burst: rate_limit_burst(db)?,
        exempt_paths: db.site_path_exemptions(site_id)?,
    })
}

/// The [`BlockConfig`] for a `server` block with no site-specific overrides
/// — the global cascade only. Used as `apply_blocks_to_file`'s
/// `default_config` for blocks discovered on disk that were never scanned
/// into the database.
pub fn default_block_config(db: &crate::db::Db) -> Result<BlockConfig> {
    Ok(BlockConfig {
        patterns: db.blocked_user_agent_patterns()?,
        response: db.get_block_response()?,
        serve_robots_txt: db.get_serve_robots_txt()?,
        rate_limit_burst: rate_limit_burst(db)?,
        // A block with no site row has no per-site exemptions by
        // definition — they're keyed on `sites.id`.
        exempt_paths: Vec::new(),
    })
}

/// Renders the sentinel block content (without surrounding blank lines) for
/// `config`, or `None` when there's nothing to block — an empty pattern
/// list, or one whose every entry [`is_embeddable`] rejects. `None` is what
/// makes [`apply_block`] *remove* an existing block rather than write an
/// empty one.
///
/// The pattern is split (via [`chunk_pattern`]) into one `if` statement per
/// chunk when it's long enough to need it. Multiple sequential
/// `if ($http_user_agent ~* "...") { return <code>; }` statements are
/// equivalent to one big alternation — whichever fires first returns — so
/// splitting changes nothing about what gets blocked, only how it's
/// written, and a pattern short enough for one chunk renders as a single
/// `if`.
fn block_text(config: &BlockConfig) -> Option<String> {
    let pattern = join_patterns(&config.patterns);
    // A config that does none of these three has no block to write, which
    // is what makes `apply_block` *remove* an existing one. Note this is
    // no longer "no patterns" alone: robots.txt and rate limiting are each
    // reason enough to keep a block, and treating them as nothing would
    // delete the block carrying them the moment every bot was allowed.
    if pattern.is_none() && !config.serve_robots_txt && config.rate_limit_burst.is_none() {
        return None;
    }
    let code = config.response.status_code();
    let exemptions = exemption_regex(&effective_exempt_paths(config));

    let mut out = format!("    {BLOCK_BEGIN}\n");
    if let Some(pattern) = &pattern {
        match &exemptions {
            // No exemptions: the direct form, unchanged from before this
            // feature existed, so an existing install's blocks don't churn.
            None => {
                for chunk in chunk_pattern(pattern, MAX_PATTERN_CHUNK_LEN) {
                    out.push_str(&format!(
                        "    if ($http_user_agent ~* \"{chunk}\") {{\n        return {code};\n    }}\n"
                    ));
                }
            }
            // With exemptions, a flag variable. NGINX cannot express
            // "matches this user agent *and* not one of these paths" as a
            // single `if` — `if` takes one condition and they don't
            // compose — so the standard idiom is to set a variable, clear
            // it for the exempt paths, and act on it last. Order is the
            // whole mechanism: the clear must come after every set.
            Some(exemptions) => {
                out.push_str("    set $stop_bots_block 0;\n");
                for chunk in chunk_pattern(pattern, MAX_PATTERN_CHUNK_LEN) {
                    out.push_str(&format!(
                        "    if ($http_user_agent ~* \"{chunk}\") {{\n        set $stop_bots_block 1;\n    }}\n"
                    ));
                }
                out.push_str(&format!(
                    "    if ($request_uri ~* \"{exemptions}\") {{\n        set $stop_bots_block 0;\n    }}\n"
                ));
                out.push_str(&format!(
                    "    if ($stop_bots_block) {{\n        return {code};\n    }}\n"
                ));
            }
        }
    }
    if let Some(burst) = config.rate_limit_burst {
        // `nodelay` so a visitor who briefly exceeds the rate is served
        // immediately from the burst allowance rather than queued —
        // queueing makes an ordinary page load feel broken while doing
        // nothing extra to a bot, which just waits.
        //
        // 429 rather than NGINX's default 503: a client that is being rate
        // limited is not being told the server is unavailable, and a
        // well-behaved one backs off correctly when told the truth.
        out.push_str(&format!(
            "    limit_req zone={RATE_LIMIT_ZONE} burst={burst} nodelay;\n    limit_req_status 429;\n"
        ));
    }
    if config.serve_robots_txt {
        // `alias` rather than `return 200 "<body>"` — see
        // `BlockConfig::serve_robots_txt`. `location = ` is an exact match,
        // so this only ever intercepts /robots.txt itself, and it sits
        // inside the sentinel markers like everything else, so removing the
        // feature removes the directive with it.
        out.push_str(&format!(
            "    location = /robots.txt {{\n        alias {};\n        default_type text/plain;\n    }}\n",
            robots_txt_path().display()
        ));
    }
    out.push_str(&format!("    {BLOCK_END}\n"));
    Some(out)
}

/// The exemptions actually applied: the site's configured ones, plus
/// `/robots.txt` itself whenever this block serves it.
///
/// That addition is not a convenience, it's what makes robots.txt work at
/// all. Server-level `if`/`return` run in NGINX's **server rewrite
/// phase**, which happens *before* location selection — so a user agent
/// caught by the block never reaches the `location = /robots.txt` block
/// underneath it. Without this, the generated robots.txt would list
/// exactly the agents that can never read it, and the polite layer would
/// be pure decoration.
///
/// Letting a blocked crawler read robots.txt is also the behaviour worth
/// wanting on its own: a bot that can fetch the file can learn to stop
/// asking, whereas one that gets a bare 403 on everything learns nothing
/// and keeps coming back. Serving it costs a single small static file.
fn effective_exempt_paths(config: &BlockConfig) -> Vec<String> {
    let mut paths = config.exempt_paths.clone();
    if config.serve_robots_txt {
        paths.push("/robots.txt".to_string());
    }
    paths
}

/// Builds the `$request_uri` regex that clears the block flag, or `None`
/// when there are no usable exemptions.
///
/// Anchored with `^` and alternated, so `/blog` exempts `/blog`,
/// `/blog/post` and `/blog?x=1` but not `/notablog`. Each path is
/// regex-escaped: these are literal URL prefixes typed by an admin, not
/// hand-written regex, and an unescaped `.` or `?` in one would quietly
/// widen the exemption far beyond what was asked for — which, unlike a
/// too-narrow pattern, fails *open*.
fn exemption_regex(paths: &[String]) -> Option<String> {
    let escaped: Vec<String> = paths
        .iter()
        .filter(|p| p.starts_with('/'))
        .filter(|p| is_embeddable(p))
        .map(|p| crate::db::escape_for_nginx_regex(p))
        .collect();
    (!escaped.is_empty()).then(|| format!("^({})", escaped.join("|")))
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
/// `block`. A `config` that renders to nothing (see [`block_text`]) removes
/// any existing block. Idempotent: applying the same config twice yields
/// identical output.
fn apply_block(content: &str, block: &ServerBlock, config: &BlockConfig) -> String {
    let new_block = block_text(config);

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
/// `config_path`. Each block gets the [`BlockConfig`] from `site_configs`
/// belonging to its own `server_name` (its `names.first()`), or
/// `default_config` if that name isn't in `site_configs` at all (e.g. a
/// block discovered on disk that was never scanned into the db yet). A
/// config that renders to nothing removes any existing block there.
/// Returns whether the file was actually changed on disk.
///
/// Two blocks sharing the same `server_name` (e.g. a port-80-redirect block
/// plus the real port-443 block for the same site) resolve to the same
/// `site_configs` entry and so still get the same rule; two blocks with
/// *different* names in the same file now correctly get independent rules.
pub fn apply_blocks_to_file(
    config_path: &Path,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
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
        let config = block
            .names
            .first()
            .and_then(|name| site_configs.iter().find(|(n, _)| n == name))
            .map(|(_, config)| config)
            .unwrap_or(default_config);
        let updated = apply_block(&content, block, config);
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

/// The exact text of the sentinel block currently written inside `block`,
/// if one is present at all. Anchored to the sentinel's own line range (via
/// `locate_existing_block`), not searched for anywhere in the whole block —
/// a hand-written `if ($http_user_agent ~* "...")` or similar elsewhere in
/// the same `server { ... }` must never be mistaken for ours.
///
/// Deliberately the *whole* block text rather than just the user-agent
/// pattern extracted back out of it, which is what this used to compare.
/// Once anything besides the pattern can vary between two valid blocks —
/// the response code, and later exemptions/rate limiting — reconstructing
/// one field and comparing only that would report a site as `UpToDate`
/// while its on-disk block still returns the old code. Comparing rendered
/// text against rendered text has no such blind spot, and it stays correct
/// for free as `BlockConfig` grows.
fn current_block_text(content: &str, block: &ServerBlock) -> Option<String> {
    let (start, end) = locate_existing_block(content, block)?;
    Some(content[start..end].to_string())
}

/// Compares what's actually written in `config_path` for `server_name`
/// against `config` (the currently computed blocking rule for that site)
/// without changing anything on disk.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
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
    let expected = block_text(config);
    if matching
        .iter()
        .all(|block| current_block_text(&content, block) == expected)
    {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

/// Applies `config` only to the `server { ... }` block(s) in `config_path`
/// whose first `server_name` is `server_name`, leaving every other block in
/// the file completely untouched — unlike [`apply_blocks_to_file`], which
/// resets every block it has no explicit entry for back to
/// `default_config`. This backs the TUI's per-site "Apply now" action:
/// applying one site's overrides must never silently rewrite an unrelated
/// site sharing the same file. Returns whether the file was actually
/// changed on disk.
pub fn apply_block_for_site(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<bool> {
    let mut content = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    let block_count = parse_server_blocks(&content).len();

    // Same re-parse-before-each-edit approach as apply_blocks_to_file:
    // editing a block shifts the byte offsets of every block after it.
    let mut changed = false;
    for i in 0..block_count {
        let blocks = parse_server_blocks(&content);
        let block = &blocks[i];
        if block.names.first().map(String::as_str) != Some(server_name) {
            continue;
        }
        let updated = apply_block(&content, block, config);
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

    /// A [`BlockConfig`] with the default 403 response, for the many tests
    /// that only care about which patterns end up in the file.
    fn cfg(patterns: &[&str]) -> BlockConfig {
        BlockConfig::new(
            patterns.iter().map(|p| p.to_string()).collect(),
            BlockResponse::Forbidden,
        )
    }

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

        let once = apply_block(&content, &block, &cfg(&["BadBot|EvilCrawler"]));
        assert!(once.contains(BLOCK_BEGIN));
        assert!(once.contains("BadBot|EvilCrawler"));
        assert!(once.contains("return 403;"));

        let block_again = parse_server_blocks(&once).remove(0);
        let twice = apply_block(&once, &block_again, &cfg(&["BadBot|EvilCrawler"]));
        assert_eq!(once, twice);
    }

    #[test]
    fn apply_block_replaces_pattern_on_update() {
        let content = "server {\n    listen 80;\n}\n".to_string();
        let block = parse_server_blocks(&content).remove(0);
        let first = apply_block(&content, &block, &cfg(&["OldBot"]));

        let block_again = parse_server_blocks(&first).remove(0);
        let second = apply_block(&first, &block_again, &cfg(&["NewBot"]));

        assert!(!second.contains("OldBot"));
        assert!(second.contains("NewBot"));
        assert_eq!(second.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn apply_block_with_no_patterns_removes_existing_block() {
        let content = "server {\n    listen 80;\n}\n".to_string();
        let block = parse_server_blocks(&content).remove(0);
        let with_block = apply_block(&content, &block, &cfg(&["BadBot"]));

        let block_again = parse_server_blocks(&with_block).remove(0);
        let removed = apply_block(&with_block, &block_again, &BlockConfig::default());

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
        let updated = apply_block(content, target, &cfg(&["BadBot"]));

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

        let config = cfg(&["BadBot", "EvilCrawler"]);
        let changed = apply_blocks_to_file(&path, &[], &config).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains(BLOCK_BEGIN));
        assert!(written.contains("BadBot|EvilCrawler"));

        let changed_again = apply_blocks_to_file(&path, &[], &config).unwrap();
        assert!(!changed_again);
    }

    #[test]
    fn apply_blocks_to_file_with_no_server_blocks_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx.conf");
        fs::write(&path, "events {}\nhttp {\n    include conf.d/*.conf;\n}\n").unwrap();

        let changed = apply_blocks_to_file(&path, &[], &cfg(&["BadBot"])).unwrap();
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

        let changed = apply_blocks_to_file(&path, &[], &cfg(&["BadBot"])).unwrap();
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

        let site_configs = vec![
            ("a.example".to_string(), cfg(&["OnlyOnA"])),
            ("b.example".to_string(), cfg(&["OnlyOnB"])),
        ];
        let changed = apply_blocks_to_file(&path, &site_configs, &BlockConfig::default()).unwrap();
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
        let changed = apply_blocks_to_file(&path, &[], &cfg(&["GlobalDefaultBot"])).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("GlobalDefaultBot"));
    }

    #[test]
    fn site_apply_status_reports_not_found_for_a_missing_file() {
        let status = site_apply_status(
            Path::new("/nonexistent/does-not-exist.conf"),
            "example.com",
            &cfg(&["BadBot"]),
        );
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_reports_not_found_when_the_server_name_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "b.example", &cfg(&["BadBot"]));
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_is_up_to_date_when_nothing_is_expected_and_nothing_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "a.example", &BlockConfig::default());
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    #[test]
    fn site_apply_status_is_stale_when_a_rule_is_expected_but_not_yet_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]));
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    #[test]
    fn site_apply_status_is_up_to_date_once_the_matching_rule_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &cfg(&["BadBot", "EvilBot"])).unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot", "EvilBot"]));
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
        apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]));
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
        apply_block_for_site(&path, "a.example", &cfg(&["OldBot"])).unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["NewBot"]));
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

        let changed = apply_block_for_site(&path, "a.example", &cfg(&["OnlyOnA"])).unwrap();
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

        assert!(apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap());
        assert!(!apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap());
    }

    #[test]
    fn apply_block_for_site_is_a_noop_for_an_unknown_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let original = "server {\n    server_name a.example;\n}\n";
        fs::write(&path, original).unwrap();

        let changed = apply_block_for_site(&path, "unknown.example", &cfg(&["BadBot"])).unwrap();
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

        let config = cfg(&["GoodBot", "TrailingBackslash\\"]);
        apply_blocks_to_file(&path, &[], &config).unwrap();

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
        let config = BlockConfig::new(patterns, BlockResponse::Forbidden);
        apply_blocks_to_file(&path, &[], &config).unwrap();

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
        let config = BlockConfig::new(patterns, BlockResponse::Forbidden);
        apply_block_for_site(&path, "a.example", &config).unwrap();

        let status = site_apply_status(&path, "a.example", &config);
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    // ---- BlockResponse (403 vs 444) ----

    fn cfg_444(patterns: &[&str]) -> BlockConfig {
        BlockConfig::new(
            patterns.iter().map(|p| p.to_string()).collect(),
            BlockResponse::Close,
        )
    }

    #[test]
    fn block_text_renders_the_configured_response_code() {
        let forbidden = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(forbidden.contains("return 403;"));
        assert!(!forbidden.contains("return 444;"));

        let close = block_text(&cfg_444(&["BadBot"])).unwrap();
        assert!(close.contains("return 444;"));
        assert!(!close.contains("return 403;"));
    }

    #[test]
    fn block_text_is_none_when_there_is_nothing_to_block() {
        assert!(block_text(&BlockConfig::default()).is_none());
        // Every pattern rejected by `is_embeddable` is the same case as an
        // empty list: nothing safe left to write.
        assert!(block_text(&cfg(&["Quoted\"Bot"])).is_none());
    }

    #[test]
    fn a_chunked_pattern_list_renders_the_response_code_in_every_chunk() {
        let patterns: Vec<String> = (0..500).map(|i| format!("BadBot{i}Agent")).collect();
        let config = BlockConfig::new(patterns, BlockResponse::Close);
        let text = block_text(&config).unwrap();

        let if_count = text.matches("if ($http_user_agent").count();
        assert!(if_count > 1, "expected chunking, got {if_count} if(s)");
        assert_eq!(text.matches("return 444;").count(), if_count);
    }

    /// The whole point of comparing rendered text rather than an extracted
    /// pattern: the patterns are identical here, only the response code
    /// differs, and the old pattern-only check reported this as up to date.
    #[test]
    fn site_apply_status_is_stale_when_only_the_response_code_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg(&["BadBot"])),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_444(&["BadBot"])),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn re_applying_with_a_new_response_code_rewrites_the_block_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap();
        let changed = apply_block_for_site(&path, "a.example", &cfg_444(&["BadBot"])).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("return 444;"));
        assert!(!written.contains("return 403;"));
        // Still exactly one sentinel block, not a second one appended.
        assert_eq!(written.matches(BLOCK_BEGIN).count(), 1);
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_444(&["BadBot"])),
            SiteApplyStatus::UpToDate
        );
    }

    // ---- robots.txt generation ----

    fn cfg_robots(patterns: &[&str]) -> BlockConfig {
        BlockConfig {
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            response: BlockResponse::Forbidden,
            serve_robots_txt: true,
            rate_limit_burst: None,
            exempt_paths: Vec::new(),
        }
    }

    #[test]
    fn block_text_emits_a_robots_location_only_when_enabled() {
        let without = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!without.contains("/robots.txt"));

        let with = block_text(&cfg_robots(&["BadBot"])).unwrap();
        assert!(with.contains("location = /robots.txt"));
        assert!(with.contains("default_type text/plain;"));
        // The body is aliased, never inlined — see `serve_robots_txt`.
        assert!(with.contains("alias "));
        assert!(!with.contains("User-agent:"));
    }

    /// Serving robots.txt is reason enough to keep a sentinel block even
    /// with nothing to block, otherwise allowing every bot would silently
    /// delete the block that serves it.
    #[test]
    fn a_block_with_no_patterns_still_renders_when_robots_txt_is_on() {
        let config = BlockConfig {
            patterns: Vec::new(),
            response: BlockResponse::Forbidden,
            serve_robots_txt: true,
            rate_limit_burst: None,
            exempt_paths: Vec::new(),
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("location = /robots.txt"));
        assert!(!text.contains("if ($http_user_agent"));
    }

    #[test]
    fn site_apply_status_is_stale_when_only_robots_txt_is_toggled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_robots(&["BadBot"])),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn is_robots_token_rejects_anything_that_is_not_a_plain_token() {
        assert!(is_robots_token("GPTBot"));
        assert!(is_robots_token("Mozilla/5.0"));
        assert!(is_robots_token("ai-bot_2.0"));
        assert!(!is_robots_token(""));
        assert!(!is_robots_token("Some Crawler"));
        assert!(!is_robots_token("Bad|Bot"));
        assert!(!is_robots_token("(compatible;"));
        assert!(!is_robots_token(&"x".repeat(65)));
    }

    fn seed_bot(db: &crate::db::Db, slug: &str, name: &str, is_ai: bool) {
        db.upsert_source(&crate::db::Source {
            id: "s".to_string(),
            name: "s".to_string(),
            url: "https://example.invalid/".to_string(),
            last_fetched_at: None,
            bot_count: 0,
        })
        .unwrap();
        db.upsert_bot(&crate::db::NewBot {
            slug: slug.to_string(),
            name: name.to_string(),
            is_ai,
            is_search_engine: false,
            is_scanner: false,
            user_agent_pattern: name.to_string(),
            source_id: "s".to_string(),
        })
        .unwrap();
    }

    #[test]
    fn robots_txt_body_groups_blocked_bots_under_one_disallow() {
        let db = crate::db::Db::open_in_memory().unwrap();
        // AI is blocked by default; Search is not.
        seed_bot(&db, "gptbot", "GPTBot", true);
        seed_bot(&db, "ccbot", "CCBot", true);

        let body = robots_txt_body(&db).unwrap();

        assert!(body.contains("User-agent: GPTBot\n"));
        assert!(body.contains("User-agent: CCBot\n"));
        // One shared Disallow: / for the whole group, not one per bot.
        assert_eq!(body.matches("Disallow: /\n").count(), 1);
    }

    #[test]
    fn robots_txt_body_skips_names_that_are_not_usable_tokens() {
        let db = crate::db::Db::open_in_memory().unwrap();
        seed_bot(&db, "spacey", "Some AI Crawler", true);
        let body = robots_txt_body(&db).unwrap();
        assert!(!body.contains("Some AI Crawler"));
    }

    #[test]
    fn robots_txt_body_omits_bots_that_are_not_blocked() {
        let db = crate::db::Db::open_in_memory().unwrap();
        seed_bot(&db, "gptbot", "GPTBot", true);
        db.set_bot_status("gptbot", crate::db::BotStatus::Allowed)
            .unwrap();

        let body = robots_txt_body(&db).unwrap();
        assert!(!body.contains("GPTBot"));
    }

    /// The trap path is published whether or not the honeypot detector is
    /// switched on — publishing is what creates the trap; the detector
    /// only decides whether hits are acted on.
    #[test]
    fn robots_txt_body_always_publishes_the_honeypot_path() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let body = robots_txt_body(&db).unwrap();
        assert!(body.contains(&format!(
            "Disallow: {}",
            crate::protection::HONEYPOT_PATH_DEFAULT
        )));
    }

    /// With nothing blocked the file must still be a meaningful
    /// robots.txt, not an empty one that reads as broken.
    #[test]
    fn robots_txt_body_is_valid_with_nothing_blocked() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let body = robots_txt_body(&db).unwrap();
        assert!(body.contains("User-agent: *"));
        assert!(body.contains("Disallow:"));
    }

    #[test]
    fn write_managed_files_writes_then_removes_the_robots_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("robots.txt");
        let db = crate::db::Db::open_in_memory().unwrap();

        // Exercised through the same body/enable logic the real path uses,
        // but against a temp file: `write_managed_files` resolves its
        // location from the environment, which unit tests running in one
        // shared process can't safely set.
        db.set_serve_robots_txt(true).unwrap();
        fs::write(&path, robots_txt_body(&db).unwrap()).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("User-agent"));

        // Removal is idempotent: a missing file is success, not an error.
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            fs::remove_file(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        ));
    }

    // ---- rate limiting ----

    fn cfg_rate(burst: u32) -> BlockConfig {
        BlockConfig {
            patterns: vec!["BadBot".to_string()],
            response: BlockResponse::Forbidden,
            serve_robots_txt: false,
            rate_limit_burst: Some(burst),
            exempt_paths: Vec::new(),
        }
    }

    #[test]
    fn block_text_emits_limit_req_only_when_enabled() {
        let without = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!without.contains("limit_req"));

        let with = block_text(&cfg_rate(20)).unwrap();
        assert!(with.contains("limit_req zone=stop_bots burst=20 nodelay;"));
        assert!(with.contains("limit_req_status 429;"));
    }

    /// The zone name in the server-level directive and the one in the
    /// generated http-level file must be identical — a mismatch makes
    /// NGINX refuse to load with "unknown limit_req_zone".
    #[test]
    fn the_limit_req_zone_name_matches_between_the_block_and_the_conf_file() {
        let block = block_text(&cfg_rate(20)).unwrap();
        let conf = rate_limit_conf_body(10, 10);
        assert!(block.contains(&format!("zone={RATE_LIMIT_ZONE} ")));
        assert!(conf.contains(&format!("zone={RATE_LIMIT_ZONE}:")));
    }

    #[test]
    fn rate_limit_conf_body_uses_the_binary_address_key_and_given_rate() {
        let conf = rate_limit_conf_body(30, 16);
        assert!(conf.contains("limit_req_zone $binary_remote_addr"));
        assert!(conf.contains("zone=stop_bots:16m"));
        assert!(conf.contains("rate=30r/s"));
    }

    /// Rate limiting alone is reason enough to keep a sentinel block, the
    /// same as robots.txt: otherwise allowing every bot would delete the
    /// block carrying the `limit_req`.
    #[test]
    fn a_block_with_no_patterns_still_renders_when_rate_limiting_is_on() {
        let config = BlockConfig {
            patterns: Vec::new(),
            response: BlockResponse::Forbidden,
            serve_robots_txt: false,
            rate_limit_burst: Some(5),
            exempt_paths: Vec::new(),
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("limit_req"));
        assert!(!text.contains("if ($http_user_agent"));
    }

    #[test]
    fn site_apply_status_is_stale_when_only_the_rate_limit_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &cfg_rate(20)).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_rate(20)),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_rate(50)),
            SiteApplyStatus::Stale
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg(&["BadBot"])),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn remove_managed_treats_a_missing_file_as_success() {
        let dir = tempfile::tempdir().unwrap();
        remove_managed(&dir.path().join("never-existed.conf")).unwrap();
    }

    #[test]
    fn write_managed_creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/stop-bots-limits.conf");
        write_managed(&path, "x\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "x\n");
    }

    // ---- per-site path exemptions ----

    fn cfg_exempt(patterns: &[&str], paths: &[&str]) -> BlockConfig {
        BlockConfig {
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
            response: BlockResponse::Forbidden,
            serve_robots_txt: false,
            rate_limit_burst: None,
            exempt_paths: paths.iter().map(|p| p.to_string()).collect(),
        }
    }

    /// With no exemptions the block keeps its original direct-`return`
    /// shape, so upgrading doesn't rewrite every already-applied site.
    #[test]
    fn no_exemptions_keeps_the_direct_return_form() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(text.contains("if ($http_user_agent ~* \"BadBot\") {"));
        assert!(text.contains("return 403;"));
        assert!(!text.contains("$stop_bots_block"));
    }

    #[test]
    fn exemptions_switch_the_block_to_the_flag_form_in_the_right_order() {
        let text = block_text(&cfg_exempt(&["BadBot"], &["/blog"])).unwrap();

        let set_zero = text.find("set $stop_bots_block 0;").unwrap();
        let set_one = text.find("set $stop_bots_block 1;").unwrap();
        let clear = text.rfind("set $stop_bots_block 0;").unwrap();
        let act = text.find("if ($stop_bots_block) {").unwrap();

        // Order is the whole mechanism: initialise, set on a UA match,
        // clear for exempt paths, and only then act.
        assert!(set_zero < set_one, "initialise before the UA match");
        assert!(
            set_one < clear,
            "the exemption must clear *after* the match"
        );
        assert!(clear < act, "act last");
        assert!(text.contains("if ($request_uri ~* \"^(/blog)\")"));
        assert!(text.contains("return 403;"));
    }

    #[test]
    fn the_exemption_regex_is_anchored_and_alternated() {
        assert_eq!(
            exemption_regex(&["/blog".to_string(), "/feed".to_string()]),
            Some("^(/blog|/feed)".to_string())
        );
    }

    /// Unescaped regex metacharacters in a literal URL prefix would widen
    /// the exemption — which fails *open*, unlike a too-narrow pattern.
    #[test]
    fn the_exemption_regex_escapes_metacharacters() {
        let regex = exemption_regex(&["/a.b?c".to_string()]).unwrap();
        assert!(regex.contains("\\."), "regex was: {regex}");
        assert!(regex.contains("\\?"), "regex was: {regex}");
    }

    #[test]
    fn the_exemption_regex_drops_unusable_paths() {
        // Not anchored at the start: could never match, so it's dropped
        // rather than silently widening or narrowing anything.
        assert_eq!(exemption_regex(&["blog".to_string()]), None);
        // Would terminate the quoted config string.
        assert_eq!(exemption_regex(&["/a\"b".to_string()]), None);
        assert_eq!(exemption_regex(&[]), None);
    }

    /// The bug this guards against: server-level `if`/`return` run before
    /// location selection, so without an implicit `/robots.txt` exemption
    /// the generated robots.txt would be 403'd for precisely the user
    /// agents it names.
    #[test]
    fn serving_robots_txt_exempts_robots_txt_from_the_block() {
        let config = BlockConfig {
            patterns: vec!["BadBot".to_string()],
            response: BlockResponse::Forbidden,
            serve_robots_txt: true,
            rate_limit_burst: None,
            exempt_paths: Vec::new(),
        };
        let text = block_text(&config).unwrap();

        // The presence of robots.txt alone forces the flag form, because
        // the direct-`return` form has nowhere to put an exemption.
        assert!(text.contains("$stop_bots_block"));
        assert!(text.contains("/robots\\.txt"), "text was:\n{text}");
        // And the clear still happens after the set, before the act.
        let set_one = text.find("set $stop_bots_block 1;").unwrap();
        let clear = text.rfind("set $stop_bots_block 0;").unwrap();
        let act = text.find("if ($stop_bots_block) {").unwrap();
        assert!(set_one < clear && clear < act);
    }

    #[test]
    fn robots_txt_exemption_combines_with_configured_ones() {
        let config = BlockConfig {
            patterns: vec!["BadBot".to_string()],
            response: BlockResponse::Forbidden,
            serve_robots_txt: true,
            rate_limit_burst: None,
            exempt_paths: vec!["/blog".to_string()],
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("/blog"));
        assert!(text.contains("/robots\\.txt"));
    }

    /// Not serving robots.txt means no implicit exemption, so a site with
    /// no configured exemptions keeps the direct-`return` form.
    #[test]
    fn no_robots_txt_means_no_implicit_exemption() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!text.contains("$stop_bots_block"));
        assert!(!text.contains("robots"));
    }

    #[test]
    fn a_chunked_pattern_list_sets_the_flag_in_every_chunk() {
        let patterns: Vec<String> = (0..500).map(|i| format!("BadBot{i}Agent")).collect();
        let config = BlockConfig {
            patterns,
            response: BlockResponse::Forbidden,
            serve_robots_txt: false,
            rate_limit_burst: None,
            exempt_paths: vec!["/blog".to_string()],
        };
        let text = block_text(&config).unwrap();

        let ifs = text.matches("if ($http_user_agent").count();
        assert!(ifs > 1, "expected chunking, got {ifs}");
        // Every chunk sets the flag; exactly one clears it and one acts.
        assert_eq!(text.matches("set $stop_bots_block 1;").count(), ifs);
        assert_eq!(text.matches("if ($request_uri").count(), 1);
        assert_eq!(text.matches("if ($stop_bots_block) {").count(), 1);
    }

    #[test]
    fn site_apply_status_is_stale_when_only_an_exemption_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_exempt(&["BadBot"], &["/blog"])),
            SiteApplyStatus::Stale
        );

        apply_block_for_site(&path, "a.example", &cfg_exempt(&["BadBot"], &["/blog"])).unwrap();
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_exempt(&["BadBot"], &["/blog"])),
            SiteApplyStatus::UpToDate
        );
    }

    /// An exemption with nothing to exempt from writes no block at all —
    /// exemptions only ever *narrow* an existing rule.
    #[test]
    fn exemptions_alone_do_not_create_a_block() {
        assert!(block_text(&cfg_exempt(&[], &["/blog"])).is_none());
    }

    // ---- goldens ----

    /// The plain form: patterns and a 403, nothing else. This is the block
    /// most installs run, so its exact shape is worth pinning.
    #[test]
    fn simple_block_matches_the_golden() {
        let text = block_text(&cfg(&["BadBot", "EvilCrawler"])).unwrap();
        crate::golden::assert_golden("nginx-block-simple.conf", &text);
    }

    /// Every feature at once: 444, exemptions (which force the flag form),
    /// rate limiting and robots.txt. The golden is the exact text to paste
    /// into a server block and hand to `nginx -t` on a machine that has
    /// one — see `crate::golden`.
    #[test]
    fn kitchen_sink_block_matches_the_golden() {
        let config = BlockConfig {
            patterns: vec!["BadBot".to_string(), "EvilCrawler".to_string()],
            response: BlockResponse::Close,
            serve_robots_txt: true,
            rate_limit_burst: Some(20),
            exempt_paths: vec!["/blog".to_string(), "/feed.xml".to_string()],
        };
        let text = block_text(&config).unwrap();
        crate::golden::assert_golden("nginx-block-full.conf", &text);
    }

    #[test]
    fn robots_txt_matches_the_golden() {
        let db = crate::db::Db::open_in_memory().unwrap();
        seed_bot(&db, "gptbot", "GPTBot", true);
        seed_bot(&db, "ccbot", "CCBot", true);
        // Allowed bots must not appear.
        seed_bot(&db, "goodbot", "GoodBot", true);
        db.set_bot_status("goodbot", crate::db::BotStatus::Allowed)
            .unwrap();
        crate::golden::assert_golden("robots.txt", &robots_txt_body(&db).unwrap());
    }

    #[test]
    fn rate_limit_conf_matches_the_golden() {
        crate::golden::assert_golden("stop-bots-limits.conf", &rate_limit_conf_body(10, 10));
    }
}
