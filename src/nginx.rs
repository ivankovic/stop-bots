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
    /// Whether this block terminates TLS — `listen ... ssl`, or an
    /// `ssl_certificate` directive.
    ///
    /// Load-bearing for exactly one thing: HTTP/1.x rejection. Browsers
    /// only negotiate HTTP/2 over TLS (h2c is effectively unused on the
    /// public web), so on a plain-`listen 80` block *every* request is
    /// HTTP/1.1 — the redirect a visitor's browser makes before it ever
    /// reaches the HTTPS block, ACME validation, everything. Emitting the
    /// rejection there would be 100% false positives, and a typical site
    /// has both blocks under one `server_name`, so a per-site setting
    /// reaches both. See `BlockConfig::reject_http_1x`.
    pub is_tls: bool,
    open: usize,
    close: usize,
}

/// A site discovered while scanning a config directory.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredSite {
    pub server_name: String,
    pub config_path: PathBuf,
}

/// A config file split the way NGINX's own reader (`ngx_conf_read_token`)
/// splits it: `{`, `}`, `;` and words, each with the byte offset it starts
/// at, plus the byte span of every `#` comment.
///
/// **Quote-aware, because what this tool writes is.** A sentinel block
/// embeds upstream bot patterns inside double quotes, and a pattern may
/// legitimately contain `#`, `{` or `}` — or, from a hostile list, the
/// marker text itself. A reader that took every `#` for a comment and
/// every brace for structure re-parsed its own output differently from
/// NGINX: a second run duplicated the whole block, left a stray
/// `return 403; }` outside it, or inserted the new block *inside* the
/// quoted string, which is a way to write directives.
///
/// The rules, each checked against a real `nginx -T`:
///
/// - A `"` or `'` opens a quoted word only where a word starts; inside,
///   a backslash escapes the next character. A quote in the middle of a
///   bare word is an ordinary character.
/// - `#` starts a comment only where a word could start. `a#b` is a word.
/// - A bare word ends at whitespace, `;` or `{` (not `${`, a variable).
///   A `}` inside one is an ordinary character (`add_header X a}b;` is
///   valid); only at the start of a token is it a block end.
/// - A backslash escapes the next character in a bare word too: `a\;b`
///   is one word.
struct Lexed {
    /// Quoted words carry their contents without the quotes (escapes are
    /// left as written; nothing here needs them undone).
    tokens: Vec<(String, usize)>,
    comments: Vec<(usize, usize)>,
}

fn lex(content: &str) -> Lexed {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut tokens = Vec::new();
    let mut comments = Vec::new();
    let mut i = 0;
    while i < len {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b @ (b';' | b'{' | b'}') => {
                tokens.push(((b as char).to_string(), i));
                i += 1;
            }
            b'#' => {
                let end = content[i..].find('\n').map_or(len, |n| i + n);
                comments.push((i, end));
                i = end;
            }
            quote @ (b'"' | b'\'') => {
                let start = i;
                i += 1;
                let body_start = i;
                while i < len && bytes[i] != quote {
                    // Skipping the escaped byte is enough even when it
                    // starts a multi-byte character: its continuation bytes
                    // can never equal an ASCII quote.
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                let body_end = i.min(len);
                tokens.push((
                    String::from_utf8_lossy(&bytes[body_start..body_end]).into_owned(),
                    start,
                ));
                i = (i + 1).min(len);
            }
            _ => {
                let start = i;
                while i < len {
                    match bytes[i] {
                        b' ' | b'\t' | b'\r' | b'\n' | b';' | b'{' => break,
                        b'\\' => i += 2,
                        b'$' if bytes.get(i + 1) == Some(&b'{') => i += 2,
                        _ => i += 1,
                    }
                }
                i = i.min(len);
                tokens.push((
                    String::from_utf8_lossy(&bytes[start..i]).into_owned(),
                    start,
                ));
            }
        }
    }
    Lexed { tokens, comments }
}

/// Finds every top-level `server { ... }` block in `content`, along with the
/// `server_name` values declared directly inside it.
fn parse_server_blocks(content: &str) -> Vec<ServerBlock> {
    let tokens = lex(content).tokens;

    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut names_stack: Vec<Vec<String>> = Vec::new();
    // Parallel to `names_stack`: whether the block currently being scanned
    // has shown any sign of terminating TLS.
    let mut tls_stack: Vec<bool> = Vec::new();
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
                    tls_stack.push(false);
                }
                prev_word = None;
            }
            "}" => {
                if let Some((open, is_server)) = stack.pop() {
                    if is_server {
                        let names = names_stack.pop().unwrap_or_default();
                        let is_tls = tls_stack.pop().unwrap_or(false);
                        blocks.push(ServerBlock {
                            names,
                            is_tls,
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
                // Two independent signals, because configs express TLS
                // both ways: `listen 443 ssl;` (the `ssl` parameter, which
                // arrives as its own token) and a bare `ssl_certificate`
                // directive alongside a `listen` that doesn't say `ssl`.
                // Either is enough; neither is required to be first.
                if directly_in_server && (word == "ssl" || word.starts_with("ssl_certificate")) {
                    if let Some(top) = tls_stack.last_mut() {
                        *top = true;
                    }
                }
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

/// The fewest literal characters every match of a user-agent pattern must
/// contain for it to be written at all.
///
/// Nothing in NGINX refuses a regex that matches every request, and the
/// block turns away whatever it matches on every site at once. An empty
/// key in ai.robots.txt, `accepted: [""]` in well-known-bots, a lone `|`
/// line in the bad-bot list or `.*` from any of them all pass `nginx -t`
/// and 403 every visitor. Three is below every real upstream entry (the
/// shortest are tokens like `FDM` and `Y!J`) and above anything that
/// cannot help matching half the web.
const MIN_PATTERN_LITERALS: usize = 3;

/// The longest single pattern this tool writes, in bytes. The longest in
/// any upstream list is under 60; this is far above it and still well
/// inside one [`MAX_PATTERN_CHUNK_LEN`] chunk, so no pattern ever needs a
/// chunk of its own that NGINX's parameter limit could refuse.
pub const MAX_PATTERN_LEN: usize = 1024;

/// Why a user-agent pattern will not be written, if it will not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternProblem {
    /// Empty, or only whitespace.
    Empty,
    /// A newline, tab or other control character — no real user agent has
    /// one, and NGINX turns `\n`-style escapes into them anyway.
    ControlCharacter,
    /// See [`is_embeddable`].
    NotEmbeddable,
    /// Longer than [`MAX_PATTERN_LEN`].
    TooLong,
    /// Some way of matching it needs fewer than [`MIN_PATTERN_LITERALS`]
    /// literal characters, or it has an empty alternative — it matches
    /// (nearly) every user agent.
    MatchesTooMuch,
    /// A repeated group that itself repeats something, `(a+)+`: the shape
    /// that makes a backtracking engine take exponential time per request.
    Backtracks,
    /// Unbalanced, or a construct (lookaround, `\x`, `\Q`, inline flags)
    /// this check does not understand. Refused rather than guessed at.
    Unchecked,
}

impl std::fmt::Display for PatternProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PatternProblem::Empty => "it is empty",
            PatternProblem::ControlCharacter => "it contains a control character",
            PatternProblem::NotEmbeddable => "it contains a double quote or ends in a backslash",
            PatternProblem::TooLong => "it is too long",
            PatternProblem::MatchesTooMuch => "it would match (nearly) every user agent",
            PatternProblem::Backtracks => "it nests one repetition inside another",
            PatternProblem::Unchecked => "it is not a regex this tool can check",
        })
    }
}

/// Why `pattern` must not be joined into a sentinel block, or `None` when
/// it is safe to.
///
/// **A structural check, not a regex engine.** Deciding whether a PCRE
/// pattern matches every string needs one, and the `regex` crate would add
/// about 1.5MB to a static musl binary for this one question. What is
/// decidable by walking the pattern is enough: the fewest literal
/// characters any match must contain. A pattern that can match with fewer
/// than [`MIN_PATTERN_LITERALS`] is refused, and that covers the empty
/// pattern, `.*`, `^`, `a?b?c?`, `(abc)?` and `Bot|.*` alike, because each
/// has a way to match nearly nothing. It errs towards refusing: anything it
/// does not understand is [`PatternProblem::Unchecked`].
pub fn pattern_problem(pattern: &str) -> Option<PatternProblem> {
    if pattern.trim().is_empty() {
        return Some(PatternProblem::Empty);
    }
    if pattern.chars().any(char::is_control) {
        return Some(PatternProblem::ControlCharacter);
    }
    if !is_embeddable(pattern) {
        return Some(PatternProblem::NotEmbeddable);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Some(PatternProblem::TooLong);
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut shape = Shape {
        chars: &chars,
        pos: 0,
    };
    match shape.alternation(0) {
        Err(problem) => Some(problem),
        Ok(_) if shape.pos != chars.len() => Some(PatternProblem::Unchecked),
        Ok(group) if group.min_literals < MIN_PATTERN_LITERALS => {
            Some(PatternProblem::MatchesTooMuch)
        }
        Ok(_) => None,
    }
}

/// Whether `pattern` may be joined into a sentinel block.
pub fn is_usable_pattern(pattern: &str) -> bool {
    pattern_problem(pattern).is_none()
}

/// What [`Shape`] learns about a stretch of pattern.
struct Measured {
    /// The fewest literal characters any match of it contains.
    min_literals: usize,
    /// Whether it contains a quantifier anywhere.
    quantified: bool,
}

/// A recursive walk over a PCRE pattern, just deep enough for
/// [`pattern_problem`].
struct Shape<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Shape<'_> {
    /// Deep enough for any real pattern; a limit so a hostile one cannot
    /// recurse without bound.
    const MAX_DEPTH: usize = 16;

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    /// `a|b|c`, up to an unopened `)` or the end: the fewest literals of
    /// any alternative, since a match only needs one.
    fn alternation(&mut self, depth: usize) -> Result<Measured, PatternProblem> {
        if depth > Self::MAX_DEPTH {
            return Err(PatternProblem::Unchecked);
        }
        let mut min_literals = usize::MAX;
        let mut quantified = false;
        loop {
            let branch = self.sequence(depth)?;
            min_literals = min_literals.min(branch.min_literals);
            quantified |= branch.quantified;
            if self.peek() != Some('|') {
                return Ok(Measured {
                    min_literals,
                    quantified,
                });
            }
            self.pos += 1;
        }
    }

    /// Atoms one after another, each with its quantifier. An empty one is
    /// an empty alternative, which matches everything wherever it is.
    fn sequence(&mut self, depth: usize) -> Result<Measured, PatternProblem> {
        let start = self.pos;
        let mut min_literals = 0usize;
        let mut quantified = false;
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom(depth)?;
            match self.quantifier() {
                Some((min, repeats)) => {
                    if repeats && atom.quantified {
                        return Err(PatternProblem::Backtracks);
                    }
                    min_literals =
                        min_literals.saturating_add(atom.min_literals.saturating_mul(min));
                    quantified = true;
                }
                None => {
                    min_literals = min_literals.saturating_add(atom.min_literals);
                    quantified |= atom.quantified;
                }
            }
        }
        if self.pos == start {
            return Err(PatternProblem::MatchesTooMuch);
        }
        Ok(Measured {
            min_literals,
            quantified,
        })
    }

    fn atom(&mut self, depth: usize) -> Result<Measured, PatternProblem> {
        let literal = |n| Measured {
            min_literals: n,
            quantified: false,
        };
        let c = self.peek().ok_or(PatternProblem::Unchecked)?;
        self.pos += 1;
        match c {
            '(' => {
                // `(?:` is the only `(?` form upstream lists use; the rest
                // (lookaround, flags, named groups) are refused.
                if self.peek() == Some('?') {
                    if self.chars.get(self.pos + 1) != Some(&':') {
                        return Err(PatternProblem::Unchecked);
                    }
                    self.pos += 2;
                }
                let inner = self.alternation(depth + 1)?;
                if self.peek() != Some(')') {
                    return Err(PatternProblem::Unchecked);
                }
                self.pos += 1;
                Ok(inner)
            }
            '[' => {
                let start = self.pos;
                self.class()?;
                // `[Tt]` is how upstream spells one letter in either case
                // (`i[Tt][Mm][Ss]`), and the match is case-insensitive
                // anyway, so it counts as the literal it is.
                let members = &self.chars[start..self.pos - 1];
                let one_letter = matches!(members, [a, b] if a.is_alphabetic() && a.to_lowercase().eq(b.to_lowercase()));
                Ok(literal(usize::from(one_letter)))
            }
            '\\' => {
                let escaped = self.peek().ok_or(PatternProblem::Unchecked)?;
                self.pos += 1;
                match escaped {
                    // Anchors and character types: they match, but not a
                    // literal character.
                    'b' | 'B' | 'A' | 'z' | 'Z' | 'G' | 'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'h'
                    | 'H' | 'v' | 'V' => Ok(literal(0)),
                    // `\x41`, `\p{..}`, `\Q..\E`, back-references: each
                    // would need its own parsing to count honestly.
                    c if c.is_ascii_alphanumeric() => Err(PatternProblem::Unchecked),
                    _ => Ok(literal(1)),
                }
            }
            '.' | '^' | '$' => Ok(literal(0)),
            // A quantifier with nothing to repeat.
            '*' | '+' | '?' => Err(PatternProblem::Unchecked),
            // A `{` is a literal unless it reads as a quantifier, which
            // here would have nothing to repeat.
            '{' => {
                self.pos -= 1;
                if self.braces().is_some() {
                    return Err(PatternProblem::Unchecked);
                }
                self.pos += 1;
                Ok(literal(1))
            }
            _ => Ok(literal(1)),
        }
    }

    /// Skips a `[...]` class, already past its `[`.
    fn class(&mut self) -> Result<(), PatternProblem> {
        if self.peek() == Some('^') {
            self.pos += 1;
        }
        // A `]` straight after the opening is a literal member.
        if self.peek() == Some(']') {
            self.pos += 1;
        }
        loop {
            match self.peek().ok_or(PatternProblem::Unchecked)? {
                ']' => {
                    self.pos += 1;
                    return Ok(());
                }
                '\\' => self.pos += 2,
                '[' if self.chars.get(self.pos + 1) == Some(&':') => {
                    // `[:alpha:]`: its `]` does not close the class.
                    let rest = &self.chars[self.pos..];
                    let close = rest
                        .windows(2)
                        .position(|w| w == [':', ']'])
                        .ok_or(PatternProblem::Unchecked)?;
                    self.pos += close + 2;
                }
                _ => self.pos += 1,
            }
        }
    }

    /// A quantifier at the current position, as `(minimum count, whether
    /// it can repeat)`, consuming it and any lazy or possessive suffix. A
    /// `{` that is not a valid quantifier is a literal in PCRE, and `None`.
    fn quantifier(&mut self) -> Option<(usize, bool)> {
        let found = match self.peek()? {
            '{' => self.braces()?,
            symbol => {
                let found = match symbol {
                    '?' => (0, false),
                    '*' => (0, true),
                    '+' => (1, true),
                    _ => return None,
                };
                self.pos += 1;
                found
            }
        };
        if matches!(self.peek(), Some('?' | '+')) {
            self.pos += 1;
        }
        Some(found)
    }

    /// `{n}`, `{n,}` or `{n,m}` at the current position, consumed. Leaves
    /// the position alone if what is there is not one.
    fn braces(&mut self) -> Option<(usize, bool)> {
        let rest: String = self.chars[self.pos..].iter().take(16).collect();
        let body = rest.strip_prefix('{')?.split('}').next()?;
        if body.len() + 2 > rest.len() {
            return None;
        }
        let (min, max) = match body.split_once(',') {
            None => (body, Some(body)),
            Some((min, "")) => (min, None),
            Some((min, max)) => (min, Some(max)),
        };
        let min: usize = min.parse().ok()?;
        let max: Option<usize> = match max {
            Some(max) => Some(max.parse().ok()?),
            None => None,
        };
        self.pos += body.chars().count() + 2;
        Some((min, max.is_none_or(|max| max > 1)))
    }
}

/// The patterns in `patterns` that are safe to write (see
/// [`pattern_problem`]), in order. Empty is the same "nothing to block" case
/// as an empty list, which removes any existing sentinel block instead of
/// writing an empty one.
fn usable_patterns(patterns: &[String]) -> Vec<&str> {
    patterns
        .iter()
        .map(String::as_str)
        .filter(|p| is_usable_pattern(p))
        .collect()
}

/// Maximum byte length of a single chunk [`chunk_patterns`] produces.
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

/// Joins `patterns` with `|` into pieces of at most `max_len` bytes each,
/// **never splitting a pattern**. A single pattern longer than `max_len`
/// becomes its own oversized chunk rather than being dropped or cut.
///
/// This used to join everything first and then split the result on every
/// `|` — including the `|` of an escaped `\|` and the ones inside a
/// `(a|b)` group. A chunk could then end in the backslash of `\|`, which
/// escapes the closing quote of `if ($http_user_agent ~* "...")`, and NGINX
/// read the start of the next chunk as directives. Verified with a real
/// `nginx -t`: a line in a downloaded bot list could put an `include` into
/// a config that root loads, unattended, from cron.
///
/// Every chunk is checked again as it is built, and a pattern that would
/// make one unsafe is left out rather than written: the only safe failure
/// for a string that is about to become config is to not write it.
fn chunk_patterns(patterns: &[&str], max_len: usize) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    for pattern in patterns.iter().filter(|p| is_embeddable(p)) {
        match chunks.last_mut() {
            Some(last) if last.len() + 1 + pattern.len() <= max_len => {
                last.push('|');
                last.push_str(pattern);
            }
            _ => chunks.push(pattern.to_string()),
        }
    }
    chunks.retain(|chunk| is_embeddable(chunk));
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

/// Where this host's `conf.d` actually is: the environment override if
/// one is set, else `conf.d` under the stored NGINX root.
///
/// Derived from [`root`] rather than fixed, and that is the whole point.
/// An NGINX in a container keeps its config tree somewhere like
/// `/srv/app/nginx`; `scan-sites` stores that as `nginx:root` and every
/// site file is found and rewritten there. The `http`-context files this
/// module also generates went to [`CONF_D_DIR`] regardless — a directory
/// that on such a host does not exist until this code creates it, and
/// that NGINX never reads.
///
/// The failure that produced was not a missing feature but a broken
/// server: `write_managed_files` runs first and reported success, the
/// site blocks were then rewritten to read `$stop_bots_trusted`, and only
/// the reload found out that nothing defined it. NGINX refuses to load
/// such a config at all, so the *whole* server — every unrelated site
/// included — was one restart away from not coming back.
///
/// **Only a `conf.d` that already exists**, and never one this code
/// creates. The root is wherever site configs were scanned from, which is
/// not always the NGINX prefix: the container suite passes
/// `--root /etc/nginx/sites-enabled`, and creating `conf.d` inside *that*
/// puts a directory where `include sites-enabled/*` globs, so NGINX tries
/// to `pread()` a directory and refuses to start. A `conf.d` that is
/// already there is one NGINX was built around; one this code invents is a
/// guess about a glob it cannot see.
///
/// Takes the root already resolved rather than reading it back out of the
/// database, because [`root`] lets a `--root` flag win over the stored
/// setting and the two must not disagree.
///
/// Unchanged for a normal host install: [`root`] falls back to
/// [`DEFAULT_ROOT`], whose `conf.d` exists, so this still resolves to
/// [`CONF_D_DIR`].
pub fn conf_d_dir(root: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os(CONF_D_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let beside_the_sites = root.join("conf.d");
    if beside_the_sites.is_dir() {
        return beside_the_sites;
    }
    PathBuf::from(CONF_D_DIR)
}

/// The generated `limit_req_zone` file.
pub fn rate_limit_conf_path(conf_d: &Path) -> PathBuf {
    conf_d.join("stop-bots-limits.conf")
}

/// The generated trust file: which clients no block applies to.
///
/// In `conf.d` for the reason [`rate_limit_conf_path`] is. `geo` and `map`
/// are `http`-context directives, and `geo` is the only way NGINX has to
/// ask "is this address inside that CIDR" — a server-level `if` can only
/// compare `$remote_addr` as text, which cannot express a /28, let alone
/// the many spellings of an IPv6 prefix.
pub fn trusted_conf_path(conf_d: &Path) -> PathBuf {
    conf_d.join("stop-bots-trusted.conf")
}

/// The variable the trust file defines: `1` for a trusted client, `0`
/// otherwise. Read by every sentinel block that blocks anything.
const TRUSTED_VAR: &str = "$stop_bots_trusted";

/// The rate-limit key the trust file defines — empty for a trusted client,
/// which `limit_req_zone` does not account at all, and the client's
/// address for everyone else.
const LIMIT_KEY_VAR: &str = "$stop_bots_limit_key";

/// Holds the request path while an agent exemption is being checked, and
/// `""` otherwise — see [`agent_exemption_clears`]. Server-level, set
/// before every read, so no `map` or `http`-level declaration is needed.
const AGENT_EXEMPT_VAR: &str = "$stop_bots_exempt";

/// The zone a site's `limit_req` uses while anything is trusted: keyed on
/// [`LIMIT_KEY_VAR`], in a file of its own
/// ([`untrusted_rate_limit_conf_path`]).
///
/// **A second zone, not the first one re-keyed.** NGINX keeps a
/// `limit_req_zone`'s shared memory across a reload and refuses a reload
/// that gives the same zone a different key — `limit_req "stop_bots" uses
/// the "$binary_remote_addr" key while previously it used ...`. `nginx -t`
/// cannot see that, because it never compares against the running
/// config, so the reload is rejected after the test passed and NGINX
/// keeps serving the old config: every later apply silently does nothing.
/// The container suite caught exactly that. A zone that is only ever
/// created with one key, and a site that switches which zone it names,
/// never asks NGINX to re-key anything.
const UNTRUSTED_RATE_LIMIT_ZONE: &str = "stop_bots_untrusted";

/// The file declaring [`UNTRUSTED_RATE_LIMIT_ZONE`]. Its own file, rather
/// than a line in the trust file or the limits file, because it has to
/// exist exactly when both rate limiting is on and something is trusted,
/// and a file of its own gets the write-before, remove-after lifecycle
/// every other generated file already has.
pub fn untrusted_rate_limit_conf_path(conf_d: &Path) -> PathBuf {
    conf_d.join("stop-bots-limits-untrusted.conf")
}

/// The shared memory zone name used by both the generated
/// `limit_req_zone` and every `limit_req` that references it. One
/// constant, because a mismatch between the two is not a subtle bug: NGINX
/// refuses to start with "unknown limit_req_zone".
const RATE_LIMIT_ZONE: &str = "stop_bots";

/// An optional per-site rule that decides a request is unwanted from its
/// *shape* rather than from a user-agent pattern.
///
/// Each is a separate toggle rather than one "strict requests" switch, and
/// deliberately so: if four rules hid behind one setting and an admin's
/// monitoring stopped working, they'd have no way to tell which one did
/// it. Every variant is off by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestRule {
    /// HTTP/1.0 and HTTP/1.1. Only emitted in TLS blocks — see
    /// [`for_block`].
    Http1x,
    /// No `Accept` header. Every browser sends one; a fair amount of
    /// tooling sends nothing.
    NoAccept,
    /// No `Accept-Language`. Browsers send it; most scripts don't. Weaker
    /// than `NoAccept` — some privacy configurations strip it.
    NoAcceptLanguage,
    /// Empty or absent `User-Agent`. Distinct from bot-pattern matching,
    /// which can only catch agents that identify themselves.
    NoUserAgent,
    /// A `Host` that is a bare IP address rather than a name. Scanners
    /// sweep address ranges; real visitors arrive by hostname.
    IpLiteralHost,
    /// TLS 1.0 and 1.1. The same "only modern clients" argument as
    /// [`Self::Http1x`] but on firmer ground — both are formally
    /// deprecated and no current browser offers them. Inert outside a TLS
    /// block, where `$ssl_protocol` is empty.
    OldTls,
}

impl RequestRule {
    pub const ALL: [RequestRule; 6] = [
        RequestRule::Http1x,
        RequestRule::NoAccept,
        RequestRule::NoAcceptLanguage,
        RequestRule::NoUserAgent,
        RequestRule::IpLiteralHost,
        RequestRule::OldTls,
    ];

    /// Stable id — a `site_request_rules.rule` value in every installed
    /// database, so never rename one without a migration.
    pub fn id(self) -> &'static str {
        match self {
            RequestRule::Http1x => "http_1x",
            RequestRule::NoAccept => "no_accept",
            RequestRule::NoAcceptLanguage => "no_accept_language",
            RequestRule::NoUserAgent => "no_user_agent",
            RequestRule::IpLiteralHost => "ip_literal_host",
            RequestRule::OldTls => "old_tls",
        }
    }

    pub fn from_id(id: &str) -> Option<RequestRule> {
        RequestRule::ALL.into_iter().find(|r| r.id() == id)
    }

    pub fn label(self) -> &'static str {
        match self {
            RequestRule::Http1x => "HTTP/1.x requests",
            RequestRule::NoAccept => "No Accept header",
            RequestRule::NoAcceptLanguage => "No Accept-Language",
            RequestRule::NoUserAgent => "No User-Agent",
            RequestRule::IpLiteralHost => "Host is an IP",
            RequestRule::OldTls => "TLS 1.0 / 1.1",
        }
    }

    /// A one-line note on what this turns away besides bots, shown next to
    /// the toggle. Every one of these has collateral; saying so at the
    /// point of the decision is the whole point.
    pub fn caveat(self) -> &'static str {
        match self {
            RequestRule::Http1x => "also turns away crawlers and API clients",
            RequestRule::NoAccept => "some API clients send none",
            RequestRule::NoAcceptLanguage => "privacy tooling strips it",
            RequestRule::NoUserAgent => "scripts and health checks often omit it",
            RequestRule::IpLiteralHost => "breaks reaching the site by IP",
            RequestRule::OldTls => "very old clients only",
        }
    }

    /// Whether the rule can only work in a TLS-terminating block.
    fn needs_tls(self) -> bool {
        matches!(self, RequestRule::Http1x | RequestRule::OldTls)
    }

    /// The NGINX condition, without the surrounding `if (...)`.
    fn condition(self) -> &'static str {
        match self {
            RequestRule::Http1x => r#"$server_protocol ~ "^HTTP/1\.""#,
            RequestRule::NoAccept => r#"$http_accept = """#,
            RequestRule::NoAcceptLanguage => r#"$http_accept_language = """#,
            RequestRule::NoUserAgent => r#"$http_user_agent = """#,
            // Anchored, and matching both an IPv4 literal and a bracketed
            // IPv6 one. `$host` is already lowercased and port-stripped by
            // NGINX, which `$http_host` is not.
            RequestRule::IpLiteralHost => r#"$host ~ "^(\d+\.\d+\.\d+\.\d+|\[)""#,
            RequestRule::OldTls => r#"$ssl_protocol ~ "^TLSv1(\.[01])?$""#,
        }
    }
}

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
    /// Request-path prefixes exempt only for clients whose user agent
    /// contains the given string, sorted by user agent (see
    /// [`crate::db::AgentExemption`]). Rendered by
    /// [`agent_exemption_clears`], after every set like the other clears.
    pub agent_exemptions: Vec<crate::db::AgentExemption>,
    /// Per-site [`RequestRule`]s switched on for this site.
    ///
    /// These decide a request is unwanted from its shape rather than from
    /// a user-agent pattern, and they are the bluntest instruments in the
    /// project. Two things make them survivable, and both are enforced
    /// rather than documented:
    ///
    /// 1. **TLS-only rules are dropped in non-TLS blocks** (see
    ///    [`for_block`]). Browsers don't negotiate HTTP/2 without TLS, so
    ///    on a `listen 80` block every request is HTTP/1.1 — and a site's
    ///    port-80 and port-443 blocks routinely share one `server_name`,
    ///    which is what a per-site setting keys on.
    /// 2. **`/.well-known/` is always exempt** whenever any of these is on
    ///    (see `effective_exempt_paths`). ACME HTTP-01 validation is
    ///    fetched over HTTP/1.1 by a non-browser client with no `Accept`
    ///    and often no `User-Agent`; blocking it doesn't fail now, it
    ///    fails at certificate renewal weeks later.
    ///
    /// What no guard fixes: each rule turns away some legitimate
    /// non-browser client. See [`RequestRule::caveat`].
    pub request_rules: Vec<RequestRule>,
    /// The body of the trust file (see [`trusted_conf_body`]), or `None`
    /// when nothing is trusted.
    ///
    /// Only whether it is `Some` reaches the block text — one `if` that
    /// clears the flag. The body is carried anyway because it is part of
    /// what this site's protection *is*: trusting a second user agent
    /// changes no site's block, only the file, and a site whose file is
    /// out of date must still read as `Stale` or nobody will apply it. See
    /// [`trust_file_is_current`].
    pub trust: Option<String>,
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
        .filter(|bot| db.bot_is_blocked(bot).unwrap_or(false))
        .filter_map(|bot| robots_token(&bot))
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

/// The `User-agent:` token to publish for `bot`, or `None` if nothing
/// usable can be derived.
///
/// **Prefers the user-agent pattern over the display name**, which is not
/// a cosmetic choice. A bot's `name` is humanised from its slug by the
/// well-known-bots parser — `ai-search-bot` becomes `Ai Search Bot` — so
/// it is both mis-cased *and* contains spaces, and a name with spaces is
/// no use as a robots token. Filtering on the name alone meant the
/// generated robots.txt listed **none** of that source's bots while still
/// being served: a file that forbade nobody, which is worse than no file,
/// because it looks like the feature is working.
///
/// The pattern is the substring the bot actually sends, which is exactly
/// what a robots token is. Backslash escapes are undone (patterns are
/// NGINX regex fragments: `Googlebot\/`), a trailing `/` is trimmed
/// (`Googlebot/` is a UA prefix, not a token), and only the first
/// alternative of a merged pattern is used — one `User-agent:` line has
/// room for one token.
fn robots_token(bot: &crate::db::Bot) -> Option<String> {
    let first = bot.user_agent_pattern.split('|').next().unwrap_or_default();
    let unescaped = first.replace('\\', "");
    let candidate = unescaped.trim_end_matches('/');
    if is_robots_token(candidate) {
        return Some(candidate.to_string());
    }
    // A name that happens to be a clean token (ai.robots.txt keys entries
    // by the real token, so this is the common path for that source).
    is_robots_token(&bot.name).then(|| bot.name.clone())
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

/// The same limit, in [`UNTRUSTED_RATE_LIMIT_ZONE`]: keyed on the trust
/// file's [`LIMIT_KEY_VAR`], which is that same binary address for
/// everyone but a trusted client — for whom it is empty, and NGINX does
/// not account a request with an empty key. `limit_req` is not allowed
/// inside `if`, so the key is the only place a rate limit can be lifted
/// for one client.
pub fn untrusted_rate_limit_conf_body(rate_per_second: i64, zone_megabytes: i64) -> String {
    format!(
        "# Generated by stop-bots. Edits will be overwritten.\n\
         limit_req_zone {LIMIT_KEY_VAR} zone={UNTRUSTED_RATE_LIMIT_ZONE}:{zone_megabytes}m \
         rate={rate_per_second}r/s;\n"
    )
}

/// The trust file's body for what `db` trusts, or `None` when it trusts
/// nothing — in which case there is no file, and no block mentions it.
pub fn trusted_conf(db: &crate::db::Db) -> Result<Option<String>> {
    Ok(trusted_conf_body(
        &db.list_trusted_addresses()?,
        &db.list_trusted_user_agents()?,
    ))
}

/// The trust file: three variables, each defined in terms of the last.
///
/// - A `geo` over the client address, because it is the only CIDR-aware
///   lookup NGINX has.
/// - A `map` over the user agent whose *default* is that `geo` result, so
///   the one variable a sentinel block reads, [`TRUSTED_VAR`], is "the
///   address or the user agent is trusted".
/// - The rate-limit key (see [`untrusted_rate_limit_conf_body`]), defined
///   here so that it exists exactly when the variable it reads does. It
///   is harmless unreferenced.
///
/// User agents match the way a manual user-agent block does: a
/// case-insensitive, regex-escaped substring. Each one has been through
/// `db::validate_trusted_user_agent`, and is filtered by [`is_embeddable`]
/// again here rather than trusting the caller — a quote in a `map` key
/// would not break one site, it would stop NGINX loading at all.
///
/// All three are evaluated lazily, per request, and only when read.
pub fn trusted_conf_body(addresses: &[String], user_agents: &[String]) -> Option<String> {
    let user_agents: Vec<String> = user_agents
        .iter()
        .map(|ua| crate::db::escape_for_nginx_regex(ua))
        .filter(|ua| !ua.is_empty() && is_embeddable(ua))
        .collect();
    let addresses: Vec<&String> = addresses
        .iter()
        .filter(|a| crate::db::is_valid_address(a))
        .collect();
    if addresses.is_empty() && user_agents.is_empty() {
        return None;
    }
    let mut out = String::from("# Generated by stop-bots. Edits will be overwritten.\n");
    out.push_str("geo $stop_bots_trusted_address {\n    default 0;\n");
    for address in addresses {
        out.push_str(&format!("    {address} 1;\n"));
    }
    out.push_str("}\n");
    out.push_str(&format!(
        "map $http_user_agent {TRUSTED_VAR} {{\n    default $stop_bots_trusted_address;\n"
    ));
    for ua in user_agents {
        out.push_str(&format!("    \"~*{ua}\" 1;\n"));
    }
    out.push_str("}\n");
    out.push_str(&format!(
        "map {TRUSTED_VAR} {LIMIT_KEY_VAR} {{\n    1 \"\";\n    default $binary_remote_addr;\n}}\n"
    ));
    Some(out)
}

/// Whether the trust file on disk is the one `config` expects, given what
/// was read from it (`None`: missing or unreadable).
///
/// Only asked of a site that writes a block at all: with no block, nothing
/// on that site reads the file. And a site that expects *no* trust file is
/// current whatever is on disk — its block text is what says whether it
/// still references one, and that is compared separately.
///
/// Pure, taking the file's contents rather than reading them, so that it
/// can be tested without the environment-resolved path; see
/// [`MANAGED_DIR_ENV`].
fn trust_file_is_current(config: &BlockConfig, on_disk: Option<&str>) -> bool {
    match (&config.trust, block_text(config)) {
        (Some(expected), Some(_)) => on_disk == Some(expected.as_str()),
        _ => true,
    }
}

/// Creates or updates every file the config about to be written will
/// reference. **Runs before any site config is touched**, so an `alias` or
/// a `limit_req` never points at something that isn't there yet.
///
/// Deliberately does not delete anything — see
/// [`remove_unused_managed_files`] for why the two halves are separate.
pub fn write_managed_files(db: &crate::db::Db, root: &Path) -> Result<usize> {
    write_planned_managed_files(&planned_managed_files(db, root)?)
}

/// The managed files the current settings call for, as `(path, body)`
/// pairs.
///
/// Split out of [`write_managed_files`] so that the `Db` reads and the
/// disk writes can happen in different places: the TUI resolves this on
/// the main thread (`Db` isn't `Sync`) and writes it on a background
/// thread, so an apply doesn't stall the event loop. The CLI still calls
/// [`write_managed_files`], which does both in one go.
pub fn planned_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let conf_d = conf_d_dir(root);
    let mut files = Vec::new();
    if db.get_serve_robots_txt()? {
        files.push((robots_txt_path(), robots_txt_body(db)?));
    }
    // The trust file before the untrusted zone, which reads a variable it
    // defines. NGINX resolves variables after parsing every file, so on
    // disk the order does not matter — but a write that fails between the
    // two should leave the definition behind, not the reference.
    let trust = trusted_conf(db)?;
    if let Some(body) = &trust {
        files.push((trusted_conf_path(&conf_d), body.clone()));
    }
    if db.get_rate_limit_enabled()? {
        let (rps, megabytes) = (db.get_rate_limit_rps()?, db.get_rate_limit_zone_mb()?);
        // Written even while every site names the untrusted zone instead:
        // a site not yet rewritten still names this one, and removing it
        // is only safe once none does — which is `unused_managed_files`'s
        // job, and it would have to know which zone every site on disk
        // names. An idle zone costs its shared memory and nothing else.
        files.push((
            rate_limit_conf_path(&conf_d),
            rate_limit_conf_body(rps, megabytes),
        ));
        if trust.is_some() {
            files.push((
                untrusted_rate_limit_conf_path(&conf_d),
                untrusted_rate_limit_conf_body(rps, megabytes),
            ));
        }
    }
    Ok(files)
}

/// Writes what [`planned_managed_files`] resolved. Touches no `Db`.
///
/// Returns how many files it actually changed, because that can be the
/// whole of an apply: trusting a second user agent rewrites the trust
/// file and no site's block, and an apply that counted only site files
/// would decide NGINX had nothing new to read and never reload it.
pub fn write_planned_managed_files(files: &[(PathBuf, String)]) -> Result<usize> {
    let mut changed = 0;
    for (path, body) in files {
        if fs::read_to_string(path).ok().as_deref() != Some(body.as_str()) {
            write_managed(path, body)?;
            changed += 1;
        }
    }
    Ok(changed)
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
pub fn remove_unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<usize> {
    remove_planned_managed_files(&unused_managed_files(db, root)?)
}

/// The managed files the current settings no longer reference. Split from
/// the removal for the same reason [`planned_managed_files`] is split from
/// the write.
pub fn unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<PathBuf>> {
    let conf_d = conf_d_dir(root);
    let mut paths = Vec::new();
    if !db.get_serve_robots_txt()? {
        paths.push(robots_txt_path());
    }
    let rate_limited = db.get_rate_limit_enabled()?;
    let trusted = trusted_conf(db)?.is_some();
    if !rate_limited {
        paths.push(rate_limit_conf_path(&conf_d));
    }
    // Before the trust file: it reads a variable the trust file defines,
    // so for the moment between the two deletions it must be this one
    // that is already gone.
    if !(rate_limited && trusted) {
        paths.push(untrusted_rate_limit_conf_path(&conf_d));
    }
    if !trusted {
        paths.push(trusted_conf_path(&conf_d));
    }
    Ok(paths)
}

/// Deletes what [`unused_managed_files`] resolved. Touches no `Db`.
/// Returns how many were actually there to delete — see
/// [`write_planned_managed_files`] for why an apply needs the count.
pub fn remove_planned_managed_files(paths: &[PathBuf]) -> Result<usize> {
    let mut removed = 0;
    for path in paths {
        if remove_managed(path)? {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Writes a file this project owns outright. Replaced, never written
/// through — see [`write_atomically`].
fn write_managed(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    write_atomically(path, body.as_bytes(), 0o644, None)
}

/// Replaces `path` with `content`: a new file beside it, then a rename
/// over it.
///
/// **A rename replaces a symlink; a write follows it.** Everything here
/// runs as root, and on a host whose NGINX tree is a bind mount an
/// unprivileged user may be able to create files in it. `fs::write` on a
/// `conf.d/stop-bots-trusted.conf` they had made a link to `/etc/shadow`
/// would have written our text there. The temporary file is created with
/// `O_EXCL` under a random name, so a link planted at a guessed name makes
/// the create fail rather than be followed. It is also what makes the
/// write atomic: NGINX, or a reload that races us, sees the old file or
/// the new one, never half of one.
///
/// A leading dot keeps the temporary file out of NGINX's own globs
/// (`include sites-enabled/*`), which, like the shell's, skip dot files.
fn write_atomically(
    path: &Path,
    content: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?
        .to_string_lossy();
    for _ in 0..8 {
        let temp = path.with_file_name(format!(".{name}.stop-bots-{:016x}", random_u64()));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to write {}", path.display()))
            }
        };
        let written = (|| -> std::io::Result<()> {
            file.write_all(content)?;
            if let Some((uid, gid)) = owner {
                // Best effort: only root can give a file away, and a
                // non-root run that got this far owns what it replaces.
                let _ = std::os::unix::fs::fchown(&file, Some(uid), Some(gid));
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            fs::rename(&temp, path)
        })();
        if let Err(err) = written {
            let _ = fs::remove_file(&temp);
            return Err(err).with_context(|| format!("failed to write {}", path.display()));
        }
        return Ok(());
    }
    anyhow::bail!(
        "failed to write {}: could not create a temporary file beside it",
        path.display()
    )
}

/// Unpredictable enough for a temporary file name, without a dependency:
/// std seeds every `RandomState` from the OS.
fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    hasher.finish()
}

/// Where an operator's site file really is: `path` itself, or, when a
/// symlink is involved, its target — which must be inside `root`.
///
/// Site files are legitimately links (`sites-enabled/x` to
/// `../sites-available/x`), so a link is followed rather than replaced.
/// But the same writable-tree case [`write_atomically`] is about applies:
/// a link to a file outside the NGINX config is not one this tool was
/// pointed at, and root rewriting whatever `server {` block it finds there
/// is exactly what the link was planted for.
fn resolve_site_file(path: &Path, root: &Path) -> Result<PathBuf> {
    let resolved =
        fs::canonicalize(path).with_context(|| format!("failed to read {}", path.display()))?;
    let as_given = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if resolved == as_given {
        return Ok(resolved);
    }
    let root = fs::canonicalize(root)
        .with_context(|| format!("failed to read the NGINX root {}", root.display()))?;
    if !resolved.starts_with(&root) {
        anyhow::bail!(
            "refusing to write {}: it links to {}, outside the NGINX root {}",
            path.display(),
            resolved.display(),
            root.display()
        );
    }
    Ok(resolved)
}

/// Writes an operator's site file in place of `path`, following a link to
/// it (see [`resolve_site_file`]) and keeping its mode and owner.
///
/// A file the operator made read-only stays unwritten: a rename would
/// replace it regardless of its permission bits, which is not what
/// `chmod 444` was asking for — and running without root is reported as
/// the permission error it is.
fn write_site_file(path: &Path, root: &Path, content: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let resolved = resolve_site_file(path, root)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&resolved)
        .with_context(|| format!("failed to write {}", path.display()))?;
    let meta = fs::metadata(&resolved)
        .with_context(|| format!("failed to read {}", resolved.display()))?;
    write_atomically(
        &resolved,
        content.as_bytes(),
        meta.mode() & 0o7777,
        Some((meta.uid(), meta.gid())),
    )
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
fn remove_managed(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
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
        agent_exemptions: db.site_agent_exemptions(site_id)?,
        request_rules: site_request_rules(db, site_id)?,
        trust: trusted_conf(db)?,
    })
}

/// The request-shape rules switched on for one site, in a stable order.
/// An unrecognised stored id is skipped rather than erroring: a database
/// written by a newer build must not stop an older one from applying
/// anything at all.
pub fn site_request_rules(db: &crate::db::Db, site_id: i64) -> Result<Vec<RequestRule>> {
    let mut rules: Vec<RequestRule> = db
        .site_request_rules(site_id)?
        .iter()
        .filter_map(|id| RequestRule::from_id(id))
        .collect();
    rules.sort();
    Ok(rules)
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
        // A block with no site row has no per-site settings by
        // definition — both are keyed on `sites.id`.
        exempt_paths: Vec::new(),
        agent_exemptions: Vec::new(),
        request_rules: Vec::new(),
        trust: trusted_conf(db)?,
    })
}

/// Renders the sentinel block content (without surrounding blank lines) for
/// `config`, or `None` when there's nothing to block — an empty pattern
/// list, or one whose every entry [`pattern_problem`] rejects. `None` is what
/// makes [`apply_block`] *remove* an existing block rather than write an
/// empty one.
///
/// The patterns are split (via [`chunk_patterns`]) into one `if` statement per
/// chunk when it's long enough to need it. Multiple sequential
/// `if ($http_user_agent ~* "...") { return <code>; }` statements are
/// equivalent to one big alternation — whichever fires first returns — so
/// splitting changes nothing about what gets blocked, only how it's
/// written, and a pattern short enough for one chunk renders as a single
/// `if`.
fn block_text(config: &BlockConfig) -> Option<String> {
    let chunks = chunk_patterns(&usable_patterns(&config.patterns), MAX_PATTERN_CHUNK_LEN);
    let pattern = (!chunks.is_empty()).then_some(chunks);
    // Nothing to block and nothing to serve means no block at all, which
    // is what makes `apply_block` *remove* an existing one. Note this is
    // not "no patterns" alone: robots.txt, rate limiting and HTTP/1.x
    // rejection are each reason enough to keep a block, and treating any
    // of them as nothing would delete the block carrying it the moment
    // every bot happened to be allowed.
    if pattern.is_none()
        && !config.serve_robots_txt
        && config.rate_limit_burst.is_none()
        && config.request_rules.is_empty()
    {
        return None;
    }
    let code = config.response.status_code();
    let (prefixes, exact) = effective_exempt_paths(config);
    let exemptions = exemption_regex(&prefixes, exact);

    let mut out = format!("    {BLOCK_BEGIN}\n");

    // Two things can decide a request is unwanted: its user agent, and
    // (optionally) its HTTP version. NGINX's `if` takes exactly one
    // condition and they don't compose, so more than one reason — or any
    // reason at all combined with an exemption — means the flag idiom:
    // initialise a variable, let each reason set it, clear it for exempt
    // paths, and act on it last. Order is the whole mechanism.
    //
    // A single reason with no exemptions keeps the older direct-`return`
    // form, so a plain bot-blocking site's config doesn't churn.
    //
    // Trust is a clear like an exemption, but only where there is a block
    // to clear: with nothing blocking, a trusted client already gets
    // through, and the flag dance would be noise. (Rate limiting needs no
    // `if` — it cannot have one — and is lifted by naming a zone keyed so
    // that a trusted client is not counted; see
    // `UNTRUSTED_RATE_LIMIT_ZONE`.)
    let blocks_something = pattern.is_some() || !config.request_rules.is_empty();
    let clears_trusted = config.trust.is_some() && blocks_something;
    // Like trust, and unlike the plain exemptions, only where there is a
    // block to clear: they are narrower than a plain exemption, so a site
    // with nothing blocking already lets their clients through.
    let agent_clears = if blocks_something {
        agent_exemption_clears(&config.agent_exemptions)
    } else {
        String::new()
    };
    let uses_flag = exemptions.is_some()
        || clears_trusted
        || !agent_clears.is_empty()
        || (pattern.is_some() && !config.request_rules.is_empty());

    if uses_flag {
        out.push_str("    set $stop_bots_block 0;\n");
    }
    // Tarpit is a normal rejection whose body is throttled to a crawl:
    // `$limit_rate` is a writable NGINX variable, and one byte per second
    // turns the few hundred bytes of a default error page into minutes of
    // held connection. Chosen over the `limit_req`-without-`nodelay`
    // idiom deliberately — that one needs an http-context `map` over
    // `$stop_bots_block`, and if the variable is ever undefined NGINX
    // refuses to start. This fails the other way: if a small body turns
    // out not to be throttled, the client simply gets an ordinary 403.
    let throttle = if config.response.is_tarpit() {
        "set $limit_rate 1;\n        "
    } else {
        ""
    };

    // The tail shared by every blocker's `if`: set the flag, or return
    // directly when there's only one reason and nothing to exempt.
    let set_blocked = if uses_flag {
        "set $stop_bots_block 1;\n    }\n".to_string()
    } else {
        format!("{throttle}return {code};\n    }}\n")
    };

    if let Some(chunks) = &pattern {
        for chunk in chunks {
            out.push_str(&format!(
                "    if ($http_user_agent ~* \"{chunk}\") {{\n        {set_blocked}"
            ));
        }
    }
    for rule in &config.request_rules {
        out.push_str(&format!(
            "    if ({}) {{\n        {set_blocked}",
            rule.condition()
        ));
    }
    if let Some(exemptions) = &exemptions {
        out.push_str(&format!(
            "    if ($uri ~* \"{exemptions}\") {{\n        set $stop_bots_block 0;\n    }}\n"
        ));
    }
    out.push_str(&agent_clears);
    if clears_trusted {
        // After every set, like the exemption clear, and for the same
        // reason: order is the mechanism. A trusted client is let through
        // whatever the reason it matched — a bot pattern, a request-shape
        // rule, a manual user-agent block.
        out.push_str(&format!(
            "    if ({TRUSTED_VAR}) {{\n        set $stop_bots_block 0;\n    }}\n"
        ));
    }
    if uses_flag {
        out.push_str(&format!(
            "    if ($stop_bots_block) {{\n        {throttle}return {code};\n    }}\n"
        ));
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
        let zone = if config.trust.is_some() {
            UNTRUSTED_RATE_LIMIT_ZONE
        } else {
            RATE_LIMIT_ZONE
        };
        out.push_str(&format!(
            "    limit_req zone={zone} burst={burst} nodelay;\n    limit_req_status 429;\n"
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

/// The exemptions actually applied, as `(prefixes, exact paths)`: the
/// site's configured prefixes, plus `/robots.txt` itself — exactly that
/// file, not everything under it — whenever this block serves it.
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
fn effective_exempt_paths(config: &BlockConfig) -> (Vec<String>, &'static [&'static str]) {
    let mut paths = config.exempt_paths.clone();
    let exact: &[&str] = if config.serve_robots_txt {
        &["/robots.txt"]
    } else {
        &[]
    };
    if !config.request_rules.is_empty() {
        // Never optional, and never surfaced as a setting to switch off.
        // `/.well-known/` is where ACME HTTP-01 validation is fetched
        // from, by a non-browser client speaking HTTP/1.1. Rejecting it
        // doesn't break anything today — it breaks certificate renewal
        // weeks later, which is about the least traceable failure this
        // project could ship. The same path prefix carries security.txt
        // and a pile of other machine-fetched documents, none of which
        // negotiate HTTP/2 either.
        paths.push("/.well-known/".to_string());
    }
    (paths, exact)
}

/// Narrows a site's config to what is actually safe to emit into *this*
/// `server` block.
///
/// Only one setting needs this today: HTTP/1.x rejection is dropped in a
/// block that doesn't terminate TLS. Browsers don't speak HTTP/2 without
/// it, so there every request is 1.1 and the rule would reject all
/// traffic — and a site's port-80 redirect and port-443 blocks routinely
/// share a `server_name`, which means one per-site setting reaches both.
/// Silently narrowing beats both alternatives: refusing to apply would
/// make a legitimate setting unusable on a normal two-block site, and
/// emitting it anyway would take the site down.
///
/// Status checks go through here too, so a site whose rule is correctly
/// omitted from its plain-HTTP block still reads as `UP TO DATE` rather
/// than permanently `STALE`.
fn for_block(config: &BlockConfig, block: &ServerBlock) -> BlockConfig {
    if block.is_tls {
        return config.clone();
    }
    BlockConfig {
        request_rules: config
            .request_rules
            .iter()
            .copied()
            .filter(|rule| !rule.needs_tls())
            .collect(),
        ..config.clone()
    }
}

/// Builds the `$uri` regex that clears the block flag, or `None` when
/// there are no usable exemptions: `prefixes` match anything under them,
/// `exact` only themselves.
///
/// Anchored with `^` and alternated, so `/blog` exempts `/blog` and
/// `/blog/post` but not `/notablog`. Each path is regex-escaped: these are
/// literal URL prefixes typed by an admin, not hand-written regex, and an
/// unescaped `.` or `?` in one would quietly widen the exemption far
/// beyond what was asked for — which, unlike a too-narrow pattern, fails
/// *open*.
///
/// Matched against `$uri`, never `$request_uri`, for the reason
/// [`agent_exemption_clears`] gives: the raw request line is not the path
/// NGINX serves, and `/robots.txt/../wp-login.php` begins with an exempt
/// prefix while resolving to a blocked one.
fn exemption_regex(prefixes: &[String], exact: &[&str]) -> Option<String> {
    let usable = |p: &&str| p.starts_with('/') && is_embeddable(p);
    let escaped: Vec<String> = prefixes
        .iter()
        .map(String::as_str)
        .filter(usable)
        .map(crate::db::escape_for_nginx_regex)
        .chain(
            exact
                .iter()
                .copied()
                .filter(usable)
                .map(|p| format!("{}$", crate::db::escape_for_nginx_regex(p))),
        )
        .collect();
    (!escaped.is_empty()).then(|| format!("^({})", escaped.join("|")))
}

/// The statements that clear the block flag for agent exemptions: one
/// group per user agent, or `""` when none is usable.
///
/// NGINX's `if` takes one condition, and "this user agent *and* this path"
/// is two. So each group puts the path into [`AGENT_EXEMPT_VAR`] only when
/// the user agent matches, and then tests that variable against the paths:
///
/// ```nginx
/// set $stop_bots_exempt "";
/// if ($http_user_agent ~* "okhttp") { set $stop_bots_exempt $uri; }
/// if ($stop_bots_exempt ~* "^(/remote\.php/dav/)") { set $stop_bots_block 0; }
/// ```
///
/// The reset opens every group, not just the first: a variable left
/// holding the path by one group's user agent would otherwise let the next
/// group's paths through for a client that never matched it.
///
/// `$uri`, not `$request_uri`, like the plain exemptions. `$uri` has had
/// `..` and `//` resolved and is decoded, so `/remote.php/dav/../../login`
/// is `/login` and matches nothing here; `$request_uri` is the raw request
/// line, where that same string starts with the exempt prefix while the
/// application behind the proxy resolves it to somewhere else. The plain
/// exemptions read `$request_uri` too until the same bypass was found
/// there.
///
/// The user agent is matched as an escaped, case-insensitive substring,
/// the same as a trusted one, and filtered again here rather than trusting
/// the caller, since one bad quoted string stops NGINX loading the file.
fn agent_exemption_clears(exemptions: &[crate::db::AgentExemption]) -> String {
    let mut out = String::new();
    for group in exemptions.chunk_by(|a, b| a.user_agent == b.user_agent) {
        let user_agent = crate::db::escape_for_nginx_regex(&group[0].user_agent);
        if user_agent.is_empty()
            || !is_embeddable(&user_agent)
            || user_agent.chars().any(char::is_control)
        {
            continue;
        }
        let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
        let Some(paths) = exemption_regex(&paths, &[]) else {
            continue;
        };
        out.push_str(&format!(
            "    set {AGENT_EXEMPT_VAR} \"\";\n    if ($http_user_agent ~* \"{user_agent}\") {{\n        set {AGENT_EXEMPT_VAR} $uri;\n    }}\n    if ({AGENT_EXEMPT_VAR} ~* \"{paths}\") {{\n        set $stop_bots_block 0;\n    }}\n"
        ));
    }
    out
}

/// Finds the byte range of an existing sentinel block's lines within
/// `block`, if one is already present.
fn locate_existing_block(content: &str, block: &ServerBlock) -> Option<(usize, usize)> {
    locate_marked(content, block, BLOCK_BEGIN, BLOCK_END)
}

/// The whole lines from a `begin` marker comment to the next `end` marker
/// comment inside `block`.
///
/// Markers are matched only as real comments, as [`lex`] finds them, and
/// only when the comment is exactly the marker. A text search found them
/// anywhere, including inside a quoted bot pattern: `# END stop-bots` in a
/// hand-blocked user agent ended the block half way through its first
/// `if`, and every later run left another copy behind.
fn locate_marked(
    content: &str,
    block: &ServerBlock,
    begin: &str,
    end: &str,
) -> Option<(usize, usize)> {
    let comments: Vec<(usize, usize)> = lex(content)
        .comments
        .into_iter()
        .filter(|&(start, _)| start > block.open && start < block.close)
        .collect();
    let is =
        |&(start, stop): &(usize, usize), marker: &str| content[start..stop].trim_end() == marker;
    let begin_at = comments.iter().find(|c| is(c, begin))?.0;
    let end_at = comments.iter().find(|c| c.0 > begin_at && is(c, end))?.1;
    let line_start = content[..begin_at].rfind('\n').map_or(0, |i| i + 1);
    let line_end = content[end_at..]
        .find('\n')
        .map_or(content.len(), |i| end_at + i + 1);
    Some((line_start, line_end))
}

/// Inserts, replaces or removes the sentinel bot-blocking block inside
/// `block`. A `config` that renders to nothing (see [`block_text`]) removes
/// any existing block. Idempotent: applying the same config twice yields
/// identical output.
fn apply_block(content: &str, block: &ServerBlock, config: &BlockConfig) -> String {
    let new_block = block_text(&for_block(config, block));

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

// ---- reaching the console from outside ----

/// Sentinel markers for the console's own `location` block.
///
/// Separate from [`BLOCK_BEGIN`]/[`BLOCK_END`] on purpose: the two live in
/// the same `server` block and are rewritten by different actions, so one
/// pair of markers would have "apply blocks" and "set up web access"
/// deleting each other's work.
const CONSOLE_BEGIN: &str = "# BEGIN stop-bots console (DO NOT EDIT)";
const CONSOLE_END: &str = "# END stop-bots console";

/// How the console is reached from outside this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleAccess {
    /// Its own `server` block on `host`, written as a new config file.
    ///
    /// Served over plain HTTP. Adding a certificate is a separate step
    /// (certbot), and until it is taken, the console's password form and
    /// its session cookie cross the network in the clear — which is why
    /// [`ConsoleAccess::Path`] is the default the panel offers.
    Subdomain { host: String },
    /// A `location` block inserted into an existing site's `server` block,
    /// which is how the console inherits that site's certificate.
    Path {
        /// Normalised with a leading and trailing slash, e.g. `/stop-bots/`.
        prefix: String,
        /// The site's config file, from `Db::list_sites`.
        config_path: PathBuf,
        /// The `server_name` whose block to edit.
        server_name: String,
    },
}

/// The `location` block that proxies to the console, shared by both modes.
///
/// `proxy_pass` deliberately has **no** trailing slash, and the location
/// keeps its prefix: this server matches the full path including the
/// prefix and generates links that do too, so a `proxy_pass` that stripped
/// it would leave every link pointing outside the location block. See
/// `--base-path` in `main.rs` for the same warning aimed at whoever writes
/// this by hand.
///
/// The prefix is quoted, with any `"` or `\` inside it escaped. It has
/// already passed `BasePath::parse`, which admits nothing NGINX treats as
/// syntax; the quotes are what keep that true if a prefix ever reaches
/// here some other way. This file is loaded by a root NGINX, and an
/// unquoted `;` or `}` in it is a directive of the caller's choosing.
fn console_location(prefix: &str, upstream: &std::net::SocketAddr) -> String {
    let prefix = prefix.replace('\\', r"\\").replace('"', r#"\""#);
    format!(
        "    {CONSOLE_BEGIN}\n    \
         location \"{prefix}\" {{\n        \
         proxy_pass http://{upstream};\n        \
         proxy_set_header Host $host;\n        \
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        \
         proxy_set_header X-Forwarded-Proto $scheme;\n    \
         }}\n    {CONSOLE_END}\n"
    )
}

/// A whole `server` block serving the console on `host` at `/`.
pub fn console_server_block(host: &str, upstream: &std::net::SocketAddr) -> String {
    format!(
        "# Written by stop-bots (`Web Access` panel). Safe to edit or delete.\n\
         #\n\
         # Plain HTTP: the console's password and session cookie are in the clear\n\
         # until this host has a certificate for {host}. Get one with:\n\
         #\n\
         #     certbot --nginx -d {host}\n\
         #\n\
         # then pass `--secure-cookie true` to `stop-bots web` or\n\
         # `stop-bots install web` so the cookie is HTTPS-only.\n\
         server {{\n    \
         listen 80;\n    \
         listen [::]:80;\n    \
         server_name {host};\n\n\
         {}}}\n",
        console_location("/", upstream)
    )
}

/// Where a subdomain-mode config file goes: `conf.d/<name>.conf` under the
/// config root.
///
/// `conf.d` rather than `sites-available` plus a symlink into
/// `sites-enabled`: Debian's default `nginx.conf` includes both, `conf.d`
/// needs no second step to take effect, and one file is one thing to
/// delete when an operator changes their mind.
pub fn console_site_path(root: &Path) -> PathBuf {
    root.join("conf.d").join("stop-bots-console.conf")
}

/// Inserts (or updates) the console's `location` block inside
/// `server_name`'s block in `content`.
///
/// Returns `None` if that file has no matching `server` block — a
/// mismatch between the database's idea of where a site lives and what is
/// on disk, which is a refusal rather than something to guess at.
fn with_console_location(
    content: &str,
    server_name: &str,
    prefix: &str,
    upstream: &std::net::SocketAddr,
) -> Option<String> {
    let blocks = parse_server_blocks(content);
    // Prefer the TLS block. A site normally has two — a port-80 redirect
    // and the real HTTPS one — and putting the console in the first would
    // serve its login form over cleartext on a host that has a
    // certificate sitting right there.
    let block = blocks
        .iter()
        .filter(|b| b.names.iter().any(|n| n == server_name))
        .max_by_key(|b| b.is_tls)?;

    let new_block = console_location(prefix, upstream);
    Some(match locate_console_block(content, block) {
        Some((start, end)) => {
            let mut out = String::with_capacity(content.len());
            out.push_str(&content[..start]);
            out.push_str(&new_block);
            out.push_str(&content[end..]);
            out
        }
        None => {
            let mut out = String::with_capacity(content.len() + new_block.len() + 1);
            out.push_str(&content[..block.open + 1]);
            out.push('\n');
            out.push_str(&new_block);
            out.push_str(&content[block.open + 1..]);
            out
        }
    })
}

/// [`locate_existing_block`] for the console markers.
fn locate_console_block(content: &str, block: &ServerBlock) -> Option<(usize, usize)> {
    locate_marked(content, block, CONSOLE_BEGIN, CONSOLE_END)
}

/// Writes `content` to `path`, validates the whole NGINX config, and puts
/// the previous state back if validation fails.
///
/// The reason this exists rather than a plain write: `apply_all_sites`
/// writes then tests, which is survivable when it edited an existing file
/// — but a *new* `server` block that fails `nginx -t` leaves the config
/// unloadable, and nothing looks wrong because the running NGINX keeps
/// serving from memory. The next reload is then somebody else's problem,
/// most likely certbot's renewal hook at 3am.
fn write_validated(path: &Path, content: &str, commands: &NginxCommands) -> Result<()> {
    let previous = fs::read_to_string(path).ok();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;

    if let Err(err) = test_config(commands) {
        // Put it back before reporting, so the operator is not left with a
        // config that cannot be loaded.
        let restored = match &previous {
            Some(text) => fs::write(path, text),
            None => fs::remove_file(path),
        };
        let note = if restored.is_ok() {
            "the previous config was restored"
        } else {
            "AND RESTORING THE PREVIOUS CONFIG ALSO FAILED — fix this by hand"
        };
        anyhow::bail!("{err:#}\n\n{}: {}", note, path.display());
    }
    Ok(())
}

/// Sets the console up to be reachable, and returns what it did.
///
/// Validated before it can take effect (see [`write_validated`]) and
/// reloaded only on success. The caller is responsible for the two
/// database settings that have to agree with this config — `web:base_path`
/// and `web:allowed_hosts` — because a console reachable at a path it does
/// not serve, or under a `Host` it refuses, is broken in a way that looks
/// like a 404 or a 403 rather than like a configuration mistake.
pub fn apply_console_access(
    root: &Path,
    access: &ConsoleAccess,
    upstream: &std::net::SocketAddr,
    commands: &NginxCommands,
) -> Result<PathBuf> {
    match access {
        ConsoleAccess::Subdomain { host } => {
            let path = console_site_path(root);
            write_validated(&path, &console_server_block(host, upstream), commands)?;
            Ok(path)
        }
        ConsoleAccess::Path {
            prefix,
            config_path,
            server_name,
        } => {
            let content = fs::read_to_string(config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?;
            let updated = with_console_location(&content, server_name, prefix, upstream)
                .with_context(|| {
                    format!(
                        "{} has no `server` block for {server_name} — re-scan sites and try again",
                        config_path.display()
                    )
                })?;
            write_validated(config_path, &updated, commands)?;
            Ok(config_path.clone())
        }
    }
}

/// Recursively walks `root` looking for NGINX config files containing
/// `server { ... }` blocks, returning one [`DiscoveredSite`] per block (named
/// after its first `server_name`). Files with no server block, or that
/// aren't valid UTF-8 text, are silently skipped.
///
/// A `root` that does not exist *is* an error, unlike anything unreadable
/// inside one. The difference matters: a mistyped `--root` used to walk
/// nothing and report "0 site(s)", which reads exactly like a correct run
/// against a server that has no sites — so the mistake looked like an
/// answer. A file that can't be read inside a real root is a different
/// thing, and still skipped.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    if !root.exists() {
        anyhow::bail!("{} does not exist", root.display());
    }
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
///
/// `root` is the NGINX config root: a `config_path` that is a symlink is
/// written through only to a target inside it (see [`write_site_file`]).
pub fn apply_blocks_to_file(
    config_path: &Path,
    root: &Path,
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
        let block = nth_block(&blocks, i, block_count, config_path)?;
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
    write_site_file(config_path, root, &content)?;
    Ok(true)
}

/// Block `i` of `blocks`, which must still number `expected`.
///
/// Re-parsing between edits relies on an edit never adding or removing a
/// `server` block. The sentinel block only holds quoted text and
/// `location`s, so it cannot, unless the reader and NGINX disagree about
/// where a quoted string ends — which is how a bot pattern once turned
/// into a second `server` block. Refusing is the safe answer if they ever
/// disagree again.
fn nth_block<'a>(
    blocks: &'a [ServerBlock],
    i: usize,
    expected: usize,
    config_path: &Path,
) -> Result<&'a ServerBlock> {
    if blocks.len() != expected {
        anyhow::bail!(
            "refusing to write {}: editing it changed how many server blocks it has",
            config_path.display()
        );
    }
    Ok(&blocks[i])
}

/// Whether a site's on-disk config currently matches the blocking rule
/// that would be computed for it right now — backs the TUI's per-site
/// status tag in NGINX.
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

/// Every `server_name` on the block that declares `server_name`, that one
/// included.
///
/// `scan-sites` stores a site under the *first* name on its block, because
/// one row needs one name. NGINX answers for all of them, so anything that
/// has to agree with NGINX about which hosts reach a site — the console's
/// own allowlist, so far — needs the rest too.
///
/// Falls back to just `server_name` if the file cannot be read or no block
/// declares it: a caller that gets one name behaves as it did before this
/// existed, which is the right way for this to fail.
pub fn server_names_for(config_path: &Path, server_name: &str) -> Vec<String> {
    let Ok(content) = fs::read_to_string(config_path) else {
        return vec![server_name.to_string()];
    };
    parse_server_blocks(&content)
        .into_iter()
        .find(|block| block.names.iter().any(|name| name == server_name))
        .map(|block| block.names)
        .filter(|names| !names.is_empty())
        .unwrap_or_else(|| vec![server_name.to_string()])
}

/// Compares what's actually written in `config_path` for `server_name`
/// against `config` (the currently computed blocking rule for that site)
/// without changing anything on disk.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
    conf_d: &Path,
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
    let trust_on_disk = config
        .trust
        .as_ref()
        .and_then(|_| fs::read_to_string(trusted_conf_path(conf_d)).ok());
    if matching
        .iter()
        .all(|block| current_block_text(&content, block) == block_text(&for_block(config, block)))
        && trust_file_is_current(config, trust_on_disk.as_deref())
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
/// changed on disk. `root` is as for [`apply_blocks_to_file`].
pub fn apply_block_for_site(
    config_path: &Path,
    root: &Path,
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
        let block = nth_block(&blocks, i, block_count, config_path)?;
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
    write_site_file(config_path, root, &content)?;
    Ok(true)
}

/// What [`apply_all_sites_and_reload`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyAllOutcome {
    pub sites: usize,
    pub files: usize,
    /// How many files were actually rewritten, generated ones (the trust
    /// file, the rate-limit zone) included. Zero means NGINX has nothing
    /// new to read, so there is no point reloading it.
    pub changed: usize,
    /// Whether the new config passed the test and NGINX was reloaded.
    pub reloaded: bool,
}

/// Applies the current blocking policy to every site discovered under
/// `root`, and — given `commands` — tests the result and reloads NGINX.
/// The one way every front-end applies everything.
///
/// **A config that fails the test is put back.** Every file the apply may
/// touch is read first ([`Snapshot`]); if the test then fails, each is
/// restored byte for byte and each generated file this apply created is
/// removed, before the error is returned. Writing and leaving it was
/// survivable only in appearance: the running NGINX keeps serving the old
/// config from memory, and the broken one is loaded by whatever reloads
/// next — certbot's renewal hook at 3am, or a reboot — taking every site
/// down together. A write that fails half way is put back the same way.
///
/// `None` writes without testing or reloading: `--no-reload` and
/// `--no-apply`, for a host whose NGINX this process must not touch.
pub fn apply_all_sites_and_reload(
    db: &crate::db::Db,
    root: &Path,
    commands: Option<&NginxCommands>,
) -> Result<ApplyAllOutcome> {
    let sites = discover_sites(root)?;
    let generated = planned_managed_files(db, root)?
        .into_iter()
        .map(|(path, _)| path)
        .chain(unused_managed_files(db, root)?);
    let snapshot = Snapshot::of_apply(
        root,
        generated,
        sites.iter().map(|site| site.config_path.as_path()),
    )?;

    let outcome = match apply_all_sites(db, root, &sites) {
        Ok(outcome) => outcome,
        Err(err) => return Err(snapshot.restore_after(err)),
    };
    let Some(commands) = commands.filter(|_| outcome.changed > 0) else {
        return Ok(outcome);
    };
    test_or_restore(&snapshot, commands)?;
    run(&commands.reload, "the NGINX reload")
        .context("the new config passed the test, but the reload failed")?;
    Ok(ApplyAllOutcome {
        reloaded: true,
        ..outcome
    })
}

/// The writing half of [`apply_all_sites_and_reload`].
///
/// The ordering below is load-bearing: generated files are written
/// *before* any config that aliases them, and unreferenced ones are
/// deleted only *after* every config has been rewritten (see
/// [`remove_unused_managed_files`]).
fn apply_all_sites(
    db: &crate::db::Db,
    root: &Path,
    sites: &[DiscoveredSite],
) -> Result<ApplyAllOutcome> {
    let mut changed = write_managed_files(db, root)?;
    let default_config = default_block_config(db)?;
    // Sites already known to the db (i.e. previously scanned) — the only
    // ones that can carry a per-site override at all.
    let known_sites = db.list_sites()?;

    // A single config file commonly holds multiple `server` blocks for the
    // same site (e.g. an HTTP redirect block plus the HTTPS one), so dedupe
    // by file and apply once per file rather than once per discovered site.
    let mut config_paths: Vec<_> = sites.iter().map(|s| s.config_path.clone()).collect();
    config_paths.sort();
    config_paths.dedup();

    for path in &config_paths {
        // Built fresh per file, filtered to sites that actually live in
        // *this* file: `server_name` alone isn't unique across the whole
        // `sites` table (two different files can share one, e.g. a stale
        // config left behind after a rename), so a single map built once
        // for the whole run could leak one site's override onto another's
        // same-named block in a different file. Note this join is a
        // textual `config_path` match, only valid when `root` here matches
        // whatever root was used at scan time — a mismatch just falls
        // through to `default_config`, not an error.
        let site_configs: Vec<(String, BlockConfig)> = known_sites
            .iter()
            .filter(|s| Path::new(&s.config_path) == path.as_path())
            .map(|s| Ok((s.server_name.clone(), block_config_for_site(db, s.id)?)))
            .collect::<Result<_>>()?;
        if apply_blocks_to_file(path, root, &site_configs, &default_config)? {
            changed += 1;
        }
    }

    // Only now that every config has been rewritten is it safe to delete a
    // generated file the new config no longer references.
    changed += remove_unused_managed_files(db, root)?;

    Ok(ApplyAllOutcome {
        sites: sites.len(),
        files: config_paths.len(),
        changed,
        reloaded: false,
    })
}

/// Applies one site's policy — its file and the generated files it reads —
/// and, given `commands`, tests and reloads the way
/// [`apply_all_sites_and_reload`] does. Returns the site's name and
/// whether anything changed.
pub fn apply_site_and_reload(
    db: &crate::db::Db,
    root: &Path,
    site: &crate::db::Site,
    commands: Option<&NginxCommands>,
) -> Result<(bool, bool)> {
    let managed = planned_managed_files(db, root)?;
    let config_path = Path::new(&site.config_path);
    let snapshot = Snapshot::of_apply(
        root,
        managed.iter().map(|(path, _)| path.clone()),
        [config_path],
    )?;

    let written = (|| -> Result<bool> {
        let managed_changed = write_planned_managed_files(&managed)?;
        let config = block_config_for_site(db, site.id)?;
        let site_changed = apply_block_for_site(config_path, root, &site.server_name, &config)?;
        Ok(managed_changed > 0 || site_changed)
    })();
    let changed = match written {
        Ok(changed) => changed,
        Err(err) => return Err(snapshot.restore_after(err)),
    };
    let Some(commands) = commands.filter(|_| changed) else {
        return Ok((changed, false));
    };
    test_or_restore(&snapshot, commands)?;
    run(&commands.reload, "the NGINX reload")
        .context("the new config passed the test, but the reload failed")?;
    Ok((changed, true))
}

/// Every file an apply may touch, as it was before the apply began, so
/// that a config NGINX rejects can be taken back.
///
/// Holds the bytes and the mode of each regular file, and "absent" for
/// anything else — so restoring removes a file the apply created. A
/// symlink counts as absent: the writes here replace a link rather than
/// following it (see [`write_atomically`]), and putting a planted one back
/// would put back the thing that was planted.
pub struct Snapshot {
    files: Vec<(PathBuf, Option<Held>)>,
}

/// A regular file's contents and permission bits, as [`Snapshot`] found
/// them: `(bytes, mode)`.
type Held = (Vec<u8>, u32);

impl Snapshot {
    /// Reads every file in `paths`. Fails if one exists and cannot be
    /// read, because an apply that could not be undone should not start.
    pub fn take(paths: impl IntoIterator<Item = PathBuf>) -> Result<Snapshot> {
        use std::os::unix::fs::PermissionsExt;
        let mut files = Vec::new();
        for path in paths {
            if files.iter().any(|(seen, _)| seen == &path) {
                continue;
            }
            let before = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => {
                    let bytes = fs::read(&path)
                        .with_context(|| format!("failed to read {}", path.display()))?;
                    Some((bytes, meta.permissions().mode() & 0o7777))
                }
                Ok(_) => None,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err).with_context(|| format!("failed to read {}", path.display()))
                }
            };
            files.push((path, before));
        }
        Ok(Snapshot { files })
    }

    /// A snapshot of what an apply under `root` may touch: `generated`
    /// files at their own paths, and each of `site_files` where it really
    /// is, which is where [`write_site_file`] will write it. A site file
    /// that cannot be resolved is left out; its write will fail with the
    /// same error, and that failure is what undoes the apply.
    pub fn of_apply<'a>(
        root: &Path,
        generated: impl IntoIterator<Item = PathBuf>,
        site_files: impl IntoIterator<Item = &'a Path>,
    ) -> Result<Snapshot> {
        Snapshot::take(
            generated.into_iter().chain(
                site_files
                    .into_iter()
                    .filter_map(|path| resolve_site_file(path, root).ok()),
            ),
        )
    }

    /// Puts every file back as it was. Carries on past a failure, so one
    /// stuck file does not leave the rest half restored, and names each
    /// one that could not be.
    pub fn restore(&self) -> Result<()> {
        let mut failed = Vec::new();
        for (path, before) in &self.files {
            let restored = match before {
                Some((bytes, _)) if fs::read(path).ok().as_ref() == Some(bytes) => Ok(()),
                Some((bytes, mode)) => write_atomically(path, bytes, *mode, None),
                None => match fs::symlink_metadata(path) {
                    Ok(meta) if meta.is_file() => fs::remove_file(path)
                        .with_context(|| format!("failed to remove {}", path.display())),
                    _ => Ok(()),
                },
            };
            if let Err(err) = restored {
                failed.push(format!("{err:#}"));
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("{}", failed.join("; "));
        }
        Ok(())
    }

    /// `err`, with whether the restore that follows it worked.
    fn restore_after(&self, err: anyhow::Error) -> anyhow::Error {
        match self.restore() {
            Ok(()) => err.context("nothing was applied: every file it changed was put back"),
            Err(restore) => err.context(format!(
                "AND PUTTING THE PREVIOUS FILES BACK FAILED, fix these by hand: {restore:#}"
            )),
        }
    }
}

/// Runs the configured test against what was just written, and on a
/// failure puts back everything `snapshot` holds before reporting.
pub fn test_or_restore(snapshot: &Snapshot, commands: &NginxCommands) -> Result<()> {
    test_config(commands).map_err(|err| snapshot.restore_after(err))
}

/// How to test and reload NGINX.
///
/// Two commands rather than two hardcoded invocations, because NGINX is
/// not always a service on this host. The case that forced it: NGINX in a
/// container, with its config on a bind mount this tool writes to. The
/// files are ours to edit, but `systemctl reload nginx` reloads nothing —
/// there is no such unit — and `nginx -t` either isn't installed or tests
/// a different config than the one the container will read. Both become
/// `docker exec <name> nginx ...` there.
///
/// Resolved from `Db` on the main thread and passed to the blocking half,
/// which by the rule in `app.rs` cannot reach a `Db` at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxCommands {
    /// Argv for the config check. Must exit non-zero on a bad config.
    pub test: Vec<String>,
    /// Argv for the reload.
    pub reload: Vec<String>,
}

impl NginxCommands {
    /// What a normal host install needs, and what every caller got before
    /// these were configurable.
    pub const DEFAULT_TEST: &'static str = "nginx -t";
    pub const DEFAULT_RELOAD: &'static str = "systemctl reload nginx";

    /// `settings` keys, alongside the rest of the `nginx:` family.
    pub const TEST_KEY: &'static str = "nginx:test_command";
    pub const RELOAD_KEY: &'static str = "nginx:reload_command";
    /// Where this host's site configs actually live.
    pub const ROOT_KEY: &'static str = "nginx:root";

    /// Reads both from `db`, falling back to the defaults for either one
    /// that was never set. A stored command that no longer parses is an
    /// error rather than a silent fallback: silently reloading the host's
    /// NGINX because the container command had an unbalanced quote is
    /// exactly the surprise this type exists to prevent.
    pub fn from_db(db: &crate::db::Db) -> Result<Self> {
        let stored = |key: &str, fallback: &str| -> Result<Vec<String>> {
            let raw = db.get_text_setting(key)?;
            let raw = raw.as_deref().unwrap_or(fallback);
            split_command(raw)
                .with_context(|| format!("the setting `{key}` is not a valid command"))
        };
        Ok(Self {
            test: stored(Self::TEST_KEY, Self::DEFAULT_TEST)?,
            reload: stored(Self::RELOAD_KEY, Self::DEFAULT_RELOAD)?,
        })
    }
}

/// The stock location, and what every host had before this was configurable.
pub const DEFAULT_ROOT: &str = "/etc/nginx";

/// Where to look for site configs: the flag if one was given, else the
/// stored setting, else the stock path.
///
/// The third member of the same family as `NginxCommands` and
/// `LogPaths`. An NGINX in a container moves three things away from their
/// defaults — the commands that drive it, the logs it writes, and the
/// directory its config lives in — and the first two were already stored
/// while this one had to be repeated on `scan-sites`, `apply-blocks`,
/// `install web`, `batch` and `tui`. Forgetting it on any one of them did
/// not error; it scanned `/etc/nginx`, found nothing, and reported
/// success over an empty set.
///
/// Flag beats setting, for the same reason it does for the log paths: a
/// one-off run against a checkout or a staging tree must not require the
/// stored value to be changed and put back.
pub fn root(db: &crate::db::Db, flag: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = flag {
        return Ok(path.to_path_buf());
    }
    Ok(db
        .get_text_setting(NginxCommands::ROOT_KEY)?
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT)))
}

impl Default for NginxCommands {
    fn default() -> Self {
        Self {
            test: split_command(Self::DEFAULT_TEST).expect("the default test command parses"),
            reload: split_command(Self::DEFAULT_RELOAD).expect("the default reload command parses"),
        }
    }
}

/// Splits a configured command into argv.
///
/// Deliberately *not* a shell: the string is never handed to `sh -c`, so
/// there is no expansion, no globbing, no `;` and no pipelines. What a
/// reload command needs is words, and words with spaces in them — a path
/// under `/Applications/...`, a container named with a space — which is
/// exactly single and double quotes and nothing else.
///
/// Keeping the shell out of it is the security-relevant half. This command
/// runs as root; `sh -c` would turn a settings row into arbitrary code, and
/// the settings table is reachable from the web UI.
pub fn split_command(input: &str) -> Result<Vec<String>> {
    let mut argv = Vec::new();
    let mut current = String::new();
    let mut has_word = false;
    let mut quote: Option<char> = None;

    for c in input.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => current.push(c),
            None if c == '\'' || c == '"' => {
                // An empty quoted string is still an argument, so the
                // word has to be marked as started here and not only by
                // pushing a character.
                quote = Some(c);
                has_word = true;
            }
            None if c.is_whitespace() => {
                if has_word {
                    argv.push(std::mem::take(&mut current));
                    has_word = false;
                }
            }
            None => {
                current.push(c);
                has_word = true;
            }
        }
    }

    if quote.is_some() {
        anyhow::bail!("unbalanced quote in `{input}`");
    }
    if has_word {
        argv.push(current);
    }
    if argv.is_empty() {
        anyhow::bail!("`{input}` is empty");
    }
    Ok(argv)
}

/// Runs `argv`, returning its stderr on a non-zero exit.
///
/// `output`, not `status`: `status` inherits stdout and stderr, so anything
/// the command says lands directly on the TUI's alternate screen and
/// corrupts it. Run non-root, `systemctl` additionally pulls in a polkit
/// agent, which takes over the terminal outright to ask for a password.
fn run(argv: &[String], what: &str) -> Result<()> {
    let (program, args) = argv.split_first().expect("argv is never empty");
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{}`", argv.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "{what} (`{}`) exited with {}: {}",
            argv.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Validates the currently-installed NGINX config. Run before every
/// [`reload_with`] so a malformed config — ours or an unrelated hand edit
/// elsewhere in the same install — is reported as a clear error here rather
/// than left for the admin to dig out of `systemctl status`.
fn test_config(commands: &NginxCommands) -> Result<()> {
    run(&commands.test, "the NGINX config test")
}

/// Reloads NGINX so a just-written blocking rule (from
/// [`apply_blocks_to_file`] or [`apply_block_for_site`]) actually takes
/// effect — writing the sentinel block to a site's config file alone does
/// nothing until NGINX re-reads it. Always preceded by [`test_config`]:
/// `systemctl reload` refuses a config that fails validation on its own too,
/// but checking explicitly here gets a message callers can show directly
/// rather than send the admin to `systemctl status`/`journalctl`.
pub fn reload_with(commands: &NginxCommands) -> Result<()> {
    test_config(commands)?;
    run(&commands.reload, "the NGINX reload")
}

#[cfg(test)]
mod tests {
    /// The gap this closes. An NGINX in a container moves three things:
    /// the commands that drive it, the logs it writes, and the directory
    /// its config lives in. The first two were stored; this one had to be
    /// repeated on five subcommands, and forgetting it anywhere scanned an
    /// empty /etc/nginx and reported success over nothing.
    #[test]
    fn a_stored_root_is_used_when_no_flag_is_given() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::ROOT_KEY, "/srv/domaci/nginx")
            .unwrap();
        assert_eq!(
            root(&db, None).unwrap(),
            std::path::PathBuf::from("/srv/domaci/nginx")
        );
    }

    #[test]
    fn nothing_stored_falls_back_to_the_stock_path() {
        let db = crate::db::Db::open_in_memory().unwrap();
        assert_eq!(
            root(&db, None).unwrap(),
            std::path::PathBuf::from(DEFAULT_ROOT)
        );
    }

    /// A one-off run against a checkout must not require the stored value
    /// to be changed and put back -- the same precedence `LogPaths` uses.
    #[test]
    fn an_explicit_flag_beats_the_stored_root() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::ROOT_KEY, "/srv/domaci/nginx")
            .unwrap();
        assert_eq!(
            root(&db, Some(std::path::Path::new("/tmp/fixture"))).unwrap(),
            std::path::PathBuf::from("/tmp/fixture")
        );
    }

    #[test]
    fn an_empty_stored_root_reads_as_unset() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::ROOT_KEY, "   ").unwrap();
        assert_eq!(
            root(&db, None).unwrap(),
            std::path::PathBuf::from(DEFAULT_ROOT),
            "whitespace should not become a path that scans nothing"
        );
    }

    use super::*;

    // ---- configured test/reload commands ----

    #[test]
    fn split_command_splits_on_whitespace() {
        assert_eq!(
            split_command("docker exec nginx nginx -s reload").unwrap(),
            ["docker", "exec", "nginx", "nginx", "-s", "reload"]
        );
    }

    #[test]
    fn split_command_collapses_runs_of_whitespace() {
        assert_eq!(
            split_command("  nginx\t\t-t  ").unwrap(),
            ["nginx", "-t"],
            "leading, trailing and repeated whitespace must not produce empty argv entries"
        );
    }

    #[test]
    fn split_command_keeps_quoted_spaces_in_one_argument() {
        for (input, expected) in [
            (r#"docker exec "my nginx" nginx -t"#, "my nginx"),
            (r#"docker exec 'my nginx' nginx -t"#, "my nginx"),
        ] {
            let argv = split_command(input).unwrap();
            assert_eq!(argv[2], expected, "input was: {input}");
            assert_eq!(argv.len(), 5, "input was: {input}");
        }
    }

    #[test]
    fn split_command_treats_an_empty_quoted_string_as_an_argument() {
        assert_eq!(
            split_command(r#"nginx "" -t"#).unwrap(),
            ["nginx", "", "-t"],
            "an empty argument is still an argument, and dropping it shifts every flag after it"
        );
    }

    #[test]
    fn split_command_rejects_an_unbalanced_quote() {
        let err = split_command(r#"docker exec "my nginx nginx -t"#).unwrap_err();
        assert!(
            err.to_string().contains("unbalanced quote"),
            "error was: {err}"
        );
    }

    #[test]
    fn split_command_rejects_a_command_with_no_words() {
        for input in ["", "   "] {
            assert!(
                split_command(input).is_err(),
                "{input:?} has no program to run, so it must not parse"
            );
        }
    }

    #[test]
    fn split_command_does_not_interpret_shell_metacharacters() {
        // The command is never handed to `sh -c`, so these are ordinary
        // characters in an argument. This test is the guard on that: if
        // anyone ever routes it through a shell, it starts failing.
        assert_eq!(
            split_command("nginx -t; rm -rf /").unwrap(),
            ["nginx", "-t;", "rm", "-rf", "/"],
            "`;` must be part of a word, not a command separator"
        );
    }

    #[test]
    fn nginx_commands_default_to_the_host_install() {
        let commands = NginxCommands::default();
        assert_eq!(commands.test, ["nginx", "-t"]);
        assert_eq!(commands.reload, ["systemctl", "reload", "nginx"]);
    }

    #[test]
    fn nginx_commands_fall_back_per_setting() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::RELOAD_KEY, "docker exec web nginx -s reload")
            .unwrap();

        let commands = NginxCommands::from_db(&db).unwrap();
        assert_eq!(
            commands.reload,
            ["docker", "exec", "web", "nginx", "-s", "reload"]
        );
        assert_eq!(
            commands.test,
            ["nginx", "-t"],
            "setting only the reload command must leave the test command at its default"
        );
    }

    #[test]
    fn nginx_commands_reject_a_stored_command_that_does_not_parse() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::TEST_KEY, r#"docker exec "web nginx -t"#)
            .unwrap();

        // Not a silent fallback: reloading the host's NGINX because the
        // container command had an unbalanced quote is the exact surprise
        // worth failing loudly over.
        let err = NginxCommands::from_db(&db).unwrap_err();
        assert!(
            err.to_string().contains(NginxCommands::TEST_KEY),
            "the error must name the setting at fault; it was: {err}"
        );
    }
    use std::fs;

    const FIXTURES_ROOT: &str = "tests/fixtures/nginx";

    /// Every `site_apply_status` test here leaves `trust` unset, so the
    /// trust file is never read and this path is never touched. Named
    /// rather than repeated inline so that a test which *does* set
    /// `trust` stands out by passing a real directory.
    fn no_trust_file() -> &'static Path {
        Path::new("/nonexistent/conf.d")
    }

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
        assert!(once.contains("BadBot|EvilCrawler"), "once was:\n{once}");
        assert!(once.contains("return 403;"), "once was:\n{once}");

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

        assert!(!second.contains("OldBot"), "second was:\n{second}");
        assert!(second.contains("NewBot"), "second was:\n{second}");
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
        assert!(removed.contains("listen 80;"), "removed was:\n{removed}");
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
        let changed = apply_blocks_to_file(&path, dir.path(), &[], &config).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains(BLOCK_BEGIN));
        assert!(
            written.contains("BadBot|EvilCrawler"),
            "written was:\n{written}"
        );

        let changed_again = apply_blocks_to_file(&path, dir.path(), &[], &config).unwrap();
        assert!(!changed_again);
    }

    #[test]
    fn apply_blocks_to_file_with_no_server_blocks_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx.conf");
        fs::write(&path, "events {}\nhttp {\n    include conf.d/*.conf;\n}\n").unwrap();

        let changed = apply_blocks_to_file(&path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();
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

        let changed = apply_blocks_to_file(&path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();
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
        let changed =
            apply_blocks_to_file(&path, dir.path(), &site_configs, &BlockConfig::default())
                .unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        let blocks = parse_server_blocks(&written);
        let a_region = &written[blocks[0].open..blocks[0].close];
        let b_region = &written[blocks[1].open..blocks[1].close];
        assert!(a_region.contains("OnlyOnA"), "a_region was:\n{a_region}");
        assert!(!a_region.contains("OnlyOnB"), "a_region was:\n{a_region}");
        assert!(b_region.contains("OnlyOnB"), "b_region was:\n{b_region}");
        assert!(!b_region.contains("OnlyOnA"), "b_region was:\n{b_region}");
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
        let changed =
            apply_blocks_to_file(&path, dir.path(), &[], &cfg(&["GlobalDefaultBot"])).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("GlobalDefaultBot"),
            "written was:\n{written}"
        );
    }

    #[test]
    fn site_apply_status_reports_not_found_for_a_missing_file() {
        let status = site_apply_status(
            Path::new("/nonexistent/does-not-exist.conf"),
            "example.com",
            &cfg(&["BadBot"]),
            no_trust_file(),
        );
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_reports_not_found_when_the_server_name_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "b.example", &cfg(&["BadBot"]), no_trust_file());
        assert_eq!(status, SiteApplyStatus::NotFound);
    }

    #[test]
    fn site_apply_status_is_up_to_date_when_nothing_is_expected_and_nothing_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status =
            site_apply_status(&path, "a.example", &BlockConfig::default(), no_trust_file());
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    #[test]
    fn site_apply_status_is_stale_when_a_rule_is_expected_but_not_yet_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]), no_trust_file());
        assert_eq!(status, SiteApplyStatus::Stale);
    }

    #[test]
    fn site_apply_status_is_up_to_date_once_the_matching_rule_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot", "EvilBot"])).unwrap();

        let status = site_apply_status(
            &path,
            "a.example",
            &cfg(&["BadBot", "EvilBot"]),
            no_trust_file(),
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
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["BadBot"]), no_trust_file());
        assert_eq!(status, SiteApplyStatus::UpToDate);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("AdminBot"), "written was:\n{written}");
        assert!(written.contains("BadBot"), "written was:\n{written}");
    }

    #[test]
    fn site_apply_status_is_stale_when_the_applied_pattern_differs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["OldBot"])).unwrap();

        let status = site_apply_status(&path, "a.example", &cfg(&["NewBot"]), no_trust_file());
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

        let changed =
            apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["OnlyOnA"])).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        let blocks = parse_server_blocks(&written);
        let a_region = &written[blocks[0].open..blocks[0].close];
        let b_region = &written[blocks[1].open..blocks[1].close];
        assert!(a_region.contains("OnlyOnA"), "a_region was:\n{a_region}");
        assert!(!b_region.contains(BLOCK_BEGIN));
    }

    #[test]
    fn apply_block_for_site_is_a_noop_once_already_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        assert!(apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap());
        assert!(!apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap());
    }

    #[test]
    fn apply_block_for_site_is_a_noop_for_an_unknown_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let original = "server {\n    server_name a.example;\n}\n";
        fs::write(&path, original).unwrap();

        let changed =
            apply_block_for_site(&path, dir.path(), "unknown.example", &cfg(&["BadBot"])).unwrap();
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
    fn usable_patterns_drops_only_the_unsafe_entries() {
        let patterns = vec![
            "GoodBot".to_string(),
            "Trailing\\".to_string(),
            "1h4x\\.com".to_string(),
        ];
        assert_eq!(usable_patterns(&patterns), ["GoodBot", "1h4x\\.com"]);
    }

    #[test]
    fn usable_patterns_is_empty_when_every_pattern_is_unsafe() {
        let patterns = vec!["Trailing\\".to_string(), "Quoted\"Bot".to_string()];
        assert!(usable_patterns(&patterns).is_empty());
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
        apply_blocks_to_file(&path, dir.path(), &[], &config).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("GoodBot"), "written was:\n{written}");
        assert!(
            !written.contains("TrailingBackslash"),
            "written was:\n{written}"
        );
        // The sentinel's own closing quote must be the last character
        // before the closing paren, i.e. immediately followed by `) {` —
        // not swallowed into an unterminated string.
        assert!(
            written.contains("~* \"GoodBot\") {"),
            "written was:\n{written}"
        );
    }

    #[test]
    fn chunk_patterns_keeps_everything_in_one_chunk_when_it_fits() {
        let chunks = chunk_patterns(&["AAA", "BBB", "CCC"], 2000);
        assert_eq!(chunks, vec!["AAA|BBB|CCC".to_string()]);
    }

    #[test]
    fn chunk_patterns_splits_only_between_patterns_once_the_limit_is_hit() {
        // Each pattern is 5 bytes; a limit of 11 fits exactly two plus
        // their separator (5 + 1 + 5 = 11) but not three.
        let patterns = ["AAAA0", "AAAA1", "AAAA2", "AAAA3"];
        let chunks = chunk_patterns(&patterns, 11);
        assert_eq!(
            chunks,
            vec!["AAAA0|AAAA1".to_string(), "AAAA2|AAAA3".to_string()]
        );
        // Rejoining every chunk with `|` must reconstruct the original,
        // order preserved.
        assert_eq!(chunks.join("|"), patterns.join("|"));
    }

    #[test]
    fn chunk_patterns_gives_an_oversized_pattern_its_own_chunk_rather_than_dropping_it() {
        let huge = "x".repeat(50);
        let chunks = chunk_patterns(&["AAA", &huge, "BBB"], 10);
        assert_eq!(chunks, ["AAA", huge.as_str(), "BBB"]);
    }

    #[test]
    fn chunk_patterns_never_emits_an_unsafe_chunk() {
        let chunks = chunk_patterns(&["AAA", "Evil\\", "Evil\"Bot", "BBB"], 2000);
        assert_eq!(chunks, ["AAA|BBB"]);
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
        apply_blocks_to_file(&path, dir.path(), &[], &config).unwrap();

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
        assert!(written.contains("BadBot0Agent"), "written was:\n{written}");
        assert!(
            written.contains("BadBot499Agent"),
            "written was:\n{written}"
        );
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
        apply_block_for_site(&path, dir.path(), "a.example", &config).unwrap();

        let status = site_apply_status(&path, "a.example", &config, no_trust_file());
        assert_eq!(status, SiteApplyStatus::UpToDate);
    }

    // ---- writing through links ----

    /// A link planted where a generated file goes is replaced, not written
    /// through: root would otherwise put our text wherever it pointed.
    #[test]
    fn a_generated_file_replaces_a_planted_link_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "precious\n").unwrap();
        let path = dir.path().join("stop-bots-trusted.conf");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        write_planned_managed_files(&[(path.clone(), "ours\n".to_string())]).unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
        assert!(fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(fs::read_to_string(&path).unwrap(), "ours\n");
    }

    fn one_site() -> &'static str {
        "server {\n    server_name a.example;\n}\n"
    }

    #[test]
    fn a_site_file_linking_outside_the_root_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nginx");
        fs::create_dir(&root).unwrap();
        let victim = dir.path().join("elsewhere.conf");
        fs::write(&victim, one_site()).unwrap();
        let link = root.join("a.conf");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = apply_blocks_to_file(&link, &root, &[], &cfg(&["BadBot"])).unwrap_err();

        assert!(
            err.to_string().contains("outside the NGINX root"),
            "error was: {err}"
        );
        assert_eq!(fs::read_to_string(&victim).unwrap(), one_site());
    }

    /// `sites-enabled/x` linking to `../sites-available/x` is the normal
    /// Debian layout: written through, and still a link afterwards.
    #[test]
    fn a_site_file_linking_inside_the_root_is_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir(root.join("sites-available")).unwrap();
        fs::create_dir(root.join("sites-enabled")).unwrap();
        let target = root.join("sites-available/a.conf");
        fs::write(&target, one_site()).unwrap();
        let link = root.join("sites-enabled/a.conf");
        std::os::unix::fs::symlink("../sites-available/a.conf", &link).unwrap();

        assert!(apply_blocks_to_file(&link, root, &[], &cfg(&["BadBot"])).unwrap());

        assert!(fs::read_to_string(&target).unwrap().contains("BadBot"));
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    }

    #[test]
    fn a_rewritten_site_file_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.conf");
        fs::write(&path, one_site()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        apply_blocks_to_file(&path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
    }

    // ---- taking an apply back ----

    #[test]
    fn a_snapshot_puts_back_changed_files_and_removes_created_ones() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("a.conf");
        let created = dir.path().join("stop-bots-limits.conf");
        fs::write(&existing, one_site()).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o640)).unwrap();

        let snapshot = Snapshot::take([existing.clone(), created.clone()]).unwrap();
        fs::write(&existing, "broken").unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&created, "new").unwrap();
        snapshot.restore().unwrap();

        assert_eq!(fs::read_to_string(&existing).unwrap(), one_site());
        assert_eq!(
            fs::metadata(&existing).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert!(!created.exists());
    }

    #[test]
    fn a_failed_test_puts_the_site_back_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.conf");
        fs::write(&path, one_site()).unwrap();
        let snapshot = Snapshot::of_apply(dir.path(), [], [path.as_path()]).unwrap();
        apply_blocks_to_file(&path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();

        let err = test_or_restore(&snapshot, &commands_that(false)).unwrap_err();

        assert_eq!(fs::read_to_string(&path).unwrap(), one_site());
        assert!(
            format!("{err:#}").contains("put back"),
            "error was: {err:#}"
        );
    }

    // ---- chunking never splits a pattern ----

    /// Patterns whose `|`-join is exactly `len` bytes, so a test can put the
    /// next pattern right on a chunk boundary.
    fn filler(len: usize) -> Vec<String> {
        let mut patterns = Vec::new();
        let mut used = 0;
        while used + 14 + 20 < len {
            used += usize::from(!patterns.is_empty()) + 13;
            patterns.push(format!("FillerBot{:04}", patterns.len()));
        }
        patterns.push("P".repeat(len - used - 1));
        patterns
    }

    /// The quoted regex of every `$http_user_agent` test in `text`.
    fn user_agent_regexes(text: &str) -> Vec<&str> {
        text.split("if ($http_user_agent ~* \"")
            .skip(1)
            .map(|rest| &rest[..rest.find("\") {\n").expect("closing quote")])
            .collect()
    }

    /// The injection: a chunk that ended in the backslash of `\|` escaped
    /// NGINX's closing quote, and the next chunk was read as directives.
    #[test]
    fn a_chunk_boundary_never_lands_inside_an_escaped_pipe() {
        let mut patterns = filler(1994);
        patterns.push(r"Evil\|Bot".to_string());
        let text = block_text(&BlockConfig::new(patterns, BlockResponse::Forbidden)).unwrap();

        let regexes = user_agent_regexes(&text);
        assert!(regexes.len() > 1, "the test needs two chunks:\n{text}");
        for regex in &regexes {
            assert!(
                is_embeddable(regex),
                "unsafe chunk ends {:?}",
                &regex[regex.len() - 12..]
            );
        }
        assert!(
            regexes.iter().any(|r| r.contains(r"Evil\|Bot")),
            "the pattern must be written whole:\n{text}"
        );
    }

    /// Not an injection, but the same cut: a group split across two `if`s
    /// is two regexes NGINX refuses to compile.
    #[test]
    fn a_chunk_boundary_never_lands_inside_a_group() {
        let mut patterns = filler(1990);
        patterns.push("(Alpha|Beta)Bot".to_string());
        let text = block_text(&BlockConfig::new(patterns, BlockResponse::Forbidden)).unwrap();

        let regexes = user_agent_regexes(&text);
        assert!(regexes.len() > 1, "the test needs two chunks:\n{text}");
        assert!(
            regexes.iter().any(|r| r.contains("(Alpha|Beta)Bot")),
            "the group must be written whole:\n{text}"
        );
    }

    #[test]
    fn chunks_hold_whole_patterns() {
        let patterns = ["AAAA0", r"A\|A1", "AAAA2"];
        assert_eq!(chunk_patterns(&patterns, 11), ["AAAA0|A\\|A1", "AAAA2"]);
    }

    // ---- patterns that match every visitor ----

    /// Each of these, joined into the block, turns every visitor of every
    /// site away — and `nginx -t` accepts every one of them.
    #[test]
    fn a_pattern_that_matches_everyone_is_never_written() {
        for (pattern, why) in [
            ("", "empty"),
            ("   ", "whitespace only"),
            ("|", "two empty alternatives"),
            ("|EvilBot", "a leading empty alternative"),
            ("EvilBot|", "a trailing empty alternative"),
            ("Evil||Bot", "an empty alternative in the middle"),
            ("(|Evil)Bot", "an empty alternative opening a group"),
            ("Evil(Bot|)", "an empty alternative closing a group"),
            (".*", "a wildcard"),
            (".", "any one character"),
            (".+", "one or more of anything"),
            ("^", "an anchor"),
            ("^.*$", "anchors and a wildcard"),
            ("ab", "two literal characters"),
            ("a.b", "two literal characters and a wildcard"),
            ("a?b?c?", "every literal optional"),
            ("(abc)?", "an optional group"),
            ("(abc)*", "a starred group"),
            ("[a-z]{3}", "classes are not literals"),
            ("Bot|.*", "one match-all alternative is enough"),
        ] {
            assert!(
                !is_usable_pattern(pattern),
                "{pattern:?} ({why}) must be dropped"
            );
            assert!(
                block_text(&cfg(&[pattern])).is_none(),
                "{pattern:?} ({why}) must not produce a block"
            );
        }
    }

    #[test]
    fn a_pattern_that_can_backtrack_catastrophically_is_never_written() {
        for pattern in [
            "EvilBot(a+)+",
            "EvilBot(.*)*",
            "EvilBot(x?){2,}",
            "Evil(Bot(a*))+",
        ] {
            assert!(!is_usable_pattern(pattern), "{pattern:?} must be dropped");
        }
    }

    #[test]
    fn a_pattern_this_tool_cannot_check_is_never_written() {
        for pattern in [
            "Evil(Bot",
            "EvilBot)",
            "[EvilBot",
            "(?=Evil)Bot",
            r"Evil\x41Bot",
            "*EvilBot",
            "Evil\nBot",
            "Evil\tBot",
        ] {
            assert!(!is_usable_pattern(pattern), "{pattern:?} must be dropped");
        }
        assert!(!is_usable_pattern(&"E".repeat(MAX_PATTERN_LEN + 1)));
    }

    /// Shapes the real upstream lists use, which must all survive. Checked
    /// once by hand against all 1,675 entries of the three live lists
    /// (September 2026): none is dropped.
    #[test]
    fn real_upstream_pattern_shapes_are_kept() {
        for pattern in [
            "FDM",
            "Y!J",
            r"Googlebot\/",
            r"1h4x\.com",
            r"ALittle\ Client",
            "Qwant(?:ify|bot)",
            "[cC]laude(?:[bB]ot|-[Ww]eb)",
            "i[Tt][Mm][Ss]",
            r"Datadog(?:\/{0,1}Synthetics| Synthetic)",
            r"^Mozilla\/5\.0 \(compatible; Evil\)$",
            r"Chrome\/\d+ Evil",
            "ChatGPT Agent",
            "EvilBot(ab)+",
            "x server {",
        ] {
            assert!(is_usable_pattern(pattern), "{pattern:?} must be kept");
        }
    }

    // ---- re-reading what this tool wrote: quotes, comments, braces ----

    /// Patterns NGINX reads as plain text inside the quoted regex, but
    /// that a quote-blind reader takes for a comment, a brace, a new
    /// `server` block or one of this tool's own markers.
    fn awkward_patterns() -> Vec<String> {
        vec![
            "Evil#Bot".to_string(),
            "Evil}Bot".to_string(),
            "x server {".to_string(),
            crate::db::escape_for_nginx_regex("x # END stop-bots"),
            crate::db::escape_for_nginx_regex(BLOCK_BEGIN),
        ]
    }

    /// Applies `config` to a one-site file three times and returns what
    /// each run left on disk.
    fn apply_three_times(original: &str, config: &BlockConfig) -> [String; 3] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, original).unwrap();
        std::array::from_fn(|_| {
            apply_blocks_to_file(&path, dir.path(), &[], config).unwrap();
            fs::read_to_string(&path).unwrap()
        })
    }

    #[test]
    fn reapplying_is_idempotent_whatever_a_pattern_contains() {
        let site = "server {\n    listen 80;\n    server_name a.example;\n}\n";
        for pattern in awkward_patterns() {
            let [first, second, third] = apply_three_times(site, &cfg(&["GoodBot", &pattern]));
            assert_eq!(
                second, first,
                "a second run changed the file for {pattern:?}"
            );
            assert_eq!(third, first, "a third run changed the file for {pattern:?}");
            assert_eq!(
                first.matches(&pattern).count(),
                1,
                "{pattern:?} must be written exactly once:\n{first}"
            );
            assert_eq!(
                parse_server_blocks(&first).len(),
                1,
                "{pattern:?} must not read as a second server block:\n{first}"
            );
        }
    }

    #[test]
    fn every_awkward_pattern_at_once_is_still_idempotent() {
        let site = "server {\n    listen 80;\n    server_name a.example;\n}\n";
        let patterns = awkward_patterns();
        let config = BlockConfig::new(patterns.clone(), BlockResponse::Forbidden);
        let [first, second, third] = apply_three_times(site, &config);
        assert_eq!(second, first);
        assert_eq!(third, first);
        assert_eq!(first.matches("return 403;").count(), 1, "was:\n{first}");
    }

    /// An operator's own quoted `#` and braces are no more a comment or a
    /// block than ours are.
    #[test]
    fn an_operators_quoted_hash_and_braces_survive_reapplying() {
        let site = "server {\n    listen 80;\n    server_name a.example;\n    \
                    add_header X-Note \"see #docs {here}\";\n    \
                    add_header X-Other 'it''s #fine';\n}\n";
        let [first, second, _] = apply_three_times(site, &cfg(&["BadBot"]));
        assert_eq!(second, first);
        assert!(
            first.contains("add_header X-Note \"see #docs {here}\";"),
            "was:\n{first}"
        );
        assert_eq!(parse_server_blocks(&first)[0].names, ["a.example"]);
    }

    #[test]
    fn a_hash_inside_a_bare_word_is_not_a_comment() {
        let blocks = parse_server_blocks("server {\n    server_name a#b.example;\n}\n");
        assert_eq!(blocks[0].names, ["a#b.example"]);
    }

    #[test]
    fn a_brace_inside_a_quoted_word_is_not_structure() {
        let content = "server {\n    server_name a.example;\n    add_header X \"}\";\n}\n\
                       server {\n    server_name b.example;\n}\n";
        let names: Vec<_> = parse_server_blocks(content)
            .into_iter()
            .map(|b| b.names)
            .collect();
        assert_eq!(names, [["a.example"], ["b.example"]]);
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
        assert!(
            forbidden.contains("return 403;"),
            "forbidden was:\n{forbidden}"
        );
        assert!(
            !forbidden.contains("return 444;"),
            "forbidden was:\n{forbidden}"
        );

        let close = block_text(&cfg_444(&["BadBot"])).unwrap();
        assert!(close.contains("return 444;"), "close was:\n{close}");
        assert!(!close.contains("return 403;"), "close was:\n{close}");
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
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg(&["BadBot"]), no_trust_file()),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_444(&["BadBot"]), no_trust_file()),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn re_applying_with_a_new_response_code_rewrites_the_block_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();

        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();
        let changed =
            apply_block_for_site(&path, dir.path(), "a.example", &cfg_444(&["BadBot"])).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains("return 444;"), "written was:\n{written}");
        assert!(!written.contains("return 403;"), "written was:\n{written}");
        // Still exactly one sentinel block, not a second one appended.
        assert_eq!(written.matches(BLOCK_BEGIN).count(), 1);
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_444(&["BadBot"]), no_trust_file()),
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        }
    }

    #[test]
    fn block_text_emits_a_robots_location_only_when_enabled() {
        let without = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!without.contains("/robots.txt"), "without was:\n{without}");

        let with = block_text(&cfg_robots(&["BadBot"])).unwrap();
        assert!(with.contains("location = /robots.txt"), "with was:\n{with}");
        assert!(
            with.contains("default_type text/plain;"),
            "with was:\n{with}"
        );
        // The body is aliased, never inlined — see `serve_robots_txt`.
        assert!(with.contains("alias "), "with was:\n{with}");
        assert!(!with.contains("User-agent:"), "with was:\n{with}");
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("location = /robots.txt"), "text was:\n{text}");
        assert!(!text.contains("if ($http_user_agent"), "text was:\n{text}");
    }

    #[test]
    fn site_apply_status_is_stale_when_only_robots_txt_is_toggled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_robots(&["BadBot"]),
                no_trust_file()
            ),
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

        assert!(body.contains("User-agent: GPTBot\n"), "body was:\n{body}");
        assert!(body.contains("User-agent: CCBot\n"), "body was:\n{body}");
        // One shared Disallow: / for the whole group, not one per bot.
        assert_eq!(body.matches("Disallow: /\n").count(), 1);
    }

    #[test]
    fn robots_txt_body_skips_names_that_are_not_usable_tokens() {
        let db = crate::db::Db::open_in_memory().unwrap();
        seed_bot(&db, "spacey", "Some AI Crawler", true);
        let body = robots_txt_body(&db).unwrap();
        assert!(!body.contains("Some AI Crawler"), "body was:\n{body}");
    }

    #[test]
    fn robots_txt_body_omits_bots_that_are_not_blocked() {
        let db = crate::db::Db::open_in_memory().unwrap();
        seed_bot(&db, "gptbot", "GPTBot", true);
        db.set_bot_status("gptbot", crate::db::BotStatus::Allowed)
            .unwrap();

        let body = robots_txt_body(&db).unwrap();
        assert!(!body.contains("GPTBot"), "body was:\n{body}");
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
        assert!(body.contains("User-agent: *"), "body was:\n{body}");
        assert!(body.contains("Disallow:"), "body was:\n{body}");
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        }
    }

    #[test]
    fn block_text_emits_limit_req_only_when_enabled() {
        let without = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!without.contains("limit_req"), "without was:\n{without}");

        let with = block_text(&cfg_rate(20)).unwrap();
        assert!(
            with.contains("limit_req zone=stop_bots burst=20 nodelay;"),
            "with was:\n{with}"
        );
        assert!(with.contains("limit_req_status 429;"), "with was:\n{with}");
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
        assert!(
            conf.contains("limit_req_zone $binary_remote_addr"),
            "conf was:\n{conf}"
        );
        assert!(conf.contains("zone=stop_bots:16m"), "conf was:\n{conf}");
        assert!(conf.contains("rate=30r/s"), "conf was:\n{conf}");
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("limit_req"), "text was:\n{text}");
        assert!(!text.contains("if ($http_user_agent"), "text was:\n{text}");
    }

    #[test]
    fn site_apply_status_is_stale_when_only_the_rate_limit_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg_rate(20)).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_rate(20), no_trust_file()),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg_rate(50), no_trust_file()),
            SiteApplyStatus::Stale
        );
        assert_eq!(
            site_apply_status(&path, "a.example", &cfg(&["BadBot"]), no_trust_file()),
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        }
    }

    /// With no exemptions the block keeps its original direct-`return`
    /// shape, so upgrading doesn't rewrite every already-applied site.
    #[test]
    fn no_exemptions_keeps_the_direct_return_form() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(
            text.contains("if ($http_user_agent ~* \"BadBot\") {"),
            "text was:\n{text}"
        );
        assert!(text.contains("return 403;"), "text was:\n{text}");
        assert!(!text.contains("$stop_bots_block"), "text was:\n{text}");
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
        assert!(
            text.contains("if ($uri ~* \"^(/blog)\")"),
            "text was:\n{text}"
        );
        assert!(text.contains("return 403;"), "text was:\n{text}");
    }

    /// `$request_uri` is the raw request line. `GET
    /// /blog/../wp-login.php` starts with `/blog` there, while NGINX and the
    /// application behind it serve `/wp-login.php` — a blocked bot reaching
    /// any path by prefixing an exempt one. `$uri` is already resolved.
    #[test]
    fn a_plain_exemption_matches_the_resolved_path_not_the_raw_one() {
        let text = block_text(&cfg_exempt(&["BadBot"], &["/blog"])).unwrap();
        assert!(
            text.contains("if ($uri ~* \"^(/blog)\")"),
            "text was:\n{text}"
        );
        assert!(!text.contains("$request_uri"), "text was:\n{text}");
    }

    /// `/robots.txt` is one file, not a prefix: `/robots.txt/../x` and
    /// `/robots.txtanything` are not it.
    #[test]
    fn the_robots_txt_exemption_is_exact() {
        let config = BlockConfig {
            serve_robots_txt: true,
            ..cfg_exempt(&["BadBot"], &["/blog"])
        };
        let text = block_text(&config).unwrap();
        assert!(
            text.contains("if ($uri ~* \"^(/blog|/robots\\.txt$)\")"),
            "text was:\n{text}"
        );
    }

    #[test]
    fn the_exemption_regex_is_anchored_and_alternated() {
        assert_eq!(
            exemption_regex(&["/blog".to_string(), "/feed".to_string()], &[]),
            Some("^(/blog|/feed)".to_string())
        );
    }

    /// Unescaped regex metacharacters in a literal URL prefix would widen
    /// the exemption — which fails *open*, unlike a too-narrow pattern.
    #[test]
    fn the_exemption_regex_escapes_metacharacters() {
        let regex = exemption_regex(&["/a.b?c".to_string()], &[]).unwrap();
        assert!(regex.contains("\\."), "regex was: {regex}");
        assert!(regex.contains("\\?"), "regex was: {regex}");
    }

    #[test]
    fn the_exemption_regex_drops_unusable_paths() {
        // Not anchored at the start: could never match, so it's dropped
        // rather than silently widening or narrowing anything.
        assert_eq!(exemption_regex(&["blog".to_string()], &[]), None);
        // Would terminate the quoted config string.
        assert_eq!(exemption_regex(&["/a\"b".to_string()], &[]), None);
        assert_eq!(exemption_regex(&[], &[]), None);
    }

    // ---- agent exemptions ----

    fn agent(user_agent: &str, path: &str) -> crate::db::AgentExemption {
        crate::db::AgentExemption {
            path: path.to_string(),
            user_agent: user_agent.to_string(),
        }
    }

    /// `patterns` blocked, with `exemptions` as the site's agent
    /// exemptions — sorted by user agent, as the database returns them.
    fn cfg_agent(patterns: &[&str], exemptions: &[(&str, &str)]) -> BlockConfig {
        BlockConfig {
            agent_exemptions: exemptions
                .iter()
                .map(|(ua, path)| agent(ua, path))
                .collect(),
            ..cfg(patterns)
        }
    }

    /// The Boox reader and the Jellyfin player: two apps a bot list
    /// catches by their HTTP library, each let through on its own paths,
    /// beside a plain exemption.
    #[test]
    fn an_agent_exemption_block_matches_the_golden() {
        let config = BlockConfig {
            exempt_paths: vec!["/ocs/v2.php/cloud/capabilities".to_string()],
            ..cfg_agent(
                &["okhttp", "BadBot"],
                &[
                    ("Jellyfin Android", "/videos/"),
                    ("okhttp", "/remote.php/dav/"),
                    ("okhttp", "/remote.php/webdav/"),
                ],
            )
        };
        crate::golden::assert_golden(
            "nginx-block-agent-exemptions.conf",
            &block_text(&config).unwrap(),
        );
    }

    #[test]
    fn an_agent_exemption_forces_the_flag_form_and_clears_after_every_set() {
        let text = block_text(&cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")])).unwrap();

        let set_one = text.find("set $stop_bots_block 1;").unwrap();
        let clear = text.rfind("set $stop_bots_block 0;").unwrap();
        let act = text.find("if ($stop_bots_block) {").unwrap();
        assert!(set_one < clear, "the clear must follow the match:\n{text}");
        assert!(clear < act, "act last:\n{text}");
    }

    /// Without the reset, a variable left holding the path by one group's
    /// user agent would let the next group's paths through for a client
    /// that never matched that group.
    #[test]
    fn every_agent_group_starts_by_resetting_the_variable() {
        let text = block_text(&cfg_agent(
            &["BadBot"],
            &[("Alpha", "/a/"), ("Beta", "/b/")],
        ))
        .unwrap();
        let resets: Vec<usize> = text
            .match_indices("set $stop_bots_exempt \"\";")
            .map(|(i, _)| i)
            .collect();
        let alpha = text.find("~* \"Alpha\"").unwrap();
        let beta = text.find("~* \"Beta\"").unwrap();
        assert_eq!(resets.len(), 2, "one reset per user agent:\n{text}");
        assert!(
            resets[0] < alpha && alpha < resets[1] && resets[1] < beta,
            "each group's reset must precede its own match:\n{text}"
        );
    }

    /// `$request_uri` is the raw request line: `/remote.php/dav/../../x`
    /// starts with the exempt prefix there, and the application resolves it
    /// to `/x`. `$uri` has already been resolved by NGINX.
    #[test]
    fn an_agent_exemption_matches_the_resolved_path_not_the_raw_one() {
        let text = block_text(&cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")])).unwrap();
        assert!(
            text.contains("set $stop_bots_exempt $uri;"),
            "text was:\n{text}"
        );
        assert!(!text.contains("$request_uri"), "text was:\n{text}");
    }

    #[test]
    fn an_agent_exemption_escapes_the_user_agent_and_the_paths() {
        let text = block_text(&cfg_agent(
            &["okhttp"],
            &[("okhttp/4.10.0", "/remote.php/dav/")],
        ))
        .unwrap();
        for expected in [
            "if ($http_user_agent ~* \"okhttp/4\\.10\\.0\")",
            "if ($stop_bots_exempt ~* \"^(/remote\\.php/dav/)\")",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected}; text was:\n{text}"
            );
        }
    }

    /// Narrower than a plain exemption, so with nothing blocking there is
    /// nothing for them to do — and, unlike a plain one, they don't even
    /// force the flag form beside robots.txt.
    #[test]
    fn agent_exemptions_alone_write_nothing() {
        let exemptions = &[("okhttp", "/remote.php/dav/")];
        assert!(block_text(&cfg_agent(&[], exemptions)).is_none());

        let robots_only = BlockConfig {
            serve_robots_txt: true,
            ..cfg_agent(&[], exemptions)
        };
        let text = block_text(&robots_only).unwrap();
        assert!(!text.contains("stop_bots_exempt"), "text was:\n{text}");
    }

    /// Each would either break the quoted config string or never match —
    /// and a group left with no usable path is dropped whole, so the block
    /// falls back to the direct-`return` form rather than an empty clear.
    #[test]
    fn unusable_agent_exemptions_are_dropped() {
        for (description, user_agent, path) in [
            ("a quote in the user agent", "ok\"http", "/dav/"),
            ("a control character", "ok\thttp", "/dav/"),
            ("an empty user agent", "", "/dav/"),
            ("a path with no leading slash", "okhttp", "dav/"),
            ("a quote in the path", "okhttp", "/da\"v/"),
        ] {
            let text = block_text(&cfg_agent(&["okhttp"], &[(user_agent, path)])).unwrap();
            assert!(
                !text.contains("stop_bots_exempt") && text.contains("return 403;"),
                "{description} should have been dropped; text was:\n{text}"
            );
        }
    }

    #[test]
    fn site_apply_status_is_stale_when_only_an_agent_exemption_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["okhttp"])).unwrap();
        let exempted = cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")]);

        let before = site_apply_status(&path, "a.example", &exempted, no_trust_file());
        apply_block_for_site(&path, dir.path(), "a.example", &exempted).unwrap();
        let after = site_apply_status(&path, "a.example", &exempted, no_trust_file());

        assert_eq!(
            (before, after),
            (SiteApplyStatus::Stale, SiteApplyStatus::UpToDate)
        );
    }

    #[test]
    fn a_sites_block_config_carries_its_agent_exemptions() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.upsert_site("a.example", "/etc/nginx/a.conf").unwrap();
        let site_id = db.list_sites().unwrap()[0].id;
        db.add_site_agent_exemption(site_id, "/remote.php/dav/", "okhttp")
            .unwrap();

        let config = block_config_for_site(&db, site_id).unwrap();
        assert_eq!(
            config.agent_exemptions,
            vec![agent("okhttp", "/remote.php/dav/")]
        );
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        };
        let text = block_text(&config).unwrap();

        // The presence of robots.txt alone forces the flag form, because
        // the direct-`return` form has nowhere to put an exemption.
        assert!(text.contains("$stop_bots_block"), "text was:\n{text}");
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("/blog"), "text was:\n{text}");
        assert!(text.contains("/robots\\.txt"), "text was:\n{text}");
    }

    /// Not serving robots.txt means no implicit exemption, so a site with
    /// no configured exemptions keeps the direct-`return` form.
    #[test]
    fn no_robots_txt_means_no_implicit_exemption() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!text.contains("$stop_bots_block"), "text was:\n{text}");
        assert!(!text.contains("robots"), "text was:\n{text}");
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
        };
        let text = block_text(&config).unwrap();

        let ifs = text.matches("if ($http_user_agent").count();
        assert!(ifs > 1, "expected chunking, got {ifs}");
        // Every chunk sets the flag; exactly one clears it and one acts.
        assert_eq!(text.matches("set $stop_bots_block 1;").count(), ifs);
        assert_eq!(text.matches("if ($uri ").count(), 1);
        assert_eq!(text.matches("if ($stop_bots_block) {").count(), 1);
    }

    #[test]
    fn site_apply_status_is_stale_when_only_an_exemption_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_exempt(&["BadBot"], &["/blog"]),
                no_trust_file()
            ),
            SiteApplyStatus::Stale
        );

        apply_block_for_site(
            &path,
            dir.path(),
            "a.example",
            &cfg_exempt(&["BadBot"], &["/blog"]),
        )
        .unwrap();
        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_exempt(&["BadBot"], &["/blog"]),
                no_trust_file()
            ),
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
            agent_exemptions: Vec::new(),
            request_rules: Vec::new(),
            trust: None,
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

    // ---- HTTP/1.x rejection ----

    fn cfg_http1x(patterns: &[&str]) -> BlockConfig {
        BlockConfig {
            request_rules: vec![RequestRule::Http1x],
            ..cfg(patterns)
        }
    }

    #[test]
    fn parse_detects_tls_from_a_listen_ssl_parameter() {
        let content = "server {\n    listen 443 ssl;\n    server_name a.example;\n}\n";
        assert!(parse_server_blocks(content)[0].is_tls);
    }

    #[test]
    fn parse_detects_tls_from_an_ssl_certificate_directive() {
        let content = concat!(
            "server {\n",
            "    listen 8443;\n",
            "    ssl_certificate /etc/ssl/a.pem;\n",
            "    server_name a.example;\n}\n"
        );
        assert!(parse_server_blocks(content)[0].is_tls);
    }

    #[test]
    fn parse_marks_a_plain_listen_block_as_not_tls() {
        let content = "server {\n    listen 80;\n    server_name a.example;\n}\n";
        assert!(!parse_server_blocks(content)[0].is_tls);
    }

    #[test]
    fn rejecting_http_1x_emits_a_server_protocol_condition() {
        let text = block_text(&cfg_http1x(&["BadBot"])).unwrap();
        assert!(
            text.contains(r#"if ($server_protocol ~ "^HTTP/1\.")"#),
            "text was:\n{text}"
        );
        // Two reasons to block now, so the flag form rather than a direct
        // return — otherwise the two conditions couldn't both apply.
        assert!(
            text.contains("set $stop_bots_block 1;"),
            "text was:\n{text}"
        );
        assert!(
            text.contains("if ($stop_bots_block) {"),
            "text was:\n{text}"
        );
    }

    /// The guard that keeps certificate renewal working. ACME HTTP-01 is
    /// fetched over HTTP/1.1 by a non-browser client; without this the
    /// site keeps working until its certificate expires weeks later.
    #[test]
    fn rejecting_http_1x_always_exempts_well_known() {
        let text = block_text(&cfg_http1x(&["BadBot"])).unwrap();
        assert!(text.contains(r"/\.well-known/"), "text was:\n{text}");
    }

    #[test]
    fn not_rejecting_http_1x_leaves_well_known_alone() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!text.contains("well-known"), "text was:\n{text}");
    }

    /// Rejection alone, with nothing else configured, is still a block
    /// worth writing.
    #[test]
    fn rejecting_http_1x_alone_still_writes_a_block() {
        let config = BlockConfig {
            request_rules: vec![RequestRule::Http1x],
            ..BlockConfig::default()
        };
        let text = block_text(&config).unwrap();
        assert!(text.contains("$server_protocol"), "text was:\n{text}");
        assert!(
            !text.contains("$http_user_agent"),
            "nothing to match on the UA; text was:\n{text}"
        );
    }

    /// The guard that keeps the feature from taking a site offline: a
    /// site's port-80 and port-443 blocks share one `server_name`, so the
    /// setting reaches both, and on the plain one every request is 1.1.
    #[test]
    fn rejecting_http_1x_is_dropped_in_a_non_tls_server_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.example");
        fs::write(
            &path,
            concat!(
                "server {\n    listen 80;\n    server_name a.example;\n}\n",
                "server {\n    listen 443 ssl;\n    server_name a.example;\n}\n"
            ),
        )
        .unwrap();

        apply_block_for_site(&path, dir.path(), "a.example", &cfg_http1x(&["BadBot"])).unwrap();

        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(
            written.matches("$server_protocol").count(),
            1,
            "only the TLS block may reject HTTP/1.x; written was:\n{written}"
        );
        let blocks = parse_server_blocks(&written);
        let plain = &written[blocks[0].open..blocks[0].close];
        assert!(
            !plain.contains("$server_protocol"),
            "the plain-HTTP block must not reject HTTP/1.x; it was:\n{plain}"
        );
        // ...and it still gets the ordinary user-agent blocking.
        assert!(plain.contains("$http_user_agent"), "plain was:\n{plain}");
    }

    /// The narrowing has to apply to the status check too, or the
    /// plain-HTTP block reads as permanently STALE.
    #[test]
    fn a_correctly_narrowed_non_tls_block_reads_as_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.example");
        fs::write(
            &path,
            concat!(
                "server {\n    listen 80;\n    server_name a.example;\n}\n",
                "server {\n    listen 443 ssl;\n    server_name a.example;\n}\n"
            ),
        )
        .unwrap();

        let config = cfg_http1x(&["BadBot"]);
        apply_block_for_site(&path, dir.path(), "a.example", &config).unwrap();
        assert_eq!(
            site_apply_status(&path, "a.example", &config, no_trust_file()),
            SiteApplyStatus::UpToDate
        );
    }

    #[test]
    fn site_apply_status_is_stale_when_http_1x_rejection_is_switched_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(
            &path,
            "server {\n    listen 443 ssl;\n    server_name a.example;\n}\n",
        )
        .unwrap();
        apply_block_for_site(&path, dir.path(), "a.example", &cfg(&["BadBot"])).unwrap();

        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_http1x(&["BadBot"]),
                no_trust_file()
            ),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn http_1x_rejection_matches_the_golden() {
        let config = BlockConfig {
            request_rules: vec![RequestRule::Http1x],
            ..cfg(&["BadBot"])
        };
        crate::golden::assert_golden("nginx-block-http1x.conf", &block_text(&config).unwrap());
    }

    // ---- trusted clients ----

    fn trust_body() -> String {
        trusted_conf_body(
            &["203.0.113.7".to_string(), "2001:db8::/48".to_string()],
            &["UptimeRobot".to_string(), "Pingdom.com_bot".to_string()],
        )
        .unwrap()
    }

    fn cfg_trusted(patterns: &[&str]) -> BlockConfig {
        BlockConfig {
            trust: Some(trust_body()),
            ..cfg(patterns)
        }
    }

    /// The trust file is the exact text to put in `conf.d` and hand to
    /// `nginx -t` — the container suite does exactly that.
    #[test]
    fn the_trust_file_matches_the_golden() {
        crate::golden::assert_golden("stop-bots-trusted.conf", &trust_body());
    }

    /// Bot patterns and a request-shape rule, both set the flag; trust
    /// clears it after them, so a trusted client gets through whichever
    /// one it tripped.
    #[test]
    fn a_trusted_block_matches_the_golden() {
        let config = BlockConfig {
            request_rules: vec![RequestRule::NoAcceptLanguage],
            exempt_paths: vec!["/blog".to_string()],
            agent_exemptions: Vec::new(),
            ..cfg_trusted(&["BadBot"])
        };
        crate::golden::assert_golden("nginx-block-trusted.conf", &block_text(&config).unwrap());
    }

    /// The same ordering property the exemption test pins, for the same
    /// reason: a clear before a set clears nothing. The trust clear has to
    /// come after every chunk's set, even when the pattern list is long
    /// enough to be split.
    #[test]
    fn the_trust_clear_comes_after_every_set_and_before_the_return() {
        let many: Vec<String> = (0..400).map(|i| format!("Bot{i:04}")).collect();
        let config = BlockConfig {
            patterns: many,
            ..cfg_trusted(&[])
        };
        let text = block_text(&config).unwrap();
        let clear = text
            .find("if ($stop_bots_trusted)")
            .expect("no trust clear");
        let last_set = text.rfind("set $stop_bots_block 1;").unwrap();
        let act = text.find("if ($stop_bots_block)").unwrap();
        assert!(
            last_set < clear && clear < act,
            "trust must clear after every set and before the return:\n{text}"
        );
    }

    /// A direct `return` has nowhere to put a clear, so trust must force
    /// the flag form even for the plainest block.
    #[test]
    fn trust_switches_a_plain_block_to_the_flag_form() {
        let text = block_text(&cfg_trusted(&["BadBot"])).unwrap();
        assert!(
            text.contains("set $stop_bots_block 1;"),
            "text was:\n{text}"
        );
        assert!(!text.contains("    if ($http_user_agent ~* \"BadBot\") {\n        return"));
    }

    /// Trust only ever narrows a block, like an exemption: with nothing
    /// blocked there is no block to write.
    #[test]
    fn trust_alone_does_not_create_a_block() {
        assert!(block_text(&cfg_trusted(&[])).is_none());
    }

    #[test]
    fn nothing_trusted_means_no_trust_file() {
        assert_eq!(trusted_conf_body(&[], &[]), None);
    }

    /// Validated at entry, and filtered here again: one quote in a `map`
    /// key would stop NGINX loading every site, not just this one.
    #[test]
    fn the_trust_file_drops_an_entry_that_would_break_nginx() {
        let body = trusted_conf_body(
            &["not-an-address".to_string(), "203.0.113.7".to_string()],
            &["Evil\"Bot".to_string(), "Good.Bot".to_string()],
        )
        .unwrap();
        assert!(!body.contains("not-an-address"), "body was:\n{body}");
        assert!(!body.contains("Evil"), "body was:\n{body}");
        assert!(
            body.contains("\"~*Good\\.Bot\" 1;"),
            "a trusted user agent is a literal, so its dot must be escaped:\n{body}"
        );
    }

    #[test]
    fn with_anything_trusted_a_site_limits_through_the_zone_that_skips_it() {
        let config = BlockConfig {
            rate_limit_burst: Some(20),
            ..cfg_trusted(&["BadBot"])
        };
        let block = block_text(&config).unwrap();
        assert!(
            block.contains(&format!(
                "limit_req zone={UNTRUSTED_RATE_LIMIT_ZONE} burst=20"
            )),
            "block was:\n{block}"
        );
        let conf = untrusted_rate_limit_conf_body(10, 10);
        assert!(
            conf.contains(&format!(
                "limit_req_zone {LIMIT_KEY_VAR} zone={UNTRUSTED_RATE_LIMIT_ZONE}:"
            )),
            "conf was:\n{conf}"
        );
        assert!(
            trust_body().contains(&format!("map {TRUSTED_VAR} {LIMIT_KEY_VAR}")),
            "the key the zone reads must be defined by the trust file"
        );
    }

    /// The bug the container suite found: re-keying a zone NGINX already
    /// has makes it reject the reload, after `nginx -t` passed. The
    /// original zone must keep its original key whatever is trusted.
    #[test]
    fn the_original_zone_keeps_its_key_whatever_is_trusted() {
        assert_eq!(
            rate_limit_conf_body(10, 10),
            "# Generated by stop-bots. Edits will be overwritten.\n\
             limit_req_zone $binary_remote_addr zone=stop_bots:10m rate=10r/s;\n"
        );
    }

    /// Trusting a second user agent changes the trust file and no block,
    /// and a site has to read as out of date or nobody applies it.
    #[test]
    fn a_site_is_current_only_when_the_trust_file_is_the_expected_one() {
        let config = cfg_trusted(&["BadBot"]);
        let expected = config.trust.clone().unwrap();
        for (why, on_disk, current) in [
            ("the file matches", Some(expected.as_str()), true),
            ("the file is missing", None, false),
            ("the file is an older list", Some("geo {}\n"), false),
        ] {
            assert_eq!(
                trust_file_is_current(&config, on_disk),
                current,
                "wrong answer when {why}"
            );
        }
        // A site that writes no block reads nothing from the file.
        assert!(trust_file_is_current(&cfg_trusted(&[]), None));
        // Nor does one that expects nothing trusted.
        assert!(trust_file_is_current(&cfg(&["BadBot"]), Some("leftover")));
    }

    #[test]
    fn writing_generated_files_counts_only_the_ones_that_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conf.d/stop-bots-trusted.conf");
        let files = vec![(path.clone(), trust_body())];

        assert_eq!(write_planned_managed_files(&files).unwrap(), 1);
        assert_eq!(
            write_planned_managed_files(&files).unwrap(),
            0,
            "an unchanged file must not count, or every apply reloads NGINX"
        );
        assert_eq!(
            remove_planned_managed_files(std::slice::from_ref(&path)).unwrap(),
            1
        );
        assert_eq!(remove_planned_managed_files(&[path]).unwrap(), 0);
    }

    /// A root whose `conf.d` exists: a temp tree standing in for the
    /// containerised host this was found on, whose NGINX config lives
    /// under `/srv/.../nginx` and whose `conf.d` is the directory NGINX
    /// globs.
    fn root_with_a_conf_d() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("conf.d")).unwrap();
        dir
    }

    /// The bug this family exists to prevent, and the one that actually
    /// happened on a host in September 2026: the `http`-context files went
    /// to a fixed `/etc/nginx/conf.d` while every site file was found and
    /// rewritten under the stored root. NGINX never read that directory,
    /// so the blocks referenced `$stop_bots_trusted` with nothing defining
    /// it — and NGINX refuses to load such a config at all, so one restart
    /// would have taken down every site on the box, not just the one
    /// setting had gone wrong.
    #[test]
    fn the_generated_http_files_land_in_the_roots_own_conf_d() {
        let dir = root_with_a_conf_d();
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::ROOT_KEY, dir.path().to_str().unwrap())
            .unwrap();
        db.trust_user_agent("Nextcloud").unwrap();
        db.set_rate_limit_enabled(true).unwrap();

        let planned: Vec<PathBuf> = planned_managed_files(&db, &root(&db, None).unwrap())
            .unwrap()
            .into_iter()
            .map(|(path, _)| path)
            .collect();

        for name in [
            "stop-bots-trusted.conf",
            "stop-bots-limits.conf",
            "stop-bots-limits-untrusted.conf",
        ] {
            let expected = dir.path().join("conf.d").join(name);
            assert!(
                planned.contains(&expected),
                "{name} must be written where NGINX reads it; planned:\n{planned:#?}"
            );
        }
    }

    /// The removal half has to look in the same place, or switching rate
    /// limiting off deletes nothing and leaves a live `limit_req_zone`
    /// behind while no site names it.
    #[test]
    fn the_removal_half_looks_in_the_same_directory() {
        let dir = root_with_a_conf_d();
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_text_setting(NginxCommands::ROOT_KEY, dir.path().to_str().unwrap())
            .unwrap();

        let unused = unused_managed_files(&db, &root(&db, None).unwrap()).unwrap();
        for name in ["stop-bots-trusted.conf", "stop-bots-limits.conf"] {
            let expected = dir.path().join("conf.d").join(name);
            assert!(
                unused.contains(&expected),
                "{name} must be removed from where it was written; unused:\n{unused:#?}"
            );
        }
    }

    /// And a root with no `conf.d` of its own keeps the stock path rather
    /// than inventing one. The container suite scans
    /// `/etc/nginx/sites-enabled`, which `include sites-enabled/*` globs:
    /// a `conf.d` directory created in there is something NGINX tries to
    /// `pread()` as a config file, and it refuses to start.
    #[test]
    fn a_root_without_a_conf_d_is_not_given_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(conf_d_dir(dir.path()), PathBuf::from(CONF_D_DIR));
    }

    /// A normal host install must be exactly as it was. `root` falls back
    /// to `/etc/nginx`, so this resolves to the stock path without the
    /// setting existing at all.
    #[test]
    fn conf_d_falls_back_to_the_stock_path_when_no_root_is_stored() {
        let db = crate::db::Db::open_in_memory().unwrap();
        assert_eq!(
            conf_d_dir(&root(&db, None).unwrap()),
            PathBuf::from(CONF_D_DIR)
        );
    }

    /// The staleness check reads the trust file too, and has to read it
    /// from the same directory it is written to. Reading the wrong one
    /// finds nothing, which is indistinguishable from an out-of-date file:
    /// every site would report `Stale` for ever, and an operator applying
    /// again would change nothing and be told so.
    #[test]
    fn site_apply_status_reads_the_trust_file_from_the_given_conf_d() {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("conf.d");
        fs::create_dir_all(&conf_d).unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        let config = cfg_trusted(&["BadBot"]);
        apply_block_for_site(&path, dir.path(), "a.example", &config).unwrap();

        assert_eq!(
            site_apply_status(&path, "a.example", &config, &conf_d),
            SiteApplyStatus::Stale,
            "the block is applied but the trust file it reads is not there yet"
        );

        fs::write(conf_d.join("stop-bots-trusted.conf"), trust_body()).unwrap();
        assert_eq!(
            site_apply_status(&path, "a.example", &config, &conf_d),
            SiteApplyStatus::UpToDate,
            "with the file in place the site is applied"
        );
    }

    // ---- request-shape rules ----

    fn cfg_rules(rules: &[RequestRule]) -> BlockConfig {
        BlockConfig {
            request_rules: rules.to_vec(),
            ..cfg(&["BadBot"])
        }
    }

    #[test]
    fn every_request_rule_has_a_distinct_stable_id() {
        let mut ids: Vec<&str> = RequestRule::ALL.iter().map(|r| r.id()).collect();
        let count = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), count);
        for rule in RequestRule::ALL {
            assert_eq!(RequestRule::from_id(rule.id()), Some(rule));
        }
        assert_eq!(RequestRule::from_id("nope"), None);
    }

    /// Each rule is its own toggle, so each must emit its own condition —
    /// a shared one would make them indistinguishable in the config too.
    #[test]
    fn each_rule_emits_its_own_condition() {
        for rule in RequestRule::ALL {
            let text = block_text(&cfg_rules(&[rule])).unwrap();
            assert!(
                text.contains(rule.condition()),
                "{} should emit {:?}; text was:\n{text}",
                rule.label(),
                rule.condition()
            );
        }
    }

    /// Every rule carries collateral, and the UI shows the caveat next to
    /// the toggle. An empty one would render as a bare switch and quietly
    /// imply there's no downside.
    #[test]
    fn every_rule_states_what_else_it_turns_away() {
        for rule in RequestRule::ALL {
            assert!(!rule.caveat().is_empty(), "{} needs a caveat", rule.label());
        }
    }

    #[test]
    fn any_request_rule_forces_the_well_known_exemption() {
        for rule in RequestRule::ALL {
            let text = block_text(&cfg_rules(&[rule])).unwrap();
            assert!(
                text.contains(r"/\.well-known/"),
                "{} must not break ACME renewal; text was:\n{text}",
                rule.label()
            );
        }
    }

    /// Only the two rules that depend on TLS are dropped in a plain block.
    /// The header-shape rules work identically over HTTP, so dropping them
    /// there would silently disable them on a redirect block.
    #[test]
    fn only_the_tls_dependent_rules_are_dropped_in_a_plain_block() {
        let plain = ServerBlock {
            names: vec!["a.example".to_string()],
            is_tls: false,
            open: 0,
            close: 0,
        };
        let narrowed = for_block(&cfg_rules(&RequestRule::ALL), &plain);

        assert!(!narrowed.request_rules.contains(&RequestRule::Http1x));
        assert!(!narrowed.request_rules.contains(&RequestRule::OldTls));
        assert!(narrowed.request_rules.contains(&RequestRule::NoAccept));
        assert!(narrowed.request_rules.contains(&RequestRule::NoUserAgent));
        assert!(narrowed.request_rules.contains(&RequestRule::IpLiteralHost));
    }

    #[test]
    fn a_tls_block_keeps_every_rule() {
        let tls = ServerBlock {
            names: vec!["a.example".to_string()],
            is_tls: true,
            open: 0,
            close: 0,
        };
        let narrowed = for_block(&cfg_rules(&RequestRule::ALL), &tls);
        assert_eq!(narrowed.request_rules.len(), RequestRule::ALL.len());
    }

    /// A stored id from a newer build must not stop an older one applying
    /// anything at all.
    #[test]
    fn an_unrecognised_stored_rule_id_is_skipped_not_fatal() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.upsert_site("a.example", "/etc/nginx/a.conf").unwrap();
        let site = db.list_sites().unwrap().into_iter().next().unwrap();
        db.set_site_request_rule(site.id, "from_the_future", true)
            .unwrap();
        db.set_site_request_rule(site.id, RequestRule::NoAccept.id(), true)
            .unwrap();

        assert_eq!(
            site_request_rules(&db, site.id).unwrap(),
            vec![RequestRule::NoAccept]
        );
    }

    #[test]
    fn every_request_rule_together_matches_the_golden() {
        let config = BlockConfig {
            request_rules: RequestRule::ALL.to_vec(),
            ..cfg(&["BadBot"])
        };
        crate::golden::assert_golden(
            "nginx-block-request-rules.conf",
            &block_text(&config).unwrap(),
        );
    }

    // ---- block responses ----

    fn cfg_response(response: BlockResponse) -> BlockConfig {
        BlockConfig {
            response,
            ..cfg(&["BadBot"])
        }
    }

    #[test]
    fn every_response_renders_its_own_status_code() {
        for response in BlockResponse::ALL {
            let text = block_text(&cfg_response(response)).unwrap();
            assert!(
                text.contains(&format!("return {};", response.status_code())),
                "{} should return {}; text was:\n{text}",
                response.label(),
                response.status_code()
            );
        }
    }

    /// Every option needs to say what it is *for*, or the chooser reads as
    /// five interchangeable numbers.
    #[test]
    fn every_response_explains_itself() {
        for response in BlockResponse::ALL {
            assert!(!response.rationale().is_empty(), "{:?}", response);
            assert!(!response.label().is_empty(), "{:?}", response);
        }
    }

    #[test]
    fn only_tarpit_throttles_the_response_body() {
        for response in BlockResponse::ALL {
            let text = block_text(&cfg_response(response)).unwrap();
            let throttled = text.contains("set $limit_rate 1;");
            assert_eq!(
                throttled,
                response.is_tarpit(),
                "{} throttling should be {}; text was:\n{text}",
                response.label(),
                response.is_tarpit()
            );
        }
    }

    /// The throttle has to land inside the same `if` as the return, in
    /// both block shapes — `$limit_rate` set anywhere else would apply to
    /// every visitor.
    #[test]
    fn the_tarpit_throttle_sits_with_the_return_in_both_block_shapes() {
        // Direct form: no exemptions, one reason.
        let direct = block_text(&cfg_response(BlockResponse::Tarpit)).unwrap();
        assert!(
            direct.contains("set $limit_rate 1;\n        return 403;"),
            "direct form was:\n{direct}"
        );

        // Flag form: an exemption forces it.
        let flagged = block_text(&BlockConfig {
            response: BlockResponse::Tarpit,
            exempt_paths: vec!["/blog".to_string()],
            agent_exemptions: Vec::new(),
            ..cfg(&["BadBot"])
        })
        .unwrap();
        assert!(
            flagged.contains(
                "if ($stop_bots_block) {\n        set $limit_rate 1;\n        return 403;"
            ),
            "flag form was:\n{flagged}"
        );
        assert_eq!(
            flagged.matches("set $limit_rate").count(),
            1,
            "throttling must apply once, to blocked requests only; was:\n{flagged}"
        );
    }

    #[test]
    fn changing_the_response_makes_an_applied_site_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(
            &path,
            dir.path(),
            "a.example",
            &cfg_response(BlockResponse::Gone),
        )
        .unwrap();

        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_response(BlockResponse::Gone),
                no_trust_file()
            ),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(
                &path,
                "a.example",
                &cfg_response(BlockResponse::Tarpit),
                no_trust_file()
            ),
            SiteApplyStatus::Stale
        );
    }

    #[test]
    fn tarpit_matches_the_golden() {
        crate::golden::assert_golden(
            "nginx-block-tarpit.conf",
            &block_text(&cfg_response(BlockResponse::Tarpit)).unwrap(),
        );
    }
    // ---- reaching the console from outside ----

    /// `NginxCommands` whose test either passes or fails, without needing
    /// a real NGINX. `/bin/true` and `/bin/false` rather than a written
    /// script: fewer moving parts, and nothing to make executable.
    fn commands_that(pass: bool) -> NginxCommands {
        let program = if pass { "true" } else { "false" };
        NginxCommands {
            test: vec![program.to_string()],
            reload: vec!["true".to_string()],
        }
    }

    const TWO_BLOCK_SITE: &str = "\
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    root /var/www/example.com;
}
";

    fn upstream() -> std::net::SocketAddr {
        "127.0.0.1:8787".parse().unwrap()
    }

    /// The console's login form must not end up on the port-80 redirect
    /// block when the site has a certificate sitting right there.
    #[test]
    fn path_mode_picks_the_tls_block_not_the_redirect() {
        let updated =
            with_console_location(TWO_BLOCK_SITE, "example.com", "/stop-bots/", &upstream())
                .expect("the site has a matching block");

        // Against the parsed block's own span, not the order of
        // directives: the block is inserted at the top of the `server`
        // block, so it precedes `listen 443` while still being inside it.
        let console_at = updated.find(CONSOLE_BEGIN).expect("the block was inserted");
        let blocks = parse_server_blocks(&updated);
        let tls = blocks
            .iter()
            .find(|b| b.is_tls)
            .expect("the fixture has a TLS block");
        assert!(
            console_at > tls.open && console_at < tls.close,
            "the console landed outside the TLS block:\n{updated}"
        );
    }

    /// `proxy_pass` must not have a trailing slash and the location must
    /// keep its prefix — otherwise NGINX strips the prefix and every link
    /// this console generates points outside the location block.
    #[test]
    fn the_console_location_does_not_strip_its_prefix() {
        let block = console_location("/stop-bots/", &upstream());

        assert!(
            block.contains(r#"location "/stop-bots/" {"#),
            "block was:\n{block}"
        );
        assert!(
            block.contains("proxy_pass http://127.0.0.1:8787;"),
            "a trailing slash here strips the prefix:\n{block}"
        );
    }

    /// The whole site file after path mode edits it — the exact bytes to
    /// hand `nginx -t`, and the pin on the quoted `location` prefix.
    #[test]
    fn the_path_mode_console_block_matches_the_golden() {
        let updated =
            with_console_location(TWO_BLOCK_SITE, "example.com", "/stop-bots/", &upstream())
                .unwrap();
        crate::golden::assert_golden("nginx-console-path.conf", &updated);
    }

    #[test]
    fn the_subdomain_console_block_matches_the_golden() {
        let block = console_server_block("console.example.com", &upstream());
        crate::golden::assert_golden("nginx-console-subdomain.conf", &block);
    }

    /// Quoting is the second line behind `BasePath::parse`, not a
    /// substitute for it: `ConsoleAccess::Path` is a public type, and a
    /// prefix that reaches it some other way must still be one token. A
    /// quote or backslash inside it is escaped, so it cannot close the
    /// string early.
    #[test]
    fn the_console_location_keeps_a_hostile_prefix_inside_its_quotes() {
        let block = console_location(r#"/a\" { } ;"#, &upstream());

        assert!(
            block.contains(r#"location "/a\\\" { } ;" {"#),
            "block was:\n{block}"
        );
    }

    #[test]
    fn path_mode_is_idempotent() {
        let once = with_console_location(TWO_BLOCK_SITE, "example.com", "/stop-bots/", &upstream())
            .unwrap();
        let twice =
            with_console_location(&once, "example.com", "/stop-bots/", &upstream()).unwrap();

        assert_eq!(once, twice);
        assert_eq!(twice.matches(CONSOLE_BEGIN).count(), 1);
    }

    /// Rewritten in place, so changing the prefix does not leave the old
    /// location block behind alongside the new one.
    #[test]
    fn changing_the_prefix_replaces_the_block_rather_than_adding_one() {
        let first =
            with_console_location(TWO_BLOCK_SITE, "example.com", "/stop-bots/", &upstream())
                .unwrap();
        let second =
            with_console_location(&first, "example.com", "/console/", &upstream()).unwrap();

        assert_eq!(second.matches(CONSOLE_BEGIN).count(), 1);
        assert!(
            second.contains(r#"location "/console/" {"#),
            "was:\n{second}"
        );
        assert!(!second.contains("/stop-bots/"), "was:\n{second}");
    }

    /// The console markers must not collide with the bot-blocking ones:
    /// both live in the same `server` block and are rewritten by different
    /// actions.
    #[test]
    fn the_console_block_and_the_blocking_block_coexist() {
        let with_console =
            with_console_location(TWO_BLOCK_SITE, "example.com", "/stop-bots/", &upstream())
                .unwrap();
        let blocks = parse_server_blocks(&with_console);
        let tls = blocks.iter().find(|b| b.is_tls).unwrap();
        let config = BlockConfig::new(vec!["BadBot".to_string()], BlockResponse::Forbidden);

        let both = apply_block(&with_console, tls, &config);

        assert!(both.contains(CONSOLE_BEGIN), "console block lost:\n{both}");
        assert!(both.contains(BLOCK_BEGIN), "blocking block lost:\n{both}");
        assert!(both.contains(r#"location "/stop-bots/" {"#), "was:\n{both}");
    }

    #[test]
    fn a_site_with_no_matching_block_is_a_refusal() {
        assert!(
            with_console_location(TWO_BLOCK_SITE, "other.example.org", "/x/", &upstream())
                .is_none()
        );
    }

    /// The failure this guards against: a new `server` block that does not
    /// parse leaves the whole config unloadable, and nothing looks wrong
    /// because the running NGINX keeps serving from memory.
    #[test]
    fn a_config_that_fails_validation_is_rolled_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conf.d/stop-bots-console.conf");

        let err = write_validated(&path, "server { broken", &commands_that(false)).unwrap_err();

        assert!(
            format!("{err:#}").contains("restored"),
            "the operator must be told the rollback happened: {err:#}"
        );
        assert!(
            !path.exists(),
            "a file that never validated must not be left behind"
        );
    }

    /// Rolling back an *edit* puts the previous content back, rather than
    /// deleting somebody's site config.
    #[test]
    fn a_failed_edit_restores_the_previous_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com");
        fs::write(&path, TWO_BLOCK_SITE).unwrap();

        let _ = write_validated(&path, "server { broken", &commands_that(false));

        assert_eq!(fs::read_to_string(&path).unwrap(), TWO_BLOCK_SITE);
    }

    #[test]
    fn a_config_that_validates_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("conf.d/stop-bots-console.conf");
        let block = console_server_block("console.example.com", &upstream());

        write_validated(&path, &block, &commands_that(true)).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), block);
    }

    /// Plain HTTP is a real downgrade for a page with a password form, so
    /// the generated file has to say so where whoever opens it will look.
    #[test]
    fn the_subdomain_block_warns_that_it_is_cleartext() {
        let block = console_server_block("console.example.com", &upstream());

        assert!(
            block.contains("certbot --nginx -d console.example.com"),
            "was:\n{block}"
        );
        assert!(block.contains("in the clear"), "was:\n{block}");
        assert!(
            block.contains("server_name console.example.com;"),
            "was:\n{block}"
        );
    }
}
