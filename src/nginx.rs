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

pub use crate::dirfd::DirFile;
use crate::webserver::*;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const BLOCK_BEGIN: &str = "# BEGIN stop-bots (DO NOT EDIT)";
const BLOCK_END: &str = "# END stop-bots";

/// The stock location, and what every host had before this was configurable.
pub const DEFAULT_ROOT: &str = "/etc/nginx";

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
    /// Every `listen` directly in the block, in order. Empty when it has
    /// none, which NGINX reads as port 80.
    pub listens: Vec<crate::webserver::Listen>,
    open: usize,
    close: usize,
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
    let mut listens_stack: Vec<Vec<crate::webserver::Listen>> = Vec::new();
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
                    listens_stack.push(Vec::new());
                }
                prev_word = None;
            }
            "}" => {
                if let Some((open, is_server)) = stack.pop() {
                    if is_server {
                        let names = names_stack.pop().unwrap_or_default();
                        let is_tls = tls_stack.pop().unwrap_or(false);
                        let listens = listens_stack.pop().unwrap_or_default();
                        blocks.push(ServerBlock {
                            names,
                            is_tls,
                            listens,
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
                if word == "listen" && directly_in_server {
                    let mut j = idx + 1;
                    let mut args = Vec::new();
                    while j < tokens.len() && !matches!(tokens[j].0.as_str(), ";" | "{" | "}") {
                        args.push(tokens[j].0.as_str());
                        j += 1;
                    }
                    if let Some(listen) = listen_directive(&args) {
                        if let Some(top) = listens_stack.last_mut() {
                            top.push(listen);
                        }
                    }
                    // Not skipped past: an `ssl` among them is also what
                    // marks the block TLS, below.
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

/// One `listen` directive's arguments as a [`Listen`](crate::webserver::Listen):
/// `443 ssl`, `[::]:80`, `127.0.0.1:8080`. `None` for a Unix socket, and
/// for `quic`, which is UDP and answers nothing a TCP request can ask.
/// Port 443 counts as TLS without the `ssl` parameter, for the configs
/// that still say `ssl on;` instead.
fn listen_directive(args: &[&str]) -> Option<crate::webserver::Listen> {
    let (first, params) = args.split_first()?;
    if params.contains(&"quic") {
        return None;
    }
    let (address, port) = crate::webserver::Listen::parse_address(first)?;
    Some(crate::webserver::Listen {
        address,
        port,
        tls: params.contains(&"ssl") || port == 443,
    })
}

/// `regex` as an NGINX double-quoted string, quotes included, written so
/// that the text NGINX hands to PCRE is exactly `regex`. **Every regex this
/// module writes into a config goes through here**, and every check on a
/// regex ([`pattern_problem`]) is of the text before it: that is only the
/// regex NGINX compiles because this function is exact.
///
/// It used not to exist. Patterns went between the quotes verbatim, and
/// NGINX's config reader is not verbatim: it undoes escapes inside a quoted
/// word before any directive sees it. A manually blocked user agent ending
/// in `\|` was escaped for PCRE as `\\\|`, written as it was, read back by
/// NGINX as `\\|`, and compiled to "a backslash, or nothing": a rule that
/// turned away every visitor. `Evil\(` became an unclosed group that failed
/// `nginx -t`, and with it every later apply, unattended ones included.
///
/// What NGINX does, from `ngx_conf_read_token` in
/// `src/core/ngx_conf_file.c` (the same from 1.0 to 1.27):
///
/// 1. **Finding the end of the word.** A backslash makes the next byte
///    ordinary, so `\"` does not close the string. Nothing else inside
///    double quotes is special: not `'`, `;`, `{`, `}`, `#`, `$` or
///    whitespace.
/// 2. **Unescaping it**, left to right over the bytes between the quotes:
///    `\"`, `\'` and `\\` become their second byte; `\t`, `\r` and `\n`
///    become a tab, a carriage return and a line feed; a backslash before
///    anything else is kept, and the byte after it is then read as an
///    ordinary byte. [`nginx_unquoted`] is a model of this pass.
///
/// The encoding: a `"` is written `\"`, and a backslash is written twice
/// exactly when the byte written right after it is `\`, `"`, `'`, `t`, `r`
/// or `n`, or the closing quote; everywhere else once. Pass 2 gives back
/// every character, by induction over the written text:
///
/// - A `"` was written `\"`, which is read as `"`, consuming both bytes.
/// - A doubled backslash is `\\`, read as one backslash, consuming both.
/// - A single backslash is followed by a byte outside that set, so it is
///   kept and only it is consumed. That next byte is not a backslash or a
///   quote either: the character it starts would then be written with a
///   leading `\`, and this backslash would have been doubled.
/// - Any other character is written as itself and read as itself.
///
/// Pass 1 agrees on where the string ends: every backslash it pairs with
/// the next byte is one of the pairs above, or a single backslash followed
/// by an ordinary byte, so the only unpaired `"` is the closing one. A
/// regex ending in a backslash has it doubled, so it cannot swallow the
/// closing quote.
///
/// Doubling only where NGINX would otherwise read an escape, rather than
/// every backslash, keeps every block that was already right byte for byte
/// the same: `1h4x\.com` is still written `1h4x\.com`, so no site on an
/// upgraded host reads as stale over a change that did not affect it. The
/// only blocks whose text changes are the ones NGINX was misreading.
pub fn nginx_quoted(regex: &str) -> String {
    let chars: Vec<char> = regex.chars().collect();
    let mut out = String::with_capacity(regex.len() + 2);
    out.push('"');
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '"' => out.push_str(r#"\""#),
            '\\' => {
                // The byte written right after this backslash: the next
                // character's first, which for a quote or a backslash is a
                // backslash; at the end, the closing quote.
                let next = match chars.get(i + 1) {
                    None | Some('"' | '\\') => '\\',
                    Some(&next) => next,
                };
                if matches!(next, '\\' | '"' | '\'' | 't' | 'r' | 'n') {
                    out.push('\\');
                }
                out.push('\\');
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What NGINX makes of the text between the quotes of a double-quoted
/// word: pass 2 of `ngx_conf_read_token`, as described at
/// [`nginx_quoted`].
///
/// A model, which [`nginx_quoted`] is checked against, and which reads a
/// quoted value this module wrote back out of a config file.
pub fn nginx_unquoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let unescaped = match chars.peek() {
            Some(&next @ ('"' | '\'' | '\\')) => next,
            Some('t') => '\t',
            Some('r') => '\r',
            Some('n') => '\n',
            _ => {
                out.push('\\');
                continue;
            }
        };
        out.push(unescaped);
        chars.next();
    }
    out
}

/// The bytes [`nginx_quoted`] writes for `regex`, quotes left out. An
/// upper bound for the same regex inside a longer `|`-join: the only
/// character whose encoding depends on what follows it is a final
/// backslash, which is doubled here and may not be there.
fn quoted_len(regex: &str) -> usize {
    nginx_quoted(regex).len() - 2
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
    /// one.
    ControlCharacter,
    /// Longer than [`MAX_PATTERN_LEN`].
    TooLong,
    /// Some way of matching it needs fewer than [`MIN_PATTERN_LITERALS`]
    /// literal characters, or it has an empty alternative — it matches
    /// (nearly) every user agent.
    MatchesTooMuch,
    /// A shape that makes a backtracking engine try more ways to match
    /// than PCRE's match limit allows: a repeated group that itself repeats
    /// something, `(a+)+`; a repeated group with alternatives, `(a|aa)+`;
    /// or more than one repetition anywhere, `.*.*.*`. NGINX answers a
    /// regex that hits the limit with a 500, for every request it is
    /// tested against, and `nginx -t` cannot tell.
    Backtracks,
    /// Something PCRE refuses to compile: a range out of order (`[z-a]`), a
    /// quantifier whose numbers are out of order (`{2,1}`) or too big
    /// (`{99999}`). Written, it would fail `nginx -t` and roll back every
    /// apply after it.
    Invalid,
    /// Unbalanced, or a construct (lookaround, `\x`, `\Q`, inline flags)
    /// this check does not understand. Refused rather than guessed at.
    Unchecked,
}

impl std::fmt::Display for PatternProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PatternProblem::Empty => "it is empty",
            PatternProblem::ControlCharacter => "it contains a control character",
            PatternProblem::TooLong => "it is too long",
            PatternProblem::MatchesTooMuch => "it would match (nearly) every user agent",
            PatternProblem::Backtracks => "it repeats in more than one place",
            PatternProblem::Invalid => "it is not a regex NGINX would compile",
            PatternProblem::Unchecked => "it is not a regex this tool can check",
        })
    }
}

/// Why `pattern` must not be joined into a sentinel block, or `None` when
/// it is safe to.
///
/// `pattern` is the regex as PCRE is to compile it, which is what NGINX
/// hands PCRE because [`nginx_quoted`] writes it exactly. Checking the text
/// before quoting was only ever right because of that: when patterns were
/// written verbatim, this checked one regex and NGINX compiled another.
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
///
/// **Nor a compiler.** It refuses what it can see PCRE would refuse — an
/// unbalanced group, a range or quantifier out of order, a count past
/// PCRE's limit, a POSIX class it does not know, an escape it does not
/// know — and everything it cannot check. What it cannot promise is that
/// every pattern it passes compiles: that would take PCRE itself. The one
/// real compiler on the host is `nginx -t`, which every apply runs before
/// reloading and which rolls the apply back if it fails; bisecting a
/// failure down to the one bad pattern would mean a `nginx -t` per step
/// against a scratch config tree, which an apply does not have.
pub fn pattern_problem(pattern: &str) -> Option<PatternProblem> {
    if pattern.trim().is_empty() {
        return Some(PatternProblem::Empty);
    }
    if pattern.chars().any(char::is_control) {
        return Some(PatternProblem::ControlCharacter);
    }
    if pattern.len() > MAX_PATTERN_LEN {
        return Some(PatternProblem::TooLong);
    }
    let chars: Vec<char> = pattern.chars().collect();
    let mut shape = Shape {
        chars: &chars,
        pos: 0,
        repetitions: 0,
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
    /// Whether it is a choice between alternatives, `a|b`.
    alternates: bool,
    /// Whether a quantifier may follow it. An anchor (`^`, `\b`) matches a
    /// position rather than a character, and no list repeats one.
    repeatable: bool,
}

/// A quantifier, as [`Shape::quantifier`] reads it.
struct Quantifier {
    /// The fewest repetitions.
    min: usize,
    /// Whether it can match more than once.
    repeats: bool,
    /// For `{n}`, `{n,}` and `{n,m}`: how many copies of the repeated
    /// item PCRE compiles, which it does by writing the item out that
    /// many times.
    copies: Option<usize>,
}

/// What stands at a `{`: a quantifier, or a literal brace.
enum Brace {
    /// Not a quantifier in any PCRE: `{`, `{}`, `{a}`, `x server {`.
    Literal,
    /// `{n}`, `{n,}` or `{n,m}`, `len` characters long.
    Quantifier {
        min: usize,
        max: Option<usize>,
        len: usize,
    },
}

/// One member of a `[...]` class.
enum Member {
    /// A single character, which may start or end a range.
    Char(char),
    /// A set of characters (`\d`, `[:alpha:]`), which may not.
    Set,
}

/// The largest count PCRE accepts in a `{}` quantifier.
const PCRE_MAX_REPEAT: usize = 65_535;

/// How many characters of pattern a braced quantifier may expand into.
/// PCRE compiles `(abc){100}` by writing the group out a hundred times,
/// and a compiled pattern past its size limit fails `nginx -t` with
/// "regular expression is too large". The largest in any real list is
/// `\/{0,1}`.
const MAX_REPEAT_EXPANSION: usize = 4096;

/// The POSIX classes PCRE knows inside `[...]`. Any other name fails to
/// compile.
const POSIX_CLASSES: [&str; 14] = [
    "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print", "punct",
    "space", "upper", "word", "xdigit",
];

/// A recursive walk over a PCRE pattern, just deep enough for
/// [`pattern_problem`].
struct Shape<'a> {
    chars: &'a [char],
    pos: usize,
    /// How many quantifiers that can match more than once it has passed.
    ///
    /// Each one multiplies the ways PCRE can try to match by up to the
    /// length of the user agent: `Mozilla.*.*.*.*.*.*[!#]` is tried
    /// about 150^6 ways against an ordinary Chrome user agent, hits
    /// PCRE's match limit and makes NGINX answer 500 to every browser.
    /// One is linear per starting position. No pattern in any upstream
    /// list repeats more than once (October 2026: 2 of 1,775 repeat at
    /// all), so the limit costs nothing real.
    repetitions: usize,
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
        let mut branches = 0;
        loop {
            let branch = self.sequence(depth)?;
            min_literals = min_literals.min(branch.min_literals);
            quantified |= branch.quantified;
            branches += 1;
            if self.peek() != Some('|') {
                return Ok(Measured {
                    min_literals,
                    quantified,
                    alternates: branches > 1,
                    repeatable: true,
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
            let atom_start = self.pos;
            let atom = self.atom(depth)?;
            let atom_len = self.pos - atom_start;
            match self.quantifier()? {
                Some(quantifier) => {
                    if !atom.repeatable {
                        return Err(PatternProblem::Unchecked);
                    }
                    if quantifier.copies.is_some_and(|copies| {
                        atom_len.saturating_mul(copies) > MAX_REPEAT_EXPANSION
                    }) {
                        return Err(PatternProblem::Unchecked);
                    }
                    // `(a|aa)+` can split a run of `a`s between its
                    // branches in exponentially many ways; telling
                    // overlapping branches from disjoint ones is more than
                    // a walk can do, and no list repeats a choice.
                    if quantifier.repeats && (atom.quantified || atom.alternates) {
                        return Err(PatternProblem::Backtracks);
                    }
                    if quantifier.repeats {
                        self.repetitions += 1;
                        if self.repetitions > 1 {
                            return Err(PatternProblem::Backtracks);
                        }
                    }
                    min_literals = min_literals
                        .saturating_add(atom.min_literals.saturating_mul(quantifier.min));
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
            alternates: false,
            repeatable: true,
        })
    }

    fn atom(&mut self, depth: usize) -> Result<Measured, PatternProblem> {
        let literal = |n| Measured {
            min_literals: n,
            quantified: false,
            alternates: false,
            repeatable: true,
        };
        let anchor = Measured {
            min_literals: 0,
            quantified: false,
            alternates: false,
            repeatable: false,
        };
        let c = self.peek().ok_or(PatternProblem::Unchecked)?;
        self.pos += 1;
        match c {
            '(' => {
                // `(?:` is the only `(?` form upstream lists use; the rest
                // (lookaround, flags, named groups, comments) are refused.
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
                // `[:alpha:]` outside a class is an error in PCRE, not a
                // class of `:`, `a`, `l`...
                if self.posix_class_at(self.pos - 1).is_some() {
                    return Err(PatternProblem::Invalid);
                }
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
                    // Anchors: they match a position, not a character.
                    'b' | 'B' | 'A' | 'z' | 'Z' | 'G' => Ok(anchor),
                    // Character types: they match a character, but not a
                    // literal one.
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'h' | 'H' | 'v' | 'V' => Ok(literal(0)),
                    // `\x41`, `\p{..}`, `\Q..\E`, back-references: each
                    // would need its own parsing to count honestly.
                    c if c.is_ascii_alphanumeric() => Err(PatternProblem::Unchecked),
                    _ => Ok(literal(1)),
                }
            }
            '^' | '$' => Ok(anchor),
            '.' => Ok(literal(0)),
            // A quantifier with nothing to repeat.
            '*' | '+' | '?' => Err(PatternProblem::Unchecked),
            // A `{` is a literal unless it reads as a quantifier, which
            // here would have nothing to repeat.
            '{' => {
                self.pos -= 1;
                match self.brace()? {
                    Brace::Quantifier { .. } => Err(PatternProblem::Unchecked),
                    Brace::Literal => {
                        self.pos += 1;
                        Ok(literal(1))
                    }
                }
            }
            _ => Ok(literal(1)),
        }
    }

    /// Checks a `[...]` class, already past its `[`: every member PCRE
    /// knows, and every range in order.
    fn class(&mut self) -> Result<(), PatternProblem> {
        if self.peek() == Some('^') {
            self.pos += 1;
        }
        // A `]` straight after the opening is a literal member.
        let mut first = true;
        loop {
            if self.peek().ok_or(PatternProblem::Unchecked)? == ']' && !first {
                self.pos += 1;
                return Ok(());
            }
            first = false;
            let from = self.class_member()?;
            // `a-z`; a `-` last, or first, is a literal member.
            let is_range =
                self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&c| c != ']');
            if !is_range {
                continue;
            }
            self.pos += 1;
            let to = self.class_member()?;
            match (from, to) {
                // Compared as bytes: NGINX does not ask PCRE for UTF-8
                // mode, so a range ending in `é` ends in its first byte.
                (Member::Char(from), Member::Char(to)) if from.is_ascii() && to.is_ascii() => {
                    if from > to {
                        return Err(PatternProblem::Invalid);
                    }
                }
                (Member::Char(_), Member::Char(_)) => return Err(PatternProblem::Unchecked),
                // `[\d-z]`: PCRE refuses a range from or to a set.
                _ => return Err(PatternProblem::Invalid),
            }
        }
    }

    /// One member of a class, consumed.
    fn class_member(&mut self) -> Result<Member, PatternProblem> {
        let c = self.peek().ok_or(PatternProblem::Unchecked)?;
        if c == '[' {
            if let Some((name, len)) = self.posix_class_at(self.pos) {
                if !POSIX_CLASSES.contains(&name.as_str()) {
                    return Err(PatternProblem::Invalid);
                }
                self.pos += len;
                return Ok(Member::Set);
            }
        }
        self.pos += 1;
        if c != '\\' {
            return Ok(Member::Char(c));
        }
        let escaped = self.peek().ok_or(PatternProblem::Unchecked)?;
        self.pos += 1;
        match escaped {
            'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'h' | 'H' | 'v' | 'V' => Ok(Member::Set),
            // `\x`, `\p`, `\N`, `\Q`...: each its own syntax, inside a
            // class as well as out of it.
            c if c.is_ascii_alphanumeric() => Err(PatternProblem::Unchecked),
            c => Ok(Member::Char(c)),
        }
    }

    /// The name and length of a POSIX class at `at`, if PCRE would read
    /// one there: `[:alpha:]`, or the unsupported `[.x.]` and `[=x=]`,
    /// whose name is given as empty so that it is never a known one.
    ///
    /// PCRE's own test (`check_posix_syntax`): a `[` and a terminator, then
    /// the same terminator right before a `]`, with no `]` or `[` plus
    /// terminator in between; `\]` and `\\` are skipped over.
    fn posix_class_at(&self, at: usize) -> Option<(String, usize)> {
        let rest = self.chars.get(at..)?;
        if rest.first() != Some(&'[') {
            return None;
        }
        let terminator = *rest.get(1).filter(|c| matches!(c, ':' | '.' | '='))?;
        let mut i = 2;
        while i < rest.len() {
            match rest[i] {
                '\\' if matches!(rest.get(i + 1), Some(']' | '\\')) => i += 1,
                '[' if rest.get(i + 1) == Some(&terminator) => return None,
                ']' => return None,
                c if c == terminator && rest.get(i + 1) == Some(&']') => {
                    let name = if terminator == ':' {
                        rest[2..i].iter().collect()
                    } else {
                        String::new()
                    };
                    return Some((name, i + 2));
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    /// A quantifier at the current position, consumed along with any lazy
    /// or possessive suffix. `None` if there is none, which includes a `{`
    /// that is a literal.
    fn quantifier(&mut self) -> Result<Option<Quantifier>, PatternProblem> {
        let found = match self.peek() {
            Some('{') => match self.brace()? {
                Brace::Literal => return Ok(None),
                Brace::Quantifier { min, max, len } => {
                    self.pos += len;
                    Quantifier {
                        min,
                        repeats: max.is_none_or(|max| max > 1),
                        // `{n,}` is n copies and a starred one.
                        copies: Some(max.map_or(min + 1, |max| max.max(min))),
                    }
                }
            },
            Some(symbol @ ('?' | '*' | '+')) => {
                self.pos += 1;
                Quantifier {
                    min: usize::from(symbol == '+'),
                    repeats: symbol != '?',
                    copies: None,
                }
            }
            _ => return Ok(None),
        };
        if matches!(self.peek(), Some('?' | '+')) {
            self.pos += 1;
        }
        Ok(Some(found))
    }

    /// What the `{` at the current position is. Leaves the position alone.
    ///
    /// Only the strict forms, `{n}`, `{n,}` and `{n,m}`, count as a
    /// quantifier. PCRE2 10.43 also reads `{,n}` and `{ n }` as one, where
    /// earlier versions read them as literal text: which one a host's NGINX
    /// has is not something to guess, so those are refused.
    fn brace(&self) -> Result<Brace, PatternProblem> {
        let rest = &self.chars[self.pos..];
        let body_len = rest
            .iter()
            .skip(1)
            .take_while(|&&c| c.is_ascii_digit() || c == ',' || c == ' ')
            .count();
        if body_len == 0 || rest.get(body_len + 1) != Some(&'}') {
            return Ok(Brace::Literal);
        }
        let body: String = rest[1..=body_len].iter().collect();
        let number = |text: &str| -> Result<usize, PatternProblem> {
            if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
                return Err(PatternProblem::Unchecked);
            }
            match text.parse::<usize>() {
                Ok(n) if n <= PCRE_MAX_REPEAT => Ok(n),
                _ => Err(PatternProblem::Invalid),
            }
        };
        let (min, max) = match body.split_once(',') {
            None => {
                let n = number(&body)?;
                (n, Some(n))
            }
            Some((min, "")) => (number(min)?, None),
            Some((min, max)) => (number(min)?, Some(number(max)?)),
        };
        if max.is_some_and(|max| max < min) {
            return Err(PatternProblem::Invalid);
        }
        Ok(Brace::Quantifier {
            min,
            max,
            len: body_len + 2,
        })
    }
}

/// The patterns in `patterns` that are safe to write (see
/// [`pattern_problem`]), in order. Empty is the same "nothing to block" case
/// as an empty list, which removes any existing sentinel block instead of
/// writing an empty one.
///
/// Checked again here, at render time, rather than trusted from wherever
/// they came from: a row stored by an older release, a list fetched before
/// a check existed. [`skipped_entries`] names what is left out, for the
/// status report.
pub(crate) fn usable_patterns(patterns: &[String]) -> Vec<&str> {
    patterns
        .iter()
        .map(String::as_str)
        .filter(|p| reaches_pcre_intact(p) && is_usable_pattern(p))
        .collect()
}

/// Every stored entry the render leaves out, one line each, for the
/// status report and `apply-blocks` to name: rows an older release stored
/// without today's checks, and bot-list patterns fetched before them.
/// Checked the way the render checks them, so the two cannot disagree.
///
/// A list, not an error: leaving an entry out is the safe failure, and an
/// apply must still write everything else. But an entry left out without a
/// word is a block or an exemption the operator believes is there.
pub fn skipped_entries(db: &crate::db::Db) -> Result<Vec<String>> {
    use crate::db;
    let mut skipped = Vec::new();
    for ua in db.list_blocked_user_agents()? {
        let regex = db::escape_regex_literal(&ua);
        if let Some(problem) = pattern_problem(&regex) {
            skipped.push(format!("blocked user agent {ua:?}: {problem}"));
        }
    }
    let unusable_bots = db
        .list_bots()?
        .iter()
        .filter(|bot| !is_usable_pattern(&bot.user_agent_pattern))
        .count();
    if unusable_bots > 0 {
        skipped.push(format!(
            "{unusable_bots} bot-list pattern(s) that are not a regex this tool can check"
        ));
    }
    for ua in db.list_trusted_user_agents()? {
        if let Err(err) = db::validate_trusted_user_agent(&ua) {
            skipped.push(format!("trusted user agent {ua:?}: {err}"));
        }
    }
    for site in db.list_sites()? {
        let name = &site.server_name;
        for path in db.site_path_exemptions(site.id)? {
            if let Err(err) = db::validate_exempt_path(&path) {
                skipped.push(format!("{name}: exempt path {path:?}: {err}"));
            }
        }
        for exemption in db.site_agent_exemptions(site.id)? {
            let (path, ua) = (&exemption.path, &exemption.user_agent);
            if let Err(err) =
                db::validate_exempt_path(path).and_then(|_| db::validate_exemption_user_agent(ua))
            {
                skipped.push(format!("{name}: exempt path {path:?} for {ua:?}: {err}"));
            }
        }
    }
    Ok(skipped)
}

/// Whether NGINX hands PCRE exactly `regex` when this module writes it:
/// [`nginx_quoted`] read back through [`nginx_unquoted`]. True of every
/// string by construction; asked anyway, because a regex that reached PCRE
/// as something else is how a blocked user agent once became a rule
/// against every visitor.
fn reaches_pcre_intact(regex: &str) -> bool {
    let quoted = nginx_quoted(regex);
    nginx_unquoted(&quoted[1..quoted.len() - 1]) == regex
}

/// Maximum byte length of a single chunk [`chunk_patterns`] produces, as
/// written: after [`nginx_quoted`] has escaped it.
///
/// NGINX's config-file parser has a hard ceiling on the length of a single
/// quoted parameter — confirmed empirically against a real `nginx -t`:
/// even a *properly terminated* quoted string fails with `too long
/// parameter, probably missing terminating """ character` once it crosses
/// roughly 4100 bytes (matching `NGX_CONF_BUFFER`), regardless of what
/// precedes it in the file. Having enough blocked bots is enough to reach
/// it: the `nginx-bad-bots` source alone is ~700 entries, easily exceeding
/// 4096 bytes once joined with `|`. Set well below the observed failure point to
/// stay safe regardless of how much unrelated content precedes the
/// sentinel block in a real config file (confirmed empirically too: a
/// 2000-byte quoted parameter still parses fine even after ~10KB of
/// preceding file content).
pub(crate) const MAX_PATTERN_CHUNK_LEN: usize = 2000;

/// Joins `patterns` with `|` into regexes of at most `max_len` bytes each
/// once written by [`nginx_quoted`], **never splitting a pattern**. A
/// single pattern longer than `max_len` becomes its own oversized chunk
/// rather than being dropped or cut.
///
/// This used to join everything first and then split the result on every
/// `|` — including the `|` of an escaped `\|` and the ones inside a
/// `(a|b)` group. A chunk could then end in the backslash of `\|`, which
/// escaped the closing quote of `if ($http_user_agent ~* "...")`, and NGINX
/// read the start of the next chunk as directives. Verified with a real
/// `nginx -t`: a line in a downloaded bot list could put an `include` into
/// a config that root loads, unattended, from cron. Whole patterns are
/// what keep each chunk a regex; [`nginx_quoted`] is what keeps it inside
/// its quotes whatever it ends in.
pub(crate) fn chunk_patterns(patterns: &[&str], max_len: usize) -> Vec<String> {
    let mut chunks: Vec<(String, usize)> = Vec::new();
    for pattern in patterns {
        let len = quoted_len(pattern);
        match chunks.last_mut() {
            Some((last, last_len)) if *last_len + 1 + len <= max_len => {
                last.push('|');
                last.push_str(pattern);
                *last_len += 1 + len;
            }
            _ => chunks.push((pattern.to_string(), len)),
        }
    }
    chunks.into_iter().map(|(chunk, _)| chunk).collect()
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
///
/// **The stock `conf.d` only for a root inside the stock tree.** A root
/// such as `/etc/nginx/sites-enabled` is a part of `/etc/nginx`, whose
/// `conf.d` is the one its NGINX reads. Any other root is a tree of its
/// own, and never reaches out of itself: `batch --root <scratch>` used to
/// read, and would have rewritten or removed, the host's own
/// `/etc/nginx/conf.d/stop-bots-trusted.conf`. Such a root without a
/// `conf.d` gets `<root>/conf.d`, which a write creates.
pub fn conf_d_dir(root: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os(CONF_D_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let beside_the_sites = root.join("conf.d");
    if beside_the_sites.is_dir() || !is_in_stock_tree(root) {
        return beside_the_sites;
    }
    PathBuf::from(CONF_D_DIR)
}

/// Whether `root` is [`DEFAULT_ROOT`] or a directory in it, as written: a
/// `..` anywhere in it means it may lead anywhere, so it does not count.
fn is_in_stock_tree(root: &Path) -> bool {
    root.is_absolute()
        && root.starts_with(DEFAULT_ROOT)
        && !root
            .components()
            .any(|part| part == std::path::Component::ParentDir)
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

/// The path every exemption is matched against: the path of the request
/// the client sent. See [`path_of_the_request_sent`].
const PATH_VAR: &str = "$stop_bots_path";

/// Sets [`PATH_VAR`] to the path of the request the client sent, for the
/// exemptions to be matched against instead of `$uri`.
///
/// **Why not `$uri`.** An internal redirect starts the request again at
/// NGINX's server-rewrite phase (`ngx_http_handler` sets `phase_handler`
/// to `server_rewrite_index` for an internal request), which is exactly
/// where these server-level `if`s run — and `$uri` is the *new* path
/// then. A WordPress site's `try_files $uri $uri/ /index.php?$args` sends
/// `/wp-json/wp/v2/posts` on to `/index.php`, so an exemption for
/// `/wp-json/` let the request through on the first pass and blocked it
/// on the second: every exemption on a front-controller application was
/// undone. Trust is not affected; it is
/// decided by address and user agent, which a redirect does not change.
/// (`rewrite ... last` and a named `@location` go back to the location
/// phases only, past these.)
///
/// **Why not `$request_uri` either.** It is the same on every pass, and on
/// a subrequest, but it is the request line as sent: undecoded, with `..`
/// and `//` unresolved. `/wp-json/../wp-login.php` starts with an exempt
/// prefix and is served as `/wp-login.php`; see [`exemption_regexes`] for
/// when that bypass was found.
///
/// So the path is taken from `$request_uri` only where it cannot differ
/// from what `$uri` was on the first pass: the whole path before any `?`,
/// with no `%` (nothing to decode), no `#` or `\`, no `//` (nothing to
/// merge) and no `.` or `..` segment (nothing to resolve). That is every
/// path an application routes in practice. Anything else falls back to
/// `$uri`, which is what every exemption used before: on the first pass
/// the same thing, and after a redirect at worst an exemption lost, never
/// one gained.
fn path_of_the_request_sent() -> String {
    format!(
        "    set {PATH_VAR} $uri;\n    if ($request_uri ~ {}) {{\n        set {PATH_VAR} $1;\n    }}\n    if ({PATH_VAR} ~ {}) {{\n        set {PATH_VAR} $uri;\n    }}\n",
        nginx_quoted(r"^(/[^?%#\\]*)(\?.*)?$"),
        nginx_quoted(r"//|/\.\.?(/|$)"),
    )
}

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

/// A request rule's NGINX condition, without the surrounding `if (...)`.
/// A regex in one is written by [`nginx_quoted`], like every other.
fn condition(rule: RequestRule) -> String {
    let matches = |variable: &str, regex: &str| format!("{variable} ~ {}", nginx_quoted(regex));
    match rule {
        RequestRule::Http1x => matches("$server_protocol", r"^HTTP/1\."),
        RequestRule::NoAccept => r#"$http_accept = """#.to_string(),
        RequestRule::NoAcceptLanguage => r#"$http_accept_language = """#.to_string(),
        RequestRule::NoUserAgent => r#"$http_user_agent = """#.to_string(),
        // Anchored, and matching both an IPv4 literal and a bracketed
        // IPv6 one. `$host` is already lowercased and port-stripped by
        // NGINX, which `$http_host` is not.
        RequestRule::IpLiteralHost => matches("$host", r"^(\d+\.\d+\.\d+\.\d+|\[)"),
        RequestRule::OldTls => matches("$ssl_protocol", r"^TLSv1(\.[01])?$"),
    }
}

/// The contents of the generated `limit_req_zone` file.
///
/// Keyed on `$binary_remote_addr` (4 bytes for IPv4, 16 for IPv6) rather
/// than `$remote_addr`'s string form, the conventional choice: the zone is
/// a fixed-size shared memory block and the binary key fits roughly four
/// times as many clients into it.
pub fn rate_limit_conf_body(rate_per_second: i64, zone_megabytes: i64) -> String {
    format!(
        "{}limit_req_zone $binary_remote_addr zone={RATE_LIMIT_ZONE}:{zone_megabytes}m \
         rate={rate_per_second}r/s;\n",
        managed_header()
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
        "{}limit_req_zone {LIMIT_KEY_VAR} zone={UNTRUSTED_RATE_LIMIT_ZONE}:{zone_megabytes}m \
         rate={rate_per_second}r/s;\n",
        managed_header()
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
/// case-insensitive, regex-escaped substring, written by [`nginx_quoted`]
/// with the `~*` that makes a `map` key a regex inside the quotes. Each
/// one has been through `db::validate_trusted_user_agent`, and is checked
/// again here rather than trusting the caller — a bad `map` key would not
/// break one site, it would stop NGINX loading at all.
///
/// All three are evaluated lazily, per request, and only when read.
pub fn trusted_conf_body(addresses: &[String], user_agents: &[String]) -> Option<String> {
    let user_agents: Vec<String> = user_agents
        .iter()
        .filter(|ua| is_stored_as_valid(ua, crate::db::validate_trusted_user_agent))
        .map(|ua| nginx_quoted(&format!("~*{}", crate::db::escape_regex_literal(ua))))
        .collect();
    // Trimmed before it is checked and written alike: the check trims, so
    // what it passed is the trimmed text, and that is all that is written.
    let addresses: Vec<&str> = addresses
        .iter()
        .map(|a| a.trim())
        .filter(|a| crate::db::is_valid_address(a))
        .collect();
    if addresses.is_empty() && user_agents.is_empty() {
        return None;
    }
    let mut out = managed_header();
    out.push_str("geo $stop_bots_trusted_address {\n    default 0;\n");
    for address in addresses {
        out.push_str(&format!("    {address} 1;\n"));
    }
    out.push_str("}\n");
    out.push_str(&format!(
        "map $http_user_agent {TRUSTED_VAR} {{\n    default $stop_bots_trusted_address;\n"
    ));
    for ua in user_agents {
        out.push_str(&format!("    {ua} 1;\n"));
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
///
/// The `Generated by` line is left out of the comparison: it names the
/// version that wrote the file, so comparing it would make every site on
/// a host that trusts anything `STALE` after every upgrade, with nothing
/// about what the file says having changed.
pub(crate) fn trust_file_is_current(config: &BlockConfig, on_disk: Option<&str>) -> bool {
    match (&config.trust, block_text(config)) {
        (Some(trust), Some(_)) => {
            let expected = trusted_conf_body(&trust.addresses, &trust.user_agents);
            on_disk
                .zip(expected.as_deref())
                .is_some_and(|(text, expected)| {
                    crate::generated::same_but_for_the_version(text, expected)
                })
        }
        _ => true,
    }
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

/// The directories a recorded file may be removed from: the `conf.d`
/// this root's files go into, and [`managed_dir`], each with its links
/// resolved. A directory that does not exist is left out.
pub(crate) fn managed_directories(root: &Path) -> Vec<PathBuf> {
    [conf_d_dir(root), managed_dir()]
        .iter()
        .filter_map(|dir| fs::canonicalize(dir).ok())
        .collect()
}

/// The fixed list: where each file the current settings do not call for
/// would be, if it were written today.
pub(crate) fn fallback_unused_managed_files(
    db: &crate::db::Db,
    root: &Path,
) -> Result<Vec<PathBuf>> {
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
    block_text_serving(config, &robots_txt_path())
}

/// [`block_text`], with the generated `robots.txt` served from `robots`:
/// the path NGINX reads it at, which for an NGINX in a container is not
/// where this process wrote it (see [`crate::npmplus`]).
pub(crate) fn block_text_serving(config: &BlockConfig, robots: &Path) -> Option<String> {
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
    let exemptions = exemption_regexes(&prefixes, exact);

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
    let uses_flag = !exemptions.is_empty()
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
                "    if ($http_user_agent ~* {}) {{\n        {set_blocked}",
                nginx_quoted(chunk)
            ));
        }
    }
    for rule in &config.request_rules {
        out.push_str(&format!(
            "    if ({}) {{\n        {set_blocked}",
            condition(*rule)
        ));
    }
    if !exemptions.is_empty() || !agent_clears.is_empty() {
        out.push_str(&path_of_the_request_sent());
    }
    for exemptions in &exemptions {
        out.push_str(&format!(
            "    if ({PATH_VAR} ~* {}) {{\n        set $stop_bots_block 0;\n    }}\n",
            nginx_quoted(exemptions)
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
            robots.display()
        ));
    }
    out.push_str(&format!("    {BLOCK_END}\n"));
    Some(out)
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
    let mut config = config.clone();
    if !block.is_tls {
        config.request_rules.retain(|rule| !rule.needs_tls());
    }
    config
}

/// Builds the path regexes that clear the block flag, none when there
/// are no usable exemptions: `prefixes` match anything under them, `exact`
/// only themselves.
///
/// Usually one. Each is written as one quoted parameter, which NGINX
/// refuses past about 4 KB, so a site with enough exemptions gets them
/// split between several the way [`chunk_patterns`] splits bot patterns;
/// joined into one, a hundred ordinary paths failed `nginx -t` and froze
/// every apply after them.
///
/// **An exemption is a literal path prefix, never a regex.** Anchored with
/// `^` and alternated, so `/blog` exempts `/blog` and `/blog/post` but not
/// `/notablog`. Each path is regex-escaped: these are URL prefixes typed by
/// an admin, not hand-written regex, and an unescaped `.` or `?` in one
/// would quietly widen the exemption far beyond what was asked for —
/// which, unlike a too-narrow pattern, fails *open*. The whole regex is
/// then written by [`nginx_quoted`]: before it was, a stored `/x\|` reached
/// PCRE as `^(/x\\|)`, which exempted every path on the site.
///
/// Each path is checked again with `db::validate_exempt_path` rather than
/// trusted, so a row an older release stored without that check is left
/// out (see [`skipped_entries`]) instead of written.
///
/// Matched against [`PATH_VAR`], never `$request_uri` as it stands, for the
/// reason [`agent_exemption_clears`] gives: the raw request line is not
/// the path NGINX serves, and `/robots.txt/../wp-login.php` begins with an
/// exempt prefix while resolving to a blocked one. [`PATH_VAR`] is the
/// request line's path only where it is the path NGINX serves; see
/// [`path_of_the_request_sent`].
pub(crate) fn exemption_regexes(prefixes: &[String], exact: &[&str]) -> Vec<String> {
    let usable = |p: &&str| is_stored_as_valid(p, crate::db::validate_exempt_path);
    let escaped: Vec<String> = prefixes
        .iter()
        .map(String::as_str)
        .filter(usable)
        .map(crate::db::escape_regex_literal)
        .chain(
            exact
                .iter()
                .copied()
                .filter(usable)
                .map(|p| format!("{}$", crate::db::escape_regex_literal(p))),
        )
        .collect();
    let escaped: Vec<&str> = escaped.iter().map(String::as_str).collect();
    chunk_patterns(&escaped, MAX_PATTERN_CHUNK_LEN - "^()".len())
        .into_iter()
        .map(|chunk| format!("^({chunk})"))
        .collect()
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
/// if ($http_user_agent ~* "okhttp") { set $stop_bots_exempt $stop_bots_path; }
/// if ($stop_bots_exempt ~* "^(/remote\.php/dav/)") { set $stop_bots_block 0; }
/// ```
///
/// The reset opens every group, not just the first: a variable left
/// holding the path by one group's user agent would otherwise let the next
/// group's paths through for a client that never matched it.
///
/// [`PATH_VAR`], not `$request_uri`, like the plain exemptions. `$uri` has
/// had `..` and `//` resolved and is decoded, so
/// `/remote.php/dav/../../login` is `/login` and matches nothing here;
/// `$request_uri` is the raw request line, where that same string starts
/// with the exempt prefix while the application behind the proxy resolves
/// it to somewhere else. The plain exemptions read `$request_uri` too until
/// the same bypass was found there. [`PATH_VAR`] takes the request line's
/// path only when it has nothing to resolve, and `$uri` otherwise
/// ([`path_of_the_request_sent`]), so the bypass stays closed.
///
/// The user agent is matched as an escaped, case-insensitive substring,
/// the same as a trusted one, and checked again here rather than trusting
/// the caller, since a user agent that matched more than it says would
/// exempt every client.
fn agent_exemption_clears(exemptions: &[crate::db::AgentExemption]) -> String {
    let mut out = String::new();
    for group in exemptions.chunk_by(|a, b| a.user_agent == b.user_agent) {
        let user_agent = &group[0].user_agent;
        if !is_stored_as_valid(user_agent, crate::db::validate_exemption_user_agent) {
            continue;
        }
        let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
        let paths = exemption_regexes(&paths, &[]);
        if paths.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "    set {AGENT_EXEMPT_VAR} \"\";\n    if ($http_user_agent ~* {}) {{\n        set {AGENT_EXEMPT_VAR} {PATH_VAR};\n    }}\n",
            nginx_quoted(&crate::db::escape_regex_literal(user_agent)),
        ));
        for paths in &paths {
            out.push_str(&format!(
                "    if ({AGENT_EXEMPT_VAR} ~* {}) {{\n        set $stop_bots_block 0;\n    }}\n",
                nginx_quoted(paths)
            ));
        }
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
    locate_marked_where(content, begin, end, |start| {
        start > block.open && start < block.close
    })
}

/// The sentinel block in a file that is included *into* a `server` block
/// rather than holding one, found anywhere in the file the way
/// [`locate_marked`] finds it inside a block: as real comments only.
pub(crate) fn locate_marked_in_file(content: &str) -> Option<(usize, usize)> {
    locate_marked_where(content, BLOCK_BEGIN, BLOCK_END, |_| true)
}

/// The markers of [`locate_marked_in_file`]'s block, around `body`.
pub(crate) fn marked(body: &str) -> String {
    format!("{BLOCK_BEGIN}\n{body}{BLOCK_END}\n")
}

/// [`locate_marked`], over the comments starting where `within` says.
fn locate_marked_where(
    content: &str,
    begin: &str,
    end: &str,
    within: impl Fn(usize) -> bool,
) -> Option<(usize, usize)> {
    let comments: Vec<(usize, usize)> = lex(content)
        .comments
        .into_iter()
        .filter(|&(start, _)| within(start))
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

// ---- what earlier releases wrote for the web console ----

/// The markers around the `location` the web console's Web Access panel
/// wrote into a site, before the console was removed. Nothing writes them
/// now; they are only ever taken out, by `uninstall`, with the blocks.
///
/// **Frozen**, like [`BLOCK_BEGIN`]: they are the bytes on hosts that set
/// Web Access up.
const CONSOLE_BEGIN: &str = "# BEGIN stop-bots console (DO NOT EDIT)";
const CONSOLE_END: &str = "# END stop-bots console";

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

/// The console section an earlier release wrote into `block`, if any.
fn locate_console_block(content: &str, block: &ServerBlock) -> Option<(usize, usize)> {
    locate_marked(content, block, CONSOLE_BEGIN, CONSOLE_END)
}

/// What to do when the NGINX config root is not there: most often NGINX
/// is in a container, or installed under another prefix.
fn missing_root_hint() -> &'static str {
    "If NGINX's config lives somewhere else, store where with \
     `stop-bots set-web-server nginx --root <dir>`, or pass `--root <dir>` for one run."
}

/// Recursively walks `root` looking for NGINX config files containing
/// `server { ... }` blocks, returning one [`DiscoveredSite`] per block (named
/// after its first `server_name`). Files with no server block, or that
/// aren't valid UTF-8 text, are silently skipped, and so are backups: see
/// [`crate::webserver::config_files`].
///
/// A `root` that does not exist *is* an error, unlike anything unreadable
/// inside one. The difference matters: a mistyped `--root` used to walk
/// nothing and report "0 site(s)", which reads exactly like a correct run
/// against a server that has no sites — so the mistake looked like an
/// answer. A file that can't be read inside a real root is a different
/// thing, and still skipped.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    if !root.exists() {
        return Err(crate::hint::with(
            anyhow::anyhow!("{} does not exist", root.display()),
            missing_root_hint(),
        ));
    }
    let mut sites = Vec::new();
    for entry in crate::webserver::config_files(root) {
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

/// Every named `server` block under `root`, with the addresses it listens
/// on: [`discover_sites`]' walk, keeping what the health check needs to
/// ask the site something over loopback.
pub fn site_listens(root: &Path) -> Result<Vec<crate::webserver::SiteListens>> {
    if !root.exists() {
        anyhow::bail!("{} does not exist", root.display());
    }
    let mut sites = Vec::new();
    for entry in crate::webserver::config_files(root) {
        let Ok(content) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for block in parse_server_blocks(&content) {
            if let Some(name) = block.names.first() {
                sites.push(crate::webserver::SiteListens {
                    server_name: name.clone(),
                    listens: block.listens,
                });
            }
        }
    }
    Ok(sites)
}

/// What [`apply_blocks_to_file`] would make of `content`, without writing
/// it — the half a preview shares with the apply, so the two cannot differ.
pub fn blocks_for_file(
    content: &str,
    config_path: &Path,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
) -> Result<String> {
    let mut content = content.to_string();
    let block_count = parse_server_blocks(&content).len();

    // Editing a block shifts the byte offsets of every block after it, so
    // re-parse before each edit rather than reusing stale spans. Block order
    // is stable across re-parses since edits only rewrite sentinel lines
    // inside existing braces, never add or remove server blocks.
    for i in 0..block_count {
        let blocks = parse_server_blocks(&content);
        let block = nth_block(&blocks, i, block_count, config_path)?;
        let config = block
            .names
            .first()
            .and_then(|name| site_configs.iter().find(|(n, _)| n == name))
            .map(|(_, config)| config)
            .unwrap_or(default_config);
        content = apply_block(&content, block, config);
    }
    Ok(content)
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
/// has to agree with NGINX about which hosts reach a site — telling which
/// site a logged request was for ([`crate::logscan`]) — needs the rest too.
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

/// The application that answers for `server_name` in `config_path`, as
/// [`crate::services::recognise`] reads it from the directives of every
/// `server` block there that declares one of the site's names: the
/// HTTPS block is the one that passes requests on, and it is not always
/// the one the site was scanned from.
///
/// This project's own blocks are taken out first. The bot block quotes
/// upstream user-agent patterns, which could name anything, and the
/// console section an earlier release wrote passes to the console.
///
/// `None` when the file cannot be read, which allows nothing.
pub fn site_service(config_path: &Path, server_name: &str) -> Option<crate::services::Service> {
    crate::services::recognise(&site_directives(config_path, server_name)?)
}

/// Every directive of every `server` block in `config_path` that declares
/// one of `server_name`'s names, as its name and its arguments: what
/// [`site_service`] and [`crate::webapps`] read a site from, with this
/// project's own blocks taken out first, as [`site_service`] says.
///
/// `None` when the file cannot be read or no block declares the name.
pub fn site_directives(
    config_path: &Path,
    server_name: &str,
) -> Option<Vec<(String, Vec<String>)>> {
    let content = without_injected_blocks(&fs::read_to_string(config_path).ok()?);
    let blocks = parse_server_blocks(&content);
    let names = blocks
        .iter()
        .find(|block| block.names.iter().any(|name| name == server_name))?
        .names
        .clone();
    let tokens = lex(&content).tokens;
    let mut directives = Vec::new();
    for block in blocks
        .iter()
        .filter(|block| block.names.iter().any(|name| names.contains(name)))
    {
        directives.extend(directives_within(&tokens, block.open, block.close));
    }
    Some(directives)
}

/// Each directive whose tokens lie between the byte offsets `open` and
/// `close`, as its name and its arguments: a word at the start of a
/// statement, and the words after it up to its `;` or `{`. Those of
/// nested blocks (`location`, `if`) included.
fn directives_within(
    tokens: &[(String, usize)],
    open: usize,
    close: usize,
) -> Vec<(String, Vec<String>)> {
    let mut directives = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for (token, _) in tokens
        .iter()
        .filter(|(_, offset)| *offset > open && *offset < close)
    {
        match token.as_str() {
            ";" | "{" | "}" => directives.extend(current.take()),
            word => match &mut current {
                Some((_, arguments)) => arguments.push(word.to_string()),
                None => current = Some((word.to_string(), Vec::new())),
            },
        }
    }
    directives
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

// ---- the HTTP/1.x rule where nothing speaks HTTP/2 ----

/// How many directories above a root `nginx.conf` is looked for: a root of
/// `/etc/nginx/sites-enabled` is still `/etc/nginx`'s tree.
const MAIN_CONFIG_LEVELS_UP: usize = 2;

/// Whether the NGINX config around `root` turns HTTP/2 on anywhere: an
/// `http2 on;` (NGINX 1.25.1 and later, in `http` or a `server`), or a
/// `listen` with the `http2` parameter (before that, and still read). The
/// whole tree from `nginx.conf`'s directory down, because either may be
/// in another file: `http2 on;` in `nginx.conf`'s `http` block, or the
/// `listen ... http2` of another `server` on the same port, which turns
/// HTTP/2 on for every `server` on it.
///
/// `None` when there is no `nginx.conf` at or just above `root` to read
/// from — a root whose main config is somewhere this cannot see, as in a
/// container — and nothing is refused on that.
///
/// Read with [`lex`], so a commented-out `# listen 443 ssl http2;` does
/// not count.
fn enables_http2(root: &Path) -> Option<bool> {
    let top = main_config_dir(root)?;
    for file in tree_files(&top) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let mut statement: Vec<String> = Vec::new();
        for (token, _) in lex(&content).tokens {
            if matches!(token.as_str(), ";" | "{" | "}") {
                let words: Vec<&str> = statement.iter().map(String::as_str).collect();
                match words.as_slice() {
                    ["http2", "on"] => return Some(true),
                    ["listen", rest @ ..] if rest.contains(&"http2") => return Some(true),
                    _ => {}
                }
                statement.clear();
            } else {
                statement.push(token);
            }
        }
    }
    Some(false)
}

/// The directory `nginx.conf` is in, at `root` or up to
/// [`MAIN_CONFIG_LEVELS_UP`] above it: the top of the tree NGINX reads its
/// config from. `None` when there is none to be found.
fn main_config_dir(root: &Path) -> Option<PathBuf> {
    let root = std::path::absolute(root).ok()?;
    root.ancestors()
        .take(MAIN_CONFIG_LEVELS_UP + 1)
        .find(|dir| dir.join("nginx.conf").is_file())
        .map(Path::to_path_buf)
}

/// Every config file under `top`, a few levels deep: not a backup's
/// ([`crate::webserver::is_backup_name`]), not a link (each file is found
/// once, where it is), and not larger than any config file is. In name
/// order, so what is found in them is found in the same order every time.
fn tree_files(top: &Path) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(top)
        .max_depth(4)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !crate::webserver::is_backup_name(&entry.file_name().to_string_lossy())
        })
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            fs::metadata(entry.path()).is_ok_and(|meta| meta.is_file() && meta.len() < 1 << 20)
        })
        .map(|entry| entry.into_path())
}

// ---- the access logs the config names ----

/// Every file an `access_log` directive under `root` names, in the order
/// they are found, each once. From the whole tree `nginx.conf` heads, when
/// there is one at or just above `root`: the `http` block's own log is in
/// `nginx.conf`, not with the sites.
///
/// Left out, because they are not a file on this host to read: `off`, a
/// `syslog:` target, and a path with a variable in it (`$host.log`), whose
/// files are named per request. A relative path is NGINX's prefix's; that
/// is taken to be the directory `nginx.conf` is in, which it is in
/// nginx.org's packages and the official image. (Debian's prefix is
/// `/usr/share/nginx`, where no log goes.)
///
/// Like the site scan, this reads `sites-available` rather than following
/// the links in `sites-enabled`, so a site that is not enabled can name a
/// log here; the reader leaves out one that is not there (see
/// [`crate::hostlog::Sources::new`]).
pub fn access_logs(root: &Path) -> Vec<PathBuf> {
    let top = main_config_dir(root).or_else(|| std::path::absolute(root).ok());
    let Some(top) = top else {
        return Vec::new();
    };
    let mut logs: Vec<PathBuf> = Vec::new();
    for file in tree_files(&top) {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        let mut statement: Vec<String> = Vec::new();
        for (token, _) in lex(&content).tokens {
            if !matches!(token.as_str(), ";" | "{" | "}") {
                statement.push(token);
                continue;
            }
            if let [directive, path, ..] = statement.as_slice() {
                if directive == "access_log" {
                    if let Some(path) = access_log_path(path, &top) {
                        if !logs.contains(&path) {
                            logs.push(path);
                        }
                    }
                }
            }
            statement.clear();
        }
    }
    logs
}

/// The file an `access_log`'s first argument names, made absolute against
/// `prefix`; `None` for one that names no file here. See [`access_logs`].
fn access_log_path(written: &str, prefix: &Path) -> Option<PathBuf> {
    if written == "off" || written.starts_with("syslog:") || written.contains('$') {
        return None;
    }
    Some(prefix.join(written))
}

/// Why an apply cannot write `content`'s blocks as `config_for` asks, if
/// it cannot: the HTTP/1.x rule in a TLS `server` of a host on which
/// nothing turns HTTP/2 on, where NGINX answers every visitor over
/// HTTP/1.1 and the rule would turn every one of them away. `nginx -t`
/// passes it, so it is refused here, as Apache's is without `mod_http2`.
///
/// `config_for` is the config a block is written with, or `None` for a
/// block the apply leaves alone. A block without TLS is not asked: the
/// rule is never written there (see [`for_block`]).
pub fn refusal<'a>(
    content: &str,
    config_path: &Path,
    root: &Path,
    config_for: impl Fn(&ServerBlock) -> Option<&'a BlockConfig>,
) -> Option<String> {
    let blocks = parse_server_blocks(content);
    let wants_http1x = blocks.iter().find(|block| {
        config_for(block).is_some_and(|config| {
            for_block(config, block)
                .request_rules
                .contains(&RequestRule::Http1x)
        })
    })?;
    if enables_http2(root) != Some(false) {
        return None;
    }
    let name = wants_http1x.names.first().map_or("a site", String::as_str);
    Some(format!(
        "refusing to write {}: the HTTP/1.x rule is on for {name}, but nothing in the NGINX \
         config turns HTTP/2 on (`http2 on;`, or `listen 443 ssl http2;` before NGINX \
         1.25.1): NGINX answers every visitor of it over HTTP/1.1, and the rule would turn \
         every one of them away. Turn HTTP/2 on for it, or switch the rule off for the site.",
        config_path.display()
    ))
}

/// What [`apply_block_for_site`] would make of `content`, without writing
/// it.
pub fn block_for_site(
    content: &str,
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<String> {
    let mut content = content.to_string();
    let block_count = parse_server_blocks(&content).len();

    // Same re-parse-before-each-edit approach as `blocks_for_file`:
    // editing a block shifts the byte offsets of every block after it.
    for i in 0..block_count {
        let blocks = parse_server_blocks(&content);
        let block = nth_block(&blocks, i, block_count, config_path)?;
        if block.names.first().map(String::as_str) != Some(server_name) {
            continue;
        }
        content = apply_block(&content, block, config);
    }
    Ok(content)
}

// ---- taking it all out again: `stop-bots uninstall` ----

/// `content` with every block stop-bots injected taken out of every
/// `server` block — the bot-blocking block and the console `location` an
/// earlier release wrote, found by their markers — and the line break each
/// insertion added.
///
/// The exact inverse of an insertion: a block is put right after the
/// `server {` brace with a newline in front of it, so where that is still
/// how it sits, the newline goes too and the file is byte for byte what it
/// was before stop-bots touched it. A block somebody has moved elsewhere
/// in the `server` block loses only its own lines.
pub fn without_injected_blocks(content: &str) -> String {
    let mut content = content.to_string();
    // One block per pass, re-parsed each time: taking one out shifts the
    // offsets of everything after it. Each pass removes at least one
    // marker line, so this ends.
    //
    // Within a `server` block, the one nearest the brace goes first. Both
    // kinds are inserted right after the brace, so that is the one
    // inserted last, and taking insertions back in reverse order is what
    // leaves the brace's own line break where it was.
    loop {
        let blocks = parse_server_blocks(&content);
        let found = blocks.iter().find_map(|block| {
            [
                locate_existing_block(&content, block),
                locate_console_block(&content, block),
            ]
            .into_iter()
            .flatten()
            .min()
            .map(|range| (block.open, range))
        });
        let Some((open, (start, end))) = found else {
            return content;
        };
        let inserted_newline = start == open + 2 && content.as_bytes()[open + 1] == b'\n';
        let start = if inserted_newline { open + 1 } else { start };
        content.replace_range(start..end, "");
    }
}

#[cfg(test)]
mod tests {
    use crate::db::BlockResponse;
    use crate::webserver::{is_robots_token, remove_managed};
    // ---- what releases with the web console wrote ----
    //
    // Frozen copies of the writers that put the console's section into a
    // site, so the tests can make the bytes those hosts have and check that
    // `uninstall` takes them back out.

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

    /// The gap this closes. An NGINX in a container moves three things:
    /// the commands that drive it, the logs it writes, and the directory
    /// its config lives in. The first two were stored; this one had to be
    /// repeated on five subcommands, and forgetting it anywhere scanned an
    /// empty /etc/nginx and reported success over nothing.
    #[test]
    fn a_stored_root_is_used_when_no_flag_is_given() {
        assert_eq!(
            root(&host_with_root("/srv/domaci/nginx"), None),
            std::path::PathBuf::from("/srv/domaci/nginx")
        );
    }

    #[test]
    fn nothing_stored_falls_back_to_the_stock_path() {
        assert_eq!(
            root(&crate::hostconf::HostConf::default(), None),
            std::path::PathBuf::from(DEFAULT_ROOT)
        );
    }

    /// A one-off run against a checkout must not require the stored value
    /// to be changed and put back -- the same precedence `LogPaths` uses.
    #[test]
    fn an_explicit_flag_beats_the_stored_root() {
        assert_eq!(
            root(
                &host_with_root("/srv/domaci/nginx"),
                Some(std::path::Path::new("/tmp/fixture"))
            ),
            std::path::PathBuf::from("/tmp/fixture")
        );
    }

    /// Host settings whose NGINX root is `root`.
    fn host_with_root(root: &str) -> crate::hostconf::HostConf {
        crate::hostconf::HostConf {
            nginx_root: Some(root.into()),
            ..Default::default()
        }
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
        let commands = WebServer::Nginx.default_commands();
        assert_eq!(commands.test, ["nginx", "-t"]);
        assert_eq!(commands.reload, ["systemctl", "reload", "nginx"]);
    }

    #[test]
    fn nginx_commands_fall_back_per_setting() {
        let host = crate::hostconf::HostConf {
            nginx_reload_command: Some("docker exec web nginx -s reload".into()),
            ..Default::default()
        };

        let commands = ServerCommands::from_host(&host).unwrap();
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
        let host = crate::hostconf::HostConf {
            nginx_test_command: Some(r#"docker exec "web nginx -t"#.into()),
            ..Default::default()
        };

        // Not a silent fallback: reloading the host's NGINX because the
        // container command had an unbalanced quote is the exact surprise
        // worth failing loudly over.
        let err = ServerCommands::from_host(&host).unwrap_err();
        assert!(
            err.to_string().contains("nginx_test_command"),
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

    /// A copy of a site is not a site: counted, it is stored as a second
    /// one, gets blocks written into it on every apply, and reads NOT
    /// FOUND once it is cleaned up.
    #[test]
    fn discovery_skips_backup_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let conf_d = dir.path().join("conf.d");
        let backup_dir = dir.path().join("conf.d.bak-2026-10-12");
        fs::create_dir(&conf_d).unwrap();
        fs::create_dir(&backup_dir).unwrap();
        fs::write(conf_d.join("cloud.conf"), one_site()).unwrap();
        fs::write(conf_d.join("cloud.conf.bak-2026-10-12"), one_site()).unwrap();
        fs::write(backup_dir.join("cloud.conf"), one_site()).unwrap();

        let sites = discover_sites(dir.path()).unwrap();

        let paths: Vec<&Path> = sites.iter().map(|s| s.config_path.as_path()).collect();
        assert_eq!(paths, [conf_d.join("cloud.conf")]);
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
        let changed =
            apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &config).unwrap();
        assert!(changed);

        let written = fs::read_to_string(&path).unwrap();
        assert!(written.contains(BLOCK_BEGIN));
        assert!(
            written.contains("BadBot|EvilCrawler"),
            "written was:\n{written}"
        );

        let changed_again =
            apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &config).unwrap();
        assert!(!changed_again);
    }

    #[test]
    fn apply_blocks_to_file_with_no_server_blocks_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx.conf");
        fs::write(&path, "events {}\nhttp {\n    include conf.d/*.conf;\n}\n").unwrap();

        let changed =
            apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &cfg(&["BadBot"]))
                .unwrap();
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

        let changed =
            apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &cfg(&["BadBot"]))
                .unwrap();
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
        let changed = apply_blocks_to_file(
            WebServer::Nginx,
            &path,
            dir.path(),
            &site_configs,
            &BlockConfig::default(),
        )
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
        let changed = apply_blocks_to_file(
            WebServer::Nginx,
            &path,
            dir.path(),
            &[],
            &cfg(&["GlobalDefaultBot"]),
        )
        .unwrap();
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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot", "EvilBot"]),
        )
        .unwrap();

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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();

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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["OldBot"]),
        )
        .unwrap();

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

        let changed = apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["OnlyOnA"]),
        )
        .unwrap();
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

        assert!(apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"])
        )
        .unwrap());
        assert!(!apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"])
        )
        .unwrap());
    }

    #[test]
    fn apply_block_for_site_is_a_noop_for_an_unknown_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let original = "server {\n    server_name a.example;\n}\n";
        fs::write(&path, original).unwrap();

        let changed = apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "unknown.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();
        assert!(!changed);
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    // ---- writing a regex into a quoted string, exactly ----

    /// Where NGINX's reader ends a double-quoted word that starts at
    /// `text[0]`: pass 1 of `ngx_conf_read_token`, where a backslash makes
    /// the next byte ordinary. The index of the closing quote.
    fn closing_quote(text: &str) -> Option<usize> {
        let bytes = text.as_bytes();
        let mut i = 1;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => return Some(i),
                _ => i += 1,
            }
        }
        None
    }

    /// Every string over the characters NGINX's reader treats specially,
    /// up to five long: written, it ends at its own closing quote, and
    /// reads back as itself. The whole of the claim `nginx_quoted` makes.
    /// (`r` is left out: NGINX treats it exactly as it does `t` and `n`.)
    #[test]
    fn every_regex_reaches_pcre_exactly_as_written() {
        let alphabet = ['a', '\\', '"', '\'', 't', 'n', '|'];
        let mut strings = vec![String::new()];
        for _ in 0..5 {
            let longer: Vec<String> = strings
                .iter()
                .filter(|s| s.chars().count() == strings.last().unwrap().chars().count())
                .flat_map(|s| alphabet.iter().map(move |c| format!("{s}{c}")))
                .collect();
            strings.extend(longer);
        }
        for regex in &strings {
            let quoted = nginx_quoted(regex);
            assert_eq!(
                closing_quote(&quoted),
                Some(quoted.len() - 1),
                "{regex:?} written as {quoted} does not end at its own quote"
            );
            assert_eq!(
                &nginx_unquoted(&quoted[1..quoted.len() - 1]),
                regex,
                "{regex:?} written as {quoted} reaches PCRE as something else"
            );
        }
    }

    /// The cases the review found, as written and as NGINX then reads them.
    #[test]
    fn a_backslash_is_doubled_only_where_nginx_would_read_an_escape() {
        for (regex, written) in [
            // A blocked `a\|`, escaped for PCRE: every backslash before
            // another is doubled, the last one is not.
            (r"a\\\|", r#""a\\\\\|""#),
            (r"x\\\*", r#""x\\\\\*""#),
            (r"Evil\\\(", r#""Evil\\\\\(""#),
            (r#"say "hi""#, r#""say \"hi\"""#),
            (r#"a\\\""#, r#""a\\\\\\\"""#),
            (r"end\\", r#""end\\\\""#),
            (r"\\t and \\n", r#""\\\\t and \\\\n""#),
            (r"it\'s", r#""it\\'s""#),
            // Already right before, and byte for byte the same now.
            (r"1h4x\.com", r#""1h4x\.com""#),
            (r"ALittle\ Client", r#""ALittle\ Client""#),
            (r"^(\d+\.\d+\.\d+\.\d+|\[)", r#""^(\d+\.\d+\.\d+\.\d+|\[)""#),
            ("$foo};", r#""$foo};""#),
        ] {
            assert_eq!(nginx_quoted(regex), written, "{regex:?}");
            assert_eq!(nginx_unquoted(&written[1..written.len() - 1]), regex);
        }
    }

    #[test]
    fn usable_patterns_drops_only_the_unsafe_entries() {
        let patterns = vec![
            "GoodBot".to_string(),
            "Trailing\\".to_string(),
            "1h4x\\.com".to_string(),
            "Quoted\"Bot".to_string(),
        ];
        assert_eq!(
            usable_patterns(&patterns),
            ["GoodBot", "1h4x\\.com", "Quoted\"Bot"]
        );
    }

    #[test]
    fn usable_patterns_is_empty_when_every_pattern_is_unsafe() {
        let patterns = vec!["Trailing\\".to_string(), "Evil(".to_string()];
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
        apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &config).unwrap();

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

    /// The limit is NGINX's, on the bytes in the file, so a chunk is
    /// measured as written: `a\\` is three characters of regex and five
    /// of config.
    #[test]
    fn chunk_patterns_measures_each_chunk_as_written() {
        let patterns = [r"a\\x", r"b\\x", r"c\\x"];
        let chunks = chunk_patterns(&patterns, 13);
        assert_eq!(chunks, [r"a\\x|b\\x", r"c\\x"]);
        for chunk in &chunks {
            assert!(nginx_quoted(chunk).len() - 2 <= 13, "{chunk} is too long");
        }
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
        apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &config).unwrap();

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
        apply_block_for_site(WebServer::Nginx, &path, dir.path(), "a.example", &config).unwrap();

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

        let err = apply_blocks_to_file(WebServer::Nginx, &link, &root, &[], &cfg(&["BadBot"]))
            .unwrap_err();

        assert!(
            err.to_string().contains("outside the config root"),
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

        assert!(
            apply_blocks_to_file(WebServer::Nginx, &link, root, &[], &cfg(&["BadBot"])).unwrap()
        );

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

        apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();

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
        let snapshot = Snapshot::of_apply(dir.path(), [], &[], [path.as_path()]).unwrap();
        apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();

        let err = test_or_restore(WebServer::Nginx, &snapshot, &commands_that(false)).unwrap_err();

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
                !regex.ends_with('\\'),
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

    /// Each of these passes `nginx -t` and, against an ordinary Chrome
    /// user agent, runs PCRE into its match limit: NGINX then answers 500
    /// to every browser on every site.
    #[test]
    fn a_pattern_that_repeats_more_than_once_is_never_written() {
        for (pattern, why) in [
            ("Mozilla.*.*.*.*.*.*[!#]", "adjacent repetitions"),
            ("Mozilla.*Chrome.*Safari", "two repetitions apart"),
            (r"Bot\d+\.\d+", "two repetitions of a class"),
            ("Bot.{0,500}.{0,500}x", "bounded repetitions count too"),
        ] {
            assert_eq!(
                pattern_problem(pattern),
                Some(PatternProblem::Backtracks),
                "{pattern:?} ({why})"
            );
        }
    }

    #[test]
    fn a_repeated_choice_is_never_written() {
        for pattern in ["Mozilla(.|.)*[!#]", "xyz(a|aa)+$", "Bot(?:a|b){2,}"] {
            assert_eq!(
                pattern_problem(pattern),
                Some(PatternProblem::Backtracks),
                "{pattern:?}"
            );
        }
    }

    #[test]
    fn one_repetition_and_optional_parts_are_kept() {
        for pattern in [
            r"BlogTraffic\/\d\.\d+ Feed-Fetcher",
            r"Poduptime;\s*\+fediverse\.observer",
            "Face(book){0,1}[Bb]ot",
            r"Datadog(?:\/{0,1}Synthetics| Synthetic)",
            "(sistrix|SISTRIX) [cC]rawler",
        ] {
            assert_eq!(pattern_problem(pattern), None, "{pattern:?}");
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
            crate::db::escape_regex_literal("x # END stop-bots"),
            crate::db::escape_regex_literal(BLOCK_BEGIN),
        ]
    }

    /// Applies `config` to a one-site file three times and returns what
    /// each run left on disk.
    fn apply_three_times(original: &str, config: &BlockConfig) -> [String; 3] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, original).unwrap();
        std::array::from_fn(|_| {
            apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], config).unwrap();
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
        // Every pattern rejected by `pattern_problem` is the same case as
        // an empty list: nothing safe left to write.
        assert!(block_text(&cfg(&["Trailing\\"])).is_none());
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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();

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

        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();
        let changed = apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg_444(&["BadBot"]),
        )
        .unwrap();
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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();

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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg_rate(20),
        )
        .unwrap();

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
        remove_managed(&held(&dir.path().join("never-existed.conf"))).unwrap();
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
            text.contains("if ($stop_bots_path ~* \"^(/blog)\")"),
            "text was:\n{text}"
        );
        assert!(text.contains("return 403;"), "text was:\n{text}");
    }

    /// `$request_uri` is the raw request line. `GET
    /// /blog/../wp-login.php` starts with `/blog` there, while NGINX and the
    /// application behind it serve `/wp-login.php` — a blocked bot reaching
    /// any path by prefixing an exempt one. So it is read once, into the
    /// path an exemption is matched against, and only through the capture
    /// that takes a path with nothing to resolve; then anything with a `//`
    /// or a dot segment in it goes back to `$uri`.
    #[test]
    fn a_plain_exemption_reads_the_raw_path_only_where_it_is_the_resolved_one() {
        let text = block_text(&cfg_exempt(&["BadBot"], &["/blog"])).unwrap();
        let expected = [
            "    set $stop_bots_path $uri;\n",
            "    if ($request_uri ~ \"^(/[^?%#\\\\\\]*)(\\?.*)?$\") {\n        set $stop_bots_path $1;\n    }\n",
            "    if ($stop_bots_path ~ \"//|/\\.\\.?(/|$)\") {\n        set $stop_bots_path $uri;\n    }\n",
            "    if ($stop_bots_path ~* \"^(/blog)\") {\n",
        ];
        let at: Vec<Option<usize>> = expected.iter().map(|line| text.find(line)).collect();
        assert!(
            at.iter().all(Option::is_some) && at.windows(2).all(|w| w[0] < w[1]),
            "expected, in this order:\n{}\ntext was:\n{text}",
            expected.concat()
        );
        assert_eq!(text.matches("$request_uri").count(), 1, "text was:\n{text}");
    }

    /// A front controller's `try_files ... /index.php` is an internal
    /// redirect, which runs these `if`s again with `$uri` the new path. So
    /// nothing that clears the flag may read `$uri` directly, or the
    /// redirect undoes the exemption the request was let in on.
    #[test]
    fn no_exemption_reads_the_path_an_internal_redirect_changes() {
        let config = BlockConfig {
            serve_robots_txt: true,
            ..cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")])
        };
        let config = BlockConfig {
            exempt_paths: vec!["/wp-json/".to_string()],
            ..config
        };
        let text = block_text(&config).unwrap();
        for line in text.lines().filter(|line| line.contains("$uri")) {
            assert_eq!(
                line.trim(),
                "set $stop_bots_path $uri;",
                "only the fallback reads $uri; text was:\n{text}"
            );
        }
    }

    /// A site with no exemption has nothing to match a path against, and
    /// its block keeps the text it had.
    #[test]
    fn a_block_with_no_exemption_works_out_no_path() {
        let text = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(!text.contains("stop_bots_path"), "text was:\n{text}");
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
            text.contains("if ($stop_bots_path ~* \"^(/blog|/robots\\.txt$)\")"),
            "text was:\n{text}"
        );
    }

    #[test]
    fn the_exemption_regex_is_anchored_and_alternated() {
        assert_eq!(
            exemption_regexes(&["/blog".to_string(), "/feed".to_string()], &[]),
            ["^(/blog|/feed)"]
        );
    }

    /// One quoted parameter past about 4 KB fails `nginx -t`, and a site
    /// can have more exemptions than fit in one.
    #[test]
    fn many_exemptions_are_split_between_regexes_that_each_fit() {
        let paths: Vec<String> = (0..200).map(|n| format!("/section-{n:03}/page/")).collect();
        let regexes = exemption_regexes(&paths, &[]);
        assert!(regexes.len() > 1, "{} bytes in one", regexes[0].len());
        for regex in &regexes {
            assert!(
                nginx_quoted(regex).len() <= MAX_PATTERN_CHUNK_LEN,
                "{} bytes",
                nginx_quoted(regex).len()
            );
            assert!(regex.starts_with("^(") && regex.ends_with(')'), "{regex}");
        }
        let kept = regexes
            .iter()
            .map(|r| r.matches('|').count() + 1)
            .sum::<usize>();
        assert_eq!(kept, paths.len(), "every path is in exactly one");
    }

    /// Unescaped regex metacharacters in a literal URL prefix would widen
    /// the exemption — which fails *open*, unlike a too-narrow pattern.
    #[test]
    fn the_exemption_regex_escapes_metacharacters() {
        let regex = exemption_regexes(&["/a.b?c".to_string()], &[]).remove(0);
        assert!(regex.contains("\\."), "regex was: {regex}");
        assert!(regex.contains("\\?"), "regex was: {regex}");
    }

    #[test]
    fn the_exemption_regex_drops_unusable_paths() {
        // Not anchored at the start: could never match, so it's dropped
        // rather than silently widening or narrowing anything.
        assert!(exemption_regexes(&["blog".to_string()], &[]).is_empty());
        // Would terminate the quoted config string.
        assert!(exemption_regexes(&["/a\"b".to_string()], &[]).is_empty());
        assert!(exemption_regexes(&[], &[]).is_empty());
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
    /// to `/x`. The agent exemptions read the same path the plain ones do,
    /// which is the raw one only where it has nothing to resolve.
    #[test]
    fn an_agent_exemption_matches_the_same_path_as_a_plain_one() {
        let text = block_text(&cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")])).unwrap();
        let worked_out = text.find("    if ($stop_bots_path ~ \"//");
        let read = text.find("set $stop_bots_exempt $stop_bots_path;");
        assert!(
            worked_out.is_some() && read.is_some() && worked_out < read,
            "the path must be worked out before the agent exemption reads it:\n{text}"
        );
        assert_eq!(text.matches("$request_uri").count(), 1, "text was:\n{text}");
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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["okhttp"]),
        )
        .unwrap();
        let exempted = cfg_agent(&["okhttp"], &[("okhttp", "/remote.php/dav/")]);

        let before = site_apply_status(&path, "a.example", &exempted, no_trust_file());
        apply_block_for_site(WebServer::Nginx, &path, dir.path(), "a.example", &exempted).unwrap();
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
        assert_eq!(text.matches("if ($stop_bots_path ~* ").count(), 1);
        assert_eq!(text.matches("if ($stop_bots_block) {").count(), 1);
    }

    #[test]
    fn site_apply_status_is_stale_when_only_an_exemption_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, "server {\n    server_name a.example;\n}\n").unwrap();
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();

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
            WebServer::Nginx,
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
    fn parse_reads_each_listen_with_its_address_port_and_tls() {
        let content = concat!(
            "server {\n",
            "    listen 443 ssl;\n",
            "    listen [::]:8443 ssl http2;\n",
            "    listen 127.0.0.1:8080;\n",
            "    listen 443 quic;\n",
            "    listen unix:/run/a.sock;\n",
            "    server_name a.example;\n}\n"
        );
        let listen = |address: Option<&str>, port, tls| crate::webserver::Listen {
            address: address.map(|a| a.parse().unwrap()),
            port,
            tls,
        };
        assert_eq!(
            parse_server_blocks(content)[0].listens,
            [
                listen(None, 443, true),
                listen(Some("::"), 8443, true),
                listen(Some("127.0.0.1"), 8080, false),
            ]
        );
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

        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg_http1x(&["BadBot"]),
        )
        .unwrap();

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
        apply_block_for_site(WebServer::Nginx, &path, dir.path(), "a.example", &config).unwrap();
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
        apply_block_for_site(
            WebServer::Nginx,
            &path,
            dir.path(),
            "a.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();

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

    fn trusted() -> Trust {
        Trust::from_lists(
            &["203.0.113.7".to_string(), "2001:db8::/48".to_string()],
            &["UptimeRobot".to_string(), "Pingdom.com_bot".to_string()],
        )
        .unwrap()
    }

    fn cfg_trusted(patterns: &[&str]) -> BlockConfig {
        BlockConfig {
            trust: Some(trusted()),
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

    /// What is written is what was validated: the trimmed address. The
    /// whitespace around one a console wrote never reaches the file.
    #[test]
    fn a_trusted_address_is_written_as_it_was_checked() {
        let body = trusted_conf_body(&[" \t192.0.2.9\n ".to_string()], &[]).unwrap();
        assert!(body.contains("\n    192.0.2.9 1;\n"), "body was:\n{body}");
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
            format!(
                "# Generated by stop-bots {}. Edits will be overwritten.\n\
                 limit_req_zone $binary_remote_addr zone=stop_bots:10m rate=10r/s;\n",
                crate::generated::VERSION
            )
        );
    }

    /// The trust file carries the version that wrote it, and every site
    /// that reads it is compared against it. A version bump alone must not
    /// make those sites `STALE` — nor must a file 0.0.x wrote, whose header
    /// had no version at all.
    #[test]
    fn a_trust_file_from_another_version_is_still_current() {
        let config = cfg_trusted(&["BadBot"]);
        let expected = trust_body();
        let ours = format!("# {}.", crate::generated::generated_by());
        assert!(expected.starts_with(&ours), "trust file was:\n{expected}");
        for older in [
            "# Generated by stop-bots.",
            "# Generated by stop-bots 0.0.99.",
        ] {
            let on_disk = expected.replacen(&ours, older, 1);
            assert!(
                trust_file_is_current(&config, Some(&on_disk)),
                "a trust file headed {older:?} read as stale"
            );
        }
    }

    /// The markers are how every release finds the block an earlier one
    /// injected into an operator's site file — and `uninstall` how it finds
    /// what to take out. **Frozen, and pinned literally here rather than
    /// through the constants**: a changed marker makes every block already
    /// on disk invisible, so the next apply adds a second one beside it,
    /// and `uninstall` leaves the first behind. Nor may a version ever go
    /// inside them, which would change them with every release.
    #[test]
    fn the_sentinel_markers_are_frozen() {
        assert_eq!(BLOCK_BEGIN, "# BEGIN stop-bots (DO NOT EDIT)");
        assert_eq!(BLOCK_END, "# END stop-bots");
        assert_eq!(CONSOLE_BEGIN, "# BEGIN stop-bots console (DO NOT EDIT)");
        assert_eq!(CONSOLE_END, "# END stop-bots console");
    }

    /// Nor does the block itself carry a version: `site_apply_status`
    /// compares it as text, and every site would read `STALE` after every
    /// upgrade.
    #[test]
    fn the_injected_block_names_no_version() {
        let block = block_text(&cfg(&["BadBot"])).unwrap();
        assert!(
            !block.contains(crate::generated::VERSION) && !block.contains("Generated by"),
            "block was:\n{block}"
        );
    }

    /// Trusting a second user agent changes the trust file and no block,
    /// and a site has to read as out of date or nobody applies it.
    #[test]
    fn a_site_is_current_only_when_the_trust_file_is_the_expected_one() {
        let config = cfg_trusted(&["BadBot"]);
        let expected = trust_body();
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
        assert_eq!(remove_planned_managed_files(&[held(&path)]).unwrap(), 1);
        assert_eq!(remove_planned_managed_files(&[held(&path)]).unwrap(), 0);
    }

    /// The file at `path`, held through its directory, which must exist.
    fn held(path: &Path) -> DirFile {
        DirFile::locate(path).unwrap().unwrap()
    }

    /// Where each of `files` is.
    fn paths_of(files: &[DirFile]) -> Vec<PathBuf> {
        files.iter().map(|file| file.path().to_path_buf()).collect()
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
        db.trust_user_agent("Nextcloud").unwrap();
        db.set_rate_limit_enabled(true).unwrap();
        let host = host_with_root(dir.path().to_str().unwrap());

        let planned: Vec<PathBuf> = planned_managed_files(&db, &root(&host, None))
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
        let host = host_with_root(dir.path().to_str().unwrap());

        let unused =
            paths_of(&unused_managed_files(WebServer::Nginx, &db, &root(&host, None)).unwrap());
        for name in ["stop-bots-trusted.conf", "stop-bots-limits.conf"] {
            let expected = dir.path().join("conf.d").join(name);
            assert!(
                unused.contains(&expected),
                "{name} must be removed from where it was written; unused:\n{unused:#?}"
            );
        }
    }

    // ---- the record of what was written ----

    /// A file written by a generated-file writer, recorded as one would be.
    fn written_and_recorded(db: &crate::db::Db, path: &Path, body: &str) {
        record_managed_files(db, &[(path.to_path_buf(), body.to_string())]).unwrap();
        write_planned_managed_files(&[(path.to_path_buf(), body.to_string())]).unwrap();
    }

    /// The record is a row in a database root does not always own, and an
    /// apply runs as root. So it is acted on only inside the directories this tree's
    /// files go into: a set left in the `conf.d` of a root the host no
    /// longer uses is `uninstall`'s to collect, not an apply's, because
    /// a row naming *anywhere* is exactly what an attacker would write.
    #[test]
    fn a_recorded_file_outside_the_managed_directories_is_never_collected() {
        let (old, new) = (root_with_a_conf_d(), root_with_a_conf_d());
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_rate_limit_enabled(true).unwrap();
        let left_behind = rate_limit_conf_path(&old.path().join("conf.d"));
        written_and_recorded(&db, &left_behind, &rate_limit_conf_body(10, 10));

        let unused = paths_of(&unused_managed_files(WebServer::Nginx, &db, new.path()).unwrap());

        assert!(
            !unused.contains(&left_behind),
            "a file outside this root's conf.d was collected: {unused:#?}"
        );
        assert!(
            !unused.contains(&rate_limit_conf_path(&new.path().join("conf.d"))),
            "the file the settings call for was collected: {unused:#?}"
        );
        let found = DirFile::exactly(&left_behind).unwrap();
        assert!(
            found.is_regular() && is_generated(&found),
            "uninstall, which an administrator runs, still knows it for ours"
        );
    }

    /// Hostile rows, each written straight into `managed_files` as a
    /// compromised console could: none of them may be deleted, even though
    /// every target carries this project's header, so the header alone is
    /// not what protects them.
    #[test]
    fn a_hostile_managed_files_row_deletes_nothing() {
        let root = root_with_a_conf_d();
        let conf_d = root.path().join("conf.d");
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("stop-bots-limits.conf");
        let header = rate_limit_conf_body(10, 10);
        fs::write(&victim, &header).unwrap();
        let linked = conf_d.join("stop-bots-trusted.conf");
        std::os::unix::fs::symlink(&victim, &linked).unwrap();
        let misnamed = conf_d.join("default.conf");
        fs::write(&misnamed, &header).unwrap();

        let db = crate::db::Db::open_in_memory().unwrap();
        let climbing = conf_d
            .join("..")
            .join("..")
            .join(outside.path().strip_prefix("/").unwrap())
            .join("stop-bots-limits.conf");
        for (path, kind) in [
            (victim.clone(), ManagedKind::Limits),
            (climbing.clone(), ManagedKind::Limits),
            (linked.clone(), ManagedKind::Trusted),
            (misnamed.clone(), ManagedKind::Limits),
            (PathBuf::from("/etc/passwd"), ManagedKind::Limits),
        ] {
            db.record_managed_file(&path, kind.id()).unwrap();
        }

        let collected = unused_managed_files(WebServer::Nginx, &db, root.path()).unwrap();
        remove_planned_managed_files(&collected).unwrap();
        let unused = paths_of(&collected);

        for path in [&victim, &climbing, &misnamed] {
            assert!(!unused.contains(path), "{} was collected", path.display());
        }
        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            header,
            "the target was deleted"
        );
        assert_eq!(fs::read_to_string(&misnamed).unwrap(), header);
        assert!(
            !unused.contains(&PathBuf::from("/etc/passwd")),
            "{unused:#?}"
        );
    }

    /// A row that reaches this root's `conf.d` through a link in a
    /// directory another user owns is refused: they could point the link
    /// elsewhere between the check and the removal. The file itself is
    /// still collected, by its own resolved path.
    #[test]
    fn a_recorded_path_through_a_link_is_refused() {
        let root = root_with_a_conf_d();
        let conf_d = fs::canonicalize(root.path().join("conf.d")).unwrap();
        let generated = rate_limit_conf_path(&conf_d);
        fs::write(&generated, rate_limit_conf_body(10, 10)).unwrap();
        let theirs = tempfile::tempdir().unwrap();
        let link = theirs.path().join("link");
        std::os::unix::fs::symlink(&conf_d, &link).unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        db.record_managed_file(&rate_limit_conf_path(&link), ManagedKind::Limits.id())
            .unwrap();

        let unused = paths_of(&unused_managed_files(WebServer::Nginx, &db, root.path()).unwrap());

        assert!(
            unused.iter().all(|path| !path.starts_with(theirs.path())),
            "a path through the planted link was collected: {unused:#?}"
        );
        assert!(unused.contains(&generated), "{unused:#?}");
    }

    /// **Checked once, used through what was checked.** After the files
    /// to remove are resolved, the directory they were found in is swapped
    /// for a link to another one holding a file of the same name. The
    /// removal, and the restore after NGINX refuses the result, both
    /// happen in the directory that was checked; the other is untouched,
    /// and nothing is written into it.
    #[test]
    fn a_directory_swapped_after_the_check_is_not_the_one_used() {
        let root = root_with_a_conf_d();
        let conf_d = root.path().join("conf.d");
        let body = rate_limit_conf_body(10, 10);
        fs::write(rate_limit_conf_path(&conf_d), &body).unwrap();
        let victim = tempfile::tempdir().unwrap();
        let precious = victim.path().join("stop-bots-limits.conf");
        fs::write(&precious, "precious\n").unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();

        let unused = unused_managed_files(WebServer::Nginx, &db, root.path()).unwrap();
        let snapshot = Snapshot::of_apply(root.path(), [], &unused, []).unwrap();
        let checked = root.path().join("checked");
        fs::rename(&conf_d, &checked).unwrap();
        std::os::unix::fs::symlink(victim.path(), &conf_d).unwrap();

        assert_eq!(remove_planned_managed_files(&unused).unwrap(), 1);
        assert!(!rate_limit_conf_path(&checked).exists(), "not removed");
        assert_eq!(fs::read_to_string(&precious).unwrap(), "precious\n");
        fs::remove_file(&precious).unwrap();

        test_or_restore(WebServer::Nginx, &snapshot, &commands_that(false)).unwrap_err();

        assert_eq!(
            fs::read_to_string(rate_limit_conf_path(&checked)).unwrap(),
            body,
            "not put back where it was"
        );
        assert_eq!(
            fs::read_dir(victim.path()).unwrap().count(),
            0,
            "the restore wrote into the directory the link now points at"
        );
    }

    /// A FIFO where a generated file goes is not read (a read would wait
    /// for ever), and neither it nor a directory there is collected
    /// through the record.
    #[test]
    fn a_fifo_or_a_directory_at_a_recorded_name_is_neither_read_nor_collected() {
        let (old, new) = (root_with_a_conf_d(), root_with_a_conf_d());
        let fifo = rate_limit_conf_path(&new.path().join("conf.d"));
        crate::testing::mkfifo(&fifo);
        let old_conf_d = fs::canonicalize(old.path().join("conf.d")).unwrap();
        let dir = trusted_conf_path(&old_conf_d);
        fs::create_dir(&dir).unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        for (path, kind) in [
            (fifo.clone(), ManagedKind::Limits),
            (dir.clone(), ManagedKind::Trusted),
        ] {
            db.record_managed_file(&path, kind.id()).unwrap();
        }

        let changes = preview_all_sites(WebServer::Nginx, &db, new.path()).unwrap();
        let snapshot = Snapshot::take([fifo.clone()]).unwrap();
        let unused = paths_of(&unused_managed_files(WebServer::Nginx, &db, new.path()).unwrap());

        assert!(changes.is_empty(), "{changes:#?}");
        assert!(!unused.contains(&dir), "{unused:#?}");
        snapshot.restore().unwrap();
        assert!(fs::symlink_metadata(&fifo).is_ok(), "the FIFO was touched");
    }

    /// The record says stop-bots wrote a file there once; an operator's own
    /// file under the same name since is theirs.
    #[test]
    fn a_recorded_path_now_holding_someone_else_s_file_is_left_alone() {
        let (old, new) = (root_with_a_conf_d(), root_with_a_conf_d());
        let db = crate::db::Db::open_in_memory().unwrap();
        let path = rate_limit_conf_path(&old.path().join("conf.d"));
        written_and_recorded(&db, &path, &rate_limit_conf_body(10, 10));
        fs::write(
            &path,
            "limit_req_zone $binary_remote_addr zone=mine:1m rate=1r/s;\n",
        )
        .unwrap();

        let unused = paths_of(&unused_managed_files(WebServer::Nginx, &db, new.path()).unwrap());

        assert!(!unused.contains(&path), "unused: {unused:#?}");
    }

    /// The order is what keeps the config valid between two removals: a
    /// file that reads the trust file's variable goes before it.
    #[test]
    fn recorded_files_are_removed_in_dependency_order() {
        let root = root_with_a_conf_d();
        let db = crate::db::Db::open_in_memory().unwrap();
        let conf_d = root.path().join("conf.d");
        for (path, body) in [
            (
                trusted_conf_path(&conf_d),
                trusted_conf_body(&["192.0.2.1".into()], &[]).unwrap(),
            ),
            (
                untrusted_rate_limit_conf_path(&conf_d),
                untrusted_rate_limit_conf_body(1, 1),
            ),
        ] {
            written_and_recorded(&db, &path, &body);
        }

        let unused = paths_of(&unused_managed_files(WebServer::Nginx, &db, root.path()).unwrap());

        let at = |path: PathBuf| unused.iter().position(|p| p == &path).unwrap();
        assert!(
            at(untrusted_rate_limit_conf_path(&conf_d)) < at(trusted_conf_path(&conf_d)),
            "{unused:#?}"
        );
    }

    /// A row for a file that is gone, and is not about to be written, is
    /// dropped, so the record does not grow for ever.
    #[test]
    fn recording_forgets_files_that_are_gone() {
        let dir = root_with_a_conf_d();
        let db = crate::db::Db::open_in_memory().unwrap();
        let gone = rate_limit_conf_path(&dir.path().join("conf.d"));
        let coming = trusted_conf_path(&dir.path().join("conf.d"));
        db.record_managed_file(&gone, ManagedKind::Limits.id())
            .unwrap();

        record_managed_files(&db, &[(coming.clone(), String::new())]).unwrap();

        let recorded: Vec<PathBuf> = db
            .managed_files()
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(recorded, [coming], "the vanished file's row survived");
    }

    #[test]
    fn every_managed_kind_is_known_by_its_file_name_and_its_id() {
        let conf_d = Path::new("/etc/nginx/conf.d");
        for (path, kind) in [
            (rate_limit_conf_path(conf_d), ManagedKind::Limits),
            (
                untrusted_rate_limit_conf_path(conf_d),
                ManagedKind::UntrustedLimits,
            ),
            (trusted_conf_path(conf_d), ManagedKind::Trusted),
            (robots_txt_path(), ManagedKind::RobotsTxt),
        ] {
            assert_eq!(ManagedKind::of(&path), Some(kind), "{}", path.display());
            assert_eq!(ManagedKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(
            ManagedKind::of(Path::new("/etc/nginx/conf.d/default.conf")),
            None
        );
    }

    /// And a root inside the stock tree with no `conf.d` of its own keeps
    /// the stock one rather than inventing one. The container suite scans
    /// `/etc/nginx/sites-enabled`, which `include sites-enabled/*` globs:
    /// a `conf.d` directory created in there is something NGINX tries to
    /// `pread()` as a config file, and it refuses to start.
    #[test]
    fn a_root_inside_the_stock_tree_uses_the_stock_conf_d() {
        assert_eq!(
            conf_d_dir(Path::new("/etc/nginx/sites-enabled")),
            PathBuf::from(CONF_D_DIR)
        );
    }

    /// Any other root is its own tree: `batch --root <scratch>` read the
    /// host's own `/etc/nginx/conf.d/stop-bots-trusted.conf`, and an apply
    /// there would have rewritten or removed it.
    #[test]
    fn a_root_outside_the_stock_tree_never_reaches_out_of_itself() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(conf_d_dir(dir.path()), dir.path().join("conf.d"));
        // Nor by walking out of the stock tree with `..`.
        let sneaky = Path::new("/etc/nginx/../../tmp/scratch");
        assert_eq!(conf_d_dir(sneaky), sneaky.join("conf.d"));
    }

    /// A normal host install must be exactly as it was. `root` falls back
    /// to `/etc/nginx`, so this resolves to the stock path without the
    /// setting existing at all.
    #[test]
    fn conf_d_falls_back_to_the_stock_path_when_no_root_is_stored() {
        assert_eq!(
            conf_d_dir(&root(&crate::hostconf::HostConf::default(), None)),
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
        apply_block_for_site(WebServer::Nginx, &path, dir.path(), "a.example", &config).unwrap();

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
                text.contains(&condition(rule)),
                "{} should emit {:?}; text was:\n{text}",
                rule.label(),
                condition(rule)
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

    /// An NGINX tree in a temporary directory: `nginx.conf` and one site,
    /// each with the text given.
    fn nginx_tree(main: &str, site: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sites-enabled")).unwrap();
        fs::write(dir.path().join("nginx.conf"), main).unwrap();
        fs::write(dir.path().join("sites-enabled/site.conf"), site).unwrap();
        dir
    }

    const HTTP: &str = "http {\n    include sites-enabled/*;\n}\n";
    const TLS_SITE: &str =
        "server {\n    listen 443 ssl;\n    server_name a.example;\n    ssl_certificate x.pem;\n}\n";

    /// Either spelling turns HTTP/2 on, wherever in the tree it is; a
    /// comment or `off` does not; and with no `nginx.conf` to start from,
    /// nothing can be said.
    #[test]
    fn http2_is_found_wherever_the_tree_turns_it_on() {
        for (main, site, expected) in [
            (HTTP, TLS_SITE, Some(false)),
            ("http {\n    http2 on;\n}\n", TLS_SITE, Some(true)),
            (HTTP, &TLS_SITE.replace("ssl;", "ssl http2;"), Some(true)),
            (
                HTTP,
                &TLS_SITE.replace("ssl;", "ssl;\n    http2 on;"),
                Some(true),
            ),
            (
                HTTP,
                &TLS_SITE.replace("ssl;", "ssl;\n    # listen 443 ssl http2;"),
                Some(false),
            ),
            (
                HTTP,
                &TLS_SITE.replace("ssl;", "ssl;\n    http2 off;"),
                Some(false),
            ),
        ] {
            let tree = nginx_tree(main, site);
            assert_eq!(
                enables_http2(&tree.path().join("sites-enabled")),
                expected,
                "nginx.conf:\n{main}\nsite:\n{site}"
            );
        }
        let bare = tempfile::tempdir().unwrap();
        assert_eq!(enables_http2(bare.path()), None);
    }

    /// The HTTP/1.x rule where nothing speaks HTTP/2 passes `nginx -t` and
    /// then turns away every visitor, so it is refused; where something
    /// does, or the rule is only asked of a plain block, it is not.
    #[test]
    fn the_http_1x_rule_is_refused_only_where_nothing_speaks_http2() {
        let config = cfg_rules(&[RequestRule::Http1x]);
        let plain = TLS_SITE
            .replace("443 ssl", "80")
            .replace("    ssl_certificate x.pem;\n", "");
        for (site, http2_on, refused) in [
            (TLS_SITE.to_string(), false, true),
            (TLS_SITE.to_string(), true, false),
            (plain, false, false),
        ] {
            let main = if http2_on {
                "http {\n    http2 on;\n}\n"
            } else {
                HTTP
            };
            let tree = nginx_tree(main, &site);
            let why = refusal(&site, Path::new("site.conf"), tree.path(), |_| {
                Some(&config)
            });
            assert_eq!(why.is_some(), refused, "site:\n{site}\nrefusal: {why:?}");
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
            listens: Vec::new(),
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
            listens: Vec::new(),
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
            WebServer::Nginx,
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
    // ---- what uninstall takes out of a host that had Web Access ----

    /// `ServerCommands` whose test either passes or fails, without needing
    /// a real NGINX. `/bin/true` and `/bin/false` rather than a written
    /// script: fewer moving parts, and nothing to make executable.
    fn commands_that(pass: bool) -> ServerCommands {
        let program = if pass { "true" } else { "false" };
        ServerCommands {
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

    /// A console section an earlier release left in a site and the
    /// bot-blocking block live side by side: applying the block leaves the
    /// section alone, and each is found by its own markers.
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

    // ---- uninstall ----

    /// A site file with both kinds of block in it, inserted the way the
    /// product inserts them, in either order.
    fn with_both_blocks(site: &str, console_first: bool) -> String {
        let with_block = |content: &str| {
            let block = parse_server_blocks(content)
                .into_iter()
                .find(|b| b.is_tls)
                .unwrap();
            apply_block(content, &block, &cfg(&["BadBot"]))
        };
        let with_console = |content: &str| {
            with_console_location(content, "example.com", "/stop-bots/", &upstream()).unwrap()
        };
        if console_first {
            with_block(&with_console(site))
        } else {
            with_console(&with_block(site))
        }
    }

    /// "Back as it was" means the bytes: every insertion is taken back
    /// with the line break it added, whichever order they went in.
    #[test]
    fn taking_the_blocks_out_restores_the_file_byte_for_byte() {
        for console_first in [true, false] {
            let applied = with_both_blocks(TWO_BLOCK_SITE, console_first);
            assert!(applied.contains(BLOCK_BEGIN) && applied.contains(CONSOLE_BEGIN));

            assert_eq!(
                without_injected_blocks(&applied),
                TWO_BLOCK_SITE,
                "console first: {console_first}; applied was:\n{applied}"
            );
        }
    }

    /// Every `server` block, not just the first one that has a block.
    #[test]
    fn taking_the_blocks_out_covers_every_server_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, TWO_BLOCK_SITE).unwrap();
        apply_blocks_to_file(WebServer::Nginx, &path, dir.path(), &[], &cfg(&["BadBot"])).unwrap();
        let applied = fs::read_to_string(&path).unwrap();
        assert_eq!(applied.matches(BLOCK_BEGIN).count(), 2, "{applied}");

        assert_eq!(without_injected_blocks(&applied), TWO_BLOCK_SITE);
    }

    /// A file stop-bots never touched comes back unchanged — including one
    /// with a hand-written `if` that merely looks like ours.
    #[test]
    fn a_file_without_blocks_is_left_as_it_is() {
        let own = "server {\n    # BEGIN my stuff\n    if ($http_user_agent ~* \"x\") { return 403; }\n}\n";
        assert_eq!(without_injected_blocks(own), own);
    }

    fn site_root_with_blocks() -> (tempfile::TempDir, PathBuf) {
        let dir = root_with_a_conf_d();
        let path = dir.path().join("site.conf");
        fs::write(&path, with_both_blocks(TWO_BLOCK_SITE, false)).unwrap();
        (dir, path)
    }

    #[test]
    fn removing_everything_takes_out_blocks_and_generated_files() {
        let (dir, site) = site_root_with_blocks();
        let limits = rate_limit_conf_path(&dir.path().join("conf.d"));
        fs::write(&limits, rate_limit_conf_body(10, 10)).unwrap();

        let removal = remove_everything(
            WebServer::Nginx,
            dir.path(),
            &[held(&limits)],
            Some(&commands_that(true)),
            false,
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&site).unwrap(), TWO_BLOCK_SITE);
        assert!(!limits.exists(), "the generated file is still there");
        assert_eq!(removal.site_files, [site]);
        assert_eq!(removal.generated, [limits]);
        assert!(removal.reloaded);
    }

    /// The rule every apply keeps: a config NGINX refuses is put back,
    /// not left for the next reload to find.
    #[test]
    fn removing_everything_is_put_back_when_the_test_fails() {
        let (dir, site) = site_root_with_blocks();
        let before = fs::read_to_string(&site).unwrap();
        let limits = rate_limit_conf_path(&dir.path().join("conf.d"));
        fs::write(&limits, rate_limit_conf_body(10, 10)).unwrap();

        let err = remove_everything(
            WebServer::Nginx,
            dir.path(),
            &[held(&limits)],
            Some(&commands_that(false)),
            false,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("put back"), "was: {err:#}");
        assert_eq!(fs::read_to_string(&site).unwrap(), before);
        assert_eq!(
            fs::read_to_string(&limits).unwrap(),
            rate_limit_conf_body(10, 10)
        );
    }

    #[test]
    fn a_dry_run_of_removing_everything_changes_nothing() {
        let (dir, site) = site_root_with_blocks();
        let before = fs::read_to_string(&site).unwrap();

        let removal = remove_everything(
            WebServer::Nginx,
            dir.path(),
            &[],
            Some(&commands_that(true)),
            true,
        )
        .unwrap();

        assert_eq!(removal.site_files, std::slice::from_ref(&site));
        assert!(!removal.reloaded);
        assert_eq!(fs::read_to_string(&site).unwrap(), before);
    }

    /// The console's own site file, as earlier releases wrote it, is
    /// recognised by the first line every version wrote, and a file of the
    /// operator's at that path is not.
    #[test]
    fn the_console_site_file_is_known_by_its_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stop-bots-console.conf");
        for (first_line, ours) in [
            (
                "# Written by stop-bots (`Web Access` panel). Safe to edit or delete.",
                true,
            ),
            (
                &format!(
                    "# {} (`Web Access` panel). Safe to edit or delete.",
                    crate::generated::generated_by()
                )[..],
                true,
            ),
            ("server {", false),
        ] {
            fs::write(&path, format!("{first_line}\nserver {{\n}}\n")).unwrap();
            assert_eq!(is_console_site_file(&path), ours, "{first_line}");
        }
    }

    // ---- hostile strings, as NGINX will read them ----

    /// User agents a site that logs in JSON (`escape=json`) can put in
    /// front of an operator, each with a character NGINX's config reader
    /// or PCRE treats specially. The container suite checks the same list
    /// against a real NGINX.
    const HOSTILE_USER_AGENTS: [&str; 11] = [
        r"Scraper/2.1 a\|",
        r"Scraper/2.1 x\*",
        r"Scraper/2.1 Evil\(",
        r#"Scraper/2.1 say "hi""#,
        r#"Scraper/2.1 \"quoted\""#,
        r"Scraper/2.1 trailing\",
        r"Scraper/2.1 tab\t",
        r"Scraper/2.1 line\n",
        "Scraper/2.1 $foo",
        "Scraper/2.1 }",
        "Scraper/2.1 ;",
    ];

    /// The regex of every `$http_user_agent` test in `text`, as NGINX
    /// hands it to PCRE: found the way NGINX's reader finds the end of
    /// the quoted word, then unescaped the way it unescapes one.
    fn user_agent_regexes_as_nginx_reads_them(text: &str) -> Vec<String> {
        text.split("if ($http_user_agent ~* ")
            .skip(1)
            .map(|rest| {
                let end = closing_quote(rest).expect("the quoted regex is closed");
                assert!(
                    rest[end + 1..].starts_with(") {"),
                    "the regex's own quote does not end the condition:\n{rest}"
                );
                nginx_unquoted(&rest[1..end])
            })
            .collect()
    }

    /// The finding: the regex NGINX compiles for a blocked user agent is
    /// exactly the escaped literal that `pattern_problem` checked — for
    /// every one of these, not a match-all and not a broken group.
    #[test]
    fn a_hostile_blocked_user_agent_reaches_pcre_as_the_literal_that_was_checked() {
        for user_agent in HOSTILE_USER_AGENTS {
            let literal = crate::db::escape_regex_literal(user_agent);
            assert_eq!(pattern_problem(&literal), None, "{user_agent:?}");
            let text = block_text(&cfg(&[&literal])).unwrap();
            assert_eq!(
                user_agent_regexes_as_nginx_reads_them(&text),
                [literal],
                "{user_agent:?} was written as:\n{text}"
            );
        }
    }

    /// The same list as a stored host would have it, written at once: the
    /// exact bytes to hand `nginx -t`.
    #[test]
    fn hostile_user_agents_match_the_golden() {
        let literals: Vec<String> = HOSTILE_USER_AGENTS
            .iter()
            .map(|ua| crate::db::escape_regex_literal(ua))
            .collect();
        let text = block_text(&BlockConfig::new(literals, BlockResponse::Forbidden)).unwrap();
        crate::golden::assert_golden("nginx-block-hostile.conf", &text);
    }

    /// Trusted and exempted user agents are written into quoted strings
    /// too, and read back the same way.
    #[test]
    fn a_trusted_user_agent_reaches_pcre_as_the_literal_it_is() {
        let body = trusted_conf_body(&[], &["Pingdom.com_bot (x)".to_string()]).unwrap();
        let key = body
            .lines()
            .find(|line| line.trim_start().starts_with("\"~*"))
            .expect("a user-agent key")
            .trim();
        let end = closing_quote(key).unwrap();
        assert_eq!(
            nginx_unquoted(&key[1..end]),
            r"~*Pingdom\.com_bot \(x\)",
            "key was: {key}"
        );
    }

    /// Patterns PCRE refuses to compile: each would fail `nginx -t` and
    /// roll back every apply after the one that wrote it.
    #[test]
    fn a_pattern_nginx_would_not_compile_is_never_written() {
        for (pattern, why) in [
            ("Bot[z-a]x", "a range out of order"),
            ("Bot[a-Z]x", "a range out of order, by case"),
            (r"Bot[\d-z]x", "a range from a set"),
            ("Botx{2,1}", "quantifier numbers out of order"),
            ("Botx{99999}", "a count past PCRE's limit"),
            (
                "Botx{123456789012345678901234567890}",
                "a count past any limit",
            ),
            ("Bot[[:nope:]]x", "an unknown POSIX class"),
            ("Bot[[.a.]]x", "a collating element"),
            ("[:alpha:]Bot", "a POSIX class outside a class"),
        ] {
            assert_eq!(
                pattern_problem(pattern),
                Some(PatternProblem::Invalid),
                "{pattern:?} ({why})"
            );
        }
    }

    /// Constructs this check cannot be sure of, refused rather than
    /// guessed at.
    #[test]
    fn a_pattern_whose_meaning_depends_on_the_pcre_version_is_refused() {
        for (pattern, why) in [
            ("Botx{,5}", "a quantifier only PCRE2 10.43 reads as one"),
            ("Botx{ 5 }", "likewise, with spaces"),
            ("Bot^*x", "a repeated anchor"),
            (r"Bot\b+x", "a repeated word boundary"),
            (
                "Bot(?:abcdefgh){1000}",
                "a group PCRE would write out a thousand times",
            ),
            ("Bot(?i)x", "an inline flag"),
            ("Bot(?#c)x", "a comment"),
            (r"Bot[\p]x", "an escape with its own syntax, in a class"),
        ] {
            assert_eq!(
                pattern_problem(pattern),
                Some(PatternProblem::Unchecked),
                "{pattern:?} ({why})"
            );
        }
    }

    /// And the class and quantifier forms that are fine stay fine.
    #[test]
    fn well_formed_classes_and_quantifiers_are_kept() {
        for pattern in [
            "Bot[a-z]x",
            "Bot[Z-a]x",
            "Bot[a-z-]x",
            "Bot[-a]x",
            "Bot[]a]x",
            "Bot[^]a]x",
            "Bot[[:alpha:]]x",
            r"Bot[\d\s.-]x",
            r"Bot[\]]x",
            "Botx{2}",
            "Botx{2,}",
            "Botx{0,1}",
            "Bot{}",
            "Bot{a}",
            "Bot x{",
        ] {
            assert_eq!(pattern_problem(pattern), None, "{pattern:?} must be kept");
        }
    }

    /// A path exemption stored before it was validated: `/x\|` reached
    /// PCRE as `^(/x\\|)` and exempted every path; `/x\(` failed `nginx
    /// -t`. Now neither is written, and the valid one beside it is.
    #[test]
    fn a_stored_path_exemption_that_is_not_a_literal_path_is_left_out() {
        let text = block_text(&cfg_exempt(&["BadBot"], &[r"/x\|", r"/x\(", "/blog"])).unwrap();
        assert!(
            text.contains(r#"if ($stop_bots_path ~* "^(/blog)") {"#),
            "text was:\n{text}"
        );
        assert!(!text.contains("/x"), "text was:\n{text}");
    }

    /// A literal path is a literal: every regex character in one is
    /// escaped, and the escape reaches PCRE.
    #[test]
    fn a_path_exemption_reaches_pcre_as_a_literal_prefix() {
        let text = block_text(&cfg_exempt(&["BadBot"], &["/a.b+(c)"])).unwrap();
        let rest = text.split("if ($stop_bots_path ~* ").nth(1).unwrap();
        let end = closing_quote(rest).unwrap();
        assert_eq!(nginx_unquoted(&rest[1..end]), r"^(/a\.b\+\(c\))");
    }

    /// What the render leaves out is named, so that it is not left out in
    /// silence.
    #[test]
    fn skipped_entries_names_every_stored_row_the_render_leaves_out() {
        let db = crate::db::Db::open_in_memory().unwrap();
        assert!(skipped_entries(&db).unwrap().is_empty());

        db.upsert_site("a.example", "/tmp/a").unwrap();
        let site = db.list_sites().unwrap()[0].id.to_string();
        db.insert_unvalidated_row_for_tests(
            "site_path_exemptions",
            &[("site_id", &site), ("path", r"/x\|")],
        );
        db.insert_unvalidated_row_for_tests(
            "site_agent_exemptions",
            &[
                ("site_id", &site),
                ("path", "/dav/"),
                ("user_agent", r#"ok"http"#),
            ],
        );
        db.insert_unvalidated_row_for_tests(
            "blocked_user_agents",
            &[("user_agent", "ab"), ("blocked_at", "0")],
        );
        // Stored before backslashes were refused, and written exactly now:
        // not left out.
        db.insert_unvalidated_row_for_tests(
            "blocked_user_agents",
            &[("user_agent", r"Scraper/2.1 a\|"), ("blocked_at", "0")],
        );

        let skipped = skipped_entries(&db).unwrap();
        // Named as `{:?}` spells them, so a control character shows.
        for needle in [r"/x\\|", r#"ok\"http"#, r#""ab""#] {
            assert!(
                skipped.iter().any(|line| line.contains(needle)),
                "{needle} is not named: {skipped:#?}"
            );
        }
        assert_eq!(skipped.len(), 3, "{skipped:#?}");
    }

    /// The redirect block declares the name first; the HTTPS block is
    /// the one that says what answers.
    #[test]
    fn site_service_reads_every_block_that_declares_the_site() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("media.conf");
        std::fs::write(
            &config,
            "server {\n    listen 80;\n    server_name media.example.com;\n    \
             return 301 https://$host$request_uri;\n}\n\
             server {\n    listen 443 ssl;\n    server_name media.example.com www.media.example.com;\n    \
             location / {\n        proxy_pass http://jellyfin:8096;\n    }\n}\n\
             server {\n    listen 443 ssl;\n    server_name photos.example.com;\n    \
             location / {\n        proxy_pass http://immich:2283;\n    }\n}\n",
        )
        .unwrap();

        let cases = [
            (
                "media.example.com",
                Some(crate::services::Service::Jellyfin),
            ),
            ("photos.example.com", Some(crate::services::Service::Immich)),
            ("elsewhere.example.com", None),
        ];
        for (name, expected) in cases {
            assert_eq!(site_service(&config, name), expected, "{name}");
        }
    }

    #[test]
    fn site_service_of_an_unreadable_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            site_service(&dir.path().join("missing.conf"), "a.example.com"),
            None
        );
    }

    /// Every file the tree's `access_log`s name, once each, from
    /// `nginx.conf` down, whatever the root is inside it; nothing for
    /// `off`, syslog, a variable, or a comment; a relative path under the
    /// directory `nginx.conf` is in.
    #[test]
    fn the_logs_the_config_names_are_found_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path();
        let files = [
            (
                "nginx.conf",
                "http {\n    access_log /var/log/nginx/access.log;\n    \
                 include sites-enabled/*;\n}\n",
            ),
            (
                "sites-available/shop",
                "server {\n    server_name shop.example;\n    \
                 access_log \"/srv/shop/access.log\" combined buffer=32k flush=5s;\n    \
                 location /health { access_log off; }\n    \
                 # access_log /srv/shop/commented.log;\n}\n",
            ),
            (
                "sites-available/blog",
                "server {\n    server_name blog.example;\n    \
                 access_log syslog:server=unix:/dev/log combined;\n    \
                 access_log /var/log/nginx/$host.log;\n    \
                 access_log logs/blog.log;\n    \
                 access_log /srv/shop/access.log;\n}\n",
            ),
        ];
        for (name, text) in files {
            fs::create_dir_all(top.join(name).parent().unwrap()).unwrap();
            fs::write(top.join(name), text).unwrap();
        }

        let expected = [
            PathBuf::from("/var/log/nginx/access.log"),
            top.join("logs/blog.log"),
            PathBuf::from("/srv/shop/access.log"),
        ];
        for root in [top.to_path_buf(), top.join("sites-available")] {
            assert_eq!(access_logs(&root), expected, "from {}", root.display());
        }
    }

    /// With no `nginx.conf` at or above it, the root's own files are read.
    #[test]
    fn a_root_without_nginx_conf_is_read_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("site.conf"),
            "server { server_name a.example; access_log /srv/a/access.log; }\n",
        )
        .unwrap();

        assert_eq!(
            access_logs(dir.path()),
            [PathBuf::from("/srv/a/access.log")]
        );
    }
}
