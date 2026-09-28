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

//! Unified diffs of two texts, for "show me what Apply everything would
//! change" before it changes it.
//!
//! **Patience diff, not the textbook LCS.** The inputs are NGINX site files
//! (hundreds of lines) and firewall scripts, and a firewall script on a host
//! with reputation feeds is 44,000 lines. A quadratic LCS table over two of
//! those is two billion cells. Patience diff anchors on lines that occur
//! exactly once on each side — which is almost every line of a firewall
//! script, since each carries its own address — and only falls back to a
//! small LCS table between anchors, where what is left is short runs of
//! repeated lines like `}`.
//!
//! Written here rather than taken from a crate because it is about a
//! hundred lines and is the only diffing this project does.

use std::collections::HashMap;
use std::ops::Range;

/// Lines of context around each change, as `diff -u` uses.
pub const CONTEXT: usize = 3;

/// Between two anchors, a stretch this size or smaller is diffed with an
/// exact LCS table; a bigger one is reported as "all of this replaced by
/// all of that". The product of the two lengths, so the table stays under
/// a few megabytes whatever the inputs.
const LCS_CELLS_MAX: usize = 250_000;

/// One step of an edit script: indices into the old and new line lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Equal(usize, usize),
    Delete(usize),
    Insert(usize),
}

/// A unified diff turning `old` into `new`, with `old_label` and
/// `new_label` on the `---`/`+++` lines. Empty when the two are equal.
///
/// `None` on either side is a file that does not exist: it diffs as empty,
/// and its label says so, the way `diff -N` would show a created or
/// removed file.
pub fn unified(old: Option<&str>, new: Option<&str>, old_label: &str, new_label: &str) -> String {
    if old == new {
        return String::new();
    }
    let a: Vec<&str> = old.map(|t| t.lines().collect()).unwrap_or_default();
    let b: Vec<&str> = new.map(|t| t.lines().collect()).unwrap_or_default();
    let ops = diff_lines(&a, &b);
    if ops.iter().all(|op| matches!(op, Op::Equal(..))) {
        // Differs only in a trailing newline, which `lines()` drops. Rare
        // enough to say in words rather than model.
        return format!("--- {old_label}\n+++ {new_label}\n(differs only in the final newline)\n");
    }

    let mut out = format!(
        "--- {}\n+++ {}\n",
        labelled(old_label, old.is_some()),
        labelled(new_label, new.is_some())
    );
    for hunk in hunks(&ops) {
        write_hunk(&mut out, &ops[hunk], &a, &b);
    }
    out
}

fn labelled(label: &str, exists: bool) -> String {
    if exists {
        label.to_string()
    } else {
        format!("{label} (does not exist)")
    }
}

/// The edit script from `a` to `b`.
fn diff_lines(a: &[&str], b: &[&str]) -> Vec<Op> {
    let mut ops = Vec::with_capacity(a.len().max(b.len()));
    diff_range(a, b, 0..a.len(), 0..b.len(), &mut ops);
    ops
}

fn diff_range(
    a: &[&str],
    b: &[&str],
    mut ar: Range<usize>,
    mut br: Range<usize>,
    ops: &mut Vec<Op>,
) {
    while !ar.is_empty() && !br.is_empty() && a[ar.start] == b[br.start] {
        ops.push(Op::Equal(ar.start, br.start));
        ar.start += 1;
        br.start += 1;
    }
    let mut suffix = 0;
    while !ar.is_empty() && !br.is_empty() && a[ar.end - 1] == b[br.end - 1] {
        ar.end -= 1;
        br.end -= 1;
        suffix += 1;
    }

    if ar.is_empty() || br.is_empty() {
        ops.extend(ar.clone().map(Op::Delete));
        ops.extend(br.clone().map(Op::Insert));
    } else {
        let anchors = unique_anchors(a, b, ar.clone(), br.clone());
        if anchors.is_empty() {
            if ar.len() * br.len() <= LCS_CELLS_MAX {
                lcs(a, b, ar.clone(), br.clone(), ops);
            } else {
                ops.extend(ar.clone().map(Op::Delete));
                ops.extend(br.clone().map(Op::Insert));
            }
        } else {
            let (mut pa, mut pb) = (ar.start, br.start);
            for (ai, bi) in anchors {
                diff_range(a, b, pa..ai, pb..bi, ops);
                ops.push(Op::Equal(ai, bi));
                pa = ai + 1;
                pb = bi + 1;
            }
            diff_range(a, b, pa..ar.end, pb..br.end, ops);
        }
    }

    ops.extend((0..suffix).map(|k| Op::Equal(ar.end + k, br.end + k)));
}

/// Lines that occur exactly once in each range, paired up, reduced to the
/// longest run that is increasing on both sides — patience diff's anchors.
fn unique_anchors(
    a: &[&str],
    b: &[&str],
    ar: Range<usize>,
    br: Range<usize>,
) -> Vec<(usize, usize)> {
    // (count in a, count in b, index in a, index in b)
    let mut seen: HashMap<&str, (u32, u32, usize, usize)> = HashMap::new();
    for i in ar.clone() {
        let entry = seen.entry(a[i]).or_insert((0, 0, i, 0));
        entry.0 += 1;
    }
    for j in br {
        if let Some(entry) = seen.get_mut(b[j]) {
            entry.1 += 1;
            entry.3 = j;
        }
    }
    let mut pairs: Vec<(usize, usize)> = seen
        .into_values()
        .filter(|&(ca, cb, _, _)| ca == 1 && cb == 1)
        .map(|(_, _, i, j)| (i, j))
        .collect();
    pairs.sort_unstable();
    longest_increasing(&pairs)
}

/// The longest subsequence of `pairs` (sorted by the first index) whose
/// second index is increasing, by patience sorting.
fn longest_increasing(pairs: &[(usize, usize)]) -> Vec<(usize, usize)> {
    // `tails[k]` is the index into `pairs` of the smallest tail of an
    // increasing run of length k + 1; `back[i]` is the element before
    // `pairs[i]` in the best run ending at it.
    let mut tails: Vec<usize> = Vec::new();
    let mut back: Vec<Option<usize>> = vec![None; pairs.len()];
    for (i, &(_, j)) in pairs.iter().enumerate() {
        let k = tails.partition_point(|&t| pairs[t].1 < j);
        back[i] = k.checked_sub(1).map(|k| tails[k]);
        if k == tails.len() {
            tails.push(i);
        } else {
            tails[k] = i;
        }
    }
    let mut run = Vec::with_capacity(tails.len());
    let mut at = tails.last().copied();
    while let Some(i) = at {
        run.push(pairs[i]);
        at = back[i];
    }
    run.reverse();
    run
}

/// An exact diff of two short ranges, by the longest common subsequence.
fn lcs(a: &[&str], b: &[&str], ar: Range<usize>, br: Range<usize>, ops: &mut Vec<Op>) {
    let (n, m) = (ar.len(), br.len());
    // `table[i][j]`: LCS length of a[ar.start + i..] and b[br.start + j..].
    let mut table = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[at(i, j)] = if a[ar.start + i] == b[br.start + j] {
                table[at(i + 1, j + 1)] + 1
            } else {
                table[at(i + 1, j)].max(table[at(i, j + 1)])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[ar.start + i] == b[br.start + j] {
            ops.push(Op::Equal(ar.start + i, br.start + j));
            i += 1;
            j += 1;
        } else if table[at(i + 1, j)] >= table[at(i, j + 1)] {
            ops.push(Op::Delete(ar.start + i));
            i += 1;
        } else {
            ops.push(Op::Insert(br.start + j));
            j += 1;
        }
    }
    ops.extend((ar.start + i..ar.end).map(Op::Delete));
    ops.extend((br.start + j..br.end).map(Op::Insert));
}

/// Ranges of `ops` that make up each hunk: every change with up to
/// [`CONTEXT`] equal lines either side, merging changes whose context
/// would touch.
fn hunks(ops: &[Op]) -> Vec<Range<usize>> {
    let changes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Op::Equal(..)))
        .map(|(i, _)| i)
        .collect();
    let mut hunks: Vec<Range<usize>> = Vec::new();
    for i in changes {
        let start = i.saturating_sub(CONTEXT);
        let end = (i + 1 + CONTEXT).min(ops.len());
        match hunks.last_mut() {
            Some(last) if start <= last.end => last.end = end,
            _ => hunks.push(start..end),
        }
    }
    hunks
}

fn write_hunk(out: &mut String, ops: &[Op], a: &[&str], b: &[&str]) {
    use std::fmt::Write as _;

    // Where the hunk starts on each side: the first index that side has in
    // it, or, for a side with no lines in the hunk, the line before it.
    let a_start = ops.iter().find_map(|op| match op {
        Op::Equal(i, _) | Op::Delete(i) => Some(*i),
        Op::Insert(_) => None,
    });
    let b_start = ops.iter().find_map(|op| match op {
        Op::Equal(_, j) | Op::Insert(j) => Some(*j),
        Op::Delete(_) => None,
    });
    let a_len = ops.iter().filter(|op| !matches!(op, Op::Insert(_))).count();
    let b_len = ops.iter().filter(|op| !matches!(op, Op::Delete(_))).count();
    // With context around every change, a side has no lines in a hunk
    // only when that whole file is empty, which `diff -u` writes as `0,0`.
    let range = |start: Option<usize>, len: usize| match start {
        Some(start) => format!("{},{len}", start + 1),
        None => "0,0".to_string(),
    };
    let _ = writeln!(
        out,
        "@@ -{} +{} @@",
        range(a_start, a_len),
        range(b_start, b_len)
    );
    for op in ops {
        let _ = match op {
            Op::Equal(i, _) => writeln!(out, " {}", a[*i]),
            Op::Delete(i) => writeln!(out, "-{}", a[*i]),
            Op::Insert(j) => writeln!(out, "+{}", b[*j]),
        };
    }
}

/// How many lines a diff adds and removes, from its text — for a summary
/// line that should not have to re-run the diff.
pub fn counts(diff: &str) -> (usize, usize) {
    diff.lines()
        .filter(|line| !line.starts_with("+++") && !line.starts_with("---"))
        .fold((0, 0), |(added, removed), line| {
            match line.as_bytes().first() {
                Some(b'+') => (added + 1, removed),
                Some(b'-') => (added, removed + 1),
                _ => (added, removed),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Applies a unified diff produced by [`unified`] to `old`, as `patch`
    /// would — the one check that proves the hunk headers and bodies are
    /// right, rather than merely plausible.
    fn patch(old: &str, diff: &str) -> String {
        let old: Vec<&str> = old.lines().collect();
        let mut out: Vec<String> = Vec::new();
        let mut next = 0; // next line of `old` not yet copied
        for line in diff.lines().skip(2) {
            if let Some(header) = line.strip_prefix("@@ -") {
                let start: usize = header.split([',', ' ']).next().unwrap().parse().unwrap();
                let len: usize = header.split([',', ' ']).nth(1).unwrap().parse().unwrap();
                // A zero-length side names the line it comes after.
                let begin = if len == 0 { start } else { start - 1 };
                out.extend(old[next..begin].iter().map(|l| l.to_string()));
                next = begin;
            } else if let Some(kept) = line.strip_prefix(' ') {
                assert_eq!(old[next], kept, "context line does not match");
                out.push(kept.to_string());
                next += 1;
            } else if let Some(removed) = line.strip_prefix('-') {
                assert_eq!(old[next], removed, "removed line does not match");
                next += 1;
            } else if let Some(added) = line.strip_prefix('+') {
                out.push(added.to_string());
            }
        }
        out.extend(old[next..].iter().map(|l| l.to_string()));
        out.join("\n")
    }

    fn lines(range: Range<u32>) -> String {
        range
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn equal_texts_have_no_diff() {
        assert_eq!(unified(Some("a\nb\n"), Some("a\nb\n"), "x", "y"), "");
    }

    /// The whole claim of a diff: applying it gets you the new text. A
    /// table of the shapes that trip hunk arithmetic up — a change at
    /// either end, two changes far apart, a pure insertion, repeated lines
    /// with no unique anchor.
    #[test]
    fn every_diff_patches_the_old_text_into_the_new() {
        let cases: Vec<(&str, String, String)> = vec![
            (
                "change in the middle",
                lines(0..20),
                lines(0..20).replace("line 10", "ten"),
            ),
            (
                "change on the first line",
                lines(0..10),
                lines(0..10).replace("line 0", "zero"),
            ),
            (
                "change on the last line",
                lines(0..10),
                lines(0..10).replace("line 9", "nine"),
            ),
            (
                "two changes far apart",
                lines(0..40),
                lines(0..40)
                    .replace("line 3", "three")
                    .replace("line 35", "35"),
            ),
            (
                "insertion",
                lines(0..10),
                lines(0..10).replace("line 5", "line 5\nnew"),
            ),
            (
                "deletion",
                lines(0..10),
                lines(0..10).replace("line 5\n", ""),
            ),
            ("from nothing", String::new(), lines(0..5)),
            ("to nothing", lines(0..5), String::new()),
            (
                "repeated lines",
                "}\n}\n}\nx\n}\n}".to_string(),
                "}\n}\ny\n}\n}\n}".to_string(),
            ),
        ];
        for (what, old, new) in cases {
            let diff = unified(Some(&old), Some(&new), "old", "new");
            assert!(!diff.is_empty(), "{what}: no diff");
            assert_eq!(patch(&old, &diff), new, "{what}: the diff was\n{diff}");
        }
    }

    #[test]
    fn hunks_carry_three_lines_of_context_and_the_diff_u_header() {
        let diff = unified(
            Some(&lines(0..20)),
            Some(&lines(0..20).replace("line 10", "ten")),
            "a.conf",
            "a.conf (after)",
        );
        assert_eq!(
            diff,
            "--- a.conf\n+++ a.conf (after)\n@@ -8,7 +8,7 @@\n line 7\n line 8\n line 9\n\
             -line 10\n+ten\n line 11\n line 12\n line 13\n"
        );
    }

    #[test]
    fn a_missing_file_is_labelled_as_such() {
        let diff = unified(None, Some("new\n"), "robots.txt", "robots.txt");
        assert!(
            diff.starts_with("--- robots.txt (does not exist)\n+++ robots.txt\n"),
            "{diff}"
        );
        assert!(diff.contains("+new"), "{diff}");
    }

    /// The size this exists for. A quadratic diff of two 44,000-line
    /// scripts would not finish inside the test budget; this has to.
    #[test]
    fn a_firewall_sized_diff_is_fast() {
        let old: String = (0..44_000)
            .map(|i| format!("\t10.{}.{}.{},\n", i / 65536, (i / 256) % 256, i % 256))
            .collect();
        let new = old
            .replace("\t10.0.5.5,\n", "")
            .replace("\t10.0.9.9,\n", "\t10.0.9.9,\n\t192.0.2.1,\n");
        let started = std::time::Instant::now();
        let diff = unified(Some(&old), Some(&new), "old", "new");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(250),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(counts(&diff), (1, 1), "the diff was\n{diff}");
    }

    #[test]
    fn counts_ignore_the_file_header() {
        let diff = unified(Some("a\nb\n"), Some("a\nc\nd\n"), "x", "y");
        assert_eq!(counts(&diff), (2, 1), "{diff}");
    }
}
