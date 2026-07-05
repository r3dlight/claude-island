// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// `claude-island explain`: human-readable summary of what a profile grants,
// computed without side effects (nothing is written, no proxy is started).
//
// Snippets are our own generated format, so a small line-based extractor is
// enough to pull the [[path_beneath]] rules out of the embedded TOML.

/// One filesystem rule: access tokens and the paths they apply to.
pub struct PathRule {
    pub access: Vec<String>,
    pub parents: Vec<String>,
}

/// All double-quoted strings of a line.
fn quoted_strings(line: &str) -> Vec<String> {
    line.split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

/// Extracts the [[path_beneath]] rules from a snippet.
pub fn path_rules(toml: &str) -> Vec<PathRule> {
    let mut rules: Vec<PathRule> = vec![];
    let mut current: Option<PathRule> = None;
    let mut in_parent_array = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if t.starts_with("[[") {
            if let Some(r) = current.take() {
                rules.push(r);
            }
            in_parent_array = false;
            if t == "[[path_beneath]]" {
                current = Some(PathRule {
                    access: vec![],
                    parents: vec![],
                });
            }
            continue;
        }
        let Some(rule) = current.as_mut() else {
            continue;
        };
        if t.starts_with("allowed_access") {
            rule.access = quoted_strings(t);
        } else if t.starts_with("parent") || in_parent_array {
            rule.parents.extend(quoted_strings(t));
            in_parent_array = !t.ends_with(']');
        }
    }
    if let Some(r) = current {
        rules.push(r);
    }
    rules.retain(|r| !r.parents.is_empty());
    rules
}

/// Maps a set of access tokens to a short human label. The order of LABELS
/// is the display order.
pub const LABELS: &[&str] = &["rw + exec", "rw", "read + exec", "read-only"];

pub fn label(access: &[String]) -> &'static str {
    let has = |t: &str| access.iter().any(|a| a == t);
    let rw = has("abi.read_write");
    let rx = has("abi.read_execute");
    match (rw, rx) {
        (true, true) => "rw + exec",
        (true, false) => "rw",
        (false, true) => "read + exec",
        // Individual read rights (read_file, read_dir, refer).
        (false, false) => "read-only",
    }
}
