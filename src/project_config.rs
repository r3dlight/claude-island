// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Per-project configuration: a `.claude-island.toml` file at the project
// root, applied like command-line flags, with direnv-style approval. A
// cloned repository must not be able to grant itself rights: the file is
// refused until `claude-island allow` records its content hash in
// ~/.config/claude-island/approved.list (a path the sandbox cannot write,
// covered by a canary), and any later change requires a re-approval.
//
// Supported format (flat, single-line values only):
//   envs = ["rust", "node"]
//   auto = true
//   ro = false
//   noexec = false
//   proxy = true
//   serve = true
//   ports = [9443, 9444]
//   allow = ["api.example.dev"]

use std::fs;
use std::path::Path;

pub const FILE_NAME: &str = ".claude-island.toml";
const APPROVED_LIST: &str = ".config/claude-island/approved.list";

#[derive(Default)]
pub struct ProjectConfig {
    pub envs: Vec<String>,
    pub auto: bool,
    pub ro: bool,
    pub noexec: bool,
    pub proxy: bool,
    pub serve: bool,
    pub ports: Vec<u16>,
    pub allow: Vec<String>,
}

fn parse_bool(v: &str, line: usize) -> Result<bool, String> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("line {line}: expected true or false, got {v}")),
    }
}

fn parse_str_array(v: &str, line: usize) -> Result<Vec<String>, String> {
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(format!("line {line}: expected a [\"...\"] array"))?;
    let items: Vec<String> = inner
        .split('"')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect();
    if items.is_empty() && !inner.trim().is_empty() {
        return Err(format!("line {line}: expected double-quoted strings"));
    }
    Ok(items)
}

fn parse_port_array(v: &str, line: usize) -> Result<Vec<u16>, String> {
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(format!("line {line}: expected a [port, ...] array"))?;
    inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u16>().map_err(|_| format!("line {line}: invalid port: {s}")))
        .collect()
}

/// Parses the restricted format above. Unknown keys are an error (fail
/// closed: a typo must not silently drop a setting).
pub fn parse(content: &str) -> Result<ProjectConfig, String> {
    let mut c = ProjectConfig::default();
    for (i, raw) in content.lines().enumerate() {
        let n = i + 1;
        // No '#' occurs inside our quoted values (domains, env names).
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(format!("line {n}: expected key = value"))?;
        let (key, value) = (key.trim(), value.trim());
        match key {
            "auto" => c.auto = parse_bool(value, n)?,
            "ro" => c.ro = parse_bool(value, n)?,
            "noexec" => c.noexec = parse_bool(value, n)?,
            "proxy" => c.proxy = parse_bool(value, n)?,
            "serve" => c.serve = parse_bool(value, n)?,
            "envs" => c.envs = parse_str_array(value, n)?,
            "allow" => c.allow = parse_str_array(value, n)?,
            "ports" => c.ports = parse_port_array(value, n)?,
            _ => return Err(format!("line {n}: unknown key: {key}")),
        }
    }
    Ok(c)
}

/// FNV-1a 64 of the file content, as 16 hex chars.
fn content_hash(content: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in content.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// One approval entry per project path: "hash16 /project/path".
fn approvals(home: &Path) -> Vec<(String, String)> {
    let Ok(content) = fs::read_to_string(home.join(APPROVED_LIST)) else {
        return vec![];
    };
    content
        .lines()
        .filter_map(|l| {
            let (h, p) = l.split_once(' ')?;
            Some((h.to_string(), p.to_string()))
        })
        .collect()
}

pub fn is_approved(home: &Path, project: &Path, content: &str) -> bool {
    let hash = content_hash(content);
    let project = project.to_string_lossy();
    approvals(home).iter().any(|(h, p)| *h == hash && *p == project)
}

/// Records (or replaces) the approval for this project.
pub fn approve(home: &Path, project: &Path, content: &str) -> Result<(), String> {
    let project_str = project.to_string_lossy().to_string();
    let mut entries: Vec<(String, String)> = approvals(home)
        .into_iter()
        .filter(|(_, p)| *p != project_str)
        .collect();
    entries.push((content_hash(content), project_str));
    let path = home.join(APPROVED_LIST);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    let body: String = entries.iter().map(|(h, p)| format!("{h} {p}\n")).collect();
    fs::write(&path, body).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// A short human summary of what the file asks for.
pub fn summary(c: &ProjectConfig) -> String {
    let mut parts: Vec<String> = vec![];
    if !c.envs.is_empty() {
        parts.push(format!("envs: {}", c.envs.join(", ")));
    }
    for (name, on) in [
        ("auto", c.auto),
        ("ro", c.ro),
        ("noexec", c.noexec),
        ("proxy", c.proxy),
        ("serve", c.serve),
    ] {
        if on {
            parts.push(name.to_string());
        }
    }
    if !c.ports.is_empty() {
        let ports: Vec<String> = c.ports.iter().map(|p| p.to_string()).collect();
        parts.push(format!("ports: {}", ports.join(", ")));
    }
    if !c.allow.is_empty() {
        parts.push(format!("allow: {}", c.allow.join(", ")));
    }
    if parts.is_empty() {
        "empty configuration".to_string()
    } else {
        parts.join("; ")
    }
}
