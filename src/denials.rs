// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Structured denials: run a command inside the sandbox under strace, then
// turn every syscall that failed with EACCES/EPERM (the Landlock denial
// errnos) into a structured record. This is the privilege-free path: the
// kernel Landlock audit log (ABI 7) needs root/auditd to read, whereas
// strace traces our own process tree.

/// One deduplicated denial.
pub struct Denial {
    /// read | write | exec | connect | bind | other
    pub kind: String,
    /// filesystem path, or "IP:PORT" for network denials
    pub target: String,
    /// the syscall that was denied (openat, connect, ...)
    pub syscall: String,
    /// EACCES or EPERM
    pub errno: String,
    pub count: u32,
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

impl Denial {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"kind\":\"{}\",\"target\":\"{}\",\"syscall\":\"{}\",\"errno\":\"{}\",\"count\":{}}}",
            json_escape(&self.kind),
            json_escape(&self.target),
            json_escape(&self.syscall),
            json_escape(&self.errno),
            self.count
        )
    }
}

/// Extracts the first double-quoted substring of a line.
fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parses `sin_port=htons(PORT)` and `inet_addr("IP")` (or inet6) from a
/// network syscall line.
fn parse_sockaddr(line: &str) -> Option<String> {
    let port = line
        .split("sin_port=htons(")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .or_else(|| {
            line.split("sin6_port=htons(")
                .nth(1)
                .and_then(|s| s.split(')').next())
        })?;
    let addr = line
        .split("inet_addr(\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .or_else(|| {
            line.split("inet_pton(AF_INET6, \"")
                .nth(1)
                .and_then(|s| s.split('"').next())
        })
        .unwrap_or("?");
    Some(format!("{addr}:{port}"))
}

/// Classifies a filesystem syscall into read/write/exec and pulls the path.
fn classify_fs(syscall: &str, line: &str) -> Option<(String, String)> {
    let path = first_quoted(line)?;
    let kind = match syscall {
        "execve" | "execveat" => "exec",
        "unlink" | "unlinkat" | "rename" | "renameat" | "renameat2" | "mkdir" | "mkdirat"
        | "rmdir" | "chmod" | "fchmodat" | "chown" | "fchownat" | "truncate" | "link"
        | "linkat" | "symlink" | "symlinkat" | "mknod" | "mknodat" | "utimensat" => "write",
        // Write if any write-ish flag is present, else read.
        "openat" | "open"
            if line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC") =>
        {
            "write"
        }
        "openat" | "open" => "read",
        _ => "read", // stat, access, readlink, getdents, statx, ...
    };
    Some((kind.to_string(), path))
}

/// Parses strace output (with -y for fd paths) into deduplicated denials,
/// most frequent first.
pub fn parse(strace_output: &str) -> Vec<Denial> {
    let mut map: std::collections::BTreeMap<(String, String), (String, String, u32)> =
        Default::default();

    for line in strace_output.lines() {
        let errno = if line.contains("= -1 EACCES") {
            "EACCES"
        } else if line.contains("= -1 EPERM") {
            "EPERM"
        } else {
            continue;
        };

        // Syscall name: the identifier just before the first '('.
        let Some(paren) = line.find('(') else {
            continue;
        };
        let before = &line[..paren];
        let syscall = before
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_string();
        if syscall.is_empty() {
            continue;
        }

        let (kind, target) = match syscall.as_str() {
            "connect" => match parse_sockaddr(line) {
                Some(t) => ("connect".to_string(), t),
                None => continue,
            },
            "bind" => match parse_sockaddr(line) {
                Some(t) => ("bind".to_string(), t),
                None => continue,
            },
            "sendto" | "sendmsg" => match parse_sockaddr(line) {
                Some(t) => ("connect".to_string(), t),
                None => continue,
            },
            _ => match classify_fs(&syscall, line) {
                Some(v) => v,
                None => continue,
            },
        };

        let entry = map.entry((kind.clone(), target.clone())).or_insert((
            syscall.clone(),
            errno.to_string(),
            0,
        ));
        entry.2 += 1;
    }

    let mut out: Vec<Denial> = map
        .into_iter()
        .map(|((kind, target), (syscall, errno, count))| Denial {
            kind,
            target,
            syscall,
            errno,
            count,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.target.cmp(&b.target)));
    out
}
