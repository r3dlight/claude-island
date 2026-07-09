// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Session report: summarize the outbound-audit log into "what tried to leave,
// where, and was it blocked". Pure parsing over the log lines written by the
// broker (`=== session start ===` markers, `host METHOD path body=..`, and
// `!!! LEAK BLOCKED/ALLOWED` / `!!! L7 DENIED` events), so it is unit-testable.

use std::collections::BTreeMap;

/// One aggregated leak attempt (blocked or allowed), with an occurrence count.
pub struct LeakEvent {
    pub blocked: bool,
    pub what: String,
    pub host: String,
    pub count: usize,
}

/// One aggregated L7 method/path denial.
pub struct L7Event {
    pub request: String,
    pub host: String,
    pub count: usize,
}

pub struct Report {
    pub requests: usize,
    pub hosts: Vec<String>,
    pub leaks: Vec<LeakEvent>,
    pub l7: Vec<L7Event>,
}

/// Strips the `[timestamp] ` prefix from a log line.
fn strip_ts(line: &str) -> &str {
    match line.find("] ") {
        Some(i) => &line[i + 2..],
        None => line,
    }
}

/// Splits `"<what> -> <host> (body ..)"` into (what, host), tolerating a
/// missing trailing `(body ..)`.
fn split_arrow(s: &str) -> Option<(String, String)> {
    let (what, rest) = s.rsplit_once(" -> ")?;
    let host = rest.split(" (body").next().unwrap_or(rest).trim();
    Some((what.trim().to_string(), host.to_string()))
}

/// Parses the audit log. With `last_session`, only the lines after the final
/// `=== session start ===` marker are considered.
pub fn parse(log: &str, last_session: bool) -> Report {
    let body = if last_session {
        match log.rfind("=== session start ===") {
            Some(i) => &log[i..],
            None => log,
        }
    } else {
        log
    };

    let mut requests = 0usize;
    let mut hosts: BTreeMap<String, ()> = BTreeMap::new();
    let mut leaks: BTreeMap<(bool, String, String), usize> = BTreeMap::new();
    let mut l7: BTreeMap<(String, String), usize> = BTreeMap::new();

    for line in body.lines() {
        let line = strip_ts(line.trim());
        if line.starts_with("=== session") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("!!! LEAK BLOCKED: ") {
            if let Some((what, host)) = split_arrow(rest) {
                hosts.insert(host.clone(), ());
                *leaks.entry((true, what, host)).or_insert(0) += 1;
            }
        } else if let Some(rest) = line.strip_prefix("!!! LEAK ALLOWED: ") {
            if let Some((what, host)) = split_arrow(rest) {
                hosts.insert(host.clone(), ());
                *leaks.entry((false, what, host)).or_insert(0) += 1;
            }
        } else if let Some(rest) = line.strip_prefix("!!! L7 DENIED: ") {
            if let Some((req, host)) = split_arrow(rest) {
                hosts.insert(host.clone(), ());
                *l7.entry((req, host)).or_insert(0) += 1;
            }
        } else if line.contains(" body=") {
            requests += 1;
            if let Some(host) = line.split_whitespace().next() {
                hosts.insert(host.to_string(), ());
            }
        }
    }

    Report {
        requests,
        hosts: hosts.into_keys().collect(),
        leaks: leaks
            .into_iter()
            .map(|((blocked, what, host), count)| LeakEvent {
                blocked,
                what,
                host,
                count,
            })
            .collect(),
        l7: l7
            .into_iter()
            .map(|((request, host), count)| L7Event {
                request,
                host,
                count,
            })
            .collect(),
    }
}

/// Renders the report as human-readable text.
pub fn render(r: &Report, scope: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("claude-island session report ({scope})\n"));
    out.push_str(&format!(
        "  outbound requests: {} to {} host(s)\n",
        r.requests,
        r.hosts.len()
    ));

    if r.leaks.is_empty() && r.l7.is_empty() {
        out.push_str("\n  no leak attempts or L7 denials recorded\n");
        return out;
    }

    if !r.leaks.is_empty() {
        let blocked = r.leaks.iter().filter(|l| l.blocked).count();
        let allowed = r.leaks.len() - blocked;
        out.push_str(&format!(
            "\n  LEAK ATTEMPTS ({blocked} blocked, {allowed} allowed):\n"
        ));
        for l in &r.leaks {
            let tag = if l.blocked { "BLOCKED" } else { "ALLOWED" };
            let times = if l.count > 1 {
                format!("  x{}", l.count)
            } else {
                String::new()
            };
            out.push_str(&format!("    {tag}  {:<34} -> {}{times}\n", l.what, l.host));
        }
    }

    if !r.l7.is_empty() {
        out.push_str(&format!("\n  L7 DENIED ({}):\n", r.l7.len()));
        for e in &r.l7 {
            let times = if e.count > 1 {
                format!("  x{}", e.count)
            } else {
                String::new()
            };
            out.push_str(&format!("    {:<34} -> {}{times}\n", e.request, e.host));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
[100] === session start ===
[101] api.anthropic.com POST /v1/messages body=2000B preview=\"...\"
[102] example.com POST /x body=20B preview=\"...\"
[103] !!! LEAK BLOCKED: AWS access key -> example.com (body 20B)
[104] !!! LEAK BLOCKED: code from src/algo.rs (9 fragments) -> pastebin.com (body 900B)
[105] !!! LEAK BLOCKED: AWS access key -> example.com (body 20B)
[106] !!! LEAK ALLOWED: honeytoken \"HT\" -> webhook.site (body 5B)
[107] !!! L7 DENIED: DELETE /repos/x -> api.github.com
[108] github.com GET / body=0B preview=\"\"
";

    #[test]
    fn parses_last_session_events() {
        let r = parse(LOG, true);
        assert_eq!(r.requests, 3); // anthropic, example, github request lines
                                   // Two AWS blocks to example.com aggregate into one event with count 2.
        let aws = r.leaks.iter().find(|l| l.what == "AWS access key").unwrap();
        assert!(aws.blocked);
        assert_eq!(aws.count, 2);
        assert_eq!(aws.host, "example.com");
        // One allowed honeytoken.
        assert!(r
            .leaks
            .iter()
            .any(|l| !l.blocked && l.host == "webhook.site"));
        // One L7 denial.
        assert_eq!(r.l7.len(), 1);
        assert_eq!(r.l7[0].host, "api.github.com");
    }

    #[test]
    fn last_session_ignores_prior_sessions() {
        let two = format!(
            "[1] === session start ===\n[2] !!! LEAK BLOCKED: old -> old.com (body 1B)\n{LOG}"
        );
        let r = parse(&two, true);
        assert!(!r.leaks.iter().any(|l| l.what == "old"));
        let all = parse(&two, false);
        assert!(all.leaks.iter().any(|l| l.what == "old"));
    }

    #[test]
    fn empty_log_reports_nothing() {
        let r = parse("", true);
        assert_eq!(r.requests, 0);
        assert!(render(&r, "last session").contains("no leak attempts"));
    }
}
