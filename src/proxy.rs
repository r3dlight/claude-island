// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Domain-filtering HTTP CONNECT proxy.
//
// Runs OUTSIDE the sandbox (wrapper threads, unrestricted); inside the
// sandbox, Landlock only lets traffic out to the proxy port. Landlock's
// port-based filtering thus becomes domain-based filtering. An allowlisted
// domain also covers its subdomains (suffix match).
//
// Interactive mode (--ask): a request to a non-allowlisted domain is still
// denied, but the domain is appended to a pending file. The user approves
// it later (`claude-island approve <domain>`, or live with
// `claude-island watch`), which writes to domains.allow; the proxy re-reads
// that file per request, so the next connection to the domain succeeds.
// Fully asynchronous: it never touches the terminal the agent's TUI uses.
//
// The pending file is the universal channel: it works on any system with no
// dependency. A best-effort notification (a user hook, notify-send, or tmux)
// is layered on top but is never required.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::broker::Broker;
use crate::pty::Prompter;

pub struct Proxy {
    pub port: u16,
}

type Log = Arc<Mutex<Box<dyn Write + Send>>>;

/// Shared proxy state (all fields immutable except the interior-mutable maps).
struct State {
    /// Fixed allowlist: base domains + environments + --allow.
    fixed: Vec<String>,
    /// domains.allow, re-read per non-fixed request so approvals go live.
    allow_file: PathBuf,
    /// Pending denied domains awaiting approval (async fallback).
    pending_file: PathBuf,
    /// Async mode (--ask without a TTY): record + notify instead of prompting.
    interactive: bool,
    /// Inline mode (--ask with a TTY): ask the user through the PTY pump.
    prompter: Option<Prompter>,
    /// Hosts already recorded/notified, to avoid duplicate spam (async).
    notified: Mutex<HashSet<String>>,
    /// Cached inline decisions this session, to avoid re-prompting a host.
    decisions: Mutex<HashMap<String, bool>>,
    /// Credential broker: TLS-terminate and inject auth for certain hosts.
    broker: Option<Arc<Broker>>,
    log: Log,
}

fn log_line(log: &Log, msg: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut w) = log.lock() {
        writeln!(w, "[{ts}] {msg}").ok();
        w.flush().ok();
    }
}

/// Parses a domains file: one entry per line, `#` comments, blanks skipped.
pub fn read_domains_file(path: &Path) -> Vec<String> {
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };
    content
        .lines()
        .filter_map(|l| {
            let d = l.split('#').next().unwrap_or("").trim();
            (!d.is_empty()).then(|| d.to_string())
        })
        .collect()
}

fn matches(host: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|d| host == d || host.ends_with(&format!(".{d}")))
}

impl State {
    fn allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        matches(&host, &self.fixed) || matches(&host, &read_domains_file(&self.allow_file))
    }

    /// Inline decision for a denied host: cached, else ask via the pump.
    /// On approval, persist to domains.allow (so it survives the session and
    /// future connections skip the prompt) and log the decision.
    fn decide_inline(&self, host: &str, prompter: &Prompter) -> bool {
        let host = host.to_ascii_lowercase();
        if let Ok(cache) = self.decisions.lock() {
            if let Some(&d) = cache.get(&host) {
                return d;
            }
        }
        let decision = prompter.ask(&host);
        if let Ok(mut cache) = self.decisions.lock() {
            cache.insert(host.clone(), decision);
        }
        if decision {
            self.persist_allow(&host);
            log_line(&self.log, &format!("APPROVED (inline): {host}"));
        } else {
            log_line(&self.log, &format!("DENIED (inline): {host}"));
        }
        decision
    }

    /// Appends a host to domains.allow if not already present.
    fn persist_allow(&self, host: &str) {
        let mut domains = read_domains_file(&self.allow_file);
        if domains.iter().any(|d| d == host) {
            return;
        }
        domains.push(host.to_string());
        domains.sort();
        domains.dedup();
        if let Some(parent) = self.allow_file.parent() {
            fs::create_dir_all(parent).ok();
        }
        let body: String = domains.iter().map(|d| format!("{d}\n")).collect();
        if let Err(e) = fs::write(&self.allow_file, body) {
            log_line(&self.log, &format!("failed to persist allowlist: {e}"));
        }
    }

    /// On an interactive denial: record the host once, then notify.
    fn record_denied(&self, host: &str) {
        let host = host.to_ascii_lowercase();
        {
            let mut seen = match self.notified.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if !seen.insert(host.clone()) {
                return; // already handled this session
            }
        }
        let mut pending = read_domains_file(&self.pending_file);
        if !pending.iter().any(|d| d == &host) {
            pending.push(host.clone());
            if let Some(parent) = self.pending_file.parent() {
                fs::create_dir_all(parent).ok();
            }
            let body: String = pending.iter().map(|d| format!("{d}\n")).collect();
            if let Err(e) = fs::write(&self.pending_file, body) {
                log_line(&self.log, &format!("failed to record pending domain: {e}"));
            }
        }
        notify(&host);
    }
}

/// Best-effort notification that does NOT touch the agent's terminal. The
/// pending file is the real, universal channel; this is only a courtesy, in
/// order (all optional, failures ignored):
///   1. CLAUDE_ISLAND_NOTIFY hook (run as `sh -c "$HOOK" -- <message>`),
///   2. notify-send desktop notification (freedesktop),
///   3. tmux status line if inside tmux,
///   4. nothing.
fn notify(host: &str) {
    desktop_notify(&format!(
        "claude-island: blocked {host} (approve: claude-island approve {host})"
    ));
}

/// Best-effort desktop notification (user hook, else notify-send, else tmux),
/// none of which touch the agent's terminal. All optional.
pub fn desktop_notify(msg: &str) {
    if let Ok(hook) = std::env::var("CLAUDE_ISLAND_NOTIFY") {
        if !hook.trim().is_empty() {
            Command::new("sh")
                .arg("-c")
                .arg(&hook)
                .arg("--")
                .arg(msg)
                .spawn()
                .ok();
            return;
        }
    }
    if Command::new("notify-send")
        .arg("claude-island")
        .arg(msg)
        .spawn()
        .is_ok()
    {
        return;
    }
    if std::env::var("TMUX").is_ok() {
        Command::new("tmux")
            .arg("display-message")
            .arg(msg)
            .status()
            .ok();
    }
}

/// Starts the proxy on an ephemeral 127.0.0.1 port; does not block.
#[allow(clippy::too_many_arguments)]
pub fn start(
    fixed: Vec<String>,
    allow_file: PathBuf,
    pending_file: PathBuf,
    interactive: bool,
    prompter: Option<Prompter>,
    broker: Option<Arc<Broker>>,
    log_path: &Path,
) -> io::Result<Proxy> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let log: Log = Arc::new(Mutex::new(Box::new(file)));
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let mode = if prompter.is_some() {
        "inline"
    } else if interactive {
        "async"
    } else {
        "static"
    };
    log_line(
        &log,
        &format!(
            "starting on 127.0.0.1:{port}, fixed allowlist: {} (mode: {mode})",
            fixed.join(" ")
        ),
    );
    let state = Arc::new(State {
        fixed,
        allow_file,
        pending_file,
        interactive,
        prompter,
        notified: Mutex::new(HashSet::new()),
        decisions: Mutex::new(HashMap::new()),
        broker,
        log,
    });
    spawn_accept_loop(listener, state);
    Ok(Proxy { port })
}

fn spawn_accept_loop(listener: TcpListener, state: Arc<State>) {
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let state = state.clone();
            thread::spawn(move || handle(conn, &state));
        }
    });
}

fn respond(client: &mut TcpStream, status: &str) {
    client
        .write_all(
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .ok();
}

fn handle(mut client: TcpStream, state: &State) {
    client.set_read_timeout(Some(Duration::from_secs(15))).ok();

    // Read the request header (capped at 8 KiB).
    let mut buf = [0u8; 8192];
    let mut n = 0;
    loop {
        match client.read(&mut buf[n..]) {
            Ok(0) => return,
            Ok(k) => {
                n += k;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if n == buf.len() {
                    respond(&mut client, "431 Request Header Fields Too Large");
                    return;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("");
    let target = first.next().unwrap_or("");

    if method != "CONNECT" {
        // No plaintext HTTP through this proxy: everything goes via CONNECT (TLS).
        log_line(&state.log, &format!("denied (method {method}): {target}"));
        respond(&mut client, "405 Method Not Allowed");
        return;
    }
    let Some((host, port_s)) = target.rsplit_once(':') else {
        respond(&mut client, "400 Bad Request");
        return;
    };
    let Ok(port) = port_s.parse::<u16>() else {
        respond(&mut client, "400 Bad Request");
        return;
    };
    // Decide whether to allow this connection.
    let bad_port = !(port == 443 || port == 80);
    let mut allow_now = !bad_port && state.allowed(host);
    if !allow_now && !bad_port {
        log_line(&state.log, &format!("DENIED: {host}:{port}"));
        if let Some(prompter) = &state.prompter {
            // Inline: block this connection until the user answers.
            allow_now = state.decide_inline(host, prompter);
        } else if state.interactive {
            state.record_denied(host);
        }
    } else if bad_port {
        log_line(&state.log, &format!("DENIED (port {port}): {host}"));
    }
    if !allow_now {
        respond(&mut client, "403 Forbidden");
        return;
    }

    // Credential broker: for configured hosts, terminate TLS here and inject
    // the real credential (which never enters the sandbox) instead of a plain
    // tunnel. Only over 443.
    if port == 443 {
        if let Some(broker) = &state.broker {
            if broker.should_terminate(host) {
                let host = host.to_string();
                client.set_read_timeout(None).ok();
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                match broker.mitm(client, &host, port) {
                    Ok(()) => log_line(&state.log, &format!("brokered: {host}:{port}")),
                    Err(e) => log_line(&state.log, &format!("broker error {host}: {e}")),
                }
                return;
            }
        }
    }

    match TcpStream::connect((host, port)) {
        Ok(server) => {
            log_line(&state.log, &format!("allowed: {host}:{port}"));
            client.set_read_timeout(None).ok();
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            tunnel(client, server);
        }
        Err(e) => {
            log_line(
                &state.log,
                &format!("connection to {host}:{port} failed: {e}"),
            );
            respond(&mut client, "502 Bad Gateway");
        }
    }
}

fn tunnel(client: TcpStream, server: TcpStream) {
    let (Ok(c_read), Ok(mut s_write)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let mut c = c_read;
        io::copy(&mut c, &mut s_write).ok();
        s_write.shutdown(Shutdown::Write).ok();
    });
    let mut s_read = server;
    let mut c_write = client;
    io::copy(&mut s_read, &mut c_write).ok();
    c_write.shutdown(Shutdown::Write).ok();
    up.join().ok();
}

/// Internal test mode: `claude-island __proxy dom1 dom2...` prints the
/// chosen port then serves forever (logs to stderr, non-interactive).
pub fn standalone(domains: &[String]) -> Result<std::process::ExitCode, String> {
    let log: Log = Arc::new(Mutex::new(Box::new(io::stderr())));
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("proxy bind: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("proxy local address: {e}"))?
        .port();
    println!("{port}");
    io::stdout().flush().ok();
    let state = Arc::new(State {
        fixed: domains.to_vec(),
        allow_file: PathBuf::from("/nonexistent"),
        pending_file: PathBuf::from("/nonexistent"),
        interactive: false,
        prompter: None,
        notified: Mutex::new(HashSet::new()),
        decisions: Mutex::new(HashMap::new()),
        broker: None,
        log,
    });
    spawn_accept_loop(listener, state);
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
