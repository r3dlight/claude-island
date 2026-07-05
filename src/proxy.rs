// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Domain-filtering HTTP CONNECT proxy.
//
// Runs OUTSIDE the sandbox (wrapper threads, unrestricted); inside the
// sandbox, Landlock only lets traffic out to the proxy port. Landlock's
// port-based filtering thus becomes domain-based filtering. An allowlisted
// domain also covers its subdomains (suffix match).

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Proxy {
    pub port: u16,
}

type Log = Arc<Mutex<Box<dyn Write + Send>>>;

fn log_line(log: &Log, msg: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut w) = log.lock() {
        let _ = writeln!(w, "[{ts}] {msg}");
        let _ = w.flush();
    }
}

/// Starts the proxy on an ephemeral 127.0.0.1 port; does not block.
pub fn start(domains: Vec<String>, log_path: &Path) -> io::Result<Proxy> {
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
    log_line(
        &log,
        &format!(
            "starting on 127.0.0.1:{port}, allowlist: {}",
            domains.join(" ")
        ),
    );
    spawn_accept_loop(listener, Arc::new(domains), log);
    Ok(Proxy { port })
}

fn spawn_accept_loop(listener: TcpListener, allow: Arc<Vec<String>>, log: Log) {
    thread::spawn(move || {
        for conn in listener.incoming() {
            if let Ok(stream) = conn {
                let allow = allow.clone();
                let log = log.clone();
                thread::spawn(move || handle(stream, &allow, &log));
            }
        }
    });
}

fn allowed(host: &str, allow: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    allow
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn respond(client: &mut TcpStream, status: &str) {
    let _ = client.write_all(
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes(),
    );
}

fn handle(mut client: TcpStream, allow: &[String], log: &Log) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));

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
        log_line(log, &format!("denied (method {method}): {target}"));
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
    if !(port == 443 || port == 80) || !allowed(host, allow) {
        log_line(log, &format!("DENIED: {host}:{port}"));
        respond(&mut client, "403 Forbidden");
        return;
    }

    match TcpStream::connect((host, port)) {
        Ok(server) => {
            log_line(log, &format!("allowed: {host}:{port}"));
            let _ = client.set_read_timeout(None);
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .is_err()
            {
                return;
            }
            tunnel(client, server);
        }
        Err(e) => {
            log_line(log, &format!("connection to {host}:{port} failed: {e}"));
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
        let _ = io::copy(&mut c, &mut s_write);
        let _ = s_write.shutdown(Shutdown::Write);
    });
    let mut s_read = server;
    let mut c_write = client;
    let _ = io::copy(&mut s_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let _ = up.join();
}

/// Internal test mode: `claude-island __proxy dom1 dom2...` prints the
/// chosen port then serves forever (logs to stderr).
pub fn standalone(domains: &[String]) -> Result<std::process::ExitCode, String> {
    let log: Log = Arc::new(Mutex::new(Box::new(io::stderr())));
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("proxy bind: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("proxy local address: {e}"))?
        .port();
    println!("{port}");
    let _ = io::stdout().flush();
    spawn_accept_loop(listener, Arc::new(domains.to_vec()), log);
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
