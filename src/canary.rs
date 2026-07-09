// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Canary suite: regression tests executed INSIDE the sandbox
// (`claude-island check` copies the binary into the project and re-runs it
// in __canary mode through `island run`). Each canary attempts an access
// that must be denied (a leak = FAIL) or allowed (nominal operation).

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

enum Verdict {
    Pass,
    Fail(String),
    Skip(String),
}

use Verdict::{Fail, Pass, Skip};

/// An access that MUST be denied by Landlock (EACCES/EPERM).
fn expect_denied(res: std::io::Result<()>) -> Verdict {
    match res {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
        Err(e) if e.kind() == ErrorKind::NotFound => Skip("target absent".into()),
        Err(e) => Skip(format!("unexpected error: {e}")),
        Ok(()) => Fail("access GRANTED where it should be denied".into()),
    }
}

/// An access that MUST work (otherwise the sandbox is too strict).
fn expect_allowed(res: std::io::Result<()>) -> Verdict {
    match res {
        Ok(()) => Pass,
        Err(e) => Fail(format!("denied where it should work: {e}")),
    }
}

fn connect(addr: &str) -> std::io::Result<()> {
    let sa: SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(ErrorKind::InvalidInput, format!("bad address {addr}: {e}"))
    })?;
    TcpStream::connect_timeout(&sa, Duration::from_millis(500)).map(|_| ())
}

/// The proxy port inside the sandbox, parsed from HTTPS_PROXY
/// (http://127.0.0.1:PORT), injected by the wrapper in --proxy mode.
fn proxy_port() -> Option<u16> {
    let v = env::var("HTTPS_PROXY").ok()?;
    v.rsplit_once(':')?.1.trim_end_matches('/').parse().ok()
}

/// Sends a CONNECT request through the proxy and returns the status code of
/// the first response line (e.g. 200, 403, 502).
fn proxy_request(port: u16, target: &str) -> std::io::Result<u16> {
    use std::io::{Read, Write};
    let sa: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| {
        std::io::Error::new(ErrorKind::InvalidInput, format!("bad proxy address: {e}"))
    })?;
    let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())?;
    let mut buf = [0u8; 256];
    let mut n = 0;
    while n < buf.len() && !buf[..n].windows(2).any(|w| w == b"\r\n") {
        match s.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) => return Err(e),
        }
    }
    let line = String::from_utf8_lossy(&buf[..n]);
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("unparsable proxy response: {line}")))
}

/// Sandbox modes under test, mirroring the wrapper flags.
pub struct Modes {
    pub ro: bool,
    pub noexec: bool,
    pub proxy: bool,
    pub deny: Vec<String>,
}

pub fn run_all(m: Modes) -> ExitCode {
    let home = PathBuf::from(env::var("HOME").unwrap_or_default());
    let project = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut fails = 0u32;
    let mut record = |name: &str, v: Verdict| match v {
        Pass => println!("[PASS] {name}"),
        Skip(why) => println!("[SKIP] {name} ({why})"),
        Fail(why) => {
            println!("[FAIL] {name}: {why}");
            fails += 1;
        }
    };

    // Preliminary detection: if $HOME is listable, the sandbox is inactive.
    if fs::read_dir(&home).is_ok() {
        println!("[FAIL] SANDBOX INACTIVE: $HOME is listable, no Landlock restriction applies");
        println!("result: FAILURE (run outside the sandbox?)");
        return ExitCode::from(1);
    }

    // Accesses that MUST be denied.
    record(
        "deny: list $HOME",
        expect_denied(fs::read_dir(&home).map(|_| ())),
    );
    record(
        "deny: read ~/.ssh",
        expect_denied(fs::read_dir(home.join(".ssh")).map(|_| ())),
    );
    record(
        "deny: read ~/.aws",
        expect_denied(fs::read_dir(home.join(".aws")).map(|_| ())),
    );
    record(
        "deny: read ~/.config/gh",
        expect_denied(fs::read_dir(home.join(".config/gh")).map(|_| ())),
    );
    // Shell startup files (persistence vector), across shells. Absent files
    // are reported as SKIP; creating them is covered by the $HOME-root and
    // ~/.config canaries below.
    for rc in [
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
    ] {
        record(
            &format!("deny: write ~/{rc}"),
            expect_denied(
                OpenOptions::new()
                    .append(true)
                    .open(home.join(rc))
                    .map(|_| ()),
            ),
        );
    }
    // Persistence and self-escape directories: systemd user units, desktop
    // autostart, Island's own profiles, claude-island's config (which holds
    // the proxy allowlist).
    for dir in [
        ".config/systemd/user",
        ".config/autostart",
        ".config/island/profiles",
        ".config/claude-island",
    ] {
        record(&format!("deny: create a file in ~/{dir}"), {
            let p = home.join(dir).join("claude-island-canary-forbidden");
            match File::create(&p) {
                Ok(_) => {
                    fs::remove_file(&p).ok();
                    Fail(format!("creation GRANTED in ~/{dir}"))
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) if e.kind() == ErrorKind::NotFound => Skip("directory absent".into()),
                Err(e) => Skip(format!("unexpected error: {e}")),
            }
        });
    }
    record("deny: create a file at the root of $HOME", {
        let p = home.join(".claude-island-canary-forbidden");
        match File::create(&p) {
            Ok(_) => {
                fs::remove_file(&p).ok();
                Fail("creation GRANTED in $HOME".into())
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
            Err(e) => Skip(format!("unexpected error: {e}")),
        }
    });
    record(
        "deny: TCP bind on a non-allowed port (34567)",
        match TcpListener::bind("127.0.0.1:34567") {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
            Err(e) => Skip(format!("unexpected error: {e}")),
            Ok(_) => Fail("bind GRANTED".into()),
        },
    );
    record(
        "deny: TCP connect to a non-allowed port (9)",
        match connect("127.0.0.1:9") {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
            Err(e) => Fail(format!("connect not blocked by Landlock ({e})")),
            Ok(()) => Fail("connect GRANTED".into()),
        },
    );

    // Probes live in a dedicated granted subdir (.claude-island-canary-dir,
    // placed by cmd_check before sandboxing) so they work in every mode,
    // including deny mode where the project root is no longer writable.
    let cdir = project.join(".claude-island-canary-dir");
    let probe = cdir.join("exec");
    if m.noexec {
        record(
            "deny (--noexec): execute a file inside the project",
            match Command::new(&probe).status() {
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) if e.kind() == ErrorKind::NotFound => Skip("probe absent".into()),
                Err(e) => Skip(format!("unexpected error: {e}")),
                Ok(_) => Fail("execution GRANTED in a noexec project".into()),
            },
        );
    } else {
        record(
            "allow: execute a file inside the project",
            match Command::new(&probe).status() {
                Ok(s) if s.success() => Pass,
                Ok(_) => Fail("probe exited with a non-zero code".into()),
                Err(e) if e.kind() == ErrorKind::NotFound => Skip("probe absent".into()),
                Err(e) => Fail(format!("denied where it should work: {e}")),
            },
        );
    }

    // Project write into the granted subdir: denied in --ro, required otherwise.
    if m.ro {
        record("deny (--ro): write inside the project", {
            let p = cdir.join("w");
            match File::create(&p) {
                Ok(_) => {
                    fs::remove_file(&p).ok();
                    Fail("write GRANTED in a read-only project".into())
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) => Skip(format!("unexpected error: {e}")),
            }
        });
        record(
            "allow (--ro): read the project",
            expect_allowed(fs::read_dir(&project).map(|_| ())),
        );
    } else {
        record("allow: write inside the project", {
            let p = cdir.join("w");
            let r = File::create(&p).map(|_| ());
            fs::remove_file(&p).ok();
            expect_allowed(r)
        });
    }

    // Deny mode: the CONTENTS of denied entries must be unreadable and they
    // must be unwritable. (Directory listings under a denied dir may still
    // leak names, because the read_dir grant on the project root propagates
    // to the subtree; contents and writes are what is actually protected.)
    // Also, the project root must not accept a new file (the documented
    // trade-off), while listing the root still works.
    if !m.deny.is_empty() {
        // Authoritative: a known secret file inside the synthetic denied dir.
        record(
            "deny (--deny): read contents of a denied file",
            match fs::read(project.join(".claude-island-canary-denied/secret")) {
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) if e.kind() == ErrorKind::NotFound => Skip("synthetic secret absent".into()),
                Err(e) => Skip(format!("unexpected error: {e}")),
                Ok(_) => Fail("denied file contents are readable".into()),
            },
        );
        record(
            "deny (--deny): write into a denied dir",
            match File::create(project.join(".claude-island-canary-denied/planted")) {
                Ok(_) => Fail("write GRANTED into a denied dir".into()),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    Skip("synthetic denied dir absent".into())
                }
                Err(e) => Skip(format!("unexpected error: {e}")),
            },
        );
        // Best effort on user-specified entries that are plain files.
        for name in &m.deny {
            if name.starts_with(".claude-island-canary") {
                continue;
            }
            record(
                &format!("deny (--deny): read contents of ~project/{name}"),
                match fs::read(project.join(name)) {
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                    Err(e) if e.kind() == ErrorKind::NotFound => Skip("entry absent".into()),
                    Err(_) => Skip("not a plain file (dir contents covered above)".into()),
                    Ok(_) => Fail(format!("{name} contents are readable despite --deny")),
                },
            );
        }
        record(
            "deny (--deny): create a new file at the project root",
            match File::create(project.join(".claude-island-canary-rootnew")) {
                Ok(_) => {
                    fs::remove_file(project.join(".claude-island-canary-rootnew")).ok();
                    Fail("root file creation GRANTED under --deny".into())
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) => Skip(format!("unexpected error: {e}")),
            },
        );
        record(
            "allow (--deny): list the project root",
            expect_allowed(fs::read_dir(&project).map(|_| ())),
        );
    }
    record(
        "allow: read /etc/os-release",
        expect_allowed(fs::read_to_string("/etc/os-release").map(|_| ())),
    );
    record(
        "allow: execute /usr/bin/true",
        expect_allowed(Command::new("/usr/bin/true").status().and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(std::io::Error::other("non-zero exit code"))
            }
        })),
    );
    record("allow: write inside TMPDIR (workspace)", {
        match env::var("TMPDIR") {
            Ok(t) => {
                let p = PathBuf::from(t).join("claude-island-canary");
                let r = File::create(&p).map(|_| ());
                fs::remove_file(&p).ok();
                expect_allowed(r)
            }
            Err(_) => Skip("TMPDIR not set".into()),
        }
    });
    if m.proxy {
        // In --proxy mode, the ONLY outbound TCP is the proxy port, and the
        // proxy itself enforces the domain allowlist.
        record(
            "deny (--proxy): direct TCP connect to port 443",
            match connect("127.0.0.1:443") {
                Err(e) if e.kind() == ErrorKind::PermissionDenied => Pass,
                Err(e) => Fail(format!("direct 443 not blocked by Landlock ({e})")),
                Ok(()) => Fail("direct 443 connect GRANTED".into()),
            },
        );
        match proxy_port() {
            None => record(
                "allow (--proxy): reach the filtering proxy",
                Skip("HTTPS_PROXY not set or unparsable".into()),
            ),
            Some(port) => {
                record(
                    "allow (--proxy): reach the filtering proxy",
                    expect_allowed(connect(&format!("127.0.0.1:{port}"))),
                );
                record(
                    "deny (--proxy): CONNECT to a non-allowlisted domain",
                    match proxy_request(port, "claude-island-canary-denied.example:443") {
                        Ok(403) => Pass,
                        Ok(code) => Fail(format!("proxy answered {code} instead of 403")),
                        Err(e) => Skip(format!("proxy unreachable: {e}")),
                    },
                );
                record(
                    "allow (--proxy): CONNECT to an allowlisted domain (api.anthropic.com)",
                    match proxy_request(port, "api.anthropic.com:443") {
                        // 200 = tunnel established; 502 = allowlisted but no
                        // network right now: both prove the allowlist logic.
                        Ok(200) | Ok(502) => Pass,
                        Ok(403) => Fail("allowlisted domain refused by the proxy".into()),
                        Ok(code) => Skip(format!("unexpected proxy answer: {code}")),
                        Err(e) => Skip(format!("proxy unreachable: {e}")),
                    },
                );
            }
        }
    } else {
        record(
            "allow: TCP connect to port 443 (not blocked by Landlock)",
            match connect("127.0.0.1:443") {
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    Fail("port 443 is denied".into())
                }
                _ => Pass, // connection refused or timeout = Landlock let it through
            },
        );
    }

    if fails > 0 {
        println!("result: FAILURE ({fails} canary(ies) failed)");
        return ExitCode::from(1);
    }
    println!("result: OK, the sandbox holds its promises");
    ExitCode::SUCCESS
}
