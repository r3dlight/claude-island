// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Credential broker: a TLS-terminating proxy that injects an Authorization
// header OUTSIDE the sandbox, so the real token never enters it. The
// sandboxed tool (gh, git, curl) trusts an ephemeral local CA (injected via
// env), connects through the proxy, and we swap in the real credential.
//
// Only configured credential hosts are terminated; every other allowlisted
// host is tunnelled untouched (normal --proxy behaviour). The CA is
// generated fresh per session and never persisted as trusted anywhere.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::detect::Detector;
use crate::pty::Prompter;

/// Hosts that legitimately carry your code (the Anthropic API): audited but
/// never flagged as a leak, so `--detect` does not alarm on normal use.
const CODE_EXPECTED: &[&str] = &["api.anthropic.com", "statsig.anthropic.com"];

/// Largest request body buffered for leak scanning; larger ones stream
/// unscanned (source files are small, so this misses little).
const SCAN_CAP: usize = 8 * 1024 * 1024;

/// Inspects an outbound body and returns whether to proceed (false = block).
type Inspector<'a> = &'a dyn Fn(&[u8]) -> bool;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A credential to inject for a set of hosts. GitHub wants `Bearer` for the
/// REST API but Basic auth for git-over-HTTPS, so the header is computed per
/// host: `bearer_hosts` get `Bearer <token>`, the rest get
/// `Basic base64(x-access-token:<token>)`.
pub struct Credential {
    pub hosts: Vec<String>,
    pub bearer_hosts: Vec<String>,
    pub token: String,
}

/// Standard base64 of `input` (for Basic auth).
fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The broker: an in-memory CA plus the credentials to inject.
pub struct Broker {
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    ca_key: rcgen::KeyPair,
    ca: rcgen::Certificate,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    creds: Vec<Credential>,
    upstream_roots: Arc<RootCertStore>,
    /// Inspection mode (--inspect): terminate EVERY host and audit outbound
    /// requests. The file is opened once and guarded by a mutex so concurrent
    /// request threads do not interleave their lines.
    inspect: bool,
    audit: Option<Mutex<std::fs::File>>,
    /// Leak detection (--detect): scan outbound bodies against the project.
    detector: Option<Arc<Detector>>,
    /// Inline prompter (--ask): ask the user before blocking a detected leak,
    /// instead of blocking outright.
    prompter: Option<Prompter>,
}

impl Broker {
    /// Builds a broker with an ephemeral CA. Returns None if there is nothing
    /// to do (no credentials and no inspection).
    pub fn new(
        creds: Vec<Credential>,
        inspect: bool,
        audit_path: Option<PathBuf>,
        detector: Option<Arc<Detector>>,
        prompter: Option<Prompter>,
    ) -> Result<Option<Arc<Broker>>, String> {
        if creds.is_empty() && !inspect {
            return Ok(None);
        }
        let audit = match audit_path {
            Some(p) => {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&p)
                    .map_err(|e| format!("opening audit log {}: {e}", p.display()))?;
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                writeln!(f, "[{ts}] === session start ===").ok();
                Some(Mutex::new(f))
            }
            None => None,
        };
        // Install the ring crypto provider (idempotent, ignore if already set).
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let mut params =
            rcgen::CertificateParams::new(vec![]).map_err(|e| format!("ca params: {e}"))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "claude-island session CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().map_err(|e| format!("ca key: {e}"))?;
        let ca = params
            .self_signed(&ca_key)
            .map_err(|e| format!("ca sign: {e}"))?;
        let ca_cert_pem = ca.pem();
        let ca_cert_der = ca.der().clone();

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        Ok(Some(Arc::new(Broker {
            ca_cert_der,
            ca_cert_pem,
            ca_key,
            ca,
            leaves: Mutex::new(HashMap::new()),
            creds,
            upstream_roots: Arc::new(roots),
            inspect,
            audit,
            detector,
            prompter,
        })))
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Should this host be TLS-terminated? True in inspection mode (every
    /// host) or for a credential host.
    pub fn should_terminate(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.inspect || self.creds.iter().any(|c| c.matches(&host))
    }

    fn credential_for(&self, host: &str) -> Option<&Credential> {
        let host = host.to_ascii_lowercase();
        self.creds.iter().find(|c| c.matches(&host))
    }

    /// A rustls ServerConfig with a leaf cert for `host`, signed by our CA.
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Ok(cache) = self.leaves.lock() {
            if let Some(cfg) = cache.get(host) {
                return Ok(cfg.clone());
            }
        }
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let leaf_key = rcgen::KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
        let leaf = params
            .signed_by(&leaf_key, &self.ca, &self.ca_key)
            .map_err(|e| format!("leaf sign: {e}"))?;

        let chain = vec![leaf.der().clone(), self.ca_cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| format!("server config: {e}"))?;
        // Force HTTP/1.1 so we do not have to speak HTTP/2.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        if let Ok(mut cache) = self.leaves.lock() {
            cache.insert(host.to_string(), cfg.clone());
        }
        Ok(cfg)
    }

    /// Terminates TLS with the client (impersonating `host`), reads the HTTP
    /// request, injects the credential, forwards to the real host over a
    /// fresh verified TLS connection, and relays the response back.
    pub fn mitm(&self, client_tcp: TcpStream, host: &str, port: u16) -> Result<(), String> {
        let cfg = self.server_config(host)?;
        let conn = ServerConnection::new(cfg).map_err(|e| format!("server conn: {e}"))?;
        let mut client = StreamOwned::new(conn, client_tcp);

        // Upstream TLS connection to the real host.
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(self.upstream_roots.clone())
            .with_no_client_auth();
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
        let up_conn = ClientConnection::new(Arc::new(client_cfg), server_name)
            .map_err(|e| format!("client conn: {e}"))?;
        let up_tcp =
            TcpStream::connect((host, port)).map_err(|e| format!("upstream connect: {e}"))?;
        let mut upstream = StreamOwned::new(up_conn, up_tcp);

        let header = self.credential_for(host).map(|c| c.header_for(host));

        // Leak detection: for hosts that are not code-expected, scan the
        // outbound body; a detected leak is blocked (the request is not
        // forwarded) and alerted.
        let scan = self.detector.is_some()
            && !CODE_EXPECTED
                .iter()
                .any(|h| *h == host.to_ascii_lowercase());
        let closure = |body: &[u8]| self.check_leak(host, body);
        let inspector: Option<Inspector> = if scan { Some(&closure) } else { None };

        let info = relay_http(&mut client, &mut upstream, header.as_deref(), inspector)?;
        self.write_audit(host, &info);
        Ok(())
    }

    /// Scans one outbound body for project content. Returns whether to proceed
    /// (true) or block (false). A leak is alerted (audit log + notification).
    fn check_leak(&self, host: &str, body: &[u8]) -> bool {
        let Some(det) = &self.detector else {
            return true;
        };
        let Some(leak) = det.scan(body) else {
            return true;
        };
        let gz = if leak.compressed { ", gzip" } else { "" };
        let what = if leak.kind == "honeytoken" {
            format!("honeytoken {:?}{gz}", leak.detail)
        } else {
            format!("code from {} ({} fragments{gz})", leak.detail, leak.score)
        };
        // With an inline prompter (--ask), let the user decide per leak;
        // otherwise fail safe and block. Default (timeout/no answer) is block.
        let allowed = match &self.prompter {
            Some(p) => p.ask_leak(&what, host),
            None => false,
        };
        let verdict = if allowed {
            "LEAK ALLOWED"
        } else {
            "LEAK BLOCKED"
        };
        let msg = format!("{verdict}: {what} -> {host}");
        if let Some(lock) = &self.audit {
            if let Ok(mut f) = lock.lock() {
                let ts = now_secs();
                writeln!(f, "[{ts}] !!! {msg} (body {}B)", body.len()).ok();
            }
        }
        if !allowed {
            crate::proxy::desktop_notify(&format!("claude-island: {msg}"));
        }
        allowed
    }

    /// Appends one outbound request to the audit log: destination, method,
    /// path, body size, and a truncated body preview. Serialized by a mutex
    /// so concurrent threads do not interleave. Authorization is never logged.
    fn write_audit(&self, host: &str, info: &RequestInfo) {
        let Some(lock) = &self.audit else { return };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut f) = lock.lock() {
            writeln!(
                f,
                "[{ts}] {host} {} {} body={}B preview={:?}",
                info.method, info.path, info.body_len, info.preview
            )
            .ok();
        }
    }
}

/// A summary of one outbound request, for the audit log.
struct RequestInfo {
    method: String,
    path: String,
    body_len: usize,
    preview: String,
}

impl Credential {
    fn matches(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| h == host)
    }

    /// The Authorization header value for a given host.
    fn header_for(&self, host: &str) -> String {
        if self.bearer_hosts.iter().any(|h| h == host) {
            format!("Bearer {}", self.token)
        } else {
            format!(
                "Basic {}",
                base64(format!("x-access-token:{}", self.token).as_bytes())
            )
        }
    }
}

/// Reads one HTTP/1.1 request from `client`, injects the credential, sends it
/// to `upstream`, then relays the response back. Forces `Connection: close`
/// so bodies are simple to bound (Content-Length, chunked, or read-to-EOF).
fn relay_http<C: Read + Write, U: Read + Write>(
    client: &mut C,
    upstream: &mut U,
    inject_header: Option<&str>,
    inspect: Option<Inspector>,
) -> Result<RequestInfo, String> {
    let (head, mut leftover) = read_headers(client)?;
    let mut lines: Vec<String> = head.split("\r\n").map(|s| s.to_string()).collect();

    // Request line summary (method + path), for the audit log.
    let request_line = lines.first().cloned().unwrap_or_default();
    let mut rl = request_line.split_whitespace();
    let method = rl.next().unwrap_or("").to_string();
    let path = rl.next().unwrap_or("").to_string();

    // Strip Authorization ONLY when we will inject our own credential (a
    // credential host); otherwise pass the client's auth through unchanged
    // (inspection must not break the tool's own authentication). Always drop
    // the Connection headers and force Connection: close.
    lines.retain(|l| {
        let lower = l.to_ascii_lowercase();
        let strip_auth = inject_header.is_some() && lower.starts_with("authorization:");
        !strip_auth && !lower.starts_with("connection:") && !lower.starts_with("proxy-connection:")
    });
    if let Some(h) = inject_header {
        lines.insert(1, format!("Authorization: {h}"));
    }
    lines.insert(1, "Connection: close".to_string());

    let content_length =
        header_value(&lines, "content-length").and_then(|v| v.trim().parse::<usize>().ok());
    let chunked = header_value(&lines, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);

    let request = format!("{}\r\n\r\n", lines.join("\r\n"));

    // If inspecting AND the body fits, buffer it fully so it can be scanned
    // before anything is sent upstream (so a leak can be blocked cleanly).
    let buffered = if inspect.is_some() {
        buffer_body(client, &mut leftover, content_length, chunked, SCAN_CAP)?
    } else {
        None
    };

    let body_len = buffered
        .as_ref()
        .map(|b| b.len())
        .unwrap_or_else(|| content_length.unwrap_or(leftover.len()));
    let preview_src = buffered.as_deref().unwrap_or(&leftover);
    let preview_len = preview_src.len().min(400);
    let preview = String::from_utf8_lossy(&preview_src[..preview_len]).into_owned();

    if let (Some(check), Some(body)) = (inspect, &buffered) {
        if !check(body) {
            // Blocked: tell the client and never touch the real host.
            write_error(client, "403 Forbidden (claude-island: leak blocked)");
            return Ok(RequestInfo {
                method,
                path,
                body_len,
                preview,
            });
        }
    }

    upstream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;

    // Forward the request body: the buffered copy if we have it, else stream.
    if let Some(body) = &buffered {
        upstream.write_all(body).map_err(|e| format!("body: {e}"))?;
    } else if let Some(len) = content_length {
        forward_n(client, upstream, &mut leftover, len)?;
    } else if chunked {
        forward_chunked(client, upstream, &mut leftover)?;
    }
    upstream.flush().ok();

    // Relay the whole response (headers + body) back to the client, until EOF
    // (we forced Connection: close upstream too).
    let mut buf = [0u8; 16384];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    client.flush().ok();
    Ok(RequestInfo {
        method,
        path,
        body_len,
        preview,
    })
}

/// Reads up to the end of HTTP headers; returns (headers-without-crlfcrlf,
/// bytes already read past the headers).
fn read_headers<C: Read>(client: &mut C) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = client
            .read(&mut tmp)
            .map_err(|e| format!("read headers: {e}"))?;
        if n == 0 {
            return Err("client closed before request".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        if buf.len() > 64 * 1024 {
            return Err("request headers too large".into());
        }
    }
}

fn header_value(lines: &[String], name: &str) -> Option<String> {
    lines.iter().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_string())
    })
}

/// Sends a minimal HTTP error response to the client (used to block a leak).
fn write_error<C: Write>(client: &mut C, status: &str) {
    client
        .write_all(
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .ok();
    client.flush().ok();
}

/// Reads the full request body into memory for scanning, using `leftover`
/// first. Returns None if the body is larger than `cap` (caller then streams
/// it unscanned). A body-less request yields an empty buffer.
fn buffer_body<C: Read>(
    client: &mut C,
    leftover: &mut Vec<u8>,
    content_length: Option<usize>,
    chunked: bool,
    cap: usize,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(len) = content_length {
        if len > cap {
            return Ok(None);
        }
        let mut buf = std::mem::take(leftover);
        buf.truncate(len);
        let mut tmp = [0u8; 16384];
        while buf.len() < len {
            let n = client
                .read(&mut tmp)
                .map_err(|e| format!("body read: {e}"))?;
            if n == 0 {
                break;
            }
            let want = (len - buf.len()).min(n);
            buf.extend_from_slice(&tmp[..want]);
        }
        Ok(Some(buf))
    } else if chunked {
        let mut buf = std::mem::take(leftover);
        let mut tmp = [0u8; 16384];
        while find_subslice(&buf, b"0\r\n\r\n").is_none() {
            if buf.len() > cap {
                return Ok(None);
            }
            let n = client
                .read(&mut tmp)
                .map_err(|e| format!("chunk read: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok(Some(buf))
    } else {
        Ok(Some(std::mem::take(leftover)))
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Forwards exactly `len` body bytes, using already-buffered `leftover` first.
fn forward_n<C: Read, U: Write>(
    client: &mut C,
    upstream: &mut U,
    leftover: &mut Vec<u8>,
    len: usize,
) -> Result<(), String> {
    let mut remaining = len;
    let take = leftover.len().min(remaining);
    if take > 0 {
        upstream
            .write_all(&leftover[..take])
            .map_err(|e| format!("body: {e}"))?;
        leftover.drain(..take);
        remaining -= take;
    }
    let mut buf = [0u8; 16384];
    while remaining > 0 {
        let n = client
            .read(&mut buf)
            .map_err(|e| format!("body read: {e}"))?;
        if n == 0 {
            break;
        }
        let k = n.min(remaining);
        upstream
            .write_all(&buf[..k])
            .map_err(|e| format!("body write: {e}"))?;
        remaining -= k;
    }
    Ok(())
}

/// Forwards a chunked request body verbatim until the terminating 0-chunk.
fn forward_chunked<C: Read, U: Write>(
    client: &mut C,
    upstream: &mut U,
    leftover: &mut Vec<u8>,
) -> Result<(), String> {
    // Simple pass-through: keep forwarding until we see the terminator.
    let mut buf = leftover.clone();
    leftover.clear();
    let mut tmp = [0u8; 16384];
    loop {
        if find_subslice(&buf, b"0\r\n\r\n").is_some() {
            upstream
                .write_all(&buf)
                .map_err(|e| format!("chunk: {e}"))?;
            return Ok(());
        }
        let n = client
            .read(&mut tmp)
            .map_err(|e| format!("chunk read: {e}"))?;
        if n == 0 {
            upstream.write_all(&buf).ok();
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8 * 1024 * 1024 {
            return Err("chunked body too large".into());
        }
    }
}
