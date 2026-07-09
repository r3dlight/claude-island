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
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

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
}

impl Broker {
    /// Builds a broker with an ephemeral CA. Returns None if no credentials.
    pub fn new(creds: Vec<Credential>) -> Result<Option<Arc<Broker>>, String> {
        if creds.is_empty() {
            return Ok(None);
        }
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
        })))
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Is this host one we terminate (broker credentials for)?
    pub fn brokers(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.creds.iter().any(|c| c.matches(&host))
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
        relay_http(&mut client, &mut upstream, header.as_deref())
    }
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
) -> Result<(), String> {
    let (head, mut leftover) = read_headers(client)?;
    let mut lines: Vec<String> = head.split("\r\n").map(|s| s.to_string()).collect();

    // Drop any client Authorization (the sandbox only ever has a placeholder
    // or none) and the Connection headers, then inject the real credential
    // and force Connection: close.
    lines.retain(|l| {
        let lower = l.to_ascii_lowercase();
        !lower.starts_with("authorization:")
            && !lower.starts_with("connection:")
            && !lower.starts_with("proxy-connection:")
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
    upstream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write request: {e}"))?;

    // Forward the request body.
    if let Some(len) = content_length {
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
    Ok(())
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
