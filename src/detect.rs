// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Leak detection (--detect): fingerprint the project's files at startup, then
// scan outbound request bodies (which --inspect already sees in plaintext)
// for that content. Two signals:
//   - honeytokens: exact strings the user wants to watch (precise);
//   - fingerprints: sampled k-grams of the project files, robust to small
//     edits and reformatting, to catch a chunk of local code being sent out.
//
// Scanning excludes the code-expected hosts (the Anthropic API legitimately
// carries your code); it targets everything else, where an outbound copy of
// local code is a real exfiltration signal.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// k-gram length (over whitespace-stripped bytes).
const K: usize = 32;
/// Cap on decompressed output, to defuse a decompression bomb.
const DECOMP_CAP: u64 = 64 * 1024 * 1024;
/// Keep ~1 in 8 k-grams (deterministic content sampling): a shared substring
/// long enough will share sampled fingerprints on both sides.
const SAMPLE_MASK: u64 = 0x7;
/// Minimum matched fingerprints from one file to call it a leak.
const THRESHOLD: usize = 6;
/// Directories never indexed (build output, deps, VCS).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".next",
    ".cache",
];
/// Skip files larger than this (bytes); big blobs are rarely source.
const MAX_FILE: u64 = 1_000_000;

pub struct Detector {
    /// fingerprint -> a representative file that contains it.
    fps: HashMap<u64, String>,
    /// file -> its number of distinct fingerprints (for the adaptive threshold
    /// so a small file, which yields few fingerprints, is still catchable).
    file_fps: HashMap<String, usize>,
    honeytokens: Vec<String>,
    pub files: usize,
}

/// A detected leak in an outbound body.
pub struct Leak {
    pub kind: &'static str, // "honeytoken" | "secret" | "code"
    pub detail: String,     // the token, the secret type, or the matched file
    pub score: usize,       // matched fingerprints (0 for honeytoken/secret)
    pub compressed: bool,   // the body was gzip/zlib compressed
}

/// Decompresses a gzip or zlib body (recognized by its magic bytes), capped to
/// defuse a decompression bomb. Returns None if it is not compressed or the
/// stream is corrupt. This lets scanning see through compressed exfiltration.
fn maybe_decompress(body: &[u8]) -> Option<Vec<u8>> {
    let reader: Box<dyn Read> = if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
        Box::new(flate2::read::GzDecoder::new(body))
    } else if body.len() >= 2 && body[0] == 0x78 && matches!(body[1], 0x01 | 0x9c | 0xda) {
        Box::new(flate2::read::ZlibDecoder::new(body))
    } else {
        return None;
    };
    let mut out = Vec::new();
    // A short read (corrupt tail) still yields the bytes decoded so far, which
    // is enough to scan; only a hard error with nothing decoded gives up.
    reader.take(DECOMP_CAP).read_to_end(&mut out).ok();
    (!out.is_empty()).then_some(out)
}

fn hash64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Sampled k-gram fingerprints of `data` (whitespace stripped).
fn fingerprints(data: &[u8]) -> Vec<u64> {
    let norm: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = vec![];
    if norm.len() < K {
        return out;
    }
    for i in 0..=norm.len() - K {
        let h = hash64(&norm[i..i + K]);
        if h & SAMPLE_MASK == 0 {
            out.push(h);
        }
    }
    out
}

fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0)
}

/// Well-known secret formats: (type name, prefix, minimum run of following
/// token characters). The prefixes are distinctive enough to keep false
/// positives near zero. Used to catch credentials leaving the sandbox even
/// when they are not part of the project's own files.
const SECRET_RULES: &[(&str, &str, usize)] = &[
    ("AWS access key", "AKIA", 16),
    ("AWS access key", "ASIA", 16),
    ("GitHub token", "ghp_", 30),
    ("GitHub token", "gho_", 30),
    ("GitHub token", "ghs_", 30),
    ("GitHub token", "ghu_", 30),
    ("GitHub token", "ghr_", 30),
    ("GitHub token", "github_pat_", 20),
    ("Google API key", "AIza", 30),
    ("Stripe key", "sk_live_", 20),
    ("Stripe key", "rk_live_", 20),
    ("Slack token", "xoxb-", 10),
    ("Slack token", "xoxp-", 10),
    ("Slack token", "xoxa-", 10),
    ("Slack token", "xoxr-", 10),
    ("OpenAI key", "sk-proj-", 20),
];

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Scans for a well-known secret format. Returns the secret TYPE only, never
/// the secret value itself (which must never be logged). Also catches PEM
/// private keys.
fn scan_secrets(text: &str) -> Option<&'static str> {
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        return Some("private key");
    }
    let bytes = text.as_bytes();
    for (name, prefix, min_len) in SECRET_RULES {
        let mut from = 0;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel + prefix.len();
            let run = bytes[start..]
                .iter()
                .take_while(|b| is_token_char(**b))
                .count();
            if run >= *min_len {
                return Some(name);
            }
            from = start; // advance past this occurrence and keep looking
        }
    }
    None
}

impl Detector {
    /// Indexes the project and loads honeytokens. Always returns a detector:
    /// known-secret scanning works even with no project files or honeytokens.
    pub fn index(project: &Path, honeytokens: Vec<String>) -> Option<Detector> {
        let mut fps = HashMap::new();
        let mut file_fps = HashMap::new();
        let mut files = 0usize;
        index_dir(project, project, &mut fps, &mut file_fps, &mut files);
        Some(Detector {
            fps,
            file_fps,
            honeytokens,
            files,
        })
    }

    /// Scans an outbound body. Returns the strongest leak signal, if any.
    /// A gzip/zlib body is transparently decompressed first, so compressed
    /// exfiltration is caught too. Order: honeytokens, known secrets, project
    /// code (with a per-file adaptive threshold).
    pub fn scan(&self, body: &[u8]) -> Option<Leak> {
        let decompressed = maybe_decompress(body);
        let compressed = decompressed.is_some();
        let data = decompressed.as_deref().unwrap_or(body);
        let text = String::from_utf8_lossy(data);

        // Honeytokens (exact, high confidence).
        for t in &self.honeytokens {
            if !t.is_empty() && text.contains(t.as_str()) {
                return Some(Leak {
                    kind: "honeytoken",
                    detail: t.clone(),
                    score: 0,
                    compressed,
                });
            }
        }
        // Well-known secret formats (AWS/GitHub/Google/Stripe/Slack, PEM keys).
        if let Some(kind) = scan_secrets(&text) {
            return Some(Leak {
                kind: "secret",
                detail: kind.to_string(),
                score: 0,
                compressed,
            });
        }
        // Project code: fingerprint overlap tallied per file. The threshold is
        // adaptive - a file that yields few fingerprints (a short file) needs
        // proportionally fewer matches, so a full copy of it is still caught,
        // while an accidental overlap with a large file still needs THRESHOLD.
        let mut per_file: HashMap<&str, usize> = HashMap::new();
        for h in fingerprints(data) {
            if let Some(file) = self.fps.get(&h) {
                *per_file.entry(file.as_str()).or_insert(0) += 1;
            }
        }
        per_file
            .into_iter()
            .filter(|(file, n)| {
                let total = self.file_fps.get(*file).copied().unwrap_or(THRESHOLD);
                *n >= total.clamp(2, THRESHOLD)
            })
            .max_by_key(|(_, n)| *n)
            .map(|(file, n)| Leak {
                kind: "code",
                detail: file.to_string(),
                score: n,
                compressed,
            })
    }
}

fn index_dir(
    root: &Path,
    dir: &Path,
    fps: &mut HashMap<u64, String>,
    file_fps: &mut HashMap<String, usize>,
    files: &mut usize,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            index_dir(root, &path, fps, file_fps, files);
        } else if ft.is_file() {
            if entry.metadata().map(|m| m.len() > MAX_FILE).unwrap_or(true) {
                continue;
            }
            let Ok(data) = std::fs::read(&path) else {
                continue;
            };
            if looks_binary(&data) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let distinct: std::collections::HashSet<u64> =
                fingerprints(&data).into_iter().collect();
            if distinct.is_empty() {
                continue;
            }
            file_fps.insert(rel.clone(), distinct.len());
            for h in distinct {
                fps.entry(h).or_insert_with(|| rel.clone());
            }
            *files += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Write;

    // A few lines of code: enough non-whitespace to yield well over THRESHOLD
    // sampled fingerprints.
    const CODE: &str = "fn compute_secret(seed: u64) -> u64 {\n    \
        let mut acc = seed.wrapping_mul(0xDEADBEEFCAFEBABE);\n    \
        for i in 0..64 { acc ^= (i as u64).rotate_left(13).wrapping_add(0x1337C0DE); }\n    \
        acc.wrapping_add(0xABADCAFEF00DFACE)\n}\n";
    const BENIGN: &str =
        "the quick brown fox jumps over the lazy dog, again and again and again, at noon.";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A detector holding one indexed "file" and the given honeytokens.
    fn detector(content: &str, honeytokens: Vec<String>) -> Detector {
        let mut fps = HashMap::new();
        let distinct: std::collections::HashSet<u64> =
            fingerprints(content.as_bytes()).into_iter().collect();
        let count = distinct.len();
        for h in distinct {
            fps.entry(h).or_insert_with(|| "src/x.rs".to_string());
        }
        let mut file_fps = HashMap::new();
        file_fps.insert("src/x.rs".to_string(), count);
        Detector {
            fps,
            file_fps,
            honeytokens,
            files: 1,
        }
    }

    #[test]
    fn fingerprints_are_deterministic_and_nonempty() {
        let a = fingerprints(CODE.as_bytes());
        let b = fingerprints(CODE.as_bytes());
        assert_eq!(a, b);
        assert!(a.len() > THRESHOLD, "got {} fingerprints", a.len());
    }

    #[test]
    fn fingerprints_ignore_whitespace() {
        // Same code, reformatted (indentation and newlines changed only).
        let reflowed = CODE.replace("    ", "\t").replace('\n', " \n  ");
        let mut a = fingerprints(CODE.as_bytes());
        let mut b = fingerprints(reflowed.as_bytes());
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "whitespace changes must not change fingerprints");
    }

    #[test]
    fn fingerprints_too_short_is_empty() {
        assert!(fingerprints(b"short").is_empty());
    }

    #[test]
    fn scan_detects_indexed_code() {
        let d = detector(CODE, vec![]);
        let leak = d.scan(CODE.as_bytes()).expect("code must be detected");
        assert_eq!(leak.kind, "code");
        assert_eq!(leak.detail, "src/x.rs");
        assert!(!leak.compressed);
        assert!(leak.score >= THRESHOLD);
    }

    #[test]
    fn scan_detects_reformatted_code() {
        let d = detector(CODE, vec![]);
        let reflowed = CODE.replace("    ", "\t\t").replace('\n', "\n\n");
        assert!(d.scan(reflowed.as_bytes()).is_some());
    }

    #[test]
    fn scan_ignores_benign_body() {
        let d = detector(CODE, vec![]);
        assert!(d.scan(BENIGN.as_bytes()).is_none());
    }

    #[test]
    fn scan_matches_honeytoken() {
        let d = detector(CODE, vec!["SUPER_SECRET_XYZ".to_string()]);
        let body = b"prefix junk SUPER_SECRET_XYZ trailing";
        let leak = d.scan(body).expect("honeytoken must be detected");
        assert_eq!(leak.kind, "honeytoken");
        assert_eq!(leak.detail, "SUPER_SECRET_XYZ");
    }

    #[test]
    fn scan_sees_through_gzip() {
        let d = detector(CODE, vec![]);
        let leak = d
            .scan(&gzip(CODE.as_bytes()))
            .expect("gzipped code detected");
        assert_eq!(leak.kind, "code");
        assert!(leak.compressed);
    }

    #[test]
    fn scan_sees_through_zlib() {
        let d = detector(CODE, vec![]);
        let leak = d.scan(&zlib(CODE.as_bytes())).expect("zlib code detected");
        assert!(leak.compressed);
    }

    #[test]
    fn maybe_decompress_roundtrips_and_rejects_plain() {
        assert_eq!(
            maybe_decompress(&gzip(CODE.as_bytes())).as_deref(),
            Some(CODE.as_bytes())
        );
        assert_eq!(
            maybe_decompress(&zlib(CODE.as_bytes())).as_deref(),
            Some(CODE.as_bytes())
        );
        assert!(maybe_decompress(CODE.as_bytes()).is_none());
    }

    #[test]
    fn index_counts_source_and_skips_deps_and_binary() {
        let root = std::env::temp_dir().join(format!("ci-detect-{}-{}", std::process::id(), "idx"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("src/a.rs"), CODE).unwrap();
        std::fs::write(root.join("node_modules/pkg/dep.js"), CODE).unwrap();
        std::fs::write(root.join("blob.bin"), b"\x00\x01\x02\x00binary\x00data").unwrap();

        let d = Detector::index(&root, vec![]).expect("something to index");
        assert_eq!(d.files, 1, "only src/a.rs should be indexed");

        // The one indexed file is detectable; content living only under
        // node_modules would be too if indexed, so verify the file label.
        let leak = d.scan(CODE.as_bytes()).expect("indexed code detected");
        assert_eq!(leak.detail, "src/a.rs");

        let _ = std::fs::remove_dir_all(&root);
    }

    // Test secrets are assembled from fragments via `concat!` so no full secret
    // pattern ever appears as a literal in this source file, which would trip
    // GitHub push protection / secret scanners. The runtime value is complete,
    // so the detector still sees a real match.
    const AWS_KEY: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

    #[test]
    fn scan_detects_known_secrets() {
        let d = detector(CODE, vec![]);
        let cases: [(&str, &str); 5] = [
            (AWS_KEY, "AWS access key"),
            (
                concat!("ghp_", "012345678901234567890123456789012345"),
                "GitHub token",
            ),
            (
                concat!("AIza", "SyA0000000000000000000000000000000000"),
                "Google API key",
            ),
            (
                concat!("sk_", "live_", "0123456789abcdefghijklmn"),
                "Stripe key",
            ),
            (
                concat!("-----BEGIN ", "OPENSSH PRIVATE ", "KEY-----\nabc\n-----END"),
                "private key",
            ),
        ];
        for (secret, want) in cases {
            let body = format!("prefix {secret} suffix");
            let leak = d.scan(body.as_bytes()).expect("secret must be detected");
            assert_eq!(leak.kind, "secret");
            assert_eq!(leak.detail, want, "case: {want}");
        }
    }

    #[test]
    fn scan_secrets_no_false_positive_on_benign() {
        let d = detector(CODE, vec![]);
        // Prefixes present but the trailing run is too short to qualify.
        assert!(scan_secrets(concat!("ghp_", "short and ", "AKIA", "tooshort")).is_none());
        assert!(d.scan(BENIGN.as_bytes()).is_none());
    }

    #[test]
    fn scan_secret_survives_gzip() {
        let d = detector(CODE, vec![]);
        let body = format!("key {AWS_KEY} tail");
        let leak = d
            .scan(&gzip(body.as_bytes()))
            .expect("gzipped secret detected");
        assert_eq!(leak.kind, "secret");
        assert!(leak.compressed);
    }

    #[test]
    fn adaptive_threshold_catches_small_file() {
        // A short file yields fewer than THRESHOLD fingerprints; a full copy of
        // it must still be detected thanks to the per-file adaptive threshold.
        let small = "fn tiny_unique_marker_42() -> u64 { 0xFEEDFACE }";
        let d = detector(small, vec![]);
        let fp = fingerprints(small.as_bytes()).len();
        assert!(
            fp < THRESHOLD,
            "test needs a small file (<{THRESHOLD} fp), got {fp}"
        );
        let leak = d
            .scan(small.as_bytes())
            .expect("small file leak must be caught");
        assert_eq!(leak.kind, "code");
    }
}
