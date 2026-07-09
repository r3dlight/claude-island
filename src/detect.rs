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
    honeytokens: Vec<String>,
    pub files: usize,
}

/// A detected leak in an outbound body.
pub struct Leak {
    pub kind: &'static str, // "honeytoken" | "code"
    pub detail: String,     // the token, or the matched file
    pub score: usize,       // matched fingerprints (0 for honeytoken)
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

impl Detector {
    /// Indexes the project and loads honeytokens. Returns None if there is
    /// nothing to detect (no indexable files and no honeytokens).
    pub fn index(project: &Path, honeytokens: Vec<String>) -> Option<Detector> {
        let mut fps = HashMap::new();
        let mut files = 0usize;
        index_dir(project, project, &mut fps, &mut files);
        if fps.is_empty() && honeytokens.is_empty() {
            return None;
        }
        Some(Detector {
            fps,
            honeytokens,
            files,
        })
    }

    /// Scans an outbound body. Returns the strongest leak signal, if any.
    /// A gzip/zlib body is transparently decompressed first, so compressed
    /// exfiltration is caught too.
    pub fn scan(&self, body: &[u8]) -> Option<Leak> {
        let decompressed = maybe_decompress(body);
        let compressed = decompressed.is_some();
        let data = decompressed.as_deref().unwrap_or(body);

        // Honeytokens first (exact, high confidence).
        if !self.honeytokens.is_empty() {
            let text = String::from_utf8_lossy(data);
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
        }
        // Fingerprint overlap, tallied per source file.
        let mut per_file: HashMap<&str, usize> = HashMap::new();
        for h in fingerprints(data) {
            if let Some(file) = self.fps.get(&h) {
                *per_file.entry(file.as_str()).or_insert(0) += 1;
            }
        }
        per_file
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .filter(|(_, n)| *n >= THRESHOLD)
            .map(|(file, n)| Leak {
                kind: "code",
                detail: file.to_string(),
                score: n,
                compressed,
            })
    }
}

fn index_dir(root: &Path, dir: &Path, fps: &mut HashMap<u64, String>, files: &mut usize) {
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
            index_dir(root, &path, fps, files);
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
            let mut added = false;
            for h in fingerprints(&data) {
                fps.entry(h).or_insert_with(|| rel.clone());
                added = true;
            }
            if added {
                *files += 1;
            }
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
        for h in fingerprints(content.as_bytes()) {
            fps.entry(h).or_insert_with(|| "src/x.rs".to_string());
        }
        Detector {
            fps,
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
}
