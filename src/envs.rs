// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Dev environments: Landlock snippets embedded at compile time, presence
// checks, directories to pre-create, domains for --proxy.
//
// An environment flag installs NOTHING: it grants rights on an already
// installed toolchain. User extension: any file under
// ~/.config/claude-island/snippets/env-<name>.toml adds (or replaces) an
// environment, without a presence check.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct EnvSpec {
    pub name: String,
    pub aliases: &'static [&'static str],
    pub snippet: String,
    /// At least one of these commands must be in PATH (empty = no check).
    pub cmds: &'static [&'static str],
    /// All of these directories (relative to $HOME) must exist (empty = no check).
    pub dirs: &'static [&'static str],
    /// Directories (relative to $HOME) created upfront: a path_beneath rule
    /// requires an existing target.
    pub create: &'static [&'static str],
    /// Domains added to the proxy allowlist when this env is active.
    pub domains: &'static [&'static str],
}

#[allow(clippy::too_many_arguments)]
fn spec(
    name: &str,
    aliases: &'static [&'static str],
    snippet: &str,
    cmds: &'static [&'static str],
    dirs: &'static [&'static str],
    create: &'static [&'static str],
    domains: &'static [&'static str],
) -> EnvSpec {
    EnvSpec {
        name: name.to_string(),
        aliases,
        snippet: snippet.to_string(),
        cmds,
        dirs,
        create,
        domains,
    }
}

pub fn registry() -> Vec<EnvSpec> {
    let mut reg = vec![
        spec(
            "c",
            &["cpp"],
            include_str!("../snippets/env-c.toml"),
            &["cc", "gcc", "clang"],
            &[],
            &[".cache/ccache", ".ccache", ".conan2"],
            &["conan.io"],
        ),
        spec(
            "rust",
            &[],
            include_str!("../snippets/env-rust.toml"),
            &[],
            &[".cargo", ".rustup"],
            &[],
            &["crates.io", "static.crates.io", "index.crates.io"],
        ),
        spec(
            "go",
            &[],
            include_str!("../snippets/env-go.toml"),
            &["go"],
            &[],
            &["go", ".cache/go-build"],
            &["proxy.golang.org", "sum.golang.org"],
        ),
        spec(
            "python3",
            &[],
            include_str!("../snippets/env-python3.toml"),
            &["python3"],
            &[],
            &[".cache/pip", ".cache/uv", ".local/share/uv"],
            &["pypi.org", "files.pythonhosted.org"],
        ),
        spec(
            "node",
            &[],
            include_str!("../snippets/env-node.toml"),
            &["node", "npm"],
            &[],
            &[".npm", ".cache/yarn", ".local/share/pnpm", ".nvm"],
            &["registry.npmjs.org", "registry.yarnpkg.com"],
        ),
        spec(
            "deno",
            &[],
            include_str!("../snippets/env-deno.toml"),
            &["deno"],
            &[],
            &[".deno", ".cache/deno"],
            &["deno.land", "jsr.io"],
        ),
        spec(
            "bun",
            &[],
            include_str!("../snippets/env-bun.toml"),
            &["bun"],
            &[],
            &[".bun"],
            &["registry.npmjs.org", "bun.sh"],
        ),
        spec(
            "jvm",
            &["java", "kotlin", "scala"],
            include_str!("../snippets/env-jvm.toml"),
            &["java"],
            &[],
            &[
                ".m2",
                ".gradle",
                ".ivy2",
                ".sbt",
                ".cache/coursier",
                ".sdkman",
            ],
            &[
                "repo1.maven.org",
                "repo.maven.apache.org",
                "plugins.gradle.org",
                "services.gradle.org",
            ],
        ),
        spec(
            "ruby",
            &[],
            include_str!("../snippets/env-ruby.toml"),
            &["ruby"],
            &[],
            &[".gem", ".bundle", ".rbenv"],
            &["rubygems.org", "index.rubygems.org"],
        ),
        spec(
            "php",
            &[],
            include_str!("../snippets/env-php.toml"),
            &["php"],
            &[],
            &[".config/composer", ".composer", ".cache/composer"],
            &["packagist.org", "repo.packagist.org"],
        ),
        spec(
            "perl",
            &[],
            include_str!("../snippets/env-perl.toml"),
            &["perl"],
            &[],
            &["perl5", ".cpan", ".cpanm"],
            &["cpan.org", "metacpan.org"],
        ),
        spec(
            "dotnet",
            &[],
            include_str!("../snippets/env-dotnet.toml"),
            &["dotnet"],
            &[],
            &[".dotnet", ".nuget", ".templateengine"],
            &["nuget.org", "api.nuget.org"],
        ),
        spec(
            "haskell",
            &[],
            include_str!("../snippets/env-haskell.toml"),
            &["ghc", "stack", "cabal"],
            &[],
            &[".ghcup", ".cabal", ".stack"],
            &["hackage.haskell.org", "downloads.haskell.org"],
        ),
        spec(
            "elixir",
            &[],
            include_str!("../snippets/env-elixir.toml"),
            &["elixir", "mix"],
            &[],
            &[".mix", ".hex", ".cache/rebar3"],
            &["hex.pm", "repo.hex.pm"],
        ),
        spec(
            "zig",
            &[],
            include_str!("../snippets/env-zig.toml"),
            &["zig"],
            &[],
            &[".cache/zig"],
            &["ziglang.org"],
        ),
        spec(
            "mise",
            &[],
            include_str!("../snippets/env-mise.toml"),
            &["mise"],
            &[],
            &[".local/share/mise", ".cache/mise", ".config/mise"],
            &["mise.jdx.dev"],
        ),
    ];

    // User snippets: addition or replacement, without checks.
    if let Ok(home) = env::var("HOME") {
        let user_dir = Path::new(&home).join(".config/claude-island/snippets");
        if let Ok(entries) = fs::read_dir(&user_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                let Some(name) = fname
                    .strip_prefix("env-")
                    .and_then(|s| s.strip_suffix(".toml"))
                else {
                    continue;
                };
                let Ok(content) = fs::read_to_string(entry.path()) else {
                    continue;
                };
                if let Some(e) = reg.iter_mut().find(|e| e.name == name) {
                    e.snippet = content;
                } else {
                    reg.push(spec(name, &[], &content, &[], &[], &[], &[]));
                }
            }
        }
    }
    reg
}

/// Resolves a flag name (or alias) to the canonical environment name.
pub fn resolve(registry: &[EnvSpec], name: &str) -> Option<String> {
    registry
        .iter()
        .find(|e| e.name == name || e.aliases.contains(&name))
        .map(|e| e.name.clone())
}

pub fn has_cmd(name: &str) -> bool {
    let Ok(path) = env::var("PATH") else {
        return false;
    };
    path.split(':').any(|dir| {
        let p = Path::new(dir).join(name);
        p.is_file()
            && fs::metadata(&p)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
    })
}

pub fn verify(e: &EnvSpec, home: &Path) -> Result<(), String> {
    for d in e.dirs {
        if !home.join(d).is_dir() {
            return Err(format!(
                "--{}: ~/{d} not found. Install the toolchain outside the sandbox first.",
                e.name
            ));
        }
    }
    if !e.cmds.is_empty() && !e.cmds.iter().any(|c| has_cmd(c)) {
        return Err(format!(
            "--{}: none of ({}) found in PATH. Install the toolchain outside the sandbox first.",
            e.name,
            e.cmds.join(", ")
        ));
    }
    Ok(())
}

pub fn prepare(e: &EnvSpec, home: &Path) {
    for d in e.create {
        let _ = fs::create_dir_all(home.join(d));
    }
}
