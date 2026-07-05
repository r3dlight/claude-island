// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// Island profile generation: one profile per (project, environments,
// options), regenerated on every launch. The embedded snippets are the
// source of truth; files within a single profile compose as a union.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::envs::EnvSpec;

const BASE: &str = include_str!("../snippets/00-base.toml");
const CLAUDE: &str = include_str!("../snippets/10-claude.toml");

/// Common header: every handled access is denied by default in each file.
const HEADER: &str = "abi = 6\n\n[[ruleset]]\nhandled_access_fs = [\"abi.all\"]\nhandled_access_net = [\"abi.all\"]\nscoped = [\"abi.all\"]\n";

pub struct Profile {
    pub name: String,
    pub dir: PathBuf,
}

/// FNV-1a 64 folded to 32 bits: stable profile name for a given path.
fn hash8(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", (h as u32) ^ ((h >> 32) as u32))
}

fn slug(project: &Path) -> String {
    project
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".into())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn ports_toml(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn toml_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn generate(
    home: &Path,
    project: &Path,
    envs: &[&EnvSpec],
    ro: bool,
    noexec: bool,
    serve_ports: &[u16],
    connect_ports: &[u16],
    extra_env: &[(String, String)],
) -> io::Result<Profile> {
    // rw targets of the claude profile: created upfront.
    for d in [".claude", ".cache/claude", ".cache/claude-cli-nodejs"] {
        fs::create_dir_all(home.join(d))?;
    }

    let env_tag = if envs.is_empty() {
        String::new()
    } else {
        format!(
            "-{}",
            envs.iter().map(|e| e.name.as_str()).collect::<Vec<_>>().join("-")
        )
    };
    let ro_tag = if ro { "-ro" } else { "" };
    let noexec_tag = if noexec { "-noexec" } else { "" };
    let name = format!(
        "claude-{}{}{}{}-{}",
        slug(project),
        env_tag,
        ro_tag,
        noexec_tag,
        hash8(&project.to_string_lossy())
    );
    let dir = home.join(".config/island/profiles").join(&name);
    let _ = fs::remove_dir_all(&dir);
    let landlock = dir.join("landlock");
    fs::create_dir_all(&landlock)?;

    fs::write(landlock.join("00-base.toml"), BASE)?;
    fs::write(landlock.join("10-claude.toml"), CLAUDE)?;
    for e in envs {
        fs::write(landlock.join(format!("env-{}.toml", e.name)), &e.snippet)?;
    }

    fs::write(
        landlock.join("05-vars.toml"),
        format!(
            "{HEADER}\n[[variable]]\nname = \"home\"\nliteral = [\"{}\"]\n\n\
             [[variable]]\nname = \"project\"\nliteral = [\"{}\"]\n",
            toml_str(&home.to_string_lossy()),
            toml_str(&project.to_string_lossy()),
        ),
    )?;

    // The project: rw + exec by default; --ro drops write, --noexec drops
    // execve of project files (a speed bump only: interpreters and the
    // ld.so trick bypass it, see README), and they combine.
    let access = match (ro, noexec) {
        (false, false) => r#""abi.read_write", "abi.read_execute""#,
        (true, false) => r#""abi.read_execute""#,
        (false, true) => r#""abi.read_write""#,
        (true, true) => r#""read_file", "read_dir""#,
    };
    fs::write(
        landlock.join("15-project.toml"),
        format!("{HEADER}\n[[path_beneath]]\nallowed_access = [{access}]\nparent = [\"${{project}}\"]\n"),
    )?;

    fs::write(
        landlock.join("30-net.toml"),
        format!(
            "{HEADER}\n[[net_port]]\nallowed_access = [\"connect_tcp\"]\nport = [{}]\n",
            ports_toml(connect_ports)
        ),
    )?;
    if !serve_ports.is_empty() {
        fs::write(
            landlock.join("20-serve.toml"),
            format!(
                "{HEADER}\n[[net_port]]\nallowed_access = [\"bind_tcp\"]\nport = [{}]\n",
                ports_toml(serve_ports)
            ),
        )?;
    }

    // Island grants FULL filesystem access (write AND execute) beneath
    // every [[context]] when_beneath path (treated as a workspace,
    // AccessFs::from_all in island's workspace.rs), which would override a
    // restricted project rule by union. In --ro and --noexec modes the
    // profile therefore declares no context: it is only usable through
    // explicit selection (-p), which is how the wrapper always launches it.
    let mut p = if ro || noexec {
        String::new()
    } else {
        format!(
            "[[context]]\nwhen_beneath = \"{}\"\n",
            toml_str(&project.to_string_lossy())
        )
    };
    let claude_config = home.join(".claude");
    let mut env_entries: Vec<(String, String)> = vec![
        ("CLAUDE_CONFIG_DIR".into(), claude_config.to_string_lossy().into_owned()),
        ("DISABLE_AUTOUPDATER".into(), "1".into()),
    ];
    env_entries.extend(extra_env.iter().cloned());
    for (k, v) in &env_entries {
        p.push_str(&format!(
            "\n[[env]]\nname = \"{}\"\nliteral = \"{}\"\n",
            toml_str(k),
            toml_str(v)
        ));
    }
    fs::write(dir.join("profile.toml"), p)?;

    Ok(Profile { name, dir })
}
