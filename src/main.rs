// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// claude-island: run Claude Code inside a Landlock sandbox via Island.
//
// Subcommands: (default) run, check, __canary (internal), __proxy (internal).
//
// Error handling: no panicking calls (unwrap/expect); everything bubbles up
// as Result<_, String> to main, which prints one clean message and exits 2.

mod canary;
mod envs;
mod explain;
mod profile;
mod project_config;
mod proxy;

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

type Result<T> = std::result::Result<T, String>;

/// Pinned Island version: a known-good commit, validated by the canary
/// suite (the --ro fix depends on Island internals). `claude-island update`
/// upgrades to exactly this revision; install.sh extracts it from this file.
const ISLAND_GIT: &str = "https://github.com/landlock-lsm/island";
const ISLAND_REV: &str = "05a9d699fbf30289fd2af4311becf38ceb334df2";

/// Environment variables scrubbed before entering the sandbox: Island does
/// not filter the environment (documented limitation). This fixed list
/// covers names that the suffix patterns below cannot catch.
const SCRUB_ENV: &[&str] = &[
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
];

/// Any variable whose uppercased name ends with one of these suffixes is
/// scrubbed too (fail closed: better a missing variable inside the sandbox
/// than a leaked secret).
const SCRUB_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_KEY",
    "_PASSWORD",
    "_PASSWD",
    "_CREDENTIALS",
];

/// Exceptions kept despite matching a scrub suffix.
const KEEP_ENV: &[&str] = &["ANTHROPIC_API_KEY"];

/// Domains always reachable in --proxy mode (Anthropic API + git over HTTPS).
const BASE_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "statsig.anthropic.com",
    "claude.ai",
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
];

const DEV_SERVE_PORTS: &[u16] = &[3000, 4321, 5173, 8000, 8080];

const HELP: &str = "\
claude-island: run Claude Code inside a Landlock sandbox via Island.

Usage:
  claude-island [OPTIONS] [-- CLAUDE_ARGS...]
  claude-island check [--<env>...] [--ro] [--proxy]
                                       verify the sandbox (canary suite)
  claude-island update                 update Island (pinned revision),
                                       rebuild claude-island, re-run checks
  claude-island explain [OPTIONS]      show what the profile would grant,
                                       without writing or running anything
  claude-island allow                  approve the project's .claude-island.toml
                                       (required again after any change)
  claude-island --list                 list available environments

Options:
  --<env>          grant access to an ALREADY INSTALLED toolchain
                   (stackable). Installs nothing: refuses if missing.
                   Aliases: --java/--kotlin/--scala -> jvm, --cpp -> c.
  --auto           detect environments from project files (Cargo.toml ->
                   rust, package.json -> node, go.mod -> go, ...); an
                   auto-detected env whose toolchain is missing is skipped
                   with a warning instead of refusing
  --ro             project in READ-ONLY mode (code review)
  --noexec         deny execve of project files (speed bump: interpreters
                   and the ld.so trick bypass it); combines with --ro
  --deny NAME      protect a top-level project entry (e.g. .git, .env,
                   secrets): its file contents become unreadable and it
                   cannot be written (repeatable). Names may still appear in
                   a listing. Trade-off: no new files at the project root.
  --proxy          network restricted to a domain-filtering proxy
                   (allowlist: base domains + environments + --allow +
                   ~/.config/claude-island/domains.allow)
  --allow DOMAIN   add a domain to the proxy allowlist (repeatable)
  --serve          allow TCP bind on 3000, 4321, 5173, 8000, 8080
  --ports P1,P2    additional bind ports
  --dry-run        generate the profile and print the command without running
  --list           list environments and aliases
  -h, --help       this help

A .claude-island.toml at the project root provides per-project defaults
(envs, auto, ro, noexec, proxy, serve, ports, allow), merged with the
command line. It is refused until approved with `claude-island allow`.

Env: CLAUDE_ISLAND_MEM (default 8G), CLAUDE_ISLAND_TASKS (default 4096)
";

#[derive(Default)]
struct Opts {
    env_names: Vec<String>,
    auto: bool,
    ro: bool,
    noexec: bool,
    deny: Vec<String>,
    proxy: bool,
    serve: bool,
    ports: Vec<u16>,
    allow: Vec<String>,
    dry_run: bool,
    rest: Vec<String>,
}

/// What argument parsing decided: run/check with options, or an
/// informational action already fully described.
enum Parsed {
    Go(Opts),
    Help,
    List,
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    spec.split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port: {p}"))
        })
        .collect()
}

fn parse(args: &[String], registry: &[envs::EnvSpec]) -> Result<Parsed> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--auto" => o.auto = true,
            "--ro" => o.ro = true,
            "--noexec" => o.noexec = true,
            "--proxy" => o.proxy = true,
            "--serve" => o.serve = true,
            "--dry-run" => o.dry_run = true,
            "--ports" => {
                i += 1;
                let v = args.get(i).ok_or("--ports expects a port list")?;
                o.ports.extend(parse_ports(v)?);
            }
            "--allow" => {
                i += 1;
                let v = args.get(i).ok_or("--allow expects a domain")?;
                o.allow.push(v.clone());
            }
            "--deny" => {
                i += 1;
                let v = args.get(i).ok_or("--deny expects a project top-level name")?;
                o.deny.push(v.clone());
            }
            "--list" => return Ok(Parsed::List),
            "-h" | "--help" => return Ok(Parsed::Help),
            "--" => {
                o.rest = args[i + 1..].to_vec();
                break;
            }
            s if s.starts_with("--") => match envs::resolve(registry, &s[2..]) {
                Some(name) => {
                    if !o.env_names.contains(&name) {
                        o.env_names.push(name);
                    }
                }
                None => return Err(format!("unknown option or environment: {s} (see --list)")),
            },
            _ => return Err(format!("unknown argument: {a} (see --help)")),
        }
        i += 1;
    }
    Ok(Parsed::Go(o))
}

fn print_list(registry: &[envs::EnvSpec]) {
    for e in registry {
        let alias = if e.aliases.is_empty() {
            String::new()
        } else {
            format!(
                "  (aliases: {})",
                e.aliases
                    .iter()
                    .map(|a| format!("--{a}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        println!("--{}{}", e.name, alias);
    }
}

/// Guards: the project is the current directory, under $HOME, not $HOME.
fn guards() -> Result<(PathBuf, PathBuf)> {
    let home = PathBuf::from(env::var("HOME").map_err(|_| "HOME is not set")?);
    let project = env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| format!("cannot read the current directory: {e}"))?;
    if project == home {
        return Err("refusing to sandbox $HOME itself, run from a project directory".into());
    }
    if !project.starts_with(&home) {
        return Err(format!(
            "the project must live under $HOME ({})",
            project.display()
        ));
    }
    Ok((home, project))
}

/// Validates deny entries: v1 supports project top-level names only (a
/// nested deny like `src/secret` cannot be carved without also restricting
/// `src`, which is surprising, so it is rejected for now).
fn validate_deny(deny: &[String]) -> Result<()> {
    for d in deny {
        if d.is_empty() || d == "." || d == ".." || d.contains('/') || d.contains('\\') {
            return Err(format!(
                "--deny {d}: only project top-level names are supported (no '/', no '..')"
            ));
        }
    }
    Ok(())
}

/// Merges the project's .claude-island.toml (if any) into the options.
/// The file must have been approved with `claude-island allow`; explain is
/// lenient (warns and applies anyway, so the file can be reviewed).
fn apply_project_config(
    mut o: Opts,
    home: &std::path::Path,
    project: &std::path::Path,
    registry: &[envs::EnvSpec],
    lenient: bool,
) -> Result<Opts> {
    let path = project.join(project_config::FILE_NAME);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Ok(o);
    };
    let cfg = project_config::parse(&content).map_err(|e| format!("{}: {e}", path.display()))?;
    if !project_config::is_approved(home, project, &content) {
        let msg = format!(
            "{} is present but not approved: review it, then run `claude-island allow` \
             (required again after any change)",
            path.display()
        );
        if lenient {
            eprintln!("claude-island: warning: {msg}");
        } else {
            return Err(msg);
        }
    }
    eprintln!(
        "claude-island: applied {} ({})",
        project_config::FILE_NAME,
        project_config::summary(&cfg)
    );
    for n in &cfg.envs {
        let name = envs::resolve(registry, n)
            .ok_or_else(|| format!("{}: unknown environment: {n}", path.display()))?;
        if !o.env_names.contains(&name) {
            o.env_names.push(name);
        }
    }
    o.auto |= cfg.auto;
    o.ro |= cfg.ro;
    o.noexec |= cfg.noexec;
    o.proxy |= cfg.proxy;
    o.serve |= cfg.serve;
    o.ports.extend(cfg.ports);
    o.allow.extend(cfg.allow);
    o.deny.extend(cfg.deny);
    Ok(o)
}

/// Resolves the final environment list: explicit flags plus, with --auto,
/// the environments detected from project files. Explicit environments must
/// pass the toolchain check; auto-detected ones are skipped with a warning
/// when their toolchain is missing. `check_presence` is off for explain.
fn resolve_envs<'a>(
    o: &Opts,
    registry: &'a [envs::EnvSpec],
    project: &std::path::Path,
    home: &std::path::Path,
    check_presence: bool,
) -> Result<Vec<&'a envs::EnvSpec>> {
    let mut names = o.env_names.clone();
    let mut auto_names: Vec<String> = vec![];
    if o.auto {
        for n in envs::auto_detect(project, registry) {
            if !names.contains(&n) {
                names.push(n.clone());
                auto_names.push(n);
            }
        }
        if auto_names.is_empty() {
            eprintln!("claude-island: --auto: no environment detected");
        } else {
            eprintln!(
                "claude-island: --auto: detected environments: {}",
                auto_names.join(", ")
            );
        }
    }
    let mut sel = vec![];
    for n in &names {
        let e = registry
            .iter()
            .find(|e| &e.name == n)
            .ok_or_else(|| format!("internal error: unresolved environment {n}"))?;
        if !check_presence {
            sel.push(e);
            continue;
        }
        match envs::verify(e, home) {
            Ok(()) => {
                envs::prepare(e, home);
                sel.push(e);
            }
            Err(msg) if auto_names.contains(n) => {
                eprintln!("claude-island: --auto: skipping {msg}");
            }
            Err(msg) => return Err(msg),
        }
    }
    Ok(sel)
}

/// Proxy allowlist: base + environments + user file + --allow.
fn proxy_domains(sel: &[&envs::EnvSpec], allow: &[String], home: &std::path::Path) -> Vec<String> {
    let mut domains: Vec<String> = BASE_DOMAINS.iter().map(|s| s.to_string()).collect();
    for e in sel {
        domains.extend(e.domains.iter().map(|s| s.to_string()));
    }
    let user_file = home.join(".config/claude-island/domains.allow");
    if let Ok(content) = std::fs::read_to_string(&user_file) {
        for line in content.lines() {
            let d = line.split('#').next().unwrap_or("").trim();
            if !d.is_empty() {
                domains.push(d.to_string());
            }
        }
    }
    domains.extend(allow.iter().cloned());
    domains.sort();
    domains.dedup();
    domains
}

fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(c) => ExitCode::from(u8::try_from(c).unwrap_or(1)),
        None => ExitCode::from(1), // killed by a signal
    }
}

/// Removes secrets from a child's environment: the fixed names plus every
/// variable matching a scrub suffix, minus the KEEP_ENV exceptions.
fn scrub_env(cmd: &mut Command) {
    for v in SCRUB_ENV {
        cmd.env_remove(v);
    }
    for (k, _) in env::vars() {
        if KEEP_ENV.contains(&k.as_str()) {
            continue;
        }
        let up = k.to_ascii_uppercase();
        if SCRUB_SUFFIXES.iter().any(|s| up.ends_with(s)) {
            cmd.env_remove(&k);
        }
    }
}

/// Network configuration shared by run and check: direct ports, or the
/// filtering proxy. The Proxy handle must stay alive for the whole session.
struct NetSetup {
    connect_ports: Vec<u16>,
    extra_env: Vec<(String, String)>,
    _proxy: Option<proxy::Proxy>,
}

fn setup_network(o: &Opts, sel: &[&envs::EnvSpec], home: &std::path::Path) -> Result<NetSetup> {
    if !o.proxy {
        return Ok(NetSetup {
            connect_ports: vec![443, 80, 53],
            extra_env: vec![],
            _proxy: None,
        });
    }
    let domains = proxy_domains(sel, &o.allow, home);
    let log = home.join(".cache/claude-island/proxy.log");
    let p = proxy::start(domains, &log).map_err(|e| format!("cannot start the proxy: {e}"))?;
    eprintln!(
        "claude-island: filtering proxy on 127.0.0.1:{} (log: {})",
        p.port,
        log.display()
    );
    let mut extra_env = vec![];
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        extra_env.push((k.to_string(), format!("http://127.0.0.1:{}", p.port)));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        extra_env.push((k.to_string(), "localhost,127.0.0.1".to_string()));
    }
    Ok(NetSetup {
        connect_ports: vec![p.port, 53],
        extra_env,
        _proxy: Some(p),
    })
}

fn cmd_run(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, false)?;
    validate_deny(&o.deny)?;
    let sel = resolve_envs(&o, registry, &project, &home, true)?;

    let net = setup_network(&o, &sel, &home)?;

    let mut serve_ports: Vec<u16> = vec![];
    if o.serve {
        serve_ports.extend_from_slice(DEV_SERVE_PORTS);
    }
    serve_ports.extend(&o.ports);

    let prof = profile::generate(
        &home,
        &project,
        &sel,
        o.ro,
        o.noexec,
        &o.deny,
        &serve_ports,
        &net.connect_ports,
        &net.extra_env,
    )
    .map_err(|e| format!("profile generation: {e}"))?;

    let mut argv: Vec<String> = vec![];
    if envs::has_cmd("systemd-run") {
        argv.extend(
            ["systemd-run", "--user", "--scope", "--quiet", "--same-dir"]
                .iter()
                .map(|s| s.to_string()),
        );
        let mem = env::var("CLAUDE_ISLAND_MEM").unwrap_or_else(|_| "8G".into());
        let tasks = env::var("CLAUDE_ISLAND_TASKS").unwrap_or_else(|_| "4096".into());
        argv.push("-p".into());
        argv.push(format!("MemoryMax={mem}"));
        argv.push("-p".into());
        argv.push(format!("TasksMax={tasks}"));
    }
    argv.extend(
        ["island", "run", "-p", &prof.name, "--", "claude"]
            .iter()
            .map(|s| s.to_string()),
    );
    argv.extend(o.rest.iter().cloned());

    if o.dry_run {
        println!("generated profile: {}", prof.dir.display());
        println!("scrubbed variables: {}", SCRUB_ENV.join(", "));
        println!(
            "scrubbed patterns: *{} (kept: {})",
            SCRUB_SUFFIXES.join(", *"),
            KEEP_ENV.join(", ")
        );
        println!("command: {}", argv.join(" "));
        return Ok(ExitCode::SUCCESS);
    }
    if !envs::has_cmd("island") {
        return Err("island not found in PATH: run ./install.sh first".into());
    }

    // Ctrl+C must reach the sandboxed claude (same process group), not kill
    // the wrapper, which carries the proxy.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    scrub_env(&mut cmd);
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run {}: {e}", argv[0]))?;
    Ok(exit_code(status))
}

fn cmd_check(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, false)?;
    validate_deny(&o.deny)?;
    let sel = resolve_envs(&o, registry, &project, &home, true)?;
    if !envs::has_cmd("island") {
        return Err("island not found in PATH: run ./install.sh first".into());
    }
    let net = setup_network(&o, &sel, &home)?;

    // Canary artifacts, created BEFORE profile generation so the carve logic
    // (deny mode) enumerates and grants them: a dedicated dir holding the
    // exec/write probes (a top-level entry, granted in every mode), plus, in
    // deny mode, a synthetic denied dir with a secret to prove carving hides
    // it. Cleaned up afterwards.
    let canary_dir = project.join(".claude-island-canary-dir");
    std::fs::create_dir_all(&canary_dir)
        .map_err(|e| format!("creating canary dir: {e}"))?;
    std::fs::copy("/usr/bin/true", canary_dir.join("exec"))
        .map_err(|e| format!("exec probe copy: {e}"))?;

    let mut deny = o.deny.clone();
    let denied_dir = project.join(".claude-island-canary-denied");
    if !deny.is_empty() {
        std::fs::create_dir_all(&denied_dir).map_err(|e| format!("creating denied dir: {e}"))?;
        std::fs::write(denied_dir.join("secret"), "canary-secret\n")
            .map_err(|e| format!("writing denied secret: {e}"))?;
        deny.push(".claude-island-canary-denied".to_string());
    }

    let prof = profile::generate(
        &home,
        &project,
        &sel,
        o.ro,
        o.noexec,
        &deny,
        &[],
        &net.connect_ports,
        &net.extra_env,
    )
    .map_err(|e| format!("profile generation: {e}"))?;

    // The current binary is copied into ~/.local/bin (read + exec in every
    // profile) then re-run in canary mode. All copies happen before
    // sandboxing.
    let exe = env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bin_dir = home.join(".local/bin");
    std::fs::create_dir_all(&bin_dir)
        .map_err(|e| format!("creating {}: {e}", bin_dir.display()))?;
    let target = bin_dir.join(".claude-island-canary");
    std::fs::copy(&exe, &target).map_err(|e| format!("canary copy: {e}"))?;

    eprintln!("claude-island: canaries inside sandbox \"{}\"", prof.name);
    let mut cmd = Command::new("island");
    cmd.args(["run", "-p", &prof.name, "--"])
        .arg(&target)
        .arg("__canary");
    if o.ro {
        cmd.arg("--ro");
    }
    if o.noexec {
        cmd.arg("--noexec");
    }
    if o.proxy {
        cmd.arg("--proxy");
    }
    for d in &deny {
        cmd.arg("--deny").arg(d);
    }
    let status = cmd.status();
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_dir_all(&canary_dir);
    let _ = std::fs::remove_dir_all(&denied_dir);
    let status = status.map_err(|e| format!("failed to run island: {e}"))?;
    Ok(exit_code(status))
}

/// `explain`: a human-readable summary of what the profile would grant,
/// computed from the same inputs as run/check but with no side effect
/// (nothing written, no proxy started, no toolchain check).
fn cmd_explain(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, true)?;
    validate_deny(&o.deny)?;
    let sel = resolve_envs(&o, registry, &project, &home, false)?;
    let home_str = home.to_string_lossy().to_string();
    let project_str = project.to_string_lossy().to_string();
    let display = |p: &str| -> String {
        let p = p
            .replace("${home}", &home_str)
            .replace("${project}", &project_str);
        match p.strip_prefix(&home_str) {
            Some(rest) if !rest.is_empty() => format!("~{rest}"),
            _ => p,
        }
    };

    println!(
        "profile: {}",
        profile::name_for(&project, &sel, o.ro, o.noexec, !o.deny.is_empty())
    );
    let mode = match (o.ro, o.noexec) {
        (false, false) => "rw + exec",
        (true, false) => "read + exec (--ro)",
        (false, true) => "rw, no exec (--noexec)",
        (true, true) => "read-only (--ro --noexec)",
    };
    println!("project: {} [{mode}]", project.display());

    // Filesystem: rules from the embedded snippets plus the generated
    // project rule, grouped by access level.
    let mut groups: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    let mut texts: Vec<&str> = vec![profile::BASE, profile::CLAUDE];
    for e in &sel {
        texts.push(&e.snippet);
    }
    for text in texts {
        for rule in explain::path_rules(text) {
            let label = explain::label(&rule.access);
            for parent in &rule.parents {
                groups.entry(label).or_default().push(display(parent));
            }
        }
    }
    let project_label = match (o.ro, o.noexec) {
        (false, false) => "rw + exec",
        (true, false) => "read + exec",
        (false, true) => "rw",
        (true, true) => "read-only",
    };
    groups
        .entry(project_label)
        .or_default()
        .insert(0, "<project>".into());

    println!("\nfilesystem (everything not listed is denied)");
    for label in explain::LABELS {
        if let Some(paths) = groups.get(label) {
            println!("  {label:<11} {}", paths.join(", "));
        }
    }
    if !o.deny.is_empty() {
        println!(
            "  protected   {} (contents unreadable, unwritable; names may still list)",
            o.deny.join(", ")
        );
    }

    println!("\nnetwork");
    if o.proxy {
        let domains = proxy_domains(&sel, &o.allow, &home);
        println!("  outbound     only the filtering proxy on 127.0.0.1 (ephemeral port)");
        println!(
            "  allowlist    {} domains: {}",
            domains.len(),
            domains.join(", ")
        );
    } else {
        println!("  outbound     TCP 443, 80, 53 to ANY host (UDP is not restricted)");
    }
    let mut serve_ports: Vec<u16> = vec![];
    if o.serve {
        serve_ports.extend_from_slice(DEV_SERVE_PORTS);
    }
    serve_ports.extend(&o.ports);
    if serve_ports.is_empty() {
        println!("  listening    denied");
    } else {
        let ports: Vec<String> = serve_ports.iter().map(|p| p.to_string()).collect();
        println!("  listening    TCP {}", ports.join(", "));
    }

    println!("\nworkspaces (isolated per profile, full access inside)");
    println!("  XDG_CONFIG_HOME, XDG_DATA_HOME, XDG_STATE_HOME, XDG_CACHE_HOME,");
    println!("  XDG_RUNTIME_DIR, TMPDIR");
    if !o.ro && !o.noexec {
        println!("  note: Island also grants full access beneath the project (context path)");
    }

    println!("\nenvironment");
    let mut injected = vec![
        format!(
            "CLAUDE_CONFIG_DIR={}",
            display(&home.join(".claude").to_string_lossy())
        ),
        "DISABLE_AUTOUPDATER=1".to_string(),
    ];
    if o.proxy {
        injected.push("HTTP(S)_PROXY -> the filtering proxy".to_string());
    }
    println!("  injected     {}", injected.join(", "));
    println!("  scrubbed     {}", SCRUB_ENV.join(", "));
    println!(
        "               plus any *{} (kept: {})",
        SCRUB_SUFFIXES.join(", *"),
        KEEP_ENV.join(", ")
    );

    let mem = env::var("CLAUDE_ISLAND_MEM").unwrap_or_else(|_| "8G".into());
    let tasks = env::var("CLAUDE_ISLAND_TASKS").unwrap_or_else(|_| "4096".into());
    println!("\nlimits (systemd-run)");
    println!("  MemoryMax={mem}, TasksMax={tasks}");
    Ok(ExitCode::SUCCESS)
}

/// `allow`: approve the project's .claude-island.toml (records its content
/// hash; any later change to the file requires a new approval).
fn cmd_allow(registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let path = project.join(project_config::FILE_NAME);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cfg = project_config::parse(&content).map_err(|e| format!("{}: {e}", path.display()))?;
    for n in &cfg.envs {
        envs::resolve(registry, n)
            .ok_or_else(|| format!("{}: unknown environment: {n}", path.display()))?;
    }
    project_config::approve(&home, &project, &content)?;
    println!("approved {} for {}", project_config::FILE_NAME, project.display());
    println!("  {}", project_config::summary(&cfg));
    println!("any change to the file will require a new `claude-island allow`");
    Ok(ExitCode::SUCCESS)
}

/// Runs a command and turns a failure into an error message.
fn run_step(desc: &str, program: &str, args: &[&str]) -> Result<()> {
    eprintln!("claude-island: {desc}");
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("{desc}: failed to run {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{desc}: {program} exited with {status}"))
    }
}

/// Update everything in one safe operation: Island at the pinned revision,
/// this binary rebuilt from its sources, Island profile defaults refreshed,
/// then the canary suites when run from a project directory.
fn cmd_update() -> Result<ExitCode> {
    let home = env::var("HOME").map_err(|_| "HOME is not set")?;

    run_step(
        &format!("installing Island at pinned revision {}", &ISLAND_REV[..12]),
        "cargo",
        &[
            "install", "--locked", "--force", "--git", ISLAND_GIT, "--rev", ISLAND_REV, "island",
        ],
    )?;
    run_step(
        "refreshing Island profile defaults",
        "island",
        &["update", "--all"],
    )?;

    // Rebuild this binary if its sources are still where it was built from.
    let manifest = env!("CARGO_MANIFEST_DIR");
    if std::path::Path::new(manifest).join("Cargo.toml").exists() {
        let root = format!("{home}/.local");
        run_step(
            &format!("rebuilding claude-island from {manifest}"),
            "cargo",
            &["install", "--path", manifest, "--root", &root],
        )?;
    } else {
        eprintln!("claude-island: sources not found at {manifest}, skipping self-rebuild");
    }

    // Validate, if we are inside a project; otherwise tell the user how.
    if guards().is_ok() {
        let exe = env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        for args in [vec!["check"], vec!["check", "--ro"]] {
            let status = Command::new(&exe)
                .args(&args)
                .status()
                .map_err(|e| format!("failed to re-run {}: {e}", args.join(" ")))?;
            if !status.success() {
                return Err(format!(
                    "validation failed: claude-island {}",
                    args.join(" ")
                ));
            }
        }
        eprintln!("claude-island: update complete, sandbox validated");
    } else {
        eprintln!(
            "claude-island: update complete; run `claude-island check` and \
             `claude-island check --ro` from a project directory to validate"
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn dispatch(args: &[String]) -> Result<ExitCode> {
    match args.first().map(String::as_str) {
        Some("__canary") => {
            let rest = &args[1..];
            let deny: Vec<String> = rest
                .iter()
                .enumerate()
                .filter(|(i, a)| *a == "--deny" && rest.get(i + 1).is_some())
                .map(|(i, _)| rest[i + 1].clone())
                .collect();
            Ok(canary::run_all(canary::Modes {
                ro: rest.iter().any(|a| a == "--ro"),
                noexec: rest.iter().any(|a| a == "--noexec"),
                proxy: rest.iter().any(|a| a == "--proxy"),
                deny,
            }))
        }
        Some("__proxy") => proxy::standalone(&args[1..]),
        Some("update") => cmd_update(),
        Some("allow") => {
            let registry = envs::registry();
            cmd_allow(&registry)
        }
        Some("explain") => {
            let registry = envs::registry();
            match parse(&args[1..], &registry)? {
                Parsed::Go(o) => cmd_explain(o, &registry),
                Parsed::Help => {
                    print!("{HELP}");
                    Ok(ExitCode::SUCCESS)
                }
                Parsed::List => {
                    print_list(&registry);
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        Some("check") => {
            let registry = envs::registry();
            match parse(&args[1..], &registry)? {
                Parsed::Go(o) => cmd_check(o, &registry),
                Parsed::Help => {
                    print!("{HELP}");
                    Ok(ExitCode::SUCCESS)
                }
                Parsed::List => {
                    print_list(&registry);
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
        _ => {
            let registry = envs::registry();
            match parse(args, &registry)? {
                Parsed::Go(o) => cmd_run(o, &registry),
                Parsed::Help => {
                    print!("{HELP}");
                    Ok(ExitCode::SUCCESS)
                }
                Parsed::List => {
                    print_list(&registry);
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("claude-island: {e}");
            ExitCode::from(2)
        }
    }
}
