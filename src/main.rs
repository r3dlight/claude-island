// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// claude-island: run Claude Code inside a Landlock sandbox via Island.
//
// Subcommands: (default) run, check, __canary (internal), __proxy (internal).
//
// Error handling: no panicking calls (unwrap/expect); everything bubbles up
// as Result<_, String> to main, which prints one clean message and exits 2.

mod broker;
mod canary;
mod denials;
mod detect;
mod envs;
mod explain;
mod profile;
mod project_config;
mod proxy;
mod pty;
mod report;

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

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
  claude-island                        no args in a terminal: interactive setup
                                       (set CLAUDE_ISLAND_NO_WIZARD=1 to skip)
  claude-island [OPTIONS] [-- CLAUDE_ARGS...]
  claude-island check [--<env>...] [--ro] [--proxy]
                                       verify the sandbox (canary suite)
  claude-island update                 update Island (pinned revision),
                                       rebuild claude-island, re-run checks
  claude-island explain [OPTIONS]      show what the profile would grant,
                                       without writing or running anything
  claude-island denials [OPTS] -- CMD  run CMD in the sandbox and report every
                                       access it denied (add --json for JSONL)
  claude-island allow                  approve the project's .claude-island.toml
                                       (required again after any change)
  claude-island report [--all]         summarize what tried to leave the sandbox
                                       (leak attempts + L7 denials from the audit)
  claude-island watch                  live-approve domains blocked by --ask
  claude-island approve [DOMAIN...]    approve blocked domains (--all for every
                                       pending one); no args lists them
  claude-island completion SHELL       print a completion script (bash/zsh/fish)
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
  --ask            implies --proxy; a blocked domain is recorded as pending
                   (approve later with `claude-island watch`/`approve`),
                   asynchronously, without touching the agent's terminal
  --broker         implies --proxy; make gh/git work against GitHub without
                   the token entering the sandbox (TLS-terminating broker
                   using GITHUB_TOKEN/GH_TOKEN from your environment)
  --inspect        implies --proxy; TLS-terminate EVERY host and record every
                   outbound request (method, host, path, body preview) to
                   ~/.cache/claude-island/outbound-audit.log (leak detection).
                   May break tools that pin certs or require HTTP/2
  --detect         implies --inspect; fingerprint the project's files (plus
                   honeytokens from ~/.config/claude-island/honeytokens) and
                   BLOCK any outbound request (to a non-Anthropic host) that
                   carries your local code, with an alert in the audit log
  --l7             implies --proxy; enforce a method/path allowlist from
                   ~/.config/claude-island/l7.rules (lines: `host METHOD glob`)
                   on TLS-terminated hosts; a listed host is default-deny
                   (e.g. let the GitHub token GET issues but not DELETE repos)
  --allow DOMAIN   add a domain to the proxy allowlist (repeatable)
  --serve          allow TCP bind on 3000, 4321, 5173, 8000, 8080
  --ports P1,P2    additional bind ports
  --mem SIZE       memory limit for the session (default 8G; systemd MemoryMax)
  --tasks N        max processes/threads (default 4096; systemd TasksMax)
  --dry-run        generate the profile and print the command without running
  --json           machine-readable JSONL output (denials only)
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
    ask: bool,
    broker: bool,
    inspect: bool,
    detect: bool,
    l7: bool,
    serve: bool,
    ports: Vec<u16>,
    allow: Vec<String>,
    dry_run: bool,
    json: bool,
    mem: Option<String>,
    tasks: Option<String>,
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
            "--ask" => {
                o.proxy = true;
                o.ask = true;
            }
            "--broker" => {
                o.proxy = true;
                o.broker = true;
            }
            "--inspect" => {
                o.proxy = true;
                o.inspect = true;
            }
            "--detect" => {
                o.proxy = true;
                o.inspect = true;
                o.detect = true;
            }
            "--l7" => {
                o.proxy = true;
                o.l7 = true;
            }
            "--serve" => o.serve = true,
            "--dry-run" => o.dry_run = true,
            "--json" => o.json = true,
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
            "--mem" => {
                i += 1;
                o.mem = Some(args.get(i).ok_or("--mem expects a value, e.g. 8G")?.clone());
            }
            "--tasks" => {
                i += 1;
                o.tasks = Some(args.get(i).ok_or("--tasks expects a number")?.clone());
            }
            "--deny" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("--deny expects a project top-level name")?;
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

/// The persistent domain allowlist (approved once, applies to every session).
fn allow_file(home: &std::path::Path) -> PathBuf {
    home.join(".config/claude-island/domains.allow")
}

/// Denied domains awaiting `claude-island approve` / `watch`.
fn pending_file(home: &std::path::Path) -> PathBuf {
    home.join(".cache/claude-island/pending-domains.list")
}

/// The fixed proxy allowlist: base + active environments + --allow. The
/// persistent domains.allow file is read live by the proxy (so approvals
/// take effect without restart), not folded in here.
fn fixed_domains(sel: &[&envs::EnvSpec], allow: &[String]) -> Vec<String> {
    let mut domains: Vec<String> = BASE_DOMAINS.iter().map(|s| s.to_string()).collect();
    for e in sel {
        domains.extend(e.domains.iter().map(|s| s.to_string()));
    }
    domains.extend(allow.iter().cloned());
    domains.sort();
    domains.dedup();
    domains
}

/// The full static allowlist snapshot, for display only (explain): fixed
/// plus the current contents of domains.allow.
fn proxy_domains(sel: &[&envs::EnvSpec], allow: &[String], home: &std::path::Path) -> Vec<String> {
    let mut domains = fixed_domains(sel, allow);
    domains.extend(proxy::read_domains_file(&allow_file(home)));
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
    extra_reads: Vec<String>,
    _proxy: Option<proxy::Proxy>,
}

fn setup_network(
    o: &Opts,
    sel: &[&envs::EnvSpec],
    home: &std::path::Path,
    project: &std::path::Path,
    interactive: bool,
    prompter: Option<pty::Prompter>,
) -> Result<NetSetup> {
    if !o.proxy {
        return Ok(NetSetup {
            connect_ports: vec![443, 80, 53],
            extra_env: vec![],
            extra_reads: vec![],
            _proxy: None,
        });
    }
    let fixed = fixed_domains(sel, &o.allow);
    let log = home.join(".cache/claude-island/proxy.log");
    let inline = prompter.is_some();
    let bs = build_broker(o, home, project, prompter.clone())?;
    let p = proxy::start(
        fixed,
        allow_file(home),
        pending_file(home),
        interactive,
        prompter,
        bs.broker,
        &log,
    )
    .map_err(|e| format!("cannot start the proxy: {e}"))?;
    if inline {
        eprintln!(
            "claude-island: filtering proxy on 127.0.0.1:{} (inline: blocked domains prompt in \
             the terminal)",
            p.port
        );
    } else if interactive {
        eprintln!(
            "claude-island: filtering proxy on 127.0.0.1:{} (async: blocked domains go to \
             `claude-island watch`)",
            p.port
        );
    } else {
        eprintln!(
            "claude-island: filtering proxy on 127.0.0.1:{} (log: {})",
            p.port,
            log.display()
        );
    }
    let mut extra_env = vec![];
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        extra_env.push((k.to_string(), format!("http://127.0.0.1:{}", p.port)));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        extra_env.push((k.to_string(), "localhost,127.0.0.1".to_string()));
    }
    extra_env.extend(bs.env);
    Ok(NetSetup {
        connect_ports: vec![p.port, 53],
        extra_env,
        extra_reads: bs.reads,
        _proxy: Some(p),
    })
}

/// Result of setting up the credential broker.
#[derive(Default)]
struct BrokerSetup {
    broker: Option<std::sync::Arc<broker::Broker>>,
    /// env vars to inject into the sandbox (CA trust + placeholder GH_TOKEN)
    env: Vec<(String, String)>,
    /// paths to grant read access to (the CA bundle)
    reads: Vec<String>,
}

/// Builds the credential/inspection broker. `--broker` adds the GitHub
/// credential (from the wrapper's GITHUB_TOKEN/GH_TOKEN); `--inspect`
/// terminates every host and audits outbound requests.
fn build_broker(
    o: &Opts,
    home: &std::path::Path,
    project: &std::path::Path,
    prompter: Option<pty::Prompter>,
) -> Result<BrokerSetup> {
    if !o.broker && !o.inspect && !o.l7 {
        return Ok(BrokerSetup::default());
    }
    // L7 method/path allowlist (--l7, or composed with broker/inspect).
    let l7 = std::fs::read_to_string(home.join(".config/claude-island/l7.rules"))
        .ok()
        .and_then(|c| broker::L7Rules::parse(&c));
    if o.l7 && l7.is_none() {
        eprintln!(
            "claude-island: --l7: no rules in ~/.config/claude-island/l7.rules, filtering inactive"
        );
    }
    // Leak detector: index the project + load honeytokens (--detect).
    let detector = if o.detect {
        let honeytokens = std::fs::read_to_string(home.join(".config/claude-island/honeytokens"))
            .map(|c| {
                c.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        match detect::Detector::index(project, honeytokens) {
            Some(d) => {
                eprintln!(
                    "claude-island: --detect: indexed {} project files for leak detection",
                    d.files
                );
                Some(std::sync::Arc::new(d))
            }
            None => {
                eprintln!("claude-island: --detect: nothing to index, detection inactive");
                None
            }
        }
    } else {
        None
    };
    let mut creds = vec![];
    if o.broker {
        let token = env::var("GITHUB_TOKEN")
            .ok()
            .or_else(|| env::var("GH_TOKEN").ok());
        match token.filter(|t| !t.trim().is_empty()) {
            Some(token) => creds.push(broker::Credential {
                hosts: [
                    "github.com",
                    "api.github.com",
                    "codeload.github.com",
                    "uploads.github.com",
                    "raw.githubusercontent.com",
                    "objects.githubusercontent.com",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                bearer_hosts: ["api.github.com", "uploads.github.com"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                token,
            }),
            None => eprintln!(
                "claude-island: --broker: no GITHUB_TOKEN/GH_TOKEN in the environment, skipping"
            ),
        }
    }
    // The audit log is APPENDED across sessions (a session marker delimits
    // them) so leak forensics keep their history instead of being wiped.
    // Enabled by --inspect (full outbound trace) or --l7 (to log L7 denials).
    let audit = (o.inspect || o.l7).then(|| home.join(".cache/claude-island/outbound-audit.log"));
    if let Some(a) = &audit {
        if let Some(parent) = a.parent() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    let has_github = !creds.is_empty();
    let l7_active = l7.is_some();
    let Some(b) = broker::Broker::new(creds, o.inspect, audit.clone(), detector, prompter, l7)?
    else {
        return Ok(BrokerSetup::default());
    };

    // Combined CA bundle = system roots + our session CA, so the sandbox
    // trusts both brokered (our CA) and tunnelled (real CA) hosts.
    let system = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .unwrap_or_default();
    let bundle_path = home.join(".cache/claude-island/session-ca.pem");
    if let Some(parent) = bundle_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("ca dir: {e}"))?;
    }
    std::fs::write(
        &bundle_path,
        format!(
            "{system}
{}",
            b.ca_pem()
        ),
    )
    .map_err(|e| format!("writing CA bundle: {e}"))?;
    let bundle = bundle_path.to_string_lossy().to_string();

    let mut envs = vec![];
    for k in [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    ] {
        envs.push((k.to_string(), bundle.clone()));
    }
    // gh only sends a request if it believes it is authenticated; give it a
    // placeholder token that the broker replaces with the real one (only when
    // we are actually brokering GitHub credentials).
    if has_github {
        envs.push((
            "GH_TOKEN".to_string(),
            "brokered_by_claude_island".to_string(),
        ));
    }

    if o.broker {
        eprintln!("claude-island: --broker: GitHub credential broker active (token stays outside the sandbox)");
    }
    if l7_active {
        eprintln!("claude-island: --l7: method/path allowlist active for governed hosts");
    }
    if let Some(a) = &audit {
        eprintln!(
            "claude-island: auditing outbound requests to {}",
            a.display()
        );
    }
    Ok(BrokerSetup {
        broker: Some(b),
        env: envs,
        reads: vec![bundle],
    })
}

const BASH_COMPLETION: &str = r#"_claude_island() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=( $(compgen -W "@WORDS@" -- "$cur") )
}
complete -F _claude_island claude-island
"#;

const ZSH_COMPLETION: &str = r#"#compdef claude-island
_claude_island() {
    local -a words
    words=(@WORDS@)
    compadd -- $words
}
compdef _claude_island claude-island
"#;

/// `completion <shell>`: prints a completion script (bash, zsh, fish) with
/// the current subcommands, flags and environment names baked in.
fn cmd_completion(shell: Option<&String>, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let shell = shell.ok_or("completion needs a shell: bash, zsh or fish")?;
    let mut all: Vec<String> = [
        "check",
        "update",
        "explain",
        "denials",
        "allow",
        "report",
        "watch",
        "approve",
        "completion",
        "--auto",
        "--ro",
        "--noexec",
        "--deny",
        "--proxy",
        "--ask",
        "--allow",
        "--serve",
        "--ports",
        "--mem",
        "--tasks",
        "--dry-run",
        "--json",
        "--list",
        "--help",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for e in registry {
        all.push(format!("--{}", e.name));
        for a in e.aliases {
            all.push(format!("--{a}"));
        }
    }
    let words = all.join(" ");
    let script = match shell.as_str() {
        "bash" => BASH_COMPLETION.replace("@WORDS@", &words),
        "zsh" => ZSH_COMPLETION.replace("@WORDS@", &words),
        "fish" => {
            let mut out = String::from("complete -c claude-island -f\n");
            for w in &all {
                out.push_str(&format!("complete -c claude-island -a '{w}'\n"));
            }
            out
        }
        other => return Err(format!("unsupported shell: {other} (bash, zsh, fish)")),
    };
    print!("{script}");
    Ok(ExitCode::SUCCESS)
}

/// Reads one trimmed line from stdin after printing a prompt.
fn prompt_line(msg: &str) -> Result<String> {
    use std::io::Write;
    print!("{msg}");
    std::io::stdout().flush().ok();
    let mut s = String::new();
    if std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| format!("read: {e}"))?
        == 0
    {
        return Err("aborted".into()); // EOF
    }
    Ok(s.trim().to_string())
}

/// Yes/no question with a default (accepts y/o for yes).
fn ask_yesno(msg: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let a = prompt_line(&format!("{msg} {suffix} "))?;
    if a.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(a.chars().next(), Some('y' | 'Y' | 'o' | 'O')))
}

/// Interactive setup, run when `claude-island` is invoked with no arguments
/// in a real terminal. Asks the essentials, then launches with the choices.
fn cmd_wizard(registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (_home, project) = guards()?;
    println!("claude-island: interactive setup (Enter accepts the default)\n");
    let mut o = Opts::default();

    // 1. Dev environments.
    let detected = envs::auto_detect(&project, registry);
    if !detected.is_empty() {
        println!("detected environments: {}", detected.join(", "));
        if ask_yesno("enable them?", true)? {
            o.auto = true; // resolve_envs re-detects and skips missing toolchains
        } else if ask_yesno("pick environments manually?", false)? {
            let names = prompt_line("environments (space-separated, e.g. rust node): ")?;
            for n in names.split_whitespace() {
                match envs::resolve(registry, n) {
                    Some(name) if !o.env_names.contains(&name) => o.env_names.push(name),
                    Some(_) => {}
                    None => eprintln!("  unknown environment: {n} (skipped)"),
                }
            }
        }
    } else {
        let names = prompt_line("dev environments (space-separated, empty for none): ")?;
        for n in names.split_whitespace() {
            match envs::resolve(registry, n) {
                Some(name) if !o.env_names.contains(&name) => o.env_names.push(name),
                Some(_) => {}
                None => eprintln!("  unknown environment: {n} (skipped)"),
            }
        }
    }

    // 2. Network.
    println!("\nnetwork:");
    println!("  [1] normal (outbound 443/80/53 to any host)");
    println!("  [2] filter and ask before each new domain (--ask)");
    println!("  [3] filter + ask + detect and block code leaks (--ask --detect)");
    let net = prompt_line("choice [1]: ")?;
    match net.as_str() {
        "2" => {
            o.ask = true;
            o.proxy = true;
        }
        "3" => {
            o.ask = true;
            o.proxy = true;
            o.inspect = true;
            o.detect = true;
        }
        _ => {}
    }

    // 2b. Credential broker, only when a GitHub token is available to broker.
    let has_gh = env::var("GITHUB_TOKEN")
        .ok()
        .or_else(|| env::var("GH_TOKEN").ok())
        .is_some_and(|t| !t.trim().is_empty());
    if has_gh
        && ask_yesno(
            "let gh/git reach GitHub with your token (brokered, never enters the sandbox)?",
            false,
        )?
    {
        o.broker = true;
        o.proxy = true;
    }

    // 3. Read-only project (code review).
    if ask_yesno("\nread-only project (code review)?", false)? {
        o.ro = true;
    }

    // 4. Protect secrets present at the project root.
    let candidates: Vec<String> = [".env", ".git", "secrets", ".aws", "credentials.json"]
        .iter()
        .filter(|f| project.join(f).exists())
        .map(|s| s.to_string())
        .collect();
    if !candidates.is_empty()
        && ask_yesno(
            &format!(
                "\nhide {} from the agent (contents unreadable)?",
                candidates.join(", ")
            ),
            false,
        )?
    {
        o.deny = candidates;
    }

    // 5. Resource limits.
    let mem = prompt_line("\nmemory limit [8G]: ")?;
    if !mem.is_empty() {
        o.mem = Some(mem);
    }
    let tasks = prompt_line("max processes/threads [4096]: ")?;
    if !tasks.is_empty() {
        o.tasks = Some(tasks);
    }

    // Summary and confirm.
    let mut feats: Vec<String> = vec![];
    if o.auto {
        feats.push("--auto".into());
    }
    for e in &o.env_names {
        feats.push(format!("--{e}"));
    }
    if o.ask {
        feats.push("--ask".into());
    }
    if o.broker {
        feats.push("--broker".into());
    }
    if o.detect {
        feats.push("--detect".into());
    } else if o.inspect {
        feats.push("--inspect".into());
    }
    if o.ro {
        feats.push("--ro".into());
    }
    for d in &o.deny {
        feats.push(format!("--deny {d}"));
    }
    if let Some(m) = &o.mem {
        feats.push(format!("--mem {m}"));
    }
    if let Some(t) = &o.tasks {
        feats.push(format!("--tasks {t}"));
    }
    println!(
        "\nlaunching: claude-island {}",
        if feats.is_empty() {
            "(base sandbox)".into()
        } else {
            feats.join(" ")
        }
    );
    if !ask_yesno("proceed?", true)? {
        println!("cancelled");
        return Ok(ExitCode::SUCCESS);
    }
    println!();
    cmd_run(o, registry)
}

fn cmd_run(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, false)?;
    validate_deny(&o.deny)?;
    let sel = resolve_envs(&o, registry, &project, &home, true)?;

    // Inline approval prompts (--ask) require a real terminal to wrap in a
    // PTY; otherwise --ask falls back to the asynchronous pending-file flow.
    let use_pty = o.ask && pty::have_tty();
    let pump = if use_pty {
        Some(pty::channel().map_err(|e| format!("cannot set up the PTY channel: {e}"))?)
    } else {
        None
    };
    let prompter = pump.as_ref().map(|(p, _, _)| p.clone());
    let net = setup_network(&o, &sel, &home, &project, o.ask, prompter)?;

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
        &net.extra_reads,
    )
    .map_err(|e| format!("profile generation: {e}"))?;

    // The full launch command: systemd-run resource limits (if available)
    // wrapping `island run -- claude`. systemd-run preserves the controlling
    // terminal, so this same argv is used by both the normal and PTY paths.
    let (mem, tasks) = resource_limits(&o);
    let argv = launch_argv(&prof.name, &o.rest, &mem, &tasks);

    if o.dry_run {
        println!("generated profile: {}", prof.dir.display());
        println!("scrubbed variables: {}", SCRUB_ENV.join(", "));
        println!(
            "scrubbed patterns: *{} (kept: {})",
            SCRUB_SUFFIXES.join(", *"),
            KEEP_ENV.join(", ")
        );
        if envs::has_cmd("systemd-run") {
            println!("limits: MemoryMax={mem}, TasksMax={tasks}");
        }
        println!("command: {}", argv.join(" "));
        return Ok(ExitCode::SUCCESS);
    }
    if !envs::has_cmd("island") {
        return Err("island not found in PATH: run ./install.sh first".into());
    }

    // Ctrl+C must reach the sandboxed claude, not kill the wrapper (which
    // carries the proxy / PTY pump).
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
    }

    if let Some((_, rx, wake_r)) = pump {
        // Inline PTY path: wrap the command and pump I/O + approval prompts.
        return pty::run(&argv, scrub_env, rx, wake_r).map_err(|e| format!("pty overlay: {e}"));
    }

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    scrub_env(&mut cmd);
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run {}: {e}", argv[0]))?;
    Ok(exit_code(status))
}

/// Effective resource limits: --mem/--tasks flags, else the CLAUDE_ISLAND_MEM
/// / CLAUDE_ISLAND_TASKS env vars, else the defaults.
fn resource_limits(o: &Opts) -> (String, String) {
    let mem = o
        .mem
        .clone()
        .or_else(|| env::var("CLAUDE_ISLAND_MEM").ok())
        .unwrap_or_else(|| "8G".into());
    let tasks = o
        .tasks
        .clone()
        .or_else(|| env::var("CLAUDE_ISLAND_TASKS").ok())
        .unwrap_or_else(|| "4096".into());
    (mem, tasks)
}

/// Builds `[systemd-run ... island run -p <prof> -- <program> <rest>]`.
/// systemd-run (with MemoryMax/TasksMax) is prepended when available; it
/// preserves the controlling terminal so the PTY path works too.
/// CLAUDE_ISLAND_EXEC overrides "claude" (handy for testing with e.g. bash).
fn launch_argv(prof_name: &str, rest: &[String], mem: &str, tasks: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec![];
    if envs::has_cmd("systemd-run") {
        argv.extend(
            ["systemd-run", "--user", "--scope", "--quiet", "--same-dir"]
                .iter()
                .map(|s| s.to_string()),
        );
        argv.push("-p".into());
        argv.push(format!("MemoryMax={mem}"));
        argv.push("-p".into());
        argv.push(format!("TasksMax={tasks}"));
    }
    let program = env::var("CLAUDE_ISLAND_EXEC").unwrap_or_else(|_| "claude".into());
    argv.extend(
        ["island", "run", "-p", prof_name, "--"]
            .iter()
            .map(|s| s.to_string()),
    );
    argv.push(program);
    argv.extend(rest.iter().cloned());
    argv
}

fn cmd_check(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, false)?;
    validate_deny(&o.deny)?;
    let sel = resolve_envs(&o, registry, &project, &home, true)?;
    if !envs::has_cmd("island") {
        return Err("island not found in PATH: run ./install.sh first".into());
    }
    let net = setup_network(&o, &sel, &home, &project, false, None)?;

    // Canary artifacts, created BEFORE profile generation so the carve logic
    // (deny mode) enumerates and grants them: a dedicated dir holding the
    // exec/write probes (a top-level entry, granted in every mode), plus, in
    // deny mode, a synthetic denied dir with a secret to prove carving hides
    // it. Cleaned up afterwards.
    let canary_dir = project.join(".claude-island-canary-dir");
    std::fs::create_dir_all(&canary_dir).map_err(|e| format!("creating canary dir: {e}"))?;
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
        &net.extra_reads,
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
    std::fs::remove_file(&target).ok();
    std::fs::remove_dir_all(&canary_dir).ok();
    std::fs::remove_dir_all(&denied_dir).ok();
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
    println!(
        "approved {} for {}",
        project_config::FILE_NAME,
        project.display()
    );
    println!("  {}", project_config::summary(&cfg));
    println!("any change to the file will require a new `claude-island allow`");
    Ok(ExitCode::SUCCESS)
}

/// A one-line suggestion for how to lift a filesystem denial, using the
/// environment registry to map known toolchain dirs to their --flag.
fn suggest_fs(
    target: &str,
    kind: &str,
    home: &std::path::Path,
    registry: &[envs::EnvSpec],
) -> String {
    let home_s = home.to_string_lossy();
    // Under a known environment directory? Suggest the flag.
    if let Some(rel) = target
        .strip_prefix(&*home_s)
        .and_then(|r| r.strip_prefix('/'))
    {
        for e in registry {
            if e.dirs
                .iter()
                .chain(e.create.iter())
                .any(|d| rel == *d || rel.starts_with(&format!("{d}/")))
            {
                return format!("run with --{} to grant it", e.name);
            }
        }
    }
    // Otherwise suggest a snippet rule on the parent directory.
    let parent = target.rsplit_once('/').map(|(p, _)| p).unwrap_or(target);
    let display = parent
        .strip_prefix(&*home_s)
        .map(|r| format!("~{r}"))
        .unwrap_or_else(|| parent.to_string());
    let access = if kind == "exec" {
        "read + exec"
    } else if kind == "write" {
        "rw"
    } else {
        "read"
    };
    format!("add a snippet granting {access} on {display}")
}

/// `denials`: run a command inside the sandbox under strace and report the
/// accesses it was denied, with suggestions for how to grant them.
fn cmd_denials(o: Opts, registry: &[envs::EnvSpec]) -> Result<ExitCode> {
    let (home, project) = guards()?;
    let o = apply_project_config(o, &home, &project, registry, false)?;
    validate_deny(&o.deny)?;
    if o.rest.is_empty() {
        return Err(
            "denials requires a command: claude-island denials [flags] -- <command>".into(),
        );
    }
    if !envs::has_cmd("strace") {
        return Err(
            "strace not found in PATH: install it (the kernel audit path needs root)".into(),
        );
    }
    if !envs::has_cmd("island") {
        return Err("island not found in PATH: run ./install.sh first".into());
    }
    let sel = resolve_envs(&o, registry, &project, &home, true)?;
    let net = setup_network(&o, &sel, &home, &project, false, None)?;
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
        &net.extra_reads,
    )
    .map_err(|e| format!("profile generation: {e}"))?;

    let log = home.join(".cache/claude-island/denials.strace");
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("creating cache dir: {e}"))?;
    }

    // strace traces from OUTSIDE the sandbox (it is the ancestor of the
    // process tree); island applies Landlock then execs the command.
    eprintln!(
        "claude-island: tracing `{}` in sandbox \"{}\"",
        o.rest.join(" "),
        prof.name
    );
    let mut cmd = Command::new("strace");
    cmd.args(["-f", "-Z", "-y", "-qq", "-e", "trace=%file,%network", "-o"])
        .arg(&log)
        .args(["island", "run", "-p", &prof.name, "--"])
        .args(&o.rest);
    scrub_env(&mut cmd);
    cmd.status()
        .map_err(|e| format!("failed to run strace: {e}"))?;

    let output = std::fs::read_to_string(&log).map_err(|e| format!("reading strace log: {e}"))?;
    std::fs::remove_file(&log).ok();
    let found = denials::parse(&output);

    if o.json {
        for d in &found {
            println!("{}", d.to_json());
        }
        return Ok(ExitCode::SUCCESS);
    }

    if found.is_empty() {
        println!("no denials: the command ran without hitting the sandbox");
        return Ok(ExitCode::SUCCESS);
    }
    println!("{} distinct denial(s):", found.len());
    for d in &found {
        let display = d
            .target
            .strip_prefix(&*home.to_string_lossy())
            .map(|r| format!("~{r}"))
            .unwrap_or_else(|| d.target.clone());
        println!(
            "  {:<7} {:<48} ({} {}) x{}",
            d.kind, display, d.syscall, d.errno, d.count
        );
        let hint = match d.kind.as_str() {
            "connect" | "bind" => {
                let port = d.target.rsplit_once(':').map(|(_, p)| p).unwrap_or("?");
                if o.proxy {
                    format!("add the domain to the --proxy allowlist (denied port {port})")
                } else {
                    format!("allow port {port} with --serve/--ports, or check --proxy allowlist")
                }
            }
            _ => suggest_fs(&d.target, &d.kind, &home, registry),
        };
        println!("          -> {hint}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Appends domains to domains.allow (deduped) and removes them from the
/// pending list. Returns the set actually added.
fn approve_domains(home: &std::path::Path, domains: &[String]) -> Result<Vec<String>> {
    let af = allow_file(home);
    let mut current = proxy::read_domains_file(&af);
    let mut added = vec![];
    for d in domains {
        let d = d.trim().to_ascii_lowercase();
        if d.is_empty() {
            continue;
        }
        if !current.iter().any(|c| c == &d) {
            current.push(d.clone());
            added.push(d);
        }
    }
    if !added.is_empty() {
        if let Some(parent) = af.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("creating {}: {e}", parent.display()))?;
        }
        current.sort();
        current.dedup();
        let body: String = current.iter().map(|d| format!("{d}\n")).collect();
        std::fs::write(&af, body).map_err(|e| format!("writing {}: {e}", af.display()))?;
    }
    // Drop approved (and any explicitly named) domains from the pending list.
    let pf = pending_file(home);
    let remaining: Vec<String> = proxy::read_domains_file(&pf)
        .into_iter()
        .filter(|p| !domains.iter().any(|d| d.trim().eq_ignore_ascii_case(p)))
        .collect();
    let body: String = remaining.iter().map(|d| format!("{d}\n")).collect();
    std::fs::write(&pf, body).ok();
    Ok(added)
}

/// `approve`: approve pending domains blocked by the interactive proxy.
fn cmd_approve(args: &[String]) -> Result<ExitCode> {
    let home = PathBuf::from(env::var("HOME").map_err(|_| "HOME is not set")?);
    let pending = proxy::read_domains_file(&pending_file(&home));

    let all = args.iter().any(|a| a == "--all");
    let named: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();

    if !all && named.is_empty() {
        if pending.is_empty() {
            println!("no pending domains");
        } else {
            println!("pending domains ({}):", pending.len());
            for d in &pending {
                println!("  {d}");
            }
            println!("approve with: claude-island approve <domain>...  (or --all)");
        }
        return Ok(ExitCode::SUCCESS);
    }

    let targets = if all { pending.clone() } else { named };
    if targets.is_empty() {
        println!("nothing to approve");
        return Ok(ExitCode::SUCCESS);
    }
    let added = approve_domains(&home, &targets)?;
    if added.is_empty() {
        println!("already allowed: {}", targets.join(", "));
    } else {
        println!("approved (added to domains.allow): {}", added.join(", "));
    }
    Ok(ExitCode::SUCCESS)
}

/// `watch`: poll the pending file and interactively approve new domains.
/// Universal: runs in its own terminal, needs no notifier and no tmux.
/// `report [--all]`: summarize the outbound-audit log into what tried to
/// leave the sandbox and where (last session by default, or `--all`).
fn cmd_report(args: &[String]) -> Result<ExitCode> {
    let home = PathBuf::from(env::var("HOME").map_err(|_| "HOME is not set")?);
    let all = args.iter().any(|a| a == "--all");
    let path = home.join(".cache/claude-island/outbound-audit.log");
    let log = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            println!(
                "claude-island: no audit log yet ({}). Run with --inspect or --detect first.",
                path.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
    };
    let r = report::parse(&log, !all);
    let scope = if all { "all sessions" } else { "last session" };
    print!("{}", report::render(&r, scope));
    Ok(ExitCode::SUCCESS)
}

fn cmd_watch() -> Result<ExitCode> {
    use std::io::{BufRead, Write as _};
    let home = PathBuf::from(env::var("HOME").map_err(|_| "HOME is not set")?);
    let pf = pending_file(&home);
    println!("claude-island: watching for domains blocked by --ask (Ctrl-C to stop)");
    let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Domains already pending at startup are shown first.
    let stdin = std::io::stdin();
    loop {
        for d in proxy::read_domains_file(&pf) {
            if handled.contains(&d) {
                continue;
            }
            print!("blocked: {d}  approve? [y]es / [n]o / [q]uit: ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
                return Ok(ExitCode::SUCCESS); // EOF
            }
            match line.trim() {
                "y" | "Y" => {
                    let added = approve_domains(&home, std::slice::from_ref(&d))?;
                    println!(
                        "  {} {d}",
                        if added.is_empty() {
                            "already allowed:"
                        } else {
                            "approved:"
                        }
                    );
                    handled.insert(d);
                }
                "q" | "Q" => return Ok(ExitCode::SUCCESS),
                _ => {
                    println!("  skipped (still pending)");
                    handled.insert(d);
                }
            }
        }
        thread::sleep(Duration::from_millis(700));
    }
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
        Some("report") => cmd_report(&args[1..]),
        Some("watch") => cmd_watch(),
        Some("approve") => cmd_approve(&args[1..]),
        Some("completion") => cmd_completion(args.get(1), &envs::registry()),
        Some("denials") => {
            let registry = envs::registry();
            match parse(&args[1..], &registry)? {
                Parsed::Go(o) => cmd_denials(o, &registry),
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
            // No arguments in a real terminal: run the interactive setup,
            // unless disabled. Non-interactive (piped/cron) keeps the plain
            // base-sandbox behavior.
            if args.is_empty() && pty::have_tty() && env::var("CLAUDE_ISLAND_NO_WIZARD").is_err() {
                return cmd_wizard(&registry);
            }
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
