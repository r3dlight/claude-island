<p align="center">
  <img src="assets/logo.svg" alt="claude-island logo" width="170"/>
</p>

# claude-island

Run [Claude Code](https://claude.com/claude-code) inside a kernel-enforced
sandbox. Claude can work on the current project and nothing else: your SSH
keys, tokens, dotfiles and other projects are invisible, and the network can
be reduced to an allowlist of domains. Built on
[Island](https://github.com/landlock-lsm/island) and
[Landlock](https://landlock.io).

## Quickstart

```sh
./install.sh                # builds Island and claude-island, checks the kernel

cd ~/dev/my-project
claude-island               # no args: interactive setup, then launches
```

With no arguments, claude-island asks the essentials (environments, network,
read-only, hiding secrets) and launches with your choices. Or drive it
directly with flags:

```sh
cd ~/dev/my-project
claude-island check         # prove the sandbox holds before trusting it
claude-island --rust        # sandboxed Claude Code, with your Rust toolchain
```

Review an untrusted repository, with the project read-only and the network
reduced to an allowlist of domains:

```sh
git clone https://github.com/someone/unknown-tool ~/dev/unknown-tool
cd ~/dev/unknown-tool
claude-island --ro --proxy
```

Full-stack work: several toolchains, a dev server, one extra domain:

```sh
cd ~/dev/my-app
claude-island --rust --node --serve --proxy --allow api.my-backend.dev
```

## What the sandbox does

Claude and every process it spawns get:

| | Allowed | Denied |
|---|---------|--------|
| Files | current project (rw), Claude state and caches, system dirs (read/exec) | everything else: `~/.ssh`, `~/.aws`, `~/.config/gh`, dotfiles, other projects, `$HOME` itself |
| Network | outbound TCP 443/80/53 (only the proxy port with `--proxy`) | listening, unless `--serve`/`--ports` |
| Local services | | D-Bus, Wayland and ssh-agent sockets, abstract sockets, signals to the outside |
| Resources | 8G RAM, 4096 tasks (systemd limits, tune with `--mem`/`--tasks`) | fork bombs, runaway builds |

Secrets are also scrubbed from the environment before launch: a fixed list
(`SSH_AUTH_SOCK`, `DBUS_SESSION_BUS_ADDRESS`, `AWS_*`, ...) plus every
variable ending in `_TOKEN`, `_SECRET`, `_KEY`, `_PASSWORD`, `_PASSWD` or
`_CREDENTIALS` (`ANTHROPIC_API_KEY` is kept). Enforcement is done by the
kernel (Landlock): restrictions are inherited by all child processes and
cannot be lifted once applied.

Don't trust it, verify:

```
$ claude-island check
[PASS] deny: list $HOME
[PASS] deny: read ~/.ssh
[PASS] deny: write ~/.zshrc
[PASS] deny: create a file in ~/.config/systemd/user
[PASS] deny: TCP bind on a non-allowed port (34567)
[PASS] allow: write inside the project
[PASS] allow: execute /usr/bin/true
...
result: OK, the sandbox holds its promises
```

Canaries cover the startup files of zsh, bash and fish plus `~/.profile`,
the persistence directories (systemd user units, desktop autostart), and
two self-escape targets: Island's own profiles and claude-island's config
(which holds the proxy allowlist). Variants cover the other modes and
combine like the run flags: `check --ro` (project write must be denied),
`check --noexec` (project execve must be denied) and `check --proxy`
(direct 443 must be denied, a non-allowlisted domain must get 403, an
allowlisted one must pass).

## Install

Requirements: Linux kernel 6.12+ (Landlock ABI 6), Rust 1.89+.

```sh
./install.sh    # cargo-installs Island, builds claude-island into ~/.local/bin
```

The script also copies `~/.claude.json` into `~/.claude/` (the sandbox runs
with `CLAUDE_CONFIG_DIR=~/.claude`); a login may be requested once.

## Interactive setup

Run `claude-island` with no arguments in a terminal and it asks the
essentials, then launches with your choices:

```
$ claude-island
detected environments: rust
enable them? [Y/n]
network:
  [1] normal (outbound 443/80/53 to any host)
  [2] filter and ask before each new domain (--ask)
choice [1]: 2
read-only project (code review)? [y/N]
hide .git, .env from the agent (contents unreadable)? [y/N] y
launching: claude-island --auto --ask --deny .git --deny .env
proceed? [Y/n]
```

It auto-detects the project's environments and offers the common toggles
(network filtering, read-only, hiding secrets found at the project root).
Passing any flag skips it; so does a non-interactive context (piped, cron).
Set `CLAUDE_ISLAND_NO_WIZARD=1` to always skip it.

## Everyday usage

From a project directory under `$HOME`:

```
claude-island                       base sandbox
claude-island --rust                unlock cargo and rustup (already installed)
claude-island --rust --node --c     environments are stackable
claude-island --auto                detect environments from project files
claude-island --ro                  project in READ-ONLY mode (code review)
claude-island --noexec              deny running project files (combines with --ro)
claude-island --deny .git --deny .env  protect top-level entries from the agent
claude-island --proxy               network filtered by domain allowlist
claude-island --ask                 prompt to approve each new domain (inline)
claude-island --allow foo.dev       add a domain to the allowlist (repeatable)
claude-island denials -- cargo build  run a command, report every access it was denied
claude-island check                 canary suite: verify the sandbox holds
claude-island check --ro            same, read-only variant
claude-island check --proxy         same, domain-filtering variant
claude-island update                update Island (pinned), rebuild, re-check
claude-island explain --rust --ro   show what the profile would grant (no side effect)
claude-island allow                 approve the project's .claude-island.toml
claude-island --list                list available environments
claude-island --serve               allow TCP bind on 3000, 4321, 5173, 8000, 8080
claude-island --ports 9000,9443     additional bind ports
claude-island --mem 4G --tasks 2048 session resource limits (memory, processes)
claude-island --dry-run             show the generated profile and command
claude-island -- --resume           everything after -- is passed to claude
```

Resource limits: `--mem` / `--tasks` (or the `CLAUDE_ISLAND_MEM` /
`CLAUDE_ISLAND_TASKS` env vars; defaults 8G / 4096) apply via `systemd-run`
in every mode, including `--ask`.

### Per-project config: `.claude-island.toml`

Committed at the project root, applied like command-line flags (merged with
them), so plain `claude-island` does the right thing per project:

```toml
# .claude-island.toml
envs = ["rust", "node"]      # or: auto = true
proxy = true
serve = true
ports = [9443]
allow = ["api.my-backend.dev"]
# ro = true / noexec = true for review-only repositories
```

A cloned repository must not be able to grant itself rights, so the file
follows the direnv model: it is **refused until you approve it** with
`claude-island allow`, and any later change requires a new approval.
Approvals (content hashes) live in `~/.config/claude-island/approved.list`,
which the sandbox cannot write (covered by a canary). `explain` applies an
unapproved file anyway, with a warning, so you can review what it would
grant before approving. Unknown keys are an error: a typo cannot silently
drop a setting.

## Dev environments

**An environment flag installs nothing.** It only unlocks access to a
toolchain that is already installed, and refuses with a clear message if it
is missing. Without the flag, the toolchain is simply invisible: `cargo
build` fails because `~/.cargo` cannot even be read.

`--auto` detects environments from the project's root files (`Cargo.toml`
brings rust, `package.json` brings node, `go.mod` brings go, `pyproject.toml`
brings python3, `pom.xml`/`build.gradle` bring jvm, and so on) and combines
with explicit flags. One difference: an auto-detected environment whose
toolchain is missing is skipped with a warning instead of refusing, so
`claude-island --auto` just works on polyglot repositories.

| Flag | Checks | Unlocks |
|------|--------|---------|
| `--c`, `--cpp` | `cc`/`gcc`/`clang` | ccache caches, `~/.conan2` (compilers are in the baseline) |
| `--rust` | `~/.cargo`, `~/.rustup` | both, rw + exec |
| `--go` | `go` | `~/go`, `~/.cache/go-build` |
| `--python3` | `python3` | pip/uv caches, uv-managed pythons (venv lives in the project) |
| `--node` | `node`/`npm` | `~/.npm`, yarn cache, pnpm store, `~/.nvm` (exec only) |
| `--deno` | `deno` | `~/.deno`, deno cache |
| `--bun` | `bun` | `~/.bun` |
| `--jvm` (`--java`, `--kotlin`, `--scala`) | `java` | `~/.m2`, `~/.gradle`, `~/.ivy2`, `~/.sbt`, coursier, `~/.sdkman` (exec only) |
| `--ruby` | `ruby` | `~/.gem`, `~/.bundle`, `~/.rbenv` (exec only) |
| `--php` | `php` | composer dirs and cache |
| `--perl` | `perl` | `~/perl5`, `~/.cpan`, `~/.cpanm` |
| `--dotnet` | `dotnet` | `~/.dotnet`, `~/.nuget`, `~/.templateengine` |
| `--haskell` | `ghc`/`stack`/`cabal` | `~/.cabal`, `~/.stack`, `~/.ghcup` (exec only) |
| `--elixir` | `elixir`/`mix` | `~/.mix`, `~/.hex`, rebar3 cache |
| `--zig` | `zig` | zig cache |
| `--mise` | `mise` | everything mise manages, in one flag |

Languages whose toolchain lives entirely under `/usr` (shell, Lua, awk, and
C/C++ apart from caches) work without any flag.

Managed toolchain dirs (`~/.nvm`, `~/.sdkman`, `~/.rbenv`, `~/.ghcup`) are
execute only: `nvm install` or `npm install -g` happen outside the sandbox,
on purpose. Project-local installs work normally.

Custom environment without recompiling: drop a
`~/.config/claude-island/snippets/env-foo.toml` (same format as the files in
`snippets/`), then use `--foo`.

## Network filtering: `--proxy`

By default Landlock filters by port, so any host is reachable on 443.
`--proxy` replaces that with a domain allowlist, enforced by a small HTTP
CONNECT proxy that runs outside the sandbox; inside, only the proxy port is
reachable. The allowlist combines:

* base domains (Anthropic API, github.com and its CDNs);
* domains of the active environments (`--rust` adds crates.io, `--node` adds
  registry.npmjs.org, ...);
* your permanent additions, one per line:

```sh
# ~/.config/claude-island/domains.allow
api.my-backend.dev
gitlab.example.com          # a domain also covers its subdomains
```

* one-off additions: `--allow <domain>`.

Denials and grants are logged to `~/.cache/claude-island/proxy.log`: check
it to see what Claude actually tried to reach, and refine the list. That log
is also the session trace of which domains were contacted and which were
approved (`APPROVED (inline)` / `DENIED (inline)` lines). Because the proxy
is a CONNECT tunnel, it sees hosts, ports and timing, not the encrypted
payload (content inspection would need TLS termination, which we do not do).

### Interactive approval: `--ask`

`--ask` (implies `--proxy`) asks you to approve each new domain instead of
silently denying it. It adapts to the environment:

* **With a real terminal**, claude-island wraps Claude Code in a PTY and
  prompts inline, exactly like Claude Code's own permission prompts:

  ```
  [claude-island] allow network to api.example.dev ? [y/N]
  ```

  The connection pauses until you answer; `y` (a single keystroke) approves
  it, persists the domain to `domains.allow` (so it is remembered), and lets
  it through. A domain is asked once per session. Answer promptly: the
  underlying tool (curl, git, ...) keeps its own timeout, so a slow answer
  may make that first attempt give up. The approval is saved either way, so
  a retry succeeds immediately.

  Testing the overlay without a full Claude session: `CLAUDE_ISLAND_EXEC`
  overrides the wrapped program, e.g. `CLAUDE_ISLAND_EXEC=bash
  claude-island --ask` gives a sandboxed shell where you can trigger
  connections by hand.

* **Without a TTY** (piped, headless, cron), it falls back to the
  asynchronous flow: the blocked domain is appended to a pending list and a
  best-effort notification fires (a `CLAUDE_ISLAND_NOTIFY` hook, else
  `notify-send`, else a tmux status message). You approve out of band:

  ```sh
  claude-island watch                 # live: prompts for each blocked domain
  claude-island approve api.example.dev   # or approve specific domains
  claude-island approve --all
  ```

  `watch` runs in any second terminal, needs no notifier and no tmux, and is
  the universal path.

## Credential broker: `--broker`

By default the `gh` CLI does not work inside the sandbox (its token is
scrubbed and protected). `--broker` makes `gh`, `git` and `curl` work
against GitHub **without the token ever entering the sandbox**:

```sh
GITHUB_TOKEN=ghp_...   # in your shell, outside the sandbox
claude-island --broker
```

`--broker` implies `--proxy` and starts a TLS-terminating proxy outside the
sandbox. For GitHub hosts it presents a leaf certificate signed by an
ephemeral session CA that the sandbox is told to trust (via `SSL_CERT_FILE`
and friends, pointing at a bundle of the system roots plus our CA). It reads
the plaintext request, replaces any `Authorization` with the real credential
(`GITHUB_TOKEN`/`GH_TOKEN` from your environment), and forwards it over a
fresh, fully verified TLS connection to the real host. So:

* the real token lives only in the wrapper, never in the sandbox (not in
  files, not in the environment, not in any tool's memory);
* `gh` gets a placeholder `GH_TOKEN` so it believes it is logged in; the
  broker swaps in the real token upstream;
* non-GitHub hosts are tunnelled untouched (normal `--proxy` behaviour);
* the session CA is generated fresh each run and trusted nowhere else.

Verify with `~/.cache/claude-island/proxy.log` (`brokered: ...` lines). Only
GitHub is brokered for now.

## Leak inspection and detection: `--inspect` and `--detect`

The same TLS termination that powers the broker can look at **everything**
leaving the sandbox, in plaintext, to answer a concrete question: is my local
code being sent somewhere it should not?

### `--inspect`: total transparency

`--inspect` (implies `--proxy`) TLS-terminates **every** host and records each
outbound request to `~/.cache/claude-island/outbound-audit.log`: destination,
method, path, body size, and a truncated body preview. The Authorization
header is never logged. The log is appended across sessions (a
`=== session start ===` marker delimits them) so the history is kept.

```sh
claude-island --inspect
# in another terminal:
tail -f ~/.cache/claude-island/outbound-audit.log
```

You see exactly what each request carries and where it goes, including
`api.anthropic.com` and any third-party endpoint a tool contacts. Claude Code
itself keeps working through the interception (its own `Authorization` is
passed through untouched). Caveat: a tool that pins certificates or insists on
HTTP/2 may break under `--inspect`; such a tool is the exception.

### `--detect`: block outbound copies of your code

`--detect` (implies `--inspect`) indexes the project's files at startup into
content fingerprints (sampled k-grams, robust to reformatting), optionally
augmented by honeytokens from `~/.config/claude-island/honeytokens` (one
string per line). It then scans every outbound body to a **non-Anthropic**
host; if a chunk of your local code (or a honeytoken) appears, the request is
**blocked** with `403` and an alert is written to the audit log:

```
[1783590111] !!! LEAK BLOCKED: code from src/algo.rs (6 fragments) -> example.com (body 82B)
```

The Anthropic API is audited but never flagged: it legitimately carries your
code (that is how Claude Code works), so alarming on it would be noise. The
signal is code leaving to **anywhere else**. Bodies larger than 8 MB stream
unscanned (source files are small, so this misses little), and detection is
heuristic: a compressed or re-encoded body can evade the fingerprints.

Combine with `--ask` (in a terminal) to decide **per leak** instead of
blocking outright: a red inline prompt shows what is leaving and where, and
the request is held until you answer (default, and on timeout, is to block):

```
▌ claude-island  allow LEAK of code from src/algo.rs to example.com ?  [y/N]
```

Without a terminal (or without `--ask`), a detected leak is blocked
automatically and recorded as `!!! LEAK BLOCKED` in the audit log.

## Code review mode: `--ro` and `--noexec`

For unknown repositories (unaudited code, possible prompt injection in the
README). `--ro` makes the project read + execute only: Claude can read,
search and run tools, but cannot modify the repository. Only its own state
and the isolated TMPDIR stay writable. Verify with `claude-island check --ro`.

Execution of project files stays allowed under `--ro` because denying it
buys little: interpreted files (`bash x.sh`, `python3 x.py`) only need read,
native binaries can be launched through the loader
(`/lib64/ld-linux-x86-64.so.2 ./x`), and whatever runs stays confined by the
same sandbox anyway. If you want that speed bump against naive attacks
regardless, add `--noexec`: it denies direct `execve` of project files and
combines with `--ro` (project becomes read-only, no execution). Verify with
`claude-island check --noexec` or `check --ro --noexec`.

Note: an `--ro` profile declares no Island `[[context]]`, because Island
grants full access beneath context paths (they are treated as workspaces).
The wrapper always selects profiles explicitly, so nothing is lost; the zsh
auto-activation hook simply never picks up an `--ro` profile.

## Protecting secrets inside the project: `--deny`

The project is granted as one tree, so a `.env` or a private key committed
*inside* the repo is readable by the agent by default. `--deny <name>`
carves those out:

```sh
claude-island --deny .git --deny .env --deny secrets
# or in .claude-island.toml:  deny = [".git", ".env", "secrets"]
```

For each denied top-level entry, the agent **cannot read its file contents
and cannot write it**. This is pure Landlock: since Landlock unions rules
and cannot subtract from a granted tree, the wrapper stops granting the
whole project and instead grants each top-level entry individually, skipping
the denied ones (the project root keeps a `read_dir` grant so listing and
navigation still work).

Two honest limitations of the pure-Landlock approach:

* **New files cannot be created directly at the project root** (existing
  files and granted subdirectories stay fully writable, so editing `src/*`
  and adding `src/newmod.rs` work). Create new top-level files outside the
  sandbox.
* **Names may still appear in a listing**: the root `read_dir` grant
  propagates, so `ls secrets/` can show that `creds` exists, but
  `cat secrets/creds` is denied. Contents and writes are protected, not the
  existence of names.

v1 supports project **top-level** names only (no `src/secret`). Verify with
`claude-island check --deny <name>`.

## Diagnosing denials: `claude-island denials`

When a command misbehaves inside the sandbox, this tells you exactly what it
was denied and how to grant it. It runs the command under `strace` (the
tracer sits outside the sandbox), collects every syscall that failed with
`EACCES`/`EPERM` (the Landlock denial errnos), and reports them deduplicated
with a suggested fix:

```
$ claude-island denials -- sh -c 'cargo build; cat ~/.ssh/id_ed25519'
2 distinct denial(s):
  exec    ~/.cargo/bin/cargo   (execve EACCES) x1
          -> run with --rust to grant it
  read    ~/.ssh/id_ed25519    (openat EACCES) x1
          -> add a snippet granting read on ~/.ssh
```

Suggestions map known toolchain directories to their `--<env>` flag; other
paths get a snippet hint, and network denials report the port. `--json`
emits one JSON object per denial for tooling:

```
$ claude-island denials --json -- cargo build
{"kind":"exec","target":"/home/user/.cargo/bin/cargo","syscall":"execve","errno":"EACCES","count":1}
```

This is the privilege-free path: the kernel Landlock audit log (ABI 7) needs
root or auditd to read, whereas strace traces our own process tree. Requires
`strace` in `PATH`.

## Good to know

* Shell completion: `claude-island completion bash|zsh|fish` prints a script
  (subcommands, flags, environment names). For bash:
  `claude-island completion bash > ~/.local/share/bash-completion/completions/claude-island`;
  for fish, write to `~/.config/fish/completions/claude-island.fish`; for zsh,
  write `_claude-island` to a directory on your `$fpath`.
* Profiles are named per project; those whose project directory was deleted
  are pruned automatically on the next run (no stale-context warnings).
* git works over HTTPS inside the sandbox; SSH push happens outside
  (`nosandbox git push` with the zsh hook). Neither keys nor agent are ever
  exposed.
* The `gh` CLI does not work inside by default (its token stays protected):
  use it outside, or run with `--broker` to make it (and `git`/`curl` against
  GitHub) work without the token entering the sandbox (see above).
* Tools that hardcode `/tmp` fail: `TMPDIR` points to an isolated,
  per-profile workspace.
* `claude-island explain [flags]` prints a readable summary of what the
  profile would grant (filesystem by access level, network, allowlist,
  scrubbed variables, limits) without writing or running anything:

  ```
  $ claude-island explain --rust --ro --proxy
  project: ~/dev/unknown-tool [read + exec (--ro)]
  filesystem (everything not listed is denied)
    rw + exec   ~/.cargo, ~/.rustup
    rw          ~/.claude, ~/.cache/claude, /dev/null, ...
    read + exec <project>, /bin, /usr, ...
    read-only   /etc, /proc, /sys, ~/.gitconfig
  network
    outbound     only the filtering proxy on 127.0.0.1
    allowlist    10 domains: api.anthropic.com, crates.io, github.com, ...
  ...
  ```

* On an unexpected denial: `claude-island explain` first, then
  `island -v run -p <profile> -- <cmd>` for verbose detail.
* Island is young ("work in progress, so be careful"), so it is installed
  at a revision pinned in `src/main.rs` and validated by the canaries.
  `claude-island update` is the one safe way to move: it reinstalls Island
  at the pin, rebuilds claude-island, refreshes profile defaults and re-runs
  `check` and `check --ro`. Also re-run the checks after a kernel update.
* Optional zsh integration, to auto-sandbox every command in profiled
  directories: `source <(island hook zsh)` in `~/.zshrc`. The claude-island
  binary itself works from any shell.

## How it works

Defense in depth, eight layers:

| Layer | Mechanism | Role |
|-------|-----------|------|
| 1 | Landlock filesystem (ABI 6) | deny by default; system read/exec, project and Claude state rw (`--ro`: project read-only) |
| 2 | Landlock network | `connect_tcp` limited to 443/80/53, `bind_tcp` opt-in |
| 3 | Filtering proxy (`--proxy`) | domain allowlist, only the proxy port reachable |
| 4 | Landlock scoped | signals and abstract UNIX sockets confined |
| 5 | Island workspaces | XDG and TMPDIR isolated per profile |
| 6 | Environment scrubbing | secrets and agent handles removed |
| 7 | `systemd-run --scope` | `MemoryMax`, `TasksMax` |
| 8 | Claude Code's native sandbox | stacks freely (Landlock allows 16 nested layers) |

The wrapper is a single Rust binary; the policy snippets (`snippets/`) are
embedded at compile time. On each launch it generates a profile under
`~/.config/island/profiles/claude-<project>[-envs][-ro]-<hash>` and runs
`island run -p <profile> -- claude` under systemd resource limits.

Key Island semantics: TOML files within one profile compose as a **union**
(an environment flag can add rights), while stacked profiles compose as an
**intersection** (they can only reduce rights). That is why environments are
snippets copied into a single generated profile, never stacked profiles.

Design notes:

* `CLAUDE_CONFIG_DIR=~/.claude` keeps all Claude state in the single
  writable state directory (avoids granting file creation and deletion at
  the root of `$HOME` for the config's atomic rename).
* The Claude binary is read-only and its auto-updater disabled
  (`DISABLE_AUTOUPDATER=1`): a compromised Claude cannot replace itself.
  Update outside the sandbox.
* `~/.gitconfig` is readable (commit identity) but never writable;
  `~/.git-credentials` stays denied.

## Limitations

* Without `--proxy`, any host is reachable on 443. With it, exfiltration is
  still possible towards the allowlisted domains themselves: keep the list
  minimal.
* UDP is not covered by Landlock (QUIC/HTTP-3 passes), except with
  `--proxy` where only the proxy's TCP port is reachable.
* File metadata (stat) is not restricted; file contents are.
* No protection against kernel vulnerabilities or compromised privileged
  services.

## License

[GPL-3.0-or-later](LICENSE).
