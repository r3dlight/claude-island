#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Stephane N
# SPDX-License-Identifier: GPL-3.0-or-later
# Installs Island, builds claude-island (Rust) and installs it into ~/.local/bin.
set -euo pipefail

here="$(dirname "$(readlink -f "$0")")"

# 1. Island, at the revision pinned in src/main.rs (single source of truth).
#    Island is a young project: only `claude-island update` moves this pin,
#    and it re-runs the canary suite right after.
ISLAND_REV="$(grep -oE 'ISLAND_REV: &str = "[0-9a-f]{40}' "$here/src/main.rs" | grep -oE '[0-9a-f]{40}')"
if [[ -z "$ISLAND_REV" ]]; then
    echo "error: pinned Island revision not found in src/main.rs" >&2
    exit 1
fi
if ! command -v island >/dev/null; then
    echo "== Installing Island at pinned revision ${ISLAND_REV:0:12} =="
    cargo install --locked --git https://github.com/landlock-lsm/island --rev "$ISLAND_REV" island
fi

# 2. claude-island
echo "== Building and installing claude-island =="
rm -f "$HOME/.local/bin/claude-island"    # legacy symlink of the bash wrapper
cargo install --path "$here" --root "$HOME/.local"

# 3. Config migration: CLAUDE_CONFIG_DIR=~/.claude moves the main config to
#    ~/.claude/.claude.json; copy the existing one if needed.
if [[ -f "$HOME/.claude.json" && ! -f "$HOME/.claude/.claude.json" ]]; then
    mkdir -p "$HOME/.claude"
    cp "$HOME/.claude.json" "$HOME/.claude/.claude.json"
    echo "~/.claude.json copied to ~/.claude/.claude.json"
    echo "Tip: export CLAUDE_CONFIG_DIR=\$HOME/.claude in ~/.zshenv so that"
    echo "sessions outside the sandbox use the same config."
fi

# 4. Kernel checks
if [[ -r /sys/kernel/security/landlock/abi_version ]]; then
    echo "== Landlock ABI: $(cat /sys/kernel/security/landlock/abi_version) (>= 6 required) =="
fi
sysctl dev.tty.legacy_tiocsti 2>/dev/null || true

cat <<'EOF'

Done. Try:
    cd ~/dev/my-project
    claude-island check              # canary suite: prove the sandbox holds
    claude-island --rust --dry-run   # inspect the generated profile
    claude-island --rust --proxy     # sandboxed Claude, domain-filtered network
    claude-island --ro               # read-only project (code review)

Optional (auto-sandbox of ALL commands in profiled projects, zsh only for
now on Island's side):
    # in ~/.zshrc:
    source <(island completion zsh)
    source <(island hook zsh)
EOF
