#!/bin/sh
# SPDX-FileCopyrightText: 2026 Stephane N
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install claude-island and Island. Works two ways:
#   piped:  curl -fsSL https://raw.githubusercontent.com/r3dlight/claude-island/main/install.sh | sh
#           downloads the prebuilt binary (falling back to building from git)
#   local:  ./install.sh
#           builds from the current checkout
#
# Island (the Landlock backend) has no prebuilt binaries, so `cargo` (Rust) is
# required either way. Override the install prefix with CLAUDE_ISLAND_PREFIX.
set -eu

REPO="r3dlight/claude-island"
RAW="https://raw.githubusercontent.com/${REPO}/main"
PREFIX="${CLAUDE_ISLAND_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/claude-island"

say() { printf '== %s\n' "$1"; }
die() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# Detect a source checkout (local run). When piped, $0 is the shell name, not
# a path to this script, so src_dir stays empty and we install from release.
src_dir=""
if [ -f "$0" ]; then
    d=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    [ -f "$d/Cargo.toml" ] && src_dir="$d"
fi

# --- Island, at the revision pinned in src/main.rs (single source of truth) --
if ! have island; then
    have cargo || die "cargo (Rust) is required to install Island: https://rustup.rs"
    if [ -n "$src_dir" ]; then
        rev=$(grep -oE 'ISLAND_REV: &str = "[0-9a-f]{40}' "$src_dir/src/main.rs" | grep -oE '[0-9a-f]{40}')
    else
        have curl || die "curl is required"
        rev=$(curl -fsSL "$RAW/src/main.rs" | grep -oE 'ISLAND_REV: &str = "[0-9a-f]{40}' | grep -oE '[0-9a-f]{40}')
    fi
    [ -n "$rev" ] || die "could not determine the pinned Island revision"
    say "Installing Island at ${rev}"
    cargo install --locked --git https://github.com/landlock-lsm/island --rev "$rev" island
fi

# --- claude-island -----------------------------------------------------------
mkdir -p "$PREFIX/bin"
rm -f "$BIN" # legacy symlink of the old bash wrapper, or a previous install

if [ -n "$src_dir" ]; then
    say "Building claude-island from $src_dir"
    have cargo || die "cargo (Rust) is required: https://rustup.rs"
    cargo install --path "$src_dir" --root "$PREFIX"
else
    installed=""
    # Prefer the prebuilt binary on Linux x86_64; rename it to `claude-island`.
    if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" = "x86_64" ] && have curl; then
        say "Downloading the latest claude-island release"
        url="https://github.com/${REPO}/releases/latest/download/claude-island-linux-x86_64"
        tmp=$(mktemp)
        if curl -fSL -o "$tmp" "$url"; then
            chmod +x "$tmp"
            mv "$tmp" "$BIN"
            installed=1
        else
            rm -f "$tmp"
            say "No prebuilt binary available; building from source instead"
        fi
    fi
    if [ -z "$installed" ]; then
        have cargo || die "cargo (Rust) is required to build claude-island: https://rustup.rs"
        say "Installing claude-island from git"
        cargo install --locked --git "https://github.com/${REPO}" --root "$PREFIX" claude-island
    fi
fi

# --- config migration: CLAUDE_CONFIG_DIR=~/.claude --------------------------
if [ -f "$HOME/.claude.json" ] && [ ! -f "$HOME/.claude/.claude.json" ]; then
    mkdir -p "$HOME/.claude"
    cp "$HOME/.claude.json" "$HOME/.claude/.claude.json"
    say "~/.claude.json copied to ~/.claude/.claude.json"
    echo "   Tip: export CLAUDE_CONFIG_DIR=\$HOME/.claude in ~/.zshenv so that"
    echo "   sessions outside the sandbox use the same config."
fi

# --- kernel checks ----------------------------------------------------------
if [ -r /sys/kernel/security/landlock/abi_version ]; then
    say "Landlock ABI: $(cat /sys/kernel/security/landlock/abi_version) (>= 6 required)"
else
    say "Landlock ABI file not readable; a 6.12+ kernel with Landlock is required"
fi

# --- PATH hint --------------------------------------------------------------
case ":${PATH}:" in
    *":$PREFIX/bin:"*) : ;;
    *) echo "   Note: $PREFIX/bin is not on your PATH; add it to use 'claude-island'." ;;
esac

cat <<EOF

Done: $BIN
Try:
    cd ~/dev/my-project
    claude-island check              # canary suite: prove the sandbox holds
    claude-island                    # interactive setup, then launch
    claude-island --ro               # read-only project (code review)
    claude-island --detect           # block your code from leaving the sandbox
EOF
