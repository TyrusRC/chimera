#!/usr/bin/env bash
# Set up a local Chimera dev environment. Idempotent — safe to re-run.
#
# Usage:
#   scripts/setup.sh                 # interactive: choose native or Docker
#   scripts/setup.sh --native         # Python deps in .venv (+ prompts for apt pkgs)
#   scripts/setup.sh --native --yes   # Python deps + apt pkgs, no prompts
#   scripts/setup.sh --docker         # docker build + docker compose up -d postgres
#
# Native mode installs `pip install -e ".[dev]"` into .venv, plus (opt-in,
# asks first) the apt-installable subset of external tools: radare2,
# jadx, upx-ucl, gdb. Every other external tool (Ghidra, ilspycmd, capa,
# frida, ...) has no single correct package across distros — after this
# script runs, `chimera doctor` reports exactly what's still missing and
# how to install it.
#
# Docker mode builds the bundled-toolchain image and brings up the
# Postgres container from docker-compose.yml; it does not touch the host
# Python environment. Use this if you'd rather not install the RE
# toolchain (Ghidra, jadx, r2, ...) directly on your machine.
#
# Neither mode is required for the other — pick one. Docker already
# bundles almost everything (see README's "Optional tools" section for
# the couple of tools left out by default), so most people who choose
# Docker can skip native setup entirely.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE=""
ASSUME_YES=0

for arg in "$@"; do
    case "$arg" in
        --native) MODE="native" ;;
        --docker) MODE="docker" ;;
        --yes|-y) ASSUME_YES=1 ;;
        -h|--help)
            sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg (see --help)" >&2
            exit 2
            ;;
    esac
done

confirm() {
    local prompt="$1"
    [[ "$ASSUME_YES" == "1" ]] && return 0
    [[ ! -t 0 ]] && return 1   # non-interactive, no --yes: default no
    read -r -p "$prompt [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

if [[ -z "$MODE" ]]; then
    if [[ -t 0 ]]; then
        echo "Set up Chimera:"
        echo "  1) Native  — Python deps in .venv on this host (+ optional apt packages)"
        echo "  2) Docker  — build the bundled-toolchain image + Postgres container"
        read -r -p "Choose [1/2] (default 1): " choice
        [[ "$choice" == "2" ]] && MODE="docker" || MODE="native"
    else
        MODE="native"
    fi
fi

if [[ "$MODE" == "docker" ]]; then
    echo "=== Docker setup ==="
    command -v docker >/dev/null || {
        echo "ERROR: docker not found. See docs.docker.com/get-docker" >&2
        exit 1
    }
    docker build -t chimera:latest .
    docker compose up -d postgres
    echo
    echo "Done."
    echo "  Full stack:   docker compose up"
    echo "  One-off cmd:  docker run --rm --entrypoint chimera chimera:latest info"
    exit 0
fi

echo "=== Native setup ==="

if command -v uv >/dev/null; then
    # This repo is uv-managed (uv.lock) — its .venv has no pip inside by
    # default, so prefer `uv` end to end when it's on PATH.
    [[ -d .venv ]] || uv venv --python 3.12
    uv pip install -q -e ".[dev]"
    echo "Python dependencies installed via uv (chimera[dev])"
else
    PY=python3
    command -v "$PY" >/dev/null || { echo "ERROR: python3 not found." >&2; exit 1; }
    PYVER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || {
        echo "ERROR: Python 3.12+ required, found $PYVER." >&2
        exit 1
    }
    echo "Python $PYVER OK"
    [[ -d .venv ]] || "$PY" -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -e ".[dev]"
    echo "Python dependencies installed (chimera[dev])"
fi

if command -v apt-get >/dev/null; then
    # jadx is the only backend for .jar / .apk decompilation — a JVM archive
    # has no native layer to fall back on, so without it those inputs analyze
    # to an empty model.
    if confirm "Install apt packages (radare2, jadx, upx-ucl, gdb) via sudo apt-get?"; then
        sudo apt-get update -qq
        sudo apt-get install -y radare2 jadx upx-ucl gdb
        echo "apt packages installed"
    else
        echo "Skipped apt packages — install manually, or re-run with --yes"
    fi
else
    echo "apt-get not found — skipping system packages"
fi

echo
echo "Done."
echo "  Activate:  source .venv/bin/activate"
echo "  Check:     chimera doctor"
