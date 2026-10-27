#!/usr/bin/env bash
# Set up chimera with ALL dependencies — the full RE + exploit + malware toolkit.
# Idempotent — safe to re-run.
#
# Usage:
#   scripts/setup.sh              # install everything (sudo required for apt)
#   scripts/setup.sh --check      # dry-run: report what's installed/missing
#   scripts/setup.sh --minimal    # venv + chimera[dev] only, no extras
#   scripts/setup.sh --docker     # Docker mode (build image + postgres)
#
# Installs ALL dependencies by default — no optional tools, no prompts:
#   1. Create .venv, install chimera[dev]
#   2. Install all pip packages (pwntools, frida, capa, floss, angr, ...)
#   3. Install sibling projects (mantis, centurion) if found
#   4. Install apt packages (radare2, jadx, gdb, qemu-user, nodejs)
#   5. Install npm tools (webcrack, prettier)
#   6. Print dependency status

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="full"

for arg in "$@"; do
    case "$arg" in
        --docker)  MODE="docker" ;;
        --minimal) MODE="minimal" ;;
        --check)   MODE="check" ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg (see --help)" >&2
            exit 2
            ;;
    esac
done

check_cmd() { command -v "$1" &>/dev/null; }

VENV_PY="python3"
[ -f "$ROOT/.venv/bin/python3" ] && VENV_PY="$ROOT/.venv/bin/python3"
check_py() { $VENV_PY -c "import $1" &>/dev/null 2>&1; }

status() {
    if [ "$2" = "1" ]; then
        printf "  ✓ %-25s installed\n" "$1"
    else
        printf "  ✗ %-25s MISSING\n" "$1"
    fi
}

# ── Docker mode ──────────────────────────────────────────────────────
if [[ "$MODE" == "docker" ]]; then
    echo "=== Docker setup ==="
    check_cmd docker || { echo "ERROR: docker not found." >&2; exit 1; }
    docker build -t chimera:latest .
    docker compose up -d postgres
    echo "Done. Full stack: docker compose up"
    exit 0
fi

# ── Dependency status ────────────────────────────────────────────────
print_status() {
    echo "=== Chimera Dependency Status ==="
    echo ""
    echo "── Core RE ──"
    for cmd in r2 jadx gdb upx qemu-aarch64 node npm; do
        check_cmd "$cmd" && status "$cmd" 1 || status "$cmd" 0
    done
    echo ""
    echo "── Exploit ──"
    check_py pwnlib     && status "pwntools"   1 || status "pwntools"   0
    check_cmd ROPgadget && status "ROPgadget"  1 || status "ROPgadget"  0
    check_cmd checksec  && status "checksec"   1 || status "checksec"   0
    check_py ropper     && status "ropper"     1 || status "ropper"     0
    echo ""
    echo "── Malware ──"
    check_py yara                               && status "yara-python" 1 || status "yara-python" 0
    { check_cmd capa  || check_py capa.main; }  && status "flare-capa"  1 || status "flare-capa"  0
    { check_cmd floss || check_py floss; }      && status "flare-floss" 1 || status "flare-floss" 0
    echo ""
    echo "── Dynamic ──"
    check_py frida    && status "frida"     1 || status "frida"     0
    check_py unicorn  && status "unicorn"   1 || status "unicorn"   0
    check_py capstone && status "capstone"  1 || status "capstone"  0
    check_py keystone && status "keystone"  1 || status "keystone"  0
    check_py angr     && status "angr"      1 || status "angr"      0
    echo ""
    echo "── SAST ──"
    check_py mantis    && status "mantis-sast" 1 || status "mantis-sast" 0
    check_cmd opengrep && status "opengrep"    1 || status "opengrep"    0
    echo ""
    echo "── Mobile ──"
    check_py centurion && status "centurion" 1 || status "centurion" 0
    check_cmd apktool  && status "apktool"   1 || status "apktool"   0
    echo ""
    echo "── JS deobf ──"
    check_cmd webcrack && status "webcrack"  1 || status "webcrack"  0
    check_cmd prettier && status "prettier"  1 || status "prettier"  0
    echo ""
}

if [[ "$MODE" == "check" ]]; then
    print_status
    exit 0
fi

# ── Step 1: venv + chimera[dev] ──────────────────────────────────────
echo "=== Step 1: Python environment ==="
if check_cmd uv; then
    [[ -d .venv ]] || uv venv --python 3.12
    uv pip install -q -e ".[dev]"
    PIP="uv pip install --quiet"
    echo "  chimera[dev] installed via uv"
else
    PY=python3
    check_cmd "$PY" || { echo "ERROR: python3 not found." >&2; exit 1; }
    [[ -d .venv ]] || "$PY" -m venv .venv
    .venv/bin/pip install -q --upgrade pip
    .venv/bin/pip install -q -e ".[dev]"
    PIP=".venv/bin/pip install --quiet"
    echo "  chimera[dev] installed via pip"
fi
# Refresh venv python path for checks
VENV_PY="$ROOT/.venv/bin/python3"

[[ "$MODE" == "minimal" ]] && { echo "Done (minimal)."; print_status; exit 0; }

# ── Step 2: pip extras (always, no prompt) ───────────────────────────
echo "=== Step 2: Python packages ==="
$PIP pwntools ROPgadget ropper 2>/dev/null || true
echo "  exploit tools"
$PIP yara-python 2>/dev/null || true
$PIP flare-capa flare-floss 2>/dev/null || true
echo "  malware tools"
$PIP frida-tools unicorn capstone keystone-engine 2>/dev/null || true
echo "  dynamic tools"
$PIP angr 2>/dev/null || true
echo "  symbolic execution"

# ── Step 3: sibling projects ─────────────────────────────────────────
echo "=== Step 3: Sibling projects ==="
for sibling in mantis centurion; do
    DIR="$ROOT/../$sibling"
    if [ -d "$DIR" ]; then
        $PIP -e "$DIR" 2>/dev/null || true
        echo "  $sibling (editable from $DIR)"
    fi
done

# ── Step 4: apt packages (needs sudo) ────────────────────────────────
echo "=== Step 4: System packages ==="
if check_cmd apt-get; then
    sudo apt-get update -qq
    sudo apt-get install -y radare2 jadx upx-ucl gdb qemu-user qemu-user-static nodejs npm 2>/dev/null || true
    echo "  apt packages installed"
fi

# ── Step 5: npm tools ────────────────────────────────────────────────
echo "=== Step 5: npm tools ==="
if check_cmd npm; then
    npm install -g webcrack prettier 2>/dev/null && echo "  webcrack + prettier" || true
fi

# ── Done ─────────────────────────────────────────────────────────────
echo ""
print_status
echo "Activate: source .venv/bin/activate"
echo "Verify:   chimera doctor"
