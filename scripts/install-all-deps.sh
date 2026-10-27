#!/usr/bin/env bash
# Install ALL optional dependencies for chimera — the full RE + exploit + malware toolkit.
#
# Usage:
#   scripts/install-all-deps.sh            # interactive — asks before each group
#   scripts/install-all-deps.sh --yes      # install everything, no prompts
#   scripts/install-all-deps.sh --check    # dry-run: report what's missing
#
# Groups:
#   core      — radare2, jadx, gdb, upx, qemu-user, nodejs, npm, webcrack
#   exploit   — pwntools, ropper, ROPgadget, one_gadget, checksec
#   malware   — yara-python, flare-capa, flare-floss, speakeasy-emulator
#   dynamic   — frida, unicorn, capstone, keystone-engine, angr
#   mobile    — centurion (sibling), apktool, apkid, apkleaks
#   sast      — mantis-sast (sibling), opengrep
#   deobf     — webcrack (npm), prettier (npm)
#   emulation — qiling (pip)
#
# After running, use `chimera doctor` to verify everything.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ASSUME_YES=0
CHECK_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --yes|-y) ASSUME_YES=1 ;;
        --check)  CHECK_ONLY=1 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

confirm() {
    [[ "$ASSUME_YES" == "1" ]] && return 0
    [[ ! -t 0 ]] && return 1
    read -r -p "$1 [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

check_cmd() { command -v "$1" &>/dev/null; }
check_py()  { python3 -c "import $1" &>/dev/null; }

status() {
    local name="$1" available="$2"
    if [ "$available" = "1" ]; then
        printf "  ✓ %-25s installed\n" "$name"
    else
        printf "  ✗ %-25s MISSING\n" "$name"
    fi
}

PIP="pip3"
if [ -f "$ROOT/.venv/bin/pip" ]; then
    PIP="$ROOT/.venv/bin/pip"
elif check_cmd uv; then
    PIP="uv pip"
fi

echo "=== Chimera Dependency Status ==="
echo ""

# ── Core RE tools (apt) ─────────────────────────────────────────────
echo "── Core RE tools ──"
for cmd in r2 jadx gdb upx qemu-aarch64 node npm; do
    check_cmd "$cmd" && status "$cmd" 1 || status "$cmd" 0
done
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install core apt packages (radare2, jadx, gdb, upx, qemu-user, nodejs, npm)?"; then
    sudo apt-get update -qq
    sudo apt-get install -y radare2 jadx upx-ucl gdb qemu-user qemu-user-static nodejs npm 2>/dev/null || true
fi

# ── Exploit tools (pip + system) ─────────────────────────────────────
echo "── Exploit tools ──"
check_py pwnlib   && status "pwntools"   1 || status "pwntools"   0
check_cmd ROPgadget && status "ROPgadget" 1 || status "ROPgadget" 0
check_cmd checksec && status "checksec"   1 || status "checksec"   0
check_py ropper   && status "ropper"     1 || status "ropper"     0
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install exploit tools (pwntools, ROPgadget, ropper)?"; then
    $PIP install --quiet pwntools ROPgadget ropper 2>/dev/null || true
fi

# ── Malware analysis (pip) ───────────────────────────────────────────
echo "── Malware analysis tools ──"
check_py yara      && status "yara-python" 1 || status "yara-python" 0
check_cmd capa     && status "flare-capa"  1 || status "flare-capa"  0
check_cmd floss    && status "flare-floss" 1 || status "flare-floss" 0
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install malware tools (yara-python, flare-capa, flare-floss)?"; then
    $PIP install --quiet yara-python 2>/dev/null || true
    $PIP install --quiet flare-capa flare-floss 2>/dev/null || true
fi

# ── Dynamic analysis (pip) ───────────────────────────────────────────
echo "── Dynamic analysis tools ──"
check_py frida     && status "frida"      1 || status "frida"      0
check_py unicorn   && status "unicorn"    1 || status "unicorn"    0
check_py capstone  && status "capstone"   1 || status "capstone"   0
check_py keystone  && status "keystone"   1 || status "keystone"   0
check_py angr      && status "angr"       1 || status "angr"       0
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install dynamic tools (frida, unicorn, capstone, keystone, angr)?"; then
    $PIP install --quiet frida-tools unicorn capstone keystone-engine 2>/dev/null || true
    $PIP install --quiet angr 2>/dev/null || true
fi

# ── SAST (sibling projects) ──────────────────────────────────────────
echo "── SAST tools ──"
check_py mantis    && status "mantis-sast" 1 || status "mantis-sast" 0
check_cmd opengrep && status "opengrep"    1 || status "opengrep"    0
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install mantis-sast (editable from sibling)?"; then
    MANTIS_DIR="$ROOT/../mantis"
    if [ -d "$MANTIS_DIR" ]; then
        $PIP install --quiet -e "$MANTIS_DIR" 2>/dev/null || true
    else
        $PIP install --quiet mantis-sast 2>/dev/null || true
    fi
fi

# ── Mobile (sibling project) ─────────────────────────────────────────
echo "── Mobile tools ──"
check_py centurion && status "centurion"  1 || status "centurion"  0
check_cmd apktool  && status "apktool"    1 || status "apktool"    0
check_cmd apkid    && status "apkid"      1 || status "apkid"      0
echo ""

if [ "$CHECK_ONLY" = "0" ] && confirm "Install centurion (editable from sibling)?"; then
    CENT_DIR="$ROOT/../centurion"
    if [ -d "$CENT_DIR" ]; then
        $PIP install --quiet -e "$CENT_DIR" 2>/dev/null || true
    else
        $PIP install --quiet centurion 2>/dev/null || true
    fi
fi

# ── JS deobfuscation (npm) ───────────────────────────────────────────
echo "── JS deobfuscation ──"
check_cmd webcrack  && status "webcrack"  1 || status "webcrack"  0
check_cmd prettier  && status "prettier"  1 || status "prettier"  0
echo ""

if [ "$CHECK_ONLY" = "0" ] && check_cmd npm && confirm "Install JS tools (webcrack, prettier) via npm?"; then
    npm install -g webcrack prettier 2>/dev/null || true
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "=== Done ==="
echo "Run 'chimera doctor' for a full health check."
echo "Run 'scripts/install-all-deps.sh --check' to see what's still missing."
