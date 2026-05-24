#!/usr/bin/env bash
# End-to-end smoke against chimera:latest in Docker. Headless.
#
# Mounts:
#   ./e2e/material -> /data   (real binaries)
#   ./projects     -> /projects
#   ./cache        -> /cache
#
# Exits non-zero on the first failure. Each step prints a one-line PASS/FAIL.

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Image existence check — without this the first failure is a confusing
# "Unable to find image" buried under every test command.
if ! docker image inspect chimera:latest >/dev/null 2>&1; then
    echo "ERROR: chimera:latest not built. Run: docker build -t chimera:latest ." >&2
    exit 2
fi

mkdir -p projects cache
PASS=0
FAIL=0

# Allow opt-in --no-ghidra for slower hardware (default exercises ghidra).
NO_GHIDRA=""
if [[ "${1:-}" == "--no-ghidra" ]]; then
    NO_GHIDRA="--no-ghidra"
    shift
fi

run() {
    local label="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        echo "PASS  $label"
        PASS=$((PASS+1))
    else
        echo "FAIL  $label"
        echo "$out" | tail -10 | sed 's/^/      | /'
        FAIL=$((FAIL+1))
    fi
}

docker_run() {
    docker run --rm \
        -v "$ROOT/e2e/material:/data:ro" \
        -v "$ROOT/projects:/projects" \
        -v "$ROOT/cache:/cache" \
        -e CHIMERA_CACHE_DIR=/cache \
        --entrypoint chimera \
        chimera:latest "$@"
}

echo "=== Toolchain sanity ==="
run "info" docker run --rm --entrypoint chimera chimera:latest info

echo
echo "=== CLI analyze per format ==="
run "analyze PE  hello.exe"   docker_run analyze /data/desktop/hello.exe   --project-dir /projects/pe   --cache-dir /cache $NO_GHIDRA
run "analyze ELF hello"       docker_run analyze /data/desktop/hello       --project-dir /projects/elf  --cache-dir /cache $NO_GHIDRA
run "analyze MachO tiny"      docker_run analyze /data/desktop/tiny.macho  --project-dir /projects/macho --cache-dir /cache $NO_GHIDRA
run "analyze .NET hello.dll"  docker_run analyze /data/desktop/hello.dll   --project-dir /projects/dotnet --cache-dir /cache $NO_GHIDRA
run "analyze APK sample.apk"  docker_run analyze /data/rn-android/sample.apk --project-dir /projects/apk --cache-dir /cache $NO_GHIDRA

echo
echo "=== CLI report ==="
run "report PE"   docker_run report /data/desktop/hello.exe   --cache-dir /cache --format json
run "report APK"  docker_run report /data/rn-android/sample.apk --cache-dir /cache --format json

echo
echo "=== CLI manifest (APK) ==="
run "manifest APK" docker_run manifest /data/rn-android/sample.apk --cache-dir /cache

echo
echo "=== CLI ioc + imports + sdks ==="
run "ioc APK"      docker_run ioc /data/rn-android/sample.apk --cache-dir /cache
run "imports PE"   docker_run imports /data/desktop/hello.exe --cache-dir /cache
run "sdks APK"     docker_run sdks /data/rn-android/sample.apk --cache-dir /cache

echo
echo "=== CLI diff ==="
# Diff two cached projects (sha256 by file content)
SHA_PE=$(sha256sum e2e/material/desktop/hello.exe | cut -c1-16)
SHA_APK=$(sha256sum e2e/material/rn-android/sample.apk | cut -c1-16)
run "diff PE vs APK" docker_run diff "$SHA_PE" "$SHA_APK" --cache-dir /cache

echo
echo "=== CLI patch (recipes + raw bytes) ==="
run "patch --list-recipes" docker_run patch --list-recipes /data/desktop/hello.exe
# Single VA patch — pick header padding so the analyzer still accepts the output.
run "patch PE @ VA" docker_run patch /data/desktop/hello.exe --addr 0x140001000 --bytes 9090909090909090 --dry-run

echo
echo "=== CLI gdb-export ==="
run "gdb-export ELF" docker_run gdb-export /data/desktop/hello --cache-dir /cache --project-dir /projects --out /cache/hello.gdbinit

echo
echo "=== CLI unpack (detect-only on clean binaries) ==="
run "unpack --detect-only PE"  docker_run unpack /data/desktop/hello.exe --detect-only
run "unpack --detect-only ELF" docker_run unpack /data/desktop/hello       --detect-only

echo
echo "=== CLI attach --help (frida-python loads) ==="
run "attach --help" docker_run attach --help

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
exit "$FAIL"
