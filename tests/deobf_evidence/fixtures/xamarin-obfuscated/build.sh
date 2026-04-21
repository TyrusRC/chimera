#!/usr/bin/env bash
# Build a trivial .NET DLL and run it through ConfuserEx (or skip).
# Required: csc (mono/dotnet) and ConfuserEx. If ConfuserEx absent, ship the
# unobfuscated DLL — the test tolerates that and becomes a bail-cleanly check.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/Lib.cs" <<'CS'
using System;
public class Greeter {
    public string Hello(string name) { return "Hello " + name; }
    public int Secret() { return 0x1337; }
}
CS

if command -v dotnet >/dev/null; then
    dotnet run --project /dev/null 2>/dev/null || true
fi

if command -v csc >/dev/null; then
    csc -target:library -out:"$WORK/Lib.dll" "$WORK/Lib.cs"
elif command -v mcs >/dev/null; then
    mcs -target:library -out:"$WORK/Lib.dll" "$WORK/Lib.cs"
else
    echo "No C# compiler (csc/mcs) available" >&2
    exit 1
fi

if command -v ConfuserEx >/dev/null; then
    ConfuserEx --output="$WORK/out" "$WORK/Lib.dll" || cp "$WORK/Lib.dll" "$WORK/out/Lib.dll"
    cp "$WORK/out/Lib.dll" "$CACHE_DIR/Lib.dll"
else
    cp "$WORK/Lib.dll" "$CACHE_DIR/Lib.dll"
fi
echo "Built $CACHE_DIR/Lib.dll"
