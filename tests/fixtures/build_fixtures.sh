#!/usr/bin/env bash
# Build minimal triage fixtures for PE/ELF/.NET.
# This script is committed but NOT auto-run by CI.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Building Linux ELF fixture (gcc, static)"
gcc -static -O0 -o elf/hello src/hello.c
strip elf/hello
ls -lh elf/hello

if command -v x86_64-w64-mingw32-gcc >/dev/null; then
    echo "==> Building Windows PE fixture (mingw)"
    x86_64-w64-mingw32-gcc -O0 -o pe/hello.exe src/hello.c
    ls -lh pe/hello.exe
else
    echo "==> Skipping PE (mingw not available); using Python-synthesized fixture"
    python3 build_pe_fixture.py
fi

if command -v dotnet >/dev/null; then
    echo "==> Building .NET fixture (dotnet publish)"
    cd dotnet/src && dotnet publish -c Release -r linux-x64 --self-contained false -o ../bin
    cd ../..
else
    echo "==> Skipping .NET (dotnet not available); using Python-synthesized fixture"
    python3 build_dotnet_fixture.py
fi
