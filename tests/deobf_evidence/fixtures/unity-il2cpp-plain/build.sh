#!/usr/bin/env bash
# Produce minimal global-metadata.dat (valid magic + 100+ bytes) and a stub
# libil2cpp.so. No Unity editor required.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"

# Magic bytes \xAF\x1B\xB1\xFA then 4-byte version + padding to pass 100-byte gate.
printf '\xaf\x1b\xb1\xfa\x18\x00\x00\x00' > "$CACHE_DIR/global-metadata.dat"
dd if=/dev/zero bs=1 count=200 >> "$CACHE_DIR/global-metadata.dat" 2>/dev/null

# Stub ARM64 .so — empty ELF shell; Il2CppDumper will fail, adapter handles it.
printf '\x7fELF\x02\x01\x01\x00' > "$CACHE_DIR/libil2cpp.so"
dd if=/dev/zero bs=1 count=64 >> "$CACHE_DIR/libil2cpp.so" 2>/dev/null

echo "Built $CACHE_DIR/global-metadata.dat and libil2cpp.so"
