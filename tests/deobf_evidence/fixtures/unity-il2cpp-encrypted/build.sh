#!/usr/bin/env bash
# Produce a high-entropy global-metadata.dat with a wrong magic to simulate
# an encrypted / anti-tamper protected metadata file.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"

# Wrong magic (intentionally scrambled) + random high-entropy payload.
printf '\xde\xad\xbe\xef' > "$CACHE_DIR/global-metadata.dat"
dd if=/dev/urandom bs=1 count=65536 >> "$CACHE_DIR/global-metadata.dat" 2>/dev/null

# Stub libil2cpp.so
printf '\x7fELF\x02\x01\x01\x00' > "$CACHE_DIR/libil2cpp.so"
dd if=/dev/zero bs=1 count=64 >> "$CACHE_DIR/libil2cpp.so" 2>/dev/null

echo "Built encrypted-metadata fixture"
