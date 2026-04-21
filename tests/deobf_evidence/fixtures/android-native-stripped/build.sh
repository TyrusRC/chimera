#!/usr/bin/env bash
# Build a stripped ARM64 shared library with simple control flow.
# Required: clang with aarch64-linux-gnu target, llvm-strip.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/lib.c" <<'C'
#include <stddef.h>
int compute_answer(int n) {
  int r = 0;
  for (int i = 1; i <= n; i++) { r += i * i; }
  return r;
}
const char* banner(void) { return "chimera-test-banner-v1"; }
int entry(int argc) {
  if (argc > 3) return compute_answer(argc);
  return 0;
}
C

clang --target=aarch64-linux-gnu -shared -fPIC -O1 -nostdlib \
      -o "$WORK/libfoo.so" "$WORK/lib.c"
llvm-strip --strip-all "$WORK/libfoo.so"
cp "$WORK/libfoo.so" "$CACHE_DIR/libfoo.so"
echo "Built $CACHE_DIR/libfoo.so"
