#!/usr/bin/env bash
# Build a Hermes-compiled RN bundle. Required: hermesc.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/index.js" <<'JS'
const API = "https://chimera-test.example.com/api/v1";
function greet(n) { return "hello " + n; }
console.log(greet("world"), API);
JS
hermesc -emit-binary -O -out "$CACHE_DIR/index.android.bundle" "$WORK/index.js"
echo "Built $CACHE_DIR/index.android.bundle"
