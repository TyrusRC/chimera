#!/usr/bin/env bash
# Build a Metro-style JSC bundle — plain JS with __d() module wrappers.
# No native deps; a shell heredoc produces a realistic-enough bundle.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
cat > "$CACHE_DIR/index.android.bundle" <<'JS'
var __DEV__ = false;
var __BUNDLE_START_TIME__ = 0;
__d(function(global, require, module, exports){
  module.exports = { url: "https://chimera-jsc-test.example.com/v2" };
}, 0, [], "modA");
__d(function(global, require, module, exports){
  module.exports = { token: "Bearer sk-live-abc123def456ghi789" };
}, 1, [], "modB");
__d(function(global, require, module, exports){
  module.exports = function greet(name) { return "hello " + name; };
}, 2, [], "modC");
require(0);
JS
echo "Built $CACHE_DIR/index.android.bundle"
