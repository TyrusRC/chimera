#!/usr/bin/env bash
# swift-ios-mangled fixture: trivially copy a pre-checked-in mangled-names list
# to the cache. The mangled-name list is what the SwiftDemangleAdapter is asked
# to demangle in the evidence test; no Swift toolchain needed at fixture build
# time, only swift-demangle at evidence-test runtime.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?CACHE_DIR env var required}"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR env var required}"
cp "$FIXTURE_DIR/mangled_names.txt" "$CACHE_DIR/sample.txt"
