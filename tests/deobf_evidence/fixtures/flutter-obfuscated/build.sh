#!/usr/bin/env bash
# Build a minimal Flutter app with --obfuscate and extract libapp.so.
# Required: flutter (stable channel), dart. Large toolchain — skip if absent.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
flutter create --platforms=android -t app tiny >/dev/null
cd tiny
cat > lib/main.dart <<'DART'
import 'package:flutter/material.dart';
void main() => runApp(const MaterialApp(home: Scaffold(body: Text('hi'))));
DART
flutter build apk --release --target-platform=android-arm64 \
  --obfuscate --split-debug-info=build/debug-info >/dev/null
APK="build/app/outputs/flutter-apk/app-release.apk"
[ -s "$APK" ] || { echo "flutter build produced no APK"; exit 1; }
UNZIP="$WORK/unz"
unzip -q -d "$UNZIP" "$APK"
LIBAPP="$UNZIP/lib/arm64-v8a/libapp.so"
[ -s "$LIBAPP" ] || { echo "libapp.so not found"; exit 1; }
cp "$LIBAPP" "$CACHE_DIR/libapp.so"
echo "Built $CACHE_DIR/libapp.so"
