#!/usr/bin/env bash
# Build an APK with a trivial static byte[] + XOR string decryptor.
# jadx is NOT expected to decrypt — the test asserts that fact explicitly.
set -euo pipefail

CACHE_DIR="${CACHE_DIR:?}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC="$WORK/src/com/example/xor"
mkdir -p "$SRC"
cat > "$SRC/Main.java" <<'JAVA'
package com.example.xor;
public class Main {
  private static final byte[] BLOB = {0x10, 0x15, 0x1c, 0x1c, 0x1f};  // "hello" XOR 0x78
  public static String decrypt() {
    byte[] out = new byte[BLOB.length];
    for (int i = 0; i < BLOB.length; i++) out[i] = (byte)(BLOB[i] ^ 0x78);
    return new String(out);
  }
  public static void main(String[] a) { System.out.println(decrypt()); }
}
JAVA

CLASSES="$WORK/classes"
mkdir -p "$CLASSES"
javac -d "$CLASSES" "$SRC/Main.java"
JAR="$WORK/app.jar"
(cd "$CLASSES" && jar cf "$JAR" .)
d8 --output "$WORK" "$JAR"

cat > "$WORK/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.example.xor"><application android:label="Xor"/></manifest>
EOF
APK="$CACHE_DIR/sample.apk"
(cd "$WORK" && zip -q -r "$APK" AndroidManifest.xml classes.dex)
echo "Built $APK"
