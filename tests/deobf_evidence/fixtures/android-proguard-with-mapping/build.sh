#!/usr/bin/env bash
# Builds an obfuscated APK + retains its ProGuard mapping.txt as a sibling.
set -euo pipefail

CACHE_DIR="${CACHE_DIR:?CACHE_DIR required}"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR required}"

WORK="$CACHE_DIR/work"
rm -rf "$WORK"
mkdir -p "$WORK/src/com/example" "$WORK/classes" "$WORK/proguard"

cat > "$WORK/src/com/example/MainActivity.java" <<'EOF'
package com.example;

public class MainActivity {
    public static String greet(String name) {
        return "Hello, " + name;
    }
    public static int computeSecret(int a, int b) {
        return (a ^ 0xDEAD) + (b * 7);
    }
    public static void main(String[] args) {
        System.out.println(greet("world") + " -> " + computeSecret(1, 2));
    }
}
EOF

javac -d "$WORK/classes" "$WORK/src/com/example/MainActivity.java"

# ProGuard config: obfuscate everything, keep only `main` method, emit mapping.
cat > "$WORK/proguard/config.pro" <<'EOF'
-injars classes
-outjars classes-obf.jar
-libraryjars <java.home>/lib/rt.jar
-printmapping mapping.txt
-keep class com.example.MainActivity { public static void main(java.lang.String[]); }
-dontwarn
-dontnote
EOF

pushd "$WORK/proguard" >/dev/null
cp -r ../classes .
proguard @config.pro
popd >/dev/null

# Convert obfuscated jar to DEX.
d8 --output "$WORK" "$WORK/proguard/classes-obf.jar"

# Assemble minimal APK with manifest + dex.
cat > "$WORK/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example"/>
EOF

cd "$WORK"
zip -r sample.apk AndroidManifest.xml classes.dex

# Publish outputs: APK + sibling mapping.txt
mv "$WORK/sample.apk" "$CACHE_DIR/sample.apk"
cp "$WORK/proguard/mapping.txt" "$CACHE_DIR/sample.apk.mapping.txt"
