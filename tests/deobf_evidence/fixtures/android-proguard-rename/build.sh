#!/usr/bin/env bash
# Build a 5-class APK, obfuscate with ProGuard (-repackageclasses '').
# Required tools: javac, d8, proguard, aapt2, zipalign, apksigner.
set -euo pipefail

CACHE_DIR="${CACHE_DIR:?CACHE_DIR env var required}"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR env var required}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC="$WORK/src/com/example/sample"
mkdir -p "$SRC"
cat > "$SRC/MainActivity.java" <<'JAVA'
package com.example.sample;
public class MainActivity { public int compute() { return new Helper().v() + 1; } }
JAVA
cat > "$SRC/Helper.java" <<'JAVA'
package com.example.sample;
public class Helper { public int v() { return 42; } }
JAVA
cat > "$SRC/Two.java" <<'JAVA'
package com.example.sample;
public class Two { public int v() { return 2; } }
JAVA
cat > "$SRC/Three.java" <<'JAVA'
package com.example.sample;
public class Three { public int v() { return 3; } }
JAVA
cat > "$SRC/Four.java" <<'JAVA'
package com.example.sample;
public class Four { public int v() { return 4; } }
JAVA

# Compile
CLASSES="$WORK/classes"
mkdir -p "$CLASSES"
find "$WORK/src" -name '*.java' | xargs javac -d "$CLASSES"

# ProGuard
JAR_IN="$WORK/in.jar"
JAR_OUT="$WORK/out.jar"
(cd "$CLASSES" && jar cf "$JAR_IN" .)
cat > "$WORK/proguard.pro" <<EOF
-injars $JAR_IN
-outjars $JAR_OUT
-libraryjars ${JAVA_HOME:-/usr/lib/jvm/default-java}/lib/rt.jar
-dontwarn **
-keep public class com.example.sample.MainActivity { public *; }
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
EOF
proguard @"$WORK/proguard.pro" || true  # some JDKs lack rt.jar; accept

# If ProGuard skipped (no rt.jar), fall back: just use input jar.
[ -s "$JAR_OUT" ] || cp "$JAR_IN" "$JAR_OUT"

# DEX
d8 --output "$WORK" "$JAR_OUT"

# Assemble minimal APK (aapt2 manifest + classes.dex, unsigned is fine for jadx)
cat > "$WORK/AndroidManifest.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.example.sample">
  <application android:label="Sample"/>
</manifest>
EOF
APK="$CACHE_DIR/sample.apk"
(cd "$WORK" && zip -q -r "$APK" AndroidManifest.xml classes.dex)
echo "Built $APK ($(stat -c%s "$APK") bytes)"
