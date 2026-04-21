#!/usr/bin/env bash
# Build a 5-class APK, obfuscate with ProGuard (-repackageclasses '').
# Required tools: javac, d8, proguard (optional), zip.
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
PROGUARD_APPLIED=1
proguard @"$WORK/proguard.pro" || PROGUARD_APPLIED=0

if [ ! -s "$JAR_OUT" ] || [ "$PROGUARD_APPLIED" = "0" ]; then
  echo "WARN: ProGuard did not run (likely missing rt.jar on JDK 9+); sample is NOT obfuscated" >&2
  touch "$CACHE_DIR/.proguard_skipped"
  cp "$JAR_IN" "$JAR_OUT"
else
  rm -f "$CACHE_DIR/.proguard_skipped"
fi

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
