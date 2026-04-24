#!/usr/bin/env bash
# Builds a Kotlin app exercising data class + companion object + extension fn.
set -euo pipefail

CACHE_DIR="${CACHE_DIR:?CACHE_DIR required}"
FIXTURE_DIR="${FIXTURE_DIR:?FIXTURE_DIR required}"

WORK="$CACHE_DIR/work"
rm -rf "$WORK"
mkdir -p "$WORK/src" "$WORK/classes"

cat > "$WORK/src/Greeter.kt" <<'EOF'
package com.example

data class Greeter(val name: String, val count: Int) {
    companion object {
        fun default(): Greeter = Greeter("world", 1)
    }
    fun greet(): String = "hello, $name".repeat(count)
}

fun String.shout(): String = this.uppercase() + "!"

fun main() {
    val g = Greeter.default().copy(count = 3)
    println(g.greet().shout())
}
EOF

kotlinc "$WORK/src/Greeter.kt" -include-runtime -d "$WORK/classes/app.jar"
d8 --output "$WORK" "$WORK/classes/app.jar"

cat > "$WORK/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example"/>
EOF

cd "$WORK"
zip -r sample.apk AndroidManifest.xml classes.dex
mv "$WORK/sample.apk" "$CACHE_DIR/sample.apk"
