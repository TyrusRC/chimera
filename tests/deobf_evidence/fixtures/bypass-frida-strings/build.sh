#!/usr/bin/env bash
# Produce a tiny file whose "strings" trigger every protection detector.
set -euo pipefail
CACHE_DIR="${CACHE_DIR:?}"
cat > "$CACHE_DIR/strings.txt" <<'EOF'
LIBFRIDA
/sbin/su
PT_DENY_ATTACH
CertificatePinner
PackageManager.signatures
libjiagu.so
UPX!
com.topjohnwu.magisk
/Applications/Cydia.app
frida-agent
EOF
echo "Built $CACHE_DIR/strings.txt"
