"""Scan a jadx-decompiled source tree for protection-marker evidence.

Pure pattern walk over `*.java` / `*.kt` files: returns a list of
`(category, file:line, snippet)` hits. Used by `chimera detect-protections`
so it can report *where* a protection lives, not just yes/no.

Designed to be cheap: bytes-level prefilter per-file, then exact regex
only on files that pass the prefilter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from chimera.bypass.detector import (
    _DEBUG_PATTERNS, _FRIDA_PATTERNS, _INTEGRITY_PATTERNS,
    _JAILBREAK_PATTERNS, _ROOT_PATTERNS, _SSL_PATTERNS,
)


@dataclass
class JadxHit:
    category: str          # root_detection, ssl_pinning, anti_frida, ...
    file: Path
    line: int
    snippet: str           # the matched line, trimmed
    pattern: str


_CATEGORIES: list[tuple[str, list[str]]] = [
    ("root_detection", _ROOT_PATTERNS),
    ("jailbreak_detection", _JAILBREAK_PATTERNS),
    ("anti_frida", _FRIDA_PATTERNS),
    ("anti_debug", _DEBUG_PATTERNS),
    ("ssl_pinning", _SSL_PATTERNS),
    ("integrity", _INTEGRITY_PATTERNS),
]

# Cheap prefilter — short ASCII tokens that appear in *some* pattern in the
# matching category. If none are present in a file's raw bytes, skip the
# regex pass entirely. Keeps the full-tree walk fast on 11k-file APKs.
_PREFILTER_BY_CATEGORY: dict[str, tuple[bytes, ...]] = {
    "root_detection": (b"root", b"Root", b"Magisk", b"Superuser", b"/system/app", b"/sbin/su"),
    "jailbreak_detection": (b"Cydia", b"Sileo", b"jailbreak", b"jailbroken"),
    "anti_frida": (b"frida", b"Frida", b"27042", b"gum-js", b"LIBFRIDA"),
    "anti_debug": (b"ptrace", b"PT_DENY", b"TracerPid", b"isDebuggerConnected",
                   b"isDebuggerAttached", b"P_TRACED", b"anti-debug", b"anti_debug"),
    "ssl_pinning": (b"CertificatePinner", b"checkServerTrusted", b"TrustManager",
                    b"SecTrustEvaluate", b"BoringSSL", b"TrustKit", b"SSLPinning",
                    b"ssl-pinning", b"ssl_pinning"),
    "integrity": (b"GET_SIGNATURES", b"checksum", b"integrity", b"tamper",
                  b"csops", b"LC_CODE_SIGNATURE"),
}


def scan_jadx_tree(
    sources_dir: Path,
    platform: str,
    *,
    max_files: int = 20000,
    max_hits_per_category: int = 50,
) -> list[JadxHit]:
    """Walk *.java/*.kt under sources_dir and return protection-marker hits.

    `platform` filters root vs jailbreak detection (only relevant on the
    matching platform). `max_files` and `max_hits_per_category` cap work
    so an obfuscated 100k-file APK can't make this run forever.
    """
    sources_dir = Path(sources_dir)
    if not sources_dir.exists():
        return []

    cats = list(_CATEGORIES)
    if platform == "android":
        cats = [(c, p) for c, p in cats if c != "jailbreak_detection"]
    elif platform == "ios":
        cats = [(c, p) for c, p in cats if c != "root_detection"]

    compiled = {
        cat: [re.compile(p, re.IGNORECASE) for p in pats]
        for cat, pats in cats
    }
    hit_counts: dict[str, int] = {cat: 0 for cat, _ in cats}
    hits: list[JadxHit] = []

    for i, file in enumerate(sources_dir.rglob("*")):
        if i >= max_files:
            break
        if not file.is_file() or file.suffix not in (".java", ".kt"):
            continue
        try:
            raw = file.read_bytes()
        except OSError:
            continue

        for cat, pats in cats:
            if hit_counts[cat] >= max_hits_per_category:
                continue
            tokens = _PREFILTER_BY_CATEGORY.get(cat, ())
            if tokens and not any(t in raw for t in tokens):
                continue

            try:
                text = raw.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                continue

            for line_no, line in enumerate(text.splitlines(), start=1):
                for rx in compiled[cat]:
                    if rx.search(line):
                        hits.append(JadxHit(
                            category=cat, file=file, line=line_no,
                            snippet=line.strip()[:200],
                            pattern=rx.pattern,
                        ))
                        hit_counts[cat] += 1
                        break
                if hit_counts[cat] >= max_hits_per_category:
                    break

    return hits


def hits_to_profile_overlay(hits: list[JadxHit]) -> dict[str, list[dict]]:
    """Group hits by category for inclusion in the protection profile."""
    by_cat: dict[str, list[dict]] = {}
    for h in hits:
        by_cat.setdefault(h.category, []).append({
            "file": str(h.file),
            "line": h.line,
            "snippet": h.snippet,
            "pattern": h.pattern,
        })
    return by_cat
