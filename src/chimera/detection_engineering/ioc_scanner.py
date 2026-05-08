"""IoC pattern scanner — pull URLs, IPs, domains, hashes, crypto addresses
from analyzed strings.

Each match carries a `confidence` score (high/medium/low) and a category
tag the analyst can group on. We deliberately bias toward HIGH precision
over recall: filter aggressively to keep the IoC list short and useful
rather than long and noisy.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

# Confidence levels
CONF_HIGH = "high"
CONF_MEDIUM = "medium"
CONF_LOW = "low"


@dataclass
class IocMatch:
    value: str
    category: str          # "url" | "ipv4" | "ipv6" | "domain" | "email" | "hash_md5" | "hash_sha1" | "hash_sha256" | "btc_address" | "onion_v3"
    confidence: str        # CONF_HIGH | CONF_MEDIUM | CONF_LOW
    source_string: str     # the string the match was found in
    source_address: str | None = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "category": self.category,
            "confidence": self.confidence,
            "source_string": self.source_string[:200],
            "source_address": self.source_address,
            "notes": self.notes,
        }


# ---- Regex patterns ----
# URL: http(s)?://... up to first whitespace/quote/closing-bracket
_URL_RX = re.compile(
    r"\bhttps?://[^\s\"'<>{}|\\^`]+",
    re.IGNORECASE,
)

# IPv4: four 1-3 digit octets joined by dots, with word boundaries
_IPV4_RX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

# IPv6 (simplified — full grammar is hairy; this catches the common forms)
_IPV6_RX = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
)

# Domain (FQDN of at least 2 labels). Reject single-word "labels" — they're
# typically class names. Require at least one dot and a TLD-like ending.
_DOMAIN_RX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

_EMAIL_RX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"
)

# Hashes
_MD5_RX = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RX = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RX = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Bitcoin address (P2PKH/P2SH legacy + Bech32 SegWit). Conservative.
_BTC_RX = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{8,87})\b"
    r"|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
)

# Tor v3 onion (56-char base32 + .onion)
_ONION_V3_RX = re.compile(r"\b[a-z2-7]{56}\.onion\b")


# ---- Filters ----

# Common false positives (test/example domains)
_DOMAIN_DENYLIST: set[str] = {
    "example.com", "example.org", "example.net",
    "localhost", "localdomain", "invalid",
    "schemas.android.com", "schemas.microsoft.com",
    "schemas.xmlsoap.org", "www.w3.org", "www.iana.org",
    "java.lang", "java.util", "java.io",
    "android.app", "android.content", "android.os",
    "kotlin.collections", "kotlin.jvm",
}

# File-extension-shaped strings that look like domains
_EXT_LIKE: set[str] = {
    "so", "dll", "exe", "jar", "apk", "ipa", "dex",
    "xml", "json", "yaml", "yml", "properties", "txt",
    "py", "js", "ts", "html", "css", "md", "rst",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
    "mp3", "mp4", "wav", "ogg", "flac",
    "zip", "tar", "gz", "bz2", "7z", "rar",
    "kt", "java", "swift", "m", "h", "c", "cpp", "cc",
    "log", "bak", "tmp", "lock", "cache",
}


def _is_filtered_ipv4(addr: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(addr)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_private or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_link_local:
        return True
    if ip.is_unspecified:    # 0.0.0.0
        return True
    # Documentation ranges (RFC 5737)
    doc_ranges = (
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("203.0.113.0/24"),
    )
    if any(ip in net for net in doc_ranges):
        return True
    # Crude version-number filter: e.g., "1.2.3.4" is rarely a real IP.
    # Only filter when every octet is < 5 — this traps "1.2.3.4" style
    # version strings while keeping well-known public IPs like 8.8.8.8.
    octets = addr.split(".")
    if all(int(o) < 5 for o in octets):
        return True
    return False


def _is_filtered_domain(value: str) -> bool:
    lower = value.lower()
    if lower in _DOMAIN_DENYLIST:
        return True
    # Reject if the TLD is actually a file extension
    last = lower.rsplit(".", 1)[-1]
    if last in _EXT_LIKE:
        return True
    # Common Java/Kotlin package roots
    if any(lower.startswith(p) for p in (
        "java.", "javax.", "kotlin.", "android.", "androidx.",
        "com.android.", "org.json.", "com.google.android.",
    )):
        return True
    # Schema URIs can leak through if the URL regex didn't catch them
    if any(part in lower for part in ("schemas.", ".test", ".invalid")):
        return True
    return False


def _is_filtered_url(value: str) -> bool:
    lower = value.lower()
    if any(domain in lower for domain in (
        "://localhost", "://127.0.0.1", "://0.0.0.0",
        "://example.com", "://example.org", "://example.net",
        "://schemas.", "://www.w3.org", "://www.iana.org",
    )):
        return True
    return False


def _confidence_for_ipv4(addr: str) -> str:
    # Public IPs that aren't in version-number territory get HIGH;
    # the filter already removed everything else.
    return CONF_HIGH


def _confidence_for_domain(value: str) -> str:
    # Long, unusual domains rate HIGH; common short ones are MEDIUM.
    if len(value) >= 16 and value.count(".") >= 2:
        return CONF_HIGH
    return CONF_MEDIUM


def _extract(s) -> tuple[str | None, str | None]:
    """Pull (value, address) from a StringEntry-like, dict, or string."""
    if isinstance(s, str):
        return s, None
    if hasattr(s, "value"):
        return s.value, getattr(s, "address", None)
    if isinstance(s, dict):
        return s.get("value"), s.get("address")
    return None, None


def scan_iocs(strings: Iterable) -> list[IocMatch]:
    """Scan an iterable of strings (or StringEntry-likes) for IoCs.

    Returns deduplicated matches, ordered by category then confidence.
    """
    out: list[IocMatch] = []
    seen: set[tuple[str, str]] = set()  # (category, value)

    def add(value: str, category: str, conf: str, source: str,
            address: str | None, notes: str = ""):
        key = (category, value)
        if key in seen:
            return
        seen.add(key)
        out.append(IocMatch(
            value=value, category=category, confidence=conf,
            source_string=source, source_address=address, notes=notes,
        ))

    for s in strings:
        text, addr = _extract(s)
        if not text or len(text) < 6:
            continue

        # URLs (highest priority — strip the URL out before matching domain)
        url_matches: list[tuple[int, int, str]] = []
        for m in _URL_RX.finditer(text):
            url = m.group(0).rstrip(".,;)\"'")
            if _is_filtered_url(url):
                continue
            add(url, "url", CONF_HIGH, text, addr)
            url_matches.append((m.start(), m.end(), url))

        # Mask URL spans so the domain regex doesn't double-match them
        masked = list(text)
        for start, end, _ in url_matches:
            for i in range(start, min(end, len(masked))):
                masked[i] = " "
        masked_text = "".join(masked)

        # IPv4
        for m in _IPV4_RX.finditer(masked_text):
            ip = m.group(0)
            if _is_filtered_ipv4(ip):
                continue
            add(ip, "ipv4", _confidence_for_ipv4(ip), text, addr)

        # IPv6 — keep simple; no filtering for private ranges yet
        for m in _IPV6_RX.finditer(masked_text):
            v = m.group(0)
            # Skip obviously trivial expansions
            if v in ("::", "::1") or v.startswith("fe80:"):
                continue
            add(v, "ipv6", CONF_MEDIUM, text, addr)

        # Email
        for m in _EMAIL_RX.finditer(masked_text):
            v = m.group(0)
            domain_part = v.split("@", 1)[1]
            if _is_filtered_domain(domain_part):
                continue
            add(v, "email", CONF_MEDIUM, text, addr)

        # Domain (only if it looks like a real FQDN, AND wasn't already
        # captured as a URL host)
        for m in _DOMAIN_RX.finditer(masked_text):
            v = m.group(0).rstrip(".,;)\"'").lower()
            if _is_filtered_domain(v):
                continue
            # Skip if it's actually a hash literal
            if _MD5_RX.fullmatch(v) or _SHA1_RX.fullmatch(v) or _SHA256_RX.fullmatch(v):
                continue
            add(v, "domain", _confidence_for_domain(v), text, addr)

        # Hashes — order matters: match SHA-256 before SHA-1 before MD5
        for rx, cat in ((_SHA256_RX, "hash_sha256"),
                        (_SHA1_RX, "hash_sha1"),
                        (_MD5_RX, "hash_md5")):
            for m in rx.finditer(text):
                v = m.group(0).lower()
                add(v, cat, CONF_MEDIUM, text, addr)

        # Bitcoin
        for m in _BTC_RX.finditer(text):
            v = m.group(0)
            # Conservative: require minimum length to dodge stray hashes
            if len(v) < 26:
                continue
            add(v, "btc_address", CONF_HIGH, text, addr)

        # Tor v3 onion
        for m in _ONION_V3_RX.finditer(text.lower()):
            add(m.group(0), "onion_v3", CONF_HIGH, text, addr)

    # Sort: category alphabetical, then confidence (high first), then value
    conf_order = {CONF_HIGH: 0, CONF_MEDIUM: 1, CONF_LOW: 2}
    out.sort(key=lambda m: (m.category, conf_order.get(m.confidence, 99), m.value))
    return out


def summarize(matches: list[IocMatch]) -> dict[str, int]:
    """Counts per category — useful for the report summary line."""
    counts: dict[str, int] = {}
    for m in matches:
        counts[m.category] = counts.get(m.category, 0) + 1
    return counts
