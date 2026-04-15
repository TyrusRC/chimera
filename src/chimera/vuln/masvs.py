"""OWASP MASVS v2 mapping for Chimera findings."""

from __future__ import annotations

MASVS_CATEGORIES = {
    "MASVS-STORAGE": "Data storage and privacy",
    "MASVS-CRYPTO": "Cryptography",
    "MASVS-AUTH": "Authentication and session management",
    "MASVS-NETWORK": "Network communication",
    "MASVS-PLATFORM": "Platform interaction",
    "MASVS-CODE": "Code quality and build settings",
    "MASVS-RESILIENCE": "Resilience against reverse engineering",
}

# Rule prefix → (MASVS category, default MASTG test ID)
_RULE_MAP: dict[str, tuple[str, str]] = {
    "AUTH": ("MASVS-AUTH", "MSTG-AUTH-1"),
    "DATA": ("MASVS-STORAGE", "MSTG-STORAGE-1"),
    "NET": ("MASVS-NETWORK", "MSTG-NETWORK-1"),
    "CRYPTO": ("MASVS-CRYPTO", "MSTG-CRYPTO-1"),
    "IPC": ("MASVS-PLATFORM", "MSTG-PLATFORM-1"),
    "URL": ("MASVS-PLATFORM", "MSTG-PLATFORM-3"),
    "WEB": ("MASVS-PLATFORM", "MSTG-PLATFORM-5"),
    "NAT": ("MASVS-CODE", "MSTG-CODE-1"),
}

# Specific rule → specific MASTG test
_SPECIFIC_MAP: dict[str, str] = {
    "AUTH-001": "MSTG-STORAGE-14",
    "AUTH-002": "MSTG-AUTH-8",
    "AUTH-003": "MSTG-STORAGE-2",
    "DATA-001": "MSTG-STORAGE-1",
    "DATA-002": "MSTG-STORAGE-10",
    "DATA-003": "MSTG-STORAGE-8",
    "DATA-004": "MSTG-STORAGE-3",
    "DATA-005": "MSTG-STORAGE-5",
    "NET-001": "MSTG-NETWORK-4",
    "NET-002": "MSTG-NETWORK-1",
    "NET-003": "MSTG-NETWORK-3",
    "CRYPTO-001": "MSTG-CRYPTO-2",
    "CRYPTO-002": "MSTG-CRYPTO-1",
    "CRYPTO-003": "MSTG-CRYPTO-6",
    "CRYPTO-004": "MSTG-CRYPTO-4",
    "CRYPTO-005": "MSTG-CRYPTO-3",
    "IPC-001": "MSTG-PLATFORM-1",
    "IPC-002": "MSTG-PLATFORM-2",
    "IPC-003": "MSTG-PLATFORM-2",
    "IPC-005": "MSTG-PLATFORM-4",
    "IPC-006": "MSTG-PLATFORM-3",
    "WEB-001": "MSTG-PLATFORM-7",
    "WEB-002": "MSTG-PLATFORM-6",
    "WEB-003": "MSTG-PLATFORM-6",
    "NAT-001": "MSTG-CODE-8",
    "NAT-002": "MSTG-CODE-8",
}


def masvs_for_rule(rule_id: str) -> dict[str, str | None]:
    prefix = rule_id.split("-")[0]
    category, default_mastg = _RULE_MAP.get(prefix, ("MASVS-CODE", "MSTG-CODE-1"))
    mastg = _SPECIFIC_MAP.get(rule_id, default_mastg)
    return {"category": category, "mastg_test": mastg}
