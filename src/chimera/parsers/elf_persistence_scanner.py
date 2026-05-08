"""Scan extracted strings for Linux persistence-related paths.

Categories: cron, systemd_unit, systemd_user, rc_local, ld_preload,
bashrc, ssh_authorized, proc_inspect, dev_access, init_d, xdg_autostart.

Output is best-effort — false positives are acceptable; analysts will
re-grep for context. The goal is to surface candidates fast.
"""
from __future__ import annotations

import re
from typing import Iterable


_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("cron",            re.compile(r"/etc/cron\.(d|hourly|daily|weekly|monthly)/")),
    ("cron",            re.compile(r"/var/spool/cron/")),
    ("cron",            re.compile(r"/etc/anacrontab")),
    ("systemd_unit",    re.compile(r"/etc/systemd/system/.*\.service")),
    ("systemd_unit",    re.compile(r"/lib/systemd/system/.*\.service")),
    ("systemd_unit",    re.compile(r"/usr/lib/systemd/system/.*\.service")),
    ("systemd_user",    re.compile(r"\.config/systemd/user/.*\.service")),
    ("rc_local",        re.compile(r"/etc/rc\.local")),
    ("ld_preload",      re.compile(r"/etc/ld\.so\.preload")),
    ("ld_preload",      re.compile(r"\bLD_PRELOAD=")),
    ("bashrc",          re.compile(r"\.(bash_profile|bashrc|profile|zshrc)$")),
    ("ssh_authorized",  re.compile(r"\.ssh/authorized_keys")),
    ("proc_inspect",    re.compile(r"/proc/(self|\d+)/(maps|status|cmdline|exe|mem)")),
    ("dev_access",      re.compile(r"/dev/(mem|kmem|tcp|udp)/?")),
    ("init_d",          re.compile(r"/etc/init\.d/")),
    ("xdg_autostart",   re.compile(r"\.config/autostart/.*\.desktop")),
]


def _extract(s) -> tuple[str | None, str | None]:
    """Pull (value, address) out of a StringEntry or dict-like."""
    if hasattr(s, "value"):
        return s.value, getattr(s, "address", None)
    if isinstance(s, dict):
        return s.get("value"), s.get("address")
    return None, None


def scan_strings(strings: Iterable) -> list[dict]:
    """Return [{"category", "path", "evidence", "string_address"}, ...].

    `path` is the regex-matched fragment; `evidence` is the full string
    that contained the match. A single string can yield multiple rows
    if it matches multiple patterns.
    """
    out: list[dict] = []
    for s in strings:
        value, address = _extract(s)
        if not value:
            continue
        for category, pattern in _PATTERNS:
            m = pattern.search(value)
            if not m:
                continue
            out.append({
                "category": category,
                "path": m.group(0),
                "evidence": value,
                "string_address": address,
            })
    return out
