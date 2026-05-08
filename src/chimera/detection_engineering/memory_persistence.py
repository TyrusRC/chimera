"""Cross-reference cached files in a memory image with persistence patterns.

Reuses the regex catalog from `parsers.elf_persistence_scanner` so the
mobile-side and memory-side outputs share a vocabulary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from chimera.parsers.elf_persistence_scanner import _PATTERNS
from chimera.parsers.volatility_files import CachedFile


@dataclass
class MemoryPersistenceFinding:
    category: str         # cron / systemd_unit / ld_preload / ...
    path: str
    inode: int | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "path": self.path,
            "inode": self.inode,
            "notes": self.notes,
        }


def find_memory_persistence(files: Iterable[CachedFile]) -> list[MemoryPersistenceFinding]:
    """Return a finding per cached file path matching a persistence pattern.

    Patterns come from `parsers.elf_persistence_scanner._PATTERNS`. Each
    pattern is `(category, regex)`. We test each pattern against the
    full path; first-match wins so a file isn't double-counted.
    """
    out: list[MemoryPersistenceFinding] = []
    for f in files:
        for category, pattern in _PATTERNS:
            if pattern.search(f.path):
                out.append(MemoryPersistenceFinding(
                    category=category,
                    path=f.path,
                    inode=f.inode,
                    notes=f"file in pagecache (size={f.size})" if f.size else "",
                ))
                break
    return out


def summarize(findings: list[MemoryPersistenceFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return counts
