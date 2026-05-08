"""Score strings extracted from an analyzed binary for YARA-rule fitness.

Heuristics, in priority order:
  1. Length filter (≥ min_length, default 8).
  2. Common-token denylist (bundled `common_strings.txt`).
  3. Character-class filter: reject strings that are mostly digits or
     mostly hex — these are typically version numbers or hashes the
     analyst would surface explicitly, not pattern-match on.
  4. Score = length * rarity_weight, where rarity_weight is 1.0 for
     mixed-case alphanumeric+symbols (the analyst's friend) and 0.3
     for all-lowercase or all-printable-ASCII (often library noise).

The scorer is deterministic and pure: input is a list of (value, address)
pairs; output is a sorted list of (value, score) pairs.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

_COMMON_STRINGS_FILE = Path(__file__).parent / "common_strings.txt"


def _load_common_strings() -> set[str]:
    """Load the bundled denylist of generic strings.

    Cached at module load time. Each line is treated as one entry,
    case-insensitive comparison. Lines starting with `#` are comments.
    """
    if not _COMMON_STRINGS_FILE.exists():
        return set()
    out: set[str] = set()
    for line in _COMMON_STRINGS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line.lower())
    return out


_COMMON_STRINGS: set[str] = _load_common_strings()

# Patterns we explicitly reject as low-rule-fitness:
#   - all-digit (version numbers)
#   - all-hex (hashes / GUIDs)
#   - long runs of repeated characters
_ALL_DIGITS_RX = re.compile(r"^\d+$")
_ALL_HEX_RX = re.compile(r"^[0-9a-fA-F]{16,}$")
_REPEATED_CHAR_RX = re.compile(r"(.)\1{6,}")


def is_interesting(value: str, *, min_length: int = 8) -> bool:
    """Return True iff `value` looks like good YARA-rule material."""
    if not value or len(value) < min_length:
        return False
    if value.lower() in _COMMON_STRINGS:
        return False
    if _ALL_DIGITS_RX.match(value):
        return False
    if _ALL_HEX_RX.match(value):
        return False
    if _REPEATED_CHAR_RX.search(value):
        return False
    # Reject if mostly whitespace / punctuation
    alnum = sum(1 for c in value if c.isalnum())
    if alnum < len(value) * 0.5:
        return False
    return True


def _rarity_weight(value: str) -> float:
    """Higher for strings that look 'analyst-distinctive' rather than
    library-noise."""
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_symbol = any(not c.isalnum() and not c.isspace() for c in value)
    diversity = sum([has_upper, has_digit, has_symbol])
    if diversity >= 2:
        return 1.0
    if diversity == 1:
        return 0.7
    return 0.3


def score_strings(
    candidates: Iterable[str],
    *,
    min_length: int = 8,
    max_results: int = 50,
) -> list[tuple[str, float]]:
    """Return [(value, score)] sorted by score descending.

    Deduplicates the input first; identical strings score once.
    """
    seen: set[str] = set()
    scored: list[tuple[str, float]] = []
    for v in candidates:
        if not isinstance(v, str):
            continue
        if v in seen:
            continue
        seen.add(v)
        if not is_interesting(v, min_length=min_length):
            continue
        # Cap each candidate at 200 chars: huge strings overfit the rule
        truncated = v[:200]
        score = len(truncated) * _rarity_weight(truncated)
        scored.append((truncated, score))
    scored.sort(key=lambda t: -t[1])
    return scored[:max_results]
