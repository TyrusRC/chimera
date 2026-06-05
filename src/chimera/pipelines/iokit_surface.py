"""IOKit attack-surface mapping for macOS / iOS kernel extensions.

Phrack 72.9 documents the IOUserClient method-dispatch table layout
(IOExternalMethodDispatch) and how to walk it statically to enumerate
userland-reachable selectors. This module is a best-effort static parser:
when LIEF is installed we walk the Mach-O `__DATA_CONST,__const` section
for plausible dispatch entries; without LIEF we degrade to an empty list
plus a single note explaining how to enable the parser.

Returned shape::

    [
      {"selector": 0, "implementation": "0x...", "section": "__const",
       "note": ""},
      ...
    ]

The list is empty (with `note` populated on a synthetic entry) when we
couldn't parse — callers should display `note` to the user rather than
silently reporting "no methods".

Reference: Phrack 72, paper 9 — "An iOS Hacker's Tryst with WebKit".
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def parse_iokit_methods(kext_path: Path) -> list[dict]:
    """Return the IOKit external-method dispatch entries we can find.

    LIEF-required. Without LIEF the result is a single-element list with
    `selector == -1` carrying a `note` that explains the missing dep.
    Returning a list (not a tuple/raise) keeps the calling code uniform
    across the available / unavailable paths.
    """
    p = Path(kext_path)
    if not p.exists():
        return [{
            "selector": -1,
            "implementation": "",
            "section": "",
            "note": f"kext path does not exist: {p}",
        }]

    try:
        import lief  # type: ignore[import-not-found]
    except ImportError:
        return [{
            "selector": -1,
            "implementation": "",
            "section": "",
            "note": (
                "lief is not installed; IOKit dispatch parsing requires it. "
                "Install with `pip install lief` to enable."
            ),
        }]

    try:
        binary: Any = lief.parse(str(p))
    except Exception as exc:  # noqa: BLE001 — never crash a scan
        logger.warning("lief failed to parse %s: %s", p, exc)
        return [{
            "selector": -1,
            "implementation": "",
            "section": "",
            "note": f"lief parse error: {exc}",
        }]
    if binary is None:
        return [{
            "selector": -1,
            "implementation": "",
            "section": "",
            "note": "lief returned no object — not a recognised kext format",
        }]

    # Best-effort: scan __DATA_CONST,__const for plausible dispatch
    # entries. IOExternalMethodDispatch entries on arm64 are 32 bytes
    # (function ptr + checkScalarInputCount + checkStructureInputSize +
    # checkScalarOutputCount + checkStructureOutputSize). We don't
    # disambiguate from other const tables here; this is an upper-bound
    # candidate list the analyst can filter.
    entries: list[dict] = []
    sections = getattr(binary, "sections", None) or []
    for sect in sections:
        sect_name = getattr(sect, "name", "") or ""
        if sect_name not in ("__const", "__data", "__DATA_CONST"):
            continue
        content = bytes(getattr(sect, "content", b"") or b"")
        # Stride 32 bytes, skip zero-filled rows (padding). We only emit
        # the function-pointer field as a candidate implementation; the
        # full struct interpretation depends on kernel ABI versions and
        # is out of scope for a static shim.
        for off in range(0, len(content) - 32, 32):
            fn_ptr = int.from_bytes(content[off:off + 8], "little", signed=False)
            if fn_ptr == 0:
                continue
            # Filter wildly implausible values — kernel text typically
            # lives in the high half of address space.
            if fn_ptr < 0x1000:
                continue
            entries.append({
                "selector": len(entries),
                "implementation": hex(fn_ptr),
                "section": sect_name,
                "note": "",
            })
        if entries:
            break  # First const section with hits wins; avoid duplication.

    if not entries:
        return [{
            "selector": -1,
            "implementation": "",
            "section": "",
            "note": (
                "no IOKit dispatch candidates found in __const / __DATA_CONST. "
                "This kext may not export an IOUserClient or may use a custom layout."
            ),
        }]
    return entries
