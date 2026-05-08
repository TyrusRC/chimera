"""Bundled Frida agent scripts + script registry.

Scripts ship as `.js` files alongside this module. Each carries a header
the Python registry parses into a `ScriptMeta`. Use `list_scripts()` to
enumerate, `get_script(id)` to fetch metadata, and `read_source(id)` to
get the JS body to load via `frida.Session.create_script(...)`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_SCRIPT_DIR = Path(__file__).parent
_HEADER_RX = re.compile(r"^// chimera-frida-script\s*$", re.MULTILINE)
_KEY_RX = re.compile(r"^//\s*(?P<key>[a-z_]+):\s*(?P<value>.+?)\s*$", re.MULTILINE)


@dataclass
class ScriptMeta:
    id: str
    name: str
    description: str
    platform: str             # "android" | "ios" | "both"
    requires: list[str] = field(default_factory=list)
    risk: str = "medium"
    file: Path = field(default=Path())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "platform": self.platform,
            "requires": self.requires,
            "risk": self.risk,
            "file": str(self.file),
        }


def _parse_header(text: str, file: Path) -> Optional[ScriptMeta]:
    """Parse the metadata header at the top of a Frida script.

    Returns None if the header isn't present — callers can ignore the
    file rather than treating it as registry-loadable.
    """
    if not _HEADER_RX.search(text[:4096]):
        return None
    meta: dict[str, str] = {}
    for m in _KEY_RX.finditer(text[:4096]):
        meta[m.group("key")] = m.group("value")
    if "id" not in meta or "name" not in meta or "platform" not in meta:
        return None
    requires_raw = meta.get("requires", "")
    requires = [r.strip() for r in requires_raw.split(",") if r.strip()]
    return ScriptMeta(
        id=meta["id"],
        name=meta["name"],
        description=meta.get("description", ""),
        platform=meta["platform"],
        requires=requires,
        risk=meta.get("risk", "medium"),
        file=file,
    )


def list_scripts() -> list[ScriptMeta]:
    """Return all bundled Frida scripts with parseable headers."""
    out: list[ScriptMeta] = []
    if not _SCRIPT_DIR.exists():
        return out
    for path in sorted(_SCRIPT_DIR.glob("*.js")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        meta = _parse_header(text, path)
        if meta:
            out.append(meta)
    return out


def get_script(script_id: str) -> Optional[ScriptMeta]:
    """Lookup a single script by id."""
    for meta in list_scripts():
        if meta.id == script_id:
            return meta
    return None


def read_source(script_id: str) -> Optional[str]:
    """Return the JS source for a script id, or None if not found."""
    meta = get_script(script_id)
    if meta is None:
        return None
    try:
        return meta.file.read_text(encoding="utf-8")
    except OSError:
        return None
