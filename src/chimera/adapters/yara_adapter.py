"""YARA adapter — runs bundled rules over a binary, returns rule hits.

Loads every `*.yar` file under `chimera/bypass/yara_rules/` into a single
compiled rule set on first use. Callers can also drop additional rule
files into a directory and pass `extra_rules_dir`.

Design choice: keep this thin and synchronous-internally. YARA is fast
on `.so` files (<10 MB), and the python wrapper is C-backed so it
doesn't benefit from asyncio.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


@dataclass
class YaraHit:
    rule: str
    meta: dict[str, str] = field(default_factory=dict)
    matched_strings: list[str] = field(default_factory=list)


def _bundled_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "bypass" / "yara_rules"


class YaraAdapter(BackendAdapter):
    """Compile and run bundled YARA rules over a binary path."""

    def __init__(self, extra_rules_dir: Path | None = None):
        self._extra_rules_dir = extra_rules_dir
        self._rules: Any = None  # yara.Rules — lazy-loaded
        self._yara_module: Any | None = None
        self._tried_import = False

    def name(self) -> str:
        return "yara"

    def is_available(self) -> bool:
        if not self._tried_import:
            self._tried_import = True
            try:
                import yara  # type: ignore[import-not-found]
                self._yara_module = yara
            except ImportError as exc:
                logger.debug("yara-python not installed: %s", exc)
                self._yara_module = None
        return self._yara_module is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "dex", "fat", "dylib", "apk", "ipa"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=256, category=ToolCategory.LIGHT,
                                   estimated_seconds=5)

    def _load_rules(self) -> Any:
        if self._rules is not None:
            return self._rules
        if not self.is_available():
            raise RuntimeError("yara-python not available")

        sources: dict[str, str] = {}
        for path in sorted(_bundled_rules_dir().glob("*.yar")):
            sources[f"bundled_{path.stem}"] = path.read_text()
        if self._extra_rules_dir and self._extra_rules_dir.exists():
            for path in sorted(self._extra_rules_dir.rglob("*.yar")):
                sources[f"user_{path.stem}"] = path.read_text()

        if not sources:
            raise RuntimeError("no YARA rules found")
        self._rules = self._yara_module.compile(sources=sources)
        return self._rules

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if not self.is_available():
            return {"available": False, "hits": []}
        try:
            rules = self._load_rules()
        except Exception as exc:
            logger.warning("YARA rule load failed: %s", exc)
            return {"available": False, "hits": [], "error": str(exc)}

        timeout = int(options.get("timeout", 30))
        try:
            matches = rules.match(binary_path, timeout=timeout)
        except self._yara_module.Error as exc:
            logger.warning("YARA scan failed on %s: %s", binary_path, exc)
            return {"available": True, "hits": [], "error": str(exc)}

        hits: list[dict] = []
        for m in matches:
            meta = dict(m.meta) if hasattr(m, "meta") else {}
            matched_strings: list[str] = []
            for s in getattr(m, "strings", []) or []:
                ident = getattr(s, "identifier", "?")
                matched_strings.append(str(ident))
            hits.append({
                "rule": m.rule,
                "tags": list(getattr(m, "tags", []) or []),
                "meta": {str(k): str(v) for k, v in meta.items()},
                "matched_strings": matched_strings,
            })
        return {"available": True, "hits": hits}

    async def cleanup(self) -> None:
        self._rules = None
