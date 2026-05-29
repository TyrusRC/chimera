"""YARA-X adapter — wraps the modern VirusTotal Rust rewrite of YARA.

YARA-X is the 2025 stable successor to YARA: ~3x faster on cold scans,
better diagnostics, more accurate PE/Mach-O metadata, and a stable Python
binding (`yara-x`). The on-disk rule format is the same `.yar` so we can
reuse chimera's existing rule directory verbatim.

Selection policy:
  - If `CHIMERA_USE_YARA_X=1`, prefer YARA-X and fall back to YARA on
    import failure.
  - Otherwise, the legacy YARA adapter (`yara_adapter.YaraAdapter`)
    remains the default — we don't want to silently change behaviour
    for existing deployments.

The output shape matches `YaraAdapter.analyze()` (same dict keys) so
downstream callers don't branch on the backend.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


def _bundled_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "bypass" / "yara_rules"


class YaraXAdapter(BackendAdapter):
    """Compile and run YARA rules via the YARA-X Python binding."""

    def __init__(self, extra_rules_dir: Path | None = None):
        self._extra_rules_dir = extra_rules_dir
        self._compiled: Any = None
        self._yx_module: Any | None = None
        self._tried_import = False

    def name(self) -> str:
        return "yara-x"

    def is_available(self) -> bool:
        if not self._tried_import:
            self._tried_import = True
            try:
                import yara_x  # type: ignore[import-not-found]
                self._yx_module = yara_x
            except ImportError as exc:
                logger.debug("yara-x not installed: %s", exc)
                self._yx_module = None
        return self._yx_module is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "dex", "fat", "dylib", "apk", "ipa", "pe", "pe32", "pe64"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        return ResourceRequirement(memory_mb=192, category=ToolCategory.LIGHT,
                                   estimated_seconds=3)

    def _load_rules(self) -> Any:
        if self._compiled is not None:
            return self._compiled
        if not self.is_available():
            raise RuntimeError("yara-x not available")
        yx = self._yx_module
        compiler = yx.Compiler()
        for path in sorted(_bundled_rules_dir().glob("*.yar")):
            try:
                compiler.add_source(path.read_text(), origin=f"bundled_{path.stem}")
            except Exception as exc:
                logger.warning("yara-x rejected bundled rule %s: %s", path.name, exc)
        if self._extra_rules_dir and self._extra_rules_dir.exists():
            for path in sorted(self._extra_rules_dir.rglob("*.yar")):
                try:
                    compiler.add_source(path.read_text(), origin=f"user_{path.stem}")
                except Exception as exc:
                    logger.warning("yara-x rejected user rule %s: %s", path.name, exc)
        self._compiled = compiler.build()
        return self._compiled

    async def analyze(self, binary_path: str, options: dict) -> dict:
        if not self.is_available():
            return {"available": False, "hits": []}
        try:
            rules = self._load_rules()
        except Exception as exc:
            logger.warning("YARA-X rule load failed: %s", exc)
            return {"available": False, "hits": [], "error": str(exc)}
        try:
            scanner = self._yx_module.Scanner(rules)
            with open(binary_path, "rb") as fh:
                results = scanner.scan(fh.read())
        except Exception as exc:
            logger.warning("YARA-X scan failed on %s: %s", binary_path, exc)
            return {"available": True, "hits": [], "error": str(exc)}

        hits: list[dict] = []
        matching = getattr(results, "matching_rules", []) or []
        for m in matching:
            meta_iter = getattr(m, "metadata", []) or []
            meta = {str(k): str(v) for k, v in meta_iter}
            matched_strings: list[str] = []
            for p in getattr(m, "patterns", []) or []:
                ident = getattr(p, "identifier", "?")
                matched_strings.append(str(ident))
            hits.append({
                "rule": getattr(m, "identifier", "?"),
                "tags": list(getattr(m, "tags", []) or []),
                "meta": meta,
                "matched_strings": matched_strings,
            })
        return {"available": True, "hits": hits}

    async def cleanup(self) -> None:
        self._compiled = None


def select_yara_adapter(extra_rules_dir: Path | None = None):
    """Pick YARA-X when CHIMERA_USE_YARA_X=1 and the binding is available.

    Falls back to the legacy YaraAdapter otherwise. This keeps the
    default behaviour unchanged for existing deployments while letting
    early adopters flip a single env var to opt in.
    """
    from chimera.adapters.yara_adapter import YaraAdapter

    if os.environ.get("CHIMERA_USE_YARA_X", "").strip() in ("1", "true", "yes"):
        cand = YaraXAdapter(extra_rules_dir=extra_rules_dir)
        if cand.is_available():
            return cand
        logger.info("CHIMERA_USE_YARA_X set but yara-x is unavailable; falling back to yara")
    return YaraAdapter(extra_rules_dir=extra_rules_dir)
