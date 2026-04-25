"""React Native sub-pipeline — bundle discovery, source-map parsing, decompile orchestration."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from chimera.frameworks.react_native import INTERESTING_PATTERNS
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


def find_rn_bundle(unpack_dir: Path, platform: str) -> Path | None:
    """Locate a React Native JavaScript bundle in an unpacked APK or IPA.

    Android priority: assets/index.android.bundle, assets/index.bundle.
    iOS priority: main.jsbundle, then any *.jsbundle under unpack_dir.

    Returns first existing path or None. Never raises.
    """
    unpack_dir = Path(unpack_dir)
    if platform == "android":
        for rel in ("assets/index.android.bundle", "assets/index.bundle"):
            candidate = unpack_dir / rel
            if candidate.is_file():
                return candidate
        return None
    if platform == "ios":
        main = unpack_dir / "main.jsbundle"
        if main.is_file():
            return main
        for candidate in sorted(unpack_dir.glob("*.jsbundle")):
            if candidate.is_file():
                return candidate
        return None
    return None


def find_source_map(bundle_path: Path) -> Path | None:
    """Locate a sibling source map file next to a JS bundle.

    Priority:
      1. <bundle>.map (e.g. index.android.bundle.map)
      2. <bundle.parent>/<bundle.stem>.map (e.g. main.map for main.jsbundle)

    Returns first existing path or None. Never raises.
    """
    bundle_path = Path(bundle_path)
    candidates = [
        bundle_path.with_suffix(bundle_path.suffix + ".map"),
        bundle_path.parent / (bundle_path.stem + ".map"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def parse_source_map(map_path: Path) -> dict[str, Any] | None:
    """Read a JS source map JSON file. Returns normalized dict or None on failure.

    Tolerates partial or missing optional fields; never raises on malformed input.
    """
    try:
        raw = Path(map_path).read_text(errors="replace")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {
        "version": data.get("version", 3),
        "sources": list(data.get("sources") or []),
        "sourcesContent": list(data.get("sourcesContent") or []),
        "mappings": data.get("mappings", ""),
        "names": list(data.get("names") or []),
    }


def populate_model_from_sourcemap(
    model: UnifiedProgramModel,
    sm_data: dict[str, Any],
) -> int:
    """Populate the unified model with one FunctionInfo per source-map source.

    Sets ``original_name`` to the source path; ``name`` to its stem.
    Pulls interesting strings out of any present ``sourcesContent`` entries.
    Returns the number of functions added.
    """
    sources = sm_data.get("sources") or []
    contents = sm_data.get("sourcesContent") or []
    patterns = [re.compile(p) for p in INTERESTING_PATTERNS]
    added = 0

    for i, source in enumerate(sources):
        if not isinstance(source, str):
            continue
        model.add_function(FunctionInfo(
            address=f"rn_module_{i}",
            name=Path(source).stem or source,
            original_name=source,
            language="javascript",
            classification="unknown",
            layer="bundle",
            source_backend="react_native",
        ))
        added += 1

        if i < len(contents):
            content = contents[i]
            if not isinstance(content, str):
                continue
            for j, regex in enumerate(patterns):
                for m in regex.findall(content):
                    model.add_string(
                        address=f"rn_src_{i}_{j}",
                        value=m if isinstance(m, str) else str(m),
                        section=source,
                    )

    return added
