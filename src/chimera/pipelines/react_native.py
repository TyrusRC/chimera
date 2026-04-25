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

_HERMES_MAGIC = b"\xc6\x1f\xbc\x03"


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


def _detect_variant(bundle_path: Path) -> str:
    try:
        with open(bundle_path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return "jsc"
    return "hermes" if magic == _HERMES_MAGIC else "jsc"


async def analyze_react_native_bundle(
    *,
    bundle_path: Path,
    platform: str,
    model: UnifiedProgramModel,
    registry,
    cache,
    sha: str,
    output_root: Path,
) -> dict[str, Any]:
    """Run the React Native sub-pipeline on a discovered JS bundle.

    Returns a compact ``react_native_context`` dict suitable for inclusion in the
    triage cache. Bulk artifacts (security issues, module IDs, sources) go into
    separate cache keys via ``cache.put_json``.
    """
    bundle_path = Path(bundle_path)
    output_root = Path(output_root)

    if not bundle_path.exists():
        return {"bundle_path": None, "skipped_reason": "no_bundle_found"}

    from chimera.frameworks.react_native import ReactNativeAnalyzer

    analyzer = ReactNativeAnalyzer()
    variant = _detect_variant(bundle_path)
    bundle_size = bundle_path.stat().st_size
    decompile_dir = output_root / sha[:12]

    smap_path = find_source_map(bundle_path)
    smap_data = parse_source_map(smap_path) if smap_path else None

    if variant == "jsc":
        adapter = registry.get("webcrack")
        adapter_name = "webcrack"
    else:
        adapter = registry.get("hermes_dec")
        adapter_name = "hermes-dec"

    decompile_block: dict[str, Any] = {
        "tool": adapter_name,
        "ran": False,
        "output_dir": str(decompile_dir),
        "file_count": 0,
        "skipped_reason": None,
        "hermes_bytecode_version": None,
    }

    if adapter is None or not adapter.is_available():
        decompile_block["skipped_reason"] = "tool_unavailable"
    else:
        try:
            adapter_result = await adapter.analyze(str(bundle_path), {"output_dir": str(decompile_dir)})
            decompile_block["ran"] = bool(adapter_result.get("decompiled") or adapter_result.get("file_count", 0) > 0)
            decompile_block["file_count"] = int(adapter_result.get("file_count") or 0)
            decompile_block["hermes_bytecode_version"] = adapter_result.get("hermes_bytecode_version")
            if not decompile_block["ran"]:
                decompile_block["skipped_reason"] = "decompile_failed"
        except Exception as exc:
            logger.warning("RN decompile failed: %s", exc)
            decompile_block["skipped_reason"] = "decompile_failed"

    security_issues: list = []
    module_ids: list = []
    bundle_strings: list = []

    if variant == "jsc":
        try:
            security_issues = analyzer.scan_for_issues(bundle_path)
        except OSError as exc:
            logger.warning("RN security scan failed: %s", exc)
        try:
            module_ids = analyzer.extract_module_ids(bundle_path)
        except OSError as exc:
            logger.warning("RN module-id extraction failed: %s", exc)
        try:
            content = bundle_path.read_text(errors="replace")
            bundle_strings = analyzer._extract_strings(content)
        except OSError:
            pass
    else:
        try:
            bundle_strings = list(analyzer._extract_hermes_strings(bundle_path))
            bundle_strings.extend(analyzer.extract_utf16_strings(bundle_path))
        except OSError as exc:
            logger.warning("RN hermes string extraction failed: %s", exc)

    for i, s in enumerate(bundle_strings):
        model.add_string(address=f"rn_bundle_{i}", value=s, section="bundle")

    source_map_block: dict[str, Any] = {
        "discovered": smap_path is not None,
        "path": str(smap_path) if smap_path else None,
        "source_count": 0,
        "names_populated": 0,
    }
    if smap_data is not None:
        source_map_block["source_count"] = len(smap_data.get("sources") or [])
        names_populated = populate_model_from_sourcemap(model, smap_data)
        source_map_block["names_populated"] = names_populated
        cache.put_json(sha, "react_native_sources", list(smap_data.get("sources") or []))

    cache.put_json(sha, "react_native_issues", security_issues)
    cache.put_json(sha, "react_native_modules", module_ids)

    return {
        "bundle_path": str(bundle_path),
        "variant": variant,
        "bundle_size": bundle_size,
        "decompile": decompile_block,
        "source_map": source_map_block,
        "security_issue_count": len(security_issues),
        "module_id_count": len(module_ids),
    }
