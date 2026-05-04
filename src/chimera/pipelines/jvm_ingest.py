"""Populate the unified model from a jadx-decompiled JVM source tree.

jadx writes one `.java` (or `.kt`) file per class under
`<jadx_out>/sources/<package>/<Class>.{java,kt}`. We ingest those at
class-level granularity — one `FunctionInfo` per file — so downstream
consumers (sdks, callgraph viewer, model export) see the JVM layer.

We deliberately do NOT parse method bodies. That's an order-of-magnitude
more work and the analyst-facing tools (SDK detection, the new report
view, the TUI listings) only need class identity. Method-level ingestion
is a separate, future step.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)


# Cheap heuristic: extract a sample of string literals from a class file so
# the model has analyst-useful strings beyond r2's native-side scrape.
_STRING_LITERAL_RX = re.compile(r'"((?:\\.|[^"\\])*)"')


def ingest_jadx_classes(
    model: UnifiedProgramModel,
    sources_dir: Path,
    *,
    max_classes: int = 10000,
    max_strings: int = 2000,
    string_min_len: int = 6,
    string_max_len: int = 256,
) -> tuple[int, int]:
    """Add one FunctionInfo per .java/.kt file. Sample string literals.

    Returns (classes_added, strings_added).
    """
    sources_dir = Path(sources_dir)
    if not sources_dir.exists():
        return 0, 0

    classes_added = 0
    strings_added = 0
    seen_strings: set[str] = set()

    for file in sources_dir.rglob("*"):
        if classes_added >= max_classes and strings_added >= max_strings:
            break
        if not file.is_file() or file.suffix not in (".java", ".kt"):
            continue

        rel = file.relative_to(sources_dir)
        package = ".".join(rel.parent.parts) if rel.parent.parts else ""
        class_name = file.stem
        fqcn = f"{package}.{class_name}" if package else class_name
        kind = "kotlin" if file.suffix == ".kt" else "java"
        address = f"jvm:{fqcn}"

        if classes_added < max_classes:
            model.add_function(FunctionInfo(
                address=address,
                name=class_name,
                original_name=fqcn,
                language=kind,
                classification="unknown",
                layer="jvm",
                source_backend="jadx",
            ))
            classes_added += 1

        if strings_added < max_strings:
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.debug("could not read %s: %s", file, exc)
                continue
            for m in _STRING_LITERAL_RX.finditer(text):
                literal = m.group(1)
                if not (string_min_len <= len(literal) <= string_max_len):
                    continue
                if literal in seen_strings:
                    continue
                seen_strings.add(literal)
                model.add_string(
                    address=f"{address}:str{len(seen_strings)}",
                    value=literal,
                    section=f"jvm/{fqcn}",
                )
                strings_added += 1
                if strings_added >= max_strings:
                    break

    logger.info("jadx ingest: %d classes, %d strings", classes_added, strings_added)
    return classes_added, strings_added
