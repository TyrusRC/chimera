"""build_report must not read the same cache key twice (regression for D1)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel
from chimera.report.builder import build_report


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="d" * 64, path=Path("/x"),
        format=BinaryFormat.DOTNET_PE, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_build_report_reads_each_ilspy_key_at_most_once():
    cache = MagicMock()
    cache.list_keys.return_value = ["ilspy_main", "ilspy_helper", "pe_header"]
    reads: Counter[str] = Counter()

    def _get(sha: str, key: str):
        reads[key] += 1
        if key.startswith("ilspy_"):
            return {"assembly": key}
        return None

    cache.get_json.side_effect = _get
    build_report(_model(), cache)

    assert reads["ilspy_main"] == 1, f"ilspy_main read {reads['ilspy_main']} times"
    assert reads["ilspy_helper"] == 1, f"ilspy_helper read {reads['ilspy_helper']} times"
