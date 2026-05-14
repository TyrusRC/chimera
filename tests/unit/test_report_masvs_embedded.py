"""Mobile reports embed the MASVS matrix directly; non-mobile reports mark non-applicable."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel
from chimera.report.builder import build_report


def _apk_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="m" * 64, path=Path("/x.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def _pe_model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="p" * 64, path=Path("/x.exe"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_apk_report_embeds_masvs_matrix():
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.return_value = None
    r = build_report(_apk_model(), cache)
    assert "masvs" in r
    m = r["masvs"]
    assert m["applicable"] is True
    rows = m["rows"]
    assert isinstance(rows, list) and len(rows) >= 8
    ids = {row["control_id"] for row in rows}
    for needed in ("MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-NETWORK", "MASVS-RESILIENCE"):
        assert needed in ids, f"missing {needed}"


def test_pe_report_masvs_not_applicable():
    cache = MagicMock()
    cache.list_keys.return_value = []
    cache.get_json.return_value = None
    r = build_report(_pe_model(), cache)
    m = r["masvs"]
    assert m["applicable"] is False
    assert m["rows"] == []
