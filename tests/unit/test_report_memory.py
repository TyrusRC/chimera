"""Tests for memory-analysis report sections."""
from pathlib import Path

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.program import UnifiedProgramModel


class _StubCache:
    def __init__(self, blobs: dict | None = None):
        self.cache_dir = Path("/tmp/no-such-cache")
        self._blobs = blobs or {}

    def get_json(self, sha, key):
        return self._blobs.get(key)

    def get(self, sha, key):
        return None

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _memory_model():
    bi = BinaryInfo(
        sha256="m" * 64, path=Path("/tmp/x.lime"),
        format=BinaryFormat.MEMORY_LIME, platform=Platform.LINUX_MEMORY,
        arch=Architecture.UNKNOWN, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_report_includes_memory_keys_when_present():
    from chimera.report import build_report
    cache = _StubCache({
        "vol_pslist": {"rows": [{"pid": 1, "name": "init"}]},
        "vol_netstat": {"rows": []},
        "memory_persistence": {"findings": [{"category": "cron", "path": "/etc/cron.d/x"}]},
    })
    rep = build_report(_memory_model(), cache)
    assert "vol_pslist" in rep
    assert "memory_persistence" in rep


def test_report_memory_keys_default_empty():
    from chimera.report import build_report
    rep = build_report(_memory_model(), _StubCache())
    # Each memory key should be present with an empty value
    for key in ("vol_pslist", "vol_pstree", "vol_bash", "vol_netstat",
                "vol_malfind", "vol_lsmod", "vol_check_modules",
                "vol_check_syscall", "memory_persistence", "memory_protection"):
        assert key in rep
