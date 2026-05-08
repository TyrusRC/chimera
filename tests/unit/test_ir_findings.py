"""Unit tests for the IR finding builder."""
from pathlib import Path

import pytest

from chimera.detection_engineering.ir_findings import (
    CAT_KERNEL_ROOTKIT, CAT_MALICIOUS_MEMORY, CAT_NETWORK_ANOMALY,
    CAT_PERSISTENCE, CAT_PROCESS_ANOMALY,
    SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM,
    IRFinding, build_ir_findings, render_ir_findings_markdown,
)
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

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _memory_model():
    bi = BinaryInfo(
        sha256="m" * 64, path=Path("/tmp/x.lime"),
        format=BinaryFormat.MEMORY_LIME, platform=Platform.LINUX_MEMORY,
        arch=Architecture.UNKNOWN, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def _non_memory_model():
    bi = BinaryInfo(
        sha256="x" * 64, path=Path("/tmp/x.exe"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def test_non_memory_returns_empty():
    out = build_ir_findings(_non_memory_model(), _StubCache())
    assert out == []


def test_no_signals_yields_no_findings():
    out = build_ir_findings(_memory_model(), _StubCache())
    assert out == []


def test_hooked_syscalls_trigger_critical():
    cache = _StubCache({"vol_check_syscall": {"rows": [
        {"index": 0, "name": "sys_open", "handler_symbol": None, "handler_addr": "0xdeadbeef"},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert any(f.severity == SEV_CRITICAL and f.category == CAT_KERNEL_ROOTKIT for f in out)


def test_hidden_modules_trigger_high():
    cache = _StubCache({"vol_check_modules": {"rows": [
        {"name": "rootkit", "address": "0xfff"},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert any(f.severity == SEV_HIGH and f.category == CAT_KERNEL_ROOTKIT for f in out)


def test_malfind_rwx_triggers_high():
    cache = _StubCache({"vol_malfind": {"rows": [
        {"pid": 1, "process": "evil", "start_addr": "0x1", "end_addr": "0x2",
         "protection": "rwx"},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert any(f.category == CAT_MALICIOUS_MEMORY and f.severity == SEV_HIGH for f in out)


def test_persistence_findings_trigger_medium():
    cache = _StubCache({"memory_persistence": {"findings": [
        {"category": "cron", "path": "/etc/cron.d/evil", "inode": 1},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert any(f.category == CAT_PERSISTENCE and f.severity == SEV_MEDIUM for f in out)


def test_public_network_connections_trigger_low():
    cache = _StubCache({"vol_netstat": {"rows": [
        {"family": "AF_INET", "protocol": "TCP", "state": "ESTABLISHED",
         "local": "10.0.0.1:5555", "remote": "8.8.8.8:80",
         "pid": 100, "process": "wget"},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert any(f.category == CAT_NETWORK_ANOMALY and f.severity == SEV_LOW for f in out)


def test_private_remote_does_not_trigger_network_finding():
    cache = _StubCache({"vol_netstat": {"rows": [
        {"family": "AF_INET", "protocol": "TCP", "state": "ESTABLISHED",
         "local": "10.0.0.1:5555", "remote": "10.0.0.2:80",
         "pid": 100, "process": "wget"},
    ]}})
    out = build_ir_findings(_memory_model(), cache)
    assert all(f.category != CAT_NETWORK_ANOMALY for f in out)


def test_to_dict_round_trip():
    f = IRFinding(finding_id="X-1", title="t", category=CAT_KERNEL_ROOTKIT,
                  severity=SEV_HIGH)
    d = f.to_dict()
    assert d["finding_id"] == "X-1"


def test_render_markdown_table_and_sections():
    f = IRFinding(finding_id="X-1", title="Test", category=CAT_PERSISTENCE,
                  severity=SEV_MEDIUM, mitre_attack=["T1543"], description="d",
                  evidence=["e1"], recommendation="r")
    md = render_ir_findings_markdown([f])
    assert "| X-1 |" in md
    assert "### X-1 — Test" in md
    assert "T1543" in md


def test_render_empty():
    md = render_ir_findings_markdown([])
    assert "No IR findings" in md
