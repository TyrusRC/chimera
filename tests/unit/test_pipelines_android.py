"""Android pipeline orchestration behavior."""
from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _minimal_apk(p: Path) -> None:
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00")


async def test_android_cache_hit_short_circuits(tmp_path, caplog):
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "t.apk"
    _minimal_apk(apk)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(apk)
    cache.put_json(binary.sha256, "triage", {
        "platform": "android", "format": "apk", "framework": "native",
        "dex_count": 1, "has_native": False, "native_lib_count": 0,
        "function_count": 0, "string_count": 0, "bundle_format": None,
    })

    with caplog.at_level("INFO"):
        model = await analyze_apk(apk, cfg, registry, rm, cache)

    unpacked = cfg.project_dir / "unpacked"
    assert not unpacked.exists(), (
        "cache hit must short-circuit before unpack; found %s" % list(unpacked.rglob("*"))
        if unpacked.exists() else ""
    )
    assert model.binary.sha256 == binary.sha256


async def test_android_cache_hit_rehydrates_functions_and_strings(tmp_path):
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "r.apk"
    _minimal_apk(apk)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(apk)
    cache.put_json(binary.sha256, "triage", {"platform": "android", "framework": "native"})
    cache.put_json(binary.sha256, "r2_libfoo.so", {
        "strings": [{"string": "hello", "vaddr": 0x1000}],
        "functions": [{"name": "foo", "offset": 0x2000}],
    })

    model = await analyze_apk(apk, cfg, registry, rm, cache)
    assert [s.value for s in model.get_strings()] == ["hello"]
    assert [f.name for f in model.functions] == ["foo"]


async def test_android_r2_malformed_output_does_not_crash(tmp_path):
    """r2 returning garbage in 'strings' or 'functions' lists must be filtered, not crash."""
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "m.apk"
    _minimal_apk(apk)
    # Add a native library so r2 phase runs
    import zipfile
    with zipfile.ZipFile(apk, "a") as zf:
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 100)

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    class FakeR2:
        def name(self): return "radare2"
        def is_available(self): return True
        def supported_formats(self): return ["elf"]
        async def analyze(self, path, opts):
            return {
                "strings": [
                    {"string": "good", "vaddr": 0x1000},
                    "not-a-dict",
                    {"no_string_key": True},
                    {"string": 12345, "vaddr": "bad"},  # string value is int
                ],
                "functions": [
                    {"name": "ok", "offset": 0x2000},
                    {"no_address_at_all": True},
                    "garbage",
                ],
                "imports": [],
                "info": {}, "core": {},
            }
        async def cleanup(self): pass

    registry = AdapterRegistry()
    registry.register(FakeR2())

    model = await analyze_apk(apk, cfg, registry, rm, cache)
    string_values = [s.value for s in model.get_strings()]
    assert "good" in string_values
    assert all(isinstance(v, str) for v in string_values)
    fn_names = [f.name for f in model.functions]
    assert "ok" in fn_names
    assert "garbage" not in fn_names


async def test_android_skipped_phases_recorded_in_triage(tmp_path):
    """When r2/jadx/ghidra are missing, triage entry must list them as skipped."""
    from chimera.pipelines.android import analyze_apk
    apk = tmp_path / "a.apk"
    _minimal_apk(apk)
    # Add a native lib so r2/ghidra phases are reachable
    import zipfile
    with zipfile.ZipFile(apk, "a") as zf:
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 100)

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()  # empty

    await analyze_apk(apk, cfg, registry, rm, cache)
    from chimera.model.binary import BinaryInfo
    triage = cache.get_json(BinaryInfo.from_path(apk).sha256, "triage")
    assert "skipped_phases" in triage
    assert "radare2" in triage["skipped_phases"]
    assert "jadx" in triage["skipped_phases"]
    assert "ghidra" in triage["skipped_phases"]


async def test_android_records_jadx_context_in_triage(tmp_path):
    """Pipeline must invoke discovery + detection and record outcome in triage."""
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "k.apk"
    # Minimal APK with AndroidManifest.xml + Kotlin-containing DEX
    import zipfile
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 32 + b"Lkotlin/Metadata;")

    # Explicit mapping file as sibling of apk
    mapping = tmp_path / "k.apk.mapping.txt"
    mapping.write_text("com.example.Thing -> a.a.A:\n")

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)

    captured_options: list[dict] = []

    class FakeJadx:
        def name(self): return "jadx"
        def is_available(self): return True
        def supported_formats(self): return ["apk"]
        async def analyze(self, path, opts):
            captured_options.append(opts)
            return {"decompiled_files": 0, "packages": []}
        async def cleanup(self): pass

    registry = AdapterRegistry()
    registry.register(FakeJadx())

    await analyze_apk(apk, cfg, registry, rm, cache)
    from chimera.model.binary import BinaryInfo
    triage = cache.get_json(BinaryInfo.from_path(apk).sha256, "triage")
    assert "jadx_context" in triage
    ctx = triage["jadx_context"]
    assert ctx["kotlin_detected"] is True
    assert ctx["mapping_used"] is True
    assert ctx["mapping_source"] is not None
    # Adapter received the discovered mapping + kotlin flag
    assert captured_options, "jadx adapter was not called"
    opts = captured_options[0]
    assert opts["kotlin_aware"] is True
    assert opts["mapping_file"] is not None


async def test_android_pipeline_runs_react_native_subpipeline(tmp_path, monkeypatch):
    """When framework=react-native, RN sub-pipeline runs and writes react_native_context."""
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "rn.apk"
    bundle_bytes = b"// JS bundle\n__d(function(){},0,[]);\n"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("assets/index.android.bundle", bundle_bytes)

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()  # no adapters registered; jadx/r2/ghidra phases skip

    captured: dict = {}

    async def fake_orchestrator(**kwargs):
        captured.update(kwargs)
        return {
            "bundle_path": str(kwargs["bundle_path"]),
            "variant": "jsc",
            "bundle_size": 100,
            "decompile": {"tool": "webcrack", "ran": False, "output_dir": "x",
                          "file_count": 0, "skipped_reason": "tool_unavailable",
                          "hermes_bytecode_version": None},
            "source_map": {"discovered": False, "path": None, "source_count": 0,
                           "names_populated": 0},
            "security_issue_count": 0,
            "module_id_count": 1,
        }

    monkeypatch.setattr(
        "chimera.pipelines.android.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_apk(apk, config, registry, resource_mgr, cache)

    assert captured, "RN sub-pipeline was not invoked"
    assert captured["platform"] == "android"

    import hashlib
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"]["variant"] == "jsc"


async def test_android_pipeline_skips_rn_subpipeline_for_non_rn_apk(tmp_path, monkeypatch):
    """When framework is not react-native, RN sub-pipeline is not invoked and triage carries None."""
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "plain.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        # No assets/index.android.bundle — framework detector will return "native".

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    invoked: list = []

    async def fake_orchestrator(**kwargs):
        invoked.append(kwargs)
        return {}

    monkeypatch.setattr(
        "chimera.pipelines.android.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_apk(apk, config, registry, resource_mgr, cache)

    assert invoked == [], "RN orchestrator should not have been invoked for non-RN APK"

    import hashlib
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"] is None


async def test_android_pipeline_rn_framework_but_no_bundle_records_skip_marker(tmp_path, monkeypatch):
    """When framework is RN but find_rn_bundle returns None, triage carries the skip-marker dict."""
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.android import analyze_apk

    apk = tmp_path / "rn.apk"
    bundle_bytes = b"// JS bundle\n"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest/>")
        zf.writestr("assets/index.android.bundle", bundle_bytes)

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    # Force find_rn_bundle to None so the no-bundle branch fires even though framework is RN.
    monkeypatch.setattr(
        "chimera.pipelines.android.find_rn_bundle",
        lambda unpack_dir, platform: None,
    )

    invoked: list = []

    async def fake_orchestrator(**kwargs):
        invoked.append(kwargs)
        return {}

    monkeypatch.setattr(
        "chimera.pipelines.android.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_apk(apk, config, registry, resource_mgr, cache)

    assert invoked == [], "Orchestrator should not be invoked when no bundle is found"

    import hashlib
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"] == {
        "bundle_path": None,
        "skipped_reason": "no_bundle_found",
    }
