from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.adapters.registry import AdapterRegistry


def _minimal_ipa(p: Path) -> None:
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", b"<?xml version=\"1.0\"?><plist/>")


async def test_ios_cache_hit_short_circuits(tmp_path):
    from chimera.pipelines.ios import analyze_ipa
    ipa = tmp_path / "t.ipa"
    _minimal_ipa(ipa)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(ipa)
    cache.put_json(binary.sha256, "triage", {
        "platform": "ios", "framework": "native", "bundle_id": "com.example",
        "binary_count": 0, "framework_count": 0, "extension_count": 0,
        "function_count": 0, "string_count": 0,
    })

    model = await analyze_ipa(ipa, cfg, registry, rm, cache)
    unpacked = cfg.project_dir / "unpacked"
    assert not unpacked.exists(), "cache hit must short-circuit before unpack"
    assert model.binary.sha256 == binary.sha256


async def test_ios_cache_hit_rehydrates_functions_and_strings(tmp_path):
    from chimera.pipelines.ios import analyze_ipa
    ipa = tmp_path / "r.ipa"
    _minimal_ipa(ipa)
    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    registry = AdapterRegistry()
    rm = ResourceManager(total_ram_mb=4096)

    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(ipa)
    cache.put_json(binary.sha256, "triage", {"platform": "ios", "framework": "native"})
    cache.put_json(binary.sha256, "r2_main", {
        "strings": [{"string": "hello", "vaddr": 0x1000}],
        "functions": [{"name": "foo", "offset": 0x2000}],
    })

    model = await analyze_ipa(ipa, cfg, registry, rm, cache)
    assert [s.value for s in model.get_strings()] == ["hello"]
    assert [f.name for f in model.functions] == ["foo"]


async def test_ios_no_app_bundle_writes_explicit_status(tmp_path):
    from chimera.pipelines.ios import analyze_ipa
    import zipfile
    ipa = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("README.txt", b"no bundle")

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    await analyze_ipa(ipa, cfg, registry, rm, cache)
    from chimera.model.binary import BinaryInfo
    triage = cache.get_json(BinaryInfo.from_path(ipa).sha256, "triage")
    assert triage is not None
    assert triage.get("status") == "skipped"
    assert triage.get("reason") == "no_app_bundle"


async def test_ios_cache_hit_with_skipped_status_warns_and_returns(tmp_path, caplog):
    from chimera.pipelines.ios import analyze_ipa
    import shutil
    import zipfile
    ipa = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("README.txt", b"no bundle")

    cfg = ChimeraConfig(project_dir=tmp_path / "p", cache_dir=tmp_path / "c")
    cache = AnalysisCache(cfg.cache_dir)
    rm = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    # First run writes skipped status
    await analyze_ipa(ipa, cfg, registry, rm, cache)

    # Remove first-run unpack artifacts so we can prove the second run didn't re-unpack
    unpack_root = cfg.project_dir / "unpacked"
    if unpack_root.exists():
        shutil.rmtree(unpack_root)

    # Second run should hit cache AND warn about skipped
    with caplog.at_level("WARNING"):
        model = await analyze_ipa(ipa, cfg, registry, rm, cache)
    assert any("skipped" in r.message.lower() and "no_app_bundle" in r.message
               for r in caplog.records)
    # Unpack must still be short-circuited (Task 3 guarantee)
    assert not unpack_root.exists()


async def test_ios_pipeline_runs_react_native_subpipeline(tmp_path, monkeypatch):
    """When framework=react-native, iOS pipeline calls RN sub-pipeline against app bundle."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "rn.ipa"
    plist = plistlib.dumps({
        "CFBundleExecutable": "App",
        "CFBundleIdentifier": "com.example.rn",
    })
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60  # fake Mach-O magic
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)
        zf.writestr("Payload/App.app/main.jsbundle", b"// JS bundle\n")

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    captured: dict = {}

    async def fake_orchestrator(**kwargs):
        captured.update(kwargs)
        return {
            "bundle_path": str(kwargs["bundle_path"]),
            "variant": "jsc",
            "bundle_size": 16,
            "decompile": {"tool": "webcrack", "ran": False, "output_dir": "x",
                          "file_count": 0, "skipped_reason": "tool_unavailable",
                          "hermes_bytecode_version": None},
            "source_map": {"discovered": False, "path": None, "source_count": 0,
                           "names_populated": 0},
            "security_issue_count": 0,
            "module_id_count": 0,
        }

    monkeypatch.setattr(
        "chimera.pipelines.ios.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    assert captured, "RN sub-pipeline was not invoked from iOS pipeline"
    assert captured["platform"] == "ios"

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"]["variant"] == "jsc"


async def test_ios_pipeline_skips_rn_subpipeline_for_non_rn_ipa(tmp_path, monkeypatch):
    """When framework is not react-native, RN sub-pipeline is not invoked and triage carries None."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "plain.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.plain"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)
        # No *.jsbundle — framework detector returns "native".

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
        "chimera.pipelines.ios.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    assert invoked == []

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"] is None


async def test_ios_pipeline_rn_framework_but_no_bundle_records_skip_marker(tmp_path, monkeypatch):
    """When framework is RN but find_rn_bundle returns None, triage carries the skip-marker dict."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "rn.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.rn"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)
        zf.writestr("Payload/App.app/main.jsbundle", b"// JS bundle\n")

    config = ChimeraConfig(
        project_dir=tmp_path / "project",
        cache_dir=tmp_path / "cache",
    )
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()

    monkeypatch.setattr(
        "chimera.pipelines.ios.find_rn_bundle",
        lambda app_bundle, platform: None,
    )

    invoked: list = []

    async def fake_orchestrator(**kwargs):
        invoked.append(kwargs)
        return {}

    monkeypatch.setattr(
        "chimera.pipelines.ios.analyze_react_native_bundle",
        fake_orchestrator,
    )

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    assert invoked == []

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["react_native_context"] == {
        "bundle_path": None,
        "skipped_reason": "no_bundle_found",
    }


async def test_ios_pipeline_demangles_function_names(tmp_path, monkeypatch):
    """Phase 5.5 must demangle r2-discovered function names and preserve mangled in original_name."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.swift"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)

    config = ChimeraConfig(project_dir=tmp_path / "project", cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)

    registry = AdapterRegistry()
    adapter = SwiftDemangleAdapter()

    async def fake_demangle(names):
        return {n: f"Demangled<{n[-4:]}>" for n in names}

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "demangle_batch", fake_demangle)
    registry.register(adapter)

    class _FakeR2:
        def name(self): return "radare2"
        def is_available(self): return True
        def supported_formats(self): return ["macho"]
        def resource_estimate(self, p): return None
        async def cleanup(self): pass
        async def analyze(self, path, opts):
            return {
                "strings": [],
                "functions": [
                    {"offset": 0x1000, "name": "_$s4Demo7AppViewC4bodyQrvg"},
                    {"offset": 0x2000, "name": "regular_function"},
                ],
            }
    registry.register(_FakeR2())

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert "swift_demangle_context" in triage
    ctx = triage["swift_demangle_context"]
    assert ctx["available"] is True
    assert ctx["names_demangled"] == 1


async def test_ios_pipeline_demangles_strings_as_siblings(tmp_path, monkeypatch):
    """Phase 5.5 must add sibling string entries for mangled values; original mangled string preserved."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.swift"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)

    config = ChimeraConfig(project_dir=tmp_path / "project", cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)

    registry = AdapterRegistry()
    adapter = SwiftDemangleAdapter()

    async def fake_demangle(names):
        return {n: f"DemangledStr<{n[-4:]}>" for n in names}

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "demangle_batch", fake_demangle)
    registry.register(adapter)

    class _FakeR2:
        def name(self): return "radare2"
        def is_available(self): return True
        def supported_formats(self): return ["macho"]
        def resource_estimate(self, p): return None
        async def cleanup(self): pass
        async def analyze(self, path, opts):
            return {
                "strings": [
                    {"vaddr": 0x100, "string": "_$s4Demo10MetadataStr"},
                    {"vaddr": 0x200, "string": "Hello world"},
                ],
                "functions": [],
            }
    registry.register(_FakeR2())

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["swift_demangle_context"]["strings_demangled"] == 1


async def test_ios_pipeline_demangles_tokens_in_decompiled_bodies(tmp_path, monkeypatch):
    """Phase 5.5 must rewrite mangled tokens inside FunctionInfo.decompiled bodies."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.model.function import FunctionInfo
    from chimera.model.program import UnifiedProgramModel
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.swift"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)

    config = ChimeraConfig(project_dir=tmp_path / "project", cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)

    registry = AdapterRegistry()
    adapter = SwiftDemangleAdapter()

    async def fake_demangle(names):
        return {n: f"Decoded::{n[-4:]}" for n in names}

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "demangle_batch", fake_demangle)
    registry.register(adapter)

    class _FakeR2:
        def name(self): return "radare2"
        def is_available(self): return True
        def supported_formats(self): return ["macho"]
        def resource_estimate(self, p): return None
        async def cleanup(self): pass
        async def analyze(self, path, opts):
            return {"strings": [], "functions": [{"offset": 0x1000, "name": "decoy"}]}
    registry.register(_FakeR2())

    orig_add = UnifiedProgramModel.add_function
    injected = {"done": False}

    def patched_add(self, func: FunctionInfo) -> None:
        if not injected["done"]:
            func.decompiled = "void f() { call(_$s4Demo7AppViewC4bodyQrvg); }"
            injected["done"] = True
        orig_add(self, func)

    monkeypatch.setattr(UnifiedProgramModel, "add_function", patched_add)

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert triage["swift_demangle_context"]["decompiled_tokens_demangled"] >= 1


async def test_ios_pipeline_swift_demangle_skips_when_unavailable(tmp_path, monkeypatch):
    """When swift-demangle adapter is unavailable, Phase 5.5 records skipped_reason and counters stay 0."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa

    ipa = tmp_path / "plain.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App", "CFBundleIdentifier": "com.example.plain"})
    main_bin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", main_bin)

    config = ChimeraConfig(project_dir=tmp_path / "project", cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)

    registry = AdapterRegistry()
    adapter = SwiftDemangleAdapter()
    monkeypatch.setattr(adapter, "is_available", lambda: False)
    registry.register(adapter)

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    ctx = triage["swift_demangle_context"]
    assert ctx["available"] is False
    assert ctx["skipped_reason"] == "tool_unavailable"
    assert ctx["names_demangled"] == 0
    assert ctx["strings_demangled"] == 0
    assert ctx["decompiled_tokens_demangled"] == 0


async def test_ios_pipeline_runs_phase_4_5_objc_xref(tmp_path):
    """Phase 4.5 must populate triage with objc_xref_context."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    macho = build_macho_with_objc(
        classes=[BuilderClass(
            name="LoginVC", superclass="NSObject",
            methods=[BuilderMethod(selector="auth:", types="v16@0:8",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App",
                             "CFBundleIdentifier": "com.example.swift"})
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", macho)

    config = ChimeraConfig(project_dir=tmp_path / "project",
                            cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()  # no adapters; Phase 4.5 doesn't need any

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    import hashlib
    sha = hashlib.sha256(ipa.read_bytes()).hexdigest()
    triage = cache.get_json(sha, "triage")
    assert "objc_xref_context" in triage
    ctx = triage["objc_xref_context"]
    assert ctx["available"] is True
    assert ctx["class_count"] == 1
    assert ctx["method_count"] == 1
    assert ctx["callsite_count"] == 0  # no r2 xrefs registered, expected
    assert ctx["class_dump_enriched"] is False  # no class-dump JSON, expected
    assert ctx["category_count"] == 0


async def test_ios_pipeline_demangles_objc_class_names(tmp_path, monkeypatch):
    """Phase 5.5 must rewrite mangled class_name on ObjCMethod entries."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    macho = build_macho_with_objc(
        classes=[BuilderClass(
            name="_$s4Demo7AppViewC", superclass="NSObject",
            methods=[BuilderMethod(selector="auth:", types="v",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App",
                             "CFBundleIdentifier": "com.example.swift"})
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", macho)

    config = ChimeraConfig(project_dir=tmp_path / "project",
                            cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()
    adapter = SwiftDemangleAdapter()

    async def fake_demangle(names):
        return {n: f"Demangled<{n[-4:]}>" for n in names}

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "demangle_batch", fake_demangle)
    registry.register(adapter)

    model = await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    methods = [m for m in model.objc_methods if m.selector == "auth:"]
    assert len(methods) == 1
    assert methods[0].class_name.startswith("Demangled<")
    classes = [c for c in model.objc_classes if c.is_swift_objc]
    assert len(classes) == 1
    assert classes[0].name.startswith("Demangled<")
    # Lookup by demangled name must succeed (catches stale-dict-key regressions).
    demangled_name = classes[0].name
    looked_up = model.find_objc_method(class_name=demangled_name, selector="auth:")
    assert len(looked_up) == 1


async def test_ios_pipeline_phase_4_5_resolves_callsites_from_r2_cache(tmp_path):
    """Phase 4.5 reads cached r2 disassembly and produces non-zero callsite_count."""
    import plistlib
    import zipfile
    from chimera.adapters.registry import AdapterRegistry
    from chimera.core.cache import AnalysisCache
    from chimera.core.config import ChimeraConfig
    from chimera.core.resource_manager import ResourceManager
    from chimera.pipelines.ios import analyze_ipa
    from tests.unit._macho_builder import (
        build_macho_with_objc, BuilderClass, BuilderMethod,
    )

    macho = build_macho_with_objc(
        classes=[BuilderClass(
            name="Greeter", superclass="NSObject",
            methods=[BuilderMethod(selector="greet", types="v16@0:8",
                                    imp_addr=0x100123abc)],
        )],
        categories=[], protocols=[],
    )
    ipa = tmp_path / "swift.ipa"
    plist = plistlib.dumps({"CFBundleExecutable": "App",
                             "CFBundleIdentifier": "com.example.swift"})
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", plist)
        zf.writestr("Payload/App.app/App", macho)

    config = ChimeraConfig(project_dir=tmp_path / "project",
                            cache_dir=tmp_path / "cache")
    cache = AnalysisCache(config.cache_dir)
    resource_mgr = ResourceManager(total_ram_mb=4096)
    registry = AdapterRegistry()  # no r2 adapter

    # Pre-seed the r2 cache with a known callsite pattern. The pipeline will
    # find it during Phase 4.5 invocation of build_objc_xref → extract_callsites.
    from chimera.model.binary import BinaryInfo
    binary = BinaryInfo.from_path(ipa)
    cache.put_json(binary.sha256, "r2_App", {
        "strings": [], "functions": [],
        "per_function_disasm": {
            "0x100456000": {
                "name": "sym.test",
                "ops": [
                    {"offset": 0x100456000, "opcode": "adrp",
                     "operands": ["x0", 0x100300000], "target_sym": None},
                    {"offset": 0x100456004, "opcode": "add",
                     "operands": ["x0", "x0", 0x10], "target_sym": None},
                    {"offset": 0x100456008, "opcode": "adrp",
                     "operands": ["x1", 0x100200000], "target_sym": None},
                    {"offset": 0x10045600c, "opcode": "add",
                     "operands": ["x1", "x1", 0x40], "target_sym": None},
                    {"offset": 0x100456010, "opcode": "bl", "operands": [],
                     "target_sym": "sym.imp.objc_msgSend"},
                    {"offset": 0x100456014, "opcode": "ret",
                     "operands": [], "target_sym": None},
                ],
            },
        },
        "class_symbols": {"Greeter": "0x100300010"},
        "cstring_pool": {"0x100200040": "greet"},
    })

    await analyze_ipa(ipa, config, registry, resource_mgr, cache)

    triage = cache.get_json(binary.sha256, "triage")
    ctx = triage["objc_xref_context"]
    assert ctx["callsite_count"] >= 1
    assert ctx["callsites_resolved_static"] >= 1
