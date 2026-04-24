from pathlib import Path
from chimera.model.binary import BinaryInfo, BinaryFormat, Platform, Architecture, Framework
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel


def _make_binary():
    return BinaryInfo(
        sha256="a" * 64, path=Path("/tmp/test.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.DEX, framework=Framework.NATIVE, size_bytes=1024,
    )


class TestFunctionInfo:
    def test_create(self):
        f = FunctionInfo(
            address="0x1234", name="decrypt_string", original_name="FUN_00001234",
            language="c", classification="crypto", layer="native", source_backend="ghidra",
        )
        assert f.address == "0x1234"
        assert f.name == "decrypt_string"
        assert f.classification == "crypto"


class TestUnifiedProgramModel:
    def test_create_empty(self):
        model = UnifiedProgramModel(_make_binary())
        assert model.binary.sha256 == "a" * 64
        assert len(model.functions) == 0

    def test_add_function(self):
        model = UnifiedProgramModel(_make_binary())
        func = FunctionInfo(
            address="0x1000", name="main", original_name="FUN_00001000",
            language="java", classification="init", layer="java", source_backend="jadx",
        )
        model.add_function(func)
        assert len(model.functions) == 1
        assert model.get_function("0x1000").name == "main"

    def test_add_call_edge(self):
        model = UnifiedProgramModel(_make_binary())
        f1 = FunctionInfo(address="0x1000", name="caller", original_name="FUN_1000",
                          language="c", classification="utility", layer="native", source_backend="ghidra")
        f2 = FunctionInfo(address="0x2000", name="callee", original_name="FUN_2000",
                          language="c", classification="crypto", layer="native", source_backend="ghidra")
        model.add_function(f1)
        model.add_function(f2)
        model.add_call_edge("0x1000", "0x2000", call_type="direct")
        callees = model.get_callees("0x1000")
        assert len(callees) == 1
        assert callees[0].address == "0x2000"

    def test_add_string(self):
        model = UnifiedProgramModel(_make_binary())
        model.add_string("0x3000", "https://api.example.com/auth", section=".rodata")
        strings = model.get_strings()
        assert len(strings) == 1
        assert strings[0].value == "https://api.example.com/auth"

    def test_get_functions_by_classification(self):
        model = UnifiedProgramModel(_make_binary())
        model.add_function(FunctionInfo(address="0x1", name="a", original_name="a",
                           language="c", classification="crypto", layer="native", source_backend="ghidra"))
        model.add_function(FunctionInfo(address="0x2", name="b", original_name="b",
                           language="c", classification="utility", layer="native", source_backend="ghidra"))
        model.add_function(FunctionInfo(address="0x3", name="c", original_name="c",
                           language="c", classification="crypto", layer="native", source_backend="ghidra"))
        crypto_funcs = model.get_functions_by_classification("crypto")
        assert len(crypto_funcs) == 2


def test_add_function_collision_merges_sources():
    from chimera.model.binary import (
        Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
    )
    from chimera.model.function import FunctionInfo
    from chimera.model.program import UnifiedProgramModel
    from pathlib import Path

    b = BinaryInfo(sha256="f"*64, path=Path("/x"), format=BinaryFormat.APK,
                   platform=Platform.ANDROID, arch=Architecture.DEX,
                   framework=Framework.NATIVE, size_bytes=1)
    m = UnifiedProgramModel(b)

    m.add_function(FunctionInfo(address="0x100", name="a", original_name="a",
                                language="c", classification="unknown",
                                layer="native", source_backend="radare2"))
    m.add_function(FunctionInfo(address="0x100", name="a", original_name="a",
                                language="c", classification="unknown",
                                layer="native", source_backend="ghidra"))
    got = m.get_function("0x100")
    assert got is not None
    assert set(got.sources) >= {"radare2", "ghidra"}, got.sources


def test_dangling_call_edges_are_dropped_at_query_time():
    from chimera.model.binary import (
        Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
    )
    from chimera.model.function import FunctionInfo
    from chimera.model.program import UnifiedProgramModel
    from pathlib import Path

    b = BinaryInfo(sha256="e"*64, path=Path("/x"), format=BinaryFormat.APK,
                   platform=Platform.ANDROID, arch=Architecture.DEX,
                   framework=Framework.NATIVE, size_bytes=1)
    m = UnifiedProgramModel(b)
    m.add_function(FunctionInfo(address="0x1", name="a", original_name="a",
                                language="c", classification="unknown",
                                layer="native", source_backend="r2"))
    m.add_call_edge("0x1", "0xDEAD")  # callee does not exist
    m.add_call_edge("0xBEEF", "0x1")  # caller does not exist

    assert m.get_callees("0x1") == []   # callee 0xDEAD missing
    assert m.get_callers("0x1") == []   # caller 0xBEEF missing


def test_add_call_edge_allows_forward_reference():
    """Edges may be added before both endpoints exist; query-time filtering handles it."""
    from chimera.model.binary import (
        Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
    )
    from chimera.model.function import FunctionInfo
    from chimera.model.program import UnifiedProgramModel
    from pathlib import Path

    b = BinaryInfo(sha256="d"*64, path=Path("/x"), format=BinaryFormat.APK,
                   platform=Platform.ANDROID, arch=Architecture.DEX,
                   framework=Framework.NATIVE, size_bytes=1)
    m = UnifiedProgramModel(b)
    m.add_call_edge("0xAAA", "0xBBB")  # neither side exists yet
    m.add_function(FunctionInfo(address="0xAAA", name="a", original_name="a",
                                language="c", classification="unknown",
                                layer="native", source_backend="r2"))
    m.add_function(FunctionInfo(address="0xBBB", name="b", original_name="b",
                                language="c", classification="unknown",
                                layer="native", source_backend="r2"))
    assert [f.name for f in m.get_callees("0xAAA")] == ["b"]
    assert [f.name for f in m.get_callers("0xBBB")] == ["a"]


def test_save_function_warns_when_sources_populated(caplog, monkeypatch):
    """Until a sources column lands, save_function must warn on populated sources."""
    import logging
    from chimera.model.database import ChimeraDatabase
    from chimera.model.function import FunctionInfo

    class _Ctx:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def execute(self, *a, **k): return "OK"

    class FakePool:
        def acquire(self):
            return _Ctx()

    async def runner():
        db = ChimeraDatabase(pool=FakePool())
        f = FunctionInfo(
            address="0x1", name="a", original_name="a",
            language="c", classification="unknown",
            layer="native", source_backend="r2",
            sources=["r2", "ghidra"],
        )
        with caplog.at_level(logging.WARNING):
            await db.save_function("sha", f)

    import asyncio
    asyncio.run(runner())
    assert any(
        "sources" in r.message and "dropped" in r.message for r in caplog.records
    ), [r.message for r in caplog.records]


def test_get_strings_caches_compiled_regex():
    import re as _re
    from chimera.model.binary import (
        Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
    )
    from chimera.model.program import UnifiedProgramModel
    from pathlib import Path

    b = BinaryInfo(sha256="a"*64, path=Path("/x"), format=BinaryFormat.APK,
                   platform=Platform.ANDROID, arch=Architecture.DEX,
                   framework=Framework.NATIVE, size_bytes=1)
    m = UnifiedProgramModel(b)
    m.add_string("0x1", "hello")

    calls = []
    orig_compile = _re.compile

    def spy(p, *a, **k):
        calls.append(p)
        return orig_compile(p, *a, **k)

    import chimera.model.program as prog
    prog._re.compile = spy  # type: ignore
    try:
        m.get_strings("hel")
        m.get_strings("hel")
        m.get_strings("hel")
    finally:
        prog._re.compile = orig_compile  # type: ignore
    assert calls.count("hel") == 1
