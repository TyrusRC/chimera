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
