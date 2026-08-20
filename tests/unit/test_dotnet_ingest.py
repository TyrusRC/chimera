"""ILSpy C# ingestion — types, methods and string literals into the model."""
from __future__ import annotations

from chimera.model.binary import BinaryFormat, BinaryInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.dotnet_ingest import (
    ingest_ilspy_methods,
    ingest_ilspy_strings,
    ingest_ilspy_types,
)

SAMPLE = '''\
using System;

namespace Zexty.Validator
{
    internal sealed class KeyChecker
    {
        private const string Banner = "CINDERMARK CIPHER";

        public bool Validate(string key)
        {
            return key == "N0VAX-7C4DE-Q9R2K";
        }

        private static byte[] Derive(byte[] input)
        {
            return input;
        }
    }

    internal static class Helpers
    {
        internal static void Log(string s) { Console.WriteLine(s); }
    }
}
'''


def _model():
    return UnifiedProgramModel(BinaryInfo(
        sha256="0" * 64, path="/tmp/x.exe", format=BinaryFormat.DOTNET_PE,
        platform="windows", arch="x86_64", framework="native", size_bytes=1,
    ))


def _src(tmp_path):
    f = tmp_path / "Assembly.decompiled.cs"
    f.write_text(SAMPLE)
    return tmp_path


def test_ingests_declared_types(tmp_path):
    m = _model()
    n = ingest_ilspy_types(m, _src(tmp_path))
    assert n == 2
    names = {f.name for f in m.functions}
    assert "KeyChecker" in names
    assert "Helpers" in names
    # namespace-qualified originals
    assert any(f.original_name == "Zexty.Validator.KeyChecker" for f in m.functions)


def test_ingests_method_bodies(tmp_path):
    m = _model()
    n = ingest_ilspy_methods(m, _src(tmp_path))
    names = {f.name for f in m.functions}
    assert "Validate" in names
    assert "Derive" in names
    assert "Log" in names
    assert n >= 3


def test_control_flow_keywords_are_not_methods(tmp_path):
    src = tmp_path / "x.cs"
    # ILSpy always emits explicit modifiers, so a real method line carries
    # one; control-flow keywords never do.
    src.write_text("class C {\n    private void M() {\n        if (x) foo();\n"
                   "        while (y) bar();\n    }\n}\n")
    m = _model()
    ingest_ilspy_methods(m, tmp_path)
    names = {f.name for f in m.functions}
    assert "if" not in names and "while" not in names
    assert "M" in names


def test_ingests_string_literals(tmp_path):
    m = _model()
    n = ingest_ilspy_strings(m, _src(tmp_path))
    values = {s.value for s in m.get_strings()}
    assert "N0VAX-7C4DE-Q9R2K" in values
    assert "CINDERMARK CIPHER" in values
    assert n >= 2


def test_string_ingest_dedupes_and_respects_length(tmp_path):
    src = tmp_path / "x.cs"
    src.write_text('class C { void M() { var a = "dup"; var b = "dup"; '
                   'var c = "x"; var d = "long enough"; } }')
    m = _model()
    ingest_ilspy_strings(m, tmp_path, min_len=4)
    values = [s.value for s in m.get_strings()]
    assert values.count("dup") == 0   # too short at min_len=4? "dup" is 3
    assert "long enough" in values


def test_handles_a_single_file_path_not_only_a_dir(tmp_path):
    f = tmp_path / "One.decompiled.cs"
    f.write_text(SAMPLE)
    m = _model()
    assert ingest_ilspy_types(m, f) == 2


def test_rehydrate_from_cache_blob(tmp_path):
    """A warm cache must replay the managed types/methods, not just natives.

    The PE pipeline caches ilspy output; on a cache hit it must re-ingest
    it, or a second analysis of a .NET binary loses everything managed —
    the exact failure the MCP server hit (183 -> 15 functions).
    """
    from chimera.core.cache import AnalysisCache
    from chimera.pipelines.dotnet_ingest import rehydrate_ilspy_from_cache

    cache = AnalysisCache(tmp_path / "cache")
    sha = "b" * 64
    cache.put_json(sha, "ilspy_App.exe", {
        "available": True, "assembly": "App",
        "type_count": 1,
        "types": [{"namespace": "Zexty.Validator", "name": "KeyChecker",
                   "file": "/gone/App.decompiled.cs", "decompiled": SAMPLE}],
    })
    m = _model()
    types, methods, strings = rehydrate_ilspy_from_cache(m, cache, sha)
    assert types == 2 and methods >= 3 and strings >= 2
    names = {f.name for f in m.functions}
    assert "KeyChecker" in names and "Validate" in names
    assert "N0VAX-7C4DE-Q9R2K" in {s.value for s in m.get_strings()}


def test_rehydrate_is_a_noop_without_ilspy_entries(tmp_path):
    from chimera.core.cache import AnalysisCache
    from chimera.pipelines.dotnet_ingest import rehydrate_ilspy_from_cache
    cache = AnalysisCache(tmp_path / "cache")
    sha = "c" * 64
    cache.put_json(sha, "triage", {"format": "dotnet_pe"})
    m = _model()
    assert rehydrate_ilspy_from_cache(m, cache, sha) == (0, 0, 0)
