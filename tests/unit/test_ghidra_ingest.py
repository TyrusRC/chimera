"""Ghidra decompilation ingestion into the unified model.

Regression coverage for the bug where native pipelines cached Ghidra's
output and then discarded it, leaving `FunctionInfo.decompiled` always None
for native code. `ingest_ghidra_functions` must merge the decompiled C onto
the r2-seeded functions (matched by normalized entry-point address) and add
Ghidra-only functions.
"""

from __future__ import annotations

from chimera.model.binary import BinaryInfo
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import _norm_addr, ingest_ghidra_functions


def _model() -> UnifiedProgramModel:
    return UnifiedProgramModel(BinaryInfo(
        sha256="0" * 64, path="/tmp/x", format="elf", platform="linux",
        arch="x86_64", framework="native", size_bytes=1,
    ))


def test_norm_addr_matches_r2_and_ghidra_forms():
    # r2 emits hex(offset); Ghidra prints zero-padded, sometimes space-prefixed.
    assert _norm_addr("0x401000") == "0x401000"
    assert _norm_addr("00401000") == "0x401000"
    assert _norm_addr("ram:00401000") == "0x401000"
    assert _norm_addr(0x401000) == "0x401000"
    # Non-hex falls back to the stringified input rather than raising.
    assert _norm_addr("weird") == "weird"


def test_backfills_decompiled_onto_r2_function():
    model = _model()
    # r2 seeded this function first, with no decompiled C.
    model.add_function(FunctionInfo(
        address="0x401000", name="main", original_name="main", language="c",
        classification="unknown", layer="native", source_backend="radare2",
    ))
    ghidra_result = {
        "functions": [{"name": "main", "address": "00401000", "size": 42}],
        "decompilations": [{"address": "00401000", "code": "int main(void){return 0;}"}],
    }

    n = ingest_ghidra_functions(model, ghidra_result)

    assert n == 1
    func = model.get_function("0x401000")
    assert func is not None
    # Merged onto the SAME function (no duplicate at a different address key).
    assert len(model.functions) == 1
    assert func.decompiled == "int main(void){return 0;}"
    # First-writer identity kept, but Ghidra recorded as a contributing backend.
    assert func.name == "main"
    assert "radare2" in func.sources and "ghidra" in func.sources


def test_adds_ghidra_only_function():
    model = _model()
    ghidra_result = {
        "functions": [{"name": "helper", "address": "0x401100", "size": 10}],
        "decompilations": [{"address": "0x401100", "code": "void helper(){}"}],
    }

    n = ingest_ghidra_functions(model, ghidra_result)

    assert n == 1
    func = model.get_function("0x401100")
    assert func is not None
    assert func.source_backend == "ghidra"
    assert func.decompiled == "void helper(){}"


def test_orphan_decompilation_is_not_dropped():
    # A decompilation whose address isn't in the functions list still lands.
    model = _model()
    ghidra_result = {
        "functions": [],
        "decompilations": [{"address": "0x401200", "code": "int orphan(){return 1;}"}],
    }

    n = ingest_ghidra_functions(model, ghidra_result)

    assert n == 1
    assert model.get_function("0x401200").decompiled == "int orphan(){return 1;}"


def test_tolerates_missing_or_bad_result():
    model = _model()
    assert ingest_ghidra_functions(model, None) == 0
    assert ingest_ghidra_functions(model, {}) == 0
    assert ingest_ghidra_functions(model, {"error": "ghidra crashed"}) == 0
    assert model.functions == []


def test_merge_does_not_overwrite_existing_decompiled():
    # If the first backend already provided decompiled C, a later merge must
    # not clobber it (backfill is only for empty fields).
    model = _model()
    model.add_function(FunctionInfo(
        address="0x401000", name="main", original_name="main", language="c",
        classification="unknown", layer="native", source_backend="radare2",
        decompiled="ORIGINAL",
    ))
    ingest_ghidra_functions(model, {
        "functions": [{"name": "main", "address": "0x401000"}],
        "decompilations": [{"address": "0x401000", "code": "GHIDRA"}],
    })
    assert model.get_function("0x401000").decompiled == "ORIGINAL"
