"""r2 analysis-mode escalation for stripped binaries (A4).

Symbol-table triage recovers ~nothing on a stripped binary; the pipelines now
escalate to r2's `aaa`/`aflj` analysis pass. The decision is a pure function
and the merge is testable with a fake adapter (no r2pipe needed).
"""

from __future__ import annotations

import asyncio

from chimera.model.binary import BinaryInfo
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.pipelines.common import deepen_r2_functions, should_deepen_r2


def _model() -> UnifiedProgramModel:
    return UnifiedProgramModel(BinaryInfo(
        sha256="0" * 64, path="/tmp/x", format="elf", platform="linux",
        arch="x86_64", framework="native", size_bytes=1,
    ))


def test_should_deepen_when_forced():
    assert should_deepen_r2(1000, deep=True) is True


def test_should_deepen_on_low_count():
    assert should_deepen_r2(0, deep=False, min_functions=3) is True
    assert should_deepen_r2(2, deep=False, min_functions=3) is True
    assert should_deepen_r2(3, deep=False, min_functions=3) is False
    assert should_deepen_r2(50, deep=False, min_functions=3) is False


def test_should_deepen_min_functions_floor():
    # min_functions is floored at 1 so a 0-function triage always escalates.
    assert should_deepen_r2(0, deep=False, min_functions=0) is True


class _FakeR2:
    def __init__(self, funcs):
        self._funcs = funcs

    async def analyze(self, path, opts):
        assert opts["mode"] == "functions"
        return {"functions": self._funcs}


def test_deepen_adds_only_new_functions():
    model = _model()
    model.add_function(FunctionInfo(
        address="0x1000", name="known", original_name="known", language="c",
        classification="unknown", layer="native", source_backend="radare2",
    ))
    fake = _FakeR2([
        {"offset": 0x1000, "name": "known"},        # already present → merge
        {"offset": 0x2000, "name": "fcn.00002000"}, # new
        {"name": "no_offset"},                       # invalid → skipped
    ])
    added = asyncio.run(deepen_r2_functions(fake, "/x", model))
    assert added == 1
    assert model.get_function("0x2000") is not None
    assert len(model.functions) == 2
