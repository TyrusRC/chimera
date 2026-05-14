"""Program.add_call_edge builds by_caller / by_callee indexes for O(degree) lookup,
and _regex_cache is a bounded LRU."""
from __future__ import annotations

import time
from pathlib import Path

from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel, _REGEX_CACHE_MAX


def _model() -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="0" * 64,
        path=Path("/x"),
        format=BinaryFormat.PE64,
        platform=Platform.WINDOWS,
        arch=Architecture.X86_64,
        framework=Framework.NATIVE,
        size_bytes=1,
    )
    return UnifiedProgramModel(bi)


def _fn(addr: str) -> FunctionInfo:
    return FunctionInfo(
        address=addr,
        name=f"f_{addr}",
        original_name=f"f_{addr}",
        language="c",
        classification="user",
        layer="native",
        source_backend="test",
    )


def test_get_callees_is_o_degree_not_o_edges():
    """With 10k unrelated edges, get_callees('0x1') (degree 1) is fast."""
    m = _model()
    m.add_function(_fn("0x1"))
    m.add_function(_fn("0x2"))
    for i in range(10_000):
        addr = f"0x{i + 100:x}"
        m.add_function(_fn(addr))
        m.add_call_edge(addr, "0x2")
    m.add_call_edge("0x1", "0x2")  # the one edge from 0x1

    t = time.perf_counter()
    callees = m.get_callees("0x1")
    elapsed = time.perf_counter() - t
    assert len(callees) == 1
    # Loose budget — index path is microseconds, O(N) scan would be tens of ms.
    assert elapsed < 0.005, f"get_callees too slow: {elapsed * 1000:.2f}ms"


def test_get_callers_is_o_degree_not_o_edges():
    m = _model()
    m.add_function(_fn("0x1"))
    m.add_function(_fn("0xfeed"))
    for i in range(10_000):
        addr = f"0x{i + 100:x}"
        m.add_function(_fn(addr))
        m.add_call_edge("0x1", addr)  # 10k callees from 0x1
    m.add_call_edge("0x1", "0xfeed")

    t = time.perf_counter()
    callers = m.get_callers("0xfeed")
    elapsed = time.perf_counter() - t
    assert len(callers) == 1
    assert elapsed < 0.005, f"get_callers too slow: {elapsed * 1000:.2f}ms"


def test_get_callees_returns_same_set_as_before_for_simple_graph():
    m = _model()
    for a in ("0x1", "0x2", "0x3"):
        m.add_function(_fn(a))
    m.add_call_edge("0x1", "0x2")
    m.add_call_edge("0x1", "0x3")
    m.add_call_edge("0x2", "0x3")
    callees = {f.address for f in m.get_callees("0x1")}
    assert callees == {"0x2", "0x3"}
    callers = {f.address for f in m.get_callers("0x3")}
    assert callers == {"0x1", "0x2"}


def test_regex_cache_is_bounded_lru():
    m = _model()
    m.add_function(_fn("0x1"))
    # Force 1000 distinct patterns; cache must hold at most _REGEX_CACHE_MAX.
    for i in range(1000):
        m.get_strings(pattern=f"unique_{i}_.*")
    assert len(m._regex_cache) <= _REGEX_CACHE_MAX
    # Most recent must be present; earliest patterns evicted.
    assert "unique_999_.*" in m._regex_cache
    assert "unique_0_.*" not in m._regex_cache


def test_regex_cache_lru_promotes_on_hit():
    m = _model()
    m.add_function(_fn("0x1"))
    # Fill the cache to capacity.
    for i in range(_REGEX_CACHE_MAX):
        m.get_strings(pattern=f"p_{i}_.*")
    # Touch the oldest entry to promote it.
    m.get_strings(pattern="p_0_.*")
    # Now insert one more — the previously-second-oldest should be evicted, not p_0.
    m.get_strings(pattern="p_new_.*")
    assert "p_0_.*" in m._regex_cache
    assert "p_1_.*" not in m._regex_cache
