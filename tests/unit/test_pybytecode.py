"""Tests for the layered-Python unwrapper.

Everything is built in-memory from stdlib primitives so each test fails for a
real reason: if a detector, the recursion, or the code-object walk breaks, the
markers below stop showing up in the tree. Nothing here executes the payload —
that the unwrapper never does so is itself asserted.
"""
from __future__ import annotations

import base64
import marshal
import zlib

from chimera.unpacking.pybytecode import disassemble, unwrap
from chimera.unpacking.pymagic import detect_pyc_version, pyc_header

# A module with a nested function, a marker int const, and a marker name, so
# the tests can look for them in the recovered co_consts / co_names.
_SRC = (
    "MARKER = 1337\n"
    "def inner_helper():\n"
    "    secret_value = 4242\n"
    "    return secret_value\n"
)


def _nested_blob() -> str:
    """A .py string whose literal is base85(zlib(marshal(code)))."""
    code = compile(_SRC, "<payload>", "exec")
    packed = base64.b85encode(zlib.compress(marshal.dumps(code)))
    return f"blob = {packed!r}\n"


def test_peels_marshal_zlib_base85_layers():
    result = unwrap(_nested_blob())
    kinds = [n.kind for n in result.iter_nodes()]
    # every wrapper layer is present, outermost to innermost
    for expected in ("pyliteral", "base85", "zlib", "marshal"):
        assert expected in kinds, f"{expected} layer missing: {kinds}"

    code_nodes = result.code_nodes()
    assert code_nodes, "no code object recovered"
    deepest = result.deepest_code()
    # the marker name and int const survived into the version-independent tree
    all_names = {n for cn in code_nodes for n in (cn.co_names or ())}
    assert "inner_helper" in all_names
    summaries = [s for cn in code_nodes for s in (cn.co_consts_summary or [])]
    assert any("1337" in s for s in summaries), summaries


def test_nested_code_object_is_walked():
    result = unwrap(_nested_blob())
    names = {cn.name for cn in result.code_nodes()}
    # the module code AND the function defined inside it are both walked
    assert "<module>" in names
    assert "inner_helper" in names
    # the inner function's own local marker is reachable
    summaries = [s for cn in result.code_nodes() for s in (cn.co_consts_summary or [])]
    assert any("4242" in s for s in summaries), summaries


def test_unwrap_never_executes_the_payload(tmp_path):
    sentinel = tmp_path / "SIDE_EFFECT"
    # A payload whose top level, if executed, writes the sentinel file.
    evil_src = (
        "import pathlib\n"
        f"pathlib.Path({str(sentinel)!r}).write_text('boom')\n"
    )
    code = compile(evil_src, "<evil>", "exec")
    blob = f"payload = {base64.b85encode(zlib.compress(marshal.dumps(code)))!r}\n"

    result = unwrap(blob)
    # the code object was recovered (so we really peeled it) ...
    assert any("pathlib" in (cn.co_names or ()) for cn in result.code_nodes())
    # ... but its side effect never happened: static extraction only.
    assert not sentinel.exists(), "unwrap executed the payload — it must not"


def test_bytes_and_pyc_inputs_peel_directly():
    code = compile(_SRC, "<payload>", "exec")
    # raw marshalled bytes
    r_bytes = unwrap(marshal.dumps(code))
    assert r_bytes.code_nodes() and "inner_helper" in {
        n for cn in r_bytes.code_nodes() for n in (cn.co_names or ())}
    # a reconstructed .pyc file
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "m.pyc"
        p.write_bytes(pyc_header(312) + marshal.dumps(code))
        r_pyc = unwrap(p)
        assert r_pyc.code_nodes()


def test_version_detection_from_pyc_header():
    assert detect_pyc_version(pyc_header(312)) == 312
    assert detect_pyc_version(pyc_header(313)) == 313
    assert detect_pyc_version(b"\x00\x00not a magic") is None


def test_depth_cap_is_respected():
    # A deeply nested zlib chain must stop at max_depth, not recurse forever.
    data = marshal.dumps(compile(_SRC, "<p>", "exec"))
    for _ in range(6):
        data = zlib.compress(data)
    result = unwrap(data, max_depth=2)
    depths = [n.kind for n in result.iter_nodes()]
    # capped: fewer than the six zlib layers are peeled
    assert depths.count("zlib") <= 3


def test_disassemble_falls_back_without_xdis(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_xdis(name, *a, **k):
        if name == "xdis" or name.startswith("xdis."):
            raise ImportError("xdis blocked for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_xdis)
    code = compile(_SRC, "<p>", "exec")
    out = disassemble(code)
    assert "WARNING" in out                      # the host-table caveat
    assert "co_names/co_consts tree is always valid" in out


def test_disassemble_uses_xdis_when_available():
    import pytest
    pytest.importorskip("xdis")
    code = compile(_SRC, "<p>", "exec")
    out = disassemble(code)
    assert "xdis disassembly" in out
    assert "WARNING" not in out
