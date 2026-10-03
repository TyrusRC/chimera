"""WebAssembly support: pure-Python section parser, format routing, helpers.

The module under test is built byte-for-byte in-process (no wabt/binaryen), so
these run everywhere. Tool-driven paths (decompile recipe, Node oracle, tracer)
are validated against the real Go-WASM target out of band — see the gap report.
"""

from __future__ import annotations

import os

import pytest

from chimera.adapters import wabt
from chimera.dynamic import wasm_oracle as wo
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.parsers.wasm import WASM_MAGIC, is_wasm, parse_wasm
from chimera.pipelines.common import detect_binary_format, detect_platform
from chimera.pipelines.wasm import detect_go_wasm


# --- byte-level module builder ----------------------------------------------

def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _name(s: str) -> bytes:
    b = s.encode()
    return _uleb(len(b)) + b


def _section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + _uleb(len(payload)) + payload


def _build_wasm(*, import_module: str = "env", with_names: bool = True,
                go_exports: bool = False) -> bytes:
    typ = _section(1, _uleb(1) + b"\x60" + _uleb(0) + _uleb(0))   # one () -> ()
    imp = _section(2, _uleb(1) + _name(import_module) + _name("imp")
                   + b"\x00" + _uleb(0))                           # one func import
    fn = _section(3, _uleb(1) + _uleb(0))                          # one defined func
    mem = _section(5, _uleb(1) + b"\x00" + _uleb(1))              # min=1, no max
    exports = [(_name("check") + b"\x00" + _uleb(1))]            # func idx 1
    if go_exports:
        for nm, idx in (("run", 1), ("resume", 1), ("getsp", 1)):
            exports.append(_name(nm) + b"\x00" + _uleb(idx))
    exp = _section(7, _uleb(len(exports)) + b"".join(exports))
    data = _section(11, _uleb(2) + b"\x00\x00")                   # count=2
    parts = [WASM_MAGIC, (1).to_bytes(4, "little"), typ, imp, fn, mem, exp, data]
    if with_names:
        sub = _uleb(1) + _uleb(1) + _name("check")                # fn-names: idx1 -> check
        body = bytes([1]) + _uleb(len(sub)) + sub                 # subsection id 1
        parts.append(_section(0, _name("name") + body))
    return b"".join(parts)


@pytest.fixture
def wasm_file(tmp_path):
    p = tmp_path / "mod.wasm"
    p.write_bytes(_build_wasm())
    return p


# --- parser ------------------------------------------------------------------

def test_is_wasm(wasm_file, tmp_path):
    assert is_wasm(wasm_file)
    other = tmp_path / "x.bin"
    other.write_bytes(b"\x7fELF\x00\x00\x00\x00")
    assert not is_wasm(other)


def test_parse_counts_and_memory(wasm_file):
    mod = parse_wasm(wasm_file)
    assert mod.version == 1
    assert mod.imported_func_count == 1
    assert mod.defined_func_count == 1
    assert mod.total_func_count == 2
    assert mod.memory_min_pages == 1
    assert mod.memory_max_pages is None
    assert mod.data_segment_count == 2
    assert not mod.truncated


def test_parse_imports_exports(wasm_file):
    mod = parse_wasm(wasm_file)
    assert ("env", "imp", "func") in [(i.module, i.field, i.kind) for i in mod.imports]
    names = {e.name: e.index for e in mod.exports}
    assert names["check"] == 1


def test_parse_name_section(wasm_file):
    mod = parse_wasm(wasm_file)
    # The function-name subsection maps the defined func (index 1) to "check".
    assert mod.function_names.get(1) == "check"


def test_parse_truncated_is_soft(tmp_path):
    # A header plus a section header claiming more bytes than exist must not raise.
    p = tmp_path / "trunc.wasm"
    p.write_bytes(WASM_MAGIC + (1).to_bytes(4, "little") + bytes([1]) + _uleb(99))
    mod = parse_wasm(p)
    assert mod.truncated


def test_parse_non_wasm_returns_empty(tmp_path):
    p = tmp_path / "no.wasm"
    p.write_bytes(b"not wasm at all")
    mod = parse_wasm(p)
    assert mod.version == 1 and not mod.sections


# --- format detection / routing ----------------------------------------------

def test_detect_binary_format_wasm(wasm_file):
    assert detect_binary_format(wasm_file) == "wasm"


def test_detect_platform_wasm(wasm_file):
    assert detect_platform(wasm_file) == "wasm"


def test_binaryinfo_from_path_wasm(wasm_file):
    info = BinaryInfo.from_path(wasm_file)
    assert info.format == BinaryFormat.WASM
    assert info.platform == Platform.WASM
    assert info.arch == Architecture.WASM
    assert not info.format.is_mobile


# --- Go-WASM heuristic --------------------------------------------------------

def test_detect_go_via_gojs_import(tmp_path):
    p = tmp_path / "g.wasm"
    p.write_bytes(_build_wasm(import_module="gojs"))
    assert detect_go_wasm(parse_wasm(p), p)


def test_detect_go_via_exports(tmp_path):
    p = tmp_path / "g.wasm"
    p.write_bytes(_build_wasm(go_exports=True))
    assert detect_go_wasm(parse_wasm(p), p)


def test_detect_go_via_sibling_glue(wasm_file):
    (wasm_file.parent / "wasm_exec.js").write_text("// Go glue\n")
    assert detect_go_wasm(parse_wasm(wasm_file), wasm_file)


def test_detect_not_go(wasm_file):
    # Plain module, no gojs import / Go exports / sibling glue / go1.* bytes.
    assert not detect_go_wasm(parse_wasm(wasm_file), wasm_file)


# --- tool wrappers / discovery ------------------------------------------------

def test_tools_available_keys():
    assert set(wabt.tools_available()) == {"wasm2wat", "wasm-opt", "wasm-decompile"}


def test_find_tool_via_env(tmp_path, monkeypatch):
    fake = tmp_path / "wasm-opt"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CHIMERA_WASM_TOOLS", str(tmp_path))
    assert wabt._find_tool("wasm-opt") == str(fake)
    assert wabt._find_tool("nonexistent-tool-xyz") is None


def test_func_index_parsing():
    assert wabt._func_index("  (func (;3271;) (type 0) (param i32)") == 3271
    assert wabt._func_index('  (import "log" "log_execution" (func (;20;) (type 1)))') == 20
    assert wabt._func_index("  i32.const 5") is None


# --- oracle helpers -----------------------------------------------------------

def test_find_wasm_exec_js(wasm_file):
    assert wo.find_wasm_exec_js(wasm_file) is None
    (wasm_file.parent / "wasm_exec.js").write_text("// glue\n")
    assert wo.find_wasm_exec_js(wasm_file) is not None


def test_run_oracle_requires_glue_for_go(wasm_file):
    # go forced on, no wasm_exec.js sibling -> clear error, not a crash.
    with pytest.raises(wo.WasmOracleError):
        wo.run_oracle(wasm_file, ["x"], go=True)


# --- real-target regression (opt-in; needs the 5.8MB target + node/wabt) ------

_TARGET = "/home/kali/ctf/FlareOn26/8-crux/ext/main.wasm"


@pytest.mark.skipif(not os.path.exists(_TARGET) or not wo.node_available(),
                    reason="real Go-WASM target or node unavailable")
def test_real_go_wasm_oracle_rejects_garbage():
    r = wo.run_oracle(_TARGET, ["definitely not the flag"], export="check")
    assert r["go"] is True
    assert r["results"][0]["result"] == "Bad input"
