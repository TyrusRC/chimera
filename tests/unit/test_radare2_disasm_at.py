"""Raw disassembly-at-address (radare2 `disasm_at` mode).

Backs the get_disassembly/get_function fallback that lets an analyst reach a
symbol-less address (an .init_array constructor, an xref) in a stripped
binary — the case the kamikaze crackme exposed.
"""
from __future__ import annotations

import json

from chimera.adapters.radare2 import Radare2Adapter


class _FakeR2:
    """Duck-typed r2pipe: canned JSON per command substring."""

    def __init__(self, responses: dict[str, str]):
        self._responses = responses
        self.commands: list[str] = []

    def cmd(self, cmd: str) -> str:
        self.commands.append(cmd)
        for key, val in self._responses.items():
            if key in cmd:
                return val
        return ""


def test_disasm_at_uses_pdfj_addr_key():
    ops = {"name": "fcn.0009b4",
           "ops": [{"addr": 0x9B4, "disasm": "paciasp", "bytes": "3f2303d5"},
                   {"addr": 0x9B8, "disasm": "str x30, [x18], 8", "bytes": "50c39fd8"}]}
    r2 = _FakeR2({"pdfj": json.dumps(ops)})
    out = Radare2Adapter()._disasm_at(r2, {"address": "0x9b4"})
    assert out["ok"] and out["instruction_count"] == 2
    # "addr" key is honoured (this r2 build has no "offset").
    assert out["instructions"][0]["offset"] == "0x9b4"
    assert out["instructions"][1]["disasm"] == "str x30, [x18], 8"


def test_disasm_at_falls_back_to_pdj_when_pdfj_empty():
    # af declined / mid-function: pdfj returns no ops -> linear pdj is used.
    lin = [{"offset": 0xA6C, "disasm": "paciasp"},
           {"offset": 0xA70, "disasm": "ret"}]
    r2 = _FakeR2({"pdfj": json.dumps({"ops": []}), "pdj": json.dumps(lin)})
    out = Radare2Adapter()._disasm_at(r2, {"address": "0xa6c"})
    assert out["ok"] and out["instruction_count"] == 2
    assert out["instructions"][0]["offset"] == "0xa6c"
    assert any("pdj" in c for c in r2.commands)


def test_disasm_at_requires_address():
    out = Radare2Adapter()._disasm_at(_FakeR2({}), {})
    assert out["ok"] is False


def test_disasm_at_rejects_all_invalid_ops():
    # Unmapped / non-code address: r2 returns a run of `invalid` ops. The
    # adapter must reject it so a bad address reports not-found, not garbage.
    ops = {"ops": [{"addr": 0xDEADBEEF, "disasm": "invalid", "bytes": "ffffffff"},
                   {"addr": 0xDEADBEF4, "disasm": "invalid", "bytes": "ffffffff"}]}
    r2 = _FakeR2({"pdfj": json.dumps(ops), "pdj": json.dumps(ops["ops"])})
    out = Radare2Adapter()._disasm_at(r2, {"address": "0xdeadbeef"})
    assert out["ok"] is False and "no valid instructions" in out["error"]
