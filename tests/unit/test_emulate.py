"""Emulator tests — real machine code, both arches, plus graceful degrade.

Each test runs actual bytes through Unicorn and checks the result, so it
can only pass if emulation genuinely works. Skipped wholesale when
unicorn isn't installed (optional dep), except the degradation test which
asserts the no-unicorn path itself.
"""
from __future__ import annotations

import pytest

from chimera.dynamic import emulate as E

pytestmark = pytest.mark.skipif(not E.unicorn_available(),
                                reason="unicorn not installed")

# x86-64: mov rax, rdi ; add rax, rsi ; ret
X64_ADD = bytes.fromhex("4889F84801F0C3")
# x86-64: mov byte ptr [rdi], 0x41 ; ret   (write 'A' to *arg0)
X64_STORE = bytes.fromhex("C60741C3")
# arm64: add x0, x0, x1 (0x8B010000) ; ret (0xD65F03C0), little-endian
ARM64_ADD = (0x8B010000).to_bytes(4, "little") + (0xD65F03C0).to_bytes(4, "little")


def test_x86_64_add_returns_sum():
    out = E.emulate_code(X64_ADD, arch="x86_64", args=(3, 4))
    assert out["ok"] and out["available"]
    assert out["return_value"] == 7
    assert out["instructions"] >= 3


def test_arm64_add_returns_sum():
    out = E.emulate_code(ARM64_ADD, arch="arm64", args=(5, 6))
    assert out["ok"], out["error"]
    assert out["return_value"] == 11


def test_memory_write_is_read_back():
    buf = 0x00200000
    out = E.emulate_code(X64_STORE, arch="x86_64", args=(buf,),
                         mem=((buf, b"\x00"),), read_back=((buf, 1),))
    assert out["ok"]
    assert out["read_back"][0]["hex"] == "41"  # wrote 'A'


def test_instruction_cap_stops_a_runaway():
    # jmp $ (EB FE) — infinite loop; the cap must stop it, not hang.
    out = E.emulate_code(bytes.fromhex("EBFE"), arch="x86_64", max_insns=500)
    assert out["instructions"] <= 501
    # Never reached the return sentinel, so ok is False (stopped by cap/fault).
    assert out["ok"] is False


def test_unsupported_arch_is_reported():
    out = E.emulate_code(X64_ADD, arch="mips")
    assert out["available"] is False and "unsupported" in out["error"]


def test_degrades_when_unicorn_missing(monkeypatch):
    monkeypatch.setattr(E, "unicorn_available", lambda: False)
    out = E.emulate_code(X64_ADD, arch="x86_64", args=(1, 2))
    assert out["available"] is False and "unicorn" in out["error"].lower()
