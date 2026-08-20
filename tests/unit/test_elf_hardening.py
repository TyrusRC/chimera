"""ELF hardening detection: MTE/BTI/PAC notes + mitigation posture.

Covers the parsing added for the kamikaze crackme (an Android aarch64 PIE
whose whole difficulty is its MTE + seccomp + BTI/PAC hardening) and the
`detect_elf_hardening` summariser that feeds detect_protections.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from chimera.bypass.native_detector import detect_elf_hardening
from chimera.parsers.elf_header import _decode_memtag, _parse_gnu_property


@dataclass
class _FakeHeader:
    memtag: str | None = None
    pac: bool = False
    bti: bool = False
    relro: str = "none"
    nx: bool = False
    pie: bool = False


def test_decode_memtag_sync_heap_stack():
    # bits[1:0]=2 (sync), bit2 heap, bit3 stack -> 0b1110 == 0x0e
    assert _decode_memtag(b"\x0e\x00\x00\x00") == "sync+heap+stack"


def test_decode_memtag_async_only():
    # bits[1:0]=1 (async), no scope bits
    assert _decode_memtag(b"\x01\x00\x00\x00") == "async"


def test_decode_memtag_empty_is_none():
    assert _decode_memtag(b"") == "none"


def test_parse_gnu_property_sets_bti_and_pac():
    # One property: pr_type=GNU_PROPERTY_AARCH64_FEATURE_1_AND (0xc0000000),
    # pr_datasz=4, data word bit0=BTI bit1=PAC -> value 3.
    desc = (0xC0000000).to_bytes(4, "little") + (4).to_bytes(4, "little") \
        + (0b11).to_bytes(4, "little") + b"\x00\x00\x00\x00"  # pad to 8
    h = _FakeHeader()
    _parse_gnu_property(desc, h)
    assert h.bti is True and h.pac is True


def test_parse_gnu_property_bti_only():
    desc = (0xC0000000).to_bytes(4, "little") + (4).to_bytes(4, "little") \
        + (0b01).to_bytes(4, "little") + b"\x00\x00\x00\x00"
    h = _FakeHeader()
    _parse_gnu_property(desc, h)
    assert h.bti is True and h.pac is False


def test_hardening_collects_all_signals():
    h = _FakeHeader(memtag="sync+heap+stack", pac=True, bti=True,
                    relro="full", nx=True, pie=True)
    imports = ["puts", "__stack_chk_fail", "__memcpy_chk", "prctl"]
    # A seccomp allow-list filter leaves both BPF_RET instructions in the
    # image: BPF_RET|K (0x0006) then the return value.
    data = b"....." + b"\x06\x00\x00\x00" + (0x7FFF0000).to_bytes(4, "little") \
        + b"\x06\x00\x00\x00" + (0x80000000).to_bytes(4, "little") + b"....."
    hard = detect_elf_hardening(h, imports, data)
    assert hard["mte"] == "sync+heap+stack"
    assert hard["pac"] is True and hard["bti"] is True
    assert hard["relro"] == "full"
    assert hard["nx"] is True and hard["pie"] is True
    assert hard["stack_canary"] is True
    assert hard["fortify"] is True
    assert "seccomp" in hard


def test_hardening_empty_when_nothing_set():
    assert detect_elf_hardening(_FakeHeader(), []) == {}


def test_hardening_no_seccomp_without_both_return_words():
    h = _FakeHeader(pie=True)
    only_allow = b"\x06\x00\x00\x00" + (0x7FFF0000).to_bytes(4, "little")
    hard = detect_elf_hardening(h, [], only_allow)
    assert "seccomp" not in hard


def test_hardening_no_seccomp_on_bare_int_min():
    # 0x80000000 as a bare word (INT_MIN, a sign bit) is common and must NOT
    # trip the seccomp fingerprint without the surrounding BPF_RET opcode.
    h = _FakeHeader()
    data = b"\x00\x00\x00\x80" * 32 + (0x7FFF0000).to_bytes(4, "little") * 4
    assert "seccomp" not in detect_elf_hardening(h, [], data)
