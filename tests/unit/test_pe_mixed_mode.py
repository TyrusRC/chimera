"""Mixed-mode (C++/CLI) .NET detection from the COR20 header flags (à la mode)."""
from __future__ import annotations

import struct

from chimera.parsers.pe_header import _parse_cor20_flags

_CLR_RVA = 0x2000
_CLR_OFF = 0x400


class _Dir:
    def __init__(self, va):
        self.VirtualAddress = va


class _FakePE:
    """Minimal stand-in exposing the two bits _parse_cor20_flags uses."""

    def __init__(self, cor20: bytes):
        self.__data__ = b"\x00" * _CLR_OFF + cor20

    def get_offset_from_rva(self, rva):
        assert rva == _CLR_RVA
        return _CLR_OFF


def _cor20(flags: int, entry: int = 0x1163) -> bytes:
    # cb, MajorRV, MinorRV, MetaData(rva,size), Flags@16, EntryPoint@20
    return struct.pack("<IHHIIII", 0x48, 2, 5, 0x3000, 0x100, flags, entry) + b"\x00" * 24


def test_il_only_is_not_mixed_mode():
    mixed, rva = _parse_cor20_flags(_FakePE(_cor20(0x0001)), _Dir(_CLR_RVA))  # ILONLY
    assert mixed is False and rva is None


def test_native_entrypoint_is_mixed_mode_with_rva():
    # ILONLY clear + NATIVE_ENTRYPOINT set → mixed-mode, EntryPoint is a native RVA
    mixed, rva = _parse_cor20_flags(_FakePE(_cor20(0x0010, entry=0x1163)), _Dir(_CLR_RVA))
    assert mixed is True and rva == 0x1163


def test_mixed_without_native_flag_reports_no_rva():
    # ILONLY clear but NATIVE_ENTRYPOINT clear (e.g. 32BITREQUIRED only)
    mixed, rva = _parse_cor20_flags(_FakePE(_cor20(0x0002)), _Dir(_CLR_RVA))
    assert mixed is True and rva is None


def test_unreadable_cor20_degrades():
    class _BadPE:
        __data__ = b""

        def get_offset_from_rva(self, rva):
            raise ValueError("bad rva")

    assert _parse_cor20_flags(_BadPE(), _Dir(_CLR_RVA)) == (False, None)
