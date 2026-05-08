"""Unit tests for the PE/ELF native protection detector."""
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock

import pytest

from chimera.bypass.native_detector import (
    NativeProtectionProfile, scan_pe, scan_elf,
)


@dataclass
class _StringEntry:
    value: str
    address: str = "0x1000"
    section: Optional[str] = None


@dataclass
class _Section:
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    characteristics: int = 0
    entropy: float = 0.0
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = False


@dataclass
class _PEHdr:
    sections: list  # list[_Section]


@dataclass
class _ELFSection:
    name: str
    size: int = 0
    flags: int = 0
    is_executable: bool = False
    is_writable: bool = False


@dataclass
class _ELFHdr:
    sections: list


def _model_with_strings(values: list[str]):
    m = MagicMock()
    m.get_strings.return_value = [_StringEntry(value=v) for v in values]
    return m


def test_scan_pe_clean_binary():
    m = _model_with_strings(["hello world"])
    h = _PEHdr(sections=[_Section(name=".text"), _Section(name=".data")])
    p = scan_pe(m, h)
    assert p.packer is None
    assert p.has_anti_debug is False
    assert p.has_anti_vm is False
    assert p.high_entropy_section_count == 0


def test_scan_pe_detects_upx_via_section_name():
    m = _model_with_strings([])
    h = _PEHdr(sections=[_Section(name="UPX0"), _Section(name="UPX1")])
    p = scan_pe(m, h)
    assert p.packer == "UPX"


def test_scan_pe_detects_vmprotect_via_section_name():
    m = _model_with_strings([])
    h = _PEHdr(sections=[_Section(name=".vmp0"), _Section(name=".vmp1")])
    p = scan_pe(m, h)
    assert p.packer == "VMProtect"


def test_scan_pe_detects_anti_debug_strings():
    m = _model_with_strings([
        "blob_with_IsDebuggerPresent_inside",
        "another_with_OutputDebugStringA",
    ])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_anti_debug is True


def test_scan_pe_detects_anti_vm_strings():
    m = _model_with_strings(["hello VBoxGuest world", "vmtoolsd path"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_anti_vm is True


def test_scan_pe_detects_self_inject():
    m = _model_with_strings(["VirtualAllocEx_pointer", "CreateRemoteThread"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_self_inject is True


def test_scan_pe_detects_persistence():
    m = _model_with_strings(["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_persistence_strings is True


def test_scan_pe_high_entropy_sections():
    m = _model_with_strings([])
    h = _PEHdr(sections=[
        _Section(name=".text", entropy=7.5),
        _Section(name=".data", entropy=3.0),
        _Section(name=".rdata", entropy=7.8),
    ])
    p = scan_pe(m, h)
    assert p.high_entropy_section_count == 2


def test_scan_elf_detects_upx_section():
    m = _model_with_strings([])
    h = _ELFHdr(sections=[_ELFSection(name=".UPX")])
    p = scan_elf(m, h)
    assert p.packer == "UPX"


def test_scan_elf_detects_persistence_strings():
    m = _model_with_strings(["/etc/systemd/system/x.service"])
    h = _ELFHdr(sections=[_ELFSection(name=".text")])
    p = scan_elf(m, h)
    assert p.has_persistence_strings is True


def test_scan_elf_detects_ld_preload():
    m = _model_with_strings(["LD_PRELOAD=/tmp/x.so"])
    h = _ELFHdr(sections=[_ELFSection(name=".text")])
    p = scan_elf(m, h)
    assert p.has_persistence_strings is True


def test_scan_elf_detects_ptrace_anti_debug():
    m = _model_with_strings(["call to ptrace failed"])
    h = _ELFHdr(sections=[_ELFSection(name=".text")])
    p = scan_elf(m, h)
    assert p.has_anti_debug is True


def test_scan_pe_combined_signals():
    m = _model_with_strings([
        "IsDebuggerPresent_path",
        "VirtualBox sneaky check",
        "WriteProcessMemory call",
        "CurrentVersion\\Run key",
    ])
    h = _PEHdr(sections=[
        _Section(name=".vmp0"),
        _Section(name=".text", entropy=7.9),
    ])
    p = scan_pe(m, h)
    assert p.packer == "VMProtect"
    assert p.has_anti_debug is True
    assert p.has_anti_vm is True
    assert p.has_self_inject is True
    assert p.has_persistence_strings is True
    assert p.high_entropy_section_count >= 1
    # Details should accumulate
    assert len(p.details) >= 5
