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


def _model_with_strings(values: list[str], imports: Optional[list[str]] = None):
    m = MagicMock()
    m.get_strings.return_value = [_StringEntry(value=v) for v in values]
    m.imports = [_ImportEntry(dll="kernel32.dll", name=n) for n in (imports or [])]
    return m


@dataclass
class _ImportEntry:
    dll: str
    name: str


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


# ------------------------ import-table based detection ----------------------
#
# On PE, anti-debug is an *imports* question: `IsDebuggerPresent` lives in the
# import directory, not in the string table, so a strings-only scan misses it
# entirely. (ELF gets away with strings because imported symbol names sit in
# .dynstr, which literally is strings — hence this gap only ever showed on PE.)


def test_scan_pe_detects_anti_debug_from_import_table():
    """The API is imported, not referenced as a string — must still be found."""
    m = _model_with_strings(["totally benign"], imports=["IsDebuggerPresent"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_anti_debug is True


def test_scan_pe_detects_output_debug_string_import():
    m = _model_with_strings([], imports=["OutputDebugStringA", "GetProcAddress"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_anti_debug is True


def test_scan_pe_detects_self_inject_from_import_table():
    m = _model_with_strings([], imports=["WriteProcessMemory", "CreateRemoteThread"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_self_inject is True


def test_scan_pe_benign_imports_do_not_trigger():
    """No false positives from an ordinary import table."""
    m = _model_with_strings([], imports=["GetProcAddress", "LoadLibraryA", "printf"])
    h = _PEHdr(sections=[_Section(name=".text")])
    p = scan_pe(m, h)
    assert p.has_anti_debug is False
    assert p.has_self_inject is False
    assert p.has_anti_vm is False


def test_scan_elf_detects_anti_debug_from_import_table():
    m = _model_with_strings([], imports=["ptrace"])
    h = _ELFHdr(sections=[_ELFSection(name=".text")])
    p = scan_elf(m, h)
    assert p.has_anti_debug is True


def test_crt_ambiguous_anti_debug_is_graded_low_confidence():
    """IsDebuggerPresent alone is CRT boilerplate — flag it, but grade it."""
    m = _model_with_strings([], imports=["IsDebuggerPresent"])
    p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
    assert p.has_anti_debug is True
    assert p.anti_debug_low_confidence is True


def test_unambiguous_anti_debug_is_full_confidence():
    """NtQueryInformationProcess has no benign CRT origin."""
    m = _model_with_strings([], imports=["NtQueryInformationProcess"])
    p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
    assert p.has_anti_debug is True
    assert p.anti_debug_low_confidence is False


def test_mixed_indicators_are_full_confidence():
    m = _model_with_strings([], imports=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"])
    p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
    assert p.anti_debug_low_confidence is False


def test_no_anti_debug_leaves_confidence_flag_unset():
    m = _model_with_strings([], imports=["GetProcAddress"])
    p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
    assert p.has_anti_debug is False
    assert p.anti_debug_low_confidence is False


def test_ptrace_does_not_match_inside_traceback():
    """Go's runtime blob contains 'ptraceback' — p + traceback, not ptrace.

    This flagged every Go binary as anti-debug.
    """
    m = _model_with_strings(["stopm holding ptraceback stuck sched"])
    p = scan_elf(m, _ELFHdr(sections=[_ELFSection(name=".text")]))
    assert p.has_anti_debug is False


def test_ptrace_still_matches_as_a_real_symbol():
    for value in ("ptrace", "ptrace(PTRACE_TRACEME)", "libc ptrace failed"):
        m = _model_with_strings([value])
        p = scan_elf(m, _ELFHdr(sections=[_ELFSection(name=".text")]))
        assert p.has_anti_debug is True, value


def test_output_debug_string_still_matches_its_a_and_w_variants():
    """The prefix needles must keep matching real Win32 import names."""
    for value in ("OutputDebugStringA", "OutputDebugStringW"):
        m = _model_with_strings([], imports=[value])
        p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
        assert p.has_anti_debug is True, value


def test_go_http_binaries_are_not_flagged_anti_debug():
    """`net/http/httptrace` is in every Go binary that speaks HTTP.

    A right-side-only boundary check let this satisfy `ptrace`; the guard
    has to hold on both sides.
    """
    for value in ("net/http/httptrace", "httptrace.ClientTrace",
                  "sys_ptrace"):  # capability name, not a call
        m = _model_with_strings([value])
        p = scan_elf(m, _ELFHdr(sections=[_ELFSection(name=".text")]))
        assert p.has_anti_debug is False, value


def test_yama_ptrace_scope_is_detected():
    """The Yama knob a debugger check reads — a real indicator, not noise.

    A boundary guard on bare `ptrace` rejects `ptrace_scope` (an `_`
    continues the identifier), so it is listed as a needle in its own right.
    """
    m = _model_with_strings(["/proc/sys/kernel/yama/ptrace_scope"])
    p = scan_elf(m, _ELFHdr(sections=[_ELFSection(name=".text")]))
    assert p.has_anti_debug is True


def test_ptrace_request_constants_are_detected():
    for value in ("PTRACE_TRACEME", "PTRACE_ATTACH"):
        m = _model_with_strings([value])
        p = scan_elf(m, _ELFHdr(sections=[_ELFSection(name=".text")]))
        assert p.has_anti_debug is True, value


def test_hypervisor_vendor_tables_are_not_anti_vm():
    """CPUID vendor-signature blobs are data, not VM detection logic."""
    for value in ("HvVMwareVMwareXenVMMXenVMM", "ACC_ENV_RUNNING_ON_QEMU"):
        m = _model_with_strings([value])
        p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
        assert p.has_anti_vm is False, value


def test_real_vm_vendor_strings_still_match():
    for value in ("VMware, Inc.", "QEMU Virtual CPU"):
        m = _model_with_strings([value])
        p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
        assert p.has_anti_vm is True, value


def test_samba_rpc_stubs_are_not_persistence():
    for value in ("ndr_print_svcctl_CreateServiceW", "CreateServiceAccount"):
        m = _model_with_strings([value])
        p = scan_pe(m, _PEHdr(sections=[_Section(name=".text")]))
        assert p.has_persistence_strings is False, value
