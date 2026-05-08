"""Native (PE/ELF) protection detection.

Sibling to mobile `bypass/detector.py`. Keeps mobile and native regex
tables separate so each path stays narrow.

The profile this produces is summary-grade: booleans plus light counters.
Detail (per-import bucket, per-string evidence) is in the matched
imports' bucket field and in the persistence-scanner output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


_ANTI_DEBUG_STRINGS = (
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "ZwQueryInformationProcess",
    "OutputDebugString",
    # Linux
    "ptrace", "PT_TRACE_ME",
)

_ANTI_VM_STRINGS = (
    "VBoxGuest", "VBoxService", "VirtualBox",
    "VMware", "vmtoolsd", "vmci",
    "QEMU", "Hyper-V", "XenSource",
    "VirtualPC",
)

_SELF_INJECT_STRINGS = (
    # PE
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtMapViewOfSection", "RtlCreateUserThread", "QueueUserAPC",
    # Linux
    "process_vm_writev", "process_vm_readv",
)

_PERSISTENCE_STRINGS = (
    # PE
    "CurrentVersion\\Run", "RegSetValueExA", "RegSetValueExW",
    "ScheduleTaskCreate", "CreateServiceA", "CreateServiceW",
    # Linux
    "/etc/cron", "/etc/systemd/system", "/etc/ld.so.preload",
    "LD_PRELOAD", "@reboot",
)

# PE section-name → packer hint
_PE_SECTION_PACKER = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    ".enigma1": "Enigma Protector", ".enigma2": "Enigma Protector",
}

# ELF section-name → packer hint
_ELF_SECTION_PACKER = {
    ".UPX": "UPX",
}


@dataclass
class NativeProtectionProfile:
    packer: str | None = None
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    has_self_inject: bool = False
    has_persistence_strings: bool = False
    obfuscation: list[str] = field(default_factory=list)
    syscall_buckets: dict[str, int] = field(default_factory=dict)
    details: list[str] = field(default_factory=list)
    high_entropy_section_count: int = 0


def _string_iter(model) -> Iterable[str]:
    for s in model.get_strings():
        if hasattr(s, "value"):
            yield s.value
        elif isinstance(s, dict):
            v = s.get("value")
            if v:
                yield v


def _match_any(strings: Iterable[str], needles: Iterable[str]) -> tuple[bool, list[str]]:
    """Return (any_match, list_of_unique_hits)."""
    needle_set = set(needles)
    hits: set[str] = set()
    for s in strings:
        if not s:
            continue
        for n in needle_set:
            if n in s:
                hits.add(n)
        if len(hits) == len(needle_set):
            break
    return bool(hits), sorted(hits)


def scan_pe(model, header) -> NativeProtectionProfile:
    """Detect Windows PE protections.

    `header` is a `PEHeaderInfo` from `parsers.pe_header`.
    """
    profile = NativeProtectionProfile()

    # Section-name packer hints
    for sec in header.sections:
        if sec.name in _PE_SECTION_PACKER:
            profile.packer = _PE_SECTION_PACKER[sec.name]
            profile.details.append(f"section={sec.name} → {profile.packer}")
            break

    # High-entropy code sections (entropy > 7.0 = packed/encrypted hint)
    for sec in header.sections:
        if sec.entropy > 7.0:
            profile.high_entropy_section_count += 1
            profile.details.append(f"high entropy {sec.entropy:.2f} in {sec.name}")

    # String-based heuristics
    strings = list(_string_iter(model))
    found, hits = _match_any(strings, _ANTI_DEBUG_STRINGS)
    profile.has_anti_debug = found
    if hits:
        profile.details.append(f"anti_debug strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _ANTI_VM_STRINGS)
    profile.has_anti_vm = found
    if hits:
        profile.details.append(f"anti_vm strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _SELF_INJECT_STRINGS)
    profile.has_self_inject = found
    if hits:
        profile.details.append(f"self_inject strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _PERSISTENCE_STRINGS)
    profile.has_persistence_strings = found
    if hits:
        profile.details.append(f"persistence strings: {', '.join(hits)}")

    return profile


def scan_elf(model, header) -> NativeProtectionProfile:
    """Detect Linux ELF protections."""
    profile = NativeProtectionProfile()

    # Section-name packer hint
    for sec in header.sections:
        if sec.name in _ELF_SECTION_PACKER:
            profile.packer = _ELF_SECTION_PACKER[sec.name]
            profile.details.append(f"section={sec.name} → {profile.packer}")
            break

    # ELF doesn't expose section entropy via pyelftools directly; skip
    # entropy here (pe_header has it; elf_header could add it later).

    strings = list(_string_iter(model))
    found, hits = _match_any(strings, _ANTI_DEBUG_STRINGS)
    profile.has_anti_debug = found
    if hits:
        profile.details.append(f"anti_debug strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _ANTI_VM_STRINGS)
    profile.has_anti_vm = found
    if hits:
        profile.details.append(f"anti_vm strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _SELF_INJECT_STRINGS)
    profile.has_self_inject = found
    if hits:
        profile.details.append(f"self_inject strings: {', '.join(hits)}")
    found, hits = _match_any(strings, _PERSISTENCE_STRINGS)
    profile.has_persistence_strings = found
    if hits:
        profile.details.append(f"persistence strings: {', '.join(hits)}")

    return profile
