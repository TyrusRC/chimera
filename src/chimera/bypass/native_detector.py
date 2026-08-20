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

# The MSVC C runtime emits `IsDebuggerPresent` and `OutputDebugString` into
# ordinary release builds (CRT init, __report_gsfailure), so finding them in
# an import table is not by itself evidence of deliberate anti-debugging —
# measured against a labeled crackme corpus, they alone produced every false
# positive. The other indicators have no such benign origin. We still report
# the hit (a missed protection costs an analyst more than a checked-and-
# dismissed one) but grade it, so nobody reads boilerplate as a finding.
_CRT_AMBIGUOUS_ANTI_DEBUG = frozenset({"IsDebuggerPresent", "OutputDebugString"})

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
    #: True when the only anti-debug evidence is an indicator the MSVC CRT
    #: emits on its own. The finding still stands, but needs confirming that
    #: the API is actually called from user code before it means anything.
    anti_debug_low_confidence: bool = False


def _string_iter(model) -> Iterable[str]:
    for s in model.get_strings():
        if hasattr(s, "value"):
            yield s.value
        elif isinstance(s, dict):
            v = s.get("value")
            if v:
                yield v


def _import_name_iter(model) -> Iterable[str]:
    """Imported symbol names, as plain strings.

    Separate from `_string_iter` because these do not live in the string
    table: on PE an import name sits in the import directory, so a
    strings-only scan cannot see `IsDebuggerPresent` at all. (ELF happens
    to work either way — its imported symbol names are in `.dynstr`, which
    is literally strings — which is why this gap only ever showed on PE.)
    """
    for imp in getattr(model, "imports", None) or []:
        name = getattr(imp, "name", None)
        if not name and isinstance(imp, dict):
            name = imp.get("name")
        if name:
            yield name


def _indicator_iter(model) -> list[str]:
    """Everything a protection indicator could hide in: strings + imports."""
    return [*_string_iter(model), *_import_name_iter(model)]


# Needles short and generic enough to appear inside unrelated words. These
# require the match not to continue into another identifier: `ptrace` was
# firing on Go's runtime string blob ("stopm holding ptraceback stuck"),
# i.e. "p" + "traceback", flagging every Go binary as anti-debug.
#
# The guard is opt-in per needle rather than global on purpose: most Win32
# needles are deliberate prefixes — `OutputDebugString` has to keep matching
# the real `OutputDebugStringA`/`W` imports — so a blanket boundary rule
# would trade this false positive for several false negatives.
_BOUNDED_NEEDLES = frozenset({"ptrace"})

_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


def _contains(haystack: str, needle: str) -> bool:
    if needle not in _BOUNDED_NEEDLES:
        return needle in haystack
    start = 0
    while True:
        i = haystack.find(needle, start)
        if i == -1:
            return False
        end = i + len(needle)
        if end >= len(haystack) or haystack[end] not in _IDENT_CHARS:
            return True
        start = i + 1


def _match_any(strings: Iterable[str], needles: Iterable[str]) -> tuple[bool, list[str]]:
    """Return (any_match, list_of_unique_hits)."""
    needle_set = set(needles)
    hits: set[str] = set()
    for s in strings:
        if not s:
            continue
        for n in needle_set:
            if _contains(s, n):
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

    # Indicator heuristics — strings *and* imported symbol names.
    strings = _indicator_iter(model)
    found, hits = _match_any(strings, _ANTI_DEBUG_STRINGS)
    profile.has_anti_debug = found
    if hits:
        profile.anti_debug_low_confidence = set(hits) <= _CRT_AMBIGUOUS_ANTI_DEBUG
        caveat = ("  (weak — the MSVC CRT emits these; confirm they are "
                  "actually called)" if profile.anti_debug_low_confidence else "")
        profile.details.append(f"anti_debug strings: {', '.join(hits)}{caveat}")
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

    strings = _indicator_iter(model)
    found, hits = _match_any(strings, _ANTI_DEBUG_STRINGS)
    profile.has_anti_debug = found
    if hits:
        profile.anti_debug_low_confidence = set(hits) <= _CRT_AMBIGUOUS_ANTI_DEBUG
        caveat = ("  (weak — the MSVC CRT emits these; confirm they are "
                  "actually called)" if profile.anti_debug_low_confidence else "")
        profile.details.append(f"anti_debug strings: {', '.join(hits)}{caveat}")
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
