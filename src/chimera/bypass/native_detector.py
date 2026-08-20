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
    # Listed in their own right because a boundary guard on bare `ptrace`
    # would reject them: an `_` continues the identifier.
    "PTRACE_TRACEME", "PTRACE_ATTACH", "ptrace_scope",
    "ptrace", "PT_TRACE_ME",
)

# The MSVC C runtime emits these into ordinary release builds, so finding
# them is not by itself evidence of deliberate anti-debugging. Reported, but
# graded, so boilerplate is not read as a finding.
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
    #: Exploit-mitigation / hardening posture (ELF only). Keys present only
    #: for a signal that fired: mte, pac, bti, stack_canary, fortify, relro,
    #: nx, pie, seccomp. See `detect_elf_hardening`.
    hardening: dict = field(default_factory=dict)
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


# Needles short or generic enough to appear inside unrelated identifiers;
# these must match as a standalone token on both sides. Observed collisions:
# `ptrace` in `net/http/httptrace` and `sys_ptrace`; `VMware`/`QEMU` in CPUID
# vendor tables; `CreateServiceA/W` in Kubernetes and Samba symbol names.
#
# Opt-in per needle because several Win32 needles are deliberate prefixes —
# `OutputDebugString` must keep matching `OutputDebugStringA`/`W`.
_BOUNDED_NEEDLES = frozenset({"ptrace", "QEMU", "VMware",
                              "CreateServiceA", "CreateServiceW"})

_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


def _contains(haystack: str, needle: str) -> bool:
    """Substring test, with an identifier-boundary guard for short needles.

    The guard is *bidirectional*. A right-side-only check still let
    `httptrace` — present in every Go binary that speaks HTTP — satisfy
    `ptrace`, and `sys_ptrace` (the Linux capability name, not a call)
    do the same from the left.
    """
    if needle not in _BOUNDED_NEEDLES:
        return needle in haystack
    start = 0
    while True:
        i = haystack.find(needle, start)
        if i == -1:
            return False
        end = i + len(needle)
        left_ok = i == 0 or haystack[i - 1] not in _IDENT_CHARS
        right_ok = end >= len(haystack) or haystack[end] not in _IDENT_CHARS
        if left_ok and right_ok:
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


# A classic seccomp allow-list filter ends in two BPF return instructions:
# SECCOMP_RET_ALLOW (0x7fff0000) and SECCOMP_RET_KILL_PROCESS (0x80000000).
# Match the *whole* 8-byte sock_filter for each — BPF_RET|K (code=0x0006,
# jt=0, jf=0) followed by the little-endian return value — not just the bare
# 4-byte `k`. `0x80000000` alone is a common word (INT_MIN, a sign bit); the
# full `\x06\x00\x00\x00\x00\x00\x00\x80` instruction is not, so this keeps
# the fingerprint specific enough to avoid false positives.
# sock_filter is {u16 code, u8 jt, u8 jf, u32 k} little-endian. BPF_RET|K is
# code=0x0006, jt=jf=0; then the 4-byte return value.
_SECCOMP_RET_ALLOW = b"\x06\x00\x00\x00" + (0x7FFF0000).to_bytes(4, "little")
_SECCOMP_RET_KILL = b"\x06\x00\x00\x00" + (0x80000000).to_bytes(4, "little")


def detect_elf_hardening(header, import_names: Iterable[str],
                         data: bytes | None = None) -> dict:
    """Summarise an ELF's exploit-mitigation posture.

    Reads structural facts already parsed into `header` (RELRO/NX/PIE and the
    ARM MTE/BTI/PAC notes), plus imported-symbol tells (`__stack_chk_fail`
    for the stack canary, any `__*_chk` for FORTIFY_SOURCE), and — when raw
    `data` is supplied — a seccomp allow-list filter fingerprint. Only keys
    for signals that actually fired are returned, so an empty dict means "no
    notable hardening seen".
    """
    names = set(import_names or ())
    h: dict = {}
    if getattr(header, "memtag", None):
        h["mte"] = header.memtag                 # e.g. "sync+heap+stack"
    if getattr(header, "pac", False):
        h["pac"] = True
    if getattr(header, "bti", False):
        h["bti"] = True
    relro = getattr(header, "relro", "none")
    if relro and relro != "none":
        h["relro"] = relro                       # "partial" | "full"
    if getattr(header, "nx", False):
        h["nx"] = True
    if getattr(header, "pie", False):
        h["pie"] = True
    if "__stack_chk_fail" in names:
        h["stack_canary"] = True
    if any(n.endswith("_chk") for n in names):
        h["fortify"] = True
    if data and _SECCOMP_RET_ALLOW in data and _SECCOMP_RET_KILL in data:
        h["seccomp"] = "allowlist (kill on violation)"
    return h


def render_hardening(hardening: dict) -> str:
    """One-line human rendering of a `detect_elf_hardening` dict.

    Boolean signals show as a bare name (`pie`); valued ones as `key=value`
    (`mte=sync+heap+stack`). Shared by the detector's details line and the
    detect-protections CLI so the two never drift.
    """
    return ", ".join(f"{k}={v}" if v is not True else k
                     for k, v in hardening.items())


def scan_elf(model, header, data: bytes | None = None) -> NativeProtectionProfile:
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

    profile.hardening = detect_elf_hardening(
        header, list(_import_name_iter(model)), data)
    if profile.hardening:
        profile.details.append("hardening: " + render_hardening(profile.hardening))

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
