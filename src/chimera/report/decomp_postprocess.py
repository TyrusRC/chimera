"""Decompiler-output readability lifter.

Ghidra and r2 emit C that is *correct* but noisy: hex addresses where
string literals should be, ``FUN_140001000`` instead of recovered names,
``iVar1`` / ``uVar2`` placeholders, mangled C++ symbols, unresolved
import jumps. This module rewrites that output using the enrichment the
rest of Chimera has already collected — the `UnifiedProgramModel`'s
strings/imports/functions tables, plus any analyst overlay.

The goal isn't to match Hex-Rays cell-for-cell; it's to close the
readability gap so a triage pass against a Ghidra-decompiled function
reads like the kind of pseudo-C Hex-Rays would print.

Each pass is conservative — it only rewrites tokens we are confident
about, and never invents semantics. Order matters: address substitution
must run before function-name substitution because Ghidra spells some
function pointers ``DAT_<addr>`` and some ``FUN_<addr>``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from chimera.core.overlay import ProjectOverlay, _normalize_addr
from chimera.model.program import UnifiedProgramModel

logger = logging.getLogger(__name__)

# Ghidra-emitted placeholders.
#   DAT_<hex>  — addressable data (often a string literal)
#   PTR_<hex>  — pointer constant (often into the IAT for PE)
#   FUN_<hex>  — function with no symbol
#   LAB_<hex>  — label inside a function
#   UNK_<hex>  — unidentified
_GHIDRA_REF_RE = re.compile(r"\b(DAT|PTR|FUN|LAB|UNK)_([0-9a-fA-F]{6,16})\b")

# Ghidra's local-variable placeholders. Suffix is the slot index.
#   iVar1   signed-int locals
#   uVar1   unsigned-int locals
#   lVar1   long locals
#   pcVar1  pointer-to-char locals
#   pvVar1  pointer-to-void locals
#   pbVar1  pointer-to-byte locals
_GHIDRA_LOCAL_RE = re.compile(
    r"\b(i|u|l|s|b|p[cvb]?)Var(\d+)\b"
)
_LOCAL_PRETTY = {
    "i": "i", "u": "u", "l": "l", "s": "s", "b": "b",
    "pc": "pstr", "pv": "p", "pb": "pbuf",
}

# C++ mangled name (Itanium ABI). Recognised cheaply so we know what to feed
# c++filt; the actual demangle uses the cxxfilt module or falls back to a
# subprocess.
_CPP_MANGLED_RE = re.compile(r"\b_Z[A-Za-z0-9_$.]+\b")

# Well-known x86/x64 magic constants worth labelling. Restricted to ones
# that are unambiguous in *any* context to avoid rewriting application
# constants that just happen to collide.
_KNOWN_CONSTANTS: dict[str, str] = {
    "0xdeadbeef":  "DEADBEEF_SENTINEL",
    "0xcafebabe":  "JAVA_CLASS_MAGIC",
    "0xfeedface":  "MACHO_MAGIC_32",
    "0xfeedfacf":  "MACHO_MAGIC_64",
    "0x4d5a":      "MZ_MAGIC",          # PE
    "0x464c457f":  "ELF_MAGIC",         # 0x7f 'E' 'L' 'F' little-endian
    "0x90909090":  "NOP_SLED_x4",
    "0xcccccccc":  "INT3_FILL",
    "0xffffffff":  "MINUS_ONE_u32",
    # errno-family values left out — too many false positives in real code.
}

# Demangled-name cache so repeated rewrites of the same C++ symbol don't
# fork c++filt every pass.
_DEMANGLE_CACHE: dict[str, str] = {}


def _demangle(symbol: str) -> Optional[str]:
    """Best-effort C++ demangle. None on failure (caller keeps the original)."""
    if symbol in _DEMANGLE_CACHE:
        return _DEMANGLE_CACHE[symbol] or None
    # Prefer the cxxfilt module when present — it's a libstdc++ binding so
    # there's no subprocess overhead per symbol.
    try:
        import cxxfilt  # type: ignore
        result = cxxfilt.demangle(symbol)
    except ImportError:
        result = _demangle_via_subprocess(symbol)
    except Exception as exc:
        logger.debug("cxxfilt demangle failed for %s: %s", symbol, exc)
        result = None
    _DEMANGLE_CACHE[symbol] = result or ""
    return result or None


def _demangle_via_subprocess(symbol: str) -> Optional[str]:
    """Slow path: c++filt(1) subprocess. Cached so it only fires once per name."""
    import shutil
    import subprocess
    binary = shutil.which("c++filt") or shutil.which("c++filt-15")
    if not binary:
        return None
    try:
        out = subprocess.run(
            [binary, symbol], capture_output=True, text=True, timeout=2, check=False,
        )
        demangled = (out.stdout or "").strip()
        return demangled if demangled and demangled != symbol else None
    except (OSError, subprocess.TimeoutExpired):
        return None


@dataclass
class PostProcessResult:
    code: str
    substitutions: int       # how many tokens we rewrote
    inserted_strings: int    # of which, how many were inline string literals
    inserted_names: int      # of which, how many were function-name renames


def post_process(
    raw: str,
    model: UnifiedProgramModel,
    function_addr: str,
    overlay: Optional[ProjectOverlay] = None,
) -> PostProcessResult:
    """Apply enrichment passes to the raw decompiler output.

    `raw` may be Ghidra's C, r2's `pdc`, or anything else with similar
    placeholder conventions. Passes that don't recognise their patterns
    silently no-op, so feeding clean code is safe — the result is just
    identical to the input.
    """
    if not raw:
        return PostProcessResult(raw or "", 0, 0, 0)

    overlay = overlay or ProjectOverlay(sha256=model.binary.sha256)

    # ---- pre-compute lookup tables once per call ----
    string_by_addr: dict[str, str] = {}
    for s in model.get_strings():
        key = _normalize_addr(s.address)
        # Cap the inlined literal so we don't blow up the function body if
        # someone hits a 4 KB constant pool entry.
        text = s.value if len(s.value) <= 80 else (s.value[:77] + "...")
        string_by_addr[key] = text

    import_by_addr: dict[str, tuple[str, Optional[str]]] = {}
    for imp in model.imports:
        if not imp.address:
            continue
        import_by_addr[_normalize_addr(imp.address)] = (imp.name, imp.dll or None)

    func_by_addr: dict[str, str] = {}
    for f in model.functions:
        func_by_addr[_normalize_addr(f.address)] = f.name

    inserted_strings = 0
    inserted_names = 0
    substitutions = 0

    # ---- pass 1: Ghidra-style DAT/PTR/FUN/LAB/UNK rewrites ----

    def _ref_sub(match: re.Match[str]) -> str:
        nonlocal inserted_strings, inserted_names, substitutions
        kind, raw_addr = match.group(1), match.group(2)
        addr = _normalize_addr("0x" + raw_addr)

        if kind == "DAT":
            if addr in string_by_addr:
                substitutions += 1
                inserted_strings += 1
                return _c_string_literal(string_by_addr[addr])
            return match.group(0)

        if kind == "PTR":
            if addr in import_by_addr:
                substitutions += 1
                name, dll = import_by_addr[addr]
                return f"{dll}!{name}" if dll else name
            if addr in func_by_addr:
                substitutions += 1
                inserted_names += 1
                return func_by_addr[addr]
            return match.group(0)

        if kind == "FUN":
            candidate = func_by_addr.get(addr)
            # Skip if there's no candidate, or if the candidate is still a
            # FUN_<addr> placeholder — substituting one placeholder for
            # another (just zero-padded differently) is noise.
            if candidate and not candidate.startswith("FUN_"):
                substitutions += 1
                inserted_names += 1
                return candidate
            return match.group(0)

        # LAB_ / UNK_ — leave intact; they're meaningful as anchors.
        return match.group(0)

    code = _GHIDRA_REF_RE.sub(_ref_sub, raw)

    # ---- pass 2: variable rename via overlay ----
    var_renames = overlay.get_variable_renames(function_addr)
    if var_renames:
        for old, new in var_renames.items():
            # Whole-word so we don't rewrite substrings inside other identifiers.
            pattern = re.compile(rf"\b{re.escape(old)}\b")
            new_code, count = pattern.subn(new, code)
            if count:
                substitutions += count
                code = new_code

    # ---- pass 3: iVar1 / uVar2 / pcVar3 → typed friendly names ----
    def _local_sub(match: re.Match[str]) -> str:
        nonlocal substitutions
        prefix, idx = match.group(1), match.group(2)
        kind = _LOCAL_PRETTY.get(prefix, prefix)
        substitutions += 1
        return f"{kind}{idx}"
    code = _GHIDRA_LOCAL_RE.sub(_local_sub, code)

    # ---- pass 4: C++ demangling ----
    seen: set[str] = set()
    for sym in _CPP_MANGLED_RE.findall(code):
        if sym in seen:
            continue
        seen.add(sym)
        demangled = _demangle(sym)
        if demangled and demangled != sym:
            code = code.replace(sym, demangled)
            substitutions += 1

    # ---- pass 5: well-known magic constants ----
    for hex_value, label in _KNOWN_CONSTANTS.items():
        # Case-insensitive match on the literal; only the exact form survives
        # so `0xDEADBEEF` and `0xdeadbeef` both become `DEADBEEF_SENTINEL`.
        pattern = re.compile(rf"\b{hex_value}\b", re.IGNORECASE)
        new_code, count = pattern.subn(label, code)
        if count:
            code = new_code
            substitutions += count

    # ---- pass 6: prepend the analyst's "global" comment as a banner ----
    comments = overlay.get_comments(function_addr)
    line_zero = comments.get("0") or comments.get(0)  # tolerant of both key types
    if line_zero:
        code = f"// {line_zero}\n{code}"

    return PostProcessResult(
        code=code,
        substitutions=substitutions,
        inserted_strings=inserted_strings,
        inserted_names=inserted_names,
    )


def _c_string_literal(text: str) -> str:
    """Quote like a C string literal, escaping the few characters that matter."""
    escaped = (
        text.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'
