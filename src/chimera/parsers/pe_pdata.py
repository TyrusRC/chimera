"""x64 function recovery from the PE `.pdata` exception directory.

For a 64-bit PE, every non-leaf function must have a RUNTIME_FUNCTION entry in
`.pdata` for stack unwinding — so `.pdata` is an authoritative lower bound on
the real function count, independent of any disassembler's call-graph walk.

This matters because a `/INCREMENTAL`-linked MSVC binary routes every internal
call through an Incremental Link Table (ILT) of `jmp` thunks; r2's `aaa` does
not chase that indirection at scale and silently reports roughly the *import*
count instead of the thousands of real functions. Cross-checking against
`.pdata` catches that, and `resolve_thunk` follows an ILT entry to its target.

Pure and read-only: `parse_pdata_entries` works on raw bytes; the thin
`runtime_functions` wrapper reads the section via `pefile`.
"""
from __future__ import annotations

import struct

_RUNTIME_FUNCTION = struct.Struct("<III")  # BeginAddress, EndAddress, UnwindInfoAddress (RVAs)
_JMP_REL32 = 0xE9


def parse_pdata_entries(pdata: bytes, image_base: int) -> list[dict]:
    """Parse RUNTIME_FUNCTION rows into absolute function ranges.

    Zero rows (link-time padding) and any trailing partial row are ignored.
    """
    out: list[dict] = []
    n = len(pdata) // _RUNTIME_FUNCTION.size
    for i in range(n):
        begin, end, unwind = _RUNTIME_FUNCTION.unpack_from(pdata, i * _RUNTIME_FUNCTION.size)
        if begin == 0 and end == 0:
            continue
        out.append({
            "start": image_base + begin,
            "end": image_base + end,
            "start_rva": begin,
            "end_rva": end,
            "unwind_rva": unwind,
        })
    return out


def resolve_thunk(code5: bytes, va: int) -> int | None:
    """If `code5` begins a 5-byte `jmp rel32` ILT thunk, return its target VA."""
    if len(code5) < 5 or code5[0] != _JMP_REL32:
        return None
    (rel,) = struct.unpack_from("<i", code5, 1)
    return (va + 5 + rel) & 0xFFFFFFFFFFFFFFFF


def count_looks_bogus(r2_count: int, import_count: int, pdata_count: int) -> bool:
    """True when a disassembler's function count is untrustworthy.

    The tell is a count that barely exceeds the import count (it found imports
    and little else) while `.pdata` proves there are many times more real
    functions — the classic ILT-defeated call-graph walk.
    """
    if pdata_count <= 0:
        return False
    return r2_count <= import_count + 4 and pdata_count >= 4 * max(r2_count, 1)


def runtime_functions(path) -> list[dict]:
    """Function ranges from a PE64's `.pdata`, or [] if absent/unparseable."""
    try:
        import pefile  # noqa: PLC0415
        pe = pefile.PE(str(path), fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            if s.Name.rstrip(b"\x00") == b".pdata":
                data = s.get_data()
                pe.close()
                return parse_pdata_entries(data, image_base)
        pe.close()
    except Exception:
        return []
    return []
