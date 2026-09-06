"""Dispatch / jump-table recovery for PE binaries.

Generated code — state machines, VM interpreters, coroutine lowerings — usually
dispatches through an *array of code pointers*: either absolute VAs (8 bytes on
x64) or RVAs (4 bytes) sitting in `.rdata`/`.data`, one slot per handler. Finding
that array recovers the handler/state count and the address of every handler in
one shot, which is exactly the shape a disassembler's call-graph walk misses on
an ILT-heavy binary (see `pe_pdata`). ntfsm's 90781-entry STATES table is the
canonical example.

The trick that keeps this from drowning in false positives: only accept a run of
pointers where *every* entry lands on real code — an executable section. (An
earlier design validated against `.pdata` function starts, but a *generated*
state machine's handlers are exactly the ones missing from `.pdata` — ntfsm's
STATES entries point into `.text` at addresses that are not `.pdata` functions —
so an executable-range check is what actually catches this case. `.pdata` starts
remain available as a stricter, higher-confidence predicate for callers.)

`scan_pointer_arrays` is pure and works on raw bytes; the `find_dispatch_tables`
wrapper reads sections via `pefile`. Read-only; never raises on a bad file.
"""
from __future__ import annotations

import logging
import struct

logger = logging.getLogger(__name__)

_MASK64 = 0xFFFFFFFFFFFFFFFF


def scan_pointer_arrays(
    data: bytes,
    base_va: int,
    valid_targets,
    *,
    ptr_size: int = 8,
    is_rva: bool = False,
    image_base: int = 0,
    min_run: int = 8,
) -> list[dict]:
    """Find maximal runs of consecutive pointers that all hit `valid_targets`.

    `data` is a section's bytes; `base_va` is the VA of `data[0]`. Entries are
    read little-endian at `ptr_size`-aligned offsets. A stored value `v` maps to
    a target VA of `image_base + v` when `is_rva` else `v` directly. A run is a
    maximal span of >= `min_run` consecutive entries whose mapped target passes
    `valid_targets` (STRICT: one miss ends the run). One dict per run:

        {"offset", "base_va", "count", "ptr_size", "kind"}

    `valid_targets` is either a set/container (membership test) or a callable
    predicate `va -> bool` — the latter lets a caller pass a range check ("lands
    in an executable section") instead of an enormous set.

    NOTE: scans only at ptr_size-aligned offsets (arrays are aligned in
    practice) — an intentionally mis-aligned table would be missed. O(n).
    """
    check = valid_targets if callable(valid_targets) else valid_targets.__contains__
    fmt = "<Q" if ptr_size == 8 else "<I"
    unpack = struct.Struct(fmt).unpack_from
    out: list[dict] = []
    n_entries = len(data) // ptr_size

    run_start: int | None = None  # entry index where the current run began
    i = 0
    while i < n_entries:
        (v,) = unpack(data, i * ptr_size)
        target = (image_base + v) & _MASK64 if is_rva else v
        if check(target):
            if run_start is None:
                run_start = i
        else:
            if run_start is not None:
                _emit(out, data, base_va, run_start, i, ptr_size, is_rva, min_run)
                run_start = None
        i += 1
    if run_start is not None:
        _emit(out, data, base_va, run_start, n_entries, ptr_size, is_rva, min_run)
    return out


def _emit(out, data, base_va, start_idx, end_idx, ptr_size, is_rva, min_run):
    count = end_idx - start_idx
    if count < min_run:
        return
    offset = start_idx * ptr_size
    out.append({
        "offset": offset,
        "base_va": base_va + offset,
        "count": count,
        "ptr_size": ptr_size,
        "kind": "rva" if is_rva else "va",
    })


def find_dispatch_tables(path, *, min_run: int = 8) -> list[dict]:
    """Recover candidate dispatch tables from a PE.

    Scans `.rdata`, `.data`, and `.text` for both 8-byte absolute-VA arrays and
    4-byte RVA arrays whose every entry points into an executable section — the
    signal that catches a generated state machine even when its handlers are
    absent from `.pdata` (ntfsm's 90781-entry STATES array lives in `.text` and
    points at non-`.pdata` handlers). Each result carries a `"section"` name and
    `"pdata_backed"` (True when every entry is also a `.pdata` function start —
    higher confidence). Sorted by `count` descending (biggest table first).
    Returns [] if `pefile` is missing or the PE can't be parsed.
    """
    try:
        import pefile  # noqa: PLC0415
        from chimera.parsers.pe_pdata import runtime_functions  # noqa: PLC0415
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return []
    try:
        image_base = pe.OPTIONAL_HEADER.ImageBase
        # executable-section VA ranges — the validator
        exec_ranges: list[tuple[int, int]] = []
        for s in pe.sections:
            if s.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                lo = image_base + s.VirtualAddress
                exec_ranges.append((lo, lo + max(s.Misc_VirtualSize, s.SizeOfRawData)))
        if not exec_ranges:
            return []

        def in_exec(va: int) -> bool:
            return any(lo <= va < hi for lo, hi in exec_ranges)

        # .pdata starts, only to *tag* confidence (not to gate discovery)
        try:
            pdata_starts = {f["start"] for f in runtime_functions(path)}
        except Exception:
            pdata_starts = set()

        wanted = (b".rdata", b".data", b".text")
        results: list[dict] = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00")
            if name not in wanted:
                continue
            sec_va = image_base + s.VirtualAddress
            blob = s.get_data()
            for kwargs in (
                {"ptr_size": 8, "is_rva": False},
                {"ptr_size": 4, "is_rva": True, "image_base": image_base},
            ):
                for hit in scan_pointer_arrays(blob, sec_va, in_exec,
                                               min_run=min_run, **kwargs):
                    hit["section"] = name.decode("ascii", "replace")
                    hit["pdata_backed"] = _all_pdata_backed(
                        blob, hit, image_base, pdata_starts)
                    results.append(hit)
        results.sort(key=lambda d: d["count"], reverse=True)
        return results
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("find_dispatch_tables(%s) failed: %s", path, exc)
        return []
    finally:
        pe.close()


def _all_pdata_backed(blob, hit, image_base, pdata_starts) -> bool:
    """True when every entry of the recovered run is a `.pdata` function start."""
    if not pdata_starts:
        return False
    ps, is_rva = hit["ptr_size"], hit["kind"] == "rva"
    fmt = "<Q" if ps == 8 else "<I"
    unpack = struct.Struct(fmt).unpack_from
    for k in range(hit["count"]):
        (v,) = unpack(blob, hit["offset"] + k * ps)
        target = (image_base + v) & _MASK64 if is_rva else v
        if target not in pdata_starts:
            return False
    return True


def disassemble_many(path, vas: list[int], count: int = 32) -> dict[int, list]:
    """Bulk companion to get_disassembly: disassemble each VA in `vas`.

    Returns {va: instructions} for every VA that decoded (a VA the disassembler
    can't reach is omitted). Reuses the capstone+ILT fallback in `pe_disasm` so
    it works on the same ILT-heavy binaries the dispatch table came from.
    """
    from chimera.parsers.pe_disasm import disassemble_at  # noqa: PLC0415

    out: dict[int, list] = {}
    for va in vas:
        insns = disassemble_at(path, va, count)
        if insns:
            out[va] = insns
    return out
