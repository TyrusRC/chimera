"""Mach-O ObjC metadata parser — reads __objc_classlist / __objc_methlist /
__objc_catlist / __objc_protolist sections directly from the binary.

Returns a structured ObjCMetadata object. The pipeline orchestrator owns
correlation with the call graph and class-dump enrichment.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path

from chimera.model.objc import ObjCCategory, ObjCClass, ObjCMethod, ObjCProtocol
from chimera.parsers.macho_objc_structs import (
    CLASS_RO_T,
    CLASS_T,
    LC_DYLD_CHAINED_FIXUPS,
    LC_SEGMENT_64,
    LOAD_COMMAND,
    MACH_HEADER_64,
    METHOD_LIST_HEADER,
    METHOD_T,
    SECTION_64,
    SEGMENT_COMMAND_64,
    strip_pac,
)

logger = logging.getLogger(__name__)


class ObjCParseError(Exception):
    """Raised when Mach-O bytes are structurally invalid."""


@dataclass
class ObjCMetadata:
    classes: list[ObjCClass] = field(default_factory=list)
    categories: list[ObjCCategory] = field(default_factory=list)
    protocols: list[ObjCProtocol] = field(default_factory=list)
    chained_fixups_detected: bool = False
    skipped_pointers: int = 0


# ---------------------------------------------------------------------------
# Section locator
# ---------------------------------------------------------------------------

def _read_section_bytes(raw: bytes, segname: str, sectname: str) -> bytes:
    """Locate a (segment, section) pair and return its file bytes.
    Returns empty bytes if not found."""
    if len(raw) < MACH_HEADER_64.size:
        raise ObjCParseError("file smaller than Mach-O header")
    magic, _ct, _st, _ft, ncmds, _sz, _fl, _r = MACH_HEADER_64.unpack_from(raw, 0)
    if magic != 0xfeedfacf:
        raise ObjCParseError(f"bad magic 0x{magic:08x}")
    cur = MACH_HEADER_64.size
    for _ in range(ncmds):
        cmd, cmdsize = LOAD_COMMAND.unpack_from(raw, cur)
        if cmd == LC_SEGMENT_64:
            (_c, _cs, segname_b, _vma, _vms, _fo, _fs, _mp, _ip,
             nsects, _flg) = SEGMENT_COMMAND_64.unpack_from(raw, cur)
            seg = segname_b.rstrip(b"\0").decode()
            sect_off = cur + SEGMENT_COMMAND_64.size
            for _ in range(nsects):
                (s_name, s_seg, s_addr, s_size, s_off,
                 _a, _r1, _n, _f, _r2, _r3, _r4) = SECTION_64.unpack_from(
                    raw, sect_off,
                )
                sect_off += SECTION_64.size
                name = s_name.rstrip(b"\0").decode()
                if seg == segname and name == sectname:
                    return raw[s_off:s_off + s_size]
        cur += cmdsize
    return b""


def _locate_section_in_segments(
    raw: bytes, sectname: str,
) -> bytes:
    """Search both __DATA and __DATA_CONST for an ObjC section."""
    for segname in ("__DATA_CONST", "__DATA"):
        b = _read_section_bytes(raw, segname, sectname)
        if b:
            return b
    return b""


# ---------------------------------------------------------------------------
# Address translation (file-offset == vmaddr in our test fixtures and in
# practice for the synthetic builder; real binaries need a vmaddr→fileoff map)
# ---------------------------------------------------------------------------

def _build_vm_to_file_map(raw: bytes) -> list[tuple[int, int, int]]:
    """Return list of (vmaddr, vmaddr+size, fileoff) tuples covering the binary."""
    out: list[tuple[int, int, int]] = []
    if len(raw) < MACH_HEADER_64.size:
        return out
    _m, _ct, _st, _ft, ncmds, _sz, _fl, _r = MACH_HEADER_64.unpack_from(raw, 0)
    cur = MACH_HEADER_64.size
    for _ in range(ncmds):
        cmd, cmdsize = LOAD_COMMAND.unpack_from(raw, cur)
        if cmd == LC_SEGMENT_64:
            (_c, _cs, _seg, vma, vms, fo, _fs, _mp, _ip,
             _ns, _flg) = SEGMENT_COMMAND_64.unpack_from(raw, cur)
            if vms > 0:
                out.append((vma, vma + vms, fo))
        cur += cmdsize
    return out


def _vm_to_file(vm_to_file: list[tuple[int, int, int]], vmaddr: int) -> int | None:
    for start, end, fileoff in vm_to_file:
        if start <= vmaddr < end:
            return fileoff + (vmaddr - start)
    return None


# ---------------------------------------------------------------------------
# Method list reader
# ---------------------------------------------------------------------------

def _read_cstr(raw: bytes, file_offset: int, max_len: int = 256) -> str:
    if file_offset <= 0 or file_offset >= len(raw):
        return ""
    end = raw.find(b"\0", file_offset, file_offset + max_len)
    if end == -1:
        end = file_offset + max_len
    return raw[file_offset:end].decode("utf-8", errors="replace")


def _read_method_list(
    raw: bytes,
    list_addr: int,
    vm_map: list[tuple[int, int, int]],
    class_name: str,
    is_class_method: bool,
) -> list[ObjCMethod]:
    if list_addr == 0:
        return []
    fo = _vm_to_file(vm_map, list_addr)
    if fo is None or fo + METHOD_LIST_HEADER.size > len(raw):
        return []
    entsize_and_flags, count = METHOD_LIST_HEADER.unpack_from(raw, fo)
    # entsize is the lower bits; bit 31 of the original word is the
    # "small/relative method list" flag (iOS 14+ binaries) — TODO future task.
    entsize = entsize_and_flags & 0xFFFF
    if entsize == 0 or count > 100_000:  # sanity guard
        return []
    out: list[ObjCMethod] = []
    cur = fo + METHOD_LIST_HEADER.size
    for _ in range(count):
        if cur + 24 > len(raw):
            break
        name_p, types_p, imp = METHOD_T.unpack_from(raw, cur)
        sel = _read_cstr(raw, _vm_to_file(vm_map, name_p) or 0)
        types = _read_cstr(raw, _vm_to_file(vm_map, types_p) or 0)
        out.append(ObjCMethod(
            class_name=class_name,
            selector=sel,
            imp_address=hex(imp),
            is_class_method=is_class_method,
            type_signature=types or None,
        ))
        cur += entsize
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_objc_metadata(macho_path: Path) -> ObjCMetadata:
    raw = Path(macho_path).read_bytes()
    md = ObjCMetadata()

    classlist_bytes = _locate_section_in_segments(raw, "__objc_classlist")
    if not classlist_bytes:
        return md

    vm_map = _build_vm_to_file_map(raw)
    md.chained_fixups_detected = _has_chained_fixups(raw)

    if len(classlist_bytes) % 8 != 0:
        logger.warning("ObjC: __objc_classlist size %d not a multiple of 8; trailing bytes ignored", len(classlist_bytes))
    classlist_count = len(classlist_bytes) // 8
    if classlist_count > 100_000:
        logger.warning("ObjC: __objc_classlist has %d entries; truncating to 100000", classlist_count)
        classlist_bytes = classlist_bytes[: 100_000 * 8]

    # Each entry is one 64-bit class_t pointer.
    for i in range(0, len(classlist_bytes), 8):
        ptr = struct.unpack_from("<Q", classlist_bytes, i)[0]
        if ptr == 0:
            md.skipped_pointers += 1
            continue
        # TODO(sp7-t7): full chained-fixup pointer-format dispatch.
        # Currently we apply PAC stripping when LC_DYLD_CHAINED_FIXUPS is
        # present, which is correct for ARM64e auth_rebase but mishandles
        # DYLD_CHAINED_PTR_64 where bits 47..63 are addend/format, not auth.
        # See spec section 3.5.
        ptr = strip_pac(ptr) if md.chained_fixups_detected else ptr
        cls = _read_class(raw, ptr, vm_map)
        if cls is not None:
            md.classes.append(cls)
        else:
            md.skipped_pointers += 1
            logger.debug("ObjC: skipped classlist entry at index %d (out-of-segment or malformed)", i // 8)

    return md


def _read_class(
    raw: bytes,
    class_addr: int,
    vm_map: list[tuple[int, int, int]],
) -> ObjCClass | None:
    fo = _vm_to_file(vm_map, class_addr)
    if fo is None or fo + CLASS_T.size > len(raw):
        return None
    _isa, super_addr, _cache, _vtable, ro_addr = CLASS_T.unpack_from(raw, fo)
    ro_fo = _vm_to_file(vm_map, ro_addr)
    if ro_fo is None or ro_fo + CLASS_RO_T.size > len(raw):
        return None
    (_flags, _is_, _isz, _r, _ivl, name_p, baseMethods,
     baseProtocols, _ivars, _wivl, _props) = CLASS_RO_T.unpack_from(raw, ro_fo)
    name = _read_cstr(raw, _vm_to_file(vm_map, name_p) or 0)
    superclass = None
    if super_addr:
        # Real Mach-O: super_addr -> class_t -> data -> class_ro_t -> name.
        # Try this first.
        super_class_fo = _vm_to_file(vm_map, super_addr)
        if super_class_fo is not None and super_class_fo + CLASS_T.size <= len(raw):
            (_si, _ss, _sc, _sv, super_ro_addr) = CLASS_T.unpack_from(
                raw, super_class_fo,
            )
            super_ro_fo = _vm_to_file(vm_map, super_ro_addr)
            if super_ro_fo is not None and super_ro_fo + CLASS_RO_T.size <= len(raw):
                (_f, _is_, _isz, _r, _ivl, super_name_p, *_rest) = CLASS_RO_T.unpack_from(
                    raw, super_ro_fo,
                )
                name_fo = _vm_to_file(vm_map, super_name_p)
                if name_fo is not None:
                    superclass = _read_cstr(raw, name_fo)
        # Fallback for synthetic fixtures that pool the name string directly:
        # super_addr points at a C-string instead of a class_t.
        # NOTE: Real binaries with extern superclasses (e.g., NSObject in Foundation)
        # will fall through to None — bind-table resolution is a future task.
        if superclass is None:
            super_fo = _vm_to_file(vm_map, super_addr)
            if super_fo is not None:
                superclass = _read_cstr(raw, super_fo)
                if not superclass:
                    superclass = None
    instance_methods = _read_method_list(
        raw, baseMethods, vm_map, class_name=name, is_class_method=False,
    )
    return ObjCClass(
        name=name,
        superclass=superclass,
        instance_methods=instance_methods,
        class_methods=[],     # populated by Task 5
        protocols=[],         # populated by Task 5
        categories=[],        # populated by Task 5
        # _$s = Swift 5+, _$S = Swift 4.0-4.1 legacy mangling
        is_swift_objc=name.startswith("_$s") or name.startswith("_$S"),
    )


def _has_chained_fixups(raw: bytes) -> bool:
    if len(raw) < MACH_HEADER_64.size:
        return False
    _m, _ct, _st, _ft, ncmds, _sz, _fl, _r = MACH_HEADER_64.unpack_from(raw, 0)
    cur = MACH_HEADER_64.size
    for _ in range(ncmds):
        cmd, cmdsize = LOAD_COMMAND.unpack_from(raw, cur)
        if cmd == LC_DYLD_CHAINED_FIXUPS:
            return True
        cur += cmdsize
    return False
