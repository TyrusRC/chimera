"""Synthetic Mach-O builder — produces minimal valid x86_64 Mach-O bytes
with populated __objc_classlist / __objc_methlist / __objc_catlist /
__objc_protolist sections, for parser unit tests.

NOT a complete Mach-O writer. Only enough to exercise the ObjC parser.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from io import BytesIO

# Mach-O constants
MH_MAGIC_64 = 0xfeedfacf
CPU_TYPE_X86_64 = 0x01000007
MH_DYLIB = 0x6
LC_SEGMENT_64 = 0x19


@dataclass
class BuilderMethod:
    selector: str
    types: str
    imp_addr: int


@dataclass
class BuilderClass:
    name: str
    superclass: str | None
    methods: list[BuilderMethod] = field(default_factory=list)
    class_methods: list[BuilderMethod] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class BuilderCategory:
    name: str
    target_class: str
    methods: list[BuilderMethod] = field(default_factory=list)


@dataclass
class BuilderProtocol:
    name: str
    required_methods: list[BuilderMethod] = field(default_factory=list)
    optional_methods: list[BuilderMethod] = field(default_factory=list)


def build_macho_with_objc(
    *,
    classes: list[BuilderClass],
    categories: list[BuilderCategory],
    protocols: list[BuilderProtocol],
    arm64e: bool = False,
) -> bytes:
    """Return a complete Mach-O dylib byte-stream populated with ObjC metadata.

    Layout strategy:
      file = [mach_header_64][LC_SEGMENT_64 __DATA_CONST][LC_SEGMENT_64 __DATA]
             [section data]

    All section data is laid out contiguously after the load commands so file
    offsets are simple to compute. vmaddr == fileoff for simplicity (1:1 map).
    """
    # First, lay out section payloads in memory: strings, methods, ros, classes.
    pool = _BytesPool()
    str_addr: dict[str, int] = {}

    def _pool_str(s: str) -> int:
        if s not in str_addr:
            str_addr[s] = pool.append(s.encode() + b"\x00")
        return str_addr[s]

    def _pool_method_list(methods: list[BuilderMethod]) -> int:
        if not methods:
            return 0
        # method_list_t header: entsize=24 flags=0 (low bits of entsize_and_flags),
        # count=N, then N method_t entries.
        body = struct.pack("<II", 24, len(methods))
        for m in methods:
            body += struct.pack("<QQQ",
                                _pool_str(m.selector),
                                _pool_str(m.types),
                                m.imp_addr)
        return pool.append(body)

    def _pool_protocol_list(names: list[str]) -> int:
        if not names:
            return 0
        # protocol_list_t: count(8) then count*ptr(8) entries
        body = struct.pack("<Q", len(names))
        for n in names:
            body += struct.pack("<Q", _pool_str(n))  # protocol_t* placeholder
        return pool.append(body)

    # Build classes
    class_addrs: list[int] = []
    for c in classes:
        baseMethods = _pool_method_list(c.methods)
        classMethods = _pool_method_list(c.class_methods)
        protocols_addr = _pool_protocol_list(c.protocols)
        ro = struct.pack(
            "<IIII QQQQQQQ",
            0,          # flags
            0,          # instanceStart
            0,          # instanceSize
            0,          # reserved
            0,          # ivarLayout
            _pool_str(c.name),  # name
            baseMethods,
            protocols_addr,
            0,          # ivars
            0,          # weakIvarLayout
            0,          # baseProperties
        )
        ro_addr = pool.append(ro)
        # objc_class_t: isa(super_meta), superclass(super), cache(0), vtable(0),
        # data(ro)
        super_addr = _pool_str(c.superclass) if c.superclass else 0
        cls = struct.pack("<QQQQQ", 0, super_addr, 0, 0, ro_addr)
        class_addrs.append(pool.append(cls))

    # Build categories
    cat_addrs: list[int] = []
    for cat in categories:
        body = struct.pack(
            "<QQQQQQ",
            _pool_str(cat.name),
            _pool_str(cat.target_class),
            _pool_method_list(cat.methods),
            0, 0, 0,
        )
        cat_addrs.append(pool.append(body))

    # Build protocols
    proto_addrs: list[int] = []
    for proto in protocols:
        body = struct.pack(
            "<QQQQQQQQ II",
            0,
            _pool_str(proto.name),
            0,
            _pool_method_list(proto.required_methods),
            0,
            _pool_method_list(proto.optional_methods),
            0,
            0,
            0,
            0,
        )
        proto_addrs.append(pool.append(body))

    # Build the three list sections (each section is just an array of pointers)
    classlist_bytes = b"".join(struct.pack("<Q", a) for a in class_addrs)
    catlist_bytes = b"".join(struct.pack("<Q", a) for a in cat_addrs)
    protolist_bytes = b"".join(struct.pack("<Q", a) for a in proto_addrs)

    classlist_addr = pool.append(classlist_bytes) if classlist_bytes else 0
    catlist_addr = pool.append(catlist_bytes) if catlist_bytes else 0
    protolist_addr = pool.append(protolist_bytes) if protolist_bytes else 0

    # Now build the segments + sections + header.
    sections = [
        (b"__objc_classlist".ljust(16, b"\0"), b"__DATA_CONST".ljust(16, b"\0"),
         classlist_addr, len(classlist_bytes)),
        (b"__objc_catlist".ljust(16, b"\0"), b"__DATA_CONST".ljust(16, b"\0"),
         catlist_addr, len(catlist_bytes)),
        (b"__objc_protolist".ljust(16, b"\0"), b"__DATA_CONST".ljust(16, b"\0"),
         protolist_addr, len(protolist_bytes)),
    ]

    HEADER_SIZE = 32
    SEG_CMD_SIZE = 72
    SECT_SIZE = 80
    seg_cmd_total = SEG_CMD_SIZE + SECT_SIZE * len(sections)

    cputype = CPU_TYPE_X86_64
    cpusubtype = 3
    ncmds = 1
    flags = 0

    # Section file offsets sit AFTER the header + load commands; pool addresses
    # are already file offsets if we shift the pool by header+lc size.
    base_offset = HEADER_SIZE + seg_cmd_total
    pool_payload = pool.bytes()

    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64, cputype, cpusubtype, MH_DYLIB,
        ncmds, seg_cmd_total, flags, 0,
    )

    # One big segment covers everything.
    seg_cmd = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64, seg_cmd_total,
        b"__DATA_CONST".ljust(16, b"\0"),
        base_offset,                 # vmaddr
        len(pool_payload),           # vmsize
        base_offset,                 # fileoff
        len(pool_payload),           # filesize
        7, 7,                        # maxprot, initprot rwx
        len(sections), 0,
    )
    sect_blob = b""
    for sectname, segname, addr, size in sections:
        sect_blob += struct.pack(
            "<16s16sQQIIIIIIII",
            sectname, segname,
            base_offset + addr,      # vmaddr
            size,
            base_offset + addr,      # fileoff
            0, 0, 0, 0, 0, 0, 0,
        )

    return header + seg_cmd + sect_blob + pool_payload


class _BytesPool:
    def __init__(self) -> None:
        self._buf = BytesIO()

    def append(self, data: bytes) -> int:
        # Align to 8 bytes for pointer-aligned access.
        cur = self._buf.tell()
        pad = (-cur) & 7
        if pad:
            self._buf.write(b"\0" * pad)
        offset = self._buf.tell()
        self._buf.write(data)
        return offset

    def bytes(self) -> bytes:
        return self._buf.getvalue()
