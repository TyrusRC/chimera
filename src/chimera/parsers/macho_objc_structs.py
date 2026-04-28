"""Struct format strings + constants for Mach-O ObjC metadata sections.

Apple references:
- objc4 source: https://opensource.apple.com/source/objc4/
- dyld chained fixups: https://opensource.apple.com/source/dyld/
"""
from __future__ import annotations

import struct

# --- Mach-O load command IDs -------------------------------------------------
LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034

# --- Chained-fixup pointer formats ------------------------------------------
DYLD_CHAINED_PTR_ARM64E = 1
DYLD_CHAINED_PTR_64 = 2
DYLD_CHAINED_PTR_64_OFFSET = 6

# --- ObjC structures (64-bit ABI; little-endian) ----------------------------
# Mach-O headers
MACH_HEADER_64 = struct.Struct("<IiiIIIII")  # magic, cputype, cpusubtype,
                                              # filetype, ncmds, sizeofcmds,
                                              # flags, reserved
LOAD_COMMAND = struct.Struct("<II")           # cmd, cmdsize
SEGMENT_COMMAND_64 = struct.Struct("<II16sQQQQiiII")  # cmd, cmdsize, segname,
                                                       # vmaddr, vmsize,
                                                       # fileoff, filesize,
                                                       # maxprot, initprot,
                                                       # nsects, flags
SECTION_64 = struct.Struct("<16s16sQQIIIIIIII")  # sectname, segname, addr,
                                                   # size, offset, align,
                                                   # reloff, nreloc, flags,
                                                   # reserved1..3

# objc_class_t (after isa fixup): isa(8) superclass(8) cache(8) vtable(8) data(8)
CLASS_T = struct.Struct("<QQQQQ")

# class_ro_t (read-only data): flags(4) instanceStart(4) instanceSize(4)
# reserved(4) ivarLayout(8) name(8) baseMethods(8) baseProtocols(8) ivars(8)
# weakIvarLayout(8) baseProperties(8)
CLASS_RO_T = struct.Struct("<IIII QQQQQQQ")

# method_t (large form, 64-bit): name(8) types(8) imp(8)
METHOD_T = struct.Struct("<QQQ")

# method_list_t header: entsize_and_flags(4) count(4)
METHOD_LIST_HEADER = struct.Struct("<II")

# category_t: name(8) cls(8) instanceMethods(8) classMethods(8) protocols(8)
# instanceProperties(8)
CATEGORY_T = struct.Struct("<QQQQQQ")

# protocol_t (subset we read): isa(8) name(8) protocols(8) instanceMethods(8)
# classMethods(8) optionalInstanceMethods(8) optionalClassMethods(8)
# instanceProperties(8) size(4) flags(4)
PROTOCOL_T = struct.Struct("<QQQQQQQQ II")


# --- ARM64e PAC stripping ----------------------------------------------------
# Bits 0..46 are the canonical 47-bit user-space pointer.
_PAC_MASK = (1 << 47) - 1


def strip_pac(p: int) -> int:
    """Strip ARM64e pointer authentication bits from a runtime-resolved VA.

    Use only on pointers that already have dyld fixups applied — i.e., values
    you would observe in a live process or in a Mach-O dump. The 47-bit canonical
    user-space VA sits in bits 0..46; bits 47..63 are the auth context that
    dyld would have stripped at fixup time.

    NOT for use on raw `dyld_chained_ptr_arm64e_rebase.target` fields — those
    encode the target in bits 0..42 with auth metadata above. The chained-fixup
    decoder in `macho_objc.py` handles that case separately.
    """
    return p & _PAC_MASK
