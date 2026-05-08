"""Synthesize a minimal pefile-parseable PE32+ DLL.

Reuses the same byte layout as tests/unit/test_pe_header.py's
_build_minimal_pe64 helper, but writes to disk under tests/fixtures/pe/.
"""
import struct
from pathlib import Path

OUT = Path(__file__).parent / "pe" / "hello.exe"
OUT.parent.mkdir(parents=True, exist_ok=True)

def build(*, is_dll=False, is_dotnet=False) -> bytes:
    BUF = 0x800
    SEC_VA = 0x1000
    SEC_RAW_OFF = 0x200
    SEC_RAW_SIZE = 0x200
    OPT_HDR_SIZE = 240
    buf = bytearray(BUF)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    chars = 0x2000 if is_dll else 0x0
    struct.pack_into("<HHIIIHH", buf, pe_off + 4,
                     0x8664, 1, 0, 0, 0, OPT_HDR_SIZE, chars)
    opt = pe_off + 24
    struct.pack_into("<HBBIIII", buf, opt,
                     0x20b, 0, 0, SEC_RAW_SIZE, 0, 0, SEC_VA)
    struct.pack_into("<IQ", buf, opt + 20, SEC_VA, 0x140000000)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", buf, opt + 52, 0, 0x2000, 0x200, 0)
    struct.pack_into("<HH", buf, opt + 68, 3, 0)
    struct.pack_into("<I", buf, opt + 108, 16)
    if is_dotnet:
        clr_off = opt + 112 + 14 * 8
        struct.pack_into("<II", buf, clr_off, 0x2000, 0x48)
    sec = opt + 240
    name = b".text\x00\x00\x00"
    struct.pack_into("<8sIIIIIIHHI", buf, sec,
                     name, SEC_RAW_SIZE, SEC_VA, SEC_RAW_SIZE, SEC_RAW_OFF,
                     0, 0, 0, 0, 0x60000020)
    return bytes(buf)

OUT.write_bytes(build(is_dll=False, is_dotnet=False))
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
