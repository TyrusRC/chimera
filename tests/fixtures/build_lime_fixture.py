"""Synthesize a tiny LiME-format memory image fixture."""
import struct
from pathlib import Path

OUT = Path(__file__).parent / "memory" / "sample.lime"
OUT.parent.mkdir(parents=True, exist_ok=True)

# LiME header: magic=0x4C694D45 ("LiME"), version=1, s_addr=0, e_addr=0x1000
# Note: struct.pack("<I", 0x4C694D45) produces bytes 0x45 0x4D 0x69 0x4C
# which is the ASCII sequence "EMiL" — this is what _detect_format checks.
header = struct.pack("<IIQQ8s",
                     0x4C694D45,    # magic 'LiME' (little-endian)
                     1,              # version
                     0,              # s_addr
                     0x1000,         # e_addr
                     b"\x00" * 8)    # reserved
body = b"\x00" * 0x1000
OUT.write_bytes(header + body)
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
