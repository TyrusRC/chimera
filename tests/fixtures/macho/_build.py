"""Build a minimal valid 64-bit Mach-O executable for integration tests.

Run from the repo root:

    .venv/bin/python tests/fixtures/macho/_build.py

Re-creates `tiny.macho` — a 32-byte Mach-O64 header (cputype=x86_64,
filetype=MH_EXECUTE, ncmds=0). The standalone Mach-O pipeline must accept
this and return a `UnifiedProgramModel` without crashing.
"""
from __future__ import annotations

import struct
from pathlib import Path


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,        # MH_MAGIC_64
        0x01000007,        # cputype: x86_64
        3,                 # cpusubtype
        2,                 # filetype: MH_EXECUTE
        0,                 # ncmds
        0,                 # sizeofcmds
        0,                 # flags
        0,                 # reserved
    )
    (out / "tiny.macho").write_bytes(header)


if __name__ == "__main__":
    main(Path(__file__).parent)
