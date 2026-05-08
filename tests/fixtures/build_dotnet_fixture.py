"""Synthesize a minimal pefile-parseable DOTNET PE32+ assembly."""
import struct
from pathlib import Path

OUT = Path(__file__).parent / "dotnet" / "bin" / "hello.dll"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Reuse the build() function from build_pe_fixture.py
import sys
sys.path.insert(0, str(Path(__file__).parent))
from build_pe_fixture import build

OUT.write_bytes(build(is_dll=True, is_dotnet=True))
print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
