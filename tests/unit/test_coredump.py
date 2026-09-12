"""ELF core-dump triage logic: address→module, memory read/search, guards.

Uses CoreDump.__new__ to exercise the pure logic against synthetic mappings/
segments (a real multi-hundred-MB core isn't shipped); the parse path is
verified out-of-band on a real core.
"""
from __future__ import annotations

from chimera.parsers.coredump import CoreDump, core_triage


def _synthetic(tmp_path):
    """A CoreDump wired to a tiny backing file, bypassing ELF parsing."""
    blob = b"\x00" * 0x100 + b"MAGIC_HERE" + b"\x00" * 0x50
    f = tmp_path / "mem.bin"
    f.write_bytes(blob)
    c = CoreDump.__new__(CoreDump)
    c.path = str(f)
    c._fh = open(f, "rb")
    c.machine = "EM_X86_64"
    # one PT_LOAD mapping file offset 0 -> vaddr 0x400000
    c.loads = [{"vaddr": 0x400000, "off": 0, "filesz": len(blob),
                "memsz": len(blob), "flags": 5}]
    # a module split across two mappings (code + data)
    c.mappings = [
        {"start": 0x400000, "end": 0x401000, "file_offset": 0, "path": "/bin/victim"},
        {"start": 0x401000, "end": 0x402000, "file_offset": 0x1000, "path": "/bin/victim"},
        {"start": 0x7f0000000000, "end": 0x7f0000010000, "file_offset": 0, "path": "/lib/evil.so"},
    ]
    c.threads = [{"rip": 0x400123, "rsp": 0x7ffff000, "rax": 0}]
    return c


def test_address_to_module_uses_module_base(tmp_path):
    c = _synthetic(tmp_path)
    # address in the second mapping resolves against the module's MIN start
    assert c.address_to_module(0x401234) == ("/bin/victim", 0x1234)
    assert c.address_to_module(0x7f0000000010) == ("/lib/evil.so", 0x10)
    assert c.address_to_module(0xdead0000) is None
    c.close()


def test_modules_dedup(tmp_path):
    c = _synthetic(tmp_path)
    mods = c.modules()
    victim = next(m for m in mods if m["path"] == "/bin/victim")
    assert victim["start"] == 0x400000 and victim["end"] == 0x402000
    c.close()


def test_read_and_search(tmp_path):
    c = _synthetic(tmp_path)
    assert c.read(0x400000 + 0x100, 10) == b"MAGIC_HERE"
    assert c.search(b"MAGIC_HERE") == [0x400000 + 0x100]
    assert c.read(0xdead0000, 4) is None      # unmapped
    c.close()


def test_triage_resolves_rip_module(tmp_path):
    c = _synthetic(tmp_path)
    t = c.triage()
    assert t["machine"] == "EM_X86_64"
    assert t["crash"]["rip_module"] == "/bin/victim"
    assert t["crash"]["rip_offset"] == "0x123"
    c.close()


def test_core_triage_rejects_non_core(tmp_path):
    f = tmp_path / "notcore.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)   # ELF but not ET_CORE
    r = core_triage(str(f))
    assert r["available"] and "error" in r
