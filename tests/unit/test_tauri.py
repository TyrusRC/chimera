"""Tauri EmbeddedAssets carver (chimera.unpacking.tauri).

Fixtures hand-assemble a minimal ELF64 carrying a Tauri EmbeddedAssets table (the
`.data.rel.ro` array of 32-byte `[key_ptr,key_len,blob_ptr,blob_len]` entries whose
pointers are R_X86_64_RELATIVE relocations in `.rela.dyn`) — no real binary needed.
"""

from __future__ import annotations

import importlib.util
import struct

import pytest

_HAS_BROTLI = importlib.util.find_spec("brotli") is not None

from chimera.unpacking.tauri import (
    carve_embedded_assets,
    detect_tauri_binary,
    extract_tauri,
)

DBASE = 0x4000  # virtual base of the .data.rel.ro section


def _align8(n: int) -> int:
    return (n + 7) & ~7


def _build_tauri_elf(assets: list[tuple[str, bytes]], markers: bytes) -> bytes:
    """Assemble a minimal ELF64 with a Tauri EmbeddedAssets table.

    assets: list of (key "/path", blob bytes [already stored/compressed]).
    markers: Tauri id bytes appended as trailing data so detection fires.
    """
    n = len(assets)
    entries_size = n * 32
    keys = b""
    key_rel: list[int] = []
    for name, _blob in assets:
        key_rel.append(entries_size + len(keys))
        keys += name.encode()
    blobs = b""
    blob_rel: list[int] = []
    base_after_keys = entries_size + len(keys)
    for _name, blob in assets:
        blob_rel.append(base_after_keys + len(blobs))
        blobs += blob

    entries = b""
    relocs = []  # (loc_va, addend_va)
    for i, (name, blob) in enumerate(assets):
        key_ptr = DBASE + key_rel[i]
        blob_ptr = DBASE + blob_rel[i]
        p = DBASE + i * 32
        entries += struct.pack("<QQQQ", key_ptr, len(name.encode()), blob_ptr, len(blob))
        relocs.append((p, key_ptr))        # key_ptr slot
        relocs.append((p + 16, blob_ptr))  # blob_ptr slot
    data_content = entries + keys + blobs

    rela_content = b"".join(struct.pack("<QQq", loc, 8, add) for loc, add in relocs)

    shstr = b"\x00.data.rel.ro\x00.rela.dyn\x00.shstrtab\x00"
    name_data = shstr.index(b".data.rel.ro")
    name_rela = shstr.index(b".rela.dyn")
    name_shstr = shstr.index(b".shstrtab")

    off_shstr = 64
    off_data = _align8(off_shstr + len(shstr))
    off_rela = _align8(off_data + len(data_content))
    off_shdr = _align8(off_rela + len(rela_content))

    def shdr(name, stype, addr, off, size):
        return struct.pack("<IIQQQQIIQQ", name, stype, 0, addr, off, size, 0, 0, 1, 0)

    shdrs = b"".join([
        shdr(0, 0, 0, 0, 0),                                   # 0 NULL
        shdr(name_data, 1, DBASE, off_data, len(data_content)),  # 1 .data.rel.ro PROGBITS
        shdr(name_rela, 4, 0, off_rela, len(rela_content)),      # 2 .rela.dyn RELA
        shdr(name_shstr, 3, 0, off_shstr, len(shstr)),           # 3 .shstrtab STRTAB
    ])
    shnum = 4
    shstrndx = 3

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2   # ELFCLASS64
    ehdr[5] = 1   # ELFDATA2LSB
    ehdr[6] = 1   # EV_CURRENT
    struct.pack_into("<H", ehdr, 16, 3)       # e_type ET_DYN
    struct.pack_into("<H", ehdr, 18, 0x3E)    # e_machine x86-64
    struct.pack_into("<I", ehdr, 20, 1)       # e_version
    struct.pack_into("<Q", ehdr, 40, off_shdr)  # e_shoff
    struct.pack_into("<H", ehdr, 52, 64)      # e_ehsize
    struct.pack_into("<H", ehdr, 58, 64)      # e_shentsize
    struct.pack_into("<H", ehdr, 60, shnum)   # e_shnum
    struct.pack_into("<H", ehdr, 62, shstrndx)  # e_shstrndx

    buf = bytearray(off_shdr + len(shdrs))
    buf[0:64] = ehdr
    buf[off_shstr:off_shstr + len(shstr)] = shstr
    buf[off_data:off_data + len(data_content)] = data_content
    buf[off_rela:off_rela + len(rela_content)] = rela_content
    buf[off_shdr:off_shdr + len(shdrs)] = shdrs
    return bytes(buf) + markers


_HTML = b"<!DOCTYPE html><title>app</title><script src='main.js'></script>"
_JS = b"// stored js\nconsole.log('hi');\n"
_MARKERS = b"\n__TAURI_INTERNALS__ cargo/registry/tauri-2.11.5/lib.rs rusty_v8-0.32.1 9.5.172.19\n"


def test_detect_tauri_binary():
    elf = _build_tauri_elf([("/index.html", _HTML)], _MARKERS)
    assert detect_tauri_binary(elf) is True
    assert detect_tauri_binary(b"just a plain elf") is False


def test_carve_finds_and_decodes_stored_assets():
    elf = _build_tauri_elf([("/index.html", _HTML), ("/app.js", _JS)], _MARKERS)
    assets = carve_embedded_assets(elf, None)
    by = {a.name: a for a in assets}
    assert set(by) == {"/index.html", "/app.js"}
    # Stored (identity) HTML/JS come back as "stored" with content preserved.
    assert by["/index.html"].codec == "stored"
    assert by["/index.html"].out_size == len(_HTML)
    assert by["/app.js"].out_size == len(_JS)


def test_extract_writes_files_and_flags_runtime_v8(tmp_path):
    elf = _build_tauri_elf([("/index.html", _HTML)], _MARKERS)
    exe = tmp_path / "app"
    exe.write_bytes(elf)
    r = extract_tauri(exe, tmp_path / "out")
    assert r.ok and r.is_tauri
    assert r.tauri_version == "2.11.5"
    assert r.embedded_v8 == "rusty_v8-0.32.1"
    assert len(r.assets) == 1
    written = (tmp_path / "out" / "index.html").read_bytes()
    assert written == _HTML
    # rusty_v8 present -> must flag the runtime-decrypt caveat.
    assert "embedded V8" in r.note or "runtime-decrypt" in r.note


def test_extract_non_tauri_is_rejected(tmp_path):
    exe = tmp_path / "plain"
    exe.write_bytes(b"\x7fELF" + b"\x00" * 300)
    r = extract_tauri(exe)
    assert r.ok is False and r.is_tauri is False
    assert "not a Tauri" in r.error


@pytest.mark.skipif(not _HAS_BROTLI, reason="brotli not installed")
def test_carve_decodes_brotli_asset():
    import brotli

    payload = b"<html>" + b"A" * 2000 + b"</html>"  # compressible
    comp = brotli.compress(payload)
    elf = _build_tauri_elf([("/index.html", comp)], _MARKERS)
    assets = carve_embedded_assets(elf, None)
    assert len(assets) == 1
    a = assets[0]
    assert a.codec == "brotli"
    assert a.out_size == len(payload)
