"""Embedded-JS recovery from a Node compiled binary (nexe / SEA / pkg)."""
from __future__ import annotations

import gzip
import struct

import pytest

from chimera.unpacking.nodejs import (
    NEXE_SENTINEL,
    _SEA_MAGIC_LE,
    detect_node_binary,
    extract_nexe,
    extract_node_js,
    extract_sea,
)

_JS = b"readline.question('Enter flag: ', flag => { process.exit(0); });\n"


def _nexe(content: bytes, resources: bytes = b"") -> bytes:
    node_stub = b"MZ" + b"\x00" * 4096          # pretend host executable
    footer = struct.pack("<dd", len(content), len(resources))
    return node_stub + content + resources + NEXE_SENTINEL + footer


def _sea(code: bytes, flags: int = 0, width: int = 8) -> bytes:
    """Oldest SEA layout: magic, flags, code string_view directly."""
    lenf = "<Q" if width == 8 else "<I"
    blob = _SEA_MAGIC_LE + struct.pack("<I", flags) + struct.pack(lenf, len(code)) + code
    return b"\x7fELF" + b"\x00" * 512 + b"NODE_SEA_BLOB\x00" + blob + b"\x00" * 16


def _sea_v22(code: bytes, flags: int = 0) -> bytes:
    """Node 22+ layout: magic, flags, exec_argv_extension(uint8), code_path
    string_view, THEN the main code string_view."""
    def sv(b):
        return struct.pack("<Q", len(b)) + b
    blob = (_SEA_MAGIC_LE + struct.pack("<I", flags) + b"\x00"   # exec_argv_extension
            + sv(b"sea-prelude.js") + sv(code))
    return b"\x7fELF" + b"\x00" * 512 + b"NODE_SEA_BLOB\x00" + blob + b"\x00" * 16


# --- detection ---------------------------------------------------------------

def test_detect_nexe():
    assert detect_node_binary(_nexe(_JS)) == "nexe"


def test_detect_sea():
    assert detect_node_binary(_sea(_JS)) == "sea"


def test_detect_pkg():
    assert detect_node_binary(b"MZ" + b"\x00" * 100 + b"pkg/prelude/bootstrap.js") == "pkg"


def test_detect_none_on_plain_binary():
    assert detect_node_binary(b"\x7fELF" + b"\x00" * 4096) is None


# --- nexe carve --------------------------------------------------------------

def test_extract_nexe_returns_exact_bundle():
    js, res_size = extract_nexe(_nexe(_JS, resources=b"RESRC-BLOB"))
    assert js == _JS
    assert res_size == len(b"RESRC-BLOB")


def test_extract_nexe_inflates_gzip_bundle():
    packed = gzip.compress(_JS)
    js, _ = extract_nexe(_nexe(packed))
    assert js == _JS


def test_extract_nexe_rejects_implausible_footer():
    data = _nexe(_JS)
    # corrupt the content-size double to something larger than the file
    bad = data[:-16] + struct.pack("<dd", 1e12, 0)
    with pytest.raises(ValueError):
        extract_nexe(bad)


# --- SEA carve ---------------------------------------------------------------

def test_extract_sea_64bit_length():
    code, flags = extract_sea(_sea(_JS))
    assert code == _JS and flags == 0


def test_extract_sea_snapshot_flag_surfaced():
    _, flags = extract_sea(_sea(_JS, flags=0b10))
    assert flags & 0b10


def test_extract_sea_v22_layout_skips_codepath():
    # Node 22+ inserts exec_argv_extension + code_path before the main code;
    # the walker must return the JS, not the short code_path string.
    code, _ = extract_sea(_sea_v22(_JS))
    assert code == _JS


def test_extract_sea_skips_stray_magic_without_valid_length():
    # a bare magic with a garbage length must not shadow the real blob
    stray = _SEA_MAGIC_LE + struct.pack("<I", 0) + struct.pack("<Q", 1 << 60)
    data = b"\x00" * 32 + stray + _sea(_JS)
    code, _ = extract_sea(data)
    assert code == _JS


# --- end-to-end --------------------------------------------------------------

def test_extract_node_js_writes_file(tmp_path):
    exe = tmp_path / "anode.exe"
    exe.write_bytes(_nexe(_JS))
    r = extract_node_js(exe, tmp_path / "out")
    assert r.ok and r.kind == "nexe"
    assert r.js_size == len(_JS)
    from pathlib import Path
    assert Path(r.out_file).read_bytes() == _JS


def test_extract_node_js_sea_snapshot_names_bin(tmp_path):
    exe = tmp_path / "app"
    exe.write_bytes(_sea(_JS, flags=0b10))
    r = extract_node_js(exe, tmp_path / "out")
    assert r.ok and r.kind == "sea"
    assert r.out_file.endswith(".snapshot.bin")
    assert r.note and "snapshot" in r.note.lower()


def test_extract_node_js_pkg_is_guidance_not_extraction(tmp_path):
    exe = tmp_path / "cli"
    exe.write_bytes(b"MZ" + b"\x00" * 64 + b"pkg/prelude/bootstrap.js")
    r = extract_node_js(exe, tmp_path / "out")
    assert not r.ok and r.kind == "pkg"
    assert r.note and "pkg" in r.note.lower()


def test_extract_node_js_rejects_non_node(tmp_path):
    exe = tmp_path / "plain.bin"
    exe.write_bytes(b"\x7fELF" + b"\x00" * 256)
    r = extract_node_js(exe, tmp_path / "out")
    assert not r.ok and r.kind is None and "not a Node" in r.error
