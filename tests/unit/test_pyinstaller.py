"""Tests for the PyInstaller CArchive extractor.

Builds a minimal-but-real CArchive in-memory (cookie + TOC + a zlib'd
marshalled code object) so the test is self-contained and can fail for a
real reason: if the parser's offset math or pyc reconstruction breaks, the
round-trip marshal.loads below stops working.
"""
from __future__ import annotations

import marshal
import struct
import zlib

from chimera.unpacking.pyinstaller import (
    PYINST_MAGIC, extract_pyinstaller, is_pyinstaller,
)


def _build_archive(script_src: str = "answer = 42\n", name: bytes = b"myscript\x00\x00",
                   etype: bytes = b"s") -> bytes:
    co = compile(script_src, "<t>", "exec")
    body = marshal.dumps(co)
    comp = zlib.compress(body)
    entry_size = 18 + len(name)                     # 18-byte header + name
    toc = struct.pack("!IIIIBc", entry_size, 0, len(comp), len(body), 1, etype) + name
    overlay_wo_cookie = comp + toc                  # [data][toc]
    length_of_pkg = len(overlay_wo_cookie) + 88     # includes the 88-byte cookie
    cookie = struct.pack("!8sIIII64s", PYINST_MAGIC, length_of_pkg,
                         len(comp), len(toc), 313, b"python313.dll")
    prefix = b"MZ" + b"\x00" * 256                  # stand-in for the PE stub
    return prefix + overlay_wo_cookie + cookie


def test_detects_pyinstaller_cookie():
    assert is_pyinstaller(_build_archive())
    assert not is_pyinstaller(b"MZ" + b"\x00" * 500)


def test_extracts_and_reconstructs_a_loadable_pyc(tmp_path):
    (tmp_path / "app.exe").write_bytes(_build_archive())
    r = extract_pyinstaller(tmp_path / "app.exe", tmp_path / "out")
    assert r.ok and r.python_version == 313
    assert "myscript" in r.entry_points

    pyc = tmp_path / "out" / "myscript.pyc"
    assert pyc.exists()
    # Strip the reconstructed 16-byte header and the code object must round-trip.
    code = marshal.loads(pyc.read_bytes()[16:])
    assert 42 in code.co_consts


def test_non_pyinstaller_binary_is_rejected(tmp_path):
    (tmp_path / "plain.bin").write_bytes(b"\x7fELF" + b"\x00" * 100)
    r = extract_pyinstaller(tmp_path / "plain.bin", tmp_path / "out")
    assert r.ok is False and "not a PyInstaller" in r.error


def test_entry_name_traversal_is_refused(tmp_path):
    # A TOC entry named "../escape" must not write outside out_dir.
    (tmp_path / "evil.exe").write_bytes(
        _build_archive(name=b"../escape\x00", etype=b"s"))
    r = extract_pyinstaller(tmp_path / "evil.exe", tmp_path / "out")
    assert r.ok
    assert not (tmp_path / "escape.pyc").exists()   # never escaped the tree


def test_tail_detector_finds_cookie_without_reading_whole_file(tmp_path):
    from chimera.unpacking.pyinstaller import is_pyinstaller_file
    big = tmp_path / "frozen.exe"
    big.write_bytes(b"MZ" + b"\x00" * (2 << 20) + _build_archive())   # ~2MB + archive
    assert is_pyinstaller_file(big) is True
    plain = tmp_path / "plain.exe"
    plain.write_bytes(b"MZ" + b"\x00" * 4096)
    assert is_pyinstaller_file(plain) is False
