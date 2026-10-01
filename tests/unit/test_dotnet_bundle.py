"""Tests for the .NET single-file bundle extractor (unpacking/dotnet_bundle.py)."""
from __future__ import annotations

import struct
import zlib

from chimera.unpacking.dotnet_bundle import (
    BUNDLE_SIGNATURE, extract_bundle, is_single_file_bundle, parse_manifest,
)


def _7bit(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            break
    return bytes(out)


def _str(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _7bit(len(raw)) + raw


def _deflate(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def _build_bundle(files, *, major=6, minor=0, bundle_id="TESTID00"):
    """files: list of (path, type_int, content_bytes, compress_bool).
    Layout: [bodies][header][int64 header_offset][SIGNATURE]."""
    bodies = bytearray()
    entries = []  # (offset, size, csize, type, path)
    for path, ftype, content, compress in files:
        offset = len(bodies)
        if compress:
            body = _deflate(content)
            entries.append((offset, len(content), len(body), ftype, path))
            bodies += body
        else:
            entries.append((offset, len(content), 0, ftype, path))
            bodies += content

    header = bytearray()
    header += struct.pack("<II", major, minor)
    header += struct.pack("<i", len(files))
    header += _str(bundle_id)
    if major >= 2:
        header += b"\x00" * 32   # deps + runtimeconfig locations
        header += b"\x00" * 8    # flags
    for offset, size, csize, ftype, path in entries:
        header += struct.pack("<qqq", offset, size, csize)
        header += bytes([ftype])
        header += _str(path)

    header_offset = len(bodies)
    blob = bytes(bodies) + bytes(header)
    blob += struct.pack("<q", header_offset) + BUNDLE_SIGNATURE
    return blob


def test_is_single_file_bundle_true_and_false(tmp_path):
    blob = _build_bundle([("App.dll", 1, b"MANAGED", False)])
    p = tmp_path / "app.exe"
    p.write_bytes(blob)
    assert is_single_file_bundle(p)
    assert is_single_file_bundle(blob)

    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not a bundle" * 100)
    assert not is_single_file_bundle(plain)


def test_parse_manifest_fields():
    blob = _build_bundle(
        [("App.dll", 1, b"X", False), ("App.deps.json", 3, b"{}", False)],
        bundle_id="ABC123",
    )
    header, entries = parse_manifest(blob)
    assert header["major"] == 6 and header["bundle_id"] == "ABC123"
    assert [e.path for e in entries] == ["App.dll", "App.deps.json"]
    assert entries[1].type == "DepsJson"


def test_extract_roundtrip_plain_compressed_and_subdir(tmp_path):
    compressible = b"AAAA" * 500  # inflates far past its deflate size
    blob = _build_bundle([
        ("App.dll", 1, b"MANAGED-APP", False),
        ("App.deps.json", 3, b'{"deps":1}', False),
        ("System.Private.CoreLib.dll", 1, b"FRAMEWORK", False),
        ("cs/App.resources.dll", 1, b"SAT", False),
        ("big.dll", 1, compressible, True),
    ])
    exe = tmp_path / "TestApp.exe"
    exe.write_bytes(blob)

    r = extract_bundle(exe, tmp_path / "out")
    assert r.ok and r.file_count == 5 and len(r.extracted) == 5
    out = tmp_path / "out"
    # plain + compressed bodies recovered byte-exact
    assert (out / "App.dll").read_bytes() == b"MANAGED-APP"
    assert (out / "big.dll").read_bytes() == compressible
    # subdir tree preserved
    assert (out / "cs" / "App.resources.dll").read_bytes() == b"SAT"
    # deps.json surfaced, and the app DLL (not framework/satellite) is picked
    assert r.deps_json and r.deps_json.endswith("App.deps.json")
    assert r.main_assembly.endswith("App.dll")
    assert "System.Private" not in r.main_assembly


def test_main_assembly_prefers_host_name(tmp_path):
    # When a DLL matches the host stem it wins over other non-framework ones.
    blob = _build_bundle([
        ("Other.dll", 1, b"o", False),
        ("TestApp.dll", 1, b"m", False),
    ])
    exe = tmp_path / "TestApp.exe"
    exe.write_bytes(blob)
    r = extract_bundle(exe, tmp_path / "out")
    assert r.main_assembly.endswith("TestApp.dll")


def test_extract_non_bundle_errors(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00" * 4096)
    r = extract_bundle(p, tmp_path / "out")
    assert not r.ok and r.error
