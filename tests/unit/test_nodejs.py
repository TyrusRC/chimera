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

def test_extract_nexe_returns_content_and_resources():
    js, resources = extract_nexe(_nexe(_JS, resources=b"RESRC-BLOB"))
    assert js == _JS
    assert resources == b"RESRC-BLOB"


def test_extract_nexe_inflates_gzip_bundle():
    packed = gzip.compress(_JS)
    js, _ = extract_nexe(_nexe(packed))
    assert js == _JS


def test_extract_node_js_nexe_unpacks_resource_zip(tmp_path):
    # Modern nexe puts the real app files in the resource blob as a ZIP; the
    # content bundle is just the bootstrap loader. Verified against a real nexe
    # binary — the app source lives in resources/snapshot/app.js.
    import io
    import zipfile
    from pathlib import Path

    app = b'const FLAG = "flare-on";\nconsole.log(FLAG);\n'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("snapshot/app.js", app)
    zip_blob = buf.getvalue()

    exe = tmp_path / "myapp"
    exe.write_bytes(_nexe(b"!(function(){process.__nexe={}})();", resources=zip_blob))
    r = extract_node_js(exe, tmp_path / "out")
    assert r.ok and r.kind == "nexe"
    assert r.resource_files and any(f.endswith("snapshot/app.js") for f in r.resource_files)
    recovered = Path(r.resource_files[0]).read_bytes()
    assert recovered == app


def test_extract_node_js_nexe_resource_zip_rejects_traversal(tmp_path):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.js", b"pwned")
        zf.writestr("ok.js", b"safe")
    exe = tmp_path / "myapp"
    exe.write_bytes(_nexe(b"boot", resources=buf.getvalue()))
    r = extract_node_js(exe, tmp_path / "out")
    # the traversal entry is skipped; the safe one is kept
    assert not any("evil" in f for f in r.resource_files)
    assert any(f.endswith("ok.js") for f in r.resource_files)
    assert not (tmp_path / "evil.js").exists()


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


def test_extract_sea_prefers_modern_blob_over_coincidental_legacy_magic():
    # Regression for the real Node v24 SEA bug: an earlier coincidental magic
    # hit that parses as the permissive legacy layout (flags=0 + a big printable
    # region) must NOT shadow the true modern blob (exec_argv_extension +
    # code_path + code) found later. Modern-layout matching runs first.
    real = _sea_v22(_JS)
    filler = b"A" * 200  # a printable region that legacy parsing would grab
    fake = _SEA_MAGIC_LE + struct.pack("<I", 0) + struct.pack("<Q", len(filler)) + filler
    data = b"\x00" * 16 + fake + b"\x00" * 16 + real
    code, _ = extract_sea(data)
    assert code == _JS


def test_extract_sea_rejects_invalid_flags():
    # A magic hit whose flags word has bits outside SeaFlags (0..5) is a
    # coincidence, not a header — must not parse.
    import pytest
    bad = _SEA_MAGIC_LE + struct.pack("<I", 0xDEADBEEF) + struct.pack("<Q", 64) + b"x" * 64
    with pytest.raises(ValueError):
        extract_sea(bad)


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


# --- Electron asar -----------------------------------------------------------
# Layout verified against a real `npx asar pack`: four LE uint32 sizes
# (4, header_size, header_size-4, json_len), the JSON tree (4-byte padded),
# then the concatenated file bodies starting at 8 + header_size.

def _asar(entries, unpacked=()):
    """Build a real-format asar. `entries`: [(relpath, bytes)]; `unpacked`:
    [relpath] for entries whose bytes live outside the archive."""
    import json as _json

    tree = {"files": {}}

    def insert(path, node):
        parts = path.split("/")
        cur = tree
        for p in parts[:-1]:
            cur = cur["files"].setdefault(p, {"files": {}})
        cur["files"][parts[-1]] = node

    bodies = b""
    offset = 0
    for path, body in entries:
        insert(path, {"size": len(body), "offset": str(offset)})
        bodies += body
        offset += len(body)
    for path in unpacked:
        insert(path, {"size": 0, "offset": str(offset), "unpacked": True})

    hdr = _json.dumps(tree).encode()
    pad = (-len(hdr)) % 4
    header_size = 8 + len(hdr) + pad
    prefix = struct.pack("<4I", 4, header_size, header_size - 4, len(hdr))
    return prefix + hdr + b"\x00" * pad + bodies


def test_detect_asar():
    from chimera.unpacking.nodejs import detect_asar
    assert detect_asar(_asar([("index.js", _JS)]))
    # a random blob that merely starts with 0x04 must not be mistaken for asar
    assert not detect_asar(b"\x04\x00\x00\x00" + b"A" * 128)
    assert not detect_asar(b"\x7fELF" + b"\x00" * 256)


def test_extract_asar_nested_and_entry(tmp_path):
    from pathlib import Path
    arc = tmp_path / "app.asar"
    arc.write_bytes(_asar([
        ("index.js", _JS),
        ("lib/util.js", b"module.exports = 1;\n"),
        ("package.json", b'{"main":"index.js"}'),
    ]))
    r = extract_node_js(arc, tmp_path / "out")
    assert r.ok and r.kind == "asar"
    # nested dir preserved, bytes intact
    got = {Path(p).name: Path(p).read_bytes() for p in r.resource_files}
    assert got["index.js"] == _JS
    assert got["util.js"] == b"module.exports = 1;\n"
    assert (tmp_path / "out" / "lib" / "util.js").exists()
    # entry hint prefers index.js
    assert r.out_file.endswith("index.js")


def test_extract_asar_flags_unpacked_entries(tmp_path):
    arc = tmp_path / "app.asar"
    arc.write_bytes(_asar([("index.js", _JS)], unpacked=["native.node"]))
    r = extract_node_js(arc, tmp_path / "out")
    assert r.ok and r.note and "unpacked" in r.note.lower()


def test_extract_asar_rejects_path_traversal(tmp_path):
    from pathlib import Path
    arc = tmp_path / "evil.asar"
    arc.write_bytes(_asar([("../../escape.js", b"pwned"), ("safe.js", _JS)]))
    r = extract_node_js(arc, tmp_path / "out")
    assert r.ok
    # the traversal entry is dropped; only the safe file is written under out/
    assert not (tmp_path / "escape.js").exists()
    assert all(str(Path(p).resolve()).startswith(str((tmp_path / "out").resolve()))
               for p in r.resource_files)
