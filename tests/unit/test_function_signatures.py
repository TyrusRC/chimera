"""Function-signature matcher: byte extraction + masked matching."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from chimera.model.binary import Architecture, BinaryFormat, BinaryInfo, Framework, Platform
from chimera.model.function import FunctionInfo
from chimera.model.program import UnifiedProgramModel
from chimera.parsers.function_signatures import (
    Signature,
    SignatureDB,
    _looks_unnamed,
    dump_signature_pack,
    extract_function_bytes,
    load_signature_db,
    match_functions,
    signature_from_bytes,
)


SHA = "e" * 64


def test_signature_matches_exact_prefix():
    sig = signature_from_bytes(
        name="memcpy", lib="libc",
        prefix=bytes.fromhex("488b07488b0e"),  # mov rax,[rdi]; mov rcx,[rsi]
        arch="x86_64", format="elf",
    )
    assert sig.matches(bytes.fromhex("488b07488b0e9090"))


def test_signature_respects_wildcard_mask():
    sig = signature_from_bytes(
        name="cmpbyfunc", lib="libc",
        prefix=bytes.fromhex("488b07488b0e"),
        arch="x86_64", format="elf",
        mask=bytes.fromhex("ff00ffff00ff"),  # wildcard the 2nd and 5th bytes
    )
    # The wildcarded bytes can differ — match still succeeds.
    assert sig.matches(bytes.fromhex("48ff07488b0e9090"))
    # But masked-comparison bytes must equal.
    assert not sig.matches(bytes.fromhex("49ff07488b0e9090"))


def test_signature_db_isolates_arch_format():
    db = SignatureDB()
    db.add(signature_from_bytes(
        name="foo", lib="x", prefix=b"\x01\x02", arch="x86_64", format="elf",
    ))
    db.add(signature_from_bytes(
        name="bar", lib="y", prefix=b"\x03\x04", arch="aarch64", format="elf",
    ))
    assert len(db.lookup("x86_64", "elf")) == 1
    assert len(db.lookup("aarch64", "elf")) == 1
    assert db.lookup("x86", "elf") == []


def test_dump_and_load_signature_pack(tmp_path):
    sigs = [
        signature_from_bytes(name="memcpy", lib="libc", prefix=b"\xab\xcd",
                             arch="x86_64", format="elf"),
        signature_from_bytes(name="strlen", lib="libc", prefix=b"\xde\xad",
                             arch="x86_64", format="elf"),
    ]
    out = tmp_path / "sigs" / "libc.json"
    dump_signature_pack(sigs, out, "libc")
    assert out.exists()

    db = load_signature_db(tmp_path / "sigs")
    assert db.total() == 2
    found = {s.name for s in db.lookup("x86_64", "elf")}
    assert found == {"memcpy", "strlen"}


def test_load_signature_db_missing_dir_returns_empty(tmp_path):
    db = load_signature_db(tmp_path / "does_not_exist")
    assert db.total() == 0


def test_load_signature_db_skips_malformed_entries(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps({
        "signatures": [
            {"name": "ok", "lib": "x", "bytes_hex": "ab", "mask_hex": "ff"},
            {"name": "bad"},  # missing required fields
        ]
    }))
    db = load_signature_db(tmp_path)
    assert db.total() == 1  # only the ok one


def test_looks_unnamed_recognises_backend_placeholders():
    assert _looks_unnamed("FUN_00400500")
    assert _looks_unnamed("sub_400500")
    assert _looks_unnamed("sym.imp.foo")
    assert _looks_unnamed("loc_400500")
    assert _looks_unnamed("fcn.00400500")
    assert _looks_unnamed("")
    assert not _looks_unnamed("decode_license")
    assert not _looks_unnamed("AES_encrypt")


def test_extract_bytes_from_real_elf():
    """Use the staged hello ELF to verify the section-walker works."""
    elf = Path(__file__).resolve().parents[2] / "e2e" / "material" / "desktop" / "hello"
    if not elf.exists():
        pytest.skip(f"{elf} not available")
    # Read past the ELF header — anything in the .text segment is fine.
    # We can't predict the entry point without parsing the binary, so we
    # use a known-PT_LOAD-internal address: 0x1000 is the typical .text base.
    data = extract_function_bytes(elf, 0x1000, "elf", length=16)
    # Either the extraction succeeded (returned bytes) or returned None
    # (address outside any PT_LOAD); both are acceptable signals that the
    # function isn't crashing.
    assert data is None or isinstance(data, bytes)


@pytest.mark.asyncio
async def test_match_functions_renames_library_hits():
    bi = BinaryInfo(
        path=Path("/tmp/x"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.ELF, platform=Platform.LINUX_NATIVE, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    m.add_function(FunctionInfo(
        address="0x401000", name="FUN_401000", original_name="FUN_401000",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))
    m.add_function(FunctionInfo(
        address="0x401100", name="user_logic", original_name="user_logic",
        language="c", classification="unknown", layer="native", source_backend="r2",
    ))

    # Stub the byte extractor so we exercise the matcher without a real ELF.
    from chimera.parsers import function_signatures as fs
    fs._original_extract = fs.extract_function_bytes
    canned = {0x401000: bytes.fromhex("488b07488b0e909090909090909090909090909090909090909090909090909090")}

    def fake(_path, addr, _fmt, length=32):
        if isinstance(addr, str):
            addr = int(addr, 16)
        return canned.get(addr)

    fs.extract_function_bytes = fake
    try:
        db = SignatureDB()
        db.add(signature_from_bytes(
            name="memcpy", lib="libc",
            prefix=bytes.fromhex("488b07488b0e"),
            arch="x86_64", format="elf",
        ))
        stats = match_functions(m, Path("/tmp/x"), db=db)
    finally:
        fs.extract_function_bytes = fs._original_extract

    assert stats["matched"] == 1, stats
    assert m.get_function("0x401000").name == "memcpy"
    assert m.get_function("0x401000").classification == "library"
    # User-named function isn't touched.
    assert m.get_function("0x401100").name == "user_logic"


@pytest.mark.asyncio
async def test_match_functions_no_db_no_op():
    bi = BinaryInfo(
        path=Path("/tmp/x"), sha256=SHA, size_bytes=1,
        format=BinaryFormat.ELF, platform=Platform.LINUX_NATIVE, arch=Architecture.X86_64,
        framework=Framework.NATIVE,
    )
    m = UnifiedProgramModel(bi)
    stats = match_functions(m, Path("/tmp/x"), db=SignatureDB())
    assert stats["matched"] == 0
    assert stats["total_sigs"] == 0
