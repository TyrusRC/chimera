import struct

from chimera.unpacking import polyglot


def _fake_fat():
    # CAFEBABE, nfat=1, one arch (cputype, subtype, offset, size, align)
    return struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, 4096, 16, 12)


def test_scan_finds_embedded_formats_at_offsets(tmp_path):
    fat = _fake_fat()
    blob = b"%PDF-1.7\n" + b"A" * 91          # pdf at 0, 100 bytes
    zip_at = len(blob)
    blob += b"PK\x03\x04" + b"B" * 40          # zip local header
    fat_at = len(blob)
    blob += fat + b"C" * 64
    f = tmp_path / "poly.bin"
    f.write_bytes(blob)

    hits = polyglot.scan(str(f))
    by = {h["format"]: h["offset"] for h in hits}
    assert by["pdf"] == 0
    assert by["zip"] == zip_at
    assert by["macho-fat"] == fat_at


def test_eicar_and_vhd_detected(tmp_path):
    blob = b"junk" + b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"pad" + b"conectix" + b"\x00" * 8
    f = tmp_path / "e.bin"
    f.write_bytes(blob)
    fmts = {h["format"] for h in polyglot.scan(str(f))}
    assert "eicar" in fmts and "vhd" in fmts


def test_bare_mz_without_pe_header_is_not_reported_as_pe(tmp_path):
    f = tmp_path / "t.bin"
    f.write_bytes(b"MZ" + b"not a real pe file, no PE header here" * 3)
    assert "pe" not in {h["format"] for h in polyglot.scan(str(f))}


def test_carve_extracts_bytes_at_offset(tmp_path):
    blob = b"HEADER" + b"PK\x03\x04payloadzip" + b"TRAILER"
    f = tmp_path / "c.bin"
    f.write_bytes(blob)
    out = tmp_path / "carved.zip"
    payload = b"PK\x03\x04payloadzip"
    n = polyglot.carve(str(f), offset=6, out_path=str(out), size=len(payload))
    assert out.read_bytes() == payload and n == len(payload)


def test_macho_fat_reports_slices(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(_fake_fat() + b"\x00" * 32)
    hit = next(h for h in polyglot.scan(str(f)) if h["format"] == "macho-fat")
    assert hit["slices"] and hit["slices"][0]["offset"] == 4096
