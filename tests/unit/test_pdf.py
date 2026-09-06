"""Tests for the static PDF triage module (recon / traps / decrypt / inline images).

Structure and inline-image cases use small synthetic PDFs built inline.
The crypto cases are pinned to *independent* known-answer vectors:

* RC4  -> RFC 6229 test vector (40-bit key 01 02 03 04 05).
* R6 hash (ISO 32000-2 Algorithm 2.B) and the empty-password file-key
  derivation -> a real spec-conformant `/U` + `/UE` triple and its file
  encryption key, carried here only as opaque hex constants.

Nothing here executes or renders a document.
"""
from __future__ import annotations

import pytest

from chimera.unpacking import pdf, pdfcrypt


# --- independent KATs -------------------------------------------------------

# RFC 6229, RC4 keystream for key 0x0102030405, first 16 bytes at offset 0.
def test_rc4_matches_rfc6229_vector():
    ks = pdfcrypt.rc4(bytes.fromhex("0102030405"), b"\x00" * 16)
    assert ks.hex() == "b2396305f03dc027ccc3524a0a1118a8"


# A real R6 `/U`: 32-byte hash || 8-byte validation salt || 8-byte key salt.
_U = bytes.fromhex(
    "18fc6dfedff4b5e8e401c248d2bcf8b66bebbcda0ecd1d63154254953666d2c5"
    "a4c38d549f59144df11b6a1831324a77"
)
_UE = bytes.fromhex("13d23367fb9f891065947d20fb93834ac4567762b6fbd00672b35748617d3feb")
_FILE_KEY = bytes.fromhex(
    "c860b9bfbba2040768041ea9ab5ccaffde767e715aec742b588083c0e1ad7bc1"
)


def test_hash_r6_validates_empty_password_against_U():
    # Algorithm 2.A validation: Hash_2B(password + validation_salt) == U[:32].
    assert pdfcrypt.hash_r6(b"", _U[32:40]) == _U[:32]


def test_hash_r6_is_salt_sensitive():
    a = pdfcrypt.hash_r6(b"", _U[32:40])
    b = pdfcrypt.hash_r6(b"", _U[40:48])
    assert a != b


def test_derive_file_key_empty_password():
    key = pdfcrypt.derive_file_key_r6(b"", _U, _UE)
    assert key == _FILE_KEY


def test_derive_file_key_wrong_password_returns_none():
    assert pdfcrypt.derive_file_key_r6(b"nope", _U, _UE) is None


def test_aesv3_decrypt_roundtrips_with_file_key():
    from Crypto.Cipher import AES  # provided by the [pdf] extra
    from Crypto.Util.Padding import pad

    key = _FILE_KEY
    plaintext = b"the quick brown fox jumps"
    iv = bytes(range(16))
    blob = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    assert pdfcrypt.aesv3_decrypt(key, blob) == plaintext


# --- lenient recon + parser-differential trap detector ----------------------

# A tiny hand-built PDF with no xref and no %%EOF, a duplicate object 2, and
# two /Root entries in the trailer -- one plain, one name-hex-obfuscated
# (`/#52#6F#6F#74` decodes to `/Root`) pointing at a different object.
_TRAP_PDF = (
    b"%PDF-2.0\n"
    b"1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
    b"2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
    b"% 2 0 obj\n% <<>>\n% endobj\n"          # commented-out decoy -> commented_object
    b"3 0 obj\n<</Type/Page/Parent 2 0 R>>\nendobj\n"
    b"3 0 obj\n<</Type/Page/Parent 2 0 R>>\nendobj\n"   # genuine duplicate -> duplicate_object
    b"trailer\n<<\n  /Root 2 0 R\n  /#52#6F#6F#74 1 0 R\n>>\n"
)


def _trap_kinds(recon):
    return {t.kind for t in recon.traps}


def test_recon_recovers_objects_without_xref():
    r = pdf.recon(_TRAP_PDF)
    assert (1, 0) in r.objects and (3, 0) in r.objects


def test_recon_reports_pdf_version():
    assert pdf.recon(_TRAP_PDF).version == "2.0"


def test_trap_missing_xref_and_eof():
    kinds = _trap_kinds(pdf.recon(_TRAP_PDF))
    assert "missing_xref" in kinds
    assert "missing_eof" in kinds


def test_trap_name_hex_obfuscated_key():
    # `/#52#6F#6F#74` must be flagged and decoded to `Root`.
    traps = [t for t in pdf.recon(_TRAP_PDF).traps if t.kind == "name_hex_key"]
    assert traps and any("Root" in t.detail for t in traps)


def test_trap_multiple_roots_resolves_each_target():
    r = pdf.recon(_TRAP_PDF)
    assert any(t.kind == "multiple_roots" for t in r.traps)
    targets = {(root.num, root.gen) for root in r.roots}
    assert (1, 0) in targets and (2, 0) in targets


def test_trap_duplicate_object():
    assert "duplicate_object" in _trap_kinds(pdf.recon(_TRAP_PDF))


def test_recon_recovers_last_object_missing_endobj():
    # A hand-crafted PDF often ends the final object at `>>` with no `endobj`
    # (the /Encrypt dict is a common victim). It must still be recovered.
    data = (
        b"%PDF-2.0\n"
        b"1 0 obj\n<</Type/Catalog>>\nendobj\n"
        b"7 0 obj\n<</Filter/Standard/V 5/R 6>>\n"          # no endobj, EOF
    )
    r = pdf.recon(data)
    assert (7, 0) in r.objects
    assert b"/V 5" in r.objects[(7, 0)].dict_bytes


def test_recon_to_dict_is_json_shaped():
    d = pdf.recon(_TRAP_PDF).to_dict()
    assert d["version"] == "2.0"
    assert isinstance(d["traps"], list)
    assert isinstance(d["roots"], list)


# --- inline image extraction ------------------------------------------------

def _ahx(raw: bytes) -> bytes:
    return raw.hex().encode() + b">"


def test_inline_image_ascii_hex_decodes_to_raw():
    raw = bytes([10, 200, 30, 255])
    content = (
        b"q 4 0 0 1 0 0 cm\n"
        b"BI /W 4 /H 1 /CS /G /BPC 8 /F /AHx ID\n" + _ahx(raw) + b"\nEI Q\n"
    )
    imgs = pdf.inline_images(content)
    assert len(imgs) == 1
    assert imgs[0].params["W"] == 4 and imgs[0].params["H"] == 1
    assert imgs[0].data == raw
    assert imgs[0].codec == "raw"


def test_inline_image_dct_left_as_jpeg_bytes():
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\xff\xd9"  # minimal JPEG-ish marker frame
    content = b"BI /W 1 /H 1 /CS /G /BPC 8 /F [/AHx /DCT] ID\n" + _ahx(jpeg) + b"\nEI\n"
    imgs = pdf.inline_images(content)
    assert len(imgs) == 1
    assert imgs[0].codec == "jpeg"
    assert imgs[0].data == jpeg  # AHx peeled; DCT (JPEG) left intact


def test_inline_image_none_when_absent():
    assert pdf.inline_images(b"q 1 0 0 1 0 0 cm (hi) Tj Q") == []


# --- one-shot pdf_tour ------------------------------------------------------

def test_pdf_tour_surfaces_traps_and_objects(tmp_path):
    p = tmp_path / "t.pdf"
    p.write_bytes(_TRAP_PDF)
    tour = pdf.pdf_tour(p)
    d = tour.to_dict()
    assert d["encrypted"] is False
    assert any(t["kind"] == "multiple_roots" for t in d["traps"])
    assert d["object_count"] >= 3
