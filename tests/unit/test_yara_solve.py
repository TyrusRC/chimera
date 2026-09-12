"""yara-solve: synthesise a file that matches a YARA rule (Z3 + hash brute force).

Uses a tiny synthetic rule so the test is self-contained; skips cleanly when
the `solve` extra (z3) is not installed.
"""
from __future__ import annotations

import binascii

import pytest

from chimera.detection_engineering.yara_solve import solve_yara, z3_available

z3only = pytest.mark.skipif(not z3_available(), reason="z3 not installed")

# Pins "test1" five ways: direct ==, XOR arithmetic, the &128==0 precedence
# idiom, a range, and a brute-forced crc32 window.
_CRC1 = binascii.crc32(b"1") & 0xFFFFFFFF
_RULE = f"""
rule t {{
  condition:
    filesize == 5 and
    uint8(0) == 116 and
    uint8(0) & 128 == 0 and
    uint8(1) ^ 1 == 100 and
    uint8(2) > 114 and uint8(2) < 116 and
    uint8(3) + 0 == 116 and
    hash.crc32(4, 1) == {hex(_CRC1)}
}}
"""


@z3only
def test_solves_synthetic_rule_to_expected_bytes():
    r = solve_yara(_RULE)
    assert r["available"] and r["sat"]
    assert r["ascii"] == "test1"
    assert not r["unsupported_atoms"]
    assert r["pinned_hash_windows"] == 1
    # yara-python confirms when present; None when the module is absent.
    assert r["matched"] in (True, None)


@z3only
def test_reports_unsupported_atoms_without_crashing():
    rule = ("rule u { condition: filesize == 1 and uint8(0) == 65 and "
            "any of them }")
    r = solve_yara(rule)
    assert r["available"]
    assert any("of" in a or "them" in a for a in r["unsupported_atoms"])


@z3only
def test_size_override_when_no_filesize_atom():
    r = solve_yara("rule s { condition: uint8(0) == 90 }", size=1)
    assert r["sat"] and r["ascii"] == "Z"


def test_missing_z3_degrades_cleanly(monkeypatch):
    import chimera.detection_engineering.yara_solve as ys
    monkeypatch.setattr(ys, "z3_available", lambda: False)
    r = ys.solve_yara("rule x { condition: filesize == 1 }")
    assert r["available"] is False and "z3" in r["error"]
