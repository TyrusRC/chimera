"""PE native-runtime fingerprinting and section-entropy anomaly flagging.

Both are pure functions over already-parsed inputs, so the tests build tiny
synthetic inputs rather than real PEs.
"""
from __future__ import annotations

from dataclasses import dataclass

from chimera.frameworks.native_pe import detect_native_runtime
from chimera.parsers.pe_header import entropy_anomalies


# --- VB / twinBASIC detection ----------------------------------------------

def test_detects_twinbasic_by_ascii_marker():
    rt = detect_native_runtime(b"....twinBASIC Internal Error....", [])
    assert rt is not None and rt[0] == "vb6"
    assert "twinBASIC" in rt[1]


def test_detects_vb6_compatible_by_thunderrt6_class():
    rt = detect_native_runtime(b"junk ThunderRT6FormDC junk", [])
    assert rt is not None and rt[0] == "vb6"


def test_detects_thunderrt6_in_utf16():
    data = b"x" + "ThunderRT6Main".encode("utf-16-le") + b"y"
    rt = detect_native_runtime(data, [])
    assert rt is not None and rt[0] == "vb6"


def test_detects_classic_vb6_by_import():
    rt = detect_native_runtime(b"no markers here", ["MSVBVM60.DLL", "KERNEL32.dll"])
    assert rt is not None and rt[0] == "vb6"
    assert "VB6" in rt[1]


def test_returns_none_for_plain_native():
    assert detect_native_runtime(b"just some C code strings", ["KERNEL32.dll"]) is None


# --- section entropy anomalies ---------------------------------------------

@dataclass
class _Sec:
    name: str
    raw_size: int
    entropy: float


def test_flags_large_high_entropy_section():
    secs = [
        _Sec(".text", 690_000, 6.40),
        _Sec(".data", 1_980_000, 7.96),   # ~70% of a 2.72MB file, near-random
        _Sec(".rsrc", 4_600, 3.64),
    ]
    hits = entropy_anomalies(secs, 2_721_792)
    names = {h["name"] for h in hits}
    assert names == {".data"}
    assert hits[0]["fraction"] > 0.5


def test_does_not_flag_small_high_entropy_section():
    # A tiny packed resource shouldn't raise the "encrypted payload" signal.
    secs = [_Sec(".rsrc", 512, 7.99)]
    assert entropy_anomalies(secs, 2_000_000) == []


def test_does_not_flag_normal_code_entropy():
    assert entropy_anomalies([_Sec(".text", 900_000, 6.4)], 1_000_000) == []
