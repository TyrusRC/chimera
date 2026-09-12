"""emulate_image input_buffers: run a buffer-in / buffer-out transform routine.

The `input_buffers` parameter is what turns the full-image emulator into a
decompressor / string-decrypt / hash-of-buffer oracle — you inject the input at
a scratch VA, point an arg register at it, and read the output back. This drives
a hand-assembled leaf that computes out = ~in over the first dword.
"""
import pytest

from chimera.dynamic.emulate import unicorn_available
from chimera.dynamic.emulate_image import emulate_image

# mov eax,[rcx] ; not eax ; mov [rdx],eax ; ret
_CODE = bytes([0x8B, 0x01, 0xF7, 0xD0, 0x89, 0x02, 0xC3])


@pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")
def test_input_buffers_transform_roundtrip():
    code_va, in_va, out_va = 0x1000, 0x2000, 0x3000
    res = emulate_image(
        sections=[(code_va, _CODE)],
        entry=code_va,
        exec_ranges=[(code_va, code_va + len(_CODE))],
        args=(in_va, out_va),
        this_ptr=None,                                  # rcx is a real pointer arg, not `this`
        input_buffers=((in_va, b"\x01\x02\x03\x04"), (out_va, b"\x00\x00\x00\x00")),
        read_back=((out_va, 4),),
        watch_ascii=False,
    )
    assert res["available"] and res["ok"] and res["returned"]
    # ~0x04030201 = 0xFBFCFDFE -> little-endian bytes fe fd fc fb
    assert res["read_back"][0]["hex"] == "fefdfcfb"


@pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")
def test_input_buffers_absent_leaves_scratch_zeroed():
    """Without an input buffer the scratch VA reads back as freshly-mapped zeros."""
    code_va, in_va, out_va = 0x1000, 0x2000, 0x3000
    res = emulate_image(
        sections=[(code_va, _CODE)],
        entry=code_va,
        exec_ranges=[(code_va, code_va + len(_CODE))],
        args=(in_va, out_va),
        this_ptr=None,
        read_back=((out_va, 4),),
        watch_ascii=False,
    )
    assert res["ok"]
    assert res["read_back"][0]["hex"] == "ffffffff"     # ~0
