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


# mov eax,[rdi] ; not eax ; mov [rsi],eax ; ret   (System V arg regs)
_CODE_SYSV = bytes([0x8B, 0x07, 0xF7, 0xD0, 0x89, 0x06, 0xC3])


@pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")
def test_input_buffers_sysv_abi():
    """input_buffers must work under the SysV ABI (args in rdi/rsi, not rcx/rdx)."""
    code_va, in_va, out_va = 0x1000, 0x2000, 0x3000
    res = emulate_image(
        sections=[(code_va, _CODE_SYSV)],
        entry=code_va,
        exec_ranges=[(code_va, code_va + len(_CODE_SYSV))],
        abi="sysv",
        args=(in_va, out_va),
        this_ptr=None,
        input_buffers=((in_va, b"\x01\x02\x03\x04"), (out_va, b"\x00\x00\x00\x00")),
        read_back=((out_va, 4),),
        watch_ascii=False,
    )
    assert res["ok"] and res["returned"]
    assert res["read_back"][0]["hex"] == "fefdfcfb"


@pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")
def test_input_buffers_overlap_last_write_wins():
    """Two buffers at the same VA: the later one overwrites the earlier."""
    code_va, in_va, out_va = 0x1000, 0x2000, 0x3000
    res = emulate_image(
        sections=[(code_va, _CODE)],
        entry=code_va,
        exec_ranges=[(code_va, code_va + len(_CODE))],
        args=(in_va, out_va),
        this_ptr=None,
        input_buffers=(
            (in_va, b"\xAA\xBB\xCC\xDD"),   # written first
            (in_va, b"\x01\x02\x03\x04"),   # overlaps → wins
            (out_va, b"\x00\x00\x00\x00"),
        ),
        read_back=((out_va, 4),),
        watch_ascii=False,
    )
    assert res["ok"]
    assert res["read_back"][0]["hex"] == "fefdfcfb"   # ~01020304, not ~AABBCCDD


@pytest.mark.skipif(not unicorn_available(), reason="unicorn not installed")
def test_input_buffers_large_multipage_injected_intact():
    """A buffer spanning many pages is mapped and written whole, not just page 0."""
    code_va, in_va, out_va = 0x1000, 0x10000, 0x40000
    big = bytes((i * 7 + 3) & 0xFF for i in range(0x5000))   # 5 pages, non-trivial
    res = emulate_image(
        sections=[(code_va, _CODE)],
        entry=code_va,
        exec_ranges=[(code_va, code_va + len(_CODE))],
        args=(in_va, out_va),
        this_ptr=None,
        input_buffers=((in_va, big), (out_va, b"\x00\x00\x00\x00")),
        read_back=((in_va, len(big)), (out_va, 4)),
        watch_ascii=False,
    )
    assert res["ok"]
    # The whole multi-page input survived the mapping, including the last page.
    assert bytes.fromhex(res["read_back"][0]["hex"]) == big
    # And the leaf still transformed the first dword of it.
    expected = (~int.from_bytes(big[:4], "little")) & 0xFFFFFFFF
    assert res["read_back"][1]["hex"] == expected.to_bytes(4, "little").hex()


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
