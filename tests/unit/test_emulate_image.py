"""Full-image PE emulation core (emulate_image): stub externs, lazy-map, ASCII capture.

These are the capabilities emulate_function lacked (it maps only the function's
own bytes and halts at the first out-of-range call). The scenario below calls
an address outside the executable range (must be stubbed as a ret), reads an
unmapped address (must be lazily backed), writes "FLARE" (must be captured),
and returns (run must complete).
"""
import pytest

from chimera.dynamic.emulate_image import emulate_image, unicorn_available

pytestmark = pytest.mark.skipif(not unicorn_available(),
                                reason="unicorn not installed")

# entry 0x1000, executable range [0x1000, 0x2000). Instruction sequence:
#   mov rax, 0x50000        (48c7c000000500)  target OUTSIDE exec range
#   call rax                (ffd0)            -> stubbed as ret, continues
#   mov rbx, 0x900000       (48bb0000900000000000)  unmapped address
#   mov rcx, [rbx]          (488b0b)          -> lazily mapped, reads 0
#   mov dword [rsp-0x20],'FLAR' (c7442420464c4152)
#   mov byte  [rsp-0x1c],'E'    (c644242445)
#   ret                     (c3)              -> sentinel (completes)
_CODE = bytes.fromhex(
    "48c7c000000500" "ffd0" "48bb0000900000000000" "488b0b"
    "c7442420464c4152" "c644242445" "c3"
)


def test_emulate_image_stub_lazy_and_ascii():
    r = emulate_image(sections=[(0x1000, _CODE)], entry=0x1000,
                      exec_ranges=[(0x1000, 0x2000)])
    assert r["available"] is True
    assert r["ok"] is True and r["returned"] is True, r["error"]
    # the out-of-range call was stubbed rather than faulting
    assert "0x50000" in r["extern_calls"]
    # the write was captured as a printable run
    assert any("FLARE" in run["text"] for run in r["ascii_writes"]), r["ascii_writes"]


def test_emulate_image_without_stub_faults_on_extern():
    # with stubbing off, the call into unmapped/zero code does not cleanly return
    r = emulate_image(sections=[(0x1000, _CODE)], entry=0x1000,
                      exec_ranges=[(0x1000, 0x2000)], stub_externs=False,
                      watch_ascii=False, max_insns=5000)
    assert r["returned"] is False


def test_emulate_image_win64_first_arg_is_rcx():
    # mov rax, rcx ; ret  -> return_value must echo the win64 first arg (this_ptr)
    code = bytes.fromhex("4889c8" "c3")   # mov rax, rcx ; ret
    r = emulate_image(sections=[(0x1000, code)], entry=0x1000,
                      exec_ranges=[(0x1000, 0x2000)], args=(0x4141,), abi="win64")
    assert r["ok"] is True
    assert r["return_value"] == 0x4141
