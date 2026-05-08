from chimera.parsers.jni_register_natives import (
    find_register_natives_calls, RegisterNativesCall,
)


def test_finds_call_through_jnienv_function_pointer():
    # Synthetic per_function_disasm: a BLR through the env table at the
    # RegisterNatives slot (offset 0xd0 on AArch64; symbolic name
    # `*RegisterNatives`).
    per_func = {
        "0x1000": {
            "name": "JNI_OnLoad",
            "ops": [
                {"offset": "0x1000", "type": "mov", "opcode": "mov x0, x19", "disasm": "mov x0, x19"},
                {"offset": "0x1004", "type": "ucall", "opcode": "blr x9",
                 "disasm": "blr x9 ; [0xd0:8]=*RegisterNatives"},
                {"offset": "0x1008", "type": "ret", "opcode": "ret", "disasm": "ret"},
            ],
        },
    }
    calls = find_register_natives_calls(per_func)
    assert len(calls) == 1
    assert isinstance(calls[0], RegisterNativesCall)
    assert calls[0].caller_addr == "0x1000"
    assert calls[0].call_addr == "0x1004"


def test_recover_register_natives_minimal_table():
    from chimera.parsers.jni_register_natives import recover_register_natives
    # Pre-resolved inputs: caller's ops set x2 to a data-section addr and
    # x3 to a count immediate. The data blob holds 1 JNINativeMethod
    # entry: {name="decrypt", sig="([B)I", fnPtr=0x55500}.
    ops = [
        {"offset": "0x1000", "type": "mov", "disasm": "adrp x2, 0x40000"},
        {"offset": "0x1004", "type": "mov", "disasm": "add x2, x2, 0x100"},
        {"offset": "0x1008", "type": "mov", "disasm": "mov x3, #1"},
        {"offset": "0x100c", "type": "ucall", "disasm": "blr x9 ; *RegisterNatives"},
    ]
    # Caller fn passed in, plus a data-resolver shim mapping addresses
    # to bytes / strings / pointers.
    def resolve_string(addr):
        return {"0x40200": "decrypt", "0x40208": "([B)I"}.get(hex(addr))
    def resolve_qword(addr):
        return {"0x40100": 0x40200, "0x40108": 0x40208,
                "0x40110": 0x55500}.get(hex(addr))
    entries = recover_register_natives(
        ops=ops, call_idx=3,
        resolve_string=resolve_string,
        resolve_qword=resolve_qword,
    )
    assert len(entries) == 1
    e = entries[0]
    assert e.method_name == "decrypt"
    assert e.signature == "([B)I"
    assert e.fn_addr == "0x55500"
