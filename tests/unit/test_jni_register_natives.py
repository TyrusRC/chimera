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
