"""Unit tests for the ObjC callsite extractor."""
from __future__ import annotations


def test_extractor_resolves_plus_class_method_call():
    """+[Greeter sharedInstance] - class method on a known class symbol."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.AppDelegate.application_",
            "ops": [
                {"offset": 0x100456000, "opcode": "adrp", "operands": ["x0", 0x100300000]},
                {"offset": 0x100456004, "opcode": "add",  "operands": ["x0", "x0", 0x10]},
                {"offset": 0x100456008, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x10045600c, "opcode": "add",  "operands": ["x1", "x1", 0x40]},
                {"offset": 0x100456010, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x100456014, "opcode": "ret", "operands": []},
            ],
        },
    }
    class_symbols = {"Greeter"}
    cstring_pool = {0x100200040: "sharedInstance"}

    # The class symbol's address must be discoverable. We pass it via a parallel map.
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=class_symbols,
        cstring_pool=cstring_pool,
        class_address_to_name={0x100300010: "Greeter"},
    )
    assert len(callsites) == 1
    cs = callsites[0]
    assert cs["selector"] == "sharedInstance"
    assert cs["receiver_class"] == "Greeter"
    assert cs["caller"] == "0x100456000"
    assert cs["addr"] == "0x100456010"


def test_extractor_resolves_self_dispatch_via_entry_x0_save():
    """[self foo:] - receiver is x0 saved at function entry (mov x19, x0)."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.LoginVC.handle_",
            "ops": [
                {"offset": 0x100456000, "opcode": "mov", "operands": ["x19", "x0"]},
                {"offset": 0x100456004, "opcode": "mov", "operands": ["x0", "x19"]},
                {"offset": 0x100456008, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x10045600c, "opcode": "add",  "operands": ["x1", "x1", 0x80]},
                {"offset": 0x100456010, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x100456014, "opcode": "ret", "operands": []},
            ],
        },
    }
    cstring_pool = {0x100200080: "validate:"}

    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool=cstring_pool,
        class_address_to_name={},
    )
    assert len(callsites) == 1
    assert callsites[0]["selector"] == "validate:"
    assert callsites[0]["receiver_class"] == "self"


def test_extractor_drops_callsite_when_selector_unknown():
    """If x1 doesn't resolve to a string in cstring_pool, drop the callsite."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.test",
            "ops": [
                {"offset": 0x100456000, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x100456004, "opcode": "ret", "operands": []},
            ],
        },
    }
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool={},
        class_address_to_name={},
    )
    assert callsites == []


def test_extractor_emits_dynamic_when_receiver_unknown_but_selector_resolved():
    """Selector loaded from constant pool, but x0 is Unknown -> receiver_class=None."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.test",
            "ops": [
                {"offset": 0x100456000, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x100456004, "opcode": "add",  "operands": ["x1", "x1", 0xc0]},
                {"offset": 0x100456008, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x10045600c, "opcode": "ret", "operands": []},
            ],
        },
    }
    cstring_pool = {0x1002000c0: "doSomething"}
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool=cstring_pool,
        class_address_to_name={},
    )
    assert len(callsites) == 1
    assert callsites[0]["selector"] == "doSomething"
    assert callsites[0]["receiver_class"] is None


def test_extractor_handles_hex_string_keys_in_cstring_pool():
    """cstring_pool may use hex string keys (lowercase or uppercase)."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    # Use 0xA0 so the address has a hex letter - lowercase/uppercase forms
    # produce distinct strings ('0x1002000a0' vs '0x1002000A0').
    per_function_disasm = {
        "0x100456000": {
            "name": "sym.test",
            "ops": [
                {"offset": 0x100456000, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x100456004, "opcode": "add",  "operands": ["x1", "x1", 0xA0]},
                {"offset": 0x100456008, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x10045600c, "opcode": "ret", "operands": []},
            ],
        },
    }
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool={"0x1002000a0": "lowercase"},  # lowercase hex string
        class_address_to_name={},
    )
    assert len(callsites) == 1
    assert callsites[0]["selector"] == "lowercase"

    # Uppercase-only form must also resolve (covers the f"0x{addr:X}" branch).
    callsites_upper_only = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool={"0x1002000A0": "uppercase"},
        class_address_to_name={},
    )
    assert callsites_upper_only[0]["selector"] == "uppercase"

    # When both forms are present, lowercase wins (matches `hex(addr)` first).
    callsites_both = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool={"0x1002000a0": "lowercase", "0x1002000A0": "skipme"},
        class_address_to_name={},
    )
    # Lowercase form takes precedence (matches `hex(addr)`)
    assert callsites_both[0]["selector"] == "lowercase"
