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


def test_extractor_resolves_alloc_init_chain():
    """[[Greeter alloc] init] - first call alloc, second call init on AllocResult."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.test",
            "ops": [
                # Load _OBJC_CLASS_$_Greeter into x0
                {"offset": 0x100456000, "opcode": "adrp", "operands": ["x0", 0x100300000]},
                {"offset": 0x100456004, "opcode": "add",  "operands": ["x0", "x0", 0x10]},
                # bl objc_alloc - x0 becomes AllocResult("Greeter")
                {"offset": 0x100456008, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_alloc"},
                # Load "init" selector into x1
                {"offset": 0x10045600c, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x100456010, "opcode": "add",  "operands": ["x1", "x1", 0x100]},
                # bl objc_msgSend - should resolve receiver=Greeter, selector=init
                {"offset": 0x100456014, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
                {"offset": 0x100456018, "opcode": "ret", "operands": []},
            ],
        },
    }
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols={"Greeter"},
        cstring_pool={0x100200100: "init"},
        class_address_to_name={0x100300010: "Greeter"},
    )
    assert len(callsites) == 1
    assert callsites[0]["selector"] == "init"
    assert callsites[0]["receiver_class"] == "Greeter"


def test_extractor_resolves_super_dispatch():
    """[super foo] - bl objc_msgSendSuper2 marks receiver as 'super'."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.LoginVC.viewDidLoad",
            "ops": [
                {"offset": 0x100456000, "opcode": "adrp", "operands": ["x1", 0x100200000]},
                {"offset": 0x100456004, "opcode": "add",  "operands": ["x1", "x1", 0x40]},
                {"offset": 0x100456008, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSendSuper2"},
                {"offset": 0x10045600c, "opcode": "ret", "operands": []},
            ],
        },
    }
    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols=set(),
        cstring_pool={0x100200040: "viewDidLoad"},
        class_address_to_name={},
    )
    assert len(callsites) == 1
    assert callsites[0]["receiver_class"] == "super"


def test_extractor_emits_multiple_callsites_per_function():
    """A function with 3 objc_msgSend calls emits 3 records."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    ops = []
    addr = 0x100456000
    for i, sel_offset in enumerate([0x40, 0x80, 0xc0]):
        ops.extend([
            {"offset": addr, "opcode": "adrp", "operands": ["x0", 0x100300000]},
            {"offset": addr + 4, "opcode": "add", "operands": ["x0", "x0", 0x10]},
            {"offset": addr + 8, "opcode": "adrp", "operands": ["x1", 0x100200000]},
            {"offset": addr + 12, "opcode": "add", "operands": ["x1", "x1", sel_offset]},
            {"offset": addr + 16, "opcode": "bl", "operands": [], "target_sym": "sym.imp.objc_msgSend"},
        ])
        addr += 0x100
    ops.append({"offset": addr, "opcode": "ret", "operands": []})
    per_function_disasm = {"0x100456000": {"name": "sym.test", "ops": ops}}
    cstring_pool = {0x100200040: "a:", 0x100200080: "b:", 0x1002000c0: "c:"}

    callsites = extract_callsites(
        per_function_disasm=per_function_disasm,
        class_symbols={"Greeter"},
        cstring_pool=cstring_pool,
        class_address_to_name={0x100300010: "Greeter"},
    )
    assert [cs["selector"] for cs in callsites] == ["a:", "b:", "c:"]
    assert all(cs["receiver_class"] == "Greeter" for cs in callsites)


def test_extractor_handles_function_with_no_msg_sends():
    """A function with no objc_msgSend calls emits nothing for that function."""
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    per_function_disasm = {
        "0x100456000": {
            "name": "sym.compute",
            "ops": [
                {"offset": 0x100456000, "opcode": "add", "operands": ["x0", "x0", 1]},
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
