# tests/integration/test_objc_callsite_extraction_e2e.py
"""End-to-end: spawn r2 against the SP7 ios-objc-xref dylib fixture,
run the SP8 extractor, assert at least one Greeter.greet callsite resolves."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "deobf_evidence" / "fixtures" / "ios-objc-xref" / "sample.dylib"


@pytest.mark.asyncio
async def test_e2e_extracts_at_least_one_greet_callsite():
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        pytest.skip("r2 not on PATH")
    if not FIXTURE.exists():
        pytest.skip(f"no committed dylib at {FIXTURE}; run build_dylib.sh on macOS")

    from chimera.adapters.radare2 import Radare2Adapter
    from chimera.parsers.objc_callsite_extractor import extract_callsites

    adapter = Radare2Adapter()
    result = await adapter.analyze(str(FIXTURE), {"mode": "triage_with_disasm"})

    class_symbols_map = result.get("class_symbols", {})
    class_address_to_name = {
        int(addr_hex, 16): name
        for name, addr_hex in class_symbols_map.items()
    }
    callsites = extract_callsites(
        per_function_disasm=result.get("per_function_disasm", {}),
        class_symbols=set(class_symbols_map.keys()),
        cstring_pool=result.get("cstring_pool", {}),
        class_address_to_name=class_address_to_name,
    )
    # The Logging category's logGreeting method calls [self greet], so at
    # minimum that callsite should resolve to selector "greet".
    selectors = [cs["selector"] for cs in callsites]
    assert "greet" in selectors, (
        f"expected 'greet' selector in extracted callsites; got: {selectors}"
    )
