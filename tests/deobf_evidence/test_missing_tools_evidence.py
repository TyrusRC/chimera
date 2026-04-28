"""New-adapter evidence tests (apktool, webcrack, frida-dexdump)."""
from __future__ import annotations

import shutil

import pytest

from tests.deobf_evidence._assertions import assert_min_count
from tests.deobf_evidence._fixtures import build_sample, load_expected
from tests.deobf_evidence._registry import register_evidence


@register_evidence("webcrack", "rn-jsc-bundle")
@pytest.mark.asyncio
async def test_webcrack_deobfuscates_jsc_bundle(tmp_path):
    from chimera.adapters.webcrack import WebcrackAdapter

    if shutil.which("webcrack") is None:
        pytest.skip("webcrack not on PATH")

    sample = build_sample("rn-jsc-bundle")
    expected = load_expected("rn-jsc-bundle")["expected"]["webcrack"]

    adapter = WebcrackAdapter()
    result = await adapter.analyze(str(sample), {"output_dir": str(tmp_path)})

    assert result["return_code"] == 0, result.get("error", "")
    assert result["file_count"] >= expected["min_output_files"]


@register_evidence("apktool", "android-proguard-rename")
@pytest.mark.asyncio
async def test_apktool_decodes_apk(tmp_path):
    import shutil

    from chimera.adapters.apktool import ApktoolAdapter

    if shutil.which("apktool") is None:
        pytest.skip("apktool not on PATH")

    sample = build_sample("android-proguard-rename")
    expected = load_expected("android-proguard-rename")["expected"]["apktool"]

    adapter = ApktoolAdapter()
    result = await adapter.analyze(str(sample), {"output_dir": str(tmp_path)})

    assert result["return_code"] == 0, result.get("error", "")
    if expected["manifest_extracted"]:
        assert result["manifest_path"] is not None


@register_evidence("swift_demangle", "swift-ios-mangled")
@pytest.mark.asyncio
async def test_swift_demangle_adapter_demangles_known_symbols(tmp_path):
    from chimera.adapters.swift_demangle import SwiftDemangleAdapter

    if shutil.which("swift-demangle") is None:
        pytest.skip("swift-demangle not on PATH")

    sample = build_sample("swift-ios-mangled")
    expected = load_expected("swift-ios-mangled")["expected"]["swift_demangle"]

    names = [
        line.strip()
        for line in sample.read_text().splitlines()
        if line.strip()
    ]
    adapter = SwiftDemangleAdapter()
    result = await adapter.demangle_batch(names)

    demangled_count = sum(1 for k, v in result.items() if v != k)
    assert_min_count(demangled_count, expected["min_demangled"], "swift_demangle")
    joined = " ".join(result.values())
    assert expected["must_find_demangled_substring"] in joined, (
        f"expected substring {expected['must_find_demangled_substring']!r} in demangled output; got: {joined!r}"
    )


def test_frida_dexdump_adapter_is_registered_and_stub_enforces_stub_contract():
    """v1 ships the adapter as availability-only; analyze() must refuse to run."""
    import asyncio

    from chimera.adapters.frida_dexdump import FridaDexdumpAdapter

    adapter = FridaDexdumpAdapter()
    assert adapter.name() == "frida-dexdump"
    # is_available reflects PATH only; may be True or False.
    assert isinstance(adapter.is_available(), bool)

    async def _call():
        await adapter.analyze("/tmp/nope.apk", {})

    try:
        asyncio.run(_call())
    except NotImplementedError as e:
        assert "Sub-project 2" in str(e)
    else:
        raise AssertionError("stub must raise NotImplementedError")


@register_evidence("objc_xref", "ios-objc-xref")
def test_objc_xref_parser_finds_known_classes(tmp_path):
    from chimera.parsers.macho_objc import parse_objc_metadata
    from tests.deobf_evidence._fixtures import (
        FIXTURES_ROOT,
        load_expected,
    )

    fixture_dir = FIXTURES_ROOT / "ios-objc-xref"
    sample = fixture_dir / "sample.dylib"
    if not sample.exists():
        pytest.skip(f"no committed dylib at {sample}; run build_dylib.sh on macOS")

    expected = load_expected("ios-objc-xref")["expected"]["objc_xref"]
    md = parse_objc_metadata(sample)

    assert_min_count(len(md.classes), expected["min_classes"], "objc_xref classes")
    method_count = sum(
        len(c.instance_methods) + len(c.class_methods) for c in md.classes
    )
    assert_min_count(method_count, expected["min_methods"], "objc_xref methods")

    class_names = [c.name for c in md.classes]
    assert expected["must_find_class"] in class_names
    selectors = [
        m.selector
        for c in md.classes
        for m in c.instance_methods + c.class_methods
    ]
    assert expected["must_find_selector"] in selectors
