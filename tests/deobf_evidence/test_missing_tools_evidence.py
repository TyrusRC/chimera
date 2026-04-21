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
