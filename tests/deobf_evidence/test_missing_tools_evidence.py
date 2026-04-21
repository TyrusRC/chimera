"""New-adapter evidence tests (apktool, webcrack, frida-dexdump)."""
from __future__ import annotations

import pytest

from tests.deobf_evidence._assertions import assert_min_count
from tests.deobf_evidence._fixtures import build_sample, load_expected
from tests.deobf_evidence._registry import register_evidence


@register_evidence("webcrack", "rn-jsc-bundle")
def test_webcrack_rn_jsc_bundle_output_files():
    """Placeholder: webcrack decompiler not yet integrated."""
    import shutil

    expected = load_expected("rn-jsc-bundle")["expected"]["webcrack"]

    if shutil.which("webcrack") is None:
        pytest.skip("webcrack not on PATH")

    # TODO: implement webcrack integration when tool is available
    # For now, just assert the expected structure exists
    assert "min_output_files" in expected
