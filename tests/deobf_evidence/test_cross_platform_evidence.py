"""Cross-platform framework evidence tests (flutter, rn, xamarin, unity, webview)."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.deobf_evidence._assertions import assert_min_count, assert_string_present
from tests.deobf_evidence._fixtures import build_sample, load_expected
from tests.deobf_evidence._registry import register_evidence


@register_evidence("flutter", "flutter-obfuscated")
@pytest.mark.asyncio
async def test_flutter_recovers_dart_classes(tmp_path):
    import shutil

    from chimera.frameworks.flutter import FlutterAnalyzer

    if shutil.which("blutter") is None:
        pytest.skip("blutter not on PATH")

    sample = build_sample("flutter-obfuscated")
    expected = load_expected("flutter-obfuscated")["expected"]["flutter"]

    analyzer = FlutterAnalyzer()
    result = await analyzer.run_blutter(sample, tmp_path)

    assert_min_count(result["class_count"], expected["min_class_count"], "flutter classes")
    assert analyzer.detect_obfuscation(result) == expected["obfuscation_detected"]
    # Frida script path is surfaced for Sub-project 2's dynamic tier.
    assert Path(analyzer.frida_script_path()).exists()
