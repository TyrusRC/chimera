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


@register_evidence("react_native", "rn-hermes-bundle")
def test_rn_hermes_bundle_is_recognized_and_strings_found():
    from chimera.frameworks.react_native import ReactNativeAnalyzer

    sample = build_sample("rn-hermes-bundle")
    expected = load_expected("rn-hermes-bundle")["expected"]["react_native"]

    analyzer = ReactNativeAnalyzer()
    assert analyzer.is_hermes(sample) is expected["is_hermes"]

    result = analyzer.analyze_bundle(sample)
    strings = result["strings_of_interest"]
    # Also try the UTF-16 pass; some hermes variants store strings that way.
    strings += analyzer.extract_utf16_strings(sample)

    assert_min_count(len(strings), expected["min_strings_of_interest"], "rn hermes strings")
    assert_string_present(strings, expected["must_find_url_substring"])


@register_evidence("react_native", "rn-jsc-bundle")
def test_rn_jsc_bundle_module_ids_and_security_scan():
    from chimera.frameworks.react_native import ReactNativeAnalyzer

    sample = build_sample("rn-jsc-bundle")
    expected = load_expected("rn-jsc-bundle")["expected"]["react_native"]

    analyzer = ReactNativeAnalyzer()
    assert analyzer.is_hermes(sample) is expected["is_hermes"]

    module_ids = analyzer.extract_module_ids(sample)
    assert_min_count(len(module_ids), expected["min_module_ids"], "module ids")

    result = analyzer.analyze_bundle(sample, variant="jsc")
    assert_string_present(result["strings_of_interest"], expected["must_find_url_substring"])

    issues = result["security_issues"]
    titles = " ".join(i["title"].lower() for i in issues)
    assert expected["must_find_issue_title_substring"] in titles, (
        f"Expected bearer-token issue, saw titles: {titles!r}"
    )
