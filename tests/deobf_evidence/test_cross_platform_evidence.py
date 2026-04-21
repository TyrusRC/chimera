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


@register_evidence("xamarin", "xamarin-obfuscated")
@pytest.mark.asyncio
async def test_xamarin_ilspy_decompiles_lib(tmp_path):
    import shutil

    from chimera.frameworks.xamarin import XamarinAnalyzer

    if shutil.which("ilspycmd") is None and shutil.which("ilspy") is None:
        pytest.skip("ilspycmd not on PATH")

    sample = build_sample("xamarin-obfuscated")
    expected = load_expected("xamarin-obfuscated")["expected"]["xamarin"]

    analyzer = XamarinAnalyzer()
    result = await analyzer.decompile(sample, tmp_path)
    assert_min_count(
        result["file_count"],
        expected["ilspy_decompile_file_count_min"],
        "ilspy .cs files",
    )
    all_text = "\n".join(
        p.read_text(errors="replace") for p in tmp_path.rglob("*.cs")
    )
    assert expected["ilspy_must_contain_symbol"] in all_text


@register_evidence("unity", "unity-il2cpp-plain")
@pytest.mark.asyncio
async def test_unity_metadata_recognized(tmp_path):
    from chimera.frameworks.unity import UnityAnalyzer

    sample = build_sample("unity-il2cpp-plain")
    fixture_dir = sample.parent
    expected = load_expected("unity-il2cpp-plain")["expected"]["unity"]

    analyzer = UnityAnalyzer()
    assert (
        analyzer.find_metadata(fixture_dir) is not None
    ) is expected["metadata_magic_recognized"]
    assert (
        analyzer.find_il2cpp_binary(fixture_dir) is not None
    ) is expected["il2cpp_binary_found"]

    binary = analyzer.find_il2cpp_binary(fixture_dir)
    metadata = analyzer.find_metadata(fixture_dir)
    result = await analyzer.run_il2cppdumper(binary, metadata, tmp_path)

    # The stub sample cannot actually dump; assert clean failure contract.
    assert result["dumped"] is False
    assert result.get("guidance"), "guidance missing on failure"


@register_evidence("unity", "unity-il2cpp-encrypted")
@pytest.mark.asyncio
async def test_unity_encrypted_metadata_bails_cleanly(tmp_path):
    from chimera.frameworks.unity import UnityAnalyzer

    sample = build_sample("unity-il2cpp-encrypted")
    fixture_cache = sample.parent
    expected = load_expected("unity-il2cpp-encrypted")["expected"]["unity"]

    analyzer = UnityAnalyzer()
    assert analyzer.detect_encrypted_metadata(sample) is expected["encrypted_metadata_detected"]

    # find_metadata should reject the wrong-magic file.
    assert analyzer.find_metadata(fixture_cache) is None

    # Direct run with the raw path should produce the encrypted-metadata branch.
    binary = fixture_cache / "libil2cpp.so"
    result = await analyzer.run_il2cppdumper(binary, sample, tmp_path)
    assert result["dumped"] is False
    assert result["encrypted_metadata"] is True
    assert expected["guidance_mentions"] in result["guidance"].lower()
