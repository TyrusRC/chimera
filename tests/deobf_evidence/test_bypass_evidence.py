"""Bypass subsystem evidence tests (detector, orchestrator, scripts)."""
from __future__ import annotations

from tests.deobf_evidence._fixtures import build_sample, load_expected
from tests.deobf_evidence._registry import register_evidence


@register_evidence("bypass", "bypass-frida-strings")
def test_bypass_detector_flags_all_expected_protections():
    from chimera.bypass.detector import ProtectionDetector

    sample = build_sample("bypass-frida-strings")
    strings = sample.read_text().splitlines()
    expected = load_expected("bypass-frida-strings")["expected"]["bypass"]

    det = ProtectionDetector()

    android = det.detect_from_strings(strings, "android")
    ios = det.detect_from_strings(strings, "ios")

    assert android.has_root_detection is expected["has_root_detection_android"]
    assert ios.has_jailbreak_detection is expected["has_jailbreak_detection_ios"]

    assert android.has_anti_frida is expected["has_anti_frida"]
    assert android.has_anti_debug is expected["has_anti_debug"]
    assert android.has_ssl_pinning is expected["has_ssl_pinning"]
    assert android.has_integrity_check is expected["has_integrity_check"]
    assert android.has_packer is expected["has_packer"]
    assert expected["packer_name_contains"] in (android.packer_name or "").lower()


def test_bypass_scripts_coverage_for_every_known_protection():
    """ScriptLoader must have a script for every protection a detector may produce."""
    from chimera.bypass.detector import ProtectionProfile
    from chimera.bypass.scripts import ScriptLoader

    loader = ScriptLoader()
    profile = ProtectionProfile(
        has_root_detection=True,
        has_jailbreak_detection=True,
        has_anti_frida=True,
        has_anti_debug=True,
        has_ssl_pinning=True,
        has_integrity_check=True,
        has_packer=True,
    )
    for platform in ("android", "ios"):
        for protection in profile.bypass_order():
            script = loader.get_script_for_bypass(platform, protection)
            assert script is not None, f"Missing script: ({platform}, {protection})"
