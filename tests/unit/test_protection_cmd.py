"""chimera detect-protections — native (PE/ELF) profile merge.

The PE/ELF pipelines cache their `native_detector` result under
"native_protection" (singular); Android caches an unrelated blob under
"native_protections" (plural). The command used to read only the plural
key, so on a native target every PE/ELF signal was dropped and a binary
importing IsDebuggerPresent still printed "Anti-debug: no".
"""
from __future__ import annotations

from chimera.bypass.detector import ProtectionProfile
from chimera.cli.protection import merge_native_profile


def test_merge_promotes_native_anti_debug():
    profile = ProtectionProfile()
    merge_native_profile(profile, {"has_anti_debug": True})
    assert profile.has_anti_debug is True


def test_merge_promotes_native_packer_name():
    profile = ProtectionProfile()
    merge_native_profile(profile, {"packer": "UPX"})
    assert profile.has_packer is True
    assert profile.packer_name == "UPX"


def test_merge_does_not_override_an_existing_packer_name():
    profile = ProtectionProfile(has_packer=True, packer_name="Themida")
    merge_native_profile(profile, {"packer": "UPX"})
    assert profile.packer_name == "Themida"


def test_merge_never_clears_a_protection_found_elsewhere():
    """Merging upward only — a native miss must not undo a mobile hit."""
    profile = ProtectionProfile(has_anti_debug=True)
    merge_native_profile(profile, {"has_anti_debug": False})
    assert profile.has_anti_debug is True


def test_merge_deduplicates_obfuscation_techniques():
    profile = ProtectionProfile(obfuscation_techniques=["ollvm_cff"])
    merge_native_profile(profile, {"obfuscation": ["ollvm_cff", "str_enc"]})
    assert profile.obfuscation_techniques == ["ollvm_cff", "str_enc"]


def test_merge_tolerates_empty_or_missing_blob():
    profile = ProtectionProfile()
    merge_native_profile(profile, {})
    merge_native_profile(profile, None)
    assert profile.has_anti_debug is False
    assert profile.has_packer is False
