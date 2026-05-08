"""Smoke-tests for the new PE/ELF YARA rule files.

We just verify the rules compile and that the bundled scanner can load
them. Behavioral testing (does VMProtect rule fire on real samples?)
is integration-test territory.
"""
from pathlib import Path

import pytest

yara = pytest.importorskip("yara")


RULES_DIR = Path(__file__).parent.parent.parent / "src" / "chimera" / "bypass" / "yara_rules"


@pytest.mark.parametrize("filename", [
    "pe_packers.yar",
    "pe_anti_analysis.yar",
    "elf_packers.yar",
    "elf_persistence.yar",
])
def test_yara_rule_compiles(filename):
    path = RULES_DIR / filename
    assert path.exists(), f"missing rule file: {filename}"
    rules = yara.compile(filepath=str(path))
    # If compile succeeded, rules will iter over compiled rule list
    assert rules is not None


def test_upx_pe_rule_matches_known_string():
    rules = yara.compile(filepath=str(RULES_DIR / "pe_packers.yar"))
    sample = b"UPX!" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100
    matches = rules.match(data=sample)
    rule_names = {m.rule for m in matches}
    assert "UPX_PE" in rule_names


def test_anti_vm_rule_matches_combo():
    rules = yara.compile(filepath=str(RULES_DIR / "pe_anti_analysis.yar"))
    sample = b"VBoxGuest\x00stuff\x00VirtualBox\x00more"
    matches = rules.match(data=sample)
    rule_names = {m.rule for m in matches}
    assert "Anti_VM_Strings" in rule_names


def test_systemd_persistence_rule_matches_combo():
    rules = yara.compile(filepath=str(RULES_DIR / "elf_persistence.yar"))
    sample = b"/etc/systemd/system/evil.service\nWantedBy=multi-user.target\n"
    matches = rules.match(data=sample)
    rule_names = {m.rule for m in matches}
    assert "Systemd_Persistence_Strings" in rule_names


def test_yara_scanner_loads_new_rules():
    """End-to-end: the bundled scanner should now find +N rules."""
    from chimera.adapters.yara_adapter import YaraAdapter
    adapter = YaraAdapter()
    if not adapter.is_available():
        pytest.skip("yara-python unavailable")
    rules = adapter._load_rules()
    # Test that scan on a sample with UPX magic returns a match
    sample = b"UPX!" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100
    matches = rules.match(data=sample)
    rule_names = {m.rule for m in matches}
    assert "UPX_PE" in rule_names, f"UPX_PE not in {rule_names}"
