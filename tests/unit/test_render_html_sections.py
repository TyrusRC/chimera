"""render_html surfaces behavior, attack-surface, and MASVS sections."""
from __future__ import annotations

from chimera.report.builder import render_html


def _base_report(**overrides) -> dict:
    base = {
        "schema": "chimera-report/1",
        "generated_at": "2026-05-14T00:00:00Z",
        "binary": {
            "sha256": "a" * 64, "path": "/x.exe", "format": "pe64",
            "platform": "windows", "arch": "x86_64", "framework": "native",
            "size_bytes": 1234, "package_name": None, "version": None,
        },
        "triage": {},
        "jadx": {"decompiled_files": 0, "package_count": 0, "packages": []},
        "native_libraries": {},
        "model": {"functions": [], "strings": [], "function_count": 0, "string_count": 0,
                  "function_truncated": False, "string_truncated": False},
        "manifest_present": False,
        "native_protections": {},
        "cross_layer": {"bindings": []},
        "pe_header": {}, "pe_imports": {}, "pe_flags": {},
        "elf_persistence": [], "elf_syscalls": {},
        "dotnet_assemblies": [],
        "native_protection": {},
        "imports": [],
        "vol_pslist": {}, "vol_pstree": {}, "vol_bash": {}, "vol_netstat": {},
        "vol_malfind": {}, "vol_lsmod": {}, "vol_check_modules": {},
        "vol_check_syscall": {}, "memory_persistence": {}, "memory_protection": {},
        "behavior": {
            "anti_analysis": {"anti_debug": False, "anti_vm": False, "evidence": []},
            "network": {"cleartext_permitted": False},
            "persistence": {"indicators_present": False, "elf_persistence_count": 0},
            "iocs": {},
            "packer": {"detected": False, "name": None},
        },
        "attack_surface": {"format": "pe64"},
        "masvs": {"applicable": False, "reason": "non-mobile", "rows": []},
    }
    base.update(overrides)
    return base


def test_render_html_includes_behavior_section_with_evidence():
    report = _base_report(behavior={
        "anti_analysis": {"anti_debug": True, "anti_vm": False, "self_inject": True,
                          "anti_frida": False, "root_jailbreak_detect": False,
                          "evidence": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]},
        "network": {"cleartext_permitted": True, "user_ca_trusted": False, "pinning_present": False},
        "persistence": {"indicators_present": True, "elf_persistence_count": 2},
        "iocs": {"url": ["http://evil.example/c2"]},
        "packer": {"detected": True, "name": "upx"},
    })
    html = render_html(report)
    assert "Behavior" in html
    assert "anti_debug" in html
    assert "IsDebuggerPresent" in html
    # Packer name should surface
    assert "upx" in html


def test_render_html_includes_attack_surface_with_imports():
    report = _base_report(attack_surface={
        "format": "pe64",
        "imports_by_bucket": {
            "file": ["kernel32.dll!CreateFileW"],
            "network": ["ws2_32.dll!connect"],
        },
    })
    html = render_html(report)
    assert "Attack Surface" in html
    assert "kernel32.dll!CreateFileW" in html
    assert "ws2_32.dll!connect" in html


def test_render_html_includes_attack_surface_with_exported_components():
    report = _base_report(attack_surface={
        "format": "apk",
        "exported_components": [
            {"kind": "activity", "name": ".LoginActivity", "has_intent_filter": True},
            {"kind": "receiver", "name": ".BootReceiver", "has_intent_filter": True},
        ],
    })
    html = render_html(report)
    assert ".LoginActivity" in html
    assert ".BootReceiver" in html


def test_render_html_masvs_table_rendered_when_mobile():
    report = _base_report(masvs={
        "applicable": True,
        "reason": "mobile binary",
        "rows": [
            {"control_id": "MASVS-STORAGE", "name": "Sensitive data storage", "status": "covered", "notes": "", "evidence_keys": []},
            {"control_id": "MASVS-CRYPTO", "name": "Cryptography", "status": "partial", "notes": "", "evidence_keys": []},
        ],
    })
    html = render_html(report)
    assert "MASVS-STORAGE" in html
    assert "MASVS-CRYPTO" in html
    assert "covered" in html


def test_render_html_masvs_omitted_when_not_applicable():
    report = _base_report()  # pe64 base, masvs not applicable
    html = render_html(report)
    # The MASVS table itself should not appear for non-mobile reports.
    assert "MASVS-STORAGE" not in html
