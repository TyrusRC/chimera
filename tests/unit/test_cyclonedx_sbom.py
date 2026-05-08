"""Unit tests for the CycloneDX SBOM emitter."""
import json
from pathlib import Path

import pytest

from chimera.detection_engineering.cyclonedx_sbom import (
    SCHEMA_VERSION, build_cyclonedx_sbom,
)
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import ImportEntry
from chimera.model.program import UnifiedProgramModel


class _StubCache:
    def __init__(self, blobs: dict | None = None):
        self.cache_dir = Path("/tmp/no-such-cache")
        self._blobs = blobs or {}

    def get_json(self, sha, key):
        return self._blobs.get(key)

    def list_keys(self, sha):
        return list(self._blobs.keys())


def _pe_model(*, imports: list[ImportEntry] | None = None) -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="ab" * 32, path=Path("/tmp/sample.exe"),
        format=BinaryFormat.PE64, platform=Platform.WINDOWS,
        arch=Architecture.X86_64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    for imp in imports or []:
        m.add_import(imp)
    return m


def _apk_model(*, imports: list[ImportEntry] | None = None) -> UnifiedProgramModel:
    bi = BinaryInfo(
        sha256="cd" * 32, path=Path("/tmp/app.apk"),
        format=BinaryFormat.APK, platform=Platform.ANDROID,
        arch=Architecture.ARM64, framework=Framework.NATIVE, size_bytes=1,
    )
    m = UnifiedProgramModel(bi)
    for imp in imports or []:
        m.add_import(imp)
    return m


def test_sbom_has_required_top_level_fields():
    m = _pe_model()
    sbom = build_cyclonedx_sbom(m, _StubCache())
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == SCHEMA_VERSION
    assert sbom["version"] == 1
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in sbom
    assert "components" in sbom


def test_application_component_carries_sha256_and_filename():
    m = _pe_model()
    sbom = build_cyclonedx_sbom(m, _StubCache())
    comp = sbom["metadata"]["component"]
    assert comp["type"] == "application"
    assert comp["name"] == "sample.exe"
    assert any(h["alg"] == "SHA-256" and h["content"] == "ab" * 32 for h in comp["hashes"])


def test_imports_become_library_components():
    m = _pe_model(imports=[
        ImportEntry(dll="kernel32.dll", name="VirtualAllocEx"),
        ImportEntry(dll="kernel32.dll", name="WriteProcessMemory"),  # same DLL
        ImportEntry(dll="ws2_32.dll", name="connect"),
    ])
    sbom = build_cyclonedx_sbom(m, _StubCache())
    libs = [c for c in sbom["components"] if c["type"] == "library"]
    names = {c["name"] for c in libs}
    assert "kernel32.dll" in names
    assert "ws2_32.dll" in names
    # De-duplicated by DLL name
    assert sum(1 for c in libs if c["name"] == "kernel32.dll") == 1


def test_elf_needed_libs_become_components():
    m = _pe_model(imports=[
        ImportEntry(dll="", name="libc.so.6"),
        ImportEntry(dll="", name="libpthread.so.0"),
    ])
    sbom = build_cyclonedx_sbom(m, _StubCache())
    names = {c["name"] for c in sbom["components"] if c["type"] == "library"}
    assert "libc.so.6" in names
    assert "libpthread.so.0" in names


def test_sdk_detection_emits_components():
    m = _apk_model()
    cache = _StubCache({
        "sdks": {
            "matches": [
                {"name": "Firebase Analytics", "category": "analytics",
                 "risk_level": "moderate", "version": "21.0.0"},
                {"name": "AdMob", "category": "advertising"},
            ],
        },
    })
    sbom = build_cyclonedx_sbom(m, cache)
    sdk_libs = [c for c in sbom["components"]
                if any(p["name"] == "chimera:source" and p["value"] == "sdk_detector"
                       for p in c.get("properties", []))]
    names = {c["name"] for c in sdk_libs}
    assert "Firebase Analytics" in names
    assert "AdMob" in names
    fb = next(c for c in sdk_libs if c["name"] == "Firebase Analytics")
    assert fb["version"] == "21.0.0"


def test_native_libs_become_framework_components():
    m = _apk_model()
    cache = _StubCache({
        "r2_libnative.so": {"functions": []},
        "r2_libsecondary.so": {"functions": []},
        "r2_triage": {},  # excluded
    })
    sbom = build_cyclonedx_sbom(m, cache)
    fw_components = [c for c in sbom["components"] if c["type"] == "framework"]
    names = {c["name"] for c in fw_components}
    assert "libnative.so" in names
    assert "libsecondary.so" in names
    assert "triage" not in names


def test_sbom_is_json_serializable():
    m = _pe_model(imports=[ImportEntry(dll="kernel32.dll", name="ExitProcess")])
    sbom = build_cyclonedx_sbom(m, _StubCache())
    # Must round-trip through json without errors
    s = json.dumps(sbom)
    assert "CycloneDX" in s


def test_each_component_has_unique_bom_ref():
    m = _apk_model(imports=[
        ImportEntry(dll="", name="libc.so.6"),
    ])
    cache = _StubCache({
        "sdks": {"matches": [{"name": "Firebase"}]},
        "r2_libnative.so": {},
    })
    sbom = build_cyclonedx_sbom(m, cache)
    refs = [c["bom-ref"] for c in sbom["components"]]
    assert len(refs) == len(set(refs))
