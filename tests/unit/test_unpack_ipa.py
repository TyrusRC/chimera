import pytest
import zipfile
import plistlib
from pathlib import Path
from chimera.pipelines.common import unpack_ipa, detect_binary_format, detect_platform


@pytest.fixture
def sample_ipa(tmp_path):
    """Create a minimal IPA for testing."""
    ipa = tmp_path / "test.ipa"
    plist_data = plistlib.dumps({
        "CFBundleIdentifier": "com.example.testapp",
        "CFBundleName": "TestApp",
        "CFBundleVersion": "1.0",
        "MinimumOSVersion": "15.0",
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["testapp", "fb123456"]}
        ],
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
        },
        "LSApplicationQueriesSchemes": ["whatsapp", "telegram"],
    })
    # Fake Mach-O binary (ARM64 magic)
    macho_binary = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 56

    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/TestApp.app/Info.plist", plist_data)
        zf.writestr("Payload/TestApp.app/TestApp", macho_binary)
        zf.writestr("Payload/TestApp.app/Frameworks/SomeLib.framework/SomeLib", macho_binary)
        zf.writestr("Payload/TestApp.app/PlugIns/Widget.appex/Widget", macho_binary)
        zf.writestr("Payload/TestApp.app/embedded.mobileprovision", b"fake provision")
    return ipa


class TestUnpackIpa:
    def test_unpack_extracts_app_bundle(self, sample_ipa, tmp_path):
        output = tmp_path / "unpacked"
        result = unpack_ipa(sample_ipa, output)
        assert result["app_bundle"].exists()
        assert result["info_plist_path"].exists()
        assert result["bundle_id"] == "com.example.testapp"

    def test_unpack_finds_main_binary(self, sample_ipa, tmp_path):
        output = tmp_path / "unpacked"
        result = unpack_ipa(sample_ipa, output)
        assert result["main_binary"] is not None
        assert result["main_binary"].name == "TestApp"

    def test_unpack_finds_frameworks(self, sample_ipa, tmp_path):
        output = tmp_path / "unpacked"
        result = unpack_ipa(sample_ipa, output)
        assert len(result["frameworks"]) >= 1

    def test_unpack_finds_extensions(self, sample_ipa, tmp_path):
        output = tmp_path / "unpacked"
        result = unpack_ipa(sample_ipa, output)
        assert len(result["extensions"]) >= 1

    def test_unpack_parses_plist(self, sample_ipa, tmp_path):
        output = tmp_path / "unpacked"
        result = unpack_ipa(sample_ipa, output)
        assert result["plist"]["CFBundleName"] == "TestApp"
        assert result["plist"]["MinimumOSVersion"] == "15.0"

    def test_detect_format_ipa(self, sample_ipa):
        assert detect_binary_format(sample_ipa) == "ipa"

    def test_detect_platform_ipa(self, sample_ipa):
        assert detect_platform(sample_ipa) == "ios"
