import pytest
from pathlib import Path
from chimera.model.binary import BinaryInfo, BinaryFormat, Architecture, Platform, Framework


class TestBinaryFormat:
    def test_apk_format(self):
        assert BinaryFormat.APK.value == "apk"

    def test_ipa_format(self):
        assert BinaryFormat.IPA.value == "ipa"

    def test_elf_format(self):
        assert BinaryFormat.ELF.value == "elf"

    def test_macho_format(self):
        assert BinaryFormat.MACHO.value == "macho"

    def test_dex_format(self):
        assert BinaryFormat.DEX.value == "dex"


class TestArchitecture:
    def test_arm32(self):
        assert Architecture.ARM32.value == "arm32"

    def test_arm64(self):
        assert Architecture.ARM64.value == "arm64"

    def test_dex_arch(self):
        assert Architecture.DEX.value == "dex"


class TestPlatform:
    def test_android(self):
        assert Platform.ANDROID.value == "android"

    def test_ios(self):
        assert Platform.IOS.value == "ios"


class TestFramework:
    def test_native(self):
        assert Framework.NATIVE.value == "native"

    def test_react_native(self):
        assert Framework.REACT_NATIVE.value == "react-native"

    def test_flutter(self):
        assert Framework.FLUTTER.value == "flutter"


class TestBinaryInfo:
    def test_create_apk_info(self):
        info = BinaryInfo(
            sha256="abc123", path=Path("/tmp/test.apk"),
            format=BinaryFormat.APK, platform=Platform.ANDROID,
            arch=Architecture.DEX, framework=Framework.NATIVE,
            size_bytes=1024000,
        )
        assert info.sha256 == "abc123"
        assert info.format == BinaryFormat.APK
        assert info.platform == Platform.ANDROID
        assert info.is_mobile is True

    def test_reject_non_mobile_format(self):
        with pytest.raises(ValueError, match="not a supported mobile format"):
            BinaryInfo(
                sha256="abc", path=Path("/tmp/test.exe"),
                format=BinaryFormat.PE, platform=Platform.ANDROID,
                arch=Architecture.ARM64, framework=Framework.NATIVE,
                size_bytes=1024,
            )

    def test_from_path_computes_sha256(self, tmp_path):
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"PK\x03\x04fake apk content")
        info = BinaryInfo.from_path(apk)
        assert len(info.sha256) == 64
        assert info.path == apk
