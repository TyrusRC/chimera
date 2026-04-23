import io
import zipfile
import pytest
from pathlib import Path
from chimera.model.binary import BinaryInfo, BinaryFormat, Architecture, Platform, Framework, _detect_format


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


def test_detect_format_does_not_read_entire_file(tmp_path, monkeypatch):
    p = tmp_path / "huge.so"
    p.write_bytes(b"\x7fELF" + b"\x00" * (10 * 1024 * 1024))  # 10 MB ELF

    calls: list[int] = []

    real_open = open

    def spy_open(path, mode="r", *a, **kw):
        f = real_open(path, mode, *a, **kw)
        if "b" in mode:
            orig_read = f.read

            def tracked_read(n=-1):
                calls.append(n)
                return orig_read(n)

            f.read = tracked_read  # type: ignore[method-assign]
        return f

    monkeypatch.setattr("builtins.open", spy_open)
    _detect_format(p)
    assert all(n is not None and n <= 16 for n in calls), (
        f"magic detection must read <=16 bytes, saw reads: {calls}"
    )
    total = sum(n for n in calls if isinstance(n, int) and n > 0)
    assert total <= 64, (
        f"magic detection must read <=64 bytes total, saw {total} across {len(calls)} reads"
    )


def _make_fake_ipa(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("Payload/App.app/Info.plist", b"<plist/>")


def _make_fake_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<?xml?>")
        zf.writestr("classes.dex", b"dex\n035\x00")


def test_detect_format_disambiguates_zip_by_content_apk(tmp_path):
    p = tmp_path / "mystery.zip"  # wrong suffix on purpose
    _make_fake_apk(p)
    assert _detect_format(p) is BinaryFormat.APK


def test_detect_format_disambiguates_zip_by_content_ipa(tmp_path):
    p = tmp_path / "mystery.zip"
    _make_fake_ipa(p)
    assert _detect_format(p) is BinaryFormat.IPA


def test_detect_format_suffix_still_wins_for_empty_zip(tmp_path):
    ipa = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa, "w") as _:
        pass
    assert _detect_format(ipa) is BinaryFormat.IPA
