import pytest
import zipfile
from pathlib import Path
from chimera.pipelines.common import detect_platform, unpack_apk, detect_binary_format


class TestDetectPlatform:
    def test_apk_is_android(self, tmp_path):
        apk = tmp_path / "test.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        assert detect_platform(apk) == "android"

    def test_ipa_is_ios(self, tmp_path):
        ipa = tmp_path / "test.ipa"
        with zipfile.ZipFile(ipa, "w") as zf:
            zf.writestr("Payload/App.app/Info.plist", "<plist/>")
        assert detect_platform(ipa) == "ios"

    def test_elf_so_is_android(self, tmp_path):
        so = tmp_path / "libtest.so"
        so.write_bytes(b"\x7fELF" + b"\x00" * 60)
        assert detect_platform(so) == "android"

    def test_macho_is_ios(self, tmp_path):
        macho = tmp_path / "binary"
        macho.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        assert detect_platform(macho) == "ios"


class TestUnpackApk:
    def test_unpack_extracts_contents(self, tmp_path):
        apk = tmp_path / "test.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
            zf.writestr("classes.dex", "dex data")
            zf.writestr("lib/arm64-v8a/libnative.so", "elf data")
            zf.writestr("res/values/strings.xml", "<resources/>")
        output = tmp_path / "unpacked"
        result = unpack_apk(apk, output)
        assert result["manifest_path"].exists()
        assert len(result["dex_files"]) == 1
        assert len(result["native_libs"]) == 1
        assert result["native_libs"][0].name == "libnative.so"

    def test_unpack_handles_multi_dex(self, tmp_path):
        apk = tmp_path / "test.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
            zf.writestr("classes.dex", "dex1")
            zf.writestr("classes2.dex", "dex2")
            zf.writestr("classes3.dex", "dex3")
        output = tmp_path / "unpacked"
        result = unpack_apk(apk, output)
        assert len(result["dex_files"]) == 3


class TestDetectBinaryFormat:
    def test_apk(self, tmp_path):
        apk = tmp_path / "test.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "<manifest/>")
        assert detect_binary_format(apk) == "apk"

    def test_elf(self, tmp_path):
        so = tmp_path / "test.so"
        so.write_bytes(b"\x7fELF" + b"\x00" * 60)
        assert detect_binary_format(so) == "elf"

    def test_macho(self, tmp_path):
        m = tmp_path / "binary"
        m.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        assert detect_binary_format(m) == "macho"

    def test_dex(self, tmp_path):
        dex = tmp_path / "classes.dex"
        dex.write_bytes(b"dex\n035\x00" + b"\x00" * 60)
        assert detect_binary_format(dex) == "dex"
