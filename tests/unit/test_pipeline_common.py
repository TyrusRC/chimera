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


def test_detect_binary_format_rejects_zero_byte_file(tmp_path):
    from chimera.pipelines.common import detect_binary_format
    empty = tmp_path / "empty.apk"
    empty.write_bytes(b"")
    with pytest.raises(ValueError, match="too short"):
        detect_binary_format(empty)


def test_detect_binary_format_rejects_missing_file(tmp_path):
    from chimera.pipelines.common import detect_binary_format
    with pytest.raises(FileNotFoundError):
        detect_binary_format(tmp_path / "nope.apk")


def test_bundle_extraction_cleans_up_on_error(tmp_path):
    """If base-apk lookup fails mid-extract, _bundle/ must not be left behind."""
    import zipfile
    from chimera.pipelines.common import _find_base_apk_in_bundle

    bundle = tmp_path / "bad.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("README.txt", b"no apk")

    output_dir = tmp_path / "out"
    with pytest.raises(FileNotFoundError):
        _find_base_apk_in_bundle(bundle, output_dir)
    assert not (output_dir / "_bundle").exists(), "_bundle/ must be cleaned up on failure"


def test_ambiguous_largest_apk_raises(tmp_path):
    """If >1 APK is within 10% of the max size, fail loudly."""
    import zipfile
    from chimera.pipelines.common import _find_base_apk_in_bundle

    bundle = tmp_path / "ambiguous.xapk"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("a.apk", b"x" * 1000)
        zf.writestr("b.apk", b"y" * 995)  # within 10%
    out = tmp_path / "out"
    with pytest.raises(ValueError, match="ambiguous"):
        _find_base_apk_in_bundle(bundle, out)


def test_find_mapping_file_sibling_of_apk(tmp_path):
    """Priority 1: <apk>.mapping or <apk>.mapping.txt alongside the APK."""
    from chimera.pipelines.common import find_mapping_file
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    mapping = tmp_path / "app.apk.mapping.txt"
    mapping.write_text("original.class -> a:\n")
    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()
    assert find_mapping_file(unpack_dir, apk_path=apk) == mapping


def test_find_mapping_file_aab_bundle_metadata(tmp_path):
    """Priority 2: BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map inside unpack."""
    from chimera.pipelines.common import find_mapping_file
    unpack_dir = tmp_path / "unpacked"
    meta_dir = unpack_dir / "BUNDLE-METADATA" / "com.android.tools.build.obfuscation"
    meta_dir.mkdir(parents=True)
    mapping = meta_dir / "proguard.map"
    mapping.write_text("original.class -> a:\n")
    assert find_mapping_file(unpack_dir, apk_path=None) == mapping


def test_find_mapping_file_bundled_in_assets(tmp_path):
    """Priority 3: assets/mapping.txt or mapping.txt in unpack dir."""
    from chimera.pipelines.common import find_mapping_file
    unpack_dir = tmp_path / "unpacked"
    assets = unpack_dir / "assets"
    assets.mkdir(parents=True)
    mapping = assets / "mapping.txt"
    mapping.write_text("x -> a:\n")
    assert find_mapping_file(unpack_dir, apk_path=None) == mapping


def test_find_mapping_file_none_when_absent(tmp_path):
    from chimera.pipelines.common import find_mapping_file
    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()
    assert find_mapping_file(unpack_dir, apk_path=None) is None


def test_find_mapping_file_sibling_wins_over_bundled(tmp_path):
    """Sibling (priority 1) must beat BUNDLE-METADATA (priority 2)."""
    from chimera.pipelines.common import find_mapping_file
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    sibling = tmp_path / "app.apk.mapping"
    sibling.write_text("s -> a:\n")
    unpack_dir = tmp_path / "unpacked"
    meta_dir = unpack_dir / "BUNDLE-METADATA" / "com.android.tools.build.obfuscation"
    meta_dir.mkdir(parents=True)
    (meta_dir / "proguard.map").write_text("b -> a:\n")
    assert find_mapping_file(unpack_dir, apk_path=apk) == sibling


def test_detect_kotlin_finds_metadata_reference(tmp_path):
    """A DEX containing the bytes 'Lkotlin/Metadata;' must be detected as Kotlin."""
    from chimera.pipelines.common import detect_kotlin
    dex = tmp_path / "classes.dex"
    # Fake DEX: valid-ish header + embedded Kotlin metadata string
    dex.write_bytes(b"dex\n035\x00" + b"\x00" * 32 + b"Lkotlin/Metadata;" + b"\x00" * 32)
    assert detect_kotlin(tmp_path) is True


def test_detect_kotlin_false_on_plain_java_dex(tmp_path):
    """A DEX without the Kotlin metadata reference returns False."""
    from chimera.pipelines.common import detect_kotlin
    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"\x00" * 32 + b"Ljava/lang/String;" + b"\x00" * 32)
    assert detect_kotlin(tmp_path) is False


def test_detect_kotlin_scans_multiple_dex(tmp_path):
    """classes.dex, classes2.dex, ... are all scanned until match found."""
    from chimera.pipelines.common import detect_kotlin
    (tmp_path / "classes.dex").write_bytes(b"dex\n035\x00plain")
    (tmp_path / "classes2.dex").write_bytes(b"dex\n035\x00Lkotlin/Metadata;")
    assert detect_kotlin(tmp_path) is True


def test_detect_kotlin_false_when_no_dex(tmp_path):
    from chimera.pipelines.common import detect_kotlin
    assert detect_kotlin(tmp_path) is False
