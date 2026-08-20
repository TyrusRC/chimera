"""Plain JVM archives (.jar) — format sniffing and platform routing.

A desktop Java program is a ZIP full of .class files with no
AndroidManifest.xml, so the APK/IPA/AAB ladder fell through to its
"unknown ZIP" fallback and `chimera analyze` rejected the file outright.
jadx decompiles a .jar natively, so the only thing missing was routing.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from chimera.model.binary import BinaryFormat, Platform, BinaryInfo
from chimera.pipelines.common import detect_binary_format, detect_platform


def _make_jar(path: Path, *, with_manifest: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        if with_manifest:
            zf.writestr("META-INF/MANIFEST.MF",
                        "Manifest-Version: 1.0\nMain-Class: com.example.Main\n")
        # 0xCAFEBABE is the .class magic.
        zf.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41")
        zf.writestr("com/example/Helper.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41")
    return path


def _make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex", b"dex\n035\x00")
    return path


def test_jar_is_detected_as_jar(tmp_path):
    jar = _make_jar(tmp_path / "app.jar")
    assert detect_binary_format(jar) == "jar"


def test_jar_routes_to_the_jvm_platform(tmp_path):
    jar = _make_jar(tmp_path / "app.jar")
    assert detect_platform(jar) == "jvm"


def test_jar_without_a_manifest_still_detected(tmp_path):
    """A bare class archive is still a JVM archive."""
    jar = _make_jar(tmp_path / "nomanifest.jar", with_manifest=False)
    assert detect_binary_format(jar) == "jar"


def test_binary_info_reports_jar_format_and_platform(tmp_path):
    jar = _make_jar(tmp_path / "app.jar")
    info = BinaryInfo.from_path(jar)
    assert info.format == BinaryFormat.JAR
    assert info.platform == Platform.JVM


def test_apk_is_not_mistaken_for_a_jar(tmp_path):
    """An APK is also a zip of classes — it must still route to android."""
    apk = _make_apk(tmp_path / "app.apk")
    assert detect_binary_format(apk) == "apk"
    assert detect_platform(apk) == "android"


def test_zip_without_classes_is_not_a_jar(tmp_path):
    p = tmp_path / "plain.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("readme.txt", "hello")
    assert detect_binary_format(p) != "jar"
