import pytest
import zipfile
from pathlib import Path
from chimera.frameworks.detector import FrameworkDetector, DetectedFramework


class TestFrameworkDetector:
    def test_detect_react_native_hermes(self, tmp_path):
        # Simulate unpacked APK with Hermes bundle
        assets = tmp_path / "assets"
        assets.mkdir()
        bundle = assets / "index.android.bundle"
        bundle.write_bytes(b"\xc6\x1f\xbc\x03" + b"\x00" * 60)  # Hermes magic
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "react-native"
        assert result.variant == "hermes"

    def test_detect_react_native_jsc(self, tmp_path):
        assets = tmp_path / "assets"
        assets.mkdir()
        bundle = assets / "index.android.bundle"
        bundle.write_text("var __BUNDLE_START_TIME__=this.nativePerformanceNow()")
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "react-native"
        assert result.variant == "jsc"

    def test_detect_flutter_android(self, tmp_path):
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libflutter.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        (lib / "libapp.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "flutter"

    def test_detect_xamarin(self, tmp_path):
        assemblies = tmp_path / "assemblies"
        assemblies.mkdir()
        (assemblies / "Mono.Android.dll").write_bytes(b"MZ" + b"\x00" * 60)
        (assemblies / "Xamarin.Forms.dll").write_bytes(b"MZ" + b"\x00" * 60)
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "xamarin"

    def test_detect_unity_il2cpp(self, tmp_path):
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libil2cpp.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        assets = tmp_path / "assets" / "bin" / "Data" / "Managed" / "Metadata"
        assets.mkdir(parents=True)
        (assets / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa" + b"\x00" * 60)
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "unity-il2cpp"

    def test_detect_cordova(self, tmp_path):
        www = tmp_path / "assets" / "www"
        www.mkdir(parents=True)
        (www / "index.html").write_text("<html><script src='cordova.js'></script></html>")
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "cordova"

    def test_detect_native(self, tmp_path):
        # No framework markers
        (tmp_path / "AndroidManifest.xml").write_text("<manifest/>")
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "native"

    def test_detect_flutter_ios(self, tmp_path):
        fw = tmp_path / "Frameworks" / "Flutter.framework"
        fw.mkdir(parents=True)
        (fw / "Flutter").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        app_fw = tmp_path / "Frameworks" / "App.framework"
        app_fw.mkdir(parents=True)
        (app_fw / "App").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        result = FrameworkDetector.detect(tmp_path)
        assert result.framework == "flutter"
