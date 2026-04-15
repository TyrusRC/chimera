from pathlib import Path
from chimera.frameworks.flutter import FlutterAnalyzer


class TestFlutterAnalyzer:
    def test_find_libapp(self, tmp_path):
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libapp.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        (lib / "libflutter.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        analyzer = FlutterAnalyzer()
        result = analyzer.find_binaries(tmp_path)
        assert result["libapp"] is not None
        assert result["libflutter"] is not None

    def test_find_ios_binaries(self, tmp_path):
        app_fw = tmp_path / "Frameworks" / "App.framework"
        app_fw.mkdir(parents=True)
        (app_fw / "App").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        flutter_fw = tmp_path / "Frameworks" / "Flutter.framework"
        flutter_fw.mkdir(parents=True)
        (flutter_fw / "Flutter").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)
        analyzer = FlutterAnalyzer()
        result = analyzer.find_binaries(tmp_path)
        assert result["libapp"] is not None

    def test_extract_strings_from_binary(self, tmp_path):
        lib = tmp_path / "libapp.so"
        lib.write_bytes(b"\x7fELF" + b"\x00" * 20 + b"https://api.example.com/v1\x00secret_key_abc123\x00" + b"\x00" * 20)
        analyzer = FlutterAnalyzer()
        strings = analyzer.extract_dart_strings(lib)
        assert any("api.example.com" in s for s in strings)
