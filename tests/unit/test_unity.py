from pathlib import Path
from chimera.frameworks.unity import UnityAnalyzer


class TestUnityAnalyzer:
    def test_find_metadata(self, tmp_path):
        meta = tmp_path / "assets" / "bin" / "Data" / "Managed" / "Metadata"
        meta.mkdir(parents=True)
        (meta / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa" + b"\x00" * 100)
        analyzer = UnityAnalyzer()
        result = analyzer.find_metadata(tmp_path)
        assert result is not None

    def test_find_il2cpp(self, tmp_path):
        lib = tmp_path / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        (lib / "libil2cpp.so").write_bytes(b"\x7fELF" + b"\x00" * 60)
        analyzer = UnityAnalyzer()
        result = analyzer.find_il2cpp_binary(tmp_path)
        assert result is not None
