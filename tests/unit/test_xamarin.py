from pathlib import Path
from chimera.frameworks.xamarin import XamarinAnalyzer


class TestXamarinAnalyzer:
    def test_find_assemblies(self, tmp_path):
        assemblies = tmp_path / "assemblies"
        assemblies.mkdir()
        (assemblies / "MyApp.dll").write_bytes(b"MZ" + b"\x00" * 60)
        (assemblies / "Xamarin.Forms.dll").write_bytes(b"MZ" + b"\x00" * 60)
        analyzer = XamarinAnalyzer()
        result = analyzer.find_assemblies(tmp_path)
        assert len(result) >= 2

    def test_detect_obfuscation(self, tmp_path):
        assemblies = tmp_path / "assemblies"
        assemblies.mkdir()
        (assemblies / "a.dll").write_bytes(b"MZ" + b"\x00" * 60)
        analyzer = XamarinAnalyzer()
        # Single letter names suggest obfuscation
        assert analyzer.looks_obfuscated(["a", "b", "c"]) is True
        assert analyzer.looks_obfuscated(["MyApp", "Xamarin.Forms"]) is False
