from chimera.dynamic.code_capture import DynamicCodeCapture


class TestDynamicCodeCapture:
    def test_android_hooks_script(self):
        capture = DynamicCodeCapture()
        script = capture.get_capture_script("android")
        assert "DexClassLoader" in script
        assert "InMemoryDexClassLoader" in script
        assert "System.loadLibrary" in script

    def test_ios_hooks_script(self):
        capture = DynamicCodeCapture()
        script = capture.get_capture_script("ios")
        assert "dlopen" in script
        assert "NSBundle" in script

    def test_output_dir_creation(self, tmp_path):
        capture = DynamicCodeCapture(output_dir=tmp_path / "captured")
        assert capture.output_dir.exists()
