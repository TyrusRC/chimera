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


def test_process_message_rejects_bad_payload(tmp_path, caplog):
    from chimera.dynamic.code_capture import DynamicCodeCapture

    cap = DynamicCodeCapture(tmp_path)
    with caplog.at_level("WARNING"):
        cap.process_message({"type": "send", "payload": "not-a-dict"})
        cap.process_message({"type": "send", "payload": {"type": "code_capture"}})
        cap.process_message({"type": "send", "payload": {"type": "code_capture", "loader": 42, "path": None}})
        cap.process_message({"type": "send", "payload": {"type": "code_capture", "loader": "x", "path": "/p"}})

    assert len(cap.get_captured()) == 1
    assert cap.get_captured()[0]["path"] == "/p"
