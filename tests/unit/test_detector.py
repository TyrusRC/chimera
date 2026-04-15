import pytest
from chimera.bypass.detector import ProtectionDetector, ProtectionProfile


class TestProtectionDetector:
    def test_detect_from_strings_root(self):
        detector = ProtectionDetector()
        strings = ["rootbeer", "com.scottyab.rootbeer", "/sbin/su", "Magisk"]
        profile = detector.detect_from_strings(strings, platform="android")
        assert profile.has_root_detection is True

    def test_detect_from_strings_frida(self):
        detector = ProtectionDetector()
        strings = ["frida-server", "27042", "/proc/self/maps", "gum-js-loop"]
        profile = detector.detect_from_strings(strings, platform="android")
        assert profile.has_anti_frida is True

    def test_detect_from_strings_ssl(self):
        detector = ProtectionDetector()
        strings = ["CertificatePinner", "checkServerTrusted", "ssl_pinning"]
        profile = detector.detect_from_strings(strings, platform="android")
        assert profile.has_ssl_pinning is True

    def test_detect_from_strings_jailbreak(self):
        detector = ProtectionDetector()
        strings = ["Cydia", "/Applications/Sileo.app", "canOpenURL", "jailbroken"]
        profile = detector.detect_from_strings(strings, platform="ios")
        assert profile.has_jailbreak_detection is True

    def test_empty_strings(self):
        detector = ProtectionDetector()
        profile = detector.detect_from_strings([], platform="android")
        assert profile.has_root_detection is False
        assert profile.has_anti_frida is False

    def test_profile_bypass_order(self):
        profile = ProtectionProfile(
            has_anti_debug=True,
            has_anti_frida=True,
            has_root_detection=True,
            has_ssl_pinning=True,
        )
        order = profile.bypass_order()
        assert order.index("anti_debug") < order.index("anti_frida")
        assert order.index("anti_frida") < order.index("root_detection")
        assert order.index("root_detection") < order.index("ssl_pinning")
