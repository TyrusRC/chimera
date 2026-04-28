"""Evidence-test registry and expected coverage matrix.

Tests register themselves via @register_evidence(tool, variant). The
coverage-enforcement test asserts EXPECTED_MATRIX ⊆ REGISTERED.
"""
from __future__ import annotations

from collections.abc import Callable

REGISTERED: set[tuple[str, str]] = set()

EXPECTED_MATRIX: set[tuple[str, str]] = {
    ("jadx", "android-proguard-rename"),
    ("jadx", "android-proguard-with-mapping"),
    ("jadx", "android-xor-string"),
    ("radare2", "android-native-stripped"),
    ("ghidra", "android-native-stripped"),
    ("flutter", "flutter-obfuscated"),
    ("react_native", "rn-hermes-bundle"),
    ("react_native", "rn-jsc-bundle"),
    ("xamarin", "xamarin-obfuscated"),
    ("unity", "unity-il2cpp-plain"),
    ("unity", "unity-il2cpp-encrypted"),
    ("bypass", "bypass-frida-strings"),
    ("apktool", "android-proguard-rename"),
    ("webcrack", "rn-jsc-bundle"),
    ("jadx", "android-kotlin-metadata"),
    ("swift_demangle", "swift-ios-mangled"),
}


def register_evidence(tool: str, variant: str) -> Callable:
    def deco(fn: Callable) -> Callable:
        REGISTERED.add((tool, variant))
        return fn

    return deco
