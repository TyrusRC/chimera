"""Protection detector — scans binaries for active security protections."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ProtectionProfile:
    has_root_detection: bool = False
    has_jailbreak_detection: bool = False
    has_anti_frida: bool = False
    has_anti_debug: bool = False
    has_ssl_pinning: bool = False
    has_integrity_check: bool = False
    has_packer: bool = False
    packer_name: str | None = None
    commercial_protection: str | None = None
    details: list[str] = field(default_factory=list)

    def bypass_order(self) -> list[str]:
        """Return bypass types in correct execution order."""
        order = []
        if self.has_anti_debug:
            order.append("anti_debug")
        if self.has_anti_frida:
            order.append("anti_frida")
        if self.has_root_detection:
            order.append("root_detection")
        if self.has_jailbreak_detection:
            order.append("jailbreak_detection")
        if self.has_integrity_check:
            order.append("integrity")
        if self.has_ssl_pinning:
            order.append("ssl_pinning")
        if self.has_packer:
            order.append("packer")
        return order

    @property
    def has_any_protection(self) -> bool:
        return any([
            self.has_root_detection, self.has_jailbreak_detection,
            self.has_anti_frida, self.has_anti_debug,
            self.has_ssl_pinning, self.has_integrity_check, self.has_packer,
        ])


# Detection patterns
_ROOT_PATTERNS = [
    r"rootbeer", r"scottyab.*root", r"/sbin/su\b", r"/system/app/Superuser",
    r"com\.topjohnwu\.magisk", r"Magisk", r"KernelSU",
    r"isDeviceRooted", r"checkRoot", r"RootDetection",
]

_JAILBREAK_PATTERNS = [
    r"Cydia", r"Sileo", r"canOpenURL.*cydia", r"jailbroken", r"jailbreak",
    r"/Applications/Cydia\.app", r"/Applications/Sileo\.app",
    r"IOSSecuritySuite", r"amIJailbroken",
    r"checkra1n", r"palera1n", r"unc0ver",
]

_FRIDA_PATTERNS = [
    r"frida[-_]server", r"\b27042\b", r"/proc/self/maps.*frida",
    r"gum-js-loop", r"gmain.*frida", r"frida-agent",
    r"LIBFRIDA", r"frida[-_]gadget",
]

_DEBUG_PATTERNS = [
    r"ptrace.*TRACEME", r"PT_DENY_ATTACH", r"TracerPid",
    r"isDebuggerConnected", r"isDebuggerAttached",
    r"sysctl.*P_TRACED", r"anti[-_]?debug",
]

_SSL_PATTERNS = [
    r"CertificatePinner", r"checkServerTrusted",
    r"ssl[-_]?pinning", r"TrustManager", r"SecTrustEvaluate",
    r"BoringSSL", r"TrustKit", r"SSLPinning",
]

_INTEGRITY_PATTERNS = [
    r"PackageManager.*signatures", r"getPackageInfo.*GET_SIGNATURES",
    r"checksum", r"integrity[-_]?check", r"tamper[-_]?detect",
    r"csops", r"LC_CODE_SIGNATURE",
]


class ProtectionDetector:
    def detect_from_strings(self, strings: list[str], platform: str) -> ProtectionProfile:
        """Detect protections from a list of strings found in the binary."""
        profile = ProtectionProfile()
        combined = " ".join(strings)

        if platform == "android":
            profile.has_root_detection = _match_any(_ROOT_PATTERNS, combined)
        elif platform == "ios":
            profile.has_jailbreak_detection = _match_any(_JAILBREAK_PATTERNS, combined)

        profile.has_anti_frida = _match_any(_FRIDA_PATTERNS, combined)
        profile.has_anti_debug = _match_any(_DEBUG_PATTERNS, combined)
        profile.has_ssl_pinning = _match_any(_SSL_PATTERNS, combined)
        profile.has_integrity_check = _match_any(_INTEGRITY_PATTERNS, combined)

        # Collect details
        for name, patterns in [
            ("root_detection", _ROOT_PATTERNS),
            ("jailbreak_detection", _JAILBREAK_PATTERNS),
            ("anti_frida", _FRIDA_PATTERNS),
            ("anti_debug", _DEBUG_PATTERNS),
            ("ssl_pinning", _SSL_PATTERNS),
            ("integrity", _INTEGRITY_PATTERNS),
        ]:
            for p in patterns:
                if re.search(p, combined, re.IGNORECASE):
                    profile.details.append(f"{name}: matched '{p}'")

        return profile


def _match_any(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)
