"""React Native analyzer — Hermes bytecode + JSC bundle analysis."""

from __future__ import annotations

import re
import asyncio
import shutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_HERMES_MAGIC = b"\xc6\x1f\xbc\x03"

# Security-relevant patterns in RN bundles
_SECURITY_PATTERNS = [
    {"pattern": r"AsyncStorage\.(?:setItem|getItem)\s*\(\s*['\"](?:password|token|secret|session|auth|jwt|credential)",
     "rule_id": "AUTH-003", "title": "Sensitive data in AsyncStorage", "severity": "high"},
    {"pattern": r"__DEV__\s*(?:===?\s*true|&&|\|\||\?)",
     "rule_id": "DATA-003", "title": "Dev mode check (may be enabled)", "severity": "medium"},
    {"pattern": r"Flipper|flipperClient|ReactNativeFlipper",
     "rule_id": "DATA-003", "title": "Flipper debug tool reference", "severity": "medium"},
    {"pattern": r"CodePush\.sync|codePush\.sync|codePushOptions",
     "rule_id": "DATA-003", "title": "CodePush OTA updates enabled", "severity": "medium"},
    {"pattern": r"['\"]sk-(?:live|test)-[a-zA-Z0-9]{10,}['\"]",
     "rule_id": "AUTH-001", "title": "Hardcoded API key (Stripe-style)", "severity": "critical"},
    {"pattern": r"['\"]Bearer\s+[a-zA-Z0-9\-_.]{20,}['\"]",
     "rule_id": "AUTH-001", "title": "Hardcoded bearer token", "severity": "critical"},
]

# Strings worth extracting from bundles
_INTERESTING_PATTERNS = [
    r"https?://[^\s'\"]+",             # URLs
    r"['\"](?:api|API)[_-]?(?:key|KEY|secret|SECRET|token|TOKEN)['\"]",  # API key references
    r"firebase[a-zA-Z]*\.google(?:apis)?\.com",  # Firebase endpoints
]


class ReactNativeAnalyzer:
    def is_hermes(self, bundle_path: Path) -> bool:
        magic = bundle_path.read_bytes()[:4]
        return magic == _HERMES_MAGIC

    def analyze_bundle(self, bundle_path: Path, variant: str = "auto") -> dict:
        """Analyze a React Native JS bundle."""
        bundle_path = Path(bundle_path)

        if variant == "auto":
            variant = "hermes" if self.is_hermes(bundle_path) else "jsc"

        result = {
            "variant": variant,
            "bundle_path": str(bundle_path),
            "bundle_size": bundle_path.stat().st_size,
            "strings_of_interest": [],
            "security_issues": [],
        }

        if variant == "hermes":
            result["strings_of_interest"] = self._extract_hermes_strings(bundle_path)
            result["decompiled"] = False
            result["note"] = "Hermes bytecode — use hermes-dec for decompilation"
        else:
            content = bundle_path.read_text(errors="replace")
            result["strings_of_interest"] = self._extract_strings(content)
            result["security_issues"] = self.scan_for_issues(bundle_path)
            result["decompiled"] = True

        return result

    async def decompile_hermes(self, bundle_path: Path, output_dir: Path) -> dict:
        """Decompile Hermes bytecode using hermes-dec."""
        if not shutil.which("hermes-dec"):
            return {"error": "hermes-dec not installed", "decompiled": False}

        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "decompiled.js"

        proc = await asyncio.create_subprocess_exec(
            "hermes-dec", str(bundle_path), "-o", str(output_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if output_file.exists():
            return {
                "decompiled": True,
                "output_file": str(output_file),
                "size": output_file.stat().st_size,
            }
        return {"decompiled": False, "error": stderr.decode(errors="replace")[:500]}

    def scan_for_issues(self, bundle_path: Path) -> list[dict]:
        """Scan bundle for security-relevant patterns."""
        content = bundle_path.read_text(errors="replace")
        issues = []
        for pat in _SECURITY_PATTERNS:
            matches = re.findall(pat["pattern"], content)
            if matches:
                issues.append({
                    "pattern": pat["pattern"][:50],
                    "rule_id": pat["rule_id"],
                    "title": pat["title"],
                    "severity": pat["severity"],
                    "match_count": len(matches),
                    "sample": matches[0][:100] if matches else None,
                })
        return issues

    def _extract_strings(self, content: str) -> list[str]:
        strings = []
        for pat in _INTERESTING_PATTERNS:
            strings.extend(re.findall(pat, content))
        return list(set(strings))[:500]  # cap at 500

    def _extract_hermes_strings(self, bundle_path: Path) -> list[str]:
        """Extract readable strings from Hermes bytecode."""
        data = bundle_path.read_bytes()
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 8:
                    s = "".join(current)
                    for pat in _INTERESTING_PATTERNS:
                        if re.search(pat, s):
                            strings.append(s)
                            break
                current = []
        return list(set(strings))[:500]
