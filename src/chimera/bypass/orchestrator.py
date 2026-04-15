"""Bypass orchestrator — orders and combines bypass scripts."""

from __future__ import annotations

from chimera.bypass.detector import ProtectionProfile
from chimera.bypass.scripts import ScriptLoader


class BypassOrchestrator:
    def __init__(self):
        self._loader = ScriptLoader()

    def build_bypass_chain(self, profile: ProtectionProfile, platform: str) -> list[dict]:
        """Build ordered list of bypass scripts to execute."""
        chain = []
        for bypass_type in profile.bypass_order():
            source = self._loader.get_script_for_bypass(platform, bypass_type)
            if source:
                chain.append({
                    "name": bypass_type if bypass_type != "root_detection" else "root_bypass",
                    "type": bypass_type,
                    "source": source,
                })
        return chain

    def get_combined_script(self, profile: ProtectionProfile, platform: str) -> str:
        """Combine all bypass scripts into a single Frida script."""
        chain = self.build_bypass_chain(profile, platform)
        parts = [
            "// Chimera combined bypass script",
            f"// Platform: {platform}",
            f"// Protections detected: {', '.join(profile.bypass_order())}",
            "",
        ]
        for item in chain:
            parts.append(f"// === {item['type']} bypass ===")
            parts.append(item["source"])
            parts.append("")
        return "\n".join(parts)
