"""Bypass orchestrator — orders and combines bypass scripts.

Known limitation: anti-Frida bypass has a fundamental ordering problem.
Frida must inject before anti-Frida checks execute, but a Frida script
cannot run before Frida itself has attached. Workarounds live outside
Frida (frida-gadget with early-load, kernel-level hooks). This
orchestrator documents the limit in the combined script header.
"""

from __future__ import annotations

import shutil
import subprocess

from chimera.bypass.detector import ProtectionProfile
from chimera.bypass.scripts import ScriptLoader


class BypassOrchestrator:
    def __init__(self):
        self._loader = ScriptLoader()

    def build_bypass_chain(self, profile: ProtectionProfile, platform: str) -> list[dict]:
        chain = []
        for bypass_type in profile.bypass_order():
            source = self._loader.get_script_for_bypass(platform, bypass_type)
            if source:
                chain.append({
                    "name": {
                        "root_detection": "root_bypass",
                        "jailbreak_detection": "jailbreak_bypass",
                    }.get(bypass_type, bypass_type),
                    "type": bypass_type,
                    "source": source,
                })
        return chain

    def get_combined_script(self, profile: ProtectionProfile, platform: str) -> str:
        chain = self.build_bypass_chain(profile, platform)
        parts = [
            "// Chimera combined bypass script",
            f"// Platform: {platform}",
            f"// Protections detected: {', '.join(profile.bypass_order())}",
            "// NOTE: anti-Frida bypass cannot reliably defeat pre-attach checks",
            "// from within a Frida script; use frida-gadget early-load when needed.",
            "",
        ]
        for item in chain:
            parts.append(f"// === {item['type']} bypass ===")
            parts.append(item["source"])
            parts.append("")
        return "\n".join(parts)

    def validate_combined_script(self, script: str) -> dict:
        """Syntax-check the combined script via frida-compile --dry-run when available."""
        if shutil.which("frida-compile") is None:
            return {"validated": False, "reason": "frida-compile not on PATH"}
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(script)
            tmp_path = f.name
        try:
            proc = subprocess.run(
                ["frida-compile", "--dry-run", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "validated": proc.returncode == 0,
                "stderr": proc.stderr[-500:] if proc.returncode != 0 else "",
            }
        finally:
            import os as _os
            _os.unlink(tmp_path)
