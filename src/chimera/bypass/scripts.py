"""Frida script loader — loads bundled bypass scripts."""

from __future__ import annotations

from pathlib import Path


SCRIPTS_DIR = Path(__file__).parent.parent / "frida_scripts"

# Mapping from bypass type to script filename
_SCRIPT_MAP = {
    "android": {
        "root_bypass": "root_bypass.js",
        "anti_frida": "anti_frida.js",
        "anti_debug": "anti_debug.js",
        "ssl_pinning": "ssl_pinning.js",
    },
    "ios": {
        "jailbreak_bypass": "jailbreak_bypass.js",
        "anti_frida": "anti_frida.js",
        "anti_debug": "anti_debug.js",
        "ssl_pinning": "ssl_pinning.js",
    },
}

# Map protection type → script name per platform
_BYPASS_TO_SCRIPT = {
    "android": {
        "anti_debug": "anti_debug",
        "anti_frida": "anti_frida",
        "root_detection": "root_bypass",
        "integrity": None,  # no generic script yet
        "ssl_pinning": "ssl_pinning",
        "packer": None,
    },
    "ios": {
        "anti_debug": "anti_debug",
        "anti_frida": "anti_frida",
        "jailbreak_detection": "jailbreak_bypass",
        "integrity": None,
        "ssl_pinning": "ssl_pinning",
    },
}


class ScriptLoader:
    def available_scripts(self, platform: str) -> list[str]:
        return list(_SCRIPT_MAP.get(platform, {}).keys())

    def get_script(self, platform: str, name: str) -> str | None:
        filename = _SCRIPT_MAP.get(platform, {}).get(name)
        if not filename:
            return None
        path = SCRIPTS_DIR / platform / filename
        if not path.exists():
            return None
        return path.read_text()

    def get_script_for_bypass(self, platform: str, bypass_type: str) -> str | None:
        script_name = _BYPASS_TO_SCRIPT.get(platform, {}).get(bypass_type)
        if not script_name:
            return None
        return self.get_script(platform, script_name)
