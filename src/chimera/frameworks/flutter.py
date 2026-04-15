"""Flutter analyzer — Dart AOT snapshot analysis via blutter + string extraction."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


class FlutterAnalyzer:
    def find_binaries(self, unpack_dir: Path) -> dict:
        """Locate libapp.so/App.framework and libflutter.so/Flutter.framework."""
        unpack_dir = Path(unpack_dir)
        result = {"libapp": None, "libflutter": None, "platform": None}

        # Android
        for arch in ["arm64-v8a", "armeabi-v7a"]:
            lib_dir = unpack_dir / "lib" / arch
            app = lib_dir / "libapp.so"
            flutter = lib_dir / "libflutter.so"
            if app.exists():
                result["libapp"] = app
                result["libflutter"] = flutter if flutter.exists() else None
                result["platform"] = "android"
                result["arch"] = arch
                return result

        # iOS
        app_fw = unpack_dir / "Frameworks" / "App.framework" / "App"
        flutter_fw = unpack_dir / "Frameworks" / "Flutter.framework" / "Flutter"
        if app_fw.exists():
            result["libapp"] = app_fw
            result["libflutter"] = flutter_fw if flutter_fw.exists() else None
            result["platform"] = "ios"
            return result

        return result

    async def run_blutter(self, libapp_path: Path, output_dir: Path) -> dict:
        """Run blutter to recover Dart class/method names from AOT snapshot."""
        if not shutil.which("blutter"):
            return {"error": "blutter not installed", "analyzed": False}

        output_dir.mkdir(parents=True, exist_ok=True)

        proc = await asyncio.create_subprocess_exec(
            "blutter", str(libapp_path), str(output_dir),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        asm_dir = output_dir / "asm"
        dart_classes = []
        if asm_dir.exists():
            for f in asm_dir.rglob("*.dart"):
                dart_classes.append(f.stem)

        return {
            "analyzed": proc.returncode == 0,
            "output_dir": str(output_dir),
            "class_count": len(dart_classes),
            "classes": dart_classes[:200],
            "error": stderr.decode(errors="replace")[:500] if proc.returncode != 0 else None,
        }

    def extract_dart_strings(self, binary_path: Path) -> list[str]:
        """Extract readable strings from Dart AOT binary (string pool extraction)."""
        data = binary_path.read_bytes()
        strings = []
        current = []
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= 8:
                    s = "".join(current)
                    if _is_interesting_string(s):
                        strings.append(s)
                current = []
        return list(set(strings))[:1000]

    def detect_obfuscation(self, blutter_output: dict) -> bool:
        """Check if --obfuscate flag was used (class names are @_a1, @_b2)."""
        classes = blutter_output.get("classes", [])
        if not classes:
            return False
        obfuscated = sum(1 for c in classes if re.match(r"^@?_[a-z]\d+$", c))
        return obfuscated / len(classes) > 0.5 if classes else False


def _is_interesting_string(s: str) -> bool:
    patterns = [
        r"https?://",
        r"api[_\-.]",
        r"secret|token|key|password|auth",
        r"firebase|supabase|aws",
        r"\.com/|\.io/|\.dev/",
    ]
    return any(re.search(p, s, re.IGNORECASE) for p in patterns)
