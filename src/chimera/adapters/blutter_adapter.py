"""B(l)utter — Dart AOT snapshot extractor for Flutter apps.

Background. Flutter ships Dart code compiled to AOT machine-code snapshots
(libapp.so on Android, App on iOS). Dart's AOT runtime reserves registers
(PP=R15 Object Pool, THR=R14 Thread on x86-64; X27/X28 on AArch64) and
uses a non-System-V calling convention, so off-the-shelf IDA/Ghidra/r2
can't follow it. The community tool B(l)utter (worawit/blutter, MIT)
parses the snapshot, recovers class hierarchies + method tables, and
emits IDA / radare2 / Ghidra annotation scripts.

We integrate by shelling out — B(l)utter is a CMake C++ build with a
heavy dart-sdk dependency, so building it inside the chimera wheel would
be a poor trade. Instead we detect a `blutter` binary on PATH (or honor
`CHIMERA_BLUTTER_BIN`) and drive it. The output is the same regardless of
who built it.

Activation: opt-in. Default analyze runs detect Flutter via the existing
framework detector but DO NOT invoke B(l)utter. Analysts call
`chimera flutter-extract <apk>` or hit POST /api/projects/{id}/flutter/extract
to trigger it.

Reference:
  https://github.com/worawit/blutter — community SOTA, MIT
  Phrack 71:11 (2023) "Dart AOT internals"
  HITB 2023 — Worawit Wangwarunyoo, "B(l)utter — Reversing Flutter apps"
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class BlutterResult:
    output_dir: Path
    success: bool
    stdout: str = ""
    stderr: str = ""
    classes_dumped: int = 0
    methods_dumped: int = 0


class BlutterAdapter:
    """External-process wrapper around the B(l)utter binary."""

    def __init__(self, binary_path: Optional[str] = None,
                 timeout_s: int = 600):
        self._binary = (
            binary_path
            or os.environ.get("CHIMERA_BLUTTER_BIN")
            or shutil.which("blutter")
        )
        self._timeout_s = timeout_s

    def name(self) -> str:
        return "blutter"

    def is_available(self) -> bool:
        return bool(self._binary) and Path(self._binary).is_file() and \
               os.access(self._binary, os.X_OK)

    def binary_path(self) -> Optional[str]:
        return self._binary

    def extract(self, libapp_path: str | Path, out_dir: str | Path) -> BlutterResult:
        """Run blutter against `libapp_path`, writing artifacts to `out_dir`.

        `libapp_path` should be the Dart AOT snapshot — typically
        `lib/<abi>/libapp.so` from an APK, or
        `Frameworks/App.framework/App` from an IPA. The B(l)utter CLI
        is positional: `blutter <libapp.so> <output_dir>`.
        """
        if not self.is_available():
            return BlutterResult(
                output_dir=Path(out_dir),
                success=False,
                stderr="blutter binary not found on PATH and "
                       "CHIMERA_BLUTTER_BIN not set",
            )
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                [self._binary, str(libapp_path), str(out)],
                capture_output=True, text=True,
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return BlutterResult(
                output_dir=out, success=False,
                stderr=f"blutter timed out after {self._timeout_s}s: {exc}",
            )
        except OSError as exc:
            return BlutterResult(
                output_dir=out, success=False,
                stderr=f"failed to spawn blutter: {exc}",
            )
        classes, methods = _count_artifacts(out)
        return BlutterResult(
            output_dir=out,
            success=(proc.returncode == 0),
            stdout=proc.stdout,
            stderr=proc.stderr,
            classes_dumped=classes,
            methods_dumped=methods,
        )


def _count_artifacts(out_dir: Path) -> tuple[int, int]:
    """Best-effort count of B(l)utter's output for status reporting.

    B(l)utter writes Dart source-like files (objs/*.dart, asm/*.dart)
    plus IDA / radare2 scripts. We just count file counts as a rough
    yardstick — full parsing of each file would be over-engineering for
    a status line.
    """
    classes = 0
    methods = 0
    if not out_dir.exists():
        return classes, methods
    for p in out_dir.rglob("*.dart"):
        classes += 1
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        methods += text.count(" void ") + text.count(" Future<") + text.count(" int ")
    return classes, methods


def detect_libapp(unpack_dir: Path) -> Optional[Path]:
    """Find a Dart AOT snapshot inside an unpacked APK / IPA directory.

    APK layout: `lib/<abi>/libapp.so` (and `libflutter.so` is the engine).
    IPA layout: `Frameworks/App.framework/App` (binary) + `Flutter.framework/Flutter`.
    Returns the first libapp candidate or None.
    """
    if not unpack_dir.exists():
        return None
    candidates = list(unpack_dir.rglob("libapp.so"))
    if candidates:
        # Prefer arm64-v8a > arm64 > armeabi-v7a > others — analyst usually
        # wants the modern arch.
        priority = ["arm64-v8a", "arm64", "armeabi-v7a"]
        for arch in priority:
            for c in candidates:
                if arch in str(c):
                    return c
        return candidates[0]
    app_fw = unpack_dir / "Frameworks" / "App.framework" / "App"
    if app_fw.exists():
        return app_fw
    return None
