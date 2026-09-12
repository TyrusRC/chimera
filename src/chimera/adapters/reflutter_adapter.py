"""reFlutter — dynamic instrumentation + traffic interception for Flutter apps.

Background. B(l)utter (see `blutter_adapter`) is a *static* Dart AOT snapshot
extractor. reFlutter (Impact-I/reFlutter, MIT) is the complementary *dynamic*
tool: it repackages an APK/IPA with a patched Flutter engine so that, on device,
the app either

  - **traffic mode** — routes all its HTTP(S) through a proxy you specify and
    disables certificate pinning, so Burp/mitmproxy can see it. This is the
    standard way to MITM a Flutter app, which otherwise ignores the system proxy
    and bundles its own BoringSSL/CA (normal proxy+user-CA MITM fails), or
  - **offset mode** — dumps absolute Dart code offsets (`dump.dart`) at runtime,
    which pair with a disassembler when B(l)utter's static parse can't handle the
    app's Dart runtime.

We integrate by shelling out (reFlutter is a pip tool that downloads a prebuilt
patched engine matching the app's snapshot hash — a poor fit to vendor into the
wheel). Detect a `reflutter` binary on PATH (or honor `CHIMERA_REFLUTTER_BIN`)
and drive it. The tool is interactive (it prompts for the mode and, in traffic
mode, the proxy IP); we feed those answers on stdin.

NOTE (ceiling): reFlutter needs network to fetch the matching patched engine,
and its output `release.RE.apk` is UNSIGNED — it must be zipaligned + signed
(`apksigner` / uber-apk-signer) before install. We emit the APK and say so; we
do not sign automatically. Read-only w.r.t. the input; writes only into out_dir.

Reference: https://github.com/Impact-I/reFlutter (MIT) — `pip install reflutter`.
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
class ReflutterResult:
    output_dir: Path
    success: bool
    mode: str = "traffic"
    patched_apk: Optional[str] = None
    proxy_ip: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    hint: str = ""


class ReflutterAdapter:
    """External-process wrapper around the reFlutter binary."""

    def __init__(self, binary_path: Optional[str] = None, timeout_s: int = 900):
        self._binary = (
            binary_path
            or os.environ.get("CHIMERA_REFLUTTER_BIN")
            or shutil.which("reflutter")
        )
        self._timeout_s = timeout_s

    def name(self) -> str:
        return "reflutter"

    def is_available(self) -> bool:
        return bool(self._binary) and Path(self._binary).is_file() and \
            os.access(self._binary, os.X_OK)

    def binary_path(self) -> Optional[str]:
        return self._binary

    def patch(self, apk_path: str | Path, out_dir: str | Path, *,
              mode: str = "traffic", proxy_ip: Optional[str] = None) -> ReflutterResult:
        """Repackage `apk_path` with the patched engine, writing into `out_dir`.

        mode="traffic" needs `proxy_ip` (the Burp/mitmproxy host the app should
        dial); mode="offset" dumps Dart offsets at runtime and needs no IP.
        reFlutter writes `release.RE.apk` into its working directory, so we run
        it with cwd=out_dir and locate that file.
        """
        out = Path(out_dir)
        if not self.is_available():
            return ReflutterResult(
                output_dir=out, success=False, mode=mode,
                stderr="reflutter binary not found on PATH and "
                       "CHIMERA_REFLUTTER_BIN not set (pip install reflutter)",
            )
        if mode not in ("traffic", "offset"):
            return ReflutterResult(output_dir=out, success=False, mode=mode,
                                   stderr=f"unknown mode {mode!r} (traffic|offset)")
        if mode == "traffic" and not proxy_ip:
            return ReflutterResult(
                output_dir=out, success=False, mode=mode,
                stderr="traffic mode needs a proxy IP (--proxy)")
        out.mkdir(parents=True, exist_ok=True)
        # reFlutter is interactive: option ("1" traffic / "2" offset) then, for
        # traffic, the proxy IP. Feed both on stdin.
        stdin = "1\n" + f"{proxy_ip}\n" if mode == "traffic" else "2\n"
        try:
            proc = subprocess.run(
                [self._binary, str(Path(apk_path).resolve())],
                input=stdin, capture_output=True, text=True,
                cwd=str(out), timeout=self._timeout_s, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ReflutterResult(output_dir=out, success=False, mode=mode,
                                   stderr=f"reflutter timed out after {self._timeout_s}s: {exc}")
        except OSError as exc:
            return ReflutterResult(output_dir=out, success=False, mode=mode,
                                   stderr=f"failed to spawn reflutter: {exc}")
        patched = _find_patched_apk(out)
        ok = proc.returncode == 0 and patched is not None
        hint = ""
        if patched:
            hint = (f"Sign before install: `zipalign -p 4 {Path(patched).name} aligned.apk "
                    f"&& apksigner sign --ks <keystore> aligned.apk` (or uber-apk-signer). ")
            if mode == "traffic":
                hint += (f"Then set your proxy (Burp/mitmproxy) to listen on {proxy_ip}:8083, "
                         "install the APK, and traffic + disabled pinning flow through it.")
            else:
                hint += "Run the app; it writes Dart code offsets to dump.dart on-device."
        return ReflutterResult(
            output_dir=out, success=ok, mode=mode, patched_apk=patched,
            proxy_ip=proxy_ip, stdout=proc.stdout, stderr=proc.stderr, hint=hint,
        )


def _find_patched_apk(out_dir: Path) -> Optional[str]:
    """reFlutter emits `release.RE.apk`; fall back to any *.RE.apk in out_dir."""
    direct = out_dir / "release.RE.apk"
    if direct.is_file():
        return str(direct)
    for c in sorted(out_dir.glob("*.RE.apk")):
        if c.is_file():
            return str(c)
    return None
