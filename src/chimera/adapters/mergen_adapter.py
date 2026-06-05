"""Mergen — VMProtect / Themida devirtualizer (DEF CON 33, 2025).

Mergen (NaC-L/Mergen, MIT) is an LLVM-IR-based devirtualizer for VM-
protected regions in commercial packers like VMProtect and Themida.
Given a protected binary plus the start address of a virtualised
function, it symbolically executes the VM dispatcher, lifts the handler
chain to LLVM IR, and emits a cleaned binary (or a `.bc` / `.ll` file)
that an analyst can push back through Ghidra / r2 to recover something
close to the original control flow.

Wiring: subprocess. Mergen is a CMake C++ build with an LLVM
dependency, so bundling it inside the chimera wheel is impractical. We
detect a `mergen` binary on PATH or honour `CHIMERA_MERGEN_BIN`, and
shell out. The CLI shape is `mergen --in <path> --out <outdir> --start
<hex>` per the project's README; we treat flag names defensively so
upstream renames don't immediately break us — anything unrecognised
shows up in stderr.

Activation: opt-in. Default `chimera analyze` does NOT call Mergen even
when VMP/Themida is detected — analysts trigger it explicitly via
`chimera vmp-devirt <bin> --start 0x...` (or the REST endpoint) so the
heavy lifting only runs when wanted.

Reference:
  https://github.com/NaC-L/Mergen — MIT, DEF CON 33 (Aug 2025)
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


class MergenAdapter(BackendAdapter):
    """External-process wrapper around the Mergen devirtualizer.

    Mergen takes a long time and a lot of memory (it builds an LLVM
    module of every handler the VM dispatches through), so we class it
    HEAVY and let the scheduler gate concurrency. `is_available()` is
    cheap — a PATH lookup — and never raises, so the registry can probe
    it on every run without slowing things down.
    """

    def __init__(self, binary: Optional[str] = None):
        self._binary = (
            binary
            or os.environ.get("CHIMERA_MERGEN_BIN")
            or shutil.which("mergen")
        )

    def name(self) -> str:
        return "mergen"

    def is_available(self) -> bool:
        if not self._binary:
            return False
        p = Path(self._binary)
        return p.is_file() and os.access(self._binary, os.X_OK)

    def binary_path(self) -> Optional[str]:
        return self._binary

    def supported_formats(self) -> list[str]:
        # VMProtect targets PE primarily; Themida supports ELF builds too.
        return ["pe", "elf"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        """Mergen's LLVM IR grows roughly with handler-chain depth, which
        in turn scales with binary size in practice. 20× file size is a
        rough upper bound we've seen on commercial samples — undershoot
        and the OOM killer wakes up mid-lift.
        """
        try:
            size = Path(binary_path).stat().st_size
        except OSError:
            size = 0
        # Floor at 2 GB — even a small VMP'd routine pulls in a lot of IR.
        mem_mb = max(2048, (size * 20) // (1024 * 1024))
        return ResourceRequirement(
            memory_mb=int(mem_mb),
            category=ToolCategory.HEAVY,
            estimated_seconds=300,
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Devirtualise the routine at `options['start']` in `binary_path`.

        Required option:
          start (str | int): start address of the virtualised function,
            either an int or a hex string like "0x140001000".

        Optional:
          out_dir (str | Path): where Mergen writes its artefacts.
            Defaults to `<binary_path>.mergen/` next to the input.
          timeout (int): seconds before the subprocess is killed.
            Default 600.

        Returns a dict with the canonical adapter shape:
          available, devirt_output, output_dir, lifted_functions, error.
        Never raises — failures surface as `error` and `available=False`
        so batch callers can move on.
        """
        if not self.is_available():
            return {
                "available": False,
                "devirt_output": None,
                "output_dir": None,
                "lifted_functions": [],
                "error": "mergen binary not found on PATH and "
                         "CHIMERA_MERGEN_BIN not set",
            }

        start = options.get("start")
        if start is None:
            return {
                "available": True,
                "devirt_output": None,
                "output_dir": None,
                "lifted_functions": [],
                "error": "Mergen requires options['start'] (VM entry address)",
            }
        start_hex = _format_addr(start)

        out_dir = Path(options.get("out_dir") or f"{binary_path}.mergen")
        out_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(options.get("timeout", 600))

        cmd = [
            self._binary,  # type: ignore[list-item]
            "--in", str(binary_path),
            "--out", str(out_dir),
            "--start", start_hex,
        ]
        logger.info("mergen: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout,
                )
            except asyncio.TimeoutError:
                # Best-effort kill — Mergen can wedge on pathological samples.
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()
                return {
                    "available": True,
                    "devirt_output": None,
                    "output_dir": str(out_dir),
                    "lifted_functions": [],
                    "error": f"mergen timed out after {timeout}s",
                }
        except OSError as exc:
            return {
                "available": True,
                "devirt_output": None,
                "output_dir": str(out_dir),
                "lifted_functions": [],
                "error": f"failed to spawn mergen: {exc}",
            }

        stdout = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr = (stderr_b or b"").decode("utf-8", errors="replace")
        rc = proc.returncode

        lifted = _collect_lifted_artifacts(out_dir)
        # Mergen emits LLVM bitcode / cleaned binary; pick whichever is
        # present so the caller has one canonical "open this" pointer.
        devirt = _pick_primary_output(out_dir, start_hex)

        if rc != 0 and not lifted:
            return {
                "available": True,
                "devirt_output": None,
                "output_dir": str(out_dir),
                "lifted_functions": [],
                "error": (
                    f"mergen exited {rc}: "
                    f"{(stderr or stdout)[:500].strip()}"
                ),
            }

        return {
            "available": True,
            "devirt_output": str(devirt) if devirt else None,
            "output_dir": str(out_dir),
            "lifted_functions": lifted,
            "error": None,
        }

    async def cleanup(self) -> None:
        # No persistent state — the binary is invoked fresh each call.
        return None


def _format_addr(value: object) -> str:
    """Normalise the user-supplied start address to a `0x…` hex string.

    Mergen accepts hex on the command line; we standardise so the call
    site is the same whether the caller passed `0x140001000` (str),
    `"140001000"` (str), or `5368754176` (int).
    """
    if isinstance(value, int):
        return hex(value)
    s = str(value).strip()
    if not s:
        return "0x0"
    if s.startswith(("0x", "0X")):
        return "0x" + s[2:].lower()
    # Bare-decimal fallback — try int parse, otherwise assume hex.
    try:
        return hex(int(s, 10))
    except ValueError:
        return "0x" + s.lower()


def _collect_lifted_artifacts(out_dir: Path) -> list[str]:
    """Return the names of LLVM IR / bitcode files Mergen wrote.

    Each file roughly corresponds to one lifted handler chain (i.e. one
    devirtualised function). We surface filenames rather than parsing
    the IR — the analyst's downstream tool (Ghidra, opt, llvm-dis) is
    the right place to inspect contents.
    """
    if not out_dir.exists():
        return []
    out: list[str] = []
    for pattern in ("*.ll", "*.bc"):
        for p in sorted(out_dir.rglob(pattern)):
            out.append(p.name)
    return out


def _pick_primary_output(out_dir: Path, start_hex: str) -> Optional[Path]:
    """Pick the most-likely "open this next" artifact for the analyst.

    Preference order:
      1. A cleaned binary matching the start address (e.g.
         `devirt_0x140001000.exe`).
      2. Any cleaned `.exe` / `.dll` / `.so` in the output dir.
      3. The first `.bc` (bitcode is what users feed back into Ghidra
         via the LLVM-to-PCode importer).
      4. The first `.ll` text-IR file as a last resort.
    """
    if not out_dir.exists():
        return None
    tag = start_hex.lower()
    for p in out_dir.iterdir():
        if tag in p.name.lower() and p.suffix.lower() in {".exe", ".dll", ".so"}:
            return p
    for ext in (".exe", ".dll", ".so", ".bc", ".ll"):
        matches = sorted(out_dir.rglob(f"*{ext}"))
        if matches:
            return matches[0]
    return None
