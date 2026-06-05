"""DecLLM-style recompile gate for AI-refined decompiler output.

Strategy mirrors DecLLM (Wong et al., ISSTA 2025): run the candidate C
through `gcc -fsyntax-only` against a permissive sysroot, and if it
fails, hand the diagnostics back to the model for one repair round.
We don't try to actually link or execute — syntax-only is the cheapest
sanity check that catches most LLM scaffold errors (missing braces,
typoed identifiers, dropped semicolons) without dragging in libc.

Returning the raw compiler stderr verbatim is intentional: the repair
prompt benefits more from the literal `error: expected ';' before
'while'` than from any pretty-printed summary.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path


PERMISSIVE_HEADER = """\
/* chimera recompile-gate prelude — declares enough scaffolding that
 * decompiled snippets pass -fsyntax-only without dragging in libc. */
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long int64_t;
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;
typedef int bool;
#define true 1
#define false 0
#define NULL ((void*)0)
"""


def _find_compiler() -> str | None:
    return shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")


async def recompile_check(code: str, *, timeout: int = 10) -> tuple[bool, str]:
    """Run `gcc -fsyntax-only` against `code`; return (ok, stderr-tail).

    `ok` is True only when the compiler exits 0. The error tail is
    truncated to ~2 KiB so a repair prompt stays inside the model's
    context budget.
    """
    compiler = os.environ.get("CHIMERA_RECOMPILE_CC") or _find_compiler()
    if not compiler:
        return False, "no C compiler on PATH (set CHIMERA_RECOMPILE_CC)"
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tmp:
        tmp.write(PERMISSIVE_HEADER)
        tmp.write("\n")
        tmp.write(code)
        path = Path(tmp.name)
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                compiler, "-fsyntax-only", "-w", str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, OSError) as exc:
            return False, f"failed to invoke compiler: {exc}"
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, "compiler timed out"
    finally:
        path.unlink(missing_ok=True)
    if proc.returncode == 0:
        return True, ""
    return False, stderr.decode(errors="replace")[-2048:]
