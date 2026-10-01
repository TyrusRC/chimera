"""Make ILSpy decompile assemblies that target a .NET newer than it knows.

`ilspycmd` (ICSharpCode.Decompiler) hard-crashes during type-system init on an
assembly whose `TargetFrameworkAttribute` names a runtime the installed build
predates — e.g. an ILSpy 8.x on a `.NETCoreApp,Version=v10.0` assembly dies with
`System.ArgumentException: Argument must be between 0 and 2 (fieldCount)` while
formatting the unknown framework version. The whole decompile fails, not one
method. .NET ships a new major yearly, so any pinned ILSpy eventually hits this.

The fix is a byte-level, length-preserving rewrite of the TargetFramework
version to one ILSpy recognises (`v8.0`), done on a throwaway copy — the IL and
all other metadata are untouched, so the decompiled C# is identical. The version
token `vX.Y` is replaced in place by `v8.0` padded with trailing commas to keep
the exact byte length (so the attribute blob's length prefix stays valid); the
extra commas land after the version value, where the framework-name parser
ignores them.

Read-only w.r.t. the original file; only a temp copy is modified.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

# .NETCoreApp,Version=vX.Y  (captures the major so we only touch runtimes newer
# than what ILSpy 8.x supports). The version value runs 'v' + digits/dots.
_TF_RE = re.compile(rb"\.NETCoreApp,Version=v(\d+)\.\d[\d.]*")

# Highest .NET major a stock ILSpy 8.x type-system handles without crashing.
_MAX_KNOWN_MAJOR = 8


def patch_target_framework(data: bytes) -> bytes | None:
    """Return a copy with the TargetFramework version clamped to v8.0, or None
    if no rewrite is needed (not .NETCoreApp, or already <= v8)."""
    m = _TF_RE.search(data)
    if not m:
        return None
    if int(m.group(1)) <= _MAX_KNOWN_MAJOR:
        return None
    prefix_len = len(b".NETCoreApp,Version=")
    start = m.start() + prefix_len          # points at the leading 'v'
    end = m.end()                            # end of the version token
    token_len = end - start                  # e.g. len("v10.0") == 5
    repl = b"v8.0" + b"," * (token_len - 4)  # same byte length, recognised version
    if len(repl) != token_len:               # defensive: token shorter than "v8.0"
        return None
    return data[:start] + repl + data[end:]


def needs_compat_patch(binary_path: str | Path) -> bool:
    try:
        return patch_target_framework(Path(binary_path).read_bytes()) is not None
    except OSError:
        return False


@contextmanager
def compat_assembly(binary_path: str | Path):
    """Yield a path safe to hand to ilspycmd: the original if it already targets
    a known runtime, else a temp copy with the TargetFramework version clamped.
    The temp copy (if any) is deleted on exit."""
    src = Path(binary_path)
    try:
        data = src.read_bytes()
    except OSError:
        yield str(src)
        return
    patched = patch_target_framework(data)
    if patched is None:
        yield str(src)
        return

    fd, tmp = tempfile.mkstemp(prefix=f"{src.stem}.netcompat.", suffix=src.suffix or ".dll")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(patched)
        logger.info("ILSpy compat: clamped TargetFramework on a temp copy of %s", src.name)
        yield tmp
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
