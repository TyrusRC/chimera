"""Android native-similarity pipeline — APK to OAT to BinExport to BinDiff.

Implements the Phrack 72:13 (Bleier & Lindorfer, Aug 2025) workflow for
catching DEX-level obfuscated similarity at the AOT-compiled native
layer:

    APK -> unzip -> classes.dex
        -> dex2oat ......... (Android AOSP compiler, ART runtime)
        -> classes.oat
        -> oatdump2binexport (community)
        -> classes.BinExport
        -> bindiff           (Zynamics / Google)
        -> .BinDiff (sqlite) — similarity matrix per function

The pipeline is opt-in: chimera does not bundle dex2oat or bindiff, and
the orchestrator degrades to `{"available": False, "error": ...}` with a
specific missing-tool message when either is absent.

We rely on three external binaries:
  - `dex2oat`              — from the Android SDK build-tools / AOSP host.
  - `oatdump2binexport`    — community converter (see Phrack 72:13).
  - `bindiff` (or `bindiff_bin`) — the BinDiff differ CLI (v8+).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sqlite3
import zipfile
from pathlib import Path
from typing import Any

from chimera.adapters.oatdump_adapter import OatDumpAdapter

logger = logging.getLogger(__name__)


_BINDIFF_CANDIDATES = ("bindiff", "bindiff_bin", "differ")


def _which_bindiff() -> str | None:
    for name in _BINDIFF_CANDIDATES:
        p = shutil.which(name)
        if p:
            return p
    return None


def _extract_classes_dex(apk: Path, dest_dir: Path) -> Path | None:
    """Pull classes.dex (or the largest classesN.dex) out of an APK.

    Multi-dex apps ship classes.dex + classes2.dex + ... — we pick the
    plain `classes.dex` first; if absent we fall back to the largest one.
    Real-world callers may want to dex2oat each, but for similarity the
    primary DEX is the usual entry point.
    """
    if not apk.exists():
        return None
    try:
        with zipfile.ZipFile(apk, "r") as zf:
            names = [n for n in zf.namelist()
                     if n.startswith("classes") and n.endswith(".dex")]
            if not names:
                return None
            preferred = "classes.dex" if "classes.dex" in names else \
                        max(names, key=lambda n: zf.getinfo(n).file_size)
            dest_dir.mkdir(parents=True, exist_ok=True)
            out_path = dest_dir / Path(preferred).name
            with zf.open(preferred) as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            return out_path
    except (zipfile.BadZipFile, OSError) as exc:
        logger.warning("Failed to read APK %s: %s", apk, exc)
        return None


async def _run(*cmd: str, timeout_s: int = 600) -> tuple[int, str, str]:
    """Spawn a subprocess and capture (rc, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"timeout after {timeout_s}s"
    return (
        proc.returncode or 0,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


async def _dex_to_oat(dex_path: Path, out_oat: Path, *,
                      isa: str = "arm64") -> tuple[bool, str]:
    """Drive dex2oat to compile a DEX into an OAT image.

    dex2oat's CLI is stable enough across Android versions that
    `--dex-file=`, `--oat-file=`, and `--instruction-set=` are reliable.
    We pick arm64 by default since modern apps overwhelmingly ship
    arm64-v8a — analysts can override via env later if needed.
    """
    dex2oat = shutil.which("dex2oat")
    if not dex2oat:
        return False, "dex2oat not found on PATH (need Android AOSP host tools)"
    out_oat.parent.mkdir(parents=True, exist_ok=True)
    rc, _, stderr = await _run(
        dex2oat,
        f"--dex-file={dex_path}",
        f"--oat-file={out_oat}",
        f"--instruction-set={isa}",
        # dex2oat is chatty about missing boot images; we tolerate that
        # because OAT layout is enough for structural diff.
        "--compiler-filter=quicken",
    )
    if rc != 0:
        return False, f"dex2oat failed (rc={rc}): {stderr[:400]}"
    if not out_oat.exists():
        return False, "dex2oat exited 0 but produced no OAT file"
    return True, ""


async def _run_bindiff(be_a: Path, be_b: Path, out_dir: Path) -> tuple[Path | None, str]:
    """Diff two BinExport files. Returns (sqlite_path, error)."""
    bindiff = _which_bindiff()
    if not bindiff:
        return None, ("bindiff not found on PATH (need BinDiff v8+; "
                      "https://github.com/google/bindiff)")
    out_dir.mkdir(parents=True, exist_ok=True)
    rc, _, stderr = await _run(
        bindiff,
        f"--primary={be_a}",
        f"--secondary={be_b}",
        f"--output_dir={out_dir}",
    )
    if rc != 0:
        return None, f"bindiff failed (rc={rc}): {stderr[:400]}"
    # BinDiff writes <primary>_vs_<secondary>.BinDiff (sqlite) in out_dir.
    candidates = sorted(out_dir.glob("*.BinDiff"))
    if not candidates:
        return None, "bindiff exited 0 but produced no .BinDiff sqlite"
    return candidates[0], ""


def _summarise_bindiff(db_path: Path, *, top_n: int = 20) -> dict[str, Any]:
    """Read the BinDiff sqlite schema and produce a compact summary.

    BinDiff's `function` table has columns including `address1`, `address2`,
    `name1`, `name2`, `similarity`, and `confidence`. We pull totals and
    the top-N matches by similarity. We tolerate schema drift by probing
    for columns and falling back gracefully — the file format has moved
    between BinDiff 6/7/8.
    """
    out: dict[str, Any] = {
        "matched_functions": 0,
        "mean_similarity": 0.0,
        "top_matches": [],
    }
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.Error as exc:
        out["error"] = f"open bindiff db: {exc}"
        return out
    try:
        cur = conn.cursor()
        # Probe for the function table; some BinDiff versions call it
        # `functionmatches` or `function`.
        tables = {row[0] for row in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        table = None
        for candidate in ("function", "functionmatches"):
            if candidate in tables:
                table = candidate
                break
        if table is None:
            out["error"] = "no recognised function table in bindiff db"
            return out
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        out["matched_functions"] = int(cur.fetchone()[0] or 0)
        try:
            cur.execute(f"SELECT AVG(similarity) FROM {table}")
            avg = cur.fetchone()[0]
            out["mean_similarity"] = float(avg) if avg is not None else 0.0
        except sqlite3.Error:
            pass
        # Best-effort top-N pull. Column names vary across versions.
        try:
            cur.execute(
                f"SELECT name1, name2, similarity, confidence "
                f"FROM {table} ORDER BY similarity DESC LIMIT ?",
                (top_n,),
            )
            out["top_matches"] = [
                {
                    "name_a": r[0],
                    "name_b": r[1],
                    "similarity": float(r[2]) if r[2] is not None else 0.0,
                    "confidence": float(r[3]) if r[3] is not None else 0.0,
                }
                for r in cur.fetchall()
            ]
        except sqlite3.Error as exc:
            out["top_matches_error"] = str(exc)
    finally:
        conn.close()
    return out


async def diff_apks(apk_a: Path, apk_b: Path, *, out_dir: Path,
                    isa: str = "arm64") -> dict[str, Any]:
    """Run the full OAT-layer similarity pipeline on two APKs.

    Returns a structured summary; gracefully degrades when dex2oat,
    oatdump2binexport, or bindiff are missing — the `available` flag and
    `error` field name the missing tool explicitly so analysts know what
    to install.
    """
    apk_a = Path(apk_a)
    apk_b = Path(apk_b)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not shutil.which("dex2oat"):
        return {
            "available": False,
            "error": ("dex2oat not found on PATH — install Android AOSP "
                      "host tools (build-tools/<ver>/dex2oat)"),
        }
    adapter = OatDumpAdapter()
    if not adapter.is_available():
        return {
            "available": False,
            "error": ("oatdump2binexport not found — set "
                      "CHIMERA_OATDUMP2BINEXPORT_BIN or put it on PATH "
                      "(see Phrack 72:13)"),
        }
    if _which_bindiff() is None:
        return {
            "available": False,
            "error": ("bindiff not found on PATH — install BinDiff v8+ "
                      "from https://github.com/google/bindiff"),
        }

    # 1. Extract classes.dex from each APK.
    work_a = out_dir / "a"
    work_b = out_dir / "b"
    dex_a = _extract_classes_dex(apk_a, work_a)
    dex_b = _extract_classes_dex(apk_b, work_b)
    if dex_a is None or dex_b is None:
        return {
            "available": True,
            "error": (f"could not extract classes.dex from "
                      f"{'A' if dex_a is None else 'B'}"),
        }

    # 2. Compile each DEX to OAT.
    oat_a = work_a / "classes.oat"
    oat_b = work_b / "classes.oat"
    ok_a, err_a = await _dex_to_oat(dex_a, oat_a, isa=isa)
    if not ok_a:
        return {"available": True, "error": f"A: {err_a}"}
    ok_b, err_b = await _dex_to_oat(dex_b, oat_b, isa=isa)
    if not ok_b:
        return {"available": True, "error": f"B: {err_b}"}

    # 3. Run oatdump2binexport on each OAT.
    be_a = work_a / "classes.BinExport"
    be_b = work_b / "classes.BinExport"
    res_a = await adapter.analyze(str(oat_a), {"out": str(be_a)})
    if res_a.get("error"):
        return {"available": True, "error": f"A oatdump2binexport: {res_a['error']}"}
    res_b = await adapter.analyze(str(oat_b), {"out": str(be_b)})
    if res_b.get("error"):
        return {"available": True, "error": f"B oatdump2binexport: {res_b['error']}"}

    # 4. Diff via BinDiff.
    bindiff_out = out_dir / "bindiff"
    db_path, derr = await _run_bindiff(be_a, be_b, bindiff_out)
    if db_path is None:
        return {"available": True, "error": derr}

    # 5. Parse the BinDiff sqlite into a summary.
    summary = _summarise_bindiff(db_path)
    return {
        "available": True,
        "error": None,
        "bindiff_db": str(db_path),
        "binexport_a": str(be_a),
        "binexport_b": str(be_b),
        "functions_a": int(res_a.get("function_count") or 0),
        "functions_b": int(res_b.get("function_count") or 0),
        **summary,
    }
