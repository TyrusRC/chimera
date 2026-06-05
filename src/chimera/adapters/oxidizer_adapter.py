"""Oxidizer adapter — Rust-aware decompilation via angr.

Oxidizer (Liu et al., IEEE S&P 2026) was merged into angr master and
adds Rust-specific decompilation primitives (Result, Option, the `?`
operator, panic!/println! macros, pattern-match recovery). For chimera
this is the right backend whenever the input binary is detected as a
Rust binary — Ghidra/r2 produce barely-readable C for Rust due to
monomorphisation, generic bloat, and the panic-handler scaffolding.

We intentionally avoid pinning an angr version: angr's API is fluid
and the user's environment may carry a fork. If anything imports
wrong the adapter degrades to is_available() == False.
"""

from __future__ import annotations

from pathlib import Path

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory


def _try_import_angr():
    try:
        import angr  # type: ignore[import-not-found]
        return angr
    except ImportError:
        return None


class OxidizerAdapter(BackendAdapter):
    def name(self) -> str:
        return "oxidizer"

    def is_available(self) -> bool:
        return _try_import_angr() is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "pe"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        size_mb = (
            Path(binary_path).stat().st_size / (1024 * 1024)
            if Path(binary_path).exists() else 5
        )
        return ResourceRequirement(
            memory_mb=max(2048, int(size_mb * 80)),
            category=ToolCategory.HEAVY,
            estimated_seconds=max(60, int(size_mb * 20)),
        )

    async def analyze(self, binary_path: str, options: dict) -> dict:
        angr = _try_import_angr()
        if angr is None:
            return {"available": False, "decompiled": False,
                    "error": "angr not installed"}
        try:
            proj = angr.Project(binary_path, auto_load_libs=False)
        except Exception as exc:
            return {"available": True, "decompiled": False,
                    "error": f"angr Project failed: {exc}"}

        # Detect Rust by string panic-handler signature. Avoids false positives
        # on plain C binaries that happen to contain "Rust" in some metadata.
        is_rust = _looks_like_rust(binary_path)
        if not is_rust and not options.get("force"):
            return {
                "available": True, "decompiled": False, "is_rust": False,
                "error": "binary does not look like Rust; use --force to try anyway",
            }

        cfg = proj.analyses.CFGFast(normalize=True, regions=options.get("regions"))
        addresses = options.get("addresses") or []
        if not addresses:
            # Decompile the first N user functions to keep this bounded.
            limit = int(options.get("limit", 20))
            funcs = [f for f in cfg.functions.values()
                     if not f.is_simprocedure and not f.is_plt][:limit]
        else:
            funcs = [cfg.functions.get(int(a, 16)) for a in addresses]
            funcs = [f for f in funcs if f is not None]

        results: list[dict] = []
        for func in funcs:
            try:
                dec = proj.analyses.Decompiler(
                    func, cfg=cfg.model,
                    options=_oxidizer_options(proj),
                )
                code = dec.codegen.text if dec.codegen else ""
            except Exception as exc:
                code = ""
                err = str(exc)
            else:
                err = None
            results.append({
                "address": hex(func.addr),
                "name": func.name,
                "code": code,
                "error": err,
            })
        return {
            "available": True,
            "decompiled": any(r["code"] for r in results),
            "is_rust": is_rust,
            "functions": results,
        }

    async def cleanup(self) -> None:
        pass


def _oxidizer_options(proj):
    """Try to enable Oxidizer-specific decompiler options where present.

    The Oxidizer integration registered new option enums under
    `angr.analyses.decompiler.decompilation_options.options`. We probe
    for the names by lookup and silently skip anything unrecognised so
    older/forked angr installs still work.
    """
    try:
        from angr.analyses.decompiler.decompilation_options import (  # type: ignore[import-not-found]
            options as _DECOMP_OPTIONS,
        )
    except ImportError:
        return None
    wanted_names = {"enable_rust_decompilation", "recover_rust_macros",
                    "recover_rust_patterns"}
    selected = []
    for opt in _DECOMP_OPTIONS:
        if getattr(opt, "param", None) in wanted_names:
            selected.append((opt, True))
    return selected or None


def _looks_like_rust(path: str) -> bool:
    """Heuristic: scan the binary for known Rust strings.

    Rust binaries embed `rust_panic`, `core::` strings, and `RUSTC_*`
    section/symbol names. We grep the bytes — cheap and good enough.
    """
    needles = (b"rust_panic", b"core::panicking", b"std::sys", b"RUSTC_")
    try:
        with open(path, "rb") as fh:
            blob = fh.read(min(8 * 1024 * 1024, Path(path).stat().st_size))
    except OSError:
        return False
    return any(n in blob for n in needles)
