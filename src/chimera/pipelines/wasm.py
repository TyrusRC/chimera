"""WebAssembly analysis pipeline.

Recon-only, pure-Python: parse the module structure, label the toolchain
(Go-WASM is the common CTF/malware shape), and seed the model with the imports
and whatever functions can be named (exports always; the `name` section when the
build wasn't stripped). The heavyweight levers — wat/decompile and the dynamic
Go oracle/tracer — are separate tools (`wasm_decompile`, `wasm_oracle`), kept
out of `analyze` so loading a 6 MB module stays instant.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chimera.adapters.registry import AdapterRegistry
from chimera.core.cache import AnalysisCache
from chimera.core.config import ChimeraConfig
from chimera.core.resource_manager import ResourceManager
from chimera.model.binary import (
    Architecture, BinaryFormat, BinaryInfo, Framework, Platform,
)
from chimera.model.function import FunctionInfo, ImportEntry
from chimera.model.program import UnifiedProgramModel
from chimera.parsers.wasm import WasmModule, parse_wasm

logger = logging.getLogger(__name__)

# A stripped Go build exports exactly these (plus `mem`); their presence is the
# strongest static Go-WASM tell when the name/producers sections are gone.
_GO_EXPORTS = {"run", "resume", "getsp"}


def detect_go_wasm(mod: WasmModule, path: Path) -> bool:
    """Is this a Go-compiled module? (exports / producers / sibling glue / magic)."""
    export_names = {e.name for e in mod.exports}
    if _GO_EXPORTS.issubset(export_names):
        return True
    if mod.producers and ("Go cmd/compile" in mod.producers or "go1." in mod.producers):
        return True
    if any(i.module == "gojs" for i in mod.imports):
        return True
    if (path.parent / "wasm_exec.js").is_file():
        return True
    try:
        return b"go1." in path.read_bytes()[:4096]
    except OSError:
        return False


async def analyze_wasm(
    path: Path,
    config: ChimeraConfig,
    registry: AdapterRegistry,
    resource_mgr: ResourceManager,
    cache: AnalysisCache,
) -> UnifiedProgramModel:
    """Parse a .wasm module and seed the model. Signature matches the other
    pipelines so the engine can call it uniformly (registry/resource_mgr unused —
    recon is pure-Python)."""
    path = Path(path)
    binary = BinaryInfo.from_path(path)
    binary.format = BinaryFormat.WASM
    binary.platform = Platform.WASM
    binary.arch = Architecture.WASM

    mod = parse_wasm(path)
    is_go = detect_go_wasm(mod, path)
    binary.framework = Framework.GO if is_go else Framework.NONE

    model = UnifiedProgramModel(binary)

    for imp in mod.imports:
        model.add_import(ImportEntry(dll=imp.module, name=imp.field))

    # Exported functions are always nameable; the `name` section adds the rest on
    # an unstripped build. Index them by the wasm func index as a pseudo-address.
    named: dict[int, str] = dict(mod.function_names)
    for exp in mod.exports:
        if exp.kind == "func":
            named.setdefault(exp.index, exp.name)
    for idx, name in sorted(named.items()):
        model.add_function(FunctionInfo(
            address=f"func{idx}", name=name, original_name=name,
            language="wasm", classification="export" if name in
            {e.name for e in mod.exports} else "unknown",
            layer="wasm", source_backend="wasm-parser",
        ))

    summary = mod.to_dict()
    summary["is_go"] = is_go
    # Stash recon on the model for query tools; also cache it under triage.
    model.wasm = summary  # type: ignore[attr-defined]
    try:
        cache.put_json(binary.sha256, "triage",
                       {"platform": "wasm", "wasm": summary})
    except Exception as exc:        # cache is best-effort
        logger.warning("caching wasm triage failed: %s", exc)

    logger.info(
        "WASM pipeline: %s — %s, %d imports, %d funcs (%d defined), %s",
        path.name, "Go" if is_go else "generic", len(mod.imports),
        mod.total_func_count, mod.defined_func_count,
        "stripped" if not mod.function_names else f"{len(mod.function_names)} names",
    )
    return model
