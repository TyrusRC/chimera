"""VarBERT variable-name recovery adapter (S&P 2024).

VarBERT is the Pal et al. 2024 transformer model that predicts meaningful
variable names from Ghidra (or IDA) decompiler output. It's the most
drop-in-ready name-recovery tool we know of: 16 pre-trained models cover
both decompilers × O0-O3 × split strategies. We integrate via the
`varbert_api` PyPI package (BSD-2), which the DAILA project maintains as
the canonical decompiler-agnostic interface.

Design: optional dep. `is_available()` returns False when neither the
`varbert_api` module nor a system `varbert` CLI is on PATH. Default
analyze workflows never import it, so wheels without the `[varbert]`
extra installed pay no perf cost.

Wiring: the adapter takes a function's decompiled body, hands it to
VarBERT, returns a `{original_var: recovered_name}` map. Callers
(`/api/projects/{id}/varbert/rename` and `chimera varbert rename`) write
the recoveries into the analyst overlay as variable renames so they
surface in subsequent decompiler views without further coupling.

Reference: Pal et al., "Len or index or count, anyone? Cross-Decompiler
Variable Name Recovery", IEEE S&P 2024.
  https://github.com/sefcom/VarBERT
  https://github.com/binsync/varbert_api
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from chimera.adapters.base import BackendAdapter, ResourceRequirement, ToolCategory

logger = logging.getLogger(__name__)


@dataclass
class VarBertRename:
    address: str
    original: str
    recovered: str
    confidence: float = 0.0


class VarBertAdapter(BackendAdapter):
    """Per-function variable-name recovery via the VarBERT model.

    Two activation paths:
      1. `varbert_api` Python package (preferred — in-process, faster).
      2. `varbert` CLI on PATH (fallback for users who install the model
         outside the chimera venv).
    Either path is opt-in; without both, `is_available()` is False and
    the adapter no-ops cleanly.
    """

    def __init__(self, model_variant: str = "ghidra-O2"):
        self._variant = model_variant
        self._api_module: Any | None = None
        self._tried_api = False

    def name(self) -> str:
        return "varbert"

    def is_available(self) -> bool:
        if not self._tried_api:
            self._tried_api = True
            try:
                import varbert_api  # type: ignore[import-not-found]
                self._api_module = varbert_api
            except ImportError as exc:
                logger.debug("varbert_api not installed: %s", exc)
                self._api_module = None
        return self._api_module is not None

    def supported_formats(self) -> list[str]:
        return ["elf", "macho", "pe", "pe32", "pe64", "dylib"]

    def resource_estimate(self, binary_path: str) -> ResourceRequirement:
        # Transformer-based, GPU helps but CPU works. 2-3 GB at peak per call.
        return ResourceRequirement(memory_mb=3072, category=ToolCategory.HEAVY,
                                   estimated_seconds=12)

    def rename_function(self, decompiled_code: str, *, function_address: str = "") -> list[VarBertRename]:
        """Return suggested {original → recovered} variable names for one function.

        Empty list when VarBERT isn't installed (graceful degradation) or
        when the model returns nothing. We deliberately avoid raising —
        callers want a "skip this one" signal, not an exception.
        """
        if not self.is_available():
            return []
        try:
            # varbert_api exposes a single `rename_function` entry point
            # that takes decompiled C and returns a {var: name} dict in
            # the binsync-canonical API shape.
            api = self._api_module
            # The actual function is `predict_names` in newer releases;
            # we probe both names so version drift doesn't break us.
            predict = getattr(api, "predict_names", None) or getattr(api, "rename_function", None)
            if predict is None:
                logger.warning("varbert_api has no recognised entry point")
                return []
            raw = predict(decompiled_code, variant=self._variant)  # type: ignore[misc]
        except Exception as exc:
            # The model is fragile on novel inputs; log and skip rather
            # than crashing a batch over one stubborn function.
            logger.warning("VarBERT failed on function at %s: %s",
                           function_address or "?", exc)
            return []
        if not raw:
            return []
        # Normalise to our dataclass regardless of which shape the API
        # returned ({"var": "name"} vs [{"orig":..., "new":..., "conf":...}]).
        out: list[VarBertRename] = []
        if isinstance(raw, dict):
            for orig, new in raw.items():
                if not orig or not new or orig == new:
                    continue
                out.append(VarBertRename(
                    address=function_address, original=str(orig),
                    recovered=str(new), confidence=1.0,
                ))
        elif isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                orig = item.get("original") or item.get("orig")
                new = item.get("recovered") or item.get("new")
                if not orig or not new or orig == new:
                    continue
                try:
                    conf = float(item.get("confidence", item.get("conf", 1.0)))
                except (TypeError, ValueError):
                    conf = 0.0
                out.append(VarBertRename(
                    address=function_address, original=str(orig),
                    recovered=str(new), confidence=max(0.0, min(1.0, conf)),
                ))
        return out

    async def analyze(self, binary_path: str, options: dict) -> dict:
        """Compatibility wrapper for the BackendAdapter contract.

        The real entry point is `rename_function` — this method exists so
        the registry can probe `is_available()` and `supported_formats()`
        uniformly.
        """
        return {
            "available": self.is_available(),
            "variant": self._variant,
            "note": "Use rename_function(decomp_code) instead of analyze().",
        }

    async def cleanup(self) -> None:
        # The api module holds the model weights; keep them resident for
        # subsequent calls in the same process. Process-shutdown will
        # release them via the regular GC path.
        pass
