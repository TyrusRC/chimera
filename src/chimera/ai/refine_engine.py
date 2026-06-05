"""Pluggable refine-decompile engine selection.

The default engine is the Anthropic Messages API (same client the other AI
helpers use). Idioms (Dramko et al., NDSS 2026) is an alternative engine
backed by a local fine-tuned LLM — better at recovering composite struct/
enum types than off-the-shelf models, but requires `transformers` + GPU
weights from squaresLab/idioms. Engines are selected by string name so a
future jTrans-Refine, FidelityGPT, or SK2Decompile engine can register
without touching call sites.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Protocol

from chimera.ai.parsing import strip_fence
from chimera.ai.prompts import refine_decomp_prompt


@dataclass
class RefineResult:
    code: str
    engine: str
    raw: str  # un-fenced model output (debug)


class RefineEngine(Protocol):
    name: str

    def refine(self, pseudo_c: str, *, function_name: str = "",
               address: str = "") -> RefineResult: ...


_REGISTRY: dict[str, Callable[[], RefineEngine]] = {}


def register_engine(name: str, factory: Callable[[], RefineEngine]) -> None:
    _REGISTRY[name] = factory


def list_engines() -> list[str]:
    return sorted(_REGISTRY.keys())


def get_engine(name: str) -> RefineEngine:
    if name not in _REGISTRY:
        raise ValueError(
            f"unknown refine engine: {name!r}; available: {list_engines()}"
        )
    return _REGISTRY[name]()


class _ClaudeRefineEngine:
    name = "claude"

    def refine(self, pseudo_c: str, *, function_name: str = "",
               address: str = "") -> RefineResult:
        from chimera.ai.client import default_client
        client = default_client()
        sys_p, user_p = refine_decomp_prompt(
            pseudo_c, function_name=function_name, address=address,
        )
        raw = client.complete(sys_p, user_p)
        return RefineResult(code=strip_fence(raw), engine=self.name, raw=raw)


class _IdiomsRefineEngine:
    """Adapter for the Idioms checkpoint (NDSS 2026, squaresLab/idioms).

    Loads the checkpoint via `transformers` lazily; both `transformers`
    and a checkpoint path (CHIMERA_IDIOMS_CHECKPOINT) must be present or
    `refine` raises a clear error. We deliberately don't pin a version
    of transformers — let the user manage their ML environment.
    """

    name = "idioms"

    def __init__(self) -> None:
        self._pipeline = None

    def _load(self):
        if self._pipeline is not None:
            return self._pipeline
        checkpoint = os.environ.get("CHIMERA_IDIOMS_CHECKPOINT")
        if not checkpoint:
            raise RuntimeError(
                "Idioms engine requires CHIMERA_IDIOMS_CHECKPOINT to point "
                "at a local copy of e.g. squaresLab/idioms-6.7b"
            )
        try:
            from transformers import pipeline  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "Idioms engine requires `transformers` — "
                "`pip install transformers torch`"
            ) from exc
        self._pipeline = pipeline("text-generation", model=checkpoint)
        return self._pipeline

    def refine(self, pseudo_c: str, *, function_name: str = "",
               address: str = "") -> RefineResult:
        pipe = self._load()
        prompt = (
            "Refine the following decompiler output into idiomatic C with "
            "proper struct/enum definitions. Preserve semantics.\n\n"
            f"```c\n{pseudo_c}\n```\n\nRefined:\n```c\n"
        )
        max_new = int(os.environ.get("CHIMERA_IDIOMS_MAX_TOKENS", "2048"))
        out = pipe(prompt, max_new_tokens=max_new, do_sample=False,
                   return_full_text=False)
        raw = out[0]["generated_text"] if out else ""
        return RefineResult(code=strip_fence(raw), engine=self.name, raw=raw)


register_engine("claude", _ClaudeRefineEngine)
register_engine("idioms", _IdiomsRefineEngine)
