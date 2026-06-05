"""REALTYPE-style eval harness for AI-refined decompiler output.

Scores a refine engine against a JSONL test set of records:

    {
      "address": "0x401000",
      "function_name": "fma_helper",
      "decomp_input": "<raw Ghidra/r2 pseudo-C>",
      "expected": "<ground-truth or human-refined C>",
      "expected_structs": ["aes_ctx", "ssl_state"]   // optional
    }

For each record we measure three orthogonal signals:

1. **Recompile rate.** Does the refined C pass `gcc -fsyntax-only`?
   Borrowed from DecLLM (Wong et al., ISSTA 2025).
2. **Identifier overlap.** Jaccard over snake_case tokens in
   {refined_identifiers} ∩ {expected_identifiers} — proxies for how
   well the engine recovered semantically meaningful names.
3. **Struct recall.** Of the named structs the human wrote, what
   fraction does the refined output mention by name? Inspired by
   Idioms's REALTYPE benchmark (Dramko et al., NDSS 2026), which
   showed prior decompile models hallucinate primitive types where a
   composite type was expected.

Returns aggregate counts + a per-record breakdown. Deliberately does
not BLEU/ROUGE — empirically those over-reward style mimicry without
correlating with downstream RE usefulness.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


_IDENT = re.compile(r"\b[a-z_][a-z0-9_]{2,}\b")
_STRUCT = re.compile(r"\bstruct\s+([A-Za-z_]\w+)")


def _identifiers(code: str) -> set[str]:
    return set(_IDENT.findall(code or ""))


def _struct_names(code: str) -> set[str]:
    return set(_STRUCT.findall(code or ""))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


@dataclass
class EvalRecord:
    address: str
    recompile_ok: bool
    identifier_jaccard: float
    struct_recall: float


@dataclass
class EvalSummary:
    total: int
    recompile_rate: float
    mean_identifier_jaccard: float
    mean_struct_recall: float
    records: list[EvalRecord]

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "recompile_rate": self.recompile_rate,
            "mean_identifier_jaccard": self.mean_identifier_jaccard,
            "mean_struct_recall": self.mean_struct_recall,
            "records": [asdict(r) for r in self.records],
        }


def load_dataset(path: str | Path) -> list[dict]:
    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def evaluate(records: Iterable[dict], refine: callable) -> EvalSummary:
    """Run `refine(pseudo_c, function_name, address) -> code_str` over records."""
    from chimera.ai.recompile import recompile_check

    per: list[EvalRecord] = []
    for rec in records:
        decomp = rec.get("decomp_input") or rec.get("decomp") or ""
        expected = rec.get("expected") or ""
        addr = rec.get("address") or ""
        fname = rec.get("function_name") or ""
        refined = refine(decomp, fname, addr) or ""
        ok, _ = asyncio.run(recompile_check(refined))
        ident_j = _jaccard(_identifiers(refined), _identifiers(expected))
        expected_structs = set(rec.get("expected_structs") or [])
        if not expected_structs:
            expected_structs = _struct_names(expected)
        if expected_structs:
            recovered = expected_structs & _struct_names(refined)
            struct_recall = len(recovered) / len(expected_structs)
        else:
            struct_recall = 1.0  # nothing to recover → don't penalize
        per.append(EvalRecord(
            address=addr,
            recompile_ok=ok,
            identifier_jaccard=ident_j,
            struct_recall=struct_recall,
        ))
    n = len(per) or 1
    return EvalSummary(
        total=len(per),
        recompile_rate=sum(1 for r in per if r.recompile_ok) / n,
        mean_identifier_jaccard=sum(r.identifier_jaccard for r in per) / n,
        mean_struct_recall=sum(r.struct_recall for r in per) / n,
        records=per,
    )
