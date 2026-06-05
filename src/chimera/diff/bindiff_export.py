"""BinDiff-compatible CSV export.

zynamics BinDiff (now Google's) writes a wide internal database, but the
interchange format every analyst tool consumes — Diaphora, IDA's BinDiff
loader, downstream scripts — is a flat CSV with one row per matched
function pair:

    addr_a,addr_b,similarity,confidence,name_a,name_b

This is the lingua franca for "two binaries, here's the mapping". We emit
it so chimera diff results can flow into existing analyst pipelines
without bespoke parsing.

Columns:
  - addr_a / addr_b: hex addresses, BinDiff convention is "0x" prefixed.
  - similarity: float in [0, 1], rounded to 4dp for CSV stability.
  - confidence: float in [0, 1]. We synthesize it from the fingerprint
    source: disasm > decomp > name. Real BinDiff derives confidence from
    multiple structural heuristics; ours is a single-axis proxy that an
    analyst can still rank on.
  - name_a / name_b: function names as known to chimera (may be "" when
    the function is anonymous).

Only the `matched` and `changed` buckets produce rows. `added`/`removed`
have no counterpart on the other side so they're not representable in the
pair-wise schema.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable


BINDIFF_CSV_HEADER = ["addr_a", "addr_b", "similarity", "confidence",
                      "name_a", "name_b"]


_FP_CONFIDENCE = {
    "disasm": 1.0,
    "decomp": 0.7,
    "name": 0.3,
}


def _confidence_for(fingerprint_tag: str | None) -> float:
    """Map a fingerprint source tag to a [0, 1] confidence score.

    Backend-prefixed tags (e.g. `keenhash:disasm`) are split — only the
    suffix after the colon drives the score, so cross-backend exports
    rank consistently.
    """
    if not fingerprint_tag:
        return 0.5
    tag = fingerprint_tag.split(":", 1)[-1]
    return _FP_CONFIDENCE.get(tag, 0.5)


def _iter_pair_rows(diff_result: dict) -> Iterable[dict]:
    """Yield the matched and changed rows that have both addresses set."""
    for bucket in ("matched", "changed"):
        for row in diff_result.get(bucket) or []:
            if not row.get("a_address") or not row.get("b_address"):
                continue
            yield row


def export_bindiff_csv(diff_result: dict, output_path: str | Path) -> int:
    """Write `diff_result` to a BinDiff-format CSV at `output_path`.

    Returns the number of pair rows written (excluding the header).
    Overwrites any existing file at `output_path`. Parent directory must
    already exist — we don't create directories implicitly because the
    CLI surfaces the path the user typed.
    """
    out = Path(output_path)
    n = 0
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(BINDIFF_CSV_HEADER)
        for row in _iter_pair_rows(diff_result):
            writer.writerow([
                row["a_address"],
                row["b_address"],
                f"{float(row.get('similarity') or 0.0):.4f}",
                f"{_confidence_for(row.get('fingerprint')):.4f}",
                row.get("a_name") or "",
                row.get("b_name") or "",
            ])
            n += 1
    return n


def parse_bindiff_csv(input_path: str | Path) -> list[dict]:
    """Read a BinDiff-format CSV back into a list of dicts.

    Used by tests for round-trip verification and by analyst scripts that
    want to merge a chimera export into their own pipeline.
    """
    rows: list[dict] = []
    with Path(input_path).open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            rows.append({
                "addr_a": r.get("addr_a", ""),
                "addr_b": r.get("addr_b", ""),
                "similarity": float(r.get("similarity") or 0.0),
                "confidence": float(r.get("confidence") or 0.0),
                "name_a": r.get("name_a", ""),
                "name_b": r.get("name_b", ""),
            })
    return rows
