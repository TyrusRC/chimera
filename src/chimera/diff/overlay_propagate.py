"""Carry analyst annotations from one binary version to the next.

Chimera already has the two halves: `diff_models` matches functions across
two binaries by similarity, and `ProjectOverlay` stores the renames /
comments / types / classifications an analyst put on a binary. This joins
them — given the overlay for version A and the matched pairs A→B, it
translates every annotation onto B's addresses, so a rebuild doesn't throw
away the naming work. Only functions that matched at or above a similarity
floor carry over; everything else is reported, never guessed.

Pure and side-effect-free: `build_plan` computes what would move,
`apply_plan` writes it into B's overlay. That split keeps the decision
previewable (the default) and the write explicit (`--apply`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from chimera.core.addr import normalize_address
from chimera.core.overlay import ProjectOverlay


@dataclass
class Carried:
    """One function's annotations, translated from an A address to a B address."""
    a_address: str
    b_address: str
    similarity: float
    name: str | None = None
    signature: str | None = None
    classification: str | None = None
    comments: dict[str, str] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)


@dataclass
class PropagationPlan:
    carried: list[Carried] = field(default_factory=list)
    skipped_low_similarity: list[dict] = field(default_factory=list)
    skipped_unmatched: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "carried": len(self.carried),
            "skipped_low_similarity": len(self.skipped_low_similarity),
            "skipped_unmatched": len(self.skipped_unmatched),
        }


def _annotations_at(overlay: ProjectOverlay, addr: str) -> dict:
    """Every annotation overlay holds for `addr`, or {} if it holds none."""
    out: dict = {}
    name = overlay.get_function_name(addr)
    if name:
        out["name"] = name
    sig = overlay.get_function_type(addr)
    if sig:
        out["signature"] = sig
    cls = overlay.user_classifications.get(normalize_address(addr))
    if cls:
        out["classification"] = cls
    comments = overlay.get_comments(addr)
    if comments:
        out["comments"] = comments
    variables = overlay.get_variable_renames(addr)
    if variables:
        out["variables"] = variables
    return out


def build_plan(overlay_a: ProjectOverlay, matched: list[dict], *,
               min_similarity: float = 0.85) -> PropagationPlan:
    """Compute which of A's annotations move to B via the matched pairs.

    `matched` is the `matched` list from `diff_models` — dicts carrying
    `a_address`, `b_address`, `similarity`. A function A annotated only
    carries if its pair clears `min_similarity`; otherwise it is reported
    as skipped so the analyst sees what didn't move rather than silently
    losing it.
    """
    plan = PropagationPlan()

    # Addresses A actually annotated — the only ones worth moving.
    annotated_a = (
        set(overlay_a.function_names)
        | set(overlay_a.function_types)
        | set(overlay_a.user_classifications)
        | set(overlay_a.comments)
        | set(overlay_a.variable_renames)
    )
    annotated_a = {normalize_address(a) for a in annotated_a}

    matched_a: set[str] = set()
    for pair in matched:
        a_addr = normalize_address(pair.get("a_address"))
        b_addr = normalize_address(pair.get("b_address"))
        sim = float(pair.get("similarity", 0.0))
        if a_addr not in annotated_a:
            continue
        matched_a.add(a_addr)
        anns = _annotations_at(overlay_a, a_addr)
        if not anns:
            continue
        if sim < min_similarity:
            plan.skipped_low_similarity.append(
                {"a_address": a_addr, "b_address": b_addr, "similarity": sim})
            continue
        plan.carried.append(Carried(
            a_address=a_addr, b_address=b_addr, similarity=sim,
            name=anns.get("name"), signature=anns.get("signature"),
            classification=anns.get("classification"),
            comments=anns.get("comments", {}), variables=anns.get("variables", {}),
        ))

    for a_addr in sorted(annotated_a - matched_a):
        plan.skipped_unmatched.append({"a_address": a_addr})

    return plan


def apply_plan(plan: PropagationPlan, overlay_b: ProjectOverlay) -> int:
    """Write the carried annotations into B's overlay. Returns functions touched.

    Does not save — the caller decides when to persist, so a dry run can
    build-and-inspect without ever writing.
    """
    for c in plan.carried:
        if c.name:
            overlay_b.rename_function(c.b_address, c.name)
        if c.signature:
            overlay_b.set_function_type(c.b_address, c.signature)
        if c.classification:
            overlay_b.set_classification(c.b_address, c.classification)
        for line, text in c.comments.items():
            overlay_b.add_comment(c.b_address, line, text)
        for original, new in c.variables.items():
            overlay_b.rename_variable(c.b_address, original, new)
    return len(plan.carried)
