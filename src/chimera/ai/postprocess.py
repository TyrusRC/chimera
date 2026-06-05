"""Text-level post-processors for LLM-refined decompiler output.

Two pipelines, run after `refine_decomp_prompt` returns. Both are
deliberately conservative — we only fire on patterns where the
rewrite is provably semantics-preserving on its face, so an analyst
can audit the diff without re-reading the whole function.

- `simplify_mba`: msynth-style mixed-boolean-arithmetic simplifier.
  msynth (https://github.com/mrphrazer/msynth) is a heavier symbolic
  toolkit; if it's importable we prefer it. Otherwise we apply a tiny
  hand-curated rule set via regex that handles the most common
  identities decompilers leave behind (`x ^ x`, `x & 0`, `x | 0`, etc).

- `refactor_structure`: PseudoFix-style (Li et al., ASE 2025)
  structural cleanups. Again only the rewrites we're confident about:
  if/return-collapse to ternaries, dead `goto LAB; LAB:` removal, and
  unwrapping `do { ... } while (0);` around a single statement.

`apply_postprocess` is the orchestrator — analysts wire it onto
`ai refine-decomp --postprocess` and the report builder calls into it
the same way to keep its rendered code consistent.
"""

from __future__ import annotations

import re


def _try_msynth(code: str) -> str | None:
    """Prefer msynth when installed; return None to fall back to regex.

    We import lazily so chimera works on wheels that don't ship msynth.
    Any import or runtime failure inside msynth degrades to the local
    rules — we never want a post-processor to crash the refine path.
    """
    try:
        import importlib
        importlib.import_module("msynth")
    except Exception:
        return None
    # Hook point: msynth's public API simplifies symbolic IR, not raw C
    # text. Until we plumb a C-to-IR shim we treat msynth's presence as
    # a signal but still apply our regex rules. The hook stays so a
    # future change can replace this branch without touching callers.
    return None


# ----------------------------------------------------------------------
# msynth-style MBA simplification (regex subset)
# ----------------------------------------------------------------------

# We use a token class that matches single C identifiers and indexed
# locals (`a`, `iVar1`, `param_2`). Anything more elaborate (struct
# fields, casts, calls) we leave alone — the safety property only holds
# for plain values without side effects.
_TOK = r"[A-Za-z_][A-Za-z0-9_]*"


_MBA_RULES: list[tuple[re.Pattern[str], str]] = [
    # x & ~0  ->  x   and   ~0 & x  ->  x   (run first so the `0 & x`
    # rule below doesn't strip the `~0` operand out from under us).
    (re.compile(rf"\b({_TOK})\s*&\s*~\s*0\b"), r"\1"),
    (re.compile(rf"(?<!\w)~\s*0\s*&\s*({_TOK})\b"), r"\1"),
    # (a ^ b) ^ a  ->  b    (operand commutativity handled by a second rule)
    (re.compile(rf"\(\s*({_TOK})\s*\^\s*({_TOK})\s*\)\s*\^\s*\1\b"), r"\2"),
    # (a ^ b) ^ b  ->  a
    (re.compile(rf"\(\s*({_TOK})\s*\^\s*({_TOK})\s*\)\s*\^\s*\2\b"), r"\1"),
    # x ^ x  ->  0
    (re.compile(rf"\b({_TOK})\s*\^\s*\1\b"), "0"),
    # x & 0  ->  0   and   0 & x  ->  0  — guard against 0x… hex literals.
    (re.compile(rf"\b({_TOK})\s*&\s*0\b(?!\s*[xX])"), "0"),
    (re.compile(rf"(?<![~\w])\b0\s*&\s*({_TOK})\b"), "0"),
    # x | 0  ->  x   and   0 | x  ->  x   — same hex-literal guard.
    (re.compile(rf"\b({_TOK})\s*\|\s*0\b(?!\s*[xX])"), r"\1"),
    (re.compile(rf"(?<![~\w])\b0\s*\|\s*({_TOK})\b"), r"\1"),
    # Strip redundant parens around a bare 0 or identifier — keeps later
    # rules firing on shapes like `(x ^ x) | 0` once the inner xor folds.
    (re.compile(r"\(\s*0\s*\)"), "0"),
    # 0 | 0  ->  0   and   0 & 0  ->  0   — needed so cascaded
    # simplifications like `(x ^ x) | 0` reach a single literal.
    (re.compile(r"(?<![~\w])\b0\s*\|\s*0\b(?!\s*[xX])"), "0"),
    (re.compile(r"(?<![~\w])\b0\s*&\s*0\b(?!\s*[xX])"), "0"),
]


def simplify_mba(code: str) -> str:
    """Apply a small, safe set of MBA identities to `code`.

    Idempotent in practice — we run the rule list to fixpoint with a
    bounded iteration cap so a buggy rule can never loop forever.
    """
    prefer = _try_msynth(code)
    if prefer is not None:
        return prefer
    prev = code
    for _ in range(8):  # bounded fixpoint
        cur = prev
        for pat, repl in _MBA_RULES:
            cur = pat.sub(repl, cur)
        if cur == prev:
            return cur
        prev = cur
    return prev


# ----------------------------------------------------------------------
# PseudoFix-style structural refactors
# ----------------------------------------------------------------------

# `if (cond) { return A; } return B;`  ->  `return cond ? A : B;`
# Only fires when both branches are *single* return statements with no
# semicolons hiding inside the expressions (a crude side-effect proxy).
_IF_RETURN_RETURN = re.compile(
    r"if\s*\((?P<cond>[^()\n;]+)\)\s*\{\s*return\s+(?P<a>[^;{}\n]+);\s*\}\s*"
    r"return\s+(?P<b>[^;{}\n]+);",
)

# `goto LAB; LAB:` with optional whitespace.
_GOTO_DEAD = re.compile(
    r"goto\s+(?P<lab>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*(?P=lab)\s*:",
)

# `do { stmt; } while (0);` where stmt is a single non-brace statement.
_DOWHILE0 = re.compile(
    r"do\s*\{\s*(?P<body>[^{}\n]+;)\s*\}\s*while\s*\(\s*0\s*\)\s*;",
)


def refactor_structure(code: str) -> str:
    """Collapse a few semantics-preserving boilerplate shapes.

    Each rule fires repeatedly to fixpoint so nested matches resolve in
    one call. The patterns are restrictive on purpose — analysts should
    never have to second-guess what was rewritten.
    """
    prev = code
    for _ in range(8):
        cur = prev
        cur = _IF_RETURN_RETURN.sub(
            lambda m: f"return {m.group('cond').strip()} ? "
                      f"{m.group('a').strip()} : {m.group('b').strip()};",
            cur,
        )
        cur = _GOTO_DEAD.sub(lambda m: f"{m.group('lab')}:", cur)
        cur = _DOWHILE0.sub(lambda m: m.group("body"), cur)
        if cur == prev:
            return cur
        prev = cur
    return prev


def apply_postprocess(code: str, *, mba: bool = True,
                      structure: bool = True) -> str:
    """Run the requested post-processors in a deterministic order.

    Order matters: we simplify MBA *before* structural collapses so a
    rewritten `(x ^ x)` zero can in turn trigger an `if (0)` removal
    downstream if/when we add one.
    """
    out = code
    if mba:
        out = simplify_mba(out)
    if structure:
        out = refactor_structure(out)
    return out
